package ru.nelomai.tunnel

import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.net.VpnService
import android.os.Build
import android.os.SystemClock
import android.os.health.HealthStats
import android.os.health.SystemHealthManager
import android.os.health.UidHealthStats
import android.service.quicksettings.TileService
import android.util.Log
import androidx.activity.result.ActivityResult
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import java.io.ByteArrayInputStream
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import org.json.JSONArray

private const val TUNNEL_API_VERSION = 2
private const val TUNNEL_NAME = "nelomai"
private const val TUNNEL_LOG_TAG = "NelomaiTunnel"
private const val PHYSICAL_NETWORK_RETRY_MILLIS = 5 * 60 * 1_000L
private const val QUICK_ACTION_EVENT = "quick-toggle"
private const val QUICK_ACTION_PREFERENCES = "nelomai-quick-actions"
private const val QUICK_ACTION_PENDING = "toggle-pending"
private const val QUICK_TILE_SERVICE = "ru.nelomai.client.NelomaiQuickTileService"
private const val QUICK_ACTION_STALE_MILLIS = 60_000L

@InvokeArg
class TunnelOptionsArgs {
    var splitActive: Boolean = false
    var excludedPackages: ArrayList<String> = arrayListOf()
    var includedPackages: ArrayList<String> = arrayListOf()
    var splitTunnelRoutes: ArrayList<String> = arrayListOf()
    var excludeLocalNetworks: Boolean = false

    fun isEmpty(): Boolean =
        !splitActive &&
            excludedPackages.isEmpty() &&
            includedPackages.isEmpty() &&
            splitTunnelRoutes.isEmpty() &&
            !excludeLocalNetworks
}

@InvokeArg
class StartTunnelArgs {
    var apiVersion: Int = 0
    lateinit var configuration: ByteArray
    var options: TunnelOptionsArgs = TunnelOptionsArgs()
}

@InvokeArg
class VersionedTunnelArgs {
    var apiVersion: Int = 0
}

@InvokeArg
class CompleteQuickActionArgs {
    var success: Boolean = false
}

@InvokeArg
class TunnelMetricsArgs {
    var apiVersion: Int = 0
    var probe: Boolean = false
}

internal object TunnelPayload {
    inline fun <T> consume(payload: ByteArray, action: (ByteArray) -> T): T {
        return try {
            action(payload)
        } finally {
            payload.fill(0)
        }
    }
}

internal enum class SessionState(val wireName: String) {
    STOPPED("stopped"),
    STARTING("starting"),
    RUNNING("running"),
    STOPPING("stopping"),
    FAILED("failed"),
}

internal enum class TransitionDecision {
    PROCEED,
    REPLACE,
    ALREADY_COMPLETE,
    BUSY,
}

internal class TunnelStateGate(
    initialState: SessionState = SessionState.STOPPED,
) {
    private val state = AtomicReference(initialState)

    fun current(): SessionState = state.get()

    fun beginStart(): TransitionDecision {
        while (true) {
            when (val current = state.get()) {
                SessionState.RUNNING -> {
                    if (state.compareAndSet(current, SessionState.STARTING)) {
                        return TransitionDecision.REPLACE
                    }
                }
                SessionState.STARTING, SessionState.STOPPING -> return TransitionDecision.BUSY
                SessionState.STOPPED, SessionState.FAILED -> {
                    if (state.compareAndSet(current, SessionState.STARTING)) {
                        return TransitionDecision.PROCEED
                    }
                }
            }
        }
    }

    fun beginStop(): TransitionDecision {
        while (true) {
            when (val current = state.get()) {
                SessionState.STOPPED -> return TransitionDecision.ALREADY_COMPLETE
                SessionState.STARTING, SessionState.STOPPING -> return TransitionDecision.BUSY
                SessionState.RUNNING, SessionState.FAILED -> {
                    if (state.compareAndSet(current, SessionState.STOPPING)) {
                        return TransitionDecision.PROCEED
                    }
                }
            }
        }
    }

    fun complete(next: SessionState) {
        state.set(next)
    }
}

internal class PhysicalNetworkRetryGate {
    private var failedFingerprint: String? = null
    private var retryAfterMillis: Long = 0

    fun canAttempt(fingerprint: String, nowMillis: Long): Boolean =
        failedFingerprint != fingerprint || nowMillis >= retryAfterMillis

    fun defer(fingerprint: String, nowMillis: Long) {
        failedFingerprint = fingerprint
        retryAfterMillis = nowMillis + PHYSICAL_NETWORK_RETRY_MILLIS
    }

    fun clear() {
        failedFingerprint = null
        retryAfterMillis = 0
    }
}

private class ManagedTunnel(
    private val onStateChange: (Tunnel.State) -> Unit,
) : Tunnel {
    override fun getName(): String = TUNNEL_NAME

    override fun onStateChange(newState: Tunnel.State) {
        onStateChange.invoke(newState)
    }
}

private data class ActiveTunnelSession(
    val generation: Long,
    val config: Config,
    val options: EffectiveAndroidTunnelOptions,
    var monitor: PhysicalNetworks?,
    var localRoutes: List<Ipv4Prefix>,
    var observedNetworkFingerprint: String,
    val networkRetry: PhysicalNetworkRetryGate = PhysicalNetworkRetryGate(),
)

internal object TunnelRuntime {
    private val executor = Executors.newSingleThreadExecutor { task ->
        Thread(task, "nelomai-tunnel").apply { isDaemon = false }
    }
    private val stateGate = TunnelStateGate()
    private val suppressBackendStateChanges = AtomicBoolean(false)
    private val generation = AtomicLong(0)
    private val tunnel = ManagedTunnel { state ->
        if (!suppressBackendStateChanges.get()) {
            stateGate.complete(
                if (state == Tunnel.State.UP) SessionState.RUNNING else SessionState.STOPPED,
            )
        }
    }

    @Volatile
    private var backend: GoBackend? = null

    @Volatile
    private var activeSession: ActiveTunnelSession? = null

    fun initialize(context: Context) {
        if (backend == null) {
            synchronized(this) {
                if (backend == null) {
                    backend = GoBackend(context.applicationContext)
                }
            }
        }
    }

    fun backendVersion(): String = requireBackend().version

    fun state(): SessionState = stateGate.current()

    fun start(
        context: Context,
        args: StartTunnelArgs,
        onSuccess: (SessionState, Long) -> Unit,
        onError: (String) -> Unit,
    ) {
        val serviceReady = try {
            validateVersion(args.apiVersion)
            NelomaiVpnService.ensureStarted(context)
        } catch (error: Throwable) {
            if (args.configurationInitialized) {
                args.configuration.fill(0)
            }
            onError(errorCode(error))
            return
        }
        val replaceExisting = when (stateGate.beginStart()) {
            TransitionDecision.REPLACE -> true
            TransitionDecision.BUSY -> {
                args.configuration.fill(0)
                onError("tunnel_operation_in_progress")
                return
            }
            TransitionDecision.PROCEED -> false
            TransitionDecision.ALREADY_COMPLETE -> error("unreachable_start_transition")
        }

        executor.execute {
            val startedAt = System.nanoTime()
            Log.i(
                TUNNEL_LOG_TAG,
                "start.begin replace=$replaceExisting split=${args.options.splitActive}",
            )
            try {
                val serviceStartedAt = System.nanoTime()
                serviceReady.get(5, TimeUnit.SECONDS)
                logStage("start.service_ready", serviceStartedAt)
                if (replaceExisting) {
                    val replaceStartedAt = System.nanoTime()
                    clearActiveSession()
                    suppressBackendStateChanges.set(true)
                    try {
                        requireState(
                            requireBackend().setState(tunnel, Tunnel.State.DOWN, null),
                            Tunnel.State.DOWN,
                        )
                        AndroidSplitTunnel.clear()
                    } finally {
                        suppressBackendStateChanges.set(false)
                    }
                    logStage("start.previous_tunnel_stopped", replaceStartedAt)
                }
                val parseStartedAt = System.nanoTime()
                val originalConfig = TunnelPayload.consume(args.configuration) { payload ->
                    Config.parse(ByteArrayInputStream(payload))
                }
                logStage("start.configuration_parsed", parseStartedAt)
                val optionsStartedAt = System.nanoTime()
                val options = AndroidSplitTunnel.resolveOptions(
                    Build.VERSION.SDK_INT,
                    args.options,
                )
                val config = AndroidSplitTunnel.applyOptions(originalConfig, options)
                val monitor = if (options.splitSupported && options.excludeLocalNetworks) {
                    PhysicalNetworks(context)
                } else {
                    null
                }
                val localRoutes = monitor
                    ?.snapshot()
                    .orEmpty()
                AndroidSplitTunnel.replaceExcludedRoutes(
                    AndroidSplitTunnel.mergeExcludedRoutes(
                        options.excludedRoutes,
                        localRoutes,
                    ),
                )
                logStage(
                    "start.options_ready",
                    optionsStartedAt,
                    "split_supported=${options.splitSupported} local_routes=${localRoutes.size}",
                )

                val backendStartedAt = System.nanoTime()
                val state = requireBackend().setState(tunnel, Tunnel.State.UP, config)
                logStage("start.backend_state_up", backendStartedAt)
                val resolved = if (state == Tunnel.State.UP) {
                    val session = ActiveTunnelSession(
                        generation = generation.incrementAndGet(),
                        config = config,
                        options = options,
                        monitor = monitor,
                        localRoutes = localRoutes,
                        observedNetworkFingerprint = PhysicalNetworks.fingerprint(localRoutes),
                    )
                    activeSession = session
                    if (monitor != null) {
                        try {
                            monitor.start { networks ->
                                reapplyPhysicalNetworks(session.generation, networks)
                            }
                        } catch (_: Throwable) {
                            activeSession = null
                            monitor.stop()
                            runCatching {
                                requireBackend().setState(tunnel, Tunnel.State.DOWN, null)
                            }
                            AndroidSplitTunnel.clear()
                            throw TunnelOperationException(
                                "physical_network_monitor_unavailable",
                            )
                        }
                    }
                    SessionState.RUNNING
                } else {
                    monitor?.stop()
                    AndroidSplitTunnel.clear()
                    SessionState.FAILED
                }
                stateGate.complete(resolved)
                logStage("start.completed", startedAt, "state=${resolved.wireName}")
                onSuccess(resolved, elapsedMillis(startedAt))
            } catch (error: Throwable) {
                if (args.configurationInitialized) {
                    args.configuration.fill(0)
                }
                AndroidSplitTunnel.clear()
                stateGate.complete(SessionState.FAILED)
                val code = errorCode(error)
                Log.w(
                    TUNNEL_LOG_TAG,
                    "start.failed code=$code duration_ms=${elapsedMillis(startedAt)}",
                )
                onError(code)
            }
        }
    }

    fun stop(
        apiVersion: Int,
        onSuccess: (SessionState, Long) -> Unit,
        onError: (String) -> Unit,
    ) {
        try {
            validateVersion(apiVersion)
        } catch (error: Throwable) {
            onError(errorCode(error))
            return
        }

        when (stateGate.beginStop()) {
            TransitionDecision.ALREADY_COMPLETE -> {
                clearActiveSession()
                onSuccess(SessionState.STOPPED, 0)
                return
            }
            TransitionDecision.BUSY -> {
                onError("tunnel_operation_in_progress")
                return
            }
            TransitionDecision.PROCEED -> Unit
            TransitionDecision.REPLACE -> error("unreachable_stop_transition")
        }

        executor.execute {
            val startedAt = System.nanoTime()
            Log.i(TUNNEL_LOG_TAG, "stop.begin")
            try {
                clearActiveSession()
                val state = requireBackend().setState(tunnel, Tunnel.State.DOWN, null)
                AndroidSplitTunnel.clear()
                val resolved = if (state == Tunnel.State.DOWN) {
                    SessionState.STOPPED
                } else {
                    SessionState.FAILED
                }
                stateGate.complete(resolved)
                logStage("stop.completed", startedAt, "state=${resolved.wireName}")
                onSuccess(resolved, elapsedMillis(startedAt))
            } catch (error: Throwable) {
                AndroidSplitTunnel.clear()
                stateGate.complete(SessionState.FAILED)
                val code = errorCode(error)
                Log.w(
                    TUNNEL_LOG_TAG,
                    "stop.failed code=$code duration_ms=${elapsedMillis(startedAt)}",
                )
                onError(code)
            }
        }
    }

    fun metrics(
        apiVersion: Int,
        probe: Boolean,
        onSuccess: (Long, Long, String?) -> Unit,
        onError: (String) -> Unit,
    ) {
        try {
            validateVersion(apiVersion)
        } catch (error: Throwable) {
            onError(errorCode(error))
            return
        }
        executor.execute {
            try {
                val session = activeSession
                    ?.takeIf { stateGate.current() == SessionState.RUNNING }
                    ?: throw TunnelOperationException("tunnel_not_running")
                val statistics = requireBackend().getStatistics(tunnel)
                val target = if (probe) {
                    session.config.peers.firstOrNull()?.endpoint?.orElse(null)?.host
                } else {
                    null
                }
                onSuccess(statistics.totalRx(), statistics.totalTx(), target)
            } catch (error: Throwable) {
                onError(errorCode(error))
            }
        }
    }

    private fun requireBackend(): GoBackend =
        backend ?: error("tunnel_backend_unavailable")

    fun serviceDestroyed() {
        stateGate.complete(SessionState.STOPPED)
        clearActiveSession()
        AndroidSplitTunnel.clear()
    }

    private fun reapplyPhysicalNetworks(
        sessionGeneration: Long,
        localRoutes: List<Ipv4Prefix>,
    ) {
        executor.execute {
            val session = activeSession
                ?.takeIf { it.generation == sessionGeneration }
                ?: return@execute
            if (stateGate.current() != SessionState.RUNNING) {
                return@execute
            }

            val fingerprint = PhysicalNetworks.fingerprint(localRoutes)
            if (fingerprint == session.observedNetworkFingerprint) {
                return@execute
            }
            val nowMillis = SystemClock.elapsedRealtime()
            if (!session.networkRetry.canAttempt(fingerprint, nowMillis)) {
                return@execute
            }
            session.observedNetworkFingerprint = fingerprint
            val previousRoutes = session.localRoutes
            stateGate.complete(SessionState.STARTING)
            suppressBackendStateChanges.set(true)

            try {
                requireState(
                    requireBackend().setState(tunnel, Tunnel.State.DOWN, null),
                    Tunnel.State.DOWN,
                )
                AndroidSplitTunnel.replaceExcludedRoutes(
                    AndroidSplitTunnel.mergeExcludedRoutes(
                        session.options.excludedRoutes,
                        localRoutes,
                    ),
                )
                requireState(
                    requireBackend().setState(tunnel, Tunnel.State.UP, session.config),
                    Tunnel.State.UP,
                )
                session.localRoutes = localRoutes
                session.networkRetry.clear()
                stateGate.complete(SessionState.RUNNING)
            } catch (_: Throwable) {
                val restored = runCatching {
                    runCatching {
                        requireBackend().setState(tunnel, Tunnel.State.DOWN, null)
                    }
                    AndroidSplitTunnel.replaceExcludedRoutes(
                        AndroidSplitTunnel.mergeExcludedRoutes(
                            session.options.excludedRoutes,
                            previousRoutes,
                        ),
                    )
                    requireState(
                        requireBackend().setState(tunnel, Tunnel.State.UP, session.config),
                        Tunnel.State.UP,
                    )
                }.isSuccess
                if (restored) {
                    session.observedNetworkFingerprint =
                        PhysicalNetworks.fingerprint(previousRoutes)
                    session.networkRetry.defer(fingerprint, nowMillis)
                    session.monitor?.scheduleRetry(PHYSICAL_NETWORK_RETRY_MILLIS)
                    stateGate.complete(SessionState.RUNNING)
                } else {
                    activeSession = null
                    session.monitor?.stop()
                    AndroidSplitTunnel.clear()
                    stateGate.complete(SessionState.FAILED)
                }
            } finally {
                suppressBackendStateChanges.set(false)
            }
        }
    }

    private fun clearActiveSession() {
        val session = activeSession
        activeSession = null
        generation.incrementAndGet()
        session?.monitor?.stop()
    }

    private fun requireState(actual: Tunnel.State, expected: Tunnel.State) {
        if (actual != expected) {
            throw TunnelOperationException("unexpected_tunnel_state")
        }
    }

    private fun validateVersion(apiVersion: Int) {
        if (apiVersion != TUNNEL_API_VERSION) {
            throw TunnelOperationException("unsupported_api_version")
        }
    }

    private fun errorCode(error: Throwable): String = when (error) {
        is TunnelOperationException -> error.code
        is AndroidSplitTunnelException -> error.code
        else -> "tunnel_backend_error"
    }

    private fun elapsedMillis(startedAt: Long): Long =
        (System.nanoTime() - startedAt) / 1_000_000

    private fun logStage(stage: String, startedAt: Long, details: String? = null) {
        val suffix = details?.let { " $it" }.orEmpty()
        Log.i(
            TUNNEL_LOG_TAG,
            "$stage duration_ms=${elapsedMillis(startedAt)}$suffix",
        )
    }

}

private class TunnelOperationException(val code: String) : RuntimeException()

private val StartTunnelArgs.configurationInitialized: Boolean
    get() = try {
        configuration
        true
    } catch (_: UninitializedPropertyAccessException) {
        false
    }

private fun HealthStats.measurement(key: Int): Long? =
    if (hasMeasurement(key)) getMeasurement(key).coerceAtLeast(0L) else null

private fun HealthStats.sumMeasurements(vararg keys: Int): Long? {
    var found = false
    var total = 0L
    for (key in keys) {
        val value = measurement(key) ?: continue
        found = true
        total = if (Long.MAX_VALUE - total < value) Long.MAX_VALUE else total + value
    }
    return if (found) total else null
}

@TauriPlugin
class TunnelPlugin(private val activity: Activity) : Plugin(activity) {
    companion object {
        const val QUICK_ACTION_HEADLESS_EXTRA = "ru.nelomai.client.QUICK_ACTION_HEADLESS"

        @Volatile
        private var activeInstance: TunnelPlugin? = null
        private val quickActionStartedAt = AtomicLong(0)

        fun beginQuickToggle(): Boolean {
            val now = SystemClock.elapsedRealtime()
            while (true) {
                val startedAt = quickActionStartedAt.get()
                if (startedAt != 0L && now - startedAt < QUICK_ACTION_STALE_MILLIS) return false
                if (quickActionStartedAt.compareAndSet(startedAt, now)) return true
            }
        }

        fun dispatchQuickToggle(): Boolean {
            val plugin = activeInstance ?: run {
                Log.i(TUNNEL_LOG_TAG, "quick_toggle.dispatch_unavailable reason=no_plugin")
                return false
            }
            if (!plugin.hasListener(QUICK_ACTION_EVENT)) {
                Log.i(TUNNEL_LOG_TAG, "quick_toggle.dispatch_unavailable reason=no_listener")
                return false
            }
            if (VpnService.prepare(plugin.activity.applicationContext) != null) {
                Log.i(TUNNEL_LOG_TAG, "quick_toggle.dispatch_unavailable reason=permission_required")
                return false
            }
            plugin.trigger(QUICK_ACTION_EVENT, JSObject())
            Log.i(TUNNEL_LOG_TAG, "quick_toggle.dispatched")
            return true
        }

        fun queueQuickToggle(context: Context) {
            context.getSharedPreferences(QUICK_ACTION_PREFERENCES, Context.MODE_PRIVATE)
                .edit()
                .putBoolean(QUICK_ACTION_PENDING, true)
                .commit()
        }

        fun hasPendingQuickToggle(context: Context): Boolean =
            context.getSharedPreferences(QUICK_ACTION_PREFERENCES, Context.MODE_PRIVATE)
                .getBoolean(QUICK_ACTION_PENDING, false)

        fun tunnelState(): String = TunnelRuntime.state().wireName

        fun finishQuickToggle() {
            quickActionStartedAt.set(0)
        }

        fun refreshQuickTile(context: Context) {
            TileService.requestListeningState(
                context,
                ComponentName(context.packageName, QUICK_TILE_SERVICE),
            )
        }
    }

    init {
        TunnelRuntime.initialize(activity.applicationContext)
        activeInstance = this
    }

    @Suppress("OVERRIDE_DEPRECATION")
    override fun onDestroy() {
        if (activeInstance === this) activeInstance = null
    }

    @Command
    fun probe(invoke: Invoke) {
        val response = JSObject()
        response.put("platform", "android")
        response.put("androidApiLevel", Build.VERSION.SDK_INT)
        response.put("addressSplitTunnel", Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
        response.put(
            "applicationSplitTunnel",
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU,
        )
        response.put("permissionGranted", VpnService.prepare(activity.applicationContext) == null)

        try {
            response.put("backendAvailable", true)
            response.put("backendVersion", TunnelRuntime.backendVersion())
            response.put("error", null)
        } catch (_: Throwable) {
            response.put("backendAvailable", false)
            response.put("backendVersion", null)
            response.put("error", "tunnel_backend_unavailable")
        }

        invoke.resolve(response)
    }

    @Command
    fun requestVpnPermission(invoke: Invoke) {
        val intent = VpnService.prepare(activity.applicationContext)
        if (intent == null) {
            resolvePermission(invoke, true)
            return
        }

        startActivityForResult(invoke, intent, "vpnPermissionResult")
    }

    @Command
    fun installedApplications(invoke: Invoke) {
        try {
            val applications = JSONArray()
            InstalledApplications.query(activity.applicationContext).forEach { application ->
                val item = JSObject()
                item.put("packageId", application.packageId)
                item.put("displayName", application.displayName)
                item.put("system", application.system)
                applications.put(item)
            }
            val response = JSObject()
            response.put("applications", applications)
            invoke.resolve(response)
        } catch (_: Throwable) {
            invoke.reject("installed_applications_unavailable")
        }
    }

    @Suppress("DEPRECATION")
    @Command
    fun resourceUsage(invoke: Invoke) {
        try {
            val manager = activity.getSystemService(SystemHealthManager::class.java)
            val stats = manager.takeMyUidSnapshot()
            val response = JSObject()
            response.put("cpuUserMs", stats.measurement(UidHealthStats.MEASUREMENT_USER_CPU_TIME_MS))
            response.put("cpuSystemMs", stats.measurement(UidHealthStats.MEASUREMENT_SYSTEM_CPU_TIME_MS))
            response.put(
                "networkRxBytes",
                stats.sumMeasurements(
                    UidHealthStats.MEASUREMENT_MOBILE_RX_BYTES,
                    UidHealthStats.MEASUREMENT_WIFI_RX_BYTES,
                ),
            )
            response.put(
                "networkTxBytes",
                stats.sumMeasurements(
                    UidHealthStats.MEASUREMENT_MOBILE_TX_BYTES,
                    UidHealthStats.MEASUREMENT_WIFI_TX_BYTES,
                ),
            )
            response.put("cpuChargeMilliampMilliseconds", stats.measurement(UidHealthStats.MEASUREMENT_CPU_POWER_MAMS))
            response.put("mobileChargeMilliampMilliseconds", stats.measurement(UidHealthStats.MEASUREMENT_MOBILE_POWER_MAMS))
            response.put("wifiChargeMilliampMilliseconds", stats.measurement(UidHealthStats.MEASUREMENT_WIFI_POWER_MAMS))
            invoke.resolve(response)
        } catch (_: Throwable) {
            invoke.reject("resource_usage_unavailable")
        }
    }

    @Command
    fun takeQuickAction(invoke: Invoke) {
        val preferences = activity.getSharedPreferences(
            QUICK_ACTION_PREFERENCES,
            Context.MODE_PRIVATE,
        )
        val pending = preferences.getBoolean(QUICK_ACTION_PENDING, false)
        if (pending) preferences.edit().remove(QUICK_ACTION_PENDING).commit()
        Log.i(TUNNEL_LOG_TAG, "quick_toggle.pending_consumed pending=$pending")
        val response = JSObject()
        response.put("pending", pending)
        invoke.resolve(response)
    }

    @Command
    fun refreshQuickTile(invoke: Invoke) {
        val args = try {
            invoke.parseArgs(CompleteQuickActionArgs::class.java)
        } catch (_: Throwable) {
            invoke.reject("invalid_quick_action_result")
            return
        }
        finishQuickToggle()
        refreshQuickTile(activity.applicationContext)
        invoke.resolve()
        finishHeadlessQuickAction(args.success)
    }

    @Command
    fun startTunnel(invoke: Invoke) {
        val args = try {
            invoke.parseArgs(StartTunnelArgs::class.java)
        } catch (_: Throwable) {
            invoke.reject("invalid_tunnel_request")
            return
        }

        if (VpnService.prepare(activity.applicationContext) != null) {
            if (args.configurationInitialized) {
                args.configuration.fill(0)
            }
            invoke.reject("vpn_permission_required")
            return
        }

        TunnelRuntime.start(
            activity.applicationContext,
            args,
            { state, duration -> resolveOperation(invoke, state, duration) },
            { code -> activity.runOnUiThread { invoke.reject(code) } },
        )
    }

    @Command
    fun stopTunnel(invoke: Invoke) {
        val args = try {
            invoke.parseArgs(VersionedTunnelArgs::class.java)
        } catch (_: Throwable) {
            invoke.reject("invalid_tunnel_request")
            return
        }

        TunnelRuntime.stop(
            args.apiVersion,
            { state, duration -> resolveOperation(invoke, state, duration) },
            { code -> activity.runOnUiThread { invoke.reject(code) } },
        )
    }

    @Command
    fun tunnelStatus(invoke: Invoke) {
        val args = try {
            invoke.parseArgs(VersionedTunnelArgs::class.java)
        } catch (_: Throwable) {
            invoke.reject("invalid_tunnel_request")
            return
        }
        if (args.apiVersion != TUNNEL_API_VERSION) {
            invoke.reject("unsupported_api_version")
            return
        }

        resolveOperation(invoke, TunnelRuntime.state(), 0)
    }

    @Command
    fun tunnelMetrics(invoke: Invoke) {
        val args = try {
            invoke.parseArgs(TunnelMetricsArgs::class.java)
        } catch (_: Throwable) {
            invoke.reject("invalid_tunnel_request")
            return
        }
        TunnelRuntime.metrics(
            args.apiVersion,
            args.probe,
            { received, sent, target ->
                activity.runOnUiThread {
                    val response = JSObject()
                    response.put("receivedBytes", received)
                    response.put("sentBytes", sent)
                    response.put("probeTarget", target)
                    invoke.resolve(response)
                }
            },
            { code -> activity.runOnUiThread { invoke.reject(code) } },
        )
    }

    @ActivityCallback
    fun vpnPermissionResult(invoke: Invoke, result: ActivityResult) {
        val granted = result.resultCode == Activity.RESULT_OK &&
            VpnService.prepare(activity.applicationContext) == null
        resolvePermission(invoke, granted)
    }

    private fun resolvePermission(invoke: Invoke, granted: Boolean) {
        val response = JSObject()
        response.put("permissionGranted", granted)
        invoke.resolve(response)
    }

    private fun finishHeadlessQuickAction(success: Boolean) {
        if (!activity.intent.getBooleanExtra(QUICK_ACTION_HEADLESS_EXTRA, false)) return
        activity.runOnUiThread {
            Log.i(TUNNEL_LOG_TAG, "quick_toggle.headless_completed success=$success")
            if (!success) {
                activity.packageManager
                    .getLaunchIntentForPackage(activity.packageName)
                    ?.apply {
                        addFlags(
                            android.content.Intent.FLAG_ACTIVITY_NEW_TASK or
                                android.content.Intent.FLAG_ACTIVITY_CLEAR_TOP or
                                android.content.Intent.FLAG_ACTIVITY_SINGLE_TOP,
                        )
                    }
                    ?.let(activity::startActivity)
            }
            activity.finishAndRemoveTask()
        }
    }

    private fun resolveOperation(invoke: Invoke, state: SessionState, durationMillis: Long) {
        activity.runOnUiThread {
            val response = JSObject()
            response.put("state", state.wireName)
            response.put("durationMillis", durationMillis)
            response.put("errorCode", null)
            invoke.resolve(response)
            refreshQuickTile(activity.applicationContext)
        }
    }
}
