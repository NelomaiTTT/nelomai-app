package ru.nelomai.tunnel

import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.net.VpnService
import android.os.Build
import android.os.health.HealthStats
import android.os.health.SystemHealthManager
import android.os.health.UidHealthStats
import android.service.quicksettings.TileService
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

internal const val TUNNEL_API_VERSION = 2
private const val TUNNEL_NAME = "nelomai"
private const val QUICK_TILE_SERVICE = "ru.nelomai.client.NelomaiQuickTileService"

@InvokeArg
class TunnelOptionsArgs {
    var splitActive: Boolean = false
    var excludedPackages: ArrayList<String> = arrayListOf()
    var includedPackages: ArrayList<String> = arrayListOf()
    var splitTunnelRoutes: ArrayList<String> = arrayListOf()
    var excludeLocalNetworks: Boolean = false

    companion object {}

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
    var cacheQuickAction: Boolean = false
    var quickActionValidUntilUnix: Long? = null
    var quickConnection: QuickConnectionArgs? = null
}

@InvokeArg
class QuickConnectionArgs {
    lateinit var leaseId: String
    lateinit var layer: String
    lateinit var ticConnectionMode: String
    lateinit var routeMode: String
    var allowAlternate: Boolean = false
}

@InvokeArg
class BackgroundCredentialArgs {
    var apiVersion: Int = 0
    lateinit var panelBase: String
    lateinit var token: String
    var expiresAtUnix: Long = 0
}

@InvokeArg
class VersionedTunnelArgs {
    var apiVersion: Int = 0
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
                SessionState.STOPPED -> {
                    if (state.compareAndSet(current, SessionState.STARTING)) {
                        return TransitionDecision.PROCEED
                    }
                }
                SessionState.FAILED -> {
                    if (state.compareAndSet(current, SessionState.STARTING)) {
                        return TransitionDecision.REPLACE
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

internal class BackgroundOperationGate {
    private val active = AtomicBoolean(false)

    fun begin(): Boolean = active.compareAndSet(false, true)

    fun complete() {
        active.set(false)
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
    var networkWasUnavailable: Boolean,
)

internal object TunnelRuntime {
    private val executor = Executors.newSingleThreadExecutor { task ->
        Thread(task, "nelomai-tunnel").apply { isDaemon = false }
    }
    private val backgroundExecutor = Executors.newSingleThreadExecutor { task ->
        Thread(task, "nelomai-background-connection").apply { isDaemon = false }
    }
    private val stateGate = TunnelStateGate()
    private val backgroundOperationGate = BackgroundOperationGate()
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
        TunnelLog.initialize(context.applicationContext)
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
        keepForegroundServiceOnFailure: Boolean = false,
    ) {
        val applicationContext = context.applicationContext
        val quickPlan = args.copyForQuickPlan()
        val serviceReady = try {
            validateVersion(args.apiVersion)
            NelomaiVpnService.ensureStarted(applicationContext)
        } catch (error: Throwable) {
            if (args.configurationInitialized) {
                args.configuration.fill(0)
            }
            quickPlan?.configuration?.fill(0)
            onError(errorCode(error))
            return
        }
        val replaceExisting = when (stateGate.beginStart()) {
            TransitionDecision.REPLACE -> true
            TransitionDecision.BUSY -> {
                args.configuration.fill(0)
                quickPlan?.configuration?.fill(0)
                onError("tunnel_operation_in_progress")
                return
            }
            TransitionDecision.PROCEED -> false
            TransitionDecision.ALREADY_COMPLETE -> error("unreachable_start_transition")
        }

        executor.execute {
            val startedAt = System.nanoTime()
            TunnelLog.info(
                "start.begin",
                mapOf("replace" to replaceExisting, "split" to args.options.splitActive),
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
                val config = AndroidSplitTunnel.applyOptions(
                    originalConfig,
                    options,
                    applicationContext.packageName,
                )
                val monitor = PhysicalNetworks(context)
                val physicalState = monitor.snapshotState()
                val localRoutes = if (options.splitSupported && options.excludeLocalNetworks) {
                    physicalState.localRoutes
                } else {
                    emptyList()
                }
                NelomaiVpnService.setPhysicalNetworks(physicalState.networks)
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
                if (state == Tunnel.State.UP) {
                    NelomaiVpnService.setPhysicalNetworks(physicalState.networks)
                }
                logStage("start.backend_state_up", backendStartedAt)
                val resolved = if (state == Tunnel.State.UP) {
                    val session = ActiveTunnelSession(
                        generation = generation.incrementAndGet(),
                        config = config,
                        options = options,
                        monitor = monitor,
                        localRoutes = localRoutes,
                        observedNetworkFingerprint = physicalState.fingerprint,
                        networkWasUnavailable = !physicalState.available,
                    )
                    activeSession = session
                    try {
                        monitor.start { networkState ->
                            reapplyPhysicalNetworks(session.generation, networkState)
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
                    SessionState.RUNNING
                } else {
                    monitor.stop()
                    AndroidSplitTunnel.clear()
                    SessionState.FAILED
                }
                stateGate.complete(resolved)
                if (resolved == SessionState.RUNNING && quickPlan != null) {
                    try {
                        QuickTunnelPlanStore.save(applicationContext, quickPlan)
                    } catch (error: Throwable) {
                        TunnelLog.warning("quick_plan.save_failed", error = error)
                        if (!QuickTunnelPlanStore.clear(applicationContext)) {
                            TunnelLog.warning("quick_plan.clear_failed")
                        }
                    } finally {
                        quickPlan.configuration.fill(0)
                    }
                } else {
                    quickPlan?.configuration?.fill(0)
                    if (!keepForegroundServiceOnFailure) {
                        NelomaiVpnService.stopForegroundService()
                    }
                }
                logStage("start.completed", startedAt, "state=${resolved.wireName}")
                onSuccess(resolved, elapsedMillis(startedAt))
            } catch (error: Throwable) {
                if (args.configurationInitialized) {
                    args.configuration.fill(0)
                }
                quickPlan?.configuration?.fill(0)
                AndroidSplitTunnel.clear()
                stateGate.complete(SessionState.FAILED)
                if (!keepForegroundServiceOnFailure) {
                    NelomaiVpnService.stopForegroundService()
                }
                val code = errorCode(error)
                TunnelLog.warning(
                    "start.failed",
                    code,
                    error,
                )
                onError(code)
            }
        }
    }

    fun backgroundStart(
        context: Context,
        onSuccess: (SessionState, Long) -> Unit,
        onError: (String) -> Unit,
    ) {
        val applicationContext = context.applicationContext
        initialize(applicationContext)
        if (!backgroundOperationGate.begin()) {
            onError("tunnel_operation_in_progress")
            return
        }
        if (VpnService.prepare(applicationContext) != null) {
            backgroundOperationGate.complete()
            onError("vpn_permission_required")
            return
        }
        if (stateGate.current() in setOf(SessionState.STARTING, SessionState.STOPPING)) {
            backgroundOperationGate.complete()
            onError("tunnel_operation_in_progress")
            return
        }
        val credential = BackgroundCredentialStore.load(applicationContext) ?: run {
            backgroundOperationGate.complete()
            onError("invalid_background_token")
            return
        }
        val template = QuickTunnelPlanStore.loadTemplate(applicationContext) ?: run {
            backgroundOperationGate.complete()
            onError("quick_action_plan_unavailable")
            return
        }
        if (!QuickTunnelController.updateState(
            applicationContext,
            SessionState.STARTING,
            desiredActive = true,
        )) {
            backgroundOperationGate.complete()
            onError("quick_state_persist_failed")
            return
        }
        backgroundExecutor.execute {
            TunnelLog.info(
                "background_start.requested",
                mapOf("layer" to template.connection.layer, "route" to template.connection.routeMode),
            )
            try {
                val result = BackgroundConnectionClient.start(
                    applicationContext,
                    credential,
                    template,
                )
                val args = StartTunnelArgs().apply {
                    apiVersion = TUNNEL_API_VERSION
                    configuration = result.configuration
                    options = result.options
                    cacheQuickAction = true
                    quickActionValidUntilUnix = null
                    quickConnection = result.connection
                }
                start(
                    applicationContext,
                    args,
                    { state, duration ->
                        try {
                            onSuccess(state, duration)
                        } finally {
                            backgroundOperationGate.complete()
                        }
                    },
                    { code ->
                        backgroundExecutor.execute {
                            runCatching {
                                BackgroundConnectionClient.stop(
                                    credential,
                                    result.connection.leaseId,
                                )
                            }.onFailure { error ->
                                TunnelLog.warning(
                                    "background_start.cleanup_failed",
                                    (error as? BackgroundConnectionException)?.code,
                                )
                            }
                            try {
                                onError(code)
                            } finally {
                                backgroundOperationGate.complete()
                            }
                        }
                    },
                    keepForegroundServiceOnFailure = true,
                )
            } catch (error: Throwable) {
                val code = (error as? BackgroundConnectionException)?.code ?: errorCode(error)
                if (code == "invalid_background_token" &&
                    !BackgroundCredentialStore.clear(applicationContext)
                ) {
                    TunnelLog.warning("background_token.clear_failed")
                }
                TunnelLog.warning("background_start.failed", code, error)
                try {
                    onError(code)
                } finally {
                    backgroundOperationGate.complete()
                }
            }
        }
    }

    fun backgroundStop(
        context: Context,
        onSuccess: (SessionState, Long) -> Unit,
        onError: (String) -> Unit,
    ) {
        val applicationContext = context.applicationContext
        if (!backgroundOperationGate.begin()) {
            onError("tunnel_operation_in_progress")
            return
        }
        val credential = BackgroundCredentialStore.load(applicationContext)
        val leaseId = QuickTunnelPlanStore.loadTemplate(applicationContext)?.connection?.leaseId
        if (!QuickTunnelController.updateState(
            applicationContext,
            SessionState.STOPPING,
            desiredActive = false,
        )) {
            backgroundOperationGate.complete()
            onError("quick_state_persist_failed")
            return
        }
        stop(
            TUNNEL_API_VERSION,
            { state, duration ->
                if (credential == null || leaseId == null) {
                    NelomaiVpnService.stopForegroundService()
                    try {
                        onSuccess(state, duration)
                    } finally {
                        backgroundOperationGate.complete()
                    }
                    return@stop
                }
                backgroundExecutor.execute {
                    runCatching { BackgroundConnectionClient.stop(credential, leaseId) }
                        .onFailure { error ->
                            TunnelLog.warning(
                                "background_stop.panel_failed",
                                (error as? BackgroundConnectionException)?.code,
                            )
                    }
                    NelomaiVpnService.stopForegroundService()
                    try {
                        onSuccess(state, duration)
                    } finally {
                        backgroundOperationGate.complete()
                    }
                }
            },
            { code ->
                try {
                    onError(code)
                } finally {
                    backgroundOperationGate.complete()
                }
            },
            keepForegroundService = true,
        )
    }

    fun clearQuickPlan(context: Context): Boolean =
        QuickTunnelPlanStore.clear(context.applicationContext)

    fun clearBackgroundCredential(context: Context): Boolean =
        BackgroundCredentialStore.clear(context.applicationContext)

    fun stop(
        apiVersion: Int,
        onSuccess: (SessionState, Long) -> Unit,
        onError: (String) -> Unit,
        keepForegroundService: Boolean = false,
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
                if (!keepForegroundService) {
                    NelomaiVpnService.stopForegroundService()
                }
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
            TunnelLog.info("stop.begin")
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
                if (resolved == SessionState.STOPPED && !keepForegroundService) {
                    NelomaiVpnService.stopForegroundService()
                }
                logStage("stop.completed", startedAt, "state=${resolved.wireName}")
                onSuccess(resolved, elapsedMillis(startedAt))
            } catch (error: Throwable) {
                AndroidSplitTunnel.clear()
                stateGate.complete(SessionState.FAILED)
                val code = errorCode(error)
                TunnelLog.warning("stop.failed", code, error)
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
        physicalState: PhysicalNetworkState,
    ) {
        executor.execute {
            val session = activeSession
                ?.takeIf { it.generation == sessionGeneration }
                ?: return@execute
            if (
                stateGate.current() !in setOf(
                    SessionState.RUNNING,
                    SessionState.STOPPED,
                    SessionState.FAILED,
                )
            ) {
                return@execute
            }

            if (!physicalState.available) {
                session.networkWasUnavailable = true
                session.observedNetworkFingerprint = physicalState.fingerprint
                NelomaiVpnService.setPhysicalNetworks(emptyList())
                TunnelLog.info("tunnel.network_unavailable")
                return@execute
            }
            val localRoutes = if (
                session.options.splitSupported && session.options.excludeLocalNetworks
            ) {
                physicalState.localRoutes
            } else {
                emptyList()
            }
            val fingerprint = physicalState.fingerprint
            if (fingerprint == session.observedNetworkFingerprint && !session.networkWasUnavailable) {
                return@execute
            }
            NelomaiVpnService.setPhysicalNetworks(physicalState.networks)
            val recoveredAfterLoss = session.networkWasUnavailable
            session.observedNetworkFingerprint = fingerprint
            session.networkWasUnavailable = false
            if (localRoutes != session.localRoutes) {
                TunnelLog.info(
                    "tunnel.local_routes_deferred",
                    mapOf(
                        "active_routes" to session.localRoutes.size,
                        "next_routes" to localRoutes.size,
                    ),
                )
            }
            TunnelLog.info(
                "tunnel.underlying_networks_updated",
                mapOf("after_loss" to recoveredAfterLoss),
            )
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
        TunnelLog.info(
            stage,
            buildMap {
                put("duration_ms", elapsedMillis(startedAt))
                details?.let { put("details", it) }
            },
        )
    }

}

private class TunnelOperationException(val code: String) : RuntimeException()

internal val StartTunnelArgs.configurationInitialized: Boolean
    get() = try {
        configuration
        true
    } catch (_: UninitializedPropertyAccessException) {
        false
    }

private fun StartTunnelArgs.copyForQuickPlan(): StartTunnelArgs? {
    if (!cacheQuickAction || !configurationInitialized) return null
    return StartTunnelArgs().also { copy ->
        copy.apiVersion = apiVersion
        copy.configuration = byteArrayOf()
        copy.options = TunnelOptionsArgs().also { optionsCopy ->
            optionsCopy.splitActive = options.splitActive
            optionsCopy.excludedPackages = ArrayList(options.excludedPackages)
            optionsCopy.includedPackages = ArrayList(options.includedPackages)
            optionsCopy.splitTunnelRoutes = ArrayList(options.splitTunnelRoutes)
            optionsCopy.excludeLocalNetworks = options.excludeLocalNetworks
        }
        copy.cacheQuickAction = true
        copy.quickActionValidUntilUnix = quickActionValidUntilUnix
        copy.quickConnection = quickConnection?.copy()
    }
}

private fun QuickConnectionArgs.copy(): QuickConnectionArgs = QuickConnectionArgs().also { copy ->
    copy.leaseId = leaseId
    copy.layer = layer
    copy.ticConnectionMode = ticConnectionMode
    copy.routeMode = routeMode
    copy.allowAlternate = allowAlternate
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
        fun refreshQuickTile(context: Context) {
            TileService.requestListeningState(
                context,
                ComponentName(context.packageName, QUICK_TILE_SERVICE),
            )
        }
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
            response.put("backendVersion", GoBackend(activity.applicationContext).version)
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
    fun clearQuickPlan(invoke: Invoke) {
        TunnelServiceClient.clearQuickPlan(
            activity.applicationContext,
            { activity.runOnUiThread { invoke.resolve() } },
            { code -> activity.runOnUiThread { invoke.reject(code) } },
        )
    }

    @Command
    fun configureBackground(invoke: Invoke) {
        val args = try {
            invoke.parseArgs(BackgroundCredentialArgs::class.java)
        } catch (_: Throwable) {
            invoke.reject("invalid_background_credential")
            return
        }
        TunnelServiceClient.configureBackground(
            activity.applicationContext,
            args,
            { activity.runOnUiThread { invoke.resolve() } },
            { code -> activity.runOnUiThread { invoke.reject(code) } },
        )
    }

    @Command
    fun backgroundCredentialStatus(invoke: Invoke) {
        TunnelServiceClient.backgroundCredentialStatus(
            activity.applicationContext,
            { configured, expiresAtUnix ->
                activity.runOnUiThread {
                    val response = JSObject()
                    response.put("configured", configured)
                    response.put("expiresAtUnix", expiresAtUnix)
                    invoke.resolve(response)
                }
            },
            { code -> activity.runOnUiThread { invoke.reject(code) } },
        )
    }

    @Command
    fun clearBackground(invoke: Invoke) {
        TunnelServiceClient.clearBackground(
            activity.applicationContext,
            { activity.runOnUiThread { invoke.resolve() } },
            { code -> activity.runOnUiThread { invoke.reject(code) } },
        )
    }

    @Command
    fun takeQuickStateChange(invoke: Invoke) {
        TunnelServiceClient.takeQuickStateChange(
            activity.applicationContext,
            { changed ->
                activity.runOnUiThread {
                    val response = JSObject()
                    response.put("changed", changed)
                    invoke.resolve(response)
                }
            },
            { code -> activity.runOnUiThread { invoke.reject(code) } },
        )
    }

    @Command
    fun acknowledgeQuickStateChange(invoke: Invoke) {
        TunnelServiceClient.acknowledgeQuickStateChange(
            activity.applicationContext,
            { activity.runOnUiThread { invoke.resolve() } },
            { code -> activity.runOnUiThread { invoke.reject(code) } },
        )
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

        TunnelServiceClient.start(
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

        TunnelServiceClient.stop(
            activity.applicationContext,
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

        TunnelServiceClient.status(
            activity.applicationContext,
            args.apiVersion,
            { state, duration -> resolveOperation(invoke, state, duration) },
            { code -> activity.runOnUiThread { invoke.reject(code) } },
        )
    }

    @Command
    fun tunnelMetrics(invoke: Invoke) {
        val args = try {
            invoke.parseArgs(TunnelMetricsArgs::class.java)
        } catch (_: Throwable) {
            invoke.reject("invalid_tunnel_request")
            return
        }
        TunnelServiceClient.metrics(
            activity.applicationContext,
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
