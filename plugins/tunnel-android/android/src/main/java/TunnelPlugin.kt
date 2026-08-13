package ru.nelomai.tunnel

import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.net.VpnService
import android.os.Build
import android.os.SystemClock
import android.system.Os
import android.os.health.HealthStats
import android.os.health.SystemHealthManager
import android.os.health.UidHealthStats
import android.service.quicksettings.TileService
import android.webkit.WebView
import androidx.activity.result.ActivityResult
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import org.amnezia.awg.backend.GoBackend
import org.amnezia.awg.backend.Tunnel
import org.amnezia.awg.config.Config
import java.io.ByteArrayInputStream
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import org.json.JSONArray

internal const val TUNNEL_API_VERSION = 2
private const val TUNNEL_NAME = "nelomai"
private const val QUICK_TILE_SERVICE = "ru.nelomai.client.NelomaiQuickTileService"
private const val TUNNEL_OPERATION_WATCHDOG_MILLIS = 40_000L

@InvokeArg
class TunnelOptionsArgs {
    var splitActive: Boolean = false
    var policyHash: String? = null
    var applicationMode: String? = null
    var excludedPackages: ArrayList<String> = arrayListOf()
    var includedPackages: ArrayList<String> = arrayListOf()
    var splitTunnelRoutes: ArrayList<String> = arrayListOf()
    var excludeLocalNetworks: Boolean = false
    var dnsServers: ArrayList<String> = arrayListOf()

    companion object {}

    fun isEmpty(): Boolean =
            !splitActive &&
            policyHash == null &&
            applicationMode == null &&
            excludedPackages.isEmpty() &&
            includedPackages.isEmpty() &&
            splitTunnelRoutes.isEmpty() &&
            !excludeLocalNetworks &&
            dnsServers.isEmpty()
}

@InvokeArg
class DnsServersArgs {
    var dnsServers: ArrayList<String> = arrayListOf()
}

@InvokeArg
class StartFailureDiagnosticsArgs {
    lateinit var deviceId: String
    var errorCode: String = "connection_start_failed"
}

@InvokeArg
class StartTunnelArgs {
    var apiVersion: Int = 0
    var clientOperationId: String? = null
    var startSource: String = "ui"
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
    lateinit var deviceId: String
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

@InvokeArg
class QuickStateChangeAcknowledgeArgs {
    var revision: Long = 0L
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

internal class TunnelOperationWatchdogGate {
    private val nextGeneration = AtomicLong(0)
    private val activeGeneration = AtomicLong(0)

    fun begin(): Long {
        val generation = nextGeneration.incrementAndGet()
        activeGeneration.set(generation)
        return generation
    }

    fun complete(generation: Long): Boolean =
        activeGeneration.compareAndSet(generation, 0)

    fun expire(generation: Long): Boolean = complete(generation)
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
    val clientOperationId: String?,
    val config: Config,
    val options: EffectiveAndroidTunnelOptions,
    var monitor: PhysicalNetworks?,
    var localRoutes: List<Ipv4Prefix>,
    var observedNetworkFingerprint: String,
    var networkWasUnavailable: Boolean,
    val transport: String,
    val startedAtElapsedMillis: Long = SystemClock.elapsedRealtime(),
    var lastDiagnosticsReceivedBytes: Long? = null,
    var lastDiagnosticsSentBytes: Long? = null,
)

private data class TunnelOperationWatchdog(
    val generation: Long,
    val future: ScheduledFuture<*>,
)

internal object TunnelRuntime {
    private val executor = Executors.newSingleThreadExecutor { task ->
        Thread(task, "nelomai-tunnel").apply { isDaemon = false }
    }
    private val backgroundExecutor = Executors.newSingleThreadExecutor { task ->
        Thread(task, "nelomai-background-connection").apply { isDaemon = false }
    }
    private val watchdogExecutor = Executors.newSingleThreadScheduledExecutor { task ->
        Thread(task, "nelomai-tunnel-watchdog").apply { isDaemon = false }
    }
    private val stateGate = TunnelStateGate()
    private val backgroundOperationGate = BackgroundOperationGate()
    private val watchdogGate = TunnelOperationWatchdogGate()
    private val suppressBackendStateChanges = AtomicBoolean(false)
    private val cancelledClientStarts = ConcurrentHashMap.newKeySet<String>()
    private val generation = AtomicLong(0)
    private val tunnel = ManagedTunnel { state ->
        if (!suppressBackendStateChanges.get()) {
            if (state == Tunnel.State.UP) {
                stateGate.complete(SessionState.RUNNING)
            } else {
                stateGate.complete(SessionState.STOPPED)
                TunnelLog.warning("tunnel.backend_state_down")
                applicationContext?.let { context ->
                    runCatching { AutomaticDiagnostics.onTunnelStopped(context) }
                        .onFailure { TunnelLog.warning("diagnostics.lifecycle_failed", error = it) }
                }
            }
        }
    }

    @Volatile
    private var backend: GoBackend? = null

    private val activeTunnelHandleField by lazy {
        runCatching {
            GoBackend::class.java.getDeclaredField("currentTunnelHandle").apply {
                isAccessible = true
            }
        }
    }

    @Volatile
    private var activeSession: ActiveTunnelSession? = null

    @Volatile
    private var dataPlaneFuture: ScheduledFuture<*>? = null

    @Volatile
    private var applicationContext: Context? = null

    fun initialize(context: Context) {
        val normalizedContext = context.applicationContext
        applicationContext = normalizedContext
        TunnelLog.initialize(normalizedContext)
        if (backend == null) {
            synchronized(this) {
                if (backend == null) {
                    backend = createBackend(normalizedContext)
                }
            }
        }
    }

    fun backendVersion(): String = diagnosticBackendVersion(requireBackend().version)

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

        val watchdog = armOperationWatchdog(applicationContext, "start")
        executor.execute {
            val startedAt = System.nanoTime()
            TunnelLog.info(
                "start.begin",
                mapOf(
                    "replace" to replaceExisting,
                    "split" to args.options.splitActive,
                    "source" to args.startSource,
                ),
            )
            try {
                requireClientStartNotCancelled(args.clientOperationId)
                val serviceStartedAt = System.nanoTime()
                serviceReady.get(5, TimeUnit.SECONDS)
                requireClientStartNotCancelled(args.clientOperationId)
                logStage("start.service_ready", serviceStartedAt)
                if (replaceExisting) {
                    val replaceStartedAt = System.nanoTime()
                    activeSession?.let { logDataPlaneSnapshot(it, "tunnel_replaced") }
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
                    runCatching { AutomaticDiagnostics.onTunnelStopped(applicationContext) }
                        .onFailure { TunnelLog.warning("diagnostics.lifecycle_failed", error = it) }
                    logStage("start.previous_tunnel_stopped", replaceStartedAt)
                }
                val parseStartedAt = System.nanoTime()
                val originalConfig = TunnelPayload.consume(args.configuration) { payload ->
                    Config.parse(ByteArrayInputStream(payload))
                }
                val receivedAwg3Profile = originalConfig.getInterface()
                    .takeIf { it.headerProtectionKey.isPresent || it.contentPaddingAddition.isPresent }
                    ?.let(Awg3ProfileSnapshot::fromInterface)
                receivedAwg3Profile?.let { profile ->
                    logAwg3Profile("start.awg3_profile_received", profile)
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
                val transport = if (
                    config.getInterface().headerProtectionKey.isPresent ||
                    config.getInterface().contentPaddingAddition.isPresent
                ) {
                    "amneziawg_3"
                } else {
                    "wireguard"
                }
                val preparedAwg3Profile = if (transport == "amneziawg_3") {
                    Awg3ProfileSnapshot.fromInterface(config.getInterface())
                } else {
                    null
                }
                preparedAwg3Profile?.let { profile ->
                    logAwg3Profile("start.awg3_profile_prepared", profile)
                    val received = checkNotNull(receivedAwg3Profile) {
                        "awg3_received_profile_unavailable"
                    }
                    val differingFields = received.differingFields(profile)
                    if (differingFields.isNotEmpty()) {
                        TunnelLog.warning(
                            "start.awg3_profile_transform_mismatch",
                            "fields=${differingFields.joinToString(",")}",
                        )
                        throw TunnelOperationException("awg3_profile_transform_mismatch")
                    }
                }
                val monitor = PhysicalNetworks(context)
                val physicalState = monitor.snapshotState()
                val localRoutes = if (options.splitSupported && options.excludeLocalNetworks) {
                    physicalState.localRoutes
                } else {
                    emptyList()
                }
                NelomaiVpnService.setPhysicalNetworks(physicalState.networks)
                AndroidSplitTunnel.replaceVpnRoutes(
                    AndroidSplitTunnel.mergeExcludedRoutes(
                        options.excludedRoutes,
                        localRoutes,
                    ),
                    config.getInterface().getDnsServers().toList(),
                )
                logStage(
                    "start.options_ready",
                    optionsStartedAt,
                    "split_supported=${options.splitSupported} local_routes=${localRoutes.size}",
                )
                TunnelLog.info(
                    "start.split_options",
                    mapOf(
                        "source" to args.startSource,
                        "transport" to transport,
                        "backend_version" to diagnosticBackendVersion(requireBackend().version),
                        "application_mode" to args.options.applicationMode,
                        "included_packages_count" to options.includedPackages.size,
                        "excluded_packages_count" to options.excludedPackages.size,
                        "excluded_routes_count" to options.excludedRoutes.size,
                        "local_routes_count" to localRoutes.size,
                        "exclude_local_networks" to options.excludeLocalNetworks,
                        "policy_hash" to args.options.policyHash,
                        "dns_servers" to config.getInterface().getDnsServers()
                            .joinToString(",") { it.hostAddress ?: "unknown" },
                        "dns_forced_routes_count" to config.getInterface().getDnsServers().size,
                    ),
                )

                requireClientStartNotCancelled(args.clientOperationId)
                val backendStartedAt = System.nanoTime()
                var activeBackend = requireBackend()
                var state = activeBackend.setState(tunnel, Tunnel.State.UP, config)
                if (state == Tunnel.State.UP && preparedAwg3Profile != null) {
                    val firstRuntimeProfile = runtimeAwg3Profile(activeBackend)
                    if (!runtimeProfileMatches(preparedAwg3Profile, firstRuntimeProfile)) {
                        logAwg3Mismatch(
                            "start.awg3_runtime_profile_mismatch",
                            preparedAwg3Profile,
                            firstRuntimeProfile,
                            retry = false,
                        )
                        suppressBackendStateChanges.set(true)
                        try {
                            activeBackend.setState(tunnel, Tunnel.State.DOWN, null)
                            activeBackend = replaceBackend(applicationContext)
                            state = activeBackend.setState(tunnel, Tunnel.State.UP, config)
                        } finally {
                            suppressBackendStateChanges.set(false)
                        }
                        val retriedRuntimeProfile = if (state == Tunnel.State.UP) {
                            runtimeAwg3Profile(activeBackend)
                        } else {
                            null
                        }
                        if (
                            state != Tunnel.State.UP ||
                            !runtimeProfileMatches(preparedAwg3Profile, retriedRuntimeProfile)
                        ) {
                            logAwg3Mismatch(
                                "start.awg3_runtime_profile_mismatch",
                                preparedAwg3Profile,
                                retriedRuntimeProfile,
                                retry = true,
                            )
                            suppressBackendStateChanges.set(true)
                            try {
                                if (state == Tunnel.State.UP) {
                                    activeBackend.setState(tunnel, Tunnel.State.DOWN, null)
                                }
                            } finally {
                                suppressBackendStateChanges.set(false)
                            }
                            throw TunnelOperationException("awg3_profile_apply_failed")
                        }
                        TunnelLog.info(
                            "start.awg3_runtime_profile_recovered",
                            mapOf("fingerprint" to preparedAwg3Profile.fingerprint),
                        )
                    } else {
                        TunnelLog.info(
                            "start.awg3_runtime_profile_verified",
                            mapOf("fingerprint" to preparedAwg3Profile.fingerprint),
                        )
                    }
                }
                if (state == Tunnel.State.UP && isClientStartCancelled(args.clientOperationId)) {
                    suppressBackendStateChanges.set(true)
                    try {
                        requireState(
                            requireBackend().setState(tunnel, Tunnel.State.DOWN, null),
                            Tunnel.State.DOWN,
                        )
                    } finally {
                        suppressBackendStateChanges.set(false)
                    }
                    AndroidSplitTunnel.clear()
                    throw TunnelOperationException("tunnel_start_cancelled")
                }
                if (state == Tunnel.State.UP) {
                    NelomaiVpnService.setPhysicalNetworks(physicalState.networks)
                }
                logStage("start.backend_state_up", backendStartedAt)
                val resolved = if (state == Tunnel.State.UP) {
                    val session = ActiveTunnelSession(
                        generation = generation.incrementAndGet(),
                        clientOperationId = args.clientOperationId,
                        config = config,
                        options = options,
                        monitor = monitor,
                        localRoutes = localRoutes,
                        observedNetworkFingerprint = physicalState.fingerprint,
                        networkWasUnavailable = !physicalState.available,
                        transport = transport,
                    )
                    activeSession = session
                    try {
                        monitor.start { networkState ->
                            reapplyPhysicalNetworks(session.generation, networkState)
                        }
                        scheduleDataPlaneDiagnostics(session.generation)
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
                if (resolved == SessionState.RUNNING) {
                    runCatching { AutomaticDiagnostics.onTunnelStarted(applicationContext) }
                        .onFailure { TunnelLog.warning("diagnostics.lifecycle_failed", error = it) }
                }
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
            } finally {
                completeOperationWatchdog(watchdog)
            }
        }
    }

    fun cancelClientStart(context: Context, clientOperationId: String) {
        cancelledClientStarts.add(clientOperationId)
        executor.execute {
            val session = activeSession
            if (
                stateGate.current() != SessionState.RUNNING ||
                !shouldCancelActiveClientStart(clientOperationId, session?.clientOperationId)
            ) {
                cancelledClientStarts.remove(clientOperationId)
                return@execute
            }
            val applicationContext = context.applicationContext
            QuickTunnelController.updateState(
                applicationContext,
                SessionState.STOPPING,
                desiredActive = false,
            )
            stop(
                TUNNEL_API_VERSION,
                { state, _ ->
                    cancelledClientStarts.remove(clientOperationId)
                    QuickTunnelController.updateState(
                        applicationContext,
                        state,
                        desiredActive = false,
                        changed = true,
                    )
                    TunnelPlugin.refreshQuickTile(applicationContext)
                },
                { code ->
                    cancelledClientStarts.remove(clientOperationId)
                    TunnelLog.warning("client_start.cancel_failed", code)
                    val state = state()
                    QuickTunnelController.updateState(
                        applicationContext,
                        state,
                        desiredActive = state == SessionState.RUNNING,
                        changed = true,
                    )
                    TunnelPlugin.refreshQuickTile(applicationContext)
                },
            )
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
                    startSource = "background"
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

    fun updateQuickDns(context: Context, dnsServers: List<String>): Boolean {
        val args = TunnelOptionsArgs().apply {
            this.dnsServers = ArrayList(dnsServers)
        }
        val normalized = AndroidSplitTunnel.resolveOptions(0, args)
            .dnsServers
            .mapNotNull { it.hostAddress }
        return QuickTunnelPlanStore.updateDnsServers(context.applicationContext, normalized)
    }

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
                applicationContext?.let { context ->
                    runCatching { AutomaticDiagnostics.onTunnelStopped(context) }
                        .onFailure { TunnelLog.warning("diagnostics.lifecycle_failed", error = it) }
                }
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

        val watchdog = armOperationWatchdog(
            checkNotNull(applicationContext) { "tunnel_context_unavailable" },
            "stop",
        )
        executor.execute {
            val startedAt = System.nanoTime()
            TunnelLog.info("stop.begin")
            try {
                activeSession?.let { logDataPlaneSnapshot(it, "tunnel_stopping") }
                clearActiveSession()
                suppressBackendStateChanges.set(true)
                val state = try {
                    requireBackend().setState(tunnel, Tunnel.State.DOWN, null)
                } finally {
                    suppressBackendStateChanges.set(false)
                }
                AndroidSplitTunnel.clear()
                val resolved = if (state == Tunnel.State.DOWN) {
                    SessionState.STOPPED
                } else {
                    SessionState.FAILED
                }
                stateGate.complete(resolved)
                logStage("stop.completed", startedAt, "state=${resolved.wireName}")
                if (resolved == SessionState.STOPPED) {
                    applicationContext?.let { context ->
                        runCatching { AutomaticDiagnostics.onTunnelStopped(context) }
                            .onFailure { TunnelLog.warning("diagnostics.lifecycle_failed", error = it) }
                    }
                    if (!keepForegroundService) {
                        NelomaiVpnService.stopForegroundService()
                    }
                }
                onSuccess(resolved, elapsedMillis(startedAt))
            } catch (error: Throwable) {
                AndroidSplitTunnel.clear()
                stateGate.complete(SessionState.FAILED)
                val code = errorCode(error)
                TunnelLog.warning("stop.failed", code, error)
                onError(code)
            } finally {
                completeOperationWatchdog(watchdog)
            }
        }
    }

    fun metrics(
        apiVersion: Int,
        probe: Boolean,
        onSuccess: (Long, Long, Long?, String?) -> Unit,
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
                val latestHandshakeEpochMillis = statistics.peers()
                    .mapNotNull { key -> statistics.peer(key)?.latestHandshakeEpochMillis() }
                    .filter { it > 0 }
                    .maxOrNull()
                val target = if (probe) {
                    session.config.peers.firstOrNull()?.endpoint?.orElse(null)?.host
                } else {
                    null
                }
                onSuccess(
                    statistics.totalRx(),
                    statistics.totalTx(),
                    latestHandshakeEpochMillis,
                    target,
                )
            } catch (error: Throwable) {
                onError(errorCode(error))
            }
        }
    }

    private fun requireBackend(): GoBackend =
        backend ?: error("tunnel_backend_unavailable")

    private fun createBackend(context: Context): GoBackend {
        runCatching {
            Os.setenv("GOMEMLIMIT", GO_BACKEND_MEMORY_LIMIT, false)
        }.onFailure {
            TunnelLog.warning("backend.memory_limit_failed", error = it)
        }
        return GoBackend(context.applicationContext)
    }

    private fun replaceBackend(context: Context): GoBackend = synchronized(this) {
        createBackend(context).also { replacement -> backend = replacement }
    }

    private fun runtimeAwg3Profile(activeBackend: GoBackend): Awg3ProfileSnapshot? {
        val field = activeTunnelHandleField.getOrElse { error ->
            TunnelLog.warning("start.awg3_runtime_handle_unavailable", error = error)
            return null
        }
        val handle = runCatching { field.getInt(activeBackend) }.getOrElse { error ->
            TunnelLog.warning("start.awg3_runtime_handle_unavailable", error = error)
            return null
        }
        if (handle < 0) return null
        // The raw UAPI response contains private and preshared keys. Keep it in-memory
        // only long enough to extract the allowlisted AWG3 profile fields.
        return org.amnezia.awg.GoBackend.awgGetConfig(handle)
            ?.let(Awg3ProfileSnapshot::fromUserspace)
    }

    private fun runtimeProfileMatches(
        expected: Awg3ProfileSnapshot,
        actual: Awg3ProfileSnapshot?,
    ): Boolean = actual != null && expected.differingFields(actual).isEmpty()

    private fun logAwg3Profile(event: String, profile: Awg3ProfileSnapshot) {
        TunnelLog.info(
            event,
            mapOf(
                "fingerprint" to profile.fingerprint,
                "parameters" to profile.safeSummary,
            ),
        )
    }

    private fun logAwg3Mismatch(
        event: String,
        expected: Awg3ProfileSnapshot,
        actual: Awg3ProfileSnapshot?,
        retry: Boolean,
    ) {
        TunnelLog.warning(
            event,
            listOfNotNull(
                "retry=$retry",
                "expected=${expected.fingerprint}",
                "actual=${actual?.fingerprint ?: "unavailable"}",
                "fields=${actual?.let(expected::differingFields)?.joinToString(",") ?: "runtime_config"}",
            ).joinToString(" "),
        )
    }

    private fun armOperationWatchdog(
        context: Context,
        operation: String,
    ): TunnelOperationWatchdog {
        val generation = watchdogGate.begin()
        val future = watchdogExecutor.schedule(
            {
                if (!watchdogGate.expire(generation)) return@schedule
                terminateHungTunnelProcess(context, operation)
            },
            TUNNEL_OPERATION_WATCHDOG_MILLIS,
            TimeUnit.MILLISECONDS,
        )
        return TunnelOperationWatchdog(generation, future)
    }

    private fun terminateHungTunnelProcess(context: Context, operation: String) {
        val processId = android.os.Process.myPid()
        Thread(
            {
                try {
                    Thread.sleep(1_000)
                } finally {
                    android.os.Process.killProcess(processId)
                }
            },
            "nelomai-tunnel-watchdog-failsafe",
        ).apply { isDaemon = false }.start()
        try {
            TunnelLog.warning(
                "tunnel.operation_watchdog_expired",
                "${operation}_timeout",
            )
            QuickTunnelController.updateState(
                context.applicationContext,
                SessionState.STOPPED,
                desiredActive = false,
                changed = true,
            )
        } finally {
            android.os.Process.killProcess(processId)
        }
    }

    private fun completeOperationWatchdog(watchdog: TunnelOperationWatchdog) {
        if (watchdogGate.complete(watchdog.generation)) {
            watchdog.future.cancel(false)
        }
    }

    fun serviceDestroyed() {
        stateGate.complete(SessionState.STOPPED)
        clearActiveSession()
        AndroidSplitTunnel.clear()
    }

    fun releaseBackend() {
        if (stateGate.current() != SessionState.STOPPED || activeSession != null) return
        synchronized(this) {
            if (stateGate.current() == SessionState.STOPPED && activeSession == null) {
                backend = null
            }
        }
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
                logDataPlaneSnapshot(session, "physical_network_unavailable")
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
            logDataPlaneSnapshot(session, "physical_network_changed")
            applicationContext?.let { context ->
                runCatching { AutomaticDiagnostics.onPhysicalNetworkChanged(context) }
                    .onFailure {
                        TunnelLog.warning("diagnostics.memory_snapshot_failed", error = it)
                    }
            }
        }
    }

    private fun clearActiveSession() {
        dataPlaneFuture?.cancel(false)
        dataPlaneFuture = null
        val session = activeSession
        activeSession = null
        generation.incrementAndGet()
        session?.monitor?.stop()
    }

    private fun scheduleDataPlaneDiagnostics(sessionGeneration: Long) {
        dataPlaneFuture?.cancel(false)
        dataPlaneFuture = watchdogExecutor.scheduleAtFixedRate(
            {
                executor.execute {
                    val session = activeSession
                        ?.takeIf { it.generation == sessionGeneration }
                        ?: return@execute
                    if (stateGate.current() == SessionState.RUNNING) {
                        logDataPlaneSnapshot(session, "periodic")
                    }
                }
            },
            5,
            DATA_PLANE_DIAGNOSTICS_INTERVAL_SECONDS,
            TimeUnit.SECONDS,
        )
    }

    private fun logDataPlaneSnapshot(session: ActiveTunnelSession, reason: String) {
        try {
            val statistics = requireBackend().getStatistics(tunnel)
            val receivedBytes = statistics.totalRx()
            val sentBytes = statistics.totalTx()
            val receivedDelta = counterDelta(session.lastDiagnosticsReceivedBytes, receivedBytes)
            val sentDelta = counterDelta(session.lastDiagnosticsSentBytes, sentBytes)
            val latestHandshakeEpochMillis = statistics.peers()
                .mapNotNull { key -> statistics.peer(key)?.latestHandshakeEpochMillis() }
                .filter { it > 0 }
                .maxOrNull()
            val uptimeSeconds = (
                SystemClock.elapsedRealtime() - session.startedAtElapsedMillis
            ).coerceAtLeast(0) / 1_000L
            session.lastDiagnosticsReceivedBytes = receivedBytes
            session.lastDiagnosticsSentBytes = sentBytes
            TunnelLog.info(
                "tunnel.data_plane_snapshot",
                mapOf(
                    "reason" to reason.take(64),
                    "transport" to session.transport,
                    "uptime_seconds" to uptimeSeconds,
                    "received_bytes" to receivedBytes,
                    "sent_bytes" to sentBytes,
                    "received_delta_bytes" to receivedDelta,
                    "sent_delta_bytes" to sentDelta,
                    "latest_handshake_epoch_millis" to latestHandshakeEpochMillis,
                    "handshake_age_seconds" to latestHandshakeEpochMillis?.let {
                        ((System.currentTimeMillis() - it).coerceAtLeast(0)) / 1_000L
                    },
                    "state" to tunnelDataPlaneState(
                        uptimeSeconds,
                        latestHandshakeEpochMillis,
                        receivedDelta,
                        sentDelta,
                    ),
                ),
            )
        } catch (error: Throwable) {
            TunnelLog.warning("tunnel.data_plane_snapshot_failed", error = error)
        }
    }

    private fun requireState(actual: Tunnel.State, expected: Tunnel.State) {
        if (actual != expected) {
            throw TunnelOperationException("unexpected_tunnel_state")
        }
    }

    private fun isClientStartCancelled(clientOperationId: String?): Boolean =
        clientOperationId != null && cancelledClientStarts.contains(clientOperationId)

    private fun requireClientStartNotCancelled(clientOperationId: String?) {
        if (isClientStartCancelled(clientOperationId)) {
            throw TunnelOperationException("tunnel_start_cancelled")
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

internal fun counterDelta(previous: Long?, current: Long): Long = when {
    previous == null -> current
    current >= previous -> current - previous
    else -> current
}

internal fun tunnelDataPlaneState(
    uptimeSeconds: Long,
    latestHandshakeEpochMillis: Long?,
    receivedDeltaBytes: Long,
    sentDeltaBytes: Long,
): String = when {
    latestHandshakeEpochMillis == null -> "waiting_for_handshake"
    receivedDeltaBytes > 0 || sentDeltaBytes > 0 -> "encrypted_counter_activity"
    uptimeSeconds >= 30 -> "handshake_without_counter_activity"
    else -> "handshake_idle"
}

private const val DATA_PLANE_DIAGNOSTICS_INTERVAL_SECONDS = 5L * 60L
private const val PINNED_AWG_GO_BACKEND_BUILD = "git-08d68cd"
private const val GO_BACKEND_MEMORY_LIMIT = "256MiB"

internal fun diagnosticBackendVersion(reported: String?): String = reported
    ?.trim()
    ?.takeIf { it.isNotEmpty() && it != "(devel)" && it != "unknown" }
    ?: PINNED_AWG_GO_BACKEND_BUILD

internal fun shouldRecycleIdleVpnProcess(
    state: SessionState,
    desiredActive: Boolean,
): Boolean = state == SessionState.STOPPED && !desiredActive

private class TunnelOperationException(val code: String) : RuntimeException()

internal fun shouldCancelActiveClientStart(
    requestedOperationId: String,
    activeOperationId: String?,
): Boolean = requestedOperationId == activeOperationId

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
        copy.startSource = startSource
        copy.configuration = byteArrayOf()
        copy.options = TunnelOptionsArgs().also { optionsCopy ->
            optionsCopy.splitActive = options.splitActive
            optionsCopy.policyHash = options.policyHash
            optionsCopy.applicationMode = options.applicationMode
            optionsCopy.excludedPackages = ArrayList(options.excludedPackages)
            optionsCopy.includedPackages = ArrayList(options.includedPackages)
            optionsCopy.splitTunnelRoutes = ArrayList(options.splitTunnelRoutes)
            optionsCopy.excludeLocalNetworks = options.excludeLocalNetworks
            optionsCopy.dnsServers = ArrayList(options.dnsServers)
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
    private val quickStateChangeGate: QuickStateChangeGate
        get() = QuickStateChangeNotifications.gate

    override fun load(webView: WebView) {
        QuickStateChangeNotifications.initialize(activity.applicationContext)
    }

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
            response.put(
                "backendVersion",
                diagnosticBackendVersion(GoBackend(activity.applicationContext).version),
            )
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
        val response = JSObject()
        var available = false
        runCatching {
            activity.getSystemService(SystemHealthManager::class.java).takeMyUidSnapshot()
        }.getOrNull()?.let { stats ->
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
            available = true
        }
        runCatching { androidProcessMemory(activity.applicationContext) }.getOrNull()?.let { processes ->
            response.put("processes", processes)
            available = true
        }
        if (available) {
            invoke.resolve(response)
        } else {
            invoke.reject("resource_usage_unavailable")
        }
    }

    @Command
    fun clearQuickPlan(invoke: Invoke) {
        TunnelServiceClient.clearQuickPlan(
            activity.applicationContext,
            {
                quickStateChangeGate.clearPending()
                activity.runOnUiThread { invoke.resolve() }
            },
            { code -> activity.runOnUiThread { invoke.reject(code) } },
        )
    }

    @Command
    fun updateQuickDns(invoke: Invoke) {
        val args = try {
            invoke.parseArgs(DnsServersArgs::class.java)
        } catch (_: Throwable) {
            invoke.reject("invalid_dns_servers")
            return
        }
        TunnelServiceClient.updateQuickDns(
            activity.applicationContext,
            args.dnsServers,
            { activity.runOnUiThread { invoke.resolve() } },
            { code -> activity.runOnUiThread { invoke.reject(code) } },
        )
    }

    @Command
    fun queueStartFailureDiagnostics(invoke: Invoke) {
        val args = try {
            invoke.parseArgs(StartFailureDiagnosticsArgs::class.java)
        } catch (_: Throwable) {
            invoke.reject("invalid_start_failure_diagnostics")
            return
        }
        val deviceId = runCatching { UUID.fromString(args.deviceId).toString() }.getOrNull()
        if (deviceId == null || deviceId != args.deviceId) {
            invoke.reject("invalid_start_failure_diagnostics")
            return
        }
        AutomaticDiagnostics.onConnectionStartFailed(
            activity.applicationContext,
            deviceId,
            args.errorCode.take(80),
        ) { error ->
            activity.runOnUiThread {
                if (error == null) {
                    invoke.resolve()
                } else {
                    invoke.reject("start_failure_diagnostics_unavailable")
                }
            }
        }
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
            { configured, deviceId, expiresAtUnix ->
                activity.runOnUiThread {
                    val response = JSObject()
                    response.put("configured", configured)
                    response.put("deviceId", deviceId)
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
        val response = JSObject()
        response.put("changed", quickStateChangeGate.current())
        response.put("revision", quickStateChangeGate.snapshot())
        invoke.resolve(response)
    }

    @Command
    fun acknowledgeQuickStateChange(invoke: Invoke) {
        val args = try {
            invoke.parseArgs(QuickStateChangeAcknowledgeArgs::class.java)
        } catch (_: Throwable) {
            invoke.reject("invalid_quick_state_revision")
            return
        }
        val acknowledgedRevision = args.revision.coerceAtLeast(0L)
        TunnelServiceClient.acknowledgeQuickStateChange(
            activity.applicationContext,
            acknowledgedRevision,
            { pendingRevision ->
                quickStateChangeGate.observe(pendingRevision)
                quickStateChangeGate.acknowledgeThrough(acknowledgedRevision)
                activity.runOnUiThread { invoke.resolve() }
            },
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
            { received, sent, latestHandshakeEpochMillis, target ->
                activity.runOnUiThread {
                    val response = JSObject()
                    response.put("receivedBytes", received)
                    response.put("sentBytes", sent)
                    response.put("latestHandshakeEpochMillis", latestHandshakeEpochMillis)
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
