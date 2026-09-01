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
import java.util.ArrayDeque
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import org.json.JSONArray
import org.json.JSONObject

internal const val TUNNEL_API_VERSION = 2
private const val TUNNEL_NAME = "nelomai"
private const val QUICK_TILE_SERVICE = "ru.nelomai.client.NelomaiQuickTileService"
private const val TUNNEL_OPERATION_WATCHDOG_MILLIS = 40_000L
private const val METRICS_OPERATION_WATCHDOG_MILLIS = 1_500L
private const val UDP_REBIND_QUEUE_TIMEOUT_MILLIS = 500L
private const val UDP_REBIND_OPERATION_WATCHDOG_MILLIS = 2_500L

private fun endpointPort(endpoint: String?): Int? {
    val value = endpoint?.trim().orEmpty()
    if (value.isEmpty()) return null
    return value.substringAfterLast(':', "").toIntOrNull()?.takeIf { it in 1..65_535 }
}

internal fun diagnosticNetworkError(error: String?): String? {
    val normalized = error?.trim()?.lowercase().orEmpty()
    if (normalized.isEmpty()) return null
    return when {
        "network is unreachable" in normalized || "network unreachable" in normalized ->
            "network_unreachable"
        "no route to host" in normalized || "host is unreachable" in normalized ||
            "host unreachable" in normalized -> "host_unreachable"
        "connection refused" in normalized -> "connection_refused"
        "permission denied" in normalized || "operation not permitted" in normalized ->
            "permission_denied"
        "address not available" in normalized || "cannot assign requested address" in normalized ->
            "address_unavailable"
        "network is down" in normalized || "network down" in normalized -> "network_down"
        "timed out" in normalized || "timeout" in normalized -> "timeout"
        "socket closed" in normalized || "closed network connection" in normalized ->
            "socket_closed"
        else -> "network_io_error"
    }
}

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
    var redundancy: RedundantStartArgs? = null
}

@InvokeArg
class RedundantHealthProbeArgs {
    lateinit var kind: String
    lateinit var targetIpv4: String
    lateinit var queryName: String
    var timeoutMs: Long = 0
}

@InvokeArg
class RedundantMemberArgs {
    lateinit var slot: String
    lateinit var leaseId: String
    var healthProbe: RedundantHealthProbeArgs? = null
}

@InvokeArg
class RedundantStandbyArgs {
    var member: RedundantMemberArgs = RedundantMemberArgs()
    lateinit var configuration: ByteArray
}

@InvokeArg
class RedundantStartArgs {
    lateinit var sessionId: String
    lateinit var operationId: String
    lateinit var requestFingerprint: String
    var reserveEnabled: Boolean = false
    lateinit var virtualAddressV4: String
    var standbyDesired: Boolean = false
    lateinit var activeLeaseId: String
    lateinit var localActiveLeaseId: String
    var roleGeneration: Long = 0
    var membershipGeneration: Long = 0
    var primary: RedundantMemberArgs = RedundantMemberArgs()
    var standby: RedundantStandbyArgs? = null
}

@InvokeArg
class QuickConnectionArgs {
    lateinit var leaseId: String
    lateinit var layer: String
    lateinit var ticConnectionMode: String
    lateinit var routeMode: String
    var egressMode: String = "ipv4"
    var allowAlternate: Boolean = false
}

@InvokeArg
class BackgroundCredentialArgs {
    var apiVersion: Int = 0
    var expectedRevision: Long = 0
    lateinit var deviceId: String
    lateinit var panelBase: String
    lateinit var token: String
    var expiresAtUnix: Long = 0
    lateinit var installSecret: String
    var capabilityRevision: Long = 0
    var capabilityEnabled: Boolean = false
    lateinit var capabilityExpiresAt: String
}

@InvokeArg
class BackgroundCredentialMutationArgs {
    var expectedRevision: Long = -1
}

@InvokeArg
class BackgroundUiProvisionArgs {
    var apiVersion: Int = 0
    var expectedRevision: Long = -1
    lateinit var deviceId: String
    lateinit var panelBase: String
    lateinit var accessToken: String
    lateinit var installSecret: String
    var capabilityRevision: Long = 0
    var capabilityEnabled: Boolean = false
    lateinit var capabilityExpiresAt: String
}

@InvokeArg
class BackgroundSessionRecoveryArgs {
    lateinit var installSecret: String
}

@InvokeArg
class ConnectionIntentTemplateArgs {
    lateinit var deviceId: String
    lateinit var accountScope: String
    lateinit var layer: String
    lateinit var ticConnectionMode: String
    lateinit var routeMode: String
    lateinit var egressMode: String
    var allowAlternate: Boolean = false
    var syncBindingPreferences: Boolean = false
    var options: TunnelOptionsArgs = TunnelOptionsArgs()
}

@InvokeArg
class BeginConnectionIntentArgs {
    var apiVersion: Int = 0
    var template: ConnectionIntentTemplateArgs = ConnectionIntentTemplateArgs()
}

@InvokeArg
class CancelConnectionIntentArgs {
    var generation: Long = -1
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
    private enum class GateState {
        STOPPED,
        STARTING,
        RUNNING,
        STOPPING,
        FAILED,
        REBINDING,
    }

    private val state = AtomicReference(initialState.toGateState())

    fun current(): SessionState = state.get().toSessionState()

    fun beginStart(): TransitionDecision {
        while (true) {
            when (val current = state.get()) {
                GateState.RUNNING -> {
                    if (state.compareAndSet(current, GateState.STARTING)) {
                        return TransitionDecision.REPLACE
                    }
                }
                GateState.STARTING, GateState.STOPPING, GateState.REBINDING -> {
                    return TransitionDecision.BUSY
                }
                GateState.STOPPED -> {
                    if (state.compareAndSet(current, GateState.STARTING)) {
                        return TransitionDecision.PROCEED
                    }
                }
                GateState.FAILED -> {
                    if (state.compareAndSet(current, GateState.STARTING)) {
                        return TransitionDecision.REPLACE
                    }
                }
            }
        }
    }

    fun beginStop(): TransitionDecision {
        while (true) {
            when (val current = state.get()) {
                GateState.STOPPED -> return TransitionDecision.ALREADY_COMPLETE
                GateState.STOPPING, GateState.REBINDING -> return TransitionDecision.BUSY
                GateState.STARTING -> {
                    if (state.compareAndSet(current, GateState.STOPPING)) {
                        return TransitionDecision.PROCEED
                    }
                }
                GateState.RUNNING, GateState.FAILED -> {
                    if (state.compareAndSet(current, GateState.STOPPING)) {
                        return TransitionDecision.PROCEED
                    }
                }
            }
        }
    }

    fun beginRebind(): TransitionDecision {
        while (true) {
            when (val current = state.get()) {
                GateState.RUNNING -> {
                    if (state.compareAndSet(current, GateState.REBINDING)) {
                        return TransitionDecision.PROCEED
                    }
                }
                GateState.STARTING, GateState.STOPPING, GateState.REBINDING -> {
                    return TransitionDecision.BUSY
                }
                GateState.STOPPED, GateState.FAILED -> {
                    return TransitionDecision.ALREADY_COMPLETE
                }
            }
        }
    }

    fun cancelRebind(): Boolean =
        state.compareAndSet(GateState.REBINDING, GateState.RUNNING)

    fun complete(next: SessionState) {
        state.set(next.toGateState())
    }

    private fun SessionState.toGateState(): GateState = when (this) {
        SessionState.STOPPED -> GateState.STOPPED
        SessionState.STARTING -> GateState.STARTING
        SessionState.RUNNING -> GateState.RUNNING
        SessionState.STOPPING -> GateState.STOPPING
        SessionState.FAILED -> GateState.FAILED
    }

    private fun GateState.toSessionState(): SessionState = when (this) {
        GateState.STOPPED -> SessionState.STOPPED
        GateState.STARTING, GateState.REBINDING -> SessionState.STARTING
        GateState.RUNNING -> SessionState.RUNNING
        GateState.STOPPING -> SessionState.STOPPING
        GateState.FAILED -> SessionState.FAILED
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

internal enum class TunnelOperationWatchdogScope {
    LIFECYCLE,
    METRICS,
}

internal data class TunnelOperationWatchdogToken(
    val scope: TunnelOperationWatchdogScope,
    val generation: Long,
)

internal class TunnelOperationWatchdogGates {
    private val lifecycle = TunnelOperationWatchdogGate()
    private val metrics = TunnelOperationWatchdogGate()

    fun begin(scope: TunnelOperationWatchdogScope): TunnelOperationWatchdogToken =
        TunnelOperationWatchdogToken(scope, gate(scope).begin())

    fun complete(token: TunnelOperationWatchdogToken): Boolean =
        gate(token.scope).complete(token.generation)

    fun expire(token: TunnelOperationWatchdogToken): Boolean =
        gate(token.scope).expire(token.generation)

    private fun gate(scope: TunnelOperationWatchdogScope): TunnelOperationWatchdogGate =
        when (scope) {
            TunnelOperationWatchdogScope.LIFECYCLE -> lifecycle
            TunnelOperationWatchdogScope.METRICS -> metrics
        }
}

internal class RebindQueueGate {
    private enum class State {
        QUEUED,
        RUNNING,
        CANCELLED,
    }

    private val state = AtomicReference(State.QUEUED)

    fun begin(): Boolean = state.compareAndSet(State.QUEUED, State.RUNNING)

    fun cancel(): Boolean = state.compareAndSet(State.QUEUED, State.CANCELLED)
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
    val connectionLeaseId: String?,
    val startedAtElapsedMillis: Long = SystemClock.elapsedRealtime(),
    var lastDiagnosticsReceivedBytes: Long? = null,
    var lastDiagnosticsSentBytes: Long? = null,
    var lastNetworkTelemetry: NetworkTelemetry? = null,
    var lastNetworkTelemetryPollElapsedMillis: Long? = null,
    val recentNetworkTelemetry: ArrayDeque<JSONObject> = ArrayDeque(),
    var lastTunActivityElapsedMillis: Long = startedAtElapsedMillis,
    var lastTunWriteActivityElapsedMillis: Long = startedAtElapsedMillis,
    var lastUdpReceiveElapsedMillis: Long = startedAtElapsedMillis,
    var udpStallStartedElapsedMillis: Long? = null,
    var lastUdpRecoveryElapsedMillis: Long? = null,
    var udpRecoveryArmed: Boolean = true,
    var udpRecoveryAttempts: Int = 0,
    var pendingUdpControlProbe: PendingUdpControlProbe? = null,
    var lastDataPlaneSnapshotElapsedMillis: Long = startedAtElapsedMillis,
    var lastTelemetryErrorLoggedElapsedMillis: Long = 0,
    var networkIncidentCount: Int = 0,
    var openNetworkIncidentElapsedMillis: Long? = null,
)

internal enum class UdpControlProbeStage {
    BEFORE_REBIND,
    AFTER_REBIND,
}

internal enum class UdpControlProbeAction {
    MARK_TRANSPORT_REACHABLE,
    REBIND,
    RETRY,
    STOP,
}

internal enum class NetworkTelemetryMode {
    DISABLED,
    PASSIVE,
    UDP_RECOVERY,
}

internal fun networkTelemetryMode(transport: String): NetworkTelemetryMode = when (transport) {
    "wireguard" -> NetworkTelemetryMode.PASSIVE
    "amneziawg_3" -> NetworkTelemetryMode.UDP_RECOVERY
    else -> NetworkTelemetryMode.DISABLED
}

internal fun shouldPollNetworkTelemetry(
    mode: NetworkTelemetryMode,
    nowElapsedMillis: Long,
    lastPollElapsedMillis: Long?,
): Boolean = when (mode) {
    NetworkTelemetryMode.DISABLED -> false
    NetworkTelemetryMode.UDP_RECOVERY -> true
    NetworkTelemetryMode.PASSIVE -> lastPollElapsedMillis == null ||
        nowElapsedMillis < lastPollElapsedMillis ||
        nowElapsedMillis - lastPollElapsedMillis >= PASSIVE_NETWORK_TELEMETRY_INTERVAL_MILLIS
}

internal fun shouldPersistPeriodicNetworkTelemetry(mode: NetworkTelemetryMode): Boolean =
    mode == NetworkTelemetryMode.PASSIVE

internal fun handOffDataPlaneStall(
    leaseId: String?,
    handoff: (String) -> Boolean,
    fallback: () -> Unit,
): Boolean {
    if (leaseId != null && handoff(leaseId)) return true
    fallback()
    return false
}

private data class PendingUdpControlProbe(
    val stage: UdpControlProbeStage,
    val generation: Long,
    val startedAtElapsedMillis: Long,
    val evaluateAtElapsedMillis: Long,
    val tunWriteBytesBefore: Long,
    val udpReceiveBytesBefore: Long,
    val localPortBefore: Int,
    val localPortAfter: Int,
)

internal data class NetworkTelemetry(
    val tunReadPackets: Long,
    val tunReadBytes: Long,
    val tunReadErrors: Long,
    val tunWritePackets: Long,
    val tunWriteBytes: Long,
    val tunWriteErrors: Long,
    val udpSendCalls: Long,
    val udpSendPackets: Long,
    val udpSendBytes: Long,
    val udpSendErrors: Long,
    val udpReceiveCalls: Long,
    val udpReceivePackets: Long,
    val udpReceiveBytes: Long,
    val udpReceiveErrors: Long,
    val localPort: Int,
    val lastTunReadAtUnixMillis: Long,
    val lastTunWriteAtUnixMillis: Long,
    val lastUdpSendAtUnixMillis: Long,
    val lastUdpReceiveAtUnixMillis: Long,
    val lastUdpSendError: String?,
    val lastUdpReceiveError: String?,
    val lastUdpSendErrno: Int?,
    val lastUdpReceiveErrno: Int?,
    val endpoint: String?,
    val goHeapAllocBytes: Long,
    val goHeapSysBytes: Long,
    val goHeapIdleBytes: Long,
    val goHeapInuseBytes: Long,
    val goHeapReleasedBytes: Long,
    val goStackInuseBytes: Long,
    val goGcCycles: Long,
    val goMemoryLimitBytes: Long,
    val goDeviceStarts: Long,
    val goDeviceStartFailures: Long,
    val goDeviceCloses: Long,
    val goDevicesStarting: Long,
    val goActiveDevices: Int,
) {
    companion object {
        fun fromJson(value: String): NetworkTelemetry {
            val payload = JSONObject(value)
            return NetworkTelemetry(
                tunReadPackets = payload.getLong("tun_read_packets"),
                tunReadBytes = payload.getLong("tun_read_bytes"),
                tunReadErrors = payload.getLong("tun_read_errors"),
                tunWritePackets = payload.getLong("tun_write_packets"),
                tunWriteBytes = payload.getLong("tun_write_bytes"),
                tunWriteErrors = payload.getLong("tun_write_errors"),
                udpSendCalls = payload.getLong("udp_send_calls"),
                udpSendPackets = payload.getLong("udp_send_packets"),
                udpSendBytes = payload.getLong("udp_send_bytes"),
                udpSendErrors = payload.getLong("udp_send_errors"),
                udpReceiveCalls = payload.getLong("udp_receive_calls"),
                udpReceivePackets = payload.getLong("udp_receive_packets"),
                udpReceiveBytes = payload.getLong("udp_receive_bytes"),
                udpReceiveErrors = payload.getLong("udp_receive_errors"),
                localPort = payload.getInt("local_port"),
                lastTunReadAtUnixMillis = payload.getLong("last_tun_read_at_unix_ms"),
                lastTunWriteAtUnixMillis = payload.getLong("last_tun_write_at_unix_ms"),
                lastUdpSendAtUnixMillis = payload.getLong("last_udp_send_at_unix_ms"),
                lastUdpReceiveAtUnixMillis = payload.getLong("last_udp_receive_at_unix_ms"),
                lastUdpSendError = diagnosticNetworkError(
                    payload.optString("last_udp_send_error").takeIf(String::isNotBlank),
                ),
                lastUdpReceiveError = diagnosticNetworkError(
                    payload.optString("last_udp_receive_error").takeIf(String::isNotBlank),
                ),
                lastUdpSendErrno = payload.optInt("last_udp_send_errno")
                    .takeIf { it != 0 },
                lastUdpReceiveErrno = payload.optInt("last_udp_receive_errno")
                    .takeIf { it != 0 },
                endpoint = payload.optString("endpoint").takeIf(String::isNotBlank),
                goHeapAllocBytes = payload.optLong("go_heap_alloc_bytes"),
                goHeapSysBytes = payload.optLong("go_heap_sys_bytes"),
                goHeapIdleBytes = payload.optLong("go_heap_idle_bytes"),
                goHeapInuseBytes = payload.optLong("go_heap_inuse_bytes"),
                goHeapReleasedBytes = payload.optLong("go_heap_released_bytes"),
                goStackInuseBytes = payload.optLong("go_stack_inuse_bytes"),
                goGcCycles = payload.optLong("go_gc_cycles"),
                goMemoryLimitBytes = payload.optLong("go_memory_limit_bytes"),
                goDeviceStarts = payload.optLong("go_device_starts"),
                goDeviceStartFailures = payload.optLong("go_device_start_failures"),
                goDeviceCloses = payload.optLong("go_device_closes"),
                goDevicesStarting = payload.optLong("go_devices_starting"),
                goActiveDevices = payload.optInt("go_active_devices"),
            )
        }
    }
}

internal fun networkTelemetrySnapshotDetails(
    reason: String,
    sample: NetworkTelemetry?,
    recentSamples: List<JSONObject>?,
): Map<String, Any?> = buildMap {
    put("reason", reason.take(64))
    put("local_port", sample?.localPort)
    put("last_udp_send_error", sample?.lastUdpSendError)
    put("last_udp_receive_error", sample?.lastUdpReceiveError)
    put("last_udp_send_errno", sample?.lastUdpSendErrno)
    put("last_udp_receive_errno", sample?.lastUdpReceiveErrno)
    put("go_heap_alloc_bytes", sample?.goHeapAllocBytes)
    put("go_heap_sys_bytes", sample?.goHeapSysBytes)
    put("go_heap_idle_bytes", sample?.goHeapIdleBytes)
    put("go_heap_inuse_bytes", sample?.goHeapInuseBytes)
    put("go_heap_released_bytes", sample?.goHeapReleasedBytes)
    put("go_stack_inuse_bytes", sample?.goStackInuseBytes)
    put("go_gc_cycles", sample?.goGcCycles)
    put("go_memory_limit_bytes", sample?.goMemoryLimitBytes)
    put("go_device_starts", sample?.goDeviceStarts)
    put("go_device_start_failures", sample?.goDeviceStartFailures)
    put("go_device_closes", sample?.goDeviceCloses)
    put("go_devices_starting", sample?.goDevicesStarting)
    put("go_active_devices", sample?.goActiveDevices)
    recentSamples?.let { put("samples", JSONArray(it)) }
}

private data class TunnelOperationWatchdog(
    val token: TunnelOperationWatchdogToken,
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
    private val watchdogGates = TunnelOperationWatchdogGates()
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

    private val dataPlaneSampleQueued = AtomicBoolean(false)

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
            args.clearSensitiveConfigurations()
            quickPlan?.clearSensitiveConfigurations()
            onError(errorCode(error))
            return
        }
        val replaceExisting = when (stateGate.beginStart()) {
            TransitionDecision.REPLACE -> true
            TransitionDecision.BUSY -> {
                args.clearSensitiveConfigurations()
                quickPlan?.clearSensitiveConfigurations()
                onError("tunnel_operation_in_progress")
                return
            }
            TransitionDecision.PROCEED -> false
            TransitionDecision.ALREADY_COMPLETE -> error("unreachable_start_transition")
        }

        val watchdog = armOperationWatchdog(applicationContext, "start")
        executor.execute {
            val startedAt = System.nanoTime()
            val memoryBaselineRssBytes = processRssBytes(android.os.Process.myPid())
            var memoryDiagnosticsForFailure: TunnelStartMemoryDiagnostics? = null
            var startTransport: String? = null
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
                val memoryCaptureGeneration =
                    AutomaticDiagnostics.onTunnelStartAttempt(applicationContext)
                val startMemoryDiagnostics = TunnelStartMemoryDiagnostics(
                    memoryCaptureGeneration,
                    memoryBaselineRssBytes,
                )
                memoryDiagnosticsForFailure = startMemoryDiagnostics
                startMemoryDiagnostics.record(applicationContext, "start_begin")
                val parseStartedAt = System.nanoTime()
                startMemoryDiagnostics.record(applicationContext, "before_configuration_parse")
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
                startMemoryDiagnostics.record(applicationContext, "after_configuration_parse")
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
                startTransport = transport
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
                NelomaiVpnService.setPhysicalNetworks(
                    physicalState.networks,
                    physicalState.validated,
                )
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
                startMemoryDiagnostics.record(
                    applicationContext,
                    "after_split_options",
                    transport,
                )

                requireClientStartNotCancelled(args.clientOperationId)
                val backendStartedAt = System.nanoTime()
                var activeBackend = requireBackend()
                startMemoryDiagnostics.record(
                    applicationContext,
                    "before_backend_up",
                    transport,
                )
                var state = activeBackend.setState(tunnel, Tunnel.State.UP, config)
                startMemoryDiagnostics.record(
                    applicationContext,
                    "after_backend_up",
                    transport,
                )
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
                    NelomaiVpnService.setPhysicalNetworks(
                        physicalState.networks,
                        physicalState.validated,
                    )
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
                        connectionLeaseId = args.quickConnection?.leaseId,
                    )
                    activeSession = session
                    try {
                        runTunnelStartupPostActions(
                            required = {
                                monitor.start { networkState ->
                                    reapplyPhysicalNetworks(session.generation, networkState)
                                }
                                scheduleDataPlaneDiagnostics(session.generation)
                            },
                            optionalDiagnostics = {
                                scheduleTunnelStartMemoryDiagnostics(
                                    applicationContext,
                                    session.generation,
                                    startMemoryDiagnostics,
                                    transport,
                                )
                            },
                            onDiagnosticsFailure = {
                                TunnelLog.warning(
                                    "diagnostics.memory_start_schedule_failed",
                                    error = it,
                                )
                            },
                        )
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
                    runCatching {
                        AutomaticDiagnostics.onTunnelStarted(
                            applicationContext,
                            args.quickConnection?.leaseId,
                            transport,
                        )
                    }
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
                        quickPlan.clearSensitiveConfigurations()
                    }
                } else {
                    quickPlan?.clearSensitiveConfigurations()
                    if (!keepForegroundServiceOnFailure) {
                        runTunnelFailureCleanup(
                            optionalDiagnostics = {
                                startMemoryDiagnostics.recordFailure(
                                    applicationContext,
                                    transport,
                                )
                            },
                            requiredCleanup = NelomaiVpnService::stopForegroundService,
                            onDiagnosticsFailure = {
                                TunnelLog.warning(
                                    "diagnostics.memory_failure_capture_failed",
                                    error = it,
                                )
                            },
                        )
                    } else {
                        startMemoryDiagnostics.recordFailure(
                            applicationContext,
                            transport,
                        )
                    }
                }
                logStage("start.completed", startedAt, "state=${resolved.wireName}")
                onSuccess(resolved, elapsedMillis(startedAt))
            } catch (error: Throwable) {
                args.clearSensitiveConfigurations()
                quickPlan?.clearSensitiveConfigurations()
                AndroidSplitTunnel.clear()
                stateGate.complete(SessionState.FAILED)
                if (!keepForegroundServiceOnFailure) {
                    runTunnelFailureCleanup(
                        optionalDiagnostics = {
                            memoryDiagnosticsForFailure?.recordFailure(
                                applicationContext,
                                startTransport,
                            )
                        },
                        requiredCleanup = NelomaiVpnService::stopForegroundService,
                        onDiagnosticsFailure = {
                            TunnelLog.warning(
                                "diagnostics.memory_failure_capture_failed",
                                error = it,
                            )
                        },
                    )
                } else {
                    memoryDiagnosticsForFailure?.recordFailure(
                        applicationContext,
                        startTransport,
                    )
                }
                val code = errorCode(error)
                TunnelLog.warning(
                    "start.failed",
                    code,
                    error,
                )
                onError(code)
            } finally {
                args.clearSensitiveConfigurations()
                quickPlan?.clearSensitiveConfigurations()
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
                fun finishFailedStart(code: String) {
                    scheduleBackgroundStartFailure(
                        scheduleCleanup = backgroundExecutor::execute,
                        cleanupLease = {
                            BackgroundConnectionClient.stop(
                                credential,
                                result.connection.leaseId,
                                UUID.randomUUID().toString(),
                            )
                        },
                        notifyFailure = { onError(code) },
                        completeOperation = backgroundOperationGate::complete,
                        onCleanupFailure = { error ->
                            TunnelLog.warning(
                                "background_start.cleanup_failed",
                                (error as? BackgroundConnectionException)?.code,
                            )
                        },
                    )
                }
                start(
                    applicationContext,
                    args,
                    { state, duration ->
                        val failureCode = backgroundStartFailureCode(state)
                        if (failureCode == null) {
                            try {
                                onSuccess(state, duration)
                            } finally {
                                backgroundOperationGate.complete()
                            }
                        } else {
                            finishFailedStart(failureCode)
                        }
                    },
                    ::finishFailedStart,
                    keepForegroundServiceOnFailure = true,
                )
            } catch (error: Throwable) {
                val code = (error as? BackgroundConnectionException)?.code ?: errorCode(error)
                if (code == "invalid_background_token" &&
                    !BackgroundCredentialStore.clearInvalidCredential(applicationContext)
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
                    runCatching {
                        BackgroundConnectionClient.stop(
                            credential,
                            leaseId,
                            UUID.randomUUID().toString(),
                        )
                    }
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
                activeSession?.let { session ->
                    logDataPlaneSnapshot(session, "tunnel_stopping")
                    logNetworkTelemetrySnapshot(session, "tunnel_stopping")
                }
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
            val watchdog = try {
                armOperationWatchdog(
                    checkNotNull(applicationContext) { "tunnel_context_unavailable" },
                    "metrics",
                    METRICS_OPERATION_WATCHDOG_MILLIS,
                    TunnelOperationWatchdogScope.METRICS,
                )
            } catch (error: Throwable) {
                onError(errorCode(error))
                return@execute
            }
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
            } finally {
                completeOperationWatchdog(watchdog)
            }
        }
    }

    fun rebindUdp(
        context: Context,
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
        when (stateGate.beginRebind()) {
            TransitionDecision.PROCEED -> Unit
            TransitionDecision.BUSY -> {
                onError("tunnel_operation_in_progress")
                return
            }
            TransitionDecision.ALREADY_COMPLETE -> {
                onError("tunnel_not_running")
                return
            }
            TransitionDecision.REPLACE -> error("unreachable_rebind_transition")
        }
        val applicationContext = context.applicationContext
        val queueGate = RebindQueueGate()
        val queueWatchdog = try {
            watchdogExecutor.schedule(
                {
                    if (!queueGate.cancel()) return@schedule
                    stateGate.cancelRebind()
                    TunnelLog.warning(
                        "tunnel.udp_rebind_queue_timed_out",
                        "udp_rebind_timeout",
                    )
                    onError("udp_rebind_timeout")
                },
                UDP_REBIND_QUEUE_TIMEOUT_MILLIS,
                TimeUnit.MILLISECONDS,
            )
        } catch (error: Throwable) {
            stateGate.cancelRebind()
            val code = errorCode(error)
            TunnelLog.warning("tunnel.udp_rebind_queue_watchdog_failed", code, error)
            onError(code)
            return
        }
        val operation = Runnable {
            if (!queueGate.begin()) return@Runnable
            val startedAt = System.nanoTime()
            queueWatchdog.cancel(false)
            val watchdog = try {
                armOperationWatchdog(
                    applicationContext,
                    "udp_rebind",
                    UDP_REBIND_OPERATION_WATCHDOG_MILLIS,
                )
            } catch (error: Throwable) {
                stateGate.cancelRebind()
                val code = errorCode(error)
                TunnelLog.warning("tunnel.udp_rebind_watchdog_failed", code, error)
                onError(code)
                return@Runnable
            }
            var failureCode: String? = null
            TunnelLog.info("tunnel.udp_rebind_begin")
            try {
                val session = activeSession
                    ?: throw TunnelOperationException("tunnel_not_running")
                if (session.transport != "amneziawg_3") {
                    throw TunnelOperationException("udp_rebind_unsupported")
                }
                logDataPlaneSnapshot(session, "before_udp_rebind")
                val expectedProfile = Awg3ProfileSnapshot.fromInterface(
                    session.config.getInterface(),
                )
                val activeBackend = requireBackend()
                val before = networkTelemetry(activeBackend)
                activeBackend.rebindUdp(tunnel)
                val actualProfile = runtimeAwg3Profile(activeBackend)
                if (!runtimeProfileMatches(expectedProfile, actualProfile)) {
                    logAwg3Mismatch(
                        "tunnel.udp_rebind_profile_mismatch",
                        expectedProfile,
                        actualProfile,
                        retry = false,
                    )
                    throw TunnelOperationException("awg3_profile_apply_failed")
                }
                val after = networkTelemetry(activeBackend)
                TunnelLog.info(
                    "tunnel.udp_rebind_completed",
                    mapOf(
                        "duration_millis" to elapsedMillis(startedAt),
                        "old_local_port" to before?.localPort,
                        "new_local_port" to after?.localPort,
                    ),
                )
                stateGate.complete(SessionState.RUNNING)
            } catch (error: Throwable) {
                val code = errorCode(error)
                TunnelLog.warning("tunnel.udp_rebind_failed", code, error)
                runCatching {
                    suppressBackendStateChanges.set(true)
                    requireBackend().setState(tunnel, Tunnel.State.DOWN, null)
                }
                suppressBackendStateChanges.set(false)
                clearActiveSession()
                AndroidSplitTunnel.clear()
                stateGate.complete(SessionState.FAILED)
                failureCode = code
            } finally {
                completeOperationWatchdog(watchdog)
            }
            val durationMillis = elapsedMillis(startedAt)
            val code = failureCode
            if (code == null) {
                onSuccess(SessionState.RUNNING, durationMillis)
            } else {
                onError(code)
            }
        }
        try {
            executor.execute(operation)
        } catch (error: Throwable) {
            queueWatchdog.cancel(false)
            if (queueGate.cancel()) {
                stateGate.cancelRebind()
                val code = errorCode(error)
                TunnelLog.warning("tunnel.udp_rebind_schedule_failed", code, error)
                onError(code)
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

    private fun networkTelemetry(activeBackend: GoBackend = requireBackend()): NetworkTelemetry? =
        activeBackend.getNetworkTelemetry(tunnel)?.let(NetworkTelemetry::fromJson)

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
        timeoutMillis: Long = TUNNEL_OPERATION_WATCHDOG_MILLIS,
        scope: TunnelOperationWatchdogScope = TunnelOperationWatchdogScope.LIFECYCLE,
    ): TunnelOperationWatchdog {
        val token = watchdogGates.begin(scope)
        val future = watchdogExecutor.schedule(
            {
                if (!watchdogGates.expire(token)) return@schedule
                terminateHungTunnelProcess(context, operation)
            },
            timeoutMillis,
            TimeUnit.MILLISECONDS,
        )
        return TunnelOperationWatchdog(token, future)
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
        if (watchdogGates.complete(watchdog.token)) {
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
                NelomaiVpnService.setPhysicalNetworks(emptyList(), validated = false)
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
            NelomaiVpnService.setPhysicalNetworks(
                physicalState.networks,
                physicalState.validated,
            )
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
                if (!dataPlaneSampleQueued.compareAndSet(false, true)) {
                    return@scheduleAtFixedRate
                }
                executor.execute {
                    try {
                        val session = activeSession
                            ?.takeIf { it.generation == sessionGeneration }
                            ?: return@execute
                        if (stateGate.current() == SessionState.RUNNING) {
                            inspectNetworkTelemetry(session)
                            val now = SystemClock.elapsedRealtime()
                            if (now - session.lastDataPlaneSnapshotElapsedMillis >=
                                DATA_PLANE_DIAGNOSTICS_INTERVAL_SECONDS * 1_000L
                            ) {
                                logDataPlaneSnapshot(session, "periodic")
                                if (
                                    shouldPersistPeriodicNetworkTelemetry(
                                        networkTelemetryMode(session.transport),
                                    )
                                ) {
                                    logNetworkTelemetrySnapshot(
                                        session = session,
                                        reason = "periodic",
                                        refresh = false,
                                        includeRecentSamples = false,
                                    )
                                }
                                session.lastDataPlaneSnapshotElapsedMillis = now
                            }
                        }
                    } finally {
                        dataPlaneSampleQueued.set(false)
                    }
                }
            },
            1,
            NETWORK_TELEMETRY_INTERVAL_SECONDS,
            TimeUnit.SECONDS,
        )
    }

    private fun scheduleTunnelStartMemoryDiagnostics(
        context: Context,
        sessionGeneration: Long,
        diagnostics: TunnelStartMemoryDiagnostics,
        transport: String,
    ) {
        tunnelStartMemoryDelayedStages().forEach { (stage, delayMillis) ->
            watchdogExecutor.schedule(
                {
                    if (activeSession?.generation != sessionGeneration) return@schedule
                    if (stateGate.current() == SessionState.RUNNING) {
                        diagnostics.record(context, stage, transport)
                    }
                },
                delayMillis,
                TimeUnit.MILLISECONDS,
            )
        }
    }

    private fun inspectNetworkTelemetry(session: ActiveTunnelSession) {
        val telemetryMode = networkTelemetryMode(session.transport)
        val now = SystemClock.elapsedRealtime()
        if (
            !shouldPollNetworkTelemetry(
                mode = telemetryMode,
                nowElapsedMillis = now,
                lastPollElapsedMillis = session.lastNetworkTelemetryPollElapsedMillis,
            )
        ) {
            return
        }
        session.lastNetworkTelemetryPollElapsedMillis = now
        val sample = try {
            networkTelemetry() ?: return
        } catch (error: Throwable) {
            if (now - session.lastTelemetryErrorLoggedElapsedMillis >=
                NETWORK_TELEMETRY_ERROR_LOG_INTERVAL_MILLIS
            ) {
                session.lastTelemetryErrorLoggedElapsedMillis = now
                TunnelLog.warning("tunnel.network_telemetry_failed", error = error)
            }
            return
        }
        val previous = session.lastNetworkTelemetry
        val tunReadDelta = counterDelta(previous?.tunReadBytes, sample.tunReadBytes)
        val tunWriteDelta = counterDelta(previous?.tunWriteBytes, sample.tunWriteBytes)
        val udpReceiveDelta = counterDelta(previous?.udpReceiveBytes, sample.udpReceiveBytes)
        session.lastNetworkTelemetry = sample
        if (tunReadDelta > 0) {
            if (now - session.lastTunActivityElapsedMillis >
                UDP_RECOVERY_TUN_ACTIVITY_WINDOW_MILLIS
            ) {
                session.udpStallStartedElapsedMillis = now
            } else if (session.udpStallStartedElapsedMillis == null) {
                session.udpStallStartedElapsedMillis = now
            }
            session.lastTunActivityElapsedMillis = now
        } else if (now - session.lastTunActivityElapsedMillis >
            UDP_RECOVERY_TUN_ACTIVITY_WINDOW_MILLIS
        ) {
            session.udpStallStartedElapsedMillis = null
        }
        if (tunWriteDelta > 0) {
            session.openNetworkIncidentElapsedMillis?.let { detectedAt ->
                TunnelLog.incident(
                    "tunnel.network_incident_recovered",
                    mapOf(
                        "connection_lease_id" to session.connectionLeaseId,
                        "incident_sequence" to session.networkIncidentCount,
                        "duration_millis" to (now - detectedAt).coerceAtLeast(0),
                        "local_port" to sample.localPort,
                        "endpoint_port" to endpointPort(sample.endpoint),
                    ),
                )
                session.openNetworkIncidentElapsedMillis = null
            }
            session.lastTunWriteActivityElapsedMillis = now
            session.udpStallStartedElapsedMillis = null
            session.udpRecoveryArmed = true
            session.udpRecoveryAttempts = 0
        }
        if (udpReceiveDelta > 0) {
            session.lastUdpReceiveElapsedMillis = now
        }

        appendNetworkTelemetrySample(session, now, previous, sample)

        if (telemetryMode == NetworkTelemetryMode.PASSIVE) return

        session.pendingUdpControlProbe
            ?.takeIf { now >= it.evaluateAtElapsedMillis }
            ?.let { probe ->
                val succeeded = try {
                    requireBackend().handshakeProbeSucceeded(tunnel, probe.generation)
                } catch (error: Throwable) {
                    session.pendingUdpControlProbe = null
                    session.udpRecoveryArmed = true
                    TunnelLog.warning(
                        "tunnel.udp_control_probe_measurement_failed",
                        "udp_control_probe_failed",
                        error,
                    )
                    return
                }
                val action = udpControlProbeAction(
                    stage = probe.stage,
                    succeeded = succeeded,
                    recoveryAttempts = session.udpRecoveryAttempts,
                )
                TunnelLog.info(
                    "tunnel.udp_control_probe_evaluated",
                    mapOf(
                        "stage" to probe.stage.name.lowercase(),
                        "generation" to probe.generation,
                        "succeeded" to succeeded,
                        "action" to action.name.lowercase(),
                        "duration_millis" to (now - probe.startedAtElapsedMillis)
                            .coerceAtLeast(0),
                        "old_local_port" to probe.localPortBefore,
                        "new_local_port" to probe.localPortAfter,
                        "tun_write_delta_bytes" to counterDelta(
                            probe.tunWriteBytesBefore,
                            sample.tunWriteBytes,
                        ),
                        "udp_receive_delta_bytes" to counterDelta(
                            probe.udpReceiveBytesBefore,
                            sample.udpReceiveBytes,
                        ),
                    ),
                )
                session.pendingUdpControlProbe = null
                when (action) {
                    UdpControlProbeAction.MARK_TRANSPORT_REACHABLE -> {
                        session.udpRecoveryAttempts = 0
                        session.udpStallStartedElapsedMillis = null
                        session.udpRecoveryArmed = true
                    }
                    UdpControlProbeAction.REBIND -> applyUdpRecovery(session, sample)
                    UdpControlProbeAction.RETRY -> session.udpRecoveryArmed = true
                    UdpControlProbeAction.STOP -> {
                        TunnelLog.warning(
                            "tunnel.udp_recovery_exhausted",
                            "udp_recovery_failed",
                        )
                        stopAfterUdpRecoveryFailure()
                        return
                    }
                }
                return
            }

        if (!shouldRecoverUdpStall(
                transport = session.transport,
                uptimeMillis = now - session.startedAtElapsedMillis,
                millisSinceTunActivity = now - session.lastTunActivityElapsedMillis,
                millisSinceTunWrite = now - session.lastTunWriteActivityElapsedMillis,
                stallDurationMillis = session.udpStallStartedElapsedMillis?.let { now - it },
                millisSinceRecovery = session.lastUdpRecoveryElapsedMillis?.let { now - it },
                armed = session.udpRecoveryArmed,
            )
        ) {
            return
        }

        session.udpRecoveryArmed = false
        session.lastUdpRecoveryElapsedMillis = now
        TunnelLog.info(
            "tunnel.udp_stall_detected",
            mapOf(
                "millis_since_tun_activity" to now - session.lastTunActivityElapsedMillis,
                "millis_since_tun_write" to now - session.lastTunWriteActivityElapsedMillis,
                "millis_since_udp_receive" to now - session.lastUdpReceiveElapsedMillis,
                "local_port" to sample.localPort,
                "last_udp_send_error" to sample.lastUdpSendError,
                "last_udp_receive_error" to sample.lastUdpReceiveError,
                "last_udp_send_errno" to sample.lastUdpSendErrno,
                "last_udp_receive_errno" to sample.lastUdpReceiveErrno,
                "samples" to JSONArray(session.recentNetworkTelemetry.toList()),
            ),
        )
        if (session.openNetworkIncidentElapsedMillis == null) {
            session.networkIncidentCount += 1
            session.openNetworkIncidentElapsedMillis = now
            TunnelLog.incident(
                "tunnel.network_incident_detected",
                buildMap {
                    put("connection_lease_id", session.connectionLeaseId)
                    put("incident_sequence", session.networkIncidentCount)
                    put("kind", "suspected_data_path_stall")
                    put("local_port", sample.localPort)
                    put("endpoint_port", endpointPort(sample.endpoint))
                    put("last_udp_send_error", sample.lastUdpSendError)
                    put("last_udp_receive_error", sample.lastUdpReceiveError)
                    put("last_udp_send_errno", sample.lastUdpSendErrno)
                    put("last_udp_receive_errno", sample.lastUdpReceiveErrno)
                    if (session.networkIncidentCount <= MAX_DETAILED_NETWORK_INCIDENTS) {
                        put("samples", JSONArray(session.recentNetworkTelemetry.toList()))
                    } else {
                        put(
                            "additional_count",
                            session.networkIncidentCount - MAX_DETAILED_NETWORK_INCIDENTS,
                        )
                    }
                },
            )
        }
        try {
            startUdpControlProbe(
                session = session,
                stage = UdpControlProbeStage.BEFORE_REBIND,
                baseline = sample,
                localPortBefore = sample.localPort,
                localPortAfter = sample.localPort,
            )
        } catch (error: Throwable) {
            handleUdpControlProbeStartFailure(
                session = session,
                stage = UdpControlProbeStage.BEFORE_REBIND,
                baseline = sample,
                cause = error,
            )
        }
    }

    private fun startUdpControlProbe(
        session: ActiveTunnelSession,
        stage: UdpControlProbeStage,
        baseline: NetworkTelemetry,
        localPortBefore: Int,
        localPortAfter: Int,
    ) {
        val activeBackend = requireBackend()
        val startedAt = SystemClock.elapsedRealtime()
        val generation = activeBackend.startHandshakeProbe(tunnel)
        val timeoutMillis = activeBackend.handshakeProbeTimeoutMillis(tunnel)
        val completedAt = SystemClock.elapsedRealtime()
        session.pendingUdpControlProbe = PendingUdpControlProbe(
            stage = stage,
            generation = generation,
            startedAtElapsedMillis = startedAt,
            evaluateAtElapsedMillis = completedAt + timeoutMillis,
            tunWriteBytesBefore = baseline.tunWriteBytes,
            udpReceiveBytesBefore = baseline.udpReceiveBytes,
            localPortBefore = localPortBefore,
            localPortAfter = localPortAfter,
        )
        TunnelLog.info(
            "tunnel.udp_control_probe_started",
            mapOf(
                "stage" to stage.name.lowercase(),
                "generation" to generation,
                "evaluation_timeout_millis" to timeoutMillis,
                "duration_millis" to (completedAt - startedAt).coerceAtLeast(0),
                "old_local_port" to localPortBefore,
                "new_local_port" to localPortAfter,
            ),
        )
    }

    private fun applyUdpRecovery(session: ActiveTunnelSession, sample: NetworkTelemetry) {
        session.udpRecoveryAttempts += 1
        session.lastUdpRecoveryElapsedMillis = SystemClock.elapsedRealtime()
        val activeBackend = requireBackend()
        val startedAt = SystemClock.elapsedRealtime()
        val rebound = try {
            activeBackend.rebindUdp(tunnel)
            networkTelemetry(activeBackend) ?: sample
        } catch (error: Throwable) {
            TunnelLog.warning("tunnel.udp_recovery_failed", "udp_rebind_failed", error)
            stopAfterUdpRecoveryFailure()
            return
        }
        val completedAt = SystemClock.elapsedRealtime()
        TunnelLog.info(
            "tunnel.udp_recovery_applied",
            mapOf(
                "attempt" to session.udpRecoveryAttempts,
                "duration_millis" to (completedAt - startedAt).coerceAtLeast(0),
                "old_local_port" to sample.localPort,
                "new_local_port" to rebound.localPort,
            ),
        )
        try {
            startUdpControlProbe(
                session = session,
                stage = UdpControlProbeStage.AFTER_REBIND,
                baseline = rebound,
                localPortBefore = sample.localPort,
                localPortAfter = rebound.localPort,
            )
        } catch (error: Throwable) {
            handleUdpControlProbeStartFailure(
                session = session,
                stage = UdpControlProbeStage.AFTER_REBIND,
                baseline = rebound,
                cause = error,
            )
        }
    }

    private fun handleUdpControlProbeStartFailure(
        session: ActiveTunnelSession,
        stage: UdpControlProbeStage,
        baseline: NetworkTelemetry,
        cause: Throwable,
    ) {
        val action = udpControlProbeStartFailureAction(
            stage = stage,
            recoveryAttempts = session.udpRecoveryAttempts,
        )
        TunnelLog.warning(
            "tunnel.udp_control_probe_start_failed",
            "udp_control_probe_failed",
            cause,
        )
        TunnelLog.info(
            "tunnel.udp_control_probe_start_failure_action",
            mapOf(
                "stage" to stage.name.lowercase(),
                "action" to action.name.lowercase(),
                "attempt" to session.udpRecoveryAttempts,
                "local_port" to baseline.localPort,
            ),
        )
        when (action) {
            UdpControlProbeAction.REBIND,
            UdpControlProbeAction.RETRY,
            -> applyUdpRecovery(session, baseline)
            UdpControlProbeAction.STOP -> {
                TunnelLog.warning(
                    "tunnel.udp_recovery_exhausted",
                    "udp_recovery_failed",
                )
                stopAfterUdpRecoveryFailure()
            }
            UdpControlProbeAction.MARK_TRANSPORT_REACHABLE -> error(
                "unreachable_successful_probe_start_failure",
            )
        }
    }

    private fun stopAfterUdpRecoveryFailure() {
        val leaseId = activeSession?.connectionLeaseId
        handOffDataPlaneStall(
            leaseId = leaseId,
            handoff = NelomaiVpnService::reportDataPlaneStall,
            fallback = ::stopLocallyAfterUdpRecoveryFailure,
        )
    }

    private fun stopLocallyAfterUdpRecoveryFailure() {
        val context = applicationContext ?: run {
            suppressBackendStateChanges.set(true)
            try {
                runCatching { requireBackend().setState(tunnel, Tunnel.State.DOWN, null) }
            } finally {
                suppressBackendStateChanges.set(false)
            }
            clearActiveSession()
            AndroidSplitTunnel.clear()
            stateGate.complete(SessionState.FAILED)
            return
        }
        stop(
            TUNNEL_API_VERSION,
            { state, _ ->
                if (state != SessionState.STOPPED) {
                    runCatching { AutomaticDiagnostics.onTunnelStopped(context) }
                        .onFailure { TunnelLog.warning("diagnostics.lifecycle_failed", error = it) }
                    NelomaiVpnService.stopForegroundService()
                }
                QuickTunnelController.updateState(
                    context,
                    state,
                    desiredActive = null,
                    changed = true,
                )
                TunnelPlugin.refreshQuickTile(context)
                NelomaiVpnService.resumeConnectionIntentRecovery()
            },
            { code ->
                TunnelLog.warning("tunnel.udp_recovery_stop_failed", code)
                runCatching { AutomaticDiagnostics.onTunnelStopped(context) }
                    .onFailure { TunnelLog.warning("diagnostics.lifecycle_failed", error = it) }
                stateGate.complete(SessionState.FAILED)
                QuickTunnelController.updateState(
                    context,
                    SessionState.FAILED,
                    desiredActive = null,
                    changed = true,
                )
                TunnelPlugin.refreshQuickTile(context)
                NelomaiVpnService.resumeConnectionIntentRecovery()
            },
        )
    }

    private fun appendNetworkTelemetrySample(
        session: ActiveTunnelSession,
        now: Long,
        previous: NetworkTelemetry?,
        sample: NetworkTelemetry,
    ) {
        val tunReadDelta = counterDelta(previous?.tunReadBytes, sample.tunReadBytes)
        val tunWriteDelta = counterDelta(previous?.tunWriteBytes, sample.tunWriteBytes)
        val udpSendDelta = counterDelta(previous?.udpSendBytes, sample.udpSendBytes)
        val udpReceiveDelta = counterDelta(previous?.udpReceiveBytes, sample.udpReceiveBytes)
        val record = JSONObject().apply {
            put("elapsed_millis", (now - session.startedAtElapsedMillis).coerceAtLeast(0))
            put(
                "tun_read_delta_packets",
                counterDelta(previous?.tunReadPackets, sample.tunReadPackets),
            )
            put("tun_read_delta_bytes", tunReadDelta)
            put(
                "tun_write_delta_packets",
                counterDelta(previous?.tunWritePackets, sample.tunWritePackets),
            )
            put("tun_write_delta_bytes", tunWriteDelta)
            put(
                "udp_send_delta_packets",
                counterDelta(previous?.udpSendPackets, sample.udpSendPackets),
            )
            put("udp_send_delta_bytes", udpSendDelta)
            put(
                "udp_receive_delta_packets",
                counterDelta(previous?.udpReceivePackets, sample.udpReceivePackets),
            )
            put("udp_receive_delta_bytes", udpReceiveDelta)
            put("tun_read_bytes", sample.tunReadBytes)
            put("tun_write_bytes", sample.tunWriteBytes)
            put("udp_send_bytes", sample.udpSendBytes)
            put("udp_receive_bytes", sample.udpReceiveBytes)
            put("tun_read_errors", sample.tunReadErrors)
            put("tun_write_errors", sample.tunWriteErrors)
            put("udp_send_errors", sample.udpSendErrors)
            put("udp_receive_errors", sample.udpReceiveErrors)
            put("go_heap_alloc_bytes", sample.goHeapAllocBytes)
            put("go_heap_sys_bytes", sample.goHeapSysBytes)
            put("go_heap_idle_bytes", sample.goHeapIdleBytes)
            put("go_heap_inuse_bytes", sample.goHeapInuseBytes)
            put("go_heap_released_bytes", sample.goHeapReleasedBytes)
            put("go_stack_inuse_bytes", sample.goStackInuseBytes)
            put("go_gc_cycles", sample.goGcCycles)
            put("go_memory_limit_bytes", sample.goMemoryLimitBytes)
            put("go_device_starts", sample.goDeviceStarts)
            put("go_device_start_failures", sample.goDeviceStartFailures)
            put("go_device_closes", sample.goDeviceCloses)
            put("go_devices_starting", sample.goDevicesStarting)
            put("go_active_devices", sample.goActiveDevices)
            put("local_port", sample.localPort)
            put("last_tun_read_at_unix_ms", sample.lastTunReadAtUnixMillis)
            put("last_tun_write_at_unix_ms", sample.lastTunWriteAtUnixMillis)
            put("last_udp_send_at_unix_ms", sample.lastUdpSendAtUnixMillis)
            put("last_udp_receive_at_unix_ms", sample.lastUdpReceiveAtUnixMillis)
            sample.lastUdpSendErrno?.let { put("last_udp_send_errno", it) }
            sample.lastUdpReceiveErrno?.let { put("last_udp_receive_errno", it) }
            endpointPort(sample.endpoint)?.let { put("endpoint_port", it) }
        }
        session.recentNetworkTelemetry.addLast(record)
        while (session.recentNetworkTelemetry.size > NETWORK_TELEMETRY_RING_SAMPLES) {
            session.recentNetworkTelemetry.removeFirst()
        }
    }

    private fun logNetworkTelemetrySnapshot(
        session: ActiveTunnelSession,
        reason: String,
        refresh: Boolean = true,
        includeRecentSamples: Boolean = true,
    ) {
        if (networkTelemetryMode(session.transport) == NetworkTelemetryMode.DISABLED) return
        val now = SystemClock.elapsedRealtime()
        val sample = if (refresh) {
            runCatching { networkTelemetry() }
                .onFailure {
                    TunnelLog.warning("tunnel.network_telemetry_snapshot_failed", error = it)
                }
                .getOrNull()
        } else {
            session.lastNetworkTelemetry
        }
        if (refresh && sample != null) {
            val previous = session.lastNetworkTelemetry
            session.lastNetworkTelemetry = sample
            appendNetworkTelemetrySample(session, now, previous, sample)
        }
        TunnelLog.info(
            "tunnel.network_telemetry_snapshot",
            networkTelemetrySnapshotDetails(
                reason = reason,
                sample = sample,
                recentSamples = session.recentNetworkTelemetry.toList()
                    .takeIf { includeRecentSamples },
            ),
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

internal fun backgroundStartFailureCode(state: SessionState): String? =
    "connection_start_failed".takeUnless { state == SessionState.RUNNING }

internal fun scheduleBackgroundStartFailure(
    scheduleCleanup: (() -> Unit) -> Unit,
    cleanupLease: () -> Unit,
    notifyFailure: () -> Unit,
    completeOperation: () -> Unit,
    onCleanupFailure: (Throwable) -> Unit,
) {
    try {
        notifyFailure()
    } finally {
        try {
            scheduleCleanup {
                try {
                    runCatching(cleanupLease).onFailure { error ->
                        runCatching { onCleanupFailure(error) }
                    }
                } finally {
                    completeOperation()
                }
            }
        } catch (error: Throwable) {
            try {
                runCatching { onCleanupFailure(error) }
            } finally {
                completeOperation()
            }
        }
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

internal fun shouldRecoverUdpStall(
    transport: String,
    uptimeMillis: Long,
    millisSinceTunActivity: Long,
    millisSinceTunWrite: Long,
    stallDurationMillis: Long?,
    millisSinceRecovery: Long?,
    armed: Boolean,
): Boolean =
    transport == "amneziawg_3" &&
        armed &&
        uptimeMillis >= UDP_RECOVERY_MINIMUM_UPTIME_MILLIS &&
        millisSinceTunActivity in 0..UDP_RECOVERY_TUN_ACTIVITY_WINDOW_MILLIS &&
        millisSinceTunWrite >= UDP_RECOVERY_STALL_MILLIS &&
        stallDurationMillis != null &&
        stallDurationMillis >= UDP_RECOVERY_STALL_MILLIS &&
        (millisSinceRecovery == null || millisSinceRecovery >= UDP_RECOVERY_COOLDOWN_MILLIS)

internal fun udpControlProbeAction(
    stage: UdpControlProbeStage,
    succeeded: Boolean,
    recoveryAttempts: Int,
): UdpControlProbeAction = when {
    succeeded -> UdpControlProbeAction.MARK_TRANSPORT_REACHABLE
    stage == UdpControlProbeStage.BEFORE_REBIND -> UdpControlProbeAction.REBIND
    recoveryAttempts < UDP_RECOVERY_MAX_ATTEMPTS -> UdpControlProbeAction.RETRY
    else -> UdpControlProbeAction.STOP
}

internal fun udpControlProbeStartFailureAction(
    stage: UdpControlProbeStage,
    recoveryAttempts: Int,
): UdpControlProbeAction = when {
    recoveryAttempts >= UDP_RECOVERY_MAX_ATTEMPTS -> UdpControlProbeAction.STOP
    stage == UdpControlProbeStage.BEFORE_REBIND -> UdpControlProbeAction.REBIND
    else -> UdpControlProbeAction.RETRY
}

private const val DATA_PLANE_DIAGNOSTICS_INTERVAL_SECONDS = 5L * 60L
private const val NETWORK_TELEMETRY_INTERVAL_SECONDS = 1L
private const val PASSIVE_NETWORK_TELEMETRY_INTERVAL_MILLIS = 10_000L
private const val NETWORK_TELEMETRY_RING_SAMPLES = 45
private const val MAX_DETAILED_NETWORK_INCIDENTS = 3
private const val NETWORK_TELEMETRY_ERROR_LOG_INTERVAL_MILLIS = 60_000L
private const val UDP_RECOVERY_MINIMUM_UPTIME_MILLIS = 10_000L
private const val UDP_RECOVERY_TUN_ACTIVITY_WINDOW_MILLIS = 2_500L
private const val UDP_RECOVERY_STALL_MILLIS = 5_000L
private const val UDP_RECOVERY_COOLDOWN_MILLIS = 60_000L
private const val UDP_RECOVERY_MAX_ATTEMPTS = 2
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

private val RedundantStandbyArgs.configurationInitialized: Boolean
    get() = try {
        configuration
        true
    } catch (_: UninitializedPropertyAccessException) {
        false
    }

internal fun StartTunnelArgs.clearSensitiveConfigurations() {
    if (configurationInitialized) {
        configuration.fill(0)
    }
    redundancy?.standby?.let { standby ->
        if (standby.configurationInitialized) {
            standby.configuration.fill(0)
        }
    }
}

internal fun StartTunnelArgs.canCacheQuickPlan(): Boolean =
    cacheQuickAction && configurationInitialized && redundancy == null

private fun StartTunnelArgs.copyForQuickPlan(): StartTunnelArgs? {
    if (!canCacheQuickPlan()) return null
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
    copy.egressMode = egressMode
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
    fun rotateBackground(invoke: Invoke) {
        val args = try {
            invoke.parseArgs(BackgroundCredentialMutationArgs::class.java)
        } catch (_: Throwable) {
            invoke.reject("invalid_background_credential")
            return
        }
        TunnelServiceClient.rotateBackground(
            activity.applicationContext,
            args.expectedRevision,
            { activity.runOnUiThread { invoke.resolve() } },
            { code -> activity.runOnUiThread { invoke.reject(code) } },
        )
    }

    @Command
    fun provisionBackground(invoke: Invoke) {
        val args = try {
            invoke.parseArgs(BackgroundUiProvisionArgs::class.java)
        } catch (_: Throwable) {
            invoke.reject("invalid_background_credential", "invalid_background_credential")
            return
        }
        TunnelServiceClient.provisionBackground(
            activity.applicationContext,
            args,
            { activity.runOnUiThread { invoke.resolve() } },
            { code -> activity.runOnUiThread { invoke.reject(code, code) } },
        )
    }

    @Command
    fun backgroundCredentialStatus(invoke: Invoke) {
        TunnelServiceClient.backgroundCredentialStatus(
            activity.applicationContext,
            {
                    configured,
                    credentialRevision,
                    mutationReady,
                    mutationPending,
                    capabilityRevision,
                    capabilityEnabled,
                    capabilityExpiresAtUnix,
                    deviceId,
                    expiresAtUnix,
                ->
                activity.runOnUiThread {
                    val response = JSObject()
                    response.put("configured", configured)
                    response.put("credentialRevision", credentialRevision)
                    response.put("mutationReady", mutationReady)
                    response.put("mutationPending", mutationPending)
                    response.put("capabilityRevision", capabilityRevision)
                    response.put("capabilityEnabled", capabilityEnabled)
                    response.put("capabilityExpiresAtUnix", capabilityExpiresAtUnix)
                    response.put("deviceId", deviceId)
                    response.put("expiresAtUnix", expiresAtUnix)
                    invoke.resolve(response)
                }
            },
            { code -> activity.runOnUiThread { invoke.reject(code) } },
        )
    }

    @Command
    fun beginConnectionIntent(invoke: Invoke) {
        val args = try {
            invoke.parseArgs(BeginConnectionIntentArgs::class.java)
        } catch (_: Throwable) {
            invoke.reject("invalid_connection_intent")
            return
        }
        TunnelServiceClient.beginConnectionIntent(
            activity.applicationContext,
            args,
            { status -> activity.runOnUiThread { invoke.resolve(status.toJsObject()) } },
            { code -> activity.runOnUiThread { invoke.reject(code) } },
        )
    }

    @Command
    fun toggleConnectionIntent(invoke: Invoke) {
        TunnelServiceClient.toggleConnectionIntent(
            activity.applicationContext,
            { status -> activity.runOnUiThread { invoke.resolve(status.toJsObject()) } },
            { code -> activity.runOnUiThread { invoke.reject(code) } },
        )
    }

    @Command
    fun cancelConnectionIntent(invoke: Invoke) {
        val args = try {
            invoke.parseArgs(CancelConnectionIntentArgs::class.java)
        } catch (_: Throwable) {
            invoke.reject("invalid_connection_intent")
            return
        }
        TunnelServiceClient.cancelConnectionIntent(
            activity.applicationContext,
            args.generation,
            { status -> activity.runOnUiThread { invoke.resolve(status.toJsObject()) } },
            { code -> activity.runOnUiThread { invoke.reject(code) } },
        )
    }

    @Command
    fun cancelCurrentConnectionIntent(invoke: Invoke) {
        TunnelServiceClient.cancelCurrentConnectionIntent(
            activity.applicationContext,
            { status -> activity.runOnUiThread { invoke.resolve(status.toJsObject()) } },
            { code -> activity.runOnUiThread { invoke.reject(code) } },
        )
    }

    @Command
    fun connectionIntentStatus(invoke: Invoke) {
        TunnelServiceClient.connectionIntentStatus(
            activity.applicationContext,
            { status -> activity.runOnUiThread { invoke.resolve(status.toJsObject()) } },
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
    fun beginBackgroundLogout(invoke: Invoke) {
        TunnelServiceClient.beginBackgroundLogout(
            activity.applicationContext,
            { ownership ->
                activity.runOnUiThread {
                    invoke.resolve(JSObject().apply {
                        put("ownership", ownership.wireName)
                    })
                }
            },
            { code -> activity.runOnUiThread { invoke.reject(code) } },
        )
    }

    @Command
    fun recoverBackgroundSession(invoke: Invoke) {
        val args = try {
            invoke.parseArgs(BackgroundSessionRecoveryArgs::class.java)
        } catch (_: Throwable) {
            invoke.reject("invalid_background_recovery")
            return
        }
        TunnelServiceClient.recoverBackgroundSession(
            activity.applicationContext,
            args.installSecret,
            { accessToken, refreshToken ->
                activity.runOnUiThread {
                    val response = JSObject()
                    response.put("accessToken", accessToken)
                    response.put("refreshToken", refreshToken)
                    response.put("errorCode", null)
                    invoke.resolve(response)
                }
            },
            { code ->
                activity.runOnUiThread {
                    val response = JSObject()
                    response.put("accessToken", null)
                    response.put("refreshToken", null)
                    response.put("errorCode", code)
                    invoke.resolve(response)
                }
            },
        )
    }

    @Command
    fun takeQuickStateChange(invoke: Invoke) {
        val changed = quickStateChangeGate.current()
        val response = JSObject()
        response.put("changed", changed)
        response.put("revision", quickStateChangeGate.snapshot())
        response.put(
            "desiredActive",
            if (changed) {
                QuickTunnelController.desiredActiveSnapshot(activity.applicationContext)
            } else {
                null
            },
        )
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
            args.clearSensitiveConfigurations()
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

    @Command
    fun tunnelRebindUdp(invoke: Invoke) {
        val args = try {
            invoke.parseArgs(VersionedTunnelArgs::class.java)
        } catch (_: Throwable) {
            invoke.reject("invalid_tunnel_request")
            return
        }
        TunnelServiceClient.rebindUdp(
            activity.applicationContext,
            args.apiVersion,
            { state, duration -> resolveOperation(invoke, state, duration) },
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

    private fun ConnectionIntentServiceStatus.toJsObject(): JSObject = JSObject().apply {
        put("generation", generation)
        put("desiredActive", desiredActive)
        put("status", status)
        put("leasePhase", leasePhase)
        put("nextRetryAtUnix", nextRetryAtUnix)
        put("lastErrorCode", lastErrorCode)
    }
}
