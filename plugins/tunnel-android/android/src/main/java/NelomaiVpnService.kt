package ru.nelomai.tunnel

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.ResultReceiver
import android.system.OsConstants
import android.widget.Toast
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import org.amnezia.awg.backend.GoBackend
import org.amnezia.awg.config.Config
import java.io.ByteArrayInputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant
import java.util.UUID
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

private const val IDLE_SERVICE_STOP_DELAY_MILLIS = 400L
private const val REDUNDANT_HEALTH_TICK_MILLIS = 1_000L
private const val BACKGROUND_REFRESH_WINDOW_SECONDS = 7L * 24 * 60 * 60

/** Serializes recovery-v2 work and coalesces high-frequency health/network callbacks. */
internal class RedundantVpnWorkDispatcher(private val executor: Executor) {
    private val tickQueued = AtomicBoolean(false)
    private val resumeQueued = AtomicBoolean(false)
    private val networkGate = Any()
    private var networkQueued = false
    private var pendingValidated: Boolean? = null

    fun execute(action: () -> Unit) = executor.execute(action)

    fun tick(action: () -> Unit): Boolean {
        if (!tickQueued.compareAndSet(false, true)) return false
        executor.execute {
            try {
                action()
            } finally {
                tickQueued.set(false)
            }
        }
        return true
    }

    fun resume(action: () -> Unit): Boolean {
        if (!resumeQueued.compareAndSet(false, true)) return false
        executor.execute {
            try {
                action()
            } finally {
                resumeQueued.set(false)
            }
        }
        return true
    }

    fun network(validated: Boolean, action: (Boolean) -> Unit): Boolean {
        val schedule = synchronized(networkGate) {
            pendingValidated = validated
            if (networkQueued) false else {
                networkQueued = true
                true
            }
        }
        if (!schedule) return false
        executor.execute {
            while (true) {
                val current = synchronized(networkGate) {
                    pendingValidated?.also { pendingValidated = null } ?: run {
                        networkQueued = false
                        return@execute
                    }
                }
                action(current)
            }
        }
        return true
    }
}

/** Owns one accepted redundant start until its terminal result is delivered. */
internal class RedundantStartOperationGate {
    private val gate = Any()
    private var pending: Pending? = null

    private data class Pending(
        val operationId: String,
        val onCancelled: () -> Unit,
        var cancelled: Boolean = false,
        var workerFinished: Boolean = false,
        var terminalDelivered: Boolean = false,
    )

    fun begin(operationId: String, onCancelled: () -> Unit): Boolean = synchronized(gate) {
        if (pending != null) return@synchronized false
        pending = Pending(operationId, onCancelled)
        true
    }

    fun cancel(operationId: String): Boolean = synchronized(gate) {
        val current = pending?.takeIf { it.operationId == operationId }
            ?: return@synchronized false
        current.cancelled = true
        true
    }

    fun cancelPendingAndComplete(): String? = synchronized(gate) {
        val current = pending ?: return@synchronized null
        current.cancelled = true
        completeLocked(current.operationId, current.onCancelled)
        current.operationId
    }

    fun isCancelled(operationId: String): Boolean = synchronized(gate) {
        pending?.let { it.operationId == operationId && it.cancelled } == true
    }

    fun workerFinished(operationId: String) = synchronized(gate) {
        val current = pending?.takeIf { it.operationId == operationId } ?: return@synchronized
        current.workerFinished = true
        if (current.terminalDelivered) pending = null
    }

    fun complete(operationId: String, action: () -> Unit): Boolean = synchronized(gate) {
        completeLocked(operationId, action)
    }

    fun completeCancelled(operationId: String): Boolean = synchronized(gate) {
        val current = pending?.takeIf { it.operationId == operationId }
            ?: return@synchronized false
        current.cancelled = true
        completeLocked(operationId, current.onCancelled)
    }

    private fun completeLocked(operationId: String, action: () -> Unit): Boolean {
        val current = pending?.takeIf { it.operationId == operationId } ?: return false
        if (current.terminalDelivered) return false
        current.terminalDelivered = true
        try {
            action()
        } finally {
            if (current.workerFinished) pending = null
        }
        return true
    }
}

internal data class RedundantRevokeResult(
    val fenced: Boolean,
    val stopped: Boolean,
)

internal fun dispatchRedundantRevoke(
    dispatcher: RedundantVpnWorkDispatcher,
    fence: () -> Boolean,
    revoke: () -> Boolean,
    onComplete: (RedundantRevokeResult) -> Unit,
) {
    dispatcher.execute {
        val fenced = runCatching(fence).getOrDefault(false)
        val stopped = fenced && runCatching(revoke).getOrDefault(false)
        onComplete(RedundantRevokeResult(fenced, stopped))
    }
}

internal class IdleStopDebouncer(
    private val delayMillis: Long,
    private val schedule: (Runnable, Long) -> Unit,
    private val cancel: (Runnable) -> Unit,
) {
    private val gate = Any()
    private var pending: Runnable? = null
    private var generation = 0L

    fun schedule(action: () -> Unit) {
        val ticket = synchronized(gate) {
            generation += 1
            generation
        }
        lateinit var task: Runnable
        task = Runnable {
            val shouldRun = synchronized(gate) {
                if (generation != ticket || pending !== task) {
                    false
                } else {
                    pending = null
                    true
                }
            }
            if (shouldRun) action()
        }
        var previous: Runnable? = null
        val shouldSchedule = synchronized(gate) {
            if (generation != ticket) {
                false
            } else {
                previous = pending
                pending = task
                true
            }
        }
        previous?.let(cancel)
        if (shouldSchedule) schedule(task, delayMillis)
    }

    fun cancel() {
        val previous = synchronized(gate) {
            generation += 1
            pending.also { pending = null }
        }
        previous?.let(cancel)
    }
}

internal class AndroidConnectionIntentAttemptDispatcher(
    private val execute: (Runnable) -> Unit,
    private val persistedDelayMillis: () -> Long,
    private val scheduleAfter: (Long) -> Unit,
    private val attempt: () -> Unit,
) {
    private val gate = Any()
    private var queued = false
    private var rerunRequested = false

    fun request() {
        val shouldDispatch = synchronized(gate) {
            if (queued) {
                rerunRequested = true
                false
            } else {
                queued = true
                true
            }
        }
        if (!shouldDispatch) return
        dispatch()
    }

    private fun dispatch() {
        try {
            execute(Runnable(::runQueuedAttempt))
        } catch (error: Throwable) {
            synchronized(gate) {
                queued = false
                rerunRequested = false
            }
            throw error
        }
    }

    private fun runQueuedAttempt() {
        var deferredToTimer = false
        try {
            val delayMillis = persistedDelayMillis()
            if (delayMillis > 0) {
                scheduleAfter(delayMillis)
                deferredToTimer = true
                return
            }
            attempt()
        } finally {
            val rerun = synchronized(gate) {
                if (!deferredToTimer && rerunRequested) {
                    rerunRequested = false
                    true
                } else {
                    rerunRequested = false
                    queued = false
                    false
                }
            }
            if (rerun) dispatch()
        }
    }
}

internal data class LegacyBackgroundStartServiceBoundary(
    val start: (
        onSuccess: (SessionState, Long) -> Unit,
        onError: (String) -> Unit,
    ) -> Unit,
    val runtimeState: () -> SessionState,
    val durableDesiredActive: () -> Boolean,
    val complete: (SessionState, String?, Boolean?) -> Unit,
    val status: () -> ConnectionIntentServiceStatus?,
)

/**
 * Establishes the one Android TUN before attaching either cryptographic slot.
 * A standby admission failure leaves the already admitted primary session alive.
 */
internal fun startRedundantVpnSession(
    establishTun: () -> Int?,
    backend: RedundantSessionBackend,
    primaryConfiguration: ByteArray,
    standbyConfiguration: ByteArray?,
): NativeSession? {
    val tunFd = runCatching(establishTun).getOrNull()
    if (tunFd == null || tunFd < 0) {
        primaryConfiguration.fill(0)
        standbyConfiguration?.fill(0)
        return null
    }
    val session = backend.start(tunFd, primaryConfiguration)
    if (session == null) {
        standbyConfiguration?.fill(0)
        return null
    }
    if (standbyConfiguration != null) {
        backend.startSlot(session, 1, standbyConfiguration)
    }
    return session
}

class NelomaiVpnService : GoBackend.VpnService() {
    private val serviceGeneration = VPN_PROCESS_SERVICE_GENERATION.incrementAndGet()
    private val restoreHandler = Handler(Looper.getMainLooper())
    private val credentialExecutor = Executors.newSingleThreadExecutor { task ->
        Thread(task, "nelomai-background-credential").apply { isDaemon = true }
    }
    private val redundantExecutor = Executors.newSingleThreadExecutor { task ->
        Thread(task, "nelomai-redundant-control").apply { isDaemon = true }
    }
    private val redundantWork = RedundantVpnWorkDispatcher(redundantExecutor)
    private val redundantStartOperation = RedundantStartOperationGate()
    private val idleStopDebouncer = IdleStopDebouncer(
        delayMillis = IDLE_SERVICE_STOP_DELAY_MILLIS,
        schedule = { task, delay -> restoreHandler.postDelayed(task, delay) },
        cancel = restoreHandler::removeCallbacks,
    )
    private var restoreRetryAttempt = 0
    private lateinit var recoveryStore: AndroidRecoveryStore
    @Volatile
    private var redundantVpnOwner: RedundantVpnProcessOwner? = null
    private var redundantPhysicalNetworks: PhysicalNetworks? = null
    private val redundantHealthTick = object : Runnable {
        override fun run() {
            if (redundantVpnOwner != null) {
                redundantWork.tick {
                    redundantVpnOwner?.let { owner ->
                        runCatching(owner::tick).onFailure {
                            TunnelLog.warning("redundant.health_tick_failed", error = it)
                        }
                    }
                }
                restoreHandler.postDelayed(this, REDUNDANT_HEALTH_TICK_MILLIS)
            }
        }
    }
    private val restoreRetry = Runnable { connectionIntentLifecycle.onRetryTimer() }
    private lateinit var connectionIntentCoordinator: AndroidConnectionIntentCoordinator
    private lateinit var connectionIntentLifecycle: ConnectionIntentServiceLifecycle
    private lateinit var connectionIntentAttemptDispatcher: AndroidConnectionIntentAttemptDispatcher
    private lateinit var logoutCoordinator: AndroidLogoutCoordinator
    private val connectionIntentDispatch = AndroidConnectionIntentDispatchState()
    private val connectionIntentRuntimeFence = AndroidRuntimeStartDispatchFence()
    private val backgroundCredentialProvisionInFlight = AtomicBoolean(false)
    private val candidateProbeCache = BackgroundCandidateProbeCache()
    private val logoutRetry = Runnable { scheduleLogoutAttempt() }

    override fun getBuilder(): VpnService.Builder =
        object : VpnService.Builder() {
            override fun establish(): ParcelFileDescriptor? {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    val (excludedRoutes, forcedTunnelRoutes) =
                        AndroidSplitTunnel.currentVpnRoutes()
                    excludedRoutes.forEach(::excludeRoute)
                    // A later, more specific route keeps VPN DNS inside the tunnel even when
                    // a panel or local exclusion contains the resolver's parent prefix.
                    forcedTunnelRoutes.forEach(::addRoute)
                }
                return super.establish()
            }
        }

    override fun onCreate() {
        super.onCreate()
        TunnelLog.initialize(applicationContext)
        TunnelRuntime.initialize(applicationContext)
        recoveryStore = AndroidRecoveryStores.open(applicationContext)
        connectionIntentCoordinator = AndroidConnectionIntentCoordinator(
            recoveryStore,
            diagnostics = AndroidConnectionIntentDiagnosticsObserver {
                AutomaticDiagnostics.onConnectionIntentLeaseReplacementStarted()
            },
        )
        connectionIntentLifecycle = ConnectionIntentServiceLifecycle(
            coordinator = connectionIntentCoordinator,
            hasPendingLogout = ::hasPendingBackgroundLogout,
            scheduleLogout = ::scheduleLogoutAttempt,
            schedule = ::scheduleConnectionIntentAttempt,
        )
        connectionIntentAttemptDispatcher = AndroidConnectionIntentAttemptDispatcher(
            execute = credentialExecutor::execute,
            persistedDelayMillis = {
                (connectionIntentCoordinator.status() as? RecoveryStoreResult.Success)
                    ?.value
                    ?.let {
                        connectionIntentPersistedDelayMillis(
                            it,
                            nowUnix = System.currentTimeMillis() / 1_000,
                        )
                    } ?: 0L
            },
            scheduleAfter = ::scheduleConnectionIntentTimer,
            attempt = {
                val step = connectionIntentCoordinator.runOnce(
                    ServiceConnectionIntentPanel(),
                    ServiceConnectionIntentRuntime(),
                    onRecovered = { episodeId ->
                        runCatching {
                            AutomaticDiagnostics.onConnectionIntentRecovered(
                                applicationContext,
                                episodeId,
                            )
                        }.onFailure { failure ->
                            TunnelLog.warning(
                                "diagnostics.connection_intent_state_failed",
                                error = failure,
                            )
                        }
                    },
                    validateNewIntent = ::validateNewIntentCapability,
                )
                restoreHandler.post { completeConnectionIntentStep(step) }
            },
        )
        logoutCoordinator = AndroidLogoutCoordinator(
            AndroidBackgroundCredentialStores.open(applicationContext),
            connectionIntentCoordinator,
        )
        runCatching { AutomaticDiagnostics.initialize(applicationContext) }
            .onFailure { TunnelLog.warning("diagnostics.initialize_failed", error = it) }
        activeService = this
        serviceReady.complete(Unit)
        TunnelLog.info("service.created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        idleStopDebouncer.cancel()
        if (intent == null || intent.action in FOREGROUND_ACTIONS) {
            promoteToForeground()
        }
        if (intent == null) {
            val stickyRecovery = recoveryStore.read()
            if (!shouldEnterLegacyVpnRecovery(stickyRecovery)) {
                // A v2 envelope (or an unreadable store) owns this restart.  Do not let
                // quick/legacy recovery reinterpret it as an idle service.
                dispatchRedundantResume(stickyRecovery)
                return START_STICKY
            }
        }
        when {
            intent?.action == ACTION_QUICK_TOGGLE -> {
                cancelRestoreRetry()
                performBackgroundToggle(intent.resultReceiver())
            }
            intent?.action == ACTION_ENSURE_RUNNING -> {
                val recovery = recoveryStore.read()
                if (!shouldEnterLegacyVpnRecovery(recovery)) {
                    dispatchRedundantResume(recovery)
                } else if (!connectionIntentLifecycle.onEnsureRunning()) {
                    restoreDesiredTunnel("ensure_running")
                }
            }
            intent?.action == ACTION_CLIENT_START -> handleClientStart(intent)
            intent?.action == ACTION_CANCEL_CLIENT_START -> handleCancelClientStart(intent)
            intent?.action == ACTION_CLIENT_STOP -> handleClientStop(intent)
            intent?.action == ACTION_CLIENT_STATUS -> handleClientStatus(intent)
            intent?.action == ACTION_CLIENT_METRICS -> handleClientMetrics(intent)
            intent?.action == ACTION_CLIENT_REBIND_UDP -> handleClientRebindUdp(intent)
            intent?.action == ACTION_BEGIN_CONNECTION_INTENT -> handleBeginConnectionIntent(intent)
            intent?.action == ACTION_CANCEL_CONNECTION_INTENT -> handleCancelConnectionIntent(intent)
            intent?.action == ACTION_CANCEL_CURRENT_CONNECTION_INTENT -> {
                handleCancelCurrentConnectionIntent(intent)
            }
            intent?.action == ACTION_CONNECTION_INTENT_STATUS -> handleConnectionIntentStatus(intent)
            intent?.action == ACTION_RELEASE_REDUNDANT_STANDBY -> handleReleaseRedundantStandby(intent)
            intent?.action == ACTION_BEGIN_BACKGROUND_LOGOUT -> handleBeginBackgroundLogout(intent)
            intent?.action == ACTION_CONFIGURE_BACKGROUND -> handleConfigureBackground(intent)
            intent?.action == ACTION_ROTATE_BACKGROUND -> handleRotateBackground(intent)
            intent?.action == ACTION_PROVISION_BACKGROUND -> handleProvisionBackground(intent)
            intent?.action == ACTION_RECOVER_BACKGROUND_SESSION -> {
                handleRecoverBackgroundSession(intent)
            }
            intent?.action == ACTION_BACKGROUND_STATUS -> handleBackgroundStatus(intent)
            intent?.action == ACTION_CLEAR_BACKGROUND -> handleClearBackground(intent)
            intent?.action == ACTION_CLEAR_QUICK_PLAN -> handleClearQuickPlan(intent)
            intent?.action == ACTION_UPDATE_QUICK_DNS -> handleUpdateQuickDns(intent)
            intent?.action == ACTION_TAKE_STATE_CHANGE -> handleTakeStateChange(intent)
            intent?.action == ACTION_ACKNOWLEDGE_STATE_CHANGE -> handleAcknowledgeStateChange(intent)
            intent == null && connectionIntentLifecycle.onStickyRestart() -> Unit
            intent == null && QuickTunnelController.desiredActive(applicationContext) -> {
                restoreDesiredTunnel("sticky_restart")
            }
            intent == null && hasPendingBackgroundLogout() -> scheduleLogoutAttempt()
            intent == null -> {
                TunnelLog.info("service.idle_restart_stopped")
                ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
                stopSelf(startId)
                return START_NOT_STICKY
            }
        }
        return START_STICKY
    }

    private fun handleClientStart(intent: Intent) {
        val receiver = intent.resultReceiver()
        val configuration = intent.getByteArrayExtra(EXTRA_CONFIGURATION)
        val redundantBundle = intent.getBundleExtra(EXTRA_REDUNDANCY)
        var redundantConfiguration: ByteArray? = null
        val args = try {
            StartTunnelArgs().apply {
                apiVersion = intent.getIntExtra(EXTRA_API_VERSION, 0)
                clientOperationId = UUID.fromString(
                    requireNotNull(intent.getStringExtra(EXTRA_CLIENT_OPERATION_ID)),
                ).toString()
                startSource = intent.getStringExtra(EXTRA_START_SOURCE) ?: "ui"
                this.configuration = requireNotNull(configuration)
                options = requireNotNull(intent.getBundleExtra(EXTRA_OPTIONS)).toTunnelOptions()
                cacheQuickAction = intent.getBooleanExtra(EXTRA_CACHE_QUICK_ACTION, false)
                quickActionValidUntilUnix = intent.getLongExtra(
                    EXTRA_QUICK_ACTION_VALID_UNTIL,
                    Long.MIN_VALUE,
                ).takeUnless { it == Long.MIN_VALUE }
                quickConnection = intent.getBundleExtra(EXTRA_QUICK_CONNECTION)?.toQuickConnection()
                redundancy = redundantBundle?.toRedundantStart()?.also {
                    redundantConfiguration = it.standby?.configuration
                }
            }
        } catch (_: Throwable) {
            configuration?.fill(0)
            redundantConfiguration?.fill(0)
            redundantBundle?.getBundle("standby")?.getByteArray("configuration")?.fill(0)
            receiver.sendError("invalid_tunnel_request")
            stopIfIdle()
            return
        }
        if (args.redundancy != null && !redundantStartOperation.begin(
                requireNotNull(args.clientOperationId),
                onCancelled = {
                    QuickTunnelController.updateState(
                        applicationContext,
                        SessionState.STOPPED,
                        desiredActive = false,
                    )
                    receiver.sendOperation(SessionState.STOPPED, 0)
                },
            )
        ) {
            args.clearSensitiveConfigurations()
            receiver.sendError("tunnel_operation_in_progress")
            stopIfIdle()
            return
        }
        QuickTunnelController.updateState(
            applicationContext,
            SessionState.STARTING,
            desiredActive = true,
        )
        if (args.redundancy != null) {
            redundantWork.execute { startRedundantClient(args, receiver) }
            return
        }
        TunnelRuntime.start(
            applicationContext,
            args,
            { state, duration ->
                val durableDesiredActive = QuickTunnelController.desiredActive(applicationContext)
                QuickTunnelController.updateState(
                    applicationContext,
                    state,
                    desiredActive = legacyStartCallbackDesiredActive(
                        durableDesiredActive,
                        state,
                    ),
                )
                receiver.sendOperation(state, duration)
            },
            { code ->
                val state = TunnelRuntime.state()
                val durableDesiredActive = QuickTunnelController.desiredActive(applicationContext)
                QuickTunnelController.updateState(
                    applicationContext,
                    state,
                    desiredActive = legacyStartCallbackDesiredActive(
                        durableDesiredActive,
                        state,
                    ),
                )
                receiver.sendError(code)
                stopIfIdle()
            },
        )
    }

    private fun startRedundantClient(args: StartTunnelArgs, receiver: ResultReceiver?) {
        val startedAt = System.nanoTime()
        val clientOperationId = requireNotNull(args.clientOperationId)
        var nativeOwner: ServiceRedundantConnectionNative? = null
        var coordinatorOwner: RedundantConnectionCoordinator? = null
        try {
            if (args.apiVersion != TUNNEL_API_VERSION) {
                throw BackgroundConnectionException("unsupported_api_version")
            }
            val redundancy = requireNotNull(args.redundancy)
            val credential = serviceActiveCredential(serviceCredential().deviceId)
            val transaction = redundantTransactionFromStart(
                redundancy,
                args,
                credential.deviceId,
                Build.VERSION.SDK_INT,
            )
            val physicalState = PhysicalNetworks(applicationContext).snapshotState()
            val (coordinator, native) = createRedundantCoordinator(
                transaction,
                redundancy.virtualAddressV4,
                physicalState,
            )
            nativeOwner = native
            coordinatorOwner = coordinator
            val configurations = linkedMapOf(redundancy.primary.leaseId to args.configuration)
            redundancy.standby?.let { configurations[it.member.leaseId] = it.configuration }
            val probes = redundantHealthProbesFromStart(redundancy)
            val started = coordinator.start(
                transaction,
                configurations,
                probes,
                shouldCancel = {
                    redundantStartOperation.isCancelled(clientOperationId)
                },
                onPrimaryStarted = {
                    restoreHandler.post {
                        val current = (recoveryStore.read() as? RecoveryStoreResult.Success)
                            ?.value?.redundantTransaction
                        if (current?.desiredActive == true &&
                            current.retry.stopState == RedundantStopState.NONE
                        ) {
                            redundantStartOperation.complete(clientOperationId) {
                                QuickTunnelController.updateState(
                                    applicationContext,
                                    SessionState.RUNNING,
                                    desiredActive = true,
                                )
                                receiver.sendOperation(
                                    SessionState.RUNNING,
                                    TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt),
                                )
                            }
                        } else {
                            redundantStartOperation.completeCancelled(clientOperationId)
                        }
                    }
                },
                onPrimaryFailed = {
                    val cancelled = redundantStartOperation.isCancelled(clientOperationId)
                    coordinator.fenceRevoke()
                    coordinator.revoke()
                    installRedundantVpnOwner(null)
                    restoreHandler.post {
                        if (cancelled) {
                            redundantStartOperation.completeCancelled(clientOperationId)
                        } else {
                            redundantStartOperation.complete(clientOperationId) {
                                QuickTunnelController.updateState(
                                    applicationContext,
                                    SessionState.FAILED,
                                    desiredActive = true,
                                )
                                receiver.sendError("redundant_start_failed")
                            }
                        }
                        stopIfIdle()
                    }
                },
                onPrimaryCancelled = {
                    restoreHandler.post {
                        redundantStartOperation.completeCancelled(clientOperationId)
                    }
                },
            )
            if (!started) {
                val current = (recoveryStore.read() as? RecoveryStoreResult.Success)
                    ?.value?.redundantTransaction
                val cancelled = redundantStartOperation.isCancelled(clientOperationId) ||
                    current?.desiredActive == false ||
                    current?.retry?.stopState?.let { it != RedundantStopState.NONE } == true
                coordinator.fenceRevoke()
                coordinator.revoke()
                installRedundantVpnOwner(null)
                restoreHandler.post {
                    if (cancelled) {
                        redundantStartOperation.completeCancelled(clientOperationId)
                    } else {
                        redundantStartOperation.complete(clientOperationId) {
                            QuickTunnelController.updateState(
                                applicationContext,
                                SessionState.FAILED,
                                desiredActive = true,
                            )
                            receiver.sendError("redundant_start_failed")
                        }
                    }
                    stopIfIdle()
                }
            }
        } catch (error: Throwable) {
            coordinatorOwner?.let { coordinator ->
                runCatching {
                    if (coordinator.fenceRevoke()) coordinator.revoke()
                }
            }
            installRedundantVpnOwner(null)
            if (coordinatorOwner == null) nativeOwner?.stop()
            val code = (error as? BackgroundConnectionException)?.code
                ?: "redundant_start_failed"
            TunnelLog.warning("redundant.start_failed", code)
            restoreHandler.post {
                if (redundantStartOperation.isCancelled(clientOperationId)) {
                    redundantStartOperation.completeCancelled(clientOperationId)
                } else {
                    redundantStartOperation.complete(clientOperationId) {
                        QuickTunnelController.updateState(
                            applicationContext,
                            SessionState.FAILED,
                            desiredActive = true,
                        )
                        receiver.sendError(code)
                    }
                }
                stopIfIdle()
            }
        } finally {
            args.clearSensitiveConfigurations()
            redundantStartOperation.workerFinished(clientOperationId)
        }
    }

    private fun establishRedundantTun(config: Config): Int? = runCatching {
        val builder = getBuilder().setSession("nelomai")
        config.getInterface().excludedApplications.forEach(builder::addDisallowedApplication)
        config.getInterface().includedApplications.forEach(builder::addAllowedApplication)
        config.getInterface().addresses.forEach { builder.addAddress(it.address, it.mask) }
        config.getInterface().dnsServers.forEach {
            builder.addDnsServer(requireNotNull(it.hostAddress))
        }
        config.getInterface().dnsSearchDomains.forEach(builder::addSearchDomain)
        var sawDefaultRoute = false
        config.peers.forEach { peer ->
            peer.allowedIps.forEach { address ->
                if (address.mask == 0) sawDefaultRoute = true
                builder.addRoute(address.address, address.mask)
            }
        }
        if (!(sawDefaultRoute && config.peers.size == 1)) {
            builder.allowFamily(OsConstants.AF_INET)
            builder.allowFamily(OsConstants.AF_INET6)
        }
        builder.setMtu(config.getInterface().mtu.orElse(1280))
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)
        builder.setBlocking(true)
        builder.establish()?.detachFd()
    }.getOrNull()

    private fun createRedundantCoordinator(
        transaction: AndroidRedundantTransaction,
        probeSourceIpv4: String,
        physicalState: PhysicalNetworkState,
    ): Pair<RedundantConnectionCoordinator, ServiceRedundantConnectionNative> {
        val options = AndroidSplitTunnel.resolveOptions(
            Build.VERSION.SDK_INT,
            transaction.template.options.toTunnelOptionsArgs(),
        )
        val localRoutes = if (options.splitSupported && options.excludeLocalNetworks) {
            physicalState.localRoutes
        } else {
            emptyList()
        }
        AndroidSplitTunnel.replaceVpnRoutes(
            AndroidSplitTunnel.mergeExcludedRoutes(options.excludedRoutes, localRoutes),
            options.dnsServers,
        )
        setUnderlyingNetworks(
            physicalState.networks.toTypedArray().takeIf { it.isNotEmpty() },
        )
        val native = ServiceRedundantConnectionNative(
            backend = RedundantNativeBackend(
                JniRedundantNativeApi(applicationContext),
                protectSocket = ::protect,
            ),
            establishTun = ::establishRedundantTun,
            prepare = { configuration ->
                val config = TunnelPayload.consume(configuration) { payload ->
                    Config.parse(ByteArrayInputStream(payload))
                }.let { parsed ->
                    AndroidSplitTunnel.applyOptions(
                        parsed,
                        options,
                        applicationContext.packageName,
                    )
                }
                resolveRedundantEndpoints(config)
                PreparedRedundantConfiguration(
                    config,
                    config.toAwgUserspaceString().toByteArray(StandardCharsets.UTF_8),
                )
            },
            probeSourceIpv4 = probeSourceIpv4,
            initialNetworkValidated = physicalState.validated,
        )
        val coordinator = RedundantConnectionCoordinator(
            recoveryStore,
            ServiceRedundantConnectionPanel(::serviceActiveCredential),
            native,
            healthMonitor = RedundantHealthMonitor(
                initialNetworkValidated = physicalState.validated,
            ),
            onAllSlotsStalled = { TunnelLog.warning("redundant.session_stalled") },
            onReserveStateChanged = { state ->
                AutomaticDiagnostics.onRedundantStateChanged(
                    state?.wireName,
                    native.diagnosticMetrics(),
                )
                restoreHandler.post {
                    refreshConnectionNotification(redundantNotificationContent(state))
                }
            },
            onDiagnosticEvent = { event ->
                AutomaticDiagnostics.onRedundantEvent(event, native.diagnosticMetrics())
            },
        )
        installRedundantVpnOwner(coordinator)
        redundantPhysicalNetworks?.stop()
        redundantPhysicalNetworks = PhysicalNetworks(applicationContext).also { monitor ->
            monitor.start { state ->
                setPhysicalNetworks(state.networks, state.validated)
            }
        }
        return coordinator to native
    }

    private fun ensureRedundantCoordinator(
        transaction: AndroidRedundantTransaction,
    ): RedundantVpnProcessOwner {
        redundantVpnOwner?.let { return it }
        return createRedundantCoordinator(
            transaction,
            probeSourceIpv4 = "",
            physicalState = PhysicalNetworks(applicationContext).snapshotState(),
        ).first
    }

    private fun dispatchRedundantResume(
        recovery: RecoveryStoreResult<AndroidRecoveryEnvelope>,
    ): Boolean {
        val transaction = (recovery as? RecoveryStoreResult.Success)
            ?.value?.redundantTransaction ?: return false
        redundantWork.resume {
            runCatching { ensureRedundantCoordinator(transaction).resume() }
                .onFailure { TunnelLog.warning("redundant.resume_failed") }
        }
        return true
    }

    private fun resolveRedundantEndpoints(config: Config) {
        repeat(3) { attempt ->
            val unresolved = config.peers.mapNotNull { peer ->
                peer.endpoint.orElse(null)?.takeIf { it.resolved.orElse(null) == null }
            }
            if (unresolved.isEmpty()) return
            if (attempt < 2) Thread.sleep(1_000L)
        }
        throw BackgroundConnectionException("dns_resolution_failure")
    }

    private fun handleCancelClientStart(intent: Intent) {
        val clientOperationId = runCatching {
            UUID.fromString(
                requireNotNull(intent.getStringExtra(EXTRA_CLIENT_OPERATION_ID)),
            ).toString()
        }.getOrNull() ?: run {
            stopIfIdle()
            return
        }
        val pendingCancelled = redundantStartOperation.cancel(clientOperationId)
        if (pendingCancelled) {
            QuickTunnelController.updateState(
                applicationContext,
                SessionState.STOPPING,
                desiredActive = false,
            )
            redundantStartOperation.completeCancelled(clientOperationId)
        }
        val recovery = recoveryStore.read()
        val transaction = (recovery as? RecoveryStoreResult.Success)
            ?.value?.redundantTransaction
        if (recovery is RecoveryStoreResult.Failure) {
            TunnelLog.warning("redundant.start_cancel_recovery_failed", recovery.code)
            if (!pendingCancelled) stopIfIdle()
            return
        }
        if (transaction == null && pendingCancelled) return
        if (transaction != null) {
            if (transaction.startOperationId != clientOperationId) return
            val owner = redundantVpnOwner
            QuickTunnelController.updateState(
                applicationContext,
                SessionState.STOPPING,
                desiredActive = false,
            )
            redundantStartOperation.completeCancelled(clientOperationId)
            dispatchRedundantRevoke(
                redundantWork,
                fence = {
                    owner?.fenceRevoke() ?: (
                        recoveryStore.deferRedundantStop(
                            transaction.stopOperationId ?: UUID.randomUUID().toString(),
                        ) is RecoveryStoreResult.Success
                    )
                },
                revoke = {
                    (owner ?: ensureRedundantCoordinator(transaction)).revoke()
                },
            ) { result ->
                restoreHandler.post {
                    if (!result.fenced) {
                        TunnelLog.warning("redundant.start_cancel_fence_failed")
                    } else if (result.stopped) {
                        installRedundantVpnOwner(null)
                        QuickTunnelController.updateState(
                            applicationContext,
                            SessionState.STOPPED,
                            desiredActive = false,
                        )
                    } else {
                        TunnelLog.warning("redundant.start_cancel_pending")
                    }
                    stopIfIdle()
                }
            }
            return
        }
        TunnelRuntime.cancelClientStart(applicationContext, clientOperationId)
        stopIfIdle()
    }

    private fun handleClientStop(intent: Intent) {
        val receiver = intent.resultReceiver()
        if (intent.getIntExtra(EXTRA_API_VERSION, 0) != TUNNEL_API_VERSION) {
            receiver.sendError("unsupported_api_version")
            return
        }
        val pendingOperationId = redundantStartOperation.cancelPendingAndComplete()
        val recovery = recoveryStore.read()
        if (shouldEnterLegacyVpnRecovery(recovery)) {
            if (pendingOperationId != null) {
                receiver.sendOperation(SessionState.STOPPED, 0)
                return
            }
        }
        if (!shouldEnterLegacyVpnRecovery(recovery)) {
            val transaction = (recovery as? RecoveryStoreResult.Success)
                ?.value?.redundantTransaction
            if (transaction == null) {
                receiver.sendError("redundant_stop_fence_failed")
                return
            }
            val existingOwner = redundantVpnOwner
            QuickTunnelController.updateState(
                applicationContext,
                SessionState.STOPPING,
                desiredActive = false,
            )
            redundantStartOperation.completeCancelled(transaction.startOperationId)
            dispatchRedundantRevoke(
                redundantWork,
                fence = {
                    existingOwner?.fenceRevoke() ?: (
                        recoveryStore.deferRedundantStop(
                            transaction.stopOperationId ?: UUID.randomUUID().toString(),
                        ) is RecoveryStoreResult.Success
                    )
                },
                revoke = {
                    (existingOwner ?: ensureRedundantCoordinator(transaction)).revoke()
                },
            ) { result ->
                restoreHandler.post {
                    if (!result.fenced) {
                        receiver.sendError("redundant_stop_fence_failed")
                    } else if (result.stopped) {
                        installRedundantVpnOwner(null)
                        QuickTunnelController.updateState(
                            applicationContext,
                            SessionState.STOPPED,
                            desiredActive = false,
                        )
                        receiver.sendOperation(SessionState.STOPPED, 0)
                    } else {
                        receiver.sendError("redundant_stop_pending")
                    }
                    stopIfIdle()
                }
            }
            return
        }
        QuickTunnelController.updateState(
            applicationContext,
            SessionState.STOPPING,
            desiredActive = false,
        )
        TunnelRuntime.stop(
            intent.getIntExtra(EXTRA_API_VERSION, 0),
            { state, duration ->
                QuickTunnelController.updateState(
                    applicationContext,
                    state,
                    desiredActive = false,
                )
                receiver.sendOperation(state, duration)
            },
            { code ->
                val state = TunnelRuntime.state()
                QuickTunnelController.updateState(
                    applicationContext,
                    state,
                    desiredActive = state in setOf(
                        SessionState.RUNNING,
                        SessionState.STARTING,
                    ),
                )
                receiver.sendError(code)
                stopIfIdle()
            },
        )
    }

    private fun handleClientStatus(intent: Intent) {
        if (intent.getIntExtra(EXTRA_API_VERSION, 0) != TUNNEL_API_VERSION) {
            intent.resultReceiver().sendError("unsupported_api_version")
            stopIfIdle()
            return
        }
        val recovery = recoveryStore.read()
        val redundant = (recovery as? RecoveryStoreResult.Success)
            ?.value?.redundantTransaction
        if (redundant != null) {
            val state = if (!redundant.desiredActive ||
                redundant.retry.stopState != RedundantStopState.NONE
            ) SessionState.STOPPING else if (redundantVpnOwner?.isRunning() == true) {
                SessionState.RUNNING
            } else {
                dispatchRedundantResume(recovery)
                SessionState.STARTING
            }
            intent.resultReceiver().sendOperation(state, 0)
            return
        }
        if (recovery is RecoveryStoreResult.Failure) {
            intent.resultReceiver().sendError(recovery.code)
            return
        }
        val state = TunnelRuntime.state()
        if (shouldRestoreDesiredTunnel(
            QuickTunnelController.desiredActive(applicationContext),
            state,
        )) {
            restoreDesiredTunnel("client_status")
            intent.resultReceiver().sendOperation(SessionState.STARTING, 0)
            return
        }
        intent.resultReceiver().sendOperation(state, 0)
        stopIfIdle()
    }

    private fun handleClientMetrics(intent: Intent) {
        val receiver = intent.resultReceiver()
        if (intent.getIntExtra(EXTRA_API_VERSION, 0) != TUNNEL_API_VERSION) {
            receiver.sendError("unsupported_api_version")
            stopIfIdle()
            return
        }
        val recovery = recoveryStore.read()
        val redundant = (recovery as? RecoveryStoreResult.Success)
            ?.value?.redundantTransaction
        if (redundant != null) {
            val includeProbeTarget = intent.getBooleanExtra(EXTRA_PROBE, false)
            redundantWork.execute {
                val owner = redundantVpnOwner ?: ensureRedundantCoordinator(redundant)
                val ready = owner.isRunning() || runCatching(owner::resume).getOrDefault(false)
                val metrics = if (ready) {
                    runCatching { owner.metrics(includeProbeTarget) }.getOrNull()
                } else {
                    null
                }
                restoreHandler.post {
                    if (metrics == null) {
                        receiver.sendError("tunnel_not_running")
                    } else {
                        receiver?.send(
                            SERVICE_RESULT_OK,
                            Bundle().apply {
                                putLong(EXTRA_RECEIVED_BYTES, metrics.receivedBytes)
                                putLong(EXTRA_SENT_BYTES, metrics.sentBytes)
                                metrics.latestHandshakeEpochMillis?.let {
                                    putLong(EXTRA_LATEST_HANDSHAKE_EPOCH_MILLIS, it)
                                }
                                putString(EXTRA_PROBE_TARGET, metrics.probeTarget)
                            },
                        )
                    }
                    stopIfIdle()
                }
            }
            return
        }
        if (recovery is RecoveryStoreResult.Failure) {
            receiver.sendError(recovery.code)
            stopIfIdle()
            return
        }
        TunnelRuntime.metrics(
            TUNNEL_API_VERSION,
            intent.getBooleanExtra(EXTRA_PROBE, false),
            { received, sent, latestHandshakeEpochMillis, target ->
                receiver?.send(
                    SERVICE_RESULT_OK,
                    Bundle().apply {
                        putLong(EXTRA_RECEIVED_BYTES, received)
                        putLong(EXTRA_SENT_BYTES, sent)
                        latestHandshakeEpochMillis?.let {
                            putLong(EXTRA_LATEST_HANDSHAKE_EPOCH_MILLIS, it)
                        }
                        putString(EXTRA_PROBE_TARGET, target)
                    },
                )
                stopIfIdle()
            },
            { code ->
                receiver.sendError(code)
                stopIfIdle()
            },
        )
    }

    private fun handleClientRebindUdp(intent: Intent) {
        val receiver = intent.resultReceiver()
        val recovery = recoveryStore.read()
        if (!shouldEnterLegacyVpnRecovery(recovery)) {
            if (intent.getIntExtra(EXTRA_API_VERSION, 0) != TUNNEL_API_VERSION) {
                receiver.sendError("unsupported_api_version")
                return
            }
            val transaction = (recovery as? RecoveryStoreResult.Success)
                ?.value?.redundantTransaction
            redundantWork.execute {
                val owner = redundantVpnOwner ?: transaction?.let(::ensureRedundantCoordinator)
                val rebound = routeVpnProcessNetworkChange(
                    recoveryStore.read(),
                    owner,
                    validated = true,
                    legacyNetworkChange = {},
                )
                restoreHandler.post {
                    if (rebound) receiver.sendOperation(SessionState.RUNNING, 0)
                    else receiver.sendError("redundant_rebind_failed")
                }
            }
            return
        }
        TunnelRuntime.rebindUdp(
            applicationContext,
            intent.getIntExtra(EXTRA_API_VERSION, 0),
            { state, duration -> receiver.sendOperation(state, duration) },
            { code -> receiver.sendError(code) },
        )
    }

    private fun handleBeginConnectionIntent(intent: Intent) {
        val receiver = intent.resultReceiver()
        val template = try {
            if (intent.getIntExtra(EXTRA_API_VERSION, 0) != TUNNEL_API_VERSION) {
                throw BackgroundConnectionException("unsupported_api_version")
            }
            AndroidIntentTemplate(
                deviceId = canonicalUuid(intent.getStringExtra(EXTRA_DEVICE_ID)),
                accountScope = canonicalUuid(intent.getStringExtra(EXTRA_ACCOUNT_SCOPE)),
                layer = requireWireChoice(intent.getStringExtra(EXTRA_LAYER), setOf("tic", "stray")),
                ticConnectionMode = requireWireChoice(
                    intent.getStringExtra(EXTRA_TIC_CONNECTION_MODE),
                    setOf("personal", "dynamic"),
                ),
                routeMode = requireWireChoice(
                    intent.getStringExtra(EXTRA_ROUTE_MODE),
                    setOf("standalone", "via_tak"),
                ),
                egressMode = requireWireChoice(
                    intent.getStringExtra(EXTRA_EGRESS_MODE),
                    setOf("ipv4", "prefer_ipv6"),
                ),
                allowAlternate = intent.getBooleanExtra(EXTRA_ALLOW_ALTERNATE, false),
                syncBindingPreferences = intent.getBooleanExtra(
                    EXTRA_SYNC_BINDING_PREFERENCES,
                    false,
                ),
                options = normalizeAndroidTunnelOptions(
                    Build.VERSION.SDK_INT,
                    intent.getBundleExtra(EXTRA_OPTIONS)?.toTunnelOptions()
                        ?: TunnelOptionsArgs(),
                ),
            )
        } catch (error: BackgroundConnectionException) {
            receiver.sendError(error.code)
            stopIfIdle()
            return
        } catch (_: Throwable) {
            receiver.sendError("invalid_connection_intent")
            stopIfIdle()
            return
        }
        val current = when (val result = connectionIntentCoordinator.status()) {
            is RecoveryStoreResult.Success -> result.value
            is RecoveryStoreResult.Failure -> {
                receiver.sendError(result.code)
                stopIfIdle()
                return
            }
        }
        val ticket = connectionIntentDispatch.start(current.intent.generation)
        dispatchSerializedConnectionIntentMutation(credentialExecutor) {
            when (val accepted = executeDispatchedConnectionIntent(
                connectionIntentDispatch,
                ticket,
            ) { beginExplicitConnectionIntent(template, ticket) }) {
                is AndroidCoordinatorResult.Accepted -> {
                    QuickTunnelController.updateState(
                        applicationContext,
                        SessionState.STARTING,
                        desiredActive = null,
                    )
                    receiver?.send(
                        SERVICE_RESULT_OK,
                        connectionIntentServiceStatus(accepted.envelope).toBundle(),
                    )
                    scheduleConnectionIntentAttempt()
                }
                is AndroidCoordinatorResult.Failure -> {
                    receiver.sendError(accepted.code)
                    stopIfIdle()
                }
            }
        }
    }

    private fun handleCancelConnectionIntent(intent: Intent) {
        val receiver = intent.resultReceiver()
        val generation = intent.getLongExtra(EXTRA_GENERATION, -1)
        if (generation < 0) {
            receiver.sendError("invalid_connection_intent")
            stopIfIdle()
            return
        }
        handleConnectionIntentCancellation(intent) {
            connectionIntentCoordinator.cancel(generation)
        }
    }

    private fun handleCancelCurrentConnectionIntent(intent: Intent) {
        handleConnectionIntentCancellation(intent) {
            connectionIntentCoordinator.cancelCurrent()
        }
    }

    private fun handleConnectionIntentCancellation(
        intent: Intent,
        cancel: () -> AndroidCoordinatorResult,
    ) {
        val receiver = intent.resultReceiver()
        when (val cancelled = cancelDispatchedConnectionIntent(connectionIntentDispatch) {
            cancel()
        }) {
            is AndroidCoordinatorResult.Accepted -> {
                connectionIntentRuntimeFence.cancelActive()
                runCatching {
                    AutomaticDiagnostics.onConnectionIntentCancelled(
                        applicationContext,
                        cancelled.envelope.intent.diagnosticsEpisodeId,
                    )
                }.onFailure {
                    TunnelLog.warning(
                        "diagnostics.connection_intent_state_failed",
                        error = it,
                    )
                }
                cancelRestoreRetry()
                QuickTunnelController.updateState(
                    applicationContext,
                    SessionState.STOPPING,
                    desiredActive = null,
                )
                receiver?.send(
                    SERVICE_RESULT_OK,
                    connectionIntentServiceStatus(cancelled.envelope).toBundle(),
                )
                scheduleConnectionIntentAttempt()
            }
            is AndroidCoordinatorResult.Failure -> receiver.sendError(cancelled.code)
        }
    }

    private fun handleConnectionIntentStatus(intent: Intent) {
        when (val result = connectionIntentCoordinator.status()) {
            is RecoveryStoreResult.Success -> intent.resultReceiver()?.send(
                SERVICE_RESULT_OK,
                connectionIntentServiceStatus(
                    result.value,
                    redundantVpnOwner?.reserveState()?.wireName
                        ?: result.value.redundantTransaction?.standbyDesired
                            ?.takeIf { it }
                            ?.let { RedundantReserveState.WARMING.wireName },
                ).toBundle(),
            )
            is RecoveryStoreResult.Failure -> intent.resultReceiver().sendError(result.code)
        }
        stopIfIdle()
    }

    private fun handleReleaseRedundantStandby(intent: Intent) {
        val receiver = intent.resultReceiver()
        val recovery = recoveryStore.read()
        val envelope = (recovery as? RecoveryStoreResult.Success)?.value
        val transaction = envelope?.redundantTransaction
        if (transaction == null) {
            if (envelope == null) receiver.sendError("redundant_recovery_unavailable")
            else receiver?.send(
                SERVICE_RESULT_OK,
                connectionIntentServiceStatus(envelope).toBundle(),
            )
            stopIfIdle()
            return
        }
        redundantWork.execute {
            val owner = redundantVpnOwner ?: ensureRedundantCoordinator(transaction)
            val released = runCatching(owner::releaseStandby).getOrDefault(false)
            val current = (recoveryStore.read() as? RecoveryStoreResult.Success)?.value
            restoreHandler.post {
                if (!released || current == null) {
                    receiver.sendError("redundant_standby_release_failed")
                } else {
                    receiver?.send(
                        SERVICE_RESULT_OK,
                        connectionIntentServiceStatus(
                            current,
                            owner.reserveState()?.wireName,
                        ).toBundle(),
                    )
                }
            }
        }
    }

    private fun handleBeginBackgroundLogout(intent: Intent) {
        when (val result = beginDispatchedLogout(connectionIntentDispatch) {
            logoutCoordinator.begin()
        }) {
            is AndroidLogoutResult.Accepted -> {
                connectionIntentRuntimeFence.cancelActive()
                intent.resultReceiver()?.send(
                    SERVICE_RESULT_OK,
                    Bundle().apply {
                        putString(
                            EXTRA_LOGOUT_OWNERSHIP,
                            BackgroundLogoutOwnership.NATIVE.wireName,
                        )
                    },
                )
                scheduleLogoutAttempt()
            }
            is AndroidLogoutResult.NotOwned -> {
                connectionIntentRuntimeFence.cancelActive()
                intent.resultReceiver()?.send(
                    SERVICE_RESULT_OK,
                    Bundle().apply {
                        putString(
                            EXTRA_LOGOUT_OWNERSHIP,
                            BackgroundLogoutOwnership.NOT_OWNED.wireName,
                        )
                    },
                )
                val durableConnectionWork = result.envelope.leaseTransaction != null ||
                    result.envelope.intent.retry.pendingAction != null
                if (durableConnectionWork) scheduleConnectionIntentAttempt() else stopIfIdle()
            }
            is AndroidLogoutResult.Failure -> {
                intent.resultReceiver().sendError(result.code)
                stopIfIdle()
            }
        }
    }

    private fun handleConfigureBackground(intent: Intent) {
        val receiver = intent.resultReceiver()
        try {
            val apiVersion = intent.getIntExtra(EXTRA_API_VERSION, 0)
            val expiresAtUnix = intent.getLongExtra(EXTRA_EXPIRES_AT_UNIX, 0)
            if (apiVersion != TUNNEL_API_VERSION || expiresAtUnix <= 0) {
                throw IllegalArgumentException("invalid background credential")
            }
            val store = AndroidBackgroundCredentialStores.open(applicationContext)
            val current = when (val result = store.read()) {
                is CredentialStoreResult.Success -> result.value
                is CredentialStoreResult.Failure -> {
                    receiver.sendError(result.code)
                    return
                }
            }
            val installGeneration = if (
                current.logoutState?.phase == BackgroundLogoutPhase.FINALIZED
            ) {
                requireNotNull(current.installGeneration) + 1
            } else {
                current.installGeneration ?: 1
            }
            val configured = store.configure(
                expectedRevision = intent.getLongExtra(EXTRA_CREDENTIAL_REVISION, -1),
                provision = BackgroundCredentialProvision(
                    deviceId = requireNotNull(intent.getStringExtra(EXTRA_DEVICE_ID)),
                    panelBase = requireNotNull(intent.getStringExtra(EXTRA_PANEL_BASE)),
                    token = requireNotNull(intent.getStringExtra(EXTRA_TOKEN)),
                    expiresAtUnix = expiresAtUnix,
                    installSecret = requireNotNull(
                        intent.getStringExtra(EXTRA_INSTALL_SECRET),
                    ),
                    installGeneration = installGeneration,
                    capability = BackgroundCapabilitySnapshot(
                        revision = intent.getLongExtra(EXTRA_CAPABILITY_REVISION, -1),
                        enabled = intent.getBooleanExtra(EXTRA_CAPABILITY_ENABLED, false),
                        expiresAtUnix = Instant.parse(
                            requireNotNull(intent.getStringExtra(EXTRA_CAPABILITY_EXPIRES_AT)),
                        ).epochSecond,
                    ),
                ),
            )
            if (configured is CredentialStoreResult.Failure) {
                receiver.sendError(configured.code)
                return
            }
            runCatching { AutomaticDiagnostics.credentialUpdated(applicationContext) }
                .onFailure { TunnelLog.warning("diagnostics.credential_update_failed", error = it) }
            receiver.sendSuccess()
        } catch (_: Throwable) {
            receiver.sendError("invalid_background_credential")
        } finally {
            stopIfIdle()
        }
    }

    private fun handleBackgroundStatus(intent: Intent) {
        val envelope = when (
            val result = AndroidBackgroundCredentialStores.open(applicationContext).read()
        ) {
            is CredentialStoreResult.Success -> result.value
            is CredentialStoreResult.Failure -> {
                intent.resultReceiver().sendError(result.code)
                stopIfIdle()
                return
            }
        }
        val credential = envelope.active
        intent.resultReceiver()?.send(
            SERVICE_RESULT_OK,
            Bundle().apply {
                putBoolean(EXTRA_CONFIGURED, hasRecoverableBackgroundCredential(envelope))
                putLong(EXTRA_CREDENTIAL_REVISION, envelope.revision)
                putBoolean(
                    EXTRA_MUTATION_READY,
                    envelope.installSecret != null && envelope.capability != null,
                )
                putBoolean(
                    EXTRA_MUTATION_PENDING,
                    envelope.pending != null || envelope.reservation != null,
                )
                putLong(EXTRA_CAPABILITY_REVISION, envelope.capability?.revision ?: 0L)
                putBoolean(EXTRA_CAPABILITY_ENABLED, envelope.capability?.enabled == true)
                putLong(
                    EXTRA_CAPABILITY_EXPIRES_AT,
                    envelope.capability?.expiresAtUnix ?: Long.MIN_VALUE,
                )
                credential?.let {
                    putString(EXTRA_DEVICE_ID, it.deviceId)
                    putLong(EXTRA_EXPIRES_AT_UNIX, it.expiresAtUnix)
                }
            },
        )
        if (envelope.logoutState?.phase == BackgroundLogoutPhase.PENDING) {
            promoteToForeground()
            connectionIntentLifecycle.onEnsureRunning()
        } else {
            stopIfIdle()
        }
    }

    private fun handleRotateBackground(intent: Intent) {
        val receiver = intent.resultReceiver()
        val expectedRevision = intent.getLongExtra(EXTRA_CREDENTIAL_REVISION, -1)
        credentialExecutor.execute {
            try {
                rotateBackgroundCredential(expectedRevision)
                receiver.sendSuccess()
            } catch (error: BackgroundConnectionException) {
                receiver.sendError(error.code)
            } catch (error: CredentialRotationFailure) {
                receiver.sendError(error.code)
            } catch (_: Throwable) {
                receiver.sendError("background_credential_rotation_failed")
            } finally {
                stopIfIdle()
            }
        }
    }

    private fun handleProvisionBackground(intent: Intent) {
        val receiver = intent.resultReceiver()
        val request = try {
            require(intent.getIntExtra(EXTRA_API_VERSION, 0) == TUNNEL_API_VERSION)
            val store = AndroidBackgroundCredentialStores.open(applicationContext)
            val current = store.read().credentialOrThrow()
            val installGeneration = if (
                current.logoutState?.phase == BackgroundLogoutPhase.FINALIZED
            ) {
                Math.addExact(requireNotNull(current.installGeneration), 1)
            } else {
                current.installGeneration ?: 1
            }
            BackgroundUiProvisionRequest(
                expectedRevision = intent.getLongExtra(EXTRA_CREDENTIAL_REVISION, -1),
                deviceId = requireNotNull(intent.getStringExtra(EXTRA_DEVICE_ID)),
                panelBase = requireNotNull(intent.getStringExtra(EXTRA_PANEL_BASE)),
                accessToken = requireNotNull(intent.getStringExtra(EXTRA_ACCESS_TOKEN)),
                installSecret = requireNotNull(intent.getStringExtra(EXTRA_INSTALL_SECRET)),
                installGeneration = installGeneration,
                capability = BackgroundCapabilitySnapshot(
                    revision = intent.getLongExtra(EXTRA_CAPABILITY_REVISION, -1),
                    enabled = intent.getBooleanExtra(EXTRA_CAPABILITY_ENABLED, false),
                    expiresAtUnix = Instant.parse(
                        requireNotNull(intent.getStringExtra(EXTRA_CAPABILITY_EXPIRES_AT)),
                    ).epochSecond,
                ),
            )
        } catch (error: CredentialRotationFailure) {
            receiver.sendError(error.code)
            stopIfIdle()
            return
        } catch (_: Throwable) {
            receiver.sendError("invalid_background_credential")
            stopIfIdle()
            return
        }
        backgroundCredentialProvisionInFlight.set(true)
        credentialExecutor.execute {
            var provisioned = false
            try {
                provisionBackgroundCredential(
                    store = AndroidBackgroundCredentialStores.open(applicationContext),
                    request = request,
                    nowUnix = System.currentTimeMillis() / 1_000,
                    operationIds = { UUID.randomUUID().toString() to UUID.randomUUID().toString() },
                    prepare = BackgroundConnectionClient::prepareTokenWithBearer,
                    activate = BackgroundConnectionClient::activateToken,
                )
                provisioned = true
                runCatching { AutomaticDiagnostics.credentialUpdated(applicationContext) }
                    .onFailure {
                        TunnelLog.warning("diagnostics.credential_update_failed", error = it)
                    }
                receiver.sendSuccess()
            } catch (error: BackgroundConnectionException) {
                receiver.sendError(error.code)
            } catch (_: Throwable) {
                receiver.sendError("background_credential_provision_failed")
            } finally {
                backgroundCredentialProvisionInFlight.set(false)
                if (provisioned) connectionIntentCoordinator.credentialProvisioningCompleted()
                connectionIntentLifecycle.onEnsureRunning()
                stopIfIdle()
            }
        }
    }

    private fun rotateBackgroundCredential(expectedRevision: Long) {
        val store = AndroidBackgroundCredentialStores.open(applicationContext)
        var envelope = store.read().credentialOrThrow()
        if (envelope.revision != expectedRevision) {
            throw CredentialRotationFailure("background_credential_revision_conflict")
        }
        if (envelope.logoutState != null) {
            throw CredentialRotationFailure("background_credential_logout_pending")
        }
        var credential = envelope.active
            ?: throw CredentialRotationFailure("background_credential_active_absent")
        val installSecret = envelope.installSecret
            ?: throw CredentialRotationFailure("background_credential_unavailable")
        val nowUnix = System.currentTimeMillis() / 1_000

        if (envelope.pending == null && envelope.reservation == null) {
            val capability = refreshBackgroundCapability(envelope.capability, nowUnix) {
                BackgroundConnectionClient.capabilities(credential)
            }
            envelope = store.updateCapability(envelope.revision, capability).credentialOrThrow()
            synchronizeRedundantCapability(requireNotNull(envelope.capability))
            if (!capability.enabled || capability.expiresAtUnix <= nowUnix) return
            if (credential.expiresAtUnix > nowUnix + BACKGROUND_REFRESH_WINDOW_SECONDS) return
        }

        val preparedState = prepareBackgroundTokenDurably(
            store = store,
            envelope = envelope,
            credential = credential,
            installSecret = installSecret,
            nowUnix = nowUnix,
            operationIds = { UUID.randomUUID().toString() to UUID.randomUUID().toString() },
            prepare = BackgroundConnectionClient::prepareToken,
        )
        envelope = preparedState.envelope
        val pending = preparedState.pending

        credential = stagedBackgroundCredential(envelope, pending)
        val activation = try {
            BackgroundConnectionClient.activateToken(credential, pending, installSecret)
        } catch (error: BackgroundConnectionException) {
            if (error.code == "activation_not_applied") {
                store.discardNotApplied(
                    envelope.revision,
                    pending.activationOperationId,
                ).credentialOrThrow()
            }
            throw error
        }
        store.promotePending(
            expectedRevision = envelope.revision,
            activationOperationId = pending.activationOperationId,
            activeExpiresAtUnix = activation.activeExpiresAtUnix,
        ).credentialOrThrow()
    }

    private fun synchronizeRedundantCapability(capability: BackgroundCapabilitySnapshot) {
        val transaction = (recoveryStore.read() as? RecoveryStoreResult.Success)
            ?.value?.redundantTransaction
        if (!redundantCapabilityRequiresStandbyRelease(capability, transaction)) return
        redundantWork.execute {
            val released = runCatching {
                (redundantVpnOwner ?: ensureRedundantCoordinator(requireNotNull(transaction)))
                    .releaseStandby()
            }.onFailure {
                TunnelLog.warning("redundant.capability_release_failed", error = it)
            }.getOrDefault(false)
            if (!released) TunnelLog.warning("redundant.capability_release_pending")
        }
    }

    private fun handleRecoverBackgroundSession(intent: Intent) {
        val receiver = intent.resultReceiver()
        val installSecret = intent.getStringExtra(EXTRA_INSTALL_SECRET) ?: run {
            receiver.sendError("invalid_background_recovery")
            stopIfIdle()
            return
        }
        credentialExecutor.execute {
            try {
                val store = AndroidBackgroundCredentialStores.open(applicationContext)
                val credential = backgroundCredentialForSessionRecovery(store) { envelope ->
                    provisionBackgroundCredential(
                        store = store,
                        request = BackgroundUiProvisionRequest(
                            expectedRevision = envelope.revision,
                            deviceId = requireNotNull(envelope.deviceId),
                            panelBase = requireNotNull(envelope.panelBase),
                            accessToken = "pending-activation-replay",
                            installSecret = installSecret,
                            installGeneration = requireNotNull(envelope.installGeneration),
                            capability = envelope.capability
                                ?: BackgroundCapabilitySnapshot(0, false, 1),
                        ),
                        nowUnix = System.currentTimeMillis() / 1_000,
                        operationIds = { error("pending activation must not mint operation IDs") },
                        prepare = { _, _, _, _ ->
                            error("pending activation must not prepare another token")
                        },
                        activate = BackgroundConnectionClient::activateToken,
                    )
                }
                val recovered = BackgroundConnectionClient.recoverSession(
                    credential,
                    installSecret,
                )
                receiver?.send(
                    SERVICE_RESULT_OK,
                    Bundle().apply {
                        putString(EXTRA_ACCESS_TOKEN, recovered.accessToken)
                        putString(EXTRA_REFRESH_TOKEN, recovered.refreshToken)
                    },
                )
            } catch (error: BackgroundConnectionException) {
                receiver.sendError(error.code)
            } catch (error: CredentialRotationFailure) {
                receiver.sendError(error.code)
            } catch (_: Throwable) {
                receiver.sendError("invalid_background_recovery")
            } finally {
                stopIfIdle()
            }
        }
    }

    private fun handleClearBackground(intent: Intent) {
        if (TunnelRuntime.clearBackgroundCredential(applicationContext)) {
            intent.resultReceiver().sendSuccess()
        } else {
            intent.resultReceiver().sendError("background_storage_unavailable")
        }
        stopIfIdle()
    }

    private fun handleClearQuickPlan(intent: Intent) {
        val planCleared = TunnelRuntime.clearQuickPlan(applicationContext)
        val stateCleared = QuickTunnelController.clearStateChange(applicationContext)
        if (planCleared && stateCleared) {
            intent.resultReceiver().sendSuccess()
        } else {
            intent.resultReceiver().sendError("quick_state_persist_failed")
        }
        stopIfIdle()
    }

    private fun handleUpdateQuickDns(intent: Intent) {
        val dnsServers = intent.getStringArrayListExtra(EXTRA_DNS_SERVERS) ?: arrayListOf()
        val updated = runCatching {
            TunnelRuntime.updateQuickDns(applicationContext, dnsServers)
        }.getOrDefault(false)
        if (updated) {
            intent.resultReceiver().sendSuccess()
        } else {
            intent.resultReceiver().sendError("quick_state_persist_failed")
        }
        stopIfIdle()
    }

    private fun handleTakeStateChange(intent: Intent) {
        val revision = QuickTunnelController.takeStateChangeRevision(applicationContext)
        intent.resultReceiver()?.send(
            SERVICE_RESULT_OK,
            Bundle().apply {
                putBoolean(EXTRA_CHANGED, revision > 0L)
                putLong(EXTRA_STATE_CHANGE_REVISION, revision)
            },
        )
        stopIfIdle()
    }

    private fun handleAcknowledgeStateChange(intent: Intent) {
        val result = QuickTunnelController.acknowledgeStateChange(
            applicationContext,
            intent.getLongExtra(EXTRA_STATE_CHANGE_REVISION, 0L),
        )
        if (result.saved) {
            intent.resultReceiver()?.send(
                SERVICE_RESULT_OK,
                Bundle().apply {
                    putLong(EXTRA_STATE_CHANGE_REVISION, result.pendingRevision)
                },
            )
        } else {
            intent.resultReceiver().sendError("quick_state_persist_failed")
        }
        stopIfIdle()
    }

    override fun onRevoke() {
        TunnelLog.warning("service.vpn_revoked")
        runCatching { AutomaticDiagnostics.onTunnelStopped(applicationContext) }
            .onFailure { TunnelLog.warning("diagnostics.lifecycle_failed", error = it) }
        redundantStartOperation.cancelPendingAndComplete()
        val recovery = recoveryStore.read()
        if (recovery is RecoveryStoreResult.Success &&
            recovery.value.redundantTransaction != null
        ) {
            val transaction = requireNotNull(recovery.value.redundantTransaction)
            val owner = redundantVpnOwner
            dispatchRedundantRevoke(
                redundantWork,
                fence = {
                    owner?.fenceRevoke() ?: (
                        recoveryStore.deferRedundantStop(UUID.randomUUID().toString()) is
                            RecoveryStoreResult.Success
                    )
                },
                revoke = {
                    (owner ?: ensureRedundantCoordinator(transaction)).revoke()
                },
            ) { result ->
                restoreHandler.post {
                    if (!result.fenced) {
                        TunnelLog.warning("service.vpn_revoke_fence_failed")
                    } else if (!result.stopped) {
                        TunnelLog.warning("service.vpn_revoke_cleanup_failed")
                    }
                    invokeFrameworkVpnRevoke()
                }
            }
            QuickTunnelController.updateState(
                applicationContext,
                SessionState.STOPPING,
                desiredActive = null,
                changed = true,
            )
            return
        }
        val routed = routeVpnProcessRevoke(recovery, redundantVpnOwner) {
            val disposition = routeAndroidVpnRevoke(
                dispatch = connectionIntentDispatch,
                coordinator = connectionIntentCoordinator,
                runtimeFence = connectionIntentRuntimeFence,
                updateStopping = {
                    QuickTunnelController.updateState(
                        applicationContext,
                        SessionState.STOPPING,
                        desiredActive = null,
                        changed = true,
                    )
                },
                resumePendingWork = connectionIntentLifecycle::onEnsureRunning,
            )
            (disposition.cancelled as? AndroidCoordinatorResult.Failure)?.let {
                TunnelLog.warning("service.vpn_revoke_cancel_failed", it.code)
            }
            applyAndroidVpnRevokeLifecycle(disposition, ::invokeFrameworkVpnRevoke)
        }
        if (!routed) {
            TunnelLog.warning("service.vpn_revoke_v2_owner_unavailable")
            invokeFrameworkVpnRevoke()
        }
    }

    /** Installed by the native/panel adapter in this dedicated :vpn process. */
    internal fun installRedundantVpnOwner(owner: RedundantVpnProcessOwner?) {
        restoreHandler.removeCallbacks(redundantHealthTick)
        val previous = redundantVpnOwner
        if (previous !== owner) runCatching { previous?.closeLocal() }
        redundantVpnOwner = owner
        if (owner == null) {
            redundantPhysicalNetworks?.stop()
            redundantPhysicalNetworks = null
        }
        if (owner != null) restoreHandler.post(redundantHealthTick)
    }

    private fun invokeFrameworkVpnRevoke() {
        super.onRevoke()
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        TunnelLog.info("service.ui_task_removed")
        runCatching { AutomaticDiagnostics.onUiTaskRemoved(applicationContext) }
            .onFailure { TunnelLog.warning("diagnostics.memory_snapshot_failed", error = it) }
        super.onTaskRemoved(rootIntent)
    }

    override fun onDestroy() {
        redundantStartOperation.cancelPendingAndComplete()
        idleStopDebouncer.cancel()
        cancelRestoreRetry()
        restoreHandler.removeCallbacks(logoutRetry)
        restoreHandler.removeCallbacks(redundantHealthTick)
        installRedundantVpnOwner(null)
        credentialExecutor.shutdownNow()
        redundantExecutor.shutdownNow()
        runCatching { AutomaticDiagnostics.onTunnelStopped(applicationContext) }
            .onFailure { TunnelLog.warning("diagnostics.lifecycle_failed", error = it) }
        activeService = null
        TunnelRuntime.serviceDestroyed()
        AndroidSplitTunnel.clear()
        TunnelLog.info("service.destroyed")
        val idleMemory = runCatching {
            automaticDiagnosticsCurrentProcessMemory(applicationContext)
        }.getOrNull()
        super.onDestroy()
        TunnelRuntime.releaseBackend()
        serviceReady = CompletableFuture()
        scheduleIdleProcessRecycle(idleMemory)
    }

    private fun scheduleIdleProcessRecycle(memory: AutomaticDiagnosticsProcessMemory?) {
        if (!shouldRecycleIdleVpnProcess(
                TunnelRuntime.state(),
                QuickTunnelController.desiredActive(applicationContext),
            )
        ) {
            return
        }
        TunnelLog.info(
            "service.process_recycle_scheduled",
            mapOf(
                "rss_bytes" to memory?.residentBytes,
                "pss_bytes" to memory?.proportionalBytes,
            ),
        )
        val processId = Process.myPid()
        var attempts = 0
        lateinit var recycle: Runnable
        recycle = Runnable {
            if (serviceGeneration != VPN_PROCESS_SERVICE_GENERATION.get() ||
                activeService != null ||
                TunnelRuntime.state() != SessionState.STOPPED ||
                QuickTunnelController.desiredActive(applicationContext)
            ) {
                return@Runnable
            }
            if (AutomaticDiagnostics.hasActiveUpload() && attempts < 6) {
                attempts += 1
                restoreHandler.postDelayed(recycle, IDLE_PROCESS_RECYCLE_DELAY_MILLIS)
                return@Runnable
            }
            TunnelLog.info("service.process_recycled")
            Process.killProcess(processId)
        }
        restoreHandler.postDelayed(recycle, IDLE_PROCESS_RECYCLE_DELAY_MILLIS)
    }

    private fun performBackgroundToggle(receiver: ResultReceiver? = null) {
        // Seal any legacy projection first; the actual desired/generation pair below
        // comes from one encrypted recovery-envelope read.
        QuickTunnelController.desiredActive(applicationContext)
        val quickDispatch = when (val result = connectionIntentCoordinator.quickToggle(
            connectionIntentDispatch,
        )) {
            is RecoveryStoreResult.Success -> result.value
            is RecoveryStoreResult.Failure -> {
                receiver.sendError(result.code)
                stopIfIdle()
                return
            }
        }
        when (val dispatch = quickDispatch) {
            is AndroidQuickToggleDispatch.Start ->
                dispatchSerializedConnectionIntentMutation(credentialExecutor) {
                    val credential = BackgroundCredentialStore.load(applicationContext)
                    val quick = QuickTunnelPlanStore.loadTemplate(applicationContext)
                    val quickTemplate = try {
                        if (credential == null) {
                            null
                        } else {
                            quick?.let {
                                quickConnectionIntentTemplate(
                                    deviceId = credential.deviceId,
                                    quick = it,
                                    androidApiLevel = Build.VERSION.SDK_INT,
                                )
                            }
                        }
                    } catch (_: Throwable) {
                        null
                    }
                    when (val accepted = executeDispatchedQuickStart(
                        dispatch = connectionIntentDispatch,
                        start = dispatch,
                        selectPolicy = {
                            if (quickTemplate == null) {
                                AndroidQuickStartPolicy.LEGACY
                            } else {
                                selectQuickStartPolicy(
                                    store = AndroidBackgroundCredentialStores.open(
                                        applicationContext,
                                    ),
                                    template = quickTemplate,
                                    nowUnix = Instant.now().epochSecond,
                                    provisionInFlight = backgroundCredentialProvisionInFlight.get(),
                                    fetch = BackgroundConnectionClient::capabilities,
                                )
                            }
                        },
                        recoveryStart = {
                            if (quickTemplate == null) {
                                AndroidCoordinatorResult.Failure("connection_intent_invalid")
                            } else {
                                beginExplicitConnectionIntent(quickTemplate, dispatch.ticket)
                            }
                        },
                        legacyStart = { performLegacyBackgroundStart(receiver) },
                    )) {
                        is AndroidQuickStartExecution.RecoveryAccepted -> {
                            QuickTunnelController.updateState(
                                applicationContext,
                                SessionState.STARTING,
                                desiredActive = null,
                            )
                            receiver?.send(
                                SERVICE_RESULT_OK,
                                connectionIntentServiceStatus(accepted.envelope).toBundle(),
                            )
                            scheduleConnectionIntentAttempt()
                        }
                        AndroidQuickStartExecution.LegacyStarted -> Unit
                        is AndroidQuickStartExecution.Failure -> {
                            receiver.sendError(accepted.code)
                            if (accepted.code == "connection_intent_generation_conflict") {
                                stopIfIdle()
                            } else {
                                completeBackgroundAction(
                                    TunnelRuntime.state(),
                                    accepted.code,
                                    false,
                                    false,
                                )
                            }
                        }
                    }
                }
            AndroidQuickToggleDispatch.Stop -> {
                when (val cancelled = cancelDispatchedConnectionIntent(connectionIntentDispatch) {
                    connectionIntentCoordinator.cancelCurrentForQuickToggle()
                }) {
                    is AndroidCoordinatorResult.Accepted -> {
                        connectionIntentRuntimeFence.cancelActive()
                        QuickTunnelController.updateState(
                            applicationContext,
                            SessionState.STOPPING,
                            desiredActive = null,
                        )
                        receiver?.send(
                            SERVICE_RESULT_OK,
                            connectionIntentServiceStatus(cancelled.envelope).toBundle(),
                        )
                        scheduleConnectionIntentAttempt()
                    }
                    is AndroidCoordinatorResult.Failure -> {
                        receiver.sendError(cancelled.code)
                        completeBackgroundAction(
                            TunnelRuntime.state(),
                            cancelled.code,
                            false,
                            false,
                        )
                    }
                }
            }
        }
    }

    internal fun performLegacyBackgroundStart(
        receiver: ResultReceiver?,
        boundary: LegacyBackgroundStartServiceBoundary? = null,
    ) {
        val operation = boundary ?: LegacyBackgroundStartServiceBoundary(
            start = { onSuccess, onError ->
                TunnelRuntime.backgroundStart(applicationContext, onSuccess, onError)
            },
            runtimeState = TunnelRuntime::state,
            durableDesiredActive = {
                QuickTunnelController.desiredActive(applicationContext)
            },
            complete = { state, errorCode, desiredActive ->
                completeBackgroundAction(
                    state,
                    errorCode,
                    restoring = false,
                    starting = true,
                    desiredActive = desiredActive,
                )
            },
            status = {
                (connectionIntentCoordinator.status() as? RecoveryStoreResult.Success)
                    ?.value
                    ?.let(::connectionIntentServiceStatus)
            },
        )
        operation.start(
            { state, _ ->
                operation.complete(
                    state,
                    null,
                    legacyStartCallbackDesiredActive(
                        operation.durableDesiredActive(),
                        state,
                    ),
                )
                val status = operation.status()
                if (status == null) {
                    receiver.sendError("recovery_record_read_failed")
                } else {
                    receiver?.send(
                        SERVICE_RESULT_OK,
                        status.toBundle(),
                    )
                }
            },
            { code ->
                receiver.sendError(code)
                val state = operation.runtimeState()
                operation.complete(
                    state,
                    code,
                    legacyStartCallbackDesiredActive(
                        operation.durableDesiredActive(),
                        state,
                    ),
                )
            },
        )
    }

    private fun restoreDesiredTunnel(source: String) {
        val state = TunnelRuntime.state()
        if (!shouldRestoreDesiredTunnel(
            QuickTunnelController.desiredActive(applicationContext),
            state,
        )) {
            return
        }
        promoteToForeground()
        TunnelLog.info("service.restore_requested", mapOf("source" to source))
        scheduleConnectionIntentAttempt()
    }

    private fun scheduleConnectionIntentAttempt(delayMillis: Long = 0L) {
        restoreHandler.removeCallbacks(restoreRetry)
        val envelope = (connectionIntentCoordinator.status() as? RecoveryStoreResult.Success)?.value
        if (envelope?.isTerminalConnectionIntent() == true) {
            return
        }
        if (delayMillis > 0) {
            scheduleConnectionIntentTimer(delayMillis)
            return
        }
        connectionIntentAttemptDispatcher.request()
    }

    private fun handleDataPlaneStall(leaseId: String): Boolean {
        return when (val result = connectionIntentCoordinator.dataPlaneStalled(leaseId)) {
            is AndroidCoordinatorResult.Accepted -> {
                QuickTunnelController.updateState(
                    applicationContext,
                    SessionState.STOPPING,
                    desiredActive = null,
                    changed = true,
                )
                scheduleConnectionIntentAttempt()
                TunnelPlugin.refreshQuickTile(applicationContext)
                true
            }
            is AndroidCoordinatorResult.Failure -> {
                TunnelLog.warning("tunnel.data_plane_stall_handoff_failed", result.code)
                false
            }
        }
    }

    private fun scheduleConnectionIntentTimer(delayMillis: Long) {
        restoreHandler.removeCallbacks(restoreRetry)
        restoreHandler.postDelayed(restoreRetry, delayMillis.coerceAtLeast(1))
    }

    private fun scheduleLogoutAttempt(delayMillis: Long = 0L) {
        restoreHandler.removeCallbacks(logoutRetry)
        if (delayMillis > 0) {
            restoreHandler.postDelayed(logoutRetry, delayMillis)
            return
        }
        credentialExecutor.execute {
            val step = logoutCoordinator.runOnce(
                ServiceConnectionIntentPanel(),
                ServiceConnectionIntentRuntime(),
                activate = BackgroundConnectionClient::activateToken,
                finalize = BackgroundConnectionClient::finalizeLogout,
            )
            restoreHandler.post {
                if (step == AndroidLogoutStep.RETRY) {
                    val delay = RESTORE_RETRY_DELAYS_MILLIS[
                        restoreRetryAttempt.coerceAtMost(
                            RESTORE_RETRY_DELAYS_MILLIS.lastIndex,
                        )
                    ]
                    restoreRetryAttempt += 1
                    scheduleLogoutAttempt(delay)
                } else {
                    restoreRetryAttempt = 0
                    stopIfIdle()
                }
            }
        }
    }

    private fun hasPendingBackgroundLogout(): Boolean = when (
        val result = AndroidBackgroundCredentialStores.open(applicationContext).read()
    ) {
        is CredentialStoreResult.Success ->
            result.value.logoutState?.phase == BackgroundLogoutPhase.PENDING
        is CredentialStoreResult.Failure -> false
    }

    private fun completeConnectionIntentStep(step: AndroidCoordinatorStep) {
        val envelope = (connectionIntentCoordinator.status() as? RecoveryStoreResult.Success)?.value
        when (step) {
            AndroidCoordinatorStep.ACTIVE -> {
                cancelRestoreRetry()
                refreshConnectionNotification("VPN-подключение активно")
                QuickTunnelController.updateState(
                    applicationContext,
                    SessionState.RUNNING,
                    desiredActive = null,
                    changed = true,
                )
            }
            AndroidCoordinatorStep.IDLE -> {
                cancelRestoreRetry()
                QuickTunnelController.updateState(
                    applicationContext,
                    SessionState.STOPPED,
                    desiredActive = null,
                    changed = true,
                )
                stopIfIdle()
            }
            AndroidCoordinatorStep.RETRY -> {
                val initialTerminalPending =
                    envelope?.intent?.retry?.terminalDiagnosticPending == true
                if (initialTerminalPending) {
                    val initialTerminalEnvelope = requireNotNull(envelope)
                    val handoffStarted = initialTerminalEnvelope.intent.retry.lastErrorCode?.let {
                        errorCode ->
                        runCatching {
                            AutomaticDiagnostics.onConnectionIntentTerminalFailure(
                                applicationContext,
                                initialTerminalEnvelope.intent.diagnosticsEpisodeId,
                                errorCode,
                            ) { outcome ->
                                restoreHandler.post {
                                    routeInitialTerminalDiagnosticHandoff(
                                        outcome,
                                        acknowledge = {
                                            connectionIntentCoordinator
                                                .acknowledgeInitialTerminalDiagnostic(
                                                    initialTerminalEnvelope.intent.generation,
                                                    initialTerminalEnvelope.intent
                                                        .diagnosticsEpisodeId,
                                                )
                                        },
                                        continueRecovery = ::scheduleRestoreRetry,
                                    )
                                }
                            }
                            true
                        }.onFailure {
                            TunnelLog.warning(
                                "diagnostics.connection_intent_state_failed",
                                error = it,
                            )
                        }.getOrDefault(false)
                    } == true
                    QuickTunnelController.updateState(
                        applicationContext,
                        SessionState.STOPPED,
                        desiredActive = null,
                        changed = true,
                    )
                    if (!handoffStarted) scheduleRestoreRetry()
                    return
                } else envelope?.intent?.retry?.let { retry ->
                    val errorCode = retry.lastErrorCode
                    val nextRetryAtUnix = retry.nextRetryAtUnix
                    if (errorCode != null && nextRetryAtUnix != null) {
                        val notify = runCatching {
                            AutomaticDiagnostics.onConnectionIntentRetryScheduled(
                                applicationContext,
                                envelope.intent.diagnosticsEpisodeId,
                                errorCode,
                                retry.attempt,
                                nextRetryAtUnix,
                                retry.scheduledDelaySeconds,
                            )
                        }.onFailure {
                            TunnelLog.warning(
                                "diagnostics.connection_intent_state_failed",
                                error = it,
                            )
                        }.getOrDefault(false)
                        if (notify) {
                            refreshConnectionNotification(
                                connectionIntentRetryNotificationContent(),
                            )
                        }
                    }
                }
                scheduleRestoreRetry()
            }
            AndroidCoordinatorStep.CLEANUP_REQUIRED,
            AndroidCoordinatorStep.BUSY,
            -> scheduleRestoreRetry()
            AndroidCoordinatorStep.TERMINAL -> {
                envelope?.intent?.retry?.lastErrorCode?.let { errorCode ->
                    runCatching {
                        AutomaticDiagnostics.onConnectionIntentTerminalFailure(
                            applicationContext,
                            envelope.intent.diagnosticsEpisodeId,
                            errorCode,
                        )
                    }.onFailure {
                        TunnelLog.warning(
                            "diagnostics.connection_intent_state_failed",
                            error = it,
                        )
                    }
                }
                cancelRestoreRetry()
                refreshConnectionNotification(
                    "Автовосстановление остановлено — откройте Nelomai и нажмите «Повторить»",
                )
                QuickTunnelController.updateState(
                    applicationContext,
                    TunnelRuntime.state(),
                    desiredActive = null,
                    changed = true,
                )
            }
        }
        TunnelPlugin.refreshQuickTile(applicationContext)
    }

    private inner class ServiceConnectionIntentPanel : AndroidConnectionIntentPanel {
        override fun reconcile(
            transaction: AndroidLeaseTransaction,
            cancelIfAbsent: Boolean,
        ): BackgroundReconcileResult {
            val stalledLeaseId = transaction.leaseId.takeIf {
                transaction.cleanupFailureCode == "tunnel_data_plane_stalled"
            }
            return BackgroundConnectionClient.reconcile(
                serviceCredential(),
                stalledLeaseId?.let { requireNotNull(transaction.stopOperationId) }
                    ?: transaction.startOperationId,
                if (stalledLeaseId == null) "start" else "stalled_stop",
                transaction.replay.contractVersion,
                stalledLeaseId?.let(::androidStalledStopFingerprint)
                    ?: transaction.replay.requestFingerprint,
                cancelIfAbsent,
            )
        }

        override fun start(
            template: AndroidIntentTemplate,
            transaction: AndroidLeaseTransaction,
        ): BackgroundStartResult {
            val credential = serviceActiveCredential(template.deviceId)
            val networkIdentity = runCatching {
                PhysicalNetworks(applicationContext).snapshotState().fingerprint
            }.getOrDefault("unavailable")
            return BackgroundConnectionClient.startExact(
                credential,
                template,
                transaction,
                candidateProbeCache,
                networkIdentity,
            )
        }

        override fun syncBindingPreferences(template: AndroidIntentTemplate) {
            BackgroundConnectionClient.syncBindingPreferences(
                serviceActiveCredential(template.deviceId),
                template,
            )
        }

        override fun stop(leaseId: String, operationId: String, failureCode: String?) {
            BackgroundConnectionClient.stop(
                serviceCredential(),
                leaseId,
                operationId,
                failureCode,
            )
        }
    }

    private inner class ServiceConnectionIntentRuntime : AndroidConnectionIntentRuntime {
        private val boundary = ServiceConnectionIntentRuntimeBoundary(
            startTransport = { result, operationId, onSuccess, onError ->
                TunnelRuntime.start(
                    applicationContext,
                    StartTunnelArgs().apply {
                        apiVersion = TUNNEL_API_VERSION
                        clientOperationId = operationId
                        startSource = "connection_intent"
                        configuration = result.configuration
                        options = result.options
                        cacheQuickAction = true
                        quickConnection = result.connection
                    },
                    { state, _ -> onSuccess(state == SessionState.RUNNING) },
                    onError,
                    keepForegroundServiceOnFailure = true,
                )
            },
            cancelStartTransport = { operationId ->
                TunnelRuntime.cancelClientStart(applicationContext, operationId)
            },
            startFence = connectionIntentRuntimeFence,
            stopTransport = { onSuccess, onError ->
                TunnelRuntime.stop(
                    TUNNEL_API_VERSION,
                    { state, _ -> onSuccess(state == SessionState.STOPPED) },
                    onError,
                    keepForegroundService = true,
                )
            },
            running = { TunnelRuntime.state() == SessionState.RUNNING },
        )

        override fun start(
            result: BackgroundStartResult,
            operationId: String,
            isCurrent: () -> Boolean,
        ): Boolean = boundary.start(result, operationId, isCurrent)

        override fun stop(): Boolean = boundary.stop()

        override fun isRunning(): Boolean = boundary.isRunning()
    }

    private fun serviceCredential(): BackgroundCredential {
        val envelope = when (val result = AndroidBackgroundCredentialStores.open(
            applicationContext,
        ).read()) {
            is CredentialStoreResult.Success -> result.value
            is CredentialStoreResult.Failure -> throw BackgroundConnectionException(result.code)
        }
        return envelope.active ?: envelope.cleanupCredential
            ?: throw BackgroundConnectionException("invalid_background_token")
    }

    private fun serviceActiveCredential(deviceId: String): BackgroundCredential {
        val envelope = when (val result = AndroidBackgroundCredentialStores.open(
            applicationContext,
        ).read()) {
            is CredentialStoreResult.Success -> result.value
            is CredentialStoreResult.Failure -> throw BackgroundConnectionException(result.code)
        }
        val credential = envelope.active
            ?: throw BackgroundConnectionException("invalid_background_token")
        if (credential.deviceId != deviceId) {
            throw BackgroundConnectionException("background_credential_device_mismatch")
        }
        return credential
    }

    private fun beginExplicitConnectionIntent(
        template: AndroidIntentTemplate,
        ticket: AndroidConnectionIntentDispatchTicket,
    ): AndroidCoordinatorResult = beginObservedConnectionIntent(
        coordinator = connectionIntentCoordinator,
        template = template,
        validateNewIntent = ::validateNewIntentCapability,
        expectedGeneration = ticket.expectedGeneration,
        canCommitNewIntent = { connectionIntentDispatch.isCurrent(ticket) },
        onStarted = { diagnosticsEpisodeId ->
            runCatching {
                AutomaticDiagnostics.onConnectionIntentStarted(
                    applicationContext,
                    diagnosticsEpisodeId,
                )
            }.onFailure {
                TunnelLog.warning(
                    "diagnostics.connection_intent_state_failed",
                    error = it,
                )
            }
        },
    )

    private fun validateNewIntentCapability(template: AndroidIntentTemplate) {
        val credentialStore = AndroidBackgroundCredentialStores.open(applicationContext)
        refreshAndValidateNewIntentCapability(
            store = credentialStore,
            template = template,
            nowUnix = Instant.now().epochSecond,
            provisionInFlight = backgroundCredentialProvisionInFlight.get(),
            fetch = BackgroundConnectionClient::capabilities,
        )
    }

    private fun canonicalUuid(value: String?): String {
        val parsed = UUID.fromString(requireNotNull(value)).toString()
        if (parsed != value) throw BackgroundConnectionException("invalid_connection_intent")
        return parsed
    }

    private fun requireWireChoice(value: String?, allowed: Set<String>): String =
        requireNotNull(value).also {
            if (it !in allowed) throw BackgroundConnectionException("invalid_connection_intent")
        }

    private fun stopIfIdle() {
        applyAndroidVpnServiceIdleLifecycle(
            debouncer = idleStopDebouncer,
            shouldStop = {
                shouldStopVpnService(
                    TunnelRuntime.state(),
                    QuickTunnelController.desiredActive(applicationContext),
                    hasPendingBackgroundLogout(),
                    connectionIntentLifecycle.hasPendingWork(),
                )
            },
            stop = {
                ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
                stopSelf()
            },
        )
    }

    private fun completeBackgroundAction(
        state: SessionState,
        errorCode: String?,
        restoring: Boolean,
        starting: Boolean,
        desiredActive: Boolean? = state == SessionState.RUNNING,
    ) {
        if (errorCode == "tunnel_operation_in_progress") {
            TunnelLog.info("quick_toggle.duplicate_ignored")
            TunnelPlugin.refreshQuickTile(applicationContext)
            return
        }
        if (shouldQueueBackgroundStartFailureDiagnostics(starting, errorCode)) {
            checkNotNull(errorCode)
            TunnelLog.warning(
                "background_start.failed",
                errorCode,
            )
            var stopServiceAfterDiagnostics = false
            completeBackgroundFailureWithDiagnostics(
                queueDiagnostics = { onComplete ->
                    queueBackgroundStartFailureDiagnostics(errorCode, onComplete)
                },
                finishUserAction = {
                    stopServiceAfterDiagnostics = finishBackgroundAction(
                        state,
                        errorCode,
                        restoring,
                        deferErrorServiceStop = true,
                        desiredActive = desiredActive,
                    )
                },
                finishDeferredServiceStop = {
                    if (stopServiceAfterDiagnostics) stopForegroundService()
                },
                onDiagnosticsQueueFailure = { failure ->
                    TunnelLog.warning(
                        "diagnostics.start_failure_report_queue_failed",
                        error = failure,
                    )
                },
            )
            return
        }
        finishBackgroundAction(
            state,
            errorCode,
            restoring,
            desiredActive = desiredActive,
        )
    }

    private fun finishBackgroundAction(
        state: SessionState,
        errorCode: String?,
        restoring: Boolean,
        deferErrorServiceStop: Boolean = false,
        desiredActive: Boolean? = state == SessionState.RUNNING,
    ): Boolean {
        val retryRestore = errorCode != null && restoring && shouldRetryServiceRestore(errorCode)
        if (retryRestore) {
            QuickTunnelController.updateState(
                applicationContext,
                SessionState.STOPPED,
                desiredActive = true,
                changed = true,
            )
            TunnelLog.warning("service.restore_deferred", errorCode)
            scheduleRestoreRetry()
            TunnelPlugin.refreshQuickTile(applicationContext)
            return false
        }
        cancelRestoreRetry()
        QuickTunnelController.updateState(
            applicationContext,
            state,
            desiredActive = desiredActive,
            changed = true,
        )
        TunnelPlugin.refreshQuickTile(applicationContext)
        var deferredServiceStop = false
        errorCode?.let { code ->
            TunnelLog.warning("quick_toggle.failed", code)
            if (state != SessionState.RUNNING) {
                if (deferErrorServiceStop) {
                    deferredServiceStop = true
                } else {
                    stopForegroundService()
                }
            }
            android.os.Handler(mainLooper).post {
                Toast.makeText(applicationContext, quickActionError(code), Toast.LENGTH_LONG).show()
            }
        }
        return deferredServiceStop
    }

    private fun queueBackgroundStartFailureDiagnostics(
        errorCode: String,
        onComplete: () -> Unit,
    ) {
        val deviceId = BackgroundCredentialStore.load(applicationContext)?.deviceId
        if (deviceId == null) {
            TunnelLog.warning(
                "diagnostics.start_failure_report_queue_skipped",
                "background_credential_unavailable",
            )
            onComplete()
            return
        }
        AutomaticDiagnostics.onConnectionStartFailed(
            applicationContext,
            deviceId,
            errorCode,
        ) { onComplete() }
    }

    private fun scheduleRestoreRetry() {
        restoreHandler.removeCallbacks(restoreRetry)
        val envelope = (connectionIntentCoordinator.status() as? RecoveryStoreResult.Success)
            ?.value
        val delay = if (envelope?.intent?.retry?.nextRetryAtUnix != null) {
            connectionIntentPersistedDelayMillis(
                envelope,
                nowUnix = System.currentTimeMillis() / 1_000,
            )
        } else {
            RESTORE_RETRY_DELAYS_MILLIS[
                restoreRetryAttempt.coerceAtMost(RESTORE_RETRY_DELAYS_MILLIS.lastIndex)
            ]
        }
        restoreRetryAttempt += 1
        restoreHandler.postDelayed(restoreRetry, delay.coerceAtLeast(1))
    }

    private fun cancelRestoreRetry() {
        restoreHandler.removeCallbacks(restoreRetry)
        restoreRetryAttempt = 0
    }

    companion object {
        @Volatile
        private var serviceReady = CompletableFuture<Unit>()

        @Volatile
        private var activeService: NelomaiVpnService? = null

        private const val NOTIFICATION_CHANNEL = "nelomai-vpn"
        private const val NOTIFICATION_ID = 21
        internal const val ACTION_QUICK_TOGGLE = "ru.nelomai.tunnel.QUICK_TOGGLE"
        internal const val ACTION_ENSURE_RUNNING = "ru.nelomai.tunnel.ENSURE_RUNNING"
        internal const val ACTION_CLIENT_START = "ru.nelomai.tunnel.CLIENT_START"
        internal const val ACTION_CANCEL_CLIENT_START =
            "ru.nelomai.tunnel.CANCEL_CLIENT_START"
        internal const val ACTION_CLIENT_STOP = "ru.nelomai.tunnel.CLIENT_STOP"
        internal const val ACTION_CLIENT_STATUS = "ru.nelomai.tunnel.CLIENT_STATUS"
        internal const val ACTION_CLIENT_METRICS = "ru.nelomai.tunnel.CLIENT_METRICS"
        internal const val ACTION_CLIENT_REBIND_UDP = "ru.nelomai.tunnel.CLIENT_REBIND_UDP"
        internal const val ACTION_BEGIN_CONNECTION_INTENT =
            "ru.nelomai.tunnel.BEGIN_CONNECTION_INTENT"
        internal const val ACTION_CANCEL_CONNECTION_INTENT =
            "ru.nelomai.tunnel.CANCEL_CONNECTION_INTENT"
        internal const val ACTION_CANCEL_CURRENT_CONNECTION_INTENT =
            "ru.nelomai.tunnel.CANCEL_CURRENT_CONNECTION_INTENT"
        internal const val ACTION_CONNECTION_INTENT_STATUS =
            "ru.nelomai.tunnel.CONNECTION_INTENT_STATUS"
        internal const val ACTION_RELEASE_REDUNDANT_STANDBY =
            "ru.nelomai.tunnel.RELEASE_REDUNDANT_STANDBY"
        internal const val ACTION_BEGIN_BACKGROUND_LOGOUT =
            "ru.nelomai.tunnel.BEGIN_BACKGROUND_LOGOUT"
        internal const val ACTION_CONFIGURE_BACKGROUND = "ru.nelomai.tunnel.CONFIGURE_BACKGROUND"
        internal const val ACTION_ROTATE_BACKGROUND = "ru.nelomai.tunnel.ROTATE_BACKGROUND"
        internal const val ACTION_PROVISION_BACKGROUND = "ru.nelomai.tunnel.PROVISION_BACKGROUND"
        internal const val ACTION_RECOVER_BACKGROUND_SESSION =
            "ru.nelomai.tunnel.RECOVER_BACKGROUND_SESSION"
        internal const val ACTION_BACKGROUND_STATUS = "ru.nelomai.tunnel.BACKGROUND_STATUS"
        internal const val ACTION_CLEAR_BACKGROUND = "ru.nelomai.tunnel.CLEAR_BACKGROUND"
        internal const val ACTION_CLEAR_QUICK_PLAN = "ru.nelomai.tunnel.CLEAR_QUICK_PLAN"
        internal const val ACTION_UPDATE_QUICK_DNS = "ru.nelomai.tunnel.UPDATE_QUICK_DNS"
        internal const val ACTION_TAKE_STATE_CHANGE = "ru.nelomai.tunnel.TAKE_STATE_CHANGE"
        internal const val ACTION_ACKNOWLEDGE_STATE_CHANGE =
            "ru.nelomai.tunnel.ACKNOWLEDGE_STATE_CHANGE"
        private val FOREGROUND_ACTIONS = setOf(
            ACTION_QUICK_TOGGLE,
            ACTION_ENSURE_RUNNING,
            ACTION_CLIENT_START,
            ACTION_BEGIN_CONNECTION_INTENT,
            ACTION_BEGIN_BACKGROUND_LOGOUT,
        )
        private val RESTORE_RETRY_DELAYS_MILLIS = longArrayOf(
            2_000L,
            5_000L,
            15_000L,
            30_000L,
            60_000L,
            300_000L,
        )
        private const val IDLE_PROCESS_RECYCLE_DELAY_MILLIS = 10_000L
        private val VPN_PROCESS_SERVICE_GENERATION =
            java.util.concurrent.atomic.AtomicLong(0)

        fun ensureStarted(context: Context): CompletableFuture<Unit> {
            if (activeService != null) {
                return CompletableFuture.completedFuture(Unit)
            }
            ContextCompat.startForegroundService(
                context,
                Intent(context, NelomaiVpnService::class.java).setAction(ACTION_ENSURE_RUNNING),
            )
            return serviceReady
        }

        fun requestToggle(context: Context) {
            ContextCompat.startForegroundService(
                context,
                Intent(context, NelomaiVpnService::class.java).setAction(ACTION_QUICK_TOGGLE),
            )
        }

        fun stopForegroundService() {
            activeService?.run {
                ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }

        fun reportDataPlaneStall(leaseId: String): Boolean =
            activeService?.handleDataPlaneStall(leaseId) == true

        fun resumeConnectionIntentRecovery() {
            activeService?.scheduleConnectionIntentAttempt()
        }

        fun setPhysicalNetworks(networks: List<Network>, validated: Boolean) {
            activeService?.run {
                candidateProbeCache.invalidateNetwork()
                setUnderlyingNetworks(networks.toTypedArray().takeIf { it.isNotEmpty() })
                redundantWork.network(validated) { latestValidated ->
                    val recovery = recoveryStore.read()
                    if (!shouldEnterLegacyVpnRecovery(recovery)) {
                        if (!routeVpnProcessNetworkChange(
                                recovery,
                                redundantVpnOwner,
                                validated = latestValidated,
                                legacyNetworkChange = {},
                            )
                        ) {
                            TunnelLog.warning("redundant.network_change_failed")
                        }
                    } else {
                        restoreHandler.post {
                            if (QuickTunnelController.desiredActive(applicationContext)) {
                                runCatching {
                                    AutomaticDiagnostics.onConnectionIntentNetworkWakeup()
                                }
                                scheduleConnectionIntentAttempt()
                            }
                        }
                    }
                }
                Unit
            }
        }

        private fun quickActionError(code: String): String = when (code) {
            "vpn_permission_required" -> "Откройте Nelomai и разрешите VPN-подключение"
            "quick_action_plan_unavailable" -> "Откройте Nelomai, чтобы подготовить подключение"
            "invalid_background_token", "missing_background_token" ->
                "Откройте Nelomai и войдите в аккаунт снова"
            "tunnel_operation_in_progress" -> "Дождитесь завершения текущего действия"
            "background_transport_unavailable" -> "Не удалось связаться с панелью"
            "quick_state_persist_failed" -> "Не удалось сохранить команду подключения"
            else -> "Не удалось изменить состояние подключения"
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(
                NOTIFICATION_CHANNEL,
                "VPN-подключение",
                NotificationManager.IMPORTANCE_LOW,
            ),
        )
    }

    private fun promoteToForeground() {
        createNotificationChannel()
        ServiceCompat.startForeground(
            this,
            NOTIFICATION_ID,
            connectionNotification(),
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED
            } else {
                0
            },
        )
    }

    private fun connectionNotification(
        content: String = "VPN-подключение активно",
    ): android.app.Notification {
        val launchIntent = packageManager.getLaunchIntentForPackage(packageName)
        val pendingIntent = launchIntent?.let {
            PendingIntent.getActivity(
                this,
                0,
                it,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
        }
        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL)
            .setSmallIcon(R.drawable.ic_vpn_notification)
            .setContentTitle("Nelomai")
            .setContentText(content)
            .setOngoing(true)
            .setSilent(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .apply { pendingIntent?.let(::setContentIntent) }
            .build()
    }

    private fun refreshConnectionNotification(content: String) {
        getSystemService(NotificationManager::class.java).notify(
            NOTIFICATION_ID,
            connectionNotification(content),
        )
    }
}

private class CredentialRotationFailure(val code: String) : RuntimeException(code)

internal sealed class AndroidCoordinatorResult {
    data class Accepted(val envelope: AndroidRecoveryEnvelope) : AndroidCoordinatorResult()
    data class Failure(val code: String) : AndroidCoordinatorResult()
}

internal data class AndroidConnectionIntentDispatchTicket(
    val epoch: Long,
    val expectedGeneration: Long,
)

internal sealed class AndroidQuickToggleDispatch {
    data class Start(
        val ticket: AndroidConnectionIntentDispatchTicket,
        val recoveryOwned: Boolean = false,
    ) :
        AndroidQuickToggleDispatch()

    object Stop : AndroidQuickToggleDispatch()
}

internal class AndroidConnectionIntentDispatchState {
    private val gate = Any()
    private var epoch = 0L
    private var pendingStart = false

    fun start(expectedGeneration: Long): AndroidConnectionIntentDispatchTicket =
        synchronized(gate) {
            epoch = epoch.checkedIncrementDispatchEpoch()
            pendingStart = true
            AndroidConnectionIntentDispatchTicket(epoch, expectedGeneration)
        }

    fun toggle(
        expectedGeneration: Long,
        durableDesiredActive: Boolean,
        recoveryOwned: Boolean = false,
    ): AndroidQuickToggleDispatch = synchronized(gate) {
        toggleLocked(expectedGeneration, durableDesiredActive, recoveryOwned)
    }

    fun toggleFromSnapshot(
        snapshot: () -> RecoveryStoreResult<AndroidRecoveryEnvelope>,
    ): RecoveryStoreResult<AndroidQuickToggleDispatch> = synchronized(gate) {
        when (val result = snapshot()) {
            is RecoveryStoreResult.Success -> RecoveryStoreResult.Success(
                toggleLocked(
                    expectedGeneration = result.value.intent.generation,
                    durableDesiredActive = result.value.intent.desiredActive,
                    recoveryOwned = result.value.leaseTransaction != null,
                ),
            )
            is RecoveryStoreResult.Failure -> result
        }
    }

    private fun toggleLocked(
        expectedGeneration: Long,
        durableDesiredActive: Boolean,
        recoveryOwned: Boolean,
    ): AndroidQuickToggleDispatch {
        if (pendingStart || durableDesiredActive) {
            epoch = epoch.checkedIncrementDispatchEpoch()
            pendingStart = false
            return AndroidQuickToggleDispatch.Stop
        } else {
            epoch = epoch.checkedIncrementDispatchEpoch()
            pendingStart = true
            return AndroidQuickToggleDispatch.Start(
                AndroidConnectionIntentDispatchTicket(epoch, expectedGeneration),
                recoveryOwned,
            )
        }
    }

    fun invalidate() = synchronized(gate) {
        epoch = epoch.checkedIncrementDispatchEpoch()
        pendingStart = false
    }

    fun isCurrent(ticket: AndroidConnectionIntentDispatchTicket): Boolean =
        synchronized(gate) { pendingStart && ticket.epoch == epoch }

    fun complete(ticket: AndroidConnectionIntentDispatchTicket): Boolean = synchronized(gate) {
        if (!pendingStart || ticket.epoch != epoch) {
            false
        } else {
            pendingStart = false
            true
        }
    }

    fun runLegacyIfCurrent(
        ticket: AndroidConnectionIntentDispatchTicket,
        start: () -> Unit,
    ): Boolean = synchronized(gate) {
        if (!pendingStart || ticket.epoch != epoch) {
            false
        } else {
            try {
                start()
            } finally {
                pendingStart = false
            }
            true
        }
    }

    private fun Long.checkedIncrementDispatchEpoch(): Long =
        if (this == Long.MAX_VALUE) 1L else this + 1L
}

internal fun beginObservedConnectionIntent(
    coordinator: AndroidConnectionIntentCoordinator,
    template: AndroidIntentTemplate,
    validateNewIntent: (AndroidIntentTemplate) -> Unit = {},
    expectedGeneration: Long? = null,
    canCommitNewIntent: () -> Boolean = { true },
    onStarted: (Long) -> Unit,
): AndroidCoordinatorResult = (if (expectedGeneration == null) {
    coordinator.begin(template, validateNewIntent)
} else {
    coordinator.beginDispatched(
        template = template,
        expectedGeneration = expectedGeneration,
        canCommitNewIntent = canCommitNewIntent,
        validateNewIntent = validateNewIntent,
    )
}).also { result ->
    if (result is AndroidCoordinatorResult.Accepted) {
        onStarted(result.envelope.intent.diagnosticsEpisodeId)
    }
}

internal fun executeDispatchedConnectionIntent(
    dispatch: AndroidConnectionIntentDispatchState,
    ticket: AndroidConnectionIntentDispatchTicket,
    begin: () -> AndroidCoordinatorResult,
): AndroidCoordinatorResult {
    if (!dispatch.isCurrent(ticket)) {
        return AndroidCoordinatorResult.Failure("connection_intent_generation_conflict")
    }
    val result = begin()
    return if (dispatch.complete(ticket)) {
        result
    } else {
        AndroidCoordinatorResult.Failure("connection_intent_generation_conflict")
    }
}

internal enum class AndroidQuickStartPolicy {
    RECOVERY,
    LEGACY,
}

internal sealed class AndroidQuickStartExecution {
    data class RecoveryAccepted(val envelope: AndroidRecoveryEnvelope) :
        AndroidQuickStartExecution()

    object LegacyStarted : AndroidQuickStartExecution()
    data class Failure(val code: String) : AndroidQuickStartExecution()
}

internal fun executeDispatchedQuickStart(
    dispatch: AndroidConnectionIntentDispatchState,
    start: AndroidQuickToggleDispatch.Start,
    selectPolicy: () -> AndroidQuickStartPolicy,
    recoveryStart: () -> AndroidCoordinatorResult,
    legacyStart: () -> Unit,
): AndroidQuickStartExecution {
    if (!dispatch.isCurrent(start.ticket)) {
        return AndroidQuickStartExecution.Failure("connection_intent_generation_conflict")
    }
    val policy = if (start.recoveryOwned) {
        AndroidQuickStartPolicy.RECOVERY
    } else {
        try {
            selectPolicy()
        } catch (error: BackgroundConnectionException) {
            return if (dispatch.complete(start.ticket)) {
                AndroidQuickStartExecution.Failure(error.code)
            } else {
                AndroidQuickStartExecution.Failure("connection_intent_generation_conflict")
            }
        } catch (_: Throwable) {
            return if (dispatch.complete(start.ticket)) {
                AndroidQuickStartExecution.Failure("connection_recovery_failed")
            } else {
                AndroidQuickStartExecution.Failure("connection_intent_generation_conflict")
            }
        }
    }
    return when (policy) {
        AndroidQuickStartPolicy.RECOVERY -> when (
            val result = executeDispatchedConnectionIntent(
                dispatch,
                start.ticket,
                recoveryStart,
            )
        ) {
            is AndroidCoordinatorResult.Accepted ->
                AndroidQuickStartExecution.RecoveryAccepted(result.envelope)
            is AndroidCoordinatorResult.Failure -> AndroidQuickStartExecution.Failure(result.code)
        }
        AndroidQuickStartPolicy.LEGACY -> {
            var failure: AndroidQuickStartExecution.Failure? = null
            val dispatched = dispatch.runLegacyIfCurrent(start.ticket) {
                try {
                    legacyStart()
                } catch (error: BackgroundConnectionException) {
                    failure = AndroidQuickStartExecution.Failure(error.code)
                } catch (_: Throwable) {
                    failure = AndroidQuickStartExecution.Failure("legacy_background_start_failed")
                }
            }
            if (!dispatched) {
                AndroidQuickStartExecution.Failure("connection_intent_generation_conflict")
            } else {
                failure ?: AndroidQuickStartExecution.LegacyStarted
            }
        }
    }
}

internal fun cancelDispatchedConnectionIntent(
    dispatch: AndroidConnectionIntentDispatchState,
    cancel: () -> AndroidCoordinatorResult,
): AndroidCoordinatorResult {
    dispatch.invalidate()
    return cancel()
}

internal data class AndroidVpnRevokeDisposition(
    val cancelled: AndroidCoordinatorResult,
    val keepForeground: Boolean,
)

internal fun routeAndroidVpnRevoke(
    dispatch: AndroidConnectionIntentDispatchState,
    coordinator: AndroidConnectionIntentCoordinator,
    runtimeFence: AndroidRuntimeStartDispatchFence,
    updateStopping: () -> Unit,
    resumePendingWork: () -> Boolean,
): AndroidVpnRevokeDisposition {
    val cancelled = cancelDispatchedConnectionIntent(dispatch, coordinator::cancelCurrent)
    runtimeFence.cancelActive()
    updateStopping()
    val keepForeground = cancelled is AndroidCoordinatorResult.Accepted &&
        runCatching(resumePendingWork).getOrDefault(false)
    return AndroidVpnRevokeDisposition(cancelled, keepForeground)
}

internal fun applyAndroidVpnRevokeLifecycle(
    disposition: AndroidVpnRevokeDisposition,
    invokeFrameworkVpnRevoke: () -> Unit,
) {
    // VpnService.onRevoke() calls stopSelf(). A durable cancellation must keep
    // this service and its executor alive until coordinator cleanup reaches
    // IDLE; stopIfIdle owns the eventual foreground/service teardown.
    if (!disposition.keepForeground) invokeFrameworkVpnRevoke()
}

internal fun applyAndroidVpnServiceIdleLifecycle(
    debouncer: IdleStopDebouncer,
    shouldStop: () -> Boolean,
    stop: () -> Unit,
) {
    if (shouldStop()) {
        debouncer.schedule {
            if (shouldStop()) stop()
        }
    } else {
        debouncer.cancel()
    }
}

internal fun beginDispatchedLogout(
    dispatch: AndroidConnectionIntentDispatchState,
    begin: () -> AndroidLogoutResult,
): AndroidLogoutResult {
    dispatch.invalidate()
    return begin()
}

internal fun refreshAndValidateNewIntentCapability(
    store: BackgroundCredentialStore,
    template: AndroidIntentTemplate,
    nowUnix: Long,
    provisionInFlight: Boolean = false,
    fetch: (BackgroundCredential) -> BackgroundCapabilitySnapshot,
) {
    if (selectQuickStartPolicy(store, template, nowUnix, provisionInFlight, fetch) ==
        AndroidQuickStartPolicy.LEGACY
    ) {
        throw BackgroundConnectionException("background_credential_capability_unavailable")
    }
}

internal fun redundantCapabilityRequiresStandbyRelease(
    capability: BackgroundCapabilitySnapshot,
    transaction: AndroidRedundantTransaction?,
): Boolean = !capability.reserveEnabled && transaction?.standbyDesired == true

internal fun selectQuickStartPolicy(
    store: BackgroundCredentialStore,
    template: AndroidIntentTemplate,
    nowUnix: Long,
    provisionInFlight: Boolean = false,
    fetch: (BackgroundCredential) -> BackgroundCapabilitySnapshot,
): AndroidQuickStartPolicy {
    val before = when (val result = store.read()) {
        is CredentialStoreResult.Success -> result.value
        is CredentialStoreResult.Failure -> throw BackgroundConnectionException(result.code)
    }
    if (before.logoutState != null) {
        throw BackgroundConnectionException("background_credential_capability_unavailable")
    }
    val credential = before.active ?: if (
        provisionInFlight || before.pending != null || before.reservation != null
    ) {
        throw BackgroundConnectionException("background_credential_provision_pending")
    } else {
        return AndroidQuickStartPolicy.LEGACY
    }
    val refreshed = refreshBackgroundCapability(before.capability, nowUnix) {
        fetch(credential)
    }
    val effective = conservativeBackgroundCapability(before.capability, refreshed)
    val after = when (val result = store.updateCapability(before.revision, effective)) {
        is CredentialStoreResult.Success -> result.value
        is CredentialStoreResult.Failure -> throw BackgroundConnectionException(result.code)
    }
    val active = after.active
        ?: throw BackgroundConnectionException("background_credential_capability_unavailable")
    val capability = after.capability
    if (after.logoutState != null || active.deviceId != template.deviceId || capability == null) {
        throw BackgroundConnectionException("background_credential_capability_unavailable")
    }
    return if (capability.enabled && capability.expiresAtUnix > nowUnix) {
        AndroidQuickStartPolicy.RECOVERY
    } else {
        AndroidQuickStartPolicy.LEGACY
    }
}

internal enum class AndroidCoordinatorStep {
    IDLE,
    ACTIVE,
    RETRY,
    CLEANUP_REQUIRED,
    TERMINAL,
    BUSY,
}

internal sealed class AndroidLogoutResult {
    data class Accepted(val envelope: BackgroundCredentialEnvelope) : AndroidLogoutResult()
    data class NotOwned(val envelope: AndroidRecoveryEnvelope) : AndroidLogoutResult()
    data class Failure(val code: String) : AndroidLogoutResult()
}

internal enum class AndroidLogoutStep {
    COMPLETE,
    RETRY,
}

internal class AndroidLogoutCoordinator(
    private val credentialStore: BackgroundCredentialStore,
    private val connectionCoordinator: AndroidConnectionIntentCoordinator,
    private val operationId: () -> String = { UUID.randomUUID().toString() },
) {
    fun begin(): AndroidLogoutResult {
        val credentialBegin = when (val result = credentialStore.beginLogoutCurrent(
            operationId(),
        )) {
            is CredentialStoreResult.Success -> result.value
            is CredentialStoreResult.Failure -> return AndroidLogoutResult.Failure(result.code)
        }
        val nativeOwned = credentialBegin is BackgroundLogoutBegin.Owned
        return when (val cancelled = connectionCoordinator.cancelCurrent()) {
            is AndroidCoordinatorResult.Failure -> if (nativeOwned) {
                AndroidLogoutResult.Accepted(credentialBegin.envelope)
            } else {
                AndroidLogoutResult.Failure(cancelled.code)
            }
            is AndroidCoordinatorResult.Accepted -> if (nativeOwned) {
                AndroidLogoutResult.Accepted(credentialBegin.envelope)
            } else {
                AndroidLogoutResult.NotOwned(cancelled.envelope)
            }
        }
    }

    fun runOnce(
        panel: AndroidConnectionIntentPanel,
        runtime: AndroidConnectionIntentRuntime,
        activate: (
            BackgroundCredential,
            BackgroundPendingToken,
            String,
        ) -> BackgroundActivationResult,
        finalize: (
            BackgroundCredential,
            String,
            Long,
            String,
            String,
        ) -> BackgroundLogoutFinalizeResult,
    ): AndroidLogoutStep {
        val beforeCleanup = when (val result = credentialStore.read()) {
            is CredentialStoreResult.Success -> result.value
            is CredentialStoreResult.Failure -> return AndroidLogoutStep.RETRY
        }
        val logout = beforeCleanup.logoutState ?: return AndroidLogoutStep.COMPLETE
        if (logout.phase == BackgroundLogoutPhase.FINALIZED) return AndroidLogoutStep.COMPLETE
        beforeCleanup.pending?.let { pending ->
            val installSecret = beforeCleanup.installSecret ?: return AndroidLogoutStep.RETRY
            val credential = try {
                stagedBackgroundCredential(beforeCleanup, pending)
            } catch (_: Throwable) {
                return AndroidLogoutStep.RETRY
            }
            val activeExpiresAtUnix = try {
                val activation = activate(credential, pending, installSecret)
                if (activation.tokenGeneration != pending.tokenGeneration) {
                    return AndroidLogoutStep.RETRY
                }
                activation.activeExpiresAtUnix
            } catch (error: BackgroundConnectionException) {
                if (error.code != "activation_not_applied") {
                    return AndroidLogoutStep.RETRY
                }
                null
            } catch (_: Throwable) {
                return AndroidLogoutStep.RETRY
            }
            when (credentialStore.resolveLogoutPendingActivation(
                beforeCleanup.revision,
                logout.operationId,
                pending.activationOperationId,
                activeExpiresAtUnix,
            )) {
                is CredentialStoreResult.Success -> Unit
                is CredentialStoreResult.Failure -> return AndroidLogoutStep.RETRY
            }
        }
        val connectionEnvelope = when (val result = connectionCoordinator.status()) {
            is RecoveryStoreResult.Success -> result.value
            is RecoveryStoreResult.Failure -> return AndroidLogoutStep.RETRY
        }
        if (connectionEnvelope.intent.desiredActive) {
            when (connectionCoordinator.cancel(connectionEnvelope.intent.generation)) {
                is AndroidCoordinatorResult.Failure -> return AndroidLogoutStep.RETRY
                is AndroidCoordinatorResult.Accepted -> Unit
            }
        }
        when (connectionCoordinator.runOnce(panel, runtime)) {
            AndroidCoordinatorStep.IDLE -> Unit
            else -> return AndroidLogoutStep.RETRY
        }
        val envelope = when (val result = credentialStore.read()) {
            is CredentialStoreResult.Success -> result.value
            is CredentialStoreResult.Failure -> return AndroidLogoutStep.RETRY
        }
        val cleanupCredential = envelope.cleanupCredential
        if (cleanupCredential == null) {
            return when (credentialStore.finalizeLogout(envelope.revision, logout.operationId)) {
                is CredentialStoreResult.Success -> AndroidLogoutStep.COMPLETE
                is CredentialStoreResult.Failure -> AndroidLogoutStep.RETRY
            }
        }
        val deviceId = envelope.deviceId ?: return AndroidLogoutStep.RETRY
        val installSecret = envelope.installSecret ?: return AndroidLogoutStep.RETRY
        val accepted = try {
            finalize(
                cleanupCredential,
                deviceId,
                logout.installGeneration,
                logout.operationId,
                installSecret,
            )
        } catch (_: Throwable) {
            return AndroidLogoutStep.RETRY
        }
        if (accepted.code != "device_revoked_cleanup_accepted") {
            return AndroidLogoutStep.RETRY
        }
        return when (credentialStore.finalizeLogout(envelope.revision, logout.operationId)) {
            is CredentialStoreResult.Success -> AndroidLogoutStep.COMPLETE
            is CredentialStoreResult.Failure -> AndroidLogoutStep.RETRY
        }
    }
}

internal interface AndroidConnectionIntentPanel {
    fun reconcile(
        transaction: AndroidLeaseTransaction,
        cancelIfAbsent: Boolean,
    ): BackgroundReconcileResult

    fun start(
        template: AndroidIntentTemplate,
        transaction: AndroidLeaseTransaction,
    ): BackgroundStartResult

    fun syncBindingPreferences(template: AndroidIntentTemplate)

    fun stop(leaseId: String, operationId: String, failureCode: String? = null)
}

internal interface AndroidConnectionIntentRuntime {
    fun start(
        result: BackgroundStartResult,
        operationId: String,
        isCurrent: () -> Boolean,
    ): Boolean
    fun stop(): Boolean
    fun isRunning(): Boolean
}

internal class AndroidRuntimeStartDispatchFence {
    private val gate = Any()
    private var activeOperationId: String? = null
    private var activeCancellation: (() -> Unit)? = null

    fun dispatchIfCurrent(
        operationId: String,
        isCurrent: () -> Boolean,
        dispatch: () -> Unit,
        cancel: () -> Unit,
    ): Boolean = synchronized(gate) {
        if (!isCurrent()) return@synchronized false
        activeOperationId = operationId
        activeCancellation = cancel
        dispatch()
        true
    }

    fun cancelActive() {
        val cancellation = synchronized(gate) { activeCancellation }
        cancellation?.invoke()
    }

    fun complete(operationId: String) = synchronized(gate) {
        if (activeOperationId == operationId) {
            activeOperationId = null
            activeCancellation = null
        }
    }
}

internal sealed class AndroidRuntimeStartFenceResult {
    object STARTED : AndroidRuntimeStartFenceResult()
    data class FAILED(val errorCode: String) : AndroidRuntimeStartFenceResult()
    object CANCELLED_BEFORE_START : AndroidRuntimeStartFenceResult()
    object CANCELLED_AFTER_START : AndroidRuntimeStartFenceResult()
}

internal fun startRuntimeWithConnectionIntentFence(
    expectedGeneration: Long,
    operationId: String,
    current: () -> AndroidRecoveryEnvelope,
    result: BackgroundStartResult,
    runtime: AndroidConnectionIntentRuntime,
): AndroidRuntimeStartFenceResult {
    var dispatched = false
    val started = runtime.start(
        result = result,
        operationId = operationId,
        isCurrent = {
            val before = current()
            (before.intent.desiredActive && before.intent.generation == expectedGeneration).also {
                dispatched = it
            }
        },
    )
    if (!dispatched) {
        result.configuration.fill(0)
        return AndroidRuntimeStartFenceResult.CANCELLED_BEFORE_START
    }
    if (!started) return AndroidRuntimeStartFenceResult.FAILED("tunnel_backend_error")
    val after = current()
    return if (!after.intent.desiredActive || after.intent.generation != expectedGeneration) {
        AndroidRuntimeStartFenceResult.CANCELLED_AFTER_START
    } else {
        AndroidRuntimeStartFenceResult.STARTED
    }
}

internal class ServiceConnectionIntentRuntimeBoundary(
    private val startTransport: (
        BackgroundStartResult,
        String,
        (Boolean) -> Unit,
        (String) -> Unit,
    ) -> Unit,
    private val cancelStartTransport: (String) -> Unit = {},
    private val startFence: AndroidRuntimeStartDispatchFence = AndroidRuntimeStartDispatchFence(),
    private val stopTransport: ((Boolean) -> Unit, (String) -> Unit) -> Unit,
    private val running: () -> Boolean,
    private val timeoutMillis: Long = 45_000L,
) : AndroidConnectionIntentRuntime {
    private data class Completion(
        val succeeded: Boolean,
        val errorCode: String? = null,
    )

    override fun start(
        result: BackgroundStartResult,
        operationId: String,
        isCurrent: () -> Boolean,
    ): Boolean {
        val completed = CompletableFuture<Completion>()
        val dispatched = startFence.dispatchIfCurrent(
            operationId = operationId,
            isCurrent = isCurrent,
            dispatch = {
                startTransport(
                    result,
                    operationId,
                    { succeeded -> completed.complete(Completion(succeeded)) },
                    { code -> completed.complete(Completion(false, code)) },
                )
            },
            cancel = { cancelStartTransport(operationId) },
        )
        if (!dispatched) return false
        return try {
            val completion = await(completed)
            completion.errorCode?.let { throw BackgroundConnectionException(stableCode(it)) }
            completion.succeeded
        } finally {
            startFence.complete(operationId)
        }
    }

    override fun stop(): Boolean {
        val completed = CompletableFuture<Completion>()
        stopTransport(
            { succeeded -> completed.complete(Completion(succeeded)) },
            { code -> completed.complete(Completion(false, code)) },
        )
        return await(completed).succeeded
    }

    override fun isRunning(): Boolean = running()

    private fun await(completed: CompletableFuture<Completion>): Completion = try {
        completed.get(timeoutMillis, TimeUnit.MILLISECONDS)
    } catch (_: Throwable) {
        Completion(false, "tunnel_service_timeout")
    }

    private fun stableCode(code: String): String = try {
        code.also(AndroidRecoveryEnvelopeCodec::validateSafeValue)
    } catch (_: Throwable) {
        "tunnel_backend_error"
    }
}

internal data class ConnectionIntentServiceStatus(
    val generation: Long,
    val desiredActive: Boolean,
    val status: String,
    val leasePhase: String?,
    val nextRetryAtUnix: Long?,
    val lastErrorCode: String?,
    val reserveState: String? = null,
)

internal class ConnectionIntentServiceLifecycle(
    private val coordinator: AndroidConnectionIntentCoordinator,
    private val hasPendingLogout: () -> Boolean = { false },
    private val scheduleLogout: () -> Unit = {},
    private val schedule: () -> Unit,
) {
    fun onRetryTimer() {
        if (hasDurableWork()) schedule()
    }

    fun onStickyRestart(): Boolean = resumeDurableWork()

    fun onEnsureRunning(): Boolean = resumeDurableWork()

    fun hasPendingWork(): Boolean = hasPendingLogout() || hasDurableWork()

    private fun resumeDurableWork(): Boolean {
        if (hasPendingLogout()) {
            scheduleLogout()
            return true
        }
        val durable = hasDurableWork()
        if (durable) schedule()
        return durable
    }

    private fun hasDurableWork(): Boolean =
        (coordinator.status() as? RecoveryStoreResult.Success)
            ?.value?.let { envelope ->
                (envelope.leaseTransaction != null ||
                    envelope.intent.retry.pendingAction == "legacy_runtime_stop") &&
                    !envelope.isTerminalConnectionIntent()
            } == true
}

internal fun shouldStopVpnService(
    state: SessionState,
    desiredActive: Boolean,
    pendingLogout: Boolean,
    durableConnectionWork: Boolean,
): Boolean = state != SessionState.RUNNING && !desiredActive && !pendingLogout &&
    !durableConnectionWork

internal fun legacyStartCallbackDesiredActive(
    durableDesiredActive: Boolean,
    state: SessionState,
): Boolean? = if (!durableDesiredActive) {
    null
} else {
    state in setOf(SessionState.RUNNING, SessionState.STARTING)
}

private fun AndroidRecoveryEnvelope.isTerminalConnectionIntent(): Boolean =
    intent.desiredActive && intent.armedHistory && intent.retry.lastErrorCode != null &&
        intent.retry.nextRetryAtUnix == null &&
        intent.retry.pendingAction != "terminal_after_cleanup"

internal fun interface AndroidConnectionIntentDiagnosticsObserver {
    fun leaseReplacementStarted()
}

internal fun connectionIntentServiceStatus(
    envelope: AndroidRecoveryEnvelope,
    reserveState: String? = null,
): ConnectionIntentServiceStatus {
    val transaction = envelope.leaseTransaction
    val status = when {
        transaction?.phase == LeasePhase.CLEANUP_PENDING ||
            transaction?.phase == LeasePhase.STALE_CLEANUP -> "stopping"
        envelope.intent.desiredActive && envelope.intent.retry.lastErrorCode != null &&
            envelope.intent.retry.nextRetryAtUnix == null -> "blocked_terminal"
        envelope.intent.desiredActive &&
            (envelope.intent.retry.nextRetryAtUnix != null ||
                envelope.intent.retry.pendingAction != null) -> "recovering"
        envelope.intent.desiredActive &&
            transaction?.phase != LeasePhase.ACTIVE_CHECKPOINT -> "recovering"
        else -> "none"
    }
    return ConnectionIntentServiceStatus(
        generation = envelope.intent.generation,
        desiredActive = envelope.intent.desiredActive,
        status = status,
        leasePhase = transaction?.phase?.wireName,
        nextRetryAtUnix = envelope.intent.retry.nextRetryAtUnix,
        lastErrorCode = envelope.intent.retry.lastErrorCode,
        reserveState = reserveState,
    )
}

internal fun redundantNotificationContent(state: RedundantReserveState?): String = when (state) {
    RedundantReserveState.WARMING -> "Резерв запускается"
    RedundantReserveState.READY -> "Резерв готов"
    RedundantReserveState.UNAVAILABLE -> "Резерв временно недоступен"
    RedundantReserveState.FAILOVER -> "Подключено через резервный сервер"
    null -> "VPN-подключение активно"
}

internal fun connectionIntentRetryNotificationContent(): String =
    "Проверяем стабильность подключения; при необходимости повторим попытку автоматически"

internal fun connectionIntentPersistedDelayMillis(
    envelope: AndroidRecoveryEnvelope,
    nowUnix: Long,
): Long = envelope.intent.retry.nextRetryAtUnix
    ?.let { retryAt ->
        (retryAt - nowUnix)
            .coerceAtLeast(0)
            .coerceAtMost(900)
            .times(1_000)
    }
    ?: 0L

internal fun routeInitialTerminalDiagnosticHandoff(
    outcome: AutomaticDiagnosticsConnectionIntentReportOutcome,
    acknowledge: () -> Unit,
    continueRecovery: () -> Unit,
) {
    try {
        if (outcome.allowsTerminalHandoff) acknowledge()
    } finally {
        continueRecovery()
    }
}

internal fun quickConnectionIntentTemplate(
    deviceId: String,
    quick: QuickTunnelTemplate,
    androidApiLevel: Int,
): AndroidIntentTemplate {
    val selected = quick.connection
    return AndroidIntentTemplate(
        deviceId = deviceId,
        accountScope = deviceId,
        layer = selected.layer,
        ticConnectionMode = selected.ticConnectionMode,
        routeMode = selected.routeMode,
        egressMode = selected.egressMode,
        allowAlternate = selected.allowAlternate,
        options = normalizeAndroidTunnelOptions(androidApiLevel, quick.options),
    )
}

internal class AndroidConnectionIntentCoordinator(
    private val store: AndroidRecoveryStore,
    private val operationId: () -> String = { UUID.randomUUID().toString() },
    private val errorPolicy: ConnectionIntentErrorPolicy = ConnectionIntentErrorPolicy(),
    private val nowUnix: () -> Long = { System.currentTimeMillis() / 1_000 },
    private val diagnostics: AndroidConnectionIntentDiagnosticsObserver =
        AndroidConnectionIntentDiagnosticsObserver {},
) {
    private val operationGate = AtomicBoolean(false)

    fun begin(
        template: AndroidIntentTemplate,
        validateNewIntent: (AndroidIntentTemplate) -> Unit = {},
    ): AndroidCoordinatorResult = beginInternal(
        template = template,
        validateNewIntent = validateNewIntent,
        expectedGeneration = null,
        canCommitNewIntent = { true },
    )

    fun beginDispatched(
        template: AndroidIntentTemplate,
        expectedGeneration: Long,
        canCommitNewIntent: () -> Boolean,
        validateNewIntent: (AndroidIntentTemplate) -> Unit = {},
    ): AndroidCoordinatorResult = beginInternal(
        template,
        validateNewIntent,
        expectedGeneration,
        canCommitNewIntent,
    )

    private fun beginInternal(
        template: AndroidIntentTemplate,
        validateNewIntent: (AndroidIntentTemplate) -> Unit,
        expectedGeneration: Long?,
        canCommitNewIntent: () -> Boolean,
    ): AndroidCoordinatorResult {
        if (!canCommitNewIntent()) {
            return AndroidCoordinatorResult.Failure("connection_intent_generation_conflict")
        }
        val current = when (val result = store.read()) {
            is RecoveryStoreResult.Success -> result.value
            is RecoveryStoreResult.Failure -> return AndroidCoordinatorResult.Failure(result.code)
        }
        if (current.redundantTransaction != null) {
            return AndroidCoordinatorResult.Failure("connection_recovery_v2_owned")
        }
        if (expectedGeneration != null && current.intent.generation != expectedGeneration) {
            return AndroidCoordinatorResult.Failure("connection_intent_generation_conflict")
        }
        if (current.intent.desiredActive && current.intent.template == template &&
            !current.isTerminalConnectionIntent()
        ) {
            return AndroidCoordinatorResult.Accepted(current)
        }
        if (current.leaseTransaction != null && !current.isTerminalConnectionIntent()) {
            return AndroidCoordinatorResult.Failure("connection_cleanup_pending")
        }
        try {
            validateNewIntent(template)
        } catch (error: BackgroundConnectionException) {
            return AndroidCoordinatorResult.Failure(error.code)
        } catch (_: Throwable) {
            return AndroidCoordinatorResult.Failure("connection_recovery_failed")
        }
        if (!canCommitNewIntent()) {
            return AndroidCoordinatorResult.Failure("connection_intent_generation_conflict")
        }
        val validatedCurrent = when (val result = store.read()) {
            is RecoveryStoreResult.Success -> result.value
            is RecoveryStoreResult.Failure -> return AndroidCoordinatorResult.Failure(result.code)
        }
        if (validatedCurrent.intent.generation != current.intent.generation) {
            return AndroidCoordinatorResult.Failure("connection_intent_generation_conflict")
        }
        val measured = requiresMeasuredCandidateSelection(
            template.layer,
            template.ticConnectionMode,
            template.allowAlternate,
        )
        val replay = AndroidStartReplay(
            startOperationId = operationId(),
            contractVersion = 1,
            requestFingerprint = androidConnectionIntentFingerprint(template, measured),
        )
        if (current.isTerminalConnectionIntent()) {
            return when (val result = store.restartTerminal(
                current.intent.generation,
                template,
                replay,
                operationId(),
            )) {
                is RecoveryStoreResult.Success -> AndroidCoordinatorResult.Accepted(result.value)
                is RecoveryStoreResult.Failure -> AndroidCoordinatorResult.Failure(result.code)
            }
        }
        return when (val result = store.beginStart(current.intent.generation, template, replay)) {
            is RecoveryStoreResult.Success -> AndroidCoordinatorResult.Accepted(result.value)
            is RecoveryStoreResult.Failure -> AndroidCoordinatorResult.Failure(result.code)
        }
    }

    fun cancel(): AndroidCoordinatorResult {
        return cancelCurrent()
    }

    fun cancelCurrent(): AndroidCoordinatorResult {
        return when (val result = store.cancelCurrentIntent()) {
            is RecoveryStoreResult.Success -> AndroidCoordinatorResult.Accepted(result.value)
            is RecoveryStoreResult.Failure -> AndroidCoordinatorResult.Failure(result.code)
        }
    }

    fun cancelCurrentForQuickToggle(): AndroidCoordinatorResult {
        return when (val result = store.cancelCurrentIntentForQuickToggle()) {
            is RecoveryStoreResult.Success -> AndroidCoordinatorResult.Accepted(result.value)
            is RecoveryStoreResult.Failure -> AndroidCoordinatorResult.Failure(result.code)
        }
    }

    fun cancel(expectedGeneration: Long): AndroidCoordinatorResult {
        return when (val result = store.setDesiredActive(expectedGeneration, false)) {
            is RecoveryStoreResult.Success -> AndroidCoordinatorResult.Accepted(result.value)
            is RecoveryStoreResult.Failure -> AndroidCoordinatorResult.Failure(result.code)
        }
    }

    fun dataPlaneStalled(leaseId: String): AndroidCoordinatorResult {
        val current = when (val result = store.read()) {
            is RecoveryStoreResult.Success -> result.value
            is RecoveryStoreResult.Failure -> return AndroidCoordinatorResult.Failure(result.code)
        }
        val template = current.intent.template
            ?: return AndroidCoordinatorResult.Failure("connection_intent_invalid")
        val dynamicPoolBacked = requiresMeasuredCandidateSelection(
            template.layer,
            template.ticConnectionMode,
            template.allowAlternate,
        )
        val alreadyScheduled = current.leaseTransaction?.let { transaction ->
            transaction.phase == LeasePhase.CLEANUP_PENDING &&
                transaction.leaseId == leaseId &&
                current.intent.retry.pendingAction == "new_operation_after_cleanup" &&
                current.intent.retry.lastErrorCode == "tunnel_data_plane_stalled"
        } == true
        return when (val result = store.scheduleStalledRecovery(
            expectedGeneration = current.intent.generation,
            leaseId = leaseId,
            stopOperationId = current.leaseTransaction?.stopOperationId ?: operationId(),
            dynamicPoolBacked = dynamicPoolBacked,
            nowUnix = nowUnix(),
        )) {
            is RecoveryStoreResult.Success -> {
                if (!alreadyScheduled) diagnostics.leaseReplacementStarted()
                AndroidCoordinatorResult.Accepted(result.value)
            }
            is RecoveryStoreResult.Failure -> AndroidCoordinatorResult.Failure(result.code)
        }
    }

    fun status(): RecoveryStoreResult<AndroidRecoveryEnvelope> = store.read()

    fun credentialProvisioningCompleted(): AndroidCoordinatorResult {
        val current = when (val result = store.read()) {
            is RecoveryStoreResult.Success -> result.value
            is RecoveryStoreResult.Failure -> return AndroidCoordinatorResult.Failure(result.code)
        }
        return when (val result = store.clearCredentialProvisioningBarrier(
            current.intent.generation,
        )) {
            is RecoveryStoreResult.Success -> AndroidCoordinatorResult.Accepted(result.value)
            is RecoveryStoreResult.Failure -> AndroidCoordinatorResult.Failure(result.code)
        }
    }

    fun acknowledgeInitialTerminalDiagnostic(): RecoveryStoreResult<AndroidRecoveryEnvelope> {
        val current = when (val result = store.read()) {
            is RecoveryStoreResult.Success -> result.value
            is RecoveryStoreResult.Failure -> return result
        }
        return store.acknowledgeInitialTerminalDiagnostic(
            current.intent.generation,
            current.intent.diagnosticsEpisodeId,
        )
    }

    fun acknowledgeInitialTerminalDiagnostic(
        expectedGeneration: Long,
    ): RecoveryStoreResult<AndroidRecoveryEnvelope> =
        store.acknowledgeInitialTerminalDiagnostic(expectedGeneration)

    fun acknowledgeInitialTerminalDiagnostic(
        expectedGeneration: Long,
        expectedDiagnosticsEpisodeId: Long,
    ): RecoveryStoreResult<AndroidRecoveryEnvelope> =
        store.acknowledgeInitialTerminalDiagnostic(
            expectedGeneration,
            expectedDiagnosticsEpisodeId,
        )

    fun quickToggle(
        dispatch: AndroidConnectionIntentDispatchState,
    ): RecoveryStoreResult<AndroidQuickToggleDispatch> =
        dispatch.toggleFromSnapshot(store::read)

    fun runOnce(
        panel: AndroidConnectionIntentPanel,
        runtime: AndroidConnectionIntentRuntime,
        validateNewIntent: (AndroidIntentTemplate) -> Unit = {},
    ): AndroidCoordinatorStep = runOnce(
        panel,
        runtime,
        validateNewIntent,
        onRecovered = {},
    )

    fun runOnce(
        panel: AndroidConnectionIntentPanel,
        runtime: AndroidConnectionIntentRuntime,
        @Suppress("UNUSED_PARAMETER")
        validateNewIntent: (AndroidIntentTemplate) -> Unit,
        onRecovered: (Long) -> Unit,
    ): AndroidCoordinatorStep {
        if (!operationGate.compareAndSet(false, true)) return AndroidCoordinatorStep.BUSY
        return try {
            var envelope = store.read().coordinatorEnvelopeOrNull()
                ?: return AndroidCoordinatorStep.TERMINAL
            if (envelope.intent.retry.pendingAction == "legacy_runtime_stop") {
                return stopLegacyRuntime(envelope, runtime)
            }
            if (envelope.isTerminalConnectionIntent()) return AndroidCoordinatorStep.TERMINAL
            if (envelope.intent.retry.terminalDiagnosticPending) {
                return AndroidCoordinatorStep.RETRY
            }
            var transaction = envelope.leaseTransaction ?: return AndroidCoordinatorStep.IDLE
            resumePendingAction(
                envelope,
                transaction,
                panel,
                runtime,
            )?.let { return it }
            envelope = store.read().coordinatorEnvelopeOrNull()
                ?: return AndroidCoordinatorStep.TERMINAL
            transaction = envelope.leaseTransaction ?: return AndroidCoordinatorStep.IDLE
            when (transaction.phase) {
                LeasePhase.START_PENDING -> runPendingStart(
                    envelope,
                    transaction,
                    panel,
                    runtime,
                    onRecovered,
                )
                LeasePhase.LEASE_ACQUIRED -> {
                    if (!envelope.intent.desiredActive) {
                        requireCleanup(envelope, transaction)
                        cleanup(panel, runtime)
                    } else {
                        exactReplayAndStart(
                            envelope,
                            transaction,
                            panel,
                            runtime,
                            leaseAlreadyStored = true,
                            onRecovered = onRecovered,
                        )
                    }
                }
                LeasePhase.ACTIVE_CHECKPOINT -> {
                    if (!envelope.intent.desiredActive) {
                        requireCleanup(envelope, transaction)
                        cleanup(panel, runtime)
                    } else if (runtime.isRunning()) {
                        AndroidCoordinatorStep.ACTIVE
                    } else {
                        exactReplayAndStart(
                            envelope,
                            transaction,
                            panel,
                            runtime,
                            leaseAlreadyStored = true,
                            onRecovered = onRecovered,
                        )
                    }
                }
                LeasePhase.CLEANUP_PENDING, LeasePhase.STALE_CLEANUP -> cleanup(panel, runtime)
            }
        } catch (error: BackgroundConnectionException) {
            recordFailureDecision(error.code, error.retryAfterHeader)
        } catch (_: Throwable) {
            recordTerminalFailure("connection_recovery_failed")
        } finally {
            operationGate.set(false)
        }
    }

    private fun stopLegacyRuntime(
        envelope: AndroidRecoveryEnvelope,
        runtime: AndroidConnectionIntentRuntime,
    ): AndroidCoordinatorStep = try {
        if (!runtime.stop()) {
            recordDirectRetry(
                "legacy_runtime_stop_pending",
                pendingAction = "legacy_runtime_stop",
            )
        } else {
            when (store.completeLegacyRuntimeStop(envelope.intent.generation)) {
                is RecoveryStoreResult.Success -> AndroidCoordinatorStep.IDLE
                is RecoveryStoreResult.Failure -> AndroidCoordinatorStep.RETRY
            }
        }
    } catch (error: BackgroundConnectionException) {
        recordDirectRetry(error.code, pendingAction = "legacy_runtime_stop")
    } catch (_: Throwable) {
        recordDirectRetry(
            "legacy_runtime_stop_failed",
            pendingAction = "legacy_runtime_stop",
        )
    }

    private fun recordFailureDecision(
        code: String,
        retryAfterHeader: String? = null,
    ): AndroidCoordinatorStep {
        val envelope = store.read().coordinatorEnvelopeOrNull()
            ?: return AndroidCoordinatorStep.TERMINAL
        if (!envelope.intent.desiredActive) {
            return continueDisarmed(envelope, code)
        }
        if (code == "background_credential_provision_pending") {
            return recordDirectRetry(code)
        }
        val retry = envelope.intent.retry
        val decision = errorPolicy.classify(
            code,
            serviceRecoveryUsed = retry.serviceRecoveryUsed,
            profileRetryUsed = retry.profileRetryUsed,
            reconcileOnceUsed = retry.reconcileOnceUsed,
        )
        val profileCode = code in setOf(
            "amneziawg_profile_mismatch",
            "awg3_profile_apply_failed",
            "awg3_profile_transform_mismatch",
        )
        if (decision == ConnectionIntentDecision.TERMINAL) {
            return recordTerminalFailure(code)
        }
        val delay = if (decision == ConnectionIntentDecision.RETRY_AFTER) {
            errorPolicy.retryAfterSeconds(retryAfterHeader)
        } else {
            RETRY_DELAYS_SECONDS[retry.attempt.coerceAtMost(RETRY_DELAYS_SECONDS.lastIndex)]
        }
        val retryAt = nowUnix().saturatingAdd(delay)
        if (decision == ConnectionIntentDecision.RETRY_ONCE && profileCode) {
            val transaction = envelope.leaseTransaction
                ?: return AndroidCoordinatorStep.TERMINAL
            val leaseId = transaction.leaseId ?: run {
                recordTerminalFailure("connection_cleanup_lease_unavailable")
                return AndroidCoordinatorStep.TERMINAL
            }
            diagnostics.leaseReplacementStarted()
            return when (store.scheduleProfileRetryAfterCleanup(
                expectedGeneration = envelope.intent.generation,
                leaseId = leaseId,
                stopOperationId = operationId(),
                errorCode = code,
                nextRetryAtUnix = retryAt,
                scheduledDelaySeconds = delay,
            )) {
                is RecoveryStoreResult.Success -> AndroidCoordinatorStep.RETRY
                is RecoveryStoreResult.Failure -> AndroidCoordinatorStep.TERMINAL
            }
        }
        if (decision == ConnectionIntentDecision.RETRY_NEW_OPERATION) {
            diagnostics.leaseReplacementStarted()
            val transaction = envelope.leaseTransaction
                ?: return AndroidCoordinatorStep.TERMINAL
            if (transaction.phase in setOf(LeasePhase.CLEANUP_PENDING, LeasePhase.STALE_CLEANUP)) {
                store.recordFailure(
                    expectedGeneration = envelope.intent.generation,
                    errorCode = code,
                    nextRetryAtUnix = retryAt,
                    scheduledDelaySeconds = delay,
                    pendingAction = "new_operation_after_cleanup",
                )
                return AndroidCoordinatorStep.RETRY
            }
            store.replaceStartOperation(
                envelope.intent.generation,
                transaction.replay.copy(startOperationId = operationId()),
                code,
                retryAt,
                delay,
            )
            return AndroidCoordinatorStep.RETRY
        }
        store.recordFailure(
            expectedGeneration = envelope.intent.generation,
            errorCode = code,
            nextRetryAtUnix = retryAt,
            scheduledDelaySeconds = delay,
            serviceRecoveryUsed = retry.serviceRecoveryUsed ||
                (decision == ConnectionIntentDecision.RETRY_ONCE && code == "service_unavailable"),
            profileRetryUsed = retry.profileRetryUsed ||
                (decision == ConnectionIntentDecision.RETRY_ONCE && profileCode),
            reconcileOnceUsed = retry.reconcileOnceUsed ||
                decision == ConnectionIntentDecision.RECONCILE_ONCE,
            pendingAction = when (decision) {
                ConnectionIntentDecision.RECONCILE_THEN_RETRY,
                ConnectionIntentDecision.RECONCILE_ONCE,
                -> "reconcile"
                ConnectionIntentDecision.LOCAL_RESTART -> "local_restart"
                else -> retry.pendingAction
            },
        )
        return AndroidCoordinatorStep.RETRY
    }

    private fun resumePendingAction(
        envelope: AndroidRecoveryEnvelope,
        transaction: AndroidLeaseTransaction,
        panel: AndroidConnectionIntentPanel,
        runtime: AndroidConnectionIntentRuntime,
    ): AndroidCoordinatorStep? {
        if (!envelope.intent.desiredActive &&
            envelope.intent.retry.pendingAction !in setOf(
                "initial_terminal_after_cleanup",
                "terminal_after_cleanup",
            )
        ) {
            store.clearPendingRetryAction(envelope.intent.generation)
                .coordinatorEnvelopeOrThrow()
            return null
        }
        return when (envelope.intent.retry.pendingAction) {
        "validate_capability" -> {
            // Older versions allocated the operation before capability validation. This marker
            // therefore belongs to an already-durable operation and must resume service-owned.
            store.clearPendingRetryAction(envelope.intent.generation)
                .coordinatorEnvelopeOrThrow()
            null
        }
        "local_restart" -> {
            if (runtime.isRunning() && !runtime.stop()) {
                recordDirectRetry("local_restart_pending")
            } else {
                store.clearPendingRetryAction(envelope.intent.generation)
                    .coordinatorEnvelopeOrThrow()
                null
            }
        }
        "reconcile" -> {
            val reconciled = panel.reconcile(
                transaction,
                cancelIfAbsent = !envelope.intent.desiredActive,
            )
            if (transaction.cleanupFailureCode == "tunnel_data_plane_stalled") {
                return resumeStalledStopReconcile(envelope, transaction, reconciled)
            }
            when (reconciled.state) {
                "pending", "applying", "compensating" ->
                    recordDirectRetry("operation_reconcile_pending")
                "terminal", "cancelled" -> closeAuthoritativePendingStartAndRetry(
                    envelope,
                    transaction,
                    "operation_reconcile_${reconciled.state}",
                )
                "not_found", "applied" -> {
                    if (reconciled.state == "applied" && transaction.leaseId != null &&
                        reconciled.leaseId != null && reconciled.leaseId != transaction.leaseId
                    ) {
                        recordTerminalFailure("request_fingerprint_mismatch")
                    } else {
                        store.clearPendingRetryAction(envelope.intent.generation)
                            .coordinatorEnvelopeOrThrow()
                        null
                    }
                }
                else -> {
                    recordTerminalFailure("invalid_background_response")
                }
            }
        }
        "new_operation_after_cleanup" -> null
        "terminal_after_cleanup" -> null
        "initial_terminal_after_cleanup" -> null
        null -> null
        else -> {
            recordTerminalFailure("connection_intent_invalid")
        }
        }
    }

    private fun resumeStalledStopReconcile(
        envelope: AndroidRecoveryEnvelope,
        transaction: AndroidLeaseTransaction,
        reconciled: BackgroundReconcileResult,
    ): AndroidCoordinatorStep {
        val expectedLeaseId = requireNotNull(transaction.leaseId)
        if (reconciled.leaseId?.let { it != expectedLeaseId } == true ||
            (reconciled.leaseId == null && reconciled.leaseStatus != null)
        ) {
            return recordTerminalFailure("invalid_background_response")
        }
        return when (reconciled.state) {
            "pending", "applying", "compensating" ->
                recordDirectRetry("operation_reconcile_pending")
            "not_found" -> {
                if (reconciled.leaseId != null || reconciled.leaseStatus != null) {
                    recordTerminalFailure("invalid_background_response")
                } else {
                    recordDirectRetry(
                        "connection_stalled_stop_replay_pending",
                        pendingAction = "new_operation_after_cleanup",
                    )
                }
            }
            "applied", "terminal", "cancelled" -> {
                if (reconciled.leaseId == expectedLeaseId &&
                    reconciled.leaseStatus in setOf("released", "failed")
                ) {
                    store.completeCleanupAndRestart(
                        envelope.intent.generation,
                        transaction.replay.copy(startOperationId = operationId()),
                    ).coordinatorEnvelopeOrThrow()
                    recordDirectRetry("connection_restart_pending")
                } else {
                    recordBlockedStalledRecovery(envelope)
                }
            }
            else -> recordTerminalFailure("invalid_background_response")
        }
    }

    private fun recordBlockedStalledRecovery(
        envelope: AndroidRecoveryEnvelope,
    ): AndroidCoordinatorStep = when (store.recordFailure(
        expectedGeneration = envelope.intent.generation,
        errorCode = "connection_stall_not_recyclable",
        nextRetryAtUnix = null,
        pendingAction = null,
    )) {
        is RecoveryStoreResult.Success -> AndroidCoordinatorStep.TERMINAL
        is RecoveryStoreResult.Failure -> AndroidCoordinatorStep.TERMINAL
    }

    private fun recordTerminalFailure(code: String): AndroidCoordinatorStep {
        val envelope = store.read().coordinatorEnvelopeOrNull()
            ?: return AndroidCoordinatorStep.TERMINAL
        val transaction = envelope.leaseTransaction
        val leaseId = transaction?.leaseId
        if (leaseId != null) {
            val scheduled = if (envelope.intent.armedHistory) {
                store.scheduleTerminalAfterCleanup(
                    expectedGeneration = envelope.intent.generation,
                    leaseId = leaseId,
                    stopOperationId = transaction.stopOperationId ?: operationId(),
                    errorCode = code,
                )
            } else {
                store.scheduleInitialTerminalAfterCleanup(
                    expectedGeneration = envelope.intent.generation,
                    leaseId = leaseId,
                    stopOperationId = transaction.stopOperationId ?: operationId(),
                    errorCode = code,
                )
            }
            return when (scheduled) {
                is RecoveryStoreResult.Success -> if (envelope.intent.armedHistory) {
                    AndroidCoordinatorStep.RETRY
                } else {
                    AndroidCoordinatorStep.RETRY
                }
                is RecoveryStoreResult.Failure -> AndroidCoordinatorStep.TERMINAL
            }
        }
        if (!envelope.intent.armedHistory) {
            return when (store.scheduleInitialTerminalReconcile(
                envelope.intent.generation,
                code,
            )) {
                is RecoveryStoreResult.Success -> AndroidCoordinatorStep.RETRY
                is RecoveryStoreResult.Failure -> AndroidCoordinatorStep.TERMINAL
            }
        }
        store.recordFailure(envelope.intent.generation, code, null)
        return AndroidCoordinatorStep.TERMINAL
    }

    private fun continueDisarmed(
        envelope: AndroidRecoveryEnvelope,
        code: String,
    ): AndroidCoordinatorStep {
        val transaction = envelope.leaseTransaction ?: return AndroidCoordinatorStep.IDLE
        transaction.leaseId?.let { leaseId ->
            when (store.requireCleanup(
                envelope.intent.generation,
                leaseId,
                transaction.stopOperationId ?: operationId(),
            )) {
                is RecoveryStoreResult.Success -> Unit
                is RecoveryStoreResult.Failure -> return AndroidCoordinatorStep.TERMINAL
            }
        }
        return recordDirectRetry(code)
    }

    private fun recordDirectRetry(
        code: String,
        pendingAction: String? = null,
    ): AndroidCoordinatorStep {
        val envelope = store.read().coordinatorEnvelopeOrNull()
            ?: return AndroidCoordinatorStep.TERMINAL
        val retry = envelope.intent.retry
        val delay = RETRY_DELAYS_SECONDS[
            retry.attempt.coerceAtMost(RETRY_DELAYS_SECONDS.lastIndex)
        ]
        val result = store.recordFailure(
            expectedGeneration = envelope.intent.generation,
            errorCode = code,
            nextRetryAtUnix = nowUnix().saturatingAdd(delay),
            scheduledDelaySeconds = delay,
            pendingAction = pendingAction ?: retry.pendingAction,
        )
        return if (result is RecoveryStoreResult.Success) {
            AndroidCoordinatorStep.RETRY
        } else {
            AndroidCoordinatorStep.TERMINAL
        }
    }

    private fun recordTerminalCleanupRetry(): AndroidCoordinatorStep {
        val envelope = store.read().coordinatorEnvelopeOrNull()
            ?: return AndroidCoordinatorStep.TERMINAL
        val retry = envelope.intent.retry
        val delay = RETRY_DELAYS_SECONDS[
            retry.attempt.coerceAtMost(RETRY_DELAYS_SECONDS.lastIndex)
        ]
        val result = store.recordTerminalCleanupRetry(
            expectedGeneration = envelope.intent.generation,
            nextRetryAtUnix = nowUnix().saturatingAdd(delay),
            scheduledDelaySeconds = delay,
        )
        return if (result is RecoveryStoreResult.Success) {
            AndroidCoordinatorStep.RETRY
        } else {
            AndroidCoordinatorStep.TERMINAL
        }
    }

    private fun Long.saturatingAdd(other: Long): Long =
        if (this > Long.MAX_VALUE - other) Long.MAX_VALUE else this + other

    private companion object {
        val RETRY_DELAYS_SECONDS = longArrayOf(2, 5, 15, 30, 60, 300)
    }

    private fun runPendingStart(
        envelope: AndroidRecoveryEnvelope,
        transaction: AndroidLeaseTransaction,
        panel: AndroidConnectionIntentPanel,
        runtime: AndroidConnectionIntentRuntime,
        onRecovered: (Long) -> Unit,
    ): AndroidCoordinatorStep {
        val cancelIfAbsent = !envelope.intent.desiredActive
        val reconciled = panel.reconcile(transaction, cancelIfAbsent)
        val live = store.read().coordinatorEnvelopeOrThrow()
        if (!cancelIfAbsent && (live.intent.generation != envelope.intent.generation ||
                !live.intent.desiredActive)
        ) {
            return continueAfterReconcileFence(live, reconciled, panel, runtime)
        }
        if (cancelIfAbsent) {
            return when (reconciled.state) {
                "not_found", "terminal", "cancelled" -> {
                    store.completeCancelledStart(envelope.intent.generation)
                        .coordinatorEnvelopeOrNull()
                    AndroidCoordinatorStep.IDLE
                }
                "applied" -> {
                    val leaseId = reconciled.leaseId
                        ?: throw BackgroundConnectionException("invalid_background_response")
                    val current = store.read().coordinatorEnvelopeOrThrow()
                    store.requireCleanup(current.intent.generation, leaseId, operationId())
                        .coordinatorEnvelopeOrThrow()
                    cleanup(panel, runtime)
                }
                "pending", "applying", "compensating" ->
                    recordDirectRetry("operation_reconcile_pending")
                else -> recordDirectRetry("invalid_background_response")
            }
        }
        return when (reconciled.state) {
            "not_found", "applied" -> exactReplayAndStart(
                envelope,
                transaction,
                panel,
                runtime,
                leaseAlreadyStored = false,
                syncBeforeStart = reconciled.state == "not_found",
                onRecovered = onRecovered,
            )
            "pending", "applying", "compensating" ->
                recordDirectRetry("operation_reconcile_pending")
            "terminal", "cancelled" -> closeAuthoritativePendingStartAndRetry(
                envelope,
                transaction,
                "operation_reconcile_${reconciled.state}",
            )
            else -> {
                recordTerminalFailure("invalid_background_response")
            }
        }
    }

    private fun continueAfterReconcileFence(
        live: AndroidRecoveryEnvelope,
        staleResult: BackgroundReconcileResult,
        panel: AndroidConnectionIntentPanel,
        runtime: AndroidConnectionIntentRuntime,
    ): AndroidCoordinatorStep {
        val transaction = live.leaseTransaction ?: return AndroidCoordinatorStep.IDLE
        if (staleResult.state == "applied") {
            val leaseId = staleResult.leaseId
                ?: throw BackgroundConnectionException("invalid_background_response")
            store.requireCleanup(
                live.intent.generation,
                leaseId,
                transaction.stopOperationId ?: operationId(),
            ).coordinatorEnvelopeOrThrow()
            return cleanup(panel, runtime)
        }
        val cancelled = panel.reconcile(transaction, cancelIfAbsent = true)
        return when (cancelled.state) {
            "not_found", "terminal", "cancelled" -> {
                if (!live.intent.desiredActive && transaction.phase == LeasePhase.START_PENDING &&
                    transaction.leaseId == null
                ) {
                    store.completeCancelledStart(live.intent.generation)
                        .coordinatorEnvelopeOrThrow()
                    AndroidCoordinatorStep.IDLE
                } else {
                    recordDirectRetry("operation_reconcile_cancel_pending")
                }
            }
            "applied" -> {
                val leaseId = cancelled.leaseId
                    ?: throw BackgroundConnectionException("invalid_background_response")
                store.requireCleanup(
                    live.intent.generation,
                    leaseId,
                    transaction.stopOperationId ?: operationId(),
                ).coordinatorEnvelopeOrThrow()
                cleanup(panel, runtime)
            }
            "pending", "applying", "compensating" ->
                recordDirectRetry("operation_reconcile_pending")
            else -> recordDirectRetry("invalid_background_response")
        }
    }

    private fun closeAuthoritativePendingStartAndRetry(
        envelope: AndroidRecoveryEnvelope,
        transaction: AndroidLeaseTransaction,
        code: String,
    ): AndroidCoordinatorStep {
        if (!envelope.intent.desiredActive || transaction.phase != LeasePhase.START_PENDING ||
            transaction.leaseId != null
        ) {
            if (!envelope.intent.desiredActive && transaction.phase == LeasePhase.START_PENDING &&
                transaction.leaseId == null
            ) {
                store.completeCancelledStart(envelope.intent.generation)
                    .coordinatorEnvelopeOrNull()
                return AndroidCoordinatorStep.IDLE
            }
            return recordTerminalFailure(code)
        }
        val retry = envelope.intent.retry
        val delay = RETRY_DELAYS_SECONDS[
            retry.attempt.coerceAtMost(RETRY_DELAYS_SECONDS.lastIndex)
        ]
        return when (store.closeAuthoritativeStartAndRestart(
            expectedGeneration = envelope.intent.generation,
            replay = transaction.replay.copy(startOperationId = operationId()),
            errorCode = code,
            nextRetryAtUnix = nowUnix().saturatingAdd(delay),
            scheduledDelaySeconds = delay,
        )) {
            is RecoveryStoreResult.Success -> AndroidCoordinatorStep.RETRY
            is RecoveryStoreResult.Failure -> AndroidCoordinatorStep.TERMINAL
        }
    }

    private fun exactReplayAndStart(
        envelope: AndroidRecoveryEnvelope,
        transaction: AndroidLeaseTransaction,
        panel: AndroidConnectionIntentPanel,
        runtime: AndroidConnectionIntentRuntime,
        leaseAlreadyStored: Boolean,
        syncBeforeStart: Boolean = false,
        onRecovered: (Long) -> Unit,
    ): AndroidCoordinatorStep {
        val template = envelope.intent.template
            ?: throw BackgroundConnectionException("connection_intent_invalid")
        if (syncBeforeStart && template.syncBindingPreferences) {
            panel.syncBindingPreferences(template)
            val ready = store.read().coordinatorEnvelopeOrThrow()
            if (!ready.intent.desiredActive || ready.intent.generation != transaction.generation) {
                if (!ready.intent.desiredActive &&
                    ready.leaseTransaction?.phase == LeasePhase.START_PENDING &&
                    ready.leaseTransaction.leaseId == null
                ) {
                    store.completeCancelledStart(ready.intent.generation)
                        .coordinatorEnvelopeOrThrow()
                    return AndroidCoordinatorStep.IDLE
                }
                return AndroidCoordinatorStep.RETRY
            }
        }
        val result = panel.start(template, transaction)
        val leaseId = result.connection.leaseId
        val live = store.read().coordinatorEnvelopeOrThrow()
        if (!live.intent.desiredActive || live.intent.generation != transaction.generation) {
            result.configuration.fill(0)
            store.requireCleanup(live.intent.generation, leaseId, operationId())
                .coordinatorEnvelopeOrThrow()
            return AndroidCoordinatorStep.CLEANUP_REQUIRED
        }
        if (!leaseAlreadyStored) {
            store.recordLease(transaction.generation, leaseId).coordinatorEnvelopeOrThrow()
        } else if (transaction.leaseId != leaseId) {
            result.configuration.fill(0)
            throw BackgroundConnectionException("request_fingerprint_mismatch")
        }
        val runtimeStart = try {
            startRuntimeWithConnectionIntentFence(
                expectedGeneration = transaction.generation,
                operationId = transaction.startOperationId,
                current = { store.read().coordinatorEnvelopeOrThrow() },
                result = result,
                runtime = runtime,
            )
        } catch (error: BackgroundConnectionException) {
            if (error.code == "tunnel_handshake_timeout") {
                val acquired = store.read().coordinatorEnvelopeOrThrow()
                store.requireCleanup(acquired.intent.generation, leaseId, operationId())
                    .coordinatorEnvelopeOrThrow()
            } else if (error.code == "tunnel_start_cancelled") {
                val acquired = store.read().coordinatorEnvelopeOrThrow()
                if (!acquired.intent.desiredActive) {
                    store.requireCleanup(acquired.intent.generation, leaseId, operationId())
                        .coordinatorEnvelopeOrThrow()
                    return cleanup(panel, runtime)
                }
            }
            throw error
        }
        when (runtimeStart) {
            AndroidRuntimeStartFenceResult.CANCELLED_BEFORE_START -> {
                val cancelled = store.read().coordinatorEnvelopeOrThrow()
                store.requireCleanup(cancelled.intent.generation, leaseId, operationId())
                    .coordinatorEnvelopeOrThrow()
                return AndroidCoordinatorStep.CLEANUP_REQUIRED
            }
            AndroidRuntimeStartFenceResult.CANCELLED_AFTER_START -> {
                val acquired = store.read().coordinatorEnvelopeOrThrow()
                store.requireCleanup(acquired.intent.generation, leaseId, operationId())
                    .coordinatorEnvelopeOrThrow()
                return cleanup(panel, runtime)
            }
            is AndroidRuntimeStartFenceResult.FAILED -> {
                throw BackgroundConnectionException(runtimeStart.errorCode)
            }
            AndroidRuntimeStartFenceResult.STARTED -> Unit
        }
        runCatching { onRecovered(envelope.intent.diagnosticsEpisodeId) }
        return when (val activated = store.activateCheckpoint(transaction.generation)) {
            is RecoveryStoreResult.Success -> AndroidCoordinatorStep.ACTIVE
            is RecoveryStoreResult.Failure -> {
                val liveAfterStart = store.read().coordinatorEnvelopeOrThrow()
                if (activated.code != "connection_intent_generation_conflict" ||
                    liveAfterStart.intent.desiredActive
                ) {
                    throw BackgroundConnectionException(activated.code)
                }
                store.requireCleanup(liveAfterStart.intent.generation, leaseId, operationId())
                    .coordinatorEnvelopeOrThrow()
                cleanup(panel, runtime)
            }
        }
    }

    private fun requireCleanup(
        envelope: AndroidRecoveryEnvelope,
        transaction: AndroidLeaseTransaction,
    ) {
        val leaseId = transaction.leaseId
            ?: throw BackgroundConnectionException("connection_cleanup_lease_unavailable")
        store.requireCleanup(envelope.intent.generation, leaseId, operationId())
            .coordinatorEnvelopeOrThrow()
    }

    private fun cleanup(
        panel: AndroidConnectionIntentPanel,
        runtime: AndroidConnectionIntentRuntime,
    ): AndroidCoordinatorStep {
        var envelope = store.read().coordinatorEnvelopeOrThrow()
        var transaction = envelope.leaseTransaction ?: return AndroidCoordinatorStep.IDLE
        if (transaction.leaseId == null) {
            val reconciled = panel.reconcile(transaction, cancelIfAbsent = true)
            return when (reconciled.state) {
                "not_found", "terminal", "cancelled" -> {
                    if (envelope.intent.desiredActive &&
                        envelope.intent.retry.pendingAction == "new_operation_after_cleanup"
                    ) {
                        store.completeCleanupAndRestart(
                            envelope.intent.generation,
                            transaction.replay.copy(startOperationId = operationId()),
                        ).coordinatorEnvelopeOrThrow()
                        return recordDirectRetry("connection_restart_pending")
                    } else if (envelope.intent.retry.pendingAction == "terminal_after_cleanup") {
                        store.completeCleanupAsTerminal(envelope.intent.generation)
                            .coordinatorEnvelopeOrThrow()
                        AndroidCoordinatorStep.TERMINAL
                    } else if (envelope.intent.retry.pendingAction ==
                        "initial_terminal_after_cleanup"
                    ) {
                        store.completeInitialTerminalCleanup(envelope.intent.generation)
                            .coordinatorEnvelopeOrThrow()
                        AndroidCoordinatorStep.IDLE
                    } else if (transaction.phase == LeasePhase.START_PENDING) {
                        store.completeCancelledStart(envelope.intent.generation)
                    } else {
                        store.completeCleanup(envelope.intent.generation)
                    }.coordinatorEnvelopeOrThrow()
                    AndroidCoordinatorStep.IDLE
                }
                "applied" -> {
                    val leaseId = reconciled.leaseId
                        ?: throw BackgroundConnectionException("invalid_background_response")
                    store.requireCleanup(envelope.intent.generation, leaseId, operationId())
                        .coordinatorEnvelopeOrThrow()
                    cleanup(panel, runtime)
                }
                else -> recordDirectRetry("connection_cleanup_reconcile_pending")
            }
        }
        if (transaction.stopOperationId == null) {
            store.requireCleanup(
                envelope.intent.generation,
                requireNotNull(transaction.leaseId),
                operationId(),
            ).coordinatorEnvelopeOrThrow()
            envelope = store.read().coordinatorEnvelopeOrThrow()
            transaction = requireNotNull(envelope.leaseTransaction)
        }
        if (!transaction.localStopPending) {
            store.requireCleanup(
                envelope.intent.generation,
                requireNotNull(transaction.leaseId),
                requireNotNull(transaction.stopOperationId),
            ).coordinatorEnvelopeOrThrow()
            envelope = store.read().coordinatorEnvelopeOrThrow()
            transaction = requireNotNull(envelope.leaseTransaction)
        }
        val terminalAfterCleanup =
            envelope.intent.retry.pendingAction == "terminal_after_cleanup"
        if (!runtime.stop()) {
            return if (terminalAfterCleanup) {
                recordTerminalCleanupRetry()
            } else {
                recordDirectRetry("connection_cleanup_local_stop_pending")
            }
        }
        try {
            panel.stop(
                requireNotNull(transaction.leaseId),
                requireNotNull(transaction.stopOperationId),
                transaction.cleanupFailureCode,
            )
        } catch (error: Throwable) {
            if (terminalAfterCleanup) return recordTerminalCleanupRetry()
            throw error
        }
        return if (envelope.intent.desiredActive &&
            envelope.intent.retry.pendingAction == "new_operation_after_cleanup"
        ) {
            store.completeCleanupAndRestart(
                envelope.intent.generation,
                transaction.replay.copy(startOperationId = operationId()),
            ).coordinatorEnvelopeOrThrow()
            recordDirectRetry("connection_restart_pending")
        } else if (envelope.intent.retry.pendingAction == "terminal_after_cleanup") {
            store.completeCleanupAsTerminal(envelope.intent.generation)
                .coordinatorEnvelopeOrThrow()
            AndroidCoordinatorStep.TERMINAL
        } else if (envelope.intent.retry.pendingAction == "initial_terminal_after_cleanup") {
            store.completeInitialTerminalCleanup(envelope.intent.generation)
                .coordinatorEnvelopeOrThrow()
            AndroidCoordinatorStep.IDLE
        } else {
            store.completeCleanup(envelope.intent.generation).coordinatorEnvelopeOrThrow()
            AndroidCoordinatorStep.IDLE
        }
    }
}

private fun RecoveryStoreResult<AndroidRecoveryEnvelope>.coordinatorEnvelopeOrNull():
    AndroidRecoveryEnvelope? = when (this) {
    is RecoveryStoreResult.Success -> value
    is RecoveryStoreResult.Failure -> null
}

private fun RecoveryStoreResult<AndroidRecoveryEnvelope>.coordinatorEnvelopeOrThrow():
    AndroidRecoveryEnvelope = when (this) {
    is RecoveryStoreResult.Success -> value
    is RecoveryStoreResult.Failure -> throw BackgroundConnectionException(code)
}

internal fun androidConnectionIntentFingerprint(
    template: AndroidIntentTemplate,
    requireMeasuredSelection: Boolean,
): String {
    val canonical = buildString {
        append("{\"egress_mode\":\"")
        append(template.egressMode)
        append("\",\"kind\":\"start\",\"layer\":\"")
        append(template.layer)
        append("\",\"require_measured_selection\":")
        append(requireMeasuredSelection)
        append(",\"route_mode\":\"")
        append(template.routeMode)
        append("\",\"tic_connection_mode\":\"")
        append(template.ticConnectionMode)
        append("\"}")
    }
    return MessageDigest.getInstance("SHA-256")
        .digest(canonical.toByteArray(Charsets.UTF_8))
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}

internal fun androidStalledStopFingerprint(leaseId: String): String {
    AndroidRecoveryEnvelopeCodec.validateSafeValue(leaseId)
    val canonical = buildString {
        append("{\"failure_code\":\"tunnel_data_plane_stalled\",")
        append("\"kind\":\"stalled_stop\",")
        append("\"lease_id\":\"")
        append(leaseId)
        append("\"}")
    }
    return MessageDigest.getInstance("SHA-256")
        .digest(canonical.toByteArray(Charsets.UTF_8))
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}

private fun CredentialStoreResult<BackgroundCredentialEnvelope>.credentialOrThrow():
    BackgroundCredentialEnvelope = when (this) {
    is CredentialStoreResult.Success -> value
    is CredentialStoreResult.Failure -> throw CredentialRotationFailure(code)
}

internal fun shouldQueueBackgroundStartFailureDiagnostics(
    starting: Boolean,
    errorCode: String?,
): Boolean = starting && errorCode != null && errorCode != "tunnel_operation_in_progress"

internal fun dispatchSerializedConnectionIntentMutation(
    executor: Executor,
    mutation: () -> Unit,
) {
    executor.execute(mutation)
}

internal fun completeBackgroundFailureWithDiagnostics(
    queueDiagnostics: (() -> Unit) -> Unit,
    finishUserAction: () -> Unit,
    finishDeferredServiceStop: () -> Unit,
    onDiagnosticsQueueFailure: (Throwable) -> Unit = {},
) {
    finishUserAction()
    val pendingServiceStop = AtomicBoolean(true)
    val finishServiceStopOnce = {
        if (pendingServiceStop.compareAndSet(true, false)) {
            finishDeferredServiceStop()
        }
    }
    try {
        queueDiagnostics(finishServiceStopOnce)
    } catch (error: Throwable) {
        runCatching { onDiagnosticsQueueFailure(error) }
        finishServiceStopOnce()
    }
}

private fun ResultReceiver?.sendOperation(state: SessionState, durationMillis: Long) {
    this?.send(
        SERVICE_RESULT_OK,
        Bundle().apply {
            putString(EXTRA_STATE, state.wireName)
            putLong(EXTRA_DURATION_MILLIS, durationMillis)
        },
    )
}

private fun ResultReceiver?.sendError(code: String) {
    this?.send(
        SERVICE_RESULT_ERROR,
        Bundle().apply { putString(EXTRA_ERROR_CODE, code) },
    )
}

private fun ResultReceiver?.sendSuccess() {
    this?.send(SERVICE_RESULT_OK, Bundle.EMPTY)
}

internal fun shouldRestoreDesiredTunnel(
    desiredActive: Boolean,
    state: SessionState,
): Boolean = desiredActive && state !in setOf(SessionState.RUNNING, SessionState.STARTING)

internal fun shouldRetryServiceRestore(code: String): Boolean = code in setOf(
    "background_transport_unavailable",
    "background_panel_error",
    "connection_unavailable",
    "connection_release_failed",
    "candidate_unavailable",
    "split_tunnel_policy_unavailable",
)
