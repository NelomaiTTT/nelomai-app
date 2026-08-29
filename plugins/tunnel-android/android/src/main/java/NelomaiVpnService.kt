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
import android.widget.Toast
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import org.amnezia.awg.backend.GoBackend
import java.time.Instant
import java.util.UUID
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

private const val IDLE_SERVICE_STOP_DELAY_MILLIS = 400L
private const val BACKGROUND_REFRESH_WINDOW_SECONDS = 7L * 24 * 60 * 60
private const val BACKGROUND_MUTATION_RESERVATION_SECONDS = 10L * 60

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

class NelomaiVpnService : GoBackend.VpnService() {
    private val serviceGeneration = VPN_PROCESS_SERVICE_GENERATION.incrementAndGet()
    private val restoreHandler = Handler(Looper.getMainLooper())
    private val credentialExecutor = Executors.newSingleThreadExecutor { task ->
        Thread(task, "nelomai-background-credential").apply { isDaemon = true }
    }
    private val idleStopDebouncer = IdleStopDebouncer(
        delayMillis = IDLE_SERVICE_STOP_DELAY_MILLIS,
        schedule = { task, delay -> restoreHandler.postDelayed(task, delay) },
        cancel = restoreHandler::removeCallbacks,
    )
    private var restoreRetryAttempt = 0
    private val restoreRetry = Runnable {
        if (QuickTunnelController.desiredActive(applicationContext)) {
            performBackgroundStart(restoring = true)
        }
    }

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
        when {
            intent?.action == ACTION_QUICK_TOGGLE -> {
                cancelRestoreRetry()
                performBackgroundToggle()
            }
            intent?.action == ACTION_ENSURE_RUNNING -> {
                restoreDesiredTunnel("ensure_running")
            }
            intent?.action == ACTION_CLIENT_START -> handleClientStart(intent)
            intent?.action == ACTION_CANCEL_CLIENT_START -> handleCancelClientStart(intent)
            intent?.action == ACTION_CLIENT_STOP -> handleClientStop(intent)
            intent?.action == ACTION_CLIENT_STATUS -> handleClientStatus(intent)
            intent?.action == ACTION_CLIENT_METRICS -> handleClientMetrics(intent)
            intent?.action == ACTION_CLIENT_REBIND_UDP -> handleClientRebindUdp(intent)
            intent?.action == ACTION_CONFIGURE_BACKGROUND -> handleConfigureBackground(intent)
            intent?.action == ACTION_ROTATE_BACKGROUND -> handleRotateBackground(intent)
            intent?.action == ACTION_BACKGROUND_STATUS -> handleBackgroundStatus(intent)
            intent?.action == ACTION_CLEAR_BACKGROUND -> handleClearBackground(intent)
            intent?.action == ACTION_CLEAR_QUICK_PLAN -> handleClearQuickPlan(intent)
            intent?.action == ACTION_UPDATE_QUICK_DNS -> handleUpdateQuickDns(intent)
            intent?.action == ACTION_TAKE_STATE_CHANGE -> handleTakeStateChange(intent)
            intent?.action == ACTION_ACKNOWLEDGE_STATE_CHANGE -> handleAcknowledgeStateChange(intent)
            intent == null && QuickTunnelController.desiredActive(applicationContext) -> {
                restoreDesiredTunnel("sticky_restart")
            }
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
            }
        } catch (_: Throwable) {
            configuration?.fill(0)
            receiver.sendError("invalid_tunnel_request")
            stopIfIdle()
            return
        }
        QuickTunnelController.updateState(
            applicationContext,
            SessionState.STARTING,
            desiredActive = true,
        )
        TunnelRuntime.start(
            applicationContext,
            args,
            { state, duration ->
                QuickTunnelController.updateState(
                    applicationContext,
                    state,
                    desiredActive = state == SessionState.RUNNING,
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

    private fun handleCancelClientStart(intent: Intent) {
        val clientOperationId = runCatching {
            UUID.fromString(
                requireNotNull(intent.getStringExtra(EXTRA_CLIENT_OPERATION_ID)),
            ).toString()
        }.getOrNull() ?: run {
            stopIfIdle()
            return
        }
        TunnelRuntime.cancelClientStart(applicationContext, clientOperationId)
        stopIfIdle()
    }

    private fun handleClientStop(intent: Intent) {
        val receiver = intent.resultReceiver()
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
        TunnelRuntime.metrics(
            intent.getIntExtra(EXTRA_API_VERSION, 0),
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
        TunnelRuntime.rebindUdp(
            applicationContext,
            intent.getIntExtra(EXTRA_API_VERSION, 0),
            { state, duration -> receiver.sendOperation(state, duration) },
            { code -> receiver.sendError(code) },
        )
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
                putBoolean(EXTRA_CONFIGURED, credential != null)
                putLong(EXTRA_CREDENTIAL_REVISION, envelope.revision)
                putBoolean(
                    EXTRA_MUTATION_READY,
                    envelope.installSecret != null && envelope.capability != null,
                )
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
        stopIfIdle()
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
            val capability = BackgroundConnectionClient.capabilities(credential)
            envelope = store.updateCapability(envelope.revision, capability).credentialOrThrow()
            if (!capability.enabled || capability.expiresAtUnix <= nowUnix) return
            if (credential.expiresAtUnix > nowUnix + BACKGROUND_REFRESH_WINDOW_SECONDS) return
        }

        var pending = envelope.pending
        if (pending == null) {
            val reservation = envelope.reservation ?: run {
                val prepareOperationId = UUID.randomUUID().toString()
                val activationOperationId = UUID.randomUUID().toString()
                envelope = store.reserveMutation(
                    expectedRevision = envelope.revision,
                    mutationId = prepareOperationId,
                    deviceId = credential.deviceId,
                    expiresAtUnix = nowUnix + BACKGROUND_MUTATION_RESERVATION_SECONDS,
                    nowUnix = nowUnix,
                    activationOperationId = activationOperationId,
                ).credentialOrThrow()
                requireNotNull(envelope.reservation)
            }
            pending = BackgroundConnectionClient.prepareToken(
                credential,
                reservation.mutationId,
                reservation.activationOperationId,
                installSecret,
            )
            envelope = store.savePendingToken(
                expectedRevision = envelope.revision,
                mutationId = reservation.mutationId,
                pending = pending,
                nowUnix = System.currentTimeMillis() / 1_000,
            ).credentialOrThrow()
        }

        credential = envelope.active
            ?: throw CredentialRotationFailure("background_credential_active_absent")
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
        QuickTunnelController.updateState(
            applicationContext,
            SessionState.STOPPED,
            desiredActive = false,
            changed = true,
        )
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        super.onRevoke()
        stopSelf()
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        TunnelLog.info("service.ui_task_removed")
        runCatching { AutomaticDiagnostics.onUiTaskRemoved(applicationContext) }
            .onFailure { TunnelLog.warning("diagnostics.memory_snapshot_failed", error = it) }
        super.onTaskRemoved(rootIntent)
    }

    override fun onDestroy() {
        idleStopDebouncer.cancel()
        cancelRestoreRetry()
        credentialExecutor.shutdownNow()
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

    private fun performBackgroundToggle() {
        dispatchBackgroundToggle(
            desiredActive = QuickTunnelController.desiredActive(applicationContext),
            start = { performBackgroundStart(restoring = false) },
            stop = {
                TunnelRuntime.backgroundStop(
                    applicationContext,
                    onSuccess = { state, _ ->
                        completeBackgroundAction(state, null, false, false)
                    },
                    onError = {
                        completeBackgroundAction(TunnelRuntime.state(), it, false, false)
                    },
                )
            },
        )
    }

    private fun performBackgroundStart(restoring: Boolean) {
        TunnelRuntime.backgroundStart(
            applicationContext,
            onSuccess = { state, _ -> completeBackgroundAction(state, null, restoring, true) },
            onError = { completeBackgroundAction(TunnelRuntime.state(), it, restoring, true) },
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
        performBackgroundStart(restoring = true)
    }

    private fun stopIfIdle() {
        if (TunnelRuntime.state() != SessionState.RUNNING &&
            !QuickTunnelController.desiredActive(applicationContext)
        ) {
            idleStopDebouncer.schedule {
                if (TunnelRuntime.state() != SessionState.RUNNING &&
                    !QuickTunnelController.desiredActive(applicationContext)
                ) {
                    ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
            }
        } else {
            idleStopDebouncer.cancel()
        }
    }

    private fun completeBackgroundAction(
        state: SessionState,
        errorCode: String?,
        restoring: Boolean,
        starting: Boolean,
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
        finishBackgroundAction(state, errorCode, restoring)
    }

    private fun finishBackgroundAction(
        state: SessionState,
        errorCode: String?,
        restoring: Boolean,
        deferErrorServiceStop: Boolean = false,
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
            desiredActive = state == SessionState.RUNNING,
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
        val delay = RESTORE_RETRY_DELAYS_MILLIS[
            restoreRetryAttempt.coerceAtMost(RESTORE_RETRY_DELAYS_MILLIS.lastIndex)
        ]
        restoreRetryAttempt += 1
        restoreHandler.postDelayed(restoreRetry, delay)
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
        internal const val ACTION_CONFIGURE_BACKGROUND = "ru.nelomai.tunnel.CONFIGURE_BACKGROUND"
        internal const val ACTION_ROTATE_BACKGROUND = "ru.nelomai.tunnel.ROTATE_BACKGROUND"
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
        )
        private val RESTORE_RETRY_DELAYS_MILLIS = longArrayOf(
            5_000L,
            30_000L,
            120_000L,
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

        fun setPhysicalNetworks(networks: List<Network>) {
            activeService?.setUnderlyingNetworks(networks.toTypedArray().takeIf { it.isNotEmpty() })
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

    private fun connectionNotification(): android.app.Notification {
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
            .setContentText("VPN-подключение активно")
            .setOngoing(true)
            .setSilent(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .apply { pendingIntent?.let(::setContentIntent) }
            .build()
    }
}

private class CredentialRotationFailure(val code: String) : RuntimeException(code)

private fun CredentialStoreResult<BackgroundCredentialEnvelope>.credentialOrThrow():
    BackgroundCredentialEnvelope = when (this) {
    is CredentialStoreResult.Success -> value
    is CredentialStoreResult.Failure -> throw CredentialRotationFailure(code)
}

internal fun shouldQueueBackgroundStartFailureDiagnostics(
    starting: Boolean,
    errorCode: String?,
): Boolean = starting && errorCode != null && errorCode != "tunnel_operation_in_progress"

internal fun dispatchBackgroundToggle(
    desiredActive: Boolean,
    start: () -> Unit,
    stop: () -> Unit,
) {
    val targetActive = !desiredActive
    if (targetActive) start() else stop()
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
