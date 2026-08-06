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
import android.os.ResultReceiver
import android.widget.Toast
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import com.wireguard.android.backend.GoBackend
import java.util.concurrent.CompletableFuture

class NelomaiVpnService : GoBackend.VpnService() {
    private val restoreHandler = Handler(Looper.getMainLooper())
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
            intent?.action == ACTION_CLIENT_STOP -> handleClientStop(intent)
            intent?.action == ACTION_CLIENT_STATUS -> handleClientStatus(intent)
            intent?.action == ACTION_CLIENT_METRICS -> handleClientMetrics(intent)
            intent?.action == ACTION_CONFIGURE_BACKGROUND -> handleConfigureBackground(intent)
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
            { received, sent, target ->
                receiver?.send(
                    SERVICE_RESULT_OK,
                    Bundle().apply {
                        putLong(EXTRA_RECEIVED_BYTES, received)
                        putLong(EXTRA_SENT_BYTES, sent)
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

    private fun handleConfigureBackground(intent: Intent) {
        val receiver = intent.resultReceiver()
        try {
            val apiVersion = intent.getIntExtra(EXTRA_API_VERSION, 0)
            val expiresAtUnix = intent.getLongExtra(EXTRA_EXPIRES_AT_UNIX, 0)
            if (apiVersion != TUNNEL_API_VERSION || expiresAtUnix <= 0) {
                throw IllegalArgumentException("invalid background credential")
            }
            BackgroundCredentialStore.save(
                applicationContext,
                BackgroundCredential(
                    requireNotNull(intent.getStringExtra(EXTRA_DEVICE_ID)),
                    requireNotNull(intent.getStringExtra(EXTRA_PANEL_BASE)),
                    requireNotNull(intent.getStringExtra(EXTRA_TOKEN)),
                    expiresAtUnix,
                ),
            )
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
        val credential = BackgroundCredentialStore.load(applicationContext)
        intent.resultReceiver()?.send(
            SERVICE_RESULT_OK,
            Bundle().apply {
                putBoolean(EXTRA_CONFIGURED, credential != null)
                credential?.let {
                    putString(EXTRA_DEVICE_ID, it.deviceId)
                    putLong(EXTRA_EXPIRES_AT_UNIX, it.expiresAtUnix)
                }
            },
        )
        stopIfIdle()
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
        intent.resultReceiver()?.send(
            SERVICE_RESULT_OK,
            Bundle().apply {
                putBoolean(
                    EXTRA_CHANGED,
                    QuickTunnelController.takeStateChange(applicationContext),
                )
            },
        )
        stopIfIdle()
    }

    private fun handleAcknowledgeStateChange(intent: Intent) {
        if (QuickTunnelController.acknowledgeStateChange(applicationContext)) {
            intent.resultReceiver().sendSuccess()
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
        super.onTaskRemoved(rootIntent)
    }

    override fun onDestroy() {
        cancelRestoreRetry()
        runCatching { AutomaticDiagnostics.onTunnelStopped(applicationContext) }
            .onFailure { TunnelLog.warning("diagnostics.lifecycle_failed", error = it) }
        activeService = null
        TunnelRuntime.serviceDestroyed()
        AndroidSplitTunnel.clear()
        TunnelLog.info("service.destroyed")
        super.onDestroy()
        serviceReady = CompletableFuture()
    }

    private fun performBackgroundToggle() {
        val targetActive = !QuickTunnelController.desiredActive(applicationContext)
        QuickTunnelController.updateState(
            applicationContext,
            if (targetActive) SessionState.STARTING else SessionState.STOPPING,
            desiredActive = targetActive,
        )
        if (targetActive) {
            performBackgroundStart(restoring = false)
        } else {
            TunnelRuntime.backgroundStop(
                applicationContext,
                onSuccess = { state, _ -> completeBackgroundAction(state, null, false) },
                onError = { completeBackgroundAction(TunnelRuntime.state(), it, false) },
            )
        }
    }

    private fun performBackgroundStart(restoring: Boolean) {
        TunnelRuntime.backgroundStart(
            applicationContext,
            onSuccess = { state, _ -> completeBackgroundAction(state, null, restoring) },
            onError = { completeBackgroundAction(TunnelRuntime.state(), it, restoring) },
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
            stopForegroundService()
        }
    }

    private fun completeBackgroundAction(
        state: SessionState,
        errorCode: String?,
        restoring: Boolean,
    ) {
        if (errorCode == "tunnel_operation_in_progress") {
            TunnelLog.info("quick_toggle.duplicate_ignored")
            TunnelPlugin.refreshQuickTile(applicationContext)
            return
        }
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
            return
        }
        cancelRestoreRetry()
        QuickTunnelController.updateState(
            applicationContext,
            state,
            desiredActive = state == SessionState.RUNNING,
            changed = true,
        )
        TunnelPlugin.refreshQuickTile(applicationContext)
        errorCode?.let { code ->
            TunnelLog.warning("quick_toggle.failed", code)
            if (state != SessionState.RUNNING) {
                stopForegroundService()
            }
            android.os.Handler(mainLooper).post {
                Toast.makeText(applicationContext, quickActionError(code), Toast.LENGTH_LONG).show()
            }
        }
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
        internal const val ACTION_CLIENT_STOP = "ru.nelomai.tunnel.CLIENT_STOP"
        internal const val ACTION_CLIENT_STATUS = "ru.nelomai.tunnel.CLIENT_STATUS"
        internal const val ACTION_CLIENT_METRICS = "ru.nelomai.tunnel.CLIENT_METRICS"
        internal const val ACTION_CONFIGURE_BACKGROUND = "ru.nelomai.tunnel.CONFIGURE_BACKGROUND"
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
