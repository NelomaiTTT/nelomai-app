package ru.nelomai.tunnel

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
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
                    AndroidSplitTunnel.currentExcludedRoutes().forEach(::excludeRoute)
                }
                return super.establish()
            }
        }

    override fun onCreate() {
        super.onCreate()
        TunnelLog.initialize(applicationContext)
        TunnelRuntime.initialize(applicationContext)
        activeService = this
        serviceReady.complete(Unit)
        TunnelLog.info("service.created")
        restoreDesiredTunnel("process_created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        promoteToForeground()
        when {
            intent?.action == ACTION_QUICK_TOGGLE -> {
                cancelRestoreRetry()
                performBackgroundToggle()
            }
            intent?.action == ACTION_ENSURE_RUNNING -> {
                restoreDesiredTunnel("ensure_running")
            }
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

    override fun onRevoke() {
        TunnelLog.warning("service.vpn_revoked")
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
        activeService = null
        TunnelRuntime.serviceDestroyed()
        AndroidSplitTunnel.clear()
        TunnelLog.info("service.destroyed")
        super.onDestroy()
        serviceReady = CompletableFuture()
    }

    private fun performBackgroundToggle() {
        if (QuickTunnelController.desiredActive(applicationContext)) {
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
        private const val ACTION_QUICK_TOGGLE = "ru.nelomai.tunnel.QUICK_TOGGLE"
        private const val ACTION_ENSURE_RUNNING = "ru.nelomai.tunnel.ENSURE_RUNNING"
        private val RESTORE_RETRY_DELAYS_MILLIS = longArrayOf(
            5_000L,
            30_000L,
            120_000L,
            300_000L,
        )

        fun ensureStarted(context: Context): CompletableFuture<Unit> {
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
