package ru.nelomai.tunnel

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import com.wireguard.android.backend.GoBackend
import java.util.concurrent.CompletableFuture

class NelomaiVpnService : GoBackend.VpnService() {
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
        activeService = this
        serviceReady.complete(Unit)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
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
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        activeService = null
        TunnelRuntime.serviceDestroyed()
        AndroidSplitTunnel.clear()
        super.onDestroy()
        serviceReady = CompletableFuture()
    }

    companion object {
        @Volatile
        private var serviceReady = CompletableFuture<Unit>()

        @Volatile
        private var activeService: NelomaiVpnService? = null

        private const val NOTIFICATION_CHANNEL = "nelomai-vpn"
        private const val NOTIFICATION_ID = 21

        fun ensureStarted(context: Context): CompletableFuture<Unit> {
            ContextCompat.startForegroundService(
                context,
                Intent(context, NelomaiVpnService::class.java),
            )
            return serviceReady
        }

        fun stopForegroundService() {
            activeService?.run {
                ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
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
