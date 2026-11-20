package ru.nelomai.runtime.v1

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build

object VpnNotificationChannel {
    const val ID = "nelomai-vpn"

    fun create(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        context.getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(ID, "VPN-подключение", NotificationManager.IMPORTANCE_LOW),
        )
    }
}
