package ru.nelomai.client

import android.app.NotificationManager
import android.content.Intent
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class RuntimeVpnNotificationTest {
    @Test fun foregroundRequestPromotesBeforeOwnerBindingCompletes() {
        val controller = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        val service = controller.get()
        val notifications = service.getSystemService(NotificationManager::class.java)
        assertEquals(0, notifications.activeNotifications.size)
        service.onStartCommand(Intent("ru.nelomai.tunnel.QUICK_TOGGLE")
            .putExtra("ru.nelomai.runtime.v1.FOREGROUND_START", true), 0, 1)
        assertEquals(1, notifications.activeNotifications.size)
        controller.destroy()
    }

    @Test fun statusPollingDoesNotShowVpnNotification() {
        repeat(3) {
            val controller = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
            val service = controller.get()
            service.onStartCommand(Intent("ru.nelomai.tunnel.CONNECTION_INTENT_STATUS"), 0, it + 1)
            assertEquals(0, service.getSystemService(NotificationManager::class.java).activeNotifications.size)
            controller.destroy()
        }
    }
}
