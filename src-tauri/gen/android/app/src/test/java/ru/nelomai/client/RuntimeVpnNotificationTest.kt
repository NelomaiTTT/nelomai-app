package ru.nelomai.client

import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.ResultReceiver
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements
import org.robolectric.shadows.ShadowVpnService

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class RuntimeVpnNotificationTest {
    @Before fun grantVpnPermission() {
        ShadowVpnService.setPrepareResult(null)
    }

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

    @Test fun revokedPermissionRejectsForegroundStartWithoutNotificationOrRetry() {
        ShadowVpnService.setPrepareResult(Intent("android.net.VpnService"))
        val reply = CapturingReceiver()
        val controller = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        val service = controller.get()

        val result = service.onStartCommand(
            foregroundIntent("ru.nelomai.tunnel.BEGIN_CONNECTION_INTENT", reply),
            0,
            3,
        )
        shadowOf(Looper.getMainLooper()).idle()

        assertEquals(Service.START_NOT_STICKY, result)
        assertEquals(2, reply.resultCode)
        assertEquals("vpn_permission_required", reply.resultData?.getString("error_code"))
        assertEquals(0, service.getSystemService(NotificationManager::class.java).activeNotifications.size)
        assertEquals(3, shadowOf(service).stopSelfId)
        controller.destroy()
    }

    @Test fun revokedPermissionMakesNullRestartNonSticky() {
        ShadowVpnService.setPrepareResult(Intent("android.net.VpnService"))
        val controller = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        val service = controller.get()

        val result = service.onStartCommand(null, 0, 4)

        assertEquals(Service.START_NOT_STICKY, result)
        assertEquals(0, service.getSystemService(NotificationManager::class.java).activeNotifications.size)
        assertEquals(4, shadowOf(service).stopSelfId)
        controller.destroy()
    }

    @Test fun revokedPermissionDoesNotBlockStatusOrStop() {
        ShadowVpnService.setPrepareResult(Intent("android.net.VpnService"))
        for (action in listOf(
            "ru.nelomai.tunnel.CONNECTION_INTENT_STATUS",
            "ru.nelomai.tunnel.CLIENT_STOP",
        )) {
            val controller = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
            val service = controller.get()

            assertEquals(Service.START_STICKY, service.onStartCommand(Intent(action), 0, 5))
            assertEquals(0, service.getSystemService(NotificationManager::class.java).activeNotifications.size)
            controller.destroy()
        }
    }

    private fun foregroundIntent(action: String, receiver: ResultReceiver) = Intent(action)
        .putExtra("ru.nelomai.runtime.v1.FOREGROUND_START", true)
        .putExtra("result_receiver", receiver)
}

private class CapturingReceiver : ResultReceiver(Handler(Looper.getMainLooper())) {
    var resultCode: Int? = null
    var resultData: Bundle? = null

    override fun onReceiveResult(resultCode: Int, resultData: Bundle?) {
        this.resultCode = resultCode
        this.resultData = resultData
    }
}

@RunWith(RobolectricTestRunner::class)
@Config(
    sdk = [34],
    application = android.app.Application::class,
    shadows = [SecurityExceptionRuntimeVpnDispatcherShadow::class],
)
class RuntimeVpnForegroundSecurityExceptionTest {
    @Test fun foregroundSecurityExceptionReturnsSafeErrorWithoutRetry() {
        ShadowVpnService.setPrepareResult(null)
        val reply = CapturingReceiver()
        val controller = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        val service = controller.get()

        val result = service.onStartCommand(
            Intent("ru.nelomai.tunnel.BEGIN_CONNECTION_INTENT")
                .putExtra("ru.nelomai.runtime.v1.FOREGROUND_START", true)
                .putExtra("result_receiver", reply),
            0,
            6,
        )
        shadowOf(Looper.getMainLooper()).idle()

        assertEquals(Service.START_NOT_STICKY, result)
        assertEquals(2, reply.resultCode)
        assertEquals("vpn_permission_required", reply.resultData?.getString("error_code"))
        assertEquals(6, shadowOf(service).stopSelfId)
        controller.destroy()
    }
}

@Implements(RuntimeVpnDispatcherService::class)
class SecurityExceptionRuntimeVpnDispatcherShadow : ShadowVpnService() {
    @Implementation
    override fun startForeground(id: Int, notification: android.app.Notification, foregroundServiceType: Int) {
        throw SecurityException("vpn app-op revoked")
    }
}
