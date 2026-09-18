package ru.nelomai.tunnel

import android.app.Notification
import android.content.Intent
import android.net.VpnService
import android.os.Looper
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements
import org.robolectric.shadows.ShadowVpnService
import org.robolectric.util.ReflectionHelpers
import ru.nelomai.runtime.v1.RuntimeVpnHostV1

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE, shadows = [QueuedStartService::class])
class ForegroundStopRaceTest {
    @Test fun acceptedButUndeliveredStartPreventsOldOwnerTeardown() = verifyStop(2, false)
    @Test fun lastDeliveredStartCanFinishAndRemoveForeground() = verifyStop(1, true)
    @Test fun queuedWorkerFinishDoesNotStopNewlyDeliveredCommand() = verifyStop(2, false, true)

    private fun verifyStop(acceptedStartId: Int, shouldStop: Boolean, deliverWhileFinishQueued: Boolean = false) {
        val controller = Robolectric.buildService(VpnService::class.java).create()
        val host = controller.get()
        val engine = NelomaiVpnService(object : RuntimeVpnHostV1 {
            override val service = host
            override fun builder(beforeEstablish: (VpnService.Builder) -> Unit) = host.Builder()
        })
        val previous = ReflectionHelpers.getStaticField<Any?>(NelomaiVpnService::class.java, "activeService")
        ReflectionHelpers.setStaticField(NelomaiVpnService::class.java, "activeService", engine)
        try {
            // Deliver a no-op command through the real engine. The next start
            // may already be accepted by AMS but not delivered to this process.
            engine.onStartCommand(Intent("test.noop"), 0, 1)
            host.startForeground(21, Notification.Builder(host).setContentTitle("VPN").build())
            val framework = shadowOf(host) as QueuedStartService
            framework.acceptedStartId = acceptedStartId

            if (deliverWhileFinishQueued) {
                Thread { NelomaiVpnService.stopForegroundService() }.apply { start(); join() }
                engine.onStartCommand(Intent("test.noop"), 0, 2)
                shadowOf(Looper.getMainLooper()).idle()
            } else {
                NelomaiVpnService.stopForegroundService()
            }

            assertEquals("finish must be conditional on the handled start ID",
                if (deliverWhileFinishQueued) emptyList<Int>() else listOf(1), framework.stopRequests)
            assertEquals(shouldStop, framework.isStoppedBySelf)
            assertEquals("a pending start must retain foreground ownership", shouldStop, framework.isForegroundStopped)
        } finally {
            ReflectionHelpers.setStaticField(NelomaiVpnService::class.java, "activeService", previous)
            controller.destroy()
        }
    }
}

/** Models only AMS's accepted-start-ID fence (not provided by ShadowService).
 * The engine, command delivery and foreground lifecycle remain real. */
@Implements(VpnService::class)
class QueuedStartService : ShadowVpnService() {
    var acceptedStartId = 1
    val stopRequests = mutableListOf<Int>()
    @Implementation public override fun stopSelfResult(startId: Int): Boolean {
        stopRequests += startId
        if (startId != acceptedStartId) return false
        return super.stopSelfResult(startId)
    }
}
