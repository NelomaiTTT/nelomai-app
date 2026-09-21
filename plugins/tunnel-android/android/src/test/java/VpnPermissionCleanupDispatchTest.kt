package ru.nelomai.tunnel

import android.app.Application
import android.app.Notification
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.Looper
import android.os.ResultReceiver
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements
import org.robolectric.shadows.ShadowVpnService
import org.robolectric.util.ReflectionHelpers
import ru.nelomai.runtime.v1.RuntimeServiceIntents
import ru.nelomai.runtime.v1.RuntimeVpnHostV1

@RunWith(RobolectricTestRunner::class)
@Config(
    sdk = [34],
    application = Application::class,
    manifest = Config.NONE,
    shadows = [DeniedCleanupForegroundVpnService::class, NoNativeLibrary::class],
)
class VpnPermissionCleanupDispatchTest {
    private lateinit var context: Application

    @Before
    fun setUp() {
        context = RuntimeEnvironment.getApplication()
        val store = AndroidRecoveryStore(InMemoryRecoveryBackend(), BootIdentityProvider { 1 })
        val current = (store.read() as RecoveryStoreResult.Success).value
        assertTrue(
            store.setDesiredActive(current.intent.generation, true) is RecoveryStoreResult.Success,
        )
        ReflectionHelpers.setField(AndroidRecoveryStores, "instance", store)
    }

    @Test
    fun quickToggleStopUsesOrdinaryServiceDispatch() {
        TunnelServiceClient.toggleConnectionIntent(context, {}, {})

        val intent = shadowOf(context).nextStartedService
        assertEquals(NelomaiVpnService.ACTION_QUICK_TOGGLE, intent.action)
        assertFalse(intent.getBooleanExtra(RuntimeServiceIntents.EXTRA_FOREGROUND_START, false))
    }

    @Test
    fun quickTileStopUsesOrdinaryServiceDispatch() {
        NelomaiVpnService.requestToggle(context)

        val intent = shadowOf(context).nextStartedService
        assertEquals(NelomaiVpnService.ACTION_QUICK_TOGGLE, intent.action)
        assertFalse(intent.getBooleanExtra(RuntimeServiceIntents.EXTRA_FOREGROUND_START, false))
    }

    @Test
    fun backgroundLogoutUsesOrdinaryServiceDispatch() {
        TunnelServiceClient.beginBackgroundLogout(context, 1, {}, {})

        val intent = shadowOf(context).nextStartedService
        assertEquals(NelomaiVpnService.ACTION_BEGIN_BACKGROUND_LOGOUT, intent.action)
        assertFalse(intent.getBooleanExtra(RuntimeServiceIntents.EXTRA_FOREGROUND_START, false))
    }

    @Test
    fun bothReservePreferencesUseExistingNonStartingServiceCommand() {
        for (enabled in listOf(false, true)) {
            TunnelServiceClient.releaseRedundantStandby(context, {}, {}, reservePreference = enabled)
            val intent = shadowOf(context).nextStartedService
            assertEquals(NelomaiVpnService.ACTION_RELEASE_REDUNDANT_STANDBY, intent.action)
            assertTrue(intent.hasExtra(EXTRA_RESERVE_PREFERENCE))
            assertEquals(enabled, intent.getBooleanExtra(EXTRA_RESERVE_PREFERENCE, !enabled))
            assertFalse(intent.getBooleanExtra(RuntimeServiceIntents.EXTRA_FOREGROUND_START, false))
            assertFalse(requiresVpnStartAdmission(context, intent))
        }
    }

    @Test
    fun quickToggleStopRunsThroughEngineWithoutForegroundPermission() {
        val reply = AwaitingReceiver()
        withEngine { engine ->
            val result = engine.start(
                Intent(NelomaiVpnService.ACTION_QUICK_TOGGLE)
                    .putExtra(EXTRA_RESULT_RECEIVER, reply),
                0,
                1,
            )

            assertEquals(android.app.Service.START_STICKY, result)
            assertTrue(reply.await())
            assertEquals(SERVICE_RESULT_OK, reply.resultCode)
            assertNotNull(reply.resultData)
        }
    }

    @Test
    fun startCommandStillRequiresSuccessfulForegroundPromotion() {
        withEngine { engine ->
            assertThrows(SecurityException::class.java) {
                engine.start(
                    Intent(NelomaiVpnService.ACTION_BEGIN_CONNECTION_INTENT),
                    0,
                    2,
                )
            }
        }
    }

    private fun withEngine(block: (LatestRuntimeVpnEngineV1) -> Unit) {
        val controller = Robolectric.buildService(VpnService::class.java).create()
        val host = controller.get()
        val engine = LatestRuntimeVpnEngineV1(object : RuntimeVpnHostV1 {
            override val service = host
            override fun builder(beforeEstablish: (VpnService.Builder) -> Unit) = host.Builder()
        })
        engine.create()
        try {
            block(engine)
        } finally {
            engine.destroy()
            controller.destroy()
        }
    }
}

private class AwaitingReceiver : ResultReceiver(null) {
    private val received = CountDownLatch(1)
    var resultCode: Int? = null
        private set
    var resultData: Bundle? = null
        private set

    override fun onReceiveResult(resultCode: Int, resultData: Bundle?) {
        this.resultCode = resultCode
        this.resultData = resultData
        received.countDown()
    }

    fun await(): Boolean {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
        do {
            // The engine posts the durable worker result back to Android's
            // main looper; Robolectric does not advance that queue while waiting.
            shadowOf(Looper.getMainLooper()).idle()
            if (received.await(10, TimeUnit.MILLISECONDS)) return true
        } while (System.nanoTime() < deadline)
        return false
    }
}

@Implements(VpnService::class)
class DeniedCleanupForegroundVpnService : ShadowVpnService() {
    @Implementation
    override fun startForeground(id: Int, notification: Notification, foregroundServiceType: Int) {
        throw SecurityException("vpn app-op revoked")
    }
}

private class InMemoryRecoveryBackend : EncryptedRecordBackend {
    private var value: ByteArray? = null
    override fun read(): ByteArray? = value?.copyOf()
    override fun write(plaintext: ByteArray): Boolean {
        value = plaintext.copyOf()
        return true
    }
}
