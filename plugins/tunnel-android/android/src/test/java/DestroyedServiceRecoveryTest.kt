package ru.nelomai.tunnel

import android.net.VpnService
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.LooperMode
import org.robolectric.util.ReflectionHelpers
import ru.nelomai.runtime.v1.RuntimeServiceIntents
import ru.nelomai.runtime.v1.RuntimeVpnHostV1

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE, shadows = [NoNativeLibrary::class])
@LooperMode(LooperMode.Mode.PAUSED)
class DestroyedServiceRecoveryTest {
    @Test fun stoppedRecoveryUsesOrdinaryServiceWithoutVpnAdmission() = withEngine(stopped = true) { engine, store ->
        val before = store.read()
        engine.onDestroy()
        val request = requireNotNull(nextStart())
        assertEquals(NelomaiVpnService.ACTION_ENSURE_RUNNING, request.action)
        assertEquals(RuntimeServiceIntents.VPN_COMPONENT, request.component?.className)
        assertFalse("cleanup must not start a foreground VPN", request.getBooleanExtra(RuntimeServiceIntents.EXTRA_FOREGROUND_START, false))
        assertFalse("cleanup must remain admitted without VPN permission", requiresVpnStartAdmission(engine.applicationContext, request))
        assertEquals("handoff must retain durable cleanup", before, store.read())
        assertNull(nextStart())
    }

    @Test fun activeRecoveryStillRequestsForegroundVpnAdmission() = withEngine(stopped = false) { engine, store ->
        val before = store.read()
        engine.onDestroy()
        val request = requireNotNull(nextStart())
        assertEquals(NelomaiVpnService.ACTION_ENSURE_RUNNING, request.action)
        assertTrue(request.getBooleanExtra(RuntimeServiceIntents.EXTRA_FOREGROUND_START, false))
        assertTrue(requiresVpnStartAdmission(engine.applicationContext, request))
        assertEquals(before, store.read())
        assertNull(nextStart())
    }

    @Test fun unreadableRecoveryCannotBypassStartAdmission() = withEngine(stopped = true) { engine, store ->
        ReflectionHelpers.getField<MemoryBackend>(store, "backend").readFails = true
        val request = RuntimeServiceIntents.vpn(engine.applicationContext)
            .setAction(NelomaiVpnService.ACTION_ENSURE_RUNNING)
        assertTrue(requiresVpnStartAdmission(engine.applicationContext, request))
    }

    private fun nextStart() = shadowOf(RuntimeEnvironment.getApplication()).nextStartedService

    private fun withEngine(stopped: Boolean, test: (NelomaiVpnService, AndroidRecoveryStore) -> Unit) {
        val store = AndroidRecoveryStore(MemoryBackend(), BootIdentityProvider { 7 })
        val coordinator = AndroidConnectionIntentCoordinator(store)
        assertTrue(coordinator.begin(AndroidIntentTemplate(
            deviceId = "11111111-1111-4111-8111-111111111111", accountScope = "account",
            layer = "stray", ticConnectionMode = "dynamic", routeMode = "standalone",
            egressMode = "ipv4", allowAlternate = true,
        )) is AndroidCoordinatorResult.Accepted)
        if (stopped) coordinator.cancelCurrent()
        val oldStore = ReflectionHelpers.getField<AndroidRecoveryStore?>(AndroidRecoveryStores, "instance")
        val oldCredentials = ReflectionHelpers.getField<BackgroundCredentialStore?>(AndroidBackgroundCredentialStores, "instance")
        val oldOwner = ReflectionHelpers.getStaticField<Any?>(NelomaiVpnService::class.java, "activeService")
        ReflectionHelpers.setField(AndroidRecoveryStores, "instance", store)
        ReflectionHelpers.setField(AndroidBackgroundCredentialStores, "instance", BackgroundCredentialStore(MemoryBackend()))
        val hostController = Robolectric.buildService(VpnService::class.java).create()
        val host = hostController.get()
        fun engine() = NelomaiVpnService(object : RuntimeVpnHostV1 {
            override val service = host
            override fun builder(beforeEstablish: (VpnService.Builder) -> Unit) = host.Builder()
        })
        val engine = engine()
        engine.onCreate()
        try {
            test(engine, store)
        } finally {
            if (!ReflectionHelpers.getField<Boolean>(engine, "serviceDestroyed")) engine.onDestroy()
            ReflectionHelpers.setField(AndroidRecoveryStores, "instance", oldStore)
            ReflectionHelpers.setField(AndroidBackgroundCredentialStores, "instance", oldCredentials)
            ReflectionHelpers.setStaticField(NelomaiVpnService::class.java, "activeService", oldOwner)
            hostController.destroy()
        }
    }

    private class MemoryBackend : EncryptedRecordBackend {
        private var record: ByteArray? = null
        var readFails = false
        override fun read(): ByteArray? {
            check(!readFails) { "test recovery read failure" }
            return record?.copyOf()
        }
        override fun write(plaintext: ByteArray): Boolean { record = plaintext.copyOf(); return true }
    }
}
