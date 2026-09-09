package ru.nelomai.tunnel

import android.content.Context
import android.net.VpnService
import org.amnezia.awg.backend.GoBackend
import org.amnezia.awg.backend.Tunnel
import org.amnezia.awg.config.Config
import org.amnezia.awg.util.SharedLibraryLoader
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config as RoboConfig
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements
import org.robolectric.util.ReflectionHelpers
import ru.nelomai.runtime.v1.RuntimeVpnHostV1

@RunWith(RobolectricTestRunner::class)
@RoboConfig(sdk = [34], manifest = RoboConfig.NONE,
    shadows = [NoNativeLibrary::class, NativeStopRecorder::class])
class BackendStopLifecycleTest {
    @Test fun wireguardDownKeepsHostUntilOwnerFinishes() = verifyStop(false)
    @Test fun awgDownKeepsHostUntilOwnerFinishes() = verifyStop(true)

    private fun verifyStop(awg: Boolean) {
        val controller = Robolectric.buildService(VpnService::class.java).create()
        val host = controller.get()
        val engine = NelomaiVpnService(object : RuntimeVpnHostV1 {
            override val service = host
            override fun builder(beforeEstablish: (VpnService.Builder) -> Unit) = host.Builder()
        })
        // Install the real engine into the backend's service rendezvous without
        // starting unrelated auth/network jobs. Only JNI is substituted below.
        val previous = ReflectionHelpers.getStaticField<Any>(GoBackend::class.java, "vpnService")
        val future = previous.javaClass.getDeclaredConstructor().apply { isAccessible = true }.newInstance()
        ReflectionHelpers.setStaticField(GoBackend::class.java, "vpnService", future)
        future.javaClass.getDeclaredMethod("complete", Any::class.java).apply {
            isAccessible = true
        }.invoke(future, engine)
        val backend = GoBackend(host)
        val notifications = mutableListOf<Tunnel.State>()
        val tunnel = object : Tunnel {
            override fun getName() = "lifecycle-test"
            override fun onStateChange(state: Tunnel.State) { notifications += state }
        }
        val key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        val config = Config.parse(("[Interface]\nPrivateKey = $key\n" +
            if (awg) "HeaderProtectionKey = $key\n" else "").byteInputStream())
        assertEquals(awg, config.getInterface().headerProtectionKey.isPresent)
        ReflectionHelpers.setField(backend, "currentTunnel", tunnel)
        ReflectionHelpers.setField(backend, "currentTunnelHandle", 41)
        ReflectionHelpers.setField(backend, "currentConfig", config)
        NativeStopRecorder.stopped.clear()

        try {
            assertEquals(Tunnel.State.DOWN, backend.setState(tunnel, Tunnel.State.DOWN, null))
            assertEquals(listOf(41), NativeStopRecorder.stopped)
            assertEquals(listOf(Tunnel.State.DOWN), notifications)
            assertFalse("backend DOWN must not destroy the coordinator's host", shadowOf(host).isStoppedBySelf)
            // Explicit lifecycle ownership must still work; no global stopSelf no-op.
            engine.stopSelf()
            assertTrue(shadowOf(host).isStoppedBySelf)
        } finally {
            ReflectionHelpers.setStaticField(GoBackend::class.java, "vpnService", previous)
            controller.destroy()
        }
    }
}

@Implements(SharedLibraryLoader::class)
class NoNativeLibrary {
    companion object {
        @JvmStatic @Implementation fun loadSharedLibrary(context: Context, name: String) = Unit
    }
}

@Implements(org.amnezia.awg.GoBackend::class)
class NativeStopRecorder {
    companion object {
        val stopped = mutableListOf<Int>()
        @JvmStatic @Implementation fun awgTurnOff(handle: Int) { stopped += handle }
    }
}
