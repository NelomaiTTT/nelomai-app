package ru.nelomai.tunnel

import android.content.Context
import android.net.VpnService
import android.os.ParcelFileDescriptor
import org.amnezia.awg.backend.GoBackend
import org.amnezia.awg.backend.Tunnel
import org.amnezia.awg.config.Config
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config as RoboConfig
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements
import org.robolectric.annotation.RealObject
import org.robolectric.shadows.ShadowParcelFileDescriptor
import org.robolectric.util.ReflectionHelpers
import java.io.File
import java.io.IOException
import java.util.IdentityHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Real GoBackend lifecycle and Android descriptor API; VPN establishment/JNI are substitutes. */
@RunWith(RobolectricTestRunner::class)
@RoboConfig(sdk = [34], manifest = RoboConfig.NONE, shadows = [NoNativeLibrary::class,
    OwnershipNative::class, OwnershipVpn::class, OwnershipBuilder::class, OwnershipDescriptor::class])
class BackendTunOwnershipTest {
    @Test fun defaultBackendDoesNotRetainTunAfterNativeCloses() = withBackend(::GoBackend) { f ->
        f.start()
        assertNull(duplicate(f.backend))
        OwnershipNative.engineDescriptors.values.toList().forEach { it.close() }
        OwnershipNative.engineDescriptors.clear()
        assertTrue("no requested retention may survive native close",
            OwnershipDescriptor.files.keys.none { it.fileDescriptor.valid() })
    }

    @Test fun defaultStartDoesNotRequireRetentionDuplication() = withBackend(::GoBackend) { f ->
        OwnershipDescriptor.failDup = true
        f.start()
        assertEquals(Tunnel.State.UP, f.backend.getState(f.tunnel))
        assertNull(OwnershipDescriptor.controlCopy)
    }

    @Test fun wireguardRetainedCopySurvivesNativeDown() = retainedCopySurvivesDown(false)
    @Test fun awgRetainedCopySurvivesNativeDown() = retainedCopySurvivesDown(true)

    private fun retainedCopySurvivesDown(awg: Boolean) = withBackend { f ->
        assertNull(duplicate(f.backend))
        f.start(awg)
        val retained = requireNotNull(duplicate(f.backend))
        try {
            f.stop()
            assertNull(duplicate(f.backend))
            assertTrue("owner's duplicate must outlive native close", retained.fileDescriptor.valid())
            assertEquals("tun", ParcelFileDescriptor.AutoCloseInputStream(retained).bufferedReader().readText())
            assertTrue(OwnershipNative.engineDescriptors.isEmpty())
        } finally { retained.close() }
    }

    @Test fun nativeStartFailureDoesNotLeaveOwnedTun() = withBackend { f ->
        OwnershipNative.failStart = true
        assertThrows(Exception::class.java) { f.start() }
        assertNull(duplicate(f.backend))
        assertFalse(OwnershipDescriptor.controlCopy!!.fileDescriptor.valid())
        assertTrue(OwnershipNative.engineDescriptors.isEmpty())
    }

    @Test fun socketAdmissionFailureDoesNotLeaveOwnedTun() = withBackend { f ->
        OwnershipVpn.protectSucceeds = false
        assertThrows(Exception::class.java) { f.start() }
        assertNull(duplicate(f.backend))
        assertFalse(OwnershipDescriptor.controlCopy!!.fileDescriptor.valid())
        assertTrue(OwnershipNative.engineDescriptors.isEmpty())
    }

    @Test fun captureFailureNeverTransfersDescriptorToNative() = withBackend { f ->
        OwnershipDescriptor.failDup = true
        assertThrows(Exception::class.java) { f.start() }
        assertEquals(0, OwnershipNative.starts)
        assertNull(duplicate(f.backend))
        assertFalse(OwnershipBuilder.established!!.fileDescriptor.valid())
    }

    @Test fun healthyDuplicationFailureLeavesTransportUsable() = withBackend { f ->
        f.start()
        OwnershipDescriptor.failDup = true
        assertThrows(IOException::class.java) { duplicate(f.backend) }
        assertEquals(Tunnel.State.UP, f.backend.getState(f.tunnel))
        assertEquals(1, OwnershipNative.engineDescriptors.size)
        requireNotNull(duplicate(f.backend)).close()
    }

    @Test fun backendDownReleasesItsCopyWithoutStoppingIndependentOwner() = withBackend { f ->
        f.start()
        val control = requireNotNull(OwnershipDescriptor.controlCopy)
        f.stop()
        f.stop()
        assertFalse(control.fileDescriptor.valid())
        assertNull(duplicate(f.backend))
        assertTrue(OwnershipNative.engineDescriptors.isEmpty())
    }

    @Test fun destroyReleasesBackendCopyButNotIndependentOwnerCopy() = withBackend { f ->
        f.start()
        val retained = requireNotNull(duplicate(f.backend))
        val control = requireNotNull(OwnershipDescriptor.controlCopy)
        try {
            f.engine.onDestroy()
            assertFalse(control.fileDescriptor.valid())
            assertTrue(retained.fileDescriptor.valid())
            assertNull(duplicate(f.backend))
            assertTrue(OwnershipNative.engineDescriptors.isEmpty())
        } finally { retained.close() }
    }

    @Test fun restartDoesNotTakeOwnershipOfPreviouslyRetainedCopy() = withBackend { f ->
        f.start()
        val retained = requireNotNull(duplicate(f.backend))
        try {
            f.stop()
            f.start()
            requireNotNull(duplicate(f.backend)).close()
            f.stop()
            assertTrue(retained.fileDescriptor.valid())
            assertNull(duplicate(f.backend))
        } finally { retained.close() }
    }

    @Test fun noDescriptorIsPublishedUntilSocketsAreAdmitted() = withBackend { f ->
        OwnershipNative.beforeAdmission = { assertNull(duplicate(f.backend)) }
        f.start()
        requireNotNull(duplicate(f.backend)).close()
    }

    @Test fun lateDuplicateIsRejectedWhileNativeStopIsStillPending() = withBackend { f ->
        f.start()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val executor = Executors.newSingleThreadExecutor()
        OwnershipNative.beforeStop = { entered.countDown(); check(release.await(2, TimeUnit.SECONDS)) }
        try {
            val stopped = executor.submit { f.stop() }
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            assertNull(duplicate(f.backend))
            release.countDown()
            stopped.get(2, TimeUnit.SECONDS)
            assertNull(duplicate(f.backend))
        } finally { release.countDown(); executor.shutdownNow() }
    }

    @Test fun repeatedStopRetriesTransientCloseFailureAndAllowsNextStart() = withBackend { f ->
        f.start()
        val control = requireNotNull(OwnershipDescriptor.controlCopy)
        OwnershipDescriptor.failControlClose = true
        assertThrows(IOException::class.java) { f.stop() }
        assertThrows(IOException::class.java) { duplicate(f.backend) }
        assertThrows(IOException::class.java) { f.start() }
        assertEquals(1, OwnershipNative.starts)
        f.stop()
        assertFalse(control.fileDescriptor.valid())
        assertNull(duplicate(f.backend))
        f.start()
        requireNotNull(duplicate(f.backend)).close()
    }

    @Test fun destroyRetriesTransientCloseFailure() = withBackend { f ->
        f.start()
        val control = requireNotNull(OwnershipDescriptor.controlCopy)
        OwnershipDescriptor.failControlClose = true
        assertThrows(IOException::class.java) { f.stop() }
        f.engine.onDestroy()
        assertFalse(control.fileDescriptor.valid())
        assertNull(duplicate(f.backend))
    }

    @Test fun persistentCloseFailureStillRejectsStartAndRetention() = withBackend { f ->
        f.start()
        val control = requireNotNull(OwnershipDescriptor.controlCopy)
        repeat(2) {
            OwnershipDescriptor.failControlClose = true
            assertThrows(IOException::class.java) { f.stop() }
            assertTrue(control.fileDescriptor.valid())
            assertThrows(IOException::class.java) { f.start() }
            assertThrows(IOException::class.java) { duplicate(f.backend) }
        }
        assertEquals(1, OwnershipNative.starts)
        f.stop()
        assertFalse(control.fileDescriptor.valid())
    }

    @Test fun returningFromCloseWithoutReleaseIsNotSuccessfulStop() = withBackend { f ->
        f.start()
        val control = requireNotNull(OwnershipDescriptor.controlCopy)
        OwnershipDescriptor.skipNextControlClose = true
        assertThrows(IOException::class.java) { f.stop() }
        assertTrue(control.fileDescriptor.valid())
        assertThrows(IOException::class.java) { f.start() }
        assertThrows(IOException::class.java) { duplicate(f.backend) }
        f.stop()
        assertFalse(control.fileDescriptor.valid())
    }

    @Test fun closeFailureAfterReleaseCanBeConfirmedByRepeatedStop() = withBackend { f ->
        f.start()
        val control = requireNotNull(OwnershipDescriptor.controlCopy)
        OwnershipDescriptor.failAfterControlClose = true
        assertThrows(IOException::class.java) { f.stop() }
        assertFalse(control.fileDescriptor.valid())
        f.stop()
        assertNull(duplicate(f.backend))
    }

    @Test fun destroyClosesControlDescriptorEvenWhenNativeStopThrows() = withBackend { f ->
        f.start()
        val control = requireNotNull(OwnershipDescriptor.controlCopy)
        OwnershipNative.beforeStop = { throw IllegalStateException("native stop fixture failure") }
        assertThrows(IllegalStateException::class.java) { f.engine.onDestroy() }
        assertFalse(control.fileDescriptor.valid())
    }

    private fun duplicate(backend: GoBackend): ParcelFileDescriptor? = backend.duplicateTun()

    private class Fixture(val backend: GoBackend, val engine: GoBackend.VpnService) {
        val tunnel = object : Tunnel {
            override fun getName() = "ownership-test"
            override fun onStateChange(state: Tunnel.State) = Unit
        }
        fun start(awg: Boolean = false) {
            val key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            val config = Config.parse(("[Interface]\nPrivateKey = $key\nAddress = 10.241.0.3/32\n" +
                if (awg) "HeaderProtectionKey = $key\n" else "").byteInputStream())
            backend.setState(tunnel, Tunnel.State.UP, config)
        }
        fun stop() { backend.setState(tunnel, Tunnel.State.DOWN, null) }
    }

    private fun withBackend(createBackend: (Context) -> GoBackend = { GoBackend(it, true) }, test: (Fixture) -> Unit) {
        OwnershipNative.reset(); OwnershipDescriptor.reset(); OwnershipVpn.protectSucceeds = true
        org.robolectric.shadows.ShadowVpnService.setPrepareResult(null)
        val controller = Robolectric.buildService(VpnService::class.java).create()
        val host = controller.get()
        val engine = object : GoBackend.VpnService(host) {
            override fun getBuilder() = host.Builder()
            override fun onTunnelDown() = Unit
        }
        val previous = ReflectionHelpers.getStaticField<Any>(GoBackend::class.java, "vpnService")
        val future = previous.javaClass.getDeclaredConstructor().apply { isAccessible = true }.newInstance()
        ReflectionHelpers.setStaticField(GoBackend::class.java, "vpnService", future)
        future.javaClass.getDeclaredMethod("complete", Any::class.java).apply { isAccessible = true }.invoke(future, engine)
        OwnershipBuilder.directory = host.cacheDir
        val fixture = Fixture(createBackend(host), engine)
        try { test(fixture) } finally {
            OwnershipDescriptor.failDup = false
            runCatching { fixture.stop() }
            runCatching { engine.onDestroy() }
            OwnershipDescriptor.controlCopy?.close()
            OwnershipNative.reset()
            ReflectionHelpers.setStaticField(GoBackend::class.java, "vpnService", previous)
            controller.destroy()
        }
    }
}

@Implements(org.amnezia.awg.GoBackend::class)
class OwnershipNative {
    companion object {
        val engineDescriptors = mutableMapOf<Int, ParcelFileDescriptor>()
        var starts = 0
        var failStart = false
        var beforeAdmission: () -> Unit = {}
        var beforeStop: () -> Unit = {}
        var statistics = "last_handshake_time_sec=1\n"
        fun reset() {
            engineDescriptors.values.forEach { it.close() }; engineDescriptors.clear()
            starts = 0; failStart = false; beforeAdmission = {}; beforeStop = {}
            statistics = "last_handshake_time_sec=1\n"
        }
        @JvmStatic @Implementation fun awgVersion() = "ownership-fixture"
        @JvmStatic @Implementation fun awgTurnOn(name: String, fd: Int, config: String): Int {
            starts++
            if (failStart) { engineDescriptors.remove(fd)!!.close(); return -1 }
            return fd
        }
        @JvmStatic @Implementation fun awgTurnOff(handle: Int) { beforeStop(); engineDescriptors.remove(handle)?.close() }
        @JvmStatic @Implementation fun awgPreparedSocketToken(handle: Int) = 1L
        @JvmStatic @Implementation fun awgAdmitSockets(handle: Int, token: Long): Int { beforeAdmission(); return 0 }
        @JvmStatic @Implementation fun awgGetSocketV4(handle: Int) = 101
        @JvmStatic @Implementation fun awgGetSocketV6(handle: Int) = -1
        @JvmStatic @Implementation fun awgGetConfig(handle: Int) = statistics
    }
}

@Implements(VpnService::class)
class OwnershipVpn : org.robolectric.shadows.ShadowVpnService() {
    @Implementation fun protect(socket: Int) = protectSucceeds
    @Implementation fun setUnderlyingNetworks(networks: Array<android.net.Network>?) = true
    companion object { var protectSucceeds = true }
}

@Implements(VpnService.Builder::class)
class OwnershipBuilder {
    @Implementation fun establish(): ParcelFileDescriptor {
        val file = File.createTempFile("tun-", ".fixture", directory).apply { writeText("tun") }
        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY).also {
            established = it; OwnershipDescriptor.files[it] = file
        }
    }
    companion object { lateinit var directory: File; var established: ParcelFileDescriptor? = null }
}

@Implements(ParcelFileDescriptor::class)
class OwnershipDescriptor : ShadowParcelFileDescriptor() {
    @RealObject private lateinit var real: ParcelFileDescriptor
    @Implementation override fun dup(): ParcelFileDescriptor {
        if (failDup) { failDup = false; throw IOException("dup fixture failure") }
        return duplicateFile().also { if (real === OwnershipBuilder.established) controlCopy = it }
    }
    @Implementation override fun close() {
        if (real === controlCopy && failControlClose) {
            failControlClose = false
            throw IOException("close fixture failure")
        }
        if (real === controlCopy && skipNextControlClose) {
            skipNextControlClose = false
            return
        }
        super.close()
        if (real === controlCopy && failAfterControlClose) {
            failAfterControlClose = false
            throw IOException("close fixture failure after release")
        }
    }
    // Robolectric's dup shares a Java FileDescriptor, unlike Android's dup(2).
    // Independent file opens model descriptor ownership only, not kernel TUN routing.
    private fun duplicateFile(): ParcelFileDescriptor {
        if (!real.fileDescriptor.valid()) throw IOException("closed fixture descriptor")
        val file = requireNotNull(files[real])
        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY).also { files[it] = file }
    }
    // Robolectric has no native detachFd; retain its file-backed descriptor for the JNI fixture.
    @Implementation fun detachFd(): Int {
        val engine = duplicateFile()
        real.close()
        val handle = 40 + OwnershipNative.starts
        OwnershipNative.engineDescriptors[handle] = engine
        return handle
    }
    companion object {
        @JvmStatic @Implementation fun fromFd(fd: Int): ParcelFileDescriptor =
            requireNotNull(OwnershipNative.engineDescriptors[fd]).dup()
        @JvmStatic @Implementation fun adoptFd(fd: Int): ParcelFileDescriptor =
            requireNotNull(OwnershipNative.engineDescriptors.remove(fd))

        var failDup = false
        var failControlClose = false
        var skipNextControlClose = false
        var failAfterControlClose = false
        var controlCopy: ParcelFileDescriptor? = null
        val files = IdentityHashMap<ParcelFileDescriptor, File>()
        fun reset() {
            failDup = false; failControlClose = false; skipNextControlClose = false; failAfterControlClose = false
            controlCopy = null; OwnershipBuilder.established = null; files.clear()
        }
    }
}
