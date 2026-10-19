package ru.nelomai.tunnel

import org.amnezia.awg.backend.GoBackend
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements
import java.lang.reflect.InvocationTargetException

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], manifest = Config.NONE, shadows = [LegacyNativeShadow::class, LegacyProtectShadow::class])
class LegacySocketAdmissionTest {
    @Before fun reset() { LegacyNativeShadow.events.clear(); LegacyNativeShadow.token = 7; LegacyNativeShadow.admitResult = 0; LegacyProtectShadow.failFd = -1; LegacyProtectShadow.throwFd = -1 }
    private fun protect() {
        val method = GoBackend::class.java.getDeclaredMethod("protectAndAdmitSockets", GoBackend.VpnService::class.java, Int::class.javaPrimitiveType)
        method.isAccessible = true
        method.invoke(null, GoBackend.VpnService(android.net.VpnService()), 42)
    }
    @Test fun admitsOnlyAfterBothSocketsAreProtected() {
        protect()
        assertEquals(listOf("token", "protect:101", "protect:102", "admit:7"), LegacyNativeShadow.events)
    }
    @Test fun protectionFailureClosesWithoutAdmission() {
        LegacyProtectShadow.failFd = 102
        assertThrows(InvocationTargetException::class.java) { protect() }
        assertEquals(listOf("token", "protect:101", "protect:102", "close"), LegacyNativeShadow.events)
    }
    @Test fun protectionExceptionClosesWithoutAdmission() {
        LegacyProtectShadow.throwFd = 101
        assertThrows(InvocationTargetException::class.java) { protect() }
        assertEquals(listOf("token", "protect:101", "close"), LegacyNativeShadow.events)
    }
    @Test fun staleGenerationClosesSockets() {
        LegacyNativeShadow.admitResult = -1
        assertThrows(InvocationTargetException::class.java) { protect() }
        assertEquals("close", LegacyNativeShadow.events.last())
    }
    @Test fun missingPreparationNeverAdmits() {
        LegacyNativeShadow.token = -1
        assertThrows(InvocationTargetException::class.java) { protect() }
        assertEquals(listOf("token", "close"), LegacyNativeShadow.events)
    }
}

@Implements(value = org.amnezia.awg.GoBackend::class, isInAndroidSdk = false)
class LegacyNativeShadow {
    companion object {
        val events = mutableListOf<String>()
        var token = 7L
        var admitResult = 0
        @JvmStatic @Implementation fun awgPreparedSocketToken(handle: Int): Long { events += "token"; return token }
        @JvmStatic @Implementation fun awgGetSocketV4(handle: Int) = 101
        @JvmStatic @Implementation fun awgGetSocketV6(handle: Int) = 102
        @JvmStatic @Implementation fun awgAdmitSockets(handle: Int, generation: Long): Int { events += "admit:$generation"; return admitResult }
        @JvmStatic @Implementation fun awgCloseUdp(handle: Int): Int { events += "close"; return 0 }
    }
}

@Implements(android.net.VpnService::class)
class LegacyProtectShadow {
    companion object { var failFd = -1; var throwFd = -1 }
    @Implementation fun protect(fd: Int): Boolean {
        LegacyNativeShadow.events += "protect:$fd"
        if (fd == throwFd) throw IllegalStateException("test protection failure")
        return fd != failFd
    }
}
