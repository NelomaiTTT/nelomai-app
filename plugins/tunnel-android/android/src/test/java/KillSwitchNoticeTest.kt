package ru.nelomai.tunnel

import org.junit.Assert.*
import org.junit.Test

class KillSwitchNoticeTest {
    @Test fun continuousOutageUsesTwentySecondsAndDoesNotRepeatAcrossAttempts() {
        val notice = KillSwitchNotice()
        assertNull(notice.update("armed", null, 0))
        assertNull(notice.update("blocked", null, 100))
        assertEquals(20_000L, notice.remaining(100))
        assertNull(notice.update("blocked", "transport_error", 19_999))
        assertEquals("blocked", notice.update("blocked", "transport_error", 20_100))
        assertNull(notice.update("blocked", "http_5xx", 60_000))
        assertNull(notice.update("armed", null, 60_001))
        assertNull(notice.remaining(60_001))
        assertNull(notice.update("blocked", null, 61_000))
        assertEquals("blocked", notice.update("blocked", null, 81_000))
    }

    @Test fun explicitStopFencesLateTimerAndActionableLossIsImmediate() {
        val notice = KillSwitchNotice()
        notice.update("blocked", null, 0)
        notice.update("off", null, 5_000)
        assertNull(notice.update("off", null, 30_000))
        assertNull(notice.remaining(30_000))
        assertEquals("vpn_permission_revoked", notice.update("off", "vpn_permission_revoked", 30_001))
        assertNull(notice.update("off", "vpn_permission_revoked", 30_002))
        assertEquals("protection_lost", notice.update("off", "protection_lost", 30_003))
        assertEquals("captive_portal", notice.update("blocked", "captive_portal", 30_004))
    }
}
