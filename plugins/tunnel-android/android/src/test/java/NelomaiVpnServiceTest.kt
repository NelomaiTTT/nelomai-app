package ru.nelomai.tunnel

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NelomaiVpnServiceTest {
    @Test
    fun restoresDesiredTunnelAfterRuntimeWasLost() {
        assertTrue(shouldRestoreDesiredTunnel(true, SessionState.STOPPED))
        assertTrue(shouldRestoreDesiredTunnel(true, SessionState.FAILED))
    }

    @Test
    fun doesNotDuplicateRunningOrStartingTunnel() {
        assertFalse(shouldRestoreDesiredTunnel(true, SessionState.RUNNING))
        assertFalse(shouldRestoreDesiredTunnel(true, SessionState.STARTING))
    }

    @Test
    fun doesNotRestoreTunnelThatUserStopped() {
        assertFalse(shouldRestoreDesiredTunnel(false, SessionState.STOPPED))
        assertFalse(shouldRestoreDesiredTunnel(false, SessionState.FAILED))
    }
}
