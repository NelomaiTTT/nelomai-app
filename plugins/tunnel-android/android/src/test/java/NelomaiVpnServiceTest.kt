package ru.nelomai.tunnel

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NelomaiVpnServiceTest {
    @Test
    fun only_real_background_start_failures_queue_diagnostics() {
        assertTrue(
            shouldQueueBackgroundStartFailureDiagnostics(
                starting = true,
                errorCode = "configuration_fetch_failed",
            ),
        )
        assertFalse(
            shouldQueueBackgroundStartFailureDiagnostics(
                starting = false,
                errorCode = "configuration_fetch_failed",
            ),
        )
        assertFalse(
            shouldQueueBackgroundStartFailureDiagnostics(
                starting = true,
                errorCode = "tunnel_operation_in_progress",
            ),
        )
        assertFalse(shouldQueueBackgroundStartFailureDiagnostics(starting = true, errorCode = null))
    }

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

    @Test
    fun timedOutStartOnlyCancelsItsOwnActiveSession() {
        assertTrue(shouldCancelActiveClientStart("operation-a", "operation-a"))
        assertFalse(shouldCancelActiveClientStart("operation-a", "operation-b"))
        assertFalse(shouldCancelActiveClientStart("operation-a", null))
    }
}
