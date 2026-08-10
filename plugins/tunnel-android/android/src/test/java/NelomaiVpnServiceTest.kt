package ru.nelomai.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NelomaiVpnServiceTest {
    @Test
    fun diagnosticBackendVersionReplacesUnhelpfulLocalBuildMarkers() {
        assertEquals("git-08d68cd", diagnosticBackendVersion("(devel)"))
        assertEquals("git-08d68cd", diagnosticBackendVersion("unknown"))
        assertEquals("3.0.1", diagnosticBackendVersion("3.0.1"))
    }

    @Test
    fun dataPlaneDiagnosticsDistinguishHandshakeAndEncryptedCounterActivity() {
        assertEquals(20L, counterDelta(null, 20L))
        assertEquals(5L, counterDelta(20L, 25L))
        assertEquals(3L, counterDelta(20L, 3L))
        assertEquals(
            "waiting_for_handshake",
            tunnelDataPlaneState(60, null, 10, 10),
        )
        assertEquals(
            "encrypted_counter_activity",
            tunnelDataPlaneState(60, 1_000, 1, 0),
        )
        assertEquals(
            "handshake_without_counter_activity",
            tunnelDataPlaneState(60, 1_000, 0, 0),
        )
    }

    @Test
    fun idleVpnProcessIsRecycledOnlyAfterAbnormalMemoryGrowth() {
        assertTrue(
            shouldRecycleIdleVpnProcess(
                SessionState.STOPPED,
                desiredActive = false,
                residentBytes = 600L * 1024L * 1024L,
                proportionalBytes = 100L * 1024L * 1024L,
            ),
        )
        assertFalse(
            shouldRecycleIdleVpnProcess(
                SessionState.RUNNING,
                desiredActive = true,
                residentBytes = 900L * 1024L * 1024L,
                proportionalBytes = 800L * 1024L * 1024L,
            ),
        )
        assertFalse(
            shouldRecycleIdleVpnProcess(
                SessionState.STOPPED,
                desiredActive = false,
                residentBytes = 150L * 1024L * 1024L,
                proportionalBytes = 80L * 1024L * 1024L,
            ),
        )
    }

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
