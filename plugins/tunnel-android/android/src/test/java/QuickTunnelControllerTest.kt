package ru.nelomai.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class QuickTunnelControllerTest {
    @Test
    fun broadcastGateAvoidsPollingTheVpnServiceForPersistedChanges() {
        val gate = QuickStateChangeGate()

        assertFalse(gate.current())
        gate.observe(1)
        val firstRevision = gate.snapshot()
        assertTrue(gate.current())
        gate.acknowledgeThrough(firstRevision)
        assertFalse(gate.current())
        gate.seedPersisted(1)
        assertFalse(gate.current())

        val coldGate = QuickStateChangeGate()
        coldGate.seedPersisted(1)
        assertTrue(coldGate.current())
    }

    @Test
    fun changeArrivingDuringAcknowledgeRemainsVisible() {
        val gate = QuickStateChangeGate(initialRevision = 1)
        val acknowledgedRevision = gate.snapshot()

        gate.observe(2)
        gate.acknowledgeThrough(acknowledgedRevision)

        assertTrue(gate.current())
    }

    @Test
    fun clearingQuickPlanClearsTheLocalPendingGeneration() {
        val gate = QuickStateChangeGate(initialRevision = 4)

        gate.clearPending()

        assertFalse(gate.current())
        gate.observe(5)
        assertTrue(gate.current())
    }

    @Test
    fun keepsRecentTransition() {
        assertEquals(
            SessionState.STARTING,
            QuickTunnelController.resolveState(
                SessionState.STOPPED,
                SessionState.STARTING,
                updatedAtMillis = 1_000,
                nowMillis = 1_000 + QuickTunnelController.TRANSITION_TIMEOUT_MILLIS - 1,
            ),
        )
    }

    @Test
    fun clearsExpiredTransition() {
        assertEquals(
            SessionState.STOPPED,
            QuickTunnelController.resolveState(
                SessionState.STOPPED,
                SessionState.STOPPING,
                updatedAtMillis = 1_000,
                nowMillis = 1_000 + QuickTunnelController.TRANSITION_TIMEOUT_MILLIS,
            ),
        )
    }

    @Test
    fun clearsLegacyTransitionWithoutTimestamp() {
        assertEquals(
            SessionState.STOPPED,
            QuickTunnelController.resolveState(
                SessionState.STOPPED,
                SessionState.STARTING,
                updatedAtMillis = 0,
                nowMillis = 10_000,
            ),
        )
    }

    @Test
    fun runtimeStateTakesPriority() {
        assertEquals(
            SessionState.RUNNING,
            QuickTunnelController.resolveState(
                SessionState.RUNNING,
                SessionState.STOPPING,
                updatedAtMillis = 1_000,
                nowMillis = 10_000,
            ),
        )
    }
}
