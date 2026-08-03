package ru.nelomai.tunnel

import org.junit.Assert.assertEquals
import org.junit.Test

class QuickTunnelControllerTest {
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
