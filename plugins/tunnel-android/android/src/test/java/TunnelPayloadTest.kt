package ru.nelomai.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TunnelPayloadTest {
    @Test
    fun operationWatchdogExpiresOnlyTheCurrentUnfinishedOperation() {
        val gate = TunnelOperationWatchdogGate()
        val completed = gate.begin()

        assertTrue(gate.complete(completed))
        assertFalse(gate.expire(completed))

        val stale = gate.begin()
        val current = gate.begin()
        assertFalse(gate.expire(stale))
        assertTrue(gate.expire(current))
    }

    @Test
    fun payloadIsWipedAfterSuccessfulUse() {
        val payload = "PrivateKey = secret".encodeToByteArray()

        TunnelPayload.consume(payload) { bytes ->
            assertEquals("PrivateKey = secret", bytes.decodeToString())
        }

        assertTrue(payload.all { it == 0.toByte() })
    }

    @Test
    fun payloadIsWipedWhenUseFails() {
        val payload = "PrivateKey = secret".encodeToByteArray()

        runCatching {
            TunnelPayload.consume(payload) {
                error("bad config")
            }
        }

        assertTrue(payload.all { it == 0.toByte() })
    }

    @Test
    fun duplicateStartCannotEnterTheNativeQueueAndRunningTunnelIsReplaced() {
        val gate = TunnelStateGate()

        assertEquals(TransitionDecision.PROCEED, gate.beginStart())
        assertEquals(TransitionDecision.BUSY, gate.beginStart())
        gate.complete(SessionState.RUNNING)
        assertEquals(TransitionDecision.REPLACE, gate.beginStart())
        assertEquals(TransitionDecision.BUSY, gate.beginStart())
    }

    @Test
    fun failedTunnelIsCleanedBeforeItIsStartedAgain() {
        val gate = TunnelStateGate(SessionState.FAILED)

        assertEquals(TransitionDecision.REPLACE, gate.beginStart())
        assertEquals(TransitionDecision.BUSY, gate.beginStart())
    }

    @Test
    fun stopIsIdempotentAndBlocksConcurrentMutation() {
        val gate = TunnelStateGate(SessionState.RUNNING)

        assertEquals(TransitionDecision.PROCEED, gate.beginStop())
        assertEquals(TransitionDecision.BUSY, gate.beginStop())
        gate.complete(SessionState.STOPPED)
        assertEquals(TransitionDecision.ALREADY_COMPLETE, gate.beginStop())
    }

    @Test
    fun backgroundOperationGateSerializesTheWholeOperation() {
        val gate = BackgroundOperationGate()

        assertTrue(gate.begin())
        assertTrue(!gate.begin())
        gate.complete()
        assertTrue(gate.begin())
    }

    @Test
    fun backgroundStartRetriesUnavailableSavedServerOnlyWhenAlternateIsAllowed() {
        assertTrue(
            shouldRetryBackgroundStart(
                "saved-lease",
                true,
                "saved_connection_unavailable",
            ),
        )
        assertTrue(
            shouldRetryBackgroundStart(
                "saved-lease",
                true,
                "saved_stray_unavailable",
            ),
        )
        assertTrue(
            !shouldRetryBackgroundStart(
                "saved-lease",
                false,
                "saved_connection_unavailable",
            ),
        )
        assertTrue(
            shouldRetryBackgroundStart(
                "saved-lease",
                false,
                "connection_no_longer_active",
            ),
        )
    }
}
