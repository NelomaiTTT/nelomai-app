package ru.nelomai.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TunnelPayloadTest {
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
    fun duplicateStartCannotEnterTheNativeQueue() {
        val gate = TunnelStateGate()

        assertEquals(TransitionDecision.PROCEED, gate.beginStart())
        assertEquals(TransitionDecision.BUSY, gate.beginStart())
        gate.complete(SessionState.RUNNING)
        assertEquals(TransitionDecision.ALREADY_COMPLETE, gate.beginStart())
    }

    @Test
    fun stopIsIdempotentAndBlocksConcurrentMutation() {
        val gate = TunnelStateGate(SessionState.RUNNING)

        assertEquals(TransitionDecision.PROCEED, gate.beginStop())
        assertEquals(TransitionDecision.BUSY, gate.beginStop())
        gate.complete(SessionState.STOPPED)
        assertEquals(TransitionDecision.ALREADY_COMPLETE, gate.beginStop())
    }
}
