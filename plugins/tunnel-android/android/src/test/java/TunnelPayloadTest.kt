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
    fun duplicateStartCannotEnterTheNativeQueueAndRunningTunnelIsReplaced() {
        val gate = TunnelStateGate()

        assertEquals(TransitionDecision.PROCEED, gate.beginStart())
        assertEquals(TransitionDecision.BUSY, gate.beginStart())
        gate.complete(SessionState.RUNNING)
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
    fun physicalNetworkRetryIsDeferredOnlyForTheFailedNetwork() {
        val gate = PhysicalNetworkRetryGate()

        assertTrue(gate.canAttempt("wifi-a", 1_000))
        gate.defer("wifi-a", 1_000)

        assertTrue(!gate.canAttempt("wifi-a", 1_000 + 299_999))
        assertTrue(gate.canAttempt("wifi-a", 1_000 + 300_000))
        assertTrue(gate.canAttempt("cellular-b", 1_001))

        gate.clear()
        assertTrue(gate.canAttempt("wifi-a", 1_002))
    }
}
