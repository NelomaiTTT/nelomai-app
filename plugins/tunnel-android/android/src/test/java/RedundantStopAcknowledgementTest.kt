package ru.nelomai.tunnel

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class RedundantStopAcknowledgementTest {
    private val transaction = AndroidRedundantTransaction(
        desiredActive = true,
        template = AndroidIntentTemplate("11111111-1111-4111-8111-111111111111", "account",
            "stray", "dynamic", "standalone", "ipv4", true),
        sessionId = "22222222-2222-4222-8222-222222222222",
        slotALeaseId = "lease-a", slotBLeaseId = "lease-b", localActiveLeaseId = "lease-a",
        standbyDesired = true, roleGeneration = 0, membershipGeneration = 0,
        startOperationId = "old-start", startRequestFingerprint = "old-fingerprint",
    )
    private fun response(status: String, session: Any = JSONObject.NULL, lease: String = "lease-a") =
        JSONObject().put("connection", JSONObject()
            .put("lease_id", lease).put("status", status).put("session_id", session))
    private fun panel(reply: () -> JSONObject) = ServiceRedundantConnectionPanel(
        credential = { BackgroundCredential(it, "https://nelomai.example", "token", 1_900_000_000) },
        stopTransport = { credential, requested, lease ->
            assertEquals(transaction.template.deviceId, credential.deviceId)
            assertEquals(transaction.sessionId, requested.sessionId)
            assertEquals("lease-a", lease)
            reply()
        },
    )

    @Test fun acceptedStopAndReleasedPrimaryDoNotAcknowledgeLiveSession() {
        for (status in listOf("issued", "connected", "warm", "released", "failed")) {
            assertFalse(status, panel { response(status, transaction.sessionId) }.stop(transaction))
        }
        for (status in listOf("issued", "connected", "warm", "unknown")) {
            assertFalse(status, panel { response(status) }.stop(transaction))
        }
        for (status in listOf("released", "failed")) {
            assertTrue(status, panel { response(status) }.stop(transaction))
        }
    }

    @Test fun missingOrMismatchedConnectionCannotReleaseTheStopBarrier() {
        val missingSession = response("released").also { it.getJSONObject("connection").remove("session_id") }
        for (reply in listOf(JSONObject(), missingSession, response("released", lease = "other"),
            response("released", "another-session"))) {
            assertFalse(reply.toString(), panel { reply }.stop(transaction))
        }
        assertFalse(panel { error("transport down") }.stop(transaction))
    }

    @Test fun networkRestartRemainsBehindWholeSessionBarrierAcrossProcessRecreation() {
        var bytes: ByteArray? = null
        val backend = object : EncryptedRecordBackend {
            override fun read() = bytes?.copyOf()
            override fun write(plaintext: ByteArray): Boolean { bytes = plaintext.copyOf(); return true }
        }
        fun store() = AndroidRecoveryStore(backend, BootIdentityProvider { 7L })
        var reply = response("released", transaction.sessionId)
        val requests = mutableListOf<String?>()
        val panel = ServiceRedundantConnectionPanel(
            credential = { BackgroundCredential(it, "https://nelomai.example", "token", 1_900_000_000) },
            stopTransport = { _, requested, _ -> requests += requested.stopOperationId; reply },
        )
        val native = object : RedundantConnectionNative {
            override fun start(leaseId: String, slot: RedundantSlot, configuration: ByteArray, healthProbe: BackgroundRedundantHealthProbe?) = error("must not start")
            override fun activate(leaseId: String) = error("must not activate")
            override fun stopSlot(leaseId: String) = true
            override fun stop() = true
            override fun isUsable(leaseId: String) = false
        }
        val first = store()
        assertTrue(first.beginRedundant(transaction) is RecoveryStoreResult.Success)
        assertTrue(first.prepareRedundantTotalLoss("old-start", AndroidStartReplay("next-start", 2, "fp")) is RecoveryStoreResult.Success)
        val coordinator = RedundantConnectionCoordinator(first, panel, native)
        assertFalse(coordinator.revoke())
        val pending = (first.read() as RecoveryStoreResult.Success).value
        assertNotNull(pending.redundantTransaction)
        assertNull(pending.leaseTransaction)
        reply = response("released")
        val reopened = store()
        assertTrue(RedundantConnectionCoordinator(reopened, panel, native).revoke())
        val next = (reopened.read() as RecoveryStoreResult.Success).value
        assertNull(next.redundantTransaction)
        assertEquals("next-start", next.leaseTransaction!!.startOperationId)
        assertEquals(2, requests.size)
        assertNotNull(requests[0])
        assertEquals(requests[0], requests[1])
    }
}
