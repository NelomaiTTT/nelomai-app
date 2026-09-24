package ru.nelomai.tunnel

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class RedundantStopAcknowledgementTest {
    @Test fun retentionDecisionAndLastPrimaryAreFrozenAcrossStopRetries() {
        for (supported in listOf(false, true)) {
            var bytes: ByteArray? = null
            val store = AndroidRecoveryStore(object : EncryptedRecordBackend {
                override fun read() = bytes?.copyOf()
                override fun write(plaintext: ByteArray): Boolean { bytes = plaintext.copyOf(); return true }
            }, BootIdentityProvider { 7L })
            assertTrue(store.beginRedundant(transaction.copy(warmStopSupported = supported,
                localActiveLeaseId = "lease-b")) is RecoveryStoreResult.Success)
            val first = (store.cancelRedundantIntentAndDeferStop("stop-first", "old-start",
                retainActivePeer = true) as RecoveryStoreResult.Success).value.redundantTransaction!!
            assertEquals(supported, first.retainActivePeerOnStop)
            assertEquals("lease-b", first.localActiveLeaseId)
            val repeated = (store.cancelRedundantIntentAndDeferStop("stop-second", "old-start")
                as RecoveryStoreResult.Success).value.redundantTransaction!!
            assertEquals("stop-first", repeated.stopOperationId)
            assertEquals(first.retainActivePeerOnStop, repeated.retainActivePeerOnStop)
            assertEquals("lease-b", repeated.localActiveLeaseId)
        }
    }

    @Test fun initialStopRequestAndInFlightRoleDoNotHoldLocalShutdown() {
        for (holdRole in listOf(false, true)) checkLocalShutdown(holdRole)
    }

    private fun checkLocalShutdown(holdRole: Boolean) {
        var bytes: ByteArray? = null
        val store = AndroidRecoveryStore(object : EncryptedRecordBackend {
            override fun read() = bytes?.copyOf()
            override fun write(plaintext: ByteArray): Boolean { bytes = plaintext.copyOf(); return true }
        }, BootIdentityProvider { 7L })
        assertTrue(store.beginRedundant(transaction) is RecoveryStoreResult.Success)
        if (!holdRole) assertTrue(store.cancelRedundantIntentAndDeferStop("stop-one", "old-start") is RecoveryStoreResult.Success)
        val entered = java.util.concurrent.CountDownLatch(1)
        val release = java.util.concurrent.CountDownLatch(1)
        val nativeStops = java.util.concurrent.atomic.AtomicInteger()
        val panel = object : RedundantConnectionPanel {
            override fun recover(transaction: AndroidRedundantTransaction) = error("unused")
            override fun reportRole(transaction: AndroidRedundantTransaction, reason: String): RedundantRoleResponse {
                entered.countDown()
                check(release.await(5, java.util.concurrent.TimeUnit.SECONDS))
                error("network lost")
            }
            override fun releaseStandby(transaction: AndroidRedundantTransaction, inactiveLeaseId: String?) = error("unused")
            override fun acquireStandby(transaction: AndroidRedundantTransaction, operationId: String, replaceLeaseId: String?) = error("unused")
            override fun commitCandidate(transaction: AndroidRedundantTransaction, candidateLeaseId: String) = error("unused")
            override fun stop(transaction: AndroidRedundantTransaction): Boolean {
                entered.countDown()
                check(release.await(5, java.util.concurrent.TimeUnit.SECONDS))
                return true
            }
        }
        val native = object : RedundantConnectionNative {
            override fun start(leaseId: String, slot: RedundantSlot, configuration: ByteArray, healthProbe: BackgroundRedundantHealthProbe?) = false
            override fun activate(leaseId: String) = false
            override fun stopSlot(leaseId: String) = true
            override fun stop(): Boolean { nativeStops.incrementAndGet(); return true }
            override fun isUsable(leaseId: String) = false
        }
        val coordinator = RedundantConnectionCoordinator(store, panel, native,
            expectedStartOperationId = "old-start")
        val worker = Thread {
            if (holdRole) coordinator.reportLocalRole("primary_ready") else coordinator.notifyStop()
        }.also { it.start() }
        try {
            assertTrue(entered.await(2, java.util.concurrent.TimeUnit.SECONDS))
            if (holdRole) assertTrue(store.cancelRedundantIntentAndDeferStop("stop-one", "old-start") is RecoveryStoreResult.Success)
            assertTrue(coordinator.closeDataplaneForStop())
            assertEquals(1, nativeStops.get())
            assertNotNull((store.read() as RecoveryStoreResult.Success).value.redundantTransaction)
        } finally { release.countDown(); worker.join(2_000) }
        assertFalse(worker.isAlive)
        assertNotNull((store.read() as RecoveryStoreResult.Success).value.redundantTransaction)
    }

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

    @Test fun warmStopAcknowledgementRequiresNegotiatedCapabilityAndWholeSessionCleanup() {
        val requested = transaction.copy(warmStopSupported = true, retainActivePeerOnStop = true,
            desiredActive = false, stopOperationId = "stop-one",
            retry = transaction.retry.copy(stopState = RedundantStopState.PENDING))
        assertTrue(backgroundRedundantStopPayload(requested, "lease-a").getBoolean("retain_active_peer"))
        assertFalse(backgroundRedundantStopPayload(transaction.copy(stopOperationId = "stop-one"), "lease-a")
            .has("retain_active_peer"))
        assertFalse(panel { response("warm") }.stop(transaction))
        assertFalse(panel { response("warm") }.stop(transaction.copy(warmStopSupported = true)))
        assertTrue(panel { response("warm") }.stop(requested))
        assertFalse(panel { response("warm", transaction.sessionId) }.stop(requested))
        assertFalse(panel { response("warm", lease = "other") }.stop(requested))
        val envelope = AndroidRecoveryEnvelope.empty(7).copy(redundantTransaction = requested)
        val reopened = AndroidRecoveryEnvelopeCodec.decode(AndroidRecoveryEnvelopeCodec.encode(envelope))
        assertEquals(backgroundRedundantStopPayload(requested, "lease-a").toString(),
            backgroundRedundantStopPayload(reopened.redundantTransaction!!, "lease-a").toString())
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
