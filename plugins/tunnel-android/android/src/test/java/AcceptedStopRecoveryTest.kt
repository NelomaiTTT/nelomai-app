package ru.nelomai.tunnel

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class AcceptedStopRecoveryTest {
    private class Backend : EncryptedRecordBackend {
        var bytes: ByteArray? = null
        var failWrites = false
        override fun read() = bytes?.copyOf()
        override fun write(plaintext: ByteArray): Boolean {
            if (failWrites) return false
            bytes = plaintext.copyOf()
            return true
        }
    }

    private val device = "11111111-1111-4111-8111-111111111111"
    private val session = "22222222-2222-4222-8222-222222222222"
    private val lease = "33333333-3333-4333-8333-333333333333"
    private val start = "44444444-4444-4444-8444-444444444444"
    private val stop = "55555555-5555-4555-8555-555555555555"

    private fun prepared(backend: Backend): AndroidRecoveryStore {
        val initial = AndroidRecoveryStore(backend, BootIdentityProvider { 7L })
        val tx = AndroidRedundantTransaction(desiredActive = true,
            template = AndroidIntentTemplate(device, "account", "stray", "dynamic", "standalone", "ipv4", true),
            sessionId = session, slotALeaseId = lease, slotBLeaseId = null, localActiveLeaseId = lease,
            standbyDesired = true, roleGeneration = 0, membershipGeneration = 0,
            startOperationId = start, startRequestFingerprint = "a".repeat(64), warmStopSupported = true)
        assertTrue(initial.beginRedundant(tx) is RecoveryStoreResult.Success)
        // Decode a newly negotiated session as it is restored after process death.
        val wire = JSONObject(String(requireNotNull(backend.bytes), Charsets.UTF_8))
        wire.getJSONObject("redundantTransaction").put("asyncStopSupported", true)
        wire.getJSONObject("intent").put("armedHistory", true)
        backend.bytes = wire.toString().toByteArray(Charsets.UTF_8)
        val store = AndroidRecoveryStore(backend, BootIdentityProvider { 7L })
        assertTrue(store.cancelRedundantIntentAndDeferStop(stop, start, retainActivePeer = true) is RecoveryStoreResult.Success)
        return store
    }

    private fun acceptedReply(operation: String = stop) = JSONObject()
        .put("connection", JSONObject().put("lease_id", lease).put("status", "connected").put("session_id", session))
        .put("stop_acceptance", JSONObject().put("operation_id", operation).put("session_id", session)
            .put("lease_id", lease).put("accepted", true).put("cleanup_pending", true))

    private fun coordinator(store: AndroidRecoveryStore, close: () -> Boolean, reply: () -> JSONObject): RedundantConnectionCoordinator {
        val panel = ServiceRedundantConnectionPanel(
            credential = { BackgroundCredential(it, "https://nelomai.example", "token", 1_900_000_000) },
            stopTransport = { _, _, _ -> reply() })
        val native = object : RedundantConnectionNative {
            override fun start(leaseId: String, slot: RedundantSlot, configuration: ByteArray, healthProbe: BackgroundRedundantHealthProbe?) = false
            override fun activate(leaseId: String) = false
            override fun stopSlot(leaseId: String) = true
            override fun stop() = close()
            override fun isUsable(leaseId: String) = false
        }
        return RedundantConnectionCoordinator(store, panel, native, expectedStartOperationId = start)
    }

    @Test fun nativeClosedAndMatchedAcceptanceDetachDurablyBeforeNextStart() {
        val backend = Backend()
        val store = prepared(backend)
        assertTrue(coordinator(store, { true }, { acceptedReply() }).revoke())
        val reloaded = (AndroidRecoveryStore(backend, BootIdentityProvider { 7L }).read() as RecoveryStoreResult.Success).value
        assertNull(reloaded.redundantTransaction)
        assertFalse(reloaded.intent.desiredActive)
        // The old cleanup must survive the current transaction being removed.
        val persisted = JSONObject(String(requireNotNull(backend.bytes), Charsets.UTF_8))
        val retired = persisted.getJSONArray("acceptedStops")
        assertEquals(1, retired.length())
        assertEquals(session, retired.getJSONObject(0).getString("sessionId"))
        assertEquals(stop, retired.getJSONObject(0).getString("operationId"))
    }

    @Test fun unknownNativeAndWrongAcceptanceKeepStopBarrier() {
        for (localClosed in listOf(false, true)) {
            val backend = Backend()
            val store = prepared(backend)
            val reply = if (localClosed) acceptedReply("66666666-6666-4666-8666-666666666666") else acceptedReply()
            assertFalse(coordinator(store, { localClosed }, { reply }).revoke())
            assertNotNull((store.read() as RecoveryStoreResult.Success).value.redundantTransaction)
        }
    }

    @Test fun failedArchiveWriteKeepsExactCurrentStop() {
        val backend = Backend()
        val store = prepared(backend)
        assertFalse(coordinator(store, { backend.failWrites = true; true }, { acceptedReply() }).revoke())
        backend.failWrites = false
        val pending = (store.read() as RecoveryStoreResult.Success).value.redundantTransaction!!
        assertEquals(session, pending.sessionId)
        assertEquals(stop, pending.stopOperationId)
        assertFalse(pending.desiredActive)
    }
    @Test fun retiredCleanupSurvivesBootAndNewIntentAndLateAckOnlyRemovesOldRecord() {
        val backend = Backend()
        val store = prepared(backend)
        assertTrue(coordinator(store, { true }, { acceptedReply() }).revoke())
        val old = (store.read() as RecoveryStoreResult.Success).value.acceptedStops.single()
        val rebooted = AndroidRecoveryStore(backend, BootIdentityProvider { 8L })
        val restored = (rebooted.read() as RecoveryStoreResult.Success).value
        assertEquals(old, restored.acceptedStops.single())
        val next = AndroidRedundantTransaction(desiredActive = true,
            template = AndroidIntentTemplate(device, "account", "stray", "dynamic", "standalone", "ipv4", true),
            sessionId = "66666666-6666-4666-8666-666666666666", slotALeaseId = lease,
            slotBLeaseId = null, localActiveLeaseId = lease, standbyDesired = true,
            roleGeneration = 0, membershipGeneration = 0, startOperationId = "77777777-7777-4777-8777-777777777777",
            startRequestFingerprint = "b".repeat(64))
        assertTrue(rebooted.beginRedundant(next) is RecoveryStoreResult.Success)
        val active = (rebooted.read() as RecoveryStoreResult.Success).value
        assertTrue(rebooted.completeAcceptedCleanup(old.copy(sessionId = next.sessionId)) is RecoveryStoreResult.Success)
        assertEquals(active, (rebooted.read() as RecoveryStoreResult.Success).value)
        assertTrue(rebooted.completeAcceptedCleanup(old) is RecoveryStoreResult.Success)
        val completed = (rebooted.read() as RecoveryStoreResult.Success).value
        assertEquals(active.intent, completed.intent)
        assertEquals(next, completed.redundantTransaction)
        assertTrue(completed.acceptedStops.isEmpty())
    }

    @Test fun eighthRetiredRecordBlocksAdmissionWithoutEvictionOrExpiry() {
        val backend = Backend()
        val store = prepared(backend)
        assertTrue(coordinator(store, { true }, { acceptedReply() }).revoke())
        val current = (store.read() as RecoveryStoreResult.Success).value
        val first = current.acceptedStops.single()
        val eight = (0..7).map { index -> first.copy(
            operationId = "55555555-5555-4555-8555-%012d".format(index),
            sessionId = "22222222-2222-4222-8222-%012d".format(index), acceptedAtUnix = 0) }
        backend.bytes = AndroidRecoveryEnvelopeCodec.encode(current.copy(acceptedStops = eight))
        val restored = AndroidRecoveryStore(backend, BootIdentityProvider { 8L })
        val tx = AndroidRedundantTransaction(desiredActive = true, template = AndroidIntentTemplate(
            device, "account", "stray", "dynamic", "standalone", "ipv4", true), sessionId = session,
            slotALeaseId = lease, slotBLeaseId = null, localActiveLeaseId = lease, standbyDesired = true,
            roleGeneration = 0, membershipGeneration = 0, startOperationId = start, startRequestFingerprint = "a".repeat(64))
        assertTrue(restored.beginRedundant(tx) is RecoveryStoreResult.Failure)
        assertEquals(eight, (restored.read() as RecoveryStoreResult.Success).value.acceptedStops)
    }

    @Test fun terminalReceiptDrainsFullArchiveAndAdmitsTheNextStart() {
        val backend = Backend()
        val store = prepared(backend)
        val oldTransaction = (store.read() as RecoveryStoreResult.Success).value.redundantTransaction!!
        assertTrue(coordinator(store, { true }, { acceptedReply() }).revoke())
        val current = (store.read() as RecoveryStoreResult.Success).value
        val first = current.acceptedStops.single()
        val eight = (0..7).map { index -> first.copy(
            operationId = "55555555-5555-4555-8555-%012d".format(index),
            sessionId = "22222222-2222-4222-8222-%012d".format(index)) }
        backend.bytes = AndroidRecoveryEnvelopeCodec.encode(current.copy(acceptedStops = eight))
        val next = oldTransaction.copy(desiredActive = true, stopOperationId = null,
            retry = AndroidRedundantRetryState(), backgroundCleanupOnStop = false,
            sessionId = "66666666-6666-4666-8666-666666666666",
            startOperationId = "77777777-7777-4777-8777-777777777777")
        assertTrue(store.beginRedundant(next) is RecoveryStoreResult.Failure)
        // Panel projects APPLIED as terminal when the lease is released.
        // Only its exact final receipt authorizes removing a retired record.
        reconcileAcceptedStops(store) { old -> BackgroundReconcileResult("terminal", false,
            old.leaseId, "released", 0, null,
            StopAcceptance(old.operationId, old.sessionId, old.leaseId, false)) }
        val restarted = AndroidRecoveryStore(backend, BootIdentityProvider { 7L })
        assertTrue((restarted.read() as RecoveryStoreResult.Success).value.acceptedStops.isEmpty())
        assertTrue(restarted.beginRedundant(next) is RecoveryStoreResult.Success)
        assertEquals(next, (restarted.read() as RecoveryStoreResult.Success).value.redundantTransaction)
    }

    @Test fun terminalStateAloneCannotEraseAcceptedCleanup() {
        val backend = Backend()
        val store = prepared(backend)
        assertTrue(coordinator(store, { true }, { acceptedReply() }).revoke())
        val before = (store.read() as RecoveryStoreResult.Success).value
        val old = before.acceptedStops.single()
        val final = StopAcceptance(old.operationId, old.sessionId, old.leaseId, false)
        for (receipt in listOf(null, final.copy(operationId = device),
            final.copy(sessionId = device), final.copy(leaseId = device), final.copy(cleanupPending = true))) {
            reconcileAcceptedStops(store) { BackgroundReconcileResult("terminal", false,
                old.leaseId, "released", 0, null, receipt) }
            assertEquals(before, (store.read() as RecoveryStoreResult.Success).value)
        }
    }

    @Test fun reconcileRequiresExactTerminalAcceptanceAndUsesOriginalCredential() {
        val backend = Backend()
        val store = prepared(backend)
        assertTrue(coordinator(store, { true }, { acceptedReply() }).revoke())
        val snapshot = (store.read() as RecoveryStoreResult.Success).value
        val old = snapshot.acceptedStops.single()
        val final = StopAcceptance(old.operationId, old.sessionId, old.leaseId, false)
        fun reply(acceptance: StopAcceptance?, state: String = "applied") =
            BackgroundReconcileResult(state, false, lease, "warm", 0, null, acceptance)
        for (response in listOf(reply(null), reply(final.copy(sessionId = device)),
            reply(final.copy(cleanupPending = true)), reply(final, "applying"))) {
            reconcileAcceptedStops(store) { assertEquals("token", it.credential.token); response }
            assertEquals(snapshot, (store.read() as RecoveryStoreResult.Success).value)
        }
        reconcileAcceptedStops(store) { throw BackgroundConnectionException("background_token_expired") }
        assertEquals(snapshot, (store.read() as RecoveryStoreResult.Success).value)
        backend.failWrites = true
        reconcileAcceptedStops(store) { reply(final) }
        backend.failWrites = false
        assertEquals(snapshot, (store.read() as RecoveryStoreResult.Success).value)
        reconcileAcceptedStops(store) { reply(final) }
        assertTrue((store.read() as RecoveryStoreResult.Success).value.acceptedStops.isEmpty())
    }

    @Test fun invalidRetiredRecordIsPreservedAndKeepsAdmissionClosed() {
        val backend = Backend()
        val store = prepared(backend)
        assertTrue(coordinator(store, { true }, { acceptedReply() }).revoke())
        val wire = JSONObject(String(requireNotNull(backend.bytes), Charsets.UTF_8))
        wire.getJSONArray("acceptedStops").getJSONObject(0).put("requestFingerprint", "invalid")
        backend.bytes = wire.toString().toByteArray()
        val before = backend.bytes!!.copyOf()
        assertTrue(store.read() is RecoveryStoreResult.Failure)
        assertArrayEquals(before, backend.bytes)
        assertTrue(store.read() is RecoveryStoreResult.Failure)
    }

    @Test fun stopFingerprintAgreesWithSharedRustAndPythonFixture() {
        val transaction = AndroidRedundantTransaction(desiredActive = false,
            template = AndroidIntentTemplate(device, "account", "stray", "dynamic", "standalone", "ipv4", true),
            sessionId = "20000000-0000-4000-8000-000000000001", slotALeaseId = "20000000-0000-4000-8000-000000000003", slotBLeaseId = null,
            localActiveLeaseId = "20000000-0000-4000-8000-000000000003", standbyDesired = true, roleGeneration = 0,
            membershipGeneration = 0, startOperationId = start, startRequestFingerprint = "a".repeat(64),
            stopOperationId = "20000000-0000-4000-8000-000000000006", retainActivePeerOnStop = true, backgroundCleanupOnStop = true)
        assertEquals("56059211288db0f698ceda958b59a5548408dc3c2f1180968d309eb4e2c26eb0", backgroundRedundantStopFingerprint(transaction, "20000000-0000-4000-8000-000000000003"))
    }


    private fun fullArchive(): Pair<AndroidRecoveryStore, AndroidRedundantTransaction> {
        val backend = Backend()
        val store = prepared(backend)
        val previous = (store.read() as RecoveryStoreResult.Success).value.redundantTransaction!!
        assertTrue(coordinator(store, { true }, { acceptedReply() }).revoke())
        val current = (store.read() as RecoveryStoreResult.Success).value
        val first = current.acceptedStops.single()
        backend.bytes = AndroidRecoveryEnvelopeCodec.encode(current.copy(acceptedStops = (0..7).map { i ->
            first.copy(operationId = "55555555-5555-4555-8555-%012d".format(i),
                sessionId = "22222222-2222-4222-8222-%012d".format(i)) }))
        return store to previous.copy(desiredActive = true, stopOperationId = null,
            retry = AndroidRedundantRetryState(), backgroundCleanupOnStop = false,
            sessionId = "66666666-6666-4666-8666-666666666666",
            startOperationId = "77777777-7777-4777-8777-777777777777")
    }

    @Test fun queuedFinalReceiptAllowsTheSameStartWithoutAnotherClick() {
        val (store, next) = fullArchive()
        val first = (store.read() as RecoveryStoreResult.Success).value.acceptedStops.first()
        val queued = mutableListOf<Runnable>()
        val dispatcher = RedundantVpnWorkDispatcher(java.util.concurrent.Executor { queued.add(it) })
        assertTrue(dispatcher.tick {
            reconcileAcceptedStops(store) { old -> BackgroundReconcileResult("terminal", false,
                old.leaseId, "released", 0, null,
                StopAcceptance(old.operationId, old.sessionId, old.leaseId, old != first)) }
        })
        val checking = java.util.concurrent.CountDownLatch(1)
        val executor = java.util.concurrent.Executors.newSingleThreadExecutor()
        try {
            val start = executor.submit<RecoveryStoreResult<AndroidRecoveryEnvelope>> {
                awaitAcceptedStopCapacity(store, { checking.countDown(); false })
                store.beginRedundant(next)
            }
            assertTrue(checking.await(1, java.util.concurrent.TimeUnit.SECONDS))
            // An unrelated cleanup worker must remain able to write while Start waits.
            queued.single().run()
            assertTrue(start.get(2, java.util.concurrent.TimeUnit.SECONDS) is RecoveryStoreResult.Success)
            assertEquals(next, (store.read() as RecoveryStoreResult.Success).value.redundantTransaction)
            assertEquals(7, (store.read() as RecoveryStoreResult.Success).value.acceptedStops.size)
        } finally { executor.shutdownNow() }
    }

    @Test fun stopDuringCapacityWaitCancelsWithoutAdmittingOrResumingStart() {
        val (store, next) = fullArchive()
        val gate = RedundantStartOperationGate()
        var cancelledReplies = 0
        assertTrue(gate.begin(next.startOperationId) { cancelledReplies++ })
        val checking = java.util.concurrent.CountDownLatch(1)
        val executor = java.util.concurrent.Executors.newSingleThreadExecutor()
        val before = (store.read() as RecoveryStoreResult.Success).value
        try {
            val start = executor.submit<String> {
                try {
                    awaitAcceptedStopCapacity(store, {
                        checking.countDown(); gate.isCancelled(next.startOperationId)
                    })
                    store.beginRedundant(next)
                    "admitted"
                } catch (error: BackgroundConnectionException) { error.code }
            }
            assertTrue(checking.await(1, java.util.concurrent.TimeUnit.SECONDS))
            assertTrue(gate.cancel(next.startOperationId))
            assertEquals("tunnel_start_cancelled", start.get(1, java.util.concurrent.TimeUnit.SECONDS))
            gate.completeFailure(next.startOperationId) { fail("cancelled Start must not publish failure") }
            gate.finish(next.startOperationId)
            assertEquals(1, cancelledReplies)
            assertFalse(gate.hasPending())
            assertEquals(before, (store.read() as RecoveryStoreResult.Success).value)
            reconcileAcceptedStops(store) { old -> BackgroundReconcileResult("terminal", false,
                old.leaseId, "released", 0, null,
                StopAcceptance(old.operationId, old.sessionId, old.leaseId, false)) }
            assertNull((store.read() as RecoveryStoreResult.Success).value.redundantTransaction)
        } finally { executor.shutdownNow() }
    }

    @Test fun capacityWaitIsBoundedAndPreservesUnconfirmedRecords() {
        val (store, _) = fullArchive()
        val before = (store.read() as RecoveryStoreResult.Success).value
        val executor = java.util.concurrent.Executors.newSingleThreadExecutor()
        try {
            val result = executor.submit<String> {
                try { awaitAcceptedStopCapacity(store, { false }, timeoutMillis = 30); "admitted" }
                catch (error: BackgroundConnectionException) { error.code }
            }
            assertEquals("accepted_stop_capacity_exceeded", result.get(1, java.util.concurrent.TimeUnit.SECONDS))
            assertEquals(before, (store.read() as RecoveryStoreResult.Success).value)
        } finally { executor.shutdownNow() }
    }

    @Test fun cancelledStartCannotPassEvenWhenCapacityIsAlreadyAvailable() {
        val store = AndroidRecoveryStore(Backend(), BootIdentityProvider { 7L })
        try { awaitAcceptedStopCapacity(store, { true }); fail("cancelled") }
        catch (error: BackgroundConnectionException) { assertEquals("tunnel_start_cancelled", error.code) }
    }

    @Test fun availableCapacityNeedsNoWaitOrCleanup() {
        val store = AndroidRecoveryStore(Backend(), BootIdentityProvider { 7L })
        awaitAcceptedStopCapacity(store, { false }, timeoutMillis = 0)
        assertNull((store.read() as RecoveryStoreResult.Success).value.redundantTransaction)
    }

    @Test fun unreadableArchiveFailsClosedWithoutWaitingOrWriting() {
        val backend = Backend().apply { bytes = byteArrayOf(1, 2, 3) }
        val store = AndroidRecoveryStore(backend, BootIdentityProvider { 7L })
        val failure = store.read() as RecoveryStoreResult.Failure
        try { awaitAcceptedStopCapacity(store, { false }); fail("unreadable") }
        catch (error: BackgroundConnectionException) { assertEquals(failure.code, error.code) }
        assertArrayEquals(byteArrayOf(1, 2, 3), backend.bytes)
    }

}
