package ru.nelomai.tunnel

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test

class ReadinessBeforeStopTest {
    private val leaseA = "33333333-3333-4333-8333-333333333333"
    private val leaseB = "66666666-6666-4666-8666-666666666666"
    private val stopId = "55555555-5555-4555-8555-555555555555"
    private val active = AndroidRedundantTransaction(true,
        AndroidIntentTemplate("11111111-1111-4111-8111-111111111111", "account",
            "stray", "dynamic", "standalone", "ipv4", true),
        "22222222-2222-4222-8222-222222222222", leaseA, leaseB, leaseA,
        true, 0, 0, "44444444-4444-4444-8444-444444444444", "a".repeat(64),
        warmStopSupported = true, asyncStopSupported = true,
        retry = AndroidRedundantRetryState(roleObservationPending = true,
            pendingRoleLeaseId = leaseA, pendingRoleReason = "primary_ready"))

    private class Backend : EncryptedRecordBackend {
        var bytes: ByteArray? = null
        var failWrites = false
        var rejectEmptyWrites = false
        override fun read() = bytes?.copyOf()
        override fun write(plaintext: ByteArray): Boolean {
            if (failWrites || (rejectEmptyWrites && !org.json.JSONObject(String(plaintext, Charsets.UTF_8))
                    .has("redundantTransaction"))) return false
            bytes = plaintext.copyOf()
            return true
        }
    }

    private inner class Fixture(transaction: AndroidRedundantTransaction = active, retain: Boolean = true) {
        val backend = Backend()
        var store = AndroidRecoveryStore(backend, BootIdentityProvider { 7L })
        var serverReady = false
        var completeStop = false
        var localStops = 0
        var roleCalls = 0
        val stops = mutableListOf<String>()
        var role: (AndroidRedundantTransaction) -> RedundantRoleResponse = { tx ->
            serverReady = true
            response(tx)
        }
        private val transport = ServiceRedundantConnectionPanel(
            credential = { BackgroundCredential(it, "https://nelomai.example", "token", 1_900_000_000) },
            stopTransport = { _, tx, lease ->
                stops += backgroundRedundantStopPayload(tx, lease).toString()
                if (completeStop) org.json.JSONObject().put("connection", org.json.JSONObject()
                    .put("lease_id", lease).put("status", "released").put("session_id", org.json.JSONObject.NULL))
                else if (serverReady) org.json.JSONObject().put("stop_acceptance", org.json.JSONObject()
                    .put("operation_id", stopId).put("session_id", tx.sessionId)
                    .put("lease_id", lease).put("accepted", true).put("cleanup_pending", true))
                else org.json.JSONObject()
            })
        private val panel = object : RedundantConnectionPanel by transport {
            override fun reportRole(transaction: AndroidRedundantTransaction, reason: String): RedundantRoleResponse {
                assertEquals("primary_ready", reason)
                assertFalse(transaction.desiredActive)
                assertEquals(RedundantStopState.PENDING, transaction.retry.stopState)
                roleCalls++
                return role(transaction)
            }
        }
        private val native = object : RedundantConnectionNative {
            override fun start(leaseId: String, slot: RedundantSlot, configuration: ByteArray,
                healthProbe: BackgroundRedundantHealthProbe?) = error("Stop must never start native")
            override fun activate(leaseId: String) = error("Stop must never switch native")
            override fun stopSlot(leaseId: String) = true
            override fun stop(): Boolean { localStops++; return true }
            override fun isUsable(leaseId: String) = false
        }
        var coordinator = owner()
        init {
            assertTrue(store.beginRedundant(transaction) is RecoveryStoreResult.Success)
            assertTrue(store.cancelRedundantIntentAndDeferStop(stopId, active.startOperationId,
                retainActivePeer = retain) is RecoveryStoreResult.Success)
        }
        private fun owner() = RedundantConnectionCoordinator(store, panel, native,
            expectedStartOperationId = active.startOperationId)
        fun reopen() {
            store = AndroidRecoveryStore(backend, BootIdentityProvider { 7L })
            coordinator = owner()
        }
        fun envelope() = (store.read() as RecoveryStoreResult.Success).value
        fun response(tx: AndroidRedundantTransaction, action: String = "acknowledged",
            roleGeneration: Long = tx.roleGeneration, membershipGeneration: Long = tx.membershipGeneration) =
            RedundantRoleResponse(action, requireNotNull(tx.localActiveLeaseId),
                BackgroundRedundantSession(tx.sessionId, "connected", tx.localActiveLeaseId,
                    tx.slotALeaseId, tx.slotBLeaseId, tx.standbyDesired,
                    roleGeneration, membershipGeneration, null))
    }

    @Test fun stopPreservesOnlyProvenCurrentPrimaryReadinessAcrossRecreation() {
        for ((tx, retained) in listOf(active to true,
            active.copy(retry = active.retry.copy(pendingRoleReason = "primary_unhealthy")) to false,
            active.copy(retry = active.retry.copy(pendingRoleLeaseId = leaseB)) to false,
            active.copy(retry = active.retry.copy(pendingNativeSourceLeaseId = leaseA,
                pendingNativeActiveLeaseId = leaseB, pendingNativeActiveSlot = RedundantSlot.B,
                pendingNativeMembershipGeneration = 0, pendingNativeSwitchReason = "primary_ready")) to false)) {
            val f = Fixture(tx)
            f.reopen()
            val pending = f.envelope().redundantTransaction!!
            assertFalse(pending.desiredActive)
            assertEquals(retained, pending.retry.roleObservationPending)
            assertEquals(if (retained) "primary_ready" else null, pending.retry.pendingRoleReason)
        }
    }

    @Test fun immediateStopConfirmsEitherPrimaryBeforeAcceptanceAndDetachesOnlyAfterLocalClose() {
        for (lease in listOf(leaseA, leaseB)) {
            val f = Fixture(active.copy(localActiveLeaseId = lease,
                retry = active.retry.copy(pendingRoleLeaseId = lease)))
            assertTrue(f.coordinator.revoke())
            assertEquals(1, f.localStops)
            assertEquals(1, f.roleCalls)
            val state = f.envelope()
            assertNull(state.redundantTransaction)
            assertEquals(lease, state.acceptedStops.single().leaseId)
            assertFalse(state.intent.desiredActive)
        }
    }

    @Test fun initialNotificationAlsoConfirmsReadinessWithoutDiscardingDurableStop() {
        val f = Fixture()
        f.coordinator.notifyStop()
        assertTrue(f.serverReady)
        assertEquals(1, f.stops.size)
        assertNotNull(f.envelope().redundantTransaction)
        assertTrue(f.envelope().acceptedStops.isEmpty())
        assertTrue(f.coordinator.revoke())
        assertEquals(f.stops[0], f.stops[1])
    }

    @Test fun acknowledgedReadinessDoesNotGateAcceptedStopOnLaterRoleFailure() {
        checkAcknowledgedReadinessReplay(false)
    }

    @Test fun acknowledgedReadinessAfterRecreationDoesNotGateAcceptedStopOnLaterRoleFailure() {
        checkAcknowledgedReadinessReplay(true)
    }

    private fun checkAcknowledgedReadinessReplay(recreate: Boolean) {
        val f = Fixture()
        f.coordinator.notifyStop()
        assertTrue(f.serverReady)
        assertEquals(1, f.stops.size)
        if (recreate) f.reopen()
        f.role = { throw BackgroundConnectionException("background_transport_unavailable") }
        assertTrue(f.coordinator.revoke())
        assertEquals(1, f.roleCalls)
        assertEquals(f.stops[0], f.stops[1])
        assertEquals(stopId, f.envelope().acceptedStops.single().operationId)
    }

    @Test fun failedReadinessAcknowledgementWriteKeepsProofForReplay() {
        val f = Fixture()
        f.role = { tx ->
            f.serverReady = true
            f.backend.failWrites = true
            f.response(tx)
        }
        f.coordinator.notifyStop()
        assertTrue(f.stops.isEmpty())
        f.backend.failWrites = false
        f.reopen()
        assertTrue(f.envelope().redundantTransaction!!.retry.roleObservationPending)
        f.role = { f.response(it) }
        assertTrue(f.coordinator.revoke())
        assertEquals(2, f.roleCalls)
        assertEquals(stopId, f.envelope().acceptedStops.single().operationId)
    }

    @Test fun concurrentReadinessAcknowledgementOutlivesAnotherRequestsTransportFailure() {
        val f = Fixture()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val stopped = java.util.concurrent.atomic.AtomicBoolean()
        f.role = { tx ->
            if (f.roleCalls == 1) {
                entered.countDown()
                check(release.await(5, TimeUnit.SECONDS))
                throw BackgroundConnectionException("background_transport_unavailable")
            }
            f.serverReady = true
            f.response(tx)
        }
        val worker = Thread { stopped.set(f.coordinator.revoke()) }.also { it.start() }
        try {
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            f.coordinator.notifyStop()
            assertFalse(f.envelope().redundantTransaction!!.retry.roleObservationPending)
            release.countDown()
            worker.join(2_000)
            assertFalse(worker.isAlive)
            assertTrue(stopped.get())
            assertEquals(stopId, f.envelope().acceptedStops.single().operationId)
            assertEquals(f.stops[0], f.stops[1])
        } finally { release.countDown(); worker.join(2_000) }
    }

    @Test fun cleanupAcknowledgementCannotRestoreDeliveredReadinessAfterFailedCompletionWrite() {
        val f = Fixture()
        f.completeStop = true
        f.backend.rejectEmptyWrites = true
        assertFalse(f.coordinator.revoke())
        val pending = f.envelope().redundantTransaction!!
        assertEquals(RedundantStopState.ACKNOWLEDGED, pending.retry.stopState)
        assertFalse(pending.retry.roleObservationPending)
        assertNull(pending.retry.pendingRoleLeaseId)
        assertNull(pending.retry.pendingRoleReason)
        f.backend.rejectEmptyWrites = false
        f.reopen()
        f.role = { throw BackgroundConnectionException("background_transport_unavailable") }
        assertTrue(f.coordinator.revoke())
        assertEquals(1, f.roleCalls)
        assertNull(f.envelope().redundantTransaction)
    }

    @Test fun lostReadinessReplyRetriesBeforeStopAfterProcessRecreation() {
        val f = Fixture()
        f.role = { f.serverReady = true; throw BackgroundConnectionException("background_transport_unavailable") }
        f.coordinator.notifyStop()
        assertTrue(f.stops.isEmpty())
        assertFalse(f.coordinator.revoke())
        assertTrue(f.localStops > 0)
        assertTrue(f.stops.isEmpty())
        assertTrue(f.envelope().redundantTransaction!!.retry.roleObservationPending)
        f.reopen()
        f.role = { f.response(it) }
        assertTrue(f.coordinator.revoke())
        assertEquals(1, f.stops.size)
        assertEquals(stopId, f.envelope().acceptedStops.single().operationId)
    }

    @Test fun rebasedReadinessIsResentBeforeStopWithFrozenStopPayload() {
        val f = Fixture()
        val pending = f.envelope().redundantTransaction!!
        val payload = backgroundRedundantStopPayload(pending, leaseA).toString()
        f.role = { tx ->
            if (tx.membershipGeneration == 0L) f.response(tx, "rebase", 2, 3)
            else {
                assertEquals(2L, tx.roleGeneration)
                assertEquals(3L, tx.membershipGeneration)
                f.serverReady = true
                f.response(tx)
            }
        }
        assertTrue(f.coordinator.revoke())
        assertEquals(2, f.roleCalls)
        assertEquals(listOf(payload), f.stops)
    }

    @Test fun repeatedRebaseDefersStopRatherThanClaimingReadinessWasAcknowledged() {
        val f = Fixture()
        f.role = { tx -> f.response(tx, "rebase", tx.roleGeneration + 1, tx.membershipGeneration + 1) }
        assertFalse(f.coordinator.revoke())
        assertEquals(2, f.roleCalls)
        assertTrue(f.stops.isEmpty())
        assertNotNull(f.envelope().redundantTransaction)
    }

    @Test fun mismatchedReadinessReplyCannotReleaseStopBarrier() {
        for (invalid in listOf<(RedundantRoleResponse) -> RedundantRoleResponse>(
            { it.copy(session = it.session.copy(sessionId = "other")) },
            { it.copy(localActiveLeaseId = leaseB) },
            { it.copy(session = it.session.copy(slotALeaseId = null)) },
            { it.copy(action = "unknown") })) {
            val f = Fixture()
            f.role = { invalid(f.response(it)) }
            assertFalse(f.coordinator.revoke())
            assertTrue(f.stops.isEmpty())
            assertNotNull(f.envelope().redundantTransaction)
        }
    }

    @Test fun fencedReadinessCannotPreventOrdinaryCleanupOrFabricateAcceptance() {
        for (code in listOf("session_membership_conflict", "invalid_background_token")) {
            val f = Fixture()
            f.role = { throw BackgroundConnectionException(code) }
            assertFalse(f.coordinator.revoke())
            assertEquals(1, f.stops.size)
            assertNotNull(f.envelope().redundantTransaction)
            assertTrue(f.envelope().acceptedStops.isEmpty())
            // A prior accepted Stop may already have fenced the session while its reply was lost.
            f.serverReady = true
            assertTrue(f.coordinator.revoke())
            assertEquals(f.stops[0], f.stops[1])
        }
    }

    @Test fun readinessHttpCannotDelayLocalTunClose() {
        val f = Fixture()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        f.role = { tx ->
            entered.countDown()
            check(release.await(5, TimeUnit.SECONDS))
            f.response(tx)
        }
        val worker = Thread { f.coordinator.notifyStop() }.also { it.start() }
        try {
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            assertTrue(f.coordinator.closeDataplaneForStop())
            assertEquals(1, f.localStops)
            assertNotNull(f.envelope().redundantTransaction)
        } finally { release.countDown(); worker.join(2_000) }
        assertFalse(worker.isAlive)
    }

    @Test fun coldAndLegacyStopsDoNotWaitForUnneededReadinessHttp() {
        for (f in listOf(Fixture(active.copy(asyncStopSupported = false)), Fixture(retain = false))) {
            f.role = { throw BackgroundConnectionException("background_transport_unavailable") }
            assertFalse(f.coordinator.revoke())
            assertEquals(0, f.roleCalls)
            assertEquals(1, f.stops.size)
            assertTrue(f.localStops > 0)
        }
    }

    @Test fun lateNotificationCannotMutateNewStartAfterConcurrentStopAcceptance() {
        for (acknowledge in listOf(false, true)) checkLateNotification(acknowledge)
    }

    private fun checkLateNotification(acknowledge: Boolean) {
        val f = Fixture()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        f.role = { tx ->
            if (f.roleCalls == 1) {
                entered.countDown()
                check(release.await(5, TimeUnit.SECONDS))
                if (!acknowledge) throw BackgroundConnectionException("session_membership_conflict")
            }
            f.serverReady = true
            f.response(tx)
        }
        val worker = Thread { f.coordinator.notifyStop() }.also { it.start() }
        try {
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            assertTrue(f.coordinator.revoke())
            val next = active.copy(sessionId = "77777777-7777-4777-8777-777777777777",
                startOperationId = "88888888-8888-4888-8888-888888888888")
            assertTrue(f.store.beginRedundant(next) is RecoveryStoreResult.Success)
            val snapshot = f.envelope()
            release.countDown()
            worker.join(2_000)
            assertFalse(worker.isAlive)
            assertEquals(snapshot, f.envelope())
            assertEquals(next, f.envelope().redundantTransaction)
            assertTrue(f.stops.all { it == f.stops.first() })
        } finally { release.countDown(); worker.join(2_000) }
    }
}
