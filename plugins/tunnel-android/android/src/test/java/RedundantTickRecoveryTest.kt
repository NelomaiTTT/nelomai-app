package ru.nelomai.tunnel

import org.junit.Assert.*
import org.junit.Test

class RedundantTickRecoveryTest {
    private class Record : EncryptedRecordBackend {
        var bytes: ByteArray? = null
        override fun read() = bytes?.clone()
        override fun write(plaintext: ByteArray): Boolean { bytes = plaintext.clone(); return true }
    }
    private class Native : RedundantConnectionNative {
        var primaryFailed = false
        var standbyFailed = false
        var reads = 0
        var standbySoftFailure = false
        var healthReadFails = false
        var stopSlotFails = false
        var candidateReady = true
        val started = mutableListOf<String>()
        val activated = mutableListOf<String>()
        val slots = mutableMapOf<RedundantSlot, String>()
        override fun start(leaseId: String, slot: RedundantSlot, configuration: ByteArray,
            healthProbe: BackgroundRedundantHealthProbe?): Boolean {
            started += leaseId
            slots[slot] = leaseId
            if (slot == RedundantSlot.A) primaryFailed = false else standbyFailed = false
            return true
        }
        override fun activate(leaseId: String) = (leaseId in slots.values).also {
            if (it) activated += leaseId
        }
        override fun stopSlot(leaseId: String): Boolean {
            if (stopSlotFails) return false
            slots.entries.removeAll { it.value == leaseId }
            return true
        }
        override fun stop(): Boolean { slots.clear(); return true }
        override fun isUsable(leaseId: String) = leaseId in slots.values
        override fun healthObservations(): List<SlotObservation> {
            if (healthReadFails) throw IllegalStateException("metrics_unavailable")
            reads++
            return slots.keys.map { slot ->
                val failed = if (slot == RedundantSlot.A) primaryFailed else standbyFailed
                val warming = slots[slot] == "candidate" && !candidateReady
                SlotObservation(if (slot == RedundantSlot.A) 0 else 1, slot == RedundantSlot.A,
                    if (failed) BackendHealth.UNHEALTHY else if (warming) BackendHealth.WARMING else BackendHealth.READY,
                    hardFailure = failed, handshakeFresh = !failed,
                    consecutiveProbeSuccesses = if (failed) 0 else if (warming) 1 else 3,
                    probeFailed = standbySoftFailure && slot == RedundantSlot.B,
                    independentFailureSignal = standbySoftFailure && slot == RedundantSlot.B,
                    softFailureStartedAtMs = if (standbySoftFailure) 0 else null,
                    corroboratedProbeFailures = if (standbySoftFailure) 2 else 0,
                    stableSinceMs = 0)
            }
        }
    }
    private class Panel : RedundantConnectionPanel {
        var acquires = 0
        var releases = 0
        var commits = 0
        var roleReports = 0
        var releaseFails = false
        var commitFails = false
        var commitError: BackgroundConnectionException? = null
        var loseNextCommitReply = false
        var acquireError: BackgroundConnectionException? = null
        var roleError: BackgroundConnectionException? = null
        var roleSession: BackgroundRedundantSession? = null
        var onRole: (() -> Unit)? = null
        val acquireOperations = mutableListOf<String>()
        private fun session(t: AndroidRedundantTransaction) = BackgroundRedundantSession(
            sessionId=t.sessionId, state="connected", activeLeaseId=t.localActiveLeaseId,
            slotALeaseId=t.slotALeaseId, slotBLeaseId=t.slotBLeaseId, standbyDesired=t.standbyDesired,
            roleGeneration=t.roleGeneration, membershipGeneration=t.membershipGeneration, reason=null)
        // Full configuration replay can fail when the old reserve server is offline.
        override fun recover(transaction: AndroidRedundantTransaction): RedundantRecoveryResponse =
            throw BackgroundConnectionException("connection_retryable")
        override fun reportRole(transaction: AndroidRedundantTransaction, reason: String): RedundantRoleResponse {
            roleReports++
            roleError?.let { throw it }
            onRole?.invoke()
            return RedundantRoleResponse("acknowledged", transaction.localActiveLeaseId!!,
                roleSession ?: session(transaction))
        }
        override fun releaseStandby(transaction: AndroidRedundantTransaction, inactiveLeaseId: String?): BackgroundRedundantSession {
            releases++
            if (releaseFails) throw BackgroundConnectionException("offline")
            return session(transaction).copy(
                slotALeaseId=transaction.slotALeaseId.takeUnless { it == inactiveLeaseId },
                slotBLeaseId=transaction.slotBLeaseId.takeUnless { it == inactiveLeaseId },
                standbyDesired=false)
        }
        override fun acquireStandby(transaction: AndroidRedundantTransaction, operationId: String, replaceLeaseId: String?): BackgroundRedundantCandidate {
            acquires++
            acquireOperations += operationId
            if (roleSession != null && roleSession!!.membershipGeneration != transaction.membershipGeneration)
                throw BackgroundConnectionException("session_membership_conflict")
            acquireError?.let { throw it }
            val slot = if (replaceLeaseId == transaction.slotALeaseId) RedundantSlot.A else RedundantSlot.B
            return BackgroundRedundantCandidate(session(transaction), "candidate", slot,
                QuickConnectionArgs(), byteArrayOf(3), BackgroundRedundantHealthProbe("dns_a", "9.9.9.9", "example.com", 4000))
        }
        override fun commitCandidate(transaction: AndroidRedundantTransaction, candidateLeaseId: String): BackgroundRedundantSession {
            commits++
            if (commitFails) throw BackgroundConnectionException("offline")
            commitError?.let { throw it }
            if (roleSession != null && roleSession!!.membershipGeneration != transaction.membershipGeneration)
                throw BackgroundConnectionException("session_membership_conflict")
            val committed = if (transaction.candidateSlot == RedundantSlot.A)
                session(transaction).copy(slotALeaseId=candidateLeaseId, membershipGeneration=transaction.membershipGeneration+1)
            else session(transaction).copy(slotBLeaseId=candidateLeaseId, membershipGeneration=transaction.membershipGeneration+1)
            if (loseNextCommitReply) {
                loseNextCommitReply = false
                roleSession = committed
                throw BackgroundConnectionException("transport_error")
            }
            return committed
        }
        override fun stop(transaction: AndroidRedundantTransaction) = true
    }
    private fun transaction(standby: Boolean = true) = AndroidRedundantTransaction(
        desiredActive=true, template=AndroidIntentTemplate("11111111-1111-4111-8111-111111111111", "account", "stray", "dynamic", "standalone", "ipv4", true),
        sessionId="22222222-2222-4222-8222-222222222222", slotALeaseId="lease-a",
        slotBLeaseId=if (standby) "lease-b" else null, localActiveLeaseId="lease-a", standbyDesired=true,
        roleGeneration=1, membershipGeneration=1, startOperationId="start-operation", startRequestFingerprint="fingerprint")
    private class Fixture {
        val panel = Panel()
        val native = Native()
        var now = 1_000_000L
        var totalLoss = 0
        val store = AndroidRecoveryStore(Record(), BootIdentityProvider { 1 })
        val coordinator = RedundantConnectionCoordinator(store, panel, native,
            epochNowMs={ now }, monotonicMs={ now }, onAllSlotsStalled={ totalLoss++ })
    }
    private fun start(f: Fixture, standby: Boolean = true) {
        val configs = mutableMapOf("lease-a" to byteArrayOf(1))
        if (standby) configs["lease-b"] = byteArrayOf(2)
        assertTrue(f.coordinator.start(transaction(standby), configs))
        assertTrue(f.coordinator.isRunning())
    }
    @Test fun failedStandbyIsReplacedThroughProductionTick() {
        val f = Fixture(); start(f); f.native.standbyFailed=true
        repeat(121) { f.now+=1000; f.coordinator.tick() }
        assertTrue("No standby acquire after 121 ticks; pending=${f.coordinator.status()?.retry?.acquirePending}", f.panel.acquires>0)
    }
    @Test fun degradedStartEventuallyAcquiresMissingStandby() {
        val f = Fixture(); start(f, false)
        repeat(121) { f.now+=1000; f.coordinator.tick() }
        assertTrue("No acquire for initially degraded session after 121 ticks", f.panel.acquires>0)
    }
    @Test fun acknowledgedReleaseDoesNotRepeatEveryTick() {
        val f = Fixture(); start(f)
        assertTrue(f.coordinator.releaseStandby())
        repeat(20) { f.now+=1000; f.coordinator.tick() }
        assertEquals("Every tick repeats acknowledged release; health reads=${f.native.reads}", 1, f.panel.releases)
    }
    @Test fun primaryFailureDoesNotDeadlockReadyCandidateCommit() {
        val f = Fixture(); start(f)
        assertTrue(f.coordinator.acquireAndCommitStandby("replace", "lease-b"))
        assertEquals("candidate", f.native.slots[RedundantSlot.B])
        f.native.primaryFailed=true
        repeat(40) { f.now+=1000; f.coordinator.tick() }
        assertEquals("candidate", f.coordinator.status()?.localActiveLeaseId)
        assertEquals(1, f.panel.commits)
        assertEquals(0, f.totalLoss)
    }
    @Test fun ordinaryPrimaryFailureSwitchesToHealthyStandby() {
        val f = Fixture(); start(f); f.native.primaryFailed=true
        repeat(20) { f.now+=1000; f.coordinator.tick() }
        assertEquals("lease-b", f.coordinator.status()?.localActiveLeaseId)
        assertEquals(0, f.totalLoss)
    }
    @Test fun primaryFailureAfterReserveDisabledIsDetected() {
        val f = Fixture(); start(f)
        assertTrue(f.coordinator.releaseStandby())
        f.native.primaryFailed=true
        repeat(20) { f.now+=1000; f.coordinator.tick() }
        assertTrue("Primary failure is not observed after reserve disabled; health reads=${f.native.reads}", f.totalLoss>0)
    }
    @Test fun automaticReplacementCanProgressAfterSecondActiveFailure() {
        val f = Fixture(); start(f); f.native.primaryFailed=true
        f.coordinator.tick()
        assertEquals("lease-b", f.coordinator.status()?.localActiveLeaseId)
        repeat(60) { f.now+=1000; f.coordinator.tick() }
        assertEquals("candidate", f.native.slots[RedundantSlot.A])
        assertEquals(0, f.panel.commits)
        f.native.standbyFailed=true
        repeat(40) { f.now+=1000; f.coordinator.tick() }
        assertEquals("candidate", f.coordinator.status()?.localActiveLeaseId)
        assertEquals(1, f.panel.commits)
        assertEquals(0, f.totalLoss)
    }
    @Test fun acknowledgedReleaseStaysCompleteAfterCoordinatorReconstruction() {
        val f = Fixture(); start(f)
        assertTrue(f.coordinator.releaseStandby())
        val reconstructed = RedundantConnectionCoordinator(f.store, f.panel, f.native)
        repeat(20) { assertTrue(reconstructed.tick()) }
        assertEquals(1, f.panel.releases)
    }
    @Test fun failedSingleMemberReleaseSurvivesCoordinatorReconstruction() {
        val f = Fixture(); start(f, false); f.panel.releaseFails=true
        assertFalse(f.coordinator.releaseStandby())
        f.panel.releaseFails=false
        val reconstructed = RedundantConnectionCoordinator(f.store, f.panel, f.native)
        repeat(20) { assertTrue(reconstructed.tick()) }
        assertEquals(2, f.panel.releases)
        assertFalse(requireNotNull(reconstructed.status()).standbyDesired)
    }
    @Test fun failedReleaseDoesNotPreventDetectingActiveFailureOrActivateDisabledReserve() {
        val f = Fixture(); start(f); f.panel.releaseFails=true
        assertFalse(f.coordinator.releaseStandby())
        f.native.primaryFailed=true
        repeat(20) { f.coordinator.tick() }
        assertEquals(1, f.totalLoss)
        assertEquals(listOf("lease-a"), f.native.activated)
    }
    @Test fun failedCandidateCommitWithDeadActiveUsesExistingTotalLossRecovery() {
        val f = Fixture(); start(f)
        assertTrue(f.coordinator.acquireAndCommitStandby("replace", "lease-b"))
        f.panel.commitFails=true
        f.native.primaryFailed=true
        repeat(20) { f.coordinator.tick() }
        assertEquals(1, f.totalLoss)
        assertEquals(listOf("lease-a"), f.native.activated)
    }
    @Test fun confirmedSoftStandbyFailureAlsoSchedulesReplacement() {
        val f = Fixture(); start(f); f.native.standbySoftFailure=true
        f.coordinator.tick()
        assertTrue(requireNotNull(f.coordinator.status()).retry.acquirePending)
        assertEquals("lease-b", f.coordinator.status()?.retry?.acquireReplaceLeaseId)
    }
    @Test fun healthyStandbyAndUnvalidatedNetworkDoNotScheduleReplacement() {
        val f = Fixture(); start(f)
        f.coordinator.tick()
        assertFalse(requireNotNull(f.coordinator.status()).retry.acquirePending)
        f.coordinator.onUnderlyingNetworkChanged(false)
        f.native.standbyFailed=true
        f.coordinator.tick()
        assertFalse(requireNotNull(f.coordinator.status()).retry.acquirePending)
    }
    @Test fun inactiveReplacementKeepsExistingDelayAndDoesNotPostponeItOnEveryTick() {
        val f = Fixture(); start(f); f.native.standbyFailed=true
        f.coordinator.tick()
        repeat(59) { f.now+=1000; f.coordinator.tick() }
        assertEquals(0, f.panel.acquires)
        f.now+=1000
        assertTrue(f.coordinator.tick())
        assertEquals(1, f.panel.acquires)
        assertEquals("lease-a", f.coordinator.status()?.localActiveLeaseId)
        assertTrue(f.coordinator.tick())
        assertEquals("candidate", f.coordinator.status()?.slotBLeaseId)
        assertEquals(1, f.panel.commits)
    }
    @Test fun healthReadFailureDoesNotBlockPendingReleaseRetry() {
        val f = Fixture(); start(f); f.panel.releaseFails=true
        assertFalse(f.coordinator.releaseStandby())
        f.panel.releaseFails=false
        f.native.healthReadFails=true
        assertTrue(f.coordinator.tick())
        assertEquals(2, f.panel.releases)
        assertEquals(null, f.coordinator.status()?.slotBLeaseId)
        assertEquals(0, f.totalLoss)
    }
    @Test fun disabledStandbyCannotBeActivatedEvenWhenItsLocalStopFailed() {
        val f = Fixture(); start(f); f.native.stopSlotFails=true
        assertFalse(f.coordinator.releaseStandby())
        f.native.primaryFailed=true
        f.coordinator.tick()
        assertEquals(1, f.totalLoss)
        assertEquals(listOf("lease-a"), f.native.activated)
    }
    @Test fun readyCandidateInInitiallyEmptySlotCanReplaceDeadActive() {
        val f = Fixture(); start(f, false)
        assertTrue(f.coordinator.acquireAndCommitStandby("acquire-empty"))
        f.native.primaryFailed=true
        assertTrue(f.coordinator.tick())
        assertEquals("candidate", f.coordinator.status()?.localActiveLeaseId)
        assertEquals(1, f.panel.commits)
    }
    @Test fun unreadyCandidateIsNotCommittedOrActivatedWhenActiveFails() {
        val f = Fixture(); start(f)
        assertTrue(f.coordinator.acquireAndCommitStandby("replace", "lease-b"))
        f.native.candidateReady=false
        f.native.primaryFailed=true
        f.coordinator.tick()
        assertEquals(1, f.totalLoss)
        assertEquals(0, f.panel.commits)
        assertEquals(listOf("lease-a"), f.native.activated)
    }
    @Test fun unavailableStandbyHonorsRetryAfterAndReplaysSameOperationAfterReconstruction() {
        val f = Fixture(); start(f, false)
        f.panel.acquireError = BackgroundConnectionException("standby_unavailable", "15")
        f.coordinator.tick()
        repeat(60) { f.now += 1000; f.coordinator.tick() }
        assertEquals(1, f.panel.acquires)
        val reconstructed = RedundantConnectionCoordinator(f.store, f.panel, f.native,
            epochNowMs = { f.now }, monotonicMs = { f.now })
        repeat(14) { f.now += 1000; reconstructed.tick() }
        assertEquals(1, f.panel.acquires)
        f.panel.acquireError = null
        f.now += 1000
        assertTrue(reconstructed.tick())
        assertEquals(2, f.panel.acquires)
        assertEquals(f.panel.acquireOperations.first(), f.panel.acquireOperations.last())
        assertTrue(reconstructed.tick())
        assertEquals("candidate", reconstructed.status()?.slotBLeaseId)
    }
    @Test fun invalidAcquireRetryAfterUsesExistingErrorPolicyFallback() {
        val f = Fixture(); start(f, false)
        f.panel.acquireError = BackgroundConnectionException("standby_unavailable", "invalid")
        f.coordinator.tick()
        repeat(60) { f.now += 1000; f.coordinator.tick() }
        repeat(299) { f.now += 1000; f.coordinator.tick() }
        assertEquals(1, f.panel.acquires)
        f.now += 1000
        f.coordinator.tick()
        assertEquals(2, f.panel.acquires)
    }
    @Test fun acquireBackoffDoesNotDelayActiveFailureDetection() {
        val f = Fixture(); start(f)
        f.native.standbyFailed = true
        f.panel.acquireError = BackgroundConnectionException("standby_unavailable", "15")
        f.coordinator.tick()
        repeat(60) { f.now += 1000; f.coordinator.tick() }
        assertEquals(1, f.panel.acquires)
        f.native.primaryFailed = true
        f.coordinator.tick()
        assertEquals(1, f.totalLoss)
        assertEquals(1, f.panel.acquires)
    }
    @Test fun replayingAnUncommittedCandidateAlsoHonorsAcquireRetryAfter() {
        val f = Fixture(); start(f)
        assertTrue(f.coordinator.acquireAndCommitStandby("replace", "lease-b"))
        f.panel.acquireError = BackgroundConnectionException("connection_retryable", "15")
        val reconstructed = RedundantConnectionCoordinator(f.store, f.panel, f.native,
            epochNowMs = { f.now }, monotonicMs = { f.now })
        assertFalse(reconstructed.tick())
        repeat(14) { f.now += 1000; reconstructed.tick() }
        assertEquals(2, f.panel.acquires)
        f.panel.acquireError = null
        f.now += 1000
        assertTrue(reconstructed.tick())
        assertEquals(3, f.panel.acquires)
        assertTrue(reconstructed.tick())
        assertEquals(1, f.panel.commits)
        assertEquals("candidate", reconstructed.status()?.slotBLeaseId)
    }

    @Test fun expiredLostReplyIsReplacedWithoutRestartingActiveTunnel() {
        val f = Fixture(); start(f, false)
        f.panel.acquireError = BackgroundConnectionException("transport_error")
        assertFalse(f.coordinator.acquireAndCommitStandby("lost-reply"))
        // The panel expires the unseen candidate while the client is backing off.
        f.now += 301_000
        f.panel.acquireError = BackgroundConnectionException("operation_id_conflict")
        f.coordinator.tick()
        assertFalse(requireNotNull(f.coordinator.status()).retry.acquirePending)
        assertEquals("lease-a", f.native.slots[RedundantSlot.A])
        f.panel.acquireError = null
        repeat(62) { f.now += 1000; f.coordinator.tick() }
        assertNotEquals("lost-reply", f.panel.acquireOperations.last())
        assertEquals("candidate", f.coordinator.status()?.slotBLeaseId)
        assertEquals(listOf("lease-a"), f.native.activated)
        assertEquals(0, f.totalLoss)
    }

    @Test fun expiredPersistedCandidateIsRemovedBeforeAcquiringItsReplacement() {
        val f = Fixture(); start(f, false)
        assertTrue(f.coordinator.acquireAndCommitStandby("expired"))
        val reconstructed = RedundantConnectionCoordinator(f.store, f.panel, f.native,
            epochNowMs = { f.now }, monotonicMs = { f.now })
        f.panel.acquireError = BackgroundConnectionException("operation_id_conflict")
        reconstructed.tick()
        assertNull(reconstructed.status()?.candidateLeaseId)
        assertFalse(f.native.slots.containsValue("candidate"))
        f.panel.acquireError = null
        repeat(62) { f.now += 1000; reconstructed.tick() }
        assertNotEquals("expired", f.panel.acquireOperations.last())
        assertEquals("candidate", reconstructed.status()?.slotBLeaseId)
        assertEquals(listOf("lease-a"), f.native.activated)
        assertEquals(1, f.native.started.count { it == "lease-a" })
    }

    @Test fun failedConflictRecoveryKeepsOperationAndItsBackoff() {
        val f = Fixture(); start(f, false)
        f.panel.acquireError = BackgroundConnectionException("operation_id_conflict")
        f.panel.roleError = BackgroundConnectionException("transport_error")
        assertFalse(f.coordinator.acquireAndCommitStandby("uncertain"))
        assertEquals("uncertain", f.coordinator.status()?.retry?.acquireOperationId)
        repeat(299) { f.now += 1000; f.coordinator.tick() }
        assertEquals(1, f.panel.acquires)
        f.panel.roleError = null
        f.now += 1000
        f.coordinator.tick()
        assertFalse(requireNotNull(f.coordinator.status()).retry.acquirePending)
    }

    @Test fun conflictRecoveryPreservesCandidateAlreadyCommittedByPanel() {
        val f = Fixture(); start(f, false)
        assertTrue(f.coordinator.acquireAndCommitStandby("committed"))
        f.panel.roleSession = f.panel.commitCandidate(requireNotNull(f.coordinator.status()), "candidate")
        val reconstructed = RedundantConnectionCoordinator(f.store, f.panel, f.native,
            epochNowMs = { f.now }, monotonicMs = { f.now })
        reconstructed.tick()
        assertFalse(requireNotNull(reconstructed.status()).retry.acquirePending)
        assertEquals("candidate", reconstructed.status()?.slotBLeaseId)
        assertEquals("candidate", f.native.slots[RedundantSlot.B])
        assertEquals(listOf("lease-a"), f.native.activated)
    }

    @Test fun failedExpiredCandidateStopPreservesItsDurableIdentity() {
        val f = Fixture(); start(f, false)
        assertTrue(f.coordinator.acquireAndCommitStandby("expired"))
        val reconstructed = RedundantConnectionCoordinator(f.store, f.panel, f.native,
            epochNowMs = { f.now }, monotonicMs = { f.now })
        f.native.stopSlotFails = true
        f.panel.acquireError = BackgroundConnectionException("operation_id_conflict")
        reconstructed.tick()
        assertEquals("candidate", reconstructed.status()?.candidateLeaseId)
        assertEquals("expired", reconstructed.status()?.retry?.acquireOperationId)
        assertEquals("candidate", f.native.slots[RedundantSlot.B])
        f.native.stopSlotFails = false
        f.now += 300_000
        reconstructed.tick()
        assertNull(reconstructed.status()?.candidateLeaseId)
        assertFalse(f.native.slots.containsValue("candidate"))
    }

    @Test fun revokeDuringConflictRecoveryCannotResurrectAcquire() {
        val f = Fixture(); start(f, false)
        f.panel.acquireError = BackgroundConnectionException("operation_id_conflict")
        var fenced: AndroidRedundantTransaction? = null
        f.panel.onRole = {
            assertTrue(f.coordinator.fenceRevoke())
            fenced = f.coordinator.status()
        }
        assertFalse(f.coordinator.acquireAndCommitStandby("revoked"))
        val stopped = requireNotNull(f.coordinator.status())
        assertFalse(stopped.desiredActive)
        assertEquals(fenced, stopped)
        assertEquals(listOf("lease-a"), f.native.started)
    }

    @Test fun recoveryOfAnotherSessionCannotClearPendingAcquire() {
        val f = Fixture(); start(f, false)
        f.panel.roleSession = BackgroundRedundantSession(
            sessionId="another-session", state="connected", activeLeaseId="lease-a",
            slotALeaseId="lease-a", slotBLeaseId=null, standbyDesired=true,
            roleGeneration=1, membershipGeneration=1, reason=null)
        f.panel.acquireError = BackgroundConnectionException("operation_id_conflict")
        assertFalse(f.coordinator.acquireAndCommitStandby("uncertain"))
        assertEquals("uncertain", f.coordinator.status()?.retry?.acquireOperationId)
        assertTrue(requireNotNull(f.coordinator.status()).retry.acquirePending)
        assertEquals(listOf("lease-a"), f.native.started)
    }

    @Test fun lostCommitReplyIsConfirmedWithoutRestartingPrimary() {
        val f = Fixture(); start(f, false)
        assertTrue(f.coordinator.acquireAndCommitStandby("acquire"))
        f.panel.loseNextCommitReply = true
        repeat(10) { f.now += 1000; f.coordinator.tick() }
        assertEquals("candidate", f.coordinator.status()?.slotBLeaseId)
        assertFalse(requireNotNull(f.coordinator.status()).retry.acquirePending)
        assertEquals(1, f.panel.commits)
        assertEquals(1, f.native.started.count { it == "lease-a" })
        assertEquals(listOf("lease-a"), f.native.activated)
    }

    @Test fun unavailableCommitConfirmationBacksOffAndEventuallyReconciles() {
        val f = Fixture(); start(f, false)
        assertTrue(f.coordinator.acquireAndCommitStandby("acquire"))
        f.panel.loseNextCommitReply = true
        f.panel.roleError = BackgroundConnectionException("transport_error")
        f.coordinator.tick()
        repeat(299) { f.now += 1000; f.coordinator.tick() }
        assertEquals(1, f.panel.commits)
        assertEquals("acquire", f.coordinator.status()?.retry?.acquireOperationId)
        f.panel.roleError = null
        f.now += 1000
        f.coordinator.tick()
        assertEquals("candidate", f.coordinator.status()?.slotBLeaseId)
        assertFalse(requireNotNull(f.coordinator.status()).retry.acquirePending)
    }

    @Test fun failedCommitIsNotConfirmedUntilPanelActuallyAcceptsCandidate() {
        val f = Fixture(); start(f, false)
        assertTrue(f.coordinator.acquireAndCommitStandby("acquire"))
        f.panel.commitFails = true
        f.coordinator.tick()
        assertNull(f.coordinator.status()?.slotBLeaseId)
        assertEquals("candidate", f.coordinator.status()?.candidateLeaseId)
        assertEquals("acquire", f.coordinator.status()?.retry?.acquireOperationId)
        repeat(299) { f.now += 1000; f.coordinator.tick() }
        assertEquals(1, f.panel.commits)
        f.panel.commitFails = false
        f.now += 1000
        f.coordinator.tick()
        assertEquals("candidate", f.coordinator.status()?.slotBLeaseId)
        assertFalse(requireNotNull(f.coordinator.status()).retry.acquirePending)
    }

    @Test fun lostCommitReplyStillAllowsImmediateFailoverToConfirmedCandidate() {
        val f = Fixture(); start(f, false)
        assertTrue(f.coordinator.acquireAndCommitStandby("acquire"))
        f.panel.loseNextCommitReply = true
        f.native.primaryFailed = true
        f.coordinator.tick()
        assertEquals("candidate", f.coordinator.status()?.localActiveLeaseId)
        assertEquals(0, f.totalLoss)
    }

    @Test fun revokeDuringCommitConfirmationPreservesStopFence() {
        val f = Fixture(); start(f, false)
        assertTrue(f.coordinator.acquireAndCommitStandby("acquire"))
        f.panel.loseNextCommitReply = true
        var fenced: AndroidRedundantTransaction? = null
        f.panel.onRole = {
            assertTrue(f.coordinator.fenceRevoke())
            fenced = f.coordinator.status()
        }
        f.coordinator.tick()
        assertNotNull(fenced)
        assertEquals(fenced, f.coordinator.status())
        assertFalse(requireNotNull(f.coordinator.status()).desiredActive)
    }

    @Test fun candidateExpiredDuringCommitBackoffIsReplacedInsteadOfRetriedForever() {
        val f = Fixture(); start(f, false)
        assertTrue(f.coordinator.acquireAndCommitStandby("expired-commit"))
        f.panel.commitFails = true
        f.coordinator.tick()
        // TTL cleanup removes the candidate without changing canonical generations.
        f.now += 301_000
        f.panel.commitFails = false
        f.panel.commitError = BackgroundConnectionException("session_membership_conflict")
        f.coordinator.tick()
        assertNull(f.coordinator.status()?.candidateLeaseId)
        assertFalse(requireNotNull(f.coordinator.status()).retry.acquirePending)
        assertFalse(f.native.slots.containsValue("candidate"))
        f.panel.commitError = null
        repeat(62) { f.now += 1000; f.coordinator.tick() }
        assertNotEquals("expired-commit", f.panel.acquireOperations.last())
        assertEquals("candidate", f.coordinator.status()?.slotBLeaseId)
        assertEquals(listOf("lease-a"), f.native.activated)
    }

    @Test fun readyCommittedCandidateFailsOverBeforeBackgroundRetryDeadline() {
        val f = Fixture(); start(f, false)
        assertTrue(f.coordinator.acquireAndCommitStandby("acquire"))
        f.panel.loseNextCommitReply = true
        f.panel.roleError = BackgroundConnectionException("transport_error")
        f.coordinator.tick()
        f.panel.roleError = null
        f.now += 1000
        f.native.primaryFailed = true
        f.coordinator.tick()
        assertEquals(0, f.totalLoss)
        assertEquals("candidate", f.coordinator.status()?.localActiveLeaseId)
        assertEquals(listOf("lease-a", "candidate"), f.native.activated)
        assertEquals(listOf("lease-a", "candidate"), f.native.started)
        assertEquals(1, f.panel.commits)
        assertEquals(1, f.panel.acquires)
    }

    @Test fun urgentConfirmationFailureUsesOneAttemptAndDoesNotActivateCandidate() {
        val f = Fixture(); start(f, false)
        assertTrue(f.coordinator.acquireAndCommitStandby("acquire"))
        f.panel.loseNextCommitReply = true
        f.panel.roleError = BackgroundConnectionException("transport_error")
        f.coordinator.tick()
        val deadline = f.coordinator.status()?.retry?.nextRetryAtUnix
        f.now += 1000
        f.native.primaryFailed = true
        repeat(10) { f.coordinator.tick() }
        assertEquals(2, f.panel.roleReports) // Initial failed confirmation + one urgent attempt.
        assertEquals(1, f.totalLoss)
        assertEquals(listOf("lease-a"), f.native.activated)
        assertEquals(deadline, f.coordinator.status()?.retry?.nextRetryAtUnix)
        assertEquals(1, f.panel.commits)
        assertEquals(1, f.panel.acquires)
    }

    @Test fun urgentConfirmationDoesNotTreatUncommittedCandidateAsCurrent() {
        val f = Fixture(); start(f, false)
        assertTrue(f.coordinator.acquireAndCommitStandby("acquire"))
        f.panel.commitFails = true
        f.coordinator.tick()
        f.panel.commitFails = false
        f.now += 1000
        f.native.primaryFailed = true
        f.coordinator.tick()
        assertEquals(2, f.panel.roleReports)
        assertEquals(1, f.totalLoss)
        assertEquals(listOf("lease-a"), f.native.activated)
        assertNull(f.coordinator.status()?.slotBLeaseId)
        assertEquals(1, f.panel.commits)
    }

    @Test fun revokeDuringUrgentConfirmationPreventsFailover() {
        val f = Fixture(); start(f, false)
        assertTrue(f.coordinator.acquireAndCommitStandby("acquire"))
        f.panel.loseNextCommitReply = true
        f.panel.roleError = BackgroundConnectionException("transport_error")
        f.coordinator.tick()
        f.panel.roleError = null
        var fenced: AndroidRedundantTransaction? = null
        f.panel.onRole = {
            assertTrue(f.coordinator.fenceRevoke())
            fenced = f.coordinator.status()
        }
        f.now += 1000
        f.native.primaryFailed = true
        f.coordinator.tick()
        assertNotNull(fenced)
        assertEquals(fenced, f.coordinator.status())
        assertFalse(requireNotNull(f.coordinator.status()).desiredActive)
        assertEquals(listOf("lease-a"), f.native.activated)
        assertEquals(0, f.totalLoss)
    }
}
