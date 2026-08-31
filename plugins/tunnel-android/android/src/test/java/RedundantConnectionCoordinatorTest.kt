package ru.nelomai.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RedundantConnectionCoordinatorTest {
    @Test
    fun v2RecoveryEnvelopeNeverEntersLegacyVpnRecovery() {
        val envelope = AndroidRecoveryEnvelope(
            formatVersion = ANDROID_RECOVERY_FORMAT,
            intent = AndroidConnectionIntent.empty(1),
            leaseTransaction = null,
            redundantTransaction = transaction(),
        )

        assertFalse(shouldEnterLegacyVpnRecovery(RecoveryStoreResult.Success(envelope)))
        assertFalse(shouldEnterLegacyVpnRecovery(RecoveryStoreResult.Failure("recovery_record_corrupt")))
    }

    @Test
    fun deferredVpnOwnerRecoversV2BeforeLegacyAndFailsClosedWhenUnavailable() {
        var legacyCalls = 0
        val owner = FakeVpnOwner(recoverResult = true)

        assertTrue(routeVpnProcessRecovery(
            RecoveryStoreResult.Success(v2Envelope()), owner, { legacyCalls += 1 },
        ))
        assertEquals(1, owner.recoverCalls)
        assertEquals(0, legacyCalls)
        assertFalse(routeVpnProcessRecovery(
            RecoveryStoreResult.Success(v2Envelope()), null, { legacyCalls += 1 },
        ))
        assertEquals(0, legacyCalls)
        assertTrue(routeVpnProcessRevoke(
            RecoveryStoreResult.Success(v2Envelope()), owner, { legacyCalls += 1 },
        ))
        assertEquals(0, legacyCalls)
    }

    @Test
    fun processDeathRecoveryStartsTheLocallyActiveMemberBeforeCanonicalActive() {
        val store = store(transaction(localActiveLeaseId = "lease-a"))
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(store, FakePanel(), native)

        coordinator.recover()

        assertEquals(listOf("lease-a", "lease-b"), native.started)
        assertEquals(listOf("lease-a"), native.activated)
    }

    @Test
    fun recoveryRequiresAndActivatesTheLocalActiveConfigurationWhileStandbyIsBestEffort() {
        val native = FakeNative(startFailures = setOf("lease-b"))
        val coordinator = RedundantConnectionCoordinator(store(transaction()), FakePanel(), native)

        assertTrue(coordinator.recover())
        assertEquals(listOf("lease-a", "lease-b"), native.started)
        assertEquals(listOf("lease-a"), native.activated)

        val missingActive = RedundantConnectionCoordinator(
            store(transaction()),
            FakePanel(configurations = mapOf("lease-b" to "standby".toByteArray())),
            FakeNative(),
        )
        assertFalse(missingActive.recover())
    }

    @Test
    fun aSingleSlotFailureDoesNotInvokeLegacyStalledStop() {
        val native = FakeNative(usable = setOf("lease-b"))
        var legacyStops = 0
        val coordinator = RedundantConnectionCoordinator(
            store(transaction()),
            FakePanel(),
            native,
            onAllSlotsStalled = { legacyStops += 1 },
        )

        coordinator.slotFailed("lease-a", "primary_unhealthy")

        assertEquals(0, legacyStops)
        assertEquals("lease-b", coordinator.status()?.localActiveLeaseId)
    }

    @Test
    fun revokeClearsDesiredActiveBeforeQueuingOneSessionStop() {
        val store = store(transaction())
        val panel = FakePanel()
        val coordinator = RedundantConnectionCoordinator(store, panel, FakeNative()) {
            error("both slots are not stalled")
        }

        coordinator.revoke()
        coordinator.revoke()

        assertEquals(null, (store.read() as RecoveryStoreResult.Success).value.redundantTransaction)
        assertEquals(1, panel.stopCalls)
    }

    @Test
    fun pendingStopReplaysSameOperationAfterFailureAndClearsOnlyAfterBothAcknowledgements() {
        val store = store(transaction())
        val panel = FakePanel(stopResults = ArrayDeque(listOf(false, true)))
        val native = FakeNative(stopResults = ArrayDeque(listOf(true, true)))
        val first = RedundantConnectionCoordinator(store, panel, native, operationId = { "stop-1" })

        assertFalse(first.revoke())
        val pending = requireNotNull(first.status())
        assertFalse(pending.desiredActive)
        assertEquals("stop-1", pending.stopOperationId)
        assertEquals(RedundantStopState.PENDING, pending.retry.stopState)

        val replayed = RedundantConnectionCoordinator(store, panel, native)
        assertTrue(replayed.revoke())
        assertEquals(2, panel.stopCalls)
        assertEquals(2, native.stopCalls)
        assertEquals(null, replayed.status())
        assertTrue(replayed.start(transaction(), mapOf("lease-a" to "active".toByteArray())))
    }

    @Test
    fun roleRebaseAdoptsCanonicalGenerationsWithoutRollingBackLocalDataplaneActive() {
        val panel = FakePanel(role = RedundantRoleResponse(
            action = "rebase",
            localActiveLeaseId = "lease-a",
            session = session(activeLeaseId = "lease-b", roleGeneration = 7, membershipGeneration = 3),
        ))
        val coordinator = RedundantConnectionCoordinator(store(transaction()), panel, FakeNative()) {}

        coordinator.reportLocalRole("primary_unhealthy")

        val transaction = requireNotNull(coordinator.status())
        assertEquals("lease-a", transaction.localActiveLeaseId)
        assertEquals(7, transaction.roleGeneration)
        assertEquals(3, transaction.membershipGeneration)
        assertEquals(2, panel.roleCalls)
        assertFalse(transaction.retry.roleObservationPending)
    }

    @Test
    fun roleObservationIsDurableBeforeActivationAndReplayedAfterProcessDeath() {
        val store = store(transaction())
        val panel = FakePanel(roleFailures = ArrayDeque(listOf(true, false)))
        val native = FakeNative(usable = setOf("lease-b"))
        val first = RedundantConnectionCoordinator(store, panel, native)

        assertTrue(first.slotFailed("lease-a", "primary_unhealthy"))
        val pending = requireNotNull(first.status())
        assertTrue(pending.retry.roleObservationPending)
        assertEquals("lease-b", pending.retry.pendingRoleLeaseId)
        assertEquals("primary_unhealthy", pending.retry.pendingRoleReason)

        assertTrue(RedundantConnectionCoordinator(store, panel, native).reportLocalRole("ignored"))
        assertFalse(requireNotNull(first.status()).retry.roleObservationPending)
    }

    @Test
    fun acquireIdentityIsDurableBeforeRequestAndReplayedWithTheSameOperation() {
        val store = store(transaction())
        val panel = FakePanel(acquireFailures = ArrayDeque(listOf(true, false)))
        val coordinator = RedundantConnectionCoordinator(store, panel, FakeNative())

        assertFalse(coordinator.acquireAndCommitStandby("acquire-1"))
        val pending = requireNotNull(coordinator.status())
        assertEquals("acquire-1", pending.retry.acquireOperationId)
        assertTrue(pending.retry.acquirePending)

        assertTrue(RedundantConnectionCoordinator(store, panel, FakeNative()).acquireAndCommitStandby("different"))
        assertEquals(listOf("acquire-1", "acquire-1"), panel.acquireOperationIds)
    }

    @Test
    fun duplicateStopAndRecoveryCallbacksAreIdempotent() {
        val panel = FakePanel()
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(store(transaction()), panel, native) {}

        coordinator.recover()
        coordinator.recover()
        coordinator.revoke()
        coordinator.revoke()

        assertEquals(listOf("lease-a", "lease-b"), native.started)
        assertEquals(1, panel.stopCalls)
    }

    private fun store(transaction: AndroidRedundantTransaction): AndroidRecoveryStore {
        val backend = CoordinatorRecordBackend()
        backend.write(AndroidRecoveryEnvelopeCodec.encode(AndroidRecoveryEnvelope(
            formatVersion = ANDROID_RECOVERY_FORMAT,
            intent = AndroidConnectionIntent.empty(1),
            leaseTransaction = null,
            redundantTransaction = transaction,
        )))
        return AndroidRecoveryStore(backend, CoordinatorBootIdentity())
    }

    private fun v2Envelope() = AndroidRecoveryEnvelope(
        formatVersion = ANDROID_RECOVERY_FORMAT,
        intent = AndroidConnectionIntent.empty(1),
        leaseTransaction = null,
        redundantTransaction = transaction(),
    )

    private fun transaction(localActiveLeaseId: String? = "lease-a") = AndroidRedundantTransaction(
        desiredActive = true,
        template = AndroidIntentTemplate(
            deviceId = "11111111-1111-4111-8111-111111111111",
            accountScope = "account",
            layer = "stray",
            ticConnectionMode = "dynamic",
            routeMode = "standalone",
            egressMode = "ipv4",
            allowAlternate = true,
        ),
        sessionId = "22222222-2222-4222-8222-222222222222",
        slotALeaseId = "lease-a",
        slotBLeaseId = "lease-b",
        localActiveLeaseId = localActiveLeaseId,
        standbyDesired = true,
        roleGeneration = 1,
        membershipGeneration = 1,
        startOperationId = "start-operation",
        startRequestFingerprint = "fingerprint",
    )

    private fun session(
        activeLeaseId: String,
        roleGeneration: Long,
        membershipGeneration: Long,
    ) = BackgroundRedundantSession(
        sessionId = "22222222-2222-4222-8222-222222222222",
        state = "connected",
        activeLeaseId = activeLeaseId,
        slotALeaseId = "lease-a",
        slotBLeaseId = "lease-b",
        standbyDesired = true,
        roleGeneration = roleGeneration,
        membershipGeneration = membershipGeneration,
        reason = null,
    )
}

private class CoordinatorRecordBackend : EncryptedRecordBackend {
    var record: ByteArray? = null
    override fun read(): ByteArray? = record?.copyOf()
    override fun write(plaintext: ByteArray): Boolean {
        record = plaintext.copyOf()
        return true
    }
}

private class CoordinatorBootIdentity : BootIdentityProvider {
    override fun bootCount(): Long = 1
}

private class FakeNative(
    private val usable: Set<String> = setOf("lease-a", "lease-b"),
    private val startFailures: Set<String> = emptySet(),
    private val stopResults: ArrayDeque<Boolean> = ArrayDeque(),
) : RedundantConnectionNative {
    val started = mutableListOf<String>()
    val activated = mutableListOf<String>()
    var stopCalls = 0
    override fun start(leaseId: String, configuration: ByteArray): Boolean {
        started += leaseId
        return leaseId !in startFailures
    }
    override fun activate(leaseId: String): Boolean = (leaseId in usable).also {
        if (it) activated += leaseId
    }
    override fun stopSlot(leaseId: String): Boolean = leaseId in usable
    override fun stop(): Boolean {
        stopCalls += 1
        return stopResults.removeFirstOrNull() ?: true
    }
    override fun isUsable(leaseId: String): Boolean = leaseId in usable
}

private class FakePanel(
    private val role: RedundantRoleResponse? = null,
    private val configurations: Map<String, ByteArray>? = null,
    private val stopResults: ArrayDeque<Boolean> = ArrayDeque(),
    private val roleFailures: ArrayDeque<Boolean> = ArrayDeque(),
    private val acquireFailures: ArrayDeque<Boolean> = ArrayDeque(),
) : RedundantConnectionPanel {
    var stopCalls = 0
    var roleCalls = 0
    val acquireOperationIds = mutableListOf<String>()
    override fun recover(transaction: AndroidRedundantTransaction): RedundantRecoveryResponse =
        RedundantRecoveryResponse(
            session = BackgroundRedundantSession(
                sessionId = transaction.sessionId,
                state = "connected",
                activeLeaseId = "lease-b",
                slotALeaseId = "lease-a",
                slotBLeaseId = "lease-b",
                standbyDesired = true,
                roleGeneration = 2,
                membershipGeneration = 2,
                reason = null,
            ),
            configurations = configurations ?: mapOf(
                "lease-a" to "PrivateKey = only-in-memory-a".toByteArray(),
                "lease-b" to "PrivateKey = only-in-memory-b".toByteArray(),
            ),
        )
    override fun reportRole(transaction: AndroidRedundantTransaction, reason: String): RedundantRoleResponse {
        roleCalls += 1
        if (roleFailures.removeFirstOrNull() == true) throw BackgroundConnectionException("offline")
        return if (role?.action == "rebase" && roleCalls > 1) {
            RedundantRoleResponse("accepted", transaction.localActiveLeaseId!!, role.session)
        } else {
            role ?: RedundantRoleResponse("accepted", transaction.localActiveLeaseId!!, session())
        }
    }
    override fun acquireStandby(
        transaction: AndroidRedundantTransaction,
        operationId: String,
    ): BackgroundRedundantCandidate {
        acquireOperationIds += operationId
        if (acquireFailures.removeFirstOrNull() == true) throw BackgroundConnectionException("offline")
        return BackgroundRedundantCandidate(
            session(), "candidate", RedundantSlot.B, QuickConnectionArgs(), "candidate-config".toByteArray(),
        )
    }
    override fun commitCandidate(
        transaction: AndroidRedundantTransaction,
        candidateLeaseId: String,
    ): BackgroundRedundantSession = session()
    override fun stop(transaction: AndroidRedundantTransaction): Boolean {
        stopCalls += 1
        return stopResults.removeFirstOrNull() ?: true
    }
    private fun session() = BackgroundRedundantSession(
        sessionId = "22222222-2222-4222-8222-222222222222",
        state = "connected",
        activeLeaseId = "lease-a",
        slotALeaseId = "lease-a",
        slotBLeaseId = "lease-b",
        standbyDesired = true,
        roleGeneration = 2,
        membershipGeneration = 2,
        reason = null,
    )
}

private class FakeVpnOwner(private val recoverResult: Boolean) : RedundantVpnProcessOwner {
    var recoverCalls = 0
    override fun recover(): Boolean {
        recoverCalls += 1
        return recoverResult
    }
    override fun revoke(): Boolean = true
}
