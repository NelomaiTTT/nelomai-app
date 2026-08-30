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
    }

    @Test
    fun processDeathRecoveryStartsTheLocallyActiveMemberBeforeCanonicalActive() {
        val store = store(transaction(localActiveLeaseId = "lease-a"))
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(store, FakePanel(), native)

        coordinator.recover()

        assertEquals(listOf("lease-a", "lease-b"), native.started)
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

        assertFalse(requireNotNull((store.read() as RecoveryStoreResult.Success).value.redundantTransaction).desiredActive)
        assertEquals(1, panel.stopCalls)
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
) : RedundantConnectionNative {
    val started = mutableListOf<String>()
    override fun start(leaseId: String, configuration: ByteArray): Boolean {
        started += leaseId
        return true
    }
    override fun activate(leaseId: String): Boolean = leaseId in usable
    override fun stopSlot(leaseId: String): Boolean = leaseId in usable
    override fun stop(): Boolean = true
    override fun isUsable(leaseId: String): Boolean = leaseId in usable
}

private class FakePanel(
    private val role: RedundantRoleResponse? = null,
) : RedundantConnectionPanel {
    var stopCalls = 0
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
            configurations = mapOf(
                "lease-a" to "PrivateKey = only-in-memory-a".toByteArray(),
                "lease-b" to "PrivateKey = only-in-memory-b".toByteArray(),
            ),
        )
    override fun reportRole(transaction: AndroidRedundantTransaction, reason: String): RedundantRoleResponse =
        role ?: RedundantRoleResponse("accepted", transaction.localActiveLeaseId!!, session())
    override fun stop(transaction: AndroidRedundantTransaction) { stopCalls += 1 }
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
