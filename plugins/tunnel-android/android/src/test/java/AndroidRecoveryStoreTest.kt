package ru.nelomai.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidRecoveryStoreTest {
    @Test
    fun beginStartPublishesIntentAndPendingTransactionInOneRecord() {
        val backend = FakeEncryptedRecordBackend()
        val store = store(backend)

        val envelope = store.beginStart(0, template(), replay()).success()

        assertEquals(1, envelope.intent.generation)
        assertTrue(envelope.intent.desiredActive)
        assertEquals(LeasePhase.START_PENDING, envelope.leaseTransaction?.phase)
        assertEquals("start-operation", envelope.leaseTransaction?.startOperationId)
        assertEquals(1, backend.writeCount)
    }

    @Test
    fun everyLeasePhaseSurvivesProcessDeathWithTheFullReplayRequest() {
        val backend = FakeEncryptedRecordBackend()
        var store = store(backend)
        store.beginStart(0, template(), replay()).success()
        store = store(backend)
        store.recordLease(1, "lease-1").success()
        store = store(backend)
        val active = store.activateCheckpoint(1).success()
        store = store(backend)
        val restored = store.read().success()

        assertEquals(LeasePhase.ACTIVE_CHECKPOINT, active.leaseTransaction?.phase)
        assertEquals(active, restored)
        assertEquals(replay(), restored.leaseTransaction?.replay)
    }

    @Test
    fun cleanupKeepsOneDurableStopOperationIdUntilTerminalConfirmation() {
        val backend = FakeEncryptedRecordBackend()
        var store = store(backend)
        store.beginStart(0, template(), replay()).success()
        store.recordLease(1, "lease-1").success()
        store.requireCleanup(1, "lease-1", "stop-operation").success()
        store = store(backend)

        val pending = store.read().success()
        assertEquals(LeasePhase.CLEANUP_PENDING, pending.leaseTransaction?.phase)
        assertEquals("stop-operation", pending.leaseTransaction?.stopOperationId)
        assertTrue(store.completeCleanup(1).success().leaseTransaction == null)
    }

    @Test
    fun bootMismatchAtomicallyDisarmsIntentAndPreservesCleanup() {
        val backend = FakeEncryptedRecordBackend()
        store(backend, bootCount = 7).beginStart(0, template(), replay()).success()
        store(backend, bootCount = 7).recordLease(1, "lease-1").success()

        val stale = store(backend, bootCount = 8).read().success()

        assertFalse(stale.intent.desiredActive)
        assertEquals(8, stale.intent.bootCount)
        assertEquals(LeasePhase.STALE_CLEANUP, stale.leaseTransaction?.phase)
        assertEquals("lease-1", stale.leaseTransaction?.leaseId)
        assertEquals(stale.intent.generation, stale.leaseTransaction?.generation)
        assertNull(store(backend, bootCount = 8).completeCleanup(stale.intent.generation)
            .success().leaseTransaction)
    }

    @Test
    fun unavailableBootIdentityFailsClosedWithoutDeletingTheTransaction() {
        val backend = FakeEncryptedRecordBackend()
        store(backend, bootCount = 7).beginStart(0, template(), replay()).success()

        val failure = store(backend, bootCount = null).read().failure()

        assertEquals("boot_identity_unavailable", failure.code)
        val persisted = AndroidRecoveryEnvelopeCodec.decode(requireNotNull(backend.record))
        assertFalse(persisted.intent.desiredActive)
        assertEquals(LeasePhase.STALE_CLEANUP, persisted.leaseTransaction?.phase)
    }

    @Test
    fun corruptRecordIsReplacedByAFailClosedEnvelope() {
        val backend = FakeEncryptedRecordBackend("not-json".toByteArray())

        val failure = store(backend).read().failure()

        assertEquals("recovery_record_corrupt", failure.code)
        val persisted = AndroidRecoveryEnvelopeCodec.decode(requireNotNull(backend.record))
        assertFalse(persisted.intent.desiredActive)
        assertNull(persisted.leaseTransaction)
    }

    @Test
    fun corruptCiphertextIsReplacedByAFailClosedEnvelope() {
        val backend = FakeEncryptedRecordBackend(throwCorruptRead = true)

        val failure = store(backend).read().failure()

        assertEquals("recovery_record_corrupt", failure.code)
        backend.throwCorruptRead = false
        assertFalse(store(backend).read().success().intent.desiredActive)
    }

    @Test
    fun structurallyInvalidLeaseCheckpointIsRejectedAsCorrupt() {
        val source = FakeEncryptedRecordBackend()
        store(source).beginStart(0, template(), replay()).success()
        val invalidCheckpoint = requireNotNull(source.record)
            .toString(Charsets.UTF_8)
            .replace("\"phase\":\"start_pending\"", "\"phase\":\"active_checkpoint\"")
            .toByteArray()
        val backend = FakeEncryptedRecordBackend(invalidCheckpoint)

        val failure = store(backend).read().failure()

        assertEquals("recovery_record_corrupt", failure.code)
        assertNull(store(backend).read().success().leaseTransaction)
    }

    @Test
    fun generationOverflowRejectsStartWithoutPublishingARecord() {
        val backend = FakeEncryptedRecordBackend(
            AndroidRecoveryEnvelopeCodec.encode(
                AndroidRecoveryEnvelope.empty(bootCount = 7).copy(
                    intent = AndroidConnectionIntent.empty(7).copy(generation = Long.MAX_VALUE),
                ),
            ),
        )
        val before = backend.record?.copyOf()

        val failure = store(backend).beginStart(Long.MAX_VALUE, template(), replay()).failure()

        assertEquals("connection_intent_generation_exhausted", failure.code)
        assertTrue(before!!.contentEquals(requireNotNull(backend.record)))
    }

    @Test
    fun generationOverflowStillAllowsFailClosedStop() {
        val envelope = AndroidRecoveryEnvelope(
            formatVersion = ANDROID_RECOVERY_FORMAT,
            intent = AndroidConnectionIntent(
                generation = Long.MAX_VALUE,
                bootCount = 7,
                desiredActive = true,
                template = template(),
                retry = AndroidRetryState(),
            ),
            leaseTransaction = AndroidLeaseTransaction(
                generation = Long.MAX_VALUE,
                bootCount = 7,
                phase = LeasePhase.ACTIVE_CHECKPOINT,
                leaseId = "lease-1",
                stopOperationId = null,
                replay = replay(),
            ),
        )
        val backend = FakeEncryptedRecordBackend(AndroidRecoveryEnvelopeCodec.encode(envelope))

        val stopped = store(backend).setDesiredActive(Long.MAX_VALUE, false).success()

        assertFalse(stopped.intent.desiredActive)
        assertEquals(Long.MAX_VALUE, stopped.intent.generation)
        assertEquals(LeasePhase.STALE_CLEANUP, stopped.leaseTransaction?.phase)
    }

    @Test
    fun staleExpectedGenerationCannotOverwriteNewerState() {
        val backend = FakeEncryptedRecordBackend()
        val store = store(backend)
        store.beginStart(0, template(), replay()).success()
        val before = backend.record?.copyOf()

        val failure = store.recordLease(0, "lease-1").failure()

        assertEquals("connection_intent_generation_conflict", failure.code)
        assertTrue(before!!.contentEquals(requireNotNull(backend.record)))
    }

    @Test
    fun failedCommitNeverPublishesAnInMemoryTransition() {
        val backend = FakeEncryptedRecordBackend(failWrites = true)
        val store = store(backend)

        val failure = store.beginStart(0, template(), replay()).failure()

        assertEquals("recovery_record_write_failed", failure.code)
        assertNull(backend.record)
        backend.failWrites = false
        assertEquals(0, store.read().success().intent.generation)
    }

    @Test
    fun backendReadFailureReturnsAStableFailureInsteadOfThrowing() {
        val backend = FakeEncryptedRecordBackend(failReads = true)

        val failure = store(backend).read().failure()

        assertEquals("recovery_record_read_failed", failure.code)
    }

    @Test
    fun quickDesiredActiveMutationIsCasProtectedAndDurable() {
        val backend = FakeEncryptedRecordBackend()
        val store = store(backend)

        val enabled = store.setDesiredActive(0, true).success()
        val staleWrite = store.setDesiredActive(0, false).failure()
        val restored = store(backend).read().success()

        assertTrue(enabled.intent.desiredActive)
        assertEquals(1, enabled.intent.generation)
        assertEquals("connection_intent_generation_conflict", staleWrite.code)
        assertEquals(enabled, restored)
    }

    @Test
    fun failedBootMismatchCommitLeavesThePreviousRecordUntouched() {
        val backend = FakeEncryptedRecordBackend()
        store(backend, bootCount = 7).beginStart(0, template(), replay()).success()
        val before = requireNotNull(backend.record).copyOf()
        backend.failWrites = true

        val failure = store(backend, bootCount = 8).read().failure()

        assertEquals("recovery_record_write_failed", failure.code)
        assertTrue(before.contentEquals(requireNotNull(backend.record)))
    }

    @Test
    fun writeFailureAtEveryMutationBoundaryLeavesThePreviousRecordAuthoritative() {
        val backend = FakeEncryptedRecordBackend()
        val store = store(backend)
        store.beginStart(0, template(), replay()).success()
        failWithoutMutation(backend) { store.recordLease(1, "lease-1") }
        store.recordLease(1, "lease-1").success()
        failWithoutMutation(backend) { store.activateCheckpoint(1) }
        store.activateCheckpoint(1).success()
        failWithoutMutation(backend) { store.requireCleanup(1, "lease-1", "stop-operation") }
        store.requireCleanup(1, "lease-1", "stop-operation").success()
        failWithoutMutation(backend) { store.completeCleanup(1) }
    }

    @Test
    fun plaintextEnvelopeContainsNoCredentialOrTunnelConfigurationFields() {
        val backend = FakeEncryptedRecordBackend()
        store(backend).beginStart(0, template(), replay()).success()

        val plaintext = requireNotNull(backend.record).toString(Charsets.UTF_8).lowercase()
        listOf("configuration", "privatekey", "token", "credential", "installsecret").forEach {
            assertFalse("unexpected secret field $it", plaintext.contains(it))
        }
        assertTrue(plaintext.contains("requestfingerprint"))
    }

    @Test
    fun cleanupBlocksANewStartUntilTheTransactionIsConfirmedTerminal() {
        val backend = FakeEncryptedRecordBackend()
        val store = store(backend)
        store.beginStart(0, template(), replay()).success()
        store.recordLease(1, "lease-1").success()
        store.requireCleanup(1, "lease-1", "stop-operation").success()

        val failure = store.beginStart(1, template(), replay()).failure()

        assertEquals("connection_cleanup_pending", failure.code)
    }

    private fun failWithoutMutation(
        backend: FakeEncryptedRecordBackend,
        mutation: () -> RecoveryStoreResult<AndroidRecoveryEnvelope>,
    ) {
        val before = requireNotNull(backend.record).copyOf()
        backend.failWrites = true
        assertEquals("recovery_record_write_failed", mutation().failure().code)
        backend.failWrites = false
        assertTrue(before.contentEquals(requireNotNull(backend.record)))
    }

    private fun store(
        backend: FakeEncryptedRecordBackend,
        bootCount: Long? = 7,
    ) = AndroidRecoveryStore(backend, FakeBootIdentityProvider(bootCount))

    private fun template() = AndroidIntentTemplate(
        deviceId = "11111111-1111-4111-8111-111111111111",
        accountScope = "account-scope",
        layer = "stray",
        ticConnectionMode = "dynamic",
        routeMode = "standalone",
        egressMode = "ipv4",
        allowAlternate = true,
    )

    private fun replay() = AndroidStartReplay(
        startOperationId = "start-operation",
        contractVersion = 1,
        requestFingerprint = "fingerprint",
    )
}

private class FakeEncryptedRecordBackend(
    initialRecord: ByteArray? = null,
    var failWrites: Boolean = false,
    var failReads: Boolean = false,
    var throwCorruptRead: Boolean = false,
) : EncryptedRecordBackend {
    var record: ByteArray? = initialRecord?.copyOf()
    var writeCount: Int = 0

    override fun read(): ByteArray? {
        if (throwCorruptRead) throw EncryptedRecordCorruptException()
        if (failReads) throw IllegalStateException("read_failed")
        return record?.copyOf()
    }

    override fun write(plaintext: ByteArray): Boolean {
        writeCount += 1
        if (failWrites) return false
        record = plaintext.copyOf()
        return true
    }
}

private class FakeBootIdentityProvider(private val bootCount: Long?) : BootIdentityProvider {
    override fun bootCount(): Long? = bootCount
}

private fun <T> RecoveryStoreResult<T>.success(): T {
    assertTrue(this is RecoveryStoreResult.Success)
    return (this as RecoveryStoreResult.Success).value
}

private fun <T> RecoveryStoreResult<T>.failure(): RecoveryStoreResult.Failure {
    assertTrue(this is RecoveryStoreResult.Failure)
    return this as RecoveryStoreResult.Failure
}
