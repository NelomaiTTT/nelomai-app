package ru.nelomai.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidRecoveryStoreTest {
    @Test
    fun activeCheckpointPersistsArmedHistoryAcrossProcessDeath() {
        val backend = FakeEncryptedRecordBackend()
        var store = store(backend)
        val initial = store.beginStart(0, template(), replay()).success()
        assertFalse(initial.intent.armedHistory)

        store.recordLease(1, "lease-1").success()
        store.activateCheckpoint(1).success()
        store = store(backend)

        assertTrue(store.read().success().intent.armedHistory)
    }

    @Test
    fun activeCheckpointAtomicallyRotatesDiagnosticsWithoutBumpingRecoveryGeneration() {
        val backend = FakeEncryptedRecordBackend()
        var store = store(backend)
        val started = store.beginStart(0, template(), replay()).success()
        store.recordLease(1, "lease-1").success()

        val active = store.activateCheckpoint(1).success()
        store = store(backend)
        val reconstructed = store.read().success()

        assertEquals(1L, started.intent.diagnosticsEpisodeId)
        assertEquals(1L, active.intent.generation)
        assertEquals(1L, active.leaseTransaction?.generation)
        assertEquals(2L, active.intent.diagnosticsEpisodeId)
        assertEquals(active, reconstructed)
    }

    @Test
    fun repeatedSuccessfulCheckpointRotationsRemainMonotonicInOneRecoveryGeneration() {
        val store = store(FakeEncryptedRecordBackend())
        store.beginStart(0, template(), replay()).success()
        store.recordLease(1, "lease-1").success()
        val first = store.activateCheckpoint(1).success()

        val second = store.activateCheckpoint(1).success()

        assertEquals(1L, second.intent.generation)
        assertEquals(first.intent.diagnosticsEpisodeId + 1, second.intent.diagnosticsEpisodeId)
        assertEquals(LeasePhase.ACTIVE_CHECKPOINT, second.leaseTransaction?.phase)
    }

    @Test
    fun diagnosticsEpisodeCounterStaysMonotonicWhenRecoveryGenerationMovesIndependently() {
        assertEquals(13L, nextAndroidDiagnosticsEpisodeId(12, 8))
        assertEquals(12L, nextAndroidDiagnosticsEpisodeId(7, 12))
        assertNull(nextAndroidDiagnosticsEpisodeId(Long.MAX_VALUE, Long.MAX_VALUE))
    }

    @Test
    fun diagnosticsEpisodeSurvivesCancelAndBootTombstonesAcrossProcessDeath() {
        val backend = FakeEncryptedRecordBackend()
        var store = store(backend, bootCount = 7)
        val started = store.beginStart(0, template(), replay()).success()

        val cancelled = store.cancelCurrentIntent().success()
        store = store(backend, bootCount = 8)
        val stale = store.read().success()

        assertEquals(1L, started.intent.diagnosticsEpisodeId)
        assertEquals(1L, cancelled.intent.diagnosticsEpisodeId)
        assertEquals(1L, stale.intent.diagnosticsEpisodeId)
        assertTrue(stale.intent.generation > started.intent.generation)
    }

    @Test
    fun missingDiagnosticsEpisodeInV1AndV2DefaultsToPersistedGeneration() {
        val backend = FakeEncryptedRecordBackend()
        store(backend).beginStart(0, template(), replay()).success()
        val currentPayload = org.json.JSONObject(
            requireNotNull(backend.record).toString(Charsets.UTF_8),
        )
        currentPayload.getJSONObject("intent").remove("diagnosticsEpisodeId")

        val restoredV2 = AndroidRecoveryEnvelopeCodec.decode(
            currentPayload.toString().toByteArray(),
        )
        currentPayload.put("formatVersion", 1)
        val restoredV1 = AndroidRecoveryEnvelopeCodec.decode(
            currentPayload.toString().toByteArray(),
        )

        assertEquals(restoredV2.intent.generation, restoredV2.intent.diagnosticsEpisodeId)
        assertEquals(restoredV1.intent.generation, restoredV1.intent.diagnosticsEpisodeId)
    }

    @Test
    fun initialTerminalAfterAcquiredLeaseDisarmsAndClearsEpisodeAfterExactCleanup() {
        val backend = FakeEncryptedRecordBackend()
        var store = store(backend)
        store.beginStart(0, template(), replay()).success()
        store.recordLease(1, "lease-1").success()

        val cleanup = store.scheduleInitialTerminalAfterCleanup(
            1,
            "lease-1",
            "stop-operation",
            "service_timeout",
        ).success()
        assertFalse(cleanup.intent.desiredActive)
        assertEquals("initial_terminal_report_pending", cleanup.intent.retry.pendingAction)
        assertEquals("stop-operation", cleanup.leaseTransaction?.stopOperationId)

        store = store(backend)
        store.acknowledgeInitialTerminalDiagnostic(1).success()
        val idle = store.completeInitialTerminalCleanup(1).success()
        assertFalse(idle.intent.desiredActive)
        assertNull(idle.intent.template)
        assertNull(idle.intent.retry.lastErrorCode)
        assertNull(idle.leaseTransaction)
    }

    @Test
    fun armedTerminalAfterCleanupRemainsBlockedTerminal() {
        val backend = FakeEncryptedRecordBackend()
        val store = store(backend)
        store.beginStart(0, template(), replay()).success()
        store.recordLease(1, "lease-1").success()
        store.activateCheckpoint(1).success()

        val cleanup = store.scheduleTerminalAfterCleanup(
            1,
            "lease-1",
            "stop-operation",
            "service_timeout",
        ).success()
        val terminal = store.completeCleanupAsTerminal(1).success()

        assertTrue(cleanup.intent.armedHistory)
        assertTrue(terminal.intent.desiredActive)
        assertTrue(terminal.intent.armedHistory)
        assertEquals("service_timeout", terminal.intent.retry.lastErrorCode)
        assertNull(terminal.leaseTransaction)
    }

    @Test
    fun retryingAnArmedTerminalPreservesArmedHistoryBeforeTheNextHandshake() {
        val store = store(FakeEncryptedRecordBackend())
        store.beginStart(0, template(), replay()).success()
        store.recordLease(1, "lease-1").success()
        val active = store.activateCheckpoint(1).success()
        store.scheduleTerminalAfterCleanup(
            1,
            "lease-1",
            "stop-operation",
            "service_timeout",
        ).success()
        store.completeCleanupAsTerminal(1).success()

        val retried = store.restartTerminal(
            1,
            template(),
            replay().copy(startOperationId = "retry-operation"),
            "retry-stop-operation",
        ).success()

        assertTrue(retried.intent.desiredActive)
        assertTrue(retried.intent.armedHistory)
        assertEquals(2L, retried.intent.generation)
        assertEquals(3L, retried.intent.diagnosticsEpisodeId)
        assertTrue(retried.intent.diagnosticsEpisodeId > active.intent.diagnosticsEpisodeId)
        assertEquals(LeasePhase.START_PENDING, retried.leaseTransaction?.phase)
    }

    @Test
    fun selectedTunnelOptionsSurviveCodecAndProcessDeathExactly() {
        val backend = FakeEncryptedRecordBackend()
        val selected = template().copy(options = AndroidTunnelOptions(
            splitActive = true,
            policyHash = "policy-7",
            applicationMode = "exclude_selected",
            excludedPackages = listOf("com.example.chat"),
            splitTunnelRoutes = listOf("10.0.0.0/8"),
            excludeLocalNetworks = true,
            dnsServers = listOf("1.1.1.1"),
        ))

        store(backend).beginStart(0, selected, replay()).success()

        assertEquals(selected.options, store(backend).read().success().intent.template?.options)
        val plaintext = requireNotNull(backend.record).toString(Charsets.UTF_8).lowercase()
        listOf("configuration", "privatekey", "token", "credential").forEach {
            assertFalse("unexpected secret field $it", plaintext.contains(it))
        }
    }

    @Test
    fun legacyV1EnvelopeMigratesWithUnarmedHistoryAndEmptyOptions() {
        val legacy = AndroidRecoveryEnvelopeCodec.encode(AndroidRecoveryEnvelope.empty(7))
            .toString(Charsets.UTF_8)
            .replace("\"formatVersion\":2", "\"formatVersion\":1")
            .replace(",\"armedHistory\":false", "")
            .toByteArray()
        val restored = store(FakeEncryptedRecordBackend(legacy)).read().success()

        assertFalse(restored.intent.armedHistory)
        assertEquals(AndroidTunnelOptions(), restored.intent.template?.options ?: AndroidTunnelOptions())
        assertEquals(ANDROID_RECOVERY_FORMAT, restored.formatVersion)
    }

    @Test
    fun legacyV1ActiveCheckpointMigratesAsPreviouslyArmed() {
        val backend = FakeEncryptedRecordBackend()
        val store = store(backend)
        store.beginStart(0, template(), replay()).success()
        store.recordLease(1, "lease-1").success()
        store.activateCheckpoint(1).success()
        val legacy = requireNotNull(backend.record).toString(Charsets.UTF_8)
            .replace("\"formatVersion\":2", "\"formatVersion\":1")
            .replace(",\"armedHistory\":true", "")
            .toByteArray()

        val restored = store(FakeEncryptedRecordBackend(legacy)).read().success()

        assertTrue(restored.intent.armedHistory)
        assertEquals(LeasePhase.ACTIVE_CHECKPOINT, restored.leaseTransaction?.phase)
    }

    @Test
    fun legacyTemplateWithoutBindingSyncFieldDefaultsToFalse() {
        val backend = FakeEncryptedRecordBackend()
        store(backend).beginStart(
            0,
            template().copy(syncBindingPreferences = true),
            replay(),
        ).success()
        val legacyPayload = org.json.JSONObject(
            requireNotNull(backend.record).toString(Charsets.UTF_8),
        )
        val legacyTemplate = legacyPayload.getJSONObject("intent").getJSONObject("template")
        legacyTemplate.remove("syncBindingPreferences")
        assertFalse(legacyTemplate.has("syncBindingPreferences"))

        val restored = AndroidRecoveryEnvelopeCodec.decode(
            legacyPayload.toString().toByteArray(),
        )

        assertFalse(requireNotNull(restored.intent.template).syncBindingPreferences)
    }

    @Test
    fun tunnelOptionsAreNormalizedAndBoundedBeforePersistence() {
        val args = TunnelOptionsArgs().apply {
            splitActive = true
            policyHash = "policy-1"
            applicationMode = "exclude_selected"
            excludedPackages = arrayListOf(" com.example.chat ", "com.example.chat")
            splitTunnelRoutes = arrayListOf("10.0.0.7/8", "10.0.0.0/8")
            dnsServers = arrayListOf("1.1.1.1", "1.1.1.1")
        }

        val normalized = normalizeAndroidTunnelOptions(33, args)

        assertEquals(listOf("com.example.chat"), normalized.excludedPackages)
        assertEquals(listOf("10.0.0.0/8"), normalized.splitTunnelRoutes)
        assertEquals(listOf("1.1.1.1"), normalized.dnsServers)
        val oversized = TunnelOptionsArgs().apply {
            dnsServers = arrayListOf("1.1.1.1", "8.8.8.8", "9.9.9.9", "4.4.4.4", "2.2.2.2")
        }
        assertTrue(runCatching { normalizeAndroidTunnelOptions(33, oversized) }.isFailure)
    }

    @Test
    fun retryPersistsSelectedDelayForExactDiagnosticThresholds() {
        val backend = FakeEncryptedRecordBackend()
        var store = store(backend)
        store.beginStart(0, template(), replay()).success()

        store.recordFailure(1, "transport_error", 1_300, scheduledDelaySeconds = 300).success()
        store = store(backend)

        assertEquals(300L, store.read().success().intent.retry.scheduledDelaySeconds)
    }

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
    fun stoppingAnIdleIntentAdvancesGenerationToTombstoneAQueuedStart() {
        val backend = FakeEncryptedRecordBackend()
        val store = store(backend)

        val stopped = store.setDesiredActive(0, false).success()

        assertFalse(stopped.intent.desiredActive)
        assertEquals(1L, stopped.intent.generation)
        assertEquals(stopped, store(backend).read().success())
    }

    @Test
    fun cancelCurrentIntentAtomicallyTombstonesTheLatestGeneration() {
        val backend = FakeEncryptedRecordBackend()
        val store = store(backend)
        store.beginStart(0, template(), replay()).success()

        val stopped = store.cancelCurrentIntent().success()

        assertFalse(stopped.intent.desiredActive)
        assertEquals(2L, stopped.intent.generation)
        assertEquals(2L, stopped.leaseTransaction?.generation)
        assertEquals(stopped, store(backend).read().success())
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
    fun redundantRecoveryEnvelopePersistsControlIdentitiesWithoutConfigurationOrPrivateKey() {
        val backend = FakeEncryptedRecordBackend()
        val envelope = AndroidRecoveryEnvelope(
            formatVersion = ANDROID_RECOVERY_FORMAT,
            intent = AndroidConnectionIntent.empty(7),
            leaseTransaction = null,
            redundantTransaction = AndroidRedundantTransaction(
                desiredActive = true,
                template = template(),
                sessionId = "22222222-2222-4222-8222-222222222222",
                slotALeaseId = "lease-a",
                slotBLeaseId = "lease-b",
                localActiveLeaseId = "lease-b",
                standbyDesired = true,
                roleGeneration = 4,
                membershipGeneration = 9,
                startOperationId = "start-v2",
                startRequestFingerprint = "fingerprint-v2",
                candidateLeaseId = "candidate-lease",
                candidateSlot = RedundantSlot.A,
            ),
        )

        backend.write(AndroidRecoveryEnvelopeCodec.encode(envelope))
        val restored = store(backend).read().success()
        val plaintext = requireNotNull(backend.record).toString(Charsets.UTF_8).lowercase()

        assertEquals("lease-b", restored.redundantTransaction?.localActiveLeaseId)
        assertEquals("candidate-lease", restored.redundantTransaction?.candidateLeaseId)
        listOf("configuration", "privatekey").forEach {
            assertFalse("unexpected secret field $it", plaintext.contains(it))
        }
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
