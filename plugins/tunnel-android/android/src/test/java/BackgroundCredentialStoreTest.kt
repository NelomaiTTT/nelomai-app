package ru.nelomai.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class BackgroundCredentialStoreTest {
    @Test
    fun configurePublishesOneRevisionedCredentialEnvelope() {
        val backend = CredentialFakeBackend()
        val store = BackgroundCredentialStore(backend)

        val configured = store.configure(0, provision()).successCredential()

        assertEquals(1, configured.revision)
        assertEquals("device-token", configured.active?.token)
        assertEquals("install-secret", configured.installSecret)
        assertEquals(1, backend.writeCount)
    }

    @Test
    fun uiReservationSerializesProvisionAgainstServiceRotation() {
        val store = configuredStore()
        val reserved = store.reserveMutation(
            expectedRevision = 1,
            mutationId = "ui-mutation",
            deviceId = DEVICE_ID,
            expiresAtUnix = 150,
            nowUnix = 100,
        ).successCredential()

        val conflict = store.reserveMutation(
            expectedRevision = reserved.revision,
            mutationId = "rotation-mutation",
            deviceId = DEVICE_ID,
            expiresAtUnix = 160,
            nowUnix = 101,
        ).failureCredential()

        assertEquals("background_credential_mutation_in_progress", conflict.code)

        val configureConflict = store.configure(
            reserved.revision,
            provision(),
        ).failureCredential()
        assertEquals("background_credential_mutation_in_progress", configureConflict.code)
    }

    @Test
    fun staleRevisionAndLateMutationCannotPublishPendingToken() {
        val store = configuredStore()
        store.reserveMutation(1, "new-mutation", DEVICE_ID, 150, 100).successCredential()

        val stale = store.savePendingToken(
            expectedRevision = 0,
            mutationId = "new-mutation",
            pending = pending(),
            nowUnix = 110,
        ).failureCredential()
        val late = store.savePendingToken(
            expectedRevision = 1,
            mutationId = "old-mutation",
            pending = pending(),
            nowUnix = 110,
        ).failureCredential()

        assertEquals("background_credential_revision_conflict", stale.code)
        assertEquals("background_credential_mutation_conflict", late.code)
        assertNull(store.read().successCredential().pending)
    }

    @Test
    fun expiredPendingTokenStillRequiresExactActivationReplay() {
        val backend = CredentialFakeBackend()
        var store = BackgroundCredentialStore(backend)
        store.configure(0, provision()).successCredential()
        store.reserveMutation(1, PREPARE_ID, DEVICE_ID, 150, 100, ACTIVATE_ID)
            .successCredential()
        store.savePendingToken(1, PREPARE_ID, pending(stagedExpiresAtUnix = 101), 110)
            .successCredential()
        store = BackgroundCredentialStore(backend)

        val pending = store.pendingActivation(nowUnix = 1_000).successPending()

        assertEquals("activate-operation", pending.activationOperationId)
        assertEquals("staged-token", pending.token)
        assertEquals(101, pending.stagedExpiresAtUnix)
    }

    @Test
    fun activationNotAppliedIsTheOnlyPathThatDiscardsPending() {
        val store = storeWithPending()

        val discarded = store.discardNotApplied(1, "activate-operation").successCredential()

        assertNull(discarded.pending)
        assertEquals("device-token", discarded.active?.token)
        assertEquals(2, discarded.revision)
    }

    @Test
    fun capabilityExpiryBlocksNewPrepareButNotStoredActivationReplay() {
        val store = configuredStore(
            capability = BackgroundCapabilitySnapshot(1, enabled = true, expiresAtUnix = 101),
        )
        val expired = store.reserveMutation(1, "mutation", DEVICE_ID, 150, 102)
            .failureCredential()

        val pendingStore = storeWithPending()
        pendingStore.updateCapability(
            expectedRevision = 1,
            capability = BackgroundCapabilitySnapshot(
                revision = 2,
                enabled = false,
                expiresAtUnix = 500,
            ),
        ).successCredential()
        val replay = pendingStore.pendingActivation(nowUnix = 1_000).successPending()

        assertEquals("background_credential_capability_unavailable", expired.code)
        assertEquals("activate-operation", replay.activationOperationId)
    }

    @Test
    fun failedSynchronousCommitLeavesPreviousEnvelopeAuthoritative() {
        val backend = CredentialFakeBackend()
        val store = BackgroundCredentialStore(backend)
        store.configure(0, provision()).successCredential()
        val before = requireNotNull(backend.record).copyOf()
        backend.failWrites = true

        val failure = store.reserveMutation(1, "mutation", DEVICE_ID, 150, 100)
            .failureCredential()

        assertEquals("background_credential_write_failed", failure.code)
        assertTrue(before.contentEquals(requireNotNull(backend.record)))
    }

    @Test
    fun logoutCancelsMutationAndPreventsLatePromotion() {
        val store = storeWithPending()
        val logout = store.beginLogout(
            expectedRevision = 1,
            operationId = "logout-operation",
            installGeneration = 1,
        ).successCredential()

        val late = store.promotePending(
            expectedRevision = logout.revision,
            activationOperationId = "activate-operation",
            activeExpiresAtUnix = 10_000,
        ).failureCredential()

        assertNull(logout.active)
        assertNull(logout.pending)
        assertEquals("device-token", logout.cleanupCredential?.token)
        assertEquals("background_credential_logout_pending", late.code)
    }

    @Test
    fun finalizedLogoutKeepsOnlyASecretFreeTombstone() {
        val store = storeWithPending()
        val pendingLogout = store.beginLogout(1, "logout-operation", 1).successCredential()

        val finalized = store.finalizeLogout(
            pendingLogout.revision,
            "logout-operation",
        ).successCredential()

        assertNull(finalized.active)
        assertNull(finalized.previous)
        assertNull(finalized.pending)
        assertNull(finalized.cleanupCredential)
        assertNull(finalized.installSecret)
        assertEquals(BackgroundLogoutPhase.FINALIZED, finalized.logoutState?.phase)
    }

    @Test
    fun debugOutputNeverContainsCredentialSecrets() {
        val envelope = configuredStore().read().successCredential()

        val debug = envelope.toString() + provision().toString()

        assertFalse(debug.contains("device-token"))
        assertFalse(debug.contains("install-secret"))
    }

    @Test
    fun expiredReservationCannotReplaceAnUnknownPrepareOperation() {
        val store = configuredStore()
        store.reserveMutation(
            1,
            PREPARE_ID,
            DEVICE_ID,
            101,
            100,
            ACTIVATE_ID,
        ).successCredential()

        val conflict = store.reserveMutation(
            1,
            "44444444-4444-4444-8444-444444444444",
            DEVICE_ID,
            200,
            150,
            "55555555-5555-4555-8555-555555555555",
        ).failureCredential()

        assertEquals("background_credential_mutation_in_progress", conflict.code)
        val reservation = store.read().successCredential().reservation
        assertEquals(PREPARE_ID, reservation?.mutationId)
        assertEquals(ACTIVATE_ID, reservation?.activationOperationId)
    }

    private fun configuredStore(
        capability: BackgroundCapabilitySnapshot = BackgroundCapabilitySnapshot(
            revision = 1,
            enabled = true,
            expiresAtUnix = 500,
        ),
    ): BackgroundCredentialStore = BackgroundCredentialStore(CredentialFakeBackend()).also {
        it.configure(0, provision(capability)).successCredential()
    }

    private fun storeWithPending(
        capability: BackgroundCapabilitySnapshot = BackgroundCapabilitySnapshot(
            revision = 1,
            enabled = true,
            expiresAtUnix = 500,
        ),
    ): BackgroundCredentialStore = configuredStore(capability).also {
        it.reserveMutation(1, PREPARE_ID, DEVICE_ID, 150, 100, ACTIVATE_ID)
            .successCredential()
        it.savePendingToken(1, PREPARE_ID, pending(), 110).successCredential()
    }

    private fun provision(
        capability: BackgroundCapabilitySnapshot = BackgroundCapabilitySnapshot(
            revision = 1,
            enabled = true,
            expiresAtUnix = 500,
        ),
    ) = BackgroundCredentialProvision(
        deviceId = DEVICE_ID,
        panelBase = "https://nelomai.test",
        token = "device-token",
        expiresAtUnix = 10_000,
        installSecret = "install-secret",
        installGeneration = 1,
        capability = capability,
    )

    private fun pending(stagedExpiresAtUnix: Long = 200) = BackgroundPendingToken(
        token = "staged-token",
        stagedExpiresAtUnix = stagedExpiresAtUnix,
        tokenGeneration = 2,
        prepareOperationId = "prepare-operation",
        activationOperationId = "activate-operation",
        contractVersion = 1,
    )

    companion object {
        private const val DEVICE_ID = "11111111-1111-4111-8111-111111111111"
        private const val PREPARE_ID = "prepare-operation"
        private const val ACTIVATE_ID = "activate-operation"
    }
}

private class CredentialFakeBackend(
    var failWrites: Boolean = false,
) : EncryptedRecordBackend {
    var record: ByteArray? = null
    var writeCount = 0

    override fun read(): ByteArray? = record?.copyOf()

    override fun write(plaintext: ByteArray): Boolean {
        writeCount += 1
        if (failWrites) return false
        record = plaintext.copyOf()
        return true
    }
}

private fun CredentialStoreResult<BackgroundCredentialEnvelope>.successCredential():
    BackgroundCredentialEnvelope {
    assertTrue(this is CredentialStoreResult.Success)
    return (this as CredentialStoreResult.Success).value
}

private fun <T> CredentialStoreResult<T>.failureCredential(): CredentialStoreResult.Failure {
    assertTrue(this is CredentialStoreResult.Failure)
    return this as CredentialStoreResult.Failure
}

private fun CredentialStoreResult<BackgroundPendingToken>.successPending(): BackgroundPendingToken {
    assertTrue(this is CredentialStoreResult.Success)
    return (this as CredentialStoreResult.Success).value
}
