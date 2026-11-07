package ru.nelomai.tunnel

import java.io.File
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class BackgroundInstallGenerationStoreTest {
    private class Memory : EncryptedRecordBackend {
        var bytes: ByteArray? = null
        var writable = true
        override fun read() = bytes?.clone()
        override fun write(plaintext: ByteArray): Boolean {
            if (!writable) return false
            bytes = plaintext.clone(); return true
        }
    }

    @Test fun upgradeRollbackAndReopenNeverReuseARetainedGeneration() {
        val backend = Memory()
        val first = BackgroundInstallGenerationStore({ backend }, { 7 })
        assertEquals(8L, first.reserve(2, "latest/logout-a"))
        val reopened = BackgroundInstallGenerationStore({ backend }, { 7 })
        assertEquals(8L, reopened.reserve(8, "latest/logout-a"))
        assertEquals(9L, reopened.reserve(1, "stable/login-b"))
        assertEquals(10L, reopened.reserve(1, "new-latest/logout-c"))
        assertNull(reopened.reserve(1, "not-reserved", false))
        assertEquals(10L, reopened.reserve(1, "new-latest/logout-c", false))
    }

    @Test fun completedStableCycleCanAdvanceItsNamespaceReservationWithoutReusingTheReceipt() {
        val backend = Memory()
        val store = BackgroundInstallGenerationStore({ backend })
        assertEquals(2L, store.reserve(1, "stable:0.2.21"))
        assertNull(store.reserve(3, "stable:0.2.21", false))
        assertEquals(4L, store.reserve(3, "stable:0.2.21"))
        assertEquals(4L, store.reserve(4, "stable:0.2.21", false))
    }

    @Test fun failedWriteAndCorruptionNeverResetTheCounter() {
        val backend = Memory()
        val store = BackgroundInstallGenerationStore({ backend })
        backend.writable = false
        assertThrows(IllegalStateException::class.java) { store.reserve(3, "a") }
        assertNull(backend.bytes)
        backend.writable = true
        assertEquals(4L, store.reserve(3, "a"))
        backend.bytes = "{}".toByteArray()
        assertThrows(Exception::class.java) { store.reserve(1, "b") }
        backend.bytes = JSONObject().put("format", 1).put("generation", Int.MAX_VALUE)
            .put("operationKey", "a").toString().toByteArray()
        assertThrows(IllegalArgumentException::class.java) { store.reserve(1, "b") }
    }

    @Test fun cachedRecordAfterFailedCommitCannotAcknowledgeAnUncommittedReservation() {
        var cache: ByteArray? = null
        var writable = false
        var writes = 0
        val backend = object : EncryptedRecordBackend {
            override fun read() = cache?.clone()
            override fun write(plaintext: ByteArray): Boolean {
                // Android SharedPreferences updates memory before reporting disk failure.
                writes++; cache = plaintext.clone(); return writable
            }
        }
        val store = BackgroundInstallGenerationStore({ backend })
        assertThrows(IllegalStateException::class.java) { store.reserve(1, "same-operation") }
        assertThrows(IllegalStateException::class.java) { store.reserve(1, "same-operation") }
        writable = true
        assertEquals(2L, store.reserve(1, "same-operation"))
        assertEquals(3, writes)
    }

    @Test fun retainedFloorIncludesFinalizedLogoutAndFailsClosedOnUnreadableState() {
        val backend = Memory().apply { bytes = BackgroundCredentialEnvelopeCodec.encode(
            BackgroundCredentialEnvelope(revision = 1, installGeneration = 6,
                deviceId = "11111111-1111-4111-8111-111111111111", panelBase = "https://nelomai.ru",
                logoutState = BackgroundLogoutState("logout", 6, BackgroundLogoutPhase.FINALIZED))) }
        assertEquals(6L, backgroundInstallGenerationFloor(sequenceOf(backend)))
        backend.bytes = byteArrayOf(1)
        assertThrows(Exception::class.java) { backgroundInstallGenerationFloor(sequenceOf(backend)) }
    }

    @Test fun heldCrossProcessLockFailsPromptlyWithoutOpeningTheBackend() {
        val lock = File.createTempFile("generation-", ".lock")
        try {
            lock.outputStream().channel.use { channel -> channel.lock().use {
                val store = BackgroundInstallGenerationStore({ error("must not open storage") }, lockFile = lock)
                assertThrows(IllegalStateException::class.java) { store.reserve(1, "blocked") }
            } }
            assertEquals(2L, BackgroundInstallGenerationStore({ Memory() }, lockFile = lock).reserve(1, "free"))
        } finally { lock.delete() }
    }

    @Test fun nativeWriteInterruptionKeepsPendingFencesAndDoesNotReuseGenerationAcrossSlots() {
        val ledger = Memory()
        val local = Memory().apply { bytes = BackgroundCredentialEnvelopeCodec.encode(
            BackgroundCredentialEnvelope(revision = 1, deviceId = "11111111-1111-4111-8111-111111111111",
                panelBase = "https://nelomai.ru", installSecret = "install-secret", installGeneration = 1,
                active = BackgroundCredential("11111111-1111-4111-8111-111111111111",
                    "https://nelomai.ru", "token", 9999999999))) }
        val allocator = BackgroundInstallGenerationStore({ ledger }, { 2 })
        fun store() = BackgroundCredentialStore(local, logoutGeneration = { floor, key ->
            requireNotNull(allocator.reserve(floor, key)) })
        local.writable = false
        assertTrue(store().beginLogoutCurrent("operation-a") is CredentialStoreResult.Failure)
        local.writable = true
        val pending = (store().beginLogoutCurrent("operation-b") as CredentialStoreResult.Success).value.envelope
        assertEquals(4L, pending.installGeneration)
        assertEquals(4L, pending.logoutState?.installGeneration)
        assertEquals(pending, (store().beginLogoutCurrent("operation-c") as CredentialStoreResult.Success).value.envelope)
        assertNotNull(pending.cleanupCredential)
        assertNull(pending.active)
    }
    @Test fun conflictRepairCannotOverwriteANewerStateOrProceedAfterFailedPersistence() {
        val local = Memory().apply { bytes = BackgroundCredentialEnvelopeCodec.encode(
            BackgroundCredentialEnvelope(revision = 1, deviceId = "11111111-1111-4111-8111-111111111111",
                panelBase = "https://nelomai.ru", installSecret = "install-secret", installGeneration = 1,
                cleanupCredential = BackgroundCredential("11111111-1111-4111-8111-111111111111",
                    "https://nelomai.ru", "token", 9999999999),
                ownerCancelEpoch = 4, ownerAttempt = 42,
                logoutState = BackgroundLogoutState("old", 1, BackgroundLogoutPhase.PENDING))) }
        val ledger = Memory()
        val allocator = BackgroundInstallGenerationStore({ ledger }, { 2 })
        val store = BackgroundCredentialStore(local, logoutGeneration = { floor, key ->
            requireNotNull(allocator.reserve(floor, key)) })
        val before = (store.read() as CredentialStoreResult.Success).value
        local.writable = false
        assertTrue(store.reissueRejectedLogout(1, "old", "new") is CredentialStoreResult.Failure)
        assertEquals(before, (store.read() as CredentialStoreResult.Success).value)
        local.writable = true
        val repaired = (store.reissueRejectedLogout(1, "old", "new") as CredentialStoreResult.Success).value
        assertEquals(3L, repaired.installGeneration) // durable reservation is reused after failed native write
        assertEquals(before.ownerCancelEpoch, repaired.ownerCancelEpoch)
        assertEquals(before.ownerAttempt, repaired.ownerAttempt)
        assertTrue(store.reissueRejectedLogout(1, "old", "stale") is CredentialStoreResult.Failure)
        assertTrue(store.reissueRejectedLogout(repaired.revision, "old", "stale") is CredentialStoreResult.Failure)
        assertEquals(repaired, (store.read() as CredentialStoreResult.Success).value)
    }

    @Test fun pendingLogoutCheckpointRejectsStaleRevisionAndIdentityWithoutAdvancingState() {
        val expected = BackgroundCredentialEnvelope(revision = 1, deviceId = "11111111-1111-4111-8111-111111111111",
            panelBase = "https://nelomai.ru", installSecret = "install-secret", installGeneration = 1,
            cleanupCredential = BackgroundCredential("11111111-1111-4111-8111-111111111111",
                "https://nelomai.ru", "token", 9999999999),
            logoutState = BackgroundLogoutState("pending", 1, BackgroundLogoutPhase.PENDING))
        val backend = Memory().apply { bytes = BackgroundCredentialEnvelopeCodec.encode(expected) }
        val store = BackgroundCredentialStore(backend)
        assertTrue(store.persistPendingLogout(0, "pending") is CredentialStoreResult.Failure)
        assertTrue(store.persistPendingLogout(1, "other") is CredentialStoreResult.Failure)
        backend.writable = false
        assertTrue(store.persistPendingLogout(1, "pending") is CredentialStoreResult.Failure)
        backend.writable = true
        assertEquals(expected, (store.persistPendingLogout(1, "pending") as CredentialStoreResult.Success).value)
        assertEquals(expected, (store.read() as CredentialStoreResult.Success).value)
        assertTrue(store.finalizeLogout(1, "pending") is CredentialStoreResult.Success)
        assertTrue(store.persistPendingLogout(2, "pending") is CredentialStoreResult.Failure)
    }

}
