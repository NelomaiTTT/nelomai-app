package ru.nelomai.tunnel

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class StableGenerationRecoveryTest {
    private val device = "11111111-1111-4111-8111-111111111111"
    private val old = NativeOwnerScope(3, "family", device, "stable", "0.3.13", "0.2.21", 1, 5)
    private val next = old.copy(authEpoch = 5, sessionGeneration = 9)
    private val operation = NativeOwnerOperation(next,
        "22222222-2222-4222-8222-222222222222", 3, 100000)
    private fun wire(op: NativeOwnerOperation) = JSONObject()
        .put("owner_operation", op.toJson().toString()).put("device_id", device)
        .put("access_token", "bearer").put("install_secret", "install-secret").toString()
    private fun completed() = BackgroundCredentialEnvelope(revision = 2, deviceId = device,
        panelBase = "https://nelomai.ru", installGeneration = 1, ownerScope = old, ownerAttempt = 1, ownerCancelEpoch = 4,
        logoutState = BackgroundLogoutState("old-logout", 1, BackgroundLogoutPhase.FINALIZED))
    private class Memory(value: BackgroundCredentialEnvelope): EncryptedRecordBackend {
        var bytes = BackgroundCredentialEnvelopeCodec.encode(value)
        override fun read() = bytes.clone()
        override fun write(plaintext: ByteArray): Boolean { bytes = plaintext.clone(); return true }
        fun value() = BackgroundCredentialEnvelopeCodec.decode(bytes)
    }

    @Test fun loadedCompletedReceiptDefersMigrationUntilPhysicalExitWithoutAllocating() {
        val backend = Memory(completed())
        val before = backend.value()
        assertThrows(IllegalStateException::class.java) {
            StableBackgroundProvision.prepareGeneration(backend, wire(operation), true) { _, _, allow ->
                assertFalse(allow)
                null
            }
        }
        assertEquals(before, backend.value())
        // A reservation already exists (e.g. an interrupted earlier attempt), but
        // it must not permit rewriting state held by the loaded immutable engine.
        assertThrows(IllegalStateException::class.java) {
            StableBackgroundProvision.prepareGeneration(backend, wire(operation), true) { _, _, allow ->
                assertFalse(allow)
                8L
            }
        }
        assertEquals(before, backend.value())
        // A real process exit clears engineWasLoaded; the normal retry can prepare.
        assertTrue(StableBackgroundProvision.prepareGeneration(backend, wire(operation), false) { _, _, allow ->
            assertTrue(allow)
            8L
        })
        assertEquals(8L, backend.value().installGeneration)
        assertNull(backend.value().logoutState)
        assertEquals(before.ownerCancelEpoch, backend.value().ownerCancelEpoch)
    }

    @Test fun interruptedPreparationMustRemainReprovisionableAfterAConfirmedOtherSlotHop() {
        val source = next.copy(slot = "latest", runtimeVersion = "0.3.13", sessionGeneration = 10)
        val returned = operation.copy(scope = next.copy(sessionGeneration = 11), attempt = 4,
            provisionPredecessor = source)
        // Control: the original completed marker accepts the newer login after the hop.
        assertTrue(StableBackgroundProvision.prepare(Memory(completed()), wire(returned), false, 1000))
        val backend = Memory(completed())
        assertTrue(StableBackgroundProvision.prepare(backend, wire(operation), false, 1000))
        assertTrue(StableBackgroundProvision.prepareGeneration(backend, wire(operation), false) { _, _, _ -> 8L })
        assertNull(backend.value().logoutState)
        assertNull(backend.value().active)
        assertEquals(4L, backend.value().ownerCancelEpoch)
        // Simulate process death/deadline after preparation, before native provisioning.
        // The same account completes latest -> stable with an authenticated predecessor.
        assertTrue(StableBackgroundProvision.prepare(backend, wire(returned), false, 1000))
    }

    @Test fun logoutBetweenPreparationAndProvisionStillAllowsAFreshLogin() {
        val backend = Memory(completed())
        assertTrue(StableBackgroundProvision.prepareGeneration(backend, wire(operation), false) { _, _, _ -> 8L })
        val store = BackgroundCredentialStore(backend, nowMillis = { 1000 })
        assertTrue(store.fenceOwnerLogout(6) is CredentialStoreResult.Success)
        assertTrue((store.beginLogoutCurrent("abandoned-login") as CredentialStoreResult.Success).value is BackgroundLogoutBegin.NotOwned)
        val beforeLogin = backend.value()
        val fresh = operation.copy(scope = next.copy(authEpoch = 7), attempt = 5)
        assertTrue(store.beginOwnerOperation(beforeLogin.revision, fresh, false) is CredentialStoreResult.Success)
    }

    @Test fun preEngineReservationPreservesUnfinishedLogoutAndActivationProofs() {
        for (phase in BackgroundLogoutPhase.values()) {
            val record = if (phase == BackgroundLogoutPhase.FINALIZED) completed()
                else completed().copy(installSecret = "install-secret",
                    cleanupCredential = BackgroundCredential(device, "https://nelomai.ru", "cleanup-token", 9999999999),
                    logoutState = BackgroundLogoutState("pending", 1, phase))
            val backend = Memory(record)
            StableBackgroundProvision.prepareEngine(backend) { error("logout receipt must remain unchanged") }
            assertEquals(record, backend.value())
        }
        val reserved = completed().copy(logoutState = null, installSecret = "install-secret",
            reservation = BackgroundMutationReservation("prepare", "activate", device, 9999999999),
            pending = BackgroundPendingToken("pending-token", 9999999999, 2, "prepare", "activate", 1))
        val backend = Memory(reserved)
        StableBackgroundProvision.prepareEngine(backend) { 8 }
        assertEquals(reserved.copy(revision = 3, installGeneration = 8), backend.value())
    }

    @Test fun newerCancellationStillFencesARecoveredPreparation() {
        val backend = Memory(completed())
        assertTrue(StableBackgroundProvision.prepareGeneration(backend, wire(operation), false) { _, _, _ -> 8L })
        val store = BackgroundCredentialStore(backend, nowMillis = { 1000 })
        assertTrue(store.fenceOwnerLogout(6) is CredentialStoreResult.Success)
        val before = backend.value()
        val source = next.copy(slot = "latest", runtimeVersion = "0.3.13", sessionGeneration = 10)
        val returned = operation.copy(scope = next.copy(sessionGeneration = 11), attempt = 4,
            provisionPredecessor = source)
        assertThrows(IllegalArgumentException::class.java) {
            StableBackgroundProvision.prepare(backend, wire(returned), false, 1000)
            StableBackgroundProvision.prepareGeneration(backend, wire(returned), false) { _, _, _ ->
                error("cancelled preparation must not allocate")
            }
        }
        assertEquals(before, backend.value())
    }

    @Test fun stableLogoutLoginCyclesNeverReuseTheInstallationReceipt() {
        var ledger: ByteArray? = null
        val generations = BackgroundInstallGenerationStore({ object : EncryptedRecordBackend {
            override fun read() = ledger?.clone()
            override fun write(plaintext: ByteArray): Boolean { ledger = plaintext.clone(); return true }
        } })
        assertEquals(2L, generations.reserve(1, "stable:0.2.21"))
        val backend = Memory(completed().copy(installGeneration = 2,
            logoutState = BackgroundLogoutState("old-logout", 2, BackgroundLogoutPhase.FINALIZED)))
        val reserve = { minimum: Long, key: String, allow: Boolean -> generations.reserve(minimum, key, allow) }
        assertTrue(StableBackgroundProvision.prepareGeneration(backend, wire(operation), false, reserve))
        assertEquals(4L, backend.value().installGeneration)
        val native = BackgroundCredentialStore(backend, nowMillis = { 1000 })
        var current = backend.value()
        current = (native.beginOwnerOperation(current.revision, operation, false) as CredentialStoreResult.Success).value
        current = (native.configure(current.revision, BackgroundCredentialProvision(device,
            "https://nelomai.ru", "new-token", 9999999999, "install-secret", 4,
            BackgroundCapabilitySnapshot(0, false, 1))) as CredentialStoreResult.Success).value
        current = (native.beginLogoutCurrent("next-logout") as CredentialStoreResult.Success).value.envelope
        assertEquals(4L, current.logoutState?.installGeneration)
        assertTrue(native.finalizeLogout(current.revision, "next-logout") is CredentialStoreResult.Success)
        val later = operation.copy(scope = next.copy(authEpoch = 7), attempt = 5)
        assertTrue(StableBackgroundProvision.prepareGeneration(backend, wire(later), false, reserve))
        assertEquals(6L, backend.value().installGeneration)
        val before = backend.value()
        assertTrue(StableBackgroundProvision.prepareGeneration(backend, wire(later), true, reserve))
        assertEquals(before, backend.value())
    }

    @Test fun interruptedCurrentLoginActivationKeepsItsIdsAndCanFinishWithoutNewIssuance() {
        val record = completed().copy(ownerScope = next, ownerAttempt = 2, installGeneration = 2,
            installSecret = "install-secret",
            reservation = BackgroundMutationReservation("prepare", "activate", device, 9999999999),
            pending = BackgroundPendingToken("pending-token", 9999999999, 2, "prepare", "activate", 1))
        val backend = Memory(record)
        StableBackgroundProvision.prepareEngine(backend) { 8 }
        val prepared = backend.value()
        assertEquals(8L, prepared.installGeneration)
        assertNull(prepared.logoutState)
        assertEquals(record.pending, prepared.pending)
        assertEquals(record.reservation, prepared.reservation)
        assertEquals(record.ownerScope, prepared.ownerScope)
        assertEquals(record.ownerCancelEpoch, prepared.ownerCancelEpoch)
        val native = BackgroundCredentialStore(backend, nowMillis = { 1000 })
        val admitted = (native.beginOwnerOperation(prepared.revision, operation, false) as CredentialStoreResult.Success).value
        val finished = (native.promotePending(admitted.revision, "activate", 9999999999) as CredentialStoreResult.Success).value
        assertEquals("pending-token", finished.active?.token)
        assertEquals(9999999999, finished.active?.expiresAtUnix)
        assertNull(finished.pending)
        assertNull(finished.reservation)
    }

    @Test fun completedNewLoginCanHandoffAgainWithoutDroppingItsOlderCancellationFence() {
        val backend = Memory(completed())
        assertTrue(StableBackgroundProvision.prepareGeneration(backend, wire(operation), false) { _, _, _ -> 8L })
        val native = BackgroundCredentialStore(backend, nowMillis = { 1000 })
        val admitted = (native.beginOwnerOperation(backend.value().revision, operation, false) as CredentialStoreResult.Success).value
        assertTrue(native.configure(admitted.revision, BackgroundCredentialProvision(device,
            "https://nelomai.ru", "fresh-token", 9999999999, "install-secret", 8,
            BackgroundCapabilitySnapshot(0, false, 1))) is CredentialStoreResult.Success)
        val source = next.copy(slot = "latest", runtimeVersion = "0.3.13", sessionGeneration = 10)
        val returned = operation.copy(scope = next.copy(sessionGeneration = 11), attempt = 4,
            provisionPredecessor = source)
        assertThrows(IllegalStateException::class.java) { StableBackgroundProvision.prepare(backend, wire(returned), true, 1000) }
        assertTrue(StableBackgroundProvision.prepare(backend, wire(returned), false, 1000))
        assertEquals(returned.scope, backend.value().ownerScope)
        assertEquals(4L, backend.value().ownerCancelEpoch)
        assertTrue(native.beginOwnerOperation(backend.value().revision, returned, false) is CredentialStoreResult.Success)
        val before = backend.value()
        assertTrue(native.beginOwnerOperation(before.revision,
            returned.copy(scope = returned.scope.copy(authEpoch = 4), attempt = 99), false) is CredentialStoreResult.Failure)
        assertEquals(before, backend.value())
    }

    @Test fun completedOtherAccountDeviceMustAllowTheNewAuthenticatedEnrollment() {
        val otherDevice = "33333333-3333-4333-8333-333333333333"
        val op = operation.copy(scope = next.copy(deviceId = otherDevice))
        val input = JSONObject(wire(op)).put("device_id", otherDevice).toString()
        val control = Memory(completed())
        val native = BackgroundCredentialStore(control, nowMillis = { 1000 })
        assertTrue(native.beginOwnerOperation(control.value().revision, op, false) is CredentialStoreResult.Success)
        val backend = Memory(completed())
        assertTrue(StableBackgroundProvision.prepare(backend, input, false, 1000))
        assertTrue(StableBackgroundProvision.prepareGeneration(backend, input, false) { _, _, _ -> 8L })
        val ownerStore = BackgroundCredentialStore(backend, nowMillis = { 1000 })
        val admitted = (ownerStore.beginOwnerOperation(backend.value().revision, op, false)
            as CredentialStoreResult.Success).value
        val provisioned = (ownerStore.configure(admitted.revision, BackgroundCredentialProvision(otherDevice,
            "https://nelomai.ru", "other-account-token", 9999999999, "install-secret", 8,
            BackgroundCapabilitySnapshot(0, false, 1))) as CredentialStoreResult.Success).value
        assertEquals(otherDevice, provisioned.deviceId)
        assertEquals(otherDevice, provisioned.active?.deviceId)
        assertEquals(op.scope, provisioned.ownerScope)
        assertEquals(4L, provisioned.ownerCancelEpoch)
    }

    @Test fun otherAccountCannotReplaceActiveOrPendingAuthorityOrBypassCancellation() {
        val other = operation.copy(scope = next.copy(deviceId = "33333333-3333-4333-8333-333333333333"))
        val input = JSONObject(wire(other)).put("device_id", other.scope.deviceId).toString()
        val token = BackgroundCredential(device, "https://nelomai.ru", "old-token", 9999999999)
        val records = listOf(
            completed().copy(logoutState = null, installSecret = "install-secret", active = token, ownerCancelEpoch = null),
            completed().copy(logoutState = BackgroundLogoutState("pending", 1, BackgroundLogoutPhase.PENDING),
                installSecret = "install-secret", cleanupCredential = token),
            completed().copy(installGeneration = 2, installSecret = "install-secret",
                reservation = BackgroundMutationReservation("prepare", "activate", device, 9999999999),
                pending = BackgroundPendingToken("old-pending", 9999999999, 2, "prepare", "activate", 1)))
        for (record in records) {
            val backend = Memory(record)
            assertThrows(IllegalArgumentException::class.java) {
                StableBackgroundProvision.prepareGeneration(backend, input, false) { _, _, _ -> error("must remain fenced") }
            }
            assertEquals(record, backend.value())
        }
        val backend = Memory(completed())
        val cancelled = other.copy(scope = other.scope.copy(authEpoch = 4))
        val cancelledInput = JSONObject(wire(cancelled)).put("device_id", cancelled.scope.deviceId).toString()
        assertThrows(IllegalArgumentException::class.java) {
            StableBackgroundProvision.prepareGeneration(backend, cancelledInput, false) { _, _, _ -> error("cancelled") }
        }
        assertEquals(completed(), backend.value())
    }

}
