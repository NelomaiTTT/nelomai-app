package ru.nelomai.tunnel

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class StableBackgroundProvisionTest {
    private val device = "11111111-1111-4111-8111-111111111111"
    private val retained = NativeOwnerScope(3, "login-family", device,
        "stable", "0.3.4", "0.2.20", 1, 5)
    private val source = retained.copy(slot = "latest", containerVersion = "0.3.5",
        runtimeVersion = "0.3.5", sessionGeneration = 8)
    private val target = retained.copy(containerVersion = "0.3.5", sessionGeneration = 9)
    private val operation = NativeOwnerOperation(target,
        "22222222-2222-4222-8222-222222222222", 3, 100_000, source)

    private fun seed() = BackgroundCredentialEnvelope(revision = 2, deviceId = device,
        panelBase = "https://nelomai.ru", installSecret = "install-secret", installGeneration = 1,
        active = BackgroundCredential(device, "https://nelomai.ru", "revoked-token", 9999999999),
        ownerScope = retained, ownerAttempt = 1)

    private fun request(op: NativeOwnerOperation = operation) = JSONObject()
        .put("owner_operation", op.toJson().toString()).put("device_id", device)
        .put("access_token", "current-bearer").put("install_secret", "install-secret").toString()

    private fun retiredRequest(op: NativeOwnerOperation = operation): String {
        val input = JSONObject(request(op))
        val owner = JSONObject(input.getString("owner_operation"))
        owner.getJSONObject("provision_predecessor")
            .put("reconcile_operation_id", "44444444-4444-4444-8444-444444444444")
            .put("resume_operation_id", "55555555-5555-4555-8555-555555555555")
        return input.put("owner_operation", owner.toString()).toString()
    }

    @Test fun retainedStableUsesExactRequestedVersionInsteadOfReleaseLiteral() {
        for (version in listOf("0.2.21", "9.8.7")) {
            val old = retained.copy(runtimeVersion = version)
            val next = target.copy(runtimeVersion = version)
            val backend = MemoryBackend(seed().copy(ownerScope = old))
            assertTrue(StableBackgroundProvision.prepare(backend,
                request(operation.copy(scope = next)), false, 1000))
            assertEquals(next, backend.envelope().ownerScope)
            assertNull(backend.envelope().active)
        }
    }

    @Test fun retainedVersionAndContractMustStillMatchTarget() {
        for (wrong in listOf(retained.copy(runtimeVersion = "9.8.6"),
            retained.copy(runtimeContractVersion = 2))) {
            val record = seed().copy(ownerScope = wrong)
            val backend = MemoryBackend(record)
            assertThrows(IllegalArgumentException::class.java) {
                StableBackgroundProvision.prepare(backend, request(), false, 1000)
            }
            assertEquals(record, backend.envelope())
            assertEquals(0, backend.writes)
        }
    }

    @Test fun completedResumeRetiresUnfinishedIssuanceOnlyAfterPhysicalEngineExit() {
        val reservation = BackgroundMutationReservation("old-prepare", "old-activate", device, 3000)
        val pending = BackgroundPendingToken("old-staged", 3000, 2, "old-prepare", "old-activate", 1)
        for (staged in listOf(null, pending)) for (hadActive in listOf(false, true)) {
            val record = seed().copy(reservation = reservation, pending = staged,
                active = seed().active.takeIf { hadActive },
                previous = seed().active!!.copy(token = "old-previous").takeIf { hadActive },
                ownerOperation = NativeOwnerOperation(retained,
                    "66666666-6666-4666-8666-666666666666", 1, 500),
                capability = BackgroundCapabilitySnapshot(7, true, 9999999999))
            val backend = MemoryBackend(record)
            assertThrows(IllegalStateException::class.java) { StableBackgroundProvision.prepare(backend, retiredRequest(), true, 1000) }
            assertEquals(record, backend.envelope())
            assertEquals(0, backend.writes)
            assertTrue(StableBackgroundProvision.prepare(backend, retiredRequest(), false, 1000))
            val prepared = backend.envelope()
            assertEquals(target, prepared.ownerScope)
            assertEquals(3L, prepared.revision)
            assertNull(prepared.active)
            assertNull(prepared.previous)
            assertNull(prepared.pending)
            assertNull(prepared.reservation)
            assertNull(prepared.ownerOperation)
            assertEquals("install-secret", prepared.installSecret)
            assertEquals(1L, prepared.installGeneration)
            assertEquals(record.capability, prepared.capability)
            assertEquals(1L, prepared.ownerAttempt)
            assertTrue(StableBackgroundProvision.prepare(backend, retiredRequest(), false, 1000))
            assertEquals(prepared, backend.envelope())
            assertEquals(1, backend.writes)
        }
    }

    @Test fun unfinishedIssuanceStillRequiresExactOwnerAndCompletedResumeAuthority() {
        val record = seed().copy(reservation = BackgroundMutationReservation(
            "old-prepare", "old-activate", device, 3000))
        val invalid = mutableListOf(request(), retiredRequest(operation.copy(attempt = 1)),
            retiredRequest(operation.copy(expiresAtUnixMs = 1000)),
            retiredRequest(operation.copy(scope = target.copy(authEpoch = 4))),
            retiredRequest(operation.copy(scope = target.copy(runtimeContractVersion = 2))),
            retiredRequest(operation.copy(provisionPredecessor = source.copy(sessionGeneration = 7))),
            retiredRequest(operation.copy(provisionPredecessor = source.copy(deviceId = "33333333-3333-4333-8333-333333333333"))),
            JSONObject(retiredRequest()).put("access_token", "").toString(),
            JSONObject(retiredRequest()).put("install_secret", "other-install").toString())
        for (field in listOf("reconcile_operation_id", "resume_operation_id")) {
            for (value in listOf(null, "", "not-an-operation-id")) {
                val input = JSONObject(retiredRequest())
                val owner = JSONObject(input.getString("owner_operation"))
                if (value == null) owner.getJSONObject("provision_predecessor").remove(field)
                else owner.getJSONObject("provision_predecessor").put(field, value)
                invalid += input.put("owner_operation", owner.toString()).toString()
            }
        }
        for (wire in invalid) {
            val backend = MemoryBackend(record)
            assertThrows(IllegalArgumentException::class.java) {
                StableBackgroundProvision.prepare(backend, wire, false, 1000)
            }
            assertEquals(record, backend.envelope())
            assertEquals(0, backend.writes)
        }
        for (blocked in listOf(record.copy(ownerCancelEpoch = 4),
            record.copy(cleanupCredential = record.active),
            record.copy(active = null,
                pending = BackgroundPendingToken("old-staged", 3000, 2, "old-prepare", "old-activate", 1),
                logoutState = BackgroundLogoutState("logout", 1, BackgroundLogoutPhase.PENDING)))) {
            val backend = MemoryBackend(blocked)
            assertThrows(IllegalArgumentException::class.java) {
                StableBackgroundProvision.prepare(backend, retiredRequest(), false, 1000)
            }
            assertEquals(blocked, backend.envelope())
            assertEquals(0, backend.writes)
        }
    }

    @Test fun retainedStableGetsFreshProvisionOnlyAfterOldEngineExit() {
        for (epoch in listOf(3L, 5L)) {
        val next = operation.copy(scope = target.copy(authEpoch = epoch),
            provisionPredecessor = source.copy(authEpoch = epoch))
        val backend = MemoryBackend(seed())
        assertThrows(IllegalStateException::class.java) { StableBackgroundProvision.prepare(backend, request(next), true, 1000) }
        assertEquals(seed(), backend.envelope())
        assertEquals(0, backend.writes)
        assertTrue(StableBackgroundProvision.prepare(backend, request(next), false, 1000))
        val prepared = backend.envelope()
        assertEquals(next.scope, prepared.ownerScope)
        assertEquals(3L, prepared.revision)
        assertEquals(1L, prepared.ownerAttempt)
        assertNull(prepared.ownerOperation)
        assertNull(prepared.active)
        assertNull(prepared.previous)
        assertEquals("install-secret", prepared.installSecret)
        assertEquals(1L, prepared.installGeneration)
        // A crash before dispatch leaves a durable empty current scope. Retry
        // cannot restore the revoked token or repeatedly advance its revision.
        assertTrue(StableBackgroundProvision.prepare(backend, request(next), true, 1000))
        assertEquals(prepared, backend.envelope())
        assertEquals(1, backend.writes)
        }
    }

    @Test fun retainedStableFromOlderLoginCannotDiscardPendingWorkOrOwnerFences() {
        val login = operation.copy(scope = target.copy(authEpoch = 5),
            provisionPredecessor = source.copy(authEpoch = 5))
        val records = listOf(seed().copy(ownerCancelEpoch = 5),
            seed().copy(ownerAttempt = 3), seed().copy(cleanupCredential = seed().active),
            seed().copy(active = null, cleanupCredential = seed().active,
                logoutState = BackgroundLogoutState("logout", 1, BackgroundLogoutPhase.PENDING)),
            seed().copy(reservation = BackgroundMutationReservation("prepare", "activate", device, 3000)),
            seed().copy(reservation = BackgroundMutationReservation("prepare", "activate", device, 3000),
                pending = BackgroundPendingToken("staged", 3000, 2, "prepare", "activate", 1)),
            seed().copy(ownerScope = retained.copy(deviceId = "99999999-9999-4999-8999-999999999999")))
        for (record in records) {
            val backend = MemoryBackend(record)
            assertThrows(IllegalArgumentException::class.java) {
                StableBackgroundProvision.prepare(backend, retiredRequest(login), false, 1000)
            }
            assertEquals(record, backend.envelope())
            assertEquals(0, backend.writes)
        }
    }

    @Test fun emptyNotOwnedLogoutRetiresOldScopeForAuthenticatedLoginWithoutResumeProof() {
        val record = seed().copy(active = null, installSecret = null, ownerCancelEpoch = 4)
        val login = operation.copy(scope = target.copy(authEpoch = 5, family = "new-login"), provisionPredecessor = null)
        val backend = MemoryBackend(record)
        assertTrue(StableBackgroundProvision.prepare(backend, request(login), false, 1000))
        assertTrue(StableBackgroundProvision.prepareGeneration(backend, request(login), false) { floor, _, _ -> floor })
        val empty = backend.envelope()
        assertNull(empty.ownerScope)
        assertNull(empty.deviceId)
        assertNull(empty.panelBase)
        assertEquals(4L, empty.ownerCancelEpoch)
        assertEquals(record.ownerAttempt, empty.ownerAttempt)
        assertTrue(empty.requiresFreshProvision)
        assertTrue(StableBackgroundProvision.prepare(backend, request(login), false, 1000))
        assertTrue(StableBackgroundProvision.prepareGeneration(backend, request(login), true) { floor, _, _ -> floor })
        assertEquals(empty, backend.envelope())
        // Native admission can precede a lost/failed issuance. Its current
        // empty owner is not an old NotOwned identity to retire again.
        val store = BackgroundCredentialStore(backend, nowMillis = { 1000 })
        val admitted = (store.beginOwnerOperation(empty.revision, login, false) as CredentialStoreResult.Success).value
        assertTrue(StableBackgroundProvision.prepare(backend, request(login), true, 1000))
        assertTrue(StableBackgroundProvision.prepareGeneration(backend, request(login), true) { floor, _, _ -> floor })
        assertEquals(admitted, backend.envelope())
        val returned = login.copy(attempt = 4, scope = login.scope.copy(sessionGeneration = 11),
            provisionPredecessor = login.scope.copy(slot = "latest", runtimeVersion = "0.3.5", sessionGeneration = 10))
        assertTrue(StableBackgroundProvision.prepare(backend, request(returned), false, 1000))
        assertTrue(StableBackgroundProvision.prepareGeneration(backend, request(returned), false) { floor, _, _ -> floor })
        assertNull(backend.envelope().ownerScope)
        assertEquals(admitted.ownerAttempt, backend.envelope().ownerAttempt)
    }

    @Test fun historicalFinalizedCurrentOwnerCanRetryItsUnissuedLoginAfterRestartOrSlotHop() {
        for (roundtrip in listOf(false, true)) {
            val record = seed().copy(active = null, installSecret = null, ownerCancelEpoch = 4,
                logoutState = BackgroundLogoutState("old-logout", 1, BackgroundLogoutPhase.FINALIZED))
            val login = operation.copy(scope = target.copy(authEpoch = 5, family = "current-login"), provisionPredecessor = null)
            val backend = MemoryBackend(record)
            // Same admission written by the pinned engine before its network
            // issuance. No configure/reservation/receipt follows the failure.
            val store = BackgroundCredentialStore(backend, nowMillis = { 1000 })
            val admitted = (store.beginOwnerOperation(record.revision, login, false) as CredentialStoreResult.Success).value
            assertEquals(login.scope, admitted.ownerScope)
            assertEquals(BackgroundLogoutPhase.FINALIZED, admitted.logoutState?.phase)
            val retry = if (roundtrip) login.copy(attempt = 4, scope = login.scope.copy(sessionGeneration = 11),
                provisionPredecessor = login.scope.copy(slot = "latest", runtimeVersion = "0.3.5", sessionGeneration = 10))
                else login.copy(attempt = 4)
            assertTrue(StableBackgroundProvision.prepare(backend, request(retry), false, 1000))
            StableBackgroundProvision.prepareEngine(backend) { error("retained receipt is not an active enrollment") }
            assertTrue(StableBackgroundProvision.prepareGeneration(backend, request(retry), false) { floor, _, _ -> floor })
            val empty = backend.envelope()
            assertNull(empty.ownerScope)
            assertNull(empty.logoutState)
            assertEquals(2L, empty.installGeneration)
            assertEquals(4L, empty.ownerCancelEpoch)
            assertEquals(admitted.ownerAttempt, empty.ownerAttempt)
            assertTrue(store.beginOwnerOperation(empty.revision, login, false) is CredentialStoreResult.Failure)
            assertTrue(store.beginOwnerOperation(empty.revision, retry, false) is CredentialStoreResult.Success)
        }
    }

    @Test fun completedLogoutLeavesNewLoginAdmissionToStableWithoutRewriting() {
        val record = seed().copy(installSecret = null, active = null,
            ownerCancelEpoch = 3,
            logoutState = BackgroundLogoutState("logout", 1, BackgroundLogoutPhase.FINALIZED))
        val login = operation.copy(scope = target.copy(authEpoch = 4, family = "new-login"),
            provisionPredecessor = null)
        for (loaded in listOf(false, true)) {
            val backend = MemoryBackend(record)
            assertTrue(StableBackgroundProvision.prepare(backend, request(login), loaded, 1000))
            assertEquals(record, backend.envelope())
            assertEquals(0, backend.writes)
        }
    }

    @Test fun completedLogoutCannotAdmitOldEpochOrRetainedInstallation() {
        val finalized = seed().copy(installSecret = null, active = null,
            logoutState = BackgroundLogoutState("logout", 1, BackgroundLogoutPhase.FINALIZED))
        val login = operation.copy(scope = target.copy(authEpoch = 4, family = "new-login"),
            provisionPredecessor = null)
        val cases = listOf(
            finalized to login.copy(scope = target),
            finalized to login.copy(scope = target.copy(authEpoch = 2)),
            finalized.copy(installGeneration = 2, installSecret = "install-secret") to login,
        )
        for ((record, op) in cases) {
            val backend = MemoryBackend(record)
            assertThrows(IllegalArgumentException::class.java) {
                StableBackgroundProvision.prepare(backend, request(op), false, 1000)
            }
            assertEquals(record, backend.envelope())
            assertEquals(0, backend.writes)
        }
    }

    @Test fun unrelatedOrStaleAuthorityCannotRewriteStableCredentials() {
        val invalid = listOf(
            request(operation.copy(provisionPredecessor = null)),
            request(operation.copy(scope = target.copy(authEpoch = 4))),
            request(operation.copy(scope = target.copy(deviceId = "33333333-3333-4333-8333-333333333333"))),
            request(operation.copy(scope = target.copy(slot = "latest"))),
            request(operation.copy(scope = target.copy(runtimeVersion = "0.2.19"))),
            request(operation.copy(scope = target.copy(sessionGeneration = 8))),
            request(operation.copy(provisionPredecessor = source.copy(sessionGeneration = 7))),
            request(operation.copy(provisionPredecessor = source.copy(authEpoch = 4))),
            request(operation.copy(provisionPredecessor = source.copy(deviceId = "33333333-3333-4333-8333-333333333333"))),
            request(operation.copy(attempt = 1)),
            request(operation.copy(expiresAtUnixMs = 1000)),
            JSONObject(request()).put("install_secret", "other-install").toString(),
            JSONObject(request()).put("access_token", "").toString(),
        )
        for (wire in invalid) {
            val backend = MemoryBackend(seed())
            assertThrows(IllegalArgumentException::class.java) {
                StableBackgroundProvision.prepare(backend, wire, false, 1000)
            }
            assertEquals(seed(), backend.envelope())
            assertEquals(0, backend.writes)
        }
    }

    @Test fun unfinishedMutationLogoutAndForeignPanelRemainFenced() {
        val reservation = BackgroundMutationReservation("prepare", "activate", device, 3000)
        val records = listOf(
            seed().copy(reservation = reservation),
            seed().copy(ownerScope = retained.copy(sessionGeneration = 8)),
            seed().copy(ownerCancelEpoch = 4),
            seed().copy(cleanupCredential = seed().active),
            seed().copy(panelBase = "https://foreign.invalid",
                active = seed().active!!.copy(panelBase = "https://foreign.invalid")),
            seed().copy(active = null, logoutState = BackgroundLogoutState("logout", 1, BackgroundLogoutPhase.PENDING)),
        )
        for (record in records) {
            val backend = MemoryBackend(record)
            assertThrows(IllegalArgumentException::class.java) {
                StableBackgroundProvision.prepare(backend, request(), false, 1000)
            }
            assertEquals(record, backend.envelope())
            assertEquals(0, backend.writes)
        }
    }

    @Test fun failedPersistenceCannotReportTheHandoffAsPrepared() {
        for (record in listOf(seed(), seed().copy(reservation =
            BackgroundMutationReservation("old-prepare", "old-activate", device, 3000)))) {
            val bytes = BackgroundCredentialEnvelopeCodec.encode(record)
            val backend = object : EncryptedRecordBackend {
                override fun read() = bytes.clone()
                override fun write(plaintext: ByteArray) = false
            }
            assertThrows(IllegalStateException::class.java) {
                StableBackgroundProvision.prepare(backend, retiredRequest(), false, 1000)
            }
            assertEquals(record, BackgroundCredentialEnvelopeCodec.decode(bytes))
        }
    }

    @Test fun alreadyCurrentAndEmptyStoresNeedNoProcessRestart() {
        for (record in listOf(BackgroundCredentialEnvelope(), seed().copy(ownerScope = target))) {
            val backend = MemoryBackend(record)
            assertTrue(StableBackgroundProvision.prepare(backend, request(), true, 1000))
            assertEquals(record, backend.envelope())
            assertEquals(0, backend.writes)
        }
    }

    @Test fun sharedGenerationPreparationRetiresCompletedLogoutAndNeverRewritesPending() {
        for (finalized in listOf(false, true)) {
            val record = if (finalized) seed().copy(active = null, installSecret = null,
                logoutState = BackgroundLogoutState("old-logout", 1, BackgroundLogoutPhase.FINALIZED))
                else seed().copy(ownerScope = target)
            val backend = MemoryBackend(record)
            val wire = request(operation.copy(scope = target.copy(authEpoch = if (finalized) 4 else 3)))
            val reserve = { _: Long, _: String, allow: Boolean -> if (allow) 8L else null }
            if (finalized) {
                assertThrows(IllegalStateException::class.java) { StableBackgroundProvision.prepareGeneration(backend, wire, true, reserve) }
                assertThrows(IllegalStateException::class.java) { StableBackgroundProvision.prepareGeneration(backend, wire, true) { _, _, _ -> 8L } }
            } else {
                assertThrows(IllegalStateException::class.java) {
                    StableBackgroundProvision.prepareGeneration(backend, wire, true, reserve)
                }
                assertThrows(IllegalStateException::class.java) {
                    StableBackgroundProvision.prepareGeneration(backend, wire, true) { _, _, _ -> 8L }
                }
            }
            assertEquals(record, backend.envelope())
            assertTrue(StableBackgroundProvision.prepareGeneration(backend, wire, false, reserve))
            assertEquals(8L, backend.envelope().installGeneration)
            assertNull(backend.envelope().logoutState)
            assertEquals(record.ownerAttempt, backend.envelope().ownerAttempt)
            assertEquals(record.ownerCancelEpoch, backend.envelope().ownerCancelEpoch)
            val writes = backend.writes
            assertTrue(StableBackgroundProvision.prepareGeneration(backend, wire, true) { _, _, _ -> 8L })
            assertEquals(writes, backend.writes)
        }
        val pending = seed().copy(active = null, cleanupCredential = seed().active,
            logoutState = BackgroundLogoutState("pending", 1, BackgroundLogoutPhase.PENDING))
        val backend = MemoryBackend(pending)
        assertThrows(IllegalArgumentException::class.java) {
            StableBackgroundProvision.prepareGeneration(backend, request(), false) { _, _, _ -> error("must not allocate") }
        }
        assertEquals(pending, backend.envelope())
    }

    @Test fun preparedCompletedLogoutAdmitsANewLoginWithoutStableIncrementingTheOldCounter() {
        val backend = MemoryBackend(seed().copy(active = null, installSecret = null, ownerCancelEpoch = 3,
            logoutState = BackgroundLogoutState("old-logout", 1, BackgroundLogoutPhase.FINALIZED)))
        val op = operation.copy(scope = target.copy(authEpoch = 4))
        assertTrue(StableBackgroundProvision.prepare(backend, request(op), false, 1000))
        assertTrue(StableBackgroundProvision.prepareGeneration(backend, request(op), false) { _, _, _ -> 8L })
        val store = BackgroundCredentialStore(backend, nowMillis = { 1000 })
        val prepared = backend.envelope()
        val admitted = store.beginOwnerOperation(prepared.revision, op, false) as CredentialStoreResult.Success
        val configured = store.configure(admitted.value.revision, BackgroundCredentialProvision(device,
            "https://nelomai.ru", "fresh-token", 9999999999, "install-secret", 8,
            BackgroundCapabilitySnapshot(0, false, 1))) as CredentialStoreResult.Success
        assertEquals(8L, configured.value.installGeneration)
        assertEquals(op.scope, configured.value.ownerScope)
        assertEquals(3L, configured.value.ownerCancelEpoch)
    }

    @Test fun interruptedStableProjectionReusesItsDurableReservationAfterPhysicalExit() {
        val backend = MemoryBackend(seed().copy(ownerScope = target))
        var ledgerBytes: ByteArray? = null
        val ledger = object : EncryptedRecordBackend {
            override fun read() = ledgerBytes?.clone()
            override fun write(plaintext: ByteArray): Boolean { ledgerBytes = plaintext.clone(); return true }
        }
        val generations = BackgroundInstallGenerationStore({ ledger }, { 7 })
        val reserve = { floor: Long, key: String, allow: Boolean -> generations.reserve(floor, key, allow) }
        backend.writable = false
        assertThrows(IllegalStateException::class.java) {
            StableBackgroundProvision.prepareGeneration(backend, request(), false, reserve)
        }
        val reservation = ledgerBytes!!.clone()
        backend.writable = true
        assertThrows(IllegalStateException::class.java) {
            StableBackgroundProvision.prepareGeneration(backend, request(), true, reserve)
        }
        assertEquals(1L, backend.envelope().installGeneration)
        assertTrue(StableBackgroundProvision.prepareGeneration(backend, request(), false, reserve))
        assertEquals(8L, backend.envelope().installGeneration)
        assertArrayEquals(reservation, ledgerBytes)
    }

    @Test fun finalizedStableGenerationCannotBePreparedForAnOldOrCancelledLogin() {
        for ((scope, fence) in listOf(target.copy(authEpoch = 2) to 2L, target.copy(authEpoch = 4) to 4L, target to null)) {
            val record = seed().copy(active = null, installSecret = null, ownerCancelEpoch = fence,
                logoutState = BackgroundLogoutState("old-logout", 1, BackgroundLogoutPhase.FINALIZED))
            val backend = MemoryBackend(record)
            assertThrows(IllegalArgumentException::class.java) {
                StableBackgroundProvision.prepareGeneration(backend, request(operation.copy(scope = scope)), false) {
                    _, _, _ -> error("invalid login must not reserve a generation")
                }
            }
            assertEquals(record, backend.envelope())
        }
    }

    private class MemoryBackend(value: BackgroundCredentialEnvelope) : EncryptedRecordBackend {
        var bytes = BackgroundCredentialEnvelopeCodec.encode(value)
        var writes = 0
        var writable = true
        override fun read() = bytes.clone()
        override fun write(plaintext: ByteArray): Boolean {
            if (!writable) return false
            writes++; bytes = plaintext.clone(); return true
        }
        fun envelope() = BackgroundCredentialEnvelopeCodec.decode(bytes)
    }
}
