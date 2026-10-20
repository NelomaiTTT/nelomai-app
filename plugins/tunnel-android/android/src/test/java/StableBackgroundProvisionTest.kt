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
            assertFalse(StableBackgroundProvision.prepare(backend, retiredRequest(), true, 1000))
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
        val backend = MemoryBackend(seed())
        assertFalse(StableBackgroundProvision.prepare(backend, request(), true, 1000))
        assertEquals(seed(), backend.envelope())
        assertEquals(0, backend.writes)
        assertTrue(StableBackgroundProvision.prepare(backend, request(), false, 1000))
        val prepared = backend.envelope()
        assertEquals(target, prepared.ownerScope)
        assertEquals(3L, prepared.revision)
        assertEquals(1L, prepared.ownerAttempt)
        assertNull(prepared.ownerOperation)
        assertNull(prepared.active)
        assertNull(prepared.previous)
        assertEquals("install-secret", prepared.installSecret)
        assertEquals(1L, prepared.installGeneration)
        // A crash before dispatch leaves a durable empty current scope. Retry
        // cannot restore the revoked token or repeatedly advance its revision.
        assertTrue(StableBackgroundProvision.prepare(backend, request(), true, 1000))
        assertEquals(prepared, backend.envelope())
        assertEquals(1, backend.writes)
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

    private class MemoryBackend(value: BackgroundCredentialEnvelope) : EncryptedRecordBackend {
        var bytes = BackgroundCredentialEnvelopeCodec.encode(value)
        var writes = 0
        override fun read() = bytes.clone()
        override fun write(plaintext: ByteArray): Boolean { writes++; bytes = plaintext.clone(); return true }
        fun envelope() = BackgroundCredentialEnvelopeCodec.decode(bytes)
    }
}
