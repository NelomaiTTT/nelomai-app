package ru.nelomai.tunnel

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import java.security.cert.Certificate

class NativeAuthScopeTest {
    private fun operation(attempt: Long = 1, epoch: Long = 3) = NativeOwnerOperation.fromJson(JSONObject("""
        {"ticket":{"operation_id":"11111111-1111-4111-8111-111111111111","auth_epoch":$epoch,"attempt":$attempt,"family":"synthetic-family","device_id":"22222222-2222-4222-8222-222222222222","identity":{"slot":"stable","container_version":"0.2.16","runtime_version":"0.2.15","runtime_contract_version":1,"session_generation":7}},"expires_at_unix_ms":9999999999999}
    """))

    @Test fun ownerSnapshotHeadersPreserveEveryIdentityField() {
        val scope = operation().scope
        assertEquals(mapOf(
            "X-Nelomai-App-Version" to "0.2.16", "X-Nelomai-Container-Version" to "0.2.16",
            "X-Nelomai-Runtime-Version" to "0.2.15", "X-Nelomai-Runtime-Contract-Version" to "1",
            "X-Nelomai-Runtime-Slot" to "stable", "X-Nelomai-Session-Generation" to "7",
        ), scope.identityHeaders())
        assertEquals(scope, NativeOwnerScope.fromJson(scope.toJson()))
    }

    @Test fun realBearerTransportWritesTheSnapshotHeadersToTheConnection() {
        val connection = object : HttpsURLConnection(URL("https://synthetic.invalid")) {
            override fun connect() {}
            override fun disconnect() {}
            override fun usingProxy() = false
            override fun getCipherSuite() = "synthetic"
            override fun getLocalCertificates(): Array<Certificate>? = null
            override fun getServerCertificates(): Array<Certificate> = emptyArray()
            override fun getResponseCode() = 200
            override fun getInputStream() = "{}".byteInputStream()
        }
        val credential = BackgroundCredential(operation().scope.deviceId, "https://synthetic.invalid", "synthetic-access", 1000, operation().scope)
        val transport = UrlConnectionBackgroundApiTransport { url ->
            assertEquals("/api/client/v1/background/token", url.path)
            connection
        }
        transport.execute(credential, "POST", "background/token", null, BackgroundAuthorization.BEARER)
        assertEquals("Bearer synthetic-access", connection.getRequestProperty("Authorization"))
        assertEquals("0.2.16", connection.getRequestProperty("X-Nelomai-App-Version"))
        assertEquals("0.2.16", connection.getRequestProperty("X-Nelomai-Container-Version"))
        assertEquals("0.2.15", connection.getRequestProperty("X-Nelomai-Runtime-Version"))
        assertEquals("1", connection.getRequestProperty("X-Nelomai-Runtime-Contract-Version"))
        assertEquals("stable", connection.getRequestProperty("X-Nelomai-Runtime-Slot"))
        assertEquals("7", connection.getRequestProperty("X-Nelomai-Session-Generation"))
    }

    @Test fun newerOwnerOperationFencesOldNativeWritesWithoutErasingScope() {
        val store = BackgroundCredentialStore(MemoryBackend())
        val first = operation()
        val begun = store.beginOwnerOperation(0, first, false).value()
        val second = operation(2)
        val replaced = store.beginOwnerOperation(begun.revision, second, false).value()
        store.withOwnerOperation(first) {
            assertTrue(store.updateCapability(replaced.revision, BackgroundCapabilitySnapshot(1, true, 9999999999)) is CredentialStoreResult.Failure)
        }
        assertEquals(replaced, store.read().value())
        store.cancelOwnerOperation(second).value()
        store.withOwnerOperation(second) {
            assertTrue(store.read() is CredentialStoreResult.Failure)
        }
        assertEquals(second.scope, store.read().value().ownerScope)
    }

    @Test fun missingProtectedRecordCannotTurnAnOldCallbackIntoFreshInitialization() {
        val backend = MemoryBackend()
        val store = BackgroundCredentialStore(backend)
        val owner = operation()
        store.beginOwnerOperation(0, owner, false).value()
        backend.erase()
        store.withOwnerOperation(owner) {
            assertTrue(store.read() is CredentialStoreResult.Failure)
        }
    }

    @Test fun logoutFenceRejectsQueuedAndAlreadyRunningOwnerOperations() {
        val store = BackgroundCredentialStore(MemoryBackend())
        val first = operation()
        store.beginOwnerOperation(0, first, false).value()
        store.fenceOwnerLogout(4).value()
        val fenced = store.read().value()
        assertTrue(store.beginOwnerOperation(fenced.revision, operation(2), false) is CredentialStoreResult.Failure)
        store.withOwnerOperation(first) { assertTrue(store.read() is CredentialStoreResult.Failure) }
        assertEquals(fenced, store.read().value())
    }

    @Test fun responseAndTransportCarryServerDeviceAndEveryIdentityField() {
        val payload = JSONObject("""{"access_token":"synthetic-access","refresh_token":"synthetic-refresh","token_type":"Bearer","access_expires_in":900,"refresh_expires_in":3600,"device":{"id":"22222222-2222-4222-8222-222222222222","container_version":"0.2.16","runtime_version":"0.2.15","runtime_contract_version":1,"runtime_slot":"stable","session_generation":7}}""")
        val recovered = BackgroundSessionRecoveryResult.fromPayload(payload)
        val wire = JSONObject(recovered.responseJson)
        assertEquals("22222222-2222-4222-8222-222222222222", wire.getJSONObject("device").getString("id"))
        assertEquals("stable", wire.getJSONObject("device").getString("runtime_slot"))
        assertEquals(900, wire.getLong("access_expires_in"))
        assertFalse(recovered.toString().contains("synthetic-access"))
        val credential = BackgroundCredential(operation().scope.deviceId, "https://synthetic.invalid", "synthetic-access", 9999999999, operation().scope)
        val headers = backgroundAuthorizationHeaders(credential, BackgroundAuthorization.BEARER)
        assertEquals("Bearer synthetic-access", headers["Authorization"])
        assertEquals("0.2.15", headers["X-Nelomai-Runtime-Version"])
        assertEquals("7", headers["X-Nelomai-Session-Generation"])
        assertEquals(7, headers.size)
    }

    @Test fun scopedLegacyModeWithDisabledCapabilityKeepsBackgroundRecoveryAvailable() {
        val store = BackgroundCredentialStore(MemoryBackend())
        val owner = operation()
        val begun = store.beginOwnerOperation(0, owner, false).value()
        val request = BackgroundUiProvisionRequest(begun.revision, owner.scope.deviceId,
            "https://synthetic.invalid", "synthetic-access", "synthetic-install", 1,
            BackgroundCapabilitySnapshot(0, false, 1), owner.scope)
        var legacyCalls = 0
        val saved = store.withOwnerOperation(owner) {
            provisionOwnedBackgroundCredential(store, request, "legacy", 100,
                provision = { error("disabled capability must not start two-phase") },
                rotate = { error("fresh install has nothing to rotate") },
                legacy = { legacyCalls++; BackgroundCredential(owner.scope.deviceId, "https://synthetic.invalid", "synthetic-background", 1000) })
        }
        assertEquals(1, legacyCalls)
        assertEquals("synthetic-background", saved.active?.token)
        assertEquals(owner.scope, saved.ownerScope)
        assertTrue(hasRecoverableBackgroundCredential(saved))
        val newer = operation(2)
        assertEquals(newer.scope, store.beginOwnerOperation(saved.revision, newer, true).value().ownerScope)
    }

    @Test fun timedOutStagedActivationSurvivesAndFreshOwnerReplaysWithoutLegacyReplacement() {
        var now = 1000L
        val store = BackgroundCredentialStore(MemoryBackend(), nowMillis = { now })
        val owner = operation().copy(expiresAtUnixMs = 2000)
        var current = store.beginOwnerOperation(0, owner, false).value()
        current = store.configure(current.revision, BackgroundCredentialProvision(owner.scope.deviceId,
            "https://synthetic.invalid", "old-background", 1000, "synthetic-install", 1,
            BackgroundCapabilitySnapshot(1, true, 1000))).value()
        current = store.reserveMutation(current.revision, "prepare", owner.scope.deviceId, 1000, 100, "activate").value()
        val pending = BackgroundPendingToken("staged-background", 1000, 2, "prepare", "activate", 1)
        current = store.savePendingToken(current.revision, "prepare", pending, 100).value()
        now = 2001
        store.withOwnerOperation(owner) {
            assertTrue(store.promotePending(current.revision, "activate", 1200) is CredentialStoreResult.Failure)
        }
        assertEquals(pending, store.read().value().pending)
        val second = operation(2).copy(expiresAtUnixMs = 3000)
        current = store.beginOwnerOperation(current.revision, second, true).value()
        val request = BackgroundUiProvisionRequest(current.revision, owner.scope.deviceId,
            "https://synthetic.invalid", "unused-access", "synthetic-install", 1,
            BackgroundCapabilitySnapshot(1, true, 1000), owner.scope)
        val replayed = store.withOwnerOperation(second) {
            provisionOwnedBackgroundCredential(store, request, "legacy", 100,
                provision = { scoped -> provisionBackgroundCredential(store, scoped, 100,
                    operationIds = { error("must replay existing operation IDs") },
                    prepare = { _, _, _, _ -> error("must not prepare another token") },
                    activate = { _, saved, _ -> assertEquals(pending, saved); BackgroundActivationResult(1200, 2) }) },
                rotate = { error("pending activation has priority") },
                legacy = { error("pending activation must not be replaced by legacy issuance") })
        }
        assertEquals("staged-background", replayed.active?.token)
        assertEquals("old-background", replayed.previous?.token)
        assertNull(replayed.pending)
    }

    @Test fun newFamilyRequiresFinalizedCleanupAndUnknownLegacyScopeIsNeverAdmitted() {
        val store = BackgroundCredentialStore(MemoryBackend())
        val owner = operation()
        var current = store.beginOwnerOperation(0, owner, false).value()
        val provision = BackgroundCredentialProvision(owner.scope.deviceId, "https://synthetic.invalid",
            "synthetic-background", 1000, "synthetic-install", 1, BackgroundCapabilitySnapshot(0, false, 1))
        store.configure(current.revision, provision).value()
        val unknown = BackgroundCredentialStore(MemoryBackend())
        val legacy = unknown.configure(0, provision).value()
        assertTrue(unknown.beginOwnerOperation(legacy.revision, owner, true) is CredentialStoreResult.Failure)
        assertEquals(legacy, unknown.read().value())
        store.fenceOwnerLogout(4).value()
        current = store.beginLogoutCurrent("logout").value().envelope
        val newer = operation(2, 5).let { it.copy(scope = it.scope.copy(family = "new-family")) }
        assertTrue(store.beginOwnerOperation(current.revision, newer, false) is CredentialStoreResult.Failure)
        assertNotNull(store.read().value().cleanupCredential)
        current = store.finalizeLogout(current.revision, "logout").value()
        val begun = store.beginOwnerOperation(current.revision, newer, false).value()
        assertEquals(newer.scope, begun.ownerScope)
        store.withOwnerOperation(owner) { assertTrue(store.read() is CredentialStoreResult.Failure) }
    }

    private fun <T> CredentialStoreResult<T>.value(): T = (this as CredentialStoreResult.Success).value
    private class MemoryBackend : EncryptedRecordBackend {
        private var bytes: ByteArray? = null
        override fun read(): ByteArray? = bytes?.copyOf()
        override fun write(plaintext: ByteArray): Boolean { bytes = plaintext.copyOf(); return true }
        fun erase() { bytes = null }
    }
}
