package ru.nelomai.tunnel

import android.content.Context
import org.json.JSONObject
import java.util.UUID

/** Container compatibility for the stable contract-v1 credential store. Run in
 * :vpn, before constructing its engine, so no old executor or preferences cache
 * can race this one-record handoff. No stable artifact is patched or rebuilt. */
object StableBackgroundProvision {
    fun prepare(context: Context, request: String, engineLoaded: Boolean): Boolean {
        require(request.toByteArray().size <= 65536)
        // The dispatcher has matched this owner identity to the selected runtime.
        // Use that exact namespace, never a release number baked into the container.
        val scope = NativeOwnerOperation.fromJson(
            JSONObject(JSONObject(request).getString("owner_operation"))).scope
        require(scope.slot == "stable" && scope.runtimeContractVersion == 1L)
        val name = "runtime.stable.state.${scope.runtimeVersion}.nelomai-background-credential"
        return prepare(AndroidSecureEnvelopeBackend(context, name, "encrypted-envelope-v3",
            name, scoped = false), request, engineLoaded, System.currentTimeMillis())
    }

    /** false asks the common owner to exit the old process and retry. */
    internal fun prepare(backend: EncryptedRecordBackend, request: String,
        engineLoaded: Boolean, nowMillis: Long): Boolean {
        require(request.toByteArray().size <= 65536)
        val input = JSONObject(request)
        val owner = JSONObject(input.getString("owner_operation"))
        val operation = NativeOwnerOperation.fromJson(owner)
        val scope = operation.scope
        require(scope.slot == "stable" && scope.runtimeContractVersion == 1L)
        require(operation.expiresAtUnixMs > nowMillis)
        val raw = backend.read() ?: return true
        val current = try { BackgroundCredentialEnvelopeCodec.decode(raw) } finally { raw.fill(0) }
        val retained = current.ownerScope ?: return true // immutable legacy adoption owns this case
        if (retained == scope) return true
        // Stable already admits a new login after fully completed logout.
        // Leave its epoch/cancellation/attempt checks and the record untouched.
        if (current.logoutState?.phase == BackgroundLogoutPhase.FINALIZED &&
            current.installSecret == null && current.active == null && current.previous == null &&
            current.pending == null && current.reservation == null && current.cleanupCredential == null &&
            scope.authEpoch > retained.authEpoch) return true
        val source = requireNotNull(operation.provisionPredecessor)
        require(source.slot == "latest" && source.authEpoch == scope.authEpoch &&
            source.deviceId == scope.deviceId && source.sessionGeneration == scope.sessionGeneration - 1)
        require(retained.slot == scope.slot && retained.runtimeVersion == scope.runtimeVersion &&
            retained.runtimeContractVersion == scope.runtimeContractVersion)
        require(retained.sessionGeneration < source.sessionGeneration)
        require(scope.isSuccessorOf(retained, source))
        require(current.deviceId == scope.deviceId && input.getString("device_id") == scope.deviceId)
        require(current.panelBase == "https://nelomai.ru")
        require(input.getString("access_token").isNotBlank())
        require(current.installSecret != null && current.installSecret == input.getString("install_secret"))
        require(operation.attempt > current.ownerAttempt)
        require(current.ownerCancelEpoch == null && current.logoutState == null && current.cleanupCredential == null)
        if (current.pending != null || current.reservation != null) {
            // These IDs come only from the protected common owner's exact CLEAN
            // receipt + completed resume. That server transaction revokes all
            // old normal tokens and staged issuance. A local slot change, timeout
            // or predecessor scope alone does not authorize dropping a mutation.
            val proof = owner.getJSONObject("provision_predecessor")
            for (field in listOf("reconcile_operation_id", "resume_operation_id")) {
                val id = proof.optString(field)
                require(UUID.fromString(id).toString() == id)
            }
        }
        if (engineLoaded) return false
        // Only after physical engine exit can no late old HTTP executor write
        // its revoked result. Retire the confirmed old projections atomically;
        // immutable stable must provision again with the current bearer.
        val prepared = current.copy(revision = Math.addExact(current.revision, 1),
            ownerScope = scope, ownerOperation = null, active = null, previous = null,
            pending = null, reservation = null)
        val bytes = BackgroundCredentialEnvelopeCodec.encode(prepared)
        try { check(backend.write(bytes)) { "background_credential_persist_failed" } }
        finally { bytes.fill(0) }
        return true
    }
}
