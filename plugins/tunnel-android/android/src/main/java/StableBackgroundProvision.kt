package ru.nelomai.tunnel

import android.content.Context
import org.json.JSONObject

/** Container compatibility for the immutable 0.2.20 credential store. Run in
 * :vpn, before constructing its engine, so no old executor or preferences cache
 * can race this one-record handoff. No stable artifact is patched or rebuilt. */
object StableBackgroundProvision {
    fun prepare(context: Context, request: String, engineLoaded: Boolean): Boolean {
        val name = "runtime.stable.state.0.2.20.nelomai-background-credential"
        return prepare(AndroidSecureEnvelopeBackend(context, name, "encrypted-envelope-v3",
            name, scoped = false), request, engineLoaded, System.currentTimeMillis())
    }

    /** false asks the common owner to exit the old process and retry. */
    internal fun prepare(backend: EncryptedRecordBackend, request: String,
        engineLoaded: Boolean, nowMillis: Long): Boolean {
        require(request.toByteArray().size <= 65536)
        val input = JSONObject(request)
        val operation = NativeOwnerOperation.fromJson(JSONObject(input.getString("owner_operation")))
        val scope = operation.scope
        require(scope.slot == "stable" && scope.runtimeVersion == "0.2.20")
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
        require(retained.slot == "stable" && retained.runtimeVersion == "0.2.20")
        require(retained.sessionGeneration < source.sessionGeneration)
        require(scope.isSuccessorOf(retained, source))
        require(current.deviceId == scope.deviceId && input.getString("device_id") == scope.deviceId)
        require(current.panelBase == "https://nelomai.ru")
        require(input.getString("access_token").isNotBlank())
        require(current.installSecret != null && current.installSecret == input.getString("install_secret"))
        require(operation.attempt > current.ownerAttempt)
        require(current.ownerCancelEpoch == null && current.logoutState == null &&
            current.pending == null && current.reservation == null && current.cleanupCredential == null)
        if (engineLoaded) return false
        // The completed transition revoked the predecessor's tokens. Drop only
        // settled token projections; provisioning must issue with the new bearer.
        val prepared = current.copy(revision = Math.addExact(current.revision, 1),
            ownerScope = scope, ownerOperation = null, active = null, previous = null)
        val bytes = BackgroundCredentialEnvelopeCodec.encode(prepared)
        try { check(backend.write(bytes)) { "background_credential_persist_failed" } }
        finally { bytes.fill(0) }
        return true
    }
}
