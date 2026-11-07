package ru.nelomai.tunnel

import android.content.Context
import org.json.JSONObject
import java.util.UUID

/** Container compatibility for the stable contract-v1 credential store. Run in
 * :vpn, before constructing its engine, so no old executor or preferences cache
 * can race this one-record handoff. No stable artifact is patched or rebuilt. */
object StableBackgroundProvision {
    /** Reserve before any immutable engine can cache the namespace, including status/quick Start. */
    fun prepareEngine(context: Context, version: String) {
        require(version.length in 1..128 && version.all { it.isLetterOrDigit() || it in ".-+_" })
        val name = "runtime.stable.state.$version.nelomai-background-credential"
        prepareEngine(AndroidSecureEnvelopeBackend(context, name, "encrypted-envelope-v3", name, scoped = false)) {
            minimum -> requireNotNull(AndroidInstallGenerations.reserve(context, minimum, generationKey(version)))
        }
    }

    internal fun prepareEngine(backend: EncryptedRecordBackend, reserve: (Long) -> Long) {
        val bytes = backend.read()
        val current = try { bytes?.let(BackgroundCredentialEnvelopeCodec::decode) ?: BackgroundCredentialEnvelope() }
            finally { bytes?.fill(0) }
        // Pending logout and a completed empty receipt stay fenced. A current
        // new-login mutation may still carry the completed old marker; its exact
        // activation IDs survive normalization before the engine caches them.
        if (current.logoutState?.phase == BackgroundLogoutPhase.PENDING ||
            (current.logoutState?.phase == BackgroundLogoutPhase.FINALIZED && current.installSecret == null)) return
        val generation = reserve(current.installGeneration ?: 0)
        require(generation >= (current.installGeneration ?: 0))
        val changed = current.installGeneration != generation || current.logoutState != null
        // A failed commit may already be visible in the process cache. Confirm
        // this same projection durably before allowing the engine to load.
        val prepared = current.copy(revision = if (changed) Math.addExact(current.revision, 1) else current.revision,
            installGeneration = generation,
            // An interrupted new-login activation may still carry the completed
            // old receipt. Keep its exact current-owner mutation, not that marker.
            logoutState = null)
        val encoded = BackgroundCredentialEnvelopeCodec.encode(prepared)
        try { check(backend.write(encoded)) { "background_credential_persist_failed" } }
        finally { encoded.fill(0) }
    }

    private fun generationKey(version: String) = "stable:$version"

    fun prepare(context: Context, request: String, engineLoaded: Boolean): Boolean {
        require(request.toByteArray().size <= 65536)
        // The dispatcher has matched this owner identity to the selected runtime.
        // Use that exact namespace, never a release number baked into the container.
        val scope = NativeOwnerOperation.fromJson(
            JSONObject(JSONObject(request).getString("owner_operation"))).scope
        require(scope.slot == "stable" && scope.runtimeContractVersion == 1L)
        val name = "runtime.stable.state.${scope.runtimeVersion}.nelomai-background-credential"
        val backend = AndroidSecureEnvelopeBackend(context, name, "encrypted-envelope-v3", name, scoped = false)
        if (!prepare(backend, request, engineLoaded, System.currentTimeMillis())) return false
        if (!engineLoaded) prepareEngine(backend) { minimum ->
            requireNotNull(AndroidInstallGenerations.reserve(context, minimum, generationKey(scope.runtimeVersion)))
        }
        return prepareGeneration(backend, request, engineLoaded) { minimum, key, allowNew ->
            AndroidInstallGenerations.reserve(context, minimum, key, allowNew)
        }
    }

    internal fun prepareGeneration(backend: EncryptedRecordBackend, request: String,
        engineLoaded: Boolean, reserve: (Long, String, Boolean) -> Long?): Boolean {
        val input = JSONObject(request)
        val scope = NativeOwnerOperation.fromJson(JSONObject(input.getString("owner_operation"))).scope
        require(scope.slot == "stable" && scope.runtimeContractVersion == 1L)
        require(input.getString("device_id") == scope.deviceId)
        require(input.getString("access_token").isNotBlank() && input.getString("install_secret").isNotBlank())
        val bytes = backend.read()
        val current = try { bytes?.let(BackgroundCredentialEnvelopeCodec::decode) ?: BackgroundCredentialEnvelope() }
            finally { bytes?.fill(0) }
        require(current.logoutState?.phase != BackgroundLogoutPhase.PENDING)
        val finalized = current.logoutState?.phase == BackgroundLogoutPhase.FINALIZED
        require(finalized || current.deviceId == null || current.deviceId == scope.deviceId)
        require(current.installSecret == null || current.installSecret == input.getString("install_secret"))
        require(current.ownerCancelEpoch?.let { scope.authEpoch > it } != false)
        if (finalized) {
            require(current.installSecret == null && current.pending == null && current.reservation == null)
            require(current.ownerScope == null || scope.authEpoch > current.ownerScope.authEpoch)
        }
        val floor = maxOf(current.installGeneration ?: 0, current.logoutState?.installGeneration ?: 0)
        val minimum = if (finalized) Math.addExact(floor, 1) else floor
        val generation = reserve(minimum, generationKey(scope.runtimeVersion), !engineLoaded)
        check(generation != null) { "background_generation_unprepared" }
        if (!finalized && current.installGeneration == generation) return true
        // FINALIZED fences credentials, not legacy foreground Start. An engine
        // may already own a live tunnel: defer counter migration until its normal
        // idle process recycle instead of asking the owner to force-kill :vpn.
        check(!engineLoaded) { "background_generation_unprepared" }
        // Retire the completed identity as an empty enrollment. Native admission
        // binds the new owner later; interruption/logout before that stays
        // recoverable. Preserve the generation and attempt/cancel fences.
        val prepared = current.copy(revision = Math.addExact(current.revision, 1), installGeneration = generation,
            logoutState = if (finalized) null else current.logoutState,
            deviceId = if (finalized) null else current.deviceId,
            panelBase = if (finalized) null else current.panelBase,
            ownerScope = if (finalized) null else current.ownerScope,
            ownerOperation = if (finalized) null else current.ownerOperation,
            requiresFreshProvision = current.requiresFreshProvision || finalized)
        val encoded = BackgroundCredentialEnvelopeCodec.encode(prepared)
        try { check(backend.write(encoded)) { "background_credential_persist_failed" } }
        finally { encoded.fill(0) }
        return true
    }

    /** A loaded engine defers namespace mutation until its normal idle exit. */
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
        // Authorize a newer login here; generation preparation retires the
        // completed marker before the immutable engine reads its counter.
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
        require(current.ownerCancelEpoch?.let { scope.authEpoch > it } != false &&
            current.logoutState == null && current.cleanupCredential == null)
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
        check(!engineLoaded) { "background_generation_unprepared" }
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
