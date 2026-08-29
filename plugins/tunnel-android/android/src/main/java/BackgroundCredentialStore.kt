package ru.nelomai.tunnel

import android.content.Context
import android.util.Base64
import java.net.URI
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import org.json.JSONObject

internal const val BACKGROUND_CREDENTIAL_FORMAT = 3

internal sealed class CredentialStoreResult<out T> {
    data class Success<T>(val value: T) : CredentialStoreResult<T>()
    data class Failure(val code: String) : CredentialStoreResult<Nothing>()
}

internal data class BackgroundCredential(
    val deviceId: String,
    val panelBase: String,
    val token: String,
    val expiresAtUnix: Long,
) {
    override fun toString(): String =
        "BackgroundCredential(deviceId=$deviceId, panelBase=$panelBase, token=<redacted>, expiresAtUnix=$expiresAtUnix)"
}

internal data class BackgroundCapabilitySnapshot(
    val revision: Long,
    val enabled: Boolean,
    val expiresAtUnix: Long,
)

internal data class BackgroundCredentialProvision(
    val deviceId: String,
    val panelBase: String,
    val token: String,
    val expiresAtUnix: Long,
    val installSecret: String,
    val installGeneration: Long,
    val capability: BackgroundCapabilitySnapshot,
) {
    override fun toString(): String =
        "BackgroundCredentialProvision(deviceId=$deviceId, panelBase=$panelBase, token=<redacted>, expiresAtUnix=$expiresAtUnix, installSecret=<redacted>, installGeneration=$installGeneration, capability=$capability)"
}

internal data class BackgroundMutationReservation(
    val mutationId: String,
    val activationOperationId: String,
    val deviceId: String,
    val expiresAtUnix: Long,
)

internal data class BackgroundPendingToken(
    val token: String,
    val stagedExpiresAtUnix: Long,
    val tokenGeneration: Long,
    val prepareOperationId: String,
    val activationOperationId: String,
    val contractVersion: Int,
) {
    override fun toString(): String =
        "BackgroundPendingToken(token=<redacted>, stagedExpiresAtUnix=$stagedExpiresAtUnix, tokenGeneration=$tokenGeneration, prepareOperationId=$prepareOperationId, activationOperationId=$activationOperationId, contractVersion=$contractVersion)"
}

internal enum class BackgroundLogoutPhase(val wireName: String) {
    PENDING("pending"),
    FINALIZED("finalized"),
    ;

    companion object {
        fun fromWireName(value: String): BackgroundLogoutPhase = values().firstOrNull {
            it.wireName == value
        } ?: throw IllegalArgumentException("invalid_background_logout_phase")
    }
}

internal data class BackgroundLogoutState(
    val operationId: String,
    val installGeneration: Long,
    val phase: BackgroundLogoutPhase,
)

internal data class BackgroundCredentialEnvelope(
    val formatVersion: Int = BACKGROUND_CREDENTIAL_FORMAT,
    val revision: Long = 0,
    val deviceId: String? = null,
    val panelBase: String? = null,
    val installSecret: String? = null,
    val installGeneration: Long? = null,
    val active: BackgroundCredential? = null,
    val previous: BackgroundCredential? = null,
    val pending: BackgroundPendingToken? = null,
    val capability: BackgroundCapabilitySnapshot? = null,
    val reservation: BackgroundMutationReservation? = null,
    val cleanupCredential: BackgroundCredential? = null,
    val logoutState: BackgroundLogoutState? = null,
) {
    override fun toString(): String =
        "BackgroundCredentialEnvelope(formatVersion=$formatVersion, revision=$revision, deviceId=$deviceId, panelBase=$panelBase, installSecret=${if (installSecret == null) null else "<redacted>"}, installGeneration=$installGeneration, active=${active?.copy(token = "<redacted>")}, previous=${previous?.copy(token = "<redacted>")}, pending=${pending?.copy(token = "<redacted>")}, capability=$capability, reservation=$reservation, cleanupCredential=${cleanupCredential?.copy(token = "<redacted>")}, logoutState=$logoutState)"
}

internal object BackgroundCredentialEnvelopeCodec {
    fun encode(envelope: BackgroundCredentialEnvelope): ByteArray {
        validate(envelope)
        val payload = JSONObject().apply {
            put("formatVersion", envelope.formatVersion)
            put("revision", envelope.revision)
            envelope.deviceId?.let { put("deviceId", it) }
            envelope.panelBase?.let { put("panelBase", it) }
            envelope.installSecret?.let { put("installSecret", it) }
            envelope.installGeneration?.let { put("installGeneration", it) }
            envelope.active?.let { put("active", credentialToJson(it)) }
            envelope.previous?.let { put("previous", credentialToJson(it)) }
            envelope.pending?.let { put("pending", pendingToJson(it)) }
            envelope.capability?.let { put("capability", capabilityToJson(it)) }
            envelope.reservation?.let { put("reservation", reservationToJson(it)) }
            envelope.cleanupCredential?.let { put("cleanupCredential", credentialToJson(it)) }
            envelope.logoutState?.let { put("logoutState", logoutToJson(it)) }
        }
        return payload.toString().toByteArray(Charsets.UTF_8)
    }

    fun decode(plaintext: ByteArray): BackgroundCredentialEnvelope {
        val payload = JSONObject(plaintext.toString(Charsets.UTF_8))
        require(payload.getInt("formatVersion") == BACKGROUND_CREDENTIAL_FORMAT) {
            "unsupported_background_credential_format"
        }
        return BackgroundCredentialEnvelope(
            revision = payload.getLong("revision"),
            deviceId = payload.optionalString("deviceId"),
            panelBase = payload.optionalString("panelBase"),
            installSecret = payload.optionalString("installSecret"),
            installGeneration = payload.optionalLong("installGeneration"),
            active = payload.optionalObject("active")?.let(::credentialFromJson),
            previous = payload.optionalObject("previous")?.let(::credentialFromJson),
            pending = payload.optionalObject("pending")?.let(::pendingFromJson),
            capability = payload.optionalObject("capability")?.let(::capabilityFromJson),
            reservation = payload.optionalObject("reservation")?.let(::reservationFromJson),
            cleanupCredential = payload.optionalObject("cleanupCredential")?.let(::credentialFromJson),
            logoutState = payload.optionalObject("logoutState")?.let(::logoutFromJson),
        ).also(::validate)
    }

    fun validate(envelope: BackgroundCredentialEnvelope) {
        require(envelope.formatVersion == BACKGROUND_CREDENTIAL_FORMAT)
        require(envelope.revision >= 0)
        envelope.deviceId?.let { require(normalizeDeviceId(it) == it) }
        envelope.panelBase?.let { require(normalizePanelBase(it) == it) }
        envelope.installSecret?.let(::requireSecret)
        envelope.installGeneration?.let { require(it > 0) }
        envelope.active?.let { validateCredential(envelope, it) }
        envelope.previous?.let { validateCredential(envelope, it) }
        envelope.cleanupCredential?.let { validateCredential(envelope, it) }
        envelope.pending?.let {
            requireSecret(it.token)
            require(it.stagedExpiresAtUnix > 0 && it.tokenGeneration > 0)
            requireSafeValue(it.prepareOperationId)
            requireSafeValue(it.activationOperationId)
            require(it.contractVersion > 0)
        }
        envelope.capability?.let {
            require(it.revision >= 0 && it.expiresAtUnix > 0)
        }
        envelope.reservation?.let {
            requireSafeValue(it.mutationId)
            requireSafeValue(it.activationOperationId)
            normalizeDeviceId(it.deviceId)
            require(it.deviceId == envelope.deviceId)
            require(it.expiresAtUnix > 0)
        }
        envelope.logoutState?.let {
            requireSafeValue(it.operationId)
            require(it.installGeneration > 0)
            require(it.installGeneration == envelope.installGeneration)
        }
        if (envelope.revision == 0L) require(envelope == BackgroundCredentialEnvelope())
        if (envelope.installSecret != null) require(envelope.installGeneration != null)
        if (envelope.active != null || envelope.previous != null || envelope.pending != null ||
            envelope.reservation != null || envelope.cleanupCredential != null ||
            envelope.logoutState != null
        ) {
            require(envelope.deviceId != null && envelope.panelBase != null)
        }
        envelope.pending?.let { pending ->
            val reservation = requireNotNull(envelope.reservation)
            require(envelope.active != null && envelope.installSecret != null)
            require(pending.prepareOperationId == reservation.mutationId)
            require(pending.activationOperationId == reservation.activationOperationId)
        }
        if (envelope.reservation != null) {
            require(envelope.active != null && envelope.installSecret != null)
        }
        if (envelope.previous != null) require(envelope.active != null)
        if (envelope.logoutState?.phase == BackgroundLogoutPhase.PENDING) {
            require(envelope.active == null && envelope.pending == null)
            require(envelope.cleanupCredential != null && envelope.installSecret != null)
        }
        if (envelope.logoutState?.phase == BackgroundLogoutPhase.FINALIZED) {
            require(envelope.active == null && envelope.previous == null)
            require(envelope.pending == null && envelope.cleanupCredential == null)
            require(envelope.installSecret == null && envelope.reservation == null)
        }
    }

    fun normalizeDeviceId(value: String): String = UUID.fromString(value).toString()

    fun normalizePanelBase(value: String): String {
        val normalized = value.trim().trimEnd('/')
        val uri = URI(normalized)
        require(uri.scheme.equals("https", ignoreCase = true))
        require(!uri.host.isNullOrBlank())
        require(uri.userInfo == null && uri.query == null && uri.fragment == null)
        return normalized
    }

    fun requireSafeValue(value: String) {
        require(value.isNotBlank() && value.length <= 512 && !value.contains('\u0000'))
    }

    private fun requireSecret(value: String) {
        require(value.isNotBlank() && value.length <= 4096 && !value.contains('\u0000'))
    }

    private fun validateCredential(envelope: BackgroundCredentialEnvelope, value: BackgroundCredential) {
        require(normalizeDeviceId(value.deviceId) == value.deviceId)
        require(normalizePanelBase(value.panelBase) == value.panelBase)
        require(value.deviceId == envelope.deviceId && value.panelBase == envelope.panelBase)
        requireSecret(value.token)
        require(value.expiresAtUnix > 0)
    }

    private fun credentialToJson(value: BackgroundCredential) = JSONObject().apply {
        put("deviceId", value.deviceId); put("panelBase", value.panelBase)
        put("token", value.token); put("expiresAtUnix", value.expiresAtUnix)
    }

    private fun credentialFromJson(payload: JSONObject) = BackgroundCredential(
        normalizeDeviceId(payload.getString("deviceId")),
        normalizePanelBase(payload.getString("panelBase")),
        payload.getString("token"), payload.getLong("expiresAtUnix"),
    )

    private fun pendingToJson(value: BackgroundPendingToken) = JSONObject().apply {
        put("token", value.token); put("stagedExpiresAtUnix", value.stagedExpiresAtUnix)
        put("tokenGeneration", value.tokenGeneration); put("prepareOperationId", value.prepareOperationId)
        put("activationOperationId", value.activationOperationId); put("contractVersion", value.contractVersion)
    }

    private fun pendingFromJson(payload: JSONObject) = BackgroundPendingToken(
        payload.getString("token"), payload.getLong("stagedExpiresAtUnix"),
        payload.getLong("tokenGeneration"), payload.getString("prepareOperationId"),
        payload.getString("activationOperationId"), payload.getInt("contractVersion"),
    )

    private fun capabilityToJson(value: BackgroundCapabilitySnapshot) = JSONObject().apply {
        put("revision", value.revision); put("enabled", value.enabled); put("expiresAtUnix", value.expiresAtUnix)
    }

    private fun capabilityFromJson(payload: JSONObject) = BackgroundCapabilitySnapshot(
        payload.getLong("revision"), payload.getBoolean("enabled"), payload.getLong("expiresAtUnix"),
    )

    private fun reservationToJson(value: BackgroundMutationReservation) = JSONObject().apply {
        put("mutationId", value.mutationId); put("deviceId", value.deviceId); put("expiresAtUnix", value.expiresAtUnix)
        put("activationOperationId", value.activationOperationId)
    }

    private fun reservationFromJson(payload: JSONObject) = BackgroundMutationReservation(
        payload.getString("mutationId"), payload.getString("activationOperationId"),
        normalizeDeviceId(payload.getString("deviceId")),
        payload.getLong("expiresAtUnix"),
    )

    private fun logoutToJson(value: BackgroundLogoutState) = JSONObject().apply {
        put("operationId", value.operationId); put("installGeneration", value.installGeneration)
        put("phase", value.phase.wireName)
    }

    private fun logoutFromJson(payload: JSONObject) = BackgroundLogoutState(
        payload.getString("operationId"), payload.getLong("installGeneration"),
        BackgroundLogoutPhase.fromWireName(payload.getString("phase")),
    )

    private fun JSONObject.optionalObject(name: String): JSONObject? =
        if (has(name) && !isNull(name)) getJSONObject(name) else null
    private fun JSONObject.optionalString(name: String): String? =
        if (has(name) && !isNull(name)) getString(name) else null
    private fun JSONObject.optionalLong(name: String): Long? =
        if (has(name) && !isNull(name)) getLong(name) else null
}

internal class BackgroundCredentialStore(private val backend: EncryptedRecordBackend) {
    private val gate = Any()

    fun read(): CredentialStoreResult<BackgroundCredentialEnvelope> = synchronized(gate) {
        readLocked()
    }

    fun configure(
        expectedRevision: Long,
        provision: BackgroundCredentialProvision,
    ): CredentialStoreResult<BackgroundCredentialEnvelope> = synchronized(gate) {
        mutate(expectedRevision, advancesRevision = true) { current ->
            if (current.logoutState?.phase == BackgroundLogoutPhase.PENDING) {
                throw MutationFailure("background_credential_logout_pending")
            }
            if (current.reservation != null) {
                throw MutationFailure("background_credential_mutation_in_progress")
            }
            val deviceId = BackgroundCredentialEnvelopeCodec.normalizeDeviceId(provision.deviceId)
            val panelBase = BackgroundCredentialEnvelopeCodec.normalizePanelBase(provision.panelBase)
            current.copy(
                revision = current.revision.incrementRevision(),
                deviceId = deviceId,
                panelBase = panelBase,
                installSecret = provision.installSecret,
                installGeneration = provision.installGeneration,
                active = BackgroundCredential(
                    deviceId, panelBase, provision.token, provision.expiresAtUnix,
                ),
                previous = null,
                pending = null,
                capability = provision.capability,
                reservation = null,
                cleanupCredential = null,
                logoutState = null,
            )
        }
    }

    fun importLegacy(
        credential: BackgroundCredential,
    ): CredentialStoreResult<BackgroundCredentialEnvelope> = synchronized(gate) {
        when (val currentResult = readLocked()) {
            is CredentialStoreResult.Failure -> currentResult
            is CredentialStoreResult.Success -> {
                if (currentResult.value.revision != 0L) {
                    currentResult
                } else {
                    val normalized = credential.copy(
                        deviceId = BackgroundCredentialEnvelopeCodec.normalizeDeviceId(
                            credential.deviceId,
                        ),
                        panelBase = BackgroundCredentialEnvelopeCodec.normalizePanelBase(
                            credential.panelBase,
                        ),
                    )
                    persist(
                        BackgroundCredentialEnvelope(
                            revision = 1,
                            deviceId = normalized.deviceId,
                            panelBase = normalized.panelBase,
                            active = normalized,
                        ),
                    )
                }
            }
        }
    }

    fun replaceLegacyCredential(
        expectedRevision: Long,
        credential: BackgroundCredential,
    ): CredentialStoreResult<BackgroundCredentialEnvelope> = synchronized(gate) {
        mutate(expectedRevision, advancesRevision = true) { current ->
            val normalized = credential.copy(
                deviceId = BackgroundCredentialEnvelopeCodec.normalizeDeviceId(
                    credential.deviceId,
                ),
                panelBase = BackgroundCredentialEnvelopeCodec.normalizePanelBase(
                    credential.panelBase,
                ),
            )
            current.copy(
                revision = current.revision.incrementRevision(),
                deviceId = normalized.deviceId,
                panelBase = normalized.panelBase,
                active = normalized,
                previous = null,
                pending = null,
                reservation = null,
                cleanupCredential = null,
                logoutState = null,
            )
        }
    }

    fun clear(
        expectedRevision: Long,
    ): CredentialStoreResult<BackgroundCredentialEnvelope> = synchronized(gate) {
        mutate(expectedRevision, advancesRevision = true) { current ->
            current.copy(
                revision = current.revision.incrementRevision(),
                installSecret = null,
                active = null,
                previous = null,
                pending = null,
                capability = null,
                reservation = null,
                cleanupCredential = null,
                logoutState = null,
            )
        }
    }

    fun reserveMutation(
        expectedRevision: Long,
        mutationId: String,
        deviceId: String,
        expiresAtUnix: Long,
        nowUnix: Long,
        activationOperationId: String = mutationId,
    ): CredentialStoreResult<BackgroundCredentialEnvelope> = synchronized(gate) {
        mutate(expectedRevision, advancesRevision = false) { current ->
            requireUsable(current)
            if (current.logoutState != null) throw MutationFailure(
                "background_credential_logout_pending",
            )
            val capability = current.capability
            if (capability == null || !capability.enabled || capability.expiresAtUnix <= nowUnix) {
                throw MutationFailure("background_credential_capability_unavailable")
            }
            val normalizedDeviceId = BackgroundCredentialEnvelopeCodec.normalizeDeviceId(deviceId)
            if (normalizedDeviceId != current.deviceId) {
                throw MutationFailure("background_credential_device_mismatch")
            }
            current.reservation?.let { existing ->
                if (existing.mutationId != mutationId ||
                    existing.activationOperationId != activationOperationId
                ) {
                    throw MutationFailure("background_credential_mutation_in_progress")
                }
            }
            BackgroundCredentialEnvelopeCodec.requireSafeValue(mutationId)
            BackgroundCredentialEnvelopeCodec.requireSafeValue(activationOperationId)
            require(expiresAtUnix > nowUnix)
            current.copy(
                reservation = BackgroundMutationReservation(
                    mutationId, activationOperationId, normalizedDeviceId, expiresAtUnix,
                ),
            )
        }
    }

    fun savePendingToken(
        expectedRevision: Long,
        mutationId: String,
        pending: BackgroundPendingToken,
        @Suppress("UNUSED_PARAMETER")
        nowUnix: Long,
    ): CredentialStoreResult<BackgroundCredentialEnvelope> = synchronized(gate) {
        mutate(expectedRevision, advancesRevision = false) { current ->
            requireUsable(current)
            if (current.logoutState != null) throw MutationFailure(
                "background_credential_logout_pending",
            )
            val reservation = current.reservation
                ?: throw MutationFailure("background_credential_mutation_conflict")
            if (reservation.mutationId != mutationId ||
                pending.prepareOperationId != reservation.mutationId ||
                pending.activationOperationId != reservation.activationOperationId
            ) {
                throw MutationFailure("background_credential_mutation_conflict")
            }
            current.copy(pending = pending)
        }
    }

    fun updateCapability(
        expectedRevision: Long,
        capability: BackgroundCapabilitySnapshot,
    ): CredentialStoreResult<BackgroundCredentialEnvelope> = synchronized(gate) {
        mutate(expectedRevision, advancesRevision = true) { current ->
            current.capability?.let { existing ->
                require(capability.revision >= existing.revision)
            }
            current.copy(
                revision = current.revision.incrementRevision(),
                capability = capability,
            )
        }
    }

    fun pendingActivation(
        @Suppress("UNUSED_PARAMETER") nowUnix: Long,
    ): CredentialStoreResult<BackgroundPendingToken> = synchronized(gate) {
        when (val currentResult = readLocked()) {
            is CredentialStoreResult.Failure -> currentResult
            is CredentialStoreResult.Success -> {
                val current = currentResult.value
                when {
                    current.logoutState != null -> CredentialStoreResult.Failure(
                        "background_credential_logout_pending",
                    )
                    current.pending == null -> CredentialStoreResult.Failure(
                        "background_credential_pending_absent",
                    )
                    else -> CredentialStoreResult.Success(current.pending)
                }
            }
        }
    }

    fun promotePending(
        expectedRevision: Long,
        activationOperationId: String,
        activeExpiresAtUnix: Long,
    ): CredentialStoreResult<BackgroundCredentialEnvelope> = synchronized(gate) {
        mutate(expectedRevision, advancesRevision = true) { current ->
            if (current.logoutState != null) throw MutationFailure(
                "background_credential_logout_pending",
            )
            val pending = current.pending
                ?: throw MutationFailure("background_credential_pending_absent")
            if (pending.activationOperationId != activationOperationId) {
                throw MutationFailure("background_credential_mutation_conflict")
            }
            require(activeExpiresAtUnix > 0)
            val active = current.active
                ?: throw MutationFailure("background_credential_active_absent")
            current.copy(
                revision = current.revision.incrementRevision(),
                active = active.copy(token = pending.token, expiresAtUnix = activeExpiresAtUnix),
                previous = active,
                pending = null,
                reservation = null,
            )
        }
    }

    fun discardNotApplied(
        expectedRevision: Long,
        activationOperationId: String,
    ): CredentialStoreResult<BackgroundCredentialEnvelope> = synchronized(gate) {
        mutate(expectedRevision, advancesRevision = true) { current ->
            if (current.logoutState != null) throw MutationFailure(
                "background_credential_logout_pending",
            )
            val pending = current.pending
                ?: throw MutationFailure("background_credential_pending_absent")
            if (pending.activationOperationId != activationOperationId) {
                throw MutationFailure("background_credential_mutation_conflict")
            }
            current.copy(
                revision = current.revision.incrementRevision(),
                pending = null,
                reservation = null,
            )
        }
    }

    fun beginLogout(
        expectedRevision: Long,
        operationId: String,
        installGeneration: Long,
    ): CredentialStoreResult<BackgroundCredentialEnvelope> = synchronized(gate) {
        mutate(expectedRevision, advancesRevision = true) { current ->
            BackgroundCredentialEnvelopeCodec.requireSafeValue(operationId)
            require(installGeneration > 0)
            current.logoutState?.let { existing ->
                if (existing.operationId == operationId &&
                    existing.installGeneration == installGeneration
                ) {
                    return@mutate current
                }
                throw MutationFailure("background_credential_logout_pending")
            }
            val active = current.active
                ?: throw MutationFailure("background_credential_active_absent")
            current.copy(
                revision = current.revision.incrementRevision(),
                active = null,
                previous = null,
                pending = null,
                capability = null,
                reservation = null,
                cleanupCredential = active,
                logoutState = BackgroundLogoutState(
                    operationId, installGeneration, BackgroundLogoutPhase.PENDING,
                ),
            )
        }
    }

    fun finalizeLogout(
        expectedRevision: Long,
        operationId: String,
    ): CredentialStoreResult<BackgroundCredentialEnvelope> = synchronized(gate) {
        mutate(expectedRevision, advancesRevision = true) { current ->
            val logout = current.logoutState
                ?: throw MutationFailure("background_credential_logout_absent")
            if (logout.operationId != operationId) {
                throw MutationFailure("background_credential_mutation_conflict")
            }
            if (logout.phase == BackgroundLogoutPhase.FINALIZED) return@mutate current
            current.copy(
                revision = current.revision.incrementRevision(),
                installSecret = null,
                active = null,
                previous = null,
                pending = null,
                capability = null,
                reservation = null,
                cleanupCredential = null,
                logoutState = logout.copy(phase = BackgroundLogoutPhase.FINALIZED),
            )
        }
    }

    private fun mutate(
        expectedRevision: Long,
        advancesRevision: Boolean,
        transform: (BackgroundCredentialEnvelope) -> BackgroundCredentialEnvelope,
    ): CredentialStoreResult<BackgroundCredentialEnvelope> {
        val currentResult = readLocked()
        if (currentResult is CredentialStoreResult.Failure) return currentResult
        val current = (currentResult as CredentialStoreResult.Success).value
        if (current.revision != expectedRevision) {
            return CredentialStoreResult.Failure("background_credential_revision_conflict")
        }
        return try {
            val next = transform(current)
            if (next == current) return CredentialStoreResult.Success(current)
            val expectedNext = if (advancesRevision) current.revision + 1 else current.revision
            if (next.revision != expectedNext) {
                return CredentialStoreResult.Failure("background_credential_revision_invalid")
            }
            persist(next)
        } catch (failure: MutationFailure) {
            CredentialStoreResult.Failure(failure.code)
        } catch (_: Throwable) {
            CredentialStoreResult.Failure("background_credential_invalid")
        }
    }

    private fun readLocked(): CredentialStoreResult<BackgroundCredentialEnvelope> {
        val plaintext = try {
            backend.read()
        } catch (_: Throwable) {
            return CredentialStoreResult.Failure("background_credential_read_failed")
        } ?: return CredentialStoreResult.Success(BackgroundCredentialEnvelope())
        return try {
            CredentialStoreResult.Success(BackgroundCredentialEnvelopeCodec.decode(plaintext))
        } catch (_: Throwable) {
            CredentialStoreResult.Failure("background_credential_corrupt")
        } finally {
            plaintext.fill(0)
        }
    }

    private fun persist(
        envelope: BackgroundCredentialEnvelope,
    ): CredentialStoreResult<BackgroundCredentialEnvelope> {
        val plaintext = try {
            BackgroundCredentialEnvelopeCodec.encode(envelope)
        } catch (_: Throwable) {
            return CredentialStoreResult.Failure("background_credential_invalid")
        }
        return try {
            if (backend.write(plaintext)) CredentialStoreResult.Success(envelope)
            else CredentialStoreResult.Failure("background_credential_write_failed")
        } catch (_: Throwable) {
            CredentialStoreResult.Failure("background_credential_write_failed")
        } finally {
            plaintext.fill(0)
        }
    }

    private fun requireUsable(envelope: BackgroundCredentialEnvelope) {
        if (envelope.active == null || envelope.installSecret == null) {
            throw MutationFailure("background_credential_unavailable")
        }
    }

    private fun Long.incrementRevision(): Long {
        if (this == Long.MAX_VALUE) throw MutationFailure(
            "background_credential_revision_exhausted",
        )
        return this + 1
    }

    private class MutationFailure(val code: String) : RuntimeException(code)

    companion object {
        fun save(context: Context, credential: BackgroundCredential) {
            val store = AndroidBackgroundCredentialStores.open(context)
            val current = when (val result = store.read()) {
                is CredentialStoreResult.Success -> result.value
                is CredentialStoreResult.Failure -> error(result.code)
            }
            val saved = if (current.revision == 0L) {
                store.importLegacy(credential)
            } else {
                store.replaceLegacyCredential(current.revision, credential)
            }
            check(saved is CredentialStoreResult.Success) {
                (saved as CredentialStoreResult.Failure).code
            }
        }

        fun load(context: Context): BackgroundCredential? =
            when (val result = AndroidBackgroundCredentialStores.open(context).read()) {
                is CredentialStoreResult.Success -> result.value.active
                is CredentialStoreResult.Failure -> null
            }

        fun clear(context: Context): Boolean {
            val store = AndroidBackgroundCredentialStores.open(context)
            val current = when (val result = store.read()) {
                is CredentialStoreResult.Success -> result.value
                is CredentialStoreResult.Failure -> return false
            }
            if (current.revision == 0L) return true
            return store.clear(current.revision) is CredentialStoreResult.Success
        }

        fun clearInvalidCredential(context: Context): Boolean {
            val store = AndroidBackgroundCredentialStores.open(context)
            val current = when (val result = store.read()) {
                is CredentialStoreResult.Success -> result.value
                is CredentialStoreResult.Failure -> return false
            }
            if (current.pending != null || current.reservation != null ||
                current.logoutState != null
            ) {
                return true
            }
            if (current.revision == 0L) return true
            return store.clear(current.revision) is CredentialStoreResult.Success
        }
    }
}

private const val BACKGROUND_PREFERENCES = "nelomai-background-credential"
private const val BACKGROUND_LEGACY_CIPHERTEXT = "ciphertext"
private const val BACKGROUND_LEGACY_IV = "iv"
private const val BACKGROUND_RECORD = "encrypted-envelope-v3"
private const val BACKGROUND_KEY_ALIAS = "nelomai-background-credential"

internal class AndroidLegacyBackgroundCredentialReader(context: Context) {
    private val preferences = context.applicationContext.getSharedPreferences(
        BACKGROUND_PREFERENCES,
        Context.MODE_PRIVATE,
    )

    fun read(): BackgroundCredential? {
        val encodedCiphertext = preferences.getString(BACKGROUND_LEGACY_CIPHERTEXT, null)
            ?: return null
        val encodedIv = preferences.getString(BACKGROUND_LEGACY_IV, null) ?: return null
        var plaintext: ByteArray? = null
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                androidEnvelopeSecretKey(BACKGROUND_KEY_ALIAS),
                GCMParameterSpec(128, Base64.decode(encodedIv, Base64.NO_WRAP)),
            )
            plaintext = cipher.doFinal(Base64.decode(encodedCiphertext, Base64.NO_WRAP))
            val payload = JSONObject(plaintext.toString(Charsets.UTF_8))
            require(payload.getInt("format") == 2)
            BackgroundCredential(
                deviceId = BackgroundCredentialEnvelopeCodec.normalizeDeviceId(
                    payload.getString("deviceId"),
                ),
                panelBase = BackgroundCredentialEnvelopeCodec.normalizePanelBase(
                    payload.getString("panelBase"),
                ),
                token = payload.getString("token"),
                expiresAtUnix = payload.getLong("expiresAtUnix"),
            )
        } catch (_: Throwable) {
            null
        } finally {
            plaintext?.fill(0)
        }
    }
}

internal object AndroidBackgroundCredentialStores {
    @Volatile
    private var instance: BackgroundCredentialStore? = null

    fun open(context: Context): BackgroundCredentialStore = instance ?: synchronized(this) {
        instance ?: create(context.applicationContext).also { instance = it }
    }

    private fun create(context: Context): BackgroundCredentialStore {
        val store = BackgroundCredentialStore(
            AndroidSecureEnvelopeBackend(
                context = context,
                preferenceName = BACKGROUND_PREFERENCES,
                recordName = BACKGROUND_RECORD,
                keyAlias = BACKGROUND_KEY_ALIAS,
            ),
        )
        val current = store.read()
        if (current is CredentialStoreResult.Success && current.value.revision == 0L) {
            AndroidLegacyBackgroundCredentialReader(context).read()?.let { legacy ->
                store.importLegacy(legacy)
            }
        }
        return store
    }

    internal fun resetForTests() = synchronized(this) {
        instance = null
    }
}
