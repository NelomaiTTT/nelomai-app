package ru.nelomai.tunnel

import java.util.UUID
import org.json.JSONObject

internal const val ANDROID_RECOVERY_FORMAT = 1

internal interface EncryptedRecordBackend {
    fun read(): ByteArray?
    fun write(plaintext: ByteArray): Boolean
}

internal class EncryptedRecordCorruptException(
    cause: Throwable? = null,
) : RuntimeException("encrypted_record_corrupt", cause)

internal fun interface BootIdentityProvider {
    fun bootCount(): Long?
}

internal sealed class RecoveryStoreResult<out T> {
    data class Success<T>(val value: T) : RecoveryStoreResult<T>()
    data class Failure(val code: String) : RecoveryStoreResult<Nothing>()
}

internal data class AndroidIntentTemplate(
    val deviceId: String,
    val accountScope: String,
    val layer: String,
    val ticConnectionMode: String,
    val routeMode: String,
    val egressMode: String,
    val allowAlternate: Boolean,
)

internal data class AndroidRetryState(
    val attempt: Int = 0,
    val nextRetryAtUnix: Long? = null,
    val lastErrorCode: String? = null,
    val slowRecoveryNotified: Boolean = false,
)

internal data class AndroidConnectionIntent(
    val generation: Long,
    val bootCount: Long,
    val desiredActive: Boolean,
    val template: AndroidIntentTemplate?,
    val retry: AndroidRetryState,
) {
    companion object {
        fun empty(bootCount: Long) = AndroidConnectionIntent(
            generation = 0,
            bootCount = bootCount,
            desiredActive = false,
            template = null,
            retry = AndroidRetryState(),
        )
    }
}

internal enum class LeasePhase(val wireName: String) {
    START_PENDING("start_pending"),
    LEASE_ACQUIRED("lease_acquired"),
    ACTIVE_CHECKPOINT("active_checkpoint"),
    CLEANUP_PENDING("cleanup_pending"),
    STALE_CLEANUP("stale_cleanup"),
    ;

    companion object {
        fun fromWireName(value: String): LeasePhase = values().firstOrNull {
            it.wireName == value
        } ?: throw IllegalArgumentException("invalid_lease_phase")
    }
}

internal data class AndroidStartReplay(
    val startOperationId: String,
    val contractVersion: Int,
    val requestFingerprint: String,
)

internal data class AndroidLeaseTransaction(
    val generation: Long,
    val bootCount: Long,
    val phase: LeasePhase,
    val leaseId: String?,
    val stopOperationId: String?,
    val replay: AndroidStartReplay,
) {
    val startOperationId: String
        get() = replay.startOperationId
}

internal data class AndroidRecoveryEnvelope(
    val formatVersion: Int,
    val intent: AndroidConnectionIntent,
    val leaseTransaction: AndroidLeaseTransaction?,
) {
    companion object {
        fun empty(bootCount: Long) = AndroidRecoveryEnvelope(
            formatVersion = ANDROID_RECOVERY_FORMAT,
            intent = AndroidConnectionIntent.empty(bootCount),
            leaseTransaction = null,
        )
    }
}

internal object AndroidRecoveryEnvelopeCodec {
    fun encode(envelope: AndroidRecoveryEnvelope): ByteArray {
        validateEnvelope(envelope)
        val intent = JSONObject().apply {
            put("generation", envelope.intent.generation)
            put("bootCount", envelope.intent.bootCount)
            put("desiredActive", envelope.intent.desiredActive)
            put("retry", retryToJson(envelope.intent.retry))
            envelope.intent.template?.let { put("template", templateToJson(it)) }
        }
        val payload = JSONObject().apply {
            put("formatVersion", envelope.formatVersion)
            put("intent", intent)
            envelope.leaseTransaction?.let { put("leaseTransaction", leaseToJson(it)) }
        }
        return payload.toString().toByteArray(Charsets.UTF_8)
    }

    fun decode(plaintext: ByteArray): AndroidRecoveryEnvelope {
        val payload = JSONObject(plaintext.toString(Charsets.UTF_8))
        require(payload.getInt("formatVersion") == ANDROID_RECOVERY_FORMAT) {
            "unsupported_recovery_format"
        }
        val intentPayload = payload.getJSONObject("intent")
        val intent = AndroidConnectionIntent(
            generation = intentPayload.getLong("generation").also { require(it >= 0) },
            bootCount = intentPayload.getLong("bootCount").also { require(it >= 0) },
            desiredActive = intentPayload.getBoolean("desiredActive"),
            template = intentPayload.optionalObject("template")?.let(::templateFromJson),
            retry = retryFromJson(intentPayload.getJSONObject("retry")),
        )
        val transaction = payload.optionalObject("leaseTransaction")?.let(::leaseFromJson)
        return AndroidRecoveryEnvelope(
            formatVersion = ANDROID_RECOVERY_FORMAT,
            intent = intent,
            leaseTransaction = transaction,
        ).also(::validateEnvelope)
    }

    private fun templateToJson(template: AndroidIntentTemplate) = JSONObject().apply {
        put("deviceId", template.deviceId)
        put("accountScope", template.accountScope)
        put("layer", template.layer)
        put("ticConnectionMode", template.ticConnectionMode)
        put("routeMode", template.routeMode)
        put("egressMode", template.egressMode)
        put("allowAlternate", template.allowAlternate)
    }

    private fun templateFromJson(payload: JSONObject) = AndroidIntentTemplate(
        deviceId = UUID.fromString(payload.getString("deviceId")).toString(),
        accountScope = payload.getString("accountScope").also { requireSafeValue(it) },
        layer = payload.getString("layer").also { require(it in setOf("tic", "stray")) },
        ticConnectionMode = payload.getString("ticConnectionMode").also {
            require(it in setOf("personal", "dynamic"))
        },
        routeMode = payload.getString("routeMode").also {
            require(it in setOf("standalone", "via_tak"))
        },
        egressMode = payload.getString("egressMode").also {
            require(it in setOf("ipv4", "prefer_ipv6"))
        },
        allowAlternate = payload.getBoolean("allowAlternate"),
    )

    private fun retryToJson(retry: AndroidRetryState) = JSONObject().apply {
        put("attempt", retry.attempt)
        retry.nextRetryAtUnix?.let { put("nextRetryAtUnix", it) }
        retry.lastErrorCode?.let { put("lastErrorCode", it) }
        put("slowRecoveryNotified", retry.slowRecoveryNotified)
    }

    private fun retryFromJson(payload: JSONObject) = AndroidRetryState(
        attempt = payload.getInt("attempt").also { require(it >= 0) },
        nextRetryAtUnix = payload.optionalLong("nextRetryAtUnix"),
        lastErrorCode = payload.optionalString("lastErrorCode")?.also(::requireSafeValue),
        slowRecoveryNotified = payload.getBoolean("slowRecoveryNotified"),
    )

    private fun leaseToJson(transaction: AndroidLeaseTransaction) = JSONObject().apply {
        put("generation", transaction.generation)
        put("bootCount", transaction.bootCount)
        put("phase", transaction.phase.wireName)
        transaction.leaseId?.let { put("leaseId", it) }
        transaction.stopOperationId?.let { put("stopOperationId", it) }
        put("replay", JSONObject().apply {
            put("startOperationId", transaction.replay.startOperationId)
            put("contractVersion", transaction.replay.contractVersion)
            put("requestFingerprint", transaction.replay.requestFingerprint)
        })
    }

    private fun leaseFromJson(payload: JSONObject): AndroidLeaseTransaction {
        val replay = payload.getJSONObject("replay")
        return AndroidLeaseTransaction(
            generation = payload.getLong("generation").also { require(it > 0) },
            bootCount = payload.getLong("bootCount").also { require(it >= 0) },
            phase = LeasePhase.fromWireName(payload.getString("phase")),
            leaseId = payload.optionalString("leaseId")?.also(::requireSafeValue),
            stopOperationId = payload.optionalString("stopOperationId")?.also(::requireSafeValue),
            replay = AndroidStartReplay(
                startOperationId = replay.getString("startOperationId").also(::requireSafeValue),
                contractVersion = replay.getInt("contractVersion").also { require(it > 0) },
                requestFingerprint = replay.getString("requestFingerprint").also(::requireSafeValue),
            ),
        )
    }

    fun validateSafeValue(value: String) {
        require(value.isNotBlank() && value.length <= 512 && !value.contains('\u0000'))
    }

    private fun validateEnvelope(envelope: AndroidRecoveryEnvelope) {
        require(envelope.formatVersion == ANDROID_RECOVERY_FORMAT)
        require(envelope.intent.generation >= 0 && envelope.intent.bootCount >= 0)
        require(envelope.intent.retry.attempt >= 0)
        require(
            envelope.intent.retry.nextRetryAtUnix == null ||
                envelope.intent.retry.nextRetryAtUnix >= 0,
        )
        envelope.intent.retry.lastErrorCode?.let(::validateSafeValue)
        envelope.intent.template?.let { template ->
            require(UUID.fromString(template.deviceId).toString() == template.deviceId)
            validateSafeValue(template.accountScope)
            require(template.layer in setOf("tic", "stray"))
            require(template.ticConnectionMode in setOf("personal", "dynamic"))
            require(template.routeMode in setOf("standalone", "via_tak"))
            require(template.egressMode in setOf("ipv4", "prefer_ipv6"))
        }
        envelope.leaseTransaction?.let { transaction ->
            require(transaction.generation > 0)
            require(transaction.generation == envelope.intent.generation)
            require(transaction.bootCount >= 0)
            if (transaction.phase != LeasePhase.STALE_CLEANUP) {
                require(transaction.bootCount == envelope.intent.bootCount)
            }
            validateSafeValue(transaction.replay.startOperationId)
            require(transaction.replay.contractVersion > 0)
            validateSafeValue(transaction.replay.requestFingerprint)
            transaction.leaseId?.let(::validateSafeValue)
            transaction.stopOperationId?.let(::validateSafeValue)
            when (transaction.phase) {
                LeasePhase.START_PENDING -> {
                    require(transaction.leaseId == null)
                    require(transaction.stopOperationId == null)
                }
                LeasePhase.LEASE_ACQUIRED, LeasePhase.ACTIVE_CHECKPOINT -> {
                    require(transaction.leaseId != null)
                    require(transaction.stopOperationId == null)
                }
                LeasePhase.CLEANUP_PENDING -> {
                    require(transaction.leaseId != null)
                    require(transaction.stopOperationId != null)
                }
                LeasePhase.STALE_CLEANUP -> Unit
            }
        }
    }

    private fun requireSafeValue(value: String) = validateSafeValue(value)

    private fun JSONObject.optionalObject(name: String): JSONObject? =
        if (has(name) && !isNull(name)) getJSONObject(name) else null

    private fun JSONObject.optionalString(name: String): String? =
        if (has(name) && !isNull(name)) getString(name) else null

    private fun JSONObject.optionalLong(name: String): Long? =
        if (has(name) && !isNull(name)) getLong(name) else null
}

internal class AndroidRecoveryStore(
    private val backend: EncryptedRecordBackend,
    private val bootIdentity: BootIdentityProvider,
) {
    private val gate = Any()

    fun read(): RecoveryStoreResult<AndroidRecoveryEnvelope> = synchronized(gate) {
        readLocked()
    }

    fun beginStart(
        expectedGeneration: Long,
        template: AndroidIntentTemplate,
        replay: AndroidStartReplay,
    ): RecoveryStoreResult<AndroidRecoveryEnvelope> = synchronized(gate) {
        val currentResult = readLocked()
        if (currentResult is RecoveryStoreResult.Failure) return@synchronized currentResult
        val current = (currentResult as RecoveryStoreResult.Success).value
        if (current.intent.generation != expectedGeneration) return@synchronized generationConflict()
        if (current.leaseTransaction != null) {
            return@synchronized RecoveryStoreResult.Failure("connection_cleanup_pending")
        }
        val nextGeneration = expectedGeneration.checkedIncrement()
            ?: return@synchronized RecoveryStoreResult.Failure(
                "connection_intent_generation_exhausted",
            )
        val bootCount = bootIdentity.bootCount()
            ?: return@synchronized RecoveryStoreResult.Failure("boot_identity_unavailable")
        val next = try {
            AndroidRecoveryEnvelope(
                formatVersion = ANDROID_RECOVERY_FORMAT,
                intent = AndroidConnectionIntent(
                    generation = nextGeneration,
                    bootCount = bootCount,
                    desiredActive = true,
                    template = normalizeTemplate(template),
                    retry = AndroidRetryState(),
                ),
                leaseTransaction = AndroidLeaseTransaction(
                    generation = nextGeneration,
                    bootCount = bootCount,
                    phase = LeasePhase.START_PENDING,
                    leaseId = null,
                    stopOperationId = null,
                    replay = normalizeReplay(replay),
                ),
            )
        } catch (_: Throwable) {
            return@synchronized RecoveryStoreResult.Failure("connection_intent_invalid")
        }
        persist(next)
    }

    fun setDesiredActive(
        expectedGeneration: Long,
        desiredActive: Boolean,
    ): RecoveryStoreResult<AndroidRecoveryEnvelope> = synchronized(gate) {
        val currentResult = readLocked()
        if (currentResult is RecoveryStoreResult.Failure) return@synchronized currentResult
        val current = (currentResult as RecoveryStoreResult.Success).value
        if (current.intent.generation != expectedGeneration) return@synchronized generationConflict()
        if (current.intent.desiredActive == desiredActive) {
            return@synchronized RecoveryStoreResult.Success(current)
        }
        if (desiredActive && current.leaseTransaction != null) {
            return@synchronized RecoveryStoreResult.Failure("connection_cleanup_pending")
        }
        val nextGeneration = expectedGeneration.checkedIncrement()
            ?: if (!desiredActive) {
                expectedGeneration
            } else {
                return@synchronized RecoveryStoreResult.Failure(
                    "connection_intent_generation_exhausted",
                )
            }
        persist(
            current.copy(
                intent = current.intent.copy(
                    generation = nextGeneration,
                    desiredActive = desiredActive,
                    retry = AndroidRetryState(),
                ),
                leaseTransaction = current.leaseTransaction?.copy(
                    generation = nextGeneration,
                    phase = if (expectedGeneration == Long.MAX_VALUE) {
                        LeasePhase.STALE_CLEANUP
                    } else {
                        current.leaseTransaction.phase
                    },
                ),
            ),
        )
    }

    fun recordLease(
        expectedGeneration: Long,
        leaseId: String,
    ): RecoveryStoreResult<AndroidRecoveryEnvelope> = synchronized(gate) {
        mutateTransaction(expectedGeneration) { current, transaction ->
            require(transaction.phase == LeasePhase.START_PENDING)
            current.copy(
                leaseTransaction = transaction.copy(
                    phase = LeasePhase.LEASE_ACQUIRED,
                    leaseId = leaseId.also(AndroidRecoveryEnvelopeCodec::validateSafeValue),
                ),
            )
        }
    }

    fun activateCheckpoint(
        expectedGeneration: Long,
    ): RecoveryStoreResult<AndroidRecoveryEnvelope> = synchronized(gate) {
        mutateTransaction(expectedGeneration) { current, transaction ->
            require(transaction.phase == LeasePhase.LEASE_ACQUIRED)
            require(!transaction.leaseId.isNullOrBlank())
            current.copy(
                leaseTransaction = transaction.copy(phase = LeasePhase.ACTIVE_CHECKPOINT),
            )
        }
    }

    fun requireCleanup(
        expectedGeneration: Long,
        leaseId: String,
        stopOperationId: String,
    ): RecoveryStoreResult<AndroidRecoveryEnvelope> = synchronized(gate) {
        mutateTransaction(expectedGeneration) { current, transaction ->
            val normalizedLease = leaseId.also(AndroidRecoveryEnvelopeCodec::validateSafeValue)
            val existingLease = transaction.leaseId
            require(existingLease == null || existingLease == normalizedLease)
            current.copy(
                leaseTransaction = transaction.copy(
                    phase = LeasePhase.CLEANUP_PENDING,
                    leaseId = normalizedLease,
                    stopOperationId = stopOperationId.also(
                        AndroidRecoveryEnvelopeCodec::validateSafeValue,
                    ),
                ),
            )
        }
    }

    fun completeCleanup(
        expectedGeneration: Long,
    ): RecoveryStoreResult<AndroidRecoveryEnvelope> = synchronized(gate) {
        val currentResult = readLocked()
        if (currentResult is RecoveryStoreResult.Failure) return@synchronized currentResult
        val current = (currentResult as RecoveryStoreResult.Success).value
        if (current.intent.generation != expectedGeneration) return@synchronized generationConflict()
        val transaction = current.leaseTransaction
            ?: return@synchronized RecoveryStoreResult.Success(current)
        if (transaction.phase !in setOf(LeasePhase.CLEANUP_PENDING, LeasePhase.STALE_CLEANUP)) {
            return@synchronized RecoveryStoreResult.Failure("connection_cleanup_not_pending")
        }
        persist(current.copy(leaseTransaction = null))
    }

    private fun mutateTransaction(
        expectedGeneration: Long,
        mutation: (AndroidRecoveryEnvelope, AndroidLeaseTransaction) -> AndroidRecoveryEnvelope,
    ): RecoveryStoreResult<AndroidRecoveryEnvelope> {
        val currentResult = readLocked()
        if (currentResult is RecoveryStoreResult.Failure) return currentResult
        val current = (currentResult as RecoveryStoreResult.Success).value
        if (current.intent.generation != expectedGeneration) return generationConflict()
        val transaction = current.leaseTransaction
            ?: return RecoveryStoreResult.Failure("connection_transaction_unavailable")
        if (transaction.generation != expectedGeneration) return generationConflict()
        val next = try {
            mutation(current, transaction)
        } catch (_: Throwable) {
            return RecoveryStoreResult.Failure("connection_transaction_invalid")
        }
        return persist(next)
    }

    private fun readLocked(): RecoveryStoreResult<AndroidRecoveryEnvelope> {
        val plaintext = try {
            backend.read()
        } catch (_: EncryptedRecordCorruptException) {
            val bootCount = bootIdentity.bootCount()
                ?: return RecoveryStoreResult.Failure("boot_identity_unavailable")
            return persistFailClosed(
                AndroidRecoveryEnvelope.empty(bootCount),
                "recovery_record_corrupt",
            )
        } catch (_: Throwable) {
            return RecoveryStoreResult.Failure("recovery_record_read_failed")
        }
        val bootCount = bootIdentity.bootCount()
        if (plaintext == null) {
            return if (bootCount == null) {
                RecoveryStoreResult.Failure("boot_identity_unavailable")
            } else {
                RecoveryStoreResult.Success(AndroidRecoveryEnvelope.empty(bootCount))
            }
        }
        val current = try {
            AndroidRecoveryEnvelopeCodec.decode(plaintext)
        } catch (_: Throwable) {
            val failClosed = AndroidRecoveryEnvelope.empty(bootCount ?: 0)
            return persistFailClosed(failClosed, "recovery_record_corrupt")
        } finally {
            plaintext.fill(0)
        }
        if (bootCount == null) {
            val failClosed = staleAfterBootChange(current, current.intent.bootCount)
            return persistFailClosed(failClosed, "boot_identity_unavailable")
        }
        val liveTransactionBootMismatch = current.leaseTransaction?.let {
            it.phase != LeasePhase.STALE_CLEANUP && it.bootCount != bootCount
        } == true
        if (current.intent.bootCount != bootCount || liveTransactionBootMismatch
        ) {
            return persist(staleAfterBootChange(current, bootCount))
        }
        return RecoveryStoreResult.Success(current)
    }

    private fun persist(envelope: AndroidRecoveryEnvelope): RecoveryStoreResult<AndroidRecoveryEnvelope> {
        val plaintext = AndroidRecoveryEnvelopeCodec.encode(envelope)
        return try {
            if (backend.write(plaintext)) {
                RecoveryStoreResult.Success(envelope)
            } else {
                RecoveryStoreResult.Failure("recovery_record_write_failed")
            }
        } catch (_: Throwable) {
            RecoveryStoreResult.Failure("recovery_record_write_failed")
        } finally {
            plaintext.fill(0)
        }
    }

    private fun persistFailClosed(
        envelope: AndroidRecoveryEnvelope,
        failureCode: String,
    ): RecoveryStoreResult.Failure = when (persist(envelope)) {
        is RecoveryStoreResult.Success -> RecoveryStoreResult.Failure(failureCode)
        is RecoveryStoreResult.Failure -> RecoveryStoreResult.Failure("recovery_record_write_failed")
    }

    private fun staleAfterBootChange(
        current: AndroidRecoveryEnvelope,
        bootCount: Long,
    ): AndroidRecoveryEnvelope {
        val nextGeneration = current.intent.generation.checkedIncrement()
            ?: current.intent.generation
        return current.copy(
            intent = current.intent.copy(
                generation = nextGeneration,
                bootCount = bootCount,
                desiredActive = false,
                retry = AndroidRetryState(),
            ),
            leaseTransaction = current.leaseTransaction?.copy(
                generation = nextGeneration,
                phase = LeasePhase.STALE_CLEANUP,
            ),
        )
    }

    private fun normalizeTemplate(template: AndroidIntentTemplate): AndroidIntentTemplate {
        val normalized = template.copy(
            deviceId = UUID.fromString(template.deviceId).toString(),
            accountScope = template.accountScope.also(
                AndroidRecoveryEnvelopeCodec::validateSafeValue,
            ),
        )
        require(normalized.layer in setOf("tic", "stray"))
        require(normalized.ticConnectionMode in setOf("personal", "dynamic"))
        require(normalized.routeMode in setOf("standalone", "via_tak"))
        require(normalized.egressMode in setOf("ipv4", "prefer_ipv6"))
        return normalized
    }

    private fun normalizeReplay(replay: AndroidStartReplay): AndroidStartReplay {
        AndroidRecoveryEnvelopeCodec.validateSafeValue(replay.startOperationId)
        AndroidRecoveryEnvelopeCodec.validateSafeValue(replay.requestFingerprint)
        require(replay.contractVersion > 0)
        return replay
    }

    private fun generationConflict() =
        RecoveryStoreResult.Failure("connection_intent_generation_conflict")

    private fun Long.checkedIncrement(): Long? = if (this == Long.MAX_VALUE) null else this + 1

}
