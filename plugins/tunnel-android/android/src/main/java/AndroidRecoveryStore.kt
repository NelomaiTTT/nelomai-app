package ru.nelomai.tunnel

import java.util.UUID
import org.json.JSONObject

internal const val ANDROID_RECOVERY_FORMAT = 2
private const val ANDROID_RECOVERY_LEGACY_FORMAT = 1

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
    val syncBindingPreferences: Boolean = false,
    val options: AndroidTunnelOptions = AndroidTunnelOptions(),
)

internal data class AndroidTunnelOptions(
    val splitActive: Boolean = false,
    val policyHash: String? = null,
    val applicationMode: String? = null,
    val excludedPackages: List<String> = emptyList(),
    val includedPackages: List<String> = emptyList(),
    val splitTunnelRoutes: List<String> = emptyList(),
    val excludeLocalNetworks: Boolean = false,
    val dnsServers: List<String> = emptyList(),
) {
    fun toTunnelOptionsArgs() = TunnelOptionsArgs().also { args ->
        args.splitActive = splitActive
        args.policyHash = policyHash
        args.applicationMode = applicationMode
        args.excludedPackages = ArrayList(excludedPackages)
        args.includedPackages = ArrayList(includedPackages)
        args.splitTunnelRoutes = ArrayList(splitTunnelRoutes)
        args.excludeLocalNetworks = excludeLocalNetworks
        args.dnsServers = ArrayList(dnsServers)
    }
}

internal fun normalizeAndroidTunnelOptions(
    androidApiLevel: Int,
    args: TunnelOptionsArgs,
): AndroidTunnelOptions {
    args.policyHash?.let(AndroidRecoveryEnvelopeCodec::validateSafeValue)
    require(args.applicationMode in setOf(null, "exclude_selected", "include_selected"))
    val effective = AndroidSplitTunnel.resolveOptions(androidApiLevel, args)
    return AndroidTunnelOptions(
        splitActive = effective.splitSupported,
        policyHash = args.policyHash,
        applicationMode = args.applicationMode,
        excludedPackages = effective.excludedPackages,
        includedPackages = effective.includedPackages,
        splitTunnelRoutes = effective.excludedRoutes.map { it.canonical },
        excludeLocalNetworks = effective.excludeLocalNetworks,
        dnsServers = effective.dnsServers.mapNotNull { it.hostAddress },
    )
}

internal data class AndroidRetryState(
    val attempt: Int = 0,
    val nextRetryAtUnix: Long? = null,
    val scheduledDelaySeconds: Long? = null,
    val lastErrorCode: String? = null,
    val slowRecoveryNotified: Boolean = false,
    val serviceRecoveryUsed: Boolean = false,
    val profileRetryUsed: Boolean = false,
    val reconcileOnceUsed: Boolean = false,
    val terminalDiagnosticPending: Boolean = false,
    val pendingAction: String? = null,
)

internal data class AndroidConnectionIntent(
    val generation: Long,
    val diagnosticsEpisodeId: Long = generation,
    val bootCount: Long,
    val desiredActive: Boolean,
    val armedHistory: Boolean = false,
    val template: AndroidIntentTemplate?,
    val retry: AndroidRetryState,
) {
    companion object {
        fun empty(bootCount: Long) = AndroidConnectionIntent(
            generation = 0,
            bootCount = bootCount,
            desiredActive = false,
            armedHistory = false,
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
    val localStopPending: Boolean = false,
    val cleanupFailureCode: String? = null,
) {
    val startOperationId: String
        get() = replay.startOperationId
}

internal enum class RedundantSlot(val wireName: String) {
    A("A"),
    B("B"),
    ;

    companion object {
        fun fromWireName(value: String): RedundantSlot = values().firstOrNull {
            it.wireName == value
        } ?: throw IllegalArgumentException("invalid_redundant_slot")
    }
}

internal enum class RedundantStopState(val wireName: String) {
    NONE("none"),
    PENDING("pending"),
    ACKNOWLEDGED("acknowledged"),
    ;

    companion object {
        fun fromWireName(value: String): RedundantStopState = values().firstOrNull {
            it.wireName == value
        } ?: throw IllegalArgumentException("invalid_redundant_stop_state")
    }
}

internal data class AndroidRedundantRetryState(
    val attempt: Int = 0,
    val nextRetryAtUnix: Long? = null,
    val lastErrorCode: String? = null,
    val sessionStalledRecorded: Boolean = false,
    val stopState: RedundantStopState = RedundantStopState.NONE,
    val roleObservationPending: Boolean = false,
    val pendingRoleLeaseId: String? = null,
    val pendingRoleReason: String? = null,
    val acquirePending: Boolean = false,
    val acquireOperationId: String? = null,
    val acquireReplaceLeaseId: String? = null,
)

/** Safe recovery-v2 control state. Configurations and private keys remain ephemeral. */
internal data class AndroidRedundantTransaction(
    val desiredActive: Boolean,
    val template: AndroidIntentTemplate,
    val sessionId: String,
    val slotALeaseId: String?,
    val slotBLeaseId: String?,
    val localActiveLeaseId: String?,
    val standbyDesired: Boolean,
    val roleGeneration: Long,
    val membershipGeneration: Long,
    val startOperationId: String,
    val startRequestFingerprint: String,
    val stopOperationId: String? = null,
    val candidateLeaseId: String? = null,
    val candidateSlot: RedundantSlot? = null,
    val retry: AndroidRedundantRetryState = AndroidRedundantRetryState(),
) {
    fun containsCurrentLease(leaseId: String?): Boolean = leaseId != null &&
        leaseId in setOf(slotALeaseId, slotBLeaseId)
}

internal data class AndroidRecoveryEnvelope(
    val formatVersion: Int,
    val intent: AndroidConnectionIntent,
    val leaseTransaction: AndroidLeaseTransaction?,
    val redundantTransaction: AndroidRedundantTransaction? = null,
) {
    companion object {
        fun empty(bootCount: Long) = AndroidRecoveryEnvelope(
            formatVersion = ANDROID_RECOVERY_FORMAT,
            intent = AndroidConnectionIntent.empty(bootCount),
            leaseTransaction = null,
            redundantTransaction = null,
        )
    }
}

internal object AndroidRecoveryEnvelopeCodec {
    fun encode(envelope: AndroidRecoveryEnvelope): ByteArray {
        validateEnvelope(envelope)
        val intent = JSONObject().apply {
            put("generation", envelope.intent.generation)
            put("diagnosticsEpisodeId", envelope.intent.diagnosticsEpisodeId)
            put("bootCount", envelope.intent.bootCount)
            put("desiredActive", envelope.intent.desiredActive)
            put("armedHistory", envelope.intent.armedHistory)
            put("retry", retryToJson(envelope.intent.retry))
            envelope.intent.template?.let { put("template", templateToJson(it)) }
        }
        val payload = JSONObject().apply {
            put("formatVersion", envelope.formatVersion)
            put("intent", intent)
            envelope.leaseTransaction?.let { put("leaseTransaction", leaseToJson(it)) }
            envelope.redundantTransaction?.let { put("redundantTransaction", redundantToJson(it)) }
        }
        return payload.toString().toByteArray(Charsets.UTF_8)
    }

    fun decode(plaintext: ByteArray): AndroidRecoveryEnvelope {
        val payload = JSONObject(plaintext.toString(Charsets.UTF_8))
        val formatVersion = payload.getInt("formatVersion")
        require(formatVersion in setOf(ANDROID_RECOVERY_LEGACY_FORMAT, ANDROID_RECOVERY_FORMAT)) {
            "unsupported_recovery_format"
        }
        val intentPayload = payload.getJSONObject("intent")
        val generation = intentPayload.getLong("generation").also { require(it >= 0) }
        val intent = AndroidConnectionIntent(
            generation = generation,
            diagnosticsEpisodeId = intentPayload.optLong("diagnosticsEpisodeId", generation)
                .also { require(it >= 0) },
            bootCount = intentPayload.getLong("bootCount").also { require(it >= 0) },
            desiredActive = intentPayload.getBoolean("desiredActive"),
            armedHistory = intentPayload.optBoolean("armedHistory", false),
            template = intentPayload.optionalObject("template")?.let(::templateFromJson),
            retry = retryFromJson(intentPayload.getJSONObject("retry")),
        )
        val transaction = payload.optionalObject("leaseTransaction")?.let(::leaseFromJson)
        val redundantTransaction = payload.optionalObject("redundantTransaction")?.let(::redundantFromJson)
        val migratedIntent = if (formatVersion == ANDROID_RECOVERY_LEGACY_FORMAT &&
            (transaction?.phase == LeasePhase.ACTIVE_CHECKPOINT ||
                intent.retry.pendingAction == "terminal_after_cleanup")
        ) {
            intent.copy(armedHistory = true)
        } else {
            intent
        }
        return AndroidRecoveryEnvelope(
            formatVersion = ANDROID_RECOVERY_FORMAT,
            intent = migratedIntent,
            leaseTransaction = transaction,
            redundantTransaction = redundantTransaction,
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
        put("syncBindingPreferences", template.syncBindingPreferences)
        put("options", optionsToJson(template.options))
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
        syncBindingPreferences = payload.optBoolean("syncBindingPreferences", false),
        options = payload.optionalObject("options")?.let(::optionsFromJson) ?: AndroidTunnelOptions(),
    )

    private fun optionsToJson(options: AndroidTunnelOptions) = JSONObject().apply {
        put("splitActive", options.splitActive)
        options.policyHash?.let { put("policyHash", it) }
        options.applicationMode?.let { put("applicationMode", it) }
        put("excludedPackages", org.json.JSONArray(options.excludedPackages))
        put("includedPackages", org.json.JSONArray(options.includedPackages))
        put("splitTunnelRoutes", org.json.JSONArray(options.splitTunnelRoutes))
        put("excludeLocalNetworks", options.excludeLocalNetworks)
        put("dnsServers", org.json.JSONArray(options.dnsServers))
    }

    private fun optionsFromJson(payload: JSONObject) = AndroidTunnelOptions(
        splitActive = payload.optBoolean("splitActive", false),
        policyHash = payload.optionalString("policyHash"),
        applicationMode = payload.optionalString("applicationMode"),
        excludedPackages = payload.stringList("excludedPackages"),
        includedPackages = payload.stringList("includedPackages"),
        splitTunnelRoutes = payload.stringList("splitTunnelRoutes"),
        excludeLocalNetworks = payload.optBoolean("excludeLocalNetworks", false),
        dnsServers = payload.stringList("dnsServers"),
    )

    private fun retryToJson(retry: AndroidRetryState) = JSONObject().apply {
        put("attempt", retry.attempt)
        retry.nextRetryAtUnix?.let { put("nextRetryAtUnix", it) }
        retry.scheduledDelaySeconds?.let { put("scheduledDelaySeconds", it) }
        retry.lastErrorCode?.let { put("lastErrorCode", it) }
        put("slowRecoveryNotified", retry.slowRecoveryNotified)
        put("serviceRecoveryUsed", retry.serviceRecoveryUsed)
        put("profileRetryUsed", retry.profileRetryUsed)
        put("reconcileOnceUsed", retry.reconcileOnceUsed)
        put("terminalDiagnosticPending", retry.terminalDiagnosticPending)
        retry.pendingAction?.let { put("pendingAction", it) }
    }

    private fun retryFromJson(payload: JSONObject) = AndroidRetryState(
        attempt = payload.getInt("attempt").also { require(it >= 0) },
        nextRetryAtUnix = payload.optionalLong("nextRetryAtUnix"),
        scheduledDelaySeconds = payload.optionalLong("scheduledDelaySeconds"),
        lastErrorCode = payload.optionalString("lastErrorCode")?.also(::requireSafeValue),
        slowRecoveryNotified = payload.getBoolean("slowRecoveryNotified"),
        serviceRecoveryUsed = payload.optBoolean("serviceRecoveryUsed", false),
        profileRetryUsed = payload.optBoolean("profileRetryUsed", false),
        reconcileOnceUsed = payload.optBoolean("reconcileOnceUsed", false),
        terminalDiagnosticPending = payload.optBoolean("terminalDiagnosticPending", false),
        pendingAction = payload.optionalString("pendingAction")?.also {
            require(it in setOf(
                "reconcile",
                "local_restart",
                "validate_capability",
                "legacy_runtime_stop",
                "new_operation_after_cleanup",
                "terminal_after_cleanup",
                "initial_terminal_report_pending",
                "initial_terminal_after_cleanup",
            ))
        },
    )

    private fun leaseToJson(transaction: AndroidLeaseTransaction) = JSONObject().apply {
        put("generation", transaction.generation)
        put("bootCount", transaction.bootCount)
        put("phase", transaction.phase.wireName)
        transaction.leaseId?.let { put("leaseId", it) }
        transaction.stopOperationId?.let { put("stopOperationId", it) }
        put("localStopPending", transaction.localStopPending)
        transaction.cleanupFailureCode?.let { put("cleanupFailureCode", it) }
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
            localStopPending = payload.optBoolean("localStopPending", false),
            cleanupFailureCode = payload.optionalString("cleanupFailureCode")?.also {
                require(it == "tunnel_data_plane_stalled")
            },
            replay = AndroidStartReplay(
                startOperationId = replay.getString("startOperationId").also(::requireSafeValue),
                contractVersion = replay.getInt("contractVersion").also { require(it > 0) },
                requestFingerprint = replay.getString("requestFingerprint").also(::requireSafeValue),
            ),
        )
    }

    private fun redundantToJson(transaction: AndroidRedundantTransaction) = JSONObject().apply {
        put("desiredActive", transaction.desiredActive)
        put("template", templateToJson(transaction.template))
        put("sessionId", transaction.sessionId)
        transaction.slotALeaseId?.let { put("slotALeaseId", it) }
        transaction.slotBLeaseId?.let { put("slotBLeaseId", it) }
        transaction.localActiveLeaseId?.let { put("localActiveLeaseId", it) }
        put("standbyDesired", transaction.standbyDesired)
        put("roleGeneration", transaction.roleGeneration)
        put("membershipGeneration", transaction.membershipGeneration)
        put("startOperationId", transaction.startOperationId)
        put("startRequestFingerprint", transaction.startRequestFingerprint)
        transaction.stopOperationId?.let { put("stopOperationId", it) }
        transaction.candidateLeaseId?.let { put("candidateLeaseId", it) }
        transaction.candidateSlot?.let { put("candidateSlot", it.wireName) }
        put("retry", JSONObject().apply {
            put("attempt", transaction.retry.attempt)
            transaction.retry.nextRetryAtUnix?.let { put("nextRetryAtUnix", it) }
            transaction.retry.lastErrorCode?.let { put("lastErrorCode", it) }
            put("sessionStalledRecorded", transaction.retry.sessionStalledRecorded)
            put("stopState", transaction.retry.stopState.wireName)
            put("roleObservationPending", transaction.retry.roleObservationPending)
            transaction.retry.pendingRoleLeaseId?.let { put("pendingRoleLeaseId", it) }
            transaction.retry.pendingRoleReason?.let { put("pendingRoleReason", it) }
            put("acquirePending", transaction.retry.acquirePending)
            transaction.retry.acquireOperationId?.let { put("acquireOperationId", it) }
            transaction.retry.acquireReplaceLeaseId?.let { put("acquireReplaceLeaseId", it) }
        })
    }

    private fun redundantFromJson(payload: JSONObject): AndroidRedundantTransaction {
        val retry = payload.getJSONObject("retry")
        return AndroidRedundantTransaction(
            desiredActive = payload.getBoolean("desiredActive"),
            template = templateFromJson(payload.getJSONObject("template")),
            sessionId = UUID.fromString(payload.getString("sessionId")).toString(),
            slotALeaseId = payload.optionalString("slotALeaseId"),
            slotBLeaseId = payload.optionalString("slotBLeaseId"),
            localActiveLeaseId = payload.optionalString("localActiveLeaseId"),
            standbyDesired = payload.getBoolean("standbyDesired"),
            roleGeneration = payload.getLong("roleGeneration"),
            membershipGeneration = payload.getLong("membershipGeneration"),
            startOperationId = payload.getString("startOperationId"),
            startRequestFingerprint = payload.getString("startRequestFingerprint"),
            stopOperationId = payload.optionalString("stopOperationId"),
            candidateLeaseId = payload.optionalString("candidateLeaseId"),
            candidateSlot = payload.optionalString("candidateSlot")?.let(RedundantSlot::fromWireName),
            retry = AndroidRedundantRetryState(
                attempt = retry.getInt("attempt"),
                nextRetryAtUnix = retry.optionalLong("nextRetryAtUnix"),
                lastErrorCode = retry.optionalString("lastErrorCode"),
                sessionStalledRecorded = retry.optBoolean("sessionStalledRecorded", false),
                stopState = retry.optionalString("stopState")?.let(RedundantStopState::fromWireName)
                    ?: if (retry.optBoolean("stopQueued", false)) RedundantStopState.PENDING
                    else RedundantStopState.NONE,
                roleObservationPending = retry.optBoolean("roleObservationPending", false),
                pendingRoleLeaseId = retry.optionalString("pendingRoleLeaseId"),
                pendingRoleReason = retry.optionalString("pendingRoleReason"),
                acquirePending = retry.optBoolean("acquirePending", false),
                acquireOperationId = retry.optionalString("acquireOperationId"),
                acquireReplaceLeaseId = retry.optionalString("acquireReplaceLeaseId"),
            ),
        )
    }

    fun validateSafeValue(value: String) {
        require(value.isNotBlank() && value.length <= 512 && !value.contains('\u0000'))
    }

    private fun validateEnvelope(envelope: AndroidRecoveryEnvelope) {
        require(envelope.formatVersion == ANDROID_RECOVERY_FORMAT)
        require(envelope.intent.generation >= 0 && envelope.intent.bootCount >= 0)
        require(envelope.intent.diagnosticsEpisodeId >= 0)
        require(envelope.intent.retry.attempt >= 0)
        require(
            envelope.intent.retry.nextRetryAtUnix == null ||
                envelope.intent.retry.nextRetryAtUnix >= 0,
        )
        require(
            envelope.intent.retry.scheduledDelaySeconds == null ||
                envelope.intent.retry.scheduledDelaySeconds >= 0,
        )
        envelope.intent.retry.lastErrorCode?.let(::validateSafeValue)
        require(
            envelope.intent.retry.pendingAction in setOf(
                null,
                "reconcile",
                "local_restart",
                "validate_capability",
                "legacy_runtime_stop",
                "new_operation_after_cleanup",
                "terminal_after_cleanup",
                "initial_terminal_report_pending",
                "initial_terminal_after_cleanup",
            ),
        )
        require(
            envelope.intent.retry.terminalDiagnosticPending ==
                (envelope.intent.retry.pendingAction == "initial_terminal_report_pending"),
        )
        envelope.intent.template?.let { template ->
            require(UUID.fromString(template.deviceId).toString() == template.deviceId)
            validateSafeValue(template.accountScope)
            require(template.layer in setOf("tic", "stray"))
            require(template.ticConnectionMode in setOf("personal", "dynamic"))
            require(template.routeMode in setOf("standalone", "via_tak"))
            require(template.egressMode in setOf("ipv4", "prefer_ipv6"))
            validateOptions(template.options)
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
            require(transaction.cleanupFailureCode in setOf(null, "tunnel_data_plane_stalled"))
            if (transaction.cleanupFailureCode != null) {
                require(
                    transaction.phase in setOf(
                        LeasePhase.CLEANUP_PENDING,
                        LeasePhase.STALE_CLEANUP,
                    ),
                )
            }
            if (transaction.localStopPending) {
                require(transaction.phase in setOf(LeasePhase.CLEANUP_PENDING, LeasePhase.STALE_CLEANUP))
            }
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
        envelope.redundantTransaction?.let { transaction ->
            require(envelope.leaseTransaction == null)
            require(UUID.fromString(transaction.sessionId).toString() == transaction.sessionId)
            require(transaction.roleGeneration >= 0 && transaction.membershipGeneration >= 0)
            require(transaction.retry.attempt >= 0)
            require(transaction.retry.nextRetryAtUnix == null || transaction.retry.nextRetryAtUnix >= 0)
            transaction.template.let { template ->
                require(UUID.fromString(template.deviceId).toString() == template.deviceId)
                validateSafeValue(template.accountScope)
                validateOptions(template.options)
            }
            listOfNotNull(
                transaction.slotALeaseId,
                transaction.slotBLeaseId,
                transaction.localActiveLeaseId,
                transaction.startOperationId,
                transaction.startRequestFingerprint,
                transaction.stopOperationId,
                transaction.candidateLeaseId,
                transaction.retry.lastErrorCode,
            ).forEach(::validateSafeValue)
            require(transaction.localActiveLeaseId == null ||
                transaction.containsCurrentLease(transaction.localActiveLeaseId))
            require((transaction.candidateLeaseId == null) == (transaction.candidateSlot == null))
            if (transaction.retry.stopState != RedundantStopState.NONE) {
                require(!transaction.desiredActive)
                require(!transaction.stopOperationId.isNullOrBlank())
            }
            require(transaction.retry.roleObservationPending ==
                (transaction.retry.pendingRoleLeaseId != null && transaction.retry.pendingRoleReason != null))
            if (transaction.retry.roleObservationPending) {
                require(transaction.containsCurrentLease(transaction.retry.pendingRoleLeaseId))
            }
            require(transaction.retry.acquirePending ==
                (transaction.retry.acquireOperationId != null && transaction.retry.acquireReplaceLeaseId != null))
            transaction.retry.acquireOperationId?.let(::validateSafeValue)
            transaction.retry.acquireReplaceLeaseId?.let(::validateSafeValue)
            transaction.retry.acquireReplaceLeaseId?.let { replaceLeaseId ->
                require(transaction.containsCurrentLease(replaceLeaseId))
                require(replaceLeaseId != transaction.localActiveLeaseId)
            }
        }
        if (envelope.intent.retry.pendingAction == "terminal_after_cleanup") {
            val transaction = requireNotNull(envelope.leaseTransaction)
            require(envelope.intent.desiredActive)
            require(envelope.intent.armedHistory)
            require(envelope.intent.retry.lastErrorCode != null)
            require(transaction.phase in setOf(LeasePhase.CLEANUP_PENDING, LeasePhase.STALE_CLEANUP))
            require(!transaction.leaseId.isNullOrBlank())
            require(!transaction.stopOperationId.isNullOrBlank())
        }
        if (envelope.intent.retry.pendingAction == "initial_terminal_after_cleanup") {
            val transaction = requireNotNull(envelope.leaseTransaction)
            require(!envelope.intent.desiredActive)
            require(!envelope.intent.armedHistory)
            require(envelope.intent.retry.lastErrorCode != null)
            require(!envelope.intent.retry.terminalDiagnosticPending)
            require(
                (transaction.phase == LeasePhase.START_PENDING &&
                    transaction.leaseId == null && transaction.stopOperationId == null) ||
                    (transaction.phase in setOf(
                        LeasePhase.CLEANUP_PENDING,
                        LeasePhase.STALE_CLEANUP,
                    ) && !transaction.leaseId.isNullOrBlank() &&
                        !transaction.stopOperationId.isNullOrBlank()),
            )
        }
        if (envelope.intent.retry.pendingAction == "initial_terminal_report_pending") {
            val transaction = requireNotNull(envelope.leaseTransaction)
            require(!envelope.intent.desiredActive)
            require(!envelope.intent.armedHistory)
            require(envelope.intent.retry.lastErrorCode != null)
            require(envelope.intent.retry.terminalDiagnosticPending)
            require(
                (transaction.phase == LeasePhase.START_PENDING &&
                    transaction.leaseId == null && transaction.stopOperationId == null) ||
                    (transaction.phase in setOf(
                        LeasePhase.CLEANUP_PENDING,
                        LeasePhase.STALE_CLEANUP,
                    ) && !transaction.leaseId.isNullOrBlank() &&
                        !transaction.stopOperationId.isNullOrBlank()),
            )
        }
    }

    private fun requireSafeValue(value: String) = validateSafeValue(value)

    private fun validateOptions(options: AndroidTunnelOptions) {
        options.policyHash?.let(::validateSafeValue)
        require(options.applicationMode in setOf(null, "exclude_selected", "include_selected"))
        require(options.excludedPackages.size <= 512)
        require(options.includedPackages.size <= 512)
        require(options.splitTunnelRoutes.size <= 16_384)
        require(options.dnsServers.size <= 4)
        (options.excludedPackages + options.includedPackages + options.splitTunnelRoutes +
            options.dnsServers).forEach(::validateSafeValue)
    }

    private fun JSONObject.optionalObject(name: String): JSONObject? =
        if (has(name) && !isNull(name)) getJSONObject(name) else null

    private fun JSONObject.optionalString(name: String): String? =
        if (has(name) && !isNull(name)) getString(name) else null

    private fun JSONObject.optionalLong(name: String): Long? =
        if (has(name) && !isNull(name)) getLong(name) else null

    private fun JSONObject.stringList(name: String): List<String> {
        val values = optJSONArray(name) ?: return emptyList()
        return List(values.length()) { index -> values.getString(index) }
    }
}

internal class AndroidRecoveryStore(
    private val backend: EncryptedRecordBackend,
    private val bootIdentity: BootIdentityProvider,
) {
    private val gate = Any()

    fun read(): RecoveryStoreResult<AndroidRecoveryEnvelope> = synchronized(gate) {
        readLocked()
    }

    /** Persists only recovery-v2 control state; callers must never pass configuration bytes. */
    fun updateRedundant(
        update: (AndroidRedundantTransaction) -> AndroidRedundantTransaction,
    ): RecoveryStoreResult<AndroidRecoveryEnvelope> = synchronized(gate) {
        val currentResult = readLocked()
        if (currentResult is RecoveryStoreResult.Failure) return@synchronized currentResult
        val current = (currentResult as RecoveryStoreResult.Success).value
        val transaction = current.redundantTransaction
            ?: return@synchronized RecoveryStoreResult.Failure("redundant_recovery_not_found")
        try {
            persist(current.copy(redundantTransaction = update(transaction)))
        } catch (_: Throwable) {
            RecoveryStoreResult.Failure("redundant_recovery_invalid")
        }
    }

    fun beginRedundant(
        transaction: AndroidRedundantTransaction,
    ): RecoveryStoreResult<AndroidRecoveryEnvelope> = synchronized(gate) {
        val currentResult = readLocked()
        if (currentResult is RecoveryStoreResult.Failure) return@synchronized currentResult
        val current = (currentResult as RecoveryStoreResult.Success).value
        if (current.leaseTransaction != null || current.redundantTransaction != null) {
            return@synchronized RecoveryStoreResult.Failure("connection_cleanup_pending")
        }
        try {
            persist(current.copy(
                intent = current.intent.copy(
                    desiredActive = transaction.desiredActive,
                    template = transaction.template,
                    retry = AndroidRetryState(),
                ),
                redundantTransaction = transaction,
            ))
        } catch (_: Throwable) {
            RecoveryStoreResult.Failure("redundant_recovery_invalid")
        }
    }

    fun completeRedundantStop(
        stopOperationId: String,
    ): RecoveryStoreResult<AndroidRecoveryEnvelope> = synchronized(gate) {
        val currentResult = readLocked()
        if (currentResult is RecoveryStoreResult.Failure) return@synchronized currentResult
        val current = (currentResult as RecoveryStoreResult.Success).value
        val transaction = current.redundantTransaction
            ?: return@synchronized RecoveryStoreResult.Success(current)
        if (transaction.desiredActive || transaction.stopOperationId != stopOperationId ||
            transaction.retry.stopState != RedundantStopState.ACKNOWLEDGED
        ) {
            return@synchronized RecoveryStoreResult.Failure("redundant_stop_not_acknowledged")
        }
        persist(clearDisarmedEpisode(current).copy(redundantTransaction = null))
    }

    fun deferRedundantStop(
        stopOperationId: String,
    ): RecoveryStoreResult<AndroidRecoveryEnvelope> = updateRedundant { transaction ->
        transaction.copy(
            desiredActive = false,
            stopOperationId = transaction.stopOperationId ?: stopOperationId.also(
                AndroidRecoveryEnvelopeCodec::validateSafeValue,
            ),
            retry = transaction.retry.copy(stopState = RedundantStopState.PENDING),
        )
    }

    fun beginStart(
        expectedGeneration: Long,
        template: AndroidIntentTemplate,
        replay: AndroidStartReplay,
    ): RecoveryStoreResult<AndroidRecoveryEnvelope> = synchronized(gate) {
        val currentResult = readLocked()
        if (currentResult is RecoveryStoreResult.Failure) return@synchronized currentResult
        val current = (currentResult as RecoveryStoreResult.Success).value
        if (current.redundantTransaction != null) {
            return@synchronized RecoveryStoreResult.Failure("connection_recovery_v2_owned")
        }
        if (current.intent.generation != expectedGeneration) return@synchronized generationConflict()
        if (current.leaseTransaction != null) {
            return@synchronized RecoveryStoreResult.Failure("connection_cleanup_pending")
        }
        val nextGeneration = expectedGeneration.checkedIncrement()
            ?: return@synchronized RecoveryStoreResult.Failure(
                "connection_intent_generation_exhausted",
            )
        val nextDiagnosticsEpisodeId = nextAndroidDiagnosticsEpisodeId(
            current.intent.diagnosticsEpisodeId,
            nextGeneration,
        ) ?: return@synchronized RecoveryStoreResult.Failure(
            "connection_diagnostics_episode_exhausted",
        )
        val bootCount = bootIdentity.bootCount()
            ?: return@synchronized RecoveryStoreResult.Failure("boot_identity_unavailable")
        val next = try {
            AndroidRecoveryEnvelope(
                formatVersion = ANDROID_RECOVERY_FORMAT,
                intent = AndroidConnectionIntent(
                    generation = nextGeneration,
                    diagnosticsEpisodeId = nextDiagnosticsEpisodeId,
                    bootCount = bootCount,
                    desiredActive = true,
                    armedHistory = false,
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
                    localStopPending = false,
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
        setDesiredActiveLocked(current, desiredActive)
    }

    fun cancelCurrentIntent(): RecoveryStoreResult<AndroidRecoveryEnvelope> = synchronized(gate) {
        val currentResult = readLocked()
        if (currentResult is RecoveryStoreResult.Failure) return@synchronized currentResult
        setDesiredActiveLocked(
            (currentResult as RecoveryStoreResult.Success).value,
            desiredActive = false,
        )
    }

    fun cancelCurrentIntentForQuickToggle(): RecoveryStoreResult<AndroidRecoveryEnvelope> =
        synchronized(gate) {
            val currentResult = readLocked()
            if (currentResult is RecoveryStoreResult.Failure) return@synchronized currentResult
            val current = (currentResult as RecoveryStoreResult.Success).value
            setDesiredActiveLocked(
                current,
                desiredActive = false,
                leaseLessRuntimeStop = current.leaseTransaction == null,
            )
        }

    private fun setDesiredActiveLocked(
        current: AndroidRecoveryEnvelope,
        desiredActive: Boolean,
        leaseLessRuntimeStop: Boolean = false,
    ): RecoveryStoreResult<AndroidRecoveryEnvelope> {
        val expectedGeneration = current.intent.generation
        if (current.intent.desiredActive == desiredActive && desiredActive) {
            return RecoveryStoreResult.Success(current)
        }
        if (desiredActive && current.leaseTransaction != null) {
            return RecoveryStoreResult.Failure("connection_cleanup_pending")
        }
        val nextGeneration = expectedGeneration.checkedIncrement()
            ?: if (!desiredActive) {
                expectedGeneration
            } else {
                return RecoveryStoreResult.Failure(
                    "connection_intent_generation_exhausted",
                )
            }
        return persist(
            current.copy(
                intent = current.intent.copy(
                    generation = nextGeneration,
                    desiredActive = desiredActive,
                    retry = AndroidRetryState(
                        pendingAction = "legacy_runtime_stop".takeIf {
                            leaseLessRuntimeStop && !desiredActive
                        },
                    ),
                ),
                leaseTransaction = current.leaseTransaction?.copy(
                    generation = nextGeneration,
                    phase = if (expectedGeneration == Long.MAX_VALUE) {
                        LeasePhase.STALE_CLEANUP
                    } else {
                        current.leaseTransaction.phase
                    },
                    cleanupFailureCode = if (desiredActive) {
                        current.leaseTransaction.cleanupFailureCode
                    } else {
                        null
                    },
                ),
            ),
        )
    }

    fun completeLegacyRuntimeStop(
        expectedGeneration: Long,
    ): RecoveryStoreResult<AndroidRecoveryEnvelope> = synchronized(gate) {
        val currentResult = readLocked()
        if (currentResult is RecoveryStoreResult.Failure) return@synchronized currentResult
        val current = (currentResult as RecoveryStoreResult.Success).value
        if (current.intent.generation != expectedGeneration) return@synchronized generationConflict()
        if (current.intent.desiredActive || current.leaseTransaction != null ||
            current.intent.retry.pendingAction != "legacy_runtime_stop"
        ) {
            return@synchronized RecoveryStoreResult.Failure(
                "legacy_runtime_stop_not_pending",
            )
        }
        persist(clearDisarmedEpisode(current))
    }

    fun restartTerminal(
        expectedGeneration: Long,
        template: AndroidIntentTemplate,
        replay: AndroidStartReplay,
        stopOperationId: String,
    ): RecoveryStoreResult<AndroidRecoveryEnvelope> = synchronized(gate) {
        val currentResult = readLocked()
        if (currentResult is RecoveryStoreResult.Failure) return@synchronized currentResult
        val current = (currentResult as RecoveryStoreResult.Success).value
        if (current.redundantTransaction != null) {
            return@synchronized RecoveryStoreResult.Failure("connection_recovery_v2_owned")
        }
        if (current.intent.generation != expectedGeneration) return@synchronized generationConflict()
        if (!current.intent.desiredActive || current.intent.retry.lastErrorCode == null ||
            current.intent.retry.nextRetryAtUnix != null
        ) {
            return@synchronized RecoveryStoreResult.Failure("connection_intent_not_terminal")
        }
        val nextGeneration = expectedGeneration.checkedIncrement()
            ?: return@synchronized RecoveryStoreResult.Failure(
                "connection_intent_generation_exhausted",
            )
        val nextDiagnosticsEpisodeId = nextAndroidDiagnosticsEpisodeId(
            current.intent.diagnosticsEpisodeId,
            nextGeneration,
        ) ?: return@synchronized RecoveryStoreResult.Failure(
            "connection_diagnostics_episode_exhausted",
        )
        val normalizedTemplate = try {
            normalizeTemplate(template)
        } catch (_: Throwable) {
            return@synchronized RecoveryStoreResult.Failure("connection_intent_invalid")
        }
        val nextTransaction = current.leaseTransaction?.let { transaction ->
            val hasLease = transaction.leaseId != null
            transaction.copy(
                generation = nextGeneration,
                phase = if (hasLease) LeasePhase.CLEANUP_PENDING else LeasePhase.STALE_CLEANUP,
                stopOperationId = if (hasLease) {
                    transaction.stopOperationId ?: stopOperationId.also(
                        AndroidRecoveryEnvelopeCodec::validateSafeValue,
                    )
                } else {
                    transaction.stopOperationId
                },
                localStopPending = hasLease,
            )
        } ?: AndroidLeaseTransaction(
            generation = nextGeneration,
            bootCount = current.intent.bootCount,
            phase = LeasePhase.START_PENDING,
            leaseId = null,
            stopOperationId = null,
            replay = normalizeReplay(replay),
            localStopPending = false,
        )
        persist(
            current.copy(
                intent = current.intent.copy(
                    generation = nextGeneration,
                    diagnosticsEpisodeId = nextDiagnosticsEpisodeId,
                    armedHistory = current.intent.armedHistory,
                    template = normalizedTemplate,
                    retry = AndroidRetryState(
                        pendingAction = current.leaseTransaction?.let {
                            "new_operation_after_cleanup"
                        },
                    ),
                ),
                leaseTransaction = nextTransaction,
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
            require(transaction.phase in setOf(
                LeasePhase.LEASE_ACQUIRED,
                LeasePhase.ACTIVE_CHECKPOINT,
            ))
            require(!transaction.leaseId.isNullOrBlank())
            val nextDiagnosticsEpisodeId = requireNotNull(
                nextAndroidDiagnosticsEpisodeId(
                    current.intent.diagnosticsEpisodeId,
                    current.intent.generation,
                ),
            )
            current.copy(
                intent = current.intent.copy(
                    diagnosticsEpisodeId = nextDiagnosticsEpisodeId,
                    armedHistory = true,
                    retry = AndroidRetryState(),
                ),
                leaseTransaction = transaction.copy(phase = LeasePhase.ACTIVE_CHECKPOINT),
            )
        }
    }

    fun recordFailure(
        expectedGeneration: Long,
        errorCode: String,
        nextRetryAtUnix: Long?,
        scheduledDelaySeconds: Long? = null,
        serviceRecoveryUsed: Boolean? = null,
        profileRetryUsed: Boolean? = null,
        reconcileOnceUsed: Boolean? = null,
        pendingAction: String? = null,
    ): RecoveryStoreResult<AndroidRecoveryEnvelope> = synchronized(gate) {
        val currentResult = readLocked()
        if (currentResult is RecoveryStoreResult.Failure) return@synchronized currentResult
        val current = (currentResult as RecoveryStoreResult.Success).value
        if (current.intent.generation != expectedGeneration) return@synchronized generationConflict()
        val safeCode = try {
            errorCode.also(AndroidRecoveryEnvelopeCodec::validateSafeValue)
        } catch (_: Throwable) {
            return@synchronized RecoveryStoreResult.Failure("connection_intent_invalid")
        }
        persist(current.copy(intent = current.intent.copy(
            retry = current.intent.retry.copy(
                attempt = current.intent.retry.attempt.saturatingIncrement(),
                nextRetryAtUnix = nextRetryAtUnix,
                scheduledDelaySeconds = scheduledDelaySeconds,
                lastErrorCode = safeCode,
                serviceRecoveryUsed = serviceRecoveryUsed
                    ?: current.intent.retry.serviceRecoveryUsed,
                profileRetryUsed = profileRetryUsed
                    ?: current.intent.retry.profileRetryUsed,
                reconcileOnceUsed = reconcileOnceUsed
                    ?: current.intent.retry.reconcileOnceUsed,
                pendingAction = pendingAction,
            ),
        )))
    }

    fun recordTerminalCleanupRetry(
        expectedGeneration: Long,
        nextRetryAtUnix: Long,
        scheduledDelaySeconds: Long,
    ): RecoveryStoreResult<AndroidRecoveryEnvelope> = synchronized(gate) {
        val currentResult = readLocked()
        if (currentResult is RecoveryStoreResult.Failure) return@synchronized currentResult
        val current = (currentResult as RecoveryStoreResult.Success).value
        if (current.intent.generation != expectedGeneration) return@synchronized generationConflict()
        val transaction = current.leaseTransaction
            ?: return@synchronized RecoveryStoreResult.Failure("connection_cleanup_not_pending")
        if (!current.intent.desiredActive || current.intent.retry.lastErrorCode == null ||
            current.intent.retry.pendingAction != "terminal_after_cleanup" ||
            transaction.phase !in setOf(LeasePhase.CLEANUP_PENDING, LeasePhase.STALE_CLEANUP)
        ) {
            return@synchronized RecoveryStoreResult.Failure("connection_cleanup_not_pending")
        }
        persist(current.copy(intent = current.intent.copy(
            retry = current.intent.retry.copy(
                attempt = current.intent.retry.attempt.saturatingIncrement(),
                nextRetryAtUnix = nextRetryAtUnix,
                scheduledDelaySeconds = scheduledDelaySeconds,
            ),
        )))
    }

    fun clearPendingRetryAction(
        expectedGeneration: Long,
    ): RecoveryStoreResult<AndroidRecoveryEnvelope> = synchronized(gate) {
        val currentResult = readLocked()
        if (currentResult is RecoveryStoreResult.Failure) return@synchronized currentResult
        val current = (currentResult as RecoveryStoreResult.Success).value
        if (current.intent.generation != expectedGeneration) return@synchronized generationConflict()
        persist(current.copy(intent = current.intent.copy(
            retry = current.intent.retry.copy(pendingAction = null),
        )))
    }

    fun clearCredentialProvisioningBarrier(
        expectedGeneration: Long,
    ): RecoveryStoreResult<AndroidRecoveryEnvelope> = synchronized(gate) {
        val currentResult = readLocked()
        if (currentResult is RecoveryStoreResult.Failure) return@synchronized currentResult
        val current = (currentResult as RecoveryStoreResult.Success).value
        if (current.intent.generation != expectedGeneration) return@synchronized generationConflict()
        if (current.intent.retry.lastErrorCode != "background_credential_provision_pending") {
            return@synchronized RecoveryStoreResult.Success(current)
        }
        persist(current.copy(intent = current.intent.copy(
            retry = current.intent.retry.copy(
                attempt = 0,
                nextRetryAtUnix = null,
                scheduledDelaySeconds = null,
                lastErrorCode = null,
            ),
        )))
    }

    fun replaceStartOperation(
        expectedGeneration: Long,
        replay: AndroidStartReplay,
        errorCode: String,
        nextRetryAtUnix: Long,
        scheduledDelaySeconds: Long,
    ): RecoveryStoreResult<AndroidRecoveryEnvelope> = synchronized(gate) {
        val currentResult = readLocked()
        if (currentResult is RecoveryStoreResult.Failure) return@synchronized currentResult
        val current = (currentResult as RecoveryStoreResult.Success).value
        if (current.intent.generation != expectedGeneration) return@synchronized generationConflict()
        val transaction = current.leaseTransaction
            ?: return@synchronized RecoveryStoreResult.Failure("connection_transaction_unavailable")
        val normalized = try {
            normalizeReplay(replay)
        } catch (_: Throwable) {
            return@synchronized RecoveryStoreResult.Failure("connection_intent_invalid")
        }
        persist(current.copy(
            intent = current.intent.copy(retry = current.intent.retry.copy(
                attempt = current.intent.retry.attempt.saturatingIncrement(),
                nextRetryAtUnix = nextRetryAtUnix,
                scheduledDelaySeconds = scheduledDelaySeconds,
                lastErrorCode = errorCode.also(AndroidRecoveryEnvelopeCodec::validateSafeValue),
                pendingAction = "validate_capability",
            )),
            leaseTransaction = transaction.copy(
                phase = LeasePhase.START_PENDING,
                leaseId = null,
                stopOperationId = null,
                replay = normalized,
                localStopPending = false,
            ),
        ))
    }

    fun closeAuthoritativeStartAndRestart(
        expectedGeneration: Long,
        replay: AndroidStartReplay,
        errorCode: String,
        nextRetryAtUnix: Long,
        scheduledDelaySeconds: Long,
    ): RecoveryStoreResult<AndroidRecoveryEnvelope> = synchronized(gate) {
        val currentResult = readLocked()
        if (currentResult is RecoveryStoreResult.Failure) return@synchronized currentResult
        val current = (currentResult as RecoveryStoreResult.Success).value
        if (current.intent.generation != expectedGeneration) return@synchronized generationConflict()
        val transaction = current.leaseTransaction
            ?: return@synchronized RecoveryStoreResult.Failure("connection_transaction_unavailable")
        if (!current.intent.desiredActive || transaction.phase != LeasePhase.START_PENDING ||
            transaction.leaseId != null
        ) {
            return@synchronized RecoveryStoreResult.Failure("connection_start_not_pending")
        }
        val normalized = try {
            normalizeReplay(replay)
        } catch (_: Throwable) {
            return@synchronized RecoveryStoreResult.Failure("connection_intent_invalid")
        }
        persist(current.copy(
            intent = current.intent.copy(retry = current.intent.retry.copy(
                attempt = current.intent.retry.attempt.saturatingIncrement(),
                nextRetryAtUnix = nextRetryAtUnix,
                scheduledDelaySeconds = scheduledDelaySeconds,
                lastErrorCode = errorCode.also(AndroidRecoveryEnvelopeCodec::validateSafeValue),
                pendingAction = "validate_capability",
            )),
            leaseTransaction = transaction.copy(
                replay = normalized,
                localStopPending = false,
            ),
        ))
    }

    fun scheduleProfileRetryAfterCleanup(
        expectedGeneration: Long,
        leaseId: String,
        stopOperationId: String,
        errorCode: String,
        nextRetryAtUnix: Long,
        scheduledDelaySeconds: Long,
    ): RecoveryStoreResult<AndroidRecoveryEnvelope> = synchronized(gate) {
        val currentResult = readLocked()
        if (currentResult is RecoveryStoreResult.Failure) return@synchronized currentResult
        val current = (currentResult as RecoveryStoreResult.Success).value
        if (current.intent.generation != expectedGeneration) return@synchronized generationConflict()
        val transaction = current.leaseTransaction
            ?: return@synchronized RecoveryStoreResult.Failure("connection_transaction_unavailable")
        val normalizedLeaseId = try {
            leaseId.also(AndroidRecoveryEnvelopeCodec::validateSafeValue)
        } catch (_: Throwable) {
            return@synchronized RecoveryStoreResult.Failure("connection_intent_invalid")
        }
        if (!current.intent.desiredActive || transaction.leaseId != normalizedLeaseId ||
            transaction.phase !in setOf(LeasePhase.LEASE_ACQUIRED, LeasePhase.ACTIVE_CHECKPOINT)
        ) {
            return@synchronized RecoveryStoreResult.Failure("connection_cleanup_not_pending")
        }
        persist(current.copy(
            intent = current.intent.copy(retry = current.intent.retry.copy(
                attempt = current.intent.retry.attempt.saturatingIncrement(),
                nextRetryAtUnix = nextRetryAtUnix,
                scheduledDelaySeconds = scheduledDelaySeconds,
                lastErrorCode = errorCode.also(AndroidRecoveryEnvelopeCodec::validateSafeValue),
                profileRetryUsed = true,
                pendingAction = "new_operation_after_cleanup",
            )),
            leaseTransaction = transaction.copy(
                phase = LeasePhase.CLEANUP_PENDING,
                stopOperationId = stopOperationId.also(
                    AndroidRecoveryEnvelopeCodec::validateSafeValue,
                ),
                localStopPending = true,
            ),
        ))
    }

    fun scheduleStalledRecovery(
        expectedGeneration: Long,
        leaseId: String,
        stopOperationId: String,
        dynamicPoolBacked: Boolean,
        nowUnix: Long,
    ): RecoveryStoreResult<AndroidRecoveryEnvelope> = synchronized(gate) {
        val currentResult = readLocked()
        if (currentResult is RecoveryStoreResult.Failure) return@synchronized currentResult
        val current = (currentResult as RecoveryStoreResult.Success).value
        if (current.intent.generation != expectedGeneration) return@synchronized generationConflict()
        val transaction = current.leaseTransaction
            ?: return@synchronized RecoveryStoreResult.Failure("connection_transaction_unavailable")
        if (transaction.phase == LeasePhase.CLEANUP_PENDING &&
            transaction.leaseId == leaseId &&
            current.intent.retry.pendingAction == "new_operation_after_cleanup" &&
            current.intent.retry.lastErrorCode == "tunnel_data_plane_stalled"
        ) {
            return@synchronized RecoveryStoreResult.Success(current)
        }
        if (!current.intent.desiredActive || !current.intent.armedHistory ||
            transaction.phase != LeasePhase.ACTIVE_CHECKPOINT || transaction.leaseId != leaseId
        ) {
            return@synchronized RecoveryStoreResult.Failure("connection_stall_not_active")
        }
        val safeLease = try {
            leaseId.also(AndroidRecoveryEnvelopeCodec::validateSafeValue)
        } catch (_: Throwable) {
            return@synchronized RecoveryStoreResult.Failure("connection_intent_invalid")
        }
        val safeStop = try {
            stopOperationId.also(AndroidRecoveryEnvelopeCodec::validateSafeValue)
        } catch (_: Throwable) {
            return@synchronized RecoveryStoreResult.Failure("connection_intent_invalid")
        }
        val nextEpisodeId = nextAndroidDiagnosticsEpisodeId(
            current.intent.diagnosticsEpisodeId,
            current.intent.generation,
        ) ?: return@synchronized RecoveryStoreResult.Failure(
            "connection_diagnostics_episode_exhausted",
        )
        persist(current.copy(
            intent = current.intent.copy(
                diagnosticsEpisodeId = nextEpisodeId,
                retry = AndroidRetryState(
                    nextRetryAtUnix = nowUnix.coerceAtLeast(0),
                    scheduledDelaySeconds = 0,
                    lastErrorCode = "tunnel_data_plane_stalled",
                    pendingAction = "new_operation_after_cleanup",
                ),
            ),
            leaseTransaction = transaction.copy(
                phase = LeasePhase.CLEANUP_PENDING,
                leaseId = safeLease,
                stopOperationId = safeStop,
                localStopPending = true,
                cleanupFailureCode = if (dynamicPoolBacked) {
                    "tunnel_data_plane_stalled"
                } else {
                    null
                },
            ),
        ))
    }

    fun scheduleTerminalAfterCleanup(
        expectedGeneration: Long,
        leaseId: String,
        stopOperationId: String,
        errorCode: String,
    ): RecoveryStoreResult<AndroidRecoveryEnvelope> = synchronized(gate) {
        val currentResult = readLocked()
        if (currentResult is RecoveryStoreResult.Failure) return@synchronized currentResult
        val current = (currentResult as RecoveryStoreResult.Success).value
        if (current.intent.generation != expectedGeneration) return@synchronized generationConflict()
        val transaction = current.leaseTransaction
            ?: return@synchronized RecoveryStoreResult.Failure("connection_transaction_unavailable")
        val normalizedLeaseId = try {
            leaseId.also(AndroidRecoveryEnvelopeCodec::validateSafeValue)
        } catch (_: Throwable) {
            return@synchronized RecoveryStoreResult.Failure("connection_intent_invalid")
        }
        if (!current.intent.desiredActive || !current.intent.armedHistory ||
            transaction.leaseId != normalizedLeaseId ||
            transaction.phase !in setOf(
                LeasePhase.LEASE_ACQUIRED,
                LeasePhase.ACTIVE_CHECKPOINT,
                LeasePhase.CLEANUP_PENDING,
                LeasePhase.STALE_CLEANUP,
            )
        ) {
            return@synchronized RecoveryStoreResult.Failure("connection_cleanup_not_pending")
        }
        persist(current.copy(
            intent = current.intent.copy(retry = current.intent.retry.copy(
                attempt = current.intent.retry.attempt.saturatingIncrement(),
                nextRetryAtUnix = null,
                scheduledDelaySeconds = null,
                lastErrorCode = errorCode.also(AndroidRecoveryEnvelopeCodec::validateSafeValue),
                pendingAction = "terminal_after_cleanup",
            )),
            leaseTransaction = transaction.copy(
                phase = LeasePhase.CLEANUP_PENDING,
                stopOperationId = transaction.stopOperationId ?: stopOperationId.also(
                    AndroidRecoveryEnvelopeCodec::validateSafeValue,
                ),
                localStopPending = true,
            ),
        ))
    }

    fun scheduleInitialTerminalAfterCleanup(
        expectedGeneration: Long,
        leaseId: String,
        stopOperationId: String,
        errorCode: String,
    ): RecoveryStoreResult<AndroidRecoveryEnvelope> = synchronized(gate) {
        val currentResult = readLocked()
        if (currentResult is RecoveryStoreResult.Failure) return@synchronized currentResult
        val current = (currentResult as RecoveryStoreResult.Success).value
        if (current.intent.generation != expectedGeneration) return@synchronized generationConflict()
        val transaction = current.leaseTransaction
            ?: return@synchronized RecoveryStoreResult.Failure("connection_transaction_unavailable")
        val normalizedLeaseId = try {
            leaseId.also(AndroidRecoveryEnvelopeCodec::validateSafeValue)
        } catch (_: Throwable) {
            return@synchronized RecoveryStoreResult.Failure("connection_intent_invalid")
        }
        if (!current.intent.desiredActive || current.intent.armedHistory ||
            transaction.leaseId != normalizedLeaseId ||
            transaction.phase !in setOf(
                LeasePhase.LEASE_ACQUIRED,
                LeasePhase.CLEANUP_PENDING,
                LeasePhase.STALE_CLEANUP,
            )
        ) {
            return@synchronized RecoveryStoreResult.Failure("connection_cleanup_not_pending")
        }
        persist(current.copy(
            intent = current.intent.copy(
                desiredActive = false,
                retry = current.intent.retry.copy(
                    attempt = current.intent.retry.attempt.saturatingIncrement(),
                    nextRetryAtUnix = null,
                    scheduledDelaySeconds = null,
                    lastErrorCode = errorCode.also(
                        AndroidRecoveryEnvelopeCodec::validateSafeValue,
                    ),
                    terminalDiagnosticPending = true,
                    pendingAction = "initial_terminal_report_pending",
                ),
            ),
            leaseTransaction = transaction.copy(
                phase = LeasePhase.CLEANUP_PENDING,
                stopOperationId = transaction.stopOperationId ?: stopOperationId.also(
                    AndroidRecoveryEnvelopeCodec::validateSafeValue,
                ),
                localStopPending = true,
            ),
        ))
    }

    fun scheduleInitialTerminalReconcile(
        expectedGeneration: Long,
        errorCode: String,
    ): RecoveryStoreResult<AndroidRecoveryEnvelope> = synchronized(gate) {
        val currentResult = readLocked()
        if (currentResult is RecoveryStoreResult.Failure) return@synchronized currentResult
        val current = (currentResult as RecoveryStoreResult.Success).value
        if (current.intent.generation != expectedGeneration) return@synchronized generationConflict()
        val transaction = current.leaseTransaction
            ?: return@synchronized RecoveryStoreResult.Failure("connection_transaction_unavailable")
        if (!current.intent.desiredActive || current.intent.armedHistory ||
            transaction.phase != LeasePhase.START_PENDING || transaction.leaseId != null
        ) {
            return@synchronized RecoveryStoreResult.Failure("connection_start_not_pending")
        }
        val safeCode = try {
            errorCode.also(AndroidRecoveryEnvelopeCodec::validateSafeValue)
        } catch (_: Throwable) {
            return@synchronized RecoveryStoreResult.Failure("connection_intent_invalid")
        }
        val nextGeneration = expectedGeneration.checkedIncrement()
            ?: return@synchronized RecoveryStoreResult.Failure(
                "connection_intent_generation_exhausted",
            )
        persist(current.copy(
            intent = current.intent.copy(
                generation = nextGeneration,
                desiredActive = false,
                retry = current.intent.retry.copy(
                    attempt = current.intent.retry.attempt.saturatingIncrement(),
                    nextRetryAtUnix = null,
                    scheduledDelaySeconds = null,
                    lastErrorCode = safeCode,
                    terminalDiagnosticPending = true,
                    pendingAction = "initial_terminal_report_pending",
                ),
            ),
            leaseTransaction = transaction.copy(generation = nextGeneration),
        ))
    }

    fun acknowledgeInitialTerminalDiagnostic(
        expectedGeneration: Long,
        expectedDiagnosticsEpisodeId: Long? = null,
    ): RecoveryStoreResult<AndroidRecoveryEnvelope> = synchronized(gate) {
        val currentResult = readLocked()
        if (currentResult is RecoveryStoreResult.Failure) return@synchronized currentResult
        val current = (currentResult as RecoveryStoreResult.Success).value
        if (current.intent.generation != expectedGeneration) return@synchronized generationConflict()
        if (expectedDiagnosticsEpisodeId != null &&
            current.intent.diagnosticsEpisodeId != expectedDiagnosticsEpisodeId
        ) {
            return@synchronized generationConflict()
        }
        if (current.intent.desiredActive || current.intent.armedHistory ||
            current.intent.retry.lastErrorCode == null ||
            !current.intent.retry.terminalDiagnosticPending ||
            current.intent.retry.pendingAction != "initial_terminal_report_pending"
        ) {
            return@synchronized RecoveryStoreResult.Failure("connection_terminal_not_pending")
        }
        persist(current.copy(intent = current.intent.copy(retry = current.intent.retry.copy(
            terminalDiagnosticPending = false,
            pendingAction = "initial_terminal_after_cleanup",
        ))))
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
                    bootCount = current.intent.bootCount,
                    phase = LeasePhase.CLEANUP_PENDING,
                    leaseId = normalizedLease,
                    stopOperationId = transaction.stopOperationId ?: stopOperationId.also(
                        AndroidRecoveryEnvelopeCodec::validateSafeValue,
                    ),
                    localStopPending = true,
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
        persist(if (current.intent.desiredActive) {
            current.copy(leaseTransaction = null)
        } else {
            clearDisarmedEpisode(current)
        })
    }

    fun completeCleanupAsTerminal(
        expectedGeneration: Long,
    ): RecoveryStoreResult<AndroidRecoveryEnvelope> = synchronized(gate) {
        val currentResult = readLocked()
        if (currentResult is RecoveryStoreResult.Failure) return@synchronized currentResult
        val current = (currentResult as RecoveryStoreResult.Success).value
        if (current.intent.generation != expectedGeneration) return@synchronized generationConflict()
        val transaction = current.leaseTransaction
            ?: return@synchronized RecoveryStoreResult.Failure("connection_cleanup_not_pending")
        if (!current.intent.desiredActive || current.intent.retry.lastErrorCode == null ||
            current.intent.retry.pendingAction != "terminal_after_cleanup" ||
            transaction.phase !in setOf(LeasePhase.CLEANUP_PENDING, LeasePhase.STALE_CLEANUP)
        ) {
            return@synchronized RecoveryStoreResult.Failure("connection_cleanup_not_pending")
        }
        persist(current.copy(
            intent = current.intent.copy(retry = current.intent.retry.copy(
                nextRetryAtUnix = null,
                scheduledDelaySeconds = null,
                pendingAction = null,
            )),
            leaseTransaction = null,
        ))
    }

    fun completeInitialTerminalCleanup(
        expectedGeneration: Long,
    ): RecoveryStoreResult<AndroidRecoveryEnvelope> = synchronized(gate) {
        val currentResult = readLocked()
        if (currentResult is RecoveryStoreResult.Failure) return@synchronized currentResult
        val current = (currentResult as RecoveryStoreResult.Success).value
        if (current.intent.generation != expectedGeneration) return@synchronized generationConflict()
        val transaction = current.leaseTransaction
            ?: return@synchronized RecoveryStoreResult.Failure("connection_cleanup_not_pending")
        if (current.intent.desiredActive || current.intent.armedHistory ||
            current.intent.retry.pendingAction != "initial_terminal_after_cleanup" ||
            transaction.phase !in setOf(LeasePhase.CLEANUP_PENDING, LeasePhase.STALE_CLEANUP)
        ) {
            return@synchronized RecoveryStoreResult.Failure("connection_cleanup_not_pending")
        }
        persist(clearDisarmedEpisode(current))
    }

    fun completeCleanupAndRestart(
        expectedGeneration: Long,
        replay: AndroidStartReplay,
    ): RecoveryStoreResult<AndroidRecoveryEnvelope> = synchronized(gate) {
        val currentResult = readLocked()
        if (currentResult is RecoveryStoreResult.Failure) return@synchronized currentResult
        val current = (currentResult as RecoveryStoreResult.Success).value
        if (current.intent.generation != expectedGeneration) return@synchronized generationConflict()
        val transaction = current.leaseTransaction
            ?: return@synchronized RecoveryStoreResult.Failure("connection_cleanup_not_pending")
        if (!current.intent.desiredActive ||
            transaction.phase !in setOf(LeasePhase.CLEANUP_PENDING, LeasePhase.STALE_CLEANUP)
        ) {
            return@synchronized RecoveryStoreResult.Failure("connection_cleanup_not_pending")
        }
        val normalized = try {
            normalizeReplay(replay)
        } catch (_: Throwable) {
            return@synchronized RecoveryStoreResult.Failure("connection_intent_invalid")
        }
        persist(current.copy(
            intent = current.intent.copy(
                retry = current.intent.retry.copy(pendingAction = "validate_capability"),
            ),
            leaseTransaction = AndroidLeaseTransaction(
                generation = current.intent.generation,
                bootCount = current.intent.bootCount,
                phase = LeasePhase.START_PENDING,
                leaseId = null,
                stopOperationId = null,
                replay = normalized,
                localStopPending = false,
            ),
        ))
    }

    fun completeCancelledStart(
        expectedGeneration: Long,
    ): RecoveryStoreResult<AndroidRecoveryEnvelope> = synchronized(gate) {
        val currentResult = readLocked()
        if (currentResult is RecoveryStoreResult.Failure) return@synchronized currentResult
        val current = (currentResult as RecoveryStoreResult.Success).value
        if (current.intent.generation != expectedGeneration) return@synchronized generationConflict()
        val transaction = current.leaseTransaction
            ?: return@synchronized RecoveryStoreResult.Success(current)
        if (transaction.phase != LeasePhase.START_PENDING || transaction.leaseId != null) {
            return@synchronized RecoveryStoreResult.Failure("connection_start_not_pending")
        }
        if (current.intent.desiredActive) {
            return@synchronized RecoveryStoreResult.Failure("connection_intent_still_active")
        }
        persist(clearDisarmedEpisode(current))
    }

    private fun clearDisarmedEpisode(current: AndroidRecoveryEnvelope) = current.copy(
        intent = current.intent.copy(
            desiredActive = false,
            armedHistory = false,
            template = null,
            retry = AndroidRetryState(),
        ),
        leaseTransaction = null,
    )

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
    private fun Int.saturatingIncrement(): Int = if (this == Int.MAX_VALUE) this else this + 1

}

internal fun nextAndroidDiagnosticsEpisodeId(
    currentDiagnosticsEpisodeId: Long,
    nextRecoveryGeneration: Long,
): Long? {
    require(currentDiagnosticsEpisodeId >= 0)
    require(nextRecoveryGeneration >= 0)
    val incremented = if (currentDiagnosticsEpisodeId == Long.MAX_VALUE) {
        return null
    } else {
        currentDiagnosticsEpisodeId + 1
    }
    return maxOf(incremented, nextRecoveryGeneration)
}
