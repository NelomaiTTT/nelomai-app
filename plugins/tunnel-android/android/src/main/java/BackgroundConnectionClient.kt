package ru.nelomai.tunnel

import android.content.Context
import java.net.URI
import java.net.Inet4Address
import java.net.InetAddress
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.Locale
import java.util.UUID
import javax.net.ssl.HttpsURLConnection
import org.json.JSONArray
import org.json.JSONObject

internal const val BACKGROUND_CONNECT_TIMEOUT_MILLIS = 10_000
internal const val BACKGROUND_READ_TIMEOUT_MILLIS = 20_000
private const val BACKGROUND_MAX_RESPONSE_BYTES = 1024 * 1024
internal const val BACKGROUND_MAX_CANDIDATES = 20

internal data class BackgroundStartResult(
    val configuration: ByteArray,
    val connection: QuickConnectionArgs,
    val options: TunnelOptionsArgs,
)

internal data class BackgroundSessionRecoveryResult(
    val accessToken: String,
    val refreshToken: String,
) {
    override fun toString(): String =
        "BackgroundSessionRecoveryResult(accessToken=<redacted>, refreshToken=<redacted>)"
}

internal class BackgroundConnectionException(
    val code: String,
    val retryAfterHeader: String? = null,
) : RuntimeException(code)

internal enum class BackgroundAuthorization(val wireName: String) {
    DEVICE("Device"),
    BEARER("Bearer"),
}

internal interface BackgroundApiTransport {
    fun execute(
        credential: BackgroundCredential,
        method: String,
        endpoint: String,
        payload: JSONObject? = null,
        authorization: BackgroundAuthorization = BackgroundAuthorization.DEVICE,
    ): JSONObject
}

internal data class BackgroundServerCandidate(
    val candidateId: String,
    val layer: String,
    val regionLabel: String,
    val probeUrl: String,
    val expiresAtUnix: Long,
)

internal data class BackgroundProbeResult(
    val candidateId: String,
    val latencyMillis: Double?,
    val failureCode: String?,
    val measuredAt: String,
)

internal fun requiresMeasuredCandidateSelection(
    layer: String,
    ticConnectionMode: String,
    allowAlternate: Boolean = true,
): Boolean = allowAlternate && (layer != "tic" || ticConnectionMode != "personal")

internal class BackgroundCandidateProbeCache(
    private val nowMillis: () -> Long = System::currentTimeMillis,
    private val deadlineMillis: Int = BACKGROUND_PROBE_TIMEOUT_MILLIS,
    private val probe: (BackgroundServerCandidate, Int) -> BackgroundProbeResult =
        ::probeBackgroundCandidate,
) {
    private data class CacheEntry(
        val layer: String,
        val egressMode: String,
        val networkIdentity: String,
        val candidateIds: List<String>,
        val validUntilMillis: Long,
        val results: List<BackgroundProbeResult>,
    )

    private val gate = Any()
    private var cached: CacheEntry? = null

    fun measure(
        layer: String,
        egressMode: String,
        networkIdentity: String,
        candidates: List<BackgroundServerCandidate>,
    ): List<BackgroundProbeResult> {
        if (candidates.size > BACKGROUND_MAX_CANDIDATES) {
            throw BackgroundConnectionException("invalid_background_response")
        }
        val now = nowMillis()
        val ids = candidates.map(BackgroundServerCandidate::candidateId)
        synchronized(gate) {
            cached?.takeIf {
                it.layer == layer && it.egressMode == egressMode &&
                    it.networkIdentity == networkIdentity && it.candidateIds == ids &&
                    now < it.validUntilMillis
            }?.let { return it.results }
        }
        if (candidates.isEmpty()) return emptyList()
        val executor = Executors.newFixedThreadPool(minOf(4, candidates.size)) { task ->
            Thread(task, "nelomai-background-probe").apply { isDaemon = true }
        }
        val measuredAt = Instant.ofEpochMilli(nowMillis()).toString()
        val results = try {
            executor.invokeAll(
                candidates.map { candidate ->
                    Callable { probe(candidate, deadlineMillis) }
                },
                deadlineMillis.toLong(),
                TimeUnit.MILLISECONDS,
            ).mapIndexed { index, future ->
                if (future.isCancelled) {
                    BackgroundProbeResult(candidates[index].candidateId, null, "timeout", measuredAt)
                } else {
                    runCatching { future.get() }.getOrElse {
                        BackgroundProbeResult(
                            candidates[index].candidateId,
                            null,
                            "network_error",
                            measuredAt,
                        )
                    }
                }
            }
        } finally {
            executor.shutdownNow()
        }
        val earliestCandidateExpiry = candidates.minOf { it.expiresAtUnix }
            .coerceAtMost(Long.MAX_VALUE / 1_000)
            .times(1_000)
        val validUntil = minOf(
            now.saturatingAdd(BACKGROUND_PROBE_CACHE_MILLIS),
            earliestCandidateExpiry,
        )
        synchronized(gate) {
            cached = CacheEntry(layer, egressMode, networkIdentity, ids, validUntil, results)
        }
        return results
    }

    fun invalidateNetwork() = synchronized(gate) {
        cached = null
    }
}

private const val BACKGROUND_PROBE_TIMEOUT_MILLIS = 3_000
private const val BACKGROUND_PROBE_CACHE_MILLIS = 5L * 60 * 1_000

private fun Long.saturatingAdd(other: Long): Long =
    if (this > Long.MAX_VALUE - other) Long.MAX_VALUE else this + other

private fun probeBackgroundCandidate(
    candidate: BackgroundServerCandidate,
    timeoutMillis: Int,
): BackgroundProbeResult {
    val measuredAtMillis = System.currentTimeMillis()
    val startedAt = System.nanoTime()
    val connection = try {
        val url = URI(candidate.probeUrl)
        require(url.scheme.equals("https", ignoreCase = true))
        url.toURL().openConnection() as HttpsURLConnection
    } catch (_: Throwable) {
        return BackgroundProbeResult(
            candidate.candidateId,
            null,
            "invalid_url",
            Instant.ofEpochMilli(measuredAtMillis).toString(),
        )
    }
    return try {
        connection.requestMethod = "GET"
        connection.instanceFollowRedirects = false
        connection.connectTimeout = timeoutMillis
        connection.readTimeout = timeoutMillis
        connection.setRequestProperty("Accept", "application/json")
        val status = connection.responseCode
        if (status in 200..299) {
            BackgroundProbeResult(
                candidate.candidateId,
                (System.nanoTime() - startedAt) / 1_000_000.0,
                null,
                Instant.ofEpochMilli(measuredAtMillis).toString(),
            )
        } else {
            BackgroundProbeResult(
                candidate.candidateId,
                null,
                "http_error",
                Instant.ofEpochMilli(measuredAtMillis).toString(),
            )
        }
    } catch (error: java.net.SocketTimeoutException) {
        BackgroundProbeResult(
            candidate.candidateId,
            null,
            "timeout",
            Instant.ofEpochMilli(measuredAtMillis).toString(),
        )
    } catch (_: Throwable) {
        BackgroundProbeResult(
            candidate.candidateId,
            null,
            "network_error",
            Instant.ofEpochMilli(measuredAtMillis).toString(),
        )
    } finally {
        connection.disconnect()
    }
}

internal data class BackgroundActivationResult(
    val tokenGeneration: Long,
    val activeExpiresAtUnix: Long,
)

internal data class BackgroundReconcileResult(
    val state: String,
    val cancelRequested: Boolean,
    val leaseId: String?,
    val leaseStatus: String?,
    val retryCount: Int,
    val nextAttemptAtUnix: Long?,
)

internal data class BackgroundLogoutFinalizeResult(
    val code: String,
    val cleanupJobs: Int,
)

internal data class BackgroundUiProvisionRequest(
    val expectedRevision: Long,
    val deviceId: String,
    val panelBase: String,
    val accessToken: String,
    val installSecret: String,
    val installGeneration: Long,
    val capability: BackgroundCapabilitySnapshot,
) {
    override fun toString(): String =
        "BackgroundUiProvisionRequest(expectedRevision=$expectedRevision, deviceId=$deviceId, panelBase=$panelBase, accessToken=<redacted>, installSecret=<redacted>, installGeneration=$installGeneration, capability=$capability)"
}

internal fun provisionBackgroundCredential(
    store: BackgroundCredentialStore,
    request: BackgroundUiProvisionRequest,
    nowUnix: Long,
    operationIds: () -> Pair<String, String>,
    prepare: (BackgroundCredential, String, String, String) -> BackgroundPendingToken,
    activate: (
        BackgroundCredential,
        BackgroundPendingToken,
        String,
    ) -> BackgroundActivationResult,
): BackgroundCredentialEnvelope {
    var envelope = store.read().provisionEnvelopeOrThrow()
    if (envelope.revision != request.expectedRevision) {
        throw BackgroundConnectionException("background_credential_revision_conflict")
    }
    if (envelope.logoutState?.phase == BackgroundLogoutPhase.PENDING) {
        throw BackgroundConnectionException("background_credential_logout_pending")
    }
    val effectiveCapability = conservativeBackgroundCapability(
        envelope.capability,
        request.capability,
    )
    if (envelope.reservation == null && envelope.pending == null &&
        (!effectiveCapability.enabled || effectiveCapability.expiresAtUnix <= nowUnix)
    ) {
        if (envelope.deviceId != request.deviceId || envelope.panelBase != request.panelBase ||
            envelope.installSecret != request.installSecret ||
            envelope.installGeneration != request.installGeneration
        ) {
            throw BackgroundConnectionException("background_credential_mutation_conflict")
        }
        return store.updateCapability(
            envelope.revision,
            effectiveCapability,
        ).provisionEnvelopeOrThrow()
    }
    if (envelope.reservation != null || envelope.pending != null) {
        if (envelope.deviceId != request.deviceId || envelope.panelBase != request.panelBase ||
            envelope.installSecret != request.installSecret ||
            envelope.installGeneration != request.installGeneration
        ) {
            throw BackgroundConnectionException("background_credential_mutation_conflict")
        }
        val storedCapability = envelope.capability
        val resumedCapability = conservativeBackgroundCapability(
            storedCapability,
            request.capability,
        )
        if (envelope.pending == null) {
            if (!resumedCapability.enabled || resumedCapability.expiresAtUnix <= nowUnix) {
                store.cancelUncommittedReservation(
                    envelope.revision,
                    resumedCapability,
                ).provisionEnvelopeOrThrow()
                throw BackgroundConnectionException("background_credential_capability_unavailable")
            }
        }
        if (resumedCapability != storedCapability) {
            envelope = store.updateCapability(
                envelope.revision,
                resumedCapability,
            ).provisionEnvelopeOrThrow()
        }
    } else {
        val (prepareOperationId, activationOperationId) = operationIds()
        envelope = store.reserveProvision(
            expectedRevision = envelope.revision,
            provision = BackgroundCredentialProvisionReservation(
                deviceId = request.deviceId,
                panelBase = request.panelBase,
                installSecret = request.installSecret,
                installGeneration = request.installGeneration,
                capability = request.capability,
            ),
            mutationId = prepareOperationId,
            activationOperationId = activationOperationId,
            expiresAtUnix = nowUnix + 10L * 60,
            nowUnix = nowUnix,
        ).provisionEnvelopeOrThrow()
    }

    val preparedState = prepareBackgroundTokenDurably(
        store = store,
        envelope = envelope,
        credential = BackgroundCredential(
            request.deviceId,
            request.panelBase,
            request.accessToken,
            Long.MAX_VALUE,
        ),
        installSecret = request.installSecret,
        nowUnix = nowUnix,
        operationIds = operationIds,
        prepare = prepare,
    )
    envelope = preparedState.envelope
    val pendingToken = preparedState.pending
    val activationCredential = stagedBackgroundCredential(envelope, pendingToken)
    val activation = try {
        activate(activationCredential, pendingToken, request.installSecret)
    } catch (error: BackgroundConnectionException) {
        if (error.code == "activation_not_applied") {
            store.discardNotApplied(
                envelope.revision,
                pendingToken.activationOperationId,
            ).provisionEnvelopeOrThrow()
        }
        throw error
    }
    return store.promotePending(
        envelope.revision,
        pendingToken.activationOperationId,
        activation.activeExpiresAtUnix,
    ).provisionEnvelopeOrThrow()
}

internal data class PreparedBackgroundCredentialState(
    val envelope: BackgroundCredentialEnvelope,
    val pending: BackgroundPendingToken,
)

internal fun backgroundCredentialForSessionRecovery(
    store: BackgroundCredentialStore,
    replayPending: (BackgroundCredentialEnvelope) -> BackgroundCredentialEnvelope,
): BackgroundCredential {
    var envelope = store.read().provisionEnvelopeOrThrow()
    var authoritativeDiscard: BackgroundConnectionException? = null
    if (envelope.pending != null) {
        envelope = try {
            replayPending(envelope)
        } catch (error: BackgroundConnectionException) {
            if (error.code != "activation_not_applied") throw error
            authoritativeDiscard = error
            store.read().provisionEnvelopeOrThrow()
        }
    }
    return envelope.active ?: throw authoritativeDiscard
        ?: BackgroundConnectionException("background_recovery_unavailable")
}

internal fun stagedBackgroundCredential(
    envelope: BackgroundCredentialEnvelope,
    pending: BackgroundPendingToken,
): BackgroundCredential = BackgroundCredential(
    deviceId = envelope.deviceId
        ?: throw BackgroundConnectionException("background_credential_unavailable"),
    panelBase = envelope.panelBase
        ?: throw BackgroundConnectionException("background_credential_unavailable"),
    token = pending.token,
    expiresAtUnix = pending.stagedExpiresAtUnix,
)

internal fun prepareBackgroundTokenDurably(
    store: BackgroundCredentialStore,
    envelope: BackgroundCredentialEnvelope,
    credential: BackgroundCredential,
    installSecret: String,
    nowUnix: Long,
    operationIds: () -> Pair<String, String>,
    prepare: (BackgroundCredential, String, String, String) -> BackgroundPendingToken,
): PreparedBackgroundCredentialState {
    var current = envelope
    current.pending?.let { return PreparedBackgroundCredentialState(current, it) }
    val capability = current.capability
    if (capability == null || !capability.enabled || capability.expiresAtUnix <= nowUnix) {
        throw BackgroundConnectionException("background_credential_capability_unavailable")
    }
    var reservation = current.reservation
    if (reservation == null || reservation.expiresAtUnix <= nowUnix) {
        val (prepareOperationId, activationOperationId) = operationIds()
        current = store.reserveMutation(
            current.revision,
            prepareOperationId,
            credential.deviceId,
            nowUnix + 10L * 60,
            nowUnix,
            activationOperationId,
        ).provisionEnvelopeOrThrow()
        reservation = requireNotNull(current.reservation)
    }
    val prepared = try {
        prepare(
            credential,
            reservation.mutationId,
            reservation.activationOperationId,
            installSecret,
        )
    } catch (error: BackgroundConnectionException) {
        if (error.code != "operation_id_conflict") throw error
        val (prepareOperationId, activationOperationId) = operationIds()
        current = store.replaceUncommittedReservation(
            current.revision,
            reservation.mutationId,
            prepareOperationId,
            activationOperationId,
            nowUnix + 10L * 60,
            nowUnix,
        ).provisionEnvelopeOrThrow()
        reservation = requireNotNull(current.reservation)
        prepare(
            credential,
            reservation.mutationId,
            reservation.activationOperationId,
            installSecret,
        )
    }
    current = store.savePendingToken(
        current.revision,
        reservation.mutationId,
        prepared,
        nowUnix,
    ).provisionEnvelopeOrThrow()
    return PreparedBackgroundCredentialState(current, prepared)
}

private fun CredentialStoreResult<BackgroundCredentialEnvelope>.provisionEnvelopeOrThrow():
    BackgroundCredentialEnvelope = when (this) {
    is CredentialStoreResult.Success -> value
    is CredentialStoreResult.Failure -> throw BackgroundConnectionException(code)
}

internal class BackgroundOperationClient(
    private val transport: BackgroundApiTransport,
) {
    fun capabilities(credential: BackgroundCredential): BackgroundCapabilitySnapshot {
        val payload = transport.execute(credential, "GET", "background/capabilities")
        return parseResponse {
            BackgroundCapabilitySnapshot(
                revision = payload.getLong("revision").also { require(it > 0) },
                enabled = payload.getBoolean("connection_intent_recovery_v1"),
                expiresAtUnix = parseTimestamp(payload.getString("expires_at")),
                reserveEnabled = payload.optBoolean("android_hot_standby_v1", false),
            )
        }
    }

    fun serverCandidates(
        credential: BackgroundCredential,
        layer: String,
        egressMode: String,
    ): List<BackgroundServerCandidate> {
        require(layer in setOf("tic", "stray"))
        require(egressMode in setOf("ipv4", "prefer_ipv6"))
        val payload = transport.execute(
            credential,
            "GET",
            "background/server-candidates?layer=$layer&egress_mode=$egressMode",
        )
        return parseResponse {
            val candidates = payload.getJSONArray("candidates")
            require(candidates.length() <= BACKGROUND_MAX_CANDIDATES)
            (0 until candidates.length()).map { index ->
                val item = candidates.getJSONObject(index)
                val probeUrl = item.getString("probe_url")
                require(URI(probeUrl).scheme.equals("https", ignoreCase = true))
                BackgroundServerCandidate(
                    candidateId = item.getString("candidate_id").also(::requireWireValue),
                    layer = item.getString("layer").also {
                        require(it in setOf("tic", "stray"))
                    },
                    regionLabel = item.getString("region_label").also(::requireWireValue),
                    probeUrl = probeUrl,
                    expiresAtUnix = parseTimestamp(item.getString("expires_at")),
                )
            }
        }
    }

    fun reconcile(
        credential: BackgroundCredential,
        operationId: String,
        kind: String,
        contractVersion: Int,
        requestFingerprint: String,
        cancelIfAbsent: Boolean,
    ): BackgroundReconcileResult {
        requireUuid(operationId)
        require(kind in setOf("start", "stalled_stop"))
        require(contractVersion in 1..32)
        require(requestFingerprint.matches(Regex("[0-9a-f]{64}")))
        val payload = transport.execute(
            credential,
            "POST",
            "background/operations/reconcile",
            JSONObject().apply {
                put("operation_id", operationId)
                put("kind", kind)
                put("contract_version", contractVersion)
                put("request_fingerprint", requestFingerprint)
                put("cancel_if_absent", cancelIfAbsent)
            },
        )
        return parseResponse {
            val state = payload.getString("state").also {
                require(it in setOf(
                    "not_found", "pending", "applying", "compensating",
                    "applied", "terminal", "cancelled",
                ))
            }
            BackgroundReconcileResult(
                state = state,
                cancelRequested = payload.getBoolean("cancel_requested"),
                leaseId = payload.optionalString("lease_id")?.also(::requireWireValue),
                leaseStatus = payload.optionalString("lease_status")?.also(::requireWireValue),
                retryCount = payload.optInt("retry_count", 0).also { require(it >= 0) },
                nextAttemptAtUnix = payload.optionalString("next_attempt_at")?.let(::parseTimestamp),
            )
        }
    }

    fun stop(
        credential: BackgroundCredential,
        leaseId: String,
        operationId: String,
        failureCode: String? = null,
    ) {
        requireUuid(operationId)
        requireWireValue(leaseId)
        require(failureCode in setOf(null, "tunnel_data_plane_stalled"))
        transport.execute(
            credential,
            "POST",
            "background/connections/stop",
            JSONObject().apply {
                put("operation_id", operationId)
                put("lease_id", leaseId)
                failureCode?.let { put("failure_code", it) }
            },
        )
    }

    fun prepareToken(
        credential: BackgroundCredential,
        prepareOperationId: String,
        activationOperationId: String,
        installSecret: String,
    ): BackgroundPendingToken = prepareToken(
        credential,
        prepareOperationId,
        activationOperationId,
        installSecret,
        BackgroundAuthorization.DEVICE,
    )

    fun prepareTokenWithBearer(
        credential: BackgroundCredential,
        prepareOperationId: String,
        activationOperationId: String,
        installSecret: String,
    ): BackgroundPendingToken = prepareToken(
        credential,
        prepareOperationId,
        activationOperationId,
        installSecret,
        BackgroundAuthorization.BEARER,
    )

    private fun prepareToken(
        credential: BackgroundCredential,
        prepareOperationId: String,
        activationOperationId: String,
        installSecret: String,
        authorization: BackgroundAuthorization,
    ): BackgroundPendingToken {
        requireUuid(prepareOperationId)
        requireUuid(activationOperationId)
        requireSecret(installSecret)
        val payload = transport.execute(
            credential,
            "POST",
            "background/token/prepare",
            JSONObject().apply {
                put("prepare_operation_id", prepareOperationId)
                put("activation_operation_id", activationOperationId)
                put("install_secret", installSecret)
            },
            authorization,
        )
        return parseResponse {
            require(payload.getString("prepare_operation_id") == prepareOperationId)
            require(payload.getString("activation_operation_id") == activationOperationId)
            BackgroundPendingToken(
                token = payload.getString("token").also(::requireSecret),
                stagedExpiresAtUnix = parseTimestamp(payload.getString("staged_expires_at")),
                tokenGeneration = payload.getLong("token_generation").also { require(it > 0) },
                prepareOperationId = prepareOperationId,
                activationOperationId = activationOperationId,
                contractVersion = 1,
            )
        }
    }

    fun activateToken(
        credential: BackgroundCredential,
        pending: BackgroundPendingToken,
        installSecret: String,
    ): BackgroundActivationResult {
        requireUuid(pending.activationOperationId)
        requireSecret(pending.token)
        requireSecret(installSecret)
        val payload = transport.execute(
            credential,
            "POST",
            "background/token/activate",
            JSONObject().apply {
                put("activation_operation_id", pending.activationOperationId)
                put("token", pending.token)
                put("install_secret", installSecret)
            },
        )
        return parseResponse {
            val generation = payload.getLong("token_generation").also {
                require(it == pending.tokenGeneration)
            }
            BackgroundActivationResult(
                generation,
                parseTimestamp(payload.getString("active_expires_at")),
            )
        }
    }

    fun finalizeLogout(
        credential: BackgroundCredential,
        deviceId: String,
        installGeneration: Long,
        operationId: String,
        installSecret: String,
    ): BackgroundLogoutFinalizeResult {
        val normalizedDeviceId = UUID.fromString(deviceId).toString()
        require(installGeneration > 0)
        requireUuid(operationId)
        requireSecret(installSecret)
        val payload = transport.execute(
            credential,
            "POST",
            "background/auth/logout-finalize",
            JSONObject().apply {
                put("device_id", normalizedDeviceId)
                put("install_generation", installGeneration)
                put("operation_id", operationId)
                put("install_secret", installSecret)
            },
        )
        return parseResponse {
            val code = payload.getString("code")
            require(code == "device_revoked_cleanup_accepted")
            BackgroundLogoutFinalizeResult(
                code,
                payload.getInt("cleanup_jobs").also { require(it >= 0) },
            )
        }
    }

    private fun parseTimestamp(value: String): Long = Instant.parse(value).epochSecond

    private fun requireUuid(value: String) {
        require(UUID.fromString(value).toString() == value.lowercase(Locale.ROOT))
    }

    private fun requireWireValue(value: String) {
        require(value.isNotBlank() && value.length <= 2048 && !value.contains('\u0000'))
    }

    private fun requireSecret(value: String) {
        require(value.isNotBlank() && value.length <= 4096 && !value.contains('\u0000'))
    }

    private inline fun <T> parseResponse(block: () -> T): T = try {
        block()
    } catch (error: BackgroundConnectionException) {
        throw error
    } catch (_: Throwable) {
        throw BackgroundConnectionException("invalid_background_response")
    }
}

private class UrlConnectionBackgroundApiTransport : BackgroundApiTransport {
    override fun execute(
        credential: BackgroundCredential,
        method: String,
        endpoint: String,
        payload: JSONObject?,
        authorization: BackgroundAuthorization,
    ): JSONObject {
        val base = URI(credential.panelBase)
        val url = base.resolve("/api/client/v1/$endpoint").toURL()
        val connection = (url.openConnection() as? HttpsURLConnection)
            ?: throw BackgroundConnectionException("background_transport_unavailable")
        return try {
            connection.requestMethod = method
            connection.instanceFollowRedirects = false
            connection.connectTimeout = BACKGROUND_CONNECT_TIMEOUT_MILLIS
            connection.readTimeout = BACKGROUND_READ_TIMEOUT_MILLIS
            connection.setRequestProperty(
                "Authorization",
                "${authorization.wireName} ${credential.token}",
            )
            connection.setRequestProperty("Accept", "application/json")
            if (payload != null) {
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/json")
                val encoded = payload.toString().toByteArray(StandardCharsets.UTF_8)
                try {
                    connection.outputStream.use { it.write(encoded) }
                } finally {
                    encoded.fill(0)
                }
            }
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            val body = stream?.use { input ->
                val buffer = ByteArray(8 * 1024)
                val output = java.io.ByteArrayOutputStream()
                try {
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        if (output.size() + count > BACKGROUND_MAX_RESPONSE_BYTES) {
                            throw BackgroundConnectionException("background_response_too_large")
                        }
                        output.write(buffer, 0, count)
                    }
                    val responseBytes = output.toByteArray()
                    try {
                        responseBytes.toString(StandardCharsets.UTF_8)
                    } finally {
                        responseBytes.fill(0)
                    }
                } finally {
                    buffer.fill(0)
                }
            }.orEmpty()
            val json = runCatching { JSONObject(body) }.getOrNull()
            if (status !in 200..299) {
                throw backgroundPanelException(
                    endpoint = endpoint.substringBefore('?'),
                    status = status,
                    panelCode = json?.optString("code")?.takeIf(String::isNotBlank),
                    retryAfterHeader = connection.getHeaderField("Retry-After"),
                )
            }
            json ?: throw BackgroundConnectionException("invalid_background_response")
        } catch (error: BackgroundConnectionException) {
            throw error
        } catch (_: Throwable) {
            throw BackgroundConnectionException("background_transport_unavailable")
        } finally {
            connection.disconnect()
        }
    }
}

private fun JSONObject.optionalString(name: String): String? =
    if (has(name) && !isNull(name)) getString(name) else null

/** Task 6's session view. It contains identifiers only, never member configuration. */
internal data class BackgroundRedundantSession(
    val sessionId: String,
    val state: String,
    val activeLeaseId: String?,
    val slotALeaseId: String?,
    val slotBLeaseId: String?,
    val standbyDesired: Boolean,
    val roleGeneration: Long,
    val membershipGeneration: Long,
    val reason: String?,
) {
    fun containsCurrentLease(leaseId: String?): Boolean = leaseId != null &&
        leaseId in setOf(slotALeaseId, slotBLeaseId)
}

internal data class RedundantRoleResponse(
    val action: String,
    val localActiveLeaseId: String,
    val session: BackgroundRedundantSession,
)

internal data class BackgroundRedundantRecoveryTransport(
    val session: BackgroundRedundantSession,
    val configurations: Map<String, ByteArray>,
    val healthProbes: Map<String, BackgroundRedundantHealthProbe>,
    val virtualAddressV4: String,
)

internal data class BackgroundRedundantCandidate(
    val session: BackgroundRedundantSession,
    val candidateLeaseId: String,
    val candidateSlot: RedundantSlot,
    val connection: QuickConnectionArgs,
    val configuration: ByteArray,
    val healthProbe: BackgroundRedundantHealthProbe,
)

internal data class BackgroundRedundantHealthProbe(
    val kind: String,
    val targetIpv4: String,
    val queryName: String,
    val timeoutMs: Long,
)

internal object BackgroundConnectionClient {
    private val transport: BackgroundApiTransport = UrlConnectionBackgroundApiTransport()
    private val operations = BackgroundOperationClient(transport)
    fun start(
        context: Context,
        credential: BackgroundCredential,
        template: QuickTunnelTemplate,
    ): BackgroundStartResult {
        val previousLeaseId = template.connection.leaseId
        return try {
            startWithOperation(
                credential,
                template,
                previousLeaseId.ifBlank { UUID.randomUUID().toString() },
                context,
            )
        } catch (error: BackgroundConnectionException) {
            if (!shouldRetryBackgroundStart(
                    previousLeaseId,
                    template.connection.allowAlternate,
                    error.code,
                )
            ) {
                throw error
            }
            startWithOperation(
                credential,
                template,
                UUID.randomUUID().toString(),
                context,
            )
        }
    }

    private fun startWithOperation(
        credential: BackgroundCredential,
        template: QuickTunnelTemplate,
        operationId: String,
        context: Context,
    ): BackgroundStartResult {
        val request = backgroundStartPayload(template, operationId)
        val payload = execute(credential, "background/connections/start", request)
        val connection = payload.getJSONObject("connection").toQuickConnection()
        connection.allowAlternate = template.connection.allowAlternate
        val options = payload.optJSONObject("split_tunnel")
            ?.toTunnelOptions(context, template.options)
            ?: template.options
        val configuration = payload.getString("configuration").toByteArray(StandardCharsets.UTF_8)
        if (configuration.isEmpty() || configuration.size > BACKGROUND_MAX_RESPONSE_BYTES) {
            configuration.fill(0)
            throw BackgroundConnectionException("invalid_background_configuration")
        }
        return BackgroundStartResult(configuration, connection, options)
    }

    fun startExact(
        credential: BackgroundCredential,
        template: AndroidIntentTemplate,
        transaction: AndroidLeaseTransaction,
        probeCache: BackgroundCandidateProbeCache,
        networkIdentity: String,
    ): BackgroundStartResult {
        val connection = QuickConnectionArgs().apply {
            leaseId = ""
            layer = template.layer
            ticConnectionMode = template.ticConnectionMode
            routeMode = template.routeMode
            egressMode = template.egressMode
            allowAlternate = template.allowAlternate
        }
        val quickTemplate = QuickTunnelTemplate(
            options = template.options.toTunnelOptionsArgs(),
            connection = connection,
        )
        val measured = requiresMeasuredCandidateSelection(
            template.layer,
            template.ticConnectionMode,
            template.allowAlternate,
        )
        val probes = if (measured) {
            probeCache.measure(
                template.layer,
                template.egressMode,
                networkIdentity,
                serverCandidates(credential, template.layer, template.egressMode),
            )
        } else {
            emptyList()
        }
        val request = backgroundStartPayload(
            quickTemplate,
            transaction.startOperationId,
            probes,
            transaction.replay.contractVersion,
            transaction.replay.requestFingerprint,
            measured,
        )
        val payload = execute(credential, "background/connections/start", request)
        val selected = payload.getJSONObject("connection").toQuickConnection().also {
            it.allowAlternate = template.allowAlternate
        }
        val options = template.options.toTunnelOptionsArgs()
        val configuration = payload.getString("configuration").toByteArray(StandardCharsets.UTF_8)
        if (configuration.isEmpty() || configuration.size > BACKGROUND_MAX_RESPONSE_BYTES) {
            configuration.fill(0)
            throw BackgroundConnectionException("invalid_background_configuration")
        }
        return BackgroundStartResult(configuration, selected, options)
    }

    fun stop(
        credential: BackgroundCredential,
        leaseId: String,
        operationId: String,
        failureCode: String? = null,
    ) = operations.stop(credential, leaseId, operationId, failureCode)

    fun reportRedundantRole(
        credential: BackgroundCredential,
        transaction: AndroidRedundantTransaction,
        reason: String,
        observedAt: String? = null,
    ): RedundantRoleResponse = redundantRoleFromJson(execute(
        credential,
        "background/connections/role",
        backgroundRedundantRolePayload(transaction, reason, observedAt),
    ))

    fun recoverRedundant(
        credential: BackgroundCredential,
        transaction: AndroidRedundantTransaction,
    ): BackgroundRedundantRecoveryTransport {
        val connection = QuickConnectionArgs().apply {
            leaseId = ""
            layer = transaction.template.layer
            ticConnectionMode = transaction.template.ticConnectionMode
            routeMode = transaction.template.routeMode
            egressMode = transaction.template.egressMode
            allowAlternate = transaction.template.allowAlternate
        }
        val payload = execute(
            credential,
            "background/connections/start",
            backgroundRedundantStartPayload(
                QuickTunnelTemplate(
                    options = transaction.template.options.toTunnelOptionsArgs(),
                    connection = connection,
                ),
                transaction,
            ),
        )
        return redundantRecoveryTransportFromJson(payload, transaction)
    }

    fun releaseRedundantStandby(
        credential: BackgroundCredential,
        transaction: AndroidRedundantTransaction,
        inactiveLeaseId: String?,
    ): BackgroundRedundantSession = redundantSessionFromJson(execute(
        credential,
        "background/connections/standby/release",
        backgroundRedundantStandbyReleasePayload(transaction, inactiveLeaseId),
    ).getJSONObject("session"))

    fun acquireRedundantStandby(
        credential: BackgroundCredential,
        transaction: AndroidRedundantTransaction,
        operationId: String,
        probes: List<BackgroundProbeResult> = emptyList(),
        replaceLeaseId: String? = null,
    ): BackgroundRedundantCandidate = redundantCandidateFromJson(execute(
        credential,
        "background/connections/standby/acquire",
        backgroundRedundantStandbyAcquirePayload(transaction, operationId, probes, replaceLeaseId),
    ))

    fun commitRedundantCandidate(
        credential: BackgroundCredential,
        transaction: AndroidRedundantTransaction,
        candidateLeaseId: String,
    ): BackgroundRedundantSession = redundantSessionFromJson(execute(
        credential,
        "background/connections/standby/commit",
        backgroundRedundantCandidateCommitPayload(transaction, candidateLeaseId),
    ).getJSONObject("session"))

    fun stopRedundant(
        credential: BackgroundCredential,
        transaction: AndroidRedundantTransaction,
        leaseId: String,
    ): JSONObject = execute(
        credential,
        "background/connections/stop",
        backgroundRedundantStopPayload(transaction, leaseId),
    )

    fun uploadDiagnostics(
        credential: BackgroundCredential,
        payload: JSONObject,
    ): JSONObject = execute(credential, "background/diagnostics", payload)

    fun recoverSession(
        credential: BackgroundCredential,
        installSecret: String,
    ): BackgroundSessionRecoveryResult {
        val payload = execute(
            credential,
            "background/auth/recover",
            backgroundRecoveryPayload(installSecret),
        )
        return BackgroundSessionRecoveryResult(
            accessToken = payload.getString("access_token"),
            refreshToken = payload.getString("refresh_token"),
        )
    }

    fun capabilities(credential: BackgroundCredential): BackgroundCapabilitySnapshot =
        operations.capabilities(credential)

    fun syncBindingPreferences(
        credential: BackgroundCredential,
        template: AndroidIntentTemplate,
    ) {
        val response = execute(
            credential,
            "background/device/sync-binding",
            backgroundBindingPreferencesPayload(template),
        )
        validateBackgroundBindingSyncResponse(response)
    }

    fun serverCandidates(
        credential: BackgroundCredential,
        layer: String,
        egressMode: String,
    ): List<BackgroundServerCandidate> = operations.serverCandidates(
        credential,
        layer,
        egressMode,
    )

    fun reconcile(
        credential: BackgroundCredential,
        operationId: String,
        kind: String,
        contractVersion: Int,
        requestFingerprint: String,
        cancelIfAbsent: Boolean,
    ): BackgroundReconcileResult = operations.reconcile(
        credential,
        operationId,
        kind,
        contractVersion,
        requestFingerprint,
        cancelIfAbsent,
    )

    fun prepareToken(
        credential: BackgroundCredential,
        prepareOperationId: String,
        activationOperationId: String,
        installSecret: String,
    ): BackgroundPendingToken = operations.prepareToken(
        credential,
        prepareOperationId,
        activationOperationId,
        installSecret,
    )

    fun prepareTokenWithBearer(
        credential: BackgroundCredential,
        prepareOperationId: String,
        activationOperationId: String,
        installSecret: String,
    ): BackgroundPendingToken = operations.prepareTokenWithBearer(
        credential,
        prepareOperationId,
        activationOperationId,
        installSecret,
    )

    fun activateToken(
        credential: BackgroundCredential,
        pending: BackgroundPendingToken,
        installSecret: String,
    ): BackgroundActivationResult = operations.activateToken(
        credential,
        pending,
        installSecret,
    )

    fun finalizeLogout(
        credential: BackgroundCredential,
        deviceId: String,
        installGeneration: Long,
        operationId: String,
        installSecret: String,
    ): BackgroundLogoutFinalizeResult = operations.finalizeLogout(
        credential,
        deviceId,
        installGeneration,
        operationId,
        installSecret,
    )

    private fun execute(
        credential: BackgroundCredential,
        endpoint: String,
        payload: JSONObject,
    ): JSONObject = transport.execute(credential, "POST", endpoint, payload)
}

internal fun backgroundPanelErrorCode(
    endpoint: String,
    status: Int,
    panelCode: String?,
): String = when {
    endpoint == "background/auth/recover" && status == 404 ->
        "background_recovery_unsupported"
    endpoint == "background/capabilities" && status == 404 ->
        "recovery_contract_unsupported"
    !panelCode.isNullOrBlank() -> panelCode
    status in 500..599 -> "http_5xx"
    else -> "background_panel_error"
}

internal fun backgroundPanelException(
    endpoint: String,
    status: Int,
    panelCode: String?,
    retryAfterHeader: String?,
): BackgroundConnectionException = BackgroundConnectionException(
    backgroundPanelErrorCode(endpoint, status, panelCode),
    retryAfterHeader,
)

internal fun refreshBackgroundCapability(
    current: BackgroundCapabilitySnapshot?,
    nowUnix: Long,
    fetch: () -> BackgroundCapabilitySnapshot,
): BackgroundCapabilitySnapshot = try {
    fetch()
} catch (error: BackgroundConnectionException) {
    if (error.code != "recovery_contract_unsupported") throw error
    BackgroundCapabilitySnapshot(
        revision = current?.revision ?: 0,
        enabled = false,
        expiresAtUnix = nowUnix,
    )
}

internal fun backgroundRecoveryPayload(installSecret: String): JSONObject = JSONObject().apply {
    put("install_secret", installSecret)
}

internal fun backgroundBindingPreferencesPayload(
    template: AndroidIntentTemplate,
): JSONObject = JSONObject().apply {
    put("preferred_layer", template.layer)
    put("tic_connection_mode", template.ticConnectionMode)
    put("route_mode", template.routeMode)
    put("egress_mode", template.egressMode)
}

internal fun backgroundRedundantRolePayload(
    transaction: AndroidRedundantTransaction,
    reason: String,
    observedAt: String? = null,
): JSONObject = JSONObject().apply {
    put("session_id", transaction.sessionId)
    put("active_lease_id", requireNotNull(transaction.localActiveLeaseId))
    put("expected_role_generation", transaction.roleGeneration)
    put("expected_membership_generation", transaction.membershipGeneration)
    put("reason", reason)
    observedAt?.let { put("observed_at", it) }
}

internal fun backgroundRedundantStandbyReleasePayload(
    transaction: AndroidRedundantTransaction,
    inactiveLeaseId: String?,
): JSONObject = JSONObject().apply {
    put("session_id", transaction.sessionId)
    inactiveLeaseId?.let { put("inactive_lease_id", it) }
    put("expected_role_generation", transaction.roleGeneration)
    put("expected_membership_generation", transaction.membershipGeneration)
}

internal fun backgroundRedundantStandbyAcquirePayload(
    transaction: AndroidRedundantTransaction,
    operationId: String,
    probes: List<BackgroundProbeResult>,
    replaceLeaseId: String? = null,
): JSONObject {
    require(probes.size <= BACKGROUND_MAX_CANDIDATES)
    return JSONObject().apply {
        put("operation_id", operationId)
        put("session_id", transaction.sessionId)
        put("expected_role_generation", transaction.roleGeneration)
        put("expected_membership_generation", transaction.membershipGeneration)
        replaceLeaseId?.let { put("replace_lease_id", it) }
        put("probes", probesToJson(probes))
    }
}

internal fun backgroundRedundantCandidateCommitPayload(
    transaction: AndroidRedundantTransaction,
    candidateLeaseId: String,
): JSONObject = JSONObject().apply {
    put("session_id", transaction.sessionId)
    put("candidate_lease_id", candidateLeaseId)
    put("expected_active_lease_id", requireNotNull(transaction.localActiveLeaseId))
    put("expected_role_generation", transaction.roleGeneration)
    put("expected_membership_generation", transaction.membershipGeneration)
}

internal fun backgroundRedundantStopPayload(
    transaction: AndroidRedundantTransaction,
    leaseId: String,
): JSONObject = JSONObject().apply {
    put("operation_id", requireNotNull(transaction.stopOperationId))
    put("lease_id", leaseId)
    put("recovery_contract_version", 2)
    put("session_id", transaction.sessionId)
}

private fun probesToJson(probes: List<BackgroundProbeResult>) = JSONArray().apply {
    probes.forEach { probe -> put(JSONObject().apply {
        put("candidate_id", probe.candidateId)
        probe.latencyMillis?.let { put("latency_ms", it) }
        probe.failureCode?.let { put("failure_code", it) }
        put("measured_at", probe.measuredAt)
    }) }
}

internal fun redundantSessionFromJson(payload: JSONObject): BackgroundRedundantSession =
    BackgroundRedundantSession(
        sessionId = UUID.fromString(payload.getString("session_id")).toString(),
        state = payload.getString("state").also {
            require(it in setOf("allocating", "connected", "degraded", "stopping", "stopped", "failed"))
        },
        activeLeaseId = payload.optionalString("active_lease_id"),
        slotALeaseId = payload.optionalString("slot_a_lease_id"),
        slotBLeaseId = payload.optionalString("slot_b_lease_id"),
        standbyDesired = payload.getBoolean("standby_desired"),
        roleGeneration = payload.getLong("role_generation").also { require(it >= 0) },
        membershipGeneration = payload.getLong("membership_generation").also { require(it >= 0) },
        reason = payload.optionalString("reason"),
    )

internal fun redundantRoleFromJson(payload: JSONObject): RedundantRoleResponse = RedundantRoleResponse(
    action = payload.getString("action").also { require(it in setOf("accepted", "acknowledged", "rebase")) },
    localActiveLeaseId = payload.getString("local_active_lease_id"),
    session = redundantSessionFromJson(payload.getJSONObject("session")),
)

internal fun redundantHealthProbeFromJson(payload: JSONObject): BackgroundRedundantHealthProbe =
    validatedRedundantHealthProbe(
        kind = payload.getString("kind"),
        targetIpv4 = payload.getString("target_ipv4"),
        queryName = payload.getString("query_name"),
        timeoutMs = payload.getLong("timeout_ms"),
    )

internal fun redundantRecoveryTransportFromJson(
    payload: JSONObject,
    transaction: AndroidRedundantTransaction,
): BackgroundRedundantRecoveryTransport {
    val primaryConfiguration = payload.getString("configuration")
        .toByteArray(StandardCharsets.UTF_8)
    var standbyConfiguration: ByteArray? = null
    try {
        require(primaryConfiguration.isNotEmpty() &&
            primaryConfiguration.size <= BACKGROUND_MAX_RESPONSE_BYTES)
        val primaryLeaseId = payload.getJSONObject("connection").getString("lease_id")
        val redundancy = payload.getJSONObject("redundancy")
        val redundancyState = redundancy.getString("state").also {
            require(it in setOf("disabled", "degraded", "warming", "ready"))
        }
        require(redundancy.getString("session_id") == transaction.sessionId)
        val standbyDesired = redundancy.getBoolean("standby_desired")
        val standby = redundancy.optJSONObject("standby")
        val primaryProbe = payload.optJSONObject("health_probe")
            ?.let(::redundantHealthProbeFromJson)
        if (redundancyState == "disabled") {
            require(!standbyDesired)
            require(standby == null)
            require(primaryProbe == null)
        } else {
            require(primaryProbe != null)
        }
        require(standbyDesired || standby == null)
        val standbyLeaseId = standby?.getJSONObject("connection")?.getString("lease_id")
        standbyConfiguration = standby?.getString("configuration")
            ?.toByteArray(StandardCharsets.UTF_8)
        if (standbyConfiguration != null) {
            require(standbyConfiguration.isNotEmpty() &&
                standbyConfiguration.size <= BACKGROUND_MAX_RESPONSE_BYTES)
        }
        val returnedLeases = listOfNotNull(primaryLeaseId, standbyLeaseId).toSet()
        val allowedLeases = listOfNotNull(
            transaction.slotALeaseId,
            transaction.slotBLeaseId,
            transaction.candidateLeaseId,
        ).toSet()
        require(returnedLeases.isNotEmpty() && returnedLeases.all { it in allowedLeases })
        fun recoveredSlot(slot: RedundantSlot): String? {
            val current = when (slot) {
                RedundantSlot.A -> transaction.slotALeaseId
                RedundantSlot.B -> transaction.slotBLeaseId
            }
            val candidate = transaction.candidateLeaseId.takeIf { transaction.candidateSlot == slot }
            return candidate?.takeIf { it in returnedLeases }
                ?: current?.takeIf { it in returnedLeases }
        }
        val session = BackgroundRedundantSession(
            sessionId = transaction.sessionId,
            state = redundancyState,
            activeLeaseId = primaryLeaseId,
            slotALeaseId = recoveredSlot(RedundantSlot.A),
            slotBLeaseId = recoveredSlot(RedundantSlot.B),
            standbyDesired = standbyDesired,
            roleGeneration = redundancy.getLong("role_generation"),
            membershipGeneration = redundancy.getLong("membership_generation"),
            reason = redundancy.optionalString("reason"),
        )
        require(session.containsCurrentLease(primaryLeaseId))
        val configurations = linkedMapOf(primaryLeaseId to primaryConfiguration)
        val healthProbes = linkedMapOf<String, BackgroundRedundantHealthProbe>()
        primaryProbe?.let { healthProbes[primaryLeaseId] = it }
        if (standby != null && standbyLeaseId != null && standbyConfiguration != null) {
            configurations[standbyLeaseId] = standbyConfiguration
            healthProbes[standbyLeaseId] = redundantHealthProbeFromJson(
                standby.getJSONObject("health_probe"),
            )
        }
        return BackgroundRedundantRecoveryTransport(
            session,
            configurations,
            healthProbes,
            redundancy.getString("virtual_address_v4"),
        )
    } catch (error: Throwable) {
        primaryConfiguration.fill(0)
        standbyConfiguration?.fill(0)
        throw error
    }
}

internal fun redundantCandidateFromJson(payload: JSONObject): BackgroundRedundantCandidate {
    val configuration = payload.getString("configuration").toByteArray(StandardCharsets.UTF_8)
    try {
        require(configuration.isNotEmpty() && configuration.size <= BACKGROUND_MAX_RESPONSE_BYTES)
        return BackgroundRedundantCandidate(
            session = redundantSessionFromJson(payload.getJSONObject("session")),
            candidateLeaseId = payload.getString("candidate_lease_id"),
            candidateSlot = RedundantSlot.fromWireName(payload.getString("candidate_slot")),
            connection = payload.getJSONObject("connection").toQuickConnection(),
            configuration = configuration,
            healthProbe = redundantHealthProbeFromJson(payload.getJSONObject("health_probe")),
        )
    } catch (error: Throwable) {
        configuration.fill(0)
        throw error
    }
}

internal fun validateBackgroundBindingSyncResponse(response: JSONObject) {
    if (!response.optBoolean("ok", false) || response.has("configuration")) {
        throw BackgroundConnectionException("invalid_background_response")
    }
}

internal fun backgroundStartPayload(
    template: QuickTunnelTemplate,
    operationId: String,
    probes: List<BackgroundProbeResult> = emptyList(),
    contractVersion: Int? = null,
    requestFingerprint: String? = null,
    requireMeasuredSelection: Boolean = true,
    redundancyContractVersion: Int? = null,
    reserveEnabled: Boolean? = null,
): JSONObject {
    if (probes.size > BACKGROUND_MAX_CANDIDATES) {
        throw BackgroundConnectionException("invalid_background_response")
    }
    return JSONObject().apply {
        put("operation_id", operationId)
        put("layer", template.connection.layer)
        put("tic_connection_mode", template.connection.ticConnectionMode)
        put("route_mode", template.connection.routeMode)
        put("egress_mode", template.connection.egressMode)
        put("probes", JSONArray().apply {
            probes.forEach { probe ->
                put(JSONObject().apply {
                    put("candidate_id", probe.candidateId)
                    probe.latencyMillis?.let { put("latency_ms", it) }
                    probe.failureCode?.let { put("failure_code", it) }
                    put("measured_at", probe.measuredAt)
                })
            }
        })
        put("allow_alternate", template.connection.allowAlternate)
        if (contractVersion != null && requestFingerprint != null) {
            put("require_measured_selection", requireMeasuredSelection)
            put("recovery_contract_version", contractVersion)
            put("request_fingerprint", requestFingerprint)
        }
        if (redundancyContractVersion != null && reserveEnabled != null) {
            require(contractVersion == 2)
            require(redundancyContractVersion == 1)
            put("redundancy_contract_version", redundancyContractVersion)
            put("reserve_enabled", reserveEnabled)
        }
    }
}

internal fun backgroundRedundantStartPayload(
    template: QuickTunnelTemplate,
    transaction: AndroidRedundantTransaction,
    probes: List<BackgroundProbeResult> = emptyList(),
): JSONObject = backgroundStartPayload(
    template = template,
    operationId = transaction.startOperationId,
    probes = probes,
    contractVersion = 2,
    requestFingerprint = transaction.startRequestFingerprint,
    redundancyContractVersion = 1,
    reserveEnabled = transaction.startReserveEnabled,
)

private fun JSONObject.toTunnelOptions(
    context: Context,
    fallback: TunnelOptionsArgs,
): TunnelOptionsArgs = backgroundTunnelOptions(
    this,
    InstalledApplications.query(context).mapTo(hashSetOf(), InstalledApplication::packageId),
    fallback,
) { domain ->
    InetAddress.getAllByName(domain)
        .filterIsInstance<Inet4Address>()
        .map { "${it.hostAddress}/32" }
}

internal fun backgroundTunnelOptions(
    payload: JSONObject,
    installed: Set<String>,
    fallback: TunnelOptionsArgs,
    resolveDomain: (String) -> List<String>,
): TunnelOptionsArgs {
    with(payload) {
        if (!optBoolean("enabled", false)) {
            return TunnelOptionsArgs().apply {
                dnsServers = ArrayList(fallback.dnsServers)
            }
        }

        val packageIndex = InstalledPackageIndex(installed)
        val mandatory = stringList("mandatory_excluded_packages")
            .mapNotNullTo(linkedSetOf(), packageIndex::resolve)
        val selected = stringList("selected_packages")
            .mapNotNullTo(linkedSetOf(), packageIndex::resolve)
        val mode = optString("mode", "exclude_selected")
        val excluded = if (mode == "exclude_selected") {
            (mandatory + selected).toCollection(arrayListOf())
        } else {
            arrayListOf()
        }
        val included = if (mode == "include_selected") {
            selected.filterTo(arrayListOf()) { it !in mandatory }
        } else {
            arrayListOf()
        }
        if (mode == "include_selected" && included.isEmpty()) {
            throw BackgroundConnectionException("empty_include_selection")
        }

        val routes = linkedSetOf<String>()
        routes.addAll(stringList("excluded_ipv4_cidrs"))
        var domainResolutionFailed = false
        val rules = optJSONArray("address_rules") ?: JSONArray()
        for (index in 0 until rules.length()) {
            val rule = rules.optJSONObject(index) ?: continue
            when (rule.optString("kind")) {
                "ipv4" -> routes.add("${rule.optString("value")}/32")
                "domain" -> {
                    val domain = rule.optString("value").trim()
                    val addresses = runCatching { resolveDomain(domain) }
                        .getOrNull()
                    if (addresses.isNullOrEmpty()) {
                        domainResolutionFailed = true
                    } else {
                        routes.addAll(addresses)
                    }
                }
            }
        }
        if (domainResolutionFailed) {
            routes.addAll(fallback.splitTunnelRoutes)
        }

        return TunnelOptionsArgs().apply {
            splitActive = true
            policyHash = optString("policy_hash").takeIf(String::isNotBlank)
            applicationMode = mode
            excludedPackages = excluded
            includedPackages = included
            splitTunnelRoutes = ArrayList(routes)
            excludeLocalNetworks = optBoolean("exclude_local_networks", true)
            dnsServers = ArrayList(fallback.dnsServers)
        }
    }
}

private class InstalledPackageIndex(installed: Set<String>) {
    private val exact = installed.associateByTo(hashMapOf()) { it }
    private val folded = hashMapOf<String, String?>()

    init {
        for (packageId in installed) {
            val key = packageId.lowercase(Locale.ROOT)
            if (folded.containsKey(key)) folded[key] = null
            else folded[key] = packageId
        }
    }

    fun resolve(packageId: String): String? =
        exact[packageId] ?: folded[packageId.lowercase(Locale.ROOT)]
}

private fun JSONObject.stringList(key: String): List<String> {
    val values = optJSONArray(key) ?: return emptyList()
    return (0 until values.length()).mapNotNull { index ->
        values.optString(index).trim().takeIf(String::isNotEmpty)
    }
}

internal fun shouldRetryBackgroundStart(
    previousLeaseId: String,
    allowAlternate: Boolean,
    errorCode: String,
): Boolean = previousLeaseId.isNotBlank() && (
    errorCode == "connection_no_longer_active" ||
        errorCode == "operation_id_conflict" ||
        (allowAlternate && errorCode in setOf(
            "saved_connection_unavailable",
            "saved_stray_unavailable",
        ))
    )

private fun JSONObject.toQuickConnection(): QuickConnectionArgs = QuickConnectionArgs().apply {
    leaseId = getString("lease_id")
    layer = getString("layer")
    ticConnectionMode = getString("tic_connection_mode")
    routeMode = getString("route_mode")
    egressMode = optString("egress_mode", "ipv4")
    allowAlternate = false
}
