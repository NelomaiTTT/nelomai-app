package ru.nelomai.tunnel

import android.content.Context
import java.net.URI
import java.net.Inet4Address
import java.net.InetAddress
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.Locale
import java.util.UUID
import javax.net.ssl.HttpsURLConnection
import org.json.JSONArray
import org.json.JSONObject

private const val BACKGROUND_CONNECT_TIMEOUT_MILLIS = 10_000
private const val BACKGROUND_READ_TIMEOUT_MILLIS = 20_000
private const val BACKGROUND_MAX_RESPONSE_BYTES = 1024 * 1024

internal data class BackgroundStartResult(
    val configuration: ByteArray,
    val connection: QuickConnectionArgs,
    val options: TunnelOptionsArgs,
)

internal data class BackgroundSessionRecoveryResult(
    val accessToken: String,
    val refreshToken: String,
)

internal class BackgroundConnectionException(val code: String) : RuntimeException(code)

internal interface BackgroundApiTransport {
    fun execute(
        credential: BackgroundCredential,
        method: String,
        endpoint: String,
        payload: JSONObject? = null,
    ): JSONObject
}

internal data class BackgroundServerCandidate(
    val candidateId: String,
    val layer: String,
    val regionLabel: String,
    val probeUrl: String,
    val expiresAtUnix: Long,
)

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

internal class BackgroundOperationClient(
    private val transport: BackgroundApiTransport,
) {
    fun capabilities(credential: BackgroundCredential): BackgroundCapabilitySnapshot {
        val payload = transport.execute(credential, "GET", "background/capabilities")
        return parseResponse {
            BackgroundCapabilitySnapshot(
                revision = payload.getLong("revision").also { require(it >= 0) },
                enabled = payload.getBoolean("connection_intent_recovery_v1"),
                expiresAtUnix = parseTimestamp(payload.getString("expires_at")),
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

    fun prepareToken(
        credential: BackgroundCredential,
        prepareOperationId: String,
        activationOperationId: String,
        installSecret: String,
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
            connection.setRequestProperty("Authorization", "Device ${credential.token}")
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
                throw BackgroundConnectionException(
                    backgroundPanelErrorCode(
                        endpoint.substringBefore('?'),
                        status,
                        json?.optString("code")?.takeIf(String::isNotBlank),
                    ),
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

    fun stop(credential: BackgroundCredential, leaseId: String) {
        execute(
            credential,
            "background/connections/stop",
            JSONObject().apply {
                put("operation_id", UUID.randomUUID().toString())
                put("lease_id", leaseId)
            },
        )
    }

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
): String = panelCode?.takeIf(String::isNotBlank)
    ?: if (endpoint == "background/auth/recover" && status == 404) {
        "background_recovery_unsupported"
    } else {
        "background_panel_error"
    }

internal fun backgroundRecoveryPayload(installSecret: String): JSONObject = JSONObject().apply {
    put("install_secret", installSecret)
}

internal fun backgroundStartPayload(
    template: QuickTunnelTemplate,
    operationId: String,
): JSONObject = JSONObject().apply {
    put("operation_id", operationId)
    put("layer", template.connection.layer)
    put("tic_connection_mode", template.connection.ticConnectionMode)
    put("route_mode", template.connection.routeMode)
    put("egress_mode", template.connection.egressMode)
    put("probes", JSONArray())
    put("allow_alternate", template.connection.allowAlternate)
}

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
