package ru.nelomai.tunnel

import android.content.Context
import java.net.URI
import java.net.Inet4Address
import java.net.InetAddress
import java.nio.charset.StandardCharsets
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

internal class BackgroundConnectionException(val code: String) : RuntimeException(code)

internal object BackgroundConnectionClient {
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
        val request = JSONObject().apply {
            put("operation_id", operationId)
            put("layer", template.connection.layer)
            put("tic_connection_mode", template.connection.ticConnectionMode)
            put("route_mode", template.connection.routeMode)
            put("probes", JSONArray())
            put("allow_alternate", template.connection.allowAlternate)
        }
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

    private fun execute(
        credential: BackgroundCredential,
        endpoint: String,
        payload: JSONObject,
    ): JSONObject {
        val base = URI(credential.panelBase)
        val url = base.resolve("/api/client/v1/$endpoint").toURL()
        val connection = (url.openConnection() as? HttpsURLConnection)
            ?: throw BackgroundConnectionException("background_transport_unavailable")
        return try {
            connection.requestMethod = "POST"
            connection.instanceFollowRedirects = false
            connection.connectTimeout = BACKGROUND_CONNECT_TIMEOUT_MILLIS
            connection.readTimeout = BACKGROUND_READ_TIMEOUT_MILLIS
            connection.doOutput = true
            connection.setRequestProperty("Authorization", "Device ${credential.token}")
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setRequestProperty("Accept", "application/json")
            val encoded = payload.toString().toByteArray(StandardCharsets.UTF_8)
            try {
                connection.outputStream.use { it.write(encoded) }
            } finally {
                encoded.fill(0)
            }
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            val body = stream?.use { input ->
                val buffer = ByteArray(8 * 1024)
                val output = java.io.ByteArrayOutputStream()
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    if (output.size() + count > BACKGROUND_MAX_RESPONSE_BYTES) {
                        throw BackgroundConnectionException("background_response_too_large")
                    }
                    output.write(buffer, 0, count)
                }
                output.toByteArray().toString(StandardCharsets.UTF_8)
            }.orEmpty()
            val json = runCatching { JSONObject(body) }.getOrNull()
            if (status !in 200..299) {
                throw BackgroundConnectionException(
                    json?.optString("code")?.takeIf(String::isNotBlank)
                        ?: "background_panel_error",
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
        if (!optBoolean("enabled", false)) return TunnelOptionsArgs()

        val mandatory = stringList("mandatory_excluded_packages").toSet()
        val selected = stringList("selected_packages").toSet()
        val mode = optString("mode", "exclude_selected")
        val excluded = if (mode == "exclude_selected") {
            (mandatory + selected).filterTo(arrayListOf()) { it in installed }
        } else {
            arrayListOf()
        }
        val included = if (mode == "include_selected") {
            selected.filterTo(arrayListOf()) { it in installed && it !in mandatory }
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
            excludedPackages = excluded
            includedPackages = included
            splitTunnelRoutes = ArrayList(routes)
            excludeLocalNetworks = optBoolean("exclude_local_networks", true)
        }
    }
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
    allowAlternate = false
}
