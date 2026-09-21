package ru.nelomai.tunnel

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

private const val QUICK_PLAN_KEY_ALIAS = "nelomai-quick-tunnel-plan"
private const val QUICK_PLAN_PREFERENCES = "nelomai-quick-tunnel-plan"
private const val QUICK_PLAN_FORMAT = 3

internal data class QuickTunnelTemplate(
    val options: TunnelOptionsArgs,
    val connection: QuickConnectionArgs,
)

internal object QuickTunnelPlanStore {
    @Synchronized fun save(context: Context, args: StartTunnelArgs) = storage(context).save(args)
    @Synchronized fun updateDnsServers(context: Context, dnsServers: List<String>): Boolean =
        storage(context).updateDnsServers(dnsServers)
    @Synchronized fun updateReservePreference(context: Context, enabled: Boolean): Boolean =
        storage(context).updateReservePreference(enabled)
    @Synchronized fun loadTemplate(context: Context): QuickTunnelTemplate? = storage(context).loadTemplate()
    @Synchronized fun clear(context: Context): Boolean = storage(context).clear()

    private fun storage(context: Context) = QuickTunnelPlanStorage(AndroidSecureEnvelopeBackend(context,
        preferenceName = QUICK_PLAN_PREFERENCES, recordName = "encrypted-envelope-v1", keyAlias = QUICK_PLAN_KEY_ALIAS))
}

/** Same encrypted quick-plan record; injectable persistence for regression tests. */
internal class QuickTunnelPlanStorage(private val backend: EncryptedRecordBackend) {
    fun save(args: StartTunnelArgs) {
        if (!args.cacheQuickAction || args.quickConnection == null) return
        val preference = decrypt()?.opt("reservePreference") as? Boolean
        val plaintext = JSONObject().apply {
            put("format", QUICK_PLAN_FORMAT)
            put("validUntilUnix", args.quickActionValidUntilUnix ?: JSONObject.NULL)
            put("options", args.options.toJson())
            put("connection", args.quickConnection?.toStoredQuickConnectionJson() ?: JSONObject.NULL)
            preference?.let { put("reservePreference", it) }
        }.toString().toByteArray(Charsets.UTF_8)
        try {
            check(backend.write(plaintext)) { "quick_plan_write_failed" }
        } finally {
            plaintext.fill(0)
        }
    }

    fun updateReservePreference(enabled: Boolean): Boolean {
        val payload = decrypt() ?: JSONObject().put("format", QUICK_PLAN_FORMAT)
        payload.put("reservePreference", enabled)
        val plaintext = payload.toString().toByteArray(Charsets.UTF_8)
        return try { backend.write(plaintext) } finally { plaintext.fill(0) }
    }

    fun updateDnsServers(dnsServers: List<String>): Boolean {
        val payload = decrypt() ?: return true
        // A reserve preference may exist before the first UI start saves a plan.
        if (!payload.has("connection")) return true
        val options = payload.optJSONObject("options") ?: return false
        options.put("dnsServers", JSONArray(dnsServers))
        val plaintext = payload.toString().toByteArray(Charsets.UTF_8)
        return try {
            backend.write(plaintext)
        } finally {
            plaintext.fill(0)
        }
    }

    fun loadTemplate(): QuickTunnelTemplate? {
        val payload = decrypt() ?: return null
        return try {
            if (payload.getInt("format") != QUICK_PLAN_FORMAT) {
                clear()
                return null
            }
            val connection = payload.optJSONObject("connection")?.toStoredQuickConnection()
                ?: return null
            // This is a future-start choice, never a mutation of the durable
            // current session's startReserveEnabled/fingerprint. Legacy stays v1.
            if (connection.reserveEnabled != null) {
                (payload.opt("reservePreference") as? Boolean)?.let { connection.reserveEnabled = it }
            }
            QuickTunnelTemplate(
                options = TunnelOptionsArgs.fromJson(payload.getJSONObject("options")),
                connection = connection,
            )
        } catch (_: Throwable) {
            clear()
            null
        }
    }

    // A protected tombstone distinguishes legitimate clear from missing migration data.
    fun clear(): Boolean = backend.write("{\"format\":0}".toByteArray())

    private fun decrypt(): JSONObject? {
        val plaintext = backend.read() ?: return null
        return try {
            JSONObject(plaintext.toString(Charsets.UTF_8)).takeIf { it.optInt("format") != 0 }
        } finally { plaintext.fill(0) }
    }
}

private fun TunnelOptionsArgs.toJson(): JSONObject = JSONObject().apply {
    put("splitActive", splitActive)
    put("policyHash", policyHash)
    put("applicationMode", applicationMode)
    put("excludedPackages", JSONArray(excludedPackages))
    put("includedPackages", JSONArray(includedPackages))
    put("splitTunnelRoutes", JSONArray(splitTunnelRoutes))
    put("excludeLocalNetworks", excludeLocalNetworks)
    put("dnsServers", JSONArray(dnsServers))
}

private fun TunnelOptionsArgs.Companion.fromJson(payload: JSONObject): TunnelOptionsArgs =
    TunnelOptionsArgs().apply {
        splitActive = payload.optBoolean("splitActive", false)
        policyHash = payload.optString("policyHash").takeIf(String::isNotBlank)
        applicationMode = payload.optString("applicationMode").takeIf(String::isNotBlank)
        excludedPackages = payload.stringList("excludedPackages")
        includedPackages = payload.stringList("includedPackages")
        splitTunnelRoutes = payload.stringList("splitTunnelRoutes")
        excludeLocalNetworks = payload.optBoolean("excludeLocalNetworks", false)
        dnsServers = payload.stringList("dnsServers")
    }

private fun JSONObject.stringList(key: String): ArrayList<String> {
    val values = optJSONArray(key) ?: return arrayListOf()
    return ArrayList((0 until values.length()).map(values::getString))
}

internal fun QuickConnectionArgs.toStoredQuickConnectionJson(): JSONObject = JSONObject().apply {
    put("leaseId", leaseId)
    put("layer", layer)
    put("ticConnectionMode", ticConnectionMode)
    put("routeMode", routeMode)
    put("egressMode", egressMode)
    put("allowAlternate", allowAlternate)
    reserveEnabled?.let { put("reserveEnabled", it) }
}

internal fun JSONObject.toStoredQuickConnection(): QuickConnectionArgs = QuickConnectionArgs().apply {
    leaseId = getString("leaseId")
    layer = getString("layer")
    ticConnectionMode = getString("ticConnectionMode")
    routeMode = getString("routeMode")
    egressMode = getString("egressMode")
    allowAlternate = optBoolean("allowAlternate", false)
    reserveEnabled = if (has("reserveEnabled") && !isNull("reserveEnabled")) {
        getBoolean("reserveEnabled")
    } else null
}
