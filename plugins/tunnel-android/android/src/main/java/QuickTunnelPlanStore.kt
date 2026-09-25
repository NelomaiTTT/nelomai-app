package ru.nelomai.tunnel

import android.content.Context
import java.util.UUID
import org.json.JSONArray
import org.json.JSONObject

private const val QUICK_PLAN_KEY_ALIAS = "nelomai-quick-tunnel-plan"
private const val QUICK_PLAN_PREFERENCES = "nelomai-quick-tunnel-plan"
private const val QUICK_PLAN_FORMAT = 3

internal data class QuickTunnelTemplate(
    val options: TunnelOptionsArgs,
    val connection: QuickConnectionArgs,
    val planRevision: String? = null,
)

internal object QuickTunnelPlanStore {
    @Synchronized fun prepareForNextStart(context: Context, template: QuickTunnelTemplate) = storage(context).prepareForNextStart(template)
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
    fun prepareForNextStart(template: QuickTunnelTemplate): Boolean {
        require(template.connection.leaseId.isEmpty()) { "quick_plan_preparation_has_lease" }
        val current = loadTemplate()
        if (current != null) {
            if (!current.connection.sameSelection(template.connection)) return true
            // This record is for future starts. Updating its options does not
            // alter the active transport or the durable recovery transaction.
        }
        save(StartTunnelArgs().apply {
            cacheQuickAction = true
            options = template.options
            quickConnection = current?.connection ?: template.connection
        })
        return true
    }

    fun save(args: StartTunnelArgs) {
        if (!args.cacheQuickAction) return
        val connection = args.quickConnection ?: return
        val current = loadTemplate()
        // Only tile Starts carry a captured revision. An explicit UI Start
        // remains authoritative, including an intentional split disable.
        val options = current?.takeIf {
            args.quickPlanRevision != null && args.quickPlanRevision != it.planRevision &&
                it.connection.sameSelection(connection)
        }?.options ?: args.options
        val preference = decrypt()?.opt("reservePreference") as? Boolean
        val plaintext = JSONObject().apply {
            put("format", QUICK_PLAN_FORMAT)
            put("planRevision", UUID.randomUUID().toString())
            put("validUntilUnix", args.quickActionValidUntilUnix ?: JSONObject.NULL)
            put("options", options.toJson())
            put("connection", connection.toStoredQuickConnectionJson())
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
        payload.put("planRevision", UUID.randomUUID().toString())
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
                planRevision = payload.optString("planRevision", "legacy"),
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

private fun QuickConnectionArgs.sameSelection(other: QuickConnectionArgs): Boolean =
    layer == other.layer && ticConnectionMode == other.ticConnectionMode &&
        routeMode == other.routeMode && egressMode == other.egressMode &&
        allowAlternate == other.allowAlternate

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
