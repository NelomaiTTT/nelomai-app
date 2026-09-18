package ru.nelomai.tunnel

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import org.json.JSONArray
import org.json.JSONObject

private const val QUICK_PLAN_KEY_ALIAS = "nelomai-quick-tunnel-plan"
private const val QUICK_PLAN_PREFERENCES = "nelomai-quick-tunnel-plan"
private const val QUICK_PLAN_CIPHERTEXT = "ciphertext"
private const val QUICK_PLAN_IV = "iv"
private const val QUICK_PLAN_FORMAT = 3

internal data class QuickTunnelTemplate(
    val options: TunnelOptionsArgs,
    val connection: QuickConnectionArgs,
)

internal object QuickTunnelPlanStore {
    fun save(context: Context, args: StartTunnelArgs) {
        if (!args.cacheQuickAction || args.quickConnection == null) return
        val plaintext = JSONObject().apply {
            put("format", QUICK_PLAN_FORMAT)
            put("validUntilUnix", args.quickActionValidUntilUnix ?: JSONObject.NULL)
            put("options", args.options.toJson())
            put("connection", args.quickConnection?.toJson() ?: JSONObject.NULL)
        }.toString().toByteArray(Charsets.UTF_8)
        try {
            check(encryptAndSave(context, plaintext)) { "quick_plan_write_failed" }
        } finally {
            plaintext.fill(0)
        }
    }

    fun updateDnsServers(context: Context, dnsServers: List<String>): Boolean {
        val payload = decrypt(context) ?: return true
        val options = payload.optJSONObject("options") ?: return false
        options.put("dnsServers", JSONArray(dnsServers))
        val plaintext = payload.toString().toByteArray(Charsets.UTF_8)
        return try {
            encryptAndSave(context, plaintext)
        } finally {
            plaintext.fill(0)
        }
    }

    fun loadTemplate(context: Context): QuickTunnelTemplate? {
        val payload = decrypt(context) ?: return null
        return try {
            if (payload.getInt("format") != QUICK_PLAN_FORMAT) {
                clear(context)
                return null
            }
            val connection = payload.optJSONObject("connection")?.toStoredQuickConnection()
                ?: return null
            QuickTunnelTemplate(
                options = TunnelOptionsArgs.fromJson(payload.getJSONObject("options")),
                connection = connection,
            )
        } catch (_: Throwable) {
            clear(context)
            null
        }
    }

    private fun backend(context: Context) = AndroidSecureEnvelopeBackend(context,
        preferenceName = QUICK_PLAN_PREFERENCES, recordName = "encrypted-envelope-v1", keyAlias = QUICK_PLAN_KEY_ALIAS)

    // A protected tombstone distinguishes legitimate clear from missing migration data.
    fun clear(context: Context): Boolean = backend(context).write("{\"format\":0}".toByteArray())

    private fun encryptAndSave(context: Context, plaintext: ByteArray): Boolean = backend(context).write(plaintext)

    private fun decrypt(context: Context): JSONObject? {
        val plaintext = backend(context).read() ?: return null
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

private fun QuickConnectionArgs.toJson(): JSONObject = JSONObject().apply {
    put("leaseId", leaseId)
    put("layer", layer)
    put("ticConnectionMode", ticConnectionMode)
    put("routeMode", routeMode)
    put("egressMode", egressMode)
    put("allowAlternate", allowAlternate)
}

internal fun JSONObject.toStoredQuickConnection(): QuickConnectionArgs = QuickConnectionArgs().apply {
    leaseId = getString("leaseId")
    layer = getString("layer")
    ticConnectionMode = getString("ticConnectionMode")
    routeMode = getString("routeMode")
    egressMode = getString("egressMode")
    allowAlternate = optBoolean("allowAlternate", false)
}
