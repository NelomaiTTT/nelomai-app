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

    fun clear(context: Context): Boolean =
        context.getSharedPreferences(QUICK_PLAN_PREFERENCES, Context.MODE_PRIVATE)
            .edit()
            .clear()
            .commit()

    private fun secretKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (keyStore.getKey(QUICK_PLAN_KEY_ALIAS, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
            init(
                KeyGenParameterSpec.Builder(
                    QUICK_PLAN_KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build(),
            )
            generateKey()
        }
    }

    private fun encryptAndSave(context: Context, plaintext: ByteArray): Boolean {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey())
        val ciphertext = cipher.doFinal(plaintext)
        return context.getSharedPreferences(QUICK_PLAN_PREFERENCES, Context.MODE_PRIVATE)
            .edit()
            .putString(QUICK_PLAN_CIPHERTEXT, Base64.encodeToString(ciphertext, Base64.NO_WRAP))
            .putString(QUICK_PLAN_IV, Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
            .commit()
    }

    private fun decrypt(context: Context): JSONObject? {
        val preferences = context.getSharedPreferences(QUICK_PLAN_PREFERENCES, Context.MODE_PRIVATE)
        val encodedCiphertext = preferences.getString(QUICK_PLAN_CIPHERTEXT, null) ?: return null
        val encodedIv = preferences.getString(QUICK_PLAN_IV, null) ?: return null
        var plaintext: ByteArray? = null
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                secretKey(),
                GCMParameterSpec(128, Base64.decode(encodedIv, Base64.NO_WRAP)),
            )
            plaintext = cipher.doFinal(Base64.decode(encodedCiphertext, Base64.NO_WRAP))
            JSONObject(plaintext.toString(Charsets.UTF_8))
        } catch (_: Throwable) {
            null
        } finally {
            plaintext?.fill(0)
        }
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
