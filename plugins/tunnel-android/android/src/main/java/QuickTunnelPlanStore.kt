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
private const val QUICK_PLAN_FORMAT = 1

internal object QuickTunnelPlanStore {
    fun save(context: Context, args: StartTunnelArgs) {
        if (!args.cacheQuickAction || !args.configurationInitialized) return
        val plaintext = JSONObject().apply {
            put("format", QUICK_PLAN_FORMAT)
            put(
                "configuration",
                Base64.encodeToString(args.configuration, Base64.NO_WRAP),
            )
            put("validUntilUnix", args.quickActionValidUntilUnix ?: JSONObject.NULL)
            put("options", args.options.toJson())
        }.toString().toByteArray(Charsets.UTF_8)
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, secretKey())
            val ciphertext = cipher.doFinal(plaintext)
            context.getSharedPreferences(QUICK_PLAN_PREFERENCES, Context.MODE_PRIVATE)
                .edit()
                .putString(QUICK_PLAN_CIPHERTEXT, Base64.encodeToString(ciphertext, Base64.NO_WRAP))
                .putString(QUICK_PLAN_IV, Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
                .commit()
        } finally {
            plaintext.fill(0)
        }
    }

    fun load(context: Context, nowUnix: Long): StartTunnelArgs? {
        val preferences = context.getSharedPreferences(
            QUICK_PLAN_PREFERENCES,
            Context.MODE_PRIVATE,
        )
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
            val payload = JSONObject(plaintext.toString(Charsets.UTF_8))
            if (payload.getInt("format") != QUICK_PLAN_FORMAT) {
                clear(context)
                return null
            }
            val validUntilUnix = payload.optLongOrNull("validUntilUnix")
            if (validUntilUnix != null && nowUnix >= validUntilUnix) {
                clear(context)
                return null
            }
            StartTunnelArgs().apply {
                apiVersion = TUNNEL_API_VERSION
                configuration = Base64.decode(
                    payload.getString("configuration"),
                    Base64.NO_WRAP,
                )
                options = TunnelOptionsArgs.fromJson(payload.getJSONObject("options"))
                cacheQuickAction = false
                quickActionValidUntilUnix = validUntilUnix
            }
        } catch (_: Throwable) {
            clear(context)
            null
        } finally {
            plaintext?.fill(0)
        }
    }

    fun clear(context: Context) {
        context.getSharedPreferences(QUICK_PLAN_PREFERENCES, Context.MODE_PRIVATE)
            .edit()
            .clear()
            .commit()
    }

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
}

private fun TunnelOptionsArgs.toJson(): JSONObject = JSONObject().apply {
    put("splitActive", splitActive)
    put("excludedPackages", JSONArray(excludedPackages))
    put("includedPackages", JSONArray(includedPackages))
    put("splitTunnelRoutes", JSONArray(splitTunnelRoutes))
    put("excludeLocalNetworks", excludeLocalNetworks)
}

private fun TunnelOptionsArgs.Companion.fromJson(payload: JSONObject): TunnelOptionsArgs =
    TunnelOptionsArgs().apply {
        splitActive = payload.optBoolean("splitActive", false)
        excludedPackages = payload.stringList("excludedPackages")
        includedPackages = payload.stringList("includedPackages")
        splitTunnelRoutes = payload.stringList("splitTunnelRoutes")
        excludeLocalNetworks = payload.optBoolean("excludeLocalNetworks", false)
    }

private fun JSONObject.stringList(key: String): ArrayList<String> {
    val values = optJSONArray(key) ?: return arrayListOf()
    return ArrayList((0 until values.length()).map(values::getString))
}

private fun JSONObject.optLongOrNull(key: String): Long? =
    if (isNull(key) || !has(key)) null else getLong(key)
