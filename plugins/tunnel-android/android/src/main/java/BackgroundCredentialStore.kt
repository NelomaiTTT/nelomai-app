package ru.nelomai.tunnel

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.net.URI
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import org.json.JSONObject

private const val BACKGROUND_KEY_ALIAS = "nelomai-background-credential"
private const val BACKGROUND_PREFERENCES = "nelomai-background-credential"
private const val BACKGROUND_CIPHERTEXT = "ciphertext"
private const val BACKGROUND_IV = "iv"
private const val BACKGROUND_FORMAT = 1

internal data class BackgroundCredential(
    val panelBase: String,
    val token: String,
    val expiresAtUnix: Long,
)

internal object BackgroundCredentialStore {
    fun save(context: Context, credential: BackgroundCredential) {
        val normalizedBase = normalizePanelBase(credential.panelBase)
        val plaintext = JSONObject().apply {
            put("format", BACKGROUND_FORMAT)
            put("panelBase", normalizedBase)
            put("token", credential.token)
            put("expiresAtUnix", credential.expiresAtUnix)
        }.toString().toByteArray(Charsets.UTF_8)
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, secretKey())
            val ciphertext = cipher.doFinal(plaintext)
            val saved = context.getSharedPreferences(BACKGROUND_PREFERENCES, Context.MODE_PRIVATE)
                .edit()
                .putString(BACKGROUND_CIPHERTEXT, Base64.encodeToString(ciphertext, Base64.NO_WRAP))
                .putString(BACKGROUND_IV, Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
                .commit()
            check(saved) { "background_credential_write_failed" }
        } finally {
            plaintext.fill(0)
        }
    }

    fun load(context: Context): BackgroundCredential? {
        val preferences = context.getSharedPreferences(BACKGROUND_PREFERENCES, Context.MODE_PRIVATE)
        val encodedCiphertext = preferences.getString(BACKGROUND_CIPHERTEXT, null) ?: return null
        val encodedIv = preferences.getString(BACKGROUND_IV, null) ?: return null
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
            if (payload.getInt("format") != BACKGROUND_FORMAT) {
                clear(context)
                return null
            }
            val expiresAtUnix = payload.getLong("expiresAtUnix")
            BackgroundCredential(
                panelBase = normalizePanelBase(payload.getString("panelBase")),
                token = payload.getString("token"),
                expiresAtUnix = expiresAtUnix,
            )
        } catch (_: Throwable) {
            clear(context)
            null
        } finally {
            plaintext?.fill(0)
        }
    }

    fun clear(context: Context): Boolean =
        context.getSharedPreferences(BACKGROUND_PREFERENCES, Context.MODE_PRIVATE)
            .edit()
            .clear()
            .commit()

    private fun normalizePanelBase(value: String): String {
        val uri = URI(value.trim())
        require(uri.scheme.equals("https", ignoreCase = true))
        require(!uri.host.isNullOrBlank())
        require(uri.userInfo == null && uri.query == null && uri.fragment == null)
        return value.trim().trimEnd('/')
    }

    private fun secretKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (keyStore.getKey(BACKGROUND_KEY_ALIAS, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
            init(
                KeyGenParameterSpec.Builder(
                    BACKGROUND_KEY_ALIAS,
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
