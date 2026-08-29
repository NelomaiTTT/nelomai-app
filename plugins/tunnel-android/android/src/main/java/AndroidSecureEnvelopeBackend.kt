package ru.nelomai.tunnel

import android.content.Context
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.AEADBadTagException
import javax.crypto.BadPaddingException
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

private const val RECOVERY_PREFERENCES = "nelomai-connection-recovery"
private const val RECOVERY_RECORD = "encrypted-envelope"
private const val RECOVERY_KEY_ALIAS = "nelomai-connection-recovery"
private const val ENCRYPTED_RECORD_FORMAT: Byte = 1
private const val GCM_IV_LENGTH = 12
private const val GCM_TAG_BITS = 128

internal class AndroidSecureEnvelopeBackend(
    context: Context,
    private val preferenceName: String = RECOVERY_PREFERENCES,
    private val recordName: String = RECOVERY_RECORD,
    private val keyAlias: String = RECOVERY_KEY_ALIAS,
) : EncryptedRecordBackend {
    private val preferences = context.applicationContext.getSharedPreferences(
        preferenceName,
        Context.MODE_PRIVATE,
    )
    private val gate = Any()

    override fun read(): ByteArray? = synchronized(gate) {
        val encoded = preferences.getString(recordName, null) ?: return@synchronized null
        val record = try {
            Base64.decode(encoded, Base64.NO_WRAP)
        } catch (error: IllegalArgumentException) {
            throw EncryptedRecordCorruptException(error)
        }
        val ivLength = try {
            require(record.size > 2 + GCM_IV_LENGTH + GCM_TAG_BITS / 8) {
                "encrypted_recovery_record_too_short"
            }
            require(record[0] == ENCRYPTED_RECORD_FORMAT) {
                "unsupported_encrypted_recovery_format"
            }
            (record[1].toInt() and 0xff).also {
                require(it == GCM_IV_LENGTH && record.size > 2 + it) {
                    "invalid_encrypted_recovery_iv"
                }
            }
        } catch (error: IllegalArgumentException) {
            record.fill(0)
            throw EncryptedRecordCorruptException(error)
        }
        val iv = record.copyOfRange(2, 2 + ivLength)
        val ciphertext = record.copyOfRange(2 + ivLength, record.size)
        try {
            try {
                Cipher.getInstance("AES/GCM/NoPadding").run {
                    init(
                        Cipher.DECRYPT_MODE,
                        androidEnvelopeSecretKey(keyAlias),
                        GCMParameterSpec(GCM_TAG_BITS, iv),
                    )
                    updateAAD(recordIdentity())
                    doFinal(ciphertext)
                }
            } catch (error: AEADBadTagException) {
                throw EncryptedRecordCorruptException(error)
            } catch (error: BadPaddingException) {
                throw EncryptedRecordCorruptException(error)
            }
        } finally {
            iv.fill(0)
            ciphertext.fill(0)
            record.fill(0)
        }
    }

    override fun write(plaintext: ByteArray): Boolean = synchronized(gate) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, androidEnvelopeSecretKey(keyAlias))
            updateAAD(recordIdentity())
        }
        val ciphertext = cipher.doFinal(plaintext)
        val iv = cipher.iv
        require(iv.size == GCM_IV_LENGTH) { "invalid_generated_recovery_iv" }
        val record = ByteArray(2 + iv.size + ciphertext.size).apply {
            this[0] = ENCRYPTED_RECORD_FORMAT
            this[1] = iv.size.toByte()
            iv.copyInto(this, destinationOffset = 2)
            ciphertext.copyInto(this, destinationOffset = 2 + iv.size)
        }
        return@synchronized try {
            preferences.edit()
                .clear()
                .putString(recordName, Base64.encodeToString(record, Base64.NO_WRAP))
                .commit()
        } finally {
            iv.fill(0)
            ciphertext.fill(0)
            record.fill(0)
        }
    }

    private fun recordIdentity(): ByteArray = "$preferenceName\u0000$recordName"
        .toByteArray(Charsets.UTF_8)
}

internal fun androidEnvelopeSecretKey(keyAlias: String): SecretKey {
    val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    (keyStore.getKey(keyAlias, null) as? SecretKey)?.let { return it }
    return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
        init(
            KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build(),
        )
        generateKey()
    }
}

internal class AndroidBootIdentityProvider(context: Context) : BootIdentityProvider {
    private val resolver = context.applicationContext.contentResolver

    override fun bootCount(): Long? = runCatching {
        Settings.Global.getInt(resolver, Settings.Global.BOOT_COUNT)
            .takeIf { it >= 0 }
            ?.toLong()
    }.getOrNull()
}

internal object AndroidRecoveryStores {
    @Volatile
    private var instance: AndroidRecoveryStore? = null

    fun open(context: Context): AndroidRecoveryStore = instance ?: synchronized(this) {
        instance ?: AndroidRecoveryStore(
            backend = AndroidSecureEnvelopeBackend(context.applicationContext),
            bootIdentity = AndroidBootIdentityProvider(context.applicationContext),
        ).also { instance = it }
    }
}
