package ru.nelomai.tunnel

import android.content.Context
import android.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import org.json.JSONObject
import ru.nelomai.runtime.v1.RuntimeNativeStorageV1

/** The common locked host invokes this before admitting any runtime. */
class LatestRuntimeStorageV1 : RuntimeNativeStorageV1 {
    override fun prepare(context: Context, slot: String, version: String, legacyMigration: Boolean, migrationComplete: Boolean) {
        check(slot == AndroidRuntimeNamespace.slot && version == AndroidRuntimeNamespace.version)
        if (slot != "latest" || version != "0.2.16") { check(!legacyMigration); return }
        if (migrationComplete) { acknowledge(context); return }
        if (!legacyMigration) {
            check(legacyNames.none { context.getSharedPreferences(it, Context.MODE_PRIVATE).all.isNotEmpty() }) { "orphan_native_legacy_state" }
            return
        }
        for ((name, record) in records) {
            val source = when (name) {
                "nelomai-quick-tunnel-plan" -> legacyPair(context, name)
                "nelomai-background-credential" -> backgroundSource(context, name, record)
                else -> AndroidSecureEnvelopeBackend(context, name, record, name, scoped = false)
            }
            NativeRuntimeMigration.reseal(source,
                AndroidSecureEnvelopeBackend(context, name, record, name), receipt(context, name))
        }
        // The quick state projection is non-secret, but its revision and retry
        // markers must move together instead of aliasing the legacy preferences.
        val stateName = "nelomai-quick-tunnel-state"
        val stateReceipt = receipt(context, stateName)
        if (stateReceipt.read() == null) {
            val source = context.getSharedPreferences(stateName, Context.MODE_PRIVATE)
            val target = context.getSharedPreferences(AndroidRuntimeNamespace.record(stateName), Context.MODE_PRIVATE)
            val editor = target.edit().clear()
            source.all.forEach { (key, value) -> when (value) {
                is Boolean -> editor.putBoolean(key, value)
                is Long -> editor.putLong(key, value)
                is Int -> editor.putInt(key, value)
                is String -> editor.putString(key, value)
                else -> error("unsupported_native_quick_state")
            } }
            check(editor.commit() && source.all == target.all)
            check(stateReceipt.write("{\"format\":1}".toByteArray()))
        }
    }

    override fun acknowledge(context: Context) {
        // This is reachable only after common Rust bootstrap ACK. It is safe to
        // replay if the process died between retiring two individual sources.
        check(AndroidRuntimeNamespace.slot == "latest" && AndroidRuntimeNamespace.version == "0.2.16")
        for (name in legacyNames) {
            val proof = receipt(context, name).read()
            check(proof != null) { "native_migration_receipt_missing" }
            proof.fill(0)
            check(context.getSharedPreferences(name, Context.MODE_PRIVATE).edit().clear().commit())
        }
    }

    private fun receipt(context: Context, name: String) = AndroidSecureEnvelopeBackend(context,
        preferenceName = "native-migration-receipt-$name", recordName = "receipt-v1", keyAlias = "native-migration-receipt-$name")

    private fun backgroundSource(context: Context, name: String, record: String): EncryptedRecordBackend = object : EncryptedRecordBackend {
        override fun write(plaintext: ByteArray): Boolean = error("legacy_source_read_only")
        override fun read(): ByteArray? {
            AndroidSecureEnvelopeBackend(context, name, record, name, scoped = false).read()?.let { return it }
            val plaintext = legacyPair(context, name).read() ?: return null
            return try {
                val value = JSONObject(plaintext.toString(Charsets.UTF_8))
                check(value.getInt("format") == 2)
                val credential = BackgroundCredential(
                    deviceId = BackgroundCredentialEnvelopeCodec.normalizeDeviceId(value.getString("deviceId")),
                    panelBase = BackgroundCredentialEnvelopeCodec.normalizePanelBase(value.getString("panelBase")),
                    token = value.getString("token"), expiresAtUnix = value.getLong("expiresAtUnix"))
                BackgroundCredentialEnvelopeCodec.encode(BackgroundCredentialEnvelope(revision = 1,
                    deviceId = credential.deviceId, panelBase = credential.panelBase, active = credential))
            } finally { plaintext.fill(0) }
        }
    }

    private fun legacyPair(context: Context, name: String): EncryptedRecordBackend = object : EncryptedRecordBackend {
        override fun write(plaintext: ByteArray): Boolean = error("legacy_source_read_only")
        override fun read(): ByteArray? {
            val preferences = context.getSharedPreferences(name, Context.MODE_PRIVATE)
            val ciphertext = preferences.getString("ciphertext", null)
            val iv = preferences.getString("iv", null)
            if (ciphertext == null && iv == null) return null
            check(ciphertext != null && iv != null) { "legacy_native_record_incomplete" }
            val bytes = Base64.decode(ciphertext, Base64.NO_WRAP)
            val nonce = Base64.decode(iv, Base64.NO_WRAP)
            return try { Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE, androidEnvelopeSecretKey(name), GCMParameterSpec(128, nonce))
                doFinal(bytes)
            } } finally { bytes.fill(0); nonce.fill(0) }
        }
    }
    companion object {
        private val records = listOf("nelomai-connection-recovery" to "encrypted-envelope",
            "nelomai-background-credential" to "encrypted-envelope-v3", "nelomai-quick-tunnel-plan" to "encrypted-envelope-v1")
        private val legacyNames = records.map { it.first } + "nelomai-quick-tunnel-state"
    }
}
