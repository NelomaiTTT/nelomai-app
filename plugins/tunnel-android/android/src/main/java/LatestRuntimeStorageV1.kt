package ru.nelomai.tunnel

import android.content.Context
import android.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import org.json.JSONObject
import ru.nelomai.runtime.v1.RuntimeNativeStorageV1

/** Storage I/O boundary shared by startup and common-ACK retirement. */
internal interface NativeRuntimeStorageAccess {
    fun source(name: String, record: String): EncryptedRecordBackend
    fun destination(name: String, record: String): EncryptedRecordBackend
    fun receipt(name: String): EncryptedRecordBackend
    fun hasLegacy(name: String): Boolean
    fun retireLegacy(name: String)
    fun migrateQuickState()
    fun validateQuickStateDestination()
}

/** The common locked host invokes this before admitting any runtime. */
class LatestRuntimeStorageV1 : RuntimeNativeStorageV1 {
    override fun prepare(context: Context, slot: String, version: String, legacyMigration: Boolean, migrationComplete: Boolean) {
        prepare(AndroidNativeRuntimeStorageAccess(context), slot, version, legacyMigration, migrationComplete)
    }
    internal fun prepare(storage: NativeRuntimeStorageAccess, slot: String, version: String, legacyMigration: Boolean, migrationComplete: Boolean) {
        check(slot == AndroidRuntimeNamespace.slot && version == AndroidRuntimeNamespace.version)
        // Legacy users can upgrade directly to any maintenance release. The
        // compiled identity above selects the destination; only latest may
        // import/retire legacy records, regardless of its release number.
        if (slot != "latest") { check(!legacyMigration); return }
        if (migrationComplete) { acknowledge(storage); return }
        if (!legacyMigration) {
            check(legacyNames.none(storage::hasLegacy)) { "orphan_native_legacy_state" }
            return
        }
        for ((name, record) in records) {
            NativeRuntimeMigration.reseal(storage.source(name, record), storage.destination(name, record), storage.receipt(name))
        }
        storage.migrateQuickState()
    }

    override fun acknowledge(context: Context) = acknowledge(AndroidNativeRuntimeStorageAccess(context))

    internal fun acknowledge(storage: NativeRuntimeStorageAccess) {
        check(AndroidRuntimeNamespace.slot == "latest")
        // The common ACK can survive a crash before native source retirement.
        // Validate every remaining destination before deleting any source.
        // Once a source is gone, later opens do not depend on its old receipt.
        val remaining = legacyNames.filter(storage::hasLegacy)
        for (name in remaining) {
            val record = records.firstOrNull { it.first == name }?.second
            if (record != null) {
                NativeRuntimeMigration.validateDestination(storage.destination(name, record), storage.receipt(name))
            } else {
                val proof = checkNotNull(storage.receipt(name).read()) { "native_migration_receipt_missing" }
                try { check(JSONObject(proof.toString(Charsets.UTF_8)).getInt("format") == 1) }
                finally { proof.fill(0) }
                storage.validateQuickStateDestination()
            }
        }
        remaining.forEach(storage::retireLegacy)
    }

    companion object {
        private val records = listOf("nelomai-connection-recovery" to "encrypted-envelope",
            "nelomai-background-credential" to "encrypted-envelope-v3", "nelomai-quick-tunnel-plan" to "encrypted-envelope-v1")
        private val legacyNames = records.map { it.first } + "nelomai-quick-tunnel-state"
    }
}

private class AndroidNativeRuntimeStorageAccess(private val context: Context) : NativeRuntimeStorageAccess {
    override fun source(name: String, record: String): EncryptedRecordBackend = when (name) {
        "nelomai-quick-tunnel-plan" -> legacyPair(context, name)
        "nelomai-background-credential" -> backgroundSource(context, name, record)
        else -> AndroidSecureEnvelopeBackend(context, name, record, name, scoped = false)
    }
    override fun destination(name: String, record: String): EncryptedRecordBackend = AndroidSecureEnvelopeBackend(context, name, record, name)
    override fun hasLegacy(name: String): Boolean = context.getSharedPreferences(name, Context.MODE_PRIVATE).all.isNotEmpty()
    override fun retireLegacy(name: String) {
        check(context.getSharedPreferences(name, Context.MODE_PRIVATE).edit().clear().commit())
    }
    override fun validateQuickStateDestination() {
        check(context.getSharedPreferences(AndroidRuntimeNamespace.record("nelomai-quick-tunnel-state"), Context.MODE_PRIVATE).all.isNotEmpty()) {
            "native_migration_destination_missing"
        }
    }
    override fun migrateQuickState() {
        // The quick state projection is non-secret, but its revision and retry
        // markers must move together instead of aliasing the legacy preferences.
        val stateName = "nelomai-quick-tunnel-state"
        val stateReceipt = receipt(stateName)
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

    override fun receipt(name: String) = AndroidSecureEnvelopeBackend(context,
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
}
