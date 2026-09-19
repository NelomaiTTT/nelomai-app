package ru.nelomai.tunnel

import java.security.MessageDigest
import org.json.JSONObject

/** Plaintext exists only between the legacy decryptor and target encryptor.
 * The protected receipt is committed after a byte-exact readback. No mutation
 * of a source record occurs here; common bootstrap ACK owns its retirement. */
internal object NativeRuntimeMigration {
    fun validateDestination(target: EncryptedRecordBackend, receipt: EncryptedRecordBackend) {
        val proof = checkNotNull(receipt.read()) { "native_migration_receipt_missing" }
        validateDestination(target, proof)
    }

    private fun validateDestination(target: EncryptedRecordBackend, proof: ByteArray) {
        val expectedPresent = try {
            val marker = JSONObject(proof.toString(Charsets.UTF_8))
            check(marker.getInt("format") == 1 && marker.has("source_sha256"))
            if (marker.isNull("source_sha256")) false else {
                check(marker.getString("source_sha256").matches(Regex("[0-9a-f]{64}")))
                true
            }
        } finally { proof.fill(0) }
        // Only presence/decryption is required: an admitted owner may have
        // advanced or deliberately cleared the record in a protected envelope.
        val current = target.read()
        try { check(!expectedPresent || current != null) { "native_migration_destination_missing" } }
        finally { current?.fill(0) }
    }

    fun reseal(source: EncryptedRecordBackend, target: EncryptedRecordBackend, receipt: EncryptedRecordBackend) {
        val proof = receipt.read()
        if (proof != null) {
            // The selected owner may have advanced its revision after readback.
            // Never replay the old source over that new state.
            validateDestination(target, proof)
            return
        }
        val original = source.read()
        val existing = target.read()
        try {
            check(existing == null || (original != null && existing.contentEquals(original))) { "native_migration_destination_conflict" }
            if (original != null && existing == null) check(target.write(original)) { "native_migration_write_failed" }
            val readback = target.read()
            try { check(if (original == null) readback == null else readback != null && readback.contentEquals(original)) { "native_migration_readback_failed" } }
            finally { readback?.fill(0) }
            val digest = original?.let { MessageDigest.getInstance("SHA-256").digest(it).joinToString("") { byte -> "%02x".format(byte) } }
            val value = JSONObject().put("format", 1).put("source_sha256", digest ?: JSONObject.NULL).toString().toByteArray()
            try { check(receipt.write(value)) { "native_migration_receipt_failed" } }
            finally { value.fill(0) }
        } finally { original?.fill(0); existing?.fill(0) }
    }
}
