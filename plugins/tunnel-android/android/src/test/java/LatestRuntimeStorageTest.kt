package ru.nelomai.tunnel

import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.*
import org.junit.Test

/** Real LatestRuntimeStorage prepare/ACK control flow with in-memory protected
 * I/O. AES/GCM read failures are real; Android Keystore remains a hardware gate. */
class LatestRuntimeStorageTest {
    private class SealedRecord : EncryptedRecordBackend {
        private val key = SecretKeySpec(ByteArray(16) { 7 }, "AES")
        var ciphertext: ByteArray? = null
        override fun write(plaintext: ByteArray): Boolean {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            ciphertext = cipher.iv + cipher.doFinal(plaintext)
            return true
        }
        override fun read(): ByteArray? {
            val bytes = ciphertext ?: return null
            return try {
                Cipher.getInstance("AES/GCM/NoPadding").run {
                    init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, bytes.copyOfRange(0, 12)))
                    doFinal(bytes.copyOfRange(12, bytes.size))
                }
            } catch (error: Exception) { throw IllegalStateException("unreadable_destination", error) }
        }
    }
    private class Storage : NativeRuntimeStorageAccess {
        val names = listOf("nelomai-connection-recovery", "nelomai-background-credential", "nelomai-quick-tunnel-plan")
        val sources = names.associateWith { SealedRecord().apply { write("legacy-record".toByteArray()) } }
        val targets = names.associateWith { SealedRecord() }
        val proofs = (names + "nelomai-quick-tunnel-state").associateWith { SealedRecord() }
        var quickSource = true
        var quickTarget = false
        var failRetirement: String? = null
        override fun source(name: String, record: String) = sources.getValue(name)
        override fun destination(name: String, record: String) = targets.getValue(name)
        override fun receipt(name: String) = proofs.getValue(name)
        override fun hasLegacy(name: String) = if (name == "nelomai-quick-tunnel-state") quickSource else sources.getValue(name).ciphertext != null
        override fun retireLegacy(name: String) {
            if (failRetirement == name) { failRetirement = null; error("process_stopped_before_next_native_retirement") }
            if (name == "nelomai-quick-tunnel-state") quickSource = false else sources.getValue(name).ciphertext = null
        }
        override fun migrateQuickState() {
            quickTarget = quickSource
            proofs.getValue("nelomai-quick-tunnel-state").write("{\"format\":1}".toByteArray())
        }
        override fun validateQuickStateDestination() { check(quickTarget) { "native_migration_destination_missing" } }
    }
    private fun resealed(): Pair<LatestRuntimeStorageV1, Storage> {
        val runtime = LatestRuntimeStorageV1(); val storage = Storage()
        runtime.prepare(storage, "latest", AndroidRuntimeNamespace.version, legacyMigration = true, migrationComplete = false)
        assertTrue(storage.names.all(storage::hasLegacy))
        return runtime to storage
    }
    private fun reopenCompleted(runtime: LatestRuntimeStorageV1, storage: Storage) =
        runtime.prepare(storage, "latest", AndroidRuntimeNamespace.version, legacyMigration = false, migrationComplete = true)

    @Test fun mismatchedRuntimeIdentityCannotMigrateOrRetireSources() {
        for ((slot, version) in listOf("stable" to AndroidRuntimeNamespace.version, "latest" to "0.0.0")) {
            val storage = Storage()
            assertThrows(IllegalStateException::class.java) {
                LatestRuntimeStorageV1().prepare(storage, slot, version, legacyMigration = true, migrationComplete = false)
            }
            assertTrue(storage.names.all(storage::hasLegacy))
            assertTrue(storage.targets.values.all { it.ciphertext == null })
            assertTrue(storage.quickSource)
        }
    }

    @Test fun missingCommonMigrationCannotAdmitOrphanNativeSources() {
        val storage = Storage()
        assertThrows(IllegalStateException::class.java) {
            LatestRuntimeStorageV1().prepare(storage, "latest", AndroidRuntimeNamespace.version,
                legacyMigration = false, migrationComplete = false)
        }
        assertTrue(storage.names.all(storage::hasLegacy))
        assertTrue(storage.targets.values.all { it.ciphertext == null })
    }

    @Test fun completedMigrationWithoutLegacySourcesDoesNotRequireOldNativeReceipts() {
        val storage = Storage()
        storage.sources.values.forEach { it.ciphertext = null }
        storage.quickSource = false
        val runtime = LatestRuntimeStorageV1()
        reopenCompleted(runtime, storage)
        runtime.acknowledge(storage)
        assertTrue(storage.targets.values.all { it.ciphertext == null })
        assertTrue(storage.proofs.values.all { it.ciphertext == null })
    }

    @Test fun commonAckBeforeNativeRetirementNeverDiscardsSourceWhenDestinationDisappears() {
        for (name in Storage().names) {
            val (runtime, storage) = resealed()
            storage.targets.getValue(name).ciphertext = null
            assertThrows(IllegalStateException::class.java) { reopenCompleted(runtime, storage) }
            assertTrue(storage.names.all(storage::hasLegacy))
            assertTrue(storage.quickSource)
        }
    }
    @Test fun unreadableDestinationsAndReceiptsPreserveEverySurvivingSource() {
        for (name in Storage().names) for (corruptProof in listOf(false, true)) {
            val (runtime, storage) = resealed()
            val record = if (corruptProof) storage.proofs.getValue(name) else storage.targets.getValue(name)
            record.ciphertext!!.let { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
            assertThrows(IllegalStateException::class.java) { reopenCompleted(runtime, storage) }
            assertTrue(storage.names.all(storage::hasLegacy))
        }
    }
    @Test fun advancedDataAndProtectedClearTombstonesCanRetireWithoutOldContentEquality() {
        val (runtime, storage) = resealed()
        storage.targets.getValue("nelomai-connection-recovery").write("{\"revision\":8,\"pending\":null}".toByteArray())
        storage.targets.getValue("nelomai-background-credential").write(BackgroundCredentialEnvelopeCodec.encode(BackgroundCredentialEnvelope(revision = 8)))
        storage.targets.getValue("nelomai-quick-tunnel-plan").write("{\"format\":0}".toByteArray())
        reopenCompleted(runtime, storage)
        assertFalse(storage.names.any(storage::hasLegacy)); assertFalse(storage.quickSource)
        assertEquals("{\"format\":0}", storage.targets.getValue("nelomai-quick-tunnel-plan").read()!!.toString(Charsets.UTF_8))
        assertEquals(8, BackgroundCredentialEnvelopeCodec.decode(storage.targets.getValue("nelomai-background-credential").read()!!).revision)
    }
    @Test fun completedRetirementDoesNotPermanentlyRequireOriginalReceiptsOrDestinations() {
        val (runtime, storage) = resealed()
        reopenCompleted(runtime, storage)
        storage.proofs.values.forEach { it.ciphertext = null }
        storage.targets.values.forEach { it.ciphertext = null }
        storage.quickTarget = false
        reopenCompleted(runtime, storage)
        assertFalse(storage.names.any(storage::hasLegacy))
    }
    @Test fun crashBetweenSourceRetirementsOnlyValidatesTheSurvivingSourcesOnReopen() {
        val (runtime, storage) = resealed()
        storage.failRetirement = "nelomai-background-credential"
        assertThrows(IllegalStateException::class.java) { runtime.acknowledge(storage) }
        assertFalse(storage.hasLegacy("nelomai-connection-recovery"))
        assertTrue(storage.hasLegacy("nelomai-background-credential"))
        storage.targets.getValue("nelomai-connection-recovery").ciphertext = null
        storage.proofs.getValue("nelomai-connection-recovery").ciphertext = null
        reopenCompleted(runtime, storage)
        assertFalse(storage.names.any(storage::hasLegacy))
    }
}
