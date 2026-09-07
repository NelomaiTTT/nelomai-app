package ru.nelomai.tunnel

import org.junit.Assert.*
import org.junit.Test

class NativeRuntimeMigrationTest {
    private class Record(var bytes: ByteArray? = null) : EncryptedRecordBackend {
        var failWrite = false
        override fun read() = bytes?.clone()
        override fun write(plaintext: ByteArray): Boolean {
            if (failWrite) return false
            bytes = plaintext.clone(); return true
        }
    }
    @Test fun interruptedResealPreservesSourceAndResumesWithoutOverwritingAdvancedDestination() {
        val source = Record("{\"revision\":7,\"pending\":\"stop\"}".toByteArray())
        val target = Record()
        val proof = Record().apply { failWrite = true }
        assertThrows(IllegalStateException::class.java) { NativeRuntimeMigration.reseal(source, target, proof) }
        assertArrayEquals(source.bytes, target.bytes)
        proof.failWrite = false
        NativeRuntimeMigration.reseal(source, target, proof)
        target.bytes = "{\"revision\":8,\"pending\":null}".toByteArray()
        NativeRuntimeMigration.reseal(source, target, proof)
        assertEquals("{\"revision\":8,\"pending\":null}", target.bytes!!.toString(Charsets.UTF_8))
        assertEquals("{\"revision\":7,\"pending\":\"stop\"}", source.bytes!!.toString(Charsets.UTF_8))
    }
    @Test fun unexpectedDestinationNeverBecomesFreshState() {
        assertThrows(IllegalStateException::class.java) { NativeRuntimeMigration.reseal(Record("source".toByteArray()), Record("other".toByteArray()), Record()) }
    }
    @Test fun missingSealedDestinationRequiresRecovery() {
        val source = Record("source".toByteArray()); val target = Record(); val proof = Record()
        NativeRuntimeMigration.reseal(source, target, proof)
        target.bytes = null
        assertThrows(IllegalStateException::class.java) { NativeRuntimeMigration.reseal(source, target, proof) }
    }
}
