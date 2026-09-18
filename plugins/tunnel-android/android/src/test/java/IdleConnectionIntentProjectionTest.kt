package ru.nelomai.tunnel

import org.junit.Assert.*
import org.junit.Test

class IdleConnectionIntentProjectionTest {
    private class Memory : EncryptedRecordBackend {
        var bytes: ByteArray? = null
        var failWrite = false
        var failRead = false
        override fun read(): ByteArray? {
            if (failRead) throw java.io.IOException("synthetic cache failure")
            return bytes?.copyOf()
        }
        override fun write(plaintext: ByteArray): Boolean {
            if (failWrite) return false
            bytes = plaintext.copyOf()
            return true
        }
    }

    @Test fun idleProjectionIsReadThroughAndInvalidatedBeforeAuthoritativeWrite() {
        val file = Memory()
        val projection = IdleConnectionIntentProjection(file) { 7 }
        val reader = IdleConnectionIntentProjection(file) { 7 }
        val idle = AndroidRecoveryEnvelope.empty(7)
        projection.publish(idle)
        assertEquals(false, reader.read()?.desiredActive)
        val durable = object : EncryptedRecordBackend {
            override fun read(): ByteArray? = null
            override fun write(plaintext: ByteArray): Boolean {
                assertNull(reader.read())
                return false
            }
        }
        assertFalse(projection.wrap(durable).write(AndroidRecoveryEnvelopeCodec.encode(idle)))
        assertNull(reader.read())
    }

    @Test fun activeUnknownBootAndCorruptProjectionRequireServiceRead() {
        val file = Memory()
        val projection = IdleConnectionIntentProjection(file) { 7 }
        assertNull(projection.read())
        val idle = AndroidRecoveryEnvelope.empty(7)
        projection.publish(idle)
        assertNull(IdleConnectionIntentProjection(file) { 8 }.read())
        assertNull(IdleConnectionIntentProjection(file) { null }.read())
        projection.publish(idle.copy(intent = idle.intent.copy(desiredActive = true)))
        assertNull(projection.read())
        file.bytes = "broken".toByteArray()
        assertNull(projection.read())
    }

    @Test fun unavailableIdleCacheDoesNotBlockCancellingAnActiveIntent() {
        val file = Memory()
        val projection = IdleConnectionIntentProjection(file) { 7 }
        val durable = Memory()
        val store = AndroidRecoveryStore(projection.wrap(durable), BootIdentityProvider { 7 })
        val first = store.read() as RecoveryStoreResult.Success
        assertTrue(store.setDesiredActive(first.value.intent.generation, true) is RecoveryStoreResult.Success)
        assertNull(projection.read())
        file.failWrite = true
        val current = store.read() as RecoveryStoreResult.Success
        assertTrue(store.setDesiredActive(current.value.intent.generation, false) is RecoveryStoreResult.Success)
        assertFalse((store.read() as RecoveryStoreResult.Success).value.intent.desiredActive)
    }

    @Test fun unreadableValidCacheMustNotBeConfusedWithEmptyCache() {
        val file = Memory()
        val projection = IdleConnectionIntentProjection(file) { 7 }
        projection.publish(AndroidRecoveryEnvelope.empty(7))
        file.failRead = true
        file.failWrite = true
        assertFalse(projection.invalidate())
        file.failRead = false
        assertNotNull(projection.read())
    }

    @Test fun failedReplacementCanInvalidateByRemovingTheOldBase() {
        val file = Memory()
        val projection = IdleConnectionIntentProjection(file, remove = { file.bytes = null; true }) { 7 }
        projection.publish(AndroidRecoveryEnvelope.empty(7))
        file.failWrite = true
        assertTrue(projection.invalidate())
        assertNull(projection.read())
    }
}
