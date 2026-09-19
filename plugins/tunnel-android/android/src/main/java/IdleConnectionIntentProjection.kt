package ru.nelomai.tunnel

import android.content.Context
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import org.json.JSONObject

/** Read-only UI projection; never an authority for starting/stopping a tunnel. */
internal class IdleConnectionIntentProjection(
    private val backend: EncryptedRecordBackend,
    private val remove: () -> Boolean = { false },
    private val boot: () -> Long?,
) {
    private fun readRecord(): Pair<Long, Long>? {
        val bytes = backend.read() ?: return null
        if (bytes.size !in 1..256) return null
        return runCatching {
            val value = JSONObject(bytes.toString(Charsets.UTF_8))
            val bootCount = value.getLong("boot")
            val generation = value.getLong("generation")
            require(value.getInt("format") == 1 && bootCount >= 0 && generation >= 0)
            bootCount to generation
        }.getOrNull()
    }

    fun read(): ConnectionIntentServiceStatus? = runCatching {
        val record = readRecord() ?: return null
        if (record.first != boot()) return null
        ConnectionIntentServiceStatus(record.second, false, "none", null, null, null)
    }.getOrNull()

    fun invalidate(): Boolean {
        // Active/cleanup already has no usable idle projection. A presentation
        // cache IO error must not stop its authoritative cancellation write.
        val record = runCatching { readRecord() }
        if (record.isSuccess && record.getOrNull() == null) return true
        if (runCatching { backend.write(byteArrayOf()) }.getOrDefault(false)) return true
        return runCatching { remove() }.getOrDefault(false)
    }

    // Called under the recovery store's lock; publishing a returned snapshot
    // outside that lock could overwrite a newer active-state invalidation.
    fun observe(result: RecoveryStoreResult<AndroidRecoveryEnvelope>) {
        when (result) {
            is RecoveryStoreResult.Success -> publish(result.value)
            is RecoveryStoreResult.Failure -> invalidate()
        }
    }

    fun publish(envelope: AndroidRecoveryEnvelope) {
        val intent = envelope.intent
        if (intent.desiredActive || envelope.leaseTransaction != null || envelope.redundantTransaction != null ||
            intent.retry != AndroidRetryState() || intent.bootCount != boot()) {
            invalidate()
            return
        }
        runCatching {
            backend.write(JSONObject().put("format", 1).put("boot", intent.bootCount)
                .put("generation", intent.generation).toString().toByteArray(Charsets.UTF_8))
        }
    }

    fun wrap(durable: EncryptedRecordBackend): EncryptedRecordBackend = object : EncryptedRecordBackend {
        override fun read() = durable.read()
        override fun write(plaintext: ByteArray): Boolean {
            // No stale idle result can survive an authoritative change, including
            // a crash after that change but before publishing its new projection.
            if (!invalidate()) return false
            if (!durable.write(plaintext)) return false
            runCatching { publish(AndroidRecoveryEnvelopeCodec.decode(plaintext)) }
            return true
        }
    }

    companion object {
        fun open(context: Context): IdleConnectionIntentProjection {
            val directory = AndroidRuntimeNamespace.directory(context)
            val file = File(directory, "idle-intent-projection.json")
            val backend = object : EncryptedRecordBackend {
                // AtomicFile.openRead can delete a writer's .new file. Readers
                // must only open the committed base, never repair/rename files.
                override fun read(): ByteArray? {
                    if (!file.exists()) return null
                    return FileInputStream(file).use { stream ->
                        val bytes = ByteArray(257)
                        var size = 0
                        while (size < bytes.size) {
                            val count = stream.read(bytes, size, bytes.size - size)
                            if (count < 0) break
                            size += count
                        }
                        bytes.copyOf(size)
                    }
                }
                override fun write(plaintext: ByteArray): Boolean {
                    if (!directory.isDirectory && !directory.mkdirs()) return false
                    val staging = File.createTempFile("idle-intent-", ".tmp", directory)
                    return try {
                        FileOutputStream(staging).use {
                            it.write(plaintext)
                            it.fd.sync()
                        }
                        // Unlike AtomicFile.finishWrite, failed replacement must
                        // throw rather than silently leave an old idle base.
                        check(staging.renameTo(file)) { "idle_projection_replace_failed" }
                        true
                    } finally {
                        staging.delete()
                    }
                }
            }
            return IdleConnectionIntentProjection(backend,
                remove = { file.delete() || !file.exists() },
                boot = AndroidBootIdentityProvider(context)::bootCount)
        }
    }
}
