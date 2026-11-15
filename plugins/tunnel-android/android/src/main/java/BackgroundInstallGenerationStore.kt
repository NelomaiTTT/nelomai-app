package ru.nelomai.tunnel

import android.content.Context
import java.io.File
import java.io.RandomAccessFile
import java.nio.channels.OverlappingFileLockException
import org.json.JSONObject

/** Installation-wide sequence: runtime versions must not reuse a panel logout receipt. */
internal class BackgroundInstallGenerationStore(
    private val backendFactory: () -> EncryptedRecordBackend,
    private val retainedFloor: () -> Long = { 0 },
    private val lockFile: File? = null,
) {
    fun reserve(minimum: Long, operationKey: String, allowNew: Boolean = true): Long? = synchronized(gate) {
        require(minimum in 0..Int.MAX_VALUE.toLong() && operationKey.isNotBlank())
        val file = lockFile ?: return@synchronized reserveLocked(minimum, operationKey, allowNew)
        check(file.parentFile?.let { it.isDirectory || it.mkdirs() } == true)
        RandomAccessFile(file, "rw").use { access ->
            val lock = try { access.channel.tryLock() } catch (_: OverlappingFileLockException) { null }
            checkNotNull(lock) { "background_generation_busy" }.use {
                reserveLocked(minimum, operationKey, allowNew)
            }
        }
    }

    private fun reserveLocked(minimum: Long, key: String, allowNew: Boolean): Long? {
        // Open only while holding the inter-process lock; reload preference caches here.
        val backend = backendFactory()
        val raw = backend.read()
        val retained = try { raw?.let { JSONObject(String(it, Charsets.UTF_8)) } }
            finally { raw?.fill(0) }
        val generation = retained?.let {
            require(it.getInt("format") == 1)
            it.getLong("generation").also { value -> require(value in 1..Int.MAX_VALUE.toLong()) }
        } ?: 0L
        if (retained?.getString("operationKey") == key && generation >= minimum) {
            // A failed SharedPreferences commit can leave this value in memory.
            // Confirm durable storage before acknowledging a writable reservation.
            if (allowNew) persist(backend, generation, key)
            return generation
        }
        if (!allowNew) return null
        val floor = maxOf(generation, minimum, if (retained == null) retainedFloor() else 0L)
        require(floor in 0 until Int.MAX_VALUE.toLong()) { "background_generation_exhausted" }
        val next = floor + 1
        persist(backend, next, key)
        return next
    }

    private fun persist(backend: EncryptedRecordBackend, generation: Long, key: String) {
        val bytes = JSONObject().put("format", 1).put("generation", generation)
            .put("operationKey", key).toString().toByteArray(Charsets.UTF_8)
        try { check(backend.write(bytes)) { "background_generation_persist_failed" } }
        finally { bytes.fill(0) }
    }

    private companion object { val gate = Any() }
}

internal fun backgroundInstallGenerationFloor(records: Sequence<EncryptedRecordBackend>): Long =
    records.fold(0L) { floor, backend ->
        val bytes = backend.read() ?: return@fold floor
        val state = try { BackgroundCredentialEnvelopeCodec.decode(bytes) } finally { bytes.fill(0) }
        maxOf(floor, state.installGeneration ?: 0, state.logoutState?.installGeneration ?: 0)
    }

internal object AndroidInstallGenerations {
    private const val NAME = "nelomai-install-generation"
    // SharedPreferences' ordinary cache is process-local. Reopen with reload under
    // our file lock; all writers of this new record follow the same lock protocol.
    @Suppress("DEPRECATION")
    private fun backend(context: Context, name: String, record: String) = AndroidSecureEnvelopeBackend(
        context, name, record, name, scoped = false,
        preferenceMode = Context.MODE_PRIVATE or Context.MODE_MULTI_PROCESS)

    fun reserve(context: Context, minimum: Long, key: String, allowNew: Boolean = true): Long? =
        BackgroundInstallGenerationStore(
            backendFactory = {
                val storage = backend(context, NAME, "generation-v1")
                object : EncryptedRecordBackend by storage {
                    override fun read(): ByteArray? = storage.read().also { bytes ->
                        val file = File(context.applicationInfo.dataDir, "shared_prefs/$NAME.xml")
                        // Android treats invalid preference XML as an empty map.
                        // An existing ledger must not become a fresh counter.
                        check(bytes != null || (!file.exists() && !File(file.path + ".bak").exists())) {
                            "background_generation_record_missing"
                        }
                    }
                }
            },
            retainedFloor = {
                val directory = File(context.applicationInfo.dataDir, "shared_prefs")
                val files = if (directory.exists()) checkNotNull(directory.listFiles()) else emptyArray()
                val names = files.asSequence()
                    .filter { it.isFile && (it.name.endsWith(".xml") || it.name.endsWith(".xml.bak")) }
                    .map { it.name.removeSuffix(".bak").removeSuffix(".xml") }
                    .filter { it == "nelomai-background-credential" ||
                        it.matches(Regex("runtime\\.(latest|stable)\\.state\\.[A-Za-z0-9.+_-]+\\.nelomai-background-credential")) }
                    .distinct()
                backgroundInstallGenerationFloor(names.map { backend(context, it, "encrypted-envelope-v3") })
            },
            lockFile = File(context.filesDir, "common/background-install-generation.lock"),
        ).reserve(minimum, key, allowNew)
}
