package ru.nelomai.runtime.v1

import android.content.Context
import java.io.File
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.util.concurrent.atomic.AtomicBoolean

private val sensitiveLogcatField = Regex("""(?i)(?:authorization|cookie|(?:access|refresh|install)[_-]?(?:token|secret)|password|private[_-]?key|preshared[_-]?key|client[_-]?secret)[\\"']*\s*[:=]""")
private val logcatAuthorization = Regex("(?i)\\b(?:bearer|basic)\\s+\\S+")
private val logcatUrl = Regex("(?i)https?://[^\\s\"'<>]+")
private val logcatJwt = Regex("\\beyJ[A-Za-z0-9_-]+(?:\\.[A-Za-z0-9_-]+){1,2}")
private val logcatKeyMaterial = Regex("(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{40,}={0,2}(?![A-Za-z0-9+/_=-])")
private val logcatPriority = Regex("""^\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+\d+\s+\d+\s+([VDIWEFA])\s""")
private fun ordinaryLogcatLine(line: String): Boolean =
    logcatPriority.find(line)?.groupValues?.get(1) in listOf("I", "W", "E", "F", "A")

/** Deliberately redact before persistence, not only before upload. */
fun sanitizeLogcatLine(line: String): String {
    val match = sensitiveLogcatField.find(line)
    var value = if (match != null) line.take(match.range.first) + "[sensitive fields redacted]" else line
    value = value.replace(logcatAuthorization, "[authorization redacted]")
    value = value.replace(logcatUrl, "[url redacted]")
    value = value.replace(logcatJwt, "[token redacted]")
    value = value.replace(logcatKeyMaterial, "[key redacted]")
    return value.filter { it == '\t' || it >= ' ' }.replace('\u007f', ' ')
}

/** Single writer, two segments. A short separate lock also protects snapshots during rotation. */
class LogcatJournal(private val root: File, private val segmentBytes: Int = 1024 * 1024) {
    init { require(segmentBytes in 32..1024 * 1024); check(root.mkdirs() || root.isDirectory) }
    fun append(line: String) = guarded(root) {
        val safe = sanitizeLogcatLine(line)
        if (safe.isBlank()) return@guarded
        val current = File(root, "logcat.log")
        val bytes = (utf8Prefix(safe, segmentBytes - 1) + "\n").toByteArray(Charsets.UTF_8)
        if (current.length() + bytes.size > segmentBytes) {
            val previous = File(root, "logcat.previous.log")
            check(!previous.exists() || previous.delete())
            check(!current.exists() || current.renameTo(previous))
        }
        FileOutputStream(current, true).use { it.write(bytes) }
    }

    companion object {
        private val localGate = Any()
        private fun <T> guarded(root: File, action: () -> T): T = synchronized(localGate) {
            RandomAccessFile(File(root, "journal.lock"), "rw").use { file ->
                file.channel.lock().use { action() }
            }
        }
        private fun utf8Prefix(text: String, budget: Int): String {
            val bytes = text.toByteArray(Charsets.UTF_8)
            if (bytes.size <= budget) return text
            var end = budget
            while (end > 0 && bytes[end].toInt() and 0xc0 == 0x80) end--
            return String(bytes, 0, end, Charsets.UTF_8)
        }
        fun snapshot(root: File, maximum: Int = 2 * 1024 * 1024): String {
            require(maximum in 1..2 * 1024 * 1024)
            if (!root.isDirectory) return ""
            return guarded(root) {
                val current = tail(File(root, "logcat.log"), maximum)
                val previous = tail(File(root, "logcat.previous.log"), maximum - current.toByteArray().size)
                previous + current
            }
        }
        private fun tail(file: File, limit: Int): String {
            if (!file.isFile || limit <= 0) return ""
            return RandomAccessFile(file, "r").use { input ->
                val count = minOf(input.length(), limit.toLong()).toInt()
                input.seek(input.length() - count)
                val bytes = ByteArray(count)
                input.readFully(bytes)
                var start = 0
                while (start < count && bytes[start].toInt() and 0xc0 == 0x80) start++
                String(bytes, start, count - start, Charsets.UTF_8)
            }
        }
    }
}

/** Per-process capture policy; no preference or token survives an owner restart. */
class LogcatCapture(private val journal: LogcatJournal, private val nowMs: () -> Long) {
    data class Status(val active: Boolean, val remainingMillis: Long, val recordedBytes: Long)
    private var startedAt: Long? = null
    private var recordedBytes = 0L

    @Synchronized fun status(): Status {
        val elapsed = startedAt?.let { nowMs() - it }
        if (elapsed != null && (elapsed < 0 || elapsed >= 15 * 60 * 1000L)) startedAt = null
        return Status(startedAt != null, if (startedAt != null) 900_000L - (elapsed ?: 0) else 0, recordedBytes)
    }
    @Synchronized fun enableVerbose(): Boolean {
        if (status().active) return false
        startedAt = nowMs()
        recordedBytes = 0
        return true
    }
    @Synchronized fun stopVerbose() { startedAt = null }
    @Synchronized fun append(line: String) {
        val safe = sanitizeLogcatLine(line)
        if (safe.isBlank()) return
        val ordinary = ordinaryLogcatLine(safe)
        val bytes = safe.toByteArray(Charsets.UTF_8).size.toLong() + 1
        var verbose = status().active
        if (verbose && bytes > 2 * 1024 * 1024L - recordedBytes) {
            stopVerbose()
            verbose = false
        }
        if (!verbose && !ordinary) return
        // Redact before persistence; rotation never resets the session budget.
        journal.append(safe)
        if (verbose) {
            recordedBytes += bytes
            if (recordedBytes >= 2 * 1024 * 1024L) stopVerbose()
        }
    }
}

object PersistentLogcat {
    private val started = AtomicBoolean(false)
    @Volatile private var capture: LogcatCapture? = null
    private fun directory(files: File) = File(files, "diagnostics/logcat")

    fun verboseStatus(): LogcatCapture.Status = capture?.status() ?: LogcatCapture.Status(false, 0, 0)
    fun enableVerbose(): Boolean = capture?.enableVerbose() ?: false
    fun stopVerbose() { capture?.stopVerbose() }

    // Existing automatic-upload callers (including the immutable stable runtime)
    // get ordinary records only. Detailed capture requires explicit manual export.
    @JvmStatic fun snapshot(noBackupPath: String): String =
        manualSnapshot(noBackupPath).lineSequence().filter(::ordinaryLogcatLine).joinToString("\n")

    @JvmStatic fun manualSnapshot(noBackupPath: String): String =
        runCatching { LogcatJournal.snapshot(directory(File(noBackupPath))) }.getOrDefault("")

    internal fun command(sdk: Int, uid: Int): List<String> = buildList {
        add("/system/bin/logcat")
        // --uid arrived in Android 12. Older versions still restrict an
        // unprivileged app to its own UID; we never request READ_LOGS.
        if (sdk >= 31) add("--uid=$uid")
        addAll(listOf("-v", "threadtime", "-T", "100", "*:V"))
    }

    internal fun collectInProcess(processName: String?, ownerProcessName: String, collect: () -> Unit) {
        if (processName == ownerProcessName && ownerProcessName.isNotBlank()) collect()
    }

    private fun currentProcessName(): String? = runCatching {
        if (android.os.Build.VERSION.SDK_INT >= 28) android.app.Application.getProcessName()
        else File("/proc/self/cmdline").inputStream().use { input ->
            val bytes = ByteArray(256)
            val count = input.read(bytes)
            if (count <= 0) null else String(bytes, 0, count, Charsets.UTF_8).substringBefore('\u0000')
        }
    }.getOrNull()

    fun start(context: Context) {
        if (!started.compareAndSet(false, true)) return
        try {
            launch(context)
        } catch (_: Exception) {
            started.set(false)
        }
    }

    private fun launch(context: Context) {
        Thread({
            try {
                // UI and VPN already bind to the broker. Collect only there:
                // permanent cross-process lock waiters exempt their owner from
                // Android's cached-app freezer, keeping an idle runtime active.
                collectInProcess(currentProcessName(), context.applicationInfo.processName) {
                    val root = directory(context.noBackupFilesDir)
                    check(root.mkdirs() || root.isDirectory)
                    val process = ProcessBuilder(command(android.os.Build.VERSION.SDK_INT, android.os.Process.myUid()))
                        .redirectErrorStream(true).start()
                    try {
                        val writer = LogcatCapture(LogcatJournal(root), android.os.SystemClock::elapsedRealtime)
                        capture = writer
                        process.inputStream.bufferedReader().use { input ->
                            // Android bounds individual log records. Also cap
                            // our line accumulator rather than using readLine().
                            val line = StringBuilder()
                            var truncated = false
                            while (true) {
                                val character = input.read()
                                if (character < 0) break
                                if (character == '\n'.code) {
                                    writer.append(if (truncated) "[oversized logcat record omitted]" else line.toString())
                                    line.setLength(0); truncated = false
                                } else if (line.length < 16 * 1024) line.append(character.toChar())
                                else truncated = true
                            }
                        }
                    } finally { capture?.stopVerbose(); capture = null; process.destroy() }
                }
            } catch (_: Exception) {
                // Diagnostics must never prevent startup, login, or tunnel stop.
            } finally { started.set(false) }
        }, "nelomai-logcat").apply { isDaemon = true }.start()
    }
}
