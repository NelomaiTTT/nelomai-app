package ru.nelomai.client

import org.json.JSONObject
import ru.nelomai.runtime.v1.sanitizeLogcatLine
import java.io.File
import java.io.RandomAccessFile
import java.util.UUID

/** Immutable snapshot: the same bytes and UUID are used for every manual retry/export. */
internal class SupportDiagnosticReport(val reportId: String, val payload: String) {
    override fun toString() = "SupportDiagnosticReport($reportId)"
}

/** No owner, preferences, manifests, credentials, directory enumeration, or log journal locks. */
internal class SupportDiagnosticCollector(
    private val files: File,
    private val noBackup: File,
    private val platformVersion: String?,
) {
    fun collect(supportCode: String): SupportDiagnosticReport {
        val deadline = System.nanoTime() + 3_000_000_000L
        val directories = listOf(
            "runtime/latest/state/0.3.2/diagnostics",
            "runtime/stable/state/0.2.20/diagnostics",
            // Legacy Android releases used the unversioned diagnostics directory.
            "diagnostics",
        )
        fun logs(names: List<String>, maximum: Int): String = buildString {
            // Reserve space for EVERY source, including its label. Never let an older
            // namespace/rotated file consume the budget of the current failing log.
            val sectionLimit = maximum / (directories.size * names.size)
            for (directory in directories) for (name in names) {
                val label = "[$directory/$name; source only, active runtime unavailable]\n"
                val limit = sectionLimit - label.toByteArray(Charsets.UTF_8).size - 1
                append(label)
                append(boundedUtf8(readLog(files, "$directory/$name", deadline, supportCode, limit), limit))
                append('\n')
            }
        }
        val application = logs(listOf("android-startup.jsonl", "application.previous.jsonl", "application.jsonl", "auth-refresh.previous.jsonl", "auth-refresh.jsonl"), 96 * 1024)
        val helper = logs(listOf("android-tunnel.previous.jsonl", "android-tunnel.jsonl"), 64 * 1024)
        val logcat = buildString {
            for (name in listOf("logcat.previous.log", "logcat.log")) {
                val label = "[persistent.$name]\n"
                val limit = 48 * 1024 - label.toByteArray(Charsets.UTF_8).size - 1
                append(label)
                append(boundedUtf8(readLog(noBackup, "diagnostics/logcat/$name", deadline, supportCode, limit), limit))
                append('\n')
            }
        }
        val id = UUID.randomUUID().toString()
        val payload = JSONObject()
            .put("report_id", id)
            .put("trigger", "manual")
            .put("generated_at_unix", System.currentTimeMillis() / 1000L)
            .put("app_version", "0.3.2")
            .put("platform_version", platformVersion ?: JSONObject.NULL)
            .put("architecture", "aarch64")
            .put("application_log", application)
            .put("helper_log", helper)
            .put("logcat_log", logcat)
            .toString()
        check(payload.toByteArray(Charsets.UTF_8).size <= 768 * 1024)
        return SupportDiagnosticReport(id, payload)
    }

    private fun readLog(root: File, relative: String, deadline: Long, code: String, limit: Int = 16 * 1024): String {
        if (Thread.currentThread().isInterrupted) return "[unavailable: collection_cancelled]"
        if (System.nanoTime() >= deadline) return "[unavailable: collection_timeout]"
        return try {
            val base = root.canonicalFile
            val file = File(base, relative)
            // Reject redirected ancestors as well as a symlink at the final filename.
            if (file.canonicalFile != file.absoluteFile || !file.isFile) return "[unavailable: log_missing_or_unsafe]"
            RandomAccessFile(file, "r").use { input ->
                val length = input.length()
                val count = minOf(length, limit.toLong()).toInt()
                input.seek(length - count)
                val bytes = ByteArray(count)
                input.readFully(bytes)
                // A partial first record can hide its sensitive field name; drop the whole record.
                val start = if (length > count) bytes.indexOf('\n'.code.toByte()).let { if (it < 0) count else it + 1 } else 0
                val value = String(bytes, start, count - start, Charsets.UTF_8)
                val sanitized = value.lineSequence().joinToString("\n") { sanitizeSupportLine(it, code) }
                if (sanitized.isBlank()) "[unavailable: empty_or_truncated_log]" else sanitized
            }
        } catch (_: Exception) { "[unavailable: log_read_failed]" }
    }
}

private val supportSensitiveField = Regex("""(?i)(?:password|passwd|pwd|authorization|cookie|token|secret|install(?:ation)?[_-]?id|(?:private|public|preshared)[_-]?key|wg[_-]?key|psk|support[_-]?code|diagnostics[_-]?code|X-Nelomai-Diagnostics-Code)[\\"']*\s*[:=]""")

internal fun sanitizeSupportLine(line: String, supportCode: String): String {
    val field = supportSensitiveField.find(line)
    val safe = if (field != null) line.take(field.range.first) + "[sensitive fields redacted]" else line
    return sanitizeLogcatLine(if (supportCode.isEmpty()) safe else safe.replace(supportCode, "[support code redacted]"))
}

private fun boundedUtf8(value: String, maximum: Int): String {
    val bytes = value.toByteArray(Charsets.UTF_8)
    if (bytes.size <= maximum) return value
    val marker = "[older records truncated]\n"
    val start = bytes.size - (maximum - marker.toByteArray(Charsets.UTF_8).size)
    // Sanitizing a short sensitive field may expand it. Keep complete recent
    // records even in that case; never create an unlabelled partial first record.
    val newline = (start until bytes.size).firstOrNull { bytes[it] == '\n'.code.toByte() }
        ?: return marker
    return marker + String(bytes, newline + 1, bytes.size - newline - 1, Charsets.UTF_8)
}
