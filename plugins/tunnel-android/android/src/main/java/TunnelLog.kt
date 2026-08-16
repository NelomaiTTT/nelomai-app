package ru.nelomai.tunnel

import android.content.Context
import android.util.Log
import java.io.File
import java.time.Instant
import org.json.JSONObject

private const val TUNNEL_LOG_TAG = "NelomaiTunnel"
private const val LOG_DIRECTORY = "diagnostics"
private const val LOG_FILE = "android-tunnel.jsonl"
private const val LOG_PREVIOUS_FILE = "android-tunnel.previous.jsonl"
private const val INCIDENT_LOG_FILE = "android-network-incidents.jsonl"
private const val INCIDENT_LOG_PREVIOUS_FILE = "android-network-incidents.previous.jsonl"
private const val LOG_ROTATE_BYTES = 128 * 1024L
private const val INCIDENT_LOG_ROTATE_BYTES = 96 * 1024L

internal object TunnelLog {
    private val lock = Any()
    @Volatile private var directory: File? = null

    fun initialize(context: Context) {
        directory = File(context.applicationInfo.dataDir, LOG_DIRECTORY).apply { mkdirs() }
    }

    fun info(event: String, details: Map<String, Any?> = emptyMap()) {
        Log.i(TUNNEL_LOG_TAG, renderLogcat(event, details))
        append("info", event, details)
    }

    fun warning(event: String, code: String? = null, error: Throwable? = null) {
        val details = buildMap<String, Any?> {
            put("code", code)
            error?.javaClass?.simpleName?.let { put("error_type", it) }
        }
        Log.w(TUNNEL_LOG_TAG, renderLogcat(event, details))
        append("warning", event, details)
    }

    fun incident(event: String, details: Map<String, Any?> = emptyMap()) {
        Log.i(TUNNEL_LOG_TAG, renderLogcat(event, details))
        appendLine(
            level = "info",
            event = event,
            details = details,
            fileName = INCIDENT_LOG_FILE,
            previousFileName = INCIDENT_LOG_PREVIOUS_FILE,
            rotateBytes = INCIDENT_LOG_ROTATE_BYTES,
        )
    }

    private fun append(level: String, event: String, details: Map<String, Any?>) {
        appendLine(
            level = level,
            event = event,
            details = details,
            fileName = LOG_FILE,
            previousFileName = LOG_PREVIOUS_FILE,
            rotateBytes = LOG_ROTATE_BYTES,
        )
    }

    private fun appendLine(
        level: String,
        event: String,
        details: Map<String, Any?>,
        fileName: String,
        previousFileName: String,
        rotateBytes: Long,
    ) {
        val root = directory ?: return
        val line = JSONObject().apply {
            put("timestamp", Instant.now().toString())
            put("level", level)
            put("event", event)
            details.forEach { (key, value) -> if (value != null) put(key, value) }
        }.toString() + "\n"
        synchronized(lock) {
            runCatching {
                val current = File(root, fileName)
                if (current.exists() && current.length() + line.toByteArray().size > rotateBytes) {
                    File(root, previousFileName).delete()
                    current.renameTo(File(root, previousFileName))
                }
                current.appendText(line, Charsets.UTF_8)
            }
        }
    }

    private fun renderLogcat(event: String, details: Map<String, Any?>): String =
        buildString {
            append(event)
            details.forEach { (key, value) -> if (value != null) append(" $key=$value") }
        }
}
