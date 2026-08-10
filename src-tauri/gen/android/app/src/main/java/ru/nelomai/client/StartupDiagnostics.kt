package ru.nelomai.client

import android.app.ActivityManager
import android.app.ApplicationExitInfo
import android.content.Context
import android.os.Build
import android.os.SystemClock
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream

internal object StartupDiagnostics {
  private const val MAX_LOG_BYTES = 64 * 1024L
  private const val DIRECTORY = "diagnostics"
  private const val FILE_NAME = "android-startup.jsonl"
  private const val FRONTEND_READY_MARKER = "android-frontend-ready"
  private const val EXIT_PREFERENCES = "nelomai-startup-exit-diagnostics"
  private const val LAST_EXIT_TIMESTAMP = "last-exit-timestamp"
  private const val MAX_EXIT_RECORDS = 3
  private val writeLock = Any()
  private val processStartedAtMillis = SystemClock.elapsedRealtime()
  private val processStartedAtUnixMillis = System.currentTimeMillis()
  @Volatile private var launchStartedAtUnixMillis = System.currentTimeMillis()

  fun beginLaunch(context: Context) {
    launchStartedAtUnixMillis = System.currentTimeMillis()
    recordPreviousProcessExits(context)
    runCatching {
      File(context.applicationInfo.dataDir, "$DIRECTORY/$FRONTEND_READY_MARKER").delete()
    }
    record(context, "startup.android.activity_create_begin")
  }

  fun frontendReady(context: Context): Boolean {
    val marker = File(context.applicationInfo.dataDir, "$DIRECTORY/$FRONTEND_READY_MARKER")
    return marker.isFile && marker.lastModified() >= launchStartedAtUnixMillis
  }

  fun record(context: Context, kind: String) = record(context, kind, emptyMap())

  private fun record(context: Context, kind: String, details: Map<String, Any?>) {
    runCatching {
      val directory = File(context.applicationInfo.dataDir, DIRECTORY)
      if (!directory.exists() && !directory.mkdirs()) return
      val file = File(directory, FILE_NAME)
      val record = JSONObject()
        .put("timestamp_unix", System.currentTimeMillis() / 1_000L)
        .put("elapsed_ms", SystemClock.elapsedRealtime() - processStartedAtMillis)
        .put("kind", kind)
        .put("operation_id", JSONObject.NULL)
        .put("request_id", JSONObject.NULL)
        .put("code", JSONObject.NULL)
      details.forEach { (key, value) ->
        if (value != null) record.put(key, value)
      }
      val encoded = record.toString() + "\n"
      synchronized(writeLock) {
        if (file.length() >= MAX_LOG_BYTES) {
          FileOutputStream(file, false).use { }
        }
        FileOutputStream(file, true).bufferedWriter().use { writer ->
          writer.write(encoded)
        }
      }
    }
  }

  private fun recordPreviousProcessExits(context: Context) {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return
    runCatching {
      val preferences = context.getSharedPreferences(EXIT_PREFERENCES, Context.MODE_PRIVATE)
      val lastRecordedTimestamp = preferences.getLong(LAST_EXIT_TIMESTAMP, 0)
      val activityManager = context.getSystemService(ActivityManager::class.java)
      val exits = activityManager
        .getHistoricalProcessExitReasons(context.packageName, 0, 10)
        .asSequence()
        .filter { it.timestamp > lastRecordedTimestamp }
        .filter { it.timestamp < processStartedAtUnixMillis }
        .sortedByDescending { it.timestamp }
        .take(MAX_EXIT_RECORDS)
        .sortedBy { it.timestamp }
        .toList()
      exits.forEach { exit ->
        record(
          context,
          "startup.android.previous_process_exit",
          mapOf(
            "exit_timestamp_unix" to exit.timestamp / 1_000L,
            "process" to if (exit.processName.endsWith(":vpn")) "vpn" else "ui",
            "exit_reason" to startupExitReason(exit.reason),
            "exit_status" to exit.status,
            "importance" to exit.importance,
            "pss_bytes" to exit.pss.saturatingKilobytesToBytes(),
            "rss_bytes" to exit.rss.saturatingKilobytesToBytes(),
          ),
        )
      }
      exits.maxOfOrNull { it.timestamp }?.let { timestamp ->
        preferences.edit().putLong(LAST_EXIT_TIMESTAMP, timestamp).commit()
      }
    }
  }
}

internal fun startupExitReason(reason: Int): String = when (reason) {
  ApplicationExitInfo.REASON_EXIT_SELF -> "exit_self"
  ApplicationExitInfo.REASON_SIGNALED -> "signaled"
  ApplicationExitInfo.REASON_LOW_MEMORY -> "low_memory"
  ApplicationExitInfo.REASON_CRASH -> "crash"
  ApplicationExitInfo.REASON_CRASH_NATIVE -> "native_crash"
  ApplicationExitInfo.REASON_ANR -> "anr"
  ApplicationExitInfo.REASON_INITIALIZATION_FAILURE -> "initialization_failure"
  ApplicationExitInfo.REASON_PERMISSION_CHANGE -> "permission_change"
  ApplicationExitInfo.REASON_EXCESSIVE_RESOURCE_USAGE -> "excessive_resource_usage"
  ApplicationExitInfo.REASON_USER_REQUESTED -> "user_requested"
  ApplicationExitInfo.REASON_USER_STOPPED -> "user_stopped"
  ApplicationExitInfo.REASON_DEPENDENCY_DIED -> "dependency_died"
  ApplicationExitInfo.REASON_OTHER -> "other"
  ApplicationExitInfo.REASON_FREEZER -> "freezer"
  ApplicationExitInfo.REASON_PACKAGE_STATE_CHANGE -> "package_state_change"
  ApplicationExitInfo.REASON_PACKAGE_UPDATED -> "package_updated"
  else -> "unknown_$reason"
}

private fun Long.saturatingKilobytesToBytes(): Long? = when {
  this <= 0 -> null
  this > Long.MAX_VALUE / 1_024L -> Long.MAX_VALUE
  else -> this * 1_024L
}
