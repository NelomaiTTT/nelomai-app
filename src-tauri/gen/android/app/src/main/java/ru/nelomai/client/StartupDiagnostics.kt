package ru.nelomai.client

import android.content.Context
import android.os.SystemClock
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream

internal object StartupDiagnostics {
  private const val MAX_LOG_BYTES = 64 * 1024L
  private const val DIRECTORY = "diagnostics"
  private const val FILE_NAME = "android-startup.jsonl"
  private const val FRONTEND_READY_MARKER = "android-frontend-ready"
  private val writeLock = Any()
  private val processStartedAtMillis = SystemClock.elapsedRealtime()
  @Volatile private var launchStartedAtUnixMillis = System.currentTimeMillis()

  fun beginLaunch(context: Context) {
    launchStartedAtUnixMillis = System.currentTimeMillis()
    runCatching {
      File(context.applicationInfo.dataDir, "$DIRECTORY/$FRONTEND_READY_MARKER").delete()
    }
    record(context, "startup.android.activity_create_begin")
  }

  fun frontendReady(context: Context): Boolean {
    val marker = File(context.applicationInfo.dataDir, "$DIRECTORY/$FRONTEND_READY_MARKER")
    return marker.isFile && marker.lastModified() >= launchStartedAtUnixMillis
  }

  fun record(context: Context, kind: String) {
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
        .toString() + "\n"
      synchronized(writeLock) {
        if (file.length() >= MAX_LOG_BYTES) {
          FileOutputStream(file, false).use { }
        }
        FileOutputStream(file, true).bufferedWriter().use { writer ->
          writer.write(record)
        }
      }
    }
  }
}
