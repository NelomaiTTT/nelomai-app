package ru.nelomai.tunnel

import android.app.ActivityManager
import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import android.os.Build
import android.os.Process
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream
import org.json.JSONArray
import org.json.JSONObject

private const val AUTOMATIC_DIAGNOSTICS_PREFERENCES = "nelomai-automatic-diagnostics"
private const val AUTOMATIC_DIAGNOSTICS_DIRECTORY = "diagnostics/automatic"
private const val PENDING_DIRECTORY = "pending"
private const val SENT_DIRECTORY = "sent"
private const val REPORT_SUFFIX = ".json.gz"
private const val CHECKPOINT_INTERVAL_SECONDS = 6 * 60 * 60L
private const val SUCCESS_UPLOAD_SPACING_SECONDS = 65L
private const val MAX_SENT_REPORTS = 3
private const val MAX_APPLICATION_LOG_BYTES = 320 * 1024
private const val MAX_HELPER_LOG_BYTES = 64 * 1024
private const val MAX_REPORT_BYTES = 512 * 1024
private const val AUTOMATIC_DIAGNOSTICS_JOB_ID = 0x4e444941
private val RETRY_DELAYS_SECONDS = longArrayOf(5 * 60L, 30 * 60L, 2 * 60 * 60L, 6 * 60 * 60L)

private const val KEY_SESSION_ID = "session_id"
private const val KEY_SESSION_SEQUENCE = "session_sequence"
private const val KEY_INTERVAL_STARTED_AT = "interval_started_at"
private const val KEY_SESSION_RUNNING = "session_running"
private const val KEY_SESSION_DEVICE_ID = "session_device_id"
private const val KEY_STOPPED_SESSION_PENDING = "stopped_session_pending"
private const val KEY_PENDING_SEAL = "pending_seal"
private const val KEY_RETRY_ATTEMPT = "retry_attempt"
private const val KEY_NEXT_UPLOAD_AT = "next_upload_at"
private const val KEY_LAST_ATTEMPTED_REPORT = "last_attempted_report"
private const val UNSCOPED_REPORT = "unscoped"

private data class PendingSeal(
    val reportId: String,
    val trigger: String,
    val sessionId: String,
    val deviceId: String?,
    val sequence: Int,
    val startedAt: Long,
    val endedAt: Long,
    val tunnelRunning: Boolean,
) {
    fun toJson(): String = JSONObject().apply {
        put("report_id", reportId)
        put("trigger", trigger)
        put("session_id", sessionId)
        put("device_id", deviceId ?: JSONObject.NULL)
        put("sequence", sequence)
        put("started_at", startedAt)
        put("ended_at", endedAt)
        put("tunnel_running", tunnelRunning)
    }.toString()
}

internal object AutomaticDiagnostics {
    private val gate = Any()
    private val uploadQueued = AtomicBoolean(false)
    private val systemJobRunning = AtomicBoolean(false)
    private val executor = Executors.newSingleThreadScheduledExecutor { task ->
        Thread(task, "nelomai-automatic-diagnostics").apply { isDaemon = true }
    }
    private var checkpointFuture: ScheduledFuture<*>? = null
    private var uploadFuture: ScheduledFuture<*>? = null

    fun initialize(context: Context) {
        val applicationContext = context.applicationContext
        synchronized(gate) {
            ensureDirectories(applicationContext)
            val preferences = preferences(applicationContext)
            if (preferences.getBoolean(KEY_SESSION_RUNNING, false)) {
                markStoppedSessionPending(applicationContext)
                if (!sealCurrentInterval(
                        applicationContext,
                        "tunnel_stopped",
                        tunnelRunning = false,
                    )
                ) {
                    scheduleRetry(applicationContext, "automatic_diagnostics_report_queue_failed")
                }
            }
            pruneSent(applicationContext)
            scheduleUploadLocked(applicationContext, requestedDelaySeconds = 0)
        }
    }

    fun onTunnelStarted(context: Context) {
        val applicationContext = context.applicationContext
        synchronized(gate) {
            val preferences = preferences(applicationContext)
            if (preferences.getBoolean(KEY_SESSION_RUNNING, false)) {
                markStoppedSessionPending(applicationContext)
                check(
                    sealCurrentInterval(
                        applicationContext,
                        "tunnel_stopped",
                        tunnelRunning = false,
                    ),
                ) { "automatic_diagnostics_previous_session_not_saved" }
            }
            val now = nowUnix()
            val deviceId = BackgroundCredentialStore.load(applicationContext)?.deviceId
            check(
                preferences.edit()
                    .putString(KEY_SESSION_ID, UUID.randomUUID().toString())
                    .putInt(KEY_SESSION_SEQUENCE, 0)
                    .putLong(KEY_INTERVAL_STARTED_AT, now)
                    .putBoolean(KEY_SESSION_RUNNING, true)
                    .putString(KEY_SESSION_DEVICE_ID, deviceId)
                    .remove(KEY_STOPPED_SESSION_PENDING)
                    .remove(KEY_PENDING_SEAL)
                    .commit(),
            ) { "automatic_diagnostics_session_write_failed" }
            TunnelLog.info("diagnostics.session_started")
            scheduleCheckpointLocked(applicationContext, CHECKPOINT_INTERVAL_SECONDS)
            scheduleUploadLocked(applicationContext, requestedDelaySeconds = 0)
        }
    }

    fun onTunnelStopped(context: Context) {
        val applicationContext = context.applicationContext
        synchronized(gate) {
            checkpointFuture?.cancel(false)
            checkpointFuture = null
            val preferences = preferences(applicationContext)
            if (preferences.getBoolean(KEY_SESSION_RUNNING, false)) {
                markStoppedSessionPending(applicationContext)
                if (!sealCurrentInterval(applicationContext, "tunnel_stopped", tunnelRunning = false)) {
                    scheduleRetry(applicationContext, "automatic_diagnostics_report_queue_failed")
                    return
                }
            }
            scheduleUploadLocked(applicationContext, requestedDelaySeconds = 0)
        }
    }

    fun credentialUpdated(context: Context) {
        synchronized(gate) {
            preferences(context).edit()
                .putInt(KEY_RETRY_ATTEMPT, 0)
                .putLong(KEY_NEXT_UPLOAD_AT, 0)
                .apply()
            scheduleUploadLocked(context.applicationContext, requestedDelaySeconds = 0)
        }
    }

    fun runScheduledUpload(context: Context, onComplete: () -> Unit) {
        val applicationContext = context.applicationContext
        TunnelLog.initialize(applicationContext)
        synchronized(gate) {
            ensureDirectories(applicationContext)
            if (
                preferences(applicationContext).getBoolean(KEY_SESSION_RUNNING, false)
                && TunnelRuntime.state() != SessionState.RUNNING
            ) {
                markStoppedSessionPending(applicationContext)
            }
        }
        if (!systemJobRunning.compareAndSet(false, true)) {
            onComplete()
            return
        }
        executor.execute {
            var performed = false
            try {
                performed = processNext(applicationContext)
            } finally {
                systemJobRunning.set(false)
                try {
                    onComplete()
                } finally {
                    synchronized(gate) {
                        if (performed) {
                            scheduleSystemUploadFromPersistedState(applicationContext)
                        } else {
                            scheduleSystemUpload(applicationContext, 60)
                        }
                    }
                }
            }
        }
    }

    private fun checkpoint(context: Context) {
        synchronized(gate) {
            if (!preferences(context).getBoolean(KEY_SESSION_RUNNING, false)) return
            if (sealCurrentInterval(context, "six_hour_checkpoint", tunnelRunning = true)) {
                scheduleCheckpointLocked(context, CHECKPOINT_INTERVAL_SECONDS)
                scheduleUploadLocked(context, requestedDelaySeconds = 0)
            } else {
                scheduleCheckpointLocked(context, RETRY_DELAYS_SECONDS.first())
            }
        }
    }

    private fun sealCurrentInterval(
        context: Context,
        trigger: String,
        tunnelRunning: Boolean,
    ): Boolean {
        val preferences = preferences(context)
        val sessionId = preferences.getString(KEY_SESSION_ID, null) ?: return false
        val startedAt = preferences.getLong(KEY_INTERVAL_STARTED_AT, 0).takeIf { it > 0 }
            ?: return false
        val sequence = preferences.getInt(KEY_SESSION_SEQUENCE, 0) + 1
        return try {
            var seal = loadPendingSeal(preferences)
                ?.takeIf { it.sessionId == sessionId && it.sequence == sequence }
            if (seal == null) {
                preferences.edit().remove(KEY_PENDING_SEAL).commit()
                seal = PendingSeal(
                    reportId = UUID.randomUUID().toString(),
                    trigger = trigger,
                    sessionId = sessionId,
                    deviceId = preferences.getString(KEY_SESSION_DEVICE_ID, null),
                    sequence = sequence,
                    startedAt = startedAt,
                    endedAt = maxOf(nowUnix(), startedAt),
                    tunnelRunning = tunnelRunning,
                )
                val markerSaved = preferences.edit()
                    .putString(KEY_PENDING_SEAL, seal.toJson())
                    .commit()
                scheduleSystemUpload(context, 0)
                check(markerSaved) { "automatic_diagnostics_seal_write_failed" }
                TunnelLog.info(
                    "diagnostics.report_queued",
                    mapOf(
                        "report_id" to seal.reportId,
                        "trigger" to seal.trigger,
                        "session_id" to seal.sessionId,
                        "sequence" to seal.sequence,
                    ),
                )
            }
            val finalFile = pendingReportFile(context, seal)
            if (!finalFile.isFile) {
                val payload = buildReport(
                    context,
                    seal.reportId,
                    seal.trigger,
                    seal.sessionId,
                    seal.sequence,
                    seal.startedAt,
                    seal.endedAt,
                    seal.tunnelRunning,
                )
                writePendingReport(finalFile, payload)
            }
            val editor = preferences.edit()
                .putInt(KEY_SESSION_SEQUENCE, seal.sequence)
                .remove(KEY_PENDING_SEAL)
            if (seal.tunnelRunning) {
                editor.putLong(KEY_INTERVAL_STARTED_AT, seal.endedAt)
            } else {
                editor.remove(KEY_SESSION_ID)
                    .remove(KEY_SESSION_SEQUENCE)
                    .remove(KEY_INTERVAL_STARTED_AT)
                    .remove(KEY_SESSION_DEVICE_ID)
                    .remove(KEY_STOPPED_SESSION_PENDING)
                    .putBoolean(KEY_SESSION_RUNNING, false)
            }
            check(editor.commit()) { "automatic_diagnostics_session_write_failed" }
            if (
                (seal.trigger != trigger || seal.tunnelRunning != tunnelRunning) &&
                preferences.getBoolean(KEY_SESSION_RUNNING, false)
            ) {
                sealCurrentInterval(context, trigger, tunnelRunning)
            } else {
                true
            }
        } catch (error: Throwable) {
            TunnelLog.warning("diagnostics.report_queue_failed", error = error)
            false
        }
    }

    private fun buildReport(
        context: Context,
        reportId: String,
        trigger: String,
        sessionId: String,
        sequence: Int,
        startedAt: Long,
        endedAt: Long,
        tunnelRunning: Boolean,
    ): JSONObject {
        val processes = androidProcessMemory(context)
        logMemorySnapshot(context.packageName, processes)
        return JSONObject().apply {
            put("report_id", reportId)
            put("trigger", trigger)
            put("tunnel_session_id", sessionId)
            put("sequence", sequence)
            put("interval_started_at_unix", startedAt)
            put("interval_ended_at_unix", endedAt)
            put("tunnel_running", tunnelRunning)
            put("generated_at_unix", endedAt)
            put("app_version", appVersion(context))
            put("platform_version", Build.VERSION.RELEASE.takeIf(String::isNotBlank))
            put("architecture", Build.SUPPORTED_ABIS.firstOrNull()?.take(32) ?: "unknown")
            put(
                "application_log",
                intervalLog(
                    context,
                    "application",
                    MAX_APPLICATION_LOG_BYTES,
                    startedAt,
                    endedAt,
                ),
            )
            put(
                "helper_log",
                intervalLog(
                    context,
                    "android-tunnel",
                    MAX_HELPER_LOG_BYTES,
                    startedAt,
                    endedAt,
                ),
            )
            put(
                "resource_usage",
                JSONObject().apply {
                    put("measurement_mode", "session_delta")
                    put("session_duration_ms", (endedAt - startedAt).coerceAtLeast(0).times(1000))
                    put("components", resourceComponents(processes))
                },
            )
        }
    }

    private fun writePendingReport(finalFile: File, payload: JSONObject) {
        val directory = requireNotNull(finalFile.parentFile)
        val temporaryFile = File(directory, ".${finalFile.name}.part")
        val encoded = payload.toString().toByteArray(StandardCharsets.UTF_8)
        try {
            check(encoded.size <= MAX_REPORT_BYTES) { "automatic_diagnostics_report_too_large" }
            FileOutputStream(temporaryFile).use { output ->
                val gzip = GZIPOutputStream(output)
                gzip.write(encoded)
                gzip.finish()
                gzip.flush()
                output.fd.sync()
                gzip.close()
            }
            check(temporaryFile.renameTo(finalFile)) { "automatic_diagnostics_report_move_failed" }
        } finally {
            encoded.fill(0)
            temporaryFile.delete()
        }
    }

    private fun pendingReportFile(context: Context, seal: PendingSeal): File = File(
        pendingDirectory(context),
        automaticDiagnosticsPendingReportName(seal.endedAt, seal.deviceId, seal.reportId),
    )

    private fun loadPendingSeal(preferences: android.content.SharedPreferences): PendingSeal? {
        val encoded = preferences.getString(KEY_PENDING_SEAL, null) ?: return null
        return runCatching {
            val payload = JSONObject(encoded)
            val reportId = UUID.fromString(payload.getString("report_id")).toString()
            val sessionId = UUID.fromString(payload.getString("session_id")).toString()
            val trigger = payload.getString("trigger").takeIf {
                it == "tunnel_stopped" || it == "six_hour_checkpoint"
            } ?: error("invalid diagnostics trigger")
            val sequence = payload.getInt("sequence").takeIf { it > 0 }
                ?: error("invalid diagnostics sequence")
            val startedAt = payload.getLong("started_at").takeIf { it > 0 }
                ?: error("invalid diagnostics start")
            val endedAt = payload.getLong("ended_at").takeIf { it >= startedAt }
                ?: error("invalid diagnostics end")
            val deviceId = if (payload.isNull("device_id")) {
                null
            } else {
                UUID.fromString(payload.getString("device_id")).toString()
            }
            PendingSeal(
                reportId = reportId,
                trigger = trigger,
                sessionId = sessionId,
                deviceId = deviceId,
                sequence = sequence,
                startedAt = startedAt,
                endedAt = endedAt,
                tunnelRunning = payload.getBoolean("tunnel_running"),
            )
        }.getOrNull()
    }

    private fun scheduleCheckpointLocked(context: Context, delaySeconds: Long) {
        checkpointFuture?.cancel(false)
        checkpointFuture = executor.schedule(
            { checkpoint(context.applicationContext) },
            delaySeconds.coerceAtLeast(1),
            TimeUnit.SECONDS,
        )
    }

    private fun scheduleUploadLocked(context: Context, requestedDelaySeconds: Long) {
        if (!hasPendingWork(context)) {
            preferences(context).edit()
                .remove(KEY_LAST_ATTEMPTED_REPORT)
                .putInt(KEY_RETRY_ATTEMPT, 0)
                .putLong(KEY_NEXT_UPLOAD_AT, 0)
                .apply()
            if (!systemJobRunning.get()) cancelSystemUpload(context)
            return
        }
        val preferences = preferences(context)
        val persistedDelay = (preferences.getLong(KEY_NEXT_UPLOAD_AT, 0) - nowUnix()).coerceAtLeast(0)
        val delay = maxOf(requestedDelaySeconds, persistedDelay)
        uploadFuture?.cancel(false)
        uploadFuture = executor.schedule(
            { processNext(context.applicationContext) },
            delay,
            TimeUnit.SECONDS,
        )
        scheduleSystemUpload(context, delay)
    }

    private fun processNext(context: Context): Boolean {
        synchronized(gate) {
            val preferences = preferences(context)
            if (!preferences.getBoolean(KEY_SESSION_RUNNING, false)) {
                preferences.edit()
                    .remove(KEY_STOPPED_SESSION_PENDING)
                    .remove(KEY_PENDING_SEAL)
                    .apply()
            } else if (preferences.getBoolean(KEY_STOPPED_SESSION_PENDING, false)) {
                if (!sealCurrentInterval(context, "tunnel_stopped", tunnelRunning = false)) {
                    scheduleRetry(context, "automatic_diagnostics_report_queue_failed")
                    return true
                }
            } else {
                val seal = loadPendingSeal(preferences)
                if (seal == null && preferences.contains(KEY_PENDING_SEAL)) {
                    preferences.edit().remove(KEY_PENDING_SEAL).apply()
                }
                seal?.let {
                    if (!sealCurrentInterval(context, it.trigger, it.tunnelRunning)) {
                        scheduleRetry(context, "automatic_diagnostics_report_queue_failed")
                        return true
                    }
                }
            }
            Unit
        }
        return uploadNext(context)
    }

    private fun uploadNext(context: Context): Boolean {
        if (!uploadQueued.compareAndSet(false, true)) return false
        try {
            val credential = BackgroundCredentialStore.load(context) ?: return true
            val reports = pendingReports(context).filter {
                automaticDiagnosticsPendingReportScope(it.name) == credential.deviceId
            }
            val preferences = preferences(context)
            val reportName = automaticDiagnosticsNextPendingReport(
                reports.map(File::getName),
                preferences.getString(KEY_LAST_ATTEMPTED_REPORT, null),
            ) ?: return true
            val report = reports.first { it.name == reportName }
            check(
                preferences.edit().putString(KEY_LAST_ATTEMPTED_REPORT, report.name).commit(),
            ) { "automatic_diagnostics_attempt_write_failed" }
            val payload = readPendingReport(report)
            val expectedReportId = payload.getString("report_id")
            val response = BackgroundConnectionClient.uploadDiagnostics(credential, payload)
            if (response.getString("report_id") != expectedReportId) {
                throw BackgroundConnectionException("invalid_diagnostics_response")
            }
            markSent(context, report)
            val morePending = pendingReports(context).any {
                automaticDiagnosticsPendingReportScope(it.name) == credential.deviceId
            }
            preferences(context).edit()
                .putInt(KEY_RETRY_ATTEMPT, 0)
                .putLong(
                    KEY_NEXT_UPLOAD_AT,
                    if (morePending) nowUnix() + SUCCESS_UPLOAD_SPACING_SECONDS else 0,
                )
                .apply()
            TunnelLog.info(
                "diagnostics.report_uploaded",
                mapOf("report_id" to expectedReportId),
            )
            synchronized(gate) {
                scheduleUploadLocked(context, SUCCESS_UPLOAD_SPACING_SECONDS)
            }
        } catch (error: Throwable) {
            val code = (error as? BackgroundConnectionException)?.code
                ?: "automatic_diagnostics_upload_failed"
            TunnelLog.warning("diagnostics.report_upload_failed", code, error)
            scheduleRetry(context, code)
        } finally {
            uploadQueued.set(false)
        }
        return true
    }

    private fun scheduleRetry(context: Context, code: String) {
        val preferences = preferences(context)
        val attempt = preferences.getInt(KEY_RETRY_ATTEMPT, 0)
        val delay = automaticDiagnosticsRetryDelaySeconds(attempt)
        preferences.edit()
            .putInt(KEY_RETRY_ATTEMPT, (attempt + 1).coerceAtMost(RETRY_DELAYS_SECONDS.size))
            .putLong(KEY_NEXT_UPLOAD_AT, nowUnix() + delay)
            .apply()
        TunnelLog.info(
            "diagnostics.upload_retry_scheduled",
            mapOf("code" to code, "delay_seconds" to delay),
        )
        synchronized(gate) {
            scheduleUploadLocked(context, delay)
        }
    }

    private fun readPendingReport(file: File): JSONObject =
        GZIPInputStream(FileInputStream(file)).use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(8 * 1024)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                check(output.size() + count <= MAX_REPORT_BYTES) {
                    "automatic_diagnostics_report_too_large"
                }
                output.write(buffer, 0, count)
            }
            JSONObject(output.toString(StandardCharsets.UTF_8.name()))
        }

    private fun markSent(context: Context, report: File) {
        val destination = File(sentDirectory(context), report.name)
        check(report.renameTo(destination)) { "automatic_diagnostics_sent_move_failed" }
        pruneSent(context)
    }

    private fun pruneSent(context: Context) {
        val reports = sentDirectory(context).listFiles()
            .orEmpty()
            .filter { it.isFile && it.name.endsWith(REPORT_SUFFIX) }
        val namesToDelete = automaticDiagnosticsSentReportsToPrune(
            reports.map(File::getName),
        )
        reports.filter { it.name in namesToDelete }.forEach { report ->
            if (!report.delete()) {
                TunnelLog.warning("diagnostics.sent_prune_failed")
            }
        }
    }

    private fun pendingReports(context: Context): List<File> =
        pendingDirectory(context).listFiles()
            .orEmpty()
            .filter { it.isFile && it.name.endsWith(REPORT_SUFFIX) }
            .sortedBy(File::getName)

    private fun hasPendingWork(context: Context): Boolean =
        automaticDiagnosticsHasPendingWork(
            pendingReports(context).map(File::getName),
            preferences(context).getBoolean(KEY_STOPPED_SESSION_PENDING, false),
            preferences(context).contains(KEY_PENDING_SEAL),
            BackgroundCredentialStore.load(context)?.deviceId,
        )

    private fun markStoppedSessionPending(context: Context) {
        val saved = preferences(context).edit()
            .putBoolean(KEY_STOPPED_SESSION_PENDING, true)
            .commit()
        scheduleSystemUpload(context, 0)
        check(saved) { "automatic_diagnostics_session_write_failed" }
    }

    private fun ensureDirectories(context: Context) {
        check(pendingDirectory(context).mkdirs() || pendingDirectory(context).isDirectory)
        check(sentDirectory(context).mkdirs() || sentDirectory(context).isDirectory)
    }

    private fun pendingDirectory(context: Context): File =
        File(context.applicationInfo.dataDir, "$AUTOMATIC_DIAGNOSTICS_DIRECTORY/$PENDING_DIRECTORY")

    private fun sentDirectory(context: Context): File =
        File(context.applicationInfo.dataDir, "$AUTOMATIC_DIAGNOSTICS_DIRECTORY/$SENT_DIRECTORY")

    private fun preferences(context: Context) = context.getSharedPreferences(
        AUTOMATIC_DIAGNOSTICS_PREFERENCES,
        Context.MODE_PRIVATE,
    )

    private fun scheduleSystemUpload(context: Context, delaySeconds: Long) {
        if (systemJobRunning.get()) return
        val delayMillis = delaySeconds.coerceAtLeast(0).let { seconds ->
            if (seconds > Long.MAX_VALUE / 1000L) Long.MAX_VALUE else seconds * 1000L
        }
        val job = JobInfo.Builder(
            AUTOMATIC_DIAGNOSTICS_JOB_ID,
            ComponentName(context, AutomaticDiagnosticsJobService::class.java),
        )
            .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
            .setMinimumLatency(delayMillis)
            .setPersisted(true)
            .build()
        val scheduler = context.getSystemService(JobScheduler::class.java)
        if (scheduler.schedule(job) != JobScheduler.RESULT_SUCCESS) {
            TunnelLog.warning("diagnostics.job_schedule_failed")
        }
    }

    private fun cancelSystemUpload(context: Context) {
        context.getSystemService(JobScheduler::class.java).cancel(AUTOMATIC_DIAGNOSTICS_JOB_ID)
    }

    private fun scheduleSystemUploadFromPersistedState(context: Context) {
        if (!hasPendingWork(context)) {
            cancelSystemUpload(context)
            return
        }
        val delay = (
            preferences(context).getLong(KEY_NEXT_UPLOAD_AT, 0) - nowUnix()
        ).coerceAtLeast(0)
        scheduleSystemUpload(context, delay)
    }
}

class AutomaticDiagnosticsJobService : JobService() {
    override fun onStartJob(parameters: JobParameters): Boolean {
        AutomaticDiagnostics.runScheduledUpload(applicationContext) {
            jobFinished(parameters, false)
        }
        return true
    }

    override fun onStopJob(parameters: JobParameters): Boolean = true
}

internal fun androidProcessMemory(context: Context): JSONArray {
    val activityManager = context.getSystemService(ActivityManager::class.java)
    val packageName = context.packageName
    val processes = activityManager.runningAppProcesses.orEmpty()
        .asSequence()
        .filter { process ->
            process.uid == Process.myUid() &&
                (process.processName == packageName || process.processName.startsWith("$packageName:"))
        }
        .sortedBy { it.processName }
        .take(4)
        .toList()
    if (processes.isEmpty()) {
        val pid = Process.myPid()
        val info = activityManager.getProcessMemoryInfo(intArrayOf(pid)).firstOrNull()
        return JSONArray().apply {
            put(JSONObject().apply {
                put("processId", pid.toLong())
                put("processName", currentProcessName(context).take(192))
                putNullable("currentResidentMemoryBytes", processRssBytes(pid))
                putNullable("currentProportionalMemoryBytes", info?.totalPss?.toLong()?.times(1024L))
                putNullable("currentPrivateDirtyMemoryBytes", info?.totalPrivateDirty?.toLong()?.times(1024L))
            })
        }
    }
    val memory = activityManager.getProcessMemoryInfo(processes.map { it.pid }.toIntArray())
    return JSONArray().apply {
        processes.forEachIndexed { index, process ->
            val info = memory.getOrNull(index)
            put(JSONObject().apply {
                put("processId", process.pid.toLong())
                put("processName", process.processName.take(192))
                putNullable("currentResidentMemoryBytes", processRssBytes(process.pid))
                putNullable("currentProportionalMemoryBytes", info?.totalPss?.toLong()?.times(1024L))
                putNullable("currentPrivateDirtyMemoryBytes", info?.totalPrivateDirty?.toLong()?.times(1024L))
            })
        }
    }
}

private fun resourceComponents(processes: JSONArray): JSONArray {
    val result = JSONArray()
    var resident = 0L
    var proportional = 0L
    var privateDirty = 0L
    var residentFound = false
    var proportionalFound = false
    var privateDirtyFound = false
    for (index in 0 until processes.length()) {
        val process = processes.getJSONObject(index)
        val name = process.getString("processName")
        result.put(JSONObject().apply {
            put("component", if (name.endsWith(":vpn")) "android_vpn_process" else "android_ui_process")
            put("source", "android_activity_manager_memory_info")
            put("process_id", process.getLong("processId"))
            put("process_name", name)
            copyLong(process, this, "currentResidentMemoryBytes", "current_resident_memory_bytes")
            copyLong(process, this, "currentProportionalMemoryBytes", "current_proportional_memory_bytes")
            copyLong(process, this, "currentPrivateDirtyMemoryBytes", "current_private_dirty_memory_bytes")
        })
        process.optLongOrNull("currentResidentMemoryBytes")?.let {
            residentFound = true
            resident = resident.saturatingAdd(it)
        }
        process.optLongOrNull("currentProportionalMemoryBytes")?.let {
            proportionalFound = true
            proportional = proportional.saturatingAdd(it)
        }
        process.optLongOrNull("currentPrivateDirtyMemoryBytes")?.let {
            privateDirtyFound = true
            privateDirty = privateDirty.saturatingAdd(it)
        }
    }
    result.put(JSONObject().apply {
        put("component", "android_application_processes")
        put("source", "android_activity_manager_memory_sum")
        putNullable("current_resident_memory_bytes", resident.takeIf { residentFound })
        putNullable("current_proportional_memory_bytes", proportional.takeIf { proportionalFound })
        putNullable("current_private_dirty_memory_bytes", privateDirty.takeIf { privateDirtyFound })
    })
    return result
}

private fun logMemorySnapshot(packageName: String, processes: JSONArray) {
    for (index in 0 until processes.length()) {
        val process = processes.getJSONObject(index)
        val name = process.optString("processName")
        TunnelLog.info(
            "diagnostics.memory_snapshot",
            mapOf(
                "process" to if (name.endsWith(":vpn")) "vpn" else if (name == packageName) "ui" else "app",
                "rss_bytes" to process.optLongOrNull("currentResidentMemoryBytes"),
                "pss_bytes" to process.optLongOrNull("currentProportionalMemoryBytes"),
                "private_dirty_bytes" to process.optLongOrNull("currentPrivateDirtyMemoryBytes"),
            ),
        )
    }
}

private fun intervalLog(
    context: Context,
    stem: String,
    maximum: Int,
    startedAt: Long,
    endedAt: Long,
): String {
    val diagnostics = File(context.applicationInfo.dataDir, "diagnostics")
    val previous = readTail(File(diagnostics, "$stem.previous.jsonl"), maximum / 2)
    val current = readTail(File(diagnostics, "$stem.jsonl"), maximum)
    return automaticDiagnosticsFilterIntervalLog(
        previous + current,
        startedAt,
        endedAt,
    ).takeLast(maximum)
}

private fun readTail(file: File, maximum: Int): String = runCatching {
    FileInputStream(file).use { input ->
        val skip = (file.length() - maximum).coerceAtLeast(0)
        var remaining = skip
        while (remaining > 0) {
            val skipped = input.skip(remaining)
            if (skipped <= 0) break
            remaining -= skipped
        }
        input.readBytes().toString(StandardCharsets.UTF_8).replace("\u0000", "")
    }
}.getOrDefault("")

private fun appVersion(context: Context): String = runCatching {
    context.packageManager.getPackageInfo(context.packageName, 0).versionName
}.getOrNull()?.takeIf { it.isNotBlank() }?.take(64) ?: "unknown"

private fun currentProcessName(context: Context): String {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        return android.app.Application.getProcessName()
    }
    val commandLine = runCatching {
        FileInputStream("/proc/self/cmdline").use { input ->
            val buffer = ByteArray(256)
            val count = input.read(buffer)
            if (count <= 0) null else String(buffer, 0, count, StandardCharsets.UTF_8)
        }
    }.getOrNull()
    return automaticDiagnosticsLegacyProcessName(commandLine, context.packageName)
}

private fun processRssBytes(processId: Int): Long? = runCatching {
    File("/proc/$processId/status").useLines { lines ->
        lines.firstNotNullOfOrNull { line ->
            if (!line.startsWith("VmRSS:")) return@firstNotNullOfOrNull null
            line.substringAfter(':').trim().substringBefore(' ').toLongOrNull()?.times(1024L)
        }
    }
}.getOrNull()

private fun JSONObject.putNullable(key: String, value: Long?) {
    if (value != null) put(key, value)
}

private fun JSONObject.optLongOrNull(key: String): Long? =
    if (has(key) && !isNull(key)) optLong(key) else null

private fun copyLong(source: JSONObject, destination: JSONObject, sourceKey: String, targetKey: String) {
    source.optLongOrNull(sourceKey)?.let { destination.put(targetKey, it) }
}

private fun Long.saturatingAdd(value: Long): Long =
    if (Long.MAX_VALUE - this < value) Long.MAX_VALUE else this + value

private fun nowUnix(): Long = System.currentTimeMillis() / 1000L

internal fun automaticDiagnosticsRetryDelaySeconds(attempt: Int): Long =
    RETRY_DELAYS_SECONDS[attempt.coerceAtLeast(0).coerceAtMost(RETRY_DELAYS_SECONDS.lastIndex)]

internal fun automaticDiagnosticsNextPendingReport(
    names: List<String>,
    lastAttempted: String?,
): String? {
    val sorted = names.sorted()
    if (sorted.isEmpty()) return null
    if (lastAttempted == null) return sorted.first()
    return sorted.firstOrNull { it > lastAttempted } ?: sorted.first()
}

internal fun automaticDiagnosticsPendingReportName(
    generatedAt: Long,
    deviceId: String?,
    reportId: String,
): String = "%020d_%s_%s%s".format(
    generatedAt,
    deviceId ?: UNSCOPED_REPORT,
    reportId,
    REPORT_SUFFIX,
)

internal fun automaticDiagnosticsPendingReportScope(name: String): String? {
    if (!name.endsWith(REPORT_SUFFIX)) return null
    val parts = name.removeSuffix(REPORT_SUFFIX).split('_')
    if (parts.size != 3 || parts[1] == UNSCOPED_REPORT) return null
    return runCatching { UUID.fromString(parts[1]).toString() }
        .getOrNull()
        ?.takeIf { it == parts[1] }
}

internal fun automaticDiagnosticsHasPendingWork(
    reportNames: List<String>,
    stoppedSessionPending: Boolean,
    pendingSeal: Boolean,
    deviceId: String?,
): Boolean =
    stoppedSessionPending ||
        pendingSeal ||
        deviceId != null && reportNames.any {
            automaticDiagnosticsPendingReportScope(it) == deviceId
        }

internal fun automaticDiagnosticsLegacyProcessName(
    commandLine: String?,
    packageName: String,
): String {
    val processName = commandLine
        ?.substringBefore('\u0000')
        ?.trim()
        ?.takeIf { it == packageName || it.startsWith("$packageName:") }
    return processName ?: packageName
}

internal fun automaticDiagnosticsSentReportsToPrune(names: List<String>): Set<String> =
    names.sortedDescending().drop(MAX_SENT_REPORTS).toSet()

internal fun automaticDiagnosticsFilterIntervalLog(
    value: String,
    startedAt: Long,
    endedAt: Long,
): String {
    val lines = value.lineSequence().mapNotNull { line ->
        if (line.isBlank()) return@mapNotNull null
        val timestamp = runCatching {
            val payload = JSONObject(line)
            if (payload.has("timestamp_unix")) {
                payload.getLong("timestamp_unix")
            } else {
                Instant.parse(payload.getString("timestamp")).epochSecond
            }
        }.getOrNull() ?: return@mapNotNull null
        line.takeIf { timestamp in startedAt..endedAt }
    }.toList()
    return if (lines.isEmpty()) "" else lines.joinToString(separator = "\n", postfix = "\n")
}
