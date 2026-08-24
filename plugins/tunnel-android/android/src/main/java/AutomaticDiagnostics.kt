package ru.nelomai.tunnel

import android.app.ActivityManager
import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import android.os.Build
import android.os.Debug
import android.os.Process
import android.os.SystemClock
import android.system.Os
import android.system.OsConstants
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream
import org.json.JSONArray
import org.json.JSONObject

private const val AUTOMATIC_DIAGNOSTICS_PREFERENCES = "nelomai-automatic-diagnostics"
private const val AUTOMATIC_DIAGNOSTICS_DIRECTORY = "diagnostics/automatic"
private const val PENDING_DIRECTORY = "pending"
private const val SENT_DIRECTORY = "sent"
private const val START_FAILURE_DIRECTORY = "start-failures"
private const val REPORT_SUFFIX = ".json.gz"
private const val START_FAILURE_REQUEST_SUFFIX = ".json"
private const val MEMORY_TIMELINE_FILE = "memory-timeline.jsonl"
private const val CHECKPOINT_INTERVAL_SECONDS = 6 * 60 * 60L
private val MEMORY_SAMPLE_DELAYS_SECONDS = automaticDiagnosticsMemorySampleDelaysSeconds().toLongArray()
private const val MEMORY_GROWTH_POLL_SECONDS = 30L
private const val MEMORY_GROWTH_THRESHOLD_BYTES = 64L * 1024L * 1024L
private const val MAX_MEMORY_TIMELINE_SAMPLES = 32
private const val MAX_MEMORY_TIMELINE_FILE_BYTES = 128 * 1024L
private const val NETWORK_MEMORY_SAMPLE_COOLDOWN_SECONDS = 60L
private const val UI_REMOVED_SETTLE_SECONDS = 5L
private const val START_FAILURE_WINDOW_SECONDS = 15 * 60L
private const val START_FAILURE_COOLDOWN_SECONDS = 15 * 60L
private const val SUCCESS_UPLOAD_SPACING_SECONDS = 65L
private const val MAX_SENT_REPORTS = 3
private const val MAX_APPLICATION_LOG_BYTES = 320 * 1024
private const val MAX_STARTUP_LOG_BYTES = 16 * 1024
private const val MAX_HELPER_LOG_BYTES = 64 * 1024
private const val MAX_NETWORK_INCIDENT_LOG_BYTES = 48 * 1024
private const val MAX_REPORT_BYTES = 512 * 1024
private const val TUNNEL_START_MEMORY_GROWTH_THRESHOLD_BYTES = 256L * 1024L * 1024L
private const val TUNNEL_START_MEMORY_ABSOLUTE_THRESHOLD_BYTES = 512L * 1024L * 1024L
private const val AUTOMATIC_DIAGNOSTICS_JOB_ID = 0x4e444941
private val RETRY_DELAYS_SECONDS = longArrayOf(5 * 60L, 30 * 60L, 2 * 60 * 60L, 6 * 60 * 60L)

private const val KEY_SESSION_ID = "session_id"
private const val KEY_SESSION_SEQUENCE = "session_sequence"
private const val KEY_INTERVAL_STARTED_AT = "interval_started_at"
private const val KEY_SESSION_RUNNING = "session_running"
private const val KEY_SESSION_DEVICE_ID = "session_device_id"
private const val KEY_SESSION_LEASE_ID = "session_lease_id"
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
    val connectionLeaseId: String?,
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
        put("connection_lease_id", connectionLeaseId ?: JSONObject.NULL)
    }.toString()
}

internal object AutomaticDiagnostics {
    private val gate = Any()
    private val memoryTimelineGate = Any()
    private val uploadQueued = AtomicBoolean(false)
    private val systemJobRunning = AtomicBoolean(false)
    private val immediateUploadPending = AtomicBoolean(false)
    private val uploadScheduleGeneration = AtomicLong(0)
    private val executor = Executors.newSingleThreadScheduledExecutor { task ->
        Thread(task, "nelomai-automatic-diagnostics").apply { isDaemon = true }
    }
    private val startFailureExecutor = Executors.newSingleThreadExecutor { task ->
        Thread(task, "nelomai-start-failure-diagnostics").apply { isDaemon = true }
    }
    private var checkpointFuture: ScheduledFuture<*>? = null
    private var uploadFuture: ScheduledFuture<*>? = null
    private val memorySampleFutures = mutableListOf<ScheduledFuture<*>>()
    private var memoryGrowthFuture: ScheduledFuture<*>? = null
    private val memoryGrowthTracker = AutomaticDiagnosticsMemoryGrowthTracker(
        MEMORY_GROWTH_THRESHOLD_BYTES,
    )
    private var lastNetworkMemorySampleAt = 0L

    fun hasActiveUpload(): Boolean =
        uploadQueued.get() || systemJobRunning.get() || immediateUploadPending.get()

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

    fun onTunnelStarted(context: Context, connectionLeaseId: String?) {
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
            clearMemoryTimeline(applicationContext)
            memoryGrowthTracker.reset()
            check(
                preferences.edit()
                    .putString(KEY_SESSION_ID, UUID.randomUUID().toString())
                    .putInt(KEY_SESSION_SEQUENCE, 0)
                    .putLong(KEY_INTERVAL_STARTED_AT, now)
                    .putBoolean(KEY_SESSION_RUNNING, true)
                    .putString(KEY_SESSION_DEVICE_ID, deviceId)
                    .putString(KEY_SESSION_LEASE_ID, connectionLeaseId)
                    .remove(KEY_STOPPED_SESSION_PENDING)
                    .remove(KEY_PENDING_SEAL)
                    .commit(),
            ) { "automatic_diagnostics_session_write_failed" }
            TunnelLog.info("diagnostics.session_started")
            recordMemorySnapshot(applicationContext, "tunnel_started")
            scheduleMemorySeriesLocked(applicationContext)
            scheduleMemoryGrowthWatchLocked(applicationContext)
            scheduleCheckpointLocked(applicationContext, CHECKPOINT_INTERVAL_SECONDS)
            scheduleUploadLocked(applicationContext, requestedDelaySeconds = 0)
        }
    }

    fun onTunnelStopped(context: Context) {
        val applicationContext = context.applicationContext
        synchronized(gate) {
            checkpointFuture?.cancel(false)
            checkpointFuture = null
            cancelMemorySeriesLocked()
            cancelMemoryGrowthWatchLocked()
            recordMemorySnapshot(applicationContext, "tunnel_stopping")
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

    fun onUiTaskRemoved(context: Context) {
        val applicationContext = context.applicationContext
        executor.execute { recordMemorySnapshot(applicationContext, "ui_task_removed") }
        executor.schedule(
            { recordMemorySnapshot(applicationContext, "ui_task_removed_settled") },
            UI_REMOVED_SETTLE_SECONDS,
            TimeUnit.SECONDS,
        )
    }

    fun onPhysicalNetworkChanged(context: Context) {
        val applicationContext = context.applicationContext
        synchronized(gate) {
            val now = nowUnix()
            if (now - lastNetworkMemorySampleAt < NETWORK_MEMORY_SAMPLE_COOLDOWN_SECONDS) return
            lastNetworkMemorySampleAt = now
            executor.execute { recordMemorySnapshot(applicationContext, "physical_network_changed") }
        }
    }

    fun onConnectionStartFailed(
        context: Context,
        deviceId: String,
        errorCode: String,
        onComplete: (Throwable?) -> Unit,
    ) {
        val applicationContext = context.applicationContext
        startFailureExecutor.execute {
            val failure = runCatching {
                synchronized(gate) {
                    queueConnectionStartFailure(applicationContext, deviceId, errorCode)
                }
            }
            failure.exceptionOrNull()?.let { error ->
                TunnelLog.warning(
                    "diagnostics.start_failure_report_queue_failed",
                    error = error,
                )
            }
            onComplete(failure.exceptionOrNull())
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
                scheduleMemorySeriesLocked(context)
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
                    connectionLeaseId = preferences.getString(KEY_SESSION_LEASE_ID, null),
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
                    seal.connectionLeaseId,
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
                    .remove(KEY_SESSION_LEASE_ID)
                    .remove(KEY_STOPPED_SESSION_PENDING)
                    .putBoolean(KEY_SESSION_RUNNING, false)
            }
            check(editor.commit()) { "automatic_diagnostics_session_write_failed" }
            if (seal.tunnelRunning) {
                retainMemoryTimelineAfter(context, seal.endedAt)
            } else {
                clearMemoryTimeline(context)
            }
            memoryGrowthTracker.reset()
            if (seal.tunnelRunning && tunnelRunning) {
                recordMemorySnapshot(context, "checkpoint_started")
            }
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
        connectionLeaseId: String?,
    ): JSONObject {
        val processes = androidProcessMemory(context)
        logMemorySnapshot(context.packageName, processes, "report_$trigger")
        val finalMemorySample = automaticDiagnosticsMemorySample(
            processes,
            "report_$trigger",
            endedAt,
        )
        val memorySamples = memoryTimelineForReport(
            context,
            startedAt,
            endedAt,
            finalMemorySample,
        )
        return JSONObject().apply {
            put("report_id", reportId)
            put("trigger", trigger)
            put("tunnel_session_id", sessionId)
            put("sequence", sequence)
            put("interval_started_at_unix", startedAt)
            put("interval_ended_at_unix", endedAt)
            put("tunnel_running", tunnelRunning)
            connectionLeaseId?.let { put("connection_lease_id", it) }
            put("generated_at_unix", endedAt)
            put("app_version", appVersion(context))
            put("platform_version", Build.VERSION.RELEASE.takeIf(String::isNotBlank))
            put("architecture", Build.SUPPORTED_ABIS.firstOrNull()?.take(32) ?: "unknown")
            put(
                "application_log",
                applicationLog(context, startedAt, endedAt),
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
            val networkIncidents = intervalLog(
                context,
                "android-network-incidents",
                MAX_NETWORK_INCIDENT_LOG_BYTES,
                startedAt,
                endedAt,
            )
            if (networkIncidents.isNotBlank()) {
                put("network_incidents", networkIncidents)
            }
            put(
                "resource_usage",
                JSONObject().apply {
                    put("measurement_mode", "session_delta")
                    put("session_duration_ms", (endedAt - startedAt).coerceAtLeast(0).times(1000))
                    put("components", automaticDiagnosticsResourceComponents(processes))
                    put("memory_samples", memorySamples)
                },
            )
        }
    }

    private fun queueConnectionStartFailure(
        context: Context,
        deviceId: String,
        errorCode: String,
    ) {
        ensureDirectories(context)
        TunnelLog.warning("diagnostics.connection_start_failed", errorCode.take(80))
        val now = nowUnix()
        var queuedRequest: StartFailureRequest? = null
        var pendingExists = false
        withStartFailureLock(context) {
            val requestFile = startFailureRequestFile(context, deviceId)
            val existing = readStartFailureRequestOrQuarantine(context, requestFile, deviceId)
            pendingExists = existing?.sent == false
            if (automaticDiagnosticsShouldQueueStartFailure(
                    pendingExists = pendingExists,
                    lastQueuedAt = existing?.queuedAt ?: 0,
                    now = now,
                    cooldownSeconds = START_FAILURE_COOLDOWN_SECONDS,
                )
            ) {
                queuedRequest = StartFailureRequest(
                    reportId = UUID.randomUUID().toString(),
                    deviceId = deviceId,
                    errorCode = errorCode.take(80),
                    queuedAt = now,
                    sent = false,
                ).also {
                    writeStartFailureRequest(requestFile, it)
                    // Persist the OS job immediately after the durable marker. Report
                    // materialization below may be interrupted by process termination.
                    scheduleSystemUpload(context, delaySeconds = 0)
                }
            }
        }
        if (queuedRequest == null && pendingExists) {
            // Repair an earlier marker whose scheduling window was interrupted.
            scheduleSystemUpload(context, delaySeconds = 0)
        }
        if (queuedRequest == null) {
            TunnelLog.info(
                "diagnostics.start_failure_report_deduplicated",
                mapOf("code" to errorCode, "pending" to pendingExists),
            )
        } else {
            TunnelLog.info(
                "diagnostics.start_failure_report_queued",
                mapOf("report_id" to queuedRequest?.reportId, "code" to errorCode),
            )
        }
        try {
            materializeStartFailureRequest(context, deviceId)
        } finally {
            scheduleSystemUpload(context, delaySeconds = 0)
        }
    }

    private fun materializeStartFailureRequest(
        context: Context,
        requestedDeviceId: String? = null,
    ) {
        val deviceId = requestedDeviceId
            ?: BackgroundCredentialStore.load(context)?.deviceId
            ?: return
        withStartFailureLock(context) {
            val requestFile = startFailureRequestFile(context, deviceId)
            val request = readStartFailureRequestOrQuarantine(context, requestFile, deviceId)
                ?.takeUnless { it.sent }
                ?: return@withStartFailureLock
            val pendingReport = File(pendingDirectory(context), request.reportName)
            if (pendingReport.isFile) return@withStartFailureLock
            if (File(sentDirectory(context), request.reportName).isFile) {
                writeStartFailureRequest(requestFile, request.copy(sent = true))
                return@withStartFailureLock
            }
            TunnelLog.info(
                "diagnostics.start_failure_report_materialized",
                mapOf("report_id" to request.reportId, "code" to request.errorCode),
            )
            writePendingReport(
                pendingReport,
                buildStartFailureReport(
                    context,
                    request.reportId,
                    request.queuedAt,
                    request.errorCode,
                ),
            )
        }
    }

    private fun buildStartFailureReport(
        context: Context,
        reportId: String,
        endedAt: Long,
        errorCode: String,
    ): JSONObject {
        val startedAt = (endedAt - START_FAILURE_WINDOW_SECONDS).coerceAtLeast(0)
        val processes = androidProcessMemory(context)
        logMemorySnapshot(context.packageName, processes, "connection_start_failed")
        return JSONObject().apply {
            put("report_id", reportId)
            put("trigger", "connection_start_failed")
            put("generated_at_unix", endedAt)
            put("app_version", appVersion(context))
            put("platform_version", Build.VERSION.RELEASE.takeIf(String::isNotBlank))
            put("architecture", Build.SUPPORTED_ABIS.firstOrNull()?.take(32) ?: "unknown")
            put("application_log", applicationLog(context, startedAt, endedAt))
            put(
                "helper_log",
                startFailureHelperLog(context, startedAt, endedAt, errorCode),
            )
            put(
                "resource_usage",
                JSONObject().apply {
                    put("measurement_mode", "session_delta")
                    put("session_duration_ms", 0)
                    put("components", automaticDiagnosticsResourceComponents(processes))
                },
            )
        }
    }

    private fun writePendingReport(finalFile: File, payload: JSONObject) {
        val directory = requireNotNull(finalFile.parentFile)
        val temporaryFile = File(directory, ".${finalFile.name}.part")
        val encoded = automaticDiagnosticsCompactReportToBytes(
            payload,
            MAX_REPORT_BYTES,
        ).toString().toByteArray(StandardCharsets.UTF_8)
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
            Os.rename(temporaryFile.absolutePath, finalFile.absolutePath)
            fsyncDirectory(directory)
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
                connectionLeaseId = if (payload.isNull("connection_lease_id")) {
                    null
                } else {
                    UUID.fromString(payload.getString("connection_lease_id")).toString()
                },
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

    private fun scheduleMemorySeriesLocked(context: Context) {
        cancelMemorySeriesLocked()
        MEMORY_SAMPLE_DELAYS_SECONDS.forEach { delaySeconds ->
            memorySampleFutures += executor.schedule(
                {
                    if (preferences(context).getBoolean(KEY_SESSION_RUNNING, false)) {
                        recordMemorySnapshot(context, "tunnel_uptime_${delaySeconds}s")
                    }
                },
                delaySeconds,
                TimeUnit.SECONDS,
            )
        }
    }

    private fun cancelMemorySeriesLocked() {
        memorySampleFutures.forEach { it.cancel(false) }
        memorySampleFutures.clear()
    }

    private fun scheduleMemoryGrowthWatchLocked(context: Context) {
        cancelMemoryGrowthWatchLocked()
        memoryGrowthFuture = executor.scheduleWithFixedDelay(
            {
                synchronized(gate) {
                    if (!preferences(context).getBoolean(KEY_SESSION_RUNNING, false)) {
                        return@synchronized
                    }
                    runCatching { androidProcessMemory(context) }
                        .onSuccess { processes ->
                            val residentBytes = automaticDiagnosticsTotalResidentBytes(processes)
                            if (memoryGrowthTracker.observe(residentBytes)) {
                                recordMemorySnapshot(
                                    context,
                                    "memory_growth_threshold",
                                    processes,
                                )
                            }
                        }
                        .onFailure {
                            TunnelLog.warning("diagnostics.memory_watch_failed", error = it)
                        }
                }
            },
            MEMORY_GROWTH_POLL_SECONDS,
            MEMORY_GROWTH_POLL_SECONDS,
            TimeUnit.SECONDS,
        )
    }

    private fun cancelMemoryGrowthWatchLocked() {
        memoryGrowthFuture?.cancel(false)
        memoryGrowthFuture = null
    }

    private fun recordMemorySnapshot(
        context: Context,
        reason: String,
    ) = automaticDiagnosticsRunWithLifecycleGate(gate) {
        runCatching { androidProcessMemory(context) }
            .onSuccess { recordMemorySnapshot(context, reason, it) }
            .onFailure { TunnelLog.warning("diagnostics.memory_snapshot_failed", error = it) }
    }

    private fun recordMemorySnapshot(
        context: Context,
        reason: String,
        processes: JSONArray,
    ) = automaticDiagnosticsRunWithLifecycleGate(gate) {
        logMemorySnapshot(context.packageName, processes, reason)
        val residentBytes = automaticDiagnosticsTotalResidentBytes(processes)
        memoryGrowthTracker.reset(residentBytes)
        if (preferences(context).getBoolean(KEY_SESSION_RUNNING, false)) {
            appendMemoryTimelineSample(
                context,
                automaticDiagnosticsMemorySample(processes, reason, nowUnix()),
            )
        }
    }

    private fun scheduleUploadLocked(context: Context, requestedDelaySeconds: Long) {
        if (!hasPendingWork(context)) {
            uploadFuture?.cancel(false)
            uploadFuture = null
            uploadScheduleGeneration.incrementAndGet()
            immediateUploadPending.set(false)
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
        val scheduleGeneration = uploadScheduleGeneration.incrementAndGet()
        immediateUploadPending.set(delay == 0L)
        uploadFuture = executor.schedule(
            {
                try {
                    processNext(context.applicationContext)
                } finally {
                    if (uploadScheduleGeneration.get() == scheduleGeneration) {
                        immediateUploadPending.set(false)
                    }
                }
            },
            delay,
            TimeUnit.SECONDS,
        )
        scheduleSystemUpload(context, delay)
    }

    private fun processNext(context: Context): Boolean {
        var startFailureMaterializationFailed = false
        try {
            synchronized(gate) {
                runCatching {
                    materializeStartFailureRequest(context)
                }.onFailure { error ->
                    startFailureMaterializationFailed = true
                    TunnelLog.warning(
                        "diagnostics.report_materialization_failed",
                        "automatic_diagnostics_report_queue_failed",
                        error,
                    )
                }
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
        } catch (error: Throwable) {
            TunnelLog.warning(
                "diagnostics.report_materialization_failed",
                "automatic_diagnostics_report_queue_failed",
                error,
            )
            scheduleRetry(context, "automatic_diagnostics_report_queue_failed")
            return true
        }
        val hasUploadableReport = BackgroundCredentialStore.load(context)?.deviceId?.let { deviceId ->
            pendingReports(context).any {
                automaticDiagnosticsPendingReportScope(it.name) == deviceId
            }
        } == true
        if (startFailureMaterializationFailed && !hasUploadableReport) {
            scheduleRetry(context, "automatic_diagnostics_report_queue_failed")
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
        markStartFailureRequestSent(context, report.name)
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
            if (report.exists() && !report.delete() && report.exists()) {
                TunnelLog.warning(
                    "diagnostics.sent_prune_failed",
                    "delete_failed",
                )
            }
        }
    }

    private fun pendingReports(context: Context): List<File> =
        pendingDirectory(context).listFiles()
            .orEmpty()
            .filter { it.isFile && it.name.endsWith(REPORT_SUFFIX) }
            .sortedBy(File::getName)

    private fun hasPendingWork(context: Context): Boolean {
        val deviceId = BackgroundCredentialStore.load(context)?.deviceId
        return automaticDiagnosticsHasPendingWork(
            pendingReports(context).map(File::getName),
            preferences(context).getBoolean(KEY_STOPPED_SESSION_PENDING, false),
            preferences(context).contains(KEY_PENDING_SEAL),
            deviceId,
            deviceId?.let {
                hasPendingStartFailureRequest(context, it)
            } == true,
        )
    }

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
        check(startFailureDirectory(context).mkdirs() || startFailureDirectory(context).isDirectory)
    }

    private fun pendingDirectory(context: Context): File =
        File(context.applicationInfo.dataDir, "$AUTOMATIC_DIAGNOSTICS_DIRECTORY/$PENDING_DIRECTORY")

    private fun sentDirectory(context: Context): File =
        File(context.applicationInfo.dataDir, "$AUTOMATIC_DIAGNOSTICS_DIRECTORY/$SENT_DIRECTORY")

    private fun startFailureDirectory(context: Context): File =
        File(context.applicationInfo.dataDir, "$AUTOMATIC_DIAGNOSTICS_DIRECTORY/$START_FAILURE_DIRECTORY")

    private fun memoryTimelineFile(context: Context): File =
        File(context.applicationInfo.dataDir, "$AUTOMATIC_DIAGNOSTICS_DIRECTORY/$MEMORY_TIMELINE_FILE")

    private fun readMemoryTimelineSamples(context: Context): List<JSONObject> {
        val file = memoryTimelineFile(context)
        if (!file.isFile || file.length() > MAX_MEMORY_TIMELINE_FILE_BYTES) return emptyList()
        return file.readLines(StandardCharsets.UTF_8)
            .mapNotNull { line -> runCatching { JSONObject(line) }.getOrNull() }
            .filter { it.optLong("timestamp_unix", -1L) >= 0L }
    }

    private fun writeMemoryTimelineSamples(context: Context, samples: List<JSONObject>) {
        ensureDirectories(context)
        val file = memoryTimelineFile(context)
        val temporary = File(requireNotNull(file.parentFile), ".${file.name}.part")
        try {
            FileOutputStream(temporary).use { output ->
                val writer = output.bufferedWriter(StandardCharsets.UTF_8)
                samples.forEach { sample ->
                    writer.write(sample.toString())
                    writer.newLine()
                }
                writer.flush()
                output.fd.sync()
            }
            check(temporary.length() <= MAX_MEMORY_TIMELINE_FILE_BYTES) {
                "automatic_diagnostics_memory_timeline_too_large"
            }
            Os.rename(temporary.absolutePath, file.absolutePath)
            fsyncDirectory(requireNotNull(file.parentFile))
        } finally {
            temporary.delete()
        }
    }

    private fun appendMemoryTimelineSample(context: Context, sample: JSONObject) {
        synchronized(memoryTimelineGate) {
            val samples = readMemoryTimelineSamples(context) + sample
            writeMemoryTimelineSamples(
                context,
                automaticDiagnosticsBoundMemorySamples(
                    samples,
                    MAX_MEMORY_TIMELINE_SAMPLES,
                ),
            )
        }
    }

    private fun memoryTimelineForReport(
        context: Context,
        startedAt: Long,
        endedAt: Long,
        finalSample: JSONObject,
    ): JSONArray = synchronized(memoryTimelineGate) {
        val unique = linkedMapOf<String, JSONObject>()
        (readMemoryTimelineSamples(context) + finalSample)
            .filter { sample -> sample.optLong("timestamp_unix", -1L) in startedAt..endedAt }
            .forEach { sample ->
                val key = "${sample.optLong("timestamp_unix")}:${sample.optString("reason")}"
                unique[key] = sample
            }
        JSONArray(
            automaticDiagnosticsBoundMemorySamples(
                unique.values.toList(),
                MAX_MEMORY_TIMELINE_SAMPLES,
            ),
        )
    }

    private fun clearMemoryTimeline(context: Context) {
        synchronized(memoryTimelineGate) {
            val file = memoryTimelineFile(context)
            if (file.exists() && !file.delete() && file.exists()) {
                TunnelLog.warning("diagnostics.memory_timeline_clear_failed", "delete_failed")
            }
        }
    }

    private fun retainMemoryTimelineAfter(context: Context, endedAt: Long) {
        synchronized(memoryTimelineGate) {
            val retained = automaticDiagnosticsMemorySamplesAfter(
                readMemoryTimelineSamples(context),
                endedAt,
            )
            if (retained.isEmpty()) {
                val file = memoryTimelineFile(context)
                if (file.exists() && !file.delete() && file.exists()) {
                    TunnelLog.warning("diagnostics.memory_timeline_clear_failed", "delete_failed")
                }
            } else {
                writeMemoryTimelineSamples(context, retained)
            }
        }
    }

    private fun startFailureRequestFile(context: Context, deviceId: String): File =
        File(startFailureDirectory(context), "$deviceId$START_FAILURE_REQUEST_SUFFIX")

    private fun startFailureLockFile(context: Context): File =
        File(startFailureDirectory(context), ".queue.lock")

    private fun <T> withStartFailureLock(context: Context, action: () -> T): T {
        ensureDirectories(context)
        return RandomAccessFile(startFailureLockFile(context), "rw").use { lockFile ->
            lockFile.channel.use { channel ->
                channel.lock().use { action() }
            }
        }
    }

    private fun readStartFailureRequest(
        file: File,
        expectedDeviceId: String,
    ): StartFailureRequest? {
        if (!file.isFile) return null
        check(file.length() <= 4 * 1024L) { "automatic_diagnostics_start_failure_request_too_large" }
        return StartFailureRequest.fromJson(file.readText(StandardCharsets.UTF_8)).also {
            check(it.deviceId == expectedDeviceId) {
                "automatic_diagnostics_start_failure_request_device_mismatch"
            }
        }
    }

    private fun readStartFailureRequestOrQuarantine(
        context: Context,
        file: File,
        expectedDeviceId: String,
    ): StartFailureRequest? = try {
        readStartFailureRequest(file, expectedDeviceId)
    } catch (error: Throwable) {
        val quarantineFile = File(
            startFailureDirectory(context),
            "${file.name}.corrupt-${nowUnix()}-${UUID.randomUUID()}",
        )
        try {
            Os.rename(file.absolutePath, quarantineFile.absolutePath)
            fsyncDirectory(requireNotNull(file.parentFile))
        } catch (quarantineError: Throwable) {
            error.addSuppressed(quarantineError)
            throw error
        }
        TunnelLog.warning(
            "diagnostics.start_failure_request_quarantined",
            "invalid_start_failure_request",
            error,
        )
        null
    }

    private fun writeStartFailureRequest(file: File, request: StartFailureRequest) {
        val temporaryFile = File(requireNotNull(file.parentFile), ".${file.name}.part")
        val encoded = request.toJson().toByteArray(StandardCharsets.UTF_8)
        try {
            FileOutputStream(temporaryFile).use { output ->
                output.write(encoded)
                output.flush()
                output.fd.sync()
            }
            Os.rename(temporaryFile.absolutePath, file.absolutePath)
            fsyncDirectory(requireNotNull(file.parentFile))
        } finally {
            encoded.fill(0)
            temporaryFile.delete()
        }
    }

    private fun hasPendingStartFailureRequest(context: Context, deviceId: String): Boolean =
        withStartFailureLock(context) {
            val file = startFailureRequestFile(context, deviceId)
            if (!file.isFile) return@withStartFailureLock false
            readStartFailureRequestOrQuarantine(context, file, deviceId)?.sent == false
        }

    private fun markStartFailureRequestSent(context: Context, reportName: String) {
        val deviceId = automaticDiagnosticsPendingReportScope(reportName) ?: return
        withStartFailureLock(context) {
            val file = startFailureRequestFile(context, deviceId)
            val request = readStartFailureRequestOrQuarantine(context, file, deviceId)
                ?: return@withStartFailureLock
            if (!request.sent && request.reportName == reportName) {
                writeStartFailureRequest(file, request.copy(sent = true))
            }
        }
    }

    private fun fsyncDirectory(directory: File) {
        val descriptor = Os.open(directory.absolutePath, OsConstants.O_RDONLY, 0)
        try {
            Os.fsync(descriptor)
        } finally {
            Os.close(descriptor)
        }
    }

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
                putNullable("peakResidentMemoryBytes", processPeakRssBytes(pid))
                putNullable("currentProportionalMemoryBytes", info?.totalPss?.toLong()?.times(1024L))
                putNullable("currentPrivateDirtyMemoryBytes", info?.totalPrivateDirty?.toLong()?.times(1024L))
                putAndroidMemoryStats(info)
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
                putNullable("peakResidentMemoryBytes", processPeakRssBytes(process.pid))
                putNullable("currentProportionalMemoryBytes", info?.totalPss?.toLong()?.times(1024L))
                putNullable("currentPrivateDirtyMemoryBytes", info?.totalPrivateDirty?.toLong()?.times(1024L))
                putAndroidMemoryStats(info)
            })
        }
    }
}

internal fun automaticDiagnosticsMemorySampleDelaysSeconds(): List<Long> = listOf(
    60L,
    5 * 60L,
    15 * 60L,
    30 * 60L,
    60 * 60L,
    3 * 60 * 60L,
)

internal fun automaticDiagnosticsMemoryStatBytes(
    memoryStats: Map<String, String>,
    name: String,
): Long? = memoryStats[name]?.toLongOrNull()?.times(1024L)

private fun JSONObject.putAndroidMemoryStats(info: Debug.MemoryInfo?) {
    val stats = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
        info?.memoryStats.orEmpty()
    } else {
        emptyMap()
    }
    putNullable("pssJavaHeapBytes", automaticDiagnosticsMemoryStatBytes(stats, "summary.java-heap"))
    putNullable("pssNativeHeapBytes", automaticDiagnosticsMemoryStatBytes(stats, "summary.native-heap"))
    putNullable("pssCodeBytes", automaticDiagnosticsMemoryStatBytes(stats, "summary.code"))
    putNullable("pssStackBytes", automaticDiagnosticsMemoryStatBytes(stats, "summary.stack"))
    putNullable("pssGraphicsBytes", automaticDiagnosticsMemoryStatBytes(stats, "summary.graphics"))
    putNullable("pssPrivateOtherBytes", automaticDiagnosticsMemoryStatBytes(stats, "summary.private-other"))
    putNullable("pssSystemBytes", automaticDiagnosticsMemoryStatBytes(stats, "summary.system"))
}

internal data class AutomaticDiagnosticsProcessMemory(
    val residentBytes: Long?,
    val proportionalBytes: Long?,
)

internal class AutomaticDiagnosticsMemoryGrowthTracker(
    private val thresholdBytes: Long,
) {
    private var baselineBytes: Long? = null

    @Synchronized
    fun observe(currentBytes: Long?): Boolean {
        val current = currentBytes ?: return false
        val baseline = baselineBytes
        if (baseline == null) {
            baselineBytes = current
            return false
        }
        if (current < baseline) {
            baselineBytes = current
            return false
        }
        if (current - baseline < thresholdBytes) return false
        baselineBytes = current
        return true
    }

    @Synchronized
    fun reset(currentBytes: Long? = null) {
        baselineBytes = currentBytes
    }
}

internal fun automaticDiagnosticsBoundMemorySamples(
    samples: List<JSONObject>,
    maximum: Int,
): List<JSONObject> {
    if (maximum <= 0 || samples.isEmpty()) return emptyList()
    if (samples.size <= maximum) return samples
    if (maximum == 1) return listOf(samples.first())
    return listOf(samples.first()) + samples.takeLast(maximum - 1)
}

internal fun automaticDiagnosticsMemorySamplesAfter(
    samples: List<JSONObject>,
    endedAt: Long,
): List<JSONObject> = samples.filter { sample ->
    sample.optLong("timestamp_unix", -1L) > endedAt
}

internal fun <T> automaticDiagnosticsRunWithLifecycleGate(
    gate: Any,
    block: () -> T,
): T = synchronized(gate) { block() }

internal fun automaticDiagnosticsCompactReportToBytes(
    payload: JSONObject,
    maximum: Int,
): JSONObject {
    require(maximum > 0)
    fun encodedSize(): Int = payload.toString().toByteArray(StandardCharsets.UTF_8).size
    if (encodedSize() <= maximum) return payload

    for (field in listOf("application_log", "helper_log", "network_incidents")) {
        if (!payload.has(field) || payload.isNull(field)) continue
        val original = payload.optString(field)
        if (original.isEmpty()) continue

        payload.put(field, "")
        if (encodedSize() > maximum) continue

        var smallest = 0
        var largest = original.length
        var best = 0
        while (smallest <= largest) {
            val candidate = smallest + (largest - smallest) / 2
            payload.put(field, original.takeLast(candidate))
            if (encodedSize() <= maximum) {
                best = candidate
                smallest = candidate + 1
            } else {
                largest = candidate - 1
            }
        }
        payload.put(field, original.takeLast(best))
        return payload
    }

    check(encodedSize() <= maximum) { "automatic_diagnostics_report_too_large" }
    return payload
}

internal fun automaticDiagnosticsTotalResidentBytes(processes: JSONArray): Long? {
    var total = 0L
    var found = false
    for (index in 0 until processes.length()) {
        processes.getJSONObject(index)
            .optLongOrNull("currentResidentMemoryBytes")
            ?.let { value ->
                total = total.saturatingAdd(value)
                found = true
            }
    }
    return total.takeIf { found }
}

internal fun automaticDiagnosticsMemorySample(
    processes: JSONArray,
    reason: String,
    timestampUnix: Long,
): JSONObject = JSONObject().apply {
    put("timestamp_unix", timestampUnix.coerceAtLeast(0))
    put("reason", reason.take(64))
    putNullable("total_resident_memory_bytes", automaticDiagnosticsTotalResidentBytes(processes))
    put("components", automaticDiagnosticsResourceComponents(processes, includeAggregate = false))
}

internal class TunnelStartMemoryDetailGate(
    private val baselineRssBytes: Long?,
) {
    private val captured = AtomicBoolean(false)

    fun shouldCapture(currentRssBytes: Long?): Boolean {
        val current = currentRssBytes ?: return false
        val growth = baselineRssBytes?.let { baseline -> (current - baseline).coerceAtLeast(0) }
        val thresholdReached = current >= TUNNEL_START_MEMORY_ABSOLUTE_THRESHOLD_BYTES ||
            growth?.let { it >= TUNNEL_START_MEMORY_GROWTH_THRESHOLD_BYTES } == true
        return thresholdReached && captured.compareAndSet(false, true)
    }
}

internal fun tunnelStartMemoryDelayedStages(): List<Pair<String, Long>> = listOf(
    "after_backend_100ms" to 100L,
    "after_backend_1s" to 1_000L,
    "after_backend_5s" to 5_000L,
)

internal fun containTunnelStartMemoryDiagnosticsFailure(block: () -> Unit): Throwable? =
    runCatching(block).exceptionOrNull()

internal fun runTunnelStartupPostActions(
    required: () -> Unit,
    optionalDiagnostics: () -> Unit,
    onDiagnosticsFailure: (Throwable) -> Unit,
) {
    required()
    containTunnelStartMemoryDiagnosticsFailure(optionalDiagnostics)
        ?.let { failure -> runCatching { onDiagnosticsFailure(failure) } }
}

internal class TunnelStartMemoryDiagnostics {
    private val processId = Process.myPid()
    private val baselineRssBytes = processRssBytes(processId)
    private val detailGate = TunnelStartMemoryDetailGate(baselineRssBytes)
    private val startedAtElapsedMillis = SystemClock.elapsedRealtime()

    fun record(context: Context, stage: String, transport: String? = null) {
        val failure = containTunnelStartMemoryDiagnosticsFailure {
            recordUnchecked(context, stage, transport)
        }
        if (failure != null) {
            runCatching {
                TunnelLog.warning("diagnostics.memory_start_failed", error = failure)
            }
        }
    }

    private fun recordUnchecked(context: Context, stage: String, transport: String?) {
        val rssBytes = processRssBytes(processId)
        TunnelLog.info(
            "diagnostics.memory_start_stage",
            mapOf(
                "stage" to stage.take(64),
                "transport" to transport,
                "pid" to processId,
                "elapsed_ms" to (
                    SystemClock.elapsedRealtime() - startedAtElapsedMillis
                ).coerceAtLeast(0),
                "rss_bytes" to rssBytes,
                "rss_delta_bytes" to baselineRssBytes?.let { baseline ->
                    rssBytes?.let { current -> (current - baseline).coerceAtLeast(0) }
                },
                "peak_rss_bytes" to processPeakRssBytes(processId),
            ),
        )
        if (detailGate.shouldCapture(rssBytes)) {
            recordDetailedMemory(context, stage, transport, rssBytes)
        }
    }

    private fun recordDetailedMemory(
        context: Context,
        stage: String,
        transport: String?,
        rssBytes: Long?,
    ) {
        val activityManager = context.getSystemService(ActivityManager::class.java)
        val info = activityManager.getProcessMemoryInfo(intArrayOf(processId)).firstOrNull()
        val runtime = Runtime.getRuntime()
        val memoryStats = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            info?.memoryStats.orEmpty()
        } else {
            emptyMap()
        }
        fun statBytes(name: String): Long? = automaticDiagnosticsMemoryStatBytes(memoryStats, name)
        TunnelLog.info(
            "diagnostics.memory_pressure",
            mapOf(
                "stage" to stage.take(64),
                "transport" to transport,
                "pid" to processId,
                "rss_bytes" to rssBytes,
                "peak_rss_bytes" to processPeakRssBytes(processId),
                "pss_bytes" to info?.totalPss?.toLong()?.times(1024L),
                "private_dirty_bytes" to info?.totalPrivateDirty?.toLong()?.times(1024L),
                "java_heap_used_bytes" to (runtime.totalMemory() - runtime.freeMemory()),
                "java_heap_committed_bytes" to runtime.totalMemory(),
                "java_heap_max_bytes" to runtime.maxMemory(),
                "native_heap_allocated_bytes" to Debug.getNativeHeapAllocatedSize(),
                "native_heap_committed_bytes" to Debug.getNativeHeapSize(),
                "pss_java_heap_bytes" to statBytes("summary.java-heap"),
                "pss_native_heap_bytes" to statBytes("summary.native-heap"),
                "pss_code_bytes" to statBytes("summary.code"),
                "pss_stack_bytes" to statBytes("summary.stack"),
                "pss_graphics_bytes" to statBytes("summary.graphics"),
                "pss_private_other_bytes" to statBytes("summary.private-other"),
                "pss_system_bytes" to statBytes("summary.system"),
            ),
        )
    }
}

internal fun automaticDiagnosticsCurrentProcessMemory(
    context: Context,
): AutomaticDiagnosticsProcessMemory {
    val processId = Process.myPid()
    val activityManager = context.getSystemService(ActivityManager::class.java)
    val info = activityManager.getProcessMemoryInfo(intArrayOf(processId)).firstOrNull()
    return AutomaticDiagnosticsProcessMemory(
        residentBytes = processRssBytes(processId),
        proportionalBytes = info?.totalPss?.toLong()?.times(1024L),
    )
}

internal fun automaticDiagnosticsResourceComponents(
    processes: JSONArray,
    includeAggregate: Boolean = true,
): JSONArray {
    val result = JSONArray()
    var resident = 0L
    var peakResident = 0L
    var proportional = 0L
    var privateDirty = 0L
    var residentFound = false
    var peakResidentFound = false
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
            copyLong(process, this, "peakResidentMemoryBytes", "peak_resident_memory_bytes")
            copyLong(process, this, "currentProportionalMemoryBytes", "current_proportional_memory_bytes")
            copyLong(process, this, "currentPrivateDirtyMemoryBytes", "current_private_dirty_memory_bytes")
            copyLong(process, this, "pssJavaHeapBytes", "pss_java_heap_bytes")
            copyLong(process, this, "pssNativeHeapBytes", "pss_native_heap_bytes")
            copyLong(process, this, "pssCodeBytes", "pss_code_bytes")
            copyLong(process, this, "pssStackBytes", "pss_stack_bytes")
            copyLong(process, this, "pssGraphicsBytes", "pss_graphics_bytes")
            copyLong(process, this, "pssPrivateOtherBytes", "pss_private_other_bytes")
            copyLong(process, this, "pssSystemBytes", "pss_system_bytes")
        })
        process.optLongOrNull("currentResidentMemoryBytes")?.let {
            residentFound = true
            resident = resident.saturatingAdd(it)
        }
        process.optLongOrNull("peakResidentMemoryBytes")?.let {
            peakResidentFound = true
            peakResident = peakResident.saturatingAdd(it)
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
    if (includeAggregate) {
        result.put(JSONObject().apply {
            put("component", "android_application_processes")
            put("source", "android_activity_manager_memory_sum")
            putNullable("current_resident_memory_bytes", resident.takeIf { residentFound })
            putNullable("peak_resident_memory_bytes", peakResident.takeIf { peakResidentFound })
            putNullable("current_proportional_memory_bytes", proportional.takeIf { proportionalFound })
            putNullable("current_private_dirty_memory_bytes", privateDirty.takeIf { privateDirtyFound })
        })
    }
    return result
}

private fun logMemorySnapshot(packageName: String, processes: JSONArray, reason: String) {
    for (index in 0 until processes.length()) {
        val process = processes.getJSONObject(index)
        val name = process.optString("processName")
        TunnelLog.info(
            "diagnostics.memory_snapshot",
            mapOf(
                "process" to if (name.endsWith(":vpn")) "vpn" else if (name == packageName) "ui" else "app",
                "reason" to reason.take(64),
                "pid" to process.optLong("processId"),
                "rss_bytes" to process.optLongOrNull("currentResidentMemoryBytes"),
                "peak_rss_bytes" to process.optLongOrNull("peakResidentMemoryBytes"),
                "pss_bytes" to process.optLongOrNull("currentProportionalMemoryBytes"),
                "private_dirty_bytes" to process.optLongOrNull("currentPrivateDirtyMemoryBytes"),
                "pss_java_heap_bytes" to process.optLongOrNull("pssJavaHeapBytes"),
                "pss_native_heap_bytes" to process.optLongOrNull("pssNativeHeapBytes"),
                "pss_code_bytes" to process.optLongOrNull("pssCodeBytes"),
                "pss_stack_bytes" to process.optLongOrNull("pssStackBytes"),
                "pss_graphics_bytes" to process.optLongOrNull("pssGraphicsBytes"),
                "pss_private_other_bytes" to process.optLongOrNull("pssPrivateOtherBytes"),
                "pss_system_bytes" to process.optLongOrNull("pssSystemBytes"),
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

private fun startFailureHelperLog(
    context: Context,
    startedAt: Long,
    endedAt: Long,
    errorCode: String,
): String {
    val interval = intervalLog(
        context,
        "android-tunnel",
        MAX_HELPER_LOG_BYTES,
        startedAt,
        endedAt,
    )
    val durableEvent = JSONObject().apply {
        put("timestamp", Instant.ofEpochSecond(endedAt).toString())
        put("level", "warning")
        put("event", "diagnostics.connection_start_failed")
        put("code", errorCode.take(80))
    }.toString() + "\n"
    return (interval + durableEvent).takeLast(MAX_HELPER_LOG_BYTES)
}

private fun applicationLog(context: Context, startedAt: Long, endedAt: Long): String {
    val interval = intervalLog(
        context,
        "application",
        MAX_APPLICATION_LOG_BYTES - MAX_STARTUP_LOG_BYTES,
        startedAt,
        endedAt,
    )
    val startup = readTail(
        File(context.applicationInfo.dataDir, "diagnostics/android-startup.jsonl"),
        MAX_STARTUP_LOG_BYTES,
    ).let { automaticDiagnosticsFilterIntervalLog(it, Long.MIN_VALUE, Long.MAX_VALUE) }
    return automaticDiagnosticsCombineApplicationLogs(
        interval,
        startup,
        MAX_APPLICATION_LOG_BYTES,
    )
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
    automaticDiagnosticsStatusMemoryBytes(File("/proc/$processId/status").readText(), "VmRSS")
}.getOrNull()

private fun processPeakRssBytes(processId: Int): Long? = runCatching {
    automaticDiagnosticsStatusMemoryBytes(File("/proc/$processId/status").readText(), "VmHWM")
}.getOrNull()

internal fun automaticDiagnosticsStatusMemoryBytes(status: String, field: String): Long? =
    status.lineSequence().firstNotNullOfOrNull { line ->
        if (!line.startsWith("$field:")) return@firstNotNullOfOrNull null
        val parts = line.substringAfter(':').trim().split(Regex("\\s+"), limit = 2)
        val value = parts.firstOrNull()
            ?.toLongOrNull()
            ?.takeIf { it >= 0 }
            ?: return@firstNotNullOfOrNull null
        when (parts.getOrNull(1)?.lowercase()) {
            "kb" -> value.saturatingMultiply(1024L)
            null, "b" -> value
            else -> null
        }
    }

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

private fun Long.saturatingMultiply(value: Long): Long =
    if (this > Long.MAX_VALUE / value) Long.MAX_VALUE else this * value

private fun nowUnix(): Long = System.currentTimeMillis() / 1000L

internal fun automaticDiagnosticsRetryDelaySeconds(attempt: Int): Long =
    RETRY_DELAYS_SECONDS[attempt.coerceAtLeast(0).coerceAtMost(RETRY_DELAYS_SECONDS.lastIndex)]

internal fun automaticDiagnosticsShouldQueueStartFailure(
    pendingExists: Boolean,
    lastQueuedAt: Long,
    now: Long,
    cooldownSeconds: Long,
): Boolean =
    !pendingExists &&
        (lastQueuedAt <= 0 || now < lastQueuedAt || now - lastQueuedAt >= cooldownSeconds)

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

internal data class StartFailureRequest(
    val reportId: String,
    val deviceId: String,
    val errorCode: String,
    val queuedAt: Long,
    val sent: Boolean,
) {
    val reportName: String
        get() = automaticDiagnosticsPendingReportName(queuedAt, deviceId, reportId)

    fun toJson(): String = JSONObject().apply {
        put("format", 1)
        put("report_id", reportId)
        put("device_id", deviceId)
        put("error_code", errorCode)
        put("queued_at", queuedAt)
        put("sent", sent)
    }.toString()

    companion object {
        fun fromJson(value: String): StartFailureRequest {
            val payload = JSONObject(value)
            check(payload.getInt("format") == 1) { "invalid_start_failure_request_format" }
            val reportId = UUID.fromString(payload.getString("report_id")).toString()
            val deviceId = UUID.fromString(payload.getString("device_id")).toString()
            check(reportId == payload.getString("report_id")) { "invalid_start_failure_report_id" }
            check(deviceId == payload.getString("device_id")) { "invalid_start_failure_device_id" }
            return StartFailureRequest(
                reportId = reportId,
                deviceId = deviceId,
                errorCode = payload.getString("error_code").take(80),
                queuedAt = payload.getLong("queued_at").coerceAtLeast(0),
                sent = payload.getBoolean("sent"),
            )
        }
    }
}

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
    pendingStartFailure: Boolean = false,
): Boolean =
    stoppedSessionPending ||
        pendingSeal ||
        pendingStartFailure ||
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

internal fun automaticDiagnosticsCombineApplicationLogs(
    intervalLog: String,
    startupLog: String,
    maximum: Int,
): String = (intervalLog + startupLog).takeLast(maximum)
