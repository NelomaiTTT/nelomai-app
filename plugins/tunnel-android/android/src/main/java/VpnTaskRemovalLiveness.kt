package ru.nelomai.tunnel

import android.app.ActivityManager
import android.app.ApplicationExitInfo
import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.PersistableBundle
import android.os.Process
import java.io.File
import java.io.RandomAccessFile
import ru.nelomai.client.RuntimeProcessSelection
import ru.nelomai.client.RuntimeDispatchPolicy
import ru.nelomai.client.RuntimeSelectionStore
import ru.nelomai.client.RuntimeSelectionV1
import ru.nelomai.runtime.v1.RuntimeServiceIntents

private const val VPN_TASK_REMOVAL_LIVENESS_JOB_ID = 0x4e56504c
private const val INITIAL_DELAY_MILLIS = 15_000L
private const val RECHECK_DELAY_MILLIS = 30_000L
private const val DEADLINE_MILLIS = 60_000L
internal const val EXIT_RECORD_DELAY_MILLIS = 5_000L
private const val EXTRA_PID = "vpn_watch_pid"
private const val EXTRA_SINCE = "vpn_watch_since"
// The bound job waits for both broker reads, each with a 10s deadline.
private const val BIND_TIMEOUT_MILLIS = 30_000L
private const val FIRST_BIND_RETRY_MILLIS = 2_000L
private const val EXTRA_DEATH_SIGNAL = "vpn_watch_death_signal"
private const val EXTRA_WAITED_FOR_EXIT = "vpn_watch_waited_for_exit"

internal fun isTaskManagerStop(sinceMillis: Long, timestamp: Long, reason: Int, description: String?): Boolean =
    timestamp >= sinceMillis && reason == ApplicationExitInfo.REASON_USER_REQUESTED &&
        description?.startsWith("[STOP APP]") == true

internal fun mayDispatchTaskRemovalVpnRecovery(active: RuntimeSelectionV1): Boolean =
    active.slot == "latest" && active.runtimeVersion == BuildConfig.RUNTIME_VERSION &&
        RuntimeDispatchPolicy.mayRecoverLatestVpn(active, active)

internal data class TaskRemovalVpnWatch(
    val pid: Int,
    val sinceMillis: Long,
    val waitedForExit: Boolean = false,
    val runtime: String? = null,
    val deathSignalled: Boolean = false,
) {
    fun blocksRecovery(
        processName: String,
        exitPid: Int,
        timestamp: Long,
        reason: Int,
        description: String?,
    ): Boolean {
        if (timestamp < sinceMillis || reason != ApplicationExitInfo.REASON_USER_REQUESTED) return false
        // Android's public reason also covers a swipe from Recents. AOSP puts
        // the distinction in the public description. Treat an ambiguous user
        // request for the watched VPN process as a Stop.
        if (description?.startsWith("[REMOVE TASK]") == true) return false
        return isTaskManagerStop(sinceMillis, timestamp, reason, description) ||
            (exitPid == pid && processName.endsWith(":vpn"))
    }

    fun forCurrentProcess() = copy(pid = Process.myPid(), waitedForExit = false, deathSignalled = false)

    fun putInto(intent: Intent): Intent = intent.putExtra(EXTRA_PID, pid).putExtra(EXTRA_SINCE, sinceMillis)
        .putExtra(RuntimeServiceIntents.TASK_REMOVAL_RUNTIME, runtime).putExtra(EXTRA_WAITED_FOR_EXIT, waitedForExit)
        .putExtra(EXTRA_DEATH_SIGNAL, deathSignalled)

    fun extras(): PersistableBundle = PersistableBundle().apply {
        putInt(EXTRA_PID, pid)
        putLong(EXTRA_SINCE, sinceMillis)
        putBoolean(EXTRA_WAITED_FOR_EXIT, waitedForExit)
        putBoolean(EXTRA_DEATH_SIGNAL, deathSignalled)
        putString(RuntimeServiceIntents.TASK_REMOVAL_RUNTIME, runtime)
    }

    companion object {
        fun fromIntent(intent: Intent): TaskRemovalVpnWatch? =
            from(intent.getIntExtra(EXTRA_PID, 0), intent.getLongExtra(EXTRA_SINCE, 0), intent.getBooleanExtra(EXTRA_WAITED_FOR_EXIT, false),
                intent.getStringExtra(RuntimeServiceIntents.TASK_REMOVAL_RUNTIME), intent.getBooleanExtra(EXTRA_DEATH_SIGNAL, false))

        fun fromJob(extras: PersistableBundle): TaskRemovalVpnWatch? =
            from(extras.getInt(EXTRA_PID), extras.getLong(EXTRA_SINCE), extras.getBoolean(EXTRA_WAITED_FOR_EXIT),
                extras.getString(RuntimeServiceIntents.TASK_REMOVAL_RUNTIME), extras.getBoolean(EXTRA_DEATH_SIGNAL))

        private fun from(pid: Int, sinceMillis: Long, waitedForExit: Boolean, runtime: String?, deathSignalled: Boolean): TaskRemovalVpnWatch? =
            if (pid > 0 && sinceMillis > 0) TaskRemovalVpnWatch(pid, sinceMillis, waitedForExit, runtime, deathSignalled) else null
    }
}

internal object VpnTaskRemovalLiveness {
    private fun registeredWatch(scheduler: JobScheduler): TaskRemovalVpnWatch? =
        scheduler.getPendingJob(VPN_TASK_REMOVAL_LIVENESS_JOB_ID)?.let { TaskRemovalVpnWatch.fromJob(it.extras) }

    // Cancel and compare-and-replace run in two different Android processes.
    // JobScheduler owns the record; the lock only serializes these Binder calls.
    private fun <T> withScheduler(context: Context, action: (JobScheduler) -> T): T = synchronized(this) {
        RandomAccessFile(File(context.noBackupFilesDir, "vpn-task-removal.lock"), "rw").use { file ->
            file.channel.lock().use { action(context.getSystemService(JobScheduler::class.java)) }
        }
    }

    fun vpnProcessDied(context: Context, pid: Int) = withScheduler(context) { scheduler ->
        val watch = registeredWatch(scheduler) ?: return@withScheduler
        if (watch.pid == pid && watch.runtime != null && !watch.deathSignalled) {
            // Replace the existing job. An in-flight healthy check can no longer rearm its old snapshot.
            schedule(context, scheduler, watch.copy(deathSignalled = true), 0)
            android.util.Log.i("NelomaiTunnel", "service.task_removal_liveness_death_signal")
        }
    }

    fun cancel(context: Context) {
        runCatching {
            withScheduler(context) { it.cancel(VPN_TASK_REMOVAL_LIVENESS_JOB_ID) }
        }.onFailure { error ->
            TunnelLog.warning("service.task_removal_liveness_cancel_failed", error = error)
        }
    }

    fun schedule(context: Context, stillWanted: () -> Boolean) {
        val owner = RuntimeProcessSelection.vpnOwnerForStop()?.takeIf(::mayDispatchTaskRemovalVpnRecovery) ?: return
        withScheduler(context) { scheduler ->
            if (stillWanted()) {
                schedule(context, scheduler, TaskRemovalVpnWatch(Process.myPid(), System.currentTimeMillis(),
                    runtime = RuntimeSelectionStore.encodeVpnRecoveryOwner(owner)), INITIAL_DELAY_MILLIS)
                TunnelLog.info("service.task_removal_liveness_scheduled")
            }
        }
    }

    fun continueAfterRestore(context: Context, watch: TaskRemovalVpnWatch): Boolean =
        replace(context, watch, watch.forCurrentProcess(), RECHECK_DELAY_MILLIS)

    fun followStickyRestart(context: Context) {
        val owner = RuntimeProcessSelection.vpnOwnerForStop()?.takeIf(::mayDispatchTaskRemovalVpnRecovery) ?: return
        withScheduler(context) { scheduler ->
            val watch = registeredWatch(scheduler) ?: return@withScheduler
            if (watch.pid == Process.myPid()) return@withScheduler
            val expected = watch.runtime?.let(RuntimeSelectionStore::decode) ?: return@withScheduler
            if (RuntimeDispatchPolicy.mayRecoverLatestVpn(expected, owner) && !wasStoppedByAndroid(context, watch)) {
                schedule(context, scheduler, watch.forCurrentProcess(), RECHECK_DELAY_MILLIS)
            }
        }
    }

    private fun replace(context: Context, expected: TaskRemovalVpnWatch, next: TaskRemovalVpnWatch,
        delayMillis: Long): Boolean = withScheduler(context) { scheduler ->
        if (registeredWatch(scheduler) != expected) return@withScheduler false
        schedule(context, scheduler, next, delayMillis)
        true
    }

    fun wasStoppedByAndroid(context: Context, watch: TaskRemovalVpnWatch): Boolean =
        exitHistory(context).any { watch.blocksRecovery(it.processName, it.pid, it.timestamp, it.reason, it.description) }

    fun lastSystemStopMillis(context: Context): Long? = exitHistory(context)
        .filter { isTaskManagerStop(0, it.timestamp, it.reason, it.description) }
        .maxOfOrNull { it.timestamp }

    fun systemStoppedSince(context: Context, sinceMillis: Long): Boolean =
        lastSystemStopMillis(context)?.let { it >= sinceMillis } == true

    private fun isRegistered(context: Context, watch: TaskRemovalVpnWatch): Boolean =
        registeredWatch(context.getSystemService(JobScheduler::class.java)) == watch

    fun needsDispatch(context: Context, watch: TaskRemovalVpnWatch): Boolean {
        // Checking a healthy foreground service only requires an AMS query.
        // It must not deliver another start or rewrite a recovery snapshot.
        val runningPid = foregroundVpnPid(context)?.takeUnless { watch.deathSignalled && it == watch.pid }
        val history = if (runningPid == watch.pid) emptyList() else exitHistory(context)
        if (history.any { watch.blocksRecovery(it.processName, it.pid, it.timestamp, it.reason, it.description) }) {
            TunnelLog.info("service.task_removal_liveness_skipped", mapOf("reason" to "android_stop"))
            return false
        }
        if (runningPid == watch.pid) {
            replace(context, watch, watch, RECHECK_DELAY_MILLIS)
            return false
        }
        if (VpnService.prepare(context) != null) return false
        // A replacement can be latest or stable. Bind for owner verification before transferring the watch.
        if (runningPid != null) return isRegistered(context, watch)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && !watch.waitedForExit &&
            history.none { it.pid == watch.pid && it.timestamp >= watch.sinceMillis }
        ) {
            // The process can disappear slightly before AMS publishes its exit
            // reason. Give a concurrent system Stop time to appear.
            replace(context, watch, watch.copy(waitedForExit = true), EXIT_RECORD_DELAY_MILLIS)
            return false
        }
        return isRegistered(context, watch)
    }

    private fun schedule(context: Context, scheduler: JobScheduler, watch: TaskRemovalVpnWatch, delayMillis: Long) {
        val job = JobInfo.Builder(
            VPN_TASK_REMOVAL_LIVENESS_JOB_ID,
            ComponentName(context, VpnTaskRemovalLivenessJobService::class.java),
        )
            .setExtras(watch.extras())
            .setMinimumLatency(delayMillis)
            .setOverrideDeadline(if (watch.deathSignalled) delayMillis else DEADLINE_MILLIS)
            .build()
        check(scheduler.schedule(job) == JobScheduler.RESULT_SUCCESS) {
            "vpn_task_removal_liveness_schedule_failed"
        }
    }

    @Suppress("DEPRECATION")
    fun foregroundVpnPid(context: Context): Int? =
        context.getSystemService(ActivityManager::class.java).getRunningServices(Int.MAX_VALUE)
            .firstOrNull {
                it.service.packageName == context.packageName &&
                    it.service.className == RuntimeServiceIntents.VPN_COMPONENT && it.foreground && it.pid > 0
            }?.pid

    private fun exitHistory(context: Context): List<ApplicationExitInfo> =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            context.getSystemService(ActivityManager::class.java)
                .getHistoricalProcessExitReasons(context.packageName, 0, 16)
        } else emptyList()
}

internal fun taskRemovalVpnIntent(context: Context, watch: TaskRemovalVpnWatch): Intent =
    watch.putInto(RuntimeServiceIntents.vpn(context).setAction(RuntimeServiceIntents.TASK_REMOVAL_LIVENESS))

class VpnTaskRemovalLivenessJobService : JobService() {
    private val handler = Handler(Looper.getMainLooper())
    private var recovery: RecoveryConnection? = null

    override fun onStartJob(parameters: JobParameters): Boolean {
        val watch = TaskRemovalVpnWatch.fromJob(parameters.extras) ?: return false
        if (watch.runtime == null) return false
        TunnelLog.initialize(applicationContext)
        closeRecovery()
        return beginRecovery(parameters, watch, retryUnansweredBind = true)
    }

    private fun beginRecovery(parameters: JobParameters, watch: TaskRemovalVpnWatch, retryUnansweredBind: Boolean): Boolean {
        val connection = RecoveryConnection(parameters, watch)
        recovery = connection
        try {
            if (!VpnTaskRemovalLiveness.needsDispatch(applicationContext, watch)) {
                closeRecovery()
                return false
            }
        } catch (error: Exception) {
            logFailure(error)
            handler.post { connection.complete(RuntimeServiceIntents.TASK_REMOVAL_RETRY) }
            return true
        }
        handler.postDelayed(connection.timeout, BIND_TIMEOUT_MILLIS)
        handler.post {
            if (recovery !== connection) return@post
            connection.bound = runCatching {
                bindService(taskRemovalVpnIntent(this, watch), connection, Context.BIND_AUTO_CREATE)
            }.onFailure(::logFailure).getOrDefault(false)
            if (!connection.bound) connection.complete(RuntimeServiceIntents.TASK_REMOVAL_RETRY)
            else if (retryUnansweredBind) handler.postDelayed(connection.retryBind, FIRST_BIND_RETRY_MILLIS)
        }
        return true
    }

    private inner class RecoveryConnection(
        val parameters: JobParameters,
        val watch: TaskRemovalVpnWatch,
    ) : ServiceConnection {
        var bound = false
        val timeout = Runnable { complete(RuntimeServiceIntents.TASK_REMOVAL_RETRY) }
        // Android may never deliver a callback if the target dies before publishing its Binder.
        // Release that binding once, then recheck the original watch and Stop before binding again.
        val retryBind = Runnable {
            if (recovery === this) {
                closeRecovery()
                if (!beginRecovery(parameters, watch, retryUnansweredBind = false)) jobFinished(parameters, false)
            }
        }

        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            if (recovery !== this) return
            handler.removeCallbacks(retryBind)
            try {
                if (VpnTaskRemovalLiveness.wasStoppedByAndroid(applicationContext, watch)) {
                    complete(RuntimeServiceIntents.TASK_REMOVAL_REJECTED)
                    return
                }
                val request = Message.obtain().apply {
                    data = requireNotNull(taskRemovalVpnIntent(this@VpnTaskRemovalLivenessJobService, watch).extras)
                    arg1 = VpnTaskRemovalLiveness.foregroundVpnPid(applicationContext) ?: 0
                    replyTo = Messenger(Handler(Looper.getMainLooper()) { response ->
                        complete(response.what)
                        true
                    })
                }
                Messenger(requireNotNull(binder)).send(request)
            } catch (error: Exception) {
                logFailure(error)
                complete(RuntimeServiceIntents.TASK_REMOVAL_RETRY)
            }
        }

        override fun onServiceDisconnected(name: ComponentName?) = complete(RuntimeServiceIntents.TASK_REMOVAL_RETRY)
        override fun onNullBinding(name: ComponentName?) = complete(RuntimeServiceIntents.TASK_REMOVAL_RETRY)
        override fun onBindingDied(name: ComponentName?) = complete(RuntimeServiceIntents.TASK_REMOVAL_RETRY)

        fun complete(result: Int) {
            if (recovery !== this) return
            when (result) {
                RuntimeServiceIntents.TASK_REMOVAL_ACCEPTED -> TunnelLog.info("service.task_removal_liveness_dispatched")
                RuntimeServiceIntents.TASK_REMOVAL_REJECTED ->
                    TunnelLog.info("service.task_removal_liveness_skipped", mapOf("reason" to "runtime_or_android_stop"))
                else -> TunnelLog.info("service.task_removal_liveness_retry")
            }
            closeRecovery()
            jobFinished(parameters, result == RuntimeServiceIntents.TASK_REMOVAL_RETRY)
        }
    }

    override fun onStopJob(parameters: JobParameters): Boolean {
        if (recovery?.parameters?.jobId != parameters.jobId) return false
        closeRecovery()
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return true
        return parameters.stopReason != JobParameters.STOP_REASON_CANCELLED_BY_APP &&
            parameters.stopReason != JobParameters.STOP_REASON_USER
    }

    override fun onDestroy() {
        closeRecovery()
        super.onDestroy()
    }

    private fun closeRecovery() {
        val current = recovery ?: return
        recovery = null
        handler.removeCallbacks(current.retryBind)
        handler.removeCallbacks(current.timeout)
        if (current.bound) unbindService(current)
    }

    private fun logFailure(error: Throwable) {
        TunnelLog.warning("service.task_removal_liveness_dispatch_failed", error = error)
    }
}

// Called in the broker process. All launches still go through the existing guarded job.
fun signalWatchedVpnProcessDeath(context: Context, pid: Int) {
    runCatching { VpnTaskRemovalLiveness.vpnProcessDied(context, pid) }
        .onFailure { TunnelLog.warning("service.vpn_death_signal_failed", error = it) }
}
