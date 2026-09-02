package ru.nelomai.tunnel

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat

private const val VPN_TASK_REMOVAL_LIVENESS_JOB_ID = 0x4e56504c
private const val VPN_TASK_REMOVAL_LIVENESS_DELAY_MILLIS = 15_000L
private const val VPN_TASK_REMOVAL_LIVENESS_DEADLINE_MILLIS = 60_000L

internal object VpnTaskRemovalLiveness {
    fun schedule(context: Context) {
        val job = JobInfo.Builder(
            VPN_TASK_REMOVAL_LIVENESS_JOB_ID,
            ComponentName(context, VpnTaskRemovalLivenessJobService::class.java),
        )
            .setMinimumLatency(VPN_TASK_REMOVAL_LIVENESS_DELAY_MILLIS)
            .setOverrideDeadline(VPN_TASK_REMOVAL_LIVENESS_DEADLINE_MILLIS)
            .build()
        val scheduler = context.getSystemService(JobScheduler::class.java)
        check(scheduler.schedule(job) == JobScheduler.RESULT_SUCCESS) {
            "vpn_task_removal_liveness_schedule_failed"
        }
        TunnelLog.info("service.task_removal_liveness_scheduled")
    }
}

internal fun dispatchScheduledTaskRemovalLiveness(
    dispatch: () -> Unit,
): Result<Unit> = runCatching(dispatch)

class VpnTaskRemovalLivenessJobService : JobService() {
    override fun onStartJob(parameters: JobParameters): Boolean {
        TunnelLog.initialize(applicationContext)
        // The default process cannot safely gate this dispatch on SharedPreferences
        // written by :vpn. The VPN service rechecks its durable intent on receipt.
        dispatchScheduledTaskRemovalLiveness {
            ContextCompat.startForegroundService(
                applicationContext,
                Intent(applicationContext, NelomaiVpnService::class.java)
                    .setAction(NelomaiVpnService.ACTION_TASK_REMOVAL_LIVENESS),
            )
        }.onSuccess {
            TunnelLog.info("service.task_removal_liveness_dispatched")
        }.onFailure { error ->
            TunnelLog.warning("service.task_removal_liveness_dispatch_failed", error = error)
        }
        return false
    }

    override fun onStopJob(parameters: JobParameters): Boolean = false
}
