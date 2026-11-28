package ru.nelomai.tunnel

import android.app.ActivityManager
import android.app.ApplicationExitInfo
import android.app.job.JobInfo
import android.content.Context
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.content.ComponentName
import android.content.ContextWrapper
import android.content.Intent
import android.content.ServiceConnection
import android.net.VpnService
import android.os.Handler
import android.os.Looper
import android.os.Message
import android.os.Messenger
import org.json.JSONObject
import ru.nelomai.client.RuntimeDispatchPolicy
import ru.nelomai.client.RuntimeProcessSelection
import ru.nelomai.client.RuntimeSelectionStore
import ru.nelomai.client.RuntimeSelectionV1
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements
import org.robolectric.shadow.api.Shadow
import org.robolectric.shadows.ShadowActivityManager
import org.robolectric.shadows.ShadowProcess
import org.robolectric.shadows.ShadowVpnService
import org.robolectric.util.ReflectionHelpers
import ru.nelomai.runtime.v1.RuntimeServiceIntents
import ru.nelomai.runtime.v1.RuntimeVpnHostV1

// Android retains a running one-off JobInfo until its completion or replacement.
internal fun registerTestVpnWatch(context: Context, watch: TaskRemovalVpnWatch): JobInfo {
    val info = JobInfo.Builder(0x4e56504c, ComponentName(context, VpnTaskRemovalLivenessJobService::class.java))
        .setExtras(watch.extras()).setMinimumLatency(1_000L).build()
    assertEquals(JobScheduler.RESULT_SUCCESS, context.getSystemService(JobScheduler::class.java).schedule(info))
    return info
}

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE)
class RuntimeV2DispatchTest {
    @Test fun policyCancelRemainsAdmittedDuringPendingSwitchButApplyDoesNot() {
        val controller = Robolectric.buildService(VpnService::class.java).create()
        val host = controller.get()
        val engine = LatestRuntimeVpnEngineV1(object : RuntimeVpnHostV1 {
            override val service = host
            override fun builder(beforeEstablish: (VpnService.Builder) -> Unit) = host.Builder()
        })
        try {
            val loaded = ru.nelomai.client.RuntimeSelectionV1("latest", "0.3.0", "0.3.0", 7,
                null, "incarnation")
            val pending = loaded.copy(pendingSlot = "stable")
            assertFalse(ru.nelomai.client.RuntimeDispatchPolicy.mustExitProcess(loaded, pending))
            assertTrue(ru.nelomai.client.RuntimeDispatchPolicy.mayStop(loaded, pending))
            assertFalse(ru.nelomai.client.RuntimeDispatchPolicy.mayStart(pending))
            val cancel = RuntimeServiceIntents.vpn(host)
                .setAction(NelomaiVpnService.ACTION_CANCEL_OWNED_REDUNDANT_POLICY)
            val apply = RuntimeServiceIntents.vpn(host)
                .setAction(NelomaiVpnService.ACTION_APPLY_OWNED_REDUNDANT_POLICY)
            // Exercise the real engine classification and the dispatcher's real
            // admission predicate for a same-incarnation pending selection.
            assertTrue("cleanup cancellation was rejected as a new VPN start",
                !engine.requiresStartAdmission(cancel) || ru.nelomai.client.RuntimeDispatchPolicy.mayStart(pending))
            assertTrue(engine.requiresStartAdmission(apply))
            assertFalse(!engine.requiresStartAdmission(apply) || ru.nelomai.client.RuntimeDispatchPolicy.mayStart(pending))
            assertTrue(ru.nelomai.client.RuntimeDispatchPolicy.mustExitProcess(loaded,
                pending.copy(incarnation = "foreign")))
        } finally {
            controller.destroy()
        }
    }

    @Test fun redundantStandbyCleanupTargetsRuntimeDispatcher() {
        val context = RuntimeEnvironment.getApplication()

        TunnelServiceClient.releaseRedundantStandby(context, {}, {})

        val intent = shadowOf(context).nextStartedService
        assertEquals(
            ComponentName(context.packageName, RuntimeServiceIntents.VPN_COMPONENT),
            intent.component,
        )
        assertEquals(NelomaiVpnService.ACTION_RELEASE_REDUNDANT_STANDBY, intent.action)
        // Preference/cleanup dispatch does not establish VPN and must not require
        // foreground VPN admission while the tunnel is stopped.
        assertFalse(intent.getBooleanExtra(RuntimeServiceIntents.EXTRA_FOREGROUND_START, false))
    }

    @Test fun taskRemovalLivenessTargetsRuntimeDispatcher() {
        val context = RuntimeEnvironment.getApplication()
        val watch = TaskRemovalVpnWatch(pid = 79, sinceMillis = 1_500)

        val intent = taskRemovalVpnIntent(context, watch)
        assertEquals(
            ComponentName(context.packageName, RuntimeServiceIntents.VPN_COMPONENT),
            intent.component,
        )
        assertEquals(NelomaiVpnService.ACTION_TASK_REMOVAL_LIVENESS, intent.action)
        assertFalse(intent.getBooleanExtra(RuntimeServiceIntents.EXTRA_FOREGROUND_START, false))
        assertEquals(watch, TaskRemovalVpnWatch.fromIntent(intent))
    }

    @Test fun stickyReplacementVerifiesOwnershipBeforeRearmingForItsNextDeath() {
        val context = RuntimeEnvironment.getApplication()
        ShadowVpnService.setPrepareResult(null)
        ShadowProcess.setPid(222)
        val am = shadowOf(context.getSystemService(ActivityManager::class.java))
        val running = ActivityManager.RunningServiceInfo().apply {
            service = ComponentName(context.packageName, RuntimeServiceIntents.VPN_COMPONENT)
            pid = android.os.Process.myPid()
            foreground = true
        }
        am.setServices(listOf(running))
        val watch = TaskRemovalVpnWatch(running.pid + 1, 1_500, waitedForExit = true, runtime = "watch")
        registerTestVpnWatch(context, watch)
        assertTrue("a new foreground PID requires dispatcher admission", VpnTaskRemovalLiveness.needsDispatch(context, watch))
        VpnTaskRemovalLiveness.continueAfterRestore(context, watch)
        val jobs = context.getSystemService(JobScheduler::class.java)
        val successor = requireNotNull(TaskRemovalVpnWatch.fromJob(jobs.allPendingJobs.single().extras))
        assertEquals(watch.copy(pid = running.pid, waitedForExit = false), successor)
        assertFalse("a live admitted PID only rearms", VpnTaskRemovalLiveness.needsDispatch(context, successor))

        am.setServices(emptyList())
        assertFalse("wait for the new process's own exit record", VpnTaskRemovalLiveness.needsDispatch(context, successor))
        val delayed = requireNotNull(TaskRemovalVpnWatch.fromJob(jobs.allPendingJobs.single().extras))
        assertTrue(VpnTaskRemovalLiveness.needsDispatch(context, delayed))
    }

    @Test
    @Config(shadows = [LivenessQueryActivityManager::class])
    fun healthyJobCannotRearmAfterStopCancelsItsWatchDuringThePidQuery() = withHealthyWatch { job, params, scheduler ->
        val context = RuntimeEnvironment.getApplication()
        LivenessQueryActivityManager.afterServiceSnapshot = {
            // The old JobInfo is still registered while onStartJob is running.
            requireNotNull(scheduler.getPendingJob(params.jobId))
            VpnTaskRemovalLiveness.cancel(context)
        }

        assertFalse(job.onStartJob(params))

        assertNull("a cancelled watch must not be scheduled again", scheduler.getPendingJob(params.jobId))
    }

    @Test
    @Config(shadows = [LivenessQueryActivityManager::class])
    fun healthyJobCannotReplaceANewerWatchInstalledDuringThePidQuery() = withHealthyWatch { job, params, scheduler ->
        val context = RuntimeEnvironment.getApplication()
        val old = requireNotNull(TaskRemovalVpnWatch.fromJob(params.extras))
        var newer: TaskRemovalVpnWatch? = null
        LivenessQueryActivityManager.afterServiceSnapshot = {
            requireNotNull(scheduler.getPendingJob(params.jobId))
            registerTestVpnWatch(context, old.copy(sinceMillis = old.sinceMillis + 1, runtime = "newer"))
            newer = TaskRemovalVpnWatch.fromJob(requireNotNull(scheduler.getPendingJob(params.jobId)).extras)
        }

        assertFalse(job.onStartJob(params))

        assertEquals("an older job must not overwrite the replacement", requireNotNull(newer),
            TaskRemovalVpnWatch.fromJob(requireNotNull(scheduler.getPendingJob(params.jobId)).extras))
    }

    @Test
    @Config(shadows = [LivenessQueryActivityManager::class])
    fun currentHealthyJobRearmsItsWatch() = withHealthyWatch { job, params, scheduler ->
        val initial = requireNotNull(scheduler.getPendingJob(params.jobId))
        val old = requireNotNull(TaskRemovalVpnWatch.fromJob(params.extras))

        assertFalse(job.onStartJob(params))

        // Robolectric keeps the registered JobInfo object until schedule() replaces it.
        val rearmed = requireNotNull(scheduler.getPendingJob(params.jobId))
        assertNotSame("a healthy watch needs a successor", initial, rearmed)
        val current = requireNotNull(TaskRemovalVpnWatch.fromJob(rearmed.extras))
        assertEquals(old.pid, current.pid)
        assertEquals(old.sinceMillis, current.sinceMillis)
        assertEquals(old.runtime, current.runtime)
    }

    private fun withHealthyWatch(block: (VpnTaskRemovalLivenessJobService, JobParameters, JobScheduler) -> Unit) {
        val context = RuntimeEnvironment.getApplication()
        val previousPid = android.os.Process.myPid()
        ShadowProcess.setPid(222)
        ShadowVpnService.setPrepareResult(null)
        val scheduler = context.getSystemService(JobScheduler::class.java)
        VpnTaskRemovalLiveness.cancel(context)
        val watch = TaskRemovalVpnWatch(android.os.Process.myPid(), 1_500, runtime = "older")
        val registered = registerTestVpnWatch(context, watch)
        val params = Shadow.newInstanceOf(JobParameters::class.java)
        ReflectionHelpers.setField(params, "extras", registered.extras)
        ReflectionHelpers.setField(params, "jobId", registered.id)
        val activityManager = shadowOf(context.getSystemService(ActivityManager::class.java))
        activityManager.setServices(listOf(ActivityManager.RunningServiceInfo().apply {
            service = ComponentName(context.packageName, RuntimeServiceIntents.VPN_COMPONENT)
            pid = watch.pid
            foreground = true
        }))
        val controller = Robolectric.buildService(VpnTaskRemovalLivenessJobService::class.java).create()
        try {
            block(controller.get(), params, scheduler)
        } finally {
            LivenessQueryActivityManager.afterServiceSnapshot = null
            controller.destroy()
            VpnTaskRemovalLiveness.cancel(context)
            ShadowProcess.setPid(previousPid)
        }
    }

    @Test fun deathSignalAcceleratesOnlyTheCurrentWatchAndOutracesAHealthyJob() = withHealthyWatch { job, params, scheduler ->
        val watch = requireNotNull(TaskRemovalVpnWatch.fromJob(params.extras))
        fun current() = requireNotNull(scheduler.getPendingJob(params.jobId))
        VpnTaskRemovalLiveness.vpnProcessDied(job, watch.pid + 1)
        assertEquals(1_000L, current().minLatencyMillis)

        VpnTaskRemovalLiveness.vpnProcessDied(job, watch.pid)
        val immediate = current()
        assertEquals(0L, immediate.maxExecutionDelayMillis)
        assertEquals(0L, immediate.minLatencyMillis)
        assertFalse(job.onStartJob(params))
        val signalled = watch.copy(deathSignalled = true)
        assertEquals(signalled, TaskRemovalVpnWatch.fromJob(immediate.extras))
        assertEquals(signalled, TaskRemovalVpnWatch.fromJob(current().extras))
        assertEquals(0L, current().maxExecutionDelayMillis)

        VpnTaskRemovalLiveness.cancel(job)
        VpnTaskRemovalLiveness.vpnProcessDied(job, watch.pid)
        assertNull(scheduler.getPendingJob(params.jobId))
    }

    @Test fun binderDeathWithStaleForegroundPidStillWaitsForAndroidStopHistory() = withHealthyWatch { job, params, scheduler ->
        val watch = requireNotNull(TaskRemovalVpnWatch.fromJob(params.extras))
        VpnTaskRemovalLiveness.vpnProcessDied(job, watch.pid)
        fun current() = requireNotNull(scheduler.getPendingJob(params.jobId))
        val signalled = requireNotNull(TaskRemovalVpnWatch.fromJob(current().extras))
        assertFalse(VpnTaskRemovalLiveness.needsDispatch(job, signalled))
        val grace = requireNotNull(TaskRemovalVpnWatch.fromJob(current().extras))
        assertEquals(signalled.copy(waitedForExit = true), grace)
        assertEquals(5_000L, current().maxExecutionDelayMillis)
        val exit = ShadowActivityManager.ApplicationExitInfoBuilder.newBuilder()
            .setPid(watch.pid).setProcessName(job.packageName + ":vpn").setTimestamp(watch.sinceMillis + 1)
            .setReason(android.app.ApplicationExitInfo.REASON_USER_REQUESTED).setDescription("[STOP APP] fully stop").build()
        shadowOf(job.getSystemService(ActivityManager::class.java)).addApplicationExitInfo(exit)
        assertFalse(VpnTaskRemovalLiveness.needsDispatch(job, grace))
    }

    @Test fun preemptedJobRetriesItsOriginalWatchAndAppCancellationEndsIt() {
        val job = Robolectric.buildService(VpnTaskRemovalLivenessJobService::class.java).create().get()
        ShadowVpnService.setPrepareResult(null)
        val params = Shadow.newInstanceOf(JobParameters::class.java)
        ReflectionHelpers.setField(params, "extras", TaskRemovalVpnWatch(77, 1_500, true, "watch").extras())
        ReflectionHelpers.setField(params, "jobId", registerTestVpnWatch(job, requireNotNull(TaskRemovalVpnWatch.fromJob(params.extras))).id)
        ReflectionHelpers.setField(params, "mStopReason", JobParameters.STOP_REASON_PREEMPT)
        assertTrue(job.onStartJob(params))
        assertTrue(job.onStopJob(params))
        val context = RuntimeEnvironment.getApplication()
        val watch = requireNotNull(TaskRemovalVpnWatch.fromJob(params.extras))
        val binder = Messenger(Handler(Looper.getMainLooper()) { request ->
            request.replyTo.send(Message.obtain(null, RuntimeServiceIntents.TASK_REMOVAL_ACCEPTED))
            true
        })
        val intent = taskRemovalVpnIntent(context, watch)
        shadowOf(context).setComponentNameAndServiceForBindServiceForIntent(intent, intent.component, binder.binder)
        assertTrue("system can run the same watch again", job.onStartJob(params))
        shadowOf(Looper.getMainLooper()).idle()
        assertTrue(shadowOf(job).isJobFinished)
        assertFalse(shadowOf(job).isRescheduleNeeded)

        assertTrue(job.onStartJob(params))
        ReflectionHelpers.setField(params, "mStopReason", JobParameters.STOP_REASON_CANCELLED_BY_APP)
        assertFalse(job.onStopJob(params))
    }

    private fun withSilentFirstBind(
        check: (VpnTaskRemovalLivenessJobService, List<ServiceConnection>) -> Unit,
    ) {
        ShadowVpnService.setPrepareResult(null)
        val controller = Robolectric.buildService(VpnTaskRemovalLivenessJobService::class.java).create()
        val job = controller.get()
        val bindings = mutableListOf<ServiceConnection>()
        val context = object : ContextWrapper(job.baseContext) {
            override fun bindService(intent: Intent, callback: ServiceConnection, flags: Int): Boolean {
                bindings += callback
                return true
            }
            override fun unbindService(connection: ServiceConnection) = Unit
        }
        ReflectionHelpers.setField(job, "mBase", context)
        val info = registerTestVpnWatch(job, TaskRemovalVpnWatch(77, 1_500, true, "watch", true))
        val params = Shadow.newInstanceOf(JobParameters::class.java)
        ReflectionHelpers.setField(params, "extras", info.extras)
        ReflectionHelpers.setField(params, "jobId", info.id)
        try {
            assertTrue(job.onStartJob(params))
            shadowOf(Looper.getMainLooper()).idle()
            assertEquals(1, bindings.size)
            check(job, bindings)
        } finally {
            controller.destroy()
            VpnTaskRemovalLiveness.cancel(job)
        }
    }

    @Test fun lostProcessBeforeBindGetsOnePromptRetryAndOnlyCurrentBindingCanDispatch() =
        withSilentFirstBind { job, bindings ->
            val main = shadowOf(Looper.getMainLooper())
            main.idleFor(java.time.Duration.ofSeconds(3))
            assertEquals("silent first bind should already have been replaced", 2, bindings.size)
            var requests = 0
            var replyTo: Messenger? = null
            val target = Messenger(Handler(Looper.getMainLooper()) {
                requests++
                replyTo = it.replyTo
                true
            })
            val name = ComponentName(job, RuntimeServiceIntents.VPN_COMPONENT)
            bindings.first().onServiceConnected(name, target.binder)
            bindings.last().onServiceConnected(name, target.binder)
            main.idleFor(java.time.Duration.ofSeconds(12))
            assertEquals(1, requests)
            assertEquals(2, bindings.size)
            assertFalse(shadowOf(job).isJobFinished)
            requireNotNull(replyTo).send(Message.obtain(null, RuntimeServiceIntents.TASK_REMOVAL_ACCEPTED))
            main.idle()
            assertTrue(shadowOf(job).isJobFinished)
            assertFalse(shadowOf(job).isRescheduleNeeded)
        }

    @Test fun cancelledWatchCannotRebindAfterASilentFirstBind() = withSilentFirstBind { job, bindings ->
        VpnTaskRemovalLiveness.cancel(job)
        shadowOf(Looper.getMainLooper()).idleFor(java.time.Duration.ofSeconds(4))
        assertEquals(1, bindings.size)
        assertTrue(shadowOf(job).isJobFinished)
        assertFalse(shadowOf(job).isRescheduleNeeded)
    }

    @Test fun slowReplyOnOriginalBindingDoesNotReplayTheRequest() = withSilentFirstBind { job, bindings ->
        val main = shadowOf(Looper.getMainLooper())
        var requests = 0
        val target = Messenger(Handler(Looper.getMainLooper()) { request ->
            requests++
            val reply = request.replyTo
            Handler(Looper.getMainLooper()).postDelayed({
                reply.send(Message.obtain(null, RuntimeServiceIntents.TASK_REMOVAL_ACCEPTED))
            }, 12_000)
            true
        })
        bindings.single().onServiceConnected(ComponentName(job, RuntimeServiceIntents.VPN_COMPONENT), target.binder)
        main.idleFor(java.time.Duration.ofSeconds(13))
        assertEquals(1, bindings.size)
        assertEquals(1, requests)
        assertTrue(shadowOf(job).isJobFinished)
        assertFalse(shadowOf(job).isRescheduleNeeded)
    }

    @Test fun twoSilentBindsReturnControlToTheScheduler() = withSilentFirstBind { job, bindings ->
        shadowOf(Looper.getMainLooper()).idleFor(java.time.Duration.ofSeconds(35))
        assertEquals(2, bindings.size)
        assertTrue(shadowOf(job).isJobFinished)
        assertTrue(shadowOf(job).isRescheduleNeeded)
    }

    @Test fun taskRemovalSystemStopIsScopedToThisWatch() {
        val packageName = "ru.nelomai.client"
        val watch = TaskRemovalVpnWatch(pid = 79, sinceMillis = 1_500)
        val userRequested = android.app.ApplicationExitInfo.REASON_USER_REQUESTED
        val signaled = android.app.ApplicationExitInfo.REASON_SIGNALED
        assertFalse(watch.blocksRecovery(packageName, 79, 1_499, userRequested, "[STOP APP]"))
        assertTrue(watch.blocksRecovery(packageName, 102, 1_500, userRequested, "[STOP APP] fully stop"))
        assertTrue(watch.blocksRecovery("$packageName:vpn", 79, 1_501, userRequested, null))
        assertFalse(watch.blocksRecovery("$packageName:vpn", 79, 1_501, userRequested, "[REMOVE TASK] remove task"))
        assertFalse(watch.blocksRecovery(packageName, 102, 1_501, userRequested, "[REMOVE TASK] remove task"))
        assertFalse(watch.blocksRecovery("$packageName:vpn", 79, 1_501, signaled, null))
    }

    @Test fun oldTaskRemovalCannotStartVpnInTheStableRuntimeOrDuringHandoff() {
        val selection = RuntimeSelectionV1(
            "latest", BuildConfig.RUNTIME_VERSION, BuildConfig.RUNTIME_VERSION, 7, null, "incarnation",
        )
        val latest = RuntimeSelectionStore.decode(JSONObject(RuntimeSelectionStore.encode(selection))
            .put("vpn_authorization", JSONObject().put("scope", "a".repeat(64)).put("blocked", false)).toString())
        assertTrue(mayDispatchTaskRemovalVpnRecovery(latest))
        assertFalse(mayDispatchTaskRemovalVpnRecovery(latest.copy(slot = "stable")))
        assertFalse(mayDispatchTaskRemovalVpnRecovery(latest.copy(pendingSlot = "stable")))
        assertFalse(mayDispatchTaskRemovalVpnRecovery(latest.copy(sessionGeneration = null)))
        assertFalse(mayDispatchTaskRemovalVpnRecovery(latest.copy(runtimeVersion = "other")))
    }

    @Test fun swipePersistsTheAdmittedScopeForBrokerRecovery() {
        val context = RuntimeEnvironment.getApplication()
        val selection = RuntimeSelectionV1("latest", BuildConfig.RUNTIME_VERSION, BuildConfig.RUNTIME_VERSION,
            7, null, "broker")
        fun authorized(incarnation: String, scope: String): RuntimeSelectionV1 = RuntimeSelectionStore.decode(
            JSONObject(RuntimeSelectionStore.encode(selection.copy(incarnation = incarnation))).put("vpn_authorization",
                JSONObject().put("scope", scope.repeat(64)).put("blocked", false)).toString(),
        )
        try {
            ShadowProcess.setPid(111)
            RuntimeProcessSelection.rememberVpnOwner(authorized("broker", "a"))
            VpnTaskRemovalLiveness.schedule(context) { true }
            val job = context.getSystemService(JobScheduler::class.java).allPendingJobs.single()
            val watch = requireNotNull(TaskRemovalVpnWatch.fromJob(job.extras))
            val storedOwner = RuntimeSelectionStore.decode(requireNotNull(watch.runtime))
            assertTrue(RuntimeDispatchPolicy.mayRecoverLatestVpn(storedOwner, authorized("next-broker", "a")))
            assertFalse(RuntimeDispatchPolicy.mayRecoverLatestVpn(storedOwner, authorized("broker", "b")))
        } finally {
            RuntimeProcessSelection.clearVpnOwner()
        }
    }

    @Test fun stickyRestartOnlyTransfersAnExistingAuthorizedWatch() {
        val context = RuntimeEnvironment.getApplication()
        val jobs = context.getSystemService(JobScheduler::class.java)
        val selection = RuntimeSelectionV1("latest", BuildConfig.RUNTIME_VERSION, BuildConfig.RUNTIME_VERSION,
            7, null, "broker")
        fun owner(scope: String, broker: String) = RuntimeSelectionStore.decode(
            JSONObject(RuntimeSelectionStore.encode(selection.copy(incarnation = broker)))
                .put("vpn_authorization", JSONObject().put("scope", scope.repeat(64)).put("blocked", false)).toString())
        val watch = TaskRemovalVpnWatch(101, 1_500, waitedForExit = true,
            runtime = RuntimeSelectionStore.encodeVpnRecoveryOwner(owner("a", "old")), deathSignalled = true)
        val job = registerTestVpnWatch(context, watch)
        fun current() = jobs.getPendingJob(job.id)?.let { TaskRemovalVpnWatch.fromJob(it.extras) }
        try {
            ShadowProcess.setPid(202)
            RuntimeProcessSelection.rememberVpnOwner(owner("b", "new"))
            VpnTaskRemovalLiveness.followStickyRestart(context)
            assertEquals(watch, current())

            RuntimeProcessSelection.clearVpnOwner()
            RuntimeProcessSelection.rememberVpnOwner(owner("a", "new"))
            VpnTaskRemovalLiveness.followStickyRestart(context)
            val transferred = watch.copy(pid = 202, waitedForExit = false, deathSignalled = false)
            assertEquals(transferred, current())
            VpnTaskRemovalLiveness.vpnProcessDied(context, 101)
            assertEquals(transferred, current())
            VpnTaskRemovalLiveness.vpnProcessDied(context, 202)
            assertEquals(transferred.copy(deathSignalled = true), current())

            registerTestVpnWatch(context, watch)
            val stop = ShadowActivityManager.ApplicationExitInfoBuilder.newBuilder()
                .setPid(101).setProcessName(context.packageName + ":vpn").setTimestamp(1_501)
                .setReason(ApplicationExitInfo.REASON_USER_REQUESTED).setDescription("[STOP APP]").build()
            shadowOf(context.getSystemService(ActivityManager::class.java)).addApplicationExitInfo(stop)
            VpnTaskRemovalLiveness.followStickyRestart(context)
            assertEquals(watch, current())
            VpnTaskRemovalLiveness.cancel(context)
            VpnTaskRemovalLiveness.followStickyRestart(context)
            assertNull(current())
        } finally {
            RuntimeProcessSelection.clearVpnOwner()
        }
    }

    @Test fun systemStopProjectsOffWhenThePreviousProcessPersistedStopping() {
        val context = RuntimeEnvironment.getApplication()
        android.provider.Settings.Global.putInt(context.contentResolver, android.provider.Settings.Global.BOOT_COUNT, 7)
        assertTrue(AndroidRecoveryStores.open(context).read() is RecoveryStoreResult.Success)
        assertTrue(QuickTunnelController.updateState(context, SessionState.STOPPING))
        val pid = android.os.Process.myPid()
        val exit = org.robolectric.shadows.ShadowActivityManager.ApplicationExitInfoBuilder.newBuilder()
            .setPid(pid).setProcessName(context.packageName + ":vpn")
            .setTimestamp(System.currentTimeMillis() + 1)
            .setReason(android.app.ApplicationExitInfo.REASON_USER_REQUESTED)
            .setDescription("[STOP APP] fully stop").build()
        shadowOf(context.getSystemService(android.app.ActivityManager::class.java)).addApplicationExitInfo(exit)

        assertEquals("stopped", QuickTunnelController.state(context))
        assertTrue(QuickTunnelController.isPausedByAndroid(context))
    }

    @Test fun taskManagerStopProjectsOffWithoutConsumingTheExplicitResume() {
        val updatedAt = 1_500L
        val stopAt = 1_600L
        assertFalse(isTaskManagerStop(updatedAt, stopAt, android.app.ApplicationExitInfo.REASON_USER_REQUESTED,
            "[REMOVE TASK] remove task"))
        assertTrue(isTaskManagerStop(updatedAt, stopAt, android.app.ApplicationExitInfo.REASON_USER_REQUESTED,
            "[STOP APP] fully stop"))
        assertFalse(isTaskManagerStop(stopAt+1, stopAt, android.app.ApplicationExitInfo.REASON_USER_REQUESTED,
            "[STOP APP] fully stop"))
        assertEquals(SessionState.STOPPED, QuickTunnelController.resolveState(
            SessionState.STOPPED, SessionState.RUNNING, updatedAt, 1_700, stoppedByAndroid = true,
        ))
        assertEquals(SessionState.RUNNING, QuickTunnelController.resolveState(
            SessionState.STOPPED, SessionState.RUNNING, updatedAt, 1_700, stoppedByAndroid = false,
        ))
    }

    @Test fun redundantStandbyCleanupBypassesStartAdmission() {
        val controller = Robolectric.buildService(VpnService::class.java).create()
        val host = controller.get()
        val engine = LatestRuntimeVpnEngineV1(object : RuntimeVpnHostV1 {
            override val service = host
            override fun builder(beforeEstablish: (VpnService.Builder) -> Unit) = host.Builder()
        })
        try {
            assertFalse(
                engine.requiresStartAdmission(
                    RuntimeServiceIntents.vpn(host)
                        .setAction(NelomaiVpnService.ACTION_RELEASE_REDUNDANT_STANDBY),
                ),
            )
        } finally {
            controller.destroy()
        }
    }
}

@Implements(ActivityManager::class)
class LivenessQueryActivityManager : ShadowActivityManager() {
    @Implementation
    override fun getRunningServices(maxNum: Int): MutableList<ActivityManager.RunningServiceInfo> {
        val snapshot = super.getRunningServices(maxNum)
        // Model a concurrent Stop or replacement after AMS captured the running PID.
        afterServiceSnapshot?.let { callback ->
            afterServiceSnapshot = null
            callback()
        }
        return snapshot
    }

    companion object { var afterServiceSnapshot: (() -> Unit)? = null }
}
