package ru.nelomai.client

import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.Bundle
import android.os.IBinder
import android.os.Messenger
import android.os.Message
import android.os.ResultReceiver
import android.os.SystemClock
import java.util.UUID
import org.json.JSONObject
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import ru.nelomai.runtime.v1.RuntimeVpnEngineV1
import ru.nelomai.runtime.v1.RuntimeVpnHostV1
import ru.nelomai.runtime.v1.RuntimeVpnAuthorityV1
import ru.nelomai.runtime.v1.RuntimeVpnTransportV1
import ru.nelomai.runtime.v1.RuntimeServiceIntents
import ru.nelomai.runtime.v1.VpnNotificationChannel

class RuntimeVpnDispatcherService : VpnService(), RuntimeVpnHostV1, RuntimeVpnAuthorityV1 {
    private companion object {
        const val BROKER_RECOVERY_MILLIS = 10_000L
        // A destroyed Service does not prove that every old engine executor
        // has exited. Only physical :vpn process exit resets this marker.
        var engineWasLoaded = false
        val processToken = android.os.Binder()
    }
    override val service: VpnService get() = this
    private lateinit var selection: RuntimeSelectionStore
    @Volatile private var engine: RuntimeVpnEngineV1? = null
    @Volatile private var destroyed = false
    private var selectionVerificationInFlight = false
    private class TaskRemovalAdmission(
        val token: String,
        val owner: RuntimeSelectionV1,
        val stopRevision: Long,
        val respond: (Int) -> Unit,
        var delivered: Boolean = false,
    )

    private var taskRemovalAdmission: TaskRemovalAdmission? = null
    private var lastStartId = 0
    private var lastCommandStartId = 0
    private var lastEngineStartId = 0
    private var pendingStartReads = 0
    private var stopRevision = 0L
    private var pendingStableTileStart: Long? = null
    private val waitingStartsAndToggles = mutableSetOf<Intent>()
    @Volatile private var lastBrokerVerificationAt = 0L
    @Volatile private var retirementStarted = false
    @Volatile private var revokedByAndroid = false
    private val watchdogLock = Any()
    private var vpnWatchdog: Handler? = null
    private var retirementTimeoutArmed = false
    private var forwardedLogoutEpoch: Long? = null
    private var logoutRetryAt = 0L
    private val handler = Handler(Looper.getMainLooper())
    private val verifySelection = object : Runnable {
        override fun run() {
            if (destroyed) return
            val now = SystemClock.uptimeMillis()
            if (RuntimeProcessSelection.hasVpnOwner() && !retirementStarted &&
                now - lastBrokerVerificationAt >= BROKER_RECOVERY_MILLIS
            ) {
                beginRetirement()
                engine?.revoke()
            }
            if (!selectionVerificationInFlight) {
                selectionVerificationInFlight = true
                selection.read { result ->
                    selectionVerificationInFlight = false
                    if (!destroyed && engine != null) result.getOrNull()?.let { active ->
                        if (acceptSelection(active) && active.slot == "latest" &&
                            RuntimeDispatchPolicy.vpnLogoutEpoch(active) != null
                        ) retireVpn(active)
                    }
                }
            }
            if (!destroyed) handler.postDelayed(this, 1000)
        }
    }

    override fun onCreate() {
        super.onCreate()
        selection = RuntimeSelectionStore(this, vpnProcessToken = processToken)
        handler.post(verifySelection)
    }

    private fun promoteToForeground() {
        VpnNotificationChannel.create(this)
        ServiceCompat.startForeground(this, 1701, NotificationCompat.Builder(this, VpnNotificationChannel.ID)
            .setSmallIcon(R.drawable.ic_quick_tile).setContentTitle("Nelomai VPN").setOngoing(true).build(),
            if (Build.VERSION.SDK_INT >= 34) android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED else 0)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        lastStartId = startId
        val action = tunnelAction(intent)
        val liveness = action == RuntimeServiceIntents.TASK_REMOVAL_LIVENESS
        val preparedRecovery = if (liveness) taskRemovalAdmission?.takeIf {
            !it.delivered && it.token == intent?.getStringExtra(RuntimeServiceIntents.TASK_REMOVAL_START_ID)
        } else null
        if (liveness && preparedRecovery == null) {
            // AMS can retry a start prepared in a process that has since died.
            // Its ID advances even though it has no authority to start an engine.
            if (engine == null && taskRemovalAdmission == null && pendingStartReads == 0) {
                stopSelf(startId)
                return START_NOT_STICKY
            }
            (engine as? RuntimeVpnTransportV1)?.retiredStartRejected(startId)
            return START_STICKY
        }
        lastCommandStartId = startId
        preparedRecovery?.delivered = true
        val scopedClick = intent?.hasExtra(RuntimeServiceIntents.EXTRA_TILE_CLICK_REVISION) == true
        val admittedOwner = RuntimeProcessSelection.tileOwner()
        if (isTeardownCommand(intent) && !tileClickIsCurrent(intent, admittedOwner)) {
            if (engine == null) stopSelf(androidStartId(startId))
            return START_NOT_STICKY
        }
        if (invalidatesWaitingStarts(intent) && (!scopedClick || admittedOwner != null)) stopRevision++
        val waitingCommand = intent?.takeIf {
            action == "ru.nelomai.tunnel.CLIENT_START" ||
                (action == RuntimeServiceIntents.QUICK_TOGGLE && !isTeardownCommand(it))
        }
        if (action == "ru.nelomai.tunnel.CANCEL_CLIENT_START") {
            intent?.getStringExtra("client_operation_id")?.let { operationId ->
                waitingStartsAndToggles.removeAll {
                    tunnelAction(it) == "ru.nelomai.tunnel.CLIENT_START" &&
                        it.getStringExtra("client_operation_id") == operationId
                }
            }
        }
        val admissionRevision = stopRevision
        // A status/read request is not a foreground-service launch.
        val foregroundRequested = !liveness && (intent == null ||
            intent.getBooleanExtra(RuntimeServiceIntents.EXTRA_FOREGROUND_START, false))
        val current = engine
        if (current == null && action == "ru.nelomai.tunnel.BEGIN_BACKGROUND_LOGOUT") {
            // The broker persisted Logout before delivering this command.
            // A snapshot taken before it must not admit a waiting cold Start.
            selection.invalidatePendingSnapshot()
        }
        if (!foregroundRequested && current != null &&
            (RuntimeProcessSelection.hasVpnOwner() || action == RuntimeServiceIntents.CLIENT_STOP ||
                (scopedClick && admittedOwner?.slot == "stable")) &&
            isTeardownCommand(intent) && !current.requiresStartAdmission(intent)
        ) {
            // These commands can only tear down state already owned by this
            // engine. They must reach it even when the common broker is offline.
            runCatching { startEngine(current, intent, flags, startId) }.onFailure {
                rejectStart(intent, "runtime_teardown_failed")
            }
            return START_STICKY
        }
        // Real FGS launches must be acknowledged before waiting for Binder.
        val foregroundPromotionFailed = foregroundRequested && (
            VpnService.prepare(this) != null ||
                try {
                    promoteToForeground()
                    false
                } catch (_: SecurityException) {
                    true
                }
        )
        if (foregroundPromotionFailed && definitelyStartsVpn(intent) && intent != null &&
            action != "ru.nelomai.tunnel.TASK_REMOVAL_LIVENESS" &&
            action != "ru.nelomai.tunnel.ENSURE_RUNNING"
        ) {
            rejectStart(intent, "vpn_permission_required")
            if (retirementStarted) settleRetiredStartIds() else stopSelf(androidStartId(startId))
            return START_NOT_STICKY
        }
        if (waitingCommand != null) waitingStartsAndToggles += waitingCommand
        pendingStartReads++
        selection.read { result ->
            var recoveryResult = RuntimeServiceIntents.TASK_REMOVAL_REJECTED
            try {
                val cancelled = waitingCommand != null && !waitingStartsAndToggles.remove(waitingCommand)
                if (destroyed) return@read
                val active = result.getOrElse {
                    if (preparedRecovery?.stopRevision == stopRevision && vpnAuthorityCurrent()) {
                        recoveryResult = RuntimeServiceIntents.TASK_REMOVAL_RETRY
                    }
                    rejectStart(intent, "runtime_owner_unavailable")
                    if (!retirementStarted && !RuntimeProcessSelection.hasVpnOwner()) stopSelf(androidStartId(startId))
                    return@read
                }
                try {
                    if (preparedRecovery != null &&
                        (preparedRecovery.stopRevision != stopRevision || VpnService.prepare(this) != null ||
                            !RuntimeDispatchPolicy.mayRecoverLatestVpn(preparedRecovery.owner, active))
                    ) {
                        if (engine == null) stopSelf(androidStartId(startId))
                        return@read
                    }
                    if (!tileClickIsCurrent(intent, active)) {
                        if (engine == null) stopSelf(androidStartId(startId))
                        return@read
                    }
                    if (intent?.hasExtra(RuntimeServiceIntents.EXTRA_QUICK_START_OWNER) == true) {
                        val owner = runCatching { RuntimeSelectionStore.decode(requireNotNull(
                            intent.getStringExtra(RuntimeServiceIntents.EXTRA_QUICK_START_OWNER))) }.getOrNull()
                        if (owner == null || !RuntimeDispatchPolicy.mayRecoverLatestVpn(owner, active)) {
                            rejectStart(intent, "runtime_start_cancelled")
                            if (engine == null) stopSelf(androidStartId(startId))
                            return@read
                        }
                    }
                    if (!acceptSelection(active)) { rejectStart(intent); return@read }
                    val selectedEngine = engine ?: run {
                        if (active.slot == "stable" && !engineWasLoaded) {
                            try {
                                ru.nelomai.tunnel.StableBackgroundProvision.prepareEngine(this, active.runtimeVersion)
                            } catch (error: Exception) {
                                rejectStart(intent, "background_credential_unavailable")
                                throw error
                            }
                        }
                        engineWasLoaded = true
                        RuntimeAdapters.engine(active, this)
                    }.also {
                        engine = it; it.create()
                    }
                    if (active.slot == "latest" && RuntimeDispatchPolicy.vpnLogoutEpoch(active) != null) {
                        retireVpn(active)
                        if (!isTeardownCommand(intent)) {
                            rejectStart(intent)
                            return@read
                        }
                    }
                    val requiresStartAdmission = selectedEngine.requiresStartAdmission(intent)
                    if (!vpnAuthorityCurrent() && !isTeardownCommand(intent)) {
                        rejectStart(intent, "runtime_vpn_authority_retired")
                        return@read
                    }
                    if (cancelled || (admissionRevision != stopRevision &&
                            (requiresStartAdmission || (waitingCommand != null && action == RuntimeServiceIntents.QUICK_TOGGLE)))
                    ) {
                        rejectStart(intent, "runtime_start_cancelled")
                        return@read
                    }
                    if (foregroundPromotionFailed && requiresStartAdmission) {
                        rejectStart(intent, "vpn_permission_required")
                        stopSelf(androidStartId(startId))
                        return@read
                    }
                    if (requiresStartAdmission && !RuntimeDispatchPolicy.mayStartVpn(active)) {
                        rejectStart(intent)
                        if (foregroundRequested && !RuntimeProcessSelection.hasVpnOwner()) stopSelf(androidStartId(startId))
                        return@read
                    }
                    if (active.slot == "stable" && scopedClick && action == RuntimeServiceIntents.QUICK_TOGGLE &&
                        (!requiresStartAdmission || pendingStableTileStart != null)) return@read
                    if (active.slot == "stable" && requiresStartAdmission && (action == RuntimeServiceIntents.QUICK_TOGGLE ||
                            action == "ru.nelomai.tunnel.CLIENT_START" || action == "ru.nelomai.tunnel.BEGIN_CONNECTION_INTENT")) {
                        // The pinned stable engine predates the container's tile revision.
                        RuntimeProcessSelection.recordVpnStart()
                    }
                    RuntimeProcessSelection.rememberVpnOwner(active)
                    if (RuntimeProcessSelection.hasVpnOwner()) superviseTransport()
                    val result = startEngine(selectedEngine, intent, flags, startId)
                    // A cold latest engine can refuse the handoff before arming the
                    // next watch (e.g. an unreadable recovery record). The job still owns it.
                    recoveryResult = if (result == START_NOT_STICKY) RuntimeServiceIntents.TASK_REMOVAL_RETRY
                        else RuntimeServiceIntents.TASK_REMOVAL_ACCEPTED
                } catch (_: SecurityException) {
                    if (preparedRecovery != null && VpnService.prepare(this) == null) {
                        recoveryResult = RuntimeServiceIntents.TASK_REMOVAL_RETRY
                    }
                    rejectStart(intent, "vpn_permission_required")
                    if (preparedRecovery == null || engine == null) stopSelf(androidStartId(startId))
                } catch (_: Exception) {
                    recoveryResult = RuntimeServiceIntents.TASK_REMOVAL_RETRY
                    if (preparedRecovery == null || engine == null) stopSelf(androidStartId(startId))
                }
            } finally {
                if (preparedRecovery != null && taskRemovalAdmission === preparedRecovery) {
                    taskRemovalAdmission = null
                    preparedRecovery.respond(recoveryResult)
                }
                pendingStartReads--
                settleRetiredStartIds()
            }
        }
        return if (foregroundPromotionFailed) START_NOT_STICKY else START_STICKY
    }

    // Only the last real command may cover subsequent ignored watch deliveries.
    private fun androidStartId(startId: Int): Int = if (startId == lastCommandStartId) lastStartId else startId

    private fun settleRetiredStartIds() {
        if (!retirementStarted || destroyed || pendingStartReads != 0 || lastStartId <= lastEngineStartId) return
        val target = engine ?: return
        val startId = lastStartId
        // All delivered commands have now run or been rejected. Retire using
        // the current Android startId without executing a rejected command.
        runCatching {
            if (target is RuntimeVpnTransportV1) {
                target.retiredStartRejected(startId)
            } else {
                // The pinned stable engine accepts the old ABI only. This command
                // reads the pending change revision and runs its guarded idle check.
                target.start(Intent("ru.nelomai.runtime.stable.tunnel.TAKE_STATE_CHANGE"), 0, startId)
            }
        }.onSuccess { lastEngineStartId = maxOf(lastEngineStartId, startId) }
    }

    private fun startEngine(target: RuntimeVpnEngineV1, intent: Intent?, flags: Int, startId: Int): Int {
        // Teardown may overtake an earlier request awaiting Binder. The old
        // callback must not roll the engine's stopSelfResult identifier back.
        lastEngineStartId = maxOf(lastEngineStartId, androidStartId(startId))
        if (intent?.hasExtra(RuntimeServiceIntents.EXTRA_TILE_CLICK_REVISION) != true ||
            RuntimeProcessSelection.tileOwner()?.slot != "stable") {
            return target.start(intent, flags, lastEngineStartId)
        }
        val revision = RuntimeProcessSelection.vpnStartRevision
        when (tunnelAction(intent)) {
            "ru.nelomai.tunnel.CANCEL_CURRENT_CONNECTION_INTENT" -> {
                pendingStableTileStart = null
                // The pinned ABI cancels and schedules lease cleanup. Its legacy
                // transport without a lease needs the same fallback as UI Stop.
                intent.putExtra("result_receiver", object : ResultReceiver(null) {
                    override fun onReceiveResult(code: Int, data: Bundle?) {
                        if (code == 1 && data != null && data.getString("lease_phase") == null &&
                            !destroyed && target === engine && tileClickIsCurrent(intent, RuntimeProcessSelection.tileOwner())) {
                            target.start(Intent("ru.nelomai.runtime.stable.tunnel.CLIENT_STOP")
                                .putExtra("api_version", RuntimeServiceIntents.VPN_API_VERSION), flags, lastEngineStartId)
                        }
                    }
                })
            }
            RuntimeServiceIntents.QUICK_TOGGLE -> {
                pendingStableTileStart = revision
                // A second Off click can reach us before stable saves its Start.
                intent.putExtra("result_receiver", object : ResultReceiver(handler) {
                    override fun onReceiveResult(code: Int, data: Bundle?) {
                        if (pendingStableTileStart == revision) pendingStableTileStart = null
                    }
                })
            }
        }
        return try {
            target.start(intent, flags, lastEngineStartId)
        } catch (error: Exception) {
            if (pendingStableTileStart == revision) pendingStableTileStart = null
            throw error
        }
    }

    private val taskRemovalPreparation = Messenger(Handler(Looper.getMainLooper()) { message ->
        if (message.sendingUid != Process.myUid()) return@Handler true
        val reply = message.replyTo ?: return@Handler true
        fun respond(code: Int) {
            try { reply.send(Message.obtain(null, code)) } catch (_: android.os.RemoteException) { }
        }
        val extras = message.data
        val expected = extras.getString(RuntimeServiceIntents.TASK_REMOVAL_RUNTIME)?.let {
            runCatching { RuntimeSelectionStore.decode(it) }.getOrNull()
        }
        if (expected == null) {
            respond(RuntimeServiceIntents.TASK_REMOVAL_REJECTED)
            return@Handler true
        }
        val revision = stopRevision
        val foregroundPid = message.arg1
        selection.read { result ->
            val active = result.getOrNull()
            if (active == null) {
                respond(RuntimeServiceIntents.TASK_REMOVAL_RETRY)
                return@read
            }
            if (!vpnAuthorityCurrent() || revision != stopRevision || !RuntimeDispatchPolicy.mayRecoverLatestVpn(expected, active) ||
                VpnService.prepare(this) != null
            ) {
                respond(RuntimeServiceIntents.TASK_REMOVAL_REJECTED)
                return@read
            }
            if (RuntimeProcessSelection.needsExit(active)) {
                respond(RuntimeServiceIntents.TASK_REMOVAL_RETRY)
                // A running engine owns its retirement. A cold stale image can exit immediately.
                if (engine == null) terminateProcess()
                return@read
            }
            val previous = taskRemovalAdmission
            if (previous?.delivered == true) {
                respond(RuntimeServiceIntents.TASK_REMOVAL_RETRY)
                return@read
            }
            previous?.respond?.invoke(RuntimeServiceIntents.TASK_REMOVAL_RETRY)
            // startService only queues delivery. The job keeps responsibility until the verified engine takes it.
            val admission = TaskRemovalAdmission(UUID.randomUUID().toString(), active, revision, ::respond)
            val intent = RuntimeServiceIntents.vpn(this).setAction(RuntimeServiceIntents.TASK_REMOVAL_LIVENESS)
                .putExtras(extras).putExtra(RuntimeServiceIntents.TASK_REMOVAL_START_ID, admission.token)
            intent.removeExtra(RuntimeServiceIntents.TASK_REMOVAL_FOREGROUND_PID)
            if (foregroundPid == Process.myPid() && engine != null && RuntimeProcessSelection.hasVpnOwner()) {
                intent.putExtra(RuntimeServiceIntents.TASK_REMOVAL_FOREGROUND_PID, foregroundPid)
            }
            taskRemovalAdmission = admission
            try {
                if (engine == null) promoteToForeground()
                checkNotNull(startService(intent))
            } catch (_: Exception) {
                taskRemovalAdmission = null
                if (engine == null) ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
                respond(RuntimeServiceIntents.TASK_REMOVAL_RETRY)
            }
        }
        true
    })

    private val backgroundPreparation = Messenger(Handler(Looper.getMainLooper()) { message ->
        // Messenger supplies the Binder caller UID; this is container-private IPC.
        if (message.sendingUid != Process.myUid() || message.what != 1) return@Handler true
        // replyTo parcels a framework Messenger/Binder. An anonymous application
        // ResultReceiver in Bundle needs an app class loader in the remote process.
        val receiver = message.replyTo ?: return@Handler true
        fun respond(code: Int) {
            try { receiver.send(Message.obtain(null, code)) } catch (_: android.os.RemoteException) { }
        }
        val data = message.data
        val request = data.getString(ru.nelomai.runtime.v1.RuntimeServiceIntents.STABLE_PROVISION_REQUEST)
        selection.read { result ->
            try {
                check(!destroyed)
                val active = result.getOrThrow()
                if (RuntimeProcessSelection.needsExit(active)) {
                    // As on the started-service path, a different owner incarnation
                    // requires physical exit; generation preparation alone never does.
                    respond(2)
                    terminateProcess()
                    return@read
                }
                RuntimeProcessSelection.claim(active)
                require(RuntimeDispatchPolicy.mayStart(active) && active.slot == "stable")
                requireNotNull(request)
                require(request.toByteArray().size <= 65536)
                val identity = JSONObject(JSONObject(request).getString("owner_operation"))
                    .getJSONObject("ticket").getJSONObject("identity")
                require(identity.getString("slot") == active.slot &&
                    identity.getString("runtime_version") == active.runtimeVersion &&
                    identity.getString("container_version") == active.containerVersion &&
                    identity.getLong("runtime_contract_version") == 1L &&
                    identity.getLong("session_generation") == active.sessionGeneration)
                check(ru.nelomai.tunnel.StableBackgroundProvision.prepare(this, request, engineWasLoaded))
                respond(1)
            } catch (_: Exception) {
                respond(2)
            }
        }
        true
    })

    override fun onBind(intent: Intent?): IBinder? = when (intent?.action) {
        RuntimeServiceIntents.TASK_REMOVAL_LIVENESS -> taskRemovalPreparation.binder
        RuntimeServiceIntents.PREPARE_STABLE_BACKGROUND -> backgroundPreparation.binder
        else -> super.onBind(intent)
    }

    private fun tunnelAction(intent: Intent?): String? = intent?.action?.let { action ->
        val stablePrefix = "ru.nelomai.runtime.stable.tunnel."
        if (action.startsWith(stablePrefix)) "ru.nelomai.tunnel." + action.removePrefix(stablePrefix) else action
    }

    private fun definitelyStartsVpn(intent: Intent?): Boolean = when (tunnelAction(intent)) {
        null,
        "ru.nelomai.tunnel.BEGIN_CONNECTION_INTENT",
        "ru.nelomai.tunnel.CLIENT_START",
        "ru.nelomai.tunnel.ENSURE_RUNNING",
        "ru.nelomai.tunnel.TASK_REMOVAL_LIVENESS" -> true
        else -> false
    }

    private fun isTeardownCommand(intent: Intent?): Boolean = when (tunnelAction(intent)) {
        RuntimeServiceIntents.CLIENT_STOP,
        "ru.nelomai.tunnel.CANCEL_CLIENT_START",
        "ru.nelomai.tunnel.CANCEL_CONNECTION_INTENT",
        "ru.nelomai.tunnel.CANCEL_CURRENT_CONNECTION_INTENT",
        "ru.nelomai.tunnel.BEGIN_BACKGROUND_LOGOUT",
        "ru.nelomai.tunnel.CLEAR_BACKGROUND",
        "ru.nelomai.tunnel.CLEAR_QUICK_PLAN" -> true
        RuntimeServiceIntents.QUICK_TOGGLE -> intent?.getBooleanExtra(RuntimeServiceIntents.EXTRA_QUICK_STOP_ONLY, false) == true
        else -> false
    }

    private fun tileClickIsCurrent(intent: Intent?, active: RuntimeSelectionV1?): Boolean {
        if (intent?.hasExtra(RuntimeServiceIntents.EXTRA_TILE_CLICK_REVISION) != true) return true
        if (intent.getLongExtra(RuntimeServiceIntents.EXTRA_TILE_CLICK_REVISION, 0L) !=
            RuntimeProcessSelection.vpnStartRevision) return false
        val expected = runCatching { RuntimeSelectionStore.decode(requireNotNull(
            intent.getStringExtra(RuntimeServiceIntents.EXTRA_TILE_CLICK_OWNER))) }.getOrNull() ?: return false
        return active == null || RuntimeDispatchPolicy.sameTileOwner(expected, active)
    }

    private fun invalidatesWaitingStarts(intent: Intent?): Boolean = when (tunnelAction(intent)) {
        RuntimeServiceIntents.CLIENT_STOP ->
            intent?.getIntExtra("api_version", 0) == RuntimeServiceIntents.VPN_API_VERSION &&
                !intent.getBooleanExtra("legacy_stop_only", false)
        "ru.nelomai.tunnel.CANCEL_CURRENT_CONNECTION_INTENT" -> true
        RuntimeServiceIntents.QUICK_TOGGLE -> intent?.getBooleanExtra(RuntimeServiceIntents.EXTRA_QUICK_STOP_ONLY, false) == true
        else -> false
    }

    private fun acceptSelection(active: RuntimeSelectionV1): Boolean {
        if (RuntimeProcessSelection.sameVpnImage(active) &&
            (retirementStarted || !RuntimeProcessSelection.mayRetainVpnOwner(active))
        ) {
            retireVpn(active)
            return false
        }
        if (RuntimeProcessSelection.needsExit(active)) {
            terminateProcess()
            return false
        }
        RuntimeProcessSelection.claim(active)
        lastBrokerVerificationAt = active.brokerVerifiedAtUptimeMillis ?: SystemClock.uptimeMillis()
        return true
    }

    private fun retireVpn(active: RuntimeSelectionV1) {
        val current = engine ?: return
        val firstRetirement = beginRetirement()
        val logoutEpoch = RuntimeDispatchPolicy.vpnLogoutEpoch(active)
        if (logoutEpoch == null) {
            if (firstRetirement) current.revoke()
            return
        }
        if (forwardedLogoutEpoch == logoutEpoch || SystemClock.elapsedRealtime() < logoutRetryAt) return
        forwardedLogoutEpoch = logoutEpoch
        fun failedLogout() {
            if (destroyed || engine !== current || forwardedLogoutEpoch != logoutEpoch) return
            retryBrokerLogout()
            current.revoke()
        }
        // Use the protected broker's persisted logout epoch and the existing
        // native logout path, even if the broker died before dispatching it.
        val logout = Intent("ru.nelomai.tunnel.BEGIN_BACKGROUND_LOGOUT")
            .putExtra("owner_cancel_epoch", logoutEpoch)
            .putExtra("result_receiver", object : ResultReceiver(handler) {
                override fun onReceiveResult(resultCode: Int, resultData: Bundle?) {
                    if (resultCode != 1) failedLogout()
                }
            })
        runCatching { startEngine(current, logout, 0, lastEngineStartId) }.onFailure { failedLogout() }
    }

    private fun beginRetirement(): Boolean {
        if (retirementStarted) return false
        retirementStarted = true
        invalidateQueuedVpnStarts()
        superviseTransport(retiring = true)
        // A read rejected before retirement may already have advanced AMS's ID.
        settleRetiredStartIds()
        return true
    }

    private fun superviseTransport(retiring: Boolean = false) {
        val transport = engine as? RuntimeVpnTransportV1 ?: return
        synchronized(watchdogLock) {
            val watchdog = vpnWatchdog ?: Handler(
                HandlerThread("nelomai-vpn-watchdog").apply { start() }.looper,
            ).also { handler ->
                vpnWatchdog = handler
                if (!retiring) {
                    // Allow a verification budget and a cleanup budget even
                    // when the main Looper blocks before calling revoke.
                    val budget = BROKER_RECOVERY_MILLIS * 2
                    handler.postDelayed(object : Runnable {
                        override fun run() {
                            val remaining = lastBrokerVerificationAt + budget - SystemClock.uptimeMillis()
                            if (remaining <= 0 && closeUnverifiedProcess(transport)) return
                            handler.postDelayed(this, if (remaining > 0) remaining else BROKER_RECOVERY_MILLIS)
                        }
                    }, budget)
                }
            }
            if (retiring && !retirementTimeoutArmed) {
                retirementTimeoutArmed = true
                watchdog.postDelayed({
                    closeUnverifiedProcess(transport)
                    watchdog.looper.quitSafely()
                }, BROKER_RECOVERY_MILLIS)
            }
        }
    }

    private fun closeUnverifiedProcess(transport: RuntimeVpnTransportV1): Boolean {
        if (runCatching(transport::localTransportClosed).getOrDefault(false)) return false
        Process.killProcess(Process.myPid())
        return true
    }

    private fun retryBrokerLogout() {
        forwardedLogoutEpoch = null
        logoutRetryAt = SystemClock.elapsedRealtime() + 10_000
    }

    private fun rejectStart(intent: Intent?, errorCode: String = "runtime_switch_pending") {
        @Suppress("DEPRECATION")
        intent?.getParcelableExtra<android.os.ResultReceiver>("result_receiver")?.send(2,
            android.os.Bundle().apply { putString("error_code", errorCode) })
    }

    override fun builder(beforeEstablish: (Builder) -> Unit): Builder = object : Builder() {
        override fun establish(): ParcelFileDescriptor? {
            // Admission is checked again at the system interface boundary.
            val active = selection.snapshot()
            check(engine != null && vpnAuthorityCurrent() && !RuntimeProcessSelection.needsExit(active) &&
                (active.slot != "latest" || RuntimeProcessSelection.hasVpnOwner()) &&
                RuntimeProcessSelection.mayRetainVpnOwner(active) && RuntimeDispatchPolicy.mayStartVpn(active))
            beforeEstablish(this)
            check(vpnAuthorityCurrent()) { "runtime_vpn_authority_retired" }
            val tun = super.establish() ?: return null
            if (vpnAuthorityCurrent()) return tun
            tun.close()
            return null
        }
    }

    override fun vpnAuthorityCurrent(): Boolean = !revokedByAndroid && !retirementStarted && !destroyed
    override fun invalidateQueuedVpnStarts() { stopRevision++ }
    override fun retireVpnAuthority() { beginRetirement() }

    override fun onRevoke() {
        // Android may deliver revocation from a Binder thread. Retire admission
        // immediately, then serialize the native cleanup with service commands.
        revokedByAndroid = true
        superviseTransport(retiring = true)
        if (Looper.myLooper() == Looper.getMainLooper()) revokeOnMain()
        else handler.post(::revokeOnMain)
    }

    private fun revokeOnMain() {
        if (destroyed) return
        beginRetirement()
        engine?.revoke() ?: super.onRevoke()
    }
    override fun onTaskRemoved(rootIntent: Intent?) { engine?.taskRemoved(rootIntent) }
    override fun onDestroy() {
        if (destroyed) return
        destroyed = true
        taskRemovalAdmission?.let {
            it.respond(if (stopRevision == it.stopRevision) RuntimeServiceIntents.TASK_REMOVAL_RETRY
                else RuntimeServiceIntents.TASK_REMOVAL_REJECTED)
        }
        taskRemovalAdmission = null
        beginRetirement()
        RuntimeProcessSelection.clearVpnOwner()
        waitingStartsAndToggles.clear()
        selectionVerificationInFlight = false
        handler.removeCallbacks(verifySelection)
        val current = engine
        current?.destroy()
        synchronized(watchdogLock) {
            if ((current as? RuntimeVpnTransportV1)?.localTransportClosed() == true) {
                vpnWatchdog?.looper?.quitSafely()
            }
        }
        engine = null
        selection.close()
        super.onDestroy()
    }

    private fun terminateProcess() {
        // The old engine gets its durable cleanup handoff before physical exit.
        if (!destroyed) {
            beginRetirement()
            onDestroy()
        }
        Process.killProcess(Process.myPid())
    }
}
