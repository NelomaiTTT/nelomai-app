package ru.nelomai.client

import android.app.NotificationChannel
import android.app.NotificationManager
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
import org.json.JSONObject
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import ru.nelomai.runtime.v1.RuntimeVpnEngineV1
import ru.nelomai.runtime.v1.RuntimeVpnHostV1
import ru.nelomai.runtime.v1.RuntimeVpnAuthorityV1
import ru.nelomai.runtime.v1.RuntimeVpnTransportV1
import ru.nelomai.runtime.v1.RuntimeServiceIntents

class RuntimeVpnDispatcherService : VpnService(), RuntimeVpnHostV1, RuntimeVpnAuthorityV1 {
    private companion object {
        const val BROKER_RECOVERY_MILLIS = 10_000L
        // A destroyed Service does not prove that every old engine executor
        // has exited. Only physical :vpn process exit resets this marker.
        var engineWasLoaded = false
    }
    override val service: VpnService get() = this
    private lateinit var selection: RuntimeSelectionStore
    @Volatile private var engine: RuntimeVpnEngineV1? = null
    @Volatile private var destroyed = false
    private var selectionVerificationInFlight = false
    private var lastStartId = 0
    private var lastEngineStartId = 0
    private var pendingStartReads = 0
    private var stopRevision = 0L
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
        selection = RuntimeSelectionStore(this, allowOwnerOomManagement = false, readOffMain = true)
        handler.post(verifySelection)
    }

    private fun promoteToForeground() {
        if (Build.VERSION.SDK_INT >= 26) getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel("runtime_dispatcher", "VPN", NotificationManager.IMPORTANCE_LOW))
        ServiceCompat.startForeground(this, 1701, NotificationCompat.Builder(this, "runtime_dispatcher")
            .setSmallIcon(R.drawable.ic_quick_tile).setContentTitle("Nelomai VPN").setOngoing(true).build(),
            if (Build.VERSION.SDK_INT >= 34) android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED else 0)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        lastStartId = startId
        val action = tunnelAction(intent)
        if (invalidatesWaitingStarts(intent)) stopRevision++
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
        val foregroundRequested = intent == null ||
            intent.getBooleanExtra(RuntimeServiceIntents.EXTRA_FOREGROUND_START, false)
        val current = engine
        if (current == null && action == "ru.nelomai.tunnel.BEGIN_BACKGROUND_LOGOUT") {
            // The broker persisted Logout before delivering this command.
            // A snapshot taken before it must not admit a waiting cold Start.
            selection.invalidatePendingSnapshot()
        }
        if (!foregroundRequested && current != null &&
            (RuntimeProcessSelection.hasVpnOwner() || action == RuntimeServiceIntents.CLIENT_STOP) &&
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
            if (retirementStarted) settleRetiredStartIds() else stopSelf(startId)
            return START_NOT_STICKY
        }
        if (waitingCommand != null) waitingStartsAndToggles += waitingCommand
        pendingStartReads++
        selection.read { result ->
            try {
                val cancelled = waitingCommand != null && !waitingStartsAndToggles.remove(waitingCommand)
                if (destroyed) return@read
                val active = result.getOrElse {
                    rejectStart(intent, "runtime_owner_unavailable")
                    if (!retirementStarted && !RuntimeProcessSelection.hasVpnOwner()) stopSelf(startId)
                    return@read
                }
                try {
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
                        stopSelf(startId)
                        return@read
                    }
                    if (requiresStartAdmission && !RuntimeDispatchPolicy.mayStartVpn(active)) {
                        rejectStart(intent)
                        if (foregroundRequested && !RuntimeProcessSelection.hasVpnOwner()) stopSelf(startId)
                        return@read
                    }
                    RuntimeProcessSelection.rememberVpnOwner(active)
                    if (RuntimeProcessSelection.hasVpnOwner()) superviseTransport()
                    startEngine(selectedEngine, intent, flags, startId)
                } catch (_: SecurityException) {
                    rejectStart(intent, "vpn_permission_required")
                    stopSelf(startId)
                } catch (_: Exception) { stopSelf(startId) }
            } finally {
                pendingStartReads--
                settleRetiredStartIds()
            }
        }
        return if (foregroundPromotionFailed) START_NOT_STICKY else START_STICKY
    }

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

    private fun startEngine(target: RuntimeVpnEngineV1, intent: Intent?, flags: Int, startId: Int) {
        // Teardown may overtake an earlier request awaiting Binder. The old
        // callback must not roll the engine's stopSelfResult identifier back.
        lastEngineStartId = maxOf(lastEngineStartId, startId)
        target.start(intent, flags, lastEngineStartId)
    }

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

    override fun onBind(intent: Intent?): IBinder? =
        if (intent?.action == ru.nelomai.runtime.v1.RuntimeServiceIntents.PREPARE_STABLE_BACKGROUND)
            backgroundPreparation.binder
        else super.onBind(intent)

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
