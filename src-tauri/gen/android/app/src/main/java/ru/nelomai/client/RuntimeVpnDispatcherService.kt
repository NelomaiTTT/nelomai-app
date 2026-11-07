package ru.nelomai.client

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.Bundle
import android.os.IBinder
import android.os.Messenger
import android.os.Message
import org.json.JSONObject
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import ru.nelomai.runtime.v1.RuntimeVpnEngineV1
import ru.nelomai.runtime.v1.RuntimeVpnHostV1

class RuntimeVpnDispatcherService : VpnService(), RuntimeVpnHostV1 {
    private companion object {
        // A destroyed Service does not prove that every old engine executor
        // has exited. Only physical :vpn process exit resets this marker.
        var engineWasLoaded = false
    }
    override val service: VpnService get() = this
    private lateinit var selection: RuntimeSelectionStore
    private var loaded: RuntimeSelectionV1? = null
    private var engine: RuntimeVpnEngineV1? = null
    private var destroyed = false
    private var selectionVerificationInFlight = false
    private val handler = Handler(Looper.getMainLooper())
    private val verifySelection = object : Runnable {
        override fun run() {
            if (destroyed) return
            if (!selectionVerificationInFlight) {
                selectionVerificationInFlight = true
                selection.read { result ->
                    selectionVerificationInFlight = false
                    if (!destroyed && loaded != null &&
                        RuntimeDispatchPolicy.mustExitProcessAfterRead(loaded!!, result)) {
                        terminateProcess()
                    }
                }
            }
            if (!destroyed) handler.postDelayed(this, 1000)
        }
    }

    override fun onCreate() {
        super.onCreate()
        selection = RuntimeSelectionStore(this)
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
        // A status/read request is not a foreground-service launch. Real FGS
        // launches must be acknowledged before waiting for the owner Binder.
        val foregroundRequested = intent == null || intent.getBooleanExtra(
            ru.nelomai.runtime.v1.RuntimeServiceIntents.EXTRA_FOREGROUND_START,
            false,
        )
        val foregroundPromotionFailed = foregroundRequested && (
            VpnService.prepare(this) != null ||
                try {
                    promoteToForeground()
                    false
                } catch (_: SecurityException) {
                    true
                }
        )
        if (foregroundPromotionFailed && definitelyStartsVpn(intent)) {
            rejectStart(intent, "vpn_permission_required")
            stopSelf(startId)
            return START_NOT_STICKY
        }
        selection.read { result ->
            if (destroyed) return@read
            val active = result.getOrElse { stopSelf(startId); return@read }
            if (loaded != null && RuntimeDispatchPolicy.mustExitProcess(loaded!!, active)) {
                terminateProcess(); return@read
            }
            try {
                if (RuntimeProcessSelection.needsExit(active)) { terminateProcess(); return@read }
                RuntimeProcessSelection.claim(active)
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
                    loaded = active; engine = it; it.create()
                }
                val requiresStartAdmission = selectedEngine.requiresStartAdmission(intent)
                if (foregroundPromotionFailed && requiresStartAdmission) {
                    rejectStart(intent, "vpn_permission_required")
                    stopSelf(startId)
                    return@read
                }
                if (requiresStartAdmission && !RuntimeDispatchPolicy.mayStart(active)) {
                    rejectStart(intent)
                    return@read
                }
                selectedEngine.start(intent, flags, startId)
            } catch (_: SecurityException) {
                rejectStart(intent, "vpn_permission_required")
                stopSelf(startId)
            } catch (_: Exception) { stopSelf(startId) }
        }
        return if (foregroundPromotionFailed) START_NOT_STICKY else START_STICKY
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

    private fun definitelyStartsVpn(intent: Intent?): Boolean = when (intent?.action) {
        null,
        "ru.nelomai.tunnel.BEGIN_CONNECTION_INTENT",
        "ru.nelomai.tunnel.CLIENT_START",
        "ru.nelomai.tunnel.ENSURE_RUNNING",
        "ru.nelomai.tunnel.TASK_REMOVAL_LIVENESS" -> true
        else -> false
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
            check(loaded != null && !RuntimeDispatchPolicy.mustExitProcess(loaded!!, active) && RuntimeDispatchPolicy.mayStart(active))
            beforeEstablish(this)
            return super.establish()
        }
    }

    override fun onRevoke() { engine?.revoke() ?: super.onRevoke() }
    override fun onTaskRemoved(rootIntent: Intent?) { engine?.taskRemoved(rootIntent) }
    override fun onDestroy() {
        if (destroyed) return
        destroyed = true
        selectionVerificationInFlight = false
        handler.removeCallbacks(verifySelection)
        engine?.destroy(); engine = null
        selection.close()
        super.onDestroy()
    }

    private fun terminateProcess() {
        // The old engine gets its durable cleanup handoff before physical exit.
        if (!destroyed) onDestroy()
        Process.killProcess(Process.myPid())
    }
}
