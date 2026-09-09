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
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import ru.nelomai.runtime.v1.RuntimeVpnEngineV1
import ru.nelomai.runtime.v1.RuntimeVpnHostV1

class RuntimeVpnDispatcherService : VpnService(), RuntimeVpnHostV1 {
    override val service: VpnService get() = this
    private lateinit var selection: RuntimeSelectionStore
    private var loaded: RuntimeSelectionV1? = null
    private var engine: RuntimeVpnEngineV1? = null
    private var destroyed = false
    private val handler = Handler(Looper.getMainLooper())
    private val verifySelection = object : Runnable {
        override fun run() {
            if (destroyed) return
            selection.read { result ->
                if (loaded != null && RuntimeDispatchPolicy.mustExitProcess(loaded!!, result.getOrNull())) terminateProcess()
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
        if (intent == null || intent.getBooleanExtra(
                ru.nelomai.runtime.v1.RuntimeServiceIntents.EXTRA_FOREGROUND_START, false)) {
            promoteToForeground()
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
                val selectedEngine = engine ?: RuntimeAdapters.engine(active, this).also {
                    loaded = active; engine = it; it.create()
                }
                if (selectedEngine.requiresStartAdmission(intent) && !RuntimeDispatchPolicy.mayStart(active)) {
                    rejectStart(intent)
                    return@read
                }
                selectedEngine.start(intent, flags, startId)
            } catch (_: Exception) { stopSelf(startId) }
        }
        return START_STICKY
    }

    private fun rejectStart(intent: Intent?) {
        @Suppress("DEPRECATION")
        intent?.getParcelableExtra<android.os.ResultReceiver>("result_receiver")?.send(2,
            android.os.Bundle().apply { putString("error_code", "runtime_switch_pending") })
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
