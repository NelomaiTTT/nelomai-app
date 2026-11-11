package ru.nelomai.client

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.os.Handler
import android.os.Looper
import androidx.core.content.ContextCompat
import ru.nelomai.runtime.v1.RuntimeServiceIntents

class NelomaiQuickTileService : TileService() {
    private val selection by lazy { RuntimeSelectionStore(this, readOffMain = true) }
    private val handler = Handler(Looper.getMainLooper())
    private val pendingDispatches = mutableSetOf<AutoCloseable>()
    private var lastLoggedState: Pair<String?, Int>? = null
    private var listeningSession: Any? = null
    private val stateChanged = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == ACTION_STATE_CHANGED || intent?.action == ACTION_TILE_UPDATE) updateTile()
        }
    }

    override fun onStartListening() {
        super.onStartListening()
        if (listeningSession == null) {
            ContextCompat.registerReceiver(this, stateChanged,
                IntentFilter(ACTION_STATE_CHANGED).apply { addAction(ACTION_TILE_UPDATE) },
                ContextCompat.RECEIVER_NOT_EXPORTED)
            listeningSession = Any()
        }
        updateTile()
    }

    override fun onStopListening() {
        stopListening()
        super.onStopListening()
    }

    private fun stopListening() {
        if (listeningSession != null) {
            listeningSession = null
            unregisterReceiver(stateChanged)
        }
    }

    override fun onClick() {
        super.onClick()
        if (isLocked) {
            unlockAndRun { dispatchOrOpen() }
        } else {
            dispatchOrOpen()
        }
    }

    private fun dispatchOrOpen() {
        val session = listeningSession
        val dispatch = RuntimeDispatchGuard.begin()
        pendingDispatches += dispatch
        handler.postDelayed({ finishDispatch(dispatch) }, 15_000)
        android.util.Log.i("NelomaiTile", "toggle.requested")
        if (listeningSession != null) qsTile?.apply {
            state = Tile.STATE_UNAVAILABLE
            updateTile()
        }
        val vpnOwner = RuntimeProcessSelection.vpnOwnerForStop()
        if (vpnOwner != null && runCatching {
                RuntimeAdapters.quick(vpnOwner).desiredActive(applicationContext)
            }.getOrDefault(false)
        ) {
            // This is a Stop of the admitted local VPN, never an offline toggle.
            runCatching { startService(RuntimeServiceIntents.quickStopVpn(applicationContext)) }
                .onFailure { updateTile() }
            finishDispatch(dispatch)
            return
        }
        selection.read { result ->
            try {
                result.onSuccess { selected ->
                    runCatching {
                        if (rejectWrongRuntime(selected)) return@onSuccess
                        RuntimeProcessSelection.claim(selected)
                        val quick = RuntimeAdapters.quick(selected)
                        if (RuntimeDispatchPolicy.mayToggle(selected, quick.desiredActive(applicationContext)) && quick.toggle(applicationContext)) return@onSuccess
                    }
                    updateTile()
                }.onFailure {
                    if (session != null && listeningSession === session) qsTile?.apply {
                        state = Tile.STATE_UNAVAILABLE
                        updateTile()
                    }
                }
            } finally {
                finishDispatch(dispatch)
            }
        }
    }

    private fun updateTile() {
        val session = listeningSession ?: return
        // Selection reads may complete after listening stopped or was restarted.
        selection.read { result -> qsTile?.apply {
            if (listeningSession !== session) return@read
            label = getString(R.string.app_name)
            val selected = result.getOrNull()
            val engineState = selected?.let { runCatching {
                if (rejectWrongRuntime(it)) return@runCatching null
                RuntimeProcessSelection.claim(it)
                RuntimeAdapters.quick(it).state(applicationContext)
            }.getOrNull() }
            state = if (selected == null || selected.pendingSlot != null) Tile.STATE_UNAVAILABLE else when (engineState) {
                "running" -> Tile.STATE_ACTIVE
                "starting", "stopping" -> Tile.STATE_UNAVAILABLE
                else -> Tile.STATE_INACTIVE
            }
            val currentState = engineState to state
            if (currentState != lastLoggedState) {
                android.util.Log.i("NelomaiTile", "state.updated engine=$engineState tile=$state")
                lastLoggedState = currentState
            }
            updateTile()
        } }
    }
    private fun finishDispatch(dispatch: AutoCloseable) {
        if (pendingDispatches.remove(dispatch)) dispatch.close()
    }

    private fun rejectWrongRuntime(selected: RuntimeSelectionV1): Boolean {
        if (!RuntimeProcessSelection.needsExit(selected)) return false
        // The running dispatcher owns tunnel teardown and durable cancellation.
        if (!RuntimeProcessSelection.hasVpnOwner()) android.os.Process.killProcess(android.os.Process.myPid())
        return true
    }

    override fun onDestroy() {
        stopListening()
        pendingDispatches.toList().forEach(::finishDispatch)
        selection.close()
        super.onDestroy()
    }

    private companion object {
        const val ACTION_STATE_CHANGED = "ru.nelomai.tunnel.STATE_CHANGED"
        const val ACTION_TILE_UPDATE = "ru.nelomai.tunnel.QUICK_TILE_UPDATE"
    }
}
