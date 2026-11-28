package ru.nelomai.client

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.content.IntentFilter
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.os.Handler
import android.os.Looper
import androidx.core.content.ContextCompat
import ru.nelomai.runtime.v1.RuntimeQuickStartV1
import ru.nelomai.runtime.v1.RuntimeServiceIntents

class NelomaiQuickTileService : TileService() {
    private val selection by lazy { RuntimeSelectionStore(this, readOffMain = true) }
    private val handler = Handler(Looper.getMainLooper())
    private val retryState = Runnable { updateTile() }
    private val pendingDispatches = mutableSetOf<AutoCloseable>()
    private var lastLoggedState: Pair<String?, Int>? = null
    private var listeningSession: Any? = null
    private var displayedOwner: RuntimeSelectionV1? = null
    private var stableState: SharedPreferences? = null
    private val stableStateListener = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
        if (key == "state" || key == null) updateTile()
    }
    private val stateChanged = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            updateTile()
        }
    }

    override fun onStartListening() {
        super.onStartListening()
        if (listeningSession == null) {
            ContextCompat.registerReceiver(this, stateChanged,
                IntentFilter(ACTION_STATE_CHANGED).apply {
                    addAction(ACTION_TILE_UPDATE)
                    addAction("ru.nelomai.runtime.stable.tunnel.STATE_CHANGED")
                },
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
            handler.removeCallbacks(retryState)
            observeStableState(null)
            unregisterReceiver(stateChanged)
        }
    }

    private fun observeStableState(selected: RuntimeSelectionV1?) {
        // The pinned stable engine can update its projection without emitting STATE_CHANGED.
        val prefs = selected?.takeIf { it.slot == "stable" }?.let {
            getSharedPreferences("runtime.stable.state.${it.runtimeVersion}.nelomai-quick-tunnel-state", MODE_PRIVATE)
        }
        if (stableState === prefs) return
        stableState?.unregisterOnSharedPreferenceChangeListener(stableStateListener)
        stableState = prefs
        prefs?.registerOnSharedPreferenceChangeListener(stableStateListener)
    }

    override fun onClick() {
        super.onClick()
        val click = captureClick() ?: return
        if (isLocked) unlockAndRun { dispatch(click) } else dispatch(click)
    }

    private data class TileClick(
        val stop: Boolean,
        val owner: RuntimeSelectionV1?,
        val startRevision: Long,
        val preparedStart: Runnable?,
    )

    private fun captureClick(): TileClick? {
        val owner = displayedOwner ?: RuntimeProcessSelection.vpnOwnerForStop()
        val revision = RuntimeProcessSelection.vpnStartRevision
        val stop = when (qsTile?.state) {
            Tile.STATE_ACTIVE -> true
            Tile.STATE_INACTIVE -> false
            else -> return null
        }
        val command = if (!stop && owner?.slot == "latest") runCatching {
            (RuntimeAdapters.quick(owner) as? RuntimeQuickStartV1)
                ?.prepareStart(applicationContext, RuntimeSelectionStore.encodeVpnRecoveryOwner(owner))
        }.getOrNull() else null
        return TileClick(stop, owner, revision, command)
    }

    private fun sendStop(click: TileClick, owner: RuntimeSelectionV1) {
        if (click.startRevision != RuntimeProcessSelection.vpnStartRevision ||
            click.owner?.let { !RuntimeDispatchPolicy.sameTileOwner(it, owner) } == true) return
        val command = if (owner.slot == "stable") {
            RuntimeServiceIntents.vpn(this).setAction("ru.nelomai.runtime.stable.tunnel.CANCEL_CURRENT_CONNECTION_INTENT")
        } else RuntimeServiceIntents.quickStopVpn(this)
        startService(scopedCommand(command, click, owner))
    }

    private fun scopedCommand(command: Intent, click: TileClick, owner: RuntimeSelectionV1): Intent =
        command.putExtra(RuntimeServiceIntents.EXTRA_TILE_CLICK_REVISION, click.startRevision)
            .putExtra(RuntimeServiceIntents.EXTRA_TILE_CLICK_OWNER, RuntimeSelectionStore.encodeVpnRecoveryOwner(owner))

    private fun dispatch(click: TileClick) {
        val session = listeningSession
        val dispatch = RuntimeDispatchGuard.begin()
        pendingDispatches += dispatch
        handler.postDelayed({ finishDispatch(dispatch) }, 15_000)
        android.util.Log.i("NelomaiTile", "toggle.requested")
        val vpnOwner = RuntimeProcessSelection.vpnOwnerForStop()
        if (click.stop && vpnOwner != null) {
            runCatching { sendStop(click, vpnOwner) }.onFailure { updateTile() }
            finishDispatch(dispatch)
            return
        }
        val startOwner = click.owner?.takeIf { !click.stop && it.slot == "latest" }
        selection.read { result ->
            try {
                result.onSuccess { selected ->
                    runCatching {
                        if (click.stop) {
                            sendStop(click, selected)
                            return@onSuccess
                        }
                        if (click.owner != null && !RuntimeDispatchPolicy.sameTileOwner(click.owner, selected) &&
                            startOwner == null) {
                            updateTile()
                            return@onSuccess
                        }
                        if (startOwner != null && !RuntimeDispatchPolicy.mayRecoverLatestVpn(startOwner, selected)) {
                            updateTile()
                            return@onSuccess
                        }
                        if (rejectWrongRuntime(selected)) return@onSuccess
                        RuntimeProcessSelection.claim(selected)
                        if (startOwner != null) {
                            if (click.preparedStart == null) updateTile() else click.preparedStart.run()
                            return@onSuccess
                        }
                        val quick = RuntimeAdapters.quick(selected)
                        if (selected.slot == "latest" && quick is RuntimeQuickStartV1) {
                            if (RuntimeDispatchPolicy.mayStartVpn(selected)) {
                                val command = quick.prepareStart(applicationContext, RuntimeSelectionStore.encodeVpnRecoveryOwner(selected))
                                // Check after reading the scope. A later Start also supersedes
                                // this cold click if its dispatcher has already been destroyed.
                                if (command != null && RuntimeProcessSelection.vpnStartRevision == click.startRevision) {
                                    command.run()
                                    return@onSuccess
                                }
                            }
                        } else if (selected.slot == "stable" && RuntimeDispatchPolicy.mayStart(selected) &&
                            click.startRevision == RuntimeProcessSelection.vpnStartRevision && !quick.desiredActive(applicationContext)) {
                            val start = RuntimeServiceIntents.vpn(this).setAction("ru.nelomai.runtime.stable.tunnel.QUICK_TOGGLE")
                            ContextCompat.startForegroundService(this, RuntimeServiceIntents.foreground(scopedCommand(start, click, selected)))
                            return@onSuccess
                        }
                    }
                    updateTile()
                }.onFailure {
                    if (session != null && listeningSession === session) qsTile?.apply {
                        state = Tile.STATE_UNAVAILABLE
                        updateTile()
                        scheduleStateRetry()
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
            observeStableState(selected)
            displayedOwner = selected
            val engineState = selected?.let { runCatching {
                if (rejectWrongRuntime(it)) return@runCatching null
                RuntimeProcessSelection.claim(it)
                RuntimeAdapters.quick(it).state(applicationContext)
            }.getOrNull() }
            state = if (selected == null || selected.pendingSlot != null) Tile.STATE_UNAVAILABLE else when (engineState) {
                "running" -> Tile.STATE_ACTIVE
                "stopped", "failed" -> Tile.STATE_INACTIVE
                else -> Tile.STATE_UNAVAILABLE
            }
            if (engineState == null && selected?.pendingSlot == null) scheduleStateRetry()
            else handler.removeCallbacks(retryState)
            val currentState = engineState to state
            if (currentState != lastLoggedState) {
                android.util.Log.i("NelomaiTile", "state.updated engine=$engineState tile=$state")
                lastLoggedState = currentState
            }
            updateTile()
        } }
    }
    private fun scheduleStateRetry() {
        handler.removeCallbacks(retryState)
        handler.postDelayed(retryState, 3_000)
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
