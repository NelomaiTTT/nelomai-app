package ru.nelomai.client

import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

class NelomaiQuickTileService : TileService() {
    private val selection by lazy { RuntimeSelectionStore(this) }
    override fun onStartListening() {
        super.onStartListening()
        updateTile()
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
        qsTile?.apply {
            state = Tile.STATE_UNAVAILABLE
            updateTile()
        }
        selection.read { result -> result.onSuccess { selected ->
            runCatching {
                if (RuntimeProcessSelection.needsExit(selected)) { android.os.Process.killProcess(android.os.Process.myPid()); return@onSuccess }
                RuntimeProcessSelection.claim(selected)
                val quick = RuntimeAdapters.quick(selected)
                if (RuntimeDispatchPolicy.mayToggle(selected, quick.desiredActive(applicationContext)) && quick.toggle(applicationContext)) return@onSuccess
            }
            updateTile()
        }.onFailure { qsTile?.apply { state = Tile.STATE_UNAVAILABLE; updateTile() } } }
    }

    private fun updateTile() {
        selection.read { result -> qsTile?.apply {
            label = getString(R.string.app_name)
            val selected = result.getOrNull()
            val engineState = selected?.let { runCatching {
                if (RuntimeProcessSelection.needsExit(it)) { android.os.Process.killProcess(android.os.Process.myPid()); return@runCatching null }
                RuntimeProcessSelection.claim(it)
                RuntimeAdapters.quick(it).state(applicationContext)
            }.getOrNull() }
            state = if (selected == null || selected.pendingSlot != null) Tile.STATE_UNAVAILABLE else when (engineState) {
                "running" -> Tile.STATE_ACTIVE
                "starting", "stopping" -> Tile.STATE_UNAVAILABLE
                else -> Tile.STATE_INACTIVE
            }
            updateTile()
        } }
    }
    override fun onDestroy() { selection.close(); super.onDestroy() }
}
