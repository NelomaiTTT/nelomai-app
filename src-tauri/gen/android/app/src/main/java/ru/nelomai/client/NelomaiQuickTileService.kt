package ru.nelomai.client

import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import ru.nelomai.tunnel.QuickTunnelController

class NelomaiQuickTileService : TileService() {
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
        if (!QuickTunnelController.requestToggle(applicationContext)) {
            updateTile()
        }
    }

    private fun updateTile() {
        qsTile?.apply {
            label = getString(R.string.app_name)
            state = when (QuickTunnelController.state(applicationContext)) {
                "running" -> Tile.STATE_ACTIVE
                "starting", "stopping" -> Tile.STATE_UNAVAILABLE
                else -> Tile.STATE_INACTIVE
            }
            updateTile()
        }
    }

}
