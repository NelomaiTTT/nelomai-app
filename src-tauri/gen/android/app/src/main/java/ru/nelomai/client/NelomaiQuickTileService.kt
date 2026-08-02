package ru.nelomai.client

import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.util.Log
import ru.nelomai.tunnel.TunnelPlugin

class NelomaiQuickTileService : TileService() {
    companion object {
        private const val LOG_TAG = "NelomaiTunnel"
    }

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
        if (!TunnelPlugin.beginQuickToggle()) {
            Log.i(LOG_TAG, "quick_toggle.ignored reason=operation_in_progress")
            qsTile?.apply {
                state = Tile.STATE_UNAVAILABLE
                updateTile()
            }
            return
        }
        qsTile?.apply {
            state = Tile.STATE_UNAVAILABLE
            updateTile()
        }
        if (TunnelPlugin.dispatchQuickToggle()) {
            Log.i(LOG_TAG, "quick_toggle.background_dispatch")
            return
        }

        TunnelPlugin.queueQuickToggle(applicationContext)
        Log.i(LOG_TAG, "quick_toggle.open_headless_activity")
        val intent = Intent(this, QuickActionActivity::class.java).apply {
            putExtra(TunnelPlugin.QUICK_ACTION_HEADLESS_EXTRA, true)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_NO_ANIMATION)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startActivityAndCollapse(
                PendingIntent.getActivity(
                    this,
                    0,
                    intent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                ),
            )
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }

    private fun updateTile() {
        qsTile?.apply {
            label = getString(R.string.app_name)
            state = when (TunnelPlugin.tunnelState()) {
                "running" -> Tile.STATE_ACTIVE
                "starting", "stopping" -> Tile.STATE_UNAVAILABLE
                else -> Tile.STATE_INACTIVE
            }
            updateTile()
        }
    }
}
