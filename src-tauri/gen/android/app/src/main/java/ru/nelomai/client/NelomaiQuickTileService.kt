package ru.nelomai.client

import android.os.Handler
import android.os.Looper
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.util.Log
import android.widget.Toast
import ru.nelomai.tunnel.QuickTunnelController

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
        qsTile?.apply {
            state = Tile.STATE_UNAVAILABLE
            updateTile()
        }
        QuickTunnelController.toggle(applicationContext) { state, errorCode ->
            Handler(Looper.getMainLooper()).post {
                Log.i(
                    LOG_TAG,
                    "quick_toggle.completed state=$state error=${errorCode ?: "none"}",
                )
                updateTile()
                errorCode?.let {
                    Toast.makeText(
                        applicationContext,
                        quickActionError(it),
                        Toast.LENGTH_LONG,
                    ).show()
                }
            }
        }
    }

    private fun updateTile() {
        qsTile?.apply {
            label = getString(R.string.app_name)
            state = when (QuickTunnelController.state()) {
                "running" -> Tile.STATE_ACTIVE
                "starting", "stopping" -> Tile.STATE_UNAVAILABLE
                else -> Tile.STATE_INACTIVE
            }
            updateTile()
        }
    }

    private fun quickActionError(code: String): String = when (code) {
        "vpn_permission_required" -> "Откройте Nelomai и разрешите VPN-подключение"
        "quick_action_plan_unavailable" -> "Откройте Nelomai, чтобы подготовить подключение"
        "tunnel_operation_in_progress" -> "Дождитесь завершения текущего действия"
        else -> "Не удалось изменить состояние подключения"
    }
}
