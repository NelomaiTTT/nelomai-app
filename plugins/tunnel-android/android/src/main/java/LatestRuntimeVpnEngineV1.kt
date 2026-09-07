package ru.nelomai.tunnel

import android.content.Intent
import ru.nelomai.runtime.v1.RuntimeVpnEngineV1
import ru.nelomai.runtime.v1.RuntimeVpnHostV1

/** Versioned adapter: common dispatcher has no lease, recovery or route policy. */
class LatestRuntimeVpnEngineV1(host: RuntimeVpnHostV1) : RuntimeVpnEngineV1 {
    private val engine = NelomaiVpnService(host)
    override fun requiresStartAdmission(intent: Intent?): Boolean = when (intent?.action) {
        NelomaiVpnService.ACTION_QUICK_TOGGLE -> !QuickTunnelController.desiredActive(hostContext())
        NelomaiVpnService.ACTION_CANCEL_CLIENT_START, NelomaiVpnService.ACTION_CLIENT_STOP,
        NelomaiVpnService.ACTION_CLIENT_STATUS, NelomaiVpnService.ACTION_CLIENT_METRICS,
        NelomaiVpnService.ACTION_CANCEL_CONNECTION_INTENT, NelomaiVpnService.ACTION_CANCEL_CURRENT_CONNECTION_INTENT,
        NelomaiVpnService.ACTION_CONNECTION_INTENT_STATUS, NelomaiVpnService.ACTION_BEGIN_BACKGROUND_LOGOUT,
        NelomaiVpnService.ACTION_BACKGROUND_STATUS, NelomaiVpnService.ACTION_CLEAR_BACKGROUND,
        NelomaiVpnService.ACTION_CLEAR_QUICK_PLAN, NelomaiVpnService.ACTION_UPDATE_QUICK_DNS,
        NelomaiVpnService.ACTION_TAKE_STATE_CHANGE, NelomaiVpnService.ACTION_ACKNOWLEDGE_STATE_CHANGE -> false
        else -> true
    }
    private fun hostContext() = engine.applicationContext
    override fun create() = engine.onCreate()
    override fun start(intent: Intent?, flags: Int, startId: Int): Int = engine.onStartCommand(intent, flags, startId)
    override fun revoke() = engine.onRevoke()
    override fun taskRemoved(intent: Intent?) = engine.onTaskRemoved(intent)
    override fun destroy() = engine.onDestroy()
}

class LatestRuntimeQuickActionsV1 : ru.nelomai.runtime.v1.RuntimeQuickActionsV1 {
    override fun desiredActive(context: android.content.Context): Boolean = QuickTunnelController.desiredActive(context)
    override fun state(context: android.content.Context): String = QuickTunnelController.state(context)
    override fun toggle(context: android.content.Context): Boolean = QuickTunnelController.requestToggle(context)
}
