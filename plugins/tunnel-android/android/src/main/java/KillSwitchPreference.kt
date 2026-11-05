package ru.nelomai.tunnel

import android.content.Context
import android.os.Bundle
import app.tauri.plugin.JSObject

/** Device choice, deliberately outside runtime/account namespaces. Only :vpn writes it. */
internal class KillSwitchPreference(context: Context) {
    private val preferences = context.applicationContext.getSharedPreferences(
        "nelomai-kill-switch-device-v1", Context.MODE_PRIVATE)
    val enabled: Boolean get() = preferences.getBoolean("enabled", false)
    val disclosed: Boolean get() = preferences.getBoolean("disclosed", false)

    fun save(enabled: Boolean, confirmed: Boolean = false) {
        if (enabled && !disclosed && !confirmed) throw IllegalArgumentException("kill_switch_confirmation_required")
        check(preferences.edit().putBoolean("enabled", enabled)
            .putBoolean("disclosed", disclosed || confirmed).commit()) { "kill_switch_preference_write_failed" }
    }
}

internal fun Bundle.killSwitchStatus(): JSObject = JSObject()
    .put("vpnActive", getString(EXTRA_STATE)?.let { it != "stopped" })
    .put("supported", getBoolean("kill_switch_supported", false))
    .put("enabled", getBoolean("kill_switch_enabled", false))
    .put("disclosed", getBoolean("kill_switch_disclosed", false))
    .put("state", getString("kill_switch_state") ?: "unknown")
    .put("error", getString("kill_switch_error"))
    .put("cause", getString("kill_switch_cause"))
    .put("externalLockdown", if (containsKey("kill_switch_external_lockdown")) getBoolean("kill_switch_external_lockdown") else null)

/** Notification bookkeeping only; retry and ownership remain with the service. */
internal class KillSwitchNotice {
    private var outageSince: Long? = null
    private var notified: String? = null
    private var outageNotified = false

    fun update(state: String, actionableCause: String?, now: Long): String? {
        val immediate = "protection_unknown".takeIf { state == "unknown" } ?: actionableCause?.takeIf { it in setOf(
            "protection_lost", "vpn_permission_revoked", "captive_portal", "action_required") }
        if (state == "armed" || (state == "off" && immediate == null)) {
            outageSince = null; notified = null; outageNotified = false
            return null
        }
        if (state == "blocked" && outageSince == null) outageSince = now
        val event = immediate ?: "blocked".takeIf {
            !outageNotified && outageSince?.let { now - it >= 20_000 } == true
        } ?: return null
        if (notified == event) return null
        notified = event
        if (state in setOf("blocked", "unknown")) outageNotified = true
        return event
    }

    fun remaining(now: Long): Long? = if (outageNotified) null else
        outageSince?.let { (20_000 - (now - it)).coerceAtLeast(1) }
}
