package ru.nelomai.tunnel

import android.content.Context

object QuickTunnelController {
    private const val STATE_PREFERENCES = "nelomai-quick-tunnel-state"
    private const val STATE_CHANGED = "changed"
    private const val STATE_VALUE = "state"
    private const val STATE_UPDATED_AT_MILLIS = "state-updated-at-millis"
    private const val DESIRED_ACTIVE = "desired-active"
    internal const val TRANSITION_TIMEOUT_MILLIS = 120_000L

    @JvmStatic
    fun state(context: Context): String {
        val runtimeState = TunnelRuntime.state()
        if (runtimeState != SessionState.STOPPED) {
            return runtimeState.wireName
        }
        val preferences = preferences(context)
        val persistedState = SessionState.values().firstOrNull {
            it.wireName == preferences.getString(STATE_VALUE, SessionState.STOPPED.wireName)
        } ?: SessionState.STOPPED
        val resolvedState = resolveState(
            runtimeState,
            persistedState,
            preferences.getLong(STATE_UPDATED_AT_MILLIS, 0),
            System.currentTimeMillis(),
        )
        if (resolvedState != persistedState) {
            updateState(context, resolvedState)
        }
        return resolvedState.wireName
    }

    @JvmStatic
    fun requestToggle(context: Context): Boolean {
        val current = state(context)
        val currentState = SessionState.values().firstOrNull { it.wireName == current }
            ?: SessionState.STOPPED
        val targetActive = current != SessionState.RUNNING.wireName
        if (!updateState(
            context,
            if (targetActive) SessionState.STARTING else SessionState.STOPPING,
            desiredActive = targetActive,
        )) {
            return false
        }
        return try {
            NelomaiVpnService.requestToggle(context.applicationContext)
            true
        } catch (error: Throwable) {
            updateState(
                context,
                currentState,
                desiredActive = currentState == SessionState.RUNNING,
            )
            TunnelLog.warning("quick_toggle.dispatch_failed", "service_start_failed", error)
            false
        }
    }

    internal fun updateState(
        context: Context,
        state: SessionState,
        desiredActive: Boolean? = null,
        changed: Boolean = false,
    ): Boolean {
        val saved = preferences(context).edit().apply {
            putString(STATE_VALUE, state.wireName)
            putLong(STATE_UPDATED_AT_MILLIS, System.currentTimeMillis())
            desiredActive?.let { putBoolean(DESIRED_ACTIVE, it) }
            if (changed) putBoolean(STATE_CHANGED, true)
        }.commit()
        if (!saved) {
            TunnelLog.warning("quick_state.save_failed", "shared_preferences_commit_failed")
        }
        return saved
    }

    internal fun desiredActive(context: Context): Boolean =
        preferences(context).getBoolean(DESIRED_ACTIVE, false)

    @JvmStatic
    fun takeStateChange(context: Context): Boolean {
        return preferences(context).getBoolean(STATE_CHANGED, false)
    }

    @JvmStatic
    fun acknowledgeStateChange(context: Context): Boolean {
        val preferences = preferences(context)
        if (!preferences.getBoolean(STATE_CHANGED, false)) return true
        val saved = preferences.edit().remove(STATE_CHANGED).commit()
        if (!saved) {
            TunnelLog.warning("quick_state.change_clear_failed", "shared_preferences_commit_failed")
        }
        return saved
    }

    @JvmStatic
    fun clearStateChange(context: Context): Boolean {
        val saved = preferences(context).edit().clear().commit()
        if (!saved) {
            TunnelLog.warning("quick_state.clear_failed", "shared_preferences_commit_failed")
        }
        return saved
    }

    internal fun resolveState(
        runtimeState: SessionState,
        persistedState: SessionState,
        updatedAtMillis: Long,
        nowMillis: Long,
    ): SessionState {
        if (runtimeState != SessionState.STOPPED) return runtimeState
        if (persistedState !in setOf(SessionState.STARTING, SessionState.STOPPING)) {
            return persistedState
        }
        val transitionAge = nowMillis - updatedAtMillis
        return if (
            updatedAtMillis <= 0 ||
            transitionAge < 0 ||
            transitionAge >= TRANSITION_TIMEOUT_MILLIS
        ) {
            SessionState.STOPPED
        } else {
            persistedState
        }
    }

    private fun preferences(context: Context) =
        context.applicationContext.getSharedPreferences(STATE_PREFERENCES, Context.MODE_PRIVATE)
}
