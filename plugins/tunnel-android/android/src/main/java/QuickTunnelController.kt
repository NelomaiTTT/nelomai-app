package ru.nelomai.tunnel

import android.content.Context

object QuickTunnelController {
    private const val STATE_PREFERENCES = "nelomai-quick-tunnel-state"
    private const val STATE_CHANGED = "changed"

    @JvmStatic
    fun state(): String = TunnelRuntime.state().wireName

    @JvmStatic
    fun toggle(
        context: Context,
        completion: (state: String, errorCode: String?) -> Unit,
    ) {
        TunnelRuntime.quickToggle(
            context.applicationContext,
            { state, _ ->
                context.getSharedPreferences(STATE_PREFERENCES, Context.MODE_PRIVATE)
                    .edit()
                    .putBoolean(STATE_CHANGED, true)
                    .commit()
                completion(state.wireName, null)
            },
            { errorCode -> completion(TunnelRuntime.state().wireName, errorCode) },
        )
    }

    @JvmStatic
    fun takeStateChange(context: Context): Boolean {
        val preferences = context.getSharedPreferences(
            STATE_PREFERENCES,
            Context.MODE_PRIVATE,
        )
        val changed = preferences.getBoolean(STATE_CHANGED, false)
        if (changed) preferences.edit().remove(STATE_CHANGED).commit()
        return changed
    }

    @JvmStatic
    fun clearStateChange(context: Context) {
        context.getSharedPreferences(STATE_PREFERENCES, Context.MODE_PRIVATE)
            .edit()
            .clear()
            .commit()
    }
}
