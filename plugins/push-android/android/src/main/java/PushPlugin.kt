package ru.nelomai.push

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.content.ContextCompat
import app.tauri.annotation.Command
import app.tauri.annotation.Permission
import app.tauri.annotation.PermissionCallback
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import com.google.firebase.messaging.FirebaseMessaging

private const val NOTIFICATION_PERMISSION_ALIAS = "notifications"

@TauriPlugin(
    permissions = [
        Permission(
            strings = [Manifest.permission.POST_NOTIFICATIONS],
            alias = NOTIFICATION_PERMISSION_ALIAS,
        ),
    ],
)
class PushPlugin(private val activity: Activity) : Plugin(activity) {
    @Command
    fun prepare(invoke: Invoke) {
        val firebase = FirebaseRuntime.initialize(activity)
        if (firebase == null) {
            invoke.reject("push_not_configured")
            return
        }
        if (
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            !permissionGranted()
        ) {
            FirebaseRuntime.setDeliveryEnabled(activity, false)
            if (FirebaseRuntime.permissionRequested(activity)) {
                resolvePermissionDenied(invoke)
                return
            }
            FirebaseRuntime.markPermissionRequested(activity)
            requestPermissionForAlias(
                NOTIFICATION_PERMISSION_ALIAS,
                invoke,
                "completePrepare",
            )
            return
        }
        resolveToken(invoke)
    }

    @PermissionCallback
    fun completePrepare(invoke: Invoke) {
        if (!permissionGranted()) {
            FirebaseRuntime.setDeliveryEnabled(activity, false)
            resolvePermissionDenied(invoke)
            return
        }
        resolveToken(invoke)
    }

    @Command
    fun confirm(invoke: Invoke) {
        val token = invoke.getArgs().getString("token", "") ?: ""
        FirebaseRuntime.confirmToken(activity, token)
        invoke.resolve()
    }

    @Command
    fun disable(invoke: Invoke) {
        FirebaseRuntime.disable(activity)
        if (FirebaseRuntime.initialize(activity) == null) {
            invoke.resolve()
            return
        }
        FirebaseMessaging.getInstance().deleteToken()
        invoke.resolve()
    }

    private fun resolveToken(invoke: Invoke) {
        FirebaseRuntime.setDeliveryEnabled(activity, true)
        FirebaseRuntime.pendingToken(activity)?.let { token ->
            resolve(invoke, token, true)
            return
        }
        FirebaseMessaging.getInstance().token.addOnCompleteListener { task ->
            if (!task.isSuccessful || task.result.isNullOrBlank()) {
                invoke.reject("push_token_unavailable")
                return@addOnCompleteListener
            }
            resolve(invoke, task.result, true)
        }
    }

    private fun resolvePermissionDenied(invoke: Invoke) = resolve(invoke, "", false)

    private fun resolve(invoke: Invoke, token: String, granted: Boolean) {
        val response = JSObject()
        response.put("token", token)
        response.put("permissionGranted", granted)
        invoke.resolve(response)
    }

    private fun permissionGranted(): Boolean =
        Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
            ContextCompat.checkSelfPermission(activity, Manifest.permission.POST_NOTIFICATIONS) ==
                PackageManager.PERMISSION_GRANTED
}
