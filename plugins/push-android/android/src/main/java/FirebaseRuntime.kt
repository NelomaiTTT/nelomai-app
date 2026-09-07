package ru.nelomai.push

import android.content.Context
import com.google.firebase.FirebaseApp
import com.google.firebase.FirebaseOptions
import ru.nelomai.runtime.v1.RuntimePushGate

internal object FirebaseRuntime {
    private const val PREFERENCES = "nelomai_push"
    private const val DELIVERY_ENABLED = "delivery_enabled"
    private const val PERMISSION_REQUESTED = "permission_requested"
    private const val PENDING_TOKEN = "pending_token"

    fun initialize(context: Context): FirebaseApp? {
        FirebaseApp.getApps(context).firstOrNull()?.let { return it }
        val applicationId = BuildConfig.FIREBASE_APPLICATION_ID.trim()
        val apiKey = BuildConfig.FIREBASE_API_KEY.trim()
        val projectId = BuildConfig.FIREBASE_PROJECT_ID.trim()
        val senderId = applicationId.split(":").getOrNull(1).orEmpty()
        if (applicationId.isBlank() || apiKey.isBlank() || projectId.isBlank() || senderId.isBlank()) {
            return null
        }
        val options = FirebaseOptions.Builder()
            .setApplicationId(applicationId)
            .setApiKey(apiKey)
            .setProjectId(projectId)
            .setGcmSenderId(senderId)
            .build()
        return FirebaseApp.initializeApp(context.applicationContext, options)
    }

    private fun gate(context: Context) = RuntimePushGate(context.filesDir)
    fun epoch(context: Context): Long = gate(context).epoch()
    fun deliveryEnabled(context: Context): Boolean = gate(context).enabled()

    fun setDeliveryEnabled(context: Context, enabled: Boolean, epoch: Long? = null): Boolean {
        if (enabled) return epoch != null && gate(context).enable(epoch)
        gate(context).disable(); return true
    }

    fun permissionRequested(context: Context): Boolean =
        preferences(context).getBoolean(PERMISSION_REQUESTED, false)

    fun markPermissionRequested(context: Context) {
        preferences(context).edit().putBoolean(PERMISSION_REQUESTED, true).apply()
    }

    fun pendingToken(context: Context): String? =
        gate(context).pendingToken()

    fun savePendingToken(context: Context, token: String) {
        if (token.isBlank()) return
        gate(context).saveToken(token)
    }

    fun confirmToken(context: Context, token: String, epoch: Long): Boolean = gate(context).confirm(epoch, token)

    fun disable(context: Context) {
        gate(context).revoke(0)
        preferences(context).edit()
            .putBoolean(DELIVERY_ENABLED, false)
            .remove(PENDING_TOKEN)
            .apply()
    }

    private fun preferences(context: Context) =
        context.applicationContext.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
}
