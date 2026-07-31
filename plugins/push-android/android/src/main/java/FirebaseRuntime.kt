package ru.nelomai.push

import android.content.Context
import com.google.firebase.FirebaseApp
import com.google.firebase.FirebaseOptions

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

    fun deliveryEnabled(context: Context): Boolean =
        preferences(context).getBoolean(DELIVERY_ENABLED, false)

    fun setDeliveryEnabled(context: Context, enabled: Boolean) {
        preferences(context).edit().putBoolean(DELIVERY_ENABLED, enabled).apply()
    }

    fun permissionRequested(context: Context): Boolean =
        preferences(context).getBoolean(PERMISSION_REQUESTED, false)

    fun markPermissionRequested(context: Context) {
        preferences(context).edit().putBoolean(PERMISSION_REQUESTED, true).apply()
    }

    fun pendingToken(context: Context): String? =
        preferences(context).getString(PENDING_TOKEN, null)?.takeIf { it.isNotBlank() }

    fun savePendingToken(context: Context, token: String) {
        if (token.isBlank()) return
        preferences(context).edit().putString(PENDING_TOKEN, token).apply()
    }

    fun confirmToken(context: Context, token: String) {
        if (pendingToken(context) == token) {
            preferences(context).edit().remove(PENDING_TOKEN).apply()
        }
    }

    fun disable(context: Context) {
        preferences(context).edit()
            .putBoolean(DELIVERY_ENABLED, false)
            .remove(PENDING_TOKEN)
            .apply()
    }

    private fun preferences(context: Context) =
        context.applicationContext.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
}
