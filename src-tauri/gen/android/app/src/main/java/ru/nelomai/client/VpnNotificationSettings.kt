package ru.nelomai.client

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.webkit.JavascriptInterface
import android.webkit.WebView
import ru.nelomai.runtime.v1.SupportDiagnosticsEntry
import ru.nelomai.runtime.v1.VpnNotificationChannel

internal class VpnNotificationSettings(private val activity: Activity, private val webView: WebView) {
    @JavascriptInterface
    fun open() {
        activity.runOnUiThread {
            if (activity.isFinishing || activity.isDestroyed ||
                !SupportDiagnosticsEntry.trustedWebOrigin(webView.url)
            ) return@runOnUiThread

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                VpnNotificationChannel.create(activity)
                try {
                    activity.startActivity(Intent(Settings.ACTION_CHANNEL_NOTIFICATION_SETTINGS)
                        .putExtra(Settings.EXTRA_APP_PACKAGE, activity.packageName)
                        .putExtra(Settings.EXTRA_CHANNEL_ID, VpnNotificationChannel.ID))
                    return@runOnUiThread
                } catch (_: ActivityNotFoundException) {
                    // Some Android builds only expose application details.
                }
            }
            activity.startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                Uri.fromParts("package", activity.packageName, null)))
        }
    }
}
