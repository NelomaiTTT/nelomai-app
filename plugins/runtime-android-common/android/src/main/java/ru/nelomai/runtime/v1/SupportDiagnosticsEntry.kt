package ru.nelomai.runtime.v1

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.webkit.JavascriptInterface
import android.webkit.WebView

/** Only opens a fixed private screen. Intents/JavaScript cannot supply a code, path, or payload. */
object SupportDiagnosticsEntry {
    fun isShortcut(intent: Intent): Boolean = intent.getBooleanExtra("nelomai_support_diagnostics", false)
    fun open(activity: Activity) = activity.startActivity(Intent().setClassName(activity.packageName, "ru.nelomai.client.SupportDiagnosticsActivity"))
    fun trustedWebOrigin(url: String?): Boolean {
        val uri = url?.let { Uri.parse(it) } ?: return false
        return uri.scheme in listOf("https", "http", "tauri") && uri.host in listOf("tauri.localhost", "localhost") &&
            (uri.host != "localhost" || uri.scheme == "tauri") && uri.port == -1 && uri.userInfo == null
    }
    fun install(activity: Activity, webView: WebView) {
        webView.addJavascriptInterface(SupportDiagnosticsBridge(activity, webView), "NelomaiSupportDiagnostics")
    }
}

private class SupportDiagnosticsBridge(private val activity: Activity, private val webView: WebView) {
    @JavascriptInterface fun open() {
        activity.runOnUiThread {
            if (!activity.isFinishing && !activity.isDestroyed && SupportDiagnosticsEntry.trustedWebOrigin(webView.url)) {
                SupportDiagnosticsEntry.open(activity)
            }
        }
    }
}
