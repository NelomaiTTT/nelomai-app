package ru.nelomai.client

import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.activity.enableEdgeToEdge
import io.crates.keyring.Keyring
import ru.nelomai.tunnel.TunnelPlugin

class MainActivity : TauriActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    if (isHeadlessQuickAction(intent)) {
      setTheme(R.style.Theme_nelomai_quick_action)
    }
    enableEdgeToEdge()
    Keyring.initializeNdkContext(applicationContext)
    super.onCreate(savedInstanceState)
    hideHeadlessQuickAction(intent)
  }

  override fun onNewIntent(intent: Intent) {
    super.onNewIntent(intent)
    setIntent(intent)
    hideHeadlessQuickAction(intent)
  }

  private fun isHeadlessQuickAction(intent: Intent?): Boolean =
    intent?.getBooleanExtra(TunnelPlugin.QUICK_ACTION_HEADLESS_EXTRA, false) == true

  private fun hideHeadlessQuickAction(intent: Intent?) {
    if (!isHeadlessQuickAction(intent)) return
    window.decorView.alpha = 0f
    window.decorView.visibility = View.INVISIBLE
  }
}
