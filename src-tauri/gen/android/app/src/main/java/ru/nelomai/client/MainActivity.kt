package ru.nelomai.client

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import androidx.activity.enableEdgeToEdge
import io.crates.keyring.Keyring

class MainActivity : TauriActivity() {
  override val handleBackNavigation: Boolean = true

  private val startupHandler = Handler(Looper.getMainLooper())
  private val frontendTimeout = Runnable {
    if (!StartupDiagnostics.frontendReady(applicationContext)) {
      StartupDiagnostics.record(applicationContext, "startup.android.frontend_timeout")
    }
  }

  override fun onCreate(savedInstanceState: Bundle?) {
    StartupDiagnostics.beginLaunch(applicationContext)
    startupHandler.postDelayed(frontendTimeout, 30_000L)
    enableEdgeToEdge()
    Keyring.initializeNdkContext(applicationContext)
    StartupDiagnostics.record(applicationContext, "startup.android.keyring_ready")
    super.onCreate(savedInstanceState)
    StartupDiagnostics.record(applicationContext, "startup.android.activity_created")
  }

  override fun onStart() {
    super.onStart()
    StartupDiagnostics.record(applicationContext, startupActivityLifecycleKind("started"))
  }

  override fun onResume() {
    super.onResume()
    StartupDiagnostics.record(applicationContext, startupActivityLifecycleKind("resumed"))
  }

  override fun onPause() {
    StartupDiagnostics.record(applicationContext, startupActivityLifecycleKind("paused"))
    super.onPause()
  }

  override fun onStop() {
    StartupDiagnostics.record(applicationContext, startupActivityLifecycleKind("stopped"))
    super.onStop()
  }

  override fun onWindowFocusChanged(hasFocus: Boolean) {
    super.onWindowFocusChanged(hasFocus)
    if (hasFocus) {
      StartupDiagnostics.record(applicationContext, "startup.android.window_focused")
    }
  }

  override fun onDestroy() {
    startupHandler.removeCallbacks(frontendTimeout)
    super.onDestroy()
  }
}
