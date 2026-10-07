package ru.nelomai.client

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import androidx.activity.enableEdgeToEdge
import io.crates.keyring.Keyring

class LatestRuntimeActivity : TauriActivity() {
  override var runtimeLifecycleEnabled: Boolean = false
    private set
  private val ownerConnection by lazy { ru.nelomai.client.RuntimeSelectionStore(this) }
  override val handleBackNavigation: Boolean = true

  override fun onWebViewCreate(webView: android.webkit.WebView) {
    super.onWebViewCreate(webView)
    ru.nelomai.runtime.v1.SupportDiagnosticsEntry.install(this, webView)
  }

  private val startupHandler = Handler(Looper.getMainLooper())
  private val frontendTimeout = Runnable {
    if (!StartupDiagnostics.frontendReady(applicationContext)) {
      StartupDiagnostics.record(applicationContext, "startup.android.frontend_timeout")
    }
  }

  override fun onCreate(savedInstanceState: Bundle?) {
    // The bootstrap consumes the Binder endpoint before startActivity. A restored
    // Activity cannot re-admit itself from saved extras after process death.
    runtimeLifecycleEnabled = RuntimeEntrypoint.isAttached()
    if (!runtimeLifecycleEnabled) {
      super.onCreate(savedInstanceState)
      val allowRetry = RuntimeEntrypoint.canRetryBootstrap()
      android.util.Log.e("NelomaiStartup", if (allowRetry) "code=startup.runtime.admission_missing"
        else "code=startup.runtime.native_attachment_incomplete")
      ru.nelomai.runtime.v1.RuntimeActivityRecovery.showFailure(this,
        allowRetry = allowRetry)
      return
    }
    ownerConnection.read { result ->
      if (result.isFailure) finish()
    }
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
    if (!runtimeLifecycleEnabled) return
    StartupDiagnostics.record(applicationContext, startupActivityLifecycleKind("started"))
  }

  override fun onResume() {
    super.onResume()
    if (!runtimeLifecycleEnabled) return
    StartupDiagnostics.record(applicationContext, startupActivityLifecycleKind("resumed"))
  }

  override fun onPause() {
    if (runtimeLifecycleEnabled) StartupDiagnostics.record(applicationContext, startupActivityLifecycleKind("paused"))
    super.onPause()
  }

  override fun onStop() {
    if (runtimeLifecycleEnabled) StartupDiagnostics.record(applicationContext, startupActivityLifecycleKind("stopped"))
    super.onStop()
  }

  override fun onWindowFocusChanged(hasFocus: Boolean) {
    super.onWindowFocusChanged(hasFocus)
    if (runtimeLifecycleEnabled && hasFocus) {
      StartupDiagnostics.record(applicationContext, "startup.android.window_focused")
    }
  }

  override fun onDestroy() {
    if (runtimeLifecycleEnabled) ownerConnection.close()
    startupHandler.removeCallbacks(frontendTimeout)
    super.onDestroy()
    if (runtimeLifecycleEnabled && isFinishing) android.os.Process.killProcess(android.os.Process.myPid())
  }
}
