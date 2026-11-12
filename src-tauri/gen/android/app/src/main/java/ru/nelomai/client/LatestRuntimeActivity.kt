package ru.nelomai.client

import ru.nelomai.client.RuntimeProcessSelection
import ru.nelomai.client.RuntimeUpdateVisibility
import ru.nelomai.runtime.v1.RuntimeActivityRecovery
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import io.crates.keyring.Keyring

class LatestRuntimeActivity : TauriActivity() {
  override var runtimeLifecycleEnabled: Boolean = false
    private set
  private val ownerConnection by lazy { ru.nelomai.client.RuntimeSelectionStore(this) }
  override val handleBackNavigation: Boolean = true

  private var startupWebView: android.webkit.WebView? = null
  private var runtimeResumed = false
  private var ownerChanged = false
  private var ownerRelaunchRequested = false
  private val ownerRecovery = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
    ownerRelaunchRequested = false
    relaunchIfOwnerChanged()
  }
  private val bootstrapNetworks by lazy { BootstrapNetworkMonitor(this, ::wakeStartup) }

  override fun onWebViewCreate(webView: android.webkit.WebView) {
    super.onWebViewCreate(webView)
    ru.nelomai.runtime.v1.SupportDiagnosticsEntry.install(this, webView)
    startupWebView = webView
    if (runtimeResumed) wakeStartup()
  }

  private fun wakeStartup() {
    val webView = startupWebView ?: return
    webView.post {
      if (runtimeResumed && startupWebView === webView) {
        webView.evaluateJavascript("window.dispatchEvent(new Event('nelomai-network-restored'))", null)
      }
    }
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
      RuntimeActivityRecovery.showFailure(this,
        allowRetry = allowRetry)
      return
    }
    if (RuntimeEntrypoint.supportsUpdates()) RuntimeEntrypoint.updateUiCreated(if (savedInstanceState == null) intent.getStringExtra("nelomai_update_launch_session") else null)
    intent.removeExtra("nelomai_update_launch_session")
    ownerConnection.observeOwnerConnections { selected ->
      if (RuntimeProcessSelection.needsExit(selected)) {
        ownerChanged = true
        relaunchIfOwnerChanged()
      }
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
    runtimeResumed = true
    if (RuntimeEntrypoint.supportsUpdates()) {
      RuntimeUpdateVisibility.resumed(this)
      RuntimeEntrypoint.updateUiResumed()
    }
    bootstrapNetworks.start()
    wakeStartup()
    StartupDiagnostics.record(applicationContext, startupActivityLifecycleKind("resumed"))
    relaunchIfOwnerChanged()
  }

  override fun onPause() {
    if (RuntimeEntrypoint.supportsUpdates() && RuntimeUpdateVisibility.paused(this)) RuntimeEntrypoint.updateUiPaused()
    runtimeResumed = false
    bootstrapNetworks.stop()
    if (runtimeLifecycleEnabled) StartupDiagnostics.record(applicationContext, startupActivityLifecycleKind("paused"))
    super.onPause()
  }

  override fun onStop() {
    if (RuntimeEntrypoint.supportsUpdates()) RuntimeEntrypoint.updateUiStopped(isChangingConfigurations)
    if (runtimeLifecycleEnabled) StartupDiagnostics.record(applicationContext, startupActivityLifecycleKind("stopped"))
    super.onStop()
  }

  override fun onWindowFocusChanged(hasFocus: Boolean) {
    super.onWindowFocusChanged(hasFocus)
    if (runtimeLifecycleEnabled && hasFocus) {
      StartupDiagnostics.record(applicationContext, "startup.android.window_focused")
      relaunchIfOwnerChanged()
    }
  }

  private fun relaunchIfOwnerChanged() {
    if (!ownerChanged || ownerRelaunchRequested || !runtimeResumed || !hasWindowFocus() ||
      isFinishing || isDestroyed) return
    // Bootstrap rechecks the broker incarnation and retires only this runtime.
    runCatching {
      ownerRecovery.launch(RuntimeActivityRecovery.bootstrapIntent(this)
        .putExtra(RuntimeActivityRecovery.OWNER_RECOVERY, true))
    }.onSuccess {
      ownerRelaunchRequested = true
      ownerChanged = false
    }.onFailure {
      android.util.Log.w("NelomaiStartup", "code=startup.runtime.owner_relaunch_failed")
    }
  }

  override fun onDestroy() {
    if (RuntimeEntrypoint.supportsUpdates() && RuntimeUpdateVisibility.paused(this)) RuntimeEntrypoint.updateUiPaused()
    runtimeResumed = false
    bootstrapNetworks.stop()
    startupWebView = null
    if (runtimeLifecycleEnabled) ownerConnection.close()
    startupHandler.removeCallbacks(frontendTimeout)
    super.onDestroy()
    if (runtimeLifecycleEnabled && isFinishing) android.os.Process.killProcess(android.os.Process.myPid())
  }
}
