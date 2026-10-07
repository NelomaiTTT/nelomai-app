package ru.nelomai.client

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import ru.nelomai.runtime.v1.SupportDiagnosticsEntry

/** Launcher only: no Tauri, keyring or versioned engine is loaded here. */
class MainActivity : Activity() {
    private var selection: RuntimeSelectionStore? = null
    private var launchStarted = false
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        if (routeDiagnostics(intent)) return
        selection = RuntimeSelectionStore(this)
        setContentView(android.widget.TextView(this).apply {
            text = "Запуск Nelomai…"
            setPadding(32, 64, 32, 32)
        })
    }
    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        // onCreate can still run at background importance on a cold start.
        if (!hasFocus || launchStarted || isFinishing || isDestroyed) return
        launchStarted = true
        var stage = SupportStartupStage.LAUNCHER_OWNER_START
        runCatching {
            startService(Intent(this, RuntimeAuthBrokerService::class.java))
            stage = SupportStartupStage.LAUNCHER_OWNER_READ
            selection?.read { result ->
                if (isFinishing || isDestroyed) return@read
                result.onSuccess { startActivity(Intent(this, RuntimeBootstrapActivity::class.java)); finish() }
                    .onFailure { SupportDiagnosticsStartup.showFailure(this, SupportStartupStage.LAUNCHER_OWNER_READ, it) }
            }
        }.onFailure { SupportDiagnosticsStartup.showFailure(this, stage, it) }
    }
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        routeDiagnostics(intent)
    }
    private fun routeDiagnostics(intent: Intent): Boolean {
        if (!SupportDiagnosticsEntry.isShortcut(intent)) return false
        launchStarted = true
        SupportDiagnosticsEntry.open(this)
        finish()
        return true
    }
    override fun onDestroy() { selection?.close(); super.onDestroy() }
}

/** Runs in :runtime so Binder records the actual admitted child PID. */
class RuntimeBootstrapActivity : Activity() {
    private lateinit var selection: RuntimeSelectionStore
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        selection = RuntimeSelectionStore(this)
        selection.read { result ->
            if (isFinishing || isDestroyed) return@read
            if (result.isFailure) {
                SupportDiagnosticsStartup.showFailure(this, SupportStartupStage.BOOTSTRAP_OWNER_READ, requireNotNull(result.exceptionOrNull()))
                return@read
            }
            result.onSuccess { selected ->
                var stage = SupportStartupStage.BOOTSTRAP_PROCESS_CLAIM
                runCatching {
                    if (RuntimeProcessSelection.needsExit(selected)) {
                        startActivity(Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                        android.os.Process.killProcess(android.os.Process.myPid())
                        return@runCatching
                    }
                    if (RuntimeProcessSelection.hasAdmission(selected)) {
                        stage = SupportStartupStage.BOOTSTRAP_ACTIVITY_START
                        startActivity(Intent().setClassName(packageName, RuntimeAdapters.activity(selected)))
                        return@runCatching
                    }
                    RuntimeProcessSelection.claim(selected)
                    stage = SupportStartupStage.BOOTSTRAP_OWNER_ATTACH
                    val (fd, bootstrap) = selection.attach(selected)
                    fd.use {
                        val launch = Intent().setClassName(packageName, RuntimeAdapters.activity(selected))
                            .putExtra("runtime_endpoint_v1", fd).putExtra("runtime_bootstrap_v1", bootstrap)
                            .putExtra("runtime_selection_v1", RuntimeSelectionStore.encode(selected))
                        stage = SupportStartupStage.BOOTSTRAP_ACTIVITY_PREPARE
                        RuntimeAdapters.prepareActivity(selected, launch)
                        stage = SupportStartupStage.BOOTSTRAP_ACTIVITY_START
                        startActivity(launch)
                    }
                }.onFailure {
                    SupportDiagnosticsStartup.showFailure(this, stage, it)
                    return@read
                }
            }
            finish()
        }
    }
    override fun onDestroy() { selection.close(); super.onDestroy() }
}
