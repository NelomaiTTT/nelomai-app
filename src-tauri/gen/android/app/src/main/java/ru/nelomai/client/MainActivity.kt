package ru.nelomai.client

import android.app.Activity
import android.content.Intent
import android.os.Bundle

/** Launcher only: no Tauri, keyring or versioned engine is loaded here. */
class MainActivity : Activity() {
    private lateinit var selection: RuntimeSelectionStore
    private var launchStarted = false
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
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
        runCatching {
            startService(Intent(this, RuntimeAuthBrokerService::class.java))
            selection.read { result ->
                if (isFinishing || isDestroyed) return@read
                result.onSuccess { startActivity(Intent(this, RuntimeBootstrapActivity::class.java)); finish() }
                    .onFailure { showRuntimeStartupFailure(it) }
            }
        }.onFailure { showRuntimeStartupFailure(it) }
    }
    override fun onDestroy() { selection.close(); super.onDestroy() }
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
                showRuntimeStartupFailure(requireNotNull(result.exceptionOrNull()))
                return@read
            }
            result.onSuccess { selected ->
                runCatching {
                    if (RuntimeProcessSelection.needsExit(selected)) {
                        startActivity(Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                        android.os.Process.killProcess(android.os.Process.myPid())
                        return@runCatching
                    }
                    if (RuntimeProcessSelection.hasAdmission(selected)) {
                        startActivity(Intent().setClassName(packageName, RuntimeAdapters.activity(selected)))
                        return@runCatching
                    }
                    RuntimeProcessSelection.claim(selected)
                    val (fd, bootstrap) = selection.attach(selected)
                    fd.use {
                        val launch = Intent().setClassName(packageName, RuntimeAdapters.activity(selected))
                            .putExtra("runtime_endpoint_v1", fd).putExtra("runtime_bootstrap_v1", bootstrap)
                            .putExtra("runtime_selection_v1", RuntimeSelectionStore.encode(selected))
                        RuntimeAdapters.prepareActivity(selected, launch)
                        startActivity(launch)
                    }
                }.onFailure {
                    showRuntimeStartupFailure(it)
                    return@read
                }
            }
            finish()
        }
    }
    override fun onDestroy() { selection.close(); super.onDestroy() }
}

private fun Activity.showRuntimeStartupFailure(error: Throwable) {
    val cause = (error as? java.lang.reflect.InvocationTargetException)?.targetException ?: error
    // Do not log bootstrap payloads, tokens or exception messages containing them.
    android.util.Log.e("NelomaiStartup", "runtime_bootstrap_failed: ${cause.javaClass.name}\n" +
        cause.stackTrace.take(8).joinToString("\n"))
    setContentView(android.widget.TextView(this).apply {
        text = "Не удалось запустить Nelomai. Закройте и откройте приложение. Данные сохранены."
        setPadding(32, 64, 32, 32)
    })
}
