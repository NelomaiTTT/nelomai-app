package ru.nelomai.client

import android.app.Activity
import android.content.Intent
import android.os.Bundle

/** Launcher only: no Tauri, keyring or versioned engine is loaded here. */
class MainActivity : Activity() {
    private lateinit var selection: RuntimeSelectionStore
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        startService(Intent(this, RuntimeAuthBrokerService::class.java))
        selection = RuntimeSelectionStore(this)
        selection.read { result ->
            if (isFinishing || isDestroyed) return@read
            result.onSuccess { startActivity(Intent(this, RuntimeBootstrapActivity::class.java)); finish() }
                .onFailure { setContentView(android.widget.TextView(this).apply { text = "Запуск остановлен: требуется восстановление данных Nelomai. Повторите запуск приложения."; setPadding(32, 64, 32, 32) }) }
        }
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
                        startActivity(Intent().setClassName(packageName, RuntimeAdapters.activity(selected))
                            .putExtra("runtime_endpoint_v1", fd).putExtra("runtime_bootstrap_v1", bootstrap)
                            .putExtra("runtime_selection_v1", RuntimeSelectionStore.encode(selected)))
                    }
                }
            }
            finish()
        }
    }
    override fun onDestroy() { selection.close(); super.onDestroy() }
}
