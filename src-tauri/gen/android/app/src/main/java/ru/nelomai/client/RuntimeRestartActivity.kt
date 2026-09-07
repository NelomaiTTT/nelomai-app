package ru.nelomai.client

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

/** Common-process foreground handoff; it never loads Tauri, auth, or a runtime. */
class RuntimeRestartActivity : Activity() {
    private var runtimePid: Int = -1
    @Volatile private var ownerReady = false
    private var visible = false

    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        runtimePid = intent.getIntExtra(RuntimeRelaunchGate.EXTRA_RUNTIME_PID, -1)
        if (runtimePid <= 0) {
            finishAndRemoveTask()
            return
        }
        show("Перезапуск Nelomai…")
        Thread {
            val released = RuntimeRelaunchGate.awaitRelease(runtimePid, 6, TimeUnit.SECONDS)
            if (!released || !RuntimeOwnerReloadGate.begin()) {
                showFailure()
                return@Thread
            }
            stopService(Intent(this, RuntimeAuthBrokerService::class.java))
            if (!RuntimeOwnerReloadGate.awaitStopped(2, TimeUnit.SECONDS)) {
                RuntimeOwnerReloadGate.finish()
                showFailure()
                return@Thread
            }
            if (runCatching {
                    startService(Intent(this, RuntimeAuthBrokerService::class.java))
                }.isFailure
            ) {
                RuntimeOwnerReloadGate.finish()
                showFailure()
                return@Thread
            }
            ownerReady = RuntimeOwnerReloadGate.awaitReady(5, TimeUnit.SECONDS)
            RuntimeOwnerReloadGate.finish()
            if (ownerReady) runOnUiThread { launchIfReady() } else showFailure()
        }.start()
    }

    override fun onResume() {
        super.onResume()
        visible = true
        RuntimeRelaunchGate.foreground(runtimePid, true)
        launchIfReady()
    }

    override fun onPause() {
        visible = false
        RuntimeRelaunchGate.foreground(runtimePid, false)
        super.onPause()
    }

    override fun onDestroy() {
        RuntimeRelaunchGate.foreground(runtimePid, false)
        super.onDestroy()
    }

    private fun show(message: String) {
        setContentView(android.widget.TextView(this).apply {
            text = message
            setPadding(32, 64, 32, 32)
        })
    }

    private fun showFailure() {
        runOnUiThread {
            if (!isFinishing && !isDestroyed) {
                show("Перезапуск остановлен. Откройте Nelomai снова.")
            }
        }
    }

    private fun launchIfReady() {
        if (!ownerReady || !visible || isFinishing || isDestroyed) return
        ownerReady = false
        startActivity(
            Intent(this, RuntimeBootstrapActivity::class.java)
                .addFlags(RuntimeRestartLaunchPolicy.bootstrapFlags()),
        )
        finishAndRemoveTask()
    }
}

object RuntimeRestartLaunchPolicy {
    fun handoffFlags(): Int = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_MULTIPLE_TASK
    fun bootstrapFlags(): Int = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
}

object RuntimeOwnerReloadGate {
    private data class Reload(
        val stopped: CompletableFuture<Boolean> = CompletableFuture(),
        val ready: CompletableFuture<Boolean> = CompletableFuture(),
    )
    private var reload: Reload? = null

    @Synchronized fun begin(): Boolean {
        if (reload != null) return false
        reload = Reload()
        return true
    }

    @Synchronized fun ownerStopped(success: Boolean) {
        reload?.stopped?.complete(success)
    }

    @Synchronized fun ownerReady(success: Boolean) {
        reload?.ready?.complete(success)
    }

    fun awaitStopped(timeout: Long, unit: TimeUnit): Boolean {
        val current = synchronized(this) { reload } ?: return false
        return runCatching { current.stopped.get(timeout, unit) }.getOrDefault(false)
    }

    fun awaitReady(timeout: Long, unit: TimeUnit): Boolean {
        val current = synchronized(this) { reload } ?: return false
        return runCatching { current.ready.get(timeout, unit) }.getOrDefault(false)
    }

    @Synchronized fun finish() {
        reload = null
    }
}
