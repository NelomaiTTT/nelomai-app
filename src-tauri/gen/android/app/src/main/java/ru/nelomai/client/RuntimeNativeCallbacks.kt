package ru.nelomai.client

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.os.Process
import ru.nelomai.runtime.v1.RuntimeNativeBridgeV1
import ru.nelomai.runtime.v1.RuntimeNativeResultV1
import ru.nelomai.runtime.v1.RuntimeServiceIntents
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

/** Called on the native owner's worker, never on Android's main thread. */
class RuntimeNativeCallbacks(private val context: RuntimeAuthBrokerService) {
    fun cleanupPush(): Boolean = ru.nelomai.push.CommonPushCleanup.cleanup(context)
    private var migrationStorage: ru.nelomai.runtime.v1.RuntimeNativeStorageV1? = null
    fun prepareNativeStorage(slot: String, version: String, legacyMigration: Boolean, migrationComplete: Boolean): Boolean {
        val namespace = when (slot) {
            "latest" -> "ru.nelomai.tunnel"
            "stable" -> "ru.nelomai.runtime.stable.tunnel"
            else -> error("runtime_slot_unavailable")
        }
        val storage = Class.forName("$namespace.LatestRuntimeStorageV1").getConstructor().newInstance() as ru.nelomai.runtime.v1.RuntimeNativeStorageV1
        storage.prepare(context, slot, version, legacyMigration, migrationComplete)
        migrationStorage = storage
        return true
    }
    fun acknowledgeNativeStorage(): Boolean {
        requireNotNull(migrationStorage).acknowledge(context)
        return true
    }
    fun installApk(path: String, version: String, signer: String): Boolean = RuntimeApkInstaller.install(context, path, version, signer)
    private fun bridge(): RuntimeNativeBridgeV1 {
        val selected = RuntimeSelectionStore.decode(context.currentSelection())
        val namespace = when (selected.slot) {
            "latest" -> "ru.nelomai.tunnel"
            "stable" -> "ru.nelomai.runtime.stable.tunnel"
            else -> error("runtime_slot_unavailable")
        }
        return Class.forName("$namespace.LatestRuntimeNativeBridgeV1").getConstructor().newInstance() as RuntimeNativeBridgeV1
    }
    private fun await(call: (RuntimeNativeResultV1) -> Unit): String {
        check(android.os.Looper.myLooper() != android.os.Looper.getMainLooper())
        val completed = CompletableFuture<String>()
        call(object : RuntimeNativeResultV1 {
            override fun success(value: String) { completed.complete(value) }
            override fun failure(code: String) { completed.completeExceptionally(IllegalStateException(code)) }
        })
        return completed.get(10, TimeUnit.SECONDS)
    }
    fun prepareRevocation(cancelEpoch: Long): Boolean {
        ru.nelomai.runtime.v1.RuntimePushGate(context.filesDir).revoke(cancelEpoch)
        await { bridge().prepareRevocation(context, cancelEpoch, it) }
        return true
    }
    fun background(action: String, request: String): String {
        require(action in setOf("provision", "recover", "status"))
        return try {
            ru.nelomai.runtime.v1.RuntimeNativeBackgroundReplyV1.await { result ->
                bridge().background(context, action, request, object : RuntimeNativeResultV1 {
                    override fun success(value: String) = result.success(value)
                    override fun failure(code: String) {
                        // Only bounded machine codes, never callback payloads or exceptions' messages.
                        val safeCode = code.takeIf { it.matches(Regex("[a-z_]{1,80}")) } ?: "unknown"
                        android.util.Log.w("NelomaiOwner", "background.$action.failed code=$safeCode")
                        result.failure(code)
                    }
                })
            }
        } catch (error: Exception) {
            android.util.Log.w("NelomaiOwner", "background.$action.exception class=${error.javaClass.simpleName}")
            throw error
        }
    }

    fun stopVpn(force: Boolean): Boolean {
        val manager = context.getSystemService(ActivityManager::class.java)
        fun pids() = manager.runningAppProcesses.orEmpty().filter { it.uid == Process.myUid() && it.processName == context.packageName + ":vpn" }.map { it.pid }
        if (pids().isEmpty()) return true
        if (!force) await { bridge().stop(context, it) }
        context.stopService(RuntimeServiceIntents.vpn(context))
        // This callback is reached only after the coordinator's durable handoff.
        // Android may retain the process after service destruction; force-stop
        // owns the final process boundary, verified independently of IPC EOF.
        pids().forEach(Process::killProcess)
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
        while (System.nanoTime() < deadline) {
            if (pids().isEmpty()) return true
            Thread.sleep(25)
        }
        return false
    }

    fun relaunchRuntime(runtimePid: Int): Boolean = RuntimeRelaunchOrder.run(
        runtimePid = runtimePid,
        ownUid = Process.myUid(),
        processes = ::runtimeProcesses,
        foregroundHandoff = foreground@{
            if (!RuntimeRelaunchGate.begin(runtimePid)) return@foreground false
            val launched = runCatching {
                context.startActivity(
                    Intent(context, RuntimeRestartActivity::class.java)
                        .putExtra(RuntimeRelaunchGate.EXTRA_RUNTIME_PID, runtimePid)
                        .addFlags(RuntimeRestartLaunchPolicy.handoffFlags()),
                )
            }.isSuccess
            if (!launched) {
                RuntimeRelaunchGate.abort(runtimePid)
                return@foreground false
            }
            val foreground = RuntimeRelaunchGate.awaitForeground(runtimePid, 2, TimeUnit.SECONDS)
            if (!foreground) RuntimeRelaunchGate.abort(runtimePid)
            foreground
        },
        stopVpn = { stopVpn(false) },
        kill = Process::killProcess,
        waitUntilGone = { pid ->
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
            var gone = false
            while (System.nanoTime() < deadline) {
                if (runtimeProcesses()[pid] == null) {
                    gone = true
                    break
                }
                Thread.sleep(25)
            }
            gone
        },
        foregroundStillVisible = { RuntimeRelaunchGate.isForeground(runtimePid) },
        finishRuntimeStop = { success ->
            if (!success) RuntimeRelaunchGate.complete(runtimePid, false)
        },
    )

    fun releaseRuntimeOwnerReload(runtimePid: Int, success: Boolean): Boolean {
        RuntimeRelaunchGate.complete(runtimePid, success)
        return true
    }

    private fun runtimeProcesses(): Map<Int, RuntimeProcessInfo> =
        context.getSystemService(ActivityManager::class.java).runningAppProcesses.orEmpty()
            .associate { it.pid to RuntimeProcessInfo(it.uid, it.processName) }
}

data class RuntimeProcessInfo(val uid: Int, val name: String)

object RuntimeRelaunchOrder {
    fun run(
        runtimePid: Int,
        ownUid: Int,
        processes: () -> Map<Int, RuntimeProcessInfo>,
        foregroundHandoff: () -> Boolean,
        stopVpn: () -> Boolean,
        kill: (Int) -> Unit,
        waitUntilGone: (Int) -> Boolean,
        foregroundStillVisible: () -> Boolean,
        finishRuntimeStop: (Boolean) -> Unit,
    ): Boolean {
        fun validRuntime(): Boolean {
            val process = processes()[runtimePid] ?: return false
            return runtimePid > 0 && process.uid == ownUid && process.name.endsWith(":runtime")
        }
        if (!validRuntime() || !foregroundHandoff()) return false
        if (!stopVpn() || !validRuntime()) {
            finishRuntimeStop(false)
            return false
        }
        kill(runtimePid)
        val ready = waitUntilGone(runtimePid) && foregroundStillVisible()
        finishRuntimeStop(ready)
        return ready
    }
}

object RuntimeRelaunchGate {
    const val EXTRA_RUNTIME_PID = "runtime_restart_pid"
    private data class Handoff(
        val runtimePid: Int,
        val foreground: CompletableFuture<Unit> = CompletableFuture(),
        val release: CompletableFuture<Boolean> = CompletableFuture(),
        var visible: Boolean = false,
    )
    private var handoff: Handoff? = null

    @Synchronized fun begin(runtimePid: Int): Boolean {
        if (runtimePid <= 0 || handoff != null) return false
        handoff = Handoff(runtimePid)
        return true
    }

    @Synchronized fun foreground(runtimePid: Int, visible: Boolean) {
        val current = handoff?.takeIf { it.runtimePid == runtimePid } ?: return
        current.visible = visible
        if (visible) current.foreground.complete(Unit)
    }

    fun awaitForeground(runtimePid: Int, timeout: Long, unit: TimeUnit): Boolean {
        val current = synchronized(this) { handoff?.takeIf { it.runtimePid == runtimePid } }
            ?: return false
        return runCatching { current.foreground.get(timeout, unit) }.isSuccess &&
            synchronized(this) { handoff === current && current.visible }
    }

    @Synchronized fun isForeground(runtimePid: Int): Boolean =
        handoff?.takeIf { it.runtimePid == runtimePid }?.visible == true

    @Synchronized fun abort(runtimePid: Int) {
        val current = handoff?.takeIf { it.runtimePid == runtimePid } ?: return
        current.release.complete(false)
        handoff = null
    }

    @Synchronized fun complete(runtimePid: Int, success: Boolean) {
        handoff?.takeIf { it.runtimePid == runtimePid }?.release?.complete(success)
    }

    fun awaitRelease(runtimePid: Int, timeout: Long, unit: TimeUnit): Boolean {
        val current = synchronized(this) { handoff?.takeIf { it.runtimePid == runtimePid } }
            ?: return false
        val released = runCatching { current.release.get(timeout, unit) }.getOrDefault(false)
        synchronized(this) { if (handoff === current) handoff = null }
        return released
    }
}
