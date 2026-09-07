package ru.nelomai.client

import android.app.ActivityManager
import android.content.Context
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
    fun background(action: String, request: String): String =
        ru.nelomai.runtime.v1.RuntimeNativeBackgroundReplyV1.await { bridge().background(context, action, request, it) }

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
}
