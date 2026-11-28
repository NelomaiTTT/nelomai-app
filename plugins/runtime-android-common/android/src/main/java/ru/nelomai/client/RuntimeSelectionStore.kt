package ru.nelomai.client

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.DeadObjectException
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Parcel
import android.os.ParcelFileDescriptor
import org.json.JSONObject
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

/** Read-through Binder client. The Rust owner remains the only selection store. */
class RuntimeSelectionStore @JvmOverloads constructor(
    private val context: Context,
    private val readOffMain: Boolean = false,
) : AutoCloseable {
    private var vpnProcessToken: IBinder? = null

    // Runtimes compiled against the earlier Kotlin default constructor still use this ABI.
    @Suppress("UNUSED_PARAMETER")
    constructor(context: Context, allowOwnerOomManagement: Boolean = true, readOffMain: Boolean = false) :
        this(context, readOffMain)

    constructor(context: Context, vpnProcessToken: IBinder) :
        this(context, readOffMain = true) {
        this.vpnProcessToken = vpnProcessToken
    }

    var updateProtocol: Int = 1
        private set
    private val handler = Handler(Looper.getMainLooper())
    @Volatile private var remote: IBinder? = null
    private var connection: ServiceConnection? = null
    private var rebindAttempted = false
    private var unfrozenBindingAttempted = false
    private var ownerConnectionObserver: ((RuntimeSelectionV1) -> Unit)? = null
    private val pending = PendingSelectionReads<RuntimeSelectionV1>(8)
    private val worker = if (readOffMain) ThreadPoolExecutor(
        1, 1, 0, TimeUnit.MILLISECONDS, ArrayBlockingQueue(2),
        { task -> Thread(task, "nelomai-owner-selection").apply { isDaemon = true } },
    ) else null
    private var reading = false
    private var readVersion = 0L
    private val retryBinding = Runnable {
        if (remote == null && (pending.size() != 0 || ownerConnectionObserver != null)) {
            rebindAttempted = true
            invalidateBinding()
            bind()
        }
    }
    private val timeout = Runnable {
        readVersion++
        if (remote == null && ownerConnectionObserver == null) invalidateBinding()
        complete(Result.failure(IllegalStateException("runtime_owner_unavailable")))
    }
    private fun newConnection() = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            if (connection !== this || !unfrozenBindingAttempted) return
            handler.removeCallbacks(retryBinding)
            readVersion++
            remote = binder
            if (readOffMain) {
                readPending()
            } else {
                val result = runCatching { snapshot() }
                if (result.exceptionOrNull() is DeadObjectException) {
                    remote = null
                    scheduleBindingRetry()
                    return
                }
                if (result.isSuccess) rebindAttempted = false
                complete(result)
                if (remote === binder) result.onSuccess { ownerConnectionObserver?.invoke(it) }
            }
        }
        override fun onServiceDisconnected(name: ComponentName?) {
            if (connection !== this) return
            readVersion++
            remote = null
        }
        override fun onNullBinding(name: ComponentName?) {
            if (connection !== this) return
            invalidateBinding()
            complete(Result.failure(IllegalStateException("runtime_owner_unavailable")))
        }
        override fun onBindingDied(name: ComponentName?) {
            if (connection !== this) return
            invalidateBinding()
            complete(Result.failure(IllegalStateException("runtime_owner_unavailable")))
        }
    }
    // Android can cache an owner that has displayed UI even while a noncached
    // child is normally bound to it. WPRI separately keeps that owner unfrozen;
    // retain the normal binding as well so foreground/VPN OOM priority is not lost.
    // The normal connection owns Binder delivery, death handling and both releases.
    private val unfrozenConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) = Unit
        override fun onServiceDisconnected(name: ComponentName?) = Unit
    }

    /** Observe successful snapshots from each Binder connection of the runtime UI. */
    fun observeOwnerConnections(observer: (RuntimeSelectionV1) -> Unit) {
        check(!readOffMain)
        ownerConnectionObserver = observer
    }

    fun read(callback: (Result<RuntimeSelectionV1>) -> Unit) {
        if (!readOffMain && remote != null) {
            val result = runCatching { snapshot() }
            if (result.exceptionOrNull() !is DeadObjectException) {
                callback(result)
                return
            }
            // Queue the reader before scheduling reconnection.
            remote = null
        }
        val startOfBatch = pending.size() == 0
        if (!pending.offer(callback)) {
            callback(Result.failure(IllegalStateException("runtime_owner_queue_full")))
            return
        }
        if (startOfBatch) {
            rebindAttempted = false
            handler.postDelayed(timeout, READ_TIMEOUT_MILLIS)
        }
        when {
            connection == null -> bind()
            startOfBatch && remote == null -> scheduleBindingRetry()
            readOffMain -> readPending()
        }
    }

    private fun scheduleBindingRetry() {
        // Give AMS time to reconnect. A transaction can fail on a live broker
        // without an Android disconnect, so refresh the binding once per batch.
        if (rebindAttempted || (pending.size() == 0 && ownerConnectionObserver == null)) return
        handler.removeCallbacks(retryBinding)
        handler.postDelayed(retryBinding, REBIND_DELAY_MILLIS)
    }

    private fun bind() {
        val next = newConnection()
        connection = next
        val intent = Intent().setClassName(context.packageName, "ru.nelomai.client.RuntimeAuthBrokerService")
        val bound = try {
            if (context.bindService(intent, next, Context.BIND_AUTO_CREATE) && connection === next) {
                unfrozenBindingAttempted = true
                context.bindService(intent, unfrozenConnection, Context.BIND_AUTO_CREATE or Context.BIND_WAIVE_PRIORITY)
            } else false
        } catch (_: RuntimeException) {
            false
        }
        if (!bound && connection === next) {
            invalidateBinding()
            complete(Result.failure(IllegalStateException("runtime_owner_unavailable")))
        }
    }

    /** Discard the in-flight result, keeping its readers in the next batch. */
    fun invalidatePendingSnapshot() {
        readVersion++
    }

    private fun readPending() {
        val binder = remote ?: return
        if (reading || pending.size() == 0) return
        val version = readVersion
        val batchSize = pending.size()
        val startedAt = android.os.SystemClock.uptimeMillis()
        reading = true
        try {
            requireNotNull(worker).execute {
                val result = runCatching { snapshotFrom(binder) }
                handler.post {
                    reading = false
                    if (remote === binder && readVersion == version) {
                        when {
                            android.os.SystemClock.uptimeMillis() - startedAt >= READ_TIMEOUT_MILLIS -> timeout.run()
                            result.exceptionOrNull() is DeadObjectException -> {
                                remote = null
                                scheduleBindingRetry()
                            }
                            else -> {
                                val ready = pending.take(batchSize)
                                if (pending.size() == 0) handler.removeCallbacks(timeout)
                                ready.forEach { callback -> runCatching { callback(result) } }
                            }
                        }
                    }
                    readPending()
                }
            }
        } catch (error: java.util.concurrent.RejectedExecutionException) {
            reading = false
            complete(Result.failure(error))
        }
    }

    fun snapshot(): RuntimeSelectionV1 {
        val binder = requireNotNull(remote)
        val executor = worker ?: return snapshotFrom(binder)
        check(Looper.myLooper() != Looper.getMainLooper())
        val task = java.util.concurrent.FutureTask { snapshotFrom(binder) }
        executor.execute(task)
        return try {
            task.get(READ_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS).also {
                check(remote === binder) { "runtime_owner_changed" }
            }
        } finally {
            if (!task.isDone) {
                task.cancel(false)
                executor.remove(task)
            }
        }
    }

    private var watchedBy: IBinder? = null

    private fun snapshotFrom(binder: IBinder): RuntimeSelectionV1 {
        // The VPN dispatcher uses the serial selection worker. A synchronous call lets the
        // broker identify the token's real caller PID, which Android hides for one-way calls.
        if (vpnProcessToken != null && watchedBy !== binder) {
            val data = Parcel.obtain()
            val reply = Parcel.obtain()
            try {
                data.writeInterfaceToken(RuntimeOwnerProtocol.DESCRIPTOR)
                data.writeStrongBinder(vpnProcessToken)
                // A false transaction means this broker does not implement the optional watch.
                if (binder.transact(RuntimeOwnerProtocol.WATCH_VPN_PROCESS, data, reply, 0)) reply.readException()
                watchedBy = binder
            } catch (error: Exception) {
                // The mandatory selection below determines whether the connection is usable.
                // Retry the watch on the next read if this broker is still alive.
                android.util.Log.w("NelomaiStartup", "VPN process observer unavailable", error)
            } finally { data.recycle(); reply.recycle() }
        }
        val startedAt = android.os.SystemClock.uptimeMillis()
        return transact(binder, RuntimeOwnerProtocol.SELECTION) { _, reply ->
            decode(requireNotNull(reply.readString())).apply { brokerVerifiedAtUptimeMillis = startedAt }
        }
    }

    fun attach(selection: RuntimeSelectionV1): Pair<ParcelFileDescriptor, String> {
        val request = JSONObject().apply {
            put("target", JSONObject().apply {
                put("runtime_slot", selection.slot); put("runtime_version", selection.runtimeVersion)
                put("container_version", selection.containerVersion); put("runtime_contract_version", 1)
            })
            put("session_generation", selection.sessionGeneration ?: JSONObject.NULL)
            put("incarnation", selection.incarnation)
        }.toString()
        val data = Parcel.obtain()
        val reply = Parcel.obtain()
        try {
            data.writeInterfaceToken(RuntimeOwnerProtocol.DESCRIPTOR)
            data.writeString(request)
            check(requireNotNull(remote).transact(RuntimeOwnerProtocol.ATTACH, data, reply, 0))
            reply.readException()
            val bootstrap = requireNotNull(reply.readString())
            val fd = requireNotNull(reply.readParcelable<ParcelFileDescriptor>(ParcelFileDescriptor::class.java.classLoader))
            try {
                // Optional owner-advertised sideband, never a new field in strict V1 JSON.
                // Old owners have no tail; unknown versions stay on the legacy decoder.
                val advertised = if (reply.dataAvail() == 0) 1 else {
                    require(reply.dataAvail() == 4) { "runtime_capability_invalid" }
                    reply.readInt()
                }
                updateProtocol = if (advertised == 2) 2 else 1
                if (updateProtocol == 2) {
                    val registration = Parcel.obtain()
                    val acknowledgement = Parcel.obtain()
                    try {
                        registration.writeInterfaceToken(RuntimeOwnerProtocol.DESCRIPTOR)
                        registration.writeString(selection.incarnation)
                        registration.writeStrongBinder(RuntimeUpdateVisibility.probe)
                        check(requireNotNull(remote).transact(RuntimeOwnerProtocol.UPDATE_VISIBILITY, registration, acknowledgement, 0))
                        acknowledgement.readException()
                    } finally { registration.recycle(); acknowledgement.recycle() }
                }
                return fd to bootstrap
            } catch (error: Throwable) { fd.close(); throw error }
        } finally { data.recycle(); reply.recycle() }
    }

    private fun <T> transact(binder: IBinder, code: Int, read: (Parcel, Parcel) -> T): T {
        val data = Parcel.obtain()
        val reply = Parcel.obtain()
        try {
            data.writeInterfaceToken(RuntimeOwnerProtocol.DESCRIPTOR)
            check(binder.transact(code, data, reply, 0))
            reply.readException()
            return read(data, reply)
        } finally { data.recycle(); reply.recycle() }
    }

    private fun complete(result: Result<RuntimeSelectionV1>) {
        handler.removeCallbacks(timeout)
        handler.removeCallbacks(retryBinding)
        pending.complete(result)
    }

    private fun invalidateBinding() {
        readVersion++
        remote = null
        handler.removeCallbacks(retryBinding)
        val old = connection
        connection = null
        if (old != null) runCatching { context.unbindService(old) }
        if (unfrozenBindingAttempted) {
            unfrozenBindingAttempted = false
            runCatching { context.unbindService(unfrozenConnection) }
        }
    }

    override fun close() {
        ownerConnectionObserver = null
        handler.removeCallbacks(timeout)
        pending.complete(Result.failure(IllegalStateException("runtime_selection_store_closed")))
        invalidateBinding()
        worker?.shutdownNow()
    }

    companion object {
        private const val REBIND_DELAY_MILLIS = 250L
        private const val READ_TIMEOUT_MILLIS = 10_000L
        fun decode(value: String): RuntimeSelectionV1 {
            return RuntimeSelectionCodec.decode(value)
        }
        fun encodeVpnRecoveryOwner(value: RuntimeSelectionV1): String = encodeFields(value).apply {
            value.vpnAuthorization?.let { authorization ->
                put("vpn_authorization", JSONObject().put("scope", authorization.scope ?: JSONObject.NULL)
                    .put("blocked", authorization.blocked).put("logout_epoch", authorization.logoutEpoch ?: JSONObject.NULL))
            }
        }.toString()

        fun encode(value: RuntimeSelectionV1): String = encodeFields(value).toString()

        private fun encodeFields(value: RuntimeSelectionV1): JSONObject = JSONObject().apply {
            put("slot", value.slot); put("runtime_version", value.runtimeVersion)
            put("container_version", value.containerVersion)
            put("session_generation", value.sessionGeneration ?: JSONObject.NULL)
            put("pending_slot", value.pendingSlot ?: JSONObject.NULL)
            put("incarnation", value.incarnation)
        }
    }
}

object RuntimeOwnerProtocol {
    const val DESCRIPTOR = "ru.nelomai.runtime.v1.AuthBroker"
    const val SELECTION = IBinder.FIRST_CALL_TRANSACTION
    const val ATTACH = IBinder.FIRST_CALL_TRANSACTION + 1
    const val UPDATE_VISIBILITY = IBinder.FIRST_CALL_TRANSACTION + 2
    const val WATCH_VPN_PROCESS = IBinder.FIRST_CALL_TRANSACTION + 3
}
