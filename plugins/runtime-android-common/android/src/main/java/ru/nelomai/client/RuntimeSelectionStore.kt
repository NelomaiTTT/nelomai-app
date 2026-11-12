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
    private val allowOwnerOomManagement: Boolean = true,
    private val readOffMain: Boolean = false,
) : AutoCloseable {
    var updateProtocol: Int = 1
        private set
    private val handler = Handler(Looper.getMainLooper())
    @Volatile private var remote: IBinder? = null
    private var bound = false
    private var ownerConnectionObserver: ((RuntimeSelectionV1) -> Unit)? = null
    private val pending = PendingSelectionReads<RuntimeSelectionV1>(8)
    private val worker = if (readOffMain) ThreadPoolExecutor(
        1, 1, 0, TimeUnit.MILLISECONDS, ArrayBlockingQueue(2),
        { task -> Thread(task, "nelomai-owner-selection").apply { isDaemon = true } },
    ) else null
    private var reading = false
    private var readVersion = 0L
    private val timeout = Runnable {
        readVersion++
        complete(Result.failure(IllegalStateException("runtime_owner_unavailable")))
    }
    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            readVersion++
            remote = binder
            if (readOffMain) {
                readPending()
            } else {
                val result = runCatching { snapshot() }
                if (result.exceptionOrNull() is DeadObjectException) {
                    // Keep the pending reads and their deadline for the next Binder.
                    remote = null
                    return
                }
                complete(result)
                if (remote === binder) result.onSuccess { ownerConnectionObserver?.invoke(it) }
            }
        }
        override fun onServiceDisconnected(name: ComponentName?) { readVersion++; remote = null }
        override fun onNullBinding(name: ComponentName?) {
            invalidateBinding()
            complete(Result.failure(IllegalStateException("runtime_owner_unavailable")))
        }
        override fun onBindingDied(name: ComponentName?) {
            invalidateBinding()
            complete(Result.failure(IllegalStateException("runtime_owner_unavailable")))
        }
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
            // A transaction can observe death before onServiceDisconnected.
            // Let the existing binding deliver the replacement to queued readers.
            remote = null
        }
        val startOfBatch = pending.size() == 0
        if (!pending.offer(callback)) {
            callback(Result.failure(IllegalStateException("runtime_owner_queue_full")))
            return
        }
        if (bound) {
            if (startOfBatch) handler.postDelayed(timeout, READ_TIMEOUT_MILLIS)
            if (readOffMain) readPending()
            return
        }
        // UI callers keep the freezer dependency even when the broker is cached.
        // The VPN dispatcher needs its foreground importance to reach the broker.
        val flags = Context.BIND_AUTO_CREATE or
            (if (allowOwnerOomManagement) Context.BIND_ALLOW_OOM_MANAGEMENT else 0)
        bound = context.bindService(
            Intent().setClassName(context.packageName, "ru.nelomai.client.RuntimeAuthBrokerService"),
            connection, flags,
        )
        if (!bound) complete(Result.failure(IllegalStateException("runtime_owner_unavailable")))
        else if (startOfBatch && pending.size() != 0) handler.postDelayed(timeout, READ_TIMEOUT_MILLIS)
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
                            result.exceptionOrNull() is DeadObjectException -> remote = null
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

    private fun snapshotFrom(binder: IBinder): RuntimeSelectionV1 {
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
        pending.complete(result)
    }

    private fun invalidateBinding() {
        readVersion++
        remote = null
        if (bound) runCatching { context.unbindService(connection) }
        bound = false
    }

    override fun close() {
        ownerConnectionObserver = null
        handler.removeCallbacks(timeout)
        pending.complete(Result.failure(IllegalStateException("runtime_selection_store_closed")))
        invalidateBinding()
        worker?.shutdownNow()
    }

    companion object {
        private const val READ_TIMEOUT_MILLIS = 10_000L
        fun decode(value: String): RuntimeSelectionV1 {
            return RuntimeSelectionCodec.decode(value)
        }
        fun encode(value: RuntimeSelectionV1): String = JSONObject().apply {
            put("slot", value.slot); put("runtime_version", value.runtimeVersion)
            put("container_version", value.containerVersion)
            put("session_generation", value.sessionGeneration ?: JSONObject.NULL)
            put("pending_slot", value.pendingSlot ?: JSONObject.NULL)
            put("incarnation", value.incarnation)
        }.toString()
    }
}

object RuntimeOwnerProtocol {
    const val DESCRIPTOR = "ru.nelomai.runtime.v1.AuthBroker"
    const val SELECTION = IBinder.FIRST_CALL_TRANSACTION
    const val ATTACH = IBinder.FIRST_CALL_TRANSACTION + 1
    const val UPDATE_VISIBILITY = IBinder.FIRST_CALL_TRANSACTION + 2
}
