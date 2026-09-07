package ru.nelomai.client

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Parcel
import android.os.ParcelFileDescriptor
import org.json.JSONObject

/** Read-through Binder client. The Rust owner remains the only selection store. */
class RuntimeSelectionStore(private val context: Context) : AutoCloseable {
    private val handler = Handler(Looper.getMainLooper())
    private var remote: IBinder? = null
    private var bound = false
    private val pending = ArrayDeque<(Result<RuntimeSelectionV1>) -> Unit>()
    private val timeout = Runnable { complete(Result.failure(IllegalStateException("runtime_owner_unavailable"))) }
    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            remote = binder
            complete(runCatching { snapshot() })
        }
        override fun onServiceDisconnected(name: ComponentName?) { remote = null }
        override fun onNullBinding(name: ComponentName?) { complete(Result.failure(IllegalStateException("runtime_owner_unavailable"))) }
        override fun onBindingDied(name: ComponentName?) { remote = null; complete(Result.failure(IllegalStateException("runtime_owner_unavailable"))) }
    }

    fun read(callback: (Result<RuntimeSelectionV1>) -> Unit) {
        if (remote != null) { callback(runCatching { snapshot() }); return }
        check(pending.size < 8) { "runtime_owner_queue_full" }
        pending.addLast(callback)
        if (bound) return
        bound = context.bindService(Intent().setClassName(context.packageName, "ru.nelomai.client.RuntimeAuthBrokerService"), connection, Context.BIND_AUTO_CREATE)
        if (!bound) complete(Result.failure(IllegalStateException("runtime_owner_unavailable")))
        else handler.postDelayed(timeout, 10_000)
    }

    fun snapshot(): RuntimeSelectionV1 = transact(RuntimeOwnerProtocol.SELECTION) { _, reply ->
        decode(requireNotNull(reply.readString()))
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
            return fd to bootstrap
        } finally { data.recycle(); reply.recycle() }
    }

    private fun <T> transact(code: Int, read: (Parcel, Parcel) -> T): T {
        val data = Parcel.obtain()
        val reply = Parcel.obtain()
        try {
            data.writeInterfaceToken(RuntimeOwnerProtocol.DESCRIPTOR)
            check(requireNotNull(remote).transact(code, data, reply, 0))
            reply.readException()
            return read(data, reply)
        } finally { data.recycle(); reply.recycle() }
    }

    private fun complete(result: Result<RuntimeSelectionV1>) {
        handler.removeCallbacks(timeout)
        while (pending.isNotEmpty()) pending.removeFirst()(result)
    }

    override fun close() {
        handler.removeCallbacks(timeout)
        pending.clear()
        remote = null
        if (bound) context.unbindService(connection)
        bound = false
    }

    companion object {
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
}
