package ru.nelomai.client

import android.app.Activity
import android.os.Binder
import android.os.IBinder
import android.os.Parcel
import android.os.Process
import java.lang.ref.WeakReference
import java.util.concurrent.atomic.AtomicReference

/** Read-only proof from the admitted runtime process. No install authority lives here. */
object RuntimeUpdateVisibility {
    private const val DESCRIPTOR = "ru.nelomai.runtime.v1.UpdateVisibility"
    private val resumed = AtomicReference<WeakReference<Activity>?>(null)
    fun resumed(activity: Activity) { resumed.set(WeakReference(activity)) }
    fun paused(activity: Activity): Boolean {
        val current = resumed.get()
        return current?.get() === activity && resumed.compareAndSet(current, null)
    }
    val probe: IBinder = object : Binder() {
        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            if (code != FIRST_CALL_TRANSACTION) return super.onTransact(code, data, reply, flags)
            require(Binder.getCallingUid() == Process.myUid() && data.dataSize() < 1024 && reply != null)
            data.enforceInterface(DESCRIPTOR)
            require(data.dataAvail() == 0)
            reply.writeNoException()
            reply.writeInt(if (resumed.get()?.get() != null) 1 else 0)
            return true
        }
    }
    fun isForeground(probe: IBinder?): Boolean {
        if (probe == null) return false
        val data = Parcel.obtain()
        val reply = Parcel.obtain()
        return try {
            data.writeInterfaceToken(DESCRIPTOR)
            check(probe.transact(IBinder.FIRST_CALL_TRANSACTION, data, reply, 0))
            reply.readException()
            val visible = reply.readInt() == 1
            visible && reply.dataAvail() == 0
        } catch (_: Exception) { false }
        finally { data.recycle(); reply.recycle() }
    }
}
