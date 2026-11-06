package ru.nelomai.client

import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import android.os.Parcel
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.SystemClock
import android.util.Log

class RuntimeAuthBrokerService : Service() {
    private var host: Long = 0
    private data class UpdateUiAdmission(val pid: Int, val incarnation: String, val probe: IBinder? = null)
    private val updateUiLock = Any()
    private var updateUiAdmission: UpdateUiAdmission? = null
    fun currentSelection(): String = RuntimeNativeHost.nativeSelection(host)
    fun updateUiForeground(): Boolean {
        val admitted = synchronized(updateUiLock) { updateUiAdmission } ?: return false
        return host != 0L && RuntimeNativeHost.nativeUpdateUiForeground(host) &&
            RuntimeUpdateVisibility.isForeground(admitted.probe) &&
            synchronized(updateUiLock) { updateUiAdmission === admitted }
    }
    private val binder = object : Binder() {
        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            if (code == INTERFACE_TRANSACTION) { reply?.writeString(DESCRIPTOR); return true }
            if (Binder.getCallingUid() != Process.myUid() || data.dataSize() > 65536 || reply == null) {
                throw SecurityException("runtime_binder_rejected")
            }
            data.enforceInterface(DESCRIPTOR)
            check(host != 0L) { "runtime_owner_unavailable" }
            return when (code) {
                SELECTION -> {
                    require(data.dataAvail() == 0)
                    val selection = RuntimeNativeHost.nativeSelection(host)
                    reply.writeNoException(); reply.writeString(selection)
                    true
                }
                ATTACH -> synchronized(updateUiLock) {
                    val request = requireNotNull(data.readString())
                    require(data.dataAvail() == 0)
                    val active = RuntimeSelectionStore.decode(RuntimeNativeHost.nativeSelection(host))
                    require(RuntimeDispatchPolicy.admit(active, RuntimeSelectionStore.decode(request), Binder.getCallingUid(), Process.myUid()))
                    val pair = ParcelFileDescriptor.createSocketPair()
                    try {
                        val started = SystemClock.elapsedRealtime()
                        val bootstrap = RuntimeNativeHost.nativeAttach(host, pair[0].detachFd(), Binder.getCallingPid(), Binder.getCallingUid(), request)
                        updateUiAdmission = UpdateUiAdmission(Binder.getCallingPid(), active.incarnation)
                        Log.i("NelomaiStartup", "owner.attach duration_ms=${SystemClock.elapsedRealtime() - started}")
                        reply.writeNoException(); reply.writeString(bootstrap)
                        reply.writeParcelable(pair[1], 0)
                        reply.writeInt(2) // updater capability; legacy Binder readers ignore the tail
                    } finally { pair.forEach { it.close() } }
                    true
                }
                RuntimeOwnerProtocol.UPDATE_VISIBILITY -> synchronized(updateUiLock) {
                    val incarnation = data.readString()
                    val probe = requireNotNull(data.readStrongBinder())
                    require(data.dataAvail() == 0)
                    val admitted = requireNotNull(updateUiAdmission)
                    require(admitted.pid == Binder.getCallingPid() && admitted.incarnation == incarnation && admitted.probe == null)
                    updateUiAdmission = admitted.copy(probe = probe)
                    reply.writeNoException()
                    true
                }
                else -> super.onTransact(code, data, reply, flags)
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        host = runCatching {
            var started = SystemClock.elapsedRealtime()
            val resources = RuntimeContainerAssets.prepare(this)
            Log.i("NelomaiStartup", "owner.assets duration_ms=${SystemClock.elapsedRealtime() - started}")
            started = SystemClock.elapsedRealtime()
            RuntimeNativeHost.nativeOpen(applicationContext, filesDir.absolutePath, resources.absolutePath, RuntimeNativeCallbacks(this)).also {
                Log.i("NelomaiStartup", "owner.open duration_ms=${SystemClock.elapsedRealtime() - started} ready=${it != 0L}")
            }
        }.getOrDefault(0L)
        RuntimeOwnerReloadGate.ownerReady(host != 0L)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_STICKY

    override fun onBind(intent: Intent?): IBinder? =
        if (intent != null && intent.component?.packageName == packageName && intent.component?.className == javaClass.name && intent.action == null) binder else null

    override fun onDestroy() {
        synchronized(updateUiLock) { updateUiAdmission = null }
        val ownerClosed = host != 0L && RuntimeNativeHost.nativeClose(host)
        host = 0
        RuntimeOwnerReloadGate.ownerStopped(ownerClosed)
        super.onDestroy()
    }

    companion object {
        const val DESCRIPTOR = RuntimeOwnerProtocol.DESCRIPTOR
        const val SELECTION = RuntimeOwnerProtocol.SELECTION
        const val ATTACH = RuntimeOwnerProtocol.ATTACH
    }
}
