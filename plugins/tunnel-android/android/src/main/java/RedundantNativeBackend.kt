package ru.nelomai.tunnel

import android.content.Context
import org.amnezia.awg.util.SharedLibraryLoader

internal data class NativeSession(val handle: Int)

internal interface RedundantSessionBackend {
    fun start(tunFd: Int, primaryConfiguration: ByteArray): NativeSession?
    fun startSlot(session: NativeSession, slot: Int, configuration: ByteArray): Boolean
    fun close(session: NativeSession)
}

/** Raw Task 9 JNI boundary. Socket descriptors are pending until [admitSlot]. */
internal interface RedundantNativeApi {
    fun create(tunFd: Int): Int
    fun prepareSlot(handle: Int, slot: Int, configuration: ByteArray): IntArray
    fun prepareRebind(handle: Int, slot: Int): IntArray
    fun admitSlot(handle: Int, slot: Int): Boolean
    fun abortPreparation(handle: Int, slot: Int)
    fun switchActive(handle: Int, slot: Int): Boolean
    fun stopSlot(handle: Int, slot: Int): Boolean
    fun metrics(handle: Int): String?
    fun close(handle: Int)
}

internal class JniRedundantNativeApi(context: Context) : RedundantNativeApi {
    init {
        SharedLibraryLoader.loadSharedLibrary(context.applicationContext, "wg-go")
    }

    override fun create(tunFd: Int): Int = nativeCreate(tunFd)
    override fun prepareSlot(handle: Int, slot: Int, configuration: ByteArray): IntArray =
        nativePrepareSlot(handle, slot, configuration)
    override fun prepareRebind(handle: Int, slot: Int): IntArray =
        nativePrepareRebind(handle, slot)
    override fun admitSlot(handle: Int, slot: Int): Boolean = nativeAdmitSlot(handle, slot)
    override fun abortPreparation(handle: Int, slot: Int) =
        nativeAbortPreparation(handle, slot)
    override fun switchActive(handle: Int, slot: Int): Boolean =
        nativeSwitchActive(handle, slot)
    override fun stopSlot(handle: Int, slot: Int): Boolean = nativeStopSlot(handle, slot)
    override fun metrics(handle: Int): String? = nativeMetrics(handle)
    override fun close(handle: Int) = nativeClose(handle)

    private external fun nativeCreate(tunFd: Int): Int
    private external fun nativePrepareSlot(
        handle: Int,
        slot: Int,
        configuration: ByteArray,
    ): IntArray
    private external fun nativePrepareRebind(handle: Int, slot: Int): IntArray
    private external fun nativeAdmitSlot(handle: Int, slot: Int): Boolean
    private external fun nativeAbortPreparation(handle: Int, slot: Int)
    private external fun nativeSwitchActive(handle: Int, slot: Int): Boolean
    private external fun nativeStopSlot(handle: Int, slot: Int): Boolean
    private external fun nativeMetrics(handle: Int): String?
    private external fun nativeClose(handle: Int)
}

/**
 * Owns the synchronous Android protection barrier. Native never admits a slot
 * until every descriptor returned by the corresponding prepare call is protected.
 */
internal class RedundantNativeBackend(
    private val native: RedundantNativeApi,
    private val protectSocket: (Int) -> Boolean,
) : RedundantSessionBackend {
    private val gate = Any()
    private val activeSessions = mutableMapOf<Int, NativeSession>()

    override fun start(tunFd: Int, primaryConfiguration: ByteArray): NativeSession? {
        val handle = try {
            native.create(tunFd)
        } catch (_: Throwable) {
            primaryConfiguration.fill(0)
            return null
        }
        if (handle < 0) {
            primaryConfiguration.fill(0)
            return null
        }
        val session = NativeSession(handle)
        synchronized(gate) { activeSessions[handle] = session }
        if (startSlot(session, 0, primaryConfiguration)) return session
        runCatching { native.close(handle) }
        synchronized(gate) { activeSessions.remove(handle, session) }
        return null
    }

    override fun startSlot(
        session: NativeSession,
        slot: Int,
        configuration: ByteArray,
    ): Boolean = try {
        prepareAndAdmit(session, slot) {
            native.prepareSlot(session.handle, slot, configuration)
        }
    } finally {
        configuration.fill(0)
    }

    fun rebind(session: NativeSession, slot: Int): Boolean =
        prepareAndAdmit(session, slot) { native.prepareRebind(session.handle, slot) }

    fun switchActive(session: NativeSession, slot: Int): Boolean =
        valid(session, slot) && runCatching {
            native.switchActive(session.handle, slot)
        }.getOrDefault(false)

    fun stopSlot(session: NativeSession, slot: Int): Boolean =
        valid(session, slot) && runCatching {
            native.stopSlot(session.handle, slot)
        }.getOrDefault(false)

    fun metrics(session: NativeSession): String? = if (valid(session)) {
        runCatching { native.metrics(session.handle) }.getOrNull()
    } else {
        null
    }

    override fun close(session: NativeSession) {
        val shouldClose = synchronized(gate) { activeSessions.remove(session.handle, session) }
        if (shouldClose) runCatching { native.close(session.handle) }
    }

    private fun prepareAndAdmit(
        session: NativeSession,
        slot: Int,
        prepare: () -> IntArray,
    ): Boolean {
        if (!valid(session, slot)) return false
        val descriptors = try {
            prepare()
        } catch (_: Throwable) {
            abort(session, slot)
            return false
        }
        if (descriptors.isEmpty() || descriptors.any { it < 0 } ||
            descriptors.toSet().size != descriptors.size
        ) {
            abort(session, slot)
            return false
        }
        val protected = descriptors.all { fd ->
            runCatching { protectSocket(fd) }.getOrDefault(false)
        }
        if (!protected) {
            abort(session, slot)
            return false
        }
        val admitted = runCatching {
            native.admitSlot(session.handle, slot)
        }.getOrDefault(false)
        if (!admitted) abort(session, slot)
        return admitted
    }

    private fun abort(session: NativeSession, slot: Int) {
        runCatching { native.abortPreparation(session.handle, slot) }
    }

    private fun valid(session: NativeSession, slot: Int? = null): Boolean =
        session.handle >= 0 && (slot == null || slot in 0..1) &&
            synchronized(gate) { activeSessions[session.handle] === session }
}
