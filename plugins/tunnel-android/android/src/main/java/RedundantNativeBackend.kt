package ru.nelomai.tunnel

import android.content.Context
import android.os.ParcelFileDescriptor
import org.amnezia.awg.util.SharedLibraryLoader

internal class NativeSession(val handle: Long) {
    val operationGate = Any()
}

internal interface RedundantSessionBackend {
    fun start(tunFd: Int, primaryConfiguration: ByteArray): NativeSession?
    fun startSlot(session: NativeSession, slot: Int, configuration: ByteArray): Boolean
    fun close(session: NativeSession)
}

/** Raw Task 9 JNI boundary. Socket descriptors are pending until [admitSlot]. */
internal interface RedundantNativeApi {
    fun create(tunFd: Int): Long
    /** Encodes the opaque preparation token first, followed by one or two socket FDs. */
    fun prepareSlot(handle: Long, slot: Int, configuration: ByteArray): LongArray
    fun prepareRebind(handle: Long, slot: Int): LongArray
    fun admitSlot(handle: Long, slot: Int, preparationToken: Long): Boolean
    fun abortPreparation(handle: Long, slot: Int, preparationToken: Long)
    fun switchActive(handle: Long, slot: Int): Boolean
    fun stopSlot(handle: Long, slot: Int): Boolean
    fun metrics(handle: Long): String?
    fun close(handle: Long)
}

internal class JniRedundantNativeApi(context: Context) : RedundantNativeApi {
    init {
        SharedLibraryLoader.loadSharedLibrary(context.applicationContext, "wg-go")
    }

    override fun create(tunFd: Int): Long = nativeCreate(tunFd)
    override fun prepareSlot(
        handle: Long,
        slot: Int,
        configuration: ByteArray,
    ): LongArray = nativePrepareSlot(handle, slot, configuration)
    override fun prepareRebind(handle: Long, slot: Int): LongArray =
        nativePrepareRebind(handle, slot)
    override fun admitSlot(handle: Long, slot: Int, preparationToken: Long): Boolean =
        nativeAdmitSlot(handle, slot, preparationToken)
    override fun abortPreparation(handle: Long, slot: Int, preparationToken: Long) =
        nativeAbortPreparation(handle, slot, preparationToken)
    override fun switchActive(handle: Long, slot: Int): Boolean =
        nativeSwitchActive(handle, slot)
    override fun stopSlot(handle: Long, slot: Int): Boolean = nativeStopSlot(handle, slot)
    override fun metrics(handle: Long): String? = nativeMetrics(handle)
    override fun close(handle: Long) = nativeClose(handle)

    private external fun nativeCreate(tunFd: Int): Long
    private external fun nativePrepareSlot(
        handle: Long,
        slot: Int,
        configuration: ByteArray,
    ): LongArray
    private external fun nativePrepareRebind(handle: Long, slot: Int): LongArray
    private external fun nativeAdmitSlot(handle: Long, slot: Int, preparationToken: Long): Boolean
    private external fun nativeAbortPreparation(handle: Long, slot: Int, preparationToken: Long)
    private external fun nativeSwitchActive(handle: Long, slot: Int): Boolean
    private external fun nativeStopSlot(handle: Long, slot: Int): Boolean
    private external fun nativeMetrics(handle: Long): String?
    private external fun nativeClose(handle: Long)
}

/**
 * Owns the synchronous Android protection barrier. Native never admits a slot
 * until every descriptor returned by the corresponding prepare call is protected.
 */
internal class RedundantNativeBackend(
    private val native: RedundantNativeApi,
    private val closeTunFd: (Int) -> Unit = { fd -> ParcelFileDescriptor.adoptFd(fd).close() },
    private val protectSocket: (Int) -> Boolean,
) : RedundantSessionBackend {
    private val gate = Any()
    private val activeSessions = mutableMapOf<Long, NativeSession>()

    override fun start(tunFd: Int, primaryConfiguration: ByteArray): NativeSession? {
        val handle = try {
            native.create(tunFd)
        } catch (_: Throwable) {
            runCatching { closeTunFd(tunFd) }
            primaryConfiguration.fill(0)
            return null
        }
        if (handle <= 0L) {
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
        synchronized(session.operationGate) {
            prepareAndAdmit(session, slot) {
                native.prepareSlot(session.handle, slot, configuration)
            }
        }
    } finally {
        configuration.fill(0)
    }

    fun rebind(session: NativeSession, slot: Int): Boolean = synchronized(session.operationGate) {
        prepareAndAdmit(session, slot) { native.prepareRebind(session.handle, slot) }
    }

    fun switchActive(session: NativeSession, slot: Int): Boolean = synchronized(session.operationGate) {
        valid(session, slot) && runCatching {
            native.switchActive(session.handle, slot)
        }.getOrDefault(false)
    }

    fun stopSlot(session: NativeSession, slot: Int): Boolean = synchronized(session.operationGate) {
        valid(session, slot) && runCatching {
            native.stopSlot(session.handle, slot)
        }.getOrDefault(false)
    }

    fun metrics(session: NativeSession): String? = synchronized(session.operationGate) {
        if (valid(session)) {
            runCatching { native.metrics(session.handle) }.getOrNull()
        } else {
            null
        }
    }

    override fun close(session: NativeSession) {
        val shouldClose = synchronized(gate) { activeSessions.remove(session.handle, session) }
        if (shouldClose) synchronized(session.operationGate) {
            runCatching { native.close(session.handle) }
        }
    }

    private fun prepareAndAdmit(
        session: NativeSession,
        slot: Int,
        prepare: () -> LongArray,
    ): Boolean {
        if (!valid(session, slot)) return false
        val encoded = try {
            prepare()
        } catch (_: Throwable) {
            return false
        }
        val preparationToken = encoded.firstOrNull() ?: return false
        if (preparationToken <= 0L) return false
        if (encoded.size !in 2..3) {
            abort(session, slot, preparationToken)
            return false
        }
        for (index in 1 until encoded.size) {
            val descriptor = encoded[index]
            if (descriptor !in 0L..Int.MAX_VALUE.toLong() ||
                (index == 2 && descriptor == encoded[1]) ||
                !runCatching { protectSocket(descriptor.toInt()) }.getOrDefault(false)
            ) {
                abort(session, slot, preparationToken)
                return false
            }
        }
        val admitted = runCatching {
            native.admitSlot(session.handle, slot, preparationToken)
        }.getOrDefault(false)
        if (!admitted) abort(session, slot, preparationToken)
        return admitted
    }

    private fun abort(session: NativeSession, slot: Int, preparationToken: Long) {
        runCatching { native.abortPreparation(session.handle, slot, preparationToken) }
    }

    private fun valid(session: NativeSession, slot: Int? = null): Boolean =
        session.handle > 0L && (slot == null || slot in 0..1) &&
            synchronized(gate) { activeSessions[session.handle] === session }
}
