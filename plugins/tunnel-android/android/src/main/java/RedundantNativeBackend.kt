package ru.nelomai.tunnel

import android.content.Context
import android.os.ParcelFileDescriptor
import org.amnezia.awg.util.SharedLibraryLoader

internal class NativeSession(val handle: Long) {
    val operationGate = Any()
    val liveProbeSlots = mutableMapOf<Long, Int>()
}

internal data class NativeDnsProbeTemplate(
    val sourceIpv4: String,
    val targetIpv4: String,
    val queryName: String,
)

internal enum class NativeProbeStatus {
    PENDING,
    SUCCEEDED,
    FAILED,
    UNKNOWN,
}

internal interface RedundantSessionBackend {
    fun start(tunFd: Int, primaryConfiguration: ByteArray): NativeSession?
    fun start(tunFd: Int, primarySlot: Int, primaryConfiguration: ByteArray): NativeSession? =
        if (primarySlot == 0) start(tunFd, primaryConfiguration) else null
    fun startSlot(session: NativeSession, slot: Int, configuration: ByteArray): Boolean
    fun rebind(session: NativeSession, slot: Int): Boolean = false
    fun switchActive(session: NativeSession, slot: Int): Boolean = false
    fun stopSlot(session: NativeSession, slot: Int): Boolean = false
    fun startProbe(
        session: NativeSession,
        slot: Int,
        template: NativeDnsProbeTemplate,
    ): Long? = null
    fun probeStatus(session: NativeSession, token: Long): NativeProbeStatus =
        NativeProbeStatus.UNKNOWN
    fun cancelProbe(session: NativeSession, token: Long): Boolean = false
    fun metrics(session: NativeSession): String? = null
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
    fun startProbe(
        handle: Long,
        slot: Int,
        sourceIpv4: String,
        targetIpv4: String,
        queryName: String,
    ): Long
    fun probeStatus(handle: Long, token: Long): Int
    fun cancelProbe(handle: Long, token: Long): Boolean
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
    override fun startProbe(
        handle: Long,
        slot: Int,
        sourceIpv4: String,
        targetIpv4: String,
        queryName: String,
    ): Long = nativeStartProbe(handle, slot, sourceIpv4, targetIpv4, queryName)
    override fun probeStatus(handle: Long, token: Long): Int = nativeProbeStatus(handle, token)
    override fun cancelProbe(handle: Long, token: Long): Boolean = nativeCancelProbe(handle, token)
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
    private external fun nativeStartProbe(
        handle: Long,
        slot: Int,
        sourceIpv4: String,
        targetIpv4: String,
        queryName: String,
    ): Long
    private external fun nativeProbeStatus(handle: Long, token: Long): Int
    private external fun nativeCancelProbe(handle: Long, token: Long): Boolean
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
        return start(tunFd, 0, primaryConfiguration)
    }

    override fun start(
        tunFd: Int,
        primarySlot: Int,
        primaryConfiguration: ByteArray,
    ): NativeSession? {
        if (primarySlot !in 0..1) {
            runCatching { closeTunFd(tunFd) }
            primaryConfiguration.fill(0)
            return null
        }
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
        if (startSlot(session, primarySlot, primaryConfiguration)) return session
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

    override fun rebind(session: NativeSession, slot: Int): Boolean = synchronized(session.operationGate) {
        if (!valid(session, slot)) return@synchronized false
        cancelSlotProbes(session, slot)
        prepareAndAdmit(session, slot) { native.prepareRebind(session.handle, slot) }
    }

    override fun switchActive(session: NativeSession, slot: Int): Boolean = synchronized(session.operationGate) {
        valid(session, slot) && runCatching {
            native.switchActive(session.handle, slot)
        }.getOrDefault(false)
    }

    override fun stopSlot(session: NativeSession, slot: Int): Boolean = synchronized(session.operationGate) {
        if (!valid(session, slot)) return@synchronized false
        cancelSlotProbes(session, slot)
        runCatching { native.stopSlot(session.handle, slot) }.getOrDefault(false)
    }

    override fun startProbe(
        session: NativeSession,
        slot: Int,
        template: NativeDnsProbeTemplate,
    ): Long? = synchronized(session.operationGate) {
        if (!valid(session, slot) || !validProbeTemplate(template)) return@synchronized null
        val token = runCatching {
            native.startProbe(
                session.handle,
                slot,
                template.sourceIpv4,
                template.targetIpv4,
                template.queryName,
            )
        }.getOrDefault(-1L)
        if (token <= 0L) return@synchronized null
        if (session.liveProbeSlots.containsKey(token)) {
            runCatching { native.cancelProbe(session.handle, token) }
            session.liveProbeSlots.remove(token)
            return@synchronized null
        }
        session.liveProbeSlots[token] = slot
        token
    }

    override fun probeStatus(session: NativeSession, token: Long): NativeProbeStatus =
        synchronized(session.operationGate) {
            if (!valid(session) || token <= 0L || token !in session.liveProbeSlots) {
                return@synchronized NativeProbeStatus.UNKNOWN
            }
            val status = runCatching { native.probeStatus(session.handle, token) }
                .getOrDefault(PROBE_UNKNOWN)
                .toNativeProbeStatus()
            if (status != NativeProbeStatus.PENDING) {
                session.liveProbeSlots.remove(token)
                if (status == NativeProbeStatus.UNKNOWN) {
                    runCatching { native.cancelProbe(session.handle, token) }
                }
            }
            status
        }

    override fun cancelProbe(session: NativeSession, token: Long): Boolean =
        synchronized(session.operationGate) {
            if (!valid(session) || token !in session.liveProbeSlots) {
                return@synchronized false
            }
            val cancelled = runCatching { native.cancelProbe(session.handle, token) }.getOrNull()
            if (cancelled != null) session.liveProbeSlots.remove(token)
            cancelled == true
        }

    override fun metrics(session: NativeSession): String? = synchronized(session.operationGate) {
        if (valid(session)) {
            runCatching { native.metrics(session.handle) }.getOrNull()
        } else {
            null
        }
    }

    override fun close(session: NativeSession) {
        val shouldClose = synchronized(gate) { activeSessions.remove(session.handle, session) }
        if (shouldClose) synchronized(session.operationGate) {
            cancelAllProbes(session)
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

    private fun cancelSlotProbes(session: NativeSession, slot: Int) {
        val tokens = session.liveProbeSlots.filterValues { it == slot }.keys.toList()
        tokens.forEach { token ->
            session.liveProbeSlots.remove(token)
            runCatching { native.cancelProbe(session.handle, token) }
        }
    }

    private fun cancelAllProbes(session: NativeSession) {
        val tokens = session.liveProbeSlots.keys.toList()
        session.liveProbeSlots.clear()
        tokens.forEach { token -> runCatching { native.cancelProbe(session.handle, token) } }
    }

    private fun validProbeTemplate(template: NativeDnsProbeTemplate): Boolean =
        canonicalIpv4Cidr32(template.sourceIpv4) &&
            canonicalIpv4(template.targetIpv4) &&
            canonicalDnsName(template.queryName)

    private fun canonicalIpv4Cidr32(value: String): Boolean =
        value.endsWith("/32") && canonicalIpv4(value.removeSuffix("/32"))

    private fun canonicalIpv4(value: String): Boolean {
        val octets = value.split('.')
        return octets.size == 4 && octets.all { octet ->
            octet.isNotEmpty() && octet.length <= 3 &&
                (octet == "0" || !octet.startsWith('0')) &&
                octet.all { it in '0'..'9' } && octet.toIntOrNull() in 0..255
        }
    }

    private fun canonicalDnsName(value: String): Boolean =
        value.length in 1..253 && value == value.lowercase() && !value.endsWith('.') &&
            value.split('.').all { label ->
                label.length in 1..63 && label.first() != '-' && label.last() != '-' &&
                    label.all { it in 'a'..'z' || it in '0'..'9' || it == '-' }
            }

    private fun valid(session: NativeSession, slot: Int? = null): Boolean =
        session.handle > 0L && (slot == null || slot in 0..1) &&
            synchronized(gate) { activeSessions[session.handle] === session }

    private fun Int.toNativeProbeStatus(): NativeProbeStatus = when (this) {
        PROBE_PENDING -> NativeProbeStatus.PENDING
        PROBE_SUCCEEDED -> NativeProbeStatus.SUCCEEDED
        PROBE_FAILED -> NativeProbeStatus.FAILED
        else -> NativeProbeStatus.UNKNOWN
    }

    private companion object {
        const val PROBE_PENDING = 0
        const val PROBE_SUCCEEDED = 1
        const val PROBE_FAILED = 2
        const val PROBE_UNKNOWN = 3
    }
}
