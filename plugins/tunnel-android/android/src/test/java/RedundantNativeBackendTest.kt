package ru.nelomai.tunnel

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

class RedundantNativeBackendTest {
    @Test
    fun deviceCannotSendBeforeEveryPreparedSocketIsProtected() {
        val native = FakeRedundantNativeApi()
        val protected = mutableListOf<Int>()
        val backend = RedundantNativeBackend(native) { fd ->
            assertEquals(0, native.sentPackets)
            protected += fd
            true
        }
        val configuration = "private_key=secret\n\n".toByteArray()

        val session = backend.start(41, configuration)

        assertNotNull(session)
        assertEquals(listOf(101, 102), protected)
        assertEquals(1, native.sentPackets)
        assertArrayEquals(ByteArray(configuration.size), configuration)
    }

    @Test
    fun protectionFailureClosesPreparedRebindAndPreservesActiveSockets() {
        val native = FakeRedundantNativeApi()
        val backend = RedundantNativeBackend(native) { fd -> fd != 202 }
        val session = requireNotNull(backend.start(41, "primary-secret".toByteArray()))
        val before = native.activeSocketSet(0)
        native.nextPreparedSockets = intArrayOf(201, 202)

        val rebound = backend.rebind(session, 0)

        assertFalse(rebound)
        assertEquals(before, native.activeSocketSet(0))
        assertEquals(1, native.abortedPreparations)
        assertEquals(1, native.admissions)
    }

    @Test
    fun failedInitialProtectionClosesWholeNativeSessionAndZerosConfiguration() {
        val native = FakeRedundantNativeApi()
        val backend = RedundantNativeBackend(native) { false }
        val configuration = "primary-secret".toByteArray()

        val session = backend.start(41, configuration)

        assertEquals(null, session)
        assertEquals(listOf(7L), native.closedSessions)
        assertArrayEquals(ByteArray(configuration.size), configuration)
    }

    @Test
    fun stoppingOneSlotKeepsLogicalSessionOpen() {
        val native = FakeRedundantNativeApi()
        val backend = RedundantNativeBackend(native) { true }
        val session = requireNotNull(backend.start(41, "primary-secret".toByteArray()))
        assertTrue(backend.startSlot(session, 1, "standby-secret".toByteArray()))

        assertTrue(backend.stopSlot(session, 1))

        assertEquals(listOf(1), native.stoppedSlots)
        assertTrue(native.closedSessions.isEmpty())
        assertTrue(backend.switchActive(session, 0))
    }

    @Test
    fun recoveredLocalActiveCanCreateTheNativeSessionDirectlyInSlotB() {
        val native = FakeRedundantNativeApi()
        val backend = RedundantNativeBackend(native) { true }

        val session = backend.start(41, 1, "recovered-active-secret".toByteArray())

        assertNotNull(session)
        assertTrue(native.activeSocketSet(0).isEmpty())
        assertEquals(listOf(101, 102), native.activeSocketSet(1))
        assertTrue(backend.switchActive(requireNotNull(session), 1))
    }

    @Test
    fun reusedNativeHandleBelongsToTheNewSessionAfterClose() {
        val native = FakeRedundantNativeApi().apply {
            createHandles = ArrayDeque(listOf(7L, 7L))
        }
        val backend = RedundantNativeBackend(native) { true }
        val first = requireNotNull(backend.start(41, "first-secret".toByteArray()))
        backend.close(first)

        val second = backend.start(42, "second-secret".toByteArray())

        assertNotNull(second)
        assertTrue(backend.switchActive(requireNotNull(second), 0))
    }

    @Test
    fun rejectedSlotStartStillZerosSensitiveConfiguration() {
        val native = FakeRedundantNativeApi()
        val backend = RedundantNativeBackend(native) { true }
        val session = requireNotNull(backend.start(41, "primary-secret".toByteArray()))
        backend.close(session)
        val configuration = "standby-secret".toByteArray()

        assertFalse(backend.startSlot(session, 1, configuration))

        assertArrayEquals(ByteArray(configuration.size), configuration)
    }

    @Test
    fun prepareExceptionCannotAbortAnUnidentifiedNativeGeneration() {
        val native = FakeRedundantNativeApi()
        val backend = RedundantNativeBackend(native) { true }
        val session = requireNotNull(backend.start(41, "primary-secret".toByteArray()))
        native.prepareFailure = IllegalStateException("failure after native preparation")

        assertFalse(backend.rebind(session, 0))

        assertEquals(0, native.abortedPreparations)
    }

    @Test
    fun concurrentRebindsAreSerializedAcrossProtectionAndAdmission() {
        val native = FakeRedundantNativeApi()
        val firstProtectEntered = CountDownLatch(1)
        val releaseFirstProtect = CountDownLatch(1)
        val protectedRebindSockets = AtomicInteger(0)
        val backend = RedundantNativeBackend(native) { fd ->
            if (fd >= 200 && protectedRebindSockets.incrementAndGet() == 1) {
                firstProtectEntered.countDown()
                releaseFirstProtect.await(1, TimeUnit.SECONDS)
            }
            true
        }
        val session = requireNotNull(backend.start(41, "primary-secret".toByteArray()))
        native.nextPreparedSockets = intArrayOf(201, 202)
        val firstResult = AtomicBoolean(false)
        val secondResult = AtomicBoolean(false)
        val secondFinished = CountDownLatch(1)

        val first = thread(start = true) { firstResult.set(backend.rebind(session, 0)) }
        assertTrue(firstProtectEntered.await(1, TimeUnit.SECONDS))
        val second = thread(start = true) {
            secondResult.set(backend.rebind(session, 0))
            secondFinished.countDown()
        }

        assertFalse(secondFinished.await(50, TimeUnit.MILLISECONDS))
        releaseFirstProtect.countDown()
        first.join(1_000)
        second.join(1_000)

        assertTrue(firstResult.get())
        assertTrue(secondResult.get())
    }

    @Test
    fun closeWaitsForAnInFlightSessionOperation() {
        val native = FakeRedundantNativeApi()
        val backend = RedundantNativeBackend(native) { true }
        val session = requireNotNull(backend.start(41, "primary-secret".toByteArray()))
        native.blockSwitch = true
        val closeFinished = CountDownLatch(1)

        val switching = thread(start = true) { backend.switchActive(session, 0) }
        assertTrue(native.switchEntered.await(1, TimeUnit.SECONDS))
        val closing = thread(start = true) {
            backend.close(session)
            closeFinished.countDown()
        }

        assertFalse(closeFinished.await(50, TimeUnit.MILLISECONDS))
        native.releaseSwitch.countDown()
        switching.join(1_000)
        closing.join(1_000)

        assertEquals(listOf(7L), native.closedSessions)
    }

    @Test
    fun nativeSessionHandleIsNotNarrowedToInt() {
        val largeHandle = Int.MAX_VALUE.toLong() + 41L
        val native = FakeRedundantNativeApi().apply {
            createHandles = ArrayDeque(listOf(largeHandle))
        }
        val backend = RedundantNativeBackend(native) { true }

        val session = requireNotNull(backend.start(41, "primary-secret".toByteArray()))
        backend.close(session)

        assertEquals(largeHandle, session.handle)
        assertEquals(listOf(largeHandle), native.closedSessions)
    }

    @Test
    fun createExceptionClosesTunFdThatNeverReachedNativeOwnership() {
        val native = FakeRedundantNativeApi().apply {
            createFailure = UnsatisfiedLinkError("missing redundant JNI ABI")
        }
        val closedTunFds = mutableListOf<Int>()
        val backend = RedundantNativeBackend(
            native = native,
            protectSocket = { true },
            closeTunFd = { fd -> closedTunFds.add(fd) },
        )
        val configuration = "primary-secret".toByteArray()

        val session = backend.start(41, configuration)

        assertEquals(null, session)
        assertEquals(listOf(41), closedTunFds)
        assertArrayEquals(ByteArray(configuration.size), configuration)
    }

    @Test
    fun probeIsSlotScopedAndTerminalStatusConsumesOpaqueToken() {
        val native = FakeRedundantNativeApi()
        val backend = RedundantNativeBackend(native) { true }
        val session = requireNotNull(backend.start(41, "primary-secret".toByteArray()))
        assertTrue(backend.startSlot(session, 1, "standby-secret".toByteArray()))
        val template = NativeDnsProbeTemplate("10.200.0.2/32", "8.8.8.8", "nelomai.ru")

        val token = requireNotNull(backend.startProbe(session, 1, template))

        assertEquals(FakeProbeStart(7L, 1, template), native.probeStarts.single())
        assertEquals(NativeProbeStatus.PENDING, backend.probeStatus(session, token))
        native.probeStatuses[token] = 1
        assertEquals(NativeProbeStatus.SUCCEEDED, backend.probeStatus(session, token))
        assertEquals(NativeProbeStatus.UNKNOWN, backend.probeStatus(session, token))
    }

    @Test
    fun malformedProbeTemplateNeverCrossesNativeBoundary() {
        val native = FakeRedundantNativeApi()
        val backend = RedundantNativeBackend(native) { true }
        val session = requireNotNull(backend.start(41, "primary-secret".toByteArray()))

        assertEquals(
            null,
            backend.startProbe(
                session,
                0,
                NativeDnsProbeTemplate("10.200.0.2/24", "2001:db8::1", "Nelomai.ru."),
            ),
        )

        assertTrue(native.probeStarts.isEmpty())
    }

    @Test
    fun rebindCancelsOnlyProbesForItsExactSlot() {
        val native = FakeRedundantNativeApi()
        val backend = RedundantNativeBackend(native) { true }
        val session = requireNotNull(backend.start(41, "primary-secret".toByteArray()))
        assertTrue(backend.startSlot(session, 1, "standby-secret".toByteArray()))
        val template = NativeDnsProbeTemplate("10.200.0.2/32", "8.8.8.8", "nelomai.ru")
        val primary = requireNotNull(backend.startProbe(session, 0, template))
        val standby = requireNotNull(backend.startProbe(session, 1, template))

        assertTrue(backend.rebind(session, 1))

        assertEquals(listOf(standby), native.cancelledProbes)
        assertEquals(NativeProbeStatus.PENDING, backend.probeStatus(session, primary))
        assertEquals(NativeProbeStatus.UNKNOWN, backend.probeStatus(session, standby))
    }

    @Test
    fun stoppingSlotCancelsItsProbeWithoutAffectingOtherSlot() {
        val native = FakeRedundantNativeApi()
        val backend = RedundantNativeBackend(native) { true }
        val session = requireNotNull(backend.start(41, "primary-secret".toByteArray()))
        assertTrue(backend.startSlot(session, 1, "standby-secret".toByteArray()))
        val template = NativeDnsProbeTemplate("10.200.0.2/32", "8.8.8.8", "nelomai.ru")
        val primary = requireNotNull(backend.startProbe(session, 0, template))
        val standby = requireNotNull(backend.startProbe(session, 1, template))

        assertTrue(backend.stopSlot(session, 1))

        assertEquals(listOf(standby), native.cancelledProbes)
        assertEquals(NativeProbeStatus.PENDING, backend.probeStatus(session, primary))
        assertEquals(NativeProbeStatus.UNKNOWN, backend.probeStatus(session, standby))
    }

    @Test
    fun duplicateLiveOpaqueTokenFailsClosed() {
        val native = FakeRedundantNativeApi().apply { fixedProbeToken = 71L }
        val backend = RedundantNativeBackend(native) { true }
        val session = requireNotNull(backend.start(41, "primary-secret".toByteArray()))
        assertTrue(backend.startSlot(session, 1, "standby-secret".toByteArray()))
        val template = NativeDnsProbeTemplate("10.200.0.2/32", "8.8.8.8", "nelomai.ru")
        assertEquals(71L, backend.startProbe(session, 0, template))

        assertEquals(null, backend.startProbe(session, 1, template))

        assertEquals(listOf(71L), native.cancelledProbes)
        assertEquals(NativeProbeStatus.UNKNOWN, backend.probeStatus(session, 71L))
    }
}

private data class FakeProbeStart(
    val handle: Long,
    val slot: Int,
    val template: NativeDnsProbeTemplate,
)

private class FakeRedundantNativeApi : RedundantNativeApi {
    var createHandles = ArrayDeque(listOf(7L))
    var nextPreparedSockets = intArrayOf(101, 102)
    var sentPackets = 0
    var admissions = 0
    var abortedPreparations = 0
    var prepareFailure: Throwable? = null
    var createFailure: Throwable? = null
    var blockSwitch = false
    val switchEntered = CountDownLatch(1)
    val releaseSwitch = CountDownLatch(1)
    val stoppedSlots = mutableListOf<Int>()
    val closedSessions = mutableListOf<Long>()
    val probeStarts = mutableListOf<FakeProbeStart>()
    val probeStatuses = mutableMapOf<Long, Int>()
    val cancelledProbes = mutableListOf<Long>()
    var fixedProbeToken: Long? = null
    private var nextProbeToken = 71L
    private var nextPreparationToken = 1L
    private val prepared = mutableMapOf<Int, LongArray>()
    private val active = mutableMapOf<Int, List<Int>>()

    override fun create(tunFd: Int): Long {
        createFailure?.let { throw it }
        return createHandles.removeFirst()
    }

    override fun prepareSlot(handle: Long, slot: Int, configuration: ByteArray): LongArray =
        preparation(slot)

    override fun prepareRebind(handle: Long, slot: Int): LongArray {
        prepareFailure?.let { throw it }
        return preparation(slot)
    }

    override fun admitSlot(handle: Long, slot: Int, preparationToken: Long): Boolean {
        val pending = prepared[slot]
        if (pending?.firstOrNull() != preparationToken) return false
        admissions += 1
        active[slot] = requireNotNull(prepared.remove(slot)).drop(1).map(Long::toInt)
        sentPackets += 1
        return true
    }

    override fun abortPreparation(handle: Long, slot: Int, preparationToken: Long) {
        abortedPreparations += 1
        if (prepared[slot]?.firstOrNull() == preparationToken) prepared.remove(slot)
    }

    override fun switchActive(handle: Long, slot: Int): Boolean {
        if (blockSwitch) {
            switchEntered.countDown()
            releaseSwitch.await(1, TimeUnit.SECONDS)
        }
        return true
    }

    override fun stopSlot(handle: Long, slot: Int): Boolean {
        stoppedSlots += slot
        active.remove(slot)
        return true
    }

    override fun startProbe(
        handle: Long,
        slot: Int,
        sourceIpv4: String,
        targetIpv4: String,
        queryName: String,
    ): Long {
        val token = fixedProbeToken ?: nextProbeToken++
        probeStarts += FakeProbeStart(
            handle,
            slot,
            NativeDnsProbeTemplate(sourceIpv4, targetIpv4, queryName),
        )
        probeStatuses.putIfAbsent(token, 0)
        return token
    }

    override fun probeStatus(handle: Long, token: Long): Int = probeStatuses[token] ?: 3

    override fun cancelProbe(handle: Long, token: Long): Boolean {
        cancelledProbes += token
        probeStatuses.remove(token)
        return true
    }

    override fun metrics(handle: Long): String? = "{}"

    override fun close(handle: Long) {
        closedSessions += handle
        active.clear()
        prepared.clear()
    }

    fun activeSocketSet(slot: Int): List<Int> = active[slot].orEmpty()

    private fun preparation(slot: Int): LongArray {
        val result = longArrayOf(
            nextPreparationToken++,
            *nextPreparedSockets.map(Int::toLong).toLongArray(),
        )
        prepared[slot] = result
        return result
    }
}
