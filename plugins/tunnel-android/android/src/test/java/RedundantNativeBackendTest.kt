package ru.nelomai.tunnel

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

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
        assertEquals(listOf(7), native.closedSessions)
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
    fun reusedNativeHandleBelongsToTheNewSessionAfterClose() {
        val native = FakeRedundantNativeApi().apply {
            createHandles = ArrayDeque(listOf(7, 7))
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
    fun ambiguousPrepareFailureAbortsPendingNativeState() {
        val native = FakeRedundantNativeApi()
        val backend = RedundantNativeBackend(native) { true }
        val session = requireNotNull(backend.start(41, "primary-secret".toByteArray()))
        native.prepareFailure = IllegalStateException("failure after native preparation")

        assertFalse(backend.rebind(session, 0))

        assertEquals(1, native.abortedPreparations)
    }
}

private class FakeRedundantNativeApi : RedundantNativeApi {
    var createHandles = ArrayDeque(listOf(7))
    var nextPreparedSockets = intArrayOf(101, 102)
    var sentPackets = 0
    var admissions = 0
    var abortedPreparations = 0
    var prepareFailure: Throwable? = null
    val stoppedSlots = mutableListOf<Int>()
    val closedSessions = mutableListOf<Int>()
    private val prepared = mutableMapOf<Int, List<Int>>()
    private val active = mutableMapOf<Int, List<Int>>()

    override fun create(tunFd: Int): Int = createHandles.removeFirst()

    override fun prepareSlot(handle: Int, slot: Int, configuration: ByteArray): IntArray =
        nextPreparedSockets.copyOf().also { prepared[slot] = it.toList() }

    override fun prepareRebind(handle: Int, slot: Int): IntArray {
        prepareFailure?.let { throw it }
        return nextPreparedSockets.copyOf().also { prepared[slot] = it.toList() }
    }

    override fun admitSlot(handle: Int, slot: Int): Boolean {
        admissions += 1
        active[slot] = prepared.remove(slot).orEmpty()
        sentPackets += 1
        return true
    }

    override fun abortPreparation(handle: Int, slot: Int) {
        abortedPreparations += 1
        prepared.remove(slot)
    }

    override fun switchActive(handle: Int, slot: Int): Boolean = true

    override fun stopSlot(handle: Int, slot: Int): Boolean {
        stoppedSlots += slot
        active.remove(slot)
        return true
    }

    override fun metrics(handle: Int): String? = "{}"

    override fun close(handle: Int) {
        closedSessions += handle
        active.clear()
        prepared.clear()
    }

    fun activeSocketSet(slot: Int): List<Int> = active[slot].orEmpty()
}
