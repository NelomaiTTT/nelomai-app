package ru.nelomai.tunnel

import android.os.ParcelFileDescriptor
import java.io.File
import java.io.IOException
import java.util.IdentityHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements
import org.robolectric.annotation.RealObject
import org.robolectric.shadows.ShadowParcelFileDescriptor

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE, shadows = [RetentionDescriptor::class])
class ServiceTunRetentionTest {
    private lateinit var retention: ServiceTunRetention
    private val owner = Any()

    @Before fun reset() { retention = ServiceTunRetention(true); RetentionDescriptor.reset() }
    @After fun cleanup() {
        RetentionDescriptor.failClose = null
        RetentionDescriptor.skipClose = null
        runCatching { retention.stop(permanent = true) }
        RetentionDescriptor.files.keys.toList().forEach { runCatching { it.close() } }
        RetentionDescriptor.files.values.toSet().forEach(File::delete)
    }

    private fun tun(): ParcelFileDescriptor = RetentionDescriptor.create()
    private fun establish(owner: Any = this.owner) = requireNotNull(retention.establish(owner, ::tun))

    @Test fun healthyEnableDisableDoesNotCloseEngineOrReconnect() {
        retention = ServiceTunRetention(false)
        val engine = establish()
        assertTrue(retention.ready(owner))
        retention.setEnabled(true) { engine.dup() }
        assertEquals("armed", retention.state())
        assertTrue(engine.fileDescriptor.valid())
        retention.setEnabled(false) { fail("disable must not acquire a descriptor"); null }
        assertEquals("off", retention.state())
        assertFalse(retention.hasTun())
        assertTrue(engine.fileDescriptor.valid())
        retention.setEnabled(true) { engine.dup() }
        engine.close()
        retention.transportClosed(owner)
        assertEquals("blocked", retention.state())
    }

    @Test fun disconnectedEnableOnlyChangesPreferenceAndStopFencesLateEnable() {
        retention = ServiceTunRetention(false)
        retention.setEnabled(true) { fail("no healthy tunnel"); null }
        assertEquals("off", retention.state())
        val engine = establish()
        retention.ready(owner)
        retention.setEnabled(false) { null }
        assertThrows(IOException::class.java) {
            retention.setEnabled(true) {
                retention.stop()
                engine.dup()
            }
        }
        assertFalse(retention.hasTun())
        assertEquals("off", retention.state())
        engine.close()
    }

    @Test fun failedDisableIsUnknownAndRetryConfirmsRemoval() {
        val engine = establish()
        retention.ready(owner)
        RetentionDescriptor.failClose = RetentionDescriptor.files.keys.first { it !== engine }
        assertThrows(IOException::class.java) { retention.setEnabled(false) { null } }
        assertEquals("unknown", retention.state())
        RetentionDescriptor.failClose = null
        retention.setEnabled(false) { null }
        assertEquals("off", retention.state())
        assertTrue(engine.fileDescriptor.valid())
        engine.close()
    }

    @Test fun stopCompletionAndForcedFallbackCannotAcknowledgeOrKillANewStart() {
        establish().close(); retention.ready(owner)
        retention.stop()
        val stopped = retention.ticket()
        assertTrue(retention.stopRequested(stopped))
        assertTrue(retention.retryStop(stopped))
        retention.allowStart()
        assertFalse(retention.stopRequested(stopped))
        assertFalse(retention.retryStop(stopped))
        retention.stop()
        assertFalse(retention.stopRequested(stopped))
        assertFalse(retention.retryStop(stopped))
    }

    @Test fun enableDuringInitialStartArmsOnlyAfterReadinessAndRejectsOldOwner() {
        retention = ServiceTunRetention(false)
        val engine = establish()
        retention.registerSource(owner, retention.ticket()) { engine.dup() }
        retention.setEnabled(true)
        assertEquals("off", retention.state())
        assertFalse(retention.ready(Any()))
        assertTrue(retention.ready(owner))
        assertEquals("armed", retention.state())
        engine.close(); retention.transportClosed(owner)
        assertEquals("blocked", retention.state())
    }

    @Test fun staleSourceCannotArmProtectionForAnotherTransport() {
        retention = ServiceTunRetention(false)
        val old = establish()
        val replacement = Any()
        val next = establish(replacement)
        retention.registerSource(replacement, retention.ticket()) { next.dup() }
        retention.registerSource(owner, retention.ticket()) { fail("stale source used"); old.dup() }
        assertFalse(retention.ready(owner))
        assertTrue(retention.ready(replacement))
        retention.setEnabled(true)
        assertEquals("armed", retention.state())
        old.close(); next.close()
    }

    @Test fun disabledDoesNotDuplicateOrRetain() {
        retention = ServiceTunRetention(false)
        RetentionDescriptor.failDup = true
        establish().close()
        assertFalse(retention.hasTun())
    }

    @Test fun readyTunSurvivesNativeCloseAndAutomaticTeardown() {
        val engine = establish()
        assertTrue(retention.ready(owner))
        engine.close()
        retention.transportClosed(owner)
        assertTrue(retention.hasTun())
        retention.stop()
        assertFalse(retention.hasTun())
        assertTrue(RetentionDescriptor.files.keys.none { it.fileDescriptor.valid() })
    }

    @Test fun rejectedHandshakeCannotRearmInitialStartAndCleanupCanRetry() {
        retention.beginStart("initial")
        establish().close()
        assertTrue(retention.ready(owner))
        retention.rejectStart("initial")
        assertFalse(retention.ready(owner))
        val fd = RetentionDescriptor.files.keys.first { it.fileDescriptor.valid() }
        RetentionDescriptor.failClose = fd
        assertThrows(IOException::class.java) { retention.transportClosed(owner) }
        assertTrue(retention.hasTun())
        RetentionDescriptor.failClose = null
        retention.rejectStart("initial", transportStopped = true)
        assertFalse(retention.hasTun())
        retention.rejectStart("initial", transportStopped = true)
        assertFalse(retention.hasTun())
    }

    @Test fun replayedAttemptKeepsItsOriginalProtectionBoundary() {
        retention.beginStart("same-attempt")
        establish().close()
        retention.ready(owner)
        retention.beginStart("same-attempt")
        establish().close()
        retention.ready(owner)
        retention.rejectStart("same-attempt")
        retention.transportClosed(owner)
        assertFalse(retention.hasTun())
        assertThrows(IOException::class.java) { retention.beginStart("same-attempt") }
        retention.beginStart("new-attempt")
        establish().close()
        assertTrue(retention.ready(owner))
    }

    @Test fun rejectedRecoveryPreservesProtectionThatPredatesStart() {
        establish().close()
        retention.ready(owner)
        retention.beginStart("recovery")
        establish().close()
        retention.ready(owner)
        retention.rejectStart("recovery")
        retention.transportClosed(owner)
        assertTrue(retention.hasTun())
        retention.rejectStart("recovery", transportStopped = true)
        assertTrue(retention.hasTun())
    }

    @Test fun staleRejectedStartDoesNotDisarmReplacementOrPreventItsReadiness() {
        retention.beginStart("old")
        establish().close()
        retention.ready(owner)
        retention.stop()
        retention.allowStart()
        retention.beginStart("new")
        establish().close()
        retention.rejectStart("old", transportStopped = true)
        assertTrue(retention.ready(owner))
        retention.transportClosed(owner)
        assertTrue(retention.hasTun())
    }

    @Test fun failedInitialStartReleasesProvisionalTun() {
        establish().close()
        retention.transportClosed(owner)
        assertFalse(retention.hasTun())
        assertFalse(retention.ready(owner))
    }

    @Test fun recoveryReplacesDescriptorAndStaleCloseCannotDisarmIt() {
        establish().close()
        assertTrue(retention.ready(owner))
        val first = RetentionDescriptor.files.keys.first()
        val replacement = Any()
        establish(replacement).close()
        assertFalse(first.fileDescriptor.valid())
        retention.transportClosed(owner)
        retention.transportClosed(replacement)
        assertTrue(retention.hasTun())
        assertFalse(retention.ready(owner))
    }

    @Test fun duplicationFailureOnRecoveryKeepsNewInterfaceBlocked() {
        establish().close()
        retention.ready(owner)
        RetentionDescriptor.failDup = true
        assertThrows(IOException::class.java) { establish(Any()) }
        assertTrue(retention.hasTun())
        assertEquals(1, RetentionDescriptor.files.keys.count { it.fileDescriptor.valid() })
    }

    @Test fun duplicationFailureOnInitialStartDoesNotLeaveBlock() {
        RetentionDescriptor.failDup = true
        assertThrows(IOException::class.java) { establish() }
        assertFalse(retention.hasTun())
    }

    @Test fun stopDoesNotWaitForEstablishAndRejectsItsLateResult() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val worker = Executors.newSingleThreadExecutor()
        try {
            val pending = worker.submit<Boolean> {
                runCatching { retention.establish(owner) {
                    entered.countDown()
                    check(release.await(3, TimeUnit.SECONDS))
                    tun()
                } }.isFailure
            }
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            retention.stop()
            retention.allowStart()
            release.countDown()
            assertTrue(pending.get(2, TimeUnit.SECONDS))
            assertFalse(retention.hasTun())
            assertFalse(retention.ready(owner))
            assertTrue(RetentionDescriptor.files.keys.none { it.fileDescriptor.valid() })
        } finally { release.countDown(); worker.shutdownNow() }
    }

    @Test fun stopCloseFailureRemainsRetryableAndBlocksNewStart() {
        establish().close()
        retention.ready(owner)
        RetentionDescriptor.failClose = RetentionDescriptor.files.keys.first { it.fileDescriptor.valid() }
        assertThrows(IOException::class.java) { retention.stop() }
        assertTrue(retention.hasTun())
        assertThrows(IOException::class.java) { retention.allowStart() }
        RetentionDescriptor.failClose = null
        retention.stop()
        assertFalse(retention.hasTun())
        retention.allowStart()
        establish().close()
    }

    @Test fun returningFromCloseDoesNotProveRelease() {
        establish().close()
        RetentionDescriptor.skipClose = RetentionDescriptor.files.keys.first { it.fileDescriptor.valid() }
        assertThrows(IOException::class.java) { retention.stop() }
        assertTrue(retention.hasTun())
        RetentionDescriptor.skipClose = null
        retention.stop()
        assertFalse(retention.hasTun())
    }

    @Test fun failedRetirementKeepsBothHandlesUntilVerifiedStop() {
        establish().close()
        retention.ready(owner)
        RetentionDescriptor.failClose = RetentionDescriptor.files.keys.first { it.fileDescriptor.valid() }
        assertThrows(IOException::class.java) { establish(Any()) }
        assertEquals(2, RetentionDescriptor.files.keys.count { it.fileDescriptor.valid() })
        RetentionDescriptor.failClose = null
        assertThrows(IOException::class.java) { retention.allowStart() }
        retention.stop()
        assertFalse(retention.hasTun())
        assertTrue(RetentionDescriptor.files.keys.none { it.fileDescriptor.valid() })
    }

    @Test fun revokeOrDestroyCannotBeRearmed() {
        establish().close()
        retention.stop(permanent = true)
        assertThrows(IOException::class.java) { retention.allowStart() }
        assertThrows(IOException::class.java) { establish() }
        assertFalse(retention.ready(owner))
    }

    @Test fun lateStopCompletionCannotCloseTheNextStart() {
        establish().close()
        retention.ready(owner)
        retention.stop()
        val stopped = retention.ticket()
        retention.allowStart()
        establish().close()
        assertTrue(retention.ready(owner))
        assertFalse(retention.retryStop(stopped))
        assertTrue(retention.hasTun())
    }

    @Test fun lateStartAdmissionAndReadinessCannotCrossStop() {
        val ticket = retention.ticket()
        retention.stop()
        assertThrows(IOException::class.java) { retention.allowStart(ticket) }
        retention.allowStart()
        establish().close()
        assertFalse(retention.ready(owner, ticket))
        retention.transportClosed(owner)
        assertFalse(retention.hasTun())
    }
}

/** Independent regular-file handles replace Android dup/TUN, not kernel routing. */
@Implements(ParcelFileDescriptor::class)
class RetentionDescriptor : ShadowParcelFileDescriptor() {
    @RealObject private lateinit var descriptor: ParcelFileDescriptor
    @Implementation public override fun dup(): ParcelFileDescriptor {
        if (failDup) throw IOException("injected dup failure")
        val file = requireNotNull(files[descriptor])
        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_WRITE).also { files[it] = file }
    }
    @Implementation public override fun close() {
        if (descriptor === failClose) throw IOException("injected close failure")
        if (descriptor === skipClose) return
        super.close()
    }
    companion object {
        val files = IdentityHashMap<ParcelFileDescriptor, File>()
        var failDup = false
        var failClose: ParcelFileDescriptor? = null
        var skipClose: ParcelFileDescriptor? = null
        fun reset() { files.clear(); failDup = false; failClose = null; skipClose = null }
        fun create(): ParcelFileDescriptor {
            val file = File.createTempFile("retained-tun", ".tmp", RuntimeEnvironment.getApplication().cacheDir)
            return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_WRITE).also { files[it] = file }
        }
    }
}
