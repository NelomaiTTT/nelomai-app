package ru.nelomai.tunnel

import java.io.ByteArrayInputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.amnezia.awg.config.Config
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class RedundantProductionAdaptersTest {
    @Test
    fun stopDuringPrepareDoesNotWaitOrAdmitLateSlot() {
        for (reserve in listOf(false, true)) {
            val entered = CountDownLatch(1)
            val release = CountDownLatch(1)
            val workers = Executors.newFixedThreadPool(2)
            var tunStarts = 0
            val backend = RecordingSessionBackend()
            val input = byteArrayOf(2)
            val preparedBytes = prepared(input)
            val native = ServiceRedundantConnectionNative(
                backend = backend,
                establishTun = { tunStarts += 1; 41 },
                prepare = { bytes ->
                    if (bytes[0] == 2.toByte()) {
                        entered.countDown()
                        check(release.await(5, TimeUnit.SECONDS))
                        preparedBytes
                    } else prepared(bytes)
                },
                probeSourceIpv4 = "10.200.0.2/32",
            )
            try {
                if (reserve) assertTrue(native.start("primary", RedundantSlot.A, byteArrayOf(1), probe()))
                val starting = workers.submit<Boolean> {
                    native.start("late", if (reserve) RedundantSlot.B else RedundantSlot.A, input, probe())
                }
                assertTrue(entered.await(2, TimeUnit.SECONDS))
                val stopping = workers.submit<Boolean> { native.closeForStop() }
                assertTrue("Stop must complete while prepare remains blocked", stopping.get(1, TimeUnit.SECONDS))
                release.countDown()
                assertFalse(starting.get(2, TimeUnit.SECONDS))
                assertEquals(if (reserve) 1 else 0, tunStarts)
                assertFalse(native.isUsable("late"))
                assertTrue(input.all { it == 0.toByte() })
                assertTrue(preparedBytes.userspace.all { it == 0.toByte() })
            } finally {
                release.countDown()
                workers.shutdown()
                assertTrue(workers.awaitTermination(3, TimeUnit.SECONDS))
                native.closeForStop()
            }
        }
    }

    @Test
    fun terminalLocalStopRejectsLateNativeStartWithoutReopeningTun() {
        var tunStarts = 0
        val native = ServiceRedundantConnectionNative(
            backend = RecordingSessionBackend(),
            establishTun = { tunStarts += 1; 41 },
            prepare = ::prepared,
            probeSourceIpv4 = "10.200.0.2/32",
        )
        assertTrue(native.start("lease-a", RedundantSlot.A, byteArrayOf(1), probe()))
        assertTrue(native.closeForStop())
        val staleConfiguration = byteArrayOf(2)
        assertFalse(native.start("lease-b", RedundantSlot.B, staleConfiguration, probe()))
        assertTrue(staleConfiguration.all { it == 0.toByte() })
        assertFalse(native.activate("lease-a"))
        assertEquals(1, tunStarts)
    }

    @Test
    fun successfulInitialRebindCannotUseReserveThatDiedWhileCommitWasPending() {
        for (primary in listOf(0, 1)) {
            withDelayedInitialCommit(primary, rebindFails = false, beforeDelayedTicks = {
                it.dnsBlockedSlots = setOf(1 - primary)
                it.receiveFrozenAtMs = 15_000L
            }) { fixture, releaseReply ->
                fixture.now = 24_000L
                releaseReply()
                for (now in 24_000L..30_000L step 1_000L) {
                    fixture.tick(now)
                    assertEquals("dead reserve activated at $now, primary=$primary", 0, fixture.ready)
                }
                assertEquals(1, fixture.failed)
                assertEquals(listOf(primary), fixture.backend.activeSlots)
                assertTrue(fixture.backend.probeLaunches.any { (started, slot) ->
                    slot == 1 - primary && started >= 24_000L
                })
            }
        }
    }

    @Test
    fun successfulInitialRebindRequiresFreshReserveProbeAfterDelayedCommit() {
        for (primary in listOf(0, 1)) {
            for (tickInterval in listOf(1_000L, 2_000L)) {
                withDelayedInitialCommit(primary, rebindFails = false) { fixture, releaseReply ->
                    fixture.now = 24_000L
                    releaseReply()
                    fixture.tick(24_000L)
                    assertEquals("commit must not replace the fresh probe", 0, fixture.ready)
                    for (now in (24_000L + tickInterval)..30_000L step tickInterval) fixture.tick(now)
                    assertEquals("primary=$primary, tick=$tickInterval", 1, fixture.ready)
                    assertEquals(0, fixture.failed)
                    assertEquals(listOf(primary, 1 - primary), fixture.backend.activeSlots)
                    assertTrue(fixture.backend.probeLaunches.any { (started, slot) ->
                        slot == 1 - primary && started >= 24_000L
                    })
                }
            }
        }
    }

    @Test
    fun lateInitialCommitCannotBypassFreshProbeAtStartupDeadline() {
        for (commitAt in 25_000L..30_000L step 1_000L) {
            withDelayedInitialCommit(0, rebindFails = false, beforeDelayedTicks = {
                it.dnsBlockedSlots = setOf(1)
                it.receiveFrozenAtMs = 15_000L
            }) { fixture, releaseReply ->
                for (now in 24_000L until commitAt step 1_000L) fixture.tick(now)
                fixture.now = commitAt
                releaseReply()
                for (now in commitAt..30_000L step 1_000L) {
                    fixture.tick(now)
                    assertEquals("dead reserve activated at $now, commit=$commitAt", 0, fixture.ready)
                }
                assertEquals(1, fixture.failed)
                assertEquals(listOf(0), fixture.backend.activeSlots)
            }
        }
    }

    @Test
    fun delayedInitialReserveCommitDoesNotSpendFreshCheckBudget() {
        for (primary in listOf(0, 1)) {
            withDelayedInitialCommit(primary) { fixture, releaseReply ->
                fixture.now = 24_000L
                releaseReply()
                fixture.tick(24_000L)
                assertEquals("commit must not replace the fresh probe", 0, fixture.ready)
                assertEquals("commit latency must not expire the reserve check", 0, fixture.failed)
                for (now in 25_000L..27_000L step 1_000L) fixture.tick(now)
                assertEquals(1, fixture.ready)
                assertEquals(0, fixture.failed)
                assertEquals(listOf(primary, 1 - primary), fixture.backend.activeSlots)
                assertTrue(fixture.backend.probeLaunches.any { (started, slot) ->
                    slot == 1 - primary && started >= 24_000L
                })
            }
        }
    }

    @Test
    fun delayedInitialReserveCommitStillRequiresSuccessfulFreshProbe() {
        withDelayedInitialCommit(0) { fixture, releaseReply ->
            fixture.now = 24_000L
            fixture.dnsBlockedSlots = setOf(1)
            releaseReply()
            for (now in 24_000L..29_000L step 1_000L) {
                fixture.tick(now)
                assertEquals(0, fixture.ready)
            }
            assertEquals(1, fixture.failed)
            assertEquals(listOf(0), fixture.backend.activeSlots)
            assertTrue(fixture.backend.probeLaunches.any { (started, slot) ->
                slot == 1 && started >= 24_000L
            })
        }
    }

    @Test
    fun delayedInitialReserveCommitCannotOutliveDeadlineOrCancellation() {
        for (cancel in listOf(false, true)) {
            withDelayedInitialCommit(0) { fixture, releaseReply ->
                fixture.cancel = cancel
                for (now in 24_000L..30_000L step 1_000L) {
                    fixture.tick(now)
                    assertEquals(0, fixture.ready)
                    assertEquals(if (!cancel && now == 30_000L) 1 else 0, fixture.failed)
                    assertEquals(if (cancel) 1 else 0, fixture.cancelled)
                }
                val stopped = fixture.coordinator.status()
                fixture.now = 31_000L
                releaseReply()
                for (now in 31_000L..33_000L step 1_000L) fixture.tick(now)
                assertEquals(stopped, fixture.coordinator.status())
                assertEquals(0, fixture.ready)
                assertEquals(listOf(0), fixture.backend.activeSlots)
            }
        }
    }

    @Test
    fun inlineInitialReserveCommitCannotUsePreCommitProbe() {
        val fixture = StartupFixture(0, ::prepared, initialStandby = false)
        fixture.healthySlots = setOf(1)
        val committedAt = fixture.awaitInitialStandbyCommit()
        assertEquals(0, fixture.ready)
        assertEquals(listOf(0), fixture.backend.activeSlots)
        fixture.tick(committedAt + 100L)
        assertEquals(0, fixture.ready)
        for (now in (committedAt + 200L)..(committedAt + 4_000L) step 100L) fixture.tick(now)
        assertEquals(1, fixture.ready)
        assertEquals(0, fixture.failed)
        assertEquals(listOf(0, 1), fixture.backend.activeSlots)
        assertTrue(fixture.backend.probeLaunches.any { (started, slot) ->
            slot == 1 && started > committedAt
        })
    }

    @Test
    fun failedInitialRebindStillWaitsForHealthyReserveWarmupAndFreshProbe() {
        for (primary in listOf(0, 1)) {
            val fixture = StartupFixture(primary, ::prepared)
            fixture.healthySlots = setOf(1 - primary)
            fixture.backend.rebindFailures += primary
            fixture.failPrimaryRebind()
            for (now in 0L..8_000L step 100L) {
                fixture.tick(now)
                assertEquals("premature failure at $now", 0, fixture.failed)
                if (now < 4_000L) assertEquals(0, fixture.ready)
            }
            assertEquals(1, fixture.ready)
            assertEquals(listOf(primary, 1 - primary), fixture.backend.activeSlots)
            assertTrue(fixture.backend.probeLaunches.count { it.second == 1 - primary } >= 4)
        }
    }

    @Test
    fun failedInitialRebindCannotExtendStartupDeadlineForBrokenReserve() {
        val fixture = StartupFixture(0, ::prepared)
        fixture.healthySlots = emptySet()
        fixture.backend.rebindFailures += 0
        for (now in 0L..31_000L step 100L) {
            fixture.tick(now)
            assertEquals(0, fixture.ready)
            assertEquals(if (now < 30_000L) 0 else 1, fixture.failed)
        }
        assertEquals(listOf(0), fixture.backend.activeSlots)
    }

    @Test
    fun failedInitialRebindCannotUseReserveWithFailedPostWarmupProbe() {
        val fixture = StartupFixture(0, ::prepared, initialStandby = false)
        fixture.healthySlots = setOf(1)
        fixture.backend.rebindFailures += 0
        fixture.failPrimaryRebind()
        val committedAt = fixture.awaitInitialStandbyCommit()
        fixture.dnsBlockedSlots = setOf(1)
        fixture.receiveFrozenAtMs = committedAt
        for (now in (committedAt + 100L)..30_000L step 100L) {
            fixture.tick(now)
            assertEquals(0, fixture.ready)
        }
        assertEquals(1, fixture.failed)
        assertEquals(listOf(0), fixture.backend.activeSlots)
        assertTrue(fixture.backend.probeLaunches.any { (started, slot) ->
            slot == 1 && started > committedAt
        })
    }

    @Test
    fun completedStartupRestoresBoundedFailoverChecks() {
        val fixture = StartupFixture(0, ::prepared)
        for (now in 0L..29_000L step 100L) fixture.tick(now)
        assertEquals(1, fixture.ready)
        fixture.backend.rebindFailures += 0
        fixture.failPrimaryRebind()
        fixture.dnsBlockedSlots = setOf(1)
        for (now in 30_000L..38_000L step 100L) fixture.tick(now)
        assertEquals(1, fixture.stalled)
        assertEquals(listOf(0), fixture.backend.activeSlots)
    }

    @Test
    fun initialHandshakeBlackholeStartsThroughProvenReserveInEitherSlot() {
        for (primary in listOf(0, 1)) {
            val fixture = StartupFixture(primary, ::prepared)
            fixture.healthySlots = setOf(1 - primary)
            for (now in 0L..20_000L step 100L) {
                fixture.tick(now)
                if (now < 4_000L) assertEquals(0, fixture.ready)
            }
            assertEquals("primary=$primary", 1, fixture.ready)
            assertEquals(0, fixture.failed)
            assertEquals(listOf(primary, 1 - primary), fixture.backend.activeSlots)
            assertEquals(0, fixture.maxPrimaryCorroboration)
        }
    }

    @Test
    fun recoveryReadinessKeepsBackgroundReserveDwell() {
        val fixture = timingFixture(active = true)
        assertTrue(fixture.native.start("lease-b", RedundantSlot.B, byteArrayOf(2), probe()))
        for (now in 0L..15_000L step 100L) {
            fixture.clock.elapsedMs = now
            fixture.backend.probeStatuses.replaceAll { _, _ -> NativeProbeStatus.SUCCEEDED }
            val reserve = fixture.native.healthObservations(initialReadiness = true,
                committedStandbyLeaseId = "lease-b", freshStart = false).single { it.index == 1 }
            if (now in 11_000L..14_900L) {
                assertEquals(3, reserve.consecutiveProbeSuccesses)
                assertEquals(BackendHealth.WARMING, reserve.health)
            }
            if (now == 15_000L) assertEquals(BackendHealth.READY, reserve.health)
        }
    }

    @Test
    fun initialColdReserveCanRecoverItsOwnUdpBinding() {
        for (primary in listOf(0, 1)) {
            for (initialStandby in listOf(false, true)) {
                val fixture = StartupFixture(primary, ::prepared, initialStandby = initialStandby)
                fixture.healthySlots = emptySet()
                for (now in 0L..25_000L step 100L) {
                    if (1 - primary in fixture.backend.reboundSlots) {
                        fixture.healthySlots = setOf(1 - primary)
                    }
                    fixture.tick(now)
                }
                assertEquals("the cold reserve must receive its own recovery attempt", 1, fixture.ready)
                assertEquals(0, fixture.failed)
                assertEquals(listOf(primary, 1 - primary), fixture.backend.activeSlots)
                assertEquals(1, fixture.backend.reboundSlots.count { it == primary })
                assertEquals(1, fixture.backend.reboundSlots.count { it == 1 - primary })
            }
        }
    }

    @Test
    fun initialReserveDoesNotAccumulatePollingDelayBetweenWarmupProbes() {
        for (primary in listOf(0, 1)) {
            val fixture = StartupFixture(primary, ::prepared, initialStandby = false)
            fixture.healthySlots = setOf(1 - primary)
            var committedAt: Long? = null
            for (now in 0L..8_000L step 1_000L) {
                fixture.tick(now)
                if (fixture.coordinator.status()?.let { it.slotALeaseId != null && it.slotBLeaseId != null } == true && committedAt == null) {
                    committedAt = now
                }
                if (now <= (committedAt ?: Long.MAX_VALUE)) assertEquals(0, fixture.ready)
            }
            assertEquals("healthy reserve must be usable within 8s at the service tick", 1, fixture.ready)
            assertEquals(0, fixture.failed)
            assertEquals(listOf(primary, 1 - primary), fixture.backend.activeSlots)
            assertTrue(fixture.backend.probeLaunches.count { it.second == 1 - primary } >= 4)
            assertTrue(fixture.backend.probeLaunches.any { (started, slot) ->
                slot == 1 - primary && started > requireNotNull(committedAt)
            })
        }
    }

    @Test
    fun failedActivationCanRenewExpiredReserveProofBeforeStartupDeadline() {
        val (fixture, resumeAt) = startupWithExpiredReserveCheck()
        val attemptsBeforeResume = fixture.backend.activeSlots.size
        val probesBeforeResume = fixture.backend.probeLaunches.count { it.second == 1 }
        fixture.tick(resumeAt)
        assertEquals("The expired result cannot authorize activation", attemptsBeforeResume, fixture.backend.activeSlots.size)
        for (now in (resumeAt + 100) until 30_000 step 100L) {
            fixture.tick(now)
            if (fixture.ready > 0) break
        }
        assertTrue(fixture.backend.probeLaunches.count { it.second == 1 } > probesBeforeResume)
        assertEquals(1, fixture.ready)
        assertEquals(0, fixture.failed)
        assertEquals("lease-b", fixture.coordinator.status()?.localActiveLeaseId)
    }

    @Test
    fun activeButUncommittedReserveCannotReuseExpiredProof() {
        val fixture = startupWithUncommittedReserve()
        fixture.dnsBlockedSlots = setOf(1)
        fixture.receiveFrozenAtMs = fixture.now
        val probesBeforeResume = fixture.backend.probeLaunches.count { it.second == 1 }
        fixture.tick(fixture.now + 8_100)
        assertEquals(probesBeforeResume + 1, fixture.backend.probeLaunches.count { it.second == 1 })
        assertEquals("The first fresh probe is pending; the old reserve verdict cannot publish readiness",
            0, fixture.ready)
        assertEquals("lease-b", fixture.coordinator.status()?.retry?.pendingNativeActiveLeaseId)

        fixture.dnsBlockedSlots = emptySet()
        fixture.receiveFrozenAtMs = null
        fixture.tick(fixture.now + 100)
        assertEquals(1, fixture.ready)
        assertEquals("lease-b", fixture.coordinator.status()?.localActiveLeaseId)
        assertEquals(null, fixture.coordinator.status()?.retry?.pendingNativeActiveLeaseId)
    }

    @Test
    fun coldHealthTickReconstructsStartupJournalBeforeRetryingActivation() {
        val old = startupWithFailedReserveActivation()
        val journal = requireNotNull(old.coordinator.status())
        val fixture = StartupFixture(0, ::prepared, replay = journal, initialElapsed = old.now,
            recoverOnCreation = false)
        assertTrue(fixture.backend.activeSlots.isEmpty())
        fixture.healthySlots = setOf(1)

        fixture.tick(old.now)
        assertEquals(listOf(0), fixture.backend.activeSlots)
        assertEquals(journal.retry.pendingNativeSwitchAttempt,
            fixture.coordinator.status()?.retry?.pendingNativeSwitchAttempt)
        assertFalse(fixture.coordinator.isRunning())

        for (time in (old.now + 100) until (old.now + 30_000) step 100L) {
            fixture.tick(time)
            if (fixture.coordinator.isRunning()) break
        }
        assertTrue(fixture.coordinator.isRunning())
        assertEquals("lease-b", fixture.coordinator.status()?.localActiveLeaseId)
    }

    @Test
    fun recoveredStartupJournalRetriesColdSocketsWithinReadinessDeadline() {
        val old = startupWithFailedReserveActivation()
        val journal = requireNotNull(old.coordinator.status())
        assertEquals("primary_ready", journal.retry.pendingNativeSwitchReason)
        for (workingSlot in listOf(0, 1)) {
            for ((failedFirstRebind, handshakeOnOldSocket) in listOf(false to false, true to false, true to true)) {
                val fixture = StartupFixture(0, ::prepared, replay = journal, initialElapsed = old.now)
                fixture.healthySlots = emptySet()
                if (failedFirstRebind) fixture.backend.rebindFailures += workingSlot
                assertEquals(listOf(0), fixture.backend.activeSlots)
                val requiredRebinds = if (failedFirstRebind) 2 else 1
                for (time in old.now until (old.now + 30_000) step 1_000L) {
                    val rebinds = fixture.backend.reboundSlots.count { it == workingSlot }
                    if (rebinds == 1) fixture.backend.rebindFailures -= workingSlot
                    if (rebinds >= requiredRebinds || (handshakeOnOldSocket && rebinds == 1)) {
                        fixture.healthySlots = setOf(workingSlot)
                    }
                    fixture.tick(time)
                    if (fixture.coordinator.isRunning()) break
                }
                assertEquals("Rebind attempts for slot $workingSlot (old handshake=$handshakeOnOldSocket)",
                    requiredRebinds, fixture.backend.reboundSlots.count { it == workingSlot })
                assertTrue("Rebind should restore slot $workingSlot (failedFirstRebind=$failedFirstRebind)",
                    fixture.coordinator.isRunning())
                assertEquals(if (workingSlot == 1) listOf(0, 1) else listOf(0), fixture.backend.activeSlots)
                assertEquals(if (workingSlot == 0) "lease-a" else "lease-b",
                    fixture.coordinator.status()?.localActiveLeaseId)
                assertEquals(null, fixture.coordinator.status()?.retry?.pendingNativeActiveLeaseId)
            }
        }
    }

    @Test
    fun periodicRebindUnblocksJournalTargetAfterNetworkRebindFailsWithoutProgress() {
        val old = startupWithFailedReserveActivation()
        val journal = requireNotNull(old.coordinator.status())
        val fixture = StartupFixture(0, ::prepared, replay = journal, initialElapsed = old.now)
        fixture.healthySlots = emptySet()
        fixture.backend.rebindFailures += 1
        assertFalse(fixture.coordinator.onUnderlyingNetworkChanged(true))
        assertEquals(listOf(0, 1), fixture.backend.reboundSlots)
        fixture.backend.rebindFailures -= 1

        for (time in old.now until (old.now + 30_000) step 1_000L) {
            if (fixture.backend.reboundSlots.count { it == 1 } == 2) fixture.healthySlots = setOf(1)
            fixture.tick(time)
            if (fixture.coordinator.isRunning()) break
        }
        assertEquals(2, fixture.backend.reboundSlots.count { it == 1 })
        assertTrue("A successful timed rebind must unblock fresh reserve proof", fixture.coordinator.isRunning())
        assertEquals(listOf(0, 1), fixture.backend.activeSlots)
        assertEquals("lease-b", fixture.coordinator.status()?.localActiveLeaseId)
        assertEquals(null, fixture.coordinator.status()?.retry?.pendingNativeActiveLeaseId)
    }

    @Test
    fun networkChangeChecksStartupDeadlineBeforeEachSocketRebind() {
        for (withProgress in listOf(false, true)) {
            for (startsBeforeDeadline in listOf(false, true)) {
                val fixture = StartupFixture(0, ::prepared)
                fixture.now = if (startsBeforeDeadline) 29_999 else 30_000
                fixture.backend.beforeRebind = { fixture.now = 30_000 }
                val progress = RedundantNetworkRebindProgress().takeIf { withProgress }
                assertFalse(fixture.coordinator.onUnderlyingNetworkChanged(true, progress) { true })
                assertEquals(if (startsBeforeDeadline) listOf(0) else emptyList(),
                    fixture.backend.reboundSlots)
                if (withProgress) {
                    assertEquals(if (startsBeforeDeadline) setOf("lease-a") else emptySet(),
                        progress?.reboundLeases)
                }
            }
        }
    }

    @Test
    fun primarySkippedByNetworkRebindDeadlineCannotReuseOldProof() {
        for (afterRebind in listOf(30_000L, 31_000L)) {
            val fixture = StartupFixture(1, ::prepared)
            fixture.healthySlots = setOf(1)
            fixture.now = 24_000
            assertTrue(fixture.coordinator.onUnderlyingNetworkChanged(true))
            fixture.tick(24_000)
            fixture.tick(25_000)
            assertTrue(fixture.lastPrimaryProbeSuccesses > 0)
            assertEquals(0, fixture.ready)

            fixture.now = 26_000
            fixture.backend.beforeRebind = { fixture.now = afterRebind }
            assertFalse(fixture.coordinator.onUnderlyingNetworkChanged(true))
            assertEquals(listOf(0, 1, 0), fixture.backend.reboundSlots)
            fixture.tick(afterRebind)
            assertEquals(0, fixture.ready)
            assertEquals(1, fixture.failed)
            assertEquals(listOf(1), fixture.backend.activeSlots)
        }
    }

    @Test
    fun networkChangeBeforeFinalizingStartupSwitchKeepsJournalPending() {
        for (replay in listOf(false, true)) {
            val old = startupWithFailedReserveActivation()
            val journal = requireNotNull(old.coordinator.status()).takeIf { replay }
            val fixture = StartupFixture(0, ::prepared, replay = journal, initialElapsed = old.now)
            fixture.healthySlots = setOf(1)
            fixture.beforeJournalRead = {
                if (fixture.backend.activeSlots.last() == 1) {
                    fixture.beforeJournalRead = {}
                    fixture.startupNetworkUpdatePending = true
                }
            }
            for (time in old.now until (old.now + 20_000) step 100L) {
                fixture.tick(time)
                if (fixture.startupNetworkUpdatePending) break
            }
            assertTrue(fixture.startupNetworkUpdatePending)
            assertEquals(listOf(0, 1), fixture.backend.activeSlots)
            assertFalse(fixture.coordinator.isRunning())
            val pending = requireNotNull(fixture.coordinator.status())
            assertEquals("lease-a", pending.localActiveLeaseId)
            assertEquals("lease-b", pending.retry.pendingNativeActiveLeaseId)
            assertEquals(null, pending.retry.acquireReplaceLeaseId)

            assertTrue(fixture.coordinator.onUnderlyingNetworkChanged(true))
            fixture.startupNetworkUpdatePending = false
            val resumedAt = fixture.now + 100
            for (time in resumedAt until (old.now + 30_000) step 100L) {
                fixture.tick(time)
                if (fixture.coordinator.isRunning()) break
            }
            assertTrue(fixture.coordinator.isRunning())
            assertEquals("lease-b", fixture.coordinator.status()?.localActiveLeaseId)
        }
    }

    @Test
    fun startupSwitchCannotAdmitFinalCommitAfterProbeOrDeadlineExpires() {
        val activationTime = startupWithFailedReserveActivation().now
        for (delayNative in listOf(false, true)) {
            val fixture = StartupFixture(0, ::prepared)
            fixture.healthySlots = setOf(1)
            for (time in 0L until activationTime step 100L) fixture.tick(time)
            if (delayNative) {
                fixture.backend.beforeSwitchActive = { slot ->
                    if (slot == 1) fixture.now = 30_001
                }
            } else {
                fixture.beforeJournalRead = {
                    if (fixture.backend.activeSlots.last() == 1) {
                        fixture.beforeJournalRead = {}
                        val proof = requireNotNull(fixture.lastStandbyObservation)
                        fixture.now = requireNotNull(proof.successfulProbeValidThroughElapsedMs) + 1
                    }
                }
            }
            fixture.tick(activationTime)
            assertEquals(listOf(0, 1), fixture.backend.activeSlots)
            assertFalse(fixture.coordinator.isRunning())
            assertEquals(if (delayNative) 1 else 0, fixture.failed)
            assertEquals("lease-a", fixture.coordinator.status()?.localActiveLeaseId)
            assertEquals("lease-b", fixture.coordinator.status()?.retry?.pendingNativeActiveLeaseId)
        }
    }

    @Test
    fun firstPrimaryProofCannotExpireDuringReadinessCommit() {
        val fixture = StartupFixture(0, ::prepared)
        fixture.tick(0)
        var reads = 0
        fixture.beforeJournalRead = {
            if (++reads == 3) {
                fixture.beforeJournalRead = {}
                fixture.now = 3_001
            }
        }
        fixture.tick(1_000)
        assertEquals(3_001L, fixture.now)
        assertFalse(fixture.coordinator.isRunning())
        assertEquals(0, fixture.failed)
        fixture.tick(4_000)
        fixture.tick(5_000)
        assertTrue(fixture.coordinator.isRunning())
    }

    @Test
    fun firstReserveActivationRequiresFreshProofAcrossJournalIo() {
        val activationTime = startupWithFailedReserveActivation().now
        for (readToDelay in listOf(2, 4, null)) {
            for (pastExpiry in listOf(false, true)) {
                val fixture = StartupFixture(0, ::prepared)
                fixture.healthySlots = setOf(1)
                for (time in 0L until activationTime step 100L) fixture.tick(time)
                val delayJournal = {
                    val standby = requireNotNull(fixture.lastStandbyObservation)
                    assertTrue(standby.hasFreshSuccessfulProbe(fixture.now))
                    fixture.now = requireNotNull(standby.successfulProbeValidThroughElapsedMs) +
                        if (pastExpiry) 1 else 0
                    assertTrue(fixture.now < 30_000)
                    assertTrue(standby.standbyCheckDeadlineElapsedMs?.let { fixture.now < it } != false)
                }
                if (readToDelay == null) {
                    fixture.beforeJournalWrite = {
                        fixture.beforeJournalWrite = {}
                        delayJournal()
                    }
                } else {
                    var journalReads = 0
                    fixture.beforeJournalRead = {
                        if (++journalReads == readToDelay) {
                            fixture.beforeJournalRead = {}
                            delayJournal()
                        }
                    }
                }
                fixture.tick(activationTime)
                assertTrue(fixture.now > activationTime)
                if (pastExpiry) {
                    assertEquals("Expired proof must prevent native activation (readToDelay=$readToDelay)",
                        listOf(0), fixture.backend.activeSlots)
                    assertEquals(0, fixture.ready)
                    val retry = requireNotNull(fixture.coordinator.status()?.retry)
                    assertEquals(if (readToDelay == null) "lease-b" else null, retry.pendingNativeActiveLeaseId)
                    assertEquals(0, retry.pendingNativeSwitchAttempt)
                    for (time in (fixture.now + 100) until 30_000 step 100L) {
                        fixture.tick(time)
                        if (fixture.ready > 0) break
                    }
                }
                assertEquals(listOf(0, 1), fixture.backend.activeSlots)
                assertEquals(1, fixture.ready)
                assertEquals(0, fixture.failed)
                assertEquals("lease-b", fixture.coordinator.status()?.localActiveLeaseId)
            }
        }
    }

    @Test
    fun firstReserveActivationChecksStartupDeadlineAfterJournalWrite() {
        for (pastDeadline in listOf(false, true)) {
            val fixture = StartupFixture(0, ::prepared)
            fixture.now = 29_900
            val afterWrite = if (pastDeadline) 30_001L else 30_000L
            fixture.beforeJournalWrite = {
                fixture.beforeJournalWrite = {}
                fixture.now = afterWrite
            }
            fixture.coordinator.onHealthObservations(listOf(
                SlotObservation(0, active = true, health = BackendHealth.UNHEALTHY, hardFailure = true),
                SlotObservation(1, active = false, health = BackendHealth.READY,
                    standbyProbeState = StandbyProbeState.SUCCEEDED,
                    successfulProbeValidThroughElapsedMs = 30_500,
                    standbyCheckDeadlineElapsedMs = 31_000),
            ))
            assertEquals(afterWrite, fixture.now)
            assertEquals(if (pastDeadline) listOf(0) else listOf(0, 1), fixture.backend.activeSlots)
            assertEquals(if (pastDeadline) 0 else 1, fixture.ready)
            assertEquals(if (pastDeadline) 1 else 0, fixture.failed)
        }
    }

    @Test
    fun pendingSwitchChecksProbeExpiryAfterJournalRead() {
        for (pastExpiry in listOf(false, true)) {
            val fixture = startupWithUncommittedReserve()
            val activationAttempts = fixture.backend.activeSlots.size
            val probeStarted = fixture.backend.probeLaunches.last { it.second == 1 }.first
            val afterRead = probeStarted + 3_000 + if (pastExpiry) 1 else 0
            val sampleTime = fixture.now + 100
            assertTrue(sampleTime < afterRead)
            assertTrue(afterRead < 30_000)

            var journalReads = 0
            fixture.beforeJournalRead = {
                if (++journalReads == 2) {
                    fixture.beforeJournalRead = {}
                    fixture.dnsBlockedSlots = setOf(1)
                    fixture.receiveFrozenAtMs = fixture.now
                    fixture.now = afterRead
                }
            }
            fixture.tick(sampleTime)
            assertEquals(afterRead, fixture.now)
            if (pastExpiry) {
                assertEquals("A delayed journal read cannot authorize startup with an expired probe",
                    0, fixture.ready)
                assertEquals(activationAttempts, fixture.backend.activeSlots.size)
                assertEquals("lease-b", fixture.coordinator.status()?.retry?.pendingNativeActiveLeaseId)
            } else {
                assertEquals(1, fixture.ready)
                assertEquals("lease-b", fixture.coordinator.status()?.localActiveLeaseId)
                assertEquals(null, fixture.coordinator.status()?.retry?.pendingNativeActiveLeaseId)
            }
        }
    }

    @Test
    fun pendingSwitchChecksStandbyWindowAfterJournalRead() {
        for (readCrossesDeadline in listOf(false, true)) {
            val fixture = startupWithFailedReserveActivation()
            while (fixture.standbyCheckStartedAt() == null && fixture.now < 12_000) {
                fixture.failNextWrite()
                fixture.tick(fixture.now + 100)
            }
            val checkStartedAt = requireNotNull(fixture.standbyCheckStartedAt())
            val checkDeadline = checkStartedAt + 8_000
            fixture.tick(checkDeadline - 1_500)
            assertEquals(checkStartedAt, fixture.standbyCheckStartedAt())
            assertEquals(0, fixture.ready)
            assertEquals("lease-b", fixture.coordinator.status()?.retry?.pendingNativeActiveLeaseId)
            fixture.clearWriteFailure()
            fixture.backend.failedActivationSlot = null
            val attempts = fixture.backend.activeSlots.size

            val afterRead = checkDeadline - if (readCrossesDeadline) 0 else 1
            var journalReads = 0
            fixture.beforeJournalRead = {
                if (++journalReads == 2) {
                    fixture.beforeJournalRead = {}
                    fixture.now = afterRead
                }
            }
            fixture.tick(checkDeadline - 1)
            assertEquals(afterRead, fixture.now)
            val standby = requireNotNull(fixture.lastStandbyObservation)
            assertEquals(StandbyProbeState.SUCCEEDED, standby.standbyProbeState)
            assertTrue(standby.hasFreshSuccessfulProbe(checkDeadline))
            if (readCrossesDeadline) {
                assertEquals("An expired check window cannot authorize activation",
                    attempts, fixture.backend.activeSlots.size)
                assertEquals(0, fixture.ready)
                assertEquals("lease-b", fixture.coordinator.status()?.retry?.pendingNativeActiveLeaseId)
            } else {
                assertEquals(attempts + 1, fixture.backend.activeSlots.size)
                assertEquals(1, fixture.ready)
                assertEquals("lease-b", fixture.coordinator.status()?.localActiveLeaseId)
            }
        }
    }

    @Test
    fun rejectedStandbyCheckCannotBecomeActiveProofWithoutAnotherProbe() {
        val fixture = startupWithFailedReserveActivation()
        while (fixture.standbyCheckStartedAt() == null && fixture.now < 12_000) {
            fixture.failNextWrite()
            fixture.tick(fixture.now + 100)
        }
        val deadline = requireNotNull(fixture.standbyCheckStartedAt()) + 8_000
        fixture.tick(deadline - 1_500)
        fixture.clearWriteFailure()
        fixture.backend.failedActivationSlot = null
        fixture.backend.beforeSwitchActive = { slot -> if (slot == 1) fixture.now = deadline }
        val attempts = fixture.backend.activeSlots.size
        fixture.tick(deadline - 1)
        assertEquals(attempts + 1, fixture.backend.activeSlots.size)
        assertTrue(requireNotNull(fixture.lastStandbyObservation).hasFreshSuccessfulProbe(deadline))
        assertFalse(fixture.coordinator.isRunning())
        assertEquals("lease-b", fixture.coordinator.status()?.retry?.pendingNativeActiveLeaseId)

        fixture.backend.beforeSwitchActive = {}
        fixture.dnsBlockedSlots = setOf(1)
        fixture.tick(deadline)
        assertFalse(fixture.coordinator.isRunning())
        assertEquals(attempts + 1, fixture.backend.activeSlots.size)
        fixture.dnsBlockedSlots = emptySet()
        for (time in (deadline + 100) until 30_000 step 100L) {
            fixture.tick(time)
            if (fixture.coordinator.isRunning()) break
        }
        assertTrue(fixture.coordinator.isRunning())
        assertEquals("lease-b", fixture.coordinator.status()?.localActiveLeaseId)
    }

    @Test
    fun failedJournalIoKeepsStandbyCheckDeadlineAfterActivation() {
        checkStandbyDeadlineAfterJournalFailure(failRead = false)
        checkStandbyDeadlineAfterJournalFailure(failRead = true)
    }

    private fun checkStandbyDeadlineAfterJournalFailure(failRead: Boolean) {
        val fixture = startupWithFailedReserveActivation()
        while (fixture.standbyCheckStartedAt() == null && fixture.now < 12_000) {
            fixture.failNextWrite()
            fixture.tick(fixture.now + 100)
        }
        val deadline = requireNotNull(fixture.standbyCheckStartedAt()) + 8_000
        fixture.tick(deadline - 1_500)
        fixture.backend.failedActivationSlot = null
        if (failRead) {
            fixture.backend.beforeSwitchActive = { slot ->
                if (slot == 1) {
                    fixture.beforeJournalRead = {
                        fixture.beforeJournalRead = {}
                        error("journal temporarily unreadable")
                    }
                }
            }
        } else {
            fixture.failNextWrite()
        }
        val attempts = fixture.backend.activeSlots.size

        fixture.tick(deadline - 1)
        assertEquals(attempts + 1, fixture.backend.activeSlots.size)
        assertTrue(requireNotNull(fixture.lastStandbyObservation).hasFreshSuccessfulProbe(deadline))
        assertFalse(fixture.coordinator.isRunning())
        assertEquals("lease-b", fixture.coordinator.status()?.retry?.pendingNativeActiveLeaseId)

        fixture.backend.beforeSwitchActive = {}
        fixture.dnsBlockedSlots = setOf(1)
        fixture.tick(deadline)
        assertFalse(fixture.coordinator.isRunning())
        assertEquals(attempts + 1, fixture.backend.activeSlots.size)
        fixture.dnsBlockedSlots = emptySet()
        for (time in (deadline + 100) until 30_000 step 100L) {
            fixture.tick(time)
            if (fixture.coordinator.isRunning()) break
        }
        assertTrue(fixture.coordinator.isRunning())
        assertEquals("lease-b", fixture.coordinator.status()?.localActiveLeaseId)
    }

    @Test
    fun rollbackFromUncommittedReserveCannotReuseExpiredPrimaryProof() {
        val fixture = startupWithUncommittedReserve()
        fixture.healthySlots = setOf(0, 1)
        fixture.dnsBlockedSlots = setOf(1)
        var elapsed = fixture.now + 100
        while (elapsed < 16_000 && fixture.lastPrimaryProbeSuccesses == 0) {
            fixture.failNextWrite()
            fixture.tick(elapsed)
            elapsed += 100
        }
        assertTrue(fixture.lastPrimaryProbeSuccesses > 0)
        assertEquals(0, fixture.ready)
        assertEquals("lease-b", fixture.coordinator.status()?.retry?.pendingNativeActiveLeaseId)
        assertEquals(1, fixture.backend.activeSlots.last())

        val metrics = requireNotNull(fixture.backend.metricsOverride)
        fixture.backend.metricsOverride = {
            metrics()?.replace("\"slot\":1,\"admitted\":true", "\"slot\":1,\"admitted\":false")
        }
        fixture.dnsBlockedSlots = setOf(0, 1)
        fixture.receiveFrozenAtMs = fixture.now
        val attemptsBeforeResume = fixture.backend.activeSlots.size
        fixture.tick(fixture.now + 8_100)
        assertEquals("The rollback cannot use a stale primary probe",
            attemptsBeforeResume, fixture.backend.activeSlots.size)
        assertEquals(0, fixture.ready)

        fixture.dnsBlockedSlots = setOf(1)
        fixture.receiveFrozenAtMs = null
        fixture.tick(fixture.now + 100)
        assertEquals(1, fixture.ready)
        assertEquals("lease-a", fixture.coordinator.status()?.localActiveLeaseId)
        assertEquals(null, fixture.coordinator.status()?.retry?.pendingNativeActiveLeaseId)
    }

    @Test
    fun activeButUncommittedReserveWithoutProofStopsAtStartupDeadline() {
        val fixture = startupWithUncommittedReserve()
        fixture.dnsBlockedSlots = setOf(1)
        fixture.receiveFrozenAtMs = fixture.now
        val attemptsBeforeResume = fixture.backend.activeSlots.size
        val resumeAt = fixture.now + 8_100
        for (now in resumeAt until 30_000 step 100L) fixture.tick(now)
        fixture.tick(29_999)
        assertEquals(0, fixture.ready)
        assertEquals(0, fixture.failed)
        assertEquals("lease-b", fixture.coordinator.status()?.retry?.pendingNativeActiveLeaseId)
        val probesBeforeDeadline = fixture.backend.probeLaunches.size
        fixture.tick(30_000)
        assertEquals(1, fixture.failed)
        assertEquals(attemptsBeforeResume, fixture.backend.activeSlots.size)
        assertEquals(probesBeforeDeadline, fixture.backend.probeLaunches.size)
    }

    private fun startupWithUncommittedReserve(): StartupFixture {
        val fixture = startupWithFailedReserveActivation()
        fixture.backend.failedActivationSlot = null
        fixture.failNextWrite()
        val beforeActivation = fixture.backend.activeSlots.size
        var elapsed = fixture.now + 100
        while (elapsed < 15_000 && fixture.backend.activeSlots.size == beforeActivation) {
            fixture.tick(elapsed)
            elapsed += 100
        }
        assertEquals(beforeActivation + 1, fixture.backend.activeSlots.size)
        assertEquals(1, fixture.backend.activeSlots.last())
        assertEquals(0, fixture.ready)
        assertEquals("lease-b", fixture.coordinator.status()?.retry?.pendingNativeActiveLeaseId)
        assertEquals("lease-a", fixture.coordinator.status()?.localActiveLeaseId)

        return fixture
    }

    @Test
    fun renewedReserveProofDoesNotExtendStartupDeadline() {
        val (fixture, resumeAt) = startupWithExpiredReserveCheck()
        fixture.dnsBlockedSlots = setOf(1)
        val attemptsBeforeResume = fixture.backend.activeSlots.size
        val probesBeforeResume = fixture.backend.probeLaunches.count { it.second == 1 }
        for (now in resumeAt until 30_000 step 100L) fixture.tick(now)
        fixture.tick(29_999)
        assertEquals(0, fixture.ready)
        assertEquals(0, fixture.failed)
        val probesBeforeDeadline = fixture.backend.probeLaunches.count { it.second == 1 }
        assertTrue(probesBeforeDeadline > probesBeforeResume)
        fixture.tick(30_000)
        assertEquals(1, fixture.failed)
        assertEquals(attemptsBeforeResume, fixture.backend.activeSlots.size)
        assertEquals(probesBeforeDeadline, fixture.backend.probeLaunches.count { it.second == 1 })
    }

    @Test
    fun pendingStartupSwitchCanConsumeSlowSuccessfulReserveProbe() {
        val fixture = startupWithFailedReserveActivation()
        fixture.backend.failedActivationSlot = null
        fixture.healthySlots = setOf(0, 1)
        fixture.dnsBlockedSlots = setOf(0)
        fixture.reserveProbeAnswerDelayMs = 1_500
        val attemptsBeforeResume = fixture.backend.activeSlots.size
        val resumeAt = fixture.now + 8_100

        for (time in resumeAt until 30_000 step 1_000L) {
            fixture.tick(time)
            if (fixture.coordinator.isRunning()) break
        }

        assertTrue(fixture.backend.probeLaunches.any { (time, slot) -> time >= resumeAt && slot == 1 })
        assertTrue("The startup tick must see a completed reserve probe", fixture.coordinator.isRunning())
        assertEquals(attemptsBeforeResume + 1, fixture.backend.activeSlots.size)
        assertEquals("lease-b", fixture.coordinator.status()?.localActiveLeaseId)
    }

    @Test
    fun startupSwitchCannotReuseExpiredProofOnSameNetwork() {
        val fixture = startupWithFailedReserveActivation()
        fixture.backend.failedActivationSlot = null
        fixture.dnsBlockedSlots = setOf(1)
        val attemptsBeforeResume = fixture.backend.activeSlots.size
        val resumeAt = fixture.now + 8_100
        fixture.tick(resumeAt)
        assertEquals(attemptsBeforeResume, fixture.backend.activeSlots.size)
        assertEquals(0, fixture.ready)
        fixture.dnsBlockedSlots = emptySet()
        for (now in (resumeAt + 100) until 30_000 step 100L) {
            fixture.tick(now)
            if (fixture.ready > 0) break
        }
        assertEquals(1, fixture.ready)
        assertEquals("lease-b", fixture.coordinator.status()?.localActiveLeaseId)
    }

    private fun startupWithFailedReserveActivation(): StartupFixture {
        val fixture = StartupFixture(0, ::prepared)
        fixture.healthySlots = setOf(1)
        fixture.backend.failedActivationSlot = 1
        var elapsed = 0L
        while (elapsed <= 10_000 && fixture.coordinator.status()?.retry?.pendingNativeActiveLeaseId == null) {
            fixture.tick(elapsed)
            elapsed += 100
        }
        assertEquals("The first activation must leave a pending switch",
            "lease-b", fixture.coordinator.status()?.retry?.pendingNativeActiveLeaseId)
        return fixture
    }

    private fun startupWithExpiredReserveCheck(): Pair<StartupFixture, Long> {
        val fixture = startupWithFailedReserveActivation()
        var elapsed = fixture.now + 100
        assertTrue(fixture.coordinator.onPhysicalNetworkUnavailable("start") { true })
        fixture.backend.rebindFailures += 0
        assertFalse(fixture.coordinator.onUnderlyingNetworkChanged(true, RedundantNetworkRebindProgress()) { true })
        val beforeRetry = fixture.backend.activeSlots.size
        while (elapsed <= 20_000 && fixture.backend.activeSlots.size == beforeRetry) {
            fixture.tick(elapsed)
            elapsed += 100
        }
        assertEquals("The rebound reserve must obtain fresh proof and attempt activation",
            beforeRetry + 1, fixture.backend.activeSlots.size)
        assertEquals(0, fixture.ready)
        assertEquals("lease-b", fixture.coordinator.status()?.retry?.pendingNativeActiveLeaseId)
        assertEquals(2, fixture.coordinator.status()?.retry?.pendingNativeSwitchAttempt)
        fixture.backend.failedActivationSlot = null
        elapsed += 8_100
        assertTrue("There must be time left in the original startup budget", elapsed < 27_000)
        return fixture to elapsed
    }

    @Test
    fun failedFreshReserveCheckStillRebindsPrimaryAndNeverPublishesReady() {
        val fixture = StartupFixture(0, ::prepared, initialStandby = false)
        fixture.healthySlots = setOf(1)
        for (now in 0L..6_000L step 1_000L) fixture.tick(now)
        assertEquals(0, fixture.ready)
        fixture.dnsBlockedSlots = setOf(1)
        fixture.receiveFrozenAtMs = 6_000L
        for (now in 7_000L..30_000L step 1_000L) {
            fixture.tick(now)
            assertEquals(0, fixture.ready)
        }
        assertEquals(1, fixture.failed)
        assertEquals(listOf(0), fixture.backend.activeSlots)
        assertEquals(3, fixture.backend.reboundSlots.count { it == 0 })
        assertEquals(0, fixture.backend.reboundSlots.count { it == 1 })
    }

    @Test
    fun freshStartChecksReserveBeforeBackgroundStabilityDwell() {
        for (primary in listOf(0, 1)) {
            val fixture = StartupFixture(primary, ::prepared, initialStandby = false)
            fixture.healthySlots = setOf(1 - primary)
            for (now in 0L..8_000L step 100L) fixture.tick(now)
            assertEquals("a proven initial reserve must not wait for background dwell", 1, fixture.ready)
            assertEquals(0, fixture.failed)
            assertEquals(listOf(primary, 1 - primary), fixture.backend.activeSlots)
            assertTrue("three warmup checks plus a fresh check after commit are required",
                fixture.backend.probeLaunches.count { it.second == 1 - primary } >= 4)
        }
    }

    @Test
    fun initialFallbackReportsConfirmedReadinessForActualActiveMember() {
        for (primary in listOf(0, 1)) {
            val fixture = StartupFixture(primary, ::prepared)
            fixture.healthySlots = setOf(1 - primary)
            for (now in 0L..20_000L step 100L) fixture.tick(now)
            assertEquals(1, fixture.ready)
            val activeLease = if (primary == 0) "lease-b" else "lease-a"
            assertTrue("initial fallback must confirm the working lease to permit async Stop",
                fixture.reportedRoles.contains("primary_ready" to activeLease))
            assertFalse(fixture.reportedRoles.contains("primary_ready" to
                if (primary == 0) "lease-a" else "lease-b"))
        }
    }

    @Test
    fun initialBlackholeDoesNotUseBrokenReserveAndStillHasBoundedFailure() {
        val fixture = StartupFixture(0, ::prepared)
        fixture.healthySlots = emptySet()
        for (now in 0L..31_000L step 100L) fixture.tick(now)
        assertEquals(0, fixture.ready)
        assertEquals(1, fixture.failed)
        assertEquals(listOf(0), fixture.backend.activeSlots)
    }

    @Test
    fun cancellationWinsBeforeInitialReserveReadiness() {
        for (rebindFails in listOf(false, true)) {
            val fixture = StartupFixture(0, ::prepared)
            fixture.healthySlots = setOf(1)
            if (rebindFails) fixture.backend.rebindFailures += 0
            for (now in 0L..20_000L step 100L) {
                if (now == 3_900L) fixture.cancel = true
                fixture.tick(now)
            }
            assertEquals(0, fixture.ready)
            assertEquals(1, fixture.cancelled)
            assertEquals(listOf(0), fixture.backend.activeSlots)
        }
    }

    @Test
    fun dnsFailureWithPrimaryHandshakeAndTrafficIsNotInitialHandshakeBlackhole() {
        val fixture = StartupFixture(0, ::prepared)
        fixture.healthySlots = setOf(0, 1)
        fixture.dnsBlockedSlots = setOf(0)
        for (now in 0L..20_000L step 100L) fixture.tick(now)
        assertEquals(0, fixture.ready)
        assertEquals(0, fixture.failed)
        assertEquals(listOf(0), fixture.backend.activeSlots)
    }

    @Test
    fun healthyPrimaryCompletesWithoutAnInitialSwitch() {
        val fixture = StartupFixture(0, ::prepared)
        fixture.healthySlots = setOf(0)
        for (now in 0L..1_000L step 100L) fixture.tick(now)
        assertEquals(1, fixture.ready)
        assertEquals(0, fixture.failed)
        assertEquals(listOf(0), fixture.backend.activeSlots)
    }

    @Test
    fun immediateStopAfterNativeReadinessReportsEitherPrimaryBeforeServerStop() {
        for (primary in listOf(0, 1)) for (fallback in listOf(false, true)) {
            var serverReady = false
            val fixture = StartupFixture(primary, ::prepared, onStop = { serverReady })
            fixture.healthySlots = setOf(if (fallback) 1 - primary else primary)
            for (now in 0L..8_000L step 100L) {
                fixture.tick(now)
                if (fixture.ready == 1) break
            }
            assertEquals(1, fixture.ready)
            assertTrue(fixture.reportedRoles.isEmpty())
            assertTrue(fixture.store.updateRedundant("start") {
                it.copy(warmStopSupported = true, asyncStopSupported = true)
            } is RecoveryStoreResult.Success)
            assertTrue(fixture.store.cancelRedundantIntentAndDeferStop("immediate-stop", "start", retainActivePeer = true)
                is RecoveryStoreResult.Success)
            // Observe the real native/store readiness result, not an already acknowledged role.
            fixture.onRole = { reason -> if (reason == "primary_ready") serverReady = true }
            assertTrue(fixture.coordinator.revoke())
            assertEquals(null, fixture.coordinator.status())
        }
    }

    @Test
    fun redundantStopUsesRetainedCredentialAfterLogoutStarts() {
        val device = "11111111-1111-4111-8111-111111111111"
        var bytes: ByteArray? = null
        val credentials = BackgroundCredentialStore(object : EncryptedRecordBackend {
            override fun read() = bytes?.clone()
            override fun write(plaintext: ByteArray): Boolean { bytes = plaintext.clone(); return true }
        })
        assertTrue(credentials.configure(0, BackgroundCredentialProvision(device,
            "https://nelomai.example", "original-token", 1_900_000_000,
            "install-secret", 1, BackgroundCapabilitySnapshot(1, true, 1_900_000_000)))
            is CredentialStoreResult.Success)
        assertTrue(credentials.beginLogoutCurrent("33333333-3333-4333-8333-333333333333")
            is CredentialStoreResult.Success)
        val stopped = AndroidRedundantTransaction(false,
            AndroidIntentTemplate(device, "account", "stray", "dynamic", "standalone", "ipv4", true),
            sessionId = "22222222-2222-4222-8222-222222222222",
            slotALeaseId = "lease-a", slotBLeaseId = null, localActiveLeaseId = "lease-a", standbyDesired = false,
            roleGeneration = 1, membershipGeneration = 1, startOperationId = "start",
            startRequestFingerprint = "f".repeat(64))
        var cleanupTransportCalls = 0
        val panel = ServiceRedundantConnectionPanel(
            credential = { error("active credential must not be requested during Logout cleanup") },
            cleanupCredential = { _ ->
                val envelope = (credentials.read() as CredentialStoreResult.Success).value
                assertEquals(null, envelope.active)
                requireNotNull(envelope.cleanupCredential).also { assertEquals(device, it.deviceId) }
            },
            stopTransport = { auth, tx, lease ->
                cleanupTransportCalls++
                assertEquals("original-token", auth.token)
                assertEquals(stopped, tx)
                org.json.JSONObject().put("connection", org.json.JSONObject()
                    .put("lease_id", lease).put("status", "released").put("session_id", org.json.JSONObject.NULL))
            })
        repeat(2) { assertEquals(RedundantStopOutcome.Completed, panel.stopOutcome(stopped)) }
        assertEquals(RedundantStopOutcome.Pending, panel.stopOutcome(stopped.copy(
            template = stopped.template.copy(deviceId = "44444444-4444-4444-8444-444444444444"))))
        assertEquals("Wrong-device Stop must not reach HTTP", 2, cleanupTransportCalls)
        try {
            panel.recover(stopped)
            org.junit.Assert.fail("Cleanup credential must not authorize recovery")
        } catch (_: IllegalStateException) { }
    }

    @Test
    fun recoveredFormerActiveCanServeTheNextFailoverWithoutUserTraffic() {
        for (primary in listOf(0, 1)) {
            val fixture = pairFixture(primary)
            var firstSwitch: Int? = null
            for (now in 30_000L..45_000L step 1_000L) {
                val decision = fixture.tick(now) { slot, _ -> slot != primary }
                assertFalse("first failure unexpectedly stalled", decision.sessionStalled)
                if (decision.switchTo != null) {
                    firstSwitch = decision.switchTo
                    assertTrue(fixture.native.activate(if (firstSwitch == 0) "lease-a" else "lease-b"))
                    break
                }
            }
            assertEquals(1 - primary, firstSwitch)
            // Native consumes DNS replies itself: a healthy standby need not
            // produce any TUN writes while the other slot carries user traffic.
            for (now in 46_000L..70_000L step 1_000L) {
                val decision = fixture.tick(now) { _, _ -> true }
                assertFalse(decision.sessionStalled)
                assertEquals(null, decision.switchTo)
            }
            var secondSwitch: Int? = null
            for (now in 71_000L..85_000L step 1_000L) {
                val decision = fixture.tick(now) { slot, _ -> slot == primary }
                assertFalse("recovered former active rejected at $now, primary=$primary", decision.sessionStalled)
                if (decision.switchTo != null) { secondSwitch = decision.switchTo; break }
            }
            assertEquals("healthy former active must receive traffic again", primary, secondSwitch)
        }
    }

    @Test
    fun dnsOnlyFailureDoesNotStopOrdinaryStandbyProbes() {
        for (primary in listOf(0, 1)) {
            val fixture = pairFixture(primary)
            for (now in 30_000L..65_000L step 1_000L) {
                fixture.backend.decryptedReceivePackets = now - 29_000L
                val decision = fixture.tick(now) { slot, _ -> slot != primary }
                assertEquals(null, decision.switchTo)
                assertFalse(decision.sessionStalled)
            }
            assertTrue("Reserve checks stopped during DNS-only failure", fixture.backend.probeLaunches
                .any { (started, slot) -> slot != primary && started >= 45_000L })
        }
    }

    @Test
    fun realLossAfterDnsOnlyFailureStillChecksAndSelectsHealthyStandby() {
        for (primary in listOf(0, 1)) {
            val fixture = pairFixture(primary)
            for (now in 30_000L..56_000L step 1_000L) {
                if (now < 50_000L) fixture.backend.decryptedReceivePackets = now - 29_000L
                val decision = fixture.tick(now) { slot, _ -> slot != primary }
                assertFalse("Unexpected restart at $now", decision.sessionStalled)
                assertEquals(if (now == 56_000L) 1 - primary else null, decision.switchTo)
            }
            assertTrue(fixture.backend.probeLaunches
                .any { (started, slot) -> slot != primary && started >= 52_000L })
        }
    }

    @Test
    fun realLossAfterDnsOnlyFailureCannotSelectNowDeadStandby() {
        for (primary in listOf(0, 1)) {
            val fixture = pairFixture(primary)
            var stalledAt: Long? = null
            for (now in 30_000L..60_000L step 1_000L) {
                if (now < 50_000L) fixture.backend.decryptedReceivePackets = now - 29_000L
                val decision = fixture.tick(now) { slot, _ -> slot != primary && now < 50_000L }
                assertEquals(null, decision.switchTo)
                if (decision.sessionStalled) {
                    stalledAt = now
                    break
                }
            }
            assertEquals(57_000L, stalledAt)
        }
    }

    @Test
    fun timelyStandbyReplySurvivesPollingJitterInBothSlotOrders() {
        for (primary in listOf(0, 1)) {
            val fixture = pairFixture(primary)
            var switchedAt: Long? = null
            for (now in 30_000L..39_000L step 1_001L) {
                val decision = fixture.tick(now) { slot, started ->
                    slot != primary && now - started >= 1_500L
                }
                assertFalse(decision.sessionStalled)
                if (decision.switchTo != null) {
                    assertEquals(1 - primary, decision.switchTo)
                    switchedAt = now
                    break
                }
            }
            assertEquals(37_007L, switchedAt)
        }
    }

    @Test
    fun repeatedlyExpiredRepliesCannotRenewTheStandbyCheckBudget() {
        val fixture = pairFixture(0)
        var stalledAt: Long? = null
        for (now in 30_000L..45_000L step 3_001L) {
            val decision = fixture.tick(now) { slot, started ->
                slot == 1 && now - started >= 1_500L
            }
            assertEquals(null, decision.switchTo)
            if (decision.sessionStalled) {
                stalledAt = now
                break
            }
        }
        assertEquals(42_004L, stalledAt)
        assertFalse(fixture.backend.probeLaunches.any { it.first == stalledAt && it.second == 1 })
    }

    @Test
    fun activeStartsEveryTwoSecondsRegardlessOfResponseCompletion() {
        val fixture = timingFixture(active = true)
        for (now in 0L..6_000L step 1_000L) fixture.observe(now, healthy = true)
        assertEquals(listOf(0L, 2_000L, 4_000L, 6_000L),
            fixture.backend.probeLaunches.map { it.first })
    }

    @Test
    fun suspectedPrimaryInterleavesFreshStandbyProbesInBothSlotOrders() {
        for (primary in listOf(0, 1)) {
            val fixture = pairFixture(primary)
            for (now in 30_000L..36_000L step 1_000L) {
                val decision = fixture.tick(now) { slot, _ -> slot != primary }
                if (now < 36_000) assertEquals(null, decision.switchTo)
                else assertEquals(1 - primary, decision.switchTo)
                assertFalse(decision.sessionStalled)
            }
            assertEquals(listOf(
                30_000L to primary, 32_000L to primary, 33_000L to (1 - primary),
                34_000L to primary, 35_000L to (1 - primary), 36_000L to primary,
            ), fixture.backend.probeLaunches.filter { it.first >= 30_000L })
        }
    }

    @Test
    fun staleReadyStandbyCannotReceiveTrafficWhenBothPathsFail() {
        val fixture = pairFixture(0)
        var decision = FailoverDecision(null, false)
        for (now in 30_000L..37_000L step 1_000L) {
            decision = fixture.tick(now) { _, _ -> false }
            assertEquals(null, decision.switchTo)
            if (now < 37_000L) assertFalse(decision.sessionStalled)
        }
        assertTrue(decision.sessionStalled)
    }

    @Test
    fun pendingLatestStandbyCheckWaitsThenSwitchesWithoutStarvation() {
        val fixture = pairFixture(0)
        for (now in 30_000L..37_000L step 1_000L) {
            val decision = fixture.tick(now) { slot, started ->
                slot == 1 && (started != 35_000L || now >= 37_000L)
            }
            assertFalse(decision.sessionStalled)
            if (now < 37_000L) assertEquals(null, decision.switchTo)
            else assertEquals(1, decision.switchTo)
        }
    }

    @Test
    fun failedLatestStandbyCheckOverridesEarlierSuccess() {
        val fixture = pairFixture(0)
        for (now in 30_000L..37_000L step 1_000L) {
            val decision = fixture.tick(now) { slot, started -> slot == 1 && started < 35_000L }
            assertEquals(null, decision.switchTo)
            assertEquals(now == 37_000L, decision.sessionStalled)
        }
    }

    @Test
    fun recoveryOfPrimaryEndsAcceleratedStandbyChecks() {
        val fixture = pairFixture(0)
        for (now in 30_000L..40_000L step 1_000L) {
            val decision = fixture.tick(now) { slot, _ -> slot == 1 || now >= 34_000L }
            assertEquals(null, decision.switchTo)
            assertFalse(decision.sessionStalled)
        }
        assertEquals(listOf(33_000L), fixture.backend.probeLaunches
            .filter { it.second == 1 && it.first >= 30_000L }.map { it.first })
    }

    @Test
    fun pausedHealthTickExpiresTheCheckInsteadOfReusingSuccessOrRestartingItsBudget() {
        val fixture = pairFixture(0)
        for (now in 30_000L..36_000L step 1_000L) {
            fixture.observe(now) { slot, _ -> slot == 1 }
        }
        val afterPause = fixture.tick(60_000) { _, _ -> false }
        assertEquals(null, afterPause.switchTo)
        assertTrue(afterPause.sessionStalled)
        assertFalse(fixture.backend.probeLaunches.any { it.first == 60_000L && it.second == 1 })
        assertFalse(fixture.tick(61_000) { slot, _ -> slot == 1 }.sessionStalled)
    }

    @Test
    fun responseToProbeSentBeforeSuspicionCannotValidateStandby() {
        val fixture = pairFixture(0, warmUntil = 27_000)
        fixture.tick(28_000) { _, _ -> false }
        fixture.tick(29_000) { _, _ -> false }
        val oldToken = fixture.backend.probeDetails.entries.single {
            it.value == (28_000L to 1)
        }.key
        val observations = fixture.observe(30_000) { slot, _ -> slot == 1 }
        assertFalse(fixture.backend.probeStatuses.containsKey(oldToken))
        assertEquals(StandbyProbeState.PENDING, observations.single { it.index == 1 }.standbyProbeState)
        assertFalse(fixture.backend.probeLaunches.any { it == (30_000L to 1) })
        fixture.tick(31_000) { _, _ -> false }
        assertTrue(fixture.backend.probeLaunches.contains(31_000L to 1))
    }

    @Test
    fun hardFailureAlsoWaitsForFreshStandbyResponse() {
        val fixture = pairFixture(0)
        fixture.backend.rebindFailures += 0
        assertFalse(fixture.native.rebind("lease-a"))
        for (now in 30_000L..32_000L step 1_000L) {
            val decision = fixture.tick(now) { slot, _ -> slot == 1 }
            assertFalse(decision.sessionStalled)
            assertEquals(if (now == 32_000L) 1 else null, decision.switchTo)
        }
    }

    @Test
    fun repeatedSendErrorsRequireFreshUsableReserveBeforeFailover() {
        for (primary in listOf(0, 1)) {
            for (reserveHealthy in listOf(false, true)) {
                val fixture = pairFixture(primary)
                fixture.backend.failedProbeSendSlots += primary
                var decision = FailoverDecision(null, false)
                for (now in 30_000L..38_000L step 1_000L) {
                    decision = fixture.tick(now) { slot, _ -> slot != primary && reserveHealthy }
                    if (decision.switchTo != null || decision.sessionStalled) break
                }
                assertEquals("primary=$primary, reserve=$reserveHealthy",
                    if (reserveHealthy) 1 - primary else null, decision.switchTo)
                assertEquals(!reserveHealthy, decision.sessionStalled)
            }
        }
    }

    @Test
    fun oldOrSingleSendErrorCannotConfirmAnOngoingFailure() {
        for (oneNewError in listOf(false, true)) {
            val fixture = timingFixture(active = true)
            fixture.backend.sendErrorsBySlot[0] = 7L
            fixture.backend.countProbeSend = false
            if (oneNewError) fixture.backend.failedProbeSendSlots += 0
            fixture.observe(0, healthy = false)
            fixture.backend.failedProbeSendSlots.clear()
            for (now in 1_000L..12_000L step 1_000L) {
                val observation = fixture.observe(now, healthy = false)
                assertFalse("old error reused at $now, oneNew=$oneNewError",
                    RedundantHealthMonitor().failed(now, observation))
            }
        }
    }

    @Test
    fun decryptedTrafficCancelsRepeatedSendErrorSuspicion() {
        for (receiveFrom in listOf(1_000L, 5_000L)) {
            val fixture = timingFixture(active = true)
            fixture.backend.failedProbeSendSlots += 0
            for (now in 0L..10_000L step 1_000L) {
                if (now >= receiveFrom) fixture.backend.decryptedReceivePackets += 1L
                val observation = fixture.observe(now, healthy = false)
                if (now >= receiveFrom) assertFalse(observation.independentFailureSignal)
                assertFalse(RedundantHealthMonitor().failed(now, observation))
            }
        }
    }

    @Test
    fun successfulProbeCancelsRepeatedSendErrorSuspicion() {
        val fixture = timingFixture(active = true)
        fixture.backend.failedProbeSendSlots += 0
        for (now in 0L..4_000L step 1_000L) fixture.observe(now, healthy = false)
        fixture.backend.failedProbeSendSlots.clear()
        for (now in 5_000L..10_000L step 1_000L) {
            val observation = fixture.observe(now, healthy = true)
            assertFalse(observation.independentFailureSignal)
            assertFalse(RedundantHealthMonitor().failed(now, observation))
        }
    }

    @Test
    fun silentActiveLossReachesFailoverWithinEightSecondsAcrossProbePhases() {
        for (failureAt in listOf(30_000L, 31_000L, 32_000L)) {
            val fixture = timingFixture(active = true)
            val monitor = RedundantHealthMonitor()
            var switchedAt: Long? = null
            for (now in 0L..(failureAt + 8_000L) step 1_000L) {
                val observation = fixture.observe(now, healthy = now < failureAt)
                val decision = monitor.evaluateHealth(now, listOf(
                    observation,
                    SlotObservation(index = 1, active = false, health = BackendHealth.READY),
                ))
                if (decision.switchTo != null) {
                    assertEquals(1, decision.switchTo)
                    assertTrue(observation.probeFailed)
                    assertTrue(observation.independentFailureSignal)
                    assertEquals(2, observation.corroboratedProbeFailures)
                    switchedAt = now
                    break
                }
            }
            assertTrue("No failover within 8s for loss at $failureAt", switchedAt != null)
            assertTrue(requireNotNull(switchedAt) >= failureAt)
        }
    }

    @Test
    fun activeProbeTimesOutAtTwoSecondsButStandbyRetainsPanelTimeout() {
        val active = timingFixture(active = true)
        val standby = timingFixture(active = false)
        active.observe(0, healthy = false)
        standby.observe(0, healthy = false)
        assertFalse(active.observe(1_999, healthy = false).probeFailed)
        assertTrue(active.observe(2_000, healthy = false).probeFailed)
        assertFalse(standby.observe(2_000, healthy = false).probeFailed)
        assertTrue(standby.observe(4_000, healthy = false).probeFailed)
    }

    @Test
    fun readyStandbyKeepsSlowCadenceUntilPromotedToActive() {
        val fixture = timingFixture(active = false)
        for (now in 0L..13_000L step 1_000L) fixture.observe(now, healthy = true)
        assertEquals(BackendHealth.READY, fixture.observe(15_000, healthy = true).health)
        fixture.observe(27_000, healthy = true)
        assertTrue(fixture.backend.probeStatuses.values.none { it == NativeProbeStatus.PENDING })
        assertTrue(fixture.native.activate("lease-a"))
        fixture.observe(27_000, healthy = false)
        assertTrue(fixture.backend.probeStatuses.values.any { it == NativeProbeStatus.PENDING })
        assertTrue(fixture.observe(29_000, healthy = false).probeFailed)
    }

    @Test
    fun oneOrTwoLostProbesRecoverWithoutFailover() {
        for (recoverAt in listOf(3_000L, 5_000L)) {
            val fixture = timingFixture(active = true)
            val monitor = RedundantHealthMonitor()
            for (now in 0L..10_000L step 1_000L) {
                val observation = fixture.observe(now, healthy = now >= recoverAt)
                assertFalse("Premature failure at $now, recovery at $recoverAt",
                    monitor.failed(now, observation))
                if (now >= recoverAt) assertFalse(observation.independentFailureSignal)
            }
        }
    }

    @Test
    fun decryptedTrafficAfterTwoLossesCancelsFastFailover() {
        val fixture = timingFixture(active = true)
        for (now in 0L..4_000L step 1_000L) fixture.observe(now, healthy = false)
        fixture.backend.decryptedReceivePackets = 1
        val recovered = fixture.observe(5_000, healthy = false)
        assertFalse(recovered.independentFailureSignal)
        assertFalse(RedundantHealthMonitor().failed(5_000, recovered))
    }

    @Test
    fun promotionCapsAlreadyPendingStandbyProbeToActiveDeadline() {
        val fixture = timingFixture(active = false)
        fixture.observe(0, healthy = false)
        fixture.observe(1_000, healthy = false)
        assertTrue(fixture.native.activate("lease-a"))
        assertTrue(fixture.observe(2_000, healthy = false).probeFailed)
    }

    @Test
    fun unsentConfirmationBreaksConsecutiveFailureSequence() {
        val fixture = timingFixture(active = true)
        fixture.observe(0, healthy = false)
        fixture.observe(2_000, healthy = false)
        fixture.backend.countProbeSend = false
        assertEquals(1, fixture.observe(4_000, healthy = false).corroboratedProbeFailures)
        fixture.backend.countProbeSend = true
        val uncorroborated = fixture.observe(6_000, healthy = false)
        assertFalse(uncorroborated.independentFailureSignal)
        assertEquals(0, uncorroborated.corroboratedProbeFailures)
        assertFalse(RedundantHealthMonitor().failed(6_000, uncorroborated))
    }

    @Test
    fun urgentSequenceUsesElapsedTimeAndDoesNotWaitForReadyCadence() {
        val clock = TestDualClock(
            epochMs = 1_800_000_000_000L,
            elapsedMs = 10_000L,
        )
        val backend = RecordingSessionBackend { clock.epochMs }
        backend.probeClock = { clock.elapsedMs }
        val native = ServiceRedundantConnectionNative(
            backend = backend,
            establishTun = { 41 },
            prepare = ::prepared,
            probeSourceIpv4 = "10.200.0.2/32",
            epochNowMs = { clock.epochMs },
            elapsedNowMs = { clock.elapsedMs },
        )
        assertTrue(native.start("lease-a", RedundantSlot.A, byteArrayOf(1), probe()))
        assertTrue(native.activate("lease-a"))

        native.healthObservations()
        repeat(3) {
            backend.probeStatuses[requireNotNull(backend.latestProbeToken)] =
                NativeProbeStatus.SUCCEEDED
            clock.elapsedMs += 1L
            native.healthObservations()
            if (it < 2) {
                clock.elapsedMs += 5_000L
                native.healthObservations()
            }
        }
        clock.elapsedMs = 25_000L
        assertEquals(BackendHealth.READY, native.healthObservations().single().health)

        // The active path has already launched the next ordinary probe at 25s.
        val ordinaryToken = requireNotNull(backend.latestProbeToken)
        backend.probeStatuses[ordinaryToken] = NativeProbeStatus.FAILED
        clock.elapsedMs += 1L
        val suspected = native.healthObservations().single()
        clock.elapsedMs = 27_000L
        native.healthObservations()
        val urgentOne = requireNotNull(backend.latestProbeToken)

        assertTrue(suspected.independentFailureSignal)
        assertEquals(25_001L, suspected.softFailureStartedAtMs)
        assertEquals(0, suspected.corroboratedProbeFailures)
        assertTrue(urgentOne != ordinaryToken)

        clock.elapsedMs += 2_000L
        native.healthObservations()
        val urgentTwo = requireNotNull(backend.latestProbeToken)
        assertTrue(urgentTwo != urgentOne)
        clock.elapsedMs += 2_000L
        val corroborated = native.healthObservations().single()

        assertEquals(2, corroborated.corroboratedProbeFailures)
        assertEquals(25_001L, corroborated.softFailureStartedAtMs)
        assertTrue(corroborated.independentFailureSignal)
    }

    @Test
    fun successfulUrgentProbeClearsRetainedFailureEvidence() {
        val clock = TestDualClock(epochMs = 1_800_000_000_000L, elapsedMs = 10_000L)
        val backend = RecordingSessionBackend { clock.epochMs }
        val native = ServiceRedundantConnectionNative(
            backend = backend,
            establishTun = { 41 },
            prepare = ::prepared,
            probeSourceIpv4 = "10.200.0.2/32",
            epochNowMs = { clock.epochMs },
            elapsedNowMs = { clock.elapsedMs },
        )
        assertTrue(native.start("lease-a", RedundantSlot.A, byteArrayOf(1), probe()))
        assertTrue(native.activate("lease-a"))

        native.healthObservations()
        val ordinaryToken = requireNotNull(backend.latestProbeToken)
        backend.probeStatuses[ordinaryToken] = NativeProbeStatus.FAILED
        clock.elapsedMs += 1L
        assertTrue(native.healthObservations().single().independentFailureSignal)
        clock.elapsedMs = 12_000L
        native.healthObservations()
        backend.probeStatuses[requireNotNull(backend.latestProbeToken)] =
            NativeProbeStatus.SUCCEEDED
        clock.elapsedMs += 1L

        val recovered = native.healthObservations().single()

        assertFalse(recovered.independentFailureSignal)
        assertEquals(null, recovered.softFailureStartedAtMs)
        assertEquals(0, recovered.corroboratedProbeFailures)
    }

    @Test
    fun receiveProgressClearsRetainedFailureEvidence() {
        val fixture = suspectedFixture()
        fixture.backend.setUdpPackets(sent = 10, received = 1)
        fixture.backend.decryptedReceivePackets = 1

        val recovered = fixture.native.healthObservations().single()

        assertFalse(recovered.probeFailed)
        assertFalse(recovered.independentFailureSignal)
        assertEquals(null, recovered.softFailureStartedAtMs)
    }

    @Test
    fun handshakeOnlyReceiveProgressDoesNotHideBrokenDataPlane() {
        val fixture = suspectedFixture()
        // The server can retransmit handshakes while every client datagram is lost.
        // No authenticated IP packet or DNS reply has returned through this slot.
        fixture.backend.setUdpPackets(sent = 10, received = 6)

        val observation = fixture.native.healthObservations().single()

        assertTrue(observation.probeFailed)
        assertTrue(observation.independentFailureSignal)
    }

    @Test
    fun rebindAndNetworkInvalidationClearRetainedFailureEvidence() {
        val rebound = suspectedFixture()
        assertTrue(rebound.native.rebind("lease-a"))
        val reboundObservation = rebound.native.healthObservations().single()
        assertFalse(reboundObservation.independentFailureSignal)
        assertEquals(null, reboundObservation.softFailureStartedAtMs)

        val invalidated = suspectedFixture()
        invalidated.native.setNetworkAvailable(false)
        val invalidatedObservation = invalidated.native.healthObservations().single()
        assertFalse(invalidatedObservation.probeFailed)
        assertFalse(invalidatedObservation.independentFailureSignal)
        assertEquals(null, invalidatedObservation.softFailureStartedAtMs)
    }

    @Test
    fun productionPanelRecoveryUsesTheServiceActiveDeviceCredential() {
        val transaction = AndroidRedundantTransaction(
            desiredActive = true,
            template = AndroidIntentTemplate(
                deviceId = "11111111-1111-4111-8111-111111111111",
                accountScope = "account",
                layer = "stray",
                ticConnectionMode = "dynamic",
                routeMode = "standalone",
                egressMode = "ipv4",
                allowAlternate = true,
            ),
            sessionId = "22222222-2222-4222-8222-222222222222",
            slotALeaseId = "lease-a",
            slotBLeaseId = null,
            localActiveLeaseId = "lease-a",
            standbyDesired = false,
            roleGeneration = 1,
            membershipGeneration = 1,
            startOperationId = "operation",
            startRequestFingerprint = "f".repeat(64),
        )
        val activeCredential = BackgroundCredential(
            transaction.template.deviceId,
            "https://nelomai.example",
            "device-token",
            1_900_000_000,
        )
        var requestedDeviceId: String? = null
        var transportCredential: BackgroundCredential? = null
        val panel = ServiceRedundantConnectionPanel(
            credential = { deviceId ->
                requestedDeviceId = deviceId
                activeCredential
            },
            recoverTransport = { credential, requested ->
                transportCredential = credential
                assertSame(transaction, requested)
                BackgroundRedundantRecoveryTransport(
                    session = BackgroundRedundantSession(
                        sessionId = transaction.sessionId,
                        state = "connected",
                        activeLeaseId = "lease-a",
                        slotALeaseId = "lease-a",
                        slotBLeaseId = null,
                        standbyDesired = false,
                        roleGeneration = 1,
                        membershipGeneration = 1,
                        reason = null,
                    ),
                    configurations = mapOf("lease-a" to byteArrayOf(1)),
                    healthProbes = emptyMap(),
                    virtualAddressV4 = "10.200.0.2/32",
                )
            },
        )

        val response = panel.recover(transaction)

        assertEquals(transaction.template.deviceId, requestedDeviceId)
        assertSame(activeCredential, transportCredential)
        assertEquals(setOf("lease-a"), response.configurations.keys)
    }

    @Test
    fun productionNativeUsesOneTunAndPreservesFixedSlots() {
        val backend = RecordingSessionBackend()
        var tunCreates = 0
        val native = ServiceRedundantConnectionNative(
            backend = backend,
            establishTun = {
                tunCreates += 1
                41
            },
            prepare = ::prepared,
            probeSourceIpv4 = "10.200.0.2/32",
        )

        assertTrue(native.start("lease-b", RedundantSlot.B, byteArrayOf(1), probe()))
        assertTrue(native.activate("lease-b"))
        assertTrue(native.start("lease-a", RedundantSlot.A, byteArrayOf(2), probe()))

        assertEquals(1, tunCreates)
        assertEquals(listOf(1), backend.primarySlots)
        assertEquals(listOf(0), backend.additionalSlots)
        assertEquals(listOf(1), backend.activeSlots)
    }

    @Test
    fun productionNativeRequiresThreeProbesFreshHandshakeAndFifteenSecondsForReady() {
        var nowMs = 1_000_000L
        val backend = RecordingSessionBackend { nowMs }
        val native = ServiceRedundantConnectionNative(
            backend = backend,
            establishTun = { 41 },
            prepare = ::prepared,
            probeSourceIpv4 = "10.200.0.2/32",
            epochNowMs = { nowMs },
            elapsedNowMs = { nowMs },
        )
        assertTrue(native.start("lease-a", RedundantSlot.A, byteArrayOf(1), probe()))
        assertTrue(native.activate("lease-a"))

        native.healthObservations()
        repeat(3) { success ->
            backend.probeStatuses[requireNotNull(backend.latestProbeToken)] =
                NativeProbeStatus.SUCCEEDED
            nowMs += 1
            val observation = native.healthObservations().single()
            if (success < 2) {
                assertEquals(BackendHealth.WARMING, observation.health)
                nowMs += 5_000
                native.healthObservations()
            }
        }
        assertEquals(3, native.healthObservations().single().consecutiveProbeSuccesses)

        nowMs = 1_015_000L
        assertEquals(BackendHealth.READY, native.healthObservations().single().health)
    }

    @Test
    fun noPhysicalNetworkSuspendsNativeProbeProgress() {
        val backend = RecordingSessionBackend()
        val native = ServiceRedundantConnectionNative(
            backend = backend,
            establishTun = { 41 },
            prepare = ::prepared,
            probeSourceIpv4 = "10.200.0.2/32",
            initialNetworkAvailable = false,
        )
        assertTrue(native.start("lease-a", RedundantSlot.A, byteArrayOf(1), probe()))

        val observation = native.healthObservations().single()

        assertEquals(0, backend.probeStatuses.size)
        assertEquals(0, observation.consecutiveProbeSuccesses)
        assertEquals(BackendHealth.WARMING, observation.health)
    }

    @Test
    fun physicalNetworkReturnResumesOwnProbesWithoutOsValidation() {
        val backend = RecordingSessionBackend()
        val native = ServiceRedundantConnectionNative(
            backend = backend,
            establishTun = { 41 },
            prepare = ::prepared,
            probeSourceIpv4 = "10.200.0.2/32",
            initialNetworkAvailable = false,
        )
        assertTrue(native.start("lease-a", RedundantSlot.A, byteArrayOf(1), probe()))
        native.healthObservations()
        assertTrue(backend.probeLaunches.isEmpty())
        native.setNetworkAvailable(true)
        native.healthObservations()
        assertEquals(1, backend.probeLaunches.size)
        native.setNetworkAvailable(false)
        native.healthObservations()
        assertEquals("offline state must not start another probe", 1, backend.probeLaunches.size)
    }

    @Test
    fun timedOutProbeKeepsItsLaunchBaselineAsIndependentFailureSignal() {
        var nowMs = 1_000_000L
        val backend = RecordingSessionBackend { nowMs }
        val native = ServiceRedundantConnectionNative(
            backend = backend,
            establishTun = { 41 },
            prepare = ::prepared,
            probeSourceIpv4 = "10.200.0.2/32",
            epochNowMs = { nowMs },
            elapsedNowMs = { nowMs },
        )
        assertTrue(native.start("lease-a", RedundantSlot.A, byteArrayOf(1), probe()))
        assertTrue(native.activate("lease-a"))

        native.healthObservations()
        nowMs += 1_000
        native.healthObservations()
        nowMs += 3_000
        val timedOut = native.healthObservations().single()

        assertTrue(timedOut.probeFailed)
        assertTrue(timedOut.independentFailureSignal)
    }

    @Test
    fun preLaunchTrafficIsOutsideTheProbeFailureWindow() {
        var nowMs = 1_000_000L
        val backend = RecordingSessionBackend { nowMs }.also {
            it.countProbeSend = false
        }
        val native = ServiceRedundantConnectionNative(
            backend = backend,
            establishTun = { 41 },
            prepare = ::prepared,
            probeSourceIpv4 = "10.200.0.2/32",
            epochNowMs = { nowMs },
            elapsedNowMs = { nowMs },
        )
        assertTrue(native.start("lease-a", RedundantSlot.A, byteArrayOf(1), probe()))
        assertTrue(native.activate("lease-a"))

        native.healthObservations()
        backend.probeStatuses[requireNotNull(backend.latestProbeToken)] =
            NativeProbeStatus.SUCCEEDED
        nowMs += 1
        native.healthObservations()
        nowMs += 5_000
        backend.setUdpPackets(sent = 5, received = 0)
        native.healthObservations()
        nowMs += 4_000
        val timedOut = native.healthObservations().single()

        assertTrue(timedOut.probeFailed)
        assertFalse(timedOut.independentFailureSignal)
    }

    @Test
    fun productionNativeUsesDispatcherTunCountersAndActiveSlotProbeTarget() {
        val backend = RecordingSessionBackend()
        val native = ServiceRedundantConnectionNative(
            backend = backend,
            establishTun = { 41 },
            prepare = { configuration ->
                preparedWithEndpoint(
                    configuration,
                    if (configuration.single() == 1.toByte()) "127.0.0.1" else "127.0.0.2",
                )
            },
            probeSourceIpv4 = "10.200.0.2/32",
        )
        assertTrue(native.start("lease-a", RedundantSlot.A, byteArrayOf(1), probe()))
        assertTrue(native.start("lease-b", RedundantSlot.B, byteArrayOf(2), probe()))
        assertTrue(native.activate("lease-b"))
        backend.metricsOverride = {
            """{"dispatcher":{"OutboundBytes":14,"InboundBytes":22,"ProbePacketsInjected":9000},"slots":[{"slot":0,"admitted":true,"closed":false,"latest_handshake_at_unix_ms":999999,"telemetry":{"tun_read_bytes":0,"tun_write_bytes":0,"udp_send_errors":0,"udp_send_packets":500,"udp_receive_packets":400}},{"slot":1,"admitted":true,"closed":false,"latest_handshake_at_unix_ms":1000000,"telemetry":{"tun_read_bytes":0,"tun_write_bytes":0,"udp_send_errors":0,"udp_send_packets":700,"udp_receive_packets":600}}]}"""
        }

        val metrics = requireNotNull(native.metrics(includeProbeTarget = true))

        assertEquals(22L, metrics.receivedBytes)
        assertEquals(14L, metrics.sentBytes)
        assertEquals(1_000_000L, metrics.latestHandshakeEpochMillis)
        assertEquals("127.0.0.2", metrics.probeTarget)
    }

    @Test
    fun productionNativeDoesNotSumPerSlotOrProbeTraffic() {
        val backend = RecordingSessionBackend()
        val native = ServiceRedundantConnectionNative(
            backend = backend,
            establishTun = { 41 },
            prepare = ::prepared,
            probeSourceIpv4 = "10.200.0.2/32",
        )
        assertTrue(native.start("lease-a", RedundantSlot.A, byteArrayOf(1), probe()))
        assertTrue(native.start("lease-b", RedundantSlot.B, byteArrayOf(2), probe()))
        backend.metricsOverride = {
            """{"dispatcher":{"OutboundBytes":17,"InboundBytes":19,"ProbePacketsInjected":1000,"ProbeRepliesConsumed":900},"slots":[{"latest_handshake_at_unix_ms":1000000,"telemetry":{"tun_read_bytes":101,"tun_write_bytes":201,"udp_send_bytes":301,"udp_receive_bytes":401}},{"latest_handshake_at_unix_ms":999999,"telemetry":{"tun_read_bytes":103,"tun_write_bytes":203,"udp_send_bytes":303,"udp_receive_bytes":403}}]}"""
        }

        val metrics = requireNotNull(native.metrics(includeProbeTarget = false))

        assertEquals(19L, metrics.receivedBytes)
        assertEquals(17L, metrics.sentBytes)
    }

    @Test
    fun productionNativeScansHandshakeWithoutSlotTelemetry() {
        val backend = RecordingSessionBackend()
        val native = ServiceRedundantConnectionNative(
            backend = backend,
            establishTun = { 41 },
            prepare = ::prepared,
            probeSourceIpv4 = "10.200.0.2/32",
        )
        assertTrue(native.start("lease-a", RedundantSlot.A, byteArrayOf(1), probe()))
        backend.metricsOverride = {
            """{"dispatcher":{"OutboundBytes":1,"InboundBytes":2},"slots":[{"latest_handshake_at_unix_ms":1234567}]}"""
        }

        val metrics = requireNotNull(native.metrics(includeProbeTarget = false))

        assertEquals(1_234_567L, metrics.latestHandshakeEpochMillis)
    }

    @Test
    fun productionNativeTreatsMissingAndNegativeDispatcherCountersAsZero() {
        val backend = RecordingSessionBackend()
        val native = ServiceRedundantConnectionNative(
            backend = backend,
            establishTun = { 41 },
            prepare = ::prepared,
            probeSourceIpv4 = "10.200.0.2/32",
        )
        assertTrue(native.start("lease-a", RedundantSlot.A, byteArrayOf(1), probe()))
        backend.metricsOverride = {
            """{"dispatcher":{},"slots":[{"latest_handshake_at_unix_ms":1000000,"telemetry":{"tun_read_bytes":7,"tun_write_bytes":11}}]}"""
        }

        val missing = requireNotNull(native.metrics(includeProbeTarget = false))

        assertEquals(0L, missing.receivedBytes)
        assertEquals(0L, missing.sentBytes)

        backend.metricsOverride = {
            """{"dispatcher":{"OutboundBytes":-7,"InboundBytes":-11},"slots":[]}"""
        }

        val negative = requireNotNull(native.metrics(includeProbeTarget = false))

        assertEquals(0L, negative.receivedBytes)
        assertEquals(0L, negative.sentBytes)
    }

    @Test
    fun confirmedRebindFailureIsAHardSlotFailure() {
        val backend = RecordingSessionBackend()
        val native = ServiceRedundantConnectionNative(
            backend = backend,
            establishTun = { 41 },
            prepare = ::prepared,
            probeSourceIpv4 = "10.200.0.2/32",
        )
        assertTrue(native.start("lease-a", RedundantSlot.A, byteArrayOf(1), probe()))
        backend.rebindFailures += 0

        assertFalse(native.rebind("lease-a"))
        assertTrue(native.healthObservations().single().hardFailure)
    }

    @Test
    fun nativeClosedSlotIsAnImmediateHardFailure() {
        val backend = RecordingSessionBackend()
        val native = ServiceRedundantConnectionNative(
            backend = backend,
            establishTun = { 41 },
            prepare = ::prepared,
            probeSourceIpv4 = "10.200.0.2/32",
        )
        assertTrue(native.start("lease-a", RedundantSlot.A, byteArrayOf(1), probe()))
        backend.metricsOverride = {
            """{"slots":[{"slot":0,"admitted":true,"closed":true,"latest_handshake_at_unix_ms":1000000,"telemetry":{"tun_read_bytes":7,"tun_write_bytes":11,"tun_write_packets":0,"udp_send_errors":0,"udp_send_packets":0,"udp_receive_packets":0}}]}"""
        }

        val observation = native.healthObservations().single()

        assertTrue(observation.hardFailure)
        assertEquals(BackendHealth.UNHEALTHY, observation.health)
    }

    @Test
    fun malformedNativeMetricsFailClosedOnlyAfterBoundedBudgetAndValidSnapshotResetsIt() {
        val backend = RecordingSessionBackend()
        val native = ServiceRedundantConnectionNative(
            backend = backend,
            establishTun = { 41 },
            prepare = ::prepared,
            probeSourceIpv4 = "10.200.0.2/32",
        )
        assertTrue(native.start("lease-a", RedundantSlot.A, byteArrayOf(1), probe()))
        backend.metricsOverride = { """{"slots":[]}""" }

        assertFalse(native.healthObservations().single().hardFailure)
        assertFalse(native.healthObservations().single().hardFailure)
        assertTrue(native.healthObservations().single().hardFailure)

        backend.metricsOverride = null
        assertFalse(native.healthObservations().single().hardFailure)
        backend.metricsOverride = { """{"slots":[{"slot":"0","admitted":"true"}]}""" }
        assertFalse(native.healthObservations().single().hardFailure)
    }

    private fun withDelayedInitialCommit(
        primary: Int,
        rebindFails: Boolean = true,
        beforeDelayedTicks: (StartupFixture) -> Unit = {},
        assertions: (StartupFixture, () -> Unit) -> Unit,
    ) {
        val network = Executors.newSingleThreadExecutor()
        val commitEntered = CountDownLatch(1)
        val releaseReply = CountDownLatch(1)
        val fixture = StartupFixture(primary, ::prepared, initialStandby = false,
            standbyExecutor = network, beforeCommitReply = {
                commitEntered.countDown()
                check(releaseReply.await(5, TimeUnit.SECONDS))
            })
        fixture.healthySlots = setOf(1 - primary)
        if (rebindFails) fixture.backend.rebindFailures += primary
        try {
            fixture.tick(0)
            network.submit {}.get(1, TimeUnit.SECONDS)
            for (now in 1_000L..15_000L step 1_000L) fixture.tick(now)
            assertTrue(commitEntered.await(1, TimeUnit.SECONDS))
            beforeDelayedTicks(fixture)
            for (now in 16_000L..23_000L step 1_000L) {
                fixture.tick(now)
                assertEquals(0, fixture.ready)
                assertEquals(0, fixture.failed)
            }
            assertions(fixture) {
                releaseReply.countDown()
                network.submit {}.get(1, TimeUnit.SECONDS)
            }
        } finally {
            releaseReply.countDown()
            network.shutdown()
            assertTrue(network.awaitTermination(5, TimeUnit.SECONDS))
        }
    }

    // Real coordinator + native adapter; only JNI/transport, clock and encrypted
    // bytes storage are replaced. No fabricated SlotObservation confirmations.
    private class StartupFixture(
        private val primary: Int,
        prepare: (ByteArray) -> PreparedRedundantConfiguration,
        initialStandby: Boolean = true,
        standbyExecutor: Executor = Executor { it.run() },
        beforeCommitReply: () -> Unit = {},
        onStop: (AndroidRedundantTransaction) -> Boolean = { true },
        private val replay: AndroidRedundantTransaction? = null,
        initialElapsed: Long = 0L,
        recoverOnCreation: Boolean = true,
    ) {
        @Volatile var now = initialElapsed
        var healthySlots = setOf(0, 1)
        var dnsBlockedSlots = emptySet<Int>()
        var receiveFrozenAtMs: Long? = null
        var reserveProbeAnswerDelayMs = 0L
        var startupNetworkUpdatePending = false
        var cancel = false
        var ready = 0
        var failed = 0
        var cancelled = 0
        var stalled = 0
        var maxPrimaryCorroboration = 0
        var lastPrimaryProbeSuccesses = 0
        var lastStandbyObservation: SlotObservation? = null
        var beforeJournalRead: () -> Unit = {}
        var beforeJournalWrite: () -> Unit = {}
        val reportedRoles = mutableListOf<Pair<String, String?>>()
        var onRole: (String) -> Unit = {}
        val backend = RecordingSessionBackend { 1_800_000_000_000L }
        private val healthProbe = BackgroundRedundantHealthProbe("dns_a", "77.88.8.8", "nelomai.ru", 4000)
        private val adapter = ServiceRedundantConnectionNative(backend, { 41 }, prepare,
            probeSourceIpv4 = "10.241.0.1/32",
            epochNowMs = { 1_800_000_000_000L }, elapsedNowMs = { now })
        private val native = object : RedundantConnectionNative by adapter {
            override fun healthObservations(
                initialReadiness: Boolean,
                committedStandbyLeaseId: String?,
                freshStart: Boolean,
                startupStandbyRetryDeadlineMs: Long?,
            ): List<SlotObservation> =
                adapter.healthObservations(
                    initialReadiness, committedStandbyLeaseId, freshStart, startupStandbyRetryDeadlineMs,
                ).also { observations ->
                    lastStandbyObservation = observations.firstOrNull { it.index != primary }
                    observations.firstOrNull { it.index == primary }?.let {
                        maxPrimaryCorroboration = maxOf(maxPrimaryCorroboration, it.corroboratedProbeFailures)
                        lastPrimaryProbeSuccesses = it.consecutiveProbeSuccesses
                    }
                }
        }
        private val record = object : EncryptedRecordBackend {
            var bytes = AndroidRecoveryEnvelopeCodec.encode(AndroidRecoveryEnvelope.empty(1))
            var failNext = false
            override fun read(): ByteArray {
                beforeJournalRead()
                return bytes.clone()
            }
            override fun write(plaintext: ByteArray): Boolean {
                beforeJournalWrite()
                if (failNext) {
                    failNext = false
                    return false
                }
                bytes = plaintext.clone()
                return true
            }
        }
        val store = AndroidRecoveryStore(record, object : BootIdentityProvider {
            override fun bootCount(): Long = 1
        })
        private val transaction = AndroidRedundantTransaction(
            desiredActive = true,
            template = AndroidIntentTemplate("11111111-1111-4111-8111-111111111111",
                "account", "stray", "dynamic", "standalone", "ipv4", true),
            sessionId = "22222222-2222-4222-8222-222222222222",
            slotALeaseId = "lease-a".takeIf { primary == 0 || initialStandby },
            slotBLeaseId = "lease-b".takeIf { primary == 1 || initialStandby },
            localActiveLeaseId = if (primary == 0) "lease-a" else "lease-b",
            standbyDesired = true, roleGeneration = 1, membershipGeneration = 1,
            startOperationId = "start", startRequestFingerprint = "f".repeat(64),
        )
        private val panel = object : RedundantConnectionPanel {
            override fun recover(transaction: AndroidRedundantTransaction): RedundantRecoveryResponse {
                check(replay != null)
                return RedundantRecoveryResponse(
                    BackgroundRedundantSession(transaction.sessionId, "connected",
                        transaction.localActiveLeaseId, transaction.slotALeaseId, transaction.slotBLeaseId,
                        true, transaction.roleGeneration, transaction.membershipGeneration, null),
                    mapOf("lease-a" to byteArrayOf(1), "lease-b" to byteArrayOf(2)),
                    mapOf("lease-a" to healthProbe, "lease-b" to healthProbe),
                )
            }
            override fun reportRole(transaction: AndroidRedundantTransaction, reason: String): RedundantRoleResponse {
                reportedRoles += reason to transaction.localActiveLeaseId
                onRole(reason)
                return RedundantRoleResponse("accepted", requireNotNull(transaction.localActiveLeaseId),
                    BackgroundRedundantSession(transaction.sessionId, "connected",
                        transaction.localActiveLeaseId, transaction.slotALeaseId,
                        transaction.slotBLeaseId, true, transaction.roleGeneration,
                        transaction.membershipGeneration, null))
            }
            override fun acquireStandby(transaction: AndroidRedundantTransaction,
                operationId: String, replaceLeaseId: String?): BackgroundRedundantCandidate {
                check(replaceLeaseId == null)
                return BackgroundRedundantCandidate(
                    reportRole(transaction, "acquire").session,
                    if (primary == 0) "lease-b" else "lease-a",
                    if (primary == 0) RedundantSlot.B else RedundantSlot.A,
                    QuickConnectionArgs(), byteArrayOf(2),
                    BackgroundRedundantHealthProbe("dns_a", "77.88.8.8", "nelomai.ru", 4000),
                )
            }
            override fun commitCandidate(transaction: AndroidRedundantTransaction,
                candidateLeaseId: String): BackgroundRedundantSession {
                check(candidateLeaseId == if (primary == 0) "lease-b" else "lease-a")
                val committed = reportRole(transaction, "commit").session.copy(
                    slotALeaseId = "lease-a", slotBLeaseId = "lease-b",
                    membershipGeneration = transaction.membershipGeneration + 1,
                )
                beforeCommitReply()
                return committed
            }
            override fun stop(transaction: AndroidRedundantTransaction): Boolean = onStop(transaction)
        }
        val coordinator = RedundantConnectionCoordinator(store, panel, native,
            epochNowMs = { now }, monotonicMs = { now }, onAllSlotsStalled = { stalled++ },
            standbyExecutor = standbyExecutor, startupNetworkUpdatePending = { startupNetworkUpdatePending })

        init {
            backend.probeClock = { now }
            backend.metricsOverride = {
                (listOf(primary) + backend.additionalSlots).distinct().sorted()
                    .joinToString(prefix = "{\"slots\":[", postfix = "]}") { slot ->
                    val healthy = slot in healthySlots
                    val tx = if (healthy) 1 + now / 1000 else 3 * (1 + now / 5000)
                    val rx = if (healthy) minOf(now, receiveFrozenAtMs ?: now) / 1000 else 0
                    val handshake = if (healthy) 1_800_000_000_000L else 0L
                    """{"slot":$slot,"admitted":true,"closed":false,"latest_handshake_at_unix_ms":$handshake,"telemetry":{"udp_send_errors":0,"udp_send_packets":$tx,"tun_write_packets":$rx}}"""
                }
            }
            if (replay != null) {
                assertTrue(store.beginRedundant(replay) is RecoveryStoreResult.Success)
                if (recoverOnCreation) assertTrue(coordinator.recover())
            } else {
                val leases = listOfNotNull(transaction.slotALeaseId, transaction.slotBLeaseId)
                assertTrue(coordinator.start(transaction,
                    leases.associateWith { byteArrayOf(1) }, leases.associateWith { healthProbe },
                    shouldCancel = { cancel }, onPrimaryStarted = { ready += 1 },
                    onPrimaryFailed = { failed += 1 }, onPrimaryCancelled = { cancelled += 1 }))
            }
        }

        fun failNextWrite() { record.failNext = true }
        fun clearWriteFailure() { record.failNext = false }

        fun standbyCheckStartedAt(): Long? = adapter.javaClass
            .getDeclaredField("standbyCheckStartedAtMs").apply { isAccessible = true }.get(adapter) as Long?


        fun awaitInitialStandbyCommit(): Long {
            for (elapsed in 0L..8_000L step 100L) {
                tick(elapsed)
                if (coordinator.status()?.let { it.slotALeaseId != null && it.slotBLeaseId != null } == true) {
                    return elapsed
                }
            }
            error("initial standby was not committed within the startup check window")
        }

        fun failPrimaryRebind() {
            assertFalse(native.rebind(if (primary == 0) "lease-a" else "lease-b"))
        }

        fun tick(elapsed: Long) {
            now = elapsed
            backend.probeStatuses.replaceAll { token, status ->
                val (startedAt, slot) = backend.probeDetails.getValue(token)
                val delay = if (slot != primary) reserveProbeAnswerDelayMs else 0L
                if (status == NativeProbeStatus.PENDING && slot in healthySlots &&
                    slot !in dnsBlockedSlots && elapsed - startedAt >= delay) NativeProbeStatus.SUCCEEDED else status
            }
            coordinator.tick()
        }
    }

    private fun probe() = BackgroundRedundantHealthProbe(
        kind = "dns_a",
        targetIpv4 = "8.8.8.8",
        queryName = "nelomai.ru",
        timeoutMs = 4_000,
    )

    private fun timingFixture(active: Boolean): TimingFixture {
        val clock = TestDualClock(epochMs = 1_800_000_000_000L, elapsedMs = 0L)
        val backend = RecordingSessionBackend { clock.epochMs }
        backend.probeClock = { clock.elapsedMs }
        val native = ServiceRedundantConnectionNative(
            backend = backend,
            establishTun = { 41 },
            prepare = ::prepared,
            probeSourceIpv4 = "10.200.0.2/32",
            epochNowMs = { clock.epochMs },
            elapsedNowMs = { clock.elapsedMs },
        )
        assertTrue(native.start("lease-a", RedundantSlot.A, byteArrayOf(1), probe()))
        if (active) assertTrue(native.activate("lease-a"))
        return TimingFixture(clock, backend, native)
    }

    private fun pairFixture(primary: Int, warmUntil: Long = 29_000L): PairFixture {
        val single = timingFixture(active = false)
        single.backend.useSlotCounters = true
        assertTrue(single.native.start("lease-b", RedundantSlot.B, byteArrayOf(2), probe()))
        assertTrue(single.native.activate(if (primary == 0) "lease-a" else "lease-b"))
        val pair = PairFixture(single.clock, single.backend, single.native)
        for (now in 0L..warmUntil step 1_000L) pair.tick(now) { _, _ -> true }
        return pair
    }

    private class PairFixture(
        val clock: TestDualClock,
        val backend: RecordingSessionBackend,
        val native: ServiceRedundantConnectionNative,
    ) {
        val monitor = RedundantHealthMonitor()
        fun tick(now: Long, succeeds: (Int, Long) -> Boolean): FailoverDecision =
            monitor.evaluateHealth(now, observe(now, succeeds))

        fun observe(now: Long, succeeds: (Int, Long) -> Boolean): List<SlotObservation> {
            clock.elapsedMs = now
            backend.probeStatuses.replaceAll { token, status ->
                val (started, slot) = backend.probeDetails.getValue(token)
                if (status == NativeProbeStatus.PENDING && succeeds(slot, started)) {
                    NativeProbeStatus.SUCCEEDED
                } else status
            }
            return native.healthObservations()
        }
    }

    private class TimingFixture(
        val clock: TestDualClock,
        val backend: RecordingSessionBackend,
        val native: ServiceRedundantConnectionNative,
    ) {
        fun observe(now: Long, healthy: Boolean): SlotObservation {
            clock.elapsedMs = now
            if (healthy) {
                backend.probeStatuses.replaceAll { _, status ->
                    if (status == NativeProbeStatus.PENDING) NativeProbeStatus.SUCCEEDED else status
                }
            }
            return native.healthObservations().single()
        }
    }

    private fun suspectedFixture(): SuspectedFixture {
        val clock = TestDualClock(epochMs = 1_800_000_000_000L, elapsedMs = 10_000L)
        val backend = RecordingSessionBackend { clock.epochMs }
        val native = ServiceRedundantConnectionNative(
            backend = backend,
            establishTun = { 41 },
            prepare = ::prepared,
            probeSourceIpv4 = "10.200.0.2/32",
            epochNowMs = { clock.epochMs },
            elapsedNowMs = { clock.elapsedMs },
        )
        assertTrue(native.start("lease-a", RedundantSlot.A, byteArrayOf(1), probe()))
        assertTrue(native.activate("lease-a"))
        native.healthObservations()
        backend.probeStatuses[requireNotNull(backend.latestProbeToken)] = NativeProbeStatus.FAILED
        clock.elapsedMs += 1L
        assertTrue(native.healthObservations().single().independentFailureSignal)
        return SuspectedFixture(native, backend)
    }

    private fun prepared(@Suppress("UNUSED_PARAMETER") configuration: ByteArray): PreparedRedundantConfiguration =
        PreparedRedundantConfiguration(
            config = Config.parse(ByteArrayInputStream(TEST_CONFIG.toByteArray())),
            userspace = "private_key=redacted-for-fake".toByteArray(),
        )

    private fun preparedWithEndpoint(
        @Suppress("UNUSED_PARAMETER") configuration: ByteArray,
        endpoint: String,
    ): PreparedRedundantConfiguration = PreparedRedundantConfiguration(
        config = Config.parse(
            ByteArrayInputStream(
                TEST_CONFIG.replace("127.0.0.1", endpoint).toByteArray(),
            ),
        ),
        userspace = "private_key=redacted-for-fake".toByteArray(),
    )

    private companion object {
        val TEST_CONFIG = """
            [Interface]
            PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
            Address = 10.200.0.2/32

            [Peer]
            PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
            AllowedIPs = 0.0.0.0/0
            Endpoint = 127.0.0.1:10001
        """.trimIndent()
    }
}

private data class SuspectedFixture(
    val native: ServiceRedundantConnectionNative,
    val backend: RecordingSessionBackend,
)

private data class TestDualClock(
    var epochMs: Long,
    var elapsedMs: Long,
)

internal class RecordingSessionBackend(
    private val nowMs: () -> Long = { 1_000_000L },
) : RedundantSessionBackend {
    val primarySlots = mutableListOf<Int>()
    val additionalSlots = mutableListOf<Int>()
    val activeSlots = mutableListOf<Int>()
    val probeStatuses = mutableMapOf<Long, NativeProbeStatus>()
    val probeLaunches = mutableListOf<Pair<Long, Int>>()
    val probeDetails = mutableMapOf<Long, Pair<Long, Int>>()
    var probeClock: () -> Long = { 0L }
    var useSlotCounters = false
    private val slotSendPackets = mutableMapOf<Int, Long>()
    val sendErrorsBySlot = mutableMapOf<Int, Long>()
    val failedProbeSendSlots = mutableSetOf<Int>()
    val rebindFailures = mutableSetOf<Int>()
    var beforeRebind: () -> Unit = {}
    var beforeSwitchActive: (Int) -> Unit = {}
    var failedActivationSlot: Int? = null
    val reboundSlots = mutableListOf<Int>()
    var latestProbeToken: Long? = null
    var countProbeSend = true
    var decryptedReceivePackets = 0L
    var metricsOverride: (() -> String?)? = null
    private val admitted = mutableSetOf<Int>()
    private var nextToken = 1L

    override fun start(tunFd: Int, primaryConfiguration: ByteArray): NativeSession? =
        start(tunFd, 0, primaryConfiguration)

    override fun start(
        tunFd: Int,
        primarySlot: Int,
        primaryConfiguration: ByteArray,
    ): NativeSession {
        primarySlots += primarySlot
        admitted += primarySlot
        primaryConfiguration.fill(0)
        return NativeSession(7)
    }

    override fun startSlot(
        session: NativeSession,
        slot: Int,
        configuration: ByteArray,
    ): Boolean {
        additionalSlots += slot
        admitted += slot
        configuration.fill(0)
        return true
    }

    override fun switchActive(session: NativeSession, slot: Int): Boolean = (slot != failedActivationSlot).also {
        beforeSwitchActive(slot)
        activeSlots += slot
    }

    override fun stopSlot(session: NativeSession, slot: Int): Boolean = admitted.remove(slot)

    override fun rebind(session: NativeSession, slot: Int): Boolean {
        beforeRebind()
        reboundSlots += slot
        return slot in admitted && slot !in rebindFailures
    }

    override fun startProbe(
        session: NativeSession,
        slot: Int,
        template: NativeDnsProbeTemplate,
    ): Long = nextToken++.also {
        if (slot in failedProbeSendSlots) {
            sendErrorsBySlot[slot] = (sendErrorsBySlot[slot] ?: 0L) + 1L
        } else if (countProbeSend) {
            udpSendPackets += 1
            slotSendPackets[slot] = (slotSendPackets[slot] ?: 0L) + 1L
        }
        val launched = probeClock() to slot
        probeLaunches += launched
        probeDetails[it] = launched
        latestProbeToken = it
        probeStatuses[it] = NativeProbeStatus.PENDING
    }

    override fun probeStatus(session: NativeSession, token: Long): NativeProbeStatus =
        probeStatuses[token] ?: NativeProbeStatus.UNKNOWN

    override fun cancelProbe(session: NativeSession, token: Long): Boolean =
        probeStatuses.remove(token) != null

    override fun metrics(session: NativeSession): String? {
        val override = metricsOverride
        if (override != null) return override()
        return admitted.sorted().joinToString(
            prefix = "{\"slots\":[",
            postfix = "]}",
        ) { slot ->
            val sent = if (useSlotCounters) slotSendPackets[slot] ?: 0L else udpSendPackets
            """{"slot":$slot,"admitted":true,"closed":false,"latest_handshake_at_unix_ms":${nowMs()},"telemetry":{"tun_read_bytes":7,"tun_write_bytes":11,"tun_write_packets":$decryptedReceivePackets,"udp_send_packets":$sent,"udp_send_errors":${sendErrorsBySlot[slot] ?: 0L},"udp_receive_packets":$udpReceivePackets}}"""
        }
    }

    override fun close(session: NativeSession) {
        admitted.clear()
    }

    fun setUdpPackets(sent: Long, received: Long) {
        udpSendPackets = sent
        udpReceivePackets = received
    }

    private var udpSendPackets = 0L
    private var udpReceivePackets = 0L
}
