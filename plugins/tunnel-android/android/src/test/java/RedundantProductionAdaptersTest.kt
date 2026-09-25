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
        fixture.backend.rebindFailures += 0
        for (now in 0L..15_000L step 1_000L) fixture.tick(now)
        assertEquals("lease-b", fixture.coordinator.status()?.slotBLeaseId)
        assertEquals(0, fixture.ready)
        assertEquals(listOf(0), fixture.backend.activeSlots)
        fixture.tick(16_000L)
        assertEquals(0, fixture.ready)
        for (now in 17_000L..20_000L step 1_000L) fixture.tick(now)
        assertEquals(1, fixture.ready)
        assertEquals(0, fixture.failed)
        assertEquals(listOf(0, 1), fixture.backend.activeSlots)
        assertTrue(fixture.backend.probeLaunches.any { (started, slot) ->
            slot == 1 && started >= 16_000L
        })
    }

    @Test
    fun failedInitialRebindStillWaitsForHealthyReserveWarmupAndFreshProbe() {
        for (primary in listOf(0, 1)) {
            val fixture = StartupFixture(primary, ::prepared)
            fixture.healthySlots = setOf(1 - primary)
            fixture.backend.rebindFailures += primary
            for (now in 0L..20_000L step 100L) {
                fixture.tick(now)
                assertEquals("premature failure at $now", 0, fixture.failed)
                if (now < 15_000L) assertEquals(0, fixture.ready)
            }
            assertEquals(1, fixture.ready)
            assertEquals(listOf(primary, 1 - primary), fixture.backend.activeSlots)
            assertTrue(fixture.backend.probeLaunches.any { (started, slot) ->
                slot == 1 - primary && started >= 15_000L
            })
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
        val fixture = StartupFixture(0, ::prepared)
        fixture.healthySlots = setOf(1)
        fixture.backend.rebindFailures += 0
        for (now in 0L..20_000L step 100L) {
            if (now >= 14_900L) fixture.dnsBlockedSlots = setOf(1)
            fixture.tick(now)
            assertEquals(0, fixture.ready)
        }
        assertEquals(1, fixture.failed)
        assertEquals(listOf(0), fixture.backend.activeSlots)
        assertTrue(fixture.backend.probeLaunches.any { (started, slot) ->
            slot == 1 && started >= 15_000L
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
                if (now < 15_000L) assertEquals(0, fixture.ready)
            }
            assertEquals("primary=$primary", 1, fixture.ready)
            assertEquals(0, fixture.failed)
            assertEquals(listOf(primary, 1 - primary), fixture.backend.activeSlots)
            assertEquals(0, fixture.maxPrimaryCorroboration)
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
                if (now == 14_900L) fixture.cancel = true
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
        invalidated.native.setNetworkValidated(false)
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
    fun availableButUnvalidatedNetworkSuspendsNativeProbeProgress() {
        val backend = RecordingSessionBackend()
        val native = ServiceRedundantConnectionNative(
            backend = backend,
            establishTun = { 41 },
            prepare = ::prepared,
            probeSourceIpv4 = "10.200.0.2/32",
            initialNetworkValidated = false,
        )
        assertTrue(native.start("lease-a", RedundantSlot.A, byteArrayOf(1), probe()))

        val observation = native.healthObservations().single()

        assertEquals(0, backend.probeStatuses.size)
        assertEquals(0, observation.consecutiveProbeSuccesses)
        assertEquals(BackendHealth.WARMING, observation.health)
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
            """{"dispatcher":{"OutboundBytes":14,"InboundBytes":22,"ProbePacketsInjected":9000},"slots":[{"slot":0,"admitted":true,"closed":false,"latest_handshake_at_unix_ms":999999,"telemetry":{"tun_read_bytes":0,"tun_write_bytes":0,"udp_send_packets":500,"udp_receive_packets":400}},{"slot":1,"admitted":true,"closed":false,"latest_handshake_at_unix_ms":1000000,"telemetry":{"tun_read_bytes":0,"tun_write_bytes":0,"udp_send_packets":700,"udp_receive_packets":600}}]}"""
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
            """{"slots":[{"slot":0,"admitted":true,"closed":true,"latest_handshake_at_unix_ms":1000000,"telemetry":{"tun_read_bytes":7,"tun_write_bytes":11,"tun_write_packets":0,"udp_send_packets":0,"udp_receive_packets":0}}]}"""
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
    ) {
        @Volatile var now = 0L
        var healthySlots = setOf(0, 1)
        var dnsBlockedSlots = emptySet<Int>()
        var receiveFrozenAtMs: Long? = null
        var cancel = false
        var ready = 0
        var failed = 0
        var cancelled = 0
        var stalled = 0
        var maxPrimaryCorroboration = 0
        val backend = RecordingSessionBackend { 1_800_000_000_000L }
        private val adapter = ServiceRedundantConnectionNative(backend, { 41 }, prepare,
            probeSourceIpv4 = "10.241.0.1/32",
            epochNowMs = { 1_800_000_000_000L }, elapsedNowMs = { now })
        private val native = object : RedundantConnectionNative by adapter {
            override fun healthObservations(initialReadiness: Boolean,
                committedStandbyLeaseId: String?, freshStart: Boolean): List<SlotObservation> =
                adapter.healthObservations(initialReadiness, committedStandbyLeaseId, freshStart).also { observations ->
                    observations.firstOrNull { it.index == primary }?.let {
                        maxPrimaryCorroboration = maxOf(maxPrimaryCorroboration, it.corroboratedProbeFailures)
                    }
                }
        }
        private val record = object : EncryptedRecordBackend {
            var bytes = AndroidRecoveryEnvelopeCodec.encode(AndroidRecoveryEnvelope.empty(1))
            override fun read(): ByteArray = bytes.clone()
            override fun write(plaintext: ByteArray): Boolean {
                bytes = plaintext.clone()
                return true
            }
        }
        private val store = AndroidRecoveryStore(record, object : BootIdentityProvider {
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
            override fun recover(transaction: AndroidRedundantTransaction): RedundantRecoveryResponse =
                error("unexpected recovery")
            override fun reportRole(transaction: AndroidRedundantTransaction, reason: String): RedundantRoleResponse =
                RedundantRoleResponse("accepted", requireNotNull(transaction.localActiveLeaseId),
                    BackgroundRedundantSession(transaction.sessionId, "connected",
                        transaction.localActiveLeaseId, transaction.slotALeaseId,
                        transaction.slotBLeaseId, true, transaction.roleGeneration,
                        transaction.membershipGeneration, null))
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
            override fun stop(transaction: AndroidRedundantTransaction): Boolean = true
        }
        val coordinator = RedundantConnectionCoordinator(store, panel, native,
            epochNowMs = { now }, monotonicMs = { now }, onAllSlotsStalled = { stalled++ },
            standbyExecutor = standbyExecutor)

        init {
            backend.probeClock = { now }
            backend.metricsOverride = {
                (listOf(primary) + backend.additionalSlots).distinct().sorted()
                    .joinToString(prefix = "{\"slots\":[", postfix = "]}") { slot ->
                    val healthy = slot in healthySlots
                    val tx = if (healthy) 1 + now / 1000 else 3 * (1 + now / 5000)
                    val rx = if (healthy) minOf(now, receiveFrozenAtMs ?: now) / 1000 else 0
                    val handshake = if (healthy) 1_800_000_000_000L else 0L
                    """{"slot":$slot,"admitted":true,"closed":false,"latest_handshake_at_unix_ms":$handshake,"telemetry":{"udp_send_packets":$tx,"tun_write_packets":$rx}}"""
                }
            }
            val probe = BackgroundRedundantHealthProbe("dns_a", "77.88.8.8", "nelomai.ru", 4000)
            assertTrue(coordinator.start(transaction,
                listOfNotNull(transaction.slotALeaseId, transaction.slotBLeaseId)
                    .associateWith { byteArrayOf(1) },
                listOfNotNull(transaction.slotALeaseId, transaction.slotBLeaseId)
                    .associateWith { probe },
                shouldCancel = { cancel }, onPrimaryStarted = { ready += 1 },
                onPrimaryFailed = { failed += 1 }, onPrimaryCancelled = { cancelled += 1 }))
        }

        fun failPrimaryRebind() {
            assertFalse(native.rebind(if (primary == 0) "lease-a" else "lease-b"))
        }

        fun tick(elapsed: Long) {
            now = elapsed
            backend.probeStatuses.replaceAll { token, status ->
                val slot = backend.probeDetails.getValue(token).second
                if (status == NativeProbeStatus.PENDING && slot in healthySlots &&
                    slot !in dnsBlockedSlots) NativeProbeStatus.SUCCEEDED else status
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
    val rebindFailures = mutableSetOf<Int>()
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

    override fun switchActive(session: NativeSession, slot: Int): Boolean = true.also {
        activeSlots += slot
    }

    override fun stopSlot(session: NativeSession, slot: Int): Boolean = admitted.remove(slot)

    override fun rebind(session: NativeSession, slot: Int): Boolean =
        slot in admitted && slot !in rebindFailures

    override fun startProbe(
        session: NativeSession,
        slot: Int,
        template: NativeDnsProbeTemplate,
    ): Long = nextToken++.also {
        if (countProbeSend) {
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
            """{"slot":$slot,"admitted":true,"closed":false,"latest_handshake_at_unix_ms":${nowMs()},"telemetry":{"tun_read_bytes":7,"tun_write_bytes":11,"tun_write_packets":$decryptedReceivePackets,"udp_send_packets":$sent,"udp_receive_packets":$udpReceivePackets}}"""
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
