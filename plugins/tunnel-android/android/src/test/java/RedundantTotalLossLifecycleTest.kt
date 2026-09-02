package ru.nelomai.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RedundantTotalLossLifecycleTest {
    @Test
    fun commandAdmissionRejectsEveryStaleOrSupersededOwnerBoundary() {
        val recovery = RecoveryStoreResult.Success(redundantEnvelope())
        fun disposition(
            generation: Long = 7,
            destroyed: Boolean = false,
            installed: String? = "v2-start",
            ownerMatches: Boolean = true,
            stopPending: Boolean = false,
            tombstoneUnreadable: Boolean = false,
            logout: BackgroundLogoutReadState = BackgroundLogoutReadState.NONE,
        ) = redundantTotalLossCommandDisposition(
            ownerServiceGeneration = 7,
            currentServiceGeneration = generation,
            serviceDestroyed = destroyed,
            startOperationId = "v2-start",
            installedStartOperationId = installed,
            installedOwnerMatches = ownerMatches,
            stopPending = stopPending,
            tombstoneUnreadable = tombstoneUnreadable,
            stopLookupPending = false,
            logoutState = logout,
            recovery = recovery,
        )

        assertEquals(RedundantTotalLossCommandDisposition.PREPARE_RESTART_AND_STOP, disposition())
        assertEquals(RedundantTotalLossCommandDisposition.IGNORE, disposition(generation = 8))
        assertEquals(RedundantTotalLossCommandDisposition.IGNORE, disposition(destroyed = true))
        assertEquals(RedundantTotalLossCommandDisposition.IGNORE, disposition(installed = "new-owner"))
        assertEquals(RedundantTotalLossCommandDisposition.IGNORE, disposition(ownerMatches = false))
        assertEquals(RedundantTotalLossCommandDisposition.IGNORE, disposition(stopPending = true))
        assertEquals(RedundantTotalLossCommandDisposition.IGNORE, disposition(tombstoneUnreadable = true))
        assertEquals(
            RedundantTotalLossCommandDisposition.IGNORE,
            disposition(logout = BackgroundLogoutReadState.PENDING),
        )
    }

    @Test
    fun currentOwnerWithUnreadableRecoveryStillRequestsFailClosedStop() {
        assertEquals(
            RedundantTotalLossCommandDisposition.FAIL_CLOSED_STOP,
            redundantTotalLossCommandDisposition(
                ownerServiceGeneration = 7,
                currentServiceGeneration = 7,
                serviceDestroyed = false,
                startOperationId = "v2-start",
                installedStartOperationId = "v2-start",
                installedOwnerMatches = true,
                stopPending = false,
                tombstoneUnreadable = false,
                stopLookupPending = false,
                logoutState = BackgroundLogoutReadState.NONE,
                recovery = RecoveryStoreResult.Failure("recovery_record_read_failed"),
            ),
        )
    }

    @Test
    fun acknowledgedRestartIsQueuedAndResumedOnlyFromStartPending() {
        val fixture = Fixture(recovery = RecoveryStoreResult.Success(restartEnvelope()))

        fixture.lifecycle.onCleanupAcknowledged(7)
        assertEquals(0, fixture.resumes)
        fixture.runPosted()

        assertEquals(listOf("starting", "resume"), fixture.events)
        assertEquals(1, fixture.startingPublications)
        assertEquals(1, fixture.resumes)
        assertEquals(0, fixture.stops)
        assertEquals(0, fixture.cleanupRetries)
    }

    @Test
    fun acknowledgedExplicitStopStopsWhenIdle() {
        val fixture = Fixture(recovery = RecoveryStoreResult.Success(stoppedEnvelope()))

        fixture.lifecycle.onCleanupAcknowledged(7)
        fixture.runPosted()

        assertEquals(0, fixture.resumes)
        assertEquals(1, fixture.stops)
    }

    @Test
    fun onlyExactPromotedTotalLossEnvelopePublishesStarting() {
        val exact = restartEnvelope()
        assertTrue(isExactPromotedRedundantTotalLossRestart(exact))

        val variants = listOf(
            exact.copy(redundantTransaction = redundantEnvelope().redundantTransaction),
            exact.copy(intent = exact.intent.copy(desiredActive = false)),
            exact.copy(intent = exact.intent.copy(
                retry = exact.intent.retry.copy(pendingAction = "validate_capability"),
            )),
            exact.copy(intent = exact.intent.copy(
                retry = exact.intent.retry.copy(
                    redundantTotalLossSourceStartOperationId = null,
                ),
            )),
            exact.copy(leaseTransaction = exact.leaseTransaction?.copy(
                generation = exact.intent.generation + 1,
            )),
            exact.copy(leaseTransaction = exact.leaseTransaction?.copy(
                phase = LeasePhase.LEASE_ACQUIRED,
            )),
            exact.copy(leaseTransaction = exact.leaseTransaction?.copy(
                leaseId = "lease",
            )),
            exact.copy(leaseTransaction = exact.leaseTransaction?.copy(
                replay = exact.leaseTransaction.replay.copy(
                    startOperationId = requireNotNull(
                        exact.intent.retry.redundantTotalLossSourceStartOperationId,
                    ),
                ),
            )),
            exact.copy(leaseTransaction = null),
        )

        variants.forEach { assertFalse(isExactPromotedRedundantTotalLossRestart(it)) }
    }

    @Test
    fun serviceResumeRoutesOnlyBarrierOrExactPromotionThroughFinalGate() {
        assertTrue(shouldRouteConnectionIntentResumeThroughRedundantGate(
            barrierPending = false,
            recovery = RecoveryStoreResult.Success(restartEnvelope()),
        ))
        assertTrue(shouldRouteConnectionIntentResumeThroughRedundantGate(
            barrierPending = true,
            recovery = RecoveryStoreResult.Success(stoppedEnvelope()),
        ))
        assertTrue(shouldRouteConnectionIntentResumeThroughRedundantGate(
            barrierPending = false,
            recovery = RecoveryStoreResult.Failure("recovery_record_read_failed"),
        ))
        assertFalse(shouldRouteConnectionIntentResumeThroughRedundantGate(
            barrierPending = false,
            recovery = RecoveryStoreResult.Success(stoppedEnvelope()),
        ))
    }

    @Test
    fun genericDurableStartResumesWithoutPublishingTotalLossStarting() {
        val generic = restartEnvelope().let { envelope ->
            envelope.copy(
                intent = envelope.intent.copy(retry = AndroidRetryState()),
            )
        }
        val fixture = Fixture(recovery = RecoveryStoreResult.Success(generic))

        fixture.lifecycle.onCleanupAcknowledged(7)
        fixture.runPosted()

        assertEquals(emptyList<String>(), fixture.events.filter { it == "starting" })
        assertEquals(1, fixture.resumes)
    }

    @Test
    fun logoutWinsOverPromotedRestart() {
        val fixture = Fixture(
            recovery = RecoveryStoreResult.Success(restartEnvelope()),
            logout = BackgroundLogoutReadState.PENDING,
        )

        fixture.lifecycle.onCleanupAcknowledged(7)
        fixture.runPosted()

        assertEquals(1, fixture.logouts)
        assertEquals(0, fixture.resumes)
        assertEquals(0, fixture.startingPublications)
    }

    @Test
    fun pendingBarrierOrUnreadableRecoveryRetriesWithoutStarting() {
        val barrier = Fixture(
            recovery = RecoveryStoreResult.Success(restartEnvelope()),
            barrierPending = true,
        )
        barrier.lifecycle.onCleanupAcknowledged(7)
        barrier.runPosted()

        val unreadable = Fixture(
            recovery = RecoveryStoreResult.Failure("recovery_record_read_failed"),
        )
        unreadable.lifecycle.onCleanupAcknowledged(7)
        unreadable.runPosted()

        assertEquals(1, barrier.cleanupRetries)
        assertEquals(0, barrier.resumes)
        assertEquals(0, barrier.startingPublications)
        assertEquals(1, unreadable.cleanupRetries)
        assertEquals(0, unreadable.resumes)
        assertEquals(0, unreadable.startingPublications)
    }

    @Test
    fun staleServiceGenerationMakesTheQueuedCompletionANoOp() {
        val fixture = Fixture(
            recovery = RecoveryStoreResult.Success(restartEnvelope()),
            generation = 8,
        )

        fixture.lifecycle.onCleanupAcknowledged(7)
        fixture.runPosted()

        assertEquals(0, fixture.resumes)
        assertEquals(0, fixture.stops)
        assertEquals(0, fixture.cleanupRetries)
        assertEquals(0, fixture.startingPublications)
    }

    @Test
    fun repeatedExactDurableRetryKeepsPublishingStartingBeforeResume() {
        val fixture = Fixture(recovery = RecoveryStoreResult.Success(restartEnvelope()))

        repeat(2) {
            fixture.lifecycle.onCleanupAcknowledged(7)
            fixture.runPosted()
        }

        assertEquals(
            listOf("starting", "resume", "starting", "resume"),
            fixture.events,
        )
    }

    private class Fixture(
        recovery: RecoveryStoreResult<AndroidRecoveryEnvelope>,
        logout: BackgroundLogoutReadState = BackgroundLogoutReadState.NONE,
        barrierPending: Boolean = false,
        generation: Long = 7,
    ) {
        private var posted: (() -> Unit)? = null
        var resumes = 0
        var stops = 0
        var cleanupRetries = 0
        var logouts = 0
        var startingPublications = 0
        val events = mutableListOf<String>()
        val lifecycle = RedundantTotalLossLifecycle(
            currentServiceGeneration = { generation },
            barrierPending = { barrierPending },
            logoutState = { logout },
            recovery = { recovery },
            post = { posted = it },
            retryCleanup = { cleanupRetries += 1 },
            publishRestartStarting = {
                startingPublications += 1
                events += "starting"
            },
            resume = {
                resumes += 1
                events += "resume"
            },
            scheduleLogout = { logouts += 1 },
            stopIfIdle = { stops += 1 },
        )

        fun runPosted() = requireNotNull(posted).invoke()
    }

    companion object {
        private fun restartEnvelope(): AndroidRecoveryEnvelope {
            val intent = AndroidConnectionIntent.empty(1).copy(
                generation = 1,
                desiredActive = true,
                template = template(),
                retry = AndroidRetryState(
                    pendingAction = "redundant_total_loss_restart",
                    redundantTotalLossSourceStartOperationId = "v2-start",
                ),
            )
            return AndroidRecoveryEnvelope(
                formatVersion = ANDROID_RECOVERY_FORMAT,
                intent = intent,
                leaseTransaction = AndroidLeaseTransaction(
                    generation = 1,
                    bootCount = 1,
                    phase = LeasePhase.START_PENDING,
                    leaseId = null,
                    stopOperationId = null,
                    replay = AndroidStartReplay("restart", 1, "fingerprint"),
                ),
            )
        }

        private fun stoppedEnvelope() = AndroidRecoveryEnvelope.empty(1)

        private fun redundantEnvelope() = AndroidRecoveryEnvelope(
            formatVersion = ANDROID_RECOVERY_FORMAT,
            intent = AndroidConnectionIntent.empty(1).copy(
                desiredActive = true,
                template = template(),
            ),
            leaseTransaction = null,
            redundantTransaction = AndroidRedundantTransaction(
                desiredActive = true,
                template = template(),
                sessionId = "22222222-2222-4222-8222-222222222222",
                slotALeaseId = "lease-a",
                slotBLeaseId = "lease-b",
                localActiveLeaseId = "lease-a",
                standbyDesired = true,
                roleGeneration = 1,
                membershipGeneration = 1,
                startOperationId = "v2-start",
                startRequestFingerprint = "fingerprint",
            ),
        )

        private fun template() = AndroidIntentTemplate(
            deviceId = "11111111-1111-4111-8111-111111111111",
            accountScope = "account",
            layer = "stray",
            ticConnectionMode = "dynamic",
            routeMode = "standalone",
            egressMode = "ipv4",
            allowAlternate = true,
        )
    }
}
