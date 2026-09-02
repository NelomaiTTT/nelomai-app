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
            stopLookupPending: Boolean = false,
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
            stopLookupPending = stopLookupPending,
            logoutState = logout,
            recovery = recovery,
        )

        assertEquals(RedundantTotalLossCommandDisposition.PREPARE_RESTART_AND_STOP, disposition())
        assertEquals(RedundantTotalLossCommandDisposition.IGNORE, disposition(generation = 8))
        assertEquals(RedundantTotalLossCommandDisposition.IGNORE, disposition(destroyed = true))
        assertEquals(RedundantTotalLossCommandDisposition.IGNORE, disposition(installed = "new-owner"))
        assertEquals(RedundantTotalLossCommandDisposition.IGNORE, disposition(ownerMatches = false))
        assertEquals(RedundantTotalLossCommandDisposition.IGNORE, disposition(stopPending = true))
        assertEquals(
            RedundantTotalLossCommandDisposition.DEFER_UNTIL_BARRIER_RELEASE,
            disposition(tombstoneUnreadable = true),
        )
        assertEquals(
            RedundantTotalLossCommandDisposition.DEFER_UNTIL_BARRIER_RELEASE,
            disposition(stopLookupPending = true),
        )
        assertEquals(
            RedundantTotalLossCommandDisposition.IGNORE,
            disposition(logout = BackgroundLogoutReadState.PENDING),
        )
        assertEquals(
            RedundantTotalLossCommandDisposition.DEFER_UNTIL_CREDENTIAL_READABLE,
            disposition(logout = BackgroundLogoutReadState.UNREADABLE),
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
    fun unreadableCredentialSchedulesRetryWithoutImmediateReplay() {
        val lifecycle = RedundantTotalLossCommandLifecycle<String>()
        var retries = 0

        lifecycle.handle(
            command = "current-owner",
            disposition =
                RedundantTotalLossCommandDisposition.DEFER_UNTIL_CREDENTIAL_READABLE,
            barrierPendingAfterDefer = { error("credential retry read barrier") },
            replayDeferred = { error("credential retry replayed immediately") },
            scheduleDeferredRetry = { retries += 1 },
            prepareRestartAndStop = { error("credential retry prepared restart") },
            failClosedStop = { error("credential retry failed closed") },
        )

        assertEquals(1, retries)
        assertTrue(lifecycle.replay { assertEquals("current-owner", it) })
    }

    @Test
    fun deferredCommandKeepsLatestIdentityAndReplaysOnlyOnce() {
        val lifecycle = RedundantTotalLossCommandLifecycle<String>()
        val replayed = mutableListOf<String>()

        listOf("old-owner", "current-owner").forEach { command ->
            lifecycle.handle(
                command = command,
                disposition = RedundantTotalLossCommandDisposition.DEFER_UNTIL_BARRIER_RELEASE,
                barrierPendingAfterDefer = { true },
                replayDeferred = { error("barrier is still pending") },
                scheduleDeferredRetry = { error("unexpected credential retry") },
                prepareRestartAndStop = { error("deferred command was prepared") },
                failClosedStop = { error("deferred command failed closed") },
            )
        }

        assertTrue(lifecycle.replay { replayed += it })
        assertFalse(lifecycle.replay { replayed += it })
        assertEquals(listOf("current-owner"), replayed)
    }

    @Test
    fun terminalCommandDispositionsRouteOnlyTheirConsumer() {
        val lifecycle = RedundantTotalLossCommandLifecycle<String>()
        val prepared = mutableListOf<String>()
        val failedClosed = mutableListOf<String>()

        listOf(
            "ignored" to RedundantTotalLossCommandDisposition.IGNORE,
            "prepared" to RedundantTotalLossCommandDisposition.PREPARE_RESTART_AND_STOP,
            "failed" to RedundantTotalLossCommandDisposition.FAIL_CLOSED_STOP,
        ).forEach { (command, disposition) ->
            lifecycle.handle(
                command = command,
                disposition = disposition,
                barrierPendingAfterDefer = { error("terminal command checked a barrier") },
                replayDeferred = { error("terminal command requested replay") },
                scheduleDeferredRetry = { error("terminal command scheduled retry") },
                prepareRestartAndStop = { prepared += it },
                failClosedStop = { failedClosed += it },
            )
        }

        assertEquals(listOf("prepared"), prepared)
        assertEquals(listOf("failed"), failedClosed)
        assertFalse(lifecycle.replay { error("terminal command was retained") })
    }

    @Test
    fun deferredCommandReplaysWhenBarrierClearsDuringEnqueue() {
        val lifecycle = RedundantTotalLossCommandLifecycle<String>()
        val replayed = mutableListOf<String>()

        lifecycle.handle(
            command = "current-owner",
            disposition = RedundantTotalLossCommandDisposition.DEFER_UNTIL_BARRIER_RELEASE,
            barrierPendingAfterDefer = { false },
            replayDeferred = {
                assertTrue(lifecycle.replay { replayed += it })
            },
            scheduleDeferredRetry = { error("unexpected credential retry") },
            prepareRestartAndStop = { error("deferred command was prepared") },
            failClosedStop = { error("deferred command failed closed") },
        )

        assertEquals(listOf("current-owner"), replayed)
        assertFalse(lifecycle.replay { replayed += it })
    }

    @Test
    fun barrierResumeDispatchesReplayAndDurableWorkTogether() {
        val lifecycle = RedundantTotalLossCommandLifecycle<String>()
        lifecycle.handle(
            command = "current-owner",
            disposition = RedundantTotalLossCommandDisposition.DEFER_UNTIL_BARRIER_RELEASE,
            barrierPendingAfterDefer = { true },
            replayDeferred = { error("barrier is still pending") },
            scheduleDeferredRetry = { error("unexpected credential retry") },
            prepareRestartAndStop = { error("deferred command was prepared") },
            failClosedStop = { error("deferred command failed closed") },
        )
        val events = mutableListOf<String>()
        var posted: (() -> Unit)? = null

        dispatchDeferredRedundantTotalLossAndDurableWork(
            dispatch = { posted = it },
            dispatchAllowed = { true },
            lifecycle = lifecycle,
            reprocess = { events += "total-loss:$it" },
            resumeDurableWork = { events += "durable-work" },
        )

        assertEquals(emptyList<String>(), events)
        requireNotNull(posted).invoke()
        assertEquals(listOf("total-loss:current-owner", "durable-work"), events)
    }

    @Test
    fun invalidatedDispatchDoesNotReplayOrResumeDurableWork() {
        val lifecycle = RedundantTotalLossCommandLifecycle<String>()
        lifecycle.handle(
            command = "current-owner",
            disposition = RedundantTotalLossCommandDisposition.DEFER_UNTIL_BARRIER_RELEASE,
            barrierPendingAfterDefer = { true },
            replayDeferred = { error("barrier is still pending") },
            scheduleDeferredRetry = { error("unexpected credential retry") },
            prepareRestartAndStop = { error("deferred command was prepared") },
            failClosedStop = { error("deferred command failed closed") },
        )
        val events = mutableListOf<String>()
        var posted: (() -> Unit)? = null

        dispatchDeferredRedundantTotalLossAndDurableWork(
            dispatch = { posted = it },
            dispatchAllowed = { false },
            lifecycle = lifecycle,
            reprocess = { events += "total-loss:$it" },
            resumeDurableWork = { events += "durable-work" },
        )

        requireNotNull(posted).invoke()
        assertEquals(emptyList<String>(), events)
    }

    @Test
    fun lookupReleaseRechecksCurrentCommandAndPreparesOnlyOnce() {
        val fixture = CommandFixture(recovery = RecoveryStoreResult.Success(redundantEnvelope()))
        fixture.lookupTokens = 1

        fixture.handle()
        assertEquals(0, fixture.prepares)

        fixture.lookupTokens = 0
        fixture.releaseBarrier()
        fixture.releaseBarrier()

        assertEquals(1, fixture.prepares)
        assertEquals(0, fixture.failClosedStops)
    }

    @Test
    fun actualStopOrLogoutWinsBeforeDeferredCommandReplay() {
        val stopped = CommandFixture(recovery = RecoveryStoreResult.Success(redundantEnvelope()))
        stopped.lookupTokens = 1
        stopped.handle()
        stopped.stopPending = true
        stopped.lookupTokens = 0
        stopped.releaseBarrier()

        val loggedOut = CommandFixture(recovery = RecoveryStoreResult.Success(redundantEnvelope()))
        loggedOut.lookupTokens = 1
        loggedOut.handle()
        loggedOut.logout = BackgroundLogoutReadState.PENDING
        loggedOut.lookupTokens = 0
        loggedOut.releaseBarrier()

        assertEquals(0, stopped.prepares)
        assertEquals(0, stopped.failClosedStops)
        assertEquals(0, loggedOut.prepares)
        assertEquals(0, loggedOut.failClosedStops)
    }

    @Test
    fun unreadableRecoveryAfterBarrierReleaseFailsClosedWithoutRestart() {
        val fixture = CommandFixture(recovery = RecoveryStoreResult.Success(redundantEnvelope()))
        fixture.lookupTokens = 1
        fixture.handle()
        fixture.recovery = RecoveryStoreResult.Failure("recovery_record_read_failed")
        fixture.lookupTokens = 0

        fixture.releaseBarrier()

        assertEquals(0, fixture.prepares)
        assertEquals(1, fixture.failClosedStops)
    }

    @Test
    fun overlappingLookupTokensKeepCommandDeferredUntilLastRelease() {
        val fixture = CommandFixture(recovery = RecoveryStoreResult.Success(redundantEnvelope()))
        fixture.lookupTokens = 2
        fixture.handle()

        fixture.lookupTokens = 1
        fixture.releaseBarrier()
        assertEquals(0, fixture.prepares)

        fixture.lookupTokens = 0
        fixture.releaseBarrier()
        assertEquals(1, fixture.prepares)
    }

    @Test
    fun changedGenerationOrOwnerMakesDeferredCommandInert() {
        val staleGeneration = CommandFixture(
            recovery = RecoveryStoreResult.Success(redundantEnvelope()),
        )
        staleGeneration.lookupTokens = 1
        staleGeneration.handle()
        staleGeneration.currentGeneration = 8
        staleGeneration.lookupTokens = 0
        staleGeneration.releaseBarrier()

        val staleOwner = CommandFixture(recovery = RecoveryStoreResult.Success(redundantEnvelope()))
        staleOwner.lookupTokens = 1
        staleOwner.handle()
        staleOwner.installedOwnerMatches = false
        staleOwner.lookupTokens = 0
        staleOwner.releaseBarrier()

        assertEquals(0, staleGeneration.prepares)
        assertEquals(0, staleGeneration.failClosedStops)
        assertEquals(0, staleOwner.prepares)
        assertEquals(0, staleOwner.failClosedStops)
    }

    @Test
    fun unreadableCredentialRetriesThenPreparesExactlyOnceWhenReadable() {
        val fixture = CommandFixture(recovery = RecoveryStoreResult.Success(redundantEnvelope()))
        fixture.logout = BackgroundLogoutReadState.UNREADABLE

        fixture.handle()
        assertEquals(0, fixture.prepares)
        assertEquals(1, fixture.scheduledRetries)

        fixture.logout = BackgroundLogoutReadState.NONE
        fixture.releaseBarrier()
        fixture.releaseBarrier()

        assertEquals(1, fixture.prepares)
        assertEquals(0, fixture.failClosedStops)
    }

    @Test
    fun realLogoutWinsWhenCredentialBecomesReadableBeforeRetry() {
        val fixture = CommandFixture(recovery = RecoveryStoreResult.Success(redundantEnvelope()))
        fixture.logout = BackgroundLogoutReadState.UNREADABLE
        fixture.handle()

        fixture.logout = BackgroundLogoutReadState.PENDING
        fixture.releaseBarrier()

        assertEquals(0, fixture.prepares)
        assertEquals(0, fixture.failClosedStops)
    }

    @Test
    fun credentialRetryBecomesInertForChangedGenerationOrOwner() {
        val staleGeneration = CommandFixture(
            recovery = RecoveryStoreResult.Success(redundantEnvelope()),
        )
        staleGeneration.logout = BackgroundLogoutReadState.UNREADABLE
        staleGeneration.handle()
        staleGeneration.currentGeneration = 8
        staleGeneration.logout = BackgroundLogoutReadState.NONE
        staleGeneration.releaseBarrier()

        val staleOwner = CommandFixture(recovery = RecoveryStoreResult.Success(redundantEnvelope()))
        staleOwner.logout = BackgroundLogoutReadState.UNREADABLE
        staleOwner.handle()
        staleOwner.installedOwnerMatches = false
        staleOwner.logout = BackgroundLogoutReadState.NONE
        staleOwner.releaseBarrier()

        assertEquals(0, staleGeneration.prepares)
        assertEquals(0, staleGeneration.failClosedStops)
        assertEquals(0, staleOwner.prepares)
        assertEquals(0, staleOwner.failClosedStops)
    }

    @Test
    fun stopLookupBarrierDefersCredentialRetryUntilLookupRelease() {
        val fixture = CommandFixture(recovery = RecoveryStoreResult.Success(redundantEnvelope()))
        fixture.lookupTokens = 1
        fixture.logout = BackgroundLogoutReadState.UNREADABLE

        fixture.handle()
        assertEquals(0, fixture.scheduledRetries)

        fixture.lookupTokens = 0
        fixture.releaseBarrier()

        assertEquals(1, fixture.scheduledRetries)
        assertEquals(0, fixture.prepares)
    }

    @Test
    fun totalLossRetrySchedulerDeduplicatesAndCancelsItsTask() {
        val scheduled = mutableMapOf<Runnable, Long>()
        var retries = 0
        var scheduleAllowed = true
        val scheduler = RedundantTotalLossRetryScheduler(
            retry = { retries += 1 },
            delayMillis = 1_000L,
            scheduleAllowed = { scheduleAllowed },
            remove = { scheduled.remove(it) },
            postDelayed = { task, delay -> scheduled[task] = delay },
        )

        scheduler.schedule()
        scheduler.schedule()

        assertEquals(listOf(1_000L), scheduled.values.toList())
        val task = scheduled.keys.single()
        scheduled.remove(task)
        task.run()
        assertEquals(1, retries)

        scheduler.schedule()
        scheduler.cancel()
        assertTrue(scheduled.isEmpty())

        scheduleAllowed = false
        scheduler.schedule()
        assertTrue(scheduled.isEmpty())
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
        assertEquals(0, fixture.stateReadRetries)
        assertEquals(0, fixture.cleanupRetries)
    }

    @Test
    fun unreadableCredentialRetriesPromotedRestartUntilCredentialIsReadable() {
        val fixture = Fixture(
            recovery = RecoveryStoreResult.Success(restartEnvelope()),
            logout = BackgroundLogoutReadState.UNREADABLE,
        )

        fixture.lifecycle.onCleanupAcknowledged(7)
        fixture.runPosted()

        assertEquals(1, fixture.stateReadRetries)
        assertEquals(0, fixture.logouts)
        assertEquals(0, fixture.resumes)
        assertEquals(0, fixture.cleanupRetries)

        fixture.logoutState = BackgroundLogoutReadState.NONE
        fixture.lifecycle.onCleanupAcknowledged(7)
        fixture.runPosted()

        assertEquals(listOf("starting", "resume"), fixture.events)
        assertEquals(1, fixture.resumes)
    }

    @Test
    fun unreadableRecoverySchedulesStateReadRetryInsteadOfBarrierCleanup() {
        val fixture = Fixture(
            recovery = RecoveryStoreResult.Failure("recovery_record_read_failed"),
        )

        fixture.lifecycle.onCleanupAcknowledged(7)
        fixture.runPosted()

        assertEquals(1, fixture.stateReadRetries)
        assertEquals(0, fixture.cleanupRetries)
        assertEquals(0, fixture.resumes)
        assertEquals(0, fixture.startingPublications)
    }

    @Test
    fun readableRecoveryAfterRetryResumesThePromotedRestart() {
        val fixture = Fixture(
            recovery = RecoveryStoreResult.Failure("recovery_record_read_failed"),
        )

        fixture.lifecycle.onCleanupAcknowledged(7)
        fixture.runPosted()
        fixture.recoveryState = RecoveryStoreResult.Success(restartEnvelope())
        fixture.lifecycle.onCleanupAcknowledged(7)
        fixture.runPosted()

        assertEquals(1, fixture.stateReadRetries)
        assertEquals(0, fixture.cleanupRetries)
        assertEquals(listOf("starting", "resume"), fixture.events)
    }

    @Test
    fun logoutWinsWhenItStartsAfterARecoveryReadFailure() {
        val fixture = Fixture(
            recovery = RecoveryStoreResult.Failure("recovery_record_read_failed"),
        )

        fixture.lifecycle.onCleanupAcknowledged(7)
        fixture.runPosted()
        fixture.logoutState = BackgroundLogoutReadState.PENDING
        fixture.lifecycle.onCleanupAcknowledged(7)
        fixture.runPosted()

        assertEquals(1, fixture.stateReadRetries)
        assertEquals(1, fixture.logouts)
        assertEquals(0, fixture.resumes)
        assertEquals(0, fixture.startingPublications)
    }

    @Test
    fun barrierAndUnreadableRecoveryUseTheirOwnWakeups() {
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
        assertEquals(0, barrier.stateReadRetries)
        assertEquals(0, barrier.resumes)
        assertEquals(0, barrier.startingPublications)
        assertEquals(0, unreadable.cleanupRetries)
        assertEquals(1, unreadable.stateReadRetries)
        assertEquals(0, unreadable.resumes)
        assertEquals(0, unreadable.startingPublications)
    }

    @Test
    fun readableSupersedingRedundantWorkDoesNotStartStateReadPolling() {
        val fixture = Fixture(
            recovery = RecoveryStoreResult.Success(redundantEnvelope()),
        )

        fixture.lifecycle.onCleanupAcknowledged(7)
        fixture.runPosted()

        assertEquals(1, fixture.cleanupRetries)
        assertEquals(0, fixture.stateReadRetries)
        assertEquals(0, fixture.resumes)
        assertEquals(0, fixture.startingPublications)
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
        assertEquals(0, fixture.stateReadRetries)
        assertEquals(0, fixture.startingPublications)
    }

    @Test
    fun destroyedServiceMakesTheQueuedCompletionANoOp() {
        val fixture = Fixture(recovery = RecoveryStoreResult.Success(restartEnvelope()))
        fixture.serviceActive = false

        fixture.lifecycle.onCleanupAcknowledged(7)
        fixture.runPosted()

        assertEquals(0, fixture.resumes)
        assertEquals(0, fixture.stops)
        assertEquals(0, fixture.cleanupRetries)
        assertEquals(0, fixture.stateReadRetries)
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
        var stateReadRetries = 0
        var startingPublications = 0
        var logoutState = logout
        var recoveryState = recovery
        var serviceActive = true
        val events = mutableListOf<String>()
        val lifecycle = RedundantTotalLossLifecycle(
            currentServiceGeneration = { generation },
            serviceActive = { serviceActive },
            barrierPending = { barrierPending },
            logoutState = { logoutState },
            recovery = { recoveryState },
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
            scheduleStateReadRetry = { stateReadRetries += 1 },
            stopIfIdle = { stops += 1 },
        )

        fun runPosted() = requireNotNull(posted).invoke()
    }

    private class CommandFixture(
        var recovery: RecoveryStoreResult<AndroidRecoveryEnvelope>,
    ) {
        private val lifecycle = RedundantTotalLossCommandLifecycle<String>()
        var currentGeneration = 7L
        var installedOwnerMatches = true
        var stopPending = false
        var lookupTokens = 0
        var logout = BackgroundLogoutReadState.NONE
        var prepares = 0
        var failClosedStops = 0
        var scheduledRetries = 0

        fun handle() {
            val disposition = redundantTotalLossCommandDisposition(
                ownerServiceGeneration = 7,
                currentServiceGeneration = currentGeneration,
                serviceDestroyed = false,
                startOperationId = "v2-start",
                installedStartOperationId = "v2-start",
                installedOwnerMatches = installedOwnerMatches,
                stopPending = stopPending,
                tombstoneUnreadable = false,
                stopLookupPending = lookupTokens > 0,
                logoutState = logout,
                recovery = recovery,
            )
            lifecycle.handle(
                command = "v2-start",
                disposition = disposition,
                barrierPendingAfterDefer = { lookupTokens > 0 },
                replayDeferred = ::releaseBarrier,
                scheduleDeferredRetry = { scheduledRetries += 1 },
                prepareRestartAndStop = { prepares += 1 },
                failClosedStop = { failClosedStops += 1 },
            )
        }

        fun releaseBarrier() {
            dispatchDeferredRedundantTotalLossAndDurableWork(
                dispatch = { it() },
                dispatchAllowed = { true },
                lifecycle = lifecycle,
                reprocess = { handle() },
                resumeDurableWork = {},
            )
        }
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
