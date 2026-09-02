package ru.nelomai.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

class NelomaiVpnServiceTest {
    @Test
    fun disabledReserveCapabilityOnlyReleasesDesiredStandby() {
        val disabled = BackgroundCapabilitySnapshot(
            revision = 2,
            enabled = true,
            expiresAtUnix = 2_000,
            reserveEnabled = false,
        )
        val enabled = disabled.copy(reserveEnabled = true)

        assertTrue(
            redundantCapabilityRequiresStandbyRelease(
                disabled,
                serviceV2Envelope().redundantTransaction,
            ),
        )
        assertFalse(
            redundantCapabilityRequiresStandbyRelease(
                enabled,
                serviceV2Envelope().redundantTransaction,
            ),
        )
        assertFalse(redundantCapabilityRequiresStandbyRelease(disabled, null))
        assertFalse(
            redundantCapabilityRequiresStandbyRelease(
                disabled,
                serviceV2Envelope().redundantTransaction?.copy(standbyDesired = false),
            ),
        )
    }

    @Test
    fun redundantStartCancellationSurvivesSetupUntilReadinessAcknowledgesIt() {
        val outcomes = mutableListOf<String>()
        val gate = RedundantStartOperationGate()

        assertTrue(gate.begin("operation-a") { outcomes += "stopped" })
        assertFalse(gate.begin("operation-b") { outcomes += "wrong" })
        assertFalse(gate.cancel("operation-b"))
        assertTrue(gate.cancel("operation-a"))
        assertTrue(gate.isCancelled("operation-a"))
        assertTrue(gate.completeCancelled("operation-a"))

        assertEquals(listOf("stopped"), outcomes)
        assertTrue(gate.isCancelled("operation-a"))
        assertFalse(gate.begin("operation-b") { outcomes += "wrong" })

        gate.finish("operation-a")

        assertFalse(gate.isCancelled("operation-a"))
        assertTrue(gate.begin("operation-b") { outcomes += "stopped-b" })
    }

    @Test
    fun redundantStartCancellationRemainsVisibleUntilWorkerObservesIt() {
        val outcomes = mutableListOf<String>()
        val gate = RedundantStartOperationGate()

        assertTrue(gate.begin("operation-a") { outcomes += "stopped" })
        assertTrue(gate.cancel("operation-a"))
        assertTrue(gate.completeCancelled("operation-a"))
        assertTrue(gate.isCancelled("operation-a"))
        assertFalse(gate.begin("operation-b") { outcomes += "wrong" })

        gate.finish("operation-a")

        assertEquals(listOf("stopped"), outcomes)
        assertFalse(gate.isCancelled("operation-a"))
        assertTrue(gate.begin("operation-b") { outcomes += "stopped-b" })
    }

    @Test
    fun redundantStopAtomicallyCancelsAndCompletesPendingStart() {
        val outcomes = mutableListOf<String>()
        val gate = RedundantStartOperationGate()

        assertTrue(gate.begin("operation-a") { outcomes += "stopped" })

        assertEquals("operation-a", gate.cancelPendingAndComplete())
        assertEquals(listOf("stopped"), outcomes)
        assertTrue(gate.isCancelled("operation-a"))
        assertFalse(gate.complete("operation-a") { outcomes += "running" })

        gate.finish("operation-a")

        assertFalse(gate.isCancelled("operation-a"))
        assertTrue(gate.begin("operation-b") { outcomes += "stopped-b" })
    }

    @Test
    fun backgroundLogoutWinsOverLateRedundantStartFailure() {
        val outcomes = mutableListOf<String>()
        val gate = RedundantStartOperationGate()

        assertTrue(gate.begin("operation-a") { outcomes += "stopped" })

        assertEquals(
            "operation-a",
            cancelPendingRedundantStartForBackgroundLogout(gate),
        )
        assertFalse(gate.complete("operation-a") { outcomes += "failed" })
        gate.finish("operation-a")

        assertEquals(listOf("stopped"), outcomes)
        assertFalse(gate.hasPending())
    }

    @Test
    fun redundantStartFailureObservesCancellationMadeAfterWorkerSnapshot() {
        val outcomes = mutableListOf<String>()
        val gate = RedundantStartOperationGate()

        assertTrue(gate.begin("operation-a") { outcomes += "stopped" })
        assertFalse(gate.isCancelled("operation-a"))
        assertTrue(gate.cancel("operation-a"))

        assertTrue(gate.completeFailure("operation-a") { outcomes += "failed" })
        gate.finish("operation-a")

        assertEquals(listOf("stopped"), outcomes)
        assertFalse(gate.hasPending())
    }

    @Test
    fun redundantStartFailureStillPublishesFailureWhenNotCancelled() {
        val outcomes = mutableListOf<String>()
        val gate = RedundantStartOperationGate()

        assertTrue(gate.begin("operation-a") { outcomes += "stopped" })

        assertTrue(gate.completeFailure("operation-a") { outcomes += "failed" })
        gate.finish("operation-a")

        assertEquals(listOf("failed"), outcomes)
        assertFalse(gate.hasPending())
    }

    @Test
    fun redundantStartReadyAndStopRacePublishesExactlyOneTerminalOutcome() {
        repeat(100) { index ->
            val outcomes = CopyOnWriteArrayList<String>()
            val gate = RedundantStartOperationGate()
            val ready = CountDownLatch(2)
            val release = CountDownLatch(1)
            val operationId = "operation-$index"
            assertTrue(gate.begin(operationId) { outcomes += "stopped" })
            val runningThread = Thread {
                ready.countDown()
                release.await()
                gate.complete(operationId) { outcomes += "running" }
            }
            val stoppedThread = Thread {
                ready.countDown()
                release.await()
                gate.completeCancelled(operationId)
            }
            runningThread.start()
            stoppedThread.start()
            assertTrue(ready.await(1, TimeUnit.SECONDS))
            release.countDown()
            runningThread.join()
            stoppedThread.join()

            assertEquals(1, outcomes.size)
            assertTrue(outcomes.single() in setOf("running", "stopped"))
            gate.finish(operationId)
        }
    }

    @Test
    fun revokeLifecycleDrainsCleanupAcrossDestroyAndFinalizesFrameworkExactlyOnce() {
        val lifecycle = RedundantRevokeLifecycleGate()
        val queued = ArrayDeque<Runnable>()
        val dispatcher = RedundantVpnWorkDispatcher(Executor(queued::addLast))
        val events = mutableListOf<String>()

        assertTrue(lifecycle.begin())
        dispatchRedundantWork(
            dispatcher = dispatcher,
            fallbackDispatcher = dispatcher,
            action = {
                events += "fence"
                events += "revoke"
                lifecycle.cleanupFinished()
                lifecycle.completeFramework { events += "framework" }
            },
            onRejected = {},
        )

        assertTrue(lifecycle.hasPendingCleanup())
        assertTrue(lifecycle.needsFrameworkCompletion())
        lifecycle.completeFramework { events += "framework" }
        assertEquals(listOf("framework"), events)

        queued.removeFirst().run()

        assertFalse(lifecycle.hasPendingCleanup())
        assertFalse(lifecycle.needsFrameworkCompletion())
        assertEquals(listOf("framework", "fence", "revoke"), events)
    }

    @Test
    fun revokeLifecycleFinalizesDuringDestroyAfterCleanupButBeforeMainCallback() {
        val lifecycle = RedundantRevokeLifecycleGate()
        val worker = ArrayDeque<Runnable>()
        val main = ArrayDeque<Runnable>()
        val dispatcher = RedundantVpnWorkDispatcher(Executor(worker::addLast))
        var frameworkCalls = 0

        assertTrue(lifecycle.begin())
        dispatchRedundantWork(
            dispatcher = dispatcher,
            fallbackDispatcher = dispatcher,
            action = {
                lifecycle.cleanupFinished()
                main += Runnable {
                    lifecycle.completeFramework { frameworkCalls += 1 }
                }
            },
            onRejected = {},
        )
        worker.removeFirst().run()

        assertFalse(lifecycle.hasPendingCleanup())
        assertTrue(lifecycle.needsFrameworkCompletion())
        assertFalse(lifecycle.begin())
        lifecycle.completeFramework { frameworkCalls += 1 }
        main.removeFirst().run()

        assertFalse(lifecycle.needsFrameworkCompletion())
        assertEquals(1, frameworkCalls)
    }

    @Test
    fun rejectedRevokeDispatchStillCompletesFrameworkFallback() {
        val lifecycle = RedundantRevokeLifecycleGate()
        val dispatcher = RedundantVpnWorkDispatcher(Executor {
            throw RejectedExecutionException("destroyed")
        })
        val fallbackQueue = ArrayDeque<Runnable>()
        val fallback = RedundantVpnWorkDispatcher(Executor(fallbackQueue::addLast))
        var frameworkCalls = 0
        var fenceCalls = 0
        var revokeCalls = 0
        var rejectedCalls = 0

        assertTrue(lifecycle.begin())
        dispatchRedundantWork(
            dispatcher = dispatcher,
            fallbackDispatcher = fallback,
            action = {
                fenceCalls += 1
                revokeCalls += 1
                lifecycle.cleanupFinished()
                lifecycle.completeFramework { frameworkCalls += 1 }
            },
            onRejected = { rejectedCalls += 1 },
        )

        assertEquals(0, fenceCalls)
        assertEquals(1, fallbackQueue.size)
        fallbackQueue.removeFirst().run()

        assertEquals(1, fenceCalls)
        assertEquals(1, revokeCalls)
        assertFalse(lifecycle.hasPendingCleanup())
        assertEquals(1, frameworkCalls)
        assertEquals(0, rejectedCalls)
    }

    @Test
    fun cancelTombstoneSurvivesStoreRecreationUntilExactCleanupAcknowledgement() {
        val backend = ServiceCancelTombstoneBackend()
        val first = RedundantCancelTombstoneStore(backend) { "stop-operation-a" }

        val persisted = first.persist("start-operation-a")

        assertTrue(persisted is RecoveryStoreResult.Success)
        val tombstone = (persisted as RecoveryStoreResult.Success).value
        assertEquals(
            RedundantCancelTombstone("start-operation-a", "stop-operation-a"),
            tombstone,
        )
        val recreated = RedundantCancelTombstoneStore(backend) { "wrong-stop" }
        assertEquals(persisted, recreated.read())
        assertFalse(recreated.clear(
            RedundantCancelTombstone("start-operation-a", "different-stop"),
        ))
        assertEquals(persisted, recreated.read())
        assertTrue(recreated.clear(tombstone))
        assertEquals(RecoveryStoreResult.Success(null), recreated.read())
    }

    @Test
    fun corruptCancelTombstoneFailsClosedInsteadOfAllowingResume() {
        val backend = ServiceCancelTombstoneBackend().apply { record = "broken" }

        assertEquals(
            RecoveryStoreResult.Failure("redundant_cancel_tombstone_corrupt"),
            RedundantCancelTombstoneStore(backend).read(),
        )
    }

    @Test
    fun unreadableRecoveryAfterPrimaryReadyRequiresFailClosedCleanup() {
        assertEquals(
            RedundantPrimaryReadyDisposition.FAIL_CLOSED,
            redundantPrimaryReadyDisposition(
                RecoveryStoreResult.Failure("recovery_record_corrupt"),
            ),
        )
        assertEquals(
            RedundantPrimaryReadyDisposition.RUNNING,
            redundantPrimaryReadyDisposition(
                RecoveryStoreResult.Success(serviceV2Envelope()),
            ),
        )
        assertEquals(
            RedundantPrimaryReadyDisposition.CANCELLED,
            redundantPrimaryReadyDisposition(
                RecoveryStoreResult.Success(serviceV2Envelope()),
                startCancelled = true,
            ),
        )
        assertEquals(
            RedundantPrimaryReadyDisposition.CANCELLED,
            redundantPrimaryReadyDisposition(
                RecoveryStoreResult.Success(serviceV2Envelope().copy(
                    redundantTransaction = serviceV2Envelope().redundantTransaction?.copy(
                        desiredActive = false,
                    ),
                )),
            ),
        )
    }

    @Test
    fun stoppedIsPublishedOnlyAfterDurableCancellationAndLocalShutdown() {
        assertFalse(shouldCompleteRedundantCancellation(
            tombstonePersisted = true,
            localClosed = false,
            cleanupStopped = false,
        ))
        assertFalse(shouldCompleteRedundantCancellation(
            tombstonePersisted = false,
            localClosed = true,
            cleanupStopped = true,
        ))
        assertTrue(shouldCompleteRedundantCancellation(
            tombstonePersisted = true,
            localClosed = true,
            cleanupStopped = false,
        ))
        assertTrue(shouldCompleteRedundantCancellation(
            tombstonePersisted = true,
            localClosed = false,
            cleanupStopped = true,
        ))
    }

    @Test
    fun oldServiceCleanupCannotPublishStoppedOverNewGenerationOrTransaction() {
        assertEquals(
            RedundantStopCompletionDisposition.PUBLISH_STOPPED,
            redundantStopCompletionDisposition(
                ownerServiceGeneration = 7,
                currentServiceGeneration = 7,
                recovery = RecoveryStoreResult.Success(serviceV1Envelope()),
            ),
        )
        assertEquals(
            RedundantStopCompletionDisposition.STALE_ONLY,
            redundantStopCompletionDisposition(
                ownerServiceGeneration = 7,
                currentServiceGeneration = 8,
                recovery = RecoveryStoreResult.Success(serviceV1Envelope()),
            ),
        )
        assertEquals(
            RedundantStopCompletionDisposition.STALE_ONLY,
            redundantStopCompletionDisposition(
                ownerServiceGeneration = 7,
                currentServiceGeneration = 7,
                recovery = RecoveryStoreResult.Success(serviceV2Envelope()),
            ),
        )
    }

    @Test
    fun oldRedundantCleanupWaitsForReadableRecoveryAndNeverOverridesANewLease() {
        val newLease = recoveryStore(ServiceRecoveryBackend()).beginStart(
            expectedGeneration = 0,
            template = template(),
            replay = AndroidStartReplay("new-start", 1, "new-fingerprint"),
        ).successEnvelope()

        assertEquals(
            RedundantStopCompletionDisposition.RETRY,
            redundantStopCompletionDisposition(
                ownerServiceGeneration = 7,
                currentServiceGeneration = 7,
                recovery = RecoveryStoreResult.Failure("recovery_record_corrupt"),
            ),
        )
        assertEquals(
            RedundantStopCompletionDisposition.STALE_ONLY,
            redundantStopCompletionDisposition(
                ownerServiceGeneration = 7,
                currentServiceGeneration = 7,
                recovery = RecoveryStoreResult.Success(newLease),
            ),
        )
    }

    @Test
    fun unreadableRecoveryFallsBackToTheInstalledRedundantOwnerIdentity() {
        assertEquals(
            "owner-start",
            redundantStopOperationId(
                pendingStopOperationId = null,
                recovery = RecoveryStoreResult.Failure("recovery_record_corrupt"),
                pendingStartOperationId = null,
                ownerStartOperationId = "owner-start",
            ),
        )
        assertEquals(
            "durable-stop",
            redundantStopOperationId(
                pendingStopOperationId = "durable-stop",
                recovery = RecoveryStoreResult.Success(serviceV2Envelope()),
                pendingStartOperationId = "pending-start",
                ownerStartOperationId = "owner-start",
            ),
        )
    }

    @Test
    fun inMemoryRedundantStopIdentityDoesNotTouchDurableRecovery() {
        var durableReads = 0

        val operationId = resolveRedundantStopOperationId(
            pendingStopOperationId = null,
            pendingStartOperationId = "pending-start",
            ownerStartOperationId = "owner-start",
        ) {
            durableReads += 1
            RecoveryStoreResult.Success(serviceV2Envelope())
        }

        assertEquals("pending-start", operationId)
        assertEquals(0, durableReads)
    }

    @Test
    fun durableRedundantStopIdentityIsReadOnlyAfterMemoryMiss() {
        var durableReads = 0

        val operationId = resolveRedundantStopOperationId(
            pendingStopOperationId = null,
            pendingStartOperationId = null,
            ownerStartOperationId = null,
        ) {
            durableReads += 1
            RecoveryStoreResult.Success(serviceV2Envelope())
        }

        assertEquals("start-operation", operationId)
        assertEquals(1, durableReads)
    }

    @Test
    fun queuedStopLookupRechecksMemoryBeforeReadingDurableRecovery() {
        val worker = ArrayDeque<Runnable>()
        val caller = ArrayDeque<Runnable>()
        val dispatcher = RedundantVpnWorkDispatcher(Executor(worker::addLast))
        val barrier = RedundantStopLookupBarrier()
        val inMemory = AtomicReference<String?>(null)
        var durableReads = 0
        var completed: String? = null

        dispatchWithRedundantStopLookupBarrier(
            dispatcher = dispatcher,
            fallbackDispatcher = dispatcher,
            barrier = barrier,
            resolveInMemory = inMemory::get,
            resolveDurable = {
                durableReads += 1
                "durable"
            },
            postToCaller = { action -> caller.addLast(Runnable(action)) },
            complete = { completed = it },
            onRejected = { throw AssertionError("lookup rejected") },
        )

        assertTrue(barrier.hasPending())
        inMemory.set("memory")
        worker.removeFirst().run()

        assertEquals(0, durableReads)
        assertNull(completed)
        assertTrue(barrier.hasPending())

        caller.removeFirst().run()

        assertEquals("memory", completed)
        assertFalse(barrier.hasPending())
    }

    @Test
    fun stopLookupInvalidatesStartsBeforeDispatchAndResumesOnlyAfterBarrierRelease() {
        val worker = ArrayDeque<Runnable>()
        val caller = ArrayDeque<Runnable>()
        val dispatcher = RedundantVpnWorkDispatcher(Executor(worker::addLast))
        val barrier = RedundantStopLookupBarrier()
        val events = mutableListOf<String>()

        dispatchWithRedundantStopLookupBarrier(
            dispatcher = dispatcher,
            fallbackDispatcher = dispatcher,
            barrier = barrier,
            resolveInMemory = { null },
            resolveDurable = {
                events += "resolve"
                "durable"
            },
            postToCaller = { action -> caller.addLast(Runnable(action)) },
            complete = {
                assertTrue(barrier.hasPending())
                events += "complete"
            },
            onBegin = {
                assertTrue(barrier.hasPending())
                events += "invalidate"
            },
            onRejected = { throw AssertionError("lookup rejected") },
            afterComplete = {
                assertFalse(barrier.hasPending())
                events += "resume"
            },
        )

        assertEquals(listOf("invalidate"), events)
        worker.removeFirst().run()
        assertEquals(listOf("invalidate", "resolve"), events)
        caller.removeFirst().run()
        assertEquals(listOf("invalidate", "resolve", "complete", "resume"), events)
    }

    @Test
    fun redundantBarrierReleaseDoesNotResumeDestroyedOrStaleService() {
        val currentEvents = mutableListOf<String>()
        handleRedundantBarrierRelease(
            ownerServiceGeneration = 7,
            currentServiceGeneration = 7,
            serviceDestroyed = false,
            resumeDurableWork = { currentEvents += "resume" },
            completeAfterDestroy = { currentEvents += "destroyed" },
        )
        assertEquals(listOf("resume"), currentEvents)

        val destroyedEvents = mutableListOf<String>()
        handleRedundantBarrierRelease(
            ownerServiceGeneration = 7,
            currentServiceGeneration = 7,
            serviceDestroyed = true,
            resumeDurableWork = { destroyedEvents += "resume" },
            completeAfterDestroy = { destroyedEvents += "destroyed" },
        )
        assertEquals(listOf("destroyed"), destroyedEvents)

        val staleEvents = mutableListOf<String>()
        handleRedundantBarrierRelease(
            ownerServiceGeneration = 7,
            currentServiceGeneration = 8,
            serviceDestroyed = false,
            resumeDurableWork = { staleEvents += "resume" },
            completeAfterDestroy = { staleEvents += "destroyed" },
        )
        assertTrue(staleEvents.isEmpty())
    }

    @Test
    fun destroyedServiceIdlePathRecyclesWithoutEvaluatingDurableWork() {
        val events = mutableListOf<String>()

        assertTrue(routeDestroyedServiceIdle(
            serviceDestroyed = true,
            recycle = { events += "recycle" },
        ))

        assertEquals(listOf("recycle"), events)

        events.clear()
        assertFalse(routeDestroyedServiceIdle(
            serviceDestroyed = false,
            recycle = { events += "recycle" },
        ))
        assertTrue(events.isEmpty())
    }

    @Test
    fun rejectedStopLookupCompletesOnCallerBeforeReleasingBarrier() {
        val caller = ArrayDeque<Runnable>()
        val rejected = RedundantVpnWorkDispatcher(Executor {
            throw RejectedExecutionException("closed")
        })
        val barrier = RedundantStopLookupBarrier()
        var rejections = 0

        dispatchWithRedundantStopLookupBarrier(
            dispatcher = rejected,
            fallbackDispatcher = rejected,
            barrier = barrier,
            resolveInMemory = { null },
            resolveDurable = { "durable" },
            postToCaller = { action -> caller.addLast(Runnable(action)) },
            complete = { throw AssertionError("lookup unexpectedly completed: $it") },
            onRejected = { rejections += 1 },
        )

        assertTrue(barrier.hasPending())
        assertEquals(0, rejections)

        caller.removeFirst().run()

        assertEquals(1, rejections)
        assertFalse(barrier.hasPending())
    }

    @Test
    fun unresolvedRedundantCleanupBlocksEveryKindOfNewStart() {
        assertTrue(redundantCleanupBlocksNewStarts(
            pendingStop = true,
            tombstoneUnreadable = false,
        ))
        assertTrue(redundantCleanupBlocksNewStarts(
            pendingStop = false,
            tombstoneUnreadable = true,
        ))
        assertTrue(redundantCleanupBlocksNewStarts(
            pendingStop = false,
            tombstoneUnreadable = false,
            stopLookupPending = true,
        ))
        assertTrue(redundantCleanupBlocksNewStarts(
            pendingStop = false,
            tombstoneUnreadable = false,
            retainedOwnerCleanupPending = true,
        ))
        assertFalse(redundantCleanupBlocksNewStarts(
            pendingStop = false,
            tombstoneUnreadable = false,
        ))
    }

    @Test
    fun delayedRedundantWorkerRejectsCleanupDisarmedAndReplacementTransactions() {
        val active = serviceV2Envelope()
        val startOperationId = requireNotNull(active.redundantTransaction).startOperationId
        var actions = 0

        assertNull(activeRedundantTransactionForWork(
            recovery = RecoveryStoreResult.Success(active),
            expectedStartOperationId = startOperationId,
            pendingStop = true,
            tombstoneUnreadable = false,
        ))
        assertNull(activeRedundantTransactionForWork(
            recovery = RecoveryStoreResult.Success(active),
            expectedStartOperationId = startOperationId,
            pendingStop = false,
            tombstoneUnreadable = true,
        ))
        assertNull(activeRedundantTransactionForWork(
            recovery = RecoveryStoreResult.Success(active),
            expectedStartOperationId = startOperationId,
            pendingStop = false,
            tombstoneUnreadable = false,
            stopLookupPending = true,
        ))
        assertNull(activeRedundantTransactionForWork(
            recovery = RecoveryStoreResult.Success(active),
            expectedStartOperationId = startOperationId,
            pendingStop = false,
            tombstoneUnreadable = false,
            retainedOwnerCleanupPending = true,
        ))
        assertNull(activeRedundantTransactionForWork(
            recovery = RecoveryStoreResult.Success(active.copy(
                redundantTransaction = requireNotNull(active.redundantTransaction).copy(
                    desiredActive = false,
                ),
            )),
            expectedStartOperationId = startOperationId,
            pendingStop = false,
            tombstoneUnreadable = false,
        ))
        assertNull(activeRedundantTransactionForWork(
            recovery = RecoveryStoreResult.Success(active),
            expectedStartOperationId = "replacement-operation",
            pendingStop = false,
            tombstoneUnreadable = false,
        ))
        activeRedundantTransactionForWork(
            recovery = RecoveryStoreResult.Success(active),
            expectedStartOperationId = startOperationId,
            pendingStop = false,
            tombstoneUnreadable = false,
        )?.let { actions += 1 }

        assertEquals(1, actions)
    }

    @Test
    fun delayedPhysicalNetworkCallbackCannotMutateAReplacementServiceOrOwner() {
        val mutationFence = RedundantOperationMutationFence()
        val callback = RedundantPhysicalNetworkCallbackIdentity(
            serviceGeneration = 7,
            startOperationId = "start-a",
        )
        var mutations = 0

        assertFalse(callback.applyIfCurrent(
            mutationFence = mutationFence,
            current = {
                RedundantPhysicalNetworkCallbackState(8, "start-a", false, false)
            },
        ) { mutations += 1 })
        assertFalse(callback.applyIfCurrent(
            mutationFence = mutationFence,
            current = {
                RedundantPhysicalNetworkCallbackState(7, "start-b", false, false)
            },
        ) { mutations += 1 })
        assertFalse(callback.applyIfCurrent(
            mutationFence = mutationFence,
            current = {
                RedundantPhysicalNetworkCallbackState(7, "start-a", true, false)
            },
        ) { mutations += 1 })
        assertFalse(callback.applyIfCurrent(
            mutationFence = mutationFence,
            current = {
                RedundantPhysicalNetworkCallbackState(
                    7,
                    "start-a",
                    pendingStop = false,
                    tombstoneUnreadable = false,
                    stopLookupPending = true,
                )
            },
        ) { mutations += 1 })
        assertFalse(callback.applyIfCurrent(
            mutationFence = mutationFence,
            current = {
                RedundantPhysicalNetworkCallbackState(
                    7,
                    "start-a",
                    pendingStop = false,
                    tombstoneUnreadable = false,
                    retainedOwnerCleanupPending = true,
                )
            },
        ) { mutations += 1 })
        assertTrue(callback.applyIfCurrent(
            mutationFence = mutationFence,
            current = {
                RedundantPhysicalNetworkCallbackState(7, "start-a", false, false)
            },
        ) { mutations += 1 })
        mutationFence.cancel("start-a")
        assertFalse(callback.applyIfCurrent(
            mutationFence = mutationFence,
            current = {
                RedundantPhysicalNetworkCallbackState(7, "start-a", false, false)
            },
        ) { mutations += 1 })

        assertEquals(1, mutations)
    }

    @Test
    fun physicalNetworkCallbackReadsReplacementIdentityInsideSerializedFence() {
        val mutationFence = RedundantOperationMutationFence()
        val callback = RedundantPhysicalNetworkCallbackIdentity(7, "start-a")
        val gateEntered = CountDownLatch(1)
        val releaseGate = CountDownLatch(1)
        val blocker = Thread {
            mutationFence.runSerializedIfActive(null) {
                gateEntered.countDown()
                check(releaseGate.await(2, TimeUnit.SECONDS))
                true
            }
        }.apply { start() }
        assertTrue(gateEntered.await(2, TimeUnit.SECONDS))
        val currentGeneration = AtomicLong(7)
        val installedOwner = AtomicReference<String?>("start-a")
        val callbackStarted = CountDownLatch(1)
        val callbackResult = AtomicReference<Boolean>()
        val mutations = AtomicInteger(0)
        val delayed = Thread {
            callbackStarted.countDown()
            callbackResult.set(callback.applyIfCurrent(
                mutationFence = mutationFence,
                current = {
                    RedundantPhysicalNetworkCallbackState(
                        currentGeneration.get(),
                        installedOwner.get(),
                        pendingStop = false,
                        tombstoneUnreadable = false,
                    )
                },
            ) { mutations.incrementAndGet() })
        }.apply { start() }
        assertTrue(callbackStarted.await(2, TimeUnit.SECONDS))

        currentGeneration.set(8)
        installedOwner.set("start-b")
        releaseGate.countDown()
        blocker.join(2_000L)
        delayed.join(2_000L)

        assertFalse(blocker.isAlive)
        assertFalse(delayed.isAlive)
        assertEquals(false, callbackResult.get())
        assertEquals(0, mutations.get())
    }

    @Test
    fun failedCancelTombstoneWriteCannotBeAcknowledgedAcrossProcessRecreation() {
        val backend = ServiceCancelTombstoneBackend().apply { writeSucceeds = false }
        val first = RedundantCancelTombstoneStore(backend) { "stop-operation-a" }

        val persisted = first.persist("start-operation-a")
        val recreated = RedundantCancelTombstoneStore(backend)

        assertEquals(
            RecoveryStoreResult.Failure("redundant_cancel_tombstone_conflict"),
            persisted,
        )
        assertEquals(RecoveryStoreResult.Success(null), recreated.read())
        assertFalse(shouldAcknowledgeRedundantQuickStop(tombstonePersisted = false))
        assertTrue(shouldAcknowledgeRedundantQuickStop(tombstonePersisted = true))
    }

    @Test
    fun connectionIntentCallbacksCannotPublishStateDuringRedundantOwnershipOrCleanup() {
        assertFalse(shouldApplyConnectionIntentStep(
            pendingStop = true,
            tombstoneUnreadable = false,
            envelope = serviceV1Envelope(),
        ))
        assertFalse(shouldApplyConnectionIntentStep(
            pendingStop = false,
            tombstoneUnreadable = false,
            envelope = serviceV2Envelope(),
        ))
        assertFalse(shouldApplyConnectionIntentStep(
            pendingStop = false,
            tombstoneUnreadable = false,
            envelope = null,
        ))
        assertFalse(shouldApplyConnectionIntentStep(
            pendingStop = false,
            tombstoneUnreadable = false,
            envelope = serviceV1Envelope(),
            stopLookupPending = true,
        ))
        assertFalse(shouldApplyConnectionIntentStep(
            pendingStop = false,
            tombstoneUnreadable = false,
            envelope = serviceV1Envelope(),
            retainedOwnerCleanupPending = true,
        ))
        assertTrue(shouldApplyConnectionIntentStep(
            pendingStop = false,
            tombstoneUnreadable = false,
            envelope = serviceV1Envelope(),
        ))
    }

    @Test
    fun installedRedundantOwnerAndItsIdentityChangeAsOneSnapshot() {
        val slot = RedundantVpnOwnerSlot()
        val owner = ServiceRedundantOwner()

        assertNull(slot.snapshot())
        assertNull(slot.install(owner, "start-a"))
        assertEquals(InstalledRedundantVpnOwner(owner, "start-a"), slot.snapshot())
        assertNull(slot.removeIf("start-b"))
        assertEquals(InstalledRedundantVpnOwner(owner, "start-a"), slot.snapshot())
        assertEquals(
            InstalledRedundantVpnOwner(owner, "start-a"),
            slot.removeIf("start-a"),
        )
        assertNull(slot.snapshot())
    }

    @Test
    fun failedAuxiliarySetupClosesBothSidesOfOwnerReplacement() {
        val slot = RedundantVpnOwnerSlot()
        val previous = ServiceRedundantOwner()
        val replacement = ServiceRedundantOwner()
        val cleanup = RetainedRedundantOwnerCleanup()
        slot.install(previous, "start-a")
        var failure: Throwable? = null

        try {
            installRedundantVpnOwnerSafely(
                mutationFence = RedundantOperationMutationFence(),
                slot = slot,
                owner = replacement,
                startOperationId = "start-b",
                closeOwner = cleanup::closeOrRetain,
            ) {
                throw IllegalStateException("monitor_failed")
            }
        } catch (error: Throwable) {
            failure = error
        }

        assertEquals("monitor_failed", failure?.message)
        assertEquals(1, previous.closeCalls)
        assertEquals(1, replacement.closeCalls)
        assertNull(slot.snapshot())
    }

    @Test
    fun failedOwnerCloseIsRetainedUntilARetrySucceeds() {
        val owner = ServiceRedundantOwner(closeResults = ArrayDeque(listOf(false, true)))
        val cleanup = RetainedRedundantOwnerCleanup()

        assertFalse(cleanup.closeOrRetain(owner))
        assertTrue(cleanup.hasPending())
        assertEquals(1, owner.closeCalls)

        assertFalse(cleanup.retry())
        assertFalse(cleanup.hasPending())
        assertEquals(2, owner.closeCalls)
    }

    @Test
    fun ownerReplacementWaitsUntilFailedPreviousCloseCompletes() {
        val slot = RedundantVpnOwnerSlot()
        val previous = ServiceRedundantOwner(closeResults = ArrayDeque(listOf(false, true)))
        val replacement = ServiceRedundantOwner()
        val cleanup = RetainedRedundantOwnerCleanup()
        slot.install(previous, "start-a")

        assertFalse(
            installRedundantVpnOwnerSafely(
                mutationFence = RedundantOperationMutationFence(),
                slot = slot,
                owner = replacement,
                startOperationId = "start-b",
                closeOwner = cleanup::closeOrRetain,
                initializeAuxiliaryState = {},
            ),
        )

        assertTrue(cleanup.hasPending())
        assertNull(slot.snapshot())
        assertEquals(1, replacement.closeCalls)
        assertFalse(cleanup.retry())
        assertEquals(2, previous.closeCalls)
    }

    @Test
    fun rejectedOwnerInstallRetainsCandidateUntilItCloses() {
        val operationId = "start-a"
        val fence = RedundantOperationMutationFence().apply { cancel(operationId) }
        val slot = RedundantVpnOwnerSlot()
        val candidate = ServiceRedundantOwner(
            closeResults = ArrayDeque(listOf(false, true)),
        )
        val cleanup = RetainedRedundantOwnerCleanup()

        assertFalse(
            installRedundantVpnOwnerSafely(
                mutationFence = fence,
                slot = slot,
                owner = candidate,
                startOperationId = operationId,
                closeOwner = cleanup::closeOrRetain,
                initializeAuxiliaryState = {},
            ),
        )

        assertNull(slot.snapshot())
        assertEquals(1, candidate.closeCalls)
        assertTrue(cleanup.hasPending())
        assertFalse(cleanup.retry())
        assertEquals(2, candidate.closeCalls)
    }

    @Test
    fun durableOnlyStopUsesCleanupOwnerWithoutInstallingIt() {
        val transaction = requireNotNull(serviceV2Envelope().redundantTransaction)
        val slot = RedundantVpnOwnerSlot()
        val cleanup = RetainedRedundantOwnerCleanup()
        val cleanupOwner = ServiceRedundantOwner()
        var creations = 0
        var deferredStops = 0

        val result = runRedundantStopCleanupAttempt(
            transaction = transaction,
            owner = null,
            createCleanupOwner = {
                creations += 1
                cleanupOwner
            },
            deferStop = {
                deferredStops += 1
                true
            },
            closeTemporaryOwner = cleanup::closeOrRetain,
        )

        assertEquals(RedundantRevokeResult(fenced = true, stopped = true), result)
        assertEquals(1, creations)
        assertEquals(1, deferredStops)
        assertEquals(1, cleanupOwner.revokeCalls)
        assertEquals(1, cleanupOwner.closeCalls)
        assertNull(slot.snapshot())
        assertFalse(cleanup.hasPending())
    }

    @Test
    fun throwingOwnerCloseIsRetainedWithoutDuplicatingTheOwner() {
        val owner = ServiceRedundantOwner(
            closeResults = ArrayDeque(listOf(null, true)),
        )
        val cleanup = RetainedRedundantOwnerCleanup()

        assertFalse(cleanup.closeOrRetain(owner))
        assertFalse(cleanup.closeOrRetain(owner))
        assertTrue(cleanup.hasPending())

        assertFalse(cleanup.retry())
        assertFalse(cleanup.hasPending())
        assertEquals(2, owner.closeCalls)
    }

    @Test
    fun tombstoneClearRaceAcknowledgesPeerClearButDoesNotStealNewGeneration() {
        val expected = RedundantCancelTombstone("start-a", "stop-a")
        val replacement = RedundantCancelTombstone("start-b", "stop-b")

        assertEquals(
            RedundantTombstoneClearDisposition.CONFIRMED,
            redundantTombstoneClearDisposition(
                cleared = false,
                durable = RecoveryStoreResult.Success(null),
                ownerServiceGeneration = 7,
                currentServiceGeneration = 7,
                expected = expected,
            ),
        )
        assertEquals(
            RedundantTombstoneClearDisposition.REPLAY_SUPERSEDING,
            redundantTombstoneClearDisposition(
                cleared = false,
                durable = RecoveryStoreResult.Success(replacement),
                ownerServiceGeneration = 7,
                currentServiceGeneration = 7,
                expected = expected,
            ),
        )
        assertEquals(
            RedundantTombstoneClearDisposition.STALE,
            redundantTombstoneClearDisposition(
                cleared = false,
                durable = RecoveryStoreResult.Success(replacement),
                ownerServiceGeneration = 7,
                currentServiceGeneration = 8,
                expected = expected,
            ),
        )
        assertEquals(
            RedundantTombstoneClearDisposition.RETRY,
            redundantTombstoneClearDisposition(
                cleared = false,
                durable = RecoveryStoreResult.Success(expected),
                ownerServiceGeneration = 7,
                currentServiceGeneration = 7,
                expected = expected,
            ),
        )
    }

    @Test
    fun emptyTombstoneReadResumesDurableWorkAfterBarrier() {
        val events = mutableListOf<String>()

        handleRedundantTombstoneRead(
            restored = RecoveryStoreResult.Success(null),
            ownerServiceGeneration = 7,
            currentServiceGeneration = 7,
            serviceDestroyed = false,
            install = { events += "install" },
            retry = { events += "retry" },
            resumeDurableWork = { events += "resume" },
            completeAfterDestroy = { events += "destroyed" },
        )

        assertEquals(listOf("resume"), events)
    }

    @Test
    fun staleTombstoneReadDoesNotResumeDurableWork() {
        val events = mutableListOf<String>()

        handleRedundantTombstoneRead(
            restored = RecoveryStoreResult.Success(null),
            ownerServiceGeneration = 7,
            currentServiceGeneration = 8,
            serviceDestroyed = false,
            install = { events += "install" },
            retry = { events += "retry" },
            resumeDurableWork = { events += "resume" },
            completeAfterDestroy = { events += "destroyed" },
        )

        assertTrue(events.isEmpty())
    }

    @Test
    fun destroyedServiceCompletesEmptyTombstoneReadWithoutResumingWork() {
        val events = mutableListOf<String>()

        handleRedundantTombstoneRead(
            restored = RecoveryStoreResult.Success(null),
            ownerServiceGeneration = 7,
            currentServiceGeneration = 7,
            serviceDestroyed = true,
            install = { events += "install" },
            retry = { events += "retry" },
            resumeDurableWork = { events += "resume" },
            completeAfterDestroy = { events += "destroyed" },
        )

        assertEquals(listOf("destroyed"), events)
    }

    @Test
    fun redundantWorkDispatcherSerializesAndCoalescesTicksAndNetworkSnapshots() {
        val queued = ArrayDeque<Runnable>()
        val dispatcher = RedundantVpnWorkDispatcher(Executor(queued::addLast))
        var ticks = 0
        var resumes = 0
        val networks = mutableListOf<Boolean>()

        assertTrue(dispatcher.tick { ticks += 1 })
        assertFalse(dispatcher.tick { ticks += 100 })
        assertTrue(dispatcher.resume { resumes += 1 })
        assertFalse(dispatcher.resume { resumes += 100 })
        assertTrue(dispatcher.network(validated = false, networks::add))
        assertFalse(dispatcher.network(validated = true, networks::add))
        assertEquals(3, queued.size)

        queued.removeFirst().run()
        queued.removeFirst().run()
        queued.removeFirst().run()

        assertEquals(1, ticks)
        assertEquals(1, resumes)
        assertEquals(listOf(true), networks)
        assertTrue(dispatcher.tick { ticks += 1 })
    }

    @Test
    fun redundantCleanupRunsOnlyOnDispatchedWorker() {
        val queued = ArrayDeque<Runnable>()
        val dispatcher = RedundantVpnWorkDispatcher(Executor(queued::addLast))
        val events = mutableListOf<String>()

        dispatchRedundantWork(
            dispatcher = dispatcher,
            fallbackDispatcher = dispatcher,
            action = {
                events += "fence"
                events += "revoke"
            },
            onRejected = {},
        )

        assertTrue(events.isEmpty())
        assertEquals(1, queued.size)

        queued.removeFirst().run()

        assertEquals(listOf("fence", "revoke"), events)
    }

    @Test
    fun redundantCleanupReportsWhenBothDispatchersReject() {
        val rejected = RedundantVpnWorkDispatcher(Executor {
            throw RejectedExecutionException("destroyed")
        })
        var actionCalls = 0
        var rejectedCalls = 0

        dispatchRedundantWork(
            dispatcher = rejected,
            fallbackDispatcher = rejected,
            action = { actionCalls += 1 },
            onRejected = { rejectedCalls += 1 },
        )

        assertEquals(0, actionCalls)
        assertEquals(1, rejectedCalls)
    }

    @Test
    fun oneLogicalRedundantSessionEstablishesAndroidTunExactlyOnce() {
        var establishCalls = 0
        val backend = FakeRedundantSessionBackend()

        val session = startRedundantVpnSession(
            establishTun = {
                establishCalls += 1
                41
            },
            backend = backend,
            primaryConfiguration = "primary-secret".toByteArray(),
            standbyConfiguration = "standby-secret".toByteArray(),
        )

        assertEquals(7L, session?.handle)
        assertEquals(1, establishCalls)
        assertEquals(listOf(41), backend.startedTunFds)
        assertEquals(listOf(1), backend.startedSlots)
    }

    @Test
    fun redundantNetworkChangeRoutesToV2OwnerWithoutLegacyRebind() {
        val owner = ServiceRedundantOwner()
        var legacyCalls = 0

        assertTrue(routeVpnProcessNetworkChange(
            RecoveryStoreResult.Success(serviceV2Envelope()),
            owner,
            validated = true,
        ) { legacyCalls += 1 })
        assertEquals(listOf(true), owner.validatedNetworks)
        assertEquals(0, legacyCalls)

        assertTrue(routeVpnProcessNetworkChange(
            RecoveryStoreResult.Success(serviceV1Envelope()),
            owner,
            validated = true,
        ) { legacyCalls += 1 })
        assertEquals(1, legacyCalls)
    }

    @Test
    fun unreadableRecoveryRecordFailsClosedForNetworkChange() {
        val owner = ServiceRedundantOwner()
        var legacyCalls = 0

        assertFalse(routeVpnProcessNetworkChange(
            RecoveryStoreResult.Failure("recovery_record_corrupt"),
            owner,
            validated = true,
        ) { legacyCalls += 1 })
        assertTrue(owner.validatedNetworks.isEmpty())
        assertEquals(0, legacyCalls)
    }

    @Test
    fun retryNotificationDoesNotClaimThatTheWorkingNetworkIsUnavailable() {
        val content = connectionIntentRetryNotificationContent()

        assertFalse(content.contains("недоступна", ignoreCase = true))
        assertTrue(content.contains("автоматически"))
    }

    @Test
    fun queuedStartInvalidatedBeforeExecutionDoesNotRefreshOrPersist() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val coordinator = coordinator(store)
        val dispatch = AndroidConnectionIntentDispatchState()
        val ticket = dispatch.start(store.load().intent.generation)
        var validations = 0

        dispatch.invalidate()
        coordinator.cancel()
        val result = coordinator.beginDispatched(
            template = template(),
            validateNewIntent = { validations += 1 },
            expectedGeneration = ticket.expectedGeneration,
            canCommitNewIntent = { dispatch.isCurrent(ticket) },
        )

        assertEquals(
            AndroidCoordinatorResult.Failure("connection_intent_generation_conflict"),
            result,
        )
        assertEquals(0, validations)
        assertFalse(store.load().intent.desiredActive)
        assertEquals(null, store.load().leaseTransaction)
    }

    @Test
    fun capabilityTransportFailureLeavesNoDurableIntentEpisodeOrOperationId() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val operationIds = AtomicInteger(0)
        val coordinator = AndroidConnectionIntentCoordinator(
            store,
            operationId = {
                operationIds.incrementAndGet()
                "11111111-1111-4111-8111-111111111112"
            },
        )
        var validations = 0

        val result = coordinator.begin(template()) {
            validations += 1
            throw BackgroundConnectionException("background_transport_unavailable")
        }
        val durable = store.load()

        assertEquals(
            AndroidCoordinatorResult.Failure("background_transport_unavailable"),
            result,
        )
        assertEquals(1, validations)
        assertEquals(0, operationIds.get())
        assertEquals(0L, durable.intent.generation)
        assertEquals(0L, durable.intent.diagnosticsEpisodeId)
        assertFalse(durable.intent.desiredActive)
        assertNull(durable.leaseTransaction)
    }

    @Test
    fun bindingPreflightLostResponseResumesAfterProcessRestartBeforeExactlyOnePanelStart() {
        val backend = ServiceRecoveryBackend()
        val firstStore = recoveryStore(backend)
        val first = coordinator(firstStore)
        val selected = template().copy(
            layer = "tic",
            ticConnectionMode = "dynamic",
            routeMode = "via_tak",
            syncBindingPreferences = true,
        )
        val accepted = first.begin(selected)
        val operationId = firstStore.load().leaseTransaction?.startOperationId
        val firstPanel = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            bindingSyncResults += Result.failure(
                BackgroundConnectionException("background_transport_unavailable"),
            )
        }
        val lost = first.runOnce(firstPanel, ServiceRuntimeFake()) { }

        assertTrue(accepted is AndroidCoordinatorResult.Accepted)
        assertEquals(AndroidCoordinatorStep.RETRY, lost)
        assertEquals(1, firstPanel.bindingSyncTemplates.size)
        assertTrue(firstStore.load().intent.retry.pendingAction == null)

        val restored = coordinator(recoveryStore(backend))
        val events = mutableListOf<String>()
        val panel = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            bindingSyncResults += Result.success(Unit)
            startResults += Result.success(startResult("lease-after-binding-sync"))
            onReconcile = { events += "reconcile" }
            onBindingSync = { events += "sync_binding" }
            onStart = { events += "start" }
        }
        val runtime = ServiceRuntimeFake()
        val resumed = restored.runOnce(panel, runtime) { }

        assertEquals(AndroidCoordinatorStep.ACTIVE, resumed)
        assertEquals(1, panel.bindingSyncTemplates.size)
        assertTrue(panel.bindingSyncTemplates.single().syncBindingPreferences)
        assertEquals(listOf(operationId), panel.startOperationIds)
        assertEquals(1, runtime.startCalls)
        assertEquals(listOf("reconcile", "sync_binding", "start"), events)
    }

    @Test
    fun stopBeforeBindingPreflightCompletesNeverCallsPanelStart() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val coordinator = coordinator(store)
        coordinator.begin(template().copy(syncBindingPreferences = true))
        coordinator.cancelCurrent()
        val panel = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
        }
        var preflightCalls = 0

        val step = coordinator.runOnce(panel, ServiceRuntimeFake()) {
            preflightCalls += 1
        }

        assertEquals(AndroidCoordinatorStep.IDLE, step)
        assertEquals(0, preflightCalls)
        assertTrue(panel.startOperationIds.isEmpty())
    }

    @Test
    fun stopWhileBindingPreflightCompletesIsFencedBeforePanelStart() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val coordinator = coordinator(store)
        coordinator.begin(template().copy(syncBindingPreferences = true))
        val panel = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            bindingSyncResults += Result.success(Unit)
            onBindingSync = { coordinator.cancelCurrent() }
        }
        val runtime = ServiceRuntimeFake()

        val step = coordinator.runOnce(panel, runtime) { }

        assertEquals(AndroidCoordinatorStep.IDLE, step)
        assertEquals(1, panel.bindingSyncTemplates.size)
        assertTrue(panel.startOperationIds.isEmpty())
        assertEquals(0, runtime.startCalls)
        assertFalse(store.load().intent.desiredActive)
    }

    @Test
    fun reconciledAppliedStartUsesExactReplayWithoutMutatingBindingAgain() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val coordinator = coordinator(store)
        coordinator.begin(template().copy(syncBindingPreferences = true))
        val panel = ServicePanelFake().apply {
            reconcileResults += reconcile(
                "applied",
                leaseId = "lease-from-lost-start-response",
            )
            startResults += Result.success(startResult("lease-from-lost-start-response"))
        }
        val runtime = ServiceRuntimeFake()

        val step = coordinator.runOnce(panel, runtime) { }

        assertEquals(AndroidCoordinatorStep.ACTIVE, step)
        assertTrue(panel.bindingSyncTemplates.isEmpty())
        assertEquals(1, panel.startOperationIds.size)
        assertEquals(1, runtime.startCalls)
    }

    @Test
    fun firstStartWaitsForCredentialProvisionWithoutPublishingRecoveryState() {
        val credentialStore = BackgroundCredentialStore(ServiceRecoveryBackend())
        credentialStore.reserveProvision(
            expectedRevision = 0,
            provision = BackgroundCredentialProvisionReservation(
                deviceId = "11111111-1111-4111-8111-111111111111",
                panelBase = "https://panel.example.test/",
                installSecret = "install-secret-value",
                installGeneration = 1,
                capability = BackgroundCapabilitySnapshot(1, true, 2_000_000_000),
            ),
            mutationId = "11111111-1111-4111-8111-111111111191",
            activationOperationId = "11111111-1111-4111-8111-111111111192",
            expiresAtUnix = 1_600,
            nowUnix = 1_000,
        ).credentialSuccess()
        val recoveryStore = recoveryStore(ServiceRecoveryBackend())
        val coordinator = AndroidConnectionIntentCoordinator(
            recoveryStore,
            operationId = SequenceOperationIds(),
            nowUnix = { 1_000 },
        )
        val panel = ServicePanelFake()

        val result = coordinator.begin(template()) { selected ->
            refreshAndValidateNewIntentCapability(
                store = credentialStore,
                template = selected,
                nowUnix = 1_000,
                fetch = { error("pending provision has no active credential") },
            )
        }

        assertEquals(
            AndroidCoordinatorResult.Failure("background_credential_provision_pending"),
            result,
        )
        val pending = recoveryStore.load()
        assertFalse(pending.intent.desiredActive)
        assertEquals(0L, pending.intent.generation)
        assertNull(pending.leaseTransaction)
        assertTrue(panel.startOperationIds.isEmpty())
    }

    @Test
    fun completedCredentialProvisionClearsOnlyItsReadinessBackoffAndWakesTheFirstStart() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val coordinator = AndroidConnectionIntentCoordinator(
            store,
            operationId = SequenceOperationIds(),
            nowUnix = { 1_000 },
        )
        store.beginStart(
            0,
            template(),
            AndroidStartReplay(
                "11111111-1111-4111-8111-111111111112",
                1,
                androidConnectionIntentFingerprint(template(), true),
            ),
        ).successEnvelope()
        store.recordFailure(
            expectedGeneration = 1,
            errorCode = "background_credential_provision_pending",
            nextRetryAtUnix = 1_002,
            pendingAction = "validate_capability",
        ).successEnvelope()
        assertEquals(1_002L, store.load().intent.retry.nextRetryAtUnix)

        val ready = coordinator.credentialProvisioningCompleted()

        assertTrue(ready is AndroidCoordinatorResult.Accepted)
        val unblocked = store.load()
        assertEquals(null, unblocked.intent.retry.nextRetryAtUnix)
        assertEquals(null, unblocked.intent.retry.lastErrorCode)
        assertEquals("validate_capability", unblocked.intent.retry.pendingAction)
        val panel = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.success(startResult("lease-ready"))
        }
        assertEquals(
            AndroidCoordinatorStep.ACTIVE,
            coordinator.runOnce(panel, ServiceRuntimeFake()) {
                error("an already durable operation must not be capability-gated")
            },
        )
    }

    @Test
    fun authoritativeCapabilityDowngradeRejectsBeforePanelOrRecoveryPersistence() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val coordinator = coordinator(store)
        val panel = ServicePanelFake()

        val result = coordinator.begin(template()) {
            throw BackgroundConnectionException("background_credential_capability_unavailable")
        }

        assertEquals(
            AndroidCoordinatorResult.Failure("background_credential_capability_unavailable"),
            result,
        )
        assertFalse(store.load().intent.desiredActive)
        assertEquals(0L, store.load().intent.generation)
        assertNull(store.load().leaseTransaction)
        assertTrue(panel.cancelIfAbsent.isEmpty())
        assertTrue(panel.startOperationIds.isEmpty())
    }

    @Test
    fun newQuickOnUsesLegacyExactlyOnceForAuthoritativeDisabledExpiredOrAbsentCapability() {
        val outcomes = listOf<(BackgroundCredential) -> BackgroundCapabilitySnapshot>(
            { BackgroundCapabilitySnapshot(2, enabled = false, expiresAtUnix = 2_000) },
            { BackgroundCapabilitySnapshot(2, enabled = true, expiresAtUnix = 1_000) },
            { throw BackgroundConnectionException("recovery_contract_unsupported") },
        )

        outcomes.forEach { fetch ->
            val credentials = configuredCredentialStore()
            val recovery = recoveryStore(ServiceRecoveryBackend())
            val coordinator = coordinator(recovery)
            val dispatch = AndroidConnectionIntentDispatchState()
            val selected = coordinator.quickToggle(dispatch).quickDispatch()
                as AndroidQuickToggleDispatch.Start
            var recoveryStarts = 0
            var legacyStarts = 0

            val result = executeDispatchedQuickStart(
                dispatch = dispatch,
                start = selected,
                selectPolicy = {
                    selectQuickStartPolicy(
                        store = credentials,
                        template = template(),
                        nowUnix = 1_000,
                        fetch = fetch,
                    )
                },
                recoveryStart = {
                    recoveryStarts += 1
                    coordinator.beginDispatched(
                        template(),
                        selected.ticket.expectedGeneration,
                        { dispatch.isCurrent(selected.ticket) },
                    )
                },
                legacyStart = { legacyStarts += 1 },
            )

            assertEquals(AndroidQuickStartExecution.LegacyStarted, result)
            assertEquals(0, recoveryStarts)
            assertEquals(1, legacyStarts)
            assertEquals(0L, recovery.load().intent.generation)
            assertEquals(0L, recovery.load().intent.diagnosticsEpisodeId)
            assertNull(recovery.load().leaseTransaction)
        }
    }

    @Test
    fun freshEnabledQuickCapabilitySelectsOnlyTheRecoveryService() {
        val credentials = configuredCredentialStore()
        val recovery = recoveryStore(ServiceRecoveryBackend())
        val coordinator = coordinator(recovery)
        val dispatch = AndroidConnectionIntentDispatchState()
        val selected = coordinator.quickToggle(dispatch).quickDispatch()
            as AndroidQuickToggleDispatch.Start
        var recoveryStarts = 0
        var legacyStarts = 0

        val result = executeDispatchedQuickStart(
            dispatch = dispatch,
            start = selected,
            selectPolicy = {
                selectQuickStartPolicy(
                    store = credentials,
                    template = template(),
                    nowUnix = 1_000,
                    fetch = {
                        BackgroundCapabilitySnapshot(2, enabled = true, expiresAtUnix = 2_000)
                    },
                )
            },
            recoveryStart = {
                recoveryStarts += 1
                coordinator.beginDispatched(
                    template(),
                    selected.ticket.expectedGeneration,
                    { dispatch.isCurrent(selected.ticket) },
                )
            },
            legacyStart = { legacyStarts += 1 },
        )

        assertTrue(result is AndroidQuickStartExecution.RecoveryAccepted)
        assertEquals(1, recoveryStarts)
        assertEquals(0, legacyStarts)
        assertEquals(LeasePhase.START_PENDING, recovery.load().leaseTransaction?.phase)
    }

    @Test
    fun quickOffRoutesARedundantSnapshotToItsDurableStopOperation() {
        val recovery = recoveryStore(ServiceRecoveryBackend())
        recovery.beginRedundant(requireNotNull(serviceV2Envelope().redundantTransaction))
            .successEnvelope()
        val selected = coordinator(recovery).quickToggle(AndroidConnectionIntentDispatchState())
            .quickDispatch()

        assertTrue(selected is AndroidQuickToggleDispatch.RedundantStop)
        assertEquals(
            "start-operation",
            (selected as AndroidQuickToggleDispatch.RedundantStop).startOperationId,
        )
    }

    @Test
    fun quickToggleReplaysADisarmedRedundantTransactionInsteadOfStartingANewTunnel() {
        val recovery = recoveryStore(ServiceRecoveryBackend())
        val transaction = requireNotNull(serviceV2Envelope().redundantTransaction).copy(
            desiredActive = false,
            stopOperationId = "stop-operation",
            retry = AndroidRedundantRetryState(stopState = RedundantStopState.PENDING),
        )
        recovery.beginRedundant(transaction).successEnvelope()

        val selected = coordinator(recovery).quickToggle(AndroidConnectionIntentDispatchState())
            .quickDispatch()

        assertTrue(selected is AndroidQuickToggleDispatch.RedundantStop)
        assertEquals(
            transaction.startOperationId,
            (selected as AndroidQuickToggleDispatch.RedundantStop).startOperationId,
        )
    }

    @Test
    fun acceptedRedundantStopImmediatelyProjectsStoppingWithoutRecoveryMutation() {
        val before = serviceV2Envelope()

        val status = redundantStoppingConnectionIntentStatus(before)

        assertEquals(before.intent.generation, status.generation)
        assertFalse(status.desiredActive)
        assertEquals("stopping", status.status)
        assertEquals(serviceV2Envelope(), before)
    }

    @Test
    fun durableQuickReplayRemainsServiceOwnedAfterCapabilityDowngrade() {
        val recovery = recoveryStore(ServiceRecoveryBackend())
        val coordinator = coordinator(recovery)
        coordinator.begin(template())
        coordinator.cancelCurrent()
        val dispatch = AndroidConnectionIntentDispatchState()
        val selected = coordinator.quickToggle(dispatch).quickDispatch()
            as AndroidQuickToggleDispatch.Start
        var policyChecks = 0
        var recoveryStarts = 0
        var legacyStarts = 0

        val result = executeDispatchedQuickStart(
            dispatch = dispatch,
            start = selected,
            selectPolicy = {
                policyChecks += 1
                AndroidQuickStartPolicy.LEGACY
            },
            recoveryStart = {
                recoveryStarts += 1
                AndroidCoordinatorResult.Accepted(recovery.load())
            },
            legacyStart = { legacyStarts += 1 },
        )

        assertTrue(selected.recoveryOwned)
        assertTrue(result is AndroidQuickStartExecution.RecoveryAccepted)
        assertEquals(0, policyChecks)
        assertEquals(1, recoveryStarts)
        assertEquals(0, legacyStarts)
    }

    @Test
    fun quickCapabilityTransportFailureDoesNotFallBackOrCreateRecoveryState() {
        val credentials = configuredCredentialStore()
        val recovery = recoveryStore(ServiceRecoveryBackend())
        val coordinator = coordinator(recovery)
        val dispatch = AndroidConnectionIntentDispatchState()
        val selected = coordinator.quickToggle(dispatch).quickDispatch()
            as AndroidQuickToggleDispatch.Start
        var recoveryStarts = 0
        var legacyStarts = 0

        val result = executeDispatchedQuickStart(
            dispatch = dispatch,
            start = selected,
            selectPolicy = {
                selectQuickStartPolicy(
                    store = credentials,
                    template = template(),
                    nowUnix = 1_000,
                    fetch = {
                        throw BackgroundConnectionException("background_transport_unavailable")
                    },
                )
            },
            recoveryStart = {
                recoveryStarts += 1
                error("transport failure must not start recovery")
            },
            legacyStart = { legacyStarts += 1 },
        )

        assertEquals(
            AndroidQuickStartExecution.Failure("background_transport_unavailable"),
            result,
        )
        assertEquals(0, recoveryStarts)
        assertEquals(0, legacyStarts)
        assertEquals(0L, recovery.load().intent.generation)
        assertNull(recovery.load().leaseTransaction)
    }

    @Test
    fun quickOffDuringBlockedCapabilitySelectionPreventsRecoveryAndLegacyStart() {
        val dispatch = AndroidConnectionIntentDispatchState()
        val selected = dispatch.toggle(
            expectedGeneration = 0,
            durableDesiredActive = false,
        ) as AndroidQuickToggleDispatch.Start
        val validationEntered = CountDownLatch(1)
        val releaseValidation = CountDownLatch(1)
        val result = AtomicReference<AndroidQuickStartExecution>()
        var recoveryStarts = 0
        var legacyStarts = 0
        val start = Thread {
            result.set(executeDispatchedQuickStart(
                dispatch = dispatch,
                start = selected,
                selectPolicy = {
                    validationEntered.countDown()
                    check(releaseValidation.await(2, TimeUnit.SECONDS))
                    AndroidQuickStartPolicy.LEGACY
                },
                recoveryStart = {
                    recoveryStarts += 1
                    error("cancelled recovery must not start")
                },
                legacyStart = { legacyStarts += 1 },
            ))
        }.apply { start() }
        assertTrue(validationEntered.await(2, TimeUnit.SECONDS))

        assertTrue(
            dispatch.toggle(
                expectedGeneration = 0,
                durableDesiredActive = false,
            ) is AndroidQuickToggleDispatch.Stop,
        )
        releaseValidation.countDown()
        start.join(2_000L)

        assertFalse(start.isAlive)
        assertEquals(
            AndroidQuickStartExecution.Failure("connection_intent_generation_conflict"),
            result.get(),
        )
        assertEquals(0, recoveryStarts)
        assertEquals(0, legacyStarts)
    }

    @Test
    fun quickToggleSelectionReadsDesiredStateAndGenerationFromOneEnvelope() {
        val backend = ServiceRecoveryBackend()
        val store = recoveryStore(backend)
        val coordinator = coordinator(store)
        val dispatch = AndroidConnectionIntentDispatchState()
        val readsBefore = backend.readCount

        val selected = coordinator.quickToggle(dispatch)

        val selection =
            (selected as RecoveryStoreResult.Success<AndroidQuickToggleDispatch>).value
        assertTrue(selection is AndroidQuickToggleDispatch.Start)
        assertEquals(readsBefore + 1, backend.readCount)
        val ticket = (selection as AndroidQuickToggleDispatch.Start).ticket
        assertEquals(0L, ticket.expectedGeneration)
    }

    @Test
    fun quickOffStopsLeaseLessLegacyRuntimeAndClearsItsDurableStopMarker() {
        val store = recoveryStore(ServiceRecoveryBackend())
        store.setDesiredActive(0, true).successEnvelope()
        val coordinator = coordinator(store)
        val dispatch = AndroidConnectionIntentDispatchState()
        val selected = coordinator.quickToggle(dispatch).quickDispatch()
        assertTrue(selected is AndroidQuickToggleDispatch.Stop)

        val cancelled = coordinator.cancelCurrentForQuickToggle()
        assertTrue(cancelled is AndroidCoordinatorResult.Accepted)
        assertFalse(store.load().intent.desiredActive)
        assertNull(store.load().leaseTransaction)
        assertEquals("legacy_runtime_stop", store.load().intent.retry.pendingAction)

        var runtimeRunning = true
        var runtimeStops = 0
        val runtime = ServiceConnectionIntentRuntimeBoundary(
            startTransport = { _, _, _, _ -> error("Quick Off must not start a runtime") },
            stopTransport = { onSuccess, _ ->
                runtimeStops += 1
                runtimeRunning = false
                onSuccess(true)
            },
            running = { runtimeRunning },
            timeoutMillis = 100,
        )

        assertEquals(
            AndroidCoordinatorStep.IDLE,
            coordinator.runOnce(ServicePanelFake(), runtime),
        )
        assertEquals(1, runtimeStops)
        assertFalse(runtimeRunning)
        assertFalse(store.load().intent.desiredActive)
        assertNull(store.load().intent.retry.pendingAction)
        assertNull(store.load().leaseTransaction)
    }

    @Test
    fun failedLegacyRuntimeStopRemainsDurableAndRetriesAfterCoordinatorRestart() {
        val backend = ServiceRecoveryBackend()
        val store = recoveryStore(backend)
        store.setDesiredActive(0, true).successEnvelope()
        val first = coordinator(store)
        assertTrue(first.cancelCurrentForQuickToggle() is AndroidCoordinatorResult.Accepted)
        val failedRuntime = ServiceRuntimeFake(
            running = true,
            stopResults = ArrayDeque(listOf(false)),
        )

        assertEquals(
            AndroidCoordinatorStep.RETRY,
            first.runOnce(ServicePanelFake(), failedRuntime),
        )
        assertEquals(1, failedRuntime.stopCalls)
        assertEquals("legacy_runtime_stop", store.load().intent.retry.pendingAction)
        assertTrue(store.load().intent.retry.nextRetryAtUnix != null)

        val restoredStore = recoveryStore(backend)
        val restored = coordinator(restoredStore)
        val recoveredRuntime = ServiceRuntimeFake(running = true)
        assertEquals(
            AndroidCoordinatorStep.IDLE,
            restored.runOnce(ServicePanelFake(), recoveredRuntime),
        )
        assertEquals(1, recoveredRuntime.stopCalls)
        assertNull(restoredStore.load().intent.retry.pendingAction)
        assertNull(restoredStore.load().intent.retry.nextRetryAtUnix)
        assertFalse(restoredStore.load().intent.desiredActive)
        assertNull(restoredStore.load().leaseTransaction)
    }

    @Test
    fun leaseLessQuickOffQueuesRealRuntimeStopBehindAnInProgressLegacyStart() {
        val gate = TunnelStateGate()
        assertEquals(TransitionDecision.PROCEED, gate.beginStart())
        val stopQueued = CountDownLatch(1)
        val releaseStop = CountDownLatch(1)
        val stopped = AtomicReference<Boolean>()
        val runtime = ServiceConnectionIntentRuntimeBoundary(
            startTransport = { _, _, _, _ -> error("Quick Off must not start a runtime") },
            stopTransport = { onSuccess, onError ->
                when (gate.beginStop()) {
                    TransitionDecision.PROCEED -> Thread {
                        stopQueued.countDown()
                        check(releaseStop.await(2, TimeUnit.SECONDS))
                        gate.complete(SessionState.STOPPED)
                        onSuccess(true)
                    }.start()
                    TransitionDecision.ALREADY_COMPLETE -> onSuccess(true)
                    TransitionDecision.BUSY -> onError("tunnel_operation_in_progress")
                    TransitionDecision.REPLACE -> error("invalid Stop transition")
                }
            },
            running = { gate.current() == SessionState.RUNNING },
            timeoutMillis = 2_000,
        )
        val stopThread = Thread { stopped.set(runtime.stop()) }.apply { start() }
        assertTrue(stopQueued.await(2, TimeUnit.SECONDS))
        assertEquals(SessionState.STOPPING, gate.current())

        // A legacy start may report its late success before the queued Stop owns the executor.
        gate.complete(SessionState.RUNNING)
        releaseStop.countDown()
        stopThread.join(2_000L)

        assertFalse(stopThread.isAlive)
        assertEquals(true, stopped.get())
        assertEquals(SessionState.STOPPED, gate.current())
    }

    @Test
    fun quickOffKeepsTrueRecoveryCleanupAndExactOperationIdsServiceOwned() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val coordinator = coordinator(store)
        coordinator.begin(template())
        val pending = requireNotNull(store.load().leaseTransaction)
        store.recordLease(pending.generation, "quick-recovery-lease").successEnvelope()
        store.activateCheckpoint(pending.generation).successEnvelope()
        val dispatch = AndroidConnectionIntentDispatchState()
        assertTrue(
            coordinator.quickToggle(dispatch).quickDispatch() is AndroidQuickToggleDispatch.Stop,
        )

        val cancelled = coordinator.cancelCurrentForQuickToggle()
        assertTrue(cancelled is AndroidCoordinatorResult.Accepted)
        val cancelledEnvelope = store.load()
        assertNull(cancelledEnvelope.intent.retry.pendingAction)
        assertEquals(pending.startOperationId, cancelledEnvelope.leaseTransaction?.startOperationId)
        val panel = ServicePanelFake().apply { stopResults += Result.success(Unit) }
        val runtime = ServiceRuntimeFake(running = true)

        assertEquals(AndroidCoordinatorStep.IDLE, coordinator.runOnce(panel, runtime))
        assertEquals(1, runtime.stopCalls)
        assertEquals(1, panel.stopOperationIds.size)
        assertEquals(1, panel.stopOperationIds.distinct().size)
        assertNull(store.load().leaseTransaction)
        assertFalse(store.load().intent.desiredActive)
    }

    @Test
    fun terminalDowngradeLegacyRetryIsStoppedByQuickOffWithoutRecoveryRestart() {
        val store = recoveryStore(ServiceRecoveryBackend())
        store.beginStart(
            0,
            template(),
            AndroidStartReplay(
                "11111111-1111-4111-8111-111111111112",
                1,
                androidConnectionIntentFingerprint(template(), true),
            ),
        ).successEnvelope()
        store.recordLease(1, "old-terminal-lease").successEnvelope()
        store.activateCheckpoint(1).successEnvelope()
        store.scheduleTerminalAfterCleanup(
            1,
            "old-terminal-lease",
            "11111111-1111-4111-8111-111111111114",
            "operation_id_conflict",
        ).successEnvelope()
        store.completeCleanupAsTerminal(1).successEnvelope()
        val terminalGeneration = store.load().intent.generation
        store.setDesiredActive(terminalGeneration, true).successEnvelope()
        val coordinator = coordinator(store)

        assertTrue(coordinator.cancelCurrentForQuickToggle() is AndroidCoordinatorResult.Accepted)
        assertEquals("legacy_runtime_stop", store.load().intent.retry.pendingAction)
        val runtime = ServiceRuntimeFake(running = true)
        assertEquals(
            AndroidCoordinatorStep.IDLE,
            coordinator.runOnce(ServicePanelFake(), runtime),
        )
        assertEquals(1, runtime.stopCalls)
        assertNull(store.load().leaseTransaction)
        assertFalse(store.load().intent.desiredActive)
    }

    @Test
    fun lateLegacyStartCallbackCannotRearmQuickOffProjection() {
        assertNull(legacyStartCallbackDesiredActive(false, SessionState.RUNNING))
        assertNull(legacyStartCallbackDesiredActive(false, SessionState.STARTING))
        assertEquals(true, legacyStartCallbackDesiredActive(true, SessionState.RUNNING))
        assertEquals(false, legacyStartCallbackDesiredActive(true, SessionState.FAILED))
    }

    @Test
    fun legacyQuickOffSurvivesTheProductionStartCallbackUntilTheQueuedStopCompletes() {
        val store = recoveryStore(ServiceRecoveryBackend())
        QuickDesiredActiveProjection.update(store, true).successIntent()
        val coordinator = coordinator(store)
        var lateSuccess: ((SessionState, Long) -> Unit)? = null
        var lateFailure: ((String) -> Unit)? = null
        var completions = 0
        val service = serviceWithoutAndroidRuntime()

        service.performLegacyBackgroundStart(
            receiver = null,
            boundary = LegacyBackgroundStartServiceBoundary(
                start = { onSuccess, onError ->
                    lateSuccess = onSuccess
                    lateFailure = onError
                },
                runtimeState = { SessionState.RUNNING },
                durableDesiredActive = { store.load().intent.desiredActive },
                complete = { _, _, desiredActive ->
                    completions += 1
                    desiredActive?.let {
                        QuickDesiredActiveProjection.update(store, it).successIntent()
                    }
                },
                status = { connectionIntentServiceStatus(store.load()) },
            ),
        )
        assertTrue(lateSuccess != null && lateFailure != null)

        val dispatch = AndroidConnectionIntentDispatchState()
        assertTrue(coordinator.quickToggle(dispatch).quickDispatch() is AndroidQuickToggleDispatch.Stop)
        assertTrue(coordinator.cancelCurrentForQuickToggle() is AndroidCoordinatorResult.Accepted)
        val cancelled = store.load()
        val cancelledGeneration = cancelled.intent.generation
        assertFalse(cancelled.intent.desiredActive)
        assertEquals("legacy_runtime_stop", cancelled.intent.retry.pendingAction)

        lateSuccess?.invoke(SessionState.RUNNING, 25)

        assertEquals(1, completions)
        val afterLateSuccess = store.load()
        assertFalse(afterLateSuccess.intent.desiredActive)
        assertEquals(cancelledGeneration, afterLateSuccess.intent.generation)
        assertEquals("legacy_runtime_stop", afterLateSuccess.intent.retry.pendingAction)
        assertNull(afterLateSuccess.leaseTransaction)
        assertNull(afterLateSuccess.intent.template)
        assertEquals(0L, afterLateSuccess.intent.diagnosticsEpisodeId)
        assertFalse(shouldRestoreDesiredTunnel(afterLateSuccess.intent.desiredActive, SessionState.STOPPED))

        val runtime = ServiceRuntimeFake(running = true)
        assertEquals(
            AndroidCoordinatorStep.IDLE,
            coordinator.runOnce(ServicePanelFake(), runtime),
        )
        val stopped = store.load()
        assertEquals(1, runtime.stopCalls)
        assertFalse(stopped.intent.desiredActive)
        assertEquals(cancelledGeneration, stopped.intent.generation)
        assertNull(stopped.intent.retry.pendingAction)
        assertNull(stopped.leaseTransaction)
    }

    @Test
    fun lateLegacyQuickFailureCannotAdvanceTheCancelledGenerationOrLoseItsStopMarker() {
        val store = recoveryStore(ServiceRecoveryBackend())
        QuickDesiredActiveProjection.update(store, true).successIntent()
        val coordinator = coordinator(store)
        var lateFailure: ((String) -> Unit)? = null
        var completions = 0
        val service = serviceWithoutAndroidRuntime()

        service.performLegacyBackgroundStart(
            receiver = null,
            boundary = LegacyBackgroundStartServiceBoundary(
                start = { _, onError -> lateFailure = onError },
                runtimeState = { SessionState.FAILED },
                durableDesiredActive = { store.load().intent.desiredActive },
                complete = { _, _, desiredActive ->
                    completions += 1
                    desiredActive?.let {
                        QuickDesiredActiveProjection.update(store, it).successIntent()
                    }
                },
                status = { connectionIntentServiceStatus(store.load()) },
            ),
        )
        assertTrue(lateFailure != null)
        val dispatch = AndroidConnectionIntentDispatchState()
        assertTrue(coordinator.quickToggle(dispatch).quickDispatch() is AndroidQuickToggleDispatch.Stop)
        assertTrue(coordinator.cancelCurrentForQuickToggle() is AndroidCoordinatorResult.Accepted)
        val cancelledGeneration = store.load().intent.generation

        lateFailure?.invoke("connection_start_failed")

        assertEquals(1, completions)
        val afterLateFailure = store.load()
        assertFalse(afterLateFailure.intent.desiredActive)
        assertEquals(cancelledGeneration, afterLateFailure.intent.generation)
        assertEquals("legacy_runtime_stop", afterLateFailure.intent.retry.pendingAction)
    }

    @Test
    fun nonCancelledLegacyQuickSuccessKeepsTheExistingDesiredGenerationArmed() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val armed = QuickDesiredActiveProjection.update(store, true).successIntent()
        var success: ((SessionState, Long) -> Unit)? = null
        var completions = 0
        val service = serviceWithoutAndroidRuntime()

        service.performLegacyBackgroundStart(
            receiver = null,
            boundary = LegacyBackgroundStartServiceBoundary(
                start = { onSuccess, _ -> success = onSuccess },
                runtimeState = { SessionState.RUNNING },
                durableDesiredActive = { store.load().intent.desiredActive },
                complete = { _, _, desiredActive ->
                    completions += 1
                    desiredActive?.let {
                        QuickDesiredActiveProjection.update(store, it).successIntent()
                    }
                },
                status = { connectionIntentServiceStatus(store.load()) },
            ),
        )
        assertTrue(success != null)

        success?.invoke(SessionState.RUNNING, 25)

        assertEquals(1, completions)
        val completed = store.load()
        assertTrue(completed.intent.desiredActive)
        assertEquals(armed.generation, completed.intent.generation)
        assertNull(completed.intent.retry.pendingAction)
        assertNull(completed.leaseTransaction)
        assertNull(completed.intent.template)
        assertEquals(0L, completed.intent.diagnosticsEpisodeId)
    }

    @Test
    fun quickOffKeepsPendingStartProjectedUntilSelectionAfterItsCommit() {
        val backend = ServiceRecoveryBackend()
        val observerStore = recoveryStore(backend)
        val dispatch = AndroidConnectionIntentDispatchState()
        val queuedStart = dispatch.start(observerStore.load().intent.generation)
        val committed = CountDownLatch(1)
        val completion = AtomicReference<Boolean>()
        lateinit var startThread: Thread

        val selected = dispatch.toggleFromSnapshot {
            val beforeCommit = observerStore.read()
            startThread = Thread {
                val result = coordinator(recoveryStore(backend)).begin(template())
                check(result is AndroidCoordinatorResult.Accepted)
                committed.countDown()
                completion.set(dispatch.complete(queuedStart))
            }
            startThread.start()
            check(committed.await(2, TimeUnit.SECONDS))
            beforeCommit
        }

        assertTrue(
            (selected as RecoveryStoreResult.Success<AndroidQuickToggleDispatch>).value is
                AndroidQuickToggleDispatch.Stop,
        )
        startThread.join(2_000)
        assertFalse(completion.get())
        coordinator(observerStore).cancelCurrent()
        assertFalse(observerStore.load().intent.desiredActive)
    }

    @Test
    fun queuedQuickOnThenOffInvalidatesTheStartBeforeItCanRun() {
        val dispatch = AndroidConnectionIntentDispatchState()

        val first = dispatch.toggle(
            expectedGeneration = 0,
            durableDesiredActive = false,
        ) as AndroidQuickToggleDispatch.Start
        val second = dispatch.toggle(
            expectedGeneration = 0,
            durableDesiredActive = false,
        )

        assertEquals(AndroidQuickToggleDispatch.Stop, second)
        assertFalse(dispatch.isCurrent(first.ticket))
        assertFalse(dispatch.complete(first.ticket))
    }

    @Test
    fun completedQueuedStartClearsThePendingDesiredProjection() {
        val dispatch = AndroidConnectionIntentDispatchState()
        val started = dispatch.toggle(
            expectedGeneration = 0,
            durableDesiredActive = false,
        ) as AndroidQuickToggleDispatch.Start

        assertTrue(dispatch.complete(started.ticket))
        assertTrue(
            dispatch.toggle(
                expectedGeneration = 1,
                durableDesiredActive = true,
            ) is AndroidQuickToggleDispatch.Stop,
        )
    }

    @Test
    fun dispatchedBeginDropsAnAcceptedResponseInvalidatedWhileItWasRunning() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val dispatch = AndroidConnectionIntentDispatchState()
        val ticket = dispatch.start(store.load().intent.generation)

        val result = executeDispatchedConnectionIntent(dispatch, ticket) {
            dispatch.invalidate()
            AndroidCoordinatorResult.Accepted(store.load())
        }

        assertEquals(
            AndroidCoordinatorResult.Failure("connection_intent_generation_conflict"),
            result,
        )
    }

    @Test
    fun busyExecutorDoesNotDelayStopTombstoneOrPermitALateRuntimeStart() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val coordinator = coordinator(store)
        coordinator.begin(template())
        val dispatch = AndroidConnectionIntentDispatchState()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val runtime = ServiceRuntimeFake()
        val panel = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.success(startResult("late-busy-lease"))
            onStart = {
                entered.countDown()
                check(release.await(2, TimeUnit.SECONDS))
            }
        }
        val executor = Executors.newSingleThreadExecutor()
        val attempt = executor.submit<AndroidCoordinatorStep> { coordinator.runOnce(panel, runtime) }
        assertTrue(entered.await(2, TimeUnit.SECONDS))

        val cancelled = cancelDispatchedConnectionIntent(dispatch) { coordinator.cancelCurrent() }

        assertTrue(cancelled is AndroidCoordinatorResult.Accepted)
        assertFalse(store.load().intent.desiredActive)
        release.countDown()
        assertEquals(AndroidCoordinatorStep.CLEANUP_REQUIRED, attempt.get(2, TimeUnit.SECONDS))
        assertEquals(0, runtime.startCalls)
        executor.shutdownNow()
    }

    @Test
    fun cancelledRuntimeCallbacksAfterLeaseAcquisitionAlwaysCompensateTheLease() {
        listOf("pre_backend", "backend_up", "post_backend_compensation").forEach { phase ->
            val backend = ServiceRecoveryBackend()
            val store = recoveryStore(backend)
            val coordinator = coordinator(store)
            coordinator.begin(template())
            var runtimeRunning = false
            var localStops = 0
            val runtime = ServiceConnectionIntentRuntimeBoundary(
                startTransport = { result, _, _, onError ->
                    result.configuration.fill(0)
                    if (phase != "pre_backend") runtimeRunning = true
                    coordinator.cancelCurrent()
                    if (phase == "post_backend_compensation") runtimeRunning = false
                    onError("tunnel_start_cancelled")
                },
                stopTransport = { onSuccess, _ ->
                    localStops += 1
                    runtimeRunning = false
                    onSuccess(true)
                },
                running = { runtimeRunning },
                timeoutMillis = 100,
            )
            val panel = ServicePanelFake().apply {
                reconcileResults += reconcile("not_found")
                startResults += Result.success(startResult("lease-$phase"))
                stopResults += Result.success(Unit)
            }

            assertEquals(AndroidCoordinatorStep.IDLE, coordinator.runOnce(panel, runtime))
            assertEquals(listOf("lease-$phase"), panel.stopLeaseIds)
            assertEquals(1, panel.stopOperationIds.distinct().size)
            assertEquals(1, localStops)
            assertEquals(null, store.load().leaseTransaction)
            assertFalse(store.load().intent.desiredActive)
        }
    }

    @Test
    fun cancelledRuntimeCleanupRetainsExactStopAcrossProcessDeathAndRetries() {
        val backend = ServiceRecoveryBackend()
        val firstStore = recoveryStore(backend)
        val first = coordinator(firstStore)
        first.begin(template())
        val cancelledRuntime = ServiceConnectionIntentRuntimeBoundary(
            startTransport = { result, _, _, onError ->
                result.configuration.fill(0)
                first.cancelCurrent()
                onError("tunnel_start_cancelled")
            },
            stopTransport = { onSuccess, _ -> onSuccess(false) },
            running = { false },
            timeoutMillis = 100,
        )
        val startPanel = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.success(startResult("lease-cancelled"))
        }

        assertEquals(AndroidCoordinatorStep.RETRY, first.runOnce(startPanel, cancelledRuntime))
        val pending = recoveryStore(backend).load()
        val stopOperationId = requireNotNull(pending.leaseTransaction?.stopOperationId)
        assertEquals(LeasePhase.CLEANUP_PENDING, pending.leaseTransaction?.phase)
        first.acknowledgeInitialTerminalDiagnostic()

        val failedPanel = ServicePanelFake().apply {
            stopResults += Result.failure(
                BackgroundConnectionException("connection_stop_failed"),
            )
        }
        assertEquals(
            AndroidCoordinatorStep.RETRY,
            coordinator(recoveryStore(backend)).runOnce(failedPanel, ServiceRuntimeFake()),
        )
        assertEquals(listOf(stopOperationId), failedPanel.stopOperationIds)
        assertEquals(
            stopOperationId,
            recoveryStore(backend).load().leaseTransaction?.stopOperationId,
        )

        val successfulPanel = ServicePanelFake().apply { stopResults += Result.success(Unit) }
        assertEquals(
            AndroidCoordinatorStep.IDLE,
            coordinator(recoveryStore(backend)).runOnce(successfulPanel, ServiceRuntimeFake()),
        )
        assertEquals(listOf(stopOperationId), successfulPanel.stopOperationIds)
        assertEquals(null, recoveryStore(backend).load().leaseTransaction)
    }

    @Test
    fun unexpectedRuntimeCancellationSchedulesTerminalCleanupWhileIntentIsStillActive() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val coordinator = coordinator(store)
        coordinator.begin(template())
        val runtime = ServiceConnectionIntentRuntimeBoundary(
            startTransport = { result, _, _, onError ->
                result.configuration.fill(0)
                onError("tunnel_start_cancelled")
            },
            stopTransport = { onSuccess, _ -> onSuccess(true) },
            running = { false },
            timeoutMillis = 100,
        )
        val panel = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.success(startResult("lease-unexpected-cancel"))
        }

        assertEquals(AndroidCoordinatorStep.RETRY, coordinator.runOnce(panel, runtime))
        assertFalse(store.load().intent.desiredActive)
        assertEquals("tunnel_start_cancelled", store.load().intent.retry.lastErrorCode)
        assertEquals(LeasePhase.CLEANUP_PENDING, store.load().leaseTransaction?.phase)
        assertEquals("initial_terminal_report_pending", store.load().intent.retry.pendingAction)
        assertEquals(emptyList<String>(), panel.stopLeaseIds)
    }

    @Test
    fun busyExecutorDoesNotDelayLogoutCredentialAndConnectionTombstones() {
        val connection = coordinator(recoveryStore(ServiceRecoveryBackend()))
        connection.begin(template())
        val credentials = configuredCredentialStore()
        val logout = AndroidLogoutCoordinator(credentials, connection) {
            "11111111-1111-4111-8111-111111111191"
        }
        val dispatch = AndroidConnectionIntentDispatchState()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val executor = Executors.newSingleThreadExecutor()
        executor.execute {
            entered.countDown()
            check(release.await(2, TimeUnit.SECONDS))
        }
        assertTrue(entered.await(2, TimeUnit.SECONDS))

        val result = beginDispatchedLogout(dispatch) { logout.begin() }

        assertTrue(result is AndroidLogoutResult.Accepted)
        assertEquals(
            BackgroundLogoutPhase.PENDING,
            credentials.read().credentialSuccess().logoutState?.phase,
        )
        assertFalse(
            (connection.status() as RecoveryStoreResult.Success).value.intent.desiredActive,
        )
        release.countDown()
        executor.shutdownNow()
    }

    @Test
    fun connectionIntentMutationIsDispatchedOffTheCallingThread() {
        val queued = ArrayDeque<Runnable>()
        val executor = Executor(queued::addLast)
        var mutationRan = false

        dispatchSerializedConnectionIntentMutation(executor) {
            mutationRan = true
        }

        assertFalse(mutationRan)
        assertEquals(1, queued.size)
        queued.removeFirst().run()
        assertTrue(mutationRan)
    }

    @Test
    fun invalidatedConnectionIntentAdmissionNeverBecomesCurrentAgain() {
        val admission = AndroidConnectionIntentAdmission()
        val stale = admission.snapshot()

        assertTrue(admission.isCurrent(stale))
        admission.invalidate()

        assertFalse(admission.isCurrent(stale))
        assertTrue(admission.isCurrent(admission.snapshot()))
    }

    @Test
    fun durableBeginFastLaneCannotBeQueuedBehindRuntimePastTheIpcTimeout() {
        val blockedRuntime = Executors.newSingleThreadExecutor()
        val fastMutation = Executors.newSingleThreadExecutor()
        val releaseRuntime = CountDownLatch(1)
        val committed = CountDownLatch(1)
        blockedRuntime.execute { releaseRuntime.await(35, TimeUnit.SECONDS) }

        dispatchSerializedConnectionIntentMutation(fastMutation) { committed.countDown() }

        assertTrue(committed.await(1, TimeUnit.SECONDS))
        releaseRuntime.countDown()
        blockedRuntime.shutdownNow()
        fastMutation.shutdownNow()
    }

    @Test
    fun initialIntentPersistsStartPendingBeforeTheFirstPanelAttemptAndRetriesTheSameOperation() {
        val backend = ServiceRecoveryBackend()
        val store = recoveryStore(backend)
        val coordinator = coordinator(store)
        val panel = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            reconcileResults += reconcile("not_found")
            startResults += Result.failure(BackgroundConnectionException("background_transport_unavailable"))
            startResults += Result.success(startResult("lease-1"))
        }

        val accepted = coordinator.begin(template())

        assertTrue(accepted is AndroidCoordinatorResult.Accepted)
        assertEquals(LeasePhase.START_PENDING, store.load().leaseTransaction?.phase)
        val operationId = store.load().leaseTransaction!!.startOperationId

        assertEquals(AndroidCoordinatorStep.RETRY, coordinator.runOnce(panel, ServiceRuntimeFake()))
        assertEquals(LeasePhase.START_PENDING, store.load().leaseTransaction?.phase)
        assertEquals(AndroidCoordinatorStep.ACTIVE, coordinator.runOnce(panel, ServiceRuntimeFake()))
        assertEquals(listOf(operationId, operationId), panel.startOperationIds)
        assertEquals(LeasePhase.ACTIVE_CHECKPOINT, store.load().leaseTransaction?.phase)
    }

    @Test
    fun recoveredCallbackClosesOldEpisodeBeforeCheckpointRotationAndCannotBlockSuccess() {
        val backend = ServiceRecoveryBackend()
        val store = recoveryStore(backend)
        val coordinator = coordinator(store)
        val started = (coordinator.begin(template()) as AndroidCoordinatorResult.Accepted).envelope
        val panel = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.success(startResult("lease-1"))
        }
        val recovered = mutableListOf<Long>()

        val step = coordinator.runOnce(
            panel,
            ServiceRuntimeFake(),
            validateNewIntent = {},
            onRecovered = { episodeId ->
                val beforeCheckpoint = store.load()
                assertEquals(LeasePhase.LEASE_ACQUIRED, beforeCheckpoint.leaseTransaction?.phase)
                assertEquals(started.intent.diagnosticsEpisodeId, episodeId)
                assertEquals(episodeId, beforeCheckpoint.intent.diagnosticsEpisodeId)
                recovered += episodeId
                error("diagnostic storage failure must not roll back a successful handshake")
            },
        )

        assertEquals(AndroidCoordinatorStep.ACTIVE, step)
        assertEquals(listOf(started.intent.diagnosticsEpisodeId), recovered)
        val reconstructed = recoveryStore(backend).load()
        assertEquals(LeasePhase.ACTIVE_CHECKPOINT, reconstructed.leaseTransaction?.phase)
        assertEquals(started.intent.diagnosticsEpisodeId + 1, reconstructed.intent.diagnosticsEpisodeId)
        assertEquals(started.intent.generation, reconstructed.intent.generation)
    }

    @Test
    fun processDeathWithUnknownStartReconcilesThenExactReplaysAppliedOperation() {
        val backend = ServiceRecoveryBackend()
        val original = coordinator(recoveryStore(backend))
        original.begin(template())
        val transaction = recoveryStore(backend).load().leaseTransaction!!
        val restored = coordinator(recoveryStore(backend))
        val panel = ServicePanelFake().apply {
            reconcileResults += reconcile("applied", leaseId = "lease-restored")
            startResults += Result.success(startResult("lease-restored"))
        }

        assertEquals(AndroidCoordinatorStep.ACTIVE, restored.runOnce(panel, ServiceRuntimeFake()))

        assertEquals(listOf(transaction.startOperationId), panel.startOperationIds)
        assertEquals(LeasePhase.ACTIVE_CHECKPOINT, recoveryStore(backend).load().leaseTransaction?.phase)
    }

    @Test
    fun stopDuringReconcileRechecksDurableIntentBeforeAnyPanelStart() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val coordinator = coordinator(store)
        coordinator.begin(template())
        var cancelled = false
        val panel = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            reconcileResults += reconcile("not_found")
            startResults += Result.success(startResult("lease-must-not-start"))
            onReconcile = {
                if (!cancelled) {
                    cancelled = true
                    coordinator.cancelCurrent()
                }
            }
        }

        assertEquals(AndroidCoordinatorStep.IDLE, coordinator.runOnce(panel, ServiceRuntimeFake()))
        assertEquals(listOf(false, true), panel.cancelIfAbsent)
        assertTrue(panel.startOperationIds.isEmpty())
        assertFalse(store.load().intent.desiredActive)
        assertNull(store.load().leaseTransaction)
    }

    @Test
    fun authoritativeTerminalOrCancelledUnknownStartClosesOldOperationAndPersistsOneFreshStart() {
        listOf("terminal", "cancelled").forEach { authoritativeState ->
            val backend = ServiceRecoveryBackend()
            val first = coordinator(recoveryStore(backend))
            first.begin(template())
            val oldOperationId = recoveryStore(backend).load().leaseTransaction!!.startOperationId
            val terminal = ServicePanelFake().apply {
                reconcileResults += reconcile(authoritativeState)
            }

            assertEquals(
                AndroidCoordinatorStep.RETRY,
                first.runOnce(terminal, ServiceRuntimeFake()),
            )

            val closedAndRestarted = recoveryStore(backend).load()
            val freshTransaction = requireNotNull(closedAndRestarted.leaseTransaction)
            val freshOperationId = freshTransaction.startOperationId
            assertEquals(LeasePhase.START_PENDING, freshTransaction.phase)
            assertTrue(freshOperationId != oldOperationId)
            assertTrue(closedAndRestarted.intent.desiredActive)
            assertTrue(closedAndRestarted.intent.retry.nextRetryAtUnix != null)
            assertEquals("recovering", connectionIntentServiceStatus(closedAndRestarted).status)

            val restoredPanel = ServicePanelFake().apply {
                reconcileResults += reconcile("not_found")
                startResults += Result.success(startResult("lease-$authoritativeState"))
            }
            assertEquals(
                AndroidCoordinatorStep.ACTIVE,
                coordinator(recoveryStore(backend)).runOnce(restoredPanel, ServiceRuntimeFake()),
            )
            assertEquals(listOf(freshOperationId), restoredPanel.startOperationIds)
        }
    }

    @Test
    fun stopWinsOverLateServiceTimeoutAndCleansAcquiredLeaseWithoutTerminalState() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val coordinator = coordinator(store)
        coordinator.begin(template())
        val pending = requireNotNull(store.load().leaseTransaction)
        store.recordLease(pending.generation, "lease-stop-timeout").successEnvelope()
        val panel = ServicePanelFake().apply {
            startResults += Result.failure(BackgroundConnectionException("service_timeout"))
            onStart = { coordinator.cancelCurrent() }
            stopResults += Result.success(Unit)
        }

        assertEquals(
            AndroidCoordinatorStep.RETRY,
            coordinator.runOnce(panel, ServiceRuntimeFake()),
        )
        assertFalse(store.load().intent.desiredActive)
        assertEquals("service_timeout", store.load().intent.retry.lastErrorCode)
        assertEquals(AndroidCoordinatorStep.IDLE, coordinator.runOnce(panel, ServiceRuntimeFake()))
        assertNull(store.load().leaseTransaction)
    }

    @Test
    fun stopWinsWhenUnknownStartReconcileBecomesTerminalOrCancelled() {
        listOf("terminal", "cancelled").forEach { state ->
            val store = recoveryStore(ServiceRecoveryBackend())
            val coordinator = coordinator(store)
            coordinator.begin(template())
            coordinator.cancelCurrent()
            val panel = ServicePanelFake().apply { reconcileResults += reconcile(state) }

            assertEquals(AndroidCoordinatorStep.IDLE, coordinator.runOnce(panel, ServiceRuntimeFake()))
            assertFalse(store.load().intent.desiredActive)
            assertNull(store.load().intent.retry.lastErrorCode)
            assertNull(store.load().leaseTransaction)
        }
    }

    @Test
    fun processDeathAfterLeaseResponseExactReplaysBeforeLocalStart() {
        val backend = ServiceRecoveryBackend()
        val store = recoveryStore(backend)
        coordinator(store).begin(template())
        val pending = store.load().leaseTransaction!!
        store.recordLease(pending.generation, "lease-acquired")
        val panel = ServicePanelFake().apply {
            startResults += Result.success(startResult("lease-acquired"))
        }

        assertEquals(
            AndroidCoordinatorStep.ACTIVE,
            coordinator(recoveryStore(backend)).runOnce(panel, ServiceRuntimeFake()),
        )
        assertEquals(listOf(pending.startOperationId), panel.startOperationIds)
    }

    @Test
    fun quickOffDuringUnknownNetworkRequestInvalidatesGenerationAndCancelsIfAbsent() {
        val backend = ServiceRecoveryBackend()
        val coordinator = coordinator(recoveryStore(backend))
        coordinator.begin(template())
        val before = recoveryStore(backend).load()

        coordinator.cancel()
        val panel = ServicePanelFake().apply {
            reconcileResults += reconcile("cancelled", cancelRequested = true)
        }

        assertEquals(AndroidCoordinatorStep.IDLE, coordinator.runOnce(panel, ServiceRuntimeFake()))
        assertFalse(recoveryStore(backend).load().intent.desiredActive)
        assertTrue(recoveryStore(backend).load().intent.generation > before.intent.generation)
        assertEquals(listOf(true), panel.cancelIfAbsent)
    }

    @Test
    fun staleLeaseResponseNeverStartsRuntimeAndDurablySchedulesCleanup() {
        val backend = ServiceRecoveryBackend()
        val coordinator = coordinator(recoveryStore(backend))
        coordinator.begin(template())
        val runtime = ServiceRuntimeFake()
        val panel = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.success(startResult("late-lease"))
            onStart = { coordinator.cancel() }
        }

        assertEquals(AndroidCoordinatorStep.CLEANUP_REQUIRED, coordinator.runOnce(panel, runtime))

        val persisted = recoveryStore(backend).load()
        assertFalse(persisted.intent.desiredActive)
        assertEquals(LeasePhase.CLEANUP_PENDING, persisted.leaseTransaction?.phase)
        assertEquals("late-lease", persisted.leaseTransaction?.leaseId)
        assertEquals(0, runtime.startCalls)
    }

    @Test
    fun invalidatedAdmissionBeforeRecoveryAttemptDoesNotTouchPanelOrRuntime() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val coordinator = coordinator(store)
        coordinator.begin(template())
        val panel = ServicePanelFake()
        val runtime = ServiceRuntimeFake()

        assertEquals(
            AndroidCoordinatorStep.BUSY,
            coordinator.runOnce(panel, runtime, canStart = { false }),
        )

        assertEquals(emptyList<String>(), panel.reconcileOperationIds)
        assertEquals(emptyList<String>(), panel.startOperationIds)
        assertEquals(0, runtime.startCalls)
        assertTrue(store.load().intent.desiredActive)
        assertEquals(LeasePhase.START_PENDING, store.load().leaseTransaction?.phase)
    }

    @Test
    fun admissionInvalidatedDuringReconcileCannotCallPanelStart() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val coordinator = coordinator(store)
        coordinator.begin(template())
        val admission = AndroidConnectionIntentAdmission()
        val ticket = admission.snapshot()
        val panel = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            onReconcile = admission::invalidate
        }

        assertEquals(
            AndroidCoordinatorStep.BUSY,
            coordinator.runOnce(
                panel,
                ServiceRuntimeFake(),
                canStart = { admission.isCurrent(ticket) },
            ),
        )

        assertEquals(1, panel.reconcileOperationIds.size)
        assertEquals(emptyList<String>(), panel.startOperationIds)
        assertEquals(LeasePhase.START_PENDING, store.load().leaseTransaction?.phase)
    }

    @Test
    fun appliedReconcileFromInvalidatedAdmissionIsCompensatedAndRestarted() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val coordinator = coordinator(store)
        coordinator.begin(template())
        val firstStartOperationId = requireNotNull(
            store.load().leaseTransaction?.startOperationId,
        )
        val admission = AndroidConnectionIntentAdmission()
        val ticket = admission.snapshot()
        val panel = ServicePanelFake().apply {
            reconcileResults += reconcile("applied", leaseId = "lease-stale-reconcile")
            stopResults += Result.success(Unit)
            onReconcile = admission::invalidate
        }
        val runtime = ServiceRuntimeFake()

        assertEquals(
            AndroidCoordinatorStep.RETRY,
            coordinator.runOnce(
                panel,
                runtime,
                canStart = { admission.isCurrent(ticket) },
            ),
        )

        assertEquals(emptyList<String>(), panel.startOperationIds)
        assertEquals(listOf("lease-stale-reconcile"), panel.stopLeaseIds)
        assertEquals(1, runtime.stopCalls)
        val restarted = requireNotNull(store.load().leaseTransaction)
        assertEquals(LeasePhase.START_PENDING, restarted.phase)
        assertNull(restarted.leaseId)
        assertTrue(firstStartOperationId != restarted.startOperationId)
    }

    @Test
    fun admissionInvalidatedDuringBindingSyncCannotCallPanelStart() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val coordinator = coordinator(store)
        coordinator.begin(template().copy(syncBindingPreferences = true))
        val admission = AndroidConnectionIntentAdmission()
        val ticket = admission.snapshot()
        val panel = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            bindingSyncResults += Result.success(Unit)
            onBindingSync = admission::invalidate
        }

        assertEquals(
            AndroidCoordinatorStep.BUSY,
            coordinator.runOnce(
                panel,
                ServiceRuntimeFake(),
                canStart = { admission.isCurrent(ticket) },
            ),
        )

        assertEquals(1, panel.bindingSyncTemplates.size)
        assertEquals(emptyList<String>(), panel.startOperationIds)
        assertEquals(LeasePhase.START_PENDING, store.load().leaseTransaction?.phase)
    }

    @Test
    fun admissionInvalidatedDuringPanelStartDurablySchedulesCleanup() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val coordinator = coordinator(store)
        coordinator.begin(template())
        val admission = AndroidConnectionIntentAdmission()
        val ticket = admission.snapshot()
        val result = startResult("lease-admission-panel-race")
        val panel = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.success(result)
            onStart = admission::invalidate
        }
        val runtime = ServiceRuntimeFake()

        assertEquals(
            AndroidCoordinatorStep.CLEANUP_REQUIRED,
            coordinator.runOnce(
                panel,
                runtime,
                canStart = { admission.isCurrent(ticket) },
            ),
        )

        assertTrue(result.configuration.all { it == 0.toByte() })
        assertEquals(0, runtime.startCalls)
        assertEquals(LeasePhase.CLEANUP_PENDING, store.load().leaseTransaction?.phase)
        assertEquals("lease-admission-panel-race", store.load().leaseTransaction?.leaseId)
        assertEquals(
            "new_operation_after_cleanup",
            store.load().intent.retry.pendingAction,
        )
    }

    @Test
    fun explicitStopAfterAdmissionInvalidationCancelsTheScheduledRestart() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val coordinator = coordinator(store)
        coordinator.begin(template())
        val admission = AndroidConnectionIntentAdmission()
        val ticket = admission.snapshot()
        val panel = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.success(startResult("lease-fenced-then-stopped"))
            stopResults += Result.success(Unit)
            onStart = admission::invalidate
        }

        assertEquals(
            AndroidCoordinatorStep.CLEANUP_REQUIRED,
            coordinator.runOnce(
                panel,
                ServiceRuntimeFake(),
                canStart = { admission.isCurrent(ticket) },
            ),
        )
        assertTrue(coordinator.cancelCurrent() is AndroidCoordinatorResult.Accepted)
        assertEquals(
            AndroidCoordinatorStep.IDLE,
            coordinator.runOnce(panel, ServiceRuntimeFake()),
        )

        assertFalse(store.load().intent.desiredActive)
        assertNull(store.load().leaseTransaction)
        assertNull(store.load().intent.retry.pendingAction)
    }

    @Test
    fun admissionInvalidatedDuringRuntimeStartIsCompensatedAndRestarted() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val coordinator = coordinator(store)
        coordinator.begin(template())
        val firstStartOperationId = requireNotNull(
            store.load().leaseTransaction?.startOperationId,
        )
        val admission = AndroidConnectionIntentAdmission()
        val ticket = admission.snapshot()
        val panel = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.success(startResult("lease-admission-runtime-race"))
            stopResults += Result.success(Unit)
        }
        var runtimeStarts = 0
        var runtimeStops = 0
        val runtime = object : AndroidConnectionIntentRuntime {
            override fun start(
                result: BackgroundStartResult,
                operationId: String,
                isCurrent: () -> Boolean,
            ): Boolean {
                if (!isCurrent()) return false
                runtimeStarts += 1
                admission.invalidate()
                result.configuration.fill(0)
                return true
            }

            override fun stop(): Boolean {
                runtimeStops += 1
                return true
            }

            override fun isRunning(): Boolean = runtimeStarts > runtimeStops
        }

        assertEquals(
            AndroidCoordinatorStep.RETRY,
            coordinator.runOnce(
                panel,
                runtime,
                canStart = { admission.isCurrent(ticket) },
            ),
        )

        assertEquals(1, runtimeStarts)
        assertEquals(1, runtimeStops)
        assertEquals(listOf("lease-admission-runtime-race"), panel.stopLeaseIds)
        val restarted = requireNotNull(store.load().leaseTransaction)
        assertTrue(store.load().intent.desiredActive)
        assertEquals(LeasePhase.START_PENDING, restarted.phase)
        assertNull(restarted.leaseId)
        assertTrue(firstStartOperationId != restarted.startOperationId)
    }

    @Test
    fun cancellationAfterLeasePersistenceIsFencedBeforeRuntimeInvocation() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val coordinator = coordinator(store)
        coordinator.begin(template())
        val pending = requireNotNull(store.load().leaseTransaction)
        store.recordLease(pending.generation, "lease-fenced")
        coordinator.cancel()
        val runtime = ServiceRuntimeFake()

        val result = startRuntimeWithConnectionIntentFence(
            expectedGeneration = pending.generation,
            operationId = pending.startOperationId,
            current = store::load,
            result = startResult("lease-fenced"),
            runtime = runtime,
        )

        assertEquals(AndroidRuntimeStartFenceResult.CANCELLED_BEFORE_START, result)
        assertEquals(0, runtime.startCalls)
    }

    @Test
    fun cancellationDuringRuntimeStartIsImmediatelyCompensated() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val coordinator = coordinator(store)
        coordinator.begin(template())
        val panel = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.success(startResult("lease-runtime-race"))
            stopResults += Result.success(Unit)
        }
        var startCalls = 0
        var stopCalls = 0
        val runtime = object : AndroidConnectionIntentRuntime {
            override fun start(
                result: BackgroundStartResult,
                operationId: String,
                isCurrent: () -> Boolean,
            ): Boolean {
                if (!isCurrent()) return false
                startCalls += 1
                coordinator.cancel()
                result.configuration.fill(0)
                return true
            }

            override fun stop(): Boolean {
                stopCalls += 1
                return true
            }

            override fun isRunning(): Boolean = startCalls > stopCalls
        }

        assertEquals(AndroidCoordinatorStep.IDLE, coordinator.runOnce(panel, runtime))
        assertEquals(1, startCalls)
        assertEquals(1, stopCalls)
        assertFalse(store.load().intent.desiredActive)
        assertEquals(null, store.load().leaseTransaction)
        assertEquals(listOf("lease-runtime-race"), panel.stopLeaseIds)
    }

    @Test
    fun runtimeDispatchFenceCancelsAnOperationInvalidatedBetweenCheckAndDispatch() {
        val fence = AndroidRuntimeStartDispatchFence()
        val checked = CountDownLatch(1)
        val releaseCheck = CountDownLatch(1)
        val dispatches = AtomicInteger(0)
        val cancellations = AtomicInteger(0)
        val dispatched = AtomicReference<Boolean>()
        val dispatchThread = Thread {
            dispatched.set(
                fence.dispatchIfCurrent(
                    operationId = "11111111-1111-4111-8111-111111111188",
                    isCurrent = {
                        checked.countDown()
                        check(releaseCheck.await(2, TimeUnit.SECONDS))
                        true
                    },
                    dispatch = { dispatches.incrementAndGet() },
                    cancel = { cancellations.incrementAndGet() },
                ),
            )
        }.apply { start() }
        assertTrue(checked.await(2, TimeUnit.SECONDS))
        val cancelThread = Thread { fence.cancelActive() }.apply { start() }

        releaseCheck.countDown()
        dispatchThread.join(2_000L)
        cancelThread.join(2_000L)

        assertEquals(true, dispatched.get())
        assertEquals(1, dispatches.get())
        assertEquals(1, cancellations.get())
        fence.complete("11111111-1111-4111-8111-111111111188")
    }

    @Test
    fun onlyOneCoordinatorAttemptCanRunAtATime() {
        val backend = ServiceRecoveryBackend()
        val coordinator = coordinator(recoveryStore(backend))
        coordinator.begin(template())
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val panel = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.failure(BackgroundConnectionException("background_transport_unavailable"))
            onStart = {
                entered.countDown()
                check(release.await(2, TimeUnit.SECONDS))
            }
        }
        val first = Thread { coordinator.runOnce(panel, ServiceRuntimeFake()) }.apply { start() }
        assertTrue(entered.await(2, TimeUnit.SECONDS))

        assertEquals(AndroidCoordinatorStep.BUSY, coordinator.runOnce(panel, ServiceRuntimeFake()))

        release.countDown()
        first.join(2_000L)
        assertFalse(first.isAlive)
    }

    @Test
    fun cleanupRetriesAcrossCoordinatorRestartsWithOneStoredStopOperationId() {
        val backend = ServiceRecoveryBackend()
        val store = recoveryStore(backend)
        val first = coordinator(store)
        first.begin(template())
        val panel = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.success(startResult("lease-cleanup"))
            stopResults += Result.failure(BackgroundConnectionException("background_transport_unavailable"))
            stopResults += Result.failure(BackgroundConnectionException("connection_release_failed"))
            stopResults += Result.success(Unit)
        }
        val runtime = ServiceRuntimeFake(startSucceeds = false)

        assertEquals(AndroidCoordinatorStep.RETRY, first.runOnce(panel, runtime))
        val stopOperationId = recoveryStore(backend).load().leaseTransaction!!.stopOperationId
        first.acknowledgeInitialTerminalDiagnostic()

        assertEquals(
            AndroidCoordinatorStep.RETRY,
            coordinator(recoveryStore(backend)).runOnce(panel, ServiceRuntimeFake()),
        )
        assertEquals(
            AndroidCoordinatorStep.RETRY,
            coordinator(recoveryStore(backend)).runOnce(panel, ServiceRuntimeFake()),
        )
        assertEquals(
            AndroidCoordinatorStep.IDLE,
            coordinator(recoveryStore(backend)).runOnce(panel, ServiceRuntimeFake()),
        )
        assertEquals(listOf(stopOperationId, stopOperationId, stopOperationId), panel.stopOperationIds)
        assertEquals(null, recoveryStore(backend).load().leaseTransaction)
    }

    @Test
    fun cleanupRetryTimerAndStickyRestartRescheduleDurableCleanupWhenDesiredIsOff() {
        val backend = ServiceRecoveryBackend()
        val store = recoveryStore(backend)
        val coordinator = coordinator(store)
        coordinator.begin(template())
        val pending = store.load().leaseTransaction!!
        coordinator.cancel()
        store.requireCleanup(store.load().intent.generation, "lease-cleanup", "stop-operation")
        assertFalse(store.load().intent.desiredActive)
        var schedules = 0

        ConnectionIntentServiceLifecycle(coordinator) { schedules += 1 }.onRetryTimer()
        ConnectionIntentServiceLifecycle(
            coordinator(recoveryStore(backend)),
        ) { schedules += 1 }.onStickyRestart()

        assertEquals(2, schedules)
        assertEquals(LeasePhase.CLEANUP_PENDING, store.load().leaseTransaction?.phase)
        assertEquals(pending.startOperationId, store.load().leaseTransaction?.startOperationId)
    }

    @Test
    fun serviceLifecycleResumesRedundantRecoveryBeforeConnectionIntent() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val transaction = requireNotNull(serviceV2Envelope().redundantTransaction)
        store.beginRedundant(transaction).successEnvelope()
        var redundantSchedules = 0
        var connectionSchedules = 0
        val lifecycle = ConnectionIntentServiceLifecycle(
            coordinator = coordinator(store),
            scheduleRedundant = { recovery ->
                assertEquals(transaction, recovery.successEnvelope().redundantTransaction)
                redundantSchedules += 1
                true
            },
            schedule = { connectionSchedules += 1 },
        )

        assertTrue(lifecycle.onEnsureRunning())

        assertEquals(1, redundantSchedules)
        assertEquals(0, connectionSchedules)
    }

    @Test
    fun retryTimerResumesRedundantRecoveryWithoutConnectionIntent() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val transaction = requireNotNull(serviceV2Envelope().redundantTransaction)
        store.beginRedundant(transaction).successEnvelope()
        var redundantSchedules = 0
        var connectionSchedules = 0
        val lifecycle = ConnectionIntentServiceLifecycle(
            coordinator = coordinator(store),
            scheduleRedundant = { recovery ->
                assertEquals(transaction, recovery.successEnvelope().redundantTransaction)
                redundantSchedules += 1
                true
            },
            schedule = { connectionSchedules += 1 },
        )

        lifecycle.onRetryTimer()

        assertEquals(1, redundantSchedules)
        assertEquals(0, connectionSchedules)
    }

    @Test
    fun retryTimerPrioritizesPendingLogoutOverRedundantRecovery() {
        val store = recoveryStore(ServiceRecoveryBackend())
        store.beginRedundant(requireNotNull(serviceV2Envelope().redundantTransaction))
            .successEnvelope()
        var logoutSchedules = 0
        var redundantSchedules = 0
        var connectionSchedules = 0
        val lifecycle = ConnectionIntentServiceLifecycle(
            coordinator = coordinator(store),
            logoutState = { BackgroundLogoutReadState.PENDING },
            scheduleLogout = { logoutSchedules += 1 },
            scheduleRedundant = {
                redundantSchedules += 1
                true
            },
            schedule = { connectionSchedules += 1 },
        )

        lifecycle.onRetryTimer()

        assertEquals(1, logoutSchedules)
        assertEquals(0, redundantSchedules)
        assertEquals(0, connectionSchedules)
    }

    @Test
    fun logoutLifecycleStopsRedundantRecoveryBeforeLogoutAndResumesAfterCleanup() {
        val redundant = serviceV2Envelope()
        val transaction = requireNotNull(redundant.redundantTransaction)
        var recovery: RecoveryStoreResult<AndroidRecoveryEnvelope> =
            RecoveryStoreResult.Success(redundant)
        val events = mutableListOf<String>()
        val lifecycle = BackgroundLogoutServiceLifecycle(
            logoutState = { BackgroundLogoutReadState.PENDING },
            recovery = { recovery },
            beginRedundantStop = { events += "stop:${it.startOperationId}" },
            runLogout = { events += "logout" },
            scheduleRetry = { events += "retry" },
            stopIfIdle = { events += "idle" },
        )

        assertTrue(lifecycle.resume())
        assertEquals(
            listOf("stop:${transaction.startOperationId}"),
            events,
        )

        recovery = RecoveryStoreResult.Success(redundant.copy(redundantTransaction = null))
        lifecycle.onRedundantStopCompleted()

        assertEquals(
            listOf(
                "stop:${transaction.startOperationId}",
                "logout",
            ),
            events,
        )
    }

    @Test
    fun logoutLifecycleRetriesWithoutFinalizingWhenRecoveryIsUnreadable() {
        val events = mutableListOf<String>()
        val lifecycle = BackgroundLogoutServiceLifecycle(
            logoutState = { BackgroundLogoutReadState.PENDING },
            recovery = { RecoveryStoreResult.Failure("recovery_read_failed") },
            beginRedundantStop = { events += "stop" },
            runLogout = { events += "logout" },
            scheduleRetry = { events += "retry" },
            stopIfIdle = { events += "idle" },
        )

        assertTrue(lifecycle.resume())

        assertEquals(listOf("retry"), events)
    }

    @Test
    fun logoutLifecycleRetriesWhenCredentialStoreIsUnreadable() {
        val events = mutableListOf<String>()
        val lifecycle = BackgroundLogoutServiceLifecycle(
            logoutState = { BackgroundLogoutReadState.UNREADABLE },
            recovery = {
                events += "recovery"
                RecoveryStoreResult.Success(AndroidRecoveryEnvelope.empty(1))
            },
            beginRedundantStop = { events += "stop" },
            runLogout = { events += "logout" },
            scheduleRetry = { events += "retry" },
            stopIfIdle = { events += "idle" },
        )

        assertTrue(lifecycle.resume())

        assertEquals(listOf("retry"), events)
    }

    @Test
    fun unreadableCredentialDuringIdleSchedulesLogoutRetry() {
        val events = mutableListOf<String>()
        val lifecycle = BackgroundLogoutServiceLifecycle(
            logoutState = { BackgroundLogoutReadState.UNREADABLE },
            recovery = {
                events += "recovery"
                RecoveryStoreResult.Success(AndroidRecoveryEnvelope.empty(1))
            },
            beginRedundantStop = { events += "stop" },
            runLogout = { events += "logout" },
            scheduleRetry = { events += "retry" },
            stopIfIdle = { events += "idle" },
        )

        assertTrue(lifecycle.onIdleCheck())

        assertEquals(listOf("retry"), events)
    }

    @Test
    fun clearedCredentialRetryReturnsServiceToIdleCheck() {
        val events = mutableListOf<String>()
        val lifecycle = BackgroundLogoutServiceLifecycle(
            logoutState = { BackgroundLogoutReadState.NONE },
            recovery = {
                events += "recovery"
                RecoveryStoreResult.Success(AndroidRecoveryEnvelope.empty(1))
            },
            beginRedundantStop = { events += "stop" },
            runLogout = { events += "logout" },
            scheduleRetry = { events += "retry" },
            stopIfIdle = { events += "idle" },
        )

        lifecycle.resumeOrStopIfIdle()

        assertEquals(listOf("idle"), events)
    }

    @Test
    fun logoutLifecycleWaitsForCancelledRedundantStartToFinish() {
        var pendingStart = true
        var recovery = RecoveryStoreResult.Success(AndroidRecoveryEnvelope.empty(1))
        val transaction = requireNotNull(serviceV2Envelope().redundantTransaction)
        val events = mutableListOf<String>()
        val lifecycle = BackgroundLogoutServiceLifecycle(
            logoutState = { BackgroundLogoutReadState.PENDING },
            hasPendingRedundantBarrier = { pendingStart },
            recovery = { recovery },
            beginRedundantStop = { events += "stop" },
            runLogout = { events += "logout" },
            scheduleRetry = { events += "retry" },
            stopIfIdle = { events += "idle" },
        )

        assertTrue(lifecycle.resume())

        assertEquals(listOf("retry"), events)

        pendingStart = false
        recovery = RecoveryStoreResult.Success(
            serviceV2Envelope().copy(redundantTransaction = transaction),
        )
        assertTrue(lifecycle.resume())

        assertEquals(listOf("retry", "stop"), events)
    }

    @Test
    fun logoutLifecycleWaitsForDurableRedundantBarrierAfterRestart() {
        var cleanupPending = true
        val events = mutableListOf<String>()
        val lifecycle = BackgroundLogoutServiceLifecycle(
            logoutState = { BackgroundLogoutReadState.PENDING },
            hasPendingRedundantBarrier = {
                backgroundLogoutRedundantBarrierPending(
                    startPending = false,
                    cleanupPending = cleanupPending,
                )
            },
            recovery = {
                RecoveryStoreResult.Success(AndroidRecoveryEnvelope.empty(1))
            },
            beginRedundantStop = { events += "stop" },
            runLogout = { events += "logout" },
            scheduleRetry = { events += "retry" },
            stopIfIdle = { events += "idle" },
        )

        assertTrue(lifecycle.resume())
        assertEquals(listOf("retry"), events)

        cleanupPending = false
        assertTrue(lifecycle.resume())
        assertEquals(listOf("retry", "logout"), events)
    }

    @Test
    fun completedRedundantStopBecomesIdleWhenLogoutIsNoLongerPending() {
        val events = mutableListOf<String>()
        val lifecycle = BackgroundLogoutServiceLifecycle(
            logoutState = { BackgroundLogoutReadState.NONE },
            recovery = { RecoveryStoreResult.Success(AndroidRecoveryEnvelope.empty(1)) },
            beginRedundantStop = { events += "stop" },
            runLogout = { events += "logout" },
            scheduleRetry = { events += "retry" },
            stopIfIdle = { events += "idle" },
        )

        lifecycle.onRedundantStopCompleted()

        assertEquals(listOf("idle"), events)
    }

    @Test
    fun stickyRestartPrioritizesPendingLogoutThatAlsoHasDurableCleanup() {
        val backend = ServiceRecoveryBackend()
        val store = recoveryStore(backend)
        val connection = coordinator(store)
        connection.begin(template())
        val pending = store.load().leaseTransaction!!
        store.recordLease(pending.generation, "lease-logout-restart")
        val credentials = configuredCredentialStore()
        AndroidLogoutCoordinator(credentials, connection) {
            "11111111-1111-4111-8111-111111111190"
        }.begin()
        store.requireCleanup(store.load().intent.generation, "lease-logout-restart", "stop-logout")
        var connectionSchedules = 0
        var logoutSchedules = 0
        val lifecycle = ConnectionIntentServiceLifecycle(
            connection,
            schedule = { connectionSchedules += 1 },
            logoutState = {
                if (credentials.read().credentialSuccess().logoutState?.phase ==
                    BackgroundLogoutPhase.PENDING
                ) BackgroundLogoutReadState.PENDING else BackgroundLogoutReadState.NONE
            },
            scheduleLogout = { logoutSchedules += 1 },
        )

        assertTrue(lifecycle.onStickyRestart())

        assertEquals(0, connectionSchedules)
        assertEquals(1, logoutSchedules)
        assertEquals(LeasePhase.CLEANUP_PENDING, store.load().leaseTransaction?.phase)
    }

    @Test
    fun serviceLifecycleTreatsUnreadableCredentialStoreAsPendingLogout() {
        val store = recoveryStore(ServiceRecoveryBackend())
        store.beginRedundant(requireNotNull(serviceV2Envelope().redundantTransaction))
            .successEnvelope()
        var logoutSchedules = 0
        var redundantSchedules = 0
        var connectionSchedules = 0
        val lifecycle = ConnectionIntentServiceLifecycle(
            coordinator = coordinator(store),
            logoutState = { BackgroundLogoutReadState.UNREADABLE },
            scheduleLogout = { logoutSchedules += 1 },
            scheduleRedundant = {
                redundantSchedules += 1
                true
            },
            schedule = { connectionSchedules += 1 },
        )

        assertTrue(lifecycle.onEnsureRunning())
        assertTrue(lifecycle.hasPendingWork())
        assertEquals(1, logoutSchedules)
        assertEquals(0, redundantSchedules)
        assertEquals(0, connectionSchedules)
    }

    @Test
    fun backgroundLogoutBlocksNewClientStartsUntilCredentialStateIsReadableAndClear() {
        assertEquals(null, backgroundLogoutClientStartFailure(BackgroundLogoutReadState.NONE))
        assertEquals(
            "background_credential_logout_pending",
            backgroundLogoutClientStartFailure(BackgroundLogoutReadState.PENDING),
        )
        assertEquals(
            "background_credential_unavailable",
            backgroundLogoutClientStartFailure(BackgroundLogoutReadState.UNREADABLE),
        )
    }

    @Test
    fun vpnRevokeDurablyCancelsAndSchedulesCleanupWithoutImmediateServiceStop() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val connection = coordinator(store)
        connection.begin(template())
        val pending = requireNotNull(store.load().leaseTransaction)
        store.recordLease(pending.generation, "lease-revoked").successEnvelope()
        val dispatch = AndroidConnectionIntentDispatchState()
        val fence = AndroidRuntimeStartDispatchFence()
        var runtimeCancelled = 0
        fence.dispatchIfCurrent("runtime-revoked", { true }, {}, { runtimeCancelled += 1 })
        val events = mutableListOf<String>()
        val lifecycle = ConnectionIntentServiceLifecycle(
            coordinator = connection,
            schedule = { events += "scheduled" },
        )

        val disposition = routeAndroidVpnRevoke(
            dispatch,
            connection,
            fence,
            updateStopping = { events += "stopping" },
            resumePendingWork = lifecycle::onEnsureRunning,
        )
        applyAndroidVpnRevokeLifecycle(disposition) {
            events += "framework_stop"
        }

        assertTrue(disposition.keepForeground)
        assertTrue(disposition.cancelled is AndroidCoordinatorResult.Accepted)
        assertFalse(store.load().intent.desiredActive)
        assertEquals(1, runtimeCancelled)
        assertEquals(listOf("stopping", "scheduled"), events)
        assertEquals(LeasePhase.LEASE_ACQUIRED, store.load().leaseTransaction?.phase)

        val panel = ServicePanelFake().apply { stopResults += Result.success(Unit) }
        assertEquals(AndroidCoordinatorStep.IDLE, connection.runOnce(panel, ServiceRuntimeFake()))
        assertEquals(null, store.load().leaseTransaction)

        var serviceReleaseCalls = 0
        applyAndroidVpnServiceIdleLifecycle(
            debouncer = IdleStopDebouncer(
                delayMillis = 0L,
                schedule = { task, _ -> task.run() },
                cancel = {},
            ),
            shouldStop = {
                shouldStopVpnService(
                    SessionState.STOPPED,
                    desiredActive = false,
                    pendingLogout = false,
                    durableConnectionWork = lifecycle.hasPendingWork(),
                )
            },
            stop = { serviceReleaseCalls += 1 },
        )
        assertEquals(1, serviceReleaseCalls)
    }

    @Test
    fun vpnRevokeCancelFailureStopsFrameworkWithoutSchedulingActiveRecovery() {
        val backend = ServiceRecoveryBackend()
        val store = recoveryStore(backend)
        val connection = coordinator(store)
        connection.begin(template())
        val pending = requireNotNull(store.load().leaseTransaction)
        store.recordLease(pending.generation, "lease-revoke-failure").successEnvelope()
        backend.writeSucceeds = false
        val dispatch = AndroidConnectionIntentDispatchState()
        val fence = AndroidRuntimeStartDispatchFence()
        var runtimeCancelled = 0
        fence.dispatchIfCurrent("runtime-revoke-failure", { true }, {}, { runtimeCancelled += 1 })
        var recoverySchedules = 0
        val lifecycle = ConnectionIntentServiceLifecycle(
            coordinator = connection,
            schedule = { recoverySchedules += 1 },
        )

        val disposition = routeAndroidVpnRevoke(
            dispatch,
            connection,
            fence,
            updateStopping = {},
            resumePendingWork = lifecycle::onEnsureRunning,
        )
        var frameworkStops = 0
        applyAndroidVpnRevokeLifecycle(disposition) { frameworkStops += 1 }

        assertTrue(disposition.cancelled is AndroidCoordinatorResult.Failure)
        assertFalse(disposition.keepForeground)
        assertEquals(1, runtimeCancelled)
        assertEquals(0, recoverySchedules)
        assertEquals(1, frameworkStops)
        assertTrue(store.load().intent.desiredActive)
    }

    @Test
    fun idleStopIsBlockedByPendingLogoutOrDurableConnectionCleanup() {
        assertFalse(
            shouldStopVpnService(
                SessionState.STOPPED,
                desiredActive = false,
                pendingLogout = true,
                durableConnectionWork = false,
            ),
        )
        assertFalse(
            shouldStopVpnService(
                SessionState.STOPPED,
                desiredActive = false,
                pendingLogout = false,
                durableConnectionWork = true,
            ),
        )
        assertTrue(
            shouldStopVpnService(
                SessionState.STOPPED,
                desiredActive = false,
                pendingLogout = false,
                durableConnectionWork = false,
            ),
        )
    }

    @Test
    fun ensureRunningResumesDurableCleanupEvenWhenDesiredActiveIsFalse() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val connection = coordinator(store)
        connection.begin(template())
        val pending = store.load().leaseTransaction!!
        store.recordLease(pending.generation, "lease-ensure-cleanup")
        connection.cancel()
        store.requireCleanup(store.load().intent.generation, "lease-ensure-cleanup", "stop-ensure")
        var schedules = 0
        val lifecycle = ConnectionIntentServiceLifecycle(connection) { schedules += 1 }

        assertTrue(lifecycle.onEnsureRunning())

        assertEquals(1, schedules)
        assertFalse(store.load().intent.desiredActive)
    }

    @Test
    fun failedLocalStopKeepsCleanupDurableAndDoesNotReleasePanelLease() {
        val backend = ServiceRecoveryBackend()
        val store = recoveryStore(backend)
        val coordinator = coordinator(store)
        coordinator.begin(template())
        val transaction = store.load().leaseTransaction!!
        store.recordLease(transaction.generation, "lease-local-stop")
        coordinator.cancel()
        val panel = ServicePanelFake().apply { stopResults += Result.success(Unit) }
        val runtime = ServiceRuntimeFake(
            running = true,
            stopResults = ArrayDeque(listOf(false, false, true)),
            stopFailureClearsRunning = true,
        )

        assertEquals(AndroidCoordinatorStep.RETRY, coordinator.runOnce(panel, runtime))
        assertEquals(LeasePhase.CLEANUP_PENDING, store.load().leaseTransaction?.phase)
        assertTrue(store.load().leaseTransaction?.localStopPending == true)
        assertTrue(panel.stopLeaseIds.isEmpty())

        assertEquals(
            AndroidCoordinatorStep.RETRY,
            coordinator(recoveryStore(backend)).runOnce(panel, runtime),
        )
        assertEquals(2, runtime.stopCalls)
        assertTrue(panel.stopLeaseIds.isEmpty())

        assertEquals(
            AndroidCoordinatorStep.IDLE,
            coordinator(recoveryStore(backend)).runOnce(panel, runtime),
        )
        assertEquals(3, runtime.stopCalls)
        assertEquals(listOf("lease-local-stop"), panel.stopLeaseIds)
        assertEquals(null, store.load().leaseTransaction)
    }

    @Test
    fun cleanup503RetriesTheExactStoredStopOperation() {
        val backend = ServiceRecoveryBackend()
        val store = recoveryStore(backend)
        val connection = coordinator(store)
        connection.begin(template())
        val pending = requireNotNull(store.load().leaseTransaction)
        store.recordLease(pending.generation, "lease-stop-503")
        connection.cancel()
        val panel = ServicePanelFake().apply {
            stopResults += Result.failure(
                BackgroundConnectionException("connection_stop_failed", "17"),
            )
            stopResults += Result.success(Unit)
        }

        assertEquals(
            AndroidCoordinatorStep.RETRY,
            connection.runOnce(panel, ServiceRuntimeFake()),
        )
        val retry = store.load()
        val stopOperationId = requireNotNull(retry.leaseTransaction?.stopOperationId)
        assertEquals(LeasePhase.CLEANUP_PENDING, retry.leaseTransaction?.phase)
        assertEquals("connection_stop_failed", retry.intent.retry.lastErrorCode)

        assertEquals(
            AndroidCoordinatorStep.IDLE,
            coordinator(recoveryStore(backend)).runOnce(panel, ServiceRuntimeFake()),
        )
        assertEquals(listOf(stopOperationId, stopOperationId), panel.stopOperationIds)
        assertEquals(null, store.load().leaseTransaction)
    }

    @Test
    fun productionRuntimeBoundaryPreservesTypedLocalFailuresForDistinctPolicies() {
        fun failedRuntime(code: String) = ServiceConnectionIntentRuntimeBoundary(
            startTransport = { result, _, _, onError ->
                result.configuration.fill(0)
                onError(code)
            },
            stopTransport = { onSuccess, _ -> onSuccess(true) },
            running = { false },
            timeoutMillis = 100,
        )

        val profileStore = recoveryStore(ServiceRecoveryBackend())
        val profile = coordinator(profileStore)
        profile.begin(template())
        val originalProfileOperation = profileStore.load().leaseTransaction!!.startOperationId
        val profilePanel = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.success(startResult("lease-profile"))
        }
        assertEquals(
            AndroidCoordinatorStep.RETRY,
            profile.runOnce(profilePanel, failedRuntime("awg3_profile_apply_failed")),
        )
        assertTrue(profileStore.load().intent.retry.profileRetryUsed)
        assertEquals(
            originalProfileOperation,
            profileStore.load().leaseTransaction?.startOperationId,
        )

        val restartStore = recoveryStore(ServiceRecoveryBackend())
        val restart = coordinator(restartStore)
        restart.begin(template())
        val restartPanel = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.success(startResult("lease-restart"))
        }
        assertEquals(
            AndroidCoordinatorStep.RETRY,
            restart.runOnce(restartPanel, failedRuntime("udp_rebind_timeout")),
        )
        assertEquals("local_restart", restartStore.load().intent.retry.pendingAction)

        val handshakeStore = recoveryStore(ServiceRecoveryBackend())
        val handshake = coordinator(handshakeStore)
        handshake.begin(template())
        val originalHandshakeOperation = handshakeStore.load().leaseTransaction!!.startOperationId
        val handshakePanel = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.success(startResult("lease-handshake"))
        }
        assertEquals(
            AndroidCoordinatorStep.RETRY,
            handshake.runOnce(handshakePanel, failedRuntime("tunnel_handshake_timeout")),
        )
        assertEquals(LeasePhase.CLEANUP_PENDING, handshakeStore.load().leaseTransaction?.phase)
        assertEquals(
            originalHandshakeOperation,
            handshakeStore.load().leaseTransaction?.startOperationId,
        )
        handshakePanel.stopResults += Result.success(Unit)
        assertEquals(
            AndroidCoordinatorStep.RETRY,
            handshake.runOnce(handshakePanel, ServiceRuntimeFake()),
        )
        assertTrue(
            handshakeStore.load().leaseTransaction?.startOperationId != originalHandshakeOperation,
        )
        assertEquals(LeasePhase.START_PENDING, handshakeStore.load().leaseTransaction?.phase)
        assertEquals(listOf("lease-handshake"), handshakePanel.stopLeaseIds)
    }

    @Test
    fun failedRuntimeStartSchedulesExactTerminalCleanupAcrossProcessRecreation() {
        val backend = ServiceRecoveryBackend()
        val store = recoveryStore(backend)
        val first = coordinator(store)
        first.begin(template())
        val panel = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.success(startResult("lease-runtime-failed"))
        }

        assertEquals(
            AndroidCoordinatorStep.RETRY,
            first.runOnce(panel, ServiceRuntimeFake(startSucceeds = false)),
        )
        val cleanup = recoveryStore(backend).load()
        val stopOperationId = requireNotNull(cleanup.leaseTransaction?.stopOperationId)
        assertEquals(LeasePhase.CLEANUP_PENDING, cleanup.leaseTransaction?.phase)
        assertEquals("initial_terminal_report_pending", cleanup.intent.retry.pendingAction)
        assertEquals("tunnel_backend_error", cleanup.intent.retry.lastErrorCode)
        first.acknowledgeInitialTerminalDiagnostic()

        val restoredPanel = ServicePanelFake().apply { stopResults += Result.success(Unit) }
        assertEquals(
            AndroidCoordinatorStep.IDLE,
            coordinator(recoveryStore(backend)).runOnce(restoredPanel, ServiceRuntimeFake()),
        )
        assertEquals(listOf(stopOperationId), restoredPanel.stopOperationIds)
        assertEquals(null, recoveryStore(backend).load().leaseTransaction)
        assertFalse(recoveryStore(backend).load().intent.desiredActive)
    }

    @Test
    fun authoritativeTerminalWithStoredLeaseSchedulesCleanupBeforePublishingTerminal() {
        val backend = ServiceRecoveryBackend()
        val store = recoveryStore(backend)
        val first = coordinator(store)
        first.begin(template())
        val pending = requireNotNull(store.load().leaseTransaction)
        store.recordLease(pending.generation, "lease-authoritative-terminal")
            .successEnvelope()
        store.recordFailure(
            pending.generation,
            "operation_reconcile_pending",
            nextRetryAtUnix = 100,
            pendingAction = "reconcile",
        ).successEnvelope()
        val reconcilePanel = ServicePanelFake().apply {
            reconcileResults += reconcile("terminal")
        }

        assertEquals(
            AndroidCoordinatorStep.RETRY,
            first.runOnce(reconcilePanel, ServiceRuntimeFake()),
        )
        val cleanup = recoveryStore(backend).load()
        val stopOperationId = requireNotNull(cleanup.leaseTransaction?.stopOperationId)
        assertEquals("initial_terminal_report_pending", cleanup.intent.retry.pendingAction)
        first.acknowledgeInitialTerminalDiagnostic()

        val restoredPanel = ServicePanelFake().apply { stopResults += Result.success(Unit) }
        assertEquals(
            AndroidCoordinatorStep.IDLE,
            coordinator(recoveryStore(backend)).runOnce(restoredPanel, ServiceRuntimeFake()),
        )
        assertEquals(listOf(stopOperationId), restoredPanel.stopOperationIds)
        assertEquals(null, recoveryStore(backend).load().leaseTransaction)
    }

    @Test
    fun profileMismatchCleansOldLeaseThenIssuesExactlyOneFreshOperationAcrossProcessDeath() {
        val backend = ServiceRecoveryBackend()
        val operationIds = SequenceOperationIds()
        val first = AndroidConnectionIntentCoordinator(recoveryStore(backend), operationIds)
        first.begin(template())
        val oldOperationId = recoveryStore(backend).load().leaseTransaction!!.startOperationId
        val profileFailure = ServiceConnectionIntentRuntimeBoundary(
            startTransport = { result, _, _, onError ->
                result.configuration.fill(0)
                onError("awg3_profile_apply_failed")
            },
            stopTransport = { onSuccess, _ -> onSuccess(true) },
            running = { false },
            timeoutMillis = 100,
        )
        val firstPanel = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.success(startResult("lease-profile-old"))
        }

        assertEquals(AndroidCoordinatorStep.RETRY, first.runOnce(firstPanel, profileFailure))

        val cleanup = recoveryStore(backend).load()
        val cleanupTransaction = requireNotNull(cleanup.leaseTransaction)
        val stopOperationId = cleanupTransaction.stopOperationId
        assertEquals(LeasePhase.CLEANUP_PENDING, cleanupTransaction.phase)
        assertEquals(oldOperationId, cleanupTransaction.startOperationId)
        assertEquals("new_operation_after_cleanup", cleanup.intent.retry.pendingAction)
        assertTrue(cleanup.intent.retry.profileRetryUsed)
        assertTrue(stopOperationId != null)

        val cleanupPanel = ServicePanelFake().apply { stopResults += Result.success(Unit) }
        assertEquals(
            AndroidCoordinatorStep.RETRY,
            AndroidConnectionIntentCoordinator(recoveryStore(backend), operationIds)
                .runOnce(cleanupPanel, ServiceRuntimeFake()),
        )
        assertEquals(listOf(stopOperationId), cleanupPanel.stopOperationIds)

        val fresh = recoveryStore(backend).load()
        val freshTransaction = requireNotNull(fresh.leaseTransaction)
        val freshOperationId = freshTransaction.startOperationId
        assertEquals(LeasePhase.START_PENDING, freshTransaction.phase)
        assertTrue(freshOperationId != oldOperationId)
        assertTrue(fresh.intent.retry.profileRetryUsed)

        val freshPanel = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.success(startResult("lease-profile-fresh"))
        }
        assertEquals(
            AndroidCoordinatorStep.RETRY,
            AndroidConnectionIntentCoordinator(recoveryStore(backend), operationIds)
                .runOnce(freshPanel, profileFailure),
        )
        assertEquals(listOf(freshOperationId), freshPanel.startOperationIds)
        val terminalCleanup = recoveryStore(backend).load()
        val terminalCleanupTransaction = requireNotNull(terminalCleanup.leaseTransaction)
        val terminalStopOperationId = requireNotNull(terminalCleanupTransaction.stopOperationId)
        assertEquals(LeasePhase.CLEANUP_PENDING, terminalCleanupTransaction.phase)
        assertEquals("initial_terminal_report_pending", terminalCleanup.intent.retry.pendingAction)
        assertEquals("stopping", connectionIntentServiceStatus(terminalCleanup).status)
        AndroidConnectionIntentCoordinator(recoveryStore(backend), operationIds)
            .acknowledgeInitialTerminalDiagnostic()

        assertEquals(
            AndroidCoordinatorStep.RETRY,
            AndroidConnectionIntentCoordinator(recoveryStore(backend), operationIds).runOnce(
                ServicePanelFake(),
                ServiceRuntimeFake(stopResults = ArrayDeque(listOf(false))),
            ),
        )
        assertEquals(
            terminalStopOperationId,
            recoveryStore(backend).load().leaseTransaction?.stopOperationId,
        )

        val failedStopPanel = ServicePanelFake().apply {
            stopResults += Result.failure(
                BackgroundConnectionException("operation_id_conflict"),
            )
        }
        assertEquals(
            AndroidCoordinatorStep.RETRY,
            AndroidConnectionIntentCoordinator(recoveryStore(backend), operationIds)
                .runOnce(failedStopPanel, ServiceRuntimeFake()),
        )
        assertEquals(listOf(terminalStopOperationId), failedStopPanel.stopOperationIds)
        assertEquals(
            terminalStopOperationId,
            recoveryStore(backend).load().leaseTransaction?.stopOperationId,
        )

        val retriableStopPanel = ServicePanelFake().apply {
            stopResults += Result.failure(
                BackgroundConnectionException("background_transport_unavailable"),
            )
        }
        assertEquals(
            AndroidCoordinatorStep.RETRY,
            AndroidConnectionIntentCoordinator(recoveryStore(backend), operationIds)
                .runOnce(retriableStopPanel, ServiceRuntimeFake()),
        )
        assertEquals(listOf(terminalStopOperationId), retriableStopPanel.stopOperationIds)
        assertEquals(
            terminalStopOperationId,
            recoveryStore(backend).load().leaseTransaction?.stopOperationId,
        )

        val successfulStopPanel = ServicePanelFake().apply {
            stopResults += Result.success(Unit)
        }
        assertEquals(
            AndroidCoordinatorStep.IDLE,
            AndroidConnectionIntentCoordinator(recoveryStore(backend), operationIds)
                .runOnce(successfulStopPanel, ServiceRuntimeFake()),
        )
        assertEquals(listOf(terminalStopOperationId), successfulStopPanel.stopOperationIds)
        val terminal = recoveryStore(backend).load()
        assertEquals(null, terminal.leaseTransaction)
        assertEquals("none", connectionIntentServiceStatus(terminal).status)
        assertFalse(terminal.intent.desiredActive)
        assertNull(terminal.intent.retry.lastErrorCode)
        assertEquals(listOf(oldOperationId), firstPanel.startOperationIds)
        assertEquals(listOf(freshOperationId), freshPanel.startOperationIds)
    }

    @Test
    fun bootMismatchTurnsKnownLeaseIntoCleanupWithoutStartingRuntime() {
        val backend = ServiceRecoveryBackend()
        val boot = AtomicLong(7)
        val store = AndroidRecoveryStore(backend, BootIdentityProvider(boot::get))
        val coordinator = coordinator(store)
        coordinator.begin(template())
        val pending = store.load().leaseTransaction!!
        store.recordLease(pending.generation, "old-boot-lease")
        boot.set(8)
        val runtime = ServiceRuntimeFake()
        val panel = ServicePanelFake().apply { stopResults += Result.success(Unit) }

        assertEquals(AndroidCoordinatorStep.IDLE, coordinator.runOnce(panel, runtime))

        assertEquals(0, runtime.startCalls)
        assertFalse(store.load().intent.desiredActive)
        assertEquals(listOf("old-boot-lease"), panel.stopLeaseIds)
    }

    @Test
    fun serviceStatusProjectsDurableStartAndCleanupPhases() {
        val backend = ServiceRecoveryBackend()
        val store = recoveryStore(backend)
        val coordinator = coordinator(store)
        coordinator.begin(template())

        val startPending = connectionIntentServiceStatus(store.load())
        assertEquals("recovering", startPending.status)
        assertEquals("start_pending", startPending.leasePhase)

        coordinator.cancel()
        val cancelled = store.load()
        store.requireCleanup(cancelled.intent.generation, "lease-1", "stop-operation-1")
        val cleanup = connectionIntentServiceStatus(store.load())
        assertEquals("stopping", cleanup.status)
        assertFalse(cleanup.desiredActive)
        assertEquals("cleanup_pending", cleanup.leasePhase)
    }

    @Test
    fun transientAndTerminalFailuresAreProjectedFromDurableRetryMetadata() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val coordinator = AndroidConnectionIntentCoordinator(
            store,
            operationId = SequenceOperationIds(),
            nowUnix = { 1_000 },
        )
        coordinator.begin(template())
        val transient = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.failure(
                BackgroundConnectionException("background_transport_unavailable"),
            )
        }

        assertEquals(AndroidCoordinatorStep.RETRY, coordinator.runOnce(transient, ServiceRuntimeFake()))
        val recovering = connectionIntentServiceStatus(store.load())
        assertEquals("recovering", recovering.status)
        assertEquals(1_002L, recovering.nextRetryAtUnix)
        assertEquals("background_transport_unavailable", recovering.lastErrorCode)

        val terminal = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.failure(BackgroundConnectionException("operation_id_conflict"))
        }
        assertEquals(AndroidCoordinatorStep.RETRY, coordinator.runOnce(terminal, ServiceRuntimeFake()))
        val idleProjection = connectionIntentServiceStatus(store.load())
        assertEquals("none", idleProjection.status)
        assertFalse(idleProjection.desiredActive)
        assertEquals("operation_id_conflict", idleProjection.lastErrorCode)
    }

    @Test
    fun explicitNewOperationDecisionIsTheOnlyBranchThatMintsAReplacementStartId() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val coordinator = coordinator(store)
        coordinator.begin(template())
        val original = store.load().leaseTransaction!!.startOperationId
        val panel = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.failure(
                BackgroundConnectionException("connection_no_longer_active"),
            )
        }

        assertEquals(AndroidCoordinatorStep.RETRY, coordinator.runOnce(panel, ServiceRuntimeFake()))

        val replacement = store.load().leaseTransaction!!.startOperationId
        assertTrue(replacement != original)
        assertEquals(LeasePhase.START_PENDING, store.load().leaseTransaction?.phase)
    }

    @Test
    fun retryAfterAndBoundedDecisionFlagsRemainDurableAcrossCoordinatorRecreation() {
        val backend = ServiceRecoveryBackend()
        val store = recoveryStore(backend)
        val first = AndroidConnectionIntentCoordinator(
            store,
            operationId = SequenceOperationIds(),
            nowUnix = { 1_000 },
        )
        first.begin(template())
        val rateLimited = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.failure(
                BackgroundConnectionException("operation_in_progress", retryAfterHeader = "120"),
            )
        }
        assertEquals(AndroidCoordinatorStep.RETRY, first.runOnce(rateLimited, ServiceRuntimeFake()))
        assertEquals(1_120L, store.load().intent.retry.nextRetryAtUnix)

        val serviceFailure = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.failure(BackgroundConnectionException("service_unavailable"))
        }
        assertEquals(AndroidCoordinatorStep.RETRY, first.runOnce(serviceFailure, ServiceRuntimeFake()))
        assertTrue(store.load().intent.retry.serviceRecoveryUsed)

        val restored = AndroidConnectionIntentCoordinator(
            recoveryStore(backend),
            operationId = SequenceOperationIds(),
            nowUnix = { 2_000 },
        )
        val repeated = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.failure(BackgroundConnectionException("service_unavailable"))
        }
        assertEquals(AndroidCoordinatorStep.RETRY, restored.runOnce(repeated, ServiceRuntimeFake()))
        assertFalse(store.load().intent.desiredActive)
    }

    @Test
    fun directRetryPersistsFreshBoundedDeadlineAcrossProcessDeath() {
        val backend = ServiceRecoveryBackend()
        val first = AndroidConnectionIntentCoordinator(
            recoveryStore(backend),
            operationId = SequenceOperationIds(),
            nowUnix = { 1_000 },
        )
        first.begin(template())
        val pending = ServicePanelFake().apply {
            reconcileResults += reconcile("pending")
        }

        assertEquals(AndroidCoordinatorStep.RETRY, first.runOnce(pending, ServiceRuntimeFake()))
        assertEquals(1_002L, recoveryStore(backend).load().intent.retry.nextRetryAtUnix)
        assertEquals(2L, recoveryStore(backend).load().intent.retry.scheduledDelaySeconds)

        val restored = AndroidConnectionIntentCoordinator(
            recoveryStore(backend),
            operationId = SequenceOperationIds(),
            nowUnix = { 1_010 },
        )
        val stillPending = ServicePanelFake().apply {
            reconcileResults += reconcile("pending")
        }
        assertEquals(
            AndroidCoordinatorStep.RETRY,
            restored.runOnce(stillPending, ServiceRuntimeFake()),
        )
        assertEquals(1_015L, recoveryStore(backend).load().intent.retry.nextRetryAtUnix)
        assertEquals(5L, recoveryStore(backend).load().intent.retry.scheduledDelaySeconds)
    }

    @Test
    fun activeCheckpointWithScheduledRetryProjectsRecoveringInsteadOfNone() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val coordinator = coordinator(store)
        coordinator.begin(template())
        val generation = store.load().intent.generation
        store.recordLease(generation, "lease-active-retry").successEnvelope()
        store.activateCheckpoint(generation).successEnvelope()
        store.recordFailure(
            expectedGeneration = generation,
            errorCode = "background_transport_unavailable",
            nextRetryAtUnix = 1_005,
            scheduledDelaySeconds = 5,
        ).successEnvelope()

        val status = connectionIntentServiceStatus(store.load())

        assertEquals("recovering", status.status)
        assertTrue(status.desiredActive)
        assertEquals(LeasePhase.ACTIVE_CHECKPOINT.wireName, status.leasePhase)
        assertEquals(1_005L, status.nextRetryAtUnix)
    }

    @Test
    fun immediateConnectionAttemptRequestsCoalesceAndRecheckPersistedDueTimeAtExecution() {
        val queued = ArrayDeque<Runnable>()
        val scheduled = mutableListOf<Long>()
        var persistedDelayMillis = 0L
        var attempts = 0
        val dispatcher = AndroidConnectionIntentAttemptDispatcher(
            execute = { queued += it },
            persistedDelayMillis = { persistedDelayMillis },
            scheduleAfter = scheduled::add,
            attempt = { attempts += 1 },
        )

        dispatcher.request()
        dispatcher.request()
        assertEquals(1, queued.size)

        persistedDelayMillis = 5_000L
        queued.removeFirst().run()

        assertEquals(0, attempts)
        assertEquals(listOf(5_000L), scheduled)

        dispatcher.request()
        dispatcher.request()
        assertEquals(1, queued.size)
        persistedDelayMillis = 0L
        queued.removeFirst().run()

        assertEquals(1, attempts)
    }

    @Test
    fun queuedConnectionAttemptKeepsAdmissionFromItsRequest() {
        val queued = ArrayDeque<Runnable>()
        val admission = AndroidConnectionIntentAdmission()
        var attempts = 0
        val dispatcher = AndroidConnectionIntentAttemptDispatcher(
            execute = { queued += it },
            persistedDelayMillis = { 0L },
            scheduleAfter = { error("unexpected retry timer") },
            captureAdmissionTicket = admission::snapshot,
            attempt = { ticket ->
                if (admission.isCurrent(ticket)) attempts += 1
            },
        )

        dispatcher.request()
        admission.invalidate()
        queued.removeFirst().run()

        assertEquals(0, attempts)

        dispatcher.request()
        queued.removeFirst().run()

        assertEquals(1, attempts)
    }

    @Test
    fun productionExecutorBoundaryDispatchesAttemptWithoutClassCast() {
        val executor = Executor(Runnable::run)
        var attempts = 0
        val dispatcher = AndroidConnectionIntentAttemptDispatcher(
            execute = executor::execute,
            persistedDelayMillis = { 0L },
            scheduleAfter = { error("unexpected retry timer") },
            attempt = { attempts += 1 },
        )

        dispatcher.request()

        assertEquals(1, attempts)
    }

    @Test
    fun requestDuringRunningAttemptQueuesOneDueTimeCheckedFollowUp() {
        val queued = ArrayDeque<Runnable>()
        val scheduled = mutableListOf<Long>()
        var persistedDelayMillis = 0L
        var attempts = 0
        lateinit var dispatcher: AndroidConnectionIntentAttemptDispatcher
        dispatcher = AndroidConnectionIntentAttemptDispatcher(
            execute = { queued += it },
            persistedDelayMillis = { persistedDelayMillis },
            scheduleAfter = scheduled::add,
            attempt = {
                attempts += 1
                if (attempts == 1) {
                    dispatcher.request()
                    dispatcher.request()
                }
            },
        )

        dispatcher.request()
        queued.removeFirst().run()

        assertEquals(1, attempts)
        assertEquals(1, queued.size)

        persistedDelayMillis = 5_000L
        queued.removeFirst().run()

        assertEquals(1, attempts)
        assertEquals(listOf(5_000L), scheduled)
        assertTrue(queued.isEmpty())
    }

    @Test
    fun disarmedStopFailureKeepsExactCleanupAndBoundedDeadlineAcrossProcessDeath() {
        val backend = ServiceRecoveryBackend()
        val store = recoveryStore(backend)
        val first = AndroidConnectionIntentCoordinator(
            store,
            operationId = SequenceOperationIds(),
            nowUnix = { 1_000 },
        )
        first.begin(template())
        val generation = store.load().intent.generation
        store.recordLease(generation, "lease-cancelled").successEnvelope()
        store.scheduleInitialTerminalAfterCleanup(
            generation,
            "lease-cancelled",
            "stop-existing",
            "service_timeout",
        ).successEnvelope()
        first.acknowledgeInitialTerminalDiagnostic()
        val failedStop = ServicePanelFake().apply {
            stopResults += Result.failure(BackgroundConnectionException("transport_error"))
        }

        assertEquals(AndroidCoordinatorStep.RETRY, first.runOnce(failedStop, ServiceRuntimeFake()))
        val pending = store.load()
        val stopOperationId = requireNotNull(pending.leaseTransaction?.stopOperationId)
        assertEquals("initial_terminal_after_cleanup", pending.intent.retry.pendingAction)
        assertEquals(2, pending.intent.retry.attempt)
        assertEquals(1_005L, pending.intent.retry.nextRetryAtUnix)
        assertEquals(5_000L, connectionIntentPersistedDelayMillis(pending, nowUnix = 1_000))

        val restored = AndroidConnectionIntentCoordinator(
            recoveryStore(backend),
            operationId = SequenceOperationIds(),
            nowUnix = { 1_010 },
        )
        val failedAgain = ServicePanelFake().apply {
            stopResults += Result.failure(BackgroundConnectionException("transport_error"))
        }
        assertEquals(
            AndroidCoordinatorStep.RETRY,
            restored.runOnce(failedAgain, ServiceRuntimeFake()),
        )
        val restoredPending = recoveryStore(backend).load()
        assertEquals(stopOperationId, restoredPending.leaseTransaction?.stopOperationId)
        assertEquals(
            "initial_terminal_after_cleanup",
            restoredPending.intent.retry.pendingAction,
        )
        assertEquals(3, restoredPending.intent.retry.attempt)
        assertEquals(1_025L, restoredPending.intent.retry.nextRetryAtUnix)
        assertEquals(15_000L, connectionIntentPersistedDelayMillis(restoredPending, nowUnix = 1_010))
        assertTrue(
            requireNotNull(restoredPending.intent.retry.nextRetryAtUnix) >
                requireNotNull(pending.intent.retry.nextRetryAtUnix),
        )
        assertEquals(listOf(stopOperationId), failedAgain.stopOperationIds)
    }

    @Test
    fun disarmedReconcileErrorPersistsBackoffAndExactStartAcrossProcessDeath() {
        val backend = ServiceRecoveryBackend()
        val store = recoveryStore(backend)
        val first = AndroidConnectionIntentCoordinator(
            store,
            operationId = SequenceOperationIds(),
            nowUnix = { 2_000 },
        )
        first.begin(template())
        first.cancelCurrent()
        val startOperationId = requireNotNull(store.load().leaseTransaction).startOperationId
        val failed = ServicePanelFake().apply {
            onReconcile = { throw BackgroundConnectionException("transport_error") }
        }

        assertEquals(AndroidCoordinatorStep.RETRY, first.runOnce(failed, ServiceRuntimeFake()))
        val pending = recoveryStore(backend).load()
        assertEquals(2_002L, pending.intent.retry.nextRetryAtUnix)
        assertEquals(startOperationId, pending.leaseTransaction?.startOperationId)
        assertEquals(listOf(true), failed.cancelIfAbsent)

        val restored = AndroidConnectionIntentCoordinator(
            recoveryStore(backend),
            operationId = SequenceOperationIds(),
            nowUnix = { 2_010 },
        )
        val failedAgain = ServicePanelFake().apply {
            onReconcile = { throw BackgroundConnectionException("transport_error") }
        }
        assertEquals(
            AndroidCoordinatorStep.RETRY,
            restored.runOnce(failedAgain, ServiceRuntimeFake()),
        )
        val restoredPending = recoveryStore(backend).load()
        assertEquals(2_015L, restoredPending.intent.retry.nextRetryAtUnix)
        assertEquals(startOperationId, restoredPending.leaseTransaction?.startOperationId)
        assertEquals(listOf(true), failedAgain.cancelIfAbsent)
    }

    @Test
    fun initialTerminalWithoutLeaseHandsOffOneDiagnosticThenCleansToIdle() {
        val backend = ServiceRecoveryBackend()
        val first = coordinator(recoveryStore(backend))
        first.begin(template())
        val terminal = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.failure(
                BackgroundConnectionException("operation_id_conflict"),
            )
        }

        assertEquals(
            AndroidCoordinatorStep.RETRY,
            first.runOnce(terminal, ServiceRuntimeFake()),
        )
        val pendingReport = recoveryStore(backend).load()
        assertFalse(pendingReport.intent.desiredActive)
        assertEquals("none", connectionIntentServiceStatus(pendingReport).status)
        assertTrue(pendingReport.intent.retry.terminalDiagnosticPending)

        val restored = coordinator(recoveryStore(backend))
        assertEquals(
            AndroidCoordinatorStep.RETRY,
            restored.runOnce(ServicePanelFake(), ServiceRuntimeFake()),
        )
        restored.acknowledgeInitialTerminalDiagnostic()
        val cancelled = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
        }
        assertEquals(AndroidCoordinatorStep.IDLE, restored.runOnce(cancelled, ServiceRuntimeFake()))
        assertNull(recoveryStore(backend).load().leaseTransaction)
    }

    @Test
    fun internalTerminalBumpReusesTheDurableSlowReportEpisodeAfterProcessDeath() {
        val backend = ServiceRecoveryBackend()
        val firstStore = recoveryStore(backend)
        val first = coordinator(firstStore)
        val started = (first.begin(template()) as AndroidCoordinatorResult.Accepted).envelope
        val diagnostics = AutomaticDiagnosticsConnectionIntentEpisode()
        assertEquals(
            AutomaticDiagnosticsConnectionIntentActions(
                queueReport = true,
                notifyUser = true,
            ),
            diagnostics.observeRetry(300),
        )
        val slowMarker = StartFailureRequest(
            reportId = "33333333-3333-4333-8333-333333333333",
            deviceId = "11111111-1111-4111-8111-111111111111",
            errorCode = "network",
            queuedAt = 1_000,
            sent = false,
            trigger = "connection_intent_slow_recovery",
            diagnosticsEpisodeId = started.intent.diagnosticsEpisodeId,
        )
        val terminal = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.failure(
                BackgroundConnectionException("operation_id_conflict"),
            )
        }

        assertEquals(AndroidCoordinatorStep.RETRY, first.runOnce(terminal, ServiceRuntimeFake()))
        val reconstructedStore = recoveryStore(backend)
        val pending = reconstructedStore.load()
        assertTrue(pending.intent.generation > started.intent.generation)
        assertEquals(started.intent.diagnosticsEpisodeId, pending.intent.diagnosticsEpisodeId)
        val reconstructedDiagnostics = AutomaticDiagnosticsConnectionIntentEpisode(
            reportQueued = false,
            notificationSent = true,
            terminalObserved = false,
        )
        assertEquals(
            AutomaticDiagnosticsConnectionIntentActions(queueReport = true),
            reconstructedDiagnostics.observeTerminal(),
        )
        val reportOutcome = automaticDiagnosticsConnectionIntentQueuePolicy(
            existing = StartFailureRequest.fromJson(slowMarker.toJson()),
            diagnosticsEpisodeId = pending.intent.diagnosticsEpisodeId,
            now = 1_001,
            cooldownSeconds = 900,
        )
        assertEquals(
            AutomaticDiagnosticsConnectionIntentReportOutcome.ALREADY_DURABLE_THIS_EPISODE,
            reportOutcome,
        )

        val restored = coordinator(reconstructedStore)
        assertEquals(AndroidCoordinatorStep.RETRY, restored.runOnce(
            ServicePanelFake(),
            ServiceRuntimeFake(),
        ))
        routeInitialTerminalDiagnosticHandoff(
            reportOutcome,
            acknowledge = { restored.acknowledgeInitialTerminalDiagnostic() },
            continueRecovery = {},
        )
        val cancelled = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
        }
        assertEquals(AndroidCoordinatorStep.IDLE, restored.runOnce(cancelled, ServiceRuntimeFake()))
        val next = (restored.begin(template()) as AndroidCoordinatorResult.Accepted).envelope
        assertEquals(next.intent.generation, next.intent.diagnosticsEpisodeId)
        assertTrue(next.intent.diagnosticsEpisodeId > pending.intent.diagnosticsEpisodeId)
        assertEquals(
            AutomaticDiagnosticsConnectionIntentActions(queueReport = true),
            AutomaticDiagnosticsConnectionIntentEpisode().observeTerminal(),
        )
    }

    @Test
    fun successfulHandshakeSeparatesLaterRecoveryReportFromTheSentPreviousEpisode() {
        val backend = ServiceRecoveryBackend()
        val store = recoveryStore(backend)
        val started = (coordinator(store).begin(template()) as AndroidCoordinatorResult.Accepted)
            .envelope
        val sentEpisodeA = StartFailureRequest(
            reportId = "33333333-3333-4333-8333-333333333333",
            deviceId = "11111111-1111-4111-8111-111111111111",
            errorCode = "network",
            queuedAt = 1_000,
            sent = true,
            trigger = "connection_intent_slow_recovery",
            diagnosticsEpisodeId = started.intent.diagnosticsEpisodeId,
        )
        store.recordLease(started.intent.generation, "lease-a").successEnvelope()
        store.activateCheckpoint(started.intent.generation).successEnvelope()
        val reconstructed = recoveryStore(backend).load()

        val episodeB = automaticDiagnosticsConnectionIntentQueuePolicy(
            existing = sentEpisodeA,
            diagnosticsEpisodeId = reconstructed.intent.diagnosticsEpisodeId,
            now = 1_900,
            cooldownSeconds = 900,
        )
        val queuedEpisodeB = sentEpisodeA.copy(
            reportId = "44444444-4444-4444-8444-444444444444",
            queuedAt = 1_900,
            sent = false,
            diagnosticsEpisodeId = reconstructed.intent.diagnosticsEpisodeId,
        )

        assertEquals(
            AutomaticDiagnosticsConnectionIntentReportOutcome.QUEUED_THIS_EPISODE,
            episodeB,
        )
        assertEquals(
            AutomaticDiagnosticsConnectionIntentReportOutcome.ALREADY_DURABLE_THIS_EPISODE,
            automaticDiagnosticsConnectionIntentQueuePolicy(
                existing = queuedEpisodeB,
                diagnosticsEpisodeId = reconstructed.intent.diagnosticsEpisodeId,
                now = 1_901,
                cooldownSeconds = 900,
            ),
        )
    }

    @Test
    fun oldEpisodeCallbackIsRejectedAfterSuccessfulCheckpointRotation() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val coordinator = coordinator(store)
        val started = (coordinator.begin(template()) as AndroidCoordinatorResult.Accepted).envelope
        store.recordLease(started.intent.generation, "lease-a").successEnvelope()
        val active = store.activateCheckpoint(started.intent.generation).successEnvelope()

        val stale = coordinator.acknowledgeInitialTerminalDiagnostic(
            started.intent.generation,
            started.intent.diagnosticsEpisodeId,
        )

        assertEquals(
            "connection_intent_generation_conflict",
            (stale as RecoveryStoreResult.Failure).code,
        )
        assertEquals(active, store.load())
    }

    @Test
    fun initialTerminalWithLeaseReportsBeforeExactCleanupAndDoesNotReportAgain() {
        val backend = ServiceRecoveryBackend()
        val store = recoveryStore(backend)
        val first = coordinator(store)
        first.begin(template())
        val generation = store.load().intent.generation
        store.recordLease(generation, "lease-initial-terminal").successEnvelope()
        val terminal = ServicePanelFake().apply {
            startResults += Result.failure(
                BackgroundConnectionException("operation_id_conflict"),
            )
        }

        assertEquals(
            AndroidCoordinatorStep.RETRY,
            first.runOnce(terminal, ServiceRuntimeFake()),
        )
        val pending = store.load()
        val stopOperationId = requireNotNull(pending.leaseTransaction?.stopOperationId)
        assertEquals("stopping", connectionIntentServiceStatus(pending).status)

        val restored = coordinator(recoveryStore(backend))
        assertEquals(
            AndroidCoordinatorStep.RETRY,
            restored.runOnce(ServicePanelFake(), ServiceRuntimeFake()),
        )
        restored.acknowledgeInitialTerminalDiagnostic()
        val cleanup = ServicePanelFake().apply { stopResults += Result.success(Unit) }
        assertEquals(AndroidCoordinatorStep.IDLE, restored.runOnce(cleanup, ServiceRuntimeFake()))
        assertEquals(listOf(stopOperationId), cleanup.stopOperationIds)
        assertNull(recoveryStore(backend).load().leaseTransaction)
    }

    @Test
    fun storageFailureKeepsInitialTerminalPendingUntilPolicySuppressionAllowsCleanup() {
        val backend = ServiceRecoveryBackend()
        val store = recoveryStore(backend)
        val coordinator = coordinator(store)
        coordinator.begin(template())
        val terminal = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.failure(
                BackgroundConnectionException("operation_id_conflict"),
            )
        }
        assertEquals(
            AndroidCoordinatorStep.RETRY,
            coordinator.runOnce(terminal, ServiceRuntimeFake()),
        )
        var scheduled = 0

        routeInitialTerminalDiagnosticHandoff(
            AutomaticDiagnosticsConnectionIntentReportOutcome.STORAGE_FAILED,
            acknowledge = { coordinator.acknowledgeInitialTerminalDiagnostic() },
            continueRecovery = { scheduled += 1 },
        )
        assertTrue(store.load().intent.retry.terminalDiagnosticPending)
        assertEquals(1, scheduled)

        routeInitialTerminalDiagnosticHandoff(
            AutomaticDiagnosticsConnectionIntentReportOutcome.SUPPRESSED_BY_POLICY,
            acknowledge = { coordinator.acknowledgeInitialTerminalDiagnostic() },
            continueRecovery = { scheduled += 1 },
        )
        assertFalse(store.load().intent.retry.terminalDiagnosticPending)
        assertEquals(2, scheduled)
        val cleanup = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
        }
        assertEquals(
            AndroidCoordinatorStep.IDLE,
            coordinator.runOnce(cleanup, ServiceRuntimeFake()),
        )
    }

    @Test
    fun staleDiagnosticHandoffCannotAcknowledgeAnotherTerminalGeneration() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val coordinator = coordinator(store)
        coordinator.begin(template())
        val terminal = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.failure(
                BackgroundConnectionException("operation_id_conflict"),
            )
        }
        assertEquals(
            AndroidCoordinatorStep.RETRY,
            coordinator.runOnce(terminal, ServiceRuntimeFake()),
        )
        val pending = store.load()

        val stale = coordinator.acknowledgeInitialTerminalDiagnostic(
            pending.intent.generation - 1,
        )

        assertEquals(
            "connection_intent_generation_conflict",
            (stale as RecoveryStoreResult.Failure).code,
        )
        assertTrue(store.load().intent.retry.terminalDiagnosticPending)
    }

    @Test
    fun quickSettingsTemplateCarriesNormalizedStoredDnsAndSplitOptions() {
        val options = TunnelOptionsArgs().apply {
            splitActive = true
            policyHash = "quick-policy"
            applicationMode = "exclude_selected"
            excludedPackages = arrayListOf(" com.example.chat ", "com.example.chat")
            splitTunnelRoutes = arrayListOf("10.0.0.7/8")
            excludeLocalNetworks = true
            dnsServers = arrayListOf("1.1.1.1", "1.1.1.1")
        }
        val quick = QuickTunnelTemplate(
            options = options,
            connection = QuickConnectionArgs().apply {
                layer = "stray"
                ticConnectionMode = "dynamic"
                routeMode = "standalone"
                egressMode = "ipv4"
                allowAlternate = true
            },
        )

        val template = quickConnectionIntentTemplate(
            deviceId = "11111111-1111-4111-8111-111111111111",
            quick = quick,
            androidApiLevel = 33,
        )

        assertEquals("quick-policy", template.options.policyHash)
        assertEquals(listOf("com.example.chat"), template.options.excludedPackages)
        assertEquals(listOf("10.0.0.0/8"), template.options.splitTunnelRoutes)
        assertEquals(listOf("1.1.1.1"), template.options.dnsServers)
        assertTrue(template.options.excludeLocalNetworks)
    }

    @Test
    fun armedRetryThatFailsBeforeHandshakeReturnsToBlockedTerminal() {
        val backend = ServiceRecoveryBackend()
        val store = recoveryStore(backend)
        store.beginStart(0, template(), AndroidStartReplay(
            "armed-start",
            1,
            androidConnectionIntentFingerprint(template(), true),
        )).successEnvelope()
        store.recordLease(1, "armed-lease").successEnvelope()
        store.activateCheckpoint(1).successEnvelope()
        store.scheduleTerminalAfterCleanup(
            1,
            "armed-lease",
            "armed-stop",
            "service_timeout",
        ).successEnvelope()
        store.completeCleanupAsTerminal(1).successEnvelope()
        val coordinator = coordinator(store)
        coordinator.begin(template())
        val terminalBeforeHandshake = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.failure(
                BackgroundConnectionException("operation_id_conflict"),
            )
        }

        assertEquals(
            AndroidCoordinatorStep.TERMINAL,
            coordinator.runOnce(terminalBeforeHandshake, ServiceRuntimeFake()),
        )
        val blocked = store.load()
        assertTrue(blocked.intent.armedHistory)
        assertEquals("blocked_terminal", connectionIntentServiceStatus(blocked).status)
    }

    @Test
    fun initialTerminalKeepsCleanupScheduledUntilOffThenAllowsANewGeneration() {
        val backend = ServiceRecoveryBackend()
        val store = recoveryStore(backend)
        val coordinator = coordinator(store)
        val first = (coordinator.begin(template()) as AndroidCoordinatorResult.Accepted).envelope
        val terminal = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.failure(BackgroundConnectionException("operation_id_conflict"))
        }
        assertEquals(AndroidCoordinatorStep.RETRY, coordinator.runOnce(terminal, ServiceRuntimeFake()))
        assertFalse(store.load().intent.desiredActive)
        coordinator.acknowledgeInitialTerminalDiagnostic()
        var schedules = 0
        val lifecycle = ConnectionIntentServiceLifecycle(coordinator) { schedules += 1 }

        assertTrue(lifecycle.onStickyRestart())
        assertEquals(1, schedules)
        val cancelled = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
        }
        assertEquals(AndroidCoordinatorStep.IDLE, coordinator.runOnce(cancelled, ServiceRuntimeFake()))
        assertFalse(lifecycle.onEnsureRunning())

        val restarted = coordinator.begin(template()) as AndroidCoordinatorResult.Accepted
        assertEquals(first.intent.generation + 2, restarted.envelope.intent.generation)
        assertEquals(0, restarted.envelope.intent.retry.attempt)
        assertEquals(null, restarted.envelope.intent.retry.nextRetryAtUnix)
        assertNull(restarted.envelope.intent.retry.pendingAction)
        assertEquals(LeasePhase.START_PENDING, restarted.envelope.leaseTransaction?.phase)
    }

    @Test
    fun sharedAppAndQuickExplicitStartPathBeginsDiagnosticsForEveryAcceptedEpisode() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val coordinator = coordinator(store)
        val observed = mutableListOf<Long>()

        beginObservedConnectionIntent(coordinator, template(), onStarted = observed::add)
        val terminal = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.failure(BackgroundConnectionException("operation_id_conflict"))
        }
        assertEquals(AndroidCoordinatorStep.RETRY, coordinator.runOnce(terminal, ServiceRuntimeFake()))
        coordinator.acknowledgeInitialTerminalDiagnostic()
        val cancelled = ServicePanelFake().apply { reconcileResults += reconcile("not_found") }
        assertEquals(AndroidCoordinatorStep.IDLE, coordinator.runOnce(cancelled, ServiceRuntimeFake()))
        beginObservedConnectionIntent(coordinator, template(), onStarted = observed::add)

        assertEquals(listOf(1L, 3L), observed)
    }

    @Test
    fun localRestartAndReconcileDecisionsExecuteTheirDistinctRecoveryActions() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val coordinator = coordinator(store)
        coordinator.begin(template())
        val pending = store.load().leaseTransaction!!
        store.recordLease(pending.generation, "lease-action")
        val panel = ServicePanelFake().apply {
            startResults += Result.failure(BackgroundConnectionException("udp_rebind_failed"))
            startResults += Result.success(startResult("lease-action"))
        }
        assertEquals(AndroidCoordinatorStep.RETRY, coordinator.runOnce(panel, ServiceRuntimeFake()))
        assertEquals("local_restart", store.load().intent.retry.pendingAction)

        val running = ServiceRuntimeFake(running = true)
        assertEquals(AndroidCoordinatorStep.ACTIVE, coordinator.runOnce(panel, running))
        assertEquals(1, running.stopCalls)

        val reconcileStore = recoveryStore(ServiceRecoveryBackend())
        val reconcileCoordinator = coordinator(reconcileStore)
        reconcileCoordinator.begin(template())
        val reconcilePending = reconcileStore.load().leaseTransaction!!
        reconcileStore.recordLease(reconcilePending.generation, "lease-reconcile")
        val reconcilePanel = ServicePanelFake().apply {
            startResults += Result.failure(BackgroundConnectionException("service_timeout"))
            reconcileResults += reconcile("applied", leaseId = "lease-reconcile")
            startResults += Result.success(startResult("lease-reconcile"))
        }
        assertEquals(
            AndroidCoordinatorStep.RETRY,
            reconcileCoordinator.runOnce(reconcilePanel, ServiceRuntimeFake()),
        )
        assertEquals("reconcile", reconcileStore.load().intent.retry.pendingAction)
        assertEquals(
            AndroidCoordinatorStep.ACTIVE,
            reconcileCoordinator.runOnce(reconcilePanel, ServiceRuntimeFake()),
        )
        assertEquals(1, reconcilePanel.cancelIfAbsent.size)
    }

    @Test
    fun dynamicAwg3StallDurablyStopsWithTypedReasonThenStartsABoundedReplacement() {
        val backend = ServiceRecoveryBackend()
        val store = recoveryStore(backend)
        val operationIds = SequenceOperationIds()
        val coordinator = AndroidConnectionIntentCoordinator(store, operationId = operationIds)
        coordinator.begin(template())
        val firstPanel = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.success(startResult("lease-stalled"))
        }
        assertEquals(
            AndroidCoordinatorStep.ACTIVE,
            coordinator.runOnce(firstPanel, ServiceRuntimeFake()),
        )

        val handoff = coordinator.dataPlaneStalled("lease-stalled")

        assertTrue(handoff is AndroidCoordinatorResult.Accepted)
        val durable = recoveryStore(backend).load()
        assertTrue(durable.intent.desiredActive)
        assertTrue(durable.intent.armedHistory)
        assertEquals(LeasePhase.CLEANUP_PENDING, durable.leaseTransaction?.phase)
        assertEquals("tunnel_data_plane_stalled", durable.leaseTransaction?.cleanupFailureCode)
        assertEquals("new_operation_after_cleanup", durable.intent.retry.pendingAction)
        val stalledStopOperationId = requireNotNull(durable.leaseTransaction?.stopOperationId)

        val cleanupPanel = ServicePanelFake().apply { stopResults += Result.success(Unit) }
        assertEquals(
            AndroidCoordinatorStep.RETRY,
            AndroidConnectionIntentCoordinator(
                recoveryStore(backend),
                operationId = operationIds,
            ).runOnce(cleanupPanel, ServiceRuntimeFake()),
        )
        assertEquals(listOf(stalledStopOperationId), cleanupPanel.stopOperationIds)
        assertEquals(listOf("tunnel_data_plane_stalled"), cleanupPanel.stopFailureCodes)
        val replacement = recoveryStore(backend).load()
        assertTrue(replacement.intent.desiredActive)
        assertEquals(LeasePhase.START_PENDING, replacement.leaseTransaction?.phase)
        assertTrue(replacement.leaseTransaction?.startOperationId != durable.leaseTransaction?.startOperationId)
    }

    @Test
    fun stalledStopFingerprintMatchesTheSharedVersionOneContract() {
        assertEquals(
            "9808141ba59407c91cb5e3b96c4b2051387fe876297dcbacde665c5b656d179f",
            androidStalledStopFingerprint("11111111-1111-4111-8111-111111111111"),
        )
    }

    @Test
    fun stalledStopConflictReconcilesTheExactStopBeforeStartingAReplacement() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val operationIds = SequenceOperationIds()
        val coordinator = AndroidConnectionIntentCoordinator(store, operationId = operationIds)
        coordinator.begin(template())
        val initial = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.success(startResult("lease-stalled"))
        }
        assertEquals(AndroidCoordinatorStep.ACTIVE, coordinator.runOnce(initial, ServiceRuntimeFake()))
        assertTrue(coordinator.dataPlaneStalled("lease-stalled") is AndroidCoordinatorResult.Accepted)
        val stalled = requireNotNull(store.load().leaseTransaction)

        val conflict = ServicePanelFake().apply {
            stopResults += Result.failure(BackgroundConnectionException("service_timeout"))
        }
        assertEquals(AndroidCoordinatorStep.RETRY, coordinator.runOnce(conflict, ServiceRuntimeFake()))
        assertEquals(listOf(stalled.stopOperationId), conflict.stopOperationIds)
        assertEquals("reconcile", store.load().intent.retry.pendingAction)

        val reconcile = ServicePanelFake().apply {
            reconcileResults += reconcile(
                state = "terminal",
                leaseId = "lease-stalled",
                leaseStatus = "failed",
            )
        }
        assertEquals(AndroidCoordinatorStep.RETRY, coordinator.runOnce(reconcile, ServiceRuntimeFake()))
        assertEquals(listOf(stalled.stopOperationId), reconcile.reconcileOperationIds)
        assertEquals(listOf("stalled_stop"), reconcile.reconcileKinds)
        val replacement = store.load()
        assertTrue(replacement.intent.desiredActive)
        assertEquals(LeasePhase.START_PENDING, replacement.leaseTransaction?.phase)
        assertTrue(replacement.leaseTransaction?.startOperationId != stalled.startOperationId)
    }

    @Test
    fun absentStalledStopReconcileExactReplaysTheStoredStopIdentity() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val coordinator = coordinator(store)
        coordinator.begin(template())
        assertEquals(
            AndroidCoordinatorStep.ACTIVE,
            coordinator.runOnce(
                ServicePanelFake().apply {
                    reconcileResults += reconcile("not_found")
                    startResults += Result.success(startResult("lease-stalled"))
                },
                ServiceRuntimeFake(),
            ),
        )
        assertTrue(coordinator.dataPlaneStalled("lease-stalled") is AndroidCoordinatorResult.Accepted)
        val stalledStopId = requireNotNull(store.load().leaseTransaction?.stopOperationId)
        assertEquals(
            AndroidCoordinatorStep.RETRY,
            coordinator.runOnce(
                ServicePanelFake().apply {
                    stopResults += Result.failure(BackgroundConnectionException("service_timeout"))
                },
                ServiceRuntimeFake(),
            ),
        )

        val absent = ServicePanelFake().apply { reconcileResults += reconcile("not_found") }
        assertEquals(AndroidCoordinatorStep.RETRY, coordinator.runOnce(absent, ServiceRuntimeFake()))
        assertEquals(listOf(stalledStopId), absent.reconcileOperationIds)
        assertEquals("new_operation_after_cleanup", store.load().intent.retry.pendingAction)

        val exactReplay = ServicePanelFake().apply { stopResults += Result.success(Unit) }
        assertEquals(AndroidCoordinatorStep.RETRY, coordinator.runOnce(exactReplay, ServiceRuntimeFake()))
        assertEquals(listOf(stalledStopId), exactReplay.stopOperationIds)
        assertEquals(listOf("tunnel_data_plane_stalled"), exactReplay.stopFailureCodes)
    }

    @Test
    fun activeLeaseAfterStalledStopReconcileBlocksReplacementUntilExplicitStop() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val coordinator = coordinator(store)
        coordinator.begin(template())
        assertEquals(
            AndroidCoordinatorStep.ACTIVE,
            coordinator.runOnce(
                ServicePanelFake().apply {
                    reconcileResults += reconcile("not_found")
                    startResults += Result.success(startResult("lease-stalled"))
                },
                ServiceRuntimeFake(),
            ),
        )
        assertTrue(coordinator.dataPlaneStalled("lease-stalled") is AndroidCoordinatorResult.Accepted)
        assertEquals(
            AndroidCoordinatorStep.RETRY,
            coordinator.runOnce(
                ServicePanelFake().apply {
                    stopResults += Result.failure(BackgroundConnectionException("service_timeout"))
                },
                ServiceRuntimeFake(),
            ),
        )

        val active = ServicePanelFake().apply {
            reconcileResults += reconcile(
                state = "terminal",
                leaseId = "lease-stalled",
                leaseStatus = "connected",
            )
        }
        assertEquals(AndroidCoordinatorStep.TERMINAL, coordinator.runOnce(active, ServiceRuntimeFake()))
        val blocked = store.load()
        assertTrue(blocked.intent.desiredActive)
        assertEquals("connection_stall_not_recyclable", blocked.intent.retry.lastErrorCode)
        assertEquals(LeasePhase.CLEANUP_PENDING, blocked.leaseTransaction?.phase)

        assertTrue(coordinator.cancelCurrent() is AndroidCoordinatorResult.Accepted)
        val explicitStop = ServicePanelFake().apply { stopResults += Result.success(Unit) }
        assertEquals(AndroidCoordinatorStep.IDLE, coordinator.runOnce(explicitStop, ServiceRuntimeFake()))
        assertEquals(listOf(null), explicitStop.stopFailureCodes)
    }

    @Test
    fun personalStallUsesOrdinaryStopAndPreservesThePersonalTemplate() {
        val personal = template().copy(
            layer = "tic",
            ticConnectionMode = "personal",
            allowAlternate = false,
        )
        val store = recoveryStore(ServiceRecoveryBackend())
        val coordinator = coordinator(store)
        coordinator.begin(personal)
        val panel = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.success(startResult("lease-personal"))
        }
        assertEquals(AndroidCoordinatorStep.ACTIVE, coordinator.runOnce(panel, ServiceRuntimeFake()))

        assertTrue(coordinator.dataPlaneStalled("lease-personal") is AndroidCoordinatorResult.Accepted)
        val cleanupPanel = ServicePanelFake().apply { stopResults += Result.success(Unit) }
        assertEquals(AndroidCoordinatorStep.RETRY, coordinator.runOnce(cleanupPanel, ServiceRuntimeFake()))

        assertEquals(listOf(null), cleanupPanel.stopFailureCodes)
        val replacement = store.load()
        assertEquals(personal, replacement.intent.template)
        assertEquals(LeasePhase.START_PENDING, replacement.leaseTransaction?.phase)
    }

    @Test
    fun pinnedStrayStallUsesOrdinaryStopAndKeepsAlternateSelectionDisabled() {
        val pinned = template().copy(allowAlternate = false)
        val store = recoveryStore(ServiceRecoveryBackend())
        val coordinator = coordinator(store)
        coordinator.begin(pinned)
        val panel = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.success(startResult("lease-pinned"))
        }
        assertEquals(AndroidCoordinatorStep.ACTIVE, coordinator.runOnce(panel, ServiceRuntimeFake()))

        assertTrue(coordinator.dataPlaneStalled("lease-pinned") is AndroidCoordinatorResult.Accepted)
        val cleanup = ServicePanelFake().apply { stopResults += Result.success(Unit) }
        assertEquals(AndroidCoordinatorStep.RETRY, coordinator.runOnce(cleanup, ServiceRuntimeFake()))

        assertEquals(listOf(null), cleanup.stopFailureCodes)
        assertFalse(requireNotNull(store.load().intent.template).allowAlternate)
    }

    @Test
    fun invalidReconcileResponseRemainsBlockedInsteadOfStartingAFreshOperation() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val coordinator = coordinator(store)
        coordinator.begin(template())
        val panel = ServicePanelFake().apply { reconcileResults += reconcile("invalid") }

        assertEquals(AndroidCoordinatorStep.RETRY, coordinator.runOnce(panel, ServiceRuntimeFake()))

        val status = connectionIntentServiceStatus(store.load())
        assertEquals("none", status.status)
        assertFalse(status.desiredActive)
        assertEquals("invalid_background_response", status.lastErrorCode)
    }

    @Test
    fun reconcileOnceIsPersistentlyBoundedAcrossAttempts() {
        val backend = ServiceRecoveryBackend()
        val first = coordinator(recoveryStore(backend))
        first.begin(template())
        val initial = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.failure(
                BackgroundConnectionException("connection_stall_not_recyclable"),
            )
        }
        assertEquals(AndroidCoordinatorStep.RETRY, first.runOnce(initial, ServiceRuntimeFake()))
        assertTrue(recoveryStore(backend).load().intent.retry.reconcileOnceUsed)

        val restored = coordinator(recoveryStore(backend))
        val repeated = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            reconcileResults += reconcile("not_found")
            startResults += Result.failure(
                BackgroundConnectionException("connection_stall_not_recyclable"),
            )
        }
        assertEquals(AndroidCoordinatorStep.RETRY, restored.runOnce(repeated, ServiceRuntimeFake()))
        assertFalse(recoveryStore(backend).load().intent.desiredActive)
    }

    @Test
    fun typedCancelRejectsAStaleGenerationWithoutChangingTheAcceptedIntent() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val coordinator = coordinator(store)
        coordinator.begin(template())
        val accepted = store.load()

        val result = coordinator.cancel(accepted.intent.generation - 1)

        assertEquals(
            AndroidCoordinatorResult.Failure("connection_intent_generation_conflict"),
            result,
        )
        assertEquals(accepted, store.load())
    }

    @Test
    fun capabilityGateRunsBeforeNewPersistenceButNotForDuplicateDurableBegin() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val operationIds = AtomicInteger(0)
        val coordinator = AndroidConnectionIntentCoordinator(
            store,
            operationId = {
                operationIds.incrementAndGet()
                "11111111-1111-4111-8111-111111111112"
            },
        )
        var capabilityEnabled = false
        var validations = 0
        val validate = { _: AndroidIntentTemplate ->
            validations += 1
            if (!capabilityEnabled) {
                throw BackgroundConnectionException("background_credential_capability_unavailable")
            }
        }

        assertEquals(
            AndroidCoordinatorResult.Failure("background_credential_capability_unavailable"),
            coordinator.begin(template(), validate),
        )
        assertEquals(1, validations)
        assertEquals(0, operationIds.get())
        assertEquals(0L, store.load().intent.generation)
        assertNull(store.load().leaseTransaction)

        capabilityEnabled = true
        assertTrue(coordinator.begin(template(), validate) is AndroidCoordinatorResult.Accepted)
        assertEquals(2, validations)
        assertEquals(1, operationIds.get())
        assertEquals(LeasePhase.START_PENDING, store.load().leaseTransaction?.phase)
        assertNull(store.load().intent.retry.pendingAction)

        capabilityEnabled = false
        val duplicate = coordinator.begin(template(), validate)
        assertTrue(duplicate is AndroidCoordinatorResult.Accepted)
        assertEquals(2, validations)
        assertEquals(1, operationIds.get())
    }

    @Test
    fun genuinelyNewIntentRefreshesCapabilityBeforePersistenceWhileDuplicateBeginBypassesRefresh() {
        val recovery = recoveryStore(ServiceRecoveryBackend())
        val connection = coordinator(recovery)
        val credentials = configuredCredentialStore(
            BackgroundCapabilitySnapshot(1, enabled = true, expiresAtUnix = 100),
        )
        var fetches = 0
        val validate = { candidate: AndroidIntentTemplate ->
            refreshAndValidateNewIntentCapability(credentials, candidate, nowUnix = 200) {
                fetches += 1
                assertEquals(0L, recovery.load().intent.generation)
                assertNull(recovery.load().leaseTransaction)
                BackgroundCapabilitySnapshot(2, enabled = true, expiresAtUnix = 500)
            }
        }

        assertTrue(connection.begin(template(), validate) is AndroidCoordinatorResult.Accepted)
        assertEquals(1, fetches)
        assertEquals(LeasePhase.START_PENDING, recovery.load().leaseTransaction?.phase)
        assertNull(recovery.load().intent.retry.pendingAction)
        assertTrue(connection.begin(template(), validate) is AndroidCoordinatorResult.Accepted)
        assertEquals(1, fetches)
        val panel = ServicePanelFake().apply {
            reconcileResults += reconcile("not_found")
            startResults += Result.success(startResult("lease-capability-refresh"))
        }
        assertEquals(
            AndroidCoordinatorStep.ACTIVE,
            connection.runOnce(panel, ServiceRuntimeFake()) {
                error("an already durable operation must not refresh capability")
            },
        )
        assertEquals(1, fetches)
        assertEquals(2L, credentials.read().credentialSuccess().capability?.revision)
    }

    @Test
    fun capabilityRefreshFailureLeavesNewIntentAndStoredSnapshotUntouched() {
        val recovery = recoveryStore(ServiceRecoveryBackend())
        val credentials = configuredCredentialStore(
            BackgroundCapabilitySnapshot(7, enabled = true, expiresAtUnix = 100),
        )
        val before = credentials.read().credentialSuccess()

        val connection = coordinator(recovery)
        val result = connection.begin(template()) { candidate ->
            refreshAndValidateNewIntentCapability(credentials, candidate, nowUnix = 200) {
                throw BackgroundConnectionException("http_5xx", "17")
            }
        }

        assertEquals(AndroidCoordinatorResult.Failure("http_5xx"), result)
        assertEquals(0L, recovery.load().intent.generation)
        assertNull(recovery.load().leaseTransaction)
        val after = credentials.read().credentialSuccess()
        assertEquals(before.revision, after.revision)
        assertEquals(before.capability, after.capability)
    }

    @Test
    fun authoritativeCapabilityDowngradePersistsBeforeNewIntentIsDenied() {
        val recovery = recoveryStore(ServiceRecoveryBackend())
        val credentials = configuredCredentialStore(
            BackgroundCapabilitySnapshot(7, enabled = true, expiresAtUnix = 100),
        )

        val connection = coordinator(recovery)
        val result = connection.begin(template()) { candidate ->
            refreshAndValidateNewIntentCapability(credentials, candidate, nowUnix = 200) {
                BackgroundCapabilitySnapshot(8, enabled = false, expiresAtUnix = 500)
            }
        }

        assertEquals(
            AndroidCoordinatorResult.Failure("background_credential_capability_unavailable"),
            result,
        )
        assertEquals(0L, recovery.load().intent.generation)
        assertNull(recovery.load().leaseTransaction)
        val stored = credentials.read().credentialSuccess().capability
        assertEquals(8L, stored?.revision)
        assertFalse(stored?.enabled ?: true)
    }

    @Test
    fun lowerCapabilityRevisionKeepsTheNewerStoredSnapshot() {
        val recovery = recoveryStore(ServiceRecoveryBackend())
        val credentials = configuredCredentialStore(
            BackgroundCapabilitySnapshot(7, enabled = true, expiresAtUnix = 500),
        )

        val connection = coordinator(recovery)
        val result = connection.begin(template()) { candidate ->
            refreshAndValidateNewIntentCapability(credentials, candidate, nowUnix = 200) {
                BackgroundCapabilitySnapshot(6, enabled = false, expiresAtUnix = 100)
            }
        }

        assertTrue(result is AndroidCoordinatorResult.Accepted)
        assertEquals(LeasePhase.START_PENDING, recovery.load().leaseTransaction?.phase)
        assertEquals(
            BackgroundCapabilitySnapshot(7, enabled = true, expiresAtUnix = 500),
            credentials.read().credentialSuccess().capability,
        )
    }

    @Test
    fun equalCapabilityRevisionCanOnlyDisableAndShortenTheStoredSnapshot() {
        val recovery = recoveryStore(ServiceRecoveryBackend())
        val credentials = configuredCredentialStore(
            BackgroundCapabilitySnapshot(7, enabled = true, expiresAtUnix = 500),
        )

        val connection = coordinator(recovery)
        val result = connection.begin(template()) { candidate ->
            refreshAndValidateNewIntentCapability(credentials, candidate, nowUnix = 200) {
                BackgroundCapabilitySnapshot(7, enabled = false, expiresAtUnix = 400)
            }
        }

        assertEquals(
            AndroidCoordinatorResult.Failure("background_credential_capability_unavailable"),
            result,
        )
        assertEquals(0L, recovery.load().intent.generation)
        assertNull(recovery.load().leaseTransaction)
        assertEquals(
            BackgroundCapabilitySnapshot(7, enabled = false, expiresAtUnix = 400),
            credentials.read().credentialSuccess().capability,
        )
    }

    @Test
    fun unsupportedCapabilityRefreshDurablyDisablesNewWork() {
        val recovery = recoveryStore(ServiceRecoveryBackend())
        val credentials = configuredCredentialStore(
            BackgroundCapabilitySnapshot(7, enabled = true, expiresAtUnix = 500),
        )

        val connection = coordinator(recovery)
        val result = connection.begin(template()) { candidate ->
            refreshAndValidateNewIntentCapability(credentials, candidate, nowUnix = 200) {
                throw BackgroundConnectionException("recovery_contract_unsupported")
            }
        }

        assertEquals(
            AndroidCoordinatorResult.Failure("background_credential_capability_unavailable"),
            result,
        )
        assertEquals(0L, recovery.load().intent.generation)
        assertNull(recovery.load().leaseTransaction)
        assertEquals(
            BackgroundCapabilitySnapshot(7, enabled = false, expiresAtUnix = 200),
            credentials.read().credentialSuccess().capability,
        )
    }

    @Test
    fun stopDuringBlockedCapabilityValidationWinsBeforeCommitAndLateAcknowledgement() {
        val store = recoveryStore(ServiceRecoveryBackend())
        val operationIds = AtomicInteger(0)
        val coordinator = AndroidConnectionIntentCoordinator(
            store,
            operationId = {
                operationIds.incrementAndGet()
                "11111111-1111-4111-8111-111111111112"
            },
        )
        val dispatch = AndroidConnectionIntentDispatchState()
        val ticket = dispatch.start(store.load().intent.generation)
        val validationEntered = CountDownLatch(1)
        val releaseValidation = CountDownLatch(1)
        val result = AtomicReference<AndroidCoordinatorResult>()
        val blockedStart = Thread {
            result.set(executeDispatchedConnectionIntent(dispatch, ticket) {
                coordinator.beginDispatched(
                    template = template(),
                    expectedGeneration = ticket.expectedGeneration,
                    canCommitNewIntent = { dispatch.isCurrent(ticket) },
                    validateNewIntent = {
                        validationEntered.countDown()
                        check(releaseValidation.await(2, TimeUnit.SECONDS))
                    },
                )
            })
        }.apply { start() }
        assertTrue(validationEntered.await(2, TimeUnit.SECONDS))

        val stopped = cancelDispatchedConnectionIntent(dispatch, coordinator::cancelCurrent)
        releaseValidation.countDown()
        blockedStart.join(2_000L)

        assertFalse(blockedStart.isAlive)
        assertTrue(stopped is AndroidCoordinatorResult.Accepted)
        assertEquals(
            AndroidCoordinatorResult.Failure("connection_intent_generation_conflict"),
            result.get(),
        )
        assertEquals(0, operationIds.get())
        val durable = store.load()
        assertEquals(1L, durable.intent.generation)
        assertFalse(durable.intent.desiredActive)
        assertNull(durable.leaseTransaction)
    }

    @Test
    fun terminalRestartValidationFailureLeavesExistingDurableOperationUntouched() {
        val store = recoveryStore(ServiceRecoveryBackend())
        store.beginStart(
            0,
            template(),
            AndroidStartReplay(
                "11111111-1111-4111-8111-111111111112",
                1,
                androidConnectionIntentFingerprint(template(), true),
            ),
        ).successEnvelope()
        store.recordLease(1, "terminal-lease").successEnvelope()
        store.activateCheckpoint(1).successEnvelope()
        store.scheduleTerminalAfterCleanup(
            1,
            "terminal-lease",
            "11111111-1111-4111-8111-111111111114",
            "operation_id_conflict",
        ).successEnvelope()
        store.completeCleanupAsTerminal(1).successEnvelope()
        val before = store.load()
        val operationIds = AtomicInteger(0)
        val coordinator = AndroidConnectionIntentCoordinator(
            store,
            operationId = {
                operationIds.incrementAndGet()
                "11111111-1111-4111-8111-111111111113"
            },
        )

        val result = coordinator.begin(template()) {
            throw BackgroundConnectionException("background_credential_capability_unavailable")
        }

        assertEquals(
            AndroidCoordinatorResult.Failure("background_credential_capability_unavailable"),
            result,
        )
        assertEquals(0, operationIds.get())
        assertEquals(before, store.load())
    }

    @Test
    fun offlineLogoutPersistsCancellationAndCleanupOnlyCredentialBeforeNetwork() {
        val recovery = recoveryStore(ServiceRecoveryBackend())
        val connection = coordinator(recovery)
        connection.begin(template())
        val credentials = configuredCredentialStore()
        val logout = AndroidLogoutCoordinator(
            credentials,
            connection,
            operationId = { "11111111-1111-4111-8111-111111111199" },
        )

        assertTrue(logout.begin() is AndroidLogoutResult.Accepted)
        val step = logout.runOnce(
            ServicePanelFake().apply { reconcileResults += reconcile("cancelled", cancelRequested = true) },
            ServiceRuntimeFake(),
            activate = { _, _, _ -> error("logout has no pending activation") },
            finalize = { _, _, _, _, _ ->
                throw BackgroundConnectionException("background_transport_unavailable")
            },
        )

        assertEquals(AndroidLogoutStep.RETRY, step)
        assertFalse(recovery.load().intent.desiredActive)
        val stored = credentials.read().credentialSuccess()
        assertEquals(BackgroundLogoutPhase.PENDING, stored.logoutState?.phase)
        assertEquals("device-token", stored.cleanupCredential?.token)
        assertEquals(null, stored.active)
    }

    @Test
    fun logoutRunOnceRetriesWithoutFinalizeWhileRedundantRecoveryExists() {
        val recovery = recoveryStore(ServiceRecoveryBackend())
        recovery.beginRedundant(requireNotNull(serviceV2Envelope().redundantTransaction))
            .successEnvelope()
        val credentials = configuredCredentialStore()
        val logout = AndroidLogoutCoordinator(
            credentials,
            coordinator(recovery),
            operationId = { "11111111-1111-4111-8111-111111111197" },
        )
        assertTrue(logout.begin() is AndroidLogoutResult.Accepted)
        var finalizeCalls = 0

        val step = logout.runOnce(
            ServicePanelFake(),
            ServiceRuntimeFake(),
            activate = { _, _, _ -> error("logout has no pending activation") },
            finalize = { _, _, _, _, _ ->
                finalizeCalls += 1
                BackgroundLogoutFinalizeResult("device_revoked_cleanup_accepted", 1)
            },
        )

        assertEquals(AndroidLogoutStep.RETRY, step)
        assertEquals(0, finalizeCalls)
        assertTrue(recovery.load().redundantTransaction != null)
        assertEquals(
            BackgroundLogoutPhase.PENDING,
            credentials.read().credentialSuccess().logoutState?.phase,
        )
    }

    @Test
    fun logoutRunOnceRechecksRedundantRecoveryBeforeFinalize() {
        val backend = ServiceRecoveryBackend()
        val recovery = recoveryStore(backend)
        val replacementBackend = ServiceRecoveryBackend()
        val replacementRecovery = recoveryStore(replacementBackend)
        replacementRecovery.beginRedundant(
            requireNotNull(serviceV2Envelope().redundantTransaction),
        ).successEnvelope()
        val credentials = configuredCredentialStore()
        val logout = AndroidLogoutCoordinator(
            credentials,
            coordinator(recovery),
            operationId = { "11111111-1111-4111-8111-111111111196" },
        )
        assertTrue(logout.begin() is AndroidLogoutResult.Accepted)
        backend.replaceRecordAfterReads(
            additionalReads = 2,
            replacement = replacementBackend.snapshotRecord(),
        )
        var finalizeCalls = 0

        val step = logout.runOnce(
            ServicePanelFake(),
            ServiceRuntimeFake(),
            activate = { _, _, _ -> error("logout has no pending activation") },
            finalize = { _, _, _, _, _ ->
                finalizeCalls += 1
                BackgroundLogoutFinalizeResult("device_revoked_cleanup_accepted", 1)
            },
        )

        assertEquals(AndroidLogoutStep.RETRY, step)
        assertEquals(0, finalizeCalls)
        assertTrue(recovery.load().redundantTransaction != null)
        assertEquals(
            BackgroundLogoutPhase.PENDING,
            credentials.read().credentialSuccess().logoutState?.phase,
        )
    }

    @Test
    fun durableLogoutTombstoneIsAcceptedForRetryWhenConnectionRecoveryReadFails() {
        val credentials = configuredCredentialStore()
        val unreadableConnection = AndroidConnectionIntentCoordinator(
            AndroidRecoveryStore(
                ServiceRecoveryBackend(),
                BootIdentityProvider { null },
            ),
        )
        val logout = AndroidLogoutCoordinator(
            credentials,
            unreadableConnection,
            operationId = { "11111111-1111-4111-8111-111111111198" },
        )

        val result = logout.begin()

        assertTrue(result is AndroidLogoutResult.Accepted)
        val durable = credentials.read().credentialSuccess()
        assertEquals(BackgroundLogoutPhase.PENDING, durable.logoutState?.phase)
        assertEquals("device-token", durable.cleanupCredential?.token)
        assertNull(durable.active)
    }

    @Test
    fun lostActivationResponseThenOfflineLogoutExactReplaysBeforeCleanupAfterProcessDeath() {
        val credentialBackend = ServiceRecoveryBackend()
        var credentials = BackgroundCredentialStore(credentialBackend)
        credentials.configure(
            0,
            BackgroundCredentialProvision(
                deviceId = "11111111-1111-4111-8111-111111111111",
                panelBase = "https://panel.example.test/",
                token = "old-active-token",
                expiresAtUnix = 100,
                installSecret = "install-secret-value",
                installGeneration = 1,
                capability = BackgroundCapabilitySnapshot(1, true, 2_000_000_000),
            ),
        ).credentialSuccess()
        val prepareId = "11111111-1111-4111-8111-111111111140"
        val activationId = "11111111-1111-4111-8111-111111111141"
        credentials.reserveMutation(
            1,
            prepareId,
            "11111111-1111-4111-8111-111111111111",
            expiresAtUnix = 500,
            nowUnix = 200,
            activationOperationId = activationId,
        ).credentialSuccess()
        credentials.savePendingToken(
            1,
            prepareId,
            BackgroundPendingToken(
                token = "server-active-staged-token",
                stagedExpiresAtUnix = 300,
                tokenGeneration = 2,
                prepareOperationId = prepareId,
                activationOperationId = activationId,
                contractVersion = 1,
            ),
            nowUnix = 200,
        ).credentialSuccess()
        val recoveryBackend = ServiceRecoveryBackend()
        val connection = coordinator(recoveryStore(recoveryBackend))
        connection.begin(template())
        val logoutId = "11111111-1111-4111-8111-111111111142"
        val logout = AndroidLogoutCoordinator(credentials, connection) { logoutId }

        assertTrue(logout.begin() is AndroidLogoutResult.Accepted)
        val durableLogout = credentials.read().credentialSuccess()
        assertEquals("old-active-token", durableLogout.cleanupCredential?.token)
        assertEquals("server-active-staged-token", durableLogout.pending?.token)
        assertEquals(activationId, durableLogout.pending?.activationOperationId)

        val firstPanel = ServicePanelFake()
        val first = logout.runOnce(
            firstPanel,
            ServiceRuntimeFake(),
            activate = { credential, pending, _ ->
                assertEquals("server-active-staged-token", credential.token)
                assertEquals(activationId, pending.activationOperationId)
                throw BackgroundConnectionException("background_panel_error")
            },
            finalize = { _, _, _, _, _ -> error("generic 401 must retry before finalize") },
        )

        assertEquals(AndroidLogoutStep.RETRY, first)
        assertTrue(firstPanel.cancelIfAbsent.isEmpty())
        credentials = BackgroundCredentialStore(credentialBackend)
        val afterGeneric401 = credentials.read().credentialSuccess()
        assertEquals("old-active-token", afterGeneric401.cleanupCredential?.token)
        assertEquals("server-active-staged-token", afterGeneric401.pending?.token)

        val restartedPanel = ServicePanelFake().apply {
            reconcileResults += reconcile("pending")
        }
        val events = mutableListOf<String>()
        val restarted = AndroidLogoutCoordinator(
            credentials,
            coordinator(recoveryStore(recoveryBackend)),
        ) { error("the durable logout operation id must be reused") }
        val replayed = restarted.runOnce(
            restartedPanel,
            ServiceRuntimeFake(),
            activate = { credential, pending, _ ->
                assertTrue(restartedPanel.cancelIfAbsent.isEmpty())
                events += "activate:${credential.token}:${pending.activationOperationId}"
                BackgroundActivationResult(2, 10_000)
            },
            finalize = { credential, _, _, operationId, _ ->
                error("pending connection cleanup must defer finalize for $credential/$operationId")
            },
        )

        assertEquals(AndroidLogoutStep.RETRY, replayed)
        assertEquals(
            listOf("activate:server-active-staged-token:$activationId"),
            events,
        )
        credentials = BackgroundCredentialStore(credentialBackend)
        val selectedAfterReplay = credentials.read().credentialSuccess()
        assertNull(selectedAfterReplay.pending)
        assertEquals("server-active-staged-token", selectedAfterReplay.cleanupCredential?.token)
        assertEquals(10_000L, selectedAfterReplay.cleanupCredential?.expiresAtUnix)

        val completed = AndroidLogoutCoordinator(
            credentials,
            coordinator(recoveryStore(recoveryBackend)),
        ) { error("the durable logout operation id must be reused") }.runOnce(
            ServicePanelFake().apply {
                reconcileResults += reconcile("cancelled", cancelRequested = true)
            },
            ServiceRuntimeFake(),
            activate = { _, _, _ -> error("the durable authoritative selection must be reused") },
            finalize = { credential, _, _, operationId, _ ->
                events += "finalize:${credential.token}:$operationId:${credential.expiresAtUnix}"
                BackgroundLogoutFinalizeResult("device_revoked_cleanup_accepted", 1)
            },
        )

        assertEquals(AndroidLogoutStep.COMPLETE, completed)
        assertEquals(
            listOf(
                "activate:server-active-staged-token:$activationId",
                "finalize:server-active-staged-token:$logoutId:10000",
            ),
            events,
        )
        val finalized = credentials.read().credentialSuccess()
        assertEquals(BackgroundLogoutPhase.FINALIZED, finalized.logoutState?.phase)
        assertNull(finalized.pending)
        assertNull(finalized.cleanupCredential)
        assertNull(finalized.installSecret)
    }

    @Test
    fun authoritativeActivationNotAppliedFinalizesWithThePreservedOldCredential() {
        val credentials = configuredCredentialStore()
        val prepareId = "11111111-1111-4111-8111-111111111143"
        val activationId = "11111111-1111-4111-8111-111111111144"
        credentials.reserveMutation(
            1,
            prepareId,
            "11111111-1111-4111-8111-111111111111",
            expiresAtUnix = 500,
            nowUnix = 200,
            activationOperationId = activationId,
        ).credentialSuccess()
        credentials.savePendingToken(
            1,
            prepareId,
            BackgroundPendingToken(
                token = "not-applied-staged-token",
                stagedExpiresAtUnix = 300,
                tokenGeneration = 2,
                prepareOperationId = prepareId,
                activationOperationId = activationId,
                contractVersion = 1,
            ),
            nowUnix = 200,
        ).credentialSuccess()
        val logout = AndroidLogoutCoordinator(
            credentials,
            coordinator(recoveryStore(ServiceRecoveryBackend())),
        ) { "11111111-1111-4111-8111-111111111145" }
        logout.begin()
        var finalizedToken: String? = null

        val step = logout.runOnce(
            ServicePanelFake(),
            ServiceRuntimeFake(),
            activate = { _, pending, _ ->
                assertEquals(activationId, pending.activationOperationId)
                throw BackgroundConnectionException("activation_not_applied")
            },
            finalize = { credential, _, _, _, _ ->
                finalizedToken = credential.token
                BackgroundLogoutFinalizeResult("device_revoked_cleanup_accepted", 0)
            },
        )

        assertEquals(AndroidLogoutStep.COMPLETE, step)
        assertEquals("device-token", finalizedToken)
        val finalized = credentials.read().credentialSuccess()
        assertEquals(BackgroundLogoutPhase.FINALIZED, finalized.logoutState?.phase)
        assertNull(finalized.pending)
        assertNull(finalized.cleanupCredential)
    }

    @Test
    fun lostLogoutFinalizeResponseReplaysTheStoredOperationEvenAfterTwentyFourHours() {
        val recovery = recoveryStore(ServiceRecoveryBackend())
        val connection = coordinator(recovery)
        val credentials = configuredCredentialStore()
        val logoutId = "11111111-1111-4111-8111-111111111198"
        val logout = AndroidLogoutCoordinator(credentials, connection) { logoutId }
        logout.begin()
        val observed = mutableListOf<String>()
        var calls = 0
        val finalize = { _: BackgroundCredential, _: String, _: Long, operationId: String, _: String ->
            observed += operationId
            calls += 1
            if (calls == 1) {
                throw BackgroundConnectionException("background_transport_unavailable")
            }
            BackgroundLogoutFinalizeResult("device_revoked_cleanup_accepted", 1)
        }

        assertEquals(
            AndroidLogoutStep.RETRY,
            logout.runOnce(
                ServicePanelFake(),
                ServiceRuntimeFake(),
                activate = { _, _, _ -> error("logout has no pending activation") },
                finalize = finalize,
            ),
        )
        assertEquals(
            AndroidLogoutStep.COMPLETE,
            AndroidLogoutCoordinator(credentials, connection) { "replacement-must-not-be-used" }
                .runOnce(
                    ServicePanelFake(),
                    ServiceRuntimeFake(),
                    activate = { _, _, _ -> error("logout has no pending activation") },
                    finalize = finalize,
                ),
        )

        assertEquals(listOf(logoutId, logoutId), observed)
        val stored = credentials.read().credentialSuccess()
        assertEquals(BackgroundLogoutPhase.FINALIZED, stored.logoutState?.phase)
        assertEquals(null, stored.cleanupCredential)
        assertEquals(null, stored.installSecret)
    }

    @Test
    fun repeatedLogoutBeginKeepsTheExactStoredFinalizeOperation() {
        val recovery = recoveryStore(ServiceRecoveryBackend())
        val connection = coordinator(recovery)
        val credentials = configuredCredentialStore()
        val operationIds = ArrayDeque(listOf(
            "11111111-1111-4111-8111-111111111128",
            "11111111-1111-4111-8111-111111111129",
        ))
        val logout = AndroidLogoutCoordinator(credentials, connection) {
            operationIds.removeFirst()
        }

        assertTrue(logout.begin() is AndroidLogoutResult.Accepted)
        assertTrue(logout.begin() is AndroidLogoutResult.Accepted)

        val stored = credentials.read().credentialSuccess()
        assertEquals("11111111-1111-4111-8111-111111111128", stored.logoutState?.operationId)
    }

    @Test
    fun restoredLogoutTombstoneCancelsConnectionBeforeAnyReconcileOrFinalize() {
        val recoveryBackend = ServiceRecoveryBackend()
        val connection = coordinator(recoveryStore(recoveryBackend))
        connection.begin(template())
        val credentials = configuredCredentialStore()
        val logoutId = "11111111-1111-4111-8111-111111111130"
        assertTrue(
            (credentials.beginLogoutCurrent(logoutId) as CredentialStoreResult.Success).value is
                BackgroundLogoutBegin.Owned,
        )
        assertTrue(recoveryStore(recoveryBackend).load().intent.desiredActive)

        val panel = ServicePanelFake().apply {
            reconcileResults += reconcile("cancelled", cancelRequested = true)
        }
        val step = AndroidLogoutCoordinator(
            credentials,
            coordinator(recoveryStore(recoveryBackend)),
        ).runOnce(
            panel,
            ServiceRuntimeFake(),
            activate = { _, _, _ -> error("logout has no pending activation") },
            finalize = { _, _, _, operationId, _ ->
                assertEquals(logoutId, operationId)
                BackgroundLogoutFinalizeResult("device_revoked_cleanup_accepted", 1)
            },
        )

        assertEquals(AndroidLogoutStep.COMPLETE, step)
        assertFalse(recoveryStore(recoveryBackend).load().intent.desiredActive)
        assertEquals(listOf(true), panel.cancelIfAbsent)
        assertEquals(BackgroundLogoutPhase.FINALIZED, credentials.read().credentialSuccess().logoutState?.phase)
    }

    @Test
    fun logoutWithoutAProvisionedBackgroundCredentialReportsNotOwnedAndCancelsConnectionIntent() {
        val recovery = recoveryStore(ServiceRecoveryBackend())
        val connection = coordinator(recovery)
        connection.begin(template())
        val credentials = BackgroundCredentialStore(ServiceRecoveryBackend())

        val result = AndroidLogoutCoordinator(credentials, connection).begin()

        assertTrue(result is AndroidLogoutResult.NotOwned)
        assertFalse(recovery.load().intent.desiredActive)
    }

    @Test
    fun logoutTombstonesInitialPendingActivationBeforeItsConcurrentResponseCanPromote() {
        val recovery = recoveryStore(ServiceRecoveryBackend())
        val connection = coordinator(recovery)
        connection.begin(template())
        val credentials = BackgroundCredentialStore(ServiceRecoveryBackend())
        val activationEntered = CountDownLatch(1)
        val releaseActivation = CountDownLatch(1)
        val provisionFailure = AtomicReference<String?>(null)
        val provision = Thread {
            try {
                provisionBackgroundCredential(
                    store = credentials,
                    request = BackgroundUiProvisionRequest(
                        expectedRevision = 0,
                        deviceId = "11111111-1111-4111-8111-111111111111",
                        panelBase = "https://panel.example.test/",
                        accessToken = "ui-access-token",
                        installSecret = "install-secret-value",
                        installGeneration = 1,
                        capability = BackgroundCapabilitySnapshot(1, true, 2_000_000_000),
                    ),
                    nowUnix = 1_000,
                    operationIds = {
                        "11111111-1111-4111-8111-111111111120" to
                            "11111111-1111-4111-8111-111111111121"
                    },
                    prepare = { _, prepareId, activateId, _ ->
                        BackgroundPendingToken(
                            token = "staged-token",
                            stagedExpiresAtUnix = 2_000,
                            tokenGeneration = 1,
                            prepareOperationId = prepareId,
                            activationOperationId = activateId,
                            contractVersion = 1,
                        )
                    },
                    activate = { _, _, _ ->
                        activationEntered.countDown()
                        check(releaseActivation.await(2, TimeUnit.SECONDS))
                        BackgroundActivationResult(1, 3_000)
                    },
                )
            } catch (error: BackgroundConnectionException) {
                provisionFailure.set(error.code)
            }
        }.apply { start() }
        assertTrue(activationEntered.await(2, TimeUnit.SECONDS))

        val logoutId = "11111111-1111-4111-8111-111111111122"
        val logout = AndroidLogoutCoordinator(credentials, connection) { logoutId }
        assertTrue(logout.begin() is AndroidLogoutResult.Accepted)

        val tombstone = credentials.read().credentialSuccess()
        assertFalse(recovery.load().intent.desiredActive)
        assertEquals(BackgroundLogoutPhase.PENDING, tombstone.logoutState?.phase)
        assertEquals(null, tombstone.cleanupCredential)
        assertEquals("staged-token", tombstone.pending?.token)
        assertEquals(
            "11111111-1111-4111-8111-111111111121",
            tombstone.pending?.activationOperationId,
        )
        assertEquals(
            "11111111-1111-4111-8111-111111111120",
            tombstone.reservation?.mutationId,
        )

        releaseActivation.countDown()
        provision.join(2_000L)
        assertFalse(provision.isAlive)
        assertEquals("background_credential_revision_conflict", provisionFailure.get())

        val events = mutableListOf<String>()
        val step = logout.runOnce(
            ServicePanelFake().apply { reconcileResults += reconcile("cancelled", cancelRequested = true) },
            ServiceRuntimeFake(),
            activate = { credential, pending, _ ->
                events += "activate:${credential.token}:${pending.activationOperationId}"
                BackgroundActivationResult(1, 3_000)
            },
            finalize = { cleanupCredential, _, _, operationId, _ ->
                events += "finalize:${cleanupCredential.token}:$operationId"
                BackgroundLogoutFinalizeResult("device_revoked_cleanup_accepted", 1)
            },
        )
        assertEquals(AndroidLogoutStep.COMPLETE, step)
        assertEquals(
            listOf(
                "activate:staged-token:11111111-1111-4111-8111-111111111121",
                "finalize:staged-token:$logoutId",
            ),
            events,
        )
    }

    @Test
    fun logoutDuringInitialReservationReportsNotOwnedAndInvalidatesLateProvision() {
        val recovery = recoveryStore(ServiceRecoveryBackend())
        val connection = coordinator(recovery)
        connection.begin(template())
        val credentials = BackgroundCredentialStore(ServiceRecoveryBackend())
        val prepareEntered = CountDownLatch(1)
        val releasePrepare = CountDownLatch(1)
        val provisionFailure = AtomicReference<String?>(null)
        val provision = Thread {
            try {
                provisionBackgroundCredential(
                    store = credentials,
                    request = BackgroundUiProvisionRequest(
                        expectedRevision = 0,
                        deviceId = "11111111-1111-4111-8111-111111111111",
                        panelBase = "https://panel.example.test/",
                        accessToken = "ui-access-token",
                        installSecret = "install-secret-value",
                        installGeneration = 1,
                        capability = BackgroundCapabilitySnapshot(1, true, 2_000_000_000),
                    ),
                    nowUnix = 1_000,
                    operationIds = {
                        "11111111-1111-4111-8111-111111111123" to
                            "11111111-1111-4111-8111-111111111124"
                    },
                    prepare = { _, prepareId, activateId, _ ->
                        prepareEntered.countDown()
                        check(releasePrepare.await(2, TimeUnit.SECONDS))
                        BackgroundPendingToken(
                            token = "late-staged-token",
                            stagedExpiresAtUnix = 2_000,
                            tokenGeneration = 1,
                            prepareOperationId = prepareId,
                            activationOperationId = activateId,
                            contractVersion = 1,
                        )
                    },
                    activate = { _, _, _ -> error("late reservation must not activate") },
                )
            } catch (error: BackgroundConnectionException) {
                provisionFailure.set(error.code)
            }
        }.apply { start() }
        assertTrue(prepareEntered.await(2, TimeUnit.SECONDS))

        val logout = AndroidLogoutCoordinator(credentials, connection) {
            "11111111-1111-4111-8111-111111111125"
        }
        assertTrue(logout.begin() is AndroidLogoutResult.NotOwned)
        val beforeCleanup = credentials.read().credentialSuccess()

        releasePrepare.countDown()
        provision.join(2_000L)
        assertFalse(provision.isAlive)
        assertEquals("background_credential_revision_conflict", provisionFailure.get())
        assertNull(beforeCleanup.logoutState)
        assertEquals(null, beforeCleanup.cleanupCredential)
        assertNull(beforeCleanup.reservation)
        assertTrue(recovery.load().leaseTransaction != null)
        assertFalse(recovery.load().intent.desiredActive)
        assertNull(credentials.read().credentialSuccess().installSecret)
    }

    @Test
    fun logoutInvalidatesInitialProvisionRevisionEvenBeforeReservationCommit() {
        val recovery = recoveryStore(ServiceRecoveryBackend())
        val connection = coordinator(recovery)
        val credentials = BackgroundCredentialStore(ServiceRecoveryBackend())
        val operationIdsEntered = CountDownLatch(1)
        val releaseOperationIds = CountDownLatch(1)
        val provisionFailure = AtomicReference<String?>(null)
        val provision = Thread {
            try {
                provisionBackgroundCredential(
                    store = credentials,
                    request = BackgroundUiProvisionRequest(
                        expectedRevision = 0,
                        deviceId = "11111111-1111-4111-8111-111111111111",
                        panelBase = "https://panel.example.test/",
                        accessToken = "ui-access-token",
                        installSecret = "install-secret-value",
                        installGeneration = 1,
                        capability = BackgroundCapabilitySnapshot(1, true, 2_000_000_000),
                    ),
                    nowUnix = 1_000,
                    operationIds = {
                        operationIdsEntered.countDown()
                        check(releaseOperationIds.await(2, TimeUnit.SECONDS))
                        "11111111-1111-4111-8111-111111111126" to
                            "11111111-1111-4111-8111-111111111127"
                    },
                    prepare = { _, _, _, _ -> error("stale provision must not reach prepare") },
                    activate = { _, _, _ -> error("stale provision must not reach activate") },
                )
            } catch (error: BackgroundConnectionException) {
                provisionFailure.set(error.code)
            }
        }.apply { start() }
        assertTrue(operationIdsEntered.await(2, TimeUnit.SECONDS))

        assertTrue(
            AndroidLogoutCoordinator(credentials, connection).begin() is AndroidLogoutResult.NotOwned,
        )

        releaseOperationIds.countDown()
        provision.join(2_000L)
        assertFalse(provision.isAlive)
        assertEquals("background_credential_revision_conflict", provisionFailure.get())
        val invalidated = credentials.read().credentialSuccess()
        assertEquals(1L, invalidated.revision)
        assertEquals(null, invalidated.active)
        assertEquals(null, invalidated.reservation)
    }

    @Test
    fun backgroundFailureIsShownBeforeDiagnosticsFinish() {
        val events = mutableListOf<String>()
        var diagnosticsComplete: (() -> Unit)? = null

        completeBackgroundFailureWithDiagnostics(
            queueDiagnostics = { onComplete ->
                events += "diagnostics_queued"
                diagnosticsComplete = onComplete
            },
            finishUserAction = { events += "failure_shown" },
            finishDeferredServiceStop = { events += "service_stopped" },
        )

        assertEquals(listOf("failure_shown", "diagnostics_queued"), events)

        diagnosticsComplete?.invoke()

        assertEquals(
            listOf("failure_shown", "diagnostics_queued", "service_stopped"),
            events,
        )
    }

    @Test
    fun diagnosticsQueueFailureDoesNotKeepTheForegroundServiceAlive() {
        val events = mutableListOf<String>()

        completeBackgroundFailureWithDiagnostics(
            queueDiagnostics = { error("diagnostics executor unavailable") },
            finishUserAction = { events += "failure_shown" },
            finishDeferredServiceStop = { events += "service_stopped" },
        )

        assertEquals(listOf("failure_shown", "service_stopped"), events)
    }

    @Test
    fun diagnosticBackendVersionReplacesUnhelpfulLocalBuildMarkers() {
        assertEquals("git-08d68cd", diagnosticBackendVersion("(devel)"))
        assertEquals("git-08d68cd", diagnosticBackendVersion("unknown"))
        assertEquals("3.0.1", diagnosticBackendVersion("3.0.1"))
    }

    @Test
    fun dataPlaneDiagnosticsDistinguishHandshakeAndEncryptedCounterActivity() {
        assertEquals(20L, counterDelta(null, 20L))
        assertEquals(5L, counterDelta(20L, 25L))
        assertEquals(3L, counterDelta(20L, 3L))
        assertEquals(
            "waiting_for_handshake",
            tunnelDataPlaneState(60, null, 10, 10),
        )
        assertEquals(
            "encrypted_counter_activity",
            tunnelDataPlaneState(60, 1_000, 1, 0),
        )
        assertEquals(
            "handshake_without_counter_activity",
            tunnelDataPlaneState(60, 1_000, 0, 0),
        )
    }

    @Test
    fun idleVpnProcessIsRecycledAfterTunnelStops() {
        assertTrue(
            shouldRecycleIdleVpnProcess(
                SessionState.STOPPED,
                desiredActive = false,
            ),
        )
        assertFalse(
            shouldRecycleIdleVpnProcess(
                SessionState.RUNNING,
                desiredActive = true,
            ),
        )
        assertFalse(
            shouldRecycleIdleVpnProcess(
                SessionState.STOPPED,
                desiredActive = true,
            ),
        )
    }

    @Test
    fun aNewServiceCommandCancelsThePendingIdleStop() {
        val scheduled = mutableListOf<Runnable>()
        var stops = 0
        val debounce = IdleStopDebouncer(
            delayMillis = 400L,
            schedule = { task, _ -> scheduled += task },
            cancel = scheduled::remove,
        )

        debounce.schedule { stops += 1 }
        debounce.cancel()

        assertTrue(scheduled.isEmpty())
        assertEquals(0, stops)
    }

    @Test
    fun repeatedIdleChecksKeepOnlyTheLatestStop() {
        val scheduled = mutableListOf<Runnable>()
        var stops = 0
        val debounce = IdleStopDebouncer(
            delayMillis = 400L,
            schedule = { task, _ -> scheduled += task },
            cancel = scheduled::remove,
        )

        debounce.schedule { stops += 1 }
        debounce.schedule { stops += 1 }
        assertEquals(1, scheduled.size)

        scheduled.single().run()

        assertEquals(1, stops)
    }

    @Test
    fun aConcurrentNewCommandInvalidatesAnOlderIdleStopBeforeItIsPosted() {
        val scheduled = CopyOnWriteArrayList<Runnable>()
        val schedulerEnteredCancel = CountDownLatch(1)
        val releaseScheduler = CountDownLatch(1)
        val stops = AtomicInteger(0)
        val debounce = IdleStopDebouncer(
            delayMillis = 400L,
            schedule = { task, _ -> scheduled += task },
            cancel = { task ->
                scheduled.remove(task)
                if (Thread.currentThread().name == "stale-idle-stop-scheduler") {
                    schedulerEnteredCancel.countDown()
                    check(releaseScheduler.await(2, TimeUnit.SECONDS))
                }
            },
        )

        debounce.schedule { stops.incrementAndGet() }
        val staleScheduler = Thread(
            { debounce.schedule { stops.incrementAndGet() } },
            "stale-idle-stop-scheduler",
        ).apply { start() }
        assertTrue(schedulerEnteredCancel.await(2, TimeUnit.SECONDS))

        debounce.cancel()
        releaseScheduler.countDown()
        staleScheduler.join(2_000L)
        assertFalse(staleScheduler.isAlive)
        scheduled.forEach(Runnable::run)

        assertEquals(0, stops.get())
    }

    @Test
    fun only_real_background_start_failures_queue_diagnostics() {
        assertTrue(
            shouldQueueBackgroundStartFailureDiagnostics(
                starting = true,
                errorCode = "configuration_fetch_failed",
            ),
        )
        assertFalse(
            shouldQueueBackgroundStartFailureDiagnostics(
                starting = false,
                errorCode = "configuration_fetch_failed",
            ),
        )
        assertFalse(
            shouldQueueBackgroundStartFailureDiagnostics(
                starting = true,
                errorCode = "tunnel_operation_in_progress",
            ),
        )
        assertFalse(shouldQueueBackgroundStartFailureDiagnostics(starting = true, errorCode = null))
    }

    @Test
    fun restoresDesiredTunnelAfterRuntimeWasLost() {
        assertTrue(shouldRestoreDesiredTunnel(true, SessionState.STOPPED))
        assertTrue(shouldRestoreDesiredTunnel(true, SessionState.FAILED))
    }

    @Test
    fun doesNotDuplicateRunningOrStartingTunnel() {
        assertFalse(shouldRestoreDesiredTunnel(true, SessionState.RUNNING))
        assertFalse(shouldRestoreDesiredTunnel(true, SessionState.STARTING))
    }

    @Test
    fun doesNotRestoreTunnelThatUserStopped() {
        assertFalse(shouldRestoreDesiredTunnel(false, SessionState.STOPPED))
        assertFalse(shouldRestoreDesiredTunnel(false, SessionState.FAILED))
    }

    @Test
    fun timedOutStartOnlyCancelsItsOwnActiveSession() {
        assertTrue(shouldCancelActiveClientStart("operation-a", "operation-a"))
        assertFalse(shouldCancelActiveClientStart("operation-a", "operation-b"))
        assertFalse(shouldCancelActiveClientStart("operation-a", null))
    }

    private fun recoveryStore(
        backend: ServiceRecoveryBackend,
        bootCount: Long = 7,
    ) = AndroidRecoveryStore(backend, BootIdentityProvider { bootCount })

    private fun configuredCredentialStore(
        capability: BackgroundCapabilitySnapshot =
            BackgroundCapabilitySnapshot(1, true, 2_000_000_000),
    ): BackgroundCredentialStore {
        val store = BackgroundCredentialStore(ServiceRecoveryBackend())
        check(store.configure(
            0,
            BackgroundCredentialProvision(
                deviceId = "11111111-1111-4111-8111-111111111111",
                panelBase = "https://panel.example.test/",
                token = "device-token",
                expiresAtUnix = 2_000_000_000,
                installSecret = "install-secret-value",
                installGeneration = 1,
                capability = capability,
            ),
        ) is CredentialStoreResult.Success)
        return store
    }

    private fun coordinator(store: AndroidRecoveryStore) = AndroidConnectionIntentCoordinator(
        store,
        operationId = SequenceOperationIds(),
    )

    private fun template() = AndroidIntentTemplate(
        deviceId = "11111111-1111-4111-8111-111111111111",
        accountScope = "account-1",
        layer = "stray",
        ticConnectionMode = "dynamic",
        routeMode = "standalone",
        egressMode = "ipv4",
        allowAlternate = true,
    )

    private fun startResult(leaseId: String) = BackgroundStartResult(
        configuration = "[Interface]".toByteArray(),
        connection = QuickConnectionArgs().apply {
            this.leaseId = leaseId
            layer = "stray"
            ticConnectionMode = "dynamic"
            routeMode = "standalone"
            egressMode = "ipv4"
            allowAlternate = true
        },
        options = TunnelOptionsArgs(),
    )

    private fun reconcile(
        state: String,
        leaseId: String? = null,
        cancelRequested: Boolean = false,
        leaseStatus: String? = null,
    ) = BackgroundReconcileResult(
        state,
        cancelRequested,
        leaseId,
        leaseStatus,
        0,
        null,
    )
}

private fun serviceV1Envelope() = AndroidRecoveryEnvelope(
    formatVersion = ANDROID_RECOVERY_FORMAT,
    intent = AndroidConnectionIntent.empty(1),
    leaseTransaction = null,
    redundantTransaction = null,
)

private fun serviceV2Envelope() = serviceV1Envelope().copy(
    redundantTransaction = AndroidRedundantTransaction(
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
        slotBLeaseId = "lease-b",
        localActiveLeaseId = "lease-a",
        standbyDesired = true,
        roleGeneration = 1,
        membershipGeneration = 1,
        startOperationId = "start-operation",
        startRequestFingerprint = "fingerprint",
    ),
)

private class ServiceRedundantOwner(
    private val closeResults: ArrayDeque<Boolean?> = ArrayDeque(),
) : RedundantVpnProcessOwner {
    val validatedNetworks = mutableListOf<Boolean>()
    var closeCalls = 0
    var revokeCalls = 0
    override fun recover(): Boolean = true
    override fun resume(): Boolean = true
    override fun revoke(): Boolean {
        revokeCalls += 1
        return true
    }
    override fun closeLocal(): Boolean {
        closeCalls += 1
        if (closeResults.isEmpty()) return true
        return closeResults.removeFirst()
            ?: throw IllegalStateException("close_failed")
    }
    override fun onUnderlyingNetworkChanged(validated: Boolean): Boolean {
        validatedNetworks += validated
        return true
    }
}

private class FakeRedundantSessionBackend : RedundantSessionBackend {
    val startedTunFds = mutableListOf<Int>()
    val startedSlots = mutableListOf<Int>()

    override fun start(tunFd: Int, primaryConfiguration: ByteArray): NativeSession? {
        startedTunFds += tunFd
        primaryConfiguration.fill(0)
        return NativeSession(7)
    }

    override fun startSlot(
        session: NativeSession,
        slot: Int,
        configuration: ByteArray,
    ): Boolean {
        startedSlots += slot
        configuration.fill(0)
        return true
    }

    override fun close(session: NativeSession) = Unit
}

private fun CredentialStoreResult<BackgroundCredentialEnvelope>.credentialSuccess():
    BackgroundCredentialEnvelope = (this as CredentialStoreResult.Success).value

private class ServiceRecoveryBackend : EncryptedRecordBackend {
    private var record: ByteArray? = null
    private var replaceAfterReadCount: Int? = null
    private var replacementRecord: ByteArray? = null
    var readCount: Int = 0
    var writeSucceeds: Boolean = true

    override fun read(): ByteArray? {
        readCount += 1
        val current = record?.copyOf()
        if (readCount == replaceAfterReadCount) {
            record = replacementRecord?.copyOf()
            replaceAfterReadCount = null
            replacementRecord = null
        }
        return current
    }

    override fun write(plaintext: ByteArray): Boolean {
        if (!writeSucceeds) return false
        record = plaintext.copyOf()
        return true
    }

    fun snapshotRecord(): ByteArray = requireNotNull(record).copyOf()

    fun replaceRecordAfterReads(additionalReads: Int, replacement: ByteArray) {
        require(additionalReads > 0)
        replaceAfterReadCount = readCount + additionalReads
        replacementRecord = replacement.copyOf()
    }
}

private class ServiceCancelTombstoneBackend : RedundantCancelTombstoneBackend {
    var record: String? = null
    var writeSucceeds: Boolean = true

    override fun read(): String? = record

    override fun compareAndWrite(expected: String?, value: String): Boolean {
        if (record != expected) return false
        if (!writeSucceeds) return false
        record = value
        return true
    }

    override fun compareAndClear(expected: String): Boolean {
        if (record != expected) return false
        record = null
        return true
    }
}

private class SequenceOperationIds : () -> String {
    private val next = AtomicInteger(0)

    override fun invoke(): String = when (next.getAndIncrement()) {
        0 -> "11111111-1111-4111-8111-111111111112"
        1 -> "11111111-1111-4111-8111-111111111113"
        else -> "11111111-1111-4111-8111-${(111111111114L + next.get()).toString().padStart(12, '0')}"
    }
}

private class ServicePanelFake : AndroidConnectionIntentPanel {
    val reconcileResults = ArrayDeque<BackgroundReconcileResult>()
    val startResults = ArrayDeque<Result<BackgroundStartResult>>()
    val bindingSyncResults = ArrayDeque<Result<Unit>>()
    val stopResults = ArrayDeque<Result<Unit>>()
    val startOperationIds = mutableListOf<String>()
    val bindingSyncTemplates = mutableListOf<AndroidIntentTemplate>()
    val stopOperationIds = mutableListOf<String?>()
    val stopLeaseIds = mutableListOf<String>()
    val stopFailureCodes = mutableListOf<String?>()
    val reconcileOperationIds = mutableListOf<String>()
    val reconcileKinds = mutableListOf<String>()
    val cancelIfAbsent = mutableListOf<Boolean>()
    var onStart: () -> Unit = {}
    var onBindingSync: () -> Unit = {}
    var onReconcile: () -> Unit = {}

    override fun reconcile(
        transaction: AndroidLeaseTransaction,
        cancelIfAbsent: Boolean,
    ): BackgroundReconcileResult {
        this.cancelIfAbsent += cancelIfAbsent
        reconcileOperationIds += if (transaction.cleanupFailureCode == "tunnel_data_plane_stalled") {
            requireNotNull(transaction.stopOperationId)
        } else {
            transaction.startOperationId
        }
        reconcileKinds += if (transaction.cleanupFailureCode == "tunnel_data_plane_stalled") {
            "stalled_stop"
        } else {
            "start"
        }
        onReconcile()
        return reconcileResults.removeFirst()
    }

    override fun start(
        template: AndroidIntentTemplate,
        transaction: AndroidLeaseTransaction,
    ): BackgroundStartResult {
        startOperationIds += transaction.startOperationId
        onStart()
        return startResults.removeFirst().getOrThrow()
    }

    override fun syncBindingPreferences(template: AndroidIntentTemplate) {
        bindingSyncTemplates += template
        onBindingSync()
        bindingSyncResults.removeFirstOrNull()?.getOrThrow()
    }

    override fun stop(leaseId: String, operationId: String, failureCode: String?) {
        stopLeaseIds += leaseId
        stopOperationIds += operationId
        stopFailureCodes += failureCode
        stopResults.removeFirst().getOrThrow()
    }
}

private class ServiceRuntimeFake(
    private val startSucceeds: Boolean = true,
    private var running: Boolean = false,
    private val stopResults: ArrayDeque<Boolean> = ArrayDeque(listOf(true)),
    private val stopFailureClearsRunning: Boolean = false,
) : AndroidConnectionIntentRuntime {
    var startCalls = 0
    var stopCalls = 0

    override fun start(
        result: BackgroundStartResult,
        operationId: String,
        isCurrent: () -> Boolean,
    ): Boolean {
        if (!isCurrent()) {
            result.configuration.fill(0)
            return false
        }
        startCalls += 1
        result.configuration.fill(0)
        return startSucceeds
    }

    override fun stop(): Boolean {
        stopCalls += 1
        val stopped = stopResults.removeFirst()
        if (stopped || stopFailureClearsRunning) running = false
        return stopped
    }

    override fun isRunning(): Boolean = running
}

private fun RecoveryStoreResult<AndroidRecoveryEnvelope>.successEnvelope():
    AndroidRecoveryEnvelope = when (this) {
    is RecoveryStoreResult.Success -> value
    is RecoveryStoreResult.Failure -> throw AssertionError(code)
    }

private fun RecoveryStoreResult<AndroidConnectionIntent>.successIntent():
    AndroidConnectionIntent = when (this) {
    is RecoveryStoreResult.Success -> value
    is RecoveryStoreResult.Failure -> throw AssertionError(code)
    }

private fun RecoveryStoreResult<AndroidQuickToggleDispatch>.quickDispatch():
    AndroidQuickToggleDispatch = when (this) {
        is RecoveryStoreResult.Success -> value
        is RecoveryStoreResult.Failure -> error("unexpected recovery store failure: $code")
    }

private fun AndroidRecoveryStore.load(): AndroidRecoveryEnvelope = read().successEnvelope()

private fun serviceWithoutAndroidRuntime(): NelomaiVpnService {
    val unsafeClass = Class.forName("sun.misc.Unsafe")
    val unsafeField = unsafeClass.getDeclaredField("theUnsafe").apply {
        isAccessible = true
    }
    val unsafe = unsafeField.get(null)
    return unsafeClass.getMethod("allocateInstance", Class::class.java)
        .invoke(unsafe, NelomaiVpnService::class.java) as NelomaiVpnService
}
