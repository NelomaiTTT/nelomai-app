package ru.nelomai.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

class RedundantConnectionCoordinatorTest {
    @Test
    fun recoveryTransportFailureRetriesSameSessionWithoutCancellingDesiredIntent() {
        for (code in listOf("background_transport_unavailable", "http_5xx", "operation_in_progress")) {
            val store = emptyStore()
            store.beginRedundant(transaction())
            val original = transaction()
            var now = 0L
            val readiness = mutableListOf<Boolean>()
            val panel = FakePanel(recoverErrors = ArrayDeque(listOf(
                BackgroundConnectionException(code, retryAfterHeader = "2"))))
            val native = FakeNative()
            val coordinator = RedundantConnectionCoordinator(store, panel, native,
                epochNowMs = { now },
                onRecoveryReadiness = { readiness += it })
            assertFalse(coordinator.recover())
            assertTrue(readiness.isEmpty())
            assertFalse(coordinator.isRunning())
            assertTrue(native.started.isEmpty())
            assertEquals(original, coordinator.status())
            now = 1_999
            assertFalse(coordinator.tick())
            assertFalse(coordinator.resume())
            assertEquals(1, panel.recoverCalls)
            now = 2_000
            assertTrue(coordinator.tick())
            assertTrue(coordinator.isRunning())
            assertEquals(listOf(true), readiness)
            assertEquals(listOf(original.startOperationId, original.startOperationId), panel.recoveredOperations)
            assertTrue(requireNotNull(coordinator.status()).desiredActive)
        }
    }

    @Test
    fun recoveryUsesBackoffAndProcessRecreationKeepsTheSameOperation() {
        val store = store(transaction())
        var now = 0L
        val panel = FakePanel(recoverErrors = ArrayDeque(List(2) {
            BackgroundConnectionException("background_transport_unavailable")
        }))
        val coordinator = RedundantConnectionCoordinator(store, panel, FakeNative(), epochNowMs = { now })
        assertFalse(coordinator.resume())
        now = 2_000
        assertFalse(coordinator.tick())
        now = 6_999
        assertFalse(coordinator.tick())
        assertEquals(2, panel.recoverCalls)
        // A recreated process replays the durable session, not a new start operation.
        val recreated = RedundantConnectionCoordinator(store, panel, FakeNative())
        assertTrue(recreated.resume())
        assertEquals(List(3) { transaction().startOperationId }, panel.recoveredOperations)
        assertEquals(transaction().startRequestFingerprint, recreated.status()?.startRequestFingerprint)
    }

    @Test
    fun nativeRecoveryFailureIsTerminalAndDoesNotEnterControlPlaneRetry() {
        val panel = FakePanel()
        val readiness = mutableListOf<Boolean>()
        val coordinator = RedundantConnectionCoordinator(store(transaction()), panel,
            FakeNative(startFailures = setOf("lease-a")), onRecoveryReadiness = { readiness += it })
        assertFalse(coordinator.recover())
        assertEquals(listOf(false), readiness)
        assertFalse(coordinator.tick())
        assertFalse(coordinator.resume())
        assertEquals(1, panel.recoverCalls)
    }

    @Test
    fun cancelledRecoveryDoesNotRetryAndTerminalFailureStillPublishesFailure() {
        val store = emptyStore()
        store.beginRedundant(transaction())
        var now = 0L
        val panel = FakePanel(recoverErrors = ArrayDeque(listOf(
            BackgroundConnectionException("http_5xx", "1"))))
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(store, panel, native, epochNowMs = { now })
        assertFalse(coordinator.recover())
        store.cancelRedundantIntentAndDeferStop("stop-op", transaction().startOperationId)
        now = 2_000
        assertFalse(coordinator.tick())
        assertEquals(1, panel.recoverCalls)
        assertTrue(native.started.isEmpty())

        val terminalStore = emptyStore()
        terminalStore.beginRedundant(transaction())
        val readiness = mutableListOf<Boolean>()
        val terminal = RedundantConnectionCoordinator(terminalStore,
            FakePanel(recoverErrors = ArrayDeque(listOf(BackgroundConnectionException("invalid_background_token")))),
            FakeNative(), onRecoveryReadiness = { readiness += it })
        runCatching { terminal.recover() }
        assertEquals(listOf(false), readiness)
    }

    @Test
    fun recoveredBackgroundSessionPublishesReadinessOnlyAfterProbeAndPublishesFailure() {
        for (healthy in listOf(true, false)) {
            val store = emptyStore()
            store.beginRedundant(transaction())
            val events = mutableListOf<Boolean>()
            val native = FakeNative().apply {
                healthSnapshots += listOfNotNull(
                    healthSlot(0, active = true,
                        health = if (healthy) BackendHealth.READY else BackendHealth.UNHEALTHY,
                        handshakeFresh = healthy,
                        consecutiveProbeSuccesses = if (healthy) 3 else 0,
                        stableSinceMs = 0),
                    healthSlot(1, health = BackendHealth.UNHEALTHY).takeUnless { healthy },
                )
            }
            val coordinator = RedundantConnectionCoordinator(store,
                FakePanel(recoveryHealthProbes = mapOf("lease-a" to probe())), native,
                onRecoveryReadiness = { events += it })
            assertTrue(coordinator.recover())
            assertTrue(events.isEmpty())
            coordinator.tick()
            assertEquals(listOf(healthy), events)
            assertEquals(healthy, coordinator.isRunning())
        }
    }

    @Test
    fun primaryIsReportedOnlyAfterItsDataplaneBecomesReady() {
        val native = FakeNative().apply {
            healthSnapshots += listOf(
                healthSlot(index = 0, active = true, health = BackendHealth.WARMING),
            )
            healthSnapshots += listOf(
                healthSlot(
                    index = 0,
                    active = true,
                    health = BackendHealth.READY,
                    handshakeFresh = true,
                    consecutiveProbeSuccesses = 3,
                    stableSinceMs = 0,
                ),
            )
        }
        var reports = 0
        val panel = FakePanel()
        val coordinator = RedundantConnectionCoordinator(
            emptyStore(),
            panel,
            native,
        )

        val started = coordinator.start(
            transaction(),
            mapOf(
                "lease-a" to byteArrayOf(1),
                "lease-b" to byteArrayOf(2),
            ),
            mapOf(
                "lease-a" to BackgroundRedundantHealthProbe(
                    "dns_a",
                    "8.8.8.8",
                    "nelomai.ru",
                    4_000,
                ),
            ),
            onPrimaryStarted = { reports += 1 },
        )

        assertTrue(started)
        assertFalse(coordinator.isRunning())
        assertEquals(0, reports)
        assertEquals(listOf("lease-a", "lease-b"), native.started)
        assertTrue(coordinator.tick())
        assertFalse(coordinator.isRunning())
        assertEquals(0, reports)
        assertTrue(coordinator.tick())
        assertTrue(coordinator.isRunning())
        assertEquals(1, reports)
        assertTrue(native.healthSnapshots.isEmpty())
        assertTrue(coordinator.tick())
        assertEquals(listOf("primary_ready"), panel.roleReasons)
    }

    @Test
    fun initialReadyReportRetriesWithoutReserveAndWithoutRestartingNative() {
        val native = FakeNative().apply {
            healthSnapshots += listOf(healthSlot(0, active = true,
                health = BackendHealth.READY, handshakeFresh = true,
                consecutiveProbeSuccesses = 3, stableSinceMs = 0))
        }
        val panel = FakePanel(roleFailures = ArrayDeque(listOf(true, false)))
        val coordinator = RedundantConnectionCoordinator(emptyStore(), panel, native)
        assertTrue(coordinator.start(transaction().copy(standbyDesired = false),
            mapOf("lease-a" to byteArrayOf(1)), mapOf("lease-a" to probe())))
        assertTrue(coordinator.tick())
        assertTrue(coordinator.isRunning())
        assertFalse(coordinator.tick())
        assertTrue(requireNotNull(coordinator.status()).retry.roleObservationPending)
        assertTrue(coordinator.tick())
        assertFalse(requireNotNull(coordinator.status()).retry.roleObservationPending)
        assertEquals(listOf("primary_ready", "primary_ready"), panel.roleReasons)
        assertEquals(listOf("lease-a"), native.started)
    }

    @Test
    fun pendingPrimaryReadinessDoesNotBlockNetworkRebinding() {
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(emptyStore(), FakePanel(), native)

        assertTrue(coordinator.start(
            transaction(),
            mapOf("lease-a" to byteArrayOf(1), "lease-b" to byteArrayOf(2)),
            mapOf("lease-a" to probe()),
        ))
        assertFalse(coordinator.isRunning())

        assertTrue(coordinator.onUnderlyingNetworkChanged(validated = false))
        assertEquals(listOf("lease-a", "lease-b"), native.rebound)
    }

    @Test
    fun failedReadyPersistFailsStartWithoutLeavingNativeRunning() {
        val backend = CoordinatorRecordBackend()
        backend.write(AndroidRecoveryEnvelopeCodec.encode(AndroidRecoveryEnvelope.empty(1)))
        val store = AndroidRecoveryStore(backend, CoordinatorBootIdentity())
        val native = FakeNative().apply {
            healthSnapshots += listOf(healthSlot(0, active = true,
                health = BackendHealth.READY, handshakeFresh = true,
                consecutiveProbeSuccesses = 3, stableSinceMs = 0))
        }
        val panel = FakePanel()
        var failed = 0
        var ready = 0
        val coordinator = RedundantConnectionCoordinator(store, panel, native)
        assertTrue(coordinator.start(transaction(),
            mapOf("lease-a" to byteArrayOf(1), "lease-b" to byteArrayOf(2)),
            mapOf("lease-a" to probe()), onPrimaryStarted = { ready++ },
            onPrimaryFailed = { failed++ }))
        backend.failOnWriteNumber = backend.writeCount + 1
        assertFalse(coordinator.tick())
        assertFalse(coordinator.isRunning())
        assertEquals(0, ready)
        assertEquals(1, failed)
        assertEquals(0, panel.roleCalls)
    }

    @Test
    fun initiallyUnvalidatedStartRebindsBeforeLaterReadiness() {
        val native = FakeNative().apply {
            healthSnapshots += listOf(
                healthSlot(
                    index = 0,
                    active = true,
                    health = BackendHealth.READY,
                    handshakeFresh = true,
                    consecutiveProbeSuccesses = 3,
                    stableSinceMs = 0,
                ),
            )
            healthSnapshots += healthSnapshots.first()
        }
        val coordinator = RedundantConnectionCoordinator(
            emptyStore(),
            FakePanel(),
            native,
            epochNowMs = { 20_000L },
            monotonicMs = { 1_000L },
            healthMonitor = RedundantHealthMonitor(
                rebindStabilizationMs = 0,
                initialNetworkValidated = false,
            ),
        )

        assertTrue(coordinator.start(
            transaction(),
            mapOf("lease-a" to byteArrayOf(1), "lease-b" to byteArrayOf(2)),
            mapOf("lease-a" to probe()),
        ))
        assertTrue(coordinator.tick())
        assertFalse(coordinator.isRunning())

        assertTrue(coordinator.onUnderlyingNetworkChanged(validated = true))
        assertEquals(listOf("lease-a", "lease-b"), native.rebound)
        assertTrue(coordinator.tick())
        assertTrue(coordinator.isRunning())
    }

    @Test
    fun revokeCancelsPendingPrimaryReadinessExactlyOnceBeforeCleanup() {
        var successes = 0
        var failures = 0
        var cancellations = 0
        val panel = FakePanel()
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(emptyStore(), panel, native)

        assertTrue(coordinator.start(
            transaction(),
            mapOf("lease-a" to byteArrayOf(1), "lease-b" to byteArrayOf(2)),
            mapOf("lease-a" to probe()),
            onPrimaryStarted = { successes += 1 },
            onPrimaryFailed = { failures += 1 },
            onPrimaryCancelled = { cancellations += 1 },
        ))
        assertTrue(coordinator.fenceRevoke())
        assertTrue(coordinator.revoke())
        assertFalse(coordinator.tick())

        assertEquals(0, successes)
        assertEquals(0, failures)
        assertEquals(1, cancellations)
        assertEquals(1, panel.stopCalls)
        assertFalse(coordinator.isRunning())
    }

    @Test
    fun primaryReadyAndRevokeRacePublishesExactlyOneTerminalCallback() {
        repeat(100) {
            val outcomes = java.util.concurrent.CopyOnWriteArrayList<String>()
            val coordinator = RedundantConnectionCoordinator(
                emptyStore(),
                FakePanel(),
                FakeNative(),
                epochNowMs = { 20_000L },
            )
            assertTrue(coordinator.start(
                transaction(),
                mapOf("lease-a" to byteArrayOf(1), "lease-b" to byteArrayOf(2)),
                mapOf("lease-a" to probe()),
                onPrimaryStarted = { outcomes += "ready" },
                onPrimaryFailed = { outcomes += "failed" },
                onPrimaryCancelled = { outcomes += "stopped" },
            ))
            val ready = java.util.concurrent.CountDownLatch(2)
            val release = java.util.concurrent.CountDownLatch(1)
            val readinessThread = Thread {
                ready.countDown()
                release.await()
                coordinator.onHealthObservations(listOf(
                    healthSlot(
                        index = 0,
                        active = true,
                        health = BackendHealth.READY,
                        handshakeFresh = true,
                        consecutiveProbeSuccesses = 3,
                        stableSinceMs = 0,
                    ),
                ))
            }
            val revokeThread = Thread {
                ready.countDown()
                release.await()
                coordinator.fenceRevoke()
            }
            readinessThread.start()
            revokeThread.start()
            assertTrue(ready.await(1, java.util.concurrent.TimeUnit.SECONDS))
            release.countDown()
            readinessThread.join()
            revokeThread.join()

            assertEquals(1, outcomes.size)
            assertTrue(outcomes.single() in setOf("ready", "stopped"))
        }
    }

    @Test
    fun primaryReadinessTimeoutFailsExactlyOnce() {
        var elapsedMs = 0L
        var failures = 0
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(
            emptyStore(),
            FakePanel(),
            native,
            monotonicMs = { elapsedMs },
        )

        assertTrue(coordinator.start(
            transaction(),
            mapOf("lease-a" to byteArrayOf(1), "lease-b" to byteArrayOf(2)),
            mapOf("lease-a" to probe()),
            onPrimaryFailed = { failures += 1 },
        ))
        elapsedMs = 30_000L

        assertFalse(coordinator.tick())
        assertFalse(coordinator.tick())
        assertFalse(coordinator.isRunning())
        assertEquals(1, failures)
        assertEquals(1, native.stopCalls)
    }

    @Test
    fun primaryReadinessFailureStartsThroughFreshStandbyExactlyOnce() {
        val failedPrimaryObservations = listOf(
            healthSlot(index = 0, active = true, hardFailure = true),
            healthSlot(index = 0, active = true, health = BackendHealth.UNHEALTHY),
        )
        for (failedPrimary in failedPrimaryObservations) {
            var ready = 0
            var failed = 0
            val native = FakeNative()
            val coordinator = RedundantConnectionCoordinator(
                emptyStore(),
                FakePanel(),
                native,
                epochNowMs = { 20_000L },
                monotonicMs = { 20_000L },
            )
            assertTrue(coordinator.start(
                transaction(),
                mapOf("lease-a" to byteArrayOf(1), "lease-b" to byteArrayOf(2)),
                mapOf("lease-a" to probe()),
                onPrimaryStarted = { ready += 1 },
                onPrimaryFailed = { failed += 1 },
            ))

            assertTrue(coordinator.onHealthObservations(listOf(
                failedPrimary,
                healthSlot(
                    index = 1,
                    health = BackendHealth.READY,
                    handshakeFresh = true,
                    consecutiveProbeSuccesses = 3,
                    stableSinceMs = 0,
                ),
            )))

            assertTrue(coordinator.isRunning())
            assertEquals("lease-b", coordinator.status()?.localActiveLeaseId)
            assertEquals(listOf("lease-a", "lease-b"), native.activated)
            assertEquals(1, ready)
            assertEquals(0, failed)
            assertEquals(0, native.stopCalls)

            assertTrue(coordinator.onHealthObservations(listOf(
                healthSlot(index = 1, active = true, health = BackendHealth.READY),
            )))
            assertEquals(1, ready)
            assertEquals(0, failed)
        }
    }

    @Test
    fun primaryReadinessDeadlineStartsThroughFreshStandbyWithoutExtendingDeadline() {
        var elapsedMs = 0L
        var ready = 0
        var failed = 0
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(
            emptyStore(),
            FakePanel(),
            native,
            epochNowMs = { elapsedMs },
            monotonicMs = { elapsedMs },
        )
        assertTrue(coordinator.start(
            transaction(),
            mapOf("lease-a" to byteArrayOf(1), "lease-b" to byteArrayOf(2)),
            mapOf("lease-a" to probe()),
            onPrimaryStarted = { ready += 1 },
            onPrimaryFailed = { failed += 1 },
        ))

        elapsedMs = 30_000L
        assertTrue(coordinator.onHealthObservations(listOf(
            healthSlot(index = 0, active = true, health = BackendHealth.WARMING),
            healthSlot(
                index = 1,
                health = BackendHealth.READY,
                handshakeFresh = true,
                consecutiveProbeSuccesses = 3,
                stableSinceMs = 0,
            ),
        )))

        assertTrue(coordinator.isRunning())
        assertEquals("lease-b", coordinator.status()?.localActiveLeaseId)
        assertEquals(listOf("lease-a", "lease-b"), native.activated)
        assertEquals(1, ready)
        assertEquals(0, failed)
    }

    @Test
    fun earlyPrimaryHardFailureWaitsForStandbyOnlyUntilOriginalDeadline() {
        var elapsedMs = 0L
        var ready = 0
        var failed = 0
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(
            emptyStore(),
            FakePanel(),
            native,
            epochNowMs = { elapsedMs },
            monotonicMs = { elapsedMs },
        )
        assertTrue(coordinator.start(
            transaction(),
            mapOf("lease-a" to byteArrayOf(1), "lease-b" to byteArrayOf(2)),
            mapOf("lease-a" to probe()),
            onPrimaryStarted = { ready += 1 },
            onPrimaryFailed = { failed += 1 },
        ))

        elapsedMs = 5_000L
        assertTrue(coordinator.onHealthObservations(listOf(
            healthSlot(index = 0, active = true, hardFailure = true),
            healthSlot(index = 1, health = BackendHealth.WARMING),
        )))
        assertFalse(coordinator.isRunning())
        assertEquals(0, ready)
        assertEquals(0, failed)
        assertEquals(0, native.stopCalls)

        elapsedMs = 20_000L
        assertTrue(coordinator.onHealthObservations(listOf(
            healthSlot(index = 0, active = true, hardFailure = true),
            healthSlot(
                index = 1,
                health = BackendHealth.READY,
                handshakeFresh = true,
                consecutiveProbeSuccesses = 3,
                stableSinceMs = 5_000L,
            ),
        )))
        assertTrue(coordinator.isRunning())
        assertEquals("lease-b", coordinator.status()?.localActiveLeaseId)
        assertEquals(1, ready)
        assertEquals(0, failed)
    }

    @Test
    fun primaryReadinessStillFailsExactlyOnceWhenBothMembersAreUnhealthy() {
        var ready = 0
        var failed = 0
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(emptyStore(), FakePanel(), native)
        assertTrue(coordinator.start(
            transaction(),
            mapOf("lease-a" to byteArrayOf(1), "lease-b" to byteArrayOf(2)),
            mapOf("lease-a" to probe()),
            onPrimaryStarted = { ready += 1 },
            onPrimaryFailed = { failed += 1 },
        ))

        assertFalse(coordinator.onHealthObservations(listOf(
            healthSlot(index = 0, active = true, health = BackendHealth.UNHEALTHY),
            healthSlot(index = 1, health = BackendHealth.UNHEALTHY),
        )))
        assertFalse(coordinator.onHealthObservations(emptyList()))

        assertFalse(coordinator.isRunning())
        assertEquals(0, ready)
        assertEquals(1, failed)
        assertEquals(1, native.stopCalls)
    }

    @Test
    fun disabledStandbyCannotSatisfyPrimaryReadinessFromAStaleReadySlot() {
        var ready = 0
        var failed = 0
        val store = emptyStore()
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(store, FakePanel(), native)
        assertTrue(coordinator.start(
            transaction(),
            mapOf("lease-a" to byteArrayOf(1), "lease-b" to byteArrayOf(2)),
            mapOf("lease-a" to probe()),
            onPrimaryStarted = { ready += 1 },
            onPrimaryFailed = { failed += 1 },
        ))
        assertTrue(store.updateRedundant("start-operation") { current ->
            current.copy(
                standbyDesired = false,
                retry = current.retry.copy(standbyReleasePending = true),
            )
        } is RecoveryStoreResult.Success)

        assertFalse(coordinator.onHealthObservations(listOf(
            healthSlot(index = 0, active = true, hardFailure = true),
            healthSlot(
                index = 1,
                health = BackendHealth.READY,
                handshakeFresh = true,
                consecutiveProbeSuccesses = 3,
                stableSinceMs = 0,
            ),
        )))

        assertFalse(coordinator.isRunning())
        assertEquals("lease-a", coordinator.status()?.localActiveLeaseId)
        assertEquals(listOf("lease-a"), native.activated)
        assertEquals(0, ready)
        assertEquals(1, failed)
        assertEquals(1, native.stopCalls)
    }

    @Test
    fun primaryReadinessDeadlineSurvivesThrowingHealthSnapshots() {
        var elapsedMs = 0L
        var failures = 0
        val coordinator = RedundantConnectionCoordinator(
            emptyStore(),
            FakePanel(),
            FakeNative(healthSnapshotFailures = 2),
            monotonicMs = { elapsedMs },
        )
        assertTrue(coordinator.start(
            transaction(),
            mapOf("lease-a" to byteArrayOf(1), "lease-b" to byteArrayOf(2)),
            mapOf("lease-a" to probe()),
            onPrimaryFailed = { failures += 1 },
        ))

        assertTrue(coordinator.tick())
        assertEquals(0, failures)

        elapsedMs = 30_000L
        assertFalse(coordinator.tick())
        assertEquals(1, failures)
    }

    @Test
    fun unreadableStoreFailsPendingPrimaryReadinessExactlyOnce() {
        var failures = 0
        val backend = CoordinatorRecordBackend()
        backend.write(AndroidRecoveryEnvelopeCodec.encode(AndroidRecoveryEnvelope.empty(1)))
        val coordinator = RedundantConnectionCoordinator(
            AndroidRecoveryStore(backend, CoordinatorBootIdentity()),
            FakePanel(),
            FakeNative(),
        )
        assertTrue(coordinator.start(
            transaction(),
            mapOf("lease-a" to byteArrayOf(1), "lease-b" to byteArrayOf(2)),
            mapOf("lease-a" to probe()),
            onPrimaryFailed = { failures += 1 },
        ))
        backend.failReads = true

        assertFalse(coordinator.tick())
        assertFalse(coordinator.tick())
        assertEquals(1, failures)
    }

    @Test
    fun cancelledStartWithUnreadableStoreStopsLocallyAndCannotLaterBecomeReady() {
        val backend = CoordinatorRecordBackend()
        backend.write(AndroidRecoveryEnvelopeCodec.encode(AndroidRecoveryEnvelope.empty(1)))
        val native = FakeNative()
        val panel = FakePanel()
        val gate = RedundantStartOperationGate()
        val outcomes = mutableListOf<String>()
        val coordinator = RedundantConnectionCoordinator(
            AndroidRecoveryStore(backend, CoordinatorBootIdentity()),
            panel,
            native,
            epochNowMs = { 20_000L },
        )
        assertTrue(gate.begin("operation-a") { outcomes += "stopped" })
        assertTrue(coordinator.start(
            transaction().copy(startOperationId = "operation-a"),
            mapOf("lease-a" to byteArrayOf(1), "lease-b" to byteArrayOf(2)),
            mapOf("lease-a" to probe()),
            shouldCancel = { gate.isCancelled("operation-a") },
            onPrimaryStarted = {
                gate.complete("operation-a") { outcomes += "running" }
                gate.finish("operation-a")
            },
            onPrimaryCancelled = {
                gate.completeCancelled("operation-a")
            },
        ))

        assertEquals("operation-a", gate.cancelPendingAndComplete())
        backend.failReads = true
        assertTrue(coordinator.closeLocal())
        backend.failReads = false

        coordinator.onHealthObservations(listOf(
            healthSlot(
                index = 0,
                active = true,
                health = BackendHealth.READY,
                handshakeFresh = true,
                consecutiveProbeSuccesses = 3,
                stableSinceMs = 0,
            ),
        ))
        assertEquals(listOf("stopped"), outcomes)
        assertTrue(gate.isCancelled("operation-a"))
        assertFalse(coordinator.isRunning())

        assertTrue(coordinator.fenceRevoke())
        assertTrue(coordinator.revoke())
        gate.finish("operation-a")

        assertEquals(2, native.stopCalls)
        assertEquals(1, panel.stopCalls)
        assertEquals(null, coordinator.status())
        assertFalse(gate.isCancelled("operation-a"))
    }

    @Test
    fun wallClockJumpCannotExpirePrimaryReadiness() {
        var wallMs = 1_000L
        var elapsedMs = 5_000L
        val coordinator = RedundantConnectionCoordinator(
            emptyStore(),
            FakePanel(),
            FakeNative(),
            epochNowMs = { wallMs },
            monotonicMs = { elapsedMs },
        )

        assertTrue(coordinator.start(
            transaction(),
            mapOf("lease-a" to byteArrayOf(1), "lease-b" to byteArrayOf(2)),
            mapOf("lease-a" to probe()),
        ))
        wallMs = Long.MAX_VALUE
        assertTrue(coordinator.tick())
        assertFalse(coordinator.isRunning())

        elapsedMs = 35_000L
        assertFalse(coordinator.tick())
    }

    @Test
    fun wallClockJumpsCannotReplaceProbeConfirmations() {
        var epochMs = 1_800_000_000_000L
        var elapsedMs = 10_000L
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(
            store(transaction()),
            FakePanel(),
            native,
            epochNowMs = { epochMs },
            monotonicMs = { elapsedMs },
            healthMonitor = RedundantHealthMonitor(rebindStabilizationMs = 0),
        )
        val failedAt = elapsedMs
        var confirmations = 0
        fun observations() = listOf(
            healthSlot(
                index = 0,
                active = true,
                probeFailed = true,
                independentFailureSignal = true,
                softFailureStartedAtMs = failedAt,
                corroboratedProbeFailures = confirmations,
            ),
            healthSlot(index = 1, health = BackendHealth.READY),
        )

        assertTrue(coordinator.onHealthObservations(observations()))
        assertTrue(native.activated.isEmpty())
        epochMs = 1L
        elapsedMs += 4_999L
        confirmations = 1
        assertTrue(coordinator.onHealthObservations(observations()))
        assertTrue(native.activated.isEmpty())

        epochMs = Long.MAX_VALUE
        elapsedMs += 1L
        confirmations = 2
        assertTrue(coordinator.onHealthObservations(observations()))
        assertEquals(listOf("lease-b"), native.activated)
    }

    @Test
    fun resumeKeepsOnePendingRecoveryUntilReadinessArrives() {
        val native = FakeNative().apply {
            healthSnapshots += listOf(
                healthSlot(
                    index = 0,
                    active = true,
                    health = BackendHealth.READY,
                    handshakeFresh = true,
                    consecutiveProbeSuccesses = 3,
                    stableSinceMs = 0,
                ),
            )
        }
        val panel = FakePanel(
            recoveryHealthProbes = mapOf("lease-a" to probe()),
        )
        val coordinator = RedundantConnectionCoordinator(
            store(transaction()),
            panel,
            native,
            monotonicMs = { 20_000L },
        )

        assertTrue(coordinator.recover())
        assertFalse(coordinator.isRunning())
        assertTrue(coordinator.resume())
        assertEquals(listOf("lease-a", "lease-b"), native.started)
        assertTrue(coordinator.tick())
        assertTrue(coordinator.isRunning())
        assertEquals(listOf("lease-a", "lease-b"), native.started)
    }

    @Test
    fun v2RecoveryEnvelopeNeverEntersLegacyVpnRecovery() {
        val envelope = AndroidRecoveryEnvelope(
            formatVersion = ANDROID_RECOVERY_FORMAT,
            intent = AndroidConnectionIntent.empty(1),
            leaseTransaction = null,
            redundantTransaction = transaction(),
        )

        assertFalse(shouldEnterLegacyVpnRecovery(RecoveryStoreResult.Success(envelope)))
        assertFalse(shouldEnterLegacyVpnRecovery(RecoveryStoreResult.Failure("recovery_record_corrupt")))
    }

    @Test
    fun deferredVpnOwnerRecoversV2BeforeLegacyAndFailsClosedWhenUnavailable() {
        var legacyCalls = 0
        val owner = FakeVpnOwner(recoverResult = true)

        assertTrue(routeVpnProcessRecovery(
            RecoveryStoreResult.Success(v2Envelope()), owner, { legacyCalls += 1 },
        ))
        assertEquals(1, owner.resumeCalls)
        assertEquals(0, owner.recoverCalls)
        assertEquals(0, legacyCalls)
        assertFalse(routeVpnProcessRecovery(
            RecoveryStoreResult.Success(v2Envelope()), null, { legacyCalls += 1 },
        ))
        assertEquals(0, legacyCalls)
        assertTrue(routeVpnProcessRevoke(
            RecoveryStoreResult.Success(v2Envelope()), owner, { legacyCalls += 1 },
        ))
        assertEquals(0, legacyCalls)
    }

    @Test
    fun stickyRestartUsesV2OwnerResumeBeforeLegacyAndStaysRestartableWhenUnavailable() {
        var legacyCalls = 0
        val owner = FakeVpnOwner(recoverResult = true)

        assertTrue(routeVpnStickyRestart(
            RecoveryStoreResult.Success(v2Envelope()), owner, { legacyCalls += 1 },
        ))
        assertEquals(1, owner.resumeCalls)
        assertEquals(0, legacyCalls)
        assertFalse(routeVpnStickyRestart(
            RecoveryStoreResult.Success(v2Envelope()), null, { legacyCalls += 1 },
        ))
        assertEquals(0, legacyCalls)
    }

    @Test
    fun processDeathRecoveryStartsTheLocallyActiveMemberBeforeCanonicalActive() {
        val store = store(transaction(localActiveLeaseId = "lease-a"))
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(store, FakePanel(), native)

        coordinator.recover()

        assertEquals(listOf("lease-a", "lease-b"), native.started)
        assertEquals(listOf("lease-a"), native.activated)
    }

    @Test
    fun ownerReportsRunningOnlyAfterNativeRecoveryHasStarted() {
        val coordinator = RedundantConnectionCoordinator(store(transaction()), FakePanel(), FakeNative())

        assertFalse(coordinator.isRunning())
        assertTrue(coordinator.recover())
        assertTrue(coordinator.isRunning())
    }

    @Test
    fun reserveStatusMovesCalmlyFromWarmingToReadyAndFailover() {
        val states = mutableListOf<RedundantReserveState?>()
        val coordinator = RedundantConnectionCoordinator(
            store(transaction()),
            FakePanel(),
            FakeNative(),
            epochNowMs = { 20_000L },
            onReserveStateChanged = states::add,
        )

        assertTrue(coordinator.recover())
        assertEquals(RedundantReserveState.WARMING, coordinator.reserveState())
        assertTrue(coordinator.onHealthObservations(listOf(
            healthSlot(index = 0, active = true, health = BackendHealth.READY),
            healthSlot(
                index = 1,
                health = BackendHealth.READY,
                handshakeFresh = true,
                consecutiveProbeSuccesses = 3,
                stableSinceMs = 0L,
            ),
        )))
        assertEquals(RedundantReserveState.READY, coordinator.reserveState())
        assertTrue(coordinator.onHealthObservations(listOf(
            healthSlot(index = 0, active = true, hardFailure = true),
            healthSlot(index = 1, health = BackendHealth.READY),
        )))
        assertEquals(RedundantReserveState.FAILOVER, coordinator.reserveState())
        assertEquals(
            listOf(
                RedundantReserveState.WARMING,
                RedundantReserveState.READY,
                RedundantReserveState.FAILOVER,
            ),
            states,
        )
        assertEquals(
            "Подключено через резервный сервер",
            redundantNotificationContent(coordinator.reserveState()),
        )
    }

    @Test
    fun recoveryRequiresAndActivatesTheLocalActiveConfigurationWhileStandbyIsBestEffort() {
        val native = FakeNative(startFailures = setOf("lease-b"))
        val coordinator = RedundantConnectionCoordinator(store(transaction()), FakePanel(), native)

        assertTrue(coordinator.recover())
        assertEquals(listOf("lease-a", "lease-b"), native.started)
        assertEquals(listOf("lease-a"), native.activated)

        val missingActive = RedundantConnectionCoordinator(
            store(transaction()),
            FakePanel(configurations = mapOf("lease-b" to "standby".toByteArray())),
            FakeNative(),
        )
        assertFalse(missingActive.recover())
    }

    @Test
    fun aSingleSlotFailureDoesNotInvokeLegacyStalledStop() {
        val native = FakeNative(usable = setOf("lease-b"))
        var legacyStops = 0
        val coordinator = RedundantConnectionCoordinator(
            store(transaction()),
            FakePanel(),
            native,
            onAllSlotsStalled = { legacyStops += 1 },
        )

        coordinator.slotFailed("lease-a", "primary_unhealthy")

        assertEquals(0, legacyStops)
        assertEquals("lease-b", coordinator.status()?.localActiveLeaseId)
    }

    @Test
    fun totalLossPublishesOneSerializedLifecycleCallback() {
        val backend = CoordinatorRecordBackend()
        val recoveryStore = store(transaction(), backend)
        var totalLossCallbacks = 0
        val coordinator = RedundantConnectionCoordinator(
            recoveryStore,
            FakePanel(),
            FakeNative(usable = emptySet()),
            onAllSlotsStalled = { totalLossCallbacks += 1 },
        )
        val writesBeforeFailure = backend.writeCount

        assertFalse(coordinator.slotFailed("lease-a", "primary_unhealthy"))
        assertFalse(coordinator.slotFailed("lease-a", "primary_unhealthy"))

        assertEquals(1, totalLossCallbacks)
        assertEquals(writesBeforeFailure, backend.writeCount)
        assertFalse(requireNotNull(coordinator.status()).retry.sessionStalledRecorded)

        val reconstructed = RedundantConnectionCoordinator(
            recoveryStore,
            FakePanel(),
            FakeNative(usable = emptySet()),
            onAllSlotsStalled = { totalLossCallbacks += 1 },
        )
        assertFalse(reconstructed.slotFailed("lease-a", "primary_unhealthy"))
        assertEquals(2, totalLossCallbacks)
    }

    @Test
    fun failedInactiveStandbySchedulesReplacementWithoutReactivatingPrimary() {
        var nowMs = 4_000_000L
        val panel = FakePanel()
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(
            store(transaction()),
            panel,
            native,
            epochNowMs = { nowMs },
        )

        assertTrue(coordinator.slotFailed("lease-b", "standby_unhealthy"))
        assertEquals("lease-a", coordinator.status()?.localActiveLeaseId)
        assertTrue(native.activated.isEmpty())
        assertEquals(0, panel.roleCalls)

        nowMs += 60_000
        assertTrue(coordinator.tick())
        assertEquals(listOf("lease-b"), panel.acquireReplaceLeaseIds)
        assertEquals("lease-a", coordinator.status()?.localActiveLeaseId)
    }

    @Test
    fun revokeClearsDesiredActiveBeforeQueuingOneSessionStop() {
        val store = store(transaction())
        val panel = FakePanel()
        val coordinator = RedundantConnectionCoordinator(store, panel, FakeNative()) {
            error("both slots are not stalled")
        }

        coordinator.revoke()
        coordinator.revoke()

        assertEquals(null, (store.read() as RecoveryStoreResult.Success).value.redundantTransaction)
        assertEquals(1, panel.stopCalls)
    }

    @Test
    fun revokeFencePersistsStopWithoutTouchingNativeOrPanel() {
        val panel = FakePanel()
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(
            store(transaction()),
            panel,
            native,
            operationId = { "stop-1" },
        )

        assertTrue(coordinator.fenceRevoke())

        val fenced = requireNotNull(coordinator.status())
        assertFalse(fenced.desiredActive)
        assertEquals("stop-1", fenced.stopOperationId)
        assertEquals(RedundantStopState.PENDING, fenced.retry.stopState)
        assertEquals(0, native.stopCalls)
        assertEquals(0, panel.stopCalls)
    }

    @Test
    fun pendingStopReplaysSameOperationAfterFailureAndClearsOnlyAfterBothAcknowledgements() {
        val store = store(transaction())
        val panel = FakePanel(stopResults = ArrayDeque(listOf(false, true)))
        val native = FakeNative(stopResults = ArrayDeque(listOf(true, true)))
        val first = RedundantConnectionCoordinator(store, panel, native, operationId = { "stop-1" })

        assertFalse(first.revoke())
        val pending = requireNotNull(first.status())
        assertFalse(pending.desiredActive)
        assertEquals("stop-1", pending.stopOperationId)
        assertEquals(RedundantStopState.PENDING, pending.retry.stopState)

        val replayed = RedundantConnectionCoordinator(store, panel, native)
        assertTrue(replayed.resume())
        assertEquals(2, panel.stopCalls)
        assertEquals(2, native.stopCalls)
        assertEquals(null, replayed.status())
        assertTrue(replayed.start(transaction(), mapOf("lease-a" to "active".toByteArray())))
    }

    @Test
    fun staleCoordinatorCannotRevokeAReplacementTransaction() {
        val backend = CoordinatorRecordBackend()
        val original = transaction()
        backend.write(AndroidRecoveryEnvelopeCodec.encode(AndroidRecoveryEnvelope(
            formatVersion = ANDROID_RECOVERY_FORMAT,
            intent = AndroidConnectionIntent.empty(1),
            leaseTransaction = null,
            redundantTransaction = original,
        )))
        val store = AndroidRecoveryStore(backend, CoordinatorBootIdentity())
        val panel = FakePanel()
        val native = FakeNative()
        val stale = RedundantConnectionCoordinator(
            store = store,
            panel = panel,
            native = native,
            expectedStartOperationId = original.startOperationId,
        )
        val replacement = original.copy(startOperationId = "replacement-start-operation")
        backend.write(AndroidRecoveryEnvelopeCodec.encode(AndroidRecoveryEnvelope(
            formatVersion = ANDROID_RECOVERY_FORMAT,
            intent = AndroidConnectionIntent.empty(1),
            leaseTransaction = null,
            redundantTransaction = replacement,
        )))

        assertFalse(stale.revoke())
        assertEquals(0, native.stopCalls)
        assertEquals(0, panel.stopCalls)
        val durable = store.read() as RecoveryStoreResult.Success
        assertEquals(replacement, durable.value.redundantTransaction)
    }

    @Test
    fun cleanupAcceptedDuringBlockedRecoveryPreventsEveryLateNativeStart() {
        val recoveryEntered = CountDownLatch(1)
        val releaseRecovery = CountDownLatch(1)
        val transaction = transaction()
        val native = FakeNative()
        val fence = RedundantOperationMutationFence()
        val coordinator = RedundantConnectionCoordinator(
            store = store(transaction),
            panel = FakePanel(
                recoverEntered = recoveryEntered,
                releaseRecovery = releaseRecovery,
            ),
            native = native,
            expectedStartOperationId = transaction.startOperationId,
            mutationFence = fence,
        )
        val result = AtomicReference<Boolean>()
        val recovery = Thread { result.set(coordinator.resume()) }.apply { start() }
        assertTrue(recoveryEntered.await(2, TimeUnit.SECONDS))

        fence.cancel(transaction.startOperationId)
        releaseRecovery.countDown()
        recovery.join(2_000L)

        assertFalse(recovery.isAlive)
        assertEquals(false, result.get())
        assertTrue(native.started.isEmpty())
        assertTrue(native.activated.isEmpty())
    }

    @Test
    fun cleanupAcceptedBeforeFreshStartPreventsDurableAndNativeActivation() {
        val transaction = transaction()
        val store = emptyStore()
        val native = FakeNative()
        val fence = RedundantOperationMutationFence().apply {
            cancel(transaction.startOperationId)
        }
        val coordinator = RedundantConnectionCoordinator(
            store = store,
            panel = FakePanel(),
            native = native,
            expectedStartOperationId = transaction.startOperationId,
            mutationFence = fence,
        )

        assertFalse(coordinator.start(
            transaction,
            configurations = mapOf(
                "lease-a" to byteArrayOf(1),
                "lease-b" to byteArrayOf(2),
            ),
        ))

        val recovery = store.read() as RecoveryStoreResult.Success
        assertEquals(null, recovery.value.redundantTransaction)
        assertTrue(native.started.isEmpty())
        assertTrue(native.activated.isEmpty())
    }

    @Test
    fun cleanupCancellationDoesNotWaitForBlockedNativeStartAndRollsItBack() {
        val nativeStartEntered = CountDownLatch(1)
        val releaseNativeStart = CountDownLatch(1)
        val transaction = transaction()
        val native = FakeNative(
            startEntered = nativeStartEntered,
            releaseStart = releaseNativeStart,
        )
        val fence = RedundantOperationMutationFence()
        val coordinator = RedundantConnectionCoordinator(
            store = emptyStore(),
            panel = FakePanel(),
            native = native,
            expectedStartOperationId = transaction.startOperationId,
            mutationFence = fence,
        )
        val startResult = AtomicReference<Boolean>()
        val start = Thread {
            startResult.set(coordinator.start(
                transaction,
                configurations = mapOf(
                    "lease-a" to byteArrayOf(1),
                    "lease-b" to byteArrayOf(2),
                ),
            ))
        }.apply { start() }
        assertTrue(nativeStartEntered.await(2, TimeUnit.SECONDS))
        val cancelCompleted = CountDownLatch(1)
        val cancel = Thread {
            fence.cancel(transaction.startOperationId)
            cancelCompleted.countDown()
        }.apply { start() }

        val completedBeforeNative = cancelCompleted.await(500, TimeUnit.MILLISECONDS)
        releaseNativeStart.countDown()
        start.join(2_000L)
        cancel.join(2_000L)

        assertTrue(completedBeforeNative)
        assertFalse(start.isAlive)
        assertFalse(cancel.isAlive)
        assertEquals(false, startResult.get())
        assertTrue(native.activated.isEmpty())
        assertEquals(1, native.stopCalls)
    }

    @Test
    fun roleRebaseAdoptsCanonicalGenerationsWithoutRollingBackLocalDataplaneActive() {
        val panel = FakePanel(role = RedundantRoleResponse(
            action = "rebase",
            localActiveLeaseId = "lease-a",
            session = session(activeLeaseId = "lease-b", roleGeneration = 7, membershipGeneration = 3),
        ))
        val coordinator = RedundantConnectionCoordinator(store(transaction()), panel, FakeNative()) {}

        coordinator.reportLocalRole("primary_unhealthy")

        val transaction = requireNotNull(coordinator.status())
        assertEquals("lease-a", transaction.localActiveLeaseId)
        assertEquals(7, transaction.roleGeneration)
        assertEquals(3, transaction.membershipGeneration)
        assertEquals(2, panel.roleCalls)
        assertFalse(transaction.retry.roleObservationPending)
    }

    @Test
    fun failedOldPrimaryIsReplacedAfterSixtySecondsWithoutFailback() {
        var nowMs = 1_000_000L
        val panel = FakePanel()
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(
            store(transaction()),
            panel,
            native,
            epochNowMs = { nowMs },
        )

        assertTrue(coordinator.onHealthObservations(listOf(
            healthSlot(index = 0, active = true, hardFailure = true),
            healthSlot(index = 1, health = BackendHealth.READY),
        )))
        assertEquals("lease-b", coordinator.status()?.localActiveLeaseId)
        assertEquals(listOf("lease-b"), native.activated)

        nowMs += 59_999
        assertTrue(coordinator.tick())
        assertTrue(panel.acquireOperationIds.isEmpty())
        assertEquals("lease-b", coordinator.status()?.localActiveLeaseId)

        nowMs += 1
        assertTrue(coordinator.tick())
        assertEquals(1, panel.acquireOperationIds.size)
        assertEquals(listOf("lease-a"), panel.acquireReplaceLeaseIds)
        assertEquals("lease-b", coordinator.status()?.localActiveLeaseId)
        assertEquals(listOf("lease-b"), native.activated)
        assertTrue(native.events.indexOf("stop:lease-a") < native.events.indexOf("start:candidate"))
    }

    @Test
    fun periodicTickConsumesNativeHealthAndSwitchesWithoutLegacyStall() {
        val native = FakeNative(healthSnapshots = ArrayDeque(listOf(listOf(
            healthSlot(index = 0, active = true, hardFailure = true),
            healthSlot(index = 1, health = BackendHealth.READY),
        ))))
        var legacyStops = 0
        val coordinator = RedundantConnectionCoordinator(
            store(transaction()),
            FakePanel(),
            native,
            onAllSlotsStalled = { legacyStops += 1 },
        )

        assertTrue(coordinator.tick())

        assertEquals("lease-b", coordinator.status()?.localActiveLeaseId)
        assertEquals(listOf("lease-b"), native.activated)
        assertEquals(0, legacyStops)
    }

    @Test
    fun validatedNetworkHandoffRebindsBothMembersBeforeStabilization() {
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(store(transaction()), FakePanel(), native)

        assertTrue(coordinator.onUnderlyingNetworkChanged(validated = true))

        assertEquals(listOf("lease-a", "lease-b"), native.rebound)
    }

    @Test
    fun availableUnvalidatedNetworkRebindsBothMembersWhileHealthStaysSuspended() {
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(store(transaction()), FakePanel(), native)

        assertTrue(coordinator.onUnderlyingNetworkChanged(validated = false))

        assertEquals(listOf("lease-a", "lease-b"), native.rebound)
    }

    @Test
    fun firstRebindFailureDoesNotSkipTheSecondCurrentMember() {
        val native = FakeNative(rebindResults = ArrayDeque(listOf(false, true)))
        val coordinator = RedundantConnectionCoordinator(store(transaction()), FakePanel(), native)

        assertFalse(coordinator.onUnderlyingNetworkChanged(validated = true))

        assertEquals(listOf("lease-a", "lease-b"), native.rebindAttempts)
        assertEquals(listOf("lease-b"), native.rebound)
    }

    @Test
    fun failedWalPersistNeverChangesTheNativeActiveMember() {
        val backend = CoordinatorRecordBackend()
        val store = store(transaction(), backend)
        backend.failOnWriteNumber = backend.writeCount + 1
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(store, FakePanel(), native)

        assertFalse(coordinator.slotFailed("lease-a", "primary_unhealthy"))

        assertEquals("lease-a", coordinator.status()?.localActiveLeaseId)
        assertTrue(native.activationAttempts.isEmpty())
    }

    @Test
    fun failedNativeActivationLeavesSourceAuthoritativeAndWalPending() {
        val native = FakeNative(activateResults = ArrayDeque(listOf(false)))
        val coordinator = RedundantConnectionCoordinator(store(transaction()), FakePanel(), native)

        assertFalse(coordinator.slotFailed("lease-a", "primary_unhealthy"))

        val pending = requireNotNull(coordinator.status())
        assertEquals("lease-a", pending.localActiveLeaseId)
        assertEquals("lease-a", pending.retry.pendingNativeSourceLeaseId)
        assertEquals("lease-b", pending.retry.pendingNativeActiveLeaseId)
        assertEquals(1, pending.retry.pendingNativeSwitchAttempt)
        assertFalse(pending.retry.roleObservationPending)
    }

    @Test
    fun failedFinalizePersistReplaysTheSameNativeTargetOnNextTick() {
        val backend = CoordinatorRecordBackend()
        val store = store(transaction(), backend)
        backend.failOnWriteNumber = backend.writeCount + 2
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(store, FakePanel(), native)

        assertFalse(coordinator.slotFailed("lease-a", "primary_unhealthy"))
        assertEquals("lease-a", coordinator.status()?.localActiveLeaseId)
        assertEquals("lease-b", coordinator.status()?.retry?.pendingNativeActiveLeaseId)

        assertTrue(coordinator.tick())
        assertEquals("lease-b", coordinator.status()?.localActiveLeaseId)
        assertEquals(listOf("lease-b", "lease-b"), native.activationAttempts)
        assertEquals(null, coordinator.status()?.retry?.pendingNativeActiveLeaseId)
    }

    @Test
    fun processRecoveryActivatesPendingTargetBeforePublishingItsRole() {
        val pending = pendingNativeSwitch()
        val panel = FakePanel(recoveredSession = session(
            activeLeaseId = "lease-a",
            roleGeneration = 2,
            membershipGeneration = 1,
        ))
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(store(pending), panel, native)

        assertTrue(coordinator.recover())

        assertEquals("lease-b", coordinator.status()?.localActiveLeaseId)
        assertEquals("lease-b", native.started.first())
        assertEquals("lease-b", native.activationAttempts.first())
        assertFalse(requireNotNull(coordinator.status()).retry.roleObservationPending)
        assertEquals(1, panel.roleCalls)
    }

    @Test
    fun processRecoveryRetriesPendingActivationBeforePublishingReadiness() {
        val panel = FakePanel(
            recoveredSession = session("lease-a", 2, 1),
            recoveryHealthProbes = mapOf("lease-b" to probe()),
        )
        val native = FakeNative(activateResults = ArrayDeque(listOf(false, true))).apply {
            healthSnapshots += listOf(healthSlot(1, active = true, health = BackendHealth.READY,
                handshakeFresh = true, consecutiveProbeSuccesses = 3, stableSinceMs = 0))
        }
        val readiness = mutableListOf<Boolean>()
        val coordinator = RedundantConnectionCoordinator(store(pendingNativeSwitch()), panel, native,
            onRecoveryReadiness = { readiness += it })

        assertFalse(coordinator.recover())
        assertTrue(readiness.isEmpty())
        assertTrue(requireNotNull(coordinator.status()).desiredActive)
        assertEquals(1, coordinator.status()?.retry?.pendingNativeSwitchAttempt)
        assertTrue(coordinator.tick())
        assertFalse(coordinator.isRunning())
        assertTrue(readiness.isEmpty())
        assertTrue(coordinator.tick())
        assertTrue(coordinator.isRunning())
        assertEquals(listOf(true), readiness)
        assertEquals("lease-b", coordinator.status()?.localActiveLeaseId)
        assertEquals(null, coordinator.status()?.retry?.pendingNativeActiveLeaseId)
        assertEquals(listOf("lease-b", "lease-b"), native.activationAttempts)
        assertEquals(listOf("start-operation", "start-operation"), panel.recoveredOperations)
    }

    @Test
    fun processRecoveryExhaustsSwitchRetriesBeforeRestoringSourceOrRequestingRestart() {
        for (sourceUsable in listOf(true, false)) {
            val panel = FakePanel(recoveredSession = session("lease-a", 2, 1),
                recoveryHealthProbes = mapOf("lease-a" to probe(), "lease-b" to probe()))
            val native = FakeNative(
                usable = if (sourceUsable) setOf("lease-a", "lease-b") else setOf("lease-b"),
                activateResults = ArrayDeque(listOf(false, false, false, true)),
            ).apply {
                healthSnapshots += listOf(healthSlot(0, active = true, health = BackendHealth.READY,
                    handshakeFresh = true, consecutiveProbeSuccesses = 3, stableSinceMs = 0))
            }
            val readiness = mutableListOf<Boolean>()
            var restarts = 0
            val coordinator = RedundantConnectionCoordinator(store(pendingNativeSwitch()), panel, native,
                onRecoveryReadiness = { readiness += it }, onAllSlotsStalled = { restarts += 1 })
            assertFalse(coordinator.recover())
            assertTrue(readiness.isEmpty())
            assertFalse(coordinator.tick())
            assertFalse(coordinator.tick())
            assertTrue(readiness.isEmpty())
            assertEquals(3, native.activationAttempts.count { it == "lease-b" })
            assertEquals(if (sourceUsable) 0 else 1, restarts)
            if (sourceUsable) {
                assertEquals("lease-a", coordinator.status()?.localActiveLeaseId)
                assertEquals(null, coordinator.status()?.retry?.pendingNativeActiveLeaseId)
                assertTrue(coordinator.tick())
                assertFalse(coordinator.isRunning())
                assertTrue(coordinator.tick())
                assertTrue(coordinator.isRunning())
                assertEquals(listOf(true), readiness)
            } else {
                assertFalse(coordinator.tick())
                assertFalse(coordinator.resume())
                assertEquals(1, restarts)
            }
        }
    }

    @Test
    fun cancellationBetweenRecoveredSwitchAttemptsPreventsAnotherActivation() {
        val store = store(pendingNativeSwitch())
        val native = FakeNative(activateResults = ArrayDeque(listOf(false, true)))
        val readiness = mutableListOf<Boolean>()
        val coordinator = RedundantConnectionCoordinator(store,
            FakePanel(recoveredSession = session("lease-a", 2, 1)), native,
            onRecoveryReadiness = { readiness += it })
        assertFalse(coordinator.recover())
        assertTrue(readiness.isEmpty())
        store.cancelRedundantIntentAndDeferStop("stop-operation", "start-operation")
        assertFalse(coordinator.tick())
        assertEquals(listOf("lease-b"), native.activationAttempts)
        assertTrue(readiness.isEmpty())
        assertFalse(requireNotNull(coordinator.status()).desiredActive)
    }

    @Test
    fun missingPendingTargetConfigurationRetainsWalWithoutStartingTheSource() {
        val pending = pendingNativeSwitch()
        val panel = FakePanel(
            recoveredSession = session(
                activeLeaseId = "lease-a",
                roleGeneration = 2,
                membershipGeneration = 1,
            ),
            configurations = mapOf("lease-a" to byteArrayOf(1)),
        )
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(store(pending), panel, native)

        assertFalse(coordinator.recover())

        assertTrue(native.started.isEmpty())
        assertEquals("lease-a", coordinator.status()?.localActiveLeaseId)
        assertEquals("lease-b", coordinator.status()?.retry?.pendingNativeActiveLeaseId)
    }

    @Test
    fun stalePendingMembershipFailsClosedInsteadOfRebasingToAnotherMemberSet() {
        var totalLosses = 0
        val panel = FakePanel(recoveredSession = session(
            activeLeaseId = "lease-a",
            roleGeneration = 2,
            membershipGeneration = 2,
            slotBLeaseId = "replacement-b",
        ))
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(
            store(pendingNativeSwitch()),
            panel,
            native,
            onAllSlotsStalled = { totalLosses += 1 },
        )

        assertFalse(coordinator.recover())

        assertEquals(0, totalLosses)
        assertEquals(1, panel.stopCalls)
        assertEquals(1, native.stopCalls)
        assertEquals(null, coordinator.status())
    }

    @Test
    fun pendingActivationRetriesAreBoundedAndReplaceTheFailedTarget() {
        val native = FakeNative(
            activateResults = ArrayDeque(listOf(false, false, false, true)),
        )
        val coordinator = RedundantConnectionCoordinator(store(transaction()), FakePanel(), native)

        assertFalse(coordinator.slotFailed("lease-a", "primary_unhealthy"))
        assertFalse(coordinator.tick())
        assertFalse(coordinator.tick())

        val resolved = requireNotNull(coordinator.status())
        assertEquals("lease-a", resolved.localActiveLeaseId)
        assertEquals(null, resolved.retry.pendingNativeActiveLeaseId)
        assertTrue(resolved.retry.acquirePending)
        assertEquals("lease-b", resolved.retry.acquireReplaceLeaseId)
        assertEquals(listOf("lease-b", "lease-b", "lease-b", "lease-a"), native.activationAttempts)
    }

    @Test
    fun explicitRevokeClearsPendingSwitchAndPreventsAnotherActivation() {
        val native = FakeNative(activateResults = ArrayDeque(listOf(false)))
        val coordinator = RedundantConnectionCoordinator(store(transaction()), FakePanel(), native)

        assertFalse(coordinator.slotFailed("lease-a", "primary_unhealthy"))
        assertTrue(coordinator.revoke())

        assertEquals(listOf("lease-b"), native.activationAttempts)
        assertEquals(null, coordinator.status())
        assertFalse(coordinator.tick())
        assertEquals(listOf("lease-b"), native.activationAttempts)
    }

    @Test
    fun memberBeingReplacedCannotBecomeActiveAndThenBeStoppedByCandidate() {
        val candidatePending = transaction().copy(
            candidateLeaseId = "candidate",
            candidateSlot = RedundantSlot.B,
            retry = AndroidRedundantRetryState(
                acquirePending = true,
                acquireOperationId = "replace-b",
                acquireReplaceLeaseId = "lease-b",
            ),
        )
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(store(candidatePending), FakePanel(), native)

        assertFalse(coordinator.slotFailed("lease-a", "primary_unhealthy"))
        assertTrue(coordinator.tick())

        assertEquals("lease-a", coordinator.status()?.localActiveLeaseId)
        assertTrue(native.activationAttempts.isEmpty())
        assertTrue("lease-b was not replaced", "stop:lease-b" in native.events)
    }

    @Test
    fun repeatedRoleFailuresCoalesceToTheLatestLocalActiveMember() {
        val panel = FakePanel(roleFailures = ArrayDeque(listOf(true, true)))
        val transaction = transaction().copy(standbyDesired = false)
        val coordinator = RedundantConnectionCoordinator(store(transaction), panel, FakeNative())

        assertTrue(coordinator.slotFailed("lease-a", "a_failed"))
        assertTrue(coordinator.slotFailed("lease-b", "b_failed"))

        val pending = requireNotNull(coordinator.status())
        assertEquals("lease-a", pending.localActiveLeaseId)
        assertEquals("lease-a", pending.retry.pendingRoleLeaseId)
        assertEquals("b_failed", pending.retry.pendingRoleReason)
    }

    @Test
    fun replacementDeadlineSurvivesCoordinatorRecreation() {
        var nowMs = 2_000_000L
        val store = store(transaction())
        val panel = FakePanel()
        val first = RedundantConnectionCoordinator(
            store,
            panel,
            FakeNative(),
            epochNowMs = { nowMs },
        )

        assertTrue(first.onHealthObservations(listOf(
            healthSlot(index = 0, active = true, hardFailure = true),
            healthSlot(index = 1, health = BackendHealth.READY),
        )))
        val pending = requireNotNull(first.status()).retry
        assertTrue(pending.acquirePending)
        assertEquals("lease-a", pending.acquireReplaceLeaseId)

        nowMs += 59_000
        assertTrue(RedundantConnectionCoordinator(
            store,
            panel,
            FakeNative(),
            epochNowMs = { nowMs },
        ).tick())
        assertTrue(panel.acquireOperationIds.isEmpty())

        nowMs += 1_000
        assertTrue(RedundantConnectionCoordinator(
            store,
            panel,
            FakeNative(),
            epochNowMs = { nowMs },
        ).tick())
        assertEquals(listOf("lease-a"), panel.acquireReplaceLeaseIds)
    }

    @Test
    fun recoveredFormerPrimaryCancelsReplacementBeforeDeadline() {
        var nowMs = 2_500_000L
        val panel = FakePanel()
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(
            store(transaction()),
            panel,
            native,
            epochNowMs = { nowMs },
            monotonicMs = { nowMs },
        )

        assertTrue(coordinator.onHealthObservations(listOf(
            healthSlot(index = 0, active = true, hardFailure = true),
            healthSlot(index = 1, health = BackendHealth.READY),
        )))
        assertTrue(requireNotNull(coordinator.status()).retry.acquirePending)

        nowMs += 15_000L
        assertTrue(coordinator.onHealthObservations(listOf(
            healthSlot(
                index = 0,
                handshakeFresh = true,
                consecutiveProbeSuccesses = 3,
                stableSinceMs = nowMs - 15_000L,
            ),
            healthSlot(index = 1, active = true, health = BackendHealth.READY),
        )))
        val recovered = requireNotNull(coordinator.status())
        assertFalse(recovered.retry.acquirePending)
        assertEquals(null, recovered.retry.acquireOperationId)
        assertEquals(null, recovered.retry.acquireReplaceLeaseId)
        assertEquals(null, recovered.retry.nextRetryAtUnix)

        nowMs += 60_000L
        assertTrue(coordinator.tick())
        assertTrue(panel.acquireOperationIds.isEmpty())
        assertEquals("lease-b", coordinator.status()?.localActiveLeaseId)
    }

    @Test
    fun disablingStandbyCancelsScheduledReplacementForTheSession() {
        var nowMs = 3_000_000L
        val panel = FakePanel()
        val coordinator = RedundantConnectionCoordinator(
            store(transaction()),
            panel,
            FakeNative(),
            epochNowMs = { nowMs },
        )

        assertTrue(coordinator.onHealthObservations(listOf(
            healthSlot(index = 0, active = true, hardFailure = true),
            healthSlot(index = 1, health = BackendHealth.READY),
        )))
        assertTrue(coordinator.releaseStandby())
        val released = requireNotNull(coordinator.status())
        assertFalse(released.standbyDesired)
        assertEquals(transaction().startReserveEnabled, released.startReserveEnabled)
        assertEquals(transaction().startRequestFingerprint, released.startRequestFingerprint)
        assertFalse(released.retry.acquirePending)
        assertEquals(null, released.retry.nextRetryAtUnix)

        nowMs += 60_000
        assertTrue(coordinator.tick())
        assertTrue(panel.acquireOperationIds.isEmpty())
        assertEquals(listOf("lease-a"), panel.releasedLeaseIds)
    }

    @Test
    fun disablingADegradedSingleMemberSessionNeedsNoSyntheticMemberRelease() {
        val panel = FakePanel()
        val single = transaction().copy(slotBLeaseId = null)
        val coordinator = RedundantConnectionCoordinator(store(single), panel, FakeNative())

        assertTrue(coordinator.releaseStandby())
        assertFalse(requireNotNull(coordinator.status()).standbyDesired)
        assertEquals(1, panel.releaseAttempts.size)
        assertEquals(null, coordinator.reserveState())
    }

    @Test
    fun failedStandbyReleaseIsRetriedByTickWithoutReenablingStandby() {
        val panel = FakePanel(releaseFailures = ArrayDeque(listOf(true, false)))
        val coordinator = RedundantConnectionCoordinator(store(transaction()), panel, FakeNative())

        assertFalse(coordinator.releaseStandby())
        assertFalse(requireNotNull(coordinator.status()).standbyDesired)
        assertTrue(coordinator.tick())

        val released = requireNotNull(coordinator.status())
        assertFalse(released.standbyDesired)
        assertEquals(null, released.slotBLeaseId)
        assertEquals(listOf("lease-b", "lease-b"), panel.releaseAttempts)
        assertTrue(panel.acquireOperationIds.isEmpty())
    }

    @Test
    fun standbyReleaseConflictRebasesGenerationsBeforeRetryingExactInactiveMember() {
        val panel = FakePanel(
            recoveredSession = session(
                activeLeaseId = "lease-a",
                roleGeneration = 7,
                membershipGeneration = 4,
            ),
            releaseFailureCodes = ArrayDeque(listOf("session_membership_conflict")),
        )
        val coordinator = RedundantConnectionCoordinator(store(transaction()), panel, FakeNative())

        assertFalse(coordinator.releaseStandby())
        val rebased = requireNotNull(coordinator.status())
        assertFalse(rebased.standbyDesired)
        assertEquals(7L, rebased.roleGeneration)
        assertEquals(4L, rebased.membershipGeneration)

        assertTrue(coordinator.tick())
        assertEquals(listOf("lease-b", "lease-b"), panel.releaseAttempts)
        assertEquals(null, coordinator.status()?.slotBLeaseId)
    }

    @Test
    fun recoveryWithDisabledStandbyStartsOnlyActiveAndDrainsCanonicalInactive() {
        val disabled = transaction().copy(standbyDesired = false)
        val panel = FakePanel()
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(store(disabled), panel, native)

        assertTrue(coordinator.recover())

        assertEquals(listOf("lease-a"), native.started)
        assertEquals(listOf("lease-a"), native.activated)
        assertEquals(listOf("lease-b"), panel.releaseAttempts)
        assertFalse(requireNotNull(coordinator.status()).standbyDesired)
        assertEquals(null, coordinator.status()?.slotBLeaseId)
    }

    @Test
    fun acquireResponseDisablingStandbyCancelsWorkAndZeroesUnusedConfiguration() {
        val panel = FakePanel(acquiredSession = session(
            activeLeaseId = "lease-a",
            roleGeneration = 2,
            membershipGeneration = 2,
            standbyDesired = false,
        ))
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(store(transaction()), panel, native)

        assertFalse(coordinator.acquireAndCommitStandby("acquire-disabled"))

        assertFalse(requireNotNull(coordinator.status()).standbyDesired)
        assertFalse(requireNotNull(coordinator.status()).retry.acquirePending)
        assertTrue(panel.candidateConfigurations.single().all { it == 0.toByte() })
        assertFalse(native.started.contains("candidate"))
    }

    @Test
    fun roleObservationIsDurableBeforeActivationAndReplayedAfterProcessDeath() {
        val store = store(transaction())
        val panel = FakePanel(roleFailures = ArrayDeque(listOf(true, false)))
        val native = FakeNative(usable = setOf("lease-b"))
        val first = RedundantConnectionCoordinator(store, panel, native)

        assertTrue(first.slotFailed("lease-a", "primary_unhealthy"))
        val pending = requireNotNull(first.status())
        assertTrue(pending.retry.roleObservationPending)
        assertEquals("lease-b", pending.retry.pendingRoleLeaseId)
        assertEquals("primary_unhealthy", pending.retry.pendingRoleReason)

        assertTrue(RedundantConnectionCoordinator(store, panel, native).reportLocalRole("ignored"))
        assertFalse(requireNotNull(first.status()).retry.roleObservationPending)
    }

    @Test
    fun terminalRoleConflictRecoversCanonicalMembershipAndRetriesExactPendingRole() {
        val recoveredConfigurations = mapOf(
            "lease-a" to "secret-a".toByteArray(),
            "lease-b" to "secret-b".toByteArray(),
        )
        val panel = FakePanel(
            role = RedundantRoleResponse(
                action = "accepted",
                localActiveLeaseId = "lease-a",
                session = session(
                    activeLeaseId = "lease-a",
                    roleGeneration = 7,
                    membershipGeneration = 4,
                ),
            ),
            configurations = recoveredConfigurations,
            recoveredSession = session(
                activeLeaseId = "lease-a",
                roleGeneration = 7,
                membershipGeneration = 4,
            ),
            roleFailureCodes = ArrayDeque(listOf("session_membership_conflict")),
        )
        val coordinator = RedundantConnectionCoordinator(store(transaction()), panel, FakeNative())

        assertTrue(coordinator.reportLocalRole("primary_unhealthy"))

        val recovered = requireNotNull(coordinator.status())
        assertEquals(2, panel.roleCalls)
        assertEquals(1, panel.recoverCalls)
        assertEquals(7L, recovered.roleGeneration)
        assertEquals(4L, recovered.membershipGeneration)
        assertFalse(recovered.retry.roleObservationPending)
        assertTrue(recoveredConfigurations.values.all { bytes -> bytes.all { it == 0.toByte() } })
    }

    @Test
    fun terminalRoleConflictFailsClosedWhenPendingActiveLeaseWasRemoved() {
        val recoveredConfigurations = mapOf(
            "replacement-a" to "replacement-secret".toByteArray(),
        )
        val panel = FakePanel(
            configurations = recoveredConfigurations,
            recoveredSession = BackgroundRedundantSession(
                sessionId = "22222222-2222-4222-8222-222222222222",
                state = "connected",
                activeLeaseId = "replacement-a",
                slotALeaseId = "replacement-a",
                slotBLeaseId = null,
                standbyDesired = true,
                roleGeneration = 7,
                membershipGeneration = 4,
                reason = null,
            ),
            roleFailureCodes = ArrayDeque(listOf("session_membership_conflict")),
        )
        var totalLossCallbacks = 0
        val coordinator = RedundantConnectionCoordinator(
            store(transaction()),
            panel,
            FakeNative(),
            onAllSlotsStalled = { totalLossCallbacks += 1 },
        )

        assertFalse(coordinator.reportLocalRole("primary_unhealthy"))
        assertFalse(coordinator.reportLocalRole("primary_unhealthy"))

        assertEquals(1, panel.roleCalls)
        assertEquals(1, panel.recoverCalls)
        assertEquals(1, totalLossCallbacks)
        assertTrue(requireNotNull(coordinator.status()).retry.roleObservationPending)
        assertTrue(recoveredConfigurations.values.all { bytes -> bytes.all { it == 0.toByte() } })
    }

    @Test
    fun terminalRoleConflictKeepsObservationPendingWhenRecoveryTransportFails() {
        val panel = FakePanel(
            roleFailureCodes = ArrayDeque(listOf("session_membership_conflict")),
            recoverFailures = ArrayDeque(listOf(true)),
        )
        var totalLossCallbacks = 0
        val coordinator = RedundantConnectionCoordinator(
            store(transaction()),
            panel,
            FakeNative(),
            onAllSlotsStalled = { totalLossCallbacks += 1 },
        )

        assertFalse(coordinator.reportLocalRole("primary_unhealthy"))

        assertEquals(1, panel.recoverCalls)
        assertEquals(0, totalLossCallbacks)
        assertTrue(requireNotNull(coordinator.status()).retry.roleObservationPending)
    }

    @Test
    fun recoveryDrainsPendingRoleObservationAfterProcessRecreation() {
        val pending = transaction(localActiveLeaseId = "lease-b").copy(
            retry = AndroidRedundantRetryState(
                roleObservationPending = true,
                pendingRoleLeaseId = "lease-b",
                pendingRoleReason = "primary_unhealthy",
            ),
        )
        val store = store(pending)
        val panel = FakePanel(role = RedundantRoleResponse(
            action = "rebase",
            localActiveLeaseId = "lease-b",
            session = session(activeLeaseId = "lease-a", roleGeneration = 7, membershipGeneration = 3),
        ))

        assertTrue(RedundantConnectionCoordinator(store, panel, FakeNative()).recover())
        val recovered = requireNotNull(RedundantConnectionCoordinator(store, panel, FakeNative()).status())
        assertEquals("lease-b", recovered.localActiveLeaseId)
        assertEquals(7, recovered.roleGeneration)
        assertEquals(3, recovered.membershipGeneration)
        assertFalse(recovered.retry.roleObservationPending)
        assertEquals(2, panel.roleCalls)
    }

    @Test
    fun acquireIdentityIsDurableBeforeRequestAndReplayedWithTheSameOperation() {
        val store = store(transaction())
        val panel = FakePanel(acquireFailures = ArrayDeque(listOf(true, false)))
        val coordinator = RedundantConnectionCoordinator(store, panel, FakeNative())

        assertFalse(coordinator.acquireAndCommitStandby("acquire-1"))
        val pending = requireNotNull(coordinator.status())
        assertEquals("acquire-1", pending.retry.acquireOperationId)
        assertTrue(pending.retry.acquirePending)

        assertTrue(RedundantConnectionCoordinator(store, panel, FakeNative()).acquireAndCommitStandby("different"))
        assertEquals(listOf("acquire-1", "acquire-1"), panel.acquireOperationIds)
    }

    @Test
    fun recoveryDrainsPendingAcquireWithItsOriginalOperationAndInactiveReplaceLease() {
        var nowMs = 1_000_000L
        val store = store(transaction())
        val panel = FakePanel(acquireFailures = ArrayDeque(listOf(true, false)))
        val first = RedundantConnectionCoordinator(store, panel, FakeNative(), epochNowMs = { nowMs })

        assertFalse(first.acquireAndCommitStandby("acquire-1", replaceLeaseId = "lease-b"))
        assertEquals("lease-b", requireNotNull(first.status()).retry.acquireReplaceLeaseId)

        val reconstructed = RedundantConnectionCoordinator(store, panel, FakeNative(), epochNowMs = { nowMs })
        assertTrue(reconstructed.recover())
        assertEquals(listOf("acquire-1"), panel.acquireOperationIds)
        nowMs += 300_000L
        assertTrue(reconstructed.tick())
        assertEquals(listOf("acquire-1", "acquire-1"), panel.acquireOperationIds)
        assertEquals(listOf("lease-b", "lease-b"), panel.acquireReplaceLeaseIds)
    }

    @Test
    fun degradedSessionAcquiresIntoEmptySlotAndReplaysNullReplacement() {
        val store = store(transaction().copy(slotBLeaseId = null))
        val panel = FakePanel(acquireFailures = ArrayDeque(listOf(true, false)))
        val first = RedundantConnectionCoordinator(store, panel, FakeNative())

        assertFalse(first.acquireAndCommitStandby("acquire-empty"))
        val pending = requireNotNull(first.status()).retry
        assertTrue(pending.acquirePending)
        assertEquals("acquire-empty", pending.acquireOperationId)
        assertEquals(null, pending.acquireReplaceLeaseId)

        assertTrue(RedundantConnectionCoordinator(store, panel, FakeNative()).acquireAndCommitStandby("different"))
        assertEquals(listOf("acquire-empty", "acquire-empty"), panel.acquireOperationIds)
        assertEquals(listOf(null, null), panel.acquireReplaceLeaseIds)
    }

    @Test
    fun stagedEmptySlotCandidateReplaysAfterRestartWithoutStoppingAMember() {
        var nowMs = 1_000_000L
        val store = store(transaction().copy(slotBLeaseId = null))
        val panel = FakePanel(acquiredSession = session(
            activeLeaseId = "lease-a",
            roleGeneration = 1,
            membershipGeneration = 1,
            slotBLeaseId = null,
        ))
        assertTrue(RedundantConnectionCoordinator(
            store,
            panel,
            FakeNative(),
            epochNowMs = { nowMs },
            monotonicMs = { nowMs },
        ).acquireAndCommitStandby("fill-empty"))

        val replayNative = FakeNative(usable = setOf("lease-a", "candidate"))
        val replayed = RedundantConnectionCoordinator(
            store,
            panel,
            replayNative,
            epochNowMs = { nowMs },
            monotonicMs = { nowMs },
        )

        assertTrue(replayed.tick())
        assertEquals(listOf("start:candidate"), replayNative.events)
        assertEquals("candidate", replayed.status()?.candidateLeaseId)
        assertEquals(null, replayed.status()?.retry?.acquireReplaceLeaseId)
        assertEquals(0, panel.commitCalls)

        nowMs += 15_000L
        replayNative.healthSnapshots += listOf(
            healthSlot(index = 0, active = true, health = BackendHealth.READY),
            healthSlot(
                index = 1,
                health = BackendHealth.READY,
                handshakeFresh = true,
                consecutiveProbeSuccesses = 3,
                stableSinceMs = nowMs - 15_000L,
            ),
        )
        assertTrue(replayed.tick())
        assertEquals(1, panel.commitCalls)
        assertEquals("candidate", replayed.status()?.slotBLeaseId)
        assertFalse(requireNotNull(replayed.status()).retry.acquirePending)
    }

    @Test
    fun initialAcquireRejectsCandidateThatAliasesTheActiveCurrentMember() {
        val panel = FakePanel(acquiredCandidateLeaseId = "lease-a")
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(store(transaction()), panel, native)

        assertFalse(coordinator.acquireAndCommitStandby(
            "malicious-alias",
            replaceLeaseId = "lease-b",
        ))

        assertTrue(native.events.isEmpty())
        assertEquals(null, coordinator.status()?.candidateLeaseId)
        assertTrue(requireNotNull(coordinator.status()).retry.acquirePending)
        assertEquals("lease-b", coordinator.status()?.retry?.acquireReplaceLeaseId)
    }

    @Test
    fun replacementCommitUsesCanonicalActiveAndGenerationsReturnedByAcquire() {
        var nowMs = 1_000_000L
        val acquired = session(
            activeLeaseId = "lease-b",
            roleGeneration = 8,
            membershipGeneration = 4,
        )
        val panel = FakePanel(acquiredSession = acquired)
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(
            store(transaction(localActiveLeaseId = "lease-b")),
            panel,
            native,
            epochNowMs = { nowMs },
            monotonicMs = { nowMs },
        )

        assertTrue(coordinator.acquireAndCommitStandby("replace-a", replaceLeaseId = "lease-a"))
        assertEquals(0, panel.commitCalls)
        native.healthSnapshots += listOf(
            healthSlot(
                index = 0,
                handshakeFresh = true,
                consecutiveProbeSuccesses = 3,
                stableSinceMs = nowMs,
            ),
            healthSlot(index = 1, health = BackendHealth.READY),
        )
        nowMs += 15_000L
        assertTrue(coordinator.tick())

        val committed = panel.commitTransactions.single()
        assertEquals("lease-b", committed.localActiveLeaseId)
        assertEquals(8, committed.roleGeneration)
        assertEquals(4, committed.membershipGeneration)
    }

    @Test
    fun replacementCanReissueExactInactiveCurrentMemberBeforeFreshCommit() {
        var nowMs = 1_000_000L
        val current = session(
            activeLeaseId = "lease-a",
            roleGeneration = 1,
            membershipGeneration = 1,
        )
        val panel = FakePanel(
            acquiredSession = current,
            acquiredCandidateLeaseId = "lease-b",
            committedSession = current,
        )
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(
            store(transaction()),
            panel,
            native,
            epochNowMs = { nowMs },
            monotonicMs = { nowMs },
        )

        assertTrue(coordinator.acquireAndCommitStandby(
            "reissue-inactive",
            replaceLeaseId = "lease-b",
        ))
        val staged = requireNotNull(coordinator.status())
        assertEquals("lease-b", staged.candidateLeaseId)
        assertEquals("lease-b", staged.retry.acquireReplaceLeaseId)
        assertEquals(listOf("stop:lease-b", "start:lease-b"), native.events)
        assertEquals(0, panel.commitCalls)

        nowMs += 15_000L
        native.healthSnapshots += listOf(
            healthSlot(index = 0, active = true, health = BackendHealth.READY),
            healthSlot(
                index = 1,
                health = BackendHealth.READY,
                handshakeFresh = true,
                consecutiveProbeSuccesses = 3,
                stableSinceMs = nowMs - 15_000L,
            ),
        )
        assertTrue(coordinator.tick())

        val committed = requireNotNull(coordinator.status())
        assertEquals(1, panel.commitCalls)
        assertEquals("lease-b", panel.commitCandidateLeaseIds.single())
        assertEquals(1, committed.roleGeneration)
        assertEquals(1, committed.membershipGeneration)
        assertEquals(null, committed.candidateLeaseId)
        assertFalse(committed.retry.acquirePending)
        assertEquals(RedundantReserveState.READY, coordinator.reserveState())
    }

    @Test
    fun replayedExactInactiveMemberSurvivesCanonicalRefreshAndRequiresFreshHealth() {
        var nowMs = 1_000_000L
        val current = session(
            activeLeaseId = "lease-a",
            roleGeneration = 1,
            membershipGeneration = 1,
        )
        val store = store(transaction())
        val panel = FakePanel(
            acquiredSession = current,
            acquiredCandidateLeaseId = "lease-b",
            committedSession = current,
        )
        assertTrue(RedundantConnectionCoordinator(
            store,
            panel,
            FakeNative(),
            epochNowMs = { nowMs },
            monotonicMs = { nowMs },
        ).acquireAndCommitStandby("reissue-inactive", replaceLeaseId = "lease-b"))

        val replayNative = FakeNative()
        val replayed = RedundantConnectionCoordinator(
            store,
            panel,
            replayNative,
            epochNowMs = { nowMs },
            monotonicMs = { nowMs },
        )
        val staleReady = listOf(
            healthSlot(index = 0, active = true, health = BackendHealth.READY),
            healthSlot(
                index = 1,
                health = BackendHealth.READY,
                handshakeFresh = true,
                consecutiveProbeSuccesses = 3,
                stableSinceMs = nowMs - 15_000L,
            ),
        )

        replayNative.healthSnapshots += staleReady
        assertTrue(replayed.tick())
        assertEquals(0, panel.commitCalls)
        assertEquals("lease-b", replayed.status()?.candidateLeaseId)
        assertEquals(listOf("stop:lease-b", "start:lease-b"), replayNative.events)

        nowMs += 15_000L
        replayNative.healthSnapshots += listOf(
            healthSlot(index = 0, active = true, health = BackendHealth.READY),
            healthSlot(
                index = 1,
                health = BackendHealth.READY,
                handshakeFresh = true,
                consecutiveProbeSuccesses = 3,
                stableSinceMs = nowMs - 15_000L,
            ),
        )
        assertTrue(replayed.tick())
        assertEquals(1, panel.commitCalls)
        assertEquals(null, replayed.status()?.candidateLeaseId)
        assertFalse(requireNotNull(replayed.status()).retry.acquirePending)
        assertEquals(RedundantReserveState.READY, replayed.reserveState())
    }

    @Test
    fun replayedExactInactiveFallbackSafelyRestagesAChangedServerCandidate() {
        var nowMs = 1_000_000L
        val current = session(
            activeLeaseId = "lease-a",
            roleGeneration = 1,
            membershipGeneration = 1,
        )
        val store = store(transaction())
        val panel = FakePanel(
            acquiredSession = current,
            acquiredCandidateLeaseIds = ArrayDeque(listOf("lease-b", "candidate-new")),
        )
        assertTrue(RedundantConnectionCoordinator(
            store,
            panel,
            FakeNative(),
            epochNowMs = { nowMs },
            monotonicMs = { nowMs },
        ).acquireAndCommitStandby("reissue-inactive", replaceLeaseId = "lease-b"))

        val replayNative = FakeNative(usable = setOf("lease-a", "lease-b", "candidate-new"))
        val replayed = RedundantConnectionCoordinator(
            store,
            panel,
            replayNative,
            epochNowMs = { nowMs },
            monotonicMs = { nowMs },
        )
        val staleReady = listOf(
            healthSlot(index = 0, active = true, health = BackendHealth.READY),
            healthSlot(
                index = 1,
                health = BackendHealth.READY,
                handshakeFresh = true,
                consecutiveProbeSuccesses = 3,
                stableSinceMs = nowMs - 15_000L,
            ),
        )

        replayNative.healthSnapshots += staleReady
        assertTrue(replayed.tick())
        assertEquals(0, panel.commitCalls)
        assertEquals("candidate-new", replayed.status()?.candidateLeaseId)
        assertEquals(listOf("stop:lease-b", "start:candidate-new"), replayNative.events)

        nowMs += 15_000L
        replayNative.healthSnapshots += listOf(
            healthSlot(index = 0, active = true, health = BackendHealth.READY),
            healthSlot(
                index = 1,
                health = BackendHealth.READY,
                handshakeFresh = true,
                consecutiveProbeSuccesses = 3,
                stableSinceMs = nowMs - 15_000L,
            ),
        )
        assertTrue(replayed.tick())
        assertEquals(1, panel.commitCalls)
        assertEquals("candidate-new", panel.commitCandidateLeaseIds.single())
        assertEquals("candidate-new", replayed.status()?.slotBLeaseId)
        assertEquals(null, replayed.status()?.candidateLeaseId)
        assertFalse(requireNotNull(replayed.status()).retry.acquirePending)
    }

    @Test
    fun startupStandbyWaitsForFailureEpisodeProbeBeforeSwitching() {
        for (recovering in listOf(false, true)) {
            var now = 20_000L
            val original = transaction().let { it.copy(retry = it.retry.copy(
                acquirePending = true, acquireOperationId = "repair", acquireReplaceLeaseId = "lease-b",
            )) }
            val readiness = mutableListOf<Boolean>()
            val native = FakeNative()
            val panel = FakePanel(recoveredSession = session("lease-a", 1, 1),
                recoveryHealthProbes = mapOf("lease-a" to probe(), "lease-b" to probe()),
                role = RedundantRoleResponse("accepted", "lease-b", session("lease-b", 2, 1)))
            val coordinator = RedundantConnectionCoordinator(if (recovering) store(original) else emptyStore(),
                panel, native, epochNowMs = { now }, monotonicMs = { now },
                onRecoveryReadiness = { readiness += it })
            if (recovering) assertTrue(coordinator.recover()) else assertTrue(coordinator.start(original,
                mapOf("lease-a" to byteArrayOf(1), "lease-b" to byteArrayOf(2)),
                mapOf("lease-a" to probe(), "lease-b" to probe()),
                onPrimaryStarted = { readiness += true }, onPrimaryFailed = { readiness += false }))
            val primary = healthSlot(0, active = true, hardFailure = true)
            val standby = healthSlot(1, health = BackendHealth.READY, handshakeFresh = true,
                consecutiveProbeSuccesses = 3, stableSinceMs = 0)

            assertTrue(coordinator.onHealthObservations(listOf(primary,
                standby.copy(standbyProbeState = StandbyProbeState.PENDING))))
            assertEquals(listOf("lease-a"), native.activated)
            assertTrue(readiness.isEmpty())
            assertEquals("lease-b", coordinator.status()?.retry?.acquireReplaceLeaseId)
            assertEquals(0, panel.roleCalls)
            assertEquals(0, native.stopCalls)

            now += 1_000L
            assertTrue(coordinator.onHealthObservations(listOf(primary,
                standby.copy(standbyProbeState = StandbyProbeState.SUCCEEDED))))
            assertEquals(listOf("lease-a", "lease-b"), native.activated)
            assertEquals(listOf(true), readiness)
            assertEquals("lease-b", coordinator.status()?.localActiveLeaseId)
            assertEquals(0, native.stopCalls)
        }
    }

    @Test
    fun startupRejectsFailedEpisodeProbeDespiteEarlierReadyHealth() {
        val native = FakeNative()
        val readiness = mutableListOf<Boolean>()
        val panel = FakePanel()
        val coordinator = RedundantConnectionCoordinator(emptyStore(), panel, native,
            epochNowMs = { 20_000L }, monotonicMs = { 20_000L })
        assertTrue(coordinator.start(transaction(),
            mapOf("lease-a" to byteArrayOf(1), "lease-b" to byteArrayOf(2)),
            mapOf("lease-a" to probe(), "lease-b" to probe()),
            onPrimaryStarted = { readiness += true }, onPrimaryFailed = { readiness += false }))

        assertFalse(coordinator.onHealthObservations(listOf(
            healthSlot(0, active = true, hardFailure = true),
            healthSlot(1, health = BackendHealth.READY, handshakeFresh = true,
                consecutiveProbeSuccesses = 3, stableSinceMs = 0)
                .copy(standbyProbeState = StandbyProbeState.FAILED),
        )))
        assertEquals(listOf("lease-a"), native.activated)
        assertEquals(listOf(false), readiness)
        assertEquals(1, native.stopCalls)
        assertEquals(0, panel.roleCalls)
        assertFalse(coordinator.isRunning())
    }

    @Test
    fun pendingStandbyEpisodeProbeCannotExtendPrimaryReadinessDeadline() {
        var now = 20_000L
        val native = FakeNative()
        val readiness = mutableListOf<Boolean>()
        val coordinator = RedundantConnectionCoordinator(emptyStore(), FakePanel(), native,
            epochNowMs = { now }, monotonicMs = { now })
        assertTrue(coordinator.start(transaction(),
            mapOf("lease-a" to byteArrayOf(1), "lease-b" to byteArrayOf(2)),
            mapOf("lease-a" to probe(), "lease-b" to probe()),
            onPrimaryStarted = { readiness += true }, onPrimaryFailed = { readiness += false }))
        val observations = listOf(
            healthSlot(0, active = true, hardFailure = true),
            healthSlot(1, health = BackendHealth.READY, handshakeFresh = true,
                consecutiveProbeSuccesses = 3, stableSinceMs = 0)
                .copy(standbyProbeState = StandbyProbeState.PENDING),
        )
        now = 49_999L
        assertTrue(coordinator.onHealthObservations(observations))
        assertEquals(listOf("lease-a"), native.activated)
        assertTrue(readiness.isEmpty())
        now = 50_000L
        assertFalse(coordinator.onHealthObservations(observations))
        assertEquals(listOf("lease-a"), native.activated)
        assertEquals(listOf(false), readiness)
        assertEquals(1, native.stopCalls)
    }

    @Test
    fun recoveredScheduledRepairDoesNotBlockFreshHealthyStandby() {
        val original = transaction().let { it.copy(retry = it.retry.copy(
            acquirePending = true,
            acquireOperationId = "repair",
            acquireReplaceLeaseId = "lease-b",
        )) }
        val native = FakeNative()
        val readiness = mutableListOf<Boolean>()
        val panel = FakePanel(
            recoveredSession = session("lease-a", 1, 1),
            recoveryHealthProbes = mapOf("lease-a" to probe(), "lease-b" to probe()),
            role = RedundantRoleResponse("accepted", "lease-b", session("lease-b", 2, 1)),
        )
        val coordinator = RedundantConnectionCoordinator(store(original), panel, native,
            epochNowMs = { 20_000L }, monotonicMs = { 20_000L },
            onRecoveryReadiness = { readiness += it })

        assertTrue(coordinator.recover())
        assertTrue(coordinator.onHealthObservations(listOf(
            healthSlot(0, active = true, health = BackendHealth.UNHEALTHY, hardFailure = true),
            healthSlot(1, health = BackendHealth.READY, handshakeFresh = true,
                consecutiveProbeSuccesses = 3, stableSinceMs = 0),
        )))

        assertEquals("lease-b", coordinator.status()?.localActiveLeaseId)
        assertEquals(listOf("lease-a", "lease-b"), native.activated)
        assertEquals(listOf(true), readiness)
        assertEquals(0, native.stopCalls)
        assertTrue(coordinator.isRunning())
        assertFalse(panel.acquireReplaceLeaseIds.contains("lease-b"))
    }

    @Test
    fun freshlyReusedCurrentStandbyFailsOverDespiteLostCommitResponse() {
        // Reconciliation succeeding or failing must not change local failover.
        for (panelOffline in listOf(false, true)) {
            val current = session("lease-a", 1, 1)
            val panel = FakePanel(
                acquiredSession = current,
                acquiredCandidateLeaseId = "lease-b",
                commitFailures = ArrayDeque(listOf(true)),
                role = RedundantRoleResponse("accepted", "lease-a", current),
                roleFailures = ArrayDeque(listOf(panelOffline, true)),
            )
            val native = FakeNative()
            var totalLoss = 0
            val coordinator = RedundantConnectionCoordinator(emptyStore(), panel, native,
                epochNowMs = { 20_000L }, monotonicMs = { 20_000L },
                onAllSlotsStalled = { totalLoss++ })
            assertTrue(coordinator.start(transaction(),
                mapOf("lease-a" to byteArrayOf(1), "lease-b" to byteArrayOf(2))))
            assertTrue(coordinator.acquireAndCommitStandby("repair", "lease-b"))
            val readyStandby = healthSlot(1, health = BackendHealth.READY,
                handshakeFresh = true, consecutiveProbeSuccesses = 3, stableSinceMs = 0)
            native.healthSnapshots += listOf(
                healthSlot(0, active = true, health = BackendHealth.READY,
                    handshakeFresh = true, consecutiveProbeSuccesses = 3, stableSinceMs = 0),
                readyStandby,
            )
            assertFalse(coordinator.tick())
            assertEquals(1, panel.commitCalls)
            assertTrue(requireNotNull(coordinator.status()?.retry?.nextRetryAtUnix) > 20L)
            val roleCalls = panel.roleCalls

            assertTrue(coordinator.onHealthObservations(listOf(
                healthSlot(0, active = true, health = BackendHealth.UNHEALTHY, hardFailure = true),
                readyStandby,
            )))

            assertEquals("lease-b", coordinator.status()?.localActiveLeaseId)
            assertEquals(null, coordinator.status()?.candidateLeaseId)
            assertEquals("lease-a", coordinator.status()?.retry?.acquireReplaceLeaseId)
            assertTrue(requireNotNull(coordinator.status()).retry.roleObservationPending)
            assertEquals(1L, coordinator.status()?.membershipGeneration)
            assertEquals(listOf("lease-a", "lease-b"), native.activated)
            assertEquals(0, totalLoss)
            assertEquals(1, panel.commitCalls)
            assertEquals(roleCalls + 1, panel.roleCalls)
        }
    }

    @Test
    fun startupRepairRecoveryKeepsCandidateAndPersistenceBarriers() {
        for (stagedCandidate in listOf(false, true)) {
            val original = transaction().copy(
                candidateLeaseId = "candidate".takeIf { stagedCandidate },
                candidateSlot = RedundantSlot.B.takeIf { stagedCandidate },
                retry = AndroidRedundantRetryState(acquirePending = true,
                    acquireOperationId = "repair", acquireReplaceLeaseId = "lease-b"),
            )
            val backend = CoordinatorRecordBackend()
            val native = FakeNative()
            val panel = FakePanel(recoveredSession = session("lease-a", 1, 1),
                recoveryHealthProbes = mapOf("lease-a" to probe(), "lease-b" to probe()))
            val readiness = mutableListOf<Boolean>()
            val coordinator = RedundantConnectionCoordinator(store(original, backend), panel, native,
                epochNowMs = { 20_000L }, monotonicMs = { 20_000L },
                onRecoveryReadiness = { readiness += it })
            assertTrue(coordinator.recover())
            if (!stagedCandidate) backend.failOnWriteNumber = backend.writeCount + 1

            assertFalse(coordinator.onHealthObservations(listOf(
                healthSlot(0, active = true, hardFailure = true),
                healthSlot(1, health = BackendHealth.READY, handshakeFresh = true,
                    consecutiveProbeSuccesses = 3, stableSinceMs = 0),
            )))

            assertEquals("lease-a", coordinator.status()?.localActiveLeaseId)
            assertEquals("lease-b", coordinator.status()?.retry?.acquireReplaceLeaseId)
            assertEquals(original.candidateLeaseId, coordinator.status()?.candidateLeaseId)
            assertEquals(listOf("lease-a"), native.activated)
            assertEquals(listOf(false), readiness)
            assertEquals(1, native.stopCalls)
            assertEquals(0, panel.roleCalls)
        }
    }

    @Test
    fun reusedCurrentFailoverKeepsFreshHealthStartStopAndPersistenceBarriers() {
        for (barrier in listOf("warming", "failed_start", "failed_write", "stop", "disabled")) {
            val backend = CoordinatorRecordBackend()
            val recoveryStore = store(transaction(), backend)
            val native = FakeNative(startFailures = if (barrier == "failed_start") setOf("lease-b") else emptySet())
            val current = session("lease-a", 1, 1)
            val panel = FakePanel(acquiredSession = current, acquiredCandidateLeaseId = "lease-b",
                role = RedundantRoleResponse("accepted", "lease-a", current))
            val coordinator = RedundantConnectionCoordinator(recoveryStore, panel, native,
                epochNowMs = { 20_000L }, monotonicMs = { 20_000L })
            assertEquals(barrier != "failed_start",
                coordinator.acquireAndCommitStandby("repair", "lease-b"))
            when (barrier) {
                "failed_write" -> backend.failOnWriteNumber = backend.writeCount + 1
                "stop" -> assertTrue(coordinator.fenceRevoke())
                "disabled" -> assertTrue(coordinator.releaseStandby())
            }

            coordinator.onHealthObservations(listOf(
                healthSlot(0, active = true, hardFailure = true),
                healthSlot(1, health = if (barrier == "warming") BackendHealth.WARMING else BackendHealth.READY,
                    handshakeFresh = barrier != "warming",
                    consecutiveProbeSuccesses = if (barrier == "warming") 0 else 3, stableSinceMs = 0),
            ))

            assertEquals(barrier, "lease-a", coordinator.status()?.localActiveLeaseId)
            assertTrue(barrier, native.activationAttempts.isEmpty())
            assertEquals(0, panel.commitCalls)
        }
    }

    @Test
    fun currentMemberCandidateIsNotInferredCommittedFromMembershipDuringFailover() {
        val pending = transaction().copy(
            candidateLeaseId = "lease-b",
            candidateSlot = RedundantSlot.B,
            retry = AndroidRedundantRetryState(
                nextRetryAtUnix = 2_100L,
                acquirePending = true,
                acquireOperationId = "reissue-inactive",
                acquireReplaceLeaseId = "lease-b",
            ),
        )
        val native = FakeNative()
        val panel = FakePanel()
        val coordinator = RedundantConnectionCoordinator(
            store(pending),
            panel,
            native,
            epochNowMs = { 2_000_000L },
            monotonicMs = { 2_000_000L },
        )

        assertFalse(coordinator.onHealthObservations(listOf(
            healthSlot(index = 0, active = true, hardFailure = true),
            healthSlot(
                index = 1,
                health = BackendHealth.READY,
                handshakeFresh = true,
                consecutiveProbeSuccesses = 3,
                stableSinceMs = 0L,
            ),
        )))

        val retained = requireNotNull(coordinator.status())
        assertEquals("lease-a", retained.localActiveLeaseId)
        assertEquals("lease-b", retained.candidateLeaseId)
        assertTrue(retained.retry.acquirePending)
        assertEquals(0, panel.commitCalls)
        assertTrue(native.activationAttempts.isEmpty())
    }

    @Test
    fun unvalidatedNetworkCannotCommitAnOtherwiseReadyCandidate() {
        var nowMs = 1_000_000L
        val panel = FakePanel()
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(
            store(transaction(localActiveLeaseId = "lease-a").copy(slotBLeaseId = null)),
            panel,
            native,
            epochNowMs = { nowMs },
            monotonicMs = { nowMs },
        )
        assertTrue(coordinator.acquireAndCommitStandby("acquire-1"))
        assertTrue(coordinator.onUnderlyingNetworkChanged(validated = false))
        native.healthSnapshots.addLast(listOf(
            healthSlot(index = 0, health = BackendHealth.READY),
            healthSlot(
                index = 1,
                handshakeFresh = true,
                consecutiveProbeSuccesses = 3,
                stableSinceMs = nowMs - 15_000L,
            ),
        ))

        assertTrue(coordinator.tick())

        assertEquals(0, panel.commitCalls)
        assertTrue(requireNotNull(coordinator.status()).retry.acquirePending)
    }

    @Test
    fun processDeathReplaysCandidateTransportAndWaitsForFreshReadiness() {
        var nowMs = 1_000_000L
        val pending = transaction(localActiveLeaseId = "lease-b").copy(
            candidateLeaseId = "candidate",
            candidateSlot = RedundantSlot.A,
            retry = AndroidRedundantRetryState(
                acquirePending = true,
                acquireOperationId = "acquire-1",
                acquireReplaceLeaseId = "lease-a",
            ),
        )
        val store = store(pending)
        val panel = FakePanel(acquiredSession = session(
            activeLeaseId = "lease-b",
            roleGeneration = 8,
            membershipGeneration = 4,
        ))
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(
            store,
            panel,
            native,
            epochNowMs = { nowMs },
            monotonicMs = { nowMs },
        )

        assertTrue(coordinator.recover())
        assertEquals(listOf("acquire-1"), panel.acquireOperationIds)
        assertEquals(listOf("lease-a"), panel.acquireReplaceLeaseIds)
        assertTrue(native.events.indexOf("stop:lease-a") < native.events.indexOf("start:candidate"))
        assertEquals(0, panel.commitCalls)

        native.healthSnapshots.addLast(listOf(
            healthSlot(
                index = 0,
                handshakeFresh = true,
                consecutiveProbeSuccesses = 3,
                stableSinceMs = nowMs,
            ),
            healthSlot(index = 1, health = BackendHealth.READY),
        ))
        assertTrue(coordinator.tick())
        assertEquals(0, panel.commitCalls)

        nowMs += 15_000L
        native.healthSnapshots.addLast(listOf(
            healthSlot(
                index = 0,
                handshakeFresh = true,
                consecutiveProbeSuccesses = 3,
                stableSinceMs = nowMs - 15_000L,
            ),
            healthSlot(index = 1, health = BackendHealth.READY),
        ))
        assertTrue(coordinator.tick())
        assertEquals(1, panel.commitCalls)
        assertFalse(requireNotNull(coordinator.status()).retry.acquirePending)
    }

    @Test
    fun disabledStandbyFencesPersistedCandidateReplay() {
        val pending = transaction().copy(
            standbyDesired = false,
            candidateLeaseId = "candidate",
            candidateSlot = RedundantSlot.B,
            retry = AndroidRedundantRetryState(
                nextRetryAtUnix = 1,
                acquirePending = true,
                acquireOperationId = "acquire-1",
                acquireReplaceLeaseId = "lease-b",
            ),
        )
        val panel = FakePanel()
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(store(pending), panel, native)

        assertTrue(coordinator.tick())

        val fenced = requireNotNull(coordinator.status())
        assertFalse(fenced.retry.acquirePending)
        assertEquals(null, fenced.candidateLeaseId)
        assertEquals(null, fenced.candidateSlot)
        assertTrue(panel.acquireOperationIds.isEmpty())
        assertFalse(native.started.contains("candidate"))
    }

    @Test
    fun recoveryFinalizesCandidateAlreadyCommittedRemotelyWithoutAnotherAcquire() {
        val pending = transaction().copy(
            candidateLeaseId = "candidate",
            candidateSlot = RedundantSlot.B,
            retry = AndroidRedundantRetryState(
                acquirePending = true,
                acquireOperationId = "acquire-1",
                acquireReplaceLeaseId = "lease-b",
            ),
        )
        val store = store(pending)
        val panel = FakePanel(
            recoveredSession = session(
                activeLeaseId = "lease-a",
                roleGeneration = 3,
                membershipGeneration = 3,
                slotBLeaseId = "candidate",
            ),
            acquireFailures = ArrayDeque(listOf(true)),
            commitFailures = ArrayDeque(listOf(true)),
        )

        assertTrue(RedundantConnectionCoordinator(store, panel, FakeNative()).recover())
        val recovered = requireNotNull(RedundantConnectionCoordinator(store, panel, FakeNative()).status())
        assertFalse(recovered.retry.acquirePending)
        assertEquals(null, recovered.retry.acquireOperationId)
        assertEquals(null, recovered.retry.acquireReplaceLeaseId)
        assertEquals(null, recovered.candidateLeaseId)
        assertEquals(null, recovered.candidateSlot)
        assertTrue(panel.acquireOperationIds.isEmpty())
        assertEquals(0, panel.commitCalls)
    }

    @Test
    fun duplicateStopAndRecoveryCallbacksAreIdempotent() {
        val panel = FakePanel()
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(store(transaction()), panel, native) {}

        coordinator.recover()
        coordinator.recover()
        coordinator.revoke()
        coordinator.revoke()

        assertEquals(listOf("lease-a", "lease-b"), native.started)
        assertEquals(1, panel.stopCalls)
    }

    private fun store(
        transaction: AndroidRedundantTransaction,
        backend: CoordinatorRecordBackend = CoordinatorRecordBackend(),
    ): AndroidRecoveryStore {
        backend.write(AndroidRecoveryEnvelopeCodec.encode(AndroidRecoveryEnvelope(
            formatVersion = ANDROID_RECOVERY_FORMAT,
            intent = AndroidConnectionIntent.empty(1),
            leaseTransaction = null,
            redundantTransaction = transaction,
        )))
        return AndroidRecoveryStore(backend, CoordinatorBootIdentity())
    }

    private fun pendingNativeSwitch() = transaction().copy(
        retry = AndroidRedundantRetryState(
            pendingNativeSourceLeaseId = "lease-a",
            pendingNativeActiveLeaseId = "lease-b",
            pendingNativeActiveSlot = RedundantSlot.B,
            pendingNativeMembershipGeneration = 1,
            pendingNativeSwitchReason = "primary_unhealthy",
        ),
    )

    private fun emptyStore(): AndroidRecoveryStore {
        val backend = CoordinatorRecordBackend()
        backend.write(AndroidRecoveryEnvelopeCodec.encode(AndroidRecoveryEnvelope.empty(1)))
        return AndroidRecoveryStore(backend, CoordinatorBootIdentity())
    }

    private fun v2Envelope() = AndroidRecoveryEnvelope(
        formatVersion = ANDROID_RECOVERY_FORMAT,
        intent = AndroidConnectionIntent.empty(1),
        leaseTransaction = null,
        redundantTransaction = transaction(),
    )

    private fun transaction(localActiveLeaseId: String? = "lease-a") = AndroidRedundantTransaction(
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
        localActiveLeaseId = localActiveLeaseId,
        standbyDesired = true,
        roleGeneration = 1,
        membershipGeneration = 1,
        startOperationId = "start-operation",
        startRequestFingerprint = "fingerprint",
    )

    private fun session(
        activeLeaseId: String,
        roleGeneration: Long,
        membershipGeneration: Long,
        slotBLeaseId: String? = "lease-b",
        standbyDesired: Boolean = true,
    ) = BackgroundRedundantSession(
        sessionId = "22222222-2222-4222-8222-222222222222",
        state = "connected",
        activeLeaseId = activeLeaseId,
        slotALeaseId = "lease-a",
        slotBLeaseId = slotBLeaseId,
        standbyDesired = standbyDesired,
        roleGeneration = roleGeneration,
        membershipGeneration = membershipGeneration,
        reason = null,
    )

    private fun healthSlot(
        index: Int,
        active: Boolean = false,
        health: BackendHealth = BackendHealth.WARMING,
        hardFailure: Boolean = false,
        probeFailed: Boolean = false,
        independentFailureSignal: Boolean = false,
        softFailureStartedAtMs: Long? = null,
        corroboratedProbeFailures: Int = 0,
        handshakeFresh: Boolean = false,
        consecutiveProbeSuccesses: Int = 0,
        stableSinceMs: Long? = null,
    ) = SlotObservation(
        index = index,
        active = active,
        health = health,
        hardFailure = hardFailure,
        probeFailed = probeFailed,
        independentFailureSignal = independentFailureSignal,
        softFailureStartedAtMs = softFailureStartedAtMs,
        corroboratedProbeFailures = corroboratedProbeFailures,
        handshakeFresh = handshakeFresh,
        consecutiveProbeSuccesses = consecutiveProbeSuccesses,
        stableSinceMs = stableSinceMs,
    )

    private fun probe() = BackgroundRedundantHealthProbe(
        "dns_a",
        "8.8.8.8",
        "nelomai.ru",
        4_000,
    )
}

private class CoordinatorRecordBackend : EncryptedRecordBackend {
    var record: ByteArray? = null
    var failReads = false
    var failOnWriteNumber: Int? = null
    var writeCount = 0
    override fun read(): ByteArray? {
        if (failReads) throw IllegalStateException("read_failed")
        return record?.copyOf()
    }
    override fun write(plaintext: ByteArray): Boolean {
        writeCount += 1
        if (writeCount == failOnWriteNumber) return false
        record = plaintext.copyOf()
        return true
    }
}

private class CoordinatorBootIdentity : BootIdentityProvider {
    override fun bootCount(): Long = 1
}

private class FakeNative(
    private val usable: Set<String> = setOf("lease-a", "lease-b"),
    private val startFailures: Set<String> = emptySet(),
    private val stopResults: ArrayDeque<Boolean> = ArrayDeque(),
    val healthSnapshots: ArrayDeque<List<SlotObservation>> = ArrayDeque(),
    private var healthSnapshotFailures: Int = 0,
    private val startEntered: CountDownLatch? = null,
    private val releaseStart: CountDownLatch? = null,
    private val activateResults: ArrayDeque<Boolean> = ArrayDeque(),
    private val rebindResults: ArrayDeque<Boolean> = ArrayDeque(),
) : RedundantConnectionNative {
    val started = mutableListOf<String>()
    val activated = mutableListOf<String>()
    val rebound = mutableListOf<String>()
    val activationAttempts = mutableListOf<String>()
    val rebindAttempts = mutableListOf<String>()
    val events = mutableListOf<String>()
    var stopCalls = 0
    override fun start(
        leaseId: String,
        slot: RedundantSlot,
        configuration: ByteArray,
        healthProbe: BackgroundRedundantHealthProbe?,
    ): Boolean {
        startEntered?.countDown()
        releaseStart?.let { check(it.await(2, TimeUnit.SECONDS)) }
        started += leaseId
        events += "start:$leaseId"
        return leaseId !in startFailures
    }
    override fun activate(leaseId: String): Boolean =
        (activateResults.removeFirstOrNull() ?: (leaseId in usable)).also {
        activationAttempts += leaseId
        if (it) activated += leaseId
    }
    override fun stopSlot(leaseId: String): Boolean = (leaseId in usable).also {
        if (it) events += "stop:$leaseId"
    }
    override fun stop(): Boolean {
        stopCalls += 1
        return stopResults.removeFirstOrNull() ?: true
    }
    override fun isUsable(leaseId: String): Boolean = leaseId in usable
    override fun rebind(leaseId: String): Boolean =
        (rebindResults.removeFirstOrNull() ?: (leaseId in usable)).also {
        rebindAttempts += leaseId
        if (it) rebound += leaseId
    }
    override fun healthObservations(): List<SlotObservation> {
        if (healthSnapshotFailures > 0) {
            healthSnapshotFailures -= 1
            throw IllegalStateException("health_snapshot_failed")
        }
        return healthSnapshots.removeFirstOrNull() ?: emptyList()
    }
}

private class FakePanel(
    private val role: RedundantRoleResponse? = null,
    private val configurations: Map<String, ByteArray>? = null,
    private val recoveredSession: BackgroundRedundantSession? = null,
    private val acquiredSession: BackgroundRedundantSession? = null,
    private val acquiredCandidateLeaseId: String = "candidate",
    private val acquiredCandidateLeaseIds: ArrayDeque<String> = ArrayDeque(),
    private val committedSession: BackgroundRedundantSession? = null,
    private val stopResults: ArrayDeque<Boolean> = ArrayDeque(),
    private val roleFailures: ArrayDeque<Boolean> = ArrayDeque(),
    private val roleFailureCodes: ArrayDeque<String> = ArrayDeque(),
    private val recoverFailures: ArrayDeque<Boolean> = ArrayDeque(),
    private val recoverErrors: ArrayDeque<BackgroundConnectionException> = ArrayDeque(),
    private val acquireFailures: ArrayDeque<Boolean> = ArrayDeque(),
    private val commitFailures: ArrayDeque<Boolean> = ArrayDeque(),
    private val releaseFailures: ArrayDeque<Boolean> = ArrayDeque(),
    private val releaseFailureCodes: ArrayDeque<String> = ArrayDeque(),
    private val recoveryHealthProbes: Map<String, BackgroundRedundantHealthProbe> = emptyMap(),
    private val recoverEntered: CountDownLatch? = null,
    private val releaseRecovery: CountDownLatch? = null,
) : RedundantConnectionPanel {
    var stopCalls = 0
    var roleCalls = 0
    val roleReasons = mutableListOf<String>()
    var recoverCalls = 0
    val recoveredOperations = mutableListOf<String>()
    var commitCalls = 0
    val acquireOperationIds = mutableListOf<String>()
    val acquireReplaceLeaseIds = mutableListOf<String?>()
    val commitCandidateLeaseIds = mutableListOf<String>()
    val commitTransactions = mutableListOf<AndroidRedundantTransaction>()
    val candidateConfigurations = mutableListOf<ByteArray>()
    val releasedLeaseIds = mutableListOf<String>()
    val releaseAttempts = mutableListOf<String?>()
    override fun recover(transaction: AndroidRedundantTransaction): RedundantRecoveryResponse {
        recoverCalls += 1
        recoveredOperations += transaction.startOperationId
        recoverErrors.removeFirstOrNull()?.let { throw it }
        if (recoverFailures.removeFirstOrNull() == true) {
            throw BackgroundConnectionException("offline")
        }
        recoverEntered?.countDown()
        releaseRecovery?.let { check(it.await(2, TimeUnit.SECONDS)) }
        return RedundantRecoveryResponse(
            session = recoveredSession ?: BackgroundRedundantSession(
                sessionId = transaction.sessionId,
                state = "connected",
                activeLeaseId = "lease-b",
                slotALeaseId = "lease-a",
                slotBLeaseId = "lease-b",
                standbyDesired = true,
                roleGeneration = 2,
                membershipGeneration = 2,
                reason = null,
            ),
            configurations = configurations ?: mapOf(
                "lease-a" to "PrivateKey = only-in-memory-a".toByteArray(),
                "lease-b" to "PrivateKey = only-in-memory-b".toByteArray(),
            ),
            healthProbes = recoveryHealthProbes,
        )
    }
    override fun reportRole(transaction: AndroidRedundantTransaction, reason: String): RedundantRoleResponse {
        roleCalls += 1
        roleReasons += reason
        roleFailureCodes.removeFirstOrNull()?.let { throw BackgroundConnectionException(it) }
        if (roleFailures.removeFirstOrNull() == true) throw BackgroundConnectionException("offline")
        return if (role?.action == "rebase" && roleCalls > 1) {
            RedundantRoleResponse("accepted", transaction.localActiveLeaseId!!, role.session)
        } else {
            role ?: RedundantRoleResponse("accepted", transaction.localActiveLeaseId!!, session())
        }
    }
    override fun releaseStandby(
        transaction: AndroidRedundantTransaction,
        inactiveLeaseId: String?,
    ): BackgroundRedundantSession {
        releaseAttempts += inactiveLeaseId
        releaseFailureCodes.removeFirstOrNull()?.let { throw BackgroundConnectionException(it) }
        if (releaseFailures.removeFirstOrNull() == true) {
            throw BackgroundConnectionException("offline")
        }
        return BackgroundRedundantSession(
        sessionId = transaction.sessionId,
        state = "connected",
        activeLeaseId = transaction.localActiveLeaseId,
        slotALeaseId = transaction.slotALeaseId.takeIf { it != inactiveLeaseId },
        slotBLeaseId = transaction.slotBLeaseId.takeIf { it != inactiveLeaseId },
        standbyDesired = false,
        roleGeneration = transaction.roleGeneration,
        membershipGeneration = transaction.membershipGeneration + 1,
        reason = null,
        ).also { inactiveLeaseId?.let(releasedLeaseIds::add) }
    }
    override fun acquireStandby(
        transaction: AndroidRedundantTransaction,
        operationId: String,
        replaceLeaseId: String?,
    ): BackgroundRedundantCandidate {
        acquireOperationIds += operationId
        acquireReplaceLeaseIds += replaceLeaseId
        if (acquireFailures.removeFirstOrNull() == true) throw BackgroundConnectionException("offline")
        val configuration = "candidate-config".toByteArray().also(candidateConfigurations::add)
        return BackgroundRedundantCandidate(
            acquiredSession ?: session(
                activeLeaseId = transaction.localActiveLeaseId!!,
                roleGeneration = transaction.roleGeneration,
                membershipGeneration = transaction.membershipGeneration,
                slotALeaseId = transaction.slotALeaseId,
                slotBLeaseId = transaction.slotBLeaseId,
            ),
            acquiredCandidateLeaseIds.removeFirstOrNull() ?: acquiredCandidateLeaseId,
            if (replaceLeaseId == transaction.slotALeaseId) RedundantSlot.A else RedundantSlot.B,
            QuickConnectionArgs(),
            configuration,
            BackgroundRedundantHealthProbe("dns_a", "8.8.8.8", "nelomai.ru", 4_000),
        )
    }
    override fun commitCandidate(
        transaction: AndroidRedundantTransaction,
        candidateLeaseId: String,
    ): BackgroundRedundantSession {
        commitCalls += 1
        commitTransactions += transaction
        commitCandidateLeaseIds += candidateLeaseId
        if (commitFailures.removeFirstOrNull() == true) throw BackgroundConnectionException("offline")
        return committedSession ?: session(
            activeLeaseId = transaction.localActiveLeaseId!!,
            roleGeneration = transaction.roleGeneration,
            membershipGeneration = transaction.membershipGeneration + 1,
            slotALeaseId = if (transaction.retry.acquireReplaceLeaseId == transaction.slotALeaseId) {
                candidateLeaseId
            } else {
                transaction.slotALeaseId
            },
            slotBLeaseId = if (transaction.retry.acquireReplaceLeaseId == transaction.slotBLeaseId ||
                transaction.slotBLeaseId == null
            ) {
                candidateLeaseId
            } else {
                transaction.slotBLeaseId
            },
        )
    }
    override fun stop(transaction: AndroidRedundantTransaction): Boolean {
        stopCalls += 1
        return stopResults.removeFirstOrNull() ?: true
    }
    private fun session(
        activeLeaseId: String = "lease-a",
        roleGeneration: Long = 2,
        membershipGeneration: Long = 2,
        slotALeaseId: String? = "lease-a",
        slotBLeaseId: String? = "lease-b",
    ) = BackgroundRedundantSession(
        sessionId = "22222222-2222-4222-8222-222222222222",
        state = "connected",
        activeLeaseId = activeLeaseId,
        slotALeaseId = slotALeaseId,
        slotBLeaseId = slotBLeaseId,
        standbyDesired = true,
        roleGeneration = roleGeneration,
        membershipGeneration = membershipGeneration,
        reason = null,
    )
}

private class FakeVpnOwner(private val recoverResult: Boolean) : RedundantVpnProcessOwner {
    var recoverCalls = 0
    var resumeCalls = 0
    override fun recover(): Boolean {
        recoverCalls += 1
        return recoverResult
    }
    override fun resume(): Boolean {
        resumeCalls += 1
        return recoverResult
    }
    override fun revoke(): Boolean = true
}
