package ru.nelomai.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class NelomaiVpnServiceTest {
    @Test
    fun backgroundToggleLeavesTransitionStateToTheAcceptedRuntimeOperation() {
        val events = mutableListOf<String>()

        dispatchBackgroundToggle(
            desiredActive = false,
            start = { events += "start" },
            stop = { events += "stop" },
        )

        assertEquals(listOf("start"), events)
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
}
