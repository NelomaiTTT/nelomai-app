package ru.nelomai.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RedundantHealthMonitorTest {
    @Test
    fun initiallyUnvalidatedNetworkCannotReportPrimaryReady() {
        val monitor = RedundantHealthMonitor(
            rebindStabilizationMs = 0,
            initialNetworkValidated = false,
        )
        val ready = slot(
            index = 0,
            active = true,
            health = BackendHealth.READY,
            handshakeFresh = true,
            successfulProbes = 3,
        )

        assertFalse(monitor.ready(nowMs = 1_000, observation = ready))
        monitor.onUnderlyingNetworkChanged(nowMs = 1_000, validated = true)
        assertTrue(monitor.ready(nowMs = 1_000, observation = ready))
    }

    @Test
    fun hardFailureSwitchesReadyStandbyImmediately() {
        val monitor = RedundantHealthMonitor()

        val decision = monitor.evaluateHealth(
            nowMs = 1_000,
            slots = listOf(
                slot(index = 0, active = true, hardFailure = true),
                slot(index = 1, health = BackendHealth.READY),
            ),
        )

        assertEquals(1, decision.switchTo)
        assertFalse(decision.sessionStalled)
    }

    @Test
    fun softFailureRequiresProbeFailureAndIndependentSignalForFiveSeconds() {
        val monitor = RedundantHealthMonitor(softFailureConfirmationMs = 5_000)
        val readyStandby = slot(index = 1, health = BackendHealth.READY)

        assertNull(monitor.evaluateHealth(
            nowMs = 1_000,
            slots = listOf(
                slot(index = 0, active = true, probeFailed = true),
                readyStandby,
            ),
        ).switchTo)
        assertNull(monitor.evaluateHealth(
            nowMs = 2_000,
            slots = listOf(
                slot(index = 0, active = true, independentFailureSignal = true),
                readyStandby,
            ),
        ).switchTo)
        assertNull(monitor.evaluateHealth(
            nowMs = 3_000,
            slots = listOf(
                slot(
                    index = 0,
                    active = true,
                    probeFailed = true,
                    independentFailureSignal = true,
                ),
                readyStandby,
            ),
        ).switchTo)
        assertEquals(1, monitor.evaluateHealth(
            nowMs = 8_000,
            slots = listOf(
                slot(
                    index = 0,
                    active = true,
                    probeFailed = true,
                    independentFailureSignal = true,
                ),
                readyStandby,
            ),
        ).switchTo)
    }

    @Test
    fun networkHandoffSuppressesFalseFailoverDuringRebindStabilization() {
        val monitor = RedundantHealthMonitor(
            softFailureConfirmationMs = 0,
            rebindStabilizationMs = 4_000,
        )
        monitor.onUnderlyingNetworkChanged(nowMs = 10_000, validated = true)
        val observations = listOf(
            slot(
                index = 0,
                active = true,
                probeFailed = true,
                independentFailureSignal = true,
            ),
            slot(index = 1, health = BackendHealth.READY),
        )

        assertNull(monitor.evaluateHealth(nowMs = 13_999, slots = observations).switchTo)
        assertEquals(1, monitor.evaluateHealth(nowMs = 14_000, slots = observations).switchTo)
    }

    @Test
    fun noValidatedNetworkSuspendsHealthInsteadOfSwitchingOrStalling() {
        val monitor = RedundantHealthMonitor(softFailureConfirmationMs = 0)
        monitor.onUnderlyingNetworkChanged(nowMs = 1_000, validated = false)

        val decision = monitor.evaluateHealth(
            nowMs = 20_000,
            slots = listOf(
                slot(index = 0, active = true, hardFailure = true),
                slot(index = 1, health = BackendHealth.READY),
            ),
        )

        assertNull(decision.switchTo)
        assertFalse(decision.sessionStalled)
    }

    @Test
    fun idleStaleHandshakeWithoutProbeFailureIsNotAHealthFailure() {
        val monitor = RedundantHealthMonitor(softFailureConfirmationMs = 0)

        val decision = monitor.evaluateHealth(
            nowMs = 60_000,
            slots = listOf(
                slot(index = 0, active = true, health = BackendHealth.WARMING),
                slot(index = 1, health = BackendHealth.READY),
            ),
        )

        assertNull(decision.switchTo)
        assertFalse(decision.sessionStalled)
    }

    @Test
    fun warmingStandbyIsOnlyUsableAfterHandshakeAndOneProbe() {
        val monitor = RedundantHealthMonitor()
        val failedActive = slot(index = 0, active = true, hardFailure = true)

        assertTrue(monitor.evaluateHealth(
            nowMs = 1_000,
            slots = listOf(failedActive, slot(index = 1)),
        ).sessionStalled)
        assertNull(monitor.evaluateHealth(
            nowMs = 2_000,
            slots = listOf(
                failedActive,
                slot(index = 1, handshakeFresh = true, successfulProbes = 1),
            ),
        ).switchTo)

        val freshMonitor = RedundantHealthMonitor()
        assertEquals(1, freshMonitor.evaluateHealth(
            nowMs = 2_000,
            slots = listOf(
                failedActive,
                slot(index = 1, handshakeFresh = true, successfulProbes = 1),
            ),
        ).switchTo)
    }

    @Test
    fun totalLossEmitsSessionStalledOnlyOnce() {
        val monitor = RedundantHealthMonitor()
        val observations = listOf(
            slot(index = 0, active = true, hardFailure = true),
            slot(index = 1, health = BackendHealth.UNHEALTHY),
        )

        assertTrue(monitor.evaluateHealth(nowMs = 1_000, slots = observations).sessionStalled)
        assertFalse(monitor.evaluateHealth(nowMs = 2_000, slots = observations).sessionStalled)
    }

    private fun slot(
        index: Int,
        active: Boolean = false,
        health: BackendHealth = BackendHealth.WARMING,
        hardFailure: Boolean = false,
        probeFailed: Boolean = false,
        independentFailureSignal: Boolean = false,
        handshakeFresh: Boolean = false,
        successfulProbes: Int = 0,
    ) = SlotObservation(
        index = index,
        active = active,
        health = health,
        hardFailure = hardFailure,
        probeFailed = probeFailed,
        independentFailureSignal = independentFailureSignal,
        handshakeFresh = handshakeFresh,
        consecutiveProbeSuccesses = successfulProbes,
    )
}
