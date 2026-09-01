package ru.nelomai.tunnel

internal enum class BackendHealth {
    WARMING,
    READY,
    SUSPECT,
    UNHEALTHY,
    RECOVERING,
}

internal data class SlotObservation(
    val index: Int,
    val active: Boolean,
    val health: BackendHealth,
    val hardFailure: Boolean = false,
    val probeFailed: Boolean = false,
    val independentFailureSignal: Boolean = false,
    val handshakeFresh: Boolean = false,
    val consecutiveProbeSuccesses: Int = 0,
    val stableSinceMs: Long? = null,
)

internal data class FailoverDecision(
    val switchTo: Int?,
    val sessionStalled: Boolean,
)

/**
 * Deterministic, session-scoped health state machine. Inputs are bounded native observations;
 * wall-clock time and networking side effects stay outside this class so failover is testable.
 */
internal class RedundantHealthMonitor(
    private val softFailureConfirmationMs: Long = DEFAULT_SOFT_FAILURE_CONFIRMATION_MS,
    private val rebindStabilizationMs: Long = DEFAULT_REBIND_STABILIZATION_MS,
) {
    private val softFailureSinceMs = mutableMapOf<Int, Long>()
    private var networkValidated = true
    private var suppressFailoverUntilMs = Long.MIN_VALUE
    private var sessionStalledEmitted = false

    init {
        require(softFailureConfirmationMs in 0..MAX_SOFT_FAILURE_CONFIRMATION_MS)
        require(rebindStabilizationMs >= 0)
    }

    fun onUnderlyingNetworkChanged(nowMs: Long, validated: Boolean) {
        networkValidated = validated
        softFailureSinceMs.clear()
        suppressFailoverUntilMs = if (validated) {
            saturatingAdd(nowMs, rebindStabilizationMs)
        } else {
            Long.MAX_VALUE
        }
    }

    fun evaluateHealth(nowMs: Long, slots: List<SlotObservation>): FailoverDecision {
        if (sessionStalledEmitted || !networkValidated || nowMs < suppressFailoverUntilMs) {
            return NONE
        }
        if (slots.size !in 1..MAX_SLOT_COUNT || slots.any { it.index !in 0..1 } ||
            slots.distinctBy(SlotObservation::index).size != slots.size
        ) {
            return NONE
        }
        val bounded = slots
        val active = bounded.singleOrNull(SlotObservation::active) ?: return NONE
        val activeHealth = classify(nowMs, active)
        val failed = active.hardFailure || activeHealth == BackendHealth.UNHEALTHY
        val softFailureConfirmed = softFailureConfirmed(nowMs, active)
        if (!failed && !softFailureConfirmed) return NONE

        val candidate = bounded
            .asSequence()
            .filterNot(SlotObservation::active)
            .filter { usableCandidate(nowMs, it) }
            .sortedWith(compareBy<SlotObservation> { classify(nowMs, it) != BackendHealth.READY }
                .thenBy(SlotObservation::index))
            .firstOrNull()
        if (candidate != null) {
            softFailureSinceMs.remove(active.index)
            return FailoverDecision(switchTo = candidate.index, sessionStalled = false)
        }
        sessionStalledEmitted = true
        return FailoverDecision(switchTo = null, sessionStalled = true)
    }

    fun health(nowMs: Long, observation: SlotObservation): BackendHealth =
        classify(nowMs, observation)

    fun ready(nowMs: Long, observation: SlotObservation): Boolean =
        networkValidated && nowMs >= suppressFailoverUntilMs &&
            classify(nowMs, observation) == BackendHealth.READY

    private fun softFailureConfirmed(nowMs: Long, active: SlotObservation): Boolean {
        if (!active.probeFailed || !active.independentFailureSignal) {
            softFailureSinceMs.remove(active.index)
            return false
        }
        val startedAt = softFailureSinceMs.getOrPut(active.index) { nowMs }
        return nowMs >= startedAt && nowMs - startedAt >= softFailureConfirmationMs
    }

    private fun classify(nowMs: Long, slot: SlotObservation): BackendHealth {
        if (slot.hardFailure) return BackendHealth.UNHEALTHY
        if (slot.health == BackendHealth.UNHEALTHY) return BackendHealth.UNHEALTHY
        if (slot.probeFailed && slot.independentFailureSignal) return BackendHealth.SUSPECT
        val stableSince = slot.stableSinceMs
        if (slot.handshakeFresh && slot.consecutiveProbeSuccesses >= READY_PROBE_SUCCESSES &&
            stableSince != null && nowMs >= stableSince && nowMs - stableSince >= READY_STABILITY_MS
        ) {
            return BackendHealth.READY
        }
        return slot.health
    }

    private fun usableCandidate(nowMs: Long, slot: SlotObservation): Boolean =
        when (classify(nowMs, slot)) {
            BackendHealth.READY -> true
            BackendHealth.WARMING, BackendHealth.RECOVERING ->
                slot.handshakeFresh && slot.consecutiveProbeSuccesses >= 1
            BackendHealth.SUSPECT, BackendHealth.UNHEALTHY -> false
        }

    private fun saturatingAdd(value: Long, increment: Long): Long =
        if (increment > Long.MAX_VALUE - value) Long.MAX_VALUE else value + increment

    private companion object {
        const val MAX_SLOT_COUNT = 2
        const val MAX_SOFT_FAILURE_CONFIRMATION_MS = 8_000L
        const val DEFAULT_SOFT_FAILURE_CONFIRMATION_MS = 5_000L
        const val DEFAULT_REBIND_STABILIZATION_MS = 4_000L
        const val READY_STABILITY_MS = 15_000L
        const val READY_PROBE_SUCCESSES = 3
        val NONE = FailoverDecision(switchTo = null, sessionStalled = false)
    }
}
