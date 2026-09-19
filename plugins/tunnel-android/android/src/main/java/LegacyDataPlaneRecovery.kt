package ru.nelomai.tunnel

internal fun routeDataPlaneStall(
    recovery: RecoveryStoreResult<AndroidRecoveryEnvelope>,
    legacyRecovery: (Long) -> Boolean,
    intentRecovery: () -> Boolean,
): Boolean {
    val envelope = (recovery as? RecoveryStoreResult.Success)?.value ?: return false
    if (envelope.redundantTransaction != null) return false
    if (envelope.intent.template != null || envelope.leaseTransaction != null) {
        return intentRecovery()
    }
    if (!envelope.intent.desiredActive || envelope.intent.retry != AndroidRetryState()) return false
    return legacyRecovery(envelope.intent.generation)
}

/** One local retry for an already-owned legacy session; never acquires another lease. */
internal class LegacyDataPlaneRecovery {
    private var attempted = false

    fun restart(isCurrent: () -> Boolean, stop: () -> Unit, start: () -> Unit): Boolean {
        if (attempted || !isCurrent()) return false
        attempted = true
        var stopped = false
        return try {
            stop()
            stopped = true
            if (!isCurrent()) return false
            start()
            if (isCurrent()) true else {
                stop()
                false
            }
        } catch (_: Throwable) {
            // Close a partially started transport, but never start after a failed stop.
            if (stopped) runCatching(stop)
            false
        }
    }
}
