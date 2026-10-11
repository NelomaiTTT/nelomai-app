package ru.nelomai.tunnel

internal data class FailedLocalRestartAuthority(
    val leaseId: String,
    val envelope: AndroidRecoveryEnvelope,
    val admissionTicket: Long,
)

internal fun dispatchLegacyClientStart(admit: () -> Boolean, start: () -> Unit): Boolean {
    if (!admit()) return false
    start()
    return true
}

/** A local replacement never grants a new intent or another lease. */
internal fun localRestartAuthority(
    recovery: RecoveryStoreResult<AndroidRecoveryEnvelope>,
    leaseId: String?,
    runtimeLeaseId: String?,
    nativeOwnerPending: Boolean,
    failedRestart: FailedLocalRestartAuthority? = null,
    admissionTicket: Long = 0,
): AndroidRecoveryEnvelope? {
    val envelope = (recovery as? RecoveryStoreResult.Success)?.value ?: return null
    if (nativeOwnerPending || leaseId.isNullOrBlank() || !envelope.intent.desiredActive ||
        envelope.redundantTransaction != null || envelope.intent.retry != AndroidRetryState()
    ) return null
    val tx = envelope.leaseTransaction
    if (tx != null) {
        if (tx.replay.contractVersion != 1 || tx.phase != LeasePhase.ACTIVE_CHECKPOINT ||
            tx.generation != envelope.intent.generation || tx.bootCount != envelope.intent.bootCount ||
            tx.leaseId != leaseId || tx.localStopPending || tx.stopOperationId != null
        ) return null
    } else if (runtimeLeaseId != leaseId &&
        !(runtimeLeaseId == null && failedRestart?.leaseId == leaseId &&
            failedRestart.envelope == envelope && failedRestart.admissionTicket == admissionTicket)
    ) return null
    if (runtimeLeaseId != null && runtimeLeaseId != leaseId) return null
    return envelope
}
