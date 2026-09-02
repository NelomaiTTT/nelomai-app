package ru.nelomai.tunnel

internal enum class RedundantTotalLossCommandDisposition {
    IGNORE,
    PREPARE_RESTART_AND_STOP,
    FAIL_CLOSED_STOP,
}

internal fun redundantTotalLossCommandDisposition(
    ownerServiceGeneration: Long,
    currentServiceGeneration: Long,
    serviceDestroyed: Boolean,
    startOperationId: String,
    installedStartOperationId: String?,
    installedOwnerMatches: Boolean,
    stopPending: Boolean,
    tombstoneUnreadable: Boolean,
    stopLookupPending: Boolean,
    logoutState: BackgroundLogoutReadState,
    recovery: RecoveryStoreResult<AndroidRecoveryEnvelope>,
): RedundantTotalLossCommandDisposition {
    if (serviceDestroyed || ownerServiceGeneration != currentServiceGeneration ||
        installedStartOperationId != startOperationId || !installedOwnerMatches ||
        stopPending || tombstoneUnreadable || stopLookupPending ||
        logoutState != BackgroundLogoutReadState.NONE
    ) {
        return RedundantTotalLossCommandDisposition.IGNORE
    }
    val envelope = when (recovery) {
        is RecoveryStoreResult.Failure -> {
            return RedundantTotalLossCommandDisposition.FAIL_CLOSED_STOP
        }
        is RecoveryStoreResult.Success -> recovery.value
    }
    val transaction = envelope.redundantTransaction
    return if (transaction?.startOperationId == startOperationId &&
        transaction.desiredActive && transaction.retry.stopState == RedundantStopState.NONE
    ) {
        RedundantTotalLossCommandDisposition.PREPARE_RESTART_AND_STOP
    } else {
        RedundantTotalLossCommandDisposition.IGNORE
    }
}

internal fun isExactPromotedRedundantTotalLossRestart(
    envelope: AndroidRecoveryEnvelope,
): Boolean {
    val lease = envelope.leaseTransaction ?: return false
    val sourceStartOperationId =
        envelope.intent.retry.redundantTotalLossSourceStartOperationId ?: return false
    return envelope.redundantTransaction == null &&
        envelope.intent.desiredActive &&
        envelope.intent.retry.pendingAction == "redundant_total_loss_restart" &&
        lease.phase == LeasePhase.START_PENDING &&
        lease.leaseId == null &&
        lease.generation == envelope.intent.generation &&
        lease.replay.startOperationId != sourceStartOperationId
}

/**
 * Resumes only durable work that exists after the redundant stop/tombstone barrier.
 * The queued generation check keeps a completion from an older service instance inert.
 */
internal class RedundantTotalLossLifecycle(
    private val currentServiceGeneration: () -> Long,
    private val barrierPending: () -> Boolean,
    private val logoutState: () -> BackgroundLogoutReadState,
    private val recovery: () -> RecoveryStoreResult<AndroidRecoveryEnvelope>,
    private val post: (() -> Unit) -> Unit,
    private val retryCleanup: () -> Unit,
    private val publishRestartStarting: () -> Unit,
    private val resume: () -> Unit,
    private val scheduleLogout: () -> Unit,
    private val stopIfIdle: () -> Unit,
) {
    fun onCleanupAcknowledged(ownerServiceGeneration: Long) {
        post {
            if (ownerServiceGeneration != currentServiceGeneration()) return@post
            if (barrierPending()) {
                retryCleanup()
                return@post
            }
            when (logoutState()) {
                BackgroundLogoutReadState.PENDING,
                BackgroundLogoutReadState.UNREADABLE,
                -> {
                    scheduleLogout()
                    return@post
                }
                BackgroundLogoutReadState.NONE -> Unit
            }
            val envelope = when (val current = recovery()) {
                is RecoveryStoreResult.Failure -> {
                    retryCleanup()
                    return@post
                }
                is RecoveryStoreResult.Success -> current.value
            }
            if (envelope.redundantTransaction != null) {
                retryCleanup()
                return@post
            }
            if (envelope.intent.desiredActive &&
                envelope.leaseTransaction?.phase == LeasePhase.START_PENDING &&
                envelope.leaseTransaction.leaseId == null
            ) {
                if (isExactPromotedRedundantTotalLossRestart(envelope)) {
                    publishRestartStarting()
                }
                resume()
            } else if (envelope.intent.desiredActive && envelope.leaseTransaction != null) {
                retryCleanup()
            } else {
                stopIfIdle()
            }
        }
    }
}
