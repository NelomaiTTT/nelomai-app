package ru.nelomai.tunnel

internal enum class RedundantTotalLossCommandDisposition {
    IGNORE,
    DEFER_UNTIL_BARRIER_RELEASE,
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
        stopPending || logoutState != BackgroundLogoutReadState.NONE
    ) {
        return RedundantTotalLossCommandDisposition.IGNORE
    }
    if (tombstoneUnreadable || stopLookupPending) {
        return RedundantTotalLossCommandDisposition.DEFER_UNTIL_BARRIER_RELEASE
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

/**
 * Retains a total-loss command that arrived behind a transient stop/tombstone barrier.
 * Only the latest command is relevant; every replay removes it before invoking service code.
 */
internal class RedundantTotalLossCommandLifecycle<T : Any> {
    private val gate = Any()
    private var deferred: T? = null

    fun handle(
        command: T,
        disposition: RedundantTotalLossCommandDisposition,
        barrierPendingAfterDefer: () -> Boolean,
        replayDeferred: () -> Unit,
        prepareRestartAndStop: (T) -> Unit,
        failClosedStop: (T) -> Unit,
    ) {
        when (disposition) {
            RedundantTotalLossCommandDisposition.IGNORE -> Unit
            RedundantTotalLossCommandDisposition.DEFER_UNTIL_BARRIER_RELEASE -> {
                synchronized(gate) { deferred = command }
                if (!barrierPendingAfterDefer()) replayDeferred()
            }
            RedundantTotalLossCommandDisposition.PREPARE_RESTART_AND_STOP -> {
                prepareRestartAndStop(command)
            }
            RedundantTotalLossCommandDisposition.FAIL_CLOSED_STOP -> failClosedStop(command)
        }
    }

    fun replay(reprocess: (T) -> Unit): Boolean {
        val command = synchronized(gate) {
            val current = deferred
            deferred = null
            current
        } ?: return false
        reprocess(command)
        return true
    }
}

internal fun <T : Any> resumeDeferredRedundantTotalLossAndDurableWork(
    lifecycle: RedundantTotalLossCommandLifecycle<T>,
    reprocess: (T) -> Unit,
    resumeDurableWork: () -> Unit,
) {
    lifecycle.replay(reprocess)
    resumeDurableWork()
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

internal fun shouldRouteConnectionIntentResumeThroughRedundantGate(
    barrierPending: Boolean,
    recovery: RecoveryStoreResult<AndroidRecoveryEnvelope>,
): Boolean = barrierPending ||
    recovery is RecoveryStoreResult.Failure ||
    isExactPromotedRedundantTotalLossRestart(
        (recovery as RecoveryStoreResult.Success).value,
    )

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
