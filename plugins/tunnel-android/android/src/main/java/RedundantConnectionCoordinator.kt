package ru.nelomai.tunnel

import java.util.UUID

/** Narrow Task 8/9 seam: native owns the one real TUN and never exposes a vendor backend. */
internal interface RedundantConnectionNative {
    fun start(leaseId: String, configuration: ByteArray): Boolean
    fun activate(leaseId: String): Boolean
    fun stopSlot(leaseId: String): Boolean
    fun stop(): Boolean
    fun isUsable(leaseId: String): Boolean
}

/** Background transport seam. Configuration bytes only cross this boundary in process memory. */
internal interface RedundantConnectionPanel {
    fun recover(transaction: AndroidRedundantTransaction): RedundantRecoveryResponse
    fun reportRole(transaction: AndroidRedundantTransaction, reason: String): RedundantRoleResponse
    fun releaseStandby(
        transaction: AndroidRedundantTransaction,
        inactiveLeaseId: String,
    ): BackgroundRedundantSession = throw UnsupportedOperationException()
    fun acquireStandby(
        transaction: AndroidRedundantTransaction,
        operationId: String,
        replaceLeaseId: String,
    ): BackgroundRedundantCandidate = throw UnsupportedOperationException()
    fun commitCandidate(
        transaction: AndroidRedundantTransaction,
        candidateLeaseId: String,
    ): BackgroundRedundantSession = throw UnsupportedOperationException()
    fun stop(transaction: AndroidRedundantTransaction): Boolean
}

internal data class RedundantRecoveryResponse(
    val session: BackgroundRedundantSession,
    val configurations: Map<String, ByteArray>,
)

/** A v2 envelope is reserved for this coordinator and must never create a recovery-v1 backend. */
internal fun shouldEnterLegacyVpnRecovery(
    recovery: RecoveryStoreResult<AndroidRecoveryEnvelope>,
): Boolean = when (recovery) {
    is RecoveryStoreResult.Success -> recovery.value.redundantTransaction == null
    is RecoveryStoreResult.Failure -> false
}

/** Deferred until Task 8/9 provide native and authenticated-panel adapters. */
internal interface RedundantVpnProcessOwner {
    fun recover(): Boolean
    fun resume(): Boolean
    fun revoke(): Boolean
}

/** Never fall through to a legacy backend when a v2 envelope is present or unreadable. */
internal fun routeVpnProcessRecovery(
    recovery: RecoveryStoreResult<AndroidRecoveryEnvelope>,
    owner: RedundantVpnProcessOwner?,
    legacyRecovery: () -> Unit,
): Boolean = when (recovery) {
    is RecoveryStoreResult.Failure -> false
    is RecoveryStoreResult.Success -> if (recovery.value.redundantTransaction != null) {
        owner?.recover() ?: false
    } else {
        legacyRecovery()
        true
    }
}

internal fun routeVpnProcessRevoke(
    recovery: RecoveryStoreResult<AndroidRecoveryEnvelope>,
    owner: RedundantVpnProcessOwner?,
    legacyRevoke: () -> Unit,
): Boolean = when (recovery) {
    is RecoveryStoreResult.Failure -> false
    is RecoveryStoreResult.Success -> if (recovery.value.redundantTransaction != null) {
        owner?.revoke() ?: false
    } else {
        legacyRevoke()
        true
    }
}

/** Used by the actual null-intent sticky restart before any legacy or quick restore path. */
internal fun routeVpnStickyRestart(
    recovery: RecoveryStoreResult<AndroidRecoveryEnvelope>,
    owner: RedundantVpnProcessOwner?,
    legacyRestart: () -> Unit,
): Boolean = when (recovery) {
    is RecoveryStoreResult.Failure -> false
    is RecoveryStoreResult.Success -> if (recovery.value.redundantTransaction != null) {
        owner?.resume() ?: false
    } else {
        legacyRestart()
        true
    }
}

/**
 * Sole recovery-v2 owner in the VPN process. It deliberately has no legacy runtime dependency:
 * a single member failure is contained here, and only a total loss may surface as session stalled.
 */
internal class RedundantConnectionCoordinator(
    private val store: AndroidRecoveryStore,
    private val panel: RedundantConnectionPanel,
    private val native: RedundantConnectionNative,
    private val operationId: () -> String = { UUID.randomUUID().toString() },
    private val onAllSlotsStalled: () -> Unit = {},
) : RedundantVpnProcessOwner {
    private val gate = Any()
    private var recoveryStarted = false

    fun status(): AndroidRedundantTransaction? =
        (store.read() as? RecoveryStoreResult.Success)?.value?.redundantTransaction

    fun start(
        transaction: AndroidRedundantTransaction,
        configurations: Map<String, ByteArray>,
    ): Boolean = synchronized(gate) {
        val active = transaction.localActiveLeaseId ?: return@synchronized false
        val activeConfiguration = configurations[active] ?: return@synchronized false
        if (store.beginRedundant(transaction) !is RecoveryStoreResult.Success) return@synchronized false
        if (!native.start(active, activeConfiguration) || !native.activate(active)) return@synchronized false
        for (leaseId in listOfNotNull(
            transaction.slotALeaseId,
            transaction.slotBLeaseId,
        ).filter { it != active }.distinct()) {
            val configuration = configurations[leaseId] ?: continue
            // A standby is never allowed to turn a usable active member into a failed start.
            native.start(leaseId, configuration)
        }
        recoveryStarted = true
        true
    }

    /** Replays the v2 session before callers attempt any recovery-v1 flow. */
    override fun recover(): Boolean = synchronized(gate) {
        val transaction = status() ?: return@synchronized false
        if (!transaction.desiredActive || transaction.retry.stopState != RedundantStopState.NONE) {
            return@synchronized false
        }
        if (recoveryStarted) return@synchronized true
        val response = panel.recover(transaction)
        val refreshed = transaction.withCanonical(response.session)
        val active = transaction.localActiveLeaseId.takeIf(response.session::containsCurrentLease)
            ?: response.session.activeLeaseId
            ?: return@synchronized false
        val activeConfiguration = response.configurations[active] ?: return@synchronized false
        if (!native.start(active, activeConfiguration) || !native.activate(active)) return@synchronized false
        val standby = listOfNotNull(
            response.session.slotALeaseId,
            response.session.slotBLeaseId,
        ).filter { it != active }.distinct()
        for (leaseId in standby) {
            val configuration = response.configurations[leaseId] ?: continue
            native.start(leaseId, configuration)
        }
        // The local active identity wins over a stale canonical role until its observation is sent.
        val persisted = persist(refreshed.copy(localActiveLeaseId = active))
        if (persisted) recoveryStarted = true
        persisted && drainPendingWorkLocked()
    }

    override fun resume(): Boolean = synchronized(gate) {
        val transaction = status() ?: return@synchronized false
        if (!transaction.desiredActive || transaction.retry.stopState != RedundantStopState.NONE) {
            return@synchronized revoke()
        }
        val restored = if (recoveryStarted) true else recover()
        restored && drainPendingWorkLocked()
    }

    private fun drainPendingWorkLocked(): Boolean {
        val transaction = status() ?: return false
        if (transaction.retry.roleObservationPending && !flushRoleObservationLocked()) return false
        val pendingAcquire = status()?.retry ?: return false
        if (pendingAcquire.acquirePending) {
            return acquireAndCommitStandby(requireNotNull(pendingAcquire.acquireOperationId))
        }
        return true
    }

    fun slotFailed(leaseId: String, reason: String): Boolean = synchronized(gate) {
        val transaction = status() ?: return@synchronized false
        if (!transaction.containsCurrentLease(leaseId)) return@synchronized false
        val surviving = listOfNotNull(transaction.slotALeaseId, transaction.slotBLeaseId)
            .firstOrNull { it != leaseId && native.isUsable(it) }
        if (surviving != null) {
            val updated = transaction.copy(
                localActiveLeaseId = surviving,
                retry = transaction.retry.copy(
                    roleObservationPending = true,
                    pendingRoleLeaseId = surviving,
                    pendingRoleReason = reason,
                ),
            )
            if (!persist(updated)) return@synchronized false
            if (!native.activate(surviving)) return@synchronized false
            reportLocalRoleLocked(reason)
            return@synchronized true
        }
        if (!transaction.retry.sessionStalledRecorded) {
            val recorded = transaction.copy(
                retry = transaction.retry.copy(sessionStalledRecorded = true),
            )
            if (!persist(recorded)) return@synchronized false
            onAllSlotsStalled()
        }
        false
    }

    /** Rebase updates canonical generations but never switches a locally active native dataplane. */
    fun reportLocalRole(reason: String): Boolean = synchronized(gate) { reportLocalRoleLocked(reason) }

    private fun reportLocalRoleLocked(reason: String): Boolean {
        val transaction = status() ?: return false
        if (!transaction.desiredActive || transaction.localActiveLeaseId == null) return false
        val pending = if (transaction.retry.roleObservationPending) transaction else transaction.copy(
            retry = transaction.retry.copy(
                roleObservationPending = true,
                pendingRoleLeaseId = transaction.localActiveLeaseId,
                pendingRoleReason = reason,
            ),
        )
        if (!persist(pending)) return false
        return flushRoleObservationLocked()
    }

    private fun flushRoleObservationLocked(): Boolean {
        var transaction = status() ?: return false
        if (!transaction.retry.roleObservationPending) return true
        repeat(2) {
            val reason = requireNotNull(transaction.retry.pendingRoleReason)
            val response = try {
                panel.reportRole(transaction, reason)
            } catch (_: Throwable) {
                return false
            }
            val canonical = transaction.withCanonical(response.session)
            if (response.action == "rebase") {
                if (!persist(canonical)) return false
                transaction = status() ?: return false
            } else {
                return persist(canonical.copy(retry = canonical.retry.copy(
                    roleObservationPending = false,
                    pendingRoleLeaseId = null,
                    pendingRoleReason = null,
                )))
            }
        }
        return false
    }

    fun releaseStandby(): Boolean = synchronized(gate) {
        val transaction = status() ?: return@synchronized false
        val inactive = listOfNotNull(transaction.slotALeaseId, transaction.slotBLeaseId)
            .firstOrNull { it != transaction.localActiveLeaseId } ?: return@synchronized false
        // Fence future acquire/commit before the panel release can be retried.
        val fenced = transaction.copy(standbyDesired = false)
        if (!persist(fenced)) return@synchronized false
        val session = panel.releaseStandby(fenced, inactive)
        if (!native.stopSlot(inactive)) return@synchronized false
        persist(fenced.withCanonical(session).copy(standbyDesired = false))
    }

    fun acquireAndCommitStandby(
        operationId: String,
        replaceLeaseId: String? = null,
    ): Boolean = synchronized(gate) {
        val transaction = status() ?: return@synchronized false
        if (!transaction.desiredActive || !transaction.standbyDesired) return@synchronized false
        val replayOperationId = transaction.retry.acquireOperationId ?: operationId
        val replacement = transaction.retry.acquireReplaceLeaseId ?: replaceLeaseId ?: listOfNotNull(
            transaction.slotALeaseId,
            transaction.slotBLeaseId,
        ).firstOrNull { it != transaction.localActiveLeaseId } ?: return@synchronized false
        if (!transaction.containsCurrentLease(replacement) || replacement == transaction.localActiveLeaseId) {
            return@synchronized false
        }
        val staged = if (transaction.retry.acquirePending) transaction else transaction.copy(
            retry = transaction.retry.copy(
                acquirePending = true,
                acquireOperationId = replayOperationId,
                acquireReplaceLeaseId = replacement,
            ),
        )
        if (!persist(staged)) return@synchronized false
        val candidate = try {
            panel.acquireStandby(
                staged,
                requireNotNull(staged.retry.acquireOperationId),
                requireNotNull(staged.retry.acquireReplaceLeaseId),
            )
        } catch (_: Throwable) {
            return@synchronized false
        }
        val candidateStaged = staged.copy(
            candidateLeaseId = candidate.candidateLeaseId,
            candidateSlot = candidate.candidateSlot,
        )
        if (!persist(candidateStaged)) return@synchronized false
        if (!native.start(candidate.candidateLeaseId, candidate.configuration)) return@synchronized false
        val session = try {
            panel.commitCandidate(candidateStaged, candidate.candidateLeaseId)
        } catch (_: Throwable) {
            return@synchronized false
        }
        val committed = candidateStaged.withCanonical(session).copy(retry = candidateStaged.retry.copy(
            acquirePending = false,
            acquireOperationId = null,
            acquireReplaceLeaseId = null,
        ))
        persist(committed)
    }

    /** onRevoke calls this synchronously; desired-active is durable before the idempotent stop is queued. */
    override fun revoke(): Boolean = synchronized(gate) {
        val transaction = status() ?: return@synchronized false
        val stopped = if (transaction.desiredActive || transaction.stopOperationId == null) {
            transaction.copy(desiredActive = false, stopOperationId = transaction.stopOperationId ?: operationId())
        } else {
            transaction
        }
        if (!persist(stopped)) return@synchronized false
        val pending = stopped.copy(retry = stopped.retry.copy(stopState = RedundantStopState.PENDING))
        if (!persist(pending)) return@synchronized false
        val localStopped = try { native.stop() } catch (_: Throwable) { false }
        val panelStopped = if (localStopped) try { panel.stop(pending) } catch (_: Throwable) { false } else false
        if (!localStopped || !panelStopped) return@synchronized false
        val acknowledged = pending.copy(retry = pending.retry.copy(stopState = RedundantStopState.ACKNOWLEDGED))
        if (!persist(acknowledged)) return@synchronized false
        store.completeRedundantStop(requireNotNull(acknowledged.stopOperationId)) is RecoveryStoreResult.Success
    }

    private fun persist(transaction: AndroidRedundantTransaction): Boolean =
        store.updateRedundant { transaction } is RecoveryStoreResult.Success
}

private fun AndroidRedundantTransaction.withCanonical(
    session: BackgroundRedundantSession,
): AndroidRedundantTransaction = copy(
    slotALeaseId = session.slotALeaseId,
    slotBLeaseId = session.slotBLeaseId,
    standbyDesired = session.standbyDesired,
    roleGeneration = session.roleGeneration,
    membershipGeneration = session.membershipGeneration,
    candidateLeaseId = candidateLeaseId.takeIf { it != session.slotALeaseId && it != session.slotBLeaseId },
    candidateSlot = candidateSlot.takeIf { candidateLeaseId != null &&
        candidateLeaseId != session.slotALeaseId && candidateLeaseId != session.slotBLeaseId },
)
