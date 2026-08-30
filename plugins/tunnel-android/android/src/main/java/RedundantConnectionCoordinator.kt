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
    ): BackgroundRedundantCandidate = throw UnsupportedOperationException()
    fun commitCandidate(
        transaction: AndroidRedundantTransaction,
        candidateLeaseId: String,
    ): BackgroundRedundantSession = throw UnsupportedOperationException()
    fun stop(transaction: AndroidRedundantTransaction)
}

internal data class RedundantRecoveryResponse(
    val session: BackgroundRedundantSession,
    val configurations: Map<String, ByteArray>,
)

/** A v2 envelope is reserved for this coordinator and must never create a recovery-v1 backend. */
internal fun shouldEnterLegacyVpnRecovery(
    recovery: RecoveryStoreResult<AndroidRecoveryEnvelope>,
): Boolean = (recovery as? RecoveryStoreResult.Success)?.value?.redundantTransaction == null

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
) {
    private val gate = Any()
    private var recoveryStarted = false

    fun status(): AndroidRedundantTransaction? =
        (store.read() as? RecoveryStoreResult.Success)?.value?.redundantTransaction

    fun start(
        transaction: AndroidRedundantTransaction,
        configurations: Map<String, ByteArray>,
    ): Boolean = synchronized(gate) {
        if (store.beginRedundant(transaction) !is RecoveryStoreResult.Success) return@synchronized false
        val active = transaction.localActiveLeaseId ?: return@synchronized false
        for (leaseId in listOf(active) + listOfNotNull(
            transaction.slotALeaseId,
            transaction.slotBLeaseId,
        ).filter { it != active }.distinct()) {
            val configuration = configurations[leaseId] ?: continue
            if (!native.start(leaseId, configuration)) return@synchronized false
        }
        recoveryStarted = true
        true
    }

    /** Replays the v2 session before callers attempt any recovery-v1 flow. */
    fun recover(): Boolean = synchronized(gate) {
        val transaction = status() ?: return@synchronized false
        if (!transaction.desiredActive || transaction.retry.stopQueued) return@synchronized false
        if (recoveryStarted) return@synchronized true
        val response = panel.recover(transaction)
        val refreshed = transaction.withCanonical(response.session)
        val active = transaction.localActiveLeaseId.takeIf(response.session::containsCurrentLease)
            ?: response.session.activeLeaseId
            ?: return@synchronized false
        val ordered = listOf(active) + listOfNotNull(
            response.session.slotALeaseId,
            response.session.slotBLeaseId,
        ).filter { it != active }.distinct()
        for (leaseId in ordered) {
            val configuration = response.configurations[leaseId] ?: continue
            if (!native.start(leaseId, configuration)) return@synchronized false
        }
        // The local active identity wins over a stale canonical role until its observation is sent.
        val persisted = persist(refreshed.copy(localActiveLeaseId = active))
        if (persisted) recoveryStarted = true
        persisted
    }

    fun slotFailed(leaseId: String, reason: String): Boolean = synchronized(gate) {
        val transaction = status() ?: return@synchronized false
        if (!transaction.containsCurrentLease(leaseId)) return@synchronized false
        val surviving = listOfNotNull(transaction.slotALeaseId, transaction.slotBLeaseId)
            .firstOrNull { it != leaseId && native.isUsable(it) }
        if (surviving != null) {
            if (!native.activate(surviving)) return@synchronized false
            val updated = transaction.copy(localActiveLeaseId = surviving)
            if (!persist(updated)) return@synchronized false
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
        val response = panel.reportRole(transaction, reason)
        return persist(transaction.withCanonical(response.session))
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

    fun acquireAndCommitStandby(operationId: String): Boolean = synchronized(gate) {
        val transaction = status() ?: return@synchronized false
        if (!transaction.desiredActive || !transaction.standbyDesired) return@synchronized false
        val candidate = panel.acquireStandby(transaction, operationId)
        val staged = transaction.copy(
            candidateLeaseId = candidate.candidateLeaseId,
            candidateSlot = candidate.candidateSlot,
        )
        if (!persist(staged)) return@synchronized false
        if (!native.start(candidate.candidateLeaseId, candidate.configuration)) return@synchronized false
        val session = panel.commitCandidate(staged, candidate.candidateLeaseId)
        persist(staged.withCanonical(session))
    }

    /** onRevoke calls this synchronously; desired-active is durable before the idempotent stop is queued. */
    fun revoke(): Boolean = synchronized(gate) {
        val transaction = status() ?: return@synchronized false
        val stopped = if (transaction.desiredActive || transaction.stopOperationId == null) {
            transaction.copy(desiredActive = false, stopOperationId = transaction.stopOperationId ?: operationId())
        } else {
            transaction
        }
        if (!persist(stopped)) return@synchronized false
        if (stopped.retry.stopQueued) return@synchronized true
        val queued = stopped.copy(retry = stopped.retry.copy(stopQueued = true))
        if (!persist(queued)) return@synchronized false
        native.stop()
        panel.stop(queued)
        true
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
