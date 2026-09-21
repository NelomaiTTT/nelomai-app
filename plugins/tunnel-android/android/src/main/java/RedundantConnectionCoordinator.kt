package ru.nelomai.tunnel

import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

/** Narrow Task 8/9 seam: native owns the one real TUN and never exposes a vendor backend. */
internal interface RedundantConnectionNative {
    fun start(
        leaseId: String,
        slot: RedundantSlot,
        configuration: ByteArray,
        healthProbe: BackgroundRedundantHealthProbe?,
    ): Boolean
    fun activate(leaseId: String): Boolean
    fun stopSlot(leaseId: String): Boolean
    fun stop(): Boolean
    fun isUsable(leaseId: String): Boolean
    fun setNetworkValidated(validated: Boolean) = Unit
    fun setProbeSourceIpv4(sourceIpv4: String) = Unit
    fun rebind(leaseId: String): Boolean = false
    fun healthObservations(): List<SlotObservation> = emptyList()
    fun metrics(includeProbeTarget: Boolean): RedundantVpnMetrics? = null
    fun diagnosticMetrics(): String? = null
}

internal data class RedundantVpnMetrics(
    val receivedBytes: Long,
    val sentBytes: Long,
    val latestHandshakeEpochMillis: Long?,
    val probeTarget: String?,
)

internal class RedundantOperationMutationFence {
    private val gate = Any()
    private val cancelled = ConcurrentHashMap.newKeySet<String>()

    fun cancel(startOperationId: String) {
        cancelled += startOperationId
        // Drain only short serialized service mutations. Native and durable I/O never hold this gate.
        synchronized(gate) { Unit }
    }

    fun runIfActive(
        startOperationId: String?,
        onCancelled: () -> Unit = {},
        action: () -> Boolean,
    ): Boolean {
        if (startOperationId != null && startOperationId in cancelled) return false
        val result = action()
        if (startOperationId != null && startOperationId in cancelled) {
            onCancelled()
            return false
        }
        return result
    }

    fun runSerializedIfActive(
        startOperationId: String?,
        action: () -> Boolean,
    ): Boolean = synchronized(gate) {
        runIfActive(startOperationId, action = action)
    }
}

internal enum class RedundantReserveState(val wireName: String) {
    WARMING("warming"),
    READY("ready"),
    UNAVAILABLE("unavailable"),
    FAILOVER("failover"),
}

internal enum class RedundantDiagnosticEvent {
    FAILOVER,
    RECOVERY,
    REPLACEMENT,
}

/** Background transport seam. Configuration bytes only cross this boundary in process memory. */
internal interface RedundantConnectionPanel {
    fun recover(transaction: AndroidRedundantTransaction): RedundantRecoveryResponse
    fun reportRole(transaction: AndroidRedundantTransaction, reason: String): RedundantRoleResponse
    fun releaseStandby(
        transaction: AndroidRedundantTransaction,
        inactiveLeaseId: String?,
    ): BackgroundRedundantSession = throw UnsupportedOperationException()
    fun acquireStandby(
        transaction: AndroidRedundantTransaction,
        operationId: String,
        replaceLeaseId: String?,
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
    val healthProbes: Map<String, BackgroundRedundantHealthProbe> = emptyMap(),
    val virtualAddressV4: String? = null,
)

private data class PendingPrimaryReadiness(
    val activeLeaseId: String,
    val activeIndex: Int,
    val deadlineElapsedMs: Long,
    val shouldCancel: () -> Boolean,
    val freshStart: Boolean,
    val drainPendingWork: Boolean,
    val onReady: () -> Unit,
    val onFailed: () -> Unit,
    val onCancelled: () -> Unit,
)

/** A v2 envelope is reserved for this coordinator and must never create a recovery-v1 backend. */
internal fun shouldEnterLegacyVpnRecovery(
    recovery: RecoveryStoreResult<AndroidRecoveryEnvelope>,
): Boolean = when (recovery) {
    is RecoveryStoreResult.Success -> recovery.value.redundantTransaction == null
    is RecoveryStoreResult.Failure -> false
}

/** Process-level recovery-v2 owner implemented by the production coordinator. */
internal interface RedundantVpnProcessOwner {
    fun recover(): Boolean
    fun resume(): Boolean
    fun fenceRevoke(): Boolean = true
    fun revoke(): Boolean
    fun closeLocal(): Boolean = true
    fun onUnderlyingNetworkChanged(validated: Boolean): Boolean = false
    fun tick(): Boolean = false
    fun isRunning(): Boolean = false
    fun metrics(includeProbeTarget: Boolean): RedundantVpnMetrics? = null
    fun reserveState(): RedundantReserveState? = null
    fun releaseStandby(): Boolean = false
}

/** Never fall through to a legacy backend when a v2 envelope is present or unreadable. */
internal fun routeVpnProcessRecovery(
    recovery: RecoveryStoreResult<AndroidRecoveryEnvelope>,
    owner: RedundantVpnProcessOwner?,
    legacyRecovery: () -> Unit,
): Boolean = when (recovery) {
    is RecoveryStoreResult.Failure -> false
    is RecoveryStoreResult.Success -> if (recovery.value.redundantTransaction != null) {
        owner?.resume() ?: false
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

/** A recovery-v2 network transition is owned exclusively by the redundant dataplane. */
internal fun routeVpnProcessNetworkChange(
    recovery: RecoveryStoreResult<AndroidRecoveryEnvelope>,
    owner: RedundantVpnProcessOwner?,
    validated: Boolean,
    legacyNetworkChange: () -> Unit,
): Boolean = when (recovery) {
    is RecoveryStoreResult.Failure -> false
    is RecoveryStoreResult.Success -> if (recovery.value.redundantTransaction != null) {
        owner?.onUnderlyingNetworkChanged(validated) ?: false
    } else {
        legacyNetworkChange()
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
    private val epochNowMs: () -> Long = System::currentTimeMillis,
    private val monotonicMs: () -> Long = {
        TimeUnit.NANOSECONDS.toMillis(System.nanoTime())
    },
    private val healthMonitor: RedundantHealthMonitor = RedundantHealthMonitor(),
    private val onReserveStateChanged: (RedundantReserveState?) -> Unit = {},
    private val onDiagnosticEvent: (RedundantDiagnosticEvent) -> Unit = {},
    expectedStartOperationId: String? = null,
    private val mutationFence: RedundantOperationMutationFence = RedundantOperationMutationFence(),
    private val onAllSlotsStalled: () -> Unit = {},
    private val onRecoveryReadiness: (Boolean) -> Unit = {},
) : RedundantVpnProcessOwner {
    private val gate = Any()
    @Volatile private var recoveryStarted = false
    @Volatile private var candidateWarmupLeaseId: String? = null
    @Volatile private var publishedReserveState: RedundantReserveState? = null
    @Volatile private var failoverActive = false
    private var totalLossCommandEmitted = false
    private var pendingPrimaryReadiness: PendingPrimaryReadiness? = null
    private var primaryReadinessFailed = false
    private var recoveryRetryAtUnix: Long? = null
    private var recoveryRetryAttempt = 0
    private var boundStartOperationId: String? = expectedStartOperationId

    fun status(): AndroidRedundantTransaction? = synchronized(gate) {
        val transaction = (store.read() as? RecoveryStoreResult.Success)
            ?.value?.redundantTransaction ?: return@synchronized null
        val expected = boundStartOperationId
        if (expected == null) {
            boundStartOperationId = transaction.startOperationId
            transaction
        } else {
            transaction.takeIf { it.startOperationId == expected }
        }
    }

    override fun isRunning(): Boolean = recoveryStarted

    override fun reserveState(): RedundantReserveState? = publishedReserveState

    override fun metrics(includeProbeTarget: Boolean): RedundantVpnMetrics? = synchronized(gate) {
        if (!isRunning()) null else native.metrics(includeProbeTarget)
    }

    fun start(
        transaction: AndroidRedundantTransaction,
        configurations: Map<String, ByteArray>,
        healthProbes: Map<String, BackgroundRedundantHealthProbe> = emptyMap(),
        shouldCancel: () -> Boolean = { false },
        onPrimaryStarted: () -> Unit = {},
        onPrimaryFailed: () -> Unit = {},
        onPrimaryCancelled: () -> Unit = {},
    ): Boolean = synchronized(gate) {
        if (totalLossCommandEmitted) return@synchronized false
        val expected = boundStartOperationId
        if (expected != null && expected != transaction.startOperationId) return@synchronized false
        boundStartOperationId = transaction.startOperationId
        val active = transaction.localActiveLeaseId ?: return@synchronized false
        val activeConfiguration = configurations[active] ?: return@synchronized false
        if (!mutationFence.runIfActive(transaction.startOperationId) {
                store.beginRedundant(transaction) is RecoveryStoreResult.Success
            }
        ) return@synchronized false
        primaryReadinessFailed = false
        if (shouldCancel()) {
            fenceRevoke()
            return@synchronized false
        }
        val activeSlot = transaction.slot(active) ?: return@synchronized false
        if (!mutateNative(transaction) {
                native.start(active, activeSlot, activeConfiguration, healthProbes[active])
            }
        ) return@synchronized false
        if (!mutateNative(transaction) { native.activate(active) }) return@synchronized false
        startStandbyMembersLocked(transaction, active, configurations, healthProbes)
        val current = status()
        if (shouldCancel() || current?.desiredActive != true ||
            current.retry.stopState != RedundantStopState.NONE
        ) {
            native.stop()
            return@synchronized false
        }
        beginPrimaryReadinessLocked(
            transaction = transaction,
            activeLeaseId = active,
            activeSlot = activeSlot,
            healthProbe = healthProbes[active],
            shouldCancel = shouldCancel,
            freshStart = true,
            drainPendingWork = false,
            onReady = onPrimaryStarted,
            onFailed = onPrimaryFailed,
            onCancelled = onPrimaryCancelled,
        )
    }

    /** Replays the v2 session before callers attempt any recovery-v1 flow. */
    override fun recover(): Boolean = synchronized(gate) {
        if (totalLossCommandEmitted) return@synchronized false
        val transaction = status() ?: return@synchronized false
        if (!transaction.desiredActive || transaction.retry.stopState != RedundantStopState.NONE) {
            return@synchronized false
        }
        if (recoveryStarted || pendingPrimaryReadiness != null) return@synchronized true
        if (primaryReadinessFailed) return@synchronized false
        if (recoveryRetryAtUnix?.let { currentUnixSeconds() < it } == true) return@synchronized false
        // Retryable control-plane errors retain the exact session. Native readiness
        // failure remains terminal; a durable switch has its own bounded retries.
        val response = try {
            panel.recover(transaction)
        } catch (error: Throwable) {
            val policy = ConnectionIntentErrorPolicy()
            val decision = policy.classify((error as? BackgroundConnectionException)?.code.orEmpty())
            if (decision == ConnectionIntentDecision.RETRY_SAME_OPERATION ||
                decision == ConnectionIntentDecision.RETRY_AFTER || error is java.io.IOException
            ) {
                val delay = if ((error as? BackgroundConnectionException)?.retryAfterHeader != null ||
                    decision == ConnectionIntentDecision.RETRY_AFTER
                ) policy.retryAfterSeconds((error as? BackgroundConnectionException)?.retryAfterHeader)
                else RECOVERY_RETRY_DELAYS_SECONDS[recoveryRetryAttempt]
                recoveryRetryAttempt = (recoveryRetryAttempt + 1).coerceAtMost(RECOVERY_RETRY_DELAYS_SECONDS.lastIndex)
                recoveryRetryAtUnix = retryDeadlineUnix(delay)
                return@synchronized false
            }
            primaryReadinessFailed = true
            onRecoveryReadiness(false)
            throw error
        }
        recoveryRetryAtUnix = null
        recoveryRetryAttempt = 0
        try {
            primaryReadinessFailed = false
            try {
                if (transaction.retry.hasPendingNativeSwitch() &&
                    !transaction.matchesPendingNativeMembership(response.session)
                ) {
                    revoke()
                    return@synchronized false
                }
                val refreshed = transaction.withRecoveredCanonical(response.session)
                val pendingTarget = refreshed.retry.pendingNativeActiveLeaseId
                val active = pendingTarget ?: transaction.localActiveLeaseId
                    .takeIf(response.session::containsCurrentLease)
                    ?: response.session.activeLeaseId ?: return@synchronized false
                val activeConfiguration = response.configurations[active] ?: return@synchronized false
                val activeSlot = refreshed.slot(active) ?: return@synchronized false
                if (pendingTarget != null && refreshed != transaction &&
                    !persistExactTransaction(transaction, refreshed)
                ) {
                    return@synchronized false
                }
                if (!mutateNative(transaction) {
                        response.virtualAddressV4?.let(native::setProbeSourceIpv4)
                        true
                    }
                ) return@synchronized false
                if (!mutateNative(transaction) {
                        native.start(
                            active,
                            activeSlot,
                            activeConfiguration,
                            response.healthProbes[active],
                        )
                    }
                ) return@synchronized false
                if (pendingTarget != null) {
                    val source = requireNotNull(refreshed.retry.pendingNativeSourceLeaseId)
                    if (source != active &&
                        refreshed.retry.pendingNativeSwitchAttempt >=
                        MAX_PENDING_NATIVE_SWITCH_ATTEMPTS - 1
                    ) {
                        response.configurations[source]?.let { configuration ->
                            refreshed.slot(source)?.let { slot ->
                                mutateNative(refreshed) {
                                    native.start(
                                        source,
                                        slot,
                                        configuration,
                                        response.healthProbes[source],
                                    )
                                }
                            }
                        }
                    }
                    if (!drainPendingNativeSwitchLocked(refreshed)) {
                        val current = status()
                        if (!totalLossCommandEmitted && current != null && current.desiredActive &&
                            current.retry.stopState == RedundantStopState.NONE &&
                            (current.retry.hasPendingNativeSwitch() || current.localActiveLeaseId == source)
                        ) {
                            // Continue full recovery on the next existing health tick,
                            // including readiness after activation or source fallback.
                            // Configurations are wiped below and refetched by exact replay.
                            recoveryRetryAtUnix = currentUnixSeconds()
                        }
                        return@synchronized false
                    }
                } else if (!mutateNative(refreshed) { native.activate(active) }) {
                    return@synchronized false
                }
                val committed = if (pendingTarget != null) {
                    status() ?: return@synchronized false
                } else {
                    refreshed
                }
                val standby = listOfNotNull(
                    response.session.slotALeaseId,
                    response.session.slotBLeaseId,
                ).filter { committed.standbyDesired && it != active }.distinct()
                for (leaseId in standby) {
                    val configuration = response.configurations[leaseId] ?: continue
                    committed.slot(leaseId)?.let { slot ->
                        mutateNative(committed) {
                            native.start(leaseId, slot, configuration, response.healthProbes[leaseId])
                        }
                    }
                }
                // The local active identity wins over a stale canonical role until its observation is sent.
                val recovered = committed.copy(localActiveLeaseId = active)
                val persisted = if (pendingTarget != null) {
                    recovered == committed || persistExactTransaction(committed, recovered)
                } else {
                    persistExactTransaction(transaction, recovered)
                }
                if (!persisted) {
                    native.stop()
                    return@synchronized false
                }
                beginPrimaryReadinessLocked(
                    transaction = recovered,
                    activeLeaseId = active,
                    activeSlot = activeSlot,
                    healthProbe = response.healthProbes[active],
                    shouldCancel = { false },
                    freshStart = false,
                    drainPendingWork = true,
                    onReady = { onRecoveryReadiness(true) },
                    onFailed = { onRecoveryReadiness(false) },
                    onCancelled = {},
                )
            } finally {
                response.configurations.values.forEach { it.fill(0) }
            }
        } finally {
            if (!recoveryStarted && pendingPrimaryReadiness == null && !primaryReadinessFailed &&
                recoveryRetryAtUnix == null && !totalLossCommandEmitted
            ) {
                primaryReadinessFailed = true
                onRecoveryReadiness(false)
            }
        }
    }

    override fun resume(): Boolean = synchronized(gate) {
        if (totalLossCommandEmitted) return@synchronized false
        val transaction = status() ?: return@synchronized false
        if (!transaction.desiredActive || transaction.retry.stopState != RedundantStopState.NONE) {
            return@synchronized revoke()
        }
        if (pendingPrimaryReadiness != null) return@synchronized true
        val restored = if (recoveryStarted) true else recover()
        restored && (pendingPrimaryReadiness != null || drainPendingWorkLocked())
    }

    private fun startStandbyMembersLocked(
        transaction: AndroidRedundantTransaction,
        activeLeaseId: String,
        configurations: Map<String, ByteArray>,
        healthProbes: Map<String, BackgroundRedundantHealthProbe>,
    ) {
        for (leaseId in listOfNotNull(
            transaction.slotALeaseId,
            transaction.slotBLeaseId,
        ).filter { transaction.standbyDesired && it != activeLeaseId }.distinct()) {
            val configuration = configurations[leaseId] ?: continue
            // A standby is never allowed to turn a usable active member into a failed start.
            transaction.slot(leaseId)?.let { slot ->
                mutateNative(transaction) {
                    native.start(leaseId, slot, configuration, healthProbes[leaseId])
                }
            }
        }
    }

    private fun beginPrimaryReadinessLocked(
        transaction: AndroidRedundantTransaction,
        activeLeaseId: String,
        activeSlot: RedundantSlot,
        healthProbe: BackgroundRedundantHealthProbe?,
        shouldCancel: () -> Boolean,
        freshStart: Boolean,
        drainPendingWork: Boolean,
        onReady: () -> Unit,
        onFailed: () -> Unit,
        onCancelled: () -> Unit,
    ): Boolean {
        if (healthProbe == null) {
            return completePrimaryReadinessLocked(
                transaction,
                drainPendingWork,
                onReady,
            )
        }
        val startedAt = monotonicMs().coerceAtLeast(0L)
        pendingPrimaryReadiness = PendingPrimaryReadiness(
            activeLeaseId = activeLeaseId,
            activeIndex = if (activeSlot == RedundantSlot.A) 0 else 1,
            deadlineElapsedMs = saturatingAdd(
                startedAt,
                PRIMARY_READINESS_TIMEOUT_MILLIS,
            ),
            shouldCancel = shouldCancel,
            freshStart = freshStart,
            drainPendingWork = drainPendingWork,
            onReady = onReady,
            onFailed = onFailed,
            onCancelled = onCancelled,
        )
        publishReserveStateLocked(transaction, emptyList())
        return true
    }

    private fun advancePrimaryReadinessLocked(
        observations: List<SlotObservation>,
    ): Boolean {
        val pending = pendingPrimaryReadiness ?: return false
        if (pending.shouldCancel()) return cancelPrimaryReadinessLocked(pending)
        val transaction = status() ?: return failPrimaryReadinessLocked(pending)
        if (!transaction.desiredActive ||
            transaction.retry.stopState != RedundantStopState.NONE
        ) {
            return cancelPrimaryReadinessLocked(pending)
        }
        if (transaction.retry.hasPendingNativeSwitch()) {
            if (!drainPendingNativeSwitchLocked(transaction)) {
                val current = status()
                return if (current?.retry?.hasPendingNativeSwitch() == true) {
                    false
                } else {
                    failPrimaryReadinessLocked(pending)
                }
            }
            val switched = status() ?: return failPrimaryReadinessLocked(pending)
            pendingPrimaryReadiness = null
            return completePrimaryReadinessLocked(
                switched,
                pending.drainPendingWork,
                pending.onReady,
            )
        }
        if (transaction.localActiveLeaseId != pending.activeLeaseId) {
            return cancelPrimaryReadinessLocked(pending)
        }
        val observation = observations.singleOrNull { it.index == pending.activeIndex }
        if (observation?.hardFailure == true ||
            observation?.health == BackendHealth.UNHEALTHY
        ) {
            return advancePrimaryReadinessThroughStandbyLocked(
                pending,
                transaction,
                observations,
            )
        }
        if (observation != null && healthMonitor.ready(elapsedNow(), observation)) {
            val ready = transaction.copy(retry = transaction.retry.copy(
                roleObservationPending = true,
                pendingRoleLeaseId = transaction.localActiveLeaseId,
                pendingRoleReason = "primary_ready",
            ))
            if (!persist(ready)) return failPrimaryReadinessLocked(pending)
            pendingPrimaryReadiness = null
            return completePrimaryReadinessLocked(
                ready,
                pending.drainPendingWork,
                pending.onReady,
            )
        }
        if (monotonicMs().coerceAtLeast(0L) >= pending.deadlineElapsedMs) {
            return advancePrimaryReadinessThroughStandbyLocked(
                pending,
                transaction,
                observations,
            )
        }
        return true
    }

    private fun advancePrimaryReadinessThroughStandbyLocked(
        pending: PendingPrimaryReadiness,
        transaction: AndroidRedundantTransaction,
        observations: List<SlotObservation>,
    ): Boolean {
        if (!transaction.standbyDesired) return failPrimaryReadinessLocked(pending)
        val standbyLeaseId = listOfNotNull(
            transaction.slotALeaseId,
            transaction.slotBLeaseId,
        ).firstOrNull { it != pending.activeLeaseId } ?: return failPrimaryReadinessLocked(pending)
        val standbyIndex = transaction.slotIndex(standbyLeaseId)
            ?: return failPrimaryReadinessLocked(pending)
        val standby = observations.singleOrNull { it.index == standbyIndex }
        // READY can predate the current failure episode. As in normal failover,
        // wait for its reserve probe and never activate an expired/failed check.
        val standbyProbeReady = standby?.standbyProbeState == StandbyProbeState.NOT_REQUIRED ||
            standby?.standbyProbeState == StandbyProbeState.SUCCEEDED
        if (standby == null || !standbyProbeReady || !healthMonitor.ready(elapsedNow(), standby)) {
            val standbyFailed = standby?.hardFailure == true ||
                standby?.health == BackendHealth.UNHEALTHY ||
                standby?.standbyProbeState == StandbyProbeState.FAILED
            if (standby != null && !standbyFailed &&
                monotonicMs().coerceAtLeast(0L) < pending.deadlineElapsedMs
            ) {
                return true
            }
            return failPrimaryReadinessLocked(pending)
        }
        // Recovery may retain a scheduled repair even though the restarted
        // CURRENT standby has recovered. Do not cancel a staged candidate.
        val readyTransaction = if (transaction.retry.acquirePending &&
            transaction.candidateLeaseId == null &&
            transaction.retry.acquireReplaceLeaseId == standbyLeaseId
        ) {
            transaction.copy(retry = transaction.retry.cancelAcquire()).also {
                if (!persistExactTransaction(transaction, it)) return failPrimaryReadinessLocked(pending)
            }
        } else transaction
        if (!switchActiveLocked(
                readyTransaction,
                target = standbyLeaseId,
                failed = pending.activeLeaseId,
                reason = HEALTH_FAILOVER_REASON,
            )
        ) {
            return if (status()?.retry?.hasPendingNativeSwitch() == true) {
                false
            } else {
                failPrimaryReadinessLocked(pending)
            }
        }
        val switched = status()?.takeIf { it.localActiveLeaseId == standbyLeaseId }
            ?: return failPrimaryReadinessLocked(pending)
        pendingPrimaryReadiness = null
        return completePrimaryReadinessLocked(
            switched,
            pending.drainPendingWork,
            pending.onReady,
        )
    }

    private fun completePrimaryReadinessLocked(
        transaction: AndroidRedundantTransaction,
        drainPendingWork: Boolean,
        onReady: () -> Unit,
    ): Boolean {
        recoveryStarted = true
        primaryReadinessFailed = false
        failoverActive = transaction.retry.acquirePending &&
            transaction.localActiveLeaseId == transaction.slotBLeaseId
        publishReserveStateLocked(transaction, emptyList())
        onReady()
        return !drainPendingWork || drainPendingWorkLocked()
    }

    private fun failPrimaryReadinessLocked(pending: PendingPrimaryReadiness): Boolean {
        if (pendingPrimaryReadiness !== pending) return false
        pendingPrimaryReadiness = null
        recoveryStarted = false
        primaryReadinessFailed = true
        runCatching(native::stop)
        publishReserveStateLocked(null, emptyList())
        pending.onFailed()
        return false
    }

    private fun cancelPrimaryReadinessLocked(pending: PendingPrimaryReadiness): Boolean {
        if (pendingPrimaryReadiness !== pending) return false
        pendingPrimaryReadiness = null
        recoveryStarted = false
        primaryReadinessFailed = false
        runCatching(native::stop)
        publishReserveStateLocked(null, emptyList())
        if (pending.freshStart) pending.onCancelled()
        return false
    }

    private fun drainPendingWorkLocked(
        observations: List<SlotObservation>? = null,
    ): Boolean {
        val transaction = status() ?: return false
        if (transaction.retry.hasPendingNativeSwitch()) {
            return drainPendingNativeSwitchLocked(transaction)
        }
        if (!transaction.standbyDesired) {
            if (!drainStandbyReleaseLocked(transaction)) return false
            return status()?.retry?.roleObservationPending != true || flushRoleObservationLocked()
        }
        if (transaction.retry.roleObservationPending && !flushRoleObservationLocked()) return false
        val current = status() ?: return false
        val pendingAcquire = current.retry
        if (pendingAcquire.acquirePending) {
            if (current.candidateLeaseId != null) {
                return advanceCandidateLocked(current, observations)
            }
            val dueAtUnix = pendingAcquire.nextRetryAtUnix
            if (dueAtUnix != null && currentUnixSeconds() < dueAtUnix) return true
            return acquireAndCommitStandby(requireNotNull(pendingAcquire.acquireOperationId))
        }
        return true
    }

    /** Applies one bounded native health snapshot without exposing a member failure to legacy recovery. */
    fun onHealthObservations(observations: List<SlotObservation>): Boolean = synchronized(gate) {
        if (totalLossCommandEmitted) return@synchronized false
        val transaction = status() ?: return@synchronized false
        if (!transaction.desiredActive || transaction.retry.stopState != RedundantStopState.NONE) {
            return@synchronized false
        }
        if (pendingPrimaryReadiness != null) {
            return@synchronized advancePrimaryReadinessLocked(observations)
        }
        if (primaryReadinessFailed) return@synchronized false
        if (recoveryRetryAtUnix != null) return@synchronized recover()
        if (transaction.retry.hasPendingNativeSwitch()) {
            return@synchronized drainPendingNativeSwitchLocked(transaction)
        }
        val activeIndex = transaction.slotIndex(transaction.localActiveLeaseId)
            ?: return@synchronized false
        val bounded = observations
            .filter { transaction.standbyDesired || it.index == activeIndex }
            .map { it.copy(active = it.index == activeIndex) }
        val replacingIndex = transaction.slotIndex(transaction.retry.acquireReplaceLeaseId)
        if (transaction.retry.acquirePending && transaction.candidateLeaseId == null &&
            replacingIndex != null && bounded.firstOrNull { it.index == replacingIndex }?.let {
                healthMonitor.ready(elapsedNow(), it)
            } == true
        ) {
            val recovered = transaction.copy(retry = transaction.retry.cancelAcquire())
            val persisted = persist(recovered)
            if (persisted) {
                failoverActive = false
                onDiagnosticEvent(RedundantDiagnosticEvent.RECOVERY)
                publishReserveStateLocked(recovered, bounded)
            }
            return@synchronized persisted
        }
        val decision = healthMonitor.evaluateHealth(elapsedNow(), bounded)
        val switchIndex = decision.switchTo
        if (switchIndex != null) {
            val candidate = transaction.candidateLeaseId
            val candidateIndex = transaction.candidateSlot?.let {
                if (it == RedundantSlot.A) 0 else 1
            }
            if (candidate != null && switchIndex == candidateIndex) {
                // Native already replaced the old member at this index. Commit its new
                // identity before switching; never activate the stale canonical lease.
                val committed = advanceCandidateLocked(transaction, bounded, forFailover = true)
                val current = status() ?: return@synchronized false
                if (!committed || current.candidateLeaseId != null ||
                    current.leaseIdAt(switchIndex) != candidate
                ) {
                    emitTotalLossCommandLocked(current)
                    return@synchronized false
                }
                return@synchronized switchActiveLocked(
                    current, candidate, requireNotNull(current.localActiveLeaseId), HEALTH_FAILOVER_REASON,
                )
            }
            val target = transaction.leaseIdAt(switchIndex) ?: return@synchronized false
            val failed = transaction.localActiveLeaseId ?: return@synchronized false
            if (target == failed) return@synchronized false
            return@synchronized switchActiveLocked(
                transaction,
                target = target,
                failed = failed,
                reason = HEALTH_FAILOVER_REASON,
            )
        }
        if (decision.sessionStalled) {
            emitTotalLossCommandLocked(transaction)
            return@synchronized false
        }
        if (transaction.standbyDesired && !transaction.retry.acquirePending &&
            transaction.candidateLeaseId == null && bounded.singleOrNull { it.active }?.let {
                healthMonitor.ready(elapsedNow(), it)
            } == true
        ) {
            val inactive = listOfNotNull(transaction.slotALeaseId, transaction.slotBLeaseId)
                .firstOrNull { it != transaction.localActiveLeaseId }
            val observation = bounded.singleOrNull { it.index == transaction.slotIndex(inactive) }
            if (inactive == null || observation == null || healthMonitor.failed(elapsedNow(), observation)) {
                if (!persist(scheduleReplacement(transaction, inactive))) return@synchronized false
            }
        }
        publishReserveStateLocked(status() ?: transaction, bounded)
        true
    }

    override fun tick(): Boolean = synchronized(gate) {
        if (totalLossCommandEmitted) return@synchronized false
        if (pendingPrimaryReadiness != null) {
            val observations = try {
                native.healthObservations()
            } catch (_: Throwable) {
                emptyList()
            }
            return@synchronized advancePrimaryReadinessLocked(observations)
        }
        val transaction = status() ?: return@synchronized false
        if (!transaction.desiredActive || transaction.retry.stopState != RedundantStopState.NONE) {
            return@synchronized false
        }
        if (primaryReadinessFailed) return@synchronized false
        if (recoveryRetryAtUnix != null) return@synchronized recover()
        if (transaction.retry.hasPendingNativeSwitch()) {
            return@synchronized drainPendingNativeSwitchLocked(transaction)
        }
        val observations = try {
            native.healthObservations()
        } catch (_: Throwable) {
            // Cleanup must remain replayable even if native telemetry is unavailable.
            return@synchronized if (!transaction.standbyDesired) {
                drainStandbyReleaseLocked(transaction)
            } else false
        }
        if (observations.isNotEmpty() && !onHealthObservations(observations)) {
            return@synchronized false
        }
        drainPendingWorkLocked(observations)
    }

    override fun onUnderlyingNetworkChanged(validated: Boolean): Boolean = synchronized(gate) {
        if (totalLossCommandEmitted) return@synchronized false
        val transaction = status() ?: return@synchronized false
        if (!transaction.desiredActive || transaction.retry.stopState != RedundantStopState.NONE) {
            return@synchronized false
        }
        if (!mutateNative(transaction) {
                healthMonitor.onUnderlyingNetworkChanged(elapsedNow(), validated)
                native.setNetworkValidated(validated)
                true
            }
        ) return@synchronized false
        val results = mutableListOf<Boolean>()
        for (leaseId in listOfNotNull(transaction.slotALeaseId, transaction.slotBLeaseId).distinct()) {
            results += mutateNative(transaction) {
                runCatching { native.rebind(leaseId) }.getOrDefault(false)
            }
        }
        results.all { it }
    }

    fun slotFailed(leaseId: String, reason: String): Boolean = synchronized(gate) {
        if (totalLossCommandEmitted) return@synchronized false
        val transaction = status() ?: return@synchronized false
        if (!transaction.containsCurrentLease(leaseId)) return@synchronized false
        if (leaseId != transaction.localActiveLeaseId) {
            if (!transaction.standbyDesired) return@synchronized true
            return@synchronized persist(scheduleReplacement(transaction, leaseId))
        }
        val surviving = listOfNotNull(transaction.slotALeaseId, transaction.slotBLeaseId)
            .firstOrNull { it != leaseId && native.isUsable(it) }
        if (surviving != null) {
            return@synchronized switchActiveLocked(transaction, surviving, leaseId, reason)
        }
        emitTotalLossCommandLocked(transaction)
        false
    }

    /** Rebase updates canonical generations but never switches a locally active native dataplane. */
    fun reportLocalRole(reason: String): Boolean = synchronized(gate) {
        if (totalLossCommandEmitted) return@synchronized false
        reportLocalRoleLocked(reason)
    }

    private fun reportLocalRoleLocked(reason: String): Boolean {
        val transaction = status() ?: return false
        if (!transaction.desiredActive || transaction.localActiveLeaseId == null) return false
        val pending = transaction.copy(
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
            } catch (error: Throwable) {
                if (error !is BackgroundConnectionException ||
                    error.code != REDUNDANT_ROLE_MEMBERSHIP_CONFLICT
                ) {
                    return false
                }
                transaction = recoverPendingRoleMembershipLocked(transaction)
                    ?: return false
                return@repeat
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

    private fun recoverPendingRoleMembershipLocked(
        transaction: AndroidRedundantTransaction,
    ): AndroidRedundantTransaction? {
        val response = try {
            panel.recover(transaction)
        } catch (_: Throwable) {
            return null
        }
        return try {
            val pendingRoleLeaseId = transaction.retry.pendingRoleLeaseId ?: return null
            if (response.session.sessionId != transaction.sessionId ||
                pendingRoleLeaseId != transaction.localActiveLeaseId ||
                !response.session.containsCurrentLease(pendingRoleLeaseId)
            ) {
                emitTotalLossCommandLocked(transaction)
                return null
            }
            val canonical = transaction.withRecoveredCanonical(response.session).copy(
                localActiveLeaseId = pendingRoleLeaseId,
            )
            if (!persistExactTransaction(transaction, canonical)) return null
            status()
        } finally {
            response.configurations.values.forEach { it.fill(0) }
        }
    }

    override fun releaseStandby(): Boolean = synchronized(gate) {
        if (totalLossCommandEmitted) return@synchronized false
        val transaction = status() ?: return@synchronized false
        if (transaction.retry.hasPendingNativeSwitch()) return@synchronized false
        if (!transaction.standbyDesired) return@synchronized drainStandbyReleaseLocked(transaction)
        // Fence future acquire/commit before the panel release can be retried.
        val fenced = transaction.copy(
            standbyDesired = false,
            retry = transaction.retry.cancelAcquire().copy(standbyReleasePending = true),
        )
        candidateWarmupLeaseId = null
        failoverActive = false
        if (!persist(fenced)) return@synchronized false
        drainStandbyReleaseLocked(fenced)
    }

    /** Replays the locally fenced exact-member release until both local and panel state agree. */
    private fun drainStandbyReleaseLocked(initial: AndroidRedundantTransaction): Boolean {
        var transaction = initial
        val inactive = listOfNotNull(transaction.slotALeaseId, transaction.slotBLeaseId)
            .firstOrNull { it != transaction.localActiveLeaseId }
        val candidate = transaction.candidateLeaseId
        if (!transaction.retry.standbyReleasePending && inactive == null && candidate == null) {
            return true
        }
        if (candidate != null && candidate != inactive) {
            if (nativeDataplaneStartedLocked() && !native.stopSlot(candidate)) return false
            transaction = transaction.copy(candidateLeaseId = null, candidateSlot = null)
            if (!persist(transaction)) return false
        }
        if (inactive != null && nativeDataplaneStartedLocked() && !native.stopSlot(inactive)) {
            return false
        }
        val session = try {
            panel.releaseStandby(transaction, inactive)
        } catch (error: Throwable) {
            return if (error is BackgroundConnectionException &&
                error.code in REDUNDANT_GENERATION_CONFLICT_CODES
            ) {
                rebaseStandbyReleaseLocked(transaction)
            } else {
                false
            }
        }
        val released = transaction.withCanonical(session)
        return persist(released.copy(
            standbyDesired = false,
            candidateLeaseId = null,
            candidateSlot = null,
            retry = released.retry.copy(standbyReleasePending = false),
        )).also { persisted ->
            if (persisted) publishReserveStateLocked(null, emptyList())
        }
    }

    private fun rebaseStandbyReleaseLocked(transaction: AndroidRedundantTransaction): Boolean {
        val response = try {
            panel.recover(transaction)
        } catch (_: Throwable) {
            return false
        }
        return try {
            val localActive = transaction.localActiveLeaseId ?: return false
            if (!response.session.containsCurrentLease(localActive)) return false
            persist(transaction.withRecoveredCanonical(response.session).copy(
                localActiveLeaseId = localActive,
                standbyDesired = false,
                retry = transaction.retry.cancelAcquire(),
            ))
            // The next serialized tick retries release with the rebased generations.
            false
        } finally {
            response.configurations.values.forEach { it.fill(0) }
        }
    }

    fun acquireAndCommitStandby(
        operationId: String,
        replaceLeaseId: String? = null,
    ): Boolean = synchronized(gate) {
        if (totalLossCommandEmitted) return@synchronized false
        val transaction = status() ?: return@synchronized false
        if (transaction.retry.hasPendingNativeSwitch()) return@synchronized false
        if (!transaction.desiredActive || !transaction.standbyDesired) return@synchronized false
        val replayOperationId = transaction.retry.acquireOperationId ?: operationId
        val replacement = if (transaction.retry.acquirePending) {
            transaction.retry.acquireReplaceLeaseId
        } else {
            replaceLeaseId ?: listOfNotNull(
                transaction.slotALeaseId,
                transaction.slotBLeaseId,
            ).firstOrNull { it != transaction.localActiveLeaseId }
        }
        if (replacement != null && (
                !transaction.containsCurrentLease(replacement) || replacement == transaction.localActiveLeaseId
            )) {
            return@synchronized false
        }
        if (replacement == null && transaction.slotALeaseId != null && transaction.slotBLeaseId != null) {
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
                staged.retry.acquireReplaceLeaseId,
            )
        } catch (error: Throwable) {
            deferAcquireRetryLocked(staged, error)
            return@synchronized false
        }
        try {
            val candidateTargetSlot = replacement?.let(staged::slot) ?: when {
                staged.slotALeaseId == null -> RedundantSlot.A
                staged.slotBLeaseId == null -> RedundantSlot.B
                else -> null
            }
            if (candidate.candidateSlot != candidateTargetSlot) return@synchronized false
            val acquiredCanonical = staged.withCanonical(candidate.session)
            if (!acquiredCanonical.standbyDesired) {
                persist(acquiredCanonical)
                return@synchronized false
            }
            val replacementLeaseId = acquiredCanonical.retry.acquireReplaceLeaseId
            if (replacementLeaseId != null &&
                (!acquiredCanonical.containsCurrentLease(replacementLeaseId) ||
                    replacementLeaseId == acquiredCanonical.localActiveLeaseId ||
                    acquiredCanonical.slot(replacementLeaseId) != candidate.candidateSlot)
            ) {
                return@synchronized false
            }
            val reissuesReplacement = replacementLeaseId != null &&
                candidate.candidateLeaseId == replacementLeaseId
            val fillsEmptySlot = replacementLeaseId == null && when (candidate.candidateSlot) {
                RedundantSlot.A -> acquiredCanonical.slotALeaseId == null
                RedundantSlot.B -> acquiredCanonical.slotBLeaseId == null
            }
            if (candidate.candidateLeaseId == acquiredCanonical.localActiveLeaseId ||
                (acquiredCanonical.containsCurrentLease(candidate.candidateLeaseId) &&
                    !reissuesReplacement) ||
                (replacementLeaseId == null && !fillsEmptySlot)
            ) {
                return@synchronized false
            }
            val candidateStaged = acquiredCanonical.copy(
                candidateLeaseId = candidate.candidateLeaseId,
                candidateSlot = candidate.candidateSlot,
            )
            if (!persist(candidateStaged)) return@synchronized false
            if (replacementLeaseId != null && !native.stopSlot(replacementLeaseId)) {
                return@synchronized false
            }
            if (!mutateNative(candidateStaged) {
                    native.start(
                        candidate.candidateLeaseId,
                        candidate.candidateSlot,
                        candidate.configuration,
                        candidate.healthProbe,
                    )
                }
            ) {
                return@synchronized false
            }
            candidateWarmupLeaseId = candidate.candidateLeaseId
            true
        } finally {
            candidate.configuration.fill(0)
        }
    }

    private fun advanceCandidateLocked(
        transaction: AndroidRedundantTransaction,
        observations: List<SlotObservation>?,
        forFailover: Boolean = false,
    ): Boolean {
        val candidateLeaseId = transaction.candidateLeaseId ?: return false
        val candidateSlot = transaction.candidateSlot ?: return false
        if (!transaction.desiredActive || !transaction.standbyDesired) {
            candidateWarmupLeaseId = null
            return persist(transaction.copy(
                candidateLeaseId = null,
                candidateSlot = null,
                retry = transaction.retry.cancelAcquire(),
            ))
        }
        val candidateIndex = if (candidateSlot == RedundantSlot.A) 0 else 1
        // Reusing a CURRENT member does not change membership. Fresh health from
        // this process's successful restart is enough for emergency local failover;
        // an unavailable commit endpoint must not turn it into total loss.
        if (forFailover && transaction.retry.acquirePending &&
            candidateLeaseId == transaction.retry.acquireReplaceLeaseId &&
            candidateLeaseId != transaction.localActiveLeaseId &&
            transaction.slotIndex(candidateLeaseId) == candidateIndex &&
            candidateWarmupLeaseId == candidateLeaseId &&
            observations?.singleOrNull { it.index == candidateIndex }?.let {
                healthMonitor.ready(elapsedNow(), it)
            } == true
        ) {
            return completeCandidateReadinessLocked(transaction, transaction, observations)
        }
        val dueAtUnix = transaction.retry.nextRetryAtUnix
        if (dueAtUnix != null && currentUnixSeconds() < dueAtUnix) {
            if (!forFailover) return true
            // A failed active member cannot wait for background retry. Only confirm
            // an already committed candidate; do not replay acquire/commit early.
            val session = reconcileCandidateCommitLocked(transaction) ?: return false
            return completeCandidateCommitLocked(transaction, session, observations.orEmpty())
        }
        if (candidateWarmupLeaseId != candidateLeaseId) {
            val replayed = try {
                panel.acquireStandby(
                    transaction,
                    requireNotNull(transaction.retry.acquireOperationId),
                    transaction.retry.acquireReplaceLeaseId,
                )
            } catch (error: Throwable) {
                if (error is BackgroundConnectionException && error.code in REDUNDANT_GENERATION_CONFLICT_CODES) {
                    reconcileCandidateCommitLocked(transaction)?.let { session ->
                        return completeCandidateCommitLocked(transaction, session, observations.orEmpty())
                    }
                }
                deferAcquireRetryLocked(transaction, error)
                return false
            }
            try {
                val replacementLeaseId = transaction.retry.acquireReplaceLeaseId
                val exactInactiveReissue = replacementLeaseId != null &&
                    candidateLeaseId == replacementLeaseId
                if (replayed.candidateSlot != candidateSlot ||
                    (replayed.candidateLeaseId != candidateLeaseId && !exactInactiveReissue)
                ) {
                    return false
                }
                val canonical = transaction.withCanonical(replayed.session)
                val replacementValid = replacementLeaseId?.let {
                    canonical.containsCurrentLease(it) &&
                        it != canonical.localActiveLeaseId &&
                        canonical.slot(it) == replayed.candidateSlot
                } ?: when (replayed.candidateSlot) {
                    RedundantSlot.A -> canonical.slotALeaseId == null
                    RedundantSlot.B -> canonical.slotBLeaseId == null
                }
                if (!replacementValid ||
                    replayed.candidateLeaseId == canonical.localActiveLeaseId ||
                    (canonical.containsCurrentLease(replayed.candidateLeaseId) &&
                        replayed.candidateLeaseId != replacementLeaseId)
                ) {
                    return false
                }
                val refreshed = canonical.copy(
                    candidateLeaseId = replayed.candidateLeaseId,
                    candidateSlot = replayed.candidateSlot,
                )
                if (!refreshed.standbyDesired) {
                    return persist(refreshed.copy(
                        candidateLeaseId = null,
                        candidateSlot = null,
                        retry = refreshed.retry.cancelAcquire(),
                    ))
                }
                if (replacementLeaseId != null && !native.stopSlot(replacementLeaseId)) {
                    return false
                }
                if (!mutateNative(refreshed) {
                        native.start(
                            replayed.candidateLeaseId,
                            replayed.candidateSlot,
                            replayed.configuration,
                            replayed.healthProbe,
                        )
                    }
                ) return false
                candidateWarmupLeaseId = replayed.candidateLeaseId
                if (!persist(refreshed)) return false
            } finally {
                replayed.configuration.fill(0)
            }
            return true
        }
        val snapshot = observations ?: runCatching { native.healthObservations() }.getOrNull()
        val observation = snapshot?.singleOrNull { it.index == candidateIndex } ?: return true
        if (!healthMonitor.ready(elapsedNow(), observation)) return true
        val session = try {
            panel.commitCandidate(transaction, candidateLeaseId)
        } catch (error: Throwable) {
            reconcileCandidateCommitLocked(transaction, error) ?: run {
                deferAcquireRetryLocked(transaction, error)
                return false
            }
        }
        return completeCandidateCommitLocked(transaction, session, listOf(observation))
    }

    private fun reconcileCandidateCommitLocked(
        transaction: AndroidRedundantTransaction,
        commitError: Throwable? = null,
    ): BackgroundRedundantSession? {
        val candidate = transaction.candidateLeaseId ?: return null
        val session = canonicalStandbySessionLocked(transaction) ?: return null
        val canonical = transaction.withCanonical(session)
        // A reused CURRENT replacement is present before commit, so membership cannot prove it.
        if (session.containsCurrentLease(candidate) &&
            canonical.slot(candidate) == transaction.candidateSlot &&
            candidate != transaction.retry.acquireReplaceLeaseId
        ) return session
        // A rejected commit at unchanged generations is not a lost successful commit:
        // with the same valid active member, the candidate is no longer committable.
        // In particular TTL cleanup leaves canonical generations unchanged.
        if (commitError is BackgroundConnectionException &&
            commitError.code == REDUNDANT_ROLE_MEMBERSHIP_CONFLICT &&
            session.standbyDesired && !session.containsCurrentLease(candidate) &&
            session.roleGeneration == transaction.roleGeneration &&
            session.membershipGeneration == transaction.membershipGeneration
        ) discardConsumedCandidateLocked(transaction, session)
        return null
    }

    private fun completeCandidateCommitLocked(
        transaction: AndroidRedundantTransaction,
        session: BackgroundRedundantSession,
        observations: List<SlotObservation>,
    ): Boolean = completeCandidateReadinessLocked(transaction, transaction.withCanonical(session), observations)

    private fun completeCandidateReadinessLocked(
        transaction: AndroidRedundantTransaction,
        canonical: AndroidRedundantTransaction,
        observations: List<SlotObservation>,
    ): Boolean {
        val committed = canonical.copy(
            candidateLeaseId = null,
            candidateSlot = null,
            retry = canonical.retry.copy(
                nextRetryAtUnix = null,
                acquirePending = false,
                acquireOperationId = null,
                acquireReplaceLeaseId = null,
            ),
        )
        if (!persistExactTransaction(transaction, committed)) return false
        candidateWarmupLeaseId = null
        failoverActive = false
        publishReserveStateLocked(committed, observations)
        if (transaction.retry.acquireReplaceLeaseId != null) {
            onDiagnosticEvent(RedundantDiagnosticEvent.REPLACEMENT)
        }
        return true
    }

    /** Serialized durable stop barrier; production callers dispatch it on redundant work. */
    override fun fenceRevoke(): Boolean = synchronized(gate) {
        val transaction = status() ?: return false
        mutationFence.cancel(transaction.startOperationId)
        val fenced = store.deferRedundantStop(
            stopOperationId = transaction.stopOperationId ?: operationId(),
            expectedStartOperationId = transaction.startOperationId,
        ) is
            RecoveryStoreResult.Success
        if (fenced) {
            val pending = pendingPrimaryReadiness
            candidateWarmupLeaseId = null
            pendingPrimaryReadiness = null
            recoveryStarted = false
            primaryReadinessFailed = false
            failoverActive = false
            publishReserveStateLocked(null, emptyList())
            if (pending?.freshStart == true) pending.onCancelled()
        }
        return fenced
    }

    /** Idempotent best-effort cleanup; callers run it on the dedicated redundant executor. */
    override fun revoke(): Boolean = synchronized(gate) {
        val beforeFence = status() ?: return@synchronized when (val current = store.read()) {
            is RecoveryStoreResult.Failure -> false
            is RecoveryStoreResult.Success -> current.value.redundantTransaction == null
        }
        if ((beforeFence.desiredActive || beforeFence.retry.stopState == RedundantStopState.NONE) &&
            !fenceRevoke()
        ) {
            return@synchronized false
        }
        val pending = status() ?: return@synchronized true
        val localStopped = try { native.stop() } catch (_: Throwable) { false }
        val panelStopped = if (localStopped) try { panel.stop(pending) } catch (_: Throwable) { false } else false
        if (!localStopped || !panelStopped) return@synchronized false
        val acknowledged = pending.copy(retry = pending.retry.copy(stopState = RedundantStopState.ACKNOWLEDGED))
        if (!persistCleanup(acknowledged)) return@synchronized false
        store.completeRedundantStop(
            stopOperationId = requireNotNull(acknowledged.stopOperationId),
            expectedStartOperationId = acknowledged.startOperationId,
        ) is RecoveryStoreResult.Success
    }

    override fun closeLocal(): Boolean = synchronized(gate) {
        val pending = pendingPrimaryReadiness
        candidateWarmupLeaseId = null
        pendingPrimaryReadiness = null
        recoveryStarted = false
        primaryReadinessFailed = false
        if (pending?.freshStart == true) pending.onCancelled()
        runCatching(native::stop).getOrDefault(false)
    }

    private fun persist(transaction: AndroidRedundantTransaction): Boolean =
        mutationFence.runIfActive(transaction.startOperationId) {
            persistCleanup(transaction)
        }

    private fun persistCleanup(transaction: AndroidRedundantTransaction): Boolean {
        val result = store.updateRedundant(transaction.startOperationId) { current ->
            // A stop fence is monotonic. Work that began before the fence may finish, but its
            // stale snapshot must never make the session desired/active again.
            if (!current.desiredActive || current.retry.stopState != RedundantStopState.NONE) {
                if (!transaction.desiredActive &&
                    transaction.stopOperationId == current.stopOperationId &&
                    transaction.retry.stopState == RedundantStopState.ACKNOWLEDGED
                ) transaction else current
            } else {
                transaction
            }
        }
        return result is RecoveryStoreResult.Success &&
            result.value.redundantTransaction == transaction
    }

    private fun switchActiveLocked(
        transaction: AndroidRedundantTransaction,
        target: String,
        failed: String,
        reason: String,
    ): Boolean {
        if (transaction.retry.hasPendingNativeSwitch()) {
            return drainPendingNativeSwitchLocked(transaction)
        }
        val targetSlot = transaction.slot(target) ?: return false
        if (transaction.localActiveLeaseId != failed || target == failed ||
            !transaction.containsCurrentLease(target) ||
            transaction.retry.acquireReplaceLeaseId == target
        ) {
            return false
        }
        val pending = transaction.copy(
            retry = transaction.retry.copy(
                pendingNativeSourceLeaseId = failed,
                pendingNativeActiveLeaseId = target,
                pendingNativeActiveSlot = targetSlot,
                pendingNativeMembershipGeneration = transaction.membershipGeneration,
                pendingNativeSwitchReason = reason,
                pendingNativeSwitchAttempt = 0,
            ),
        )
        if (!persistExactTransaction(transaction, pending)) return false
        return drainPendingNativeSwitchLocked(pending)
    }

    private fun drainPendingNativeSwitchLocked(
        pending: AndroidRedundantTransaction,
    ): Boolean {
        val retry = pending.retry
        val source = retry.pendingNativeSourceLeaseId ?: return true
        val target = retry.pendingNativeActiveLeaseId ?: return false
        val targetSlot = retry.pendingNativeActiveSlot ?: return false
        val expectedGeneration = retry.pendingNativeMembershipGeneration ?: return false
        if (pending.localActiveLeaseId != source || source == target ||
            pending.membershipGeneration != expectedGeneration ||
            pending.slot(target) != targetSlot ||
            !pending.containsCurrentLease(source) || !pending.containsCurrentLease(target)
        ) {
            revoke()
            return false
        }
        val activated = mutateNative(pending) {
            runCatching { native.activate(target) }.getOrDefault(false)
        }
        if (!activated) {
            if (retry.pendingNativeSwitchAttempt < MAX_PENDING_NATIVE_SWITCH_ATTEMPTS - 1) {
                persistPendingNativeSwitchExact(
                    pending,
                    pending.copy(retry = retry.copy(
                        pendingNativeSwitchAttempt = retry.pendingNativeSwitchAttempt + 1,
                    )),
                )
                return false
            }
            return resolveFailedPendingNativeSwitchLocked(pending)
        }
        val reason = requireNotNull(retry.pendingNativeSwitchReason)
        var committed = pending.copy(
            localActiveLeaseId = target,
            retry = retry.clearPendingNativeSwitch().copy(
                roleObservationPending = true,
                pendingRoleLeaseId = target,
                pendingRoleReason = reason,
                sessionStalledRecorded = false,
            ),
        )
        committed = scheduleReplacement(committed, source)
        if (!persistPendingNativeSwitchExact(pending, committed)) return false
        failoverActive = true
        publishReserveStateLocked(committed, emptyList())
        onDiagnosticEvent(RedundantDiagnosticEvent.FAILOVER)
        // The dataplane switch is authoritative. A panel outage leaves the durable
        // observation pending and must not roll traffic back to the failed member.
        flushRoleObservationLocked()
        return true
    }

    private fun resolveFailedPendingNativeSwitchLocked(
        pending: AndroidRedundantTransaction,
    ): Boolean {
        val source = requireNotNull(pending.retry.pendingNativeSourceLeaseId)
        val target = requireNotNull(pending.retry.pendingNativeActiveLeaseId)
        val sourceRestored = native.isUsable(source) && mutateNative(pending) {
            runCatching { native.activate(source) }.getOrDefault(false)
        }
        val resolved = if (sourceRestored) {
            scheduleReplacement(
                pending.copy(retry = pending.retry.clearPendingNativeSwitch()),
                target,
            )
        } else {
            null
        }
        if (resolved != null) {
            if (!persistPendingNativeSwitchExact(pending, resolved)) return false
        } else {
            emitTotalLossCommandLocked(pending)
        }
        return false
    }

    private fun emitTotalLossCommandLocked(transaction: AndroidRedundantTransaction): Boolean {
        if (totalLossCommandEmitted || !transaction.desiredActive ||
            transaction.retry.stopState != RedundantStopState.NONE
        ) {
            return false
        }
        val current = status() ?: return false
        if (current.startOperationId != transaction.startOperationId ||
            !current.desiredActive || current.retry.stopState != RedundantStopState.NONE
        ) {
            return false
        }
        totalLossCommandEmitted = true
        onAllSlotsStalled()
        return true
    }

    private fun persistPendingNativeSwitchExact(
        expected: AndroidRedundantTransaction,
        updated: AndroidRedundantTransaction,
    ): Boolean {
        val result = store.updateRedundant(expected.startOperationId) { current ->
            if (current.samePendingNativeSwitch(expected)) updated else current
        }
        return result is RecoveryStoreResult.Success &&
            result.value.redundantTransaction == updated
    }

    private fun persistExactTransaction(
        expected: AndroidRedundantTransaction,
        updated: AndroidRedundantTransaction,
    ): Boolean {
        val result = store.updateRedundant(expected.startOperationId) { current ->
            if (current == expected) updated else current
        }
        return result is RecoveryStoreResult.Success &&
            result.value.redundantTransaction == updated
    }

    private fun mutateNative(
        transaction: AndroidRedundantTransaction,
        action: () -> Boolean,
    ): Boolean = mutationFence.runIfActive(
        transaction.startOperationId,
        onCancelled = { runCatching(native::stop) },
        action = action,
    )

    private fun scheduleReplacement(
        transaction: AndroidRedundantTransaction,
        failedLeaseId: String?,
    ): AndroidRedundantTransaction {
        if (!transaction.standbyDesired || transaction.retry.acquirePending) return transaction
        return transaction.copy(retry = transaction.retry.copy(
            nextRetryAtUnix = retryDeadlineUnix(REPLACEMENT_DELAY_SECONDS),
            acquirePending = true,
            acquireOperationId = operationId(),
            acquireReplaceLeaseId = failedLeaseId,
        ))
    }

    private fun currentUnixSeconds(): Long = epochNowMs().coerceAtLeast(0L) / 1_000L

    private fun deferAcquireRetryLocked(transaction: AndroidRedundantTransaction, error: Throwable) {
        if (error is BackgroundConnectionException && error.code == "operation_id_conflict" &&
            rebaseConsumedAcquireLocked(transaction)
        ) return
        val delaySeconds = ConnectionIntentErrorPolicy().retryAfterSeconds(
            (error as? BackgroundConnectionException)?.retryAfterHeader,
        )
        persistExactTransaction(transaction, transaction.copy(retry = transaction.retry.copy(
            nextRetryAtUnix = retryDeadlineUnix(delaySeconds),
        )))
    }

    private fun canonicalStandbySessionLocked(
        transaction: AndroidRedundantTransaction,
    ): BackgroundRedundantSession? {
        val response = try {
            // Role acknowledgement returns canonical membership without reissuing
            // configurations through the (possibly unavailable) old standby server.
            panel.reportRole(transaction, "standby_reconcile")
        } catch (_: Throwable) {
            return null
        }
        val active = transaction.localActiveLeaseId ?: return null
        val session = response.session
        if (session.sessionId != transaction.sessionId ||
            session.state !in setOf("allocating", "connected", "degraded") ||
            response.localActiveLeaseId != active || session.activeLeaseId != active ||
            !session.containsCurrentLease(active) || status() != transaction
        ) return null
        if (transaction.withCanonical(session).slot(active) != transaction.slot(active)) return null
        return session
    }

    private fun rebaseConsumedAcquireLocked(transaction: AndroidRedundantTransaction): Boolean {
        val session = canonicalStandbySessionLocked(transaction) ?: return false
        return discardConsumedCandidateLocked(transaction, session)
    }

    private fun discardConsumedCandidateLocked(
        transaction: AndroidRedundantTransaction,
        session: BackgroundRedundantSession,
    ): Boolean {
        val canonical = transaction.withRecoveredCanonical(session)
        // A consumed acquire ID cannot be replayed after candidate TTL cleanup.
        // Reconcile first: the lease could also have become a current member.
        val obsolete = transaction.candidateLeaseId?.takeUnless(session::containsCurrentLease)
        if (obsolete != null && !mutateNative(transaction) { native.stopSlot(obsolete) }) return false
        val cleared = canonical.copy(
            candidateLeaseId = null,
            candidateSlot = null,
            retry = canonical.retry.cancelAcquire(),
        )
        if (!persistExactTransaction(transaction, cleared)) return false
        candidateWarmupLeaseId = null
        // Normal health ticks schedule a new operation if reserve is still missing/failed.
        return true
    }

    private fun retryDeadlineUnix(delaySeconds: Long): Long {
        val currentMs = epochNowMs().coerceAtLeast(0L)
        val current = currentMs / 1_000L + if (currentMs % 1_000L == 0L) 0L else 1L
        return if (current > Long.MAX_VALUE - delaySeconds) Long.MAX_VALUE
        else current + delaySeconds
    }

    private companion object {
        const val HEALTH_FAILOVER_REASON = "primary_unhealthy"
        const val REDUNDANT_ROLE_MEMBERSHIP_CONFLICT = "session_membership_conflict"
        const val MAX_PENDING_NATIVE_SWITCH_ATTEMPTS = 3
        const val PRIMARY_READINESS_TIMEOUT_MILLIS = 30_000L
        const val REPLACEMENT_DELAY_SECONDS = 60L
        val RECOVERY_RETRY_DELAYS_SECONDS = longArrayOf(2, 5, 15, 30, 60, 300)
        private val REDUNDANT_GENERATION_CONFLICT_CODES = setOf(
            "role_generation_conflict",
            "session_membership_conflict",
        )
    }

    private fun nativeDataplaneStartedLocked(): Boolean =
        recoveryStarted || pendingPrimaryReadiness != null

    private fun saturatingAdd(value: Long, increment: Long): Long =
        if (value > Long.MAX_VALUE - increment) Long.MAX_VALUE else value + increment

    private fun publishReserveStateLocked(
        transaction: AndroidRedundantTransaction?,
        observations: List<SlotObservation>,
    ) {
        val next = when {
            transaction == null || !transaction.standbyDesired -> null
            failoverActive -> RedundantReserveState.FAILOVER
            listOfNotNull(transaction.slotALeaseId, transaction.slotBLeaseId).distinct().size < 2 ->
                RedundantReserveState.UNAVAILABLE
            observations.isEmpty() -> RedundantReserveState.WARMING
            observations.filterNot(SlotObservation::active).any {
                healthMonitor.ready(elapsedNow(), it)
            } -> RedundantReserveState.READY
            observations.filterNot(SlotObservation::active).any {
                it.health == BackendHealth.UNHEALTHY || it.hardFailure
            } -> RedundantReserveState.UNAVAILABLE
            else -> RedundantReserveState.WARMING
        }
        if (publishedReserveState == next) return
        publishedReserveState = next
        onReserveStateChanged(next)
    }

    private fun elapsedNow(): Long = monotonicMs().coerceAtLeast(0L)
}

private fun AndroidRedundantRetryState.cancelAcquire(): AndroidRedundantRetryState = copy(
    nextRetryAtUnix = null,
    acquirePending = false,
    acquireOperationId = null,
    acquireReplaceLeaseId = null,
)

private fun AndroidRedundantRetryState.hasPendingNativeSwitch(): Boolean =
    pendingNativeActiveLeaseId != null

private fun AndroidRedundantRetryState.clearPendingNativeSwitch(): AndroidRedundantRetryState = copy(
    pendingNativeSourceLeaseId = null,
    pendingNativeActiveLeaseId = null,
    pendingNativeActiveSlot = null,
    pendingNativeMembershipGeneration = null,
    pendingNativeSwitchReason = null,
    pendingNativeSwitchAttempt = 0,
)

private fun AndroidRedundantTransaction.samePendingNativeSwitch(
    other: AndroidRedundantTransaction,
): Boolean = startOperationId == other.startOperationId &&
    sessionId == other.sessionId &&
    desiredActive == other.desiredActive &&
    retry.stopState == other.retry.stopState &&
    slotALeaseId == other.slotALeaseId &&
    slotBLeaseId == other.slotBLeaseId &&
    localActiveLeaseId == other.localActiveLeaseId &&
    membershipGeneration == other.membershipGeneration &&
    retry.pendingNativeSourceLeaseId == other.retry.pendingNativeSourceLeaseId &&
    retry.pendingNativeActiveLeaseId == other.retry.pendingNativeActiveLeaseId &&
    retry.pendingNativeActiveSlot == other.retry.pendingNativeActiveSlot &&
    retry.pendingNativeMembershipGeneration == other.retry.pendingNativeMembershipGeneration &&
    retry.pendingNativeSwitchReason == other.retry.pendingNativeSwitchReason &&
    retry.pendingNativeSwitchAttempt == other.retry.pendingNativeSwitchAttempt

private fun AndroidRedundantTransaction.matchesPendingNativeMembership(
    session: BackgroundRedundantSession,
): Boolean = session.sessionId == sessionId &&
    session.membershipGeneration == retry.pendingNativeMembershipGeneration &&
    session.slotALeaseId == slotALeaseId &&
    session.slotBLeaseId == slotBLeaseId &&
    session.containsCurrentLease(retry.pendingNativeSourceLeaseId) &&
    session.containsCurrentLease(retry.pendingNativeActiveLeaseId)

private fun AndroidRedundantTransaction.slotIndex(leaseId: String?): Int? {
    if (leaseId == null) return null
    return when (leaseId) {
        slotALeaseId -> 0
        slotBLeaseId -> 1
        else -> null
    }
}

private fun AndroidRedundantTransaction.slot(leaseId: String): RedundantSlot? = when (leaseId) {
    slotALeaseId -> RedundantSlot.A
    slotBLeaseId -> RedundantSlot.B
    candidateLeaseId -> candidateSlot
    else -> null
}

private fun AndroidRedundantTransaction.leaseIdAt(index: Int): String? = when (index) {
    0 -> slotALeaseId
    1 -> slotBLeaseId
    else -> null
}

private fun AndroidRedundantTransaction.withCanonical(
    session: BackgroundRedundantSession,
): AndroidRedundantTransaction {
    val canonical = copy(
        slotALeaseId = session.slotALeaseId,
        slotBLeaseId = session.slotBLeaseId,
        standbyDesired = standbyDesired && session.standbyDesired,
        roleGeneration = session.roleGeneration,
        membershipGeneration = session.membershipGeneration,
        candidateLeaseId = candidateLeaseId.takeIf {
            it != session.slotALeaseId && it != session.slotBLeaseId
        },
        candidateSlot = candidateSlot.takeIf { candidateLeaseId != null &&
            candidateLeaseId != session.slotALeaseId && candidateLeaseId != session.slotBLeaseId },
    )
    return if (session.standbyDesired) canonical else canonical.copy(
        candidateLeaseId = null,
        candidateSlot = null,
        retry = canonical.retry.cancelAcquire(),
    )
}

/** Reconcile a remote commit response before persisting its canonical member set. */
private fun AndroidRedundantTransaction.withRecoveredCanonical(
    session: BackgroundRedundantSession,
): AndroidRedundantTransaction {
    val candidate = candidateLeaseId
    val replacement = retry.acquireReplaceLeaseId
    val remoteCommitApplied = retry.acquirePending && candidate != null &&
        session.containsCurrentLease(candidate) &&
        (replacement == null || !session.containsCurrentLease(replacement))
    val canonical = withCanonical(session)
    return if (remoteCommitApplied) {
        canonical.copy(
            candidateLeaseId = null,
            candidateSlot = null,
            retry = canonical.retry.copy(
                acquirePending = false,
                acquireOperationId = null,
                acquireReplaceLeaseId = null,
            ),
        )
    } else {
        canonical
    }
}
