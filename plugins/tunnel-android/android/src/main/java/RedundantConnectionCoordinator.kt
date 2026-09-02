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
) : RedundantVpnProcessOwner {
    private val gate = Any()
    @Volatile private var recoveryStarted = false
    @Volatile private var candidateWarmupLeaseId: String? = null
    @Volatile private var publishedReserveState: RedundantReserveState? = null
    @Volatile private var failoverActive = false
    private var pendingPrimaryReadiness: PendingPrimaryReadiness? = null
    private var primaryReadinessFailed = false
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
        val transaction = status() ?: return@synchronized false
        if (!transaction.desiredActive || transaction.retry.stopState != RedundantStopState.NONE) {
            return@synchronized false
        }
        if (recoveryStarted || pendingPrimaryReadiness != null) return@synchronized true
        primaryReadinessFailed = false
        val response = panel.recover(transaction)
        try {
            val refreshed = transaction.withRecoveredCanonical(response.session)
            val active = transaction.localActiveLeaseId.takeIf(response.session::containsCurrentLease)
                ?: response.session.activeLeaseId
                ?: return@synchronized false
            val activeConfiguration = response.configurations[active] ?: return@synchronized false
            val activeSlot = refreshed.slot(active) ?: return@synchronized false
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
            if (!mutateNative(transaction) { native.activate(active) }) return@synchronized false
            val standby = listOfNotNull(
                response.session.slotALeaseId,
                response.session.slotBLeaseId,
            ).filter { refreshed.standbyDesired && it != active }.distinct()
            for (leaseId in standby) {
                val configuration = response.configurations[leaseId] ?: continue
                refreshed.slot(leaseId)?.let { slot ->
                    mutateNative(transaction) {
                        native.start(leaseId, slot, configuration, response.healthProbes[leaseId])
                    }
                }
            }
            // The local active identity wins over a stale canonical role until its observation is sent.
            val recovered = refreshed.copy(localActiveLeaseId = active)
            val persisted = persist(recovered)
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
                onReady = {},
                onFailed = {},
                onCancelled = {},
            )
        } finally {
            response.configurations.values.forEach { it.fill(0) }
        }
    }

    override fun resume(): Boolean = synchronized(gate) {
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
            transaction.retry.stopState != RedundantStopState.NONE ||
            transaction.localActiveLeaseId != pending.activeLeaseId
        ) {
            return cancelPrimaryReadinessLocked(pending)
        }
        val observation = observations.singleOrNull { it.index == pending.activeIndex }
        if (observation?.hardFailure == true ||
            observation?.health == BackendHealth.UNHEALTHY
        ) {
            return failPrimaryReadinessLocked(pending)
        }
        if (observation != null && healthMonitor.ready(elapsedNow(), observation)) {
            pendingPrimaryReadiness = null
            return completePrimaryReadinessLocked(
                transaction,
                pending.drainPendingWork,
                pending.onReady,
            )
        }
        if (monotonicMs().coerceAtLeast(0L) >= pending.deadlineElapsedMs) {
            return failPrimaryReadinessLocked(pending)
        }
        return true
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
        if (pending.freshStart) pending.onFailed()
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
        if (!transaction.standbyDesired) return drainStandbyReleaseLocked(transaction)
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
        val transaction = status() ?: return@synchronized false
        if (!transaction.desiredActive || transaction.retry.stopState != RedundantStopState.NONE) {
            return@synchronized false
        }
        if (pendingPrimaryReadiness != null) {
            return@synchronized advancePrimaryReadinessLocked(observations)
        }
        if (primaryReadinessFailed) return@synchronized false
        val activeIndex = transaction.slotIndex(transaction.localActiveLeaseId)
            ?: return@synchronized false
        val bounded = observations.map { it.copy(active = it.index == activeIndex) }
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
        if (decision.sessionStalled && !transaction.retry.sessionStalledRecorded) {
            val recorded = transaction.copy(
                retry = transaction.retry.copy(sessionStalledRecorded = true),
            )
            if (!persist(recorded)) return@synchronized false
            onAllSlotsStalled()
        }
        publishReserveStateLocked(status() ?: transaction, bounded)
        true
    }

    override fun tick(): Boolean = synchronized(gate) {
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
        if (!transaction.standbyDesired) {
            return@synchronized drainStandbyReleaseLocked(transaction)
        }
        val observations = try {
            native.healthObservations()
        } catch (_: Throwable) {
            return@synchronized false
        }
        if (observations.isNotEmpty() && !onHealthObservations(observations)) {
            return@synchronized false
        }
        drainPendingWorkLocked(observations)
    }

    override fun onUnderlyingNetworkChanged(validated: Boolean): Boolean = synchronized(gate) {
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
        listOfNotNull(transaction.slotALeaseId, transaction.slotBLeaseId)
            .distinct()
            .all { leaseId ->
                mutateNative(transaction) {
                    runCatching { native.rebind(leaseId) }.getOrDefault(false)
                }
            }
    }

    fun slotFailed(leaseId: String, reason: String): Boolean = synchronized(gate) {
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

    override fun releaseStandby(): Boolean = synchronized(gate) {
        val transaction = status() ?: return@synchronized false
        // Fence future acquire/commit before the panel release can be retried.
        val fenced = transaction.copy(
            standbyDesired = false,
            retry = transaction.retry.cancelAcquire(),
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
                error.code in REDUNDANT_RELEASE_REBASE_CODES
            ) {
                rebaseStandbyReleaseLocked(transaction)
            } else {
                false
            }
        }
        return persist(transaction.withCanonical(session).copy(
            standbyDesired = false,
            candidateLeaseId = null,
            candidateSlot = null,
        )).also { released ->
            if (released) publishReserveStateLocked(null, emptyList())
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
        val transaction = status() ?: return@synchronized false
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
        } catch (_: Throwable) {
            return@synchronized false
        }
        try {
            val acquiredCanonical = staged.withCanonical(candidate.session)
            if (!acquiredCanonical.standbyDesired) {
                persist(acquiredCanonical)
                return@synchronized false
            }
            val replacementLeaseId = acquiredCanonical.retry.acquireReplaceLeaseId
            if (replacementLeaseId != null &&
                (!acquiredCanonical.containsCurrentLease(replacementLeaseId) ||
                    replacementLeaseId == acquiredCanonical.localActiveLeaseId)
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
        if (candidateWarmupLeaseId != candidateLeaseId) {
            val replayed = try {
                panel.acquireStandby(
                    transaction,
                    requireNotNull(transaction.retry.acquireOperationId),
                    transaction.retry.acquireReplaceLeaseId,
                )
            } catch (_: Throwable) {
                return false
            }
            try {
                if (replayed.candidateLeaseId != candidateLeaseId ||
                    replayed.candidateSlot != candidateSlot
                ) {
                    return false
                }
                val refreshed = transaction.withCanonical(replayed.session)
                if (!refreshed.standbyDesired) {
                    return persist(refreshed.copy(
                        candidateLeaseId = null,
                        candidateSlot = null,
                        retry = refreshed.retry.cancelAcquire(),
                    ))
                }
                transaction.retry.acquireReplaceLeaseId?.let { replacement ->
                    if (!native.stopSlot(replacement)) return false
                }
                if (!mutateNative(refreshed) {
                        native.start(
                            candidateLeaseId,
                            candidateSlot,
                            replayed.configuration,
                            replayed.healthProbe,
                        )
                    }
                ) return false
                candidateWarmupLeaseId = candidateLeaseId
                if (!persist(refreshed)) return false
            } finally {
                replayed.configuration.fill(0)
            }
            return true
        }
        val candidateIndex = when (candidateSlot) {
            RedundantSlot.A -> 0
            RedundantSlot.B -> 1
        }
        val snapshot = observations ?: runCatching { native.healthObservations() }.getOrNull()
        val observation = snapshot?.singleOrNull { it.index == candidateIndex } ?: return true
        if (!healthMonitor.ready(elapsedNow(), observation)) return true
        val session = try {
            panel.commitCandidate(transaction, candidateLeaseId)
        } catch (_: Throwable) {
            return false
        }
        val canonical = transaction.withCanonical(session)
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
        if (!persist(committed)) return false
        candidateWarmupLeaseId = null
        failoverActive = false
        publishReserveStateLocked(committed, listOf(observation))
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
        val scheduled = scheduleReplacement(transaction, failed)
        val updated = scheduled.copy(
            localActiveLeaseId = target,
            retry = scheduled.retry.copy(
                roleObservationPending = true,
                pendingRoleLeaseId = target,
                pendingRoleReason = reason,
            ),
        )
        if (!persist(updated)) return false
        if (!mutateNative(updated) { native.activate(target) }) return false
        failoverActive = true
        publishReserveStateLocked(updated, emptyList())
        onDiagnosticEvent(RedundantDiagnosticEvent.FAILOVER)
        // The dataplane switch is authoritative. A panel outage leaves the durable
        // observation pending and must not roll traffic back to the failed member.
        flushRoleObservationLocked()
        return true
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
        failedLeaseId: String,
    ): AndroidRedundantTransaction {
        if (!transaction.standbyDesired || transaction.retry.acquirePending) return transaction
        return transaction.copy(retry = transaction.retry.copy(
            nextRetryAtUnix = replacementDeadlineUnix(),
            acquirePending = true,
            acquireOperationId = operationId(),
            acquireReplaceLeaseId = failedLeaseId,
        ))
    }

    private fun currentUnixSeconds(): Long = epochNowMs().coerceAtLeast(0L) / 1_000L

    private fun replacementDeadlineUnix(): Long {
        val currentMs = epochNowMs().coerceAtLeast(0L)
        val current = currentMs / 1_000L + if (currentMs % 1_000L == 0L) 0L else 1L
        return if (current > Long.MAX_VALUE - REPLACEMENT_DELAY_SECONDS) Long.MAX_VALUE
        else current + REPLACEMENT_DELAY_SECONDS
    }

    private companion object {
        const val HEALTH_FAILOVER_REASON = "primary_unhealthy"
        const val PRIMARY_READINESS_TIMEOUT_MILLIS = 30_000L
        const val REPLACEMENT_DELAY_SECONDS = 60L
        private val REDUNDANT_RELEASE_REBASE_CODES = setOf(
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
