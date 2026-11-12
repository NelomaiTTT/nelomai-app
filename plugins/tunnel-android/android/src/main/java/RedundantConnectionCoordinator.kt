package ru.nelomai.tunnel

import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit

internal enum class RedundantPolicyReplacement { APPLIED, DEFERRED, FAILED }

internal class RedundantNetworkRebindProgress {
    var availabilityApplied = false
    var tunRebuilt = false
    val reboundLeases = mutableSetOf<String>()
    var retryUntilElapsedMs: Long? = null
}

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
    fun closeForStop(): Boolean = stop()
    fun isUsable(leaseId: String): Boolean
    fun replacePolicy(
        options: AndroidTunnelOptions,
        keepTunOnEarlyCancellation: Boolean = false,
        shouldCancel: () -> Boolean,
    ): RedundantPolicyReplacement = RedundantPolicyReplacement.FAILED
    fun policiesEquivalent(old: AndroidTunnelOptions, new: AndroidTunnelOptions): Boolean =
        old.copy(policyHash = null) == new.copy(policyHash = null)
    fun setNetworkAvailable(available: Boolean) = Unit
    fun setProbeSourceIpv4(sourceIpv4: String) = Unit
    fun rebind(leaseId: String): Boolean = false
    fun healthObservations(
        initialReadiness: Boolean = false,
        committedStandbyLeaseId: String? = null,
        freshStart: Boolean = false,
        startupStandbyRetryDeadlineMs: Long? = null,
    ): List<SlotObservation> = emptyList()
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

internal sealed class RedundantStopOutcome {
    object Pending : RedundantStopOutcome()
    object Completed : RedundantStopOutcome()
    data class Accepted(val acceptance: StopAcceptance, val credential: BackgroundCredential) : RedundantStopOutcome()
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
    fun stopOutcome(transaction: AndroidRedundantTransaction): RedundantStopOutcome =
        if (stop(transaction)) RedundantStopOutcome.Completed else RedundantStopOutcome.Pending
}

internal data class RedundantRecoveryResponse(
    val session: BackgroundRedundantSession,
    val configurations: Map<String, ByteArray>,
    val healthProbes: Map<String, BackgroundRedundantHealthProbe> = emptyMap(),
    val virtualAddressV4: String? = null,
)

private data class ActivatedStartupStandbyCheck(
    val proofValidThroughElapsedMs: Long,
    val deadlineElapsedMs: Long,
)

private data class PendingStandbyActivation(
    val startOperationId: String,
    val leaseId: String,
    val deadlineElapsedMs: Long,
    var activated: Boolean = false,
)

private data class PendingPrimaryReadiness(
    val activeLeaseId: String,
    val activeIndex: Int,
    val deadlineElapsedMs: Long,
    var rebindAtElapsedMs: Long,
    var standbyRebindAtElapsedMs: Long = 0L,
    var physicalRebindPending: Boolean = false,
    var standbySwitchRebindPending: Boolean = false,
    var failedSwitchAttempts: Int = 0,
    var rejectedStandbyProofValidThroughElapsedMs: Long? = null,
    var activatedStandbyCheck: ActivatedStartupStandbyCheck? = null,
    val shouldCancel: () -> Boolean,
    val freshStart: Boolean,
    val onReady: () -> Unit,
    val onFailed: () -> Unit,
    val onCancelled: () -> Unit,
) {
    fun switchAttempts(retry: AndroidRedundantRetryState): Int =
        maxOf(failedSwitchAttempts, retry.pendingNativeSwitchAttempt)
}

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
    fun closeDataplaneForStop(): Boolean = closeLocal()
    fun notifyStop() = Unit
    fun onUnderlyingNetworkChanged(available: Boolean): Boolean = false
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
    available: Boolean,
    legacyNetworkChange: () -> Unit,
): Boolean = when (recovery) {
    is RecoveryStoreResult.Failure -> false
    is RecoveryStoreResult.Success -> if (recovery.value.redundantTransaction != null) {
        owner?.onUnderlyingNetworkChanged(available) ?: false
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
    private val standbyExecutor: Executor = Executor { task ->
        Thread(task, "nelomai-standby-request").apply { isDaemon = true }.start()
    },
    private val startupNetworkUpdatePending: () -> Boolean = { false },
    private val onRestartDataplaneStopped: (AndroidRedundantTransaction) -> Unit = {},
) : RedundantVpnProcessOwner {
    private val gate = Any()
    @Volatile private var recoveryStarted = false
    @Volatile private var ownedPolicyFailed = false
    @Volatile private var candidateWarmupLeaseId: String? = null
    @Volatile private var publishedReserveState: RedundantReserveState? = null
    @Volatile private var failoverActive = false
    private var totalLossCommandEmitted = false
    private var pendingPrimaryReadiness: PendingPrimaryReadiness? = null
    private var pendingStandbyActivation: PendingStandbyActivation? = null
    private var primaryReadinessFailed = false
    private var recoveryRetryAtUnix: Long? = null
    private var recoveryRetryAttempt = 0
    @Volatile private var boundStartOperationId: String? = expectedStartOperationId
    private var standbyWorkPending = false
    private var standbyWorkEpoch = 0L

    /** Only the bounded HTTP work leaves the owner gate. Apply against the exact
     * durable snapshot; Stop, role/membership changes and owner teardown fence it. */
    private fun <T> standbyWorkLocked(
        transaction: AndroidRedundantTransaction,
        forFailover: Boolean = false,
        request: () -> T,
        dispose: (T) -> Unit = {},
        complete: (Result<T>) -> Boolean,
    ): Boolean {
        if (standbyWorkPending) return true
        standbyWorkPending = true
        val epoch = standbyWorkEpoch
        var completed: Boolean? = null
        var submitted = false
        try {
            standbyExecutor.execute {
                val response = runCatching(request)
                synchronized(gate) {
                    try {
                        completed = false
                        if (epoch == standbyWorkEpoch && !totalLossCommandEmitted &&
                            status() == transaction && transaction.desiredActive &&
                            transaction.retry.stopState == RedundantStopState.NONE
                        ) {
                            completed = runCatching {
                                mutationFence.runIfActive(transaction.startOperationId) { complete(response) }
                            }.getOrDefault(false)
                            if (completed == false && forFailover) {
                                // The synchronous caller used to observe this failure.
                                // Re-check current health before signalling total loss.
                                val current = status()
                                val activeIndex = current?.slotIndex(current.localActiveLeaseId)
                                val active = runCatching { native.healthObservations() }.getOrNull()
                                    ?.singleOrNull { it.index == activeIndex }
                                if (current != null && active != null &&
                                    healthMonitor.failed(elapsedNow(), active.copy(active = true))
                                ) emitTotalLossCommandLocked(current, "standby_commit_failed", active)
                            }
                        }
                    } finally {
                        response.getOrNull()?.let(dispose)
                        standbyWorkPending = false
                    }
                    if (submitted && completed == true && recoveryStarted && pendingPrimaryReadiness == null &&
                        transaction.candidateLeaseId != null && status()?.candidateLeaseId == null
                    ) {
                        // A reply can arrive after the last tick observed a pending
                        // probe. Recheck now under the owner gate after membership commits.
                        val observations = runCatching { native.healthObservations() }.getOrNull()
                        if (!observations.isNullOrEmpty()) onHealthObservations(observations)
                    }
                }
            }
            submitted = true
        } catch (error: java.util.concurrent.RejectedExecutionException) {
            standbyWorkPending = false
            return false
        }
        // Direct executors make the same transition deterministic in unit tests.
        // Production returns immediately; async failover rechecks on commit.
        return completed ?: true
    }

    private data class StandbyReply<T>(
        val result: Result<T>,
        val canonical: RedundantRoleResponse?,
    )

    private fun <T> requestStandby(
        transaction: AndroidRedundantTransaction,
        reconcile: (Throwable) -> Boolean,
        request: () -> T,
    ): StandbyReply<T> {
        val result = runCatching(request)
        val canonical = result.exceptionOrNull()?.takeIf(reconcile)?.let {
            runCatching { panel.reportRole(transaction, "standby_reconcile") }.getOrNull()
        }
        return StandbyReply(result, canonical)
    }

    fun status(): AndroidRedundantTransaction? = synchronized(gate) {
        ownedTransactionLocked(store.read())
    }

    private fun ownedTransactionLocked(recovery: RecoveryStoreResult<AndroidRecoveryEnvelope>): AndroidRedundantTransaction? {
        val transaction = (recovery as? RecoveryStoreResult.Success)?.value?.redundantTransaction ?: return null
        val expected = boundStartOperationId
        return if (expected == null) {
            boundStartOperationId = transaction.startOperationId
            transaction
        } else {
            transaction.takeIf { it.startOperationId == expected }
        }
    }

    override fun isRunning(): Boolean = recoveryStarted
    fun policyFailed(): Boolean = ownedPolicyFailed

    fun failOwnedPolicy(): OwnedRedundantPolicyOutcome = synchronized(gate) { failOwnedPolicyLocked(null) }

    private fun failOwnedPolicyLocked(restartingSession: AndroidRedundantTransaction?): OwnedRedundantPolicyOutcome {
        ownedPolicyFailed = true
        totalLossCommandEmitted = true
        val stopped = runCatching(native::closeForStop).getOrDefault(false)
        // Publish the end of a route replacement only after native closure and
        // before a diagnostics job can observe the owner as no longer running.
        if (stopped && restartingSession != null) recordRestartDataplaneStopped(restartingSession)
        if (stopped || restartingSession == null) recoveryStarted = false
        publishReserveStateLocked(null, emptyList())
        return OwnedRedundantPolicyOutcome.FAILED
    }

    fun applyOwnedPolicy(
        scope: OwnedRedundantPolicyScope,
        options: AndroidTunnelOptions,
        shouldCancel: () -> Boolean,
    ): OwnedRedundantPolicyOutcome = synchronized(gate) {
        applyOwnedPolicyLocked(scope, options, store.read(), shouldCancel = shouldCancel)
    }

    fun refreshLocalRoutes(
        networkAvailable: Boolean,
        networkProgress: RedundantNetworkRebindProgress = RedundantNetworkRebindProgress(),
        onDeferred: () -> Unit = {},
        shouldCancel: () -> Boolean,
    ): Boolean = synchronized(gate) {
        val recovery = store.read()
        if (recovery is RecoveryStoreResult.Failure) {
            onDeferred()
            return@synchronized false
        }
        val transaction = ownedTransactionLocked(recovery) ?: return@synchronized false
        val lease = transaction.localActiveLeaseId ?: return@synchronized false
        val template = transaction.template
        val scope = OwnedRedundantPolicyScope(transaction.sessionId, lease, template.layer,
            template.ticConnectionMode, template.routeMode, template.egressMode)
        applyOwnedPolicyLocked(
            scope, template.options, recovery, networkAvailable,
            onRouteRefreshDeferred = { publishNetwork ->
                if (publishNetwork) {
                    applyUnderlyingNetworkLocked(transaction, networkAvailable,
                        rebindSockets = networkAvailable, progress = networkProgress)
                }
                onDeferred()
            },
            shouldCancel = shouldCancel,
        ) == OwnedRedundantPolicyOutcome.APPLIED
    }

    private fun applyOwnedPolicyLocked(
        scope: OwnedRedundantPolicyScope,
        options: AndroidTunnelOptions,
        recovery: RecoveryStoreResult<AndroidRecoveryEnvelope>,
        routeRefreshNetworkAvailable: Boolean? = null,
        onRouteRefreshDeferred: ((publishNetwork: Boolean) -> Unit)? = null,
        shouldCancel: () -> Boolean,
    ): OwnedRedundantPolicyOutcome {
        val envelope = (recovery as? RecoveryStoreResult.Success)?.value
            ?: throw BackgroundConnectionException("redundant_policy_preflight_rejected")
        val expected = ownedTransactionLocked(recovery)
            ?: throw BackgroundConnectionException("redundant_policy_preflight_rejected")
        val template = expected.template
        val waitForPrimary = pendingPrimaryReadiness != null && onRouteRefreshDeferred != null
        if (!envelope.intent.desiredActive || envelope.intent.template == null || envelope.leaseTransaction != null ||
            !expected.desiredActive || expected.stopOperationId != null ||
            expected.retry.stopState != RedundantStopState.NONE ||
            (!waitForPrimary && (pendingPrimaryReadiness != null || !recoveryStarted)) ||
            totalLossCommandEmitted || scope.allowAlternate ||
            scope.sessionId != expected.sessionId || !expected.containsCurrentLease(scope.leaseId) ||
            scope.layer != template.layer || scope.ticConnectionMode != template.ticConnectionMode ||
            scope.routeMode != template.routeMode || scope.egressMode != template.egressMode ||
            shouldCancel()
        ) throw BackgroundConnectionException("redundant_policy_preflight_rejected")
        val retry = expected.retry
        // Scheduled repair/role reporting is not a native mutation. Keep it intact
        // in the exact durable snapshot used by replacement and rollback below.
        val passiveRetry = retry.copy(nextRetryAtUnix = null, roleObservationPending = false,
            pendingRoleLeaseId = null, pendingRoleReason = null, acquirePending = false,
            acquireOperationId = null, acquireReplaceLeaseId = null)
        val acquireScopeValid = !retry.acquirePending || (retry.acquireOperationId != null &&
            (retry.acquireReplaceLeaseId?.let {
                expected.containsCurrentLease(it) && it != expected.localActiveLeaseId
            } ?: (expected.slotALeaseId == null || expected.slotBLeaseId == null)))
        val candidate = expected.candidateLeaseId
        val sameCurrentWarmup = candidate != null && retry.acquirePending &&
            candidate == retry.acquireReplaceLeaseId && expected.containsCurrentLease(candidate) &&
            candidate != expected.localActiveLeaseId && expected.slot(candidate) == expected.candidateSlot &&
            candidateWarmupLeaseId == candidate
        if (waitForPrimary || standbyWorkPending || passiveRetry != AndroidRedundantRetryState() || !acquireScopeValid ||
            (retry.roleObservationPending && (retry.pendingRoleLeaseId != expected.localActiveLeaseId ||
                retry.pendingRoleReason == null)) ||
            (candidate != null && !sameCurrentWarmup) ||
            (candidateWarmupLeaseId != null && !sameCurrentWarmup)
        ) {
            if (onRouteRefreshDeferred == null) throw BackgroundConnectionException("redundant_policy_busy")
            onRouteRefreshDeferred(true)
            return OwnedRedundantPolicyOutcome.FAILED
        }
        if (listOfNotNull(expected.slotALeaseId, expected.slotBLeaseId).any { !native.isUsable(it) }) {
            throw BackgroundConnectionException("redundant_policy_preflight_rejected")
        }
        var routeRefreshCancelled = false
        fun cancelled(): Boolean {
            if (routeRefreshCancelled) return true
            val cancelled = shouldCancel() || !mutationFence.runIfActive(expected.startOperationId) { true } ||
                (store.read() as? RecoveryStoreResult.Success)?.value != envelope
            // Once native cleanup observes cancellation it may close the new TUN.
            if (routeRefreshNetworkAvailable != null) routeRefreshCancelled = cancelled
            return cancelled
        }
        fun replace(policy: AndroidTunnelOptions, keepTunOnEarlyCancellation: Boolean = false) = runCatching {
            native.replacePolicy(policy, keepTunOnEarlyCancellation, ::cancelled)
        }.getOrDefault(RedundantPolicyReplacement.FAILED)
        if (routeRefreshNetworkAvailable != null) {
            if (cancelled()) {
                onRouteRefreshDeferred?.invoke(false)
                return OwnedRedundantPolicyOutcome.FAILED
            }
            native.setNetworkAvailable(routeRefreshNetworkAvailable)
            // The policy and both leases are unchanged. Rebuild only the TUN and
            // let establishTun install the current physical routes.
            val replacement = replace(options, keepTunOnEarlyCancellation = true)
            if (replacement == RedundantPolicyReplacement.DEFERRED) {
                onRouteRefreshDeferred?.invoke(false)
                return OwnedRedundantPolicyOutcome.FAILED
            }
            if (replacement == RedundantPolicyReplacement.APPLIED && !cancelled()) {
                healthMonitor.onUnderlyingNetworkChanged(elapsedNow(), routeRefreshNetworkAvailable)
                return OwnedRedundantPolicyOutcome.APPLIED
            }
            return failOwnedPolicyLocked(expected)
        }
        val updated = expected.copy(template = template.copy(options = options))
        fun persistOptions(): Boolean {
            if (cancelled()) return false
            val result = store.updateRedundant(expected.startOperationId, envelope,
                synchronizeIntentOptions = true) { current ->
                if (current == expected) updated else current
            }
            return result is RecoveryStoreResult.Success && result.value.redundantTransaction == updated
        }
        if (native.policiesEquivalent(template.options, options)) {
            if (!persistOptions()) throw BackgroundConnectionException("redundant_policy_preflight_rejected")
            return OwnedRedundantPolicyOutcome.UNCHANGED
        }
        val applied = replace(options) == RedundantPolicyReplacement.APPLIED
        if (cancelled()) {
            return failOwnedPolicyLocked(null)
        }
        if (applied && persistOptions()) {
            if (shouldCancel()) {
                return failOwnedPolicyLocked(null)
            }
            return OwnedRedundantPolicyOutcome.APPLIED
        }
        // A durable Stop or any ownership change forbids resurrecting the old TUN.
        if (!cancelled() && replace(template.options) == RedundantPolicyReplacement.APPLIED && !cancelled()) {
            return OwnedRedundantPolicyOutcome.ROLLED_BACK
        }
        return failOwnedPolicyLocked(null)
    }

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
        ownerCurrent: () -> Boolean = { true },
    ): Boolean = synchronized(gate) {
        if (totalLossCommandEmitted || !ownerCurrent()) return@synchronized false
        val expected = boundStartOperationId
        if (expected != null && expected != transaction.startOperationId) return@synchronized false
        boundStartOperationId = transaction.startOperationId
        val active = transaction.localActiveLeaseId ?: return@synchronized false
        val activeConfiguration = configurations[active] ?: return@synchronized false
        if (!mutationFence.runIfActive(transaction.startOperationId) {
                when (val saved = store.beginRedundant(transaction, ownerCurrent)) {
                    is RecoveryStoreResult.Success -> true
                    is RecoveryStoreResult.Failure -> {
                        // Do not collapse a durable admission refusal into an
                        // unexplained native failure in the diagnostic report.
                        runCatching { TunnelLog.warning("redundant.start_rejected", saved.code) }
                        false
                    }
                }
            }
        ) return@synchronized false
        primaryReadinessFailed = false
        if (shouldCancel()) {
            val retired = !ownerCurrent() && store.cancelRedundantIntentAndDeferStop(
                    transaction.stopOperationId ?: operationId(),
                    transaction.startOperationId,
                ) is RecoveryStoreResult.Success
            if (retired) mutationFence.cancel(transaction.startOperationId) else fenceRevoke()
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
    override fun recover(): Boolean = recoverUsing(panel::recover)

    /** The first Start already returned these configs; never persist them or replay it twice. */
    fun startPrepared(
        expected: AndroidRedundantTransaction,
        response: RedundantRecoveryResponse,
    ): Boolean = synchronized(gate) {
        try {
            if (status() != expected) return@synchronized false
            recoverUsing(fetch = { response }, freshStart = true)
        } finally {
            response.configurations.values.forEach { it.fill(0) }
        }
    }

    private fun recoverUsing(
        fetch: (AndroidRedundantTransaction) -> RedundantRecoveryResponse,
        freshStart: Boolean = false,
    ): Boolean = synchronized(gate) {
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
            fetch(transaction)
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
                var refreshed = transaction.withRecoveredCanonical(response.session)
                if (refreshed.retry.pendingNativeRequiresProbe) {
                    // The live check cannot survive native process death. Rebuild
                    // the source and reserve through ordinary startup readiness.
                    refreshed = refreshed.copy(retry = refreshed.retry.clearPendingNativeSwitch())
                }
                // Startup proof is process-local. Rebuild the source and reserve
                // and let the readiness tick resolve their durable switch.
                val replayStartupSwitch = refreshed.retry.pendingNativeSwitchReason == STARTUP_SWITCH_REASON
                val replayTarget = refreshed.retry.pendingNativeActiveLeaseId?.takeUnless { replayStartupSwitch }
                val active = replayTarget ?: transaction.localActiveLeaseId
                    .takeIf(response.session::containsCurrentLease)
                    ?: response.session.activeLeaseId ?: return@synchronized false
                val activeConfiguration = response.configurations[active] ?: return@synchronized false
                val activeSlot = refreshed.slot(active) ?: return@synchronized false
                if (replayTarget != null && refreshed != transaction &&
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
                if (replayTarget != null) {
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
                val committed = if (replayTarget != null) {
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
                val persisted = if (replayTarget != null) {
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
                    freshStart = freshStart || replayStartupSwitch,
                    drainPendingWork = true,
                    onReady = {},
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
        if (healthProbe == null && transaction.retry.pendingNativeSwitchReason != STARTUP_SWITCH_REASON) {
            return completePrimaryReadinessLocked(
                transaction,
                drainPendingWork,
                onReady,
            )
        }
        // With live probes, publish readiness and release the owner gate first.
        // Pending role/standby work is durable and resumes on the following tick.
        val startedAt = monotonicMs().coerceAtLeast(0L)
        pendingPrimaryReadiness = PendingPrimaryReadiness(
            activeLeaseId = activeLeaseId,
            activeIndex = if (activeSlot == RedundantSlot.A) 0 else 1,
            deadlineElapsedMs = saturatingAdd(
                startedAt,
                PRIMARY_READINESS_TIMEOUT_MILLIS,
            ),
            rebindAtElapsedMs = saturatingAdd(startedAt, INITIAL_HANDSHAKE_REBIND_MILLIS),
            shouldCancel = shouldCancel,
            freshStart = freshStart,
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
        var transaction = status() ?: return failPrimaryReadinessLocked(pending)
        if (!transaction.desiredActive ||
            transaction.retry.stopState != RedundantStopState.NONE
        ) {
            return cancelPrimaryReadinessLocked(pending)
        }
        if (startupNetworkUpdatePending()) return waitForStartupNetworkLocked(pending)
        val pendingSwitch = transaction.retry.hasPendingNativeSwitch()
        val switchAttemptAvailable = pendingSwitch &&
            pending.switchAttempts(transaction.retry) < MAX_PENDING_NATIVE_SWITCH_ATTEMPTS
        if (!pendingSwitch && transaction.localActiveLeaseId != pending.activeLeaseId) {
            return cancelPrimaryReadinessLocked(pending)
        }
        val now = elapsedNow()
        if (now > pending.deadlineElapsedMs ||
            (now == pending.deadlineElapsedMs && (!healthMonitor.networkAvailable || pendingSwitch))
        ) {
            return failPrimaryReadinessLocked(pending)
        }
        if (!healthMonitor.networkAvailable) return true
        // While its sockets are waiting for a network retry, the primary's
        // previous probe results cannot establish success or terminal failure.
        val observation = observations.singleOrNull { it.index == pending.activeIndex && !pending.physicalRebindPending }
        val switchTarget = transaction.slotIndex(transaction.retry.pendingNativeActiveLeaseId)
            ?.let { index -> observations.singleOrNull { it.index == index } }
        // Native activation can succeed before the durable switch is committed.
        val canRestorePrimary = switchTarget?.active == true &&
            (!switchAttemptAvailable || healthMonitor.failed(now, switchTarget))
        val canKeepPrimary = observation?.hasFreshSuccessfulProbe(now) == true && (!pendingSwitch || (
            (observation.active || canRestorePrimary) &&
                transaction.localActiveLeaseId == pending.activeLeaseId &&
                transaction.retry.pendingNativeSourceLeaseId == pending.activeLeaseId
        ))
        if (canKeepPrimary && observation != null && healthMonitor.primaryReady(now, observation)) {
            if (pendingSwitch && !observation.active) {
                if (startupNetworkUpdatePending()) return waitForStartupNetworkLocked(pending)
                if (!mutateNative(transaction) {
                        runCatching { native.activate(pending.activeLeaseId) }.getOrDefault(false)
                    }
                ) return true
            }
            val retry = if (pendingSwitch) transaction.retry.clearPendingNativeSwitch() else transaction.retry
            val ready = transaction.copy(retry = retry.copy(
                roleObservationPending = true,
                pendingRoleLeaseId = transaction.localActiveLeaseId,
                pendingRoleReason = "primary_ready",
            ))
            if (pendingSwitch) {
                // Keep the journal until the exact transaction can be updated.
                if (!mutationFence.runIfActive(transaction.startOperationId) {
                        persistExactTransaction(transaction, ready) {
                            val commitNow = elapsedNow()
                            commitNow < pending.deadlineElapsedMs &&
                                !startupNetworkUpdatePending() &&
                                observation.hasFreshSuccessfulProbe(commitNow)
                        }
                    }
                ) {
                    if (elapsedNow() >= pending.deadlineElapsedMs) return failPrimaryReadinessLocked(pending)
                    return true
                }
            } else if (!persist(ready) {
                    val commitNow = elapsedNow()
                    commitNow <= pending.deadlineElapsedMs && observation.hasFreshSuccessfulProbe(commitNow) &&
                        !startupNetworkUpdatePending()
                }
            ) {
                if (startupNetworkUpdatePending() || !observation.hasFreshSuccessfulProbe(elapsedNow())) {
                    return waitForStartupNetworkLocked(pending)
                }
                return failPrimaryReadinessLocked(pending)
            }
            pendingPrimaryReadiness = null
            return completePrimaryReadinessLocked(
                ready,
                drainPendingWork = false,
                pending.onReady,
            )
        }
        if (switchAttemptAvailable && !pending.standbySwitchRebindPending && standbyReadyForStart(switchTarget, now)) {
            if (!drainPendingNativeSwitchLocked(transaction, startupStandby = switchTarget)) {
                if (startupNetworkUpdatePending()) return waitForStartupNetworkLocked(pending)
                if (elapsedNow() >= pending.deadlineElapsedMs) return failPrimaryReadinessLocked(pending)
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
                drainPendingWork = false,
                pending.onReady,
            )
        }
        // The primary must not depend on reserve HTTP work. Reuse the existing
        // async acquire/commit path while it is still waiting for its handshake.
        if (!pendingSwitch && elapsedNow() < pending.deadlineElapsedMs) {
            advanceStartupStandbyLocked(transaction, observations)
            transaction = status() ?: return failPrimaryReadinessLocked(pending)
            if (!transaction.desiredActive || transaction.retry.stopState != RedundantStopState.NONE ||
                transaction.localActiveLeaseId != pending.activeLeaseId
            ) return cancelPrimaryReadinessLocked(pending)
        }
        if (startupNetworkUpdatePending()) return waitForStartupNetworkLocked(pending)
        val primaryNeedsRebind = transaction.template.layer == "stray" &&
            observation.needsStartupRebind(retryRebindFailure = pendingSwitch)
        val standbyIndex = 1 - pending.activeIndex
        val standbyObservation = observations.singleOrNull { it.index == standbyIndex }
        val standbyStartedAt = standbyObservation?.stableSinceMs
        val canUseStandby = !pendingSwitch || switchAttemptAvailable
        // The reserve has its own socket and may still be an uncommitted candidate.
        // Give it the same bounded first-handshake recovery as the primary, from
        // its own start time. Do not reset a working reserve's proofs or deadline.
        if (canUseStandby && transaction.template.layer == "stray" && transaction.standbyDesired &&
            standbyObservation.needsStartupRebind(retryRebindFailure = pendingSwitch) &&
            standbyStartedAt != null
        ) {
            val leaseId = transaction.candidateLeaseId?.takeIf {
                it == candidateWarmupLeaseId &&
                    transaction.candidateSlot == (if (standbyIndex == 0) RedundantSlot.A else RedundantSlot.B)
            } ?: transaction.leaseIdAt(standbyIndex)
            val rebindNow = elapsedNow()
            if (leaseId != null && rebindNow < pending.deadlineElapsedMs &&
                rebindNow >= saturatingAdd(standbyStartedAt, INITIAL_HANDSHAKE_REBIND_MILLIS) &&
                rebindNow >= pending.standbyRebindAtElapsedMs && healthMonitor.networkReady(rebindNow) &&
                !startupNetworkUpdatePending()
            ) {
                pending.standbyRebindAtElapsedMs = saturatingAdd(rebindNow, INITIAL_HANDSHAKE_REBIND_MILLIS)
                val rebound = mutateNative(transaction) {
                    runCatching { native.rebind(leaseId) }.getOrDefault(false)
                }
                if (rebound && leaseId == transaction.retry.pendingNativeActiveLeaseId) {
                    pending.standbySwitchRebindPending = false
                }
                return true // Rebind invalidates this snapshot's health evidence.
            }
        }
        if (!pendingSwitch) {
            val readyStandby = transaction.standbyDesired && transaction.leaseIdAt(standbyIndex) != null &&
                standbyReadyForStart(standbyObservation)
            if (observation?.hardFailure == true ||
                observation?.health == BackendHealth.UNHEALTHY ||
                (observation != null && healthMonitor.failed(elapsedNow(), observation) &&
                    (!primaryNeedsRebind || readyStandby))
            ) {
                return advancePrimaryReadinessThroughStandbyLocked(pending, transaction, observations)
            }
            // Before the first handshake, staged DNS packets cannot corroborate
            // every failed probe with outbound growth: handshake retries are slower
            // than probes. A fresh start can use an independently proven reserve;
            // this is not failure detection for an already established connection.
            if (pending.freshStart && observation?.handshakeFresh == false &&
                observation.probeFailed && readyStandby
            ) {
                return advancePrimaryReadinessThroughStandbyLocked(pending, transaction, observations)
            }
            if (elapsedNow() >= pending.deadlineElapsedMs) {
                return advancePrimaryReadinessThroughStandbyLocked(pending, transaction, observations)
            }
        }
        // A replacement UDP flow can also remain silent. Retry protected sockets
        // at the same bounded interval within the original startup deadline.
        // DNS failure after a handshake is not a reason to change the socket.
        // Do not discard an in-flight post-commit check of a warmed reserve
        // merely to retry the primary socket. Its check budget and the overall
        // startup deadline still bound this wait; a failed check permits rebind.
        val checkingInitialReserve = canUseStandby && (pendingSwitch || pending.freshStart) &&
            transaction.leaseIdAt(standbyIndex) != null &&
            standbyObservation?.health == BackendHealth.READY &&
            standbyObservation.standbyProbeState == StandbyProbeState.PENDING
        val rebindNow = elapsedNow()
        if (primaryNeedsRebind && !checkingInitialReserve &&
            rebindNow < pending.deadlineElapsedMs && rebindNow >= pending.rebindAtElapsedMs &&
            healthMonitor.networkReady(rebindNow) && !startupNetworkUpdatePending()
        ) {
            pending.rebindAtElapsedMs = saturatingAdd(rebindNow, INITIAL_HANDSHAKE_REBIND_MILLIS)
            mutateNative(transaction) { runCatching { native.rebind(pending.activeLeaseId) }.getOrDefault(false) }
        }
        return true
    }

    private fun SlotObservation?.needsStartupRebind(retryRebindFailure: Boolean): Boolean =
        this != null && ((retryRebindFailure && rebindFailureRetryable) ||
            (!handshakeFresh && !hardFailure && health != BackendHealth.UNHEALTHY))

    private fun advanceStartupStandbyLocked(
        transaction: AndroidRedundantTransaction,
        observations: List<SlotObservation>,
    ) {
        if (!transaction.standbyDesired ||
            (transaction.slotALeaseId != null && transaction.slotBLeaseId != null)
        ) return
        var current = transaction
        if (!current.retry.acquirePending && current.candidateLeaseId == null &&
            (current.slotALeaseId == null || current.slotBLeaseId == null)
        ) {
            val staged = scheduleReplacement(current, null)
            if (!persistExactTransaction(current, staged)) return
            current = staged
        }
        if (!current.retry.acquirePending) return
        if (current.candidateLeaseId != null) {
            advanceCandidateLocked(current, observations)
        } else if (current.retry.nextRetryAtUnix?.let { currentUnixSeconds() < it } != true) {
            acquireAndCommitStandby(requireNotNull(current.retry.acquireOperationId))
        }
    }

    private fun advancePrimaryReadinessThroughStandbyLocked(
        pending: PendingPrimaryReadiness,
        transaction: AndroidRedundantTransaction,
        observations: List<SlotObservation>,
    ): Boolean {
        val now = elapsedNow()
        if (!transaction.standbyDesired || now > pending.deadlineElapsedMs) {
            return failPrimaryReadinessLocked(pending)
        }
        val standbyLeaseId = listOfNotNull(
            transaction.slotALeaseId,
            transaction.slotBLeaseId,
        ).firstOrNull { it != pending.activeLeaseId } ?: return if (
            transaction.retry.acquirePending && now < pending.deadlineElapsedMs
        ) true else failPrimaryReadinessLocked(pending)
        val standbyIndex = transaction.slotIndex(standbyLeaseId)
            ?: return failPrimaryReadinessLocked(pending)
        val standby = observations.singleOrNull { it.index == standbyIndex }
        // READY can predate the current failure episode. As in normal failover,
        // wait for its reserve probe and never activate an expired/failed check.
        if (!standbyReadyForStart(standby, now)) {
            val standbyFailed = standby?.hardFailure == true ||
                standby?.health == BackendHealth.UNHEALTHY ||
                standby?.standbyProbeState == StandbyProbeState.FAILED
            if (standby != null && !standbyFailed && now < pending.deadlineElapsedMs) {
                return true
            }
            return failPrimaryReadinessLocked(pending)
        }
        pending.standbySwitchRebindPending = false
        if (!switchActiveLocked(
                transaction,
                target = standbyLeaseId,
                failed = pending.activeLeaseId,
                reason = STARTUP_SWITCH_REASON,
                startupStandby = standby,
            )
        ) {
            if (startupNetworkUpdatePending()) return waitForStartupNetworkLocked(pending)
            val current = status()
            val afterSwitch = elapsedNow()
            return when {
                afterSwitch >= pending.deadlineElapsedMs -> failPrimaryReadinessLocked(pending)
                current?.retry?.hasPendingNativeSwitch() == true -> false
                current == transaction && !standbyReadyForStart(standby, afterSwitch) -> true
                else -> failPrimaryReadinessLocked(pending)
            }
        }
        val switched = status()?.takeIf { it.localActiveLeaseId == standbyLeaseId }
            ?: return failPrimaryReadinessLocked(pending)
        pendingPrimaryReadiness = null
        return completePrimaryReadinessLocked(
            switched,
            drainPendingWork = false,
            pending.onReady,
        )
    }

    private fun standbyReadyForStart(standby: SlotObservation?, now: Long = elapsedNow()): Boolean =
        standby != null &&
            standby.hasFreshSuccessfulProbe(now) &&
            (standby.standbyProbeState == StandbyProbeState.NOT_REQUIRED ||
                standby.standbyProbeState == StandbyProbeState.SUCCEEDED) &&
            standby.standbyCheckDeadlineElapsedMs?.let { now < it } != false &&
            healthMonitor.ready(now, standby)

    private fun startupSwitchHasProof(
        startup: PendingPrimaryReadiness,
        standby: SlotObservation?,
        firstActivation: Boolean,
    ): Boolean {
        val now = elapsedNow()
        val deadline = startup.deadlineElapsedMs
        val validThrough = standby?.successfulProbeValidThroughElapsedMs ?: return false
        val rejectedProof = startup.rejectedStandbyProofValidThroughElapsedMs
        val activatedCheck = startup.activatedStandbyCheck
        val withinActivatedCheck = activatedCheck == null ||
            validThrough > activatedCheck.proofValidThroughElapsedMs ||
            now < activatedCheck.deadlineElapsedMs
        return (now < deadline || (firstActivation && now == deadline)) &&
            withinActivatedCheck && (rejectedProof == null || validThrough > rejectedProof) &&
            !startup.standbySwitchRebindPending && standbyReadyForStart(standby, now) &&
            !startupNetworkUpdatePending()
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
        onRecoveryReadiness(true)
        return !drainPendingWork || drainPendingWorkLocked()
    }

    private fun failPrimaryReadinessLocked(pending: PendingPrimaryReadiness): Boolean {
        if (pendingPrimaryReadiness !== pending) return false
        pendingPrimaryReadiness = null
        recoveryStarted = false
        primaryReadinessFailed = true
        standbyWorkEpoch++
        runCatching(native::stop)
        publishReserveStateLocked(null, emptyList())
        pending.onFailed()
        return false
    }

    private fun cancelPrimaryReadinessLocked(pending: PendingPrimaryReadiness): Boolean {
        if (pendingPrimaryReadiness !== pending) return false
        pendingPrimaryReadiness = null
        recoveryStarted = false
        primaryReadinessFailed = true
        standbyWorkEpoch++
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
        var transaction = status() ?: return@synchronized false
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
            if (!persist(recovered)) return@synchronized false
            transaction = recovered
            failoverActive = false
            onDiagnosticEvent(RedundantDiagnosticEvent.RECOVERY)
            publishReserveStateLocked(recovered, bounded)
            // Use this same fresh snapshot for failover. A later tick may be
            // beyond the bounded standby-check window. The replacement fence
            // has now been durably removed, so activation is admitted below.
        }
        val decision = healthMonitor.evaluateHealth(elapsedNow(), bounded)
        val switchIndex = decision.switchTo
        if (switchIndex != null) {
            val standby = bounded.single { it.index == switchIndex }
            val checkDeadline = standby.standbyCheckDeadlineElapsedMs
            if (checkDeadline != null && !standbyHasFailoverProof(standby, checkDeadline)) {
                return@synchronized true
            }
            val candidate = transaction.candidateLeaseId
            val candidateIndex = transaction.candidateSlot?.let {
                if (it == RedundantSlot.A) 0 else 1
            }
            if (candidate != null && switchIndex == candidateIndex) {
                // Native already replaced the old member at this index. Commit its new
                // identity before switching; never activate the stale canonical lease.
                val advanced = advanceCandidateLocked(transaction, bounded, forFailover = true)
                val current = status() ?: return@synchronized false
                // A successful advance may only have restarted a staged candidate.
                // Wait for its new probe within a live standby-check window.
                if (current.candidateLeaseId != null &&
                    (standbyWorkPending || (checkDeadline != null &&
                        (advanced || !standbyHasFailoverProof(standby, checkDeadline))))
                ) return@synchronized true
                if (!advanced || current.candidateLeaseId != null ||
                    current.leaseIdAt(switchIndex) != candidate
                ) {
                    emitTotalLossCommandLocked(current, "standby_commit_failed")
                    return@synchronized false
                }
                return@synchronized switchActiveLocked(
                    current, candidate, requireNotNull(current.localActiveLeaseId), HEALTH_FAILOVER_REASON,
                    healthStandby = standby,
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
                healthStandby = standby,
            )
        }
        if (decision.sessionStalled) {
            emitTotalLossCommandLocked(transaction, "health_check", bounded.single { it.active },
                bounded.singleOrNull { !it.active })
            return@synchronized false
        }
        if (transaction.standbyDesired && !transaction.retry.acquirePending &&
            transaction.candidateLeaseId == null
        ) {
            val inactive = listOfNotNull(transaction.slotALeaseId, transaction.slotBLeaseId)
                .firstOrNull { it != transaction.localActiveLeaseId }
            val primaryReady = bounded.singleOrNull { it.active }?.let {
                if (inactive == null) healthMonitor.primaryReady(elapsedNow(), it)
                else healthMonitor.ready(elapsedNow(), it)
            } == true
            val observation = bounded.singleOrNull { it.index == transaction.slotIndex(inactive) }
            if (primaryReady && (inactive == null || observation == null ||
                    healthMonitor.failed(elapsedNow(), observation))) {
                if (!persist(scheduleReplacement(transaction, inactive))) return@synchronized false
            }
        }
        publishReserveStateLocked(status() ?: transaction, bounded)
        true
    }

    fun tickWaitingForNetworkUpdate(): Boolean = synchronized(gate) {
        if (totalLossCommandEmitted) return@synchronized false
        val pending = pendingPrimaryReadiness ?: return@synchronized false
        waitForStartupNetworkLocked(pending)
    }

    private fun waitForStartupNetworkLocked(pending: PendingPrimaryReadiness): Boolean {
        if (pending.shouldCancel()) return cancelPrimaryReadinessLocked(pending)
        if (elapsedNow() >= pending.deadlineElapsedMs) return failPrimaryReadinessLocked(pending)
        return true
    }

    override fun tick(): Boolean = synchronized(gate) {
        if (totalLossCommandEmitted) return@synchronized false
        val pending = pendingPrimaryReadiness
        if (!recoveryStarted && startupNetworkUpdatePending()) {
            return@synchronized pending?.let(::waitForStartupNetworkLocked) ?: false
        }
        if (pending != null) {
            val transaction = status()?.takeIf { it.standbyDesired }
            val committedStandby = transaction?.leaseIdAt(1 - pending.activeIndex)
            val switchPending = committedStandby != null &&
                transaction.retry.pendingNativeActiveLeaseId == committedStandby
            if (switchPending && elapsedNow() >= pending.deadlineElapsedMs) {
                return@synchronized advancePrimaryReadinessLocked(emptyList())
            }
            val retryDeadline = pending.deadlineElapsedMs.takeIf {
                switchPending && !pending.standbySwitchRebindPending && transaction != null &&
                    pending.switchAttempts(transaction.retry) < MAX_PENDING_NATIVE_SWITCH_ATTEMPTS
            }
            val observations = try {
                native.healthObservations(
                    initialReadiness = true,
                    committedStandbyLeaseId = committedStandby,
                    freshStart = pending.freshStart,
                    startupStandbyRetryDeadlineMs = retryDeadline,
                )
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
            if (transaction.retry.pendingNativeSwitchReason == STARTUP_SWITCH_REASON ||
                (transaction.retry.pendingNativeRequiresProbe && pendingStandbyActivation == null)
            ) return@synchronized recover()
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

    override fun onUnderlyingNetworkChanged(available: Boolean): Boolean =
        onUnderlyingNetworkChanged(available) { true }

    fun onPhysicalNetworkUnavailable(startOperationId: String, shouldApply: () -> Boolean): Boolean =
        synchronized(gate) {
            if (boundStartOperationId != startOperationId || totalLossCommandEmitted || !shouldApply()) {
                return@synchronized false
            }
            mutationFence.runIfActive(startOperationId) {
                publishNetworkAvailabilityLocked(false)
                true
            }
        }

    fun onUnderlyingNetworkChanged(
        available: Boolean,
        progress: RedundantNetworkRebindProgress? = null,
        onRebindDeferred: () -> Unit = {},
        shouldApply: (recoveryReadable: Boolean) -> Boolean,
    ): Boolean = synchronized(gate) {
        if (totalLossCommandEmitted) return@synchronized false
        val recovery = store.read()
        val transaction = ownedTransactionLocked(recovery)
        if (!shouldApply(recovery is RecoveryStoreResult.Success) || transaction == null || !transaction.desiredActive ||
            transaction.retry.stopState != RedundantStopState.NONE
        ) {
            return@synchronized false
        }
        val rebound = applyUnderlyingNetworkLocked(transaction, available, rebindSockets = true, progress = progress)
        if (!rebound && progress != null && canRetryNetworkRebindLocked(progress) &&
            mutationFence.runIfActive(transaction.startOperationId) { true }
        ) {
            onRebindDeferred()
        }
        rebound
    }

    private fun publishNetworkAvailabilityLocked(available: Boolean) {
        healthMonitor.onUnderlyingNetworkChanged(elapsedNow(), available)
        native.setNetworkAvailable(available)
        pendingPrimaryReadiness?.standbySwitchRebindPending = true
    }

    private fun canRetryNetworkRebindLocked(progress: RedundantNetworkRebindProgress): Boolean {
        if (primaryReadinessFailed) return false
        val now = elapsedNow()
        val retryUntil = progress.retryUntilElapsedMs ?: (
            pendingPrimaryReadiness?.deadlineElapsedMs ?: saturatingAdd(now, INITIAL_HANDSHAKE_REBIND_MILLIS)
        ).also { progress.retryUntilElapsedMs = it }
        return now < retryUntil
    }

    private fun applyUnderlyingNetworkLocked(
        transaction: AndroidRedundantTransaction,
        available: Boolean,
        rebindSockets: Boolean,
        progress: RedundantNetworkRebindProgress? = null,
    ): Boolean {
        if (progress?.availabilityApplied != true) {
            if (!mutateNative(transaction) {
                    publishNetworkAvailabilityLocked(available)
                    true
                }
            ) return false
            progress?.availabilityApplied = true
        }
        if (!rebindSockets) return true
        val readiness = pendingPrimaryReadiness
        if (readiness != null && elapsedNow() >= readiness.deadlineElapsedMs) {
            return failPrimaryReadinessLocked(readiness)
        }
        if (progress != null && !canRetryNetworkRebindLocked(progress)) return false
        val retryUntil = progress?.retryUntilElapsedMs
        var allRebound = true
        val runningCandidate = transaction.candidateLeaseId?.takeIf { it == candidateWarmupLeaseId }
        val members = listOfNotNull(transaction.slotALeaseId, transaction.slotBLeaseId)
            .filterNot { runningCandidate != null && transaction.slot(it) == transaction.candidateSlot }
        for (leaseId in (members + listOfNotNull(runningCandidate)).distinct()) {
            if (progress?.reboundLeases?.contains(leaseId) == true) continue
            // Preparing one socket may leave no time to begin the next one.
            val now = elapsedNow()
            if (readiness != null && now >= readiness.deadlineElapsedMs) {
                // A skipped member still carries proof from the old network.
                return failPrimaryReadinessLocked(readiness)
            }
            if (retryUntil != null && now >= retryUntil) return false
            val rebound = mutateNative(transaction) {
                runCatching { native.rebind(leaseId) }.getOrDefault(false)
            }
            if (rebound) progress?.reboundLeases?.add(leaseId) else allRebound = false
            if (available && rebound && leaseId == transaction.retry.pendingNativeActiveLeaseId) {
                readiness?.standbySwitchRebindPending = false
            }
            if (readiness?.activeLeaseId == leaseId) {
                if (rebound) {
                    readiness.physicalRebindPending = false
                    readiness.rebindAtElapsedMs = saturatingAdd(elapsedNow(), INITIAL_HANDSHAKE_REBIND_MILLIS)
                } else if (progress != null) {
                    readiness.physicalRebindPending = true
                }
            }
        }
        return allRebound
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
        emitTotalLossCommandLocked(transaction, "active_slot_failed")
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
            val canonical = transaction.withRecoveredCanonical(response.session)
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
                emitTotalLossCommandLocked(transaction, "role_membership_changed")
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
        standbyWorkLocked(
            staged,
            request = {
                requestStandby(staged, { it is BackgroundConnectionException && it.code == "operation_id_conflict" }) {
                    panel.acquireStandby(staged, requireNotNull(staged.retry.acquireOperationId),
                        staged.retry.acquireReplaceLeaseId)
                }
            },
            dispose = { it.result.getOrNull()?.configuration?.fill(0) },
        ) { result ->
            val reply = result.getOrElse {
                deferAcquireRetryLocked(staged, it)
                return@standbyWorkLocked false
            }
            val candidate = reply.result.getOrElse {
                deferAcquireRetryLocked(staged, it, reply.canonical)
                return@standbyWorkLocked false
            }
            val candidateTargetSlot = replacement?.let(staged::slot) ?: when {
                staged.slotALeaseId == null -> RedundantSlot.A
                staged.slotBLeaseId == null -> RedundantSlot.B
                else -> null
            }
            if (candidate.candidateSlot != candidateTargetSlot) return@standbyWorkLocked false
            val acquiredCanonical = staged.withCanonical(candidate.session)
            if (!acquiredCanonical.standbyDesired) {
                persist(acquiredCanonical)
                return@standbyWorkLocked false
            }
            val replacementLeaseId = acquiredCanonical.retry.acquireReplaceLeaseId
            if (replacementLeaseId != null &&
                (!acquiredCanonical.containsCurrentLease(replacementLeaseId) ||
                    replacementLeaseId == acquiredCanonical.localActiveLeaseId ||
                    acquiredCanonical.slot(replacementLeaseId) != candidate.candidateSlot)
            ) {
                return@standbyWorkLocked false
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
                return@standbyWorkLocked false
            }
            val candidateStaged = acquiredCanonical.copy(
                candidateLeaseId = candidate.candidateLeaseId,
                candidateSlot = candidate.candidateSlot,
            )
            if (!persist(candidateStaged)) return@standbyWorkLocked false
            if (replacementLeaseId != null && !native.stopSlot(replacementLeaseId)) {
                return@standbyWorkLocked false
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
                return@standbyWorkLocked false
            }
            candidateWarmupLeaseId = candidate.candidateLeaseId
            true
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
        val candidateObservation = observations?.singleOrNull { it.index == candidateIndex }
        val freshForFailover = forFailover && candidateObservation?.standbyCheckDeadlineElapsedMs?.let {
            standbyHasFailoverProof(candidateObservation, it)
        } == true
        // Reusing a CURRENT member does not change membership. Fresh health from
        // this process's successful restart is enough for emergency local failover;
        // an unavailable commit endpoint must not turn it into total loss.
        if (forFailover && transaction.retry.acquirePending &&
            candidateLeaseId == transaction.retry.acquireReplaceLeaseId &&
            candidateLeaseId != transaction.localActiveLeaseId &&
            transaction.slotIndex(candidateLeaseId) == candidateIndex &&
            candidateWarmupLeaseId == candidateLeaseId &&
            candidateObservation != null &&
            (freshForFailover || healthMonitor.ready(elapsedNow(), candidateObservation))
        ) {
            return completeCandidateReadinessLocked(transaction, transaction, requireNotNull(observations))
        }
        val dueAtUnix = transaction.retry.nextRetryAtUnix
        if (dueAtUnix != null && currentUnixSeconds() < dueAtUnix) {
            if (!forFailover) return true
            // A failed active member cannot wait for background retry. Only confirm
            // an already committed candidate; do not replay acquire/commit early.
            return standbyWorkLocked(
                transaction,
                forFailover = forFailover,
                request = { panel.reportRole(transaction, "standby_reconcile") },
            ) { result ->
                val session = reconcileCandidateCommitLocked(transaction, canonical = result.getOrNull())
                    ?: return@standbyWorkLocked false
                completeCandidateCommitLocked(transaction, session, emptyList())
            }
        }
        if (candidateWarmupLeaseId != candidateLeaseId) {
            return standbyWorkLocked(
                transaction,
                forFailover = forFailover,
                request = {
                    requestStandby(transaction, { it is BackgroundConnectionException &&
                        (it.code in REDUNDANT_GENERATION_CONFLICT_CODES || it.code == "operation_id_conflict") }) {
                        panel.acquireStandby(transaction, requireNotNull(transaction.retry.acquireOperationId),
                            transaction.retry.acquireReplaceLeaseId)
                    }
                },
                dispose = { it.result.getOrNull()?.configuration?.fill(0) },
            ) { result ->
                val reply = result.getOrElse {
                    deferAcquireRetryLocked(transaction, it)
                    return@standbyWorkLocked false
                }
                val replayed = reply.result.getOrElse { error ->
                    if (error is BackgroundConnectionException && error.code in REDUNDANT_GENERATION_CONFLICT_CODES) {
                        reconcileCandidateCommitLocked(transaction, canonical = reply.canonical)?.let { session ->
                            return@standbyWorkLocked completeCandidateCommitLocked(transaction, session, emptyList())
                        }
                    }
                    deferAcquireRetryLocked(transaction, error, reply.canonical)
                    return@standbyWorkLocked false
                }
                val replacementLeaseId = transaction.retry.acquireReplaceLeaseId
                val exactInactiveReissue = replacementLeaseId != null &&
                    candidateLeaseId == replacementLeaseId
                if (replayed.candidateSlot != candidateSlot ||
                    (replayed.candidateLeaseId != candidateLeaseId && !exactInactiveReissue)
                ) {
                    return@standbyWorkLocked false
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
                    return@standbyWorkLocked false
                }
                val refreshed = canonical.copy(
                    candidateLeaseId = replayed.candidateLeaseId,
                    candidateSlot = replayed.candidateSlot,
                )
                if (!refreshed.standbyDesired) {
                    return@standbyWorkLocked persist(refreshed.copy(
                        candidateLeaseId = null,
                        candidateSlot = null,
                        retry = refreshed.retry.cancelAcquire(),
                    ))
                }
                if (replacementLeaseId != null && !native.stopSlot(replacementLeaseId)) {
                    return@standbyWorkLocked false
                }
                if (!mutateNative(refreshed) {
                        native.start(
                            replayed.candidateLeaseId,
                            replayed.candidateSlot,
                            replayed.configuration,
                            replayed.healthProbe,
                        )
                    }
                ) return@standbyWorkLocked false
                candidateWarmupLeaseId = replayed.candidateLeaseId
                if (!persist(refreshed)) return@standbyWorkLocked false
                true
            }
        }
        val snapshot = observations ?: runCatching { native.healthObservations() }.getOrNull()
        val observation = snapshot?.singleOrNull { it.index == candidateIndex } ?: return true
        if (!freshForFailover && !healthMonitor.ready(elapsedNow(), observation)) return true
        return standbyWorkLocked(
            transaction,
            forFailover = forFailover,
            request = {
                requestStandby(transaction, { true }) { panel.commitCandidate(transaction, candidateLeaseId) }
            },
        ) { result ->
            val reply = result.getOrElse {
                deferAcquireRetryLocked(transaction, it)
                return@standbyWorkLocked false
            }
            val session = reply.result.getOrElse { error ->
                reconcileCandidateCommitLocked(transaction, error, reply.canonical) ?: run {
                    deferAcquireRetryLocked(transaction, error, reply.canonical)
                    return@standbyWorkLocked false
                }
            }
            // This only publishes membership/reserve UI state. Activation remains
            // in the health tick and requires a fresh native observation.
            completeCandidateCommitLocked(transaction, session, listOf(observation))
        }
    }

    private fun reconcileCandidateCommitLocked(
        transaction: AndroidRedundantTransaction,
        commitError: Throwable? = null,
        canonical: RedundantRoleResponse? = null,
    ): BackgroundRedundantSession? {
        val candidate = transaction.candidateLeaseId ?: return null
        val session = canonicalStandbySessionLocked(transaction, canonical) ?: return null
        val membership = transaction.withCanonical(session)
        // A reused CURRENT replacement is present before commit, so membership cannot prove it.
        if (session.containsCurrentLease(candidate) &&
            membership.slot(candidate) == transaction.candidateSlot &&
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

    // A best-effort first request is not a cleanup ACK. Never hold the native
    // gate during this HTTP call: local shutdown must proceed even if it hangs.
    override fun notifyStop() {
        val pending = (store.read() as? RecoveryStoreResult.Success)?.value?.redundantTransaction
            ?.takeIf { it.startOperationId == boundStartOperationId } ?: return
        if (pending.desiredActive || pending.stopOperationId == null) return
        if (reportReadinessBeforeStop(pending)) runCatching { panel.stop(pending) }
    }

    private fun reportReadinessBeforeStop(pending: AndroidRedundantTransaction): Boolean {
        val retry = pending.retry
        if (!pending.backgroundCleanupOnStop || !retry.roleObservationPending ||
            retry.pendingRoleReason != "primary_ready" ||
            retry.pendingRoleLeaseId != pending.localActiveLeaseId ||
            retry.pendingNativeActiveLeaseId != null
        ) return true
        val acknowledged = pending.copy(retry = retry.copy(
            roleObservationPending = false,
            pendingRoleLeaseId = null,
            pendingRoleReason = null,
        ))
        // Another Stop request can acknowledge delivery while this HTTP is in flight.
        // Compare the exact stopped transaction without taking the coordinator/native gate.
        fun deliveryRecorded(): Boolean =
            (store.read() as? RecoveryStoreResult.Success)?.value?.redundantTransaction == acknowledged
        // Replay lost replies until role delivery is durably recorded. Rebasing only
        // this report never changes Stop's frozen payload.
        var report = pending
        repeat(2) {
            if (deliveryRecorded()) return true
            val response = try {
                panel.reportRole(report, "primary_ready")
            } catch (error: Throwable) {
                // Fenced/revoked roles must not prevent cleanup. Stop still owns all
                // authorization, confirmed-start and ACK checks; no acceptance is inferred here.
                return deliveryRecorded() || (error is BackgroundConnectionException &&
                    ConnectionIntentErrorPolicy().classify(error.code) == ConnectionIntentDecision.TERMINAL)
            }
            val session = response.session
            if (session.sessionId != pending.sessionId ||
                response.localActiveLeaseId != pending.localActiveLeaseId ||
                !session.containsCurrentLease(pending.localActiveLeaseId)
            ) return false
            if (response.action != "rebase") {
                if (response.action !in setOf("accepted", "acknowledged") ||
                    session.activeLeaseId != pending.localActiveLeaseId
                ) return false
                return deliveryRecorded() || persistExactTransaction(pending, acknowledged)
            }
            report = report.copy(roleGeneration = session.roleGeneration,
                membershipGeneration = session.membershipGeneration)
        }
        return deliveryRecorded()
    }

    // Called only after the service's durable cancellation fence. Native has
    // its own lock; role/recovery HTTP must not delay closing the real TUN.
    override fun closeDataplaneForStop(): Boolean {
        boundStartOperationId?.let(mutationFence::cancel)
        recoveryStarted = false
        return runCatching(native::closeForStop).getOrDefault(false)
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
        if (localStopped && pending.retry.totalLossRestartReplay != null) {
            recordRestartDataplaneStopped(pending)
        }
        val outcome = if (localStopped && reportReadinessBeforeStop(pending)) try {
            if (pending.backgroundCleanupOnStop) panel.stopOutcome(pending)
            else if (panel.stop(pending)) RedundantStopOutcome.Completed else RedundantStopOutcome.Pending
        } catch (_: Throwable) {
            RedundantStopOutcome.Pending
        } else RedundantStopOutcome.Pending
        if (outcome is RedundantStopOutcome.Accepted) {
            return@synchronized store.detachAcceptedStop(pending.startOperationId, outcome.acceptance,
                outcome.credential, nativeClosed = localStopped) is RecoveryStoreResult.Success
        }
        if (!localStopped || outcome !is RedundantStopOutcome.Completed) return@synchronized false
        // Whole-session cleanup also ends role delivery; do not restore a stale pending
        // observation from the snapshot taken before the role/Stop HTTP calls.
        val acknowledged = pending.copy(retry = pending.retry.copy(
            stopState = RedundantStopState.ACKNOWLEDGED,
            roleObservationPending = false,
            pendingRoleLeaseId = null,
            pendingRoleReason = null,
        ))
        if (!persistCleanup(acknowledged)) return@synchronized false
        store.completeRedundantStop(
            stopOperationId = requireNotNull(acknowledged.stopOperationId),
            expectedStartOperationId = acknowledged.startOperationId,
        ) is RecoveryStoreResult.Success
    }

    private fun recordRestartDataplaneStopped(transaction: AndroidRedundantTransaction) {
        runCatching { onRestartDataplaneStopped(transaction) }.onFailure { error ->
            runCatching { TunnelLog.warning("diagnostics.lifecycle_failed", error = error) }
        }
    }

    override fun closeLocal(): Boolean = synchronized(gate) {
        standbyWorkEpoch += 1
        val pending = pendingPrimaryReadiness
        candidateWarmupLeaseId = null
        pendingPrimaryReadiness = null
        recoveryStarted = false
        primaryReadinessFailed = false
        publishReserveStateLocked(null, emptyList())
        if (pending?.freshStart == true) pending.onCancelled()
        runCatching(native::stop).getOrDefault(false)
    }

    private fun persist(
        transaction: AndroidRedundantTransaction,
        canCommit: () -> Boolean = { true },
    ): Boolean =
        mutationFence.runIfActive(transaction.startOperationId) {
            persistCleanup(transaction, canCommit)
        }

    private fun persistCleanup(
        transaction: AndroidRedundantTransaction,
        canCommit: () -> Boolean = { true },
    ): Boolean {
        var admitted = false
        val result = store.updateRedundant(transaction.startOperationId) { current ->
            admitted = canCommit()
            if (!admitted) return@updateRedundant current
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
        return admitted && result is RecoveryStoreResult.Success &&
            result.value.redundantTransaction == transaction
    }

    private fun standbyHasFailoverProof(observation: SlotObservation, deadline: Long): Boolean {
        val now = elapsedNow()
        return now < deadline && healthMonitor.networkReady(now) &&
            observation.standbyCheckDeadlineElapsedMs == deadline &&
            observation.standbyProbeState == StandbyProbeState.SUCCEEDED &&
            observation.hasFreshSuccessfulProbe(now) &&
            healthMonitor.usableCandidate(now, observation)
    }

    private fun switchActiveLocked(
        transaction: AndroidRedundantTransaction,
        target: String,
        failed: String,
        reason: String,
        startupStandby: SlotObservation? = null,
        healthStandby: SlotObservation? = null,
    ): Boolean {
        if (transaction.retry.hasPendingNativeSwitch()) {
            return drainPendingNativeSwitchLocked(transaction, startupStandby)
        }
        val targetSlot = transaction.slot(target) ?: return false
        val startup = pendingPrimaryReadiness
        val checkDeadline = healthStandby?.standbyCheckDeadlineElapsedMs
        // Acquire does not change CURRENT membership. Promote the proven
        // current reserve and fence the late response with this journal write.
        // The panel expires an unused candidate; a locally staged one still needs commit.
        val retry = if ((startup != null || checkDeadline != null) &&
            transaction.candidateLeaseId == null && transaction.retry.acquirePending &&
            transaction.retry.acquireReplaceLeaseId == target
        ) transaction.retry.cancelAcquire() else transaction.retry
        if (transaction.localActiveLeaseId != failed || target == failed ||
            !transaction.containsCurrentLease(target) ||
            retry.acquireReplaceLeaseId == target
        ) {
            return false
        }
        val pending = transaction.copy(
            retry = retry.copy(
                pendingNativeSourceLeaseId = failed,
                pendingNativeActiveLeaseId = target,
                pendingNativeActiveSlot = targetSlot,
                pendingNativeMembershipGeneration = transaction.membershipGeneration,
                pendingNativeSwitchReason = reason,
                pendingNativeSwitchAttempt = 0,
                pendingNativeRequiresProbe = checkDeadline != null,
            ),
        )
        // A failed synchronous write may still publish its value in memory.
        pendingStandbyActivation = checkDeadline?.let {
            PendingStandbyActivation(pending.startOperationId, target, it)
        }
        if (!persistExactTransaction(transaction, pending) {
                (startup == null || startupSwitchHasProof(startup, startupStandby, firstActivation = true)) &&
                    (checkDeadline == null || standbyHasFailoverProof(requireNotNull(healthStandby), checkDeadline))
            }
        ) return false
        return drainPendingNativeSwitchLocked(pending, startupStandby, firstActivation = true,
            healthStandby = healthStandby)
    }

    private fun drainPendingNativeSwitchLocked(
        pending: AndroidRedundantTransaction,
        startupStandby: SlotObservation? = null,
        firstActivation: Boolean = false,
        healthStandby: SlotObservation? = null,
    ): Boolean {
        val retry = pending.retry
        val source = retry.pendingNativeSourceLeaseId ?: return true
        val target = retry.pendingNativeActiveLeaseId ?: return false
        val targetSlot = retry.pendingNativeActiveSlot ?: return false
        val expectedGeneration = retry.pendingNativeMembershipGeneration ?: return false
        val startup = pendingPrimaryReadiness
        if (retry.pendingNativeSwitchReason == STARTUP_SWITCH_REASON && startup == null) return false
        if (pending.localActiveLeaseId != source || source == target ||
            pending.membershipGeneration != expectedGeneration ||
            pending.slot(target) != targetSlot ||
            !pending.containsCurrentLease(source) || !pending.containsCurrentLease(target)
        ) {
            revoke()
            return false
        }
        // Journal I/O can age the observation. Keep the switch pending without
        // spending an activation attempt until startup has current proof.
        val attempts = startup?.switchAttempts(retry) ?: retry.pendingNativeSwitchAttempt
        if (startup != null && (attempts >= MAX_PENDING_NATIVE_SWITCH_ATTEMPTS ||
                !startupSwitchHasProof(startup, startupStandby, firstActivation))
        ) return false
        val healthActivation = pendingStandbyActivation?.takeIf {
            it.startOperationId == pending.startOperationId && it.leaseId == target
        }
        if (retry.pendingNativeRequiresProbe && healthActivation == null) return false
        val healthProof = if (healthActivation != null && !healthActivation.activated) {
            healthStandby ?: runCatching { native.healthObservations() }.getOrNull()?.singleOrNull {
                it.index == pending.slotIndex(target)
            }
        } else null
        if (healthActivation != null && !healthActivation.activated &&
            (healthProof == null || !standbyHasFailoverProof(healthProof, healthActivation.deadlineElapsedMs))
        ) {
            if (elapsedNow() >= healthActivation.deadlineElapsedMs &&
                persistPendingNativeSwitchExact(pending, pending.copy(retry = retry.clearPendingNativeSwitch()))
            ) pendingStandbyActivation = null
            return false
        }
        val activated = healthActivation?.activated == true || mutateNative(pending) {
            runCatching { native.activate(target) }.getOrDefault(false)
        }
        if (!activated) {
            // Startup may still recover on the source after exhausting activation.
            // Its readiness path must prove the source before resolving the journal.
            if (startup != null || attempts < MAX_PENDING_NATIVE_SWITCH_ATTEMPTS - 1) {
                val failedAttempts = attempts + 1
                // Keep the in-process limit even if the journal write fails.
                startup?.failedSwitchAttempts = failedAttempts
                persistPendingNativeSwitchExact(
                    pending,
                    pending.copy(retry = retry.copy(
                        pendingNativeSwitchAttempt = failedAttempts,
                    )),
                )
                return false
            }
            return resolveFailedPendingNativeSwitchLocked(pending).also {
                if (status()?.retry?.hasPendingNativeSwitch() == false) pendingStandbyActivation = null
            }
        }
        // A completed native activation needs only its durable role update on retry.
        healthActivation?.activated = true
        // Activation clears the native standby window even if journal I/O fails.
        // Keep the original window attached to this proof until a new probe succeeds.
        if (startup != null && startupStandby != null) {
            startupStandby.standbyCheckDeadlineElapsedMs?.let { deadline ->
                startup.activatedStandbyCheck = ActivatedStartupStandbyCheck(
                    requireNotNull(startupStandby.successfulProbeValidThroughElapsedMs),
                    deadline,
                )
            }
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
        if (!persistPendingNativeSwitchExact(pending, committed) {
                val accepted = startup == null || startupSwitchHasProof(startup, startupStandby, firstActivation)
                if (!accepted) {
                    // Native activation can clear the standby window before the next tick.
                    startup?.rejectedStandbyProofValidThroughElapsedMs = startupStandby?.successfulProbeValidThroughElapsedMs
                }
                accepted
            }
        ) return false
        pendingStandbyActivation = null
        failoverActive = true
        publishReserveStateLocked(committed, emptyList())
        onDiagnosticEvent(RedundantDiagnosticEvent.FAILOVER)
        // The dataplane switch is authoritative. The regular tick sends this
        // durable observation; role HTTP must not delay startup readiness.
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
            emitTotalLossCommandLocked(pending, "native_switch_failed")
        }
        return false
    }

    private fun emitTotalLossCommandLocked(
        transaction: AndroidRedundantTransaction,
        reason: String,
        active: SlotObservation? = null,
        standby: SlotObservation? = null,
    ): Boolean {
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
        runCatching {
            TunnelLog.info("redundant.recovery_triggered", mapOf(
                "reason" to reason,
                "active_health" to active?.health?.name,
                "hard_failure" to active?.hardFailure,
                "probe_failed" to active?.probeFailed,
                "independent_failure_signal" to active?.independentFailureSignal,
                "corroborated_probe_failures" to active?.corroboratedProbeFailures,
                "standby_health" to standby?.health?.name,
                "standby_probe" to standby?.standbyProbeState?.name,
            ))
        }
        onAllSlotsStalled()
        return true
    }

    private fun persistPendingNativeSwitchExact(
        expected: AndroidRedundantTransaction,
        updated: AndroidRedundantTransaction,
        canCommit: () -> Boolean = { true },
    ): Boolean {
        val result = store.updateRedundant(expected.startOperationId) { current ->
            if (current.samePendingNativeSwitch(expected) && canCommit()) updated else current
        }
        return result is RecoveryStoreResult.Success &&
            result.value.redundantTransaction == updated
    }

    private fun persistExactTransaction(
        expected: AndroidRedundantTransaction,
        updated: AndroidRedundantTransaction,
        canCommit: () -> Boolean = { true },
    ): Boolean {
        val result = store.updateRedundant(expected.startOperationId) { current ->
            if (current == expected && canCommit()) updated else current
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
            // Filling the initial empty slot is not a failed-member replacement.
            nextRetryAtUnix = if (failedLeaseId == null) null else retryDeadlineUnix(REPLACEMENT_DELAY_SECONDS),
            acquirePending = true,
            acquireOperationId = operationId(),
            acquireReplaceLeaseId = failedLeaseId,
        ))
    }

    private fun currentUnixSeconds(): Long = epochNowMs().coerceAtLeast(0L) / 1_000L

    private fun deferAcquireRetryLocked(
        transaction: AndroidRedundantTransaction,
        error: Throwable,
        canonical: RedundantRoleResponse? = null,
    ) {
        if (error is BackgroundConnectionException && error.code == "operation_id_conflict" &&
            rebaseConsumedAcquireLocked(transaction, canonical)
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
        response: RedundantRoleResponse?,
    ): BackgroundRedundantSession? {
        if (response == null) return null
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

    private fun rebaseConsumedAcquireLocked(
        transaction: AndroidRedundantTransaction,
        canonical: RedundantRoleResponse?,
    ): Boolean {
        val session = canonicalStandbySessionLocked(transaction, canonical) ?: return false
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
        const val STARTUP_SWITCH_REASON = "primary_ready"
        const val REDUNDANT_ROLE_MEMBERSHIP_CONFLICT = "session_membership_conflict"
        const val MAX_PENDING_NATIVE_SWITCH_ATTEMPTS = 3
        const val PRIMARY_READINESS_TIMEOUT_MILLIS = 30_000L
        const val INITIAL_HANDSHAKE_REBIND_MILLIS = 7_000L
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
    retry.pendingNativeSwitchAttempt == other.retry.pendingNativeSwitchAttempt &&
    retry.pendingNativeRequiresProbe == other.retry.pendingNativeRequiresProbe

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
