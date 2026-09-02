package ru.nelomai.tunnel

import org.amnezia.awg.config.Config
import org.json.JSONObject
import java.util.UUID
import java.util.concurrent.TimeUnit

internal fun RedundantHealthProbeArgs?.toBackgroundProbe(): BackgroundRedundantHealthProbe {
    val value = requireNotNull(this) { "missing_redundant_health_probe" }
    return validatedRedundantHealthProbe(
        kind = value.kind,
        targetIpv4 = value.targetIpv4,
        queryName = value.queryName,
        timeoutMs = value.timeoutMs,
    )
}

internal fun validatedRedundantHealthProbe(
    kind: String,
    targetIpv4: String,
    queryName: String,
    timeoutMs: Long,
): BackgroundRedundantHealthProbe {
    require(kind == "dns_a")
    require(timeoutMs in 1_000L..8_000L)
    require(canonicalRedundantIpv4(targetIpv4))
    require(canonicalRedundantDnsName(queryName))
    return BackgroundRedundantHealthProbe(
        kind = kind,
        targetIpv4 = targetIpv4,
        queryName = queryName,
        timeoutMs = timeoutMs,
    )
}

internal fun redundantHealthProbesFromStart(
    redundancy: RedundantStartArgs,
): Map<String, BackgroundRedundantHealthProbe> {
    require(redundancy.state in setOf("disabled", "degraded", "warming", "ready"))
    if (redundancy.state == "disabled") {
        require(!redundancy.standbyDesired)
        require(redundancy.standby == null)
        require(redundancy.primary.healthProbe == null)
    } else {
        require(redundancy.primary.healthProbe != null)
    }
    require(redundancy.standbyDesired || redundancy.standby == null)
    return linkedMapOf<String, BackgroundRedundantHealthProbe>().apply {
        redundancy.primary.healthProbe?.let {
            put(redundancy.primary.leaseId, it.toBackgroundProbe())
        }
        redundancy.standby?.let {
            put(it.member.leaseId, it.member.healthProbe.toBackgroundProbe())
        }
    }
}

internal fun redundantTransactionFromStart(
    redundancy: RedundantStartArgs,
    args: StartTunnelArgs,
    deviceId: String,
    androidApiLevel: Int,
): AndroidRedundantTransaction {
    val quick = requireNotNull(args.quickConnection) { "missing_redundant_connection" }
    val primaryLeaseId = UUID.fromString(redundancy.primary.leaseId).toString()
    require(quick.leaseId == primaryLeaseId)
    val standbyLeaseId = redundancy.standby?.member?.leaseId?.let {
        UUID.fromString(it).toString()
    }
    require(primaryLeaseId != standbyLeaseId)
    val primarySlot = RedundantSlot.fromWireName(redundancy.primary.slot)
    val standbySlot = redundancy.standby?.member?.slot?.let(RedundantSlot::fromWireName)
    require(standbySlot == null || standbySlot != primarySlot)
    val slotA = when (RedundantSlot.A) {
        primarySlot -> primaryLeaseId
        standbySlot -> standbyLeaseId
        else -> null
    }
    val slotB = when (RedundantSlot.B) {
        primarySlot -> primaryLeaseId
        standbySlot -> standbyLeaseId
        else -> null
    }
    val current = setOfNotNullCompat(slotA, slotB)
    val canonicalActive = UUID.fromString(redundancy.activeLeaseId).toString()
    val localActive = UUID.fromString(redundancy.localActiveLeaseId).toString()
    require(canonicalActive in current && localActive in current)
    require(redundancy.roleGeneration >= 0 && redundancy.membershipGeneration >= 0)
    require(redundancy.requestFingerprint.matches(Regex("^[0-9a-f]{64}$")))
    require(redundancy.virtualAddressV4.endsWith("/32") &&
        canonicalRedundantIpv4(redundancy.virtualAddressV4.removeSuffix("/32")))
    redundantHealthProbesFromStart(redundancy)
    return AndroidRedundantTransaction(
        desiredActive = true,
        template = AndroidIntentTemplate(
            deviceId = UUID.fromString(deviceId).toString(),
            accountScope = UUID.fromString(deviceId).toString(),
            layer = quick.layer,
            ticConnectionMode = quick.ticConnectionMode,
            routeMode = quick.routeMode,
            egressMode = quick.egressMode,
            allowAlternate = quick.allowAlternate,
            options = normalizeAndroidTunnelOptions(androidApiLevel, args.options),
        ),
        sessionId = UUID.fromString(redundancy.sessionId).toString(),
        slotALeaseId = slotA,
        slotBLeaseId = slotB,
        localActiveLeaseId = localActive,
        standbyDesired = redundancy.standbyDesired,
        roleGeneration = redundancy.roleGeneration,
        membershipGeneration = redundancy.membershipGeneration,
        startOperationId = UUID.fromString(redundancy.operationId).toString(),
        startRequestFingerprint = redundancy.requestFingerprint,
        startReserveEnabled = redundancy.reserveEnabled,
    )
}

private fun setOfNotNullCompat(first: String?, second: String?): Set<String> =
    listOfNotNull(first, second).toSet()

private fun canonicalRedundantIpv4(value: String): Boolean {
    val octets = value.split('.')
    return octets.size == 4 && octets.all { octet ->
        octet.isNotEmpty() && octet.length <= 3 &&
            (octet == "0" || !octet.startsWith('0')) &&
            octet.all(Char::isDigit) && octet.toIntOrNull() in 0..255
    }
}

private fun canonicalRedundantDnsName(value: String): Boolean =
    value.length in 1..253 && value == value.lowercase() && !value.endsWith('.') &&
        value.split('.').all { label ->
            label.length in 1..63 && label.first() != '-' && label.last() != '-' &&
                label.all { it in 'a'..'z' || it in '0'..'9' || it == '-' }
        }

internal data class PreparedRedundantConfiguration(
    val config: Config,
    val userspace: ByteArray,
)

/** Fixed-slot adapter over the sole dispatcher/native session. */
internal class ServiceRedundantConnectionNative(
    private val backend: RedundantSessionBackend,
    private val establishTun: (Config) -> Int?,
    private val prepare: (ByteArray) -> PreparedRedundantConfiguration,
    probeSourceIpv4: String,
    initialNetworkValidated: Boolean = true,
    private val epochNowMs: () -> Long = System::currentTimeMillis,
    private val elapsedNowMs: () -> Long = {
        TimeUnit.NANOSECONDS.toMillis(System.nanoTime())
    },
) : RedundantConnectionNative {
    private data class SlotRuntime(
        val leaseId: String,
        val slot: RedundantSlot,
        val probe: BackgroundRedundantHealthProbe?,
        val probeTarget: String?,
        var startedAtElapsedMs: Long,
        var probeToken: Long? = null,
        var probeDeadlineElapsedMs: Long? = null,
        var lastProbeAtElapsedMs: Long = Long.MIN_VALUE,
        var urgentProbe: Boolean = false,
        var consecutiveProbeSuccesses: Int = 0,
        var probeFailed: Boolean = false,
        var hardFailure: Boolean = false,
        var previousTxPackets: Long = 0,
        var previousRxPackets: Long = 0,
        var probeBaselineTxPackets: Long? = null,
        var probeBaselineRxPackets: Long? = null,
        var urgentStartedAtElapsedMs: Long? = null,
        var urgentDeadlineElapsedMs: Long? = null,
        var urgentRxPacketsAtStart: Long? = null,
        var urgentCorroboratedFailures: Int = 0,
        var urgentEvidence: Boolean = false,
    )

    private val gate = Any()
    private var session: NativeSession? = null
    private val slots = mutableMapOf<RedundantSlot, SlotRuntime>()
    private var activeSlot: RedundantSlot? = null
    private var networkValidated = initialNetworkValidated
    private var probeSourceIpv4 = probeSourceIpv4

    override fun start(
        leaseId: String,
        slot: RedundantSlot,
        configuration: ByteArray,
        healthProbe: BackgroundRedundantHealthProbe?,
    ): Boolean = synchronized(gate) {
        val existing = slots[slot]
        if (existing?.leaseId == leaseId) {
            configuration.fill(0)
            return@synchronized true
        }
        val prepared = try {
            prepare(configuration)
        } catch (_: Throwable) {
            configuration.fill(0)
            return@synchronized false
        }
        try {
            val hadSession = session != null
            val nativeSession = session ?: run {
                val tunFd = establishTun(prepared.config) ?: return@synchronized false
                backend.start(tunFd, slot.index, prepared.userspace)?.also { session = it }
                    ?: return@synchronized false
            }
            existing?.let {
                if (!backend.stopSlot(nativeSession, slot.index)) return@synchronized false
                slots.remove(slot)
            }
            if (hadSession && !backend.startSlot(nativeSession, slot.index, prepared.userspace)) {
                return@synchronized false
            }
            val probeTarget = prepared.config.peers.firstOrNull()
                ?.endpoint?.orElse(null)?.host
            slots[slot] = SlotRuntime(
                leaseId,
                slot,
                healthProbe,
                probeTarget,
                elapsedNowMs(),
            )
            true
        } finally {
            configuration.fill(0)
            prepared.userspace.fill(0)
        }
    }

    override fun activate(leaseId: String): Boolean = synchronized(gate) {
        val nativeSession = session ?: return@synchronized false
        val runtime = slots.values.singleOrNull { it.leaseId == leaseId }
            ?: return@synchronized false
        backend.switchActive(nativeSession, runtime.slot.index).also { switched ->
            if (switched) activeSlot = runtime.slot
        }
    }

    override fun stopSlot(leaseId: String): Boolean = synchronized(gate) {
        val nativeSession = session ?: return@synchronized false
        val runtime = slots.values.singleOrNull { it.leaseId == leaseId }
            ?: return@synchronized true
        backend.stopSlot(nativeSession, runtime.slot.index).also { stopped ->
            if (stopped) slots.remove(runtime.slot)
        }
    }

    override fun stop(): Boolean = synchronized(gate) {
        val nativeSession = session ?: return@synchronized true
        backend.close(nativeSession)
        slots.clear()
        session = null
        activeSlot = null
        true
    }

    override fun isUsable(leaseId: String): Boolean = synchronized(gate) {
        slots.values.any { it.leaseId == leaseId }
    }

    override fun setNetworkValidated(validated: Boolean) = synchronized(gate) {
        networkValidated = validated
        if (!validated) slots.values.forEach { runtime ->
            cancelProbeLocked(runtime)
            clearUrgentFailureLocked(runtime)
            runtime.probeFailed = false
        }
    }

    override fun setProbeSourceIpv4(sourceIpv4: String) = synchronized(gate) {
        probeSourceIpv4 = sourceIpv4
    }

    override fun rebind(leaseId: String): Boolean = synchronized(gate) {
        val nativeSession = session ?: return@synchronized false
        val runtime = slots.values.singleOrNull { it.leaseId == leaseId }
            ?: return@synchronized false
        backend.rebind(nativeSession, runtime.slot.index).also { rebound ->
            if (rebound) {
                runtime.startedAtElapsedMs = elapsedNowMs()
                runtime.consecutiveProbeSuccesses = 0
                runtime.probeFailed = false
                runtime.hardFailure = false
                runtime.probeToken = null
                runtime.probeDeadlineElapsedMs = null
                runtime.lastProbeAtElapsedMs = Long.MIN_VALUE
                runtime.probeBaselineTxPackets = null
                runtime.probeBaselineRxPackets = null
                clearUrgentFailureLocked(runtime)
            }
            if (!rebound && networkValidated) runtime.hardFailure = true
        }
    }

    override fun metrics(includeProbeTarget: Boolean): RedundantVpnMetrics? = synchronized(gate) {
        val nativeSession = session ?: return@synchronized null
        val payload = runCatching { backend.metrics(nativeSession)?.let(::JSONObject) }.getOrNull()
            ?: return@synchronized null
        val array = payload.optJSONArray("slots") ?: return@synchronized null
        var received = 0L
        var sent = 0L
        var latestHandshake: Long? = null
        for (index in 0 until array.length()) {
            val value = array.optJSONObject(index) ?: continue
            val telemetry = value.optJSONObject("telemetry") ?: continue
            received = saturatingAddPositive(received, telemetry.optLong("tun_write_bytes", 0L))
            sent = saturatingAddPositive(sent, telemetry.optLong("tun_read_bytes", 0L))
            value.optLong("latest_handshake_at_unix_ms", 0L).takeIf { it > 0L }?.let {
                latestHandshake = maxOf(latestHandshake ?: 0L, it)
            }
        }
        RedundantVpnMetrics(
            receivedBytes = received,
            sentBytes = sent,
            latestHandshakeEpochMillis = latestHandshake,
            probeTarget = activeSlot?.let(slots::get)?.probeTarget.takeIf { includeProbeTarget },
        )
    }

    override fun diagnosticMetrics(): String? = synchronized(gate) {
        val nativeSession = session ?: return@synchronized null
        runCatching { backend.metrics(nativeSession) }.getOrNull()
    }

    override fun healthObservations(): List<SlotObservation> = synchronized(gate) {
        val nativeSession = session ?: return@synchronized emptyList()
        val epochNow = epochNowMs()
        val elapsedNow = elapsedNowMs()
        val metrics = runCatching { backend.metrics(nativeSession)?.let(::JSONObject) }.getOrNull()
        val metricsBySlot = metrics?.optJSONArray("slots")?.let { array ->
            (0 until array.length()).associate { index ->
                val value = array.getJSONObject(index)
                value.getInt("slot") to value
            }
        }.orEmpty()
        slots.values.sortedBy { it.slot.index }.map { runtime ->
            val nativeMetrics = metricsBySlot[runtime.slot.index]
            val telemetry = nativeMetrics?.optJSONObject("telemetry")
            val txPackets = telemetry?.optLong("udp_send_packets") ?: runtime.previousTxPackets
            val rxPackets = telemetry?.optLong("udp_receive_packets") ?: runtime.previousRxPackets
            advanceProbeLocked(nativeSession, runtime, elapsedNow, txPackets, rxPackets)
            runtime.previousTxPackets = txPackets
            runtime.previousRxPackets = rxPackets
            val latestHandshake = nativeMetrics?.optLong("latest_handshake_at_unix_ms") ?: 0L
            val handshakeFresh = latestHandshake > 0L && epochNow >= latestHandshake &&
                epochNow - latestHandshake <= HANDSHAKE_FRESH_MILLIS
            val admitted = nativeMetrics?.optBoolean("admitted", true) ?: (metrics == null)
            val ready = handshakeFresh &&
                runtime.consecutiveProbeSuccesses >= READY_PROBE_SUCCESSES &&
                elapsedNow >= runtime.startedAtElapsedMs &&
                elapsedNow - runtime.startedAtElapsedMs >= READY_STABILITY_MILLIS
            SlotObservation(
                index = runtime.slot.index,
                active = runtime.slot == activeSlot,
                health = when {
                    !admitted || runtime.hardFailure -> BackendHealth.UNHEALTHY
                    ready -> BackendHealth.READY
                    runtime.probeFailed -> BackendHealth.SUSPECT
                    else -> BackendHealth.WARMING
                },
                hardFailure = !admitted || runtime.hardFailure,
                probeFailed = runtime.probeFailed,
                independentFailureSignal = runtime.urgentEvidence,
                softFailureStartedAtMs = runtime.urgentStartedAtElapsedMs,
                corroboratedProbeFailures = runtime.urgentCorroboratedFailures,
                handshakeFresh = handshakeFresh,
                consecutiveProbeSuccesses = runtime.consecutiveProbeSuccesses,
                stableSinceMs = runtime.startedAtElapsedMs,
            )
        }
    }

    private fun advanceProbeLocked(
        nativeSession: NativeSession,
        runtime: SlotRuntime,
        elapsedNow: Long,
        currentTxPackets: Long,
        currentRxPackets: Long,
    ) {
        if (!networkValidated) return
        val urgentRxPacketsAtStart = runtime.urgentRxPacketsAtStart
        if (runtime.urgentEvidence && urgentRxPacketsAtStart != null &&
            currentRxPackets > urgentRxPacketsAtStart
        ) {
            cancelProbeLocked(runtime)
            clearUrgentFailureLocked(runtime)
            runtime.probeFailed = false
            runtime.lastProbeAtElapsedMs = elapsedNow
            return
        }
        val urgentDeadline = runtime.urgentDeadlineElapsedMs
        if (urgentDeadline != null && elapsedNow >= urgentDeadline) {
            cancelProbeLocked(runtime)
            if (runtime.urgentCorroboratedFailures < REQUIRED_URGENT_FAILURES) {
                clearUrgentFailureLocked(runtime)
                runtime.probeFailed = false
            }
            return
        }
        val token = runtime.probeToken
        if (token != null) {
            when (backend.probeStatus(nativeSession, token)) {
                NativeProbeStatus.PENDING -> if (
                    elapsedNow >= (runtime.probeDeadlineElapsedMs ?: Long.MAX_VALUE)
                ) {
                    backend.cancelProbe(nativeSession, token)
                    finishProbe(
                        runtime,
                        elapsedNow,
                        succeeded = false,
                        currentTxPackets = currentTxPackets,
                        currentRxPackets = currentRxPackets,
                    )
                }
                NativeProbeStatus.SUCCEEDED -> finishProbe(
                    runtime,
                    elapsedNow,
                    succeeded = true,
                    currentTxPackets = currentTxPackets,
                    currentRxPackets = currentRxPackets,
                )
                NativeProbeStatus.FAILED, NativeProbeStatus.UNKNOWN ->
                    finishProbe(
                        runtime,
                        elapsedNow,
                        succeeded = false,
                        currentTxPackets = currentTxPackets,
                        currentRxPackets = currentRxPackets,
                    )
            }
            if (runtime.probeToken != null) return
        }
        val urgent = runtime.urgentEvidence
        val interval = if (urgent) {
            0L
        } else if (runtime.consecutiveProbeSuccesses >= READY_PROBE_SUCCESSES) {
            READY_PROBE_INTERVAL_MILLIS
        } else {
            WARMUP_PROBE_INTERVAL_MILLIS
        }
        if (runtime.lastProbeAtElapsedMs != Long.MIN_VALUE &&
            elapsedNow >= runtime.lastProbeAtElapsedMs &&
            elapsedNow - runtime.lastProbeAtElapsedMs < interval
        ) return
        val probe = runtime.probe ?: return
        runtime.probeBaselineTxPackets = currentTxPackets
        runtime.probeBaselineRxPackets = currentRxPackets
        runtime.urgentProbe = urgent
        val opaque = backend.startProbe(
            nativeSession,
            runtime.slot.index,
            NativeDnsProbeTemplate(
                sourceIpv4 = probeSourceIpv4,
                targetIpv4 = probe.targetIpv4,
                queryName = probe.queryName,
            ),
        ) ?: run {
            finishProbe(
                runtime,
                elapsedNow,
                succeeded = false,
                currentTxPackets = currentTxPackets,
                currentRxPackets = currentRxPackets,
            )
            return
        }
        runtime.probeToken = opaque
        val timeoutMs = if (urgent) {
            minOf(probe.timeoutMs, URGENT_PROBE_TIMEOUT_MILLIS)
        } else {
            probe.timeoutMs
        }
        runtime.probeDeadlineElapsedMs = saturatingAdd(elapsedNow, timeoutMs)
        runtime.lastProbeAtElapsedMs = elapsedNow
    }

    private fun finishProbe(
        runtime: SlotRuntime,
        elapsedNow: Long,
        succeeded: Boolean,
        currentTxPackets: Long,
        currentRxPackets: Long,
    ) {
        val wasUrgent = runtime.urgentProbe
        val baselineTx = runtime.probeBaselineTxPackets
        val baselineRx = runtime.probeBaselineRxPackets
        val sentWithoutReceive = baselineTx != null && baselineRx != null &&
            currentTxPackets > baselineTx && currentRxPackets <= baselineRx
        runtime.probeToken = null
        runtime.probeDeadlineElapsedMs = null
        runtime.lastProbeAtElapsedMs = elapsedNow
        runtime.urgentProbe = false
        runtime.probeFailed = !succeeded
        runtime.consecutiveProbeSuccesses = if (succeeded) {
            (runtime.consecutiveProbeSuccesses + 1).coerceAtMost(READY_PROBE_SUCCESSES)
        } else {
            0
        }
        if (succeeded) {
            clearUrgentFailureLocked(runtime)
        } else if (wasUrgent) {
            if (sentWithoutReceive) {
                runtime.urgentCorroboratedFailures =
                    (runtime.urgentCorroboratedFailures + 1).coerceAtMost(REQUIRED_URGENT_FAILURES)
            }
        } else if (sentWithoutReceive) {
            runtime.urgentStartedAtElapsedMs = elapsedNow
            runtime.urgentDeadlineElapsedMs = saturatingAdd(
                elapsedNow,
                URGENT_SEQUENCE_DEADLINE_MILLIS,
            )
            runtime.urgentRxPacketsAtStart = currentRxPackets
            runtime.urgentCorroboratedFailures = 0
            runtime.urgentEvidence = true
        } else {
            clearUrgentFailureLocked(runtime)
        }
    }

    private fun cancelProbeLocked(runtime: SlotRuntime) {
        val nativeSession = session ?: return
        runtime.probeToken?.let { backend.cancelProbe(nativeSession, it) }
        runtime.probeToken = null
        runtime.probeDeadlineElapsedMs = null
        runtime.urgentProbe = false
        runtime.probeBaselineTxPackets = null
        runtime.probeBaselineRxPackets = null
    }

    private fun clearUrgentFailureLocked(runtime: SlotRuntime) {
        runtime.urgentStartedAtElapsedMs = null
        runtime.urgentDeadlineElapsedMs = null
        runtime.urgentRxPacketsAtStart = null
        runtime.urgentCorroboratedFailures = 0
        runtime.urgentEvidence = false
        runtime.urgentProbe = false
    }

    private fun saturatingAdd(value: Long, increment: Long): Long =
        if (increment > Long.MAX_VALUE - value) Long.MAX_VALUE else value + increment

    private fun saturatingAddPositive(value: Long, increment: Long): Long =
        if (increment <= 0L) value else saturatingAdd(value, increment)

    private val RedundantSlot.index: Int get() = if (this == RedundantSlot.A) 0 else 1

    private companion object {
        const val READY_PROBE_SUCCESSES = 3
        const val READY_STABILITY_MILLIS = 15_000L
        const val WARMUP_PROBE_INTERVAL_MILLIS = 5_000L
        const val READY_PROBE_INTERVAL_MILLIS = 15_000L
        const val URGENT_PROBE_TIMEOUT_MILLIS = 2_000L
        const val URGENT_SEQUENCE_DEADLINE_MILLIS = 8_000L
        const val REQUIRED_URGENT_FAILURES = 2
        const val HANDSHAKE_FRESH_MILLIS = 180_000L
    }
}

/** Authenticated recovery-v2 control-plane adapter owned by the VPN process. */
internal class ServiceRedundantConnectionPanel(
    private val credential: (String) -> BackgroundCredential,
    private val recoverTransport: (
        BackgroundCredential,
        AndroidRedundantTransaction,
    ) -> BackgroundRedundantRecoveryTransport = BackgroundConnectionClient::recoverRedundant,
) : RedundantConnectionPanel {
    override fun recover(transaction: AndroidRedundantTransaction): RedundantRecoveryResponse {
        val transport = recoverTransport(
            credential(transaction.template.deviceId),
            transaction,
        )
        return RedundantRecoveryResponse(
            session = transport.session,
            configurations = transport.configurations,
            healthProbes = transport.healthProbes,
            virtualAddressV4 = transport.virtualAddressV4,
        )
    }

    override fun reportRole(
        transaction: AndroidRedundantTransaction,
        reason: String,
    ): RedundantRoleResponse = BackgroundConnectionClient.reportRedundantRole(
        credential(transaction.template.deviceId),
        transaction,
        reason,
    )

    override fun releaseStandby(
        transaction: AndroidRedundantTransaction,
        inactiveLeaseId: String?,
    ): BackgroundRedundantSession = BackgroundConnectionClient.releaseRedundantStandby(
        credential(transaction.template.deviceId),
        transaction,
        inactiveLeaseId,
    )

    override fun acquireStandby(
        transaction: AndroidRedundantTransaction,
        operationId: String,
        replaceLeaseId: String?,
    ): BackgroundRedundantCandidate = BackgroundConnectionClient.acquireRedundantStandby(
        credential(transaction.template.deviceId),
        transaction,
        operationId,
        replaceLeaseId = replaceLeaseId,
    )

    override fun commitCandidate(
        transaction: AndroidRedundantTransaction,
        candidateLeaseId: String,
    ): BackgroundRedundantSession = BackgroundConnectionClient.commitRedundantCandidate(
        credential(transaction.template.deviceId),
        transaction,
        candidateLeaseId,
    )

    override fun stop(transaction: AndroidRedundantTransaction): Boolean {
        val leaseId = transaction.localActiveLeaseId
            ?: transaction.slotALeaseId
            ?: transaction.slotBLeaseId
            ?: return false
        return runCatching {
            BackgroundConnectionClient.stopRedundant(
                credential(transaction.template.deviceId),
                transaction,
                leaseId,
            ).getJSONObject("connection")
            true
        }.getOrDefault(false)
    }
}
