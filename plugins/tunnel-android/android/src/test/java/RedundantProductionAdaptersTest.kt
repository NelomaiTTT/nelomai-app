package ru.nelomai.tunnel

import java.io.ByteArrayInputStream
import org.amnezia.awg.config.Config
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class RedundantProductionAdaptersTest {
    @Test
    fun urgentSequenceUsesElapsedTimeAndDoesNotWaitForReadyCadence() {
        val clock = TestDualClock(
            epochMs = 1_800_000_000_000L,
            elapsedMs = 10_000L,
        )
        val backend = RecordingSessionBackend { clock.epochMs }
        val native = ServiceRedundantConnectionNative(
            backend = backend,
            establishTun = { 41 },
            prepare = ::prepared,
            probeSourceIpv4 = "10.200.0.2/32",
            epochNowMs = { clock.epochMs },
            elapsedNowMs = { clock.elapsedMs },
        )
        assertTrue(native.start("lease-a", RedundantSlot.A, byteArrayOf(1), probe()))
        assertTrue(native.activate("lease-a"))

        native.healthObservations()
        repeat(3) {
            backend.probeStatuses[requireNotNull(backend.latestProbeToken)] =
                NativeProbeStatus.SUCCEEDED
            clock.elapsedMs += 1L
            native.healthObservations()
            if (it < 2) {
                clock.elapsedMs += 5_000L
                native.healthObservations()
            }
        }
        clock.elapsedMs = 25_000L
        assertEquals(BackendHealth.READY, native.healthObservations().single().health)

        clock.elapsedMs = 35_003L
        native.healthObservations()
        val ordinaryToken = requireNotNull(backend.latestProbeToken)
        backend.probeStatuses[ordinaryToken] = NativeProbeStatus.FAILED
        clock.elapsedMs += 1L
        val suspected = native.healthObservations().single()
        val urgentOne = requireNotNull(backend.latestProbeToken)

        assertTrue(suspected.independentFailureSignal)
        assertEquals(clock.elapsedMs, suspected.softFailureStartedAtMs)
        assertEquals(0, suspected.corroboratedProbeFailures)
        assertTrue(urgentOne != ordinaryToken)

        clock.elapsedMs += 2_000L
        native.healthObservations()
        val urgentTwo = requireNotNull(backend.latestProbeToken)
        assertTrue(urgentTwo != urgentOne)
        clock.elapsedMs += 2_000L
        val corroborated = native.healthObservations().single()

        assertEquals(2, corroborated.corroboratedProbeFailures)
        assertEquals(35_004L, corroborated.softFailureStartedAtMs)
        assertTrue(corroborated.independentFailureSignal)
    }

    @Test
    fun successfulUrgentProbeClearsRetainedFailureEvidence() {
        val clock = TestDualClock(epochMs = 1_800_000_000_000L, elapsedMs = 10_000L)
        val backend = RecordingSessionBackend { clock.epochMs }
        val native = ServiceRedundantConnectionNative(
            backend = backend,
            establishTun = { 41 },
            prepare = ::prepared,
            probeSourceIpv4 = "10.200.0.2/32",
            epochNowMs = { clock.epochMs },
            elapsedNowMs = { clock.elapsedMs },
        )
        assertTrue(native.start("lease-a", RedundantSlot.A, byteArrayOf(1), probe()))
        assertTrue(native.activate("lease-a"))

        native.healthObservations()
        val ordinaryToken = requireNotNull(backend.latestProbeToken)
        backend.probeStatuses[ordinaryToken] = NativeProbeStatus.FAILED
        clock.elapsedMs += 1L
        assertTrue(native.healthObservations().single().independentFailureSignal)
        backend.probeStatuses[requireNotNull(backend.latestProbeToken)] =
            NativeProbeStatus.SUCCEEDED
        clock.elapsedMs += 1L

        val recovered = native.healthObservations().single()

        assertFalse(recovered.independentFailureSignal)
        assertEquals(null, recovered.softFailureStartedAtMs)
        assertEquals(0, recovered.corroboratedProbeFailures)
    }

    @Test
    fun receiveProgressClearsRetainedFailureEvidence() {
        val fixture = suspectedFixture()
        fixture.backend.setUdpPackets(sent = 10, received = 1)

        val recovered = fixture.native.healthObservations().single()

        assertFalse(recovered.probeFailed)
        assertFalse(recovered.independentFailureSignal)
        assertEquals(null, recovered.softFailureStartedAtMs)
    }

    @Test
    fun rebindAndNetworkInvalidationClearRetainedFailureEvidence() {
        val rebound = suspectedFixture()
        assertTrue(rebound.native.rebind("lease-a"))
        val reboundObservation = rebound.native.healthObservations().single()
        assertFalse(reboundObservation.independentFailureSignal)
        assertEquals(null, reboundObservation.softFailureStartedAtMs)

        val invalidated = suspectedFixture()
        invalidated.native.setNetworkValidated(false)
        val invalidatedObservation = invalidated.native.healthObservations().single()
        assertFalse(invalidatedObservation.probeFailed)
        assertFalse(invalidatedObservation.independentFailureSignal)
        assertEquals(null, invalidatedObservation.softFailureStartedAtMs)
    }

    @Test
    fun productionPanelRecoveryUsesTheServiceActiveDeviceCredential() {
        val transaction = AndroidRedundantTransaction(
            desiredActive = true,
            template = AndroidIntentTemplate(
                deviceId = "11111111-1111-4111-8111-111111111111",
                accountScope = "account",
                layer = "stray",
                ticConnectionMode = "dynamic",
                routeMode = "standalone",
                egressMode = "ipv4",
                allowAlternate = true,
            ),
            sessionId = "22222222-2222-4222-8222-222222222222",
            slotALeaseId = "lease-a",
            slotBLeaseId = null,
            localActiveLeaseId = "lease-a",
            standbyDesired = false,
            roleGeneration = 1,
            membershipGeneration = 1,
            startOperationId = "operation",
            startRequestFingerprint = "f".repeat(64),
        )
        val activeCredential = BackgroundCredential(
            transaction.template.deviceId,
            "https://nelomai.example",
            "device-token",
            1_900_000_000,
        )
        var requestedDeviceId: String? = null
        var transportCredential: BackgroundCredential? = null
        val panel = ServiceRedundantConnectionPanel(
            credential = { deviceId ->
                requestedDeviceId = deviceId
                activeCredential
            },
            recoverTransport = { credential, requested ->
                transportCredential = credential
                assertSame(transaction, requested)
                BackgroundRedundantRecoveryTransport(
                    session = BackgroundRedundantSession(
                        sessionId = transaction.sessionId,
                        state = "connected",
                        activeLeaseId = "lease-a",
                        slotALeaseId = "lease-a",
                        slotBLeaseId = null,
                        standbyDesired = false,
                        roleGeneration = 1,
                        membershipGeneration = 1,
                        reason = null,
                    ),
                    configurations = mapOf("lease-a" to byteArrayOf(1)),
                    healthProbes = emptyMap(),
                    virtualAddressV4 = "10.200.0.2/32",
                )
            },
        )

        val response = panel.recover(transaction)

        assertEquals(transaction.template.deviceId, requestedDeviceId)
        assertSame(activeCredential, transportCredential)
        assertEquals(setOf("lease-a"), response.configurations.keys)
    }

    @Test
    fun productionNativeUsesOneTunAndPreservesFixedSlots() {
        val backend = RecordingSessionBackend()
        var tunCreates = 0
        val native = ServiceRedundantConnectionNative(
            backend = backend,
            establishTun = {
                tunCreates += 1
                41
            },
            prepare = ::prepared,
            probeSourceIpv4 = "10.200.0.2/32",
        )

        assertTrue(native.start("lease-b", RedundantSlot.B, byteArrayOf(1), probe()))
        assertTrue(native.activate("lease-b"))
        assertTrue(native.start("lease-a", RedundantSlot.A, byteArrayOf(2), probe()))

        assertEquals(1, tunCreates)
        assertEquals(listOf(1), backend.primarySlots)
        assertEquals(listOf(0), backend.additionalSlots)
        assertEquals(listOf(1), backend.activeSlots)
    }

    @Test
    fun productionNativeRequiresThreeProbesFreshHandshakeAndFifteenSecondsForReady() {
        var nowMs = 1_000_000L
        val backend = RecordingSessionBackend { nowMs }
        val native = ServiceRedundantConnectionNative(
            backend = backend,
            establishTun = { 41 },
            prepare = ::prepared,
            probeSourceIpv4 = "10.200.0.2/32",
            epochNowMs = { nowMs },
            elapsedNowMs = { nowMs },
        )
        assertTrue(native.start("lease-a", RedundantSlot.A, byteArrayOf(1), probe()))
        assertTrue(native.activate("lease-a"))

        native.healthObservations()
        repeat(3) { success ->
            backend.probeStatuses[requireNotNull(backend.latestProbeToken)] =
                NativeProbeStatus.SUCCEEDED
            nowMs += 1
            val observation = native.healthObservations().single()
            if (success < 2) {
                assertEquals(BackendHealth.WARMING, observation.health)
                nowMs += 5_000
                native.healthObservations()
            }
        }
        assertEquals(3, native.healthObservations().single().consecutiveProbeSuccesses)

        nowMs = 1_015_000L
        assertEquals(BackendHealth.READY, native.healthObservations().single().health)
    }

    @Test
    fun availableButUnvalidatedNetworkSuspendsNativeProbeProgress() {
        val backend = RecordingSessionBackend()
        val native = ServiceRedundantConnectionNative(
            backend = backend,
            establishTun = { 41 },
            prepare = ::prepared,
            probeSourceIpv4 = "10.200.0.2/32",
            initialNetworkValidated = false,
        )
        assertTrue(native.start("lease-a", RedundantSlot.A, byteArrayOf(1), probe()))

        val observation = native.healthObservations().single()

        assertEquals(0, backend.probeStatuses.size)
        assertEquals(0, observation.consecutiveProbeSuccesses)
        assertEquals(BackendHealth.WARMING, observation.health)
    }

    @Test
    fun timedOutProbeKeepsItsLaunchBaselineAsIndependentFailureSignal() {
        var nowMs = 1_000_000L
        val backend = RecordingSessionBackend { nowMs }
        val native = ServiceRedundantConnectionNative(
            backend = backend,
            establishTun = { 41 },
            prepare = ::prepared,
            probeSourceIpv4 = "10.200.0.2/32",
            epochNowMs = { nowMs },
            elapsedNowMs = { nowMs },
        )
        assertTrue(native.start("lease-a", RedundantSlot.A, byteArrayOf(1), probe()))
        assertTrue(native.activate("lease-a"))

        native.healthObservations()
        nowMs += 1_000
        native.healthObservations()
        nowMs += 3_000
        val timedOut = native.healthObservations().single()

        assertTrue(timedOut.probeFailed)
        assertTrue(timedOut.independentFailureSignal)
    }

    @Test
    fun preLaunchTrafficIsOutsideTheProbeFailureWindow() {
        var nowMs = 1_000_000L
        val backend = RecordingSessionBackend { nowMs }.also {
            it.countProbeSend = false
        }
        val native = ServiceRedundantConnectionNative(
            backend = backend,
            establishTun = { 41 },
            prepare = ::prepared,
            probeSourceIpv4 = "10.200.0.2/32",
            epochNowMs = { nowMs },
            elapsedNowMs = { nowMs },
        )
        assertTrue(native.start("lease-a", RedundantSlot.A, byteArrayOf(1), probe()))
        assertTrue(native.activate("lease-a"))

        native.healthObservations()
        backend.probeStatuses[requireNotNull(backend.latestProbeToken)] =
            NativeProbeStatus.SUCCEEDED
        nowMs += 1
        native.healthObservations()
        nowMs += 5_000
        backend.setUdpPackets(sent = 5, received = 0)
        native.healthObservations()
        nowMs += 4_000
        val timedOut = native.healthObservations().single()

        assertTrue(timedOut.probeFailed)
        assertFalse(timedOut.independentFailureSignal)
    }

    @Test
    fun productionNativePublishesBoundedSessionMetricsAcrossSlotSwitches() {
        val backend = RecordingSessionBackend()
        val native = ServiceRedundantConnectionNative(
            backend = backend,
            establishTun = { 41 },
            prepare = ::prepared,
            probeSourceIpv4 = "10.200.0.2/32",
        )
        assertTrue(native.start("lease-a", RedundantSlot.A, byteArrayOf(1), probe()))
        assertTrue(native.start("lease-b", RedundantSlot.B, byteArrayOf(2), probe()))
        assertTrue(native.activate("lease-b"))

        val metrics = requireNotNull(native.metrics(includeProbeTarget = true))

        assertEquals(22L, metrics.receivedBytes)
        assertEquals(14L, metrics.sentBytes)
        assertEquals(1_000_000L, metrics.latestHandshakeEpochMillis)
        assertEquals("127.0.0.1", metrics.probeTarget)
    }

    @Test
    fun confirmedRebindFailureIsAHardSlotFailure() {
        val backend = RecordingSessionBackend()
        val native = ServiceRedundantConnectionNative(
            backend = backend,
            establishTun = { 41 },
            prepare = ::prepared,
            probeSourceIpv4 = "10.200.0.2/32",
        )
        assertTrue(native.start("lease-a", RedundantSlot.A, byteArrayOf(1), probe()))
        backend.rebindFailures += 0

        assertFalse(native.rebind("lease-a"))
        assertTrue(native.healthObservations().single().hardFailure)
    }

    @Test
    fun nativeClosedSlotIsAnImmediateHardFailure() {
        val backend = RecordingSessionBackend()
        val native = ServiceRedundantConnectionNative(
            backend = backend,
            establishTun = { 41 },
            prepare = ::prepared,
            probeSourceIpv4 = "10.200.0.2/32",
        )
        assertTrue(native.start("lease-a", RedundantSlot.A, byteArrayOf(1), probe()))
        backend.metricsOverride = {
            """{"slots":[{"slot":0,"admitted":true,"closed":true,"latest_handshake_at_unix_ms":1000000,"telemetry":{"tun_read_bytes":7,"tun_write_bytes":11,"udp_send_packets":0,"udp_receive_packets":0}}]}"""
        }

        val observation = native.healthObservations().single()

        assertTrue(observation.hardFailure)
        assertEquals(BackendHealth.UNHEALTHY, observation.health)
    }

    @Test
    fun malformedNativeMetricsFailClosedOnlyAfterBoundedBudgetAndValidSnapshotResetsIt() {
        val backend = RecordingSessionBackend()
        val native = ServiceRedundantConnectionNative(
            backend = backend,
            establishTun = { 41 },
            prepare = ::prepared,
            probeSourceIpv4 = "10.200.0.2/32",
        )
        assertTrue(native.start("lease-a", RedundantSlot.A, byteArrayOf(1), probe()))
        backend.metricsOverride = { """{"slots":[]}""" }

        assertFalse(native.healthObservations().single().hardFailure)
        assertFalse(native.healthObservations().single().hardFailure)
        assertTrue(native.healthObservations().single().hardFailure)

        backend.metricsOverride = null
        assertFalse(native.healthObservations().single().hardFailure)
        backend.metricsOverride = { """{"slots":[{"slot":"0","admitted":"true"}]}""" }
        assertFalse(native.healthObservations().single().hardFailure)
    }

    private fun probe() = BackgroundRedundantHealthProbe(
        kind = "dns_a",
        targetIpv4 = "8.8.8.8",
        queryName = "nelomai.ru",
        timeoutMs = 4_000,
    )

    private fun suspectedFixture(): SuspectedFixture {
        val clock = TestDualClock(epochMs = 1_800_000_000_000L, elapsedMs = 10_000L)
        val backend = RecordingSessionBackend { clock.epochMs }
        val native = ServiceRedundantConnectionNative(
            backend = backend,
            establishTun = { 41 },
            prepare = ::prepared,
            probeSourceIpv4 = "10.200.0.2/32",
            epochNowMs = { clock.epochMs },
            elapsedNowMs = { clock.elapsedMs },
        )
        assertTrue(native.start("lease-a", RedundantSlot.A, byteArrayOf(1), probe()))
        assertTrue(native.activate("lease-a"))
        native.healthObservations()
        backend.probeStatuses[requireNotNull(backend.latestProbeToken)] = NativeProbeStatus.FAILED
        clock.elapsedMs += 1L
        assertTrue(native.healthObservations().single().independentFailureSignal)
        return SuspectedFixture(native, backend)
    }

    private fun prepared(@Suppress("UNUSED_PARAMETER") configuration: ByteArray): PreparedRedundantConfiguration =
        PreparedRedundantConfiguration(
            config = Config.parse(ByteArrayInputStream(TEST_CONFIG.toByteArray())),
            userspace = "private_key=redacted-for-fake".toByteArray(),
        )

    private companion object {
        val TEST_CONFIG = """
            [Interface]
            PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
            Address = 10.200.0.2/32

            [Peer]
            PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
            AllowedIPs = 0.0.0.0/0
            Endpoint = 127.0.0.1:10001
        """.trimIndent()
    }
}

private data class SuspectedFixture(
    val native: ServiceRedundantConnectionNative,
    val backend: RecordingSessionBackend,
)

private data class TestDualClock(
    var epochMs: Long,
    var elapsedMs: Long,
)

private class RecordingSessionBackend(
    private val nowMs: () -> Long = { 1_000_000L },
) : RedundantSessionBackend {
    val primarySlots = mutableListOf<Int>()
    val additionalSlots = mutableListOf<Int>()
    val activeSlots = mutableListOf<Int>()
    val probeStatuses = mutableMapOf<Long, NativeProbeStatus>()
    val rebindFailures = mutableSetOf<Int>()
    var latestProbeToken: Long? = null
    var countProbeSend = true
    var metricsOverride: (() -> String?)? = null
    private val admitted = mutableSetOf<Int>()
    private var nextToken = 1L

    override fun start(tunFd: Int, primaryConfiguration: ByteArray): NativeSession? =
        start(tunFd, 0, primaryConfiguration)

    override fun start(
        tunFd: Int,
        primarySlot: Int,
        primaryConfiguration: ByteArray,
    ): NativeSession {
        primarySlots += primarySlot
        admitted += primarySlot
        primaryConfiguration.fill(0)
        return NativeSession(7)
    }

    override fun startSlot(
        session: NativeSession,
        slot: Int,
        configuration: ByteArray,
    ): Boolean {
        additionalSlots += slot
        admitted += slot
        configuration.fill(0)
        return true
    }

    override fun switchActive(session: NativeSession, slot: Int): Boolean = true.also {
        activeSlots += slot
    }

    override fun stopSlot(session: NativeSession, slot: Int): Boolean = admitted.remove(slot)

    override fun rebind(session: NativeSession, slot: Int): Boolean =
        slot in admitted && slot !in rebindFailures

    override fun startProbe(
        session: NativeSession,
        slot: Int,
        template: NativeDnsProbeTemplate,
    ): Long = nextToken++.also {
        if (countProbeSend) udpSendPackets += 1
        latestProbeToken = it
        probeStatuses[it] = NativeProbeStatus.PENDING
    }

    override fun probeStatus(session: NativeSession, token: Long): NativeProbeStatus =
        probeStatuses[token] ?: NativeProbeStatus.UNKNOWN

    override fun cancelProbe(session: NativeSession, token: Long): Boolean =
        probeStatuses.remove(token) != null

    override fun metrics(session: NativeSession): String? {
        val override = metricsOverride
        if (override != null) return override()
        return admitted.sorted().joinToString(
            prefix = "{\"slots\":[",
            postfix = "]}",
        ) { slot ->
            """{"slot":$slot,"admitted":true,"closed":false,"latest_handshake_at_unix_ms":${nowMs()},"telemetry":{"tun_read_bytes":7,"tun_write_bytes":11,"udp_send_packets":$udpSendPackets,"udp_receive_packets":$udpReceivePackets}}"""
        }
    }

    override fun close(session: NativeSession) {
        admitted.clear()
    }

    fun setUdpPackets(sent: Long, received: Long) {
        udpSendPackets = sent
        udpReceivePackets = received
    }

    private var udpSendPackets = 0L
    private var udpReceivePackets = 0L
}
