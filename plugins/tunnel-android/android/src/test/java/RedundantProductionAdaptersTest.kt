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
            nowMs = { nowMs },
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

    private fun probe() = BackgroundRedundantHealthProbe(
        kind = "dns_a",
        targetIpv4 = "8.8.8.8",
        queryName = "nelomai.ru",
        timeoutMs = 4_000,
    )

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

private class RecordingSessionBackend(
    private val nowMs: () -> Long = { 1_000_000L },
) : RedundantSessionBackend {
    val primarySlots = mutableListOf<Int>()
    val additionalSlots = mutableListOf<Int>()
    val activeSlots = mutableListOf<Int>()
    val probeStatuses = mutableMapOf<Long, NativeProbeStatus>()
    val rebindFailures = mutableSetOf<Int>()
    var latestProbeToken: Long? = null
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
        latestProbeToken = it
        probeStatuses[it] = NativeProbeStatus.PENDING
    }

    override fun probeStatus(session: NativeSession, token: Long): NativeProbeStatus =
        probeStatuses[token] ?: NativeProbeStatus.UNKNOWN

    override fun cancelProbe(session: NativeSession, token: Long): Boolean =
        probeStatuses.remove(token) != null

    override fun metrics(session: NativeSession): String =
        admitted.sorted().joinToString(
            prefix = "{\"slots\":[",
            postfix = "]}",
        ) { slot ->
            """{"slot":$slot,"admitted":true,"latest_handshake_at_unix_ms":${nowMs()},"telemetry":{"tun_read_bytes":7,"tun_write_bytes":11,"udp_send_packets":1,"udp_receive_packets":1}}"""
        }

    override fun close(session: NativeSession) {
        admitted.clear()
    }
}
