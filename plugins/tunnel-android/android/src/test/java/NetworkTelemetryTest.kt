package ru.nelomai.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkTelemetryTest {
    @Test
    fun wireGuardCollectsPassiveTelemetryWithoutEnablingUdpRecovery() {
        assertEquals(
            NetworkTelemetryMode.PASSIVE,
            networkTelemetryMode("wireguard"),
        )
        assertEquals(
            NetworkTelemetryMode.UDP_RECOVERY,
            networkTelemetryMode("amneziawg_3"),
        )
        assertEquals(
            NetworkTelemetryMode.DISABLED,
            networkTelemetryMode("unsupported"),
        )
    }

    @Test
    fun passiveTelemetryUsesTenSecondCadenceWhileUdpRecoveryKeepsEveryTick() {
        assertTrue(
            shouldPollNetworkTelemetry(
                mode = NetworkTelemetryMode.PASSIVE,
                nowElapsedMillis = 20_000L,
                lastPollElapsedMillis = null,
            ),
        )
        assertFalse(
            shouldPollNetworkTelemetry(
                mode = NetworkTelemetryMode.PASSIVE,
                nowElapsedMillis = 20_000L,
                lastPollElapsedMillis = 15_000L,
            ),
        )
        assertTrue(
            shouldPollNetworkTelemetry(
                mode = NetworkTelemetryMode.PASSIVE,
                nowElapsedMillis = 25_000L,
                lastPollElapsedMillis = 15_000L,
            ),
        )
        assertTrue(
            shouldPollNetworkTelemetry(
                mode = NetworkTelemetryMode.UDP_RECOVERY,
                nowElapsedMillis = 20_000L,
                lastPollElapsedMillis = 19_999L,
            ),
        )
        assertFalse(
            shouldPollNetworkTelemetry(
                mode = NetworkTelemetryMode.DISABLED,
                nowElapsedMillis = 20_000L,
                lastPollElapsedMillis = null,
            ),
        )
    }

    @Test
    fun periodicPassiveSnapshotPersistsCurrentGoMemoryWithoutRecentSampleRing() {
        val details = networkTelemetrySnapshotDetails(
            reason = "periodic",
            sample = telemetrySampleWithGoMemory(),
            recentSamples = null,
        )

        assertTrue(shouldPersistPeriodicNetworkTelemetry(NetworkTelemetryMode.PASSIVE))
        assertFalse(shouldPersistPeriodicNetworkTelemetry(NetworkTelemetryMode.UDP_RECOVERY))
        assertEquals(1_048_576L, details["go_heap_alloc_bytes"])
        assertEquals(4_194_304L, details["go_heap_sys_bytes"])
        assertFalse(details.containsKey("samples"))
    }

    @Test
    fun parsesNativeTelemetryWithoutOptionalErrors() {
        val sample = NetworkTelemetry.fromJson(
            """{
                "tun_read_packets":4,"tun_read_bytes":512,"tun_read_errors":0,
                "tun_write_packets":3,"tun_write_bytes":384,"tun_write_errors":0,
                "udp_send_calls":2,"udp_send_packets":4,"udp_send_bytes":640,
                "udp_send_errors":0,"udp_receive_calls":2,"udp_receive_packets":3,
                "udp_receive_bytes":480,"udp_receive_errors":0,"local_port":51820,
                "last_tun_read_at_unix_ms":10,"last_tun_write_at_unix_ms":11,
                "last_udp_send_at_unix_ms":12,"last_udp_receive_at_unix_ms":13,
                "go_heap_alloc_bytes":1048576,"go_heap_sys_bytes":4194304,
                "go_heap_idle_bytes":2097152,"go_heap_inuse_bytes":2097152,
                "go_heap_released_bytes":1048576,"go_stack_inuse_bytes":524288,
                "go_gc_cycles":7,"go_memory_limit_bytes":268435456,
                "go_device_starts":2,"go_device_start_failures":1,
                "go_device_closes":1,"go_devices_starting":0,"go_active_devices":1
            }""".trimIndent(),
        )

        assertTrue(sample.tunReadBytes == 512L)
        assertTrue(sample.udpReceiveBytes == 480L)
        assertTrue(sample.localPort == 51820)
        assertTrue(sample.lastUdpSendError == null)
        assertTrue(sample.goHeapAllocBytes == 1048576L)
        assertTrue(sample.goHeapReleasedBytes == 1048576L)
        assertTrue(sample.goGcCycles == 7L)
        assertTrue(sample.goMemoryLimitBytes == 268435456L)
        assertTrue(sample.goDeviceStarts == 2L)
        assertTrue(sample.goDeviceStartFailures == 1L)
        assertTrue(sample.goDeviceCloses == 1L)
        assertTrue(sample.goDevicesStarting == 0L)
        assertTrue(sample.goActiveDevices == 1)
    }

    private fun telemetrySampleWithGoMemory(): NetworkTelemetry = NetworkTelemetry.fromJson(
        """{
            "tun_read_packets":4,"tun_read_bytes":512,"tun_read_errors":0,
            "tun_write_packets":3,"tun_write_bytes":384,"tun_write_errors":0,
            "udp_send_calls":2,"udp_send_packets":4,"udp_send_bytes":640,
            "udp_send_errors":0,"udp_receive_calls":2,"udp_receive_packets":3,
            "udp_receive_bytes":480,"udp_receive_errors":0,"local_port":51820,
            "last_tun_read_at_unix_ms":10,"last_tun_write_at_unix_ms":11,
            "last_udp_send_at_unix_ms":12,"last_udp_receive_at_unix_ms":13,
            "go_heap_alloc_bytes":1048576,"go_heap_sys_bytes":4194304,
            "go_heap_idle_bytes":2097152,"go_heap_inuse_bytes":2097152,
            "go_heap_released_bytes":1048576,"go_stack_inuse_bytes":524288,
            "go_gc_cycles":7,"go_memory_limit_bytes":268435456,
            "go_device_starts":2,"go_device_start_failures":1,
            "go_device_closes":1,"go_devices_starting":0,"go_active_devices":1
        }""".trimIndent(),
    )

    @Test
    fun parsesNativeTelemetryErrorDetails() {
        val sample = NetworkTelemetry.fromJson(
            """{
                "tun_read_packets":0,"tun_read_bytes":0,"tun_read_errors":0,
                "tun_write_packets":0,"tun_write_bytes":0,"tun_write_errors":0,
                "udp_send_calls":1,"udp_send_packets":0,"udp_send_bytes":0,
                "udp_send_errors":1,"udp_receive_calls":1,"udp_receive_packets":0,
                "udp_receive_bytes":0,"udp_receive_errors":1,"local_port":32000,
                "last_tun_read_at_unix_ms":0,"last_tun_write_at_unix_ms":0,
                "last_udp_send_at_unix_ms":20,"last_udp_receive_at_unix_ms":0,
                "last_udp_send_error":"write udp 10.0.0.2:32000->192.0.2.1:443: network unreachable",
                "last_udp_send_errno":101,
                "last_udp_receive_error":"read udp 10.0.0.2:32000: socket closed",
                "last_udp_receive_errno":9,
                "endpoint":"192.0.2.1:443"
            }""".trimIndent(),
        )

        assertTrue(sample.lastUdpSendError == "network_unreachable")
        assertTrue(sample.lastUdpReceiveError == "socket_closed")
        assertFalse(sample.lastUdpSendError?.contains("192.0.2.1") == true)
        assertTrue(sample.lastUdpSendErrno == 101)
        assertTrue(sample.lastUdpReceiveErrno == 9)
        assertTrue(sample.endpoint == "192.0.2.1:443")
    }

    @Test
    fun recoveryRequiresRecentTunDemandAndTunWriteSilence() {
        assertTrue(
            shouldRecoverUdpStall(
                transport = "amneziawg_3",
                uptimeMillis = 30_000,
                millisSinceTunActivity = 500,
                millisSinceTunWrite = 6_000,
                stallDurationMillis = 6_000,
                millisSinceRecovery = null,
                armed = true,
            ),
        )
        assertFalse(
            shouldRecoverUdpStall(
                transport = "amneziawg_3",
                uptimeMillis = 30_000,
                millisSinceTunActivity = 3_000,
                millisSinceTunWrite = 6_000,
                stallDurationMillis = 6_000,
                millisSinceRecovery = null,
                armed = true,
            ),
        )
        assertFalse(
            shouldRecoverUdpStall(
                transport = "amneziawg_3",
                uptimeMillis = 30_000,
                millisSinceTunActivity = 500,
                millisSinceTunWrite = 60_000,
                stallDurationMillis = 500,
                millisSinceRecovery = null,
                armed = true,
            ),
        )
        assertFalse(
            shouldRecoverUdpStall(
                transport = "amneziawg_3",
                uptimeMillis = 30_000,
                millisSinceTunActivity = 500,
                millisSinceTunWrite = 6_000,
                stallDurationMillis = 6_000,
                millisSinceRecovery = 30_000,
                armed = true,
            ),
        )
    }

    @Test
    fun recoveryNeverRunsForWireGuardOrWhileDisarmed() {
        assertFalse(
            shouldRecoverUdpStall(
                transport = "wireguard",
                uptimeMillis = 30_000,
                millisSinceTunActivity = 500,
                millisSinceTunWrite = 6_000,
                stallDurationMillis = 6_000,
                millisSinceRecovery = null,
                armed = true,
            ),
        )
        assertFalse(
            shouldRecoverUdpStall(
                transport = "amneziawg_3",
                uptimeMillis = 30_000,
                millisSinceTunActivity = 500,
                millisSinceTunWrite = 6_000,
                stallDurationMillis = 6_000,
                millisSinceRecovery = 70_000,
                armed = false,
            ),
        )
    }

    @Test
    fun recoveryCanRunForANewOutageAfterCooldown() {
        assertTrue(
            shouldRecoverUdpStall(
                transport = "amneziawg_3",
                uptimeMillis = 120_000,
                millisSinceTunActivity = 500,
                millisSinceTunWrite = 6_000,
                stallDurationMillis = 6_000,
                millisSinceRecovery = 70_000,
                armed = true,
            ),
        )
    }

    @Test
    fun failedControlProbeRebindsThenRetriesOnceAndStops() {
        assertTrue(
            udpControlProbeAction(
                stage = UdpControlProbeStage.BEFORE_REBIND,
                succeeded = false,
                recoveryAttempts = 0,
            ) == UdpControlProbeAction.REBIND,
        )
        assertTrue(
            udpControlProbeAction(
                stage = UdpControlProbeStage.AFTER_REBIND,
                succeeded = false,
                recoveryAttempts = 1,
            ) == UdpControlProbeAction.RETRY,
        )
        assertTrue(
            udpControlProbeAction(
                stage = UdpControlProbeStage.AFTER_REBIND,
                succeeded = false,
                recoveryAttempts = 2,
            ) == UdpControlProbeAction.STOP,
        )
    }

    @Test
    fun healthyOneWayTrafficDoesNotTriggerRebindAfterControlProbe() {
        assertTrue(
            udpControlProbeAction(
                stage = UdpControlProbeStage.BEFORE_REBIND,
                succeeded = true,
                recoveryAttempts = 0,
            ) == UdpControlProbeAction.MARK_TRANSPORT_REACHABLE,
        )
    }

    @Test
    fun controlProbeStartFailureRebindsImmediatelyUntilAttemptsAreExhausted() {
        assertTrue(
            udpControlProbeStartFailureAction(
                stage = UdpControlProbeStage.BEFORE_REBIND,
                recoveryAttempts = 0,
            ) == UdpControlProbeAction.REBIND,
        )
        assertTrue(
            udpControlProbeStartFailureAction(
                stage = UdpControlProbeStage.AFTER_REBIND,
                recoveryAttempts = 1,
            ) == UdpControlProbeAction.RETRY,
        )
        assertTrue(
            udpControlProbeStartFailureAction(
                stage = UdpControlProbeStage.BEFORE_REBIND,
                recoveryAttempts = 2,
            ) == UdpControlProbeAction.STOP,
        )
    }
}
