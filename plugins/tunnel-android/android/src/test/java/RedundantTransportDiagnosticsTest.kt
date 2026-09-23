package ru.nelomai.tunnel

import java.io.ByteArrayInputStream
import java.io.File
import org.amnezia.awg.config.Config
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config as RoboConfig

@RunWith(RobolectricTestRunner::class)
@RoboConfig(sdk = [34], manifest = RoboConfig.NONE)
class RedundantTransportDiagnosticsTest {
    private var now = 0L
    private val backend = RecordingSessionBackend()
    private val context get() = RuntimeEnvironment.getApplication()
    private val logFile get() = File(AndroidRuntimeNamespace.directory(context), "diagnostics/android-tunnel.jsonl")

    @Before fun initializeLog() {
        TunnelLog.initialize(context)
        logFile.writeText("")
    }

    private fun native() = ServiceRedundantConnectionNative(
        backend, { 41 }, { PreparedRedundantConfiguration(
            Config.parse(ByteArrayInputStream(CONFIG.toByteArray())), byteArrayOf(1),
        ) }, "10.200.0.2/32", elapsedNowMs = { now },
    )

    private fun events(): List<JSONObject> = logFile.readLines().map(::JSONObject)
        .filter { it.optString("event") == "redundant.transport" }

    @Test fun startupAndPreCloseCountersSurviveInReportHelperLog() {
        val native = native()
        assertTrue(native.start("a", RedundantSlot.A, byteArrayOf(1), null))
        assertTrue(native.start("b", RedundantSlot.B, byteArrayOf(2), null))
        backend.setUdpPackets(19, 3)
        now = 5_000
        native.healthObservations()
        native.stop()
        val terminal = events().filter { it.optString("phase") == "before_stop" }
        assertEquals(2, terminal.size)
        assertEquals(setOf(0, 1), terminal.map { it.getInt("slot") }.toSet())
        terminal.forEach { assertEquals(19L, it.getLong("udp_send_packets")); assertEquals(3L, it.getLong("udp_receive_packets")) }
        // Exercise the actual report assembler after volatile VPN data is gone.
        val method = AutomaticDiagnostics.javaClass.declaredMethods.single { it.name == "buildReport" }
        method.isAccessible = true
        val epoch = System.currentTimeMillis() / 1000
        val report = method.invoke(AutomaticDiagnostics, context, "report", "tunnel_interrupted", "session", 1,
            epoch - 60, epoch + 60, false, null) as JSONObject
        assertTrue(report.getString("helper_log").contains("redundant.transport"))
        assertTrue(report.getString("helper_log").contains("before_stop"))
    }

    @Test fun samplingIsBoundedAndNeverWritesConfigurationOrEndpoint() {
        backend.metricsOverride = { """{"slots":[{"slot":0,"admitted":true,"configuration":"SECRET","telemetry":{"udp_send_packets":7,"udp_send_errors":1,"last_udp_send_errno":101,"endpoint":"SECRET","private_key":"SECRET"}}]}""" }
        val native = native()
        native.start("a", RedundantSlot.A, byteArrayOf(1), null)
        for (tick in 0L..120_000L step 100L) { now = tick; native.healthObservations() }
        val events = events()
        assertTrue(events.isNotEmpty())
        assertTrue("unbounded startup sampling: ${events.size}", events.size <= 8)
        assertEquals(101L, events.last().getLong("last_udp_send_errno"))
        assertFalse(logFile.readText().contains("SECRET"))
        val before = events.size
        now += 10_000; native.healthObservations()
        assertEquals(before, events().size)
    }

    @Test fun rebindRearmsBoundedSamplingAndLogsBothResults() {
        val native = native()
        native.start("a", RedundantSlot.A, byteArrayOf(1), null)
        now = 60_000
        assertTrue(native.rebind("a"))
        backend.rebindFailures += 0
        assertFalse(native.rebind("a"))
        val phases = events().map { it.getString("phase") }
        assertTrue(phases.contains("rebind_succeeded"))
        assertTrue(phases.contains("rebind_failed"))
        now += 5_000; native.healthObservations()
        assertEquals("sample", events().last().getString("phase"))
    }

    private companion object {
        val CONFIG = """
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
