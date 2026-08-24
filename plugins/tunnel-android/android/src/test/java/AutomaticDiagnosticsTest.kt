package ru.nelomai.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

class AutomaticDiagnosticsTest {
    @Test
    fun procStatusMemoryParserReadsCurrentAndPeakRssSafely() {
        val status = """
            Name: nelomai
            VmHWM: 456789 kB
            VmRSS: 345678 kB
        """.trimIndent()

        assertEquals(
            345678L * 1024L,
            automaticDiagnosticsStatusMemoryBytes(status, "VmRSS"),
        )
        assertEquals(
            456789L * 1024L,
            automaticDiagnosticsStatusMemoryBytes(status, "VmHWM"),
        )
        assertNull(automaticDiagnosticsStatusMemoryBytes(status, "VmPeak"))
    }

    @Test
    fun startFailureRequestRoundTripsItsDurableIdentityAndState() {
        val request = StartFailureRequest(
            reportId = "33333333-3333-4333-8333-333333333333",
            deviceId = "11111111-1111-4111-8111-111111111111",
            errorCode = "configuration_fetch_failed",
            queuedAt = 1_000,
            sent = false,
        )

        val restored = StartFailureRequest.fromJson(request.toJson())

        assertEquals(request, restored)
        assertEquals(
            automaticDiagnosticsPendingReportName(
                1_000,
                request.deviceId,
                request.reportId,
            ),
            restored.reportName,
        )
        assertTrue(StartFailureRequest.fromJson(request.copy(sent = true).toJson()).sent)
    }

    @Test
    fun retryScheduleCapsAtSixHours() {
        assertEquals(5 * 60L, automaticDiagnosticsRetryDelaySeconds(0))
        assertEquals(30 * 60L, automaticDiagnosticsRetryDelaySeconds(1))
        assertEquals(2 * 60 * 60L, automaticDiagnosticsRetryDelaySeconds(2))
        assertEquals(6 * 60 * 60L, automaticDiagnosticsRetryDelaySeconds(3))
        assertEquals(6 * 60 * 60L, automaticDiagnosticsRetryDelaySeconds(20))
    }

    @Test
    fun startFailureReportIsDeduplicatedWhilePendingAndRateLimitedAfterUpload() {
        assertTrue(
            automaticDiagnosticsShouldQueueStartFailure(
                pendingExists = false,
                lastQueuedAt = 0,
                now = 1_000,
                cooldownSeconds = 900,
            ),
        )
        assertTrue(
            !automaticDiagnosticsShouldQueueStartFailure(
                pendingExists = true,
                lastQueuedAt = 100,
                now = 2_000,
                cooldownSeconds = 900,
            ),
        )
        assertTrue(
            !automaticDiagnosticsShouldQueueStartFailure(
                pendingExists = false,
                lastQueuedAt = 1_000,
                now = 1_899,
                cooldownSeconds = 900,
            ),
        )
        assertTrue(
            automaticDiagnosticsShouldQueueStartFailure(
                pendingExists = false,
                lastQueuedAt = 1_000,
                now = 1_900,
                cooldownSeconds = 900,
            ),
        )
    }

    @Test
    fun startFailureReportsAndPendingWorkAreScopedToTheDevice() {
        val firstDevice = "11111111-1111-4111-8111-111111111111"
        val secondDevice = "22222222-2222-4222-8222-222222222222"
        val reportName = automaticDiagnosticsPendingReportName(
            1_000,
            firstDevice,
            "33333333-3333-4333-8333-333333333333",
        )

        assertEquals(firstDevice, automaticDiagnosticsPendingReportScope(reportName))
        assertTrue(
            automaticDiagnosticsHasPendingWork(
                emptyList(),
                stoppedSessionPending = false,
                pendingSeal = false,
                deviceId = firstDevice,
                pendingStartFailure = true,
            ),
        )
        assertTrue(
            !automaticDiagnosticsHasPendingWork(
                listOf(reportName),
                stoppedSessionPending = false,
                pendingSeal = false,
                deviceId = secondDevice,
                pendingStartFailure = false,
            ),
        )
    }

    @Test
    fun retentionPrunesOnlySentReportsOlderThanTheLatestThree() {
        val sent = listOf("0001.json.gz", "0002.json.gz", "0003.json.gz", "0004.json.gz")
        val pending = setOf("pending-0001.json.gz", "pending-0002.json.gz")

        val deleted = automaticDiagnosticsSentReportsToPrune(sent)

        assertEquals(setOf("0001.json.gz"), deleted)
        assertTrue(deleted.intersect(pending).isEmpty())
    }

    @Test
    fun reportLogContainsOnlyTheCurrentTunnelInterval() {
        val logs = """
            {"timestamp_unix":99,"kind":"before"}
            {"timestamp_unix":100,"kind":"start"}
            {"timestamp":"1970-01-01T00:02:30Z","event":"middle"}
            {"timestamp_unix":201,"kind":"after"}
        """.trimIndent()

        val filtered = automaticDiagnosticsFilterIntervalLog(logs, 100, 200)

        assertTrue(filtered.contains("start"))
        assertTrue(filtered.contains("middle"))
        assertTrue(!filtered.contains("before"))
        assertTrue(!filtered.contains("after"))
    }

    @Test
    fun startupStagesAreKeptAlongsideTheTunnelInterval() {
        val combined = automaticDiagnosticsCombineApplicationLogs(
            "{\"kind\":\"connection.started\"}\n",
            "{\"kind\":\"startup.android.activity_created\"}\n",
            1024,
        )

        assertTrue(combined.contains("connection.started"))
        assertTrue(combined.contains("startup.android.activity_created"))
    }

    @Test
    fun failedOldestReportDoesNotBlockNewerReports() {
        val reports = listOf("0001.json.gz", "0002.json.gz", "0003.json.gz")

        assertEquals("0001.json.gz", automaticDiagnosticsNextPendingReport(reports, null))
        assertEquals("0002.json.gz", automaticDiagnosticsNextPendingReport(reports, "0001.json.gz"))
        assertEquals("0003.json.gz", automaticDiagnosticsNextPendingReport(reports, "0002.json.gz"))
        assertEquals("0001.json.gz", automaticDiagnosticsNextPendingReport(reports, "0003.json.gz"))
        assertNull(automaticDiagnosticsNextPendingReport(emptyList(), "0001.json.gz"))
    }

    @Test
    fun stoppedSessionRemainsPendingWithoutAQueuedReport() {
        assertTrue(
            automaticDiagnosticsHasPendingWork(
                emptyList(),
                stoppedSessionPending = true,
                pendingSeal = false,
                deviceId = null,
            ),
        )
        assertTrue(
            automaticDiagnosticsHasPendingWork(
                emptyList(),
                stoppedSessionPending = false,
                pendingSeal = true,
                deviceId = null,
            ),
        )
    }

    @Test
    fun pendingReportsAreScopedToTheDeviceThatCreatedThem() {
        val firstDevice = "11111111-1111-4111-8111-111111111111"
        val secondDevice = "22222222-2222-4222-8222-222222222222"
        val report = automaticDiagnosticsPendingReportName(
            100,
            firstDevice,
            "33333333-3333-4333-8333-333333333333",
        )
        val unscoped = automaticDiagnosticsPendingReportName(
            101,
            null,
            "44444444-4444-4444-8444-444444444444",
        )

        assertEquals(firstDevice, automaticDiagnosticsPendingReportScope(report))
        assertNull(automaticDiagnosticsPendingReportScope(unscoped))
        assertTrue(
            automaticDiagnosticsHasPendingWork(
                listOf(report, unscoped),
                stoppedSessionPending = false,
                pendingSeal = false,
                deviceId = firstDevice,
            ),
        )
        assertTrue(
            !automaticDiagnosticsHasPendingWork(
                listOf(report, unscoped),
                stoppedSessionPending = false,
                pendingSeal = false,
                deviceId = secondDevice,
            ),
        )
    }

    @Test
    fun legacyProcessNameUsesProcCommandLineWithoutInventingVpnSuffix() {
        val packageName = "ru.nelomai.app"

        assertEquals(
            "$packageName:vpn",
            automaticDiagnosticsLegacyProcessName("$packageName:vpn\u0000ignored", packageName),
        )
        assertEquals(
            packageName,
            automaticDiagnosticsLegacyProcessName("$packageName\u0000ignored", packageName),
        )
        assertEquals(packageName, automaticDiagnosticsLegacyProcessName(null, packageName))
        assertEquals(
            packageName,
            automaticDiagnosticsLegacyProcessName("another.application", packageName),
        )
    }

    @Test
    fun tunnelStartMemoryDetailGateCapturesOneLargeGrowthOrAbsolutePeak() {
        val mebibyte = 1024L * 1024L
        val growing = TunnelStartMemoryDetailGate(100L * mebibyte)

        assertTrue(!growing.shouldCapture(355L * mebibyte))
        assertTrue(growing.shouldCapture(356L * mebibyte))
        assertTrue(!growing.shouldCapture(700L * mebibyte))

        val alreadyLarge = TunnelStartMemoryDetailGate(null)
        assertTrue(alreadyLarge.shouldCapture(512L * mebibyte))
        assertTrue(!alreadyLarge.shouldCapture(700L * mebibyte))
    }

    @Test
    fun tunnelStartMemoryDelayedStagesCoverTransientReleaseWindow() {
        assertEquals(
            listOf(
                "after_backend_100ms" to 100L,
                "after_backend_1s" to 1_000L,
                "after_backend_5s" to 5_000L,
            ),
            tunnelStartMemoryDelayedStages(),
        )
    }

    @Test
    fun tunnelSessionMemorySamplesCoverEarlyAndLongRunningUiGrowth() {
        assertEquals(
            listOf(60L, 5 * 60L, 15 * 60L, 30 * 60L, 60 * 60L, 3 * 60 * 60L),
            automaticDiagnosticsMemorySampleDelaysSeconds(),
        )
    }

    @Test
    fun androidMemoryStatsAreConvertedFromKibibytesWithoutThrowing() {
        val stats = mapOf(
            "summary.graphics" to "123",
            "summary.native-heap" to "invalid",
        )

        assertEquals(
            123L * 1024L,
            automaticDiagnosticsMemoryStatBytes(stats, "summary.graphics"),
        )
        assertNull(automaticDiagnosticsMemoryStatBytes(stats, "summary.native-heap"))
        assertNull(automaticDiagnosticsMemoryStatBytes(stats, "summary.system"))
    }

    @Test
    fun memoryGrowthTrackerCapturesCumulativeGrowthAndResetsAfterRelease() {
        val mebibyte = 1024L * 1024L
        val tracker = AutomaticDiagnosticsMemoryGrowthTracker(64L * mebibyte)

        assertTrue(!tracker.observe(100L * mebibyte))
        assertTrue(!tracker.observe(150L * mebibyte))
        assertTrue(tracker.observe(164L * mebibyte))
        assertTrue(!tracker.observe(120L * mebibyte))
        assertTrue(tracker.observe(184L * mebibyte))
    }

    @Test
    fun structuredMemoryComponentsKeepAndroidPssCategories() {
        val processes = JSONArray().put(
            JSONObject()
                .put("processId", 42L)
                .put("processName", "ru.nelomai.client:vpn")
                .put("currentResidentMemoryBytes", 400L)
                .put("pssJavaHeapBytes", 100L)
                .put("pssNativeHeapBytes", 200L)
                .put("pssGraphicsBytes", 50L),
        )

        val component = automaticDiagnosticsResourceComponents(processes).getJSONObject(0)

        assertEquals(100L, component.getLong("pss_java_heap_bytes"))
        assertEquals(200L, component.getLong("pss_native_heap_bytes"))
        assertEquals(50L, component.getLong("pss_graphics_bytes"))
    }

    @Test
    fun boundedMemoryTimelinePreservesSessionBaselineAndNewestSamples() {
        val samples = (1L..4L).map { timestamp ->
            JSONObject()
                .put("timestamp_unix", timestamp)
                .put("reason", "sample_$timestamp")
        }

        val bounded = automaticDiagnosticsBoundMemorySamples(samples, maximum = 3)

        assertEquals(
            listOf(1L, 3L, 4L),
            bounded.map { it.getLong("timestamp_unix") },
        )
    }

    @Test
    fun sealedMemoryTimelineKeepsOnlySamplesAfterTheClosedInterval() {
        val samples = listOf(99L, 100L, 101L).map { timestamp ->
            JSONObject()
                .put("timestamp_unix", timestamp)
                .put("reason", "sample_$timestamp")
        }

        val retained = automaticDiagnosticsMemorySamplesAfter(samples, endedAt = 100L)

        assertEquals(listOf(101L), retained.map { it.getLong("timestamp_unix") })
    }

    @Test
    fun oversizedReportCompactionPreservesMemoryTimeline() {
        val memorySamples = JSONArray().apply {
            put(JSONObject().put("timestamp_unix", 1L).put("reason", "baseline"))
            put(JSONObject().put("timestamp_unix", 2L).put("reason", "peak"))
        }
        val payload = JSONObject()
            .put("application_log", "a".repeat(900))
            .put("helper_log", "h".repeat(200))
            .put("network_incidents", "n".repeat(200))
            .put(
                "resource_usage",
                JSONObject().put("memory_samples", memorySamples),
            )

        val compacted = automaticDiagnosticsCompactReportToBytes(payload, maximum = 700)

        assertTrue(compacted.toString().toByteArray(Charsets.UTF_8).size <= 700)
        assertEquals(
            memorySamples.toString(),
            compacted.getJSONObject("resource_usage").getJSONArray("memory_samples").toString(),
        )
        assertEquals("h".repeat(200), compacted.getString("helper_log"))
        assertEquals("n".repeat(200), compacted.getString("network_incidents"))
        assertTrue(compacted.getString("application_log").length < 900)
    }

    @Test
    fun lifecycleGatePreventsSnapshotFromOverlappingSeal() {
        val gate = Any()
        val sealEntered = CountDownLatch(1)
        val releaseSeal = CountDownLatch(1)
        val snapshotAttempted = CountDownLatch(1)
        val snapshotEntered = CountDownLatch(1)
        val sealThread = thread(start = true) {
            automaticDiagnosticsRunWithLifecycleGate(gate) {
                sealEntered.countDown()
                releaseSeal.await(2, TimeUnit.SECONDS)
            }
        }
        assertTrue(sealEntered.await(2, TimeUnit.SECONDS))
        val snapshotThread = thread(start = true) {
            snapshotAttempted.countDown()
            automaticDiagnosticsRunWithLifecycleGate(gate) {
                snapshotEntered.countDown()
            }
        }

        assertTrue(snapshotAttempted.await(2, TimeUnit.SECONDS))
        assertTrue(!snapshotEntered.await(100, TimeUnit.MILLISECONDS))
        releaseSeal.countDown()
        assertTrue(snapshotEntered.await(2, TimeUnit.SECONDS))
        sealThread.join(2_000)
        snapshotThread.join(2_000)
        assertTrue(!sealThread.isAlive)
        assertTrue(!snapshotThread.isAlive)
    }

    @Test
    fun tunnelStartMemoryDiagnosticsCannotAbortTunnelStartup() {
        val failure = containTunnelStartMemoryDiagnosticsFailure {
            throw IllegalStateException("diagnostic failure")
        }

        assertEquals("diagnostic failure", failure?.message)
    }

    @Test
    fun optionalTunnelStartupDiagnosticsCannotFailRequiredStartupHooks() {
        var requiredRan = false
        var recordedFailure: Throwable? = null

        runTunnelStartupPostActions(
            required = { requiredRan = true },
            optionalDiagnostics = { throw IllegalStateException("schedule rejected") },
            onDiagnosticsFailure = { recordedFailure = it },
        )

        assertTrue(requiredRan)
        assertEquals("schedule rejected", recordedFailure?.message)
    }

    @Test
    fun optionalTunnelStartupDiagnosticsFailureReporterIsAlsoFailOpen() {
        runTunnelStartupPostActions(
            required = {},
            optionalDiagnostics = { throw IllegalStateException("schedule rejected") },
            onDiagnosticsFailure = { throw IllegalStateException("logger rejected") },
        )
    }
}
