package ru.nelomai.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

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
}
