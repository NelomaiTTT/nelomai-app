package ru.nelomai.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AutomaticDiagnosticsTest {
    @Test
    fun retryScheduleCapsAtSixHours() {
        assertEquals(5 * 60L, automaticDiagnosticsRetryDelaySeconds(0))
        assertEquals(30 * 60L, automaticDiagnosticsRetryDelaySeconds(1))
        assertEquals(2 * 60 * 60L, automaticDiagnosticsRetryDelaySeconds(2))
        assertEquals(6 * 60 * 60L, automaticDiagnosticsRetryDelaySeconds(3))
        assertEquals(6 * 60 * 60L, automaticDiagnosticsRetryDelaySeconds(20))
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
