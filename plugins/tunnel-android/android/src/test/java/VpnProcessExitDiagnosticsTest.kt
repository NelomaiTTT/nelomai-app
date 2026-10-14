package ru.nelomai.tunnel

import android.app.ActivityManager
import android.app.ApplicationExitInfo
import android.content.Context
import android.os.Process
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements
import org.robolectric.shadows.ShadowActivityManager
import java.io.File

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE,
    shadows = [VpnExitActivityManagerShadow::class, DiagnosticDirectorySyncShadow::class])
class VpnProcessExitDiagnosticsTest {
    private val context get() = RuntimeEnvironment.getApplication()
    private val preferences get() = context.getSharedPreferences(
        AndroidRuntimeNamespace.record("nelomai-automatic-diagnostics"), Context.MODE_PRIVATE,
    )

    @Before fun prepareSession() {
        org.robolectric.shadows.ShadowProcess.setPid(27418)
        preferences.edit().clear().putInt("session_process_id", 3380).commit()
        VpnExitActivityManagerShadow.failQuery = false
        VpnExitActivityManagerShadow.queries.clear()
        TunnelLog.initialize(context)
    }

    private fun report(trigger: String = "tunnel_interrupted"): JSONObject =
        AutomaticDiagnostics.javaClass.declaredMethods.single { it.name == "buildReport" }
            .apply { isAccessible = true }
            .invoke(AutomaticDiagnostics, context, "report", trigger, "session", 1,
                100L, 200L, false, "lease", null) as JSONObject

    private fun event(report: JSONObject): JSONObject =
        report.getString("helper_log").lineSequence().filter(String::isNotBlank)
            .mapNotNull { runCatching { JSONObject(it) }.getOrNull() }
            .single { it.optString("event") == "tunnel.previous_process_exit" }

    private fun exit(
        pid: Int = 3380,
        process: String = "${context.packageName}:vpn",
        timestamp: Long = 210_123,
        reason: Int = ApplicationExitInfo.REASON_CRASH_NATIVE,
        status: Int = 11,
    ) = ShadowActivityManager.ApplicationExitInfoBuilder.newBuilder()
        .setPid(pid).setProcessName(process).setTimestamp(timestamp)
        .setReason(reason).setStatus(status).setImportance(125)
        .setDescription("password=must_not_escape")
        .build().also { shadowOf(context.getSystemService(ActivityManager::class.java)).addApplicationExitInfo(it) }

    @Test fun actualReportQueriesPriorVpnPidDespiteNewerUiDeathsAndIncludesExitAfterLastLive() {
        exit()
        repeat(20) { exit(pid = 4000 + it, process = "${context.packageName}:runtime", timestamp = 220_000L + it) }
        val report = report()
        val event = event(report)
        assertEquals("available", event.getString("availability"))
        assertEquals("application_exit_info", event.getString("source"))
        assertEquals("vpn", event.getString("process"))
        assertEquals(3380, event.getInt("pid"))
        assertEquals("native_crash", event.getString("exit_reason"))
        assertEquals(ApplicationExitInfo.REASON_CRASH_NATIVE, event.getInt("exit_reason_code"))
        assertEquals(11, event.getInt("exit_status"))
        assertEquals(210_123L, event.getLong("exit_timestamp_unix_ms"))
        assertEquals(125, event.getInt("importance"))
        assertEquals(200L, report.getLong("interval_ended_at_unix"))
        assertEquals(listOf(Triple(context.packageName, 3380, 1)), VpnExitActivityManagerShadow.queries)
        assertFalse(report.toString().contains("must_not_escape"))
    }

    @Test fun staleExitWrongProcessAndFutureTimestampRemainUnavailable() {
        for ((process, timestamp) in listOf(
            "${context.packageName}:vpn" to 99_999L,
            "${context.packageName}:runtime" to 210_123L,
            "other.package:vpn" to 210_123L,
            "${context.packageName}:vpn" to Long.MAX_VALUE,
        )) {
            exit(process = process, timestamp = timestamp)
            val event = event(report())
            assertEquals("not_found", event.getString("availability"))
            assertFalse(event.has("exit_reason"))
        }
    }

    @Test fun missingPidDoesNotBorrowAnotherProcessExit() {
        preferences.edit().remove("session_process_id").commit()
        exit()
        val event = event(report())
        assertEquals("pid_unavailable", event.getString("availability"))
        assertFalse(event.has("exit_reason"))
        assertTrue(VpnExitActivityManagerShadow.queries.isEmpty())
    }

    @Test fun emptyHistoryAndPlatformFailureDoNotPreventReportOrLeakExceptionText() {
        assertEquals("not_found", event(report()).getString("availability"))
        VpnExitActivityManagerShadow.failQuery = true
        val report = report()
        assertEquals("query_failed", event(report).getString("availability"))
        assertEquals("SecurityException", event(report).getString("error_type"))
        assertFalse(report.toString().contains("must_not_escape"))
    }

    @Test fun signalLowMemoryFreezerAndUnknownReasonsRetainTheirRawSystemCodes() {
        for ((reason, name) in listOf(
            ApplicationExitInfo.REASON_SIGNALED to "signaled",
            ApplicationExitInfo.REASON_LOW_MEMORY to "low_memory",
            ApplicationExitInfo.REASON_FREEZER to "freezer",
            999 to "unknown",
        )) {
            exit(reason = reason, status = 9)
            val event = event(report())
            assertEquals(name, event.getString("exit_reason"))
            assertEquals(reason, event.getInt("exit_reason_code"))
            assertEquals(9, event.getInt("exit_status"))
            assertTrue(event.has("low_memory_kill_report_supported"))
        }
    }

    @Test fun normalStopAndCheckpointDoNotAttributePastProcessDeaths() {
        exit()
        for (trigger in listOf("tunnel_stopped", "six_hour_checkpoint")) {
            assertFalse(report(trigger).getString("helper_log").contains("tunnel.previous_process_exit"))
        }
        assertTrue(VpnExitActivityManagerShadow.queries.isEmpty())
    }

    @Test fun capturedExitIsAlsoPersistedForManualDiagnostics() {
        exit()
        val captured = event(report())
        val log = File(AndroidRuntimeNamespace.directory(context), "diagnostics/android-tunnel.jsonl")
        assertTrue("Manual diagnostics have no persisted VPN exit", log.isFile)
        val persisted = log.readLines().map(::JSONObject)
            .single { it.optString("event") == "tunnel.previous_process_exit" }
        assertEquals(captured.getInt("pid"), persisted.getInt("pid"))
        assertEquals(captured.getLong("exit_timestamp_unix_ms"), persisted.getLong("exit_timestamp_unix_ms"))
        assertEquals(captured.getString("exit_reason"), persisted.getString("exit_reason"))
    }

    @Test fun fullHelperLogKeepsExitWithinTheExistingUploadLimit() {
        exit()
        val directory = File(AndroidRuntimeNamespace.directory(context), "diagnostics").apply { mkdirs() }
        val line = JSONObject().put("timestamp", "1970-01-01T00:02:30Z")
            .put("event", "old_sample").put("details", "x".repeat(400)).toString() + "\n"
        for (name in listOf("android-tunnel.previous.jsonl", "android-tunnel.jsonl")) {
            File(directory, name).writeText(line.repeat(300))
        }
        val captured = report()
        assertTrue(captured.getString("helper_log").length <= 65_536)
        assertEquals("native_crash", event(captured).getString("exit_reason"))
    }

    @Test fun compressedPendingReportFreezesTheCapturedExitAcrossLaterHistoryChanges() {
        exit()
        val captured = report()
        val file = File(context.cacheDir, "captured-exit.json.gz")
        AutomaticDiagnostics.javaClass.declaredMethods.single { it.name == "writePendingReport" }
            .apply { isAccessible = true }.invoke(AutomaticDiagnostics, file, captured)
        exit(reason = ApplicationExitInfo.REASON_LOW_MEMORY)
        preferences.edit().remove("session_process_id").commit()
        val restored = AutomaticDiagnostics.javaClass.declaredMethods.single { it.name == "readPendingReport" }
            .apply { isAccessible = true }.invoke(AutomaticDiagnostics, file) as JSONObject
        assertEquals(event(captured).toString(), event(restored).toString())
        assertEquals("native_crash", event(restored).getString("exit_reason"))
        assertEquals(1, VpnExitActivityManagerShadow.queries.size)
    }

    @Test fun realSessionStartPersistsVpnPidAndTerminalSealRemovesIt() {
        preferences.edit().clear().commit()
        AutomaticDiagnostics.onTunnelStarted(context, "lease", "wireguard")
        try {
            assertEquals(Process.myPid(), preferences.getInt("session_process_id", 0))
        } finally {
            AutomaticDiagnostics.onTunnelStopped(context)
        }
        assertFalse(preferences.contains("session_process_id"))
    }
}

@Implements(ActivityManager::class)
class VpnExitActivityManagerShadow : ShadowActivityManager() {
    companion object {
        var failQuery = false
        val queries = mutableListOf<Triple<String?, Int, Int>>()
    }

    @Implementation fun getProcessMemoryInfo(pids: IntArray): Array<android.os.Debug.MemoryInfo> =
        Array(pids.size) { android.os.Debug.MemoryInfo() }

    @Implementation(minSdk = 30)
    override fun getHistoricalProcessExitReasons(packageName: String?, pid: Int, maxNum: Int): MutableList<*> {
        queries += Triple(packageName, pid, maxNum)
        if (failQuery) throw SecurityException("password=must_not_escape")
        return super.getHistoricalProcessExitReasons(packageName, pid, maxNum)
    }
}

// Robolectric cannot fsync directories. Keep file rename/compression/preferences
// real while supplying the unsupported android.system.Os boundary.
@Implements(android.system.Os::class)
@Suppress("UNUSED_PARAMETER")
class DiagnosticDirectorySyncShadow {
    companion object {
        @JvmStatic @Implementation
        fun open(path: String, flags: Int, mode: Int): java.io.FileDescriptor {
            assertTrue(File(path).isDirectory)
            return java.io.FileDescriptor()
        }

        @JvmStatic @Implementation fun fsync(descriptor: java.io.FileDescriptor) = Unit
        @JvmStatic @Implementation fun close(descriptor: java.io.FileDescriptor) = Unit
        @JvmStatic @Implementation fun rename(oldPath: String, newPath: String) {
            java.nio.file.Files.move(File(oldPath).toPath(), File(newPath).toPath(),
                java.nio.file.StandardCopyOption.REPLACE_EXISTING)
        }
    }
}

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28], manifest = Config.NONE)
class VpnProcessExitUnsupportedAndroidTest {
    @Test fun preAndroid11StillBuildsInterruptedReportWithoutCallingUnavailableApi() {
        val context = RuntimeEnvironment.getApplication()
        val report = AutomaticDiagnostics.javaClass.declaredMethods.single { it.name == "buildReport" }
            .apply { isAccessible = true }
            .invoke(AutomaticDiagnostics, context, "report", "tunnel_interrupted", "session", 1,
                100L, 200L, false, "lease", null) as JSONObject
        val event = report.getString("helper_log").lineSequence().filter(String::isNotBlank)
            .map(::JSONObject).single { it.optString("event") == "tunnel.previous_process_exit" }
        assertEquals("unsupported", event.getString("availability"))
        assertFalse(event.has("exit_reason"))
    }
}
