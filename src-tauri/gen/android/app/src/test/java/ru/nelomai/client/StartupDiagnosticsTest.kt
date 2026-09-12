package ru.nelomai.client

import android.app.ApplicationExitInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.assertFalse
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class StartupDiagnosticsTest {
  @get:Rule val temporary = TemporaryFolder()

  @Test
  fun freshFrontendMarkerSurvivesSecondPrecisionFileTimestamp() {
    val launch = 1_789_154_420_467L
    val marker = temporary.newFile()
    marker.writeText((launch + 333L).toString())
    assertTrue(marker.setLastModified(1_789_154_420_000L))
    assertTrue(frontendMarkerReady(marker, launch))
  }

  @Test
  fun oldLaunchMarkerCannotBecomeReadyFromFileTimestampAlone() {
    val launch = 1_789_154_420_467L
    val marker = temporary.newFile()
    // Even a failed deletion or a subsequently touched stale file is not readiness.
    marker.writeText((launch - 1L).toString())
    assertTrue(marker.setLastModified(launch + 1_000L))
    assertFalse(frontendMarkerReady(marker, launch))
  }

  @Test
  fun missingMalformedAndLegacySecondsMarkersAreNotReady() {
    val launch = 1_789_154_420_467L
    assertFalse(frontendMarkerReady(File(temporary.root, "missing"), launch))
    assertFalse(frontendMarkerReady(temporary.root, launch))
    val marker = temporary.newFile()
    for (content in listOf("", "partial", "1789154420", "9".repeat(100), "-1")) {
      marker.writeText(content)
      assertTrue(marker.setLastModified(launch + 1_000L))
      assertFalse(frontendMarkerReady(marker, launch))
    }
  }

  @Test
  fun diagnosticsFilesAndReadyMarkersStayInsideExactRuntimeNamespace() {
    val latest = startupDiagnosticsDirectory(File("/data/files"), "latest", "0.2.16")
    assertEquals(File("/data/files/runtime/latest/state/0.2.16/diagnostics"), latest)
    assertNotEquals(latest, startupDiagnosticsDirectory(File("/data/files"), "stable", "0.2.16"))
    assertNotEquals(latest, startupDiagnosticsDirectory(File("/data/files"), "latest", "0.2.17"))
  }

  @Test
  fun activityLifecycleMarkersDistinguishForegroundAndBackgroundTransitions() {
    assertEquals("startup.android.activity_started", startupActivityLifecycleKind("started"))
    assertEquals("startup.android.activity_resumed", startupActivityLifecycleKind("resumed"))
    assertEquals("startup.android.activity_paused", startupActivityLifecycleKind("paused"))
    assertEquals("startup.android.activity_stopped", startupActivityLifecycleKind("stopped"))
  }

  @Test
  fun exitReasonsKeepNativeCrashesAndMemoryPressureDistinct() {
    assertEquals(
      "native_crash",
      startupExitReason(ApplicationExitInfo.REASON_CRASH_NATIVE),
    )
    assertEquals(
      "low_memory",
      startupExitReason(ApplicationExitInfo.REASON_LOW_MEMORY),
    )
    assertEquals("unknown_999", startupExitReason(999))
  }
}
