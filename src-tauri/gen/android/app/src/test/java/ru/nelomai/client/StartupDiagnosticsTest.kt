package ru.nelomai.client

import android.app.ApplicationExitInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test
import java.io.File

class StartupDiagnosticsTest {
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
