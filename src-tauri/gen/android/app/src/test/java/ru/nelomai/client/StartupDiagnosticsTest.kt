package ru.nelomai.client

import android.app.ApplicationExitInfo
import org.junit.Assert.assertEquals
import org.junit.Test

class StartupDiagnosticsTest {
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
