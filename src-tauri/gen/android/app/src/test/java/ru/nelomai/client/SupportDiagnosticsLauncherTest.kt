package ru.nelomai.client

import android.content.Intent
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

@RunWith(org.robolectric.RobolectricTestRunner::class)
@Config(sdk = [28])
class SupportDiagnosticsLauncherTest {
    @Test fun coldShortcutNeverStartsOrBindsTheRuntimeOwner() {
        val controller = Robolectric.buildActivity(MainActivity::class.java,
            Intent().putExtra("nelomai_support_diagnostics", true).putExtra("support_code", "ignored-extra"))
        val activity = controller.setup().get()
        activity.onWindowFocusChanged(true)
        assertEquals("ru.nelomai.client.SupportDiagnosticsActivity", shadowOf(activity).nextStartedActivity.component?.className)
        assertTrue(activity.isFinishing)
        assertNull(shadowOf(activity.application).nextStartedService)
        assertTrue(shadowOf(activity.application).boundServiceConnections.isEmpty())
    }

    @Test fun reusedLauncherRoutesShortcutBeforeAnyOwnerRead() {
        val controller = Robolectric.buildActivity(MainActivity::class.java).create().start().resume()
        controller.newIntent(Intent().putExtra("nelomai_support_diagnostics", true))
        val activity = controller.get()
        activity.onWindowFocusChanged(true)
        assertEquals("ru.nelomai.client.SupportDiagnosticsActivity", shadowOf(activity).nextStartedActivity.component?.className)
        assertNull(shadowOf(activity.application).nextStartedService)
        assertTrue(shadowOf(activity.application).boundServiceConnections.isEmpty())
        controller.pause().stop().destroy()
    }
}
