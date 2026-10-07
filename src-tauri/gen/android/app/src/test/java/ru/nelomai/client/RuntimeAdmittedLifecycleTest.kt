package ru.nelomai.client

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.Looper
import org.junit.Assert.*
import org.junit.Before
import org.junit.After
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28], shadows = [AdmittedRustShadow::class, KeyringContextShadow::class])
class RuntimeAdmittedLifecycleTest {
    @After fun cleanProcess() = resetRuntimeProcessForTest()
    @Before fun admittedProcess() {
        resetRuntimeProcessForTest()
        AdmittedRustShadow.calls.clear()
        val selected = RuntimeSelectionV1("latest", "0.3.3", "0.3.3", 1L, null, "admitted-test")
        RuntimeProcessSelection.claim(selected)
        RuntimeProcessSelection.markAdmitted()
        // Only JNI admission is unavailable on the host JVM. The subsequent
        // Activity, generated lifecycle, Binder snapshot and bootstrap are real.
        RuntimeEntrypoint::class.java.getDeclaredField("attached").apply {
            isAccessible = true; setBoolean(null, true)
        }
        bindRecoveryOwnerForTest(selected = selected)
    }

    @Test fun admittedReopenRetainsNativeLifecycleAndSuperclassState() {
        val controller = Robolectric.buildActivity(LatestRuntimeActivity::class.java, Intent()).setup()
        val activity = controller.get()
        shadowOf(Looper.getMainLooper()).idle()
        assertFalse(activity.isFinishing)
        activity.onWindowFocusChanged(true)
        activity.onLowMemory()
        controller.newIntent(Intent())
        val saved = Bundle()
        controller.saveInstanceState(saved).pause().stop().destroy()
        assertTrue(saved.containsKey("__wryActivityId"))
        for (callback in listOf("create", "focus", "lowMemory", "newIntent", "save", "destroy", "webviewDestroy")) {
            assertEquals("native callback $callback", 1, AdmittedRustShadow.calls.count { it == callback })
        }
        assertNull(activity.findViewById<android.widget.Button>(0x00d10007))
        assertNotNull(activity.getPluginManager())
        val reopened = Robolectric.buildActivity(LatestRuntimeActivity::class.java, Intent()).setup(saved)
        assertEquals(2, AdmittedRustShadow.calls.count { it == "create" })
        reopened.pause().stop().destroy()
    }

    @Test fun admittedBootstrapOpensSelectedActivityWithoutAnotherEndpoint() {
        val controller = Robolectric.buildActivity(RuntimeBootstrapActivity::class.java).setup()
        shadowOf(Looper.getMainLooper()).idle()
        val launch = shadowOf(controller.get()).nextStartedActivity
        assertEquals("ru.nelomai.client.LatestRuntimeActivity", launch.component?.className)
        assertFalse(launch.hasExtra("runtime_endpoint_v1"))
        assertFalse(launch.hasExtra("runtime_bootstrap_v1"))
        assertTrue(controller.get().isFinishing)
        controller.pause().stop().destroy()
    }
}

// Replace only unavailable JNI boundaries; the generated Wry/Tauri methods run.
@Implements(Rust::class)
@Suppress("UNUSED_PARAMETER")
class AdmittedRustShadow {
    companion object {
        val calls = mutableListOf<String>()
        @JvmStatic @Implementation fun __staticInitializer__() = Unit
        @JvmStatic @Implementation fun onActivityCreate(activity: WryActivity) { calls += "create" }
        @JvmStatic @Implementation fun onWindowFocusChanged(activity: WryActivity, focus: Boolean) { calls += "focus" }
        @JvmStatic @Implementation fun onActivitySaveInstanceState() { calls += "save" }
        @JvmStatic @Implementation fun onActivityDestroy(activity: WryActivity) { calls += "destroy" }
        @JvmStatic @Implementation fun onWebviewDestroy(activity: WryActivity, id: String) { calls += "webviewDestroy" }
        @JvmStatic @Implementation fun onActivityLowMemory() { calls += "lowMemory" }
        @JvmStatic @Implementation fun onNewIntent(intent: Intent) { calls += "newIntent" }
        @JvmStatic @Implementation fun create() = Unit
        @JvmStatic @Implementation fun wryCreate() = Unit
        @JvmStatic @Implementation fun start() = Unit
        @JvmStatic @Implementation fun resume() = Unit
        @JvmStatic @Implementation fun pause() = Unit
        @JvmStatic @Implementation fun stop() = Unit
    }
}

@Implements(io.crates.keyring.Keyring.Companion::class)
@Suppress("UNUSED_PARAMETER")
class KeyringContextShadow {
    @Implementation fun initializeNdkContext(context: Context) = Unit
}
