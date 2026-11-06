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
@Config(sdk = [28], shadows = [AdmittedRustShadow::class, KeyringContextShadow::class, RuntimeUpdateNativeShadow::class])
class RuntimeAdmittedLifecycleTest {
    @After fun cleanProcess() = resetRuntimeProcessForTest()
    @Before fun admittedProcess() {
        resetRuntimeProcessForTest()
        AdmittedRustShadow.calls.clear()
        RuntimeUpdateNativeShadow.events.clear()
        RuntimeEntrypoint::class.java.declaredFields.firstOrNull { it.name == "updateLifecycle" }?.let {
            it.isAccessible = true
            it.set(null, it.type.getDeclaredConstructor().newInstance())
        }
        val selected = RuntimeSelectionV1("latest", "0.3.3", "0.3.3", 1L, null, "admitted-test")
        RuntimeProcessSelection.claim(selected)
        RuntimeProcessSelection.markAdmitted()
        // Only JNI admission is unavailable on the host JVM. The subsequent
        // Activity, generated lifecycle, Binder snapshot and bootstrap are real.
        RuntimeEntrypoint::class.java.getDeclaredField("attached").apply {
            isAccessible = true; setBoolean(null, true)
        }
        RuntimeEntrypoint::class.java.getDeclaredField("updateProtocolVersion").apply { isAccessible = true; setInt(null, 2) }
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

    @Test fun oldActivityDestructionCannotRevokeReplacementForeground() {
        val old = Robolectric.buildActivity(LatestRuntimeActivity::class.java, Intent()).setup()
        old.pause().stop()
        val replacement = Robolectric.buildActivity(LatestRuntimeActivity::class.java, Intent()).setup()
        val before = RuntimeUpdateNativeShadow.events.toList()
        old.destroy()
        assertEquals("the old Activity cannot publish background for its replacement", before, RuntimeUpdateNativeShadow.events)
        assertTrue(RuntimeUpdateVisibility.isForeground(RuntimeUpdateVisibility.probe))
        replacement.pause().stop().destroy()
    }

    @Test fun finishedUiExitsRuntimeProcessWhileOrdinaryBackgroundKeepsIt() {
        val controller = Robolectric.buildActivity(LatestRuntimeActivity::class.java, Intent()).setup()
        controller.pause().stop()
        assertFalse(org.robolectric.shadows.ShadowProcess.wasKilled(android.os.Process.myPid()))
        controller.start().resume()
        assertEquals("true:false:null:2", RuntimeUpdateNativeShadow.events.last())
        controller.get().finish()
        controller.pause().stop().destroy()
        // Robolectric records killProcess without terminating this JVM. Do not
        // reuse its static admission/lifecycle after this point as a real launch.
        assertTrue(org.robolectric.shadows.ShadowProcess.wasKilled(android.os.Process.myPid()))
    }

    @Test fun legacyOwnerDoesNotUseNewContainerVisibilityOrNativeUpdaterAbi() {
        RuntimeEntrypoint::class.java.declaredFields.firstOrNull { it.name == "updateProtocolVersion" }?.apply {
            isAccessible = true; setInt(null, 1)
        }
        val controller = Robolectric.buildActivity(LatestRuntimeActivity::class.java, Intent()).setup()
        assertTrue("capability1 cannot use new updater lifecycle ABI", RuntimeUpdateNativeShadow.events.isEmpty())
        assertFalse(RuntimeUpdateVisibility.isForeground(RuntimeUpdateVisibility.probe))
        controller.pause().stop().destroy()
        assertTrue(RuntimeUpdateNativeShadow.events.isEmpty())
    }

    @Test fun admittedBootstrapOpensSelectedActivityWithoutAnotherEndpoint() {
        val controller = Robolectric.buildActivity(RuntimeBootstrapActivity::class.java,
            Intent().putExtra("nelomai_update_launch_session", "d65074d4-f6fe-4d7a-a7d4-0d01ac701c99")).setup()
        shadowOf(Looper.getMainLooper()).idle()
        val launch = shadowOf(controller.get()).nextStartedActivity
        assertEquals("ru.nelomai.client.LatestRuntimeActivity", launch.component?.className)
        assertFalse(launch.hasExtra("runtime_endpoint_v1"))
        assertFalse(launch.hasExtra("runtime_bootstrap_v1"))
        assertFalse("reopening the existing runtime must not reset deferral", launch.hasExtra("nelomai_update_launch_session"))
        assertTrue(controller.get().isFinishing)
        controller.pause().stop().destroy()
    }

    @Test fun onlyActualLauncherCreatesNewPromptSession() {
        for (action in listOf(Intent.ACTION_MAIN, null)) {
            val controller = Robolectric.buildActivity(MainActivity::class.java, Intent(action)).setup()
            controller.get().onWindowFocusChanged(true)
            shadowOf(Looper.getMainLooper()).idle()
            val launched = shadowOf(controller.get()).nextStartedActivity
            assertEquals("ru.nelomai.client.RuntimeBootstrapActivity", launched.component?.className)
            val session = launched.getStringExtra("nelomai_update_launch_session")
            if (action == Intent.ACTION_MAIN) assertNotNull("actual user launch needs a new prompt session", session)
            else assertNull("technical relaunch must keep the prior prompt session", session)
            controller.pause().stop().destroy()
        }
    }

    @Test fun realActivityChecksStartupAndForegroundWithoutBackgroundPollingOrDuplicateResume() {
        val controller = Robolectric.buildActivity(LatestRuntimeActivity::class.java, Intent()).setup()
        assertEquals(listOf("true:false:null:1"), RuntimeUpdateNativeShadow.events)
        assertTrue(RuntimeUpdateVisibility.isForeground(RuntimeUpdateVisibility.probe))
        org.robolectric.util.ReflectionHelpers.callInstanceMethod<Void>(controller.get(), "onResume")
        assertEquals(1, RuntimeUpdateNativeShadow.events.size)
        controller.pause().stop()
        assertFalse(RuntimeUpdateVisibility.isForeground(RuntimeUpdateVisibility.probe))
        assertEquals("false:false:null:0", RuntimeUpdateNativeShadow.events.last())
        val count = RuntimeUpdateNativeShadow.events.size
        shadowOf(Looper.getMainLooper()).idleFor(java.time.Duration.ofMinutes(31))
        assertEquals("background has no update scheduler", count, RuntimeUpdateNativeShadow.events.size)
        controller.start().resume()
        assertEquals("true:false:null:2", RuntimeUpdateNativeShadow.events.last())
        controller.pause().stop().destroy()
    }

    @Test fun rotationDoesNotBecomeForegroundCheckOrNewUserLaunch() {
        val intent = Intent().putExtra("nelomai_update_launch_session", "d65074d4-f6fe-4d7a-a7d4-0d01ac701c99")
        val controller = Robolectric.buildActivity(LatestRuntimeActivity::class.java, intent).setup()
        assertEquals("true:true:d65074d4-f6fe-4d7a-a7d4-0d01ac701c99:1", RuntimeUpdateNativeShadow.events.firstOrNull())
        val saved = Bundle()
        controller.saveInstanceState(saved)
        org.robolectric.util.ReflectionHelpers.setField(controller.get(), "mChangingConfigurations", true)
        controller.pause().stop().destroy()
        val recreated = Robolectric.buildActivity(LatestRuntimeActivity::class.java, intent).setup(saved)
        assertEquals("true:false:null:0", RuntimeUpdateNativeShadow.events.last())
        assertEquals(1, RuntimeUpdateNativeShadow.events.count { it.endsWith(":1") || it.endsWith(":2") })
        recreated.pause().stop().destroy()
    }
}

@Implements(RuntimeEntrypoint::class)
@Suppress("UNUSED_PARAMETER")
class RuntimeUpdateNativeShadow {
    companion object { val events = mutableListOf<String>() }
    @Implementation fun updateUi(foreground: Boolean, newUserLaunch: Boolean, session: String?, reason: Int) {
        events += "$foreground:$newUserLaunch:$session:$reason"
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
