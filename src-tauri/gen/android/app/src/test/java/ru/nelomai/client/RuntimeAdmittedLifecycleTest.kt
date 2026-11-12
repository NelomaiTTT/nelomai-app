package ru.nelomai.client

import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Binder
import android.os.Bundle
import android.os.DeadObjectException
import android.os.Looper
import android.os.Parcel
import android.os.Process
import android.widget.Button
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
import ru.nelomai.runtime.v1.RuntimeActivityRecovery

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28], shadows = [AdmittedRustShadow::class, KeyringContextShadow::class, RuntimeUpdateNativeShadow::class])
class RuntimeAdmittedLifecycleTest {
    private val selected = RuntimeSelectionV1("latest", "0.3.3", "0.3.3", 1L, null, "admitted-test")
    @After fun cleanProcess() = resetRuntimeProcessForTest()
    @Before fun admittedProcess() {
        resetRuntimeProcessForTest()
        AdmittedRustShadow.calls.clear()
        RuntimeUpdateNativeShadow.events.clear()
        RuntimeEntrypoint::class.java.declaredFields.firstOrNull { it.name == "updateLifecycle" }?.let {
            it.isAccessible = true
            it.set(null, it.type.getDeclaredConstructor().newInstance())
        }
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

    @Test fun replacementBrokerRelaunchesTheFocusedRuntimeOnlyOnce() {
        val controller = Robolectric.buildActivity(LatestRuntimeActivity::class.java, Intent()).setup()
        val activity = controller.get()
        shadowOf(Looper.getMainLooper()).idle()
        controller.windowFocusChanged(true)
        reconnect(activity, selected)
        assertNull(shadowOf(activity).nextStartedActivity)
        reconnect(activity, selected.copy(incarnation = "replacement-broker"))
        val launch = shadowOf(activity).nextStartedActivity
        assertNotNull("a replacement broker must request a fresh runtime admission", launch)
        assertEquals(RuntimeBootstrapActivity::class.java.name, launch.component?.className)
        assertFalse(launch.hasExtra("runtime_endpoint_v1"))
        assertFalse(launch.hasExtra("nelomai_update_launch_session"))
        controller.windowFocusChanged(true)
        assertNull(shadowOf(activity).nextStartedActivity)
        assertFalse(org.robolectric.shadows.ShadowProcess.wasKilled(Process.myPid()))

        bindRecoveryOwnerForTest(selected = selected.copy(incarnation = "replacement-broker"))
        val bootstrap = Robolectric.buildActivity(RuntimeBootstrapActivity::class.java, launch).setup().windowFocusChanged(true)
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals(MainActivity::class.java.name, shadowOf(bootstrap.get()).nextStartedActivity?.component?.className)
        assertTrue(org.robolectric.shadows.ShadowProcess.wasKilled(Process.myPid()))
        assertNull(shadowOf(activity.application).nextStoppedService)
        bootstrap.pause().stop().destroy()
        controller.pause().stop().destroy()
    }

    @Test fun retryAfterRecoveryReadFailureCanReplaceTheAdmittedRuntime() {
        val controller = Robolectric.buildActivity(LatestRuntimeActivity::class.java, Intent()).setup()
        val activity = controller.get()
        shadowOf(Looper.getMainLooper()).idle()
        controller.windowFocusChanged(true)
        reconnect(activity, selected.copy(incarnation = "replacement-broker"))
        val recovery = shadowOf(activity).nextStartedActivity
        assertNotNull(recovery)

        bindRecoveryOwnerForTest(failRead = true)
        val failed = Robolectric.buildActivity(RuntimeBootstrapActivity::class.java, recovery).setup().windowFocusChanged(true)
        shadowOf(Looper.getMainLooper()).idle()
        failed.get().findViewById<Button>(0x00d10007).performClick()
        val retry = shadowOf(failed.get()).nextStartedActivity
        assertNotNull(retry)
        assertTrue(retry.flags and Intent.FLAG_ACTIVITY_FORWARD_RESULT != 0)
        assertFalse(retry.getBooleanExtra("nelomai_manual_runtime_retry", false))
        failed.pause().stop().destroy()

        bindRecoveryOwnerForTest(selected = selected.copy(incarnation = "healthy-broker"))
        val retried = Robolectric.buildActivity(RuntimeBootstrapActivity::class.java, retry).setup().windowFocusChanged(true)
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals(MainActivity::class.java.name, shadowOf(retried.get()).nextStartedActivity?.component?.className)
        assertTrue(org.robolectric.shadows.ShadowProcess.wasKilled(Process.myPid()))
        assertNull(shadowOf(activity.application).nextStoppedService)
        retried.pause().stop().destroy()
        controller.pause().stop().destroy()
    }

    @Test fun cancelingRecoveryAllowsTheNextBrokerConnectionToRecover() {
        val controller = Robolectric.buildActivity(LatestRuntimeActivity::class.java, Intent()).setup()
        val activity = controller.get()
        shadowOf(Looper.getMainLooper()).idle()
        controller.windowFocusChanged(true)
        reconnect(activity, selected.copy(incarnation = "replacement-broker"))
        val recovery = shadowOf(activity).nextStartedActivityForResult
        assertNotNull("recovery must deliver its result to the runtime", recovery)
        assertTrue("recovery must request a result", recovery.requestCode >= 0)
        controller.windowFocusChanged(false).pause().stop()
        shadowOf(activity).receiveResult(recovery.intent, Activity.RESULT_CANCELED, null)
        controller.restart().start().resume().windowFocusChanged(true)
        assertNull("canceling must not immediately reopen the same recovery",
            shadowOf(activity).nextStartedActivityForResult)

        reconnect(activity, selected.copy(incarnation = "healthy-broker"))
        val secondRecovery = shadowOf(activity).nextStartedActivityForResult
        assertEquals(RuntimeBootstrapActivity::class.java.name, secondRecovery?.intent?.component?.className)
        controller.windowFocusChanged(false).pause().stop()
        reconnect(activity, selected.copy(incarnation = "next-broker"))
        assertNull(shadowOf(activity).nextStartedActivityForResult)
        shadowOf(activity).receiveResult(secondRecovery.intent, Activity.RESULT_CANCELED, null)
        controller.restart().start().resume().windowFocusChanged(true)
        assertEquals(RuntimeBootstrapActivity::class.java.name,
            shadowOf(activity).nextStartedActivityForResult?.intent?.component?.className)
        controller.pause().stop().destroy()
    }

    @Test fun replacementBrokerInBackgroundWaitsForWindowFocus() {
        val controller = Robolectric.buildActivity(LatestRuntimeActivity::class.java, Intent()).setup()
        val activity = controller.get()
        shadowOf(Looper.getMainLooper()).idle()
        controller.windowFocusChanged(false).pause().stop()
        reconnect(activity, selected.copy(incarnation = "replacement-broker"))
        assertNull(shadowOf(activity).nextStartedActivity)
        assertFalse(org.robolectric.shadows.ShadowProcess.wasKilled(Process.myPid()))
        controller.start().resume()
        assertNull(shadowOf(activity).nextStartedActivity)
        controller.windowFocusChanged(true)
        assertEquals(RuntimeBootstrapActivity::class.java.name, shadowOf(activity).nextStartedActivity?.component?.className)
        controller.pause().stop().destroy()
    }

    @Test fun firstSelectionReadCanFindThatTheBrokerAlreadyRestarted() {
        bindRecoveryOwnerForTest(selected = selected.copy(incarnation = "replacement-broker"))
        val controller = Robolectric.buildActivity(LatestRuntimeActivity::class.java, Intent()).setup()
        shadowOf(Looper.getMainLooper()).idle()
        assertNull(shadowOf(controller.get()).nextStartedActivity)
        controller.windowFocusChanged(true)
        assertEquals(RuntimeBootstrapActivity::class.java.name,
            shadowOf(controller.get()).nextStartedActivity?.component?.className)
        controller.pause().stop().destroy()
    }

    @Test fun homeBeforeOwnerReplyDefersRuntimeReplacementUntilForeground() {
        val firstReplacement = selected.copy(incarnation = "first-replacement")
        var initialReads = 0
        bindRecoveryOwnerForTest(onRequest = {
            initialReads++
            throw DeadObjectException()
        })
        val recovery = Intent().putExtra(RuntimeActivityRecovery.OWNER_RECOVERY, true)
        val bootstrap = Robolectric.buildActivity(RuntimeBootstrapActivity::class.java, recovery)
            .setup().windowFocusChanged(true)
        val activity = bootstrap.get()
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals(1, initialReads)

        // Home can pause the Activity before the window reports focus loss.
        bootstrap.pause().stop()
        assertTrue(activity.hasWindowFocus())
        reconnect(activity, firstReplacement)
        assertFalse("late Binder response must not kill the background runtime",
            org.robolectric.shadows.ShadowProcess.wasKilled(Process.myPid()))
        assertNull(shadowOf(activity).nextStartedActivity)
        assertFalse(activity.isFinishing)
        bootstrap.windowFocusChanged(false)

        val current = selected.copy(incarnation = "current-broker")
        var currentReads = 0
        reconnect(activity, current) { currentReads++ }
        bootstrap.restart().start().resume()
        assertEquals(1, currentReads)
        assertNull(shadowOf(activity).nextStartedActivity)
        bootstrap.windowFocusChanged(true)
        assertEquals("refocus must read the current Binder", 2, currentReads)
        val handoff = shadowOf(activity).nextStartedActivity
        assertEquals(MainActivity::class.java.name, handoff?.component?.className)
        assertTrue(org.robolectric.shadows.ShadowProcess.wasKilled(Process.myPid()))
        bootstrap.windowFocusChanged(true)
        assertNull(shadowOf(activity).nextStartedActivity)
        assertNull(shadowOf(activity.application).nextStoppedService)
        bootstrap.pause().stop().destroy()

        // Robolectric keeps the process in the test JVM. Clear process-local
        // admission to follow the existing launcher and request a new socket.
        resetRuntimeProcessForTest()
        val requests = mutableListOf<Int>()
        bindRecoveryOwnerForTest(selected = current, onRequest = { requests += it })
        val launcher = Robolectric.buildActivity(MainActivity::class.java, handoff).setup()
            .windowFocusChanged(true)
        shadowOf(Looper.getMainLooper()).idle()
        val freshLaunch = shadowOf(launcher.get()).nextStartedActivity
        assertEquals(RuntimeBootstrapActivity::class.java.name, freshLaunch?.component?.className)
        launcher.pause().stop().destroy()
        val fresh = Robolectric.buildActivity(RuntimeBootstrapActivity::class.java, freshLaunch).setup()
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals(listOf(RuntimeOwnerProtocol.SELECTION, RuntimeOwnerProtocol.SELECTION, RuntimeOwnerProtocol.ATTACH), requests)
        fresh.pause().stop().destroy()
    }

    private fun reconnect(activity: Activity, next: RuntimeSelectionV1, onRead: () -> Unit = {}) {
        val connection = shadowOf(activity.application).boundServiceConnections.single()
        val component = ComponentName(activity, RuntimeAuthBrokerService::class.java)
        connection.onServiceDisconnected(component)
        connection.onServiceConnected(component, object : Binder() {
            override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
                assertEquals(RuntimeOwnerProtocol.SELECTION, code)
                data.enforceInterface(RuntimeOwnerProtocol.DESCRIPTOR)
                onRead()
                requireNotNull(reply).writeNoException()
                reply.writeString(RuntimeSelectionStore.encode(next))
                return true
            }
        })
        shadowOf(Looper.getMainLooper()).idle()
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
