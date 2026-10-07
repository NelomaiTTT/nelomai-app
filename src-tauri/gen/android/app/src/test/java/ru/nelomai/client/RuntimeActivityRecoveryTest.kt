package ru.nelomai.client

import android.content.Intent
import android.content.ComponentName
import android.os.Binder
import android.os.Bundle
import android.os.Looper
import android.os.Parcel
import android.os.ParcelFileDescriptor
import android.widget.Button
import org.junit.Assert.*
import org.junit.Before
import org.junit.After
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowProcess
import org.robolectric.shadows.ShadowLog
import java.time.Duration

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [24, 28])
class RuntimeActivityRecoveryTest {
    @Before @After fun freshProcess() = resetRuntimeProcessForTest()
    @Test fun coldRecreationCompletesAndroidLifecycleWithoutNativeLoadOrAutomaticDispatch() {
        val controller = Robolectric.buildActivity(LatestRuntimeActivity::class.java, Intent())
            .setup(Bundle().apply { putInt("__wryActivityId", 123) })
        val activity = controller.get()
        assertTrue(ShadowLog.getLogsForTag("NelomaiStartup").any {
            it.msg == "code=startup.runtime.admission_missing"
        })
        activity.onWindowFocusChanged(true)
        activity.onLowMemory()
        activity.onConfigurationChanged(android.content.res.Configuration(activity.resources.configuration))
        controller.newIntent(Intent())
        val saved = Bundle()
        controller.saveInstanceState(saved).pause().stop().restart().start().resume()
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMinutes(1))
        assertNull(shadowOf(activity).nextStartedActivity)
        assertNull(shadowOf(activity.application).nextStartedService)
        assertTrue(shadowOf(activity.application).boundServiceConnections.isEmpty())
        controller.pause().stop().destroy()
        assertFalse(ShadowProcess.wasKilled(android.os.Process.myPid()))

        val restored = Robolectric.buildActivity(LatestRuntimeActivity::class.java, Intent()).setup(saved)
        assertNull(shadowOf(restored.get()).nextStartedActivity)
        restored.get().finish()
        restored.pause().stop().destroy()
        assertFalse(ShadowProcess.wasKilled(android.os.Process.myPid()))
    }

    @Test fun retryDispatchesExistingBootstrapExactlyOnceAndCarriesNoOldLaunchData() {
        val controller = Robolectric.buildActivity(LatestRuntimeActivity::class.java,
            Intent().putExtra("runtime_bootstrap_v1", "stale-data")).setup()
        val activity = controller.get()
        val retry = activity.findViewById<Button>(0x00d10007)
        assertNotNull("missing manual Retry", retry)
        assertNull(shadowOf(activity).nextStartedActivity)
        retry.performClick()
        retry.performClick()
        activity.onWindowFocusChanged(true)
        val launch = shadowOf(activity).nextStartedActivity
        assertEquals("ru.nelomai.client.RuntimeBootstrapActivity", launch.component?.className)
        assertFalse(launch.hasExtra("runtime_bootstrap_v1"))
        assertFalse(launch.hasExtra("runtime_endpoint_v1"))
        assertFalse(launch.hasExtra("runtime_selection_v1"))
        assertNull(shadowOf(activity).nextStartedActivity)
        assertTrue(activity.isFinishing)
        controller.pause().stop().destroy()
        assertFalse(ShadowProcess.wasKilled(android.os.Process.myPid()))
    }

    @Test fun partialNativeAttachmentHasNoRetryAndCannotAttemptAnotherAttachment() {
        val selected = RuntimeSelectionV1("latest", "0.3.3", "0.3.3", 1L, null, "partial-test")
        val pipe = ParcelFileDescriptor.createPipe()
        pipe[0].use { endpoint -> pipe[1].use {
            val launch = Intent().putExtra("runtime_selection_v1", RuntimeSelectionStore.encode(selected))
                .putExtra("runtime_endpoint_v1", endpoint).putExtra("runtime_bootstrap_v1", "{}")
            // A genuine native-load failure, after validation. No native mocking.
            assertTrue(runCatching { RuntimeEntrypoint.attachFromIntent(launch) }.exceptionOrNull()
                is UnsatisfiedLinkError)
            val controller = Robolectric.buildActivity(LatestRuntimeActivity::class.java).setup()
            assertTrue(ShadowLog.getLogsForTag("NelomaiStartup").any {
                it.msg == "code=startup.runtime.native_attachment_incomplete"
            })
            assertNull(controller.get().findViewById<Button>(0x00d10007))
            assertNotNull(controller.get().findViewById<Button>(0x00d10006))
            assertNull(shadowOf(controller.get()).nextStartedActivity)
            assertTrue(runCatching { RuntimeEntrypoint.attachFromIntent(launch) }.exceptionOrNull()
                is IllegalStateException)
            controller.get().finish()
            controller.pause().stop().destroy()
            assertFalse(ShadowProcess.wasKilled(android.os.Process.myPid()))
        } }
    }

    @Test fun bootstrapOwnerFailureOffersOneManualRetryAndNeverLoops() {
        bindRecoveryOwnerForTest(failRead = true)
        val controller = Robolectric.buildActivity(RuntimeBootstrapActivity::class.java).setup()
        val activity = controller.get()
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMinutes(1))
        assertNull(shadowOf(activity).nextStartedActivity)
        assertFalse(activity.isFinishing)
        val retry = activity.findViewById<Button>(0x00d10007)
        assertNotNull("owner failure must allow manual retry", retry)
        retry.performClick()
        retry.performClick()
        assertEquals("ru.nelomai.client.RuntimeBootstrapActivity",
            shadowOf(activity).nextStartedActivity.component?.className)
        assertNull(shadowOf(activity).nextStartedActivity)
        controller.pause().stop().destroy()
    }

    @Test fun restoringFailedBootstrapDoesNotRetryOwnerWithoutAnotherClick() {
        var reads = 0
        bindRecoveryOwnerForTest(failRead = true, onRequest = { reads++ })
        val controller = Robolectric.buildActivity(RuntimeBootstrapActivity::class.java).setup()
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals(1, reads)
        val saved = Bundle()
        controller.saveInstanceState(saved).pause().stop().destroy()
        val restored = Robolectric.buildActivity(RuntimeBootstrapActivity::class.java).setup(saved)
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMinutes(1))
        assertEquals("recreation must retain failure rather than retry owner", 1, reads)
        val retry = restored.get().findViewById<Button>(0x00d10007)
        assertNotNull(retry)
        assertNull(shadowOf(restored.get()).nextStartedActivity)
        retry.performClick()
        assertEquals("ru.nelomai.client.RuntimeBootstrapActivity",
            shadowOf(restored.get()).nextStartedActivity.component?.className)
        restored.pause().stop().destroy()
    }

    @Test fun manualRetryCannotKillAnExistingDifferentRuntimeProcess() {
        val selected = RuntimeSelectionV1("latest", "0.3.3", "0.3.3", 1L, null, "current-owner")
        RuntimeProcessSelection.claim(selected.copy(incarnation = "already-loaded"))
        bindRecoveryOwnerForTest(selected = selected)
        val controller = Robolectric.buildActivity(RuntimeBootstrapActivity::class.java,
            Intent().putExtra("nelomai_manual_runtime_retry", true)).setup()
        shadowOf(Looper.getMainLooper()).idle()
        assertFalse(ShadowProcess.wasKilled(android.os.Process.myPid()))
        assertNull(shadowOf(controller.get()).nextStartedActivity)
        assertNull(controller.get().findViewById<Button>(0x00d10007))
        assertFalse(controller.get().isFinishing)
        controller.pause().stop().destroy()
    }

    @Test fun bootstrapPrepareFailureNeverOffersAnotherNativeAttach() {
        bindRecoveryOwnerForTest()
        val controller = Robolectric.buildActivity(RuntimeBootstrapActivity::class.java).setup()
        shadowOf(Looper.getMainLooper()).idle()
        assertFalse("bootstrap error must remain visible", controller.get().isFinishing)
        assertNotNull(controller.get().findViewById<Button>(0x00d10006))
        assertNull(controller.get().findViewById<Button>(0x00d10007))
        assertNull(shadowOf(controller.get()).nextStartedActivity)
        assertFalse(ShadowProcess.wasKilled(android.os.Process.myPid()))
        controller.pause().stop().destroy()
    }

    @Test fun failedRetryDispatchStaysVisibleAndCannotDispatchAgain() {
        val controller = Robolectric.buildActivity(RecoveryDispatchFailureActivity::class.java).setup()
        val activity = controller.get()
        ru.nelomai.runtime.v1.RuntimeActivityRecovery.showFailure(activity, true)
        val retry = activity.findViewById<Button>(0x00d10007)
        retry.performClick()
        retry.performClick()
        assertEquals(1, activity.attempts)
        assertFalse(retry.isEnabled)
        assertFalse(activity.isFinishing)
        assertNotNull(activity.findViewById<Button>(0x00d10006))
        controller.pause().stop().destroy()
    }
}

class RecoveryDispatchFailureActivity : android.app.Activity() {
    var attempts = 0
    override fun startActivity(intent: Intent) {
        attempts++
        throw android.content.ActivityNotFoundException("test dispatch failure")
    }
}

internal fun bindRecoveryOwnerForTest(failRead: Boolean = false,
        selected: RuntimeSelectionV1 = RuntimeSelectionV1("latest", "0.3.3", "0.3.3", 1L, null, "owner-test"),
        onRequest: () -> Unit = {}) {
        val application = RuntimeEnvironment.getApplication()
        shadowOf(application).setComponentNameAndServiceForBindService(
            ComponentName(application, RuntimeAuthBrokerService::class.java), object : Binder() {
                override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
                    data.enforceInterface(RuntimeOwnerProtocol.DESCRIPTOR)
                    onRequest()
                    val response = requireNotNull(reply)
                    if (failRead) {
                        response.writeException(IllegalStateException("owner unavailable"))
                    } else {
                        response.writeNoException()
                        if (code == RuntimeOwnerProtocol.SELECTION) {
                            response.writeString(RuntimeSelectionStore.encode(selected))
                        } else if (code == RuntimeOwnerProtocol.ATTACH) {
                            val pipe = ParcelFileDescriptor.createPipe()
                            pipe[0].use { endpoint -> pipe[1].use {
                                response.writeString("{}")
                                response.writeParcelable(endpoint, 0)
                            } }
                        } else return false
                    }
                    return true
                }
            })
    }

// Robolectric reuses the classloader; simulate process death without production reset APIs.
internal fun resetRuntimeProcessForTest() {
    for (type in listOf(RuntimeEntrypoint::class.java, RuntimeProcessSelection::class.java)) {
        for (field in type.declaredFields) {
            if (java.lang.reflect.Modifier.isStatic(field.modifiers) &&
                !java.lang.reflect.Modifier.isFinal(field.modifiers)) {
                field.isAccessible = true
                if (field.type == Boolean::class.javaPrimitiveType) field.setBoolean(null, false)
                else if (field.name == "loaded") field.set(null, null)
            }
        }
    }
}
