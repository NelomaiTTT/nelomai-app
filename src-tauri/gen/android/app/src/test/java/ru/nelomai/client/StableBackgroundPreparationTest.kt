package ru.nelomai.client

import android.content.ComponentName
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.Messenger
import android.os.ResultReceiver
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.util.ReflectionHelpers
import ru.nelomai.runtime.v1.RuntimeServiceIntents
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class StableBackgroundPreparationTest {
    private class BindingContext(val mode: String) : ContextWrapper(RuntimeEnvironment.getApplication()) {
        val connected = CountDownLatch(1)
        var registered = false
        var binds = 0
        var unbinds = 0
        var received: String? = null
        val messenger = Messenger(Handler(Looper.getMainLooper()) { message ->
            received = message.data.getString(RuntimeServiceIntents.STABLE_PROVISION_REQUEST)
            @Suppress("DEPRECATION")
            val receiver = message.data.getParcelable<ResultReceiver>("result_receiver")!!
            if (mode != "timeout") receiver.send(if (mode == "reject") 2 else 1, Bundle())
            true
        })
        override fun bindService(intent: Intent, connection: ServiceConnection, flags: Int): Boolean {
            assertEquals(RuntimeServiceIntents.PREPARE_STABLE_BACKGROUND, intent.action)
            assertEquals(Context.BIND_AUTO_CREATE, flags)
            assertFalse(intent.hasExtra(RuntimeServiceIntents.STABLE_PROVISION_REQUEST))
            binds++; registered = true
            if (mode == "security") {
                connected.countDown()
                throw SecurityException("test permission denial")
            }
            val name = ComponentName(packageName, RuntimeVpnDispatcherService::class.java.name)
            when (mode) {
                "unavailable" -> Unit
                "death" -> connection.onBindingDied(name)
                else -> connection.onServiceConnected(name, messenger.binder)
            }
            connected.countDown()
            return mode != "unavailable"
        }
        override fun unbindService(connection: ServiceConnection) { unbinds++; registered = false }
        override fun startService(intent: Intent): ComponentName? = error("preparation advanced VPN startId")
    }

    private fun exercise(mode: String, timeoutMillis: Long = 3000) {
        val context = BindingContext(mode)
        val broker = RuntimeAuthBrokerService()
        ReflectionHelpers.setField(broker, "mBase", context)
        val callback = RuntimeNativeCallbacks(broker)
        val request = JSONObject().put("owner_operation", JSONObject()
            .put("expires_at_unix_ms", System.currentTimeMillis() + timeoutMillis).toString()).toString()
        val executor = Executors.newSingleThreadExecutor()
        try {
            val call = executor.submit<Unit> {
                val method = RuntimeNativeCallbacks::class.java.getDeclaredMethod("prepareStableBackground", String::class.java)
                method.isAccessible = true
                method.invoke(callback, request)
            }
            assertTrue(context.connected.await(2, TimeUnit.SECONDS))
            shadowOf(Looper.getMainLooper()).idle()
            if (mode == "success") {
                call.get(2, TimeUnit.SECONDS)
                assertEquals(request, context.received)
            } else assertThrows(java.util.concurrent.ExecutionException::class.java) { call.get(2, TimeUnit.SECONDS) }
            assertEquals(1, context.binds)
            assertEquals(1, context.unbinds)
            assertFalse(context.registered)
        } finally { executor.shutdownNow() }
    }

    @Test fun successfulPreparationBindsWithoutStartingAndAlwaysUnbinds() = exercise("success")
    @Test fun refusedPreparationUnbindsWithoutForcingVpnExit() = exercise("reject")
    @Test fun failedBindingDoesNotLeaveAConnection() = exercise("unavailable")
    @Test fun deniedBindingAlsoReleasesItsSystemRegistration() = exercise("security")
    @Test fun deadBindingUnbindsAndDoesNotStartAnotherService() = exercise("death")
    @Test fun missingReplyRespectsTheOriginalDeadlineAndUnbinds() = exercise("timeout", 250)
}
