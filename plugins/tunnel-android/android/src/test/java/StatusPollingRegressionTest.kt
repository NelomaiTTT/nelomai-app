package ru.nelomai.tunnel

import android.content.ComponentName
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.content.ServiceConnection
import android.os.Binder
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.ResultReceiver
import java.time.Duration
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import ru.nelomai.runtime.v1.RuntimeServiceIntents

/** Existing public client API; only the remote Android process is simulated. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE)
class StatusPollingRegressionTest {
    @Test fun hundredPollsReuseOneServiceStartWithoutCachingStatus() {
        var starts = 0
        var binds = 0
        var unbinds = 0
        var observations = 0
        var callbacks = 0
        val handler = Handler(Looper.getMainLooper())
        lateinit var endpoint: Messenger
        fun respond(receiver: ResultReceiver) {
            observations++
            receiver.send(SERVICE_RESULT_OK, Bundle().apply {
                putString(EXTRA_STATE, SessionState.STOPPED.wireName)
                putLong(EXTRA_DURATION_MILLIS, observations.toLong())
                putBinder("status_endpoint", endpoint.binder)
                putLong("status_generation", 42L)
                putString("status_runtime", "${BuildConfig.RUNTIME_SLOT}/${BuildConfig.RUNTIME_VERSION}")
            })
        }
        endpoint = Messenger(object : Handler(Looper.getMainLooper()) {
            override fun handleMessage(message: Message) {
                @Suppress("DEPRECATION")
                val receiver = message.data.getParcelable<ResultReceiver>(EXTRA_RESULT_RECEIVER)!!
                respond(receiver)
            }
        })
        val host = object : ContextWrapper(RuntimeEnvironment.getApplication()) {
            override fun getApplicationContext(): Context = this
            override fun startService(intent: Intent): ComponentName {
                assertEquals(NelomaiVpnService.ACTION_CLIENT_STATUS, intent.action)
                starts++
                respond(intent.resultReceiver()!!)
                return ComponentName(packageName, RuntimeServiceIntents.VPN_COMPONENT)
            }
            override fun bindService(intent: Intent, connection: ServiceConnection, flags: Int): Boolean {
                binds++
                handler.post {
                    connection.onServiceConnected(
                        ComponentName(packageName, RuntimeServiceIntents.VPN_COMPONENT), Binder())
                }
                return true
            }
            override fun unbindService(connection: ServiceConnection) { unbinds++ }
        }
        try {
            repeat(100) { index ->
                TunnelServiceClient.status(host, TUNNEL_API_VERSION, { state, duration ->
                    assertEquals(SessionState.STOPPED, state)
                    assertEquals(index + 1L, duration)
                    callbacks++
                }, { fail(it) })
                shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(1))
            }
            assertEquals(100, callbacks)
            assertEquals(100, observations)
            assertEquals("NLM-013: status polling must not restart the service", 1, starts)
            assertEquals(1, binds)
            shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(5))
            assertEquals(1, unbinds)
        } finally {
            shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(31))
        }
    }
}
