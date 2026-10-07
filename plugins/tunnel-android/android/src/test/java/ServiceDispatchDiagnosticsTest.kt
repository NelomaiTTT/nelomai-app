package ru.nelomai.tunnel

import android.content.ComponentName
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.os.Looper
import java.time.Duration
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowLog

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE)
class ServiceDispatchDiagnosticsTest {
    private class RejectingHost : ContextWrapper(RuntimeEnvironment.getApplication()) {
        var starts = 0
        override fun getApplicationContext(): Context = this
        override fun startService(intent: Intent): ComponentName {
            starts++
            throw SecurityException("private-token-from-platform")
        }
        override fun startForegroundService(intent: Intent): ComponentName {
            starts++
            throw IllegalStateException("private-token-from-platform")
        }
    }

    @Test fun failedStopRecordsSafeDispatchStageAndClassWithoutChangingCallback() {
        val host = RejectingHost()
        val errors = mutableListOf<String>()
        TunnelServiceClient.stop(host, TUNNEL_API_VERSION, { _, _ -> fail("unexpected success") }, errors::add)
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(31))
        assertEquals(listOf("android_service_dispatch_unavailable"), errors)
        assertEquals(1, host.starts)
        assertSafeEvent("client_service.dispatch_failed", "SecurityException")
    }

    @Test fun failedForegroundStartRecordsDistinctStageWithoutRetryOrSecret() {
        val host = RejectingHost()
        val errors = mutableListOf<String>()
        val args = BeginConnectionIntentArgs().apply {
            apiVersion = TUNNEL_API_VERSION
            template.apply {
                deviceId = "11111111-1111-4111-8111-111111111111"
                accountScope = "private-account-scope"
                layer = "tic"
                ticConnectionMode = "dynamic"
                routeMode = "full"
                egressMode = "auto"
            }
        }
        TunnelServiceClient.beginConnectionIntent(host, args, { fail("unexpected success") }, errors::add)
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(31))
        assertEquals(listOf("android_service_dispatch_unavailable"), errors)
        assertEquals(1, host.starts)
        assertSafeEvent("client_service.foreground_dispatch_failed", "IllegalStateException")
    }

    @Test fun invalidAccessTokenRetainsItsMachineCodeAndTerminalPolicy() {
        val event = automaticDiagnosticsConnectionIntentEvent("terminal_failure", "invalid_access_token")
        val safe = JSONObject(automaticDiagnosticsSafeConnectionIntentLog(event.toString()).trim())
        assertEquals("invalid_access_token", safe.getString("code"))
        assertEquals("authorization", safe.getString("reason_class"))
        val request = StartFailureRequest("33333333-3333-4333-8333-333333333333",
            "11111111-1111-4111-8111-111111111111", "invalid_access_token", 100, false)
        assertEquals("invalid_access_token", StartFailureRequest.fromJson(request.toJson()).errorCode)
        assertEquals(ConnectionIntentDecision.TERMINAL, ConnectionIntentErrorPolicy().classify("invalid_access_token"))
        assertEquals("other", automaticDiagnosticsStartFailureCode("private-token-from-platform"))
    }

    private fun assertSafeEvent(event: String, type: String) {
        val records = ShadowLog.getLogsForTag("NelomaiTunnel")
        val record = records.single { it.msg.contains(event) }
        assertTrue(record.msg.contains("android_service_dispatch_unavailable"))
        assertTrue(record.msg.contains(type))
        assertNull(record.throwable)
        assertFalse(records.any { it.msg.contains("private-token") || it.msg.contains("private-account") })
    }
}
