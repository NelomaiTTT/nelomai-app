package ru.nelomai.tunnel

import android.os.Looper
import android.os.Bundle
import android.os.ResultReceiver
import java.time.Duration
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE)
class RedundantStartProtocolTest {
    @Test fun coreStopScopeSurvivesServiceDispatchWhileExplicitStopRemainsUnscoped() {
        val context = RuntimeEnvironment.getApplication()
        for (legacyOnly in listOf(true, false)) {
            TunnelServiceClient.stop(context, TUNNEL_API_VERSION, { _, _ -> }, {}, legacyOnly = legacyOnly)
            val intent = shadowOf(context).nextStartedService
            assertEquals(NelomaiVpnService.ACTION_CLIENT_STOP, intent.action)
            assertEquals(legacyOnly, intent.getBooleanExtra(EXTRA_LEGACY_STOP_ONLY, false))
        }
    }
    @Test fun successfulLegacyStartDoesNotSendLateCancellationAndUsesFreshRequestIdentity() {
        val context = RuntimeEnvironment.getApplication()
        val errors = mutableListOf<String>()
        val successes = mutableListOf<SessionState>()
        fun start() = TunnelServiceClient.start(context,
            StartTunnelArgs().also { it.configuration = byteArrayOf(1) },
            { state, _ -> successes += state }, { errors += it })
        start()
        val first = shadowOf(context).nextStartedService
        @Suppress("DEPRECATION")
        val receiver = requireNotNull(first.getParcelableExtra<ResultReceiver>(EXTRA_RESULT_RECEIVER))
        receiver.send(SERVICE_RESULT_OK, Bundle().also {
            it.putString(EXTRA_STATE, SessionState.RUNNING.wireName)
        })
        shadowOf(Looper.getMainLooper()).idle()
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(30))
        assertEquals(listOf(SessionState.RUNNING), successes)
        assertEquals(emptyList<String>(), errors)
        assertNull(shadowOf(context).nextStartedService)
        start()
        val second = shadowOf(context).nextStartedService
        assertNotEquals(first.getStringExtra(EXTRA_CLIENT_OPERATION_ID),
            second.getStringExtra(EXTRA_CLIENT_OPERATION_ID))
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(30))
        val cancel = shadowOf(context).nextStartedService
        assertEquals(second.getStringExtra(EXTRA_CLIENT_OPERATION_ID),
            cancel.getStringExtra(EXTRA_CLIENT_OPERATION_ID))
    }

    @Test fun timeoutCancelsTheSameCanonicalOperationThatOwnsTheRedundantSession() {
        val context = RuntimeEnvironment.getApplication()
        val operation = "30000000-0000-4000-8000-000000000001"
        val args = StartTunnelArgs().also {
            it.configuration = byteArrayOf(1)
            it.redundancy = RedundantStartArgs().also { redundant ->
                redundant.operationId = operation
                redundant.sessionId = "20000000-0000-4000-8000-000000000001"
                redundant.state = "disabled"
                redundant.requestFingerprint = "a".repeat(64)
                redundant.virtualAddressV4 = "10.241.0.1/32"
                redundant.activeLeaseId = "10000000-0000-4000-8000-000000000001"
                redundant.localActiveLeaseId = redundant.activeLeaseId
                redundant.primary = RedundantMemberArgs().also { member ->
                    member.slot = "A"
                    member.leaseId = redundant.activeLeaseId
                }
            }
        }
        val errors = mutableListOf<String>()
        TunnelServiceClient.start(context, args, { _, _ -> }, { errors += it })
        val start = shadowOf(context).nextStartedService
        assertEquals(operation, start.getStringExtra(EXTRA_CLIENT_OPERATION_ID))
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(30))
        val cancel = shadowOf(context).nextStartedService
        assertEquals(NelomaiVpnService.ACTION_CANCEL_CLIENT_START, cancel.action)
        assertEquals(operation, cancel.getStringExtra(EXTRA_CLIENT_OPERATION_ID))
        assertEquals(listOf("tunnel_start_timeout"), errors)
    }

    @Test fun unresponsiveStatusStillReportsServiceTimeoutNotConnectionTimeout() {
        val context = RuntimeEnvironment.getApplication()
        val errors = mutableListOf<String>()
        TunnelServiceClient.status(context, TUNNEL_API_VERSION, { _, _ -> }, { errors += it })
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(30))
        assertEquals(listOf("tunnel_service_timeout"), errors)
    }
}
