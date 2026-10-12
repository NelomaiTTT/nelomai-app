package ru.nelomai.tunnel

import android.content.Intent
import android.net.VpnService
import android.os.Binder
import android.os.Bundle
import android.os.ResultReceiver
import android.os.SystemClock
import java.time.Duration
import java.util.concurrent.Executor
import java.util.concurrent.ExecutorService
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.LooperMode
import org.robolectric.shadows.ShadowSystemClock
import org.robolectric.util.ReflectionHelpers
import ru.nelomai.runtime.v1.RuntimeVpnHostV1

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE)
@LooperMode(LooperMode.Mode.PAUSED)
class OwnedPolicyCancellationServiceTest {
    @Test fun unknownCancelBurstHasBoundedRetentionAndFailsClosedForOverflowedId() = withService { f ->
        val delayed = listOf(f.request("unknown-0"), f.request("unknown-1999"), f.request("fresh-during-overflow"))
        repeat(2000) { f.cancel("unknown-$it") }
        assertTrue("unknown cancellation IDs retained without bound", f.retainedCount() <= 128)
        delayed.forEach(f::dispatch)
        assertEquals(List(3) { SERVICE_RESULT_ERROR to "redundant_policy_preflight_rejected" }, f.replies)
        assertTrue(f.jobs.isEmpty())
        assertEquals(1, f.native.tunStarts)
    }

    @Test fun expiryDropsOnlyTheOldRequestWindowAndAllowsFreshWork() = withService { f ->
        val expired = f.request("unknown-1999")
        repeat(2000) { f.cancel("unknown-$it") }
        ShadowSystemClock.advanceBy(Duration.ofMillis(30_001))
        f.dispatch(expired)
        assertEquals(listOf(SERVICE_RESULT_ERROR to "redundant_policy_preflight_rejected"), f.replies)
        assertEquals(1, f.native.tunStarts)
        f.replies.clear()
        f.dispatch(f.request("fresh"))
        f.runWork()
        assertEquals(listOf(SERVICE_RESULT_OK to "applied"), f.replies)
        assertTrue("expired cancellation IDs were never reclaimed", f.retainedCount() <= 2)
    }

    @Test fun cancelledBeforeDispatchNeverReplacesEitherNativeSlot() = withService { f ->
        val delayed = f.request("cancelled-before-dispatch")
        f.cancel("cancelled-before-dispatch")
        f.dispatch(delayed)
        assertEquals(listOf(SERVICE_RESULT_ERROR to "redundant_policy_preflight_rejected"), f.replies)
        assertTrue(f.jobs.isEmpty())
        assertEquals(1, f.native.tunStarts)
        assertTrue(f.native.coordinator.isRunning())
    }

    @Test fun rejectedAndCompletedRequestsDoNotAccumulateLateCancelIds() = withService { f ->
        for (rejected in listOf(true, false)) {
            val id = if (rejected) "rejected" else "completed"
            val request = f.request(id)
            if (rejected) request.putExtra(EXTRA_API_VERSION, -1)
            f.dispatch(request)
            if (!rejected) f.runWork()
            assertEquals(if (rejected) SERVICE_RESULT_ERROR else SERVICE_RESULT_OK, f.replies.last().first)
            val retained = f.retainedCount()
            repeat(20) { f.cancel(id) }
            assertEquals("late cancellation reintroduced a retired ID", retained, f.retainedCount())
            assertTrue(f.native.coordinator.isRunning())
        }
    }

    @Test fun activeCancellationCannotBeLostToUnknownCancelFlood() = withService { f ->
        f.native.duringEstablish = {
            if (f.native.tunStarts == 2) {
                repeat(2000) { f.cancel("unknown-$it") }
                f.cancel("active")
            }
        }
        f.dispatch(f.request("active"))
        f.runWork()
        assertEquals(listOf(SERVICE_RESULT_OK to "failed"), f.replies)
        assertFalse(f.native.coordinator.isRunning())
        assertFalse(f.native.native.isUsable("lease-a"))
        assertEquals(1, f.native.backend.primarySlots.size)
        assertTrue("completed/unknown cancellations retained without bound", f.retainedCount() <= 128)
    }

    private fun withService(test: (Fixture) -> Unit) {
        val host = Robolectric.buildService(VpnService::class.java).create()
        val service = NelomaiVpnService(object : RuntimeVpnHostV1 {
            override val service = host.get()
            override fun builder(beforeEstablish: (VpnService.Builder) -> Unit) = service.Builder().also(beforeEstablish)
        })
        val fixture = Fixture(service)
        try { test(fixture) } finally {
            fixture.native.native.closeForStop()
            ReflectionHelpers.getField<ExecutorService>(service, "redundantExecutor").shutdownNow()
            ReflectionHelpers.getField<ExecutorService>(service, "credentialExecutor").shutdownNow()
            host.destroy()
        }
    }

    private class Fixture(val service: NelomaiVpnService) {
        val native = OwnedRedundantPolicyTest.Fixture()
        val jobs = mutableListOf<Runnable>()
        val replies = mutableListOf<Pair<Int, String?>>()
        init {
            ReflectionHelpers.setField(service, "recoveryStore", native.store)
            ReflectionHelpers.setField(service, "connectionIntentCoordinator", AndroidConnectionIntentCoordinator(native.store))
            ReflectionHelpers.setField(service, "redundantWork", RedundantVpnWorkDispatcher(Executor { jobs += it }))
            ReflectionHelpers.getField<RedundantVpnOwnerSlot>(service, "redundantVpnOwnerSlot")
                .install(native.coordinator, "operation")
        }
        fun cancel(id: String) { service.onStartCommand(Intent(NelomaiVpnService.ACTION_CANCEL_OWNED_REDUNDANT_POLICY)
            .putExtra(EXTRA_CLIENT_OPERATION_ID, id), 0, 1) }
        fun dispatch(request: Intent) { service.onStartCommand(request, 0, 1) }
        fun runWork() { assertEquals(1, jobs.size); jobs.removeAt(0).run() }
        fun request(id: String): Intent = Intent(NelomaiVpnService.ACTION_APPLY_OWNED_REDUNDANT_POLICY)
            .putExtra(EXTRA_API_VERSION, TUNNEL_API_VERSION)
            .putExtra(EXTRA_CLIENT_OPERATION_ID, id)
            .putExtra(EXTRA_POLICY_SESSION_ID, native.scope.sessionId)
            .putExtra(EXTRA_POLICY_DEADLINE, SystemClock.elapsedRealtime() + 30_000)
            .putExtra(EXTRA_POLICY_REPLY_OWNER, Bundle().apply { putBinder("owner", Binder()) })
            .putExtra(EXTRA_QUICK_CONNECTION, QuickConnectionArgs().also {
                it.leaseId = native.scope.leaseId; it.layer = native.scope.layer
                it.ticConnectionMode = native.scope.ticConnectionMode; it.routeMode = native.scope.routeMode
                it.egressMode = native.scope.egressMode; it.allowAlternate = false
            }.toBundle())
            .putExtra(EXTRA_OPTIONS, native.policy.toTunnelOptionsArgs().toBundle())
            .putExtra(EXTRA_RESULT_RECEIVER, object : ResultReceiver(null) {
                override fun onReceiveResult(resultCode: Int, resultData: Bundle?) {
                    replies += resultCode to resultData?.getString(
                        if (resultCode == SERVICE_RESULT_OK) EXTRA_POLICY_OUTCOME else EXTRA_ERROR_CODE)
                }
            })
        fun retainedCount(): Int {
            val state = ReflectionHelpers.getField<Any>(service, "ownedPolicyCancelled")
            // Inspect retained memory without adding a test-only production getter.
            return if (state is Collection<*>) state.size else {
                (state.javaClass.getDeclaredField("recent").apply { isAccessible = true }.get(state) as Map<*, *>).size
            }
        }
    }
}
