package ru.nelomai.tunnel

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.ResultReceiver
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.LooperMode
import org.robolectric.util.ReflectionHelpers
import org.robolectric.shadows.ShadowLog
import ru.nelomai.runtime.v1.RuntimeVpnHostV1
import java.util.concurrent.Executor

/** Exercise the actual accepted Start callback, not a copy of its projection. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE)
@LooperMode(LooperMode.Mode.PAUSED)
class RedundantStartCancellationProjectionTest {
    @Test fun internalRestartCancellationPreservesThePreparedRecoveryRecord() = withPendingStart { f ->
        f.store.prepareRedundantTotalLoss(START, AndroidStartReplay("replacement", 2, "fp")).value()
        val prepared = f.store.read().value()
        assertTrue(f.gate.completeCancelled(START))
        assertEquals(prepared, f.store.read().value())
        assertEquals(SERVICE_RESULT_ERROR, f.receiver.code)
        assertEquals("tunnel_start_cancelled", f.receiver.data?.getString(EXTRA_ERROR_CODE))
        assertFalse(f.gate.completeCancelled(START))
        assertEquals(1, f.receiver.deliveries)
    }

    @Test fun explicitDurableStopIsNotRewrittenByTheCancelledStartCallback() = withPendingStart { f ->
        f.store.prepareRedundantTotalLoss(START, AndroidStartReplay("replacement", 2, "fp")).value()
        val stopped = f.store.cancelRedundantIntentAndDeferStop("user-stop", START).value()
        assertFalse(stopped.intent.desiredActive)
        assertNull(stopped.redundantTransaction?.retry?.totalLossRestartReplay)
        f.gate.completeCancelled(START)
        assertEquals(stopped, f.store.read().value())
        assertEquals(SERVICE_RESULT_ERROR, f.receiver.code)
    }

    @Test fun lateOldStartCancellationCannotDisarmAPromotedReplacement() = withPendingStart { f ->
        f.store.prepareRedundantTotalLoss(START, AndroidStartReplay("replacement", 2, "fp")).value()
        f.store.deferRedundantStop("internal-stop", START).value()
        f.store.updateRedundant(START) {
            it.copy(retry = it.retry.copy(stopState = RedundantStopState.ACKNOWLEDGED))
        }.value()
        val replacement = f.store.completeRedundantStop("internal-stop", START).value()
        assertTrue(replacement.intent.desiredActive)
        assertEquals("replacement", replacement.leaseTransaction?.startOperationId)
        f.gate.completeCancelled(START)
        assertEquals(replacement, f.store.read().value())
        assertEquals("tunnel_start_cancelled", f.receiver.data?.getString(EXTRA_ERROR_CODE))
    }

    @Test fun explicitStopDuringPreparedRestartDoesNotAttemptAnInvalidQuickProjection() = withPendingStart { f ->
        f.store.prepareRedundantTotalLoss(START, AndroidStartReplay("replacement", 2, "fp")).value()
        ShadowLog.clear()
        ReflectionHelpers.callInstanceMethod<Unit>(f.service, "handleClientStop",
            ReflectionHelpers.ClassParameter.from(Intent::class.java,
                Intent(NelomaiVpnService.ACTION_CLIENT_STOP)
                    .putExtra(EXTRA_API_VERSION, TUNNEL_API_VERSION)
                    .putExtra(EXTRA_RESULT_RECEIVER, Receiver())))
        val stopped = f.store.read().value()
        assertFalse(stopped.intent.desiredActive)
        assertNull(stopped.redundantTransaction?.retry?.totalLossRestartReplay)
        assertTrue("Stop must not issue a rejected recovery write",
            ShadowLog.getLogsForTag("NelomaiTunnel").none { it.msg.contains("recovery_save_failed") })
    }

    @Test fun cancelledClientStartUsesTheDurableStopInsteadOfAQuickProjection() = withPendingStart { f ->
        f.store.prepareRedundantTotalLoss(START, AndroidStartReplay("replacement", 2, "fp")).value()
        ShadowLog.clear()
        ReflectionHelpers.callInstanceMethod<Unit>(f.service, "beginCancelledRedundantStartStop",
            ReflectionHelpers.ClassParameter.from(String::class.java, START))
        assertDurablyStoppedWithoutRejectedWrites(f.store)
    }

    @Test fun logoutDuringPreparedRestartUsesTheDurableStopInsteadOfAQuickProjection() = withPendingStart { f ->
        val prepared = f.store.prepareRedundantTotalLoss(START, AndroidStartReplay("replacement", 2, "fp")).value()
        ShadowLog.clear()
        ReflectionHelpers.callInstanceMethod<Unit>(f.service, "beginBackgroundLogoutRedundantStop",
            ReflectionHelpers.ClassParameter.from(AndroidRedundantTransaction::class.java,
                requireNotNull(prepared.redundantTransaction)))
        assertDurablyStoppedWithoutRejectedWrites(f.store)
    }

    private fun assertDurablyStoppedWithoutRejectedWrites(store: AndroidRecoveryStore) {
        val stopped = store.read().value()
        assertFalse(stopped.intent.desiredActive)
        assertNull(stopped.redundantTransaction?.retry?.totalLossRestartReplay)
        assertTrue("Stop must not issue a rejected recovery write",
            ShadowLog.getLogsForTag("NelomaiTunnel").none { it.msg.contains("recovery_save_failed") })
    }

    private fun withPendingStart(action: (Fixture) -> Unit) {
        val store = AndroidRecoveryStore(MemoryBackend(), BootIdentityProvider { 7L })
        val oldStore = ReflectionHelpers.getField<AndroidRecoveryStore?>(AndroidRecoveryStores, "instance")
        val oldCredentials = ReflectionHelpers.getField<BackgroundCredentialStore?>(AndroidBackgroundCredentialStores, "instance")
        ReflectionHelpers.setField(AndroidRecoveryStores, "instance", store)
        ReflectionHelpers.setField(AndroidBackgroundCredentialStores, "instance", BackgroundCredentialStore(MemoryBackend()))
        try {
            val host = Robolectric.buildService(VpnService::class.java).create().get()
            val service = NelomaiVpnService(object : RuntimeVpnHostV1 {
                override val service = host
                override fun builder(beforeEstablish: (VpnService.Builder) -> Unit) = host.Builder()
            })
            ReflectionHelpers.setField(service, "recoveryStore", store)
            ReflectionHelpers.setField(service, "connectionIntentCoordinator", AndroidConnectionIntentCoordinator(store))
            ReflectionHelpers.setField(service, "redundantCancelTombstones",
                RedundantCancelTombstoneStore(TombstoneBackend()) { "stop-operation" })
            val generation = ReflectionHelpers.getField<Long>(service, "serviceGeneration")
            ReflectionHelpers.setField(service, "redundantTotalLossLifecycle", RedundantTotalLossLifecycle(
                currentServiceGeneration = { generation }, serviceActive = { true },
                barrierPending = { false }, logoutState = { BackgroundLogoutReadState.NONE },
                recovery = store::read, post = { it() }, retryCleanup = {},
                publishRestartStarting = {}, resume = {}, scheduleLogout = {},
                scheduleStateReadRetry = {}, stopIfIdle = {},
            ))
            val jobs = ArrayDeque<Runnable>()
            ReflectionHelpers.setField(service, "redundantWork", RedundantVpnWorkDispatcher(Executor(jobs::addLast)))
            val receiver = Receiver()
            val redundancy = RedundantStartArgs().apply {
                sessionId = SESSION; state = "allocated"; operationId = START
                requestFingerprint = "fingerprint"; virtualAddressV4 = "10.241.0.3/32"
                activeLeaseId = "lease-a"; localActiveLeaseId = "lease-a"
                primary = RedundantMemberArgs().apply { slot = "a"; leaseId = "lease-a" }
            }
            ReflectionHelpers.callInstanceMethod<Unit>(service, "handleClientStart",
                ReflectionHelpers.ClassParameter.from(Intent::class.java,
                    Intent(NelomaiVpnService.ACTION_CLIENT_START)
                        .putExtra(EXTRA_API_VERSION, TUNNEL_API_VERSION)
                        .putExtra(EXTRA_CLIENT_OPERATION_ID, START)
                        .putExtra(EXTRA_CONFIGURATION, byteArrayOf(1))
                        .putExtra(EXTRA_OPTIONS, TunnelOptionsArgs().toBundle())
                        .putExtra(EXTRA_REDUNDANCY, redundancy.toBundle())
                        .putExtra(EXTRA_RESULT_RECEIVER, receiver)))
            val gate = ReflectionHelpers.getField<RedundantStartOperationGate>(service, "redundantStartOperation")
            assertTrue("Start must have registered its real callback", gate.hasPending())
            assertNull(receiver.code)
            // The queued native worker does not run: the fault is after admission
            // and before its readiness callback, with a real persisted transaction.
            store.beginRedundant(AndroidRedundantTransaction(desiredActive = true,
                template = AndroidIntentTemplate(DEVICE, "scope", "stray", "dynamic", "standalone", "ipv4", true),
                sessionId = SESSION, slotALeaseId = "lease-a", slotBLeaseId = null,
                localActiveLeaseId = "lease-a", standbyDesired = false,
                roleGeneration = 0, membershipGeneration = 0,
                startOperationId = START, startRequestFingerprint = "fingerprint")).value()
            action(Fixture(service, store, gate, receiver))
        } finally {
            ReflectionHelpers.setField(AndroidRecoveryStores, "instance", oldStore)
            ReflectionHelpers.setField(AndroidBackgroundCredentialStores, "instance", oldCredentials)
        }
    }

    private data class Fixture(val service: NelomaiVpnService, val store: AndroidRecoveryStore, val gate: RedundantStartOperationGate, val receiver: Receiver)
    private class Receiver : ResultReceiver(null) {
        var code: Int? = null
        var data: Bundle? = null
        var deliveries = 0
        override fun onReceiveResult(resultCode: Int, resultData: Bundle?) {
            code = resultCode; data = resultData; deliveries++
        }
    }
    private class MemoryBackend : EncryptedRecordBackend {
        private var bytes: ByteArray? = null
        override fun read() = bytes?.copyOf()
        override fun write(plaintext: ByteArray): Boolean { bytes = plaintext.copyOf(); return true }
    }
    private class TombstoneBackend : RedundantCancelTombstoneBackend {
        private var record: String? = null
        override fun read() = record
        override fun compareAndWrite(expected: String?, value: String): Boolean {
            if (record != expected) return false
            record = value
            return true
        }
        override fun compareAndClear(expected: String): Boolean {
            if (record != expected) return false
            record = null
            return true
        }
    }
    private fun RecoveryStoreResult<AndroidRecoveryEnvelope>.value(): AndroidRecoveryEnvelope = when (this) {
        is RecoveryStoreResult.Success -> value
        is RecoveryStoreResult.Failure -> throw AssertionError(code)
    }
    companion object {
        private const val START = "33333333-3333-4333-8333-333333333333"
        private const val SESSION = "22222222-2222-4222-8222-222222222222"
        private const val DEVICE = "11111111-1111-4111-8111-111111111111"
    }
}
