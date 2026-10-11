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
import org.robolectric.util.ReflectionHelpers
import ru.nelomai.runtime.v1.RuntimeVpnHostV1

class LocalRestartAdmissionTest {
    @Test fun replacementExcludesCoordinatorReplayButDoesNotBlockUserCancellation() {
        val store = AndroidRecoveryStore(Record(), BootIdentityProvider { 1 })
        active(store)
        val coordinator = AndroidConnectionIntentCoordinator(store)
        val panel = object : AndroidConnectionIntentPanel {
            override fun reconcile(transaction: AndroidLeaseTransaction, cancelIfAbsent: Boolean): BackgroundReconcileResult = error("unexpected replay")
            override fun start(template: AndroidIntentTemplate, transaction: AndroidLeaseTransaction): BackgroundStartResult = error("unexpected lease acquisition")
            override fun syncBindingPreferences(template: AndroidIntentTemplate) = error("unexpected preference update")
            override fun stop(leaseId: String, operationId: String, failureCode: String?) = error("unexpected server cleanup")
        }
        val runtime = object : AndroidConnectionIntentRuntime {
            override fun start(result: BackgroundStartResult, operationId: String, isCurrent: () -> Boolean) = error("unexpected restart")
            override fun stop() = error("unexpected local cleanup")
            override fun isRunning() = true
        }
        assertTrue(coordinator.beginLocalRestart())
        assertFalse(coordinator.beginLocalRestart())
        assertEquals(AndroidCoordinatorStep.BUSY, coordinator.runOnce(panel, runtime))
        coordinator.completeLocalRestart()
        assertEquals(AndroidCoordinatorStep.ACTIVE, coordinator.runOnce(panel, runtime))
        assertTrue(coordinator.beginLocalRestart())
        assertTrue(coordinator.cancelCurrent() is AndroidCoordinatorResult.Accepted)
        assertNull(localRestartAuthority(store.read(), "lease", "lease", false))
        coordinator.completeLocalRestart()
    }

    @Test fun failedDurableAdmissionNeverDispatchesNativeStart() {
        val store = AndroidRecoveryStore(Record(), BootIdentityProvider { 1 })
        val active = active(store)
        store.cancelCurrentIntent()
        var starts = 0
        assertFalse(dispatchLegacyClientStart(
            admit = { QuickDesiredActiveProjection.update(store, true) is RecoveryStoreResult.Success },
            start = { starts++ },
        ))
        assertEquals(0, starts)
        val stopped = (store.read() as RecoveryStoreResult.Success).value
        assertFalse(stopped.intent.desiredActive)
        assertEquals(active.leaseTransaction?.leaseId, stopped.leaseTransaction?.leaseId)
    }

    @Test fun replacementKeepsExactArmedIntentAndLease() {
        val store = AndroidRecoveryStore(Record(), BootIdentityProvider { 1 })
        val before = active(store)
        assertEquals(before, localRestartAuthority(store.read(), "lease", "lease", false))
        assertEquals(before, (store.read() as RecoveryStoreResult.Success).value)
        // Rollback after a failed native replacement still uses the same active checkpoint.
        assertEquals(before, localRestartAuthority(store.read(), "lease", null, false))
        store.cancelCurrentIntent()
        assertNull(localRestartAuthority(store.read(), "lease", "lease", false))
    }

    @Test fun legacyRollbackNeedsTheExactFailedReplacementProof() {
        val store = AndroidRecoveryStore(Record(), BootIdentityProvider { 1 })
        QuickDesiredActiveProjection.update(store, true)
        val authority = requireNotNull(localRestartAuthority(store.read(), "lease", "lease", false))
        val failed = FailedLocalRestartAuthority("lease", authority, 7)
        assertNull(localRestartAuthority(store.read(), "lease", null, false))
        assertEquals(authority, localRestartAuthority(store.read(), "lease", null, false, failed, 7))
        assertNull(localRestartAuthority(store.read(), "foreign", null, false, failed, 7))
        assertNull(localRestartAuthority(store.read(), "lease", null, false, failed, 8))
        store.cancelCurrentIntent()
        assertNull(localRestartAuthority(store.read(), "lease", null, false, failed, 7))
    }

    @Test fun foreignLeaseCleanupAndNativeOwnershipCannotUseLocalReplacement() {
        val store = AndroidRecoveryStore(Record(), BootIdentityProvider { 1 })
        val current = active(store)
        assertNull(localRestartAuthority(store.read(), "foreign", "lease", false))
        assertNull(localRestartAuthority(store.read(), "lease", "foreign", false))
        assertNull(localRestartAuthority(store.read(), "lease", "lease", true))
        assertNull(localRestartAuthority(RecoveryStoreResult.Failure("unreadable"), "lease", "lease", false))
        val tx = requireNotNull(current.leaseTransaction)
        for (changed in listOf(
            current.copy(leaseTransaction = tx.copy(phase = LeasePhase.CLEANUP_PENDING)),
            current.copy(leaseTransaction = tx.copy(localStopPending = true)),
            current.copy(leaseTransaction = tx.copy(replay = tx.replay.copy(contractVersion = 2))),
            current.copy(intent = current.intent.copy(retry = AndroidRetryState(pendingAction = "stop"))),
            current.copy(intent = current.intent.copy(generation = current.intent.generation + 1)),
        )) {
            assertNull(localRestartAuthority(RecoveryStoreResult.Success(changed), "lease", "lease", false))
        }
    }

    private fun active(store: AndroidRecoveryStore): AndroidRecoveryEnvelope {
        val template = AndroidIntentTemplate("11111111-1111-4111-8111-111111111111", "account", "tic", "dynamic", "via_tak", "prefer_ipv6", false)
        val started = (store.beginStart(0, template, AndroidStartReplay("start", 1, "fingerprint")) as RecoveryStoreResult.Success).value
        store.recordLease(started.intent.generation, "lease")
        return (store.activateCheckpoint(started.intent.generation) as RecoveryStoreResult.Success).value
    }

    private class Record : EncryptedRecordBackend {
        private var bytes: ByteArray? = null
        override fun read() = bytes?.clone()
        override fun write(plaintext: ByteArray): Boolean { bytes = plaintext.clone(); return true }
    }
}

/** Exercise the actual service command boundary with a refused durable write. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE)
class LegacyStartServiceAdmissionTest {
    @Test fun rejectedQuickProjectionReturnsErrorBeforeNativeDispatch() {
        val backend = object : EncryptedRecordBackend {
            var bytes: ByteArray? = null
            override fun read() = bytes?.clone()
            override fun write(plaintext: ByteArray): Boolean { bytes = plaintext.clone(); return true }
        }
        val store = AndroidRecoveryStore(backend, BootIdentityProvider { 1 })
        val template = AndroidIntentTemplate("11111111-1111-4111-8111-111111111111", "account", "tic", "dynamic", "via_tak", "ipv4", false)
        store.beginStart(0, template, AndroidStartReplay("start", 1, "fp"))
        store.recordLease(1, "lease")
        store.activateCheckpoint(1)
        store.cancelCurrentIntent()
        val before = store.read()
        val oldStore = ReflectionHelpers.getField<AndroidRecoveryStore?>(AndroidRecoveryStores, "instance")
        ReflectionHelpers.setField(AndroidRecoveryStores, "instance", store)
        val hostController = Robolectric.buildService(VpnService::class.java).create()
        try {
            val host = hostController.get()
            val service = NelomaiVpnService(object : RuntimeVpnHostV1 {
                override val service = host
                override fun builder(beforeEstablish: (VpnService.Builder) -> Unit) = host.Builder()
            })
            ReflectionHelpers.setField(service, "recoveryStore", store)
            ReflectionHelpers.setField(service, "connectionIntentCoordinator", AndroidConnectionIntentCoordinator(store))
            // The fixture ends at command admission, not the unrelated idle
            // lifecycle that normally needs the full service onCreate.
            ReflectionHelpers.getField<AndroidServiceCallbackGate>(service, "serviceCallbackGate").close()
            var errorCode: String? = null
            var deliveries = 0
            val receiver = object : ResultReceiver(null) {
                override fun onReceiveResult(resultCode: Int, resultData: Bundle?) {
                    assertEquals(SERVICE_RESULT_ERROR, resultCode)
                    errorCode = resultData?.getString(EXTRA_ERROR_CODE)
                    deliveries++
                }
            }
            ReflectionHelpers.callInstanceMethod<Unit>(service, "handleClientStart",
                ReflectionHelpers.ClassParameter.from(Intent::class.java,
                    Intent(NelomaiVpnService.ACTION_CLIENT_START)
                        .putExtra(EXTRA_API_VERSION, TUNNEL_API_VERSION)
                        .putExtra(EXTRA_CLIENT_OPERATION_ID, "22222222-2222-4222-8222-222222222222")
                        .putExtra(EXTRA_CONFIGURATION, byteArrayOf(1))
                        .putExtra(EXTRA_OPTIONS, TunnelOptionsArgs().toBundle())
                        .putExtra(EXTRA_RESULT_RECEIVER, receiver)))
            assertEquals("connection_start_admission_failed", errorCode)
            assertEquals(1, deliveries)
            assertEquals(before, store.read())
        } finally {
            ReflectionHelpers.setField(AndroidRecoveryStores, "instance", oldStore)
            hostController.destroy()
        }
    }
}
