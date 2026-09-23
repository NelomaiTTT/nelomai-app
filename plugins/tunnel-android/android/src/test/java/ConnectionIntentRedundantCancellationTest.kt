package ru.nelomai.tunnel

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.Looper
import android.os.ResultReceiver
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.LooperMode
import org.robolectric.util.ReflectionHelpers
import ru.nelomai.runtime.v1.RuntimeVpnHostV1
import java.util.concurrent.Executor

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE)
@LooperMode(LooperMode.Mode.PAUSED)
class ConnectionIntentRedundantCancellationTest {
    @Test
    fun scopedStopFromDestroyedServiceCannotDisarmRecovery() {
        assertLateScopedStopPreservesRecovery {
            ReflectionHelpers.setField(it, "serviceDestroyed", true)
        }
    }

    @Test
    fun scopedStopFromSupersededServiceCannotDisarmNewSession() {
        assertLateScopedStopPreservesRecovery { oldService ->
            // Construct without draining the old instance's queued main-thread callback.
            NelomaiVpnService(ReflectionHelpers.getField(oldService, "runtimeHost"))
        }
    }

    @Test
    fun scopedStopFromClosedServiceCannotDisarmRecovery() {
        assertLateScopedStopPreservesRecovery {
            ReflectionHelpers.getField<AndroidServiceCallbackGate>(it, "serviceCallbackGate").close()
        }
    }

    private fun assertLateScopedStopPreservesRecovery(retireService: (NelomaiVpnService) -> Unit) {
        val fixture = serviceFixture(withRedundant = false)
        val jobs = ArrayDeque<Runnable>()
        ReflectionHelpers.setField(fixture.service, "redundantWork", RedundantVpnWorkDispatcher(Executor(jobs::addLast)))
        val barrier = ReflectionHelpers.getField<RedundantStopLookupBarrier>(fixture.service, "redundantStopLookupBarrier")
        val receiver = RecordingResultReceiver()
        fixture.service.onStartCommand(Intent(NelomaiVpnService.ACTION_CLIENT_STOP)
            .putExtra(EXTRA_API_VERSION, TUNNEL_API_VERSION)
            .putExtra(EXTRA_LEGACY_STOP_ONLY, true)
            .putExtra(EXTRA_RESULT_RECEIVER, receiver), 0, 1)
        // Read the empty recovery record now, but delay completion until the
        // service has retired and a new desired session is persisted.
        jobs.removeFirst().run()
        assertTrue(barrier.hasPending())
        assertNull(receiver.resultCode)
        retireService(fixture.service)
        fixture.store.setDesiredActive(0, true).successEnvelope()
        val before = fixture.store.beginRedundant(redundantTransaction()).successEnvelope()

        val completion = runCatching { shadowOf(Looper.getMainLooper()).idle() }
        assertEquals(before, fixture.store.read().successEnvelope())
        assertNull(completion.exceptionOrNull())
        assertEquals(SERVICE_RESULT_ERROR, receiver.resultCode)
        assertEquals("redundant_session_service_owned", receiver.resultData?.getString(EXTRA_ERROR_CODE))
        assertFalse(barrier.hasPending())
        assertNull(fixture.tombstones.record)
    }

    @Test
    fun scopedStopStillCompletesForCurrentServiceWithoutNativeOwner() {
        val fixture = serviceFixture(withRedundant = false)
        fixture.store.setDesiredActive(0, true).successEnvelope()
        val jobs = ArrayDeque<Runnable>()
        ReflectionHelpers.setField(fixture.service, "redundantWork", RedundantVpnWorkDispatcher(Executor(jobs::addLast)))
        val receiver = RecordingResultReceiver()
        fixture.service.onStartCommand(Intent(NelomaiVpnService.ACTION_CLIENT_STOP)
            .putExtra(EXTRA_API_VERSION, TUNNEL_API_VERSION)
            .putExtra(EXTRA_LEGACY_STOP_ONLY, true)
            .putExtra(EXTRA_RESULT_RECEIVER, receiver), 0, 1)
        jobs.removeFirst().run()
        shadowOf(Looper.getMainLooper()).idle()
        assertFalse(fixture.store.read().successEnvelope().intent.desiredActive)
        assertEquals(SERVICE_RESULT_OK, receiver.resultCode)
        assertFalse(ReflectionHelpers.getField<RedundantStopLookupBarrier>(fixture.service, "redundantStopLookupBarrier").hasPending())
    }

    @Test
    fun explicitClientStopStillCancelsTheCurrentNativeStart() {
        val fixture = serviceFixture()
        val jobs = ArrayDeque<Runnable>()
        ReflectionHelpers.setField(fixture.service, "redundantWork", RedundantVpnWorkDispatcher(Executor(jobs::addLast)))
        val gate = ReflectionHelpers.getField<RedundantStartOperationGate>(fixture.service, "redundantStartOperation")
        assertTrue(gate.begin("start-operation") {})
        fixture.service.onStartCommand(Intent(NelomaiVpnService.ACTION_CLIENT_STOP)
            .putExtra(EXTRA_API_VERSION, TUNNEL_API_VERSION)
            .putExtra(EXTRA_RESULT_RECEIVER, RecordingResultReceiver()), 0, 1)
        assertTrue(gate.isCancelled("start-operation"))
        assertNotNull(ReflectionHelpers.getField<Any?>(fixture.service, "pendingRedundantStop"))
    }

    @Test
    fun scopedStopCannotInvalidateTileCredentialPreflight() {
        val fixture = serviceFixture(withRedundant = false)
        val dispatch = ReflectionHelpers.getField<AndroidConnectionIntentDispatchState>(fixture.service, "connectionIntentDispatch")
        val ticket = dispatch.start(1)
        val jobs = ArrayDeque<Runnable>()
        ReflectionHelpers.setField(fixture.service, "redundantWork", RedundantVpnWorkDispatcher(Executor(jobs::addLast)))
        val receiver = RecordingResultReceiver()
        fixture.service.onStartCommand(Intent(NelomaiVpnService.ACTION_CLIENT_STOP)
            .putExtra(EXTRA_API_VERSION, TUNNEL_API_VERSION)
            .putExtra(EXTRA_LEGACY_STOP_ONLY, true)
            .putExtra(EXTRA_RESULT_RECEIVER, receiver), 0, 1)
        jobs.removeFirst().run()
        shadowOf(Looper.getMainLooper()).idle()
        assertTrue(dispatch.isCurrent(ticket))
        assertEquals(SERVICE_RESULT_ERROR, receiver.resultCode)
        assertEquals("redundant_session_service_owned", receiver.resultData?.getString(EXTRA_ERROR_CODE))
    }

    @Test
    fun staleCoreStopCannotCancelNewNativeStartDuringOwnershipLookup() {
        val fixture = serviceFixture()
        val jobs = ArrayDeque<Runnable>()
        ReflectionHelpers.setField(fixture.service, "redundantWork", RedundantVpnWorkDispatcher(Executor(jobs::addLast)))
        val gate = ReflectionHelpers.getField<RedundantStartOperationGate>(fixture.service, "redundantStartOperation")
        val receiver = RecordingResultReceiver()
        val before = fixture.store.read().successEnvelope()
        fixture.service.onStartCommand(Intent(NelomaiVpnService.ACTION_CLIENT_STOP)
            .putExtra(EXTRA_API_VERSION, TUNNEL_API_VERSION)
            .putExtra(EXTRA_LEGACY_STOP_ONLY, true)
            .putExtra(EXTRA_RESULT_RECEIVER, receiver), 0, 1)
        assertTrue(gate.begin("new-tile-start") { error("must not cancel new start") })
        jobs.removeFirst().run()
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals(SERVICE_RESULT_ERROR, receiver.resultCode)
        assertEquals("redundant_session_service_owned", receiver.resultData?.getString(EXTRA_ERROR_CODE))
        assertFalse(gate.isCancelled("new-tile-start"))
        assertEquals(before, fixture.store.read().successEnvelope())
        assertNull(fixture.tombstones.record)
    }

    @Test
    fun staleCoreStopPreservesDurableSessionAndPendingReplacement() {
        for (replacement in listOf(false, true)) {
            val fixture = serviceFixture()
            if (replacement) {
                fixture.store.prepareRedundantTotalLoss("start-operation", AndroidStartReplay("replacement", 2, "fp")).successEnvelope()
                fixture.store.deferRedundantStop("stop", "start-operation").successEnvelope()
                fixture.store.updateRedundant("start-operation") {
                    it.copy(retry = it.retry.copy(stopState = RedundantStopState.ACKNOWLEDGED))
                }.successEnvelope()
                fixture.store.completeRedundantStop("stop", "start-operation").successEnvelope()
            }
            val jobs = ArrayDeque<Runnable>()
            ReflectionHelpers.setField(fixture.service, "redundantWork", RedundantVpnWorkDispatcher(Executor(jobs::addLast)))
            val before = fixture.store.read().successEnvelope()
            val receiver = RecordingResultReceiver()
            fixture.service.onStartCommand(Intent(NelomaiVpnService.ACTION_CLIENT_STOP)
                .putExtra(EXTRA_API_VERSION, TUNNEL_API_VERSION)
                .putExtra(EXTRA_LEGACY_STOP_ONLY, true)
                .putExtra(EXTRA_RESULT_RECEIVER, receiver), 0, 1)
            jobs.removeFirst().run()
            shadowOf(Looper.getMainLooper()).idle()
            assertEquals(SERVICE_RESULT_ERROR, receiver.resultCode)
            assertEquals("redundant_session_service_owned", receiver.resultData?.getString(EXTRA_ERROR_CODE))
            assertEquals(before, fixture.store.read().successEnvelope())
            assertNull(fixture.tombstones.record)
        }
    }

    @Test
    fun currentConnectionIntentCancellationEntersDurableRedundantStop() {
        val fixture = serviceFixture()
        val receiver = RecordingResultReceiver()

        fixture.service.onStartCommand(
            Intent(NelomaiVpnService.ACTION_CANCEL_CURRENT_CONNECTION_INTENT)
                .putExtra(EXTRA_RESULT_RECEIVER, receiver),
            0,
            1,
        )

        val stopped = fixture.store.read().successEnvelope()
        val transaction = requireNotNull(stopped.redundantTransaction)
        assertFalse(transaction.desiredActive)
        assertEquals(RedundantStopState.PENDING, transaction.retry.stopState)
        assertNotNull(transaction.stopOperationId)
        assertNotNull(fixture.tombstones.record)
        assertEquals(SERVICE_RESULT_OK, receiver.resultCode)
        val status = requireNotNull(receiver.resultData).toConnectionIntentServiceStatus()
        assertFalse(status.desiredActive)
        assertEquals("stopping", status.status)
        assertEquals("cleanup_pending", status.leasePhase)
    }

    @Test
    fun staleGenerationCancellationDoesNotEnterRedundantStop() {
        val fixture = serviceFixture()
        val receiver = RecordingResultReceiver()

        fixture.service.onStartCommand(
            Intent(NelomaiVpnService.ACTION_CANCEL_CONNECTION_INTENT)
                .putExtra(EXTRA_GENERATION, 0L)
                .putExtra(EXTRA_RESULT_RECEIVER, receiver),
            0,
            1,
        )

        val retained = fixture.store.read().successEnvelope()
        val transaction = requireNotNull(retained.redundantTransaction)
        assertTrue(transaction.desiredActive)
        assertEquals(RedundantStopState.NONE, transaction.retry.stopState)
        assertNull(transaction.stopOperationId)
        assertNull(fixture.tombstones.record)
        assertEquals(SERVICE_RESULT_ERROR, receiver.resultCode)
        assertEquals(
            "connection_intent_generation_conflict",
            receiver.resultData?.getString(EXTRA_ERROR_CODE),
        )
    }

    private fun serviceFixture(withRedundant: Boolean = true): ServiceFixture {
        val backend = CancellationRecoveryBackend()
        val store = AndroidRecoveryStore(backend, BootIdentityProvider { 7 })
        if (withRedundant) {
            store.setDesiredActive(0, true).successEnvelope()
            store.beginRedundant(redundantTransaction()).successEnvelope()
        }
        val tombstones = CancellationTombstoneBackend()
        val hostController = Robolectric.buildService(VpnService::class.java).create()
        val host = hostController.get()
        val service = NelomaiVpnService(object : RuntimeVpnHostV1 {
            override val service = host
            override fun builder(beforeEstablish: (VpnService.Builder) -> Unit) = host.Builder()
        })
        ReflectionHelpers.setField(service, "recoveryStore", store)
        ReflectionHelpers.setField(
            service,
            "connectionIntentCoordinator",
            AndroidConnectionIntentCoordinator(store),
        )
        ReflectionHelpers.setField(
            service,
            "redundantCancelTombstones",
            RedundantCancelTombstoneStore(tombstones) { "stop-operation" },
        )
        // Only the command engine is under test; do not launch unrelated
        // background networking after its lookup barrier is released.
        val generation = ReflectionHelpers.getField<Long>(service, "serviceGeneration")
        ReflectionHelpers.setField(service, "redundantTotalLossLifecycle", RedundantTotalLossLifecycle(
            currentServiceGeneration = { generation }, serviceActive = { true },
            barrierPending = { false }, logoutState = { BackgroundLogoutReadState.NONE },
            recovery = store::read, post = { it() }, retryCleanup = {},
            publishRestartStarting = {}, resume = {}, scheduleLogout = {},
            scheduleStateReadRetry = {}, stopIfIdle = {},
        ))
        return ServiceFixture(service, store, tombstones)
    }

    private fun redundantTransaction() = AndroidRedundantTransaction(
        desiredActive = true,
        template = AndroidIntentTemplate(
            deviceId = "11111111-1111-4111-8111-111111111111",
            accountScope = "account",
            layer = "stray",
            ticConnectionMode = "dynamic",
            routeMode = "standalone",
            egressMode = "ipv4",
            allowAlternate = true,
        ),
        sessionId = "22222222-2222-4222-8222-222222222222",
        slotALeaseId = "lease-a",
        slotBLeaseId = "lease-b",
        localActiveLeaseId = "lease-a",
        standbyDesired = true,
        roleGeneration = 1,
        membershipGeneration = 1,
        startOperationId = "start-operation",
        startRequestFingerprint = "fingerprint",
    )
}

private data class ServiceFixture(
    val service: NelomaiVpnService,
    val store: AndroidRecoveryStore,
    val tombstones: CancellationTombstoneBackend,
)

private class RecordingResultReceiver : ResultReceiver(null) {
    var resultCode: Int? = null
    var resultData: Bundle? = null

    override fun onReceiveResult(resultCode: Int, resultData: Bundle?) {
        this.resultCode = resultCode
        this.resultData = resultData
    }
}

private class CancellationRecoveryBackend : EncryptedRecordBackend {
    private var record: ByteArray? = null

    override fun read(): ByteArray? = record?.copyOf()

    override fun write(plaintext: ByteArray): Boolean {
        record = plaintext.copyOf()
        return true
    }
}

private class CancellationTombstoneBackend : RedundantCancelTombstoneBackend {
    var record: String? = null

    override fun read(): String? = record

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

private fun RecoveryStoreResult<AndroidRecoveryEnvelope>.successEnvelope():
    AndroidRecoveryEnvelope = when (this) {
    is RecoveryStoreResult.Success -> value
    is RecoveryStoreResult.Failure -> throw AssertionError(code)
}
