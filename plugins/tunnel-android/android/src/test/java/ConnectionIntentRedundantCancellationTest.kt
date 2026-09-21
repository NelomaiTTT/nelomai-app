package ru.nelomai.tunnel

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
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
import org.robolectric.annotation.Config
import org.robolectric.util.ReflectionHelpers
import ru.nelomai.runtime.v1.RuntimeVpnHostV1

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE)
class ConnectionIntentRedundantCancellationTest {
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

    private fun serviceFixture(): ServiceFixture {
        val backend = CancellationRecoveryBackend()
        val store = AndroidRecoveryStore(backend, BootIdentityProvider { 7 })
        store.setDesiredActive(0, true).successEnvelope()
        store.beginRedundant(redundantTransaction()).successEnvelope()
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
