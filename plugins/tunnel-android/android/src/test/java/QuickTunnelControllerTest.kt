package ru.nelomai.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class QuickTunnelControllerTest {
    @Test
    fun desiredActiveProjectionUsesTheRecoveryEnvelopeGeneration() {
        val backend = QuickFakeEncryptedRecordBackend()
        val store = AndroidRecoveryStore(backend, BootIdentityProvider { 9 })

        val enabled = QuickDesiredActiveProjection.update(store, true).successIntent()
        val disabled = QuickDesiredActiveProjection.update(store, false).successIntent()

        assertTrue(enabled.desiredActive)
        assertEquals(1, enabled.generation)
        assertFalse(disabled.desiredActive)
        assertEquals(2, disabled.generation)
        assertFalse(QuickDesiredActiveProjection.read(store).successIntent().desiredActive)
    }

    @Test
    fun failedRecoveryCommitRejectsQuickOnWithoutPublishingIntent() {
        val backend = QuickFakeEncryptedRecordBackend(failWrites = true)
        val store = AndroidRecoveryStore(backend, BootIdentityProvider { 9 })

        val result = QuickDesiredActiveProjection.update(store, true)

        assertTrue(result is RecoveryStoreResult.Failure)
        assertEquals("recovery_record_write_failed", (result as RecoveryStoreResult.Failure).code)
        backend.failWrites = false
        assertFalse(QuickDesiredActiveProjection.read(store).successIntent().desiredActive)
    }

    @Test
    fun broadcastGateAvoidsPollingTheVpnServiceForPersistedChanges() {
        val gate = QuickStateChangeGate()

        assertFalse(gate.current())
        gate.observe(1)
        val firstRevision = gate.snapshot()
        assertTrue(gate.current())
        gate.acknowledgeThrough(firstRevision)
        assertFalse(gate.current())
        gate.seedPersisted(1)
        assertFalse(gate.current())

        val coldGate = QuickStateChangeGate()
        coldGate.seedPersisted(1)
        assertTrue(coldGate.current())
    }

    @Test
    fun changeArrivingDuringAcknowledgeRemainsVisible() {
        val gate = QuickStateChangeGate(initialRevision = 1)
        val acknowledgedRevision = gate.snapshot()

        gate.observe(2)
        gate.acknowledgeThrough(acknowledgedRevision)

        assertTrue(gate.current())
    }

    @Test
    fun clearingQuickPlanClearsTheLocalPendingGeneration() {
        val gate = QuickStateChangeGate(initialRevision = 4)

        gate.clearPending()

        assertFalse(gate.current())
        gate.observe(5)
        assertTrue(gate.current())
    }

    @Test
    fun keepsRecentTransition() {
        assertEquals(
            SessionState.STARTING,
            QuickTunnelController.resolveState(
                SessionState.STOPPED,
                SessionState.STARTING,
                updatedAtMillis = 1_000,
                nowMillis = 1_000 + QuickTunnelController.TRANSITION_TIMEOUT_MILLIS - 1,
            ),
        )
    }

    @Test
    fun clearsExpiredTransition() {
        assertEquals(
            SessionState.STOPPED,
            QuickTunnelController.resolveState(
                SessionState.STOPPED,
                SessionState.STOPPING,
                updatedAtMillis = 1_000,
                nowMillis = 1_000 + QuickTunnelController.TRANSITION_TIMEOUT_MILLIS,
            ),
        )
    }

    @Test
    fun clearsLegacyTransitionWithoutTimestamp() {
        assertEquals(
            SessionState.STOPPED,
            QuickTunnelController.resolveState(
                SessionState.STOPPED,
                SessionState.STARTING,
                updatedAtMillis = 0,
                nowMillis = 10_000,
            ),
        )
    }

    @Test
    fun runtimeStateTakesPriority() {
        assertEquals(
            SessionState.RUNNING,
            QuickTunnelController.resolveState(
                SessionState.RUNNING,
                SessionState.STOPPING,
                updatedAtMillis = 1_000,
                nowMillis = 10_000,
            ),
        )
    }
}

private class QuickFakeEncryptedRecordBackend(
    var failWrites: Boolean = false,
) : EncryptedRecordBackend {
    private var record: ByteArray? = null

    override fun read(): ByteArray? = record?.copyOf()

    override fun write(plaintext: ByteArray): Boolean {
        if (failWrites) return false
        record = plaintext.copyOf()
        return true
    }
}

private fun RecoveryStoreResult<AndroidConnectionIntent>.successIntent(): AndroidConnectionIntent {
    assertTrue(this is RecoveryStoreResult.Success)
    return (this as RecoveryStoreResult.Success).value
}
