package ru.nelomai.tunnel

import org.junit.Assert.*
import org.junit.Test

class TotalLossRestartRegressionTest {
    private class Backend : EncryptedRecordBackend {
        var bytes: ByteArray? = null
        override fun read() = bytes?.copyOf()
        override fun write(plaintext: ByteArray): Boolean {
            bytes = plaintext.copyOf()
            return true
        }
    }
    private fun store(backend: Backend) = AndroidRecoveryStore(backend, BootIdentityProvider { 7L })
    private fun <T> RecoveryStoreResult<T>.value() = (this as RecoveryStoreResult.Success).value
    private fun promoted(backend: Backend): AndroidRecoveryStore {
        val store = store(backend)
        val template = AndroidIntentTemplate("11111111-1111-4111-8111-111111111111", "account-scope",
            "stray", "dynamic", "standalone", "ipv4", true)
        val tx = AndroidRedundantTransaction(desiredActive = true, template = template,
            sessionId = "22222222-2222-4222-8222-222222222222", slotALeaseId = "lease-a", slotBLeaseId = "lease-b",
            localActiveLeaseId = "lease-a", standbyDesired = true, roleGeneration = 0, membershipGeneration = 0,
            startOperationId = "old-start", startRequestFingerprint = "old-fingerprint")
        store.beginRedundant(tx).value()
        store.prepareRedundantTotalLoss("old-start", AndroidStartReplay("replacement-start", 2, "fp")).value()
        store.deferRedundantStop("old-stop", "old-start").value()
        store.updateRedundant("old-start") { it.copy(retry = it.retry.copy(stopState = RedundantStopState.ACKNOWLEDGED)) }.value()
        store.completeRedundantStop("old-stop", "old-start").value()
        return store
    }
    private class Panel(private val state: String) : AndroidConnectionIntentPanel {
        var starts = 0
        override fun reconcile(transaction: AndroidLeaseTransaction, cancelIfAbsent: Boolean) =
            BackgroundReconcileResult(state, false, null, null, 0, null)
        override fun start(template: AndroidIntentTemplate, transaction: AndroidLeaseTransaction): BackgroundStartResult {
            starts++
            throw BackgroundConnectionException("connection_already_active")
        }
        override fun syncBindingPreferences(template: AndroidIntentTemplate) {}
        override fun stop(leaseId: String, operationId: String, failureCode: String?) { error("unexpected stop") }
    }
    private val runtime = object : AndroidConnectionIntentRuntime {
        override fun start(result: BackgroundStartResult, operationId: String, isCurrent: () -> Boolean) = error("unexpected native start")
        override fun stop() = true
        override fun isRunning() = false
    }

    @Test fun conflictAfterNetworkRestartRetriesAndSurvivesProcessRecreation() {
        val backend = Backend()
        val first = promoted(backend)
        val panel = Panel("not_found")
        assertEquals(AndroidCoordinatorStep.RETRY, AndroidConnectionIntentCoordinator(first).runOnce(panel, runtime))
        assertEquals(1, panel.starts)
        val retry = first.read().value().intent.retry
        assertEquals("reconcile", retry.pendingAction)
        assertNull(retry.redundantTotalLossSourceStartOperationId)
        val reopened = store(backend)
        assertEquals(AndroidCoordinatorStep.RETRY,
            AndroidConnectionIntentCoordinator(reopened).runOnce(Panel("terminal"), runtime))
        assertTrue(reopened.read().value().intent.desiredActive)
        assertNotEquals("replacement-start", reopened.read().value().leaseTransaction!!.startOperationId)
    }

    @Test fun installedCandidateMarkerCanResumeTerminalOperationWithoutClearingData() {
        val backend = Backend()
        promoted(backend)
        val reopened = store(backend)
        assertEquals("redundant_total_loss_restart", reopened.read().value().intent.retry.pendingAction)
        assertEquals(AndroidCoordinatorStep.RETRY,
            AndroidConnectionIntentCoordinator(reopened).runOnce(Panel("terminal"), runtime))
        val next = reopened.read().value()
        assertTrue(next.intent.desiredActive)
        assertEquals(2, next.leaseTransaction!!.replay.contractVersion)
        assertNull(next.intent.retry.redundantTotalLossSourceStartOperationId)
    }

    @Test fun changingRetryActionClearsItsPairedSourceButSameActionRetainsIt() {
        for (action in listOf("redundant_total_loss_restart", "reconcile", "local_restart", null)) {
            val store = promoted(Backend())
            val next = store.recordFailure(store.read().value().intent.generation,
                "test_error", 100, pendingAction = action).value()
            assertEquals(action, next.intent.retry.pendingAction)
            assertEquals(if (action == "redundant_total_loss_restart") "old-start" else null,
                next.intent.retry.redundantTotalLossSourceStartOperationId)
        }
    }

    @Test fun terminalAndNewOperationTransitionsConsumePersistedRestartMarker() {
        for (transition in listOf("terminal", "replace", "close")) {
            val store = promoted(Backend())
            val current = store.read().value()
            val replay = current.leaseTransaction!!.replay.copy(startOperationId = "next-start")
            val next = when (transition) {
                "terminal" -> store.scheduleInitialTerminalReconcile(current.intent.generation, "invalid_background_response")
                "replace" -> store.replaceStartOperation(current.intent.generation, replay, "retry", 100, 2)
                else -> store.closeAuthoritativeStartAndRestart(current.intent.generation, replay, "retry", 100, 2)
            }.value()
            assertNull(next.intent.retry.redundantTotalLossSourceStartOperationId)
            assertEquals(transition != "terminal", next.intent.desiredActive)
        }
    }

    @Test fun rejectedEncodingReturnsFailureWithoutOverwritingRecoverableRecord() {
        val backend = Backend()
        val store = promoted(backend)
        val before = backend.bytes!!.copyOf()
        assertTrue(store.recordFailure(store.read().value().intent.generation, "retry", 100,
            scheduledDelaySeconds = -1, pendingAction = "redundant_total_loss_restart") is RecoveryStoreResult.Failure)
        assertArrayEquals(before, backend.bytes)
        assertEquals("redundant_total_loss_restart", store.read().value().intent.retry.pendingAction)
    }

    @Test fun pendingReplacementIsStillNativeOwnedBeforeItsNewSessionExists() {
        val store = promoted(Backend())
        // Pending v2 replay still needs the intent coordinator, not the
        // already-allocated redundant owner. Ownership must not change routing.
        assertTrue(shouldEnterLegacyVpnRecovery(store.read()))
        assertTrue(connectionIntentServiceStatus(store.read().value()).redundantSessionOwned)
    }
}
