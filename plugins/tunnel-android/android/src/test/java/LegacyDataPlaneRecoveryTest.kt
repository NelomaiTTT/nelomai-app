package ru.nelomai.tunnel

import org.junit.Assert.*
import org.junit.Test

class LegacyDataPlaneRecoveryTest {
    @Test fun tileSessionWithoutIntentUsesLegacyRecoveryAndPreservesGeneration() {
        val store = AndroidRecoveryStore(Record(), BootIdentityProvider { 1 })
        val armed = QuickDesiredActiveProjection.update(store, true) as RecoveryStoreResult.Success
        val before = (store.read() as RecoveryStoreResult.Success).value
        assertNull(before.intent.template)
        assertNull(before.leaseTransaction)
        var generation: Long? = null
        assertTrue(routeDataPlaneStall(
            store.read(),
            legacyRecovery = { generation = it; true },
            intentRecovery = { error("legacy session must not enter intent recovery") },
        ))
        assertEquals(armed.value.generation, generation)
        assertEquals(before, (store.read() as RecoveryStoreResult.Success).value)
    }

    @Test fun stoppedOrUnreadableSessionCannotStartLegacyRecovery() {
        val store = AndroidRecoveryStore(Record(), BootIdentityProvider { 1 })
        for (state in listOf(store.read(), RecoveryStoreResult.Failure("unreadable"))) {
            assertFalse(routeDataPlaneStall(
                state,
                legacyRecovery = { error("no restart authority") },
                intentRecovery = { error("no intent") },
            ))
        }
    }

    @Test fun sameSessionGetsOnlyOneLocalRestart() {
        val recovery = LegacyDataPlaneRecovery()
        val events = mutableListOf<String>()
        repeat(2) { attempt ->
            assertEquals(attempt == 0, recovery.restart(
                isCurrent = { true },
                stop = { events += "stop" },
                start = { events += "start" },
            ))
        }
        assertEquals(listOf("stop", "start"), events)
    }

    @Test fun redundantOrPendingRecoveryNeverFallsBackToLegacyRestart() {
        val store = AndroidRecoveryStore(Record(), BootIdentityProvider { 1 })
        QuickDesiredActiveProjection.update(store, true)
        val current = (store.read() as RecoveryStoreResult.Success).value
        val redundant = AndroidRedundantTransaction(
            desiredActive = true,
            template = AndroidIntentTemplate("device", "account", "stray", "auto", "full", "auto", false),
            sessionId = "22222222-2222-4222-8222-222222222222",
            slotALeaseId = "a", slotBLeaseId = "b", localActiveLeaseId = "a",
            standbyDesired = true, roleGeneration = 0, membershipGeneration = 0,
            startOperationId = "start", startRequestFingerprint = "fingerprint",
        )
        for (envelope in listOf(
            current.copy(redundantTransaction = redundant),
            current.copy(intent = current.intent.copy(retry = AndroidRetryState(pendingAction = "stop"))),
        )) {
            assertFalse(routeDataPlaneStall(
                RecoveryStoreResult.Success(envelope),
                legacyRecovery = { error("owned by another recovery path") },
                intentRecovery = { error("not a measured intent") },
            ))
        }
    }

    @Test fun failedNativeStartIsClosedAndCannotBeRetried() {
        val recovery = LegacyDataPlaneRecovery()
        val events = mutableListOf<String>()
        repeat(2) {
            assertFalse(recovery.restart(
                isCurrent = { true },
                stop = { events += "stop" },
                start = { events += "start"; error("native start failed") },
            ))
        }
        assertEquals(listOf("stop", "start", "stop"), events)
    }

    @Test fun userStopBeforeOrDuringLocalStopPreventsRestart() {
        for (initial in listOf(false, true)) {
            var current = initial
            val events = mutableListOf<String>()
            assertFalse(LegacyDataPlaneRecovery().restart(
                isCurrent = { current },
                stop = { events += "stop"; current = false },
                start = { events += "start" },
            ))
            assertEquals(if (initial) listOf("stop") else emptyList<String>(), events)
        }
    }

    @Test fun cancellationDuringNativeStartClosesTheRestartedTransport() {
        var current = true
        val events = mutableListOf<String>()
        assertFalse(LegacyDataPlaneRecovery().restart(
            isCurrent = { current },
            stop = { events += "stop" },
            start = { events += "start"; current = false },
        ))
        assertEquals(listOf("stop", "start", "stop"), events)
    }

    @Test fun failedNativeStopNeverStartsAndDoesNotLoop() {
        val recovery = LegacyDataPlaneRecovery()
        var stops = 0
        repeat(2) {
            assertFalse(recovery.restart(
                isCurrent = { true },
                stop = { stops += 1; error("stop failed") },
                start = { error("must not start after failed stop") },
            ))
        }
        assertEquals(1, stops)
    }

    private class Record : EncryptedRecordBackend {
        private var bytes: ByteArray? = null
        override fun read(): ByteArray? = bytes?.clone()
        override fun write(plaintext: ByteArray): Boolean { bytes = plaintext.clone(); return true }
    }
}
