package ru.nelomai.client

import org.junit.Assert.*
import org.junit.Test

class StableBackgroundPreparationTest {
    @Test fun readyRecordDoesNotStopTheWorkingVpn() {
        assertTrue(prepareStableBackgroundAfterExit({ true }, { error("unexpected stop") }))
    }

    @Test fun oldProcessExitsBeforeTheOnlyRetry() {
        val events = mutableListOf<String>()
        assertTrue(prepareStableBackgroundAfterExit(
            { events += "prepare"; events.size == 3 },
            { events += "exit"; true },
        ))
        assertEquals(listOf("prepare", "exit", "prepare"), events)
    }

    @Test fun unconfirmedExitNeverPreparesTheRecordAgain() {
        var probes = 0
        assertFalse(prepareStableBackgroundAfterExit({ probes++; false }, { false }))
        assertEquals(1, probes)
    }

    @Test fun refusedRetryNeverRestartsForever() {
        var probes = 0
        var exits = 0
        assertFalse(prepareStableBackgroundAfterExit({ probes++; false }, { exits++; true }))
        assertEquals(2, probes)
        assertEquals(1, exits)
    }
}
