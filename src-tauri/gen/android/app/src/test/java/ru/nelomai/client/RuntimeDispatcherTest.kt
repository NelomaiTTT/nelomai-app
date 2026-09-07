package ru.nelomai.client

import org.junit.Assert.*
import org.junit.Test

class RuntimeDispatcherTest {
    private val selected = RuntimeSelectionV1("latest", "0.2.16", "0.2.16", 7L, null, "launch-1")

    @Test fun pendingSwitchBlocksStartButAllowsStop() {
        val pending = selected.copy(pendingSlot = "stable")
        assertFalse(RuntimeDispatchPolicy.mayStart(pending))
        assertTrue(RuntimeDispatchPolicy.mayStop(selected, pending))
        assertTrue(RuntimeDispatchPolicy.mayToggle(pending, durableDesiredActive = true))
        assertFalse(RuntimeDispatchPolicy.mayToggle(pending, durableDesiredActive = false))
    }

    @Test fun binderAdmissionRejectsIdentityGenerationAndUidMismatch() {
        assertTrue(RuntimeDispatchPolicy.admit(selected, selected, 10001, 10001))
        assertFalse(RuntimeDispatchPolicy.admit(selected, selected, 10002, 10001))
        assertFalse(RuntimeDispatchPolicy.admit(selected, selected.copy(slot = "stable"), 10001, 10001))
        assertFalse(RuntimeDispatchPolicy.admit(selected, selected.copy(runtimeVersion = "0.2.15"), 10001, 10001))
        assertFalse(RuntimeDispatchPolicy.admit(selected, selected.copy(sessionGeneration = 6L), 10001, 10001))
        assertFalse(RuntimeDispatchPolicy.admit(selected, selected.copy(incarnation = "launch-0"), 10001, 10001))
    }

    @Test fun unenrolledNullIsNotInventedGeneration() {
        val fresh = selected.copy(sessionGeneration = null)
        assertTrue(RuntimeDispatchPolicy.admit(fresh, fresh, 10001, 10001))
        assertFalse(RuntimeDispatchPolicy.admit(fresh, fresh.copy(sessionGeneration = 0L), 10001, 10001))
        assertFalse(RuntimeDispatchPolicy.mayStart(fresh))
    }

    @Test fun slotOrIncarnationChangeRequiresVpnProcessExit() {
        assertFalse(RuntimeDispatchPolicy.mustExitProcess(selected, selected))
        assertTrue(RuntimeDispatchPolicy.mustExitProcess(selected, selected.copy(slot = "stable")))
        assertTrue(RuntimeDispatchPolicy.mustExitProcess(selected, selected.copy(incarnation = "launch-2")))
        assertTrue(RuntimeDispatchPolicy.mustExitProcess(selected, null))
    }

    @Test fun runtimeCannotSupplyLibraryName() {
        assertEquals("nelomai_app_lib", RuntimeDispatchPolicy.library(selected))
        assertEquals("nelomai_runtime_stable", RuntimeDispatchPolicy.library(selected.copy(slot = "stable")))
        assertThrows(IllegalArgumentException::class.java) { RuntimeDispatchPolicy.library(selected.copy(slot = "../../anything")) }
    }
}
