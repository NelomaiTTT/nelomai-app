package ru.nelomai.client

import android.content.Intent
import org.junit.Assert.*
import org.junit.Test
import java.io.File

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

    @Test fun relaunchWaitsForForegroundAndOldRuntimeExitBeforeReleasingBootstrap() {
        val events = mutableListOf<String>()
        assertTrue(RuntimeRelaunchOrder.run(
            runtimePid = 42,
            ownUid = 10001,
            processes = { mapOf(42 to RuntimeProcessInfo(10001, "ru.nelomai.client:runtime")) },
            foregroundHandoff = { events += "common_foreground"; true },
            stopVpn = { events += "vpn_stopped"; true },
            kill = { events += "runtime_killed" },
            waitUntilGone = { events += "runtime_gone"; true },
            foregroundStillVisible = { events += "common_still_foreground"; true },
            finishRuntimeStop = { events += "runtime_stop_confirmed:$it" },
        ))
        assertEquals(
            listOf(
                "common_foreground",
                "vpn_stopped",
                "runtime_killed",
                "runtime_gone",
                "common_still_foreground",
                "runtime_stop_confirmed:true",
            ),
            events,
        )
    }

    @Test fun failedIndependentVpnStopNeverKillsOrLaunches() {
        val events = mutableListOf<String>()
        assertFalse(RuntimeRelaunchOrder.run(
            runtimePid = 42,
            ownUid = 10001,
            processes = { mapOf(42 to RuntimeProcessInfo(10001, "ru.nelomai.client:runtime")) },
            foregroundHandoff = { events += "common_foreground"; true },
            stopVpn = { events += "vpn_failed"; false },
            kill = { events += "unexpected_kill" },
            waitUntilGone = { events += "unexpected_wait"; true },
            foregroundStillVisible = { events += "unexpected_foreground_check"; true },
            finishRuntimeStop = { events += "runtime_stop_confirmed:$it" },
        ))
        assertEquals(listOf("common_foreground", "vpn_failed", "runtime_stop_confirmed:false"), events)
    }

    @Test fun backgroundedHandoffNeverStopsOrReleasesNewRuntime() {
        val events = mutableListOf<String>()
        assertFalse(RuntimeRelaunchOrder.run(
            runtimePid = 42,
            ownUid = 10001,
            processes = { mapOf(42 to RuntimeProcessInfo(10001, "ru.nelomai.client:runtime")) },
            foregroundHandoff = { events += "common_not_foreground"; false },
            stopVpn = { events += "unexpected_vpn_stop"; true },
            kill = { events += "unexpected_kill" },
            waitUntilGone = { events += "unexpected_wait"; true },
            foregroundStillVisible = { events += "unexpected_foreground_check"; true },
            finishRuntimeStop = { events += "unexpected_release:$it" },
        ))
        assertEquals(listOf("common_not_foreground"), events)
    }

    @Test fun leavingForegroundAfterOldRuntimeExitDoesNotReleaseBootstrap() {
        val events = mutableListOf<String>()
        assertFalse(RuntimeRelaunchOrder.run(
            runtimePid = 42,
            ownUid = 10001,
            processes = { mapOf(42 to RuntimeProcessInfo(10001, "ru.nelomai.client:runtime")) },
            foregroundHandoff = { true },
            stopVpn = { true },
            kill = { events += "runtime_killed" },
            waitUntilGone = { events += "runtime_gone"; true },
            foregroundStillVisible = { false },
            finishRuntimeStop = { events += "runtime_stop_confirmed:$it" },
        ))
        assertEquals(listOf("runtime_killed", "runtime_gone", "runtime_stop_confirmed:false"), events)
    }

    @Test fun restartHandoffHasAnIsolatedTaskAndClearsTheRuntimeTaskOnlyAfterRelease() {
        val handoff = RuntimeRestartLaunchPolicy.handoffFlags()
        assertEquals(Intent.FLAG_ACTIVITY_NEW_TASK, handoff and Intent.FLAG_ACTIVITY_NEW_TASK)
        assertEquals(Intent.FLAG_ACTIVITY_MULTIPLE_TASK, handoff and Intent.FLAG_ACTIVITY_MULTIPLE_TASK)
        assertEquals(0, handoff and Intent.FLAG_ACTIVITY_CLEAR_TASK)

        val bootstrap = RuntimeRestartLaunchPolicy.bootstrapFlags()
        assertEquals(Intent.FLAG_ACTIVITY_NEW_TASK, bootstrap and Intent.FLAG_ACTIVITY_NEW_TASK)
        assertEquals(Intent.FLAG_ACTIVITY_CLEAR_TASK, bootstrap and Intent.FLAG_ACTIVITY_CLEAR_TASK)

        val manifest = sequenceOf(
            File("app/src/main/AndroidManifest.xml"),
            File("src/main/AndroidManifest.xml"),
        ).first { it.isFile }.readText()
        assertTrue(manifest.contains("android:name=\".RuntimeRestartActivity\""))
        assertTrue(manifest.contains("android:exported=\"false\""))
        assertTrue(manifest.contains("android:taskAffinity=\"\${applicationId}.runtime_restart\""))
    }

    @Test fun ownerReloadRequiresBoundedCloseAndOpenAcknowledgements() {
        RuntimeOwnerReloadGate.finish()
        assertTrue(RuntimeOwnerReloadGate.begin())
        assertFalse(RuntimeOwnerReloadGate.begin())
        RuntimeOwnerReloadGate.ownerStopped(true)
        assertTrue(RuntimeOwnerReloadGate.awaitStopped(1, java.util.concurrent.TimeUnit.SECONDS))
        RuntimeOwnerReloadGate.ownerReady(true)
        assertTrue(RuntimeOwnerReloadGate.awaitReady(1, java.util.concurrent.TimeUnit.SECONDS))
        RuntimeOwnerReloadGate.finish()
    }
}
