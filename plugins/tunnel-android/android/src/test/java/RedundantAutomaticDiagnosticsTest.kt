package ru.nelomai.tunnel

import android.content.Context
import android.net.VpnService
import android.os.Looper
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.LooperMode
import org.robolectric.util.ReflectionHelpers
import ru.nelomai.runtime.v1.RuntimeVpnHostV1
import java.io.File
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit

/** Real service factory, coordinator, preferences, sealing and compressed report files.
 * Native/network edges are replaced; timers are held so tests cannot upload anything. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE,
    shadows = [CompletionNoLibrary::class, DiagnosticDirectorySyncShadow::class, VpnExitActivityManagerShadow::class])
@LooperMode(LooperMode.Mode.PAUSED)
class RedundantAutomaticDiagnosticsTest {
    @Test fun initialStartCreatesCheckpointAndOneStopReport() = fixture { f ->
        val owner = f.owner()
        assertTrue(owner.start(f.tx, configs()))
        f.idle()
        assertTrue("successful redundant Start must open diagnostics", f.running())
        val id = f.session()
        assertNotNull(ReflectionHelpers.getField<Any?>(AutomaticDiagnostics, "checkpointFuture"))
        f.diagnostics("checkpoint", f.context)
        assertEquals(listOf("six_hour_checkpoint"), f.reports().map { it.getString("trigger") })
        assertEquals(id, f.session())
        AutomaticDiagnostics.onTunnelStopped(f.context)
        AutomaticDiagnostics.onTunnelStopped(f.context)
        val reports = f.reports()
        assertEquals(2, reports.size)
        assertEquals(setOf(1, 2), reports.map { it.getInt("sequence") }.toSet())
        assertEquals(setOf(id), reports.map { it.getString("tunnel_session_id") }.toSet())
        assertEquals(1, reports.count { it.getString("trigger") == "tunnel_stopped" })
    }

    @Test fun completedServiceStopSealsExactlyOnceBeforeServiceDestruction() = fixture { f ->
        val owner = f.owner()
        assertTrue(owner.start(f.tx, configs())); f.idle()
        val id = f.session()
        assertTrue(owner.revoke())
        val complete = f.stopCompletion(f.tx.startOperationId, owner)
        complete()
        assertFalse("completed service Stop must end diagnostics", f.running())
        val report = f.reports().single()
        assertEquals("tunnel_stopped", report.getString("trigger"))
        assertEquals(id, report.getString("tunnel_session_id"))
        assertEquals(1, report.getInt("sequence"))
        complete()
        AutomaticDiagnostics.initialize(f.context)
        assertEquals("neither duplicate completion nor next process initialization may reseal", 1, f.reports().size)
    }

    @Test fun staleStopCompletionCannotSealCurrentSession() = fixture { f ->
        val owner = f.owner()
        assertTrue(owner.start(f.tx, configs())); f.idle()
        val id = f.session()
        f.stopCompletion("old-start", null)()
        assertTrue(f.running())
        assertEquals(id, f.session())
        assertTrue(f.reports().isEmpty())
    }

    @Test fun automaticRestartSealsTheOldSessionAfterItsStopRecordIsRetired() = fixture { f ->
        var stoppedBeforePanelAck = false
        val owner = f.owner(onPanelStop = {
            stoppedBeforePanelAck = f.prefs.getBoolean("stopped_session_pending", false)
        })
        assertTrue(owner.start(f.tx, configs())); f.idle()
        val oldSession = f.session()
        assertTrue(f.store.prepareRedundantTotalLoss(f.tx.startOperationId,
            redundantTotalLossRestartReplay(f.tx, "replacement")) is RecoveryStoreResult.Success)
        assertTrue(f.store.deferRedundantStop("stop", f.tx.startOperationId) is RecoveryStoreResult.Success)

        assertTrue(owner.revoke())
        assertTrue("Mark the old session before requesting panel cleanup", stoppedBeforePanelAck)
        assertNull(owner.status())
        AutomaticDiagnostics.onTunnelStarted(f.context, "lease-new", "amneziawg",
            "new-owner", f.tx.template.deviceId)

        val report = f.reports().single()
        assertEquals(oldSession, report.getString("tunnel_session_id"))
        assertEquals("tunnel_stopped", report.getString("trigger"))
        assertTrue(f.running())
        assertNotEquals(oldSession, f.session())
    }

    @Test fun failedRouteReplacementSealsAsStoppedEvenIfUploadRunsDuringClosure() = fixture { f ->
        val barrier = ReflectionHelpers.getField<RedundantStopLookupBarrier>(f.service, "redundantStopLookupBarrier")
        val owner = f.owner(onNativeStop = {
            val lookup = barrier.begin()
            try {
                AutomaticDiagnostics.runScheduledUpload(f.context) {}
                f.diagnostics("processNext", f.context)
            } finally {
                barrier.complete(lookup)
            }
        })
        assertTrue(owner.start(f.tx, configs())); f.idle()
        val oldSession = f.session()

        assertFalse(owner.refreshLocalRoutes(true) { false })
        AutomaticDiagnostics.runScheduledUpload(f.context) {}
        f.diagnostics("processNext", f.context)

        val report = f.reports().single()
        assertEquals(oldSession, report.getString("tunnel_session_id"))
        assertEquals("tunnel_stopped", report.getString("trigger"))
    }

    @Test fun recoveryOpensSessionAndRepeatedReadinessAndRoleSwitchDoNotDuplicateIt() = fixture { f ->
        assertTrue(f.store.beginRedundant(f.tx) is RecoveryStoreResult.Success)
        val owner = f.owner()
        assertTrue(owner.recover())
        f.idle()
        assertTrue("recovered owner must open diagnostics", f.running())
        val id = f.session()
        val started = f.prefs.getLong("interval_started_at", 0)
        // Real coordinator promotion changes the active lease, not the session.
        assertTrue(owner.slotFailed("lease-a", "test_failure"))
        repeat(3) {
            f.publish(owner)
            assertTrue(owner.resume())
            f.idle()
        }
        assertEquals("lease-b", owner.status()?.localActiveLeaseId)
        assertEquals(id, f.session())
        assertEquals(started, f.prefs.getLong("interval_started_at", 0))
        assertEquals(0, f.reports().size)
        AutomaticDiagnostics.onTunnelStopped(f.context)
        assertEquals(1, f.reports().size)
    }

    @Test fun processRestartSealsOldIntervalThenStartsExactlyOneRecoveredInterval() = fixture { f ->
        val owner = f.owner()
        assertTrue(owner.start(f.tx, configs())); f.idle()
        assertTrue(f.running())
        val oldId = f.session()
        org.robolectric.shadows.ShadowProcess.setPid(android.os.Process.myPid() + 1)
        AutomaticDiagnostics.initialize(f.context)
        assertEquals(1, f.reports().size)
        assertFalse(f.running())
        val recovered = f.owner()
        assertTrue(recovered.recover()); f.idle()
        val newId = f.session()
        assertNotEquals(oldId, newId)
        f.publish(recovered); f.idle()
        assertEquals(newId, f.session())
        AutomaticDiagnostics.onTunnelStopped(f.context)
        assertEquals(2, f.reports().size)
        assertEquals(2, f.reports().map { it.getString("tunnel_session_id") }.toSet().size)
    }

    @Test fun failedOrRetiredOwnerCannotOpenDiagnostics() = fixture { f ->
        val owner = f.owner(usable = false)
        assertFalse(owner.start(f.tx, configs())); f.idle()
        assertFalse(f.running())
        f.service.installRedundantVpnOwner(null)
        f.publish(owner); f.idle()
        assertFalse(f.running())
        assertEquals(0, f.reports().size)
    }

    @Test fun cancelledStartAndRetiredReadyOwnerCannotStartAnInterval() = fixture { f ->
        val owner = f.owner()
        assertTrue(owner.start(f.tx, configs()))
        // Stop wins before the queued ready callback reaches the service.
        assertTrue(f.store.updateRedundant { it.copy(desiredActive = false) } is RecoveryStoreResult.Success)
        f.idle()
        assertFalse(f.running())
        f.service.installRedundantVpnOwner(null)
        f.publish(owner); f.idle()
        assertFalse(f.running())
        assertTrue(f.reports().isEmpty())
    }

    @Test fun repeatedReadyRepairsCancelledCheckpointWithoutChangingInterval() = fixture { f ->
        val owner = f.owner()
        assertTrue(owner.start(f.tx, configs())); f.idle()
        val id = f.session()
        val future = ReflectionHelpers.getField<java.util.concurrent.ScheduledFuture<*>>(
            AutomaticDiagnostics, "checkpointFuture")
        future.cancel(false)
        f.publish(owner); f.idle()
        val repaired = ReflectionHelpers.getField<java.util.concurrent.ScheduledFuture<*>>(
            AutomaticDiagnostics, "checkpointFuture")
        assertNotSame(future, repaired)
        assertFalse(repaired.isCancelled)
        assertEquals(id, f.session())
        assertTrue(f.reports().isEmpty())
        // A fresh owner in the same process is still the same server session.
        val recovered = f.owner()
        assertTrue(recovered.recover()); f.idle()
        assertEquals(id, f.session())
        assertSame(repaired, ReflectionHelpers.getField<Any>(AutomaticDiagnostics, "checkpointFuture"))
        assertTrue(f.reports().isEmpty())
    }

    @Test fun healthReadinessMustPrecedeDiagnostics() = fixture { f ->
        val owner = f.owner()
        val probe = BackgroundRedundantHealthProbe("dns_a", "8.8.8.8", "nelomai.ru", 4_000)
        assertTrue(owner.start(f.tx, configs(), mapOf("lease-a" to probe, "lease-b" to probe)))
        f.idle()
        assertFalse(owner.isRunning())
        assertFalse(f.running())
        assertTrue(owner.onHealthObservations(listOf(SlotObservation(index = 0, active = true,
            health = BackendHealth.READY, handshakeFresh = true, consecutiveProbeSuccesses = 3,
            stableSinceMs = 0, successfulProbeValidThroughElapsedMs = Long.MAX_VALUE))))
        f.idle()
        assertTrue(owner.isRunning())
        assertTrue(f.running())
        assertTrue(f.reports().isEmpty())
    }

    @Test fun systemUploadDoesNotSealLiveRedundantSession() = fixture { f ->
        val owner = f.owner()
        assertTrue(owner.start(f.tx, configs())); f.idle()
        assertTrue(owner.isRunning())
        AutomaticDiagnostics.runScheduledUpload(f.context) {}
        assertFalse(f.prefs.getBoolean("stopped_session_pending", false))
        f.diagnostics("processNext", f.context)
        assertTrue(f.running())
        assertTrue(f.reports().isEmpty())
    }

    @Test fun recoveredReadinessIsPublishedAfterTemporaryStopLookup() = fixture { f ->
        val owner = f.owner()
        val barrier = ReflectionHelpers.getField<RedundantStopLookupBarrier>(f.service, "redundantStopLookupBarrier")
        val lookup = barrier.begin()
        assertTrue(owner.start(f.tx, configs()))
        f.idle()
        assertTrue(owner.isRunning())
        assertFalse(f.running())

        assertTrue(barrier.complete(lookup))
        ReflectionHelpers.getField<Runnable>(f.service, "redundantHealthTick").run()
        f.idle()
        assertTrue(f.running())
    }

    @Test fun livenessSamplePreservesRecentHistoryOnProcessRecovery() = fixture { f ->
        val owner = f.owner()
        assertTrue(owner.start(f.tx, configs())); f.idle()
        val oldStart = System.currentTimeMillis() / 1000L - 60
        f.prefs.edit().putLong("interval_started_at", oldStart)
            .putLong("session_last_live_at", oldStart).commit()
        TunnelLog.info("test.redundant_live")
        f.memorySample()
        AutomaticDiagnostics.initialize(f.context)
        val report = f.reports().single()
        assertTrue(report.getLong("interval_ended_at_unix") > oldStart)
        assertTrue(report.getString("helper_log").contains("test.redundant_live"))
    }

    @Test fun missingOwnerStillSealsInterruptedSession() = fixture { f ->
        val owner = f.owner()
        assertTrue(owner.start(f.tx, configs())); f.idle()
        f.service.installRedundantVpnOwner(null)
        AutomaticDiagnostics.runScheduledUpload(f.context) {}
        f.diagnostics("processNext", f.context)
        assertFalse(f.running())
        assertEquals(listOf("tunnel_interrupted"), f.reports().map { it.getString("trigger") })
    }

    @Test fun anotherSessionMustNotKeepOldDiagnosticIntervalAlive() = fixture { f ->
        val owner = f.owner()
        assertTrue(owner.start(f.tx, configs())); f.idle()
        assertTrue(f.store.updateRedundant { it.copy(sessionId = "33333333-3333-4333-8333-333333333333") }
            is RecoveryStoreResult.Success)
        val oldLive = System.currentTimeMillis() / 1000L - 60
        f.prefs.edit().putLong("session_last_live_at", oldLive).commit()
        f.memorySample()
        assertEquals(oldLive, f.prefs.getLong("session_last_live_at", 0))
        AutomaticDiagnostics.runScheduledUpload(f.context) {}
        f.diagnostics("processNext", f.context)
        assertFalse(f.running())
    }

    @Test fun unreadableRecoveryDoesNotDeclareLiveOwnerStopped() = fixture { f ->
        val owner = f.owner()
        assertTrue(owner.start(f.tx, configs())); f.idle()
        val id = f.session()
        val oldLive = System.currentTimeMillis() / 1000L - 60
        f.prefs.edit().putLong("session_last_live_at", oldLive).commit()
        f.failRecoveryReads(true)
        f.memorySample()
        assertEquals(oldLive, f.prefs.getLong("session_last_live_at", 0))
        AutomaticDiagnostics.runScheduledUpload(f.context) {}
        assertFalse(f.prefs.getBoolean("stopped_session_pending", false))
        assertTrue(f.running())
        assertEquals(id, f.session())
        f.failRecoveryReads(false)
        f.memorySample()
        assertTrue(f.prefs.getLong("session_last_live_at", 0) > oldLive)
        assertTrue(f.reports().isEmpty())
    }

    @Test fun durableStopCannotBeHiddenByStillInstalledOwner() = fixture { f ->
        val owner = f.owner()
        assertTrue(owner.start(f.tx, configs())); f.idle()
        val oldLive = System.currentTimeMillis() / 1000L - 60
        f.prefs.edit().putLong("session_last_live_at", oldLive).commit()
        assertTrue(f.store.updateRedundant { it.copy(desiredActive = false) } is RecoveryStoreResult.Success)
        assertTrue(owner.isRunning())
        f.memorySample()
        assertEquals(oldLive, f.prefs.getLong("session_last_live_at", 0))
        AutomaticDiagnostics.runScheduledUpload(f.context) {}
        f.diagnostics("processNext", f.context)
        assertFalse(f.running())
        assertEquals(1, f.reports().size)
    }

    @Test fun legacySessionStillUsesLegacyRuntimeState() = fixture { f ->
        val state = ReflectionHelpers.getField<TunnelStateGate>(TunnelRuntime, "stateGate")
        val previous = state.current()
        try {
            AutomaticDiagnostics.onTunnelStarted(f.context, "lease", "wireguard")
            state.complete(SessionState.RUNNING)
            AutomaticDiagnostics.runScheduledUpload(f.context) {}
            f.diagnostics("processNext", f.context)
            assertTrue(f.running())
            assertTrue(f.reports().isEmpty())
            state.complete(SessionState.STOPPED)
            AutomaticDiagnostics.runScheduledUpload(f.context) {}
            f.diagnostics("processNext", f.context)
            assertFalse(f.running())
            assertEquals(1, f.reports().size)
        } finally { state.complete(previous) }
    }

    @Test fun routeMetadataRefreshPreservesSameDiagnosticSession() = fixture { f ->
        val owner = f.owner()
        assertTrue(owner.start(f.tx, configs())); f.idle()
        val id = f.session()
        val checkpoint = ReflectionHelpers.getField<Any>(AutomaticDiagnostics, "checkpointFuture")
        val slot = ReflectionHelpers.getField<RedundantVpnOwnerSlot>(f.service, "redundantVpnOwnerSlot")
        val effective = AndroidSplitTunnel.resolveOptions(34,
            f.tx.template.options.toTunnelOptionsArgs(), f.tx.template.egressMode,
            privateDnsHostname = null)
        repeat(3) {
            val before = slot.snapshot()
            f.duringRecoveryRead({ slot.updateRouteBaseline(owner, null, effective) }) {
                AutomaticDiagnostics.runScheduledUpload(f.context) {}
                f.diagnostics("processNext", f.context)
            }
            assertNotSame(before, slot.snapshot())
            assertSame(owner, slot.snapshot()?.owner)
            assertEquals(f.tx.startOperationId, slot.snapshot()?.startOperationId)
            assertTrue(owner.isRunning())
            assertTrue(f.running())
            assertEquals(id, f.session())
            assertSame(checkpoint, ReflectionHelpers.getField<Any>(AutomaticDiagnostics, "checkpointFuture"))
            assertTrue(f.reports().isEmpty())
        }
        val oldLive = System.currentTimeMillis() / 1000L - 60
        f.prefs.edit().putLong("session_last_live_at", oldLive).commit()
        f.duringRecoveryRead({ slot.updateRouteBaseline(owner, null, effective) }) { f.memorySample() }
        assertTrue(f.prefs.getLong("session_last_live_at", 0) > oldLive)
        AutomaticDiagnostics.onTunnelStopped(f.context)
        AutomaticDiagnostics.onTunnelStopped(f.context)
        assertEquals(1, f.reports().size)
    }

    @Test fun ownerReplacementDuringReadIsUnknownUntilNextObservation() = fixture { f ->
        val owner = f.owner()
        assertTrue(owner.start(f.tx, configs())); f.idle()
        val slot = ReflectionHelpers.getField<RedundantVpnOwnerSlot>(f.service, "redundantVpnOwnerSlot")
        val replacement = object : RedundantVpnProcessOwner by owner {}
        f.duringRecoveryRead({ slot.install(replacement, f.tx.startOperationId) }) {
            assertNull(NelomaiVpnService.redundantDiagnosticsSessionRunning(f.tx.sessionId, f.tx.template.deviceId))
        }
        assertEquals(true, NelomaiVpnService.redundantDiagnosticsSessionRunning(f.tx.sessionId, f.tx.template.deviceId))
        assertTrue(f.running())
        assertTrue(f.reports().isEmpty())
    }

    @Test fun operationReplacementDuringReadCannotRefreshOldSession() = fixture { f ->
        val owner = f.owner()
        assertTrue(owner.start(f.tx, configs())); f.idle()
        val slot = ReflectionHelpers.getField<RedundantVpnOwnerSlot>(f.service, "redundantVpnOwnerSlot")
        val oldLive = System.currentTimeMillis() / 1000L - 60
        f.prefs.edit().putLong("session_last_live_at", oldLive).commit()
        f.duringRecoveryRead({ slot.install(owner, "different-operation") }) { f.memorySample() }
        assertEquals(oldLive, f.prefs.getLong("session_last_live_at", 0))
        // A subsequent stable observation must reject the old durable transaction.
        assertEquals(false, NelomaiVpnService.redundantDiagnosticsSessionRunning(f.tx.sessionId, f.tx.template.deviceId))
        AutomaticDiagnostics.runScheduledUpload(f.context) {}
        f.diagnostics("processNext", f.context)
        assertFalse(f.running())
    }

    @Test fun localStopAckPersistsNormalEndBeforeRemoteCleanupAndProcessExit() = fixture { f ->
        val owner = f.owner()
        assertTrue(owner.start(f.tx, configs())); f.idle()
        val id = f.session()
        assertTrue(f.store.cancelRedundantIntentAndDeferStop("stop", f.tx.startOperationId) is RecoveryStoreResult.Success)
        assertTrue(owner.closeDataplaneForStop())
        val waiters = ReflectionHelpers.getField<MutableMap<String, MutableList<(RedundantRevokeResult) -> Unit>>>(
            f.service, "redundantStopWaiters")
        var acknowledged = false
        waiters[f.tx.startOperationId] = mutableListOf({
            assertTrue("normal stop must be durable before owner may kill VPN process",
                f.prefs.getBoolean("stopped_session_pending", false))
            assertEquals("tunnel_stopped", f.prefs.getString("stopped_session_trigger", null))
            assertTrue("ACK must not wait for report construction", f.reports().isEmpty())
            acknowledged = true
        })
        call(f.service, "completeRedundantStopWaiters", f.tx.startOperationId, RedundantRevokeResult(true, true))
        assertTrue(acknowledged)
        val endedAt = f.prefs.getLong("stopped_session_ended_at", 0)
        assertTrue(endedAt > 0)
        call(f.service, "completeRedundantStopWaiters", f.tx.startOperationId, RedundantRevokeResult(true, true))
        f.diagnostics("checkpoint", f.context)
        assertTrue(f.reports().isEmpty())
        assertEquals(endedAt, f.prefs.getLong("stopped_session_ended_at", 0))
        // Re-enter the real startup recovery, as after process death before remote cleanup.
        f.service.installRedundantVpnOwner(null)
        AutomaticDiagnostics.initialize(f.context)
        AutomaticDiagnostics.initialize(f.context)
        AutomaticDiagnostics.onTunnelStopped(f.context)
        val report = f.reports().single()
        assertEquals("tunnel_stopped", report.getString("trigger"))
        assertEquals(id, report.getString("tunnel_session_id"))
        assertEquals(endedAt, report.getLong("interval_ended_at_unix"))
    }

    @Test fun staleOrUnconfirmedStopCannotMarkCurrentDiagnosticsNormallyStopped() {
        for (case in listOf("unfenced", "not_closed", "other_operation", "other_session", "other_device", "still_active", "retired_service")) fixture { f ->
            val owner = f.owner()
            assertTrue(owner.start(f.tx, configs())); f.idle()
            if (case != "still_active") assertTrue(f.store.cancelRedundantIntentAndDeferStop("stop", f.tx.startOperationId) is RecoveryStoreResult.Success)
            if (case == "other_session") f.prefs.edit().putString("session_owner_id", "other").commit()
            if (case == "other_device") f.prefs.edit().putString("session_device_id", "other").commit()
            if (case == "retired_service") ReflectionHelpers.setField(f.service, "serviceDestroyed", true)
            call(f.service, "completeRedundantStopWaiters", if (case == "other_operation") "retired" else f.tx.startOperationId,
                RedundantRevokeResult(case != "unfenced", case != "not_closed"))
            assertFalse(case, f.prefs.getBoolean("stopped_session_pending", false))
        }
    }

    @Test fun diagnosticReadFailureStillAcknowledgesClosedDataplane() = fixture { f ->
        val owner = f.owner()
        assertTrue(owner.start(f.tx, configs())); f.idle()
        assertTrue(owner.closeDataplaneForStop())
        val waiters = ReflectionHelpers.getField<MutableMap<String, MutableList<(RedundantRevokeResult) -> Unit>>>(f.service, "redundantStopWaiters")
        var acknowledged = false
        waiters[f.tx.startOperationId] = mutableListOf({ acknowledged = it.fenced && it.stopped })
        f.failRecoveryReads(true)
        try {
            call(f.service, "completeRedundantStopWaiters", f.tx.startOperationId, RedundantRevokeResult(true, true))
            assertTrue(acknowledged)
        } finally { f.failRecoveryReads(false) }
    }

    @Test fun normalCleanupPreservesLocalStopTimeWithoutDuplicateReport() = fixture { f ->
        val owner = f.owner()
        assertTrue(owner.start(f.tx, configs())); f.idle()
        assertTrue(f.store.cancelRedundantIntentAndDeferStop("stop", f.tx.startOperationId) is RecoveryStoreResult.Success)
        assertTrue(owner.closeDataplaneForStop())
        call(f.service, "completeRedundantStopWaiters", f.tx.startOperationId, RedundantRevokeResult(true, true))
        // Simulate time spent in remote cleanup without making the test sleep.
        val end = System.currentTimeMillis() / 1000L - 10
        f.prefs.edit().putLong("interval_started_at", end - 10).putLong("stopped_session_ended_at", end).commit()
        AutomaticDiagnostics.onTunnelStopped(f.context)
        AutomaticDiagnostics.onTunnelStopped(f.context)
        assertEquals(end, f.reports().single().getLong("interval_ended_at_unix"))
    }

    @Test fun serviceRetiredDuringRecoveryReadCannotSealDiagnostics() = fixture { f ->
        val owner = f.owner()
        assertTrue(owner.start(f.tx, configs())); f.idle()
        assertTrue(f.store.cancelRedundantIntentAndDeferStop("stop", f.tx.startOperationId) is RecoveryStoreResult.Success)
        f.duringRecoveryRead({ ReflectionHelpers.setField(f.service, "serviceDestroyed", true) }) {
            call(f.service, "completeRedundantStopWaiters", f.tx.startOperationId, RedundantRevokeResult(true, true))
        }
        assertFalse(f.prefs.getBoolean("stopped_session_pending", false))
    }


    @Test fun scheduledUploadBeforeLocalAckRemainsNormalAfterProcessExit() = fixture { f ->
        val owner = f.owner()
        assertTrue(owner.start(f.tx, configs())); f.idle()
        assertTrue(f.store.cancelRedundantIntentAndDeferStop("stop", f.tx.startOperationId) is RecoveryStoreResult.Success)
        assertTrue(owner.closeDataplaneForStop())
        // JobService may run while the cleanup thread has closed the dataplane,
        // before restoreHandler processes the local close completion.
        AutomaticDiagnostics.runScheduledUpload(f.context) {}
        call(f.service, "completeRedundantStopWaiters", f.tx.startOperationId, RedundantRevokeResult(true, true))
        f.service.installRedundantVpnOwner(null)
        AutomaticDiagnostics.initialize(f.context)
        AutomaticDiagnostics.initialize(f.context)
        assertEquals("tunnel_stopped", f.reports().single().getString("trigger"))
    }

    @Test fun scheduledMaterializationBeforeLocalAckDoesNotReportInterruption() = fixture { f ->
        val owner = f.owner()
        assertTrue(owner.start(f.tx, configs())); f.idle()
        assertTrue(f.store.cancelRedundantIntentAndDeferStop("stop", f.tx.startOperationId) is RecoveryStoreResult.Success)
        assertTrue(owner.closeDataplaneForStop())
        AutomaticDiagnostics.runScheduledUpload(f.context) {}
        f.diagnostics("processNext", f.context)
        assertTrue("no report before local closure is acknowledged", f.reports().isEmpty())
        call(f.service, "completeRedundantStopWaiters", f.tx.startOperationId, RedundantRevokeResult(true, true))
        AutomaticDiagnostics.onTunnelStopped(f.context)
        assertEquals("tunnel_stopped", f.reports().single().getString("trigger"))
    }


    @Test fun scheduledUploadWaitsForPendingCleanupAfterRecoveryRecordIsRemoved() = fixture { f ->
        val owner = f.owner()
        assertTrue(owner.start(f.tx, configs())); f.idle()
        val complete = f.stopCompletion(f.tx.startOperationId, owner)
        assertTrue(owner.revoke())
        assertNull((f.store.read() as RecoveryStoreResult.Success).value.redundantTransaction)
        AutomaticDiagnostics.runScheduledUpload(f.context) {}
        f.diagnostics("processNext", f.context)
        assertTrue("the matching cleanup completion still owns normal termination", f.reports().isEmpty())
        complete()
        AutomaticDiagnostics.initialize(f.context)
        assertEquals("tunnel_stopped", f.reports().single().getString("trigger"))
    }

    @Test fun scheduledUploadDoesNotHideUnrequestedOrForeignStop() {
        for (case in listOf("not_fenced", "other_session", "other_device", "other_operation")) fixture { f ->
            val owner = f.owner()
            assertTrue(owner.start(f.tx, configs())); f.idle()
            val id = f.session()
            if (case != "not_fenced") {
                assertTrue(f.store.cancelRedundantIntentAndDeferStop("stop", f.tx.startOperationId) is RecoveryStoreResult.Success)
            }
            if (case == "other_session") f.prefs.edit().putString("session_owner_id", "other").commit()
            if (case == "other_device") f.prefs.edit().putString("session_device_id", "other").commit()
            if (case == "other_operation") {
                ReflectionHelpers.getField<RedundantVpnOwnerSlot>(f.service, "redundantVpnOwnerSlot")
                    .install(owner, "other-start")
            }
            assertTrue(owner.closeDataplaneForStop())
            AutomaticDiagnostics.runScheduledUpload(f.context) {}
            f.diagnostics("processNext", f.context)
            assertEquals(case, "tunnel_interrupted", f.reports()
                .single { it.getString("tunnel_session_id") == id }.getString("trigger"))
        }
    }


    @Test fun normalStopRetainsOriginalIdentityAfterContainerUpdate() = fixture { f ->
        f.containerVersion("0.3.13")
        val owner = f.owner()
        assertTrue(owner.start(f.tx, configs())); f.idle()
        assertTrue(f.store.cancelRedundantIntentAndDeferStop("stop", f.tx.startOperationId) is RecoveryStoreResult.Success)
        assertTrue(owner.closeDataplaneForStop())
        f.withDiagnosticOwner("0.3.13") {
            call(f.service, "completeRedundantStopWaiters", f.tx.startOperationId, RedundantRevokeResult(true, true))
        }
        assertTrue(f.reports().isEmpty())
        f.service.installRedundantVpnOwner(null)
        f.containerVersion("0.3.14")
        AutomaticDiagnostics.initialize(f.context)
        AutomaticDiagnostics.initialize(f.context)
        f.assertOriginalIdentity(f.reports().single())
    }

    @Test fun normalStopKeepsIdentityWhenBackgroundJobSealsFirst() = fixture { f ->
        f.containerVersion("0.3.13")
        val owner = f.owner()
        assertTrue(owner.start(f.tx, configs())); f.idle()
        assertTrue(f.store.cancelRedundantIntentAndDeferStop("stop", f.tx.startOperationId) is RecoveryStoreResult.Success)
        assertTrue(owner.closeDataplaneForStop())
        f.withDiagnosticOwner("0.3.13") {
            call(f.service, "completeRedundantStopWaiters", f.tx.startOperationId, RedundantRevokeResult(true, true))
        }
        f.diagnostics("processNext", f.context)
        AutomaticDiagnostics.onTunnelStopped(f.context)
        f.assertOriginalIdentity(f.reports().single())
    }

    @Test fun normalStopIdentityIsNotReplacedByRepeatedAckOrCleanup() = fixture { f ->
        f.containerVersion("0.3.13")
        val owner = f.owner()
        assertTrue(owner.start(f.tx, configs())); f.idle()
        assertTrue(f.store.cancelRedundantIntentAndDeferStop("stop", f.tx.startOperationId) is RecoveryStoreResult.Success)
        assertTrue(owner.closeDataplaneForStop())
        f.withDiagnosticOwner("0.3.13") {
            call(f.service, "completeRedundantStopWaiters", f.tx.startOperationId, RedundantRevokeResult(true, true))
        }
        f.containerVersion("0.3.14")
        f.withDiagnosticOwner("0.3.14") {
            call(f.service, "completeRedundantStopWaiters", f.tx.startOperationId, RedundantRevokeResult(true, true))
            AutomaticDiagnostics.onTunnelStopped(f.context)
        }
        f.assertOriginalIdentity(f.reports().single())
        // A later session must not inherit the earlier normal-stop identity.
        AutomaticDiagnostics.onTunnelStarted(f.context, null, "amneziawg_3", "next-session", f.tx.template.deviceId)
        AutomaticDiagnostics.initialize(f.context)
        val interrupted = f.reports().single { it.getString("trigger") == "tunnel_interrupted" }
        assertEquals("0.3.14", interrupted.getString("app_version"))
        assertFalse(interrupted.has("container_version"))
    }

    @Test fun legacyNormalStopMarkerDoesNotAcquireCurrentRuntimeIdentity() = fixture { f ->
        val owner = f.owner()
        assertTrue(owner.start(f.tx, configs())); f.idle()
        f.prefs.edit().putBoolean("stopped_session_pending", true)
            .putString("stopped_session_trigger", "tunnel_stopped")
            .putLong("stopped_session_ended_at", System.currentTimeMillis() / 1000L).commit()
        f.containerVersion("0.3.14")
        f.withDiagnosticOwner("0.3.14") { AutomaticDiagnostics.onTunnelStopped(f.context) }
        val report = f.reports().single()
        assertEquals("0.3.14", report.getString("app_version"))
        assertFalse(report.has("container_version"))
        assertFalse(report.has("runtime_version"))
    }

    @Test fun normalStopIdentitySurvivesUnfinishedCheckpointMaterialization() = fixture { f ->
        f.containerVersion("0.3.13")
        val owner = f.owner()
        assertTrue(owner.start(f.tx, configs())); f.idle()
        // Persisted seals validate lease UUIDs, unlike the coordinator's synthetic lease names.
        f.prefs.edit().putString("session_lease_id", "44444444-4444-4444-8444-444444444444").commit()
        val pending = f.diagnostics("pendingDirectory", f.context) as File
        pending.deleteRecursively(); pending.parentFile!!.mkdirs(); pending.writeText("blocked")
        try {
            f.withDiagnosticOwner("0.3.13") { f.diagnostics("checkpoint", f.context) }
            assertTrue(f.prefs.contains("pending_seal"))
        } finally { pending.delete(); pending.mkdirs() }
        assertTrue(f.store.cancelRedundantIntentAndDeferStop("stop", f.tx.startOperationId) is RecoveryStoreResult.Success)
        assertTrue(owner.closeDataplaneForStop())
        f.withDiagnosticOwner("0.3.13") {
            call(f.service, "completeRedundantStopWaiters", f.tx.startOperationId, RedundantRevokeResult(true, true))
        }
        f.containerVersion("0.3.14")
        AutomaticDiagnostics.initialize(f.context)
        AutomaticDiagnostics.initialize(f.context)
        assertEquals(2, f.reports().size)
        assertEquals(1, f.reports().count { it.getString("trigger") == "six_hour_checkpoint" })
        f.assertOriginalIdentity(f.reports().single { it.getString("trigger") == "tunnel_stopped" })
    }

    @Test fun normalStopDoesNotClaimRuntimeFromCancelledOrUnprovisionedOwner() {
        for (case in listOf("fenced", "fresh_provision_required", "logout", "foreign_namespace")) fixture { f ->
            f.containerVersion("0.3.13")
            val owner = f.owner()
            assertTrue(owner.start(f.tx, configs())); f.idle()
            val id = f.session()
            assertTrue(f.store.cancelRedundantIntentAndDeferStop("stop", f.tx.startOperationId) is RecoveryStoreResult.Success)
            assertTrue(owner.closeDataplaneForStop())
            f.withDiagnosticOwner("0.3.13", transform = {
                when (case) {
                    "fenced" -> it.copy(ownerCancelEpoch = 1)
                    "fresh_provision_required" -> it.copy(requiresFreshProvision = true)
                    "logout" -> it.copy(active = null, logoutState = BackgroundLogoutState("logout", 1, BackgroundLogoutPhase.PENDING))
                    else -> it.copy(ownerScope = it.ownerScope!!.copy(runtimeVersion = "foreign-runtime"))
                }
            }) { call(f.service, "completeRedundantStopWaiters", f.tx.startOperationId, RedundantRevokeResult(true, true)) }
            f.diagnostics("processNext", f.context)
            val report = f.reports().single { it.getString("tunnel_session_id") == id }
            assertEquals(case, "0.3.13", report.getString("container_version"))
            assertFalse(case, report.has("runtime_version"))
        }
    }

    private class Fixture(val context: Context, val service: NelomaiVpnService,
        val store: AndroidRecoveryStore, val memorySample: () -> Unit,
        val failRecoveryReads: (Boolean) -> Unit) {
        val tx = AndroidRedundantTransaction(true,
            AndroidIntentTemplate("11111111-1111-4111-8111-111111111111", "account",
                "stray", "dynamic", "standalone", "ipv4", true),
            "22222222-2222-4222-8222-222222222222", "lease-a", "lease-b", "lease-a",
            true, 1, 1, "start", "fingerprint")
        val prefs = context.getSharedPreferences(AndroidRuntimeNamespace.record("nelomai-automatic-diagnostics"), 0)
        fun containerVersion(version: String) {
            val info = context.packageManager.getPackageInfo(context.packageName, 0).apply { versionName = version }
            shadowOf(context.packageManager).installPackage(info)
        }
        fun assertOriginalIdentity(report: JSONObject) {
            assertEquals("tunnel_stopped", report.getString("trigger"))
            assertEquals("0.3.13", report.getString("app_version"))
            assertEquals("0.3.13", report.getString("container_version"))
            assertEquals(AndroidRuntimeNamespace.version, report.getString("runtime_version"))
            assertEquals(AndroidRuntimeNamespace.slot, report.getString("runtime_slot"))
            assertEquals(1, report.getInt("runtime_contract_version"))
            assertFalse(report.has("session_generation"))
            assertFalse(report.has("family"))
        }
        fun withDiagnosticOwner(container: String,
            transform: (BackgroundCredentialEnvelope) -> BackgroundCredentialEnvelope = { it },
            block: () -> Unit) {
            val scope = NativeOwnerScope(1, "private-family", tx.template.deviceId,
                AndroidRuntimeNamespace.slot, container, AndroidRuntimeNamespace.version, 1, 7)
            val envelope = transform(BackgroundCredentialEnvelope(revision = 1, deviceId = scope.deviceId,
                panelBase = "https://synthetic.invalid", installSecret = "install", installGeneration = 1,
                active = BackgroundCredential(scope.deviceId, "https://synthetic.invalid", "test-token", 9999999999),
                ownerScope = scope))
            val backend = object : EncryptedRecordBackend {
                var bytes = BackgroundCredentialEnvelopeCodec.encode(envelope)
                override fun read() = bytes.copyOf()
                override fun write(plaintext: ByteArray): Boolean { bytes = plaintext.copyOf(); return true }
            }
            val old = ReflectionHelpers.getField<BackgroundCredentialStore?>(AndroidBackgroundCredentialStores, "instance")
            ReflectionHelpers.setField(AndroidBackgroundCredentialStores, "instance", BackgroundCredentialStore(backend))
            try { block() } finally { ReflectionHelpers.setField(AndroidBackgroundCredentialStores, "instance", old) }
        }
        fun stopCompletion(operation: String, owner: RedundantVpnProcessOwner?): () -> Unit {
            val tombstones = RedundantCancelTombstoneStore(object : RedundantCancelTombstoneBackend {
                var raw: String? = null
                override fun read() = raw
                override fun compareAndWrite(expected: String?, value: String): Boolean {
                    if (raw != expected) return false
                    raw = value; return true
                }
                override fun compareAndClear(expected: String): Boolean {
                    if (raw != expected) return false
                    raw = null; return true
                }
            }) { "test-stop" }
            val tombstone = (tombstones.persist(operation) as RecoveryStoreResult.Success).value
            ReflectionHelpers.setField(service, "redundantCancelTombstones", tombstones)
            val generation = ReflectionHelpers.getField<Long>(service, "serviceGeneration")
            ReflectionHelpers.setField(service, "redundantTotalLossLifecycle", RedundantTotalLossLifecycle(
                currentServiceGeneration = { generation }, serviceActive = { true },
                barrierPending = { false }, logoutState = { BackgroundLogoutReadState.NONE },
                recovery = store::read, post = { it() }, retryCleanup = {},
                publishRestartStarting = {}, resume = {}, scheduleLogout = {},
                scheduleStateReadRetry = {}, stopIfIdle = {},
            ))
            // The real async cleanup result enters the service's completion callback.
            val pendingType = Class.forName("ru.nelomai.tunnel.PendingRedundantStop")
            val pending = pendingType.declaredConstructors.single { !it.isSynthetic }.apply { isAccessible = true }
                .newInstance(operation, tombstone, owner, generation, true, false, null)
            ReflectionHelpers.setField(service, "pendingRedundantStop", pending)
            val attempt = Class.forName("ru.nelomai.tunnel.PendingRedundantStopAttempt")
                .declaredConstructors.single().apply { isAccessible = true }
                .newInstance(pending, tombstone, RedundantRevokeResult(fenced = true, stopped = true))
            return { call(service, "completePendingRedundantStopAttempt", attempt) }
        }
        fun duringRecoveryRead(change: () -> Unit, test: () -> Unit) {
            val backend = ReflectionHelpers.getField<EncryptedRecordBackend>(store, "backend")
            val changed = java.util.concurrent.atomic.AtomicBoolean(false)
            ReflectionHelpers.setField(store, "backend", object : EncryptedRecordBackend {
                override fun read(): ByteArray? = backend.read().also {
                    if (changed.compareAndSet(false, true)) change()
                }
                override fun write(plaintext: ByteArray) = backend.write(plaintext)
            })
            try { test(); assertTrue("interleaving did not execute", changed.get()) }
            finally { ReflectionHelpers.setField(store, "backend", backend) }
        }
        fun running() = prefs.getBoolean("session_running", false)
        fun session() = prefs.getString("session_id", null)
        fun idle() { shadowOf(Looper.getMainLooper()).idle() }
        fun diagnostics(name: String, vararg args: Any?): Any? = call(AutomaticDiagnostics, name, *args)
        fun reports(): List<JSONObject> {
            val dir = diagnostics("pendingDirectory", context) as File
            return dir.listFiles().orEmpty().filter { it.isFile }.map {
                diagnostics("readPendingReport", it) as JSONObject
            }
        }
        fun publish(owner: RedundantConnectionCoordinator) {
            call(service, "publishRedundantRecoveryReadiness", tx.startOperationId, owner, true)
        }
        fun owner(
            usable: Boolean = true,
            onPanelStop: () -> Unit = {},
            onNativeStop: () -> Unit = {},
        ): RedundantConnectionCoordinator {
            val method = service.javaClass.declaredMethods.single { it.name == "createRedundantCoordinator" }
            // The 0.5 factory has an extra TUN readiness argument.
            val args = mutableListOf<Any>(tx, "10.241.0.2/32",
                PhysicalNetworkState(emptyList(), listOf(org.robolectric.shadows.ShadowNetwork.newInstance(1)), true, "test"), false)
            if (method.parameterCount == 5) args.add(false)
            @Suppress("UNCHECKED_CAST")
            val pair = method.apply { isAccessible = true }.invoke(service, *args.toTypedArray())
                as Pair<RedundantConnectionCoordinator, ServiceRedundantConnectionNative>
            val native = object : RedundantConnectionNative {
                override fun start(leaseId: String, slot: RedundantSlot, configuration: ByteArray,
                    healthProbe: BackgroundRedundantHealthProbe?) = usable
                override fun activate(leaseId: String) = usable
                override fun stopSlot(leaseId: String) = true
                override fun stop(): Boolean {
                    onNativeStop()
                    return true
                }
                override fun isUsable(leaseId: String) = usable
            }
            ReflectionHelpers.setField(pair.first, "native", native)
            if (pair.first.javaClass.declaredFields.any { it.name == "onPrimaryReady" }) {
                ReflectionHelpers.setField(pair.first, "onPrimaryReady", { true })
            }
            ReflectionHelpers.setField(pair.first, "panel", object : RedundantConnectionPanel {
                fun session(t: AndroidRedundantTransaction) = BackgroundRedundantSession(t.sessionId,
                    "connected", t.localActiveLeaseId, t.slotALeaseId, t.slotBLeaseId,
                    true, t.roleGeneration, t.membershipGeneration, null)
                override fun recover(transaction: AndroidRedundantTransaction) =
                    RedundantRecoveryResponse(session(transaction), configs())
                override fun reportRole(transaction: AndroidRedundantTransaction, reason: String) =
                    RedundantRoleResponse("acknowledged", requireNotNull(transaction.localActiveLeaseId), session(transaction))
                override fun stop(transaction: AndroidRedundantTransaction): Boolean {
                    onPanelStop()
                    return true
                }
            })
            fencelessInstall(pair.first)
            return pair.first
        }
        private fun fencelessInstall(owner: RedundantConnectionCoordinator) {
            service.installRedundantVpnOwner(owner, tx.startOperationId)
        }
    }

    private fun fixture(test: (Fixture) -> Unit) {
        val controller = Robolectric.buildService(VpnService::class.java).create()
        val host = controller.get()
        val service = NelomaiVpnService(object : RuntimeVpnHostV1 {
            override val service = host
            override fun builder(beforeEstablish: (VpnService.Builder) -> Unit) = host.Builder().also(beforeEstablish)
        })
        var recoveryReadsFail = false
        val store = AndroidRecoveryStore(object : EncryptedRecordBackend {
            var bytes: ByteArray? = null
            override fun read(): ByteArray? {
                check(!recoveryReadsFail) { "test_read_failed" }
                return bytes?.copyOf()
            }
            override fun write(plaintext: ByteArray): Boolean { bytes = plaintext.copyOf(); return true }
        }, BootIdentityProvider { 1L })
        ReflectionHelpers.setField(service, "recoveryStore", store)
        var memoryWatch: Runnable? = null
        val timers = object : ScheduledThreadPoolExecutor(1) {
            override fun schedule(command: Runnable, delay: Long, unit: TimeUnit) =
                super.schedule(command, 365, TimeUnit.DAYS)
            override fun scheduleWithFixedDelay(command: Runnable, initialDelay: Long,
                delay: Long, unit: TimeUnit): java.util.concurrent.ScheduledFuture<*> {
                memoryWatch = command
                return super.scheduleWithFixedDelay(command, 365, 365, TimeUnit.DAYS)
            }
            override fun execute(command: Runnable) = Unit
        }
        val old = ReflectionHelpers.getField<Any>(AutomaticDiagnostics, "executor")
        replaceExecutor(timers)
        val f = Fixture(host.applicationContext, service, store,
            memorySample = { requireNotNull(memoryWatch).run() },
            failRecoveryReads = { recoveryReadsFail = it })
        val previousService = ReflectionHelpers.getStaticField<Any?>(NelomaiVpnService::class.java, "activeService")
        ReflectionHelpers.setStaticField(NelomaiVpnService::class.java, "activeService", service)
        try {
            f.prefs.edit().clear().commit()
            TunnelLog.initialize(f.context)
            test(f)
        } finally {
            recoveryReadsFail = false
            service.installRedundantVpnOwner(null)
            (ReflectionHelpers.getField<android.os.Handler>(service, "restoreHandler")).removeCallbacksAndMessages(null)
            AutomaticDiagnostics.onTunnelStopped(f.context)
            timers.shutdownNow()
            replaceExecutor(old)
            ReflectionHelpers.setStaticField(NelomaiVpnService::class.java, "activeService", previousService)
            controller.destroy()
        }
    }

    companion object {
        private fun configs() = mapOf("lease-a" to byteArrayOf(1), "lease-b" to byteArrayOf(2))
        private fun call(target: Any, name: String, vararg args: Any?): Any? = target.javaClass.declaredMethods
            .single { it.name == name && it.parameterCount == args.size }.apply { isAccessible = true }.invoke(target, *args)
        private fun replaceExecutor(value: Any) {
            val field = AutomaticDiagnostics.javaClass.getDeclaredField("executor")
            val type = Class.forName("sun.misc.Unsafe")
            val unsafe = type.getDeclaredField("theUnsafe").apply { isAccessible = true }.get(null)
            val base = type.getMethod("staticFieldBase", java.lang.reflect.Field::class.java).invoke(unsafe, field)
            val offset = type.getMethod("staticFieldOffset", java.lang.reflect.Field::class.java).invoke(unsafe, field)
            type.getMethod("putObject", Any::class.java, java.lang.Long.TYPE, Any::class.java).invoke(unsafe, base, offset, value)
        }
    }
}
