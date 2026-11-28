package ru.nelomai.tunnel

import android.app.ActivityManager
import android.app.ApplicationExitInfo
import android.app.Application
import android.app.Notification
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.net.VpnService
import android.os.Bundle
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.ResultReceiver
import org.amnezia.awg.backend.GoBackend
import org.amnezia.awg.backend.Tunnel
import org.amnezia.awg.util.SharedLibraryLoader
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements
import org.robolectric.annotation.LooperMode
import org.robolectric.shadows.ShadowActivityManager
import org.robolectric.shadows.ShadowSystemClock
import org.robolectric.util.ReflectionHelpers
import ru.nelomai.client.RuntimeProcessSelection
import ru.nelomai.client.RuntimeSelectionStore
import ru.nelomai.client.RuntimeSelectionV1
import ru.nelomai.runtime.v1.RuntimeVpnHostV1
import java.time.Duration
import java.util.concurrent.AbstractExecutorService
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Delayed
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit

/** Real runtime, backend and service callbacks; only JNI/platform edges are shadowed. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE, shadows = [CompletionNoLibrary::class,
    CompletionNative::class, CompletionVpnPermission::class, CompletionVpnBuilder::class,
    CompletionFileDescriptor::class, CompletionQuickPlan::class, CompletionPanel::class])
@LooperMode(LooperMode.Mode.PAUSED)
class NativeLocalRestartCompletionTest {
    @Test
    @Config(shadows = [NoNativeLibrary::class, OwnershipNative::class, OwnershipVpn::class,
        RetentionServiceBuilder::class, OwnershipDescriptor::class])
    fun forcedStopRequiresDurableCancellationExactVpnProcessAndCurrentEpoch() {
        for (scenario in listOf("force", "active_intent", "other_process", "new_start", "already_stopped")) {
            OwnershipNative.reset(); OwnershipDescriptor.reset(); OwnershipVpn.protectSucceeds = true
            org.robolectric.shadows.ShadowProcess.clearKilledProcesses()
            try { withRuntime(retainTunDescriptor = true) { f ->
                f.armCheckpoint()
                TunnelRuntime.start(f.context, args(), { _, _ -> }, { fail(it) }, keepForegroundServiceOnFailure = true)
                f.work.runNext()
                f.service.onLegacyTransportReady(f.backend)
                val retention = ReflectionHelpers.getField<ServiceTunRetention>(f.service, "tunRetention")
                val pid = android.os.Process.myPid()
                val manager = f.context.getSystemService(android.app.ActivityManager::class.java)
                org.robolectric.Shadows.shadowOf(manager).setProcesses(listOf(
                    android.app.ActivityManager.RunningAppProcessInfo().apply {
                        this.pid = pid; uid = android.os.Process.myUid()
                        processName = f.context.packageName + if (scenario == "other_process") ":runtime" else ":vpn"
                    }))
                if (scenario != "active_intent") assertTrue(f.coordinator.cancelCurrent() is AndroidCoordinatorResult.Accepted)
                ReflectionHelpers.callInstanceMethod<Boolean>(f.service, "releaseProtection",
                    ReflectionHelpers.ClassParameter.from(Boolean::class.javaPrimitiveType, false))
                val expiry = f.timers.scheduled.last()
                assertEquals(40_000L, expiry.second)
                if (scenario == "new_start") retention.allowStart()
                if (scenario == "already_stopped") {
                    TunnelRuntime.stop(TUNNEL_API_VERSION, { _, _ -> }, { fail(it) })
                    f.work.runNext()
                }
                expiry.first.run()
                assertEquals(scenario, scenario == "force", org.robolectric.shadows.ShadowProcess.wasKilled(pid))
                if (scenario == "force") assertFalse(f.envelope().intent.desiredActive)
            } } finally {
                OwnershipNative.reset()
                OwnershipDescriptor.files.values.toSet().forEach { it.delete() }
            }
        }
    }

    @Test
    @Config(shadows = [NoNativeLibrary::class, OwnershipNative::class, OwnershipVpn::class,
        RetentionServiceBuilder::class, OwnershipDescriptor::class])
    fun automaticWatchdogCannotDestroyRetainedProtection() {
        OwnershipNative.reset(); OwnershipDescriptor.reset(); OwnershipVpn.protectSucceeds = true
        org.robolectric.shadows.ShadowProcess.clearKilledProcesses()
        try { withRuntime(retainTunDescriptor = true) { f ->
            TunnelRuntime.start(f.context, args(), { _, _ -> }, { fail(it) }, keepForegroundServiceOnFailure = true)
            f.work.runNext(); f.service.onLegacyTransportReady(f.backend)
            ReflectionHelpers.callInstanceMethod<Unit>(TunnelRuntime, "terminateHungTunnelProcess",
                ReflectionHelpers.ClassParameter.from(Context::class.java, f.context),
                ReflectionHelpers.ClassParameter.from(String::class.java, "metrics"))
            assertFalse(org.robolectric.shadows.ShadowProcess.wasKilled(android.os.Process.myPid()))
            assertEquals("blocked", ReflectionHelpers.getField<ServiceTunRetention>(f.service, "tunRetention").state())
        } } finally { OwnershipNative.reset(); OwnershipDescriptor.files.values.toSet().forEach { it.delete() } }
    }

    @Test
    @Config(shadows = [NoNativeLibrary::class, OwnershipNative::class, OwnershipVpn::class,
        RetentionServiceBuilder::class, OwnershipDescriptor::class])
    fun nativeStartCancellationAfterHandshakeMustReleaseTun() {
        OwnershipNative.reset(); OwnershipDescriptor.reset(); OwnershipVpn.protectSucceeds = true
        try {
            withRuntime(retainTunDescriptor = true) { f ->
                OwnershipNative.statistics = "public_key=${"01".repeat(32)}\nlast_handshake_time_sec=1\n"
                val start = args().apply { startSource = "connection_intent" }
                val id = requireNotNull(start.clientOperationId)
                TunnelRuntime.start(f.context, start, { _, _ -> }, { fail(it) }, keepForegroundServiceOnFailure = true)
                f.work.runNext()
                TunnelRuntime.metrics(TUNNEL_API_VERSION, false, { _, _, _, _ -> }, { fail(it) })
                f.work.runNext()
                // The service-owned Start fence calls this cancellation directly;
                // no Core failed-start compensation follows it.
                TunnelRuntime.cancelClientStart(f.context, id)
                f.work.runNext()
                f.work.runNext()
                assertEquals(SessionState.STOPPED, TunnelRuntime.state())
                assertTrue(OwnershipNative.engineDescriptors.isEmpty())
                assertFalse("Cancelled service-owned initial Start must not retain its TUN",
                    ReflectionHelpers.getField<ServiceTunRetention>(f.service, "tunRetention").hasTun())
            }
        } finally {
            OwnershipNative.reset()
            OwnershipDescriptor.files.values.toSet().forEach { it.delete() }
        }
    }

    @Test
    @Config(shadows = [NoNativeLibrary::class, OwnershipNative::class, OwnershipVpn::class,
        RetentionServiceBuilder::class, OwnershipDescriptor::class])
    fun rejectedInitialStartCloseFailureMustRetry() {
        OwnershipNative.reset(); OwnershipDescriptor.reset(); OwnershipVpn.protectSucceeds = true
        try {
            withRuntime(retainTunDescriptor = true) { f ->
                OwnershipNative.statistics = "public_key=${"01".repeat(32)}\nlast_handshake_time_sec=1\n"
                TunnelRuntime.start(f.context, args().apply { startSource = "user" },
                    { _, _ -> }, { fail(it) }, keepForegroundServiceOnFailure = true)
                f.work.runNext()
                TunnelRuntime.metrics(TUNNEL_API_VERSION, false, { _, _, _, _ -> }, { fail(it) })
                f.work.runNext()
                val retention = ReflectionHelpers.getField<ServiceTunRetention>(f.service, "tunRetention")
                // Fail the service-owned original's close once, after native DOWN.
                OwnershipDescriptor.controlCopy = OwnershipBuilder.established
                OwnershipDescriptor.failControlClose = true
                var errors = 0
                TunnelRuntime.stop(TUNNEL_API_VERSION, { _, _ -> fail("unconfirmed close succeeded") },
                    { errors++ }, failedStartOperationId = args().clientOperationId)
                f.work.runNext()
                assertEquals(1, errors)
                assertEquals(Tunnel.State.DOWN, f.backend.getState(f.tunnel))
                assertEquals(SessionState.FAILED, TunnelRuntime.state())
                assertTrue(retention.hasTun())
                // Core resumes durable compensation using ordinary legacy-only Stop.
                var successes = 0
                TunnelRuntime.stop(TUNNEL_API_VERSION, { _, _ -> successes++ }, { fail(it) })
                f.work.runNext()
                assertEquals(1, successes)
                assertEquals(SessionState.STOPPED, TunnelRuntime.state())
                assertFalse("Successful cleanup retry must release retained TUN", retention.hasTun())
            }
        } finally {
            OwnershipNative.reset()
            OwnershipDescriptor.files.values.toSet().forEach { it.delete() }
        }
    }

    @Test
    @Config(shadows = [NoNativeLibrary::class, OwnershipNative::class, OwnershipVpn::class,
        RetentionServiceBuilder::class, OwnershipDescriptor::class])
    fun initialStartCancelledAfterHandshakeMustReleaseTun() = verifyRejectedStart(false)

    @Test
    @Config(shadows = [NoNativeLibrary::class, OwnershipNative::class, OwnershipVpn::class,
        RetentionServiceBuilder::class, OwnershipDescriptor::class])
    fun rejectedRecoveryPreservesPreviouslyArmedTun() = verifyRejectedStart(true)

    private fun verifyRejectedStart(previouslyArmed: Boolean) {
        OwnershipNative.reset(); OwnershipDescriptor.reset(); OwnershipVpn.protectSucceeds = true
        try {
            withRuntime(retainTunDescriptor = true) { f ->
                OwnershipNative.statistics = "public_key=${"01".repeat(32)}\nlast_handshake_time_sec=1\n"
                TunnelRuntime.start(f.context, args().apply { startSource = "user" },
                    { _, _ -> }, { fail(it) }, keepForegroundServiceOnFailure = true)
                f.work.runNext()
                TunnelRuntime.metrics(TUNNEL_API_VERSION, false, { _, _, observed, _ ->
                    assertNotNull(observed)
                }, { fail(it) })
                f.work.runNext()
                val rejectedOperationId = if (previouslyArmed) "40000000-0000-4000-8000-000000000002"
                    else requireNotNull(args().clientOperationId)
                if (previouslyArmed) {
                    TunnelRuntime.start(f.context, args().apply { clientOperationId = rejectedOperationId }, { _, _ -> }, { fail(it) },
                        keepForegroundServiceOnFailure = true)
                    f.work.runNext()
                    TunnelRuntime.metrics(TUNNEL_API_VERSION, false, { _, _, _, _ -> }, { fail(it) })
                    f.work.runNext()
                }
                // Core still checks cancellation after ensure_awg3_handshake and
                // uses scoped compensation before publishing Phase::Connected.
                var replies = 0
                val receiver = Receiver { code, _ -> assertEquals(SERVICE_RESULT_OK, code); replies++ }
                ReflectionHelpers.setField(f.service, "redundantWork",
                    RedundantVpnWorkDispatcher(java.util.concurrent.Executor { it.run() }))
                ReflectionHelpers.callInstanceMethod<Unit>(f.service, "handleClientStop",
                    ReflectionHelpers.ClassParameter.from(Intent::class.java,
                        Intent(NelomaiVpnService.ACTION_CLIENT_STOP)
                            .putExtra(EXTRA_API_VERSION, TUNNEL_API_VERSION)
                            .putExtra(EXTRA_LEGACY_STOP_ONLY, true)
                            .putExtra(EXTRA_FAILED_START_OPERATION_ID, rejectedOperationId)
                            .putExtra(EXTRA_RESULT_RECEIVER, receiver)))
                org.robolectric.Shadows.shadowOf(android.os.Looper.getMainLooper()).idle()
                f.work.runNext()
                assertEquals(1, replies)
                assertEquals(SessionState.STOPPED, TunnelRuntime.state())
                val retained = ReflectionHelpers.getField<ServiceTunRetention>(f.service, "tunRetention")
                assertEquals("Only protection predating the rejected Start may remain",
                    previouslyArmed, retained.hasTun())
            }
        } finally {
            OwnershipNative.reset()
            OwnershipDescriptor.files.values.toSet().forEach { it.delete() }
        }
    }

    @Test
    @Config(shadows = [NoNativeLibrary::class, OwnershipNative::class, OwnershipVpn::class,
        RetentionServiceBuilder::class, OwnershipDescriptor::class])
    fun existingMetricsArmsServiceRetentionOnlyAfterHandshake() {
        for (handshake in listOf(0L, 1L)) {
            OwnershipNative.reset(); OwnershipDescriptor.reset(); OwnershipVpn.protectSucceeds = true
            withRuntime(retainTunDescriptor = true) { f ->
                OwnershipNative.statistics = "public_key=${"01".repeat(32)}\nlast_handshake_time_sec=$handshake\n"
                TunnelRuntime.start(f.context, args(), { _, _ -> }, { fail(it) }, keepForegroundServiceOnFailure = true)
                f.work.runNext()
                var replies = 0
                TunnelRuntime.metrics(TUNNEL_API_VERSION, false, { _, _, observed, _ ->
                    replies++
                    assertEquals(handshake.takeIf { it > 0 }?.times(1000), observed)
                }, { fail(it) })
                f.work.runNext()
                assertEquals(1, replies)
                f.backend.setState(f.tunnel, Tunnel.State.DOWN, null)
                val retained = ReflectionHelpers.getField<ServiceTunRetention>(f.service, "tunRetention")
                assertEquals(handshake > 0, retained.hasTun())
            }
            OwnershipNative.reset()
            OwnershipDescriptor.files.values.toSet().forEach { it.delete() }
        }
    }

    @Test
    @Config(shadows = [NoNativeLibrary::class, OwnershipNative::class, OwnershipVpn::class,
        RetentionServiceBuilder::class, OwnershipDescriptor::class])
    fun failedStartBusyStopIsStillReleasedByGenericCleanupRetry() {
        OwnershipNative.reset(); OwnershipDescriptor.reset(); OwnershipVpn.protectSucceeds = true
        try {
            withRuntime(retainTunDescriptor = true) { f ->
                OwnershipNative.statistics = "public_key=${"01".repeat(32)}\nlast_handshake_time_sec=1\n"
                TunnelRuntime.start(f.context, args(), { _, _ -> }, { fail(it) }, keepForegroundServiceOnFailure = true)
                f.work.runNext()
                TunnelRuntime.metrics(TUNNEL_API_VERSION, false, { _, _, _, _ -> }, { fail(it) })
                f.work.runNext()
                val gate = ReflectionHelpers.getField<TunnelStateGate>(TunnelRuntime, "stateGate")
                assertEquals(TransitionDecision.PROCEED, gate.beginRebind())
                var errors = 0
                TunnelRuntime.stop(TUNNEL_API_VERSION, { _, _ -> fail("busy Stop succeeded") }, {
                    assertEquals("tunnel_operation_in_progress", it); errors++
                }, failedStartOperationId = args().clientOperationId!!)
                assertEquals(1, errors)
                gate.complete(SessionState.RUNNING)
                // A queued observation must not re-arm the rejected Start.
                TunnelRuntime.metrics(TUNNEL_API_VERSION, false, { _, _, _, _ -> }, { fail(it) })
                f.work.runNext()
                TunnelRuntime.stop(TUNNEL_API_VERSION, { _, _ -> }, { fail(it) })
                f.work.runNext()
                assertFalse(ReflectionHelpers.getField<ServiceTunRetention>(f.service, "tunRetention").hasTun())
            }
        } finally {
            OwnershipNative.reset()
            OwnershipDescriptor.files.values.toSet().forEach { it.delete() }
        }
    }

    // Returning normally cannot signal rejection to the runtime's native catch.
    // This characterizes the mechanism, not a historical RED against old production.
    @Test fun normalCallbackRejectionLeavesNativeUp() = withRuntime { f ->
        val replies = mutableListOf<String>()
        TunnelRuntime.start(f.context, args(), { _, _ -> replies += "normal-rejection" },
            { replies += it }, keepForegroundServiceOnFailure = true)
        f.work.runNext()
        assertEquals(listOf("normal-rejection"), replies)
        assertEquals(Tunnel.State.UP, f.backend.getState(f.tunnel))
        assertEquals(SessionState.RUNNING, TunnelRuntime.state())
        assertEquals(listOf("up"), CompletionNative.events)
    }

    @Test fun thrownLateCallbackRejectionClosesNativeBeforeError() = verifyLateRejection("local_restart")
    @Test fun cancelledInitialCallbackClosesNativeBeforeError() = verifyLateRejection("user")

    @Test fun wireGuardBindsRecoveryToItsStartAfterATemporaryStoreReadError() = withRuntime { f ->
        assertTrue(f.store.setDesiredActive(0, true) is RecoveryStoreResult.Success)
        val generation = f.envelope().intent.generation
        f.record.readFails = true
        CompletionNative.onUp = { f.record.readFails = false }
        val replies = mutableListOf<String>()
        TunnelRuntime.start(f.context, args(), { _, _ -> replies += "up" },
            { replies += it }, keepForegroundServiceOnFailure = true)
        f.work.runNext()
        assertEquals(listOf("up"), replies)
        val session = ReflectionHelpers.getField<Any>(TunnelRuntime, "activeSession")
        val boundGeneration = ReflectionHelpers.getField<Long?>(session, "wireGuardRecoveryOwnerGeneration")
        assertEquals("the successful start captured its owner", generation as Long?, boundGeneration)
    }

    private fun verifyLateRejection(source: String) = withRuntime { f ->
        var callbacks = 0
        TunnelRuntime.start(f.context, args().apply { startSource = source }, { state, _ ->
            callbacks++
            assertEquals(SessionState.RUNNING, state)
            assertEquals(Tunnel.State.UP, f.backend.getState(f.tunnel))
            CompletionNative.events += "late-rejection"
            throw TunnelOperationException("tunnel_start_cancelled")
        }, { code ->
            callbacks++
            assertEquals("tunnel_start_cancelled", code)
            assertEquals(Tunnel.State.DOWN, f.backend.getState(f.tunnel))
            assertEquals(SessionState.FAILED, TunnelRuntime.state())
            assertNull(TunnelRuntime.activeLeaseId())
            CompletionNative.events += "error"
        }, keepForegroundServiceOnFailure = true)
        f.work.runNext()
        assertEquals(2, callbacks)
        assertEquals(listOf("up", "late-rejection", "down", "error"), CompletionNative.events)
    }

    @Test fun uiStartRejectedAfterUpClosesNativeBeforeError() = withRuntime { f ->
        TunnelRuntime.start(f.context, args().apply { startSource = "ui" }, { _, _ ->
            assertEquals(Tunnel.State.UP, f.backend.getState(f.tunnel))
            CompletionNative.events += "late-rejection"
            throw TunnelOperationException("tunnel_start_cancelled")
        }, { code ->
            assertEquals("tunnel_start_cancelled", code)
            assertEquals(Tunnel.State.DOWN, f.backend.getState(f.tunnel))
            assertEquals(SessionState.FAILED, TunnelRuntime.state())
            assertNull(TunnelRuntime.activeLeaseId())
            CompletionNative.events += "error"
        }, keepForegroundServiceOnFailure = true)
        f.work.runNext()
        assertEquals(listOf("up", "late-rejection", "down", "error"), CompletionNative.events)
    }

    @Test fun stoppedProjectionIsNotProofOfCompletedBackendDestroy() = withRuntime { f ->
        assertEquals(SessionState.STOPPED, TunnelRuntime.state())
        assertTrue(f.service.localTransportClosed())
        ReflectionHelpers.setField(f.service, "serviceDestroyed", true)
        assertFalse(f.service.localTransportClosed())
        ReflectionHelpers.setField(f.service, "nativeDestroyBarrier", TunnelRuntime.nativeOperationsBarrier())
        assertFalse(f.service.localTransportClosed())
        f.work.runNext()
        assertTrue(f.service.localTransportClosed())
    }

    @Test fun lateNativeUpClosesItsOwnBackendAfterServiceClearedTheSharedReference() = withRuntime { f ->
        var current = true
        CompletionNative.onUp = {
            current = false
            ReflectionHelpers.setField(f.service, "serviceDestroyed", true)
            TunnelRuntime.serviceDestroyed()
            TunnelRuntime.releaseBackend()
            ReflectionHelpers.setField(f.service, "nativeDestroyBarrier", TunnelRuntime.nativeOperationsBarrier())
            assertFalse(f.service.localTransportClosed())
        }
        TunnelRuntime.start(f.context, args().apply { startSource = "ui" },
            { _, _ -> fail("retired owner succeeded") }, {
                assertEquals("tunnel_start_cancelled", it)
                assertEquals(Tunnel.State.DOWN, f.backend.getState(f.tunnel))
                CompletionNative.events += "error"
            }, keepForegroundServiceOnFailure = true, ownerCurrent = { current })
        f.work.runNext()
        assertEquals(listOf("up", "down", "error"), CompletionNative.events)
        assertFalse(f.service.localTransportClosed())
        f.work.runNext()
        assertTrue(f.service.localTransportClosed())
    }

    @Test fun firstUiStopCommandJournalsLocalCleanupWhileLegacyTunIsUp() = withRuntime { f ->
        QuickDesiredActiveProjection.update(f.store, true)
        TunnelRuntime.start(f.context, args().apply { startSource = "ui" },
            { _, _ -> }, { fail(it) }, keepForegroundServiceOnFailure = true)
        f.work.runNext()
        assertEquals(Tunnel.State.UP, f.backend.getState(f.tunnel))
        assertNull(f.envelope().leaseTransaction)
        var replied = false
        val stop = Intent("ru.nelomai.tunnel.CANCEL_CURRENT_CONNECTION_INTENT").putExtra(
            EXTRA_RESULT_RECEIVER, Receiver { code, _ ->
                assertEquals(SERVICE_RESULT_OK, code)
                assertFalse(f.envelope().intent.desiredActive)
                assertEquals("legacy_runtime_stop", f.envelope().intent.retry.pendingAction)
                replied = true
            },
        )
        ReflectionHelpers.callInstanceMethod<Unit>(f.service, "handleCancelCurrentConnectionIntent",
            ReflectionHelpers.ClassParameter.from(Intent::class.java, stop))
        assertTrue(replied)
    }

    @Test fun lateUiStartFailureAfterStopCannotDisarmTheAcceptedReplacement() = withRuntime { f ->
        CompletionNative.onUp = {
            f.stopFromUi()
            assertTrue(f.coordinator.begin(AndroidIntentTemplate(
                "11111111-1111-4111-8111-111111111111", "scope",
                "tic", "dynamic", "standalone", "ipv4", false,
            )) is AndroidCoordinatorResult.Accepted)
        }
        var rejected = false
        f.startService(Receiver { code, data ->
            assertEquals(SERVICE_RESULT_ERROR, code)
            assertEquals("tunnel_start_cancelled", data?.getString(EXTRA_ERROR_CODE))
            assertEquals(Tunnel.State.DOWN, f.backend.getState(f.tunnel))
            rejected = true
        }, source = "ui")
        f.work.runNext()
        assertTrue(rejected)
        assertEquals(listOf("up", "down"), CompletionNative.events)
        assertTrue(f.envelope().intent.desiredActive)
    }

    @Test fun delayedCancelForAnOlderOperationDoesNotCancelTheCurrentNativeStart() = withRuntime { f ->
        var started = false
        f.startService(Receiver { code, _ ->
            assertEquals(SERVICE_RESULT_OK, code)
            started = true
        }, source = "ui")
        f.cancelClientStart("11111111-1111-4111-8111-111111111111")
        f.work.runNext()
        assertTrue(started)
        assertEquals(Tunnel.State.UP, f.backend.getState(f.tunnel))
        f.work.runNext()
    }

    @Test fun timedOutLegacyStartDisarmsOnlyItsOwnDesiredConnection() = withRuntime { f ->
        val operation = "11111111-1111-4111-8111-111111111111"
        var failure: String? = null
        f.startService(Receiver { code, data ->
            assertEquals(SERVICE_RESULT_ERROR, code)
            failure = data?.getString(EXTRA_ERROR_CODE)
        }, source = "ui", operationId = operation)
        assertTrue(f.envelope().intent.desiredActive)
        f.cancelClientStart(operation)
        f.work.runNext()
        assertEquals("tunnel_start_cancelled", failure)
        assertFalse("the timed-out start still owns its desired state", f.envelope().intent.desiredActive)
        f.work.runNext()
        assertTrue(CompletionNative.events.isEmpty())
    }

    @Test fun timedOutLegacyStartCannotDisarmANewerDurableIntent() = withRuntime { f ->
        val operation = "11111111-1111-4111-8111-111111111111"
        var failure: String? = null
        f.startService(Receiver { _, data -> failure = data?.getString(EXTRA_ERROR_CODE) },
            source = "ui", operationId = operation)
        f.cancelClientStart(operation)
        val replacement = f.beginReplacement()
        f.work.runNext()
        f.work.runNext()
        assertEquals("tunnel_start_cancelled", failure)
        assertEquals(replacement, f.envelope())
    }

    @Test fun cancellationAfterNativeUpCannotDisarmAReplacementDuringDown() = withRuntime { f ->
        val operation = "22222222-2222-4222-8222-222222222222"
        f.startService(Receiver { code, _ -> assertEquals(SERVICE_RESULT_OK, code) },
            source = "ui", operationId = operation)
        f.work.runNext()
        f.cancelClientStart(operation)
        f.work.runNext()
        assertFalse(f.envelope().intent.desiredActive)
        val replacement = f.beginReplacement()
        f.work.runNext()
        assertEquals(listOf("up", "down"), CompletionNative.events)
        assertEquals(replacement, f.envelope())
    }

    @Test fun startImmediatelyAfterStopReplyIsAdmitted() = withRuntime { f ->
        TunnelRuntime.start(f.context, args(), { _, _ -> }, { fail(it) }, keepForegroundServiceOnFailure = true)
        f.work.runNext()
        var started = false
        var failure: String? = null
        TunnelRuntime.stop(TUNNEL_API_VERSION, { state, _ ->
            if (state == SessionState.STOPPED) {
                TunnelRuntime.start(f.context, args(), { _, _ -> started = true }, { failure = it },
                    keepForegroundServiceOnFailure = true)
            }
        }, { fail(it) }, keepForegroundService = true)
        f.work.runNext()
        assertNull(failure)
        assertEquals(listOf("up", "down"), CompletionNative.events)
        f.work.runNext()
        assertTrue(started)
        assertEquals(SessionState.RUNNING, TunnelRuntime.state())
    }

    @Test fun staleStopReplyDoesNotPublishStoppedOverANewerIntent() = withRuntime { f ->
        f.startService(Receiver { code, _ -> assertEquals(SERVICE_RESULT_OK, code) }, source = "ui")
        f.work.runNext()
        var replied = false
        f.stopLegacyService(Receiver { code, _ -> replied = code == SERVICE_RESULT_OK })
        val replacement = f.beginReplacement()
        assertTrue(QuickTunnelController.updateState(f.context, SessionState.STARTING))
        f.work.runNext()
        assertTrue(replied)
        assertEquals(replacement, f.envelope())
        assertEquals("starting", QuickTunnelController.state(f.context))
    }

    @Test fun directStopRejectedDuringRebindKeepsTheRunningIntent() = withRuntime { f ->
        f.startService(Receiver { code, _ -> assertEquals(SERVICE_RESULT_OK, code) }, source = "ui")
        f.work.runNext()
        val gate = ReflectionHelpers.getField<TunnelStateGate>(TunnelRuntime, "stateGate")
        assertEquals(TransitionDecision.PROCEED, gate.beginRebind())
        var failure: String? = null
        f.stopLegacyService(Receiver { _, data -> failure = data?.getString(EXTRA_ERROR_CODE) })
        assertEquals("tunnel_operation_in_progress", failure)
        assertTrue(gate.cancelRebind())
        assertEquals(Tunnel.State.UP, f.backend.getState(f.tunnel))
        assertTrue(f.envelope().intent.desiredActive)
    }

    @Test fun busyStopDoesNotDisarmAConnectionWithAnActiveLease() = withRuntime { f ->
        f.armCheckpoint()
        var started = false
        f.startService(Receiver { code, _ -> started = code == SERVICE_RESULT_OK })
        f.work.runNext()
        assertTrue(started)
        val connected = f.envelope()
        assertNotNull(connected.leaseTransaction)
        val gate = ReflectionHelpers.getField<TunnelStateGate>(TunnelRuntime, "stateGate")
        assertEquals(TransitionDecision.PROCEED, gate.beginRebind())
        var failure: String? = null
        f.stopLegacyService(Receiver { _, data -> failure = data?.getString(EXTRA_ERROR_CODE) })
        assertEquals("tunnel_operation_in_progress", failure)
        assertEquals(connected, f.envelope())
    }

    @Test fun busyStopCannotUndoAnAlreadyJournalledStop() = withRuntime { f ->
        f.startService(Receiver { code, _ -> assertEquals(SERVICE_RESULT_OK, code) }, source = "ui")
        f.work.runNext()
        val gate = ReflectionHelpers.getField<TunnelStateGate>(TunnelRuntime, "stateGate")
        assertEquals(TransitionDecision.PROCEED, gate.beginRebind())
        f.stopFromUi()
        val acceptedStop = f.envelope()
        assertEquals("legacy_runtime_stop", acceptedStop.intent.retry.pendingAction)
        var failure: String? = null
        f.stopLegacyService(Receiver { _, data -> failure = data?.getString(EXTRA_ERROR_CODE) })
        assertEquals("tunnel_operation_in_progress", failure)
        assertEquals(acceptedStop, f.envelope())
    }

    @Test fun aSecondStopWaitsForTheSamePhysicalClose() = withRuntime { f ->
        TunnelRuntime.start(f.context, args(), { _, _ -> }, { fail(it) }, keepForegroundServiceOnFailure = true)
        f.work.runNext()
        val results = mutableListOf<String>()
        repeat(2) {
            TunnelRuntime.stop(TUNNEL_API_VERSION, { state, _ -> results += state.wireName },
                { code -> results += code }, keepForegroundService = true)
        }
        assertTrue("both callers must wait until native DOWN completes", results.isEmpty())
        f.work.runNext()
        assertEquals(listOf("up", "down"), CompletionNative.events)
        assertEquals(listOf("stopped", "stopped"), results)
    }

    @Test fun matchingLocalRestartRemainsCancelledAfterRecoveryLookupFails() = withRuntime { f ->
        f.armCheckpoint()
        val operation = "11111111-1111-4111-8111-111111111111"
        var rejected = false
        f.startService(Receiver { code, data ->
            assertEquals(SERVICE_RESULT_ERROR, code)
            assertEquals("tunnel_start_cancelled", data?.getString(EXTRA_ERROR_CODE))
            rejected = true
        }, operationId = operation)
        f.cancelClientStart(operation)
        f.record.readFails = true
        f.lookupWork.runNext()
        f.record.readFails = false
        shadowOf(Looper.getMainLooper()).idle()
        f.work.runNext()
        assertTrue(rejected)
        assertTrue(CompletionNative.events.isEmpty())
        assertNull(ReflectionHelpers.getField<FailedLocalRestartAuthority?>(f.service, "failedLocalRestartAuthority"))
        f.work.runNext()
    }

    @Test fun tileStartFencesTheOldHotStandbyWhenAndroidInterruptedStopBeforeItsMarker() = withTileRuntime { f ->
        val old = f.beginHotStandby()
        assertTrue(f.coordinator.cancelCurrent() is AndroidCoordinatorResult.Accepted)
        assertFalse(f.envelope().intent.desiredActive)
        assertTrue(requireNotNull(f.envelope().redundantTransaction).desiredActive)

        val commits = mutableListOf<AndroidRecoveryEnvelope>()
        f.record.onCommit = { commits += AndroidRecoveryEnvelopeCodec.decode(it) }
        f.firstTapAfterSystemStop(SessionState.STOPPING)

        // A process kill can leave the very first accepted write as the only durable state.
        val accepted = commits.first { it.pendingQuickStart != null }
        val fenced = requireNotNull(accepted.redundantTransaction)
        assertEquals(old.startOperationId, fenced.startOperationId)
        assertFalse("the old session must no longer be eligible for recovery", fenced.desiredActive)
        assertEquals(RedundantStopState.PENDING, fenced.retry.stopState)
        assertNotNull(fenced.stopOperationId)
        assertNotNull(f.envelope().pendingQuickStart)
    }

    @Test fun offTileQueuesNextStartWhileTheOldRemoteStopIsPending() = withTileRuntime { f ->
        val oldStop = f.preparePendingHotStandbyStop()

        f.firstTapAfterSystemStop(SessionState.STOPPED)

        val saved = f.envelope()
        assertNotNull("the first Off-tile tap must start the next connection", saved.pendingQuickStart)
        assertEquals(oldStop.stopOperationId, saved.redundantTransaction?.stopOperationId)
        assertFalse(saved.intent.desiredActive)
        assertTrue(f.backgroundWork.jobs.isEmpty())
    }

    @Test fun delayedOffTileStartCannotStopReplacementInSameGeneration() = withTileRuntime { f ->
        val old = f.preparePendingHotStandbyStop()
        val command = f.offTileStartCommand(SessionState.STOPPED)
        f.completeOldStop(old)
        f.prepareQuick()
        val replacement = f.beginHotStandby("newer-session")
        val before = f.envelope()

        f.service.onStartCommand(command, 0, 2)
        f.drainImmediateWork()

        assertTrue("late tap stopped the replacement", CompletionPanel.redundantStops.isEmpty())
        assertEquals(before, f.envelope())
        assertEquals(replacement, f.envelope().redundantTransaction)
    }

    @Test fun systemStopAfterDurableStartBeforeTileUpdatePreventsPassiveResume() =
        checkColdSystemStop(NelomaiVpnService.ACTION_ENSURE_RUNNING, SessionState.STOPPED)

    @Test fun stopForwardedBeforeReplacementCommitCannotCancelReplacementOnDelivery() = withTileRuntime { f ->
        val old = f.beginHotStandby("old-session")
        val stop = ru.nelomai.runtime.v1.RuntimeServiceIntents.quickStopVpn(f.context)
            .putExtra(ru.nelomai.runtime.v1.RuntimeServiceIntents.EXTRA_TILE_CLICK_REVISION, RuntimeProcessSelection.vpnStartRevision)
        assertTrue(f.store.cancelRedundantIntentAndDeferStop("old-stop", old.startOperationId) is RecoveryStoreResult.Success)
        f.completeOldStop(requireNotNull(f.envelope().redundantTransaction))
        f.prepareQuick()
        val replacement = old.copy(startOperationId = "replacement-session")
        assertTrue(f.store.beginRedundant(replacement) is RecoveryStoreResult.Success)
        f.service.onStartCommand(stop, 0, 2)
        f.drainImmediateWork()
        assertTrue(f.envelope().intent.desiredActive)
        assertEquals("replacement-session", f.envelope().redundantTransaction?.startOperationId)
        assertTrue(CompletionPanel.redundantStops.isEmpty())
        val current = Intent(stop).putExtra(ru.nelomai.runtime.v1.RuntimeServiceIntents.EXTRA_TILE_CLICK_REVISION,
            RuntimeProcessSelection.vpnStartRevision)
        f.service.onStartCommand(current, 0, 3)
        f.drainImmediateWork()
        assertEquals(listOf("replacement-session"), CompletionPanel.redundantStops.map { it.startOperationId })
    }

    @Test fun newOffTapAfterAnotherSystemStopStartsOnce() = repeatAndroidStop(true)

    @Test fun noOffTapAfterAnotherSystemStopStaysOff() = repeatAndroidStop(false)

    @Test fun freshOffTapAfterPassiveRemovalOfOldRequestStartsOnce() = repeatAndroidStop(true, true)

    private fun Fixture.captureActualOffTileCommand(): Intent {
        val owner = requireNotNull(RuntimeProcessSelection.vpnOwnerForStop())
        requireNotNull(LatestRuntimeQuickActionsV1().prepareStart(context, RuntimeSelectionStore.encodeVpnRecoveryOwner(owner))).run()
        return requireNotNull(shadowOf(context.applicationContext as Application).nextStartedService)
    }

    private fun repeatAndroidStop(newTap: Boolean, consumeBeforeTap: Boolean = false) {
        val record = Record()
        val firstTime = System.currentTimeMillis() - 10_000
        withTileRuntime(record) { f ->
            f.preparePendingHotStandbyStop()
            f.recordSystemStop(SessionState.STOPPING, firstTime - 1000)
            val request = f.captureActualOffTileCommand().putExtra("quick_start_requested_at", firstTime)
            f.service.onStartCommand(request, 0, 1)
            assertEquals(firstTime, f.envelope().pendingQuickStart?.requestedAtMillis)
            assertEquals(RedundantStopState.PENDING, f.envelope().redundantTransaction?.retry?.stopState)
        }
        withTileRuntime(record) { f ->
            val sample = f.prepareQuick()
            f.recordSystemStop(SessionState.STOPPING)
            assertEquals(firstTime, f.envelope().pendingQuickStart?.requestedAtMillis)
            var starts = 0
            CompletionPanel.onStart = {
                starts++
                BackgroundStartResult(sample.configuration, sample.quickConnection!!, sample.options)
            }
            if (consumeBeforeTap) {
                f.service.onStartCommand(Intent(NelomaiVpnService.ACTION_ENSURE_RUNNING), 0, 1)
                shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(2))
                f.drainImmediateWork()
                assertNull(f.envelope().pendingQuickStart)
            }
            val cmd = if (newTap) f.captureActualOffTileCommand() else Intent(NelomaiVpnService.ACTION_ENSURE_RUNNING)
            if (newTap) assertTrue(cmd.getLongExtra("quick_start_requested_at", 0) > firstTime)
            f.service.onStartCommand(cmd, 0, 2)
            shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(2))
            f.drainImmediateWork()
            assertEquals(1, CompletionPanel.redundantStops.size)
            assertEquals(if (newTap) 1 else 0, starts)
            assertEquals(if (newTap) Tunnel.State.UP else Tunnel.State.DOWN, f.backend.getState(f.tunnel))
        }
    }

    @Test fun delayedOffTileStartStillStartsOnceAfterItsOwnCleanup() = withTileRuntime { f ->
        val old = f.preparePendingHotStandbyStop()
        val command = f.offTileStartCommand(SessionState.STOPPED)
        f.completeOldStop(old)
        val sample = f.prepareQuick()

        f.service.onStartCommand(command, 0, 2)
        f.service.onStartCommand(command, 0, 3)
        f.assertFreshQuickStart(sample)
        val started = f.envelope()
        f.service.onStartCommand(command, 0, 4)
        f.drainImmediateWork()
        assertEquals(started, f.envelope())
        assertEquals(Tunnel.State.UP, f.backend.getState(f.tunnel))
    }

    @Test fun delayedOffTileStartCannotRestartAfterAnotherSessionCompleted() = withTileRuntime { f ->
        val old = f.preparePendingHotStandbyStop()
        val command = f.offTileStartCommand(SessionState.STOPPED)
        f.completeOldStop(old)
        f.completeOldStop(f.preparePendingHotStandbyStop())
        f.prepareQuick()
        val before = f.envelope()

        f.service.onStartCommand(command, 0, 2)
        f.drainImmediateWork()

        assertEquals(before, f.envelope())
        assertTrue(CompletionNative.events.isEmpty())
    }

    @Test fun oldUnscopedStartAfterInterruptedStopCannotStopCurrentSession() = withTileRuntime { f ->
        f.beginHotStandby()
        f.prepareQuick()
        val before = f.envelope()
        val oldCommand = Intent(NelomaiVpnService.ACTION_QUICK_TOGGLE)
            .putExtra(NelomaiVpnService.EXTRA_START_AFTER_INTERRUPTED_STOP, true)

        f.service.onStartCommand(oldCommand, 0, 2)
        f.drainImmediateWork()

        assertEquals(before, f.envelope())
        assertTrue(CompletionPanel.redundantStops.isEmpty())
    }

    @Test fun stickyRestartFinishesInterruptedHotStandbyStopBeforeAnyTap() =
        checkInterruptedStopBeforeTap(null)

    @Test fun ensureRunningFinishesInterruptedHotStandbyStopBeforeAnyTap() =
        checkInterruptedStopBeforeTap(NelomaiVpnService.ACTION_ENSURE_RUNNING)

    @Test fun clientStatusCannotRecoverHotStandbyDuringInterruptedStop() =
        checkInterruptedStopBeforeTap(NelomaiVpnService.ACTION_CLIENT_STATUS)

    @Test fun clientMetricsCannotRecoverHotStandbyDuringInterruptedStop() =
        checkInterruptedStopBeforeTap(NelomaiVpnService.ACTION_CLIENT_METRICS)

    private fun checkInterruptedStopBeforeTap(action: String?) {
        val record = Record()
        val startId = java.util.UUID.randomUUID().toString()
        withTileRuntime(record) { f ->
            f.beginHotStandby(startId)
            assertTrue(f.coordinator.cancelCurrent() is AndroidCoordinatorResult.Accepted)
            assertTrue(QuickTunnelController.updateState(f.context, SessionState.STOPPING))
        }
        withTileRuntime(record) { f ->
            assertFalse(f.envelope().intent.desiredActive)
            assertTrue(requireNotNull(f.envelope().redundantTransaction).desiredActive)
            f.prepareQuick()
            val command = action?.let { Intent(it).putExtra(EXTRA_API_VERSION, TUNNEL_API_VERSION) }
            f.service.onStartCommand(command, 0, 1)
            f.drainImmediateWork()

            assertTrue("unexpected panel recovery: ${CompletionPanel.redundantRecoveries}",
                CompletionPanel.redundantRecoveries.isEmpty())
            val stop = CompletionPanel.redundantStops.single()
            assertEquals(startId, stop.startOperationId)
            assertFalse(stop.desiredActive)
            assertEquals(RedundantStopState.PENDING, stop.retry.stopState)
            assertNotNull(stop.stopOperationId)
            val saved = f.envelope()
            assertNull(saved.redundantTransaction)
            assertNull(saved.pendingQuickStart)
            assertFalse(saved.intent.desiredActive)
            assertTrue(CompletionNative.events.isEmpty())
        }
    }

    @Test fun stickyRestartContinuesFirstTileTapAfterCleanup() =
        checkTileStartAfterRecreation(null)

    @Test fun ensureRunningContinuesFirstTileTapAfterCleanup() =
        checkTileStartAfterRecreation(Intent(NelomaiVpnService.ACTION_ENSURE_RUNNING))

    private fun checkTileStartAfterRecreation(restart: Intent?) {
        val record = Record()
        withTileRuntime(record) { f ->
            f.preparePendingHotStandbyStop()
            f.firstTapAfterSystemStop(SessionState.STOPPING)
        }

        // Reopen both the recovery record and the local Stop marker. The new
        // engine must finish the original panel operation before the next Start.
        withTileRuntime(record) { f ->
            assertEquals("old-stop", f.envelope().redundantTransaction?.stopOperationId)
            val sample = f.prepareQuick()
            f.service.onStartCommand(restart, 0, 2)
            shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(2))
            f.assertFreshQuickStart(sample)
            assertEquals("old-stop", CompletionPanel.redundantStops.single().stopOperationId)
            assertNull(f.envelope().pendingQuickStart)
        }
    }

    @Test fun rejectedLegacyCleanupKeepsTheFirstTapDuringHotStandbyStop() = withTileRuntime { f ->
        f.preparePendingHotStandbyStop()
        f.firstTapAfterSystemStop(SessionState.STOPPING)
        val requested = requireNotNull(f.envelope().pendingQuickStart)
        var rejection: String? = null
        val cleanup = Intent(NelomaiVpnService.ACTION_CLIENT_STOP)
            .putExtra(EXTRA_API_VERSION, TUNNEL_API_VERSION)
            .putExtra(EXTRA_LEGACY_STOP_ONLY, true)
            .putExtra(EXTRA_RESULT_RECEIVER, Receiver { code, data ->
                assertEquals(SERVICE_RESULT_ERROR, code)
                rejection = data?.getString(EXTRA_ERROR_CODE)
            })
        f.service.onStartCommand(cleanup, 0, 2)
        // No remote credential is configured, so the earlier Stop stays unacknowledged.
        repeat(f.lookupWork.jobs.size) { f.lookupWork.runNext() }
        shadowOf(Looper.getMainLooper()).idle()

        assertEquals("redundant_session_service_owned", rejection)
        assertEquals("old-stop", f.envelope().redundantTransaction?.stopOperationId)
        assertEquals(requested, f.envelope().pendingQuickStart)
    }

    @Test fun explicitClientStopCancelsTheQueuedFirstTap() = withTileRuntime { f ->
        f.preparePendingHotStandbyStop()
        f.firstTapAfterSystemStop(SessionState.STOPPING)
        assertNotNull(f.envelope().pendingQuickStart)

        f.service.onStartCommand(Intent(NelomaiVpnService.ACTION_CLIENT_STOP)
            .putExtra(EXTRA_API_VERSION, TUNNEL_API_VERSION), 0, 2)

        val cancelled = f.envelope()
        assertNull(cancelled.pendingQuickStart)
        assertFalse(cancelled.intent.desiredActive)
        assertEquals("old-stop", cancelled.redundantTransaction?.stopOperationId)
    }

    @Test fun queuedFirstTapCannotStartVpnForAnotherAccountAfterServiceRecreation() {
        val record = Record()
        withTileRuntime(record) { f ->
            f.preparePendingHotStandbyStop()
            f.firstTapAfterSystemStop(SessionState.STOPPING)
            assertNotNull(f.envelope().pendingQuickStart)
        }
        // The runtime version, process incarnation and broker generation stay the same.
        withTileRuntime(record, accountScope = "b".repeat(64)) { f ->
            f.service.onStartCommand(null, 0, 2)

            val fenced = f.envelope()
            assertNull(fenced.pendingQuickStart)
            assertFalse(fenced.intent.desiredActive)
            assertEquals("old-stop", fenced.redundantTransaction?.stopOperationId)
            assertTrue(f.backgroundWork.jobs.isEmpty())
        }
    }

    @Test fun firstTapRestartsLegacyTunnelWhenAndroidStoppedItWithoutALeaseRecord() = withTileRuntime { f ->
        val sample = f.prepareQuick()
        assertTrue(f.store.setDesiredActive(0, true) is RecoveryStoreResult.Success)
        assertNull(f.envelope().leaseTransaction)
        f.firstTapAfterSystemStop(SessionState.RUNNING)
        f.assertFreshQuickStart(sample)
    }

    @Test fun delayedLegacyQuickStartResponseCannotReopenAfterQuickOffCompletes() = withRuntime { f ->
        val sample = f.prepareQuick()
        var rejected = false
        f.quickToggle(stopOnly = false, receiver = Receiver { code, data ->
            assertEquals(SERVICE_RESULT_ERROR, code)
            assertEquals("tunnel_start_cancelled", data?.getString(EXTRA_ERROR_CODE))
            rejected = true
        })
        f.credentialsWork.runNext()
        assertTrue(f.envelope().intent.desiredActive)
        CompletionPanel.onStart = {
            f.quickToggle(stopOnly = true)
            val stopped = f.envelope().intent
            assertEquals("legacy_runtime_stop", stopped.retry.pendingAction)
            TunnelRuntime.stop(TUNNEL_API_VERSION, { state, _ ->
                assertEquals(SessionState.STOPPED, state)
                assertTrue(f.store.completeLegacyRuntimeStop(stopped.generation) is RecoveryStoreResult.Success)
            }, { fail(it) }, keepForegroundService = true)
            assertFalse(f.envelope().intent.desiredActive)
            assertNull(f.envelope().intent.retry.pendingAction)
            BackgroundStartResult(sample.configuration, sample.quickConnection!!, sample.options)
        }
        f.backgroundWork.runNext()
        assertTrue(rejected)
        assertTrue(f.work.jobs.isEmpty())
        assertEquals(Tunnel.State.DOWN, f.backend.getState(f.tunnel))
        if (f.backgroundWork.jobs.isNotEmpty()) f.backgroundWork.runNext()
        assertEquals(org.robolectric.shadows.ShadowLog.getLogs().joinToString("\n") { it.msg },
            listOf("lease"), CompletionPanel.stopped)
    }

    @Test fun rejectedQuickSuccessHoldsAdmissionUntilItsLeaseIsClosed() = withRuntime { f ->
        val sample = f.prepareQuick()
        CompletionPanel.onStart = {
            BackgroundStartResult(sample.configuration, sample.quickConnection!!, sample.options)
        }
        TunnelRuntime.backgroundStart(f.context, { _, _ ->
            throw TunnelOperationException("tunnel_start_cancelled")
        }, { assertEquals("tunnel_start_cancelled", it) })
        f.backgroundWork.runNext()
        f.work.runNext()
        var rejected = false
        TunnelRuntime.backgroundStart(f.context, { _, _ -> fail("new Start admitted before cleanup") }, {
            assertEquals("tunnel_operation_in_progress", it)
            rejected = true
        })
        assertTrue(rejected)
        f.backgroundWork.runNext()
        assertEquals(listOf("lease"), CompletionPanel.stopped)
    }

    @Test fun anOldCallbackCannotOverwriteTheNewStartState() = withRuntime { f ->
        var replacementStarted = false
        var originalFailed = false
        TunnelRuntime.start(f.context, args().apply { startSource = "ui" }, { _, _ ->
            TunnelRuntime.start(f.context, args().apply { startSource = "ui" },
                { state, _ -> replacementStarted = state == SessionState.RUNNING }, { fail(it) })
            assertEquals(SessionState.STARTING, TunnelRuntime.state())
            throw TunnelOperationException("tunnel_start_cancelled")
        }, {
            assertEquals("tunnel_start_cancelled", it)
            assertEquals(SessionState.STARTING, TunnelRuntime.state())
            originalFailed = true
        }, keepForegroundServiceOnFailure = true)
        f.work.runNext()
        assertTrue(originalFailed)
        f.work.runNext()
        assertTrue(replacementStarted)
    }

    @Test fun ownerInvalidatedAtNativeUpFailsClosedBeforeError() = withRuntime { f ->
        var current = true
        var errors = 0
        CompletionNative.onUp = { current = false }
        TunnelRuntime.start(f.context, args(), { _, _ -> fail("cancelled owner succeeded") }, {
            errors++
            assertEquals("tunnel_start_cancelled", it)
            assertEquals(Tunnel.State.DOWN, f.backend.getState(f.tunnel))
            assertEquals(SessionState.FAILED, TunnelRuntime.state())
            CompletionNative.events += "error"
        }, keepForegroundServiceOnFailure = true, ownerCurrent = { current })
        f.work.runNext()
        assertEquals(1, errors)
        assertEquals(listOf("up", "down", "error"), CompletionNative.events)
    }

    @Test fun serviceCallbackUserStopAfterUpClosesNativeBeforeError() = withRuntime { f ->
        f.armCheckpoint()
        val preferences = ReflectionHelpers.callInstanceMethod<SharedPreferences>(
            QuickTunnelController, "preferences", ReflectionHelpers.ClassParameter.from(Context::class.java, f.context))
        var stopped: AndroidRecoveryEnvelope? = null
        val listener = SharedPreferences.OnSharedPreferenceChangeListener { prefs, key ->
            if (key == "state" && prefs.getString(key, null) == SessionState.RUNNING.wireName && stopped == null) {
                stopped = (f.store.cancelCurrentIntent() as RecoveryStoreResult.Success).value
                CompletionNative.events += "user-stop"
            }
        }
        preferences.registerOnSharedPreferenceChangeListener(listener)
        var errors = 0
        try {
            f.startService(Receiver { code, data ->
                errors++
                assertEquals(SERVICE_RESULT_ERROR, code)
                assertEquals("tunnel_start_cancelled", data?.getString(EXTRA_ERROR_CODE))
                assertEquals(Tunnel.State.DOWN, f.backend.getState(f.tunnel))
                assertEquals(SessionState.FAILED, TunnelRuntime.state())
                CompletionNative.events += "error"
            })
            f.work.runNext()
            assertEquals(1, errors)
            assertNotNull(stopped)
            assertEquals(stopped, f.envelope())
            assertFalse(f.envelope().intent.desiredActive)
            assertEquals(listOf("up", "user-stop", "down", "error"), CompletionNative.events)
        } finally { preferences.unregisterOnSharedPreferenceChangeListener(listener) }
    }

    @Test fun legacyNativeFailureAllowsReentrantRollbackWithoutOldFinallyUnlockingIt() = withRuntime { f ->
        // Legacy armed intent has no lease transaction; establish its real active runtime lease.
        QuickDesiredActiveProjection.update(f.store, true)
        TunnelRuntime.start(f.context, args(), { _, _ -> }, { fail(it) }, keepForegroundServiceOnFailure = true)
        f.work.runNext()
        val authority = f.envelope()
        assertNull(authority.leaseTransaction)
        CompletionNative.events.clear()
        CompletionNative.failNextUp = true
        var errors = 0
        var rollbackReplies = 0
        f.startService(Receiver { code, _ ->
            errors++
            assertEquals(SERVICE_RESULT_ERROR, code)
            assertEquals(Tunnel.State.DOWN, f.backend.getState(f.tunnel))
            assertEquals(SessionState.FAILED, TunnelRuntime.state())
            assertEquals(authority, f.envelope())
            assertNotNull(ReflectionHelpers.getField<FailedLocalRestartAuthority?>(f.service, "failedLocalRestartAuthority"))
            f.startService(Receiver { rollbackCode, _ ->
                rollbackReplies++
                assertEquals(SERVICE_RESULT_OK, rollbackCode)
            })
            assertEquals(1, f.work.jobs.size)
        })
        f.work.runNext()
        assertEquals(1, errors)
        assertFalse("old error callback finally must not release rollback's gate", f.coordinator.beginLocalRestart())
        f.work.runNext()
        assertEquals(1, rollbackReplies)
        assertEquals(Tunnel.State.UP, f.backend.getState(f.tunnel))
        assertEquals(authority, f.envelope())
        assertNull(ReflectionHelpers.getField<FailedLocalRestartAuthority?>(f.service, "failedLocalRestartAuthority"))
        assertTrue(f.coordinator.beginLocalRestart())
        f.coordinator.completeLocalRestart()
    }

    @Test fun statusAfterSystemStopDuringRunningOnlyFinishesTheOldSession() =
        checkColdSystemStop(NelomaiVpnService.ACTION_CLIENT_STATUS)

    @Test fun metricsAfterSystemStopDuringRunningOnlyFinishesTheOldSession() =
        checkColdSystemStop(NelomaiVpnService.ACTION_CLIENT_METRICS)

    @Test fun passiveEnsureAfterSystemStopDoesNotRearmOrRecover() =
        checkColdSystemStop(NelomaiVpnService.ACTION_ENSURE_RUNNING)

    @Test fun stickyAfterSystemStopDoesNotRearmOrRecover() = checkColdSystemStop(null)

    @Test fun systemStopRetriesUnreadableIntentBeforeProcessingPassiveRequests() =
        retriesUnreadableStoppedIntent(SessionState.RUNNING)

    @Test fun systemStopRetriesUnreadableUnpublishedStart() = retriesUnreadableStoppedIntent(SessionState.STOPPED)

    private fun retriesUnreadableStoppedIntent(lastPublished: SessionState) {
        val record = Record()
        val operation = java.util.UUID.randomUUID().toString()
        withTileRuntime(record) { f ->
            f.beginHotStandby(operation)
            f.recordSystemStop(lastPublished)
        }
        withTileRuntime(record) { f ->
            f.prepareQuick()
            val status = Intent(NelomaiVpnService.ACTION_CLIENT_STATUS)
                .putExtra(EXTRA_API_VERSION, TUNNEL_API_VERSION)
            record.readFails = true
            assertEquals(android.app.Service.START_NOT_STICKY, f.service.onStartCommand(status, 0, 1))
            assertTrue(CompletionPanel.redundantRecoveries.isEmpty())
            assertTrue(CompletionPanel.redundantStops.isEmpty())
            record.readFails = false
            f.service.onStartCommand(status, 0, 2)
            f.drainImmediateWork()
            assertEquals(listOf(operation), CompletionPanel.redundantStops.map { it.startOperationId })
            assertTrue(CompletionPanel.redundantRecoveries.isEmpty())
            assertFalse(f.envelope().intent.desiredActive)
        }
    }

    @Test fun lateSystemStopCancelsRecoveryOnNextStatus() = lateSystemStop(afterStatus = true)

    @Test fun lateSystemStopCancelsRecoveryWithoutOpeningTheApp() = lateSystemStop(afterStatus = false)

    @Test fun systemStopPublishedAfterFirstBackgroundCheckStillCancelsTheWatch() =
        lateSystemStop(afterStatus = false, afterFirstCheck = true)

    @Test fun coldReadFailureStillCancelsRecoveryOnDelayedSystemStop() =
        lateSystemStop(afterStatus = false, failFirstRead = true)

    private fun lateSystemStop(afterStatus: Boolean, afterFirstCheck: Boolean = false, failFirstRead: Boolean = false) {
        val record = armedKillSwitchRecord { f ->
            assertTrue(QuickTunnelController.updateState(f.context, SessionState.RUNNING))
        }
        record.failNextRead = failFirstRead
        val stoppedAt = System.currentTimeMillis()
        withTileRuntime(record, retainTunDescriptor = true) { f ->
            assertFalse(record.failNextRead)
            if (failFirstRead) f.service.onStartCommand(Intent(NelomaiVpnService.ACTION_TAKE_STATE_CHANGE), 0, 1)
            shadowOf(Looper.getMainLooper()).idle()
            if (!failFirstRead) assertNotNull(f.protectionNotice())
            val scheduler = f.context.getSystemService(android.app.job.JobScheduler::class.java)
            registerTestVpnWatch(f.context, TaskRemovalVpnWatch(123, stoppedAt))
            assertEquals(1, scheduler.allPendingJobs.size)
            if (afterFirstCheck) f.publishSystemStop(requireNotNull(f.envelope().armedAtMillis) - 1)
            f.service.onStartCommand(Intent(NelomaiVpnService.ACTION_TAKE_STATE_CHANGE), 0, 1)
            if (afterFirstCheck) {
                shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(6))
                assertTrue(f.envelope().intent.desiredActive)
                assertNotNull(f.protectionNotice())
            }
            f.publishSystemStop(stoppedAt)
            if (afterStatus) {
                f.service.onStartCommand(Intent(NelomaiVpnService.ACTION_CLIENT_STATUS)
                    .putExtra(EXTRA_API_VERSION, TUNNEL_API_VERSION), 0, 2)
            } else {
                shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(if (afterFirstCheck) 60 else 6))
            }
            f.drainImmediateWork()
            assertTrue(scheduler.allPendingJobs.isEmpty())
            assertFalse("late system Stop must disarm the persisted owner", f.envelope().intent.desiredActive)
            assertNull(f.protectionNotice())
            f.service.onStartCommand(Intent(NelomaiVpnService.ACTION_ENSURE_RUNNING), 0, 3)
            f.drainImmediateWork()
            assertFalse(f.envelope().intent.desiredActive)
            assertTrue(CompletionNative.events.none { it == "up" })
        }
    }

    private fun Fixture.publishSystemStop(at: Long) {
        val exit = ShadowActivityManager.ApplicationExitInfoBuilder.newBuilder()
            .setPid(123).setProcessName(context.packageName + ":vpn").setTimestamp(at)
            .setReason(ApplicationExitInfo.REASON_USER_REQUESTED).setDescription("[STOP APP]").build()
        shadowOf(context.getSystemService(ActivityManager::class.java)).addApplicationExitInfo(exit)
    }

    @Test fun lateSystemStopAlsoStopsAnAlreadyRestoredLocalTunnel() {
        val record = Record()
        withTileRuntime(record) { f ->
            assertTrue(QuickTunnelController.updateState(f.context, SessionState.RUNNING, desiredActive = true))
            assertNull(f.envelope().leaseTransaction)
        }
        val stoppedAt = System.currentTimeMillis()
        withTileRuntime(record) { f ->
            f.service.onStartCommand(Intent(NelomaiVpnService.ACTION_TAKE_STATE_CHANGE), 0, 1)
            TunnelRuntime.start(f.context, args(), { _, _ -> }, { fail(it) }, keepForegroundServiceOnFailure = true)
            f.work.runNext()
            assertEquals(SessionState.RUNNING, TunnelRuntime.state())
            // The recovery worker waits for a callback from the separate native executor.
            f.work.runImmediately = true
            f.publishSystemStop(stoppedAt)
            f.service.onStartCommand(Intent(NelomaiVpnService.ACTION_CLIENT_STATUS)
                .putExtra(EXTRA_API_VERSION, TUNNEL_API_VERSION), 0, 2)
            f.drainImmediateWork()
            assertFalse(f.envelope().intent.desiredActive)
            assertEquals(Tunnel.State.DOWN, f.backend.getState(f.tunnel))
            assertNull(f.envelope().intent.retry.pendingAction)
            assertNull(f.protectionNotice())
        }
    }

    @Test fun delayedSystemStopCannotCancelANewerStart() {
        val record = Record()
        withTileRuntime(record) { f ->
            assertTrue(f.store.setDesiredActive(0, true) is RecoveryStoreResult.Success)
        }
        val stoppedAt = System.currentTimeMillis()
        withTileRuntime(record) { f ->
            f.service.onStartCommand(Intent(NelomaiVpnService.ACTION_TAKE_STATE_CHANGE), 0, 1)
            assertTrue(f.store.cancelCurrentIntent() is RecoveryStoreResult.Success)
            val replacement = f.beginReplacement()
            f.publishSystemStop(stoppedAt)
            f.service.onStartCommand(Intent(NelomaiVpnService.ACTION_TAKE_STATE_CHANGE), 0, 2)
            shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(6))
            assertEquals(replacement, f.envelope())
        }
    }

    private fun Fixture.startUi(hotStandby: Boolean, onReply: () -> Unit = {}): String {
        var replies = 0
        if (hotStandby) KillSwitchPreference(context).save(enabled = true, confirmed = true)
        val args = if (hotStandby) prepareQuick() else args()
        val lease = java.util.UUID.randomUUID().toString()
        val operation = java.util.UUID.randomUUID().toString()
        val quick = requireNotNull(args.quickConnection).apply { leaseId = lease; allowAlternate = hotStandby }
        val redundant = if (hotStandby) RedundantStartArgs().apply {
            sessionId = java.util.UUID.randomUUID().toString()
            state = "ready"
            operationId = operation
            requestFingerprint = "a".repeat(64)
            virtualAddressV4 = "10.241.0.3/32"
            activeLeaseId = lease
            localActiveLeaseId = lease
            reserveEnabled = true
            standbyDesired = true
            fun member(slotName: String, id: String) = RedundantMemberArgs().apply {
                slot = slotName
                leaseId = id
                healthProbe = RedundantHealthProbeArgs().apply {
                    kind = "dns_a"; targetIpv4 = "10.8.0.1"; queryName = "test.invalid"; timeoutMs = 1500
                }
            }
            primary = member(RedundantSlot.A.wireName, lease)
            standby = RedundantStandbyArgs().apply {
                member = member(RedundantSlot.B.wireName, java.util.UUID.randomUUID().toString())
                configuration = args.configuration.copyOf()
            }
        } else null
        service.onStartCommand(Intent(NelomaiVpnService.ACTION_CLIENT_START)
            .putExtra(EXTRA_API_VERSION, TUNNEL_API_VERSION)
            .putExtra(EXTRA_CLIENT_OPERATION_ID, operation)
            .putExtra(EXTRA_START_SOURCE, "ui")
            .putExtra(EXTRA_CONFIGURATION, args.configuration)
            .putExtra(EXTRA_OPTIONS, args.options.toBundle())
            .putExtra(EXTRA_QUICK_CONNECTION, quick.toBundle())
            .apply { redundant?.let { putExtra(EXTRA_REDUNDANCY, it.toBundle()) } }
            .putExtra(EXTRA_RESULT_RECEIVER, Receiver { code, data ->
                assertEquals(data?.getString(EXTRA_ERROR_CODE), SERVICE_RESULT_OK, code)
                assertEquals(SessionState.RUNNING.wireName, data?.getString(EXTRA_STATE))
                onReply()
                replies++
            }), 0, 1)
        drainImmediateWork()
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(1))
        drainImmediateWork()
        assertEquals(1, replies)
        return operation
    }

    @Test fun passiveReadFailureAfterNewUiStartKeepsUnretainedVpnRunning() {
        val stoppedAt = System.currentTimeMillis() - 1_000
        val record = Record().apply { storeTime = stoppedAt - 1_000 }
        withTileRuntime(record) { it.startUi(false) }
        record.storeTime = stoppedAt + 1_000
        withTileRuntime(record, retainTunDescriptor = false) { f ->
            f.startUi(false)
            assertTrue(requireNotNull(f.envelope().armedAtMillis) > stoppedAt)
            val host = ReflectionHelpers.getField<RuntimeVpnHostV1>(f.service, "runtimeHost").service
            val before = f.envelope()
            val replies = mutableListOf<Pair<Int, String?>>()
            val command = Intent(NelomaiVpnService.ACTION_TAKE_STATE_CHANGE)
                .putExtra(EXTRA_RESULT_RECEIVER, Receiver { code, data ->
                    replies += code to data?.getString(EXTRA_ERROR_CODE)
                })

            f.publishSystemStop(stoppedAt)
            record.failNextRead = true
            f.service.onStartCommand(command, 0, 3)
            shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(1))
            assertEquals(listOf(SERVICE_RESULT_ERROR to "recovery_record_read_failed"), replies)
            assertFalse("a failed observation must not stop the active service", shadowOf(host).isStoppedBySelf)
            assertEquals(Tunnel.State.UP, f.backend.getState(f.tunnel))

            f.service.onStartCommand(command, 0, 4)
            f.drainImmediateWork()
            assertEquals(listOf(SERVICE_RESULT_ERROR to "recovery_record_read_failed",
                SERVICE_RESULT_OK to null), replies)
            assertEquals(before, f.envelope())
            assertEquals(Tunnel.State.UP, f.backend.getState(f.tunnel))
        }
    }

    @Test fun failedFirstObservationCanFinishAnIdleService() = withTileRuntime { f ->
        assertFalse(f.envelope().intent.desiredActive)
        f.publishSystemStop(System.currentTimeMillis())
        f.record.failNextRead = true
        val command = Intent(NelomaiVpnService.ACTION_TAKE_STATE_CHANGE)
        assertEquals(android.app.Service.START_NOT_STICKY, f.service.onStartCommand(command, 0, 1))
        assertFalse(f.record.failNextRead)
        val host = ReflectionHelpers.getField<RuntimeVpnHostV1>(f.service, "runtimeHost").service
        assertEquals(1, shadowOf(host).stopSelfResultId)
        assertTrue(CompletionNative.events.none { it == "up" })
    }

    @Test @Config(shadows = [StatusBrokerSelection::class])
    fun boundStatusConsumesPublishedStopBeforeRecovery() = checkBoundStatusAfterSystemStop(false)

    @Test @Config(shadows = [StatusBrokerSelection::class])
    fun boundStatusRetriesFailedJournalReadOnSameEndpoint() = checkBoundStatusAfterSystemStop(true)

    private fun checkBoundStatusAfterSystemStop(failFirstPoll: Boolean) {
        val record = armedKillSwitchRecord { f ->
            assertTrue(QuickTunnelController.updateState(f.context, SessionState.RUNNING))
        }
        record.failNextRead = true
        withTileRuntime(record, retainTunDescriptor = true) { f ->
            val looper = shadowOf(Looper.getMainLooper())
            val poll = f.openStatusEndpoint()
            looper.idleFor(Duration.ofSeconds(6))
            assertNotNull(f.protectionNotice())
            fun restoreRequests() = org.robolectric.shadows.ShadowLog.getLogs()
                .count { it.msg.contains("service.restore_requested") }
            val before = restoreRequests()
            f.publishSystemStop(System.currentTimeMillis())
            if (failFirstPoll) {
                record.failNextRead = true
                val (code, result) = poll()
                assertEquals(SERVICE_RESULT_ERROR, code)
                assertEquals("recovery_record_read_failed", result.getString(EXTRA_ERROR_CODE))
                assertTrue(f.envelope().intent.desiredActive)
                assertEquals(before, restoreRequests())
            }
            val (code, result) = poll()
            assertEquals(SERVICE_RESULT_OK, code)
            assertEquals(SessionState.STOPPED.wireName, result.getString(EXTRA_STATE))
            assertFalse(f.envelope().intent.desiredActive)
            assertNull(f.protectionNotice())
            assertEquals(before, restoreRequests())
            f.drainImmediateWork()
            assertTrue(CompletionNative.events.none { it == "up" })
        }
    }

    private fun Fixture.openStatusEndpoint(): () -> Pair<Int, Bundle> {
        val looper = shadowOf(Looper.getMainLooper())
        var bootstrap: Bundle? = null
        service.onStartCommand(Intent(NelomaiVpnService.ACTION_CLIENT_STATUS)
            .putExtra(EXTRA_API_VERSION, TUNNEL_API_VERSION)
            .putExtra(EXTRA_RESULT_RECEIVER, Receiver { code, data ->
                assertEquals(SERVICE_RESULT_OK, code)
                bootstrap = data
            }), 0, 1)
        looper.idle()
        val endpoint = requireNotNull(bootstrap)
        val messenger = android.os.Messenger(requireNotNull(endpoint.getBinder(EXTRA_STATUS_ENDPOINT)))
        return {
            var reply: Pair<Int, Bundle>? = null
            messenger.send(android.os.Message.obtain(null, STATUS_OBSERVE).apply {
                data = Bundle().apply {
                    putInt(EXTRA_API_VERSION, TUNNEL_API_VERSION)
                    putLong(EXTRA_STATUS_GENERATION, endpoint.getLong(EXTRA_STATUS_GENERATION))
                    putString(EXTRA_STATUS_RUNTIME, endpoint.getString(EXTRA_STATUS_RUNTIME))
                    putParcelable(EXTRA_RESULT_RECEIVER, Receiver { code, result -> reply = code to requireNotNull(result) })
                }
            })
            looper.idle()
            requireNotNull(reply).also { (_, result) ->
                assertEquals(endpoint.getLong(EXTRA_STATUS_GENERATION), result.getLong(EXTRA_STATUS_GENERATION))
                assertEquals(endpoint.getString(EXTRA_STATUS_RUNTIME), result.getString(EXTRA_STATUS_RUNTIME))
            }
        }
    }

    @Test @Config(shadows = [StatusBrokerSelection::class])
    fun boundStatusReflectsSystemStopWhileRestoredTransportCloses() =
        checkBoundStatusUntilTransportCloses(repeatStopFromUi = false)

    @Test @Config(shadows = [StatusBrokerSelection::class])
    fun boundStatusKeepsStoppingWhenUiRepeatsSystemStop() =
        checkBoundStatusUntilTransportCloses(repeatStopFromUi = true)

    private fun checkBoundStatusUntilTransportCloses(repeatStopFromUi: Boolean) {
        val record = Record()
        withTileRuntime(record) { f ->
            assertTrue(QuickTunnelController.updateState(f.context, SessionState.RUNNING, desiredActive = true))
        }
        withTileRuntime(record) { f ->
            val poll = f.openStatusEndpoint()
            fun assertStatus(expected: SessionState, transport: Tunnel.State) {
                val (code, reply) = poll()
                assertEquals(SERVICE_RESULT_OK, code)
                assertEquals(transport, f.backend.getState(f.tunnel))
                assertEquals(expected.wireName, reply.getString(EXTRA_STATE))
                assertFalse(f.envelope().intent.desiredActive)
            }
            TunnelRuntime.start(f.context, args(), { _, _ -> }, { fail(it) }, keepForegroundServiceOnFailure = true)
            f.work.runNext()
            f.publishSystemStop(System.currentTimeMillis())
            assertStatus(SessionState.STOPPING, Tunnel.State.UP)
            if (repeatStopFromUi) {
                var result: Int? = null
                f.service.onStartCommand(Intent(NelomaiVpnService.ACTION_CANCEL_CURRENT_CONNECTION_INTENT)
                    .putExtra(EXTRA_RESULT_RECEIVER, Receiver { code, _ -> result = code }), 0, 2)
                shadowOf(Looper.getMainLooper()).idle()
                assertEquals(SERVICE_RESULT_OK, result)
            }
            repeat(2) { assertStatus(SessionState.STOPPING, Tunnel.State.UP) }
            val repliesDuringNativeClose = mutableListOf<Pair<Int, String?>>()
            CompletionNative.onDown = {
                val (code, reply) = poll()
                repliesDuringNativeClose += code to reply.getString(EXTRA_STATE)
            }
            f.work.runImmediately = true
            f.drainImmediateWork()
            assertEquals("Binder status inside awgTurnOff",
                listOf(SERVICE_RESULT_OK to SessionState.STOPPING.wireName), repliesDuringNativeClose)
            assertStatus(SessionState.STOPPED, Tunnel.State.DOWN)
        }
    }

    @Test fun lateSystemStopKeepsNewUiStart() = verifyNewUiStart(false)

    @Test @Config(shadows = [ConfirmedStandbyTransport::class, StandbyPhysicalNetwork::class])
    fun lateSystemStopKeepsNewHotStandbyUiStart() = verifyNewUiStart(true)

    private fun verifyNewUiStart(hotStandby: Boolean) {
        val stoppedAt = System.currentTimeMillis() - 1_000
        val record = Record().apply { storeTime = stoppedAt - 1_000 }
        withTileRuntime(record) { it.startUi(false) }
        record.storeTime = stoppedAt + 1_000
        withTileRuntime(record, retainTunDescriptor = hotStandby) { f ->
            val operation = f.startUi(hotStandby)
            val before = f.envelope()
            f.work.runImmediately = true
            f.publishSystemStop(stoppedAt)
            if (!hotStandby) f.service.onStartCommand(Intent(NelomaiVpnService.ACTION_TAKE_STATE_CHANGE), 0, 2)
            shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(6))
            f.drainImmediateWork()
            assertTrue(f.envelope().intent.desiredActive)
            if (hotStandby) {
                assertEquals(operation, before.redundantTransaction?.startOperationId)
                assertEquals(operation, f.envelope().redundantTransaction?.startOperationId)
                assertEquals(RedundantStopState.NONE, f.envelope().redundantTransaction?.retry?.stopState)
            } else assertEquals(Tunnel.State.UP, f.backend.getState(f.tunnel))
            assertTrue(requireNotNull(f.envelope().armedAtMillis) > stoppedAt)
            ReflectionHelpers.getField<android.os.Handler>(f.service, "restoreHandler").removeCallbacksAndMessages(null)
        }
        // After another process death, the durable start time must distinguish
        // the two exit records even though the lease generation was reused.
        withTileRuntime(record, retainTunDescriptor = hotStandby) { f ->
            f.publishSystemStop(stoppedAt)
            f.service.onStartCommand(Intent(NelomaiVpnService.ACTION_TAKE_STATE_CHANGE), 0, 1)
            assertTrue(f.envelope().intent.desiredActive)
            f.publishSystemStop(requireNotNull(f.envelope().armedAtMillis) + 1)
            f.service.onStartCommand(Intent(NelomaiVpnService.ACTION_TAKE_STATE_CHANGE), 0, 2)
            assertFalse(f.envelope().intent.desiredActive)
            assertNull(f.protectionNotice())
        }
    }

    @Test @Config(shadows = [ConfirmedStandbyTransport::class, StandbyPhysicalNetwork::class])
    fun coldRestartFromHotStandbyStartReplyShowsProtectionLoss() = verifyStandbyLoss(false)

    @Test @Config(shadows = [ConfirmedStandbyTransport::class, StandbyPhysicalNetwork::class])
    fun coldRestartRetriesUnreadableStandbyCheckpointWithoutRpc() = verifyStandbyLoss(true)

    private fun verifyStandbyLoss(failFirstRead: Boolean) {
        val atReply = Record()
        withTileRuntime(retainTunDescriptor = true) { f ->
            f.startUi(true) { assertTrue(atReply.write(requireNotNull(f.record.read()))) }
            // The dead process cannot deliver its queued health checks.
            ReflectionHelpers.getField<android.os.Handler>(f.service, "restoreHandler").removeCallbacksAndMessages(null)
        }
        atReply.failNextRead = failFirstRead
        withTileRuntime(atReply, retainTunDescriptor = true) { f ->
            assertFalse(atReply.failNextRead)
            if (failFirstRead) shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(6))
            else shadowOf(Looper.getMainLooper()).idle()
            assertTrue(f.envelope().intent.armedHistory)
            assertEquals("Защита прервана, восстанавливаем VPN",
                f.protectionNotice()?.extras?.getCharSequence(Notification.EXTRA_TEXT))
        }
    }

    @Test fun coldStatusAfterSystemStopDoesNotAnnounceProtectionLoss() {
        val record = armedKillSwitchRecord { it.recordSystemStop(SessionState.RUNNING) }
        withTileRuntime(record, retainTunDescriptor = true) { f ->
            shadowOf(Looper.getMainLooper()).idle()
            assertNull(f.protectionNotice())
            f.readStatusAfterSystemStop()
        }
    }

    @Test fun coldStatusClearsProtectionLossWhenAndroidPublishesStopAfterCreation() {
        val record = armedKillSwitchRecord()
        withTileRuntime(record, retainTunDescriptor = true) { f ->
            shadowOf(Looper.getMainLooper()).idle()
            assertNotNull(f.protectionNotice())
            f.recordSystemStop(SessionState.RUNNING)
            f.readStatusAfterSystemStop()
        }
    }

    @Test fun firstTileStartAfterLateSystemStopClearsOldProtectionNotice() {
        val record = armedKillSwitchRecord()
        withTileRuntime(record, retainTunDescriptor = true) { f ->
            shadowOf(Looper.getMainLooper()).idle()
            assertNotNull(f.protectionNotice())
            f.prepareQuick()
            f.firstTapAfterSystemStop(SessionState.RUNNING)
            shadowOf(Looper.getMainLooper()).idle()
            assertNull(f.protectionNotice())
        }
    }

    @Test fun vpnProcessDeathAfterANewerStartReportsProtectionLoss() {
        val record = armedKillSwitchRecord { f ->
            val armedAt = requireNotNull(f.envelope().armedAtMillis)
            val manager = shadowOf(f.context.getSystemService(ActivityManager::class.java))
            fun exit(at: Long, reason: Int, description: String) = ShadowActivityManager.ApplicationExitInfoBuilder
                .newBuilder().setPid(100).setProcessName(f.context.packageName + ":vpn")
                .setTimestamp(at).setReason(reason).setDescription(description).build()
            manager.addApplicationExitInfo(exit(armedAt - 1000, ApplicationExitInfo.REASON_USER_REQUESTED, "[STOP APP]"))
            manager.addApplicationExitInfo(exit(armedAt + 1000, ApplicationExitInfo.REASON_LOW_MEMORY, "low memory"))
        }
        withTileRuntime(record, retainTunDescriptor = true) { f ->
            shadowOf(Looper.getMainLooper()).idle()
            assertEquals("Защита прервана, восстанавливаем VPN",
                f.protectionNotice()?.extras?.getCharSequence(Notification.EXTRA_TEXT))
            assertTrue(f.envelope().intent.desiredActive)
        }
    }

    private fun armedKillSwitchRecord(beforeDeath: (Fixture) -> Unit = {}): Record = Record().also { record ->
        withTileRuntime(record, retainTunDescriptor = true) { f ->
            KillSwitchPreference(f.context).save(enabled = true, confirmed = true)
            f.armCheckpoint()
            beforeDeath(f)
        }
    }

    private fun Fixture.protectionNotice(): Notification? =
        context.getSystemService(NotificationManager::class.java).activeNotifications
            .firstOrNull { it.id == 22 }?.notification

    private fun Fixture.readStatusAfterSystemStop() {
        service.onStartCommand(Intent(NelomaiVpnService.ACTION_CLIENT_STATUS)
            .putExtra(EXTRA_API_VERSION, TUNNEL_API_VERSION), 0, 1)
        drainImmediateWork()
        assertFalse(envelope().intent.desiredActive)
        assertNull(protectionNotice())
    }

    private fun checkColdSystemStop(action: String?, lastPublished: SessionState = SessionState.RUNNING) {
        val record = Record()
        val operation = java.util.UUID.randomUUID().toString()
        withTileRuntime(record) { f ->
            f.beginHotStandby(operation)
            f.recordSystemStop(lastPublished)
        }
        withTileRuntime(record) { f ->
            f.prepareQuick()
            val cmd = action?.let { Intent(it).putExtra(EXTRA_API_VERSION, TUNNEL_API_VERSION) }
            f.service.onStartCommand(cmd, 0, 1)
            f.drainImmediateWork()
            assertTrue("passive command recovered old session: ${CompletionPanel.redundantRecoveries}",
                CompletionPanel.redundantRecoveries.isEmpty())
            assertEquals(listOf(operation), CompletionPanel.redundantStops.map { it.startOperationId })
            assertFalse(f.envelope().intent.desiredActive)
            assertEquals("stopped", QuickTunnelController.state(f.context))
            assertTrue(CompletionNative.events.isEmpty())
        }
    }

    @Test fun admittedForegroundReplacementOnlyTransfersItsWatchWhileColdRecoveryResumesHotStandby() =
        withTileRuntime { f ->
            f.beginHotStandby()
            val original = f.envelope()
            val pid = 772
            org.robolectric.shadows.ShadowProcess.setPid(pid)
            val owner = RuntimeSelectionStore.encodeVpnRecoveryOwner(requireNotNull(RuntimeProcessSelection.vpnOwnerForStop()))
            val watch = TaskRemovalVpnWatch(pid + 1, System.currentTimeMillis(), true, owner)
            registerTestVpnWatch(f.context, watch)
            val command = taskRemovalVpnIntent(f.context, watch)
            val foregroundKey = ru.nelomai.runtime.v1.RuntimeServiceIntents.TASK_REMOVAL_FOREGROUND_PID
            f.service.onStartCommand(command.putExtra(foregroundKey, pid), 0, 1)
            val jobs = f.context.getSystemService(android.app.job.JobScheduler::class.java)
            val transferred = TaskRemovalVpnWatch.fromJob(jobs.allPendingJobs.single().extras)
            assertEquals(watch.copy(pid = pid, waitedForExit = false), transferred)
            assertEquals(original, f.envelope())
            assertTrue("a live transfer must not recover the lease again", f.lookupWork.jobs.isEmpty())

            f.service.onStartCommand(taskRemovalVpnIntent(f.context, requireNotNull(transferred)), 0, 2)
            assertEquals("a cold delivery must queue Hot Standby recovery", 1, f.lookupWork.jobs.size)
        }

    @Test fun watchKeepsHandoffUntilTheColdStoreCanBeRead() = withTileRuntime { f ->
        f.beginHotStandby()
        org.robolectric.shadows.ShadowProcess.setPid(772)
        val watch = TaskRemovalVpnWatch(47, System.currentTimeMillis())
        val initialJob = registerTestVpnWatch(f.context, watch)
        val command = taskRemovalVpnIntent(f.context, watch)
        val jobs = f.context.getSystemService(android.app.job.JobScheduler::class.java)
        f.record.readFails = true
        assertEquals(android.app.Service.START_NOT_STICKY, f.service.onStartCommand(command, 0, 1))
        assertEquals(initialJob, jobs.allPendingJobs.single())
        assertTrue(f.lookupWork.jobs.isEmpty())
        f.record.readFails = false
        assertEquals(android.app.Service.START_STICKY, f.service.onStartCommand(command, 0, 2))
        assertEquals(1, jobs.allPendingJobs.size)
        assertEquals(1, f.lookupWork.jobs.size)
    }

    @Test fun coldHandoffRetriesAReadFailureInsideTheRecoveryWorker() = withTileRuntime { f ->
        f.beginHotStandby()
        org.robolectric.shadows.ShadowProcess.setPid(772)
        val watch = TaskRemovalVpnWatch(47, System.currentTimeMillis())
        registerTestVpnWatch(f.context, watch)
        val command = taskRemovalVpnIntent(f.context, watch)
        f.service.onStartCommand(command, 0, 1)
        f.record.readFails = true
        f.lookupWork.runNext()
        shadowOf(Looper.getMainLooper()).idle()
        f.record.readFails = false
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(3))
        assertEquals("the original worker lost its read and must be replaced", 1, f.lookupWork.jobs.size)
    }

    @Test @Config(shadows = [CompletionExitHistory::class])
    fun queuedOffTileStartSurvivesTemporaryHistoryFailure() = checkQueuedStartAfterHistoryReturns(false)

    @Test @Config(shadows = [CompletionExitHistory::class])
    fun queuedOffTileStartSurvivesTheWholeHistoryBackoff() = checkQueuedStartAfterHistoryReturns(true)

    private fun checkQueuedStartAfterHistoryReturns(longOutage: Boolean) = withTileRuntime { f ->
        val old = f.preparePendingHotStandbyStop()
        val command = f.offTileStartCommand(SessionState.STOPPED)
        f.completeOldStop(old)
        val sample = f.prepareQuick()
        f.record.onCommit = { bytes ->
            if (JSONObject(String(bytes)).has("pendingQuickStart")) {
                CompletionExitHistory.unavailable = true
                f.record.onCommit = null
            }
        }
        try {
            f.service.onStartCommand(command, 0, 2)
            assertTrue(CompletionExitHistory.unavailable)
            if (longOutage) {
                shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMinutes(8))
                assertTrue(CompletionNative.events.isEmpty())
            }
            assertNotNull(f.envelope().pendingQuickStart)
        } finally {
            CompletionExitHistory.unavailable = false
        }
        shadowOf(Looper.getMainLooper()).idleFor(if (longOutage) Duration.ofMinutes(5) else Duration.ofSeconds(3))
        f.assertFreshQuickStart(sample)
    }

    @Test @Config(shadows = [CompletionExitHistory::class])
    fun preparedOffTapIsKeptWhenHistoryReadFailsAtDelivery() = withTileRuntime { f ->
        val old = f.preparePendingHotStandbyStop()
        val command = f.offTileStartCommand(SessionState.STOPPED)
        f.completeOldStop(old)
        val sample = f.prepareQuick()
        CompletionExitHistory.unavailable = true
        try {
            f.service.onStartCommand(command, 0, 1)
            assertNotNull(f.envelope().pendingQuickStart)
            assertTrue(CompletionNative.events.isEmpty())
        } finally {
            CompletionExitHistory.unavailable = false
        }
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(3))
        f.assertFreshQuickStart(sample)
    }

    @Test @Config(shadows = [CompletionExitHistory::class])
    fun coldUiStopCancelsSavedQuickStartWhileHistoryIsUnavailable() {
        val record = Record()
        withTileRuntime(record) { f ->
            f.preparePendingHotStandbyStop()
            f.firstTapAfterSystemStop(SessionState.STOPPING)
            assertNotNull(f.envelope().pendingQuickStart)
        }
        withTileRuntime(record) { f ->
            f.prepareQuick()
            CompletionExitHistory.unavailable = true
            try {
                f.service.onStartCommand(Intent(NelomaiVpnService.ACTION_CANCEL_CURRENT_CONNECTION_INTENT), 0, 1)
                assertNull(f.envelope().pendingQuickStart)
            } finally {
                CompletionExitHistory.unavailable = false
            }
            f.service.onStartCommand(Intent(NelomaiVpnService.ACTION_ENSURE_RUNNING), 0, 2)
            f.drainImmediateWork()
            assertFalse(f.envelope().intent.desiredActive)
            assertTrue(CompletionNative.events.isEmpty())
        }
    }

    @Test fun swipeKeepsWatchForInstalledHotStandbyWithUnreadableStore() = withTileRuntime { f ->
        val transaction = f.beginHotStandby()
        val owner = java.lang.reflect.Proxy.newProxyInstance(RedundantVpnProcessOwner::class.java.classLoader,
            arrayOf(RedundantVpnProcessOwner::class.java)) { _, method, _ -> method.returnType == Boolean::class.javaPrimitiveType }
            as RedundantVpnProcessOwner
        f.service.installRedundantVpnOwner(owner, transaction.startOperationId)
        try {
            assertEquals(SessionState.STOPPED, TunnelRuntime.state())
            org.robolectric.shadows.ShadowProcess.setPid(772)
            f.record.readFails = true
            f.service.onTaskRemoved(null)
            val jobs = f.context.getSystemService(android.app.job.JobScheduler::class.java)
            assertNotNull(TaskRemovalVpnWatch.fromJob(jobs.allPendingJobs.single().extras))
        } finally {
            f.record.readFails = false
            f.service.installRedundantVpnOwner(null)
        }
    }

    @Test fun firstStatusAfterSystemStopCannotAdvertiseTheOldQueuedStart() {
        val record = Record()
        val oldTap = System.currentTimeMillis() - 2_000
        withTileRuntime(record) { f ->
            val old = f.preparePendingHotStandbyStop()
            f.recordSystemStop(SessionState.STOPPING, oldTap - 500)
            f.service.onStartCommand(f.captureActualOffTileCommand().putExtra("quick_start_requested_at", oldTap), 0, 1)
            f.completeOldStop(old)
            assertNotNull(f.envelope().pendingQuickStart)
        }
        withTileRuntime(record) { f ->
            f.recordSystemStop(SessionState.STOPPED, oldTap + 500)
            f.service.onStartCommand(Intent(NelomaiVpnService.ACTION_CLIENT_STATUS)
                .putExtra(EXTRA_API_VERSION, TUNNEL_API_VERSION), 0, 1)
            assertNull(f.envelope().pendingQuickStart)
            assertEquals("none", connectionIntentServiceStatus(f.envelope()).status)
        }
    }

    @Test fun lateJobDoesNotStopOrRestartTheStickyRecoveryAlreadyInProgress() = withTileRuntime { f ->
        f.beginHotStandby()
        org.robolectric.shadows.ShadowProcess.setPid(772)
        val owner = requireNotNull(RuntimeProcessSelection.vpnOwnerForStop())
        val old = TaskRemovalVpnWatch(771, System.currentTimeMillis(), deathSignalled = true,
            runtime = RuntimeSelectionStore.encodeVpnRecoveryOwner(owner))
        val job = registerTestVpnWatch(f.context, old)
        f.service.onStartCommand(null, 0, 1)
        val scheduler = f.context.getSystemService(android.app.job.JobScheduler::class.java)
        assertEquals(old.forCurrentProcess(), TaskRemovalVpnWatch.fromJob(requireNotNull(scheduler.getPendingJob(job.id)).extras))
        assertEquals(1, f.lookupWork.jobs.size)
        f.service.onStartCommand(taskRemovalVpnIntent(f.context, old), 0, 2)
        val host = ReflectionHelpers.getField<RuntimeVpnHostV1>(f.service, "runtimeHost").service
        assertNotEquals("the delayed job must not stop its successor", 2, shadowOf(host).stopSelfResultId)
        assertEquals("only the original restore runs", 1, f.lookupWork.jobs.size)
    }

    @Test fun delayedWatchAfterAnotherSwipeCannotStopTheCurrentRecovery() = withTileRuntime { f ->
        f.beginHotStandby()
        org.robolectric.shadows.ShadowProcess.setPid(772)
        val owner = requireNotNull(RuntimeProcessSelection.vpnOwnerForStop())
        val old = TaskRemovalVpnWatch(771, System.currentTimeMillis() - 2_000, deathSignalled = true,
            runtime = RuntimeSelectionStore.encodeVpnRecoveryOwner(owner))
        val job = registerTestVpnWatch(f.context, old)
        f.service.onStartCommand(null, 0, 1)
        f.service.onTaskRemoved(null)
        val scheduler = f.context.getSystemService(android.app.job.JobScheduler::class.java)
        fun current() = requireNotNull(TaskRemovalVpnWatch.fromJob(requireNotNull(scheduler.getPendingJob(job.id)).extras))
        val newer = current()
        assertEquals(772, newer.pid)
        assertTrue(newer.sinceMillis > old.sinceMillis)
        f.service.onStartCommand(taskRemovalVpnIntent(f.context, old), 0, 2)
        assertNotEquals(2, f.stoppedStartId())
        assertEquals(newer, current())
        assertEquals(1, f.lookupWork.jobs.size)
    }

    @Test fun lateUnreadableWatchDoesNotStopTheAcceptedJobBeforeItsWorkerRuns() = withTileRuntime { f ->
        f.beginHotStandby()
        org.robolectric.shadows.ShadowProcess.setPid(772)
        val old = TaskRemovalVpnWatch(771, System.currentTimeMillis())
        registerTestVpnWatch(f.context, old)
        f.service.onStartCommand(taskRemovalVpnIntent(f.context, old), 0, 1)
        assertEquals(1, f.lookupWork.jobs.size)
        f.record.readFails = true
        try {
            f.service.onStartCommand(taskRemovalVpnIntent(f.context, old), 0, 2)
            shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(500))
            assertNotEquals(2, f.stoppedStartId())
            assertEquals(1, f.lookupWork.jobs.size)
        } finally {
            f.record.readFails = false
        }
    }

    @Test fun rejectedWatchPreservesAnIdleStopAndUsesTheNewestAndroidStartId() = withTileRuntime { f ->
        f.service.onStartCommand(Intent(NelomaiVpnService.ACTION_ENSURE_RUNNING), 0, 1)
        val main = shadowOf(Looper.getMainLooper())
        main.idleFor(Duration.ofMillis(250))
        f.record.readFails = true
        try {
            val watch = TaskRemovalVpnWatch(771, System.currentTimeMillis())
            f.service.onStartCommand(taskRemovalVpnIntent(f.context, watch), 0, 2)
            assertNotEquals("the pending idle check owns shutdown", 2, f.stoppedStartId())
        } finally {
            f.record.readFails = false
        }
        main.idleFor(Duration.ofMillis(151))
        assertEquals("an idle service must still leave foreground", 2, f.stoppedStartId())
    }

    @Test fun consecutiveColdRejectedWatchesReleaseTheLastStart() = withTileRuntime { f ->
        f.beginHotStandby()
        val command = taskRemovalVpnIntent(f.context, TaskRemovalVpnWatch(771, System.currentTimeMillis()))
        for (id in 1..2) {
            f.service.onStartCommand(command, 0, id)
            assertEquals(id, f.stoppedStartId())
        }
        assertTrue(f.lookupWork.jobs.isEmpty())
    }

    private fun Fixture.stoppedStartId(): Int {
        val host = ReflectionHelpers.getField<RuntimeVpnHostV1>(service, "runtimeHost").service
        return shadowOf(host).stopSelfResultId
    }

    @Test fun stickyRestartRetriesHotStandbyAfterTemporaryStoreFailureWithoutAWatchWakeup() = withTileRuntime { f ->
        f.beginHotStandby()
        val owner = requireNotNull(RuntimeProcessSelection.vpnOwnerForStop())
        org.robolectric.shadows.ShadowProcess.setPid(772)
        val watch = TaskRemovalVpnWatch(android.os.Process.myPid() + 1, System.currentTimeMillis(),
            runtime = RuntimeSelectionStore.encodeVpnRecoveryOwner(owner))
        val job = registerTestVpnWatch(f.context, watch)
        val scheduler = f.context.getSystemService(android.app.job.JobScheduler::class.java)
        fun current() = TaskRemovalVpnWatch.fromJob(requireNotNull(scheduler.getPendingJob(job.id)).extras)
        f.record.readFails = true
        f.service.onStartCommand(null, 0, 1)
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals(watch, current())
        f.record.readFails = false
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(3))
        assertEquals("a live service must resume the saved Hot Standby itself", 1, f.lookupWork.jobs.size)
        assertEquals("a recovered service watches its next death", watch.copy(pid = android.os.Process.myPid()), current())
    }

    @Test @Config(shadows = [DeferredFailureDiagnostics::class])
    fun queuedStartWithNoSavedPlanFinishesOnceAndAllowsAnotherFreshTap() = withTileRuntime { f ->
        val old = f.preparePendingHotStandbyStop()
        val command = f.offTileStartCommand(SessionState.STOPPED)
        f.completeOldStop(old)
        val sample = f.prepareQuick()
        val originalPlan = CompletionQuickPlan.template
        CompletionQuickPlan.template = null
        f.service.onStartCommand(command, 0, 1)
        f.drainImmediateWork()
        assertNull(f.envelope().pendingQuickStart)
        assertFalse(f.envelope().intent.desiredActive)
        assertTrue(CompletionNative.events.isEmpty())
        val finishOldReport = requireNotNull(DeferredFailureDiagnostics.finish)
        DeferredFailureDiagnostics.finish = null
        CompletionQuickPlan.template = originalPlan
        f.service.onStartCommand(f.captureActualOffTileCommand(), 0, 2)
        f.assertFreshQuickStart(sample)
        val host = ReflectionHelpers.getField<RuntimeVpnHostV1>(f.service, "runtimeHost").service
        finishOldReport(null)
        shadowOf(Looper.getMainLooper()).idle()
        assertNotEquals("the completed report must not stop the new VPN service", 2, shadowOf(host).stopSelfResultId)
        assertEquals(Tunnel.State.UP, f.backend.getState(f.tunnel))
    }

    @Test fun failedClearOfRejectedTapRetriesOnlyTheClear() = withTileRuntime { f ->
        val old = f.preparePendingHotStandbyStop()
        val command = f.offTileStartCommand(SessionState.STOPPED)
        f.completeOldStop(old)
        f.prepareQuick()
        val validPlan = CompletionQuickPlan.template
        CompletionQuickPlan.template = null
        f.record.onCommit = { bytes ->
            if (JSONObject(String(bytes)).has("pendingQuickStart")) f.record.writeFails = true
        }
        f.service.onStartCommand(command, 0, 1)
        f.drainImmediateWork()
        assertNotNull(f.envelope().pendingQuickStart)
        CompletionQuickPlan.template = validPlan
        f.record.writeFails = false
        f.record.onCommit = null
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(6))
        f.drainImmediateWork()
        assertNull(f.envelope().pendingQuickStart)
        assertFalse(f.envelope().intent.desiredActive)
        assertTrue(CompletionNative.events.isEmpty())
    }

    private fun Fixture.rejectTapDuringWriteFailure(): StartTunnelArgs {
        val old = preparePendingHotStandbyStop()
        val command = offTileStartCommand(SessionState.STOPPED)
        completeOldStop(old)
        val sample = prepareQuick()
        val validPlan = CompletionQuickPlan.template
        CompletionQuickPlan.template = null
        record.onCommit = { bytes ->
            if (JSONObject(String(bytes)).has("pendingQuickStart")) record.writeFails = true
        }
        service.onStartCommand(command, 0, 1)
        drainImmediateWork()
        assertNotNull(envelope().pendingQuickStart)
        assertTrue(CompletionNative.events.isEmpty())
        record.onCommit = null
        record.writeFails = false
        CompletionQuickPlan.template = validPlan
        return sample
    }

    @Test @Config(shadows = [DeferredFailureDiagnostics::class])
    fun recreatedServiceDoesNotStartRejectedTapWhenThePlanReturns() {
        val original = Record()
        val crashedJournal = Record()
        val credentialRecord = Record()
        val crashedCredentials = Record()
        lateinit var sample: StartTunnelArgs
        withTileRuntime(original, credentialRecord = credentialRecord) { f ->
            sample = f.rejectTapDuringWriteFailure()
            // Capture exactly what a newly created process could read. Callbacks
            // draining on the old fixture during teardown cannot mutate these bytes.
            assertTrue(crashedJournal.write(requireNotNull(original.read())))
            assertTrue(crashedCredentials.write(requireNotNull(credentialRecord.read())))
            assertNotNull("credential in the crash snapshot", BackgroundCredentialStore(crashedCredentials).read().let {
                (it as? CredentialStoreResult.Success)?.value?.active
            })
        }
        withTileRuntime(crashedJournal, credentialRecord = crashedCredentials) { f ->
            val request = requireNotNull(f.envelope().pendingQuickStart)
            assertFalse(VpnTaskRemovalLiveness.systemStoppedSince(f.context, request.requestedAtMillis))
            CompletionQuickPlan.template = QuickTunnelTemplate(sample.options, sample.quickConnection!!)
            val restored = AndroidBackgroundCredentialStores.open(f.context)
            val read = restored.read()
            assertSame("recreated service reads the captured credential backend", crashedCredentials,
                ReflectionHelpers.getField<EncryptedRecordBackend>(restored, "backend"))
            assertTrue("restored credential: " + when (read) {
                is CredentialStoreResult.Success -> "revision=" + read.value.revision + ", active=" + (read.value.active != null)
                is CredentialStoreResult.Failure -> read.code
            }, read is CredentialStoreResult.Success && read.value.active != null)
            var panelStarts = 0
            CompletionPanel.onStart = {
                panelStarts++
                BackgroundStartResult(sample.configuration, sample.quickConnection!!, sample.options)
            }
            f.service.onStartCommand(null, 0, 1)
            f.drainImmediateWork()
            assertEquals("the rejected tap must not allocate a new session", 0, panelStarts)
            assertNull(f.envelope().pendingQuickStart)
            assertFalse(f.envelope().intent.desiredActive)
            assertTrue(CompletionNative.events.isEmpty())
        }
    }

    @Test fun freshTapBeforeRejectedTapCleanupStartsOnce() = withTileRuntime { f ->
        val sample = f.rejectTapDuringWriteFailure()
        f.service.onStartCommand(f.captureActualOffTileCommand(), 0, 2)
        f.assertFreshQuickStart(sample)
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(6))
        f.drainImmediateWork()
        assertTrue(f.envelope().intent.desiredActive)
        assertEquals(listOf("up"), CompletionNative.events)
    }

    @Test fun interruptedStopTileChecksV2CapabilityOnceBeforeCommittingTheNewStart() = withTileRuntime { f ->
        val old = f.preparePendingHotStandbyStop()
        val command = f.offTileStartCommand(SessionState.STOPPED)
        f.completeOldStop(old)
        f.prepareQuick().quickConnection!!.reserveEnabled = true
        var requests = 0
        CompletionPanel.onCapabilities = {
            requests++
            BackgroundCapabilitySnapshot(2, true, Long.MAX_VALUE, reserveEnabled = true)
        }
        f.service.onStartCommand(command, 0, 1)
        f.drainImmediateWork()
        assertTrue(f.envelope().intent.desiredActive)
        assertEquals(2, f.envelope().leaseTransaction?.replay?.contractVersion)
        assertEquals("one live authorization for this explicit Hot Standby start", 1, requests)
    }

    @Test fun freshTapDuringRejectedTapCompletionStartsOnce() = withTileRuntime { f ->
        val old = f.preparePendingHotStandbyStop()
        val first = f.offTileStartCommand(SessionState.STOPPED)
        val firstTime = first.getLongExtra("quick_start_requested_at", 0)
        f.completeOldStop(old)
        val sample = f.prepareQuick()
        // The disabled recovery capability rejects this v2 plan before it starts.
        sample.quickConnection!!.reserveEnabled = true
        val prefs = f.context.getSharedPreferences(
            AndroidRuntimeNamespace.record("nelomai-quick-tunnel-state"), Context.MODE_PRIVATE,
        )
        assertTrue(prefs.edit().remove("rejected-tile-tap").commit())
        var replacementQueued = false
        val listener = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
            if (key == "rejected-tile-tap" && !replacementQueued) {
                val rejected = requireNotNull(f.envelope().pendingQuickStart)
                assertTrue(QuickTunnelController.wasRejectedTap(f.context, rejected))
                f.record.writeFails = false
                f.record.onCommit = null
                sample.quickConnection!!.reserveEnabled = null
                val replacement = f.captureActualOffTileCommand()
                    .putExtra("quick_start_requested_at", firstTime + 1)
                f.service.onStartCommand(replacement, 0, 2)
                assertEquals(firstTime + 1, f.envelope().pendingQuickStart?.requestedAtMillis)
                replacementQueued = true
            }
        }
        prefs.registerOnSharedPreferenceChangeListener(listener)
        try {
            f.record.onCommit = { bytes ->
                if (JSONObject(String(bytes)).has("pendingQuickStart")) f.record.writeFails = true
            }
            var starts = 0
            CompletionPanel.onStart = {
                starts++
                BackgroundStartResult(sample.configuration, sample.quickConnection!!, sample.options)
            }
            f.service.onStartCommand(first, 0, 1)
            f.drainImmediateWork()
            assertTrue("the new tap must overlap the old rejection", replacementQueued)
            assertEquals("only the new tap allocates a connection", 1, starts)
            assertTrue(f.envelope().intent.desiredActive)
            assertEquals(Tunnel.State.UP, f.backend.getState(f.tunnel))
            val host = ReflectionHelpers.getField<RuntimeVpnHostV1>(f.service, "runtimeHost").service
            assertNotEquals("the old failure must not stop the new request", 2, shadowOf(host).stopSelfResultId)
        } finally {
            prefs.unregisterOnSharedPreferenceChangeListener(listener)
            f.record.onCommit = null
            f.record.writeFails = false
        }
    }

    @Test fun coldWatchCompletesOnlyTheInterruptedStop() {
        val record = Record()
        var operation = ""
        withTileRuntime(record) { f -> operation = f.preparePendingHotStandbyStop().startOperationId }
        withTileRuntime(record) { f ->
            f.prepareQuick()
            val watch = TaskRemovalVpnWatch(47, System.currentTimeMillis())
            f.service.onStartCommand(taskRemovalVpnIntent(f.context, watch), 0, 1)
            f.drainImmediateWork()
            assertEquals(listOf(operation), CompletionPanel.redundantStops.map { it.startOperationId })
            assertNull(f.envelope().redundantTransaction)
            assertFalse(f.envelope().intent.desiredActive)
            assertTrue(CompletionPanel.redundantRecoveries.isEmpty())
            assertTrue(CompletionNative.events.isEmpty())
            assertTrue(f.context.getSystemService(android.app.job.JobScheduler::class.java).allPendingJobs.isEmpty())
        }
    }

    @Test fun retriedWatchEndsWhenTheLatestDurableIntentHasStopped() = withTileRuntime { f ->
        val watch = TaskRemovalVpnWatch(47, System.currentTimeMillis())
        f.service.onStartCommand(taskRemovalVpnIntent(f.context, watch), 0, 1)
        assertNull(f.envelope().redundantTransaction)
        assertFalse(f.envelope().intent.desiredActive)
        assertTrue(f.context.getSystemService(android.app.job.JobScheduler::class.java).allPendingJobs.isEmpty())
        assertTrue(f.lookupWork.jobs.isEmpty())
    }

    private fun withTileRuntime(record: Record = Record(), accountScope: String = "a".repeat(64),
        credentialRecord: Record = Record(), retainTunDescriptor: Boolean = false, test: (Fixture) -> Unit) {
        val selection = RuntimeSelectionV1("latest", BuildConfig.RUNTIME_VERSION, BuildConfig.RUNTIME_VERSION,
            7L, null, "tile-test")
        val brokerReply = JSONObject(RuntimeSelectionStore.encode(selection)).put("vpn_authorization",
            JSONObject().put("scope", accountScope).put("blocked", false))
        RuntimeProcessSelection.rememberVpnOwner(RuntimeSelectionStore.decode(brokerReply.toString()))
        try {
            withRuntime(record, credentialRecord, retainTunDescriptor) { fixture ->
                fixture.service.onCreate()
                test(fixture)
            }
        } finally {
            RuntimeProcessSelection.clearVpnOwner()
        }
    }

    private fun withRuntime(record: Record = Record(), credentialRecord: Record = Record(), retainTunDescriptor: Boolean = false, test: (Fixture) -> Unit) {
        val controller = Robolectric.buildService(VpnService::class.java).create()
        val host = controller.get()
        if (retainTunDescriptor) OwnershipBuilder.directory = host.cacheDir
        val store = AndroidRecoveryStore(record, BootIdentityProvider { 1 }) { record.storeTime ?: (System.currentTimeMillis() - 2_000) }
        val coordinator = AndroidConnectionIntentCoordinator(store)
        val service = NelomaiVpnService(object : RuntimeVpnHostV1 {
            override val service = host
            override fun builder(beforeEstablish: (VpnService.Builder) -> Unit) = host.Builder().also(beforeEstablish)
        }, retainTunDescriptor)
        val saved = mutableListOf<() -> Unit>()
        fun field(target: Any, name: String, value: Any?) {
            val old = ReflectionHelpers.getField<Any?>(target, name)
            val raw = target.javaClass.getDeclaredField(name).apply { isAccessible = true }
            // Kotlin object vals are static final on Java 17. Replace only fixture
            // scheduling/state fields, without shadowing runtime execution.
            fun set(replacement: Any?) {
                if (java.lang.reflect.Modifier.isStatic(raw.modifiers) && java.lang.reflect.Modifier.isFinal(raw.modifiers)) {
                    val type = Class.forName("sun.misc.Unsafe")
                    val unsafe = type.getDeclaredField("theUnsafe").apply { isAccessible = true }.get(null)
                    val base = type.getMethod("staticFieldBase", java.lang.reflect.Field::class.java).invoke(unsafe, raw)
                    val offset = type.getMethod("staticFieldOffset", java.lang.reflect.Field::class.java).invoke(unsafe, raw)
                    type.getMethod("putObject", Any::class.java, java.lang.Long.TYPE, Any::class.java)
                        .invoke(unsafe, base, offset, replacement)
                } else raw.set(target, replacement)
            }
            set(value)
            saved += { set(old) }
        }
        fun static(type: Class<*>, name: String, value: Any?) {
            val old = ReflectionHelpers.getStaticField<Any?>(type, name)
            saved += { ReflectionHelpers.setStaticField(type, name, old) }
            ReflectionHelpers.setStaticField(type, name, value)
        }
        val work = Work()
        val credentialsWork = Work()
        val backgroundWork = Work()
        val lookupWork = Work()
        val timers = DormantTimers()
        try {
            CompletionNative.events.clear(); CompletionNative.onUp = {}; CompletionNative.failNextUp = false
            org.robolectric.shadows.ShadowVpnService.setPrepareResult(null)
            field(AndroidRecoveryStores, "instance", store)
            field(AndroidBackgroundCredentialStores, "instance", BackgroundCredentialStore(credentialRecord))
            field(service, "recoveryStore", store)
            field(service, "connectionIntentCoordinator", coordinator)
            field(service, "connectionIntentLifecycle", ConnectionIntentServiceLifecycle(coordinator, schedule = {}))
            field(service, "connectionIntentAttemptDispatcher", AndroidConnectionIntentAttemptDispatcher(
                execute = {}, persistedDelayMillis = { 0L }, scheduleAfter = {}, attempt = {}))
            field(service, "credentialExecutor", credentialsWork)
            field(service, "backgroundLogoutLifecycle", BackgroundLogoutServiceLifecycle(
                logoutState = { BackgroundLogoutReadState.NONE }, recovery = store::read,
                beginRedundantStop = { error("unexpected logout") }, runLogout = {}, scheduleRetry = {}, stopIfIdle = {}))
            val serviceGeneration = ReflectionHelpers.getField<Long>(service, "serviceGeneration")
            field(service, "redundantWork", RedundantVpnWorkDispatcher(lookupWork))
            field(service, "redundantTotalLossLifecycle", RedundantTotalLossLifecycle(
                currentServiceGeneration = { serviceGeneration }, serviceActive = { false }, barrierPending = { false },
                logoutState = { BackgroundLogoutReadState.NONE }, recovery = store::read, post = { it() },
                retryCleanup = {}, publishRestartStarting = {}, resume = {}, scheduleLogout = {},
                scheduleStateReadRetry = {}, stopIfIdle = {}))
            static(NelomaiVpnService::class.java, "activeService", service)
            static(NelomaiVpnService::class.java, "serviceReady", CompletableFuture.completedFuture(Unit))
            val oldFuture = ReflectionHelpers.getStaticField<Any>(GoBackend::class.java, "vpnService")
            val future = oldFuture.javaClass.getDeclaredConstructor().apply { isAccessible = true }.newInstance()
            future.javaClass.getDeclaredMethod("complete", Any::class.java).apply { isAccessible = true }.invoke(future, service)
            static(GoBackend::class.java, "vpnService", future)
            field(TunnelRuntime, "executor", work)
            field(TunnelRuntime, "backgroundExecutor", backgroundWork)
            field(TunnelRuntime, "backgroundOperationGate", BackgroundOperationGate())
            field(TunnelRuntime, "watchdogExecutor", timers)
            // The JVM can inline a static final reference. Reset the gate itself so
            // compiled state() and the native callbacks observe the same object.
            val stateGate = ReflectionHelpers.getField<TunnelStateGate>(TunnelRuntime, "stateGate")
            field(stateGate, "state", ReflectionHelpers.getField<Any>(TunnelStateGate(), "state"))
            field(stateGate, "revision", 0L)
            field(TunnelRuntime, "activeSession", null)
            field(TunnelRuntime, "applicationContext", host.applicationContext)
            val backend = GoBackend(host.applicationContext)
            field(TunnelRuntime, "backend", backend)
            val tunnel = ReflectionHelpers.getField<Tunnel>(TunnelRuntime, "tunnel")
            try { test(Fixture(host.applicationContext, service, store, coordinator, backend, tunnel,
                work, credentialsWork, backgroundWork, lookupWork, record, timers)) }
            finally {
                shadowOf(Looper.getMainLooper()).idle()
                ReflectionHelpers.callInstanceMethod<Unit>(TunnelRuntime, "clearActiveSession")
                backend.setState(tunnel, Tunnel.State.DOWN, null)
                ReflectionHelpers.getField<ServiceTunRetention>(service, "tunRetention").stop(permanent = true)
            }
        } finally {
            saved.asReversed().forEach { it() }
            CompletionNative.onUp = {}
            CompletionNative.onDown = {}
            CompletionQuickPlan.template = null
            CompletionPanel.onCapabilities = null
            CompletionPanel.onStart = null
            CompletionPanel.stopped.clear()
            CompletionPanel.redundantStops.clear()
            CompletionPanel.redundantRecoveries.clear()
            timers.shutdownNow()
            controller.destroy()
        }
    }

    private class Fixture(val context: Context, val service: NelomaiVpnService,
        val store: AndroidRecoveryStore, val coordinator: AndroidConnectionIntentCoordinator,
        val backend: GoBackend, val tunnel: Tunnel, val work: Work,
        val credentialsWork: Work, val backgroundWork: Work, val lookupWork: Work, val record: Record, val timers: DormantTimers) {
        fun envelope() = (store.read() as RecoveryStoreResult.Success).value
        fun beginHotStandby(startOperationId: String = java.util.UUID.randomUUID().toString()): AndroidRedundantTransaction {
            val transaction = AndroidRedundantTransaction(
                desiredActive = true,
                template = AndroidIntentTemplate("11111111-1111-4111-8111-111111111111", "account",
                    "stray", "dynamic", "standalone", "ipv4", true),
                sessionId = "22222222-2222-4222-8222-222222222222",
                slotALeaseId = "lease-a", slotBLeaseId = null, localActiveLeaseId = "lease-a",
                standbyDesired = true, roleGeneration = 1, membershipGeneration = 1,
                startOperationId = startOperationId, startRequestFingerprint = "fingerprint",
            )
            assertTrue(store.beginRedundant(transaction) is RecoveryStoreResult.Success)
            return transaction
        }

        fun preparePendingHotStandbyStop(): AndroidRedundantTransaction {
            val old = beginHotStandby()
            assertTrue(store.cancelRedundantIntentAndDeferStop("old-stop", old.startOperationId,
                retainActivePeer = true) is RecoveryStoreResult.Success)
            return requireNotNull(envelope().redundantTransaction)
        }

        fun completeOldStop(old: AndroidRedundantTransaction) {
            assertTrue(store.updateRedundant(old.startOperationId) {
                it.copy(retry = it.retry.copy(stopState = RedundantStopState.ACKNOWLEDGED))
            } is RecoveryStoreResult.Success)
            assertTrue(store.completeRedundantStop(requireNotNull(old.stopOperationId), old.startOperationId)
                is RecoveryStoreResult.Success)
        }

        fun firstTapAfterSystemStop(lastPublished: SessionState) {
            service.onStartCommand(offTileStartCommand(lastPublished), 0, 1)
        }

        fun recordSystemStop(lastPublished: SessionState, exitAt: Long = System.currentTimeMillis() - 1_000) {
            assertTrue(QuickTunnelController.updateState(context, lastPublished))
            // ExitInfo and the tap use wall time. Robolectric's paused looper
            // clock does not advance the JVM's System.currentTimeMillis().
            context.getSharedPreferences(AndroidRuntimeNamespace.record("nelomai-quick-tunnel-state"), Context.MODE_PRIVATE)
                .edit().putLong("state-updated-at-millis", exitAt - 1).commit()
            val exit = ShadowActivityManager.ApplicationExitInfoBuilder.newBuilder()
                .setPid(android.os.Process.myPid()).setProcessName(context.packageName + ":vpn")
                .setTimestamp(exitAt)
                .setReason(ApplicationExitInfo.REASON_USER_REQUESTED)
                .setDescription("[STOP APP] fully stop").build()
            shadowOf(context.getSystemService(ActivityManager::class.java)).addApplicationExitInfo(exit)
            ShadowSystemClock.advanceBy(Duration.ofSeconds(1))
            assertEquals("stopped", QuickTunnelController.state(context))
        }

        fun offTileStartCommand(lastPublished: SessionState): Intent {
            recordSystemStop(lastPublished)
            assertTrue(QuickTunnelController.requestToggle(context))
            return requireNotNull(shadowOf(context.applicationContext as Application).nextStartedService)
        }

        fun assertFreshQuickStart(sample: StartTunnelArgs) {
            var starts = 0
            CompletionPanel.onStart = {
                starts++
                assertNull("old Stop must complete before allocation", envelope().redundantTransaction)
                BackgroundStartResult(sample.configuration, sample.quickConnection!!, sample.options)
            }
            drainImmediateWork()
            assertEquals("fresh panel allocation from one tap", 1, starts)
            assertEquals(Tunnel.State.UP, backend.getState(tunnel))
            assertTrue(envelope().intent.desiredActive)
        }

        fun drainImmediateWork() {
            // Workers are deterministic; draining only immediate callbacks leaves timers paused.
            for (step in 1..24) {
                shadowOf(Looper.getMainLooper()).idle()
                val next = listOf(lookupWork, credentialsWork, backgroundWork, work)
                    .firstOrNull { it.jobs.isNotEmpty() } ?: return
                next.runNext()
            }
            fail("service work did not settle")
        }

        fun beginReplacement(): AndroidRecoveryEnvelope {
            assertTrue(coordinator.begin(AndroidIntentTemplate(
                "11111111-1111-4111-8111-111111111111", "scope",
                "tic", "dynamic", "standalone", "ipv4", false,
            )) is AndroidCoordinatorResult.Accepted)
            return envelope()
        }
        fun prepareQuick(): StartTunnelArgs {
            val sample = args()
            CompletionQuickPlan.template = QuickTunnelTemplate(sample.options, sample.quickConnection!!)
            val credential = AndroidBackgroundCredentialStores.open(context)
            assertTrue(credential.configure(0, BackgroundCredentialProvision(
                "11111111-1111-4111-8111-111111111111", "https://panel.example.test/",
                "fixture-token", Long.MAX_VALUE, "fixture-secret", 1, CompletionPanel.capability,
            )) is CredentialStoreResult.Success)
            return sample
        }
        fun armCheckpoint() {
            store.beginStart(0, AndroidIntentTemplate("11111111-1111-4111-8111-111111111111",
                "scope", "tic", "dynamic", "standalone", "ipv4", false), AndroidStartReplay("initial", 1, "fp"))
            store.recordLease(envelope().intent.generation, "lease")
            store.activateCheckpoint(envelope().intent.generation)
        }
        fun stopLegacyService(receiver: ResultReceiver) {
            ReflectionHelpers.callInstanceMethod<Unit>(service, "beginLegacyClientStop",
                ReflectionHelpers.ClassParameter.from(Int::class.javaPrimitiveType!!, TUNNEL_API_VERSION),
                ReflectionHelpers.ClassParameter.from(ResultReceiver::class.java, receiver),
                ReflectionHelpers.ClassParameter.from(Boolean::class.javaPrimitiveType!!, true),
                ReflectionHelpers.ClassParameter.from(String::class.java, null),
                ReflectionHelpers.ClassParameter.from(String::class.java, null))
        }
        fun stopFromUi() {
            ReflectionHelpers.callInstanceMethod<Unit>(service, "handleCancelCurrentConnectionIntent",
                ReflectionHelpers.ClassParameter.from(Intent::class.java,
                    Intent("ru.nelomai.tunnel.CANCEL_CURRENT_CONNECTION_INTENT")))
        }
        fun quickToggle(stopOnly: Boolean, receiver: ResultReceiver? = null) {
            val dispatch = ReflectionHelpers.getField<AndroidConnectionIntentDispatchState>(
                service, "connectionIntentDispatch")
            ReflectionHelpers.callInstanceMethod<Unit>(service, "applyBackgroundToggleResult",
                ReflectionHelpers.ClassParameter.from(RecoveryStoreResult::class.java,
                    coordinator.quickToggle(dispatch, stopOnly)),
                ReflectionHelpers.ClassParameter.from(ResultReceiver::class.java, receiver),
                ReflectionHelpers.ClassParameter.from(AndroidPendingQuickStart::class.java, null))
        }
        fun cancelClientStart(operationId: String) {
            ReflectionHelpers.callInstanceMethod<Unit>(service, "handleCancelClientStart",
                ReflectionHelpers.ClassParameter.from(Intent::class.java,
                    Intent("ru.nelomai.tunnel.CANCEL_CLIENT_START")
                        .putExtra(EXTRA_CLIENT_OPERATION_ID, operationId)))
        }
        fun startService(receiver: ResultReceiver, source: String = "local_restart",
            operationId: String = java.util.UUID.randomUUID().toString()) {
            val args = args()
            ReflectionHelpers.callInstanceMethod<Unit>(service, "handleClientStart",
                ReflectionHelpers.ClassParameter.from(Intent::class.java,
                    Intent(NelomaiVpnService.ACTION_CLIENT_START)
                        .putExtra(EXTRA_API_VERSION, TUNNEL_API_VERSION)
                        .putExtra(EXTRA_CLIENT_OPERATION_ID, operationId)
                        .putExtra(EXTRA_CONFIGURATION, args.configuration)
                        .putExtra(EXTRA_START_SOURCE, source)
                        .putExtra(EXTRA_OPTIONS, args.options.toBundle())
                        .putExtra(EXTRA_QUICK_CONNECTION, args.quickConnection!!.toBundle())
                        .putExtra(EXTRA_RESULT_RECEIVER, receiver)))
        }
    }
    private class Receiver(val receive: (Int, Bundle?) -> Unit) : ResultReceiver(null) {
        override fun onReceiveResult(resultCode: Int, resultData: Bundle?) = receive(resultCode, resultData)
    }
    private class Record : EncryptedRecordBackend {
        private var bytes: ByteArray? = null
        var storeTime: Long? = null
        var failNextRead = false
        var readFails = false
        var writeFails = false
        var onCommit: ((ByteArray) -> Unit)? = null
        override fun read(): ByteArray? {
            if (failNextRead) {
                failNextRead = false
                error("temporary read failure")
            }
            check(!readFails)
            return bytes?.copyOf()
        }
        override fun write(plaintext: ByteArray): Boolean {
            if (writeFails) return false
            bytes = plaintext.copyOf()
            onCommit?.invoke(plaintext)
            return true
        }
    }
    private class Work : AbstractExecutorService() {
        val jobs = ArrayDeque<Runnable>()
        var runImmediately = false
        override fun execute(command: Runnable) {
            if (runImmediately) command.run() else jobs.addLast(command)
        }
        fun runNext() {
            assertTrue("native worker must be queued", jobs.isNotEmpty())
            try { jobs.removeFirst().run() } catch (error: Throwable) {
                throw AssertionError(org.robolectric.shadows.ShadowLog.getLogs().joinToString("\n") { it.msg }, error)
            }
        }
        override fun shutdown() = Unit
        override fun shutdownNow(): MutableList<Runnable> = mutableListOf()
        override fun isShutdown() = false
        override fun isTerminated() = false
        override fun awaitTermination(timeout: Long, unit: TimeUnit) = false
    }
    private class DormantTimers : ScheduledThreadPoolExecutor(1) {
        val scheduled = mutableListOf<Pair<Runnable, Long>>()
        override fun schedule(command: Runnable, delay: Long, unit: TimeUnit): ScheduledFuture<*> {
            scheduled += command to unit.toMillis(delay)
            return DormantFuture()
        }
        override fun scheduleAtFixedRate(command: Runnable, delay: Long, period: Long, unit: TimeUnit): ScheduledFuture<*> = DormantFuture()
    }
    private class DormantFuture : ScheduledFuture<Unit> {
        override fun getDelay(unit: TimeUnit) = Long.MAX_VALUE
        override fun compareTo(other: Delayed) = 0
        override fun cancel(mayInterruptIfRunning: Boolean) = true
        override fun isCancelled() = true
        override fun isDone() = true
        override fun get() = Unit
        override fun get(timeout: Long, unit: TimeUnit) = Unit
    }
    companion object {
        private fun args() = StartTunnelArgs().apply {
            clientOperationId = "40000000-0000-4000-8000-000000000001"
            apiVersion = TUNNEL_API_VERSION; startSource = "local_restart"
            configuration = ("[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n" +
                "Address = 10.241.0.3/32\n").toByteArray()
            quickConnection = QuickConnectionArgs().apply {
                leaseId = "lease"; layer = "tic"; ticConnectionMode = "dynamic"; routeMode = "standalone"
                allowAlternate = false
            }
        }
    }
}

@Implements(QuickTunnelPlanStore::class)
internal class CompletionQuickPlan {
    @Implementation fun loadTemplate(context: Context): QuickTunnelTemplate? = template
    companion object { internal var template: QuickTunnelTemplate? = null }
}

@Implements(BackgroundConnectionClient::class)
internal class CompletionPanel {
    @Implementation fun capabilities(credential: BackgroundCredential) = onCapabilities?.invoke() ?: capability
    @Implementation fun start(
        context: Context, credential: BackgroundCredential, template: QuickTunnelTemplate,
    ): BackgroundStartResult = requireNotNull(onStart)()
    @Implementation fun stop(
        credential: BackgroundCredential, leaseId: String, operationId: String, failureCode: String?,
    ) { stopped += leaseId }
    @Implementation fun recoverRedundant(
        credential: BackgroundCredential, transaction: AndroidRedundantTransaction,
    ): BackgroundRedundantRecoveryTransport {
        redundantRecoveries += transaction.startOperationId
        throw java.io.IOException("panel recovery unavailable")
    }
    @Implementation fun stopRedundant(
        credential: BackgroundCredential, transaction: AndroidRedundantTransaction, leaseId: String,
    ): JSONObject {
        redundantStops += transaction
        return JSONObject().put("connection", JSONObject().put("lease_id", leaseId)
            .put("status", "released").put("session_id", JSONObject.NULL))
    }
    companion object {
        internal var onCapabilities: (() -> BackgroundCapabilitySnapshot)? = null
        internal val capability = BackgroundCapabilitySnapshot(1, false, Long.MAX_VALUE)
        internal var onStart: (() -> BackgroundStartResult)? = null
        val stopped = mutableListOf<String>()
        val redundantStops = mutableListOf<AndroidRedundantTransaction>()
        val redundantRecoveries = mutableListOf<String>()
    }
}

@Implements(SharedLibraryLoader::class)
class CompletionNoLibrary {
    companion object {
        @JvmStatic @Implementation fun loadSharedLibrary(context: Context, name: String) = Unit
    }
}
@Implements(org.amnezia.awg.GoBackend::class)
class CompletionNative {
    companion object {
        val events = mutableListOf<String>()
        var onUp: () -> Unit = {}
        var onDown: () -> Unit = {}
        var failNextUp = false
        @JvmStatic @Implementation fun awgVersion() = "test-jni"
        @JvmStatic @Implementation fun awgTurnOn(name: String, fd: Int, config: String): Int {
            if (failNextUp) { failNextUp = false; events += "up-failed"; return -1 }
            events += "up"; onUp(); return 41
        }
        @JvmStatic @Implementation fun awgTurnOff(handle: Int) {
            onDown()
            events += "down"
        }
        @JvmStatic @Implementation fun awgPreparedSocketToken(handle: Int) = 1L
        @JvmStatic @Implementation fun awgAdmitSockets(handle: Int, token: Long) = 0
        @JvmStatic @Implementation fun awgGetSocketV4(handle: Int) = 101
        @JvmStatic @Implementation fun awgGetSocketV6(handle: Int) = -1
        @JvmStatic @Implementation fun awgGetConfig(handle: Int) = "last_handshake_time_sec=1\n"
    }
}
@Implements(VpnService::class)
class CompletionVpnPermission : org.robolectric.shadows.ShadowVpnService() {
    @Implementation fun protect(socket: Int) = true
    @Implementation fun setUnderlyingNetworks(networks: Array<android.net.Network>?) = true
}
@Implements(VpnService.Builder::class)
class CompletionVpnBuilder {
    @org.robolectric.annotation.RealObject private lateinit var builder: VpnService.Builder
    // Package verification normally crosses Android's package-manager Binder.
    @Implementation fun addDisallowedApplication(packageName: String): VpnService.Builder = builder
    @Implementation fun establish(): ParcelFileDescriptor {
        val pipe = ParcelFileDescriptor.createPipe()
        pipe[1].close()
        return pipe[0]
    }
}
@Implements(ParcelFileDescriptor::class)
class CompletionFileDescriptor : org.robolectric.shadows.ShadowParcelFileDescriptor() {
    @Implementation fun detachFd() = 7
}

@Implements(ServiceRedundantConnectionNative::class)
internal class ConfirmedStandbyTransport {
    @Implementation fun start(leaseId: String, slot: RedundantSlot, configuration: ByteArray,
        healthProbe: BackgroundRedundantHealthProbe?): Boolean = true
    @Implementation fun activate(leaseId: String): Boolean = true
    @Implementation fun isUsable(leaseId: String): Boolean = true
    @Implementation fun confirmTunReady(): Boolean = true
    @Implementation fun healthObservations(initialReadiness: Boolean, committedStandbyLeaseId: String?,
        freshStart: Boolean, startupStandbyRetryDeadlineMs: Long?) = listOf(
        SlotObservation(0, true, BackendHealth.READY, handshakeFresh = true, consecutiveProbeSuccesses = 2,
            successfulProbeValidThroughElapsedMs = Long.MAX_VALUE),
        SlotObservation(1, false, BackendHealth.READY, handshakeFresh = true, consecutiveProbeSuccesses = 2,
            standbyProbeState = StandbyProbeState.SUCCEEDED, successfulProbeValidThroughElapsedMs = Long.MAX_VALUE),
    )
}

@Implements(PhysicalNetworks::class)
internal class StandbyPhysicalNetwork {
    @Implementation fun snapshotState() = PhysicalNetworkState(emptyList(),
        listOf(org.robolectric.shadows.ShadowNetwork.newInstance(1)), true, "test")
}

@Implements(ActivityManager::class)
class CompletionExitHistory : ShadowActivityManager() {
    @Implementation
    override fun getHistoricalProcessExitReasons(packageName: String?, pid: Int, maxNum: Int): MutableList<*> {
        check(!unavailable) { "history unavailable while the start is queued" }
        return super.getHistoricalProcessExitReasons(packageName, pid, maxNum)
    }

    companion object { var unavailable = false }
}

@Implements(AutomaticDiagnostics::class)
class DeferredFailureDiagnostics {
    @Implementation
    fun onConnectionStartFailed(context: Context, deviceId: String, errorCode: String, onComplete: (Throwable?) -> Unit) {
        finish = onComplete
    }

    companion object { var finish: ((Throwable?) -> Unit)? = null }
}

@Implements(RuntimeSelectionStore::class)
class StatusBrokerSelection {
    @Implementation fun read(callback: (Result<RuntimeSelectionV1>) -> Unit) {
        callback(Result.success(requireNotNull(RuntimeProcessSelection.vpnOwnerForStop())))
    }
}
