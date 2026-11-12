package ru.nelomai.tunnel

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
import org.robolectric.util.ReflectionHelpers
import ru.nelomai.runtime.v1.RuntimeVpnHostV1
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

    @Test fun thrownLateCallbackRejectionClosesNativeBeforeError() = withRuntime { f ->
        var callbacks = 0
        TunnelRuntime.start(f.context, args(), { state, _ ->
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

    private fun withRuntime(test: (Fixture) -> Unit) {
        val controller = Robolectric.buildService(VpnService::class.java).create()
        val host = controller.get()
        val record = Record()
        val store = AndroidRecoveryStore(record, BootIdentityProvider { 1 })
        val coordinator = AndroidConnectionIntentCoordinator(store)
        val service = NelomaiVpnService(object : RuntimeVpnHostV1 {
            override val service = host
            override fun builder(beforeEstablish: (VpnService.Builder) -> Unit) = host.Builder().also(beforeEstablish)
        })
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
            field(AndroidBackgroundCredentialStores, "instance", BackgroundCredentialStore(Record()))
            field(service, "recoveryStore", store)
            field(service, "connectionIntentCoordinator", coordinator)
            field(service, "connectionIntentLifecycle", ConnectionIntentServiceLifecycle(coordinator, schedule = {}))
            field(service, "connectionIntentAttemptDispatcher", AndroidConnectionIntentAttemptDispatcher(
                execute = {}, persistedDelayMillis = { 0L }, scheduleAfter = {}, attempt = {}))
            field(service, "credentialExecutor", credentialsWork)
            field(service, "backgroundLogoutLifecycle", BackgroundLogoutServiceLifecycle(
                logoutState = { BackgroundLogoutReadState.NONE }, recovery = store::read,
                beginRedundantStop = { error("unexpected logout") }, runLogout = {}, scheduleRetry = {}, stopIfIdle = {}))
            field(service, "redundantWork", RedundantVpnWorkDispatcher(lookupWork))
            field(service, "redundantTotalLossLifecycle", RedundantTotalLossLifecycle(
                currentServiceGeneration = { 0L }, serviceActive = { false }, barrierPending = { false },
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
            field(TunnelRuntime, "stateGate", TunnelStateGate())
            field(TunnelRuntime, "activeSession", null)
            field(TunnelRuntime, "applicationContext", host.applicationContext)
            val backend = GoBackend(host.applicationContext)
            field(TunnelRuntime, "backend", backend)
            val tunnel = ReflectionHelpers.getField<Tunnel>(TunnelRuntime, "tunnel")
            try { test(Fixture(host.applicationContext, service, store, coordinator, backend, tunnel,
                work, credentialsWork, backgroundWork, lookupWork, record)) }
            finally {
                shadowOf(Looper.getMainLooper()).idle()
                ReflectionHelpers.callInstanceMethod<Unit>(TunnelRuntime, "clearActiveSession")
                backend.setState(tunnel, Tunnel.State.DOWN, null)
            }
        } finally {
            saved.asReversed().forEach { it() }
            CompletionNative.onUp = {}
            CompletionQuickPlan.template = null
            CompletionPanel.onStart = null
            CompletionPanel.stopped.clear()
            timers.shutdownNow()
            controller.destroy()
        }
    }

    private class Fixture(val context: Context, val service: NelomaiVpnService,
        val store: AndroidRecoveryStore, val coordinator: AndroidConnectionIntentCoordinator,
        val backend: GoBackend, val tunnel: Tunnel, val work: Work,
        val credentialsWork: Work, val backgroundWork: Work, val lookupWork: Work, val record: Record) {
        fun envelope() = (store.read() as RecoveryStoreResult.Success).value
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
                ReflectionHelpers.ClassParameter.from(ResultReceiver::class.java, receiver))
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
                ReflectionHelpers.ClassParameter.from(ResultReceiver::class.java, receiver))
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
        var readFails = false
        override fun read(): ByteArray? {
            check(!readFails)
            return bytes?.copyOf()
        }
        override fun write(plaintext: ByteArray): Boolean { bytes = plaintext.copyOf(); return true }
    }
    private class Work : AbstractExecutorService() {
        val jobs = ArrayDeque<Runnable>()
        override fun execute(command: Runnable) { jobs.addLast(command) }
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
        override fun schedule(command: Runnable, delay: Long, unit: TimeUnit): ScheduledFuture<*> = DormantFuture()
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
    @Implementation fun capabilities(credential: BackgroundCredential) = capability
    @Implementation fun start(
        context: Context, credential: BackgroundCredential, template: QuickTunnelTemplate,
    ): BackgroundStartResult = requireNotNull(onStart)()
    @Implementation fun stop(
        credential: BackgroundCredential, leaseId: String, operationId: String, failureCode: String?,
    ) { stopped += leaseId }
    companion object {
        internal val capability = BackgroundCapabilitySnapshot(1, false, Long.MAX_VALUE)
        internal var onStart: (() -> BackgroundStartResult)? = null
        val stopped = mutableListOf<String>()
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
        var failNextUp = false
        @JvmStatic @Implementation fun awgVersion() = "test-jni"
        @JvmStatic @Implementation fun awgTurnOn(name: String, fd: Int, config: String): Int {
            if (failNextUp) { failNextUp = false; events += "up-failed"; return -1 }
            events += "up"; onUp(); return 41
        }
        @JvmStatic @Implementation fun awgTurnOff(handle: Int) { events += "down" }
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
