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
    shadows = [RedundantDiagnosticsNoLibrary::class, RedundantDiagnosticsDirectorySync::class, RedundantDiagnosticsActivityManager::class])
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

    @Test fun readyFromAnotherProcessCannotReusePreviousInterval() = fixture { f ->
        val owner = f.owner()
        assertTrue(owner.start(f.tx, configs())); f.idle()
        val oldId = f.session()
        val previousPid = android.os.Process.myPid()
        try {
            org.robolectric.shadows.ShadowProcess.setPid(previousPid + 1)
            f.publish(owner); f.idle()
            assertNotEquals(oldId, f.session())
            assertTrue(f.running())
            assertEquals(listOf("tunnel_interrupted"), f.reports().map { it.getString("trigger") })
        } finally { org.robolectric.shadows.ShadowProcess.setPid(previousPid) }
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
            stableSinceMs = 0))))
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
        repeat(3) {
            val before = slot.snapshot()
            f.duringRecoveryRead({ slot.install(owner, f.tx.startOperationId, RedundantVpnRouteBaseline(listOf("192.168.1.0/24"))) }) {
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
        f.duringRecoveryRead({ slot.install(owner, f.tx.startOperationId, RedundantVpnRouteBaseline(listOf("192.168.1.0/24"))) }) { f.memorySample() }
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

    private class Fixture(val context: Context, val service: NelomaiVpnService,
        val store: AndroidRecoveryStore, val memorySample: () -> Unit,
        val failRecoveryReads: (Boolean) -> Unit) {
        val tx = AndroidRedundantTransaction(true,
            AndroidIntentTemplate("11111111-1111-4111-8111-111111111111", "account",
                "stray", "dynamic", "standalone", "ipv4", true),
            "22222222-2222-4222-8222-222222222222", "lease-a", "lease-b", "lease-a",
            true, 1, 1, "start", "fingerprint")
        val prefs = context.getSharedPreferences(AndroidRuntimeNamespace.record("nelomai-automatic-diagnostics"), 0)
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
            val pending = pendingType.declaredConstructors.single().apply { isAccessible = true }
                .newInstance(operation, tombstone, owner, generation, true, false)
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
        fun owner(usable: Boolean = true): RedundantConnectionCoordinator {
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
                override fun stop() = true
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
                override fun stop(transaction: AndroidRedundantTransaction) = true
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

@org.robolectric.annotation.Implements(org.amnezia.awg.util.SharedLibraryLoader::class)
class RedundantDiagnosticsNoLibrary {
    companion object {
        @JvmStatic @org.robolectric.annotation.Implementation
        fun loadSharedLibrary(context: Context, name: String) = Unit
    }
}
@org.robolectric.annotation.Implements(android.app.ActivityManager::class)
class RedundantDiagnosticsActivityManager : org.robolectric.shadows.ShadowActivityManager() {
    @org.robolectric.annotation.Implementation
    fun getProcessMemoryInfo(pids: IntArray): Array<android.os.Debug.MemoryInfo> =
        Array(pids.size) { android.os.Debug.MemoryInfo() }
}
// Robolectric cannot fsync directories; report files, compression and preferences remain real.
@org.robolectric.annotation.Implements(android.system.Os::class)
@Suppress("UNUSED_PARAMETER")
class RedundantDiagnosticsDirectorySync {
    companion object {
        @JvmStatic @org.robolectric.annotation.Implementation
        fun open(path: String, flags: Int, mode: Int): java.io.FileDescriptor {
            assertTrue(File(path).isDirectory)
            return java.io.FileDescriptor()
        }
        @JvmStatic @org.robolectric.annotation.Implementation fun fsync(fd: java.io.FileDescriptor) = Unit
        @JvmStatic @org.robolectric.annotation.Implementation fun close(fd: java.io.FileDescriptor) = Unit
        @JvmStatic @org.robolectric.annotation.Implementation fun rename(oldPath: String, newPath: String) {
            java.nio.file.Files.move(File(oldPath).toPath(), File(newPath).toPath(),
                java.nio.file.StandardCopyOption.REPLACE_EXISTING)
        }
    }
}
