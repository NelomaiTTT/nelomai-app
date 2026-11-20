package ru.nelomai.client

import android.app.Application
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Handler
import android.os.Message
import android.os.Messenger
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.ResultReceiver
import java.time.Duration
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements
import org.robolectric.shadows.ShadowProcess
import org.robolectric.shadows.ShadowPausedSystemClock
import org.robolectric.shadows.ShadowVpnService
import org.robolectric.util.ReflectionHelpers
import ru.nelomai.runtime.v1.RuntimeQuickActionsV1
import ru.nelomai.runtime.v1.RuntimeServiceIntents
import ru.nelomai.runtime.v1.RuntimeVpnAuthorityV1
import ru.nelomai.runtime.v1.RuntimeVpnEngineV1
import ru.nelomai.runtime.v1.RuntimeVpnHostV1
import ru.nelomai.runtime.v1.RuntimeVpnTransportV1

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class, shadows = [
    BrokerRecoverySelectionShadow::class, BrokerRecoveryAdaptersShadow::class,
    BrokerRecoveryBuilderShadow::class, LoggingTileServiceShadow::class,
])
class RuntimeVpnBrokerRecoveryTest {
    private fun selection(
        incarnation: String,
        generation: Long = 7,
        scope: String? = "a".repeat(64),
        blocked: Boolean = false,
        logoutEpoch: Long? = null,
        slot: String = "latest",
        pendingSlot: String? = null,
        runtimeVersion: String = "0.3.14",
        containerVersion: String = "0.3.14",
    ): RuntimeSelectionV1 = RuntimeSelectionStore.decode(
        JSONObject(RuntimeSelectionStore.encode(
            RuntimeSelectionV1(slot, runtimeVersion, containerVersion, generation, pendingSlot, incarnation),
        )).put("vpn_authorization", JSONObject().put("scope", scope ?: JSONObject.NULL)
            .put("blocked", blocked).put("logout_epoch", logoutEpoch ?: JSONObject.NULL)).toString(),
    )

    private val original = selection("old-broker")

    @Before fun setup() {
        ReflectionHelpers.setStaticField(RuntimeProcessSelection::class.java, "loaded", null)
        ShadowVpnService.setPrepareResult(null)
        BrokerRecoverySelectionShadow.selected = original
        BrokerRecoverySelectionShadow.unavailable = false
        BrokerRecoverySelectionShadow.pending = null
        BrokerRecoveryAdaptersShadow.destroyed = 0
        BrokerRecoveryAdaptersShadow.established = 0
        BrokerRecoveryAdaptersShadow.actions.clear()
        BrokerRecoveryAdaptersShadow.startIds.clear()
        BrokerRecoveryAdaptersShadow.rejectedStartIds.clear()
        BrokerRecoveryAdaptersShadow.revoked = 0
        BrokerRecoveryAdaptersShadow.logoutEpochs.clear()
        BrokerRecoveryAdaptersShadow.beforeEstablish = null
        BrokerRecoveryAdaptersShadow.logoutResult = null
        BrokerRecoveryAdaptersShadow.quickToggleWouldStart = false
        BrokerRecoveryAdaptersShadow.beforeSystemEstablish = null
        BrokerRecoveryAdaptersShadow.transportClosed = true
        BrokerRecoveryAdaptersShadow.onRevoke = null
    }

    private fun connectedService() =
        Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create().also {
            assertEquals(Service.START_STICKY, it.get().onStartCommand(
                RuntimeServiceIntents.foreground(Intent("ru.nelomai.tunnel.CLIENT_START")), 0, 1,
            ))
            assertEquals(1, BrokerRecoveryAdaptersShadow.established)
        }

    private fun reconcileNewOwner() {
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(1))
    }

    private fun advanceWatchdog(service: RuntimeVpnDispatcherService, seconds: Long) {
        val watchdog = ReflectionHelpers.getField<Handler>(service, "vpnWatchdog")
        try {
            shadowOf(watchdog.looper).idleFor(Duration.ofSeconds(seconds))
        } catch (error: IllegalStateException) {
            // The simulated kill returns and the watchdog quits its Looper.
            val looperExited = error.message == "Looper is quitting" ||
                error.message.orEmpty().endsWith("failed. Is handler thread dead?")
            if (!looperExited || !ShadowProcess.wasKilled(Process.myPid())) throw error
        }
    }

    private fun prepareWatch(service: RuntimeVpnDispatcherService, owner: String): List<Int> {
        val replies = mutableListOf<Int>()
        val request = Message.obtain().apply {
            data.putString(RuntimeServiceIntents.TASK_REMOVAL_RUNTIME, owner)
            replyTo = Messenger(Handler(Looper.getMainLooper()) { replies.add(it.what); true })
        }
        Messenger(service.onBind(Intent(RuntimeServiceIntents.TASK_REMOVAL_LIVENESS))).send(request)
        shadowOf(Looper.getMainLooper()).idle()
        return replies
    }

    @Test fun jobRetriesWhenColdEngineCannotReadStopStateAndDoesNotTakeOwnership() {
        val ctrl = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        try {
            val service = ctrl.get()
            val app = shadowOf(RuntimeEnvironment.getApplication())
            val watch = RuntimeSelectionStore.encodeVpnRecoveryOwner(original)
            BrokerRecoveryAdaptersShadow.watchResult = Service.START_NOT_STICKY
            val failed = prepareWatch(service, watch)
            service.onStartCommand(requireNotNull(app.nextStartedService), 0, 1)
            shadowOf(Looper.getMainLooper()).idle()
            assertEquals(listOf(RuntimeServiceIntents.TASK_REMOVAL_RETRY), failed)
            BrokerRecoveryAdaptersShadow.watchResult = Service.START_STICKY
            val retried = prepareWatch(service, watch)
            service.onStartCommand(requireNotNull(app.nextStartedService), 0, 2)
            shadowOf(Looper.getMainLooper()).idle()
            assertEquals(listOf(RuntimeServiceIntents.TASK_REMOVAL_ACCEPTED), retried)
        } finally {
            BrokerRecoveryAdaptersShadow.watchResult = Service.START_STICKY
            ctrl.destroy()
        }
    }

    @Test fun coldWatchRetriesSecondBrokerReadThenReachesEngineAfterBrokerRestart() {
        val service = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create().get()
        val context = RuntimeEnvironment.getApplication()
        val watch = RuntimeSelectionStore.encodeVpnRecoveryOwner(original)
        BrokerRecoverySelectionShadow.selected = selection("restarted-broker")
        val first = prepareWatch(service, watch)
        val command = requireNotNull(shadowOf(context).nextStartedService)
        assertTrue("job still owns the handoff", first.isEmpty())
        BrokerRecoverySelectionShadow.unavailable = true
        service.onStartCommand(command, 0, 10)
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals(listOf(RuntimeServiceIntents.TASK_REMOVAL_RETRY), first)
        assertTrue(BrokerRecoveryAdaptersShadow.actions.isEmpty())

        BrokerRecoverySelectionShadow.unavailable = false
        val retry = prepareWatch(service, watch)
        service.onStartCommand(requireNotNull(shadowOf(context).nextStartedService), 0, 11)
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals(listOf(RuntimeServiceIntents.TASK_REMOVAL_LIVENESS), BrokerRecoveryAdaptersShadow.actions)
        assertEquals(listOf(RuntimeServiceIntents.TASK_REMOVAL_ACCEPTED), retry)
    }

    @Test fun watchRechecksAuthorizationAtDelivery() {
        val service = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create().get()
        val context = RuntimeEnvironment.getApplication()
        val watch = RuntimeSelectionStore.encodeVpnRecoveryOwner(original)
        val rejected = listOf(
            selection("old-broker", scope = "b".repeat(64)),
            selection("old-broker", scope = null),
            selection("old-broker", generation = 8L),
            selection("old-broker", blocked = true, logoutEpoch = 8),
            selection("old-broker", slot = "stable"), selection("old-broker", pendingSlot = "stable"),
            selection("old-broker", runtimeVersion = "next"), selection("old-broker", containerVersion = "next"),
        )
        rejected.forEachIndexed { index, changed ->
            BrokerRecoverySelectionShadow.selected = original
            val replies = prepareWatch(service, watch)
            val command = requireNotNull(shadowOf(context).nextStartedService)
            BrokerRecoverySelectionShadow.selected = changed
            service.onStartCommand(command, 0, index + 1)
            shadowOf(Looper.getMainLooper()).idle()
            assertEquals(listOf(RuntimeServiceIntents.TASK_REMOVAL_REJECTED), replies)
            assertTrue(BrokerRecoveryAdaptersShadow.actions.isEmpty())
            assertEquals("a retry must refuse the changed selection before starting the service",
                listOf(RuntimeServiceIntents.TASK_REMOVAL_REJECTED), prepareWatch(service, watch))
            assertNull(shadowOf(context).nextStartedService)
        }
        BrokerRecoverySelectionShadow.selected = original
        assertEquals("old job has no proof of account scope", listOf(RuntimeServiceIntents.TASK_REMOVAL_REJECTED),
            prepareWatch(service, RuntimeSelectionStore.encode(original)))
        assertNull(shadowOf(context).nextStartedService)
    }

    @Test fun redeliveredWatchFromOldProcessCannotStopAColdStartWaitingOnBinder() =
        checkOrphanWatchDuringSelection(true)

    @Test fun redeliveredWatchDoesNotKeepARejectedColdStartAlive() =
        checkOrphanWatchDuringSelection(false)

    private fun checkOrphanWatchDuringSelection(allowStart: Boolean) {
        val old = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        prepareWatch(old.get(), RuntimeSelectionStore.encodeVpnRecoveryOwner(original))
        val replay = requireNotNull(shadowOf(RuntimeEnvironment.getApplication()).nextStartedService)
        old.destroy()
        val current = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        try {
            val service = current.get()
            val pending = mutableListOf<(Result<RuntimeSelectionV1>) -> Unit>()
            BrokerRecoverySelectionShadow.pending = pending
            val start = RuntimeServiceIntents.foreground(Intent("ru.nelomai.tunnel.CLIENT_START"))
            service.onStartCommand(start, 0, 1)
            val policy = service.onStartCommand(replay, Service.START_FLAG_RETRY, 2)
            assertNotEquals(2, shadowOf(service).stopSelfId)
            assertEquals(Service.START_STICKY, policy)
            if (allowStart) {
                pending.single().invoke(Result.success(original))
                assertEquals(listOf(2), BrokerRecoveryAdaptersShadow.startIds)
                assertEquals(listOf(start.action), BrokerRecoveryAdaptersShadow.actions)
            } else {
                pending.single().invoke(Result.failure(IllegalStateException("runtime_owner_unavailable")))
                assertEquals(2, shadowOf(service).stopSelfId)
                assertTrue(BrokerRecoveryAdaptersShadow.actions.isEmpty())
            }
        } finally {
            current.destroy()
        }
    }

    @Test fun olderBinderFailureCannotConsumeTheIdOfANewerPendingStart() {
        val controller = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        try {
            val service = controller.get()
            val pending = mutableListOf<(Result<RuntimeSelectionV1>) -> Unit>()
            BrokerRecoverySelectionShadow.pending = pending
            service.onStartCommand(Intent("ru.nelomai.tunnel.CLIENT_STATUS"), 0, 1)
            service.onStartCommand(RuntimeServiceIntents.foreground(Intent("ru.nelomai.tunnel.CLIENT_START")), 0, 2)
            val orphan = RuntimeServiceIntents.vpn(service).setAction(RuntimeServiceIntents.TASK_REMOVAL_LIVENESS)
            service.onStartCommand(orphan, Service.START_FLAG_RETRY, 3)
            pending[0](Result.failure(IllegalStateException("runtime_owner_unavailable")))
            assertEquals(1, shadowOf(service).stopSelfId)
            pending[1](Result.success(original))
            assertEquals(listOf(3), BrokerRecoveryAdaptersShadow.startIds)
            assertEquals(listOf("ru.nelomai.tunnel.CLIENT_START"), BrokerRecoveryAdaptersShadow.actions)
        } finally {
            controller.destroy()
        }
    }

    @Test fun replayDoesNotStartWorkInARunningEngineAndDoesNotProtectAnIdleColdService() {
        val context = RuntimeEnvironment.getApplication()
        val orphan = RuntimeServiceIntents.vpn(context).setAction(RuntimeServiceIntents.TASK_REMOVAL_LIVENESS)
        val cold = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        try {
            assertEquals(Service.START_NOT_STICKY, cold.get().onStartCommand(orphan, Service.START_FLAG_RETRY, 1))
            assertEquals(1, shadowOf(cold.get()).stopSelfId)
        } finally {
            cold.destroy()
        }
        val warm = connectedService()
        try {
            assertEquals(Service.START_STICKY, warm.get().onStartCommand(orphan, Service.START_FLAG_RETRY, 2))
            assertEquals(listOf(2), BrokerRecoveryAdaptersShadow.rejectedStartIds)
            assertEquals(listOf("ru.nelomai.tunnel.CLIENT_START"), BrokerRecoveryAdaptersShadow.actions)
            assertNotEquals(2, shadowOf(warm.get()).stopSelfId)
        } finally {
            warm.destroy()
        }
    }

    @Test fun explicitStopAfterPreparationRejectsTheWaitingWatch() {
        val service = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create().get()
        val replies = prepareWatch(service, RuntimeSelectionStore.encodeVpnRecoveryOwner(original))
        val command = requireNotNull(shadowOf(RuntimeEnvironment.getApplication()).nextStartedService)
        service.onStartCommand(Intent(RuntimeServiceIntents.CLIENT_STOP)
            .putExtra("api_version", RuntimeServiceIntents.VPN_API_VERSION), 0, 2)
        service.onStartCommand(command, 0, 3)
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals(listOf(RuntimeServiceIntents.CLIENT_STOP), BrokerRecoveryAdaptersShadow.actions)
        assertEquals(listOf(RuntimeServiceIntents.TASK_REMOVAL_REJECTED), replies)
    }

    @Test fun sameAuthorizedSessionRebindsWithoutDestroyingOrRecreatingTun() {
        val old = connectedService()
        BrokerRecoverySelectionShadow.selected = selection("new-broker")
        assertFalse(RuntimeProcessSelection.needsExit(BrokerRecoverySelectionShadow.selected))
        reconcileNewOwner()
        assertFalse(ShadowProcess.wasKilled(Process.myPid()))
        assertEquals(0, BrokerRecoveryAdaptersShadow.destroyed)
        assertEquals(1, BrokerRecoveryAdaptersShadow.established)
        old.destroy()
    }

    @Test fun changedSessionDoesNotPreserveTunnel() {
        val old = connectedService()
        BrokerRecoverySelectionShadow.selected = selection("new-broker", generation = 8L)
        reconcileNewOwner()
        assertEquals(1, BrokerRecoveryAdaptersShadow.revoked)
        assertFalse(ShadowProcess.wasKilled(Process.myPid()))
        old.destroy()
    }

    @Test fun changedAuthorizationInTheSameBrokerRetiresTheOldTunnel() {
        val old = connectedService()
        BrokerRecoverySelectionShadow.selected = selection("old-broker", scope = "b".repeat(64))
        reconcileNewOwner()
        assertEquals(1, BrokerRecoveryAdaptersShadow.revoked)
        old.get().onStartCommand(RuntimeServiceIntents.foreground(Intent("ru.nelomai.tunnel.CLIENT_START")), 0, 2)
        assertEquals(1, BrokerRecoveryAdaptersShadow.established)
        old.destroy()
    }

    @Test fun missingConfirmedScopeInTheSameBrokerRetiresTheOldTunnel() {
        val old = connectedService()
        BrokerRecoverySelectionShadow.selected = selection("old-broker", scope = null)
        reconcileNewOwner()
        assertEquals(1, BrokerRecoveryAdaptersShadow.revoked)
        old.destroy()
    }

    @Test fun statusReadDuringBrokerDeathLeavesRunningVpnAvailableForRecovery() {
        val old = connectedService()
        val vpn = old.get()
        BrokerRecoverySelectionShadow.unavailable = true
        vpn.onStartCommand(Intent("ru.nelomai.tunnel.CLIENT_STATUS"), 0, 2)
        assertNotEquals(2, shadowOf(vpn).stopSelfId)
        BrokerRecoverySelectionShadow.unavailable = false
        BrokerRecoverySelectionShadow.selected = selection("new-broker")
        reconcileNewOwner()
        assertFalse(ShadowProcess.wasKilled(Process.myPid()))
        assertEquals(0, BrokerRecoveryAdaptersShadow.destroyed)
        old.destroy()
    }

    @Test fun stopAndLogoutReachTheRunningEngineAfterRebinding() {
        val old = connectedService()
        BrokerRecoverySelectionShadow.selected = selection("new-broker")
        val commands = listOf("ru.nelomai.tunnel.CLIENT_STOP", "ru.nelomai.tunnel.BEGIN_BACKGROUND_LOGOUT")
        commands.forEachIndexed { index, action -> old.get().onStartCommand(Intent(action), 0, index + 2) }
        assertEquals(commands, BrokerRecoveryAdaptersShadow.actions.takeLast(2))
        assertFalse(ShadowProcess.wasKilled(Process.myPid()))
        old.destroy()
    }

    @Test fun stopReachesTheRunningEngineWhileTheBrokerIsUnavailable() {
        val old = connectedService()
        BrokerRecoverySelectionShadow.unavailable = true
        old.get().onStartCommand(Intent("ru.nelomai.tunnel.CLIENT_STOP"), 0, 2)
        assertEquals("ru.nelomai.tunnel.CLIENT_STOP", BrokerRecoveryAdaptersShadow.actions.last())
        old.destroy()
    }

    @Test fun lateStatusDoesNotRollBackTheStopStartId() {
        val old = connectedService()
        val pending = mutableListOf<(Result<RuntimeSelectionV1>) -> Unit>()
        BrokerRecoverySelectionShadow.pending = pending
        old.get().onStartCommand(Intent("ru.nelomai.tunnel.CLIENT_STATUS"), 0, 2)
        old.get().onStartCommand(Intent(RuntimeServiceIntents.CLIENT_STOP), 0, 3)
        pending.single().invoke(Result.success(original))
        assertEquals(listOf(1, 3, 3), BrokerRecoveryAdaptersShadow.startIds)
        old.destroy()
    }

    @Test fun preparedOffTileStartRechecksAccountAndSlotBeforeLoadingEngine() {
        val command = RuntimeServiceIntents.vpn(RuntimeEnvironment.getApplication())
            .setAction(RuntimeServiceIntents.QUICK_TOGGLE)
            .putExtra(RuntimeServiceIntents.EXTRA_QUICK_START_OWNER, RuntimeSelectionStore.encodeVpnRecoveryOwner(original))
        val controller = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        try {
            for (other in listOf(selection("new", scope = "b".repeat(64)), selection("stable", slot = "stable"))) {
                BrokerRecoverySelectionShadow.selected = other
                controller.get().onStartCommand(command, 0, 1)
                assertTrue(BrokerRecoveryAdaptersShadow.actions.isEmpty())
            }
            BrokerRecoverySelectionShadow.selected = original
            controller.get().onStartCommand(command, 0, 2)
            assertEquals(listOf(RuntimeServiceIntents.QUICK_TOGGLE), BrokerRecoveryAdaptersShadow.actions)
        } finally {
            controller.destroy()
        }
    }

    @Test fun stableRestartSupersedesTheEarlierTileStop() {
        val stable = selection("stable", slot = "stable", runtimeVersion = "0.2.21")
        BrokerRecoverySelectionShadow.selected = stable
        // The engine is a test adapter. Provisioning the pinned native library is covered on the emulator.
        ReflectionHelpers.setStaticField(RuntimeVpnDispatcherService::class.java, "engineWasLoaded", true)
        val ctrl = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        try {
            val vpn = ctrl.get()
            val start = Intent("ru.nelomai.runtime.stable.tunnel.CLIENT_START")
            val stop = Intent("ru.nelomai.runtime.stable.tunnel.CLIENT_STOP")
                .putExtra("api_version", RuntimeServiceIntents.VPN_API_VERSION)
            vpn.onStartCommand(start, 0, 1)
            val delayed = Intent(stop)
                .putExtra(RuntimeServiceIntents.EXTRA_TILE_CLICK_REVISION, RuntimeProcessSelection.vpnStartRevision)
                .putExtra(RuntimeServiceIntents.EXTRA_TILE_CLICK_OWNER, RuntimeSelectionStore.encodeVpnRecoveryOwner(stable))
            val tileStart = "ru.nelomai.runtime.stable.tunnel.QUICK_TOGGLE"
            val delayedStart = Intent(delayed).setAction(tileStart)
            vpn.onStartCommand(stop, 0, 2)
            vpn.onStartCommand(start, 0, 3)
            vpn.onStartCommand(delayed, 0, 4)
            vpn.onStartCommand(delayedStart, 0, 5)
            assertEquals(listOf(start.action, stop.action, start.action), BrokerRecoveryAdaptersShadow.actions)
            val fresh = Intent(delayedStart).putExtra(RuntimeServiceIntents.EXTRA_TILE_CLICK_REVISION,
                RuntimeProcessSelection.vpnStartRevision)
            BrokerRecoveryAdaptersShadow.quickToggleWouldStart = false
            vpn.onStartCommand(fresh, 0, 6)
            assertEquals(3, BrokerRecoveryAdaptersShadow.actions.size)
            vpn.onStartCommand(stop, 0, 7)
            BrokerRecoveryAdaptersShadow.quickToggleWouldStart = true
            vpn.onStartCommand(fresh, 0, 8)
            vpn.onStartCommand(fresh, 0, 9)
            assertEquals(listOf(start.action, stop.action, start.action, stop.action, tileStart),
                BrokerRecoveryAdaptersShadow.actions)
        } finally { ctrl.destroy() }
    }

    @Test fun stableTileStopCancelsWaitingStartAndRoutesBothKindsOfCleanup() {
        val stable = selection("stable", slot = "stable", runtimeVersion = "0.2.21")
        val prefix = "ru.nelomai.runtime.stable.tunnel."
        BrokerRecoverySelectionShadow.selected = stable
        ReflectionHelpers.setStaticField(RuntimeVpnDispatcherService::class.java, "engineWasLoaded", true)
        val ctrl = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        try {
            val service = ctrl.get()
            val start = Intent(prefix + "CLIENT_START")
            service.onStartCommand(start, 0, 1)
            val stop = Intent(prefix + "CANCEL_CURRENT_CONNECTION_INTENT")
                .putExtra(RuntimeServiceIntents.EXTRA_TILE_CLICK_REVISION, RuntimeProcessSelection.vpnStartRevision)
                .putExtra(RuntimeServiceIntents.EXTRA_TILE_CLICK_OWNER, RuntimeSelectionStore.encodeVpnRecoveryOwner(stable))
            val pending = mutableListOf<(Result<RuntimeSelectionV1>) -> Unit>()
            BrokerRecoverySelectionShadow.pending = pending
            service.onStartCommand(start, 0, 2)
            BrokerRecoveryAdaptersShadow.stableStopLease = true
            service.onStartCommand(Intent(stop), 0, 3)
            pending.single()(Result.success(stable))
            assertEquals(listOf(start.action, stop.action), BrokerRecoveryAdaptersShadow.actions)
            BrokerRecoveryAdaptersShadow.stableStopLease = false
            service.onStartCommand(Intent(stop), 0, 4)
            assertEquals(listOf(start.action, stop.action, stop.action, prefix + "CLIENT_STOP"),
                BrokerRecoveryAdaptersShadow.actions)
        } finally {
            BrokerRecoverySelectionShadow.pending = null
            ctrl.destroy()
        }
    }

    @Test fun quickTileUsesAStopOnlyCommandWhileBrokerIsUnavailable() {
        val old = connectedService()
        BrokerRecoverySelectionShadow.unavailable = true
        val tile = Robolectric.buildService(NelomaiQuickTileService::class.java).create()
        LoggingTileServiceShadow.locked = false
        LoggingTileServiceShadow.tile = ReflectionHelpers.callConstructor(android.service.quicksettings.Tile::class.java)
        LoggingTileServiceShadow.tile!!.state = android.service.quicksettings.Tile.STATE_ACTIVE
        tile.get().onClick()
        val command = requireNotNull(shadowOf(RuntimeEnvironment.getApplication()).nextStartedService)
        assertEquals(RuntimeServiceIntents.QUICK_TOGGLE, command.action)
        assertTrue(command.getBooleanExtra(RuntimeServiceIntents.EXTRA_QUICK_STOP_ONLY, false))
        old.get().onStartCommand(command, 0, 2)
        assertEquals(command.action, BrokerRecoveryAdaptersShadow.actions.last())
        tile.destroy()
        old.destroy()
    }

    @Test fun stopInvalidatesAStartStillWaitingForBinder() {
        val old = connectedService()
        val pending = mutableListOf<(Result<RuntimeSelectionV1>) -> Unit>()
        BrokerRecoverySelectionShadow.pending = pending
        old.get().onStartCommand(RuntimeServiceIntents.foreground(Intent("ru.nelomai.tunnel.CLIENT_START")), 0, 2)
        old.get().onStartCommand(Intent("ru.nelomai.tunnel.CLIENT_STOP").putExtra("api_version", 2), 0, 3)
        assertEquals(1, pending.size)
        pending.single().invoke(Result.success(selection("new-broker")))
        assertEquals(1, BrokerRecoveryAdaptersShadow.established)
        assertEquals("ru.nelomai.tunnel.CLIENT_STOP", BrokerRecoveryAdaptersShadow.actions.last())
        old.destroy()
    }

    @Test fun firstTunCannotEstablishUnderAnOwnerDifferentFromItsStart() {
        BrokerRecoveryAdaptersShadow.beforeEstablish = {
            BrokerRecoverySelectionShadow.selected = selection("old-broker", scope = "b".repeat(64))
        }
        val controller = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        controller.get().onStartCommand(RuntimeServiceIntents.foreground(Intent("ru.nelomai.tunnel.CLIENT_START")), 0, 1)
        assertEquals(0, BrokerRecoveryAdaptersShadow.established)
        controller.destroy()
    }

    @Test fun addressedCancelFencesOnlyTheMatchingQueuedStart() {
        val old = connectedService()
        val pending = mutableListOf<(Result<RuntimeSelectionV1>) -> Unit>()
        BrokerRecoverySelectionShadow.pending = pending
        for ((index, id) in listOf("first", "second").withIndex()) {
            old.get().onStartCommand(RuntimeServiceIntents.foreground(
                Intent("ru.nelomai.tunnel.CLIENT_START").putExtra("client_operation_id", id),
            ), 0, index + 2)
        }
        old.get().onStartCommand(Intent("ru.nelomai.tunnel.CANCEL_CLIENT_START")
            .putExtra("client_operation_id", "first"), 0, 4)
        pending.toList().forEach { it(Result.success(selection("new-broker"))) }
        assertEquals(2, BrokerRecoveryAdaptersShadow.established)
        old.destroy()
    }

    @Test fun unrecoveredBrokerCannotKeepTheVpnPastItsVerificationBudget() {
        val old = connectedService()
        BrokerRecoverySelectionShadow.pending = mutableListOf()
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(1))
        assertEquals(1, BrokerRecoverySelectionShadow.pending?.size)
        old.get().onStartCommand(Intent("ru.nelomai.tunnel.CLIENT_STOP"), 0, 2)
        assertEquals("ru.nelomai.tunnel.CLIENT_STOP", BrokerRecoveryAdaptersShadow.actions.last())
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(8))
        assertEquals(0, BrokerRecoveryAdaptersShadow.revoked)
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(1))
        assertEquals(1, BrokerRecoveryAdaptersShadow.revoked)
        old.destroy()
    }

    @Test fun deviceSleepDoesNotConsumeTheBrokerVerificationBudget() {
        val old = connectedService()
        ShadowPausedSystemClock.simulateDeepSleep(Duration.ofMinutes(2))
        reconcileNewOwner()
        assertEquals(0, BrokerRecoveryAdaptersShadow.revoked)
        old.destroy()
    }

    @Test fun delayedSelectionCallbackDoesNotRenewOldBrokerProof() {
        ReflectionHelpers.setField(original, "brokerVerifiedAtUptimeMillis",
            android.os.SystemClock.uptimeMillis() - 9_000L)
        val old = connectedService()
        BrokerRecoverySelectionShadow.pending = mutableListOf()
        reconcileNewOwner()
        assertEquals(1, BrokerRecoveryAdaptersShadow.revoked)
        old.destroy()
    }

    @Test fun generationCancellationFencesAQueuedToggleThatWouldNowStart() {
        val old = connectedService()
        val pending = mutableListOf<(Result<RuntimeSelectionV1>) -> Unit>()
        BrokerRecoverySelectionShadow.pending = pending
        old.get().onStartCommand(Intent(RuntimeServiceIntents.QUICK_TOGGLE), 0, 2)
        old.get().onStartCommand(Intent("ru.nelomai.tunnel.CANCEL_CONNECTION_INTENT")
            .putExtra("generation", 7L), 0, 3)
        BrokerRecoveryAdaptersShadow.quickToggleWouldStart = true
        pending.single().invoke(Result.success(selection("new-broker")))
        assertEquals(1, BrokerRecoveryAdaptersShadow.established)
        assertEquals("ru.nelomai.tunnel.CANCEL_CONNECTION_INTENT", BrokerRecoveryAdaptersShadow.actions.last())
        old.destroy()
    }

    @Test fun generationCancellationFencesAQueuedBegin() {
        val old = connectedService()
        val pending = mutableListOf<(Result<RuntimeSelectionV1>) -> Unit>()
        BrokerRecoverySelectionShadow.pending = pending
        old.get().onStartCommand(Intent("ru.nelomai.tunnel.BEGIN_CONNECTION_INTENT"), 0, 2)
        old.get().onStartCommand(Intent("ru.nelomai.tunnel.CANCEL_CONNECTION_INTENT")
            .putExtra("generation", 7L), 0, 3)
        pending.single().invoke(Result.success(selection("new-broker")))
        assertEquals(1, BrokerRecoveryAdaptersShadow.established)
        assertEquals("ru.nelomai.tunnel.CANCEL_CONNECTION_INTENT", BrokerRecoveryAdaptersShadow.actions.last())
        old.destroy()
    }

    @Test fun rejectedScopedTeardownDoesNotFenceAQueuedBegin() {
        val old = connectedService()
        val pending = mutableListOf<(Result<RuntimeSelectionV1>) -> Unit>()
        BrokerRecoverySelectionShadow.pending = pending
        val vpn = old.get()
        vpn.onStartCommand(Intent("ru.nelomai.tunnel.BEGIN_CONNECTION_INTENT"), 0, 2)
        vpn.onStartCommand(Intent("ru.nelomai.tunnel.CANCEL_CONNECTION_INTENT")
            .putExtra("generation", 6L), 0, 3)
        vpn.onStartCommand(Intent("ru.nelomai.tunnel.BEGIN_BACKGROUND_LOGOUT")
            .putExtra("owner_cancel_epoch", 6L), 0, 4)
        pending.single().invoke(Result.success(selection("new-broker")))
        assertEquals(2, BrokerRecoveryAdaptersShadow.established)
        old.destroy()
    }

    @Test fun stableStopFencesAStartEvenWhenTheirBinderReadsFinishSeparately() {
        val stable = RuntimeSelectionV1("stable", "0.2.20", "0.3.14", 7, null, "old-broker")
        BrokerRecoverySelectionShadow.selected = stable
        val old = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        shadowOf(Looper.getMainLooper()).idle()
        val pending = mutableListOf<(Result<RuntimeSelectionV1>) -> Unit>()
        BrokerRecoverySelectionShadow.pending = pending
        ReflectionHelpers.setStaticField(RuntimeVpnDispatcherService::class.java, "engineWasLoaded", true)
        val vpn = old.get()
        val stableStop = "ru.nelomai.runtime.stable.tunnel.CLIENT_STOP"
        val stop = Intent(stableStop)
            .putExtra("api_version", RuntimeServiceIntents.VPN_API_VERSION)
        vpn.onStartCommand(RuntimeServiceIntents.foreground(
            Intent("ru.nelomai.runtime.stable.tunnel.CLIENT_START"),
        ), 0, 1)
        vpn.onStartCommand(stop, 0, 2)
        assertEquals(2, pending.size)
        pending.first().invoke(Result.success(stable))
        assertEquals(0, BrokerRecoveryAdaptersShadow.established)
        pending.last().invoke(Result.failure(IllegalStateException("broker unavailable")))
        vpn.onStartCommand(stop, 0, 3)
        assertEquals(listOf(stableStop), BrokerRecoveryAdaptersShadow.actions)
        old.destroy()
    }

    @Test fun revocationWhilePreparingTheBuilderPreventsSystemEstablish() {
        BrokerRecoveryAdaptersShadow.beforeSystemEstablish = { it.service.onRevoke() }
        val controller = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        controller.get().onStartCommand(RuntimeServiceIntents.foreground(
            Intent("ru.nelomai.tunnel.CLIENT_START"),
        ), 0, 1)
        assertEquals(0, BrokerRecoveryAdaptersShadow.established)
        controller.destroy()
    }

    @Test fun queuedStopWinsWhenTheVerificationCallbackRunsFirst() {
        val old = connectedService()
        val pending = mutableListOf<(Result<RuntimeSelectionV1>) -> Unit>()
        BrokerRecoverySelectionShadow.pending = pending
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(1))
        old.get().onStartCommand(Intent("ru.nelomai.tunnel.CLIENT_STOP"), 0, 2)
        assertEquals(1, pending.size)
        assertEquals("ru.nelomai.tunnel.CLIENT_STOP", BrokerRecoveryAdaptersShadow.actions.last())
        val result = Result.success(selection("new-broker"))
        pending.forEach { it(result) }
        assertFalse(ShadowProcess.wasKilled(Process.myPid()))
        assertEquals("ru.nelomai.tunnel.CLIENT_STOP", BrokerRecoveryAdaptersShadow.actions.last())
        old.destroy()
    }

    @Test fun revokeStillReachesTheEngineDuringBrokerRebinding() {
        val old = connectedService()
        ShadowVpnService.setPrepareResult(Intent("android.net.VpnService"))
        old.get().onRevoke()
        BrokerRecoverySelectionShadow.selected = selection("new-broker")
        reconcileNewOwner()
        assertEquals(1, BrokerRecoveryAdaptersShadow.revoked)
        assertEquals(1, BrokerRecoveryAdaptersShadow.established)
        assertFalse(ShadowProcess.wasKilled(Process.myPid()))
        old.destroy()
    }

    @Test fun frameworkRevocationClosesTheProcessIfTransportStaysOpen() {
        val old = connectedService()
        BrokerRecoveryAdaptersShadow.transportClosed = false
        BrokerRecoveryAdaptersShadow.onRevoke = {
            advanceWatchdog(old.get(), 9)
            assertFalse(ShadowProcess.wasKilled(Process.myPid()))
            advanceWatchdog(old.get(), 1)
            assertTrue(ShadowProcess.wasKilled(Process.myPid()))
        }
        old.get().onRevoke()
        assertEquals(1, BrokerRecoveryAdaptersShadow.revoked)
        assertTrue(ShadowProcess.wasKilled(Process.myPid()))
        old.destroy()
    }

    @Test fun revokeFromBinderArmsTheWatchdogBeforeMainCanRunCleanup() {
        val old = connectedService()
        BrokerRecoveryAdaptersShadow.transportClosed = false
        val vpn = old.get()
        Thread { vpn.onRevoke() }.apply { start(); join() }
        assertFalse(vpn.vpnAuthorityCurrent())
        assertEquals(0, BrokerRecoveryAdaptersShadow.revoked)
        advanceWatchdog(vpn, 10)
        assertTrue(ShadowProcess.wasKilled(Process.myPid()))
        old.destroy()
    }

    @Test fun watchdogExpiresUnverifiedTransportEvenIfMainCannotStartRetirement() {
        val old = connectedService()
        BrokerRecoveryAdaptersShadow.transportClosed = false
        BrokerRecoverySelectionShadow.unavailable = true
        advanceWatchdog(old.get(), 19)
        assertEquals(0, BrokerRecoveryAdaptersShadow.revoked)
        assertFalse(ShadowProcess.wasKilled(Process.myPid()))
        advanceWatchdog(old.get(), 1)
        assertTrue(ShadowProcess.wasKilled(Process.myPid()))
        old.destroy()
    }

    @Test fun ordinaryDestroyLeavesWatchdogArmedUntilTheTransportCloses() {
        val old = connectedService()
        BrokerRecoveryAdaptersShadow.transportClosed = false
        val vpn = old.get()
        old.destroy()
        assertFalse(ShadowProcess.wasKilled(Process.myPid()))
        advanceWatchdog(vpn, 10)
        assertTrue(ShadowProcess.wasKilled(Process.myPid()))
    }

    @Test fun aPendingLogoutReachesTheEngineAndCannotStartAStickyTunnel() {
        val old = connectedService()
        BrokerRecoverySelectionShadow.selected = selection("new-broker", scope = null, blocked = true, logoutEpoch = 8)
        reconcileNewOwner()
        assertEquals(listOf(8L), BrokerRecoveryAdaptersShadow.logoutEpochs)
        assertFalse(old.get().vpnAuthorityCurrent())
        assertFalse(ShadowProcess.wasKilled(Process.myPid()))
        old.destroy()
        ReflectionHelpers.setStaticField(RuntimeProcessSelection::class.java, "loaded", null)
        val replacement = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        replacement.get().onStartCommand(null, 0, 1)
        assertEquals(1, BrokerRecoveryAdaptersShadow.established)
        assertEquals(listOf(8L, 8L), BrokerRecoveryAdaptersShadow.logoutEpochs)
        replacement.destroy()
    }

    @Test fun coldStatusWithRevokedPermissionStillDeliversPersistedLogout() {
        ShadowVpnService.setPrepareResult(Intent("android.net.VpnService"))
        BrokerRecoverySelectionShadow.selected = selection("new-broker", scope = null, blocked = true, logoutEpoch = 8)
        val replacement = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        replacement.get().onStartCommand(Intent("ru.nelomai.tunnel.CLIENT_STATUS"), 0, 1)
        assertEquals(0, BrokerRecoveryAdaptersShadow.established)
        assertEquals(listOf(8L), BrokerRecoveryAdaptersShadow.logoutEpochs)
        assertEquals("ru.nelomai.tunnel.BEGIN_BACKGROUND_LOGOUT", BrokerRecoveryAdaptersShadow.actions.last())
        replacement.destroy()
    }

    @Test fun coldStopDeliversBothPersistedLogoutAndTheRequestedStop() {
        BrokerRecoverySelectionShadow.selected = selection("new-broker", scope = null, blocked = true, logoutEpoch = 8)
        val replacement = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        replacement.get().onStartCommand(Intent("ru.nelomai.tunnel.CLIENT_STOP"), 0, 1)
        assertEquals(listOf(8L), BrokerRecoveryAdaptersShadow.logoutEpochs)
        assertEquals("ru.nelomai.tunnel.CLIENT_STOP", BrokerRecoveryAdaptersShadow.actions.last())
        assertEquals(0, BrokerRecoveryAdaptersShadow.established)
        replacement.destroy()
    }

    @Test fun logoutCleanupClearsTheQuickPlanWithAWarmOrColdService() {
        val clear = "ru.nelomai.tunnel.CLEAR_QUICK_PLAN"
        val warm = connectedService()
        BrokerRecoverySelectionShadow.selected = selection("old-broker", scope = null, blocked = true, logoutEpoch = 8)
        reconcileNewOwner()
        warm.get().onStartCommand(Intent(clear), 0, 2)
        assertEquals("warm retired service must execute cleanup", clear, BrokerRecoveryAdaptersShadow.actions.last())
        warm.destroy()
        ReflectionHelpers.setStaticField(RuntimeProcessSelection::class.java, "loaded", null)
        val cold = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        cold.get().onStartCommand(Intent(clear), 0, 1)
        assertEquals("fresh service after Logout must execute cleanup", clear, BrokerRecoveryAdaptersShadow.actions.last())
        assertEquals(1, BrokerRecoveryAdaptersShadow.established)
        cold.destroy()
    }

    @Test fun rejectedStatusCannotStrandTheRetiredServiceAtItsOldStartId() {
        val old = connectedService()
        BrokerRecoverySelectionShadow.selected = selection("old-broker", scope = null, blocked = true, logoutEpoch = 8)
        reconcileNewOwner()
        old.get().onStartCommand(Intent("ru.nelomai.tunnel.CLIENT_STATUS"), 0, 2)
        assertEquals("retired engine must be able to stop at the latest startId", listOf(2),
            BrokerRecoveryAdaptersShadow.rejectedStartIds)
        assertFalse(BrokerRecoveryAdaptersShadow.actions.contains("ru.nelomai.tunnel.CLIENT_STATUS"))
        old.destroy()
    }

    @Test fun retirementReconcilesAStatusRejectedBeforeTheBrokerDeadline() {
        val old = connectedService()
        BrokerRecoverySelectionShadow.unavailable = true
        old.get().onStartCommand(Intent("ru.nelomai.tunnel.CLIENT_STATUS"), 0, 2)
        assertTrue(BrokerRecoveryAdaptersShadow.rejectedStartIds.isEmpty())
        assertEquals(0, BrokerRecoveryAdaptersShadow.revoked)
        BrokerRecoveryAdaptersShadow.onRevoke = {
            assertEquals(listOf(2), BrokerRecoveryAdaptersShadow.rejectedStartIds)
        }
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(11))
        assertEquals(1, BrokerRecoveryAdaptersShadow.revoked)
        assertEquals(listOf(2), BrokerRecoveryAdaptersShadow.rejectedStartIds)
        old.destroy()
    }

    @Test fun retiredStableEngineUsesTheExistingReadCommandToSettleStartId() {
        BrokerRecoverySelectionShadow.selected =
            RuntimeSelectionV1("stable", "0.2.21", "0.3.14", 7, null, "old-broker")
        ReflectionHelpers.setStaticField(RuntimeVpnDispatcherService::class.java, "engineWasLoaded", true)
        val old = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        val prefix = "ru.nelomai.runtime.stable.tunnel."
        old.get().onStartCommand(RuntimeServiceIntents.foreground(Intent(prefix + "CLIENT_START")), 0, 1)
        old.get().onRevoke()
        old.get().onStartCommand(Intent(prefix + "CLIENT_STATUS"), 0, 2)
        assertEquals(listOf(prefix + "CLIENT_START", prefix + "TAKE_STATE_CHANGE"),
            BrokerRecoveryAdaptersShadow.actions)
        assertEquals(listOf(1, 2), BrokerRecoveryAdaptersShadow.startIds)
        assertEquals(1, BrokerRecoveryAdaptersShadow.revoked)
        old.destroy()
    }

    @Test fun asynchronousFailureOfNativeLogoutFallsBackToRevocation() {
        val old = connectedService()
        BrokerRecoveryAdaptersShadow.logoutResult = 2
        BrokerRecoverySelectionShadow.selected = selection("new-broker", scope = null, blocked = true, logoutEpoch = 8)
        reconcileNewOwner()
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals(1, BrokerRecoveryAdaptersShadow.revoked)
        old.destroy()
    }

    @Test fun validatedLogoutImmediatelyRetiresAuthorityWithTheBrokerUnavailable() {
        val old = connectedService()
        BrokerRecoverySelectionShadow.unavailable = true
        val vpn = old.get()
        vpn.onStartCommand(Intent("ru.nelomai.tunnel.BEGIN_BACKGROUND_LOGOUT")
            .putExtra("owner_cancel_epoch", 8L), 0, 2)
        assertEquals(listOf(8L), BrokerRecoveryAdaptersShadow.logoutEpochs)
        assertFalse(vpn.vpnAuthorityCurrent())
        old.destroy()
    }

    @Test fun logoutWithNoStopCallbackStillClosesTheProcessIfTransportStaysOpen() {
        val old = connectedService()
        BrokerRecoveryAdaptersShadow.transportClosed = false
        BrokerRecoverySelectionShadow.selected = selection("new-broker", scope = null, blocked = true, logoutEpoch = 8)
        reconcileNewOwner()
        assertFalse(ShadowProcess.wasKilled(Process.myPid()))
        advanceWatchdog(old.get(), 10)
        assertTrue(ShadowProcess.wasKilled(Process.myPid()))
        old.destroy()
    }
}

@Implements(RuntimeSelectionStore::class)
class BrokerRecoverySelectionShadow {
    @Implementation fun read(callback: (Result<RuntimeSelectionV1>) -> Unit) {
        pending?.let { it.add(callback); return }
        callback(if (unavailable) Result.failure(IllegalStateException("runtime_owner_unavailable"))
            else Result.success(selected))
    }
    @Implementation fun snapshot(): RuntimeSelectionV1 = selected
    @Implementation fun close() = Unit

    companion object {
        lateinit var selected: RuntimeSelectionV1
        var unavailable = false
        var pending: MutableList<(Result<RuntimeSelectionV1>) -> Unit>? = null
    }
}

@Implements(RuntimeAdapters::class, isInAndroidSdk = false)
class BrokerRecoveryAdaptersShadow {
    @Implementation fun engine(selected: RuntimeSelectionV1, host: RuntimeVpnHostV1): RuntimeVpnEngineV1 {
        val adapter = object : RuntimeVpnEngineV1, RuntimeVpnTransportV1 {
            override fun requiresStartAdmission(intent: Intent?) =
                intent == null || intent.action == "ru.nelomai.tunnel.CLIENT_START" ||
                    intent.action == "ru.nelomai.runtime.stable.tunnel.CLIENT_START" ||
                    intent.action == "ru.nelomai.tunnel.BEGIN_CONNECTION_INTENT" ||
                    ((intent.action == RuntimeServiceIntents.QUICK_TOGGLE ||
                        intent.action == "ru.nelomai.runtime.stable.tunnel.QUICK_TOGGLE") && quickToggleWouldStart &&
                        !intent.getBooleanExtra(RuntimeServiceIntents.EXTRA_QUICK_STOP_ONLY, false))
            override fun create() = Unit
            override fun start(intent: Intent?, flags: Int, startId: Int): Int {
                actions += intent?.action
                startIds += startId
                if (intent?.action == "ru.nelomai.runtime.stable.tunnel.CANCEL_CURRENT_CONNECTION_INTENT") {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra<ResultReceiver>("result_receiver")?.send(1, android.os.Bundle().apply {
                        if (stableStopLease) putString("lease_phase", "cleanup_pending")
                    })
                }
                if (intent?.action == "ru.nelomai.tunnel.BEGIN_BACKGROUND_LOGOUT") {
                    logoutEpochs += intent.getLongExtra("owner_cancel_epoch", -1)
                    if (intent.getLongExtra("owner_cancel_epoch", -1) == 8L) {
                        (host as RuntimeVpnAuthorityV1).retireVpnAuthority()
                    }
                    logoutResult?.let { result ->
                        @Suppress("DEPRECATION")
                        intent.getParcelableExtra<ResultReceiver>("result_receiver")?.send(result, null)
                    }
                }
                if (intent?.action == "ru.nelomai.tunnel.CANCEL_CONNECTION_INTENT" &&
                    intent.getLongExtra("generation", -1) == 7L
                ) {
                    (host as RuntimeVpnAuthorityV1).invalidateQueuedVpnStarts()
                }
                if (requiresStartAdmission(intent)) {
                    beforeEstablish?.invoke()
                    host.builder { beforeSystemEstablish?.invoke(host) }.establish()?.use { established++ }
                }
                return if (intent?.action == RuntimeServiceIntents.TASK_REMOVAL_LIVENESS) watchResult else Service.START_STICKY
            }
            override fun revoke() {
                revoked++
                onRevoke?.invoke()
            }
            override fun taskRemoved(intent: Intent?) = Unit
            override fun destroy() { destroyed++ }
            override fun localTransportClosed(): Boolean = transportClosed
            override fun retiredStartRejected(startId: Int) { rejectedStartIds += startId }
        }
        return if (selected.slot == "stable") object : RuntimeVpnEngineV1 by adapter {} else adapter
    }

    @Implementation fun quick(selected: RuntimeSelectionV1): RuntimeQuickActionsV1 =
        object : RuntimeQuickActionsV1 {
            override fun desiredActive(context: Context): Boolean = true
            override fun state(context: Context) = error("unexpected state read")
            override fun toggle(context: Context) = error("unexpected toggle")
        }

    companion object {
        var destroyed = 0
        var established = 0
        var revoked = 0
        val actions = mutableListOf<String?>()
        val startIds = mutableListOf<Int>()
        val rejectedStartIds = mutableListOf<Int>()
        val logoutEpochs = mutableListOf<Long>()
        var beforeEstablish: (() -> Unit)? = null
        var logoutResult: Int? = null
        var watchResult = Service.START_STICKY
        var stableStopLease = true
        var quickToggleWouldStart = false
        var beforeSystemEstablish: ((RuntimeVpnHostV1) -> Unit)? = null
        var transportClosed = true
        var onRevoke: (() -> Unit)? = null
    }
}

@Implements(VpnService.Builder::class)
class BrokerRecoveryBuilderShadow {
    @Implementation fun establish(): ParcelFileDescriptor =
        ParcelFileDescriptor.createPipe().let { (read, write) -> write.close(); read }
}
