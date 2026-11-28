@file:Suppress("INVISIBLE_MEMBER", "INVISIBLE_REFERENCE")

package ru.nelomai.client

import android.content.Context
import android.content.Intent
import android.os.Handler
import android.os.Looper
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
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
import org.robolectric.shadows.ShadowLog
import org.robolectric.shadows.ShadowService
import org.robolectric.util.ReflectionHelpers
import ru.nelomai.tunnel.AndroidIntentTemplate
import ru.nelomai.tunnel.AndroidRecoveryStore
import ru.nelomai.tunnel.AndroidRecoveryStores
import ru.nelomai.tunnel.AndroidRedundantTransaction
import ru.nelomai.tunnel.BootIdentityProvider
import ru.nelomai.tunnel.EncryptedRecordBackend
import ru.nelomai.tunnel.RecoveryStoreResult
import ru.nelomai.tunnel.RedundantStopState

@RunWith(RobolectricTestRunner::class)
@Config(
    sdk = [34], application = android.app.Application::class,
    shadows = [TileSelectionShadow::class, LoggingTileServiceShadow::class, LoggingTileShadow::class],
)
class QuickTileLoggingTest {
    @Before fun setUp() {
        RuntimeProcessSelection.clearVpnOwner()
        ReflectionHelpers.setStaticField(RuntimeProcessSelection::class.java, "loaded", null)
        TileSelectionShadow.result = Result.success(selection)
        TileSelectionShadow.pending = null
        LoggingTileServiceShadow.tile = ReflectionHelpers.callConstructor(Tile::class.java)
        LoggingTileServiceShadow.locked = false
        LoggingTileServiceShadow.afterUnlock = null
        LoggingTileShadow.updates = 0
        ShadowLog.clear()
        engineState("running")
    }

    @Test fun onTileTapAtLockCannotIssueStartAfterStopCompletes() {
        val broker = org.json.JSONObject(RuntimeSelectionStore.encode(selection))
            .put("vpn_authorization", org.json.JSONObject().put("scope", "a".repeat(64)).put("blocked", false))
        val owner = RuntimeSelectionStore.decode(broker.toString())
        var bytes: ByteArray? = null
        val backendClass = EncryptedRecordBackend::class.java
        val record = java.lang.reflect.Proxy.newProxyInstance(backendClass.classLoader, arrayOf(backendClass)) { _, method, args ->
            when (method.name) {
                "read" -> bytes?.copyOf()
                "write" -> {
                    bytes = (args.single() as ByteArray).copyOf()
                    true
                }
                else -> error("Unexpected recovery record method ${method.name}")
            }
        } as EncryptedRecordBackend
        val store = AndroidRecoveryStore(record, BootIdentityProvider { 7 })
        val old = AndroidRedundantTransaction(true,
            AndroidIntentTemplate("11111111-1111-4111-8111-111111111111", "account", "stray",
                "dynamic", "standalone", "ipv4", true),
            "22222222-2222-4222-8222-222222222222", "lease-a", null, "lease-a", true, 1, 1, "old-start", "fp")
        ReflectionHelpers.setField(AndroidRecoveryStores, "instance", store)
        assertTrue(store.beginRedundant(old) is RecoveryStoreResult.Success)

        RuntimeProcessSelection.rememberVpnOwner(owner)
        TileSelectionShadow.result = Result.success(owner)
        val controller = Robolectric.buildService(NelomaiQuickTileService::class.java).create()
        try {
            val service = controller.get()
            engineState("running")
            service.onStartListening()
            assertEquals(Tile.STATE_ACTIVE, LoggingTileServiceShadow.tile?.state)
            LoggingTileServiceShadow.locked = true
            service.onClick()
            val unlock = requireNotNull(LoggingTileServiceShadow.afterUnlock)
            assertNull(shadowOf(RuntimeEnvironment.getApplication()).nextStartedService)
            assertTrue(store.cancelRedundantIntentAndDeferStop("prior-stop", "old-start") is RecoveryStoreResult.Success)
            assertTrue(store.updateRedundant("old-start") { it.copy(retry = it.retry.copy(stopState = RedundantStopState.ACKNOWLEDGED)) } is RecoveryStoreResult.Success)
            assertTrue(store.completeRedundantStop("prior-stop","old-start") is RecoveryStoreResult.Success)
            engineState("stopped")
            LoggingTileServiceShadow.locked = false
            service.onStartListening()
            assertEquals(Tile.STATE_INACTIVE, LoggingTileServiceShadow.tile?.state)
            unlock.run()
            val cmd = shadowOf(RuntimeEnvironment.getApplication()).nextStartedService
            val stopOnly = cmd?.getBooleanExtra(ru.nelomai.runtime.v1.RuntimeServiceIntents.EXTRA_QUICK_STOP_ONLY,false)
            assertTrue("tap on active tile may only Stop or do nothing", cmd == null || stopOnly == true)
        } finally {
            controller.destroy()
            RuntimeProcessSelection.clearVpnOwner()
            ReflectionHelpers.setField(AndroidRecoveryStores, "instance", null)
        }
    }

    @Test fun offClickCapturesOldStopBeforeTileSelectionReply() = delayedOffClick(ClickRace.REPLACEMENT)

    @Test fun offClickCannotTransferToDifferentAccountInTileSelectionReply() = delayedOffClick(ClickRace.OTHER_ACCOUNT)

    @Test fun offClickCapturesOldStopBeforeScreenUnlock() = delayedOffClick(ClickRace.UNLOCK)

    @Test fun coldOffClickStartsWithoutPriorTileSnapshot() = delayedOffClick(ClickRace.COLD)

    @Test fun coldOffClickCannotRestartReplacementThatAlreadyStopped() = delayedOffClick(ClickRace.COLD_REPLACEMENT)

    @Test fun coldOffClickCannotRestartReplacementAfterDispatcherDestruction() =
        delayedOffClick(ClickRace.COLD_REPLACEMENT_DESTROYED)

    @Test fun coldOffClickSurvivesPassiveDispatcherAdmission() = delayedOffClick(ClickRace.COLD_STATUS)

    private enum class ClickRace { REPLACEMENT, OTHER_ACCOUNT, UNLOCK, COLD, COLD_STATUS, COLD_REPLACEMENT, COLD_REPLACEMENT_DESTROYED }

    private fun delayedOffClick(race: ClickRace) {
        val coldReplacement = race == ClickRace.COLD_REPLACEMENT || race == ClickRace.COLD_REPLACEMENT_DESTROYED
        val cold = race == ClickRace.COLD || race == ClickRace.COLD_STATUS || coldReplacement
        val locked = race == ClickRace.UNLOCK
        val broker = org.json.JSONObject(RuntimeSelectionStore.encode(selection))
            .put("vpn_authorization", org.json.JSONObject().put("scope", "a".repeat(64)).put("blocked", false))
        val owner = RuntimeSelectionStore.decode(broker.toString())
        var bytes: ByteArray? = null
        val backendClass = EncryptedRecordBackend::class.java
        val record = java.lang.reflect.Proxy.newProxyInstance(backendClass.classLoader, arrayOf(backendClass)) { _, method, args ->
            when (method.name) {
                "read" -> bytes?.copyOf()
                "write" -> {
                    bytes = (args.single() as ByteArray).copyOf()
                    true
                }
                else -> error("Unexpected recovery record method ${method.name}")
            }
        } as EncryptedRecordBackend
        val store = AndroidRecoveryStore(record, BootIdentityProvider { 7 })
        val old = AndroidRedundantTransaction(true,
            AndroidIntentTemplate("11111111-1111-4111-8111-111111111111", "account", "stray",
                "dynamic", "standalone", "ipv4", true),
            "22222222-2222-4222-8222-222222222222", "lease-a", null, "lease-a", true, 1, 1, "old-start", "fp")
        ReflectionHelpers.setField(AndroidRecoveryStores, "instance", store)
        assertTrue(store.beginRedundant(old) is RecoveryStoreResult.Success)
        assertTrue(store.cancelRedundantIntentAndDeferStop("old-stop", "old-start") is RecoveryStoreResult.Success)
        engineState("stopped")
        TileSelectionShadow.result = Result.success(owner)
        val controller = Robolectric.buildService(NelomaiQuickTileService::class.java).create()
        try {
            val service = controller.get()
            if (cold) LoggingTileServiceShadow.tile?.state = Tile.STATE_INACTIVE else service.onStartListening()
            assertEquals(Tile.STATE_INACTIVE, LoggingTileServiceShadow.tile?.state)
            LoggingTileServiceShadow.locked = locked
            TileSelectionShadow.pending = mutableListOf()
            service.onClick()
            if (locked) {
                assertTrue(TileSelectionShadow.pending!!.isEmpty())
                assertNull(shadowOf(RuntimeEnvironment.getApplication()).nextStartedService)
            }
            if (race == ClickRace.COLD_STATUS) RuntimeProcessSelection.rememberVpnOwner(owner)
            if (race != ClickRace.COLD && race != ClickRace.COLD_STATUS) {
                assertTrue(store.updateRedundant("old-start") {
                    it.copy(retry = it.retry.copy(stopState = RedundantStopState.ACKNOWLEDGED))
                } is RecoveryStoreResult.Success)
                assertTrue(store.completeRedundantStop("old-stop", "old-start") is RecoveryStoreResult.Success)
                assertTrue(store.beginRedundant(old.copy(startOperationId = "replacement")) is RecoveryStoreResult.Success)
                engineState("running")
            }
            if (coldReplacement) {
                RuntimeProcessSelection.rememberVpnOwner(owner)
                assertTrue(store.cancelRedundantIntentAndDeferStop("replacement-stop", "replacement") is RecoveryStoreResult.Success)
                assertTrue(store.updateRedundant("replacement") {
                    it.copy(retry = it.retry.copy(stopState = RedundantStopState.ACKNOWLEDGED))
                } is RecoveryStoreResult.Success)
                assertTrue(store.completeRedundantStop("replacement-stop", "replacement") is RecoveryStoreResult.Success)
                engineState("stopped")
                if (race == ClickRace.COLD_REPLACEMENT_DESTROYED) {
                    Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create().destroy()
                    assertNull(RuntimeProcessSelection.vpnOwnerForStop())
                }
            }
            if (locked) {
                TileSelectionShadow.pending = null
                service.onStartListening()
                assertEquals(Tile.STATE_ACTIVE, LoggingTileServiceShadow.tile?.state)
                TileSelectionShadow.pending = mutableListOf()
                requireNotNull(LoggingTileServiceShadow.afterUnlock).run()
            }
            val reply = TileSelectionShadow.pending!!.removeAt(0)
            if (race == ClickRace.OTHER_ACCOUNT) broker.getJSONObject("vpn_authorization").put("scope", "b".repeat(64))
            reply(Result.success(RuntimeSelectionStore.decode(broker.toString())))

            val command = shadowOf(RuntimeEnvironment.getApplication()).nextStartedService
            if (race == ClickRace.OTHER_ACCOUNT || coldReplacement) {
                assertNull("stale click dispatched a new command", command)
            } else assertEquals("old-start", command?.getStringExtra("client_operation_id"))
        } finally {
            controller.destroy()
            RuntimeProcessSelection.clearVpnOwner()
            ReflectionHelpers.setField(AndroidRecoveryStores, "instance", null)
        }
    }

    @Test fun supersededLockedStopRefreshesTheActiveTile() {
        val controller = Robolectric.buildService(NelomaiQuickTileService::class.java).create()
        try {
            val tile = controller.get()
            RuntimeProcessSelection.rememberVpnOwner(selection)
            tile.onStartListening()
            assertEquals(Tile.STATE_ACTIVE, LoggingTileServiceShadow.tile?.state)
            LoggingTileServiceShadow.locked = true
            tile.onClick()
            RuntimeProcessSelection.recordVpnStart()
            requireNotNull(LoggingTileServiceShadow.afterUnlock).run()
            assertNull(shadowOf(RuntimeEnvironment.getApplication()).nextStartedService)
            assertEquals(Tile.STATE_ACTIVE, LoggingTileServiceShadow.tile?.state)
        } finally {
            controller.destroy()
            RuntimeProcessSelection.clearVpnOwner()
        }
    }

    @Test fun repeatedStateLogsOnceButStillPublishesEveryRefresh() {
        val controller = Robolectric.buildService(NelomaiQuickTileService::class.java).create()
        repeat(149) { controller.get().onStartListening() }
        assertEquals(listOf("state.updated engine=running tile=2"), messages())
        assertEquals(149, LoggingTileShadow.updates)
        assertEquals(Tile.STATE_ACTIVE, LoggingTileServiceShadow.tile?.state)
        controller.destroy()
    }

    @Test fun logsEveryTransitionIncludingReturnAndSameTileState() {
        val controller = Robolectric.buildService(NelomaiQuickTileService::class.java).create()
        for (state in listOf("stopped", "starting", "stopping", "stopped", "running")) {
            engineState(state)
            repeat(2) { controller.get().onStartListening() }
        }
        assertEquals(listOf(
            "state.updated engine=stopped tile=1",
            "state.updated engine=starting tile=0",
            "state.updated engine=stopping tile=0",
            "state.updated engine=stopped tile=1",
            "state.updated engine=running tile=2",
        ), messages())
        assertEquals(10, LoggingTileShadow.updates)
        controller.destroy()
    }

    @Test fun logsChangedTileEvenWhenEngineIsUnchanged() {
        val controller = Robolectric.buildService(NelomaiQuickTileService::class.java).create()
        controller.get().onStartListening()
        TileSelectionShadow.result = Result.success(selection.copy(pendingSlot = "stable"))
        repeat(2) { controller.get().onStartListening() }
        assertEquals(listOf("state.updated engine=running tile=2", "state.updated engine=running tile=0"), messages())
        controller.destroy()
    }

    @Test fun unknownInitialStateAndRecoveryAreLogged() {
        val controller = Robolectric.buildService(NelomaiQuickTileService::class.java).create()
        TileSelectionShadow.result = Result.failure(IllegalStateException("runtime_owner_unavailable"))
        repeat(2) { controller.get().onStartListening() }
        TileSelectionShadow.result = Result.success(selection)
        controller.get().onStartListening()
        TileSelectionShadow.result = Result.failure(IllegalStateException("runtime_owner_unavailable"))
        controller.get().onStartListening()
        assertEquals(listOf(
            "state.updated engine=null tile=0", "state.updated engine=running tile=2",
            "state.updated engine=null tile=0",
        ), messages())
        controller.destroy()
    }

    @Test fun recreatedServiceLogsItsFirstStateAgain() {
        repeat(2) {
            val controller = Robolectric.buildService(NelomaiQuickTileService::class.java).create()
            repeat(2) { controller.get().onStartListening() }
            controller.destroy()
        }
        assertEquals(List(2) { "state.updated engine=running tile=2" }, messages())
    }

    @Test fun missingSystemTileDoesNotConsumeFirstLog() {
        val controller = Robolectric.buildService(NelomaiQuickTileService::class.java).create()
        LoggingTileServiceShadow.tile = null
        controller.get().onStartListening()
        assertEquals(emptyList<String>(), messages())
        LoggingTileServiceShadow.tile = ReflectionHelpers.callConstructor(Tile::class.java)
        repeat(2) { controller.get().onStartListening() }
        assertEquals(listOf("state.updated engine=running tile=2"), messages())
        assertEquals(2, LoggingTileShadow.updates)
        controller.destroy()
    }

    @Test fun unreadableRecoveryAfterAnOlderAndroidStopIsUnavailableUntilItCanBeRead() {
        var failRead = false
        var bytes: ByteArray? = null
        val type = EncryptedRecordBackend::class.java
        val record = java.lang.reflect.Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { _, method, args ->
            when (method.name) {
                "read" -> { check(!failRead); bytes?.copyOf() }
                "write" -> { bytes = (args.single() as ByteArray).copyOf(); true }
                else -> error(method.name)
            }
        } as EncryptedRecordBackend
        val store = AndroidRecoveryStore(record, BootIdentityProvider { 7 })
        val controller = Robolectric.buildService(NelomaiQuickTileService::class.java).create()
        ReflectionHelpers.setField(AndroidRecoveryStores, "instance", store)
        try {
            val service = controller.get()
            val exit = org.robolectric.shadows.ShadowActivityManager.ApplicationExitInfoBuilder.newBuilder()
                .setTimestamp(System.currentTimeMillis() - 10_000).setPid(321)
                .setProcessName(service.packageName + ":vpn")
                .setReason(android.app.ApplicationExitInfo.REASON_USER_REQUESTED)
                .setDescription("[STOP APP] fully stop").build()
            shadowOf(service.getSystemService(android.app.ActivityManager::class.java)).addApplicationExitInfo(exit)
            assertTrue(store.setDesiredActive(0, true) is RecoveryStoreResult.Success)
            failRead = true
            service.onStartListening()
            assertEquals(Tile.STATE_UNAVAILABLE, LoggingTileServiceShadow.tile?.state)
            failRead = false
            shadowOf(Looper.getMainLooper()).idleFor(java.time.Duration.ofSeconds(5))
            assertEquals(Tile.STATE_ACTIVE, LoggingTileServiceShadow.tile?.state)
        } finally {
            controller.destroy()
            ReflectionHelpers.setField(AndroidRecoveryStores, "instance", null)
        }
    }

    @Test fun failedSelectionDuringTapRefreshesTheSameOpenTileWhenBrokerReturns() {
        val controller = Robolectric.buildService(NelomaiQuickTileService::class.java).create()
        val service = controller.get()
        service.onStartListening()
        assertEquals(Tile.STATE_ACTIVE, LoggingTileServiceShadow.tile?.state)
        TileSelectionShadow.result = Result.failure(IllegalStateException("runtime_owner_unavailable"))
        service.onClick()
        assertEquals(Tile.STATE_UNAVAILABLE, LoggingTileServiceShadow.tile?.state)
        TileSelectionShadow.result = Result.success(selection)
        shadowOf(Looper.getMainLooper()).idleFor(java.time.Duration.ofSeconds(5))
        assertEquals(Tile.STATE_ACTIVE, LoggingTileServiceShadow.tile?.state)
        controller.destroy()
    }

    @Test fun unavailableEngineStateDoesNotPresentAWorkingTunnelAsOff() {
        val controller = Robolectric.buildService(NelomaiQuickTileService::class.java).create()
        val service = controller.get()
        service.onStartListening()
        assertEquals(Tile.STATE_ACTIVE, LoggingTileServiceShadow.tile?.state)
        val slot = ru.nelomai.tunnel.BuildConfig.RUNTIME_SLOT
        val version = ru.nelomai.tunnel.BuildConfig.RUNTIME_VERSION
        val prefs = service.getSharedPreferences("runtime.$slot.state.$version.nelomai-quick-tunnel-state", Context.MODE_PRIVATE)
        prefs.edit().putInt("state", 1).commit()
        stateChanged()
        idle()
        assertEquals(Tile.STATE_UNAVAILABLE, LoggingTileServiceShadow.tile?.state)
        engineState("running")
        shadowOf(Looper.getMainLooper()).idleFor(java.time.Duration.ofSeconds(5))
        assertEquals(Tile.STATE_ACTIVE, LoggingTileServiceShadow.tile?.state)
        controller.destroy()
    }

    @Test fun listeningTilePublishesAsyncStopAndStartWithoutAnotherListeningCallback() {
        val controller = Robolectric.buildService(NelomaiQuickTileService::class.java).create()
        val handler = ReflectionHelpers.getField<Handler>(controller.get(), "mHandler")
        handler.sendEmptyMessage(1) // Android MSG_START_LISTENING.
        idle()
        assertEquals(Tile.STATE_ACTIVE, LoggingTileServiceShadow.tile?.state)
        for ((state, tile) in listOf("stopping" to Tile.STATE_UNAVAILABLE,
                "stopped" to Tile.STATE_INACTIVE, "failed" to Tile.STATE_INACTIVE, "starting" to Tile.STATE_UNAVAILABLE,
                "running" to Tile.STATE_ACTIVE)) {
            engineState(state)
            stateChanged()
            // Android ignores this duplicate while already listening.
            handler.sendEmptyMessage(1)
            idle()
            assertEquals(tile, LoggingTileServiceShadow.tile?.state)
        }
        controller.destroy()
    }

    @Test fun listenerStopsAndResumesWithoutDuplicateSubscriptions() {
        val controller = Robolectric.buildService(NelomaiQuickTileService::class.java).create()
        val service = controller.get()
        repeat(3) { service.onStartListening() }
        val before = LoggingTileShadow.updates
        stateChanged()
        idle()
        assertEquals(before + 1, LoggingTileShadow.updates)
        service.onStopListening()
        engineState("stopped")
        stateChanged()
        idle()
        assertEquals(before + 1, LoggingTileShadow.updates)
        service.onStartListening()
        assertEquals(Tile.STATE_INACTIVE, LoggingTileServiceShadow.tile?.state)
        val resumed = LoggingTileShadow.updates
        stateChanged()
        idle()
        assertEquals(resumed + 1, LoggingTileShadow.updates)
        controller.destroy()
        stateChanged()
        idle()
        assertEquals(resumed + 1, LoggingTileShadow.updates)
    }

    @Test fun oldListeningCallbackCannotPublishIntoANewerListeningSession() {
        val controller = Robolectric.buildService(NelomaiQuickTileService::class.java).create()
        val service = controller.get()
        TileSelectionShadow.pending = mutableListOf()
        service.onStartListening()
        val old = TileSelectionShadow.pending!!.removeAt(0)
        service.onStopListening()
        service.onStartListening()
        val current = TileSelectionShadow.pending!!.removeAt(0)
        engineState("stopped")
        current(Result.success(selection))
        assertEquals(Tile.STATE_INACTIVE, LoggingTileServiceShadow.tile?.state)
        val before = LoggingTileShadow.updates
        engineState("running")
        old(Result.success(selection))
        assertEquals(before, LoggingTileShadow.updates)
        assertEquals(Tile.STATE_INACTIVE, LoggingTileServiceShadow.tile?.state)
        controller.destroy()
    }

    @Test fun pendingStateCallbackCannotPublishAfterDestroy() {
        val controller = Robolectric.buildService(NelomaiQuickTileService::class.java).create()
        TileSelectionShadow.pending = mutableListOf()
        controller.get().onStartListening()
        val pending = TileSelectionShadow.pending!!.removeAt(0)
        controller.destroy()
        val before = LoggingTileShadow.updates
        pending(Result.success(selection))
        assertEquals(before, LoggingTileShadow.updates)
    }

    @Test fun oldToggleFailureCannotDisableANewerListeningSession() {
        val controller = Robolectric.buildService(NelomaiQuickTileService::class.java).create()
        val service = controller.get()
        service.onStartListening()
        TileSelectionShadow.pending = mutableListOf()
        service.onClick()
        val old = TileSelectionShadow.pending!!.removeAt(0)
        service.onStopListening()
        TileSelectionShadow.pending = null
        service.onStartListening()
        assertEquals(Tile.STATE_ACTIVE, LoggingTileServiceShadow.tile?.state)
        val before = LoggingTileShadow.updates
        old(Result.failure(IllegalStateException("old_owner_read_failed")))
        assertEquals(before, LoggingTileShadow.updates)
        assertEquals(Tile.STATE_ACTIVE, LoggingTileServiceShadow.tile?.state)
        controller.destroy()
    }

    @Test fun pinnedStableStateChangesReachTheOpenShadeWithoutAnotherListeningCallback() {
        assumeTrue("Requires the linked stable runtime AAR",
            java.lang.Boolean.getBoolean("nelomai.test.hasStableRuntimeAar"))
        val stable = selection.copy(slot = "stable", runtimeVersion = "0.2.21")
        TileSelectionShadow.result = Result.success(stable)
        val controller = Robolectric.buildService(NelomaiQuickTileService::class.java).create()
        try {
            controller.get().onStartListening()
            val type = Class.forName("ru.nelomai.runtime.stable.tunnel.QuickTunnelController")
            val write = type.declaredMethods.single { it.name.startsWith("updateState") && it.parameterCount == 4 }
            val states = Class.forName("ru.nelomai.runtime.stable.tunnel.SessionState").enumConstants
            for ((state, expected) in listOf("RUNNING" to Tile.STATE_ACTIVE, "STOPPED" to Tile.STATE_INACTIVE)) {
                assertEquals(true, write.invoke(type.getField("INSTANCE").get(null),
                    RuntimeEnvironment.getApplication(), states.single { (it as Enum<*>).name == state }, null, false))
                idle()
                assertEquals(state.lowercase(), RuntimeAdapters.quick(stable).state(RuntimeEnvironment.getApplication()))
                assertEquals(messages().joinToString(), expected, LoggingTileServiceShadow.tile?.state)
            }
        } finally { controller.destroy() }
    }

    @Test fun realProducerRefreshesListeningTileWithoutUiChangeFlag() {
        val controller = Robolectric.buildService(NelomaiQuickTileService::class.java).create()
        val handler = ReflectionHelpers.getField<Handler>(controller.get(), "mHandler")
        handler.sendEmptyMessage(1)
        idle()
        assertEquals(Tile.STATE_ACTIVE, LoggingTileServiceShadow.tile?.state)
        // Module-internal producer, with real persistence and notifications.
        val type = Class.forName("ru.nelomai.tunnel.QuickTunnelController")
        val method = type.declaredMethods.single { it.name.startsWith("updateState") && it.parameterCount == 7 }
        val states = Class.forName("ru.nelomai.tunnel.SessionState").enumConstants
        for ((name, tile) in listOf("STOPPED" to Tile.STATE_INACTIVE,
                "STARTING" to Tile.STATE_UNAVAILABLE, "RUNNING" to Tile.STATE_ACTIVE)) {
            assertEquals(true, method.invoke(type.getField("INSTANCE").get(null),
                RuntimeEnvironment.getApplication(), states.single { (it as Enum<*>).name == name },
                null, false, { true }, null, { _: Long -> }))
            // A second SystemUI listening request alone cannot deliver the update.
            handler.sendEmptyMessage(1)
            idle()
            assertEquals(tile, LoggingTileServiceShadow.tile?.state)
        }
        controller.destroy()
    }

    private fun stateChanged() {
        val context = RuntimeEnvironment.getApplication()
        context.sendBroadcast(Intent("ru.nelomai.tunnel.STATE_CHANGED").setPackage(context.packageName))
    }

    private fun idle() = org.robolectric.Shadows.shadowOf(Looper.getMainLooper()).idle()

    private fun messages() = ShadowLog.getLogsForTag("NelomaiTile")
        .filter { it.msg.startsWith("state.updated") }.map { it.msg }

    private fun engineState(state: String) {
        val slot = ru.nelomai.tunnel.BuildConfig.RUNTIME_SLOT
        val version = ru.nelomai.tunnel.BuildConfig.RUNTIME_VERSION
        RuntimeEnvironment.getApplication().getSharedPreferences(
            "runtime.$slot.state.$version.nelomai-quick-tunnel-state", Context.MODE_PRIVATE,
        ).edit().putString("state", state)
            .putLong("state-updated-at-millis", System.currentTimeMillis()).commit()
    }

    private val selection = RuntimeSelectionV1("latest", "0.3.0", "0.3.0", 7L, null, "tile-test")
}

// Only the owner Binder and SystemUI endpoints are replaced; tile logic and runtime state reads are real.
@Implements(RuntimeSelectionStore::class)
class TileSelectionShadow {
    @Implementation fun read(callback: (Result<RuntimeSelectionV1>) -> Unit) {
        pending?.let { it.add(callback); return }
        callback(result)
    }
    @Implementation fun close() = Unit
    companion object {
        var result: Result<RuntimeSelectionV1> = Result.failure(IllegalStateException())
        var pending: MutableList<(Result<RuntimeSelectionV1>) -> Unit>? = null
    }
}

@Implements(TileService::class)
class LoggingTileServiceShadow : ShadowService() {
    @Implementation fun getQsTile(): Tile? = tile
    @Implementation fun isLocked(): Boolean = locked
    @Implementation fun unlockAndRun(action: Runnable) { afterUnlock = action }
    companion object {
        var tile: Tile? = null
        var locked = false
        var afterUnlock: Runnable? = null
    }
}

@Implements(Tile::class)
class LoggingTileShadow {
    @Implementation fun updateTile() { updates++ }
    companion object { var updates = 0 }
}
