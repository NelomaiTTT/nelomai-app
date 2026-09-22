package ru.nelomai.client

import android.content.Context
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements
import org.robolectric.shadows.ShadowLog
import org.robolectric.shadows.ShadowService
import org.robolectric.util.ReflectionHelpers

@RunWith(RobolectricTestRunner::class)
@Config(
    sdk = [34], application = android.app.Application::class,
    shadows = [TileSelectionShadow::class, LoggingTileServiceShadow::class, LoggingTileShadow::class],
)
class QuickTileLoggingTest {
    @Before fun setUp() {
        TileSelectionShadow.result = Result.success(selection)
        LoggingTileServiceShadow.tile = ReflectionHelpers.callConstructor(Tile::class.java)
        LoggingTileShadow.updates = 0
        ShadowLog.clear()
        engineState("running")
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
    @Implementation fun read(callback: (Result<RuntimeSelectionV1>) -> Unit) { callback(result) }
    @Implementation fun close() = Unit
    companion object { var result: Result<RuntimeSelectionV1> = Result.failure(IllegalStateException()) }
}

@Implements(TileService::class)
class LoggingTileServiceShadow : ShadowService() {
    @Implementation fun getQsTile(): Tile? = tile
    companion object { var tile: Tile? = null }
}

@Implements(Tile::class)
class LoggingTileShadow {
    @Implementation fun updateTile() { updates++ }
    companion object { var updates = 0 }
}
