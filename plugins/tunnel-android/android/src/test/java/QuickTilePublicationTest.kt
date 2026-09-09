package ru.nelomai.tunnel

import android.content.ComponentName
import android.content.Context
import android.service.quicksettings.TileService
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE, shadows = [TileRefreshRecorder::class])
class QuickTilePublicationTest {
    @Test fun everyCommittedTransitionWakesTileEvenWithoutUiChangeFlag() {
        val context = RuntimeEnvironment.getApplication()
        val observed = mutableListOf<String?>()
        TileRefreshRecorder.onRequest = { ctx, component ->
            assertEquals("ru.nelomai.client.NelomaiQuickTileService", component.className)
            assertEquals(ctx.packageName, component.packageName)
            observed += ctx.getSharedPreferences(
                AndroidRuntimeNamespace.record("nelomai-quick-tunnel-state"), 0).getString("state", null)
        }
        try {
            repeat(2) {
                for (state in listOf(SessionState.STARTING, SessionState.RUNNING,
                        SessionState.STOPPING, SessionState.STOPPED)) {
                    assertTrue(QuickTunnelController.updateState(context, state, changed = false))
                }
            }
            assertEquals(listOf("starting", "running", "stopping", "stopped",
                "starting", "running", "stopping", "stopped"), observed)
        } finally { TileRefreshRecorder.onRequest = { _, _ -> } }
    }
}

/** Only Android's external SystemUI endpoint is replaced; persistence is real. */
@Implements(TileService::class)
class TileRefreshRecorder {
    companion object {
        var onRequest: (Context, ComponentName) -> Unit = { _, _ -> }
        @JvmStatic @Implementation
        fun requestListeningState(context: Context, component: ComponentName) = onRequest(context, component)
    }
}
