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
    @Test fun reservePreferenceSurvivesLatePlanSaveAndNeverChangesLiveStartArgs() {
        val backend = QuickPlanMemoryBackend()
        val storage = QuickTunnelPlanStorage(backend)
        val args = StartTunnelArgs().apply {
            cacheQuickAction = true
            quickConnection = quickConnection(true)
        }
        storage.save(args)
        for (enabled in listOf(false, true, false)) {
            assertTrue(storage.updateReservePreference(enabled))
            // A running UI start may publish its old plan after the preference changed.
            storage.save(args)
            assertEquals(enabled, QuickTunnelPlanStorage(backend).loadTemplate()?.connection?.reserveEnabled)
            assertEquals(true, args.quickConnection?.reserveEnabled)
        }
        backend.failWrites = true
        assertFalse(storage.updateReservePreference(true))
        assertEquals(false, storage.loadTemplate()?.connection?.reserveEnabled)
    }

    @Test fun reservePreferenceBeforeFirstPlanDoesNotUpgradeLegacyTemplates() {
        val storage = QuickTunnelPlanStorage(QuickPlanMemoryBackend())
        assertTrue(storage.updateReservePreference(false))
        assertNull(storage.loadTemplate())
        assertTrue(storage.updateDnsServers(listOf("9.9.9.9")))
        val args = StartTunnelArgs().apply {
            cacheQuickAction = true
            quickConnection = quickConnection(null)
        }
        storage.save(args)
        assertNull(storage.loadTemplate()?.connection?.reserveEnabled)
        args.quickConnection?.reserveEnabled = true
        storage.save(args)
        assertEquals(false, storage.loadTemplate()?.connection?.reserveEnabled)
        assertTrue(storage.updateDnsServers(listOf("9.9.9.9")))
        assertEquals(listOf("9.9.9.9"), storage.loadTemplate()?.options?.dnsServers)
        assertEquals(false, storage.loadTemplate()?.connection?.reserveEnabled)
        assertTrue(storage.clear())
        storage.save(args)
        assertEquals(true, storage.loadTemplate()?.connection?.reserveEnabled)
    }

    private fun quickConnection(reserve: Boolean?) = QuickConnectionArgs().apply {
        leaseId = ""; layer = "stray"; ticConnectionMode = "dynamic"
        routeMode = "standalone"; reserveEnabled = reserve
    }

    @Test fun storedQuickPlanAndServiceIpcPreserveBothReserveChoicesAndLegacyAbsence() {
        for (choice in listOf(null, false, true)) {
            val original = QuickConnectionArgs().apply {
                leaseId = ""; layer = "stray"; ticConnectionMode = "dynamic"
                routeMode = "standalone"; reserveEnabled = choice
            }
            val fromService = original.toBundle().toQuickConnection()
            val restored = fromService.toStoredQuickConnectionJson().toStoredQuickConnection()
            assertEquals(choice, restored.reserveEnabled)
            assertEquals("", restored.leaseId)
        }
    }

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

private class QuickPlanMemoryBackend : EncryptedRecordBackend {
    private var bytes: ByteArray? = null
    var failWrites = false
    override fun read(): ByteArray? = bytes?.copyOf()
    override fun write(plaintext: ByteArray): Boolean {
        if (failWrites) return false
        bytes = plaintext.copyOf()
        return true
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
