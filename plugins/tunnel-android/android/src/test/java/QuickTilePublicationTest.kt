package ru.nelomai.tunnel

import android.content.ComponentName
import android.content.Context
import android.service.quicksettings.TileService
import org.json.JSONObject
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
    @Test fun explicitUiStartCanDisableSplitWithoutRestoringAnOldPolicy() {
        val storage = QuickTunnelPlanStorage(QuickPlanMemoryBackend())
        storage.prepareForNextStart(QuickTunnelTemplate(TunnelOptionsArgs().apply {
            policyHash = "old-policy"; splitActive = true
        }, quickConnection(true)))
        storage.save(StartTunnelArgs().apply {
            cacheQuickAction = true
            quickConnection = quickConnection(true).apply { leaseId = "ui-lease" }
            options = TunnelOptionsArgs()
        })
        assertNull(storage.loadTemplate()?.options?.policyHash)
        assertFalse(requireNotNull(storage.loadTemplate()).options.splitActive)
    }

    @Test fun policyArrivingAfterFirstStartRepairsNextStartWithoutChangingRunningArgs() {
        checkFirstStartPolicyRace(syncBeforeSave = false)
    }

    @Test fun lateFirstStartSaveCannotRollBackTheSyncedPolicy() {
        checkFirstStartPolicyRace(syncBeforeSave = true)
    }

    private fun checkFirstStartPolicyRace(syncBeforeSave: Boolean) {
        val backend = QuickPlanMemoryBackend()
        val storage = QuickTunnelPlanStorage(backend)
        storage.prepareForNextStart(QuickTunnelTemplate(TunnelOptionsArgs(), quickConnection(true)))
        val captured = requireNotNull(storage.loadTemplate())
        val running = StartTunnelArgs().apply {
            cacheQuickAction = true
            quickPlanRevision = captured.planRevision
            configuration = byteArrayOf(1)
            options = captured.options
            quickConnection = captured.connection.apply { leaseId = "running-lease" }
        }
        val fresh = QuickTunnelTemplate(TunnelOptionsArgs().apply {
            policyHash = "synced-policy"
            splitActive = true
            excludedPackages = arrayListOf("com.example.excluded")
            splitTunnelRoutes = arrayListOf("192.168.0.0/16")
        }, quickConnection(true))
        storage.updateReservePreference(false)
        if (syncBeforeSave) storage.prepareForNextStart(fresh)
        storage.save(requireNotNull(running.copyForQuickPlan()))
        if (!syncBeforeSave) storage.prepareForNextStart(fresh)
        val restored = requireNotNull(QuickTunnelPlanStorage(backend).loadTemplate())
        assertEquals("synced-policy", restored.options.policyHash)
        assertTrue(restored.options.splitActive)
        assertEquals(listOf("com.example.excluded"), restored.options.excludedPackages)
        assertEquals(listOf("192.168.0.0/16"), restored.options.splitTunnelRoutes)
        assertEquals("running-lease", restored.connection.leaseId)
        assertEquals(false, restored.connection.reserveEnabled)
        assertNull(running.options.policyHash)
        assertFalse(running.options.splitActive)
        assertEquals(true, running.quickConnection?.reserveEnabled)
    }

    @Test fun lateTileSaveCannotUndoAnExplicitlyDisabledSyncedPolicy() {
        val storage = QuickTunnelPlanStorage(QuickPlanMemoryBackend())
        storage.prepareForNextStart(QuickTunnelTemplate(TunnelOptionsArgs().apply {
            policyHash = "old-policy"; splitActive = true
        }, quickConnection(true)))
        val captured = requireNotNull(storage.loadTemplate())
        storage.prepareForNextStart(QuickTunnelTemplate(TunnelOptionsArgs(), quickConnection(true)))
        storage.save(StartTunnelArgs().apply {
            cacheQuickAction = true
            quickPlanRevision = captured.planRevision
            quickConnection = captured.connection.apply { leaseId = "late-lease" }
            options = captured.options
        })
        assertNull(storage.loadTemplate()?.options?.policyHash)
        assertFalse(requireNotNull(storage.loadTemplate()).options.splitActive)
        assertEquals("late-lease", storage.loadTemplate()?.connection?.leaseId)
    }

    @Test fun quickPlanRevisionSurvivesRecoveryWithoutChangingThePanelFingerprint() {
        val storage = QuickTunnelPlanStorage(QuickPlanMemoryBackend())
        storage.prepareForNextStart(QuickTunnelTemplate(TunnelOptionsArgs(), quickConnection(true)))
        val template = quickConnectionIntentTemplate("11111111-1111-4111-8111-111111111111",
            requireNotNull(storage.loadTemplate()), 34)
        assertNotNull(template.quickPlanRevision)
        val recovery = AndroidRecoveryStore(QuickPlanMemoryBackend(), BootIdentityProvider { 1 })
        assertTrue(AndroidConnectionIntentCoordinator(recovery).begin(template) is AndroidCoordinatorResult.Accepted)
        val envelope = (recovery.read() as RecoveryStoreResult.Success).value
        val restored = AndroidRecoveryEnvelopeCodec.decode(AndroidRecoveryEnvelopeCodec.encode(envelope))
        assertEquals(template.quickPlanRevision, restored.intent.template?.quickPlanRevision)
        assertEquals(androidConnectionIntentFingerprint(template, true, true),
            androidConnectionIntentFingerprint(template.copy(quickPlanRevision = null), true, true))
    }

    @Test fun legacyQuickPlansWithoutRevisionStillDetectAConcurrentRefresh() {
        val backend = QuickPlanMemoryBackend()
        val storage = QuickTunnelPlanStorage(backend)
        storage.prepareForNextStart(QuickTunnelTemplate(TunnelOptionsArgs(), quickConnection(true)))
        val legacy = JSONObject(String(requireNotNull(backend.read()))).apply { remove("planRevision") }
        backend.write(legacy.toString().toByteArray())
        val captured = requireNotNull(storage.loadTemplate())
        assertNotNull(captured.planRevision)
        storage.updateDnsServers(listOf("77.88.8.8"))
        storage.save(StartTunnelArgs().apply {
            cacheQuickAction = true; quickPlanRevision = captured.planRevision
            quickConnection = captured.connection; options = captured.options
        })
        assertEquals(listOf("77.88.8.8"), storage.loadTemplate()?.options?.dnsServers)
    }

    @Test fun savingAnotherProtocolNeverInheritsThePreviousPlansPolicy() {
        val storage = QuickTunnelPlanStorage(QuickPlanMemoryBackend())
        storage.prepareForNextStart(QuickTunnelTemplate(TunnelOptionsArgs().apply {
            policyHash = "stray-policy"; splitActive = true
        }, quickConnection(true)))
        storage.save(StartTunnelArgs().apply {
            cacheQuickAction = true
            quickConnection = quickConnection(true).apply { layer = "tic"; leaseId = "tic-lease" }
            options = TunnelOptionsArgs()
        })
        val restored = requireNotNull(storage.loadTemplate())
        assertNull(restored.options.policyHash)
        assertFalse(restored.options.splitActive)
        assertEquals("tic-lease", restored.connection.leaseId)
    }

    @Test fun unusedPreparationRefreshesPolicyButKeepsTheUsersReserveChoice() {
        val storage = QuickTunnelPlanStorage(QuickPlanMemoryBackend())
        val fallback = QuickTunnelTemplate(TunnelOptionsArgs(), quickConnection(true))
        assertTrue(storage.prepareForNextStart(fallback))
        assertTrue(storage.updateReservePreference(false))
        val synced = QuickTunnelTemplate(TunnelOptionsArgs().apply {
            splitActive = true
            policyHash = "synced-policy"
            excludedPackages = arrayListOf("com.example.excluded")
            excludeLocalNetworks = true
        }, quickConnection(true))
        assertTrue(storage.prepareForNextStart(synced))
        val restored = requireNotNull(storage.loadTemplate())
        assertEquals("synced-policy", restored.options.policyHash)
        assertTrue(restored.options.splitActive)
        assertEquals(listOf("com.example.excluded"), restored.options.excludedPackages)
        assertTrue(restored.options.excludeLocalNetworks)
        assertEquals(false, restored.connection.reserveEnabled)
        assertEquals("", restored.connection.leaseId)
    }

    @Test fun preparationRefreshesFutureOptionsButCannotChangeOwnershipOrAnotherProtocol() {
        val storage = QuickTunnelPlanStorage(QuickPlanMemoryBackend())
        val saved = StartTunnelArgs().apply {
            cacheQuickAction = true
            quickConnection = quickConnection(true).apply { leaseId = "working-lease" }
            options = TunnelOptionsArgs().apply { policyHash = "working-policy" }
        }
        storage.save(saved)
        val late = QuickTunnelTemplate(TunnelOptionsArgs().apply { policyHash = "late-policy" }, quickConnection(true))
        assertTrue(storage.prepareForNextStart(late))
        assertEquals("late-policy", storage.loadTemplate()?.options?.policyHash)
        assertEquals("working-lease", storage.loadTemplate()?.connection?.leaseId)
        assertEquals("working-policy", saved.options.policyHash)
        saved.quickConnection?.leaseId = ""
        saved.quickConnection?.layer = "tic"
        storage.save(saved)
        assertTrue(storage.prepareForNextStart(late))
        assertEquals("working-policy", storage.loadTemplate()?.options?.policyHash)
        assertEquals("tic", storage.loadTemplate()?.connection?.layer)
    }

    @Test fun preparationCreatesMissingTemplateWithoutLeaseAndPreservesExistingPlan() {
        val storage = QuickTunnelPlanStorage(QuickPlanMemoryBackend())
        storage.updateReservePreference(false)
        val prepared = QuickTunnelTemplate(TunnelOptionsArgs().apply {
            dnsServers = arrayListOf("9.9.9.9")
            excludeLocalNetworks = true
        }, quickConnection(true))
        assertTrue(storage.prepareForNextStart(prepared))
        assertEquals("", storage.loadTemplate()?.connection?.leaseId)
        assertEquals(false, storage.loadTemplate()?.connection?.reserveEnabled)
        assertEquals(listOf("9.9.9.9"), storage.loadTemplate()?.options?.dnsServers)
        val old = StartTunnelArgs().apply { cacheQuickAction = true; quickConnection = quickConnection(true).apply { leaseId = "active-lease" } }
        storage.save(old)
        assertTrue(storage.prepareForNextStart(prepared))
        assertEquals("active-lease", storage.loadTemplate()?.connection?.leaseId)
    }

    @Test fun corruptNewLegacyEnvelopeMustNotBeMistakenForMissingSource() {
        val context = RuntimeEnvironment.getApplication()
        val name = "nelomai-quick-tunnel-plan"
        context.getSharedPreferences(name, Context.MODE_PRIVATE).edit()
            .putString("encrypted-envelope-v1", "AA==").commit()
        val source = AndroidNativeRuntimeStorageAccess(context).source(name, "encrypted-envelope-v1")
        assertThrows(EncryptedRecordCorruptException::class.java) { source.read() }
        assertTrue(context.getSharedPreferences(name, Context.MODE_PRIVATE).contains("encrypted-envelope-v1"))
    }

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
