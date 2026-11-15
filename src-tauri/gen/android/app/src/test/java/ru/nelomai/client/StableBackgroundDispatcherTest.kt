package ru.nelomai.client

import android.content.Intent
import android.os.Bundle
import android.os.ResultReceiver
import android.os.Messenger
import android.os.Message
import android.os.Parcel
import android.os.Looper
import org.robolectric.Shadows.shadowOf
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements
import org.robolectric.annotation.RealObject
import org.robolectric.util.ReflectionHelpers
import ru.nelomai.runtime.v1.RuntimeServiceIntents
import ru.nelomai.runtime.v1.RuntimeVpnEngineV1
import ru.nelomai.runtime.v1.RuntimeVpnHostV1

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class,
    shadows = [TileSelectionShadow::class, StableEnvelopeIoShadow::class, StableEngineAdapterShadow::class])
class StableBackgroundDispatcherTest {
    private var selected = RuntimeSelectionV1("stable", "0.2.20", "0.3.5", 9, null, "stable-test")
    private val device = "11111111-1111-4111-8111-111111111111"
    private fun scope(slot: String, generation: Long) = JSONObject()
        .put("auth_epoch", 3).put("family", "login-family").put("device_id", device)
        .put("identity", JSONObject().put("slot", slot).put("container_version", "0.3.5")
            .put("runtime_version", if (slot == "stable") selected.runtimeVersion else "0.3.5")
            .put("runtime_contract_version", 1).put("session_generation", generation))
    private fun request(generation: Long = 9) = JSONObject().put("device_id", device)
        .put("access_token", "current-bearer").put("install_secret", "install-secret")
        .put("owner_operation", JSONObject().put("ticket", scope("stable", generation)
            .put("operation_id", "22222222-2222-4222-8222-222222222222").put("attempt", 3))
            .put("expires_at_unix_ms", System.currentTimeMillis() + 9000)
            .put("provision_predecessor", scope("latest", 8)).toString()).toString()

    @Before fun setUp() {
        StableEnvelopeIoShadow.version = selected.runtimeVersion
        StableEnvelopeIoShadow.generationBytes = null
        StableEnvelopeIoShadow.failNativeWrites = false
        StableEnvelopeIoShadow.cacheFailedWrite = false
        StableEngineAdapterShadow.generations.clear()
        StableEngineAdapterShadow.starts = 0
        StableEngineAdapterShadow.actions.clear()
        StableEngineAdapterShadow.lastStartId = 0
        TileSelectionShadow.result = Result.success(selected)
        ReflectionHelpers.setStaticField(RuntimeProcessSelection::class.java, "loaded", null)
        ReflectionHelpers.setStaticField(RuntimeProcessSelection::class.java, "admitted", false)
        ReflectionHelpers.setStaticField(RuntimeVpnDispatcherService::class.java, "engineWasLoaded", false)
        StableEnvelopeIoShadow.bytes = JSONObject().put("formatVersion", 3).put("revision", 2)
            .put("deviceId", device).put("panelBase", "https://nelomai.ru")
            .put("installSecret", "install-secret").put("installGeneration", 1)
            .put("ownerScope", scope("stable", 5)).put("ownerAttempt", 1)
            .put("active", JSONObject().put("deviceId", device).put("panelBase", "https://nelomai.ru")
                .put("token", "revoked-token").put("expiresAtUnix", 9999999999L))
            .toString().toByteArray()
    }

    private fun dispatch(service: RuntimeVpnDispatcherService, wire: String): Pair<Int, Bundle?> {
        val previousEngine = ReflectionHelpers.getField<Any?>(service, "engine")
        var result: Pair<Int, Bundle?>? = null
        val receiver = Messenger(android.os.Handler(Looper.getMainLooper()) { reply ->
            result = reply.what to reply.data
            true
        })
        val request = Message.obtain(null, 1).apply {
            replyTo = receiver
            data = Bundle().apply { putString(RuntimeServiceIntents.STABLE_PROVISION_REQUEST, wire) }
        }
        val parcel = Parcel.obtain()
        val transferred = try {
            request.writeToParcel(parcel, 0)
            parcel.setDataPosition(0)
            Message.CREATOR.createFromParcel(parcel)
        } finally { parcel.recycle() }
        Messenger(service.onBind(Intent(RuntimeServiceIntents.PREPARE_STABLE_BACKGROUND))).send(transferred)
        shadowOf(Looper.getMainLooper()).idle()
        assertSame(previousEngine, ReflectionHelpers.getField<Any?>(service, "engine"))
        return requireNotNull(result)
    }

    @Test fun recreatedBrokerCannotLeaveBoundOnlyProcessPermanentlyFenced() {
        val first = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        assertEquals(1, dispatch(first.get(), request()).first)
        first.destroy()
        assertTrue(StableEngineAdapterShadow.generations.isEmpty())
        val before = StableEnvelopeIoShadow.bytes!!.clone()
        selected = selected.copy(incarnation = "broker-recreated")
        TileSelectionShadow.result = Result.success(selected)
        val second = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        assertEquals(2, dispatch(second.get(), request()).first)
        assertArrayEquals(before, StableEnvelopeIoShadow.bytes)
        assertTrue(org.robolectric.shadows.ShadowProcess.wasKilled(android.os.Process.myPid()))
        second.destroy()
        // Real process exit resets the process fence; a new binding succeeds.
        ReflectionHelpers.setStaticField(RuntimeProcessSelection::class.java, "loaded", null)
        val third = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        assertEquals(1, dispatch(third.get(), request()).first)
        third.destroy()
    }

    @Test fun systemVpnBindingStillDelegatesToAndroidAndExpiredPreparationDoesNotMutate() {
        val controller = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        assertNotNull(controller.get().onBind(Intent(android.net.VpnService.SERVICE_INTERFACE)))
        val before = StableEnvelopeIoShadow.bytes!!.clone()
        val wire = JSONObject(request())
        val op = JSONObject(wire.getString("owner_operation")).put("expires_at_unix_ms", System.currentTimeMillis() - 1)
        wire.put("owner_operation", op.toString())
        assertEquals(2, dispatch(controller.get(), wire.toString()).first)
        assertArrayEquals(before, StableEnvelopeIoShadow.bytes)
        assertNull(StableEnvelopeIoShadow.generationBytes)
        assertTrue(StableEngineAdapterShadow.actions.isEmpty())
        controller.destroy()
    }

    @Test fun anotherUidCannotPrepareCredentials() {
        val controller = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        val before = StableEnvelopeIoShadow.bytes!!.clone()
        var replied = false
        val receiver = Messenger(android.os.Handler(Looper.getMainLooper()) { replied = true; true })
        val previous = android.os.Binder.getCallingUid()
        try {
            org.robolectric.shadows.ShadowBinder.setCallingUid(android.os.Process.myUid() + 1)
            Messenger(controller.get().onBind(Intent(RuntimeServiceIntents.PREPARE_STABLE_BACKGROUND))).send(
                Message.obtain(null, 1).apply {
                    replyTo = receiver
                    data = Bundle().apply { putString(RuntimeServiceIntents.STABLE_PROVISION_REQUEST, request()) }
                })
        } finally { org.robolectric.shadows.ShadowBinder.setCallingUid(previous) }
        shadowOf(Looper.getMainLooper()).idle()
        assertFalse(replied)
        assertArrayEquals(before, StableEnvelopeIoShadow.bytes)
        assertNull(StableEnvelopeIoShadow.generationBytes)
        controller.destroy()
    }

    @Test fun dispatcherPreparesTheRecordBeforeConstructingImmutableStableEngine() {
        val controller = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        val (code, data) = dispatch(controller.get(), request())
        assertEquals(1, code)
        assertFalse(data!!.getBoolean("restart_required"))
        val saved = JSONObject(String(StableEnvelopeIoShadow.bytes!!))
        assertEquals(9L, saved.getJSONObject("ownerScope").getJSONObject("identity").getLong("session_generation"))
        assertFalse(saved.has("active"))
        assertTrue(saved.getLong("installGeneration") > 1)
        controller.destroy()
    }

    @Test fun selectedStableVersionControlsPreparationAndStorageNamespace() {
        for (version in listOf("0.2.21", "9.8.7")) {
            selected = selected.copy(runtimeVersion = version)
            setUp()
            dispatcherPreparesTheRecordBeforeConstructingImmutableStableEngine()
        }
    }

    @Test fun anotherRuntimeVersionNeverMutatesSelectedStableStorage() {
        selected = selected.copy(runtimeVersion = "9.8.7")
        setUp()
        val before = StableEnvelopeIoShadow.bytes!!.clone()
        val input = JSONObject(request())
        val owner = JSONObject(input.getString("owner_operation"))
        owner.getJSONObject("ticket").getJSONObject("identity").put("runtime_version", "9.8.6")
        input.put("owner_operation", owner.toString())
        val controller = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        assertEquals(2, dispatch(controller.get(), input.toString()).first)
        assertArrayEquals(before, StableEnvelopeIoShadow.bytes)
        controller.destroy()
    }

    @Test fun completedResumeCanRetireAnOldReservationBeforeLoadingStable() {
        val retained = JSONObject(String(StableEnvelopeIoShadow.bytes!!))
        retained.put("reservation", JSONObject().put("mutationId", "old-prepare")
            .put("activationOperationId", "old-activate").put("deviceId", device)
            .put("expiresAtUnix", 3000))
        StableEnvelopeIoShadow.bytes = retained.toString().toByteArray()
        val input = JSONObject(request())
        val operation = JSONObject(input.getString("owner_operation"))
        operation.getJSONObject("provision_predecessor")
            .put("reconcile_operation_id", "44444444-4444-4444-8444-444444444444")
            .put("resume_operation_id", "55555555-5555-4555-8555-555555555555")
        input.put("owner_operation", operation.toString())
        val controller = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        val (code, data) = dispatch(controller.get(), input.toString())
        assertEquals(1, code)
        assertFalse(data!!.getBoolean("restart_required"))
        val saved = JSONObject(String(StableEnvelopeIoShadow.bytes!!))
        assertEquals(9L, saved.getJSONObject("ownerScope").getJSONObject("identity").getLong("session_generation"))
        assertFalse(saved.has("reservation"))
        assertFalse(saved.has("active"))
        controller.destroy()
    }

    @Test fun staleSelectionAndPendingTransitionNeverMutateTheRecord() {
        val before = StableEnvelopeIoShadow.bytes!!.clone()
        val controller = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        assertEquals(2, dispatch(controller.get(), request(8)).first)
        TileSelectionShadow.result = Result.success(selected.copy(pendingSlot = "latest"))
        assertEquals(2, dispatch(controller.get(), request()).first)
        assertArrayEquals(before, StableEnvelopeIoShadow.bytes)
        controller.destroy()
    }

    @Test fun counterIsPreparedBeforeEngineReadsCredentialsAndDoesNotRestartRunningOwner() {
        val record = JSONObject(String(StableEnvelopeIoShadow.bytes!!)).put("ownerScope", scope("stable", 9))
        StableEnvelopeIoShadow.bytes = record.toString().toByteArray()
        val controller = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        controller.get().onStartCommand(Intent("background_status"), 0, 1)
        assertEquals(listOf(2L), StableEngineAdapterShadow.generations)
        assertEquals(1, StableEngineAdapterShadow.starts)
        val before = StableEnvelopeIoShadow.bytes!!.clone()
        val (code, reply) = dispatch(controller.get(), request())
        assertEquals(1, code)
        assertFalse(reply!!.getBoolean("restart_required"))
        assertArrayEquals(before, StableEnvelopeIoShadow.bytes)
        assertEquals("revoked-token", JSONObject(String(before)).getJSONObject("active").getString("token"))
        assertEquals(1, StableEngineAdapterShadow.starts)
        controller.destroy()
    }

    @Test fun unexpectedLoadedCounterMismatchFailsWithoutRequestingForceExit() {
        StableEnvelopeIoShadow.bytes = JSONObject(String(StableEnvelopeIoShadow.bytes!!))
            .put("ownerScope", scope("stable", 9)).toString().toByteArray()
        ReflectionHelpers.setStaticField(RuntimeVpnDispatcherService::class.java, "engineWasLoaded", true)
        val before = StableEnvelopeIoShadow.bytes!!.clone()
        val controller = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        val (code, reply) = dispatch(controller.get(), request())
        assertEquals(2, code)
        assertFalse(reply!!.getBoolean("restart_required"))
        assertArrayEquals(before, StableEnvelopeIoShadow.bytes)
        assertTrue(StableEngineAdapterShadow.generations.isEmpty())
        controller.destroy()
    }

    @Test fun serviceRecreationCannotRewriteCredentialsHeldByAnEarlierEngine() {
        val first = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        first.get().onStartCommand(Intent("background_status"), 0, 1)
        assertEquals(listOf(2L), StableEngineAdapterShadow.generations)
        val before = StableEnvelopeIoShadow.bytes!!.clone()
        first.destroy()
        StableEnvelopeIoShadow.generationBytes = JSONObject().put("format", 1).put("generation", 9)
            .put("operationKey", "other-process-operation").toString().toByteArray()
        val second = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        second.get().onStartCommand(Intent("background_status"), 0, 1)
        assertEquals(listOf(2L, 2L), StableEngineAdapterShadow.generations)
        assertArrayEquals(before, StableEnvelopeIoShadow.bytes)
        second.destroy()
    }

    @Test fun failedCounterProjectionNeverConstructsEngineAndRetryReusesReservation() {
        val before = StableEnvelopeIoShadow.bytes!!.clone()
        StableEnvelopeIoShadow.failNativeWrites = true
        val first = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        first.get().onStartCommand(Intent("background_status"), 0, 1)
        assertTrue(StableEngineAdapterShadow.generations.isEmpty())
        assertArrayEquals(before, StableEnvelopeIoShadow.bytes)
        val reserved = StableEnvelopeIoShadow.generationBytes!!.clone()
        first.destroy()
        StableEnvelopeIoShadow.failNativeWrites = false
        val second = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        second.get().onStartCommand(Intent("background_status"), 0, 1)
        assertEquals(listOf(2L), StableEngineAdapterShadow.generations)
        assertArrayEquals(reserved, StableEnvelopeIoShadow.generationBytes)
        second.destroy()
    }

    @Test fun failedNativeCommitCacheCannotAdmitEngineBeforeDurableRetry() {
        StableEnvelopeIoShadow.failNativeWrites = true
        StableEnvelopeIoShadow.cacheFailedWrite = true
        val replies = mutableListOf<Pair<Int, String?>>()
        val receiver = object : ResultReceiver(null) {
            override fun onReceiveResult(code: Int, data: Bundle?) {
                replies += code to data?.getString("error_code")
            }
        }
        val first = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        repeat(2) {
            first.get().onStartCommand(Intent("background_status").putExtra("result_receiver", receiver), 0, 1)
            assertTrue(StableEngineAdapterShadow.generations.isEmpty())
        }
        assertEquals(listOf(2 to "background_credential_unavailable", 2 to "background_credential_unavailable"), replies)
        val reservation = StableEnvelopeIoShadow.generationBytes!!.clone()
        first.destroy()
        StableEnvelopeIoShadow.failNativeWrites = false
        val second = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        second.get().onStartCommand(Intent("background_status"), 0, 1)
        assertEquals(listOf(2L), StableEngineAdapterShadow.generations)
        assertArrayEquals(reservation, StableEnvelopeIoShadow.generationBytes)
        second.destroy()
    }

    @Test fun delayedNewLoginPreparationCannotForceExitALoadedFinalizedEngine() {
        // Immutable stable can run a legacy foreground tunnel while the earlier
        // completed receipt is retained and first background provision failed.
        val record = JSONObject(String(StableEnvelopeIoShadow.bytes!!))
            .put("logoutState", JSONObject().put("operationId", "completed-logout")
                .put("installGeneration", 1).put("phase", "finalized"))
            .put("ownerScope", scope("stable", 5).put("auth_epoch", 1))
            .put("ownerCancelEpoch", 2)
        record.remove("installSecret")
        record.remove("active")
        StableEnvelopeIoShadow.bytes = record.toString().toByteArray()
        val controller = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        controller.get().onStartCommand(Intent("ru.nelomai.tunnel.CLIENT_START"), 0, 1)
        assertEquals(1, StableEngineAdapterShadow.starts)
        val before = StableEnvelopeIoShadow.bytes!!.clone()
        val (code, reply) = dispatch(controller.get(), request())
        // The owner force-kills :vpn on restart_required; a delayed generation
        // migration must defer instead, even for an old clean FINALIZED marker.
        assertEquals(2, code)
        assertFalse(reply!!.getBoolean("restart_required"))
        assertArrayEquals(before, StableEnvelopeIoShadow.bytes)
        assertEquals(1, StableEngineAdapterShadow.starts)
        controller.destroy()
    }

    @Test fun boundPreparationDoesNotAdvanceStartedEngineIdOrDisturbItsWork() {
        val record = JSONObject(String(StableEnvelopeIoShadow.bytes!!))
            .put("logoutState", JSONObject().put("operationId", "completed-logout")
                .put("installGeneration", 1).put("phase", "finalized"))
            .put("ownerScope", scope("stable", 5).put("auth_epoch", 1))
            .put("ownerCancelEpoch", 2)
        record.remove("installSecret"); record.remove("active")
        StableEnvelopeIoShadow.bytes = record.toString().toByteArray()
        val first = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        first.get().onStartCommand(Intent("background_status"), 0, 1)
        val (code, reply) = dispatch(first.get(), request())
        assertEquals(2, code)
        assertFalse(reply!!.getBoolean("restart_required"))
        assertEquals(1, StableEngineAdapterShadow.lastStartId)
        assertEquals(1, StableEngineAdapterShadow.starts)
        assertFalse(shadowOf(first.get()).isStoppedBySelf)
        // Only physical exit (not service recreation) unlocks namespace migration.
        first.destroy()
        ReflectionHelpers.setStaticField(RuntimeVpnDispatcherService::class.java, "engineWasLoaded", false)
        val second = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        assertEquals(1, dispatch(second.get(), request()).first)
        assertFalse(JSONObject(String(StableEnvelopeIoShadow.bytes!!)).has("logoutState"))
        second.destroy()
    }

    @Test fun serviceRecreationDoesNotStandInForPhysicalProcessExit() {
        ReflectionHelpers.setStaticField(RuntimeVpnDispatcherService::class.java, "engineWasLoaded", true)
        val before = StableEnvelopeIoShadow.bytes!!.clone()
        repeat(2) {
            val controller = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
            val (code, data) = dispatch(controller.get(), request())
            assertEquals(2, code)
            assertFalse(data!!.getBoolean("restart_required"))
            assertArrayEquals(before, StableEnvelopeIoShadow.bytes)
            controller.destroy()
        }
    }
}

/** Replace only encrypted Android I/O; ownership and migration code remain real. */
@Implements(className = "ru.nelomai.tunnel.AndroidSecureEnvelopeBackend", isInAndroidSdk = false)
class StableEnvelopeIoShadow {
    @RealObject private lateinit var backend: Any
    private fun isGenerationRecord(): Boolean {
        val name = ReflectionHelpers.getField<String>(backend, "preferenceName")
        require(ReflectionHelpers.getField<String>(backend, "keyAlias") == name)
        if (name == "nelomai-install-generation") {
            require(ReflectionHelpers.getField<String>(backend, "recordName") == "generation-v1")
            return true
        }
        require(name == "runtime.stable.state.$version.nelomai-background-credential")
        require(ReflectionHelpers.getField<String>(backend, "recordName") == "encrypted-envelope-v3")
        return false
    }
    @Implementation fun read(): ByteArray? = if (isGenerationRecord()) generationBytes?.clone() else bytes?.clone()
    @Implementation fun write(value: ByteArray): Boolean {
        if (isGenerationRecord()) generationBytes = value.clone() else {
            if (failNativeWrites) {
                if (cacheFailedWrite) bytes = value.clone()
                return false
            }
            bytes = value.clone()
        }
        return true
    }
    companion object {
        var bytes: ByteArray? = null
        var generationBytes: ByteArray? = null
        var failNativeWrites = false
        var cacheFailedWrite = false
        var version = "0.2.20"
    }
}

/** Replace the immutable native engine only; dispatcher and storage preparation remain real. */
@Implements(RuntimeAdapters::class, isInAndroidSdk = false)
class StableEngineAdapterShadow {
    @Suppress("UNUSED_PARAMETER")
    @Implementation fun engine(selected: RuntimeSelectionV1, host: RuntimeVpnHostV1): RuntimeVpnEngineV1 {
        require(selected.slot == "stable")
        generations += JSONObject(String(StableEnvelopeIoShadow.bytes!!)).getLong("installGeneration")
        return object : RuntimeVpnEngineV1 {
            override fun requiresStartAdmission(intent: Intent?) = false
            override fun create() = Unit
            override fun start(intent: Intent?, flags: Int, startId: Int): Int {
                starts++; actions += intent?.action; lastStartId = startId
                return 1
            }
            override fun revoke() = Unit
            override fun taskRemoved(intent: Intent?) = Unit
            override fun destroy() = Unit
        }
    }
    companion object {
        val generations = mutableListOf<Long>()
        val actions = mutableListOf<String?>()
        var starts = 0
        var lastStartId = 0
    }
}
