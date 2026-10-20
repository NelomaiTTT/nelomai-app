package ru.nelomai.client

import android.content.Intent
import android.os.Bundle
import android.os.ResultReceiver
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

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class,
    shadows = [TileSelectionShadow::class, StableEnvelopeIoShadow::class])
class StableBackgroundDispatcherTest {
    private val selected = RuntimeSelectionV1("stable", "0.2.20", "0.3.5", 9, null, "stable-test")
    private val device = "11111111-1111-4111-8111-111111111111"
    private fun scope(slot: String, generation: Long) = JSONObject()
        .put("auth_epoch", 3).put("family", "login-family").put("device_id", device)
        .put("identity", JSONObject().put("slot", slot).put("container_version", "0.3.5")
            .put("runtime_version", if (slot == "stable") "0.2.20" else "0.3.5")
            .put("runtime_contract_version", 1).put("session_generation", generation))
    private fun request(generation: Long = 9) = JSONObject().put("device_id", device)
        .put("access_token", "current-bearer").put("install_secret", "install-secret")
        .put("owner_operation", JSONObject().put("ticket", scope("stable", generation)
            .put("operation_id", "22222222-2222-4222-8222-222222222222").put("attempt", 3))
            .put("expires_at_unix_ms", System.currentTimeMillis() + 9000)
            .put("provision_predecessor", scope("latest", 8)).toString()).toString()

    @Before fun setUp() {
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
        var result: Pair<Int, Bundle?>? = null
        val receiver = object : ResultReceiver(null) {
            override fun onReceiveResult(code: Int, data: Bundle?) { result = code to data }
        }
        service.onStartCommand(Intent().setAction(RuntimeServiceIntents.PREPARE_STABLE_BACKGROUND)
            .putExtra(RuntimeServiceIntents.STABLE_PROVISION_REQUEST, wire)
            .putExtra("result_receiver", receiver), 0, 1)
        assertNull(ReflectionHelpers.getField<Any?>(service, "engine"))
        return requireNotNull(result)
    }

    @Test fun dispatcherPreparesTheRecordBeforeConstructingImmutableStableEngine() {
        val controller = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        val (code, data) = dispatch(controller.get(), request())
        assertEquals(1, code)
        assertFalse(data!!.getBoolean("restart_required"))
        val saved = JSONObject(String(StableEnvelopeIoShadow.bytes!!))
        assertEquals(9L, saved.getJSONObject("ownerScope").getJSONObject("identity").getLong("session_generation"))
        assertFalse(saved.has("active"))
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

    @Test fun serviceRecreationDoesNotStandInForPhysicalProcessExit() {
        ReflectionHelpers.setStaticField(RuntimeVpnDispatcherService::class.java, "engineWasLoaded", true)
        val before = StableEnvelopeIoShadow.bytes!!.clone()
        repeat(2) {
            val controller = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
            val (code, data) = dispatch(controller.get(), request())
            assertEquals(1, code)
            assertTrue(data!!.getBoolean("restart_required"))
            assertArrayEquals(before, StableEnvelopeIoShadow.bytes)
            controller.destroy()
        }
    }
}

/** Replace only encrypted Android I/O; ownership and migration code remain real. */
@Implements(className = "ru.nelomai.tunnel.AndroidSecureEnvelopeBackend", isInAndroidSdk = false)
class StableEnvelopeIoShadow {
    @RealObject private lateinit var backend: Any
    private fun requireStableNamespace() {
        val name = "runtime.stable.state.0.2.20.nelomai-background-credential"
        require(ReflectionHelpers.getField<String>(backend, "preferenceName") == name)
        require(ReflectionHelpers.getField<String>(backend, "keyAlias") == name)
        require(ReflectionHelpers.getField<String>(backend, "recordName") == "encrypted-envelope-v3")
    }
    @Implementation fun read(): ByteArray? { requireStableNamespace(); return bytes?.clone() }
    @Implementation fun write(value: ByteArray): Boolean { requireStableNamespace(); bytes = value.clone(); return true }
    companion object { var bytes: ByteArray? = null }
}
