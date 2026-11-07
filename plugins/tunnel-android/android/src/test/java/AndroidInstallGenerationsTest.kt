package ru.nelomai.tunnel

import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import java.io.File
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements
import org.robolectric.annotation.RealObject
import org.robolectric.util.ReflectionHelpers

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class, shadows = [GenerationEnvelopeIoShadow::class])
class AndroidInstallGenerationsTest {
    private lateinit var context: Context
    private val modes = mutableListOf<Int>()
    private val device = "11111111-1111-4111-8111-111111111111"
    @Before fun setup() {
        GenerationEnvelopeIoShadow.records.clear()
        context = object : ContextWrapper(RuntimeEnvironment.getApplication()) {
            override fun getApplicationContext(): Context = this
            override fun getSharedPreferences(name: String, mode: Int): SharedPreferences {
                modes += mode
                return super.getSharedPreferences(name, mode)
            }
        }
        AndroidBackgroundCredentialStores.resetForTests()
    }
    private fun seed(name: String, generation: Long, backup: Boolean = false) {
        // Actual preference file discovery, with encrypted I/O alone replaced.
        context.getSharedPreferences(name, 0).edit().putString("test", "marker").commit()
        GenerationEnvelopeIoShadow.records[name] = BackgroundCredentialEnvelopeCodec.encode(
            BackgroundCredentialEnvelope(revision = 1, installGeneration = generation))
        if (backup) {
            val file = File(context.applicationInfo.dataDir, "shared_prefs/$name.xml")
            check(file.renameTo(File(file.path + ".bak")))
        }
    }
    @Suppress("DEPRECATION")
    @Test fun productionFactoryUsesInstallationLedgerAndReloadsRetainedNamespaces() {
        seed("runtime.latest.state.0.0.1.nelomai-background-credential", 9)
        seed("runtime.stable.state.0.2.21.nelomai-background-credential", 5)
        seed("runtime.latest.state.0.0.2.nelomai-background-credential", 11, backup = true)
        val store = AndroidBackgroundCredentialStores.open(context)
        assertTrue(store.configure(0, BackgroundCredentialProvision(device, "https://nelomai.ru", "token",
            9999999999, "install-secret", 1, BackgroundCapabilitySnapshot(0, false, 1))) is CredentialStoreResult.Success)
        val pending = (store.beginLogoutCurrent("logout") as CredentialStoreResult.Success).value.envelope
        assertEquals(12L, pending.logoutState?.installGeneration)
        val after = modes.drop(4) // three seeds + ordinary scoped store
        assertTrue(after.isNotEmpty())
        assertTrue(after.all { it and Context.MODE_MULTI_PROCESS != 0 })
        assertTrue(File(context.filesDir, "common/background-install-generation.lock").isFile)
    }
    @Test fun existingLedgerFileWithoutItsRecordCannotBecomeANewCounter() {
        context.getSharedPreferences("nelomai-install-generation", 0).edit()
            .putString("unexpected", "retained").commit()
        assertThrows(IllegalStateException::class.java) {
            AndroidInstallGenerations.reserve(context, 1, "must-not-reset")
        }
        assertNull(GenerationEnvelopeIoShadow.records["nelomai-install-generation"])
    }

    @Test fun stableEnginePreparationMakesLoadedOwnerProvisionANoop() {
        val scope = NativeOwnerScope(5, "login", device, "stable", "0.3.14", "0.2.21", 1, 7)
        val owner = NativeOwnerOperation(scope, "22222222-2222-4222-8222-222222222222", 52,
            System.currentTimeMillis() + 10000)
        val wire = JSONObject().put("owner_operation", owner.toJson().toString())
            .put("device_id", device).put("access_token", "bearer").put("install_secret", "install-secret").toString()
        seed("runtime.latest.state.0.0.1.nelomai-background-credential", 9)
        assertThrows(IllegalStateException::class.java) {
            StableBackgroundProvision.prepare(context, wire, true)
        }
        StableBackgroundProvision.prepareEngine(context, scope.runtimeVersion)
        assertTrue(StableBackgroundProvision.prepare(context, wire, true))
        val name = "runtime.stable.state.0.2.21.nelomai-background-credential"
        val prepared = GenerationEnvelopeIoShadow.records[name]!!.clone()
        assertEquals(10L, BackgroundCredentialEnvelopeCodec.decode(prepared).installGeneration)
        assertTrue(StableBackgroundProvision.prepare(context, wire, true))
        assertArrayEquals(prepared, GenerationEnvelopeIoShadow.records[name])
    }
}

/** Cryptography alone is replaced: Android factory, discovery, lock and native transitions are real. */
@Implements(AndroidSecureEnvelopeBackend::class, isInAndroidSdk = false)
class GenerationEnvelopeIoShadow {
    @RealObject private lateinit var backend: AndroidSecureEnvelopeBackend
    private fun name(): String {
        val name = ReflectionHelpers.getField<String>(backend, "preferenceName")
        assertEquals(name, ReflectionHelpers.getField<String>(backend, "keyAlias"))
        assertEquals(if (name == "nelomai-install-generation") "generation-v1" else "encrypted-envelope-v3",
            ReflectionHelpers.getField<String>(backend, "recordName"))
        return name
    }
    @Implementation fun read(): ByteArray? = records[name()]?.clone()
    @Implementation fun write(bytes: ByteArray): Boolean { records[name()] = bytes.clone(); return true }
    companion object { val records = mutableMapOf<String, ByteArray>() }
}
