package ru.nelomai.tunnel

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.security.KeyStore
import java.util.UUID
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AndroidSecureEnvelopeBackendInstrumentedTest {
    @Test
    fun keystoreRoundTripUsesOneOpaqueSynchronousPreferenceRecord() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val suffix = UUID.randomUUID().toString()
        val preferenceName = "recovery-test-$suffix"
        val recordName = "envelope"
        val keyAlias = "recovery-test-$suffix"
        val preferences = context.getSharedPreferences(preferenceName, Context.MODE_PRIVATE)
        val backend = AndroidSecureEnvelopeBackend(
            context = context,
            preferenceName = preferenceName,
            recordName = recordName,
            keyAlias = keyAlias,
        )
        val plaintext = "device-id=request-fingerprint".toByteArray()

        try {
            assertEquals(true, backend.write(plaintext))
            assertEquals(1, preferences.all.size)
            val persisted = preferences.getString(recordName, null)
            assertNotNull(persisted)
            assertFalse(requireNotNull(persisted).contains("request-fingerprint"))
            assertArrayEquals(plaintext, backend.read())
            assertNotNull(AndroidBootIdentityProvider(context).bootCount())

            preferences.edit().putString(recordName, "broken-record").commit()
            val recoveryStore = AndroidRecoveryStore(
                backend,
                AndroidBootIdentityProvider(context),
            )
            val corruptResult = recoveryStore.read()
            assertEquals(
                "recovery_record_corrupt",
                (corruptResult as RecoveryStoreResult.Failure).code,
            )
            assertFalse(
                (recoveryStore.read() as RecoveryStoreResult.Success)
                    .value.intent.desiredActive,
            )
        } finally {
            plaintext.fill(0)
            preferences.edit().clear().commit()
            KeyStore.getInstance("AndroidKeyStore").apply {
                load(null)
                if (containsAlias(keyAlias)) deleteEntry(keyAlias)
            }
        }
    }

    @Test
    fun legacyDesiredActiveCannotRearmAfterTheMigrationIsSealed() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val quickPreferences = context.getSharedPreferences(
            "nelomai-quick-tunnel-state",
            Context.MODE_PRIVATE,
        )
        val recoveryPreferences = context.getSharedPreferences(
            "nelomai-connection-recovery",
            Context.MODE_PRIVATE,
        )
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        quickPreferences.edit().clear().putBoolean("desired-active", true).commit()
        recoveryPreferences.edit().clear().commit()
        if (keyStore.containsAlias("nelomai-connection-recovery")) {
            keyStore.deleteEntry("nelomai-connection-recovery")
        }

        try {
            assertTrue(QuickTunnelController.desiredActive(context))
            assertTrue(quickPreferences.getBoolean("recovery-projection-migrated", false))
            assertFalse(quickPreferences.contains("desired-active"))

            recoveryPreferences.edit()
                .putString("encrypted-envelope", "broken-record")
                .commit()
            quickPreferences.edit().putBoolean("desired-active", true).commit()

            assertFalse(QuickTunnelController.desiredActive(context))
        } finally {
            quickPreferences.edit().clear().commit()
            recoveryPreferences.edit().clear().commit()
            if (keyStore.containsAlias("nelomai-connection-recovery")) {
                keyStore.deleteEntry("nelomai-connection-recovery")
            }
        }
    }
}
