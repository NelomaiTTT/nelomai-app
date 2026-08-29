package ru.nelomai.tunnel

import android.content.Context
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.security.KeyStore
import javax.crypto.Cipher
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class BackgroundCredentialStoreInstrumentedTest {
    @Test
    fun formatTwoCredentialMigratesWithoutDeletingTheActiveToken() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val preferences = context.getSharedPreferences(
            "nelomai-background-credential",
            Context.MODE_PRIVATE,
        )
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        preferences.edit().clear().commit()
        if (keyStore.containsAlias(KEY_ALIAS)) keyStore.deleteEntry(KEY_ALIAS)
        AndroidBackgroundCredentialStores.resetForTests()

        val plaintext = JSONObject().apply {
            put("format", 2)
            put("deviceId", DEVICE_ID)
            put("panelBase", "https://nelomai.example")
            put("token", "legacy-device-token")
            put("expiresAtUnix", 1_900_000_000)
        }.toString().toByteArray()

        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
                init(Cipher.ENCRYPT_MODE, androidEnvelopeSecretKey(KEY_ALIAS))
            }
            val ciphertext = cipher.doFinal(plaintext)
            assertTrue(
                preferences.edit()
                    .putString("ciphertext", Base64.encodeToString(ciphertext, Base64.NO_WRAP))
                    .putString("iv", Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
                    .commit(),
            )
            ciphertext.fill(0)

            val migrated = AndroidBackgroundCredentialStores.open(context).read()
            assertTrue(migrated is CredentialStoreResult.Success)
            val envelope = (migrated as CredentialStoreResult.Success).value
            assertEquals(1, envelope.revision)
            assertEquals("legacy-device-token", envelope.active?.token)
            assertEquals(null, envelope.installSecret)
            assertEquals(1, preferences.all.size)
            assertFalse(preferences.contains("ciphertext"))
            assertFalse(preferences.contains("iv"))
            val opaque = preferences.getString("encrypted-envelope-v3", null)
            assertNotNull(opaque)
            assertFalse(requireNotNull(opaque).contains("legacy-device-token"))

            AndroidBackgroundCredentialStores.resetForTests()
            val reopened = AndroidBackgroundCredentialStores.open(context).read()
            assertEquals(
                "legacy-device-token",
                (reopened as CredentialStoreResult.Success).value.active?.token,
            )
        } finally {
            plaintext.fill(0)
            AndroidBackgroundCredentialStores.resetForTests()
            preferences.edit().clear().commit()
            if (keyStore.containsAlias(KEY_ALIAS)) keyStore.deleteEntry(KEY_ALIAS)
        }
    }

    companion object {
        private const val KEY_ALIAS = "nelomai-background-credential"
        private const val DEVICE_ID = "11111111-1111-4111-8111-111111111111"
    }
}
