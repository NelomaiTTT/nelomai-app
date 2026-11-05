package ru.nelomai.tunnel

import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE)
class KillSwitchPreferenceTest {
    @org.junit.Test fun unavailableLockdownObservationIsUnknownRatherThanDisabled() {
        val status = android.os.Bundle().apply { putString(EXTRA_STATE, "stopped") }.killSwitchStatus()
        org.junit.Assert.assertTrue(status.isNull("externalLockdown"))
        org.junit.Assert.assertFalse(status.getBoolean("vpnActive"))
    }

    @Test fun defaultOffDisclosureCancellationAndPersistence() {
        val context = RuntimeEnvironment.getApplication()
        val prefs = context.getSharedPreferences("nelomai-kill-switch-device-v1", 0)
        prefs.edit().clear().commit()
        val choice = KillSwitchPreference(context)
        assertFalse(choice.enabled); assertFalse(choice.disclosed)
        assertThrows(IllegalArgumentException::class.java) { choice.save(true) }
        assertFalse(choice.enabled); assertFalse(choice.disclosed)
        choice.save(true, confirmed = true)
        val reopened = KillSwitchPreference(ContextWrapper(context))
        assertTrue(reopened.enabled); assertTrue(reopened.disclosed)
        reopened.save(false)
        reopened.save(true) // Disclosure stays accepted after disable and a new instance.
        assertTrue(KillSwitchPreference(context).enabled)
        assertTrue(KillSwitchPreference(context).disclosed)
    }

    @Test fun failedSaveDoesNotClaimPreferenceOrDisclosureWasStored() {
        val application = RuntimeEnvironment.getApplication()
        val real = application.getSharedPreferences("failed-kill-switch", 0)
        real.edit().clear().commit()
        val failing = object : ContextWrapper(application) {
            override fun getApplicationContext(): Context = this
            override fun getSharedPreferences(name: String, mode: Int): SharedPreferences =
                object : SharedPreferences by real {
                    override fun edit(): SharedPreferences.Editor = object : SharedPreferences.Editor by real.edit() {
                        override fun putBoolean(key: String, value: Boolean): SharedPreferences.Editor = this
                        override fun commit(): Boolean = false
                    }
                }
        }
        val choice = KillSwitchPreference(failing)
        assertThrows(IllegalStateException::class.java) { choice.save(true, confirmed = true) }
        assertFalse(choice.enabled); assertFalse(choice.disclosed)
    }
}
