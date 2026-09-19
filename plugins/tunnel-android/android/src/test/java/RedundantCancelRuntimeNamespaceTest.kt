package ru.nelomai.tunnel

import android.content.Context
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE)
class RedundantCancelRuntimeNamespaceTest {
    private class Record(var value: ByteArray? = null) : EncryptedRecordBackend {
        override fun read(): ByteArray? = value?.clone()
        override fun write(plaintext: ByteArray): Boolean {
            value = plaintext.clone()
            return true
        }
    }

    private class RealPlaintextStorage(context: Context) : NativeRuntimeStorageAccess {
        private val sources = mutableMapOf<String, Record>()
        private val destinations = mutableMapOf<String, Record>()
        private val receipts = mutableMapOf<String, Record>()
        private val native = AndroidNativeRuntimeStorageAccess(context) { receipt(it) }

        override fun source(name: String, record: String) =
            sources.getOrPut("$name/$record") { Record() }

        override fun destination(name: String, record: String) =
            destinations.getOrPut("$name/$record") { Record() }

        override fun receipt(name: String) = receipts.getOrPut(name) { Record() }
        override fun hasLegacy(name: String) = native.hasLegacy(name)
        override fun retireLegacy(name: String) = native.retireLegacy(name)
        override fun migrateQuickState() = native.migrateQuickState()
        override fun validateQuickStateDestination(name: String) =
            native.validateQuickStateDestination(name)
    }

    private fun preferences(context: Context, name: String) =
        context.getSharedPreferences(name, Context.MODE_PRIVATE)

    @Test fun realPlaintextMigrationPreservesSourceUntilAckAndFencesRetry() {
        val context = RuntimeEnvironment.getApplication().applicationContext
        val legacy = preferences(context, REDUNDANT_CANCEL_PREFERENCES)
        val target = preferences(
            context,
            AndroidRuntimeNamespace.record(REDUNDANT_CANCEL_PREFERENCES),
        )
        val quickSource = preferences(context, "nelomai-quick-tunnel-state")
        val quickTarget = preferences(
            context,
            AndroidRuntimeNamespace.record("nelomai-quick-tunnel-state"),
        )
        listOf(legacy, target, quickSource, quickTarget).forEach {
            assertTrue(it.edit().clear().commit())
        }
        val legacyValue = "1\nlegacy-start\nlegacy-stop"
        val advancedValue = "2\nadvanced-start\nadvanced-stop\nfalse"
        assertTrue(legacy.edit().putString("tombstone", legacyValue).commit())
        val runtime = LatestRuntimeStorageV1()
        val storage = RealPlaintextStorage(context)

        runtime.prepare(storage, "latest", AndroidRuntimeNamespace.version,
            legacyMigration = true, migrationComplete = false)
        assertEquals(legacyValue, target.getString("tombstone", null))
        assertEquals(legacyValue, legacy.getString("tombstone", null))
        assertTrue("missing quick state is optional", quickTarget.all.isEmpty())

        assertTrue(target.edit().putString("tombstone", advancedValue).commit())
        runtime.prepare(storage, "latest", AndroidRuntimeNamespace.version,
            legacyMigration = true, migrationComplete = false)
        assertEquals(advancedValue, target.getString("tombstone", null))
        assertEquals(legacyValue, legacy.getString("tombstone", null))

        runtime.acknowledge(storage)
        assertTrue(legacy.all.isEmpty())
        assertEquals(advancedValue, target.getString("tombstone", null))
        assertTrue(quickSource.all.isEmpty())
    }

    @Test fun absentLegacyTombstoneIsOptional() {
        val context = RuntimeEnvironment.getApplication().applicationContext
        val legacy = preferences(context, REDUNDANT_CANCEL_PREFERENCES)
        val target = preferences(
            context,
            AndroidRuntimeNamespace.record(REDUNDANT_CANCEL_PREFERENCES),
        )
        assertTrue(legacy.edit().clear().commit())
        assertTrue(target.edit().clear().commit())
        val runtime = LatestRuntimeStorageV1()
        val storage = RealPlaintextStorage(context)

        runtime.prepare(storage, "latest", AndroidRuntimeNamespace.version,
            legacyMigration = true, migrationComplete = false)
        runtime.acknowledge(storage)

        assertTrue(legacy.all.isEmpty())
        assertTrue(target.all.isEmpty())
    }

    @Test fun backendClearOnlyRemovesTheSelectedRuntimeTombstone() {
        val context = RuntimeEnvironment.getApplication().applicationContext
        val legacy = context.getSharedPreferences("nelomai-redundant-cancel", Context.MODE_PRIVATE)
        val selected = context.getSharedPreferences(
            AndroidRuntimeNamespace.record("nelomai-redundant-cancel"),
            Context.MODE_PRIVATE,
        )
        val other = context.getSharedPreferences(
            "runtime.stable.state.0.2.20.nelomai-redundant-cancel",
            Context.MODE_PRIVATE,
        )
        listOf(legacy, selected, other).forEach { it.edit().clear().commit() }
        val sourceValue = "1\nlegacy-start\nlegacy-stop"
        val selectedValue = "2\nselected-start\nselected-stop\nfalse"
        val otherValue = "2\nother-start\nother-stop\nfalse"
        assertTrue(legacy.edit().putString("tombstone", sourceValue).commit())
        assertTrue(selected.edit().putString("tombstone", selectedValue).commit())
        assertTrue(other.edit().putString("tombstone", otherValue).commit())

        val backend = AndroidRedundantCancelTombstoneBackend(context)
        assertEquals(selectedValue, backend.read())
        assertTrue(backend.compareAndClear(selectedValue))

        assertNull(selected.getString("tombstone", null))
        assertFalse(selected.contains("tombstone"))
        assertEquals(sourceValue, legacy.getString("tombstone", null))
        assertEquals(otherValue, other.getString("tombstone", null))
    }
}
