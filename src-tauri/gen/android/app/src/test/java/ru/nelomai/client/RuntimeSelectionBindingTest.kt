package ru.nelomai.client

import android.content.ComponentName
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.content.ServiceConnection
import android.os.Binder
import android.os.Parcel
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [24, 28])
class RuntimeSelectionBindingTest {
    private class BindingContext : ContextWrapper(RuntimeEnvironment.getApplication()) {
        val active = linkedMapOf<ServiceConnection, Int>()
        val removed = mutableListOf<ServiceConnection>()
        var rejectFlags: Int? = null
        var throwOnBind = false
        override fun bindService(intent: Intent, connection: ServiceConnection, flags: Int): Boolean {
            assertEquals("ru.nelomai.client.RuntimeAuthBrokerService", intent.component?.className)
            // ContextImpl registers ServiceDispatcher before the system result;
            // false and SecurityException still require unbindService.
            active[connection] = flags
            if (flags == rejectFlags) {
                if (throwOnBind) throw SecurityException("binding rejected")
                return false
            }
            return true
        }
        override fun unbindService(connection: ServiceConnection) {
            check(active.remove(connection) != null) { "binding released twice" }
            removed += connection
        }
        fun ownerConnection() = active.entries.single {
            it.value and Context.BIND_WAIVE_PRIORITY == 0
        }.key
        fun connect(connection: ServiceConnection = ownerConnection()) {
            connection.onServiceConnected(ComponentName(this, RuntimeAuthBrokerService::class.java),
                object : Binder() {
                    override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
                        data.enforceInterface(RuntimeOwnerProtocol.DESCRIPTOR)
                        // A noncached client must retain both normal OOM priority and the
                        // freezer exemption, including after the owner has displayed UI.
                        check(active.values.any { it and Context.BIND_WAIVE_PRIORITY != 0 })
                        requireNotNull(reply).writeNoException()
                        reply.writeString(RuntimeSelectionStore.encode(
                            RuntimeSelectionV1("latest", "0.5.0", "0.5.0", 1L, null, "owner-test")))
                        return true
                    }
                })
        }
    }

    @Test fun readsRetainNormalPriorityAndFreezerBindingUntilClose() {
        val context = BindingContext()
        val store = RuntimeSelectionStore(context)
        val results = mutableListOf<Result<RuntimeSelectionV1>>()
        store.read { results += it }
        context.connect()
        store.read { results += it }
        assertEquals(2, results.size)
        assertTrue(results.all { it.isSuccess })
        assertEquals(setOf(Context.BIND_AUTO_CREATE,
            Context.BIND_AUTO_CREATE or Context.BIND_WAIVE_PRIORITY), context.active.values.toSet())
        store.close()
        store.close()
        assertTrue(context.active.isEmpty())
        assertEquals(2, context.removed.size)
    }

    @Test fun partialBindingFailureReleasesOwnerAndAllowsRetry() {
        for (throws in listOf(false, true)) {
            val context = BindingContext().apply {
                rejectFlags = Context.BIND_AUTO_CREATE or Context.BIND_WAIVE_PRIORITY
                throwOnBind = throws
            }
            val store = RuntimeSelectionStore(context)
            val results = mutableListOf<Result<RuntimeSelectionV1>>()
            repeat(2) { attempt ->
                store.read { results += it }
                assertEquals(attempt + 1, results.size)
                assertTrue(results.last().isFailure)
                assertTrue(context.active.isEmpty())
                assertEquals((attempt + 1) * 2, context.removed.size)
            }
            // Late callbacks cannot resurrect either failed binding.
            context.removed.forEach { context.connect(it) }
            context.rejectFlags = null
            store.read { results += it }
            context.connect()
            assertEquals(3, results.size)
            assertTrue(results.last().isSuccess)
            store.close()
            store.close()
            assertTrue(context.active.isEmpty())
            assertEquals(6, context.removed.size)
        }
    }

    @Test fun rejectedPrimaryBindingIsReleasedAndAllowsRetry() {
        for (throws in listOf(false, true)) {
            val context = BindingContext().apply { rejectFlags = Context.BIND_AUTO_CREATE; throwOnBind = throws }
            val store = RuntimeSelectionStore(context)
            var result: Result<RuntimeSelectionV1>? = null
            store.read { result = it }
            assertTrue(requireNotNull(result).isFailure)
            assertTrue(context.active.isEmpty())
            assertEquals(1, context.removed.size)
            store.close()
            assertEquals(1, context.removed.size)
            context.rejectFlags = null
            store.read { result = it }
            context.connect()
            assertTrue(requireNotNull(result).isSuccess)
            store.close()
            assertTrue(context.active.isEmpty())
            assertEquals(3, context.removed.size)
        }
    }

    @Test fun closeWhileConnectingReleasesBothAndIgnoresLateConnectedCallback() {
        val context = BindingContext()
        val store = RuntimeSelectionStore(context)
        val results = mutableListOf<Result<RuntimeSelectionV1>>()
        store.read { results += it }
        val connection = context.ownerConnection()
        store.close()
        context.connect(connection)
        assertEquals(1, results.size)
        assertTrue(results.single().isFailure)
        assertTrue(context.active.isEmpty())
        assertEquals(2, context.removed.size)
        assertTrue(runCatching { store.snapshot() }.isFailure)
    }

    @Test @Config(sdk = [28]) fun deadBindingReleasesBothBeforeRebinding() {
        val context = BindingContext()
        val store = RuntimeSelectionStore(context)
        store.read { assertTrue(it.isSuccess) }
        context.connect()
        context.ownerConnection().onBindingDied(ComponentName(context, RuntimeAuthBrokerService::class.java))
        assertTrue(context.active.isEmpty())
        assertEquals(2, context.removed.size)
        var result: Result<RuntimeSelectionV1>? = null
        store.read { result = it }
        context.connect()
        assertTrue(requireNotNull(result).isSuccess)
        store.close()
        assertEquals(4, context.removed.size)
    }
}
