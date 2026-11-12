package ru.nelomai.client

import android.content.Context
import android.content.ComponentName
import android.content.ContextWrapper
import android.content.Intent
import android.content.ServiceConnection
import android.os.Binder
import android.os.DeadObjectException
import android.os.Looper
import android.os.Parcel
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.util.ReflectionHelpers

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE)
class RuntimeSelectionBindingTest {
    @Test fun stalledVpnReadTimesOutWithoutBlockingMainOrAcceptingLateSelection() {
        lateinit var connection: ServiceConnection
        val context = object : ContextWrapper(RuntimeEnvironment.getApplication()) {
            override fun bindService(intent: Intent, callback: ServiceConnection, flags: Int): Boolean {
                connection = callback
                return true
            }
            override fun unbindService(connection: ServiceConnection) = Unit
        }
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val returned = CountDownLatch(1)
        val owner = object : Binder() {
            override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
                entered.countDown()
                check(release.await(5, TimeUnit.SECONDS))
                requireNotNull(reply).writeNoException()
                reply.writeString(RuntimeSelectionStore.encode(
                    RuntimeSelectionV1("latest", "0.3.14", "0.3.14", 7, null, "broker"),
                ))
                returned.countDown()
                return true
            }
        }
        val results = mutableListOf<Result<RuntimeSelectionV1>>()
        RuntimeSelectionStore(context, readOffMain = true).use { store ->
            try {
                store.read { results += it }
                connection.onServiceConnected(ComponentName(context, "broker"), owner)
                assertTrue(entered.await(2, TimeUnit.SECONDS))
                shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(10))
                assertTrue(results.single().isFailure)
                release.countDown()
                assertTrue(returned.await(2, TimeUnit.SECONDS))
                shadowOf(Looper.getMainLooper()).idle()
                assertEquals(1, results.size)
            } finally {
                release.countDown()
            }
        }
    }

    @Test fun deadBinderKeepsTheReadQueuedForTheReplacement() {
        lateinit var connection: ServiceConnection
        val context = object : ContextWrapper(RuntimeEnvironment.getApplication()) {
            override fun bindService(intent: Intent, serviceConnection: ServiceConnection, flags: Int): Boolean {
                connection = serviceConnection
                return true
            }
            override fun unbindService(connection: ServiceConnection) = Unit
        }
        val component = ComponentName(context, "ru.nelomai.client.RuntimeAuthBrokerService")
        val selected = RuntimeSelectionV1("latest", "0.3.14", "0.3.14", 7, null, "new-broker")
        var dead = false
        fun owner() = object : Binder() {
            override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
                if (dead) throw DeadObjectException()
                requireNotNull(reply).writeNoException()
                reply.writeString(RuntimeSelectionStore.encode(selected))
                return true
            }
        }
        RuntimeSelectionStore(context).use { store ->
            var initial: Result<RuntimeSelectionV1>? = null
            store.read { initial = it }
            dead = true
            connection.onServiceConnected(component, owner())
            assertNull("first dead Binder must leave the read queued", initial)
            dead = false
            connection.onServiceConnected(component, owner())
            assertEquals(selected, initial?.getOrThrow())
            dead = true
            var result: Result<RuntimeSelectionV1>? = null
            store.read { result = it }
            assertNull(result)
            dead = false
            connection.onServiceConnected(component, owner())
            assertEquals(selected, result?.getOrThrow())

            result = null
            dead = true
            store.read { result = it }
            shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(9))
            connection.onServiceConnected(component, owner())
            assertNull(result)
            shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(1))
            assertEquals("runtime_owner_unavailable", result?.exceptionOrNull()?.message)
        }
    }

    @Test fun invalidatedBinderSnapshotCannotAdmitAnEarlierQueuedStart() {
        lateinit var connection: ServiceConnection
        val context = object : ContextWrapper(RuntimeEnvironment.getApplication()) {
            override fun bindService(intent: Intent, callback: ServiceConnection, flags: Int): Boolean {
                connection = callback
                return true
            }
            override fun unbindService(connection: ServiceConnection) = Unit
        }
        val firstRead = CountDownLatch(1)
        val release = CountDownLatch(1)
        val reads = AtomicInteger()
        val owner = object : Binder() {
            override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
                val generation = reads.incrementAndGet().toLong()
                if (generation == 1L) {
                    firstRead.countDown()
                    check(release.await(5, TimeUnit.SECONDS))
                }
                requireNotNull(reply).writeNoException()
                reply.writeString(RuntimeSelectionStore.encode(
                    RuntimeSelectionV1("latest", "0.3.14", "0.3.14", generation, null, "broker"),
                ))
                return true
            }
        }
        val results = mutableListOf<Long?>()
        RuntimeSelectionStore(context, readOffMain = true).use { store ->
            try {
                store.read { results += it.getOrThrow().sessionGeneration }
                connection.onServiceConnected(ComponentName(context, "broker"), owner)
                assertTrue(firstRead.await(2, TimeUnit.SECONDS))
                store.invalidatePendingSnapshot()
                store.read { results += it.getOrThrow().sessionGeneration }
                release.countDown()
                val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
                while (results.size < 2 && System.nanoTime() < deadline) {
                    shadowOf(Looper.getMainLooper()).idle()
                    Thread.yield()
                }
                assertEquals(listOf(2L, 2L), results)
            } finally {
                release.countDown()
            }
        }
    }

    @Test fun vpnUsesAnOrdinaryBindingToTheBroker() {
        val controller = Robolectric.buildService(RuntimeVpnDispatcherService::class.java).create()
        val vpn = controller.get()
        var flags = 0
        val context = object : ContextWrapper(vpn.baseContext) {
            override fun bindService(intent: Intent, connection: ServiceConnection, bindFlags: Int): Boolean {
                flags = bindFlags
                return false
            }
        }
        val selection = ReflectionHelpers.getField<RuntimeSelectionStore>(vpn, "selection")
        selection.close()
        ReflectionHelpers.setField(selection, "context", context)
        try {
            selection.read { assertTrue(it.isFailure) }
            assertEquals(Context.BIND_AUTO_CREATE, flags)
        } finally {
            controller.destroy()
        }
    }

    @Test fun ownerBindingTracksFreezerDependencyUntilClose() {
        var boundFlags = 0
        var boundConnection: ServiceConnection? = null
        var unbinds = 0
        val context = object : ContextWrapper(RuntimeEnvironment.getApplication()) {
            override fun bindService(intent: Intent, connection: ServiceConnection, flags: Int): Boolean {
                assertEquals("ru.nelomai.client.RuntimeAuthBrokerService", intent.component?.className)
                boundFlags = flags
                boundConnection = connection
                return true
            }
            override fun unbindService(connection: ServiceConnection) {
                assertSame(boundConnection, connection)
                unbinds++
            }
        }
        var completed: Result<RuntimeSelectionV1>? = null
        val selection = RuntimeSelectionStore(context)
        selection.read { completed = it }
        assertTrue(boundFlags and Context.BIND_AUTO_CREATE != 0)
        // Android otherwise permits a previously visible owner to become cached
        // while its runtime is still in the previous-activity state. This flag
        // preserves the platform's explicit shouldNotFreeze dependency.
        assertTrue("Owner must not freeze ahead of its noncached runtime",
            boundFlags and Context.BIND_ALLOW_OOM_MANAGEMENT != 0)
        assertNull(completed)
        selection.close()
        assertTrue(requireNotNull(completed).isFailure)
        selection.close()
        assertEquals(1, unbinds)
    }
}
