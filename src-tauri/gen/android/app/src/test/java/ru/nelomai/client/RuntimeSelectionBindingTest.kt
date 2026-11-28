package ru.nelomai.client

import android.content.ComponentName
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.content.ServiceConnection
import android.os.Binder
import android.os.Build
import android.os.Parcel
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

import android.os.DeadObjectException
import android.os.Looper
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.robolectric.Robolectric
import org.robolectric.Shadows.shadowOf
import org.robolectric.util.ReflectionHelpers

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

    @Test fun transientObserverFailureRetriesOnTheSameBroker() =
        verifyObserverRecovery(android.os.TransactionTooLargeException())

    @Test fun failedObserverTransactionOnALiveBrokerPreservesSelection() =
        verifyObserverRecovery(DeadObjectException())

    private fun verifyObserverRecovery(firstFailure: android.os.RemoteException) {
        lateinit var connection: ServiceConnection
        val context = object : ContextWrapper(RuntimeEnvironment.getApplication()) {
            override fun bindService(intent: Intent, callback: ServiceConnection, flags: Int): Boolean {
                if (flags and Context.BIND_WAIVE_PRIORITY == 0) connection = callback
                return true
            }
            override fun unbindService(connection: ServiceConnection) = Unit
        }
        val selected = RuntimeSelectionV1("latest", "0.3.15", "0.3.15", 1, null, "broker")
        val token = Binder()
        var attempts = 0
        var observed: android.os.IBinder? = null
        val broker = object : Binder() {
            override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
                data.enforceInterface(RuntimeOwnerProtocol.DESCRIPTOR)
                requireNotNull(reply)
                when (code) {
                    RuntimeOwnerProtocol.WATCH_VPN_PROCESS -> {
                        if (++attempts == 1) throw firstFailure
                        observed = data.readStrongBinder()
                        reply.writeNoException()
                    }
                    RuntimeOwnerProtocol.SELECTION -> {
                        reply.writeNoException()
                        reply.writeString(RuntimeSelectionStore.encode(selected))
                    }
                    else -> return false
                }
                return true
            }
        }
        RuntimeSelectionStore(context, token).use { store ->
            val values = mutableListOf<Result<RuntimeSelectionV1>>()
            repeat(3) { i ->
                store.read { values += it }
                if (i == 0) connection.onServiceConnected(ComponentName(context, "broker"), broker)
                val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
                while (values.size <= i && System.nanoTime() < deadline) {
                    shadowOf(Looper.getMainLooper()).idle()
                    Thread.yield()
                }
                assertEquals("selection must complete on this Binder", i + 1, values.size)
                assertEquals(selected, values[i].getOrThrow())
            }
            assertSame(token, observed)
            assertEquals("retry until registered, then stop", 2, attempts)
        }
    }

    @Test fun existingKotlinCallersCanOpenTheStoreWithDefaultBindingOptions() {
        val ctor = RuntimeSelectionStore::class.java.getConstructor(Context::class.java,
            Boolean::class.javaPrimitiveType, Boolean::class.javaPrimitiveType, Int::class.javaPrimitiveType,
            Class.forName("kotlin.jvm.internal.DefaultConstructorMarker"))
        (ctor.newInstance(RuntimeEnvironment.getApplication(), false, false, 6, null) as RuntimeSelectionStore).close()
    }

    @Test fun stalledVpnReadTimesOutWithoutBlockingMainOrAcceptingLateSelection() {
        lateinit var connection: ServiceConnection
        val context = object : ContextWrapper(RuntimeEnvironment.getApplication()) {
            override fun bindService(intent: Intent, callback: ServiceConnection, flags: Int): Boolean {
                if (flags and Context.BIND_WAIVE_PRIORITY == 0) connection = callback
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
                if (flags and Context.BIND_WAIVE_PRIORITY == 0) connection = serviceConnection
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

    @Test fun cachedUiReadRecoversFromOneFailureWithoutAnAndroidDisconnect() = checkUiSelectionReconnect(false)
    @Test fun observerRecoversWhenTheIdleReplacementFailsItsFirstSelection() = checkUiSelectionReconnect(true)

    private fun checkUiSelectionReconnect(observerOnly: Boolean) {
        val context = BindingContext()
        val selected = RuntimeSelectionV1("latest", "0.3.15", "0.3.15", 7, null, "broker")
        var failOnce = false
        val owner = object : Binder() {
            override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
                if (failOnce) {
                    failOnce = false
                    throw DeadObjectException()
                }
                requireNotNull(reply).writeNoException()
                reply.writeString(RuntimeSelectionStore.encode(selected))
                return true
            }
        }
        val results = mutableListOf<RuntimeSelectionV1>()
        val observed = mutableListOf<RuntimeSelectionV1>()
        RuntimeSelectionStore(context).use { store ->
            if (observerOnly) store.observeOwnerConnections { observed += it }
            store.read { results += it.getOrThrow() }
            val first = context.ownerConnection()
            first.onServiceConnected(null, owner)
            failOnce = true
            if (observerOnly) {
                first.onServiceDisconnected(null)
                first.onServiceConnected(null, owner)
            } else {
                store.read { results += it.getOrThrow() }
            }
            assertFalse(failOnce)
            shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(1))
            assertEquals(2, context.removed.size)
            first.onServiceDisconnected(null)
            if (Build.VERSION.SDK_INT >= 26) first.onBindingDied(null)
            context.ownerConnection().onServiceConnected(null, owner)
            assertEquals(if (observerOnly) listOf(selected) else listOf(selected, selected), results)
            assertEquals(if (observerOnly) listOf(selected, selected) else emptyList(), observed)
        }
    }

    @Test fun vpnRetriesOneFailedSelectionOnALiveBroker() = verifyVpnSelectionRebind(recovered = true)

    @Test fun repeatedSelectionFailureKeepsTheOriginalDeadline() = verifyVpnSelectionRebind(recovered = false)

    private fun verifyVpnSelectionRebind(recovered: Boolean) {
        val context = BindingContext()
        val selected = RuntimeSelectionV1("latest", "0.3.15", "0.3.15", 7, null, "broker")
        val reads = AtomicInteger()
        val owner = object : Binder() {
            override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
                if (reads.incrementAndGet() == 1 || !recovered) throw DeadObjectException()
                requireNotNull(reply).writeNoException()
                reply.writeString(RuntimeSelectionStore.encode(selected))
                return true
            }
        }
        val main = shadowOf(Looper.getMainLooper())
        val results = mutableListOf<Result<RuntimeSelectionV1>>()
        fun await(predicate: () -> Boolean) {
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
            while (!predicate() && System.nanoTime() < deadline) {
                main.idle()
                Thread.yield()
            }
            assertTrue(predicate())
        }
        RuntimeSelectionStore(context, readOffMain = true).use { store ->
            store.read { results += it }
            val first = context.ownerConnection()
            main.idleFor(Duration.ofSeconds(8))
            first.onServiceConnected(null, owner)
            await { reads.get() == 1 && !ReflectionHelpers.getField<Boolean>(store, "reading") }
            main.idleFor(Duration.ofSeconds(1))
            assertEquals(2, context.removed.size)
            val second = context.ownerConnection()
            assertNotSame(first, second)
            second.onServiceConnected(null, owner)
            first.onServiceDisconnected(null)
            if (Build.VERSION.SDK_INT >= 26) first.onBindingDied(null)
            await { reads.get() == 2 && !ReflectionHelpers.getField<Boolean>(store, "reading") }
            if (recovered) {
                assertEquals(selected, results.single().getOrThrow())
            } else {
                assertTrue(results.isEmpty())
            }
            main.idleFor(Duration.ofSeconds(1))
            if (!recovered) assertEquals("runtime_owner_unavailable", results.single().exceptionOrNull()?.message)
            assertEquals(if (recovered) 2 else 4, context.removed.size)
            assertEquals(1, results.size)
        }
    }

    @Test fun invalidatedBinderSnapshotCannotAdmitAnEarlierQueuedStart() {
        lateinit var connection: ServiceConnection
        val context = object : ContextWrapper(RuntimeEnvironment.getApplication()) {
            override fun bindService(intent: Intent, callback: ServiceConnection, flags: Int): Boolean {
                if (flags and Context.BIND_WAIVE_PRIORITY == 0) connection = callback
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

}
