package ru.nelomai.tunnel

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.net.VpnService
import android.os.Bundle
import android.os.ParcelFileDescriptor
import android.os.ResultReceiver
import org.amnezia.awg.backend.GoBackend
import org.amnezia.awg.backend.Tunnel
import org.amnezia.awg.util.SharedLibraryLoader
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements
import org.robolectric.annotation.LooperMode
import org.robolectric.util.ReflectionHelpers
import ru.nelomai.runtime.v1.RuntimeVpnHostV1
import java.util.concurrent.AbstractExecutorService
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Delayed
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit

/** Real runtime, backend and service callbacks; only JNI/platform edges are shadowed. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE, shadows = [CompletionNoLibrary::class,
    CompletionNative::class, CompletionVpnPermission::class, CompletionVpnBuilder::class,
    CompletionFileDescriptor::class])
@LooperMode(LooperMode.Mode.PAUSED)
class NativeLocalRestartCompletionTest {
    // Returning normally cannot signal rejection to the runtime's native catch.
    // This characterizes the mechanism, not a historical RED against old production.
    @Test fun normalCallbackRejectionLeavesNativeUp() = withRuntime { f ->
        val replies = mutableListOf<String>()
        TunnelRuntime.start(f.context, args(), { _, _ -> replies += "normal-rejection" },
            { replies += it }, keepForegroundServiceOnFailure = true)
        f.work.runNext()
        assertEquals(listOf("normal-rejection"), replies)
        assertEquals(Tunnel.State.UP, f.backend.getState(f.tunnel))
        assertEquals(SessionState.RUNNING, TunnelRuntime.state())
        assertEquals(listOf("up"), CompletionNative.events)
    }

    @Test fun thrownLateCallbackRejectionClosesNativeBeforeError() = withRuntime { f ->
        var callbacks = 0
        TunnelRuntime.start(f.context, args(), { state, _ ->
            callbacks++
            assertEquals(SessionState.RUNNING, state)
            assertEquals(Tunnel.State.UP, f.backend.getState(f.tunnel))
            CompletionNative.events += "late-rejection"
            throw TunnelOperationException("tunnel_start_cancelled")
        }, { code ->
            callbacks++
            assertEquals("tunnel_start_cancelled", code)
            assertEquals(Tunnel.State.DOWN, f.backend.getState(f.tunnel))
            assertEquals(SessionState.FAILED, TunnelRuntime.state())
            assertNull(TunnelRuntime.activeLeaseId())
            CompletionNative.events += "error"
        }, keepForegroundServiceOnFailure = true)
        f.work.runNext()
        assertEquals(2, callbacks)
        assertEquals(listOf("up", "late-rejection", "down", "error"), CompletionNative.events)
    }

    @Test fun ownerInvalidatedAtNativeUpFailsClosedBeforeError() = withRuntime { f ->
        var current = true
        var errors = 0
        CompletionNative.onUp = { current = false }
        TunnelRuntime.start(f.context, args(), { _, _ -> fail("cancelled owner succeeded") }, {
            errors++
            assertEquals("tunnel_start_cancelled", it)
            assertEquals(Tunnel.State.DOWN, f.backend.getState(f.tunnel))
            assertEquals(SessionState.FAILED, TunnelRuntime.state())
            CompletionNative.events += "error"
        }, keepForegroundServiceOnFailure = true, ownerCurrent = { current })
        f.work.runNext()
        assertEquals(1, errors)
        assertEquals(listOf("up", "down", "error"), CompletionNative.events)
    }

    @Test fun serviceCallbackUserStopAfterUpClosesNativeBeforeError() = withRuntime { f ->
        f.armCheckpoint()
        val preferences = ReflectionHelpers.callInstanceMethod<SharedPreferences>(
            QuickTunnelController, "preferences", ReflectionHelpers.ClassParameter.from(Context::class.java, f.context))
        var stopped: AndroidRecoveryEnvelope? = null
        val listener = SharedPreferences.OnSharedPreferenceChangeListener { prefs, key ->
            if (key == "state" && prefs.getString(key, null) == SessionState.RUNNING.wireName && stopped == null) {
                stopped = (f.store.cancelCurrentIntent() as RecoveryStoreResult.Success).value
                CompletionNative.events += "user-stop"
            }
        }
        preferences.registerOnSharedPreferenceChangeListener(listener)
        var errors = 0
        try {
            f.startService(Receiver { code, data ->
                errors++
                assertEquals(SERVICE_RESULT_ERROR, code)
                assertEquals("tunnel_start_cancelled", data?.getString(EXTRA_ERROR_CODE))
                assertEquals(Tunnel.State.DOWN, f.backend.getState(f.tunnel))
                assertEquals(SessionState.FAILED, TunnelRuntime.state())
                CompletionNative.events += "error"
            })
            f.work.runNext()
            assertEquals(1, errors)
            assertNotNull(stopped)
            assertEquals(stopped, f.envelope())
            assertFalse(f.envelope().intent.desiredActive)
            assertEquals(listOf("up", "user-stop", "down", "error"), CompletionNative.events)
        } finally { preferences.unregisterOnSharedPreferenceChangeListener(listener) }
    }

    @Test fun legacyNativeFailureAllowsReentrantRollbackWithoutOldFinallyUnlockingIt() = withRuntime { f ->
        // Legacy armed intent has no lease transaction; establish its real active runtime lease.
        QuickDesiredActiveProjection.update(f.store, true)
        TunnelRuntime.start(f.context, args(), { _, _ -> }, { fail(it) }, keepForegroundServiceOnFailure = true)
        f.work.runNext()
        val authority = f.envelope()
        assertNull(authority.leaseTransaction)
        CompletionNative.events.clear()
        CompletionNative.failNextUp = true
        var errors = 0
        var rollbackReplies = 0
        f.startService(Receiver { code, _ ->
            errors++
            assertEquals(SERVICE_RESULT_ERROR, code)
            assertEquals(Tunnel.State.DOWN, f.backend.getState(f.tunnel))
            assertEquals(SessionState.FAILED, TunnelRuntime.state())
            assertEquals(authority, f.envelope())
            assertNotNull(ReflectionHelpers.getField<FailedLocalRestartAuthority?>(f.service, "failedLocalRestartAuthority"))
            f.startService(Receiver { rollbackCode, _ ->
                rollbackReplies++
                assertEquals(SERVICE_RESULT_OK, rollbackCode)
            })
            assertEquals(1, f.work.jobs.size)
        })
        f.work.runNext()
        assertEquals(1, errors)
        assertFalse("old error callback finally must not release rollback's gate", f.coordinator.beginLocalRestart())
        f.work.runNext()
        assertEquals(1, rollbackReplies)
        assertEquals(Tunnel.State.UP, f.backend.getState(f.tunnel))
        assertEquals(authority, f.envelope())
        assertNull(ReflectionHelpers.getField<FailedLocalRestartAuthority?>(f.service, "failedLocalRestartAuthority"))
        assertTrue(f.coordinator.beginLocalRestart())
        f.coordinator.completeLocalRestart()
    }

    private fun withRuntime(test: (Fixture) -> Unit) {
        val controller = Robolectric.buildService(VpnService::class.java).create()
        val host = controller.get()
        val store = AndroidRecoveryStore(Record(), BootIdentityProvider { 1 })
        val coordinator = AndroidConnectionIntentCoordinator(store)
        val service = NelomaiVpnService(object : RuntimeVpnHostV1 {
            override val service = host
            override fun builder(beforeEstablish: (VpnService.Builder) -> Unit) = host.Builder().also(beforeEstablish)
        })
        val saved = mutableListOf<() -> Unit>()
        fun field(target: Any, name: String, value: Any?) {
            val old = ReflectionHelpers.getField<Any?>(target, name)
            val raw = target.javaClass.getDeclaredField(name).apply { isAccessible = true }
            // Kotlin object vals are static final on Java 17. Replace only fixture
            // scheduling/state fields, without shadowing runtime execution.
            fun set(replacement: Any?) {
                if (java.lang.reflect.Modifier.isStatic(raw.modifiers) && java.lang.reflect.Modifier.isFinal(raw.modifiers)) {
                    val type = Class.forName("sun.misc.Unsafe")
                    val unsafe = type.getDeclaredField("theUnsafe").apply { isAccessible = true }.get(null)
                    val base = type.getMethod("staticFieldBase", java.lang.reflect.Field::class.java).invoke(unsafe, raw)
                    val offset = type.getMethod("staticFieldOffset", java.lang.reflect.Field::class.java).invoke(unsafe, raw)
                    type.getMethod("putObject", Any::class.java, java.lang.Long.TYPE, Any::class.java)
                        .invoke(unsafe, base, offset, replacement)
                } else raw.set(target, replacement)
            }
            set(value)
            saved += { set(old) }
        }
        fun static(type: Class<*>, name: String, value: Any?) {
            val old = ReflectionHelpers.getStaticField<Any?>(type, name)
            saved += { ReflectionHelpers.setStaticField(type, name, old) }
            ReflectionHelpers.setStaticField(type, name, value)
        }
        val work = Work()
        val timers = DormantTimers()
        try {
            CompletionNative.events.clear(); CompletionNative.onUp = {}; CompletionNative.failNextUp = false
            org.robolectric.shadows.ShadowVpnService.setPrepareResult(null)
            field(AndroidRecoveryStores, "instance", store)
            field(AndroidBackgroundCredentialStores, "instance", BackgroundCredentialStore(Record()))
            field(service, "recoveryStore", store)
            field(service, "connectionIntentCoordinator", coordinator)
            field(service, "connectionIntentLifecycle", ConnectionIntentServiceLifecycle(coordinator, schedule = {}))
            field(service, "backgroundLogoutLifecycle", BackgroundLogoutServiceLifecycle(
                logoutState = { BackgroundLogoutReadState.NONE }, recovery = store::read,
                beginRedundantStop = { error("unexpected logout") }, runLogout = {}, scheduleRetry = {}, stopIfIdle = {}))
            field(service, "redundantWork", RedundantVpnWorkDispatcher(Work()))
            static(NelomaiVpnService::class.java, "activeService", service)
            static(NelomaiVpnService::class.java, "serviceReady", CompletableFuture.completedFuture(Unit))
            val oldFuture = ReflectionHelpers.getStaticField<Any>(GoBackend::class.java, "vpnService")
            val future = oldFuture.javaClass.getDeclaredConstructor().apply { isAccessible = true }.newInstance()
            future.javaClass.getDeclaredMethod("complete", Any::class.java).apply { isAccessible = true }.invoke(future, service)
            static(GoBackend::class.java, "vpnService", future)
            field(TunnelRuntime, "executor", work)
            field(TunnelRuntime, "watchdogExecutor", timers)
            field(TunnelRuntime, "stateGate", TunnelStateGate())
            field(TunnelRuntime, "activeSession", null)
            field(TunnelRuntime, "applicationContext", host.applicationContext)
            val backend = GoBackend(host.applicationContext)
            field(TunnelRuntime, "backend", backend)
            val tunnel = ReflectionHelpers.getField<Tunnel>(TunnelRuntime, "tunnel")
            try { test(Fixture(host.applicationContext, service, store, coordinator, backend, tunnel, work)) }
            finally {
                ReflectionHelpers.callInstanceMethod<Unit>(TunnelRuntime, "clearActiveSession")
                backend.setState(tunnel, Tunnel.State.DOWN, null)
            }
        } finally {
            saved.asReversed().forEach { it() }
            CompletionNative.onUp = {}
            timers.shutdownNow()
            controller.destroy()
        }
    }

    private class Fixture(val context: Context, val service: NelomaiVpnService,
        val store: AndroidRecoveryStore, val coordinator: AndroidConnectionIntentCoordinator,
        val backend: GoBackend, val tunnel: Tunnel, val work: Work) {
        fun envelope() = (store.read() as RecoveryStoreResult.Success).value
        fun armCheckpoint() {
            store.beginStart(0, AndroidIntentTemplate("11111111-1111-4111-8111-111111111111",
                "scope", "tic", "dynamic", "standalone", "ipv4", false), AndroidStartReplay("initial", 1, "fp"))
            store.recordLease(envelope().intent.generation, "lease")
            store.activateCheckpoint(envelope().intent.generation)
        }
        fun startService(receiver: ResultReceiver) {
            val args = args()
            ReflectionHelpers.callInstanceMethod<Unit>(service, "handleClientStart",
                ReflectionHelpers.ClassParameter.from(Intent::class.java,
                    Intent(NelomaiVpnService.ACTION_CLIENT_START)
                        .putExtra(EXTRA_API_VERSION, TUNNEL_API_VERSION)
                        .putExtra(EXTRA_CLIENT_OPERATION_ID, java.util.UUID.randomUUID().toString())
                        .putExtra(EXTRA_CONFIGURATION, args.configuration)
                        .putExtra(EXTRA_START_SOURCE, "local_restart")
                        .putExtra(EXTRA_OPTIONS, args.options.toBundle())
                        .putExtra(EXTRA_QUICK_CONNECTION, args.quickConnection!!.toBundle())
                        .putExtra(EXTRA_RESULT_RECEIVER, receiver)))
        }
    }
    private class Receiver(val receive: (Int, Bundle?) -> Unit) : ResultReceiver(null) {
        override fun onReceiveResult(resultCode: Int, resultData: Bundle?) = receive(resultCode, resultData)
    }
    private class Record : EncryptedRecordBackend {
        private var bytes: ByteArray? = null
        override fun read() = bytes?.copyOf()
        override fun write(plaintext: ByteArray): Boolean { bytes = plaintext.copyOf(); return true }
    }
    private class Work : AbstractExecutorService() {
        val jobs = ArrayDeque<Runnable>()
        override fun execute(command: Runnable) { jobs.addLast(command) }
        fun runNext() {
            assertTrue("native worker must be queued", jobs.isNotEmpty())
            try { jobs.removeFirst().run() } catch (error: Throwable) {
                throw AssertionError(org.robolectric.shadows.ShadowLog.getLogs().joinToString("\n") { it.msg }, error)
            }
        }
        override fun shutdown() = Unit
        override fun shutdownNow(): MutableList<Runnable> = mutableListOf()
        override fun isShutdown() = false
        override fun isTerminated() = false
        override fun awaitTermination(timeout: Long, unit: TimeUnit) = false
    }
    private class DormantTimers : ScheduledThreadPoolExecutor(1) {
        override fun schedule(command: Runnable, delay: Long, unit: TimeUnit): ScheduledFuture<*> = DormantFuture()
        override fun scheduleAtFixedRate(command: Runnable, delay: Long, period: Long, unit: TimeUnit): ScheduledFuture<*> = DormantFuture()
    }
    private class DormantFuture : ScheduledFuture<Unit> {
        override fun getDelay(unit: TimeUnit) = Long.MAX_VALUE
        override fun compareTo(other: Delayed) = 0
        override fun cancel(mayInterruptIfRunning: Boolean) = true
        override fun isCancelled() = true
        override fun isDone() = true
        override fun get() = Unit
        override fun get(timeout: Long, unit: TimeUnit) = Unit
    }
    companion object {
        private fun args() = StartTunnelArgs().apply {
            apiVersion = TUNNEL_API_VERSION; startSource = "local_restart"
            configuration = ("[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n" +
                "Address = 10.241.0.3/32\n").toByteArray()
            quickConnection = QuickConnectionArgs().apply {
                leaseId = "lease"; layer = "tic"; ticConnectionMode = "dynamic"; routeMode = "standalone"
                allowAlternate = false
            }
        }
    }
}

@Implements(SharedLibraryLoader::class)
class CompletionNoLibrary {
    companion object {
        @JvmStatic @Implementation fun loadSharedLibrary(context: Context, name: String) = Unit
    }
}
@Implements(org.amnezia.awg.GoBackend::class)
class CompletionNative {
    companion object {
        val events = mutableListOf<String>()
        var onUp: () -> Unit = {}
        var failNextUp = false
        @JvmStatic @Implementation fun awgVersion() = "test-jni"
        @JvmStatic @Implementation fun awgTurnOn(name: String, fd: Int, config: String): Int {
            if (failNextUp) { failNextUp = false; events += "up-failed"; return -1 }
            events += "up"; onUp(); return 41
        }
        @JvmStatic @Implementation fun awgTurnOff(handle: Int) { events += "down" }
        @JvmStatic @Implementation fun awgPreparedSocketToken(handle: Int) = 1L
        @JvmStatic @Implementation fun awgAdmitSockets(handle: Int, token: Long) = 0
        @JvmStatic @Implementation fun awgGetSocketV4(handle: Int) = 101
        @JvmStatic @Implementation fun awgGetSocketV6(handle: Int) = -1
        @JvmStatic @Implementation fun awgGetConfig(handle: Int) = "last_handshake_time_sec=1\n"
    }
}
@Implements(VpnService::class)
class CompletionVpnPermission : org.robolectric.shadows.ShadowVpnService() {
    @Implementation fun protect(socket: Int) = true
    @Implementation fun setUnderlyingNetworks(networks: Array<android.net.Network>?) = true
}
@Implements(VpnService.Builder::class)
class CompletionVpnBuilder {
    @org.robolectric.annotation.RealObject private lateinit var builder: VpnService.Builder
    // Package verification normally crosses Android's package-manager Binder.
    @Implementation fun addDisallowedApplication(packageName: String): VpnService.Builder = builder
    @Implementation fun establish(): ParcelFileDescriptor {
        val pipe = ParcelFileDescriptor.createPipe()
        pipe[1].close()
        return pipe[0]
    }
}
@Implements(ParcelFileDescriptor::class)
class CompletionFileDescriptor : org.robolectric.shadows.ShadowParcelFileDescriptor() {
    @Implementation fun detachFd() = 7
}
