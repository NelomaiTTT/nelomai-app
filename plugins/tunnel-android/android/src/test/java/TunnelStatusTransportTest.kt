package ru.nelomai.tunnel

import android.app.Notification
import android.content.ComponentName
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.content.ServiceConnection
import android.net.VpnService
import android.os.Binder
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Messenger
import android.os.Message
import android.os.Process
import android.os.Parcel
import android.os.Parcelable
import android.os.ResultReceiver
import android.provider.Settings
import java.io.File
import java.time.Duration
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Robolectric
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.Implements
import org.robolectric.shadows.ShadowBinder
import org.robolectric.util.ReflectionHelpers
import ru.nelomai.runtime.v1.RuntimeServiceIntents
import ru.nelomai.runtime.v1.RuntimeVpnHostV1

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE)
class TunnelStatusTransportTest {
    // OS boundaries only: no VPN service, native backend, hardware or network.
    private class Host(private val frameworkService: VpnService? = null) : ContextWrapper(RuntimeEnvironment.getApplication()) {
        var starts = 0
        var binds = 0
        var unbinds = 0
        var observations = 0
        var state = SessionState.STOPPED
        var error: String? = null
        var current = true
        var runtimeMatches = true
        var bindResult = true
        var bindThrows = false
        var unbindThrows = false
        var holdReplies = false
        var holdVerification = false
        var verifyCalls = 0
        var observeThrows = false
        var transformReply: (Bundle) -> Unit = {}
        val replies = mutableListOf<() -> Unit>()
        val verifications = mutableListOf<(Boolean) -> Unit>()
        val mutationActions = mutableListOf<String?>()
        var connection: ServiceConnection? = null
        val handler = Handler(Looper.getMainLooper())
        val component = ComponentName(packageName, RuntimeServiceIntents.VPN_COMPONENT)
        val endpoint = TunnelStatusEndpoint(42, { current }, { complete ->
            verifyCalls++
            if (holdVerification) verifications.add(complete) else complete(runtimeMatches)
        }, { intent ->
            if (observeThrows) throw IllegalStateException("injected observer failure")
            respond(intent.resultReceiver(), intent.getIntExtra(EXTRA_API_VERSION, 0))
        })

        override fun getApplicationContext(): Context = this
        override fun bindService(intent: Intent, connection: ServiceConnection, flags: Int): Boolean {
            assertEquals(component, intent.component)
            assertEquals(VpnService.SERVICE_INTERFACE, intent.action)
            assertTrue(flags and Context.BIND_AUTO_CREATE != 0)
            binds++
            this.connection = connection
            if (bindThrows) throw SecurityException("injected binding failure")
            if (!bindResult) return false
            handler.post { connection.onServiceConnected(component, frameworkService?.onBind(intent) ?: Binder()) }
            return true
        }
        override fun unbindService(connection: ServiceConnection) {
            unbinds++
            if (unbindThrows) throw IllegalArgumentException("already unbound")
        }
        override fun startService(intent: Intent): ComponentName {
            assertEquals(component, intent.component)
            if (intent.action != NelomaiVpnService.ACTION_CLIENT_STATUS) {
                mutationActions.add(intent.action)
                intent.resultReceiver()!!.send(SERVICE_RESULT_OK, Bundle().apply {
                    putString(EXTRA_STATE, state.wireName)
                })
                return component
            }
            starts++
            respond(intent.resultReceiver(), intent.getIntExtra(EXTRA_API_VERSION, 0))
            return component
        }
        private fun respond(receiver: ResultReceiver?, apiVersion: Int) {
            observations++
            val capturedState = state
            val capturedError = if (apiVersion != TUNNEL_API_VERSION) "unsupported_api_version" else error
            val result = Bundle().apply {
                putString(EXTRA_STATE, capturedState.wireName)
                putLong(EXTRA_DURATION_MILLIS, 0)
                putString(EXTRA_ERROR_CODE, capturedError)
            }
            val reply = {
                val wire = object : ResultReceiver(handler) {
                    override fun onReceiveResult(code: Int, data: Bundle?) {
                        val response = Bundle(data ?: Bundle.EMPTY)
                        transformReply(response)
                        receiver!!.send(code, response)
                    }
                }
                endpoint.replyTo(wire).send(
                    if (capturedError == null) SERVICE_RESULT_OK else SERVICE_RESULT_ERROR, result)
            }
            if (holdReplies) replies.add(reply) else reply()
        }
    }

    @After fun releasePollingLease() {
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(6))
    }

    private fun poll(host: Host, expected: SessionState = host.state, expectedError: String? = host.error) {
        var callbacks = 0
        TunnelServiceClient.status(host, TUNNEL_API_VERSION, { state, _ ->
            callbacks++
            assertNull(expectedError)
            assertEquals(expected, state)
        }, { code -> callbacks++; assertEquals(expectedError, code) })
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals(1, callbacks)
    }

    @Test fun hundredIdlePollsUseOneServiceStartAndOneBindingButHundredLiveObservations() {
        val host = Host()
        var callbacks = 0
        repeat(100) {
            TunnelServiceClient.status(host, TUNNEL_API_VERSION, { state, duration ->
                assertEquals(SessionState.STOPPED, state)
                assertEquals(0L, duration)
                callbacks++
            }, { fail(it) })
            shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(1))
        }
        assertEquals(100, callbacks)
        assertEquals(100, host.observations)
        assertEquals("NLM-013: repeated status must reuse its live endpoint", 1, host.starts)
        assertEquals(1, host.binds)
    }

    @Test fun bindingUsesRealStandardVpnBinderAndNoPrivateBindAction() {
        val service = Robolectric.buildService(VpnService::class.java).create()
        try {
            assertNotNull(service.get().onBind(Intent(VpnService.SERVICE_INTERFACE)))
            assertNull(service.get().onBind(Intent(NelomaiVpnService.ACTION_CLIENT_STATUS)))
        } finally { service.destroy() }
    }

    @Test fun boundPollingDoesNotPreventRealEngineStopSelfOrForegroundRemovalAndReleasesOnBackground() {
        val controller = Robolectric.buildService(VpnService::class.java).create()
        val service = controller.get()
        val engine = NelomaiVpnService(object : RuntimeVpnHostV1 {
            override val service = controller.get()
            override fun builder(beforeEstablish: (VpnService.Builder) -> Unit) = service.Builder()
        })
        val previous = ReflectionHelpers.getStaticField<Any?>(NelomaiVpnService::class.java, "activeService")
        ReflectionHelpers.setStaticField(NelomaiVpnService::class.java, "activeService", engine)
        try {
            val host = Host(service)
            engine.onStartCommand(Intent("test.noop"), 0, 1)
            service.startForeground(21, Notification.Builder(service).setContentTitle("VPN").build())
            poll(host)
            NelomaiVpnService.stopForegroundService()
            assertTrue(shadowOf(service).isStoppedBySelf)
            assertEquals(1, shadowOf(service).stopSelfResultId)
            assertTrue(shadowOf(service).isForegroundStopped)
            assertEquals(0, host.unbinds)
            poll(host)
            assertEquals(1, host.starts)
            // Robolectric does not implement AMS binding ownership. We verify
            // real stopSelf/foreground calls and transport unbinding; Android's
            // final onDestroy delivery after that unbind remains an OS boundary.
            shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(5))
            assertEquals(1, host.unbinds)
        } finally {
            ReflectionHelpers.setStaticField(NelomaiVpnService::class.java, "activeService", previous)
            controller.destroy()
        }
    }

    @Test fun directLegacyStartAndEveryRuntimeTransitionRemainLiveEvenWithIdleProjection() {
        val host = Host()
        Settings.Global.putInt(host.contentResolver, Settings.Global.BOOT_COUNT, 7)
        IdleConnectionIntentProjection.open(host).publish(AndroidRecoveryEnvelope.empty(7))
        poll(host)
        QuickTunnelController.updateState(host, SessionState.STARTING, desiredActive = true)
        for (state in SessionState.values()) {
            host.state = state
            poll(host)
        }
        assertEquals(1, host.starts)
        assertEquals(1 + SessionState.values().size, host.observations)
    }

    @Test fun recoveryLogoutCleanupAndCorruptOrRebootedProjectionNeverSupplyAStatus() {
        val host = Host()
        Settings.Global.putInt(host.contentResolver, Settings.Global.BOOT_COUNT, 7)
        IdleConnectionIntentProjection.open(host).publish(AndroidRecoveryEnvelope.empty(7))
        poll(host)
        host.state = SessionState.STOPPING
        poll(host)
        for (code in listOf("recovery_record_read_failed", "boot_identity_unavailable", "background_logout_pending")) {
            host.error = code
            poll(host)
        }
        host.error = null
        Settings.Global.putInt(host.contentResolver, Settings.Global.BOOT_COUNT, 8)
        poll(host)
        File(AndroidRuntimeNamespace.directory(host), "idle-intent-projection.json").writeText("broken")
        poll(host)
        assertEquals(1, host.starts)
    }

    @Test fun concurrentColdPollsBootstrapOnlyOnce() {
        val host = Host()
        var callbacks = 0
        repeat(100) {
            TunnelServiceClient.status(host, TUNNEL_API_VERSION, { _, _ -> callbacks++ }, { fail(it) })
        }
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals(100, callbacks)
        assertEquals(100, host.observations)
        assertEquals(1, host.starts)
        assertEquals(1, host.binds)
    }

    @Test fun fiveSecondsWithoutPollingReleaseBindingAndNextPollBootstrapsAgain() {
        val host = Host()
        poll(host)
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(4))
        poll(host)
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(4))
        assertEquals(0, host.unbinds)
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(1))
        assertEquals(1, host.unbinds)
        poll(host)
        assertEquals(2, host.binds)
        assertEquals(2, host.starts)
    }

    @Test fun unavailableBindingFallsBackToExistingRpcWithoutInventingStopped() {
        for (throws in listOf(false, true)) {
            val host = Host().apply { bindResult = false; bindThrows = throws; state = SessionState.RUNNING }
            repeat(3) { poll(host) }
            assertEquals(3, host.starts)
            shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(5))
            assertEquals(1, host.unbinds)
        }
    }

    @Test fun disconnectDeathAndNullBindingDiscardSessionAndIgnoreLateReplies() {
        for (event in listOf("disconnect", "death", "null")) {
            val host = Host()
            poll(host)
            host.holdReplies = true
            var successes = 0
            var failures = 0
            TunnelServiceClient.status(host, TUNNEL_API_VERSION, { _, _ -> successes++ }, { failures++ })
            shadowOf(Looper.getMainLooper()).idle()
            val oldConnection = host.connection!!
            when (event) {
                "disconnect" -> oldConnection.onServiceDisconnected(host.component)
                "death" -> oldConnection.onBindingDied(host.component)
                else -> oldConnection.onNullBinding(host.component)
            }
            assertEquals(1, failures)
            assertEquals(1, host.unbinds)
            host.replies.forEach { it() }
            shadowOf(Looper.getMainLooper()).idle()
            assertEquals(0, successes)
            assertEquals(1, failures)
            host.holdReplies = false
            poll(host)
            oldConnection.onBindingDied(host.component)
            poll(host)
            assertEquals(2, host.starts)
            shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(5))
        }
    }

    @Test fun requestWatchdogCompletesEachOutstandingCallbackOnceAndLateReplyCannotResurrectEndpoint() {
        val host = Host().apply { holdReplies = true; unbindThrows = true }
        var successes = 0
        var failures = 0
        repeat(3) {
            TunnelServiceClient.status(host, TUNNEL_API_VERSION, { _, _ -> successes++ }, { failures++ })
        }
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(29))
        assertEquals(0, failures)
        assertEquals(0, host.unbinds)
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(1))
        assertEquals(3, failures)
        assertEquals(1, host.unbinds)
        host.replies.forEach { it() }
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals(0, successes)
        assertEquals(3, failures)
        host.holdReplies = false
        poll(host)
        assertEquals(2, host.starts)
    }

    @Test fun generationChangeRevokeAndRuntimeSwitchFenceRepliesAlreadyInFlight() {
        for (reason in listOf("generation", "revoke", "runtime")) {
            val host = Host()
            poll(host)
            host.holdReplies = true
            var successes = 0
            var failures = 0
            TunnelServiceClient.status(host, TUNNEL_API_VERSION, { _, _ -> successes++ }, { failures++ })
            shadowOf(Looper.getMainLooper()).idle()
            when (reason) {
                "generation" -> host.current = false
                "revoke" -> host.endpoint.close()
                else -> host.runtimeMatches = false
            }
            host.replies.forEach { it() }
            shadowOf(Looper.getMainLooper()).idle()
            assertEquals(0, successes)
            assertEquals(1, failures)
            assertEquals(1, host.unbinds)
        }
    }

    @Test fun endpointRejectsWrongOpcodeGenerationAndRuntimeWithoutObservation() {
        val host = Host()
        var errors = 0
        val reply = object : ResultReceiver(Handler(Looper.getMainLooper())) {
            override fun onReceiveResult(code: Int, data: Bundle?) { assertEquals(SERVICE_RESULT_ERROR, code); errors++ }
        }
        for (bad in listOf("opcode", "generation", "runtime")) {
            host.endpoint.messenger.send(Message.obtain().apply {
                what = if (bad == "opcode") 99 else STATUS_OBSERVE
                data = Bundle().apply {
                    putLong(EXTRA_STATUS_GENERATION, if (bad == "generation") 43 else 42)
                    putInt(EXTRA_API_VERSION, TUNNEL_API_VERSION)
                    putString(EXTRA_STATUS_RUNTIME, if (bad == "runtime") "old/runtime" else "${BuildConfig.RUNTIME_SLOT}/${BuildConfig.RUNTIME_VERSION}")
                    putParcelable(EXTRA_RESULT_RECEIVER, reply)
                }
            })
        }
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals(2, errors) // Wrong opcode is dropped before reading its reply parcel.
        assertEquals(0, host.observations)
    }

    private fun message(reply: ResultReceiver): Message = Message.obtain().apply {
        what = STATUS_OBSERVE
        data = Bundle().apply {
            putInt(EXTRA_API_VERSION, TUNNEL_API_VERSION)
            putLong(EXTRA_STATUS_GENERATION, 42)
            putString(EXTRA_STATUS_RUNTIME, "${BuildConfig.RUNTIME_SLOT}/${BuildConfig.RUNTIME_VERSION}")
            putParcelable(EXTRA_RESULT_RECEIVER, reply)
        }
    }

    private fun parcelledMessage(reply: ResultReceiver, change: (Message) -> Unit = {}): Message {
        val request = message(reply).also(change)
        val parcel = Parcel.obtain()
        try {
            parcel.writeBundle(request.data)
            parcel.setDataPosition(0)
            // On-device Messenger defaults to a boot loader that cannot see
            // runtime classes. Robolectric's default can see test/app classes,
            // so model only that visibility boundary; Parcel remains real.
            val bootLoader = object : ClassLoader(ResultReceiver::class.java.classLoader) {
                override fun loadClass(name: String, resolve: Boolean): Class<*> {
                    if (name.startsWith("ru.nelomai.")) throw ClassNotFoundException(name)
                    return super.loadClass(name, resolve)
                }
            }
            request.data = parcel.readBundle(bootLoader)!!
            return request
        } finally { parcel.recycle() }
    }

    @Test
    @Config(shadows = [ParcelResultReceiver::class])
    fun parcelledReplyReceivesFreshRunningAndStoppedStatusWithoutTimeout() {
        val host = Host()
        val states = mutableListOf<String?>()
        val reply = object : ResultReceiver(Handler(Looper.getMainLooper())) {
            override fun onReceiveResult(code: Int, data: Bundle?) {
                assertEquals(SERVICE_RESULT_OK, code)
                states.add(data?.getString(EXTRA_STATE))
            }
        }
        host.state = SessionState.RUNNING
        host.endpoint.messenger.send(parcelledMessage(reply))
        shadowOf(Looper.getMainLooper()).idle()
        host.state = SessionState.STOPPED
        host.endpoint.messenger.send(parcelledMessage(reply))
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals(listOf("running", "stopped"), states)
        assertEquals(2, host.observations)
    }

    @Test
    @Config(shadows = [ParcelResultReceiver::class])
    fun parcelledReplyStillRejectsStaleGenerationAndRuntime() {
        val host = Host()
        val errors = mutableListOf<String?>()
        val reply = object : ResultReceiver(Handler(Looper.getMainLooper())) {
            override fun onReceiveResult(code: Int, data: Bundle?) {
                assertEquals(SERVICE_RESULT_ERROR, code)
                errors.add(data?.getString(EXTRA_ERROR_CODE))
            }
        }
        host.endpoint.messenger.send(parcelledMessage(reply) { it.data.putLong(EXTRA_STATUS_GENERATION, 43) })
        host.endpoint.messenger.send(parcelledMessage(reply) { it.data.putString(EXTRA_STATUS_RUNTIME, "old/runtime") })
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals(listOf(STATUS_ENDPOINT_UNAVAILABLE, STATUS_ENDPOINT_UNAVAILABLE), errors)
        assertEquals(0, host.observations)
        assertEquals(0, host.verifyCalls)
    }

    @Test fun wrongUidIsDroppedBeforeDeserializationAndWrongApiNeverObserves() {
        val host = Host()
        var errors = 0
        val reply = object : ResultReceiver(Handler(Looper.getMainLooper())) {
            override fun onReceiveResult(code: Int, data: Bundle?) { assertEquals(SERVICE_RESULT_ERROR, code); errors++ }
        }
        ShadowBinder.setCallingUid(Process.myUid() + 1)
        try { host.endpoint.messenger.send(message(reply)) }
        finally { ShadowBinder.setCallingUid(Process.myUid()) }
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals(0, errors)
        host.endpoint.messenger.send(message(reply).apply { data.putInt(EXTRA_API_VERSION, -1) })
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals(1, errors)
        assertEquals(0, host.observations)
        assertEquals(0, host.verifyCalls)
    }

    @Test fun malformedReplyParcelAndObserverExceptionCannotEscapeTheServiceHandler() {
        val host = Host()
        // Wrong Parcelable type must not cast-crash the :vpn Handler.
        host.endpoint.messenger.send(Message.obtain().apply {
            what = STATUS_OBSERVE
            data = Bundle().apply { putParcelable(EXTRA_RESULT_RECEIVER, Intent("wrong_type")) }
        })
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals(0, host.observations)
        poll(host)
        host.observeThrows = true
        poll(host, expectedError = STATUS_ENDPOINT_UNAVAILABLE)
        assertEquals(1, host.unbinds)
    }

    @Test fun malformedParcelableIsContainedAndWrongUidDoesNotUnpackIt() {
        val host = Host()
        fun malformed(): Message {
            val parcel = Parcel.obtain()
            try {
                parcel.writeBundle(Bundle().apply { putParcelable(EXTRA_RESULT_RECEIVER, ExplodingParcelable()) })
                parcel.setDataPosition(0)
                return Message.obtain().apply {
                    what = STATUS_OBSERVE
                    data = parcel.readBundle(ExplodingParcelable::class.java.classLoader)!!
                }
            } finally { parcel.recycle() }
        }
        ExplodingParcelable.reads = 0
        ShadowBinder.setCallingUid(Process.myUid() + 1)
        try { host.endpoint.messenger.send(malformed()) }
        finally { ShadowBinder.setCallingUid(Process.myUid()) }
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals(0, ExplodingParcelable.reads)
        host.endpoint.messenger.send(malformed())
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals(1, ExplodingParcelable.reads)
        assertEquals(0, host.observations)
    }

    @Test fun duplicateBootstrapReplyCompletesOnceAndDoesNotCreateAnotherBinding() {
        val host = Host().apply { holdReplies = true }
        var callbacks = 0
        TunnelServiceClient.status(host, TUNNEL_API_VERSION, { _, _ -> callbacks++ }, { fail(it) })
        shadowOf(Looper.getMainLooper()).idle()
        repeat(2) { host.replies.single().invoke() }
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals(1, callbacks)
        host.holdReplies = false
        poll(host)
        assertEquals(1, host.binds)
        assertEquals(1, host.starts)
    }

    @Test fun invalidApiIsRejectedBeforeAnyBindingOrServiceStart() {
        val host = Host()
        var errors = 0
        TunnelServiceClient.status(host, -1, { _, _ -> fail("invalid API accepted") }, {
            assertEquals("unsupported_api_version", it)
            errors++
        })
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals(1, errors)
        assertEquals(0, host.binds)
        assertEquals(0, host.starts)
    }

    @Test fun slowColdBootstrapKeepsBindingPastFiveSecondsThenExpiresAfterCompletion() {
        val host = Host().apply { holdReplies = true }
        var successes = 0
        TunnelServiceClient.status(host, TUNNEL_API_VERSION, { _, _ -> successes++ }, { fail(it) })
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(12))
        assertEquals(0, host.unbinds)
        assertEquals(0, successes)
        host.replies.single().invoke()
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals(1, successes)
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(4))
        assertEquals(0, host.unbinds)
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(1))
        assertEquals(1, host.unbinds)
    }

    @Test fun lateSelectionCallbackAfterCloseCannotObserveOrReplyWithState() {
        val host = Host()
        poll(host)
        host.holdVerification = true
        var successes = 0
        var errors = 0
        TunnelServiceClient.status(host, TUNNEL_API_VERSION, { _, _ -> successes++ }, { errors++ })
        shadowOf(Looper.getMainLooper()).idle()
        host.endpoint.close()
        host.verifications.single().invoke(true)
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals(0, successes)
        assertEquals(1, errors)
        assertEquals(1, host.observations)
    }

    @Test fun inconsistentReplyGenerationOrRuntimeDiscardsEndpoint() {
        for (key in listOf(EXTRA_STATUS_GENERATION, EXTRA_STATUS_RUNTIME)) {
            val host = Host()
            poll(host)
            host.transformReply = {
                if (key == EXTRA_STATUS_GENERATION) it.putLong(key, 99) else it.putString(key, "old/runtime")
            }
            poll(host, expectedError = STATUS_ENDPOINT_UNAVAILABLE)
            assertEquals(1, host.unbinds)
        }
    }

    @Test fun endpointBinderDeathReleasesBindingAndNextPollBootstraps() {
        val host = Host()
        val recipients = mutableListOf<IBinder.DeathRecipient>()
        val deathBinder = object : IBinder by host.endpoint.messenger.binder {
            override fun linkToDeath(recipient: IBinder.DeathRecipient, flags: Int) { recipients.add(recipient) }
            override fun unlinkToDeath(recipient: IBinder.DeathRecipient, flags: Int): Boolean = recipients.remove(recipient)
        }
        host.transformReply = { it.putBinder(EXTRA_STATUS_ENDPOINT, deathBinder) }
        poll(host)
        recipients.toList().forEach { it.binderDied() }
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals(1, host.unbinds)
        poll(host)
        assertEquals(2, host.starts)
    }

    @Test fun stopBypassesFailedObserverAndUnreadableProjection() {
        val host = Host().apply { bindThrows = true }
        poll(host)
        val directory = AndroidRuntimeNamespace.directory(host).also { it.mkdirs() }
        val projectionFile = File(directory, "idle-intent-projection.json")
        projectionFile.delete()
        projectionFile.mkdir()
        val child = File(projectionFile, "fixture").also { it.writeText("busy") }
        try {
            assertFalse(IdleConnectionIntentProjection.open(host).invalidate())
            var stopped = 0
            TunnelServiceClient.stop(host, TUNNEL_API_VERSION, { _, _ -> stopped++ }, { fail(it) })
            shadowOf(Looper.getMainLooper()).idle()
            assertEquals(1, stopped)
            assertEquals(listOf(NelomaiVpnService.ACTION_CLIENT_STOP), host.mutationActions)
            assertTrue(QuickTunnelController.updateState(host, SessionState.STOPPED, changed = true))
        } finally { child.delete(); projectionFile.delete() }
    }
}

// Robolectric's default ShadowResultReceiver invokes onReceiveResult locally,
// dropping replies on deserialized receivers. Keep the actual framework Binder
// send implementation for tests that cross a Parcel boundary.
@Implements(ResultReceiver::class)
class ParcelResultReceiver

class ExplodingParcelable : Parcelable {
    override fun describeContents() = 0
    override fun writeToParcel(destination: Parcel, flags: Int) {}
    companion object {
        var reads = 0
        @JvmField val CREATOR = object : Parcelable.Creator<ExplodingParcelable> {
            override fun createFromParcel(source: Parcel): ExplodingParcelable {
                reads++
                throw IllegalArgumentException("injected malformed parcel")
            }
            override fun newArray(size: Int): Array<ExplodingParcelable?> = arrayOfNulls(size)
        }
    }
}
