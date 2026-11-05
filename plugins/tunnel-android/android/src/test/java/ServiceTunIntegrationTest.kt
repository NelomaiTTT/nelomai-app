package ru.nelomai.tunnel

import android.net.VpnService
import org.amnezia.awg.backend.GoBackend
import org.amnezia.awg.backend.Tunnel
import org.amnezia.awg.config.Config
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config as RoboConfig
import org.robolectric.annotation.LooperMode
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements
import org.robolectric.annotation.RealObject
import org.robolectric.util.ReflectionHelpers
import ru.nelomai.runtime.v1.RuntimeVpnHostV1

/** Production service/factory/adapters; file TUN, JNI and network backend are substitutes. */
@RunWith(RobolectricTestRunner::class)
@RoboConfig(sdk = [34], manifest = RoboConfig.NONE, shadows = [NoNativeLibrary::class,
    OwnershipNative::class, OwnershipVpn::class, RetentionServiceBuilder::class, OwnershipDescriptor::class])
@LooperMode(LooperMode.Mode.PAUSED)
class ServiceTunIntegrationTest {
    @Test fun healthyPreferenceToggleKeepsLegacyAndRedundantTransport() {
        for (redundant in listOf(false, true)) fixture(enabled = false) { f ->
            f.host.getSharedPreferences("nelomai-kill-switch-device-v1", 0).edit().clear().commit()
            val native = if (redundant) f.redundant().also {
                assertTrue(it.start("a", RedundantSlot.A, configBytes(), null))
                assertTrue(it.activate("a")); assertTrue(it.confirmTunReady())
            } else null
            if (!redundant) { f.startLegacy(); f.confirmLegacy() }
            val original = OwnershipBuilder.established
            val descriptors = OwnershipNative.engineDescriptors.values.toList()
            var replies = 0
            val reply = object : android.os.ResultReceiver(android.os.Handler(android.os.Looper.getMainLooper())) {
                override fun onReceiveResult(code: Int, data: android.os.Bundle?) {
                    assertEquals(SERVICE_RESULT_OK, code); replies++
                }
            }
            fun set(enabled: Boolean) {
                f.call("handleKillSwitchPreference", android.content.Intent()
                    .putExtra("enabled", enabled).putExtra("confirmed", true)
                    .putExtra(EXTRA_RESULT_RECEIVER, reply))
                shadowOf(android.os.Looper.getMainLooper()).idle()
            }
            set(true)
            assertEquals("armed", f.retention.state())
            assertTrue(KillSwitchPreference(f.host).enabled)
            set(false)
            assertEquals("off", f.retention.state())
            assertFalse(KillSwitchPreference(f.host).enabled)
            assertTrue(KillSwitchPreference(f.host).disclosed)
            set(true)
            assertEquals("armed", f.retention.state())
            assertEquals(3, replies)
            assertSame(original, OwnershipBuilder.established)
            assertTrue(descriptors.all { it.fileDescriptor.valid() })
            native?.stop() ?: f.stopLegacy()
            assertEquals("blocked", f.retention.state())
        }
    }

    @Test fun protectionStatusReportsNativeVpnAndActionableCauseWithoutBootstrap() = fixture { f ->
        ReflectionHelpers.setField(f.service, "killSwitchCause", "access_expired")
        val running = android.os.Bundle().apply { putString(EXTRA_STATE, "running") }
        f.call("appendKillSwitchStatus", running)
        val status = running.killSwitchStatus()
        assertTrue(status.getBoolean("vpnActive"))
        assertEquals("action_required", status.getString("cause"))
        assertEquals("off", status.getString("state"))
        val stopped = android.os.Bundle().apply { putString(EXTRA_STATE, "stopped") }
        f.call("appendKillSwitchStatus", stopped)
        assertFalse(stopped.killSwitchStatus().getBoolean("vpnActive"))
    }

    @Test fun oldHandshakeCannotClaimRecoveryAfterPathLoss() = fixture { f ->
        f.startLegacy()
        f.service.onLegacyTransportReady(f.backend, 1_000)
        assertEquals("armed", f.retention.state())
        f.retention.unavailable(f.backend)
        assertEquals("blocked", f.retention.state())
        f.service.onLegacyTransportReady(f.backend, 1_000)
        assertEquals("blocked", f.retention.state())
        f.service.onLegacyTransportReady(f.backend, 2_000)
        assertEquals("armed", f.retention.state())
    }

    @Test fun serviceNotificationWaitsTwentySecondsAndStopCancelsIt() = fixture { f ->
        KillSwitchPreference(f.host).save(true, confirmed = true)
        val manager = shadowOf(f.host.getSystemService(android.app.NotificationManager::class.java))
        val main = shadowOf(android.os.Looper.getMainLooper())
        f.startLegacy(); f.confirmLegacy(); main.idle()
        f.stopLegacy(); main.idle()
        assertNull(manager.getNotification(22))
        main.idleFor(java.time.Duration.ofSeconds(19))
        assertNull(manager.getNotification(22))
        main.idleFor(java.time.Duration.ofSeconds(1))
        assertNotNull(manager.getNotification(22))
        f.call("releaseProtection", false); main.idle()
        assertNull(manager.getNotification(22))
        main.idleFor(java.time.Duration.ofSeconds(20))
        assertNull(manager.getNotification(22))
    }

    @Test fun readinessCallbackMustNotWaitForNativeMutation() {
        for (enabled in listOf(true, false)) fixture(enabled) { f ->
        val native = f.redundant()
        assertTrue(native.start("a", RedundantSlot.A, configBytes(), null))
        assertTrue(native.activate("a"))
        val entered = java.util.concurrent.CountDownLatch(1)
        val release = java.util.concurrent.CountDownLatch(1)
        val delegate = ReflectionHelpers.getField<RedundantSessionBackend>(native, "backend")
        ReflectionHelpers.setField(native, "backend", object : RedundantSessionBackend by delegate {
            override fun startSlot(session: NativeSession, slot: Int, configuration: ByteArray): Boolean {
                entered.countDown()
                check(release.await(3, java.util.concurrent.TimeUnit.SECONDS))
                return delegate.startSlot(session, slot, configuration)
            }
        })
        val workers = java.util.concurrent.Executors.newFixedThreadPool(2)
        try {
            val standby = workers.submit<Boolean> { native.start("b", RedundantSlot.B, configBytes(), null) }
            assertTrue(entered.await(2, java.util.concurrent.TimeUnit.SECONDS))
            // NelomaiVpnService invokes this synchronously from restoreHandler (main).
            val ready = workers.submit<Boolean> { native.confirmTunReady() }
            assertTrue("UI readiness callback must stay responsive while native is occupied",
                ready.get(300, java.util.concurrent.TimeUnit.MILLISECONDS))
            release.countDown()
            assertTrue(standby.get(2, java.util.concurrent.TimeUnit.SECONDS))
        } finally { release.countDown(); workers.shutdown(); workers.awaitTermination(3, java.util.concurrent.TimeUnit.SECONDS); native.stop() }
        assertFalse(native.confirmTunReady())
        }
    }

    @Test fun redundantRecoveryAfterRejectedLegacyStartCanConfirmTun() = fixture { f ->
        f.retention.beginStart("legacy")
        f.startLegacy()
        f.confirmLegacy()
        f.retention.rejectStart("legacy")
        f.stopLegacy()
        val native = f.redundant()
        assertTrue(native.start("a", RedundantSlot.A, configBytes(), null))
        assertTrue(native.activate("a"))
        assertTrue(native.confirmTunReady())
        f.retention.rejectStart("legacy")
        native.stop()
        assertTrue(f.retention.hasTun())
    }

    @Test fun serviceRetainsLegacyTunAcrossNativeDownAndRecovery() = fixture { f ->
        f.startLegacy()
        f.confirmLegacy()
        f.stopLegacy()
        assertTrue(f.retention.hasTun())
        assertTrue(OwnershipNative.engineDescriptors.isEmpty())
        f.startLegacy()
        f.confirmLegacy()
        f.stopLegacy()
        assertTrue(f.retention.hasTun())
        // Existing automatic foreground cleanup must not destroy an armed owner.
        ReflectionHelpers.setField(f.service, "lastHandledStartId", 1)
        f.call("finishService", 1)
        assertFalse(shadowOf(f.host).isStoppedBySelf)
        assertEquals(true, f.call("releaseProtection", false))
        assertFalse(f.retention.hasTun())
    }

    @Test fun serviceReleasesUnconfirmedLegacyTunOnNativeDown() = fixture { f ->
        f.startLegacy()
        f.call("confirmLegacyTun", f.retention.ticket())
        // A successful transport callback alone is not handshake readiness.
        f.stopLegacy()
        assertFalse(f.retention.hasTun())
    }

    @Test fun legacySocketAdmissionFailureReleasesServiceTun() = fixture { f ->
        OwnershipVpn.protectSucceeds = false
        assertThrows(Exception::class.java) { f.startLegacy() }
        assertFalse(f.retention.hasTun())
        assertTrue(OwnershipNative.engineDescriptors.isEmpty())
    }

    @Test fun nativeCloseExceptionStillReleasesProvisionalServiceCopy() = fixture { f ->
        f.startLegacy()
        OwnershipNative.beforeStop = { throw IllegalStateException("injected native close failure") }
        assertThrows(IllegalStateException::class.java) { f.stopLegacy() }
        assertFalse(f.retention.hasTun())
    }

    @Test fun hotStandbyUsesOneTunAcrossPromotionBothSlotLossAndFullClose() = fixture { f ->
        val native = f.redundant()
        assertTrue(native.start("a", RedundantSlot.A, configBytes(), null))
        val shared = OwnershipBuilder.established
        assertTrue(native.start("b", RedundantSlot.B, configBytes(), null))
        assertSame(shared, OwnershipBuilder.established)
        assertTrue(native.activate("a"))
        assertTrue(native.confirmTunReady())
        assertTrue(native.activate("b"))
        assertTrue(native.stopSlot("a"))
        assertTrue(native.stopSlot("b"))
        assertTrue(native.stop())
        assertTrue(OwnershipNative.engineDescriptors.isEmpty())
        assertTrue(f.retention.hasTun())
        assertTrue(shared!!.fileDescriptor.valid())
        // A recovered coordinator may own another lease and another TUN.
        val replacement = f.redundant()
        assertTrue(replacement.start("new", RedundantSlot.A, configBytes(), null))
        assertFalse(shared.fileDescriptor.valid())
        assertTrue(replacement.confirmTunReady())
        assertTrue(native.closeForStop())
        assertTrue(f.retention.hasTun())
        assertTrue(replacement.closeForStop())
        assertTrue(f.retention.hasTun())
        assertEquals(true, f.call("releaseProtection", false))
        assertFalse(f.retention.hasTun())
    }

    @Test fun cancelledInitialRedundantReadinessDoesNotKeepBlock() = fixture { f ->
        val native = f.redundant()
        assertTrue(native.start("a", RedundantSlot.A, configBytes(), null))
        assertTrue(native.activate("a"))
        assertTrue(native.closeForStop())
        assertFalse(native.confirmTunReady())
        assertFalse(f.retention.hasTun())
    }

    @Test fun initialRedundantNativeFailureClosesServiceCopy() = fixture { f ->
        val native = f.redundant(failStart = true)
        assertFalse(native.start("a", RedundantSlot.A, configBytes(), null))
        assertFalse(f.retention.hasTun())
        assertTrue(OwnershipNative.engineDescriptors.isEmpty())
    }

    @Test fun blockedPolicyReplacementDoesNotClaimARecoveredPath() = fixture { f ->
        val native = f.redundant()
        assertTrue(native.start("a", RedundantSlot.A, configBytes(), null))
        assertTrue(native.activate("a")); assertTrue(native.confirmTunReady())
        val owner = ReflectionHelpers.getField<Any>(f.retention, "currentOwner")
        f.retention.unavailable(owner)
        assertEquals("blocked", f.retention.state())
        val before = OwnershipBuilder.established!!
        assertTrue(native.replacePolicy(AndroidTunnelOptions()) { false })
        assertNotSame(before, OwnershipBuilder.established)
        assertTrue(f.retention.hasTun())
        assertEquals("blocked", f.retention.state())
        // Only the existing health/readiness callback may confirm the new path.
        assertTrue(native.confirmTunReady())
        assertEquals("armed", f.retention.state())
        native.stop()
        assertEquals("blocked", f.retention.state())
    }

    @Test fun policyReplacementPreservesArmedTunWhenNativeAdmissionFails() = fixture { f ->
        val native = f.redundant()
        assertTrue(native.start("a", RedundantSlot.A, configBytes(), null))
        assertTrue(native.activate("a"))
        assertTrue(native.confirmTunReady())
        val before = OwnershipBuilder.established!!
        f.failRedundantStart = true
        assertFalse(native.replacePolicy(AndroidTunnelOptions()) { false })
        assertFalse(before.fileDescriptor.valid())
        assertTrue(f.retention.hasTun())
        assertTrue(OwnershipBuilder.established!!.fileDescriptor.valid())
        native.stop()
        assertTrue(f.retention.hasTun())
    }

    private class Fixture(val host: VpnService, val service: NelomaiVpnService) {
        val backend = GoBackend(host, true)
        val retention: ServiceTunRetention = ReflectionHelpers.getField(service, "tunRetention")
        var failRedundantStart = false
        private val tunnel = object : Tunnel {
            override fun getName() = "retention-service"
            override fun onStateChange(state: Tunnel.State) = Unit
        }
        fun startLegacy() { backend.setState(tunnel, Tunnel.State.UP, Config.parse(configBytes().inputStream())) }
        fun stopLegacy() { backend.setState(tunnel, Tunnel.State.DOWN, null) }
        fun confirmLegacy() {
            call("confirmLegacyTun", retention.ticket())
            service.onLegacyTransportReady(backend)
        }
        fun call(name: String, vararg args: Any?): Any? = service.javaClass.declaredMethods
            .single { it.name == name && it.parameterCount == args.size }
            .apply { isAccessible = true }.invoke(service, *args)
        fun redundant(failStart: Boolean = false): ServiceRedundantConnectionNative {
            val store = AndroidRecoveryStore(object : EncryptedRecordBackend {
                var bytes: ByteArray? = null
                override fun read() = bytes?.copyOf()
                override fun write(plaintext: ByteArray): Boolean { bytes = plaintext.copyOf(); return true }
            }, BootIdentityProvider { 7L })
            ReflectionHelpers.setField(service, "recoveryStore", store)
            val tx = AndroidRedundantTransaction(true,
                AndroidIntentTemplate("device", "account", "stray", "dynamic", "standalone", "ipv4", true),
                "session", "a", "b", "a", true, 0, 0, "start", "fingerprint")
            @Suppress("UNCHECKED_CAST")
            val pair = call("createRedundantCoordinator", tx, "10.200.0.2/32",
                PhysicalNetworkState(emptyList(), emptyList(), false, "fixture"), false, false)
                as Pair<RedundantConnectionCoordinator, ServiceRedundantConnectionNative>
            val recording = RecordingSessionBackend()
            val backend = object : RedundantSessionBackend by recording {
                override fun start(fd: Int, slot: Int, configuration: ByteArray): NativeSession? {
                    if (failStart || failRedundantStart) {
                        OwnershipNative.engineDescriptors.remove(fd)?.close()
                        return null
                    }
                    return recording.start(fd, slot, configuration)
                }
                override fun close(session: NativeSession) {
                    recording.close(session)
                    OwnershipNative.engineDescriptors.values.forEach { it.close() }
                    OwnershipNative.engineDescriptors.clear()
                }
            }
            ReflectionHelpers.setField(pair.second, "backend", backend)
            return pair.second
        }
    }

    private fun fixture(enabled: Boolean = true, test: (Fixture) -> Unit) {
        OwnershipNative.reset(); OwnershipDescriptor.reset(); OwnershipVpn.protectSucceeds = true
        org.robolectric.shadows.ShadowVpnService.setPrepareResult(null)
        val controller = Robolectric.buildService(VpnService::class.java).create()
        val host = controller.get()
        val service = NelomaiVpnService(object : RuntimeVpnHostV1 {
            override val service = host
            override fun builder(beforeEstablish: (VpnService.Builder) -> Unit) = host.Builder()
        }, retainTunDescriptor = enabled)
        OwnershipBuilder.directory = host.cacheDir
        val previous = ReflectionHelpers.getStaticField<Any>(GoBackend::class.java, "vpnService")
        val future = previous.javaClass.getDeclaredConstructor().apply { isAccessible = true }.newInstance()
        ReflectionHelpers.setStaticField(GoBackend::class.java, "vpnService", future)
        future.javaClass.getDeclaredMethod("complete", Any::class.java).apply { isAccessible = true }.invoke(future, service)
        val f = Fixture(host, service)
        try { test(f) } finally {
            runCatching { f.stopLegacy() }
            f.retention.stop(permanent = true)
            OwnershipNative.reset()
            OwnershipDescriptor.files.keys.toList().forEach { runCatching { it.close() } }
            OwnershipDescriptor.files.values.toSet().forEach { it.delete() }
            ReflectionHelpers.setStaticField(GoBackend::class.java, "vpnService", previous)
            controller.destroy()
        }
    }

    companion object {
        private fun configBytes() = """
            [Interface]
            PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
            Address = 10.200.0.2/32
            [Peer]
            PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
            Endpoint = 127.0.0.1:51820
            AllowedIPs = 0.0.0.0/0
        """.trimIndent().toByteArray()
    }
}

/** There is no binder package manager in this fixture; app scope/routing is not under test. */
@Implements(VpnService.Builder::class)
class RetentionServiceBuilder {
    @RealObject private lateinit var builder: VpnService.Builder
    @Implementation fun establish() = OwnershipBuilder().establish()
    @Implementation fun addDisallowedApplication(packageName: String) = builder
    @Implementation fun addAllowedApplication(packageName: String) = builder
}
