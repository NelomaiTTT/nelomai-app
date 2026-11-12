package ru.nelomai.tunnel

import android.net.Network
import android.os.SystemClock
import org.amnezia.awg.backend.GoBackend
import org.amnezia.awg.backend.Tunnel
import org.amnezia.awg.config.Config
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config as RoboConfig
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements
import org.robolectric.shadows.ShadowSystemClock
import org.robolectric.util.ReflectionHelpers
import org.robolectric.util.ReflectionHelpers.ClassParameter.from
import java.time.Duration
import java.util.ArrayDeque
import java.util.concurrent.ExecutorService
import java.util.concurrent.TimeUnit
import java.util.function.BooleanSupplier

@RunWith(RobolectricTestRunner::class)
@RoboConfig(sdk = [34], manifest = RoboConfig.NONE,
    shadows = [NoNativeLibrary::class, UdpRecoveryBackend::class])
class WireGuardPendingRecoveryTest {
    @Test fun receivedDataCancelsThePendingProbe() =
        verifyProbe(readBytes = 200, writeBytes = 200, expectedRebinds = 0)

    @Test fun absenceOfTrafficDemandCancelsThePendingProbe() =
        verifyProbe(readBytes = 100, writeBytes = 100, expectedRebinds = 0)

    @Test fun theFirstPacketAfterAnIdleGapDoesNotReuseTheOldProbe() =
        verifyProbe(readBytes = 200, writeBytes = 100, expectedRebinds = 0, demandGap = true)

    @Test fun durableStopPreventsRebindBeforeTheNativeStopRuns() =
        verifyProbe(readBytes = 200, writeBytes = 100, expectedRebinds = 0, durableStop = true)

    @Test fun receivedDataDuringProbeEvaluationPreventsRebind() =
        verifyProbe(readBytes = 200, writeBytes = 100, expectedRebinds = 0, lateReceive = true)

    @Test fun ongoingStallStillRebindsAfterNegativeProbe() =
        verifyProbe(readBytes = 200, writeBytes = 100, expectedRebinds = 1)

    @Test fun stopAcceptedDuringProbeEvaluationPreventsRebind() =
        verifyProbe(readBytes = 200, writeBytes = 100, stopDuringProbe = true, expectedRebinds = 0)

    @Test fun stopAcceptedAtTheSocketOperationPreventsRebind() =
        verifyProbe(readBytes = 200, writeBytes = 100, stopBeforeNativeRebind = true, expectedRebinds = 0)

    @Test fun stopAcceptedDuringRebindPreventsAdmissionAndAnotherHandshake() =
        verifyProbe(readBytes = 200, writeBytes = 100, stopDuringRebind = true, expectedRebinds = 1)

    @Test fun aReadErrorAfterDurableStopDoesNotAdmitPreparedSockets() =
        verifyProbe(readBytes = 200, writeBytes = 100, stopDuringRebind = true,
            admissionReadFails = true, expectedRebinds = 1)

    @Test fun aQueuedNetworkChangeDoesNotAdmitPreparedSockets() =
        verifyProbe(readBytes = 200, writeBytes = 100, networkLostDuringRebind = true, expectedRebinds = 1)

    @Test fun aNewIntentDoesNotAdmitSocketsPreparedForThePreviousOwner() =
        verifyProbe(readBytes = 200, writeBytes = 100, expectedRebinds = 1, replaceIntentDuringRebind = true)

    @Test fun aNewIntentCannotBecomeOwnerOfTheFirstRecoveryOfAnOldTunnel() =
        verifyProbe(readBytes = 200, writeBytes = 100, expectedRebinds = 0, replaceIntentBeforeRecovery = true)

    @Test fun aQueuedExplicitAwgRebindDoesNotDisarmAutomaticRecovery() =
        verifyProbe(readBytes = 200, writeBytes = 100, explicitAwgRebind = true, expectedRebinds = 1)

    @Test fun receivedDataDuringRebindPreventsAnotherHandshake() =
        verifyProbe(readBytes = 200, writeBytes = 100, expectedRebinds = 1, receiveDuringRebind = true)

    @Test fun expiredDemandDuringRebindPreventsAnotherHandshake() =
        verifyProbe(readBytes = 200, writeBytes = 100, expectedRebinds = 1, demandExpiresDuringRebind = true)

    @Test fun anOldPacketDuringRebindDoesNotProveCurrentDemand() =
        verifyProbe(readBytes = 200, writeBytes = 100, expectedRebinds = 1,
            demandExpiresDuringRebind = true, oldReadDuringRebind = true)

    @Test fun exhaustedWireGuardRecoveryLeavesVpnAndLeaseInPlace() =
        verifyProbe(readBytes = 200, writeBytes = 100, expectedRebinds = 0, exhausted = true)

    @Test fun failedFirstRebindAllowsOnlyTheRemainingRecoveryAttempt() {
        verifyProbe(readBytes = 200, writeBytes = 100, expectedRebinds = 1, rebindFails = true)
        verifyProbe(readBytes = 200, writeBytes = 100, expectedRebinds = 1, rebindFails = true,
            priorRebinds = 1)
    }

    @Test fun aFailedHandshakeStartDoesNotSpendTheNextAttemptImmediately() =
        verifyProbe(readBytes = 200, writeBytes = 100, expectedRebinds = 1, followupProbeFails = true)

    @Test fun aSuccessfulHandshakeDoesNotProveDataplaneRecovery() =
        verifyProbe(readBytes = 200, writeBytes = 100, expectedRebinds = 0,
            priorRebinds = 1, handshakeSucceededAfterRebind = true)

    @Test fun anIdleGapDoesNotResetAnExhaustedRecoveryBudget() =
        verifyProbe(readBytes = 200, writeBytes = 100, expectedRebinds = 0,
            exhausted = true, demandGap = true)

    @Test fun aReturningPhysicalNetworkRearmsAnExhaustedTunnel() =
        verifyProbe(readBytes = 200, writeBytes = 100, expectedRebinds = 0, exhausted = true,
            afterPhysicalNetworkReturn = true)

    @Test fun queuedNetworkLossDuringTheProbePreventsRebind() =
        verifyProbe(readBytes = 200, writeBytes = 100, expectedRebinds = 0, networkLostDuringProbe = true)

    @Test fun aRecoveryStoreFailureBeforeTheFirstProbeObservesTheCooldown() =
        verifyProbe(readBytes = 200, writeBytes = 100, expectedRebinds = 0, storeFailsBeforeFirstProbe = true)

    @Test fun temporaryRecoveryStoreFailureDoesNotDisarmTheSession() =
        verifyProbe(readBytes = 200, writeBytes = 100, expectedRebinds = 0, temporaryStoreFailure = true)

    @Test fun changingOnlyNetworkValidationDoesNotResetAnExhaustedBudget() =
        verifyProbe(readBytes = 200, writeBytes = 100, expectedRebinds = 0,
            exhausted = true, validationOnly = true)

    private fun verifyProbe(
        readBytes: Long,
        writeBytes: Long,
        expectedRebinds: Int,
        stopDuringProbe: Boolean = false,
        stopDuringRebind: Boolean = false,
        admissionReadFails: Boolean = false,
        networkLostDuringRebind: Boolean = false,
        replaceIntentBeforeRecovery: Boolean = false,
        replaceIntentDuringRebind: Boolean = false,
        stopBeforeNativeRebind: Boolean = false,
        explicitAwgRebind: Boolean = false,
        exhausted: Boolean = false,
        rebindFails: Boolean = false,
        followupProbeFails: Boolean = false,
        priorRebinds: Int = 0,
        afterPhysicalNetworkReturn: Boolean = false,
        demandGap: Boolean = false,
        durableStop: Boolean = false,
        lateReceive: Boolean = false,
        receiveDuringRebind: Boolean = false,
        demandExpiresDuringRebind: Boolean = false,
        oldReadDuringRebind: Boolean = false,
        networkLostDuringProbe: Boolean = false,
        temporaryStoreFailure: Boolean = false,
        storeFailsBeforeFirstProbe: Boolean = false,
        validationOnly: Boolean = false,
        handshakeSucceededAfterRebind: Boolean = false,
    ) {
        val gate = ReflectionHelpers.getField<TunnelStateGate>(TunnelRuntime, "stateGate")
        val oldBackend = ReflectionHelpers.getField<GoBackend?>(TunnelRuntime, "backend")
        val oldSession = ReflectionHelpers.getField<Any?>(TunnelRuntime, "activeSession")
        val oldState = gate.current()
        val oldContext = ReflectionHelpers.getField<android.content.Context?>(TunnelRuntime, "applicationContext")
        val oldStore = ReflectionHelpers.getField<AndroidRecoveryStore?>(AndroidRecoveryStores, "instance")
        var failNextRead = false
        val store = AndroidRecoveryStore(object : EncryptedRecordBackend {
            private var data: ByteArray? = null
            override fun read(): ByteArray? {
                if (failNextRead) {
                    failNextRead = false
                    error("temporary keystore read error")
                }
                return data?.clone()
            }
            override fun write(plaintext: ByteArray): Boolean {
                data = plaintext.clone()
                return true
            }
        }, BootIdentityProvider { 1 })
        assertEquals(true, store.setDesiredActive(0, true) is RecoveryStoreResult.Success)
        if (durableStop) assertEquals(true, store.cancelCurrentIntent() is RecoveryStoreResult.Success)
        ShadowSystemClock.advanceBy(Duration.ofSeconds(30))
        val now = SystemClock.elapsedRealtime()
        val config = Config.parse("[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n".byteInputStream())
        val sessionType = Class.forName("ru.nelomai.tunnel.ActiveTunnelSession")
        val probe = Class.forName("ru.nelomai.tunnel.PendingUdpControlProbe").declaredConstructors.single()
            .apply { isAccessible = true }
            .newInstance(if (exhausted || handshakeSucceededAfterRebind) UdpControlProbeStage.AFTER_REBIND else UdpControlProbeStage.BEFORE_REBIND,
                1L, now - 5_000, now, 100L, 100L, 51820, 51820)
        val session = sessionType.declaredConstructors.single { !it.isSynthetic }.apply { isAccessible = true }
            .newInstance(1L, null, null, config, EffectiveAndroidTunnelOptions(), null, emptyList<Ipv4Prefix>(),
                "", false, if (explicitAwgRebind) "amneziawg_3" else "wireguard", null, now - 20_000, null, null,
                NetworkTelemetry.fromJson(telemetry(100, 100)),
                ArrayDeque<JSONObject>(), if (demandGap || readBytes == 100L) now - 6_000 else now - 1_000,
                now - 10_000, now - 10_000, now - 8_000,
                now - 5_000, false, if (exhausted) 2 else priorRebinds, LegacyDataPlaneRecovery(), probe, now, 0L, 0, null)
        val owner = (store.read() as RecoveryStoreResult.Success).value.intent.generation
        ReflectionHelpers.setField(session, "wireGuardRecoveryOwnerGeneration", owner)
        fun replaceIntent() {
            val cancelled = store.cancelCurrentIntent() as RecoveryStoreResult.Success
            assertEquals(true, store.setDesiredActive(cancelled.value.intent.generation, true) is RecoveryStoreResult.Success)
        }
        if (replaceIntentBeforeRecovery) replaceIntent()
        val backend = GoBackend(RuntimeEnvironment.getApplication())
        ReflectionHelpers.setField(TunnelRuntime, "backend", backend)
        ReflectionHelpers.setField(TunnelRuntime, "applicationContext", RuntimeEnvironment.getApplication())
        ReflectionHelpers.setField(AndroidRecoveryStores, "instance", store)
        ReflectionHelpers.setField(TunnelRuntime, "activeSession", session)
        gate.complete(SessionState.RUNNING)
        UdpRecoveryBackend.telemetry = telemetry(readBytes, writeBytes)
        UdpRecoveryBackend.rebinds = 0
        UdpRecoveryBackend.probeStarts = 0
        UdpRecoveryBackend.rebindAdmissions = 0
        UdpRecoveryBackend.rebindKeepalives = 0
        UdpRecoveryBackend.failProbeStart = followupProbeFails
        UdpRecoveryBackend.beforeRebind = {
            if (stopBeforeNativeRebind) assertEquals(true, store.cancelCurrentIntent() is RecoveryStoreResult.Success)
        }
        fun enqueueNetwork(physical: PhysicalNetworkState) {
            ReflectionHelpers.callInstanceMethod<Unit>(TunnelRuntime, "reapplyPhysicalNetworks",
                from(Long::class.java, 1L), from(PhysicalNetworkState::class.java, physical))
        }
        UdpRecoveryBackend.probeResult = {
            if (networkLostDuringProbe) enqueueNetwork(PhysicalNetworkState(emptyList(), emptyList(), false, "offline"))
            if (temporaryStoreFailure) failNextRead = true
            if (stopDuringProbe) assertEquals(TransitionDecision.PROCEED, gate.beginStop())
            if (explicitAwgRebind) assertEquals(TransitionDecision.PROCEED, gate.beginRebind())
            if (lateReceive) UdpRecoveryBackend.telemetry = telemetry(readBytes, 200)
            handshakeSucceededAfterRebind
        }
        UdpRecoveryBackend.afterRebind = {
            if (stopDuringRebind) assertEquals(true, store.cancelCurrentIntent() is RecoveryStoreResult.Success)
            if (replaceIntentDuringRebind) replaceIntent()
            if (admissionReadFails) failNextRead = true
            if (networkLostDuringRebind) enqueueNetwork(PhysicalNetworkState(emptyList(), emptyList(), false, "offline"))
            if (receiveDuringRebind) UdpRecoveryBackend.telemetry = telemetry(readBytes, 200)
            if (oldReadDuringRebind) UdpRecoveryBackend.telemetry = telemetry(readBytes + 100, writeBytes)
            if (demandExpiresDuringRebind) ShadowSystemClock.advanceBy(Duration.ofSeconds(3))
            if (rebindFails) throw IllegalStateException("socket unavailable")
        }
        try {
            if (afterPhysicalNetworkReturn || validationOnly) {
                val network = ReflectionHelpers.callConstructor(Network::class.java, from(Int::class.java, 100))
                val path = "100:wlan0"
                ReflectionHelpers.setField(session, "observedNetworkFingerprint", "validated=false\n$path")
                if (afterPhysicalNetworkReturn) {
                    enqueueNetwork(PhysicalNetworkState(emptyList(), emptyList(), false, "validated=false"))
                }
                enqueueNetwork(PhysicalNetworkState(emptyList(), listOf(network), true, "validated=true\n$path"))
                TunnelRuntime.nativeOperationsBarrier().get(5, TimeUnit.SECONDS)
                assertEquals(if (validationOnly) 2 else 0,
                    ReflectionHelpers.getField<Int>(session, "udpRecoveryAttempts"))
                assertEquals(!validationOnly, ReflectionHelpers.getField<Boolean>(session, "udpRecoveryArmed"))
                if (!validationOnly) {
                    assertNull(ReflectionHelpers.getField<Long?>(session, "lastUdpRecoveryElapsedMillis"))
                    assertNull(ReflectionHelpers.getField<Any?>(session, "pendingUdpControlProbe"))
                }
                return
            }
            if (storeFailsBeforeFirstProbe) {
                ReflectionHelpers.setField(session, "pendingUdpControlProbe", null)
                ReflectionHelpers.setField(session, "udpRecoveryArmed", true)
                ReflectionHelpers.setField(session, "lastUdpRecoveryElapsedMillis", null)
                failNextRead = true
            }
            val executor = ReflectionHelpers.getField<ExecutorService>(TunnelRuntime, "executor")
            executor.submit {
                @Suppress("UNCHECKED_CAST")
                ReflectionHelpers.callInstanceMethod<Unit>(TunnelRuntime, "inspectNetworkTelemetry",
                    from(sessionType as Class<Any>, session))
            }.get(5, TimeUnit.SECONDS)
            TunnelRuntime.nativeOperationsBarrier().get(5, TimeUnit.SECONDS)
            if (temporaryStoreFailure || storeFailsBeforeFirstProbe) {
                assertEquals(true, ReflectionHelpers.getField<Boolean>(session, "udpRecoveryArmed"))
            }
            if (storeFailsBeforeFirstProbe) {
                val lastAttempt = ReflectionHelpers.getField<Long?>(session, "lastUdpRecoveryElapsedMillis")
                assertEquals("owner read attempts share the normal cooldown", now as Long?, lastAttempt)
            }
            if (handshakeSucceededAfterRebind) {
                assertEquals("handshake without TUN traffic preserves attempts", priorRebinds,
                    ReflectionHelpers.getField<Int>(session, "udpRecoveryAttempts"))
            }
            if (stopBeforeNativeRebind) {
                assertEquals(priorRebinds, ReflectionHelpers.getField<Int>(session, "udpRecoveryAttempts"))
            }
            assertEquals("socket rebinds", expectedRebinds, UdpRecoveryBackend.rebinds)
            if (stopDuringRebind || stopBeforeNativeRebind || admissionReadFails ||
                networkLostDuringRebind || replaceIntentDuringRebind || replaceIntentBeforeRecovery
            ) {
                assertEquals(0, UdpRecoveryBackend.rebindAdmissions)
                assertEquals(0, UdpRecoveryBackend.rebindKeepalives)
            }
            if (receiveDuringRebind || demandExpiresDuringRebind) {
                assertEquals("the active socket must stay in use", 0, UdpRecoveryBackend.rebindAdmissions)
                assertEquals(0, UdpRecoveryBackend.rebindKeepalives)
            }
            val followup = expectedRebinds == 1 && !stopDuringRebind && !networkLostDuringRebind && !rebindFails &&
                !admissionReadFails && !replaceIntentDuringRebind &&
                !receiveDuringRebind && !demandExpiresDuringRebind
            assertEquals("additional handshakes", if (followup) 1 else 0, UdpRecoveryBackend.probeStarts)
            if (exhausted || rebindFails) {
                assertEquals(rebindFails && priorRebinds == 0,
                    ReflectionHelpers.getField<Boolean>(session, "udpRecoveryArmed"))
                assertEquals(SessionState.RUNNING, gate.current())
                assertEquals(session, ReflectionHelpers.getField<Any?>(TunnelRuntime, "activeSession"))
            }
            val pending = ReflectionHelpers.getField<Any?>(session, "pendingUdpControlProbe")
            if (followup && !followupProbeFails) assertNotNull(pending) else assertNull(pending)
            if (followupProbeFails) {
                assertEquals(1, ReflectionHelpers.getField<Int>(session, "udpRecoveryAttempts"))
                assertEquals(true, ReflectionHelpers.getField<Boolean>(session, "udpRecoveryArmed"))
            }
        } finally {
            ReflectionHelpers.setField(TunnelRuntime, "backend", oldBackend)
            ReflectionHelpers.setField(TunnelRuntime, "applicationContext", oldContext)
            ReflectionHelpers.setField(AndroidRecoveryStores, "instance", oldStore)
            ReflectionHelpers.setField(TunnelRuntime, "activeSession", oldSession)
            gate.complete(oldState)
            UdpRecoveryBackend.probeResult = { false }
            UdpRecoveryBackend.beforeRebind = {}
            UdpRecoveryBackend.failProbeStart = false
            UdpRecoveryBackend.afterRebind = {}
        }
    }

    private fun telemetry(readBytes: Long, writeBytes: Long): String =
        """{"tun_read_packets":10,"tun_read_bytes":$readBytes,"tun_read_errors":0,
            "tun_write_packets":10,"tun_write_bytes":$writeBytes,"tun_write_errors":0,
            "udp_send_calls":10,"udp_send_packets":10,"udp_send_bytes":100,"udp_send_errors":0,
            "udp_receive_calls":10,"udp_receive_packets":10,"udp_receive_bytes":100,"udp_receive_errors":0,
            "local_port":51820,"last_tun_read_at_unix_ms":1,"last_tun_write_at_unix_ms":1,
            "last_udp_send_at_unix_ms":1,"last_udp_receive_at_unix_ms":1}""".trimIndent()
}

@Implements(GoBackend::class)
class UdpRecoveryBackend {
    companion object {
        var telemetry = ""
        var rebinds = 0
        var probeStarts = 0
        var rebindAdmissions = 0
        var rebindKeepalives = 0
        var failProbeStart = false
        var beforeRebind: () -> Unit = {}
        var probeResult: () -> Boolean = { false }
        var afterRebind: () -> Unit = {}
    }

    @Implementation fun getNetworkTelemetry(tunnel: Tunnel): String = telemetry
    @Implementation fun handshakeProbeSucceeded(tunnel: Tunnel, generation: Long): Boolean = probeResult()
    @Implementation fun rebindUdp(tunnel: Tunnel) {
        rebindUdp(tunnel, BooleanSupplier { true }, BooleanSupplier { true })
    }

    @Implementation fun rebindUdp(tunnel: Tunnel, mayRebind: BooleanSupplier, stillOwned: BooleanSupplier): GoBackend.UdpRebindResult {
        beforeRebind()
        if (!mayRebind.asBoolean) return GoBackend.UdpRebindResult.SKIPPED
        rebinds++
        afterRebind()
        if (!mayRebind.asBoolean) return GoBackend.UdpRebindResult.ABORTED
        rebindAdmissions++
        if (stillOwned.asBoolean) rebindKeepalives++
        return GoBackend.UdpRebindResult.APPLIED
    }

    @Implementation fun startHandshakeProbe(tunnel: Tunnel): Long {
        probeStarts++
        check(!failProbeStart) { "UDP send failed" }
        return 2L
    }

    @Implementation fun startHandshakeProbe(tunnel: Tunnel, allowed: BooleanSupplier): Long =
        if (allowed.asBoolean) startHandshakeProbe(tunnel) else 0L
    @Implementation fun handshakeProbeTimeoutMillis(tunnel: Tunnel): Long = 5_000L
}
