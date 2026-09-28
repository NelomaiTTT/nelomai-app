package ru.nelomai.tunnel

import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowNetwork

/** Real recovery/coordinator/health; fake native and panel, no VPN or JNI. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE)
class UnvalidatedPhysicalNetworkReadinessTest {
    @Test fun healthyTunnelOnUnvalidatedPhysicalNetworkSurvivesStartDeadline() {
        checkReadiness(available = true, handshake = true, probes = 3)
    }

    @Test fun absentPhysicalNetworkCannotBecomeReadyFromStaleObservations() {
        checkReadiness(available = false, handshake = true, probes = 3)
    }

    @Test fun availableNetworkDoesNotReplaceHandshake() {
        checkReadiness(available = true, handshake = false, probes = 3)
    }

    @Test fun availableNetworkDoesNotReplaceTunneledProbe() {
        checkReadiness(available = true, handshake = true, probes = 0)
    }

    private fun checkReadiness(available: Boolean, handshake: Boolean, probes: Int) {
        for (layer in listOf("tic", "stray")) {
            val physical = PhysicalNetworkState(emptyList(),
                if (available) listOf(ShadowNetwork.newInstance(253)) else emptyList(),
                validated = false, fingerprint = "unvalidated-test")
            var time = 0L
            var ready = 0
            var failed = 0
            var stops = 0
            val record = object : EncryptedRecordBackend {
                var bytes = AndroidRecoveryEnvelopeCodec.encode(AndroidRecoveryEnvelope.empty(1))
                override fun read() = bytes.copyOf()
                override fun write(plaintext: ByteArray): Boolean {
                    bytes = plaintext.copyOf()
                    return true
                }
            }
            val native = object : RedundantConnectionNative {
                override fun start(leaseId: String, slot: RedundantSlot,
                    configuration: ByteArray, healthProbe: BackgroundRedundantHealthProbe?) = true
                override fun activate(leaseId: String) = true
                override fun stopSlot(leaseId: String) = true
                override fun stop(): Boolean { stops++; return true }
                override fun isUsable(leaseId: String) = true
            }
            val panel = object : RedundantConnectionPanel {
                override fun recover(transaction: AndroidRedundantTransaction): RedundantRecoveryResponse =
                    error("Unexpected panel recovery")
                override fun reportRole(transaction: AndroidRedundantTransaction, reason: String): RedundantRoleResponse =
                    error("Unexpected role request")
                override fun stop(transaction: AndroidRedundantTransaction) = true
            }
            val coordinator = RedundantConnectionCoordinator(
                AndroidRecoveryStore(record, BootIdentityProvider { 1L }), panel, native,
                epochNowMs = { time }, monotonicMs = { time },
                healthMonitor = RedundantHealthMonitor(initialNetworkAvailable = physical.available),
            )
            val tx = AndroidRedundantTransaction(
                desiredActive = true,
                template = AndroidIntentTemplate("11111111-1111-4111-8111-111111111111",
                    "account", layer, "dynamic", "standalone", "ipv4", true),
                sessionId = "22222222-2222-4222-8222-222222222222",
                slotALeaseId = "lease-a", slotBLeaseId = null, localActiveLeaseId = "lease-a",
                standbyDesired = false, roleGeneration = 1, membershipGeneration = 1,
                startOperationId = "test-start", startRequestFingerprint = "test-fingerprint",
            )
            assertTrue(coordinator.start(tx, mapOf("lease-a" to byteArrayOf(1)),
                mapOf("lease-a" to BackgroundRedundantHealthProbe("dns_a", "9.9.9.9", "example.com", 4000)),
                onPrimaryStarted = { ready++ }, onPrimaryFailed = { failed++ }))
            val observations = listOf(SlotObservation(0, active = true, health = BackendHealth.READY,
                handshakeFresh = handshake, consecutiveProbeSuccesses = probes, stableSinceMs = 0))
            time = 1_000
            coordinator.onHealthObservations(observations)
            val expectedReady = available && handshake && probes > 0
            time = 31_000
            coordinator.onHealthObservations(observations)
            assertEquals("$layer readiness", if (expectedReady) 1 else 0, ready)
            assertEquals("$layer timeout", if (expectedReady) 0 else 1, failed)
            assertEquals("$layer native stop", if (expectedReady) 0 else 1, stops)
            assertEquals(expectedReady, coordinator.isRunning())
        }
    }
}
