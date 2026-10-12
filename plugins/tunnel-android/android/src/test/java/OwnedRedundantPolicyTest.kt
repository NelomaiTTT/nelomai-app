package ru.nelomai.tunnel

import java.io.ByteArrayInputStream
import org.amnezia.awg.config.Config
import org.junit.Assert.*
import org.junit.Test

class OwnedRedundantPolicyTest {
    @Test fun replacementPreservesBothMembersAndPromotedActiveBAndColdOptions() {
        for (active in listOf("lease-a", "lease-b")) {
            val f = Fixture(active)
            val before = f.coordinator.status()!!
            assertEquals(OwnedRedundantPolicyOutcome.APPLIED, f.apply())
            assertEquals(before.copy(template = before.template.copy(options = f.policy)),
                f.coordinator.status())
            assertEquals(f.policy, f.coldStore().read().let {
                (it as RecoveryStoreResult.Success).value.redundantTransaction!!.template.options
            })
            val cold = (f.coldStore().read() as RecoveryStoreResult.Success).value
            assertEquals("cold intent must use the same policy", f.policy, cold.intent.template!!.options)
            assertEquals(before.template, cold.intent.template.copy(options = before.template.options))
            assertEquals(listOf(if (active == "lease-a") 0 else 1), f.backend.primarySlots.takeLast(1))
            assertTrue(f.native.isUsable("lease-a"))
            assertTrue(f.native.isUsable("lease-b"))
            assertEquals(listOf(f.policy, f.policy), f.preparedPolicies)
            assertEquals(0, f.panelCalls)
        }
    }

    @Test fun hashOnlyUpdateIsUnchangedWithoutRecreatingTun() {
        val f = Fixture()
        assertEquals(OwnedRedundantPolicyOutcome.UNCHANGED,
            f.apply(AndroidTunnelOptions(policyHash = "hash-new")))
        assertEquals(1, f.tunStarts)
        assertEquals("hash-new", f.coordinator.status()!!.template.options.policyHash)
    }

    @Test fun ineffectiveDns46SaveDoesNotReplaceTheNativePair() {
        val f = Fixture(egressMode = "prefer_ipv6")
        assertEquals(OwnedRedundantPolicyOutcome.UNCHANGED, f.apply(AndroidTunnelOptions(
            policyHash = "hash-new", dnsServers = listOf("1.1.1.1"))))
        assertEquals(1, f.tunStarts)
    }

    @Test fun replacementFailureRollsBackAndLeavesDurableOptionsUntouched() {
        val f = Fixture()
        f.failTunStarts = setOf(2)
        val before = f.coordinator.status()
        assertEquals(OwnedRedundantPolicyOutcome.ROLLED_BACK, f.apply())
        assertEquals(before, f.coordinator.status())
        assertEquals(3, f.tunStarts)
        assertTrue(f.coordinator.isRunning())
        assertTrue(f.native.isUsable("lease-a"))
        assertTrue(f.native.isUsable("lease-b"))
    }

    @Test fun durableWriteFailureRollsNativeBack() {
        val f = Fixture()
        f.record.failNextWrite = true
        assertEquals(OwnedRedundantPolicyOutcome.ROLLED_BACK, f.apply())
        assertEquals(AndroidTunnelOptions(), f.coordinator.status()!!.template.options)
        assertEquals(3, f.tunStarts)
    }

    @Test fun doubleFailureClosesOwnerAndCannotClaimRunning() {
        val f = Fixture()
        f.failTunStarts = setOf(2, 3)
        assertEquals(OwnedRedundantPolicyOutcome.FAILED, f.apply())
        assertFalse(f.coordinator.isRunning())
        assertFalse(f.native.isUsable("lease-a"))
        assertFalse(f.native.isUsable("lease-b"))
        assertFalse(f.native.start("late", RedundantSlot.A, byteArrayOf(9), null))
        assertTrue(f.coordinator.policyFailed())
        assertFalse(f.coordinator.resume())
        assertEquals(0, f.panelCalls)
    }

    @Test fun stopDuringEstablishNeverRollsBackOrPersistsNewOptions() {
        val f = Fixture()
        f.duringEstablish = {
            if (f.tunStarts == 2) {
                f.cancelled = true
                f.coordinator.closeDataplaneForStop()
            }
        }
        assertEquals(OwnedRedundantPolicyOutcome.FAILED, f.apply())
        assertEquals(2, f.tunStarts)
        assertEquals("Stop must prohibit even transient backend resurrection", 1, f.backend.primarySlots.size)
        assertFalse(f.native.isUsable("lease-a"))
        assertFalse(f.coordinator.isRunning())
        assertEquals(AndroidTunnelOptions(), f.coordinator.status()!!.template.options)
    }

    @Test fun wrongScopeAndPendingWorkFailBeforeNativeMutation() {
        val changes: List<(OwnedRedundantPolicyScope) -> OwnedRedundantPolicyScope> = listOf(
            { it.copy(sessionId = "wrong") }, { it.copy(leaseId = "candidate") },
            { it.copy(layer = "tic") }, { it.copy(ticConnectionMode = "personal") },
            { it.copy(routeMode = "via_tak") }, { it.copy(egressMode = "prefer_ipv6") },
            { it.copy(allowAlternate = true) },
        )
        for (change in changes) {
            val f = Fixture()
            try { f.coordinator.applyOwnedPolicy(change(f.scope), f.policy) { false }; fail() }
            catch (_: BackgroundConnectionException) { }
            assertEquals(1, f.tunStarts)
            assertTrue(f.coordinator.isRunning())
        }
        for (retry in listOf(AndroidRedundantRetryState(roleObservationPending = true,
                pendingRoleLeaseId = "lease-a", pendingRoleReason = "primary_ready"),
            AndroidRedundantRetryState(acquirePending = true, acquireOperationId = "acquire"),
            AndroidRedundantRetryState(standbyReleasePending = true))) {
            val f = Fixture()
            assertTrue(f.store.updateRedundant { it.copy(retry = retry) } is RecoveryStoreResult.Success)
            try { f.apply(); fail() } catch (_: BackgroundConnectionException) { }
            assertEquals(1, f.tunStarts)
        }
    }

    @Test fun missingNativeMemberAndDurableStopRejectBeforeReplacement() {
        for (stop in listOf(false, true)) {
            val f = Fixture()
            if (stop) f.store.cancelCurrentIntent() else assertTrue(f.native.stopSlot("lease-b"))
            try { f.apply(); fail() } catch (_: BackgroundConnectionException) { }
            assertEquals(1, f.tunStarts)
        }
    }

    @Test fun pendingCandidateCannotBeRebuiltAsAnExtantMember() {
        val f = Fixture()
        assertTrue(f.store.updateRedundant { it.copy(candidateLeaseId = "candidate",
            candidateSlot = RedundantSlot.B) } is RecoveryStoreResult.Success)
        try { f.apply(); fail() } catch (_: BackgroundConnectionException) { }
        assertEquals(1, f.tunStarts)
    }

    @Test fun ownerChangeDuringNativeReplacementNeverWritesOrRollsBack() {
        val f = Fixture()
        f.duringEstablish = {
            if (f.tunStarts == 2) f.store.updateRedundant { it.copy(membershipGeneration = 8) }
        }
        assertEquals(OwnedRedundantPolicyOutcome.FAILED, f.apply())
        assertEquals(2, f.tunStarts)
        assertEquals(8, f.coordinator.status()!!.membershipGeneration)
        assertEquals(AndroidTunnelOptions(), f.coordinator.status()!!.template.options)
        assertFalse(f.native.isUsable("lease-a"))
    }

    @Test fun preparationUsesActualAddressForDns46AndKeepsNumericEndpoint() {
        val bytes = CONFIG.replace("10.200.0.2/32", "10.255.255.53/32").toByteArray()
        val prepared = prepareOwnedRedundantConfiguration(bytes, AndroidTunnelOptions(),
            "prefer_ipv6", 36, "ru.nelomai.client")
        assertEquals(listOf("10.255.255.54"), prepared.config.getInterface().dnsServers.map { it.hostAddress })
        assertEquals("127.0.0.1", prepared.config.peers.single().endpoint.get().host)
        assertTrue(bytes.all { it == 0.toByte() })
        prepared.userspace.fill(0)
        prepared.baseConfiguration?.fill(0)
    }

    @Test fun productionPreparerAppliesDnsAndApplicationsWhilePreservingTransportAndRollbackBytes() {
        val original = CONFIG.replace("Address = 10.200.0.2/32", """
            Address = 10.200.0.2/32
            MTU = 1392
            Jc = 4
            Jmin = 10
            Jmax = 20
            ExcludedApplications = com.example.old
        """.trimIndent()).toByteArray()
        for (include in listOf(false, true)) {
            val input = original.copyOf()
            val policy = if (include) AndroidTunnelOptions(splitActive = true,
                applicationMode = "include_selected", includedPackages = listOf("com.example.selected", "ru.nelomai.client"),
                dnsServers = listOf("1.1.1.1"), splitTunnelRoutes = listOf("192.0.2.0/24"))
            else AndroidTunnelOptions(splitActive = true, applicationMode = "exclude_selected",
                excludedPackages = listOf("com.example.selected"), dnsServers = listOf("1.1.1.1"),
                splitTunnelRoutes = listOf("192.0.2.0/24"))
            val prepared = prepareOwnedRedundantConfiguration(input, policy, "ipv4", 36, "ru.nelomai.client")
            try {
                val iface = prepared.config.getInterface()
                assertEquals(listOf("1.1.1.1"), iface.dnsServers.map { it.hostAddress })
                assertEquals(if (include) setOf("com.example.selected") else emptySet<String>(), iface.includedApplications)
                assertEquals(if (include) emptySet<String>() else setOf("com.example.selected", "ru.nelomai.client"), iface.excludedApplications)
                assertEquals(listOf("10.200.0.2/32"), iface.addresses.map { it.toString() })
                assertEquals(1392, iface.mtu.get())
                assertEquals(4, iface.junkPacketCount.get())
                val peer = prepared.config.peers.single()
                assertEquals("127.0.0.1:10001", peer.endpoint.get().toString())
                assertEquals(listOf("0.0.0.0/0"), peer.allowedIps.map { it.toString() })
                val userspace = prepared.userspace.toString(Charsets.UTF_8)
                assertTrue(userspace.contains("endpoint=127.0.0.1:10001\n"))
                assertTrue(userspace.contains("allowed_ip=0.0.0.0/0\n"))
                assertArrayEquals("rollback cache must retain the original DNS/apps/transport", original, prepared.baseConfiguration)
                assertTrue(input.all { it == 0.toByte() })
            } finally {
                prepared.userspace.fill(0)
                prepared.baseConfiguration?.fill(0)
            }
        }
        original.fill(0)
    }

    @Test fun transientConfigurationCopiesAreWipedAndTerminalStopDiscardsAllBytes() {
        val f = Fixture()
        val originalRetained = retainedBytes(f.native)
        assertTrue(originalRetained.all { bytes -> bytes.any { it != 0.toByte() } })
        assertTrue(f.initialBytes.all { bytes -> bytes.all { it == 0.toByte() } })
        assertEquals(OwnedRedundantPolicyOutcome.APPLIED, f.apply())
        assertTrue("replacement must wipe the retired slot bytes",
            originalRetained.all { bytes -> bytes.all { it == 0.toByte() } })
        val replacementRetained = retainedBytes(f.native)
        assertTrue(replacementRetained.all { bytes -> bytes.any { it != 0.toByte() } })
        assertTrue(f.consumedBytes.all { bytes -> bytes.all { it == 0.toByte() } })
        assertTrue(f.native.stopSlot("lease-b"))
        assertEquals(1, replacementRetained.count { bytes -> bytes.all { it == 0.toByte() } })
        assertFalse(f.native.isUsable("lease-b"))
        assertTrue(f.native.closeForStop())
        assertTrue(replacementRetained.all { bytes -> bytes.all { it == 0.toByte() } })
        val starts = f.tunStarts
        assertFalse(f.native.replacePolicy(f.policy) { false })
        assertEquals(starts, f.tunStarts)
    }

    private fun retainedBytes(native: ServiceRedundantConnectionNative): List<ByteArray> {
        val slots = native.javaClass.getDeclaredField("slots").apply { isAccessible = true }.get(native) as Map<*, *>
        return slots.values.map { runtime ->
            runtime!!.javaClass.getDeclaredField("configuration").apply { isAccessible = true }.get(runtime) as ByteArray
        }
    }

    internal class Fixture(active: String = "lease-a", egressMode: String = "ipv4") {
        val record = PolicyRecord()
        fun coldStore() = AndroidRecoveryStore(record, object : BootIdentityProvider {
            override fun bootCount() = 1L
        })
        val store = coldStore()
        val backend = RecordingSessionBackend()
        var tunStarts = 0
        var failTunStarts = emptySet<Int>()
        var duringEstablish: () -> Unit = {}
        var cancelled = false
        var panelCalls = 0
        val preparedPolicies = mutableListOf<AndroidTunnelOptions>()
        val consumedBytes = mutableListOf<ByteArray>()
        val initialBytes = listOf(byteArrayOf(1, 2), byteArrayOf(3, 4))
        val policy = AndroidTunnelOptions(splitActive = true, policyHash = "hash-new",
            splitTunnelRoutes = listOf("192.0.2.0/24"), dnsServers = listOf("1.1.1.1"))
        val scope = OwnedRedundantPolicyScope("22222222-2222-4222-8222-222222222222", "lease-a", "stray", "dynamic", "standalone", egressMode)
        val native = ServiceRedundantConnectionNative(backend, establishTun = {
            tunStarts += 1
            duringEstablish()
            if (tunStarts in failTunStarts) null else 41
        }, prepare = ::prepare, probeSourceIpv4 = "10.200.0.2/32", preparePolicy = { bytes, options ->
            preparedPolicies += options
            prepare(bytes)
        }, equivalentPolicy = { old, new ->
            AndroidSplitTunnel.resolveOptions(36, old.toTunnelOptionsArgs(), egressMode) ==
                AndroidSplitTunnel.resolveOptions(36, new.toTunnelOptionsArgs(), egressMode)
        })
        fun prepare(bytes: ByteArray): PreparedRedundantConfiguration {
            assertTrue(bytes.any { it != 0.toByte() })
            consumedBytes += bytes
            return PreparedRedundantConfiguration(Config.parse(ByteArrayInputStream(CONFIG.toByteArray())),
                byteArrayOf(5, 6).also { consumedBytes += it })
        }
        val panel = object : RedundantConnectionPanel {
            override fun recover(transaction: AndroidRedundantTransaction): RedundantRecoveryResponse {
                panelCalls++; error("unexpected network recovery")
            }
            override fun reportRole(transaction: AndroidRedundantTransaction, reason: String): RedundantRoleResponse {
                panelCalls++; error("unexpected role report")
            }
            override fun stop(transaction: AndroidRedundantTransaction): Boolean {
                panelCalls++; error("unexpected server stop")
            }
        }
        val coordinator = testRedundantCoordinator(store, panel, native)
        init {
            record.write(AndroidRecoveryEnvelopeCodec.encode(AndroidRecoveryEnvelope.empty(1)))
            val tx = AndroidRedundantTransaction(true,
                AndroidIntentTemplate("11111111-1111-4111-8111-111111111111", "account", "stray", "dynamic", "standalone", egressMode, true),
                "22222222-2222-4222-8222-222222222222", "lease-a", "lease-b", active, true, 4, 7, "operation", "fingerprint")
            assertTrue("start failed: ${store.read()}", coordinator.start(tx, mapOf("lease-a" to initialBytes[0], "lease-b" to initialBytes[1])))
        }
        fun apply(options: AndroidTunnelOptions = policy) = coordinator.applyOwnedPolicy(scope, options) { cancelled }
    }

    internal class PolicyRecord : EncryptedRecordBackend {
        var bytes: ByteArray? = null
        var failNextWrite = false
        override fun read(): ByteArray? = bytes?.copyOf()
        override fun write(plaintext: ByteArray): Boolean {
            if (failNextWrite) { failNextWrite = false; return false }
            bytes = plaintext.copyOf()
            return true
        }
    }

    companion object {
        private val CONFIG = """
            [Interface]
            PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
            Address = 10.200.0.2/32
            DNS = 9.9.9.9

            [Peer]
            PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
            AllowedIPs = 0.0.0.0/0
            Endpoint = 127.0.0.1:10001
        """.trimIndent()
    }
}
