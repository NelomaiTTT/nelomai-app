package ru.nelomai.tunnel

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RedundantStartArgsTest {
    @Test
    fun `disabled single-member start accepts no health probe`() {
        val primaryLease = "10000000-0000-4000-8000-000000000001"
        val args = StartTunnelArgs().also {
            it.configuration = byteArrayOf(1)
            it.quickConnection = QuickConnectionArgs().also { connection ->
                connection.leaseId = primaryLease
                connection.layer = "stray"
                connection.ticConnectionMode = "dynamic"
                connection.routeMode = "standalone"
                connection.egressMode = "ipv4"
            }
            it.redundancy = RedundantStartArgs().also { redundant ->
                redundant.sessionId = "20000000-0000-4000-8000-000000000001"
                redundant.operationId = "30000000-0000-4000-8000-000000000001"
                redundant.requestFingerprint = "a".repeat(64)
                redundant.virtualAddressV4 = "10.0.0.2/32"
                redundant.standbyDesired = false
                redundant.activeLeaseId = primaryLease
                redundant.localActiveLeaseId = primaryLease
                redundant.primary = RedundantMemberArgs().also { member ->
                    member.slot = "A"
                    member.leaseId = primaryLease
                    member.healthProbe = null
                }
            }
        }

        val transaction = redundantTransactionFromStart(
            requireNotNull(args.redundancy),
            args,
            "40000000-0000-4000-8000-000000000001",
            androidApiLevel = 36,
        )

        assertFalse(transaction.standbyDesired)
        assertEquals(null, transaction.slotBLeaseId)
        assertTrue(redundantHealthProbesFromStart(requireNotNull(args.redundancy)).isEmpty())
    }

    @Test
    fun `clearing start args zeroes primary and standby configurations`() {
        val args = StartTunnelArgs().also {
            it.configuration = byteArrayOf(1, 2, 3)
            it.redundancy = RedundantStartArgs().also { redundant ->
                redundant.standby = RedundantStandbyArgs().also { standby ->
                    standby.configuration = byteArrayOf(4, 5, 6)
                }
            }
        }

        args.clearSensitiveConfigurations()

        assertArrayEquals(byteArrayOf(0, 0, 0), args.configuration)
        assertArrayEquals(
            byteArrayOf(0, 0, 0),
            args.redundancy?.standby?.configuration,
        )
    }

    @Test
    fun `redundant starts cannot enter the legacy quick plan`() {
        val args = StartTunnelArgs().also {
            it.configuration = byteArrayOf(1)
            it.cacheQuickAction = true
            it.redundancy = RedundantStartArgs()
        }

        assertFalse(args.canCacheQuickPlan())
    }

    @Test
    fun `production transaction preserves fixed member slots and safe replay identity`() {
        val primaryLease = "10000000-0000-4000-8000-000000000001"
        val standbyLease = "10000000-0000-4000-8000-000000000002"
        val args = StartTunnelArgs().also {
            it.apiVersion = TUNNEL_API_VERSION
            it.configuration = byteArrayOf(1)
            it.quickConnection = QuickConnectionArgs().also { connection ->
                connection.leaseId = primaryLease
                connection.layer = "stray"
                connection.ticConnectionMode = "dynamic"
                connection.routeMode = "standalone"
                connection.egressMode = "ipv4"
            }
            it.redundancy = RedundantStartArgs().also { redundant ->
                redundant.sessionId = "20000000-0000-4000-8000-000000000001"
                redundant.operationId = "30000000-0000-4000-8000-000000000001"
                redundant.requestFingerprint = "a".repeat(64)
                redundant.reserveEnabled = false
                redundant.virtualAddressV4 = "10.200.0.2/32"
                redundant.standbyDesired = true
                redundant.activeLeaseId = primaryLease
                redundant.localActiveLeaseId = primaryLease
                redundant.roleGeneration = 2
                redundant.membershipGeneration = 3
                redundant.primary = member("A", primaryLease)
                redundant.standby = RedundantStandbyArgs().also { standby ->
                    standby.member = member("B", standbyLease)
                    standby.configuration = byteArrayOf(2)
                }
            }
        }

        val transaction = redundantTransactionFromStart(
            requireNotNull(args.redundancy),
            args,
            "40000000-0000-4000-8000-000000000001",
            androidApiLevel = 36,
        )

        assertEquals(primaryLease, transaction.slotALeaseId)
        assertEquals(standbyLease, transaction.slotBLeaseId)
        assertEquals(primaryLease, transaction.localActiveLeaseId)
        assertEquals("a".repeat(64), transaction.startRequestFingerprint)
        assertFalse(transaction.startReserveEnabled)
    }

    @Test
    fun `start health probes enforce the shared wire contract`() {
        listOf(999L, 8_001L).forEach { timeoutMs ->
            val probe = requireNotNull(member("A", "lease-a").healthProbe).also {
                it.timeoutMs = timeoutMs
            }
            assertRejected { probe.toBackgroundProbe() }
        }

        requireNotNull(member("A", "lease-a").healthProbe).also { probe ->
            probe.targetIpv4 = "08.8.8.8"
            assertRejected { probe.toBackgroundProbe() }
        }
        requireNotNull(member("A", "lease-a").healthProbe).also { probe ->
            probe.queryName = "Nelomai.ru"
            assertRejected { probe.toBackgroundProbe() }
        }
    }

    private fun member(slot: String, leaseId: String) = RedundantMemberArgs().also {
        it.slot = slot
        it.leaseId = leaseId
        it.healthProbe = RedundantHealthProbeArgs().also { probe ->
            probe.kind = "dns_a"
            probe.targetIpv4 = "8.8.8.8"
            probe.queryName = "nelomai.ru"
            probe.timeoutMs = 4_000
        }
    }

    private fun assertRejected(block: () -> Unit) {
        try {
            block()
            throw AssertionError("expected invalid redundant health probe")
        } catch (_: IllegalArgumentException) {
            // Expected.
        }
    }
}
