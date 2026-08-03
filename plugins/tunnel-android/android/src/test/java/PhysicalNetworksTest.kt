package ru.nelomai.tunnel

import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Test

class PhysicalNetworksTest {
    @Test
    fun canonicalizesDeduplicatesAndSortsPhysicalIpv4Networks() {
        val snapshots = listOf(
            physicalNetwork(
                "192.168.50.42/24",
                "10.20.30.40/16",
                wifi = true,
            ),
            physicalNetwork(
                "192.168.50.99/24",
                "172.20.4.7/20",
                ethernet = true,
            ),
        )

        assertEquals(
            listOf(
                "10.20.0.0/16",
                "172.20.0.0/20",
                "192.168.50.0/24",
            ),
            PhysicalNetworks.canonicalCidrs(snapshots).map { it.canonical },
        )
    }

    @Test
    fun ignoresInactiveVpnAndUnsupportedTransports() {
        val snapshots = listOf(
            physicalNetwork("192.168.1.10/24", active = false, wifi = true),
            physicalNetwork("192.168.2.10/24", vpn = true, wifi = true),
            physicalNetwork("192.168.3.10/24"),
            physicalNetwork("100.64.1.10/24", cellular = true),
        )

        assertEquals(
            listOf("100.64.1.0/24"),
            PhysicalNetworks.canonicalCidrs(snapshots).map { it.canonical },
        )
    }

    @Test
    fun keepsInternetNetworkWhenAndroidValidationIsUnavailable() {
        val snapshots = listOf(
            physicalNetwork(
                "192.168.10.25/24",
                wifi = true,
                validated = false,
            ),
        )

        assertEquals(
            listOf("192.168.10.0/24"),
            PhysicalNetworks.canonicalCidrs(snapshots).map { it.canonical },
        )
    }

    @Test
    fun prefersValidatedNetworksButFallsBackWhenValidationIsUnavailable() {
        val validated = "wifi" to physicalNetwork(
            "192.168.10.25/24",
            wifi = true,
        )
        val transient = "cellular" to physicalNetwork(
            "100.64.1.10/24",
            cellular = true,
            validated = false,
        )

        assertEquals(
            listOf(validated),
            PhysicalNetworks.preferValidatedNetworks(listOf(validated, transient)),
        )
        assertEquals(
            listOf(transient),
            PhysicalNetworks.preferValidatedNetworks(listOf(transient)),
        )
    }

    @Test
    fun localRoutesIgnoreCarrierNetworks() {
        val snapshots = listOf(
            physicalNetwork("192.168.10.25/24", wifi = true),
            physicalNetwork("100.64.1.10/24", cellular = true),
        )

        assertEquals(
            listOf("192.168.10.0/24"),
            PhysicalNetworks.canonicalLocalCidrs(snapshots).map { it.canonical },
        )
    }

    @Test
    fun ignoresUnsafeAndHostOnlyAddresses() {
        val snapshots = listOf(
            physicalNetwork(
                "127.0.0.1/8",
                "169.254.10.20/16",
                "224.0.0.1/24",
                "0.0.0.0/24",
                "192.168.1.5/32",
                "2001:db8::10/64",
                wifi = true,
            ),
        )

        assertEquals(emptyList<Ipv4Prefix>(), PhysicalNetworks.canonicalCidrs(snapshots))
    }

    @Test
    fun fingerprintIsIndependentOfNetworkEnumerationOrder() {
        val first = PhysicalNetworks.canonicalCidrs(
            listOf(
                physicalNetwork("192.168.1.50/24", wifi = true),
                physicalNetwork("100.64.20.8/24", cellular = true),
            ),
        )
        val second = PhysicalNetworks.canonicalCidrs(
            listOf(
                physicalNetwork("100.64.20.9/24", cellular = true),
                physicalNetwork("192.168.1.2/24", wifi = true),
            ),
        )

        assertEquals(
            PhysicalNetworks.fingerprint(first),
            PhysicalNetworks.fingerprint(second),
        )
    }

    @Test
    fun stateFingerprintIsIndependentOfNetworkEnumerationOrder() {
        val routes = PhysicalNetworks.canonicalCidrs(
            listOf(physicalNetwork("192.168.1.50/24", wifi = true)),
        )

        assertEquals(
            PhysicalNetworks.stateFingerprint(listOf("102", "101"), routes),
            PhysicalNetworks.stateFingerprint(listOf("101", "102"), routes),
        )
    }

    private fun physicalNetwork(
        vararg addresses: String,
        active: Boolean = true,
        validated: Boolean = true,
        wifi: Boolean = false,
        cellular: Boolean = false,
        ethernet: Boolean = false,
        vpn: Boolean = false,
    ): PhysicalNetworkSnapshot =
        PhysicalNetworkSnapshot(
            active = active,
            validated = validated,
            wifi = wifi,
            cellular = cellular,
            ethernet = ethernet,
            vpn = vpn,
            addresses = addresses.map(::physicalAddress),
        )

    private fun physicalAddress(value: String): PhysicalLinkAddress {
        val parts = value.split("/")
        return PhysicalLinkAddress(
            address = InetAddress.getByName(parts[0]),
            prefixLength = parts[1].toInt(),
        )
    }
}
