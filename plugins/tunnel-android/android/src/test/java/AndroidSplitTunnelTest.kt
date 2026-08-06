package ru.nelomai.tunnel

import com.wireguard.config.Config
import java.io.ByteArrayInputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidSplitTunnelTest {
    @Test
    fun api32DropsEverySplitOptionWithoutValidation() {
        val args = TunnelOptionsArgs().apply {
            splitActive = true
            excludedPackages = ArrayList(List(513) { "bad package $it" })
            includedPackages = arrayListOf("also bad")
            splitTunnelRoutes = arrayListOf("not-a-cidr")
            excludeLocalNetworks = true
        }

        val effective = AndroidSplitTunnel.resolveOptions(32, args)

        assertTrue(effective.isEmpty())
    }

    @Test
    fun api33RejectsConflictingApplicationModes() {
        val args = TunnelOptionsArgs().apply {
            splitActive = true
            excludedPackages = arrayListOf("com.example.excluded")
            includedPackages = arrayListOf("com.example.included")
        }

        val error = runCatching {
            AndroidSplitTunnel.resolveOptions(33, args)
        }.exceptionOrNull() as AndroidSplitTunnelException

        assertEquals("conflicting_application_rules", error.code)
    }

    @Test
    fun api33DropsOptionsWhenSplitIsInactive() {
        val args = TunnelOptionsArgs().apply {
            excludedPackages = arrayListOf("com.example.excluded")
            splitTunnelRoutes = arrayListOf("203.0.113.0/24")
            excludeLocalNetworks = true
        }

        assertTrue(AndroidSplitTunnel.resolveOptions(33, args).isEmpty())
    }

    @Test
    fun api33DeduplicatesPackagesAndEnforcesTheLimit() {
        val valid = TunnelOptionsArgs().apply {
            splitActive = true
            excludedPackages = arrayListOf(
                "com.example.first",
                "com.example.first",
                "com.example.second",
            )
        }

        assertEquals(
            listOf("com.example.first", "com.example.second"),
            AndroidSplitTunnel.resolveOptions(33, valid).excludedPackages,
        )

        val oversized = TunnelOptionsArgs().apply {
            splitActive = true
            excludedPackages = ArrayList(List(513) { "com.example.package$it" })
        }
        val error = runCatching {
            AndroidSplitTunnel.resolveOptions(33, oversized)
        }.exceptionOrNull() as AndroidSplitTunnelException
        assertEquals("application_rules_limit", error.code)
    }

    @Test
    fun api33CanonicalizesAndDeduplicatesIpv4Cidrs() {
        val args = TunnelOptionsArgs().apply {
            splitActive = true
            splitTunnelRoutes = arrayListOf(
                "203.0.113.17/24",
                "203.0.113.0/24",
                "198.51.100.255/25",
            )
            excludeLocalNetworks = true
        }

        val effective = AndroidSplitTunnel.resolveOptions(33, args)

        assertEquals(
            listOf("203.0.113.0/24", "198.51.100.128/25"),
            effective.excludedRoutes.map { it.canonical },
        )
        assertTrue(effective.excludeLocalNetworks)
    }

    @Test
    fun api33EnforcesTheIpv4CidrLimit() {
        val args = TunnelOptionsArgs().apply {
            splitActive = true
            splitTunnelRoutes = ArrayList(
                List(16_385) { index ->
                    val first = index ushr 16
                    val second = index ushr 8 and 0xff
                    val third = index and 0xff
                    "$first.$second.$third.1/32"
                },
            )
        }

        val error = runCatching {
            AndroidSplitTunnel.resolveOptions(33, args)
        }.exceptionOrNull() as AndroidSplitTunnelException

        assertEquals("split_tunnel_routes_limit", error.code)
    }

    @Test
    fun localNetworksAreMergedInMemoryWithoutChangingPanelRoutes() {
        val panelRoutes = listOf(
            prefix("203.0.113.0/24"),
            prefix("192.168.1.0/24"),
        )
        val localRoutes = listOf(
            prefix("192.168.1.0/24"),
            prefix("10.0.0.0/8"),
        )

        val merged = AndroidSplitTunnel.mergeExcludedRoutes(panelRoutes, localRoutes)

        assertEquals(
            listOf("10.0.0.0/8", "192.168.1.0/24", "203.0.113.0/24"),
            merged.map { it.canonical },
        )
        assertEquals(
            listOf("203.0.113.0/24", "192.168.1.0/24"),
            panelRoutes.map { it.canonical },
        )
    }

    @Test
    fun everyApiKeepsControlTrafficOutsideTheTunnel() {
        val original = parseConfig(
            """
            [Interface]
            PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
            Address = 10.8.1.2/32
            DNS = 8.8.8.8
            MTU = 1280
            ExcludedApplications = com.example.old

            [Peer]
            PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
            AllowedIPs = 0.0.0.0/0
            Endpoint = 127.0.0.1:10001
            PersistentKeepalive = 21
            """.trimIndent(),
        )
        val args = TunnelOptionsArgs().apply {
            splitActive = true
            includedPackages = arrayListOf("com.example.selected")
            splitTunnelRoutes = arrayListOf("203.0.113.0/24")
        }

        val api32 = AndroidSplitTunnel.applyOptions(
            original,
            AndroidSplitTunnel.resolveOptions(32, args),
            "ru.nelomai.client",
        )
        assertEquals(
            setOf("com.example.old", "ru.nelomai.client"),
            api32.getInterface().excludedApplications,
        )

        val api33 = AndroidSplitTunnel.applyOptions(
            original,
            AndroidSplitTunnel.resolveOptions(33, args),
            "ru.nelomai.client",
        )
        assertTrue(api33.getInterface().excludedApplications.isEmpty())
        assertEquals(
            setOf("com.example.selected"),
            api33.getInterface().includedApplications,
        )
        assertEquals(original.getInterface().addresses, api33.getInterface().addresses)
        assertEquals(original.getInterface().dnsServers, api33.getInterface().dnsServers)
        assertEquals(original.getInterface().keyPair, api33.getInterface().keyPair)
        assertEquals(original.getInterface().mtu, api33.getInterface().mtu)
        assertEquals(original.peers, api33.peers)
        assertEquals(
            setOf("0.0.0.0/0"),
            api33.peers.single().allowedIps.map { it.toString() }.toSet(),
        )
    }

    @Test
    fun dnsOverrideAppliesIndependentlyFromSplitTunnelSupport() {
        val original = parseConfig(
            """
            [Interface]
            PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
            Address = 10.8.1.2/32
            DNS = 8.8.8.8

            [Peer]
            PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
            AllowedIPs = 0.0.0.0/0
            Endpoint = 127.0.0.1:10001
            """.trimIndent(),
        )
        val args = TunnelOptionsArgs().apply {
            dnsServers = arrayListOf("9.9.9.9", "149.112.112.112")
        }

        val updated = AndroidSplitTunnel.applyOptions(
            original,
            AndroidSplitTunnel.resolveOptions(32, args),
            "ru.nelomai.client",
        )

        assertEquals(
            setOf("9.9.9.9", "149.112.112.112"),
            updated.getInterface().dnsServers.map { it.hostAddress }.toSet(),
        )
    }

    @Test
    fun dnsRoutesStayInTheTunnelWhenAParentPrefixIsExcluded() {
        val args = TunnelOptionsArgs().apply {
            splitActive = true
            splitTunnelRoutes = arrayListOf("9.0.0.0/8", "149.112.0.0/16")
            dnsServers = arrayListOf("9.9.9.9", "149.112.112.112")
        }
        val options = AndroidSplitTunnel.resolveOptions(33, args)

        val routes = AndroidSplitTunnel.planVpnRoutes(
            options.excludedRoutes,
            options.dnsServers,
        )

        assertEquals(
            listOf("9.0.0.0/8", "149.112.0.0/16"),
            routes.excludedRoutes.map { it.canonical },
        )
        assertEquals(
            listOf("9.9.9.9/32", "149.112.112.112/32"),
            routes.forcedTunnelRoutes.map { it.canonical },
        )
    }

    @Test
    fun dnsRotationKeepsAllFourResolversInsideTheTunnel() {
        val dnsServers = arrayListOf(
            "8.8.8.8",
            "77.88.8.8",
            "9.9.9.9",
            "8.8.4.4",
        )
        val args = TunnelOptionsArgs().apply {
            splitActive = true
            splitTunnelRoutes = arrayListOf("8.0.0.0/8", "9.0.0.0/8", "77.0.0.0/8")
            this.dnsServers = dnsServers
        }
        val options = AndroidSplitTunnel.resolveOptions(33, args)

        val routes = AndroidSplitTunnel.planVpnRoutes(
            options.excludedRoutes,
            options.dnsServers,
        )

        assertEquals(
            dnsServers.map { "$it/32" },
            routes.forcedTunnelRoutes.map { it.canonical },
        )
    }

    private fun parseConfig(value: String): Config =
        Config.parse(ByteArrayInputStream(value.encodeToByteArray()))

    private fun prefix(value: String): Ipv4Prefix {
        val args = TunnelOptionsArgs().apply {
            splitActive = true
            splitTunnelRoutes = arrayListOf(value)
        }
        return AndroidSplitTunnel.resolveOptions(33, args).excludedRoutes.single()
    }
}
