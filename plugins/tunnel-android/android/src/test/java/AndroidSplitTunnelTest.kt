package ru.nelomai.tunnel

import com.wireguard.config.Config
import java.io.ByteArrayInputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidSplitTunnelTest {
    @Test
    fun api32DropsEverySplitOptionWithoutValidation() {
        val args = TunnelOptionsArgs().apply {
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
            excludedPackages = arrayListOf("com.example.excluded")
            includedPackages = arrayListOf("com.example.included")
        }

        val error = runCatching {
            AndroidSplitTunnel.resolveOptions(33, args)
        }.exceptionOrNull() as AndroidSplitTunnelException

        assertEquals("conflicting_application_rules", error.code)
    }

    @Test
    fun api33DeduplicatesPackagesAndEnforcesTheLimit() {
        val valid = TunnelOptionsArgs().apply {
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
    fun api32KeepsOriginalConfigAndApi33RebuildsOnlyApplicationRules() {
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
            includedPackages = arrayListOf("com.example.selected")
            splitTunnelRoutes = arrayListOf("203.0.113.0/24")
        }

        val api32 = AndroidSplitTunnel.applyOptions(
            original,
            AndroidSplitTunnel.resolveOptions(32, args),
        )
        assertSame(original, api32)

        val api33 = AndroidSplitTunnel.applyOptions(
            original,
            AndroidSplitTunnel.resolveOptions(33, args),
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

    private fun parseConfig(value: String): Config =
        Config.parse(ByteArrayInputStream(value.encodeToByteArray()))
}
