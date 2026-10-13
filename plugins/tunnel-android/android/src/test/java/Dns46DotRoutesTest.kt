package ru.nelomai.tunnel

import org.junit.Assert.*
import org.junit.Test

class Dns46DotRoutesTest {
    @Test fun invalidMetadataNeverForcesRoutes() {
        for ((hostname, endpoint) in listOf("1.2.3.4" to "93.184.216.34", "dns.nelomai.ru" to "10.0.0.1",
            "dns.nelomai.ru" to "224.0.0.1", "dns..nelomai.ru" to "93.184.216.34")) {
            val args = options().apply { dns46DotHostname = hostname; dns46DotEndpointIpv4s = arrayListOf(endpoint) }
            assertTrue(AndroidSplitTunnel.resolveOptions(34, args, "prefer_ipv6", privateDnsHostname = hostname).dns46DotRoutes.isEmpty())
        }
    }
    private fun options() = TunnelOptionsArgs().apply {
        splitActive = true
        splitTunnelRoutes = arrayListOf("0.0.0.0/0", "93.184.216.34/32")
        dns46DotHostname = "dns.nelomai.ru"
        dns46DotEndpointIpv4s = arrayListOf("93.184.216.34", "93.184.216.35")
        dns46DotExpiresAtUnix = 4_000_000_000
    }
    @Test fun readyOwnProviderForcesOnlyOwnIpv4RoutesWithoutReplacingDns53() {
        val effective = AndroidSplitTunnel.resolveOptions(34, options(), "prefer_ipv6",
            privateDnsHostname = "dns.nelomai.ru")
        val routes = AndroidSplitTunnel.planVpnRoutes(effective.excludedRoutes, effective.dnsServers, effective.dns46DotRoutes)
        assertTrue(routes.forcedTunnelRoutes.map { it.canonical }.containsAll(
            listOf("93.184.216.34/32", "93.184.216.35/32")))
        assertEquals(listOf("10.255.255.53"), effective.dnsServers.map { it.hostAddress })
    }
    @Test fun foreignMissingExpiredAndIpv4ModeDoNotForceOwnRoutes() {
        for (provider in listOf(null, "dns.quad9.net")) {
            val effective = AndroidSplitTunnel.resolveOptions(34, options(), "prefer_ipv6", privateDnsHostname = provider)
            assertFalse(AndroidSplitTunnel.planVpnRoutes(effective.excludedRoutes,effective.dnsServers,effective.dns46DotRoutes)
                .forcedTunnelRoutes.any { it.canonical.startsWith("93.") })
        }
        for (mode in listOf("ipv4", "prefer_ipv6")) {
            val args = options().apply { if (mode == "prefer_ipv6") dns46DotExpiresAtUnix = 0 }
            val effective = AndroidSplitTunnel.resolveOptions(34,args,mode,privateDnsHostname="dns.nelomai.ru")
            assertFalse(AndroidSplitTunnel.planVpnRoutes(effective.excludedRoutes,effective.dnsServers,effective.dns46DotRoutes)
                .forcedTunnelRoutes.any { it.canonical.startsWith("93.") })
        }
    }
}
