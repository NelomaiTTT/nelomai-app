package ru.nelomai.tunnel

import android.net.RouteInfo
import android.net.VpnService
import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.util.ReflectionHelpers
import ru.nelomai.runtime.v1.RuntimeVpnHostV1

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE)
class AndroidDnsRouteBuilderTest {
    @Test
    fun coldStrictProviderSurvivesBundleAndOverridesExclusionsInBuilderAndAllowedIps() {
        val controller = Robolectric.buildService(VpnService::class.java).create()
        val host = controller.get()
        val resolver = host.contentResolver
        android.provider.Settings.Global.putString(resolver, "private_dns_mode", "hostname")
        android.provider.Settings.Global.putString(resolver, "private_dns_specifier", "dns.nelomai.ru")
        val args = TunnelOptionsArgs().apply {
            splitActive = true
            splitTunnelRoutes = arrayListOf("0.0.0.0/0", "93.184.216.34/32")
            dns46DotHostname = "dns.nelomai.ru"
            dns46DotEndpointIpv4s = arrayListOf("93.184.216.34")
            dns46DotExpiresAtUnix = 4_000_000_000
        }.toBundle().toTunnelOptions()
        val config = org.amnezia.awg.config.Config.parse(java.io.ByteArrayInputStream("""
            [Interface]
            PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
            Address = 10.241.0.3/32
            [Peer]
            PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
            AllowedIPs = 10.0.0.0/8
            Endpoint = 127.0.0.1:10001
        """.trimIndent().toByteArray()))
        try {
            val provider = AndroidSplitTunnel.privateDnsHostname(host)
            assertEquals("dns.nelomai.ru", provider)
            val options = AndroidSplitTunnel.resolveConfigurationOptions(34, args, "prefer_ipv6", config, provider)
            val prepared = AndroidSplitTunnel.applyOptions(config, options, "ru.nelomai.test")
            assertEquals(setOf("10.0.0.0/8", "93.184.216.34/32"),
                prepared.peers.single().allowedIps.map { it.toString() }.toSet())
            val engine = NelomaiVpnService(object : RuntimeVpnHostV1 {
                override val service = host
                override fun builder(beforeEstablish: (VpnService.Builder) -> Unit) = host.Builder().also(beforeEstablish)
            })
            AndroidSplitTunnel.replaceVpnRoutes(options.excludedRoutes, options.dnsServers, options.dns46DotRoutes)
            val builder = engine.getBuilder()
            val routes = ReflectionHelpers.getField<List<RouteInfo>>(builder, "mRoutes")
            val own = routes.single { it.destination.toString() == "93.184.216.34/32" }
            assertEquals(RouteInfo.RTN_UNICAST, own.type)
            assertEquals("hostname", android.provider.Settings.Global.getString(resolver, "private_dns_mode"))
            assertEquals("dns.nelomai.ru", android.provider.Settings.Global.getString(resolver, "private_dns_specifier"))
            assertEquals(listOf("10.255.255.53"), options.dnsServers.map { it.hostAddress })
            android.provider.Settings.Global.putString(resolver, "private_dns_mode", "opportunistic")
            org.junit.Assert.assertNull(AndroidSplitTunnel.privateDnsHostname(host))
        } finally {
            AndroidSplitTunnel.clear()
            android.provider.Settings.Global.putString(resolver, "private_dns_mode", null)
            android.provider.Settings.Global.putString(resolver, "private_dns_specifier", null)
            controller.destroy()
        }
    }

    @Test
    fun dns46RouteOverridesParentAndExactExclusionsInTheActualVpnBuilder() {
        val options = AndroidSplitTunnel.resolveOptions(
            34,
            TunnelOptionsArgs().apply {
                splitActive = true
                excludeLocalNetworks = true
                splitTunnelRoutes = arrayListOf("10.0.0.0/8", "10.255.255.54/32")
                dnsServers = arrayListOf("9.9.9.9", "149.112.112.112")
            },
            "prefer_ipv6",
            listOf("10.255.255.53"),
        )
        val controller = Robolectric.buildService(VpnService::class.java).create()
        val host = controller.get()
        val engine = NelomaiVpnService(object : RuntimeVpnHostV1 {
            override val service = host
            override fun builder(beforeEstablish: (VpnService.Builder) -> Unit) =
                host.Builder().also(beforeEstablish)
        })
        AndroidSplitTunnel.replaceVpnRoutes(options.excludedRoutes, options.dnsServers)
        try {
            val builder = engine.getBuilder().addRoute(InetAddress.getByAddress(byteArrayOf(0, 0, 0, 0)), 0)
            val routes = ReflectionHelpers.getField<List<RouteInfo>>(builder, "mRoutes")
            val routeTypes = routes.associate {
                "${it.destination.address.hostAddress}/${it.destination.prefixLength}" to it.type
            }

            assertEquals(
                "Actual routes: $routeTypes",
                RouteInfo.RTN_UNICAST,
                routeTypes["10.255.255.54/32"],
            )
            assertEquals(
                RouteInfo.RTN_THROW,
                routeTypes["10.0.0.0/8"],
            )
        } finally {
            AndroidSplitTunnel.clear()
            controller.destroy()
        }
    }
}
