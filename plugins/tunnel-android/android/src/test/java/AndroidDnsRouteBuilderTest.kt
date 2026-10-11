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
