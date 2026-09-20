package ru.nelomai.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RedundantPhysicalNetworkRouteRefreshTest {
    @Test
    fun unchangedLocalRoutesDoNotRequestRestart() {
        val options = splitOptions(panelRoutes = listOf(PANEL_ROUTE))
        val baseline = requireNotNull(
            redundantVpnRouteBaseline(options, listOf(LAN_ROUTE)),
        )

        assertFalse(
            redundantLocalRouteRefreshRequired(
                baseline,
                options,
                listOf(LAN_ROUTE),
            ),
        )
    }

    @Test
    fun changedLocalRoutesRequestRestart() {
        val options = splitOptions(panelRoutes = listOf(PANEL_ROUTE))
        val baseline = requireNotNull(
            redundantVpnRouteBaseline(options, listOf(LAN_ROUTE)),
        )

        assertTrue(
            redundantLocalRouteRefreshRequired(
                baseline,
                options,
                listOf(REPLACEMENT_LAN_ROUTE),
            ),
        )
    }

    @Test
    fun excludedLocalDisabledNeverCreatesOrRefreshesRouteBaseline() {
        val options = splitOptions(
            panelRoutes = listOf(PANEL_ROUTE),
            excludeLocalNetworks = false,
        )

        assertNull(redundantVpnRouteBaseline(options, listOf(LAN_ROUTE)))
        assertFalse(
            redundantLocalRouteRefreshRequired(
                baseline = null,
                options = options,
                localRoutes = listOf(REPLACEMENT_LAN_ROUTE),
            ),
        )
    }

    @Test
    fun canonicalRouteOrderingDoesNotRequestRestart() {
        val options = splitOptions(panelRoutes = listOf(PANEL_ROUTE, SECOND_PANEL_ROUTE))
        val baseline = requireNotNull(
            redundantVpnRouteBaseline(
                options,
                listOf(LAN_ROUTE, REPLACEMENT_LAN_ROUTE),
            ),
        )

        assertFalse(
            redundantLocalRouteRefreshRequired(
                baseline,
                options.copy(excludedRoutes = options.excludedRoutes.reversed()),
                listOf(REPLACEMENT_LAN_ROUTE, LAN_ROUTE),
            ),
        )
    }

    @Test
    fun sameEffectiveExclusionsAfterMergingDoNotRequestRestart() {
        val options = splitOptions(panelRoutes = listOf(PANEL_ROUTE, LAN_ROUTE))
        val baseline = requireNotNull(
            redundantVpnRouteBaseline(options, listOf(LAN_ROUTE)),
        )

        assertFalse(
            redundantLocalRouteRefreshRequired(
                baseline,
                options,
                localRoutes = emptyList(),
            ),
        )
    }

    @Test
    fun staleOwnerCallbackCannotRequestRouteRefresh() {
        val installedOwner = RouteRefreshOwner()
        val staleOwner = RouteRefreshOwner()
        val identity = RedundantPhysicalNetworkCallbackIdentity(
            serviceGeneration = 7,
            startOperationId = "start-a",
            owner = staleOwner,
        )
        var restarts = 0

        val applied = identity.applyIfCurrent(
            mutationFence = RedundantOperationMutationFence(),
            current = {
                RedundantPhysicalNetworkCallbackState(
                    serviceGeneration = 7,
                    installedStartOperationId = "start-a",
                    installedOwner = installedOwner,
                    pendingStop = false,
                    tombstoneUnreadable = false,
                )
            },
        ) { restarts += 1 }

        assertFalse(applied)
        assertEquals(0, restarts)
    }

    @Test
    fun startupCancellationAndStopBarrierPreventRouteRefreshResurrection() {
        val owner = RouteRefreshOwner()
        val identity = RedundantPhysicalNetworkCallbackIdentity(
            serviceGeneration = 7,
            startOperationId = "start-a",
            owner = owner,
        )
        val cancelledFence = RedundantOperationMutationFence().apply { cancel("start-a") }
        var restarts = 0
        fun state(pendingStop: Boolean) = RedundantPhysicalNetworkCallbackState(
            serviceGeneration = 7,
            installedStartOperationId = "start-a",
            installedOwner = owner,
            pendingStop = pendingStop,
            tombstoneUnreadable = false,
        )

        assertFalse(identity.applyIfCurrent(cancelledFence, { state(false) }) { restarts += 1 })
        assertFalse(
            identity.applyIfCurrent(
                RedundantOperationMutationFence(),
                { state(true) },
            ) { restarts += 1 },
        )

        assertEquals(0, restarts)
    }

    private fun splitOptions(
        panelRoutes: List<Ipv4Prefix>,
        excludeLocalNetworks: Boolean = true,
    ) = EffectiveAndroidTunnelOptions(
        splitSupported = true,
        excludedRoutes = panelRoutes,
        excludeLocalNetworks = excludeLocalNetworks,
    )

    private class RouteRefreshOwner : RedundantVpnProcessOwner {
        override fun recover(): Boolean = true
        override fun resume(): Boolean = true
        override fun revoke(): Boolean = true
    }

    private companion object {
        val PANEL_ROUTE = Ipv4Prefix(0xcb007100.toInt(), 24, "203.0.113.0/24")
        val SECOND_PANEL_ROUTE = Ipv4Prefix(0xc6336400.toInt(), 24, "198.51.100.0/24")
        val LAN_ROUTE = Ipv4Prefix(0xc0a80100.toInt(), 24, "192.168.1.0/24")
        val REPLACEMENT_LAN_ROUTE = Ipv4Prefix(0x0a000000, 8, "10.0.0.0/8")
    }
}
