package ru.nelomai.tunnel

internal data class RedundantVpnRouteBaseline(
    val effectiveExcludedRoutes: List<String>,
)

internal fun redundantVpnRouteBaseline(
    options: EffectiveAndroidTunnelOptions,
    localRoutes: List<Ipv4Prefix>,
): RedundantVpnRouteBaseline? {
    if (!options.splitSupported || !options.excludeLocalNetworks) return null
    return RedundantVpnRouteBaseline(
        AndroidSplitTunnel.mergeExcludedRoutes(options.excludedRoutes, localRoutes)
            .map(Ipv4Prefix::canonical),
    )
}

internal fun redundantLocalRouteRefreshRequired(
    baseline: RedundantVpnRouteBaseline?,
    options: EffectiveAndroidTunnelOptions,
    localRoutes: List<Ipv4Prefix>,
): Boolean {
    val installed = baseline ?: return false
    val current = redundantVpnRouteBaseline(options, localRoutes) ?: return false
    return installed != current
}
