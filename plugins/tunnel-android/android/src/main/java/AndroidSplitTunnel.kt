package ru.nelomai.tunnel

import android.net.IpPrefix
import com.wireguard.config.Config
import com.wireguard.config.Interface
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicReference

private const val MAX_APPLICATION_RULES = 512
private const val MAX_EXCLUDED_ROUTES = 16_384
private val PACKAGE_ID = Regex("^[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z0-9_]+)+$")

internal class AndroidSplitTunnelException(
    val code: String,
) : RuntimeException(code)

internal data class Ipv4Prefix(
    val address: Int,
    val prefixLength: Int,
    val canonical: String,
) {
    fun toIpPrefix(): IpPrefix {
        val bytes = byteArrayOf(
            (address ushr 24).toByte(),
            (address ushr 16).toByte(),
            (address ushr 8).toByte(),
            address.toByte(),
        )
        return IpPrefix(InetAddress.getByAddress(bytes), prefixLength)
    }
}

internal data class EffectiveAndroidTunnelOptions(
    val splitSupported: Boolean = false,
    val excludedPackages: List<String> = emptyList(),
    val includedPackages: List<String> = emptyList(),
    val excludedRoutes: List<Ipv4Prefix> = emptyList(),
    val excludeLocalNetworks: Boolean = false,
) {
    fun isEmpty(): Boolean =
        excludedPackages.isEmpty() &&
            includedPackages.isEmpty() &&
            excludedRoutes.isEmpty() &&
            !excludeLocalNetworks
}

internal object AndroidSplitTunnel {
    private val currentRoutes = AtomicReference<List<Ipv4Prefix>>(emptyList())

    fun resolveOptions(
        androidApiLevel: Int,
        args: TunnelOptionsArgs,
    ): EffectiveAndroidTunnelOptions {
        if (androidApiLevel < 33 || !args.splitActive) {
            return EffectiveAndroidTunnelOptions()
        }
        if (args.excludedPackages.isNotEmpty() && args.includedPackages.isNotEmpty()) {
            throw AndroidSplitTunnelException("conflicting_application_rules")
        }

        val excludedPackages = normalizePackages(args.excludedPackages)
        val includedPackages = normalizePackages(args.includedPackages)
        val excludedRoutes = linkedMapOf<String, Ipv4Prefix>()
        args.splitTunnelRoutes.forEach { value ->
            val prefix = canonicalIpv4Prefix(value)
            excludedRoutes.putIfAbsent(prefix.canonical, prefix)
        }
        if (excludedRoutes.size > MAX_EXCLUDED_ROUTES) {
            throw AndroidSplitTunnelException("split_tunnel_routes_limit")
        }
        return EffectiveAndroidTunnelOptions(
            splitSupported = true,
            excludedPackages = excludedPackages,
            includedPackages = includedPackages,
            excludedRoutes = excludedRoutes.values.toList(),
            excludeLocalNetworks = args.excludeLocalNetworks,
        )
    }

    fun applyOptions(
        config: Config,
        options: EffectiveAndroidTunnelOptions,
    ): Config {
        if (!options.splitSupported) {
            return config
        }

        val source = config.getInterface()
        val builder = Interface.Builder()
            .addAddresses(source.getAddresses())
            .addDnsServers(source.getDnsServers())
            .addDnsSearchDomains(source.getDnsSearchDomains())
            .setKeyPair(source.getKeyPair())
        if (source.getListenPort().isPresent) {
            builder.setListenPort(source.getListenPort().get())
        }
        if (source.getMtu().isPresent) {
            builder.setMtu(source.getMtu().get())
        }
        if (options.excludedPackages.isNotEmpty()) {
            builder.excludeApplications(options.excludedPackages)
        } else if (options.includedPackages.isNotEmpty()) {
            builder.includeApplications(options.includedPackages)
        }

        return Config.Builder()
            .setInterface(builder.build())
            .addPeers(config.getPeers())
            .build()
    }

    fun replaceExcludedRoutes(routes: List<Ipv4Prefix>) {
        currentRoutes.set(routes.toList())
    }

    fun mergeExcludedRoutes(
        panelRoutes: List<Ipv4Prefix>,
        localRoutes: List<Ipv4Prefix>,
    ): List<Ipv4Prefix> {
        val routes = linkedMapOf<String, Ipv4Prefix>()
        panelRoutes.forEach { routes.putIfAbsent(it.canonical, it) }
        localRoutes.forEach { routes.putIfAbsent(it.canonical, it) }
        return routes.values.sortedWith { first, second ->
            val addressOrder = Integer.compareUnsigned(first.address, second.address)
            if (addressOrder != 0) {
                addressOrder
            } else {
                first.prefixLength.compareTo(second.prefixLength)
            }
        }
    }

    fun currentExcludedRoutes(): List<IpPrefix> =
        currentRoutes.get().map(Ipv4Prefix::toIpPrefix)

    fun clear() {
        currentRoutes.set(emptyList())
    }

    private fun normalizePackages(values: List<String>): List<String> {
        val packages = linkedSetOf<String>()
        values.forEach { raw ->
            val packageId = raw.trim()
            if (!PACKAGE_ID.matches(packageId)) {
                throw AndroidSplitTunnelException("invalid_application_id")
            }
            packages.add(packageId)
        }
        if (packages.size > MAX_APPLICATION_RULES) {
            throw AndroidSplitTunnelException("application_rules_limit")
        }
        return packages.toList()
    }

    private fun canonicalIpv4Prefix(value: String): Ipv4Prefix {
        val parts = value.trim().split("/")
        if (parts.size != 2) {
            throw AndroidSplitTunnelException("invalid_split_tunnel_route")
        }
        val prefixLength = parts[1].toIntOrNull()
            ?.takeIf { it in 0..32 }
            ?: throw AndroidSplitTunnelException("invalid_split_tunnel_route")
        val octets = parts[0].split(".")
        if (octets.size != 4) {
            throw AndroidSplitTunnelException("invalid_split_tunnel_route")
        }
        val address = octets.fold(0) { accumulator, raw ->
            val octet = raw.toIntOrNull()
                ?.takeIf { it in 0..255 && raw == it.toString() }
                ?: throw AndroidSplitTunnelException("invalid_split_tunnel_route")
            accumulator shl 8 or octet
        }
        val mask = when (prefixLength) {
            0 -> 0
            else -> -1 shl (32 - prefixLength)
        }
        val network = address and mask
        val canonicalAddress = listOf(
            network ushr 24 and 0xff,
            network ushr 16 and 0xff,
            network ushr 8 and 0xff,
            network and 0xff,
        ).joinToString(".")
        return Ipv4Prefix(
            address = network,
            prefixLength = prefixLength,
            canonical = "$canonicalAddress/$prefixLength",
        )
    }
}
