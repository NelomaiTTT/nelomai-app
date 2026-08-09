package ru.nelomai.tunnel

import android.net.IpPrefix
import android.os.Build
import androidx.annotation.RequiresApi
import org.amnezia.awg.config.Config
import org.amnezia.awg.config.Interface
import java.net.Inet4Address
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicReference

private const val MAX_APPLICATION_RULES = 512
private const val MAX_EXCLUDED_ROUTES = 16_384
private const val MAX_DNS_SERVERS = 4
private val PACKAGE_ID = Regex("^[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z0-9_]+)+$")

internal class AndroidSplitTunnelException(
    val code: String,
) : RuntimeException(code)

internal data class Ipv4Prefix(
    val address: Int,
    val prefixLength: Int,
    val canonical: String,
) {
    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
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
    val dnsServers: List<InetAddress> = emptyList(),
) {
    fun isEmpty(): Boolean =
        excludedPackages.isEmpty() &&
            includedPackages.isEmpty() &&
            excludedRoutes.isEmpty() &&
            !excludeLocalNetworks &&
            dnsServers.isEmpty()
}

internal data class AndroidVpnRoutes(
    val excludedRoutes: List<Ipv4Prefix> = emptyList(),
    val forcedTunnelRoutes: List<Ipv4Prefix> = emptyList(),
)

internal object AndroidSplitTunnel {
    private val currentVpnRoutes = AtomicReference(AndroidVpnRoutes())

    fun resolveOptions(
        androidApiLevel: Int,
        args: TunnelOptionsArgs,
    ): EffectiveAndroidTunnelOptions {
        val dnsServers = normalizeDnsServers(args.dnsServers)
        if (androidApiLevel < 33 || !args.splitActive) {
            return EffectiveAndroidTunnelOptions(dnsServers = dnsServers)
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
            dnsServers = dnsServers,
        )
    }

    fun applyOptions(
        config: Config,
        options: EffectiveAndroidTunnelOptions,
        controlPackageName: String,
    ): Config {
        val source = config.getInterface()
        val includedPackages = if (options.splitSupported) {
            options.includedPackages.filterNot { it == controlPackageName }
        } else {
            source.includedApplications.filterNot { it == controlPackageName }
        }
        val excludedPackages = when {
            includedPackages.isNotEmpty() -> emptyList()
            options.splitSupported -> (options.excludedPackages + controlPackageName).distinct()
            else -> (source.excludedApplications + controlPackageName).distinct()
        }
        val builder = Interface.Builder()
            .addAddresses(source.getAddresses())
            .addDnsServers(options.dnsServers.ifEmpty { source.getDnsServers() })
            .addDnsSearchDomains(source.getDnsSearchDomains())
            .setKeyPair(source.getKeyPair())
        if (source.getListenPort().isPresent) {
            builder.setListenPort(source.getListenPort().get())
        }
        if (source.getMtu().isPresent) {
            builder.setMtu(source.getMtu().get())
        }
        source.junkPacketCount.ifPresent(builder::setJunkPacketCount)
        source.junkPacketMinSize.ifPresent(builder::setJunkPacketMinSize)
        source.junkPacketMaxSize.ifPresent(builder::setJunkPacketMaxSize)
        source.initPacketJunkSize.ifPresent(builder::setInitPacketJunkSize)
        source.responsePacketJunkSize.ifPresent(builder::setResponsePacketJunkSize)
        source.cookieReplyPacketJunkSize.ifPresent(builder::setCookieReplyPacketJunkSize)
        source.transportPacketJunkSize.ifPresent(builder::setTransportPacketJunkSize)
        source.initPacketMagicHeader.ifPresent(builder::setInitPacketMagicHeader)
        source.responsePacketMagicHeader.ifPresent(builder::setResponsePacketMagicHeader)
        source.underloadPacketMagicHeader.ifPresent(builder::setUnderloadPacketMagicHeader)
        source.transportPacketMagicHeader.ifPresent(builder::setTransportPacketMagicHeader)
        source.specialJunkI1.ifPresent(builder::setSpecialJunkI1)
        source.specialJunkI2.ifPresent(builder::setSpecialJunkI2)
        source.specialJunkI3.ifPresent(builder::setSpecialJunkI3)
        source.specialJunkI4.ifPresent(builder::setSpecialJunkI4)
        source.specialJunkI5.ifPresent(builder::setSpecialJunkI5)
        source.headerProtectionKey.ifPresent(builder::setHeaderProtectionKey)
        source.contentPaddingAddition.ifPresent(builder::setContentPaddingAddition)
        source.rekeyAfterTime.ifPresent(builder::setRekeyAfterTime)
        source.rekeyTimeout.ifPresent(builder::setRekeyTimeout)
        source.rejectAfterTime.ifPresent(builder::setRejectAfterTime)
        source.keepaliveTimeout.ifPresent(builder::setKeepaliveTimeout)
        source.maxHandshakeAttempts.ifPresent(builder::setMaxHandshakeAttempts)
        if (excludedPackages.isNotEmpty()) {
            builder.excludeApplications(excludedPackages)
        } else if (includedPackages.isNotEmpty()) {
            builder.includeApplications(includedPackages)
        }

        return Config.Builder()
            .setInterface(builder.build())
            .addPeers(config.getPeers())
            .build()
    }

    fun replaceVpnRoutes(
        excludedRoutes: List<Ipv4Prefix>,
        dnsServers: List<InetAddress>,
    ) {
        currentVpnRoutes.set(planVpnRoutes(excludedRoutes, dnsServers))
    }

    fun planVpnRoutes(
        excludedRoutes: List<Ipv4Prefix>,
        dnsServers: List<InetAddress>,
    ): AndroidVpnRoutes = AndroidVpnRoutes(
        excludedRoutes = excludedRoutes.toList(),
        forcedTunnelRoutes = dnsServers.filterIsInstance<Inet4Address>().map { server ->
            canonicalIpv4Prefix("${server.hostAddress}/32")
        },
    )

    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    fun currentVpnRoutes(): Pair<List<IpPrefix>, List<IpPrefix>> {
        val routes = currentVpnRoutes.get()
        return Pair(
            routes.excludedRoutes.map(Ipv4Prefix::toIpPrefix),
            routes.forcedTunnelRoutes.map(Ipv4Prefix::toIpPrefix),
        )
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

    fun clear() {
        currentVpnRoutes.set(AndroidVpnRoutes())
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

    private fun normalizeDnsServers(values: List<String>): List<InetAddress> {
        if (values.size > MAX_DNS_SERVERS) {
            throw AndroidSplitTunnelException("dns_servers_limit")
        }
        val servers = linkedMapOf<String, InetAddress>()
        values.forEach { raw ->
            val octets = raw.trim().split(".")
            if (octets.size != 4) {
                throw AndroidSplitTunnelException("invalid_dns_server")
            }
            val bytes = octets.map { value ->
                value.toIntOrNull()
                    ?.takeIf { it in 0..255 && value == it.toString() }
                    ?.toByte()
                    ?: throw AndroidSplitTunnelException("invalid_dns_server")
            }.toByteArray()
            val canonical = octets.joinToString(".")
            servers.putIfAbsent(canonical, InetAddress.getByAddress(bytes))
        }
        return servers.values.toList()
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
