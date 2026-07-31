package ru.nelomai.tunnel

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.Handler
import android.os.Looper
import java.net.Inet4Address
import java.net.InetAddress

private const val NETWORK_CHANGE_DEBOUNCE_MILLIS = 300L
private const val NETWORK_SNAPSHOT_RETRY_MILLIS = 300_000L

internal data class PhysicalLinkAddress(
    val address: InetAddress,
    val prefixLength: Int,
)

internal data class PhysicalNetworkSnapshot(
    val active: Boolean,
    val wifi: Boolean,
    val cellular: Boolean,
    val ethernet: Boolean,
    val vpn: Boolean,
    val addresses: List<PhysicalLinkAddress>,
)

internal class PhysicalNetworks(context: Context) {
    private val connectivityManager =
        context.applicationContext.getSystemService(ConnectivityManager::class.java)
    private val handler = Handler(Looper.getMainLooper())
    private val lock = Any()

    private var callback: ConnectivityManager.NetworkCallback? = null
    private var listener: ((List<Ipv4Prefix>) -> Unit)? = null
    private val refresh = Runnable {
        val currentListener = synchronized(lock) { listener }
        runCatching(::snapshot)
            .onSuccess { currentListener?.invoke(it) }
            .onFailure {
                val active = synchronized(lock) { callback != null && listener != null }
                if (active) {
                    scheduleRetry(NETWORK_SNAPSHOT_RETRY_MILLIS)
                }
            }
    }

    @Suppress("DEPRECATION")
    fun snapshot(): List<Ipv4Prefix> {
        val networks = connectivityManager.allNetworks.mapNotNull { network ->
            val capabilities = connectivityManager.getNetworkCapabilities(network)
                ?: return@mapNotNull null
            val properties = connectivityManager.getLinkProperties(network)
                ?: return@mapNotNull null
            snapshot(capabilities, properties)
        }
        return canonicalCidrs(networks)
    }

    fun start(listener: (List<Ipv4Prefix>) -> Unit) {
        synchronized(lock) {
            if (callback != null) {
                return
            }
            this.listener = listener
            val networkCallback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) = scheduleRefresh()

                override fun onLost(network: Network) = scheduleRefresh()

                override fun onCapabilitiesChanged(
                    network: Network,
                    networkCapabilities: NetworkCapabilities,
                ) = scheduleRefresh()

                override fun onLinkPropertiesChanged(
                    network: Network,
                    linkProperties: LinkProperties,
                ) = scheduleRefresh()
            }
            callback = networkCallback
            val requestBuilder = NetworkRequest.Builder()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                requestBuilder.clearCapabilities()
            }
            requestBuilder.addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            val request = requestBuilder.build()
            connectivityManager.registerNetworkCallback(request, networkCallback)
        }
        scheduleRefresh()
    }

    fun scheduleRetry(delayMillis: Long) {
        handler.removeCallbacks(refresh)
        handler.postDelayed(refresh, delayMillis)
    }

    fun stop() {
        val current = synchronized(lock) {
            val value = callback
            callback = null
            listener = null
            value
        }
        handler.removeCallbacks(refresh)
        if (current != null) {
            runCatching { connectivityManager.unregisterNetworkCallback(current) }
        }
    }

    private fun scheduleRefresh() {
        handler.removeCallbacks(refresh)
        handler.postDelayed(refresh, NETWORK_CHANGE_DEBOUNCE_MILLIS)
    }

    companion object {
        fun canonicalCidrs(networks: List<PhysicalNetworkSnapshot>): List<Ipv4Prefix> {
            val routes = linkedMapOf<String, Ipv4Prefix>()
            networks.asSequence()
                .filter(PhysicalNetworkSnapshot::active)
                .filterNot(PhysicalNetworkSnapshot::vpn)
                .filter { it.wifi || it.cellular || it.ethernet }
                .flatMap { it.addresses.asSequence() }
                .mapNotNull(::canonicalPhysicalNetwork)
                .forEach { routes.putIfAbsent(it.canonical, it) }
            return AndroidSplitTunnel.mergeExcludedRoutes(emptyList(), routes.values.toList())
        }

        fun fingerprint(routes: List<Ipv4Prefix>): String =
            routes.joinToString(separator = "\n", transform = Ipv4Prefix::canonical)

        private fun snapshot(
            capabilities: NetworkCapabilities,
            properties: LinkProperties,
        ): PhysicalNetworkSnapshot =
            PhysicalNetworkSnapshot(
                active = true,
                wifi = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI),
                cellular = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR),
                ethernet = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET),
                vpn = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN),
                addresses = properties.linkAddresses.map {
                    PhysicalLinkAddress(
                        address = it.address,
                        prefixLength = it.prefixLength,
                    )
                },
            )

        private fun canonicalPhysicalNetwork(value: PhysicalLinkAddress): Ipv4Prefix? {
            val address = value.address as? Inet4Address ?: return null
            if (value.prefixLength !in 1..31) {
                return null
            }
            if (
                address.isAnyLocalAddress ||
                address.isLoopbackAddress ||
                address.isMulticastAddress ||
                address.isLinkLocalAddress
            ) {
                return null
            }

            val rawAddress = address.address.fold(0) { accumulator, octet ->
                accumulator shl 8 or (octet.toInt() and 0xff)
            }
            val mask = -1 shl (32 - value.prefixLength)
            val network = rawAddress and mask
            val canonicalAddress = listOf(
                network ushr 24 and 0xff,
                network ushr 16 and 0xff,
                network ushr 8 and 0xff,
                network and 0xff,
            ).joinToString(".")
            return Ipv4Prefix(
                address = network,
                prefixLength = value.prefixLength,
                canonical = "$canonicalAddress/${value.prefixLength}",
            )
        }
    }
}
