package ru.nelomai.client

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Handler
import android.os.Looper

/** Foreground bootstrap wakeups observe physical links, even behind a live VPN. */
internal class BootstrapNetworkMonitor(context: Context, private val onReady: () -> Unit) {
    private val connectivity = context.applicationContext.getSystemService(ConnectivityManager::class.java)
    private val handler = Handler(Looper.getMainLooper())
    private var callback: ConnectivityManager.NetworkCallback? = null
    private val networks = mutableMapOf<Network, Boolean>()

    fun start() {
        if (callback != null || connectivity == null) return
        val observer = object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
                val physical = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                val validated = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
                handler.post {
                    if (callback !== this) return@post
                    if (!physical) {
                        networks.remove(network)
                        return@post
                    }
                    val previous = networks.put(network, validated)
                    if (previous == null || (!previous && validated)) onReady()
                }
            }

            override fun onLost(network: Network) {
                handler.post { if (callback === this) networks.remove(network) }
            }
        }
        callback = observer
        try {
            connectivity.registerNetworkCallback(NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build(), observer)
        } catch (_: RuntimeException) {
            callback = null
            networks.clear()
            android.util.Log.w("NelomaiStartup", "bootstrap.network_observer_unavailable")
        }
    }

    fun stop() {
        val previous = callback
        callback = null
        networks.clear()
        if (previous != null) runCatching { connectivity?.unregisterNetworkCallback(previous) }
    }
}
