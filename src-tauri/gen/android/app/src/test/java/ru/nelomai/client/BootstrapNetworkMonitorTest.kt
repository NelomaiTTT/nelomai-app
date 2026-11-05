package ru.nelomai.client

import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Looper
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements
import org.robolectric.shadows.ShadowConnectivityManager
import org.robolectric.shadows.ShadowNetwork

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE, shadows = [BootstrapConnectivityShadow::class])
class BootstrapNetworkMonitorTest {
    @Test fun physicalReturnWakesBootstrapEvenWhenVpnRemainsTheDefaultNetwork() {
        val context = RuntimeEnvironment.getApplication()
        val connectivity = shadowOf(context.getSystemService(ConnectivityManager::class.java)) as BootstrapConnectivityShadow
        var wakes = 0
        val monitor = BootstrapNetworkMonitor(context) { wakes++ }
        monitor.start()
        monitor.start()
        try {
            assertEquals(1, connectivity.networkCallbacks.size)
            assertTrue(connectivity.request!!.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN))
            assertTrue(connectivity.request!!.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET))
            val callback = connectivity.networkCallbacks.single()
            val network = ShadowNetwork.newInstance(42)
            val caps = NetworkCapabilities()
            shadowOf(caps).addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            shadowOf(caps).addTransportType(NetworkCapabilities.TRANSPORT_VPN)
            callback.onCapabilitiesChanged(network, caps)
            shadowOf(Looper.getMainLooper()).idle()
            assertEquals(0, wakes)
            shadowOf(caps).removeTransportType(NetworkCapabilities.TRANSPORT_VPN)
            shadowOf(caps).addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            callback.onCapabilitiesChanged(network, caps)
            callback.onCapabilitiesChanged(network, caps)
            shadowOf(Looper.getMainLooper()).idle()
            assertEquals("a new physical link wakes once, without waiting for OS validation", 1, wakes)
            shadowOf(caps).addCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            callback.onCapabilitiesChanged(network, caps)
            callback.onCapabilitiesChanged(network, caps)
            shadowOf(Looper.getMainLooper()).idle()
            assertEquals("new validation gives an early attempt another chance", 2, wakes)
            callback.onLost(network)
            callback.onCapabilitiesChanged(network, caps)
            shadowOf(Looper.getMainLooper()).idle()
            assertEquals(3, wakes)
            callback.onCapabilitiesChanged(ShadowNetwork.newInstance(46), caps)
            monitor.stop()
            shadowOf(Looper.getMainLooper()).idle()
            assertEquals("queued callbacks cannot outlive the subscription", 3, wakes)
            callback.onCapabilitiesChanged(ShadowNetwork.newInstance(43), caps)
            shadowOf(Looper.getMainLooper()).idle()
            assertEquals("late callbacks from a stopped monitor are ignored", 3, wakes)
            monitor.start()
            callback.onCapabilitiesChanged(ShadowNetwork.newInstance(44), caps)
            shadowOf(Looper.getMainLooper()).idle()
            assertEquals("an old subscription cannot wake the next lifecycle", 3, wakes)
            connectivity.networkCallbacks.single().onCapabilitiesChanged(network, caps)
            shadowOf(Looper.getMainLooper()).idle()
            assertEquals(4, wakes)
        } finally {
            monitor.stop()
        }
        assertTrue(connectivity.networkCallbacks.isEmpty())
    }

    @Test fun linksWithoutInternetCapabilityDoNotCauseRequests() {
        val context = RuntimeEnvironment.getApplication()
        val connectivity = shadowOf(context.getSystemService(ConnectivityManager::class.java))
        var wakes = 0
        val monitor = BootstrapNetworkMonitor(context) { wakes++ }
        monitor.start()
        try {
            val network = ShadowNetwork.newInstance(45)
            connectivity.networkCallbacks.single().onCapabilitiesChanged(network, NetworkCapabilities())
            shadowOf(Looper.getMainLooper()).idle()
            assertEquals(0, wakes)
        } finally {
            monitor.stop()
        }
    }

    @Test fun failedRegistrationDoesNotPreventTheNextForegroundAttempt() {
        val context = RuntimeEnvironment.getApplication()
        val connectivity = shadowOf(context.getSystemService(ConnectivityManager::class.java)) as BootstrapConnectivityShadow
        val monitor = BootstrapNetworkMonitor(context) {}
        connectivity.rejectRegistration = true
        monitor.start()
        assertTrue(connectivity.networkCallbacks.isEmpty())
        connectivity.rejectRegistration = false
        monitor.start()
        assertEquals(1, connectivity.networkCallbacks.size)
        monitor.stop()
        assertTrue(connectivity.networkCallbacks.isEmpty())
    }
}

@Implements(ConnectivityManager::class)
class BootstrapConnectivityShadow : ShadowConnectivityManager() {
    var request: NetworkRequest? = null
    var rejectRegistration = false
    @Implementation
    override fun registerNetworkCallback(request: NetworkRequest, callback: ConnectivityManager.NetworkCallback) {
        if (rejectRegistration) throw SecurityException("test denied")
        this.request = request
        super.registerNetworkCallback(request, callback)
    }
}
