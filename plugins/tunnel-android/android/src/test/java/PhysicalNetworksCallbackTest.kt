package ru.nelomai.tunnel

import android.net.ConnectivityManager
import android.net.LinkAddress
import android.net.LinkProperties
import android.net.NetworkCapabilities
import android.net.NetworkInfo
import android.net.IpPrefix
import android.net.RouteInfo
import android.os.Looper
import java.net.InetAddress
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowNetwork
import org.robolectric.shadows.ShadowNetworkInfo
import org.robolectric.util.ReflectionHelpers
import org.robolectric.util.ReflectionHelpers.ClassParameter.from

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE)
class PhysicalNetworksCallbackTest {
    @Test fun initialSnapshotDoesNotRebindHealthyPrimaryButRealChangesStillDo() {
        val context = RuntimeEnvironment.getApplication()
        val shadow = shadowOf(context.getSystemService(ConnectivityManager::class.java))
        shadow.clearAllNetworks()
        val network = ShadowNetwork.newInstance(253)
        shadow.addNetwork(network, ShadowNetworkInfo.newInstance(
            NetworkInfo.DetailedState.CONNECTED, ConnectivityManager.TYPE_MOBILE, 0, true, true))
        val caps = NetworkCapabilities()
        shadowOf(caps).addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
        shadowOf(caps).addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        shadowOf(caps).addCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        shadow.setNetworkCapabilities(network, caps)
        shadow.setLinkProperties(network, LinkProperties().also { it.interfaceName = "rmnet_data0" })
        val monitor = PhysicalNetworks(context)
        val baseline = monitor.snapshotState()
        val health = RedundantHealthMonitor()
        val working = SlotObservation(index = 0, active = true, health = BackendHealth.WARMING,
            handshakeFresh = true, consecutiveProbeSuccesses = 1)
        val updates = mutableListOf<PhysicalNetworkState>()
        fun flush() = shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(301))
        try {
            monitor.start(initialState = baseline) {
                updates += it
                health.onUnderlyingNetworkChanged(1_000L, it.validated)
            }
            flush()
            assertEquals("initial network is already applied by the VPN owner", 0, updates.size)
            assertTrue("ready primary must not wait for a synthetic rebind", health.primaryReady(1_301L, working))
            val callback = shadow.networkCallbacks.single()
            shadowOf(caps).removeCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            callback.onCapabilitiesChanged(network, caps)
            flush()
            assertEquals(1, updates.size)
            assertEquals(false, health.primaryReady(1_301L, working))
            shadowOf(caps).addCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            callback.onCapabilitiesChanged(network, caps)
            flush()
            assertEquals(2, updates.size)
            assertEquals(false, health.primaryReady(4_999L, working))
            assertTrue(health.primaryReady(5_000L, working))
        } finally {
            monitor.stop()
        }
    }

    @Test fun networkLostBetweenSnapshotAndRegistrationIsNotSuppressed() {
        val context = RuntimeEnvironment.getApplication()
        val shadow = shadowOf(context.getSystemService(ConnectivityManager::class.java))
        shadow.clearAllNetworks()
        val monitor = PhysicalNetworks(context)
        val baseline = monitor.snapshotState().copy(validated = true, fingerprint = "previous-network")
        val updates = mutableListOf<PhysicalNetworkState>()
        try {
            monitor.start(initialState = baseline) { updates += it }
            shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(301))
            assertEquals(1, updates.size)
            assertEquals(false, updates.single().available)
            assertEquals(false, updates.single().validated)
        } finally {
            monitor.stop()
        }
    }

    @Test fun listenerDoesNotHoldMonitorLockWhileTunnelOwnerStopsMonitoring() {
        val context = RuntimeEnvironment.getApplication()
        val monitor = PhysicalNetworks(context)
        val stopped = CountDownLatch(1)
        var worker: Thread? = null
        monitor.start {
            worker = Thread {
                monitor.stop()
                stopped.countDown()
            }.also { it.start() }
            assertTrue("owner cleanup must not wait for callback's monitor lock",
                stopped.await(1, TimeUnit.SECONDS))
        }
        try {
            shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(301))
        } finally {
            worker?.join(2_000)
            monitor.stop()
        }
    }

    @Test fun repeatedMetadataDoesNotNotifyButRealLinkChangesAndRestartDo() {
        val context = RuntimeEnvironment.getApplication()
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val shadow = shadowOf(cm)
        shadow.clearAllNetworks()
        val network = ShadowNetwork.newInstance(253)
        shadow.addNetwork(network, ShadowNetworkInfo.newInstance(
            NetworkInfo.DetailedState.CONNECTED, ConnectivityManager.TYPE_MOBILE, 0, true, true))
        val caps = NetworkCapabilities()
        shadowOf(caps).addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
        shadowOf(caps).addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        shadowOf(caps).addCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        shadow.setNetworkCapabilities(network, caps)
        fun properties(address: String) = LinkProperties().also {
            it.interfaceName = "rmnet_data0"
            val linkAddress = ReflectionHelpers.callConstructor(LinkAddress::class.java,
                from(String::class.java, address))
            ReflectionHelpers.callInstanceMethod<Boolean>(it, "addLinkAddress",
                from(LinkAddress::class.java, linkAddress))
        }
        var link = properties("10.0.0.2/30")
        shadow.setLinkProperties(network, link)
        val monitor = PhysicalNetworks(context)
        val updates = mutableListOf<PhysicalNetworkState>()
        fun flush() = shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(301))
        monitor.start { updates += it }
        flush()
        assertEquals(1, updates.size)
        val callback = shadow.networkCallbacks.single()
        repeat(3) {
            shadowOf(caps).setLinkDownstreamBandwidthKbps(1000 + it)
            callback.onCapabilitiesChanged(network, caps)
            callback.onLinkPropertiesChanged(network, link)
            flush()
        }
        assertEquals("unchanged network must not reset tunnel readiness", 1, updates.size)
        // A carrier IP change on the SAME network ID must not be hidden by deduplication.
        link = properties("10.0.0.6/30")
        shadow.setLinkProperties(network, link)
        callback.onLinkPropertiesChanged(network, link)
        flush()
        assertEquals(2, updates.size)
        assertNotEquals(updates[0].fingerprint, updates[1].fingerprint)
        val destination = ReflectionHelpers.callConstructor(IpPrefix::class.java,
            from(String::class.java, "0.0.0.0/0"))
        val route = ReflectionHelpers.callConstructor(RouteInfo::class.java,
            from(IpPrefix::class.java, destination),
            from(InetAddress::class.java, InetAddress.getByName("10.0.0.5")),
            from(String::class.java, "rmnet_data0"))
        ReflectionHelpers.callInstanceMethod<Boolean>(link, "addRoute", from(RouteInfo::class.java, route))
        shadow.setLinkProperties(network, link)
        callback.onLinkPropertiesChanged(network, link)
        flush()
        assertEquals("gateway change must reach the tunnel owner", 3, updates.size)
        shadowOf(caps).removeCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        shadow.setNetworkCapabilities(network, caps)
        callback.onCapabilitiesChanged(network, caps)
        flush()
        assertEquals(4, updates.size)
        shadow.removeNetwork(network)
        callback.onLost(network)
        flush()
        assertEquals(5, updates.size)
        assertEquals(false, updates.last().available)
        monitor.stop()
        monitor.start { updates += it }
        flush()
        assertEquals("new listener must receive current snapshot", 6, updates.size)
        monitor.stop()
    }
}
