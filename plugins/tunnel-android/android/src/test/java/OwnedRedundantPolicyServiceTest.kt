package ru.nelomai.tunnel

import android.net.VpnService
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.util.ReflectionHelpers
import ru.nelomai.runtime.v1.RuntimeVpnHostV1
import java.util.concurrent.Executor
import java.util.concurrent.ExecutorService

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE)
class OwnedRedundantPolicyServiceTest {
    @Test fun queuedOldPolicyCallbackUsesNewOptionsOfTheSameRealOwner() {
        val host = Robolectric.buildService(VpnService::class.java).create()
        val service = NelomaiVpnService(object : RuntimeVpnHostV1 {
            override val service = host.get()
            override fun builder(beforeEstablish: (VpnService.Builder) -> Unit) = service.Builder().also(beforeEstablish)
        })
        val f = OwnedRedundantPolicyTest.Fixture()
        val jobs = mutableListOf<Runnable>()
        try {
            ReflectionHelpers.setField(service, "recoveryStore", f.store)
            ReflectionHelpers.setField(service, "redundantWork", RedundantVpnWorkDispatcher(Executor { jobs += it }))
            val ownerSlot = ReflectionHelpers.getField<RedundantVpnOwnerSlot>(service, "redundantVpnOwnerSlot")
            ownerSlot.install(f.coordinator, "operation")
            val generation = ReflectionHelpers.getField<Long>(service, "serviceGeneration")
            val identity = RedundantPhysicalNetworkCallbackIdentity(generation, "operation", f.coordinator)
            val old = AndroidSplitTunnel.resolveOptions(34, AndroidTunnelOptions(splitActive = true,
                excludeLocalNetworks = true, splitTunnelRoutes = listOf("192.0.2.0/24")).toTunnelOptionsArgs())
            val new = AndroidSplitTunnel.resolveOptions(34, AndroidTunnelOptions(splitActive = true,
                excludeLocalNetworks = true, splitTunnelRoutes = listOf("198.51.100.0/24")).toTunnelOptionsArgs())
            val state = PhysicalNetworkState(emptyList(), emptyList(), false, "physical")
            // Callback was captured before Save; owner/start/service identities stay identical.
            val queuedCallback = {
                ReflectionHelpers.callInstanceMethod<Unit>(service, "applyRedundantPhysicalNetworks",
                    ReflectionHelpers.ClassParameter.from(RedundantPhysicalNetworkCallbackIdentity::class.java, identity),
                    ReflectionHelpers.ClassParameter.from(EffectiveAndroidTunnelOptions::class.java, old),
                    ReflectionHelpers.ClassParameter.from(RedundantConnectionCoordinator::class.java, f.coordinator),
                    ReflectionHelpers.ClassParameter.from(PhysicalNetworkState::class.java, state))
            }
            ownerSlot.updateRouteBaseline(f.coordinator, redundantVpnRouteBaseline(new, emptyList()), new)
            val before = f.store.read()
            val result = runCatching(queuedCallback)
            assertEquals(before, f.store.read())
            assertTrue("old callback forced recovery: ${result.exceptionOrNull()}", result.isSuccess)
            assertTrue(f.coordinator.isRunning())
            assertEquals(0, f.panelCalls)
            assertEquals(1, jobs.size) // current network notification, no recovery/start/stop work
        } finally {
            f.native.closeForStop()
            ReflectionHelpers.getField<ExecutorService>(service, "redundantExecutor").shutdownNow()
            ReflectionHelpers.getField<ExecutorService>(service, "credentialExecutor").shutdownNow()
            host.destroy()
        }
    }
}
