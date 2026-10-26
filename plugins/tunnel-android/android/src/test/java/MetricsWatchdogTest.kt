package ru.nelomai.tunnel

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.util.ReflectionHelpers

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE)
class MetricsWatchdogTest {
    @Test fun stoppedMetricsCompletesWatchdogBeforeErrorCallback() {
        ReflectionHelpers.setField(TunnelRuntime, "applicationContext", RuntimeEnvironment.getApplication())
        val gates = ReflectionHelpers.getField<TunnelOperationWatchdogGates>(TunnelRuntime, "watchdogGates")
        val done = CountDownLatch(1)
        var stillArmed: Boolean? = null
        var code: String? = null
        TunnelRuntime.metrics(TUNNEL_API_VERSION, false,
            { _, _, _, _ -> done.countDown() },
            { error ->
                code = error
                // Expire deterministically at the callback boundary. This also
                // disarms the real timer when exercising the unfixed code.
                val metricGate = ReflectionHelpers.getField<TunnelOperationWatchdogGate>(gates, "metrics")
                val generation = ReflectionHelpers.getField<AtomicLong>(metricGate, "nextGeneration").get()
                stillArmed = gates.expire(TunnelOperationWatchdogToken(TunnelOperationWatchdogScope.METRICS, generation))
                done.countDown()
            })
        assertTrue(done.await(5, TimeUnit.SECONDS))
        assertEquals("tunnel_not_running", code)
        assertEquals("callback must run outside the process-killing watchdog", false, stillArmed)
    }
}
