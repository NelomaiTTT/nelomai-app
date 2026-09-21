package ru.nelomai.tunnel

import android.app.job.JobParameters
import android.content.ComponentName
import android.net.VpnService
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.util.ReflectionHelpers
import ru.nelomai.runtime.v1.RuntimeServiceIntents
import ru.nelomai.runtime.v1.RuntimeVpnHostV1

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE)
class RuntimeV2DispatchTest {
    @Test fun redundantStandbyCleanupTargetsRuntimeDispatcher() {
        val context = RuntimeEnvironment.getApplication()

        TunnelServiceClient.releaseRedundantStandby(context, {}, {})

        val intent = shadowOf(context).nextStartedService
        assertEquals(
            ComponentName(context.packageName, RuntimeServiceIntents.VPN_COMPONENT),
            intent.component,
        )
        assertEquals(NelomaiVpnService.ACTION_RELEASE_REDUNDANT_STANDBY, intent.action)
        // Preference/cleanup dispatch does not establish VPN and must not require
        // foreground VPN admission while the tunnel is stopped.
        assertFalse(intent.getBooleanExtra(RuntimeServiceIntents.EXTRA_FOREGROUND_START, false))
    }

    @Test fun taskRemovalLivenessTargetsRuntimeDispatcher() {
        val context = RuntimeEnvironment.getApplication()
        val controller = Robolectric.buildService(VpnTaskRemovalLivenessJobService::class.java).create()
        try {
            controller.get().onStartJob(ReflectionHelpers.newInstance(JobParameters::class.java))

            val intent = shadowOf(context).nextStartedService
            assertEquals(
                ComponentName(context.packageName, RuntimeServiceIntents.VPN_COMPONENT),
                intent.component,
            )
            assertEquals(NelomaiVpnService.ACTION_TASK_REMOVAL_LIVENESS, intent.action)
            assertTrue(intent.getBooleanExtra(RuntimeServiceIntents.EXTRA_FOREGROUND_START, false))
        } finally {
            controller.destroy()
        }
    }

    @Test fun redundantStandbyCleanupBypassesStartAdmission() {
        val controller = Robolectric.buildService(VpnService::class.java).create()
        val host = controller.get()
        val engine = LatestRuntimeVpnEngineV1(object : RuntimeVpnHostV1 {
            override val service = host
            override fun builder(beforeEstablish: (VpnService.Builder) -> Unit) = host.Builder()
        })
        try {
            assertFalse(
                engine.requiresStartAdmission(
                    RuntimeServiceIntents.vpn(host)
                        .setAction(NelomaiVpnService.ACTION_RELEASE_REDUNDANT_STANDBY),
                ),
            )
        } finally {
            controller.destroy()
        }
    }
}
