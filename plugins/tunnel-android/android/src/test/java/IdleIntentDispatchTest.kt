package ru.nelomai.tunnel

import android.provider.Settings
import java.io.File
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE)
class IdleIntentDispatchTest {
    @Test fun readerDoesNotRemoveAConcurrentStagingFile() {
        val context = RuntimeEnvironment.getApplication()
        Settings.Global.putInt(context.contentResolver, Settings.Global.BOOT_COUNT, 7)
        val projection = IdleConnectionIntentProjection.open(context)
        projection.publish(AndroidRecoveryEnvelope.empty(7))
        val staged = File(AndroidRuntimeNamespace.directory(context), "idle-intent-projection.json.new")
        staged.writeText("uncommitted")
        try {
            assertNotNull(projection.read())
            assertEquals("uncommitted", staged.readText())
        } finally { staged.delete() }
    }

    @Test fun idleUiPollsDoNotStartServiceButInvalidationRestoresLiveRequest() {
        val context = RuntimeEnvironment.getApplication()
        Settings.Global.putInt(context.contentResolver, Settings.Global.BOOT_COUNT, 7)
        val projection = IdleConnectionIntentProjection.open(context)
        projection.publish(AndroidRecoveryEnvelope.empty(7))
        var callbacks = 0
        repeat(100) {
            TunnelServiceClient.connectionIntentStatus(context, { status ->
                callbacks++
                assertFalse(status.desiredActive)
                assertEquals("none", status.status)
            }, { fail(it) })
        }
        assertEquals(100, callbacks)
        assertNull(shadowOf(context).nextStartedService)
        assertTrue(projection.invalidate())
        TunnelServiceClient.connectionIntentStatus(context, { fail("must query service") }, {})
        assertEquals(NelomaiVpnService.ACTION_CONNECTION_INTENT_STATUS,
            shadowOf(context).nextStartedService.action)
    }
}
