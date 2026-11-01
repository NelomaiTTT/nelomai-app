package ru.nelomai.client

import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.content.ServiceConnection
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE)
class RuntimeSelectionBindingTest {
    @Test fun ownerBindingTracksFreezerDependencyUntilClose() {
        var boundFlags = 0
        var boundConnection: ServiceConnection? = null
        var unbinds = 0
        val context = object : ContextWrapper(RuntimeEnvironment.getApplication()) {
            override fun bindService(intent: Intent, connection: ServiceConnection, flags: Int): Boolean {
                assertEquals("ru.nelomai.client.RuntimeAuthBrokerService", intent.component?.className)
                boundFlags = flags
                boundConnection = connection
                return true
            }
            override fun unbindService(connection: ServiceConnection) {
                assertSame(boundConnection, connection)
                unbinds++
            }
        }
        var completed: Result<RuntimeSelectionV1>? = null
        val selection = RuntimeSelectionStore(context)
        selection.read { completed = it }
        assertTrue(boundFlags and Context.BIND_AUTO_CREATE != 0)
        // Android otherwise permits a previously visible owner to become cached
        // while its runtime is still in the previous-activity state. This flag
        // preserves the platform's explicit shouldNotFreeze dependency.
        assertTrue("Owner must not freeze ahead of its noncached runtime",
            boundFlags and Context.BIND_ALLOW_OOM_MANAGEMENT != 0)
        assertNull(completed)
        selection.close()
        assertTrue(requireNotNull(completed).isFailure)
        selection.close()
        assertEquals(1, unbinds)
    }
}
