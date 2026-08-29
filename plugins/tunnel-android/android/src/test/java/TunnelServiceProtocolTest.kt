package ru.nelomai.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TunnelServiceProtocolTest {
    @Test
    fun serviceRequestCompletionIgnoresLateRepliesAfterTimeout() {
        val completion = ServiceRequestCompletion()
        var callbacks = 0

        assertTrue(completion.finish { callbacks += 1 })
        assertFalse(completion.finish { callbacks += 1 })

        assertEquals(1, callbacks)
    }

    @Test
    fun credentialMutationTimeoutOutlivesThreeWorstCaseNetworkSteps() {
        assertTrue(backgroundCredentialMutationTimeoutMillis() > 90_000L)
    }
}
