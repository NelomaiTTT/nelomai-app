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

    @Test
    fun foregroundServiceDispatchKeepsItsStableAndroidSourceCode() {
        assertEquals(
            "android_service_dispatch_unavailable",
            androidServiceDispatchErrorCode(),
        )
    }

    @Test
    fun userStopProtocolCarriesNoStatusDerivedGeneration() {
        val current = cancelConnectionIntentServiceRequest(generation = null)
        val exact = cancelConnectionIntentServiceRequest(generation = 17L)

        assertEquals(NelomaiVpnService.ACTION_CANCEL_CURRENT_CONNECTION_INTENT, current.action)
        assertEquals(null, current.generation)
        assertEquals(NelomaiVpnService.ACTION_CANCEL_CONNECTION_INTENT, exact.action)
        assertEquals(17L, exact.generation)
    }

}
