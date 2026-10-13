package ru.nelomai.tunnel

import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE)
class AsyncStopTransportTest {
    @Test fun negotiatedCapabilitySurvivesServiceBundleAndOldBundleDefaultsFalse() {
        val args = RedundantStartArgs().apply {
            asyncStopV1 = true
            warmStopV1 = true
            sessionId = "22222222-2222-4222-8222-222222222222"
            state = "degraded"
            operationId = "44444444-4444-4444-8444-444444444444"
            requestFingerprint = "a".repeat(64)
            virtualAddressV4 = "10.87.0.2/32"
            activeLeaseId = "33333333-3333-4333-8333-333333333333"
            localActiveLeaseId = activeLeaseId
            primary = RedundantMemberArgs().apply { slot = "A"; leaseId = activeLeaseId }
        }
        val bundle = args.toBundle()
        assertTrue(bundle.toRedundantStart().asyncStopV1)
        bundle.remove("async_stop_v1")
        assertFalse(bundle.toRedundantStart().asyncStopV1)
        assertTrue(bundle.toRedundantStart().warmStopV1)
    }
}
