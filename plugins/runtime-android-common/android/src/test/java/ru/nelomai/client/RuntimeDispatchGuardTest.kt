package ru.nelomai.client

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RuntimeDispatchGuardTest {
    @Test fun leasesProtectRecycleAndReleaseExactlyOnce() {
        val first = RuntimeDispatchGuard.begin()
        val second = RuntimeDispatchGuard.begin()
        assertTrue(RuntimeDispatchGuard.hasPending())

        first.close()
        first.close()
        assertTrue(RuntimeDispatchGuard.hasPending())

        second.close()
        assertFalse(RuntimeDispatchGuard.hasPending())
    }

}
