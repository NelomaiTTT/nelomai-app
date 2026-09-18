package ru.nelomai.tunnel
import org.junit.Assert.assertEquals
import org.junit.Test
class NativeBackgroundProvisionPolicyTest {
    @Test fun freshTokenRefreshesChangedCapabilityAndPendingAlwaysResumesTwoPhase() {
        assertEquals("rotate", NativeBackgroundProvisionPolicy.mode(true, true, false, true, true, true, false, false))
        assertEquals("noop", NativeBackgroundProvisionPolicy.mode(true, true, false, true, true, true, true, false))
        assertEquals("two_phase", NativeBackgroundProvisionPolicy.mode(false, false, true, false, false, false, false, false))
        assertEquals("two_phase", NativeBackgroundProvisionPolicy.mode(true, true, false, true, false, true, false, false))
        assertEquals("legacy", NativeBackgroundProvisionPolicy.mode(false, false, false, false, false, false, false, false))
    }
}
