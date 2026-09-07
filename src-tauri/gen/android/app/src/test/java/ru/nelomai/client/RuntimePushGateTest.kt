package ru.nelomai.client
import java.nio.file.Files
import org.junit.Assert.*
import org.junit.Test
import ru.nelomai.runtime.v1.RuntimePushGate
class RuntimePushGateTest {
    @Test fun logoutInvalidatesInFlightPermissionTokenAndConfirmCallbacksAcrossInstances() {
        val directory = Files.createTempDirectory("push-gate-test").toFile()
        try {
            val runtime = RuntimePushGate(directory)
            val owner = RuntimePushGate(directory)
            val beforeLogout = runtime.epoch()
            assertTrue(runtime.enable(beforeLogout))
            owner.revoke(1)
            assertFalse(runtime.enable(beforeLogout))
            assertFalse(runtime.confirm(beforeLogout, "late-token"))
            assertFalse(owner.enabled())
            assertTrue(runtime.enable(runtime.epoch()))
        } finally { directory.deleteRecursively() }
    }
}
