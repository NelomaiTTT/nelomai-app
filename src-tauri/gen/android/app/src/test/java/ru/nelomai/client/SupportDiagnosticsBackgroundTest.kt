package ru.nelomai.client

import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowLog
import ru.nelomai.runtime.v1.SupportBackgroundDiagnostics

@RunWith(org.robolectric.RobolectricTestRunner::class)
@Config(sdk = [28])
class SupportDiagnosticsBackgroundTest {
    @Test fun nativeOwnerFailureKeepsRecoverAndProvisionCancellationDistinct() {
        SupportBackgroundDiagnostics.recordFailure("recover", "background_owner_cancelled")
        SupportBackgroundDiagnostics.recordFailure("provision", "background_owner_scope_mismatch")
        val messages = ShadowLog.getLogsForTag("NelomaiOwner").map { it.msg }
        assertTrue(messages.contains("background.recover.failed code=background_owner_cancelled"))
        assertTrue(messages.contains("background.provision.failed code=background_owner_scope_mismatch"))
    }

    @Test fun unknownCallbackCodesAndActionsCannotBecomeDiagnosticSecrets() {
        SupportBackgroundDiagnostics.recordFailure("recover", "secret_that_looks_like_a_code")
        SupportBackgroundDiagnostics.recordFailure("password_secret", "background_owner_cancelled")
        val messages = ShadowLog.getLogsForTag("NelomaiOwner").map { it.msg }
        assertTrue(messages.contains("background.recover.failed code=native_failure_unclassified"))
        assertFalse(messages.any { it.contains("secret") })
    }
}
