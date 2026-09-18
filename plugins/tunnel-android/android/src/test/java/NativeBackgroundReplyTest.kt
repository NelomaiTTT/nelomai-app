package ru.nelomai.tunnel

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import ru.nelomai.runtime.v1.RuntimeNativeBackgroundReplyV1

class NativeBackgroundReplyTest {
    @Test fun refusalsCrossTheActualCallbackWithoutBecomingExceptions() {
        for (code in listOf("invalid_background_token", "invalid_background_recovery", "activation_not_applied",
            "background_recovery_unsupported", "background_owner_scope_mismatch", "background_credential_unavailable", "background_recovery_not_issued", "app_access_unavailable")) {
            val reply = JSONObject(RuntimeNativeBackgroundReplyV1.await { it.failure(code) })
            assertEquals(1, reply.getInt("format"))
            assertEquals("failure", reply.getString("outcome"))
            assertEquals(code, reply.getString("code"))
        }
    }
    @Test fun unknownErrorsAreBoundedAndSuccessRemainsStructured() {
        val unknown = JSONObject(RuntimeNativeBackgroundReplyV1.await { it.failure("private prose ".repeat(10000)) })
        assertEquals("native_outcome_unknown", unknown.getString("code"))
        val success = JSONObject(RuntimeNativeBackgroundReplyV1.await { it.success("null") })
        assertEquals("success", success.getString("outcome"))
        assertTrue(success.isNull("value"))
    }
}
