package ru.nelomai.runtime.v1

import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import org.json.JSONObject

/** Common JNI callback boundary; failures must never depend on exception prose. */
object RuntimeNativeBackgroundReplyV1 {
    private const val MAX_REPLY_BYTES = 65536
    private val refusals = setOf("invalid_background_token", "invalid_background_recovery", "activation_not_applied",
        "background_recovery_unsupported", "background_owner_scope_mismatch", "background_credential_unavailable", "app_access_unavailable")
    fun await(call: (RuntimeNativeResultV1) -> Unit): String {
        val completed = CompletableFuture<String>()
        call(object : RuntimeNativeResultV1 {
            override fun success(value: String) {
                try {
                    require(value.toByteArray().size <= MAX_REPLY_BYTES)
                    val payload = if (value == "null") JSONObject.NULL else JSONObject(value)
                    val reply = JSONObject().put("format", 1).put("outcome", "success").put("value", payload).toString()
                    require(reply.toByteArray().size <= MAX_REPLY_BYTES)
                    completed.complete(reply)
                } catch (_: Exception) { completed.completeExceptionally(IllegalStateException("native_outcome_unknown")) }
            }
            override fun failure(code: String) {
                completed.complete(JSONObject().put("format", 1).put("outcome", "failure")
                    .put("code", if (code in refusals) code else "native_outcome_unknown").toString())
            }
        })
        return completed.get(10, TimeUnit.SECONDS)
    }
}
