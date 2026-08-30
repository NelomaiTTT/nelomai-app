package ru.nelomai.tunnel

import java.io.File
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test

class ConnectionIntentErrorPolicyTest {
    @Test
    fun sharedFixtureHasIdenticalKotlinDecisions() {
        val fixture = JSONObject(
            File("../../../contracts/fixtures/valid/connection-intent-error-policy.json")
                .readText(),
        )
        val policy = ConnectionIntentErrorPolicy()
        val cases = fixture.getJSONArray("cases")

        for (index in 0 until cases.length()) {
            val case = cases.getJSONObject(index)
            assertEquals(
                "fixture case ${case.getString("code")}",
                case.getString("decision"),
                policy.classify(case.getString("code")).wireName,
            )
        }
        assertEquals(
            fixture.getString("unknown_decision"),
            policy.classify("future_unrecognized_error").wireName,
        )
    }

    @Test
    fun boundedRecoveryCodesBecomeTerminalAfterTheirSingleRecovery() {
        val policy = ConnectionIntentErrorPolicy()

        assertEquals(
            ConnectionIntentDecision.RETRY_ONCE,
            policy.classify("service_unavailable", serviceRecoveryUsed = false),
        )
        assertEquals(
            ConnectionIntentDecision.TERMINAL,
            policy.classify("service_unavailable", serviceRecoveryUsed = true),
        )
        assertEquals(
            ConnectionIntentDecision.RETRY_ONCE,
            policy.classify("amneziawg_profile_mismatch", profileRetryUsed = false),
        )
        assertEquals(
            ConnectionIntentDecision.TERMINAL,
            policy.classify("amneziawg_profile_mismatch", profileRetryUsed = true),
        )
        assertEquals(
            ConnectionIntentDecision.TERMINAL,
            policy.classify("operation_id_conflict"),
        )
        assertEquals(
            ConnectionIntentDecision.RETRY_SAME_OPERATION,
            policy.classify("connection_stop_failed"),
        )
    }

    @Test
    fun retryAfterUsesTheFixtureBoundsAndFallback() {
        val policy = ConnectionIntentErrorPolicy()

        assertEquals(1L, policy.retryAfterSeconds("1"))
        assertEquals(900L, policy.retryAfterSeconds("900"))
        assertEquals(300L, policy.retryAfterSeconds(null))
        assertEquals(300L, policy.retryAfterSeconds("0"))
        assertEquals(300L, policy.retryAfterSeconds("901"))
        assertEquals(300L, policy.retryAfterSeconds("not-a-number"))
    }
}
