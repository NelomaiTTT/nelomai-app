package ru.nelomai.tunnel

internal enum class ConnectionIntentDecision(val wireName: String) {
    RETRY_SAME_OPERATION("retry_same_operation"),
    RETRY_NEW_OPERATION("retry_new_operation"),
    RECONCILE_THEN_RETRY("reconcile_then_retry"),
    RETRY_ONCE("retry_once"),
    RETRY_AFTER("retry_after"),
    LOCAL_RESTART("local_restart"),
    RECONCILE_ONCE("reconcile_once"),
    TERMINAL("terminal"),
}

internal class ConnectionIntentErrorPolicy {
    fun classify(
        code: String,
        serviceRecoveryUsed: Boolean = false,
        profileRetryUsed: Boolean = false,
        reconcileOnceUsed: Boolean = false,
    ): ConnectionIntentDecision {
        val decision = DECISIONS[code] ?: ConnectionIntentDecision.TERMINAL
        return when {
            decision == ConnectionIntentDecision.RECONCILE_ONCE && reconcileOnceUsed ->
                ConnectionIntentDecision.TERMINAL
            decision != ConnectionIntentDecision.RETRY_ONCE -> decision
            code == "service_unavailable" && serviceRecoveryUsed ->
                ConnectionIntentDecision.TERMINAL
            code in PROFILE_MISMATCH_CODES && profileRetryUsed ->
                ConnectionIntentDecision.TERMINAL
            else -> decision
        }
    }

    fun retryAfterSeconds(header: String?): Long = header
        ?.trim()
        ?.toLongOrNull()
        ?.takeIf { it in MINIMUM_RETRY_AFTER_SECONDS..MAXIMUM_RETRY_AFTER_SECONDS }
        ?: FALLBACK_RETRY_AFTER_SECONDS

    private companion object {
        const val MINIMUM_RETRY_AFTER_SECONDS = 1L
        const val MAXIMUM_RETRY_AFTER_SECONDS = 900L
        const val FALLBACK_RETRY_AFTER_SECONDS = 300L

        val PROFILE_MISMATCH_CODES = setOf(
            "amneziawg_profile_mismatch",
            "awg3_profile_apply_failed",
            "awg3_profile_transform_mismatch",
        )

        val DECISIONS = buildMap {
            listOf(
                "transport_error",
                "background_transport_unavailable",
                "http_5xx",
                "connection_unavailable",
                "candidate_unavailable",
                "configuration_fetch_failed",
                "binding_sync_failed",
                "connection_release_pending",
                "connection_release_failed",
                "connection_stop_failed",
                "probe_results_required",
                "saved_connection_unavailable",
                "saved_stray_unavailable",
                "connection_stall_verification_unavailable",
                "endpoint_route_lost",
                "endpoint_route_unavailable",
                "physical_network_monitor_unavailable",
                "physical_egress_unavailable",
                "local_networks_unavailable",
            ).forEach { put(it, ConnectionIntentDecision.RETRY_SAME_OPERATION) }
            listOf(
                "connection_no_longer_active",
                "tunnel_handshake_timeout",
            ).forEach { put(it, ConnectionIntentDecision.RETRY_NEW_OPERATION) }
            listOf(
                "connection_already_active",
                "service_timeout",
                "tunnel_service_timeout",
                "service_stopping",
                "android_service_dispatch_unavailable",
            ).forEach { put(it, ConnectionIntentDecision.RECONCILE_THEN_RETRY) }
            listOf(
                "service_unavailable",
                "amneziawg_profile_mismatch",
                "awg3_profile_apply_failed",
                "awg3_profile_transform_mismatch",
            ).forEach { put(it, ConnectionIntentDecision.RETRY_ONCE) }
            listOf(
                "connection_stall_recycle_rate_limited",
                "operation_in_progress",
                "device_operation_busy",
            ).forEach { put(it, ConnectionIntentDecision.RETRY_AFTER) }
            listOf("udp_rebind_failed", "udp_rebind_timeout").forEach {
                put(it, ConnectionIntentDecision.LOCAL_RESTART)
            }
            put("connection_stall_not_recyclable", ConnectionIntentDecision.RECONCILE_ONCE)
        }
    }
}
