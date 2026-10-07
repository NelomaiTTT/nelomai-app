package ru.nelomai.runtime.v1

import android.util.Log

/** Observation only: never change or reinterpret the callback passed to the owner. */
object SupportBackgroundDiagnostics {
    private val actions = setOf("provision", "recover", "status")
    private val codes = setOf(
        "background_owner_cancelled", "background_owner_scope_mismatch",
        "invalid_background_token", "invalid_background_recovery", "activation_not_applied",
        "background_recovery_unsupported", "background_recovery_not_issued",
        "background_credential_unavailable", "background_credential_logout_pending",
        "background_credential_mutation_in_progress", "background_credential_mutation_conflict",
        "background_credential_generation_conflict", "background_credential_capability_unavailable",
        "background_credential_device_mismatch", "background_credential_activation_pending",
        "background_credential_pending_absent", "background_credential_logout_absent",
        "app_access_unavailable", "native_outcome_unknown",
    )

    fun recordFailure(action: String, code: String) {
        if (action !in actions) return
        val safeCode = code.takeIf { it in codes } ?: "native_failure_unclassified"
        Log.w("NelomaiOwner", "background.$action.failed code=$safeCode")
    }
}
