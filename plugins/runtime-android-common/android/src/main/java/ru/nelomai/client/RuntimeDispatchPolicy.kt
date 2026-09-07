package ru.nelomai.client

/** Non-secret view returned by the Rust common owner; never persisted in Kotlin. */
data class RuntimeSelectionV1(
    val slot: String,
    val runtimeVersion: String,
    val containerVersion: String,
    val sessionGeneration: Long?,
    val pendingSlot: String?,
    val incarnation: String,
)

object RuntimeDispatchPolicy {
    private fun valid(value: RuntimeSelectionV1): Boolean =
        value.slot in setOf("latest", "stable") &&
            value.runtimeVersion.isNotBlank() && value.runtimeVersion.length <= 64 &&
            value.containerVersion.isNotBlank() && value.containerVersion.length <= 64 &&
            (value.sessionGeneration == null || value.sessionGeneration > 0) &&
            (value.pendingSlot == null || value.pendingSlot in setOf("latest", "stable")) &&
            value.incarnation.isNotBlank() && value.incarnation.length <= 128

    fun admit(active: RuntimeSelectionV1, request: RuntimeSelectionV1, callerUid: Int, ownerUid: Int): Boolean =
        callerUid == ownerUid && valid(active) && valid(request) &&
            active.slot == request.slot && active.runtimeVersion == request.runtimeVersion &&
            active.containerVersion == request.containerVersion &&
            active.sessionGeneration == request.sessionGeneration && active.incarnation == request.incarnation

    fun mayStart(active: RuntimeSelectionV1): Boolean =
        valid(active) && active.pendingSlot == null && active.sessionGeneration != null

    fun mayToggle(active: RuntimeSelectionV1, durableDesiredActive: Boolean): Boolean =
        valid(active) && (durableDesiredActive || mayStart(active))

    fun mayStop(loaded: RuntimeSelectionV1, active: RuntimeSelectionV1): Boolean =
        valid(active) && loaded.slot == active.slot && loaded.runtimeVersion == active.runtimeVersion &&
            loaded.incarnation == active.incarnation

    fun mustExitProcess(loaded: RuntimeSelectionV1, active: RuntimeSelectionV1?): Boolean =
        active == null || !valid(active) || loaded.slot != active.slot ||
            loaded.runtimeVersion != active.runtimeVersion || loaded.incarnation != active.incarnation

    fun library(active: RuntimeSelectionV1): String {
        require(valid(active)) { "Invalid verified runtime selection" }
        return when (active.slot) {
            "latest" -> "nelomai_app_lib"
            "stable" -> "nelomai_runtime_stable"
            else -> error("Unreachable runtime slot")
        }
    }
}
