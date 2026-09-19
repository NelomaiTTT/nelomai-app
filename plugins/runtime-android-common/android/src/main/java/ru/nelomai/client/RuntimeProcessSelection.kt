package ru.nelomai.client

/** Process-local load fence only, never an authoritative selection writer. */
object RuntimeProcessSelection {
    private var loaded: RuntimeSelectionV1? = null
    private var admitted = false
    @Synchronized fun markAdmitted() { check(loaded != null); admitted = true }
    @Synchronized fun hasAdmission(selected: RuntimeSelectionV1): Boolean = admitted && !needsExit(selected)
    @Synchronized fun needsExit(selected: RuntimeSelectionV1): Boolean =
        loaded?.let { RuntimeDispatchPolicy.mustExitProcess(it, selected) } ?: false
    @Synchronized fun claim(selected: RuntimeSelectionV1) {
        loaded?.let {
            check(!RuntimeDispatchPolicy.mustExitProcess(it, selected)) { "runtime_process_restart_required" }
        }
        loaded = selected
    }
}
