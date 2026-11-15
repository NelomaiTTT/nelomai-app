package ru.nelomai.client

/** Process-local load fence only, never an authoritative selection writer. */
object RuntimeProcessSelection {
    private var loaded: RuntimeSelectionV1? = null
    private var admitted = false
    private var vpnOwner: RuntimeSelectionV1? = null
    @Synchronized fun markAdmitted() { check(loaded != null); admitted = true }
    @Synchronized fun hasAdmission(selected: RuntimeSelectionV1): Boolean = admitted && !needsExit(selected)
    @Synchronized fun needsExit(selected: RuntimeSelectionV1): Boolean =
        loaded?.let {
            RuntimeDispatchPolicy.mustExitProcess(it, selected) &&
                vpnOwner?.let { owner -> RuntimeDispatchPolicy.mayRetainVpnOwner(owner, selected) } != true
        } ?: false

    @Synchronized fun rememberVpnOwner(selected: RuntimeSelectionV1) {
        // The dispatcher records the admitted owner before starting engine work.
        if (vpnOwner == null && selected.slot == "latest" && RuntimeDispatchPolicy.mayStartVpn(selected)) {
            vpnOwner = selected
        }
    }

    @Synchronized fun clearVpnOwner() { vpnOwner = null }
    @Synchronized fun hasVpnOwner(): Boolean = vpnOwner != null
    @Synchronized fun vpnOwnerForStop(): RuntimeSelectionV1? = vpnOwner
    @Synchronized fun sameVpnImage(selected: RuntimeSelectionV1): Boolean =
        vpnOwner?.let { RuntimeDispatchPolicy.sameVpnImage(it, selected) } == true

    @Synchronized fun mayRetainVpnOwner(selected: RuntimeSelectionV1): Boolean =
        vpnOwner?.let { RuntimeDispatchPolicy.mayRetainVpnOwner(it, selected) } ?: true

    @Synchronized fun claim(selected: RuntimeSelectionV1) {
        check(!needsExit(selected)) { "runtime_process_restart_required" }
        loaded = selected
        if (vpnOwner != null && selected.vpnAuthorization?.scope != null && mayRetainVpnOwner(selected)) {
            vpnOwner = selected
        }
    }
}
