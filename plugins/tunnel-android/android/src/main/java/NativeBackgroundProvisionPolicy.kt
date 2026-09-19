package ru.nelomai.tunnel
internal object NativeBackgroundProvisionPolicy {
    fun mode(configured: Boolean, ready: Boolean, pending: Boolean, sameDevice: Boolean,
        freshToken: Boolean, storedCapabilityAvailable: Boolean, capabilityMatches: Boolean,
        desiredEnabled: Boolean): String = when {
        pending -> "two_phase"
        configured && ready && sameDevice && freshToken && capabilityMatches -> "noop"
        configured && ready && sameDevice && freshToken -> "rotate"
        desiredEnabled || storedCapabilityAvailable -> "two_phase"
        else -> "legacy"
    }
}
