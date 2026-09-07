package ru.nelomai.client

import ru.nelomai.runtime.v1.RuntimeQuickActionsV1
import ru.nelomai.runtime.v1.RuntimeVpnEngineV1
import ru.nelomai.runtime.v1.RuntimeVpnHostV1

/** Fixed ABI mapping, resolved only after the common owner admitted selection. */
object RuntimeAdapters {
    private fun tunnelPackage(selected: RuntimeSelectionV1): String = when (selected.slot) {
        "latest" -> "ru.nelomai.tunnel"
        "stable" -> "ru.nelomai.runtime.stable.tunnel"
        else -> throw IllegalArgumentException("runtime_slot_unavailable")
    }
    fun engine(selected: RuntimeSelectionV1, host: RuntimeVpnHostV1): RuntimeVpnEngineV1 =
        Class.forName(tunnelPackage(selected) + ".LatestRuntimeVpnEngineV1")
            .getConstructor(RuntimeVpnHostV1::class.java).newInstance(host) as RuntimeVpnEngineV1
    fun quick(selected: RuntimeSelectionV1): RuntimeQuickActionsV1 =
        Class.forName(tunnelPackage(selected) + ".LatestRuntimeQuickActionsV1")
            .getConstructor().newInstance() as RuntimeQuickActionsV1
    fun activity(selected: RuntimeSelectionV1): String = when (selected.slot) {
        "latest" -> "ru.nelomai.client.LatestRuntimeActivity"
        "stable" -> "ru.nelomai.runtime.stable.LatestRuntimeActivity"
        else -> throw IllegalArgumentException("runtime_slot_unavailable")
    }
}
