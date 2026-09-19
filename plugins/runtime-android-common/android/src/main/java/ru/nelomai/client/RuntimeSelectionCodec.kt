package ru.nelomai.client

import org.json.JSONObject

object RuntimeSelectionCodec {
    fun decode(value: String): RuntimeSelectionV1 {
        require(value.toByteArray().size <= 65536)
        val json = JSONObject(value)
        val target = json.optJSONObject("target") ?: json
        return RuntimeSelectionV1(target.optString("runtime_slot", target.optString("slot")), target.getString("runtime_version"),
            target.getString("container_version"), if (json.isNull("session_generation")) null else json.getLong("session_generation"),
            if (json.isNull("pending_slot")) null else json.getString("pending_slot"), json.getString("incarnation"))
    }
}
