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
            .also { selection ->
                json.optJSONObject("vpn_authorization")?.let { authorization ->
                    val scope = authorization.optString("scope", "").takeIf { value ->
                        value.length == 64 && value.all { it in '0'..'9' || it in 'a'..'f' }
                    }
                    val logoutEpoch = if (authorization.isNull("logout_epoch")) null
                    else authorization.getLong("logout_epoch").also { require(it >= 0) }
                    selection.vpnAuthorization =
                        VpnBrokerAuthorization(scope, authorization.getBoolean("blocked"), logoutEpoch)
                }
            }
    }
}
