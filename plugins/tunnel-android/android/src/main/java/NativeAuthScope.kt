package ru.nelomai.tunnel

import org.json.JSONObject
import java.util.UUID

/** Owner-issued provenance, stored inside the existing protected envelope. */
internal data class NativeOwnerScope(
    val authEpoch: Long,
    val family: String,
    val deviceId: String,
    val slot: String,
    val containerVersion: String,
    val runtimeVersion: String,
    val runtimeContractVersion: Long,
    val sessionGeneration: Long,
) {
    init {
        require(authEpoch >= 0 && family.isNotBlank() && family.length <= 128)
        require(UUID.fromString(deviceId).toString() == deviceId)
        require(slot == "stable" || slot == "latest")
        require(runtimeContractVersion > 0 && sessionGeneration > 0)
        for (version in listOf(containerVersion, runtimeVersion)) {
            require(version.length in 1..128 && version.all { it.isLetterOrDigit() || it in ".-+_" })
        }
    }

    fun identityHeaders(): Map<String, String> = mapOf(
        "X-Nelomai-App-Version" to containerVersion,
        "X-Nelomai-Container-Version" to containerVersion,
        "X-Nelomai-Runtime-Version" to runtimeVersion,
        "X-Nelomai-Runtime-Contract-Version" to runtimeContractVersion.toString(),
        "X-Nelomai-Runtime-Slot" to slot,
        "X-Nelomai-Session-Generation" to sessionGeneration.toString(),
    )

    fun toJson(): JSONObject = JSONObject().apply {
        put("auth_epoch", authEpoch); put("family", family); put("device_id", deviceId)
        put("identity", JSONObject().apply {
            put("slot", slot); put("container_version", containerVersion)
            put("runtime_version", runtimeVersion); put("runtime_contract_version", runtimeContractVersion)
            put("session_generation", sessionGeneration)
        })
    }

    companion object {
        fun fromJson(value: JSONObject): NativeOwnerScope {
            val identity = value.getJSONObject("identity")
            return NativeOwnerScope(
                value.getLong("auth_epoch"), value.getString("family"), value.getString("device_id"),
                identity.getString("slot"), identity.getString("container_version"),
                identity.getString("runtime_version"), identity.getLong("runtime_contract_version"),
                identity.getLong("session_generation"),
            )
        }
    }
}

internal data class NativeOwnerOperation(
    val scope: NativeOwnerScope,
    val operationId: String,
    val attempt: Long,
    val expiresAtUnixMs: Long,
) {
    init {
        require(UUID.fromString(operationId).toString() == operationId && attempt > 0)
        require(expiresAtUnixMs > 0)
    }

    fun toJson(): JSONObject = JSONObject().apply {
        put("ticket", scope.toJson().apply { put("operation_id", operationId); put("attempt", attempt) })
        put("expires_at_unix_ms", expiresAtUnixMs)
    }

    companion object {
        fun fromJson(value: JSONObject): NativeOwnerOperation {
            val ticket = value.getJSONObject("ticket")
            return NativeOwnerOperation(NativeOwnerScope.fromJson(ticket), ticket.getString("operation_id"),
                ticket.getLong("attempt"), value.getLong("expires_at_unix_ms"))
        }
    }
}
