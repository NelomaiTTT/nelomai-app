package ru.nelomai.tunnel

import android.content.Context
import org.json.JSONObject
import ru.nelomai.runtime.v1.RuntimeNativeBridgeV1
import ru.nelomai.runtime.v1.RuntimeNativeResultV1
import java.time.Instant

/** Owner-only bridge to the existing protected background credential owner. */
class LatestRuntimeNativeBridgeV1 : RuntimeNativeBridgeV1 {
    override fun prepareRevocation(context: Context, epoch: Long, result: RuntimeNativeResultV1) {
        TunnelServiceClient.beginBackgroundLogout(context, epoch,
            { result.success(JSONObject().put("ownership", it.wireName).toString()) }, result::failure)
    }
    override fun stop(context: Context, result: RuntimeNativeResultV1) {
        TunnelServiceClient.stop(context, TUNNEL_API_VERSION,
            { state, _ -> if (state == SessionState.STOPPED) result.success("{}") else result.failure("native_stop_incomplete") }, result::failure)
    }
    override fun background(context: Context, action: String, request: String, result: RuntimeNativeResultV1) {
        require(request.toByteArray().size <= 65536)
        val input = JSONObject(request)
        if (action == "recover") {
            TunnelServiceClient.recoverBackgroundSession(context, input.getString("install_secret"),
                input.getString("owner_operation"), result::success, result::failure)
            return
        }
        require(action == "status" || action == "provision")
        TunnelServiceClient.backgroundCredentialStatus(context,
            { configured, revision, ready, pending, capability, enabled, expiry, device, tokenExpiry ->
                if (action == "status") result.success("null") else {
                    val desired = input.getJSONObject("capability")
                    val now = Instant.now().epochSecond
                    val desiredEnabled = desired.getBoolean("enabled")
                    val matches = capability == desired.getLong("revision") && enabled == desiredEnabled &&
                        (!enabled || (expiry == desired.getLong("expires_at_unix") && expiry > now))
                    val args = BackgroundUiProvisionArgs().apply {
                        apiVersion = TUNNEL_API_VERSION
                        ownerOperation = input.getString("owner_operation")
                        mode = NativeBackgroundProvisionPolicy.mode(configured, ready, pending,
                            device == input.getString("device_id"), tokenExpiry != null && tokenExpiry > now + 7L * 24 * 60 * 60,
                            enabled && expiry != null && expiry > now, matches, desiredEnabled)
                        expectedRevision = revision
                        deviceId = input.getString("device_id")
                        panelBase = "https://nelomai.ru"
                        accessToken = input.getString("access_token")
                        installSecret = input.getString("install_secret")
                        capabilityRevision = desired.getLong("revision")
                        capabilityEnabled = desiredEnabled
                        capabilityExpiresAt = desired.getString("expires_at")
                    }
                    TunnelServiceClient.provisionBackground(context, args, { result.success("null") }, result::failure)
                }
            }, result::failure)
    }
}
