package ru.nelomai.tunnel

import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.ResultReceiver
import androidx.core.content.ContextCompat

internal const val SERVICE_RESULT_OK = 1
internal const val SERVICE_RESULT_ERROR = 2

internal const val EXTRA_RESULT_RECEIVER = "result_receiver"
internal const val EXTRA_API_VERSION = "api_version"
internal const val EXTRA_START_SOURCE = "start_source"
internal const val EXTRA_CONFIGURATION = "configuration"
internal const val EXTRA_OPTIONS = "options"
internal const val EXTRA_CACHE_QUICK_ACTION = "cache_quick_action"
internal const val EXTRA_QUICK_ACTION_VALID_UNTIL = "quick_action_valid_until"
internal const val EXTRA_QUICK_CONNECTION = "quick_connection"
internal const val EXTRA_PROBE = "probe"
internal const val EXTRA_STATE = "state"
internal const val EXTRA_DURATION_MILLIS = "duration_millis"
internal const val EXTRA_ERROR_CODE = "error_code"
internal const val EXTRA_RECEIVED_BYTES = "received_bytes"
internal const val EXTRA_SENT_BYTES = "sent_bytes"
internal const val EXTRA_PROBE_TARGET = "probe_target"
internal const val EXTRA_PANEL_BASE = "panel_base"
internal const val EXTRA_TOKEN = "token"
internal const val EXTRA_DEVICE_ID = "device_id"
internal const val EXTRA_EXPIRES_AT_UNIX = "expires_at_unix"
internal const val EXTRA_CONFIGURED = "configured"
internal const val EXTRA_CHANGED = "changed"
internal const val EXTRA_DNS_SERVERS = "dns_servers"

internal object TunnelServiceClient {
    fun start(
        context: Context,
        args: StartTunnelArgs,
        onSuccess: (SessionState, Long) -> Unit,
        onError: (String) -> Unit,
    ) {
        val configuration = args.configuration.copyOf()
        try {
            dispatch(
                context,
                Intent(context, NelomaiVpnService::class.java)
                    .setAction(NelomaiVpnService.ACTION_CLIENT_START)
                    .putExtra(EXTRA_API_VERSION, args.apiVersion)
                    .putExtra(EXTRA_START_SOURCE, args.startSource)
                    .putExtra(EXTRA_CONFIGURATION, configuration)
                    .putExtra(EXTRA_OPTIONS, args.options.toBundle())
                    .putExtra(EXTRA_CACHE_QUICK_ACTION, args.cacheQuickAction)
                    .putExtra(
                        EXTRA_QUICK_ACTION_VALID_UNTIL,
                        args.quickActionValidUntilUnix ?: Long.MIN_VALUE,
                    )
                    .putExtra(EXTRA_QUICK_CONNECTION, args.quickConnection?.toBundle())
                    .putExtra(
                        EXTRA_RESULT_RECEIVER,
                        operationReceiver(onSuccess, onError),
                    ),
                onError,
                foreground = true,
            )
        } finally {
            args.configuration.fill(0)
            configuration.fill(0)
        }
    }

    fun stop(
        context: Context,
        apiVersion: Int,
        onSuccess: (SessionState, Long) -> Unit,
        onError: (String) -> Unit,
    ) = dispatch(
        context,
        Intent(context, NelomaiVpnService::class.java)
            .setAction(NelomaiVpnService.ACTION_CLIENT_STOP)
            .putExtra(EXTRA_API_VERSION, apiVersion)
            .putExtra(EXTRA_RESULT_RECEIVER, operationReceiver(onSuccess, onError)),
        onError,
    )

    fun status(
        context: Context,
        apiVersion: Int,
        onSuccess: (SessionState, Long) -> Unit,
        onError: (String) -> Unit,
    ) = dispatch(
        context,
        Intent(context, NelomaiVpnService::class.java)
            .setAction(NelomaiVpnService.ACTION_CLIENT_STATUS)
            .putExtra(EXTRA_API_VERSION, apiVersion)
            .putExtra(EXTRA_RESULT_RECEIVER, operationReceiver(onSuccess, onError)),
        onError,
    )

    fun metrics(
        context: Context,
        apiVersion: Int,
        probe: Boolean,
        onSuccess: (Long, Long, String?) -> Unit,
        onError: (String) -> Unit,
    ) = dispatch(
        context,
        Intent(context, NelomaiVpnService::class.java)
            .setAction(NelomaiVpnService.ACTION_CLIENT_METRICS)
            .putExtra(EXTRA_API_VERSION, apiVersion)
            .putExtra(EXTRA_PROBE, probe)
            .putExtra(
                EXTRA_RESULT_RECEIVER,
                object : ResultReceiver(Handler(Looper.getMainLooper())) {
                    override fun onReceiveResult(resultCode: Int, resultData: Bundle?) {
                        if (resultCode == SERVICE_RESULT_OK && resultData != null) {
                            onSuccess(
                                resultData.getLong(EXTRA_RECEIVED_BYTES),
                                resultData.getLong(EXTRA_SENT_BYTES),
                                resultData.getString(EXTRA_PROBE_TARGET),
                            )
                        } else {
                            onError(resultData?.getString(EXTRA_ERROR_CODE) ?: "tunnel_backend_error")
                        }
                    }
                },
            ),
        onError,
    )

    fun configureBackground(
        context: Context,
        args: BackgroundCredentialArgs,
        onSuccess: () -> Unit,
        onError: (String) -> Unit,
    ) = requestBundle(
        context,
        Intent(context, NelomaiVpnService::class.java)
            .setAction(NelomaiVpnService.ACTION_CONFIGURE_BACKGROUND)
            .putExtra(EXTRA_API_VERSION, args.apiVersion)
            .putExtra(EXTRA_DEVICE_ID, args.deviceId)
            .putExtra(EXTRA_PANEL_BASE, args.panelBase)
            .putExtra(EXTRA_TOKEN, args.token)
            .putExtra(EXTRA_EXPIRES_AT_UNIX, args.expiresAtUnix),
        { onSuccess() },
        onError,
    )

    fun backgroundCredentialStatus(
        context: Context,
        onSuccess: (Boolean, String?, Long?) -> Unit,
        onError: (String) -> Unit,
    ) = requestBundle(
        context,
        Intent(context, NelomaiVpnService::class.java)
            .setAction(NelomaiVpnService.ACTION_BACKGROUND_STATUS),
        {
            val configured = it.getBoolean(EXTRA_CONFIGURED)
            onSuccess(
                configured,
                if (configured) it.getString(EXTRA_DEVICE_ID) else null,
                if (configured) it.getLong(EXTRA_EXPIRES_AT_UNIX) else null,
            )
        },
        onError,
    )

    fun clearBackground(
        context: Context,
        onSuccess: () -> Unit,
        onError: (String) -> Unit,
    ) = requestBundle(
        context,
        Intent(context, NelomaiVpnService::class.java)
            .setAction(NelomaiVpnService.ACTION_CLEAR_BACKGROUND),
        { onSuccess() },
        onError,
    )

    fun clearQuickPlan(
        context: Context,
        onSuccess: () -> Unit,
        onError: (String) -> Unit,
    ) = requestBundle(
        context,
        Intent(context, NelomaiVpnService::class.java)
            .setAction(NelomaiVpnService.ACTION_CLEAR_QUICK_PLAN),
        { onSuccess() },
        onError,
    )

    fun updateQuickDns(
        context: Context,
        dnsServers: ArrayList<String>,
        onSuccess: () -> Unit,
        onError: (String) -> Unit,
    ) = requestBundle(
        context,
        Intent(context, NelomaiVpnService::class.java)
            .setAction(NelomaiVpnService.ACTION_UPDATE_QUICK_DNS)
            .putStringArrayListExtra(EXTRA_DNS_SERVERS, dnsServers),
        { onSuccess() },
        onError,
    )

    fun takeQuickStateChange(
        context: Context,
        onSuccess: (Boolean) -> Unit,
        onError: (String) -> Unit,
    ) = requestBundle(
        context,
        Intent(context, NelomaiVpnService::class.java)
            .setAction(NelomaiVpnService.ACTION_TAKE_STATE_CHANGE),
        { onSuccess(it.getBoolean(EXTRA_CHANGED)) },
        onError,
    )

    fun acknowledgeQuickStateChange(
        context: Context,
        onSuccess: () -> Unit,
        onError: (String) -> Unit,
    ) = requestBundle(
        context,
        Intent(context, NelomaiVpnService::class.java)
            .setAction(NelomaiVpnService.ACTION_ACKNOWLEDGE_STATE_CHANGE),
        { onSuccess() },
        onError,
    )

    private fun operationReceiver(
        onSuccess: (SessionState, Long) -> Unit,
        onError: (String) -> Unit,
    ): ResultReceiver = object : ResultReceiver(Handler(Looper.getMainLooper())) {
        override fun onReceiveResult(resultCode: Int, resultData: Bundle?) {
            if (resultCode == SERVICE_RESULT_OK && resultData != null) {
                val state = SessionState.values().firstOrNull {
                    it.wireName == resultData.getString(EXTRA_STATE)
                } ?: SessionState.FAILED
                onSuccess(state, resultData.getLong(EXTRA_DURATION_MILLIS))
            } else {
                onError(resultData?.getString(EXTRA_ERROR_CODE) ?: "tunnel_backend_error")
            }
        }
    }

    private fun requestBundle(
        context: Context,
        intent: Intent,
        onSuccess: (Bundle) -> Unit,
        onError: (String) -> Unit,
    ) = dispatch(
        context,
        intent.putExtra(
            EXTRA_RESULT_RECEIVER,
            object : ResultReceiver(Handler(Looper.getMainLooper())) {
                override fun onReceiveResult(resultCode: Int, resultData: Bundle?) {
                    if (resultCode == SERVICE_RESULT_OK) {
                        onSuccess(resultData ?: Bundle.EMPTY)
                    } else {
                        onError(resultData?.getString(EXTRA_ERROR_CODE) ?: "tunnel_backend_error")
                    }
                }
            },
        ),
        onError,
    )

    private fun dispatch(
        context: Context,
        intent: Intent,
        onError: (String) -> Unit = {},
        foreground: Boolean = false,
    ) {
        try {
            if (foreground) {
                ContextCompat.startForegroundService(context.applicationContext, intent)
            } else {
                context.applicationContext.startService(intent)
            }
        } catch (_: Throwable) {
            onError("tunnel_service_unavailable")
        }
    }
}

internal fun Intent.resultReceiver(): ResultReceiver? =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        getParcelableExtra(EXTRA_RESULT_RECEIVER, ResultReceiver::class.java)
    } else {
        @Suppress("DEPRECATION")
        getParcelableExtra(EXTRA_RESULT_RECEIVER)
    }

internal fun TunnelOptionsArgs.toBundle(): Bundle = Bundle().apply {
    putBoolean("split_active", splitActive)
    putString("policy_hash", policyHash)
    putString("application_mode", applicationMode)
    putStringArrayList("excluded_packages", excludedPackages)
    putStringArrayList("included_packages", includedPackages)
    putStringArrayList("split_tunnel_routes", splitTunnelRoutes)
    putBoolean("exclude_local_networks", excludeLocalNetworks)
    putStringArrayList("dns_servers", dnsServers)
}

internal fun Bundle.toTunnelOptions(): TunnelOptionsArgs = TunnelOptionsArgs().also {
    it.splitActive = getBoolean("split_active")
    it.policyHash = getString("policy_hash")
    it.applicationMode = getString("application_mode")
    it.excludedPackages = getStringArrayList("excluded_packages") ?: arrayListOf()
    it.includedPackages = getStringArrayList("included_packages") ?: arrayListOf()
    it.splitTunnelRoutes = getStringArrayList("split_tunnel_routes") ?: arrayListOf()
    it.excludeLocalNetworks = getBoolean("exclude_local_networks")
    it.dnsServers = getStringArrayList("dns_servers") ?: arrayListOf()
}

internal fun QuickConnectionArgs.toBundle(): Bundle = Bundle().apply {
    putString("lease_id", leaseId)
    putString("layer", layer)
    putString("tic_connection_mode", ticConnectionMode)
    putString("route_mode", routeMode)
    putBoolean("allow_alternate", allowAlternate)
}

internal fun Bundle.toQuickConnection(): QuickConnectionArgs = QuickConnectionArgs().also {
    it.leaseId = requireNotNull(getString("lease_id"))
    it.layer = requireNotNull(getString("layer"))
    it.ticConnectionMode = requireNotNull(getString("tic_connection_mode"))
    it.routeMode = requireNotNull(getString("route_mode"))
    it.allowAlternate = getBoolean("allow_alternate")
}
