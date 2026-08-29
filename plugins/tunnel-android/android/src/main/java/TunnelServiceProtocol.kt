package ru.nelomai.tunnel

import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.ResultReceiver
import androidx.core.content.ContextCompat
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

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
internal const val EXTRA_LATEST_HANDSHAKE_EPOCH_MILLIS = "latest_handshake_epoch_millis"
internal const val EXTRA_PROBE_TARGET = "probe_target"
internal const val EXTRA_PANEL_BASE = "panel_base"
internal const val EXTRA_TOKEN = "token"
internal const val EXTRA_DEVICE_ID = "device_id"
internal const val EXTRA_EXPIRES_AT_UNIX = "expires_at_unix"
internal const val EXTRA_CONFIGURED = "configured"
internal const val EXTRA_CREDENTIAL_REVISION = "credential_revision"
internal const val EXTRA_INSTALL_SECRET = "install_secret"
internal const val EXTRA_ACCESS_TOKEN = "access_token"
internal const val EXTRA_REFRESH_TOKEN = "refresh_token"
internal const val EXTRA_CAPABILITY_REVISION = "capability_revision"
internal const val EXTRA_CAPABILITY_ENABLED = "capability_enabled"
internal const val EXTRA_CAPABILITY_EXPIRES_AT = "capability_expires_at"
internal const val EXTRA_MUTATION_READY = "mutation_ready"
internal const val EXTRA_MUTATION_PENDING = "mutation_pending"
internal const val EXTRA_CHANGED = "changed"
internal const val EXTRA_STATE_CHANGE_REVISION = "state_change_revision"
internal const val EXTRA_DNS_SERVERS = "dns_servers"
internal const val EXTRA_CLIENT_OPERATION_ID = "client_operation_id"
private const val QUICK_DNS_UPDATE_TIMEOUT_MILLIS = 3_000L
private const val METRICS_REQUEST_TIMEOUT_MILLIS = 1_800L
private const val UDP_REBIND_REQUEST_TIMEOUT_MILLIS = 3_250L
private const val SERVICE_REQUEST_TIMEOUT_MILLIS = 30_000L
private const val SERVICE_REQUEST_TIMEOUT_ERROR = "tunnel_service_timeout"
private const val CREDENTIAL_MUTATION_NETWORK_STEPS = 3L
private const val CREDENTIAL_MUTATION_COMPLETION_SLACK_MILLIS = 5_000L

internal fun backgroundCredentialMutationTimeoutMillis(): Long =
    CREDENTIAL_MUTATION_NETWORK_STEPS *
        (BACKGROUND_CONNECT_TIMEOUT_MILLIS + BACKGROUND_READ_TIMEOUT_MILLIS).toLong() +
        CREDENTIAL_MUTATION_COMPLETION_SLACK_MILLIS

internal class ServiceRequestCompletion {
    private val completed = AtomicBoolean(false)

    fun finish(action: () -> Unit): Boolean {
        if (!completed.compareAndSet(false, true)) return false
        action()
        return true
    }
}

internal object TunnelServiceClient {
    fun start(
        context: Context,
        args: StartTunnelArgs,
        onSuccess: (SessionState, Long) -> Unit,
        onError: (String) -> Unit,
    ) {
        val configuration = args.configuration.copyOf()
        val clientOperationId = UUID.randomUUID().toString()
        try {
            requestBundle(
                context,
                Intent(context, NelomaiVpnService::class.java)
                    .setAction(NelomaiVpnService.ACTION_CLIENT_START)
                    .putExtra(EXTRA_API_VERSION, args.apiVersion)
                    .putExtra(EXTRA_CLIENT_OPERATION_ID, clientOperationId)
                    .putExtra(EXTRA_START_SOURCE, args.startSource)
                    .putExtra(EXTRA_CONFIGURATION, configuration)
                    .putExtra(EXTRA_OPTIONS, args.options.toBundle())
                    .putExtra(EXTRA_CACHE_QUICK_ACTION, args.cacheQuickAction)
                    .putExtra(
                        EXTRA_QUICK_ACTION_VALID_UNTIL,
                        args.quickActionValidUntilUnix ?: Long.MIN_VALUE,
                    )
                    .putExtra(EXTRA_QUICK_CONNECTION, args.quickConnection?.toBundle()),
                { result ->
                    val state = SessionState.values().firstOrNull {
                        it.wireName == result.getString(EXTRA_STATE)
                    } ?: SessionState.FAILED
                    onSuccess(state, result.getLong(EXTRA_DURATION_MILLIS))
                },
                onError,
                foreground = true,
                onTimeout = { cancelClientStart(context, clientOperationId) },
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
    ) = requestBundle(
        context,
        Intent(context, NelomaiVpnService::class.java)
            .setAction(NelomaiVpnService.ACTION_CLIENT_STOP)
            .putExtra(EXTRA_API_VERSION, apiVersion),
        { result ->
            val state = SessionState.values().firstOrNull {
                it.wireName == result.getString(EXTRA_STATE)
            } ?: SessionState.FAILED
            onSuccess(state, result.getLong(EXTRA_DURATION_MILLIS))
        },
        onError,
    )

    fun status(
        context: Context,
        apiVersion: Int,
        onSuccess: (SessionState, Long) -> Unit,
        onError: (String) -> Unit,
    ) = requestBundle(
        context,
        Intent(context, NelomaiVpnService::class.java)
            .setAction(NelomaiVpnService.ACTION_CLIENT_STATUS)
            .putExtra(EXTRA_API_VERSION, apiVersion),
        { result ->
            val state = SessionState.values().firstOrNull {
                it.wireName == result.getString(EXTRA_STATE)
            } ?: SessionState.FAILED
            onSuccess(state, result.getLong(EXTRA_DURATION_MILLIS))
        },
        onError,
    )

    fun metrics(
        context: Context,
        apiVersion: Int,
        probe: Boolean,
        onSuccess: (Long, Long, Long?, String?) -> Unit,
        onError: (String) -> Unit,
    ) = requestBundle(
        context,
        Intent(context, NelomaiVpnService::class.java)
            .setAction(NelomaiVpnService.ACTION_CLIENT_METRICS)
            .putExtra(EXTRA_API_VERSION, apiVersion)
            .putExtra(EXTRA_PROBE, probe),
        { result ->
            onSuccess(
                result.getLong(EXTRA_RECEIVED_BYTES),
                result.getLong(EXTRA_SENT_BYTES),
                result.getLong(EXTRA_LATEST_HANDSHAKE_EPOCH_MILLIS)
                    .takeIf { result.containsKey(EXTRA_LATEST_HANDSHAKE_EPOCH_MILLIS) },
                result.getString(EXTRA_PROBE_TARGET),
            )
        },
        onError,
        timeoutMillis = METRICS_REQUEST_TIMEOUT_MILLIS,
    )

    fun rebindUdp(
        context: Context,
        apiVersion: Int,
        onSuccess: (SessionState, Long) -> Unit,
        onError: (String) -> Unit,
    ) = requestBundle(
        context,
        Intent(context, NelomaiVpnService::class.java)
            .setAction(NelomaiVpnService.ACTION_CLIENT_REBIND_UDP)
            .putExtra(EXTRA_API_VERSION, apiVersion),
        { result ->
            val state = SessionState.values().firstOrNull {
                it.wireName == result.getString(EXTRA_STATE)
            } ?: SessionState.FAILED
            onSuccess(state, result.getLong(EXTRA_DURATION_MILLIS))
        },
        onError,
        timeoutMillis = UDP_REBIND_REQUEST_TIMEOUT_MILLIS,
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
            .putExtra(EXTRA_CREDENTIAL_REVISION, args.expectedRevision)
            .putExtra(EXTRA_DEVICE_ID, args.deviceId)
            .putExtra(EXTRA_PANEL_BASE, args.panelBase)
            .putExtra(EXTRA_TOKEN, args.token)
            .putExtra(EXTRA_EXPIRES_AT_UNIX, args.expiresAtUnix)
            .putExtra(EXTRA_INSTALL_SECRET, args.installSecret)
            .putExtra(EXTRA_CAPABILITY_REVISION, args.capabilityRevision)
            .putExtra(EXTRA_CAPABILITY_ENABLED, args.capabilityEnabled)
            .putExtra(EXTRA_CAPABILITY_EXPIRES_AT, args.capabilityExpiresAt),
        { onSuccess() },
        onError,
    )

    fun backgroundCredentialStatus(
        context: Context,
        onSuccess: (Boolean, Long, Boolean, Boolean, Boolean, Long?, String?, Long?) -> Unit,
        onError: (String) -> Unit,
    ) = requestBundle(
        context,
        Intent(context, NelomaiVpnService::class.java)
            .setAction(NelomaiVpnService.ACTION_BACKGROUND_STATUS),
        {
            val configured = it.getBoolean(EXTRA_CONFIGURED)
            onSuccess(
                configured,
                it.getLong(EXTRA_CREDENTIAL_REVISION),
                it.getBoolean(EXTRA_MUTATION_READY),
                it.getBoolean(EXTRA_MUTATION_PENDING),
                it.getBoolean(EXTRA_CAPABILITY_ENABLED),
                it.getLong(EXTRA_CAPABILITY_EXPIRES_AT).takeIf { value ->
                    value != Long.MIN_VALUE
                },
                if (configured) it.getString(EXTRA_DEVICE_ID) else null,
                if (configured) it.getLong(EXTRA_EXPIRES_AT_UNIX) else null,
            )
        },
        onError,
    )

    fun rotateBackground(
        context: Context,
        expectedRevision: Long,
        onSuccess: () -> Unit,
        onError: (String) -> Unit,
    ) = requestBundle(
        context,
        Intent(context, NelomaiVpnService::class.java)
            .setAction(NelomaiVpnService.ACTION_ROTATE_BACKGROUND)
            .putExtra(EXTRA_CREDENTIAL_REVISION, expectedRevision),
        { onSuccess() },
        onError,
        timeoutMillis = backgroundCredentialMutationTimeoutMillis(),
    )

    fun provisionBackground(
        context: Context,
        args: BackgroundUiProvisionArgs,
        onSuccess: () -> Unit,
        onError: (String) -> Unit,
    ) = requestBundle(
        context,
        Intent(context, NelomaiVpnService::class.java)
            .setAction(NelomaiVpnService.ACTION_PROVISION_BACKGROUND)
            .putExtra(EXTRA_API_VERSION, args.apiVersion)
            .putExtra(EXTRA_CREDENTIAL_REVISION, args.expectedRevision)
            .putExtra(EXTRA_DEVICE_ID, args.deviceId)
            .putExtra(EXTRA_PANEL_BASE, args.panelBase)
            .putExtra(EXTRA_ACCESS_TOKEN, args.accessToken)
            .putExtra(EXTRA_INSTALL_SECRET, args.installSecret)
            .putExtra(EXTRA_CAPABILITY_REVISION, args.capabilityRevision)
            .putExtra(EXTRA_CAPABILITY_ENABLED, args.capabilityEnabled)
            .putExtra(EXTRA_CAPABILITY_EXPIRES_AT, args.capabilityExpiresAt),
        { onSuccess() },
        onError,
        timeoutMillis = backgroundCredentialMutationTimeoutMillis(),
    )

    fun recoverBackgroundSession(
        context: Context,
        installSecret: String,
        onSuccess: (String, String) -> Unit,
        onError: (String) -> Unit,
    ) = requestBundle(
        context,
        Intent(context, NelomaiVpnService::class.java)
            .setAction(NelomaiVpnService.ACTION_RECOVER_BACKGROUND_SESSION)
            .putExtra(EXTRA_INSTALL_SECRET, installSecret),
        { result ->
            onSuccess(
                requireNotNull(result.getString(EXTRA_ACCESS_TOKEN)),
                requireNotNull(result.getString(EXTRA_REFRESH_TOKEN)),
            )
        },
        onError,
        timeoutMillis = backgroundCredentialMutationTimeoutMillis(),
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
        timeoutMillis = QUICK_DNS_UPDATE_TIMEOUT_MILLIS,
    )

    fun takeQuickStateChange(
        context: Context,
        onSuccess: (Boolean, Long) -> Unit,
        onError: (String) -> Unit,
    ) = requestBundle(
        context,
        Intent(context, NelomaiVpnService::class.java)
            .setAction(NelomaiVpnService.ACTION_TAKE_STATE_CHANGE),
        {
            onSuccess(
                it.getBoolean(EXTRA_CHANGED),
                it.getLong(EXTRA_STATE_CHANGE_REVISION),
            )
        },
        onError,
    )

    fun acknowledgeQuickStateChange(
        context: Context,
        revision: Long,
        onSuccess: (Long) -> Unit,
        onError: (String) -> Unit,
    ) = requestBundle(
        context,
        Intent(context, NelomaiVpnService::class.java)
            .setAction(NelomaiVpnService.ACTION_ACKNOWLEDGE_STATE_CHANGE)
            .putExtra(EXTRA_STATE_CHANGE_REVISION, revision),
        { onSuccess(it.getLong(EXTRA_STATE_CHANGE_REVISION)) },
        onError,
    )

    private fun requestBundle(
        context: Context,
        intent: Intent,
        onSuccess: (Bundle) -> Unit,
        onError: (String) -> Unit,
        foreground: Boolean = false,
        timeoutMillis: Long = SERVICE_REQUEST_TIMEOUT_MILLIS,
        onTimeout: () -> Unit = {},
    ) {
        val completion = ServiceRequestCompletion()
        val handler = Handler(Looper.getMainLooper())
        lateinit var timeout: Runnable
        fun finish(action: () -> Unit) {
            completion.finish {
                handler.removeCallbacks(timeout)
                action()
            }
        }
        timeout = Runnable {
            finish {
                try {
                    onTimeout()
                } finally {
                    onError(SERVICE_REQUEST_TIMEOUT_ERROR)
                }
            }
        }
        val receiver = object : ResultReceiver(handler) {
            override fun onReceiveResult(resultCode: Int, resultData: Bundle?) {
                finish {
                    if (resultCode == SERVICE_RESULT_OK) {
                        onSuccess(resultData ?: Bundle.EMPTY)
                    } else {
                        onError(resultData?.getString(EXTRA_ERROR_CODE) ?: "tunnel_backend_error")
                    }
                }
            }
        }
        handler.postDelayed(timeout, timeoutMillis.coerceAtLeast(1))
        dispatch(
            context,
            intent.putExtra(EXTRA_RESULT_RECEIVER, receiver),
            { code -> finish { onError(code) } },
            foreground,
        )
    }

    private fun cancelClientStart(context: Context, clientOperationId: String) {
        dispatch(
            context,
            Intent(context, NelomaiVpnService::class.java)
                .setAction(NelomaiVpnService.ACTION_CANCEL_CLIENT_START)
                .putExtra(EXTRA_CLIENT_OPERATION_ID, clientOperationId),
            { code -> TunnelLog.warning("client_start.cancel_dispatch_failed", code) },
        )
    }

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
    putString("egress_mode", egressMode)
    putBoolean("allow_alternate", allowAlternate)
}

internal fun Bundle.toQuickConnection(): QuickConnectionArgs = QuickConnectionArgs().also {
    it.leaseId = requireNotNull(getString("lease_id"))
    it.layer = requireNotNull(getString("layer"))
    it.ticConnectionMode = requireNotNull(getString("tic_connection_mode"))
    it.routeMode = requireNotNull(getString("route_mode"))
    it.egressMode = getString("egress_mode") ?: "ipv4"
    it.allowAlternate = getBoolean("allow_alternate")
}
