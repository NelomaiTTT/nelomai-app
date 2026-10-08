package ru.nelomai.tunnel

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.Process
import android.os.ResultReceiver
import ru.nelomai.runtime.v1.RuntimeServiceIntents

internal const val EXTRA_STATUS_ENDPOINT = "status_endpoint"
internal const val EXTRA_STATUS_GENERATION = "status_generation"
internal const val EXTRA_STATUS_RUNTIME = "status_runtime"
internal const val STATUS_OBSERVE = 1
internal const val STATUS_ENDPOINT_UNAVAILABLE = "tunnel_status_endpoint_unavailable"
internal const val STATUS_POLL_IDLE_MILLIS = 5_000L
private const val STATUS_REQUEST_TIMEOUT_MILLIS = 30_000L
private val statusRuntimeIdentity get() = "${BuildConfig.RUNTIME_SLOT}/${BuildConfig.RUNTIME_VERSION}"

/** A capability for status only. It never accepts a service action or native command. */
internal class TunnelStatusEndpoint(
    private val generation: Long,
    private val isCurrent: () -> Boolean,
    private val verifyRuntime: ((Boolean) -> Unit) -> Unit,
    private val observe: (Intent) -> Unit,
) {
    private val handler = Handler(Looper.getMainLooper())
    private var closed = false
    val messenger = Messenger(object : Handler(Looper.getMainLooper()) {
        override fun handleMessage(message: Message) {
            // Do not even unpack caller-controlled data before checking identity
            // and opcode. The standard framework VPN binder is never used here.
            if (message.sendingUid != Process.myUid() || message.what != STATUS_OBSERVE) return
            var reply: ResultReceiver? = null
            try {
                val data = message.data
                // Messenger does not supply our runtime loader. The caller's
                // ResultReceiver subclass must be resolved before unparcelling.
                data.classLoader = TunnelStatusEndpoint::class.java.classLoader
                @Suppress("DEPRECATION")
                val receiver = data.getParcelable<android.os.Parcelable>(EXTRA_RESULT_RECEIVER) as? ResultReceiver
                    ?: return
                reply = receiver
                if (data.getLong(EXTRA_STATUS_GENERATION, -1) != generation ||
                    data.getString(EXTRA_STATUS_RUNTIME) != statusRuntimeIdentity
                ) { reject(reply); return }
                val apiVersion = data.getInt(EXTRA_API_VERSION)
                if (apiVersion != TUNNEL_API_VERSION) {
                    receiver.send(SERVICE_RESULT_ERROR, Bundle().apply {
                        putString(EXTRA_ERROR_CODE, "unsupported_api_version")
                    })
                    return
                }
                verified(receiver) {
                    // Construct the action here, never deserialize a caller's Intent.
                    observe(Intent().setAction(NelomaiVpnService.ACTION_CLIENT_STATUS)
                        .putExtra(EXTRA_API_VERSION, apiVersion)
                        .putExtra(EXTRA_RESULT_RECEIVER, receiver))
                }
            } catch (_: Exception) {
                reject(reply)
            }
        }
    })

    fun close() { closed = true }

    /** Fence the reply too: a queued observation must not outlive revoke/destroy/switch. */
    fun replyTo(receiver: ResultReceiver?): ResultReceiver = object : ResultReceiver(handler) {
        override fun onReceiveResult(resultCode: Int, resultData: Bundle?) {
            verified(receiver) {
                receiver?.send(resultCode, Bundle(resultData ?: Bundle.EMPTY).apply {
                    putBinder(EXTRA_STATUS_ENDPOINT, messenger.binder)
                    putLong(EXTRA_STATUS_GENERATION, generation)
                    putString(EXTRA_STATUS_RUNTIME, statusRuntimeIdentity)
                })
            }
        }
    }

    private fun verified(reply: ResultReceiver?, action: () -> Unit) {
        if (closed || !isCurrent()) { reject(reply); return }
        val completion = ServiceRequestCompletion()
        try {
            verifyRuntime { matches ->
                completion.finish {
                    try {
                        if (!matches || closed || !isCurrent()) reject(reply) else action()
                    } catch (_: Exception) { reject(reply) }
                }
            }
        } catch (_: Exception) { completion.finish { reject(reply) } }
    }

    private fun reject(reply: ResultReceiver?) {
        reply?.send(SERVICE_RESULT_ERROR, Bundle().apply {
            putString(EXTRA_ERROR_CODE, STATUS_ENDPOINT_UNAVAILABLE)
        })
    }
}

/** Main-looper-owned polling lease. No persisted status and no mutation transport. */
internal object TunnelStatusTransport {
    private val handler = Handler(Looper.getMainLooper())
    private var session: Session? = null

    fun request(context: Context, apiVersion: Int, success: (Bundle) -> Unit, error: (String) -> Unit) {
        val request = {
            if (apiVersion != TUNNEL_API_VERSION) error("unsupported_api_version") else {
                val owner = session ?: Session(context.applicationContext).also { session = it }
                owner.request(apiVersion, success, error)
            }
        }
        if (Looper.myLooper() == Looper.getMainLooper()) request() else handler.post { request() }
    }

    private class Request(
        val apiVersion: Int,
        val success: (Bundle) -> Unit,
        val error: (String) -> Unit,
    ) {
        var sent = false
        lateinit var timeout: Runnable
    }

    private class Session(private val context: Context) {
        private var closed = false
        private var bindingAttempted = false
        private var bound = false
        private var bootstrapped = false
        private var bootstrapInFlight = false
        private var endpoint: Messenger? = null
        private var generation = -1L
        private var runtime: String? = null
        private val requests = linkedSetOf<Request>()
        private val idle = Runnable { close("tunnel_service_timeout") }
        private val died = IBinder.DeathRecipient { handler.post { close(STATUS_ENDPOINT_UNAVAILABLE) } }
        private val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
                if (!closed && (name != vpnComponent() || service == null)) close(STATUS_ENDPOINT_UNAVAILABLE)
            }
            override fun onServiceDisconnected(name: ComponentName?) = close(STATUS_ENDPOINT_UNAVAILABLE)
            override fun onBindingDied(name: ComponentName?) = close(STATUS_ENDPOINT_UNAVAILABLE)
            override fun onNullBinding(name: ComponentName?) = close(STATUS_ENDPOINT_UNAVAILABLE)
        }

        private fun vpnComponent() = ComponentName(context.packageName, RuntimeServiceIntents.VPN_COMPONENT)

        fun request(apiVersion: Int, success: (Bundle) -> Unit, error: (String) -> Unit) {
            if (closed) { error(STATUS_ENDPOINT_UNAVAILABLE); return }
            handler.removeCallbacks(idle)
            val request = Request(apiVersion, success, error)
            request.timeout = Runnable { close("tunnel_service_timeout") }
            requests.add(request)
            handler.postDelayed(request.timeout, STATUS_REQUEST_TIMEOUT_MILLIS)
            if (!bindingAttempted) {
                bindingAttempted = true
                bound = try {
                    // The framework VPN binder is ONLY a lifetime binding. Never
                    // transact on it; the private endpoint arrives through our RPC.
                    context.bindService(RuntimeServiceIntents.vpn(context)
                        .setAction(VpnService.SERVICE_INTERFACE), connection, Context.BIND_AUTO_CREATE)
                } catch (_: Exception) { false }
            }
            flush()
        }

        private fun flush() {
            if (closed || bootstrapInFlight) return
            for (request in requests.toList()) {
                if (request.sent) continue
                request.sent = true
                val bootstrap = !bootstrapped
                if (bootstrap) bootstrapInFlight = true
                send(request, bootstrap)
                if (bootstrap) return
            }
        }

        private fun send(request: Request, bootstrap: Boolean) {
            val receiver = object : ResultReceiver(handler) {
                override fun onReceiveResult(code: Int, value: Bundle?) {
                    if (closed || request !in requests) return
                    val result = value ?: Bundle.EMPTY
                    if (result.getString(EXTRA_ERROR_CODE) == STATUS_ENDPOINT_UNAVAILABLE) {
                        close(STATUS_ENDPOINT_UNAVAILABLE)
                        return
                    }
                    if (!bootstrap && endpoint != null && (
                        result.getLong(EXTRA_STATUS_GENERATION, -1) != generation ||
                            result.getString(EXTRA_STATUS_RUNTIME) != runtime
                    )) {
                        close(STATUS_ENDPOINT_UNAVAILABLE)
                        return
                    }
                    if (bootstrap) {
                        bootstrapped = true
                        bootstrapInFlight = false
                        if (bound) {
                            val binder = result.getBinder(EXTRA_STATUS_ENDPOINT)
                            val remoteGeneration = result.getLong(EXTRA_STATUS_GENERATION, -1)
                            val remoteRuntime = result.getString(EXTRA_STATUS_RUNTIME)
                            if (binder != null) {
                                if (remoteGeneration < 0 || remoteRuntime != statusRuntimeIdentity) {
                                    close(STATUS_ENDPOINT_UNAVAILABLE)
                                    return
                                }
                                try { binder.linkToDeath(died, 0) } catch (_: Exception) {
                                    close(STATUS_ENDPOINT_UNAVAILABLE)
                                    return
                                }
                                endpoint = Messenger(binder)
                                generation = remoteGeneration
                                runtime = remoteRuntime
                            }
                        }
                    }
                    requests.remove(request)
                    handler.removeCallbacks(request.timeout)
                    if (requests.isEmpty()) handler.postDelayed(idle, STATUS_POLL_IDLE_MILLIS)
                    if (code == SERVICE_RESULT_OK) request.success(result)
                    else request.error(result.getString(EXTRA_ERROR_CODE) ?: "tunnel_backend_error")
                    flush()
                }
            }
            try {
                val remote = endpoint
                if (remote != null) {
                    remote.send(Message.obtain().apply {
                        what = STATUS_OBSERVE
                        data = Bundle().apply {
                            putInt(EXTRA_API_VERSION, request.apiVersion)
                            putLong(EXTRA_STATUS_GENERATION, generation)
                            putString(EXTRA_STATUS_RUNTIME, runtime)
                            putParcelable(EXTRA_RESULT_RECEIVER, receiver)
                        }
                    })
                } else {
                    // Bind unavailable/old runtime without endpoint: retain the
                    // existing authoritative RPC, never invent a stopped result.
                    context.startService(RuntimeServiceIntents.vpn(context)
                        .setAction(NelomaiVpnService.ACTION_CLIENT_STATUS)
                        .putExtra(EXTRA_API_VERSION, request.apiVersion)
                        .putExtra(EXTRA_RESULT_RECEIVER, receiver))
                }
            } catch (_: Exception) { close(androidServiceDispatchErrorCode()) }
        }

        private fun close(code: String) {
            if (closed) return
            closed = true
            if (session === this) session = null
            handler.removeCallbacks(idle)
            endpoint?.binder?.let { runCatching { it.unlinkToDeath(died, 0) } }
            endpoint = null
            // Also attempt cleanup after a failed bind; some framework failures
            // occur after registering the connection. Unbind errors are advisory.
            if (bindingAttempted) runCatching { context.unbindService(connection) }
            bound = false
            val abandoned = requests.toList()
            requests.clear()
            abandoned.forEach { handler.removeCallbacks(it.timeout) }
            abandoned.forEach { it.error(code) }
        }
    }
}
