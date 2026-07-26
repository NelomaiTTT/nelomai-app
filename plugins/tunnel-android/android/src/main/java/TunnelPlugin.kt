package ru.nelomai.tunnel

import android.app.Activity
import android.net.VpnService
import androidx.activity.result.ActivityResult
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import com.wireguard.config.Interface as WireGuardInterface
import com.wireguard.config.Peer
import com.wireguard.crypto.KeyPair
import java.util.concurrent.Executors

@TauriPlugin
class TunnelPlugin(private val activity: Activity) : Plugin(activity) {
    private val backend by lazy {
        GoBackend(activity.applicationContext)
    }
    private val tunnelExecutor = Executors.newSingleThreadExecutor()
    private val smokeTunnel = object : Tunnel {
        private var state = Tunnel.State.DOWN

        override fun getName() = "nelomai-spike"

        override fun onStateChange(newState: Tunnel.State) {
            state = newState
        }

        fun state() = state
    }
    private val smokeConfig by lazy {
        val interfaceKeyPair = KeyPair()
        val peerKeyPair = KeyPair()
        val wireGuardInterface = WireGuardInterface.Builder()
            .parseAddresses("192.0.2.2/32")
            .setKeyPair(interfaceKeyPair)
            .build()
        val peer = Peer.Builder()
            .parseAllowedIPs("192.0.2.1/32")
            .parseEndpoint("192.0.2.1:51820")
            .setPublicKey(peerKeyPair.publicKey)
            .build()

        Config.Builder()
            .setInterface(wireGuardInterface)
            .addPeer(peer)
            .build()
    }

    @Command
    fun probe(invoke: Invoke) {
        val response = JSObject()
        response.put("platform", "android")
        response.put("permissionGranted", VpnService.prepare(activity.applicationContext) == null)

        try {
            response.put("backendAvailable", true)
            response.put("backendVersion", backend.version)
            response.put("error", null)
        } catch (error: Throwable) {
            response.put("backendAvailable", false)
            response.put("backendVersion", null)
            response.put("error", error.message ?: error.javaClass.simpleName)
        }

        invoke.resolve(response)
    }

    @Command
    fun requestVpnPermission(invoke: Invoke) {
        val intent = VpnService.prepare(activity.applicationContext)
        if (intent == null) {
            resolvePermission(invoke, true)
            return
        }

        startActivityForResult(invoke, intent, "vpnPermissionResult")
    }

    @Command
    fun startSmokeTunnel(invoke: Invoke) {
        if (VpnService.prepare(activity.applicationContext) != null) {
            invoke.reject("VPN permission is required")
            return
        }

        tunnelExecutor.execute {
            val startedAt = System.nanoTime()
            try {
                val state = backend.setState(smokeTunnel, Tunnel.State.UP, smokeConfig)
                activity.runOnUiThread {
                    resolveSmoke(invoke, state, startedAt)
                }
            } catch (error: Throwable) {
                activity.runOnUiThread {
                    invoke.reject(error.message ?: error.javaClass.simpleName)
                }
            }
        }
    }

    @Command
    fun stopSmokeTunnel(invoke: Invoke) {
        tunnelExecutor.execute {
            val startedAt = System.nanoTime()
            try {
                val state = backend.setState(smokeTunnel, Tunnel.State.DOWN, null)
                activity.runOnUiThread {
                    resolveSmoke(invoke, state, startedAt)
                }
            } catch (error: Throwable) {
                activity.runOnUiThread {
                    invoke.reject(error.message ?: error.javaClass.simpleName)
                }
            }
        }
    }

    @Command
    fun smokeTunnelStatus(invoke: Invoke) {
        val response = JSObject()
        response.put("state", smokeTunnel.state().name.lowercase())
        response.put("durationMillis", 0)
        invoke.resolve(response)
    }

    @ActivityCallback
    fun vpnPermissionResult(invoke: Invoke, result: ActivityResult) {
        val granted = result.resultCode == Activity.RESULT_OK &&
            VpnService.prepare(activity.applicationContext) == null
        resolvePermission(invoke, granted)
    }

    private fun resolvePermission(invoke: Invoke, granted: Boolean) {
        val response = JSObject()
        response.put("permissionGranted", granted)
        invoke.resolve(response)
    }

    private fun resolveSmoke(invoke: Invoke, state: Tunnel.State, startedAt: Long) {
        val response = JSObject()
        response.put("state", state.name.lowercase())
        response.put("durationMillis", (System.nanoTime() - startedAt) / 1_000_000)
        invoke.resolve(response)
    }
}
