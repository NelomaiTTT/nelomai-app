package ru.nelomai.runtime.v1

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.IBinder

/** Container-owned ABI. Never copied or relocated into a versioned runtime. */
interface RuntimeVpnEngineV1 {
    fun requiresStartAdmission(intent: Intent?): Boolean
    fun create()
    fun start(intent: Intent?, flags: Int, startId: Int): Int
    fun revoke()
    fun taskRemoved(intent: Intent?)
    fun destroy()
}

interface RuntimeQuickActionsV1 {
    fun desiredActive(context: Context): Boolean
    fun state(context: Context): String
    fun toggle(context: Context): Boolean
}

interface RuntimeNativeResultV1 {
    fun success(value: String)
    fun failure(code: String)
}
interface RuntimeNativeBridgeV1 {
    fun prepareRevocation(context: Context, epoch: Long, result: RuntimeNativeResultV1)
    fun stop(context: Context, result: RuntimeNativeResultV1)
    fun background(context: Context, action: String, request: String, result: RuntimeNativeResultV1)
}

interface RuntimeNativeStorageV1 {
    fun prepare(context: Context, slot: String, version: String, legacyMigration: Boolean, migrationComplete: Boolean)
    fun acknowledge(context: Context)
}

interface RuntimeVpnHostV1 {
    val service: VpnService
    fun builder(beforeEstablish: (VpnService.Builder) -> Unit): VpnService.Builder
}

/** Optional on the latest Android engine and host. The retained V1 ABI stays intact. */
interface RuntimeVpnAuthorityV1 {
    fun vpnAuthorityCurrent(): Boolean
    fun invalidateQueuedVpnStarts()
    fun retireVpnAuthority()
}

interface RuntimeVpnTransportV1 {
    fun localTransportClosed(): Boolean
}

/** The name is container-owned and cannot be supplied by a runtime command. */
object RuntimeServiceIntents {
    const val VPN_COMPONENT = "ru.nelomai.client.RuntimeVpnDispatcherService"
    const val CLIENT_STOP = "ru.nelomai.tunnel.CLIENT_STOP"
    const val VPN_API_VERSION = 2
    const val QUICK_TOGGLE = "ru.nelomai.tunnel.QUICK_TOGGLE"
    const val EXTRA_QUICK_STOP_ONLY = "ru.nelomai.runtime.v1.QUICK_STOP_ONLY"
    const val EXTRA_FOREGROUND_START = "ru.nelomai.runtime.v1.FOREGROUND_START"
    const val PREPARE_STABLE_BACKGROUND = "ru.nelomai.runtime.v1.PREPARE_STABLE_BACKGROUND"
    const val STABLE_PROVISION_REQUEST = "ru.nelomai.runtime.v1.STABLE_PROVISION_REQUEST"
    @JvmStatic fun foreground(intent: Intent): Intent = intent.putExtra(EXTRA_FOREGROUND_START, true)
    @JvmStatic fun vpn(context: Context): Intent = Intent().setClassName(context.packageName, VPN_COMPONENT)
    @JvmStatic fun quickStopVpn(context: Context): Intent =
        vpn(context).setAction(QUICK_TOGGLE).putExtra(EXTRA_QUICK_STOP_ONLY, true)
}
