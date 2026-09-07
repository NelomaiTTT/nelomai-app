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

/** The name is container-owned and cannot be supplied by a runtime command. */
object RuntimeServiceIntents {
    const val VPN_COMPONENT = "ru.nelomai.client.RuntimeVpnDispatcherService"
    @JvmStatic fun vpn(context: Context): Intent = Intent().setClassName(context.packageName, VPN_COMPONENT)
}
