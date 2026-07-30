package ru.nelomai.tunnel

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import com.wireguard.android.backend.GoBackend
import java.util.concurrent.CompletableFuture

class NelomaiVpnService : GoBackend.VpnService() {
    override fun getBuilder(): VpnService.Builder =
        object : VpnService.Builder() {
            override fun establish(): ParcelFileDescriptor? {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    AndroidSplitTunnel.currentExcludedRoutes().forEach(::excludeRoute)
                }
                return super.establish()
            }
        }

    override fun onCreate() {
        super.onCreate()
        serviceReady.complete(Unit)
    }

    override fun onDestroy() {
        AndroidSplitTunnel.clear()
        super.onDestroy()
        serviceReady = CompletableFuture()
    }

    companion object {
        @Volatile
        private var serviceReady = CompletableFuture<Unit>()

        fun ensureStarted(context: Context): CompletableFuture<Unit> {
            context.startService(Intent(context, NelomaiVpnService::class.java))
            return serviceReady
        }
    }
}
