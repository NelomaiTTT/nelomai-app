package ru.nelomai.client

import android.content.Intent
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.util.Log

object RuntimeEntrypoint {
    private var attached = false
    external fun attach(fd: Int, bootstrap: String)
    @Synchronized fun attachFromIntent(intent: Intent) {
        if (attached) return
        val selected = RuntimeSelectionCodec.decode(requireNotNull(intent.getStringExtra("runtime_selection_v1")))
        RuntimeProcessSelection.claim(selected)
        var started = SystemClock.elapsedRealtime()
        System.loadLibrary(RuntimeDispatchPolicy.library(selected))
        Log.i("NelomaiStartup", "runtime.load_library duration_ms=${SystemClock.elapsedRealtime() - started}")
        @Suppress("DEPRECATION")
        val fd = requireNotNull(intent.getParcelableExtra<ParcelFileDescriptor>("runtime_endpoint_v1"))
        val bootstrap = requireNotNull(intent.getStringExtra("runtime_bootstrap_v1"))
        require(bootstrap.toByteArray().size <= 65536)
        started = SystemClock.elapsedRealtime()
        attach(fd.detachFd(), bootstrap)
        Log.i("NelomaiStartup", "runtime.attach duration_ms=${SystemClock.elapsedRealtime() - started}")
        intent.removeExtra("runtime_endpoint_v1")
        intent.removeExtra("runtime_bootstrap_v1")
        attached = true
        RuntimeProcessSelection.markAdmitted()
    }
}
