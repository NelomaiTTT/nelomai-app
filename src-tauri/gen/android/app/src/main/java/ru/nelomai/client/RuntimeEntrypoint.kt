package ru.nelomai.client

import android.content.Intent
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.util.Log

object RuntimeEntrypoint {
    private var attached = false
    private var nativeAttachAttempted = false
    @Synchronized fun isAttached(): Boolean = attached
    @Synchronized fun canRetryBootstrap(): Boolean = !nativeAttachAttempted
    external fun attach(fd: Int, bootstrap: String)
    @Synchronized fun attachFromIntent(intent: Intent) {
        if (attached) return
        check(!nativeAttachAttempted) { "runtime_attachment_incomplete" }
        val selected = RuntimeSelectionCodec.decode(requireNotNull(intent.getStringExtra("runtime_selection_v1")))
        // Activity intents restored after process death no longer own these one-shot
        // inputs. Reject them before pinning the process or loading native code.
        @Suppress("DEPRECATION")
        val fd = requireNotNull(intent.getParcelableExtra<ParcelFileDescriptor>("runtime_endpoint_v1"))
        require(fd.fileDescriptor.valid()) { "runtime_endpoint_unavailable" }
        val bootstrap = requireNotNull(intent.getStringExtra("runtime_bootstrap_v1"))
        require(bootstrap.isNotBlank() && bootstrap.toByteArray().size <= 65536)
        val library = RuntimeDispatchPolicy.library(selected)
        RuntimeProcessSelection.claim(selected)
        var started = SystemClock.elapsedRealtime()
        // Once native loading begins, failure may leave process-global native state.
        // Only process death clears this fence; no retry or Activity recreation does.
        nativeAttachAttempted = true
        System.loadLibrary(library)
        Log.i("NelomaiStartup", "runtime.load_library duration_ms=${SystemClock.elapsedRealtime() - started}")
        started = SystemClock.elapsedRealtime()
        attach(fd.detachFd(), bootstrap)
        Log.i("NelomaiStartup", "runtime.attach duration_ms=${SystemClock.elapsedRealtime() - started}")
        intent.removeExtra("runtime_endpoint_v1")
        intent.removeExtra("runtime_bootstrap_v1")
        attached = true
        RuntimeProcessSelection.markAdmitted()
    }
}
