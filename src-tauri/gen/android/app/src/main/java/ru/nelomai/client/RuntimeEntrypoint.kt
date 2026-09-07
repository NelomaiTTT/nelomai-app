package ru.nelomai.client

import android.content.Intent
import android.os.ParcelFileDescriptor

object RuntimeEntrypoint {
    private var attached = false
    external fun attach(fd: Int, bootstrap: String)
    @Synchronized fun attachFromIntent(intent: Intent) {
        if (attached) return
        val selected = RuntimeSelectionCodec.decode(requireNotNull(intent.getStringExtra("runtime_selection_v1")))
        RuntimeProcessSelection.claim(selected)
        System.loadLibrary(RuntimeDispatchPolicy.library(selected))
        @Suppress("DEPRECATION")
        val fd = requireNotNull(intent.getParcelableExtra<ParcelFileDescriptor>("runtime_endpoint_v1"))
        val bootstrap = requireNotNull(intent.getStringExtra("runtime_bootstrap_v1"))
        require(bootstrap.toByteArray().size <= 65536)
        attach(fd.detachFd(), bootstrap)
        intent.removeExtra("runtime_endpoint_v1")
        intent.removeExtra("runtime_bootstrap_v1")
        attached = true
        RuntimeProcessSelection.markAdmitted()
    }
}
