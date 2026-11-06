package ru.nelomai.client

import android.content.Intent
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.util.Log

object RuntimeEntrypoint {
    private var attached = false
    private var nativeAttachAttempted = false
    private var updateLifecycle = RuntimeUpdateLifecycle()
    private var updateProtocolVersion = 1
    @Synchronized fun supportsUpdates(): Boolean = attached && updateProtocolVersion == 2
    @Synchronized fun isAttached(): Boolean = attached
    @Synchronized fun canRetryBootstrap(): Boolean = !nativeAttachAttempted
    external fun attach(fd: Int, bootstrap: String)
    external fun attachWithUpdates(fd: Int, bootstrap: String, updateProtocol: Int)
    external fun updateUi(foreground: Boolean, newUserLaunch: Boolean, session: String?, reason: Int)
    fun updateUiCreated(session: String?) { updateLifecycle.created(session) }
    fun updateUiResumed() { updateLifecycle.resume()?.let { updateUi(true, it.session != null, it.session, it.reason) } }
    fun updateUiPaused() { if (updateLifecycle.pause()) updateUi(false, false, null, 0) }
    fun updateUiStopped(changingConfigurations: Boolean) { updateLifecycle.stop(changingConfigurations) }
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
        val updateProtocol = intent.getIntExtra("nelomai_update_protocol", 1)
        if (updateProtocol == 2) attachWithUpdates(fd.detachFd(), bootstrap, 2)
        else attach(fd.detachFd(), bootstrap)
        updateProtocolVersion = if (updateProtocol == 2) 2 else 1
        Log.i("NelomaiStartup", "runtime.attach duration_ms=${SystemClock.elapsedRealtime() - started}")
        intent.removeExtra("runtime_endpoint_v1")
        intent.removeExtra("runtime_bootstrap_v1")
        intent.removeExtra("nelomai_update_protocol")
        attached = true
        RuntimeProcessSelection.markAdmitted()
    }
}

/** Process-local lifecycle survives Activity/WebView recreation. Only a real
 * stopped UI schedules a foreground check; pause immediately removes install permission. */
internal class RuntimeUpdateLifecycle {
    data class Resume(val session: String?, val reason: Int)
    private var seen = false
    private var visible = false
    private var backgrounded = false
    private var launchSession: String? = null
    fun created(session: String?) {
        if (!seen) launchSession = session?.takeIf { runCatching { java.util.UUID.fromString(it) }.isSuccess }
    }
    fun resume(): Resume? {
        if (visible) return null
        visible = true
        val result = Resume(launchSession, if (!seen) 1 else if (backgrounded) 2 else 0)
        seen = true
        launchSession = null
        backgrounded = false
        return result
    }
    fun pause(): Boolean = visible.also { visible = false }
    fun stop(changingConfigurations: Boolean) { if (!changingConfigurations) backgrounded = true }
}
