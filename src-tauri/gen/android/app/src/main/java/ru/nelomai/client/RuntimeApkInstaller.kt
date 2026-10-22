package ru.nelomai.client

import android.app.Activity
import android.content.ClipData
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.core.content.FileProvider
import java.io.File
import java.lang.ref.WeakReference
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeoutException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

internal object RuntimeApkValidation {
    fun path(root: File, value: String): File = File(value).canonicalFile.also {
        require(it.isFile && it.extension.lowercase() == "apk" && it.parentFile == root.canonicalFile) { "invalid_apk_path" }
    }
    fun signers(archive: Set<String>, installed: Set<String>, expected: String): Boolean =
        expected.matches(Regex("[0-9a-f]{64}")) && archive.isNotEmpty() && archive == installed && expected in archive
}

internal class RuntimeInstallerLifecycle {
    private var dispatched = false
    private var pausedAfterDispatch = false
    private var returnReported = false

    fun markDispatched() { dispatched = true }
    fun onPause() { if (dispatched) pausedAfterDispatch = true }
    fun onResume(): Boolean {
        if (!pausedAfterDispatch || returnReported) return false
        returnReported = true
        return true
    }
}

internal fun installerFailureCode(error: Throwable): String = when (error) {
    is TimeoutException -> "installer_wait_timeout"
    is SecurityException -> "installer_security_error"
    is IllegalArgumentException, is IllegalStateException ->
        error.message?.takeIf { it.matches(Regex("[a-z0-9_]{1,64}")) } ?: "installer_validation_failed"
    else -> "installer_open_failed"
}

/** Arguments never cross the runtime channel or an Intent. Only this common
 * process holds the download path and the install continuation. */
internal object RuntimeApkInstaller {
    data class Request(val path: String, val version: String, val signer: String,
        val nonce: String = UUID.randomUUID().toString(), val result: CompletableFuture<Boolean> = CompletableFuture())
    private val pending = AtomicReference<Request?>(null)
    fun install(context: Context, path: String, version: String, signer: String): Boolean {
        val request = Request(path, version, signer)
        check(pending.compareAndSet(null, request)) { "update_install_in_progress" }
        StartupDiagnostics.record(context, "update.android.install_requested")
        return try {
            context.startActivity(Intent(context, RuntimeApkInstallerActivity::class.java)
                .putExtra("request", request.nonce).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            StartupDiagnostics.record(context, "update.android.installer_activity_dispatched")
            request.result.get(15, TimeUnit.MINUTES).also { installed ->
                StartupDiagnostics.record(
                    context,
                    if (installed) "update.android.installer_succeeded"
                    else "update.android.installer_cancelled",
                )
            }
        } catch (error: Throwable) {
            // Invalidate the request before recovery can resume the old runtime.
            // A late permission/result callback must not dispatch another install.
            request.result.completeExceptionally(error)
            StartupDiagnostics.recordCode(
                context,
                "update.android.install_failed",
                installerFailureCode(error),
            )
            throw error
        } finally { pending.compareAndSet(request, null) }
    }
    fun request(nonce: String?): Request? = pending.get()?.takeIf { nonce != null && it.nonce == nonce }
}

/** Common non-exported installer; stable AAR contributes no provider or installer. */
class RuntimeApkInstallerActivity : Activity() {
    private var request: RuntimeApkInstaller.Request? = null
    private val installerLifecycle = RuntimeInstallerLifecycle()
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        StartupDiagnostics.record(this, "update.android.installer_activity_created")
        request = RuntimeApkInstaller.request(intent.getStringExtra("request"))
        if (request == null) {
            StartupDiagnostics.recordCode(this, "update.android.installer_activity_failed", "request_missing")
            finish()
            return
        }
        val activity = WeakReference(this)
        request!!.result.whenComplete { _, failure ->
            if (failure != null) activity.get()?.let { host -> host.runOnUiThread {
                if (!host.isDestroyed && !host.isFinishing) {
                    host.finishActivity(2)
                    host.finishActivity(1)
                    host.finish()
                }
            } }
        }
        if (state != null) {
            StartupDiagnostics.record(this, "update.android.installer_activity_recreated")
            return
        }
        try {
            validate(requireNotNull(request))
            StartupDiagnostics.record(this, "update.android.package_validated")
            if (Build.VERSION.SDK_INT >= 26 && !packageManager.canRequestPackageInstalls()) {
                StartupDiagnostics.record(this, "update.android.unknown_sources_requested")
                @Suppress("DEPRECATION")
                startActivityForResult(Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:$packageName")), 1)
            } else openInstaller()
        } catch (error: Throwable) { fail(error) }
    }
    @Deprecated("Android callback")
    override fun onActivityResult(code: Int, result: Int, data: Intent?) {
        super.onActivityResult(code, result, data)
        if (code != 1 && code != 2) return
        try {
            val value = activeRequest()
            if (code == 1) {
                StartupDiagnostics.record(this, "update.android.unknown_sources_returned")
                if (Build.VERSION.SDK_INT >= 26 && !packageManager.canRequestPackageInstalls()) {
                    StartupDiagnostics.recordCode(this, "update.android.installer_cancelled", "unknown_sources_denied")
                    complete(false)
                } else openInstaller()
            } else when (result) {
                RESULT_CANCELED -> complete(false)
                RESULT_OK -> {
                    validate(value)
                    check(packageInfo(packageName, false)?.versionName == value.version) { "installed_version_mismatch" }
                    complete(true)
                }
                else -> error("installer_result_failed")
            }
        } catch (error: Throwable) { fail(error) }
    }
    private fun complete(opened: Boolean) { request?.result?.complete(opened); finish() }
    private fun fail(error: Throwable) {
        StartupDiagnostics.recordCode(
            this,
            "update.android.installer_activity_failed",
            installerFailureCode(error),
        )
        request?.result?.completeExceptionally(error)
        finish()
    }
    override fun onPause() {
        installerLifecycle.onPause()
        super.onPause()
    }
    override fun onResume() {
        super.onResume()
        if (installerLifecycle.onResume()) {
            // Returning alone is not an install result. Wait for Android's callback.
            StartupDiagnostics.record(this, "update.android.installer_activity_returned")
        }
    }
    override fun onDestroy() {
        if (isFinishing && request?.result?.isDone == false) {
            StartupDiagnostics.recordCode(this, "update.android.installer_activity_failed", "activity_destroyed")
            request?.result?.complete(false)
        }
        super.onDestroy()
    }
    private fun validate(value: RuntimeApkInstaller.Request): File {
        require(value.version.isNotBlank() && value.version.length <= 64) { "invalid_version" }
        val file = RuntimeApkValidation.path(File(cacheDir, "updates"), value.path)
        val archive = requireNotNull(packageInfo(file.absolutePath, true)) { "archive_info_missing" }
        require(archive.packageName == packageName && archive.versionName == value.version) { "package_mismatch" }
        val installed = requireNotNull(packageInfo(packageName, false)) { "installed_info_missing" }
        val archiveSigners = signers(archive)
        require(archiveSigners.isNotEmpty()) { "archive_signers_missing" }
        val installedSigners = signers(installed)
        require(installedSigners.isNotEmpty()) { "installed_signers_missing" }
        require(RuntimeApkValidation.signers(archiveSigners, installedSigners, value.signer.trim().lowercase())) { "signer_mismatch" }
        return file
    }
    @Suppress("DEPRECATION")
    private fun packageInfo(value: String, archive: Boolean): PackageInfo? {
        var flags = if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES
        // Android 9/10 only collect archive certificates when GET_SIGNATURES is set.
        if (archive && Build.VERSION.SDK_INT in 28..29) flags = flags or PackageManager.GET_SIGNATURES
        return if (archive) packageManager.getPackageArchiveInfo(value, flags) else packageManager.getPackageInfo(value, flags)
    }
    @Suppress("DEPRECATION")
    private fun signers(info: PackageInfo): Set<String> {
        val values = if (Build.VERSION.SDK_INT >= 28) info.signingInfo?.apkContentsSigners.orEmpty() else info.signatures.orEmpty()
        return values.mapTo(mutableSetOf()) { signature -> MessageDigest.getInstance("SHA-256")
            .digest(signature.toByteArray()).joinToString("") { "%02x".format(it) } }
    }
    private fun activeRequest(): RuntimeApkInstaller.Request = requireNotNull(request).also {
        check(RuntimeApkInstaller.request(it.nonce) === it && !it.result.isDone) { "request_expired" }
    }
    @Suppress("DEPRECATION")
    private fun openInstaller() {
        // Revalidate after unknown-sources permission UI; no stale package proof.
        val file = validate(activeRequest())
        val uri = FileProvider.getUriForFile(this, "$packageName.fileprovider", file)
        val intent = Intent(Intent.ACTION_INSTALL_PACKAGE).apply {
            setDataAndType(uri, "application/vnd.android.package-archive")
            clipData = ClipData.newRawUri("Nelomai update", uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            putExtra(Intent.EXTRA_RETURN_RESULT, true)
        }
        activeRequest()
        startActivityForResult(intent, 2)
        installerLifecycle.markDispatched()
        StartupDiagnostics.record(this, "update.android.installer_intent_dispatched")
    }
}
