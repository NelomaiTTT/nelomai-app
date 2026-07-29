package ru.nelomai.updater

import android.app.Activity
import android.content.ClipData
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.activity.result.ActivityResult
import androidx.core.content.FileProvider
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicReference

private const val APK_MIME_TYPE = "application/vnd.android.package-archive"
private val SHA256_PATTERN = Regex("^[0-9a-f]{64}$")

@InvokeArg
class InstallApkArgs {
    lateinit var path: String
    lateinit var expectedVersion: String
    lateinit var expectedSignerSha256: String
}

private data class ValidatedApk(
    val file: File,
)

private class UpdateInstallException(val code: String) : RuntimeException()

@TauriPlugin
class UpdaterPlugin(private val activity: Activity) : Plugin(activity) {
    private val pendingInstall = AtomicReference<InstallApkArgs?>(null)

    @Command
    fun installApk(invoke: Invoke) {
        val args = try {
            invoke.parseArgs(InstallApkArgs::class.java)
        } catch (_: Throwable) {
            invoke.reject("invalid_update_request")
            return
        }

        try {
            val apk = validateApk(args)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
                !activity.packageManager.canRequestPackageInstalls()
            ) {
                if (!pendingInstall.compareAndSet(null, args)) {
                    invoke.reject("update_install_in_progress")
                    return
                }
                val settingsIntent = Intent(
                    Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                    Uri.parse("package:${activity.packageName}"),
                )
                startActivityForResult(invoke, settingsIntent, "unknownSourcesResult")
                return
            }
            openInstaller(apk, invoke)
        } catch (error: UpdateInstallException) {
            invoke.reject(error.code)
        } catch (_: Throwable) {
            invoke.reject("apk_validation_failed")
        }
    }

    @ActivityCallback
    fun unknownSourcesResult(invoke: Invoke, @Suppress("UNUSED_PARAMETER") result: ActivityResult) {
        val args = pendingInstall.getAndSet(null)
        if (args == null) {
            invoke.reject("invalid_update_request")
            return
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
            !activity.packageManager.canRequestPackageInstalls()
        ) {
            invoke.reject("install_permission_denied")
            return
        }

        try {
            openInstaller(validateApk(args), invoke)
        } catch (error: UpdateInstallException) {
            invoke.reject(error.code)
        } catch (_: Throwable) {
            invoke.reject("apk_validation_failed")
        }
    }

    private fun validateApk(args: InstallApkArgs): ValidatedApk {
        val signer = args.expectedSignerSha256.trim().lowercase()
        if (!SHA256_PATTERN.matches(signer)) {
            throw UpdateInstallException("invalid_apk_signer")
        }
        if (args.expectedVersion.isBlank() || args.expectedVersion.length > 64) {
            throw UpdateInstallException("invalid_update_version")
        }

        val updatesRoot = File(activity.cacheDir, "updates").canonicalFile
        val apk = File(args.path).canonicalFile
        if (
            !apk.isFile ||
            apk.extension.lowercase() != "apk" ||
            apk.parentFile != updatesRoot
        ) {
            throw UpdateInstallException("invalid_apk_path")
        }

        val archive = packageInfo(apk.absolutePath, archive = true)
            ?: throw UpdateInstallException("invalid_apk")
        if (archive.packageName != activity.packageName) {
            throw UpdateInstallException("apk_package_mismatch")
        }
        if (archive.versionName != args.expectedVersion) {
            throw UpdateInstallException("apk_version_mismatch")
        }

        val installed = packageInfo(activity.packageName, archive = false)
            ?: throw UpdateInstallException("installed_package_unavailable")
        val archiveSigners = signerDigests(archive)
        val installedSigners = signerDigests(installed)
        if (
            archiveSigners.isEmpty() ||
            archiveSigners != installedSigners ||
            signer !in archiveSigners
        ) {
            throw UpdateInstallException("apk_signature_mismatch")
        }
        return ValidatedApk(apk)
    }

    @Suppress("DEPRECATION")
    private fun packageInfo(value: String, archive: Boolean): PackageInfo? {
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            PackageManager.GET_SIGNING_CERTIFICATES
        } else {
            PackageManager.GET_SIGNATURES
        }
        return if (archive) {
            activity.packageManager.getPackageArchiveInfo(value, flags)
        } else {
            activity.packageManager.getPackageInfo(value, flags)
        }
    }

    @Suppress("DEPRECATION")
    private fun signerDigests(info: PackageInfo): Set<String> {
        val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            info.signingInfo?.apkContentsSigners.orEmpty()
        } else {
            info.signatures.orEmpty()
        }
        return signatures.mapTo(mutableSetOf()) { signature ->
            MessageDigest.getInstance("SHA-256")
                .digest(signature.toByteArray())
                .joinToString("") { byte -> "%02x".format(byte) }
        }
    }

    private fun openInstaller(apk: ValidatedApk, invoke: Invoke) {
        val authority = "${activity.packageName}.fileprovider"
        val uri = FileProvider.getUriForFile(activity, authority, apk.file)
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, APK_MIME_TYPE)
            clipData = ClipData.newRawUri("Nelomai update", uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        if (intent.resolveActivity(activity.packageManager) == null) {
            throw UpdateInstallException("apk_installer_unavailable")
        }
        activity.startActivity(intent)
        val response = JSObject()
        response.put("installerOpened", true)
        invoke.resolve(response)
    }
}
