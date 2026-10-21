package ru.nelomai.client

import android.app.Activity
import android.content.Intent
import android.content.pm.ActivityInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.ResolveInfo
import android.content.pm.Signature
import android.content.pm.SigningInfo
import android.os.Bundle
import android.os.Looper
import android.provider.Settings
import androidx.core.content.FileProvider
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicReference
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.util.ReflectionHelpers

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
@Suppress("DEPRECATION")
class RuntimeApkInstallerTest {
    @Suppress("UNCHECKED_CAST")
    private fun pending() = RuntimeApkInstaller::class.java.getDeclaredField("pending").let {
        it.isAccessible = true
        it.get(RuntimeApkInstaller) as AtomicReference<RuntimeApkInstaller.Request?>
    }

    @Before @After fun clearRequest() {
        pending().set(null)
        // AndroidX caches canonical roots across Robolectric's per-test data dirs.
        val cache = FileProvider::class.java.getDeclaredField("sCache").apply { isAccessible = true }
        (cache.get(null) as MutableMap<*, *>).clear()
    }

    private fun signing(signature: Signature): SigningInfo =
        ReflectionHelpers.callConstructor(SigningInfo::class.java).also { shadowOf(it).setSignatures(arrayOf(signature)) }

    private fun request(permission: Boolean = true): RuntimeApkInstaller.Request {
        val context = RuntimeEnvironment.getApplication()
        val manager = shadowOf(context.packageManager)
        val signature = Signature(byteArrayOf(1, 2, 3))
        @Suppress("DEPRECATION")
        val installed = shadowOf(context.packageManager).getInternalMutablePackageInfo(context.packageName)
        installed.versionName = "0.3.6"
        installed.signatures = arrayOf(signature)
        installed.signingInfo = signing(signature)
        val file = File(context.cacheDir, "updates/update.apk").canonicalFile.apply {
            parentFile!!.mkdirs()
            writeBytes(byteArrayOf(1))
        }
        manager.setPackageArchiveInfo(file.path, PackageInfo().apply {
            packageName = context.packageName
            versionName = "0.3.7"
            signatures = arrayOf(signature)
            signingInfo = signing(signature)
        })
        manager.setCanRequestPackageInstalls(permission)
        val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
        @Suppress("DEPRECATION")
        for (action in listOf(Intent.ACTION_VIEW, Intent.ACTION_INSTALL_PACKAGE)) {
            manager.addResolveInfoForIntent(Intent(action).setDataAndType(uri, "application/vnd.android.package-archive"),
                ResolveInfo().apply { activityInfo = ActivityInfo().apply {
                    packageName = "com.android.packageinstaller"
                    name = "Installer"
                    exported = true
                } })
        }
        val signer = MessageDigest.getInstance("SHA-256").digest(signature.toByteArray())
            .joinToString("") { "%02x".format(it) }
        return RuntimeApkInstaller.Request(file.path, "0.3.7", signer).also { pending().set(it) }
    }

    private fun launch(request: RuntimeApkInstaller.Request) = Robolectric.buildActivity(
        RuntimeApkInstallerActivity::class.java, Intent().putExtra("request", request.nonce),
    ).setup()

    @Test fun installerDispatchWaitsForSystemResultAndCancelCompletesOnlyItsRequest() {
        val request = request()
        val controller = launch(request)
        val activity = controller.get()
        val started = shadowOf(activity).nextStartedActivityForResult
        assertNotNull(org.robolectric.shadows.ShadowLog.getLogsForTag("NelomaiStartup").joinToString { it.msg }, started)
        assertNotNull(started)
        assertTrue(started.requestCode >= 0)
        assertTrue(started.intent.getBooleanExtra(Intent.EXTRA_RETURN_RESULT, false))
        assertFalse("opening the installer is not an installation result", request.result.isDone)
        shadowOf(activity).callOnActivityResult(started.requestCode, Activity.RESULT_CANCELED, null)
        assertFalse(request.result.get(1, TimeUnit.SECONDS))
        assertTrue(activity.isFinishing)
        controller.pause().stop().destroy()
    }

    @Test fun permissionReturnRevalidatesApkAndDoesNotDispatchIfSignerChanged() {
        val request = request(permission = false)
        val activity = launch(request).get()
        val permission = shadowOf(activity).nextStartedActivityForResult
        assertEquals(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, permission.intent.action)
        val context = RuntimeEnvironment.getApplication()
        val manager = shadowOf(context.packageManager)
        manager.setCanRequestPackageInstalls(true)
        manager.setPackageArchiveInfo(request.path, PackageInfo().apply {
            packageName = context.packageName
            versionName = request.version
            signatures = arrayOf(Signature(byteArrayOf(9)))
            signingInfo = signing(Signature(byteArrayOf(9)))
        })
        shadowOf(activity).callOnActivityResult(permission.requestCode, Activity.RESULT_OK, null)
        assertTrue(request.result.isCompletedExceptionally)
        assertNull(shadowOf(activity).nextStartedActivityForResult)
    }

    @Test fun reportedSuccessRequiresInstalledVersionAndSigner() {
        val request = request()
        val activity = launch(request).get()
        val started = shadowOf(activity).nextStartedActivityForResult
        assertNotNull(org.robolectric.shadows.ShadowLog.getLogsForTag("NelomaiStartup").joinToString { it.msg }, started)
        shadowOf(activity).callOnActivityResult(started.requestCode, Activity.RESULT_OK, null)
        assertTrue("old installed package cannot prove update success", request.result.isCompletedExceptionally)
    }

    @Test fun matchingInstalledPackageConfirmsSuccessfulResult() {
        val request = request()
        val activity = launch(request).get()
        val started = shadowOf(activity).nextStartedActivityForResult
        assertNotNull(org.robolectric.shadows.ShadowLog.getLogsForTag("NelomaiStartup").joinToString { it.msg }, started)
        val context = RuntimeEnvironment.getApplication()
        @Suppress("DEPRECATION")
        val installed = shadowOf(context.packageManager).getInternalMutablePackageInfo(context.packageName)
        installed.versionName = request.version
        shadowOf(activity).callOnActivityResult(started.requestCode, Activity.RESULT_OK, null)
        assertTrue(request.result.get(1, TimeUnit.SECONDS))
    }

    @Test fun returnOrRecreationDoesNotGuessCancellationOrLosePendingRequest() {
        val request = request()
        val controller = launch(request)
        assertFalse(request.result.isDone)
        assertNotNull(shadowOf(controller.get()).nextStartedActivityForResult)
        controller.pause().stop()
        val state = Bundle()
        controller.saveInstanceState(state).destroy()
        assertFalse(request.result.isDone)
        val restored = Robolectric.buildActivity(RuntimeApkInstallerActivity::class.java,
            Intent().putExtra("request", request.nonce)).setup(state)
        assertFalse(request.result.isDone)
        assertNull(shadowOf(restored.get()).nextStartedActivityForResult)
        shadowOf(restored.get()).callOnActivityResult(2, Activity.RESULT_CANCELED, null)
        assertFalse(request.result.get(1, TimeUnit.SECONDS))
    }

    @Test fun expiredRequestCannotOpenInstallerAfterPermissionReturn() {
        val request = request(permission = false)
        val activity = launch(request).get()
        val permission = shadowOf(activity).nextStartedActivityForResult
        request.result.completeExceptionally(TimeoutException())
        shadowOf(Looper.getMainLooper()).idle()
        assertTrue(activity.isFinishing)
        shadowOf(RuntimeEnvironment.getApplication().packageManager).setCanRequestPackageInstalls(true)
        shadowOf(activity).callOnActivityResult(permission.requestCode, Activity.RESULT_OK, null)
        assertNull(shadowOf(activity).nextStartedActivityForResult)
    }

    @Test fun oldPermissionResultCannotDispatchOrCompleteANewerRequest() {
        val old = request(permission = false)
        val activity = launch(old).get()
        val permission = shadowOf(activity).nextStartedActivityForResult
        val current = request()
        shadowOf(activity).callOnActivityResult(permission.requestCode, Activity.RESULT_OK, null)
        assertTrue(old.result.isCompletedExceptionally)
        assertFalse(current.result.isDone)
        assertSame(current, pending().get())
        assertNull(shadowOf(activity).nextStartedActivityForResult)
    }
}
