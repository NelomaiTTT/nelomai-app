package ru.nelomai.client

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import ru.nelomai.runtime.v1.SupportDiagnosticsEntry
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory

@RunWith(org.robolectric.RobolectricTestRunner::class)
@Config(sdk = [28])
class SupportDiagnosticsActivityTest {
    @Test fun verboseButtonsControlRealCollectorWithoutLoginUploadOrExtendingOnRecreation() {
        val controller = Robolectric.buildActivity(SupportDiagnosticsActivity::class.java).setup()
        val activity = controller.get()
        val root = File(activity.cacheDir, "timed-logcat").apply { mkdirs() }
        var now = 100L
        val capture = ru.nelomai.runtime.v1.LogcatCapture(ru.nelomai.runtime.v1.LogcatJournal(root)) { now }
        val field = ru.nelomai.runtime.v1.PersistentLogcat::class.java.getDeclaredField("capture").apply { isAccessible = true }
        val old = field.get(null)
        field.set(null, capture)
        try {
            val start = activity.findViewById<Button>(0x00d10006)
            val stop = activity.findViewById<Button>(0x00d10007)
            assertNotNull("pre-login screen needs verbose start", start)
            assertNotNull("pre-login screen needs verbose stop", stop)
            start.performClick()
            assertTrue(capture.status().active)
            assertFalse(start.isEnabled); assertTrue(stop.isEnabled)
            assertNull(shadowOf(activity.application).nextStartedService)
            assertEquals("", activity.findViewById<EditText>(SupportDiagnosticsActivity.CODE_FIELD).text.toString())
            assertTrue(activity.findViewById<android.widget.TextView>(SupportDiagnosticsActivity.STATUS_VIEW).text.contains("не собран"))
            now += 60_000
            controller.pause().stop().destroy()
            val reopened = Robolectric.buildActivity(SupportDiagnosticsActivity::class.java).setup()
            assertEquals(840_000L, capture.status().remainingMillis)
            assertFalse(reopened.get().findViewById<Button>(0x00d10006).isEnabled)
            reopened.get().findViewById<Button>(0x00d10007).performClick()
            assertFalse(capture.status().active)
            assertTrue(reopened.get().findViewById<Button>(0x00d10006).isEnabled)
            reopened.pause().stop().destroy()
        } finally { field.set(null, old) }
    }

    @Test fun verboseScreenShowsExpiryAndDoesNotPretendAnAbsentCollectorStarted() {
        val field = ru.nelomai.runtime.v1.PersistentLogcat::class.java.getDeclaredField("capture").apply { isAccessible = true }
        val old = field.get(null)
        field.set(null, null)
        val controller = Robolectric.buildActivity(SupportDiagnosticsActivity::class.java).setup()
        try {
            val activity = controller.get()
            val start = activity.findViewById<Button>(0x00d10006)
            assertNotNull(start)
            start.performClick()
            assertFalse(ru.nelomai.runtime.v1.PersistentLogcat.verboseStatus().active)
            assertFalse(activity.findViewById<Button>(0x00d10007).isEnabled)
            assertTrue(activity.findViewById<android.widget.TextView>(0x00d10008).text.contains("недоступен"))
            var now = 0L
            val capture = ru.nelomai.runtime.v1.LogcatCapture(ru.nelomai.runtime.v1.LogcatJournal(File(activity.cacheDir, "expiry-logcat"))) { now }
            field.set(null, capture)
            start.performClick()
            now = 900_000
            shadowOf(android.os.Looper.getMainLooper()).idleFor(java.time.Duration.ofSeconds(1))
            assertFalse(activity.findViewById<Button>(0x00d10007).isEnabled)
            assertTrue(start.isEnabled)
        } finally { controller.pause().stop().destroy(); field.set(null, old) }
    }

    @Test fun screenNeedsNoRuntimeAndDoesNotRestoreSupportCode() {
        val controller = Robolectric.buildActivity(SupportDiagnosticsActivity::class.java).setup()
        val activity = controller.get()
        val code = activity.findViewById<EditText>(SupportDiagnosticsActivity.CODE_FIELD)
        assertNotNull(code)
        assertFalse(code.isSaveEnabled)
        code.setText("never-save-this-code")
        val state = Bundle()
        controller.saveInstanceState(state)
        assertFalse(state.toString().contains("never-save-this-code"))
        controller.pause().stop().destroy()
        val restored = Robolectric.buildActivity(SupportDiagnosticsActivity::class.java).create(state).start().resume().visible().get()
        assertEquals("", restored.findViewById<EditText>(SupportDiagnosticsActivity.CODE_FIELD).text.toString())
        assertNotNull(restored.findViewById<Button>(SupportDiagnosticsActivity.SAVE_BUTTON))
        assertNotNull(restored.findViewById<Button>(SupportDiagnosticsActivity.SHARE_BUTTON))
        assertNull(shadowOf(activity.application).nextStartedService)
    }

    @Test fun emptyCodeDoesNotUploadOrStartAnAccountService() {
        val activity = Robolectric.buildActivity(SupportDiagnosticsActivity::class.java).setup().get()
        activity.findViewById<Button>(SupportDiagnosticsActivity.SEND_BUTTON).performClick()
        assertNull(shadowOf(activity.application).nextStartedService)
        assertNull(shadowOf(activity).nextStartedActivity)
        assertTrue(activity.findViewById<android.widget.TextView>(SupportDiagnosticsActivity.STATUS_VIEW).text.contains("код"))
    }

    @Test fun entryCreatesOnlyAnExplicitContainerIntentAndRejectsRemoteWebOrigins() {
        val activity = Robolectric.buildActivity(Activity::class.java).setup().get()
        SupportDiagnosticsEntry.open(activity)
        val launch = shadowOf(activity).nextStartedActivity
        assertEquals("ru.nelomai.client.SupportDiagnosticsActivity", launch.component?.className)
        assertNull(launch.extras)
        assertTrue(SupportDiagnosticsEntry.isShortcut(Intent().putExtra("nelomai_support_diagnostics", true)))
        assertFalse(SupportDiagnosticsEntry.isShortcut(Intent().putExtra("support_code", "ignored")))
        assertTrue(SupportDiagnosticsEntry.trustedWebOrigin("https://tauri.localhost/index.html"))
        assertTrue(SupportDiagnosticsEntry.trustedWebOrigin("http://tauri.localhost/"))
        assertFalse(SupportDiagnosticsEntry.trustedWebOrigin("https://tauri.localhost.evil.invalid/"))
        assertFalse(SupportDiagnosticsEntry.trustedWebOrigin("https://nelomai.ru/"))
    }

    @Test fun packagedShortcutResolvesToLauncherAndDiagnosticsActivityIsPrivate() {
        val root = sequenceOf(File("../.."), File("../../../.."), File("../../../../..")).first {
            File(it, "src-tauri/gen/android/app/src/main/AndroidManifest.xml").isFile
        }
        val factory = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = true }
        val manifest = factory.newDocumentBuilder().parse(File(root, "src-tauri/gen/android/app/src/main/AndroidManifest.xml"))
        val android = "http://schemas.android.com/apk/res/android"
        val activities = manifest.getElementsByTagName("activity")
        val diagnostics = (0 until activities.length).map { activities.item(it) as org.w3c.dom.Element }
            .firstOrNull { it.getAttributeNS(android, "name") == ".SupportDiagnosticsActivity" }
        assertNotNull("private container activity must be registered", diagnostics)
        assertEquals("false", diagnostics!!.getAttributeNS(android, "exported"))
        assertEquals("", diagnostics.getAttributeNS(android, "process"))
        val shortcuts = factory.newDocumentBuilder().parse(File(root, "src-tauri/gen/android/app/src/main/res/xml/shortcuts.xml"))
        val intent = shortcuts.getElementsByTagName("intent").item(0) as org.w3c.dom.Element
        assertEquals("ru.nelomai.client.MainActivity", intent.getAttributeNS(android, "targetClass"))
        val extra = intent.getElementsByTagName("extra").item(0) as org.w3c.dom.Element
        assertEquals("nelomai_support_diagnostics", extra.getAttributeNS(android, "name"))
        assertEquals("true", extra.getAttributeNS(android, "value"))
    }

    @Test fun startupFailureOffersPrivateDiagnosticsAndLogsOnlyExactStageWithoutExceptionSecrets() {
        val activity = Robolectric.buildActivity(Activity::class.java).setup().get()
        SupportDiagnosticsStartup.showFailure(activity, SupportStartupStage.LAUNCHER_OWNER_READ,
            IllegalStateException("password=do-not-log support-code=do-not-log"))
        val messages = org.robolectric.shadows.ShadowLog.getLogsForTag("NelomaiStartup").map { it.msg }
        assertTrue(messages.any { it.contains("startup.launcher.owner_read_failed") })
        assertFalse(messages.any { it.contains("do-not-log") })
        activity.findViewById<Button>(SupportDiagnosticsStartup.OPEN_BUTTON).performClick()
        assertEquals("ru.nelomai.client.SupportDiagnosticsActivity", shadowOf(activity).nextStartedActivity.component?.className)
        assertNull(shadowOf(activity.application).nextStartedService)
    }

    @Test fun localSaveWorksWithoutACodeAndWritesTheFrozenSanitizedPayload() {
        val activity = Robolectric.buildActivity(SupportDiagnosticsActivity::class.java).setup().get()
        val log = File(activity.filesDir, "runtime/stable/state/0.2.20/diagnostics/application.jsonl")
        requireNotNull(log.parentFile).mkdirs(); log.writeText("password=never-export\nstable_owner_unavailable\n")
        activity.findViewById<Button>(SupportDiagnosticsActivity.SAVE_BUTTON).performClick()
        await { shadowOf(activity).peekNextStartedActivity() != null }
        val intent = shadowOf(activity).nextStartedActivity
        assertEquals(Intent.ACTION_CREATE_DOCUMENT, intent.action)
        assertEquals("application/json", intent.type)
        assertTrue(intent.categories.contains(Intent.CATEGORY_OPENABLE))
        val saved = File(activity.cacheDir, "saved-diagnostics.json")
        shadowOf(activity).receiveResult(intent, Activity.RESULT_OK, Intent().setData(Uri.fromFile(saved)))
        await { saved.isFile && saved.length() > 0 }
        val payload = saved.readText()
        assertTrue(payload.contains("stable_owner_unavailable"))
        assertFalse(payload.contains("never-export"))
        val id = org.json.JSONObject(payload).getString("report_id")
        assertEquals("nelomai-diagnostics-$id.json", intent.getStringExtra(Intent.EXTRA_TITLE))
        assertNull(shadowOf(activity.application).nextStartedService)
    }

    @Test fun documentPickerKeepsTheReportFrozenAndDisablesNewCollectionUntilResult() {
        val activity = Robolectric.buildActivity(SupportDiagnosticsActivity::class.java).setup().get()
        activity.findViewById<Button>(SupportDiagnosticsActivity.SAVE_BUTTON).performClick()
        await { shadowOf(activity).peekNextStartedActivity() != null }
        assertFalse(activity.findViewById<Button>(SupportDiagnosticsActivity.SEND_BUTTON).isEnabled)
        assertFalse(activity.findViewById<Button>(SupportDiagnosticsActivity.SAVE_BUTTON).isEnabled)
        val picker = shadowOf(activity).nextStartedActivity
        shadowOf(activity).receiveResult(picker, Activity.RESULT_CANCELED, null)
        assertTrue(activity.findViewById<Button>(SupportDiagnosticsActivity.SAVE_BUTTON).isEnabled)
        assertTrue(activity.findViewById<android.widget.TextView>(SupportDiagnosticsActivity.STATUS_VIEW).text.contains("local_save_cancelled"))
    }

    @Test fun shareGrantsOnlyTheSanitizedJsonSnapshotAndNeverExportsAnAccountFile() {
        val activity = Robolectric.buildActivity(SupportDiagnosticsActivity::class.java).setup().get()
        val log = File(activity.filesDir, "runtime/latest/state/0.3.2/diagnostics/application.jsonl")
        requireNotNull(log.parentFile).mkdirs(); log.writeText("install_secret=never-share\nowner_failed\n")
        activity.findViewById<Button>(SupportDiagnosticsActivity.SHARE_BUTTON).performClick()
        await { shadowOf(activity).peekNextStartedActivity() != null }
        val chooser = shadowOf(activity).nextStartedActivity
        assertEquals(Intent.ACTION_CHOOSER, chooser.action)
        @Suppress("DEPRECATION")
        val share = chooser.getParcelableExtra<Intent>(Intent.EXTRA_INTENT)!!
        assertEquals(Intent.ACTION_SEND, share.action)
        assertEquals("application/json", share.type)
        assertEquals(Intent.FLAG_GRANT_READ_URI_PERMISSION, share.flags and Intent.FLAG_GRANT_READ_URI_PERMISSION)
        @Suppress("DEPRECATION")
        val uri = share.getParcelableExtra<Uri>(Intent.EXTRA_STREAM)!!
        assertEquals("${activity.packageName}.fileprovider", uri.authority)
        assertTrue(uri.path!!.startsWith("/support_diagnostics/"))
        val body = activity.contentResolver.openInputStream(uri)!!.bufferedReader().use { it.readText() }
        assertTrue(body.contains("owner_failed"))
        assertFalse(body.contains("never-share"))
        assertEquals(org.json.JSONObject(body).getString("report_id") + ".json", uri.lastPathSegment)
        assertNull(shadowOf(activity.application).nextStartedService)
    }

    private fun await(condition: () -> Boolean) {
        val deadline = System.nanoTime() + 3_000_000_000L
        while (!condition() && System.nanoTime() < deadline) {
            shadowOf(android.os.Looper.getMainLooper()).idle()
            Thread.sleep(10)
        }
        shadowOf(android.os.Looper.getMainLooper()).idle()
        assertTrue("operation did not finish within 3 seconds", condition())
    }
}
