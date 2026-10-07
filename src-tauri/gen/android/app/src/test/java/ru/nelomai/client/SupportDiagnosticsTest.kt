package ru.nelomai.client

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import java.net.URL
import java.security.Principal
import java.security.cert.Certificate
import javax.net.ssl.HttpsURLConnection

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28], manifest = Config.NONE)
class SupportDiagnosticsTest {
    private val uploadCode = "nld_" + "A".repeat(43)
    private fun roots(test: (File, File) -> Unit) {
        val root = Files.createTempDirectory("support-diagnostics").toFile()
        try { test(File(root, "files").apply { mkdirs() }, File(root, "no_backup").apply { mkdirs() }) }
        finally { root.deleteRecursively() }
    }
    private fun log(files: File, name: String, text: String): File = File(files, name).apply {
        requireNotNull(parentFile).mkdirs(); writeText(text)
    }

    @Test fun frozenReportUsesManualContractAndNeverInventsActiveRuntime() = roots { files, backup ->
        val source = log(files, "runtime/stable/state/0.2.20/diagnostics/application.jsonl", "owner_unavailable\n")
        val report = SupportDiagnosticCollector(files, backup, "Android 16").collect("fake-support-code")
        val original = report.payload
        source.writeText("changed after collection\n")
        val body = JSONObject(report.payload)
        assertEquals("manual", body.getString("trigger"))
        assertEquals("0.3.2", body.getString("app_version"))
        assertFalse(body.has("platform"))
        assertEquals("aarch64", body.getString("architecture"))
        assertEquals("Android 16", body.getString("platform_version"))
        assertEquals(report.reportId, java.util.UUID.fromString(body.getString("report_id")).toString())
        assertTrue(body.getLong("generated_at_unix") > 0)
        assertTrue(body.getString("application_log").contains("owner_unavailable"))
        assertFalse(body.has("runtime_slot"))
        assertFalse(body.has("session_generation"))
        assertFalse(body.has("tunnel_running"))
        assertFalse(original.contains("fake-support-code"))
        assertEquals(original, report.payload)
        assertNotEquals(report.reportId, SupportDiagnosticCollector(files, backup, null).collect("").reportId)
    }

    @Test fun payloadHasExactlyThePanelSupportRequestKeysFromTheContractFixture() = roots { files, backup ->
        val fixture = javaClass.getResourceAsStream("/support-diagnostics-request.json")!!.use {
            JSONObject(it.bufferedReader(Charsets.UTF_8).readText())
        }
        val body = JSONObject(SupportDiagnosticCollector(files, backup, "Android 13 (API 33)").collect("").payload)
        assertEquals(fixture.keys().asSequence().toSet(), body.keys().asSequence().toSet())
        for (field in listOf("trigger", "app_version", "architecture", "platform_version")) {
            assertEquals(fixture.getString(field), body.getString(field))
        }
        assertEquals(4, java.util.UUID.fromString(body.getString("report_id")).version())
        assertTrue(body.getLong("generated_at_unix") > 0)
        for (field in listOf("application_log", "helper_log", "logcat_log")) assertTrue(body.get(field) is String)
    }

    @Test fun collectorReadsOnlyExactLogsAndRejectsSymlinksWithoutWritingAnything() = roots { files, backup ->
        val forbidden = log(files, "runtime/latest/state/0.3.2/auth.json", "DO_NOT_EXPORT_AUTH")
        log(files, "runtime/latest/state/0.3.3/diagnostics/application.jsonl", "DO_NOT_EXPORT_033")
        val link = File(files, "runtime/latest/state/0.3.2/diagnostics/application.jsonl")
        requireNotNull(link.parentFile).mkdirs(); Files.createSymbolicLink(link.toPath(), forbidden.toPath())
        log(files, "runtime/stable/state/0.2.20/diagnostics/android-tunnel.jsonl", "vpn_permission_cancelled\n")
        log(backup, "diagnostics/logcat/logcat.log", "runtime_owner_unavailable\n")
        val before = files.walkTopDown().map { it.relativeTo(files).path }.toList()
        val payload = SupportDiagnosticCollector(files, backup, null).collect("").payload
        assertFalse(payload.contains("DO_NOT_EXPORT"))
        assertTrue(payload.contains("unavailable"))
        assertTrue(payload.contains("vpn_permission_cancelled"))
        assertTrue(payload.contains("runtime_owner_unavailable"))
        assertEquals(before, files.walkTopDown().map { it.relativeTo(files).path }.toList())
        assertFalse(File(backup, "diagnostics/logcat/journal.lock").exists())
    }

    @Test fun sanitizerRemovesCredentialsKeysSupportCodeAndUrlSecrets() = roots { files, backup ->
        val secrets = listOf("hunter2", "access-secret", "install-secret", "wg-secret", "support-secret", "free-code-123")
        log(files, "runtime/latest/state/0.3.2/diagnostics/application.jsonl", """
            stage=login_failed password=hunter2
            {"access_token":"access-secret"}
            install_secret=install-secret
            PrivateKey = wg-secret
            X-Nelomai-Diagnostics-Code: support-secret
            ordinary message free-code-123
            https://user:pass@example.invalid/path?token=query-secret
            Authorization: Bearer bearer-secret
            token=generic-secret
            Cookie: cookie-secret
            safe_stage=vpn_permission_cancelled
        """.trimIndent())
        val payload = SupportDiagnosticCollector(files, backup, null).collect("free-code-123").payload
        for (secret in secrets + listOf("query-secret", "bearer-secret", "generic-secret", "cookie-secret")) {
            assertFalse("leaked $secret", payload.contains(secret))
        }
        assertTrue(payload.contains("vpn_permission_cancelled"))
    }

    @Test fun oversizedPartialLinesAreOmittedAndUtf8PayloadStaysBounded() = roots { files, backup ->
        log(files, "runtime/latest/state/0.3.2/diagnostics/application.jsonl", "password=" + "s".repeat(500_000) + "\nfinal_stage\n")
        log(backup, "diagnostics/logcat/logcat.log", "Я".repeat(500_000))
        val report = SupportDiagnosticCollector(files, backup, null).collect("")
        assertTrue(report.payload.toByteArray().size <= 768 * 1024)
        assertFalse(report.payload.contains("ssssssss"))
        assertTrue(report.payload.contains("final_stage"))
        assertFalse(report.payload.contains("\uFFFD"))
    }

    @Test fun fullRotatedLogsPreserveTheLatestRecordFromEverySource() = roots { files, backup ->
        val directories = listOf("runtime/latest/state/0.3.2/diagnostics", "runtime/stable/state/0.2.20/diagnostics", "diagnostics")
        val markers = mutableListOf<Pair<String, String>>()
        for ((index, directory) in directories.withIndex()) {
            for (name in listOf("android-startup.jsonl", "application.previous.jsonl", "application.jsonl", "auth-refresh.previous.jsonl", "auth-refresh.jsonl", "android-tunnel.previous.jsonl", "android-tunnel.jsonl")) {
                val marker = "last-$index-$name"
                log(files, "$directory/$name", "старое событие\n".repeat(4000) + "$marker\n")
                markers += (if (name.startsWith("android-tunnel")) "helper_log" else "application_log") to marker
            }
        }
        for (name in listOf("logcat.previous.log", "logcat.log")) {
            val marker = "last-$name"
            log(backup, "diagnostics/logcat/$name", "старое событие\n".repeat(6000) + "$marker\n")
            markers += "logcat_log" to marker
        }
        val body = JSONObject(SupportDiagnosticCollector(files, backup, null).collect("").payload)
        for ((field, marker) in markers) assertTrue("missing $marker", body.getString(field).contains(marker))
        for ((field, limit) in listOf("application_log" to 96*1024, "helper_log" to 64*1024, "logcat_log" to 96*1024)) {
            val value = body.getString(field)
            assertTrue("oversized $field", value.toByteArray(Charsets.UTF_8).size <= limit)
            assertFalse(value.contains("\uFFFD"))
        }
    }

    @Test fun refreshJournalsAreCollectedBoundedAndSanitizedFromEveryNamespace() = roots { files, backup ->
        val markers = mutableListOf<String>()
        for ((index, directory) in listOf("runtime/latest/state/0.3.2/diagnostics", "runtime/stable/state/0.2.20/diagnostics", "diagnostics").withIndex()) {
            for (name in listOf("auth-refresh.previous.jsonl", "auth-refresh.jsonl")) {
                val marker = "refresh-$index-$name"
                log(files, "$directory/$name", "old refresh event\n".repeat(5000) + "$marker\npassword=do-not-include\n")
                markers += marker
            }
        }
        val body = JSONObject(SupportDiagnosticCollector(files, backup, null).collect("").payload)
        val value = body.getString("application_log")
        for (marker in markers) assertTrue("missing $marker", value.contains(marker))
        assertFalse(value.contains("do-not-include"))
        assertTrue(value.toByteArray(Charsets.UTF_8).size <= 96*1024)
    }

    @Test fun localExportRedactsUnlabelledOtherSupportCodesWithoutEnteredCode() = roots { files, backup ->
        val otherCode = "nld_" + "B".repeat(42) + "-"
        log(files, "runtime/stable/state/0.2.20/diagnostics/application.jsonl",
            "ordinary message: [$otherCode] safe_stage=login_failed\n")
        val report = SupportDiagnosticCollector(files, backup, null).collect("")
        assertFalse("local save/share leaked a support capability", report.payload.contains(otherCode))
        assertTrue(report.payload.contains("safe_stage=login_failed"))
    }

    @Test fun uploadUsesFixedHttpsHeaderOnlyAndRetriesExactFrozenPayload() = roots { files, backup ->
        val report = SupportDiagnosticCollector(files, backup, null).collect(uploadCode)
        val requests = mutableListOf<Connection>()
        val uploader = SupportDiagnosticUploader { url -> Connection(url, 200,
            """{"report_id":"${report.reportId}","request_id":"request-1","received_bytes":123}""").also { requests += it } }
        repeat(2) { assertTrue(uploader.upload(report, uploadCode) is SupportUploadResult.Success) }
        assertEquals(2, requests.size)
        for (request in requests) {
            assertEquals("https://nelomai.ru/api/client/v1/diagnostics/support", request.url.toString())
            assertEquals("POST", request.requestMethod)
            assertEquals("application/json", request.getRequestProperty("Content-Type"))
            assertEquals(uploadCode, request.getRequestProperty("X-Nelomai-Diagnostics-Code"))
            assertNull(request.getRequestProperty("Authorization"))
            assertFalse(request.instanceFollowRedirects)
            assertTrue(request.connectTimeout in 1..10_000)
            assertTrue(request.readTimeout in 1..15_000)
            assertEquals(report.payload, request.sent.toString("UTF-8"))
            assertFalse(request.sent.toString("UTF-8").contains(uploadCode))
            assertTrue(request.closed)
        }
    }

    @Test fun redirectIsFailureAndApiErrorKeepsRetryAfterWithoutEchoingSecrets() = roots { files, backup ->
        val report = SupportDiagnosticCollector(files, backup, null).collect("")
        val redirect = Connection(URL("https://nelomai.ru"), 302, "")
        assertTrue(SupportDiagnosticUploader { redirect }.upload(report, uploadCode) is SupportUploadResult.Failure)
        val limited = Connection(URL("https://nelomai.ru"), 429,
            """{"api_version":"1","request_id":"r","code":"diagnostics_code_exhausted","message":"$uploadCode"}""")
        limited.retryAfter = "120"
        val result = SupportDiagnosticUploader { limited }.upload(report, uploadCode) as SupportUploadResult.Failure
        assertEquals(429, result.status)
        assertEquals("diagnostics_code_exhausted", result.code)
        assertEquals(120L, result.retryAfterSeconds)
        assertFalse(result.toString().contains(uploadCode))
    }

    @Test fun malformedOrOversizedResponsesCannotCountAsSuccess() = roots { files, backup ->
        val report = SupportDiagnosticCollector(files, backup, null).collect("")
        for (response in listOf("{}", """{"report_id":"wrong","request_id":"r","received_bytes":1}""", "x".repeat(20_000))) {
            assertTrue(SupportDiagnosticUploader { Connection(URL("https://nelomai.ru"), 200, response) }
                .upload(report, uploadCode) is SupportUploadResult.Failure)
        }
        assertThrows(IllegalArgumentException::class.java) {
            SupportDiagnosticUploader { error("must not connect") }.upload(report, "bad\r\nheader")
        }
    }

    @Test fun invalidCodeFormatCannotOpenAConnection() = roots { files, backup ->
        val report = SupportDiagnosticCollector(files, backup, null).collect("")
        for (code in listOf("", "fake-code", "nld_" + "A".repeat(42), "nld_" + "A".repeat(44), "nld_" + "/".repeat(43))) {
            assertThrows(IllegalArgumentException::class.java) {
                SupportDiagnosticUploader { Connection(URL("https://nelomai.ru"), 200, "{}") }.upload(report, code)
            }
        }
    }

    @Test fun panelErrorsAreParsedFromExistingFlatApiErrorJson() = roots { files, backup ->
        val report = SupportDiagnosticCollector(files, backup, null).collect("")
        for ((status, code) in listOf(401 to "invalid_diagnostics_code", 429 to "diagnostics_code_exhausted",
            409 to "diagnostics_report_id_conflict", 422 to "invalid_support_diagnostics")) {
            val result = SupportDiagnosticUploader {
                Connection(it, status, """{"api_version":"1","request_id":"r","code":"$code","message":"hidden"}""")
            }.upload(report, uploadCode) as SupportUploadResult.Failure
            assertEquals(status, result.status)
            assertEquals(code, result.code)
        }
    }

    @Test fun byteCountMustBeAnUnsignedIntegerAndCancelledUploadNeverConnects() = roots { files, backup ->
        val report = SupportDiagnosticCollector(files, backup, null).collect("")
        for (count in listOf("1.5", "-1", "\"123\"")) {
            val result = SupportDiagnosticUploader {
                Connection(it, 200, """{"report_id":"${report.reportId}","request_id":"r","received_bytes":$count}""")
            }.upload(report, uploadCode)
            assertTrue("invalid byte count $count accepted", result is SupportUploadResult.Failure)
        }
        val uploader = SupportDiagnosticUploader { error("cancelled request must not connect") }
        uploader.cancel()
        assertEquals("upload_cancelled", (uploader.upload(report, uploadCode) as SupportUploadResult.Failure).code)
    }

    @Test fun cancellationReturnsEvenWhenTheNetworkReadIgnoresInterruptAndDisconnect() = roots { files, backup ->
        val entered = java.util.concurrent.CountDownLatch(1)
        val release = java.util.concurrent.CountDownLatch(1)
        val request = object : Connection(URL("https://nelomai.ru"), 200, "") {
            override fun getInputStream() = object : java.io.InputStream() {
                override fun read(): Int {
                    entered.countDown()
                    while (release.count > 0) { try { release.await() } catch (_: InterruptedException) {} }
                    return -1
                }
            }
        }
        val uploader = SupportDiagnosticUploader { request }
        val executor = java.util.concurrent.Executors.newSingleThreadExecutor()
        try {
            val result = executor.submit<SupportUploadResult> { uploader.upload(SupportDiagnosticCollector(files, backup, null).collect(""), uploadCode) }
            assertTrue(entered.await(1, java.util.concurrent.TimeUnit.SECONDS))
            uploader.cancel()
            assertEquals("upload_cancelled", (result.get(1, java.util.concurrent.TimeUnit.SECONDS) as SupportUploadResult.Failure).code)
        } finally { release.countDown(); executor.shutdownNow() }
    }

    private open class Connection(url: URL, private val status: Int, body: String) : HttpsURLConnection(url) {
        val sent = ByteArrayOutputStream()
        var closed = false
        var retryAfter: String? = null
        private val response = body.toByteArray()
        override fun getOutputStream() = sent
        override fun getInputStream(): java.io.InputStream = ByteArrayInputStream(response)
        override fun getErrorStream() = ByteArrayInputStream(response)
        override fun getResponseCode() = status
        override fun getHeaderField(name: String?) = if (name == "Retry-After") retryAfter else null
        override fun disconnect() { closed = true }
        override fun usingProxy() = false
        override fun connect() {}
        override fun getCipherSuite() = "TLS_TEST"
        override fun getLocalCertificates(): Array<Certificate>? = null
        override fun getServerCertificates(): Array<Certificate> = emptyArray()
        override fun getPeerPrincipal(): Principal? = null
        override fun getLocalPrincipal(): Principal? = null
    }
}
