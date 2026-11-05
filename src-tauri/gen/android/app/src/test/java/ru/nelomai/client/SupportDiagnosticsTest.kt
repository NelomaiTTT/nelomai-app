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
import okhttp3.Call
import okhttp3.Callback
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody
import okhttp3.Protocol
import okio.Timeout
import okio.sink
import okio.source
import okio.buffer

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
        assertEquals(BuildConfig.VERSION_NAME, body.getString("app_version"))
        assertEquals(BuildConfig.VERSION_NAME, body.getString("container_version"))
        assertFalse(body.has("runtime_version"))
        assertFalse(body.has("runtime_contract_version"))
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
        assertEquals(fixture.keys().asSequence().toSet() + "container_version", body.keys().asSequence().toSet())
        // The fixture records an older client's schema, not this build's version.
        assertEquals(BuildConfig.VERSION_NAME, body.getString("app_version"))
        for (field in listOf("trigger", "architecture", "platform_version")) {
            assertEquals(fixture.getString(field), body.getString(field))
        }
        assertEquals(4, java.util.UUID.fromString(body.getString("report_id")).version())
        assertTrue(body.getLong("generated_at_unix") > 0)
        for (field in listOf("application_log", "helper_log", "logcat_log")) assertTrue(body.get(field) is String)
    }

    @Test fun collectorReadsOnlyExactLogsAndRejectsSymlinksWithoutWritingAnything() = roots { files, backup ->
        val forbidden = log(files, "runtime/latest/state/0.3.2/auth.json", "DO_NOT_EXPORT_AUTH")
        log(files, "runtime/latest/state/0.4.0/diagnostics/application.jsonl", "DO_NOT_EXPORT_040")
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
        val directories = listOf("runtime/latest/state/${BuildConfig.VERSION_NAME}/diagnostics", "runtime/latest/state/0.3.2/diagnostics", "runtime/stable/state/0.2.20/diagnostics", "diagnostics")
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
        for ((index, directory) in listOf("runtime/latest/state/${BuildConfig.VERSION_NAME}/diagnostics", "runtime/latest/state/0.3.2/diagnostics", "runtime/stable/state/0.2.20/diagnostics", "diagnostics").withIndex()) {
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
        val uploader = SupportDiagnosticUploader { outgoing -> Connection(outgoing, 200,
            """{"report_id":"${report.reportId}","request_id":"request-1","received_bytes":123}""").also { requests += it } }
        repeat(2) { assertTrue(uploader.upload(report, uploadCode) is SupportUploadResult.Success) }
        assertEquals(2, requests.size)
        for (request in requests) {
            assertEquals("https://nelomai.ru/api/client/v1/diagnostics/support", request.url.toString())
            assertEquals("POST", request.requestMethod)
            assertEquals("application/json", request.getRequestProperty("Content-Type"))
            assertEquals(uploadCode, request.getRequestProperty("X-Nelomai-Diagnostics-Code"))
            assertNull(request.getRequestProperty("Authorization"))
            assertTrue(request.timeout().timeoutNanos() in 1..java.util.concurrent.TimeUnit.SECONDS.toNanos(30))
            assertEquals(report.payload, request.sent.toString("UTF-8"))
            assertFalse(request.sent.toString("UTF-8").contains(uploadCode))
            assertTrue(request.closed)
        }
    }

    @Test fun absentCodeUploadsFrozenSanitizedReportWithoutAnAuthorizationHeader() = roots { files, backup ->
        log(files, "diagnostics/application.jsonl", "password=never-upload\nlogin_failed\n")
        val report = SupportDiagnosticCollector(files, backup, null).collect("")
        val requests = mutableListOf<Connection>()
        val uploader = SupportDiagnosticUploader { outgoing -> Connection(outgoing, 200,
            """{"report_id":"${report.reportId}","request_id":"anonymous-request","received_bytes":123}""").also { requests += it } }
        repeat(2) { assertTrue(uploader.upload(report, "") is SupportUploadResult.Success) }
        assertEquals(2, requests.size)
        for (request in requests) {
            assertEquals("https://nelomai.ru/api/client/v1/diagnostics/support", request.url.toString())
            assertNull(request.getRequestProperty("X-Nelomai-Diagnostics-Code"))
            assertNull(request.getRequestProperty("Authorization"))
            assertEquals("", request.getRequestProperty("Cookie"))
            assertEquals(report.payload, request.sent.toString("UTF-8"))
            assertFalse(request.sent.toString("UTF-8").contains("never-upload"))
        }
    }

    @Test fun redirectIsFailureAndApiErrorKeepsRetryAfterWithoutEchoingSecrets() = roots { files, backup ->
        val report = SupportDiagnosticCollector(files, backup, null).collect("")
        val redirect = Connection(URL("https://nelomai.ru"), 302, "")
        assertTrue(SupportDiagnosticUploader { redirect.bind(it) }.upload(report, uploadCode) is SupportUploadResult.Failure)
        val limited = Connection(URL("https://nelomai.ru"), 429,
            """{"api_version":"1","request_id":"r","code":"diagnostics_code_exhausted","message":"$uploadCode"}""")
        limited.retryAfter = "120"
        val result = SupportDiagnosticUploader { limited.bind(it) }.upload(report, uploadCode) as SupportUploadResult.Failure
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
        for (code in listOf(" ", "fake-code", "nld_" + "A".repeat(42), "nld_" + "A".repeat(44), "nld_" + "/".repeat(43))) {
            assertThrows(IllegalArgumentException::class.java) {
                SupportDiagnosticUploader { Connection(URL("https://nelomai.ru"), 200, "{}") }.upload(report, code)
            }
        }
    }

    @Test fun panelErrorsAreParsedFromExistingFlatApiErrorJson() = roots { files, backup ->
        val report = SupportDiagnosticCollector(files, backup, null).collect("")
        for ((status, code) in listOf(401 to "invalid_diagnostics_code", 429 to "diagnostics_code_exhausted",
            409 to "diagnostics_report_id_conflict", 422 to "invalid_support_diagnostics")) {
            val requests = mutableListOf<Connection>()
            val result = SupportDiagnosticUploader {
                Connection(it, status, """{"api_version":"1","request_id":"r","code":"$code","message":"hidden"}""").also { request -> requests += request }
            }.upload(report, uploadCode) as SupportUploadResult.Failure
            assertEquals(status, result.status)
            assertEquals(code, result.code)
            assertEquals("a coded rejection must never retry anonymously", 1, requests.size)
            assertEquals(uploadCode, requests.single().getRequestProperty("X-Nelomai-Diagnostics-Code"))
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
        val uploader = SupportDiagnosticUploader { request.bind(it) }
        val executor = java.util.concurrent.Executors.newSingleThreadExecutor()
        try {
            val result = executor.submit<SupportUploadResult> { uploader.upload(SupportDiagnosticCollector(files, backup, null).collect(""), uploadCode) }
            assertTrue(entered.await(1, java.util.concurrent.TimeUnit.SECONDS))
            uploader.cancel()
            assertEquals("upload_cancelled", (result.get(1, java.util.concurrent.TimeUnit.SECONDS) as SupportUploadResult.Failure).code)
        } finally { release.countDown(); executor.shutdownNow() }
    }

    @Test fun tlsFailureUsesBackupUrlBeforeWritingTheReport() = roots { files, backup ->
        val report = SupportDiagnosticCollector(files, backup, null).collect(uploadCode)
        val requests = mutableListOf<Connection>()
        val uploader = SupportDiagnosticUploader { outgoing ->
            object : Connection(outgoing, 200, """{"report_id":"${report.reportId}","request_id":"r","received_bytes":123}""") {
                override fun connect() { if (url.host == "nelomai.ru") throw javax.net.ssl.SSLHandshakeException("synthetic") }
                override fun getOutputStream(): ByteArrayOutputStream {
                    connect()
                    return super.getOutputStream()
                }
            }.also { requests += it }
        }
        assertTrue(uploader.upload(report, uploadCode) is SupportUploadResult.Success)
        assertEquals(listOf("nelomai.ru", "nelomai.top"), requests.map { it.url.host })
        assertEquals(0, requests.first().sent.size())
        assertTrue(requests.first().closed)
        assertEquals(report.payload, requests.last().sent.toString("UTF-8"))
        assertEquals(uploadCode, requests.last().getRequestProperty("X-Nelomai-Diagnostics-Code"))
    }

    @Test fun failureAfterSendingReportNeverRetriesOnBackup() = roots { files, backup ->
        val report = SupportDiagnosticCollector(files, backup, null).collect("")
        for (error in listOf(java.io.EOFException("after body"), java.net.SocketTimeoutException("after body"))) {
            val requests = mutableListOf<Connection>()
            val uploader = SupportDiagnosticUploader { outgoing -> object : Connection(outgoing, 200, "") {
                override fun getResponseCode(): Int = throw error
            }.also { requests += it } }
            assertTrue(uploader.upload(report, "") is SupportUploadResult.Failure)
            assertEquals(1, requests.size)
            assertEquals(report.payload, requests.single().sent.toString("UTF-8"))
        }
    }

    @Test fun timeoutDuringReportWriteNeverRetriesOnBackup() = roots { files, backup ->
        val report = SupportDiagnosticCollector(files, backup, null).collect("")
        val requests = mutableListOf<Connection>()
        val uploader = SupportDiagnosticUploader { outgoing ->
            object : Connection(outgoing, 200, "") {
                override fun getOutputStream() = object : ByteArrayOutputStream() {
                    override fun write(bytes: ByteArray, offset: Int, length: Int) {
                        sent.write(bytes, offset, minOf(1, length))
                        throw java.net.SocketTimeoutException("partial body")
                    }
                }
            }.also { requests += it }
        }
        assertTrue(uploader.upload(report, "") is SupportUploadResult.Failure)
        assertEquals(1, requests.size)
        assertEquals(1, requests.single().sent.size())
    }

    @Test fun cancellationDuringHandshakeNeverOpensBackup() = roots { files, backup ->
        val report = SupportDiagnosticCollector(files, backup, null).collect("")
        var calls = 0
        lateinit var uploader: SupportDiagnosticUploader
        uploader = SupportDiagnosticUploader { outgoing ->
            calls++
            object : Connection(outgoing, 200, "") {
                override fun connect() {
                    uploader.cancel()
                    throw javax.net.ssl.SSLHandshakeException("cancelled handshake")
                }
            }
        }
        val result = uploader.upload(report, "") as SupportUploadResult.Failure
        assertEquals("upload_cancelled", result.code)
        assertEquals(1, calls)
    }

    @Test fun connectTimeoutUsesBackupBeforeWritingTheReport() = roots { files, backup ->
        val report = SupportDiagnosticCollector(files, backup, null).collect(uploadCode)
        val requests = mutableListOf<Connection>()
        val uploader = SupportDiagnosticUploader { outgoing ->
            object : Connection(outgoing, 200, """{"report_id":"${report.reportId}","request_id":"r","received_bytes":123}""") {
                override fun connect() {
                    if (url.host == "nelomai.ru") throw java.net.SocketTimeoutException("connect timeout")
                }
            }.also { requests += it }
        }
        assertTrue(uploader.upload(report, uploadCode) is SupportUploadResult.Success)
        assertEquals(listOf("nelomai.ru", "nelomai.top"), requests.map { it.url.host })
        assertEquals(0, requests.first().sent.size())
        assertTrue(requests.first().closed)
        assertEquals(report.payload, requests.last().sent.toString("UTF-8"))
        assertEquals(uploadCode, requests.last().getRequestProperty("X-Nelomai-Diagnostics-Code"))
    }

    @Test fun connectTimeoutOnAllRoutesStopsAfterDirectIpAttempt() = roots { files, backup ->
        val report = SupportDiagnosticCollector(files, backup, null).collect("")
        val hosts = mutableListOf<String>()
        val uploader = SupportDiagnosticUploader { outgoing ->
            hosts += outgoing.url.host
            object : Connection(outgoing, 200, "") {
                override fun connect(): Unit = throw java.net.SocketTimeoutException("connect timeout")
            }
        }
        assertTrue(uploader.upload(report, "") is SupportUploadResult.Failure)
        assertEquals(listOf("nelomai.ru", "nelomai.top", "nelomai.top"), hosts)
    }

    @Test fun lateTlsFailureOnIpNeverReplaysTheReportWithAnotherIdentity() = roots { files, backup ->
        val report = SupportDiagnosticCollector(files, backup, null).collect("")
        val requests = mutableListOf<Connection>()
        val uploader = SupportDiagnosticUploader { outgoing ->
            val number = requests.size + 1
            object : Connection(outgoing, 200, "") {
                override fun connect() { if (number < 3) throw java.net.UnknownHostException("outage") }
                override fun getOutputStream() = object : ByteArrayOutputStream() {
                    override fun write(bytes: ByteArray, offset: Int, length: Int) {
                        sent.write(bytes, offset, minOf(1, length))
                        throw javax.net.ssl.SSLHandshakeException("late failure after partial write")
                    }
                }
            }.also { requests += it }
        }
        assertTrue(uploader.upload(report, "") is SupportUploadResult.Failure)
        assertEquals(listOf("nelomai.ru", "nelomai.top", "nelomai.top"), requests.map { it.url.host })
        assertEquals(1, requests.sumOf { it.sent.size() })
    }

    private open class Connection(private var outgoing: Request, private val status: Int, body: String) : Call {
        constructor(url: URL, status: Int, body: String) : this(Request.Builder().url(url).build(), status, body)
        val url: URL get() = outgoing.url.toUrl()
        val requestMethod: String get() = outgoing.method
        val sent = ByteArrayOutputStream()
        var closed = false
        var retryAfter: String? = null
        private val response = body.toByteArray()
        private val limit = Timeout()
        private var executed = false
        @Volatile private var cancelled = false
        fun bind(request: Request): Connection { outgoing = request; return this }
        fun getRequestProperty(name: String): String? = outgoing.header(name)
        open fun getOutputStream() = sent
        open fun getInputStream(): java.io.InputStream = ByteArrayInputStream(response)
        open fun getErrorStream(): java.io.InputStream = ByteArrayInputStream(response)
        open fun getResponseCode() = status
        open fun connect() {}
        override fun request() = outgoing
        override fun timeout() = limit
        override fun isExecuted() = executed
        override fun isCanceled() = cancelled
        override fun cancel() { cancelled = true; closed = true }
        override fun clone(): Call = error("unused async/clone call")
        override fun enqueue(responseCallback: Callback): Unit = error("unused async/clone call")
        override fun execute(): Response {
            executed = true
            try {
                if (cancelled) throw java.io.IOException("cancelled")
                connect()
                val sink = getOutputStream().sink().buffer()
                outgoing.body?.writeTo(sink)
                sink.flush()
                val code = getResponseCode()
                val input = if (code == 200) getInputStream() else getErrorStream()
                val responseBody = object : ResponseBody() {
                    private val source = input.source().buffer()
                    override fun contentType(): okhttp3.MediaType? = null
                    override fun contentLength() = -1L
                    override fun source() = source
                    override fun close() { closed = true; super.close() }
                }
                return Response.Builder().request(outgoing).protocol(Protocol.HTTP_1_1).code(code).message("test")
                    .apply { retryAfter?.let { header("Retry-After", it) } }.body(responseBody).build()
            } catch (error: Exception) { closed = true; throw error }
        }
    }
}
