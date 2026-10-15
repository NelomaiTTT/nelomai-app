package ru.nelomai.tunnel

import java.io.ByteArrayOutputStream
import java.net.SocketTimeoutException
import java.net.URL
import java.security.cert.Certificate
import javax.net.ssl.HttpsURLConnection
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowLog

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE)
class BackgroundStopTimingTest {
    private val credential = BackgroundCredential(
        "11111111-1111-4111-8111-111111111111",
        "https://private-panel.invalid",
        "secret-device-token",
        1_900_000_000,
    )
    private val operationId = "22222222-2222-4222-8222-222222222222"
    private val payload = JSONObject().put("operation_id", operationId).put("private", "secret-body")

    @Before fun clearLogs() = ShadowLog.clear()

    @Test fun stopRecordsRequestHeadersAndBodyCompletionWithoutSensitiveValues() {
        val connection = Connection()
        val result = UrlConnectionBackgroundApiTransport { connection }.execute(
            credential, "POST", "background/connections/stop", payload,
        )
        assertTrue(result.getBoolean("ok"))
        assertTrue(connection.disconnected)
        assertEquals("Device secret-device-token", connection.getRequestProperty("Authorization"))
        assertEquals(payload.toString(), connection.output.toString("UTF-8"))
        val records = timings()
        assertEquals(listOf("prepare", "request_body", "request_body_written", "response_headers", "complete"), phases(records))
        assertTrue(records.all { it.contains("operation_id=$operationId") })
        assertDurationsAndPrivacy(records)
    }

    @Test fun connectOrWriteFailureIsDistinguishedFromWaitingForResponse() {
        for (failAt in listOf("request_body", "response_headers", "response_body")) {
            ShadowLog.clear()
            val connection = Connection(failAt)
            try {
                UrlConnectionBackgroundApiTransport { connection }.execute(
                    credential, "POST", "background/connections/stop", payload,
                )
                fail("expected transport failure")
            } catch (error: BackgroundConnectionException) {
                assertEquals("background_transport_unavailable", error.code)
            }
            assertTrue(connection.disconnected)
            val records = timings()
            assertEquals("failed", phases(records).last())
            assertTrue(records.last().contains("failed_phase=$failAt"))
            assertTrue(records.last().contains("error_type=SocketTimeoutException"))
            assertEquals(failAt != "request_body", "request_body_written" in phases(records))
            assertDurationsAndPrivacy(records)
        }
    }

    @Test fun unrelatedRequestsDoNotGenerateStopTimings() {
        UrlConnectionBackgroundApiTransport { Connection() }.execute(
            credential, "POST", "background/token", payload,
        )
        assertTrue(timings().isEmpty())
    }

    @Test fun malformedOperationIdIsNotCopiedIntoDiagnostics() {
        UrlConnectionBackgroundApiTransport { Connection() }.execute(
            credential, "POST", "background/connections/stop",
            JSONObject().put("operation_id", "secret-body"),
        )
        assertDurationsAndPrivacy(timings())
        assertTrue(timings().none { it.contains("operation_id=") })
    }

    private fun timings() = ShadowLog.getLogsForTag("NelomaiTunnel")
        .map { it.msg }.filter { it.startsWith("background.stop_http ") }

    private fun phases(records: List<String>) = records.map {
        Regex("(?:^| )phase=([a-z_]+)(?: |$)").find(it)!!.groupValues[1]
    }

    private fun assertDurationsAndPrivacy(records: List<String>) {
        assertFalse("phase diagnostics missing", records.isEmpty())
        val durations = records.map {
            Regex("(?:^| )elapsed_ms=([0-9]+)(?: |$)").find(it)!!.groupValues[1].toLong()
        }
        assertEquals(durations.sorted(), durations)
        for (secret in listOf(credential.token, "secret-body", "private-panel.invalid", "secret-response", "secret-error")) {
            assertTrue("diagnostics leaked $secret", records.none { it.contains(secret) })
        }
    }

    private class Connection(private val failAt: String? = null) :
        HttpsURLConnection(URL("https://private-panel.invalid")) {
        val output = ByteArrayOutputStream()
        var disconnected = false
        override fun connect() {}
        override fun disconnect() { disconnected = true }
        override fun usingProxy() = false
        override fun getCipherSuite() = "synthetic"
        override fun getLocalCertificates(): Array<Certificate>? = null
        override fun getServerCertificates(): Array<Certificate> = emptyArray()
        override fun getOutputStream(): ByteArrayOutputStream {
            if (failAt == "request_body") throw SocketTimeoutException("secret-error")
            return output
        }
        override fun getResponseCode(): Int {
            if (failAt == "response_headers") throw SocketTimeoutException("secret-error")
            return 200
        }
        override fun getInputStream(): java.io.InputStream {
            if (failAt == "response_body") throw SocketTimeoutException("secret-error")
            return """{"ok":true,"private":"secret-response"}""".byteInputStream()
        }
    }
}
