package ru.nelomai.tunnel

import java.io.IOException
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import okhttp3.Call
import okhttp3.EventListener
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.SocketPolicy
import okio.Buffer
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
        "11111111-1111-4111-8111-111111111111", "https://private-panel.invalid", "secret-device-token", 1_900_000_000,
    )
    private val operationId = "22222222-2222-4222-8222-222222222222"
    private val payload = JSONObject().put("operation_id", operationId).put("private", "secret-body")

    @Before fun clearLogs() = ShadowLog.clear()

    @Test fun stopRecordsRequestHeadersAndBodyCompletionWithoutSensitiveValues() {
        MockWebServer().use { server ->
            server.enqueue(MockResponse().setBody("""{"ok":true,"private":"secret-response"}"""))
            val result = transport(server).execute(credential, "POST", "background/connections/stop", payload)
            assertTrue(result.getBoolean("ok"))
            val request = server.takeRequest(2, TimeUnit.SECONDS)!!
            assertEquals("Device secret-device-token", request.getHeader("Authorization"))
            assertEquals(payload.toString(), request.body.readUtf8())
            assertEquals(listOf("prepare", "request_body", "request_body_written", "response_headers", "complete"), phases(timings()))
            assertTrue(timings().all { it.contains("operation_id=$operationId") })
            assertDurationsAndPrivacy(timings())
        }
    }

    @Test fun failureBeforeSendingBodyIsNotReportedAsWaitingForResponse() {
        val client = backgroundHttpClient.newBuilder().addInterceptor { throw IOException("secret-error") }.build()
        expectCode("background_transport_unavailable") {
            BackgroundHttpApiTransport(newCall = client::newCall).execute(credential, "POST", "background/connections/stop", payload)
        }
        assertTrue(timings().last().contains("failed_phase=request_body"))
        assertFalse("request_body_written" in phases(timings()))
        assertDurationsAndPrivacy(timings())
    }

    @Test fun waitingForResponseFailureIsRecordedWithoutSensitiveValues() {
        val client = backgroundHttpClient.newBuilder().addInterceptor { chain ->
            chain.request().body!!.writeTo(Buffer())
            throw IOException("secret-error")
        }.build()
        expectCode("background_transport_unavailable") {
            BackgroundHttpApiTransport(newCall = client::newCall).execute(credential, "POST", "background/connections/stop", payload)
        }
        assertEquals("failed", phases(timings()).last())
        assertTrue(timings().last().contains("failed_phase=response_headers"))
        assertDurationsAndPrivacy(timings())
    }

    @Test fun unrelatedRequestsDoNotGenerateStopTimings() {
        BackgroundHttpApiTransport(newCall = responseClient()::newCall).execute(credential, "POST", "background/token", payload)
        assertTrue(timings().isEmpty())
    }

    @Test fun malformedOperationIdIsNotCopiedIntoDiagnostics() {
        BackgroundHttpApiTransport(newCall = responseClient()::newCall).execute(
            credential, "POST", "background/connections/stop", JSONObject().put("operation_id", "secret-body"))
        assertDurationsAndPrivacy(timings())
        assertTrue(timings().none { it.contains("operation_id=") })
    }

    @Test fun cancellingStartClosesBlockedSocketWithoutWaitingForReadTimeout() {
        for (bodyStarted in listOf(false, true)) MockWebServer().use { server ->
            // Dispatch after reading the request: MockWebServer's queued throttle
            // would otherwise also throttle the incoming request body.
            server.dispatcher = object : okhttp3.mockwebserver.Dispatcher() {
                override fun dispatch(request: okhttp3.mockwebserver.RecordedRequest) =
                    if (bodyStarted) MockResponse().setBody("{\"ok\":true}").throttleBody(1, 3, TimeUnit.SECONDS)
                    else MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE)
            }
            server.start()
            val cancellation = CompletableFuture<Unit>()
            val readingBody = java.util.concurrent.CountDownLatch(1)
            val client = backgroundHttpClient.newBuilder().eventListener(object : EventListener() {
                override fun responseBodyStart(call: Call) { readingBody.countDown() }
            }).build()
            val outcome = CompletableFuture<String>()
            val worker = Thread {
                try {
                    transport(server, cancellation, client).execute(credential, "POST", "background/connections/start", payload)
                    outcome.complete("accepted")
                } catch (error: BackgroundConnectionException) { outcome.complete(error.code) }
            }.apply { start() }
            try {
                assertNotNull(server.takeRequest(2, TimeUnit.SECONDS))
                if (bodyStarted) assertTrue(readingBody.await(2, TimeUnit.SECONDS))
                cancellation.complete(Unit)
                assertEquals("tunnel_start_cancelled", outcome.get(2, TimeUnit.SECONDS))
            } finally { cancellation.complete(Unit); worker.join(2_000) }
            assertFalse(worker.isAlive)
        }
    }

    @Test fun cancelledStartDoesNotOpenAnotherHttpRequest() {
        var opened = false
        expectCode("tunnel_start_cancelled") {
            BackgroundHttpApiTransport(CompletableFuture.completedFuture(Unit)) { opened = true; error("must not create call") }
                .execute(credential, "POST", "background/connections/start", payload)
        }
        assertFalse(opened)
    }

    @Test fun cancellationDuringCallRegistrationPreventsIo() {
        val cancellation = CompletableFuture<Unit>()
        val dnsCalls = java.util.concurrent.atomic.AtomicInteger()
        val client = noNetworkClient(dnsCalls)
        expectCode("tunnel_start_cancelled") {
            BackgroundHttpApiTransport(cancellation) { request ->
                cancellation.complete(Unit)
                client.newCall(request)
            }.execute(credential, "POST", "background/connections/start", payload)
        }
        assertEquals(0, dnsCalls.get())
    }

    @Test fun cancellationAfterRegistrationPreventsIo() {
        val cancellation = CompletableFuture<Unit>()
        // RealCall.execute has begun, but DNS/socket I/O has not. Unlike pre-connect
        // URLConnection.disconnect, this cancellation remains effective.
        val dnsCalls = java.util.concurrent.atomic.AtomicInteger()
        val client = noNetworkClient(dnsCalls).newBuilder().eventListener(object : EventListener() {
            override fun callStart(call: Call) { cancellation.complete(Unit) }
        }).build()
        expectCode("tunnel_start_cancelled") {
            BackgroundHttpApiTransport(cancellation, client::newCall)
                .execute(credential, "POST", "background/connections/start", payload)
        }
        assertEquals(0, dnsCalls.get())
    }

    @Test fun lateResponseAfterCancellationCannotBeAccepted() {
        val cancellation = CompletableFuture<Unit>()
        val client = backgroundHttpClient.newBuilder().addInterceptor { chain ->
            cancellation.complete(Unit)
            response(chain.request())
        }.build()
        expectCode("tunnel_start_cancelled") {
            BackgroundHttpApiTransport(cancellation, client::newCall)
                .execute(credential, "POST", "background/connections/start", payload)
        }
    }

    @Test fun finishedRequestDetachesItsCancellationCallback() {
        val cancellation = CompletableFuture<Unit>()
        var call: Call? = null
        BackgroundHttpApiTransport(cancellation) { request -> responseClient().newCall(request).also { call = it } }
            .execute(credential, "POST", "background/connections/start", payload)
        cancellation.complete(Unit)
        assertFalse(call!!.isCanceled())
    }

    @Test fun transportRejectsCleartextAndDoesNotFollowRedirects() {
        expectCode("background_transport_unavailable") {
            BackgroundHttpApiTransport { error("cleartext must be rejected before creating call") }
                .execute(credential.copy(panelBase = "http://private-panel.invalid"), "GET", "background/token", null)
        }
        MockWebServer().use { server ->
            server.enqueue(MockResponse().setResponseCode(302).addHeader("Location", server.url("/secret-target")))
            expectCode("background_panel_error") {
                transport(server).execute(credential, "POST", "background/connections/start", payload)
            }
            assertEquals(1, server.requestCount)
        }
    }

    @Test fun unreachableFirstAddressDoesNotPreventUsingTheNextAddress() {
        MockWebServer().use { server ->
            server.start(java.net.InetAddress.getByName("127.0.0.1"), 0)
            server.enqueue(MockResponse().setBody("{\"ok\":true}"))
            val client = backgroundHttpClient.newBuilder().dns(object : okhttp3.Dns {
                override fun lookup(hostname: String) = listOf(
                    java.net.InetAddress.getByName("127.0.0.2"),
                    java.net.InetAddress.getByName("127.0.0.1"),
                )
            }).build()
            val result = BackgroundHttpApiTransport { request ->
                client.newCall(request.newBuilder().url(server.url("/").newBuilder().host("synthetic.invalid").build()).build())
            }.execute(credential, "POST", "background/connections/start", payload)
            assertTrue(result.getBoolean("ok"))
            assertEquals(1, server.requestCount)
        }
    }

    @Test fun transportLimitsResponseAndPreservesRetryAfter() {
        MockWebServer().use { server ->
            server.enqueue(MockResponse().setBody("x".repeat(1024 * 1024 + 1)))
            expectCode("background_response_too_large") {
                transport(server).execute(credential, "GET", "background/token", null)
            }
            server.enqueue(MockResponse().setResponseCode(429).addHeader("Retry-After", "7").setBody("{}"))
            try {
                transport(server).execute(credential, "GET", "background/token", null)
                fail("expected panel failure")
            } catch (error: BackgroundConnectionException) { assertEquals("7", error.retryAfterHeader) }
        }
    }

    // Only the test factory rewrites the validated HTTPS request to a loopback HTTP
    // fixture; production uses the client's platform TLS trust and hostname checks.
    private fun transport(server: MockWebServer, cancellation: CompletableFuture<Unit>? = null,
                          client: OkHttpClient = backgroundHttpClient) =
        BackgroundHttpApiTransport(cancellation) { request ->
            client.newCall(request.newBuilder().url(server.url(request.url.encodedPath)).build())
        }

    private fun noNetworkClient(dnsCalls: java.util.concurrent.atomic.AtomicInteger): OkHttpClient =
        backgroundHttpClient.newBuilder().dns(object : okhttp3.Dns {
            override fun lookup(hostname: String): List<java.net.InetAddress> {
                dnsCalls.incrementAndGet()
                throw IOException("unexpected DNS/socket I/O")
            }
        }).build()

    private fun responseClient() = backgroundHttpClient.newBuilder().addInterceptor { chain ->
        chain.request().body?.writeTo(Buffer())
        response(chain.request())
    }.build()

    private fun response(request: Request) = Response.Builder().request(request).protocol(Protocol.HTTP_1_1)
        .code(200).message("OK").body("{\"ok\":true}".toResponseBody("application/json".toMediaType())).build()

    private fun expectCode(code: String, action: () -> Unit) {
        try { action(); fail("expected $code") }
        catch (error: BackgroundConnectionException) { assertEquals(code, error.code) }
    }

    private fun timings() = ShadowLog.getLogsForTag("NelomaiTunnel")
        .map { it.msg }.filter { it.startsWith("background.stop_http ") }
    private fun phases(records: List<String>) = records.map {
        Regex("(?:^| )phase=([a-z_]+)(?: |$)").find(it)!!.groupValues[1]
    }
    private fun assertDurationsAndPrivacy(records: List<String>) {
        assertFalse("phase diagnostics missing", records.isEmpty())
        val durations = records.map { Regex("(?:^| )elapsed_ms=([0-9]+)(?: |$)").find(it)!!.groupValues[1].toLong() }
        assertEquals(durations.sorted(), durations)
        for (secret in listOf(credential.token, "secret-body", "private-panel.invalid", "secret-response", "secret-error")) {
            assertTrue("diagnostics leaked $secret", records.none { it.contains(secret) })
        }
    }
}
