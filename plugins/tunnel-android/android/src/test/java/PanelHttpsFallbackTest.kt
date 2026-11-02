package ru.nelomai.tunnel

import java.io.EOFException
import java.net.InetAddress
import java.net.Proxy
import java.net.SocketTimeoutException
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLHandshakeException
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okio.Buffer
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE)
class PanelHttpsFallbackTest {
    private val credential = BackgroundCredential("11111111-1111-4111-8111-111111111111", "https://nelomai.ru", "synthetic", 1_900_000_000)

    @Test fun directIpRouteIsOnlyAttemptedAfterBothDomainFailures() {
        val hosts = mutableListOf<String>()
        val client = backgroundHttpClient.newBuilder().addInterceptor { chain ->
            val request = chain.request()
            hosts += request.url.host
            if (hosts.size < 3) throw java.net.UnknownHostException("synthetic DNS outage")
            Response.Builder().request(request).protocol(Protocol.HTTP_1_1).code(200).message("OK")
                .body("{\"ok\":true}".toResponseBody()).build()
        }.build()
        val result = runCatching { BackgroundHttpApiTransport(newCall = client::newCall)
            .execute(credential, "POST", "background/token", JSONObject()) }
        assertEquals(listOf("nelomai.ru", "nelomai.top", "nelomai.top"), hosts)
        assertTrue(result.getOrThrow().getBoolean("ok"))
    }

    @Test fun handshakeFailureChangesHostAndSendsBodyOnlyOnBackup() {
        val hosts = mutableListOf<String>()
        var written = ""
        val client = backgroundHttpClient.newBuilder().addInterceptor { chain ->
            val request = chain.request()
            hosts += request.url.host
            if (request.url.host == "nelomai.ru") throw SSLHandshakeException("synthetic TLS failure")
            assertEquals("Device synthetic", request.header("Authorization"))
            written = Buffer().also { request.body!!.writeTo(it) }.readUtf8()
            Response.Builder().request(request).protocol(Protocol.HTTP_1_1).code(200).message("OK")
                .body("{\"ok\":true}".toResponseBody()).build()
        }.build()
        val payload = JSONObject().put("operation_id", "22222222-2222-4222-8222-222222222222")
        assertTrue(BackgroundHttpApiTransport(newCall = client::newCall)
            .execute(credential, "POST", "background/token", payload).getBoolean("ok"))
        assertEquals(listOf("nelomai.ru", "nelomai.top"), hosts)
        assertEquals(payload.toString(), written)
    }

    @Test fun numericNetworkFailureDoesNotRepeatWithAnotherHostname() {
        val hosts = mutableListOf<String>()
        val client = backgroundHttpClient.newBuilder().addInterceptor { chain ->
            hosts += chain.request().url.host
            throw java.net.ConnectException("unreachable")
        }.build()
        assertTrue(runCatching { BackgroundHttpApiTransport(newCall = client::newCall)
            .execute(credential, "POST", "background/token", JSONObject()) }.isFailure)
        assertEquals(listOf("nelomai.ru", "nelomai.top", "nelomai.top"), hosts)
    }

    @Test fun lateTlsFailureOnIpDoesNotReplayTheBodyWithAnotherIdentity() {
        val hosts = mutableListOf<String>()
        var writes = 0
        val client = backgroundHttpClient.newBuilder().addInterceptor { chain ->
            hosts += chain.request().url.host
            if (hosts.size < 3) throw java.net.UnknownHostException("outage")
            chain.request().body!!.writeTo(Buffer())
            writes++
            throw SSLHandshakeException("late failure after body write")
        }.build()
        assertTrue(runCatching { BackgroundHttpApiTransport(newCall = client::newCall)
            .execute(credential, "POST", "background/token", JSONObject()) }.isFailure)
        assertEquals(listOf("nelomai.ru", "nelomai.top", "nelomai.top"), hosts)
        assertEquals(1, writes)
    }

    @Test fun failureAfterWritingBodyNeverReplaysEvenIfItLooksLikeHandshakeFailure() {
        for (error in listOf(EOFException(), SocketTimeoutException(), SSLHandshakeException("late"))) {
            var calls = 0
            val client = backgroundHttpClient.newBuilder().addInterceptor { chain ->
                calls++
                chain.request().body!!.writeTo(Buffer())
                throw error
            }.build()
            assertTrue(runCatching { BackgroundHttpApiTransport(newCall = client::newCall)
                .execute(credential, "POST", "background/token", JSONObject()) }.isFailure)
            assertEquals(1, calls)
        }
    }

    @Test fun httpErrorsAndOtherOriginsDoNotAcquireAnotherAttempt() {
        for (code in listOf(307, 401, 429, 503)) {
            var calls = 0
            val client = backgroundHttpClient.newBuilder().addInterceptor { chain ->
                calls++
                Response.Builder().request(chain.request()).protocol(Protocol.HTTP_1_1).code(code).message("failed")
                    .body("{}".toResponseBody()).build()
            }.build()
            assertTrue(runCatching { BackgroundHttpApiTransport(newCall = client::newCall)
                .execute(credential, "POST", "background/token", JSONObject()) }.isFailure)
            assertEquals(1, calls)
        }
        for (base in listOf("https://nelomai.ru:8443", "https://x.nelomai.ru", "https://nelomai.ru.evil.test")) {
            var calls = 0
            val client = backgroundHttpClient.newBuilder().addInterceptor { calls++; throw SSLHandshakeException("fail") }.build()
            assertTrue(runCatching { BackgroundHttpApiTransport(newCall = client::newCall)
                .execute(credential.copy(panelBase = base), "POST", "background/token", JSONObject()) }.isFailure)
            assertEquals(1, calls)
        }
    }

    @Test fun cancellationDuringFailedConnectPreventsBackupCall() {
        val cancellation = CompletableFuture<Unit>()
        var calls = 0
        val client = backgroundHttpClient.newBuilder().addInterceptor {
            calls++; cancellation.complete(Unit); throw SSLHandshakeException("fail")
        }.build()
        val error = runCatching { BackgroundHttpApiTransport(cancellation, client::newCall)
            .execute(credential, "POST", "background/token", JSONObject()) }.exceptionOrNull() as BackgroundConnectionException
        assertEquals("tunnel_start_cancelled", error.code)
        assertEquals(1, calls)
    }

    @Test fun backupPostIsNotReplayedByOkHttpAfterAnHttpError() {
        for (status in listOf(408, 503)) {
            MockWebServer().use { server ->
                server.enqueue(MockResponse().setResponseCode(status).setHeader("Retry-After", "0").setBody("{}"))
                server.enqueue(MockResponse().setBody("{\"ok\":true}"))
                server.start()
                val hosts = mutableListOf<String>()
                val client = backgroundHttpClient.newBuilder().proxy(Proxy.NO_PROXY).addInterceptor { chain ->
                    val request = chain.request()
                    hosts += request.url.host
                    if (request.url.host == "nelomai.ru") throw SSLHandshakeException("primary unavailable")
                    // Keep OkHttp's actual protocol/retry stack; replace only the destination.
                    chain.proceed(request.newBuilder().url(server.url(request.url.encodedPath)).build())
                }.build()
                val payload = JSONObject().put("operation_id", "22222222-2222-4222-8222-222222222222")
                val result = runCatching { BackgroundHttpApiTransport(newCall = client::newCall)
                    .execute(credential, "POST", "background/token", payload) }
                assertEquals("POST repeated internally after HTTP $status", 1, server.requestCount)
                assertTrue(result.isFailure)
                assertEquals(listOf("nelomai.ru", "nelomai.top"), hosts)
                val received = server.takeRequest(1, TimeUnit.SECONDS)!!
                assertEquals("POST", received.method)
                assertEquals("Device synthetic", received.getHeader("Authorization"))
                assertEquals(payload.toString(), received.body.readUtf8())
            }
        }
    }

    @Test fun oneShotBodyStillTriesTheNextAddressBeforeSending() {
        MockWebServer().use { server ->
            server.enqueue(MockResponse().setBody("{\"ok\":true}"))
            server.start(InetAddress.getByName("127.0.0.1"), 0)
            var lookups = 0
            val client = backgroundHttpClient.newBuilder()
                .proxy(Proxy.NO_PROXY)
                .dns(object : okhttp3.Dns {
                    override fun lookup(hostname: String): List<InetAddress> {
                        lookups++
                        return listOf(InetAddress.getByName("127.0.0.2"), InetAddress.getByName("127.0.0.1"))
                    }
                })
                .addInterceptor { chain ->
                    val request = chain.request()
                    val target = server.url(request.url.encodedPath).newBuilder().host("panel-route.test").build()
                    chain.proceed(request.newBuilder().url(target).build())
                }.build()
            val payload = JSONObject().put("operation_id", "22222222-2222-4222-8222-222222222222")
            assertTrue(BackgroundHttpApiTransport(newCall = client::newCall)
                .execute(credential, "POST", "background/token", payload).getBoolean("ok"))
            assertEquals(1, lookups)
            assertEquals(1, server.requestCount)
            assertEquals(payload.toString(), server.takeRequest(1, TimeUnit.SECONDS)!!.body.readUtf8())
        }
    }
}
