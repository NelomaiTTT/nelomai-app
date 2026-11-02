package ru.nelomai.tunnel

import java.net.InetAddress
import java.net.UnknownHostException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import okhttp3.mockwebserver.MockResponse
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.ConscryptMode
import ru.nelomai.runtime.v1.PanelDns
import ru.nelomai.runtime.v1.PanelDirectIpRoute
import ru.nelomai.testing.PanelTlsFixture

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE)
// The JVM fixture observes real SNI through JSSE; Robolectric's provider default differs by host architecture.
@ConscryptMode(ConscryptMode.Mode.OFF)
class PanelIpTlsTest {
    private val credential = BackgroundCredential("11111111-1111-4111-8111-111111111111", "https://nelomai.ru", "synthetic", 1_900_000_000)

    @Test fun failedDnsUsesBothNamesThenNumericIpWithNormalTlsAndOneBody() {
        PanelTlsFixture().use { tls ->
            val names = mutableListOf<String>()
            val dns = PanelDns { host -> names += host; throw UnknownHostException("outage") }
            val client = tls.client(backgroundHttpClient, dns)
            val routes = mutableListOf<Pair<String, Boolean>>()
            tls.server.enqueue(MockResponse().setBody("{\"ok\":true}"))
            val transport = BackgroundHttpApiTransport(newCall = { request ->
                routes += request.url.host to (request.tag(PanelDirectIpRoute::class.java) != null)
                newBackgroundPanelCall(request, client)
            })
            val payload = JSONObject().put("operation_id", "22222222-2222-4222-8222-222222222222")
            assertTrue(transport.execute(credential, "POST", "background/token", payload).getBoolean("ok"))
            assertEquals(listOf("nelomai.ru" to false, "nelomai.top" to false, "nelomai.top" to true), routes)
            assertEquals(listOf("nelomai.ru", "nelomai.top"), names)
            assertEquals(listOf("45.144.221.68"), tls.destinations)
            assertTrue(tls.serverNames.isNotEmpty() && tls.serverNames.all { it == "nelomai.top" })
            val received = tls.server.takeRequest(1, TimeUnit.SECONDS)!!
            assertEquals("nelomai.top", received.getHeader("Host"))
            assertEquals("Device synthetic", received.getHeader("Authorization"))
            assertEquals(payload.toString(), received.body.readUtf8())
            assertEquals(1, tls.server.requestCount)
        }
    }

    @Test fun stalledDnsStillReachesIpWithinTheExistingOperationBudget() {
        val release = CountDownLatch(1)
        try {
            PanelTlsFixture().use { tls ->
                val dns = PanelDns { release.await(); emptyList() }
                val client = tls.client(backgroundHttpClient, dns)
                tls.server.enqueue(MockResponse().setBody("{\"ok\":true}"))
                val began = System.nanoTime()
                assertTrue(BackgroundHttpApiTransport(newCall = { newBackgroundPanelCall(it, client) })
                    .execute(credential, "POST", "background/token", JSONObject()).getBoolean("ok"))
                assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - began) < 5000)
                assertEquals(listOf("45.144.221.68"), tls.destinations)
            }
        } finally { release.countDown() }
    }

    @Test fun primaryDnsAndBackupTlsFailuresStillUseTheHealthyPrimaryCertificateOnIp() {
        for (backupDnsAvailable in listOf(false, true)) {
            PanelTlsFixture(backupCertificate = false).use { tls ->
                val names = mutableListOf<String>()
                val client = tls.client(backgroundHttpClient, PanelDns { host ->
                    names += host
                    if (host == "nelomai.ru" || !backupDnsAvailable) throw UnknownHostException("outage")
                    listOf(InetAddress.getByAddress(byteArrayOf(45, 144.toByte(), 221.toByte(), 68)))
                })
                val routes = mutableListOf<Pair<String, Boolean>>()
                val calls = mutableListOf<okhttp3.Call>()
                tls.server.enqueue(MockResponse().setBody("{\"ok\":true}"))
                val payload = JSONObject().put("operation_id", "22222222-2222-4222-8222-222222222222")
                val result = BackgroundHttpApiTransport(newCall = { request ->
                    routes += request.url.host to (request.tag(PanelDirectIpRoute::class.java) != null)
                    newBackgroundPanelCall(request, client).also(calls::add)
                }).execute(credential, "POST", "background/token", payload)
                assertTrue(result.getBoolean("ok"))
                assertEquals(listOf("nelomai.ru" to false, "nelomai.top" to false, "nelomai.top" to true, "nelomai.ru" to true), routes)
                assertEquals(listOf("nelomai.ru", "nelomai.top"), names)
                assertEquals(if (backupDnsAvailable) listOf("nelomai.top", "nelomai.top", "nelomai.ru") else listOf("nelomai.top", "nelomai.ru"), tls.serverNames)
                assertEquals(if (backupDnsAvailable) listOf("45.144.221.68", "45.144.221.68", "45.144.221.68") else listOf("45.144.221.68", "45.144.221.68"), tls.destinations)
                assertTrue(calls.all { it.timeout().timeoutNanos() in 1..TimeUnit.SECONDS.toNanos(30) })
                assertTrue(calls.last().timeout().timeoutNanos() < calls.first().timeout().timeoutNanos())
                val received = tls.server.takeRequest(1, TimeUnit.SECONDS)!!
                assertEquals("nelomai.ru", received.getHeader("Host"))
                assertEquals("Device synthetic", received.getHeader("Authorization"))
                assertEquals(payload.toString(), received.body.readUtf8())
                assertEquals(1, tls.server.requestCount)
            }
        }
    }

    @Test fun cancellationAfterIpTlsFailurePreventsTheOtherIdentity() {
        PanelTlsFixture(backupCertificate = false).use { tls ->
            val cancellation = java.util.concurrent.CompletableFuture<Unit>()
            val routes = mutableListOf<String>()
            val client = tls.client(backgroundHttpClient, PanelDns { throw UnknownHostException("outage") }).newBuilder()
                .addInterceptor { chain ->
                    try { chain.proceed(chain.request()) }
                    catch (error: java.io.IOException) {
                        if (chain.request().tag(PanelDirectIpRoute::class.java) != null) cancellation.complete(Unit)
                        throw error
                    }
                }.build()
            val error = runCatching { BackgroundHttpApiTransport(cancellation, newCall = { request ->
                routes += request.url.host
                newBackgroundPanelCall(request, client)
            }).execute(credential, "POST", "background/token", JSONObject()) }.exceptionOrNull() as BackgroundConnectionException
            assertEquals("tunnel_start_cancelled", error.code)
            assertEquals(listOf("nelomai.ru", "nelomai.top", "nelomai.top"), routes)
            assertEquals(listOf("nelomai.top"), tls.serverNames)
        }
    }

    @Test fun directIpRejectsUntrustedCertificatesBeforeSending() {
        PanelTlsFixture(trustFixtures = false).use { tls ->
            val client = tls.client(backgroundHttpClient, PanelDns { throw UnknownHostException("outage") })
            val result = runCatching { BackgroundHttpApiTransport(newCall = { newBackgroundPanelCall(it, client) })
                .execute(credential, "POST", "background/token", JSONObject()) }
            assertTrue(result.isFailure)
            assertEquals(listOf("45.144.221.68", "45.144.221.68"), tls.destinations)
            val received = tls.server.takeRequest(200, TimeUnit.MILLISECONDS)
            assertTrue(received == null || received.requestLine.isEmpty())
        }
    }

    @Test fun httpErrorOnDirectIpDoesNotReplayThePostInternally() {
        PanelTlsFixture().use { tls ->
            val client = tls.client(backgroundHttpClient, PanelDns { throw UnknownHostException("outage") })
            tls.server.enqueue(MockResponse().setResponseCode(408).setBody("{}"))
            tls.server.enqueue(MockResponse().setBody("{\"ok\":true}"))
            assertTrue(runCatching { BackgroundHttpApiTransport(newCall = { newBackgroundPanelCall(it, client) })
                .execute(credential, "POST", "background/token", JSONObject()) }.isFailure)
            assertEquals(1, tls.server.requestCount)
        }
    }

    @Test fun directIpDoesNotDependOnResolvingTheSystemHttpProxy() {
        PanelTlsFixture().use { tls ->
            val client = tls.client(backgroundHttpClient, PanelDns { throw UnknownHostException("outage") }).newBuilder()
                .proxy(java.net.Proxy(java.net.Proxy.Type.HTTP, java.net.InetSocketAddress.createUnresolved("proxy.invalid", 3128))).build()
            tls.server.enqueue(MockResponse().setBody("{\"ok\":true}"))
            val request = okhttp3.Request.Builder().url("https://nelomai.top/health")
                .tag(PanelDirectIpRoute::class.java, PanelDirectIpRoute).build()
            newBackgroundPanelCall(request, client).execute().use { response -> assertEquals(200, response.code) }
            assertEquals(listOf("45.144.221.68"), tls.destinations)
        }
    }
}
