package ru.nelomai.client

import java.net.InetAddress
import java.net.UnknownHostException
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import okhttp3.mockwebserver.MockResponse
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
@Config(sdk = [28], manifest = Config.NONE)
// The JVM fixture observes real SNI through JSSE; Robolectric's provider default differs by host architecture.
@ConscryptMode(ConscryptMode.Mode.OFF)
class SupportIpTlsTest {
    private val code = "nld_" + "A".repeat(43)
    private fun report(test: (SupportDiagnosticReport) -> Unit) {
        val root = Files.createTempDirectory("support-ip-tls").toFile()
        try { test(SupportDiagnosticCollector(root.resolve("files").apply { mkdirs() }, root.resolve("backup").apply { mkdirs() }, null).collect(code)) }
        finally { root.deleteRecursively() }
    }

    @Test fun failedDnsUsesBothNamesThenIpWithTheOriginalFrozenReportAndTlsIdentity() = report { report ->
        PanelTlsFixture().use { tls ->
            val names = mutableListOf<String>()
            val client = tls.client(supportHttpClient, PanelDns { host -> names += host; throw UnknownHostException("outage") })
            val routes = mutableListOf<Pair<String, Boolean>>()
            tls.server.enqueue(MockResponse().setBody("""{"report_id":"${report.reportId}","request_id":"r","received_bytes":123}"""))
            val uploader = SupportDiagnosticUploader { request ->
                routes += request.url.host to (request.tag(PanelDirectIpRoute::class.java) != null)
                newSupportPanelCall(request, client)
            }
            assertTrue(uploader.upload(report, code) is SupportUploadResult.Success)
            assertEquals(listOf("nelomai.ru" to false, "nelomai.top" to false, "nelomai.top" to true), routes)
            assertEquals(listOf("nelomai.ru", "nelomai.top"), names)
            assertEquals(listOf("45.144.221.68"), tls.destinations)
            assertTrue(tls.serverNames.isNotEmpty() && tls.serverNames.all { it == "nelomai.top" })
            val received = tls.server.takeRequest(1, TimeUnit.SECONDS)!!
            assertEquals("nelomai.top", received.getHeader("Host"))
            assertEquals(code, received.getHeader("X-Nelomai-Diagnostics-Code"))
            assertNull(received.getHeader("Authorization"))
            assertEquals(report.payload, received.body.readUtf8())
            assertEquals(1, tls.server.requestCount)
        }
    }

    @Test fun primaryDnsAndBackupTlsFailuresStillUseTheHealthyPrimaryCertificateOnIp() = report { report ->
        for (backupDnsAvailable in listOf(false, true)) {
            PanelTlsFixture(backupCertificate = false).use { tls ->
                val names = mutableListOf<String>()
                val client = tls.client(supportHttpClient, PanelDns { host ->
                    names += host
                    if (host == "nelomai.ru" || !backupDnsAvailable) throw UnknownHostException("outage")
                    listOf(InetAddress.getByAddress(byteArrayOf(45, 144.toByte(), 221.toByte(), 68)))
                })
                val routes = mutableListOf<Pair<String, Boolean>>()
                val calls = mutableListOf<okhttp3.Call>()
                tls.server.enqueue(MockResponse().setBody("""{"report_id":"${report.reportId}","request_id":"r","received_bytes":123}"""))
                val result = SupportDiagnosticUploader { request ->
                    routes += request.url.host to (request.tag(PanelDirectIpRoute::class.java) != null)
                    newSupportPanelCall(request, client).also(calls::add)
                }.upload(report, code)
                assertTrue(result is SupportUploadResult.Success)
                assertEquals(listOf("nelomai.ru" to false, "nelomai.top" to false, "nelomai.top" to true, "nelomai.ru" to true), routes)
                assertEquals(listOf("nelomai.ru", "nelomai.top"), names)
                assertEquals(if (backupDnsAvailable) listOf("nelomai.top", "nelomai.top", "nelomai.ru") else listOf("nelomai.top", "nelomai.ru"), tls.serverNames)
                assertEquals(if (backupDnsAvailable) listOf("45.144.221.68", "45.144.221.68", "45.144.221.68") else listOf("45.144.221.68", "45.144.221.68"), tls.destinations)
                assertTrue(calls.all { it.timeout().timeoutNanos() in 1..TimeUnit.SECONDS.toNanos(30) })
                assertTrue(calls.last().timeout().timeoutNanos() < calls.first().timeout().timeoutNanos())
                val received = tls.server.takeRequest(1, TimeUnit.SECONDS)!!
                assertEquals("nelomai.ru", received.getHeader("Host"))
                assertEquals(code, received.getHeader("X-Nelomai-Diagnostics-Code"))
                assertNull(received.getHeader("Authorization"))
                assertEquals(report.payload, received.body.readUtf8())
                assertEquals(1, tls.server.requestCount)
            }
        }
    }

    @Test fun cancellationAfterIpTlsFailurePreventsTheOtherIdentity() = report { report ->
        PanelTlsFixture(backupCertificate = false).use { tls ->
            lateinit var uploader: SupportDiagnosticUploader
            val routes = mutableListOf<String>()
            val client = tls.client(supportHttpClient, PanelDns { throw UnknownHostException("outage") }).newBuilder()
                .addInterceptor { chain ->
                    try { chain.proceed(chain.request()) }
                    catch (error: java.io.IOException) {
                        if (chain.request().tag(PanelDirectIpRoute::class.java) != null) uploader.cancel()
                        throw error
                    }
                }.build()
            uploader = SupportDiagnosticUploader { request ->
                routes += request.url.host
                newSupportPanelCall(request, client)
            }
            assertEquals("upload_cancelled", (uploader.upload(report, code) as SupportUploadResult.Failure).code)
            assertEquals(listOf("nelomai.ru", "nelomai.top", "nelomai.top"), routes)
            assertEquals(listOf("nelomai.top"), tls.serverNames)
        }
    }

    @Test fun directIpRejectsUntrustedCertificatesBeforeSending() = report { report ->
        PanelTlsFixture(trustFixtures = false).use { tls ->
            val client = tls.client(supportHttpClient, PanelDns { throw UnknownHostException("outage") })
            assertTrue(SupportDiagnosticUploader { newSupportPanelCall(it, client) }.upload(report, code) is SupportUploadResult.Failure)
            assertEquals(listOf("45.144.221.68", "45.144.221.68"), tls.destinations)
            val received = tls.server.takeRequest(200, TimeUnit.MILLISECONDS)
            assertTrue(received == null || received.requestLine.isEmpty())
        }
    }

    @Test fun httpErrorsAndRedirectsOnIpNeverReplayTheReport() = report { report ->
        for (status in listOf(408, 503, 307)) {
            PanelTlsFixture().use { tls ->
                val client = tls.client(supportHttpClient, PanelDns { throw UnknownHostException("outage") })
                tls.server.enqueue(MockResponse().setResponseCode(status).setHeader("Retry-After", "0")
                    .setHeader("Location", "https://nelomai.ru/redirect").setBody("{}"))
                tls.server.enqueue(MockResponse().setBody("""{"report_id":"${report.reportId}","request_id":"r","received_bytes":123}"""))
                val result = SupportDiagnosticUploader { newSupportPanelCall(it, client) }.upload(report, code)
                assertTrue(result is SupportUploadResult.Failure)
                assertEquals(1, tls.server.requestCount)
                assertEquals(report.payload, tls.server.takeRequest(1, TimeUnit.SECONDS)!!.body.readUtf8())
            }
        }
    }

    @Test fun cancellationDuringSecondDnsLookupPreventsTheIpAttempt() = report { report ->
        val routes = mutableListOf<String>()
        lateinit var uploader: SupportDiagnosticUploader
        val dns = PanelDns { host ->
            if (host == "nelomai.top") uploader.cancel()
            throw UnknownHostException("outage")
        }
        val client = supportHttpClient.newBuilder().dns(object : okhttp3.Dns {
            override fun lookup(hostname: String) = dns.lookup(hostname)
        }).build()
        uploader = SupportDiagnosticUploader { request ->
            routes += request.url.host
            newSupportPanelCall(request, client)
        }
        assertEquals("upload_cancelled", (uploader.upload(report, code) as SupportUploadResult.Failure).code)
        assertEquals(listOf("nelomai.ru", "nelomai.top"), routes)
    }

    @Test fun cancellationWhileReadingAnIpResponseClosesTheActualCall() = report { report ->
        PanelTlsFixture().use { tls ->
            val headers = java.util.concurrent.CountDownLatch(1)
            val active = java.util.concurrent.atomic.AtomicReference<okhttp3.Call>()
            val client = tls.client(supportHttpClient, PanelDns { throw UnknownHostException("outage") })
                .newBuilder().eventListenerFactory { call ->
                    val delegate = supportHttpClient.eventListenerFactory.create(call)
                    object : okhttp3.EventListener() {
                        override fun callStart(call: okhttp3.Call) = delegate.callStart(call)
                        override fun requestHeadersStart(call: okhttp3.Call) = delegate.requestHeadersStart(call)
                        override fun responseHeadersEnd(call: okhttp3.Call, response: okhttp3.Response) { headers.countDown() }
                    }
                }.build()
            tls.server.enqueue(MockResponse().setBody("""{"report_id":"${report.reportId}","request_id":"r","received_bytes":123}""")
                .setBodyDelay(500, TimeUnit.MILLISECONDS))
            val uploader = SupportDiagnosticUploader { newSupportPanelCall(it, client).also(active::set) }
            val executor = java.util.concurrent.Executors.newSingleThreadExecutor()
            try {
                val result = executor.submit<SupportUploadResult> { uploader.upload(report, code) }
                assertTrue(headers.await(3, TimeUnit.SECONDS))
                uploader.cancel()
                assertEquals("upload_cancelled", (result.get(1, TimeUnit.SECONDS) as SupportUploadResult.Failure).code)
                assertTrue(active.get().isCanceled())
            } finally { uploader.cancel(); executor.shutdownNow() }
        }
    }
}
