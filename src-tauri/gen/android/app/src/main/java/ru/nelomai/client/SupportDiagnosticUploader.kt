package ru.nelomai.client

import org.json.JSONObject
import java.net.Proxy
import java.util.concurrent.CancellationException
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import okhttp3.Call
import okhttp3.ConnectionPool
import okhttp3.EventListener
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody
import okio.BufferedSink
import ru.nelomai.runtime.v1.PanelDns
import ru.nelomai.runtime.v1.PanelDirectIpRoute

internal sealed class SupportUploadResult {
    class Success(val reportId: String, val requestId: String, val receivedBytes: Long) : SupportUploadResult()
    data class Failure(val code: String, val status: Int? = null, val retryAfterSeconds: Long? = null) : SupportUploadResult()
}

private class SupportRequestState {
    @Volatile var tracked = false
    @Volatile var httpStarted = false
}

internal val supportHttpClient = OkHttpClient.Builder()
    .proxy(Proxy.NO_PROXY)
    .connectTimeout(10, TimeUnit.SECONDS)
    .readTimeout(15, TimeUnit.SECONDS)
    .writeTimeout(15, TimeUnit.SECONDS)
    .followRedirects(false)
    .followSslRedirects(false)
    .protocols(listOf(Protocol.HTTP_1_1))
    .connectionPool(ConnectionPool(0, 1, TimeUnit.MINUTES))
    .dns(object : okhttp3.Dns { override fun lookup(hostname: String) = PanelDns.Default.lookup(hostname) })
    .eventListenerFactory {
        object : EventListener() {
            override fun callStart(call: Call) { call.request().tag(SupportRequestState::class.java)?.tracked = true }
            override fun requestHeadersStart(call: Call) { call.request().tag(SupportRequestState::class.java)?.httpStarted = true }
        }
    }
    .build()

internal fun newSupportPanelCall(request: Request, client: OkHttpClient = supportHttpClient): Call {
    val selected = if (request.tag(PanelDirectIpRoute::class.java) == null) client else {
        require(request.url.isHttps && request.url.port == 443 && request.url.username.isEmpty() && request.url.password.isEmpty())
        client.newBuilder().proxy(Proxy.NO_PROXY).dns(object : okhttp3.Dns {
            override fun lookup(hostname: String) = PanelDns.Default.directAddresses(hostname)
        }).build()
    }
    return selected.newCall(request)
}

/** Direct native HTTPS. Never consults ClientApi, runtime IPC, keyring, or account auth. */
internal class SupportDiagnosticUploader(
    private val newCall: (Request) -> Call = { newSupportPanelCall(it) },
) {
    @Volatile private var activeCall: Call? = null
    @Volatile private var operation: FutureTask<SupportUploadResult>? = null
    private val cancelled = AtomicBoolean(false)

    fun cancel() {
        cancelled.set(true)
        operation?.cancel(true)
        activeCall?.cancel()
    }

    fun upload(report: SupportDiagnosticReport, supportCode: String): SupportUploadResult {
        require(supportCode.isEmpty() || validSupportDiagnosticsCode(supportCode))
        val bytes = report.payload.toByteArray(Charsets.UTF_8)
        require(bytes.size <= 768 * 1024)
        if (cancelled.get()) return SupportUploadResult.Failure("upload_cancelled")
        lateinit var task: FutureTask<SupportUploadResult>
        task = FutureTask { performUpload(report, supportCode, bytes) { task.isCancelled } }
        operation = task
        if (cancelled.get()) task.cancel(true)
        Thread(task, "support-https").apply { isDaemon = true }.start()
        return try { task.get(30, TimeUnit.SECONDS) }
        catch (_: TimeoutException) {
            task.cancel(true); activeCall?.cancel()
            SupportUploadResult.Failure("upload_timeout")
        } catch (_: CancellationException) { SupportUploadResult.Failure("upload_cancelled") }
        catch (_: InterruptedException) {
            task.cancel(true); activeCall?.cancel(); Thread.currentThread().interrupt()
            SupportUploadResult.Failure("upload_cancelled")
        } catch (_: Exception) { SupportUploadResult.Failure("transport_unavailable") }
        finally { if (operation === task) operation = null }
    }

    private fun performUpload(report: SupportDiagnosticReport, supportCode: String, bytes: ByteArray, isCancelled: () -> Boolean): SupportUploadResult {
        val deadline = System.nanoTime() + 30_000_000_000L
        val stopped = { cancelled.get() || isCancelled() || Thread.currentThread().isInterrupted }
        val state = SupportRequestState()
        var localCall: Call? = null
        fun executePrepared(): okhttp3.Response {
            val body = object : RequestBody() {
                override fun contentType() = "application/json".toMediaType()
                override fun contentLength() = bytes.size.toLong()
                override fun isOneShot() = true
                override fun writeTo(sink: BufferedSink) { state.httpStarted = true; sink.write(bytes) }
            }
            var prepared = Request.Builder().url("https://nelomai.ru/api/client/v1/diagnostics/support")
                .header("Content-Type", "application/json").header("Accept", "application/json").header("Cookie", "")
                .apply { if (supportCode.isNotEmpty()) header("X-Nelomai-Diagnostics-Code", supportCode) }
                .post(body).tag(SupportRequestState::class.java, state).build()
            var stage = 0
            while (true) {
                if (stopped()) throw CancellationException()
                val remaining = deadline - System.nanoTime()
                if (remaining <= 0) throw java.io.InterruptedIOException()
                val call = newCall(prepared)
                localCall = call
                activeCall = call
                call.timeout().timeout(remaining, TimeUnit.NANOSECONDS)
                if (stopped()) { call.cancel(); throw CancellationException() }
                try { return call.execute() }
                catch (error: java.io.IOException) {
                    val tlsFailure = error is javax.net.ssl.SSLHandshakeException || error is javax.net.ssl.SSLPeerUnverifiedException
                    val knownConnectFailure = error is java.net.UnknownHostException || error is java.net.ConnectException ||
                        error is java.net.NoRouteToHostException || error is java.net.SocketTimeoutException ||
                        tlsFailure
                    if (stage >= 3 || (stage == 2 && !tlsFailure) || state.httpStarted || (!state.tracked && !knownConnectFailure) ||
                        stopped() || System.nanoTime() >= deadline) throw error
                    prepared = prepared.newBuilder().apply {
                        when (stage) {
                            0 -> url(prepared.url.newBuilder().host("nelomai.top").build()).removeHeader("Host")
                            1 -> tag(PanelDirectIpRoute::class.java, PanelDirectIpRoute)
                            // Same IP, other approved TLS identity; no retry after HTTP starts.
                            else -> url(prepared.url.newBuilder().host("nelomai.ru").build()).removeHeader("Host")
                        }
                    }.build()
                    stage++
                }
            }
        }
        return try {
            executePrepared().use { response ->
                val status = response.code
                if (status in 300..399) return SupportUploadResult.Failure("redirect_rejected", status)
                val body = response.body?.byteStream()?.use { input ->
                    val out = java.io.ByteArrayOutputStream()
                    val buffer = ByteArray(1024)
                    while (true) {
                        if (stopped() || System.nanoTime() >= deadline) throw java.io.InterruptedIOException()
                        val count = input.read(buffer)
                        if (count < 0) break
                        if (out.size() + count > 16 * 1024) return SupportUploadResult.Failure("response_too_large", status)
                        out.write(buffer, 0, count)
                    }
                    out.toString("UTF-8")
                }.orEmpty()
                if (stopped()) return SupportUploadResult.Failure("upload_cancelled")
                if (System.nanoTime() >= deadline) return SupportUploadResult.Failure("upload_timeout")
                val json = runCatching { JSONObject(body) }.getOrNull()
                if (status == 200) {
                    val id = json?.optString("report_id")
                    val requestId = json?.optString("request_id").orEmpty()
                    val received = json?.opt("received_bytes")
                    val receivedBytes = when (received) { is Int -> received.toLong(); is Long -> received; else -> null }
                    if (id != report.reportId || requestId.isBlank() || requestId.length > 128 || receivedBytes == null || receivedBytes < 0) {
                        SupportUploadResult.Failure("invalid_response", status)
                    } else SupportUploadResult.Success(report.reportId, requestId, receivedBytes)
                } else {
                    val code = json?.optString("code")?.takeIf { it in setOf(
                        "invalid_diagnostics_code", "diagnostics_code_exhausted", "diagnostics_report_id_conflict", "invalid_support_diagnostics",
                    ) } ?: "upload_rejected"
                    val retryAfter = response.header("Retry-After")?.toLongOrNull()?.takeIf { it in 0..86400 }
                    SupportUploadResult.Failure(code, status, retryAfter)
                }
            }
        } catch (_: Exception) {
            SupportUploadResult.Failure(when { stopped() -> "upload_cancelled"; System.nanoTime() >= deadline -> "upload_timeout"; else -> "transport_unavailable" })
        } finally {
            localCall?.cancel()
            if (activeCall === localCall) activeCall = null
        }
    }
}

internal fun validSupportDiagnosticsCode(value: String): Boolean = value.matches(Regex("nld_[A-Za-z0-9_-]{43}"))
