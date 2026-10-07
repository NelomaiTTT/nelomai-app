package ru.nelomai.client

import org.json.JSONObject
import java.net.Proxy
import java.net.URL
import java.util.concurrent.CancellationException
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.HttpsURLConnection

internal sealed class SupportUploadResult {
    class Success(val reportId: String, val requestId: String, val receivedBytes: Long) : SupportUploadResult()
    data class Failure(val code: String, val status: Int? = null, val retryAfterSeconds: Long? = null) : SupportUploadResult()
}

/** Direct native HTTPS. Never consults ClientApi, runtime IPC, keyring, or account auth. */
internal class SupportDiagnosticUploader(
    private val connect: (URL) -> HttpsURLConnection = { it.openConnection(Proxy.NO_PROXY) as HttpsURLConnection },
) {
    @Volatile private var connection: HttpsURLConnection? = null
    @Volatile private var operation: FutureTask<SupportUploadResult>? = null
    private val cancelled = AtomicBoolean(false)

    fun cancel() {
        cancelled.set(true)
        operation?.cancel(true)
        disconnectAsync()
    }

    fun upload(report: SupportDiagnosticReport, supportCode: String): SupportUploadResult {
        require(validSupportDiagnosticsCode(supportCode))
        val bytes = report.payload.toByteArray(Charsets.UTF_8)
        require(bytes.size <= 768 * 1024)
        if (cancelled.get()) return SupportUploadResult.Failure("upload_cancelled")
        val task = FutureTask { performUpload(report, supportCode, bytes) }
        operation = task
        if (cancelled.get()) task.cancel(true)
        Thread(task, "support-https").apply { isDaemon = true }.start()
        return try { task.get(30, TimeUnit.SECONDS) }
        catch (_: TimeoutException) {
            task.cancel(true); disconnectAsync()
            SupportUploadResult.Failure("upload_timeout")
        } catch (_: CancellationException) { SupportUploadResult.Failure("upload_cancelled") }
        catch (_: InterruptedException) {
            task.cancel(true); disconnectAsync(); Thread.currentThread().interrupt()
            SupportUploadResult.Failure("upload_cancelled")
        } catch (_: Exception) { SupportUploadResult.Failure("transport_unavailable") }
        finally { if (operation === task) operation = null }
    }

    private fun disconnectAsync() {
        val active = connection ?: return
        Thread({ runCatching { active.disconnect() } }, "support-https-close").apply { isDaemon = true }.start()
    }

    private fun performUpload(report: SupportDiagnosticReport, supportCode: String, bytes: ByteArray): SupportUploadResult {
        val deadline = System.nanoTime() + 30_000_000_000L
        var request: HttpsURLConnection? = null
        return try {
            if (cancelled.get()) return SupportUploadResult.Failure("upload_cancelled")
            request = connect(URL("https://nelomai.ru/api/client/v1/diagnostics/support"))
            connection = request
            if (cancelled.get()) return SupportUploadResult.Failure("upload_cancelled")
            request.instanceFollowRedirects = false
            request.connectTimeout = 10_000
            request.readTimeout = 15_000
            request.useCaches = false
            request.requestMethod = "POST"
            request.doOutput = true
            request.setRequestProperty("Content-Type", "application/json")
            request.setRequestProperty("Accept", "application/json")
            request.setRequestProperty("Cookie", "")
            request.setRequestProperty("X-Nelomai-Diagnostics-Code", supportCode)
            request.setFixedLengthStreamingMode(bytes.size)
            request.outputStream.use { it.write(bytes) }
            val status = request.responseCode
            if (status in 300..399) return SupportUploadResult.Failure("redirect_rejected", status)
            val stream = if (status == 200) request.inputStream else request.errorStream
            val body = stream?.use { input ->
                val out = java.io.ByteArrayOutputStream()
                val buffer = ByteArray(1024)
                while (true) {
                    if (cancelled.get() || Thread.currentThread().isInterrupted || System.nanoTime() >= deadline) throw java.io.InterruptedIOException()
                    val count = input.read(buffer)
                    if (count < 0) break
                    if (out.size() + count > 16 * 1024) return SupportUploadResult.Failure("response_too_large", status)
                    out.write(buffer, 0, count)
                }
                out.toString("UTF-8")
            }.orEmpty()
            if (cancelled.get()) return SupportUploadResult.Failure("upload_cancelled")
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
                val retryAfter = request.getHeaderField("Retry-After")?.toLongOrNull()?.takeIf { it in 0..86400 }
                SupportUploadResult.Failure(code, status, retryAfter)
            }
        } catch (_: Exception) {
            SupportUploadResult.Failure(when { cancelled.get() || Thread.currentThread().isInterrupted -> "upload_cancelled"; System.nanoTime() >= deadline -> "upload_timeout"; else -> "transport_unavailable" })
        } finally {
            runCatching { request?.disconnect() }
            if (connection === request) connection = null
        }
    }
}

internal fun validSupportDiagnosticsCode(value: String): Boolean = value.matches(Regex("nld_[A-Za-z0-9_-]{43}"))
