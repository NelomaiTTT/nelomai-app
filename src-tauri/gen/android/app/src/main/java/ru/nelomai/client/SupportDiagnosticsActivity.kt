package ru.nelomai.client

import android.app.Activity
import android.content.ClipData
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.core.content.FileProvider
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.Future
import ru.nelomai.runtime.v1.PersistentLogcat

/** Container-owned pre-login UI, deliberately independent of the runtime/owner. */
class SupportDiagnosticsActivity : Activity() {
    private lateinit var code: EditText
    private lateinit var status: TextView
    private val actions = mutableListOf<Button>()
    private lateinit var cancel: Button
    private lateinit var verboseStatus: TextView
    private lateinit var verboseStart: Button
    private lateinit var verboseStop: Button
    private val verboseTick = object : Runnable {
        override fun run() {
            refreshVerboseStatus()
            handler.postDelayed(this, 1_000)
        }
    }
    private val handler = Handler(Looper.getMainLooper())
    private val worker = Executors.newSingleThreadExecutor { task -> Thread(task, "support-diagnostics").apply { isDaemon = true } }
    @Volatile private var report: SupportDiagnosticReport? = null
    private var pendingSave: SupportDiagnosticReport? = null
    @Volatile private var uploader: SupportDiagnosticUploader? = null
    private var task: Future<*>? = null
    private var busy = false
    @Volatile private var attempt = 0

    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        val retained = lastNonConfigurationInstance as? RetainedReport
        report = retained?.report
        pendingSave = retained?.pendingSave
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 48, 24, 32)
        }
        fun text(value: String) = TextView(this).apply { text = value; setPadding(0, 8, 0, 16); layout.addView(this) }
        text("Диагностика Nelomai").textSize = 24f
        text("Вход в аккаунт не нужен. Собираются только ограниченные журналы Nelomai с удалением секретов. " +
            "Код поддержки разрешает только отправку отчёта; его срок и лимит проверяет сервер. Можно сохранить или поделиться отчётом без кода.")
        text("Обычно сохраняются информационные сообщения, предупреждения и ошибки. " +
            "Подробная запись выключится через 15 минут, при достижении 2 МиБ или после перезапуска процесса приложения. " +
            "Закрытие этого экрана запись не останавливает. После воспроизведения ошибки нажмите «Собрать новый отчёт». " +
            "Подробные сообщения отправляются только вручную.")
        verboseStatus = text("").apply { id = VERBOSE_STATUS }
        verboseStart = Button(this).apply {
            id = VERBOSE_START; text = "Подробная запись на 15 минут"
            setOnClickListener {
                if (PersistentLogcat.enableVerbose()) refreshVerboseStatus()
                else if (PersistentLogcat.verboseStatus().active) refreshVerboseStatus()
                else verboseStatus.text = "Сборщик недоступен. Повторите позже; обычное сохранение отчёта доступно."
            }
            layout.addView(this)
        }
        verboseStop = Button(this).apply {
            id = VERBOSE_STOP; text = "Остановить подробную запись"
            setOnClickListener { PersistentLogcat.stopVerbose(); refreshVerboseStatus() }
            layout.addView(this)
        }
        refreshVerboseStatus()
        text("Код поддержки")
        code = EditText(this).apply {
            id = CODE_FIELD
            hint = "Введите код вручную"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            isSingleLine = true
            isSaveEnabled = false
            isSaveFromParentEnabled = false
            if (Build.VERSION.SDK_INT >= 26) importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
            layout.addView(this)
        }
        status = text("Отчёт ещё не собран. Отправка выполняется только по нажатию кнопки.").apply { id = STATUS_VIEW; accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE }
        fun button(id: Int, label: String, action: () -> Unit) = Button(this).apply {
            this.id = id; text = label; setOnClickListener { action() }; layout.addView(this); actions += this
        }
        button(SEND_BUTTON, "Отправить / повторить отправку") { send() }
        button(SAVE_BUTTON, "Сохранить отчёт") { prepare { save(it) } }
        button(SHARE_BUTTON, "Поделиться отчётом") { prepare { share(it) } }
        button(View.generateViewId(), "Собрать новый отчёт") {
            report = null
            prepare { status.text = "Отчёт ${it.reportId} собран. Недоступные журналы отмечены в отчёте." }
        }
        cancel = button(View.generateViewId(), "Отменить") { cancelOperation() }
        cancel.isEnabled = false
        setContentView(ScrollView(this).apply { addView(layout) })
        report?.let { status.text = "Отчёт ${it.reportId} сохранён в памяти. Для повторной отправки введите код." }
        if (pendingSave != null) setBusy(true)
    }

    private class RetainedReport(val report: SupportDiagnosticReport?, val pendingSave: SupportDiagnosticReport?)
    override fun onRetainNonConfigurationInstance(): Any = RetainedReport(report, pendingSave)

    private fun refreshVerboseStatus() {
        val capture = PersistentLogcat.verboseStatus()
        verboseStart.isEnabled = !capture.active
        verboseStop.isEnabled = capture.active
        val seconds = (capture.remainingMillis + 999) / 1_000
        verboseStatus.text = if (capture.active) {
            "Подробная запись: ещё ${seconds / 60} мин ${seconds % 60} сек; ${capture.recordedBytes / 1024} из 2048 КиБ."
        } else "Подробная запись выключена. Ранее собранные журналы сохранены в пределах лимита."
    }

    override fun onResume() {
        super.onResume()
        handler.removeCallbacks(verboseTick)
        verboseTick.run()
    }

    override fun onPause() {
        handler.removeCallbacks(verboseTick)
        super.onPause()
    }

    private fun collect(enteredCode: String, current: Int): SupportDiagnosticReport = report ?: SupportDiagnosticCollector(
        filesDir, noBackupFilesDir, "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})",
    ).collect(enteredCode).also {
        if (current != attempt || Thread.currentThread().isInterrupted) throw InterruptedException()
        report = it
    }

    private fun setBusy(value: Boolean) {
        busy = value
        actions.forEach { it.isEnabled = !value }
        code.isEnabled = !value
        cancel.isEnabled = value
    }

    private fun send() {
        if (busy) return
        val enteredCode = code.text.toString().trim()
        if (!validSupportDiagnosticsCode(enteredCode)) {
            status.text = "Введите код поддержки: nld_ и 43 символа, без пробелов и переносов строк."
            return
        }
        val current = ++attempt
        setBusy(true); status.text = "Сбор и отправка отчёта…"
        val upload = SupportDiagnosticUploader().also { uploader = it }
        task = worker.submit {
            val result = try { upload.upload(collect(enteredCode, current), enteredCode) }
                catch (_: Exception) { SupportUploadResult.Failure("collection_failed") }
            handler.post {
                if (current != attempt || isDestroyed || isFinishing) return@post
                uploader = null; setBusy(false)
                status.text = when (result) {
                    is SupportUploadResult.Success -> "Отчёт ${result.reportId} отправлен. Принято ${result.receivedBytes} байт."
                    is SupportUploadResult.Failure -> "Отправка не выполнена: ${result.code}" +
                        (result.status?.let { " (HTTP $it)" } ?: "") +
                        (result.retryAfterSeconds?.let { ". Повторите вручную через $it сек." } ?: ". Можно повторить вручную.") +
                        " Отчёт доступен для сохранения и отправки через другое приложение."
                }
            }
        }
    }

    private fun prepare(action: (SupportDiagnosticReport) -> Unit) {
        if (busy) return
        val enteredCode = code.text.toString().trim()
        val current = ++attempt
        setBusy(true); status.text = "Сбор локального отчёта…"
        task = worker.submit {
            val result = runCatching { collect(enteredCode, current) }
            handler.post {
                if (current != attempt || isDestroyed || isFinishing) return@post
                setBusy(false)
                result.onSuccess { frozen ->
                    runCatching { action(frozen) }.onFailure { status.text = "local_export_unavailable: выберите сохранение отчёта." }
                }.onFailure { status.text = "collection_failed: не удалось собрать отчёт." }
            }
        }
    }

    private fun cancelOperation() {
        ++attempt
        uploader?.cancel()
        task?.cancel(true)
        setBusy(false)
        status.text = "operation_cancelled: отправка могла уже завершиться на сервере. Повтор использует тот же отчёт."
    }

    private fun save(frozen: SupportDiagnosticReport) {
        pendingSave = frozen
        setBusy(true)
        try {
            startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "application/json"
                putExtra(Intent.EXTRA_TITLE, "nelomai-diagnostics-${frozen.reportId}.json")
            }, SAVE_REQUEST)
        } catch (error: Exception) { pendingSave = null; setBusy(false); throw error }
    }

    private fun share(frozen: SupportDiagnosticReport) {
        val directory = File(cacheDir, "support-diagnostics").apply { check(mkdirs() || isDirectory) }
        val file = File(directory, "${frozen.reportId}.json").apply { writeText(frozen.payload, Charsets.UTF_8) }
        val uri = FileProvider.getUriForFile(this, "$packageName.fileprovider", file)
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "application/json"
            putExtra(Intent.EXTRA_STREAM, uri)
            clipData = ClipData.newRawUri("Nelomai diagnostics", uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        startActivity(Intent.createChooser(intent, "Поделиться отчётом Nelomai"))
        status.text = "Отчёт ${frozen.reportId} подготовлен для отправки через выбранное приложение."
    }

    @Deprecated("Platform activity result API is sufficient for the container screen")
    override fun onActivityResult(request: Int, result: Int, data: Intent?) {
        super.onActivityResult(request, result, data)
        if (request != SAVE_REQUEST) return
        val frozen = pendingSave
        pendingSave = null
        setBusy(false)
        if (result != RESULT_OK || data?.data == null) { status.text = "local_save_cancelled: отчёт сохранён в памяти."; return }
        if (frozen == null) { status.text = "local_save_unavailable: соберите отчёт заново."; return }
        val uri = data.data!!
        val current = ++attempt
        setBusy(true)
        status.text = "Сохраняем отчёт…"
        task = worker.submit {
            // Only our already-sanitized snapshot is written to the user-selected destination.
            val saved = runCatching { contentResolver.openOutputStream(uri, "wt")!!.use { out -> out.write(frozen.payload.toByteArray(Charsets.UTF_8)) } }.isSuccess
            handler.post {
                if (current != attempt || isDestroyed || isFinishing) return@post
                setBusy(false)
                status.text = if (saved) "Отчёт ${frozen.reportId} сохранён." else "local_save_failed: попробуйте поделиться отчётом."
            }
        }
    }

    override fun onDestroy() {
        ++attempt
        code.setText("")
        uploader?.cancel()
        task?.cancel(true); worker.shutdownNow(); handler.removeCallbacksAndMessages(null)
        super.onDestroy()
    }

    companion object {
        const val CODE_FIELD = 0x00d10001
        const val STATUS_VIEW = 0x00d10002
        const val SEND_BUTTON = 0x00d10003
        const val SAVE_BUTTON = 0x00d10004
        const val SHARE_BUTTON = 0x00d10005
        const val VERBOSE_START = 0x00d10006
        const val VERBOSE_STOP = 0x00d10007
        const val VERBOSE_STATUS = 0x00d10008
        private const val SAVE_REQUEST = 10
    }
}
