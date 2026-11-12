(() => {
  const dialog = document.getElementById("diagnostics");
  const collect = document.getElementById("collect-report");
  const save = document.getElementById("save-report");
  const send = document.getElementById("send-report");
  const code = document.getElementById("support-code");
  const status = document.getElementById("report-status");
  let report;

  const errors = new Map([
    ["save_failed", "Не удалось сохранить файл. Выберите другое место."],
    ["support_code_invalid", "Код поддержки недействителен или истёк."],
    ["support_timeout", "Панель не ответила вовремя. Отчёт можно сохранить или отправить повторно."],
    ["support_network_unavailable", "Нет связи с панелью. Отчёт можно сохранить и отправить позже."],
    ["support_rate_limited", "Панель временно ограничила отправку. Повторите позже."],
    ["support_unavailable", "Панель не подтвердила получение. Сохраните отчёт в файл."],
    ["support_rejected", "Панель не подтвердила получение. Сохраните отчёт в файл."],
    ["support_receipt_invalid", "Панель не подтвердила получение. Сохраните отчёт в файл."],
    ["report_expired", "Соберите отчёт заново."],
  ]);

  function invoke(command, args = {}) {
    return window.__TAURI_INTERNALS__.invoke(command, args);
  }

  async function run(message, operation) {
    if (collect.disabled) return;
    collect.disabled = save.disabled = send.disabled = code.disabled = true;
    status.textContent = message;
    try {
      status.textContent = await operation();
    } catch (error) {
      status.textContent = errors.get(error) ?? "Диагностика временно недоступна.";
    } finally {
      collect.disabled = save.disabled = send.disabled = code.disabled = false;
    }
  }

  const mode = window.location.hash;
  const close = document.getElementById("close-diagnostics");
  if (mode === "#support") {
    document.title = "Nelomai — диагностика";
    document.getElementById("failure-copy").hidden = true;
    close.hidden = true;
    dialog.show();
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) code.value = "";
    });
  } else {
    if (mode === "#interrupted") {
      document.title = "Работа Nelomai прервана";
      document.getElementById("failure-title").textContent = document.title;
      document.getElementById("failure-reason").textContent = "Компонент приложения неожиданно завершил работу.";
      document.getElementById("failure-retry").textContent = "Соберите отчёт, затем закройте это окно и откройте Nelomai снова.";
    }
    document.getElementById("open-diagnostics").addEventListener("click", () => dialog.showModal());
    close.addEventListener("click", () => dialog.close());
  }
  dialog.addEventListener("close", () => { code.value = ""; });

  collect.addEventListener("click", () => run("Собираем…", async () => {
    report = await invoke("app_collect_support_diagnostics");
    document.getElementById("report-actions").hidden = false;
    document.getElementById("report-details").textContent =
      `${Math.ceil(report.bytes / 1024)} КиБ · Источников журналов: ${report.logSources}.` +
      (report.incompleteSources ? " Часть данных недоступна или сокращена." : "") +
      (report.serviceAvailable ? "" : " Состояние службы недоступно.");
    collect.textContent = "Собрать заново";
    return "Отчёт готов.";
  }));
  save.addEventListener("click", () => {
    if (report) return run("Сохраняем…", async () =>
      await invoke("app_save_support_diagnostics", { reportId: report.reportId }) ? "Отчёт сохранён." : "");
  });
  send.addEventListener("click", () => {
    if (report) return run("Отправляем…", async () => {
      const id = await invoke("app_send_support_diagnostics", {
        reportId: report.reportId,
        supportCode: code.value.trim() || null,
      });
      code.value = "";
      return `Отчёт отправлен. Номер для поддержки: ${id.slice(0, 8)}.`;
    });
  });
})();
