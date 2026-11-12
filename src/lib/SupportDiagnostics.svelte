<script lang="ts">
  import {
    nativeClient,
    type SupportReportSummary,
  } from "./native-client";
  import { supportErrorMessage } from "./support-diagnostics";

  let { open = $bindable(false) }: { open?: boolean } = $props();
  let dialog: HTMLDialogElement;
  let report = $state<SupportReportSummary | null>(null);
  let busy = $state<"collect" | "save" | "send" | null>(null);
  let status = $state("");
  let supportCode = $state("");

  export function show() {
    if (!dialog.open) {
      dialog.showModal();
      open = true;
    }
  }

  function handleClose() {
    open = false;
    supportCode = "";
  }

  async function collect() {
    if (busy) return;
    busy = "collect";
    status = "";
    try {
      report = await nativeClient.collectSupportDiagnostics();
      status = "Отчёт готов.";
    } catch (error) {
      status = supportErrorMessage(error);
    } finally {
      busy = null;
    }
  }

  async function save() {
    if (busy || !report) return;
    busy = "save";
    status = "";
    try {
      if (await nativeClient.saveSupportDiagnostics(report.reportId)) {
        status = "Отчёт сохранён.";
      }
    } catch (error) {
      status = supportErrorMessage(error);
    } finally {
      busy = null;
    }
  }

  async function send() {
    if (busy || !report) return;
    busy = "send";
    status = "";
    try {
      const id = await nativeClient.sendSupportDiagnostics(report.reportId, supportCode.trim() || null);
      supportCode = "";
      status = `Отчёт отправлен. Номер для поддержки: ${id.slice(0, 8)}.`;
    } catch (error) {
      status = supportErrorMessage(error);
    } finally {
      busy = null;
    }
  }
</script>

<dialog bind:this={dialog} onclose={handleClose} aria-labelledby="support-diagnostics-title">
  <div class="heading">
    <h2 id="support-diagnostics-title">Диагностика</h2>
    <button type="button" aria-label="Закрыть диагностику" onclick={() => dialog.close()}>×</button>
  </div>
  <p>Соберите отчёт о запуске и подключении. Его можно сохранить в файл или отправить в поддержку без входа.</p>
  <button type="button" disabled={busy !== null} onclick={collect}>
    {busy === "collect" ? "Собираем…" : report ? "Собрать заново" : "Собрать отчёт"}
  </button>
  {#if report}
    <p class="details">
      {Math.ceil(report.bytes / 1024)} КиБ · Источников журналов: {report.logSources}.
      {report.incompleteSources ? "Часть данных недоступна или сокращена." : ""}
      {report.serviceAvailable ? "" : " Состояние службы недоступно."}
    </p>
    <label>
      Код поддержки <span>(если выдали)</span>
      <input
        type="password"
        bind:value={supportCode}
        autocomplete="off"
        spellcheck={false}
        maxlength="47"
        disabled={busy !== null}
      />
    </label>
    <div class="actions">
      <button type="button" disabled={busy !== null} onclick={save}>
        {busy === "save" ? "Сохраняем…" : "Сохранить файл"}
      </button>
      <button class="send" type="button" disabled={busy !== null} onclick={send}>
        {busy === "send" ? "Отправляем…" : "Отправить отчёт"}
      </button>
    </div>
  {/if}
  <p class="status" role="status">{status}</p>
</dialog>

<style>
  dialog {
    width: min(500px, calc(100vw - 40px));
    max-height: calc(100dvh - 40px);
    box-sizing: border-box;
    overflow: auto;
    padding: 24px;
    border: 1px solid #65707866;
    border-radius: 12px;
    background: #10161a;
    color: #f4f6f6;
    box-shadow: 0 16px 60px #0006;
  }
  dialog::backdrop { background: #0a1119aa; }
  .heading, .actions { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
  .heading { justify-content: space-between; }
  h2 { margin: 0; font-size: 1.45rem; }
  p { margin: 16px 0; line-height: 1.5; }
  .details, label span { color: #b2bfc4; }
  label { display: grid; margin: 16px 0; gap: 6px; }
  input, button {
    border: 1px solid #61747877;
    border-radius: 8px;
    padding: 8px 12px;
    font: inherit;
    color: inherit;
    background: #1b252b;
  }
  button:not(:disabled) { cursor: pointer; }
  .send { background: #6bd3c5; color: #081719; }
  .status { min-height: 1.5em; margin-bottom: 0; }
</style>
