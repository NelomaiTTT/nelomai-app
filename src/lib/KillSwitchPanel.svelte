<script lang="ts">
  import type { KillSwitchStatus } from "./kill-switch";
  let { status, busy, actionError = null, onenabled, onstop, onretry }: {
    status: KillSwitchStatus; busy: boolean; actionError?: string | null;
    onenabled: (enabled: boolean) => void; onstop: () => void; onretry: () => void;
  } = $props();
</script>
<section class="protection" aria-label="Защита от утечки IP">
  <label>
    <strong>Защита от утечки IP</strong>
    <input type="checkbox" checked={status.enabled === true} disabled={busy || !status.supported || status.enabled === null}
      onchange={(event) => { const value = event.currentTarget.checked; event.currentTarget.checked = status.enabled === true; onenabled(value); }} />
  </label>
  <p role="status">
    {#if !status.supported}Защита недоступна в этой версии приложения.
    {:else if status.state === "unknown"}Статус защиты неизвестен. Блокировка не подтверждена.
    {:else if status.error === "protection_lost"}Защита прервалась. Она возобновится после успешного VPN-подключения.
    {:else if status.error === "vpn_permission_revoked"}Разрешение VPN отозвано. Защита выключена.
    {:else if status.state === "blocked"}Интернет заблокирован для защиты IP.
    {:else if status.state === "armed"}Защита активна. Выбранный трафик идёт через VPN.
    {:else if status.enabled}Защита включится после успешного VPN-подключения.
    {:else}Защита выключена.{/if}
  </p>
  {#if status.cause === "captive_portal"}<p>Сеть требует входа. Автоматически снимать блокировку приложение не будет.</p>{/if}
  {#if status.cause === "action_required"}<p>Для восстановления проверьте вход в аккаунт и разрешение VPN.</p>{/if}
  {#if status.externalLockdown}<p>В Android включена системная блокировка без VPN. Локальный Stop её не отключает.</p>{/if}
  {#if actionError}<p role="alert">{actionError}</p>{/if}
  <div class="actions">
    {#if status.state === "blocked"}<button type="button" disabled={busy} onclick={onretry}>Повторить сейчас</button>{/if}
    <button type="button" onclick={onstop}>Выключить VPN и блокировку</button>
  </div>
  <details>
    <summary>Как работает защита</summary>
    <p>После первого успешного подключения защита удерживает выбранный для VPN трафик при сбое, пока приложение восстанавливает связь. Исключения split tunneling сохраняют прямой доступ. Закрытие окна не выключает защиту.</p>
    <p>Принудительная остановка, гибель VPN-процесса или перезагрузка устройства могут прервать защиту. После перезапуска она включится только при новом успешном подключении. Эта функция не включает системную блокировку Android.</p>
    <p>Чтобы выйти из блокировки без доступа к серверу, нажмите «Выключить VPN и блокировку». Сохранённый выбор защиты останется для следующего подключения. Если Android отдельно запрещает соединения без VPN, измените эту системную настройку самостоятельно.</p>
  </details>
</section>
<style>
  .protection { padding: 16px 20px; margin: 12px 0; border: 1px solid #30443d; border-radius: 16px; background: #101f1b; color: #eef5f1; }
  label { display: flex; align-items: center; justify-content: space-between; gap: 16px; }
  input { width: 20px; height: 20px; accent-color: #a7edca; }
  p { margin: 10px 0; line-height: 1.5; font-size: 14px; }
  .actions { display: flex; flex-wrap: wrap; gap: 8px; margin: 12px 0; }
  button { border: 1px solid #648474; border-radius: 10px; padding: 10px 14px; background: transparent; color: inherit; cursor: pointer; }
  button:disabled { opacity: .5; cursor: wait; }
  summary { cursor: pointer; font-size: 14px; }
</style>
