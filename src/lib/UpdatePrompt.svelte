<script lang="ts">
  import type {UpdateStatus} from "./app-model";
  import {canConfirmUpdate} from "./update-presentation";
  let {status,visible,busy,onconfirm,onlater,onpresented,ondiagnostics,diagnosticsOpen=false}:{
    status:UpdateStatus;visible:boolean;busy:boolean;onconfirm:()=>void;onlater:()=>void;
    onpresented:()=>void;ondiagnostics?:()=>void;diagnosticsOpen?:boolean;
  }=$props();
  let dialog:HTMLDialogElement;
  $effect(()=>{if(!dialog)return;if(visible&&!diagnosticsOpen&&!dialog.open){dialog.showModal();onpresented();}else if(!visible&&dialog.open){dialog.close();}});
</script>
<dialog bind:this={dialog} oncancel={(event)=>{event.preventDefault();onlater();}} aria-labelledby="update-confirm-title">
  <h2 id="update-confirm-title">Установить новую версию</h2>
  <p>Nelomai {status.version}</p>
  <p>{status.phase === "checking" ? "Проверяем, доступна ли эта версия…" : status.phase === "downloading" ? "Обновление скачивается. После «Да» дождёмся загрузки и проверки файла." : "Перед установкой проверим файл обновления."}</p>
  <p>Для установки VPN будет отключён. Может потребоваться системное подтверждение.</p>
  <div class="actions">
    {#if ondiagnostics}
      <button type="button" class="later" onclick={ondiagnostics}>Диагностика</button>
    {/if}
    <button type="button" class="later" disabled={busy} onclick={onlater}>Нет, позже</button><button type="button" class="confirm" disabled={busy || !canConfirmUpdate(status)} onclick={onconfirm}>Да</button></div>
</dialog>
<style>
 dialog{width:min(420px,calc(100vw - 48px));box-sizing:border-box;border:1px solid #68707855;border-radius:8px;padding:28px;background:#101418;color:#f5f6f8;box-shadow:0 20px 80px #0005}
 dialog::backdrop{background:#10182088}h2{font-size:23px;margin:0 0 16px}p{line-height:1.5;font-size:14px}.actions{display:flex;flex-wrap:wrap;justify-content:flex-end;gap:10px;margin-top:24px}button{border-radius:12px;padding:11px 17px;border:1px solid #7775;font:inherit;cursor:pointer}.confirm{background:#68d5c8;color:#071511}.later{background:transparent;color:inherit}
</style>
