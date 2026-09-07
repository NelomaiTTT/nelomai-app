<script lang="ts">
  import {
    createRuntimeSelectorActions,
    runtimeRestartRequired,
    runtimeSelectorVisible,
    type RuntimeStatus,
  } from "./app-model";

  let {
    status,
    busy,
    onselect,
    onrestart,
  }: {
    status: RuntimeStatus;
    busy: boolean;
    onselect: (useStable: boolean) => Promise<void>;
    onrestart: () => Promise<void>;
  } = $props();

  let requestBusy = $state(false);
  let restartDismissed = $state(false);
  const actions = createRuntimeSelectorActions(
    (useStable) => onselect(useStable),
    () => onrestart(),
  );

  async function select(useStable: boolean) {
    requestBusy = true;
    restartDismissed = false;
    try {
      await actions.select(useStable);
    } finally {
      requestBusy = false;
    }
  }

  function later() {
    actions.later();
    restartDismissed = true;
  }
</script>

{#if runtimeSelectorVisible(status)}
  <section class="runtime-selector" aria-label="Версия runtime">
    <div>
      <p>Runtime</p>
      <strong>Контракт {status.runtimeContractVersion}</strong>
    </div>
    <label class="stable-toggle">
      <span>
        <strong>Использовать стабильную версию</strong>
        <small>{status.latestVersion} → {status.stableVersion}</small>
      </span>
      <input
        type="checkbox"
        checked={(status.pendingSlot ?? status.selectedSlot) === "stable"}
        disabled={busy || requestBusy}
        onchange={(event) => select(event.currentTarget.checked)}
      />
    </label>
  </section>

  {#if runtimeRestartRequired(status) && !restartDismissed}
    <section class="runtime-restart" aria-live="polite">
      <div>
        <strong>Runtime будет изменён после перезапуска</strong>
        <span>Новое подключение недоступно до безопасного перезапуска.</span>
      </div>
      <div class="runtime-actions">
        <button type="button" onclick={later} disabled={busy || requestBusy}>Позже</button>
        <button
          class="restart"
          type="button"
          onclick={() => actions.restartNow()}
          disabled={busy || requestBusy}
        >
          Перезапустить сейчас
        </button>
      </div>
    </section>
  {/if}
{/if}

<style>
  .runtime-selector,
  .runtime-restart {
    padding-top: 18px;
    display: grid;
    gap: 12px;
    border-top: 1px solid #2a3036;
  }

  .runtime-selector > div,
  .runtime-restart > div:first-child {
    display: grid;
    gap: 4px;
  }

  p,
  strong,
  span {
    margin: 0;
  }

  p,
  .runtime-restart span {
    color: #9ca5ad;
    font-size: 12px;
  }

  .stable-toggle {
    display: grid;
    grid-template-columns: 1fr auto;
    align-items: center;
    gap: 16px;
  }

  .stable-toggle > span {
    display: grid;
    gap: 4px;
  }

  .stable-toggle small {
    color: #9ca5ad;
  }

  .stable-toggle input {
    width: 42px;
    height: 22px;
    accent-color: #67d5c4;
  }

  .runtime-restart {
    color: #ffe5ae;
  }

  .runtime-actions {
    display: flex;
    gap: 8px;
  }

  button {
    min-height: 38px;
    padding: 0 12px;
    color: #effaf8;
    border: 1px solid #5e5137;
    border-radius: 6px;
    background: #2a2112;
    cursor: pointer;
  }

  button.restart {
    color: #06110f;
    border-color: #67d5c4;
    background: #67d5c4;
    font-weight: 740;
  }

  button:disabled {
    cursor: wait;
    opacity: 0.58;
  }

  @media (max-width: 420px) {
    .runtime-actions {
      flex-direction: column;
    }
  }
</style>
