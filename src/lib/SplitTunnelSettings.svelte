<script lang="ts">
  import {
    buildApplicationRows,
    settingsUpdate,
    splitTunnelWarningMessage,
    type InstalledApplication,
    type SplitTunnelMode,
    type SplitTunnelSettingsUpdate,
    type SplitTunnelState,
    type SplitTunnelAddressRule,
  } from "./split-tunnel";
  import { commandMessage } from "./native-client";

  let {
    state: settings,
    applications,
    busy,
    onclose,
    onsave,
    onrefresh,
    onaddaddressrule = undefined,
    onremoveaddressrule = undefined,
  }: {
    state: SplitTunnelState;
    applications: InstalledApplication[];
    busy: boolean;
    onclose: () => void;
    onsave: (request: SplitTunnelSettingsUpdate) => Promise<boolean>;
    onrefresh: () => Promise<void>;
    onaddaddressrule?: (
      value: string,
      scope: SplitTunnelAddressRule["scope"],
    ) => Promise<void>;
    onremoveaddressrule?: (
      ruleId: number,
      scope: SplitTunnelAddressRule["scope"],
    ) => Promise<void>;
  } = $props();

  let mode = $state<SplitTunnelMode>(initialMode());
  let excludeLocalNetworks = $state(initialLocalNetworks());
  let selected = $state(initialSelected());
  let search = $state("");
  let showSystem = $state(false);
  let localBusy = $state(false);
  let localError = $state<string | null>(null);
  let addressValue = $state("");

  let rows = $derived(
    buildApplicationRows(
      {
        ...settings,
        mode,
        excludeLocalNetworks,
        selectedPackages: [...selected],
      },
      applications,
      search,
      showSystem,
    ),
  );
  let addressRules = $derived(settings.addressRules ?? []);

  let androidLegacy = $derived(
    settings.capabilities.platform === "android" &&
      (settings.capabilities.androidApiLevel ?? 0) <= 32,
  );
  let applicationSettingsVisible = $derived(
    settings.capabilities.platform === "android" ||
      settings.capabilities.applicationSplitTunnel,
  );
  let desktopLocalNetworksForced = $derived(
    settings.capabilities.addressSplitTunnel &&
      ["windows", "linux", "macos"].includes(
        settings.capabilities.platform,
      ),
  );
  let localNetworksEditable = $derived(
    settings.capabilities.platform === "android" &&
      (settings.capabilities.androidApiLevel ?? 0) >= 33,
  );

  $effect(() => {
    mode = settings.mode;
    excludeLocalNetworks = settings.excludeLocalNetworks;
    selected = new Set(settings.selectedPackages);
  });

  function initialMode(): SplitTunnelMode {
    return settings.mode;
  }

  function initialLocalNetworks(): boolean {
    return settings.excludeLocalNetworks;
  }

  function initialSelected(): Set<string> {
    return new Set(settings.selectedPackages);
  }

  function togglePackage(packageId: string, checked: boolean) {
    const next = new Set(selected);
    if (checked) next.add(packageId);
    else next.delete(packageId);
    selected = next;
  }

  async function save() {
    if (localBusy || busy) return;
    localBusy = true;
    localError = null;
    try {
      const saved = await onsave(
        settingsUpdate(
          mode,
          excludeLocalNetworks,
          selected,
          applications,
          settings.mandatoryExcludedPackages,
        ),
      );
      if (saved) onclose();
    } catch (reason) {
      localError = commandMessage(reason, "split_tunnel");
    } finally {
      localBusy = false;
    }
  }

  async function refresh() {
    if (localBusy || busy) return;
    localBusy = true;
    localError = null;
    try {
      await onrefresh();
    } catch {
      localError = "Не удалось обновить настройки";
    } finally {
      localBusy = false;
    }
  }

  async function addAddressRule(scope: SplitTunnelAddressRule["scope"]) {
    const value = addressValue.trim();
    if (!value || !onaddaddressrule || localBusy || busy) return;
    localBusy = true;
    localError = null;
    try {
      await onaddaddressrule(value, scope);
      addressValue = "";
    } catch (reason) {
      localError = commandMessage(reason, "split_tunnel");
    } finally {
      localBusy = false;
    }
  }

  async function removeAddressRule(rule: SplitTunnelAddressRule) {
    if (!onremoveaddressrule || localBusy || busy) return;
    localBusy = true;
    localError = null;
    try {
      await onremoveaddressrule(rule.id, rule.scope);
    } catch (reason) {
      localError = commandMessage(reason, "split_tunnel");
    } finally {
      localBusy = false;
    }
  }
</script>

<div class="settings-overlay" role="presentation">
  <div
    class="split-settings"
    role="dialog"
    aria-modal="true"
    aria-labelledby="split-tunnel-title"
  >
    <header>
      <div>
        <p class="eyebrow">Подключение</p>
        <h2 id="split-tunnel-title">Split-tunnel</h2>
      </div>
      <button
        class="icon-button"
        type="button"
        aria-label="Закрыть"
        onclick={onclose}
        disabled={localBusy || busy}
      >
        ×
      </button>
    </header>

    {#if androidLegacy}
      <p class="notice">Split-tunnel доступен на Android 13 и новее</p>
    {/if}
    {#if !settings.enabled}
      <p class="notice">Функция пока выключена в общих настройках.</p>
    {/if}
    {#if settings.warning}
      <p class="warning">
        {splitTunnelWarningMessage(settings.warning)}
      </p>
    {/if}

    {#if applicationSettingsVisible}
      <fieldset disabled={localBusy || busy}>
        <legend>Режим приложений</legend>
        <div class="segmented">
          <label>
            <input
              type="radio"
              value="exclude_selected"
              bind:group={mode}
            />
            <span>Исключить выбранные</span>
          </label>
          <label>
            <input
              type="radio"
              value="include_selected"
              bind:group={mode}
            />
            <span>Только выбранные через VPN</span>
          </label>
        </div>
      </fieldset>
    {/if}

    <label class="toggle-row">
      <span>
        <strong>Исключить локальные адреса</strong>
        <small>
          {desktopLocalNetworksForced
            ? "На компьютере локальная сеть всегда доступна напрямую"
            : "Принтеры, роутеры и устройства в текущей сети"}
        </small>
      </span>
      <input
        type="checkbox"
        checked={desktopLocalNetworksForced || excludeLocalNetworks}
        onchange={(event) =>
          (excludeLocalNetworks = (
            event.currentTarget as HTMLInputElement
          ).checked)}
        disabled={localBusy || busy || !localNetworksEditable}
      />
    </label>

    {#if settings.enabled && settings.capabilities.addressSplitTunnel}
      <section class="address-rules" aria-labelledby="address-rules-title">
        <div>
          <p class="eyebrow">Адреса</p>
          <h3 id="address-rules-title">Исключить ресурс из VPN</h3>
          <p class="address-description">
            IPv4-адрес, домен или ссылка будут открываться напрямую.
          </p>
        </div>
        <div class="address-add">
          <input
            type="text"
            bind:value={addressValue}
            maxlength="2048"
            placeholder="Например, example.com или https://example.com/page"
            disabled={localBusy || busy}
          />
          <div class="address-actions">
            <button
              class="quiet-button"
              type="button"
              onclick={() => addAddressRule("this_device")}
              disabled={!addressValue.trim() || localBusy || busy}
            >Для этого устройства</button>
            <button
              class="quiet-button"
              type="button"
              onclick={() => addAddressRule("all_devices")}
              disabled={!addressValue.trim() || localBusy || busy}
            >Для всех моих</button>
          </div>
        </div>
        {#if addressRules.length}
          <ul class="address-rule-list">
            {#each addressRules as rule (`${rule.scope}:${rule.id}`)}
              <li>
                <span>
                  <strong>{rule.value}</strong>
                  <small>
                    {rule.scope === "all_devices"
                      ? "Все мои устройства"
                      : "Это устройство"}
                  </small>
                </span>
                <button
                  class="icon-button"
                  type="button"
                  aria-label={`Удалить ${rule.value}`}
                  onclick={() => removeAddressRule(rule)}
                  disabled={localBusy || busy}
                >×</button>
              </li>
            {/each}
          </ul>
        {/if}
      </section>
    {/if}

    {#if applicationSettingsVisible}
      <div class="application-tools">
        <label class="search-field">
          <span>Поиск приложений</span>
          <input
            type="search"
            bind:value={search}
            placeholder="Название или package ID"
          />
        </label>
        <label class="system-toggle">
          <input type="checkbox" bind:checked={showSystem} />
          <span>Показать системные</span>
        </label>
      </div>

      <div class="application-list">
        {#each rows as application (application.packageId)}
          <label class:locked={application.locked} class="application-row">
            <input
              type="checkbox"
              checked={application.selected}
              disabled={application.locked || localBusy || busy}
              onchange={(event) =>
                togglePackage(
                  application.packageId,
                  (event.currentTarget as HTMLInputElement).checked,
                )}
            />
            <span>
              <strong>{application.displayName}</strong>
              <small>{application.packageId}</small>
            </span>
            {#if application.mandatory}
              <em>
                {mode === "include_selected"
                  ? "Всегда вне VPN"
                  : "Обязательно"}
              </em>
            {:else if !application.available}
              <em>Не установлено</em>
            {:else if application.suggested}
              <em>Предлагаем</em>
            {/if}
          </label>
        {:else}
          <p class="empty">Подходящих приложений не найдено</p>
        {/each}
      </div>
    {/if}

    {#if localError}
      <p class="error" aria-live="polite">{localError}</p>
    {/if}

    <footer>
      <button
        class="quiet-button"
        type="button"
        onclick={refresh}
        disabled={localBusy || busy}
      >
        Принудительная синхронизация
      </button>
      <button
        class="primary-button"
        type="button"
        onclick={save}
        disabled={localBusy || busy}
      >
        {localBusy ? "Сохраняем…" : "Сохранить"}
      </button>
    </footer>
  </div>
</div>

<style>
  .settings-overlay {
    position: fixed;
    z-index: 30;
    inset: 0;
    padding: 24px;
    display: grid;
    place-items: center;
    background: rgba(3, 5, 7, 0.78);
    backdrop-filter: blur(12px);
  }

  .split-settings {
    width: min(760px, 100%);
    max-height: min(820px, calc(100dvh - 48px));
    padding: 26px;
    display: grid;
    gap: 22px;
    overflow-x: hidden;
    overflow-y: auto;
    color: #f5f6f8;
    border: 1px solid #3a444d;
    border-radius: 8px;
    background: #101418;
    box-shadow: 0 24px 80px rgba(0, 0, 0, 0.48);
  }

  header,
  footer,
  .toggle-row,
  .system-toggle,
  .application-row {
    display: flex;
    align-items: center;
  }

  header {
    justify-content: space-between;
    gap: 20px;
  }

  h2,
  h3,
  p {
    margin: 0;
  }

  h2 {
    font-size: 25px;
    letter-spacing: 0;
  }

  .eyebrow {
    margin-bottom: 6px;
    color: #68cfc0;
    font-size: 12px;
    font-weight: 720;
    text-transform: uppercase;
  }

  .icon-button {
    width: 40px;
    height: 40px;
    color: #e7ebee;
    border: 1px solid #3a444d;
    border-radius: 6px;
    background: #171c21;
    font-size: 25px;
    cursor: pointer;
  }

  .notice,
  .warning {
    padding: 12px 14px;
    color: #d4e9e5;
    border-left: 3px solid #67d5c4;
    background: #142723;
    line-height: 1.45;
  }

  .warning {
    color: #f2dfb2;
    border-left-color: #d6ac59;
    background: #2a2418;
  }

  fieldset {
    margin: 0;
    padding: 0;
    border: 0;
  }

  legend,
  .search-field > span {
    margin-bottom: 8px;
    color: #9ca5ad;
    font-size: 12px;
  }

  .segmented {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 4px;
    padding: 4px;
    border: 1px solid #333b43;
    border-radius: 7px;
    background: #0c1014;
  }

  .segmented label {
    position: relative;
  }

  .segmented input {
    position: absolute;
    opacity: 0;
    pointer-events: none;
  }

  .segmented span {
    min-height: 42px;
    padding: 8px;
    display: grid;
    place-items: center;
    border-radius: 5px;
    text-align: center;
  }

  .segmented input:checked + span {
    color: #eafffb;
    background: #225d55;
  }

  .toggle-row {
    justify-content: space-between;
    gap: 18px;
  }

  .address-rules {
    display: grid;
    gap: 12px;
    padding: 16px;
    border: 1px solid #333b43;
    border-radius: 7px;
    background: #0c1014;
  }

  h3 {
    margin: 0;
    font-size: 17px;
  }

  .address-description,
  .address-rule-list small {
    color: #9ca5ad;
    font-size: 13px;
  }

  .address-add {
    display: grid;
    gap: 8px;
  }

  .address-add input {
    min-width: 0;
    min-height: 42px;
    padding: 10px 12px;
    color: #f5f6f8;
    border: 1px solid #3a444d;
    border-radius: 6px;
    background: #171c21;
  }

  .address-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }

  .address-rule-list {
    margin: 0;
    padding: 0;
    display: grid;
    max-height: 220px;
    gap: 6px;
    overflow-y: auto;
    list-style: none;
  }

  .address-rule-list li {
    min-height: 44px;
    padding: 8px 10px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    border-top: 1px solid #283039;
  }

  .address-rule-list span {
    min-width: 0;
    display: grid;
    gap: 3px;
  }

  .address-rule-list strong {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .toggle-row > span {
    display: grid;
    gap: 4px;
  }

  .toggle-row small,
  .application-row small {
    color: #909aa3;
  }

  .toggle-row input,
  .system-toggle input,
  .application-row input {
    accent-color: #67d5c4;
  }

  .toggle-row input {
    width: 44px;
    min-height: 24px;
  }

  .application-tools {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    align-items: end;
    gap: 16px;
  }

  .search-field {
    display: grid;
  }

  .search-field input {
    width: 100%;
    min-height: 44px;
    padding: 0 12px;
    color: #fff;
    border: 1px solid #3a444d;
    border-radius: 6px;
    outline: none;
    background: #0c1014;
  }

  .system-toggle {
    min-height: 44px;
    gap: 8px;
  }

  .application-list {
    min-height: 360px;
    max-height: 660px;
    overflow-y: auto;
    border-block: 1px solid #2a3036;
  }

  .application-row {
    min-height: 64px;
    gap: 12px;
    border-bottom: 1px solid #252b31;
  }

  .application-row > span {
    min-width: 0;
    display: grid;
    flex: 1;
    gap: 3px;
  }

  .application-row strong,
  .application-row small {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .application-row em {
    color: #8edfd2;
    font-size: 11px;
    font-style: normal;
  }

  .application-row.locked {
    background: rgba(103, 213, 196, 0.05);
  }

  .empty {
    padding: 36px 0;
    color: #909aa3;
    text-align: center;
  }

  .error {
    color: #ff9999;
    font-size: 13px;
  }

  footer {
    justify-content: flex-end;
    gap: 10px;
  }

  button {
    min-height: 42px;
    padding: 0 16px;
    border: 0;
    border-radius: 6px;
    font: inherit;
    letter-spacing: 0;
    cursor: pointer;
  }

  button:disabled {
    cursor: wait;
    opacity: 0.58;
  }

  .primary-button {
    color: #06110f;
    background: #67d5c4;
    font-weight: 740;
  }

  .quiet-button {
    color: #d1d7dc;
    border: 1px solid #343c44;
    background: transparent;
  }

  @media (max-width: 620px) {
    .settings-overlay {
      padding: 0;
      place-items: stretch;
    }

    .split-settings {
      max-height: 100dvh;
      min-height: 100dvh;
      padding:
        max(20px, env(safe-area-inset-top, 0px))
        max(20px, env(safe-area-inset-right, 0px))
        max(20px, env(safe-area-inset-bottom, 0px))
        max(20px, env(safe-area-inset-left, 0px));
      border: 0;
      border-radius: 0;
    }

    .segmented,
    .application-tools {
      grid-template-columns: 1fr;
    }

    footer {
      align-items: stretch;
      flex-direction: column-reverse;
    }

    footer button {
      width: 100%;
    }
  }
</style>
