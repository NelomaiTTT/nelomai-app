<script lang="ts">
  import { onMount } from "svelte";
  import { addPluginListener, type PluginListener } from "@tauri-apps/api/core";
  import { getCurrentWindow } from "@tauri-apps/api/window";
  import { listen, type UnlistenFn } from "@tauri-apps/api/event";
  import SplitTunnelSettings from "$lib/SplitTunnelSettings.svelte";
  import NotificationsPanel from "$lib/NotificationsPanel.svelte";
  import { appendNotificationPage, mergeRefreshedNotifications } from "$lib/notifications";

  import {
    bindingRequest,
    defaultRouteModeForLayer,
    requiresServerProbes,
    viewForPhase,
    type AppView,
    type AppPreferences,
    type Bootstrap,
    type Connection,
    type ConnectionMetrics,
    type Layer,
    type PeerOption,
    type Phase,
    type RouteMode,
    type TicConnectionMode,
    type UpdateStatus,
  } from "$lib/app-model";
  import {
    commandMessage,
    nativeClient,
    type AppNotification,
    type LoginRequest,
  } from "$lib/native-client";
  import {
    emptyIncludeSelection,
    splitTunnelWarningMessage,
    type InstalledApplication,
    type SplitTunnelSettingsUpdate,
    type SplitTunnelAddressRule,
    type SplitTunnelState,
  } from "$lib/split-tunnel";

  let view = $state<AppView>("loading");
  let phase = $state<Phase>("signed_out");
  let bootstrap = $state<Bootstrap | null>(null);
  let peers = $state<PeerOption[]>([]);
  let selectedPeerId = $state("");
  let selectedLayer = $state<Layer>("stray");
  let ticConnectionMode = $state<TicConnectionMode>("dynamic");
  let routeMode = $state<RouteMode>("standalone");
  let busy = $state(false);
  let probeBusy = $state(false);
  let availableCandidates = $state(0);
  let connection = $state<Connection | null>(null);
  let connectionMetrics = $state<ConnectionMetrics | null>(null);
  let pinnedStray = $state<Connection | null>(null);
  let error = $state<string | null>(null);
  let diagnosticsBusy = $state(false);
  let diagnosticsStatus = $state<string | null>(null);
  let updateStatus = $state<UpdateStatus | null>(null);
  let updateBusy = $state(false);
  let updateTimer: number | null = null;
  let stateTimer: number | null = null;
  let runtimeStateBusy = false;
  let splitTunnelState = $state<SplitTunnelState | null>(null);
  let splitTunnelApplications = $state<InstalledApplication[]>([]);
  let splitTunnelOpen = $state(false);
  let splitTunnelBusy = $state(false);
  let splitTunnelLoaded = $state(false);
  let runtimeWarning = $state<string | null>(null);
  let notifications = $state<AppNotification[]>([]);
  let notificationUnreadCount = $state(0);
  let notificationNextCursor = $state<number | null>(null);
  let notificationHistoryExpanded = $state(false);
  let notificationsOpen = $state(false);
  let notificationsBusy = $state(false);
  let notificationsError = $state<string | null>(null);
  let appPreferences = $state<AppPreferences | null>(null);
  let quickActionBusy = false;
  let quickActionQueued = false;
  let quickActionRetryTimer: number | null = null;
  let quickActionListener: PluginListener | null = null;
  let nativeStateUnlisten: UnlistenFn | null = null;
  let splitTunnelBlocksStart = $derived(
    splitTunnelState !== null &&
      emptyIncludeSelection(splitTunnelState, splitTunnelApplications),
  );

  let login = $state("");
  let password = $state("");
  let deviceName = $state("Это устройство");

  const phaseLabels: Record<Phase, string> = {
    signed_out: "Вход не выполнен",
    authenticating: "Входим",
    needs_peer_binding: "Нужно выбрать пир",
    access_expired: "Доступ истёк",
    ready: "Готово к подключению",
    measuring: "Проверяем серверы",
    connecting: "Подключаемся",
    connected: "Подключено",
    stopping: "Отключаемся",
    update_required: "Требуется обновление",
    server_unavailable: "Сервер недоступен",
    error: "Что-то пошло не так",
  };

  onMount(() => {
    let disposed = false;
    void restore();
    void loadAppPreferences();
    void initializeQuickActions().then((listener) => {
      if (disposed) {
        void listener?.unregister();
      } else {
        quickActionListener = listener;
      }
    });
    void listen<string | null>("native-connection-changed", (event) => {
      if (event.payload) error = event.payload;
      void synchronizeRuntimeState();
    }).then((unlisten) => {
      if (disposed) unlisten();
      else nativeStateUnlisten = unlisten;
    });
    stateTimer = window.setInterval(() => {
      if (document.visibilityState === "visible") void synchronizeRuntimeState();
    }, 1_000);
    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible") void refreshProbes();
    }, 300_000);
    const notificationTimer = window.setInterval(() => {
      if (document.visibilityState === "visible" && bootstrap) {
        void refreshNotifications(false, true);
      }
    }, 60_000);
    const handleVisibility = () => {
      if (document.visibilityState === "visible") {
        void synchronizeRuntimeState();
        void refreshProbes();
        if (bootstrap) void refreshNotifications(false, true);
      }
    };
    document.addEventListener("visibilitychange", handleVisibility);
    return () => {
      disposed = true;
      window.clearInterval(timer);
      window.clearInterval(notificationTimer);
      if (stateTimer !== null) window.clearInterval(stateTimer);
      document.removeEventListener("visibilitychange", handleVisibility);
      clearUpdateTimer();
      if (quickActionRetryTimer !== null) window.clearTimeout(quickActionRetryTimer);
      void quickActionListener?.unregister();
      nativeStateUnlisten?.();
    };
  });

  async function loadAppPreferences() {
    appPreferences = await nativeClient.preferences().catch(() => null);
  }

  async function setCloseToTray(event: Event) {
    const enabled = (event.currentTarget as HTMLInputElement).checked;
    try {
      appPreferences = await nativeClient.setCloseToTray(enabled);
    } catch (reason) {
      error = commandMessage(reason);
    }
  }

  async function initializeQuickActions(): Promise<PluginListener | null> {
    let listener: PluginListener | null = null;
    try {
      listener = await addPluginListener("tunnel-android", "quick-toggle", () => {
        void nativeClient.takeQuickAction().then((pending) => {
          if (!pending) return;
          quickActionQueued = true;
          void processQuickAction();
        });
      });
      if (await nativeClient.takeQuickAction()) quickActionQueued = true;
      void processQuickAction();
    } catch {
      // The Android quick-action bridge is intentionally absent on desktop.
    }
    return listener;
  }

  async function processQuickAction() {
    if (!quickActionQueued) return;
    if (quickActionBusy || busy) {
      scheduleQuickAction();
      return;
    }
    quickActionQueued = false;
    quickActionBusy = true;
    error = null;
    try {
      const current = await nativeClient.quickToggle();
      phase = current.phase;
      connection = current.connection;
      connectionMetrics = current.metrics;
      runtimeWarning = current.warning;
      view = viewForPhase(current.phase);
    } catch (reason) {
      error = commandMessage(reason);
      await getCurrentWindow().show().catch(() => undefined);
      await getCurrentWindow().setFocus().catch(() => undefined);
    } finally {
      quickActionBusy = false;
      if (quickActionQueued) scheduleQuickAction();
    }
  }

  function scheduleQuickAction() {
    if (quickActionRetryTimer !== null) return;
    quickActionRetryTimer = window.setTimeout(() => {
      quickActionRetryTimer = null;
      void processQuickAction();
    }, 150);
  }

  async function synchronizeRuntimeState() {
    if (
      busy ||
      runtimeStateBusy ||
      !bootstrap?.binding ||
      !["ready", "connecting", "connected", "stopping"].includes(phase)
    ) {
      return;
    }
    runtimeStateBusy = true;
    try {
      const previous = phase;
      const current = await nativeClient.state().catch(() => null);
      if (!current) return;
      runtimeWarning = current.warning;
      connectionMetrics = current.metrics;
      if (current.phase === phase) {
        connection = current.connection;
        return;
      }
      phase = current.phase;
      connection = current.connection;
      view = viewForPhase(current.phase);
      if (
        (previous === "connected" || previous === "connecting") &&
        current.phase !== "connected" &&
        current.phase !== "connecting" &&
        current.phase !== "stopping"
      ) {
        error = "Подключение остановилось. Запустите его снова.";
        await loadSplitTunnel(false);
      }
    } finally {
      runtimeStateBusy = false;
    }
  }

  async function restore() {
    busy = true;
    error = null;
    diagnosticsStatus = null;
    try {
      const response = await nativeClient.bootstrap();
      await applyBootstrap(response);
    } catch (reason) {
      const code = commandCode(reason);
      if (code === "signed_out") {
        phase = "signed_out";
        view = "sign_in";
      } else if (code === "access_expired") {
        phase = "access_expired";
        view = "access_expired";
      } else if (code === "update_required") {
        phase = "update_required";
        view = "update_required";
      } else {
        phase = "server_unavailable";
        view = "unavailable";
        error = commandMessage(reason);
      }
    } finally {
      busy = false;
      if (quickActionQueued) void processQuickAction();
    }
  }

  async function applyBootstrap(response: Bootstrap) {
    bootstrap = response;
    pinnedStray = response.pinned_stray;
    selectedLayer = response.defaults.layer;
    ticConnectionMode = response.defaults.tic_connection_mode;
    routeMode = response.defaults.route_mode;
    void refreshUpdateStatus();
    void refreshNotifications(false, true);

    if (response.update.required) {
      phase = "update_required";
      view = "update_required";
      return;
    }
    if (!response.access.can_connect || response.access.state === "expired") {
      phase = "access_expired";
      view = "access_expired";
      return;
    }
    if (!response.binding) {
      phase = "needs_peer_binding";
      view = "peer_selection";
      await loadPeers();
      return;
    }

    const state = await nativeClient.state();
    phase = state.phase;
    connection = state.connection;
    connectionMetrics = state.metrics;
    runtimeWarning = state.warning;
    view = viewForPhase(state.phase);
    await loadSplitTunnel(false);
    if (state.phase === "ready") void refreshProbes();
  }

  async function submitLogin(event: SubmitEvent) {
    event.preventDefault();
    if (busy) return;
    busy = true;
    error = null;
    diagnosticsStatus = null;
    phase = "authenticating";
    try {
      const request: LoginRequest = {
        login: login.trim(),
        password,
        deviceName: deviceName.trim() || "Это устройство",
        platformVersion: null,
      };
      const response = await nativeClient.login(request);
      password = "";
      await applyBootstrap(response);
    } catch (reason) {
      phase = "signed_out";
      view = "sign_in";
      error = commandMessage(reason);
    } finally {
      busy = false;
    }
  }

  async function loadPeers() {
    error = null;
    try {
      const response = await nativeClient.peerOptions();
      peers = response.peers;
      selectedPeerId =
        response.peers.find((peer) => peer.selectable)?.id ?? "";
    } catch (reason) {
      peers = [];
      selectedPeerId = "";
      error = commandMessage(reason);
    }
  }

  function changeLayer(event: Event) {
    selectedLayer = (event.currentTarget as HTMLInputElement).value as Layer;
    routeMode = defaultRouteModeForLayer(selectedLayer);
    void refreshProbes();
  }

  async function bindSelectedPeer() {
    if (!bootstrap || !selectedPeerId || busy) return;
    busy = true;
    error = null;
    try {
      await nativeClient.bindPeer(
        bindingRequest(selectedPeerId, bootstrap),
      );
      await restore();
    } catch (reason) {
      error = commandMessage(reason);
    } finally {
      busy = false;
    }
  }

  async function toggleConnection() {
    if (busy) return;
    if (phase !== "connected" && splitTunnelBlocksStart) {
      splitTunnelOpen = true;
      return;
    }
    const stopping = phase === "connected" || phase === "stopping";
    busy = true;
    error = null;
    try {
      if (stopping) {
        connection = await nativeClient.stop();
        connectionMetrics = null;
        phase = "ready";
      } else {
        phase = "connecting";
        connectionMetrics = null;
        await nativeClient.prepareTunnel();
        await syncBindingPreferences();
        connection = await nativeClient.start({
          layer: selectedLayer,
          ticConnectionMode,
          routeMode: selectedLayer === "stray" ? "standalone" : routeMode,
          allowAlternate: true,
        });
        phase = "connected";
      }
      view = "connection";
      const current = await nativeClient.state();
      runtimeWarning = current.warning;
      connectionMetrics = current.metrics;
    } catch (reason) {
      const current = await nativeClient.state().catch(() => null);
      phase = current?.phase ?? (stopping ? "stopping" : "error");
      connection = current?.connection ?? connection;
      connectionMetrics = current?.metrics ?? connectionMetrics;
      runtimeWarning = current?.warning ?? runtimeWarning;
      error = commandMessage(reason);
    } finally {
      busy = false;
    }
  }

  async function syncBindingPreferences() {
    const binding = bootstrap?.binding;
    if (!binding) return;
    const desiredMode =
      selectedLayer === "stray" ? "dynamic" : ticConnectionMode;
    const desiredRoute =
      selectedLayer === "stray" ? "standalone" : routeMode;
    if (
      binding.preferred_layer === selectedLayer &&
      binding.tic_connection_mode === desiredMode &&
      binding.route_mode === desiredRoute
    ) {
      return;
    }
    const response = await nativeClient.bindPeer({
      peer_id: binding.peer_id,
      preferred_layer: selectedLayer,
      tic_connection_mode: desiredMode,
      route_mode: desiredRoute,
    });
    if (response.binding && bootstrap) {
      bootstrap = {
        ...bootstrap,
        binding: response.binding,
        defaults: {
          layer: selectedLayer,
          tic_connection_mode: desiredMode,
          route_mode: desiredRoute,
        },
      };
    }
  }

  async function toggleSavedStray() {
    if (busy) return;
    const leaseId =
      pinnedStray?.lease_id ??
      (connection?.layer === "stray" && connection.pinned
        ? connection.lease_id
        : null);
    busy = true;
    error = null;
    try {
      if (leaseId) {
        const updated = await nativeClient.unpinStray(leaseId);
        if (connection?.lease_id === leaseId) connection = updated;
        pinnedStray = null;
      } else {
        connection = await nativeClient.pinStray();
        pinnedStray = connection;
      }
    } catch (reason) {
      error = commandMessage(reason);
    } finally {
      busy = false;
    }
  }

  async function unbindPeer() {
    if (busy) return;
    busy = true;
    error = null;
    try {
      await nativeClient.unbindPeer();
      connection = null;
      pinnedStray = null;
      bootstrap = bootstrap
        ? { ...bootstrap, binding: null, connection: null, pinned_stray: null }
        : null;
      phase = "needs_peer_binding";
      view = "peer_selection";
      await loadPeers();
    } catch (reason) {
      error = commandMessage(reason);
    } finally {
      busy = false;
    }
  }

  async function refreshProbes() {
    if (!requiresServerProbes(selectedLayer, ticConnectionMode)) {
      availableCandidates = 0;
      return;
    }
    if (
      probeBusy ||
      !bootstrap?.binding ||
      phase === "connected" ||
      phase === "connecting" ||
      phase === "stopping"
    ) {
      return;
    }
    probeBusy = true;
    const measuredLayer = selectedLayer;
    if (phase === "ready") phase = "measuring";
    try {
      const results = await nativeClient.refreshProbes(measuredLayer);
      if (results.layer === selectedLayer) {
        availableCandidates = results.probes.length;
        error = null;
      }
    } catch {
      availableCandidates = 0;
    } finally {
      probeBusy = false;
      if (phase === "measuring") phase = "ready";
      if (measuredLayer !== selectedLayer) void refreshProbes();
    }
  }

  async function logout() {
    if (busy) return;
    busy = true;
    error = null;
    try {
      await nativeClient.logout();
      bootstrap = null;
      connection = null;
      pinnedStray = null;
      peers = [];
      selectedPeerId = "";
      password = "";
      diagnosticsStatus = null;
      updateStatus = null;
      splitTunnelState = null;
      splitTunnelApplications = [];
      splitTunnelOpen = false;
      splitTunnelLoaded = false;
      runtimeWarning = null;
      notifications = [];
      notificationUnreadCount = 0;
      notificationNextCursor = null;
      notificationHistoryExpanded = false;
      notificationsOpen = false;
      clearUpdateTimer();
      phase = "signed_out";
      view = "sign_in";
    } catch (reason) {
      error = commandMessage(reason);
    } finally {
      busy = false;
    }
  }

  async function sendDiagnostics() {
    if (diagnosticsBusy) return;
    diagnosticsBusy = true;
    diagnosticsStatus = null;
    try {
      const response = await nativeClient.sendDiagnostics();
      diagnosticsStatus = `Отчёт ${response.report_id.slice(0, 8)} отправлен`;
    } catch (reason) {
      diagnosticsStatus = commandMessage(reason);
    } finally {
      diagnosticsBusy = false;
    }
  }

  async function refreshNotifications(append: boolean, silent = false) {
    if (notificationsBusy || !bootstrap) return;
    notificationsBusy = true;
    if (!silent) notificationsError = null;
    try {
      const response = await nativeClient.notifications(
        append ? notificationNextCursor : null,
      );
      if (append) {
        notifications = appendNotificationPage(notifications, response.notifications);
        notificationHistoryExpanded = true;
        notificationNextCursor = response.next_cursor;
      } else if (silent && notificationsOpen && notificationHistoryExpanded) {
        notifications = mergeRefreshedNotifications(notifications, response.notifications);
      } else {
        notifications = response.notifications;
        notificationHistoryExpanded = false;
        notificationNextCursor = response.next_cursor;
      }
      notificationUnreadCount = response.unread_count;
    } catch (reason) {
      if (!silent || notificationsOpen) {
        notificationsError = commandMessage(reason);
      }
    } finally {
      notificationsBusy = false;
    }
  }

  async function openNotifications() {
    notificationsOpen = true;
    await refreshNotifications(false);
  }

  async function markNotificationRead(messageId: number) {
    if (notificationsBusy) return;
    notificationsBusy = true;
    notificationsError = null;
    try {
      const response = await nativeClient.markNotificationRead(messageId);
      const readAt = new Date().toISOString();
      notifications = notifications.map((notification) =>
        notification.id === messageId
          ? { ...notification, read_at: notification.read_at ?? readAt }
          : notification,
      );
      notificationUnreadCount = response.unread_count;
    } catch (reason) {
      notificationsError = commandMessage(reason);
    } finally {
      notificationsBusy = false;
    }
  }

  async function markAllNotificationsRead() {
    if (notificationsBusy) return;
    notificationsBusy = true;
    notificationsError = null;
    try {
      const response = await nativeClient.markAllNotificationsRead();
      const readAt = new Date().toISOString();
      notifications = notifications.map((notification) => ({
        ...notification,
        read_at: notification.read_at ?? readAt,
      }));
      notificationUnreadCount = response.unread_count;
    } catch (reason) {
      notificationsError = commandMessage(reason);
    } finally {
      notificationsBusy = false;
    }
  }

  async function refreshUpdateStatus() {
    clearUpdateTimer();
    try {
      updateStatus = await nativeClient.updateStatus();
      if (
        updateStatus.phase === "downloading" ||
        (updateStatus.supported &&
          updateStatus.automatic &&
          updateStatus.phase === "available")
      ) {
        updateTimer = window.setTimeout(refreshUpdateStatus, 500);
      }
    } catch {
      updateStatus = null;
    }
  }

  async function installUpdate() {
    if (updateBusy) return;
    updateBusy = true;
    error = null;
    updateTimer = window.setTimeout(refreshUpdateStatus, 100);
    try {
      updateStatus = await nativeClient.installUpdate();
    } catch (reason) {
      error = commandMessage(reason);
      await refreshUpdateStatus();
    } finally {
      updateBusy = false;
    }
  }

  async function setAutomaticUpdates(event: Event) {
    const input = event.currentTarget as HTMLInputElement;
    try {
      updateStatus = await nativeClient.setAutomaticUpdates(input.checked);
      if (input.checked) {
        updateTimer = window.setTimeout(refreshUpdateStatus, 100);
      }
    } catch (reason) {
      input.checked = !input.checked;
      error = commandMessage(reason);
    }
  }

  async function restartForUpdate() {
    if (updateBusy) return;
    updateBusy = true;
    try {
      await nativeClient.restartForUpdate();
    } catch (reason) {
      error = commandMessage(reason);
      updateBusy = false;
    }
  }

  function clearUpdateTimer() {
    if (updateTimer !== null) {
      window.clearTimeout(updateTimer);
      updateTimer = null;
    }
  }

  async function loadSplitTunnel(force: boolean) {
    if (splitTunnelBusy) return;
    splitTunnelBusy = true;
    try {
      splitTunnelApplications =
        await nativeClient.splitTunnelInstalledApplications();
      splitTunnelState = force
        ? await nativeClient.refreshSplitTunnel()
        : await nativeClient.splitTunnelState();
      runtimeWarning = splitTunnelState.warning;
    } catch {
      if (force) throw new Error("split_tunnel_refresh_failed");
    } finally {
      splitTunnelLoaded = true;
      splitTunnelBusy = false;
    }
  }

  async function openSplitTunnel() {
    await loadSplitTunnel(false);
    if (splitTunnelState) splitTunnelOpen = true;
  }

  async function saveSplitTunnel(
    request: SplitTunnelSettingsUpdate,
  ): Promise<boolean> {
    try {
      let response = await nativeClient.saveSplitTunnel(request, false);
      if (response.requiresReconnectConfirmation) {
        const confirmed = window.confirm(
          "Чтобы применить настройки, текущее подключение будет кратковременно перезапущено. Продолжить?",
        );
        if (!confirmed) return false;
        response = await nativeClient.saveSplitTunnel(request, true);
      }
      splitTunnelState = response.state;
      return response.saved;
    } catch (reason) {
      const current = await nativeClient.state().catch(() => null);
      if (current) {
        phase = current.phase;
        connection = current.connection;
        connectionMetrics = current.metrics;
        view = viewForPhase(current.phase);
      }
      await loadSplitTunnel(false);
      throw reason;
    }
  }

  async function addSplitTunnelAddressRule(
    value: string,
    scope: SplitTunnelAddressRule["scope"],
  ): Promise<void> {
    splitTunnelState = await nativeClient.addSplitTunnelAddressRule(value, scope);
    runtimeWarning = splitTunnelState.warning;
  }

  async function removeSplitTunnelAddressRule(
    ruleId: number,
    scope: SplitTunnelAddressRule["scope"],
  ): Promise<void> {
    splitTunnelState = await nativeClient.removeSplitTunnelAddressRule(ruleId, scope);
    runtimeWarning = splitTunnelState.warning;
  }

  function updateProgress(status: UpdateStatus): string {
    if (!status.total || status.total <= 0) {
      return formatBytes(status.downloaded);
    }
    const percent = Math.min(
      100,
      Math.round((status.downloaded / status.total) * 100),
    );
    return `${percent}%`;
  }

  function formatBytes(value: number): string {
    if (value < 1024 * 1024) return `${Math.round(value / 1024)} КБ`;
    if (value >= 1024 * 1024 * 1024) {
      return `${(value / (1024 * 1024 * 1024)).toFixed(1)} ГБ`;
    }
    return `${(value / (1024 * 1024)).toFixed(1)} МБ`;
  }

  function commandCode(reason: unknown): string | null {
    if (
      typeof reason === "object" &&
      reason !== null &&
      "code" in reason &&
      typeof reason.code === "string"
    ) {
      return reason.code;
    }
    return null;
  }
</script>

<svelte:head>
  <title>Nelomai</title>
</svelte:head>

<main class="app-shell">
  <header>
    <a class="brand" href="/" aria-label="Nelomai">
      <span class="brand-mark" aria-hidden="true">✦</span>
      <span>Nelomai</span>
    </a>
    <div class="header-actions">
      <span class="status" data-phase={phase}>
        <span aria-hidden="true"></span>
        {phaseLabels[phase]}
      </span>
      {#if view !== "loading" && view !== "sign_in"}
        <button
          class="quiet-button notification-button"
          type="button"
          onclick={openNotifications}
          aria-label={notificationUnreadCount
            ? `Уведомления, непрочитанных: ${notificationUnreadCount}`
            : "Уведомления"}
        >
          Уведомления
          {#if notificationUnreadCount}
            <span>{Math.min(notificationUnreadCount, 99)}</span>
          {/if}
        </button>
        <button
          class="quiet-button"
          type="button"
          onclick={sendDiagnostics}
          disabled={diagnosticsBusy}
        >
          {diagnosticsBusy ? "Отправляем…" : "Отправить логи"}
        </button>
        <button class="quiet-button" type="button" onclick={logout} disabled={busy}>
          Выйти
        </button>
      {/if}
    </div>
  </header>
  {#if diagnosticsStatus}
    <p class="diagnostics-status" aria-live="polite">{diagnosticsStatus}</p>
  {/if}
  {#if updateStatus && updateStatus.phase !== "idle" && view !== "sign_in"}
    <section class="update-banner" aria-live="polite">
      <div>
        <p class="eyebrow">Обновление</p>
        {#if updateStatus.phase === "downloading"}
          <strong>Загружаем Nelomai {updateStatus.version}</strong>
          <span>{updateProgress(updateStatus)}</span>
        {:else if updateStatus.phase === "ready_to_restart"}
          <strong>Nelomai {updateStatus.version} готов к запуску</strong>
          <span>Перезапустите приложение, чтобы завершить обновление.</span>
        {:else if updateStatus.phase === "awaiting_installation"}
          <strong>Подтвердите установку Nelomai {updateStatus.version}</strong>
          <span>Завершите обновление в системном окне Android.</span>
        {:else if updateStatus.phase === "failed"}
          <strong>Не удалось установить Nelomai {updateStatus.version}</strong>
          <span>Можно повторить загрузку сейчас.</span>
        {:else}
          <strong>Доступна версия {updateStatus.version}</strong>
          <span>
            {updateStatus.supported
              ? updateStatus.notes || "Обновление готово к загрузке."
              : "Эту версию необходимо установить вручную."}
          </span>
        {/if}
      </div>
      {#if updateStatus.phase === "ready_to_restart"}
        <button
          class="primary-button update-action"
          type="button"
          onclick={restartForUpdate}
          disabled={updateBusy}
        >
          Перезапустить
        </button>
      {:else if updateStatus.supported && updateStatus.phase !== "downloading"}
        <button
          class="secondary-button update-action"
          type="button"
          onclick={installUpdate}
          disabled={updateBusy}
        >
          {updateBusy
            ? "Начинаем…"
            : updateStatus.phase === "awaiting_installation"
              ? "Открыть снова"
              : "Обновить"}
        </button>
      {/if}
    </section>
  {/if}

  <section class="workspace" aria-live="polite">
    {#if view === "loading"}
      <div class="center-state">
        <div class="loader" aria-hidden="true"></div>
        <h1>Открываем приложение</h1>
      </div>
    {:else if view === "sign_in"}
      <form class="panel sign-in" onsubmit={submitLogin}>
        <div>
          <p class="eyebrow">Личный аккаунт</p>
          <h1>Вход в Nelomai</h1>
        </div>
        <label>
          <span>Логин</span>
          <input
            bind:value={login}
            autocomplete="username"
            required
            spellcheck="false"
          />
        </label>
        <label>
          <span>Пароль</span>
          <input
            bind:value={password}
            type="password"
            autocomplete="current-password"
            required
          />
        </label>
        <label>
          <span>Название устройства</span>
          <input bind:value={deviceName} maxlength="80" required />
        </label>
        {#if error}<p class="error-message">{error}</p>{/if}
        <button class="primary-button" type="submit" disabled={busy}>
          {busy ? "Входим…" : "Войти"}
        </button>
      </form>
    {:else if view === "peer_selection"}
      <div class="panel peer-panel">
        <div class="panel-heading">
          <div>
            <p class="eyebrow">Это устройство</p>
            <h1>Выберите пир</h1>
          </div>
          <span class="counter">{peers.length}</span>
        </div>

        {#if peers.length}
          <div class="peer-list">
            {#each peers as peer}
              <label class:disabled={!peer.selectable} class="peer-row">
                <input
                  type="radio"
                  name="peer"
                  value={peer.id}
                  bind:group={selectedPeerId}
                  disabled={!peer.selectable}
                />
                <span class="peer-copy">
                  <strong>{peer.name}</strong>
                  <span>{peer.interface_name} · пир {peer.slot}</span>
                  <span class="peer-comment">
                    {peer.comment || "Комментария ещё нет"}
                  </span>
                </span>
                <span class="peer-state">
                  {peer.last_handshake_at ? "Использовался" : "Свободен"}
                </span>
              </label>
            {/each}
          </div>
          {#if error}<p class="error-message">{error}</p>{/if}
          <button
            class="primary-button"
            type="button"
            onclick={bindSelectedPeer}
            disabled={!selectedPeerId || busy}
          >
            {busy ? "Сохраняем…" : "Использовать этот пир"}
          </button>
        {:else}
          <div class="empty-state">
            <h2>Нет доступных пиров</h2>
            {#if error}<p class="error-message">{error}</p>{/if}
            <button class="secondary-button" type="button" onclick={loadPeers}>
              Проверить ещё раз
            </button>
          </div>
        {/if}
      </div>
    {:else if view === "connection"}
      <div class="connection-layout">
        <section class="panel connection-panel">
          <div>
            <p class="eyebrow">Подключение</p>
            <h1>
              {phase === "connected"
                ? "Интернет защищён"
                : phase === "connecting"
                  ? "Восстанавливаем подключение"
                : phase === "stopping"
                  ? "Завершаем подключение"
                  : "Готово к запуску"}
            </h1>
          </div>

          <button
            class:stop={phase === "connected" || phase === "stopping"}
            class="connect-button"
            type="button"
            onclick={toggleConnection}
            disabled={busy ||
              phase === "connecting" ||
              (!splitTunnelLoaded &&
                phase !== "connected" &&
                phase !== "stopping") ||
              (splitTunnelBlocksStart &&
                phase !== "connected" &&
                phase !== "stopping")}
          >
            <span>
              {phase === "connected"
                ? "Стоп"
                : phase === "connecting"
                  ? "Подключаемся"
                : phase === "stopping"
                  ? "Повторить"
                  : "Старт"}
            </span>
            <small>
              {busy
                ? phaseLabels[phase]
                : phase === "stopping"
                  ? "Завершить отключение"
                  : "Нажмите для переключения"}
            </small>
          </button>

          {#if phase === "connected"}
            <dl class="connection-metrics" aria-label="Показатели подключения">
              <div>
                <dt>Трафик сессии</dt>
                <dd>
                  ↓ {formatBytes(connectionMetrics?.receivedBytes ?? 0)}
                  <span>↑ {formatBytes(connectionMetrics?.sentBytes ?? 0)}</span>
                </dd>
              </div>
              <div>
                <dt>Пинг</dt>
                <dd>
                  {connectionMetrics?.latencyMs == null
                    ? "—"
                    : `${connectionMetrics.latencyMs} мс`}
                </dd>
              </div>
              <div>
                <dt>Потери</dt>
                <dd>
                  {connectionMetrics?.packetLossPercent == null
                    ? "—"
                    : `${connectionMetrics.packetLossPercent}%`}
                </dd>
              </div>
            </dl>
          {/if}

          {#if error}<p class="error-message">{error}</p>{/if}
          {#if runtimeWarning}
            <p class="warning-message">
              {splitTunnelWarningMessage(runtimeWarning)}
            </p>
          {/if}
          {#if splitTunnelBlocksStart &&
            phase !== "connecting" &&
            phase !== "connected" &&
            phase !== "stopping"}
            <p class="error-message">
              Выберите хотя бы одно приложение для подключения через VPN
            </p>
          {/if}
        </section>

        <aside class="panel settings-panel">
          <div>
            <p class="eyebrow">Маршрут</p>
            <h2>Параметры подключения</h2>
          </div>

          <fieldset
            disabled={busy ||
              phase === "connecting" ||
              phase === "connected" ||
              phase === "stopping"}
          >
            <legend>Система</legend>
            <div class="segmented">
              <label>
                <input
                  type="radio"
                  value="tic"
                  bind:group={selectedLayer}
                  onchange={changeLayer}
                />
                <span>Tic / Tak</span>
              </label>
              <label>
                <input
                  type="radio"
                  value="stray"
                  bind:group={selectedLayer}
                  onchange={changeLayer}
                />
                <span>Stray</span>
              </label>
            </div>
          </fieldset>

          {#if selectedLayer === "tic"}
            <label class="select-field">
              <span>Режим</span>
              <select
                bind:value={ticConnectionMode}
                onchange={refreshProbes}
                disabled={busy ||
                  phase === "connecting" ||
                  phase === "connected" ||
                  phase === "stopping"}
              >
                <option value="personal">Постоянный пир</option>
                <option value="dynamic">Динамический</option>
              </select>
            </label>
            <label class="select-field">
              <span>Маршрут</span>
              <select
                bind:value={routeMode}
                disabled={busy ||
                  phase === "connecting" ||
                  phase === "connected" ||
                  phase === "stopping"}
              >
                <option value="via_tak">Через Tak</option>
                <option value="standalone">Напрямую</option>
              </select>
            </label>
          {/if}

          {#if bootstrap?.binding}
            <div class="binding-summary">
              <span>Используемый пир</span>
              <strong>{bootstrap.binding.interface_name} · {bootstrap.binding.slot}</strong>
            </div>
          {/if}
          <div class="binding-summary">
            <span>Доступные серверы</span>
            <strong>
              {requiresServerProbes(selectedLayer, ticConnectionMode)
                ? probeBusy
                  ? "Проверяем"
                  : availableCandidates
                : "Личный пир"}
            </strong>
          </div>
          {#if updateStatus?.supported}
            <label class="update-preference">
              <span>
                <strong>Автоматические обновления</strong>
                <small>Загружать новые версии в фоне</small>
              </span>
              <input
                type="checkbox"
                checked={updateStatus.automatic}
                onchange={setAutomaticUpdates}
              />
            </label>
          {/if}
          {#if appPreferences?.closeToTraySupported}
            <label class="update-preference">
              <span>
                <strong>Крестик сворачивает в трей</strong>
                <small>Приложение продолжит работать в фоне</small>
              </span>
              <input
                type="checkbox"
                checked={appPreferences.closeToTray}
                onchange={setCloseToTray}
              />
            </label>
          {/if}
          <button
            class="secondary-button"
            type="button"
            onclick={openSplitTunnel}
            disabled={busy || splitTunnelBusy}
          >
            {splitTunnelBusy ? "Открываем…" : "Split-tunnel"}
          </button>
          {#if pinnedStray || (selectedLayer === "stray" && phase === "connected")}
            <button
              class="secondary-button"
              type="button"
              onclick={toggleSavedStray}
              disabled={busy}
            >
              {pinnedStray || connection?.pinned
                ? "Отменить сохранение Stray"
                : "Сохранить подключение"}
            </button>
          {/if}
          <button
            class="quiet-button binding-action"
            type="button"
            onclick={unbindPeer}
            disabled={busy}
          >
            Выбрать другой пир
          </button>
        </aside>
      </div>
    {:else if view === "access_expired"}
      <div class="panel message-panel">
        <p class="eyebrow">Доступ</p>
        <h1>Подключение пока недоступно</h1>
        <button class="secondary-button" type="button" onclick={restore} disabled={busy}>
          Проверить снова
        </button>
      </div>
    {:else if view === "update_required"}
      <div class="panel message-panel">
        <p class="eyebrow">Обновление</p>
        <h1>Нужно обновить Nelomai</h1>
        {#if bootstrap?.update.release_notes}
          <p>{bootstrap.update.release_notes}</p>
        {/if}
        {#if updateStatus?.supported}
          {#if updateStatus.phase === "ready_to_restart"}
            <button
              class="primary-button"
              type="button"
              onclick={restartForUpdate}
              disabled={updateBusy}
            >
              Перезапустить
            </button>
          {:else if updateStatus.phase === "awaiting_installation"}
            <p>Завершите обновление в системном окне Android.</p>
            <button
              class="primary-button"
              type="button"
              onclick={installUpdate}
              disabled={updateBusy}
            >
              {updateBusy ? "Открываем…" : "Открыть снова"}
            </button>
          {:else if updateStatus.phase !== "downloading"}
            <button
              class="primary-button"
              type="button"
              onclick={installUpdate}
              disabled={updateBusy}
            >
              {updateBusy ? "Начинаем…" : "Обновить"}
            </button>
          {/if}
        {:else}
          <p>Установите новую версию приложения вручную.</p>
        {/if}
      </div>
    {:else}
      <div class="panel message-panel">
        <p class="eyebrow">Подключение к панели</p>
        <h1>Сейчас сервис недоступен</h1>
        {#if error}<p class="error-message">{error}</p>{/if}
        <button class="secondary-button" type="button" onclick={restore} disabled={busy}>
          {busy ? "Проверяем…" : "Повторить"}
        </button>
      </div>
    {/if}
  </section>
</main>

{#if splitTunnelOpen && splitTunnelState}
  <SplitTunnelSettings
    state={splitTunnelState}
    applications={splitTunnelApplications}
    busy={splitTunnelBusy}
    onclose={() => (splitTunnelOpen = false)}
    onsave={saveSplitTunnel}
    onrefresh={() => loadSplitTunnel(true)}
    onaddaddressrule={addSplitTunnelAddressRule}
    onremoveaddressrule={removeSplitTunnelAddressRule}
  />
{/if}

{#if notificationsOpen}
  <NotificationsPanel
    {notifications}
    unreadCount={notificationUnreadCount}
    nextCursor={notificationNextCursor}
    busy={notificationsBusy}
    error={notificationsError}
    onclose={() => (notificationsOpen = false)}
    onread={markNotificationRead}
    onreadall={markAllNotificationsRead}
    onloadmore={() => refreshNotifications(true)}
  />
{/if}

<style>
  :global(*) {
    box-sizing: border-box;
  }

  :global(html) {
    min-width: 320px;
    min-height: 100%;
    color-scheme: dark;
  }

  :global(body) {
    margin: 0;
    min-width: 320px;
    min-height: 100vh;
    color: #f5f6f8;
    background:
      linear-gradient(180deg, rgba(12, 35, 43, 0.34), transparent 42%),
      #080a0d;
    font-family:
      Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI",
      sans-serif;
  }

  :global(button),
  :global(input),
  :global(select) {
    font: inherit;
  }

  :global(button) {
    letter-spacing: 0;
  }

  .app-shell {
    min-height: 100vh;
    display: grid;
    grid-template-rows: auto 1fr;
  }

  header {
    width: min(1180px, calc(100% - 40px));
    min-height: 72px;
    margin: 0 auto;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 20px;
    border-bottom: 1px solid #242a30;
  }

  .brand {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    color: #fff;
    font-size: 21px;
    font-weight: 720;
    text-decoration: none;
  }

  .brand-mark {
    width: 34px;
    height: 34px;
    display: grid;
    place-items: center;
    color: #071011;
    background: #f4f6f7;
    border-radius: 7px;
    font-size: 21px;
  }

  .header-actions,
  .status {
    display: flex;
    align-items: center;
  }

  .header-actions {
    gap: 16px;
  }

  .status {
    gap: 8px;
    color: #aeb6bd;
    font-size: 13px;
  }

  .status > span {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #85909a;
  }

  .status[data-phase="ready"] > span,
  .status[data-phase="connected"] > span {
    background: #59d6bd;
  }

  .status[data-phase="error"] > span,
  .status[data-phase="server_unavailable"] > span,
  .status[data-phase="access_expired"] > span {
    background: #e97171;
  }

  .workspace {
    width: min(1180px, calc(100% - 40px));
    margin: 0 auto;
    padding: 48px 0 64px;
    display: grid;
    place-items: center;
  }

  .diagnostics-status {
    width: min(1180px, calc(100% - 40px));
    margin: 10px auto 0;
    color: #aeb6bd;
    font-size: 13px;
    text-align: right;
  }

  .update-banner {
    width: min(1180px, calc(100% - 40px));
    margin: 14px auto 0;
    padding: 16px 18px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 18px;
    border: 1px solid #32675f;
    border-radius: 8px;
    background: #102923;
  }

  .update-banner > div {
    min-width: 0;
    display: grid;
    gap: 4px;
  }

  .update-banner .eyebrow {
    margin: 0;
  }

  .update-banner strong,
  .update-banner span {
    overflow-wrap: anywhere;
  }

  .update-banner span {
    color: #b7c7c3;
    font-size: 13px;
  }

  .update-action {
    flex: 0 0 auto;
  }

  .panel {
    width: 100%;
    border: 1px solid #303841;
    border-radius: 8px;
    background: rgba(16, 20, 24, 0.94);
    box-shadow: 0 18px 48px rgba(0, 0, 0, 0.22);
  }

  .sign-in {
    width: min(440px, 100%);
    padding: 32px;
    display: grid;
    gap: 20px;
  }

  h1,
  h2,
  p {
    margin-top: 0;
  }

  h1 {
    margin-bottom: 0;
    font-size: clamp(28px, 4vw, 40px);
    line-height: 1.08;
    letter-spacing: 0;
  }

  h2 {
    margin-bottom: 0;
    font-size: 20px;
    letter-spacing: 0;
  }

  .eyebrow {
    margin-bottom: 7px;
    color: #68cfc0;
    font-size: 12px;
    font-weight: 720;
    text-transform: uppercase;
  }

  label {
    display: grid;
    gap: 8px;
    color: #cbd1d6;
    font-size: 13px;
  }

  input,
  select {
    width: 100%;
    min-height: 44px;
    padding: 0 12px;
    color: #fff;
    border: 1px solid #3a444d;
    border-radius: 6px;
    outline: none;
    background: #0c1014;
  }

  input:focus,
  select:focus {
    border-color: #67d5c4;
    box-shadow: 0 0 0 3px rgba(103, 213, 196, 0.14);
  }

  button {
    min-height: 42px;
    border: 0;
    border-radius: 6px;
    cursor: pointer;
  }

  button:disabled {
    cursor: wait;
    opacity: 0.58;
  }

  .primary-button,
  .secondary-button {
    padding: 0 18px;
    color: #06110f;
    background: #67d5c4;
    font-weight: 740;
  }

  .secondary-button {
    color: #effaf8;
    border: 1px solid #3a8075;
    background: #173d38;
  }

  .quiet-button {
    min-height: 34px;
    padding: 0 12px;
    color: #d1d7dc;
    border: 1px solid #343c44;
    background: transparent;
  }

  .notification-button {
    position: relative;
    display: inline-flex;
    align-items: center;
    gap: 8px;
  }

  .notification-button > span {
    min-width: 20px;
    height: 20px;
    padding: 0 6px;
    display: grid;
    place-items: center;
    color: #06110f;
    border-radius: 10px;
    background: #67d5c4;
    font-size: 11px;
    font-weight: 760;
  }

  .binding-action {
    width: 100%;
  }

  .error-message {
    margin: 0;
    color: #ff9999;
    font-size: 13px;
  }

  .warning-message {
    margin: 0;
    padding: 10px 12px;
    color: #ffe5ae;
    border: 1px solid #6f562b;
    border-radius: 6px;
    background: #2a2112;
    font-size: 13px;
    line-height: 1.45;
  }

  .center-state {
    display: grid;
    justify-items: center;
    gap: 18px;
    text-align: center;
  }

  .loader {
    width: 30px;
    height: 30px;
    border: 3px solid #2d393d;
    border-top-color: #67d5c4;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }

  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }

  .peer-panel {
    max-width: 780px;
    padding: 28px;
    display: grid;
    gap: 24px;
  }

  .panel-heading {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 20px;
  }

  .counter {
    min-width: 38px;
    height: 30px;
    padding: 0 10px;
    display: grid;
    place-items: center;
    color: #9ee5da;
    border: 1px solid #326a62;
    border-radius: 15px;
    font-size: 13px;
  }

  .peer-list {
    display: grid;
    border-top: 1px solid #2a3036;
  }

  .peer-row {
    min-height: 86px;
    padding: 14px 4px;
    display: grid;
    grid-template-columns: 20px minmax(0, 1fr) auto;
    align-items: center;
    gap: 14px;
    border-bottom: 1px solid #2a3036;
    cursor: pointer;
  }

  .peer-row.disabled {
    opacity: 0.45;
    cursor: not-allowed;
  }

  .peer-row input {
    width: 18px;
    min-height: 18px;
    accent-color: #67d5c4;
  }

  .peer-copy {
    min-width: 0;
    display: grid;
    gap: 3px;
  }

  .peer-copy strong,
  .peer-copy span {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .peer-copy strong {
    color: #fff;
    font-size: 16px;
  }

  .peer-copy span {
    color: #909aa3;
  }

  .peer-comment {
    color: #c5ccd2 !important;
  }

  .peer-state {
    color: #9ca6af;
    font-size: 12px;
  }

  .connection-layout {
    width: 100%;
    display: grid;
    grid-template-columns: minmax(0, 1.5fr) minmax(300px, 0.75fr);
    gap: 20px;
  }

  .connection-panel,
  .settings-panel {
    padding: 30px;
  }

  .connection-panel {
    min-height: 450px;
    display: grid;
    align-content: space-between;
    gap: 36px;
  }

  .connect-button {
    width: min(250px, 64vw);
    aspect-ratio: 1;
    min-height: 0;
    justify-self: center;
    display: grid;
    place-content: center;
    gap: 6px;
    color: #07110f;
    border: 10px solid rgba(130, 236, 218, 0.32);
    border-radius: 50%;
    background: #67d5c4;
    box-shadow: 0 0 40px rgba(103, 213, 196, 0.17);
  }

  .connect-button.stop {
    color: #fff;
    border-color: rgba(229, 105, 105, 0.28);
    background: #a52931;
    box-shadow: 0 0 40px rgba(229, 105, 105, 0.15);
  }

  .connect-button span {
    font-size: 32px;
    font-weight: 780;
  }

  .connect-button small {
    font-size: 11px;
  }

  .connection-metrics {
    margin: 0;
    display: grid;
    grid-template-columns: minmax(0, 1.6fr) repeat(2, minmax(90px, 0.7fr));
    gap: 8px;
  }

  .connection-metrics > div {
    min-width: 0;
    padding: 12px 14px;
    border: 1px solid rgba(118, 137, 151, 0.3);
    border-radius: 7px;
    background: rgba(10, 15, 20, 0.72);
  }

  .connection-metrics dt {
    color: #929da6;
    font-size: 11px;
  }

  .connection-metrics dd {
    margin: 5px 0 0;
    color: #f4f7f8;
    font-size: 15px;
    font-weight: 720;
    white-space: nowrap;
  }

  .connection-metrics dd span {
    margin-left: 8px;
    color: #aeb9c0;
  }

  .settings-panel {
    display: grid;
    align-content: start;
    gap: 28px;
  }

  fieldset {
    margin: 0;
    padding: 0;
    border: 0;
  }

  legend,
  .select-field > span,
  .binding-summary > span {
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
    min-height: 38px;
    display: grid;
    place-items: center;
    border-radius: 5px;
  }

  .segmented input:checked + span {
    color: #eafffb;
    background: #225d55;
  }

  .select-field {
    gap: 0;
  }

  .binding-summary {
    padding-top: 18px;
    display: grid;
    gap: 4px;
    border-top: 1px solid #2a3036;
  }

  .update-preference {
    padding-top: 18px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 18px;
    border-top: 1px solid #2a3036;
  }

  .update-preference > span {
    display: grid;
    gap: 4px;
  }

  .update-preference small {
    color: #9ca5ad;
    font-size: 12px;
  }

  .update-preference input {
    width: 44px;
    min-height: 24px;
    margin: 0;
    accent-color: #67d5c4;
  }

  .message-panel {
    max-width: 600px;
    padding: 36px;
    display: grid;
    justify-items: start;
    gap: 20px;
  }

  .message-panel p:not(.eyebrow) {
    margin-bottom: 0;
    color: #aeb6bd;
    line-height: 1.55;
  }

  .empty-state {
    min-height: 220px;
    display: grid;
    place-content: center;
    justify-items: center;
    gap: 20px;
    text-align: center;
  }

  @media (max-width: 760px) {
    header,
    .workspace,
    .update-banner {
      width: min(100% - 28px, 620px);
    }

    header {
      min-height: 64px;
      padding: 12px 0;
      flex-wrap: wrap;
    }

    .status {
      display: none;
    }

    .header-actions {
      width: 100%;
      order: 2;
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 8px;
    }

    .header-actions .quiet-button {
      min-width: 0;
      padding: 0 9px;
      font-size: 12px;
    }

    .workspace {
      padding: 24px 0 36px;
      align-items: start;
    }

    .sign-in,
    .peer-panel,
    .connection-panel,
    .settings-panel,
    .message-panel {
      padding: 22px;
    }

    .connection-layout {
      grid-template-columns: 1fr;
    }

    .connection-panel {
      min-height: 390px;
    }

    .connection-metrics {
      grid-template-columns: 1fr 1fr;
    }

    .connection-metrics > div:first-child {
      grid-column: 1 / -1;
    }

    .settings-panel {
      order: 2;
    }

    .update-banner {
      align-items: stretch;
      flex-direction: column;
    }

    .update-action {
      width: 100%;
    }

    .peer-row {
      grid-template-columns: 20px minmax(0, 1fr);
    }

    .peer-state {
      grid-column: 2;
    }
  }

  @media (max-width: 420px) {
    .brand {
      font-size: 19px;
    }

    h1 {
      font-size: 29px;
    }

    .connect-button {
      width: min(230px, 70vw);
    }
  }

  @media (prefers-reduced-motion: reduce) {
    .loader {
      animation-duration: 1.8s;
    }
  }
</style>
