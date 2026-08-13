import { invoke as tauriInvoke } from "@tauri-apps/api/core";

import type {
  AppState,
  AppPreferences,
  BindPeerRequest,
  Bootstrap,
  Connection,
  NativeCommandError,
  PeerBinding,
  PeerOptions,
  ProbeResults,
  Layer,
  DnsProvider,
  StartCommandRequest,
  UpdateStatus,
} from "./app-model";
import type {
  InstalledApplication,
  SplitTunnelSaveResult,
  SplitTunnelSettingsUpdate,
  SplitTunnelAddressRule,
  SplitTunnelState,
} from "./split-tunnel";

type Invoke = (
  command: string,
  args?: Record<string, unknown>,
) => Promise<unknown>;

export const START_FAILURE_DIAGNOSTICS_UI_TIMEOUT_MILLIS = 5_000;

export function waitForSettlement(
  promise: Promise<unknown>,
  timeoutMillis: number,
): Promise<boolean> {
  return new Promise((resolve) => {
    let completed = false;
    const timer = setTimeout(() => {
      if (completed) return;
      completed = true;
      resolve(false);
    }, Math.max(1, timeoutMillis));
    const finish = () => {
      if (completed) return;
      completed = true;
      clearTimeout(timer);
      resolve(true);
    };
    void promise.then(finish, finish);
  });
}

export type StartupStage =
  | "frontend_mounted"
  | "frontend_first_frame"
  | "bootstrap_slow";

export interface LoginRequest {
  login: string;
  password: string;
  deviceName: string;
  platformVersion: string | null;
}

export interface SafePeerBindingResponse {
  apiVersion: "1";
  requestId: string;
  binding: PeerBinding | null;
}

export interface DiagnosticUploadResponse {
  api_version: "1";
  request_id: string;
  report_id: string;
  received_bytes: number;
}

export interface AppNotification {
  id: number;
  kind: string;
  title: string;
  body: string;
  url: string | null;
  created_at: string;
  read_at: string | null;
}

export interface AppNotificationList {
  api_version: "1";
  request_id: string;
  notifications: AppNotification[];
  unread_count: number;
  next_cursor: number | null;
}

export interface AppNotificationReadResponse {
  api_version: "1";
  request_id: string;
  updated: number;
  unread_count: number;
}

export function createNativeClient(
  invoke: Invoke = (command, args) => tauriInvoke(command, args),
) {
  return {
    state: () => invoke("app_state") as Promise<AppState>,
    preferences: () => invoke("app_preferences") as Promise<AppPreferences>,
    setCloseToTray: (enabled: boolean) =>
      invoke("app_set_close_to_tray", { enabled }) as Promise<AppPreferences>,
    setDnsProvider: (provider: DnsProvider) =>
      invoke("app_set_dns_provider", { provider }) as Promise<AppPreferences>,
    login: (request: LoginRequest) =>
      invoke("app_login", { request }) as Promise<Bootstrap>,
    bootstrap: () => invoke("app_bootstrap") as Promise<Bootstrap>,
    peerOptions: () => invoke("app_peer_options") as Promise<PeerOptions>,
    bindPeer: (request: BindPeerRequest) =>
      invoke("app_bind_peer", { request }) as Promise<SafePeerBindingResponse>,
    unbindPeer: () =>
      invoke("app_unbind_peer") as Promise<SafePeerBindingResponse>,
    refreshProbes: (layer: Layer) =>
      invoke("app_refresh_probes", { layer }) as Promise<ProbeResults>,
    prepareTunnel: (deviceId: string) =>
      invoke("app_prepare_tunnel", { deviceId }) as Promise<void>,
    queueStartFailureDiagnostics: (deviceId: string, errorCode: string) =>
      invoke("app_queue_start_failure_diagnostics", {
        deviceId,
        errorCode,
      }) as Promise<void>,
    start: (request: StartCommandRequest) =>
      invoke("app_start", { request }) as Promise<Connection>,
    startSavedStray: () =>
      invoke("app_start_saved_stray") as Promise<string>,
    stop: () => invoke("app_stop") as Promise<Connection>,
    pinStray: () => invoke("app_pin_stray") as Promise<Connection>,
    unpinStray: (leaseId: string) =>
      invoke("app_unpin_stray", {
        request: { leaseId },
      }) as Promise<Connection>,
    sendDiagnostics: () =>
      invoke("app_send_diagnostics") as Promise<DiagnosticUploadResponse>,
    recordStartupStage: (stage: StartupStage) =>
      invoke("app_record_startup_stage", { stage }) as Promise<void>,
    notifications: (cursor: number | null = null) =>
      invoke("app_notifications", { cursor }) as Promise<AppNotificationList>,
    markNotificationRead: (messageId: number) =>
      invoke("app_notification_read", { messageId }) as Promise<AppNotificationReadResponse>,
    markAllNotificationsRead: () =>
      invoke("app_notifications_read_all") as Promise<AppNotificationReadResponse>,
    registerPushToken: (token: string) =>
      invoke("app_register_push_token", { token }) as Promise<void>,
    updateStatus: () =>
      invoke("app_update_status") as Promise<UpdateStatus>,
    setAutomaticUpdates: (enabled: boolean) =>
      invoke("app_update_set_automatic", { enabled }) as Promise<UpdateStatus>,
    installUpdate: () =>
      invoke("app_update_install") as Promise<UpdateStatus>,
    restartForUpdate: () =>
      invoke("app_update_restart") as Promise<void>,
    splitTunnelState: () =>
      invoke("app_split_tunnel_state") as Promise<SplitTunnelState>,
    splitTunnelInstalledApplications: () =>
      invoke(
        "app_split_tunnel_installed_applications",
      ) as Promise<InstalledApplication[]>,
    saveSplitTunnel: (
      request: SplitTunnelSettingsUpdate,
      confirmReconnect: boolean,
    ) =>
      invoke("app_split_tunnel_save", {
        request,
        confirmReconnect,
      }) as Promise<SplitTunnelSaveResult>,
    refreshSplitTunnel: () =>
      invoke("app_split_tunnel_refresh") as Promise<SplitTunnelState>,
    addSplitTunnelAddressRule: (
      value: string,
      scope: SplitTunnelAddressRule["scope"],
    ) =>
      invoke("app_split_tunnel_add_address_rule", {
        request: { value, scope },
      }) as Promise<SplitTunnelState>,
    removeSplitTunnelAddressRule: (
      ruleId: number,
      scope: SplitTunnelAddressRule["scope"],
    ) =>
      invoke("app_split_tunnel_remove_address_rule", {
        ruleId,
        scope,
      }) as Promise<SplitTunnelState>,
    logout: () => invoke("app_logout") as Promise<void>,
  };
}

export type UserErrorContext =
  | "generic"
  | "startup"
  | "login"
  | "peer_list"
  | "peer_bind"
  | "start"
  | "stop"
  | "preferences"
  | "saved_stray"
  | "unbind_peer"
  | "logout"
  | "diagnostics"
  | "notifications"
  | "update"
  | "split_tunnel";

export interface UserErrorOptions {
  personalPeer?: boolean;
}

export interface NativeConnectionChangedEvent {
  error: NativeCommandError | null;
  action: "start" | "stop";
}

export function commandCode(error: unknown): string | null {
  if (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    typeof (error as NativeCommandError).code === "string"
  ) {
    return (error as NativeCommandError).code;
  }
  return null;
}

function nativeErrorMessage(error: unknown): string | null {
  if (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    typeof (error as NativeCommandError).code === "string" &&
    "message" in error &&
    typeof (error as NativeCommandError).message === "string"
  ) {
    return (error as NativeCommandError).message;
  }
  return null;
}

function unavailableMessage(context: UserErrorContext): string {
  switch (context) {
    case "login":
      return "Панель Nelomai не отвечает. Проверьте интернет и попробуйте войти снова.";
    case "startup":
      return "Панель Nelomai не отвечает. Проверьте интернет и нажмите «Повторить».";
    case "start":
      return "Не удалось получить подключение. Проверьте интернет и нажмите «Старт» ещё раз.";
    case "stop":
      return "VPN на устройстве остановлен, но панель не подтвердила отключение. Нажмите «Повторить».";
    case "peer_list":
      return "Не удалось загрузить пиры. Проверьте интернет и нажмите «Проверить ещё раз».";
    case "peer_bind":
      return "Не удалось выбрать пир. Проверьте интернет и нажмите «Использовать этот пир» ещё раз.";
    case "diagnostics":
      return "Не удалось отправить логи. Проверьте интернет и повторите отправку.";
    case "notifications":
      return "Не удалось загрузить уведомления. Проверьте интернет и повторите попытку.";
    case "update":
      return "Не удалось загрузить обновление. Проверьте интернет и нажмите «Обновить» ещё раз.";
    case "split_tunnel":
      return "Не удалось загрузить настройки split-tunnel. Проверьте интернет и нажмите «Принудительная синхронизация».";
    case "saved_stray":
      return "Не удалось изменить сохранённое подключение. Проверьте интернет и повторите действие.";
    case "unbind_peer":
      return "Не удалось сменить пир. Проверьте интернет и повторите действие.";
    case "logout":
      return "Не удалось выйти из аккаунта. Проверьте интернет и нажмите «Выйти» ещё раз.";
    default:
      return "Панель Nelomai не отвечает. Проверьте интернет и повторите действие.";
  }
}

export function commandMessage(
  error: unknown,
  context: UserErrorContext = "generic",
  options: UserErrorOptions = {},
): string {
  const code = commandCode(error);
  const original = nativeErrorMessage(error);

  if (
    context === "start" &&
    options.personalPeer &&
    (code === "personal_peer_unavailable" ||
      code === "configuration_fetch_failed")
  ) {
    return "Ваш домашний сервер временно недоступен. Попробуйте позже или используйте динамический режим.";
  }

  switch (code) {
    case "temporarily_unavailable":
      return unavailableMessage(context);
    case "startup_timeout":
      return "Запуск не завершился вовремя. Проверьте интернет и нажмите «Повторить».";
    case "signed_out":
    case "invalid_access_token":
    case "invalid_refresh_token":
    case "refresh_token_reused":
      return "Сессия этого устройства завершена. Войдите в аккаунт снова.";
    case "access_expired":
      return "Срок доступа истёк. Продлите его в панели и нажмите «Проверить снова».";
    case "critical_update_required":
    case "update_required":
      return "Эта версия больше не может подключаться. Установите обновление, чтобы продолжить.";
    case "device_limit_reached":
      return "Все пиры уже заняты другими устройствами. Освободите один из них в панели или используйте существующее устройство.";
    case "connection_unavailable":
      return "Не удалось подобрать рабочий сервер. Подождите несколько секунд и нажмите «Старт» ещё раз — приложение попробует другой сервер.";
    case "candidate_unavailable":
      return "Выбранный сервер перестал отвечать. Нажмите «Старт» ещё раз — приложение выберет другой.";
    case "configuration_fetch_failed":
      return "Сервер не смог подготовить подключение. Нажмите «Старт» ещё раз. Если ошибка повторяется в личном режиме — выберите другой пир.";
    case "connection_already_active":
      return "Не удалось завершить предыдущее подключение. Нажмите «Старт» ещё раз.";
    case "connection_no_longer_active":
      return "Нажмите «Старт» ещё раз";
    case "connection_release_failed":
      return "Предыдущее подключение ещё освобождается. Подождите несколько секунд и нажмите «Старт» снова.";
    case "saved_connection_unavailable":
    case "saved_stray_unavailable":
      return "Сохранённый сервер не отвечает. Нажмите «Старт», чтобы выбрать другой доступный сервер.";
    case "probe_results_required":
      return "Не удалось проверить доступные серверы. Проверьте интернет и нажмите «Старт» ещё раз.";
    case "connection_stop_failed":
      return "VPN ещё не удалось полностью остановить. Нажмите «Повторить». Если ошибка останется — перезапустите приложение.";
    case "vpn_permission_denied":
    case "vpn_permission_required":
      return "Разрешите VPN-подключение в системном окне Android. Затем нажмите «Старт» ещё раз.";
    case "tunnel_service_unavailable":
      return context === "start"
        ? "Системный компонент VPN не отвечает. Нажмите «Старт» ещё раз и подтвердите восстановление. Если ошибка повторится — переустановите Nelomai."
        : "Системный компонент VPN не отвечает. Нажмите «Повторить» и подтвердите восстановление. Если ошибка повторится — переустановите Nelomai.";
    case "tunnel_backend_unavailable":
      return "Система VPN недоступна на этом устройстве. Перезапустите Nelomai и попробуйте снова.";
    case "tunnel_failed":
      return context === "stop"
        ? "VPN ещё не удалось полностью остановить. Нажмите «Повторить». Если ошибка останется — перезапустите приложение."
        : "Не удалось запустить VPN. Отключите другие VPN-приложения и попробуйте снова. Если ошибка повторится — отправьте логи.";
    case "physical_network_monitor_unavailable":
      return "Не удалось определить активную сеть. Убедитесь, что Wi-Fi или мобильный интернет включён, и повторите подключение.";
    case "physical_egress_unavailable":
      return "Не удалось определить активное подключение устройства к сети. Переподключите Wi-Fi или мобильный интернет и нажмите «Старт» снова.";
    case "local_networks_unavailable":
      return "Не удалось определить локальную сеть. Переподключите устройство к сети и нажмите «Старт» снова.";
    case "endpoint_route_unavailable":
      return "Не удалось безопасно проложить маршрут до Stray-сервера. Переподключите устройство к сети и нажмите «Старт» снова.";
    case "endpoint_route_lost":
      return "Сеть изменилась, поэтому Stray остановлен для защиты. Нажмите «Старт» снова.";
    case "amneziawg_profile_mismatch":
    case "awg3_profile_apply_failed":
    case "awg3_profile_transform_mismatch":
      return "Не удалось применить параметры Stray. Нажмите «Старт» ещё раз. Если ошибка повторится — отправьте логи.";
    case "route_conflict":
      return "Маршрут split-tunnel уже используется другим VPN. Отключите другие VPN-приложения и попробуйте снова.";
    case "route_add_failed":
    case "route_del_failed":
    case "route_delete_failed":
    case "route_command_failed":
    case "route_command_unavailable":
    case "route_table_unavailable":
    case "ip_command_unavailable":
      return "Не удалось применить маршруты split-tunnel. Отключите другие VPN-приложения и попробуйте снова.";
    case "helper_install_cancelled":
      return "Установка системного компонента отменена. Нажмите «Старт» ещё раз и подтвердите запрос администратора.";
    case "helper_authorization_unavailable":
      return "Не удалось открыть запрос прав администратора. Перезапустите Nelomai и нажмите «Старт» ещё раз.";
    case "helper_installer_timeout":
      return "Системная настройка не завершилась. Закройте оставшееся системное окно и нажмите «Старт» снова.";
    case "helper_resources_unavailable":
      return "В приложении отсутствует системный компонент VPN. Переустановите последнюю версию Nelomai.";
    case "installed_applications_unavailable":
      return "Android не предоставил список приложений. Перезапустите Nelomai и откройте split-tunnel снова.";
    case "split_tunnel_policy_unavailable":
      return "Не удалось загрузить настройки split-tunnel. Проверьте интернет и нажмите «Принудительная синхронизация».";
    case "split_tunnel_state_save_failed":
      return "VPN продолжает работать, но новые настройки могут не сохраниться после перезапуска. Попробуйте сохранить их ещё раз.";
    case "preferences_unavailable":
      return "Изменение не сохранилось. Повторите попытку; если ошибка останется — перезапустите Nelomai.";
    case "diagnostics_unavailable":
    case "diagnostics_storage_unavailable":
      return "Не удалось подготовить логи. Перезапустите Nelomai и повторите отправку.";
    case "update_failed":
      return original?.startsWith("Разрешите ") || original?.includes("вручную")
        ? original
        : "Не удалось установить обновление. Проверьте интернет и нажмите «Обновить» ещё раз.";
    default:
      return original ?? "Не удалось выполнить действие. Повторите попытку.";
  }
}

export const nativeClient = createNativeClient();
