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
    prepareTunnel: () => invoke("app_prepare_tunnel") as Promise<void>,
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

export function commandMessage(error: unknown): string {
  if (
    typeof error === "object" &&
    error !== null &&
    "message" in error &&
    typeof (error as NativeCommandError).message === "string"
  ) {
    return (error as NativeCommandError).message;
  }
  return "Не удалось выполнить действие";
}

export const nativeClient = createNativeClient();
