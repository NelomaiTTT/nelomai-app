import { invoke as tauriInvoke } from "@tauri-apps/api/core";

import type {
  AppState,
  BindPeerRequest,
  Bootstrap,
  Connection,
  NativeCommandError,
  PeerBinding,
  PeerOptions,
  ProbeResults,
  Layer,
  StartCommandRequest,
  UpdateStatus,
} from "./app-model";

type Invoke = (
  command: string,
  args?: Record<string, unknown>,
) => Promise<unknown>;

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

export function createNativeClient(
  invoke: Invoke = (command, args) => tauriInvoke(command, args),
) {
  return {
    state: () => invoke("app_state") as Promise<AppState>,
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
    updateStatus: () =>
      invoke("app_update_status") as Promise<UpdateStatus>,
    setAutomaticUpdates: (enabled: boolean) =>
      invoke("app_update_set_automatic", { enabled }) as Promise<UpdateStatus>,
    installUpdate: () =>
      invoke("app_update_install") as Promise<UpdateStatus>,
    restartForUpdate: () =>
      invoke("app_update_restart") as Promise<void>,
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
