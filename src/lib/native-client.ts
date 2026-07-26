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
    refreshProbes: (layer: Layer) =>
      invoke("app_refresh_probes", { layer }) as Promise<ProbeResults>,
    start: (request: StartCommandRequest) =>
      invoke("app_start", { request }) as Promise<Connection>,
    startSavedStray: () =>
      invoke("app_start_saved_stray") as Promise<string>,
    stop: () => invoke("app_stop") as Promise<Connection>,
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
