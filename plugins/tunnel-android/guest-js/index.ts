import { invoke } from "@tauri-apps/api/core";

export interface TunnelProbe {
  platform: string;
  backendAvailable: boolean;
  permissionGranted: boolean;
  backendVersion: string | null;
  error: string | null;
}

export interface SmokeResult {
  state: "up" | "down" | "unsupported";
  durationMillis: number;
}

export async function probe(): Promise<TunnelProbe> {
  return invoke<TunnelProbe>("plugin:tunnel-android|probe");
}

export async function requestVpnPermission(): Promise<boolean> {
  const result = await invoke<{ permissionGranted: boolean }>(
    "plugin:tunnel-android|request_vpn_permission",
  );
  return result.permissionGranted;
}

export async function startSmokeTunnel(): Promise<SmokeResult> {
  return invoke<SmokeResult>("plugin:tunnel-android|start_smoke_tunnel");
}

export async function stopSmokeTunnel(): Promise<SmokeResult> {
  return invoke<SmokeResult>("plugin:tunnel-android|stop_smoke_tunnel");
}

export async function smokeTunnelStatus(): Promise<SmokeResult> {
  return invoke<SmokeResult>("plugin:tunnel-android|smoke_tunnel_status");
}
