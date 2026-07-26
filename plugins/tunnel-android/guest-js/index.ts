import { invoke } from "@tauri-apps/api/core";

export interface TunnelProbe {
  platform: string;
  backendAvailable: boolean;
  permissionGranted: boolean;
  backendVersion: string | null;
  error: string | null;
}

export interface TunnelStatus {
  state: "stopped" | "starting" | "running" | "stopping" | "failed" | "unsupported";
  durationMillis: number;
  errorCode: string | null;
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

export async function tunnelStatus(): Promise<TunnelStatus> {
  return invoke<TunnelStatus>("plugin:tunnel-android|tunnel_status");
}
