import { invoke } from "@tauri-apps/api/core";

export interface TunnelProbe {
  platform: string;
  androidApiLevel: number | null;
  addressSplitTunnel: boolean;
  applicationSplitTunnel: boolean;
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

export interface InstalledApplication {
  packageId: string;
  displayName: string;
  system: boolean;
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

export async function installedApplications(): Promise<InstalledApplication[]> {
  const result = await invoke<{ applications: InstalledApplication[] }>(
    "plugin:tunnel-android|installed_applications",
  );
  return result.applications;
}

export async function tunnelStatus(): Promise<TunnelStatus> {
  return invoke<TunnelStatus>("plugin:tunnel-android|tunnel_status");
}
