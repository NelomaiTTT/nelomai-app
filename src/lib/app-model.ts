export type Phase =
  | "signed_out"
  | "authenticating"
  | "needs_peer_binding"
  | "access_expired"
  | "ready"
  | "measuring"
  | "connecting"
  | "connected"
  | "stopping"
  | "update_required"
  | "server_unavailable"
  | "error";

export type AppView =
  | "loading"
  | "sign_in"
  | "peer_selection"
  | "access_expired"
  | "update_required"
  | "connection"
  | "unavailable";

export type Layer = "tic" | "stray";
export type TicConnectionMode = "personal" | "dynamic";
export type RouteMode = "standalone" | "via_tak";
export type Platform = "android" | "windows" | "macos" | "linux";

export interface Access {
  state: "active" | "expired";
  can_login: boolean;
  can_connect: boolean;
  expires_at: string | null;
}

export interface Device {
  id: string;
  name: string;
  platform: Platform;
}

export interface PeerBinding {
  id: string;
  peer_id: string;
  interface_id: string;
  interface_name: string;
  slot: number;
  preferred_layer: Layer;
  tic_connection_mode: TicConnectionMode;
  route_mode: RouteMode;
}

export interface Connection {
  lease_id: string;
  layer: Layer;
  tic_connection_mode: TicConnectionMode;
  route_mode: RouteMode;
  status:
    | "allocating"
    | "issued"
    | "connected"
    | "warm"
    | "released"
    | "failed";
  pinned: boolean;
  stopped_at: string | null;
}

export interface BootstrapDefaults {
  layer: Layer;
  tic_connection_mode: TicConnectionMode;
  route_mode: RouteMode;
}

export interface UpdateState {
  current_version: string | null;
  minimum_version: string | null;
  update_available: boolean;
  required: boolean;
  release_notes: string | null;
}

export type UpdatePhase =
  | "idle"
  | "available"
  | "downloading"
  | "ready_to_restart"
  | "awaiting_installation"
  | "failed";

export interface UpdateStatus {
  supported: boolean;
  automatic: boolean;
  phase: UpdatePhase;
  version: string | null;
  notes: string | null;
  required: boolean;
  downloaded: number;
  total: number | null;
  errorCode: string | null;
}

export interface Bootstrap {
  api_version: "1";
  request_id: string;
  access: Access;
  device: Device;
  binding: PeerBinding | null;
  connection: Connection | null;
  pinned_stray: Connection | null;
  defaults: BootstrapDefaults;
  update: UpdateState;
}

export interface PeerOption {
  id: string;
  interface_id: string;
  interface_name: string;
  slot: number;
  name: string;
  comment: string | null;
  last_handshake_at: string | null;
  bound_to_app: boolean;
  bound_to_this_device: boolean;
  selectable: boolean;
}

export interface PeerOptions {
  api_version: "1";
  request_id: string;
  peers: PeerOption[];
}

export interface AppState {
  phase: Phase;
  connection: Connection | null;
  warning: string | null;
  metrics: ConnectionMetrics | null;
}

export interface ConnectionMetrics {
  receivedBytes: number;
  sentBytes: number;
  latencyMs: number | null;
  packetLossPercent: number | null;
}

export interface AppPreferences {
  closeToTraySupported: boolean;
  closeToTray: boolean;
  dnsProvider: DnsProvider;
}

export type DnsProvider = "auto" | "google" | "yandex" | "quad9";

export interface BindPeerRequest {
  peer_id: string;
  preferred_layer: Layer;
  tic_connection_mode: TicConnectionMode;
  route_mode: RouteMode;
}

export interface StartCommandRequest {
  layer: Layer;
  ticConnectionMode: TicConnectionMode;
  routeMode: RouteMode;
  allowAlternate: boolean;
}

export interface ProbeResults {
  layer: Layer;
  probes: Array<{
    candidate_id: string;
    latency_ms: number;
    measured_at: string;
  }>;
}

export interface NativeCommandError {
  code: string;
  message: string;
}

export function viewForPhase(phase: Phase): AppView {
  switch (phase) {
    case "signed_out":
      return "sign_in";
    case "needs_peer_binding":
      return "peer_selection";
    case "access_expired":
      return "access_expired";
    case "update_required":
      return "update_required";
    case "server_unavailable":
    case "error":
      return "unavailable";
    default:
      return "connection";
  }
}

export function bindingRequest(
  peerId: string,
  bootstrap: Bootstrap,
): BindPeerRequest {
  return {
    peer_id: peerId,
    preferred_layer: bootstrap.defaults.layer,
    tic_connection_mode: bootstrap.defaults.tic_connection_mode,
    route_mode: bootstrap.defaults.route_mode,
  };
}

export function requiresServerProbes(
  layer: Layer,
  ticConnectionMode: TicConnectionMode,
): boolean {
  return layer !== "tic" || ticConnectionMode !== "personal";
}

export function defaultRouteModeForLayer(layer: Layer): RouteMode {
  return layer === "tic" ? "via_tak" : "standalone";
}
