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
export type EgressMode = "ipv4" | "prefer_ipv6";
export type Platform = "android" | "windows" | "macos" | "linux";
export type ConnectionIntentStatus = "none" | "recovering" | "blocked_terminal";
export type ReserveState = "warming" | "ready" | "unavailable" | "failover";
export type PrimaryConnectionAction = "start" | "stop" | "retry";
export type RuntimeSlot = "latest" | "stable";
export type RuntimeSwitchPhase =
  | "requested"
  | "cleanup_handed_off"
  | "runtime_stopping"
  | "local_stopped"
  | "server_reconciling"
  | "auth_resuming"
  | "complete";

export interface RuntimeStatus {
  containerVersion: string;
  selectedSlot: RuntimeSlot;
  activeSlot: RuntimeSlot;
  pendingSlot: RuntimeSlot | null;
  latestVersion: string;
  stableVersion: string | null;
  runtimeContractVersion: number;
  manifestVerified: boolean;
  stableAvailable: boolean;
  switchId: string | null;
  phase: RuntimeSwitchPhase | null;
  engineRole: "primary" | "redundant";
}

export function runtimeSelectorVisible(status: RuntimeStatus): boolean {
  return (
    status.manifestVerified &&
    status.stableAvailable &&
    status.stableVersion !== null &&
    status.stableVersion !== status.latestVersion
  );
}

export function runtimeRestartRequired(status: RuntimeStatus): boolean {
  return (
    (status.pendingSlot !== null && status.pendingSlot !== status.activeSlot) ||
    status.selectedSlot !== status.activeSlot
  );
}

export function runtimeStartBlocked(status: RuntimeStatus | null): boolean {
  if (status === null) return false;
  return (
    runtimeRestartRequired(status) ||
    (status.phase !== null && status.phase !== "complete")
  );
}

export function createRuntimeSelectorActions(
  select: (useStable: boolean) => Promise<void>,
  restart: () => Promise<void>,
) {
  let inFlight: Promise<void> | null = null;
  return {
    select(useStable: boolean): Promise<void> {
      if (inFlight) return inFlight;
      const request = Promise.resolve(select(useStable));
      const tracked = request.finally(() => {
        if (inFlight === tracked) inFlight = null;
      });
      inFlight = tracked;
      return tracked;
    },
    later(): void {},
    restartNow(): Promise<void> {
      return restart();
    },
  };
}

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
  egress_mode: EgressMode;
}

export interface Connection {
  lease_id: string;
  pool_id: string | null;
  layer: Layer;
  tic_connection_mode: TicConnectionMode;
  route_mode: RouteMode;
  egress_mode: EgressMode;
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
  capabilities: ConnectionIntentCapability | null;
}

export interface Dns46DotCapability {
  ready: true;
  hostname: string;
  endpoint_ipv4s: string[];
}

export interface ConnectionIntentCapability {
  dns46_dot?: Dns46DotCapability | null;
  revision: number;
  expires_at: string;
  connection_intent_recovery_v1: boolean;
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
  localStopPendingCleanup?: boolean;
  connection: Connection | null;
  connectionIntentStatus: ConnectionIntentStatus;
  nextRetryAtUnix: number | null;
  warning: string | null;
  metrics: ConnectionMetrics | null;
  reserveState: ReserveState | null;
}

export function primaryAction(state: {
  phase: Phase;
  connectionIntentStatus: ConnectionIntentStatus;
}): PrimaryConnectionAction {
  if (state.connectionIntentStatus === "recovering") return "stop";
  if (state.connectionIntentStatus === "blocked_terminal") return "retry";
  return ["connecting", "connected", "stopping"].includes(state.phase) ? "stop" : "start";
}

export function hasSecondaryStop(state: {
  connectionIntentStatus: ConnectionIntentStatus;
}): boolean {
  return state.connectionIntentStatus === "blocked_terminal";
}

export function recoveryCopy(status: ConnectionIntentStatus): string {
  switch (status) {
    case "recovering":
      return "Приложение проверяет стабильность подключения и при необходимости повторит попытку автоматически.";
    case "blocked_terminal":
      return "Автоматическое восстановление остановлено. Нажмите «Повторить» или «Стоп».";
    default:
      return "";
  }
}

export function visibleConnectionIntentStatus(
  phase: Phase,
  status: ConnectionIntentStatus,
): ConnectionIntentStatus {
  return phase === "connected" && status === "recovering" ? "none" : status;
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
  personalTicEgressMode: EgressMode;
  dynamicTicEgressMode: EgressMode;
  useReserveConnection: boolean;
}

export function defaultAppPreferences(platform: Platform): AppPreferences {
  return {
    closeToTraySupported: false,
    closeToTray: true,
    dnsProvider: "auto",
    personalTicEgressMode: "ipv4",
    dynamicTicEgressMode: "ipv4",
    useReserveConnection: platform === "android",
  };
}

export function connectionView(state: {
  reserveState: ReserveState | null;
}): { statusText: string; requiresUserAction: boolean } {
  const statusText = state.reserveState === null
    ? "Подключено"
    : {
        warming: "Резерв запускается",
        ready: "Резерв готов",
        unavailable: "Резерв временно недоступен",
        failover: "Подключено через резервный сервер",
      }[state.reserveState];
  return { statusText, requiresUserAction: false };
}

export type DnsProvider = "auto" | "google" | "yandex" | "quad9";

export interface BindPeerRequest {
  peer_id: string;
  expected_binding_id?: string;
  preferred_layer: Layer;
  tic_connection_mode: TicConnectionMode;
  route_mode: RouteMode;
  egress_mode: EgressMode;
}

export interface StartCommandRequest {
  deviceId: string;
  bindingRequest?: BindPeerRequest | null;
  layer: Layer;
  ticConnectionMode: TicConnectionMode;
  routeMode: RouteMode;
  egressMode: EgressMode;
  allowAlternate: boolean;
}

export interface StartCommandResponse {
  status: "connected" | "recovering";
  connection: Connection | null;
  nextRetryAtUnix: number | null;
}

export interface ProbeResults {
  layer: Layer;
  egress_mode: EgressMode;
  probes: Array<{
    candidate_id: string;
    latency_ms?: number;
    failure_code?:
      | "invalid_url"
      | "unsupported_scheme"
      | "timeout"
      | "network_error"
      | "http_error"
      | "unknown";
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

export function viewForAppState(
  state: Pick<AppState, "phase" | "connectionIntentStatus">,
): AppView {
  return state.connectionIntentStatus === "none" ? viewForPhase(state.phase) : "connection";
}

export function bindingRequest(
  peerId: string,
  bootstrap: Bootstrap,
  egressMode: EgressMode,
): BindPeerRequest {
  const effectiveEgressMode =
    bootstrap.defaults.layer === "tic" &&
    bootstrap.defaults.route_mode === "via_tak"
      ? egressMode
      : "ipv4";
  return {
    peer_id: peerId,
    preferred_layer: bootstrap.defaults.layer,
    tic_connection_mode: bootstrap.defaults.tic_connection_mode,
    route_mode: bootstrap.defaults.route_mode,
    egress_mode: effectiveEgressMode,
  };
}

export function bindingPreferenceUpdateRequest(
  binding: PeerBinding,
  layer: Layer,
  ticConnectionMode: TicConnectionMode,
  routeMode: RouteMode,
  egressMode: EgressMode,
): BindPeerRequest {
  // Native Start may save preferences after this UI snapshot was read, even
  // across a page reload. Reassert the desired settings with the existing CAS.
  return {
    peer_id: binding.peer_id,
    expected_binding_id: binding.id,
    preferred_layer: layer,
    tic_connection_mode: ticConnectionMode,
    route_mode: routeMode,
    egress_mode: egressMode,
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

export function connectionEgressMode(
  layer: Layer,
  routeMode: RouteMode,
  ticConnectionMode: TicConnectionMode,
  preferences: Pick<
    AppPreferences,
    "personalTicEgressMode" | "dynamicTicEgressMode"
  > | null,
): EgressMode {
  if (layer !== "tic" || routeMode !== "via_tak" || !preferences) {
    return "ipv4";
  }
  return ticConnectionMode === "personal"
    ? preferences.personalTicEgressMode
    : preferences.dynamicTicEgressMode;
}

export function dns46DotHostname(capability: ConnectionIntentCapability | null | undefined, nowMillis = Date.now()): string | null {
  const dot = capability?.dns46_dot;
  if (!capability || capability.revision < 1 || !(Date.parse(capability.expires_at) > nowMillis) || dot?.ready !== true) return null;
  if (!/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(dot.hostname) ||
      /^\d+(?:\.\d+){3}$/.test(dot.hostname) ||
      !Array.isArray(dot.endpoint_ipv4s) || dot.endpoint_ipv4s.length === 0 || dot.endpoint_ipv4s.length > 16) return null;
  for (const ip of dot.endpoint_ipv4s) {
    const parts = ip.split('.');
    if (parts.length !== 4 || parts.some(part => !/^\d+$/.test(part) || Number(part) > 255 || String(Number(part)) !== part)) return null;
    const [a,b,c] = parts.map(Number);
    if (a === 0 || a === 10 || a === 127 || a >= 224 || (a === 169 && b === 254) ||
        (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) ||
        (a === 198 && (b === 18 || b === 19)) || (a === 192 && b === 0 && c === 2) ||
        (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113)) return null;
  }
  return dot.hostname;
}
