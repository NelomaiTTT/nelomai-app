use serde::{Deserialize, Serialize};
use std::fmt;

mod split_tunnel;

pub use split_tunnel::{
    SplitTunnelAddressRule, SplitTunnelAddressRuleKind, SplitTunnelAddressRuleScope,
    SplitTunnelAddressRuleUpdate, SplitTunnelApplyResult, SplitTunnelApplyStatus, SplitTunnelMode,
    SplitTunnelPolicy, SplitTunnelRevision, SplitTunnelSelectedPackage, SplitTunnelSettingsUpdate,
    SplitTunnelTimestampError, SplitTunnelTimestampField,
};

pub const API_PREFIX: &str = "/api/client/v1";
pub const CONTRACT_VERSION: &str = "1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum ApiVersion {
    #[serde(rename = "1")]
    V1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessState {
    Active,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
    Tic,
    Stray,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TicConnectionMode {
    Personal,
    Dynamic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteMode {
    Standalone,
    ViaTak,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Android,
    Windows,
    Macos,
    Linux,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseStatus {
    Allocating,
    Issued,
    Connected,
    Warm,
    Released,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Access {
    pub state: AccessState,
    pub can_login: bool,
    pub can_connect: bool,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub platform: Platform,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PeerOption {
    pub id: String,
    pub interface_id: String,
    pub interface_name: String,
    pub slot: u32,
    pub name: String,
    pub comment: Option<String>,
    pub last_handshake_at: Option<String>,
    pub bound_to_app: bool,
    pub bound_to_this_device: bool,
    pub selectable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PeerOptions {
    pub api_version: ApiVersion,
    pub request_id: String,
    pub peers: Vec<PeerOption>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct BindPeerRequest {
    pub peer_id: String,
    pub preferred_layer: Layer,
    pub tic_connection_mode: TicConnectionMode,
    pub route_mode: RouteMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PeerBinding {
    pub id: String,
    pub peer_id: String,
    pub interface_id: String,
    pub interface_name: String,
    pub slot: u32,
    pub preferred_layer: Layer,
    pub tic_connection_mode: TicConnectionMode,
    pub route_mode: RouteMode,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PeerBindingResponse {
    pub api_version: ApiVersion,
    pub request_id: String,
    pub binding: Option<PeerBinding>,
    pub configuration: Option<String>,
}

impl fmt::Debug for PeerBindingResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerBindingResponse")
            .field("api_version", &self.api_version)
            .field("request_id", &self.request_id)
            .field("binding", &self.binding)
            .field(
                "configuration",
                &self.configuration.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ServerCandidate {
    pub candidate_id: String,
    pub layer: Layer,
    pub region_label: String,
    pub probe_url: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ServerCandidatesResponse {
    pub api_version: ApiVersion,
    pub request_id: String,
    pub candidates: Vec<ServerCandidate>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbeResult {
    pub candidate_id: String,
    pub latency_ms: f64,
    pub measured_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbeResults {
    pub layer: Layer,
    pub probes: Vec<ProbeResult>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerSelectionRequest {
    pub layer: Layer,
    pub probes: Vec<ProbeResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ServerSelectionResponse {
    pub api_version: ApiVersion,
    pub request_id: String,
    pub candidate_id: String,
    pub layer: Layer,
    pub region_label: String,
    pub probe_url: String,
    pub selection_reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Connection {
    pub lease_id: String,
    pub layer: Layer,
    pub tic_connection_mode: TicConnectionMode,
    pub route_mode: RouteMode,
    pub status: LeaseStatus,
    pub pinned: bool,
    pub stopped_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct BootstrapDefaults {
    pub layer: Layer,
    pub tic_connection_mode: TicConnectionMode,
    pub route_mode: RouteMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct UpdateState {
    pub current_version: Option<String>,
    pub minimum_version: Option<String>,
    pub update_available: bool,
    pub required: bool,
    pub release_notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct UpdateManifest {
    pub version: String,
    pub notes: Option<String>,
    pub pub_date: Option<String>,
    pub url: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Bootstrap {
    pub api_version: ApiVersion,
    pub request_id: String,
    pub access: Access,
    pub device: Device,
    pub binding: Option<PeerBinding>,
    pub connection: Option<Connection>,
    pub pinned_stray: Option<Connection>,
    pub defaults: BootstrapDefaults,
    pub update: UpdateState,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnectionStartRequest {
    pub operation_id: String,
    pub layer: Layer,
    pub tic_connection_mode: TicConnectionMode,
    pub route_mode: RouteMode,
    pub probes: Vec<ProbeResult>,
    pub allow_alternate: bool,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ConnectionStartResponse {
    pub api_version: ApiVersion,
    pub request_id: String,
    pub connection: Connection,
    pub configuration: String,
    pub reused: bool,
}

impl fmt::Debug for ConnectionStartResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionStartResponse")
            .field("api_version", &self.api_version)
            .field("request_id", &self.request_id)
            .field("connection", &self.connection)
            .field("configuration", &"<redacted>")
            .field("reused", &self.reused)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ConnectionOperationRequest {
    pub operation_id: String,
    pub lease_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ConnectionOperationResponse {
    pub api_version: ApiVersion,
    pub request_id: String,
    pub connection: Connection,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorPayload {
    pub request_id: String,
    pub code: String,
    pub message: String,
}
