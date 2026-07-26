use serde::{Deserialize, Serialize};

pub const API_PREFIX: &str = "/api/client/v1";
pub const CONTRACT_VERSION: &str = "1";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub enum ApiVersion {
    #[serde(rename = "1")]
    V1,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessState {
    Active,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
    Tic,
    Stray,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionMode {
    Fixed,
    Dynamic,
    Pinned,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteMode {
    Standalone,
    ViaTak,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionStatus {
    Disconnected,
    Probing,
    Starting,
    Connected,
    Stopping,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Android,
    Windows,
    Macos,
    Linux,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactArch {
    X86_64,
    Aarch64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseChannel {
    Stable,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateRequirement {
    None,
    Available,
    Required,
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
    pub binding_peer_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ClientDefaults {
    pub layer: Layer,
    pub mode: ConnectionMode,
    pub route_mode: RouteMode,
    pub probe_refresh_seconds: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct UpdateSummary {
    pub requirement: UpdateRequirement,
    pub latest_version: String,
    pub minimum_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Capabilities {
    pub pin_stray: bool,
    pub split_tunnel: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Bootstrap {
    pub api_version: ApiVersion,
    pub request_id: String,
    pub access: Access,
    pub device: Device,
    pub defaults: ClientDefaults,
    pub update: UpdateSummary,
    pub capabilities: Capabilities,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PeerOption {
    pub id: String,
    pub name: String,
    pub comment: Option<String>,
    pub last_handshake_at: Option<String>,
    pub bound_to_app: bool,
    pub selectable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PeerOptions {
    pub api_version: ApiVersion,
    pub request_id: String,
    pub peers: Vec<PeerOption>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ProbeMeasurement {
    pub candidate_id: String,
    pub latency_ms: Option<u32>,
    pub reachable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ProbeResults {
    pub api_version: ApiVersion,
    pub operation_id: String,
    pub measured_at: String,
    pub results: Vec<ProbeMeasurement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ConnectionStart {
    pub api_version: ApiVersion,
    pub operation_id: String,
    pub layer: Layer,
    pub mode: ConnectionMode,
    pub route_mode: RouteMode,
    pub candidate_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct SafeError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ConnectionState {
    pub api_version: ApiVersion,
    pub request_id: String,
    pub status: ConnectionStatus,
    pub operation_id: Option<String>,
    pub layer: Option<Layer>,
    pub mode: Option<ConnectionMode>,
    pub route_mode: Option<RouteMode>,
    pub changed_at: String,
    pub can_retry: bool,
    pub error: Option<SafeError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct UpdateArtifact {
    pub id: String,
    pub platform: Platform,
    pub arch: ArtifactArch,
    pub size_bytes: u64,
    pub sha256: String,
    pub signature: String,
    pub download_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct UpdateManifest {
    pub api_version: ApiVersion,
    pub request_id: String,
    pub channel: ReleaseChannel,
    pub version: String,
    pub minimum_version: String,
    pub critical: bool,
    pub published_at: String,
    pub notes: String,
    pub artifacts: Vec<UpdateArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorPayload {
    pub request_id: String,
    pub code: String,
    pub message: String,
}
