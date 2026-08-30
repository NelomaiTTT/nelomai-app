use serde::{Deserialize, Serialize};
use std::fmt;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const MAX_CANDIDATES_OR_PROBES: usize = 20;

mod bounded_connection_items {
    use super::MAX_CANDIDATES_OR_PROBES;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<T, S>(items: &[T], serializer: S) -> Result<S::Ok, S::Error>
    where
        T: Serialize,
        S: Serializer,
    {
        if items.len() > MAX_CANDIDATES_OR_PROBES {
            return Err(<S::Error as serde::ser::Error>::custom(
                "connection item count exceeds 20",
            ));
        }
        items.serialize(serializer)
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Vec<T>, D::Error>
    where
        T: Deserialize<'de>,
        D: Deserializer<'de>,
    {
        let items = Vec::<T>::deserialize(deserializer)?;
        if items.len() > MAX_CANDIDATES_OR_PROBES {
            return Err(<D::Error as serde::de::Error>::custom(
                "connection item count exceeds 20",
            ));
        }
        Ok(items)
    }
}

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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressMode {
    #[default]
    Ipv4,
    PreferIpv6,
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
pub struct AppNotification {
    pub id: i64,
    pub kind: String,
    pub title: String,
    pub body: String,
    pub url: Option<String>,
    pub created_at: String,
    pub read_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct AppNotificationList {
    pub api_version: ApiVersion,
    pub request_id: String,
    pub notifications: Vec<AppNotification>,
    pub unread_count: u32,
    pub next_cursor: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct AppNotificationReadResponse {
    pub api_version: ApiVersion,
    pub request_id: String,
    pub updated: u32,
    pub unread_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PushRegistrationRequest {
    pub provider: String,
    pub token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PushRegistrationResponse {
    pub api_version: ApiVersion,
    pub request_id: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct BindPeerRequest {
    pub peer_id: String,
    pub preferred_layer: Layer,
    pub tic_connection_mode: TicConnectionMode,
    pub route_mode: RouteMode,
    #[serde(default)]
    pub egress_mode: EgressMode,
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
    #[serde(default)]
    pub egress_mode: EgressMode,
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
    #[serde(with = "bounded_connection_items")]
    pub candidates: Vec<ServerCandidate>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeFailureCode {
    InvalidUrl,
    UnsupportedScheme,
    Timeout,
    NetworkError,
    HttpError,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbeResult {
    pub candidate_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<ProbeFailureCode>,
    pub measured_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbeResults {
    pub layer: Layer,
    #[serde(default)]
    pub egress_mode: EgressMode,
    #[serde(with = "bounded_connection_items")]
    pub probes: Vec<ProbeResult>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerSelectionRequest {
    pub layer: Layer,
    #[serde(default)]
    pub egress_mode: EgressMode,
    #[serde(with = "bounded_connection_items")]
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
    #[serde(default)]
    pub pool_id: Option<String>,
    pub layer: Layer,
    pub tic_connection_mode: TicConnectionMode,
    pub route_mode: RouteMode,
    #[serde(default)]
    pub egress_mode: EgressMode,
    #[serde(default)]
    pub probe_url: Option<String>,
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
    #[serde(default)]
    pub capabilities: Option<ConnectionIntentCapability>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ConnectionIntentCapability {
    pub revision: i64,
    pub expires_at: String,
    pub connection_intent_recovery_v1: bool,
}

impl ConnectionIntentCapability {
    pub fn expires_at_unix(&self) -> Option<i64> {
        OffsetDateTime::parse(&self.expires_at, &Rfc3339)
            .ok()
            .map(|expires_at| expires_at.unix_timestamp())
    }

    pub fn is_recovery_enabled_at(&self, now_unix: i64) -> bool {
        self.revision > 0
            && self.connection_intent_recovery_v1
            && self
                .expires_at_unix()
                .is_some_and(|expires_at| expires_at > now_unix)
    }
}

pub fn allows_new_connection_intent_operation(
    capability: Option<&ConnectionIntentCapability>,
    now_unix: i64,
) -> bool {
    capability.is_some_and(|capability| capability.is_recovery_enabled_at(now_unix))
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ConnectionIntentCapabilityResponse {
    pub api_version: ApiVersion,
    pub request_id: String,
    #[serde(flatten)]
    pub capability: ConnectionIntentCapability,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnectionStartRequest {
    pub operation_id: String,
    pub layer: Layer,
    pub tic_connection_mode: TicConnectionMode,
    pub route_mode: RouteMode,
    #[serde(default)]
    pub egress_mode: EgressMode,
    #[serde(with = "bounded_connection_items")]
    pub probes: Vec<ProbeResult>,
    pub allow_alternate: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub require_measured_selection: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_contract_version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_fingerprint: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ConnectionOperationResponse {
    pub api_version: ApiVersion,
    pub request_id: String,
    pub connection: Connection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    Start,
    StalledStop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    NotFound,
    Pending,
    Applying,
    Compensating,
    Applied,
    Terminal,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct OperationReconcileRequest {
    pub operation_id: String,
    pub kind: OperationKind,
    #[serde(default = "default_recovery_contract_version")]
    pub contract_version: u32,
    pub request_fingerprint: String,
    #[serde(default)]
    pub cancel_if_absent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct OperationReconcileResponse {
    pub api_version: ApiVersion,
    pub request_id: String,
    pub state: OperationState,
    pub cancel_requested: bool,
    #[serde(default)]
    pub lease_id: Option<String>,
    #[serde(default)]
    pub lease_status: Option<LeaseStatus>,
    #[serde(default)]
    pub retry_count: u32,
    #[serde(default)]
    pub next_attempt_at: Option<String>,
}

const fn is_false(value: &bool) -> bool {
    !*value
}

const fn default_recovery_contract_version() -> u32 {
    1
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorPayload {
    pub request_id: String,
    pub code: String,
    pub message: String,
}
