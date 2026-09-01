use nelomai_client_tunnel::{
    RedundantTunnelMemberStart, RedundantTunnelStandbyStart, RedundantTunnelStart,
};
use nelomai_contracts::{HealthProbeKind, RedundancyMemberSlot, RedundantHealthProbe};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroizing;

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeRequest {}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeResponse {
    pub platform: String,
    pub android_api_level: Option<u32>,
    pub address_split_tunnel: bool,
    pub application_split_tunnel: bool,
    pub backend_available: bool,
    pub permission_granted: bool,
    pub backend_version: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionRequest {}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionResponse {
    pub permission_granted: bool,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledApplicationsRequest {}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InstalledApplication {
    pub package_id: String,
    pub display_name: String,
    pub system: bool,
}

#[derive(Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InstalledApplicationsResponse {
    pub applications: Vec<InstalledApplication>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceUsageRequest {}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsServersRequest {
    pub dns_servers: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartFailureDiagnosticsRequest {
    pub device_id: String,
    pub error_code: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceUsageResponse {
    pub cpu_user_ms: Option<u64>,
    pub cpu_system_ms: Option<u64>,
    pub network_rx_bytes: Option<u64>,
    pub network_tx_bytes: Option<u64>,
    pub cpu_charge_milliamp_milliseconds: Option<u64>,
    pub mobile_charge_milliamp_milliseconds: Option<u64>,
    pub wifi_charge_milliamp_milliseconds: Option<u64>,
    #[serde(default)]
    pub processes: Vec<AndroidProcessResourceUsage>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AndroidProcessResourceUsage {
    pub process_id: u64,
    pub process_name: String,
    pub current_resident_memory_bytes: Option<u64>,
    pub peak_resident_memory_bytes: Option<u64>,
    pub current_proportional_memory_bytes: Option<u64>,
    pub current_private_dirty_memory_bytes: Option<u64>,
}

impl fmt::Debug for InstalledApplicationsResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstalledApplicationsResponse")
            .field("applications_count", &self.applications.len())
            .finish()
    }
}

pub const TUNNEL_API_VERSION: u16 = 2;

#[derive(Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TunnelOptions {
    pub split_active: bool,
    pub policy_hash: Option<String>,
    pub application_mode: Option<String>,
    pub excluded_packages: Vec<String>,
    pub included_packages: Vec<String>,
    pub split_tunnel_routes: Vec<String>,
    pub exclude_local_networks: bool,
    pub dns_servers: Vec<String>,
}

impl fmt::Debug for TunnelOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TunnelOptions")
            .field("split_active", &self.split_active)
            .field("excluded_packages_count", &self.excluded_packages.len())
            .field("included_packages_count", &self.included_packages.len())
            .field("split_tunnel_routes_count", &self.split_tunnel_routes.len())
            .field("exclude_local_networks", &self.exclude_local_networks)
            .field("dns_servers_count", &self.dns_servers.len())
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedundantHealthProbeRequest {
    pub kind: String,
    pub target_ipv4: String,
    pub query_name: String,
    pub timeout_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedundantMemberRequest {
    pub slot: String,
    pub lease_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_probe: Option<RedundantHealthProbeRequest>,
}

pub struct RedundantStandbyRequest {
    pub member: RedundantMemberRequest,
    pub configuration: Zeroizing<Vec<u8>>,
}

impl RedundantStandbyRequest {
    pub fn new(member: RedundantMemberRequest, configuration: &[u8]) -> Self {
        Self {
            member,
            configuration: Zeroizing::new(configuration.to_vec()),
        }
    }
}

impl fmt::Debug for RedundantStandbyRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedundantStandbyRequest")
            .field("member", &self.member)
            .field("configuration", &"<redacted>")
            .finish()
    }
}

impl Serialize for RedundantStandbyRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct WireStandby<'a> {
            member: &'a RedundantMemberRequest,
            configuration: &'a [u8],
        }

        WireStandby {
            member: &self.member,
            configuration: self.configuration.as_slice(),
        }
        .serialize(serializer)
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedundantStartRequest {
    pub session_id: String,
    pub operation_id: String,
    pub request_fingerprint: String,
    pub reserve_enabled: bool,
    pub virtual_address_v4: String,
    pub standby_desired: bool,
    pub active_lease_id: String,
    pub local_active_lease_id: String,
    pub role_generation: u64,
    pub membership_generation: u64,
    pub primary: RedundantMemberRequest,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub standby: Option<RedundantStandbyRequest>,
}

impl From<RedundantHealthProbe> for RedundantHealthProbeRequest {
    fn from(probe: RedundantHealthProbe) -> Self {
        Self {
            kind: match probe.kind {
                HealthProbeKind::DnsA => "dns_a",
            }
            .to_string(),
            target_ipv4: probe.target_ipv4.to_string(),
            query_name: probe.query_name,
            timeout_ms: probe.timeout_ms,
        }
    }
}

impl From<RedundantTunnelMemberStart> for RedundantMemberRequest {
    fn from(member: RedundantTunnelMemberStart) -> Self {
        Self {
            slot: match member.slot {
                RedundancyMemberSlot::A => "A",
                RedundancyMemberSlot::B => "B",
            }
            .to_string(),
            lease_id: member.lease_id,
            health_probe: member.health_probe.map(Into::into),
        }
    }
}

impl From<RedundantTunnelStandbyStart> for RedundantStandbyRequest {
    fn from(standby: RedundantTunnelStandbyStart) -> Self {
        Self::new(standby.member.into(), standby.configuration.as_bytes())
    }
}

impl From<RedundantTunnelStart> for RedundantStartRequest {
    fn from(start: RedundantTunnelStart) -> Self {
        Self {
            session_id: start.session_id,
            operation_id: start.operation_id,
            request_fingerprint: start.request_fingerprint,
            reserve_enabled: start.reserve_enabled,
            virtual_address_v4: start.virtual_address_v4,
            standby_desired: start.standby_desired,
            active_lease_id: start.active_lease_id,
            local_active_lease_id: start.local_active_lease_id,
            role_generation: start.role_generation,
            membership_generation: start.membership_generation,
            primary: start.primary.into(),
            standby: start.standby.map(Into::into),
        }
    }
}

pub struct StartTunnelRequest {
    pub api_version: u16,
    pub start_source: String,
    pub configuration: Zeroizing<Vec<u8>>,
    pub options: TunnelOptions,
    pub cache_quick_action: bool,
    pub quick_action_valid_until_unix: Option<i64>,
    pub quick_connection: Option<QuickConnectionRequest>,
    pub redundancy: Option<RedundantStartRequest>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct QuickConnectionRequest {
    pub lease_id: String,
    pub layer: String,
    pub tic_connection_mode: String,
    pub route_mode: String,
    pub egress_mode: String,
    pub allow_alternate: bool,
}

impl StartTunnelRequest {
    pub fn new(configuration: &[u8]) -> Self {
        Self {
            api_version: TUNNEL_API_VERSION,
            start_source: "ui".to_string(),
            configuration: Zeroizing::new(configuration.to_vec()),
            options: TunnelOptions::default(),
            cache_quick_action: false,
            quick_action_valid_until_unix: None,
            quick_connection: None,
            redundancy: None,
        }
    }
}

impl fmt::Debug for StartTunnelRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StartTunnelRequest")
            .field("api_version", &self.api_version)
            .field("configuration", &"<redacted>")
            .field("options", &self.options)
            .field("cache_quick_action", &self.cache_quick_action)
            .field(
                "quick_action_valid_until_unix",
                &self.quick_action_valid_until_unix,
            )
            .field("quick_connection", &self.quick_connection)
            .field("redundancy", &self.redundancy)
            .finish()
    }
}

impl Serialize for StartTunnelRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct WireRequest<'a> {
            api_version: u16,
            start_source: &'a str,
            configuration: &'a [u8],
            options: &'a TunnelOptions,
            cache_quick_action: bool,
            quick_action_valid_until_unix: Option<i64>,
            quick_connection: &'a Option<QuickConnectionRequest>,
            #[serde(skip_serializing_if = "Option::is_none")]
            redundancy: Option<&'a RedundantStartRequest>,
        }

        WireRequest {
            api_version: self.api_version,
            start_source: &self.start_source,
            configuration: self.configuration.as_slice(),
            options: &self.options,
            cache_quick_action: self.cache_quick_action,
            quick_action_valid_until_unix: self.quick_action_valid_until_unix,
            quick_connection: &self.quick_connection,
            redundancy: self.redundancy.as_ref(),
        }
        .serialize(serializer)
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackgroundCredentialRequest {
    pub api_version: u16,
    pub expected_revision: i64,
    pub device_id: String,
    pub panel_base: String,
    pub token: String,
    pub expires_at_unix: i64,
    pub install_secret: String,
    pub capability_revision: i64,
    pub capability_enabled: bool,
    pub capability_expires_at: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BackgroundCredentialStatusResponse {
    pub configured: bool,
    pub credential_revision: i64,
    pub mutation_ready: bool,
    pub mutation_pending: bool,
    #[serde(default)]
    pub capability_revision: i64,
    pub capability_enabled: bool,
    pub capability_expires_at_unix: Option<i64>,
    pub device_id: Option<String>,
    pub expires_at_unix: Option<i64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BackgroundLogoutOwnership {
    Native,
    NotOwned,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BackgroundLogoutOwnershipResponse {
    pub ownership: BackgroundLogoutOwnership,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackgroundCredentialMutationRequest {
    pub expected_revision: i64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionIntentTemplateRequest {
    pub device_id: String,
    pub account_scope: String,
    pub layer: String,
    pub tic_connection_mode: String,
    pub route_mode: String,
    pub egress_mode: String,
    pub allow_alternate: bool,
    #[serde(default)]
    pub sync_binding_preferences: bool,
    #[serde(default)]
    pub options: TunnelOptions,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BeginConnectionIntentRequest {
    pub api_version: u16,
    pub template: ConnectionIntentTemplateRequest,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CancelConnectionIntentRequest {
    pub generation: u64,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionIntentStatusResponse {
    pub generation: u64,
    pub desired_active: bool,
    pub status: String,
    pub lease_phase: Option<String>,
    pub next_retry_at_unix: Option<i64>,
    pub last_error_code: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackgroundUiProvisionRequest {
    pub api_version: u16,
    pub expected_revision: i64,
    pub device_id: String,
    pub panel_base: String,
    pub access_token: String,
    pub install_secret: String,
    pub capability_revision: i64,
    pub capability_enabled: bool,
    pub capability_expires_at: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackgroundSessionRecoveryRequest {
    pub install_secret: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackgroundSessionRecoveryResponse {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub error_code: Option<String>,
}

impl fmt::Debug for BackgroundSessionRecoveryRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackgroundSessionRecoveryRequest")
            .field("install_secret", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for BackgroundSessionRecoveryResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackgroundSessionRecoveryResponse")
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("error_code", &self.error_code)
            .finish()
    }
}

impl fmt::Debug for BackgroundCredentialRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackgroundCredentialRequest")
            .field("api_version", &self.api_version)
            .field("expected_revision", &self.expected_revision)
            .field("device_id", &self.device_id)
            .field("panel_base", &self.panel_base)
            .field("token", &"<redacted>")
            .field("expires_at_unix", &self.expires_at_unix)
            .field("install_secret", &"<redacted>")
            .field("capability_revision", &self.capability_revision)
            .field("capability_enabled", &self.capability_enabled)
            .field("capability_expires_at", &self.capability_expires_at)
            .finish()
    }
}

impl fmt::Debug for BackgroundUiProvisionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackgroundUiProvisionRequest")
            .field("api_version", &self.api_version)
            .field("expected_revision", &self.expected_revision)
            .field("device_id", &self.device_id)
            .field("panel_base", &self.panel_base)
            .field("access_token", &"<redacted>")
            .field("install_secret", &"<redacted>")
            .field("capability_revision", &self.capability_revision)
            .field("capability_enabled", &self.capability_enabled)
            .field("capability_expires_at", &self.capability_expires_at)
            .finish()
    }
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StopTunnelRequest {
    pub api_version: u16,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelStatusRequest {
    pub api_version: u16,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelMetricsRequest {
    pub api_version: u16,
    pub probe: bool,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelMetricsResponse {
    pub received_bytes: u64,
    pub sent_bytes: u64,
    pub latest_handshake_epoch_millis: Option<u64>,
    pub probe_target: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelOperationResponse {
    pub state: String,
    pub duration_millis: u64,
    pub error_code: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuickStateChangeResponse {
    pub changed: bool,
    pub revision: u64,
    pub desired_active: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuickStateChangeAcknowledgeRequest {
    pub revision: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_request_redacts_wireguard_configuration() {
        let request = StartTunnelRequest::new(b"PrivateKey = never-log-this");
        let debug = format!("{request:?}");

        assert!(!debug.contains("never-log-this"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn start_request_serializes_bytes_and_versioned_options() {
        let request = StartTunnelRequest::new(b"[Interface]");
        let value = serde_json::to_value(&request).unwrap();

        assert_eq!(value["apiVersion"], TUNNEL_API_VERSION);
        assert_eq!(value["startSource"], "ui");
        assert_eq!(value["configuration"][0], b'[');
        assert_eq!(value["options"]["excludedPackages"], serde_json::json!([]));
        assert_eq!(value["options"]["includedPackages"], serde_json::json!([]));
        assert_eq!(value["options"]["splitTunnelRoutes"], serde_json::json!([]));
        assert_eq!(value["options"]["excludeLocalNetworks"], false);
        assert_eq!(value["options"]["splitActive"], false);
        assert_eq!(value["options"]["policyHash"], serde_json::Value::Null);
        assert_eq!(value["options"]["applicationMode"], serde_json::Value::Null);
        assert_eq!(value["cacheQuickAction"], false);
        assert_eq!(value["quickActionValidUntilUnix"], serde_json::Value::Null);
        assert!(value.get("redundancy").is_none());
    }

    #[test]
    fn start_request_serializes_both_redundant_members_and_redacts_configs() {
        let mut request = StartTunnelRequest::new(b"primary-never-log-this");
        request.redundancy = Some(RedundantStartRequest {
            session_id: "session-1".to_string(),
            operation_id: "operation-1".to_string(),
            request_fingerprint: "f".repeat(64),
            reserve_enabled: true,
            virtual_address_v4: "10.200.0.2/32".to_string(),
            standby_desired: true,
            active_lease_id: "lease-a".to_string(),
            local_active_lease_id: "lease-a".to_string(),
            role_generation: 0,
            membership_generation: 0,
            primary: RedundantMemberRequest {
                slot: "A".to_string(),
                lease_id: "lease-a".to_string(),
                health_probe: Some(RedundantHealthProbeRequest {
                    kind: "dns_a".to_string(),
                    target_ipv4: "8.8.8.8".to_string(),
                    query_name: "nelomai.ru".to_string(),
                    timeout_ms: 4000,
                }),
            },
            standby: Some(RedundantStandbyRequest::new(
                RedundantMemberRequest {
                    slot: "B".to_string(),
                    lease_id: "lease-b".to_string(),
                    health_probe: Some(RedundantHealthProbeRequest {
                        kind: "dns_a".to_string(),
                        target_ipv4: "8.8.8.8".to_string(),
                        query_name: "nelomai.ru".to_string(),
                        timeout_ms: 4000,
                    }),
                },
                b"standby-never-log-this",
            )),
        });

        let value = serde_json::to_value(&request).unwrap();
        let debug = format!("{request:?}");

        assert_eq!(value["redundancy"]["primary"]["slot"], "A");
        assert_eq!(value["redundancy"]["reserveEnabled"], true);
        assert_eq!(value["redundancy"]["standby"]["member"]["slot"], "B");
        assert_eq!(value["redundancy"]["standby"]["configuration"][0], b's');
        assert_eq!(
            value["redundancy"]["primary"]["healthProbe"]["targetIpv4"],
            "8.8.8.8"
        );
        assert!(!debug.contains("primary-never-log-this"));
        assert!(!debug.contains("standby-never-log-this"));
    }

    #[test]
    fn start_request_serializes_a_bounded_quick_action_plan() {
        let mut request = StartTunnelRequest::new(b"[Interface]");
        request.cache_quick_action = true;
        request.quick_action_valid_until_unix = Some(1_785_700_000);

        let value = serde_json::to_value(&request).unwrap();

        assert_eq!(value["cacheQuickAction"], true);
        assert_eq!(value["quickActionValidUntilUnix"], 1_785_700_000_i64);
    }

    #[test]
    fn quick_connection_preserves_the_selected_egress_mode() {
        let quick: QuickConnectionRequest = serde_json::from_value(serde_json::json!({
            "leaseId": "lease-ipv6",
            "layer": "tic",
            "ticConnectionMode": "dynamic",
            "routeMode": "via_tak",
            "egressMode": "prefer_ipv6",
            "allowAlternate": true
        }))
        .unwrap();

        let value = serde_json::to_value(quick).unwrap();

        assert_eq!(value["egressMode"], "prefer_ipv6");
    }

    #[test]
    fn start_failure_diagnostics_uses_the_mobile_command_field_name() {
        let value = serde_json::to_value(StartFailureDiagnosticsRequest {
            device_id: "11111111-1111-4111-8111-111111111111".to_string(),
            error_code: "configuration_fetch_failed".to_string(),
        })
        .unwrap();

        assert_eq!(value["deviceId"], "11111111-1111-4111-8111-111111111111");
        assert_eq!(value["errorCode"], "configuration_fetch_failed");
    }

    #[test]
    fn background_credential_is_device_scoped_and_redacts_the_token() {
        let request = BackgroundCredentialRequest {
            api_version: TUNNEL_API_VERSION,
            expected_revision: 3,
            device_id: "11111111-1111-4111-8111-111111111111".to_string(),
            panel_base: "https://nelomai.example".to_string(),
            token: "never-log-this-token".to_string(),
            expires_at_unix: 1_785_700_000,
            install_secret: "never-log-install-secret".to_string(),
            capability_revision: 1,
            capability_enabled: true,
            capability_expires_at: "2026-08-29T12:00:00Z".to_string(),
        };

        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(value["deviceId"], "11111111-1111-4111-8111-111111111111");
        let debug = format!("{request:?}");
        assert!(debug.contains("11111111-1111-4111-8111-111111111111"));
        assert!(!debug.contains("never-log-this-token"));
        assert!(!debug.contains("never-log-install-secret"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn background_credential_status_preserves_the_capability_revision() {
        let status: BackgroundCredentialStatusResponse =
            serde_json::from_value(serde_json::json!({
                "configured": true,
                "credentialRevision": 7,
                "mutationReady": true,
                "mutationPending": false,
                "capabilityRevision": 17,
                "capabilityEnabled": true,
                "capabilityExpiresAtUnix": 1_800_000_000_i64,
                "deviceId": "11111111-1111-4111-8111-111111111111",
                "expiresAtUnix": 1_900_000_000_i64
            }))
            .unwrap();

        assert_eq!(status.capability_revision, 17);
    }

    #[test]
    fn background_logout_ownership_deserializes_both_native_decisions() {
        let native: BackgroundLogoutOwnershipResponse =
            serde_json::from_value(serde_json::json!({ "ownership": "native" })).unwrap();
        let legacy: BackgroundLogoutOwnershipResponse =
            serde_json::from_value(serde_json::json!({ "ownership": "not_owned" })).unwrap();

        assert_eq!(native.ownership, BackgroundLogoutOwnership::Native);
        assert_eq!(legacy.ownership, BackgroundLogoutOwnership::NotOwned);
    }

    #[test]
    fn ui_background_provision_redacts_both_authentication_secrets() {
        let request = BackgroundUiProvisionRequest {
            api_version: TUNNEL_API_VERSION,
            expected_revision: 4,
            device_id: "11111111-1111-4111-8111-111111111111".to_string(),
            panel_base: "https://nelomai.example".to_string(),
            access_token: "never-log-access-token".to_string(),
            install_secret: "never-log-install-secret".to_string(),
            capability_revision: 2,
            capability_enabled: true,
            capability_expires_at: "2026-08-29T12:00:00Z".to_string(),
        };

        let debug = format!("{request:?}");
        assert!(!debug.contains("never-log-access-token"));
        assert!(!debug.contains("never-log-install-secret"));
        assert_eq!(
            serde_json::to_value(&request).unwrap()["accessToken"],
            "never-log-access-token"
        );
    }

    #[test]
    fn background_session_recovery_redacts_every_session_secret() {
        let request = BackgroundSessionRecoveryRequest {
            install_secret: "never-log-install-secret".to_string(),
        };
        let response: BackgroundSessionRecoveryResponse =
            serde_json::from_value(serde_json::json!({
                "accessToken": "never-log-access",
                "refreshToken": "never-log-refresh",
                "errorCode": null
            }))
            .unwrap();

        assert_eq!(
            serde_json::to_value(&request).unwrap()["installSecret"],
            "never-log-install-secret"
        );
        assert!(!format!("{request:?}").contains("never-log-install-secret"));
        let debug = format!("{response:?}");
        assert!(!debug.contains("never-log-access"));
        assert!(!debug.contains("never-log-refresh"));
    }

    #[test]
    fn background_session_recovery_can_return_a_stable_error_without_tokens() {
        let response: BackgroundSessionRecoveryResponse =
            serde_json::from_value(serde_json::json!({"errorCode": "invalid_background_token"}))
                .unwrap();

        assert_eq!(
            response.error_code.as_deref(),
            Some("invalid_background_token")
        );
        assert!(response.access_token.is_none());
        assert!(response.refresh_token.is_none());
    }

    #[test]
    fn connection_intent_ipc_preserves_normalized_template_and_generation() {
        let request = BeginConnectionIntentRequest {
            api_version: TUNNEL_API_VERSION,
            template: ConnectionIntentTemplateRequest {
                device_id: "11111111-1111-4111-8111-111111111111".to_string(),
                account_scope: "11111111-1111-4111-8111-111111111111".to_string(),
                layer: "stray".to_string(),
                tic_connection_mode: "dynamic".to_string(),
                route_mode: "standalone".to_string(),
                egress_mode: "ipv4".to_string(),
                allow_alternate: true,
                sync_binding_preferences: true,
                options: TunnelOptions {
                    split_active: true,
                    policy_hash: Some("policy-7".to_string()),
                    application_mode: Some("exclude_selected".to_string()),
                    excluded_packages: vec!["com.example.chat".to_string()],
                    split_tunnel_routes: vec!["10.0.0.0/8".to_string()],
                    dns_servers: vec!["1.1.1.1".to_string()],
                    ..Default::default()
                },
            },
        };
        let value = serde_json::to_value(request).unwrap();

        assert_eq!(value["apiVersion"], TUNNEL_API_VERSION);
        assert_eq!(value["template"]["layer"], "stray");
        assert_eq!(value["template"]["allowAlternate"], true);
        assert_eq!(value["template"]["syncBindingPreferences"], true);
        assert_eq!(value["template"]["options"]["dnsServers"][0], "1.1.1.1");
        assert_eq!(
            value["template"]["options"]["excludedPackages"][0],
            "com.example.chat"
        );

        let status: ConnectionIntentStatusResponse = serde_json::from_value(serde_json::json!({
            "generation": 9,
            "desiredActive": true,
            "status": "recovering",
            "leasePhase": "start_pending",
            "nextRetryAtUnix": 1_800_000_000_i64,
            "lastErrorCode": "connection_unavailable"
        }))
        .unwrap();
        assert_eq!(status.generation, 9);
        assert_eq!(status.lease_phase.as_deref(), Some("start_pending"));

        let cancel = serde_json::to_value(CancelConnectionIntentRequest { generation: 9 }).unwrap();
        assert_eq!(cancel["generation"], 9);
    }

    #[test]
    fn quick_state_change_preserves_the_desired_active_projection() {
        let stopped: QuickStateChangeResponse = serde_json::from_value(serde_json::json!({
            "changed": true,
            "revision": 11,
            "desiredActive": false
        }))
        .unwrap();
        let unavailable: QuickStateChangeResponse = serde_json::from_value(serde_json::json!({
            "changed": false,
            "revision": 0,
            "desiredActive": null
        }))
        .unwrap();

        assert_eq!(stopped.desired_active, Some(false));
        assert_eq!(unavailable.desired_active, None);
    }

    #[test]
    fn installed_application_inventory_has_no_icons_and_redacts_debug_output() {
        let response = InstalledApplicationsResponse {
            applications: vec![InstalledApplication {
                package_id: "com.example.private".to_string(),
                display_name: "Private application".to_string(),
                system: false,
            }],
        };

        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "applications": [{
                    "packageId": "com.example.private",
                    "displayName": "Private application",
                    "system": false
                }]
            })
        );
        assert!(value["applications"][0].get("icon").is_none());
        let debug = format!("{response:?}");
        assert!(!debug.contains("com.example.private"));
        assert!(!debug.contains("Private application"));
        assert!(debug.contains("applications_count"));
    }
}
