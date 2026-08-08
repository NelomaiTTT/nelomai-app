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

#[derive(Clone, Default, Deserialize, Serialize)]
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

pub struct StartTunnelRequest {
    pub api_version: u16,
    pub start_source: String,
    pub configuration: Zeroizing<Vec<u8>>,
    pub options: TunnelOptions,
    pub cache_quick_action: bool,
    pub quick_action_valid_until_unix: Option<i64>,
    pub quick_connection: Option<QuickConnectionRequest>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct QuickConnectionRequest {
    pub lease_id: String,
    pub layer: String,
    pub tic_connection_mode: String,
    pub route_mode: String,
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
        }

        WireRequest {
            api_version: self.api_version,
            start_source: &self.start_source,
            configuration: self.configuration.as_slice(),
            options: &self.options,
            cache_quick_action: self.cache_quick_action,
            quick_action_valid_until_unix: self.quick_action_valid_until_unix,
            quick_connection: &self.quick_connection,
        }
        .serialize(serializer)
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackgroundCredentialRequest {
    pub api_version: u16,
    pub device_id: String,
    pub panel_base: String,
    pub token: String,
    pub expires_at_unix: i64,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BackgroundCredentialStatusResponse {
    pub configured: bool,
    pub device_id: Option<String>,
    pub expires_at_unix: Option<i64>,
}

impl fmt::Debug for BackgroundCredentialRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackgroundCredentialRequest")
            .field("api_version", &self.api_version)
            .field("device_id", &self.device_id)
            .field("panel_base", &self.panel_base)
            .field("token", &"<redacted>")
            .field("expires_at_unix", &self.expires_at_unix)
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
            device_id: "11111111-1111-4111-8111-111111111111".to_string(),
            panel_base: "https://nelomai.example".to_string(),
            token: "never-log-this-token".to_string(),
            expires_at_unix: 1_785_700_000,
        };

        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(value["deviceId"], "11111111-1111-4111-8111-111111111111");
        let debug = format!("{request:?}");
        assert!(debug.contains("11111111-1111-4111-8111-111111111111"));
        assert!(!debug.contains("never-log-this-token"));
        assert!(debug.contains("<redacted>"));
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
