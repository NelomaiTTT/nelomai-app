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
    pub excluded_packages: Vec<String>,
    pub included_packages: Vec<String>,
    pub split_tunnel_routes: Vec<String>,
    pub exclude_local_networks: bool,
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
            .finish()
    }
}

pub struct StartTunnelRequest {
    pub api_version: u16,
    pub configuration: Zeroizing<Vec<u8>>,
    pub options: TunnelOptions,
}

impl StartTunnelRequest {
    pub fn new(configuration: &[u8]) -> Self {
        Self {
            api_version: TUNNEL_API_VERSION,
            configuration: Zeroizing::new(configuration.to_vec()),
            options: TunnelOptions::default(),
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
            configuration: &'a [u8],
            options: &'a TunnelOptions,
        }

        WireRequest {
            api_version: self.api_version,
            configuration: self.configuration.as_slice(),
            options: &self.options,
        }
        .serialize(serializer)
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
pub struct QuickActionResponse {
    pub pending: bool,
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
        assert_eq!(value["configuration"][0], b'[');
        assert_eq!(value["options"]["excludedPackages"], serde_json::json!([]));
        assert_eq!(value["options"]["includedPackages"], serde_json::json!([]));
        assert_eq!(value["options"]["splitTunnelRoutes"], serde_json::json!([]));
        assert_eq!(value["options"]["excludeLocalNetworks"], false);
        assert_eq!(value["options"]["splitActive"], false);
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
