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

pub const TUNNEL_API_VERSION: u16 = 1;

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelOptions {
    pub excluded_packages: Vec<String>,
    pub included_packages: Vec<String>,
    pub split_tunnel_routes: Vec<String>,
    pub exclude_local_networks: bool,
}

impl fmt::Debug for TunnelOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TunnelOptions")
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

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelOperationResponse {
    pub state: String,
    pub duration_millis: u64,
    pub error_code: Option<String>,
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
    }
}
