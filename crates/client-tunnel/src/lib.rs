use async_trait::async_trait;
use nelomai_contracts::{EgressMode, Layer, RouteMode, SplitTunnelMode, TicConnectionMode};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use thiserror::Error;
use zeroize::Zeroizing;

mod routes;

pub use routes::{Ipv4RoutePlan, RoutePlanError};

const MAX_PACKAGE_IDS: usize = 512;
const MAX_IPV4_CIDRS: usize = 16_384;
const MAX_POLICY_HASH_LENGTH: usize = 128;

pub struct TunnelConfiguration(Zeroizing<String>);

impl TunnelConfiguration {
    pub fn new(configuration: String) -> Self {
        Self(Zeroizing::new(configuration))
    }

    pub fn expose(&self) -> &str {
        self.0.as_str()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn transport(&self) -> TunnelTransport {
        detect_configuration_transport(self.expose())
    }

    pub fn override_dns(&mut self, servers: &[IpAddr]) -> Result<(), TunnelConfigurationError> {
        if servers.is_empty() {
            return Ok(());
        }

        let newline = if self.0.contains("\r\n") {
            "\r\n"
        } else {
            "\n"
        };
        let trailing_newline = self.0.ends_with('\n');
        let mut output = Vec::new();
        let mut interface_found = false;
        let mut in_interface = false;
        let mut dns_inserted = false;
        let dns = format!(
            "DNS = {}",
            servers
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );

        for raw_line in self.0.lines() {
            let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
            let trimmed = line.trim();
            let section = trimmed
                .strip_prefix('[')
                .and_then(|value| value.strip_suffix(']'));
            if let Some(section) = section {
                if in_interface && !dns_inserted {
                    output.push(dns.clone());
                    dns_inserted = true;
                }
                in_interface = section.eq_ignore_ascii_case("Interface");
                interface_found |= in_interface;
            }
            if in_interface
                && trimmed
                    .split_once('=')
                    .is_some_and(|(key, _)| key.trim().eq_ignore_ascii_case("DNS"))
            {
                continue;
            }
            output.push(line.to_string());
        }
        if in_interface && !dns_inserted {
            output.push(dns);
        }
        if !interface_found {
            return Err(TunnelConfigurationError::MissingInterface);
        }

        let mut updated = output.join(newline);
        if trailing_newline {
            updated.push_str(newline);
        }
        self.0 = Zeroizing::new(updated);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TunnelTransport {
    #[default]
    WireGuard,
    AmneziaWg3,
}

pub fn detect_configuration_transport(configuration: &str) -> TunnelTransport {
    let mut in_interface = false;
    let mut header_protection_key = false;
    let mut content_padding_addition = false;

    for raw_line in configuration.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_interface = line.eq_ignore_ascii_case("[Interface]");
            continue;
        }
        if !in_interface {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if value.trim().is_empty() {
            continue;
        }
        match key.trim().to_ascii_lowercase().as_str() {
            "headerprotectionkey" => header_protection_key = true,
            "contentpaddingaddition" => content_padding_addition = true,
            _ => {}
        }
    }

    if header_protection_key && content_padding_addition {
        TunnelTransport::AmneziaWg3
    } else {
        TunnelTransport::WireGuard
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TunnelConfigurationError {
    #[error("wireguard interface section is missing")]
    MissingInterface,
}

impl fmt::Debug for TunnelConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TunnelConfiguration(<redacted>)")
    }
}

pub struct TunnelStartRequest {
    pub configuration: TunnelConfiguration,
    pub options: TunnelOptions,
    pub quick_reconnect: QuickReconnect,
    pub quick_connection: Option<QuickConnection>,
}

impl TunnelStartRequest {
    pub fn full_tunnel(configuration: TunnelConfiguration) -> Self {
        Self {
            configuration,
            options: TunnelOptions::default(),
            quick_reconnect: QuickReconnect::Disabled,
            quick_connection: None,
        }
    }
}

impl fmt::Debug for TunnelStartRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TunnelStartRequest")
            .field("configuration", &"<redacted>")
            .field("options", &self.options)
            .field("quick_reconnect", &self.quick_reconnect)
            .field("quick_connection", &self.quick_connection)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuickConnection {
    pub lease_id: String,
    pub layer: Layer,
    pub tic_connection_mode: TicConnectionMode,
    pub route_mode: RouteMode,
    pub egress_mode: EgressMode,
    pub allow_alternate: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum QuickReconnect {
    #[default]
    Disabled,
    Persistent,
    Until(i64),
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct TunnelOptions {
    pub application_mode: Option<SplitTunnelMode>,
    pub package_ids: Vec<String>,
    pub excluded_ipv4_cidrs: Vec<String>,
    pub exclude_local_networks: bool,
    pub policy_hash: Option<String>,
    pub dns_servers: Vec<IpAddr>,
}

impl fmt::Debug for TunnelOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TunnelOptions")
            .field("application_mode", &self.application_mode)
            .field("package_ids_count", &self.package_ids.len())
            .field("excluded_ipv4_cidrs_count", &self.excluded_ipv4_cidrs.len())
            .field("exclude_local_networks", &self.exclude_local_networks)
            .field("policy_hash", &self.policy_hash)
            .field("dns_servers_count", &self.dns_servers.len())
            .finish()
    }
}

impl TunnelOptions {
    pub fn has_same_effective_routes(&self, other: &Self) -> bool {
        self.application_mode == other.application_mode
            && self.package_ids == other.package_ids
            && self.excluded_ipv4_cidrs == other.excluded_ipv4_cidrs
            && self.exclude_local_networks == other.exclude_local_networks
    }

    pub fn validate(&self) -> Result<(), TunnelOptionsError> {
        if self.package_ids.len() > MAX_PACKAGE_IDS {
            return Err(TunnelOptionsError::new(
                "split_tunnel_selected_packages_limit",
            ));
        }
        if self.excluded_ipv4_cidrs.len() > MAX_IPV4_CIDRS {
            return Err(TunnelOptionsError::new("split_tunnel_cidrs_limit"));
        }
        if self.application_mode.is_none() && !self.package_ids.is_empty() {
            return Err(TunnelOptionsError::new(
                "split_tunnel_application_mode_missing",
            ));
        }
        if self
            .package_ids
            .iter()
            .any(|value| !valid_package_id(value))
        {
            return Err(TunnelOptionsError::new("split_tunnel_invalid_package_id"));
        }
        if self
            .package_ids
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            != self.package_ids.len()
        {
            return Err(TunnelOptionsError::new("split_tunnel_duplicate_package_id"));
        }
        if self
            .excluded_ipv4_cidrs
            .iter()
            .any(|value| !valid_ipv4_cidr(value))
        {
            return Err(TunnelOptionsError::new("split_tunnel_invalid_ipv4_cidr"));
        }
        Ok(())
    }
}

#[derive(Clone, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopTunnelOptions {
    pub excluded_ipv4_cidrs: Vec<String>,
    pub exclude_local_networks: bool,
    pub policy_hash: Option<String>,
}

impl DesktopTunnelOptions {
    pub fn from_tunnel_options(options: &TunnelOptions) -> Self {
        if options.policy_hash.is_none() {
            return Self::default();
        }
        Self {
            excluded_ipv4_cidrs: options.excluded_ipv4_cidrs.clone(),
            exclude_local_networks: options.exclude_local_networks,
            policy_hash: options.policy_hash.clone(),
        }
    }

    pub fn validate(&self) -> Result<(), TunnelOptionsError> {
        if self.excluded_ipv4_cidrs.len() > MAX_IPV4_CIDRS {
            return Err(TunnelOptionsError::new("split_tunnel_cidrs_limit"));
        }
        if self.policy_hash.is_none()
            && (self.exclude_local_networks || !self.excluded_ipv4_cidrs.is_empty())
        {
            return Err(TunnelOptionsError::new("split_tunnel_inactive_options"));
        }
        if self.policy_hash.as_ref().is_some_and(|value| {
            value.is_empty() || value.len() > MAX_POLICY_HASH_LENGTH || !value.is_ascii()
        }) {
            return Err(TunnelOptionsError::new("split_tunnel_invalid_policy_hash"));
        }
        let mut normalized = std::collections::HashSet::new();
        for value in &self.excluded_ipv4_cidrs {
            let network = value
                .parse::<ipnet::Ipv4Net>()
                .map_err(|_| TunnelOptionsError::new("split_tunnel_invalid_ipv4_cidr"))?;
            if network.addr() != network.network() || network.to_string() != *value {
                return Err(TunnelOptionsError::new(
                    "split_tunnel_noncanonical_ipv4_cidr",
                ));
            }
            if !normalized.insert(network) {
                return Err(TunnelOptionsError::new("split_tunnel_duplicate_ipv4_cidr"));
            }
        }
        Ok(())
    }
}

impl fmt::Debug for DesktopTunnelOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DesktopTunnelOptions")
            .field("excluded_ipv4_cidrs_count", &self.excluded_ipv4_cidrs.len())
            .field("exclude_local_networks", &self.exclude_local_networks)
            .field("policy_hash_present", &self.policy_hash.is_some())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("{code}")]
pub struct TunnelOptionsError {
    code: &'static str,
}

impl TunnelOptionsError {
    fn new(code: &'static str) -> Self {
        Self { code }
    }

    pub fn stable_code(self) -> &'static str {
        self.code
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TunnelPlatform {
    Android,
    Windows,
    Linux,
    Macos,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TunnelCapabilities {
    pub platform: TunnelPlatform,
    pub android_api_level: Option<u32>,
    pub address_split_tunnel: bool,
    pub application_split_tunnel: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TunnelStatus {
    #[default]
    Stopped,
    Starting,
    Running,
    Stopping,
    Failed,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelMetrics {
    pub received_bytes: u64,
    pub sent_bytes: u64,
    #[serde(default)]
    pub latest_handshake_epoch_millis: Option<u64>,
    pub probe_target: Option<String>,
}

#[derive(Debug, Error)]
pub enum TunnelError {
    #[error("tunnel backend rejected the operation: {0}")]
    Backend(String),
    #[error("tunnel options are invalid: {code}")]
    InvalidOptions { code: &'static str },
}

#[async_trait]
pub trait TunnelController: Send + Sync {
    async fn start(&self, request: TunnelStartRequest) -> Result<(), TunnelError>;
    async fn stop(&self) -> Result<(), TunnelError>;
    /// Rebind the client UDP socket without replacing the panel lease.
    ///
    /// Returns `true` when the active backend performed a rebind and `false`
    /// when the platform does not support the operation.
    async fn rebind_udp(&self) -> Result<bool, TunnelError> {
        Ok(false)
    }
    async fn status(&self) -> Result<TunnelStatus, TunnelError>;
    async fn metrics(&self, _probe: bool) -> Result<Option<TunnelMetrics>, TunnelError> {
        Ok(None)
    }
    async fn physical_network_fingerprint(&self) -> Result<Option<String>, TunnelError> {
        Ok(None)
    }
    async fn capabilities(&self) -> Result<TunnelCapabilities, TunnelError> {
        Ok(TunnelCapabilities::default())
    }
}

fn valid_package_id(value: &str) -> bool {
    if value.is_empty() || value.len() > 255 {
        return false;
    }
    let mut segments = value.split('.');
    let Some(first) = segments.next() else {
        return false;
    };
    let Some(second) = segments.next() else {
        return false;
    };
    let valid_segment = |segment: &str| {
        !segment.is_empty()
            && segment
                .bytes()
                .all(|character| character.is_ascii_alphanumeric() || character == b'_')
    };
    first
        .bytes()
        .next()
        .is_some_and(|character| character.is_ascii_alphabetic())
        && valid_segment(first)
        && valid_segment(second)
        && segments.all(valid_segment)
}

fn valid_ipv4_cidr(value: &str) -> bool {
    let Some((address, prefix)) = value.split_once('/') else {
        return false;
    };
    address.parse::<Ipv4Addr>().is_ok()
        && prefix
            .parse::<u8>()
            .is_ok_and(|prefix_length| prefix_length <= 32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_debug_never_contains_wireguard_material() {
        let configuration =
            TunnelConfiguration::new("[Interface]\nPrivateKey = never-log-this\n".to_string());
        let debug = format!("{configuration:?}");
        assert!(!debug.contains("never-log-this"));
        assert_eq!(debug, "TunnelConfiguration(<redacted>)");
    }

    #[test]
    fn configuration_can_be_consumed_once_by_a_tunnel_backend() {
        let configuration = TunnelConfiguration::new("config".to_string());
        assert_eq!(configuration.expose(), "config");
    }

    #[test]
    fn configuration_transport_requires_both_awg3_markers_in_interface() {
        let awg3 = TunnelConfiguration::new(
            "[Interface]\nHeaderProtectionKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nContentPaddingAddition = 0-64\n\n[Peer]\nPublicKey = peer\n"
                .to_string(),
        );
        assert_eq!(awg3.transport(), TunnelTransport::AmneziaWg3);

        assert_eq!(
            detect_configuration_transport(
                "[Interface]\nHeaderProtectionKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
            ),
            TunnelTransport::WireGuard
        );
        assert_eq!(
            detect_configuration_transport(
                "[Interface]\nPrivateKey = secret\n[Peer]\nHeaderProtectionKey = value\nContentPaddingAddition = 0-64\n"
            ),
            TunnelTransport::WireGuard
        );
    }

    #[test]
    fn configuration_dns_override_replaces_interface_dns_only() {
        let mut configuration = TunnelConfiguration::new(
            "[Interface]\r\nPrivateKey = secret\r\nDNS = 1.1.1.1\r\n\r\n[Peer]\r\n# DNS = peer-comment\r\nPublicKey = peer\r\n"
                .to_string(),
        );

        configuration
            .override_dns(&[
                "9.9.9.9".parse().unwrap(),
                "149.112.112.112".parse().unwrap(),
            ])
            .unwrap();

        assert_eq!(
            configuration.expose(),
            "[Interface]\r\nPrivateKey = secret\r\n\r\nDNS = 9.9.9.9, 149.112.112.112\r\n[Peer]\r\n# DNS = peer-comment\r\nPublicKey = peer\r\n"
        );
    }

    #[test]
    fn configuration_dns_override_requires_interface() {
        let mut configuration = TunnelConfiguration::new("[Peer]\nPublicKey = peer\n".to_string());
        assert_eq!(
            configuration.override_dns(&["8.8.8.8".parse().unwrap()]),
            Err(TunnelConfigurationError::MissingInterface)
        );
    }

    #[test]
    fn tunnel_start_request_debug_redacts_configuration_packages_and_cidrs() {
        let request = TunnelStartRequest {
            configuration: TunnelConfiguration::new(
                "[Interface]\nPrivateKey = never-log-this\n".to_string(),
            ),
            options: TunnelOptions {
                application_mode: Some(SplitTunnelMode::ExcludeSelected),
                package_ids: vec!["com.example.secret".to_string()],
                excluded_ipv4_cidrs: vec!["203.0.113.0/24".to_string()],
                exclude_local_networks: true,
                policy_hash: Some("sha256:test".to_string()),
                dns_servers: vec!["8.8.8.8".parse().unwrap()],
            },
            quick_reconnect: QuickReconnect::Persistent,
            quick_connection: None,
        };

        let debug = format!("{request:?}");
        assert!(!debug.contains("never-log-this"));
        assert!(!debug.contains("com.example.secret"));
        assert!(!debug.contains("203.0.113.0/24"));
        assert!(debug.contains("package_ids_count"));
    }

    #[test]
    fn tunnel_options_validate_packages_and_ipv4_cidrs() {
        let valid = TunnelOptions {
            application_mode: Some(SplitTunnelMode::ExcludeSelected),
            package_ids: vec!["com.example.app_1".to_string()],
            excluded_ipv4_cidrs: vec!["203.0.113.0/24".to_string()],
            exclude_local_networks: true,
            policy_hash: Some("sha256:test".to_string()),
            dns_servers: vec!["8.8.8.8".parse().unwrap()],
        };
        assert!(valid.validate().is_ok());

        let invalid_package = TunnelOptions {
            package_ids: vec!["com.example.bad package".to_string()],
            ..valid.clone()
        };
        assert_eq!(
            invalid_package.validate().unwrap_err().stable_code(),
            "split_tunnel_invalid_package_id"
        );

        let invalid_cidr = TunnelOptions {
            excluded_ipv4_cidrs: vec!["2001:db8::/32".to_string()],
            ..valid
        };
        assert_eq!(
            invalid_cidr.validate().unwrap_err().stable_code(),
            "split_tunnel_invalid_ipv4_cidr"
        );
    }

    #[test]
    fn policy_hash_does_not_change_effective_routes() {
        let first = TunnelOptions {
            application_mode: Some(SplitTunnelMode::ExcludeSelected),
            package_ids: vec!["com.example.app".to_string()],
            excluded_ipv4_cidrs: vec!["203.0.113.0/24".to_string()],
            exclude_local_networks: true,
            policy_hash: Some("sha256:first".to_string()),
            dns_servers: vec!["8.8.8.8".parse().unwrap()],
        };
        let second = TunnelOptions {
            policy_hash: Some("sha256:second".to_string()),
            ..first.clone()
        };
        let changed_route = TunnelOptions {
            excluded_ipv4_cidrs: vec!["198.51.100.0/24".to_string()],
            ..second.clone()
        };

        assert!(first.has_same_effective_routes(&second));
        assert!(!first.has_same_effective_routes(&changed_route));
    }

    #[test]
    fn desktop_options_are_redacted_and_require_canonical_unique_cidrs() {
        let options = DesktopTunnelOptions {
            excluded_ipv4_cidrs: vec!["203.0.113.0/24".to_string()],
            exclude_local_networks: true,
            policy_hash: Some("sha256:secret-policy".to_string()),
        };
        assert!(options.validate().is_ok());
        let debug = format!("{options:?}");
        assert!(!debug.contains("203.0.113.0"));
        assert!(!debug.contains("secret-policy"));

        let noncanonical = DesktopTunnelOptions {
            excluded_ipv4_cidrs: vec!["203.0.113.1/24".to_string()],
            ..options.clone()
        };
        assert_eq!(
            noncanonical.validate().unwrap_err().stable_code(),
            "split_tunnel_noncanonical_ipv4_cidr"
        );

        let duplicate = DesktopTunnelOptions {
            excluded_ipv4_cidrs: vec!["203.0.113.0/24".to_string(), "203.0.113.0/24".to_string()],
            ..options
        };
        assert_eq!(
            duplicate.validate().unwrap_err().stable_code(),
            "split_tunnel_duplicate_ipv4_cidr"
        );
    }
}
