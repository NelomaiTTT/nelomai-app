use async_trait::async_trait;
use nelomai_contracts::SplitTunnelMode;
use std::fmt;
use std::net::Ipv4Addr;
use thiserror::Error;
use zeroize::Zeroizing;

const MAX_PACKAGE_IDS: usize = 512;
const MAX_IPV4_CIDRS: usize = 16_384;

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
}

impl fmt::Debug for TunnelConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TunnelConfiguration(<redacted>)")
    }
}

pub struct TunnelStartRequest {
    pub configuration: TunnelConfiguration,
    pub options: TunnelOptions,
}

impl TunnelStartRequest {
    pub fn full_tunnel(configuration: TunnelConfiguration) -> Self {
        Self {
            configuration,
            options: TunnelOptions::default(),
        }
    }
}

impl fmt::Debug for TunnelStartRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TunnelStartRequest")
            .field("configuration", &"<redacted>")
            .field("options", &self.options)
            .finish()
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct TunnelOptions {
    pub application_mode: Option<SplitTunnelMode>,
    pub package_ids: Vec<String>,
    pub excluded_ipv4_cidrs: Vec<String>,
    pub exclude_local_networks: bool,
    pub policy_hash: Option<String>,
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
            .finish()
    }
}

impl TunnelOptions {
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
            .excluded_ipv4_cidrs
            .iter()
            .any(|value| !valid_ipv4_cidr(value))
        {
            return Err(TunnelOptionsError::new("split_tunnel_invalid_ipv4_cidr"));
        }
        Ok(())
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
    async fn status(&self) -> Result<TunnelStatus, TunnelError>;
    async fn capabilities(&self) -> Result<TunnelCapabilities, TunnelError> {
        Ok(TunnelCapabilities::default())
    }
}

fn valid_package_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !value.starts_with('.')
        && !value.ends_with('.')
        && !value.contains("..")
        && value.bytes().all(|character| {
            character.is_ascii_alphanumeric() || character == b'_' || character == b'.'
        })
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
            },
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
}
