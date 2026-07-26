use async_trait::async_trait;
use std::fmt;
use thiserror::Error;
use zeroize::Zeroizing;

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
}

#[async_trait]
pub trait TunnelController: Send + Sync {
    async fn start(&self, configuration: TunnelConfiguration) -> Result<(), TunnelError>;
    async fn stop(&self) -> Result<(), TunnelError>;
    async fn status(&self) -> Result<TunnelStatus, TunnelError>;
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
}
