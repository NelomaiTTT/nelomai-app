use crate::DesktopTunnelOptions;
use ipnet::Ipv4Net;
use std::fmt;
use thiserror::Error;

const MAX_ROUTES: usize = 16_384;

#[derive(Clone, PartialEq, Eq)]
pub struct Ipv4RoutePlan {
    pub policy_hash: Option<String>,
    pub excluded_networks: Vec<Ipv4Net>,
    pub exclude_local_networks: bool,
}

impl Ipv4RoutePlan {
    pub fn from_options(options: &DesktopTunnelOptions) -> Result<Self, RoutePlanError> {
        options
            .validate()
            .map_err(|error| RoutePlanError::InvalidOptions(error.stable_code()))?;
        let networks = options
            .excluded_ipv4_cidrs
            .iter()
            .map(|value| {
                value
                    .parse::<Ipv4Net>()
                    .map_err(|_| RoutePlanError::InvalidNetwork)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            policy_hash: options.policy_hash.clone(),
            excluded_networks: compact(networks)?,
            exclude_local_networks: options.exclude_local_networks,
        })
    }

    pub fn active(&self) -> bool {
        self.policy_hash.is_some()
    }
}

impl fmt::Debug for Ipv4RoutePlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ipv4RoutePlan")
            .field("policy_hash_present", &self.policy_hash.is_some())
            .field("excluded_networks_count", &self.excluded_networks.len())
            .field("exclude_local_networks", &self.exclude_local_networks)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RoutePlanError {
    #[error("invalid desktop tunnel options: {0}")]
    InvalidOptions(&'static str),
    #[error("invalid IPv4 route")]
    InvalidNetwork,
    #[error("route plan is too large")]
    TooLarge,
}

impl RoutePlanError {
    pub fn stable_code(self) -> &'static str {
        match self {
            Self::InvalidOptions(code) => code,
            Self::InvalidNetwork => "split_tunnel_invalid_ipv4_cidr",
            Self::TooLarge => "route_plan_too_large",
        }
    }
}

fn compact(mut networks: Vec<Ipv4Net>) -> Result<Vec<Ipv4Net>, RoutePlanError> {
    if networks.len() > MAX_ROUTES {
        return Err(RoutePlanError::TooLarge);
    }
    networks.sort_unstable();
    networks.dedup();
    let networks = Ipv4Net::aggregate(&networks);
    if networks.len() > MAX_ROUTES {
        return Err(RoutePlanError::TooLarge);
    }
    Ok(networks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_plan_compacts_covered_and_adjacent_networks() {
        let plan = Ipv4RoutePlan::from_options(&DesktopTunnelOptions {
            excluded_ipv4_cidrs: vec![
                "10.0.0.0/9".to_string(),
                "10.128.0.0/9".to_string(),
                "10.1.0.0/16".to_string(),
                "203.0.113.0/24".to_string(),
            ],
            exclude_local_networks: true,
            policy_hash: Some("sha256:test".to_string()),
        })
        .unwrap();

        assert_eq!(
            plan.excluded_networks,
            vec![
                "10.0.0.0/8".parse().unwrap(),
                "203.0.113.0/24".parse().unwrap()
            ]
        );
    }

    #[test]
    fn inactive_options_produce_no_complement() {
        let plan = Ipv4RoutePlan::from_options(&DesktopTunnelOptions::default()).unwrap();
        assert!(!plan.active());
        assert!(plan.excluded_networks.is_empty());
    }
}
