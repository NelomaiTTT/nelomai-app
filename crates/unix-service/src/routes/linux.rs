use super::{OwnedRoute, RouteBackend};
use crate::ServiceError;
use ipnet::Ipv4Net;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const ROUTE_METRIC: u32 = 42_760;

#[derive(Clone)]
pub(crate) struct LinuxEgress {
    interface: String,
    gateway: String,
}

pub(crate) struct SystemRouteBackend {
    ip: PathBuf,
}

impl SystemRouteBackend {
    pub(crate) fn new() -> Result<Self, ServiceError> {
        let ip = ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"]
            .into_iter()
            .map(PathBuf::from)
            .find(|path| path.is_file())
            .ok_or_else(|| ServiceError::Backend("ip_command_unavailable".to_string()))?;
        Ok(Self { ip })
    }
}

impl RouteBackend for SystemRouteBackend {
    type Egress = LinuxEgress;

    fn discover_egress(&self) -> Result<Self::Egress, ServiceError> {
        parse_default_route(&run(&self.ip, &["-4", "route", "show", "default"])?.stdout)
            .ok_or_else(|| ServiceError::Backend("physical_egress_unavailable".to_string()))
    }

    fn local_networks(&self, egress: &Self::Egress) -> Result<Vec<Ipv4Net>, ServiceError> {
        Ok(parse_local_networks(
            &run(
                &self.ip,
                &[
                    "-o",
                    "-4",
                    "addr",
                    "show",
                    "dev",
                    &egress.interface,
                    "scope",
                    "global",
                ],
            )?
            .stdout,
        ))
    }

    fn owned_route(&self, egress: &Self::Egress, network: Ipv4Net) -> OwnedRoute {
        OwnedRoute {
            destination: network.to_string(),
            interface_identifier: egress.interface.clone(),
            gateway: Some(egress.gateway.clone()),
            metric: Some(ROUTE_METRIC),
        }
    }

    fn add_route(&self, route: &OwnedRoute) -> Result<(), ServiceError> {
        mutate_route(&self.ip, "add", route)
    }

    fn remove_route(&self, route: &OwnedRoute) -> Result<(), ServiceError> {
        mutate_route(&self.ip, "del", route)
    }
}

fn mutate_route(ip: &Path, action: &str, route: &OwnedRoute) -> Result<(), ServiceError> {
    let gateway = route
        .gateway
        .as_deref()
        .ok_or_else(|| ServiceError::Backend("route_state_invalid".to_string()))?;
    let metric = route
        .metric
        .ok_or_else(|| ServiceError::Backend("route_state_invalid".to_string()))?
        .to_string();
    let output = Command::new(ip)
        .args([
            "-4",
            "route",
            action,
            &route.destination,
            "via",
            gateway,
            "dev",
            &route.interface_identifier,
            "metric",
            &metric,
            "proto",
            "static",
        ])
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .output()
        .map_err(|_| ServiceError::Backend("route_command_failed".to_string()))?;
    if output.status.success()
        || (action == "del" && String::from_utf8_lossy(&output.stderr).contains("No such process"))
    {
        Ok(())
    } else {
        Err(ServiceError::Backend(format!("route_{action}_failed")))
    }
}

fn run(path: &Path, arguments: &[&str]) -> Result<Output, ServiceError> {
    let output = Command::new(path)
        .args(arguments)
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .output()
        .map_err(|_| ServiceError::Backend("route_command_failed".to_string()))?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(ServiceError::Backend("route_command_failed".to_string()))
    }
}

fn parse_default_route(output: &[u8]) -> Option<LinuxEgress> {
    String::from_utf8_lossy(output)
        .lines()
        .filter_map(|line| {
            let tokens = line.split_whitespace().collect::<Vec<_>>();
            if tokens.first() != Some(&"default") {
                return None;
            }
            let gateway = value_after(&tokens, "via")?;
            let interface = value_after(&tokens, "dev")?;
            if virtual_interface(interface) {
                return None;
            }
            let metric = value_after(&tokens, "metric")
                .and_then(|value| value.parse::<u32>().ok())
                .unwrap_or_default();
            Some((
                metric,
                LinuxEgress {
                    interface: interface.to_string(),
                    gateway: gateway.to_string(),
                },
            ))
        })
        .min_by_key(|(metric, _)| *metric)
        .map(|(_, egress)| egress)
}

fn parse_local_networks(output: &[u8]) -> Vec<Ipv4Net> {
    String::from_utf8_lossy(output)
        .lines()
        .filter_map(|line| {
            let tokens = line.split_whitespace().collect::<Vec<_>>();
            let network = value_after(&tokens, "inet")?.parse::<Ipv4Net>().ok()?;
            Ipv4Net::new(network.network(), network.prefix_len()).ok()
        })
        .collect()
}

fn value_after<'a>(tokens: &'a [&str], key: &str) -> Option<&'a str> {
    tokens
        .iter()
        .position(|token| *token == key)
        .and_then(|index| tokens.get(index + 1).copied())
}

fn virtual_interface(value: &str) -> bool {
    [
        "nlm-wg",
        "wg",
        "tun",
        "tap",
        "veth",
        "docker",
        "br-",
        "tailscale",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix))
        || value == "lo"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lowest_metric_physical_default_route() {
        let output = b"default via 10.0.0.1 dev wg0 metric 1\n\
default via 192.168.1.1 dev enp3s0 proto dhcp src 192.168.1.20 metric 100\n";
        let route = parse_default_route(output).unwrap();
        assert_eq!(route.interface, "enp3s0");
        assert_eq!(route.gateway, "192.168.1.1");
    }

    #[test]
    fn parses_canonical_local_networks() {
        let routes = parse_local_networks(
            b"2: enp3s0    inet 192.168.1.20/24 brd 192.168.1.255 scope global enp3s0\n",
        );
        assert_eq!(routes, vec!["192.168.1.0/24".parse().unwrap()]);
    }
}
