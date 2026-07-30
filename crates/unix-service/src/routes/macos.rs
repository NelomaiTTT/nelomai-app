use super::{OwnedRoute, RouteBackend};
use crate::ServiceError;
use ipnet::Ipv4Net;
use std::net::Ipv4Addr;
use std::process::{Command, Output};

const ROUTE: &str = "/sbin/route";
const IFCONFIG: &str = "/sbin/ifconfig";

#[derive(Clone)]
pub(crate) struct MacosEgress {
    interface: String,
    gateway: String,
}

pub(crate) struct SystemRouteBackend;

impl SystemRouteBackend {
    pub(crate) fn new() -> Result<Self, ServiceError> {
        if !std::path::Path::new(ROUTE).is_file() || !std::path::Path::new(IFCONFIG).is_file() {
            return Err(ServiceError::Backend(
                "route_command_unavailable".to_string(),
            ));
        }
        Ok(Self)
    }
}

impl RouteBackend for SystemRouteBackend {
    type Egress = MacosEgress;

    fn discover_egress(&self) -> Result<Self::Egress, ServiceError> {
        parse_default_route(&run(ROUTE, &["-n", "get", "default"])?.stdout)
            .ok_or_else(|| ServiceError::Backend("physical_egress_unavailable".to_string()))
    }

    fn local_networks(&self, egress: &Self::Egress) -> Result<Vec<Ipv4Net>, ServiceError> {
        Ok(parse_local_networks(
            &run(IFCONFIG, &[&egress.interface])?.stdout,
        ))
    }

    fn owned_route(&self, egress: &Self::Egress, network: Ipv4Net) -> OwnedRoute {
        OwnedRoute {
            destination: network.to_string(),
            interface_identifier: egress.interface.clone(),
            gateway: Some(egress.gateway.clone()),
            metric: None,
        }
    }

    fn add_route(&self, route: &OwnedRoute) -> Result<(), ServiceError> {
        mutate_route("add", route)
    }

    fn remove_route(&self, route: &OwnedRoute) -> Result<(), ServiceError> {
        mutate_route("delete", route)
    }
}

fn mutate_route(action: &str, route: &OwnedRoute) -> Result<(), ServiceError> {
    let gateway = route
        .gateway
        .as_deref()
        .ok_or_else(|| ServiceError::Backend("route_state_invalid".to_string()))?;
    let output = Command::new(ROUTE)
        .args(["-n", action, "-net", &route.destination, gateway])
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .output()
        .map_err(|_| ServiceError::Backend("route_command_failed".to_string()))?;
    if output.status.success()
        || (action == "delete" && String::from_utf8_lossy(&output.stderr).contains("not in table"))
    {
        Ok(())
    } else {
        Err(ServiceError::Backend(format!("route_{action}_failed")))
    }
}

fn run(path: &str, arguments: &[&str]) -> Result<Output, ServiceError> {
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

fn parse_default_route(output: &[u8]) -> Option<MacosEgress> {
    let mut gateway = None;
    let mut interface = None;
    for line in String::from_utf8_lossy(output).lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key.trim() {
            "gateway" => gateway = Some(value.trim().to_string()),
            "interface" => interface = Some(value.trim().to_string()),
            _ => {}
        }
    }
    let interface = interface?;
    if interface == "lo0"
        || interface.starts_with("utun")
        || interface.starts_with("bridge")
        || interface.starts_with("tap")
        || interface.starts_with("tun")
    {
        return None;
    }
    Some(MacosEgress {
        interface,
        gateway: gateway?,
    })
}

fn parse_local_networks(output: &[u8]) -> Vec<Ipv4Net> {
    String::from_utf8_lossy(output)
        .lines()
        .filter_map(|line| {
            let tokens = line.split_whitespace().collect::<Vec<_>>();
            if tokens.first() != Some(&"inet") {
                return None;
            }
            let address = tokens.get(1)?.parse::<Ipv4Addr>().ok()?;
            let mask = value_after(&tokens, "netmask")?;
            let prefix = prefix_from_mask(mask)?;
            Ipv4Net::new(address, prefix)
                .ok()
                .and_then(|network| Ipv4Net::new(network.network(), prefix).ok())
        })
        .collect()
}

fn prefix_from_mask(value: &str) -> Option<u8> {
    let raw = value.strip_prefix("0x")?;
    let mask = u32::from_str_radix(raw, 16).ok()?;
    let prefix = mask.count_ones() as u8;
    let expected = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (mask == expected).then_some(prefix)
}

fn value_after<'a>(tokens: &'a [&str], key: &str) -> Option<&'a str> {
    tokens
        .iter()
        .position(|token| *token == key)
        .and_then(|index| tokens.get(index + 1).copied())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_default_route_and_rejects_tunnels() {
        let route = parse_default_route(
            b"   route to: default\n\
destination: default\n\
       mask: default\n\
    gateway: 192.168.1.1\n\
  interface: en0\n",
        )
        .unwrap();
        assert_eq!(route.interface, "en0");
        assert_eq!(route.gateway, "192.168.1.1");
        assert!(parse_default_route(b"gateway: 10.0.0.1\ninterface: utun3\n").is_none());
    }

    #[test]
    fn parses_ifconfig_network() {
        let routes = parse_local_networks(
            b"\tinet 192.168.1.20 netmask 0xffffff00 broadcast 192.168.1.255\n",
        );
        assert_eq!(routes, vec!["192.168.1.0/24".parse().unwrap()]);
    }
}
