use super::{OwnedRoute, RouteBackend};
use crate::process::{output_with_timeout, COMMAND_TIMEOUT};
use crate::ServiceError;
use ipnet::Ipv4Net;
use std::net::Ipv4Addr;
use std::process::{Command, Output};

const ROUTE: &str = "/sbin/route";
const IFCONFIG: &str = "/sbin/ifconfig";
const NETSTAT: &str = "/usr/sbin/netstat";

#[derive(Clone)]
pub(crate) struct MacosEgress {
    interface: String,
    gateway: String,
    source: Option<Ipv4Addr>,
}

pub(crate) struct SystemRouteBackend;

impl SystemRouteBackend {
    pub(crate) fn new() -> Result<Self, ServiceError> {
        if !std::path::Path::new(ROUTE).is_file()
            || !std::path::Path::new(IFCONFIG).is_file()
            || !std::path::Path::new(NETSTAT).is_file()
        {
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
        let mut egress =
            parse_physical_default_route(&run(NETSTAT, &["-rn", "-f", "inet"])?.stdout)
                .or_else(|| {
                    run(ROUTE, &["-n", "get", "default"])
                        .ok()
                        .and_then(|output| parse_default_route(&output.stdout))
                })
                .ok_or_else(|| ServiceError::Backend("physical_egress_unavailable".to_string()))?;
        egress.source = parse_source_address(&run(IFCONFIG, &[&egress.interface])?.stdout);
        Ok(egress)
    }

    fn local_networks(&self, egress: &Self::Egress) -> Result<Vec<Ipv4Net>, ServiceError> {
        Ok(parse_local_networks(
            &run(IFCONFIG, &[&egress.interface])?.stdout,
        ))
    }

    fn fingerprint_material(&self, egress: &Self::Egress, local_networks: &[Ipv4Net]) -> String {
        let networks = local_networks
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "macos\0{}\0{}\0{}\0{}",
            egress.interface,
            egress.gateway,
            egress
                .source
                .map(|value| value.to_string())
                .unwrap_or_default(),
            networks
        )
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

    fn route_exists(&self, route: &OwnedRoute) -> Result<bool, ServiceError> {
        let output = output_with_timeout(
            Command::new(ROUTE)
                .args(["-n", "get", "-net", &route.destination])
                .env("LANG", "C")
                .env("LC_ALL", "C"),
            COMMAND_TIMEOUT,
        )
        .map_err(|_| ServiceError::Backend("route_command_failed".to_string()))?;
        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            return if error.contains("not in table") || error.contains("not found") {
                Ok(false)
            } else {
                Err(ServiceError::Backend("route_command_failed".to_string()))
            };
        }
        route_lookup_matches(&output.stdout, route)
    }

    fn route_presence(&self, routes: &[OwnedRoute]) -> Result<Vec<bool>, ServiceError> {
        let output = run(NETSTAT, &["-rn", "-f", "inet"])?;
        route_table_presence(&output.stdout, routes)
    }

    fn remove_route(&self, route: &OwnedRoute) -> Result<(), ServiceError> {
        mutate_route("delete", route)
    }
}

fn route_table_presence(output: &[u8], routes: &[OwnedRoute]) -> Result<Vec<bool>, ServiceError> {
    let output = String::from_utf8_lossy(output);
    let table = output
        .lines()
        .filter_map(|line| {
            let tokens = line.split_whitespace().collect::<Vec<_>>();
            let destination = parse_netstat_destination(tokens.first().copied()?)?;
            let gateway = tokens.get(1)?.parse::<Ipv4Addr>().ok()?;
            let interface = tokens.get(3)?.to_string();
            Some((destination, gateway, interface))
        })
        .collect::<Vec<_>>();
    routes
        .iter()
        .map(|route| {
            let destination = canonical_destination(route)?;
            let gateway = route
                .gateway
                .as_deref()
                .and_then(|value| value.parse::<Ipv4Addr>().ok())
                .ok_or_else(|| ServiceError::Backend("route_state_invalid".to_string()))?;
            Ok(table
                .iter()
                .any(|(actual_destination, actual_gateway, actual_interface)| {
                    *actual_destination == destination
                        && *actual_gateway == gateway
                        && actual_interface == &route.interface_identifier
                }))
        })
        .collect()
}

fn canonical_destination(route: &OwnedRoute) -> Result<Ipv4Net, ServiceError> {
    route
        .destination
        .parse::<Ipv4Net>()
        .ok()
        .filter(|network| network.to_string() == route.destination)
        .ok_or_else(|| ServiceError::Backend("route_state_invalid".to_string()))
}

fn parse_netstat_destination(value: &str) -> Option<Ipv4Net> {
    if value == "default" {
        return "0.0.0.0/0".parse().ok();
    }
    let (address, explicit_prefix) = match value.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix.parse::<u8>().ok()?)),
        None => (value, None),
    };
    let octets = address
        .split('.')
        .map(str::parse::<u8>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    if octets.is_empty() || octets.len() > 4 {
        return None;
    }
    let prefix = explicit_prefix.unwrap_or((octets.len() as u8) * 8);
    if prefix > 32 {
        return None;
    }
    let mut padded = [0_u8; 4];
    padded[..octets.len()].copy_from_slice(&octets);
    let network = Ipv4Net::new(Ipv4Addr::from(padded), prefix).ok()?;
    Ipv4Net::new(network.network(), prefix).ok()
}

fn route_lookup_matches(output: &[u8], route: &OwnedRoute) -> Result<bool, ServiceError> {
    let expected = canonical_destination(route)?;
    let gateway = route
        .gateway
        .as_deref()
        .ok_or_else(|| ServiceError::Backend("route_state_invalid".to_string()))?;
    let mut destination = None;
    let mut mask = None;
    let mut actual_gateway = None;
    let mut interface = None;
    for line in String::from_utf8_lossy(output).lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key.trim() {
            "destination" => destination = value.trim().parse::<Ipv4Addr>().ok(),
            "mask" => mask = parse_ipv4_mask(value.trim()),
            "gateway" => actual_gateway = Some(value.trim().to_string()),
            "interface" => interface = Some(value.trim().to_string()),
            _ => {}
        }
    }
    Ok(destination == Some(expected.network())
        && mask == Some(expected.prefix_len())
        && actual_gateway.as_deref() == Some(gateway)
        && interface.as_deref() == Some(route.interface_identifier.as_str()))
}

fn parse_ipv4_mask(value: &str) -> Option<u8> {
    let mask = if let Some(hex) = value.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).ok()?
    } else {
        u32::from_be_bytes(value.parse::<Ipv4Addr>().ok()?.octets())
    };
    let prefix = mask.count_ones() as u8;
    (mask
        == if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        })
    .then_some(prefix)
}

fn mutate_route(action: &str, route: &OwnedRoute) -> Result<(), ServiceError> {
    let gateway = route
        .gateway
        .as_deref()
        .ok_or_else(|| ServiceError::Backend("route_state_invalid".to_string()))?;
    let output = output_with_timeout(
        Command::new(ROUTE)
            .args(route_arguments(action, route, gateway))
            .env("LANG", "C")
            .env("LC_ALL", "C"),
        COMMAND_TIMEOUT,
    )
    .map_err(|_| ServiceError::Backend("route_command_failed".to_string()))?;
    if output.status.success()
        || (action == "delete" && String::from_utf8_lossy(&output.stderr).contains("not in table"))
    {
        Ok(())
    } else {
        Err(ServiceError::Backend(format!("route_{action}_failed")))
    }
}

fn route_arguments<'a>(action: &'a str, route: &'a OwnedRoute, gateway: &'a str) -> [&'a str; 7] {
    [
        "-n",
        action,
        "-net",
        "-ifscope",
        &route.interface_identifier,
        &route.destination,
        gateway,
    ]
}

fn run(path: &str, arguments: &[&str]) -> Result<Output, ServiceError> {
    let output = output_with_timeout(
        Command::new(path)
            .args(arguments)
            .env("LANG", "C")
            .env("LC_ALL", "C"),
        COMMAND_TIMEOUT,
    )
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
    if !physical_interface(&interface) {
        return None;
    }
    Some(MacosEgress {
        interface,
        gateway: gateway?,
        source: None,
    })
}

fn parse_physical_default_route(output: &[u8]) -> Option<MacosEgress> {
    String::from_utf8_lossy(output).lines().find_map(|line| {
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        if tokens.first() != Some(&"default") {
            return None;
        }
        let gateway = tokens.get(1)?.parse::<Ipv4Addr>().ok()?;
        let interface = tokens.get(3)?.to_string();
        if !physical_interface(&interface) {
            return None;
        }
        Some(MacosEgress {
            interface,
            gateway: gateway.to_string(),
            source: None,
        })
    })
}

fn physical_interface(interface: &str) -> bool {
    interface != "lo0"
        && !interface.starts_with("utun")
        && !interface.starts_with("bridge")
        && !interface.starts_with("tap")
        && !interface.starts_with("tun")
}

fn parse_source_address(output: &[u8]) -> Option<Ipv4Addr> {
    String::from_utf8_lossy(output).lines().find_map(|line| {
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        (tokens.first() == Some(&"inet"))
            .then(|| tokens.get(1)?.parse::<Ipv4Addr>().ok())
            .flatten()
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
        assert_eq!(route.source, None);
        assert!(parse_default_route(b"gateway: 10.0.0.1\ninterface: utun3\n").is_none());
    }

    #[test]
    fn parses_ifconfig_network() {
        let routes = parse_local_networks(
            b"\tinet 192.168.1.20 netmask 0xffffff00 broadcast 192.168.1.255\n",
        );
        assert_eq!(routes, vec!["192.168.1.0/24".parse().unwrap()]);
        assert_eq!(
            parse_source_address(
                b"\tinet 192.168.1.20 netmask 0xffffff00 broadcast 192.168.1.255\n"
            ),
            Some(Ipv4Addr::new(192, 168, 1, 20))
        );
    }

    #[test]
    fn physical_default_route_ignores_the_active_tunnel() {
        let output = b"Routing tables\n\
Internet:\n\
Destination        Gateway            Flags               Netif Expire\n\
default            link#19            UCSg                utun4\n\
default            192.168.3.1        UGScIg                en0\n";

        let route = parse_physical_default_route(output).unwrap();

        assert_eq!(route.interface, "en0");
        assert_eq!(route.gateway, "192.168.3.1");
    }

    #[test]
    fn route_lookup_requires_the_exact_owned_route() {
        let route = OwnedRoute {
            destination: "203.0.113.0/24".to_string(),
            interface_identifier: "en0".to_string(),
            gateway: Some("192.168.3.1".to_string()),
            metric: None,
        };
        let output = b"   route to: 203.0.113.0\n\
destination: 203.0.113.0\n\
       mask: 255.255.255.0\n\
    gateway: 192.168.3.1\n\
  interface: en0\n";

        assert!(route_lookup_matches(output, &route).unwrap());
        assert!(!route_lookup_matches(
            b"destination: 203.0.113.0\nmask: 255.255.255.0\ngateway: 192.168.4.1\ninterface: en0\n",
            &route,
        )
        .unwrap());
    }

    #[test]
    fn route_table_presence_matches_owned_routes_from_one_snapshot() {
        let routes = vec![
            OwnedRoute {
                destination: "203.0.113.0/24".to_string(),
                interface_identifier: "en0".to_string(),
                gateway: Some("192.168.3.1".to_string()),
                metric: None,
            },
            OwnedRoute {
                destination: "198.51.100.8/32".to_string(),
                interface_identifier: "en0".to_string(),
                gateway: Some("192.168.3.1".to_string()),
                metric: None,
            },
        ];
        let output = b"Routing tables\n\
Internet:\n\
Destination        Gateway            Flags               Netif Expire\n\
203.0.113/24       192.168.3.1        UGSc                  en0\n\
198.51.100.9       192.168.3.1        UGHS                  en0\n";

        assert_eq!(
            route_table_presence(output, &routes).unwrap(),
            vec![true, false]
        );
    }

    #[test]
    fn parses_abbreviated_netstat_destinations() {
        assert_eq!(
            parse_netstat_destination("10/8"),
            Some("10.0.0.0/8".parse().unwrap())
        );
        assert_eq!(
            parse_netstat_destination("192.168.3"),
            Some("192.168.3.0/24".parse().unwrap())
        );
        assert_eq!(
            parse_netstat_destination("203.0.113.8"),
            Some("203.0.113.8/32".parse().unwrap())
        );
    }

    #[test]
    fn route_mutation_is_scoped_to_the_recorded_interface() {
        let route = OwnedRoute {
            destination: "203.0.113.0/24".to_string(),
            interface_identifier: "en7".to_string(),
            gateway: Some("192.168.1.1".to_string()),
            metric: None,
        };

        assert_eq!(
            route_arguments("delete", &route, "192.168.1.1"),
            [
                "-n",
                "delete",
                "-net",
                "-ifscope",
                "en7",
                "203.0.113.0/24",
                "192.168.1.1",
            ]
        );
    }
}
