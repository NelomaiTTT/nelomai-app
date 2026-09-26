use super::{
    network::{RouteScope, RouteValue},
    Slot,
};
use ipnet::IpNet;
use std::{io, net::Ipv4Addr};

/// Native indexes are obtained from already-owned members, never from app IPC.
#[derive(Clone, Debug)]
pub struct MemberRoutes {
    pub slot: Slot,
    pub interface: u32,
    pub allowed: Vec<IpNet>,
    pub probe: Ipv4Addr,
}

/// Common data route plan for adapters with truly interface-scoped probe routes.
/// Windows must not map Member to a globally visible high-metric route: after an
/// active interface disappears it would silently admit user traffic on reserve.
pub fn member_route_plan(
    active: Slot,
    members: &[MemberRoutes],
    physical_exclusions: &[IpNet],
    metric: u32,
) -> io::Result<Vec<RouteValue>> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "invalid_member_routes");
    if members.is_empty()
        || members.len() > 2
        || physical_exclusions.len() > 16384
        || members.iter().any(|m| {
            m.interface == 0
                || m.allowed.len() > 16384
                || m.allowed.is_empty()
                || m.probe.is_unspecified()
                || m.probe.is_multicast()
                || m.probe.is_loopback()
                || m.probe.is_broadcast()
                || !m
                    .allowed
                    .iter()
                    .any(|n| n.contains(&std::net::IpAddr::V4(m.probe)))
        })
        || members.len() == 2
            && (members[0].slot == members[1].slot || members[0].interface == members[1].interface)
    {
        return Err(invalid());
    }
    let member = members
        .iter()
        .find(|m| m.slot == active)
        .ok_or_else(invalid)?;
    let mut data = Vec::new();
    for network in IpNet::aggregate(&member.allowed) {
        if network.prefix_len() == 0 {
            let halves = if network.addr().is_ipv4() {
                ["0.0.0.0/1", "128.0.0.0/1"]
            } else {
                ["::/1", "8000::/1"]
            };
            data.extend(halves.map(|s| s.parse::<IpNet>().expect("fixed network")));
        } else {
            data.push(network);
        }
    }
    // Equal/broader bypasses must win too, including an exclusion of a /1.
    // More-specific physical routes remain in the session's bypass set and win
    // the normal longest-prefix lookup without enumerating a huge complement.
    data.retain(|n| !physical_exclusions.iter().any(|e| e.contains(n)));
    let mut result = data
        .into_iter()
        .map(|destination| RouteValue {
            destination,
            scope: RouteScope::Global,
            interface: member.interface,
            gateway: None,
            metric,
        })
        .collect::<Vec<_>>();
    for member in members {
        result.push(RouteValue {
            destination: IpNet::from(std::net::IpAddr::V4(member.probe)),
            scope: RouteScope::Member(member.interface),
            interface: member.interface,
            gateway: None,
            metric,
        });
    }
    Ok(result)
}
