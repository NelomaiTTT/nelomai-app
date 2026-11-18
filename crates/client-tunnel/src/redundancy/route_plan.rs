use super::{
    network::{RouteScope, RouteValue},
    Slot,
};
use ipnet::IpNet;
use std::{io, net::Ipv4Addr};

pub(crate) const UNIX_DATA_ROUTE_LIMIT: usize = 16_384;

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
    if physical_exclusions.len() > 16_384 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid_member_routes",
        ));
    }
    let member = active_member(active, members)?;
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
    Ok(with_probes(member, members, data, metric))
}

fn active_member(active: Slot, members: &[MemberRoutes]) -> io::Result<&MemberRoutes> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "invalid_member_routes");
    if members.is_empty()
        || members.len() > 2
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
    members
        .iter()
        .find(|m| m.slot == active)
        .ok_or_else(invalid)
}

/// Darwin treats an unscoped route whose key is the unspecified address as
/// a default, even for a nonzero prefix. Keep both scoped defaults intact.
pub fn macos_scoped_default_exclusions() -> [IpNet; 2] {
    [
        std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
    ]
    .map(IpNet::from)
}

/// Unix data routes are confined to the configured allowed set, with holes for
/// physical traffic. The kernel's existing routes handle those destinations.
pub fn tunnel_destinations(allowed: &[IpNet], exclusions: &[IpNet]) -> io::Result<Vec<IpNet>> {
    tunnel_destinations_preserving(allowed, exclusions, &[])
}

/// Preserve longest-prefix precedence where subtracting a bypass would produce a
/// tunnel route as specific as (or more specific than) a former OS route winner.
pub fn tunnel_destinations_preserving(
    allowed: &[IpNet],
    exclusions: &[IpNet],
    existing: &[IpNet],
) -> io::Result<Vec<IpNet>> {
    const LIMIT: usize = UNIX_DATA_ROUTE_LIMIT;
    let too_large = || io::Error::new(io::ErrorKind::InvalidInput, "route_plan_too_large");
    if allowed.len() > LIMIT || exclusions.len() > LIMIT || existing.len() > 32_768 {
        return Err(too_large());
    }
    // Aggregation gives ordered, disjoint intervals for the binary search below.
    let excluded = IpNet::aggregate(&exclusions.to_vec());
    let existing: std::collections::HashSet<_> = existing.iter().map(|n| n.trunc()).collect();
    // More-specific AllowedIPs can outrank an intervening foreign route.
    // Aggregating them with adjacent or enclosing allowed prefixes loses that priority.
    let allowed: std::collections::BTreeSet<_> = allowed.iter().map(IpNet::trunc).collect();
    let mut stack: Vec<_> = allowed.into_iter().map(|n| (n, n.prefix_len())).collect();
    let mut result = std::collections::BTreeSet::new();
    while let Some((net, original_prefix)) = stack.pop() {
        let first = excluded.partition_point(|e| e.broadcast() < net.network());
        if let Some(e) = excluded.get(first) {
            if e.contains(&net) {
                continue;
            }
        }
        if net.prefix_len() == original_prefix && original_prefix != 0 && existing.contains(&net) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "foreign_route_conflict",
            ));
        }
        let overlaps = excluded.get(first).is_some_and(|e| net.contains(e));
        if overlaps || net.prefix_len() == 0 {
            // Keep both OS defaults intact even for a full tunnel.
            stack.extend(
                net.subnets(net.prefix_len() + 1)
                    .expect("non-host prefix")
                    .map(|n| (n, original_prefix)),
            );
        } else {
            if !existing.is_empty()
                && std::iter::successors(Some(net), IpNet::supernet)
                    .take_while(|n| n.prefix_len() > original_prefix)
                    .any(|n| existing.contains(&n))
            {
                continue;
            }
            result.insert(net);
            if result.len() > LIMIT {
                return Err(too_large());
            }
        }
    }
    Ok(result.into_iter().collect())
}

pub fn unix_member_route_plan(
    active: Slot,
    members: &[MemberRoutes],
    exclusions: &[IpNet],
    existing: &[IpNet],
    metric: u32,
) -> io::Result<Vec<RouteValue>> {
    let member = active_member(active, members)?;
    let data = tunnel_destinations_preserving(&member.allowed, exclusions, existing)?;
    Ok(with_probes(member, members, data, metric))
}

fn with_probes(
    member: &MemberRoutes,
    members: &[MemberRoutes],
    data: Vec<IpNet>,
    metric: u32,
) -> Vec<RouteValue> {
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
    result
}
