//! Read-only physical egress discovery. Resolver ownership is intentionally a
//! separate factory responsibility; this result is not a complete DNS policy.
use super::*;
use nelomai_client_tunnel::{DesktopTunnelOptions, Ipv4RoutePlan};
use std::collections::{HashMap, HashSet};

pub struct PhysicalRoutes {
    pub bypasses: Vec<RouteValue>,
    pub retained_routes: Vec<RouteValue>,
}

impl<C: LinuxNetworkCommands> LinuxNetwork<C> {
    /// `owned` must come from this session's durable journal, not client IPC.
    /// Only ordinary main-table routing plus our exact bound probe rules is
    /// supported. Unknown policy routing is an error, never a guessed gateway.
    pub fn resolve_physical_routes(
        &mut self,
        options: &DesktopTunnelOptions,
        endpoints: &[IpAddr],
        owned: &[IpNet],
    ) -> io::Result<PhysicalRoutes> {
        let plan = Ipv4RoutePlan::from_options(options).map_err(|_| invalid())?;
        if endpoints.is_empty()
            || endpoints.len() > 2
            || owned.len() > 32768
            || endpoints
                .iter()
                .any(|e| e.is_unspecified() || e.is_loopback() || e.is_multicast())
        {
            return Err(invalid());
        }
        let mut requested = plan
            .excluded_networks
            .into_iter()
            .map(IpNet::V4)
            .collect::<Vec<_>>();
        requested.extend(endpoints.iter().copied().map(IpNet::from));
        requested.sort();
        requested.dedup();
        let links = self.physical_links()?;
        let mut result = PhysicalRoutes {
            bypasses: vec![],
            retained_routes: vec![],
        };
        for ipv6 in [false, true] {
            let needed = requested.iter().any(|n| n.addr().is_ipv6() == ipv6);
            if !needed && !plan.exclude_local_networks {
                continue;
            }
            self.verify_main_rules(ipv6)?;
            let text = self.commands.ip(&[
                "-j".into(),
                "-N".into(),
                family(ipv6).into(),
                "route".into(),
                "show".into(),
                "table".into(),
                "main".into(),
            ])?;
            let mut routes = Vec::new();
            for row in rows(&text)? {
                let row = row.as_object().ok_or_else(invalid)?;
                // A blackhole/multipath/nhid route may have no top-level dev.
                // Ignoring it could route around a deliberate policy block.
                if !row.contains_key("dev") {
                    return Err(io::Error::other("physical_route_unsupported"));
                }
                // Other VPNs are not physical egress. Their exact destination
                // conflicts are rejected later by the owned route transaction.
                let Some(index) = row
                    .get("dev")
                    .and_then(Value::as_str)
                    .and_then(|n| links.get(n))
                else {
                    continue;
                };
                routes.push(parse_route(row, ipv6, *index)?);
            }
            for destination in requested
                .iter()
                .copied()
                .filter(|n| n.addr().is_ipv6() == ipv6)
            {
                let exact = routes
                    .iter()
                    .filter(|r| r.destination == destination)
                    .collect::<Vec<_>>();
                if !owned.contains(&destination) && !exact.is_empty() {
                    if exact.len() != 1 {
                        return Err(invalid());
                    }
                    result.retained_routes.push(exact[0].clone());
                    continue;
                }
                // Ignore our former bypass while selecting its new physical
                // next hop after a network change. An on-link LAN prefix is
                // more specific than a physical default, not via its gateway.
                let mut candidates = routes
                    .iter()
                    .filter(|r| {
                        !owned.contains(&r.destination)
                            && r.destination.prefix_len() <= destination.prefix_len()
                            && r.destination.contains(&destination.network())
                    })
                    .collect::<Vec<_>>();
                candidates
                    .sort_by_key(|r| (std::cmp::Reverse(r.destination.prefix_len()), r.metric));
                let best = candidates
                    .first()
                    .ok_or_else(|| io::Error::other("physical_egress_unavailable"))?;
                if candidates.get(1).is_some_and(|r| {
                    r.destination.prefix_len() == best.destination.prefix_len()
                        && r.metric == best.metric
                }) {
                    return Err(io::Error::other("physical_egress_ambiguous"));
                }
                result.bypasses.push(RouteValue {
                    destination,
                    scope: RouteScope::Global,
                    interface: best.interface,
                    gateway: best.gateway,
                    metric: 42,
                });
            }
            if plan.exclude_local_networks {
                for route in routes.into_iter().filter(|r| {
                    r.gateway.is_none()
                        && r.destination.prefix_len() > 0
                        && r.destination.prefix_len() < if ipv6 { 128 } else { 32 }
                        && !requested.contains(&r.destination)
                }) {
                    if result
                        .retained_routes
                        .iter()
                        .any(|r| r.destination == route.destination)
                    {
                        return Err(io::Error::other("physical_lan_ambiguous"));
                    }
                    result.retained_routes.push(route);
                }
            }
        }
        if result.bypasses.len() + result.retained_routes.len() > 16384 {
            return Err(invalid());
        }
        Ok(result)
    }

    fn physical_links(&mut self) -> io::Result<HashMap<String, u32>> {
        let text = self
            .commands
            .ip(&["-j".into(), "-d".into(), "link".into(), "show".into()])?;
        let mut links = HashMap::new();
        for row in rows(&text)? {
            let row = row.as_object().ok_or_else(invalid)?;
            if row.get("link_type").and_then(Value::as_str) != Some("ether") {
                continue;
            }
            if row.get("master").is_some() {
                continue;
            } // slave is not an L3 uplink
            if let Some(info) = row.get("linkinfo") {
                if !matches!(
                    info.get("info_kind").and_then(Value::as_str),
                    Some("vlan" | "bridge" | "bond")
                ) {
                    continue;
                }
            }
            let flags = row
                .get("flags")
                .and_then(Value::as_array)
                .ok_or_else(invalid)?;
            if !flags.iter().any(|f| f == "UP") || !flags.iter().any(|f| f == "LOWER_UP") {
                continue;
            }
            let name = string(row, "ifname")?;
            let index = number(row, "ifindex")?;
            if self
                .members
                .iter()
                .any(|m| m.interface == index || m.name == name)
            {
                continue;
            }
            if index == 0 || self.name(index)? != name || links.insert(name.into(), index).is_some()
            {
                return Err(invalid());
            }
        }
        Ok(links)
    }

    fn verify_main_rules(&mut self, ipv6: bool) -> io::Result<()> {
        let text = self.commands.ip(&[
            "-j".into(),
            "-N".into(),
            family(ipv6).into(),
            "rule".into(),
            "show".into(),
        ])?;
        let mut seen = HashSet::new();
        for row in rows(&text)? {
            let row = row.as_object().ok_or_else(invalid)?;
            let priority = number(row, "priority")?;
            if !seen.insert(priority) || string(row, "src")? != "all" {
                return Err(invalid());
            }
            if let Some(member) = self.members.iter().find(|m| m.priority == priority) {
                only_keys(row, &["priority", "src", "table", "protocol", "oif"])?;
                if number(row, "table")? != member.table
                    || number(row, "protocol")? != 4
                    || string(row, "oif")? != self.name(member.interface)?
                {
                    return Err(invalid());
                }
            } else {
                only_keys(row, &["priority", "src", "table", "protocol"])?;
                if !matches!(
                    (priority, number(row, "table")?),
                    (0, 255) | (32766, 254) | (32767, 253)
                ) {
                    return Err(invalid());
                }
                if row.contains_key("protocol") {
                    number(row, "protocol")?;
                }
            }
        }
        if !seen.contains(&0) || !seen.contains(&32766) {
            return Err(invalid());
        }
        Ok(())
    }
}

pub(super) fn validate_metadata(row: &Map<String, Value>, destination: IpNet) -> io::Result<()> {
    if !matches!(number(row, "protocol")?, 2 | 3 | 4 | 9 | 16) {
        return Err(invalid());
    }
    if let Some(value) = row.get("prefsrc") {
        let ip = value
            .as_str()
            .ok_or_else(invalid)?
            .parse::<IpAddr>()
            .map_err(|_| invalid())?;
        if ip.is_unspecified() || ip.is_multicast() || ip.is_ipv6() != destination.addr().is_ipv6()
        {
            return Err(invalid());
        }
    }
    if row.contains_key("expires") && number(row, "expires")? == 0 {
        return Err(invalid());
    }
    Ok(())
}

fn parse_route(row: &Map<String, Value>, ipv6: bool, interface: u32) -> io::Result<RouteValue> {
    only_keys(
        row,
        &[
            "dst", "dev", "gateway", "protocol", "scope", "metric", "flags", "type", "table",
            "pref", "prefsrc", "expires",
        ],
    )?;
    let dst = string(row, "dst")?;
    let destination = if dst == "default" {
        if ipv6 { "::/0" } else { "0.0.0.0/0" }
            .parse()
            .map_err(|_| invalid())?
    } else {
        dst.parse::<IpNet>()
            .or_else(|_| dst.parse::<IpAddr>().map(IpNet::from))
            .map_err(|_| invalid())?
    };
    if destination != destination.trunc()
        || destination.addr().is_ipv6() != ipv6
        || row.get("type").is_some_and(|v| v != "unicast")
        || row
            .get("flags")
            .is_some_and(|v| v.as_array().is_none_or(|a| !a.is_empty()))
        || row.get("pref").is_some_and(|v| v != "medium")
        || (row.contains_key("table") && number(row, "table")? != 254)
    {
        return Err(invalid());
    }
    validate_metadata(row, destination)?;
    let gateway = row
        .get("gateway")
        .map(|v| {
            v.as_str()
                .ok_or_else(invalid)?
                .parse::<IpAddr>()
                .map_err(|_| invalid())
        })
        .transpose()?;
    if gateway.is_some_and(|g| {
        g.is_ipv6() != ipv6 || g.is_unspecified() || g.is_multicast() || g.is_loopback()
    }) {
        return Err(invalid());
    }
    if let Some(scope) = row.get("scope") {
        let (text, num) = if gateway.is_some() {
            ("global", 0)
        } else {
            ("link", 253)
        };
        if scope != text && number(row, "scope")? != num {
            return Err(invalid());
        }
    }
    Ok(RouteValue {
        destination,
        scope: RouteScope::Global,
        interface,
        gateway,
        metric: if row.contains_key("metric") {
            number(row, "metric")?
        } else {
            0
        },
    })
}
