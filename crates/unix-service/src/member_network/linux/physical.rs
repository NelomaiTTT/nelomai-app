//! Read-only physical egress discovery. Resolver ownership is intentionally a
//! separate factory responsibility; this result is not a complete DNS policy.
use super::*;
use nelomai_client_tunnel::{DesktopTunnelOptions, Ipv4RoutePlan};
use std::collections::{HashMap, HashSet};

const MAIN_RULE_PRIORITY: u32 = 32766;

pub struct PhysicalRoutes {
    pub exclusions: Vec<IpNet>,
    pub existing: Vec<IpNet>,
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
        owned: &[RouteValue],
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
        let owned: HashSet<_> = owned
            .iter()
            .filter(|r| {
                matches!(
                    r.scope,
                    RouteScope::Global | RouteScope::LinuxMainPriority(_)
                ) && r.gateway.is_none()
            })
            .map(|r| (r.destination, r.interface, r.metric))
            .collect();
        let links = self.physical_links()?;
        let mut result = PhysicalRoutes {
            exclusions: requested.clone(),
            existing: vec![],
            retained_routes: vec![],
        };
        for ipv6 in [false, true] {
            let needed = requested.iter().any(|n| n.addr().is_ipv6() == ipv6);
            if !needed && !plan.exclude_local_networks {
                continue;
            }
            self.verify_policy_rules_through(ipv6, u32::MAX)?;
            let text = self.commands.ip(&[
                "-j".into(),
                "-N".into(),
                family(ipv6).into(),
                "route".into(),
                "show".into(),
                "table".into(),
                "main".into(),
            ])?;
            let mut physical = Vec::new();
            let mut foreign = Vec::new();
            for row in rows(&text)? {
                let row = row.as_object().ok_or_else(invalid)?;
                let name = string(row, "dev")?;
                if let Some(index) = links.get(name) {
                    physical.push(parse_route(row, ipv6, *index)?);
                } else {
                    let net = destination(row, ipv6)?;
                    // Only exact routes through our registered member may be
                    // removed from the projection of the post-exclusion table.
                    let is_owned = self
                        .members
                        .iter()
                        .find(|m| m.name == name)
                        .is_some_and(|m| {
                            parse_route(row, ipv6, m.interface).is_ok_and(|r| {
                                r.gateway.is_none() && owned.contains(&(net, m.interface, r.metric))
                            })
                        });
                    if !is_owned {
                        foreign.push((
                            net,
                            row.get("metric")
                                .map(|_| number(row, "metric"))
                                .transpose()?
                                .unwrap_or(0),
                        ));
                    }
                }
            }
            result
                .existing
                .extend(physical.iter().map(|r| r.destination));
            result.existing.extend(foreign.iter().map(|(net, _)| *net));
            for endpoint in endpoints.iter().filter(|ip| ip.is_ipv6() == ipv6) {
                let mut candidates: Vec<_> = physical
                    .iter()
                    .filter(|r| r.destination.contains(endpoint))
                    .collect();
                let rank = |n: IpNet, metric| (std::cmp::Reverse(n.prefix_len()), metric);
                candidates.sort_by_key(|r| rank(r.destination, r.metric));
                let best = candidates
                    .first()
                    .ok_or_else(|| io::Error::other("physical_egress_unavailable"))?;
                if candidates.get(1).is_some_and(|r| {
                    rank(r.destination, r.metric) == rank(best.destination, best.metric)
                }) || foreign.iter().any(|(net, metric)| {
                    net.contains(endpoint)
                        && rank(*net, *metric) <= rank(best.destination, best.metric)
                }) {
                    return Err(io::Error::other("physical_egress_ambiguous"));
                }
                if !result.retained_routes.contains(best) {
                    result.retained_routes.push((*best).clone());
                }
            }
            if plan.exclude_local_networks {
                for route in physical.into_iter().filter(|r| {
                    r.gateway.is_none()
                        && r.destination.prefix_len() > 0
                        && r.destination.prefix_len() < if ipv6 { 128 } else { 32 }
                }) {
                    result.exclusions.push(route.destination);
                    // fe80:: destinations are scoped by the socket's interface.
                    // Several interfaces legitimately carry the same prefix.
                    if matches!(route.destination.addr(), IpAddr::V6(ip) if ip.is_unicast_link_local())
                    {
                        continue;
                    }
                    if result.retained_routes.contains(&route) {
                        continue;
                    }
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
        result.exclusions.sort_unstable();
        result.exclusions.dedup();
        if result.exclusions.len() > 16_384 || result.retained_routes.len() > 16_384 {
            return Err(invalid());
        }
        Ok(result)
    }

    pub(crate) fn physical_links(&mut self) -> io::Result<HashMap<String, u32>> {
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

    /// Ordinary data routes rely on the unconditional main lookup. Later
    /// rules remain available for traffic with no matching main-table route.
    pub(crate) fn verify_main_rules(&mut self, ipv6: bool) -> io::Result<()> {
        self.verify_policy_rules_through(ipv6, MAIN_RULE_PRIORITY)
    }

    fn verify_policy_rules_through(&mut self, ipv6: bool, last_priority: u32) -> io::Result<()> {
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
            if priority > last_priority {
                continue;
            }
            if !seen.insert(priority) || string(row, "src")? != "all" {
                return Err(invalid());
            }
            if let Some(member) = self.members.iter().find(|m| m.priority == priority) {
                // A vanished member's exact oif rule is detached by the
                // kernel, so it cannot steer traffic while the reserve takes over.
                self.verify_member_rule_row(row, member)?;
            } else {
                only_keys(row, &["priority", "src", "table", "protocol"])?;
                if !matches!(
                    (priority, number(row, "table")?),
                    (0, 255) | (MAIN_RULE_PRIORITY, 254) | (32767, 253)
                ) {
                    return Err(invalid());
                }
                if row.contains_key("protocol") {
                    number(row, "protocol")?;
                }
            }
        }
        if !seen.contains(&0) || !seen.contains(&MAIN_RULE_PRIORITY) {
            return Err(invalid());
        }
        Ok(())
    }
}

pub(super) fn validate_metadata(row: &Map<String, Value>, destination: IpNet) -> io::Result<()> {
    // iproute2 suppresses RTPROT_BOOT in normal table dumps, including JSON
    // numeric mode. Only this read-only physical dependency accepts omission.
    if row.contains_key("protocol") && !matches!(number(row, "protocol")?, 2 | 3 | 4 | 9 | 16) {
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

pub(super) fn destination(row: &Map<String, Value>, ipv6: bool) -> io::Result<IpNet> {
    let dst = string(row, "dst")?;
    if dst == "default" {
        if ipv6 { "::/0" } else { "0.0.0.0/0" }
            .parse()
            .map_err(|_| invalid())
    } else {
        dst.parse::<IpNet>()
            .or_else(|_| dst.parse::<IpAddr>().map(IpNet::from))
            .map_err(|_| invalid())
    }
}

fn parse_route(row: &Map<String, Value>, ipv6: bool, interface: u32) -> io::Result<RouteValue> {
    only_keys(
        row,
        &[
            "dst", "dev", "gateway", "protocol", "scope", "metric", "flags", "type", "table",
            "pref", "prefsrc", "expires",
        ],
    )?;
    let destination = destination(row, ipv6)?;
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
