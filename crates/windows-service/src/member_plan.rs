//! Pure route planning for a WFP-guarded Windows pair. These routes are GLOBAL,
//! including member probe /32s: WindowsInterface is a native key, NOT isolation.
//! The caller MUST guard inactive interfaces with WFP before applying this plan
//! and retain that guard through failures/removal. Metrics/shadows alone cannot
//! isolate a reserve after the active/physical path disappears.
//!
//! Inputs are captured and verified by the privileged owner, never app IPC.
//! There is no discovery, verification of live state, or native mutation here.

use ipnet::IpNet;
use nelomai_client_tunnel::redundancy::{
    network::{RouteScope, RouteValue},
    route_plan::{self, MemberRoutes},
    Slot,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr},
};

pub const MAX_ROUTES: usize = 16_384;
pub const ACTIVE_PROBE_METRIC: u32 = 1;
pub const INACTIVE_PROBE_METRIC: u32 = 100;

/// Family-specific interface metric already verified by the owner. This is not
/// a native proof or IPC type; the owner must revalidate before guarded apply.
#[derive(Clone, Copy, Debug)]
pub struct InterfaceMetric {
    pub interface: u32,
    pub ipv6: bool,
    pub metric: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Plan {
    pub routes: Vec<RouteValue>,
    pub guard_required: bool,
}

#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum PlanError {
    #[error("invalid_guarded_member_routes")]
    Invalid,
    #[error("guarded_route_plan_too_large")]
    TooLarge,
    #[error("missing_verified_interface_metric: interface={interface}, ipv6={ipv6}")]
    MissingMetric { interface: u32, ipv6: bool },
    #[error("unsupported_member_interface_metrics: owned interfaces must have equal verified metrics for ipv6={ipv6}")]
    UnequalMemberMetrics { ipv6: bool },
    #[error("missing_verified_physical_probe_route: {0}/32")]
    MissingPhysicalProbe(Ipv4Addr),
    #[error("missing_resolved_physical_exclusion_route: {0}")]
    MissingExclusion(IpNet),
    #[error("unsupported_route_metrics: {0}: effective metrics overflow or physical shadow does not strictly beat every competing member /32 (including active)")]
    UnsupportedMetric(IpNet),
    #[error("conflicting_guarded_route_key")]
    Conflict,
}

/// Physical exclusions require corresponding resolved bypasses. A physical
/// probe shadow requires an exact supplied /32 (no guessing a default next hop).
/// Data prefixes use the common planner, including split defaults/exclusions.
pub fn member_route_plan(
    active: Slot,
    members: &[MemberRoutes],
    physical_exclusions: &[IpNet],
    physical_bypasses: &[RouteValue],
    verified_metrics: &[InterfaceMetric],
    data_metric: u32,
) -> Result<Plan, PlanError> {
    if physical_exclusions.len() > MAX_ROUTES
        || physical_bypasses.len() > MAX_ROUTES
        || verified_metrics.len() > MAX_ROUTES
        || members.iter().any(|m| m.allowed.len() > MAX_ROUTES)
    {
        return Err(PlanError::TooLarge);
    }
    if members.is_empty()
        || members.len() > 2
        || members
            .iter()
            .any(|m| m.allowed.iter().any(|n| *n != n.trunc()))
        || physical_exclusions.iter().any(|n| *n != n.trunc())
    {
        return Err(PlanError::Invalid);
    }
    // The common planner validates member slot/index uniqueness, active presence,
    // probe validity/AllowedIPs and implements split defaults and exclusions.
    let common = route_plan::member_route_plan(active, members, physical_exclusions, data_metric)
        .map_err(|_| PlanError::Invalid)?;
    let active_member = members
        .iter()
        .find(|m| m.slot == active)
        .ok_or(PlanError::Invalid)?;
    let mut metrics = BTreeMap::new();
    for metric in verified_metrics {
        if metric.interface == 0
            || metrics
                .insert((metric.interface, metric.ipv6), metric.metric)
                .is_some()
        {
            return Err(PlanError::Invalid);
        }
    }
    // IPv4 probes are mandatory. If either member uses IPv6, obtain and compare
    // both members' IPv6 metrics too; a family metric is never inferred from v4.
    let ipv6 = members
        .iter()
        .any(|m| m.allowed.iter().any(|n| n.addr().is_ipv6()));
    for family in [false, true].into_iter().filter(|v6| !*v6 || ipv6) {
        let mut expected = None;
        for member in members {
            let value = interface_metric(&metrics, member.interface, family)?;
            if expected.is_some_and(|old| old != value) {
                return Err(PlanError::UnequalMemberMetrics { ipv6: family });
            }
            expected = Some(value);
        }
    }
    let mut physical = BTreeMap::new();
    for supplied in physical_bypasses {
        validate_physical(supplied, members)?;
        let mut route = supplied.clone();
        route.scope = RouteScope::WindowsInterface(route.interface);
        effective_metric(&metrics, &route)?;
        if physical
            .insert(route.destination, route.clone())
            .is_some_and(|old| old != route)
        {
            return Err(PlanError::Conflict);
        }
    }
    for exclusion in physical_exclusions {
        if !physical.contains_key(exclusion) {
            return Err(PlanError::MissingExclusion(*exclusion));
        }
    }
    let mut routes = BTreeMap::new();
    for mut route in common.into_iter().filter(|r| r.scope == RouteScope::Global) {
        route.scope = RouteScope::WindowsInterface(active_member.interface);
        effective_metric(&metrics, &route)?;
        routes.insert((route.destination, route.interface), route);
    }
    for route in physical.values() {
        routes.insert((route.destination, route.interface), route.clone());
    }
    for member in members {
        let route = probe_route(
            member.probe,
            member.interface,
            if member.slot == active {
                ACTIVE_PROBE_METRIC
            } else {
                INACTIVE_PROBE_METRIC
            },
        );
        effective_metric(&metrics, &route)?;
        // A data /32 may share this native key. Probe policy owns that key's
        // metric; do not create aliased Global/Member journal entries.
        routes.insert((route.destination, route.interface), route);
    }
    let probes: BTreeSet<_> = members.iter().map(|m| m.probe).collect();
    for probe in probes {
        let address = IpAddr::V4(probe);
        let destination = IpNet::from(address);
        let excluded = physical_exclusions.iter().any(|e| e.contains(&address));
        let covered = active_member.allowed.iter().any(|n| n.contains(&address));
        let shadow = if covered && !excluded {
            probe_route(probe, active_member.interface, ACTIVE_PROBE_METRIC)
        } else {
            let mut route = physical
                .get(&destination)
                .ok_or(PlanError::MissingPhysicalProbe(probe))?
                .clone();
            route.metric = ACTIVE_PROBE_METRIC;
            route
        };
        let shadow_weight = effective_metric(&metrics, &shadow)?;
        // Check against EVERY other /32, including the active's own probe and
        // any supplied physical /32. Ties are unsupported, never ECMP guesses.
        for route in routes
            .values()
            .filter(|r| r.destination == destination && r.interface != shadow.interface)
        {
            if shadow_weight >= effective_metric(&metrics, route)? {
                return Err(PlanError::UnsupportedMetric(destination));
            }
        }
        routes.insert((destination, shadow.interface), shadow);
    }
    if routes.len() > MAX_ROUTES {
        return Err(PlanError::TooLarge);
    }
    Ok(Plan {
        routes: routes.into_values().collect(),
        guard_required: true,
    })
}

fn interface_metric(
    metrics: &BTreeMap<(u32, bool), u32>,
    interface: u32,
    ipv6: bool,
) -> Result<u32, PlanError> {
    metrics
        .get(&(interface, ipv6))
        .copied()
        .ok_or(PlanError::MissingMetric { interface, ipv6 })
}
fn effective_metric(
    metrics: &BTreeMap<(u32, bool), u32>,
    route: &RouteValue,
) -> Result<u32, PlanError> {
    interface_metric(metrics, route.interface, route.destination.addr().is_ipv6())?
        .checked_add(route.metric)
        .ok_or(PlanError::UnsupportedMetric(route.destination))
}
fn probe_route(probe: Ipv4Addr, interface: u32, metric: u32) -> RouteValue {
    RouteValue {
        destination: IpNet::from(IpAddr::V4(probe)),
        scope: RouteScope::WindowsInterface(interface),
        interface,
        gateway: None,
        metric,
    }
}
fn validate_physical(route: &RouteValue, members: &[MemberRoutes]) -> Result<(), PlanError> {
    if route.interface == 0
        || members.iter().any(|m| m.interface == route.interface)
        || route.destination != route.destination.trunc()
        || !matches!(route.scope, RouteScope::Global)
            && route.scope != RouteScope::WindowsInterface(route.interface)
        || route.gateway.is_some_and(|g| {
            g.is_ipv4() != route.destination.addr().is_ipv4()
                || g.is_unspecified()
                || g.is_multicast()
                || g.is_loopback()
                || matches!(g, IpAddr::V4(ip) if ip.is_broadcast())
        })
    {
        return Err(PlanError::Invalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nelomai_client_tunnel::redundancy::network::RouteScope;
    use std::{collections::BTreeSet, net::IpAddr};

    fn member(slot: Slot, interface: u32, probe: &str) -> MemberRoutes {
        MemberRoutes {
            slot,
            interface,
            allowed: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
            probe: probe.parse().unwrap(),
        }
    }
    fn members() -> [MemberRoutes; 2] {
        [
            member(Slot::A, 10, "9.9.9.9"),
            member(Slot::B, 20, "1.1.1.1"),
        ]
    }
    fn metrics() -> Vec<InterfaceMetric> {
        [10, 20]
            .into_iter()
            .flat_map(|interface| {
                [false, true].map(move |ipv6| InterfaceMetric {
                    interface,
                    ipv6,
                    metric: 50,
                })
            })
            .collect()
    }
    fn physical(destination: &str) -> RouteValue {
        let destination: IpNet = destination.parse().unwrap();
        RouteValue {
            destination,
            scope: RouteScope::Global,
            interface: 30,
            gateway: Some(
                if destination.addr().is_ipv4() {
                    "192.0.2.1"
                } else {
                    "2001:db8::1"
                }
                .parse()
                .unwrap(),
            ),
            metric: 7,
        }
    }
    fn physical_metrics() -> Vec<InterfaceMetric> {
        let mut values = metrics();
        values.extend([false, true].map(|ipv6| InterfaceMetric {
            interface: 30,
            ipv6,
            metric: 10,
        }));
        values
    }
    fn lookup(plan: &Plan, address: &str, metrics: &[InterfaceMetric]) -> Vec<u32> {
        let address: IpAddr = address.parse().unwrap();
        let candidates: Vec<_> = plan
            .routes
            .iter()
            .filter(|r| r.destination.contains(&address))
            .collect();
        let prefix = candidates
            .iter()
            .map(|r| r.destination.prefix_len())
            .max()
            .unwrap();
        let weight = |r: &&RouteValue| -> u64 {
            let m = metrics
                .iter()
                .find(|m| m.interface == r.interface && m.ipv6 == address.is_ipv6())
                .unwrap();
            u64::from(m.metric) + u64::from(r.metric)
        };
        let best = candidates
            .iter()
            .filter(|r| r.destination.prefix_len() == prefix)
            .map(weight)
            .min()
            .unwrap();
        candidates
            .iter()
            .filter(|r| r.destination.prefix_len() == prefix && weight(r) == best)
            .map(|r| r.interface)
            .collect()
    }
    #[test]
    fn role_swap_same_probe_keeps_two_stable_keys_and_swaps_metrics() {
        let mut ms = members();
        ms[1].probe = ms[0].probe;
        let a = member_route_plan(Slot::A, &ms, &[], &[], &metrics(), 5).unwrap();
        let b = member_route_plan(Slot::B, &ms, &[], &[], &metrics(), 5).unwrap();
        for (plan, active) in [(&a, 10), (&b, 20)] {
            assert!(plan.guard_required);
            assert!(plan
                .routes
                .iter()
                .all(|r| r.scope == RouteScope::WindowsInterface(r.interface)));
            let probes: Vec<_> = plan
                .routes
                .iter()
                .filter(|r| r.destination == "9.9.9.9/32".parse::<IpNet>().unwrap())
                .collect();
            assert_eq!(probes.len(), 2);
            for route in probes {
                assert_eq!(
                    route.metric,
                    if route.interface == active { 1 } else { 100 }
                );
            }
            assert_eq!(lookup(plan, "9.9.9.9", &metrics()), [active]);
        }
    }
    #[test]
    fn differing_probes_are_shadowed_on_active_not_unbound_reserve() {
        for (slot, interface) in [(Slot::A, 10), (Slot::B, 20)] {
            let plan = member_route_plan(slot, &members(), &[], &[], &metrics(), 5).unwrap();
            for ip in ["9.9.9.9", "1.1.1.1", "8.8.8.8", "2001:4860::8888"] {
                assert_eq!(lookup(&plan, ip, &metrics()), [interface]);
            }
            let inactive: Vec<_> = plan
                .routes
                .iter()
                .filter(|r| r.interface != interface)
                .collect();
            assert_eq!(inactive.len(), 1);
            assert_eq!(inactive[0].destination.prefix_len(), 32);
            let keys: BTreeSet<_> = plan
                .routes
                .iter()
                .map(|r| (r.destination, r.interface))
                .collect();
            assert_eq!(keys.len(), plan.routes.len());
        }
    }
    #[test]
    fn excluded_probe_uses_physical_even_when_active_allowed_covers_it() {
        let ex = ["9.9.9.0/24".parse().unwrap()];
        let bypass = [physical("9.9.9.0/24"), physical("9.9.9.9/32")];
        let plan =
            member_route_plan(Slot::A, &members(), &ex, &bypass, &physical_metrics(), 5).unwrap();
        assert_eq!(lookup(&plan, "9.9.9.9", &physical_metrics()), [30]);
        assert_eq!(lookup(&plan, "9.9.9.10", &physical_metrics()), [30]);
        assert_eq!(lookup(&plan, "1.1.1.1", &physical_metrics()), [10]);
    }
    #[test]
    fn physical_shadow_must_strictly_beat_active_too_not_just_reserve() {
        let mut ms = members();
        ms[1].probe = ms[0].probe;
        let ex = ["9.9.9.9/32".parse().unwrap()];
        let bypass = [physical("9.9.9.9/32")];
        for metric in [50, 51, 148, u32::MAX] {
            let mut metrics = physical_metrics();
            metrics
                .iter_mut()
                .filter(|m| m.interface == 30)
                .for_each(|m| m.metric = metric);
            let error = member_route_plan(Slot::A, &ms, &ex, &bypass, &metrics, 5).unwrap_err();
            assert!(matches!(error, PlanError::UnsupportedMetric(_)));
            assert!(error.to_string().contains("including active"));
        }
    }
    #[test]
    fn reserve_probe_outside_active_allowed_requires_exact_physical_shadow() {
        let mut ms = members();
        ms[0].allowed = vec!["9.0.0.0/8".parse().unwrap()];
        let fallback = [physical("1.1.1.1/32")];
        let plan = member_route_plan(Slot::A, &ms, &[], &fallback, &physical_metrics(), 5).unwrap();
        assert_eq!(lookup(&plan, "1.1.1.1", &physical_metrics()), [30]);
        assert!(matches!(
            member_route_plan(Slot::A, &ms, &[], &[], &metrics(), 5),
            Err(PlanError::MissingPhysicalProbe(_))
        ));
        assert!(member_route_plan(
            Slot::A,
            &ms,
            &[],
            &[physical("0.0.0.0/0")],
            &physical_metrics(),
            5
        )
        .is_err());
    }
    #[test]
    fn ipv6_split_default_and_narrow_physical_exclusion_use_common_data_plan() {
        let ex = [
            "8000::/1".parse().unwrap(),
            "2001:db8::/32".parse().unwrap(),
        ];
        let bypass = [physical("8000::/1"), physical("2001:db8::/32")];
        let plan =
            member_route_plan(Slot::A, &members(), &ex, &bypass, &physical_metrics(), 5).unwrap();
        assert!(plan
            .routes
            .iter()
            .any(|r| r.interface == 10 && r.destination == "::/1".parse::<IpNet>().unwrap()));
        assert!(!plan
            .routes
            .iter()
            .any(|r| r.interface == 10 && r.destination == "8000::/1".parse::<IpNet>().unwrap()));
        assert_eq!(lookup(&plan, "2001:db8::20", &physical_metrics()), [30]);
        assert_eq!(lookup(&plan, "9000::1", &physical_metrics()), [30]);
        assert_eq!(lookup(&plan, "2001:4860::1", &physical_metrics()), [10]);
    }
    #[test]
    fn invalid_members_metrics_and_route_shapes_fail_closed() {
        for mutation in 0..9 {
            let mut ms = members();
            let mut im = physical_metrics();
            let mut bypass = vec![];
            match mutation {
                0 => ms[1].slot = Slot::A,
                1 => ms[1].interface = 10,
                2 => ms[0].interface = 0,
                3 => im.retain(|m| m.interface != 20),
                4 => im
                    .iter_mut()
                    .filter(|m| m.interface == 20)
                    .for_each(|m| m.metric += 1),
                5 => ms[0].allowed = vec!["9.1.1.1/8".parse().unwrap()],
                6 => {
                    let mut r = physical("203.0.113.0/24");
                    r.gateway = Some("::1".parse().unwrap());
                    bypass.push(r);
                }
                7 => {
                    let mut r = physical("203.0.113.0/24");
                    r.interface = 10;
                    r.scope = RouteScope::WindowsInterface(10);
                    bypass.push(r);
                }
                _ => im.push(im[0]),
            }
            assert!(
                member_route_plan(Slot::A, &ms, &[], &bypass, &im, 5).is_err(),
                "mutation {mutation}"
            );
        }
        assert!(member_route_plan(Slot::B, &members()[..1], &[], &[], &metrics(), 5).is_err());
        assert!(member_route_plan(Slot::A, &[], &[], &[], &metrics(), 5).is_err());
    }
    #[test]
    fn data_host_prefix_aliases_probe_without_duplicate_key() {
        let ms = [MemberRoutes {
            allowed: vec!["9.9.9.9/32".parse().unwrap()],
            ..member(Slot::A, 10, "9.9.9.9")
        }];
        let plan = member_route_plan(Slot::A, &ms, &[], &[], &metrics(), 9).unwrap();
        assert_eq!(plan.routes.len(), 1);
        assert_eq!(plan.routes[0].metric, 1);
    }
    #[test]
    fn missing_exclusion_path_and_conflicting_physical_keys_are_rejected() {
        let ex = ["203.0.113.0/24".parse().unwrap()];
        assert!(member_route_plan(Slot::A, &members(), &ex, &[], &metrics(), 5).is_err());
        let a = physical("203.0.113.0/24");
        let mut b = a.clone();
        b.gateway = Some("192.0.2.2".parse().unwrap());
        assert!(
            member_route_plan(Slot::A, &members(), &ex, &[a, b], &physical_metrics(), 5).is_err()
        );
    }
    #[test]
    fn all_input_and_expanded_output_bounds_are_enforced() {
        let too_many = vec![physical("203.0.113.0/24"); 16_385];
        assert!(matches!(
            member_route_plan(Slot::A, &members(), &[], &too_many, &physical_metrics(), 5),
            Err(PlanError::TooLarge)
        ));
        let mut ms = members();
        ms[0].allowed = vec!["0.0.0.0/0".parse().unwrap(); 16_385];
        assert!(matches!(
            member_route_plan(Slot::A, &ms, &[], &[], &metrics(), 5),
            Err(PlanError::TooLarge)
        ));
        let bypass: Vec<_> = (0..16_384u32)
            .map(|i| physical(&format!("{}/32", Ipv4Addr::from(0xac100000 + i))))
            .collect();
        assert!(matches!(
            member_route_plan(Slot::A, &members(), &[], &bypass, &physical_metrics(), 5),
            Err(PlanError::TooLarge)
        ));
        let plan = member_route_plan(
            Slot::A,
            &members(),
            &[],
            &bypass[..16_377],
            &physical_metrics(),
            5,
        )
        .unwrap();
        assert_eq!(plan.routes.len(), 16_384);
    }
    #[test]
    fn outside_active_shadow_wins_strict_effective_metric_boundary() {
        let mut ms = members();
        ms[0].allowed = vec!["9.0.0.0/8".parse().unwrap()];
        let bypass = [physical("1.1.1.1/32")];
        let mut im = physical_metrics();
        im.iter_mut()
            .filter(|m| m.interface == 30)
            .for_each(|m| m.metric = 148);
        let plan = member_route_plan(Slot::A, &ms, &[], &bypass, &im, 5).unwrap();
        assert_eq!(lookup(&plan, "1.1.1.1", &im), [30]); // 148+1 < 50+100
        im.iter_mut()
            .filter(|m| m.interface == 30)
            .for_each(|m| m.metric = 149);
        assert!(matches!(
            member_route_plan(Slot::A, &ms, &[], &bypass, &im, 5),
            Err(PlanError::UnsupportedMetric(_))
        ));
    }
    #[test]
    fn verified_family_metrics_are_required_equal_and_cannot_overflow() {
        let mut im = metrics();
        im.retain(|m| !(m.interface == 20 && m.ipv6));
        assert_eq!(
            member_route_plan(Slot::A, &members(), &[], &[], &im, 5),
            Err(PlanError::MissingMetric {
                interface: 20,
                ipv6: true
            })
        );
        let mut im = metrics();
        im.iter_mut()
            .find(|m| m.interface == 20 && m.ipv6)
            .unwrap()
            .metric += 1;
        assert_eq!(
            member_route_plan(Slot::A, &members(), &[], &[], &im, 5),
            Err(PlanError::UnequalMemberMetrics { ipv6: true })
        );
        let mut im = metrics();
        im.iter_mut().for_each(|m| m.metric = u32::MAX);
        assert!(matches!(
            member_route_plan(Slot::A, &members(), &[], &[], &im, 5),
            Err(PlanError::UnsupportedMetric(_))
        ));
    }
    #[test]
    fn invalid_bypass_scope_prefix_gateway_or_exclusion_is_not_normalized() {
        for bad in 0..5 {
            let mut route = physical("203.0.113.0/24");
            match bad {
                0 => route.scope = RouteScope::Member(30),
                1 => route.scope = RouteScope::WindowsInterface(31),
                2 => route.destination = "203.0.113.1/24".parse().unwrap(),
                3 => route.gateway = Some("0.0.0.0".parse().unwrap()),
                _ => route.interface = 0,
            }
            assert_eq!(
                member_route_plan(Slot::A, &members(), &[], &[route], &physical_metrics(), 5),
                Err(PlanError::Invalid)
            );
        }
        assert_eq!(
            member_route_plan(
                Slot::A,
                &members(),
                &["203.0.113.1/24".parse().unwrap()],
                &[],
                &metrics(),
                5
            ),
            Err(PlanError::Invalid)
        );
    }
}
