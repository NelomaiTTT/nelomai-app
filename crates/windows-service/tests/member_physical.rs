// Portable selector only: no native API or host discovery.
use nelomai_windows_service::member_routes;
#[path = "../src/member_physical.rs"]
mod member_physical;
use member_physical::*;
use member_routes::{NativeProof, Row};
use nelomai_client_tunnel::redundancy::network::{RouteScope, RouteValue};
use std::net::IpAddr;

fn interface(index: u32, family: Family, metric: u32) -> InterfaceRecord {
    InterfaceRecord {
        proof: PhysicalProof {
            identity: InterfaceIdentity {
                index,
                luid: index as u64 * 100,
                guid: [index as u8; 16],
            },
            family,
            metric,
        },
        alias: format!("Ethernet {index}"),
        if_type: 6,
        tunnel_type: 0,
        oper_status: 1,
        status_flags: 1,
    }
}
fn row(prefix: &str, index: u32, gateway: Option<&str>, metric: u32) -> Row {
    Row::static_route(
        RouteValue {
            destination: prefix.parse().unwrap(),
            scope: RouteScope::WindowsInterface(index),
            interface: index,
            gateway: gateway.map(|v| v.parse().unwrap()),
            metric,
        },
        NativeProof {
            index,
            luid: index as u64 * 100,
        },
    )
}
fn capture(rows: Vec<Row>, interfaces: Vec<InterfaceRecord>) -> PhysicalSnapshot {
    PhysicalSnapshot::new(rows, interfaces, &[]).unwrap()
}
fn ip(value: &str) -> IpAddr {
    value.parse().unwrap()
}

#[test]
fn windows_lan_rows_are_retained_without_treating_them_as_remote_hosts() {
    // Observed physical Ethernet table on the Windows acceptance device.
    let prefixes = [
        "192.168.3.0/24",
        "192.168.3.166/32",
        "192.168.3.255/32",
        "224.0.0.0/4",
        "255.255.255.255/32",
        "fe80::/64",
        "fe80::4d76:53b2:9dde:bc19/128",
        "ff00::/8",
    ];
    let mut rows = prefixes
        .iter()
        .map(|p| row(p, 26, None, 256))
        .collect::<Vec<_>>();
    rows.push(row("0.0.0.0/0", 26, Some("192.168.3.1"), 0));
    let snapshot = capture(
        rows.clone(),
        vec![interface(26, Family::V4, 25), interface(26, Family::V6, 25)],
    );
    let mut retained = Vec::new();
    for original in &rows[..prefixes.len()] {
        let resolved = snapshot.resolve_bypass(original.route.destination).unwrap();
        assert_eq!(resolved.row, *original);
        snapshot.verify(&resolved).unwrap();
        retained.push(resolved.row.route);
    }
    // Exercise the actual downstream pair planner too: native LAN rows must
    // never become owned mutations, while both tunnels still receive probes.
    use nelomai_client_tunnel::redundancy::{route_plan::MemberRoutes, Slot};
    use nelomai_windows_service::member_plan::{member_route_plan, InterfaceMetric};
    let members = [Slot::A, Slot::B]
        .into_iter()
        .enumerate()
        .map(|(i, slot)| MemberRoutes {
            slot,
            interface: 40 + i as u32,
            allowed: vec!["0.0.0.0/0".parse().unwrap()],
            probe: if i == 0 { "1.1.1.1" } else { "8.8.8.8" }.parse().unwrap(),
        })
        .collect::<Vec<_>>();
    let exclusions = prefixes.map(|p| p.parse().unwrap());
    let metrics = [
        InterfaceMetric {
            interface: 26,
            ipv6: false,
            metric: 25,
        },
        InterfaceMetric {
            interface: 26,
            ipv6: true,
            metric: 25,
        },
        InterfaceMetric {
            interface: 40,
            ipv6: false,
            metric: 5,
        },
        InterfaceMetric {
            interface: 41,
            ipv6: false,
            metric: 5,
        },
    ];
    let plan = member_route_plan(Slot::A, &members, &exclusions, &retained, &metrics, 0).unwrap();
    let writes = plan
        .routes
        .iter()
        .filter(|r| !retained.contains(r))
        .collect::<Vec<_>>();
    assert!(writes
        .iter()
        .all(|r| r.interface == 40 || r.interface == 41));
    assert!(writes
        .iter()
        .any(|r| r.destination.to_string() == "0.0.0.0/1" && r.interface == 40));
    assert!(writes
        .iter()
        .any(|r| r.destination.to_string() == "8.8.8.8/32" && r.interface == 41));
    // Resolving an endpoint is still a different, strictly unicast operation.
    for host in ["224.0.0.1", "255.255.255.255", "fe80::1", "ff02::1"] {
        assert_eq!(
            snapshot.resolve_host(ip(host)).unwrap_err(),
            DiscoveryError::Invalid
        );
    }
}

#[test]
fn native_local_delivery_rows_are_not_turned_into_physical_bypasses() {
    // Actual GetIpForwardTable2 flags: Windows marks local addresses and both
    // directed/limited broadcast as Loopback even on the physical Ethernet NIC.
    let values = [
        ("192.168.3.0/24", 0),
        ("192.168.3.166/32", 1),
        ("192.168.3.255/32", 1),
        ("224.0.0.0/4", 0),
        ("255.255.255.255/32", 1),
        ("fe80::/64", 0),
        ("fe80::4d76:53b2:9dde:bc19/128", 1),
        ("ff00::/8", 0),
    ];
    let mut rows = values
        .iter()
        .map(|(prefix, loopback)| {
            let mut row = row(prefix, 26, None, 256);
            row.flags = [*loopback, 1, 0, 0];
            row
        })
        .collect::<Vec<_>>();
    let mut expired = row("198.51.100.0/24", 26, None, 256);
    expired.valid_lifetime = 0;
    rows.push(expired);
    rows.push(row("203.0.113.0/24", 29, None, 0));
    let mut virtual_interface = interface(29, Family::V4, 1);
    virtual_interface.status_flags = 0;
    let snapshot = capture(
        rows.clone(),
        vec![
            interface(26, Family::V4, 25),
            interface(26, Family::V6, 25),
            virtual_interface,
        ],
    );
    let mut actual = snapshot.lan_prefixes();
    actual.sort();
    let mut expected = ["192.168.3.0/24", "224.0.0.0/4", "fe80::/64", "ff00::/8"]
        .map(|p| p.parse::<ipnet::IpNet>().unwrap());
    expected.sort();
    assert_eq!(actual, expected);
    for prefix in actual {
        let retained = snapshot.resolve_bypass(prefix).unwrap();
        assert_eq!(retained.row.route.destination, prefix);
        assert_eq!(retained.row.flags[0], 0);
        snapshot.verify(&retained).unwrap();
    }
    // Discovery does not remove, adopt or rewrite the native local-delivery rows.
    assert_eq!(snapshot.rows(), rows);
    assert!(snapshot.resolve_host(ip("255.255.255.255")).is_err());
    assert!(snapshot
        .resolve_host(ip("fe80::4d76:53b2:9dde:bc19"))
        .is_err());
}

#[test]
fn exact_owned_host_shadow_is_removed_before_selecting_underlying_gateway() {
    let shadow = row("10.0.0.1/32", 7, Some("192.0.2.99"), 0);
    let base = row("0.0.0.0/0", 7, Some("192.0.2.1"), 10);
    let snapshot = capture(
        vec![shadow.clone(), base.clone()],
        vec![interface(7, Family::V4, 1)],
    );
    let filtered = snapshot.without_owned_rows(&[shadow]).unwrap();
    assert_eq!(
        filtered.resolve_host(ip("10.0.0.1")).unwrap().path.row,
        base
    );
    assert_eq!(filtered.proofs(), snapshot.proofs());
    assert_eq!(snapshot.rows().len(), 2);
}

#[test]
fn special_lan_bypass_needs_exact_live_physical_evidence_and_unambiguous_scope() {
    for prefix in ["224.0.0.0/4", "255.255.255.255/32", "fe80::/64", "ff00::/8"] {
        let net: ipnet::IpNet = prefix.parse().unwrap();
        let family = Family::of(net.addr());
        let good = row(prefix, 7, None, 256);
        let record = interface(7, family, 25);
        let before = capture(vec![good.clone()], vec![record.clone()]);
        let retained = before.resolve_bypass(net).unwrap();
        for mutation in 0..6 {
            let mut changed = good.clone();
            let mut record = record.clone();
            match mutation {
                0 => changed.valid_lifetime = 0,
                1 => changed.flags[0] = 1,
                2 => record.oper_status = 2,
                3 => record.status_flags = 0,
                4 => {
                    changed.route.gateway = Some(if family == Family::V4 {
                        ip("192.0.2.1")
                    } else {
                        ip("fe80::1")
                    })
                }
                _ => {
                    changed.route.destination = if family == Family::V4 {
                        "0.0.0.0/0"
                    } else {
                        "::/0"
                    }
                    .parse()
                    .unwrap()
                }
            }
            let after = capture(vec![changed], vec![record]);
            assert!(
                after.resolve_bypass(net).is_err(),
                "{prefix} mutation {mutation}"
            );
            assert!(after.verify(&retained).is_err());
        }
        let ambiguous = capture(
            vec![good, row(prefix, 8, None, 256)],
            vec![record, interface(8, family, 25)],
        );
        assert_eq!(
            ambiguous.resolve_bypass(net).unwrap_err(),
            DiscoveryError::Ambiguous
        );
    }
}

#[test]
fn bypass_keeps_host_and_default_selection_and_whole_prefix_checks() {
    let default = row("0.0.0.0/0", 7, Some("192.0.2.1"), 10);
    let narrow = row("192.168.0.0/24", 7, None, 1);
    let snapshot = capture(
        vec![default.clone(), narrow],
        vec![interface(7, Family::V4, 25)],
    );
    for prefix in ["0.0.0.0/0", "203.0.113.1/32"] {
        assert_eq!(
            snapshot
                .resolve_bypass(prefix.parse().unwrap())
                .unwrap()
                .row,
            default
        );
    }
    assert!(snapshot
        .resolve_bypass("192.168.0.0/16".parse().unwrap())
        .is_err());
    assert!(snapshot
        .resolve_bypass("192.168.0.1/24".parse().unwrap())
        .is_err());
    assert_eq!(
        snapshot
            .resolve_bypass("::/0".parse().unwrap())
            .unwrap_err(),
        DiscoveryError::NoRoute
    );
}

#[test]
fn lan_bypass_does_not_override_a_better_unicast_route_or_hide_a_tie() {
    let on_link = row("192.168.3.0/24", 7, None, 256);
    let routed = row("192.168.3.0/24", 8, Some("192.0.2.1"), 10);
    let destination = on_link.route.destination;
    let records = vec![interface(7, Family::V4, 25), interface(8, Family::V4, 25)];
    let snapshot = capture(vec![on_link.clone(), routed.clone()], records.clone());
    assert_eq!(snapshot.resolve_bypass(destination).unwrap().row, routed);
    let mut tied = routed;
    tied.route.metric = 256;
    let snapshot = capture(vec![on_link, tied], records);
    assert_eq!(
        snapshot.resolve_bypass(destination).unwrap_err(),
        DiscoveryError::Ambiguous
    );
}
#[test]
fn foreign_equal_prefix_on_other_interface_is_not_excluded() {
    let own = row("10.0.0.1/32", 7, Some("192.0.2.1"), 0);
    let foreign = row("10.0.0.1/32", 8, Some("198.51.100.1"), 1);
    let snapshot = capture(
        vec![own.clone(), foreign.clone()],
        vec![interface(7, Family::V4, 1), interface(8, Family::V4, 1)],
    );
    assert_eq!(
        snapshot
            .without_owned_rows(&[own])
            .unwrap()
            .resolve_host(ip("10.0.0.1"))
            .unwrap()
            .path
            .row,
        foreign
    );
}
#[test]
fn owned_exclusion_rejects_replacement_metadata_duplicate_and_missing_identity() {
    let own = row("10.0.0.1/32", 7, Some("192.0.2.1"), 0);
    for mutation in 0..4 {
        let mut actual = own.clone();
        let mut rows = vec![];
        let mut interfaces = vec![interface(7, Family::V4, 1)];
        match mutation {
            0 => actual.origin += 1,
            1 => rows.push(own.clone()),
            2 => actual.route.gateway = Some(ip("192.0.2.2")),
            _ => interfaces[0].if_type = 131,
        }
        rows.push(actual);
        let snapshot = capture(rows, interfaces);
        assert!(snapshot.without_owned_rows(&[own.clone()]).is_err());
    }
    let snapshot = capture(vec![], vec![interface(7, Family::V4, 1)]);
    assert!(snapshot
        .without_owned_rows(&[own.clone()])
        .unwrap()
        .rows()
        .is_empty());
    assert!(capture(vec![], vec![]).without_owned_rows(&[own]).is_err());
}

#[test]
fn defaults_are_per_family_and_use_combined_metric_without_overflow() {
    let rows = vec![
        row("0.0.0.0/0", 7, Some("192.0.2.1"), 1),
        row("0.0.0.0/0", 8, Some("198.51.100.1"), 5),
        row("::/0", 8, Some("fe80::1"), 3),
    ];
    let snapshot = capture(
        rows.clone(),
        vec![
            interface(7, Family::V4, 100),
            interface(8, Family::V4, 2),
            interface(8, Family::V6, 10),
        ],
    );
    assert_eq!(
        snapshot.default_route(Family::V4).unwrap().unwrap().row,
        rows[1]
    );
    assert_eq!(
        snapshot.default_route(Family::V6).unwrap().unwrap().row,
        rows[2]
    );
    let snapshot = capture(
        vec![
            row("0.0.0.0/0", 7, None, u32::MAX),
            row("0.0.0.0/0", 8, None, 3),
        ],
        vec![
            interface(7, Family::V4, u32::MAX),
            interface(8, Family::V4, 1),
        ],
    );
    assert_eq!(
        snapshot
            .default_route(Family::V4)
            .unwrap()
            .unwrap()
            .proof
            .identity
            .index,
        8
    );
}

#[test]
fn longest_prefix_lan_beats_cheaper_default_and_resolves_on_link_next_hop() {
    let lan = row("192.168.10.0/24", 8, None, 100);
    let snapshot = capture(
        vec![row("0.0.0.0/0", 7, Some("192.0.2.1"), 1), lan.clone()],
        vec![interface(7, Family::V4, 1), interface(8, Family::V4, 100)],
    );
    let host = snapshot.resolve_host(ip("192.168.10.99")).unwrap();
    assert_eq!(host.path.row, lan);
    assert_eq!(
        host.path.row.route.gateway.unwrap_or(host.destination),
        ip("192.168.10.99")
    );
    assert_eq!(host.destination, ip("192.168.10.99"));
}

#[test]
fn missing_ipv6_does_not_fall_back_to_ipv4_or_invent_default() {
    let snapshot = capture(
        vec![row("0.0.0.0/0", 7, Some("192.0.2.1"), 1)],
        vec![interface(7, Family::V4, 1)],
    );
    assert!(snapshot.default_route(Family::V6).unwrap().is_none());
    assert_eq!(
        snapshot.resolve_host(ip("2001:db8::5")).unwrap_err(),
        DiscoveryError::NoRoute
    );
    let local = capture(
        vec![row("2001:db8::/64", 7, None, 1)],
        vec![interface(7, Family::V6, 1)],
    );
    assert!(local.default_route(Family::V6).unwrap().is_none());
    assert!(local.resolve_host(ip("2001:db8::5")).is_ok());
}

#[test]
fn equal_best_different_egress_or_gateway_fails_closed_in_any_order() {
    for second_index in [7, 8] {
        let mut rows = vec![
            row("0.0.0.0/0", 7, Some("192.0.2.1"), 5),
            row("0.0.0.0/0", second_index, Some("192.0.2.2"), 5),
        ];
        for _ in 0..2 {
            let snapshot = capture(
                rows.clone(),
                vec![interface(7, Family::V4, 1), interface(8, Family::V4, 1)],
            );
            assert_eq!(
                snapshot.default_route(Family::V4).unwrap_err(),
                DiscoveryError::Ambiguous
            );
            assert_eq!(
                snapshot.resolve_host(ip("203.0.113.9")).unwrap_err(),
                DiscoveryError::Ambiguous
            );
            rows.reverse();
        }
    }
}

#[test]
fn tunnel_ppp_down_virtual_and_ambiguous_interfaces_are_never_physical() {
    let good = interface(7, Family::V4, 50);
    let foreign = interface(8, Family::V4, 1);
    let mut rejected = vec![];
    for kind in [23, 131, 24, 1] {
        let mut r = foreign.clone();
        r.if_type = kind;
        rejected.push(r);
    }
    let mut r = foreign.clone();
    r.tunnel_type = 13;
    rejected.push(r);
    let mut r = foreign.clone();
    r.oper_status = 2;
    rejected.push(r);
    for flags in [0, 3, 0x81, 0x11, 0x21] {
        let mut r = foreign.clone();
        r.status_flags = flags;
        rejected.push(r);
    }
    for foreign in rejected {
        let snapshot = capture(
            vec![
                row("0.0.0.0/0", 7, Some("192.0.2.1"), 50),
                row("203.0.113.9/32", 8, None, 0),
            ],
            vec![good.clone(), foreign],
        );
        assert_eq!(
            snapshot
                .resolve_host(ip("203.0.113.9"))
                .unwrap()
                .path
                .proof
                .identity
                .index,
            7
        );
        assert_eq!(snapshot.rows().len(), 2); // retain the complete input, not just selected routes
        assert_eq!(snapshot.proofs().len(), 1);
    }
}

#[test]
fn ethernet_wifi_and_both_wwan_kinds_are_accepted_with_hardware_proof() {
    for kind in [6, 71, 243, 244] {
        let mut record = interface(7, Family::V4, 5);
        record.if_type = kind;
        assert!(capture(vec![row("0.0.0.0/0", 7, None, 1)], vec![record])
            .default_route(Family::V4)
            .unwrap()
            .is_some());
    }
}

#[test]
fn exact_owned_identity_and_nelomai_aliases_are_excluded() {
    let good = interface(7, Family::V4, 1);
    let routes = vec![row("0.0.0.0/0", 7, None, 1)];
    let snapshot =
        PhysicalSnapshot::new(routes.clone(), vec![good.clone()], &[good.proof.identity]).unwrap();
    assert!(snapshot.default_route(Family::V4).unwrap().is_none());
    let mut stale = good.proof.identity;
    stale.luid += 1;
    assert!(
        PhysicalSnapshot::new(routes.clone(), vec![good.clone()], &[stale])
            .unwrap()
            .default_route(Family::V4)
            .unwrap()
            .is_some()
    );
    for alias in ["Nelomai", "nelomai-latest-A", " NeLoMaI stable B "] {
        let mut named = good.clone();
        named.alias = alias.into();
        assert!(capture(routes.clone(), vec![named])
            .default_route(Family::V4)
            .unwrap()
            .is_none());
    }
}

#[test]
fn both_endpoints_resolve_independently_and_keep_full_route_metadata() {
    let mut a = row("203.0.113.5/32", 7, Some("192.0.2.1"), 11);
    a.protocol = 16;
    a.origin = 2;
    a.site_prefix_length = 8;
    a.valid_lifetime = 300;
    a.preferred_lifetime = 200;
    a.flags = [0, 1, 1, 0];
    let b = row("2001:db8:9::/64", 8, Some("fe80::2"), 19);
    let snapshot = capture(
        vec![a.clone(), b.clone()],
        vec![interface(7, Family::V4, 3), interface(8, Family::V6, 4)],
    );
    let first = snapshot.resolve_host(ip("203.0.113.5")).unwrap();
    let second = snapshot.resolve_host(ip("2001:db8:9::5")).unwrap();
    assert_eq!(first.path.row, a);
    assert_eq!(second.path.row, b);
    assert_eq!(first.path.row.route.gateway, Some(ip("192.0.2.1")));
    assert_eq!(second.path.row.route.gateway, Some(ip("fe80::2")));
    assert_eq!(second.path.proof.identity.index, 8); // explicit zone for link-local gateway
}

#[test]
fn scopeless_link_local_or_nonunicast_host_is_rejected_not_guessed() {
    let snapshot = capture(
        vec![
            row("::/0", 7, Some("fe80::1"), 1),
            row("0.0.0.0/0", 7, None, 1),
        ],
        vec![interface(7, Family::V6, 1), interface(7, Family::V4, 1)],
    );
    for host in [
        "fe80::1",
        "ff02::1",
        "::",
        "::1",
        "::ffff:192.0.2.1",
        "224.0.0.1",
        "255.255.255.255",
        "0.0.0.0",
        "127.0.0.1",
    ] {
        assert_eq!(
            snapshot.resolve_host(ip(host)).unwrap_err(),
            DiscoveryError::Invalid
        );
    }
}

#[test]
fn fresh_verification_rejects_index_reuse_guid_metric_or_route_metadata_change() {
    let original = row("0.0.0.0/0", 7, Some("192.0.2.1"), 1);
    let record = interface(7, Family::V4, 3);
    let old = capture(vec![original.clone()], vec![record.clone()]);
    let path = old.default_route(Family::V4).unwrap().unwrap();
    assert!(old.verify(&path).is_ok());
    for change in 0..5 {
        let mut r = record.clone();
        let mut route = original.clone();
        match change {
            0 => {
                r.proof.identity.luid += 1;
                route.luid += 1;
            }
            1 => r.proof.identity.guid[0] += 1,
            2 => r.proof.metric += 1,
            3 => route.protocol += 1,
            _ => route.valid_lifetime -= 1,
        }
        assert_eq!(
            capture(vec![route], vec![r]).verify(&path).unwrap_err(),
            DiscoveryError::Stale
        );
    }
    assert_eq!(
        capture(vec![], vec![]).verify(&path).unwrap_err(),
        DiscoveryError::Stale
    );
}

#[test]
fn missing_or_conflicting_interface_evidence_and_malformed_rows_fail_closed() {
    let route = row("0.0.0.0/0", 7, None, 1);
    assert!(PhysicalSnapshot::new(vec![route.clone()], vec![], &[]).is_err());
    let good = interface(7, Family::V4, 1);
    let mut different = good.clone();
    different.proof.identity.guid[0] += 1;
    assert!(
        PhysicalSnapshot::new(vec![route.clone()], vec![good.clone(), different], &[]).is_err()
    );
    let mut bad = route.clone();
    bad.luid += 1;
    assert!(PhysicalSnapshot::new(vec![bad], vec![good.clone()], &[]).is_err());
    let mut bad = route.clone();
    bad.route.gateway = Some(ip("2001:db8::1"));
    assert!(PhysicalSnapshot::new(vec![bad], vec![good.clone()], &[]).is_err());
    let mut bad = route;
    bad.route.destination = "192.0.2.1/24".parse().unwrap();
    assert!(PhysicalSnapshot::new(vec![bad], vec![good], &[]).is_err());
}

#[test]
fn table_bound_is_enforced_before_selection() {
    let routes = vec![row("0.0.0.0/0", 7, None, 1); member_routes::MAX_TABLE_ROWS + 1];
    assert!(PhysicalSnapshot::new(routes, vec![interface(7, Family::V4, 1)], &[]).is_err());
}

#[test]
fn nonwinning_ties_do_not_hide_a_unique_more_specific_route() {
    let specific = row("203.0.113.0/24", 9, Some("192.0.2.9"), 999);
    let mut rows = vec![
        row("0.0.0.0/0", 7, None, 1),
        row("0.0.0.0/0", 8, None, 1),
        specific.clone(),
    ];
    for _ in 0..3 {
        let snapshot = capture(
            rows.clone(),
            vec![
                interface(7, Family::V4, 1),
                interface(8, Family::V4, 1),
                interface(9, Family::V4, 1),
            ],
        );
        assert_eq!(
            snapshot.resolve_host(ip("203.0.113.5")).unwrap().path.row,
            specific
        );
        rows.rotate_left(1);
    }
}

#[test]
fn fresh_verification_checks_all_retained_row_fields_and_physical_eligibility() {
    let original = row("0.0.0.0/0", 7, Some("192.0.2.1"), 10);
    let record = interface(7, Family::V4, 3);
    let path = capture(vec![original.clone()], vec![record.clone()])
        .default_route(Family::V4)
        .unwrap()
        .unwrap();
    for mutation in 0..11 {
        let mut route = original.clone();
        let mut record = record.clone();
        match mutation {
            0 => route.route.destination = "0.0.0.0/1".parse().unwrap(),
            1 => route.route.gateway = Some(ip("192.0.2.2")),
            2 => route.route.metric += 1,
            3 => route.origin += 1,
            4 => route.site_prefix_length += 1,
            5 => route.preferred_lifetime -= 1,
            6 => route.flags[1] = 1,
            7 => route.flags[2] = 1,
            8 => route.flags[3] = 1,
            9 => record.oper_status = 2,
            _ => record.alias = "Nelomai".into(),
        }
        assert_eq!(
            capture(vec![route], vec![record])
                .verify(&path)
                .unwrap_err(),
            DiscoveryError::Stale
        );
    }
}

#[test]
fn expired_or_loopback_rows_cannot_be_selected_even_on_a_physical_interface() {
    let mut expired = row("203.0.113.1/32", 7, None, 0);
    expired.valid_lifetime = 0;
    let mut loopback = row("203.0.113.2/32", 7, None, 0);
    loopback.flags[0] = 1;
    let default = row("0.0.0.0/0", 7, Some("192.0.2.1"), 99);
    let snapshot = capture(
        vec![expired, loopback, default.clone()],
        vec![interface(7, Family::V4, 1)],
    );
    for host in ["203.0.113.1", "203.0.113.2"] {
        assert_eq!(snapshot.resolve_host(ip(host)).unwrap().path.row, default);
    }
}
