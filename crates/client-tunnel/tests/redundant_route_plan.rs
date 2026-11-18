use nelomai_client_tunnel::redundancy::{network::*, route_plan::*, Slot};
fn member(slot: Slot, index: u32) -> MemberRoutes {
    MemberRoutes {
        slot,
        interface: index,
        allowed: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
        probe: "9.9.9.9".parse().unwrap(),
    }
}
#[test]
fn primary_first_and_reserve_install_preserve_exact_active_routes() {
    let primary = member(Slot::A, 10);
    let a = member_route_plan(Slot::A, std::slice::from_ref(&primary), &[], 0).unwrap();
    let b = member_route_plan(Slot::A, &[primary, member(Slot::B, 20)], &[], 0).unwrap();
    assert_eq!(
        a.iter().filter(|r| r.scope == RouteScope::Global).count(),
        4
    );
    for route in &a {
        assert!(b.contains(route));
    }
    assert_eq!(b.len(), a.len() + 1);
    assert_eq!(
        b.last().unwrap(),
        &RouteValue {
            destination: "9.9.9.9/32".parse().unwrap(),
            scope: RouteScope::Member(20),
            interface: 20,
            gateway: None,
            metric: 0
        }
    );
    assert!(b
        .iter()
        .filter(|r| r.scope == RouteScope::Global)
        .all(|r| r.interface == 10));
}
#[test]
fn promotion_moves_both_families_but_preserves_each_bound_probe() {
    let routes =
        member_route_plan(Slot::B, &[member(Slot::A, 10), member(Slot::B, 20)], &[], 0).unwrap();
    let globals = routes
        .iter()
        .filter(|r| r.scope == RouteScope::Global)
        .collect::<Vec<_>>();
    assert_eq!(globals.len(), 4);
    assert!(globals.iter().all(|r| r.interface == 20));
    assert!(globals
        .iter()
        .any(|r| r.destination.to_string() == "8000::/1"));
    assert!(routes.iter().any(|r| r.scope == RouteScope::Member(10)));
    assert!(routes.iter().any(|r| r.scope == RouteScope::Member(20)));
}
#[test]
fn broad_physical_exclusion_cannot_be_shadowed_by_split_default() {
    let routes = member_route_plan(
        Slot::A,
        &[member(Slot::A, 10)],
        &["0.0.0.0/1".parse().unwrap()],
        0,
    )
    .unwrap();
    let global_v4 = routes
        .iter()
        .filter(|r| r.scope == RouteScope::Global && r.destination.addr().is_ipv4())
        .collect::<Vec<_>>();
    assert_eq!(global_v4.len(), 1);
    assert_eq!(global_v4[0].destination.to_string(), "128.0.0.0/1");
    assert!(routes.iter().any(|r| r.scope == RouteScope::Member(10))); // probe still via VPN
}
#[test]
fn invalid_members_or_probe_outside_allowed_ips_are_rejected() {
    assert!(member_route_plan(Slot::A, &[member(Slot::B, 20)], &[], 0).is_err());
    assert!(
        member_route_plan(Slot::A, &[member(Slot::A, 10), member(Slot::A, 20)], &[], 0).is_err()
    );
    assert!(
        member_route_plan(Slot::A, &[member(Slot::A, 10), member(Slot::B, 10)], &[], 0).is_err()
    );
    let mut narrow = member(Slot::B, 20);
    narrow.allowed = vec!["192.0.2.0/24".parse().unwrap()];
    assert!(member_route_plan(Slot::A, &[member(Slot::A, 10), narrow], &[], 0).is_err());
}

#[test]
fn unix_plan_excludes_pinned_peers_lan_and_user_ranges_within_original_allowed_ips() {
    let mut m = member(Slot::A, 10);
    m.allowed = ["192.0.2.0/24", "2001:db8::/124"]
        .map(|n| n.parse().unwrap())
        .to_vec();
    m.probe = "192.0.2.7".parse().unwrap();
    let holes = [
        "192.0.2.7/32",
        "192.0.2.64/26",
        "2001:db8::f/128",
        "203.0.113.1/32",
    ]
    .map(|n| n.parse().unwrap());
    let data = unix_member_route_plan(Slot::A, &[m], &holes, &[], 0).unwrap();
    let covered = |addr: std::net::IpAddr| {
        data.iter()
            .any(|r| r.scope == RouteScope::Global && r.destination.contains(&addr))
    };
    for i in 0..=255 {
        assert_eq!(
            covered(std::net::Ipv4Addr::new(192, 0, 2, i).into()),
            i != 7 && !(64..128).contains(&i)
        );
    }
    for i in 0..=16 {
        assert_eq!(
            covered(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i).into()),
            i < 15
        );
    }
    assert!(!covered("203.0.113.2".parse().unwrap()));
    assert!(data
        .iter()
        .any(|r| r.scope == RouteScope::Member(10) && r.destination == holes[0]));
}

#[test]
fn carving_a_lan_endpoint_preserves_the_entire_connected_os_route() {
    let all = ["0.0.0.0/0".parse().unwrap()];
    let hole = ["192.168.1.7/32".parse().unwrap()];
    let lan: ipnet::IpNet = "192.168.1.0/24".parse().unwrap();
    let plan = tunnel_destinations_preserving(&all, &hole, &[lan]).unwrap();
    assert!(plan
        .iter()
        .all(|net| !lan.contains(net) && !net.contains(&lan)));
    assert!(plan
        .iter()
        .any(|net| net.contains(&"192.168.2.7".parse::<std::net::IpAddr>().unwrap())));
    // A configured /25 originally beat the OS /24.
    let narrow = ["192.168.1.0/25".parse().unwrap()];
    assert_eq!(
        tunnel_destinations_preserving(&narrow, &hole, &[lan]).unwrap(),
        tunnel_destinations(&narrow, &hole).unwrap()
    );
}

#[test]
fn full_tunnel_preserves_existing_half_defaults_when_subdividing() {
    let allowed = ["0.0.0.0/0", "::/0"].map(|n| n.parse().unwrap());
    let existing = ["0.0.0.0/1", "8000::/1"].map(|n| n.parse().unwrap());
    let holes = ["20.2.3.4/32", "a000::1/128"].map(|n| n.parse().unwrap());
    let plan = tunnel_destinations_preserving(&allowed, &holes, &existing).unwrap();
    for route in existing {
        assert!(plan.iter().all(|net| !route.contains(net)));
    }
    for ip in ["130.1.2.3", "2001:db8::2"] {
        let ip = ip.parse::<std::net::IpAddr>().unwrap();
        assert!(plan.iter().any(|net| net.contains(&ip)));
    }
}

#[test]
fn explicit_allowed_prefix_conflicts_even_when_subdivided() {
    let existing = ["203.0.113.0/24".parse().unwrap()];
    let exclusions = ["203.0.113.9/32".parse().unwrap()];
    let error = tunnel_destinations_preserving(&existing, &exclusions, &existing).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
}

#[test]
fn oversized_complement_fails_without_widening_routes_or_partial_output() {
    let holes: Vec<_> = (0..1024)
        .map(|i| {
            ipnet::IpNet::from(std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                (i as u128) << 111,
            )))
        })
        .collect();
    assert!(tunnel_destinations(&["::/0".parse().unwrap()], &holes).is_err());
}

#[test]
fn explicit_nested_and_adjacent_allowed_prefixes_keep_their_original_priority() {
    let allowed = ["0.0.0.0/0", "192.168.1.0/25", "192.168.1.128/25"].map(|n| n.parse().unwrap());
    let os: ipnet::IpNet = "192.168.1.0/24".parse().unwrap();
    let endpoint = "192.168.1.9/32".parse().unwrap();
    let plan = tunnel_destinations_preserving(&allowed, &[endpoint], &[os]).unwrap();
    for addr in [1, 8, 10, 130, 254] {
        let ip = std::net::IpAddr::from(std::net::Ipv4Addr::new(192, 168, 1, addr));
        assert!(plan
            .iter()
            .any(|net| net.contains(&ip) && net.prefix_len() > os.prefix_len()));
    }
    assert!(plan.iter().all(|net| !net.contains(&endpoint)));
}
