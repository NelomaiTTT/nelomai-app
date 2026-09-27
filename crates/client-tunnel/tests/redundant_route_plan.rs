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
