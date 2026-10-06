use super::*;

use crate::{
    member_carrier::{Intent, Provenance},
    member_carrier_guard as policy,
    member_carrier_native_ownership::{Binding, Context, Role},
    member_carrier_pair as pair, member_owner as owner,
};
use nelomai_client_tunnel::redundancy::Slot;
use nelomai_client_tunnel::{DesktopTunnelOptions, TunnelTransport};
use nelomai_contracts::dispatcher::{EngineIdentity, TunnelSlot};
fn parent_fixture() -> (Context, pair::Record) {
    let scope = nelomai_client_tunnel::redundancy::SessionScope {
        runtime: RuntimeSlot::Stable,
        runtime_generation: 2,
        session_id: "11111111-1111-4111-8111-111111111111".into(),
        connection_generation: 3,
    };
    let provenance = Provenance {
        boot_id: [8; 16],
        network_epoch: 7,
        runtime: EngineIdentity {
            slot: RuntimeSlot::Stable,
            runtime_version: "0.3.3".into(),
            container_version: "0.3.3".into(),
            runtime_contract_version: 1,
            manifest_sha256: "a".repeat(64),
        },
    };
    let context = Context {
        intent: Intent {
            scope: scope.clone(),
            addresses: vec!["10.7.0.2/32".parse().unwrap()],
        },
        provenance: provenance.clone(),
        bindings: std::array::from_fn(|i| {
            Binding {
            role: [Role::RoleCarrier,Role::MemberA,Role::MemberB][i], guid: [(i+1) as u8;16],
            name: ["carrier-c","member-a","member-b"][i].into(),
            registry_path: [r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{01010101-0101-0101-0101-010101010101}",
                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{02020202-0202-0202-0202-020202020202}",
                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{03030303-0303-0303-0303-030303030303}"][i].into(),
        }
        }),
    };
    let c = owner::InterfaceProof {
        index: 7,
        luid: 90,
        guid: [1; 16],
    };
    let a = owner::InterfaceProof {
        index: 8,
        luid: 91,
        guid: [2; 16],
    };
    let member = pair::MemberState {
        owner: owner::Record {
            intent: owner::Intent {
                scope: scope.clone(),
                slot: TunnelSlot::A,
                transport: TunnelTransport::WireGuard,
                engine: crate::test_engine_path("wireguard.exe"),
                config_sha256: [4; 32],
            },
            phase: owner::Phase::Running,
            proof: Some(owner::NativeProof {
                interface: a,
                process: owner::ProcessProof {
                    pid: 50,
                    creation_time: 100,
                },
            }),
            retired_proof: None,
            previous_config_sha256: None,
        },
        lease_id: "22222222-2222-4222-8222-222222222222".into(),
        probe: nelomai_contracts::RedundantHealthProbe {
            kind: nelomai_contracts::HealthProbeKind::DnsA,
            target_ipv4: "1.1.1.1".parse().unwrap(),
            query_name: "example.com".into(),
            timeout_ms: 2000,
        },
        endpoint: "192.0.2.11".parse().unwrap(),
        allowed: vec!["0.0.0.0/0".parse().unwrap()],
        peer: [3; 32],
    };
    let base = policy::Model::new(
        scope.clone(),
        policy::Carrier {
            identity: policy::Identity {
                scope: scope.clone(),
                proof: c,
            },
            sources: vec!["10.7.0.2".parse().unwrap()],
        },
        [
            Some(policy::Member {
                identity: policy::Identity {
                    scope: scope.clone(),
                    proof: a,
                },
                probes: vec![],
            }),
            None,
        ],
        None,
    )
    .unwrap()
    .without_permits()
    .unwrap();
    let mut captured = base.expected.clone();
    captured.sublayer.as_mut().unwrap().weight = 41;
    let base = base
        .readback_after(&policy::Model::empty(scope.clone()).unwrap(), &captured)
        .unwrap();
    let dns = dns::Snapshot {
        interface: dns::OwnedInterface {
            scope: scope.clone(),
            guid: c.guid,
            luid: c.luid,
            index: c.index,
        },
        settings: dns::Settings {
            version: 1,
            flags: 0,
            domain: None,
            name_server: None,
            search_list: None,
            registration_enabled: 0,
            register_adapter_name: 0,
            enable_llmnr: 0,
            query_adapter_name: 0,
            profile_name_server: None,
        },
    };
    let baseline = pair::NetworkSnapshot {
        routes: vec![],
        dns: Some(dns.clone()),
    };
    let target = pair::NetworkSnapshot {
        routes: vec![
            route("0.0.0.0/1", 8, 0, None),
            route("128.0.0.0/1", 8, 0, None),
            route("1.1.1.1/32", 8, 1, None),
            route("192.0.2.11/32", 20, 10, Some("192.0.2.1")),
        ],
        dns: Some(dns.with_servers(&["1.1.1.1".parse().unwrap()]).unwrap()),
    };
    let r = pair::Record {
        version: 2,
        scope,
        provenance,
        revision: 10,
        phase: pair::Phase::Starting,
        addresses: context.intent.addresses.clone(),
        dns: vec!["1.1.1.1".parse().unwrap()],
        carrier: Some(c),
        members: [Some(member), None],
        active: None,
        options: Some(DesktopTunnelOptions::default()),
        guard: base,
        pending_guard: None,
        pending: Some(pair::Effect::Network),
        network: Some(pair::NetworkState {
            baseline: baseline.clone(),
            current: baseline,
            pending: Some(target),
        }),
        stop_stage: 0,
        operation: Some(pair::Operation::Start(Slot::A)),
    };
    r.validate().unwrap();
    (context, r)
}
fn route(dst: &str, index: u32, metric: u32, gateway: Option<&str>) -> RouteValue {
    RouteValue {
        destination: dst.parse().unwrap(),
        interface: index,
        scope: RouteScope::WindowsInterface(index),
        metric,
        gateway: gateway.map(|s| s.parse().unwrap()),
    }
}
fn before_network() -> (Context, pair::Record, Carrier, dns::Snapshot) {
    let (c, mut r) = parent_fixture();
    r.network = None;
    r.pending = None;
    let carrier = r.guard.carrier.clone().unwrap();
    let mut b = baseline();
    b.interface.scope = r.scope.clone();
    (c, r, carrier, b)
}
// Break: using an acknowledged live Capture record from the wrong boot, runtime,
// scope, C proof, phase or after even a partial Network child intent.
#[test]
fn capture_record_is_exact_original_starting_before_every_network_child() {
    let (c, r, carrier, _) = before_network();
    assert!(compare_capture_record(&c, &r, &carrier).is_ok());
    for fault in 0..7 {
        let mut x = r.clone();
        match fault {
            0 => x.provenance.boot_id = [9; 16],
            1 => x.scope.runtime_generation += 1,
            2 => x.carrier.as_mut().unwrap().luid += 1,
            3 => x.phase = pair::Phase::Closing,
            4 => x.network = parent_fixture().1.network,
            5 => {
                x.guard = policy::Model::new(
                    x.scope.clone(),
                    carrier.clone(),
                    x.guard.members.clone(),
                    Some(Slot::A),
                )
                .unwrap()
            }
            _ => x.pending = Some(pair::Effect::HoldProbe(Slot::A)),
        }
        assert!(
            compare_capture_record(&c, &x, &carrier).is_err(),
            "fault {fault}"
        );
    }
}
// Break: refusing truthful untouched baseline after C retirement, or treating
// historic Pair network metadata as an SDK restoration ACK.
#[test]
fn retired_record_allows_no_exchange_history_or_exact_restored_network_only_at_stage_ten() {
    let (c, mut r, carrier, b) = before_network();
    r.phase = pair::Phase::Closing;
    r.operation = None;
    r.active = None;
    r.stop_stage = 10;
    r.pending = Some(pair::Effect::Guard);
    r.pending_guard = Some(
        policy::ExchangePlan::new(&r.guard, &policy::Model::empty(r.scope.clone()).unwrap())
            .unwrap(),
    );
    assert!(compare_retired_record(&c, &r, &carrier, &b).is_ok());
    let restored = pair::NetworkSnapshot {
        routes: vec![],
        dns: Some(b.clone()),
    };
    r.network = Some(pair::NetworkState {
        baseline: restored.clone(),
        current: restored,
        pending: None,
    });
    assert!(compare_retired_record(&c, &r, &carrier, &b).is_ok());
    for fault in 0..6 {
        let mut x = r.clone();
        match fault {
            0 => x.stop_stage = 9,
            1 => x.stop_stage = 1,
            2 => x.pending = None,
            3 => {
                x.network.as_mut().unwrap().pending = Some(pair::NetworkSnapshot {
                    routes: vec![],
                    dns: Some(b.clone()),
                })
            }
            4 => {
                x.network
                    .as_mut()
                    .unwrap()
                    .current
                    .dns
                    .as_mut()
                    .unwrap()
                    .settings
                    .enable_llmnr = 1
            }
            _ => x
                .network
                .as_mut()
                .unwrap()
                .current
                .routes
                .push(route("1.1.1.1/32", 8, 1, None)),
        }
        assert!(
            compare_retired_record(&c, &x, &carrier, &b).is_err(),
            "fault {fault}"
        );
    }
}
// Break: a weak registration retaining the SDK root forever or replacing equal
// baseline data with a different original capability.
#[test]
fn original_read_alias_and_weak_liveness_do_not_retain_or_adopt_another_capture() {
    let slot = CaptureSlot::new();
    let first = Rc::new(baseline());
    slot.capture(|s| s.retain(first.clone())).unwrap();
    let read = slot.read().unwrap();
    let weak = Rc::downgrade(&read);
    assert!(Rc::ptr_eq(&read, &first));
    assert!(!Rc::ptr_eq(&read, &Rc::new(baseline())));
    drop(read);
    drop(first);
    assert!(weak.upgrade().is_some());
    drop(slot);
    assert!(weak.upgrade().is_none());
}

use crate::{
    member_carrier_guard::Identity,
    member_owner::InterfaceProof,
    member_routes::{NativeProof, Row},
};
use nelomai_client_tunnel::redundancy::{
    network::{RouteScope, RouteValue},
    SessionScope,
};
use nelomai_contracts::RuntimeSlot;
use std::panic::{catch_unwind, AssertUnwindSafe};
fn carrier() -> Carrier {
    Carrier {
        identity: Identity {
            scope: SessionScope {
                runtime: RuntimeSlot::Stable,
                runtime_generation: 7,
                session_id: "11111111-1111-4111-8111-111111111111".into(),
                connection_generation: 9,
            },
            proof: InterfaceProof {
                index: 7,
                luid: 90,
                guid: [1; 16],
            },
        },
        sources: vec!["10.7.0.2".parse().unwrap()],
    }
}
fn baseline() -> dns::Snapshot {
    let c = carrier();
    dns::Snapshot {
        interface: dns::OwnedInterface {
            scope: c.identity.scope,
            guid: [1; 16],
            luid: 90,
            index: 7,
        },
        settings: dns::Settings {
            version: 1,
            flags: 0,
            domain: Some("original.example".into()),
            name_server: None,
            search_list: Some("original.example,private.example".into()),
            registration_enabled: 0,
            register_adapter_name: 0,
            enable_llmnr: 0,
            query_adapter_name: 0,
            profile_name_server: None,
        },
    }
}
fn facts() -> NetworkFacts {
    NetworkFacts {
        current: vec![],
        pending: None,
        carrier_rows: vec![],
        egress_rows: [vec![], vec![]],
        active: None,
        pending_active: None,
        stopping: false,
    }
}
fn onlink() -> Row {
    let mut row = Row::static_route(
        RouteValue {
            destination: "10.7.0.2/32".parse().unwrap(),
            scope: RouteScope::WindowsInterface(7),
            interface: 7,
            gateway: None,
            metric: 0,
        },
        NativeProof { index: 7, luid: 90 },
    );
    row.protocol = 2;
    row.flags[0] = 1;
    row
}
// Break: rejecting the actual newly-created C's SDK DNS baseline before any child/owned route.
#[test]
fn initial_sdk_baseline_accepts_no_child_or_owned_routes_without_granting_an_exchange() {
    assert!(compare_initial(&carrier(), &facts(), &baseline(), None).is_ok());
    let mut f = facts();
    f.carrier_rows.push(onlink());
    assert!(compare_initial(&carrier(), &f, &baseline(), None).is_ok());
    f.carrier_rows = ["10.7.0.2/32", "224.0.0.0/4"]
        .into_iter()
        .enumerate()
        .map(|(i, destination)| {
            let mut row = onlink();
            row.route.destination = destination.parse().unwrap();
            row.flags = if i == 0 { [1, 1, 0, 0] } else { [0, 1, 0, 0] };
            if i == 1 {
                row.origin = 1;
            }
            row
        })
        .collect();
    for i in 0..2 {
        let mut incidental = onlink();
        incidental.route.interface = 8 + i as u32;
        incidental.route.scope = RouteScope::WindowsInterface(incidental.route.interface);
        incidental.luid = 91 + i as u64;
        incidental.route.destination = "224.0.0.0/4".parse().unwrap();
        incidental.origin = 1;
        incidental.flags = [0, 1, 0, 0];
        f.egress_rows[i].push(incidental);
    }
    assert!(compare_initial(&carrier(), &f, &baseline(), None).is_ok());
}
// Break: treating a protected child, active/pending/stopping journal or member route as fresh.
#[test]
fn initial_capture_refuses_every_child_network_or_route_obligation() {
    for fault in 0..8 {
        let mut f = facts();
        let mut raw = None;
        let mut dns = baseline();
        match fault {
            0 => raw = Some(b"actual protected child".as_slice()),
            1 => f.pending = Some(vec![]),
            2 => f.active = Some(nelomai_client_tunnel::redundancy::Slot::A),
            3 => f.pending_active = Some(nelomai_client_tunnel::redundancy::Slot::B),
            4 => f.stopping = true,
            5 => {
                f.pending = Some(vec![super::super::member_carrier_network::RouteFact {
                    expected: onlink().route,
                    actual: None,
                }])
            }
            6 => {
                let row = onlink();
                f.current
                    .push(super::super::member_carrier_network::RouteFact {
                        expected: row.route.clone(),
                        actual: Some(row),
                    });
            }
            _ => dns.interface.guid = [2; 16],
        }
        assert!(
            compare_initial(&carrier(), &f, &dns, raw).is_err(),
            "fault {fault}"
        );
    }
}
// Break: accepting equal C names/indexes from a foreign GUID/LUID/scope or unsupported complete DNS metadata.
#[test]
fn initial_dns_baseline_requires_full_original_interface_and_supported_empty_settings() {
    for fault in 0..9 {
        let mut d = baseline();
        match fault {
            0 => d.interface.guid = [2; 16],
            1 => d.interface.luid += 1,
            2 => d.interface.index += 1,
            3 => d.interface.scope.connection_generation += 1,
            4 => d.settings.version = 2,
            5 => d.settings.flags = 1 << 63,
            6 => d.settings.name_server = Some("1.1.1.1".into()),
            7 => d.settings.enable_llmnr = 2,
            _ => d.settings.domain = Some("bad\0domain".into()),
        }
        assert!(
            compare_initial(&carrier(), &facts(), &d, None).is_err(),
            "fault {fault}"
        );
    }
}
// Break: inventing an exchange ACK from a zero-length ACK list after an unacknowledged SDK attempt.
#[test]
fn untouched_and_restored_are_distinct_and_unknown_attempts_never_become_untouched() {
    let b = baseline();
    let mut selected = b.clone();
    selected.settings.name_server = Some("1.1.1.1".into());
    assert_eq!(
        classify_dns(&b, 0, &[]).unwrap(),
        DnsBaselineDisposition::NeverExchanged
    );
    assert!(classify_dns(&b, 1, &[]).is_err());
    assert_eq!(
        classify_dns(&b, 2, &[selected.clone(), b.clone()]).unwrap(),
        DnsBaselineDisposition::RestoredByLastAck
    );
    assert!(classify_dns(&b, 2, &[selected.clone()]).is_err());
    assert!(classify_dns(&b, 1, &[selected]).is_err());
    assert!(classify_dns(&b, 0, &[b.clone()]).is_err());
}
// Break: comparing only server text or accepting a prior baseline ACK instead of the LAST actual ACK.
#[test]
fn last_restore_ack_compares_every_dns_field_and_exact_original_history() {
    let b = baseline();
    let mut active = b.clone();
    active.settings.name_server = Some("1.1.1.1".into());
    assert!(classify_dns(&b, 2, &[b.clone(), active]).is_err());
    for fault in 0..5 {
        let mut foreign = b.clone();
        match fault {
            0 => foreign.interface.guid = [9; 16],
            1 => foreign.interface.scope.runtime_generation += 1,
            2 => foreign.settings.search_list = Some("foreign.example".into()),
            3 => foreign.settings.flags = 2,
            _ => foreign.settings.enable_llmnr = 1,
        }
        assert!(classify_dns(&b, 1, &[foreign]).is_err(), "fault {fault}");
    }
}
// Break: dropping first SDK capture on Err/unwind or requiring successful outer postflight to read retained facts.
#[test]
fn actual_capture_callback_retains_first_original_before_error_or_unwind_postflight() {
    struct Tracked(Rc<Cell<usize>>);
    impl Drop for Tracked {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1)
        }
    }
    for unwind in [false, true] {
        let drops = Rc::new(Cell::new(0));
        let slot = CaptureSlot::new();
        let result = catch_unwind(AssertUnwindSafe(|| {
            slot.capture(|sink| {
                sink.retain(Rc::new(Tracked(drops.clone())))?;
                if unwind {
                    panic!("actual postflight unwind")
                } else {
                    Err(conflict())
                }
            })
        }));
        assert_eq!(drops.get(), 0);
        assert!(slot.read().is_ok());
        assert!(slot.failed.get());
        if unwind {
            assert!(result.is_err())
        } else {
            assert!(result.unwrap().is_err())
        }
        drop(slot);
        assert_eq!(drops.get(), 1);
    }
}
// Break: replacing the first original with equal-shaped data or reentering and catching denial to fake success.
#[test]
fn duplicate_and_caught_reentry_deny_without_replacing_retained_original() {
    let slot = CaptureSlot::new();
    let original = Rc::new(7);
    assert!(slot.capture(|s| s.retain(original.clone())).is_ok());
    assert!(slot.capture(|s| s.retain(Rc::new(7))).is_err());
    assert!(Rc::ptr_eq(&slot.read().unwrap(), &original));
    let slot = CaptureSlot::new();
    assert!(slot
        .capture(|s| {
            s.retain(original.clone())?;
            assert!(s.capture(|_| Ok(())).is_err());
            Ok(())
        })
        .is_err());
    assert!(slot.failed.get());
    assert!(Rc::ptr_eq(&slot.read().unwrap(), &original));
}
// Break: returning a successful capture with no real SDK callback or accepting a second callback in the same bracket.
#[test]
fn missing_or_duplicate_sdk_callback_cannot_mint_baseline() {
    let slot = CaptureSlot::<u32>::new();
    assert!(slot.capture(|_| Ok(())).is_err());
    assert!(slot.read().is_err());
    let slot = CaptureSlot::new();
    assert!(slot
        .capture(|s| {
            s.retain(Rc::new(7))?;
            assert!(s.retain(Rc::new(8)).is_err());
            Ok(())
        })
        .is_err());
    assert_eq!(*slot.read().unwrap(), 7);
}
