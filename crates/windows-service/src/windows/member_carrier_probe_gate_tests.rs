use super::*;
use crate::{
    member_carrier::{Intent, Provenance},
    member_carrier_native_ownership::{Binding, Role},
    member_owner as owner,
    member_physical::{InterfaceRecord, PhysicalProof},
};
use nelomai_client_tunnel::{DesktopTunnelOptions, TunnelTransport};
use nelomai_contracts::{
    dispatcher::{EngineIdentity, TunnelSlot},
    RuntimeSlot,
};

fn network_fixture() -> (Context, pair::Record) {
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
            // The prior process identity remains factual after a fresh Start.
            retired_proof: Some(owner::NativeProof {
                interface: a,
                process: owner::ProcessProof {
                    pid: 40,
                    creation_time: 90,
                },
            }),
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
fn physical() -> PhysicalSnapshot {
    let row = Row::static_route(
        route("0.0.0.0/0", 20, 10, Some("192.0.2.1")),
        NativeProof {
            index: 20,
            luid: 200,
        },
    );
    PhysicalSnapshot::new(
        vec![row],
        vec![InterfaceRecord {
            proof: PhysicalProof {
                identity: InterfaceIdentity {
                    index: 20,
                    luid: 200,
                    guid: [20; 16],
                },
                family: Family::V4,
                metric: 5,
            },
            alias: "Ethernet".into(),
            if_type: 6,
            tunnel_type: 0,
            oper_status: 1,
            status_flags: 1,
        }],
        &[],
    )
    .unwrap()
}

use std::panic::{catch_unwind, AssertUnwindSafe};
fn fixture() -> (Context, pair::Record) {
    let (context, mut r) = network_fixture();
    let n = r.network.as_mut().unwrap();
    n.current = n.pending.take().unwrap();
    r.pending = Some(pair::Effect::HoldProbe(Slot::A));
    r.validate().unwrap();
    (context, r)
}
fn tuple() -> ProbeTuple {
    ProbeTuple {
        source: "10.7.0.2".parse().unwrap(),
        source_port: 40123,
        target: "1.1.1.1".parse().unwrap(),
        target_port: 53,
        protocol: 17,
    }
}
fn usable(mut r: pair::Record) -> pair::Record {
    let mut members = r.guard.members.clone();
    members[0].as_mut().unwrap().probes = vec![tuple()];
    r.guard = policy::Model::new(
        r.scope.clone(),
        r.guard.carrier.clone().unwrap(),
        members,
        Some(Slot::A),
    )
    .unwrap()
    .inherit_sublayer_weight(&r.guard)
    .unwrap();
    r.pending = Some(pair::Effect::Data(Slot::A));
    r
}
fn row(context: &Context, role: usize) -> rows::Record {
    let key = rows::RowKey {
        index: if role == 0 { 7 } else { 8 },
        luid: if role == 0 { 90 } else { 91 },
    };
    let baseline = rows::Snapshot {
        interface: rows::InterfaceRow {
            key,
            policy: rows::InterfacePolicy {
                advertising: false,
                forwarding: false,
                weak_host_send: false,
                weak_host_receive: false,
                automatic_metric: false,
                neighbor_unreachability: true,
                managed_address_configuration: false,
                other_stateful_configuration: false,
                advertise_default_route: false,
                router_discovery: 0,
                dad_transmits: 1,
                base_reachable_time: 30000,
                retransmit_time: 1000,
                path_mtu_discovery_timeout: 600000,
                link_local_behavior: 0,
                link_local_timeout: 0,
                zone_indices: [0; 16],
                metric: 5,
                mtu: 1420,
                disable_default_routes: true,
            },
            observed: rows::InterfaceObserved {
                site_prefix_length: 0,
                max_reassembly_size: 0,
                interface_identifier: 0,
                min_router_advertisement_interval: 200,
                max_router_advertisement_interval: 600,
                connected: true,
                supports_wake_up_patterns: false,
                supports_neighbor_discovery: true,
                supports_router_discovery: true,
                reachable_time: 27000,
                transmit_offload: 0,
                receive_offload: 0,
            },
        },
        address: None,
    };
    let mut current = baseline.clone();
    let mut creation = None;
    if role == 0 {
        let a = rows::AddressRow {
            key,
            policy: rows::AddressPolicy {
                address: [10, 7, 0, 2],
                prefix_origin: 1,
                suffix_origin: 1,
                valid_lifetime: u32::MAX,
                preferred_lifetime: u32::MAX,
                on_link_prefix_length: 32,
                skip_as_source: false,
            },
            observed: rows::AddressObserved {
                dad_state: 4,
                scope_id: 0,
                creation_timestamp: 123456789,
            },
        };
        current.address = Some(a.clone());
        creation = Some(a);
    }
    current.interface.policy.weak_host_send = true;
    current.interface.policy.weak_host_receive = true;
    let r = rows::Record {
        version: 1,
        domain: rows::DOMAIN.into(),
        binding: rows::Binding {
            scope: context.intent.scope.clone(),
            boot_id: context.provenance.boot_id,
            runtime: context.provenance.runtime.clone(),
            network_epoch: context.provenance.network_epoch,
            role: if role == 0 {
                rows::Role::Carrier
            } else {
                rows::Role::MemberA
            },
            guid: context.bindings[role].guid,
            name: context.bindings[role].name.clone(),
            key,
            address: [10, 7, 0, 2],
        },
        revision: 3,
        phase: rows::Phase::Captured,
        baseline,
        current,
        pending: None,
        creation,
    };
    r.validate().unwrap();
    r
}
fn resources<'a>(c: &'a rows::Record, a: &'a rows::Record) -> RowFacts<'a> {
    [
        Some((&c.binding, c, &c.current)),
        Some((&a.binding, a, &a.current)),
        None,
    ]
}
fn retire_fixture() -> (
    Context,
    pair::Record,
    rows::Record,
    super::super::member_carrier_members::ClosedMemberBinding,
) {
    let (context, mut r) = fixture();
    let mut b = r.members[0].clone().unwrap();
    b.owner.intent.slot = TunnelSlot::B;
    b.owner.intent.config_sha256 = [6; 32];
    b.owner.proof = Some(owner::NativeProof {
        interface: owner::InterfaceProof {
            index: 9,
            luid: 92,
            guid: [3; 16],
        },
        process: owner::ProcessProof {
            pid: 60,
            creation_time: 110,
        },
    });
    b.owner.retired_proof.as_mut().unwrap().interface = b.owner.proof.unwrap().interface;
    b.lease_id = "33333333-3333-4333-8333-333333333333".into();
    b.probe.target_ipv4 = "9.9.9.9".parse().unwrap();
    b.endpoint = "192.0.2.12".parse().unwrap();
    b.peer = [5; 32];
    let closed = super::super::member_carrier_members::ClosedMemberBinding {
        intent: b.owner.intent.clone(),
        proof: b.owner.proof.unwrap(),
    };
    r.members[1] = Some(b);
    let both = policy::Model::new(
        r.scope.clone(),
        r.guard.carrier.clone().unwrap(),
        [
            r.guard.members[0].clone(),
            Some(policy::Member {
                identity: policy::Identity {
                    scope: r.scope.clone(),
                    proof: closed.proof.interface,
                },
                probes: vec![],
            }),
        ],
        Some(Slot::A),
    )
    .unwrap()
    .without_permits()
    .unwrap()
    .inherit_sublayer_weight(&r.guard)
    .unwrap();
    let desired = r.guard.clone();
    r.guard = both;
    r.phase = pair::Phase::Running;
    r.active = Some(Slot::A);
    r.operation = Some(pair::Operation::Retire(Slot::B));
    r.pending = Some(pair::Effect::Guard);
    r.pending_guard = Some(policy::ExchangePlan::new(&r.guard, &desired).unwrap());
    r.validate().unwrap();
    let mut stopped = row(&context, 1);
    stopped.binding.role = rows::Role::MemberB;
    stopped.binding.guid = [3; 16];
    stopped.binding.name = "member-b".into();
    stopped.binding.key = rows::RowKey { index: 9, luid: 92 };
    stopped.baseline.interface.key = stopped.binding.key;
    stopped.current = stopped.baseline.clone();
    stopped.phase = rows::Phase::Stopped;
    stopped.validate().unwrap();
    (context, r, stopped, closed)
}
fn guard_resources<'a>(
    c: &'a rows::Record,
    a: &'a rows::Record,
    b: &'a rows::Record,
) -> GuardRowFacts<'a> {
    [
        Some((&c.binding, c, Some(&c.current))),
        Some((&a.binding, a, Some(&a.current))),
        Some((&b.binding, b, None)),
    ]
}

// Break: dropping the actual stopped target facts because observed is None,
// then requiring a live metric/SDK sample for the already-closed original.
#[test]
fn retire_base_accepts_exact_closed_target_without_metric_or_probe_permission() {
    let (c, r, stopped, closed) = retire_fixture();
    let carrier = row(&c, 0);
    let active = row(&c, 1);
    let desired = &r.pending_guard.as_ref().unwrap().base;
    assert_eq!(compare_guard_target(&c, &r, desired), Ok(()));
    let metrics = compare_guard_rows(
        &c,
        &r,
        desired,
        guard_resources(&carrier, &active, &stopped),
        [None, Some(&closed)],
    )
    .unwrap();
    assert_eq!(
        metrics
            .iter()
            .map(|m| (m.interface, m.ipv6, m.metric))
            .collect::<Vec<_>>(),
        vec![(8, false, 5)]
    );
    assert!(compare_rows(&c, &r, resources(&carrier, &active)).is_err());
    assert!(compare_stage(&c, &r, Purpose::Use(Slot::B)).is_err());
}

// Break: keeping historical original rows after members[B]=None makes the
// next deny-base/active-A permit exchange require B again or grant it a metric.
#[test]
fn removed_member_history_remains_factual_during_active_other_reinstall() {
    let (c, mut r, stopped, closed) = retire_fixture();
    r.guard = r.pending_guard.as_ref().unwrap().base.clone();
    r.members[1] = None;
    let desired = usable(r.clone()).guard;
    r.pending = Some(pair::Effect::Guard);
    r.pending_guard = Some(policy::ExchangePlan::new(&r.guard, &desired).unwrap());
    let carrier = row(&c, 0);
    let active = row(&c, 1);
    for permits in [false, true] {
        let target = if permits {
            desired.clone()
        } else {
            r.pending_guard.as_ref().unwrap().base.clone()
        };
        if permits {
            r.guard = r.pending_guard.as_ref().unwrap().base.clone();
        }
        r.validate().unwrap();
        let metrics = compare_guard_rows(
            &c,
            &r,
            &target,
            guard_resources(&carrier, &active, &stopped),
            [None, Some(&closed)],
        )
        .unwrap();
        assert_eq!(
            metrics
                .iter()
                .map(|m| (m.interface, m.ipv6, m.metric))
                .collect::<Vec<_>>(),
            vec![(8, false, 5)]
        );
        assert!(compare_guard_rows(
            &c,
            &r,
            &target,
            guard_resources(&carrier, &active, &stopped),
            [None, None]
        )
        .is_err());
        let mut foreign = closed.clone();
        foreign.proof.interface.luid = 999;
        assert!(compare_guard_rows(
            &c,
            &r,
            &target,
            guard_resources(&carrier, &active, &stopped),
            [None, Some(&foreign)]
        )
        .is_err());
        let mut drift = stopped.clone();
        drift.current.interface.policy.metric += 1;
        assert!(compare_guard_rows(
            &c,
            &r,
            &target,
            guard_resources(&carrier, &active, &drift),
            [None, Some(&closed)]
        )
        .is_err());
        let mut no_ack = guard_resources(&carrier, &active, &stopped);
        no_ack[2] = None;
        assert!(compare_guard_rows(&c, &r, &target, no_ack, [None, Some(&closed)]).is_err());
    }
}

// Break: treating None observation, a stopped journal or foreign equal-looking
// history as authority, or removing old bases outside exact Retire-other-active.
#[test]
fn closed_guard_rows_deny_missing_cap_foreign_original_and_partial_retirement() {
    let (c, r, stopped, closed) = retire_fixture();
    let carrier = row(&c, 0);
    let active = row(&c, 1);
    let desired = &r.pending_guard.as_ref().unwrap().base;
    assert!(compare_guard_rows(
        &c,
        &r,
        desired,
        guard_resources(&carrier, &active, &stopped),
        [None, None]
    )
    .is_err());
    for fault in 0..18 {
        let mut x = r.clone();
        let mut ack = stopped.clone();
        let mut history = closed.clone();
        match fault {
            0 => history.intent.scope.connection_generation += 1,
            1 => history.intent.slot = TunnelSlot::A,
            2 => history.proof.process.creation_time += 1,
            3 => history.intent.config_sha256 = [9; 32],
            4 => history.proof.interface.index += 1,
            5 => ack.binding.boot_id = [9; 16],
            6 => ack.binding.network_epoch += 1,
            7 => ack.binding.guid = [4; 16],
            8 => ack.binding.name = "foreign-b".into(),
            9 => ack.phase = rows::Phase::Captured,
            10 => ack.current.interface.policy.weak_host_receive = true,
            11 => ack.baseline.interface.policy.weak_host_send = true,
            12 => ack.current.interface.policy.metric += 1,
            13 => x.active = Some(Slot::B),
            14 => x.operation = Some(pair::Operation::Rebind),
            15 => x.phase = pair::Phase::Starting,
            16 => x
                .network
                .as_mut()
                .unwrap()
                .current
                .routes
                .push(route("9.9.9.9/32", 9, 2, None)),
            _ => x.stop_stage = 1,
        }
        assert!(
            compare_guard_rows(
                &c,
                &x,
                desired,
                guard_resources(&carrier, &active, &ack),
                [None, Some(&history)]
            )
            .is_err(),
            "fault {fault}"
        );
    }
    let mut facts = guard_resources(&carrier, &active, &stopped);
    facts[2] = Some((&stopped.binding, &stopped, Some(&stopped.current)));
    assert!(compare_guard_rows(&c, &r, desired, facts, [None, Some(&closed)]).is_err());
    let empty = policy::Model::empty(r.scope.clone()).unwrap();
    assert!(compare_guard_rows(
        &c,
        &r,
        &empty,
        guard_resources(&carrier, &active, &stopped),
        [None, Some(&closed)]
    )
    .is_err());
}
fn network(r: &pair::Record) -> super::super::member_carrier_network::NetworkFacts {
    let current = r
        .network
        .as_ref()
        .unwrap()
        .current
        .routes
        .iter()
        .map(|route| super::super::member_carrier_network::RouteFact {
            expected: route.clone(),
            actual: Some(Row::static_route(
                route.clone(),
                NativeProof {
                    index: route.interface,
                    luid: if route.interface == 8 { 91 } else { 200 },
                },
            )),
        })
        .collect::<Vec<_>>();
    super::super::member_carrier_network::NetworkFacts {
        current,
        pending: None,
        active: Some(Slot::A),
        pending_active: None,
        stopping: false,
    }
}
// Break: denying actual Starting HoldProbe or treating generic request/JSON as an open grant.
#[test]
fn open_requires_exact_current_hold_probe_operation_without_any_allows() {
    let (c, r) = fixture();
    assert_eq!(compare_stage(&c, &r, Purpose::Open(Slot::A)), Ok(()));
    let mut running = r.clone();
    running.phase = pair::Phase::Running;
    running.active = Some(Slot::A);
    running.operation = Some(pair::Operation::Attach(Slot::A));
    assert_eq!(compare_stage(&c, &running, Purpose::Open(Slot::A)), Ok(()));
    running.operation = Some(pair::Operation::Rebind);
    let original = running.members[0].as_ref().unwrap().owner.clone();
    assert_eq!(compare_stage(&c, &running, Purpose::Open(Slot::A)), Ok(()));
    assert!(running.members[0].as_ref().unwrap().owner == original);
    for pending in [
        None,
        Some(pair::Effect::ReleaseProbes),
        Some(pair::Effect::HoldProbe(Slot::B)),
    ] {
        let mut wrong = running.clone();
        wrong.pending = pending;
        assert!(compare_stage(&c, &wrong, Purpose::Open(Slot::A)).is_err());
    }
    let mut closed = running.clone();
    let owner = &mut closed.members[0].as_mut().unwrap().owner;
    owner.phase = crate::member_owner::Phase::Stopped;
    owner.retired_proof = owner.proof.take();
    assert!(compare_stage(&c, &closed, Purpose::Open(Slot::A)).is_err());
    for fault in 0..9 {
        let mut x = r.clone();
        match fault {
            0 => x.pending = None,
            1 => x.pending = Some(pair::Effect::Data(Slot::A)),
            2 => x.phase = pair::Phase::Fresh,
            3 => x.operation = None,
            4 => x.stop_stage = 1,
            5 => x.provenance.network_epoch += 1,
            6 => x.scope.connection_generation += 1,
            7 => x.guard = usable(r.clone()).guard,
            _ => x.pending_guard = Some(policy::ExchangePlan::new(&r.guard, &r.guard).unwrap()),
        }
        assert!(
            compare_stage(&c, &x, Purpose::Open(Slot::A)).is_err(),
            "fault {fault}"
        );
    }
    assert!(compare_stage(&c, &r, Purpose::Open(Slot::B)).is_err());
}
// Break: denying fresh Data use, Running observation or allowing a withdrawn/foreign stage.
#[test]
fn use_allows_exact_starting_data_and_running_observation_not_withdrawal() {
    let (c, r) = fixture();
    let data = usable(r.clone());
    assert_eq!(compare_stage(&c, &data, Purpose::Use(Slot::A)), Ok(()));
    assert_eq!(compare_tuple(&data, Slot::A, &tuple()), Ok(()));
    let mut live = data.clone();
    live.phase = pair::Phase::Running;
    live.active = Some(Slot::A);
    live.operation = None;
    live.pending = None;
    assert_eq!(compare_stage(&c, &live, Purpose::Use(Slot::A)), Ok(()));
    for fault in 0..6 {
        let mut x = live.clone();
        match fault {
            0 => x.phase = pair::Phase::Closing,
            1 => x.pending = Some(pair::Effect::Network),
            2 => x.pending = Some(pair::Effect::Data(Slot::B)),
            3 => x.guard = r.guard.clone(),
            4 => x.operation = Some(pair::Operation::Retire(Slot::A)),
            _ => x.carrier.as_mut().unwrap().luid += 1,
        }
        assert!(
            compare_stage(&c, &x, Purpose::Use(Slot::A)).is_err(),
            "fault {fault}"
        );
    }
}
// Break: accepting provided tuple as resource permission or changing port/protocol/endpoint.
#[test]
fn open_ack_tuple_is_compared_but_never_adopted_as_use_permission() {
    let (_, r) = fixture();
    assert_eq!(compare_open_tuple(&r, Slot::A, &tuple()), Ok(()));
    assert!(compare_tuple(&r, Slot::A, &tuple()).is_err());
    let mut t = tuple();
    t.target = "1.1.1.2".parse().unwrap();
    assert!(compare_open_tuple(&r, Slot::A, &t).is_err());
}
#[test]
fn foreign_tuple_fields_or_missing_exact_guard_tuple_are_denied() {
    let (_, r) = fixture();
    let data = usable(r);
    for fault in 0..6 {
        let mut t = tuple();
        match fault {
            0 => t.source = "10.7.0.3".parse().unwrap(),
            1 => t.source_port = 0,
            2 => t.target = "1.1.1.2".parse().unwrap(),
            3 => t.target_port = 54,
            4 => t.protocol = 6,
            _ => t.source_port += 1,
        }
        assert!(compare_tuple(&data, Slot::A, &t).is_err(), "fault {fault}");
    }
    assert!(compare_tuple(&data, Slot::B, &tuple()).is_err());
}
// Break: equating no permits with no bases, partial filter keys, or unowned priority.
#[test]
fn guard_requires_full_original_snapshot_captured_priority_and_correct_permit_mode() {
    let (_, r) = fixture();
    assert_eq!(
        compare_guard(&r, Purpose::Open(Slot::A), &r.guard.expected),
        Ok(())
    );
    for fault in 0..4 {
        let mut s = r.guard.expected.clone();
        match fault {
            0 => {
                s.filters.pop();
            }
            1 => s.sublayer.as_mut().unwrap().weight += 1,
            2 => s.filters[0].action = policy::Action::Permit,
            _ => s.egress[0].as_mut().unwrap().proof.luid += 1,
        }
        assert!(
            compare_guard(&r, Purpose::Open(Slot::A), &s).is_err(),
            "fault {fault}"
        );
    }
    let data = usable(r);
    assert_eq!(
        compare_guard(&data, Purpose::Use(Slot::A), &data.guard.expected),
        Ok(())
    );
    assert!(compare_guard(&data, Purpose::Preparing, &data.guard.expected).is_err());
}
// Break: releasing before withdrawal, after row restoration, or reviving live Source in Closing.
#[test]
fn preparing_and_closing_are_exact_distinct_withdrawn_cleanup_stages() {
    let (c, mut r) = fixture();
    r.phase = pair::Phase::Running;
    r.active = Some(Slot::A);
    r.operation = Some(pair::Operation::Rebind);
    r.pending = Some(pair::Effect::ReleaseProbes);
    assert_eq!(compare_stage(&c, &r, Purpose::Preparing), Ok(()));
    assert!(compare_stage(&c, &r, Purpose::Closing).is_err());
    r.phase = pair::Phase::Closing;
    r.active = None;
    r.operation = None;
    r.stop_stage = 1;
    assert_eq!(compare_stage(&c, &r, Purpose::Closing), Ok(()));
    assert!(compare_stage(&c, &r, Purpose::Preparing).is_err());
    for stage in [2, 3, 4, 8, 9, 10, 12] {
        r.stop_stage = stage;
        assert!(compare_stage(&c, &r, Purpose::Closing).is_err());
    }
    r.stop_stage = 0;
    r.pending = Some(pair::Effect::Guard);
    let before = usable(fixture().1).guard;
    r.guard = before.without_permits().unwrap();
    r.pending_guard = Some(policy::ExchangePlan::new(&before, &r.guard).unwrap());
    assert_eq!(compare_stage(&c, &r, Purpose::Closing), Ok(()));
}
// Break: granting from saved weak flags without original full row ACK or current live readiness.
#[test]
fn full_rows_require_carrier_created_ready_and_exact_owned_weak_member_policy() {
    let (c, r) = fixture();
    let carrier = row(&c, 0);
    let member = row(&c, 1);
    let metrics = compare_rows(&c, &r, resources(&carrier, &member)).unwrap();
    assert_eq!(metrics.len(), 1);
    assert_eq!((metrics[0].interface, metrics[0].metric), (8, 5));
    let mut preweak = carrier.clone();
    preweak.current.interface.policy = preweak.baseline.interface.policy.clone();
    assert!(compare_rows(&c, &r, resources(&preweak, &member)).is_err());
    assert!(compare_rows_for(&c, &r, resources(&preweak, &member), RowMode::Bases).is_ok());
    for fault in 0..9 {
        let mut a = member.clone();
        let mut carrier = carrier.clone();
        match fault {
            0 => a.current.interface.policy.weak_host_receive = false,
            1 => a.baseline.interface.policy.weak_host_send = true,
            2 => a.current.interface.policy.forwarding = true,
            3 => a.binding.network_epoch += 1,
            4 => a.phase = rows::Phase::Closing,
            5 => carrier.creation = None,
            6 => carrier.current.address.as_mut().unwrap().observed.dad_state = 1,
            7 => carrier.current.interface.policy.weak_host_send = false,
            _ => a.current.address = carrier.current.address.clone(),
        }
        assert!(
            compare_rows(&c, &r, resources(&carrier, &a)).is_err(),
            "fault {fault}"
        );
    }
    let mut missing = resources(&carrier, &member);
    missing[1] = None;
    assert!(compare_rows(&c, &r, missing).is_err());
}
// Break: accepting arbitrary valid-shaped route JSON instead of the full endpoint/split plan.
#[test]
fn network_requires_exact_current_route_dns_endpoint_and_physical_plan() {
    let (_, r) = fixture();
    let p = physical();
    let m = [InterfaceMetric {
        interface: 8,
        ipv6: false,
        metric: 5,
    }];
    let expected = vec![
        route("0.0.0.0/1", 8, 0, None),
        route("128.0.0.0/1", 8, 0, None),
        route("1.1.1.1/32", 8, 1, None),
        route("192.0.2.11/32", 20, 10, Some("192.0.2.1")),
    ];
    let mut actual = network_plan(&r, &p, &m).unwrap();
    actual.sort_by_key(|r| (r.destination, r.interface));
    let mut expected = expected;
    expected.sort_by_key(|r| (r.destination, r.interface));
    assert_eq!(actual, expected);
    let f = network(&r);
    let d = r.network.as_ref().unwrap().current.dns.as_ref().unwrap();
    assert_eq!(
        compare_network(&r, &f, d, Some(b"actual protected sampler bytes"), &p, &m),
        Ok(())
    );
    for fault in 0..8 {
        let mut f = network(&r);
        let mut d = d.clone();
        match fault {
            0 => {
                f.current.pop();
            }
            1 => f.current[0].actual.as_mut().unwrap().protocol += 1,
            2 => f.pending = Some(vec![]),
            3 => f.active = Some(Slot::B),
            4 => d.settings.enable_llmnr += 1,
            5 => f.current[0].actual.as_mut().unwrap().luid += 1,
            6 => f.stopping = true,
            _ => f.current[3].actual = None,
        }
        assert!(
            compare_network(&r, &f, &d, Some(b"bytes"), &p, &m).is_err(),
            "fault {fault}"
        );
    }
    assert!(compare_network(&r, &f, d, None, &p, &m).is_err());
    let mut wrong = r.clone();
    wrong.members[0].as_mut().unwrap().endpoint = "192.0.2.12".parse().unwrap();
    assert!(compare_network(&wrong, &f, d, Some(b"bytes"), &p, &m).is_err());
}
// Break: dropping a retained original before failed validation or replacing it with equal metadata.
#[test]
fn first_registration_retains_on_error_duplicate_and_unwind() {
    struct Tracked<'a>(&'a Cell<u32>);
    impl Drop for Tracked<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    for panic in [false, true] {
        let drops = Cell::new(0);
        let slot = Retained::new();
        let fence = Fence::new();
        let out = catch_unwind(AssertUnwindSafe(|| {
            slot.first(Tracked(&drops), &fence, |_| {
                if panic {
                    panic!("registration unwind")
                }
                Err(GuardError::Conflict)
            })
        }));
        if panic {
            assert!(out.is_err());
        } else {
            assert!(out.unwrap().is_err());
        }
        assert!(slot.value.borrow().is_some());
        assert_eq!(drops.get(), 0);
        assert!(fence.inspect(Purpose::Open(Slot::A), || Ok(())).is_err());
        drop(slot);
        assert_eq!(drops.get(), 1);
    }
    let slot = Retained::new();
    let fence = Fence::new();
    let original = std::rc::Rc::new(7);
    assert_eq!(slot.first(original.clone(), &fence, |_| Ok(())), Ok(()));
    assert!(slot.first(original.clone(), &fence, |_| Ok(())).is_err());
    assert!(std::rc::Rc::ptr_eq(
        slot.value.borrow().as_ref().unwrap(),
        &original
    ));
}
// Break: ignoring failure/caught reentry or granting forward again after cleanup.
#[test]
fn failure_unwind_and_reentry_keep_forward_revoked_without_claiming_cleanup_permission() {
    for fault in 0..3 {
        let f = Fence::new();
        let result = catch_unwind(AssertUnwindSafe(|| {
            f.inspect(Purpose::Open(Slot::A), || match fault {
                0 => Err(GuardError::Conflict),
                1 => panic!("authorization unwind"),
                _ => {
                    let _ = f.inspect(Purpose::Use(Slot::A), || Ok(()));
                    Ok(())
                }
            })
        }));
        if fault == 1 {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert!(f.inspect(Purpose::Use(Slot::A), || Ok(())).is_err());
        // This private serialization helper grants no native cleanup. The real
        // caller still authenticates exact Closing Pair + actual original pin.
        assert_eq!(f.inspect(Purpose::Closing, || Ok(())), Ok(()));
        assert!(f.inspect(Purpose::Open(Slot::A), || Ok(())).is_err());
    }
}
// Break: forcing a Guard callback through HoldProbe/Data or accepting a foreign/future target.
#[test]
fn guard_callback_has_distinct_full_plan_stage_and_never_a_port_grant() {
    let (c, mut r) = fixture();
    let desired = usable(r.clone()).guard;
    r.pending = Some(pair::Effect::Guard);
    r.pending_guard = Some(policy::ExchangePlan::new(&r.guard, &desired).unwrap());
    // Tuple-bearing deny base is a separate static commit BEFORE permits.
    assert!(compare_guard_target(&c, &r, &desired).is_err());
    r.guard = r
        .pending_guard
        .as_ref()
        .unwrap()
        .base
        .inherit_sublayer_weight(&r.guard)
        .unwrap();
    assert_eq!(compare_guard_target(&c, &r, &desired), Ok(()));
    assert!(compare_stage(&c, &r, Purpose::Use(Slot::A)).is_err());
    for fault in 0..5 {
        let mut x = r.clone();
        match fault {
            0 => x.pending = None,
            1 => x.pending_guard = None,
            2 => x.stop_stage = 1,
            3 => x.scope.connection_generation += 1,
            _ => x.provenance.boot_id = [9; 16],
        }
        assert!(
            compare_guard_target(&c, &x, &desired).is_err(),
            "fault {fault}"
        );
    }
    let mut wrong = desired.clone();
    wrong.members[0].as_mut().unwrap().identity.proof.luid += 1;
    assert!(compare_guard_target(&c, &r, &wrong).is_err());
}
// Break: requiring future weak-host/routes/ports before the first blocking base, or granting ports from baseline rows.
#[test]
fn first_blocking_guard_target_and_baseline_rows_are_not_port_permission() {
    let (c, mut r) = fixture();
    let base = policy::Model::new(
        r.scope.clone(),
        r.guard.carrier.clone().unwrap(),
        r.guard.members.clone(),
        None,
    )
    .unwrap()
    .without_permits()
    .unwrap();
    r.guard = policy::Model::empty(r.scope.clone()).unwrap();
    r.network = None;
    r.pending = Some(pair::Effect::Guard);
    r.pending_guard = Some(policy::ExchangePlan::new(&r.guard, &base).unwrap());
    assert_eq!(compare_guard_target(&c, &r, &base), Ok(()));
    let mut carrier = row(&c, 0);
    let mut member = row(&c, 1);
    carrier.current.interface.policy = carrier.baseline.interface.policy.clone();
    member.current = member.baseline.clone();
    assert!(compare_rows_for(&c, &r, resources(&carrier, &member), RowMode::Bases).is_ok());
    assert!(compare_rows(&c, &r, resources(&carrier, &member)).is_err());
    carrier.current.interface.policy.weak_host_send = true;
    assert!(compare_rows_for(&c, &r, resources(&carrier, &member), RowMode::Bases).is_err());
    carrier.current.interface.policy = carrier.baseline.interface.policy.clone();
    member.current.interface.policy.weak_host_send = true;
    assert!(compare_rows_for(&c, &r, resources(&carrier, &member), RowMode::Bases).is_err());
}
// Break: refusing retained Closing registration before withdrawal, or letting it authorize socket release/allows.
#[test]
fn closing_registration_can_precede_withdrawal_but_port_release_cannot() {
    let (c, mut r) = fixture();
    r = usable(r);
    let withdrawn = r.guard.without_permits().unwrap();
    r.phase = pair::Phase::Closing;
    r.operation = None;
    r.active = None;
    r.pending = Some(pair::Effect::Guard);
    r.pending_guard = Some(policy::ExchangePlan::new(&r.guard, &withdrawn).unwrap());
    assert_eq!(compare_closing_registration(&c, &r), Ok(()));
    assert_eq!(compare_guard_target(&c, &r, &withdrawn), Ok(()));
    assert!(compare_stage(&c, &r, Purpose::Closing).is_err());
    assert!(compare_guard_target(&c, &r, &r.guard).is_err());

    for member_phase in [owner::Phase::Prepared, owner::Phase::Running] {
        for stop_stage in [0, 1] {
            let mut partial = r.clone();
            partial.guard = policy::Model::empty(partial.scope.clone()).unwrap();
            partial.network = None;
            partial.pending_guard = None;
            partial.stop_stage = stop_stage;
            partial.pending = Some(if stop_stage == 0 {
                pair::Effect::Guard
            } else {
                pair::Effect::ReleaseProbes
            });
            let member = &mut partial.members[0].as_mut().unwrap().owner;
            member.phase = member_phase;
            if member_phase == owner::Phase::Prepared {
                member.proof = None;
            }
            partial.validate().unwrap();
            assert_eq!(
                compare_closing_registration(&c, &partial),
                Ok(()),
                "partial Closing {stop_stage}, {member_phase:?}"
            );
            for purpose in [
                Purpose::Closing,
                Purpose::Open(Slot::A),
                Purpose::Use(Slot::A),
            ] {
                assert!(compare_stage(&c, &partial, purpose).is_err());
            }
            assert!(compare_guard_target(&c, &partial, &partial.guard).is_err());
            let mut foreign = partial.clone();
            foreign.provenance.boot_id = [9; 16];
            assert!(compare_closing_registration(&c, &foreign).is_err());
            foreign = partial.clone();
            foreign.scope.connection_generation += 1;
            assert!(compare_closing_registration(&c, &foreign).is_err());
            let mut wrong_stage = partial.clone();
            wrong_stage.stop_stage = 2;
            assert!(compare_closing_registration(&c, &wrong_stage).is_err());
            if stop_stage == 0 {
                let mut wrong_plan = partial.clone();
                wrong_plan.pending_guard = r.pending_guard.clone();
                assert!(compare_closing_registration(&c, &wrong_plan).is_err());
            } else {
                let mut unexpected_plan = partial.clone();
                unexpected_plan.pending_guard =
                    Some(policy::ExchangePlan::new(&partial.guard, &partial.guard).unwrap());
                assert!(compare_closing_registration(&c, &unexpected_plan).is_err());
            }
        }
    }
}
// Break: requiring a future ExchangePlan to retain actual Closing before the
// normal close_permits ACK, or rejecting a factual already-withdrawn ACK.
#[test]
fn closing_registration_retains_normal_stop_and_withdrawn_lost_ack_without_rearming() {
    let (c, mut r) = fixture();
    r = usable(r);
    r.phase = pair::Phase::Closing;
    r.active = None;
    r.operation = None;
    r.pending = Some(pair::Effect::Guard);
    assert_eq!(compare_closing_registration(&c, &r), Ok(()));
    assert!(compare_stage(&c, &r, Purpose::Closing).is_err());
    let withdrawn = r.guard.without_permits().unwrap();
    r.pending_guard = Some(policy::ExchangePlan::new(&r.guard, &withdrawn).unwrap());
    r.guard = withdrawn;
    assert_eq!(compare_closing_registration(&c, &r), Ok(()));
    assert_eq!(compare_stage(&c, &r, Purpose::Closing), Ok(()));
    let mut foreign = r.clone();
    foreign.guard = fixture().1.guard;
    assert!(compare_closing_registration(&c, &foreign).is_err());

    let (_, mut r) = fixture();
    let desired = usable(r.clone()).guard;
    let plan = policy::ExchangePlan::new(&r.guard, &desired).unwrap();
    assert_eq!(plan.expected.expected, plan.base.expected);
    assert_ne!(plan.expected, plan.base);
    r.phase = pair::Phase::Closing;
    r.operation = None;
    r.active = None;
    r.pending = Some(pair::Effect::Guard);
    r.guard = plan.base.clone(); // Actual ACKed probe-bearing deny-only base.
    r.pending_guard = Some(plan.clone());
    assert_eq!(compare_closing_registration(&c, &r), Ok(()));
    assert_eq!(compare_stage(&c, &r, Purpose::Closing), Ok(()));
    let mut foreign = r.clone();
    foreign.guard.members[0].as_mut().unwrap().probes[0].source_port += 1;
    foreign.guard.validate().unwrap(); // Equal WFP snapshot is insufficient.
    assert!(compare_closing_registration(&c, &foreign).is_err());
    assert!(compare_stage(&c, &foreign, Purpose::Closing).is_err());

    let empty = policy::Model::empty(r.scope.clone()).unwrap();
    let unbound = policy::Model::new(
        r.scope.clone(),
        desired.carrier.clone().unwrap(),
        desired.members.clone(),
        desired.active,
    )
    .unwrap();
    let mut creation = policy::ExchangePlan::new(&empty, &unbound).unwrap();
    creation.captured_sublayer_weight = desired.assigned_sublayer_weight;
    creation.base = plan.base;
    creation.desired = desired;
    creation.validate().unwrap();
    r.pending_guard = Some(creation);
    assert_eq!(compare_closing_registration(&c, &r), Ok(()));
    assert_eq!(compare_stage(&c, &r, Purpose::Closing), Ok(()));
    r.guard.assigned_sublayer_weight = Some(42);
    r.guard.expected.sublayer.as_mut().unwrap().weight = 42;
    r.guard.validate().unwrap();
    assert!(compare_closing_registration(&c, &r).is_err());
    assert!(compare_stage(&c, &r, Purpose::Closing).is_err());
}
// Break: giving data permits with no actual canonical original/ACK, or from an
// equal-shaped provided tuple alone. Production joins supply both real facts.
#[test]
fn guard_probe_target_requires_actual_tuple_and_exact_original_registration_ack() {
    let (_, r) = fixture();
    let desired = usable(r.clone()).guard;
    let t = tuple();
    assert_eq!(
        compare_guard_probe(&r, &desired, Slot::A, Some(&t), Some(&t)),
        Ok(())
    );
    for (actual, ack) in [(None, Some(&t)), (Some(&t), None), (None, None)] {
        assert!(compare_guard_probe(&r, &desired, Slot::A, actual, ack).is_err());
    }
    let mut foreign = t.clone();
    foreign.source_port += 1;
    assert!(compare_guard_probe(&r, &desired, Slot::A, Some(&foreign), Some(&t)).is_err());
    assert!(compare_guard_probe(&r, &desired, Slot::A, Some(&t), Some(&foreign)).is_err());
    let no_probe = policy::Model::new(
        r.scope.clone(),
        r.guard.carrier.clone().unwrap(),
        r.guard.members.clone(),
        Some(Slot::A),
    )
    .unwrap()
    .inherit_sublayer_weight(&r.guard)
    .unwrap();
    assert!(compare_guard_probe(&r, &no_probe, Slot::A, None, None).is_err());
}
// Break: forcing sockets before a deny-only base, or letting an absent member
// take a live probe tuple from another canonical slot.
#[test]
fn blocking_base_probe_comparison_does_not_require_future_ports_or_adopt_foreign_slots() {
    let (_, r) = fixture();
    assert_eq!(
        compare_guard_probe(&r, &r.guard, Slot::A, None, None),
        Ok(())
    );
    assert_eq!(
        compare_guard_probe(&r, &r.guard, Slot::B, None, None),
        Ok(())
    );
    assert!(compare_guard_probe(&r, &r.guard, Slot::B, Some(&tuple()), Some(&tuple())).is_err());
}
// Break: invoking live Source/Guard from a retired callback, using foreign histories or wrong removal stage.
#[test]
fn retired_guard_callback_compares_exact_original_history_and_only_stage_ten_removal() {
    let (c, mut r) = fixture();
    r.phase = pair::Phase::Closing;
    r.operation = None;
    r.active = None;
    r.stop_stage = 10;
    r.pending = Some(pair::Effect::Guard);
    r.pending_guard = Some(
        policy::ExchangePlan::new(&r.guard, &policy::Model::empty(r.scope.clone()).unwrap())
            .unwrap(),
    );
    let carrier = r.guard.carrier.clone().unwrap();
    let identity = r.guard.members[0].as_ref().unwrap().identity.clone();
    assert_eq!(
        compare_retired_target(&c, &r, &carrier, [Some(&identity), None]),
        Ok(())
    );
    for stage in [0, 1, 8, 9, 11, 12] {
        let mut x = r.clone();
        x.stop_stage = stage;
        assert!(compare_retired_target(&c, &x, &carrier, [Some(&identity), None]).is_err());
    }
    let mut foreign = identity.clone();
    foreign.proof.luid += 1;
    assert!(compare_retired_target(&c, &r, &carrier, [Some(&foreign), None]).is_err());
    assert!(compare_retired_target(&c, &r, &carrier, [None, None]).is_err());
}
// Break: clearing enclosing serialization taint after a minimal capability check fails or unwinds.
#[test]
fn minimal_metadata_failure_is_sticky_without_recursing_into_effect_fence() {
    let f = Fence::new();
    assert_eq!(
        f.inspect(Purpose::Open(Slot::A), || checked_metadata(&f, || Ok(7))),
        Ok(7)
    );
    assert!(f
        .inspect(Purpose::Open(Slot::A), || {
            assert!(checked_metadata(&f, || Err::<(), _>(GuardError::Conflict)).is_err());
            Ok(())
        })
        .is_err());
    assert!(f.inspect(Purpose::Use(Slot::A), || Ok(())).is_err());
    let f = Fence::new();
    assert!(catch_unwind(AssertUnwindSafe(|| checked_metadata(&f, || {
        panic!("metadata unwind");
        #[allow(unreachable_code)]
        Ok(())
    })))
    .is_err());
    assert!(f.inspect(Purpose::Open(Slot::A), || Ok(())).is_err());
}
// Break: replacing the first weak inventory with foreign equal-shaped data, or keeping the actor alive with registration.
#[test]
fn weak_registration_retains_exact_first_origin_and_expiry_denies_without_a_strong_cycle() {
    let actor = std::rc::Rc::new(7);
    let foreign = std::rc::Rc::new(7);
    let slot = Retained::new();
    let f = Fence::new();
    assert_eq!(
        slot.first(std::rc::Rc::downgrade(&actor), &f, |retained| {
            let actual = retained.upgrade().ok_or(GuardError::Conflict)?;
            if std::rc::Rc::ptr_eq(&actual, &actor) {
                Ok(())
            } else {
                Err(GuardError::Conflict)
            }
        }),
        Ok(())
    );
    assert!(slot
        .first(std::rc::Rc::downgrade(&foreign), &f, |_| Ok(()))
        .is_err());
    assert!(std::rc::Weak::ptr_eq(
        slot.value.borrow().as_ref().unwrap(),
        &std::rc::Rc::downgrade(&actor)
    ));
    drop(actor);
    assert!(slot.value.borrow().as_ref().unwrap().upgrade().is_none());
}

// Prepared ownership metadata after C publication is not probe/Guard authority.
#[test]
fn starting_prepared_origin_retains_metadata_without_granting_any_probe_effect() {
    let (context, mut record) = fixture();
    let proof = record.members[0].as_ref().unwrap().owner.proof.unwrap();
    record.members[0].as_mut().unwrap().owner.phase = owner::Phase::Prepared;
    record.members[0].as_mut().unwrap().owner.proof = None;
    record.guard = policy::Model::empty(record.scope.clone()).unwrap();
    record.network = None;
    record.pending = None;
    record.validate().unwrap();
    assert_eq!(compare_origin(&context, &record), Ok(()));
    assert!(compare_identity(&context, &record).is_err());
    for purpose in [
        Purpose::Open(Slot::A),
        Purpose::Open(Slot::B),
        Purpose::Use(Slot::A),
        Purpose::Use(Slot::B),
        Purpose::Preparing,
        Purpose::Closing,
        Purpose::Guard,
    ] {
        assert!(
            compare_stage(&context, &record, purpose).is_err(),
            "{purpose:?}"
        );
    }
    assert!(compare_guard_target(&context, &record, &record.guard).is_err());
    let mut foreign = context.clone();
    foreign.provenance.boot_id[0] ^= 1;
    assert!(compare_origin(&foreign, &record).is_err());
    foreign = context.clone();
    foreign.intent.scope.connection_generation += 1;
    assert!(compare_origin(&foreign, &record).is_err());
    foreign = context.clone();
    foreign.bindings[0].guid[0] ^= 1;
    assert!(compare_origin(&foreign, &record).is_err());

    let mut live = record.clone();
    live.members[0].as_mut().unwrap().owner.phase = owner::Phase::Running;
    live.members[0].as_mut().unwrap().owner.proof = Some(proof);
    assert_eq!(compare_origin(&context, &live), Ok(()));
    live.members[0]
        .as_mut()
        .unwrap()
        .owner
        .proof
        .as_mut()
        .unwrap()
        .interface
        .guid[0] ^= 1;
    live.validate().unwrap();
    assert!(compare_origin(&context, &live).is_err());

    let mut retired = record.clone();
    retired.members[0].as_mut().unwrap().owner.retired_proof = Some(proof);
    retired.validate().unwrap();
    assert_eq!(compare_origin(&context, &retired), Ok(()));
    assert!(compare_identity(&context, &retired).is_err());
    retired.members[0]
        .as_mut()
        .unwrap()
        .owner
        .retired_proof
        .as_mut()
        .unwrap()
        .interface
        .guid[0] ^= 1;
    retired.validate().unwrap();
    assert!(compare_origin(&context, &retired).is_err());
}
