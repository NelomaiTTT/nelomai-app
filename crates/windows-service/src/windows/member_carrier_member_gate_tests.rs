use super::*;
use crate::{
    member_carrier::{Intent as CarrierIntent, Provenance},
    member_carrier_native_ownership::{Binding, Role},
    member_owner as owner,
};
use nelomai_client_tunnel::TunnelTransport;
use nelomai_contracts::{dispatcher::EngineIdentity, RuntimeSlot};

fn fixture() -> (Context, pair::Record, Intent) {
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
        intent: CarrierIntent {
            scope: scope.clone(),
            addresses: vec!["10.7.0.2/32".parse().unwrap()],
        },
        provenance: provenance.clone(),
        bindings: std::array::from_fn(|i| Binding {
            role: [Role::RoleCarrier, Role::MemberA, Role::MemberB][i],
            guid: [(i + 1) as u8; 16],
            name: ["carrier-c", "member-a", "member-b"][i].into(),
            registry_path: format!("test-key-{i}"),
        }),
    };
    let intent = Intent {
        scope: scope.clone(),
        slot: TunnelSlot::A,
        transport: TunnelTransport::WireGuard,
        engine: crate::test_engine_path("wireguard.exe"),
        config_sha256: [4; 32],
    };
    let member = pair::MemberState {
        owner: owner::Record {
            intent: intent.clone(),
            phase: owner::Phase::Prepared,
            proof: None,
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
    let r = pair::Record {
        version: 2,
        scope: scope.clone(),
        provenance,
        revision: 10,
        phase: pair::Phase::Starting,
        addresses: context.intent.addresses.clone(),
        dns: vec![],
        carrier: Some(owner::InterfaceProof {
            index: 7,
            luid: 90,
            guid: [1; 16],
        }),
        members: [Some(member), None],
        active: None,
        options: Some(nelomai_client_tunnel::DesktopTunnelOptions::default()),
        guard: policy::Model::empty(scope).unwrap(),
        pending_guard: None,
        pending: Some(pair::Effect::MemberStart(Slot::A)),
        network: None,
        stop_stage: 0,
        operation: Some(pair::Operation::Start(Slot::A)),
    };
    r.validate().unwrap();
    (context, r, intent)
}
fn proof(i: usize) -> NativeProof {
    NativeProof {
        interface: owner::InterfaceProof {
            index: 8 + i as u32,
            luid: 91 + i as u64,
            guid: [(2 + i) as u8; 16],
        },
        process: owner::ProcessProof {
            pid: 50 + i as u32,
            creation_time: 100 + i as u64,
        },
    }
}
fn reserve() -> (Context, pair::Record, Intent) {
    let (c, mut r, _) = fixture();
    r.members[0].as_mut().unwrap().owner.phase = owner::Phase::Running;
    r.members[0].as_mut().unwrap().owner.proof = Some(proof(0));
    let mut b = r.members[0].clone().unwrap();
    b.owner.intent.slot = TunnelSlot::B;
    b.owner.phase = owner::Phase::Prepared;
    b.owner.proof = None;
    b.lease_id = "33333333-3333-4333-8333-333333333333".into();
    b.owner.intent.config_sha256 = [5; 32];
    let intent = b.owner.intent.clone();
    r.members[1] = Some(b);
    r.phase = pair::Phase::Running;
    r.active = Some(Slot::A);
    r.operation = Some(pair::Operation::Attach(Slot::B));
    r.pending = Some(pair::Effect::MemberStart(Slot::B));
    let model = policy::Model::new(
        r.scope.clone(),
        policy::Carrier {
            identity: policy::Identity {
                scope: r.scope.clone(),
                proof: r.carrier.unwrap(),
            },
            sources: vec!["10.7.0.2".parse().unwrap()],
        },
        [
            Some(policy::Member {
                identity: policy::Identity {
                    scope: r.scope.clone(),
                    proof: proof(0).interface,
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
    let mut actual = model.expected.clone();
    actual.sublayer.as_mut().unwrap().weight = 41;
    r.guard = model
        .readback_after(&policy::Model::empty(r.scope.clone()).unwrap(), &actual)
        .unwrap();
    r.network = Some(pair::NetworkState {
        baseline: pair::NetworkSnapshot {
            routes: vec![],
            dns: None,
        },
        current: pair::NetworkSnapshot {
            routes: vec![],
            dns: None,
        },
        pending: None,
    });
    r.validate().unwrap();
    (c, r, intent)
}
fn closing(slot: Slot) -> (Context, pair::Record, Intent) {
    let (c, mut r, _) = reserve();
    r.members[1] = None;
    if slot == Slot::B {
        let mut b = r.members[0].clone().unwrap();
        b.owner.intent.slot = TunnelSlot::B;
        b.owner.proof = Some(proof(1));
        b.lease_id = "33333333-3333-4333-8333-333333333333".into();
        r.members[1] = Some(b);
        let m = policy::Model::new(
            r.scope.clone(),
            r.guard.carrier.clone().unwrap(),
            std::array::from_fn(|i| {
                Some(policy::Member {
                    identity: policy::Identity {
                        scope: r.scope.clone(),
                        proof: proof(i).interface,
                    },
                    probes: vec![],
                })
            }),
            None,
        )
        .unwrap()
        .without_permits()
        .unwrap();
        r.guard = m.inherit_sublayer_weight(&r.guard).unwrap();
    }
    r.phase = pair::Phase::Closing;
    r.active = None;
    r.operation = None;
    r.stop_stage = if slot == Slot::A { 4 } else { 5 };
    r.pending = Some(pair::Effect::MemberStop(slot));
    let intent = r.members[if slot == Slot::A { 0 } else { 1 }]
        .as_ref()
        .unwrap()
        .owner
        .intent
        .clone();
    r.validate().unwrap();
    (c, r, intent)
}
fn retirement(slot: Slot) -> (Context, pair::Record, Intent) {
    let (c, mut record, intent) = closing(slot);
    record.phase = pair::Phase::Running;
    record.active = Some(if slot == Slot::A { Slot::B } else { Slot::A });
    record.operation = Some(pair::Operation::Retire(slot));
    record.stop_stage = 0;
    if record.members[1].is_none() {
        let (_, full, _) = closing(Slot::B);
        record.members = full.members;
        record.guard = full.guard;
    }
    record.validate().unwrap();
    (c, record, intent)
}

fn rebinding(slot: Slot) -> (Context, pair::Record, Intent) {
    let (c, mut r, _) = closing(Slot::B);
    r.phase = pair::Phase::Running;
    r.active = Some(Slot::A);
    r.operation = Some(pair::Operation::Rebind);
    r.stop_stage = 0;
    r.pending = Some(pair::Effect::Rebind(slot));
    let intent = r.members[usize::from(slot == Slot::B)]
        .as_ref()
        .unwrap()
        .owner
        .intent
        .clone();
    r.validate().unwrap();
    (c, r, intent)
}

#[test]
fn rebind_stage_is_disjoint_from_creation_retirement_and_closing() {
    for slot in [Slot::A, Slot::B] {
        let (c, r, intent) = rebinding(slot);
        assert_eq!(
            rebind_stage(&c, &r, &intent).unwrap(),
            Use::Rebind(index(&intent))
        );
        assert!(stage(&c, &r, &intent, false).is_err());
        assert!(stage(&c, &r, &intent, true).is_err());
        assert!(retirement_stage(&c, &r, &intent).is_err());
    }
}

#[test]
fn rebind_stage_denies_foreign_scope_epoch_target_and_unfinished_guard() {
    for fault in 0..9 {
        let (c, mut r, mut intent) = rebinding(Slot::B);
        match fault {
            0 => r.provenance.network_epoch += 1,
            1 => intent.scope.runtime_generation += 1,
            2 => r.pending = Some(pair::Effect::Rebind(Slot::A)),
            3 => r.operation = Some(pair::Operation::Retire(Slot::B)),
            4 => r.phase = pair::Phase::Closing,
            5 => r.members[1].as_mut().unwrap().owner.proof = None,
            6 => r.active = None,
            7 => r.guard.permits = true,
            _ => r.network = None,
        }
        assert!(rebind_stage(&c, &r, &intent).is_err(), "fault {fault}");
    }
}

#[test]
fn rebind_rows_preserve_c_and_all_live_member_weak_rows_with_actual_readback() {
    let (c, r, _) = rebinding(Slot::B);
    let records = std::array::from_fn(|n| Some(row(&c, &r, n, Use::Reserve)));
    resource_rows(&c, &r, Use::Rebind(1), rowfacts(&records)).unwrap();
    for cut in 0..5 {
        let mut wrong = records.clone();
        match cut {
            0 => {
                wrong[2]
                    .as_mut()
                    .unwrap()
                    .current
                    .interface
                    .policy
                    .weak_host_receive = false
            }
            1 => wrong[1].as_mut().unwrap().phase = rows::Phase::Stopped,
            2 => wrong[0].as_mut().unwrap().binding.network_epoch += 1,
            3 => wrong[2] = None,
            _ => {
                wrong[0]
                    .as_mut()
                    .unwrap()
                    .current
                    .address
                    .as_mut()
                    .unwrap()
                    .observed
                    .dad_state = 1
            }
        }
        assert!(resource_rows(&c, &r, Use::Rebind(1), rowfacts(&wrong)).is_err());
    }
    let mut absent = rowfacts(&records);
    absent[2].as_mut().unwrap().observed = None;
    assert!(resource_rows(&c, &r, Use::Rebind(1), absent).is_err());
}

#[test]
fn rebind_requires_all_probes_absent_and_keeps_original_network_active() {
    let (_, mut r, _) = rebinding(Slot::A);
    probes(&r, Use::Rebind(0), &[]).unwrap();
    let tuple = policy::ProbeTuple {
        source: "10.7.0.2".parse().unwrap(),
        source_port: 53001,
        target: "1.1.1.1".parse().unwrap(),
        target_port: 53,
        protocol: 17,
    };
    assert!(probes(&r, Use::Rebind(0), &[tuple]).is_err());
    let dns = dns_snapshot(&r);
    r.network.as_mut().unwrap().baseline.dns = Some(dns.clone());
    r.network.as_mut().unwrap().current.dns = Some(dns.clone());
    let ack = (vec![], vec![dns.clone()]);
    let mut routes = no_routes();
    routes.active = Some(Slot::A);
    let check = |routes: &super::super::member_carrier_network::NetworkFacts| {
        network(
            &r,
            Use::Rebind(0),
            NetworkFact {
                routes,
                dns: &dns,
                protected: Some(b"protected actual ACK"),
            },
            Some(&ack),
        )
    };
    check(&routes).unwrap();
    routes.active = Some(Slot::B);
    assert!(check(&routes).is_err());
}

#[test]
fn rebind_guard_retains_actual_captured_priority_and_exact_static_bases() {
    let (_, r, _) = rebinding(Slot::A);
    guard(&r, Use::Rebind(0), &r.guard.expected).unwrap();
    for cut in 0..4 {
        let mut actual = r.guard.expected.clone();
        match cut {
            0 => actual.sublayer.as_mut().unwrap().weight += 1,
            1 => actual.filters.pop().map(|_| ()).unwrap(),
            2 => actual.carrier.as_mut().unwrap().identity.proof.luid += 1,
            _ => actual.egress[1].as_mut().unwrap().proof.index += 1,
        }
        assert!(guard(&r, Use::Rebind(0), &actual).is_err());
    }
    let mut permitted = r.clone();
    permitted.guard.permits = true;
    assert!(guard(&permitted, Use::Rebind(0), &r.guard.expected).is_err());
}

// Break: normal standby Stop is incorrectly conflated with full Closing.
#[test]
fn retirement_stage_is_disjoint_and_preserves_the_other_active_original() {
    for slot in [Slot::A, Slot::B] {
        let (c, record, intent) = retirement(slot);
        assert_eq!(
            retirement_stage(&c, &record, &intent).unwrap(),
            Use::Retire(index(&intent))
        );
        assert!(stage(&c, &record, &intent, true).is_err());
        let (_, closing, _) = closing(slot);
        assert!(retirement_stage(&c, &closing, &intent).is_err());
    }
}

#[test]
fn retirement_stage_denies_wrong_target_active_generation_and_pending_effect() {
    for fault in 0..8 {
        let (c, mut r, mut i) = retirement(Slot::B);
        match fault {
            0 => r.active = Some(Slot::B),
            1 => r.operation = Some(pair::Operation::Retire(Slot::A)),
            2 => r.pending = Some(pair::Effect::ReleaseProbes),
            3 => r.stop_stage = 5,
            4 => i.scope.runtime_generation += 1,
            5 => r.members[0] = None,
            6 => r.provenance.network_epoch += 1,
            _ => i.config_sha256 = [9; 32],
        }
        assert!(retirement_stage(&c, &r, &i).is_err(), "fault {fault}");
    }
}

// Break: an empty-only gate denies the actual primary/reserve/Closing effects.
#[test]
fn member_stage_accepts_primary_reserve_and_each_exact_stop() {
    let (c, r, i) = fixture();
    assert_eq!(stage(&c, &r, &i, false).unwrap(), Use::Primary);
    original_bindings(&c, &r, &i, Use::Primary, &carrier(&r), &[None, None], None).unwrap();
    let (c, r, i) = reserve();
    assert_eq!(stage(&c, &r, &i, false).unwrap(), Use::Reserve);
    for slot in [Slot::A, Slot::B] {
        let (c, r, i) = closing(slot);
        assert_eq!(stage(&c, &r, &i, true).unwrap(), Use::Stop);
    }
}
#[test]
fn member_stage_rejects_foreign_scope_intent_operation_and_wrong_closing_stage() {
    for fault in 0..8 {
        let (c, mut r, mut i) = closing(Slot::A);
        match fault {
            0 => r.stop_stage = 5,
            1 => r.pending = Some(pair::Effect::MemberStop(Slot::B)),
            2 => r.phase = pair::Phase::Starting,
            3 => i.config_sha256 = [8; 32],
            4 => r.provenance.boot_id = [9; 16],
            5 => i.scope.runtime_generation += 1,
            6 => r.operation = Some(pair::Operation::Start(Slot::A)),
            _ => r.active = Some(Slot::A),
        }
        assert!(stage(&c, &r, &i, true).is_err(), "fault {fault}");
    }
    let (c, mut r, i) = reserve();
    r.operation = Some(pair::Operation::Switch(Slot::B));
    assert!(stage(&c, &r, &i, false).is_err());
}
// Break: accepting equality without captured assigned priority, or any permit.
#[test]
fn actual_guard_requires_full_empty_primary_or_exact_captured_blocks() {
    let (_, r, _) = fixture();
    guard(&r, Use::Primary, &r.guard.expected).unwrap();
    let (_, r, _) = reserve();
    guard(&r, Use::Reserve, &r.guard.expected).unwrap();
    let (_, r, _) = closing(Slot::B);
    guard(&r, Use::Stop, &r.guard.expected).unwrap();
    for fault in 0..4 {
        let (_, r, _) = reserve();
        let mut actual = r.guard.expected.clone();
        match fault {
            0 => actual.sublayer.as_mut().unwrap().weight += 1,
            1 => actual.filters.pop().map(|_| ()).unwrap(),
            2 => actual.filters[0].action = policy::Action::Permit,
            _ => actual.egress[0] = None,
        }
        assert!(guard(&r, Use::Reserve, &actual).is_err());
    }
}

fn carrier(r: &pair::Record) -> policy::Carrier {
    policy::Carrier {
        identity: policy::Identity {
            scope: r.scope.clone(),
            proof: r.carrier.unwrap(),
        },
        sources: r.addresses.iter().map(|a| a.addr()).collect(),
    }
}
#[test]
fn start_bindings_reject_target_presence_and_stop_compares_exact_retired_history() {
    let (c, r, i) = reserve();
    let a = policy::Identity {
        scope: r.scope.clone(),
        proof: proof(0).interface,
    };
    original_bindings(
        &c,
        &r,
        &i,
        Use::Reserve,
        &carrier(&r),
        &[Some(a.clone()), None],
        None,
    )
    .unwrap();
    assert!(original_bindings(
        &c,
        &r,
        &i,
        Use::Reserve,
        &carrier(&r),
        &[
            Some(a),
            Some(policy::Identity {
                scope: r.scope.clone(),
                proof: proof(1).interface
            })
        ],
        None
    )
    .is_err());
    let (c, r, i) = closing(Slot::B);
    let history = std::array::from_fn(|n| {
        Some(policy::Identity {
            scope: r.scope.clone(),
            proof: proof(n).interface,
        })
    });
    original_bindings(&c, &r, &i, Use::Stop, &carrier(&r), &history, None).unwrap();
    for fault in 0..3 {
        let mut wrong = history.clone();
        match fault {
            0 => wrong[0] = None,
            1 => wrong[0].as_mut().unwrap().proof.luid += 1,
            _ => wrong[0].as_mut().unwrap().scope.connection_generation += 1,
        }
        assert!(original_bindings(&c, &r, &i, Use::Stop, &carrier(&r), &wrong, None).is_err());
    }
}
fn row(c: &Context, r: &pair::Record, n: usize, usage: Use) -> rows::Record {
    let p = if n == 0 {
        r.carrier.unwrap()
    } else {
        proof(n - 1).interface
    };
    let binding = rows::Binding {
        scope: r.scope.clone(),
        runtime: c.provenance.runtime.clone(),
        boot_id: c.provenance.boot_id,
        network_epoch: c.provenance.network_epoch,
        role: [
            rows::Role::Carrier,
            rows::Role::MemberA,
            rows::Role::MemberB,
        ][n],
        guid: p.guid,
        name: c.bindings[n].name.clone(),
        key: rows::RowKey {
            index: p.index,
            luid: p.luid,
        },
        address: [10, 7, 0, 2],
    };
    let baseline = rows::Snapshot {
        interface: rows::InterfaceRow {
            key: binding.key,
            policy: rows::InterfacePolicy {
                advertising: false,
                forwarding: false,
                weak_host_send: false,
                weak_host_receive: false,
                automatic_metric: true,
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
                site_prefix_length: 0,
                metric: 10,
                mtu: 1420,
                disable_default_routes: false,
            },
            observed: rows::InterfaceObserved {
                max_reassembly_size: 0,
                interface_identifier: 0,
                min_router_advertisement_interval: 0,
                max_router_advertisement_interval: 0,
                connected: true,
                supports_wake_up_patterns: false,
                supports_neighbor_discovery: true,
                supports_router_discovery: false,
                reachable_time: 30000,
                transmit_offload: 0,
                receive_offload: 0,
            },
        },
        address: None,
    };
    let address = (n == 0).then_some(rows::AddressRow {
        key: binding.key,
        policy: rows::AddressPolicy {
            address: binding.address,
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
            creation_timestamp: 100,
        },
    });
    let mut current = baseline.clone();
    current.address = address.clone();
    if usage == Use::Reserve {
        current.interface.policy.weak_host_send = true;
        current.interface.policy.weak_host_receive = true;
    }
    let record = rows::Record {
        version: 1,
        domain: rows::DOMAIN.into(),
        binding,
        revision: 2,
        phase: if usage == Use::Stop {
            rows::Phase::Closing
        } else {
            rows::Phase::Captured
        },
        baseline,
        current,
        pending: None,
        creation: address,
    };
    record.validate().unwrap();
    record
}
fn rowfacts(records: &[Option<rows::Record>; 3]) -> [Option<RowFact<'_>>; 3] {
    std::array::from_fn(|n| {
        records[n].as_ref().map(|r| RowFact {
            binding: &r.binding,
            acknowledged: r,
            observed: Some(&r.current),
        })
    })
}
#[test]
fn resource_rows_require_original_ack_ready_c_and_exact_weak_baseline_before_stop() {
    let (c, r, _) = fixture();
    let records = [Some(row(&c, &r, 0, Use::Primary)), None, None];
    resource_rows(&c, &r, Use::Primary, rowfacts(&records)).unwrap();
    let (c, r, _) = reserve();
    let records = [
        Some(row(&c, &r, 0, Use::Reserve)),
        Some(row(&c, &r, 1, Use::Reserve)),
        None,
    ];
    resource_rows(&c, &r, Use::Reserve, rowfacts(&records)).unwrap();
    let (c, r, _) = closing(Slot::B);
    let records = std::array::from_fn(|n| Some(row(&c, &r, n, Use::Stop)));
    resource_rows(&c, &r, Use::Stop, rowfacts(&records)).unwrap();
    let mut facts = rowfacts(&records);
    facts[1].as_mut().unwrap().observed = None;
    resource_rows(&c, &r, Use::Stop, facts).unwrap(); // Exact closed-row ACK, no removed SDK row.
    for fault in 0..6 {
        let mut wrong = records.clone();
        let a = wrong[1].as_mut().unwrap();
        match fault {
            0 => a.current.interface.policy.weak_host_send = true,
            1 => a.binding.boot_id = [9; 16],
            2 => a.binding.key.luid += 1,
            3 => a.current.interface.policy.metric += 1,
            4 => {
                a.pending = Some(rows::Pending {
                    before: a.current.clone(),
                    target: rows::Target::Interface(a.baseline.interface.policy.clone()),
                })
            }
            _ => wrong[2] = None,
        }
        assert!(
            resource_rows(&c, &r, Use::Stop, rowfacts(&wrong)).is_err(),
            "fault {fault}"
        );
    }
}
fn dns_snapshot(r: &pair::Record) -> crate::member_dns::Snapshot {
    let c = r.carrier.unwrap();
    crate::member_dns::Snapshot {
        interface: crate::member_dns::OwnedInterface {
            scope: r.scope.clone(),
            guid: c.guid,
            luid: c.luid,
            index: c.index,
        },
        settings: crate::member_dns::Settings {
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
    }
}
fn no_routes() -> super::super::member_carrier_network::NetworkFacts {
    super::super::member_carrier_network::NetworkFacts {
        current: vec![],
        pending: None,
        carrier_rows: vec![],
        egress_rows: [vec![], vec![]],
        active: None,
        pending_active: None,
        stopping: false,
    }
}
#[test]
fn network_before_effects_accepts_empty_owner_history_and_closing_requires_restored_dns_ack() {
    use super::super::member_carrier_network_owner::RouteAttempt;
    use nelomai_client_tunnel::redundancy::network::{RouteScope, RouteValue};
    let (_, r, _) = fixture();
    let mut actual = no_routes();
    let c = r.carrier.unwrap();
    actual.carrier_rows = ["10.7.0.2/32", "224.0.0.0/4"]
        .into_iter()
        .enumerate()
        .map(|(i, destination)| {
            let mut row = crate::member_routes::Row::static_route(
                RouteValue {
                    destination: destination.parse().unwrap(),
                    scope: RouteScope::WindowsInterface(c.index),
                    interface: c.index,
                    gateway: None,
                    metric: 0,
                },
                crate::member_routes::NativeProof {
                    index: c.index,
                    luid: c.luid,
                },
            );
            row.protocol = 2;
            row.origin = if i == 1 { 1 } else { 0 };
            row.flags = if i == 0 { [1, 1, 0, 0] } else { [0, 1, 0, 0] };
            row
        })
        .collect();
    for i in 0..2 {
        let mut incidental = actual.carrier_rows[1].clone();
        incidental.route.interface = 8 + i as u32;
        incidental.route.scope = RouteScope::WindowsInterface(incidental.route.interface);
        incidental.luid = 91 + i as u64;
        actual.egress_rows[i].push(incidental);
    }
    let dns = dns_snapshot(&r);
    let empty = (vec![], vec![]);
    let route = crate::member_routes::Row::static_route(
        RouteValue {
            destination: "1.1.1.1/32".parse().unwrap(),
            scope: RouteScope::WindowsInterface(8),
            interface: 8,
            gateway: None,
            metric: 5,
        },
        crate::member_routes::NativeProof { index: 8, luid: 91 },
    );
    for usage in [Use::Primary, Use::ServiceStop(0)] {
        for ack in [None, Some(&empty)] {
            network(
                &r,
                usage,
                NetworkFact {
                    routes: &actual,
                    dns: &dns,
                    protected: None,
                },
                ack,
            )
            .unwrap();
        }
        let mut empty_dns = dns.clone();
        empty_dns.settings.name_server = Some(String::new());
        empty_dns.settings.profile_name_server = Some(String::new());
        network(
            &r,
            usage,
            NetworkFact {
                routes: &actual,
                dns: &empty_dns,
                protected: None,
            },
            Some(&empty),
        )
        .unwrap();
        for profile in [false, true] {
            let mut nonempty_dns = empty_dns.clone();
            if profile {
                nonempty_dns.settings.profile_name_server = Some("1.1.1.1".into());
            } else {
                nonempty_dns.settings.name_server = Some("1.1.1.1".into());
            }
            assert!(network(
                &r,
                usage,
                NetworkFact {
                    routes: &actual,
                    dns: &nonempty_dns,
                    protected: None
                },
                Some(&empty),
            )
            .is_err());
        }
        for acknowledged in [false, true] {
            let attempts = (
                vec![RouteAttempt {
                    row: route.clone(),
                    deleting: false,
                    acknowledged,
                }],
                vec![],
            );
            assert!(network(
                &r,
                usage,
                NetworkFact {
                    routes: &actual,
                    dns: &dns,
                    protected: None
                },
                Some(&attempts),
            )
            .is_err());
        }
        let dns_history = (vec![], vec![dns.clone()]);
        assert!(network(
            &r,
            usage,
            NetworkFact {
                routes: &actual,
                dns: &dns,
                protected: None
            },
            Some(&dns_history),
        )
        .is_err());
    }
    let (_, mut r, _) = closing(Slot::A);
    let dns = dns_snapshot(&r);
    let n = r.network.as_mut().unwrap();
    n.baseline.dns = Some(dns.clone());
    n.current = n.baseline.clone();
    let mut actual = no_routes();
    actual.stopping = true;
    let ack = (vec![], vec![dns.clone()]);
    network(
        &r,
        Use::Stop,
        NetworkFact {
            routes: &actual,
            dns: &dns,
            protected: Some(b"original-record"),
        },
        Some(&ack),
    )
    .unwrap();
    assert!(network(
        &r,
        Use::Stop,
        NetworkFact {
            routes: &actual,
            dns: &dns,
            protected: Some(b"original-record")
        },
        None
    )
    .is_err());
    let bad = (vec![], vec![]);
    assert!(network(
        &r,
        Use::Stop,
        NetworkFact {
            routes: &actual,
            dns: &dns,
            protected: Some(b"original-record")
        },
        Some(&bad)
    )
    .is_err());
    actual.pending = Some(vec![]);
    assert!(network(
        &r,
        Use::Stop,
        NetworkFact {
            routes: &actual,
            dns: &dns,
            protected: Some(b"original-record")
        },
        Some(&ack)
    )
    .is_err());
}
#[test]
fn opaque_probe_inventory_is_empty_before_primary_and_allows_no_ports_at_stop() {
    let (_, r, _) = fixture();
    probes(&r, Use::Primary, &[]).unwrap();
    let tuple = policy::ProbeTuple {
        source: "10.7.0.2".parse().unwrap(),
        source_port: 45000,
        target: "1.1.1.1".parse().unwrap(),
        target_port: 53,
        protocol: 17,
    };
    assert!(probes(&r, Use::Primary, &[tuple.clone()]).is_err());
    let (_, r, _) = closing(Slot::A);
    probes(&r, Use::Stop, &[]).unwrap();
    assert!(probes(&r, Use::Stop, &[tuple]).is_err());
}
#[test]
fn pair_selection_is_monotonic_and_never_returns_from_closing_to_forward() {
    let (_, old, _) = fixture();
    let mut next = old.clone();
    next.revision += 1;
    advance(&old, &next).unwrap();
    assert!(advance(&next, &old).is_err());
    assert!(advance(&old, &old).is_err());
    let (_, old, _) = closing(Slot::A);
    let (_, mut next, _) = closing(Slot::B);
    next.revision = old.revision + 1;
    advance(&old, &next).unwrap();
    next.phase = pair::Phase::Running;
    assert!(advance(&old, &next).is_err());
}
#[test]
fn cleanup_fence_rejects_caught_reentry_and_unwind_never_rearms_forward() {
    let fence = GateFence::default();
    fence.run(false, || Ok(())).unwrap();
    assert!(fence
        .run(false, || {
            assert!(fence.run(false, || Ok(())).is_err());
            Ok(())
        })
        .is_err());
    assert!(fence.run(false, || Ok(())).is_err());
    fence.run(true, || Ok(())).unwrap();
    let fence = GateFence::default();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        fence.run(false, || -> Result<()> { panic!("late gate read") })
    }));
    assert!(result.is_err());
    assert!(fence.run(false, || Ok(())).is_err());
    fence.run(true, || Ok(())).unwrap();
}
#[test]
fn rooted_originals_survive_error_unwind_and_gate_drop() {
    struct Tracked(std::rc::Rc<Cell<usize>>);
    impl Drop for Tracked {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let drops = std::rc::Rc::new(Cell::new(0));
    let mut root = Root::new(Tracked(drops.clone()));
    assert!(root.get_mut().is_ok());
    drop(root);
    assert_eq!(drops.get(), 0);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _root = Root::new(Tracked(drops.clone()));
        panic!("postflight")
    }));
    assert!(result.is_err());
    assert_eq!(drops.get(), 0);
}
#[test]
fn weak_registration_keeps_first_identity_without_owning_or_replacing_actor_root() {
    let original = std::rc::Rc::new(7);
    let foreign = std::rc::Rc::new(7);
    let mut registration = Registration::default();
    registration.retain(&original).unwrap();
    assert_eq!(std::rc::Rc::strong_count(&original), 1);
    assert!(registration.retain(&foreign).is_err());
    assert!(std::rc::Rc::ptr_eq(&registration.get().unwrap(), &original));
    registration.retain(&original).unwrap();
    drop(original);
    assert!(registration.get().is_err());
    assert!(registration.retain(&foreign).is_err());
}
#[test]
fn first_weak_closing_registration_survives_postflight_failure_and_unwind() {
    let original = std::rc::Rc::new(7);
    let mut registration = Registration::default();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        registration.retain(&original).unwrap();
        panic!("Closing postflight");
    }));
    assert!(result.is_err());
    assert!(std::rc::Rc::ptr_eq(&registration.get().unwrap(), &original));
    assert!(registration.retain(&std::rc::Rc::new(7)).is_err());
    registration.retain(&original).unwrap();
}

#[test]
fn installed_bases_cannot_omit_remaining_original_member_even_with_equal_guard_json() {
    let (_, mut r, _) = closing(Slot::B);
    r.guard = policy::Model::new(
        r.scope.clone(),
        r.guard.carrier.clone().unwrap(),
        [None, r.guard.members[1].clone()],
        None,
    )
    .unwrap()
    .without_permits()
    .unwrap()
    .inherit_sublayer_weight(&r.guard)
    .unwrap();
    r.validate().unwrap();
    assert!(guard(&r, Use::Stop, &r.guard.expected).is_err());
}

#[test]
fn protected_guard_postflight_rejects_replacement_creation_and_disappearance() {
    protected_continuity(None, None).unwrap();
    protected_continuity(
        Some(b"same protected revision"),
        Some(b"same protected revision"),
    )
    .unwrap();
    assert!(protected_continuity(Some(b"old"), Some(b"replacement")).is_err());
    assert!(protected_continuity(None, Some(b"new")).is_err());
    assert!(protected_continuity(Some(b"old"), None).is_err());
}

#[test]
fn partial_stop_requires_exact_original_intent_and_actual_native_proof() {
    let (_, _, intent) = fixture();
    assert_eq!(
        partial_original_proof(&intent, (intent.clone(), Some(proof(0)))).unwrap(),
        proof(0)
    );
    assert_eq!(
        partial_original_proof(&intent, (intent.clone(), None)),
        Err(Error::Pending)
    );
    for fault in 0..5 {
        let mut foreign = intent.clone();
        match fault {
            0 => foreign.scope.runtime_generation += 1,
            1 => foreign.scope.connection_generation += 1,
            2 => foreign.slot = TunnelSlot::B,
            3 => foreign.config_sha256 = [9; 32],
            _ => foreign.engine = crate::test_engine_path("foreign.exe"),
        }
        assert!(partial_original_proof(&intent, (foreign, Some(proof(0)))).is_err());
    }
}

#[test]
fn service_only_gate_is_disjoint_exact_closing_with_no_target_native_grant() {
    // Break caught: normal Stop weakened, imported proof allowed, or new lane
    // requires fabricated target NIC/installed bases before unknown Start ACK.
    let (context, mut record, intent) = fixture();
    record.phase = pair::Phase::Closing;
    record.operation = None;
    record.stop_stage = 4;
    record.pending = Some(pair::Effect::MemberStop(Slot::A));
    record.validate().unwrap();
    assert_eq!(
        service_stop_stage(&context, &record, &intent).unwrap(),
        Use::ServiceStop(0)
    );
    guard(&record, Use::ServiceStop(0), &record.guard.expected).unwrap();
    assert!(guard(&record, Use::Stop, &record.guard.expected).is_err());
    for cut in 0..8 {
        let mut wrong = record.clone();
        match cut {
            0 => wrong.phase = pair::Phase::Starting,
            1 => wrong.stop_stage = 5,
            2 => wrong.pending = Some(pair::Effect::MemberStop(Slot::B)),
            3 => wrong.members[0].as_mut().unwrap().owner.proof = Some(proof(0)),
            4 => wrong.provenance.network_epoch += 1,
            5 => wrong.scope.runtime_generation += 1,
            6 => {
                wrong.members[0]
                    .as_mut()
                    .unwrap()
                    .owner
                    .intent
                    .config_sha256 = [9; 32]
            }
            _ => wrong.active = Some(Slot::A),
        }
        assert!(
            service_stop_stage(&context, &wrong, &intent).is_err(),
            "cut {cut}"
        );
    }
    let facts = no_routes();
    let dns = dns_snapshot(&record);
    network(
        &record,
        Use::ServiceStop(0),
        NetworkFact {
            routes: &facts,
            dns: &dns,
            protected: None,
        },
        None,
    )
    .unwrap();
    let mut polluted = no_routes();
    polluted.pending = Some(vec![]);
    assert!(network(
        &record,
        Use::ServiceStop(0),
        NetworkFact {
            routes: &polluted,
            dns: &dns,
            protected: None
        },
        None
    )
    .is_err());
}

#[test]
fn service_only_window_is_never_ordinary_closing_forward_or_rebind_authority() {
    for usage in [
        Use::Primary,
        Use::Reserve,
        Use::Stop,
        Use::Retire(0),
        Use::Retired(1),
        Use::Rebind(0),
    ] {
        service_window_usage(usage, false).unwrap();
        assert!(service_window_usage(usage, true).is_err());
    }
    for target in [0, 1] {
        service_window_usage(Use::ServiceStop(target), true).unwrap();
        assert!(service_window_usage(Use::ServiceStop(target), false).is_err());
    }
}

#[test]
fn reserve_route_read_requires_exact_last_original_ack_and_no_unknown_or_extra_rows() {
    use super::super::{
        member_carrier_network::RouteFact, member_carrier_network_owner::RouteAttempt,
    };
    use nelomai_client_tunnel::redundancy::network::{RouteScope, RouteValue};
    let (_, mut record, _) = reserve();
    let route = RouteValue {
        destination: "1.1.1.1/32".parse().unwrap(),
        scope: RouteScope::WindowsInterface(8),
        interface: 8,
        gateway: None,
        metric: 5,
    };
    let row = crate::member_routes::Row::static_route(
        route.clone(),
        crate::member_routes::NativeProof { index: 8, luid: 91 },
    );
    let dns = dns_snapshot(&record);
    let n = record.network.as_mut().unwrap();
    n.baseline.dns = Some(dns.clone());
    n.current.dns = Some(dns.clone());
    n.current.routes = vec![route.clone()];
    let facts = || {
        let mut f = no_routes();
        f.active = Some(Slot::A);
        f.current.push(RouteFact {
            expected: route.clone(),
            actual: Some(row.clone()),
        });
        f.egress_rows[0].push(row.clone());
        f
    };
    let acks = || {
        (
            vec![RouteAttempt {
                row: row.clone(),
                deleting: false,
                acknowledged: true,
            }],
            vec![dns.clone()],
        )
    };
    network(
        &record,
        Use::Reserve,
        NetworkFact {
            routes: &facts(),
            dns: &dns,
            protected: Some(b"actual native record"),
        },
        Some(&acks()),
    )
    .unwrap();
    for fault in 0..9 {
        let mut actual = facts();
        let mut ack = acks();
        match fault {
            0 => ack.0[0].acknowledged = false,
            1 => ack.0[0].deleting = true,
            2 => ack.0[0].row.luid += 1,
            3 => actual.current[0].actual = None,
            4 => actual.current[0].actual.as_mut().unwrap().protocol = 99,
            5 => actual.active = Some(Slot::B),
            6 => actual.current.push(RouteFact {
                expected: route.clone(),
                actual: Some(row.clone()),
            }),
            7 => actual.pending_active = Some(Slot::B),
            _ => ack.1[0].settings.enable_llmnr = 1,
        }
        assert!(
            network(
                &record,
                Use::Reserve,
                NetworkFact {
                    routes: &actual,
                    dns: &dns,
                    protected: Some(b"actual native record")
                },
                Some(&ack)
            )
            .is_err(),
            "fault {fault}"
        );
    }
    let mut stopped = acks();
    stopped.0.push(RouteAttempt {
        row,
        deleting: true,
        acknowledged: true,
    });
    let mut absent = no_routes();
    absent.stopping = true;
    record.phase = pair::Phase::Closing;
    record.network.as_mut().unwrap().current.routes.clear();
    network(
        &record,
        Use::Stop,
        NetworkFact {
            routes: &absent,
            dns: &dns,
            protected: Some(b"actual native record"),
        },
        Some(&stopped),
    )
    .unwrap();
    stopped.0.last_mut().unwrap().acknowledged = false;
    assert!(network(
        &record,
        Use::Stop,
        NetworkFact {
            routes: &absent,
            dns: &dns,
            protected: Some(b"actual native record")
        },
        Some(&stopped)
    )
    .is_err());
}

#[test]
fn reserve_probe_tuples_are_exact_original_facts_without_any_allow_grant() {
    let (_, mut record, _) = reserve();
    let tuple = policy::ProbeTuple {
        source: "10.7.0.2".parse().unwrap(),
        source_port: 45000,
        target: "1.1.1.1".parse().unwrap(),
        target_port: 53,
        protocol: 17,
    };
    let mut member = record.guard.members[0].clone().unwrap();
    member.probes = vec![tuple.clone()];
    record.guard = policy::Model::new(
        record.scope.clone(),
        record.guard.carrier.clone().unwrap(),
        [Some(member), None],
        None,
    )
    .unwrap()
    .without_permits()
    .unwrap()
    .inherit_sublayer_weight(&record.guard)
    .unwrap();
    record.validate().unwrap();
    guard(&record, Use::Reserve, &record.guard.expected).unwrap();
    probes(&record, Use::Reserve, &[tuple.clone()]).unwrap();
    assert!(probes(&record, Use::Reserve, &[]).is_err());
    assert!(probes(&record, Use::Reserve, &[tuple.clone(), tuple.clone()]).is_err());
    let mut foreign = tuple;
    foreign.source_port += 1;
    assert!(probes(&record, Use::Reserve, &[foreign]).is_err());
    assert!(!record.guard.permits);
}

#[test]
fn retirement_rows_restore_only_target_and_keep_c_other_weak_and_original() {
    let (c, r, _) = retirement(Slot::B);
    let mut records = [
        Some(row(&c, &r, 0, Use::Reserve)),
        Some(row(&c, &r, 1, Use::Reserve)),
        Some(row(&c, &r, 2, Use::Stop)),
    ];
    records[2].as_mut().unwrap().phase = rows::Phase::Stopped;
    resource_rows(&c, &r, Use::Retire(1), rowfacts(&records)).unwrap();
    for fault in 0..5 {
        let mut wrong = records.clone();
        match fault {
            0 => {
                wrong[2]
                    .as_mut()
                    .unwrap()
                    .current
                    .interface
                    .policy
                    .weak_host_send = true
            }
            1 => {
                wrong[0]
                    .as_mut()
                    .unwrap()
                    .current
                    .interface
                    .policy
                    .weak_host_send = false
            }
            2 => {
                wrong[1]
                    .as_mut()
                    .unwrap()
                    .current
                    .interface
                    .policy
                    .weak_host_receive = false
            }
            3 => wrong[2].as_mut().unwrap().phase = rows::Phase::Closing,
            _ => wrong[2] = None,
        }
        assert!(resource_rows(&c, &r, Use::Retire(1), rowfacts(&wrong)).is_err());
    }
    // Retire preflight needs live native target rows; only actual window history
    // can justify the later stopped-target row projection.
    let mut facts = rowfacts(&records);
    facts[2].as_mut().unwrap().observed = None;
    assert!(resource_rows(&c, &r, Use::Retire(1), facts).is_err());
    records[2].as_mut().unwrap().binding.key.luid += 1;
    assert!(resource_rows(&c, &r, Use::Retire(1), rowfacts(&records)).is_err());
}

#[test]
fn retirement_postflight_uses_original_closed_target_rows_without_old_nic_query() {
    let (c, r, _) = retirement(Slot::B);
    let mut records = [
        Some(row(&c, &r, 0, Use::Reserve)),
        Some(row(&c, &r, 1, Use::Reserve)),
        Some(row(&c, &r, 2, Use::Stop)),
    ];
    records[2].as_mut().unwrap().phase = rows::Phase::Stopped;
    let mut facts = rowfacts(&records);
    facts[2].as_mut().unwrap().observed = None;
    resource_rows(&c, &r, Use::Retired(1), facts).unwrap();
    let mut facts = rowfacts(&records);
    facts[1].as_mut().unwrap().observed = None;
    assert!(resource_rows(&c, &r, Use::Retired(1), facts).is_err());
    records[2]
        .as_mut()
        .unwrap()
        .current
        .interface
        .policy
        .weak_host_receive = true;
    let mut facts = rowfacts(&records);
    facts[2].as_mut().unwrap().observed = None;
    assert!(resource_rows(&c, &r, Use::Retired(1), facts).is_err());
}

#[test]
fn retirement_network_requires_other_active_and_target_routes_actually_removed() {
    use super::super::{
        member_carrier_network::RouteFact, member_carrier_network_owner::RouteAttempt,
    };
    use nelomai_client_tunnel::redundancy::network::{RouteScope, RouteValue};
    let (_, mut r, _) = retirement(Slot::B);
    let dns = dns_snapshot(&r);
    r.network.as_mut().unwrap().current.dns = Some(dns.clone());
    let mut facts = no_routes();
    facts.active = Some(Slot::A);
    let mut ack = (vec![], vec![dns.clone()]);
    let check = |record: &pair::Record,
                 facts: &super::super::member_carrier_network::NetworkFacts,
                 ack: &NetworkAcks| {
        network(
            record,
            Use::Retire(1),
            NetworkFact {
                routes: facts,
                dns: &dns,
                protected: Some(b"original network"),
            },
            Some(ack),
        )
    };
    check(&r, &facts, &ack).unwrap();
    facts.active = Some(Slot::B);
    assert!(check(&r, &facts, &ack).is_err());
    facts.active = Some(Slot::A);
    let route = RouteValue {
        destination: "1.1.1.1/32".parse().unwrap(),
        interface: 9,
        scope: RouteScope::WindowsInterface(9),
        gateway: None,
        metric: 50,
    };
    let row = crate::member_routes::Row::static_route(
        route.clone(),
        crate::member_routes::NativeProof { index: 9, luid: 92 },
    );
    let mut incidental = row.clone();
    incidental.route.destination = "224.0.0.0/4".parse().unwrap();
    incidental.protocol = 2;
    incidental.origin = 1;
    incidental.flags = [0, 1, 0, 0];
    facts.egress_rows[1].push(incidental);
    check(&r, &facts, &ack).unwrap();
    r.network
        .as_mut()
        .unwrap()
        .current
        .routes
        .push(route.clone());
    facts.current.push(RouteFact {
        expected: route,
        actual: Some(row.clone()),
    });
    facts.egress_rows[1].push(row.clone());
    ack.0.push(RouteAttempt {
        row,
        deleting: false,
        acknowledged: true,
    });
    assert!(check(&r, &facts, &ack).is_err());
}

#[test]
fn retirement_probe_comparison_keeps_only_other_live_tuple_not_all_retired() {
    let (_, mut r, _) = retirement(Slot::B);
    let tuple = policy::ProbeTuple {
        source: "10.7.0.2".parse().unwrap(),
        source_port: 45000,
        target: "1.1.1.1".parse().unwrap(),
        target_port: 53,
        protocol: 17,
    };
    let mut target = tuple.clone();
    target.source_port += 1;
    let mut members = r.guard.members.clone();
    members[0].as_mut().unwrap().probes = vec![tuple.clone()];
    members[1].as_mut().unwrap().probes = vec![target.clone()];
    r.guard = policy::Model::new(
        r.scope.clone(),
        r.guard.carrier.clone().unwrap(),
        members,
        None,
    )
    .unwrap()
    .without_permits()
    .unwrap()
    .inherit_sublayer_weight(&r.guard)
    .unwrap();
    probes(&r, Use::Retire(1), &[tuple.clone()]).unwrap();
    assert!(probes(&r, Use::Retire(1), &[]).is_err());
    assert!(probes(&r, Use::Retire(1), &[tuple, target]).is_err());
}
