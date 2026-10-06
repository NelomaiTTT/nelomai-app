use super::*;
use crate::{
    member_carrier::{Intent, Provenance},
    member_carrier_native_ownership::{Binding, Role},
    member_owner as owner,
};
use nelomai_client_tunnel::redundancy::Slot;
use nelomai_client_tunnel::{DesktopTunnelOptions, TunnelTransport};
use nelomai_contracts::{
    dispatcher::{EngineIdentity, TunnelSlot},
    RuntimeSlot,
};

fn fixture() -> (Context, pair::Record) {
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
            name: ["carrier-c","member-a","member-b"][i].into(), registry_path: [
                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{01010101-0101-0101-0101-010101010101}",
                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{02020202-0202-0202-0202-020202020202}",
                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{03030303-0303-0303-0303-030303030303}",
            ][i].into(),
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
        endpoint: "192.0.2.11".parse().unwrap(),
        allowed: vec!["0.0.0.0/0".parse().unwrap()],
        peer: [3; 32],
        probe: nelomai_contracts::RedundantHealthProbe {
            kind: nelomai_contracts::HealthProbeKind::DnsA,
            target_ipv4: "1.1.1.1".parse().unwrap(),
            query_name: "example.com".into(),
            timeout_ms: 2000,
        },
    };
    let model = policy::Model::new(
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
    let mut observed = model.expected.clone();
    observed.sublayer.as_mut().unwrap().weight = 41;
    let guard = model
        .readback_after(&policy::Model::empty(scope.clone()).unwrap(), &observed)
        .unwrap();
    let record = pair::Record {
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
        guard,
        pending_guard: None,
        pending: Some(pair::Effect::WeakRows),
        network: None,
        stop_stage: 0,
        operation: Some(pair::Operation::Start(Slot::A)),
    };
    record.validate().unwrap();
    (context, record)
}
fn row_fixture(context: &Context, record: &pair::Record, role: rows::Role) -> rows::Record {
    let i = role_index(role);
    let proof = if i == 0 {
        record.carrier.unwrap()
    } else {
        record.members[i - 1]
            .as_ref()
            .unwrap()
            .owner
            .proof
            .unwrap()
            .interface
    };
    let binding = rows::Binding {
        scope: record.scope.clone(),
        boot_id: context.provenance.boot_id,
        runtime: context.provenance.runtime.clone(),
        network_epoch: context.provenance.network_epoch,
        role,
        guid: proof.guid,
        name: context.bindings[i].name.clone(),
        key: rows::RowKey {
            index: proof.index,
            luid: proof.luid,
        },
        // Actual native member binding carries the logical VIP for comparison;
        // addresslessness is current/baseline.address == None, not zero binding.
        address: [10, 7, 0, 2],
    };
    let baseline = rows::Snapshot {
        interface: rows::InterfaceRow {
            key: rows::RowKey {
                index: proof.index,
                luid: proof.luid,
            },
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
                path_mtu_discovery_timeout: 0,
                link_local_behavior: 0,
                link_local_timeout: 0,
                zone_indices: [0; 16],
                site_prefix_length: 0,
                metric: 5,
                mtu: 1420,
                disable_default_routes: true,
            },
            observed: rows::InterfaceObserved {
                max_reassembly_size: 0,
                interface_identifier: 0,
                min_router_advertisement_interval: 0,
                max_router_advertisement_interval: 0,
                connected: true,
                supports_wake_up_patterns: false,
                supports_neighbor_discovery: true,
                supports_router_discovery: true,
                reachable_time: 30000,
                transmit_offload: 0,
                receive_offload: 0,
            },
        },
        address: None,
    };
    let mut current = baseline.clone();
    if i == 0 {
        current.address = Some(rows::AddressRow {
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
    }
    let r = rows::Record {
        version: 1,
        domain: rows::DOMAIN.into(),
        binding,
        revision: 4,
        phase: rows::Phase::Captured,
        baseline,
        current: current.clone(),
        pending: None,
        creation: current.address,
    };
    r.validate().unwrap();
    r
}
fn pending_weak(mut row: rows::Record) -> (rows::Record, rows::Target) {
    let mut policy = row.baseline.interface.policy.clone();
    policy.weak_host_send = true;
    policy.weak_host_receive = true;
    let target = rows::Target::Interface(policy);
    row.pending = Some(rows::Pending {
        before: row.current.clone(),
        target: target.clone(),
    });
    row.validate().unwrap();
    (row, target)
}
fn closing(mut r: pair::Record, stage: u8, effect: pair::Effect) -> pair::Record {
    r.phase = pair::Phase::Closing;
    r.active = None;
    r.operation = None;
    r.stop_stage = stage;
    r.pending = Some(effect);
    r
}

// Break: allowing Create/Start after the bootstrap-only creator was upgraded.
#[test]
fn creation_and_new_session_are_denied_after_full_upgrade() {
    let (c, r) = fixture();
    for stage in [
        LifecycleStage::Resolve,
        LifecycleStage::Create,
        LifecycleStage::Session,
    ] {
        assert!(compare_lifecycle_stage(&c, &r, stage).is_err());
    }
    assert!(compare_lifecycle_stage(&c, &r, LifecycleStage::Observe).is_ok());
}

// Break: final resource checks reuse stage8 permission or require cleared
// Stopped carrier metadata to masquerade as a live original C.
#[test]
fn full_empty_guard_has_disjoint_closing_and_stopped_frames() {
    let (c, mut r) = fixture();
    r = closing(r, 12, pair::Effect::FullEmpty);
    r.guard = policy::Model::empty(r.scope.clone()).unwrap();
    let empty = policy::Snapshot {
        version: 2,
        scope: r.scope.clone(),
        carrier: None,
        egress: [None, None],
        sublayer: None,
        filters: vec![],
    };
    compare_full_empty_guard(&c, &r, &empty).unwrap();
    let mut stopped = r.clone();
    stopped.phase = pair::Phase::Stopped;
    stopped.pending = None;
    stopped.carrier = None;
    stopped.members = [None, None];
    compare_full_empty_guard(&c, &stopped, &empty).unwrap();
    for fault in 0..7 {
        let mut wrong = r.clone();
        let mut observed = empty.clone();
        match fault {
            0 => wrong.stop_stage = 8,
            1 => wrong.pending = Some(pair::Effect::CarrierClose),
            2 => wrong.phase = pair::Phase::Running,
            3 => wrong.provenance.network_epoch += 1,
            4 => wrong.addresses.clear(),
            5 => observed.version = 1,
            _ => observed.scope.runtime_generation += 1,
        }
        assert!(
            compare_full_empty_guard(&c, &wrong, &observed).is_err(),
            "{fault}"
        );
    }
}

#[test]
fn restored_keys_resources_read_actual_closing11_not_future_full_empty() {
    let (context, record) = fixture();
    let mut record = closing(record, 11, pair::Effect::RestoreKeys);
    record.guard = policy::Model::empty(record.scope.clone()).unwrap();
    let observed = record.guard.expected.clone();
    compare_restored_keys_guard(&context, &record, &observed).unwrap();
    assert!(compare_full_empty_guard(&context, &record, &observed).is_err());
    for fault in 0..7 {
        let mut wrong = record.clone();
        let mut actual = observed.clone();
        match fault {
            0 => wrong.stop_stage = 12,
            1 => wrong.pending = Some(pair::Effect::FullEmpty),
            2 => wrong.pending = None,
            3 => wrong.phase = pair::Phase::Stopped,
            4 => wrong.carrier = None,
            5 => wrong.provenance.network_epoch += 1,
            _ => actual.scope.runtime_generation += 1,
        }
        assert!(compare_restored_keys_guard(&context, &wrong, &actual).is_err());
    }
}
// Break: final empty history requires C.creation=None (losing genuine original
// provenance), or permits live native observations/restoration/binding drift.
#[test]
fn full_empty_rows_keep_c_creation_history_but_require_stopped_original_baselines() {
    let (c, r) = fixture();
    for role in [rows::Role::Carrier, rows::Role::MemberA] {
        let mut ack = row_fixture(&c, &r, role);
        ack.phase = rows::Phase::Stopped;
        ack.current = ack.baseline.clone();
        let original = CapturedRow {
            binding: ack.binding.clone(),
            baseline: ack.baseline.clone(),
        };
        let identity = policy::Identity {
            scope: ack.binding.scope.clone(),
            proof: owner::InterfaceProof {
                guid: ack.binding.guid,
                index: ack.binding.key.index,
                luid: ack.binding.key.luid,
            },
        };
        compare_full_empty_row(&original, &ack, &identity, None).unwrap();
        for fault in 0..7 {
            let mut wrong = ack.clone();
            let mut proof = identity.clone();
            let observed = match fault {
                0 => {
                    wrong.phase = rows::Phase::Closing;
                    None
                }
                1 => {
                    wrong.current.interface.policy.weak_host_send = true;
                    None
                }
                2 => {
                    proof.proof.index += 1;
                    None
                }
                3 => {
                    wrong.baseline.interface.policy.metric += 1;
                    wrong.current.interface.policy.metric += 1;
                    None
                }
                4 => {
                    wrong.binding.network_epoch += 1;
                    None
                }
                5 => {
                    proof.scope.connection_generation += 1;
                    None
                }
                _ => Some(&ack.current),
            };
            assert!(
                compare_full_empty_row(&original, &wrong, &proof, observed).is_err(),
                "{role:?}/{fault}"
            );
        }
    }
}

// Break: exact End and Close effects become interchangeable or use the wrong stop stage.
#[test]
fn exact_end_close_and_address_delete_stages_do_not_cross_authorize() {
    let (c, r) = fixture();
    let end = closing(r.clone(), 7, pair::Effect::CarrierSessionEnd);
    assert!(compare_lifecycle_stage(&c, &end, LifecycleStage::End).is_ok());
    assert!(compare_lifecycle_stage(&c, &end, LifecycleStage::Close).is_err());
    let close = closing(r.clone(), 8, pair::Effect::CarrierClose);
    assert!(compare_lifecycle_stage(&c, &close, LifecycleStage::Close).is_ok());
    assert!(compare_lifecycle_stage(&c, &close, LifecycleStage::End).is_err());
    let delete = closing(r, 6, pair::Effect::CarrierAddressDelete);
    assert!(compare_row_stage(&c, &delete, rows::Role::Carrier, &rows::Target::Delete).is_ok());
    assert!(compare_row_stage(&c, &end, rows::Role::Carrier, &rows::Target::Delete).is_err());
}
// Break: weak-host CAS accepts a target before the exact whole-Pair WeakRows intent or captured bases.
#[test]
fn weak_rows_require_exact_intent_captured_bases_and_no_permits() {
    let (c, r) = fixture();
    let (row, target) = pending_weak(row_fixture(&c, &r, rows::Role::MemberA));
    assert!(compare_row_stage(&c, &r, row.binding.role, &target).is_ok());
    assert!(compare_guard_blocks(&r, &r.guard.expected).is_ok());
    let mut drift = r.clone();
    drift.pending = Some(pair::Effect::Network);
    assert!(compare_row_stage(&c, &drift, row.binding.role, &target).is_err());
    let mut sdk = r.guard.expected.clone();
    sdk.sublayer.as_mut().unwrap().weight += 1;
    assert!(compare_guard_blocks(&r, &sdk).is_err());
    sdk = r.guard.expected.clone();
    sdk.filters[0].action = policy::Action::Permit;
    assert!(compare_guard_blocks(&r, &sdk).is_err());
}
// Break: pending target equality or a partial policy is accepted instead of complete original ACK/protected/native before.
#[test]
fn row_effect_requires_full_pending_before_and_preserves_every_other_field() {
    let (c, r) = fixture();
    let (ack, target) = pending_weak(row_fixture(&c, &r, rows::Role::MemberA));
    assert!(compare_row_effect(&c, &r, &ack.binding, &target, &ack, &ack, &ack.current).is_ok());
    let mut native = ack.current.clone();
    native.interface.policy.metric += 1;
    assert!(compare_row_effect(&c, &r, &ack.binding, &target, &ack, &ack, &native).is_err());
    let mut protected = ack.clone();
    protected.revision += 1;
    assert!(compare_row_effect(
        &c,
        &r,
        &ack.binding,
        &target,
        &ack,
        &protected,
        &ack.current
    )
    .is_err());
    let mut target = match target {
        rows::Target::Interface(p) => p,
        _ => unreachable!(),
    };
    target.forwarding = true;
    assert!(compare_row_effect(
        &c,
        &r,
        &ack.binding,
        &rows::Target::Interface(target),
        &ack,
        &ack,
        &ack.current
    )
    .is_err());
}
// Break: restoration admits the wrong phase/stage, or a new baseline instead of the original full row baseline.
#[test]
fn restore_only_closing_three_exact_original_baseline() {
    let (c, r) = fixture();
    let mut ack = row_fixture(&c, &r, rows::Role::MemberA);
    ack.current.interface.policy.weak_host_send = true;
    ack.current.interface.policy.weak_host_receive = true;
    ack.phase = rows::Phase::Closing;
    let target = rows::Target::Interface(ack.baseline.interface.policy.clone());
    ack.pending = Some(rows::Pending {
        before: ack.current.clone(),
        target: target.clone(),
    });
    let r = closing(r, 3, pair::Effect::RestoreWeak);
    assert!(compare_row_effect(&c, &r, &ack.binding, &target, &ack, &ack, &ack.current).is_ok());
    let mut drift = r.clone();
    drift.stop_stage = 2;
    assert!(compare_row_stage(&c, &drift, ack.binding.role, &target).is_err());
    let mut changed = ack.baseline.interface.policy.clone();
    changed.mtu += 1;
    assert!(compare_row_effect(
        &c,
        &r,
        &ack.binding,
        &rows::Target::Interface(changed),
        &ack,
        &ack,
        &ack.current
    )
    .is_err());
}
// Break: deleting a matching SDK address without the actual original acknowledged creation.
#[test]
fn address_delete_requires_same_original_creation_and_full_before() {
    let (c, r) = fixture();
    let mut ack = row_fixture(&c, &r, rows::Role::Carrier);
    ack.phase = rows::Phase::Closing;
    ack.pending = Some(rows::Pending {
        before: ack.current.clone(),
        target: rows::Target::Delete,
    });
    let r = closing(r, 6, pair::Effect::CarrierAddressDelete);
    assert!(compare_row_effect(
        &c,
        &r,
        &ack.binding,
        &rows::Target::Delete,
        &ack,
        &ack,
        &ack.current
    )
    .is_ok());
    let mut lost = ack.clone();
    lost.creation = None;
    assert!(compare_row_effect(
        &c,
        &r,
        &ack.binding,
        &rows::Target::Delete,
        &lost,
        &ack,
        &ack.current
    )
    .is_err());
    let mut native = ack.current.clone();
    native.address.as_mut().unwrap().observed.creation_timestamp += 1;
    assert!(compare_row_effect(
        &c,
        &r,
        &ack.binding,
        &rows::Target::Delete,
        &ack,
        &ack,
        &native
    )
    .is_err());
}
// Break: weak restoration/address absence is inferred from rows which are still pending or have altered metadata.
#[test]
fn closing_carrier_requires_address_gone_and_exact_weak_restoration() {
    let (c, r) = fixture();
    let mut row = row_fixture(&c, &r, rows::Role::Carrier);
    row.phase = rows::Phase::Stopped;
    row.current = row.baseline.clone();
    assert!(compare_closed_carrier_row(&c, &r, &row, &row.current).is_ok());
    let mut native = row.current.clone();
    native.interface.policy.weak_host_send = true;
    assert!(compare_closed_carrier_row(&c, &r, &row, &native).is_err());
    row.pending = Some(rows::Pending {
        before: row.current.clone(),
        target: rows::Target::Delete,
    });
    assert!(compare_closed_carrier_row(&c, &r, &row, &native).is_err());
}
// Break: caught nested error or unwind returns a successful outer authorization or rearms forward.
#[test]
fn lifecycle_fence_retains_failure_and_cleanup_never_rearms() {
    let fence = LifecycleFence::new();
    assert!(fence
        .run(false, || {
            let _ = fence.run(false, || Ok(()));
            Ok(())
        })
        .is_err());
    assert!(fence.run(false, || Ok(())).is_err());
    assert!(fence.run(true, || Ok(())).is_ok());
    assert!(fence.run(false, || Ok(())).is_err());
    let fence = LifecycleFence::new();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = fence.run(false, || -> std::io::Result<()> { panic!("native read") });
    }));
    assert!(fence.run(false, || Ok(())).is_err());
}

// Break: readonly SDK observations are confused with writable baseline policy.
#[test]
fn restored_row_uses_full_current_ack_without_freezing_old_readonly_observations() {
    let (c, r) = fixture();
    let mut row = row_fixture(&c, &r, rows::Role::Carrier);
    row.phase = rows::Phase::Stopped;
    row.current = row.baseline.clone();
    row.current.interface.observed.reachable_time += 1;
    assert!(compare_closed_carrier_row(&c, &r, &row, &row.current).is_ok());
    let mut changed_sdk = row.current.clone();
    changed_sdk.interface.observed.reachable_time += 1;
    assert!(compare_closed_carrier_row(&c, &r, &row, &changed_sdk).is_err());
}

// Break: stage-six metadata alone substitutes for actual weak restoration.
#[test]
fn address_delete_denies_unrestored_weak_flags() {
    let (c, r) = fixture();
    let mut row = row_fixture(&c, &r, rows::Role::Carrier);
    row.phase = rows::Phase::Closing;
    row.current.interface.policy.weak_host_send = true;
    row.pending = Some(rows::Pending {
        before: row.current.clone(),
        target: rows::Target::Delete,
    });
    let r = closing(r, 6, pair::Effect::CarrierAddressDelete);
    assert!(compare_row_effect(
        &c,
        &r,
        &row.binding,
        &rows::Target::Delete,
        &row,
        &row,
        &row.current
    )
    .is_err());
}

// Break: actual Create ACK requires unchanged DAD progress instead of its exact
// immutable address identity/timestamp; native-before still must be full exact.
#[test]
fn address_delete_uses_original_creation_identity_after_dad_progress() {
    let (c, r) = fixture();
    let mut row = row_fixture(&c, &r, rows::Role::Carrier);
    row.creation.as_mut().unwrap().observed.dad_state = 3;
    row.phase = rows::Phase::Closing;
    row.pending = Some(rows::Pending {
        before: row.current.clone(),
        target: rows::Target::Delete,
    });
    let r = closing(r, 6, pair::Effect::CarrierAddressDelete);
    assert!(compare_row_effect(
        &c,
        &r,
        &row.binding,
        &rows::Target::Delete,
        &row,
        &row,
        &row.current
    )
    .is_ok());
}

// Break: already-revoked cleanup swallows a nested denial and reports success.
#[test]
fn cleanup_fence_cannot_swallow_nested_failure() {
    let fence = LifecycleFence::new();
    assert!(fence
        .run(true, || {
            let _ = fence.run(true, || Ok(()));
            Ok(())
        })
        .is_err());
    assert!(fence.run(true, || Ok(())).is_ok());
    assert!(fence.run(false, || Ok(())).is_err());
}

// Break: a zero-address or other logical-VIP member binding is accepted merely
// because its actual SDK address row is absent.
#[test]
fn addressless_member_binding_still_requires_exact_logical_vip() {
    let (c, r) = fixture();
    let row = row_fixture(&c, &r, rows::Role::MemberA);
    assert!(compare_row_binding(&c, &r, &row.binding).is_ok());
    let mut foreign = row.binding.clone();
    foreign.address = [0; 4];
    assert!(compare_row_binding(&c, &r, &foreign).is_err());
    foreign.address = [10, 7, 0, 3];
    assert!(compare_row_binding(&c, &r, &foreign).is_err());
}

// Break: a closed sibling accepts captured/pending/unrestored/foreign ACKs.
// Typed same-original CLOSED/native absence remains a separate actual Window
// requirement; this helper cannot manufacture that native capability.
#[test]
fn closed_member_ack_requires_exact_original_stopped_baseline() {
    let (c, r) = fixture();
    let mut row = row_fixture(&c, &r, rows::Role::MemberA);
    let original = row.binding.clone();
    let baseline = row.baseline.clone();
    row.phase = rows::Phase::Stopped;
    assert!(compare_closed_member_ack(&original, &baseline, &row).is_ok());
    let mut bad = row.clone();
    bad.phase = rows::Phase::Captured;
    assert!(compare_closed_member_ack(&original, &baseline, &bad).is_err());
    bad = row.clone();
    bad.current.interface.policy.weak_host_send = true;
    assert!(compare_closed_member_ack(&original, &baseline, &bad).is_err());
    bad = row.clone();
    bad.binding.guid = [9; 16];
    assert!(compare_closed_member_ack(&original, &baseline, &bad).is_err());
    bad = row.clone();
    bad.baseline.interface.policy.metric += 1;
    assert!(compare_closed_member_ack(&original, &baseline, &bad).is_err());
}

// Break: replacement overwrites the immutable first row registration, or an
// equal-valued foreign pin can select the next generation.
#[test]
fn row_lineage_appends_without_adopting_equal_foreign_origins() {
    use std::rc::Rc;
    let (c, r) = fixture();
    let row = row_fixture(&c, &r, rows::Role::MemberA);
    let lineage = RowLineage::new();
    let first = Rc::new(7);
    let old = lineage.begin(None).unwrap();
    lineage
        .retain(
            old,
            &first,
            || {
                Ok(CapturedRow {
                    binding: row.binding.clone(),
                    baseline: row.baseline.clone(),
                })
            },
            |_| Ok(()),
        )
        .unwrap();
    lineage.complete(old).unwrap();
    assert!(Rc::ptr_eq(&lineage.read(false).unwrap().0, &first));
    let next = lineage.begin(Some(&first)).unwrap();
    assert!(lineage.read(false).is_err());
    let new = Rc::new(7);
    lineage
        .retain(
            next,
            &new,
            || {
                Ok(CapturedRow {
                    binding: row.binding.clone(),
                    baseline: row.baseline.clone(),
                })
            },
            |_| Ok(()),
        )
        .unwrap();
    lineage.complete(next).unwrap();
    assert!(Rc::ptr_eq(&lineage.read(false).unwrap().0, &new));
    assert!(Rc::ptr_eq(&lineage.original(old).unwrap().0, &first));
    assert!(lineage.begin(Some(&Rc::new(7))).is_err());
    assert!(Rc::ptr_eq(&lineage.read(true).unwrap().0, &new));
}

// Break: failed/unwound postflight erases the new original, rearms forward, or
// leaves a strong Gate->row->Gate cycle. Actor owns these actual test pins.
#[test]
fn row_lineage_roots_registration_before_error_and_unwind_without_strong_cycle() {
    use std::{cell::Cell, rc::Rc};
    struct Pin(Rc<Cell<usize>>);
    impl Drop for Pin {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let (c, r) = fixture();
    let row = row_fixture(&c, &r, rows::Role::MemberA);
    for unwind in [false, true] {
        let dropped = Rc::new(Cell::new(0));
        let pin = Rc::new(Pin(dropped.clone()));
        let lineage = RowLineage::new();
        let attempt = lineage.begin(None).unwrap();
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            lineage.retain(
                attempt,
                &pin,
                || {
                    Ok(CapturedRow {
                        binding: row.binding.clone(),
                        baseline: row.baseline.clone(),
                    })
                },
                |_| {
                    if unwind {
                        panic!("postflight");
                    }
                    Err(conflict())
                },
            )
        }));
        if unwind {
            assert!(caught.is_err());
        } else {
            assert!(caught.unwrap().is_err());
        }
        assert!(lineage.read(false).is_err());
        assert!(Rc::ptr_eq(&lineage.read(true).unwrap().0, &pin));
        assert!(lineage.complete(attempt).is_err());
        assert!(lineage.begin(None).is_err());
        drop(pin);
        assert_eq!(dropped.get(), 1);
        assert!(lineage.read(true).is_err());
    }
}

// Break: catching a nested registration denial permits the outer attempt to
// complete, or duplicate ACK registration replaces the first original.
#[test]
fn row_lineage_denies_caught_reentry_and_duplicate_ack() {
    use std::rc::Rc;
    let (c, r) = fixture();
    let row = row_fixture(&c, &r, rows::Role::MemberA);
    let lineage = RowLineage::new();
    let pin = Rc::new(1);
    let attempt = lineage.begin(None).unwrap();
    assert!(lineage
        .retain(
            attempt,
            &pin,
            || Ok(CapturedRow {
                binding: row.binding.clone(),
                baseline: row.baseline.clone(),
            }),
            |_| {
                let _ = lineage.complete(attempt);
                Ok(())
            }
        )
        .is_err());
    assert!(lineage.complete(attempt).is_err());
    assert!(lineage
        .retain(
            attempt,
            &Rc::new(1),
            || panic!("duplicate inspected"),
            |_| Ok(())
        )
        .is_err());
    assert!(Rc::ptr_eq(&lineage.read(true).unwrap().0, &pin));
}

// Break: a capture aperture admits a different lifecycle/effect/target, an
// active target, permits, or a baseline that already contains a weak delta.
#[test]
fn member_capture_frame_is_target_exact_and_baseline_only() {
    let (c, r) = fixture();
    let row = row_fixture(&c, &r, rows::Role::MemberA);
    assert!(compare_member_capture_frame(&c, &r, &row.binding, false).is_ok());
    assert!(compare_member_capture_baseline(&row.binding, &row).is_ok());
    for effect in [
        pair::Effect::Guard,
        pair::Effect::Network,
        pair::Effect::HoldProbe(Slot::A),
    ] {
        let mut wrong = r.clone();
        wrong.pending = Some(effect);
        assert!(compare_member_capture_frame(&c, &wrong, &row.binding, false).is_err());
    }
    let mut wrong = r.clone();
    wrong.operation = Some(pair::Operation::Start(Slot::B));
    assert!(compare_member_capture_frame(&c, &wrong, &row.binding, false).is_err());
    assert!(compare_member_capture_frame(&c, &r, &row.binding, true).is_err());
    let mut foreign = row.binding.clone();
    foreign.key.index += 1;
    assert!(compare_member_capture_frame(&c, &r, &foreign, false).is_err());
    for change in 0..4 {
        let mut wrong = row.clone();
        match change {
            0 => {
                wrong.baseline.interface.policy.weak_host_send = true;
                wrong.current = wrong.baseline.clone();
            }
            1 => wrong.phase = rows::Phase::Stopped,
            2 => wrong.current.interface.policy.metric += 1,
            _ => wrong.baseline.interface.policy.forwarding = true,
        }
        assert!(compare_member_capture_baseline(&row.binding, &wrong).is_err());
    }
}

// Break: first committed Start cannot capture its addressless baseline before
// initial base installation, or this read-only aperture accepts pending Guard,
// a fresh/Prepared owner, traffic allows, or a replacement without its old seal.
#[test]
fn initial_started_capture_can_read_prebase_but_never_guard_or_effect_permission() {
    let (c, mut r) = fixture();
    let row = row_fixture(&c, &r, rows::Role::MemberA);
    r.pending = None;
    r.guard = policy::Model::empty(r.scope.clone()).unwrap();
    r.validate().unwrap();
    compare_member_capture_frame(&c, &r, &row.binding, false).unwrap();
    for stage in [
        LifecycleStage::Observe,
        LifecycleStage::Create,
        LifecycleStage::Session,
        LifecycleStage::End,
        LifecycleStage::Close,
        LifecycleStage::AfterClose,
    ] {
        assert!(
            compare_lifecycle_stage(&c, &r, stage).is_err(),
            "ordinary stage must not acquire the typed first-Start read aperture"
        );
    }
    assert!(compare_member_capture_frame(&c, &r, &row.binding, true).is_err());
    for fault in 0..4 {
        let mut bad = r.clone();
        match fault {
            0 => bad.pending = Some(pair::Effect::Guard),
            1 => bad.phase = pair::Phase::Fresh,
            2 => bad.members[0].as_mut().unwrap().owner.phase = owner::Phase::Prepared,
            _ => bad.operation = Some(pair::Operation::Start(Slot::B)),
        }
        assert!(compare_member_capture_frame(&c, &bad, &row.binding, false).is_err());
    }
}

// Break: a lost intent CAS ACK prevents the same original from observing its
// exact cleanup obligation, or desired/private bytes are silently promoted to ACK.
#[test]
fn closing_write_attempt_observes_before_or_applied_without_promoting_ack() {
    let (c, r) = fixture();
    let r = closing(r, 3, pair::Effect::RestoreWeak);
    let ack = row_fixture(&c, &r, rows::Role::MemberA);
    let original = CapturedRow {
        binding: ack.binding.clone(),
        baseline: ack.baseline.clone(),
    };
    let mut desired = ack.clone();
    desired.revision += 1;
    let mut policy = ack.baseline.interface.policy.clone();
    policy.weak_host_send = true;
    policy.weak_host_receive = true;
    desired.pending = Some(rows::Pending {
        before: ack.current.clone(),
        target: rows::Target::Interface(policy.clone()),
    });
    desired.validate().unwrap();
    for applied in [false, true] {
        let mut actual = ack.current.clone();
        if applied {
            actual.interface.policy = policy.clone();
        }
        assert_eq!(
            compare_closing_row_observation(ClosingRowObservation {
                context: &c,
                pair: &r,
                original: &original,
                acknowledged: &ack,
                protected: &desired,
                actual: &actual,
                attempt: Some((&ack, &desired)),
            })
            .unwrap(),
            ClosingRowWriteState::DesiredAttempt
        );
        assert_eq!(ack.revision, 4);
        assert!(ack.pending.is_none());
        let target = rows::Target::Interface(ack.baseline.interface.policy.clone());
        assert!(
            compare_row_effect(&c, &r, &ack.binding, &target, &ack, &desired, &actual).is_err()
        );
    }
}

// Break: false CAS/private-before is treated as desired native application, or
// absence of the actual attempted original is replaced with metadata adoption.
#[test]
fn closing_false_write_requires_private_before_native_before() {
    let (c, r) = fixture();
    let r = closing(r, 3, pair::Effect::RestoreWeak);
    let ack = row_fixture(&c, &r, rows::Role::MemberA);
    let original = CapturedRow {
        binding: ack.binding.clone(),
        baseline: ack.baseline.clone(),
    };
    let mut before = ack.clone();
    before.revision += 1; // a previous retained, unknown-own CAS obligation
    let mut desired = before.clone();
    desired.revision += 1;
    desired.current.interface.policy.weak_host_send = true;
    desired.current.interface.policy.weak_host_receive = true;
    for (actual, want) in [(&before.current, true), (&desired.current, false)] {
        let result = compare_closing_row_observation(ClosingRowObservation {
            context: &c,
            pair: &r,
            original: &original,
            acknowledged: &ack,
            protected: &before,
            actual,
            attempt: Some((&before, &desired)),
        });
        assert_eq!(result.is_ok(), want);
        if want {
            assert_eq!(result.unwrap(), ClosingRowWriteState::BeforeAttempt);
        }
    }
    assert!(compare_closing_row_observation(ClosingRowObservation {
        context: &c,
        pair: &r,
        original: &original,
        acknowledged: &ack,
        protected: &desired,
        actual: &desired.current,
        attempt: None,
    })
    .is_err());
}

// Break: Closing comparison admits a foreign/stale/partial attempt, arbitrary
// policy delta, future stage, or native snapshot other than exact before/applied.
#[test]
fn closing_attempt_denies_foreign_frame_baseline_creation_and_native_drift() {
    let (c, r) = fixture();
    let r = closing(r, 3, pair::Effect::RestoreWeak);
    let ack = row_fixture(&c, &r, rows::Role::MemberA);
    let original = CapturedRow {
        binding: ack.binding.clone(),
        baseline: ack.baseline.clone(),
    };
    let mut desired = ack.clone();
    desired.revision += 1;
    desired.current.interface.policy.weak_host_send = true;
    for fault in 0..10 {
        let mut pair = r.clone();
        let mut target = desired.clone();
        let mut actual = desired.current.clone();
        let mut before = ack.clone();
        match fault {
            0 => pair = fixture().1, // Source/forward frame cannot use Closing facts
            1 => pair = closing(r.clone(), 7, pair::Effect::CarrierSessionEnd),
            2 => target.binding.key.index += 1,
            3 => {
                target.baseline.interface.policy.metric += 1;
                target.current.interface.policy.metric += 1;
            }
            4 => target.revision += 1,
            5 => target.current.interface.policy.forwarding = true,
            6 => actual.interface.policy.weak_host_receive = true,
            7 => actual.interface.key.luid += 1,
            8 => before.revision += 3,
            _ => target.binding.network_epoch += 1,
        }
        assert!(
            compare_closing_row_observation(ClosingRowObservation {
                context: &c,
                pair: &pair,
                original: &original,
                acknowledged: &ack,
                protected: &target,
                actual: &actual,
                attempt: Some((&before, &target)),
            })
            .is_err(),
            "fault {fault}"
        );
    }
}

// Break: observation of an original pending Delete becomes a new ownership or
// native-delete grant, including a matching-looking creation added only in attempt.
#[test]
fn closing_delete_observation_keeps_original_creation_and_effect_ack_separate() {
    let (c, r) = fixture();
    let r = closing(r, 6, pair::Effect::CarrierAddressDelete);
    let mut ack = row_fixture(&c, &r, rows::Role::Carrier);
    ack.phase = rows::Phase::Closing;
    let original = CapturedRow {
        binding: ack.binding.clone(),
        baseline: ack.baseline.clone(),
    };
    let mut desired = ack.clone();
    desired.revision += 1;
    desired.pending = Some(rows::Pending {
        before: ack.current.clone(),
        target: rows::Target::Delete,
    });
    let mut deleted = ack.current.clone();
    deleted.address = None;
    for actual in [&ack.current, &deleted] {
        assert_eq!(
            compare_closing_row_observation(ClosingRowObservation {
                context: &c,
                pair: &r,
                original: &original,
                acknowledged: &ack,
                protected: &desired,
                actual,
                attempt: Some((&ack, &desired)),
            })
            .unwrap(),
            ClosingRowWriteState::DesiredAttempt
        );
        assert!(compare_row_effect(
            &c,
            &r,
            &ack.binding,
            &rows::Target::Delete,
            &ack,
            &desired,
            actual
        )
        .is_err());
    }
    let mut missing = ack.clone();
    missing.creation = None;
    missing.current.address = None;
    assert!(compare_closing_row_observation(ClosingRowObservation {
        context: &c,
        pair: &r,
        original: &original,
        acknowledged: &missing,
        protected: &desired,
        actual: &deleted,
        attempt: Some((&ack, &desired)),
    })
    .is_err());
    let mut foreign = desired.clone();
    foreign
        .creation
        .as_mut()
        .unwrap()
        .observed
        .creation_timestamp += 1;
    foreign
        .current
        .address
        .as_mut()
        .unwrap()
        .observed
        .creation_timestamp += 1;
    foreign.pending.as_mut().unwrap().before = foreign.current.clone();
    assert!(compare_closing_row_observation(ClosingRowObservation {
        context: &c,
        pair: &r,
        original: &original,
        acknowledged: &ack,
        protected: &foreign,
        actual: &deleted,
        attempt: Some((&ack, &foreign)),
    })
    .is_err());
}

// Break: a prepublication C Create-confirmation attempt is imported as creation
// provenance. The actual Ready RowOwner's CreatedAddressReceipt is deliberately
// NOT an input here; only that retained owner can reconcile its own creation.
#[test]
fn closing_prepublication_create_confirmation_cannot_import_creation() {
    let (c, r) = fixture();
    let r = closing(r, 3, pair::Effect::RestoreWeak);
    let mut desired = row_fixture(&c, &r, rows::Role::Carrier);
    let original = CapturedRow {
        binding: desired.binding.clone(),
        baseline: desired.baseline.clone(),
    };
    let mut ack = desired.clone();
    ack.current = ack.baseline.clone();
    ack.creation = None;
    ack.pending = Some(rows::Pending {
        before: ack.baseline.clone(),
        target: rows::Target::Create(desired.creation.as_ref().unwrap().policy.clone()),
    });
    desired.revision = 5;
    ack.validate().unwrap();
    desired.validate().unwrap();
    for protected in [&ack, &desired] {
        assert!(compare_closing_row_observation(ClosingRowObservation {
            context: &c,
            pair: &r,
            original: &original,
            acknowledged: &ack,
            protected,
            actual: &desired.current,
            attempt: Some((&ack, &desired)),
        })
        .is_err());
    }
    assert!(ack.creation.is_none());
    assert!(matches!(
        ack.pending.unwrap().target,
        rows::Target::Create(_)
    ));
}

// Break: a lost baseline ACK can be completed/retried, or its supplied original
// is destroyed by the gate. Old generation remains separate immutable history.
#[test]
fn row_lineage_lost_new_ack_keeps_old_history_and_denies_forward_retry() {
    use std::rc::Rc;
    let (c, r) = fixture();
    let row = row_fixture(&c, &r, rows::Role::MemberA);
    let lineage = RowLineage::new();
    let old = Rc::new(23);
    let first = lineage.begin(None).unwrap();
    lineage
        .retain(
            first,
            &old,
            || {
                Ok(CapturedRow {
                    binding: row.binding.clone(),
                    baseline: row.baseline.clone(),
                })
            },
            |_| Ok(()),
        )
        .unwrap();
    lineage.complete(first).unwrap();
    let next = lineage.begin(Some(&old)).unwrap();
    let pin = Rc::new(24);
    assert!(lineage
        .retain(
            next,
            &pin,
            || Err(conflict()),
            |_| panic!("unknown postflight")
        )
        .is_err());
    assert!(lineage.complete(next).is_err());
    assert!(lineage.read(false).is_err());
    assert!(lineage.read(true).is_err());
    assert!(Rc::ptr_eq(&lineage.original(first).unwrap().0, &old));
    assert!(std::rc::Weak::ptr_eq(
        lineage.generations.borrow()[next].pin.as_ref().unwrap(),
        &Rc::downgrade(&pin)
    ));
    assert!(lineage.begin(Some(&old)).is_err());
}

// Break: a generation transition treats the very same old origin as a new ACK.
#[test]
fn row_lineage_cannot_reenroll_old_original_as_new_baseline() {
    use std::rc::Rc;
    let (c, r) = fixture();
    let row = row_fixture(&c, &r, rows::Role::MemberA);
    let lineage = RowLineage::new();
    let pin = Rc::new(23);
    let first = lineage.begin(None).unwrap();
    lineage
        .retain(
            first,
            &pin,
            || {
                Ok(CapturedRow {
                    binding: row.binding.clone(),
                    baseline: row.baseline.clone(),
                })
            },
            |_| Ok(()),
        )
        .unwrap();
    lineage.complete(first).unwrap();
    let next = lineage.begin(Some(&pin)).unwrap();
    assert!(lineage
        .retain(
            next,
            &pin,
            || Ok(CapturedRow {
                binding: row.binding.clone(),
                baseline: row.baseline.clone(),
            }),
            |_| Ok(())
        )
        .is_err());
    assert!(lineage.complete(next).is_err());
    assert!(Rc::ptr_eq(&lineage.original(first).unwrap().0, &pin));
}

// The first MemberStart Observe sees Prepared metadata before any SDK member ACK.
#[test]
fn initial_member_start_window_allows_only_exact_unstarted_primary_bindings() {
    let (context, running) = fixture();
    let identity = policy::Identity {
        scope: running.scope.clone(),
        proof: running.members[0]
            .as_ref()
            .unwrap()
            .owner
            .proof
            .unwrap()
            .interface,
    };
    assert!(compare_member_bindings(&running, &[Some(identity.clone()), None]).is_ok());
    let mut wrong_identity = identity.clone();
    wrong_identity.proof.luid += 1;
    assert!(compare_member_bindings(&running, &[Some(wrong_identity), None]).is_err());

    let mut prepared = running.clone();
    let owner = &mut prepared.members[0].as_mut().unwrap().owner;
    owner.phase = owner::Phase::Prepared;
    owner.proof = None;
    prepared.pending = Some(pair::Effect::MemberStart(Slot::A));
    prepared.guard = policy::Model::empty(prepared.scope.clone()).unwrap();
    prepared.validate().unwrap();
    compare_lifecycle_stage(&context, &prepared, LifecycleStage::Observe).unwrap();
    assert!(compare_member_bindings(&prepared, &[None, None]).is_ok());
    for fault in 0..14 {
        let mut record = prepared.clone();
        match fault {
            0 => record.pending = Some(pair::Effect::MemberStart(Slot::B)),
            1 => record.operation = Some(pair::Operation::Start(Slot::B)),
            2 => record.phase = pair::Phase::Closing,
            3 => record.stop_stage = 1,
            4 => record.active = Some(Slot::A),
            5 => {
                record.network = Some(pair::NetworkState {
                    baseline: pair::NetworkSnapshot {
                        routes: vec![],
                        dns: None,
                    },
                    current: pair::NetworkSnapshot {
                        routes: vec![],
                        dns: None,
                    },
                    pending: None,
                })
            }
            6 => {
                record.pending_guard =
                    Some(policy::ExchangePlan::new(&record.guard, &record.guard).unwrap())
            }
            7 => record.guard = running.guard.clone(),
            8 => record.members[0].as_mut().unwrap().owner.phase = owner::Phase::Running,
            9 => {
                let mut other = record.members[0].as_ref().unwrap().clone();
                other.owner.intent.slot = TunnelSlot::B;
                record.members[1] = Some(other);
            }
            10 => record.pending = None,
            11 => record.operation = Some(pair::Operation::Attach(Slot::A)),
            12 => {
                record.members[0].as_mut().unwrap().owner.retired_proof =
                    running.members[0].as_ref().unwrap().owner.proof
            }
            _ => {
                record.members[0].as_mut().unwrap().owner.proof =
                    running.members[0].as_ref().unwrap().owner.proof
            }
        }
        assert!(
            compare_member_bindings(&record, &[None, None]).is_err(),
            "fault {fault}"
        );
    }
    for slot in 0..2 {
        let mut egress = [None, None];
        egress[slot] = Some(identity.clone());
        assert!(compare_member_bindings(&prepared, &egress).is_err());
    }
}
