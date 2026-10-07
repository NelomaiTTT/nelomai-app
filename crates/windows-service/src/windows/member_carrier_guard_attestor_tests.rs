use super::*;
use crate::{
    member_carrier::{Intent, Provenance},
    member_carrier_native_ownership::{Binding, Role},
    member_owner as owner,
};
use nelomai_client_tunnel::{
    redundancy::{SessionScope, Slot},
    TunnelTransport,
};
use nelomai_contracts::{
    dispatcher::{EngineIdentity, TunnelSlot},
    RuntimeSlot,
};
use std::panic::{catch_unwind, AssertUnwindSafe};

#[test]
fn guard_attestor_cleanup_read_after_failed_forward_never_rearms_forward() {
    let fence = AttestorFence::new();
    assert!(fence
        .inspect_channel(false, || Err::<(), _>(GuardError::Conflict))
        .is_err());
    assert!(fence.inspect_channel(false, || Ok(())).is_err());
    assert_eq!(fence.inspect_cleanup(|| Ok(17)), Ok(17));
    assert!(fence.inspect_channel(false, || Ok(())).is_err());
    assert_eq!(fence.inspect_cleanup(|| Ok(19)), Ok(19));
}
#[test]
fn guard_attestor_cleanup_ignored_nested_failure_cannot_complete_outer_call() {
    for fault in 0..3 {
        let fence = AttestorFence::new();
        assert!(fence
            .inspect_channel(false, || Err::<(), _>(GuardError::Conflict))
            .is_err());
        let result = catch_unwind(AssertUnwindSafe(|| {
            fence.inspect_cleanup(|| {
                match fault {
                    0 => assert!(fence.inspect_channel(false, || Ok(())).is_err()),
                    1 => assert!(fence.inspect_cleanup(|| Ok(())).is_err()),
                    _ => panic!("cleanup SDK observation unwound"),
                }
                Ok(())
            })
        }));
        assert!(!matches!(result, Ok(Ok(()))));
        assert!(fence.inspect_channel(false, || Ok(())).is_err());
    }
}

fn fixture() -> (Context, pair::Record, Model) {
    let scope = SessionScope {
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
                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{03030303-0303-0303-0303-030303030303}"][i].into() }
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
    let desired = Model::new(
        scope.clone(),
        Carrier {
            identity: Identity {
                scope: scope.clone(),
                proof: c,
            },
            sources: vec!["10.7.0.2".parse().unwrap()],
        },
        [
            Some(policy::Member {
                identity: Identity {
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
    let guard = Model::empty(scope.clone()).unwrap();
    let record = pair::Record {
        version: 2,
        scope,
        provenance,
        revision: 3,
        phase: pair::Phase::Starting,
        addresses: context.intent.addresses.clone(),
        dns: vec![],
        carrier: Some(c),
        members: [Some(member), None],
        active: None,
        options: Some(nelomai_client_tunnel::DesktopTunnelOptions::default()),
        guard: guard.clone(),
        pending_guard: Some(policy::ExchangePlan::new(&guard, &desired).unwrap()),
        pending: Some(pair::Effect::Guard),
        network: None,
        stop_stage: 0,
        operation: Some(pair::Operation::Start(Slot::A)),
    };
    record.validate().unwrap();
    (context, record, desired)
}
fn facts(model: &Model) -> BindingFacts<'_> {
    BindingFacts {
        scope: &model.scope,
        carrier: model.carrier.as_ref(),
        egress: model
            .members
            .each_ref()
            .map(|m| m.as_ref().map(|m| &m.identity)),
    }
}

fn terminal_fixture() -> (
    Context,
    pair::Record,
    Model,
    original_members::ClosedMemberBinding,
) {
    let (context, mut record, bindings) = fixture();
    let member = record.members[0].as_ref().unwrap();
    let history = original_members::ClosedMemberBinding {
        intent: member.owner.intent.clone(),
        proof: member.owner.proof.unwrap(),
    };
    record.phase = pair::Phase::Stopped;
    record.stop_stage = 12;
    record.carrier = None;
    record.members = [None, None];
    record.active = None;
    record.operation = None;
    record.pending = None;
    record.pending_guard = None;
    record.guard = Model::empty(record.scope.clone()).unwrap();
    record.validate().unwrap();
    (context, record, bindings, history)
}

#[test]
fn terminal_guard_read_is_separate_from_closing_and_compares_actual_closed_history() {
    let (context, record, bindings, history) = terminal_fixture();
    // The compiled RED used the original Closing comparator here. The new
    // terminal lane is separate; the old Closing/forward contracts stay shut.
    assert!(
        compare_terminal_bindings(&context, &record, &facts(&bindings), &[history.clone()]).is_ok()
    );
    assert!(compare_retired_read(&context, &record).is_err());
    assert!(compare_pair(&context, &record).is_err());
    let c_only = BindingFacts {
        scope: &bindings.scope,
        carrier: bindings.carrier.as_ref(),
        egress: [None, None],
    };
    compare_terminal_bindings(&context, &record, &c_only, &[]).unwrap();
    assert_eq!(
        bindings.members[0].as_ref().unwrap().identity.proof,
        history.proof.interface
    );
}

#[test]
fn terminal_guard_read_rejects_early_pending_foreign_and_unjoined_histories() {
    let (context, record, bindings, history) = terminal_fixture();
    for fault in 0..9 {
        let mut expected = record.clone();
        let mut actual = bindings.clone();
        let mut closed = vec![history.clone()];
        match fault {
            0 => expected.phase = pair::Phase::Closing,
            1 => expected.stop_stage = 11,
            2 => expected.pending = Some(pair::Effect::FullEmpty),
            3 => expected.provenance.boot_id[0] ^= 1,
            4 => actual.scope.connection_generation += 1,
            5 => actual.carrier.as_mut().unwrap().identity.proof.guid = [9; 16],
            6 => closed.clear(),
            7 => closed[0].proof.process.creation_time = 0,
            _ => closed.push(history.clone()),
        }
        assert!(
            compare_terminal_bindings(&context, &expected, &facts(&actual), &closed).is_err(),
            "fault {fault}"
        );
    }
    // Neither missing SDK projection nor equal unjoined saved proof is enough.
    let mut missing = bindings.clone();
    missing.members[0] = None;
    assert!(compare_terminal_bindings(&context, &record, &facts(&missing), &[history]).is_err());
    assert!(compare_terminal_read(&context, &fixture().1).is_err());
}
fn captured(model: &Model) -> Model {
    let mut actual = model.expected.clone();
    actual.sublayer.as_mut().unwrap().weight = 41;
    model
        .readback_after(&Model::empty(model.scope.clone()).unwrap(), &actual)
        .unwrap()
}
fn permits(base: &Model) -> Model {
    let mut members = base.members.clone();
    members[0].as_mut().unwrap().probes = vec![policy::ProbeTuple {
        source: "10.7.0.2".parse().unwrap(),
        source_port: 40123,
        target: "1.1.1.1".parse().unwrap(),
        target_port: 53,
        protocol: 17,
    }];
    Model::new(
        base.scope.clone(),
        base.carrier.clone().unwrap(),
        members,
        Some(Slot::A),
    )
    .unwrap()
    .inherit_sublayer_weight(base)
    .unwrap()
}

// Break: refusing the valid first Starting static-base edge.
#[test]
fn first_static_base_accepts_exact_starting_original_comparison() {
    let (c, r, d) = fixture();
    assert_eq!(compare_bindings(&c, &r, &facts(&d)), Ok(()));
    assert_eq!(
        compare_exchange(&c, &r, SessionKind::StaticBase, &r.guard, &d),
        Ok(ExchangeEdge::Base)
    );
}
// Break: allowing a Dynamic transaction to create persistent blocks.
#[test]
fn wrong_transaction_kind_cannot_install_bases() {
    let (c, r, d) = fixture();
    assert!(compare_exchange(&c, &r, SessionKind::DynamicPermits, &r.guard, &d).is_err());
}
// Break: accepting a stale protected record, malformed shape, or foreign context.
#[test]
fn foreign_scope_provenance_address_revision_phase_or_effect_is_denied() {
    let (c, r, d) = fixture();
    for fault in 0..9 {
        let mut wrong = r.clone();
        match fault {
            0 => wrong.scope.connection_generation += 1,
            1 => wrong.provenance.boot_id = [9; 16],
            2 => wrong.provenance.network_epoch += 1,
            3 => wrong.addresses = vec!["10.9.0.2/32".parse().unwrap()],
            4 => wrong.revision = 0,
            5 => wrong.phase = pair::Phase::Fresh,
            6 => wrong.pending = Some(pair::Effect::WeakRows),
            7 => wrong.operation = None,
            _ => wrong.stop_stage = 1,
        }
        assert!(
            compare_exchange(&c, &wrong, SessionKind::StaticBase, &wrong.guard, &d).is_err(),
            "fault {fault}"
        );
    }
}
// Break: adopting an equal index with a foreign GUID/LUID or a missing live member.
#[test]
fn bindings_require_complete_exact_carrier_and_egress_proofs() {
    let (c, r, d) = fixture();
    for fault in 0..7 {
        let mut wrong = d.clone();
        match fault {
            0 => wrong.carrier.as_mut().unwrap().identity.proof.guid = [9; 16],
            1 => wrong.carrier.as_mut().unwrap().identity.proof.luid += 1,
            2 => wrong.carrier.as_mut().unwrap().sources = vec!["10.8.0.2".parse().unwrap()],
            3 => wrong.members[0] = None,
            4 => wrong.members[0].as_mut().unwrap().identity.proof.index += 1,
            5 => wrong.members[1] = wrong.members[0].clone(),
            _ => wrong.scope.runtime_generation += 1,
        }
        assert!(
            compare_bindings(&c, &r, &facts(&wrong)).is_err(),
            "fault {fault}"
        );
    }
}
// Break: inferring a permitted exchange from partial JSON rather than the FULL plan.
#[test]
fn malformed_missing_foreign_or_partial_plan_is_denied() {
    let (c, r, d) = fixture();
    for fault in 0..5 {
        let mut wrong = r.clone();
        match fault {
            0 => wrong.pending_guard = None,
            1 => wrong.pending_guard.as_mut().unwrap().version = 1,
            2 => wrong.pending_guard.as_mut().unwrap().withdrawn = d.clone(),
            3 => {
                wrong
                    .pending_guard
                    .as_mut()
                    .unwrap()
                    .captured_sublayer_weight = Some(41)
            }
            _ => wrong
                .pending_guard
                .as_mut()
                .unwrap()
                .desired
                .expected
                .filters
                .pop()
                .map(|_| ())
                .unwrap(),
        }
        assert!(
            compare_exchange(&c, &wrong, SessionKind::StaticBase, &wrong.guard, &d).is_err(),
            "fault {fault}"
        );
    }
}
// Break: forgetting the original captured priority in later allow installation.
#[test]
fn captured_initial_plan_allows_only_exact_later_dynamic_desired() {
    let (c, mut r, base) = fixture();
    let live = permits(&base);
    let mut plan = policy::ExchangePlan::new(&r.guard, &live).unwrap();
    plan.captured_sublayer_weight = Some(41);
    plan.base = captured(&plan.base);
    plan.desired = live.inherit_sublayer_weight(&plan.base).unwrap();
    plan.validate().unwrap();
    r.guard = plan.base.clone();
    r.pending_guard = Some(plan.clone());
    assert_eq!(
        compare_exchange(&c, &r, SessionKind::DynamicPermits, &r.guard, &plan.desired),
        Ok(ExchangeEdge::Install)
    );
    let mut wrong = plan.desired.clone();
    wrong.assigned_sublayer_weight = Some(42);
    assert!(compare_exchange(&c, &r, SessionKind::DynamicPermits, &r.guard, &wrong).is_err());
}
// Break: adopting a JSON-only captured priority before the original base install ACK.
#[test]
fn captured_priority_cannot_be_adopted_at_the_first_empty_to_base_edge() {
    let (context, mut record, base) = fixture();
    let mut plan = record.pending_guard.clone().unwrap();
    plan.captured_sublayer_weight = Some(41);
    plan.base = captured(&base);
    plan.desired = plan.base.clone();
    plan.validate().unwrap();
    record.pending_guard = Some(plan.clone());
    record.validate().unwrap();
    assert!(compare_exchange(
        &context,
        &record,
        SessionKind::StaticBase,
        &record.guard,
        &plan.base
    )
    .is_err());
}
// Break: allowing a later edge to jump past withdrawal or accepting replayed edges.
#[test]
fn withdrawn_base_and_desired_edges_require_the_current_exact_predecessor() {
    let (c, mut r, b) = fixture();
    let base = captured(&b);
    let live = permits(&base);
    let target = base.clone();
    let plan = policy::ExchangePlan::new(&live, &target).unwrap();
    r.phase = pair::Phase::Running;
    r.active = Some(Slot::A);
    r.operation = Some(pair::Operation::Rebind);
    r.guard = live.clone();
    r.pending_guard = Some(plan.clone());
    assert_eq!(
        compare_exchange(&c, &r, SessionKind::DynamicPermits, &live, &plan.withdrawn),
        Ok(ExchangeEdge::Withdraw)
    );
    assert!(compare_exchange(&c, &r, SessionKind::StaticBase, &live, &target).is_err());
    r.guard = plan.withdrawn.clone();
    assert!(compare_exchange(&c, &r, SessionKind::DynamicPermits, &live, &plan.withdrawn).is_err());
}
// Break: refusing a real static update after permits are withdrawn.
#[test]
fn subsequent_static_base_requires_full_exact_pending_plan() {
    let (c, mut r, b) = fixture();
    let base = captured(&b);
    let live = permits(&base);
    let target = Model::new(
        base.scope.clone(),
        base.carrier.clone().unwrap(),
        base.members.clone(),
        Some(Slot::A),
    )
    .unwrap()
    .without_permits()
    .unwrap()
    .inherit_sublayer_weight(&base)
    .unwrap();
    let plan = policy::ExchangePlan::new(&live, &target).unwrap();
    r.phase = pair::Phase::Running;
    r.active = Some(Slot::A);
    r.operation = Some(pair::Operation::Rebind);
    r.guard = plan.withdrawn.clone();
    r.pending_guard = Some(plan.clone());
    assert_eq!(
        compare_exchange(&c, &r, SessionKind::StaticBase, &r.guard, &plan.base),
        Ok(ExchangeEdge::Base)
    );
}
// Break: admitting allows in Closing or confusing NativeEmpty stage9 with Guard10.
#[test]
fn closing_guard_stages_never_rearm_and_stage9_is_not_guard_permission() {
    let (c, mut r, b) = fixture();
    let base = captured(&b);
    let live = permits(&base);
    let withdrawn = live.without_permits().unwrap();
    r.phase = pair::Phase::Closing;
    r.active = None;
    r.operation = None;
    r.guard = live.clone();
    r.pending_guard = Some(policy::ExchangePlan::new(&live, &withdrawn).unwrap());
    assert_eq!(
        compare_exchange(&c, &r, SessionKind::DynamicPermits, &live, &withdrawn),
        Ok(ExchangeEdge::Withdraw)
    );
    r.stop_stage = 9;
    r.pending = Some(pair::Effect::NativeEmpty);
    assert!(compare_exchange(&c, &r, SessionKind::DynamicPermits, &live, &withdrawn).is_err());
    r.stop_stage = 10;
    r.pending = Some(pair::Effect::Guard);
    r.guard = base.clone();
    r.pending_guard =
        Some(policy::ExchangePlan::new(&base, &Model::empty(r.scope.clone()).unwrap()).unwrap());
    assert_eq!(
        compare_exchange(
            &c,
            &r,
            SessionKind::StaticBase,
            &base,
            &Model::empty(r.scope.clone()).unwrap()
        ),
        Ok(ExchangeEdge::RemoveBase)
    );
    let desired = permits(&base);
    r.pending_guard = Some(policy::ExchangePlan::new(&base, &desired).unwrap());
    assert!(compare_exchange(&c, &r, SessionKind::DynamicPermits, &base, &desired).is_err());
}
// Break: skipping the gate or the second same-transaction full read.
#[test]
fn locked_join_brackets_mandatory_gate_with_two_exact_reads() {
    let (_, _, b) = fixture();
    let events = std::cell::RefCell::new(Vec::new());
    assert_eq!(
        check_locked(
            &b,
            || {
                events.borrow_mut().push("read");
                Ok(b.expected.clone())
            },
            || {
                events.borrow_mut().push("gate");
                Ok(())
            }
        ),
        Ok(())
    );
    assert_eq!(&*events.borrow(), &["read", "gate", "read"]);
}
// Break: treating a failed resource gate or drifted second read as success.
#[test]
fn locked_join_denies_gate_error_and_current_transaction_drift() {
    let (_, _, b) = fixture();
    assert_eq!(
        check_locked(
            &b,
            || Ok(b.expected.clone()),
            || Err(GuardError::RemovalUnconfirmed)
        ),
        Err(GuardError::RemovalUnconfirmed)
    );
    let calls = Cell::new(0);
    assert!(check_locked(
        &b,
        || {
            calls.set(calls.get() + 1);
            let mut s = b.expected.clone();
            if calls.get() == 2 {
                s.filters.pop();
            }
            Ok(s)
        },
        || Ok(())
    )
    .is_err());
}
// Break: clearing sticky taint after callback error, unwind, or swallowed reentry.
#[test]
fn sticky_fence_rejects_error_unwind_and_swallowed_reentry() {
    for fault in 0..3 {
        let fence = AttestorFence::new();
        let result = catch_unwind(AssertUnwindSafe(|| {
            fence.inspect_channel(false, || match fault {
                0 => Err(GuardError::RemovalUnconfirmed),
                1 => panic!("actual read unwind"),
                _ => {
                    assert!(fence.inspect_channel(false, || Ok(())).is_err());
                    Ok(())
                }
            })
        }));
        if fault == 1 {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert!(fence.inspect_channel(false, || Ok(())).is_err());
    }
}
// Break: poisoning valid sequential reads or failing to execute their callback.
#[test]
fn successful_factual_reads_do_not_grant_or_poison_later_valid_reads() {
    let fence = AttestorFence::new();
    assert_eq!(fence.inspect_channel(false, || Ok(7)), Ok(7));
    assert_eq!(fence.inspect_channel(false, || Ok(9)), Ok(9));
}

// Break: reopening forward selection or changing protected bytes at the same revision.
#[test]
fn selection_requires_monotonic_exact_context_and_cannot_leave_closing() {
    let (context, record, _) = fixture();
    assert_eq!(compare_selection(&context, &record, &record), Ok(()));
    let mut next = record.clone();
    next.revision += 1;
    assert_eq!(compare_selection(&context, &record, &next), Ok(()));
    for fault in 0..3 {
        let mut wrong = record.clone();
        match fault {
            0 => wrong.revision -= 1,
            1 => wrong.pending = None,
            _ => wrong.provenance.network_epoch += 1,
        }
        assert!(
            compare_selection(&context, &record, &wrong).is_err(),
            "fault {fault}"
        );
    }
    let mut closing = next.clone();
    closing.revision = 5;
    closing.phase = pair::Phase::Closing;
    closing.active = None;
    closing.operation = None;
    assert_eq!(compare_selection(&context, &next, &closing), Ok(()));
    let mut forward = next.clone();
    forward.revision = closing.revision + 1;
    assert!(compare_selection(&context, &closing, &forward).is_err());
}
// Break: treating a live Closing window as an original retired/full-EMPTY capability.
#[test]
fn source_live_closing_and_retired_channels_are_distinct_and_terminal_denied() {
    let (_, mut record, _) = fixture();
    assert_eq!(window_channel(&record), Ok(WindowChannel::Source));
    record.phase = pair::Phase::Closing;
    for stage in [0, 3, 6, 8] {
        record.stop_stage = stage;
        assert_eq!(window_channel(&record), Ok(WindowChannel::Closing));
    }
    for stage in [9, 10] {
        record.stop_stage = stage;
        assert_eq!(window_channel(&record), Ok(WindowChannel::Retired));
    }
    for stage in [11, 12] {
        record.stop_stage = stage;
        assert_eq!(window_channel(&record), Err(GuardError::RemovalUnconfirmed));
    }
}
// Break: allowing cancelled forward calls or preventing separately authorized cleanup.
#[test]
fn cancellation_rejects_forward_without_turning_closing_into_forward_permission() {
    let (_, mut record, _) = fixture();
    assert_eq!(cancellation(&record, false), Ok(()));
    assert_eq!(cancellation(&record, true), Err(GuardError::Conflict));
    record.phase = pair::Phase::Closing;
    assert_eq!(cancellation(&record, true), Ok(()));
}
// Break: accepting valid-shaped foreign planned identity or probe policy as ownership.
#[test]
fn independently_valid_foreign_plan_and_wrong_probe_target_are_denied() {
    let (context, mut record, base) = fixture();
    for fault in 0..2 {
        let mut members = base.members.clone();
        if fault == 0 {
            members[0].as_mut().unwrap().identity.proof.guid = [9; 16];
        } else {
            members[0].as_mut().unwrap().probes = vec![policy::ProbeTuple {
                source: "10.7.0.2".parse().unwrap(),
                source_port: 40123,
                target: "1.1.1.2".parse().unwrap(),
                target_port: 53,
                protocol: 17,
            }];
        }
        let wrong = Model::new(
            record.scope.clone(),
            base.carrier.clone().unwrap(),
            members,
            None,
        )
        .unwrap()
        .without_permits()
        .unwrap();
        record.pending_guard = Some(policy::ExchangePlan::new(&record.guard, &wrong).unwrap());
        record.validate().unwrap();
        assert!(compare_exchange(
            &context,
            &record,
            SessionKind::StaticBase,
            &record.guard,
            &wrong
        )
        .is_err());
    }
}
// Break: calling G despite a failed first locked read or clearing taint on locked drift.
#[test]
fn locked_error_or_drift_poison_fence_and_first_read_failure_never_calls_gate() {
    let (_, _, base) = fixture();
    let fence = AttestorFence::new();
    let gate_called = Cell::new(false);
    assert!(fence
        .inspect_channel(false, || check_locked(
            &base,
            || Err(GuardError::Conflict),
            || {
                gate_called.set(true);
                Ok(())
            }
        ))
        .is_err());
    assert!(!gate_called.get());
    assert!(fence.inspect_channel(false, || Ok(())).is_err());
}

// Break: keeping G inside a joined snapshot, so actual resource APIs cannot
// perform their own sibling joins under the SAME original outer window.
#[test]
fn resource_gate_can_join_between_two_separate_locked_snapshot_joins() {
    let (_, _, base) = fixture();
    let joined = AttestorFence::new();
    let events = std::cell::RefCell::new(Vec::new());
    assert_eq!(
        check_window_locked(
            &base,
            |callback| joined.inspect_channel(false, || {
                events.borrow_mut().push("snapshot-join");
                callback(&base.expected)
            }),
            |snapshot| {
                events.borrow_mut().push("locked-read");
                Ok(snapshot.clone())
            },
            || {
                // These are production serialization/failure guards, not fake
                // opaque native Source/G capabilities. The actual native adapter
                // supplies NativeBindingsWindow.inspect to this SAME helper.
                joined.inspect_channel(false, || {
                    events.borrow_mut().push("held-probe-join");
                    Ok(())
                })?;
                joined.inspect_channel(false, || {
                    events.borrow_mut().push("network-join");
                    Ok(())
                })
            }
        ),
        Ok(())
    );
    assert_eq!(
        &*events.borrow(),
        &[
            "snapshot-join",
            "locked-read",
            "held-probe-join",
            "network-join",
            "snapshot-join",
            "locked-read"
        ]
    );
}

fn retired_fixture(stage: u8) -> (Context, pair::Record, Model) {
    let (context, mut record, base) = fixture();
    let base = captured(&base);
    record.phase = pair::Phase::Closing;
    record.operation = None;
    record.active = None;
    record.stop_stage = stage;
    record.guard = base.clone();
    record.pending = Some(if stage == 9 {
        pair::Effect::NativeEmpty
    } else {
        pair::Effect::Guard
    });
    record.pending_guard = if stage == 10 {
        Some(
            policy::ExchangePlan::new(&base, &Model::empty(record.scope.clone()).unwrap()).unwrap(),
        )
    } else {
        None
    };
    record.validate().unwrap();
    (context, record, base)
}
// Break: treating stage9 NativeEmpty as mutation permission or refusing exact stage10 removal.
#[test]
fn retired_stage9_is_factual_only_and_exact_stage10_has_a_distinct_removal_gate() {
    let (context, record, base) = retired_fixture(9);
    assert_eq!(compare_retired_read(&context, &record), Ok(()));
    assert!(compare_retired_removal(
        &context,
        &record,
        SessionKind::StaticBase,
        &base,
        &Model::empty(record.scope.clone()).unwrap()
    )
    .is_err());
    let (context, record, base) = retired_fixture(10);
    assert_eq!(window_channel(&record), Ok(WindowChannel::Retired));
    assert_eq!(compare_retired_read(&context, &record), Ok(()));
    assert_eq!(
        compare_retired_removal(
            &context,
            &record,
            SessionKind::StaticBase,
            &base,
            &Model::empty(record.scope.clone()).unwrap()
        ),
        Ok(ExchangeEdge::RemoveBase)
    );
    let mut unplanned_read = record.clone();
    unplanned_read.pending_guard = None;
    compare_retired_read(&context, &unplanned_read).unwrap();
    assert!(compare_retired_removal(
        &context,
        &unplanned_read,
        SessionKind::StaticBase,
        &base,
        &Model::empty(record.scope.clone()).unwrap(),
    )
    .is_err());
    for (stage, effect) in [
        (11, pair::Effect::RestoreKeys),
        (12, pair::Effect::FullEmpty),
    ] {
        let mut final_read = record.clone();
        final_read.stop_stage = stage;
        final_read.pending = Some(effect);
        final_read.pending_guard = None;
        final_read.guard = Model::empty(final_read.scope.clone()).unwrap();
        compare_retired_read(&context, &final_read).unwrap();
        assert!(compare_retired_removal(
            &context,
            &final_read,
            SessionKind::StaticBase,
            &base,
            &final_read.guard,
        )
        .is_err());
        for fault in 0..5 {
            let mut wrong = final_read.clone();
            match fault {
                0 => wrong.pending = None,
                1 => wrong.pending = Some(pair::Effect::NativeEmpty),
                2 => wrong.guard = base.clone(),
                3 => wrong.pending_guard = record.pending_guard.clone(),
                _ => wrong.operation = Some(pair::Operation::Retire(Slot::B)),
            }
            assert!(compare_retired_read(&context, &wrong).is_err());
        }
    }
}
#[test]
fn after_close_stage8_can_read_registered_retired_facts_but_not_remove_bases() {
    let (context, mut current, base) = retired_fixture(9);
    current.stop_stage = 8;
    current.pending = Some(pair::Effect::CarrierClose);
    compare_retired_read(&context, &current).unwrap();
    let empty = Model::empty(current.scope.clone()).unwrap();
    assert!(
        compare_retired_removal(&context, &current, SessionKind::StaticBase, &base, &empty)
            .is_err()
    );
    for fault in 0..5 {
        let mut wrong = current.clone();
        match fault {
            0 => wrong.stop_stage = 7,
            1 => wrong.pending = Some(pair::Effect::NativeEmpty),
            2 => wrong.active = Some(Slot::A),
            3 => wrong.operation = Some(pair::Operation::Retire(Slot::B)),
            _ => wrong.provenance.network_epoch += 1,
        }
        assert!(
            compare_retired_read(&context, &wrong).is_err(),
            "fault {fault}"
        );
    }
}
// Break: historical JSON allows, a foreign full proof, or wrong phase/stage become deletion permission.
#[test]
fn retired_removal_refuses_wrong_phase_effect_kind_permits_and_foreign_history() {
    let (context, record, base) = retired_fixture(10);
    let empty = Model::empty(record.scope.clone()).unwrap();
    for fault in 0..7 {
        let mut wrong = record.clone();
        match fault {
            0 => wrong.phase = pair::Phase::Starting,
            1 => wrong.stop_stage = 8,
            2 => wrong.pending = Some(pair::Effect::NativeEmpty),
            3 => wrong.pending_guard = None,
            4 => wrong.guard = permits(&base),
            5 => wrong.carrier.as_mut().unwrap().luid += 1,
            _ => wrong.provenance.boot_id = [9; 16],
        }
        assert!(
            compare_retired_removal(&context, &wrong, SessionKind::StaticBase, &base, &empty)
                .is_err(),
            "fault {fault}"
        );
    }
    assert!(compare_retired_removal(
        &context,
        &record,
        SessionKind::DynamicPermits,
        &base,
        &empty
    )
    .is_err());
}
// Break: accepting lost delete ACK as a new expected state without the current protected plan checkpoint.
#[test]
fn retired_lost_ack_readback_does_not_adopt_a_new_current_transaction_policy() {
    let (context, record, base) = retired_fixture(10);
    let empty = Model::empty(record.scope.clone()).unwrap();
    assert_eq!(compare_retired_read(&context, &record), Ok(()));
    let gate = Cell::new(false);
    assert!(check_locked(
        &base,
        || Ok(empty.expected.clone()),
        || {
            gate.set(true);
            Ok(())
        }
    )
    .is_err());
    assert!(!gate.get());
    assert!(
        compare_retired_removal(&context, &record, SessionKind::StaticBase, &empty, &empty)
            .is_err()
    );
    let mut acknowledged = record;
    acknowledged.guard = empty;
    assert_eq!(compare_retired_read(&context, &acknowledged), Ok(()));
}
// Break: dropping the first registered opaque reader on failed origin/phase checks.
#[test]
fn registration_retains_first_original_before_error_and_denies_equal_replacement() {
    struct Tracked<'a>(&'a Cell<u32>);
    impl Drop for Tracked<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let drops = Cell::new(0);
    let registration = Registration::new(None);
    let fence = AttestorFence::new();
    assert!(
        register_original_channel(&registration, &fence, Tracked(&drops), false, |_| Err(
            GuardError::Conflict
        ))
        .is_err()
    );
    assert!(registration.value.borrow().is_some());
    assert_eq!(drops.get(), 0);
    assert!(fence.inspect_channel(false, || Ok(())).is_err());
    let original = std::rc::Rc::new(7);
    let valid = Registration::new(None);
    let other = AttestorFence::new();
    assert_eq!(
        register_original_channel(&valid, &other, original.clone(), false, |_| Ok(())),
        Ok(())
    );
    assert!(
        register_original_channel(&valid, &other, original.clone(), false, |_| Ok(())).is_err()
    );
    assert!(std::rc::Rc::ptr_eq(
        valid.value.borrow().as_ref().unwrap(),
        &original
    ));
}
// Break: weakening same-origin pointer checks or permitting a caught one-time registration reentry.
#[test]
fn registration_wrong_origin_and_swallowed_reentry_never_replace_or_rearm() {
    let original = std::rc::Rc::new(7);
    let equal_foreign = std::rc::Rc::new(7);
    let slot = Registration::new(None);
    let fence = AttestorFence::new();
    assert!(
        register_original_channel(&slot, &fence, equal_foreign.clone(), false, |actual| {
            if std::rc::Rc::ptr_eq(actual, &original) {
                Ok(())
            } else {
                Err(GuardError::Conflict)
            }
        })
        .is_err()
    );
    assert!(std::rc::Rc::ptr_eq(
        slot.value.borrow().as_ref().unwrap(),
        &equal_foreign
    ));
    let slot = Registration::new(None);
    let fence = AttestorFence::new();
    assert!(
        register_original_channel(&slot, &fence, original.clone(), false, |_| {
            assert!(
                register_original_channel(&slot, &fence, original.clone(), false, |_| Ok(()))
                    .is_err()
            );
            Ok(())
        })
        .is_err()
    );
    assert!(fence.inspect_channel(false, || Ok(())).is_err());
}

// Break: losing the first retained original on callback unwind.
#[test]
fn registration_unwind_retains_original_and_taints_all_later_calls() {
    struct Tracked<'a>(&'a Cell<u32>);
    impl Drop for Tracked<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let drops = Cell::new(0);
    let slot = Registration::new(None);
    let fence = AttestorFence::new();
    assert!(catch_unwind(AssertUnwindSafe(|| {
        register_original_channel(&slot, &fence, Tracked(&drops), false, |_| {
            panic!("registration unwind")
        })
    }))
    .is_err());
    assert!(slot.value.borrow().is_some());
    assert_eq!(drops.get(), 0);
    assert!(fence.inspect_channel(false, || Ok(())).is_err());
    drop(slot);
    assert_eq!(drops.get(), 1);
}
// Break: adopting numeric historical proof, missing A history, or fabricated SDK presence.
#[test]
fn retired_bindings_require_whole_original_history_not_foreign_equal_shaped_facts() {
    let (context, record, base) = retired_fixture(10);
    assert_eq!(compare_bindings(&context, &record, &facts(&base)), Ok(()));
    let mut carrier = base.carrier.clone().unwrap();
    carrier.identity.proof.luid += 1;
    let mut actual = facts(&base);
    actual.carrier = Some(&carrier);
    assert!(compare_bindings(&context, &record, &actual).is_err());
    actual.carrier = base.carrier.as_ref();
    actual.egress[0] = None;
    assert!(compare_bindings(&context, &record, &actual).is_err());
    actual.egress = [base.members[0].as_ref().map(|m| &m.identity); 2];
    assert!(compare_bindings(&context, &record, &actual).is_err());
}
// A normal retired standby remains rooted for cleanup, but is no longer a live
// Pair member. ONLY original closed-receipt facts may explain that extra identity.
#[test]
fn original_closed_history_explains_removed_member_without_live_adoption() {
    let (context, mut record, base) = fixture();
    let owner = &record.members[0].as_ref().unwrap().owner;
    let closed = original_members::ClosedMemberBinding {
        intent: owner.intent.clone(),
        proof: owner.proof.unwrap(),
    };
    record.members[0] = None;
    record.operation = None;
    record.pending = None;
    record.pending_guard = None;
    record.validate().unwrap();
    assert!(compare_bindings(&context, &record, &facts(&base)).is_err());
    assert_eq!(
        compare_bindings_with_history(&context, &record, &facts(&base), [Some(&closed), None]),
        Ok(())
    );
    assert!(compare_bindings_with_history(&context, &record, &facts(&base), [None, None]).is_err());
    for fault in 0..6 {
        let mut wrong = closed.clone();
        match fault {
            0 => wrong.intent.slot = TunnelSlot::B,
            1 => wrong.intent.scope.connection_generation += 1,
            2 => wrong.proof.interface.guid = [8; 16],
            3 => wrong.proof.interface.luid += 1,
            4 => wrong.proof.interface.index += 1,
            _ => wrong.proof.process.pid = 0,
        }
        assert!(
            compare_bindings_with_history(&context, &record, &facts(&base), [Some(&wrong), None])
                .is_err(),
            "fault {fault}"
        );
    }
    let mut missing = facts(&base);
    missing.egress[0] = None;
    assert!(
        compare_bindings_with_history(&context, &record, &missing, [Some(&closed), None]).is_err()
    );
}
// Break: a swallowed malformed snapshot join or second read failure grants G/success.
#[test]
fn split_join_requires_one_successful_callback_per_snapshot_and_second_read() {
    let (_, _, base) = fixture();
    for fault in 0..3 {
        let joins = Cell::new(0);
        let gate_calls = Cell::new(0);
        assert!(check_window_locked(
            &base,
            |callback| {
                joins.set(joins.get() + 1);
                if fault == 0 {
                    return Ok(());
                }
                callback(&base.expected)?;
                if fault == 1 {
                    assert!(callback(&base.expected).is_err());
                }
                Ok(())
            },
            |snapshot| {
                if fault == 2 && joins.get() == 2 {
                    Err(GuardError::Conflict)
                } else {
                    Ok(snapshot.clone())
                }
            },
            || {
                gate_calls.set(gate_calls.get() + 1);
                Ok(())
            }
        )
        .is_err());
        assert_eq!(gate_calls.get(), u32::from(fault == 2));
    }
}
