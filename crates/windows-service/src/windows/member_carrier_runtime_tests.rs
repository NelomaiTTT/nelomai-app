use super::*;

#[test]
fn member_capture_binding_requires_whole_original_context_and_started_interface() {
    use crate::member_carrier_rows as r;
    let context = record().context;
    let mut identity = original_identity();
    identity.guid = context.bindings[1].guid;
    identity.name = context.bindings[1].name.clone();
    let binding = member_rows_binding(&context, r::Role::MemberA, &identity).unwrap();
    let proof = crate::member_owner::InterfaceProof {
        guid: identity.guid,
        luid: identity.luid,
        index: identity.index,
    };
    compare_member_capture_binding(&context, &binding, r::Role::MemberA, proof).unwrap();
    for fault in 0..10 {
        let mut other = binding.clone();
        match fault {
            0 => other.scope.connection_generation += 1,
            1 => other.boot_id[0] ^= 1,
            2 => other.runtime.manifest_sha256 = "b".repeat(64),
            3 => other.network_epoch += 1,
            4 => other.address[3] += 1,
            5 => other.role = r::Role::MemberB,
            6 => other.guid[0] ^= 1,
            7 => other.name.push('x'),
            8 => other.key.index += 1,
            _ => other.key.luid += 1,
        }
        assert!(
            compare_member_capture_binding(&context, &other, r::Role::MemberA, proof).is_err(),
            "fault {fault}"
        );
    }
}

#[test]
fn generation_write_selection_is_one_attempt_and_exact_bytes_only() {
    let selection = GenerationWriteSelection::new();
    assert!(selection.verify(b"capture").is_err());
    selection.begin(b"capture").unwrap();
    selection.verify(b"capture").unwrap();
    assert!(selection.verify(b"equal-looking replacement").is_err());
    assert!(selection.begin(b"capture").is_err());
    assert!(selection.verify(b"capture").is_err());
    let failed = GenerationWriteSelection::new();
    failed.begin(b"unconfirmed").unwrap();
    failed.revoke();
    assert!(failed.begin(b"unconfirmed").is_err());
    assert!(failed.verify(b"unconfirmed").is_err());
}

#[test]
fn generation_storage_selection_requires_actual_unrevoked_initial_bytes() {
    let selection = GenerationWriteSelection::new();
    assert!(selection.with_retained(|_| Ok(())).is_err());
    selection.begin(b"original captured baseline").unwrap();
    assert_eq!(
        selection.with_retained(|bytes| Ok(bytes.to_vec())).unwrap(),
        b"original captured baseline"
    );
    selection.revoke();
    let visited = Cell::new(false);
    assert!(selection
        .with_retained(|_| {
            visited.set(true);
            Ok(())
        })
        .is_err());
    assert!(!visited.get());
    let nested = GenerationWriteSelection::new();
    nested.begin(b"original").unwrap();
    assert!(nested
        .with_retained(|_| {
            nested.revoke();
            Ok(())
        })
        .is_err());
}

#[test]
fn generation_historical_bytes_survive_forward_revocation_without_rearming_write() {
    let selection = GenerationWriteSelection::new();
    assert!(selection.with_historical_bytes(|_| Ok(())).is_err());
    selection.begin(b"original captured baseline").unwrap();
    selection.revoke();
    assert_eq!(
        selection
            .with_historical_bytes(|bytes| Ok(bytes.to_vec()))
            .unwrap(),
        b"original captured baseline"
    );
    assert!(selection.verify(b"original captured baseline").is_err());
    assert!(selection.begin(b"original captured baseline").is_err());
    assert!(selection.with_retained(|_| Ok(())).is_err());
}

#[test]
fn completed_capture_storage_comparison_preserves_initial_baseline_through_cleanup() {
    use crate::member_carrier_rows as r;
    let mut captured = pending_rows();
    captured.binding.role = r::Role::MemberA;
    captured.binding.guid = record().context.bindings[1].guid;
    captured.binding.name = record().context.bindings[1].name.clone();
    captured.phase = r::Phase::Captured;
    captured.revision = 1;
    captured.pending = None;
    captured.creation = None;
    captured.current = captured.baseline.clone();
    captured.validate().unwrap();
    let mut current = captured.clone();
    current.revision += 1;
    current.phase = r::Phase::Closing;
    compare_completed_capture_storage(&captured.binding, &captured, &current).unwrap();
    current.phase = r::Phase::Stopped;
    compare_completed_capture_storage(&captured.binding, &captured, &current).unwrap();
    for fault in 0..7 {
        let mut baseline = captured.clone();
        let mut acknowledged = current.clone();
        match fault {
            0 => baseline.phase = r::Phase::Closing,
            1 => baseline.revision += 1,
            2 => baseline.current.interface.policy.metric += 1,
            3 => baseline.binding.key.index += 1,
            4 => acknowledged.binding.name.push('x'),
            5 => acknowledged.baseline.interface.policy.metric += 1,
            _ => baseline.binding.role = r::Role::Carrier,
        }
        assert!(
            compare_completed_capture_storage(&captured.binding, &baseline, &acknowledged).is_err(),
            "fault {fault}"
        );
    }
}

#[test]
fn generation_projection_revokes_on_error_unwind_or_swallowed_reentry() {
    for fault in 0..4 {
        let revoked = Cell::new(false);
        let busy = Cell::new(false);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
            let mut operation = GenerationProjection::begin(&revoked, &busy)?;
            assert!(busy.get());
            match fault {
                1 => return Err(CarrierError::Conflict),
                2 => panic!("generation postflight"),
                3 => assert!(GenerationProjection::begin(&revoked, &busy).is_err()),
                _ => {}
            }
            operation.complete()
        }));
        assert!(!busy.get());
        if fault == 0 {
            assert!(result.unwrap().is_ok());
            assert!(!revoked.get());
        } else {
            assert!(result.is_err() || result.unwrap().is_err());
            assert!(revoked.get());
            assert!(GenerationProjection::begin(&revoked, &busy).is_err());
        }
    }
}

#[test]
fn generation_storage_comparison_cannot_reuse_old_owner_or_change_member_scope() {
    use crate::member_carrier_rows as r;
    let context = record().context;
    let mut identity = original_identity();
    identity.guid = context.bindings[1].guid;
    identity.name = context.bindings[1].name.clone();
    identity.index += 1;
    identity.luid += 1;
    let binding = member_rows_binding(&context, r::Role::MemberA, &identity).unwrap();
    let mut old = pending_rows();
    old.binding = binding.clone();
    old.baseline.interface.key = binding.key;
    old.current = old.baseline.clone();
    old.phase = r::Phase::Stopped;
    old.pending = None;
    old.creation = None;
    old.validate().unwrap();
    let mut next = old.clone();
    next.phase = r::Phase::Captured;
    next.revision = 1;
    next.binding.key.index += 1;
    next.binding.key.luid += 1;
    next.current.interface.key = next.binding.key;
    next.baseline = next.current.clone();
    next.validate().unwrap();
    assert!(compare_member_generation_storage(&context, &old, &next, &next.binding).is_ok());
    assert!(
        r::validate_transition(Some(&old), &next, false).is_err(),
        "normal store stays closed"
    );
    for fault in 0..15 {
        let mut before = old.clone();
        let mut after = next.clone();
        let mut expected = next.binding.clone();
        match fault {
            0 => before.phase = r::Phase::Captured,
            1 => after.phase = r::Phase::Stopped,
            2 => after.revision = 2,
            3 => after.binding.scope.connection_generation += 1,
            4 => after.binding.network_epoch += 1,
            5 => after.binding.boot_id[0] ^= 1,
            6 => after.binding.runtime.manifest_sha256 = "b".repeat(64),
            7 => after.binding.role = r::Role::Carrier,
            8 => after.binding.address[3] += 1,
            9 => after.binding.guid[0] ^= 1,
            10 => after.binding.name.push('x'),
            11 => after.current.interface.policy.metric += 1,
            12 => after.baseline.interface.policy.weak_host_send = true,
            13 => after.binding.key.luid += 1,
            _ => {
                // Equal old/new logical addresses do not authorize a VIP
                // that differs from the original session's intent.
                before.binding.address[3] += 1;
                after.binding.address = before.binding.address;
                expected.address = before.binding.address;
            }
        }
        assert!(
            compare_member_generation_storage(&context, &before, &after, &expected).is_err(),
            "fault {fault}"
        );
    }
}

#[test]
fn bracket_facts_require_actual_outer_read_and_expire_on_error_or_unwind() {
    let pin = BracketFacts::new();
    assert!(pin.snapshot().is_err());
    assert_eq!(pin.within(vec![7], || pin.snapshot()), Ok(vec![7]));
    assert!(pin.snapshot().is_err());
    assert!(pin
        .within(vec![8], || {
            assert_eq!(pin.snapshot(), Ok(vec![8]));
            Err::<(), _>(CarrierError::Conflict)
        })
        .is_err());
    assert!(pin.snapshot().is_err());
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| pin
        .within(vec![9], || -> Result<()> {
            panic!("native bracket postflight")
        })))
    .is_err());
    assert!(pin.snapshot().is_err());
    assert!(pin
        .within(vec![10], || {
            assert!(pin.within(vec![11], || Ok(())).is_err());
            Ok(())
        })
        .is_err());
    assert!(pin.snapshot().is_err());
}

#[test]
fn actual_closed_member_rows_remain_closed_during_forward_carrier_retirement() {
    assert_eq!(
        resource_row_channel(false, true),
        ResourceRowChannel::Closed
    );
    assert_eq!(resource_row_channel(true, true), ResourceRowChannel::Closed);
    assert_eq!(
        resource_row_channel(false, false),
        ResourceRowChannel::Source
    );
    assert_eq!(
        resource_row_channel(true, false),
        ResourceRowChannel::Closing
    );
}
#[test]
fn joined_sample_caught_reentry_cannot_invoke_even_read_only_callback() {
    for cleanup in [false, true] {
        let fence = SourceFence::new(Rc::new(Cell::new(false)));
        let read_called = Cell::new(false);
        let outer_read = |expected: &u8| {
            assert!(fence
                .joined_read(
                    cleanup,
                    expected,
                    || {
                        assert!(fence
                            .joined_read(cleanup, expected, || Ok(7), || Ok::<_, ()>(()), || ())
                            .is_err());
                        Ok(7)
                    },
                    || {
                        read_called.set(true);
                        Ok(())
                    },
                    || (),
                )
                .is_err());
            Ok(())
        };
        let result = if cleanup {
            fence.inspect_cleanup(|| Ok(7), outer_read, || ())
        } else {
            fence.inspect(|| Ok(7), outer_read, || ())
        };
        assert!(result.is_err());
        assert!(!read_called.get());
        assert!(fence.revoked.get());
    }
}
#[test]
fn original_read_window_joins_actual_outer_sample_without_reentrant_owner_entry() {
    let fence = SourceFence::new(Rc::new(Cell::new(false)));
    let count = Cell::new(0);
    fence
        .inspect(
            || Ok::<_, ()>(7),
            |expected| {
                fence.joined_read(
                    false,
                    expected,
                    || Ok(7),
                    || {
                        count.set(1);
                        Ok(())
                    },
                    || (),
                )
            },
            || (),
        )
        .unwrap();
    assert_eq!(count.get(), 1);
    assert!(!fence.revoked.get());
}
#[test]
fn joined_read_refuses_outside_lease_wrong_lifecycle_drift_error_and_swallowed_reentry() {
    for cleanup in [false, true] {
        for fault in 0..6 {
            let fence = SourceFence::new(Rc::new(Cell::new(false)));
            let sample = Cell::new(7);
            let calls = Cell::new(0);
            let read = |expected: &u8| {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    fence.joined_read(
                        if fault == 0 { !cleanup } else { cleanup },
                        expected,
                        || {
                            calls.set(calls.get() + 1);
                            if fault == 1 {
                                Err(())
                            } else {
                                Ok(sample.get())
                            }
                        },
                        || {
                            match fault {
                                2 => {
                                    sample.set(8);
                                }
                                3 => {
                                    return Err(());
                                }
                                4 => {
                                    assert!(fence
                                        .joined_read(cleanup, expected, || Ok(7), || Ok(()), || ())
                                        .is_err());
                                }
                                5 => {
                                    panic!("joined callback unwind");
                                }
                                _ => {}
                            }
                            Ok(())
                        },
                        || (),
                    )
                }));
                if fault == 5 {
                    assert!(result.is_err());
                } else {
                    assert!(result.unwrap().is_err());
                }
                assert!(fence.busy.get());
                Ok(()) // Ignored inner error cannot make outer callback succeed.
            };
            let outer = if cleanup {
                fence.inspect_cleanup(|| Ok(7), read, || ())
            } else {
                fence.inspect(|| Ok(7), read, || ())
            };
            assert!(outer.is_err(), "{cleanup}/{fault}");
            assert!(fence.revoked.get());
            assert!(!fence.busy.get());
            assert!(!fence.joined_busy.get());
            fence
                .inspect_cleanup(
                    || Ok::<_, ()>(7),
                    |expected| fence.joined_read(true, expected, || Ok(7), || Ok(()), || ()),
                    || (),
                )
                .unwrap();
            assert!(fence.inspect(|| Ok::<_, ()>(7), |_| Ok(()), || ()).is_err());
        }
    }
    let fence = SourceFence::new(Rc::new(Cell::new(false)));
    assert!(fence
        .joined_read(false, &7, || Ok(7), || Ok::<_, ()>(()), || ())
        .is_err());
    assert!(fence.revoked.get());
}
use crate::member_carrier::{Intent, Provenance};
#[cfg(not(windows))]
use crate::member_carrier_creators as creators;
use crate::member_carrier_native_ownership::{
    Binding, Context, FullNativeRows, KeyPhase, KeyReceipt, Phase, Record, Role, Value,
};
#[cfg(windows)]
use crate::windows::member_carrier_creators as creators;
use nelomai_client_tunnel::redundancy::SessionScope;
use nelomai_contracts::{dispatcher::EngineIdentity, RuntimeSlot};

#[test]
fn source_callback_fence_retains_the_same_failure_signal_and_brackets_all_facts() {
    let revoked = Rc::new(Cell::new(false));
    let fence = SourceFence::new(revoked.clone());
    let calls = Cell::new(0);
    let result = fence.inspect(
        || {
            calls.set(calls.get() + 1);
            Ok::<_, CarrierError>((17, [1, 2]))
        },
        |facts| Ok(facts.0 + 1),
        || CarrierError::Conflict,
    );
    assert_eq!(result, Ok(18));
    assert_eq!(calls.get(), 2);
    assert!(!revoked.get());
    assert!(!fence.busy.get());
    for fault in 0..4 {
        let revoked = Rc::new(Cell::new(false));
        let fence = SourceFence::new(revoked.clone());
        let calls = Cell::new(0);
        let result = fence.inspect(
            || {
                calls.set(calls.get() + 1);
                if (fault == 0 && calls.get() == 1) || (fault == 2 && calls.get() == 2) {
                    Err(CarrierError::Journal)
                } else {
                    Ok((1, [1, if fault == 3 { calls.get() } else { 1 }]))
                }
            },
            |_| {
                if fault == 1 {
                    Err(CarrierError::Native)
                } else {
                    Ok(())
                }
            },
            || CarrierError::Conflict,
        );
        assert!(result.is_err(), "fault {fault}");
        assert!(revoked.get());
        assert!(!fence.busy.get());
        let no_read = fence.inspect(
            || panic!("a revoked source must not sample or invoke the callback"),
            |_: &u8| Ok::<_, CarrierError>(()),
            || CarrierError::Conflict,
        );
        assert_eq!(no_read, Err(CarrierError::Conflict));
    }
}

#[test]
fn source_callback_cannot_ignore_reentry_revocation_or_unwind() {
    for fault in 0..3 {
        let revoked = Rc::new(Cell::new(false));
        let fence = SourceFence::new(revoked.clone());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            fence.inspect(
                || Ok::<_, CarrierError>(7),
                |_| {
                    match fault {
                        0 => {
                            assert!(fence
                                .inspect(|| Ok(7), |_| Ok(()), || CarrierError::Conflict)
                                .is_err());
                            assert!(
                                fence.busy.get(),
                                "nested refusal must retain the outer operation"
                            );
                        }
                        1 => revoked.set(true),
                        _ => panic!("source inspection callback unwound"),
                    }
                    Ok(())
                },
                || CarrierError::Conflict,
            )
        }));
        if fault == 2 {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), Err(CarrierError::Conflict));
        }
        assert!(revoked.get());
        assert!(!fence.busy.get());
    }
}

#[test]
fn source_closing_facts_never_rearm_forward_and_cannot_ignore_reentrant_cleanup() {
    let revoked = Rc::new(Cell::new(false));
    let fence = SourceFence::new(revoked.clone());
    assert_eq!(
        fence.inspect_cleanup(
            || Ok::<_, CarrierError>(5),
            |v| Ok(*v),
            || CarrierError::Conflict
        ),
        Ok(5)
    );
    assert!(revoked.get());
    assert_eq!(
        fence.inspect(|| Ok(5), |_| Ok(()), || CarrierError::Conflict),
        Err(CarrierError::Conflict)
    );
    let nested = fence.inspect_cleanup(
        || Ok(5),
        |_| {
            assert!(fence
                .inspect_cleanup(|| Ok(5), |_| Ok(()), || CarrierError::Conflict)
                .is_err());
            Ok(())
        },
        || CarrierError::Conflict,
    );
    assert_eq!(nested, Err(CarrierError::Conflict));
    assert!(!fence.busy.get());
    // Factual retry is allowed only through the cleanup path. The actual native
    // reader separately requires Closing and SAME retained originals each time.
    assert_eq!(
        fence.inspect_cleanup(|| Ok(5), |v| Ok(*v), || CarrierError::Conflict),
        Ok(5)
    );
    assert!(revoked.get());
}

#[test]
fn shared_original_is_the_same_retained_owner_not_equal_reconstructed_data() {
    let original = SharedOriginal::new(vec![1_u8]);
    let second = original.pin();
    second.borrow().unwrap().push(2);
    assert_eq!(*original.borrow().unwrap(), vec![1, 2]);
    drop(original);
    assert_eq!(*second.borrow().unwrap(), vec![1, 2]);
    assert!(!second.revoked.get());
}

#[test]
fn cleanup_write_root_is_registered_original_without_reborrowing_effect_owner() {
    let original = SharedOriginal::new(vec![1_u8]);
    let root = CleanupWriteRoot::new(&original);
    assert!(root.verify().is_err());
    root.admit().unwrap();
    // Raw callbacks run while the actual original owner is already borrowed.
    let held = original.borrow().unwrap();
    root.verify().unwrap();
    drop(held);
    drop(original);
    // Equal data elsewhere never revives the dead original owner.
    let _equal = SharedOriginal::new(vec![1_u8]);
    assert!(root.verify().is_err());
}

#[test]
fn cleanup_write_root_failure_is_permanent_and_revokes_shared_forward_only() {
    let original = SharedOriginal::new(vec![1_u8]);
    let root = CleanupWriteRoot::new(&original);
    root.admit().unwrap();
    root.fail();
    assert!(original.revoked.get());
    assert!(root.verify().is_err());
    assert!(root.admit().is_err());
    // Retained obligations are still the same owner; no implicit cleanup.
    assert_eq!(*original.borrow().unwrap(), vec![1]);
}

#[test]
fn caught_reentrant_borrow_irreversibly_revokes_both_actual_components() {
    let original = SharedOriginal::new(7_u8);
    let second = original.pin();
    let held = original.borrow().unwrap();
    assert!(second.borrow().is_err());
    assert!(original.revoked.get());
    drop(held);
    // Factual retained borrow is still possible for cleanup, but neither pin
    // may reset forward revocation or replace the SAME original object.
    assert_eq!(*second.borrow().unwrap(), 7);
    assert!(second.revoked.get());
}

fn original_identity() -> creators::Identity {
    creators::Identity {
        guid: [1; 16],
        luid: 77,
        index: 7,
        name: "carrier-c".into(),
        description: "Nelomai carrier Tunnel".into(),
        if_type: 53,
        tunnel_type: 0,
    }
}

fn retired_member(index: usize) -> carrier_provider::ExpectedProvider {
    let c = record().context;
    carrier_provider::ExpectedProvider {
        identity: carrier_provider::Expected {
            guid: c.bindings[index].guid,
            luid: 77 + index as u64,
            index: 7 + index as u32,
            name: c.bindings[index].name.clone(),
            description: "actual captured member Tunnel".into(),
            if_type: 53,
            tunnel_type: 0,
        },
        kind: if index == 1 {
            carrier_provider::ProviderKind::WireGuardNt
        } else {
            carrier_provider::ProviderKind::Wintun
        },
    }
}

#[test]
fn closed_bindings_projection_is_data_only_for_exact_c_and_captured_member_roles() {
    let context = record().context;
    let members = [retired_member(2), retired_member(1)];
    let bindings = comparison_bindings(&context, &original_identity(), &members).unwrap();
    assert_eq!(bindings.scope, context.intent.scope);
    assert_eq!(bindings.carrier.as_ref().unwrap().identity.proof.index, 7);
    assert_eq!(
        bindings.carrier.as_ref().unwrap().sources,
        vec![context.intent.addresses[0].addr()]
    );
    assert_eq!(bindings.egress[0].as_ref().unwrap().proof.index, 8);
    assert_eq!(bindings.egress[1].as_ref().unwrap().proof.index, 9);
    let b_only = comparison_bindings(&context, &original_identity(), &members[..1]).unwrap();
    assert!(b_only.egress[0].is_none());
    assert_eq!(b_only.egress[1], bindings.egress[1]);
    // This projection neither queries a native NIC nor imports a live ACK;
    // actual caller is the opaque SAME-owner closed C+A/B reader.
}

#[test]
fn mixed_closing_projection_retains_closed_a_and_live_b_without_changing_live_sdk_inputs() {
    let context = record().context;
    let live = vec![retired_member(2)];
    let closed = vec![retired_member(1)];
    let bindings =
        closing_comparison_bindings(&context, &original_identity(), &live, &closed).unwrap();
    assert_eq!(bindings.egress[0].as_ref().unwrap().proof.index, 8);
    assert_eq!(bindings.egress[1].as_ref().unwrap().proof.index, 9);
    assert_eq!(live, vec![retired_member(2)]);
    // No retirement data can enter the live provider slice through projection.
    for fault in 0..5 {
        let mut wrong = closed.clone();
        match fault {
            0 => wrong[0] = live[0].clone(),
            1 => wrong[0].identity.guid = [8; 16],
            2 => wrong[0].identity.index = live[0].identity.index,
            3 => wrong[0].identity.luid = live[0].identity.luid,
            _ => wrong[0].identity.name.push_str("-foreign"),
        }
        assert!(
            closing_comparison_bindings(&context, &original_identity(), &live, &wrong).is_err(),
            "fault={fault}"
        );
    }
    assert!(closing_comparison_bindings(
        &context,
        &original_identity(),
        &[],
        &[retired_member(1), retired_member(2)]
    )
    .is_ok());
}

#[test]
fn closed_bindings_reject_duplicate_foreign_or_reused_comparison_identities() {
    for fault in 0..8 {
        let context = record().context;
        let mut carrier = original_identity();
        let mut members = [retired_member(1), retired_member(2)];
        match fault {
            0 => members[1].identity.luid = carrier.luid,
            1 => members[1].identity.index = carrier.index,
            2 => members[1].identity.guid = members[0].identity.guid,
            3 => members[0].identity.name.push_str("-foreign"),
            4 => carrier.guid = [9; 16],
            5 => members[1].identity.if_type = 6,
            6 => members[0].identity.tunnel_type = 1,
            _ => carrier.luid = 0,
        }
        assert!(
            comparison_bindings(&context, &carrier, &members).is_err(),
            "fault {fault}"
        );
    }
}

fn pending_rows() -> crate::member_carrier_rows::Record {
    use crate::member_carrier_rows as r;
    let binding = rows_binding(&record().context, &original_identity()).unwrap();
    let policy = r::InterfacePolicy {
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
    };
    let baseline = r::Snapshot {
        interface: r::InterfaceRow {
            key: binding.key,
            policy,
            observed: r::InterfaceObserved {
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
    let target = r::Target::Create(r::AddressPolicy {
        address: binding.address,
        prefix_origin: 1,
        suffix_origin: 1,
        valid_lifetime: u32::MAX,
        preferred_lifetime: u32::MAX,
        on_link_prefix_length: 32,
        skip_as_source: false,
    });
    r::Record {
        version: 1,
        domain: r::DOMAIN.into(),
        binding,
        revision: 2,
        phase: r::Phase::Captured,
        baseline: baseline.clone(),
        current: baseline.clone(),
        pending: Some(r::Pending {
            before: baseline,
            target,
        }),
        creation: None,
    }
}

fn ready_rows() -> crate::member_carrier_rows::Record {
    use crate::member_carrier_rows as r;
    let mut rows = pending_rows();
    let r::Target::Create(policy) = rows.pending.take().unwrap().target else {
        unreachable!()
    };
    let address = r::AddressRow {
        key: rows.binding.key,
        policy,
        observed: r::AddressObserved {
            dad_state: 4,
            scope_id: 0,
            creation_timestamp: 12,
        },
    };
    rows.creation = Some(address.clone());
    rows.current.address = Some(address);
    rows.revision += 1;
    rows.validate().unwrap();
    rows
}

fn early_closing_pair() -> crate::member_carrier_pair::Record {
    use crate::{member_carrier_guard as g, member_carrier_pair as p};
    let context = record().context;
    p::Record {
        version: 2,
        scope: context.intent.scope.clone(),
        provenance: context.provenance,
        revision: 4,
        phase: p::Phase::Closing,
        addresses: context.intent.addresses,
        dns: vec![],
        carrier: None,
        members: [None, None],
        active: None,
        options: Some(nelomai_client_tunnel::DesktopTunnelOptions::default()),
        guard: g::Model::empty(context.intent.scope).unwrap(),
        pending_guard: None,
        pending: Some(p::Effect::RestoreWeak),
        network: None,
        stop_stage: 3,
        operation: None,
    }
}

#[test]
fn created_cleanup_storage_is_exact_prepublication_closing_c_only_not_live_or_foreign() {
    use crate::member_carrier_rows as r;
    let context = record().context;
    let pair = early_closing_pair();
    let before = pending_rows();
    let mut desired = ready_rows();
    desired.phase = r::Phase::Closing;
    compare_created_cleanup_storage(&context, &pair, &before.binding, &before, &desired).unwrap();
    for fault in 0..13 {
        let mut other_pair = pair.clone();
        let mut other = desired.clone();
        match fault {
            0 => other_pair.phase = crate::member_carrier_pair::Phase::Starting,
            1 => other_pair.scope.connection_generation += 1,
            2 => other_pair.provenance.network_epoch += 1,
            3 => other_pair.addresses = vec!["10.7.0.3/32".parse().unwrap()],
            4 => other_pair.stop_stage = 7,
            5 => {
                other_pair.carrier = Some(crate::member_owner::InterfaceProof {
                    guid: [9; 16],
                    luid: before.binding.key.luid,
                    index: before.binding.key.index,
                })
            }
            6 => other.phase = r::Phase::Captured,
            7 => other.binding.role = r::Role::MemberA,
            8 => other.binding.runtime.manifest_sha256 = "b".repeat(64),
            9 => other.revision += 1,
            10 => other.baseline.interface.policy.metric += 1,
            11 => other.creation = None,
            _ => other.binding.address[3] += 1,
        }
        assert!(
            compare_created_cleanup_storage(
                &context,
                &other_pair,
                &before.binding,
                &before,
                &other
            )
            .is_err(),
            "fault {fault}"
        );
    }
}

fn initial_captured_rows() -> crate::member_carrier_rows::Record {
    let mut initial = pending_rows();
    initial.revision = 1;
    initial.pending = None;
    initial
}

#[test]
fn initial_capture_cleanup_accepts_only_new_closing_confirmation_not_initial_ack_adoption() {
    use crate::member_carrier_rows as r;
    let context = record().context;
    let pair = early_closing_pair();
    let initial = initial_captured_rows();
    for present in [false, true] {
        let mut desired = initial.clone();
        desired.revision = 2;
        desired.phase = r::Phase::Closing;
        compare_initial_capture_cleanup_storage(
            &context,
            &pair,
            &initial.binding,
            &initial,
            present.then_some(&initial),
            &desired,
        )
        .unwrap();
        desired.phase = r::Phase::Captured;
        assert!(compare_initial_capture_cleanup_storage(
            &context,
            &pair,
            &initial.binding,
            &initial,
            present.then_some(&initial),
            &desired,
        )
        .is_err());
    }
}

#[test]
fn initial_capture_cleanup_retry_preserves_original_baseline_and_does_not_create_an_address() {
    use crate::member_carrier_rows as r;
    let context = record().context;
    let pair = early_closing_pair();
    let initial = initial_captured_rows();
    let mut expected = initial.clone();
    expected.revision = 2;
    expected.phase = r::Phase::Closing;
    let mut desired = expected.clone();
    desired.revision = 3;
    desired.current.interface.observed.reachable_time = 31000;
    compare_initial_capture_cleanup_storage(
        &context,
        &pair,
        &initial.binding,
        &initial,
        Some(&expected),
        &desired,
    )
    .unwrap();
    for fault in 0..12 {
        let mut selected = pair.clone();
        let mut wrong = desired.clone();
        match fault {
            0 => selected.pending = None,
            1 => selected.pending = Some(crate::member_carrier_pair::Effect::CarrierReady),
            2 => selected.stop_stage = 7,
            3 => selected.scope.connection_generation += 1,
            4 => selected.provenance.network_epoch += 1,
            5 => wrong.revision = 2,
            6 => wrong.binding.role = r::Role::MemberA,
            7 => wrong.current.interface.policy.weak_host_send = true,
            8 => wrong.current = ready_rows().current,
            9 => wrong.creation = ready_rows().creation,
            10 => wrong.baseline.interface.policy.metric += 1,
            _ => wrong.pending = pending_rows().pending,
        }
        assert!(
            compare_initial_capture_cleanup_storage(
                &context,
                &selected,
                &initial.binding,
                &initial,
                Some(&expected),
                &wrong,
            )
            .is_err(),
            "fault {fault}"
        );
    }
}

#[test]
fn created_cleanup_storage_never_accepts_unselected_or_mismatched_stop_effect() {
    use crate::member_carrier_pair::Effect;
    let context = record().context;
    let before = pending_rows();
    let mut desired = ready_rows();
    desired.phase = crate::member_carrier_rows::Phase::Closing;
    for pending in [
        None,
        Some(Effect::CarrierReady),
        Some(Effect::CarrierAddressDelete),
        Some(Effect::RestoreKeys),
    ] {
        let mut pair = early_closing_pair(); // stage3 requires actual RestoreWeak
        pair.pending = pending;
        assert!(
            compare_created_cleanup_storage(&context, &pair, &before.binding, &before, &desired)
                .is_err(),
            "pending={pending:?}"
        );
    }
}

#[test]
fn resource_rows_require_actual_ack_protected_bytes_and_complete_current_native_rows() {
    use crate::member_carrier_rows as rows;
    let context = record().context;
    let ack = ready_rows();
    let identity = crate::member_carrier_guard::Identity {
        scope: context.intent.scope.clone(),
        proof: crate::member_owner::InterfaceProof {
            guid: ack.binding.guid,
            index: ack.binding.key.index,
            luid: ack.binding.key.luid,
        },
    };
    assert!(compare_resource_rows(
        &context,
        &identity,
        &ack.binding,
        &ack,
        &ack,
        Some(&ack.current),
        ResourceRowChannel::Source
    )
    .is_ok());
    for fault in 0..8 {
        let mut protected = ack.clone();
        let mut actual = ack.current.clone();
        let mut original = ack.binding.clone();
        let mut expected = identity.clone();
        match fault {
            0 => protected.revision += 1,
            1 => original.network_epoch += 1,
            2 => expected.proof.luid += 1,
            3 => actual.interface.policy.forwarding = true,
            4 => actual.address.as_mut().unwrap().observed.creation_timestamp += 1,
            5 => actual.address.as_mut().unwrap().observed.dad_state = 1,
            6 => original.role = rows::Role::MemberA,
            _ => protected.current.interface.policy.weak_host_send = true,
        }
        assert!(
            compare_resource_rows(
                &context,
                &expected,
                &original,
                &ack,
                &protected,
                Some(&actual),
                ResourceRowChannel::Source
            )
            .is_err(),
            "fault {fault}"
        );
    }
}

#[test]
fn resource_rows_closed_history_is_separate_from_live_sdk_and_cannot_rearm() {
    use crate::member_carrier_rows as rows;
    let context = record().context;
    let mut ack = ready_rows();
    ack.binding.role = rows::Role::MemberA;
    ack.binding.guid = context.bindings[1].guid;
    ack.binding.name = context.bindings[1].name.clone();
    ack.binding.key = rows::RowKey {
        index: 41,
        luid: 4100,
    };
    ack.baseline.interface.key = ack.binding.key;
    ack.current = ack.baseline.clone();
    ack.creation = None;
    ack.phase = rows::Phase::Stopped;
    ack.validate().unwrap();
    let identity = crate::member_carrier_guard::Identity {
        scope: context.intent.scope.clone(),
        proof: crate::member_owner::InterfaceProof {
            guid: ack.binding.guid,
            index: 41,
            luid: 4100,
        },
    };
    assert!(compare_resource_rows(
        &context,
        &identity,
        &ack.binding,
        &ack,
        &ack,
        None,
        ResourceRowChannel::Closed
    )
    .is_ok());
    assert!(compare_resource_rows(
        &context,
        &identity,
        &ack.binding,
        &ack,
        &ack,
        Some(&ack.current),
        ResourceRowChannel::Closed
    )
    .is_err());
    assert!(compare_resource_rows(
        &context,
        &identity,
        &ack.binding,
        &ack,
        &ack,
        Some(&ack.current),
        ResourceRowChannel::Source
    )
    .is_err());
    ack.phase = rows::Phase::Captured;
    assert!(compare_resource_rows(
        &context,
        &identity,
        &ack.binding,
        &ack,
        &ack,
        None,
        ResourceRowChannel::Closed
    )
    .is_err());
}

#[test]
fn retiring_member_rows_require_stopped_original_ack_and_still_live_sdk() {
    use crate::member_carrier_rows as rows;
    let context = record().context;
    let mut ack = ready_rows();
    ack.binding.role = rows::Role::MemberA;
    ack.binding.guid = context.bindings[1].guid;
    ack.binding.name = context.bindings[1].name.clone();
    ack.binding.key = rows::RowKey {
        index: 41,
        luid: 4100,
    };
    ack.baseline.interface.key = ack.binding.key;
    ack.current = ack.baseline.clone();
    ack.creation = None;
    ack.phase = rows::Phase::Closing;
    ack.validate().unwrap();
    let identity = crate::member_carrier_guard::Identity {
        scope: context.intent.scope.clone(),
        proof: crate::member_owner::InterfaceProof {
            guid: ack.binding.guid,
            index: 41,
            luid: 4100,
        },
    };
    assert!(compare_resource_rows(
        &context,
        &identity,
        &ack.binding,
        &ack,
        &ack,
        Some(&ack.current),
        ResourceRowChannel::Retiring
    )
    .is_err());
    ack.phase = rows::Phase::Stopped;
    assert!(compare_resource_rows(
        &context,
        &identity,
        &ack.binding,
        &ack,
        &ack,
        Some(&ack.current),
        ResourceRowChannel::Retiring
    )
    .is_ok());
    assert!(compare_resource_rows(
        &context,
        &identity,
        &ack.binding,
        &ack,
        &ack,
        None,
        ResourceRowChannel::Retiring
    )
    .is_err());
    assert!(compare_resource_rows(
        &context,
        &identity,
        &ack.binding,
        &ack,
        &ack,
        Some(&ack.current),
        ResourceRowChannel::Source
    )
    .is_err());
    let mut wrong = ack.current.clone();
    wrong.interface.policy.weak_host_send = true;
    assert!(compare_resource_rows(
        &context,
        &identity,
        &ack.binding,
        &ack,
        &ack,
        Some(&wrong),
        ResourceRowChannel::Retiring
    )
    .is_err());
}

#[test]
fn retired_carrier_rows_require_same_stopped_ack_and_no_live_sdk_projection() {
    let context = record().context;
    let mut ack = ready_rows();
    ack.phase = crate::member_carrier_rows::Phase::Stopped;
    ack.current = ack.baseline.clone();
    ack.validate().unwrap();
    let identity = crate::member_carrier_guard::Identity {
        scope: context.intent.scope.clone(),
        proof: crate::member_owner::InterfaceProof {
            guid: ack.binding.guid,
            index: ack.binding.key.index,
            luid: ack.binding.key.luid,
        },
    };
    assert!(compare_resource_rows(
        &context,
        &identity,
        &ack.binding,
        &ack,
        &ack,
        None,
        ResourceRowChannel::Retired
    )
    .is_ok());
    // Closing's C is still live: only the actual Retired full-absence bracket
    // can consume the historical C RowOwner ACK without querying its old index.
    assert!(compare_resource_rows(
        &context,
        &identity,
        &ack.binding,
        &ack,
        &ack,
        None,
        ResourceRowChannel::Closed
    )
    .is_err());
    assert!(compare_resource_rows(
        &context,
        &identity,
        &ack.binding,
        &ack,
        &ack,
        Some(&ack.current),
        ResourceRowChannel::Retired
    )
    .is_err());
    ack.phase = crate::member_carrier_rows::Phase::Captured;
    assert!(compare_resource_rows(
        &context,
        &identity,
        &ack.binding,
        &ack,
        &ack,
        None,
        ResourceRowChannel::Retired
    )
    .is_err());
}

#[test]
fn ready_source_comparison_requires_original_c_and_same_address_creation_metadata() {
    let rows = ready_rows();
    let mut capture = rows.creation.clone().unwrap();
    capture.observed.dad_state = 1; // Original causal receipt before Preferred.
    let source = ready_source_comparison(
        &record().context,
        &original_identity(),
        &rows.binding,
        &capture,
        &rows,
        &rows.current,
    )
    .unwrap();
    assert_eq!(source.identity.proof.index, original_identity().index);
    assert_eq!(
        source.sources,
        vec![std::net::IpAddr::V4(rows.binding.address.into())]
    );
    // Weak flags may be independently owned and acknowledged later; the source
    // comparison still requires full exact current policy, never JSON-only use.
    let mut changed = rows.clone();
    changed.current.interface.policy.weak_host_send = true;
    changed.current.interface.policy.weak_host_receive = true;
    assert!(ready_source_comparison(
        &record().context,
        &original_identity(),
        &changed.binding,
        &capture,
        &changed,
        &changed.current
    )
    .is_ok());
}

#[test]
fn row_effect_source_read_keeps_ready_address_during_exact_pending_weak_delta() {
    use crate::member_carrier_rows as r;
    let mut rows = ready_rows();
    let captured = rows.creation.clone().unwrap();
    let mut policy = rows.current.interface.policy.clone();
    policy.weak_host_send = true;
    policy.weak_host_receive = true;
    rows.pending = Some(r::Pending {
        before: rows.current.clone(),
        target: r::Target::Interface(policy.clone()),
    });
    rows.validate().unwrap();
    // The ordinary source reader cannot serve G's exact pending row callback:
    // RowOwner writes pending durably BEFORE independently authorizing the Set.
    let target = rows.pending.as_ref().unwrap().target.clone();
    assert!(ready_source_comparison(
        &record().context,
        &original_identity(),
        &rows.binding,
        &captured,
        &rows,
        &rows.current
    )
    .is_err());
    assert!(row_effect_source_comparison(
        &record(),
        &original_identity(),
        &rows.binding,
        &captured,
        &rows,
        &rows.current,
        &target
    )
    .is_ok());
    let mut applied = rows.current.clone();
    applied.interface.policy = policy;
    assert!(row_effect_source_comparison(
        &record(),
        &original_identity(),
        &rows.binding,
        &captured,
        &rows,
        &applied,
        &target
    )
    .is_ok());
    assert!(ready_source_comparison(
        &record().context,
        &original_identity(),
        &rows.binding,
        &captured,
        &rows,
        &applied
    )
    .is_err());
}

#[test]
fn pending_row_source_facts_reject_any_nonexact_address_interface_target_or_native_phase() {
    use crate::member_carrier_rows as r;
    for fault in 0..16 {
        let mut receipts = record();
        let mut rows = ready_rows();
        let mut capture = rows.creation.clone().unwrap();
        let mut original = original_identity();
        let binding = rows.binding.clone();
        let mut policy = rows.current.interface.policy.clone();
        policy.weak_host_send = true;
        policy.weak_host_receive = true;
        let mut target = r::Target::Interface(policy);
        rows.pending = Some(r::Pending {
            before: rows.current.clone(),
            target: target.clone(),
        });
        let mut actual = rows.current.clone();
        match fault {
            0 => rows.pending = None,
            1 => target = r::Target::Delete,
            2 => rows.pending.as_mut().unwrap().target = r::Target::Delete,
            3 => actual.address.as_mut().unwrap().observed.dad_state = 1,
            4 => actual.address.as_mut().unwrap().observed.creation_timestamp += 1,
            5 => actual.interface.policy.weak_host_send = true, // Partial target, not before/after.
            6 => actual.interface.policy.metric += 1,
            7 => actual.interface.policy.forwarding = true,
            8 => rows.phase = r::Phase::Closing,
            9 => receipts.phase = Phase::Closing,
            10 => receipts.keys[0].new_key_ack = false,
            11 => rows.binding.network_epoch += 1,
            12 => capture.key.luid += 1,
            13 => original.guid = [9; 16],
            14 => rows.pending.as_mut().unwrap().before.interface.policy.mtu += 1,
            _ => rows.creation = None,
        }
        assert!(
            row_effect_source_comparison(
                &receipts, &original, &binding, &capture, &rows, &actual, &target
            )
            .is_err(),
            "fault {fault}"
        );
    }
}

#[test]
fn ready_source_denies_tentative_foreign_pending_retired_or_policy_drift() {
    for fault in 0..12 {
        let mut rows = ready_rows();
        let mut captured = rows.creation.clone().unwrap();
        let mut identity = original_identity();
        let binding = rows.binding.clone();
        let mut native = rows.current.clone();
        match fault {
            0 => native.address.as_mut().unwrap().observed.dad_state = 1,
            1 => native.address.as_mut().unwrap().observed.creation_timestamp += 1,
            2 => native.address.as_mut().unwrap().policy.skip_as_source = true,
            3 => native.interface.policy.weak_host_receive = true,
            4 => rows.phase = crate::member_carrier_rows::Phase::Closing,
            5 => {
                rows.pending = Some(crate::member_carrier_rows::Pending {
                    before: rows.current.clone(),
                    target: crate::member_carrier_rows::Target::Delete,
                })
            }
            6 => captured.key.index += 1,
            7 => identity.guid = [9; 16],
            8 => rows.binding.network_epoch += 1,
            9 => rows.creation = None,
            10 => native.address = None,
            _ => {
                native.interface.policy.forwarding = true;
                rows.current.interface.policy.forwarding = true;
            }
        }
        assert!(
            ready_source_comparison(
                &record().context,
                &identity,
                &binding,
                &captured,
                &rows,
                &native
            )
            .is_err(),
            "fault {fault}"
        );
    }
}

#[test]
fn row_effect_requires_the_exact_pending_target_and_original_carrier_binding() {
    let native = record();
    let rows = pending_rows();
    let target = rows.pending.as_ref().unwrap().target.clone();
    assert!(validate_rows_effect(&native, &rows, &rows.binding, &target).is_ok());
    for drift in 0..7 {
        let mut changed = rows.clone();
        match drift {
            0 => changed.pending = None,
            1 => changed.binding.role = crate::member_carrier_rows::Role::MemberA,
            2 => changed.binding.network_epoch += 1,
            3 => changed.binding.key.index += 1,
            4 => changed.binding.scope.connection_generation += 1,
            5 => {
                changed.pending.as_mut().unwrap().target =
                    crate::member_carrier_rows::Target::Delete
            }
            _ => {
                changed
                    .pending
                    .as_mut()
                    .unwrap()
                    .before
                    .interface
                    .policy
                    .metric += 1
            }
        }
        assert!(
            validate_rows_effect(&native, &changed, &rows.binding, &target).is_err(),
            "drift {drift}"
        );
    }
}

#[test]
fn actual_member_row_selection_preserves_scope_and_never_grants_member_vip_creation() {
    use crate::member_carrier_rows as r;
    for role in [r::Role::MemberA, r::Role::MemberB] {
        let native = record();
        let i = if role == r::Role::MemberA { 1 } else { 2 };
        let mut identity = original_identity();
        identity.guid = native.context.bindings[i].guid;
        identity.name = native.context.bindings[i].name.clone();
        identity.index += i as u32;
        identity.luid += i as u64;
        let binding = member_rows_binding(&native.context, role, &identity).unwrap();
        assert_eq!(binding.scope, native.context.intent.scope);
        assert_eq!(binding.role, role);
        assert_eq!(binding.address, [10, 7, 0, 2]);
        let mut rows = pending_rows();
        rows.binding = binding.clone();
        rows.baseline.interface.key = binding.key;
        rows.current = rows.baseline.clone();
        let mut weak = rows.current.interface.policy.clone();
        weak.weak_host_send = true;
        weak.weak_host_receive = true;
        let change = r::Target::Interface(weak);
        rows.pending = Some(r::Pending {
            before: rows.current.clone(),
            target: change.clone(),
        });
        rows.validate().unwrap();
        assert!(validate_rows_effect(&native, &rows, &binding, &change).is_ok());
        rows.phase = r::Phase::Closing;
        let restore = r::Target::Interface(rows.baseline.interface.policy.clone());
        rows.pending.as_mut().unwrap().target = restore.clone();
        assert!(validate_rows_effect(&native, &rows, &binding, &restore).is_ok());
        // Stop persists native Closing FIRST. Exact weak baseline restoration
        // must still precede actual member Stop, under live-original cleanup
        // reads. This is data validation, not G's effect permission.
        let mut closing = native.clone();
        closing.phase = Phase::Closing;
        assert!(validate_rows_effect(&closing, &rows, &binding, &restore).is_ok());
        rows.phase = r::Phase::Captured;
        let creation = pending_rows().pending.unwrap().target;
        rows.pending.as_mut().unwrap().target = creation.clone();
        assert!(validate_rows_effect(&native, &rows, &binding, &creation).is_err());
        assert!(member_rows_binding(&native.context, r::Role::Carrier, &identity).is_err());
    }
}

#[test]
fn member_row_effect_denies_foreign_binding_key_revision_and_nonweak_changes() {
    use crate::member_carrier_rows as r;
    let native = record();
    let mut identity = original_identity();
    identity.guid = native.context.bindings[1].guid;
    identity.name = native.context.bindings[1].name.clone();
    let binding = member_rows_binding(&native.context, r::Role::MemberA, &identity).unwrap();
    let mut rows = pending_rows();
    rows.binding = binding.clone();
    rows.baseline.interface.key = binding.key;
    rows.current = rows.baseline.clone();
    let change = r::Target::Interface(rows.current.interface.policy.clone());
    rows.pending = Some(r::Pending {
        before: rows.current.clone(),
        target: change.clone(),
    });
    for fault in 0..9 {
        let mut native = native.clone();
        let mut rows = rows.clone();
        match fault {
            0 => native.keys[1].new_key_ack = false,
            1 => native.keys[1].pending = Some(Value::Absent),
            2 => native.keys[1].phase = KeyPhase::RestorePending,
            3 => rows.binding.guid = [9; 16],
            4 => rows.binding.name.push_str("-foreign"),
            5 => rows.binding.role = r::Role::MemberB,
            6 => rows.binding.address[3] += 1,
            7 => rows.pending = None,
            _ => {
                let r::Target::Interface(policy) = &mut rows.pending.as_mut().unwrap().target
                else {
                    unreachable!()
                };
                policy.forwarding = true;
            }
        }
        let target = rows
            .pending
            .as_ref()
            .map(|p| p.target.clone())
            .unwrap_or(change.clone());
        assert!(
            validate_rows_effect(&native, &rows, &binding, &target).is_err(),
            "fault {fault}"
        );
    }
}

#[test]
fn member_closing_restoration_cannot_rearm_or_accept_drift() {
    use crate::member_carrier_rows as r;
    for role in [r::Role::MemberA, r::Role::MemberB] {
        let mut native = record();
        native.phase = Phase::Closing;
        let i = if role == r::Role::MemberA { 1 } else { 2 };
        let mut identity = original_identity();
        identity.guid = native.context.bindings[i].guid;
        identity.name = native.context.bindings[i].name.clone();
        let binding = member_rows_binding(&native.context, role, &identity).unwrap();
        let mut rows = pending_rows();
        rows.binding = binding.clone();
        rows.baseline.interface.key = binding.key;
        rows.current = rows.baseline.clone();
        rows.phase = r::Phase::Closing;
        let restore = r::Target::Interface(rows.baseline.interface.policy.clone());
        rows.pending = Some(r::Pending {
            before: rows.current.clone(),
            target: restore.clone(),
        });
        assert!(validate_rows_effect(&native, &rows, &binding, &restore).is_ok());
        for fault in 0..8 {
            let mut native = native.clone();
            let mut rows = rows.clone();
            match fault {
                0 => rows.phase = r::Phase::Captured,
                1 => {
                    if let r::Target::Interface(policy) = &mut rows.pending.as_mut().unwrap().target
                    {
                        policy.weak_host_send = !policy.weak_host_send;
                    }
                }
                2 => rows.pending = None,
                3 => rows.binding.network_epoch += 1,
                4 => native.keys[i].new_key_ack = false,
                5 => native.keys[i].pending = Some(Value::Absent),
                6 => native.phase = Phase::Stopped,
                _ => rows.binding.scope.connection_generation += 1,
            }
            let target = rows
                .pending
                .as_ref()
                .map(|p| p.target.clone())
                .unwrap_or(restore.clone());
            assert!(
                validate_rows_effect(&native, &rows, &binding, &target).is_err(),
                "{role:?} fault {fault}"
            );
        }
    }
}

#[test]
fn equal_carrier_identity_cannot_authorize_a_different_logical_vip() {
    let native = record();
    let mut rows = pending_rows();
    rows.binding.address = [10, 7, 0, 99];
    let crate::member_carrier_rows::Target::Create(policy) =
        &mut rows.pending.as_mut().unwrap().target
    else {
        panic!("create fixture")
    };
    policy.address = rows.binding.address;
    rows.validate().unwrap();
    let target = rows.pending.as_ref().unwrap().target.clone();
    assert!(validate_rows_effect(&native, &rows, &rows.binding, &target).is_err());
}

#[test]
fn closing_row_gate_allows_only_exact_baseline_restoration_never_creation_or_new_weak_flags() {
    use crate::member_carrier_rows as r;
    let mut native = record();
    native.phase = Phase::Closing;
    let mut rows = pending_rows();
    let create = rows.pending.as_ref().unwrap().target.clone();
    assert!(validate_rows_effect(&native, &rows, &rows.binding, &create).is_err());
    rows.phase = r::Phase::Closing;
    let restore = r::Target::Interface(rows.baseline.interface.policy.clone());
    rows.pending.as_mut().unwrap().target = restore.clone();
    assert!(validate_rows_effect(&native, &rows, &rows.binding, &restore).is_ok());
    let mut weak = rows.baseline.interface.policy.clone();
    weak.weak_host_send = true;
    rows.pending.as_mut().unwrap().target = r::Target::Interface(weak.clone());
    assert!(
        validate_rows_effect(&native, &rows, &rows.binding, &r::Target::Interface(weak)).is_err()
    );
    rows.pending.as_mut().unwrap().target = restore.clone();
    native.phase = Phase::Stopped;
    assert!(validate_rows_effect(&native, &rows, &rows.binding, &restore).is_err());
}

#[test]
fn carrier_row_binding_retains_original_identity_and_exact_runtime_scope() {
    let r = record();
    let b = rows_binding(&r.context, &original_identity()).unwrap();
    assert_eq!(b.scope, r.context.intent.scope);
    assert_eq!(b.role, crate::member_carrier_rows::Role::Carrier);
    assert_eq!(b.key.luid, 77);
    assert_eq!(b.key.index, 7);
    assert_eq!(b.address, [10, 7, 0, 2]);
    assert_eq!(b.boot_id, [8; 16]);
    assert_eq!(b.network_epoch, 7);
}

#[test]
fn foreign_or_unusable_original_carrier_cannot_bind_native_row_owner() {
    let context = record().context;
    for field in 0..6 {
        let mut identity = original_identity();
        match field {
            0 => identity.guid = [2; 16],
            1 => identity.name = "member-a".into(),
            2 => identity.luid = 0,
            3 => identity.index = 0,
            4 => identity.if_type = 6,
            _ => identity.tunnel_type = 1,
        }
        assert!(rows_binding(&context, &identity).is_err());
    }
}

#[test]
fn row_bridge_never_discards_an_unsupported_or_second_logical_address() {
    for addresses in [
        vec!["fd00::2/128"],
        vec!["10.7.0.2/24"],
        vec!["10.7.0.2/32", "10.7.0.3/32"],
        vec![],
    ] {
        let mut context = record().context;
        context.intent.addresses = addresses.into_iter().map(|a| a.parse().unwrap()).collect();
        assert!(rows_binding(&context, &original_identity()).is_err());
    }
}

fn record() -> Record {
    let bindings = std::array::from_fn(|i| {
        let byte = (i + 1) as u8;
        Binding {
            role: [Role::RoleCarrier, Role::MemberA, Role::MemberB][i],
            guid: [byte; 16],
            name: ["carrier-c", "member-a", "member-b"][i].into(),
            registry_path: format!(
                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{{{byte:02X}{byte:02X}{byte:02X}{byte:02X}-{byte:02X}{byte:02X}-{byte:02X}{byte:02X}-{byte:02X}{byte:02X}-{byte:02X}{byte:02X}{byte:02X}{byte:02X}{byte:02X}{byte:02X}}}"
            ),
        }
    });
    Record {
        version: 2,
        context: Context {
            intent: Intent {
                scope: SessionScope {
                    runtime: RuntimeSlot::Stable,
                    runtime_generation: 2,
                    session_id: "11111111-1111-4111-8111-111111111111".into(),
                    connection_generation: 3,
                },
                addresses: vec!["10.7.0.2/32".parse().unwrap()],
            },
            provenance: Provenance {
                boot_id: [8; 16],
                network_epoch: 7,
                runtime: EngineIdentity {
                    slot: RuntimeSlot::Stable,
                    runtime_version: "0.3.3".into(),
                    container_version: "0.3.3".into(),
                    runtime_contract_version: 1,
                    manifest_sha256: "a".repeat(64),
                },
            },
            bindings,
        },
        generation: 13,
        phase: Phase::Preparing,
        keys: std::array::from_fn(|i| KeyReceipt {
            role: [Role::RoleCarrier, Role::MemberA, Role::MemberB][i],
            phase: KeyPhase::Disabled,
            new_key_ack: true,
            baseline: Value::Absent,
            current: Value::DwordZero,
            pending: None,
        }),
        native_rows: FullNativeRows::Unbound,
    }
}

#[test]
fn exact_create_stage_requires_fresh_permission_and_creation_revision() {
    let r = record();
    assert!(validate_stage(
        &r,
        &r.context,
        &r.context.bindings[0],
        13,
        true,
        Use::Create
    )
    .is_ok());
    for (generation, fresh) in [(0, true), (12, true), (14, true), (13, false)] {
        assert!(validate_stage(
            &r,
            &r.context,
            &r.context.bindings[0],
            generation,
            fresh,
            Use::Create
        )
        .is_err());
    }
}

#[test]
fn terminal_revision_accepts_only_stopped_restored_native_keys_and_original_birth() {
    let mut stopped = record();
    stopped.phase = Phase::Stopped;
    for key in &mut stopped.keys {
        key.phase = KeyPhase::Clean;
        key.current = Value::Absent;
    }
    validate_terminal_stage(&stopped, &stopped.context, &stopped.context.bindings[0], 10).unwrap();
    // A never-started member key is legitimate; the C's original NEW key ACK
    // remains mandatory independently of actual closed native history.
    stopped.keys[2].new_key_ack = false;
    validate_terminal_stage(&stopped, &stopped.context, &stopped.context.bindings[0], 10).unwrap();
    for use_ in [Use::Create, Use::Live, Use::Cleanup] {
        assert!(validate_stage(
            &stopped,
            &stopped.context,
            &stopped.context.bindings[0],
            10,
            true,
            use_
        )
        .is_err());
    }
    for fault in 0..10 {
        let mut bad = stopped.clone();
        let mut context = stopped.context.clone();
        let mut binding = stopped.context.bindings[0].clone();
        let mut generation = 10;
        match fault {
            0 => bad.phase = Phase::Closing,
            1 => bad.phase = Phase::Preparing,
            2 => bad.keys[0].new_key_ack = false,
            3 => {
                bad.phase = Phase::Closing;
                bad.keys[1].phase = KeyPhase::Disabled;
                bad.keys[1].current = Value::DwordZero;
            }
            4 => bad.keys[2].pending = Some(Value::DwordZero),
            5 => context.provenance.network_epoch += 1,
            6 => binding = context.bindings[1].clone(),
            7 => generation = 0,
            8 => generation = 14,
            _ => bad.context.intent.scope.connection_generation += 1,
        }
        assert!(
            validate_terminal_stage(&bad, &context, &binding, generation).is_err(),
            "fault {fault}"
        );
    }
}

#[test]
fn pregraph_native_empty_original_revision_keeps_cleanup_keys_until_later_stage() {
    let mut closing = record();
    closing.phase = Phase::Closing;
    validate_retired_read_stage(
        &closing,
        &closing.context,
        &closing.context.bindings[0],
        10,
        RetiredReadStage::Cleanup,
    )
    .unwrap();
    assert!(validate_retired_read_stage(
        &closing,
        &closing.context,
        &closing.context.bindings[0],
        10,
        RetiredReadStage::Terminal
    )
    .is_err());
    let mut restored = closing.clone();
    restored.phase = Phase::Stopped;
    for key in &mut restored.keys {
        key.phase = KeyPhase::Clean;
        key.current = Value::Absent;
    }
    validate_retired_read_stage(
        &restored,
        &restored.context,
        &restored.context.bindings[0],
        10,
        RetiredReadStage::Terminal,
    )
    .unwrap();
    assert!(validate_retired_read_stage(
        &restored,
        &restored.context,
        &restored.context.bindings[0],
        10,
        RetiredReadStage::Cleanup
    )
    .is_err());
    for fault in 0..5 {
        let mut bad = closing.clone();
        let mut context = closing.context.clone();
        match fault {
            0 => bad.keys[0].new_key_ack = false,
            1 => bad.keys[0].pending = Some(Value::Absent),
            2 => bad.keys[0].current = Value::Absent,
            3 => context.provenance.network_epoch += 1,
            _ => bad.phase = Phase::Preparing,
        }
        assert!(validate_retired_read_stage(
            &bad,
            &context,
            &context.bindings[0],
            10,
            RetiredReadStage::Cleanup
        )
        .is_err());
    }
}

#[test]
fn slow_authentication_cannot_accept_a_different_protected_revision() {
    let before = record();
    assert!(same_record(&before, record()).is_ok());
    let mut after = record();
    after.generation += 1;
    // Both records independently satisfy live-stage validation. That is NOT
    // permission to carry the first authenticated operation into a new epoch.
    validate_stage(
        &after,
        &after.context,
        &after.context.bindings[0],
        13,
        true,
        Use::Live,
    )
    .unwrap();
    assert!(same_record(&before, after).is_err());
    let mut after = record();
    after.phase = Phase::Closing;
    assert!(same_record(&before, after).is_err());
}

#[test]
fn terminal_original_universe_requires_stopped_keys_zero_live_inputs_and_empty_sdk_result() {
    let mut stopped = record();
    stopped.phase = Phase::Stopped;
    for key in &mut stopped.keys {
        key.phase = KeyPhase::Clean;
        key.current = Value::Absent;
    }
    let called = Cell::new(0);
    assert_eq!(
        inspect_terminal_universe(&stopped, &stopped.context, 0, || {
            called.set(called.get() + 1);
            Ok(Vec::<u8>::new())
        }),
        Ok(vec![])
    );
    assert_eq!(
        called.get(),
        1,
        "terminal branch must still query actual full SDK"
    );
    assert!(inspect_terminal_universe(&stopped, &stopped.context, 0, || Ok(vec![17])).is_err());
    for fault in 0..6 {
        let mut other = stopped.clone();
        let mut context = stopped.context.clone();
        let mut live = 0;
        match fault {
            0 => other.phase = Phase::Closing,
            1 => other.phase = Phase::Preparing,
            2 => other.keys[0].new_key_ack = false,
            3 => other.keys[1].current = Value::DwordZero,
            4 => context.provenance.network_epoch += 1,
            _ => live = 1,
        }
        let called = Cell::new(false);
        assert!(
            inspect_terminal_universe(&other, &context, live, || {
                called.set(true);
                Ok(Vec::<u8>::new())
            })
            .is_err(),
            "fault {fault}"
        );
        assert!(!called.get());
    }
}

#[test]
fn live_original_revision_may_precede_later_sibling_key_updates_but_never_future() {
    let r = record();
    assert!(validate_stage(&r, &r.context, &r.context.bindings[0], 10, true, Use::Live).is_ok());
    for (generation, fresh) in [(0, true), (14, true), (10, false)] {
        assert!(validate_stage(
            &r,
            &r.context,
            &r.context.bindings[0],
            generation,
            fresh,
            Use::Live
        )
        .is_err());
    }
}

#[test]
fn closing_is_cleanup_only_even_when_a_stale_forward_fresh_flag_is_true() {
    let mut r = record();
    r.phase = Phase::Closing;
    for fresh in [false, true] {
        assert!(validate_stage(
            &r,
            &r.context,
            &r.context.bindings[0],
            10,
            fresh,
            Use::Cleanup
        )
        .is_ok());
        for use_ in [Use::Create, Use::Live] {
            assert!(
                validate_stage(&r, &r.context, &r.context.bindings[0], 10, fresh, use_).is_err()
            );
        }
    }
    for phase in [Phase::Preparing, Phase::Stopped] {
        r.phase = phase;
        assert!(validate_stage(
            &r,
            &r.context,
            &r.context.bindings[0],
            10,
            false,
            Use::Cleanup
        )
        .is_err());
    }
}

#[test]
fn native_stage_rejects_foreign_binding_context_or_unresolved_carrier_key() {
    let expected = record();
    for use_ in [Use::Create, Use::Live, Use::Cleanup] {
        let mut good = expected.clone();
        if use_ == Use::Cleanup {
            good.phase = Phase::Closing;
        }
        for i in 1..3 {
            assert!(validate_stage(
                &good,
                &good.context,
                &good.context.bindings[i],
                13,
                true,
                use_
            )
            .is_err());
        }
        let mut foreign = good.context.clone();
        foreign.provenance.network_epoch += 1;
        assert!(
            validate_stage(&good, &foreign, &good.context.bindings[0], 13, true, use_).is_err()
        );
        for phase in [
            KeyPhase::Unstarted,
            KeyPhase::CreatePending,
            KeyPhase::Captured,
            KeyPhase::DisablePending,
            KeyPhase::RestorePending,
            KeyPhase::Clean,
        ] {
            let mut r = good.clone();
            r.keys[0].phase = phase;
            assert!(
                validate_stage(&r, &good.context, &good.context.bindings[0], 13, true, use_)
                    .is_err()
            );
        }
        let mut r = good.clone();
        r.keys[0].new_key_ack = false;
        assert!(
            validate_stage(&r, &good.context, &good.context.bindings[0], 13, true, use_).is_err()
        );
        r = good.clone();
        r.keys[0].current = Value::Absent;
        assert!(
            validate_stage(&r, &good.context, &good.context.bindings[0], 13, true, use_).is_err()
        );
        r = good.clone();
        r.keys[0].pending = Some(Value::DwordZero);
        assert!(
            validate_stage(&r, &good.context, &good.context.bindings[0], 13, true, use_).is_err()
        );
    }
}
