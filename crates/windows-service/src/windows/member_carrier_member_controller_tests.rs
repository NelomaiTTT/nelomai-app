use super::*;
use std::{
    cell::Cell,
    panic::{catch_unwind, AssertUnwindSafe},
};

fn initial_noc_receipt_data(context: &crate::member_carrier_native_ownership::Context) -> Vec<u8> {
    use crate::member_carrier_native_ownership::{
        FullNativeRows, KeyPhase, KeyReceipt, Phase, Record, Role, Value,
    };
    Record {
        version: 2,
        context: context.clone(),
        generation: 1,
        phase: Phase::Preparing,
        keys: [Role::RoleCarrier, Role::MemberA, Role::MemberB].map(|role| KeyReceipt {
            role,
            phase: KeyPhase::Unstarted,
            new_key_ack: false,
            baseline: Value::Absent,
            current: Value::Absent,
            pending: None,
        }),
        native_rows: FullNativeRows::Unbound,
    }
    .encode()
    .unwrap()
}

#[test]
fn initial_noc_inventory_requires_original_receipt_and_valid_creator_data() {
    let (context, _) = never_bootstrap_full_frame();
    let mut effects = std::array::from_fn(|_| None);
    let receipt = initial_noc_receipt_data(&context);
    effects[2] = Some(receipt.clone());
    let calls = Cell::new(0);
    require_never_inventory(&context, &effects, None, |bytes| {
        assert_eq!(bytes, receipt);
        calls.set(calls.get() + 1);
        Ok(())
    })
    .unwrap();
    assert_eq!(calls.get(), 1);
    assert!(require_never_inventory(&context, &effects, None, |_| {
        Err(crate::member_carrier::CarrierError::Conflict)
    })
    .is_err());
    for index in [0, 1, 3, 4, 5, 6] {
        let mut foreign = effects.clone();
        foreign[index] = Some(vec![0]);
        assert!(require_never_inventory(&context, &foreign, None, |_| {
            panic!("other effect must deny before original receipt callback")
        })
        .is_err());
    }
    assert!(
        require_never_inventory(&context, &effects, Some(b"{}"), |_| {
            panic!("malformed Creator DATA must not reach receipt admission")
        })
        .is_err()
    );
}

#[test]
fn initial_noc_registration_retains_only_exact_weak_original_before_postflight() {
    let actual = Rc::new(vec![1]);
    let registration = InitialNoCRegistration::new();
    assert!(registration.read().is_err());
    registration
        .retain(&actual, |retained| {
            assert!(std::ptr::eq(retained, actual.as_ref()));
            let weak = registration
                .original
                .borrow()
                .as_ref()
                .unwrap()
                .upgrade()
                .unwrap();
            assert!(Rc::ptr_eq(&weak, &actual));
            assert!(!registration.acknowledged.get());
            Ok(())
        })
        .unwrap();
    assert!(Rc::ptr_eq(&registration.read().unwrap(), &actual));
    assert_eq!(Rc::strong_count(&actual), 1);
    drop(actual);
    assert!(registration.read().is_err());
    assert!(registration.retain(&Rc::new(vec![1]), |_| Ok(())).is_err());
}

#[test]
fn initial_noc_registration_error_unwind_duplicate_and_reentry_never_rearm() {
    use crate::member_carrier::CarrierError;
    for fault in 0..4 {
        let registration = InitialNoCRegistration::new();
        let actual = Rc::new(vec![1]);
        let equal_foreign = Rc::new(vec![1]);
        let result = catch_unwind(AssertUnwindSafe(|| {
            registration.retain(&actual, |_| match fault {
                0 => Err(CarrierError::Native),
                1 => panic!("lost registration postflight"),
                2 => {
                    assert!(registration.retain(&actual, |_| Ok(())).is_err());
                    Ok(()) // Swallowed reentry must still poison outer success.
                }
                _ => {
                    assert!(registration.retain(&equal_foreign, |_| Ok(())).is_err());
                    Ok(())
                }
            })
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        let retained = registration
            .original
            .borrow()
            .as_ref()
            .unwrap()
            .upgrade()
            .unwrap();
        assert!(Rc::ptr_eq(&retained, &actual));
        assert!(!Rc::ptr_eq(&retained, &equal_foreign));
        assert!(registration.read().is_err());
        assert!(registration.retain(&actual, |_| Ok(())).is_err());
    }
    let registration = InitialNoCRegistration::new();
    let actual = Rc::new(1);
    registration.retain(&actual, |_| Ok(())).unwrap();
    assert!(registration.retain(&actual, |_| Ok(())).is_err());
    assert!(registration.read().is_err());
}

#[test]
fn initial_noc_creator_data_is_context_comparison_never_receipt_authority() {
    let (context, _) = never_bootstrap_full_frame();
    // DATA fixtures use the real strict Creator parser; no native ACK is made.
    let creator = serde_json::to_vec(&serde_json::json!({
        "version": 1, "context": context,
        "process": { "pid": 51, "creation_time": 61 }
    }))
    .unwrap();
    let mut effects = std::array::from_fn(|_| None);
    require_never_inventory(&context, &effects, Some(&creator), |_| {
        panic!("Creator DATA does not require or mint receipt admission")
    })
    .unwrap();
    effects[2] = Some(initial_noc_receipt_data(&context));
    assert!(
        require_never_inventory(&context, &effects, Some(&creator), |_| {
            Err(crate::member_carrier::CarrierError::Pending)
        })
        .is_err()
    );
    for fault in 0..6 {
        let mut value: serde_json::Value = serde_json::from_slice(&creator).unwrap();
        match fault {
            0 => value["context"]["provenance"]["network_epoch"] = 8.into(),
            1 => value["context"]["intent"]["scope"]["connection_generation"] = 4.into(),
            2 => {
                value["context"]["provenance"]["runtime"]["manifest_sha256"] = "b".repeat(64).into()
            }
            3 => value["process"]["pid"] = 0.into(),
            4 => value["unexpected"] = true.into(),
            _ => value["version"] = 2.into(),
        }
        let foreign = serde_json::to_vec(&value).unwrap();
        assert!(
            require_never_inventory(&context, &effects, Some(&foreign), |_| {
                panic!("foreign Creator must deny before original receipt callback")
            })
            .is_err(),
            "fault {fault}"
        );
    }
}

#[test]
fn initial_noc_inventory_never_admits_noninitial_native_receipt_data() {
    let (context, _) = never_bootstrap_full_frame();
    let initial = initial_noc_receipt_data(&context);
    for fault in 0..9 {
        let mut value: serde_json::Value = serde_json::from_slice(&initial).unwrap();
        match fault {
            0 => value["generation"] = 2.into(),
            1 => value["phase"] = "Closing".into(),
            2 => value["context"]["provenance"]["network_epoch"] = 8.into(),
            3 => value["keys"][0]["phase"] = "CreatePending".into(),
            4 => value["keys"][1]["new_key_ack"] = true.into(),
            5 => value["keys"][2]["current"] = "DwordZero".into(),
            6 => value["keys"][0]["pending"] = "DwordZero".into(),
            7 => value["unexpected"] = true.into(),
            _ => value = serde_json::json!({}),
        }
        let effects =
            std::array::from_fn(|i| (i == 2).then(|| serde_json::to_vec(&value).unwrap()));
        assert!(
            require_never_inventory(&context, &effects, None, |_| {
                Ok(()) // External reader cannot widen the DATA predicate.
            })
            .is_err(),
            "fault {fault}"
        );
    }
}

#[test]
fn initial_noc_inventory_requires_explicit_unbound_rows_before_reader_admission() {
    let (context, _) = never_bootstrap_full_frame();
    let initial = initial_noc_receipt_data(&context);
    let effects = std::array::from_fn(|i| (i == 2).then(|| initial.clone()));
    let calls = Cell::new(0);
    require_never_inventory(&context, &effects, None, |observed| {
        assert_eq!(observed, initial);
        calls.set(calls.get() + 1);
        Ok(())
    })
    .unwrap();
    assert_eq!(calls.get(), 1);

    // FullNativeRows currently has ONLY Unbound. There is no valid Bound
    // producer/helper in native ownership; these are real unsupported wire
    // inputs, not a fabricated enum variant or native row ACK.
    for rows in [
        Some(serde_json::json!("Bound")),
        Some(serde_json::json!({"Bound": {}})),
        Some(serde_json::Value::Null),
        None,
    ] {
        let mut value: serde_json::Value = serde_json::from_slice(&initial).unwrap();
        match rows {
            Some(rows) => value["native_rows"] = rows,
            None => {
                value.as_object_mut().unwrap().remove("native_rows");
            }
        }
        let effects =
            std::array::from_fn(|i| (i == 2).then(|| serde_json::to_vec(&value).unwrap()));
        assert!(require_never_inventory(&context, &effects, None, |_| {
            calls.set(calls.get() + 1);
            Ok(())
        })
        .is_err());
        assert_eq!(calls.get(), 1, "row DATA must deny before original reader");
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault {
    Register,
    Postflight,
    LostAck,
}

#[test]
fn terminal_member_ledger_requires_every_original_generation_and_closed_started_root() {
    let history = NeverMemberHistory::default();
    verify_terminal_generation_coverage(&history, [None, None], &[]).unwrap();
    history.prepare(0).unwrap();
    verify_terminal_generation_coverage(
        &history,
        [Some(TerminalMemberRoot::Prepared(1)), None],
        &[],
    )
    .unwrap();
    history.carrier_attempted.set(true);
    history.start(0, 1).unwrap();
    assert!(verify_terminal_generation_coverage(&history, [None, None], &[]).is_err());
    assert!(verify_terminal_generation_coverage(
        &history,
        [Some(TerminalMemberRoot::Unstarted(1)), None],
        &[]
    )
    .is_err());
    verify_terminal_generation_coverage(&history, [Some(TerminalMemberRoot::Closed(1)), None], &[])
        .unwrap();
    history.retire_generation(0, 1).unwrap();
    assert!(verify_terminal_generation_coverage(&history, [None, None], &[]).is_err());
    verify_terminal_generation_coverage(&history, [None, None], &[(0, 1, 2)]).unwrap();
    history.prepare(0).unwrap();
    history.start(0, 2).unwrap();
    history.retire_generation(0, 2).unwrap();
    let chain = [(0, 2, 3), (0, 1, 2)];
    verify_terminal_generation_coverage(&history, [None, None], &chain).unwrap();
    for invalid in [
        vec![(0, 1, 2), (0, 1, 2)],
        vec![(0, 1, 3)],
        vec![(1, 1, 2)],
        vec![(0, 0, 1)],
        vec![(0, 2, 3)],
    ] {
        assert!(verify_terminal_generation_coverage(&history, [None, None], &invalid).is_err());
    }
    assert!(verify_terminal_generation_coverage(
        &history,
        [Some(TerminalMemberRoot::Prepared(2)), None],
        &chain
    )
    .is_err());
}

#[test]
fn terminal_root_disposition_denies_partial_and_unfinished_closed_postflight() {
    let (mut root, _) = root();
    root.verify_terminal_inert().unwrap();
    start(&mut root, None).unwrap();
    assert!(root.verify_terminal_inert().is_err());
    assert!(root
        .stop(
            |o| Ok((42, Owned(o.0.clone()))),
            |_| Ok(()),
            |_, _, _| Err(Fault::Postflight)
        )
        .is_err());
    assert!(root.verify_terminal_inert().is_err());
    root.stop(
        |_| panic!("no repeated Stop"),
        |_| Ok(()),
        |_, _, _| Ok::<_, Fault>(()),
    )
    .unwrap();
    root.verify_terminal_inert().unwrap();
}

struct ColdPackagePin(Rc<Cell<usize>>);
#[test]
fn cold_member_start_cannot_construct_missing_pre_c_package_and_refreshes_same_root() {
    let drops = Rc::new(Cell::new(0));
    let mut missing: ColdPackageRoot<ColdPackagePin> = ColdPackageRoot::new();
    assert!(matches!(
        missing.verify_existing(|| Ok(()), |_| panic!("no original"), Fault::LostAck),
        Err(ColdPackageError::Boundary(Fault::LostAck))
    ));
    assert!(missing.original.is_none());
    let mut root = ColdPackageRoot::new();
    root.verify(
        || Ok::<_, Fault>(()),
        || Ok(ColdPackagePin(drops.clone())),
        |_| panic!(),
    )
    .unwrap();
    let original = root.original.as_ref().unwrap() as *const _;
    let refreshed = Cell::new(false);
    root.verify_existing(
        || Ok::<_, Fault>(()),
        |pin| {
            assert_eq!(pin as *const _, original);
            refreshed.set(true);
            Ok(())
        },
        Fault::LostAck,
    )
    .unwrap();
    assert!(refreshed.get());
    assert_eq!(drops.get(), 0);
    assert!(matches!(
        root.verify_existing(|| Err(Fault::Postflight), |_| panic!(), Fault::LostAck),
        Err(ColdPackageError::Boundary(Fault::Postflight))
    ));
    assert_eq!(root.original.as_ref().unwrap() as *const _, original);
    assert!(matches!(
        root.verify_existing(|| Ok::<_, Fault>(()), |_| panic!(), Fault::LostAck),
        Err(ColdPackageError::Retired)
    ));
}
impl Drop for ColdPackagePin {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}

// Break: returning only metadata, dropping the original before postflight, or
// replacing/retrying it after a source/package error or unwind.
#[test]
fn cold_carrier_package_roots_original_before_postflight_and_refreshes_without_reconstruction() {
    let drops = Rc::new(Cell::new(0));
    let mut root = ColdPackageRoot::new();
    let auth = Cell::new(0);
    root.verify(
        || {
            auth.set(auth.get() + 1);
            Ok::<_, Fault>(())
        },
        || Ok(ColdPackagePin(drops.clone())),
        |_| panic!("new package must come from actual constructor, not refresh"),
    )
    .unwrap();
    assert_eq!(auth.get(), 2);
    let original = root.original.as_ref().unwrap() as *const _;
    let refresh = Cell::new(0);
    root.verify(
        || Ok::<_, Fault>(()),
        || panic!("same prepared origin must not reconstruct package"),
        |_| {
            refresh.set(refresh.get() + 1);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(refresh.get(), 1);
    assert_eq!(root.original.as_ref().unwrap() as *const _, original);
    assert_eq!(drops.get(), 0);
    drop(root);
    assert_eq!(drops.get(), 1); // Readonly pins have no unknown native effects.
}

#[test]
fn cold_carrier_package_keeps_original_on_failed_source_postflight_or_unwind() {
    for unwind in [false, true] {
        let drops = Rc::new(Cell::new(0));
        let mut root = ColdPackageRoot::new();
        let auth = Cell::new(0);
        let result = catch_unwind(AssertUnwindSafe(|| {
            root.verify(
                || {
                    auth.set(auth.get() + 1);
                    if auth.get() == 2 {
                        if unwind {
                            panic!("source postflight unwind");
                        }
                        return Err(Fault::Postflight);
                    }
                    Ok(())
                },
                || Ok(ColdPackagePin(drops.clone())),
                |_| panic!("refresh is not initial construction"),
            )
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert!(matches!(
                result.unwrap(),
                Err(ColdPackageError::Boundary(Fault::Postflight))
            ));
        }
        assert!(root.original.is_some());
        assert_eq!(drops.get(), 0);
        assert!(matches!(
            root.verify(
                || panic!("denied package must not read an alternate source"),
                || panic!("denied package must not replace its original"),
                |_| Ok::<_, Fault>(()),
            ),
            Err(ColdPackageError::Retired)
        ));
        drop(root);
        assert_eq!(drops.get(), 1);
    }
}

#[test]
fn cold_carrier_package_constructor_or_preflight_failure_never_creates_acceptance() {
    for fail_before in [false, true] {
        let mut root = ColdPackageRoot::<ColdPackagePin>::new();
        let constructed = Cell::new(0);
        assert!(matches!(
            root.verify(
                || if fail_before {
                    Err(Fault::Postflight)
                } else {
                    Ok(())
                },
                || {
                    constructed.set(constructed.get() + 1);
                    Err(Fault::LostAck)
                },
                |_| panic!("no original package exists"),
            ),
            Err(ColdPackageError::Boundary(_))
        ));
        assert_eq!(constructed.get(), usize::from(!fail_before));
        assert!(root.original.is_none());
        assert!(matches!(
            root.verify(
                || panic!("failed attempt must stay denied"),
                || panic!("must not retry constructor"),
                |_| Ok::<_, Fault>(()),
            ),
            Err(ColdPackageError::Retired)
        ));
    }
}

#[test]
fn cold_carrier_package_failed_refresh_or_unwind_retains_same_original_and_denies_retry() {
    for unwind in [false, true] {
        let drops = Rc::new(Cell::new(0));
        let mut root = ColdPackageRoot::new();
        root.verify(
            || Ok::<_, Fault>(()),
            || Ok(ColdPackagePin(drops.clone())),
            |_| unreachable!(),
        )
        .unwrap();
        let original = root.original.as_ref().unwrap() as *const _;
        let result = catch_unwind(AssertUnwindSafe(|| {
            root.verify(
                || Ok::<_, Fault>(()),
                || panic!("original package already retained"),
                |_| {
                    if unwind {
                        panic!("package observation unwind");
                    }
                    Err(Fault::Postflight)
                },
            )
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert_eq!(root.original.as_ref().unwrap() as *const _, original);
        assert_eq!(drops.get(), 0);
        assert!(matches!(
            root.verify(
                || panic!("cannot rearm original after refresh error"),
                || panic!("cannot replace denied package"),
                |_| Ok::<_, Fault>(()),
            ),
            Err(ColdPackageError::Retired)
        ));
    }
}

// Break: treating a missing prepared/controller lookup as original no-effect
// history, or clearing that history on a failed construction/Start/unwind.
#[test]
fn never_member_history_is_sticky_before_fallible_construction_and_start() {
    let original = Rc::new(NeverMemberHistory::default());
    original.cold().unwrap();
    original.uncaptured(1).unwrap();
    original.prepare(0).unwrap();
    assert!(original.uncaptured(0).is_err());
    assert!(original.prepare(0).is_err());
    original.cold().unwrap(); // Readonly preparation is not native Start.
    original.carrier_attempted.set(true);
    assert!(original.cold().is_err());
    original.uncaptured(1).unwrap();
    let held = original.clone();
    assert!(catch_unwind(AssertUnwindSafe(|| {
        held.start(0, 1).unwrap();
        panic!("lost native Start ACK");
    }))
    .is_err());
    drop(held);
    assert!(original.start(0, 1).is_err());
    assert!(original.uncaptured(0).is_err());
    assert!(original.cold().is_err());
    assert!(original.start(1, 1).is_err());
    assert!(original.uncaptured(1).is_err()); // Uncertain attempt cannot be erased.
    assert!(original.prepare(2).is_err());
}

// Break: permanent bool poison after genuine retirement, or resetting a slot
// by missing lookup/drop/old generation while an original Start remains live.
#[test]
fn never_member_generation_reprepares_only_after_same_closed_generation_and_never_rearms_old_start()
{
    let history = NeverMemberHistory::default();
    assert!(history.retire_generation(0, 1).is_err());
    assert_eq!(history.prepare(0).unwrap(), 1);
    history.carrier_attempted.set(true);
    history.start(0, 1).unwrap();
    assert!(history.retire_generation(0, 2).is_err());
    assert_eq!(history.retire_generation(0, 1).unwrap(), 2);
    assert!(history.retire_generation(0, 1).is_err());
    assert!(history.uncaptured(0).is_err()); // Retired is not never-created.
    assert_eq!(history.prepare(0).unwrap(), 2);
    assert!(history.start(0, 1).is_err());
    history.start(0, 2).unwrap(); // stale original did not poison new generation.
    assert!(history.start(0, 2).is_err());
    assert_eq!(history.retire_generation(0, 2).unwrap(), 3);
    assert_eq!(history.prepare(0).unwrap(), 3);
    assert!(history.cold().is_err());
    assert!(history.retire_generation(1, 1).is_err());
}

// Break: consuming an old Stop ticket after a later generation/Start, or
// treating same-slot caller generation values as an original retirement ACK.
#[test]
fn retired_member_generation_facts_deny_stale_ticket_and_new_start() {
    let history = NeverMemberHistory::default();
    assert!(history.verify_retired_generation(0, 1, 2).is_err());
    history.prepare(0).unwrap();
    history.carrier_attempted.set(true);
    history.start(0, 1).unwrap();
    history.retire_generation(0, 1).unwrap();
    history.verify_retired_generation(0, 1, 2).unwrap();
    for (index, old, next) in [(0, 0, 2), (0, 1, 3), (0, 2, 3), (1, 1, 2), (2, 1, 2)] {
        assert!(history.verify_retired_generation(index, old, next).is_err());
    }
    history.prepare(0).unwrap();
    history.verify_retired_generation(0, 1, 2).unwrap(); // readonly next prepare.
    history.start(0, 2).unwrap();
    assert!(history.verify_retired_generation(0, 1, 2).is_err());
    history.retire_generation(0, 2).unwrap();
    assert!(history.verify_retired_generation(0, 1, 2).is_err());
    history.verify_retired_generation(0, 2, 3).unwrap();
}

#[test]
fn never_member_fresh_or_closing_frame_is_exact_and_does_not_create_ack() {
    use crate::member_carrier_pair as pair;
    use nelomai_contracts::dispatcher::TunnelSlot;
    let (context, mut closing, _) = operation_fixture();
    let mut fresh = closing.clone();
    fresh.phase = pair::Phase::Fresh;
    fresh.addresses.clear();
    fresh.dns.clear();
    fresh.options = None;
    fresh.operation = None;
    fresh.pending = None;
    fresh.members = [None, None];
    fresh.validate().unwrap();
    validate_never_member_frame(&context, &fresh, TunnelSlot::B).unwrap();
    closing.phase = pair::Phase::Closing;
    closing.active = None;
    closing.operation = None;
    closing.stop_stage = 5;
    closing.pending = Some(pair::Effect::MemberStop(
        nelomai_client_tunnel::redundancy::Slot::B,
    ));
    validate_never_member_frame(&context, &closing, TunnelSlot::B).unwrap();
    assert!(validate_never_member_frame(&context, &closing, TunnelSlot::A).is_err());
    for fault in 0..4 {
        let mut bad = closing.clone();
        match fault {
            0 => bad.provenance.network_epoch += 1,
            1 => bad.stop_stage = 4,
            2 => bad.pending = None,
            _ => bad.phase = pair::Phase::Running,
        }
        assert!(validate_never_member_frame(&context, &bad, TunnelSlot::B).is_err());
    }
}

// Break: reusing the Closing decoder for an actual no-C Stopped publication,
// or accepting native history/a foreign scope merely because Pair is terminal.
#[test]
fn never_member_terminal_frame_is_separate_exact_and_requires_no_native_history() {
    use crate::member_carrier_pair as pair;
    use nelomai_contracts::dispatcher::TunnelSlot;
    let (context, mut stopped, _) = operation_fixture();
    stopped.phase = pair::Phase::Stopped;
    stopped.stop_stage = 12;
    stopped.carrier = None;
    stopped.members = [None, None];
    stopped.active = None;
    stopped.pending = None;
    stopped.operation = None;
    stopped.validate().unwrap();
    validate_never_member_terminal_frame(&context, &stopped).unwrap();
    assert!(validate_never_member_frame(&context, &stopped, TunnelSlot::B).is_err());
    for fault in 0..7 {
        let mut bad = stopped.clone();
        match fault {
            0 => bad.phase = pair::Phase::Closing,
            1 => bad.provenance.network_epoch += 1,
            2 => bad.scope.connection_generation += 1,
            3 => bad.stop_stage = 11,
            4 => {
                bad.pending = Some(pair::Effect::MemberStop(
                    nelomai_client_tunnel::redundancy::Slot::B,
                ))
            }
            5 => {
                bad.carrier = Some(crate::member_owner::InterfaceProof {
                    index: 10,
                    luid: 11,
                    guid: [1; 16],
                })
            }
            _ => bad.phase = pair::Phase::Fresh,
        }
        assert!(validate_never_member_terminal_frame(&context, &bad).is_err());
    }
    let history = NeverMemberHistory::default();
    history.prepare(0).unwrap(); // Readonly failed prepare is still cold.
    history.cold().unwrap();
    history.carrier_attempted.set(true);
    assert!(history.cold().is_err()); // Stopped JSON cannot erase attempts.
}

fn never_bootstrap_frame(
    stage: u8,
) -> (
    crate::member_carrier_native_ownership::Context,
    crate::member_carrier_pair::Record,
) {
    use crate::member_carrier_pair as pair;
    let (context, mut record, _) = operation_fixture();
    record.phase = pair::Phase::Closing;
    record.operation = None;
    record.active = None;
    record.carrier = None;
    record.network = None;
    record.stop_stage = stage;
    record.pending = Some(if stage == 9 {
        pair::Effect::NativeEmpty
    } else {
        pair::Effect::Guard
    });
    record.validate().unwrap();
    (context, record)
}

#[test]
fn never_bootstrap_native_frame_accepts_only_exact_no_c_closing9_and10() {
    for stage in [9, 10] {
        let (context, mut record) = never_bootstrap_frame(stage);
        validate_never_bootstrap_native_frame(&context, &record).unwrap();
        assert!(validate_never_member_frame(
            &context,
            &record,
            nelomai_contracts::dispatcher::TunnelSlot::A
        )
        .is_err());
        assert!(validate_never_member_terminal_frame(&context, &record).is_err());
        record.members = [None, None];
        record.addresses.clear(); // Original Fresh -> cold Closing, no C/address publication.
        record.dns.clear();
        record.options = None;
        validate_never_bootstrap_native_frame(&context, &record).unwrap();
    }
}

#[test]
fn never_bootstrap_native_frame_denies_foreign_scope_effect_history_and_guard() {
    use crate::{member_carrier_pair as pair, member_owner as owner};
    for fault in 0..16 {
        let (context, mut record) = never_bootstrap_frame(9);
        match fault {
            0 => record.scope.connection_generation += 1,
            1 => record.provenance.network_epoch += 1,
            2 => record.stop_stage = 10,
            3 => record.pending = None,
            4 => record.phase = pair::Phase::Stopped,
            5 => {
                record.carrier = Some(owner::InterfaceProof {
                    index: 7,
                    luid: 8,
                    guid: [1; 16],
                })
            }
            6 => {
                record.members[0].as_mut().unwrap().owner.proof = Some(owner::NativeProof {
                    process: owner::ProcessProof {
                        pid: 51,
                        creation_time: 61,
                    },
                    interface: owner::InterfaceProof {
                        index: 21,
                        luid: 31,
                        guid: [3; 16],
                    },
                })
            }
            7 => record.guard.permits = true,
            8 => record.operation = Some(pair::Operation::Rebind),
            9 => record.addresses = vec!["10.7.0.99/32".parse().unwrap()],
            10 => record.members[0].as_mut().unwrap().owner.phase = owner::Phase::Stopped,
            11 => {
                record.members[0].as_mut().unwrap().owner.retired_proof = Some(owner::NativeProof {
                    process: owner::ProcessProof {
                        pid: 51,
                        creation_time: 61,
                    },
                    interface: owner::InterfaceProof {
                        index: 21,
                        luid: 31,
                        guid: [3; 16],
                    },
                })
            }
            12 => {
                record.members[0]
                    .as_mut()
                    .unwrap()
                    .owner
                    .previous_config_sha256 = Some([7; 32])
            }
            13 => record.guard.assigned_sublayer_weight = Some(11),
            14 => record.scope.runtime_generation += 1,
            _ => {
                record.members[0]
                    .as_mut()
                    .unwrap()
                    .owner
                    .intent
                    .scope
                    .connection_generation += 1
            }
        }
        assert!(
            validate_never_bootstrap_native_frame(&context, &record).is_err(),
            "fault {fault}"
        );
    }
}

#[test]
fn never_bootstrap_native_frame_cannot_cross_other_cleanup_stages_or_origin_bindings() {
    use crate::member_carrier_native_ownership::Role;
    for stage in 0..=12 {
        let (context, mut record) = never_bootstrap_frame(9);
        record.stop_stage = stage;
        if stage != 9 {
            assert!(validate_never_bootstrap_native_frame(&context, &record).is_err());
        }
    }
    let (mut context, record) = never_bootstrap_frame(9);
    context.bindings[1].role = Role::MemberB;
    assert!(validate_never_bootstrap_native_frame(&context, &record).is_err());
    let history = NeverMemberHistory::default();
    history.started[1].set(true);
    assert!(
        verify_never_bootstrap_reads(&history, &context, &record, || panic!(
            "started ledger must not query native absence"
        ))
        .is_err()
    );
}

#[test]
fn never_bootstrap_reads_use_actual_sticky_ledger_and_recheck_after_each_read() {
    let (context, record) = never_bootstrap_frame(9);
    let history = NeverMemberHistory::default();
    history.prepare(1).unwrap(); // Readonly prepared origin is not a native attempt.
    let reads = Cell::new(0);
    verify_never_bootstrap_reads(&history, &context, &record, || {
        reads.set(reads.get() + 1);
        Ok(())
    })
    .unwrap();
    assert_eq!(reads.get(), 2);
    let failed = verify_never_bootstrap_reads(&history, &context, &record, || {
        history.carrier_attempted.set(true); // Unknown partial C cannot erase its original ledger.
        Ok(())
    });
    assert!(failed.is_err());
    assert!(
        verify_never_bootstrap_reads(&history, &context, &record, || panic!(
            "partial-C must not enter cold reads"
        ))
        .is_err()
    );
}

#[test]
fn never_bootstrap_read_failures_and_unwind_never_create_absence_success() {
    use crate::member_carrier::CarrierError;
    let (context, record) = never_bootstrap_frame(10);
    let history = NeverMemberHistory::default();
    for cut in [1, 2] {
        let count = Cell::new(0);
        let result = verify_never_bootstrap_reads(&history, &context, &record, || {
            count.set(count.get() + 1);
            if count.get() == cut {
                Err(CarrierError::Native)
            } else {
                Ok(())
            }
        });
        assert_eq!(result, Err(CarrierError::Native));
        assert_eq!(count.get(), cut);
    }
    assert!(catch_unwind(AssertUnwindSafe(|| {
        verify_never_bootstrap_reads(&history, &context, &record, || {
            panic!("native readonly boundary unwind")
        })
    }))
    .is_err());
    history.cold().unwrap(); // A readonly failure does not manufacture effect/Stop history.
}

fn never_bootstrap_full_frame() -> (
    crate::member_carrier_native_ownership::Context,
    crate::member_carrier_pair::Record,
) {
    let (context, mut record) = never_bootstrap_frame(9);
    record.stop_stage = 12;
    record.pending = Some(crate::member_carrier_pair::Effect::FullEmpty);
    record.validate().unwrap();
    (context, record)
}

#[test]
fn never_bootstrap_full_reads_are_disjoint_closing12_not_nativeempty_or_terminal() {
    use crate::member_carrier_pair as pair;
    let (context, mut record) = never_bootstrap_full_frame();
    let history = NeverMemberHistory::default();
    history.prepare(0).unwrap(); // Original readonly preparation has no native effects.
    let reads = Cell::new(0);
    verify_never_bootstrap_full_reads(&history, &context, &record, || {
        reads.set(reads.get() + 1);
        Ok(())
    })
    .unwrap();
    assert_eq!(reads.get(), 2);
    assert!(validate_never_bootstrap_native_frame(&context, &record).is_err());
    assert!(validate_never_member_terminal_frame(&context, &record).is_err());
    record.members = [None, None];
    record.addresses.clear();
    record.dns.clear();
    record.options = None;
    verify_never_bootstrap_full_reads(&history, &context, &record, || Ok(())).unwrap();
    for (stage, pending, phase) in [
        (9, Some(pair::Effect::NativeEmpty), pair::Phase::Closing),
        (10, Some(pair::Effect::Guard), pair::Phase::Closing),
        (12, None, pair::Phase::Stopped),
        (12, Some(pair::Effect::FullEmpty), pair::Phase::Running),
    ] {
        let mut bad = record.clone();
        bad.stop_stage = stage;
        bad.pending = pending;
        bad.phase = phase;
        assert!(
            verify_never_bootstrap_full_reads(&history, &context, &bad, || panic!(
                "wrong-stage frames must not query native absence"
            ))
            .is_err()
        );
    }
}

#[test]
fn never_bootstrap_full_denies_foreign_origin_native_history_guard_and_unknown_reads() {
    use crate::{member_carrier::CarrierError, member_carrier_pair as pair, member_owner as owner};
    for fault in 0..14 {
        let (mut context, mut record) = never_bootstrap_full_frame();
        match fault {
            0 => record.scope.runtime_generation += 1,
            1 => record.provenance.network_epoch += 1,
            2 => record.pending = None,
            3 => record.operation = Some(pair::Operation::Rebind),
            4 => record.guard.permits = true,
            5 => record.guard.assigned_sublayer_weight = Some(11),
            6 => record.addresses = vec!["10.7.0.99/32".parse().unwrap()],
            7 => {
                record.carrier = Some(owner::InterfaceProof {
                    index: 7,
                    luid: 8,
                    guid: [1; 16],
                })
            }
            8 => record.members[0].as_mut().unwrap().owner.phase = owner::Phase::Stopped,
            9 => {
                record.members[0]
                    .as_mut()
                    .unwrap()
                    .owner
                    .previous_config_sha256 = Some([7; 32])
            }
            10 => {
                record.members[0].as_mut().unwrap().owner.proof = Some(owner::NativeProof {
                    process: owner::ProcessProof {
                        pid: 51,
                        creation_time: 61,
                    },
                    interface: owner::InterfaceProof {
                        index: 21,
                        luid: 31,
                        guid: [3; 16],
                    },
                })
            }
            11 => context.bindings[1].role = crate::member_carrier_native_ownership::Role::MemberB,
            12 => {
                record.members[0]
                    .as_mut()
                    .unwrap()
                    .owner
                    .intent
                    .scope
                    .connection_generation += 1
            }
            _ => {
                record.addresses.clear();
                record.dns.push("8.8.8.8".parse().unwrap());
            }
        }
        assert!(
            verify_never_bootstrap_full_reads(
                &NeverMemberHistory::default(),
                &context,
                &record,
                || panic!("foreign frame must not query native absence")
            )
            .is_err(),
            "fault {fault}"
        );
    }
    let (context, record) = never_bootstrap_full_frame();
    for cut in [1, 2] {
        let history = NeverMemberHistory::default();
        let reads = Cell::new(0);
        assert_eq!(
            verify_never_bootstrap_full_reads(&history, &context, &record, || {
                reads.set(reads.get() + 1);
                if reads.get() == cut {
                    Err(CarrierError::Native)
                } else {
                    Ok(())
                }
            }),
            Err(CarrierError::Native)
        );
        assert_eq!(reads.get(), cut);
        history.cold().unwrap();
    }
    for index in 0..7 {
        let records = std::array::from_fn(|i| (i == index).then(|| vec![0]));
        assert!(verify_never_bootstrap_full_reads(
            &NeverMemberHistory::default(),
            &context,
            &record,
            || require_never_native_records(&records)
        )
        .is_err());
    }
}

#[test]
fn never_bootstrap_full_rechecks_actual_ledger_and_never_erases_partial_c_or_unwind() {
    let (context, record) = never_bootstrap_full_frame();
    for started_member in [None, Some(0), Some(1)] {
        let history = NeverMemberHistory::default();
        let reads = Cell::new(0);
        assert!(
            verify_never_bootstrap_full_reads(&history, &context, &record, || {
                reads.set(reads.get() + 1);
                if let Some(index) = started_member {
                    history.started[index].set(true);
                } else {
                    history.carrier_attempted.set(true);
                }
                Ok(())
            })
            .is_err()
        );
        assert_eq!(reads.get(), 1);
        assert!(
            verify_never_bootstrap_full_reads(&history, &context, &record, || panic!(
                "unknown partial must not infer native absence"
            ))
            .is_err()
        );
    }
    let history = NeverMemberHistory::default();
    assert!(catch_unwind(AssertUnwindSafe(|| {
        verify_never_bootstrap_full_reads(&history, &context, &record, || {
            panic!("readonly native boundary unwind")
        })
    }))
    .is_err());
    history.cold().unwrap();
}

// OS open is the fake boundary, not a successful native owner or receipt.
#[test]
fn never_member_file_absence_rechecks_original_parent_and_rejects_creation_between_reads() {
    let parents = Cell::new(0);
    let reads = Cell::new(0);
    verify_absent_file_reads(
        || {
            parents.set(parents.get() + 1);
            Ok::<_, Fault>(())
        },
        || {
            reads.set(reads.get() + 1);
            Ok(false)
        },
        || Fault::Postflight,
    )
    .unwrap();
    assert_eq!((parents.get(), reads.get()), (3, 2));
    let reads = Cell::new(0);
    assert!(verify_absent_file_reads(
        || Ok::<_, Fault>(()),
        || {
            reads.set(reads.get() + 1);
            Ok(reads.get() == 2)
        },
        || Fault::Postflight,
    )
    .is_err());
    assert!(verify_absent_file_reads(
        || Err::<(), _>(Fault::Postflight),
        || Ok(false),
        || Fault::Postflight,
    )
    .is_err());
    assert!(verify_absent_file_reads(
        || Ok::<_, Fault>(()),
        || Err(Fault::LostAck),
        || Fault::Postflight,
    )
    .is_err());
}

// Only native registry read boundary is doubled; actual policy reads exact
// parent, child and values. This production reader has no effect methods.
struct NeverRegistry {
    present: bool,
    value: crate::member_carrier_native_ownership::NativeValue,
    name_reads: Cell<usize>,
    drift_parent: bool,
    foreign_child: bool,
    unknown: bool,
}
impl NeverRegistryRead for NeverRegistry {
    type Handle = bool; // false = parent, true = child at fake OS boundary.
    fn interfaces(&mut self) -> crate::member_carrier::Result<bool> {
        Ok(false)
    }
    fn name(&mut self, child: &bool) -> crate::member_carrier::Result<String> {
        let parent = r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces";
        self.name_reads.set(self.name_reads.get() + 1);
        if !child && self.drift_parent && self.name_reads.get() > 1 {
            return Ok("foreign".into());
        }
        if *child {
            Ok(format!(
                "{parent}\\{}",
                if self.foreign_child {
                    "{foreign}"
                } else {
                    "{02020202-0202-0202-0202-020202020202}"
                }
            ))
        } else {
            Ok(parent.into())
        }
    }
    fn open(&mut self, parent: &bool, child: &str) -> crate::member_carrier::Result<Option<bool>> {
        assert!(!parent);
        assert_eq!(child, "{02020202-0202-0202-0202-020202020202}");
        if self.unknown {
            return Err(crate::member_carrier::CarrierError::Pending);
        }
        Ok(self.present.then_some(true))
    }
    fn value(
        &mut self,
        child: &bool,
    ) -> crate::member_carrier::Result<crate::member_carrier_native_ownership::NativeValue> {
        assert!(*child);
        Ok(self.value.clone())
    }
}
#[test]
fn never_member_key_read_requires_exact_absence_or_disabled_facts_without_mutation() {
    use crate::member_carrier_native_ownership::NativeValue;
    let (context, _, _) = operation_fixture();
    let mut registry = NeverRegistry {
        present: false,
        value: NativeValue::Absent,
        name_reads: Cell::new(0),
        drift_parent: false,
        foreign_child: false,
        unknown: false,
    };
    inspect_never_member_key(&mut registry, &context, 1, NeverKeyFact::Absent).unwrap();
    registry.present = true;
    registry.value = NativeValue::Dword(0);
    inspect_never_member_key(&mut registry, &context, 1, NeverKeyFact::Disabled).unwrap();
    assert!(inspect_never_member_key(&mut registry, &context, 1, NeverKeyFact::Absent).is_err());
    for fault in 0..5 {
        registry.name_reads.set(0);
        registry.drift_parent = fault == 0;
        registry.foreign_child = fault == 1;
        registry.unknown = fault == 2;
        registry.value = if fault == 3 {
            NativeValue::Dword(1)
        } else if fault == 4 {
            NativeValue::Other {
                kind: 1,
                bytes: vec![0; 4],
            }
        } else {
            NativeValue::Dword(0)
        };
        assert!(
            inspect_never_member_key(&mut registry, &context, 1, NeverKeyFact::Disabled).is_err()
        );
    }
}

#[test]
fn never_member_all_native_record_kinds_must_be_absent_not_missing_receipt_alone() {
    let none = std::array::from_fn(|_| None);
    require_never_native_records(&none).unwrap();
    for kind in 0..7 {
        let mut records = none.clone();
        records[kind] = Some(vec![0]);
        assert!(require_never_native_records(&records).is_err());
    }
}

#[test]
fn unknown_native_or_journal_outcome_remains_pending_not_completion() {
    use crate::member_carrier::CarrierError;
    assert_eq!(pending_unknown(CarrierError::Native), CarrierError::Pending);
    assert_eq!(
        pending_unknown(CarrierError::Journal),
        CarrierError::Pending
    );
    assert_eq!(
        pending_unknown(CarrierError::Conflict),
        CarrierError::Conflict
    );
}

#[test]
fn rebound_record_requires_exact_old_origin_interface_and_new_process() {
    use crate::{member_carrier_pair as pair, member_owner as owner};
    use nelomai_client_tunnel::redundancy::Slot;
    let (context, mut expected, _) = operation_fixture();
    let old = owner::NativeProof {
        process: owner::ProcessProof {
            pid: 51,
            creation_time: 61,
        },
        interface: owner::InterfaceProof {
            index: 21,
            luid: 31,
            guid: [2; 16],
        },
    };
    expected.phase = pair::Phase::Running;
    expected.active = Some(Slot::A);
    expected.operation = Some(pair::Operation::Rebind);
    expected.pending = Some(pair::Effect::Rebind(Slot::A));
    expected.network = Some(pair::NetworkState {
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
    let prior = expected.members[0].as_mut().unwrap();
    prior.owner.phase = owner::Phase::Running;
    prior.owner.proof = Some(old);
    let prior = prior.owner.clone();
    let mut next = prior.clone();
    next.retired_proof = Some(old);
    next.proof.as_mut().unwrap().process.creation_time += 1;
    validate_rebound_record(&context, &expected, &prior, &next).unwrap();
    for fault in 0..7 {
        let mut wrong = next.clone();
        match fault {
            0 => wrong.retired_proof = None,
            1 => wrong.proof.as_mut().unwrap().process = old.process,
            2 => wrong.proof.as_mut().unwrap().interface.index += 1,
            3 => wrong.intent.scope.connection_generation += 1,
            4 => wrong.intent.config_sha256 = [5; 32],
            5 => wrong.phase = owner::Phase::Prepared,
            _ => wrong.proof.as_mut().unwrap().interface.luid += 1,
        }
        assert!(validate_rebound_record(&context, &expected, &prior, &wrong).is_err());
    }
}

fn operation_fixture() -> (
    crate::member_carrier_native_ownership::Context,
    crate::member_carrier_pair::Record,
    crate::member_owner::Intent,
) {
    use crate::{
        member_carrier::{Intent as CarrierIntent, Provenance},
        member_carrier_native_ownership::{Binding, Context, Role},
        member_carrier_pair as pair, member_owner as owner,
    };
    use nelomai_contracts::{
        dispatcher::{EngineIdentity, TunnelSlot},
        RuntimeSlot,
    };
    let scope = nelomai_client_tunnel::redundancy::SessionScope {
        runtime: RuntimeSlot::Stable,
        runtime_generation: 2,
        session_id: "11111111-1111-4111-8111-111111111111".into(),
        connection_generation: 3,
    };
    let context = Context {
        intent: CarrierIntent {
            scope: scope.clone(),
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
        bindings: std::array::from_fn(|n| Binding {
            role: [Role::RoleCarrier, Role::MemberA, Role::MemberB][n],
            guid: [(n + 1) as u8; 16],
            name: ["carrier-c", "member-a", "member-b"][n].into(),
            registry_path: format!(
                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{{{0:02x}{0:02x}{0:02x}{0:02x}-{0:02x}{0:02x}-{0:02x}{0:02x}-{0:02x}{0:02x}-{0:02x}{0:02x}{0:02x}{0:02x}{0:02x}{0:02x}}}",
                n + 1
            ),
        }),
    };
    let intent = owner::Intent {
        scope: scope.clone(),
        slot: TunnelSlot::A,
        transport: nelomai_client_tunnel::TunnelTransport::WireGuard,
        engine: crate::test_engine_path("engine.exe"),
        config_sha256: [9; 32],
    };
    let expected = pair::Record {
        version: 2,
        scope: scope.clone(),
        provenance: context.provenance.clone(),
        revision: 2,
        phase: pair::Phase::Starting,
        addresses: context.intent.addresses.clone(),
        dns: vec!["1.1.1.1".parse().unwrap()],
        carrier: Some(owner::InterfaceProof {
            index: 10,
            luid: 11,
            guid: [1; 16],
        }),
        members: [
            Some(pair::MemberState {
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
                peer: [2; 32],
            }),
            None,
        ],
        active: None,
        options: None,
        guard: crate::member_carrier_guard::Model::empty(scope).unwrap(),
        pending_guard: None,
        pending: Some(pair::Effect::MemberStart(
            nelomai_client_tunnel::redundancy::Slot::A,
        )),
        network: None,
        stop_stage: 0,
        operation: Some(pair::Operation::Start(
            nelomai_client_tunnel::redundancy::Slot::A,
        )),
    };
    expected.validate().unwrap();
    (context, expected, intent)
}
#[test]
fn exact_current_start_and_closing_stop_are_the_only_admitted_operations() {
    let (context, mut expected, intent) = operation_fixture();
    assert!(
        validate_member_operation(&context, &expected, &intent, MemberOperation::Start).is_ok()
    );
    assert!(
        validate_member_operation(&context, &expected, &intent, MemberOperation::Stop).is_err()
    );
    expected.phase = crate::member_carrier_pair::Phase::Closing;
    expected.operation = None;
    expected.stop_stage = 4;
    expected.pending = Some(crate::member_carrier_pair::Effect::MemberStop(
        nelomai_client_tunnel::redundancy::Slot::A,
    ));
    assert!(validate_member_operation(&context, &expected, &intent, MemberOperation::Stop).is_ok());
    expected.stop_stage = 5;
    assert!(
        validate_member_operation(&context, &expected, &intent, MemberOperation::Stop).is_err()
    );
}

#[test]
fn controller_retirement_accepts_only_exact_running_target_other_active() {
    use crate::{member_carrier_pair as pair, member_owner as owner};
    use nelomai_client_tunnel::redundancy::Slot;
    let (c, mut r, intent) = operation_fixture();
    r.members[0].as_mut().unwrap().owner.phase = owner::Phase::Running;
    let proof = owner::NativeProof {
        interface: owner::InterfaceProof {
            index: 12,
            luid: 13,
            guid: [2; 16],
        },
        process: owner::ProcessProof {
            pid: 14,
            creation_time: 15,
        },
    };
    r.members[0].as_mut().unwrap().owner.proof = Some(proof);
    let mut other = r.members[0].clone().unwrap();
    other.owner.intent.slot = nelomai_contracts::dispatcher::TunnelSlot::B;
    other.owner.proof.as_mut().unwrap().interface = owner::InterfaceProof {
        index: 16,
        luid: 17,
        guid: [3; 16],
    };
    other.owner.proof.as_mut().unwrap().process.pid = 18;
    other.lease_id = "33333333-3333-4333-8333-333333333333".into();
    r.members[1] = Some(other);
    r.phase = pair::Phase::Running;
    r.active = Some(Slot::B);
    r.operation = Some(pair::Operation::Retire(Slot::A));
    r.pending = Some(pair::Effect::MemberStop(Slot::A));
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
    validate_member_operation(&c, &r, &intent, MemberOperation::Retire).unwrap();
    let running = &r.members[0].as_ref().unwrap().owner;
    let mut rebind = r.clone();
    rebind.operation = Some(pair::Operation::Rebind);
    rebind.pending = Some(pair::Effect::Rebind(Slot::A));
    validate_rebind_operation(&c, &rebind, &intent).unwrap();
    assert!(validate_rebind_operation(&c, &r, &intent).is_err());
    rebind.pending = Some(pair::Effect::Rebind(Slot::B));
    assert!(validate_rebind_operation(&c, &rebind, &intent).is_err());
    validate_original_observation(&c, &r, running, &(intent.clone(), proof)).unwrap();
    let mut replacement = proof;
    replacement.process.creation_time += 1;
    assert!(
        validate_original_observation(&c, &r, running, &(intent.clone(), replacement)).is_err()
    );
    let mut changed_pair = r.clone();
    changed_pair.members[0].as_mut().unwrap().owner.proof = Some(replacement);
    assert!(
        validate_original_observation(&c, &changed_pair, running, &(intent.clone(), proof))
            .is_err()
    );
    let history = super::super::member_carrier_members::ClosedMemberBinding {
        intent: intent.clone(),
        proof,
    };
    validate_retirement_history(&c, &r, &intent, &history).unwrap();
    for fault in 0..4 {
        let mut foreign = history.clone();
        match fault {
            0 => foreign.proof.interface.luid += 1,
            1 => foreign.proof.process.creation_time += 1,
            2 => foreign.intent.scope.connection_generation += 1,
            _ => foreign.intent.config_sha256 = [8; 32],
        }
        assert!(validate_retirement_history(&c, &r, &intent, &foreign).is_err());
    }
    assert!(validate_member_operation(&c, &r, &intent, MemberOperation::Stop).is_err());
    for fault in 0..5 {
        let mut wrong = r.clone();
        match fault {
            0 => wrong.active = Some(Slot::A),
            1 => wrong.operation = Some(pair::Operation::Retire(Slot::B)),
            2 => wrong.phase = pair::Phase::Closing,
            3 => wrong.pending = Some(pair::Effect::ReleaseProbes),
            _ => wrong.stop_stage = 4,
        }
        assert!(validate_member_operation(&c, &wrong, &intent, MemberOperation::Retire).is_err());
    }
}
#[test]
fn stale_scope_runtime_and_connection_generations_never_authorize_start() {
    let (context, expected, intent) = operation_fixture();
    for runtime in [true, false] {
        let mut changed = context.clone();
        if runtime {
            changed.intent.scope.runtime_generation += 1;
        } else {
            changed.intent.scope.connection_generation += 1;
        }
        assert!(
            validate_member_operation(&changed, &expected, &intent, MemberOperation::Start)
                .is_err()
        );
    }
    let mut changed = context.clone();
    changed.intent.scope.session_id = "33333333-3333-4333-8333-333333333333".into();
    assert!(
        validate_member_operation(&changed, &expected, &intent, MemberOperation::Start).is_err()
    );
}
#[test]
fn changed_boot_epoch_runtime_or_native_intent_cannot_substitute_for_original() {
    let (context, expected, intent) = operation_fixture();
    for n in 0..3 {
        let mut changed = context.clone();
        match n {
            0 => changed.provenance.boot_id = [7; 16],
            1 => changed.provenance.network_epoch += 1,
            _ => changed.provenance.runtime.manifest_sha256 = "b".repeat(64),
        }
        assert!(
            validate_member_operation(&changed, &expected, &intent, MemberOperation::Start)
                .is_err()
        );
    }
    let mut different = intent.clone();
    different.config_sha256 = [10; 32];
    assert!(
        validate_member_operation(&context, &expected, &different, MemberOperation::Start).is_err()
    );
    different = intent;
    different.slot = nelomai_contracts::dispatcher::TunnelSlot::B;
    assert!(
        validate_member_operation(&context, &expected, &different, MemberOperation::Start).is_err()
    );
}

#[test]
fn precreation_rejects_mismatched_generation_scope_and_other_role_receipt() {
    use crate::member_carrier_native_ownership::{
        FullNativeRows, KeyPhase, KeyReceipt, Phase, Record, Role, Value,
    };
    use nelomai_contracts::dispatcher::TunnelSlot;
    let (context, _, _) = operation_fixture();
    let current = Record {
        version: 2,
        context: context.clone(),
        generation: 10,
        phase: Phase::Preparing,
        keys: std::array::from_fn(|n| KeyReceipt {
            role: [Role::RoleCarrier, Role::MemberA, Role::MemberB][n],
            phase: KeyPhase::Disabled,
            new_key_ack: true,
            baseline: Value::Absent,
            current: Value::DwordZero,
            pending: None,
        }),
        native_rows: FullNativeRows::Unbound,
    };
    current.encode().unwrap();
    assert!(validate_member_precreation(
        &context,
        &current,
        &current,
        &context.bindings[1],
        TunnelSlot::A
    )
    .is_ok());
    for n in 0..4 {
        let mut borrowed = current.clone();
        match n {
            0 => borrowed.generation += 1,
            1 => borrowed.context.intent.scope.connection_generation += 1,
            2 => borrowed.context.provenance.network_epoch += 1,
            _ => borrowed.phase = Phase::Closing,
        }
        assert!(validate_member_precreation(
            &context,
            &current,
            &borrowed,
            &context.bindings[1],
            TunnelSlot::A
        )
        .is_err());
    }
    for index in [0, 2] {
        assert!(validate_member_precreation(
            &context,
            &current,
            &current,
            &context.bindings[index],
            TunnelSlot::A
        )
        .is_err());
    }
    let mut no_ack = current.clone();
    no_ack.keys[1].new_key_ack = false;
    assert!(validate_member_precreation(
        &context,
        &no_ack,
        &no_ack,
        &context.bindings[1],
        TunnelSlot::A
    )
    .is_err());
}
struct Owned(Rc<Cell<usize>>);

// Break: treating unsaved next as current original authority, or requiring its
// not-yet-returned Prepared member before actual prepare_state can run.
#[test]
fn unsaved_prepare_proposal_is_compared_to_original_fresh_not_minted_as_ack() {
    use crate::member_carrier_pair as pair;
    let (context, mut proposal, intent) = operation_fixture();
    proposal.members = [None, None];
    proposal.carrier = None;
    proposal.pending = None;
    let mut fresh = proposal.clone();
    fresh.phase = pair::Phase::Fresh;
    fresh.operation = None;
    fresh.addresses.clear();
    fresh.dns.clear();
    fresh.options = None;
    fresh.validate().unwrap();
    proposal.validate().unwrap();
    validate_preparation_proposal(&context, &fresh, &proposal, &intent).unwrap();
    for fault in 0..6 {
        let mut changed = proposal.clone();
        match fault {
            0 => changed.revision += 1,
            1 => changed.pending = Some(pair::Effect::CarrierReady),
            2 => changed.members[0] = operation_fixture().1.members[0].clone(),
            3 => changed.provenance.network_epoch += 1,
            4 => changed.scope.connection_generation += 1,
            _ => {
                changed.operation = Some(pair::Operation::Start(
                    nelomai_client_tunnel::redundancy::Slot::B,
                ))
            }
        }
        assert!(validate_preparation_proposal(&context, &fresh, &changed, &intent).is_err());
    }
    assert!(validate_preparation_proposal(&context, &proposal, &proposal, &intent).is_err());
}

// Break: creating/adopting a second owner, overwriting an existing slot, or
// discarding the original after failed post-attachment validation/unwind.
#[test]
fn readonly_prepared_owner_transfers_once_and_is_rooted_before_fallible_attach() {
    let drops = Rc::new(Cell::new(0));
    let mut prepared = PreparedRoot::new(Owned(drops.clone()));
    let mut attached = None;
    assert_eq!(
        prepared.attach(&mut attached, |o| o, |_| Err(Fault::Register)),
        Err(RootError::Operation(Fault::Register))
    );
    assert!(prepared.owner.is_none());
    assert!(attached.is_some());
    assert_eq!(drops.get(), 0);
    assert_eq!(
        prepared.attach(&mut attached, |o| o, |_| Ok::<_, Fault>(())),
        Err(RootError::Retired)
    );
    drop(attached);
    assert_eq!(drops.get(), 1);

    let mut prepared = PreparedRoot::new(Owned(drops.clone()));
    let mut occupied = Some(Owned(drops.clone()));
    assert_eq!(
        prepared.attach(&mut occupied, |o| o, |_| Ok::<_, Fault>(())),
        Err(RootError::Retired)
    );
    assert!(prepared.owner.is_some());
    let mut attached = None;
    assert!(catch_unwind(AssertUnwindSafe(|| {
        let _: Result<(), RootError<Fault>> =
            prepared.attach(&mut attached, |o| o, |_| panic!("attach postflight"));
    }))
    .is_err());
    assert!(attached.is_some());
    assert!(prepared.owner.is_none());
    assert_eq!(drops.get(), 1);
}

fn live_preparation_fixture() -> (
    crate::member_carrier_native_ownership::Context,
    crate::member_carrier_pair::Record,
    crate::member_owner::Intent,
) {
    use crate::{member_carrier_pair as pair, member_owner as owner};
    let (context, mut current, mut reserve) = operation_fixture();
    current.phase = pair::Phase::Running;
    current.active = Some(nelomai_client_tunnel::redundancy::Slot::A);
    current.pending = None;
    current.operation = None;
    let primary = current.members[0].as_mut().unwrap();
    primary.owner.phase = owner::Phase::Running;
    primary.owner.proof = Some(owner::NativeProof {
        process: owner::ProcessProof {
            pid: 50,
            creation_time: 51,
        },
        interface: owner::InterfaceProof {
            index: 12,
            luid: 13,
            guid: [2; 16],
        },
    });
    current.network = Some(pair::NetworkState {
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
    reserve.slot = nelomai_contracts::dispatcher::TunnelSlot::B;
    reserve.config_sha256 = [19; 32]; // A different peer/endpoint profile is valid.
    current.validate().unwrap();
    (context, current, reserve)
}

// Break: requiring Fresh for live Attach, or importing an unsaved Attach/member
// publication instead of comparing prepare_state's unchanged Running clone.
#[test]
fn live_prepare_accepts_only_unchanged_running_clone_before_attach_publication() {
    use crate::member_carrier_pair as pair;
    let (context, current, intent) = live_preparation_fixture();
    validate_live_preparation_proposal(&context, &current, &current, &intent).unwrap();
    assert!(validate_preparation_proposal(&context, &current, &current, &intent).is_err());
    for fault in 0..10 {
        let mut proposed = current.clone();
        match fault {
            0 => proposed.revision += 1,
            1 => {
                proposed.operation = Some(pair::Operation::Attach(
                    nelomai_client_tunnel::redundancy::Slot::B,
                ))
            }
            2 => {
                proposed.pending = Some(pair::Effect::MemberStart(
                    nelomai_client_tunnel::redundancy::Slot::B,
                ))
            }
            3 => proposed.members[1] = proposed.members[0].clone(),
            4 => proposed.phase = pair::Phase::Starting,
            5 => proposed.members[0].as_mut().unwrap().endpoint = "192.0.2.99".parse().unwrap(),
            6 => proposed.provenance.network_epoch += 1,
            7 => proposed.scope.connection_generation += 1,
            8 => proposed.dns = vec!["9.9.9.9".parse().unwrap()],
            _ => proposed.network = None,
        }
        assert!(
            validate_live_preparation_proposal(&context, &current, &proposed, &intent).is_err()
        );
    }
    let mut primary_intent = intent.clone();
    primary_intent.slot = nelomai_contracts::dispatcher::TunnelSlot::A;
    assert!(
        validate_live_preparation_proposal(&context, &current, &current, &primary_intent).is_err()
    );
    let mut foreign_context = context.clone();
    foreign_context.provenance.network_epoch += 1;
    assert!(
        validate_live_preparation_proposal(&foreign_context, &current, &current, &intent).is_err()
    );
    let mut busy = current.clone();
    busy.operation = Some(pair::Operation::Rebind);
    assert!(validate_live_preparation_proposal(&context, &busy, &busy, &intent).is_err());
}

// Break: accepting historical target identity or a same-NIC/different-process
// record without the remaining controller's actual original read.
#[test]
fn live_prepare_requires_original_other_process_c_and_target_native_absence() {
    let (context, current, intent) = live_preparation_fixture();
    let owner = &current.members[0].as_ref().unwrap().owner;
    let other = (owner.intent.clone(), owner.proof.unwrap());
    let members = [Some(other.1.interface), None];
    validate_live_preparation_observation(
        &context,
        &current,
        &intent,
        current.carrier,
        members,
        [false; 2],
        &other,
    )
    .unwrap();
    for fault in 0..7 {
        let (mut c, mut m, mut closed, mut actual) =
            (current.carrier, members, [false; 2], other.clone());
        match fault {
            0 => c = None,
            1 => c.as_mut().unwrap().luid += 1,
            2 => m[0] = None,
            3 => {
                m[1] = Some(crate::member_owner::InterfaceProof {
                    index: 60,
                    luid: 61,
                    guid: [3; 16],
                })
            }
            4 => closed[1] = true,
            5 => closed[0] = true,
            _ => actual.1.process.creation_time += 1,
        }
        assert!(validate_live_preparation_observation(
            &context, &current, &intent, c, m, closed, &actual
        )
        .is_err());
    }
}

// Break: attaching a preparation to a foreign/replaced Source or preserving it
// solely through an ownership cycle when the actor's original Source is lost.
#[test]
fn live_prepare_source_registration_is_nonowning_and_never_accepts_equal_replacement() {
    let original = Rc::new(17);
    let registered = PreparedSourceRegistration::from_original(&original);
    assert!(registered.verify(&original));
    assert_eq!(Rc::strong_count(&original), 1);
    assert!(!registered.verify(&Rc::new(17)));
    drop(original);
    assert!(!registered.verify(&Rc::new(17)));
}

// Break: rejecting genuine initial Start for lack of a replacement ticket, or
// treating a prepared/cold/reused generation as actual initial Running lineage.
#[test]
fn initial_started_ledger_requires_actual_first_prepared_and_start_attempt() {
    let history = NeverMemberHistory::default();
    assert!(history.verify_initial_started(0, 1).is_err());
    history.prepare(0).unwrap();
    assert!(history.verify_initial_started(0, 1).is_err());
    history.carrier_attempted.set(true);
    assert!(history.verify_initial_started(0, 1).is_err());
    history.start(0, 1).unwrap();
    history.verify_initial_started(0, 1).unwrap();
    assert!(history.verify_initial_started(1, 1).is_err());
    assert!(history.verify_initial_started(0, 0).is_err());
    assert!(history.verify_initial_started(0, 2).is_err());
    history.retire_generation(0, 1).unwrap();
    history.prepare(0).unwrap();
    history.start(0, 2).unwrap();
    assert!(history.verify_initial_started(0, 2).is_err());
    assert!(history.verify_initial_started(0, 1).is_err());
}

// Break: adopting equal-valued original/source aliases or keeping a reverse
// Source/member/cap/Source strong cycle. The actor owns independent Source.
#[test]
fn initial_started_origin_keeps_prepared_origin_but_only_weak_source_identity() {
    let original = Rc::new(11);
    let source = Rc::new(22);
    let seal = InitialStartedOrigin::from_original(&original, &source);
    seal.verify(&original, &source).unwrap();
    seal.verify_retained_source().unwrap();
    assert!(seal.verify(&Rc::new(11), &source).is_err());
    assert!(seal.verify(&original, &Rc::new(22)).is_err());
    assert_eq!(Rc::strong_count(&source), 1);
    assert_eq!(Rc::strong_count(&original), 2);
    let weak = Rc::downgrade(&source);
    drop(source);
    assert!(weak.upgrade().is_none());
    assert!(seal.verify_retained_source().is_err());
    assert!(seal.verify(&original, &Rc::new(22)).is_err());
    drop(seal);
    assert_eq!(Rc::strong_count(&original), 1);
}

// Break: replacing the other member/network/C after readonly prepare, or
// confusing a live Attach publication with initial Start or Closing.
#[test]
fn live_prepare_attachment_preserves_original_other_network_and_uses_attach_only() {
    use crate::member_carrier_pair as pair;
    use nelomai_client_tunnel::redundancy::Slot;
    let (context, prepared_against, intent) = live_preparation_fixture();
    let mut current = prepared_against.clone();
    let mut member = operation_fixture().1.members[0].clone().unwrap();
    member.owner.intent = intent.clone();
    member.lease_id = "33333333-3333-4333-8333-333333333333".into();
    member.endpoint = "192.0.2.99".parse().unwrap(); // Not primary profile equality.
    current.members[1] = Some(member);
    current.operation = Some(pair::Operation::Attach(Slot::B));
    current.pending = Some(pair::Effect::MemberStart(Slot::B));
    current.revision += 3;
    current.validate().unwrap();
    validate_live_preparation_attachment(&context, &prepared_against, &current, &intent).unwrap();
    for fault in 0..7 {
        let mut changed = current.clone();
        match fault {
            0 => {
                changed.members[0]
                    .as_mut()
                    .unwrap()
                    .owner
                    .proof
                    .as_mut()
                    .unwrap()
                    .process
                    .pid += 1
            }
            1 => changed.carrier.as_mut().unwrap().luid += 1,
            2 => changed.operation = Some(pair::Operation::Start(Slot::B)),
            3 => changed.active = Some(Slot::B),
            4 => changed.network = None,
            5 => changed.revision = prepared_against.revision,
            _ => {
                changed.members[1]
                    .as_mut()
                    .unwrap()
                    .owner
                    .intent
                    .config_sha256 = [99; 32]
            }
        }
        assert!(validate_live_preparation_attachment(
            &context,
            &prepared_against,
            &changed,
            &intent
        )
        .is_err());
    }
}

// Break: treating retired Pair metadata/Drop as a closed-generation receipt,
// or retiring an active/unknown/Closing generation to admit a new owner.
#[test]
fn closed_generation_receipt_precondition_requires_completed_retire_not_old_live_metadata() {
    use crate::{member_carrier_pair as pair, member_owner as owner};
    let (context, current, _) = live_preparation_fixture();
    let mut retired = current.clone();
    let mut stopped = retired.members[0].take().unwrap().owner;
    stopped.phase = owner::Phase::Stopped;
    stopped.retired_proof = stopped.proof.take();
    let mut remaining = current.members[0].clone().unwrap();
    remaining.owner.intent.slot = nelomai_contracts::dispatcher::TunnelSlot::B;
    remaining.owner.proof.as_mut().unwrap().interface = owner::InterfaceProof {
        index: 18,
        luid: 19,
        guid: [3; 16],
    };
    remaining.owner.proof.as_mut().unwrap().process.pid = 70;
    retired.members[1] = Some(remaining);
    retired.active = Some(nelomai_client_tunnel::redundancy::Slot::B);
    retired.validate().unwrap();
    validate_closed_generation_retirement(&context, &retired, &stopped).unwrap();
    for fault in 0..7 {
        let (mut p, mut ack) = (retired.clone(), stopped.clone());
        match fault {
            0 => ack.retired_proof = None,
            1 => ack.phase = owner::Phase::Running,
            2 => p.members[0] = current.members[0].clone(),
            3 => {
                p.operation = Some(pair::Operation::Retire(
                    nelomai_client_tunnel::redundancy::Slot::A,
                ))
            }
            4 => p.phase = pair::Phase::Closing,
            5 => ack.intent.scope.connection_generation += 1,
            _ => ack.retired_proof.as_mut().unwrap().interface.guid = [99; 16],
        }
        assert!(validate_closed_generation_retirement(&context, &p, &ack).is_err());
    }
}

fn replacement_fixture() -> (
    crate::member_carrier_native_ownership::Context,
    crate::member_carrier_pair::Record,
    crate::member_owner::Intent,
    crate::member_owner::Record,
) {
    use crate::member_owner as owner;
    let (context, current, intent) = live_preparation_fixture();
    let stopped = owner::Record {
        intent: owner::Intent {
            config_sha256: [20; 32],
            ..intent.clone()
        },
        phase: owner::Phase::Stopped,
        proof: None,
        retired_proof: Some(owner::NativeProof {
            process: owner::ProcessProof {
                pid: 70,
                creation_time: 71,
            },
            interface: owner::InterfaceProof {
                index: 18,
                luid: 19,
                guid: [3; 16],
            },
        }),
        previous_config_sha256: None,
    };
    (context, current, intent, stopped)
}

// Break: accepting a private predecessor by equal JSON/schema rather than
// matching the actual original Stop ticket's exact scope/slot/proof/config.
#[test]
fn replacement_prior_requires_exact_original_stopped_generation() {
    let (context, _, intent, stopped) = replacement_fixture();
    validate_replacement_prior(&context, &intent, &stopped, Some(&stopped)).unwrap();
    assert!(validate_replacement_prior(&context, &intent, &stopped, None).is_err());
    for fault in 0..7 {
        let mut changed = stopped.clone();
        match fault {
            0 => changed.intent.config_sha256 = [22; 32],
            1 => changed.intent.scope.connection_generation += 1,
            2 => changed.intent.slot = nelomai_contracts::dispatcher::TunnelSlot::A,
            3 => changed.retired_proof.as_mut().unwrap().process.pid += 1,
            4 => changed.retired_proof.as_mut().unwrap().interface.guid = [99; 16],
            5 => changed.retired_proof = None,
            _ => changed.intent.engine = crate::test_engine_path("foreign.exe"),
        }
        assert!(validate_replacement_prior(&context, &intent, &stopped, Some(&changed)).is_err());
    }
}

// Break: dropping either closed owner root or its actual ticket when the next
// readonly construction fails/unwinds; moving only one root on missing input.
#[test]
fn replacement_retains_both_original_roots_and_ticket_before_failure_or_unwind() {
    let drops = Rc::new(Cell::new(0));
    let ticket = Rc::new(Owned(drops.clone()));
    let mut prepared = Some(Owned(drops.clone()));
    let mut controller = Some(Owned(drops.clone()));
    let mut retired = Vec::new();
    retain_verified_closed_generation(&mut prepared, &mut controller, &ticket, &mut retired)
        .unwrap();
    assert!(prepared.is_none() && controller.is_none());
    assert_eq!(retired.len(), 1);
    assert!(Rc::ptr_eq(&retired[0]._ticket, &ticket));
    assert_eq!(drops.get(), 0);
    assert!(catch_unwind(AssertUnwindSafe(|| panic!("next readonly preparation"))).is_err());
    assert_eq!(drops.get(), 0);
    assert!(retain_verified_closed_generation(
        &mut prepared,
        &mut controller,
        &ticket,
        &mut retired
    )
    .is_err());
    prepared = Some(Owned(drops.clone()));
    assert!(retain_verified_closed_generation(
        &mut prepared,
        &mut controller,
        &ticket,
        &mut retired
    )
    .is_err());
    assert!(prepared.is_some());
    assert_eq!(retired.len(), 1);
    drop(retired);
    assert_eq!(drops.get(), 2);
    drop(ticket);
    assert_eq!(drops.get(), 3);
}

#[test]
fn started_replacement_lineage_requires_actual_next_generation_started_on_same_ledger() {
    let history = NeverMemberHistory::default();
    history.carrier_attempted.set(true);
    let first = history.prepare(1).unwrap();
    history.start(1, first).unwrap();
    let next = history.retire_generation(1, first).unwrap();
    assert!(history.verify_started_generation(1, first, next).is_err());
    assert_eq!(history.prepare(1).unwrap(), 2);
    assert!(history.verify_started_generation(1, first, next).is_err());
    history.start(1, next).unwrap();
    history.verify_started_generation(1, first, next).unwrap();
    assert!(history.verify_started_generation(0, first, next).is_err());
    assert!(history.verify_started_generation(1, 0, next).is_err());
    assert!(history.verify_started_generation(1, first, 3).is_err());
    history.retire_generation(1, next).unwrap();
    assert!(history.verify_started_generation(1, first, next).is_err());
}

// Break: allowing unknown closed history for first Attach, or mixing previous
// target SDK identity into the live universe during same-owner replacement.
#[test]
fn replacement_observation_keeps_typed_target_history_separate_from_live_sdk() {
    let (context, current, intent, stopped) = replacement_fixture();
    let other = current.members[0].as_ref().unwrap().owner.clone();
    let proof = other.proof.unwrap();
    let live = [Some(proof.interface), None];
    validate_replacement_preparation_observation(
        &context,
        &current,
        &intent,
        current.carrier,
        live,
        ReplacementHistory {
            closed: [false, true],
            stopped: &stopped,
            intent: &stopped.intent,
            proof: stopped.retired_proof.unwrap(),
        },
        &(other.intent.clone(), proof),
    )
    .unwrap();
    assert!(validate_live_preparation_observation(
        &context,
        &current,
        &intent,
        current.carrier,
        live,
        [false, true],
        &(other.intent.clone(), proof),
    )
    .is_err());
    for fault in 0..5 {
        let (mut history, mut observed, mut retired) = ([false, true], live, stopped.clone());
        match fault {
            0 => history[0] = true,
            1 => history[1] = false,
            2 => observed[1] = Some(stopped.retired_proof.unwrap().interface),
            3 => retired.retired_proof.as_mut().unwrap().interface.luid += 1,
            _ => observed[0] = None,
        }
        assert!(validate_replacement_preparation_observation(
            &context,
            &current,
            &intent,
            current.carrier,
            observed,
            ReplacementHistory {
                closed: history,
                stopped: &stopped,
                intent: &retired.intent,
                proof: retired.retired_proof.unwrap()
            },
            &(other.intent.clone(), proof),
        )
        .is_err());
    }
}

// Break: making primary-only Stop depend on a created B controller, or calling
// started/lost-ACK metadata "unstarted" and manufacturing a Stopped record.
#[test]
fn unstarted_absence_requires_exact_closing_slot_and_never_accepts_running_proof() {
    use crate::{member_carrier_pair as pair, member_owner as owner};
    use nelomai_contracts::dispatcher::TunnelSlot;
    let (context, mut current, intent) = operation_fixture();
    current.phase = pair::Phase::Closing;
    current.operation = None;
    current.active = None;
    current.stop_stage = 4;
    current.pending = Some(pair::Effect::MemberStop(
        nelomai_client_tunnel::redundancy::Slot::A,
    ));
    current.validate().unwrap();
    validate_unstarted_closing(&context, &current, TunnelSlot::A, Some(&intent)).unwrap();
    assert!(validate_unstarted_closing(&context, &current, TunnelSlot::A, None).is_err());
    current.stop_stage = 5;
    current.pending = Some(pair::Effect::MemberStop(
        nelomai_client_tunnel::redundancy::Slot::B,
    ));
    validate_unstarted_closing(&context, &current, TunnelSlot::B, None).unwrap();
    assert!(validate_unstarted_closing(&context, &current, TunnelSlot::A, Some(&intent)).is_err());
    current.stop_stage = 4;
    current.pending = Some(pair::Effect::MemberStop(
        nelomai_client_tunnel::redundancy::Slot::A,
    ));
    current.members[0].as_mut().unwrap().owner.phase = owner::Phase::Running;
    current.members[0].as_mut().unwrap().owner.proof = Some(owner::NativeProof {
        process: owner::ProcessProof {
            pid: 50,
            creation_time: 51,
        },
        interface: owner::InterfaceProof {
            index: 12,
            luid: 13,
            guid: [2; 16],
        },
    });
    assert!(validate_unstarted_closing(&context, &current, TunnelSlot::A, Some(&intent)).is_err());
    let mut foreign = context.clone();
    foreign.provenance.network_epoch += 1;
    assert!(validate_unstarted_closing(&foreign, &current, TunnelSlot::B, None).is_err());
}

// Break: rejecting an original Prepared owner at actual Closing12, or relaxing
// the ordinary MemberStop lane instead of keeping FullEmpty disjoint.
#[test]
fn prepared_no_start_closing12_is_actual_full_empty_not_stopped_projection() {
    use crate::member_carrier_pair as pair;
    use nelomai_contracts::dispatcher::TunnelSlot;
    let (context, mut record, _) = operation_fixture();
    record.phase = pair::Phase::Closing;
    record.operation = None;
    record.active = None;
    record.stop_stage = 12;
    record.pending = Some(pair::Effect::FullEmpty);
    record.validate().unwrap();
    validate_never_member_frame(&context, &record, TunnelSlot::A).unwrap();
    validate_never_member_frame(&context, &record, TunnelSlot::B).unwrap();
    assert!(validate_unstarted_closing(
        &context,
        &record,
        TunnelSlot::A,
        record.members[0].as_ref().map(|m| &m.owner.intent)
    )
    .is_err());
    assert!(validate_never_member_terminal_frame(&context, &record).is_err());
}

#[test]
fn closing12_no_start_uses_current_original_preparation_history_not_missing_owner() {
    let history = NeverMemberHistory::default();
    assert!(history.verify_unstarted_preparation(0, 1).is_err());
    let generation = history.prepare(0).unwrap();
    assert!(history.verify_unstarted_preparation(0, generation).is_err());
    history.carrier_attempted.set(true);
    history.verify_unstarted_preparation(0, generation).unwrap();
    assert!(history.verify_unstarted_preparation(1, generation).is_err());
    assert!(history.verify_unstarted_preparation(0, 0).is_err());
    assert!(history
        .verify_unstarted_preparation(0, generation + 1)
        .is_err());
    history.start(0, generation).unwrap();
    assert!(history.verify_unstarted_preparation(0, generation).is_err());
}

#[test]
fn prepublication_prepared_coverage_needs_original_root_for_every_preparation() {
    let history = NeverMemberHistory::default();
    history.carrier_attempted.set(true);
    verify_prepublication_prepared_coverage(&history, [None, None], [false, false]).unwrap();
    assert!(
        verify_prepublication_prepared_coverage(&history, [None, None], [true, false]).is_err()
    );
    history.prepare(0).unwrap();
    assert!(
        verify_prepublication_prepared_coverage(&history, [None, None], [false, false]).is_err()
    );
    verify_prepublication_prepared_coverage(&history, [Some(1), None], [true, false]).unwrap();
    verify_prepublication_prepared_coverage(&history, [Some(1), None], [false, false]).unwrap();
    assert!(
        verify_prepublication_prepared_coverage(&history, [Some(2), None], [true, false]).is_err()
    );
    assert!(
        verify_prepublication_prepared_coverage(&history, [None, Some(1)], [false, true]).is_err()
    );
    history.start(0, 1).unwrap();
    assert!(
        verify_prepublication_prepared_coverage(&history, [Some(1), None], [true, false]).is_err()
    );
}

#[test]
fn closing12_unstarted_frame_rejects_live_history_foreign_context_and_other_effects() {
    use crate::{member_carrier_pair as pair, member_owner as owner};
    use nelomai_contracts::dispatcher::TunnelSlot;
    let (context, mut record, intent) = operation_fixture();
    record.phase = pair::Phase::Closing;
    record.operation = None;
    record.active = None;
    record.stop_stage = 12;
    record.pending = Some(pair::Effect::FullEmpty);
    validate_closing12_unstarted(&context, &record, TunnelSlot::A, Some(&intent)).unwrap();
    let mut unpublished = record.clone();
    unpublished.carrier = None;
    validate_closing12_unstarted(&context, &unpublished, TunnelSlot::A, Some(&intent)).unwrap();
    assert!(validate_closing12_unstarted(&context, &record, TunnelSlot::A, None).is_err());
    for fault in 0..15 {
        let mut bad = record.clone();
        let mut foreign = context.clone();
        match fault {
            0 => bad.phase = pair::Phase::Stopped,
            1 => bad.pending = None,
            2 => bad.pending = Some(pair::Effect::NativeEmpty),
            3 => bad.stop_stage = 5,
            4 => foreign.provenance.network_epoch += 1,
            5 => foreign.intent.scope.runtime_generation += 1,
            6 => bad.guard.permits = true,
            7 => bad.guard.assigned_sublayer_weight = Some(13),
            8 => bad.operation = Some(pair::Operation::Rebind),
            9 => bad.members[0].as_mut().unwrap().owner.phase = owner::Phase::Running,
            10 => {
                bad.members[0]
                    .as_mut()
                    .unwrap()
                    .owner
                    .previous_config_sha256 = Some([2; 32])
            }
            11 => {
                bad.members[0].as_mut().unwrap().owner.retired_proof = Some(owner::NativeProof {
                    process: owner::ProcessProof {
                        pid: 7,
                        creation_time: 8,
                    },
                    interface: owner::InterfaceProof {
                        index: 9,
                        luid: 10,
                        guid: [2; 16],
                    },
                })
            }
            12 => bad.carrier.as_mut().unwrap().guid = [3; 16],
            13 => foreign.bindings[1].role = crate::member_carrier_native_ownership::Role::MemberB,
            _ => bad.addresses = vec!["10.7.0.99/32".parse().unwrap()],
        }
        assert!(
            validate_closing12_unstarted(&foreign, &bad, TunnelSlot::A, Some(&intent)).is_err(),
            "fault {fault}"
        );
    }
}

#[test]
fn pregraph_native_empty_prepared_originals_do_not_require_closing12() {
    use crate::member_carrier_pair as pair;
    use nelomai_contracts::dispatcher::TunnelSlot;
    let (context, mut record, intent) = operation_fixture();
    record.phase = pair::Phase::Closing;
    record.options = Some(nelomai_client_tunnel::DesktopTunnelOptions::default());
    record.operation = None;
    record.active = None;
    for (stage, effect) in [(9, pair::Effect::NativeEmpty), (10, pair::Effect::Guard)] {
        record.stop_stage = stage;
        record.pending = Some(effect);
        validate_pregraph_native_empty_unstarted(&context, &record, TunnelSlot::A, Some(&intent))
            .unwrap();
        assert!(
            validate_closing12_unstarted(&context, &record, TunnelSlot::A, Some(&intent)).is_err()
        );
        assert!(
            validate_pregraph_native_empty_unstarted(&context, &record, TunnelSlot::A, None)
                .is_err()
        );
        let mut started = record.clone();
        started.members[0].as_mut().unwrap().owner.phase = crate::member_owner::Phase::Running;
        assert!(validate_pregraph_native_empty_unstarted(
            &context,
            &started,
            TunnelSlot::A,
            Some(&intent)
        )
        .is_err());
    }
    record.stop_stage = 12;
    record.pending = Some(pair::Effect::FullEmpty);
    assert!(validate_pregraph_native_empty_unstarted(
        &context,
        &record,
        TunnelSlot::A,
        Some(&intent)
    )
    .is_err());
}

// Break: moving C creation before actual readonly preparation/full absence.
#[test]
fn before_carrier_preflight_is_only_exact_primary_preparation_not_start_or_attach() {
    let (context, mut record, intent) = operation_fixture();
    record.carrier = None;
    record.pending = None;
    record.validate().unwrap();
    validate_before_carrier(&context, &record, &intent).unwrap();
    for fault in 0..5 {
        let mut changed = record.clone();
        match fault {
            0 => {
                changed.carrier = Some(crate::member_owner::InterfaceProof {
                    index: 4,
                    luid: 5,
                    guid: [1; 16],
                })
            }
            1 => {
                changed.pending = Some(crate::member_carrier_pair::Effect::MemberStart(
                    nelomai_client_tunnel::redundancy::Slot::A,
                ))
            }
            2 => {
                changed.operation = Some(crate::member_carrier_pair::Operation::Attach(
                    nelomai_client_tunnel::redundancy::Slot::A,
                ))
            }
            3 => changed.scope.connection_generation += 1,
            _ => {
                changed.members[0]
                    .as_mut()
                    .unwrap()
                    .owner
                    .intent
                    .config_sha256 = [7; 32]
            }
        }
        assert!(validate_before_carrier(&context, &changed, &intent).is_err());
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}
type Root = OperationRoot<Owned, u64, Owned, Owned>;
fn root() -> (Root, Rc<Cell<usize>>) {
    let drops = Rc::new(Cell::new(0));
    (OperationRoot::new(Owned(drops.clone())), drops)
}
fn start(root: &mut Root, fault: Option<Fault>) -> Result<(), RootError<Fault>> {
    root.start(
        |_| Ok(41),
        |owner| Ok(Owned(owner.0.clone())),
        |_, _| {
            if fault == Some(Fault::Register) {
                Err(Fault::Register)
            } else {
                Ok(())
            }
        },
        |_, _| {
            if fault == Some(Fault::Postflight) {
                Err(Fault::Postflight)
            } else {
                Ok(())
            }
        },
    )
}

// Break caught: discarding the returned Running ACK or original reader before
// fallible inventory publication.
#[test]
fn failed_registration_keeps_running_ack_and_original_reader_rooted() {
    let (mut root, drops) = root();
    assert_eq!(
        start(&mut root, Some(Fault::Register)),
        Err(RootError::Operation(Fault::Register))
    );
    assert_eq!(root.running, Some(41));
    assert!(root.reader.is_some());
    assert!(!root.registered);
    assert_eq!(drops.get(), 0);
    drop(root);
    assert_eq!(drops.get(), 0);
}
#[test]
fn lost_postflight_keeps_registered_ack_and_blocks_duplicate_start() {
    let (mut root, drops) = root();
    assert_eq!(
        start(&mut root, Some(Fault::Postflight)),
        Err(RootError::Operation(Fault::Postflight))
    );
    assert!(root.registered);
    assert_eq!(root.running, Some(41));
    assert_eq!(start(&mut root, None), Err(RootError::Retired));
    drop(root);
    assert_eq!(drops.get(), 0);
}
#[test]
fn unwind_after_native_ack_keeps_owner_reader_and_running_return() {
    let (mut root, drops) = root();
    assert!(catch_unwind(AssertUnwindSafe(|| {
        let _: Result<(), RootError<Fault>> = root.start(
            |_| Ok(41),
            |o| Ok(Owned(o.0.clone())),
            |_, _| panic!("inventory unwind"),
            |_, _| Ok(()),
        );
    }))
    .is_err());
    assert_eq!(root.running, Some(41));
    assert!(root.reader.is_some());
    assert_eq!(start(&mut root, None), Err(RootError::Retired));
    drop(root);
    assert_eq!(drops.get(), 0);
}
#[test]
fn lost_native_ack_keeps_original_owner_without_minting_running_or_reader() {
    let (mut root, drops) = root();
    assert_eq!(
        root.start(
            |_| Err(Fault::LostAck),
            |_| unreachable!(),
            |_, _| unreachable!(),
            |_, _| unreachable!()
        ),
        Err(RootError::Operation(Fault::LostAck))
    );
    assert!(root.running.is_none() && root.reader.is_none());
    assert_eq!(start(&mut root, None), Err(RootError::Retired));
    drop(root);
    assert_eq!(drops.get(), 0);
}
#[test]
fn stopped_ack_and_same_receipt_survive_closed_registration_failure() {
    let (mut root, drops) = root();
    start(&mut root, None).unwrap();
    assert_eq!(
        root.stop(
            |o| Ok((42, Owned(o.0.clone()))),
            |_| Err(Fault::Register),
            |_, _, _| Ok(())
        ),
        Err(RootError::Operation(Fault::Register))
    );
    assert_eq!(root.stopped, Some(42));
    let original = root.closed.as_ref().unwrap().clone();
    assert!(root
        .stop(
            |_| panic!("must never Stop twice"),
            |ack| {
                assert!(Rc::ptr_eq(&original, ack));
                Ok(())
            },
            |_, ack, _| {
                assert!(Rc::ptr_eq(&original, ack));
                Ok::<_, Fault>(())
            }
        )
        .is_ok());
    assert!(root.closed_registered);
    assert_eq!(drops.get(), 0);
}
#[test]
fn stop_unwind_preserves_same_receipt_before_postflight() {
    let (mut root, drops) = root();
    start(&mut root, None).unwrap();
    assert!(catch_unwind(AssertUnwindSafe(|| {
        let _: Result<(), RootError<Fault>> = root.stop(
            |o| Ok((42, Owned(o.0.clone()))),
            |_| panic!("closed register unwind"),
            |_, _, _| Ok(()),
        );
    }))
    .is_err());
    assert_eq!(root.stopped, Some(42));
    assert!(root.closed.is_some());
    drop(root);
    assert_eq!(drops.get(), 0);
}
#[test]
fn completed_stop_releases_pins_only_after_ack_registration_and_postflight() {
    let (mut root, drops) = root();
    start(&mut root, None).unwrap();
    let outcome = root.stop(
        |o| Ok((42, Owned(o.0.clone()))),
        |_| Ok(()),
        |_, _, _| Ok::<_, Fault>(()),
    );
    assert!(outcome.is_ok());
    drop(root);
    assert_eq!(drops.get(), 3);
}

#[test]
fn partial_start_without_reader_requires_owner_checked_closed_postflight() {
    let (mut root, drops) = root();
    let original = root.owner.as_ref().unwrap().0.clone();
    root.attempted = true;
    let checked = Cell::new(false);
    assert!(root
        .stop(
            |o| Ok((42, Owned(o.0.clone()))),
            |_| Ok(()),
            |_, _, (owner, reader)| {
                assert!(Rc::ptr_eq(&original, &owner.0));
                assert!(reader.is_none());
                checked.set(true);
                Ok::<_, Fault>(())
            },
        )
        .is_ok());
    assert!(checked.get());
    assert!(root.running.is_none());
    assert!(root.reader.is_none());
    drop(root);
    assert_eq!(drops.get(), 2);
}

#[test]
fn reader_failure_then_failed_closed_postflight_retains_owner_and_same_ack_for_retry() {
    let (mut root, drops) = root();
    assert_eq!(
        root.start(
            |_| Ok(41),
            |_| Err(Fault::Register),
            |_, _| panic!("no reader to register"),
            |_, _| panic!("no Running postflight")
        ),
        Err(RootError::Operation(Fault::Register))
    );
    assert_eq!(root.running, Some(41));
    assert!(root.reader.is_none());
    assert_eq!(
        root.stop(
            |owner| Ok((42, Owned(owner.0.clone()))),
            |_| Ok(()),
            |_, _, (_, reader)| {
                assert!(reader.is_none());
                Err(Fault::Postflight)
            }
        ),
        Err(RootError::Operation(Fault::Postflight))
    );
    assert!(!root.completed);
    let original = root.closed.as_ref().unwrap().clone();
    assert!(root
        .stop(
            |_| panic!("never repeat native Stop after actual ACK"),
            |receipt| {
                assert!(Rc::ptr_eq(&original, receipt));
                Ok(())
            },
            |_, receipt, (owner, reader)| {
                assert!(reader.is_none());
                assert!(Rc::ptr_eq(&owner.0, &receipt.0));
                Ok::<_, Fault>(())
            }
        )
        .is_ok());
    drop(original);
    drop(root);
    assert_eq!(drops.get(), 2);
}
