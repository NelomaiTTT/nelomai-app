use super::*;
use crate::member_carrier::{Intent, Provenance};
use crate::member_carrier_native_ownership::{Binding, FullNativeRows, KeyReceipt, Role};
use nelomai_client_tunnel::redundancy::SessionScope;
use nelomai_contracts::{dispatcher::EngineIdentity, RuntimeSlot};

#[test]
fn original_unupgraded_close_receipt_does_not_require_or_invent_full_delegate() {
    use std::{cell::Cell, rc::Rc};
    let signal = Rc::new(Cell::new(false));
    let upgrade = LifecycleUpgrade::<()>::new(signal.clone());
    let root = OriginalReadCapture::new(signal.clone());
    let actual = Rc::new(());
    upgrade
        .retain_original_read(&root, &actual, |_, _| {
            panic!("no bootstrap delegate exists")
        })
        .unwrap();
    assert!(Rc::ptr_eq(&root.pin().unwrap(), &actual));
    root.confirm(&actual).unwrap();
    assert!(upgrade.replacement.borrow().is_none());
    assert!(
        upgrade.inspect(false, |_| Ok(())).is_err(),
        "receipt supplies no full forward authority"
    );
    assert!(signal.get());
}

#[test]
fn original_upgraded_close_receipt_roots_before_mandatory_delegate_and_never_retries_error() {
    use std::{
        cell::Cell,
        rc::{Rc, Weak},
    };
    let signal = Rc::new(Cell::new(false));
    let upgrade = LifecycleUpgrade::<Option<Weak<()>>>::new(signal.clone());
    upgrade.register(None, |_| Ok(())).unwrap();
    let root = OriginalReadCapture::new(signal.clone());
    let actual = Rc::new(());
    assert_eq!(
        upgrade.retain_original_read(&root, &actual, |weak, pin| {
            assert!(
                Rc::ptr_eq(&root.pin()?, &actual),
                "actor retains BEFORE weak registration"
            );
            *weak = Some(Rc::downgrade(pin));
            Err(Error::Native)
        }),
        Err(Error::Native)
    );
    assert!(Rc::ptr_eq(&root.pin().unwrap(), &actual));
    assert!(
        root.require_registered().is_err(),
        "AfterClose cannot synthesize successful registration"
    );
    assert!(upgrade
        .retain_original_read(&root, &actual, |_, _| panic!(
            "failed registration retry forbidden"
        ))
        .is_err());
    upgrade
        .inspect(true, |weak| {
            assert!(Rc::ptr_eq(
                &weak.as_ref().unwrap().upgrade().unwrap(),
                &actual
            ));
            Ok(())
        })
        .unwrap();
    assert!(upgrade.inspect(false, |_| Ok(())).is_err());
}

#[test]
fn original_read_capture_roots_exact_ack_before_weak_registration_and_afterclose_postflight() {
    use std::{cell::Cell, rc::Rc};
    let signal = Rc::new(Cell::new(false));
    let root = OriginalReadCapture::new(signal.clone());
    let actual = Rc::new(90u64);
    let mut weak = None;
    assert!(
        root.require_registered().is_err(),
        "None is no close completion"
    );
    root.capture(actual.clone(), |pin| {
        assert!(
            Rc::ptr_eq(&root.pin()?, &actual),
            "actor root BEFORE any registration/postflight"
        );
        assert!(Rc::ptr_eq(pin, &actual));
        weak = Some(Rc::downgrade(pin));
        Ok(())
    })
    .unwrap();
    root.require_registered().unwrap(); // factual registration prerequisite, NOT a cleanup effect
    let observed = weak.unwrap().upgrade().unwrap();
    assert!(
        Rc::ptr_eq(&observed, &root.pin().unwrap()),
        "AfterClose sees the exact original ACK"
    );
    assert!(signal.get(), "cleanup capture never resumes forward");
}

#[test]
fn original_read_capture_registration_error_or_unwind_keeps_facts_without_retry() {
    use std::{
        cell::Cell,
        panic::{catch_unwind, AssertUnwindSafe},
        rc::Rc,
    };
    for unwind in [false, true] {
        let signal = Rc::new(Cell::new(false));
        let root = OriginalReadCapture::new(signal.clone());
        let actual = Rc::new(90u64);
        let result = catch_unwind(AssertUnwindSafe(|| {
            root.capture(actual.clone(), |pin| {
                assert!(Rc::ptr_eq(&root.pin().unwrap(), pin));
                if unwind {
                    panic!("actual weak registration unwound");
                }
                Err(Error::Native)
            })
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), Err(Error::Native));
        }
        assert!(Rc::ptr_eq(&root.pin().unwrap(), &actual));
        root.confirm(&actual).unwrap(); // cleanup receipt facts only
        assert!(root.require_registered().is_err());
        let mut retried = false;
        assert!(root
            .capture(actual.clone(), |_| {
                retried = true;
                Ok(())
            })
            .is_err());
        assert!(!retried);
        assert!(signal.get());
    }
}

#[test]
fn original_read_capture_same_rc_confirmation_never_repeats_registration() {
    use std::{cell::Cell, rc::Rc};
    let root = OriginalReadCapture::new(Rc::new(Cell::new(false)));
    let actual = Rc::new(90u64);
    root.capture(actual.clone(), |_| Ok(())).unwrap();
    let mut replaced = false;
    root.capture(actual.clone(), |_| {
        replaced = true;
        Ok(())
    })
    .unwrap();
    root.confirm(&actual).unwrap();
    assert!(
        !replaced,
        "actual close postflight retry reuses registration, not a second reader"
    );
    root.require_registered().unwrap();
}

#[test]
fn original_read_capture_foreign_equal_rc_never_replaces_original_or_rearms() {
    use std::{cell::Cell, rc::Rc};
    let root = OriginalReadCapture::new(Rc::new(Cell::new(false)));
    let actual = Rc::new(90u64);
    let equal = Rc::new(90u64);
    root.capture(actual.clone(), |_| Ok(())).unwrap();
    assert!(root
        .capture(equal.clone(), |_| panic!("foreign registration forbidden"))
        .is_err());
    assert!(Rc::ptr_eq(&root.pin().unwrap(), &actual));
    assert!(!Rc::ptr_eq(&root.pin().unwrap(), &equal));
    assert!(root.confirm(&equal).is_err());
    root.confirm(&actual).unwrap();
    assert!(root.require_registered().is_err());
}

#[test]
fn original_read_capture_caught_nested_handoff_failure_is_sticky() {
    use std::{cell::Cell, rc::Rc};
    let root = OriginalReadCapture::new(Rc::new(Cell::new(false)));
    let actual = Rc::new(());
    assert!(root
        .capture(actual.clone(), |_| {
            assert!(root.capture(actual.clone(), |_| Ok(())).is_err());
            Ok(())
        })
        .is_err());
    root.confirm(&actual).unwrap();
    assert!(root.require_registered().is_err());
}

#[test]
fn original_read_capture_lost_postflight_retains_registered_original_and_drop_cannot_resume() {
    use std::{
        cell::Cell,
        panic::{catch_unwind, AssertUnwindSafe},
        rc::Rc,
    };
    let signal = Rc::new(Cell::new(false));
    let actual = Rc::new(());
    let root = OriginalReadCapture::new(signal.clone());
    let weak = Rc::downgrade(&actual);
    root.capture(actual.clone(), |_| Ok(())).unwrap();
    let result = catch_unwind(AssertUnwindSafe(|| {
        assert!(Rc::ptr_eq(&root.pin().unwrap(), &weak.upgrade().unwrap()));
        panic!("native capture/AfterClose postflight unwound AFTER original ACK handoff");
    }));
    assert!(result.is_err());
    root.confirm(&actual).unwrap();
    assert!(Rc::ptr_eq(&root.pin().unwrap(), &actual));
    drop(root);
    assert!(signal.get());
}

// These mutate production registration/dispatch mechanics, not a parallel
// lifecycle model. A delegate is mandatory; None supplies no successful IO.
#[derive(Clone)]
struct UpgradeOriginal(std::rc::Rc<()>);
struct UpgradeDelegate {
    original: UpgradeOriginal,
    session: Option<UpgradeOriginal>,
    current: Option<UpgradeOriginal>,
    dropped: std::rc::Rc<std::cell::Cell<usize>>,
}
impl Drop for UpgradeDelegate {
    fn drop(&mut self) {
        self.dropped.set(self.dropped.get() + 1);
    }
}
fn delegate(
    original: &UpgradeOriginal,
    dropped: &std::rc::Rc<std::cell::Cell<usize>>,
) -> UpgradeDelegate {
    UpgradeDelegate {
        original: original.clone(),
        session: None,
        current: None,
        dropped: dropped.clone(),
    }
}

#[test]
fn lifecycle_upgrade_retains_actual_replacement_before_error_or_unwind_and_cleanup_is_not_resume() {
    use std::{
        cell::Cell,
        panic::{catch_unwind, AssertUnwindSafe},
        rc::Rc,
    };
    for unwind in [false, true] {
        let origin = UpgradeOriginal(Rc::new(()));
        let dropped = Rc::new(Cell::new(0));
        let slot = LifecycleUpgrade::new(Rc::new(Cell::new(false)));
        let result = catch_unwind(AssertUnwindSafe(|| {
            slot.register(delegate(&origin, &dropped), |g| {
                assert!(Rc::ptr_eq(&g.original.0, &origin.0));
                g.session = Some(origin.clone());
                if unwind {
                    panic!("replacement postflight unwound");
                }
                Err(Error::Conflict)
            })
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), Err(Error::Conflict));
        }
        assert_eq!(dropped.get(), 0);
        assert!(slot.revoked.get());
        assert!(slot.inspect(false, |_| Ok(())).is_err());
        slot.inspect(true, |g| {
            assert!(Rc::ptr_eq(&g.session.as_ref().unwrap().0, &origin.0));
            Ok(())
        })
        .unwrap();
        assert!(slot.inspect(false, |_| Ok(())).is_err());
    }
}

#[test]
fn lifecycle_upgrade_is_one_shot_even_equal_replacements_are_retained_not_selected() {
    use std::{cell::Cell, rc::Rc};
    let origin = UpgradeOriginal(Rc::new(()));
    let dropped = Rc::new(Cell::new(0));
    let slot = LifecycleUpgrade::new(Rc::new(Cell::new(false)));
    slot.register(delegate(&origin, &dropped), |g| {
        g.session = Some(origin.clone());
        Ok(())
    })
    .unwrap();
    let mut invoked = false;
    assert!(slot
        .register(delegate(&origin, &dropped), |_| {
            invoked = true;
            Ok(())
        })
        .is_err());
    assert!(!invoked);
    assert_eq!(dropped.get(), 0);
    assert_eq!(slot.rejected.borrow().len(), 1);
    assert!(slot.inspect(false, |_| Ok(())).is_err());
    slot.inspect(true, |g| {
        assert!(g.session.is_some(), "first original remains selected");
        Ok(())
    })
    .unwrap();
}

#[test]
fn lifecycle_upgrade_none_or_pre_revoked_entry_cannot_supply_late_authority() {
    use std::{cell::Cell, rc::Rc};
    let signal = Rc::new(Cell::new(false));
    let slot = LifecycleUpgrade::<UpgradeDelegate>::new(signal.clone());
    assert!(slot.inspect(false, |_| Ok(())).is_err());
    assert!(slot.inspect(true, |_| Ok(())).is_err());
    let origin = UpgradeOriginal(Rc::new(()));
    let dropped = Rc::new(Cell::new(0));
    signal.set(true);
    let mut called = false;
    assert!(slot
        .register(delegate(&origin, &dropped), |_| {
            called = true;
            Ok(())
        })
        .is_err());
    assert!(!called);
    assert_eq!(dropped.get(), 0);
    assert!(slot.replacement.borrow().is_some());
    assert!(slot.inspect(false, |_| Ok(())).is_err());
}

#[test]
fn lifecycle_upgrade_dispatch_uses_each_actual_current_opaque_pair_and_never_rearms() {
    use std::{
        cell::Cell,
        panic::{catch_unwind, AssertUnwindSafe},
        rc::Rc,
    };
    for unwind in [false, true] {
        let origin = UpgradeOriginal(Rc::new(()));
        let first = UpgradeOriginal(Rc::new(()));
        let current = UpgradeOriginal(Rc::new(()));
        let dropped = Rc::new(Cell::new(0));
        let slot = LifecycleUpgrade::new(Rc::new(Cell::new(false)));
        slot.register(delegate(&origin, &dropped), |g| {
            g.session = Some(origin.clone());
            g.current = Some(first.clone());
            Ok(())
        })
        .unwrap();
        slot.inspect(false, |g| {
            g.current = Some(current.clone());
            assert!(!Rc::ptr_eq(&g.current.as_ref().unwrap().0, &first.0));
            assert!(Rc::ptr_eq(&g.current.as_ref().unwrap().0, &current.0));
            Ok(())
        })
        .unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| {
            slot.inspect(false, |_| {
                if unwind {
                    panic!("late native delegate unwound");
                }
                Err::<(), _>(Error::Native)
            })
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), Err(Error::Native));
        }
        slot.inspect(true, |g| {
            assert!(Rc::ptr_eq(&g.current.as_ref().unwrap().0, &current.0));
            Ok(())
        })
        .unwrap();
        assert!(slot.inspect(false, |_| Ok(())).is_err());
        assert_eq!(dropped.get(), 0);
    }
}

#[test]
fn lifecycle_upgrade_caught_nested_borrow_failure_is_sticky_and_does_not_drop_original() {
    use std::{cell::Cell, rc::Rc};
    let origin = UpgradeOriginal(Rc::new(()));
    let dropped = Rc::new(Cell::new(0));
    let slot = LifecycleUpgrade::new(Rc::new(Cell::new(false)));
    slot.register(delegate(&origin, &dropped), |_| Ok(()))
        .unwrap();
    assert!(slot
        .inspect(false, |_| {
            assert!(slot.inspect(false, |_| Ok(())).is_err());
            Ok(())
        })
        .is_err());
    assert!(slot.inspect(false, |_| Ok(())).is_err());
    assert_eq!(dropped.get(), 0);
}

#[test]
fn lifecycle_upgrade_successful_cleanup_entry_alone_retires_all_forward_aliases() {
    use std::{cell::Cell, rc::Rc};
    let signal = Rc::new(Cell::new(false));
    let origin = UpgradeOriginal(Rc::new(()));
    let dropped = Rc::new(Cell::new(0));
    let slot = LifecycleUpgrade::new(signal.clone());
    slot.register(delegate(&origin, &dropped), |_| Ok(()))
        .unwrap();
    slot.inspect(true, |_| Ok(())).unwrap();
    assert!(signal.get());
    assert!(slot.inspect(false, |_| Ok(())).is_err());
    slot.inspect(true, |_| Ok(())).unwrap();
    assert_eq!(dropped.get(), 0);
    drop(slot);
    assert!(
        signal.get(),
        "Drop cannot revive an independently retained forward alias"
    );
}

fn native_record() -> Record {
    let bindings = std::array::from_fn(|i| {
        let b = (i + 1) as u8;
        Binding {
            role: [Role::RoleCarrier, Role::MemberA, Role::MemberB][i],
            guid: [b; 16],
            name: ["carrier-c", "member-a", "member-b"][i].into(),
            registry_path: format!(
                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{{{b:02X}{b:02X}{b:02X}{b:02X}-{b:02X}{b:02X}-{b:02X}{b:02X}-{b:02X}{b:02X}-{b:02X}{b:02X}{b:02X}{b:02X}{b:02X}{b:02X}}}"
            ),
        }
    });
    Record {
        version: 2,
        context: receipts::Context {
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
        generation: 5,
        phase: Phase::Preparing,
        keys: std::array::from_fn(|i| KeyReceipt {
            role: [Role::RoleCarrier, Role::MemberA, Role::MemberB][i],
            phase: if i == 0 {
                KeyPhase::Disabled
            } else {
                KeyPhase::Unstarted
            },
            new_key_ack: i == 0,
            baseline: Value::Absent,
            current: if i == 0 {
                Value::DwordZero
            } else {
                Value::Absent
            },
            pending: None,
        }),
        native_rows: FullNativeRows::Unbound,
    }
}
fn carrier_scope(r: &Record) -> creators::Scope {
    creators::Scope {
        context: r.context.clone(),
        binding: r.context.bindings[0].clone(),
        generation: r.generation,
    }
}
fn original(r: &Record) -> creators::OriginalIdentity {
    creators::OriginalIdentity {
        scope: carrier_scope(r),
        identity: creators::Identity {
            guid: r.context.bindings[0].guid,
            luid: 90,
            index: 7,
            name: r.context.bindings[0].name.clone(),
            description: "Nelomai carrier".into(),
            if_type: 53,
            tunnel_type: 0,
        },
    }
}
fn ready_pair(native: &Record) -> crate::member_carrier_pair::Record {
    use crate::member_carrier_pair as pair;
    pair::Record {
        version: 2,
        scope: native.context.intent.scope.clone(),
        provenance: native.context.provenance.clone(),
        revision: 3,
        phase: pair::Phase::Starting,
        addresses: native.context.intent.addresses.clone(),
        dns: vec![],
        carrier: None,
        members: [None, None],
        active: None,
        options: Some(nelomai_client_tunnel::DesktopTunnelOptions::default()),
        guard: crate::member_carrier_guard::Model::empty(native.context.intent.scope.clone())
            .unwrap(),
        pending_guard: None,
        pending: Some(pair::Effect::CarrierReady),
        network: None,
        stop_stage: 0,
        operation: Some(pair::Operation::Start(
            nelomai_client_tunnel::redundancy::Slot::A,
        )),
    }
}

#[test]
fn carrier_ready_pair_comparison_requires_exact_unselected_initial_operation() {
    let native = native_record();
    let pair = ready_pair(&native);
    pair.validate().unwrap();
    validate_carrier_ready_pair(&native, &pair).unwrap();
    for fault in 0..10 {
        let mut changed = pair.clone();
        use crate::member_carrier_pair as p;
        use nelomai_client_tunnel::redundancy::Slot;
        match fault {
            0 => changed.phase = p::Phase::Running,
            1 => changed.pending = Some(p::Effect::MemberStart(Slot::A)),
            2 => changed.operation = Some(p::Operation::Attach(Slot::A)),
            3 => {
                changed.carrier = Some(crate::member_owner::InterfaceProof {
                    index: 7,
                    luid: 90,
                    guid: [1; 16],
                })
            }
            4 => changed.active = Some(Slot::A),
            5 => changed.options = None,
            6 => changed.stop_stage = 1,
            7 => changed.addresses = vec!["10.7.0.3/32".parse().unwrap()],
            8 => changed.provenance.network_epoch += 1,
            9 => {
                changed.network = Some(p::NetworkState {
                    baseline: p::NetworkSnapshot {
                        routes: vec![],
                        dns: None,
                    },
                    current: p::NetworkSnapshot {
                        routes: vec![],
                        dns: None,
                    },
                    pending: None,
                })
            }
            _ => unreachable!(),
        }
        assert!(
            validate_carrier_ready_pair(&native, &changed).is_err(),
            "fault {fault}"
        );
    }
}

#[test]
fn startup_projection_distinguishes_absent_c_from_same_original_c() {
    let r = native_record();
    receipts::validate_record(&r).unwrap();
    let scope = carrier_scope(&r);
    for stage in [StartupStage::Resolve, StartupStage::BeforeCreate] {
        validate_startup(&r, &scope, stage, &[]).unwrap();
        assert!(validate_startup(&r, &scope, stage, &[original(&r)]).is_err());
    }
    for stage in [
        StartupStage::BeforeSession,
        StartupStage::BeforeDrain,
        StartupStage::AddressCreate,
    ] {
        validate_startup(&r, &scope, stage, &[original(&r)]).unwrap();
        assert!(validate_startup(&r, &scope, stage, &[]).is_err());
    }
    validate_startup(&r, &scope, StartupStage::Observe, &[]).unwrap();
    validate_startup(&r, &scope, StartupStage::Observe, &[original(&r)]).unwrap();
}

fn closing_pair(native: &Record, stage: u8) -> crate::member_carrier_pair::Record {
    use crate::member_carrier_pair as p;
    let mut pair = ready_pair(native);
    pair.phase = p::Phase::Closing;
    pair.operation = None;
    pair.stop_stage = stage;
    pair.pending = Some(match stage {
        6 => p::Effect::CarrierAddressDelete,
        7 => p::Effect::CarrierSessionEnd,
        8 => p::Effect::CarrierClose,
        _ => unreachable!(),
    });
    pair.carrier = Some(crate::member_owner::InterfaceProof {
        index: 7,
        luid: 90,
        guid: [1; 16],
    });
    pair
}

#[test]
fn c_only_closing_comparison_requires_exact_stop_stage_and_original_or_closed_absence() {
    let mut native = native_record();
    let scope = carrier_scope(&native);
    native.phase = Phase::Closing;
    native.generation += 1; // actual durable Closing advances, original scope stays
    for (step, stage) in [
        (6, ClosingStage::AddressDelete),
        (7, ClosingStage::SessionEnd),
        (8, ClosingStage::CarrierClose),
    ] {
        let pair = closing_pair(&native, step);
        pair.validate().unwrap();
        let original = original(&native);
        // Opaque original creation scope is the pre-Closing scope, not a guess
        // reconstructed from today's incremented journal revision.
        let original = creators::OriginalIdentity {
            scope: scope.clone(),
            ..original
        };
        validate_c_only_closing(&native, &scope, &pair, stage, &[original.clone()]).unwrap();
        validate_c_only_closing(&native, &scope, &pair, ClosingStage::Observe, &[original])
            .unwrap();
        assert!(validate_c_only_closing(&native, &scope, &pair, stage, &[]).is_err());
    }
    let pair = closing_pair(&native, 8);
    validate_c_only_closing(&native, &scope, &pair, ClosingStage::AfterClose, &[]).unwrap();
    assert!(validate_c_only_closing(
        &native,
        &scope,
        &pair,
        ClosingStage::AfterClose,
        &[creators::OriginalIdentity {
            scope: scope.clone(),
            ..original(&native)
        }]
    )
    .is_err());
}

#[test]
fn c_only_closing_comparison_rejects_foreign_live_or_unfinished_resources() {
    let mut native = native_record();
    let scope = carrier_scope(&native);
    native.phase = Phase::Closing;
    let original = original(&native);
    for fault in 0..12 {
        let mut n = native.clone();
        let mut pair = closing_pair(&native, 7);
        let mut originals = vec![original.clone()];
        match fault {
            0 => n.phase = Phase::Preparing,
            1 => n.generation = scope.generation - 1,
            2 => n.keys[0].new_key_ack = false,
            3 => n.keys[1].phase = KeyPhase::CreatePending,
            4 => pair.phase = crate::member_carrier_pair::Phase::Starting,
            5 => pair.pending = Some(crate::member_carrier_pair::Effect::CarrierClose),
            6 => pair.stop_stage = 8,
            7 => {
                pair.operation = Some(crate::member_carrier_pair::Operation::Start(
                    nelomai_client_tunnel::redundancy::Slot::A,
                ))
            }
            8 => pair.carrier.as_mut().unwrap().luid += 1,
            9 => originals[0].scope.generation += 1,
            10 => originals[0].identity.name = "foreign-c".into(),
            11 => originals.push(original.clone()),
            _ => unreachable!(),
        }
        assert!(
            validate_c_only_closing(&n, &scope, &pair, ClosingStage::SessionEnd, &originals)
                .is_err(),
            "fault {fault}"
        );
    }
}

#[test]
fn unpublished_close_frame_cannot_adopt_a_pair_carrier_or_later_stage() {
    let mut native = native_record();
    let scope = carrier_scope(&native);
    native.phase = Phase::Closing;
    native.generation += 1;
    let mut pair = closing_pair(&native, 8);
    pair.carrier = None; // raw Create ACK did NOT publish a provider identity
    validate_unpublished_after_close(&native, &scope, &pair).unwrap();
    for fault in 0..8 {
        let mut n = native.clone();
        let mut p = pair.clone();
        match fault {
            0 => {
                p.carrier = Some(crate::member_owner::InterfaceProof {
                    guid: [1; 16],
                    index: 7,
                    luid: 90,
                })
            }
            1 => p.stop_stage = 9,
            2 => p.pending = Some(crate::member_carrier_pair::Effect::NativeEmpty),
            3 => p.phase = crate::member_carrier_pair::Phase::Stopped,
            4 => n.keys[0].new_key_ack = false,
            5 => n.phase = Phase::Stopped,
            6 => p.provenance.network_epoch += 1,
            7 => p.addresses.clear(),
            _ => unreachable!(),
        }
        assert!(
            validate_unpublished_after_close(&n, &scope, &p).is_err(),
            "fault {fault}"
        );
    }
}

#[test]
fn operation_selection_is_monotonic_and_cannot_return_from_closing_to_forward() {
    let n = native_record();
    let ready = ready_pair(&n);
    let mut close = closing_pair(&n, 6);
    close.revision = ready.revision + 1;
    validate_operation_selection(&n.context, &ready, &ready).unwrap();
    validate_operation_selection(&n.context, &ready, &close).unwrap();
    let mut end = closing_pair(&n, 7);
    end.revision = close.revision + 1;
    validate_operation_selection(&n.context, &close, &end).unwrap();
    for fault in 0..8 {
        let mut changed = end.clone();
        match fault {
            0 => changed.scope.connection_generation += 1,
            1 => changed.provenance.network_epoch += 1,
            2 => changed.revision = close.revision - 1,
            3 => changed.revision = close.revision,
            4 => changed.stop_stage = 5,
            5 => {
                changed.phase = crate::member_carrier_pair::Phase::Starting;
                changed.stop_stage = 0;
                changed.operation = ready.operation;
                changed.pending = ready.pending;
            }
            6 => changed.addresses = vec!["10.7.0.3/32".parse().unwrap()],
            7 => changed.phase = crate::member_carrier_pair::Phase::Stopped,
            _ => unreachable!(),
        }
        assert!(
            validate_operation_selection(&n.context, &close, &changed).is_err(),
            "fault {fault}"
        );
    }
    assert!(validate_operation_selection(&n.context, &close, &ready).is_err());
}

#[test]
fn startup_projection_rejects_member_keys_foreign_originals_and_stale_generation() {
    let r = native_record();
    let scope = carrier_scope(&r);
    for fault in 0..11 {
        let mut changed = r.clone();
        let mut originals = vec![original(&r)];
        let mut scope = scope.clone();
        match fault {
            0 => changed.phase = Phase::Closing,
            1 => changed.generation += 1,
            2 => scope.generation += 1,
            3 => changed.keys[0].new_key_ack = false,
            4 => changed.keys[1].phase = KeyPhase::CreatePending,
            5 => originals[0].scope.generation += 1,
            6 => originals[0].identity.guid = [9; 16],
            7 => originals[0].identity.name = "foreign".into(),
            8 => originals[0].identity.index = 0,
            9 => originals[0].identity.if_type = 6,
            10 => originals.push(original(&r)),
            _ => unreachable!(),
        }
        assert!(
            validate_startup(&changed, &scope, StartupStage::AddressCreate, &originals).is_err(),
            "fault {fault}"
        );
    }
}

// Complete factual Sample, using the existing hand-derived row policy fixture.
fn ready_gate_sample() -> Sample {
    use crate::member_carrier_rows::*;
    let record = native_record();
    let original = original(&record);
    let mut snapshot = Snapshot {
        interface: InterfaceRow {
            key: RowKey {
                luid: 3300,
                index: 33,
            },
            policy: InterfacePolicy {
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
                site_prefix_length: 0,
                metric: 42,
                mtu: 1420,
                disable_default_routes: true,
            },
            observed: InterfaceObserved {
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

    snapshot.address = Some(AddressRow {
        key: snapshot.interface.key,
        policy: AddressPolicy {
            address: [10, 77, 0, 2],
            prefix_origin: 1,
            suffix_origin: 1,
            valid_lifetime: u32::MAX,
            preferred_lifetime: u32::MAX,
            on_link_prefix_length: 32,
            skip_as_source: false,
        },
        observed: AddressObserved {
            dad_state: 4,
            scope_id: 0,
            creation_timestamp: 100,
        },
    });
    let provider = provider::Observation {
        interface: provider::Expected {
            guid: original.identity.guid,
            luid: original.identity.luid,
            index: original.identity.index,
            name: original.identity.name.clone(),
            description: original.identity.description.clone(),
            if_type: 53,
            tunnel_type: 0,
        },
        instance: provider::Device {
            instance: "ROOT\\WINTUN\\0000".into(),
            devinst: 1,
            presence: provider::Presence::Present,
            class_guid: [1; 16],
            status: 0,
            problem: 0,
            hardware_ids: vec!["Wintun".into()],
            compatible_ids: vec![],
            service: "Wintun".into(),
            description: original.identity.description.clone(),
            name: original.identity.name.clone(),
            wireguard_name: None,
            standard_name: None,
            netcfg_instance_id: "original-C".into(),
            net_luid_index: 1,
            if_type: 53,
            driver: provider::DriverMetadata {
                provider: "WireGuard LLC".into(),
                version: "0.14.1.0".into(),
                date_filetime: 1,
                inf: "oem1.inf".into(),
                matching_device_id: "Wintun".into(),
                driver_key: "0000".into(),
            },
        },
    };
    Sample {
        native: record.encode().unwrap(),
        rows: Some(b"protected rows".to_vec()),
        originals: creators::UniverseObservation {
            context: record.context,
            originals: vec![creators::Observation {
                scope: original.scope,
                identity: original.identity,
                provider: provider.clone(),
            }],
            complete: vec![(provider::ProviderKind::Wintun, provider)],
        },
        snapshot: Some(snapshot),
    }
}

#[test]
fn ready_gate_sample_accepts_readonly_row_drift() {
    let before = ready_gate_sample();
    let mut after = before.clone();
    let snapshot = after.snapshot.as_mut().unwrap();
    snapshot.interface.observed.connected = false;
    snapshot.interface.observed.reachable_time += 1000;
    snapshot.interface.observed.supports_wake_up_patterns = true;
    snapshot
        .interface
        .observed
        .min_router_advertisement_interval += 1;
    snapshot
        .interface
        .observed
        .max_router_advertisement_interval += 1;
    snapshot.interface.observed.transmit_offload = 1;
    snapshot.interface.observed.receive_offload = 2;
    snapshot.address.as_mut().unwrap().observed.dad_state = 2;
    assert_ne!(
        before.snapshot, after.snapshot,
        "readonly facts remain observable"
    );
    assert_eq!(before, after, "readonly facts are not owned CAS fields");
}

#[test]
fn ready_gate_sample_rejects_owned_rows_protected_bytes_and_full_provider_drift() {
    for mutate in [
        (|s: &mut Sample| s.snapshot.as_mut().unwrap().interface.key.index += 1) as fn(&mut Sample),
        |s| s.snapshot.as_mut().unwrap().interface.policy.metric += 1,
        |s| {
            s.snapshot
                .as_mut()
                .unwrap()
                .address
                .as_mut()
                .unwrap()
                .key
                .index += 1
        },
        |s| {
            s.snapshot
                .as_mut()
                .unwrap()
                .address
                .as_mut()
                .unwrap()
                .policy
                .address[3] += 1
        },
        |s| {
            s.snapshot
                .as_mut()
                .unwrap()
                .address
                .as_mut()
                .unwrap()
                .observed
                .scope_id += 1
        },
        |s| {
            s.snapshot
                .as_mut()
                .unwrap()
                .address
                .as_mut()
                .unwrap()
                .observed
                .creation_timestamp += 1
        },
        |s| s.snapshot.as_mut().unwrap().address = None,
        |s| s.snapshot = None,
        |s| s.native.push(0),
        |s| s.rows.as_mut().unwrap().push(0),
        |s| s.rows = None,
        |s| s.originals.context.provenance.boot_id[0] ^= 1,
        |s| s.originals.originals[0].scope.generation += 1,
        |s| s.originals.originals[0].identity.index += 1,
        |s| s.originals.originals[0].provider.instance.problem = 22,
        |s| s.originals.complete[0].1.instance.problem = 22,
        |s| s.originals.complete.clear(),
    ] {
        let before = ready_gate_sample();
        let mut after = before.clone();
        mutate(&mut after);
        assert_ne!(before, after);
    }
    let mut absent = ready_gate_sample();
    absent.snapshot = None;
    assert_eq!(absent, absent.clone());
}
