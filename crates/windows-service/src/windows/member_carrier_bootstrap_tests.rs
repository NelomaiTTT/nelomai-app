//! Portable retention tests, also included in the real crate test suite.
//! The only double is an opaque returned SDK owner with observable destruction.
use super::{LoadError, LoadSlot};

#[test]
fn module_only_original_load_read_checks_retained_owner_without_consuming_effect_borrow() {
    let drops = Rc::new(Cell::new(0));
    let mut source = LoadSlot::empty();
    source
        .load_into(
            &mut (),
            |_| Ok::<_, &str>(()),
            |_, slot| {
                *slot = Some(SdkOwner(drops.clone()));
                Ok(())
            },
            |_, _| Ok(()),
        )
        .unwrap();
    let mut read = None;
    source
        .retain_module_only_read_into(&mut read, |_| Ok::<_, &str>(()))
        .unwrap();
    let read = read.unwrap();
    for _ in 0..2 {
        source
            .verify_original_loaded_read(&read, |owner| {
                assert!(Rc::ptr_eq(&owner.0, &drops));
                assert_eq!(drops.get(), 0);
                Ok::<_, &str>(())
            })
            .unwrap();
    }
    assert_eq!(
        source.verify_original_loaded_read(&read, |_| Err("foreign native ACK")),
        Err(LoadError::Boundary("foreign native ACK"))
    );
    assert!(source.acknowledged.is_some());
    let foreign = LoadSlot::<SdkOwner>::empty();
    assert!(foreign
        .verify_original_loaded_read(&read, |_| -> Result<(), &str> {
            panic!("foreign loader must deny before native receipt comparison")
        })
        .is_err());
    source
        .with_original_module_only(&read, |owner| {
            assert!(Rc::ptr_eq(&owner.0, &drops));
            Ok::<_, &str>(())
        })
        .unwrap();
    assert_eq!(drops.get(), 0);
    drop(source);
    assert_eq!(drops.get(), 0);
}

#[test]
fn module_only_original_load_read_denies_partial_wrapper_and_transferred_owner() {
    for partial in [true, false] {
        let mut source = LoadSlot::empty();
        let _ = source.load_into(
            &mut (),
            |_| Ok::<_, &str>(()),
            |_, slot| {
                *slot = Some(SdkOwner(Rc::new(Cell::new(0))));
                if partial {
                    Err("unknown internal load")
                } else {
                    Ok(())
                }
            },
            |_, _| Ok(()),
        );
        let mut read = None;
        let _ = source.retain_module_only_read_into(&mut read, |_| Ok::<_, &str>(()));
        let read = read.unwrap();
        if !partial {
            let mut raw = None;
            source
                .drain_terminal_into(&mut raw, |_| Ok::<_, &str>(()))
                .unwrap();
        }
        assert!(source
            .verify_original_loaded_read(&read, |_| -> Result<(), &str> {
                panic!("partial or moved owner must not expose native comparison")
            })
            .is_err());
    }
}

// Break: accepting the pre-load owning wrapper as a native ACK, losing the
// retained candidate on postflight faults, or using an equal foreign loader.
#[test]
fn module_only_load_read_distinguishes_returned_boundary_from_partial_wrapper() {
    for stage in 0..4 {
        let drops = Rc::new(Cell::new(0));
        let mut source = LoadSlot::empty();
        if stage != 0 {
            let result = source.load_into(
                &mut (),
                |_| Ok(()),
                |_, owner| {
                    *owner = Some(SdkOwner(drops.clone()));
                    if stage == 1 {
                        Err("unknown load return")
                    } else {
                        Ok(())
                    }
                },
                |_, _| {
                    if stage == 2 {
                        Err("after load return")
                    } else {
                        Ok(())
                    }
                },
            );
            assert_eq!(result.is_ok(), stage == 3);
        }
        let mut retained = None;
        let result = source.retain_module_only_read_into(&mut retained, |_| Ok::<_, &str>(()));
        assert_eq!(result.is_ok(), stage >= 2);
        let read = retained
            .as_ref()
            .expect("candidate rooted before validation");
        assert_eq!(source.verify_module_only_read(read).is_ok(), stage >= 2);
        let foreign = LoadSlot::<SdkOwner>::empty();
        assert!(foreign.verify_module_only_read(read).is_err());
        assert!(source
            .retain_module_only_read_into(&mut None, |_| Ok::<_, &str>(()))
            .is_err());
        drop(source);
        assert_eq!(
            drops.get(),
            0,
            "unknown loader Drop must not dispose originals"
        );
    }
}

#[test]
fn module_only_load_read_retains_first_pin_on_error_unwind_and_swallowed_reentry() {
    for fault in 0..3 {
        let mut source = LoadSlot::empty();
        source
            .load_into(
                &mut (),
                |_| Ok::<_, &str>(()),
                |_, slot| {
                    *slot = Some(SdkOwner(Rc::new(Cell::new(0))));
                    Ok(())
                },
                |_, _| Ok(()),
            )
            .unwrap();
        let mut destination = None;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            source.retain_module_only_read_into(&mut destination, |actual| match fault {
                0 => Err("capture postflight"),
                1 => panic!("capture unwind"),
                _ => {
                    assert!(source
                        .retain_module_only_read_into(&mut None, |_| Ok::<_, &str>(()))
                        .is_err());
                    assert!(actual.same_loader(&source));
                    Ok(())
                }
            })
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        let read = destination.unwrap();
        assert!(read.same_loader(&source));
        assert!(source.verify_module_only_read(&read).is_err());
    }
}

// Break: handing the original through Result, dropping it on close/postflight
// error/unwind, or permitting a repeated external effect after uncertainty.
#[test]
fn module_only_original_borrow_keeps_owner_rooted_and_never_repeats_callback() {
    for fault in 0..4 {
        let drops = Rc::new(Cell::new(0));
        let mut source = LoadSlot::empty();
        source
            .load_into(
                &mut (),
                |_| Ok::<_, &str>(()),
                |_, slot| {
                    *slot = Some(SdkOwner(drops.clone()));
                    Ok(())
                },
                |_, _| Ok(()),
            )
            .unwrap();
        let mut read = None;
        source
            .retain_module_only_read_into(&mut read, |_| Ok::<_, &str>(()))
            .unwrap();
        let read = read.unwrap();
        let calls = Cell::new(0);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            source.with_original_module_only(&read, |owner| {
                calls.set(calls.get() + 1);
                assert!(Rc::ptr_eq(&owner.0, &drops));
                assert_eq!(drops.get(), 0);
                match fault {
                    0 => Ok(()),
                    1 => Err("external close error"),
                    2 => panic!("external close unwind"),
                    _ => {
                        assert!(read.call.run(|| Ok(())).is_err());
                        Ok(())
                    }
                }
            })
        }));
        assert_eq!(calls.get(), 1);
        assert_eq!(
            result.is_ok() && result.as_ref().unwrap().is_ok(),
            fault == 0
        );
        assert_eq!(drops.get(), 0);
        assert!(source
            .with_original_module_only(&read, |_| {
                calls.set(calls.get() + 1);
                Ok::<_, &str>(())
            })
            .is_err());
        assert_eq!(calls.get(), 1);
        assert!(source.acknowledged.is_some());
        drop(source);
        assert_eq!(drops.get(), 0);
    }
}

use std::{cell::Cell, rc::Rc};

// Break: an attempted/failed release or an equal foreign raw loader can
// authorize disposition, or the external native-ACK comparison is skipped.
#[test]
fn module_only_terminal_transfer_requires_completed_original_release() {
    for fault in 0..3 {
        let mut original = LoadSlot::empty();
        original
            .load_into(
                &mut (),
                |_| Ok::<_, &str>(()),
                |_, slot| {
                    *slot = Some(31u32);
                    Ok(())
                },
                |_, _| Ok(()),
            )
            .unwrap();
        let mut read = None;
        original
            .retain_module_only_read_into(&mut read, |_| Ok::<_, &str>(()))
            .unwrap();
        let read = read.unwrap();
        let release = original.with_original_module_only(&read, |value| {
            *value = 47;
            if fault == 1 {
                return Err("native ACK lost");
            }
            Ok(())
        });
        assert_eq!(release.is_ok(), fault != 1);
        let mut raw = None;
        original
            .drain_terminal_into(&mut raw, |_| Ok::<_, &str>(()))
            .unwrap();
        let checks = Cell::new(0);
        let result =
            original.verify_module_only_terminal_cut(raw.as_ref().unwrap(), &read, |value| {
                checks.set(checks.get() + 1);
                assert_eq!(*value, 47);
                if fault == 2 {
                    return Err("native disposition unknown");
                }
                Ok(())
            });
        assert_eq!(result.is_ok(), fault == 0);
        assert_eq!(checks.get(), usize::from(fault != 1));
        let foreign = LoadSlot::<u32>::empty();
        assert!(foreign
            .verify_module_only_terminal_cut(
                raw.as_ref().unwrap(),
                &read,
                |_| -> Result<(), &str> { panic!("foreign cannot query native") }
            )
            .is_err());
        assert!(original.acknowledged.is_none());
        assert_eq!(raw.as_ref().unwrap().acknowledged, Some(47));
    }
}

#[cfg(not(windows))]
use crate::member_carrier_assembly::TerminalResources;
#[cfg(windows)]
use crate::windows::member_carrier_assembly::TerminalResources;

// Break: moving the WHOLE old LoadSlot preserves its unknown-retaining Drop
// inside a supposedly inert terminal C. Cut the actual owning field instead;
// caller roots must still retain it on every registration failure/unwind.
#[test]
fn terminal_load_cut_retains_same_owner_before_postflight_and_disarms_only_source_shell() {
    let unloaded = Rc::new(Cell::new(0));
    let mut source = LoadSlot::empty();
    source
        .load_into(
            &mut (),
            |_| Ok::<_, ()>(()),
            |_, owner| {
                *owner = Some(SdkOwner(unloaded.clone()));
                Ok(())
            },
            |_, _| Ok(()),
        )
        .unwrap();
    let mut output = TerminalResources::new(None);
    assert_eq!(
        source.drain_terminal_into(output.retained_mut(), |raw| {
            assert!(Rc::ptr_eq(&raw.acknowledged.as_ref().unwrap().0, &unloaded));
            Err("postflight")
        }),
        Err(LoadError::Boundary("postflight"))
    );
    assert!(source.acknowledged.is_none());
    let raw = output.retained().as_ref().unwrap();
    source.verify_terminal_transfer(raw).unwrap();
    assert!(source
        .load_into(
            &mut (),
            |_| panic!("terminal cannot reopen"),
            |_, _| panic!("terminal cannot reload"),
            |_, _| Ok::<_, ()>(())
        )
        .is_err());
    drop(source);
    assert_eq!(unloaded.get(), 0);
    drop(output); // unknown caller root never unloads transferred originals
    assert_eq!(unloaded.get(), 0);
}

#[test]
fn terminal_load_cut_keeps_partial_internal_ack_on_unwind_and_rejects_foreign_output() {
    let unloaded = Rc::new(Cell::new(0));
    let mut source = LoadSlot::empty();
    assert_eq!(
        source.load_into(
            &mut (),
            |_| Ok(()),
            |_, owner| {
                *owner = Some(SdkOwner(unloaded.clone()));
                Err("internal postflight")
            },
            |_, _| Ok(())
        ),
        Err(LoadError::Boundary("internal postflight"))
    );
    let mut output = TerminalResources::new(None);
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        source.drain_terminal_into(output.retained_mut(), |_| panic!("terminal registration"))
            as Result<(), LoadError<()>>
    }))
    .is_err());
    let raw = output.retained().as_ref().unwrap();
    source.verify_terminal_transfer(raw).unwrap();
    let foreign = LoadSlot::<SdkOwner>::empty();
    assert!(foreign.verify_terminal_transfer(raw).is_err());
    assert!(source
        .drain_terminal_into(output.retained_mut(), |_| Ok::<_, ()>(()))
        .is_err());
    drop(source);
    drop(output);
    assert_eq!(unloaded.get(), 0);
}

#[test]
fn terminal_load_unknown_absent_ack_does_not_mint_loaded_owner_or_allow_reload() {
    let mut source = LoadSlot::<SdkOwner>::empty();
    assert_eq!(
        source.load_into(
            &mut (),
            |_| Ok(()),
            |_, _| Err("lost load ACK"),
            |_, _| Ok(())
        ),
        Err(LoadError::Boundary("lost load ACK"))
    );
    let mut output = TerminalResources::new(None);
    source
        .drain_terminal_into(output.retained_mut(), |_| Ok::<_, ()>(()))
        .unwrap();
    let raw = output.retained().as_ref().unwrap();
    assert!(raw.attempted);
    assert!(raw.acknowledged.is_none());
    source.verify_terminal_transfer(raw).unwrap(); // ownership cut ONLY
    assert!(source
        .load_into(
            &mut (),
            |_| panic!("reopen"),
            |_, _| panic!("reopen"),
            |_, _| Ok::<_, ()>(())
        )
        .is_err());
}

#[test]
fn terminal_module_separation_retains_same_sdk_owner_outside_resource_t_before_error() {
    let unloaded = Rc::new(Cell::new(0));
    let mut source = LoadSlot::empty();
    source
        .load_into(
            &mut (),
            |_| Ok::<_, ()>(()),
            |_, owner| {
                *owner = Some(SdkOwner(unloaded.clone()));
                Ok(())
            },
            |_, _| Ok(()),
        )
        .unwrap();
    let mut raw = TerminalResources::new(None);
    source
        .drain_terminal_into(raw.retained_mut(), |_| Ok::<_, ()>(()))
        .unwrap();
    let mut modules = TerminalResources::new(Vec::new());
    let raw = raw.retained_mut().as_mut().unwrap();
    assert_eq!(
        raw.separate_module_into(modules.retained_mut(), |module| {
            assert!(Rc::ptr_eq(
                &module.original().map_err(|_| "missing")?.0,
                &unloaded
            ));
            Err("postflight")
        }),
        Err(LoadError::Boundary("postflight"))
    );
    raw.verify_module_transfer(&modules.retained()[0]).unwrap();
    assert!(raw.acknowledged.is_none());
    assert!(raw
        .separate_module_into(modules.retained_mut(), |_| Ok::<_, &str>(()))
        .is_err());
    drop(source);
    drop(modules); // separate unknown module root, NOT inert resource T
    assert_eq!(unloaded.get(), 0);
}

#[test]
fn terminal_module_separation_unwind_and_occupied_foreign_read_never_recreate_owner() {
    let unloaded = Rc::new(Cell::new(0));
    let mut source = LoadSlot::empty();
    source
        .load(
            &mut (),
            |_| Ok::<_, ()>(()),
            |_| Ok(SdkOwner(unloaded.clone())),
            |_, _| Ok(()),
        )
        .unwrap();
    let mut raw = TerminalResources::new(None);
    source
        .drain_terminal_into(raw.retained_mut(), |_| Ok::<_, ()>(()))
        .unwrap();
    let mut modules = TerminalResources::new(Vec::new());
    let raw = raw.retained_mut().as_mut().unwrap();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        raw.separate_module_into(modules.retained_mut(), |_| panic!("after separation"))
            as Result<(), LoadError<()>>
    }))
    .is_err());
    raw.verify_module_transfer(&modules.retained()[0]).unwrap();
    let mut foreign = LoadSlot::<SdkOwner>::empty();
    let mut foreign_raw = TerminalResources::new(None);
    foreign
        .drain_terminal_into(foreign_raw.retained_mut(), |_| Ok::<_, ()>(()))
        .unwrap();
    assert!(foreign_raw
        .retained()
        .as_ref()
        .unwrap()
        .verify_module_transfer(&modules.retained()[0])
        .is_err());
    drop(modules);
    assert_eq!(unloaded.get(), 0);
}

#[test]
fn terminal_module_unknown_wrapper_absence_is_not_a_loaded_module_receipt() {
    let mut source = LoadSlot::<SdkOwner>::empty();
    source
        .load_into(&mut (), |_| Ok(()), |_, _| Err("unknown"), |_, _| Ok(()))
        .unwrap_err();
    let mut raw = TerminalResources::new(None);
    source
        .drain_terminal_into(raw.retained_mut(), |_| Ok::<_, ()>(()))
        .unwrap();
    let mut modules = TerminalResources::new(Vec::new());
    let raw = raw.retained_mut().as_mut().unwrap();
    raw.separate_module_into(modules.retained_mut(), |_| Ok::<_, ()>(()))
        .unwrap();
    raw.verify_module_transfer(&modules.retained()[0]).unwrap(); // ownership only
    assert!(modules.retained()[0].original().is_err());
}

struct SdkOwner(Rc<Cell<u32>>);
impl Drop for SdkOwner {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}

#[test]
fn terminal_module_raw_cut_does_not_carry_unknown_retaining_destructor_after_explicit_owning_transfer(
) {
    let drops = Rc::new(Cell::new(0));
    let mut source = LoadSlot::empty();
    source
        .load(
            &mut (),
            |_| Ok::<_, ()>(()),
            |_| Ok(SdkOwner(drops.clone())),
            |_, _| Ok(()),
        )
        .unwrap();
    let mut raw = TerminalResources::new(None);
    source
        .drain_terminal_into(raw.retained_mut(), |_| Ok::<_, ()>(()))
        .unwrap();
    let mut modules = TerminalResources::new(Vec::new());
    raw.retained_mut()
        .as_mut()
        .unwrap()
        .separate_module_into(modules.retained_mut(), |_| Ok::<_, ()>(()))
        .unwrap();
    drop(source);
    drop(raw); // transferred shell no longer owns ANY SDK owner
    assert_eq!(drops.get(), 0);
    // Factual owning extraction, NOT a native unload permission. The only
    // double is a plain external return with observable Rust destruction; real
    // LoadedWintun independently requires its actual module-close ACK/permit.
    let mut originals = None;
    modules.transfer_original_into(&mut originals).unwrap();
    drop(originals);
    assert_eq!(drops.get(), 1);
}

#[cfg(windows)]
#[test]
fn native_bootstrap_cut_is_original_once_even_without_module_ack() {
    use super::native::{NativeBootstrapSlot, NativeBootstrapTerminalParts};
    let mut source = NativeBootstrapSlot::empty();
    let foreign = NativeBootstrapSlot::empty();
    let mut raw = TerminalResources::new(NativeBootstrapTerminalParts::empty());
    source.drain_terminal_into(&mut raw).unwrap();
    source
        .verify_original_terminal_transfer(raw.retained())
        .unwrap();
    assert!(foreign
        .verify_original_terminal_transfer(raw.retained())
        .is_err());
    assert!(raw.retained().original_inputs().is_none()); // facts, NOT absence proof
    let mut modules = TerminalResources::new(Vec::new());
    raw.retained_mut()
        .transfer_loaded_module_into(
            &mut modules,
            |v| v,
            |module| {
                // A pure ownership cut never synthesizes an owning SDK return.
                assert!(module.original().is_err());
                Err(crate::member_carrier::CarrierError::Conflict)
            },
        )
        .unwrap_err();
    raw.retained()
        .verify_original_module_transfer(&modules.retained()[0])
        .unwrap();
    assert!(modules.retained_mut()[0]
        .with_original_loaded_module::<()>(|_| panic!("no reconstructed module"))
        .is_err());
    let mut replacement = TerminalResources::new(NativeBootstrapTerminalParts::empty());
    assert!(source.drain_terminal_into(&mut replacement).is_err());
    assert!(replacement.retained().original_inputs().is_none());
}

#[test]
fn internally_acknowledged_load_survives_loader_error_and_unwind() {
    // A Result<T> loader cannot retain an ACK captured before its own failure.
    for unwind in [false, true] {
        let unloaded = Rc::new(Cell::new(0));
        let mut slot = LoadSlot::empty();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            slot.load_into(
                &mut (),
                |_| Ok(()),
                |_, original| {
                    *original = Some(SdkOwner(unloaded.clone()));
                    if unwind {
                        panic!("inspection after internal ACK")
                    }
                    Err("internal postflight")
                },
                |_, _| panic!("failed loader must not continue"),
            )
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert_eq!(
                result.unwrap(),
                Err(LoadError::Boundary("internal postflight"))
            );
        }
        assert!(slot.acknowledged.is_some());
        assert_eq!(unloaded.get(), 0);
        assert_eq!(
            slot.load_into(
                &mut (),
                |_| panic!("repeat"),
                |_, _| panic!("repeat"),
                |_, _| Ok::<_, &str>(())
            ),
            Err(LoadError::AlreadyAttempted)
        );
        drop(slot);
        assert_eq!(unloaded.get(), 0);
    }
}

#[test]
fn successful_loader_without_original_ack_cannot_pass_postflight_or_retry() {
    let mut slot = LoadSlot::<u32>::empty();
    assert_eq!(
        slot.load_into(
            &mut (),
            |_| Ok(()),
            |_, _| Ok(()),
            |_, _| panic!("no original ACK")
        ),
        Err(LoadError::<()>::MissingAcknowledgement)
    );
    assert!(slot.acknowledged.is_none());
    assert_eq!(
        slot.load_into(
            &mut (),
            |_| panic!("retry"),
            |_, _| panic!("retry"),
            |_, _| Ok::<_, ()>(())
        ),
        Err(LoadError::AlreadyAttempted)
    );
}

#[test]
fn in_place_loader_and_postflight_use_same_ack_and_deny_repeat_on_all_paths() {
    for stage in 0..4 {
        let mut slot = LoadSlot::empty();
        let mut state = 7;
        let outcome = slot.load_into(
            &mut state,
            |state| {
                assert_eq!(*state, 7);
                *state = 8;
                if stage == 0 {
                    Err("preflight")
                } else {
                    Ok(())
                }
            },
            |state, ack| {
                assert_eq!(*state, 8);
                *state = 9;
                *ack = Some(14);
                if stage == 1 {
                    Err("internal postflight")
                } else {
                    Ok(())
                }
            },
            |state, ack| {
                assert_eq!((*state, *ack), (9, 14));
                *state = 10;
                *ack = 15;
                if stage == 2 {
                    Err("postflight")
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(
            outcome,
            match stage {
                0 => Err(LoadError::Boundary("preflight")),
                1 => Err(LoadError::Boundary("internal postflight")),
                2 => Err(LoadError::Boundary("postflight")),
                _ => Ok(()),
            }
        );
        assert_eq!(
            state,
            match stage {
                0 => 8,
                1 => 9,
                _ => 10,
            }
        );
        assert_eq!(
            slot.acknowledged,
            match stage {
                0 => None,
                1 => Some(14),
                _ => Some(15),
            }
        );
        assert_eq!(
            slot.load_into(
                &mut state,
                |_| panic!("retry"),
                |_, _| panic!("retry"),
                |_, _| Ok::<_, &str>(())
            ),
            Err(LoadError::AlreadyAttempted)
        );
    }
}

#[test]
fn acknowledged_load_survives_failed_postflight_without_implicit_unload() {
    // Moving retention after postflight loses the returned native ACK.
    let unloaded = Rc::new(Cell::new(0));
    let mut slot = LoadSlot::empty();
    assert_eq!(
        slot.load(
            &mut (),
            |_| Ok(()),
            |_| Ok(SdkOwner(unloaded.clone())),
            |_, _| Err("postflight")
        ),
        Err(LoadError::Boundary("postflight"))
    );
    assert_eq!(
        unloaded.get(),
        0,
        "native ACK must be retained before postflight"
    );
    assert!(slot.acknowledged.is_some());
    drop(slot);
    assert_eq!(unloaded.get(), 0, "abandonment is not unload authority");
}

#[test]
fn acknowledged_load_survives_postflight_unwind() {
    // Keeping the ACK only on a normal return would unload during unwind.
    let unloaded = Rc::new(Cell::new(0));
    let mut slot = LoadSlot::empty();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        slot.load(
            &mut (),
            |_| Ok::<_, ()>(()),
            |_| Ok(SdkOwner(unloaded.clone())),
            |_, _| panic!("SDK post-load inspection unwound"),
        )
    }));
    assert!(result.is_err());
    assert_eq!(unloaded.get(), 0);
    assert!(slot.acknowledged.is_some());
    drop(slot);
    assert_eq!(unloaded.get(), 0);
}

#[test]
fn load_is_never_repeated_after_preflight_load_postflight_failure_or_success() {
    // Clearing attempted after failure, or overwriting an ACK, repeats loading.
    for failing_stage in 0..4 {
        let unloaded = Rc::new(Cell::new(0));
        let loads = Cell::new(0);
        let mut slot = LoadSlot::empty();
        let first = slot.load(
            &mut (),
            |_| {
                if failing_stage == 0 {
                    Err("preflight")
                } else {
                    Ok(())
                }
            },
            |_| {
                loads.set(loads.get() + 1);
                if failing_stage == 1 {
                    Err("load")
                } else {
                    Ok(SdkOwner(unloaded.clone()))
                }
            },
            |_, _| {
                if failing_stage == 2 {
                    Err("postflight")
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(
            first,
            match failing_stage {
                0 => Err(LoadError::Boundary("preflight")),
                1 => Err(LoadError::Boundary("load")),
                2 => Err(LoadError::Boundary("postflight")),
                _ => Ok(()),
            }
        );
        for _ in 0..2 {
            assert_eq!(
                slot.load(
                    &mut (),
                    |_| panic!("preflight retry"),
                    |_| {
                        loads.set(loads.get() + 1);
                        Ok::<_, &str>(SdkOwner(unloaded.clone()))
                    },
                    |_, _| panic!("postflight retry"),
                ),
                Err(LoadError::AlreadyAttempted)
            );
        }
        assert_eq!(loads.get(), if failing_stage == 0 { 0 } else { 1 });
        assert_eq!(slot.acknowledged.is_some(), failing_stage >= 2);
        assert_eq!(unloaded.get(), 0);
        drop(slot);
        assert_eq!(unloaded.get(), 0);
    }
}

#[test]
fn preflight_or_loader_unwind_denies_second_attempt_without_fabricating_an_ack() {
    // Setting attempted after either callback makes a caught unwind retryable.
    for preflight_unwinds in [false, true] {
        let mut slot = LoadSlot::<SdkOwner>::empty();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            slot.load(
                &mut (),
                |_| {
                    if preflight_unwinds {
                        panic!("preflight unwind");
                    }
                    Ok::<_, ()>(())
                },
                |_| panic!("load unwind before returned ACK"),
                |_, _| Ok(()),
            )
        }));
        assert!(result.is_err());
        assert!(slot.acknowledged.is_none());
        assert_eq!(
            slot.load(
                &mut (),
                |_| panic!("retry preflight"),
                |_| panic!("retry load"),
                |_, _| Ok::<_, ()>(())
            ),
            Err(LoadError::AlreadyAttempted)
        );
    }
}

#[test]
fn original_return_and_same_mutable_state_are_available_to_postflight() {
    // Substituting another object or state loses the actual native return.
    struct Returned {
        identity: Rc<()>,
        observed: u32,
    }
    let identity = Rc::new(());
    let mut native_state = 7;
    let mut slot = LoadSlot::empty();
    slot.load(
        &mut native_state,
        |state| {
            assert_eq!(*state, 7);
            *state = 8;
            Ok::<_, ()>(())
        },
        |state| {
            assert_eq!(*state, 8);
            *state = 9;
            Ok(Returned {
                identity: identity.clone(),
                observed: 14,
            })
        },
        |state, returned| {
            assert_eq!(*state, 9);
            assert!(Rc::ptr_eq(&identity, &returned.identity));
            assert_eq!(returned.observed, 14);
            returned.observed = 15;
            *state = 10;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(native_state, 10);
    let returned = slot.acknowledged.as_ref().unwrap();
    assert_eq!(returned.observed, 15);
    assert!(Rc::ptr_eq(&returned.identity, &identity));
}

#[test]
fn failed_postflight_keeps_changes_to_the_actual_retained_owner() {
    // Returning a clone to postflight would lose partially captured metadata.
    let mut slot = LoadSlot::empty();
    assert_eq!(
        slot.load(
            &mut (),
            |_| Ok(()),
            |_| Ok(14_u32),
            |_, owner| {
                *owner = 15;
                Err("capture failed after returned ACK")
            }
        ),
        Err(LoadError::Boundary("capture failed after returned ACK"))
    );
    assert_eq!(slot.acknowledged, Some(15));
}
