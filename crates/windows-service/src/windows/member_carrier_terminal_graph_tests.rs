use super::*;
use std::{
    cell::{Cell, RefCell},
    panic::{catch_unwind, AssertUnwindSafe},
    rc::Rc,
};

struct Original(Rc<Cell<usize>>);
impl Drop for Original {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}

// Break: dropping a gate/pin on a failed alias read, or exporting the root
// only after fallible postflight. This is the helper used by the native slot.
#[test]
fn pregraph_release_slot_retains_inputs_and_root_before_failed_handoff() {
    for fault in 0..4 {
        let drops = Rc::new(Cell::new(0));
        let inputs = (
            Original(drops.clone()),
            Original(drops.clone()),
            Original(drops.clone()),
        );
        let mut slot = RetainedReleaseInputs::new(inputs);
        let mut exported = None;
        let result = catch_unwind(AssertUnwindSafe(|| {
            slot.construct_into(
                &mut exported,
                |inputs, root| {
                    assert_eq!(drops.get(), 0);
                    if fault == 0 {
                        return Err(conflict());
                    }
                    if fault == 1 {
                        panic!("alias read unwind");
                    }
                    *root = Some(Rc::new(Original(inputs.0 .0.clone())));
                    Ok(())
                },
                |root| {
                    assert_eq!(drops.get(), 0);
                    assert!(
                        Rc::strong_count(root) >= 2,
                        "root exported before postflight"
                    );
                    if fault == 2 {
                        return Err(conflict());
                    }
                    panic!("root postflight unwind");
                },
            )
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert_eq!(exported.is_some(), fault >= 2);
        assert!(slot
            .construct_into(&mut None, |_, _| panic!("repeat"), |_| Ok(()))
            .is_err());
        drop(exported);
        drop(slot);
        assert_eq!(
            drops.get(),
            0,
            "unknown inputs and constructed root stay retained"
        );
    }
}

// Break: retaining an already-authenticated root alias forever (and therefore
// its serialized lease), or disposing inputs/root without the same proof.
#[test]
fn pregraph_release_slot_disposes_known_outputs_only_after_original_check() {
    let drops = Rc::new(Cell::new(0));
    let mut slot = RetainedReleaseInputs::new((Original(drops.clone()), Original(drops.clone())));
    let mut exported = None;
    slot.construct_into(
        &mut exported,
        |_, root| {
            *root = Some(Rc::new(Original(drops.clone())));
            Ok(())
        },
        |_| Ok(()),
    )
    .unwrap();
    let root = exported.as_ref().unwrap();
    let checks = Cell::new(0);
    slot.release_with(root, || {
        // Two checks bracket input disposal; the third authenticates the
        // still-held root before its alias is removed, AFTER inert inputs drop.
        assert_eq!(drops.get(), if checks.get() == 2 { 2 } else { 0 });
        checks.set(checks.get() + 1);
        Ok(())
    })
    .unwrap();
    assert_eq!(checks.get(), 3);
    assert_eq!(drops.get(), 2);
    assert!(slot
        .release_with(root, || panic!("repeat disposal verifier"))
        .is_err());
    drop(exported);
    assert_eq!(
        drops.get(),
        3,
        "no retained root alias after known disposal"
    );
    drop(slot);
    assert_eq!(drops.get(), 3);

    let unknown_drops = Rc::new(Cell::new(0));
    let mut unknown = RetainedReleaseInputs::new(Original(unknown_drops.clone()));
    let mut output = None;
    unknown
        .construct_into(
            &mut output,
            |_, root| {
                *root = Some(Rc::new(Original(unknown_drops.clone())));
                Ok(())
            },
            |_| Ok(()),
        )
        .unwrap();
    assert!(unknown
        .release_with(output.as_ref().unwrap(), || Err(conflict()))
        .is_err());
    drop(output);
    drop(unknown);
    assert_eq!(unknown_drops.get(), 0);
}

// Break: partial pregraph ownership is moved into a temporary before its
// module destination exists, or an Err/unwind/reentry is treated as a cut ACK.
#[test]
fn pregraph_owning_cut_roots_both_original_destinations_before_postflight() {
    for fault in 0..4 {
        let drops = Rc::new(Cell::new(0));
        let original = Rc::new(Original(drops.clone()));
        let mut cut = PregraphOwnershipCut::new(Some(original.clone()), None);
        let result = catch_unwind(AssertUnwindSafe(|| {
            cut.capture(
                |_, _| Ok(()),
                |carrier, module| {
                    *module = carrier.take();
                    if fault == 0 {
                        return Err(conflict());
                    }
                    if fault == 1 {
                        panic!("after real module move");
                    }
                    Ok(())
                },
                |carrier, module, completed| {
                    assert!(carrier.is_none());
                    assert!(Rc::ptr_eq(module.as_ref().unwrap(), &original));
                    assert!(completed.verify().is_err());
                    if fault == 2 {
                        return Err(conflict());
                    }
                    assert!(completed.run(|| Ok(())).is_err());
                    Ok(()) // caught recursive attempt must still deny whole cut
                },
            )
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert!(cut.completed.verify().is_err());
        assert!(Rc::ptr_eq(
            cut.modules.retained().as_ref().unwrap(),
            &original
        ));
        assert!(cut
            .capture(|_, _| panic!("repeat"), |_, _| Ok(()), |_, _, _| Ok(()))
            .is_err());
        drop(original);
        drop(cut);
        assert_eq!(
            drops.get(),
            0,
            "unknown owning output must survive abandonment"
        );
    }
    let drops = Rc::new(Cell::new(0));
    let mut cut = PregraphOwnershipCut::new(Some(Original(drops.clone())), None);
    cut.capture(
        |_, _| Ok(()),
        |c, m| {
            *m = c.take();
            Ok(())
        },
        |c, m, _| {
            assert!(c.is_none());
            assert!(m.is_some());
            Ok(())
        },
    )
    .unwrap();
    cut.completed.verify().unwrap();
    assert_eq!(drops.get(), 0, "owning capture is not resource disposal");
    drop(cut);
    assert_eq!(drops.get(), 0);
}

// Break: selecting one closed controller while overlooking another retained
// owner of the same slot. None here is factual selection only; the actual
// private Never/member ledger must independently authenticate an unused slot.
#[test]
fn terminal_current_owner_selection_denies_extra_equal_and_distinct_originals() {
    let first = Original(Rc::new(Cell::new(0)));
    let foreign = Original(Rc::new(Cell::new(0)));
    assert!(single_current_original::<Original>([]).unwrap().is_none());
    let selected = single_current_original([&first]).unwrap().unwrap();
    assert!(std::ptr::eq(selected, &first));
    assert!(single_current_original([&first, &foreign]).is_err());
    assert!(single_current_original([&first, &first]).is_err());
    assert_eq!(first.0.get(), 0, "selection cannot consume an owner");
    assert_eq!(foreign.0.get(), 0);
}

// Break: retaining an equal foreign receipt instead of the first native
// original, losing that original on callback fault, or treating a factual
// repeat as completion of the enclosing supervised release.
#[test]
fn adapter_receipt_retention_is_same_rc_only_and_never_whole_call_success() {
    for unwind in [false, true] {
        let drops = Rc::new(Cell::new(0));
        let original = Rc::new(Original(drops.clone()));
        let retained = TerminalResources::new(RefCell::new(None));
        let whole = TerminalCallState::new();
        let result = catch_unwind(AssertUnwindSafe(|| {
            whole.run(|| {
                retain_same_receipt(retained.retained(), original.clone())?;
                assert!(Rc::ptr_eq(
                    retained.retained().borrow().as_ref().unwrap(),
                    &original
                ));
                retain_same_receipt(retained.retained(), original.clone())?;
                assert!(whole.verify().is_err());
                if unwind {
                    panic!("adapter reference supervised postflight");
                }
                Err(conflict())
            })
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert!(whole.verify().is_err());
        let equal_foreign = Rc::new(Original(drops.clone()));
        assert!(retain_same_receipt(retained.retained(), equal_foreign.clone()).is_err());
        assert!(Rc::ptr_eq(
            retained.retained().borrow().as_ref().unwrap(),
            &original
        ));
        let _borrow = retained.retained().borrow_mut();
        assert!(retain_same_receipt(retained.retained(), original.clone()).is_err());
        drop(_borrow);
        drop(equal_foreign);
        assert_eq!(drops.get(), 1);
        drop(original);
        drop(retained);
        assert_eq!(drops.get(), 1, "unknown graph retains first original");
    }
}

// Break: close once for each graph alias, or deduplicate foreign equal facts.
#[test]
fn canonical_origins_deduplicate_only_the_same_rc_before_once_close() {
    let first = Rc::new(RefCell::new(49u32));
    let foreign_equal = Rc::new(RefCell::new(49u32));
    let selected = unique_originals([
        first.clone(),
        foreign_equal.clone(),
        first.clone(),
        foreign_equal.clone(),
    ]);
    assert_eq!(selected.len(), 2);
    assert!(Rc::ptr_eq(&selected[0], &first));
    assert!(Rc::ptr_eq(&selected[1], &foreign_equal));
    *selected[0].borrow_mut() = 10;
    assert_eq!(*first.borrow(), 10);
    assert_eq!(*foreign_equal.borrow(), 49);
}

// Break: moving canonical owners before module separation is rooted, accepting
// lost/unwound cut completion, or authorizing a suppressed recursive cut.
#[test]
fn canonical_cut_retains_both_outputs_and_requires_whole_success() {
    for unwind in [false, true] {
        let dropped = Rc::new(Cell::new(0));
        let original = Rc::new(Original(dropped.clone()));
        let mut source = TerminalResources::new(original.clone());
        let mut external_module = TerminalResources::new(None);
        let completed = TerminalCallState::new();
        let result = catch_unwind(AssertUnwindSafe(|| {
            completed.run(|| {
                source
                    .transfer_original_into(external_module.retained_mut())
                    .map_err(|_| conflict())?;
                assert!(Rc::ptr_eq(
                    external_module.retained().as_ref().unwrap(),
                    &original
                ));
                assert!(
                    completed.verify().is_err(),
                    "an inner transfer is not whole-cut ACK"
                );
                if unwind {
                    panic!("after exact module-root transfer");
                }
                Err(conflict())
            })
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert!(completed.verify().is_err());
        assert!(completed.run(|| panic!("must never rerun")).is_err());
        drop(source);
        drop(original);
        drop(external_module);
        assert_eq!(
            dropped.get(),
            0,
            "unknown output abandonment cannot disarm owners"
        );
    }
}

#[test]
fn canonical_cut_reentry_and_equal_foreign_destination_cannot_be_suppressed() {
    let completed = TerminalCallState::new();
    assert!(completed
        .run(|| {
            assert!(completed.run(|| panic!("recursive transfer")).is_err());
            Ok(())
        })
        .is_err());
    assert!(completed.verify().is_err());
    let original = Rc::new(7u32);
    let foreign = Rc::new(7u32);
    let mut source = TerminalResources::new(original.clone());
    let mut destination = TerminalResources::new(Some(foreign.clone()));
    assert!(source
        .transfer_original_into(destination.retained_mut())
        .is_err());
    assert!(Rc::ptr_eq(source.retained(), &original));
    assert!(Rc::ptr_eq(
        destination.retained().as_ref().unwrap(),
        &foreign
    ));
}

// Break: publishing actual closed resources after the inner callback succeeded
// but the enclosing original supervisor/Retired postflight failed or unwound.
// These markers exercise the SAME production whole-call protocol; they are
// deliberately not constructors or successful substitutes for native ACKs.
#[test]
fn inner_close_completion_cannot_survive_lost_whole_call_postflight() {
    for unwind in [false, true] {
        let inner = TerminalCallState::new();
        let whole = TerminalCallState::new();
        let drops = Rc::new(Cell::new(0));
        let retained = TerminalResources::new(Original(drops.clone()));
        let result = catch_unwind(AssertUnwindSafe(|| {
            whole.run(|| {
                inner.run(|| Ok(()))?;
                inner.verify()?;
                if unwind {
                    panic!("outer terminal supervisor postflight");
                }
                Err(conflict())
            })
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        inner.verify().unwrap();
        assert!(whole.verify().is_err());
        assert!(whole
            .run(|| panic!("cannot repeat terminal close"))
            .is_err());
        drop(retained);
        assert_eq!(drops.get(), 0);
    }
}
