use super::*;
use std::{cell::RefCell, rc::Rc};

// Real LoadAttempt + ModuleRelease backend; only the OS/pre/post boundaries
// below are doubles. None implements the unsafe native authorization supplier.
fn no_constructor_loaded() -> (
    LoadAttempt<Boundary>,
    Rc<OriginalModuleLoadRead<Rc<Module>>>,
) {
    let state = Rc::new(RefCell::new(State::default()));
    let mut loaded = LoadAttempt::empty();
    loaded
        .load(Boundary(state), &AtomicBool::new(false))
        .unwrap();
    let mut original = None;
    loaded
        .retain_original_load_read_into(&mut original, |_| Ok(()))
        .unwrap();
    (loaded, original.unwrap())
}
struct NoConstructorAck {
    module: Rc<Module>,
    original: Rc<OriginalModuleLoadRead<Rc<Module>>>,
    proof: Rc<Cell<u8>>,
}

// Break: verifying the receipt after revoking its read gate rejects the genuine
// owner; dropping it before ACK/post or bypassing module.1 permits repeated free.
#[test]
fn no_constructor_backend_releases_exact_original_once_after_revocation() {
    let (mut loaded, original) = no_constructor_loaded();
    let module = loaded.owner.as_ref().unwrap().module.clone();
    let valid = loaded.owner.as_ref().unwrap().valid.clone();
    let release = ModuleRelease::new();
    let loans = LeasePins::new();
    let mut terminal = None;
    let mut retained = None;
    let proof = Rc::new(Cell::new(7));
    let free_calls = Cell::new(0);
    loaded
        .release_original_into(
            OriginalLoadRelease {
                original: &original,
                same_module: Rc::ptr_eq,
                terminal: &mut terminal,
                release: &release,
                loans: &loans,
            },
            (original.clone(), proof.clone()),
            &mut retained,
            |receipt, supplier| {
                assert!(Rc::ptr_eq(receipt, &original));
                assert!(Rc::ptr_eq(supplier, &proof));
                assert!(release.was_attempted());
                assert!(!original.available.get());
                assert!(!valid.get());
                original.inspect_release_pre_with(
                    &release,
                    &loans,
                    &AtomicBool::new(false),
                    |actual| {
                        assert!(Rc::ptr_eq(actual, &module));
                        let _query_loan = loans.retain_read()?;
                        Ok(())
                    },
                )?;
                Ok(())
            },
            |receipt, supplier| {
                free_calls.set(free_calls.get() + 1);
                assert!(release.effect_started.get());
                Ok(NoConstructorAck {
                    module: module.clone(),
                    original: receipt.clone(),
                    proof: supplier.clone(),
                })
            },
            |ack| {
                assert!(release.acknowledged());
                assert!(Rc::ptr_eq(&ack.module, &module));
                assert!(Rc::ptr_eq(&ack.original, &original));
                assert!(Rc::ptr_eq(&ack.proof, &proof));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(free_calls.get(), 1);
    assert!(loaded.owner.is_none());
    let ack = retained.as_ref().unwrap();
    loaded
        .verify_original_release(&ack.original, &terminal, &release, Rc::ptr_eq)
        .unwrap();
    loaded
        .verify_original_disposition(&ack.original, &terminal, &release, &loans, Rc::ptr_eq)
        .unwrap();
    assert!(loaded
        .verify_original_load_read(&original, Rc::ptr_eq)
        .is_err());
    assert!(original
        .inspect_cleanup_with(
            &AtomicBool::new(false),
            || Ok(()),
            |_| panic!("revoked ordinary query")
        )
        .is_err());
    assert!(loaded
        .release_original_into(
            OriginalLoadRelease {
                original: &original,
                same_module: Rc::ptr_eq,
                terminal: &mut terminal,
                release: &release,
                loans: &loans
            },
            (original.clone(), proof.clone()),
            &mut retained,
            |_, _| panic!("repeat pre"),
            |_, _| panic!("repeat native"),
            |_| panic!("repeat post"),
        )
        .is_err());
    assert_eq!(free_calls.get(), 1);
    assert!(Rc::ptr_eq(&retained.as_ref().unwrap().module, &module));
}

// Break: a pre/native/post error or unwind drops proof/owner, invents an ACK,
// loses the actual returned ACK, or rearms an ambiguous reference release.
#[test]
fn no_constructor_backend_retains_originals_at_every_failed_boundary() {
    // 0 pre error, 1 pre unwind, 2 free error, 3 free unwind, 4 lost ACK,
    // 5 post error, 6 post unwind. A lost native return cannot create a receipt.
    for fault in 0..7 {
        let (mut loaded, original) = no_constructor_loaded();
        let module = loaded.owner.as_ref().unwrap().module.clone();
        let release = ModuleRelease::new();
        let loans = LeasePins::new();
        let mut terminal = None;
        let mut retained = None;
        let proof = Rc::new(Cell::new(7));
        let proof_weak = Rc::downgrade(&proof);
        let read_weak = Rc::downgrade(&original);
        let free_calls = Cell::new(0);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            loaded.release_original_into(
                OriginalLoadRelease {
                    original: &original,
                    same_module: Rc::ptr_eq,
                    terminal: &mut terminal,
                    release: &release,
                    loans: &loans,
                },
                (original.clone(), proof.clone()),
                &mut retained,
                |_, _| match fault {
                    0 => Err(Error::Conflict),
                    1 => panic!("pre unknown"),
                    _ => Ok(()),
                },
                |receipt, supplier| {
                    free_calls.set(free_calls.get() + 1);
                    match fault {
                        2 => Err(Error::Native),
                        3 => panic!("FreeLibrary unknown"),
                        4 => Err(Error::Native), // external effect with no usable return
                        _ => Ok(NoConstructorAck {
                            module: module.clone(),
                            original: receipt.clone(),
                            proof: supplier.clone(),
                        }),
                    }
                },
                |_| match fault {
                    5 => Err(Error::Conflict),
                    6 => panic!("post unknown"),
                    _ => panic!("post without native ACK"),
                },
            )
        }));
        assert!(
            outcome.is_err() || outcome.unwrap().is_err(),
            "fault {fault}"
        );
        assert!(Rc::ptr_eq(&loaded.owner.as_ref().unwrap().module, &module));
        assert!(!loaded.owner.as_ref().unwrap().valid.get());
        assert!(terminal.is_some());
        assert!(release.was_attempted());
        assert_eq!(free_calls.get(), usize::from(fault >= 2));
        assert_eq!(retained.is_some(), fault >= 5);
        assert_eq!(release.acknowledged(), fault >= 5);
        assert!(original
            .inspect_release_pre_with(&release, &loans, &AtomicBool::new(false), |_| panic!(
                "failed/returned frame image query"
            ))
            .is_err());
        assert_eq!(
            loaded
                .verify_original_release(&original, &terminal, &release, Rc::ptr_eq)
                .is_ok(),
            fault >= 5
        );
        assert!(loaded
            .verify_original_disposition(&original, &terminal, &release, &loans, Rc::ptr_eq)
            .is_err());
        if let Some(ack) = retained.as_ref() {
            assert!(Rc::ptr_eq(&ack.module, &module));
            assert!(Rc::ptr_eq(&ack.original, &original));
            assert!(Rc::ptr_eq(&ack.proof, &proof));
        }
        // Even removing the caller's returned ACK never authorizes another free.
        drop(retained.take());
        assert!(loaded
            .release_original_into(
                OriginalLoadRelease {
                    original: &original,
                    same_module: Rc::ptr_eq,
                    terminal: &mut terminal,
                    release: &release,
                    loans: &loans
                },
                (original.clone(), proof.clone()),
                &mut retained,
                |_, _| panic!("retry pre"),
                |_, _| panic!("retry free"),
                |_| panic!("retry post"),
            )
            .is_err());
        drop(proof);
        drop(original);
        drop(loaded);
        assert!(proof_weak.upgrade().is_some(), "failed proof root {fault}");
        assert!(read_weak.upgrade().is_some(), "failed receipt root {fault}");
    }
}

// Break: equal/foreign/missing receipts or origin drift release a different own
// reference; a live actual module loan or poisoned count is ignored.
#[test]
fn no_constructor_backend_denies_foreign_missing_and_live_loan_origins() {
    for defect in 0..8 {
        let (mut loaded, original) = no_constructor_loaded();
        let (_foreign, foreign_read) = no_constructor_loaded();
        let forged = Rc::new(OriginalModuleLoadRead {
            module: original.module.clone(),
            valid: original.valid.clone(),
            available: original.available.clone(),
            inspecting: Cell::new(false),
            tainted: Cell::new(false),
        });
        let candidate = match defect {
            0 => &foreign_read,
            1 => &forged,
            _ => &original,
        };
        let release = ModuleRelease::new();
        let loans = LeasePins::new();
        let mut terminal = None;
        let mut retained: Option<NoConstructorAck> = None;
        let proof = Rc::new(Cell::new(7));
        match defect {
            2 => {
                loaded.original_read.borrow_mut().take();
            }
            3 => {
                loaded.owner.as_mut().unwrap().module = foreign_read.module.clone();
            }
            4 => {
                loaded.owner.as_mut().unwrap().valid = Rc::new(Cell::new(true));
            }
            5 => {
                loans.retain().unwrap();
            }
            6 => {
                loans.release();
            } // unknown zero count is not positive absence
            7 => {
                loaded.read_available = Rc::new(Cell::new(true));
            }
            _ => (),
        }
        assert!(
            loaded
                .release_original_into(
                    OriginalLoadRelease {
                        original: candidate,
                        same_module: Rc::ptr_eq,
                        terminal: &mut terminal,
                        release: &release,
                        loans: &loans
                    },
                    (candidate.clone(), proof),
                    &mut retained,
                    |_, _| panic!("invalid origin pre"),
                    |_, _| panic!("invalid origin free"),
                    |_| panic!("invalid origin post"),
                )
                .is_err(),
            "defect {defect}"
        );
        assert!(loaded.owner.is_some());
        assert!(retained.is_none());
        assert!(!release.acknowledged());
        assert!(release.was_attempted());
        assert!(!loaded.read_available.get());
        if defect == 5 {
            loans.release();
        }
        assert!(loaded
            .release_original_into(
                OriginalLoadRelease {
                    original: candidate,
                    same_module: Rc::ptr_eq,
                    terminal: &mut terminal,
                    release: &release,
                    loans: &loans
                },
                (candidate.clone(), Rc::new(Cell::new(7))),
                &mut retained,
                |_, _| panic!("invalid retry pre"),
                |_, _| panic!("invalid retry free"),
                |_| panic!("invalid retry post"),
            )
            .is_err());
    }
}

// Break: occupied caller storage overwrites an original ACK; a nonexistent load
// is treated as a successful owner or an earlier disposition is overwritten.
#[test]
fn no_constructor_backend_preserves_occupied_ack_and_missing_owner() {
    for defect in 0..4 {
        let (mut loaded, original) = no_constructor_loaded();
        let (mut other, other_read) = no_constructor_loaded();
        let proof = Rc::new(Cell::new(7));
        let release = ModuleRelease::new();
        let loans = LeasePins::new();
        let mut terminal = None;
        let mut retained = None;
        match defect {
            0 => {
                retained = Some(NoConstructorAck {
                    module: other.owner.as_ref().unwrap().module.clone(),
                    original: other_read.clone(),
                    proof: proof.clone(),
                });
            }
            1 => {
                std::mem::forget(loaded.owner.take());
            }
            2 => {
                terminal = Some((
                    other.owner.as_ref().unwrap().module.clone(),
                    other.owner.as_ref().unwrap().valid.clone(),
                ));
            }
            3 => {
                loaded = LoadAttempt::empty();
            } // no successful loader ACK at all
            _ => unreachable!(),
        }
        assert!(loaded
            .release_original_into(
                OriginalLoadRelease {
                    original: &original,
                    same_module: Rc::ptr_eq,
                    terminal: &mut terminal,
                    release: &release,
                    loans: &loans
                },
                (original.clone(), proof),
                &mut retained,
                |_, _| panic!("missing/occupied pre"),
                |_, _| panic!("missing/occupied free"),
                |_| panic!("missing/occupied post"),
            )
            .is_err());
        assert!(!release.acknowledged());
        assert!(!loaded.read_available.get());
        if defect == 0 {
            assert!(Rc::ptr_eq(
                &retained.as_ref().unwrap().original,
                &other_read
            ));
        }
        if defect == 2 {
            assert!(Rc::ptr_eq(
                &terminal.as_ref().unwrap().0,
                &other.owner.as_ref().unwrap().module
            ));
        }
        assert!(loaded
            .verify_original_release(&original, &terminal, &release, Rc::ptr_eq)
            .is_err());
        // This other load is unrelated and was not released by rejection.
        assert!(other.owner.is_some());
        drop(other.owner.take());
    }
}

// Break: factual ACK/disposition accepts a foreign or equal reconstructed
// receipt, substituted terminal identity or a gate with no actual native ACK.
#[test]
fn no_constructor_backend_factual_ack_denies_foreign_equal_and_missing_origins() {
    let (mut loaded, original) = no_constructor_loaded();
    let (_foreign, foreign) = no_constructor_loaded();
    let module = original.module.clone();
    let release = ModuleRelease::new();
    let loans = LeasePins::new();
    let mut terminal = None;
    let mut retained = None;
    loaded
        .release_original_into(
            OriginalLoadRelease {
                original: &original,
                same_module: Rc::ptr_eq,
                terminal: &mut terminal,
                release: &release,
                loans: &loans,
            },
            (original.clone(), Rc::new(Cell::new(7))),
            &mut retained,
            |_, _| Ok(()),
            |receipt, proof| {
                Ok(NoConstructorAck {
                    module: module.clone(),
                    original: receipt.clone(),
                    proof: proof.clone(),
                })
            },
            |_| Ok(()),
        )
        .unwrap();
    let equal = Rc::new(OriginalModuleLoadRead {
        module: original.module.clone(),
        valid: original.valid.clone(),
        available: original.available.clone(),
        inspecting: Cell::new(false),
        tainted: Cell::new(false),
    });
    for candidate in [&foreign, &equal] {
        assert!(loaded
            .verify_original_release(candidate, &terminal, &release, Rc::ptr_eq)
            .is_err());
        assert!(loaded
            .verify_original_disposition(candidate, &terminal, &release, &loans, Rc::ptr_eq)
            .is_err());
    }
    let missing_ack = ModuleRelease::new();
    assert!(loaded
        .verify_original_release(&original, &terminal, &missing_ack, Rc::ptr_eq)
        .is_err());
    assert!(loaded
        .verify_original_release(&original, &None, &release, Rc::ptr_eq)
        .is_err());
    let wrong_terminal = Some((foreign.module.clone(), original.valid.clone()));
    assert!(loaded
        .verify_original_release(&original, &wrong_terminal, &release, Rc::ptr_eq)
        .is_err());
    loaded
        .verify_original_disposition(
            &retained.as_ref().unwrap().original,
            &terminal,
            &release,
            &loans,
            Rc::ptr_eq,
        )
        .unwrap();
}

#[cfg(windows)]
fn actual_no_constructor_release_backend_compile_contract<
    P: native::NativeNoConstructorModuleReleaseProof,
>(
    loaded: &mut native::LoadedWintun,
    original: &Rc<native::NativeOriginalModuleLoadRead>,
    proof: Rc<P>,
    retained: &mut Option<native::NativeNoConstructorModuleReleased<P>>,
) -> Result<()> {
    // Actual fixed native API; no unsafe supplier implementation and no run.
    loaded.release_no_constructor_into(original, proof, retained)?;
    let ack = retained.as_ref().ok_or(Error::Conflict)?;
    loaded.verify_original_no_constructor_native_release(ack)?;
    loaded.verify_no_constructor_disposition(ack)
}

// Break: reopening ordinary image trust or admitting a factual image query
// before selection, after effect/postflight, or after pre has returned.
#[test]
fn no_constructor_release_pre_reader_opens_only_inside_actual_pre_frame() {
    let (loaded, original) = no_constructor_loaded();
    let module = original.module.clone();
    let release = ModuleRelease::new();
    let loans = LeasePins::new();
    let cancelled = AtomicBool::new(false);
    let queries = Cell::new(0);
    assert!(original
        .inspect_release_pre_with(&release, &loans, &cancelled, |_| panic!("unselected image"))
        .is_err());
    loaded.deny_original_load_reads();
    let mut retained = None;
    release
        .run_into(
            &mut retained,
            || {
                original.inspect_release_pre_with(&release, &loans, &cancelled, |actual| {
                    assert!(Rc::ptr_eq(actual, &module));
                    assert!(!original.valid.get());
                    assert!(!original.available.get());
                    let _loan = loans.retain_read()?;
                    queries.set(queries.get() + 1);
                    Ok(())
                })?;
                assert!(loans.is_empty());
                assert!(!original.valid.get());
                assert!(!original.available.get());
                Ok(())
            },
            || {
                assert!(original
                    .inspect_release_pre_with(&release, &loans, &cancelled, |_| panic!(
                        "effect image"
                    ))
                    .is_err());
                Ok(module.clone())
            },
            |_| {
                assert!(original
                    .inspect_release_pre_with(&release, &loans, &cancelled, |_| panic!(
                        "post image"
                    ))
                    .is_err());
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(queries.get(), 1);
    assert!(original
        .inspect_release_pre_with(&release, &loans, &cancelled, |_| panic!("completed image"))
        .is_err());
    assert!(original
        .inspect_cleanup_with(&cancelled, || Ok(()), |_| panic!("ordinary read rearmed"))
        .is_err());
    assert!(release
        .run_into(
            &mut retained,
            || panic!("repeat pre"),
            || panic!("repeat free"),
            |_| Ok(())
        )
        .is_err());
    assert!(original
        .inspect_release_pre_with(&release, &loans, &cancelled, |_| panic!("repeat image"))
        .is_err());
}

// Break: failed/unwound/finished pre leaves a reusable pre aperture, or a caught
// read failure is allowed to proceed to FreeLibrary on the same original.
#[test]
fn no_constructor_release_pre_reader_poison_and_rundown_deny_native_effect() {
    for fault in 0..6 {
        let (loaded, original) = no_constructor_loaded();
        loaded.deny_original_load_reads();
        let release = ModuleRelease::new();
        let loans = LeasePins::new();
        let cancelled = AtomicBool::new(false);
        let mut retained: Option<()> = None;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            release.run_into(
                &mut retained,
                || {
                    match fault {
                        0 => {
                            original.inspect_release_pre_with(
                                &release,
                                &loans,
                                &cancelled,
                                |_| Err(Error::Conflict),
                            )?;
                        }
                        1 => {
                            original.inspect_release_pre_with(
                                &release,
                                &loans,
                                &cancelled,
                                |_| panic!("pre factual read unwind"),
                            )?;
                        }
                        2 => {
                            assert!(original
                                .inspect_release_pre_with(&release, &loans, &cancelled, |_| Err(
                                    Error::Native
                                ))
                                .is_err());
                            return Ok(()); // caught read error must still poison effect
                        }
                        3 => return Err(Error::Conflict), // error outside fact reader
                        4 => panic!("pre supplier unwind"),
                        5 => {
                            assert!(release
                                .run_into(
                                    &mut None::<()>,
                                    || panic!("reentered pre"),
                                    || Ok(()),
                                    |_| Ok(())
                                )
                                .is_err());
                            assert!(original
                                .inspect_release_pre_with(&release, &loans, &cancelled, |_| panic!(
                                    "tainted image"
                                ))
                                .is_err());
                            return Ok(());
                        }
                        _ => unreachable!(),
                    }
                    Ok(())
                },
                || panic!("failed pre must never free"),
                |_| panic!("no ACK post"),
            )
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert!(retained.is_none());
        assert!(!release.effect_started.get());
        assert!(original
            .inspect_release_pre_with(&release, &loans, &cancelled, |_| panic!(
                "abandoned pre image"
            ))
            .is_err());
        assert!(!original.valid.get());
        assert!(!original.available.get());
    }
}

// Break: active loans/cancellation/live ordinary read gate are mistaken for
// a valid pre-read origin, or their denial allows a native effect if caught.
#[test]
fn no_constructor_release_pre_reader_requires_revoked_zero_loan_original() {
    for defect in 0..5 {
        let (loaded, original) = no_constructor_loaded();
        let release = ModuleRelease::new();
        let loans = LeasePins::new();
        let cancelled = AtomicBool::new(defect == 3);
        if defect != 0 {
            loaded.deny_original_load_reads();
        }
        match defect {
            1 => {
                loans.retain().unwrap();
            }
            2 => loans.release(),
            4 => {
                original.tainted.set(true);
            }
            _ => (),
        }
        assert!(release
            .run_into(
                &mut None::<()>,
                || original.inspect_release_pre_with(&release, &loans, &cancelled, |_| panic!(
                    "invalid pre query"
                )),
                || panic!("invalid pre free"),
                |_| panic!("invalid pre post"),
            )
            .is_err());
        assert!(!release.effect_started.get());
    }
}

// Break: a new actual loan introduced by fallible pre/post escapes the backend
// and permits native release or completed owning disposition.
#[test]
fn no_constructor_backend_rechecks_actual_loans_across_pre_and_post() {
    for post_loan in [false, true] {
        let (mut loaded, original) = no_constructor_loaded();
        let module = original.module.clone();
        let release = ModuleRelease::new();
        let loans = LeasePins::new();
        let mut terminal = None;
        let mut retained = None;
        assert!(loaded
            .release_original_into(
                OriginalLoadRelease {
                    original: &original,
                    same_module: Rc::ptr_eq,
                    terminal: &mut terminal,
                    release: &release,
                    loans: &loans
                },
                (original.clone(), Rc::new(Cell::new(7))),
                &mut retained,
                |_, _| {
                    if !post_loan {
                        loans.retain()?;
                    }
                    Ok(())
                },
                |receipt, proof| {
                    assert!(post_loan, "pre acquired loan must deny free");
                    Ok(NoConstructorAck {
                        module: module.clone(),
                        original: receipt.clone(),
                        proof: proof.clone(),
                    })
                },
                |_| {
                    loans.retain()?;
                    Ok(())
                },
            )
            .is_err());
        assert!(loaded.owner.is_some());
        assert_eq!(retained.is_some(), post_loan);
        assert_eq!(release.acknowledged(), post_loan);
        loans.release();
        assert!(loaded
            .verify_original_disposition(&original, &terminal, &release, &loans, Rc::ptr_eq)
            .is_err());
    }
}

#[cfg(windows)]
fn actual_no_constructor_release_pre_read_compile_contract(
    original: &native::NativeOriginalModuleLoadRead,
    runtime: &crate::windows::member_carrier_key_authority::RuntimeRead,
    cancelled: &AtomicBool,
) -> Result<()> {
    original.verify_release_pre_read(runtime, cancelled)
}

// Break: retaining the returned native original only AFTER fallible postflight.
// This is the production release protocol, not an SDK success/permission mock.
#[test]
fn retained_module_ack_survives_postflight_error_and_unwind_without_disposal() {
    for unwind in [false, true] {
        let release = ModuleRelease::new();
        let original = Rc::new(Cell::new(41));
        let identity = Rc::downgrade(&original);
        let mut retained = None;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            release.run_into(
                &mut retained,
                || Ok(()),
                || Ok(original),
                |actual| {
                    assert!(Rc::ptr_eq(actual, &identity.upgrade().unwrap()));
                    if unwind {
                        panic!("postflight lost after native return");
                    }
                    Err(Error::Conflict)
                },
            )
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        let ack = retained
            .as_ref()
            .expect("original retained before postflight");
        assert!(Rc::ptr_eq(ack, &identity.upgrade().unwrap()));
        assert_eq!(ack.get(), 41);
        assert!(release.acknowledged());
        assert!(!release.complete.get());
        assert!(release
            .run_into(
                &mut retained,
                || panic!("retry check"),
                || panic!("retry native call"),
                |_| Ok(())
            )
            .is_err());
        assert!(identity.upgrade().is_some());
    }
}

#[test]
fn retained_module_ack_does_not_invent_native_return_or_replace_occupied_original() {
    for unwind in [false, true] {
        let release = ModuleRelease::new();
        let mut retained: Option<Rc<Cell<u8>>> = None;
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            release.run_into(
                &mut retained,
                || Ok(()),
                || {
                    if unwind {
                        panic!("native return unknown");
                    }
                    Err(Error::Native)
                },
                |_| panic!("no ACK postflight"),
            )
        }));
        assert!(r.is_err() || r.unwrap().is_err());
        assert!(retained.is_none());
        assert!(!release.acknowledged());
        assert!(release.was_attempted());
        assert!(!release.image_available());
    }
    let release = ModuleRelease::new();
    let original = Rc::new(Cell::new(3));
    let mut retained = Some(original.clone());
    assert!(release
        .run_into(
            &mut retained,
            || panic!("occupied check"),
            || panic!("occupied native call"),
            |_| panic!("occupied post")
        )
        .is_err());
    assert!(Rc::ptr_eq(retained.as_ref().unwrap(), &original));
    assert!(!release.acknowledged());
}

#[test]
fn actual_lease_pin_tracker_denies_unload_with_any_holder_or_unknown_bookkeeping() {
    let pins = LeasePins::new();
    assert!(pins.is_empty());
    pins.retain().unwrap();
    pins.retain().unwrap();
    assert!(!pins.is_empty());
    pins.release();
    assert!(!pins.is_empty());
    pins.release();
    assert!(pins.is_empty());
    pins.release();
    assert!(!pins.is_empty());
    assert!(pins.retain().is_err());
    let overflow = LeasePins::new();
    overflow.held.set(usize::MAX);
    assert!(overflow.retain().is_err());
    overflow.held.set(0);
    assert!(!overflow.is_empty());
}

// Break: a factual load-ACK reader holds the real cooperative lease but leaves
// the original's holder count empty, allowing unload during its image query.
#[test]
fn original_load_read_lease_blocks_unload_until_read_rundown_even_on_unwind() {
    for unwind in [false, true] {
        let pins = LeasePins::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _read = pins.retain_read().unwrap();
            assert!(!pins.is_empty());
            if unwind {
                panic!("factual lease rundown");
            }
        }));
        assert_eq!(result.is_err(), unwind);
        assert!(pins.is_empty());
    }
    let pins = LeasePins::new();
    pins.release(); // genuinely inconsistent original bookkeeping
    assert!(pins.retain_read().is_err());
    assert!(!pins.is_empty());
}

// Break: never releasing a known terminal owner, repeating an OS unload after
// error/unwind, or admitting stale image reads after an ambiguous OS call.
#[test]
fn explicit_module_release_calls_once_after_checks_and_revokes_all_image_reads() {
    let release = ModuleRelease::new();
    let calls = Cell::new(0);
    release
        .run(
            || Ok(()),
            || {
                calls.set(calls.get() + 1);
                Ok(())
            },
            || Ok(()),
        )
        .unwrap();
    assert_eq!(calls.get(), 1);
    assert!(!release.image_available());
    assert!(release.complete.get());
    assert!(release
        .run(
            || panic!("repeat check"),
            || panic!("repeat unload"),
            || Ok(())
        )
        .is_err());
    assert_eq!(calls.get(), 1);
}
#[test]
fn module_release_preflight_error_or_unwind_never_unloads_and_never_retries() {
    for unwind in [false, true] {
        let release = ModuleRelease::new();
        let calls = Cell::new(0);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            release.run(
                || {
                    if unwind {
                        panic!("terminal preflight unwind");
                    }
                    Err(Error::Conflict)
                },
                || {
                    calls.set(calls.get() + 1);
                    Ok(())
                },
                || Ok(()),
            )
        }));
        assert!(r.is_err() || r.unwrap().is_err());
        assert_eq!(calls.get(), 0);
        assert!(release
            .run(
                || Ok(()),
                || {
                    calls.set(calls.get() + 1);
                    Ok(())
                },
                || Ok(())
            )
            .is_err());
        assert_eq!(calls.get(), 0);
        assert!(!release.complete.get());
    }
}
#[test]
fn module_release_os_error_unwind_or_lost_postflight_ack_is_not_retryable() {
    for fault in 0..3 {
        let release = ModuleRelease::new();
        let calls = Cell::new(0);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            release.run(
                || Ok(()),
                || {
                    calls.set(calls.get() + 1);
                    match fault {
                        0 => Err(Error::Native),
                        1 => panic!("unload unwind"),
                        _ => Ok(()),
                    }
                },
                || Err(Error::Conflict),
            )
        }));
        assert!(r.is_err() || r.unwrap().is_err());
        assert_eq!(calls.get(), 1);
        assert!(!release.image_available());
        assert!(!release.complete.get());
        assert_eq!(release.unloaded.get(), fault == 2);
        assert!(release
            .run(
                || Ok(()),
                || {
                    calls.set(calls.get() + 1);
                    Ok(())
                },
                || Ok(())
            )
            .is_err());
        assert_eq!(calls.get(), 1);
    }
}
#[test]
fn caught_module_release_reentry_denies_before_native_call() {
    let release = ModuleRelease::new();
    let calls = Cell::new(0);
    assert!(release
        .run(
            || {
                assert!(release.run(|| Ok(()), || Ok(()), || Ok(())).is_err());
                Ok(())
            },
            || {
                calls.set(calls.get() + 1);
                Ok(())
            },
            || Ok(())
        )
        .is_err());
    assert_eq!(calls.get(), 0);
}

#[test]
fn caught_post_unload_reentry_keeps_native_ack_but_never_completes_release() {
    let release = ModuleRelease::new();
    let calls = Cell::new(0);
    assert!(release
        .run(
            || Ok(()),
            || {
                calls.set(calls.get() + 1);
                Ok(())
            },
            || {
                assert!(release
                    .run(
                        || panic!("duplicate check"),
                        || panic!("duplicate unload"),
                        || Ok(())
                    )
                    .is_err());
                Ok(())
            }
        )
        .is_err());
    assert_eq!(calls.get(), 1);
    assert!(release.unloaded.get());
    assert!(!release.complete.get());
    assert!(!release.image_available());
}

#[derive(Default)]
struct State {
    calls: Vec<&'static str>,
    fail: Option<usize>,
    panic: Option<usize>,
    lease_held: bool,
    loaded: usize,
    original_load_retained: bool,
    unloads: usize,
    cancel_at: Option<(usize, Rc<AtomicBool>)>,
    deny_lease_verification: bool,
}
type Shared = Rc<RefCell<State>>;
struct Boundary(Shared);
struct Lease(Shared);
struct Module(Shared);
impl Drop for Lease {
    fn drop(&mut self) {
        let mut s = self.0.borrow_mut();
        assert!(s.lease_held);
        s.lease_held = false;
        s.calls.push("release");
    }
}
impl Drop for Module {
    fn drop(&mut self) {
        let mut s = self.0.borrow_mut();
        s.unloads += 1;
        s.calls.push("unload");
    }
}
impl Boundary {
    fn call(&self, name: &'static str) -> Result<()> {
        let mut s = self.0.borrow_mut();
        s.calls.push(name);
        if let Some((at, cancelled)) = &s.cancel_at {
            if *at == s.calls.len() {
                cancelled.store(true, Ordering::Release);
            }
        }
        if s.panic == Some(s.calls.len()) {
            panic!("injected boundary failure");
        }
        if s.fail == Some(s.calls.len()) {
            Err(Error::Conflict)
        } else {
            Ok(())
        }
    }
}
impl Kernel for Boundary {
    type Lease = Lease;
    type Module = Rc<Module>;
    fn source(&mut self) -> Result<()> {
        self.call("source")
    }
    fn absent_module(&mut self) -> Result<()> {
        self.call("absent")
    }
    fn lease(&mut self, _: &AtomicBool) -> Result<Lease> {
        self.call("lease")?;
        self.0.borrow_mut().lease_held = true;
        Ok(Lease(self.0.clone()))
    }
    fn verify_lease(&mut self, lease: &mut Lease, _: &AtomicBool) -> Result<()> {
        assert!(Rc::ptr_eq(&lease.0, &self.0));
        assert!(self.0.borrow().lease_held);
        self.call("verify_lease")?;
        if self.0.borrow().deny_lease_verification {
            Err(Error::Conflict)
        } else {
            Ok(())
        }
    }
    fn package(&mut self) -> Result<()> {
        self.call("package")
    }
    fn load(&mut self) -> Result<Rc<Module>> {
        assert!(self.0.borrow().lease_held);
        self.call("load")?;
        self.0.borrow_mut().loaded += 1;
        Ok(Rc::new(Module(self.0.clone())))
    }
    fn module(&mut self, _: &Rc<Module>) -> Result<()> {
        self.call("module")
    }
    fn original_load_retained(
        &mut self,
        module: &Rc<Module>,
        lease: &mut Lease,
        _: &AtomicBool,
    ) -> Result<()> {
        assert!(Rc::ptr_eq(&module.0, &self.0));
        assert!(Rc::ptr_eq(&lease.0, &self.0));
        assert!(self.0.borrow().lease_held);
        self.0.borrow_mut().original_load_retained = true;
        Ok(())
    }
}

const EXPECTED: [&str; 13] = [
    "source",
    "absent",
    "lease",
    "source",
    "package",
    "source",
    "verify_lease",
    "absent",
    "load",
    "module",
    "package",
    "source",
    "verify_lease",
];

// Break: treating forward postflight success as the load ACK hides a genuine
// returned native reference after error/unwind. Only OS boundaries are doubled.
#[test]
fn original_load_read_survives_every_postload_error_without_rearming_forward() {
    for failure in 10..=13 {
        for unwind in [false, true] {
            let state = Shared::default();
            if unwind {
                state.borrow_mut().panic = Some(failure);
            } else {
                state.borrow_mut().fail = Some(failure);
            }
            let mut attempt = LoadAttempt::empty();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                attempt.load(Boundary(state.clone()), &AtomicBool::new(false))
            }));
            assert!(result.is_err() || result.unwrap().is_err());
            let calls = state.borrow().calls.len();
            let mut pin = None;
            attempt
                .retain_original_load_read_into(&mut pin, |_| Ok(()))
                .unwrap();
            let pin = pin.unwrap();
            attempt.verify_original_load_read(&pin, Rc::ptr_eq).unwrap();
            assert!(Rc::ptr_eq(
                &pin.module,
                &attempt.owner.as_ref().unwrap().module
            ));
            assert!(!pin.valid.get());
            assert_eq!(state.borrow().calls.len(), calls, "issuance is SDK-free");
            assert!(attempt
                .load(Boundary(state.clone()), &AtomicBool::new(false))
                .is_err());
            drop(attempt);
            drop(pin);
            assert_eq!(state.borrow().unloads, 0, "unknown owner remains retained");
        }
    }
}

// Break: wrapper/attempt presence, equal raw identities or a changed owner
// would be accepted as the ORIGINAL returned native load.
#[test]
fn original_load_read_denies_missing_foreign_duplicate_and_owner_drift() {
    for failure in 1..=9 {
        let state = Shared::default();
        state.borrow_mut().fail = Some(failure);
        let mut attempt = LoadAttempt::empty();
        assert!(attempt
            .load(Boundary(state.clone()), &AtomicBool::new(false))
            .is_err());
        let mut pin = None;
        assert!(attempt
            .retain_original_load_read_into(&mut pin, |_| panic!("no ACK"))
            .is_err());
        assert!(pin.is_none());
        assert_eq!(state.borrow().loaded, 0);
    }
    let state = Shared::default();
    let mut original = LoadAttempt::empty();
    original
        .load(Boundary(state.clone()), &AtomicBool::new(false))
        .unwrap();
    let mut pin = None;
    original
        .retain_original_load_read_into(&mut pin, |_| Ok(()))
        .unwrap();
    let pin = pin.unwrap();
    let mut foreign = LoadAttempt::empty();
    foreign
        .load(Boundary(state.clone()), &AtomicBool::new(false))
        .unwrap();
    assert!(foreign.verify_original_load_read(&pin, Rc::ptr_eq).is_err());
    let mut second = None;
    assert!(original
        .retain_original_load_read_into(&mut second, |_| panic!("duplicate"))
        .is_err());
    assert!(second.is_none());
    // An equal boundary identity is not the same original Module Rc.
    let owner = original.owner.as_mut().unwrap();
    let old_module = owner.module.clone();
    owner.module = Rc::new(Module(state.clone()));
    assert!(original
        .verify_original_load_read(&pin, Rc::ptr_eq)
        .is_err());
    original.owner.as_mut().unwrap().module = old_module;
    let old_valid = original.owner.as_ref().unwrap().valid.clone();
    original.owner.as_mut().unwrap().valid = Rc::new(Cell::new(true));
    assert!(original
        .verify_original_load_read(&pin, Rc::ptr_eq)
        .is_err());
    original.owner.as_mut().unwrap().valid = old_valid;
    let owner = original.owner.take().unwrap();
    assert!(original
        .verify_original_load_read(&pin, Rc::ptr_eq)
        .is_err());
    original.owner = Some(owner);
}

// Break: leaving the receipt local until postflight loses it on error/unwind,
// or swallowed nested issuance silently publishes a second original.
#[test]
fn original_load_read_is_rooted_before_capture_postflight_and_never_replaced() {
    for fault in 0..3 {
        let state = Shared::default();
        let mut attempt = LoadAttempt::empty();
        attempt
            .load(Boundary(state.clone()), &AtomicBool::new(false))
            .unwrap();
        let mut pin = None;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            attempt.retain_original_load_read_into(&mut pin, |actual| {
                attempt.verify_original_load_read(actual, Rc::ptr_eq)?;
                match fault {
                    0 => Err(Error::Native),
                    1 => panic!("read-pin postflight"),
                    _ => {
                        let mut nested = None;
                        assert!(attempt
                            .retain_original_load_read_into(&mut nested, |_| Ok(()))
                            .is_err());
                        assert!(nested.is_none());
                        Ok(())
                    }
                }
            })
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        let pin = pin.unwrap();
        // Facts survive failed publication; this is not a completed permission.
        attempt.verify_original_load_read(&pin, Rc::ptr_eq).unwrap();
        let mut occupied = Some(pin.clone());
        assert!(attempt
            .retain_original_load_read_into(&mut occupied, |_| Ok(()))
            .is_err());
        assert!(Rc::ptr_eq(occupied.as_ref().unwrap(), &pin));
        assert_eq!(state.borrow().loaded, 1);
        assert_eq!(state.borrow().unloads, 0);
    }
}

// Break: factual cleanup re-arms a failed load, or queries a reference after
// release started. The actual ModuleRelease protocol supplies disposition.
#[test]
fn original_load_cleanup_read_preserves_poison_and_denies_release_before_queries() {
    for release_fault in 0..3 {
        let state = Shared::default();
        state.borrow_mut().fail = Some(10);
        let mut attempt = LoadAttempt::empty();
        assert!(attempt
            .load(Boundary(state.clone()), &AtomicBool::new(false))
            .is_err());
        state.borrow_mut().fail = None;
        let mut pin = None;
        attempt
            .retain_original_load_read_into(&mut pin, |_| Ok(()))
            .unwrap();
        let pin = pin.unwrap();
        let release = ModuleRelease::new();
        let owner = attempt.owner.as_mut().unwrap();
        pin.inspect_cleanup_with(
            &AtomicBool::new(false),
            || {
                if release.was_attempted() {
                    Err(Error::Conflict)
                } else {
                    Ok(())
                }
            },
            |module| {
                assert!(Rc::ptr_eq(module, &owner.module));
                let mut lease = owner.kernel.lease(&AtomicBool::new(false))?;
                owner.kernel.source()?;
                owner
                    .kernel
                    .verify_lease(&mut lease, &AtomicBool::new(false))?;
                owner.kernel.module(module)?;
                owner
                    .kernel
                    .verify_lease(&mut lease, &AtomicBool::new(false))?;
                owner.kernel.source()
            },
        )
        .unwrap();
        assert!(!owner.valid.get());
        assert_eq!(state.borrow().loaded, 1);
        let result = release.run(
            || {
                if release_fault == 0 {
                    Err(Error::Conflict)
                } else {
                    Ok(())
                }
            },
            || {
                if release_fault == 1 {
                    Err(Error::Native)
                } else {
                    Ok(())
                }
            },
            || Ok(()),
        );
        assert_eq!(result.is_ok(), release_fault == 2);
        let queried = Cell::new(false);
        assert!(pin
            .inspect_cleanup_with(
                &AtomicBool::new(false),
                || {
                    if release.was_attempted() {
                        Err(Error::Conflict)
                    } else {
                        Ok(())
                    }
                },
                |_| {
                    queried.set(true);
                    Ok(())
                }
            )
            .is_err());
        assert!(!queried.get());
        assert!(!owner.valid.get());
        assert_eq!(state.borrow().unloads, 0);
    }
}

// Break: error/unwind/swallowed reentry publishes fresh factual trust or
// nested image verification re-arms the same original's poisoned forward gate.
#[test]
fn original_load_cleanup_read_error_unwind_and_reentry_are_sticky() {
    for fault in 0..3 {
        let state = Shared::default();
        let mut attempt = LoadAttempt::empty();
        attempt
            .load(Boundary(state.clone()), &AtomicBool::new(false))
            .unwrap();
        let mut pin = None;
        attempt
            .retain_original_load_read_into(&mut pin, |_| Ok(()))
            .unwrap();
        let pin = pin.unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pin.inspect_cleanup_with(
                &AtomicBool::new(false),
                || Ok(()),
                |_| match fault {
                    0 => Err(Error::Native),
                    1 => panic!("cleanup facts unwind"),
                    _ => {
                        assert!(pin
                            .inspect_cleanup_with(
                                &AtomicBool::new(false),
                                || Ok(()),
                                |_| panic!("nested query")
                            )
                            .is_err());
                        Ok(())
                    }
                },
            )
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert!(!pin.valid.get());
        assert!(pin
            .inspect_cleanup_with(
                &AtomicBool::new(false),
                || Ok(()),
                |_| panic!("tainted retry")
            )
            .is_err());
        assert!(!pin.valid.get());
        assert_eq!(state.borrow().loaded, 1);
        assert_eq!(state.borrow().unloads, 0);
    }
}

// Break: terminal disposition was selected before the native release protocol
// began (e.g. allocation/unwind), but an independent pin can still query image.
#[test]
fn original_load_read_denies_selected_disposition_before_release_protocol() {
    let state = Shared::default();
    let mut attempt = LoadAttempt::empty();
    attempt
        .load(Boundary(state.clone()), &AtomicBool::new(false))
        .unwrap();
    let mut pin = None;
    attempt
        .retain_original_load_read_into(&mut pin, |_| Ok(()))
        .unwrap();
    let pin = pin.unwrap();
    attempt.deny_original_load_reads();
    assert!(attempt.verify_original_load_read(&pin, Rc::ptr_eq).is_err());
    let queried = Cell::new(false);
    assert!(pin
        .inspect_cleanup_with(
            &AtomicBool::new(false),
            || Ok(()),
            |_| {
                queried.set(true);
                Ok(())
            }
        )
        .is_err());
    assert!(!queried.get());
    assert!(!pin.valid.get());
    assert_eq!(state.borrow().unloads, 0);
}

#[test]
fn load_attempt_retains_internal_os_ack_before_failed_postload_queries() {
    // Break: keeping the OS load ACK in a local until package/image/source
    // checks complete implicitly unloads the original on Err or unwind.
    for failure in 10..=13 {
        for unwinds in [false, true] {
            let s = Shared::default();
            if unwinds {
                s.borrow_mut().panic = Some(failure);
            } else {
                s.borrow_mut().fail = Some(failure);
            }
            let mut attempt = LoadAttempt::empty();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                attempt.load(Boundary(s.clone()), &AtomicBool::new(false))
            }));
            assert!(result.is_err() || result.unwrap().is_err());
            assert_eq!(s.borrow().loaded, 1);
            assert_eq!(s.borrow().unloads, 0);
            assert!(
                s.borrow().original_load_retained,
                "actual retained load ACK must precede every post-load Err/unwind"
            );
            assert!(
                !s.borrow().lease_held,
                "rundown releases timing lease, not module ACK"
            );
            let owner = attempt.owner.as_ref().expect("original internal load ACK");
            assert!(
                !owner.valid.get(),
                "failed postload is never executable trust"
            );
            let calls = s.borrow().calls.len();
            assert!(attempt
                .load(Boundary(s.clone()), &AtomicBool::new(false))
                .is_err());
            assert_eq!(s.borrow().calls.len(), calls);
            drop(attempt);
            assert_eq!(s.borrow().unloads, 0, "abandonment is not cleanup");
        }
    }
}

#[test]
fn authenticated_cold_load_holds_original_module_after_bracketed_load() {
    let s = Shared::default();
    let loaded = load(Boundary(s.clone()), &AtomicBool::new(false)).unwrap();
    assert!(loaded.valid.get());
    assert_eq!(&s.borrow().calls[..13], EXPECTED);
    assert_eq!(s.borrow().calls[13..], ["release"]);
    assert_eq!(s.borrow().loaded, 1);
    assert_eq!(s.borrow().unloads, 0);
    assert!(!s.borrow().lease_held);
    drop(loaded);
    assert_eq!(s.borrow().unloads, 1);
}

#[test]
fn cancelled_load_never_enters_source_or_native_boundary() {
    let s = Shared::default();
    assert!(matches!(
        load(Boundary(s.clone()), &AtomicBool::new(true)),
        Err(Error::Cancelled)
    ));
    assert!(s.borrow().calls.is_empty());
}

#[test]
fn each_failed_load_boundary_retains_unknown_ack_and_releases_timing_lease() {
    for failure in 1..=13 {
        let s = Shared::default();
        s.borrow_mut().fail = Some(failure);
        assert!(load(Boundary(s.clone()), &AtomicBool::new(false)).is_err());
        let state = s.borrow();
        assert!(!state.lease_held);
        assert_eq!(state.loaded, usize::from(failure > 9));
        assert_eq!(state.unloads, 0);
        assert_eq!(&state.calls[..failure], &EXPECTED[..failure]);
        if failure > 3 {
            assert_eq!(state.calls[failure..], ["release"]);
        }
    }
}

#[test]
fn unwinding_after_load_never_implicitly_releases_original_module_reference() {
    for failure in 1..=13 {
        let s = Shared::default();
        s.borrow_mut().panic = Some(failure);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            load(Boundary(s.clone()), &AtomicBool::new(false))
        }))
        .is_err());
        let state = s.borrow();
        assert!(!state.lease_held);
        assert_eq!(state.loaded, usize::from(failure > 9));
        assert_eq!(state.unloads, 0);
    }
}

#[test]
fn cancellation_at_last_native_absence_never_executes_dll_initialization() {
    for at in [5, 8] {
        let s = Shared::default();
        let cancelled = Rc::new(AtomicBool::new(false));
        s.borrow_mut().cancel_at = Some((at, cancelled.clone()));
        assert!(matches!(
            load(Boundary(s.clone()), &cancelled),
            Err(Error::Cancelled)
        ));
        assert_eq!(s.borrow().loaded, 0);
        assert_eq!(s.borrow().unloads, 0);
        assert!(!s.borrow().lease_held);
    }
}

#[test]
fn cleanup_owned_refresh_after_poison_queries_all_boundaries_without_rearming() {
    let s = Shared::default();
    let mut loaded = load(Boundary(s.clone()), &AtomicBool::new(false)).unwrap();
    loaded.valid.set(false);
    s.borrow_mut().calls.clear();
    loaded
        .reattest_cleanup_with(&AtomicBool::new(false), |boundary| {
            assert!(boundary.0.borrow().lease_held);
            boundary.call("cleanup package")
        })
        .unwrap();
    assert_eq!(
        s.borrow().calls,
        [
            "lease",
            "source",
            "cleanup package",
            "source",
            "verify_lease",
            "module",
            "verify_lease",
            "release"
        ]
    );
    assert!(!loaded.valid.get());
    assert_eq!(
        loaded.reattest_cold(&AtomicBool::new(false)),
        Err(Error::Conflict)
    );
    assert_eq!(s.borrow().loaded, 1);
    assert_eq!(s.borrow().unloads, 0);
}

#[test]
fn cleanup_refresh_failure_or_unwind_never_revives_forward_module() {
    for failure in 1..=7 {
        for unwind in [false, true] {
            let s = Shared::default();
            let mut loaded = load(Boundary(s.clone()), &AtomicBool::new(false)).unwrap();
            s.borrow_mut().calls.clear();
            if unwind {
                s.borrow_mut().panic = Some(failure);
            } else {
                s.borrow_mut().fail = Some(failure);
            }
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                loaded.reattest_cleanup_with(&AtomicBool::new(false), |boundary| {
                    boundary.call("cleanup package")
                })
            }));
            if unwind {
                assert!(result.is_err());
            } else {
                assert_eq!(result.unwrap(), Err(Error::Conflict));
            }
            assert!(!loaded.valid.get());
            assert!(!s.borrow().lease_held);
            assert_eq!(s.borrow().unloads, 0);
        }
    }
}

#[test]
fn owned_package_refresh_uses_same_lease_and_factual_image_reads_without_reloading() {
    let s = Shared::default();
    let mut loaded = load(Boundary(s.clone()), &AtomicBool::new(false)).unwrap();
    s.borrow_mut().calls.clear();
    let valid = loaded.valid.clone();
    loaded
        .reattest_with(&AtomicBool::new(false), |boundary| {
            assert!(boundary.0.borrow().lease_held);
            assert!(!valid.get());
            image_cleanup_read(&valid, || boundary.call("original image"))?;
            assert!(!valid.get()); // the inner factual read cannot rearm the caller
            boundary.call("owned package")
        })
        .unwrap();
    assert_eq!(
        s.borrow().calls,
        [
            "lease",
            "source",
            "original image",
            "owned package",
            "source",
            "verify_lease",
            "module",
            "verify_lease",
            "release"
        ]
    );
    assert!(valid.get());
    assert_eq!(s.borrow().loaded, 1);
}

#[test]
fn owned_package_error_or_unwind_never_rearms_module_or_releases_its_original_pin() {
    for unwind in [false, true] {
        let s = Shared::default();
        let mut loaded = load(Boundary(s.clone()), &AtomicBool::new(false)).unwrap();
        s.borrow_mut().calls.clear();
        let valid = loaded.valid.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            loaded.reattest_with(&AtomicBool::new(false), |_| {
                image_cleanup_read(&valid, || Ok(()))?;
                if unwind {
                    panic!("unknown post-create package query");
                }
                Err(Error::Native)
            })
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), Err(Error::Native));
        }
        assert!(!valid.get());
        assert!(!s.borrow().lease_held);
        assert_eq!(s.borrow().unloads, 0);
        assert_eq!(
            loaded.reattest_with(&AtomicBool::new(false), |_| {
                panic!("revoked original must never query again")
            }),
            Err(Error::Conflict)
        );
        drop(loaded);
        assert_eq!(s.borrow().unloads, 1);
    }
}

#[test]
fn fresh_cold_module_borrow_never_reuses_prior_source_or_package_check() {
    let s = Shared::default();
    let mut loaded = load(Boundary(s.clone()), &AtomicBool::new(false)).unwrap();
    s.borrow_mut().calls.clear();
    loaded.reattest_cold(&AtomicBool::new(false)).unwrap();
    assert_eq!(
        s.borrow().calls,
        [
            "lease",
            "source",
            "package",
            "source",
            "verify_lease",
            "module",
            "verify_lease",
            "release"
        ]
    );
    assert!(loaded.valid.get());
    assert_eq!(s.borrow().loaded, 1);
    assert_eq!(s.borrow().unloads, 0);
}

#[test]
fn cold_reattest_error_or_panic_permanently_revokes_executable_borrow() {
    for failure in 1..=7 {
        for panic in [false, true] {
            let s = Shared::default();
            let mut loaded = load(Boundary(s.clone()), &AtomicBool::new(false)).unwrap();
            s.borrow_mut().calls.clear();
            if panic {
                s.borrow_mut().panic = Some(failure);
            } else {
                s.borrow_mut().fail = Some(failure);
            }
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                loaded.reattest_cold(&AtomicBool::new(false))
            }));
            if panic {
                assert!(result.is_err());
            } else {
                assert_eq!(result.unwrap(), Err(Error::Conflict));
            }
            assert!(!loaded.valid.get());
            assert!(!s.borrow().lease_held);
            let calls = s.borrow().calls.clone();
            assert_eq!(
                loaded.reattest_cold(&AtomicBool::new(false)),
                Err(Error::Conflict)
            );
            assert_eq!(s.borrow().calls, calls);
            assert_eq!(s.borrow().unloads, 0);
            drop(loaded);
            assert_eq!(s.borrow().unloads, 1);
        }
    }
}

#[test]
fn revoked_cooperative_lease_cannot_initialize_or_return_executable_module() {
    let s = Shared::default();
    s.borrow_mut().deny_lease_verification = true;
    assert!(matches!(
        load(Boundary(s.clone()), &AtomicBool::new(false)),
        Err(Error::Conflict)
    ));
    assert_eq!(s.borrow().loaded, 0);
    assert!(!s.borrow().lease_held);

    let s = Shared::default();
    let mut loaded = load(Boundary(s.clone()), &AtomicBool::new(false)).unwrap();
    s.borrow_mut().deny_lease_verification = true;
    assert_eq!(
        loaded.reattest_cold(&AtomicBool::new(false)),
        Err(Error::Conflict)
    );
    assert!(!loaded.valid.get());
    assert!(!s.borrow().lease_held);
    assert_eq!(s.borrow().loaded, 1);
}

#[test]
fn poisoned_forward_image_still_supports_authenticated_factual_cleanup_reads_without_rearming() {
    // Break caught: using the irreversible forward gate for factual cleanup,
    // or inadvertently restoring forward permission after successful cleanup.
    let valid = Cell::new(false);
    let calls = Cell::new(0);
    assert_eq!(
        image_cleanup_read(&valid, || {
            calls.set(calls.get() + 1);
            Ok(())
        }),
        Ok(())
    );
    assert_eq!(calls.get(), 1);
    assert!(!valid.get());
    assert_eq!(
        image_read(&valid, || panic!("must not rearm")),
        Err(Error::Conflict)
    );
}

#[test]
fn failed_cleanup_read_revokes_a_previously_live_image_and_cannot_mask_errors() {
    let valid = Cell::new(true);
    assert_eq!(
        image_cleanup_read(&valid, || Err(Error::Native)),
        Err(Error::Native)
    );
    assert!(!valid.get());
    let valid = Cell::new(true);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        image_cleanup_read(&valid, || panic!("actual source query failed"))
    }));
    assert!(result.is_err());
    assert!(!valid.get());
}

#[test]
fn original_image_read_failure_revokes_every_retained_reader() {
    for unwind in [false, true] {
        let valid = Rc::new(std::cell::Cell::new(true));
        let other_reader = valid.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            image_read(&valid, || {
                assert!(!other_reader.get()); // unavailable during validation
                if unwind {
                    panic!("source/image query failed");
                }
                Err(Error::Native)
            })
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), Err(Error::Native));
        }
        assert!(!other_reader.get());
        assert_eq!(
            image_read(&other_reader, || panic!("cannot rearm")),
            Err(Error::Conflict)
        );
    }
}

#[test]
fn original_image_read_success_never_executes_cold_package_or_load() {
    let valid = std::cell::Cell::new(true);
    let calls = RefCell::new(vec![]);
    image_read(&valid, || {
        calls
            .borrow_mut()
            .extend(["original source", "original image", "original source"]);
        Ok(())
    })
    .unwrap();
    assert!(valid.get());
    assert_eq!(
        *calls.borrow(),
        ["original source", "original image", "original source"]
    );
}

const HELD_REFRESH: [&str; 9] = [
    "runtime",
    "lease",
    "source",
    "owned package",
    "source",
    "verify_lease",
    "module",
    "verify_lease",
    "runtime",
];

#[test]
fn retained_module_keeps_cooperative_lease_across_the_callers_effect() {
    // Break caught: returning only the module and dropping the acquired lease
    // before the caller can perform its separately authorized operation.
    let s = Shared::default();
    let cancelled = AtomicBool::new(false);
    let mut loaded = load(Boundary(s.clone()), &cancelled).unwrap();
    let valid = loaded.valid.clone();
    s.borrow_mut().calls.clear();
    let held = loaded
        .retain_with(
            &cancelled,
            false,
            &mut (),
            |boundary, ()| boundary.call("runtime"),
            |boundary, ()| boundary.call("owned package"),
        )
        .unwrap();
    assert!(valid.get());
    assert!(s.borrow().lease_held);
    assert_eq!(s.borrow().calls, HELD_REFRESH);
    assert!(Rc::ptr_eq(&held.module.0, &s));
    // Portable caller operation, never a native effect.
    s.borrow_mut().calls.push("caller effect");
    drop(held);
    assert!(!s.borrow().lease_held);
    assert_eq!(s.borrow().calls[9..], ["caller effect", "release"]);
    assert_eq!(s.borrow().loaded, 1);
    assert_eq!(s.borrow().unloads, 0);
    drop(loaded);
    assert_eq!(s.borrow().calls[11..], ["unload"]);
}

#[test]
fn retained_refresh_errors_and_unwinds_poison_shared_image_at_every_boundary() {
    // Break caught: authentication outside the poison gate, or leaked lease
    // on an early/late failed runtime, source, package, module or lease check.
    for cleanup in [false, true] {
        for failure in 1..=9 {
            for unwind in [false, true] {
                let s = Shared::default();
                let cancelled = AtomicBool::new(false);
                let mut loaded = load(Boundary(s.clone()), &cancelled).unwrap();
                let image_valid = loaded.valid.clone();
                s.borrow_mut().calls.clear();
                if unwind {
                    s.borrow_mut().panic = Some(failure);
                } else {
                    s.borrow_mut().fail = Some(failure);
                }
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    loaded
                        .retain_with(
                            &cancelled,
                            cleanup,
                            &mut (),
                            |boundary, ()| boundary.call("runtime"),
                            |boundary, ()| boundary.call("owned package"),
                        )
                        .map(drop)
                }));
                if unwind {
                    assert!(result.is_err());
                } else {
                    assert_eq!(result.unwrap(), Err(Error::Conflict));
                }
                assert!(!image_valid.get());
                assert!(!s.borrow().lease_held);
                assert_eq!(&s.borrow().calls[..failure], &HELD_REFRESH[..failure]);
                assert_eq!(
                    &s.borrow().calls[failure..],
                    if failure > 2 {
                        &["release"][..]
                    } else {
                        &[][..]
                    }
                );
                assert_eq!(s.borrow().unloads, 0);
            }
        }
    }
}

#[test]
fn cancellation_before_or_during_retained_refresh_never_returns_a_lease() {
    // Break caught: missing entry/final cancellation checks, including a
    // cancellation raised by the last outer runtime verification.
    for cleanup in [false, true] {
        for at in 0..=9 {
            let s = Shared::default();
            let cancelled = Rc::new(AtomicBool::new(false));
            let mut loaded = load(Boundary(s.clone()), &cancelled).unwrap();
            s.borrow_mut().calls.clear();
            if at == 0 {
                cancelled.store(true, Ordering::Release);
            } else {
                s.borrow_mut().cancel_at = Some((at, cancelled.clone()));
            }
            assert!(matches!(
                loaded.retain_with(
                    &cancelled,
                    cleanup,
                    &mut (),
                    |boundary, ()| boundary.call("runtime"),
                    |boundary, ()| boundary.call("owned package")
                ),
                Err(Error::Cancelled)
            ));
            assert!(!loaded.valid.get());
            assert!(!s.borrow().lease_held);
            assert_eq!(s.borrow().unloads, 0);
            if at == 0 {
                assert!(s.borrow().calls.is_empty());
            }
        }
    }
}

#[test]
fn held_cleanup_refresh_preserves_poison_and_denies_later_forward_reads() {
    // Break caught: successful factual cleanup reviving a denied forward gate.
    let s = Shared::default();
    let cancelled = AtomicBool::new(false);
    let mut loaded = load(Boundary(s.clone()), &cancelled).unwrap();
    let valid = loaded.valid.clone();
    loaded.valid.set(false);
    s.borrow_mut().calls.clear();
    let held = loaded
        .retain_with(
            &cancelled,
            true,
            &mut (),
            |boundary, ()| boundary.call("runtime"),
            |boundary, ()| boundary.call("owned package"),
        )
        .unwrap();
    assert!(!valid.get());
    assert!(s.borrow().lease_held);
    drop(held);
    let calls = s.borrow().calls.clone();
    assert!(matches!(
        loaded.retain_with(
            &cancelled,
            false,
            &mut (),
            |_, ()| panic!("denied forward runtime query"),
            |_, ()| panic!("denied forward package query")
        ),
        Err(Error::Conflict)
    ));
    assert_eq!(s.borrow().calls, calls);
}

#[test]
fn nested_original_image_read_cannot_rearm_the_in_progress_retained_refresh() {
    // Break caught: restoring forward trust before the outer package/module/
    // runtime checks finish, despite the inner inventory's factual image read.
    let s = Shared::default();
    let cancelled = AtomicBool::new(false);
    let mut loaded = load(Boundary(s.clone()), &cancelled).unwrap();
    let valid = loaded.valid.clone();
    let held = loaded
        .retain_with(
            &cancelled,
            false,
            &mut (),
            |boundary, ()| {
                assert!(!valid.get());
                boundary.call("runtime")
            },
            |boundary, ()| {
                assert!(boundary.0.borrow().lease_held);
                image_cleanup_read(&valid, || Ok(()))?;
                assert!(!valid.get());
                boundary.call("owned package")
            },
        )
        .unwrap();
    assert!(valid.get());
    drop(held);
}

#[test]
fn retained_holder_releases_the_lease_on_caller_error_or_unwind() {
    // Break caught: transferring the lease out of RAII ownership on success.
    for unwind in [false, true] {
        let s = Shared::default();
        let cancelled = AtomicBool::new(false);
        let mut loaded = load(Boundary(s.clone()), &cancelled).unwrap();
        s.borrow_mut().calls.clear();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
            let _held = loaded.retain_with(
                &cancelled,
                false,
                &mut (),
                |boundary, ()| boundary.call("runtime"),
                |boundary, ()| boundary.call("owned package"),
            )?;
            assert!(s.borrow().lease_held);
            if unwind {
                panic!("caller operation unwound");
            }
            Err(Error::Native)
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), Err(Error::Native));
        }
        assert!(!s.borrow().lease_held);
        assert_eq!(s.borrow().calls[9..], ["release"]);
        assert_eq!(s.borrow().unloads, 0);
    }
}

#[test]
fn retained_original_module_outlives_loaded_and_drops_before_the_lease() {
    // Break caught: retaining only an HMODULE number, or releasing the lease
    // before the holder releases the last original DLL reference.
    for unwind in [false, true] {
        let s = Shared::default();
        let cancelled = AtomicBool::new(false);
        let mut loaded = load(Boundary(s.clone()), &cancelled).unwrap();
        s.borrow_mut().calls.clear();
        let held = loaded
            .retain_with(
                &cancelled,
                false,
                &mut (),
                |boundary, ()| boundary.call("runtime"),
                |boundary, ()| boundary.call("owned package"),
            )
            .unwrap();
        drop(loaded);
        assert_eq!(s.borrow().unloads, 0);
        assert!(s.borrow().lease_held);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _held = held;
            if unwind {
                panic!("caller unwound after dropping Loaded");
            }
        }));
        assert_eq!(result.is_err(), unwind);
        assert_eq!(s.borrow().calls[9..], ["unload", "release"]);
        assert_eq!(s.borrow().unloads, 1);
        assert!(!s.borrow().lease_held);
    }
}

#[test]
fn denied_lease_verification_never_returns_a_retained_resource_owner() {
    // Break caught: trusting acquisition and omitting the actual held lease's
    // independent verification at the protected module-return seam.
    let s = Shared::default();
    let cancelled = AtomicBool::new(false);
    let mut loaded = load(Boundary(s.clone()), &cancelled).unwrap();
    s.borrow_mut().calls.clear();
    s.borrow_mut().deny_lease_verification = true;
    assert!(matches!(
        loaded.retain_with(
            &cancelled,
            false,
            &mut (),
            |boundary, ()| boundary.call("runtime"),
            |boundary, ()| boundary.call("owned package")
        ),
        Err(Error::Conflict)
    ));
    assert!(!loaded.valid.get());
    assert!(!s.borrow().lease_held);
    assert_eq!(
        s.borrow().calls,
        [
            "runtime",
            "lease",
            "source",
            "owned package",
            "source",
            "verify_lease",
            "release",
        ]
    );
}

#[test]
fn held_verification_checks_the_same_resource_without_releasing_the_lease() {
    // Break caught: checking a newly acquired lease instead of the lease held
    // across the caller's seam, or dropping it after a successful verification.
    let s = Shared::default();
    let cancelled = AtomicBool::new(false);
    let mut loaded = load(Boundary(s.clone()), &cancelled).unwrap();
    let valid = loaded.valid.clone();
    let mut held = loaded
        .retain_with(
            &cancelled,
            false,
            &mut (),
            |boundary, ()| boundary.call("runtime"),
            |boundary, ()| boundary.call("owned package"),
        )
        .unwrap();
    s.borrow_mut().calls.clear();
    let mut boundary = Boundary(s.clone());
    held.verify_with(&valid, false, &cancelled, |module, lease| {
        assert!(!valid.get());
        assert!(Rc::ptr_eq(&module.0, &s));
        boundary.verify_lease(lease, &cancelled)
    })
    .unwrap();
    assert!(valid.get());
    assert!(s.borrow().lease_held);
    assert_eq!(s.borrow().calls, ["verify_lease"]);
    drop(loaded);
    drop(held);
    assert_eq!(s.borrow().calls[1..], ["unload", "release"]);
}

#[test]
fn held_verification_errors_and_unwinds_poison_all_readers_but_retain_resources_until_drop() {
    // Break caught: failed retained lease/runtime checks leaving the shared
    // OriginalImage forward state valid, or relinquishing resources mid-seam.
    for cleanup in [false, true] {
        for unwind in [false, true] {
            let s = Shared::default();
            let cancelled = AtomicBool::new(false);
            let mut loaded = load(Boundary(s.clone()), &cancelled).unwrap();
            let valid = loaded.valid.clone();
            let mut held = loaded
                .retain_with(
                    &cancelled,
                    false,
                    &mut (),
                    |boundary, ()| boundary.call("runtime"),
                    |boundary, ()| boundary.call("owned package"),
                )
                .unwrap();
            s.borrow_mut().calls.clear();
            if unwind {
                s.borrow_mut().panic = Some(1);
            } else {
                s.borrow_mut().deny_lease_verification = true;
            }
            let mut boundary = Boundary(s.clone());
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                held.verify_with(&valid, cleanup, &cancelled, |_, lease| {
                    boundary.verify_lease(lease, &cancelled)
                })
            }));
            if unwind {
                assert!(result.is_err());
            } else {
                assert_eq!(result.unwrap(), Err(Error::Conflict));
            }
            assert!(!valid.get());
            assert!(s.borrow().lease_held);
            assert_eq!(s.borrow().unloads, 0);
            assert_eq!(
                held.verify_with(&valid, false, &cancelled, |_, _| panic!(
                    "poisoned forward owner must not recheck"
                )),
                Err(Error::Conflict)
            );
            drop(loaded);
            drop(held);
            assert_eq!(s.borrow().calls, ["verify_lease", "unload", "release"]);
        }
    }
}

#[test]
fn held_cleanup_verification_preserves_prior_poison() {
    // Break caught: cleanup rechecks granting forward permission afterward.
    let s = Shared::default();
    let cancelled = AtomicBool::new(false);
    let mut loaded = load(Boundary(s.clone()), &cancelled).unwrap();
    let valid = loaded.valid.clone();
    valid.set(false);
    let mut held = loaded
        .retain_with(
            &cancelled,
            true,
            &mut (),
            |boundary, ()| boundary.call("runtime"),
            |boundary, ()| boundary.call("owned package"),
        )
        .unwrap();
    let mut boundary = Boundary(s.clone());
    held.verify_with(&valid, true, &cancelled, |_, lease| {
        boundary.verify_lease(lease, &cancelled)
    })
    .unwrap();
    assert!(!valid.get());
    assert!(s.borrow().lease_held);
}

#[test]
fn forward_acquired_holder_supports_factual_cleanup_after_revocation_without_rearming() {
    let s = Shared::default();
    let cancelled = AtomicBool::new(false);
    let mut loaded = load(Boundary(s.clone()), &cancelled).unwrap();
    let valid = loaded.valid.clone();
    let mut held = loaded
        .retain_with(
            &cancelled,
            false,
            &mut (),
            |boundary, ()| boundary.call("runtime"),
            |boundary, ()| boundary.call("owned package"),
        )
        .unwrap();
    valid.set(false);
    let mut boundary = Boundary(s.clone());
    held.verify_with(&valid, true, &cancelled, |_, lease| {
        boundary.verify_lease(lease, &cancelled)
    })
    .unwrap();
    assert!(!valid.get());
    assert!(s.borrow().lease_held);
    assert_eq!(
        held.verify_with(&valid, false, &cancelled, |_, _| {
            panic!("factual cleanup must not restore forward grant")
        }),
        Err(Error::Conflict)
    );
    drop(loaded);
    drop(held);
    assert_eq!(s.borrow().unloads, 1);
    assert!(!s.borrow().lease_held);
}

#[test]
fn cancellation_at_held_verification_entry_or_exit_poisons_shared_forward_state() {
    // Break caught: checking cancellation only when the lease was acquired.
    for cleanup in [false, true] {
        for at_entry in [false, true] {
            let s = Shared::default();
            let cancelled = AtomicBool::new(false);
            let mut loaded = load(Boundary(s.clone()), &cancelled).unwrap();
            let valid = loaded.valid.clone();
            let mut held = loaded
                .retain_with(
                    &cancelled,
                    false,
                    &mut (),
                    |boundary, ()| boundary.call("runtime"),
                    |boundary, ()| boundary.call("owned package"),
                )
                .unwrap();
            cancelled.store(at_entry, Ordering::Release);
            let called = Cell::new(false);
            assert_eq!(
                held.verify_with(&valid, cleanup, &cancelled, |_, _| {
                    called.set(true);
                    cancelled.store(true, Ordering::Release);
                    Ok(())
                }),
                Err(Error::Cancelled)
            );
            assert_eq!(called.get(), !at_entry);
            assert!(!valid.get());
            assert!(s.borrow().lease_held);
        }
    }
}

#[cfg(windows)]
fn actual_original_native_load_reader_compile_contract(
    loaded: &native::LoadedWintun,
    runtime: &crate::windows::member_carrier_key_authority::RuntimeRead,
    source: &Rc<crate::windows::member_carrier_payload::native::WintunSource>,
    cancelled: &AtomicBool,
) -> Result<()> {
    // Actual native types and callsites only; never invoked on host/Windows.
    let mut original = None;
    loaded.retain_original_load_read_into(&mut original)?;
    let original: Rc<native::NativeOriginalModuleLoadRead> = original.ok_or(Error::Conflict)?;
    loaded.verify_original_load_read(&original)?;
    if !original.same_original(&original.clone())
        || !original.matches_source(source)
        || !original.matches_runtime(runtime)
    {
        return Err(Error::Conflict);
    }
    original.verify_cleanup_read(runtime, cancelled)?;
    original.verify_process_code_lifetime()?;
    loaded.verify_original_load_read(&original)
}

#[cfg(windows)]
fn actual_retained_runtime_and_native_lease_compile_contract(
    loaded: &mut native::LoadedWintun,
    runtime: &crate::windows::member_carrier_key_authority::RuntimeRead,
    cancelled: &AtomicBool,
    originals: &mut crate::windows::member_carrier_wintun::native::OriginalPackageInventory,
) -> Result<()> {
    // Compile-only regression with actual native types. Never executed.
    let _ = loaded.original_owned_module_read(runtime, cancelled, originals)?;
    let _ = loaded.original_owned_module_read_for_cleanup(runtime, cancelled, originals)?;
    let mut held: native::OriginalModuleLease =
        loaded.retain_owned_module_read(runtime, cancelled, originals)?;
    held.verify(cancelled)?;
    // Cleanup of the SAME previously forward-acquired holder remains factual
    // after revocation; it must not require or revive its old forward grant.
    held.verify_for_cleanup(cancelled)?;
    let _: std::ptr::NonNull<std::ffi::c_void> = held.module();
    drop(held);
    let mut cleanup: native::OriginalModuleLease =
        loaded.retain_owned_module_read_for_cleanup(runtime, cancelled, originals)?;
    cleanup.verify(cancelled)?;
    let _: std::ptr::NonNull<std::ffi::c_void> = cleanup.module();
    Ok(())
}
// Break: pin native return is local until postflight, an uncertain pin retries,
// or code can be exposed before the genuine original pin completes.
#[test]
fn process_anchor_retains_native_pin_before_postflight_and_denies_unknown_sdk() {
    for fault in 0..5 {
        let source = Rc::new(Cell::new(7_u8));
        let anchor = ProcessAnchor::new(source.clone());
        assert!(anchor
            .inspect(|_, _: &Rc<Cell<u8>>| panic!("SDK before ACK"))
            .is_err());
        let native = Rc::new(Cell::new(19_u8));
        let calls = Cell::new(0);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            anchor.pin(
                || Ok(()),
                || {
                    calls.set(calls.get() + 1);
                    match fault {
                        0 => Err(Error::Native),
                        1 => panic!("pin OS unknown"),
                        _ => Ok(native.clone()),
                    }
                },
                |original| {
                    assert!(Rc::ptr_eq(anchor.ack.borrow().as_ref().unwrap(), original));
                    assert!(Rc::ptr_eq(original.as_ref(), &native));
                    match fault {
                        2 => Err(Error::Conflict),
                        3 => panic!("pin postflight"),
                        _ => Ok(()),
                    }
                },
            )
        }));
        assert_eq!(result.is_ok() && result.unwrap().is_ok(), fault == 4);
        assert_eq!(anchor.ack.borrow().is_some(), fault >= 2);
        assert_eq!(calls.get(), 1);
        assert_eq!(
            anchor
                .inspect(|actual_source, actual_pin| {
                    assert!(Rc::ptr_eq(actual_source, &source));
                    assert!(Rc::ptr_eq(actual_pin, &native));
                    Ok(())
                })
                .is_ok(),
            fault == 4
        );
        assert!(anchor
            .pin(|| panic!("retry check"), || panic!("retry pin"), |_| Ok(()))
            .is_err());
        assert_eq!(calls.get(), 1);
    }
}

// Break: swallowed pin/read reentry or source drift creates usable code trust.
#[test]
fn process_anchor_swallowed_pin_reentry_in_preflight_never_reaches_native_pin() {
    let anchor = ProcessAnchor::new(Rc::new(Cell::new(3_u8)));
    let calls = Cell::new(0);
    assert!(anchor
        .pin(
            || {
                assert!(anchor.pin(|| Ok(()), || Ok(7_usize), |_| Ok(())).is_err());
                Ok(()) // original checker catches the conflicting call
            },
            || {
                calls.set(calls.get() + 1);
                Ok(11_usize)
            },
            |_| Ok(())
        )
        .is_err());
    assert_eq!(
        calls.get(),
        0,
        "revoked preflight must not invoke the OS PIN"
    );
    assert!(anchor.ack.borrow().is_none());
    assert!(anchor
        .pin(|| Ok(()), || panic!("retry"), |_| Ok(()))
        .is_err());
    assert!(anchor.inspect(|_, _| panic!("unknown SDK")).is_err());
}

#[test]
fn process_anchor_reentry_and_original_drift_are_irreversible() {
    let source = Rc::new(Cell::new(3_u8));
    let anchor = ProcessAnchor::new(source.clone());
    assert!(anchor
        .pin(
            || Ok(()),
            || Ok(Rc::new(Cell::new(23_u8))),
            |_| {
                assert!(anchor
                    .pin(|| Ok(()), || panic!("duplicate pin"), |_| Ok(()))
                    .is_err());
                Ok(())
            }
        )
        .is_err());
    assert!(anchor.inspect(|_, _| panic!("uncertain SDK")).is_err());
    for fault in 0..3 {
        let anchor = ProcessAnchor::new(source.clone());
        anchor
            .pin(|| Ok(()), || Ok(Rc::new(Cell::new(23_u8))), |_| Ok(()))
            .unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            anchor.inspect(|_, _| match fault {
                0 => Err(Error::Conflict),
                1 => panic!("source/owner/file verification unwind"),
                _ => {
                    assert!(anchor.inspect(|_, _| panic!("nested SDK")).is_err());
                    Ok(())
                }
            })
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert!(anchor.inspect(|_, _| panic!("tainted SDK retry")).is_err());
        assert!(anchor.ack.borrow().is_some());
    }
}

// Break: a process anchor is weak/session-rooted, accepts a foreign registry,
// or must reuse the old session load receipt to make a repeat start succeed.
#[test]
fn process_anchor_registry_outlives_session_and_repeat_load_has_fresh_receipt() {
    let claim = AtomicBool::new(false);
    let registry = ProcessAnchorRegistry::new();
    let source = Rc::new(Cell::new(7_u8));
    let (anchor, first) = registry.select(source.clone(), &claim).unwrap();
    assert!(first);
    let pin_calls = Cell::new(0);
    anchor
        .pin(
            || Ok(()),
            || {
                pin_calls.set(1);
                Ok(41_usize)
            },
            |_| Ok(()),
        )
        .unwrap();
    let state = Shared::default();
    let mut old_session = LoadAttempt::empty();
    old_session
        .load(Boundary(state.clone()), &AtomicBool::new(false))
        .unwrap();
    let mut old_read = None;
    old_session
        .retain_original_load_read_into(&mut old_read, |_| Ok(()))
        .unwrap();
    // Host OS boundary owns this reference; native pin is a distinct object.
    drop(old_read.take());
    drop(old_session.owner.take());
    drop(old_session);
    assert_eq!(state.borrow().unloads, 1);
    let (same_anchor, first) = registry.select(source.clone(), &claim).unwrap();
    assert!(!first);
    assert!(Rc::ptr_eq(&same_anchor, &anchor));
    same_anchor
        .inspect(|held_source, pin| {
            assert!(Rc::ptr_eq(held_source, &source));
            assert_eq!(*pin, 41);
            Ok(())
        })
        .unwrap();
    let mut new_session = LoadAttempt::empty();
    new_session
        .load(Boundary(state.clone()), &AtomicBool::new(false))
        .unwrap();
    let mut new_read = None;
    new_session
        .retain_original_load_read_into(&mut new_read, |_| Ok(()))
        .unwrap();
    assert_eq!(
        state.borrow().loaded,
        2,
        "repeat still calls real loader boundary"
    );
    assert_eq!(pin_calls.get(), 1);
    let foreign_registry = ProcessAnchorRegistry::<_, usize>::new();
    assert!(foreign_registry.select(source.clone(), &claim).is_err());
    let weak = Rc::downgrade(&anchor);
    drop(same_anchor);
    drop(anchor);
    drop(registry); // thread exit cannot discard the process source/owner anchor
    assert!(weak.upgrade().is_some());
}

// Break: pre-PIN cancellation/authentication failure permits a native call or
// a later SDK retry; late held-lease/source checks escape the sticky postflight.
#[test]
fn process_anchor_preflight_and_late_postflight_faults_never_rearm() {
    for phase in ["pre", "late"] {
        for fault in ["error", "unwind", "cancel"] {
            let claim = AtomicBool::new(false);
            let registry = ProcessAnchorRegistry::new();
            let source = Rc::new(Cell::new(5));
            let (root, _) = registry.select(source.clone(), &claim).unwrap();
            let pin_calls = Cell::new(0);
            let cancel = AtomicBool::new(false);
            let fail = || match fault {
                "error" => Err(Error::Conflict),
                "unwind" => panic!("original authentication/held lease failed"),
                _ => {
                    cancel.store(true, Ordering::Release);
                    checkpoint(&cancel)
                }
            };
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                root.pin(
                    || if phase == "pre" { fail() } else { Ok(()) },
                    || {
                        pin_calls.set(pin_calls.get() + 1);
                        Ok(53_usize)
                    },
                    |ack| {
                        assert!(Rc::ptr_eq(root.ack.borrow().as_ref().unwrap(), ack));
                        fail()
                    },
                )
            }));
            assert!(result.is_err() || result.unwrap().is_err());
            assert_eq!(pin_calls.get(), usize::from(phase == "late"));
            assert_eq!(root.ack.borrow().is_some(), phase == "late");
            cancel.store(false, Ordering::Release); // external cancellation clearing is NOT rearm
            let (same, first) = registry.select(source, &claim).unwrap();
            assert!(!first);
            assert!(Rc::ptr_eq(&root, &same));
            assert!(same.inspect(|_, _| panic!("unknown SDK exposure")).is_err());
            assert!(same
                .pin(|| Ok(()), || panic!("second PIN"), |_| Ok(()))
                .is_err());
        }
    }
}

// Break: repeat inspection skips external source authentication, swallows its
// failure, or roots a session/serialized lease with the process source.
#[test]
fn process_anchor_repeat_authentication_failure_is_sticky() {
    struct Source {
        engine: std::sync::Arc<()>,
        file: Rc<Cell<u64>>,
    }
    {
        let engine = std::sync::Arc::new(());
        let file = Rc::new(Cell::new(71_u64));
        let original = Rc::new(Source {
            engine: engine.clone(),
            file: file.clone(),
        });
        let claim = AtomicBool::new(false);
        let registry = ProcessAnchorRegistry::new();
        let (root, _) = registry.select(original.clone(), &claim).unwrap();
        root.pin(|| Ok(()), || Ok(59_usize), |_| Ok(())).unwrap();
        let current = Rc::new(Source {
            engine: engine.clone(),
            file: file.clone(),
        });
        let (same, first) = registry.select(current.clone(), &claim).unwrap();
        assert!(!first);
        assert!(Rc::ptr_eq(&root, &same));
        same.inspect(|held, pin| {
            // Independent source instances, but same retained engine/file. Only
            // external auth is doubled: registry/receipt/read protocol is real.
            assert!(!Rc::ptr_eq(held, &current));
            assert!(std::sync::Arc::ptr_eq(&held.engine, &current.engine));
            assert!(Rc::ptr_eq(&held.file, &current.file));
            assert_eq!(*pin, 59);
            Ok(())
        })
        .unwrap();
        let auth_reads = Cell::new(0);
        assert_eq!(
            same.inspect(|_, _| {
                auth_reads.set(auth_reads.get() + 1);
                Err(Error::Conflict) // external source authentication, not a fake resource grant
            }),
            Err(Error::Conflict)
        );
        assert_eq!(auth_reads.get(), 1);
        assert!(same.inspect(|_, _| panic!("foreign SDK exposure")).is_err());
        assert!(root.ack.borrow().is_some());
        assert!(std::sync::Arc::ptr_eq(&root.source.engine, &engine));
    }
}

// Break: a session's equal mapping/source/PIN values substitute for the exact
// process-registry root, or wrapper-only selection supplies a completed PIN.
#[test]
fn process_anchor_registry_requires_exact_original_not_equal_pin_values() {
    let registry = ProcessAnchorRegistry::new();
    let claim = AtomicBool::new(false);
    let source = Rc::new(Cell::new(79));
    let (root, _) = registry.select(source.clone(), &claim).unwrap();
    assert!(registry
        .inspect_original(&root, |_, _: &usize| panic!("no ACK"))
        .is_err());
    root.pin(|| Ok(()), || Ok(83_usize), |_| Ok(())).unwrap();
    let foreign = Rc::new(ProcessAnchor::new(source.clone()));
    foreign.pin(|| Ok(()), || Ok(83_usize), |_| Ok(())).unwrap();
    assert!(registry
        .inspect_original(&foreign, |_, _| panic!("equal raw PIN adoption"))
        .is_err());
    let reads = Cell::new(0);
    registry
        .inspect_original(&root.clone(), |actual, pin| {
            assert!(Rc::ptr_eq(actual, &source));
            assert_eq!(*pin, 83);
            reads.set(reads.get() + 1);
            Ok(())
        })
        .unwrap();
    assert_eq!(reads.get(), 1);
    let empty = ProcessAnchorRegistry::new();
    assert!(empty
        .inspect_original(&root, |_, _| panic!("foreign registry"))
        .is_err());
}

// Break: adopt an equal engine-owner object, changed signed runtime/file, or
// unknown file index. This comparator is used by the actual native sampler;
// file/engine inputs double external identity observations only, not ACKs.
#[test]
fn process_anchor_source_comparison_requires_same_owner_runtime_and_original_file() {
    use nelomai_contracts::{dispatcher::EngineIdentity, RuntimeSlot};
    let owner = std::sync::Arc::new(3_u8);
    let identity = EngineIdentity {
        slot: RuntimeSlot::Latest,
        runtime_version: "0.3.3".into(),
        runtime_contract_version: 1,
        container_version: "0.3.3".into(),
        manifest_sha256: "a".repeat(64),
    };
    for mutation in 0..11 {
        let mut current_owner = owner.clone();
        let mut current_identity = identity.clone();
        let mut original_file = (101, 103, 107);
        let mut current_file = (101, 103, 107);
        match mutation {
            0 => {}
            1 => current_owner = std::sync::Arc::new(3_u8), // equal owner value, foreign Arc
            2 => current_identity.slot = RuntimeSlot::Stable,
            3 => current_identity.runtime_version = "0.3.4".into(),
            4 => current_identity.runtime_contract_version = 2,
            5 => current_identity.container_version = "0.3.4".into(),
            6 => current_identity.manifest_sha256 = "b".repeat(64),
            7 => current_file.0 = 109,
            8 => current_file.1 = 109,
            9 => current_file.2 = 109,
            _ => {
                original_file = (101, 0, 0);
                current_file = (101, 0, 0);
            }
        }
        assert_eq!(
            compare_process_source_origin(
                &owner,
                &current_owner,
                &identity,
                &current_identity,
                original_file,
                current_file,
            )
            .is_ok(),
            mutation == 0,
            "mutation {mutation}"
        );
    }
}
