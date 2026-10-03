use super::*;
use nelomai_client_tunnel::redundancy::control::PairControl;

use crate::member_carrier_pair::tests::{
    ConstructionFault, StartupTransferFixture, StartupTransferOwner,
};

#[test]
fn module_only_cleanup_repeats_fresh_reads_but_never_retries_failed_calls() {
    use std::{
        cell::{Cell, RefCell},
        panic::{catch_unwind, AssertUnwindSafe},
    };
    for failure in 0..4 {
        let history = RefCell::new(Vec::new());
        let calls = Cell::new(0);
        for _ in 0..3 {
            run_repeated_module_only_read_call(
                &history,
                || Ok(()),
                || {
                    calls.set(calls.get() + 1);
                    Ok(())
                },
            )
            .unwrap();
        }
        assert_eq!(calls.get(), 3);
        let auth = Cell::new(0);
        let result = catch_unwind(AssertUnwindSafe(|| {
            run_repeated_module_only_read_call(
                &history,
                || {
                    auth.set(auth.get() + 1);
                    if failure == 0 || failure == 3 && auth.get() == 2 {
                        return Err(Error::Conflict);
                    }
                    Ok(())
                },
                || {
                    if failure == 2 {
                        panic!("native read unwind");
                    }
                    if failure == 1 {
                        return Err(Error::Native);
                    }
                    Ok(())
                },
            )
        }));
        assert!(!matches!(result, Ok(Ok(()))));
        assert_eq!(
            history.borrow().len(),
            4,
            "failed original call remains retained"
        );
        assert!(run_repeated_module_only_read_call(
            &history,
            || panic!("no retry"),
            || panic!("no read")
        )
        .is_err());
    }
    let history = RefCell::new(Vec::new());
    for _ in 0..32 {
        run_repeated_module_only_read_call(&history, || Ok(()), || Ok(())).unwrap();
    }
    assert!(run_repeated_module_only_read_call(
        &history,
        || panic!("bounded history"),
        || panic!("bounded read")
    )
    .is_err());
}

#[test]
fn module_only_read_completion_waits_for_authenticated_bounded_return() {
    use std::cell::{Cell, RefCell};
    let state = TerminalCallState::new();
    let events = RefCell::new(Vec::new());
    let calls = Cell::new(0);
    run_module_only_read_call(
        &state,
        || {
            events.borrow_mut().push("authenticate");
            Ok(())
        },
        || {
            calls.set(calls.get() + 1);
            events.borrow_mut().push("bounded_return");
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        *events.borrow(),
        ["authenticate", "bounded_return", "authenticate"]
    );
    state.verify().unwrap();
    assert!(run_module_only_read_call(
        &state,
        || panic!("no retry auth"),
        || panic!("no retry read")
    )
    .is_err());
    assert_eq!(calls.get(), 1);
    assert!(state.verify().is_err());
}

#[test]
fn module_only_read_failure_or_unwind_never_marks_completion_or_retries() {
    use std::cell::Cell;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    for fault in 0..5 {
        let state = TerminalCallState::new();
        let auth = Cell::new(0);
        let reads = Cell::new(0);
        let result = catch_unwind(AssertUnwindSafe(|| {
            run_module_only_read_call(
                &state,
                || {
                    let n = auth.get() + 1;
                    auth.set(n);
                    if fault == 0 || fault == 3 && n == 2 {
                        return Err(Error::Conflict);
                    };
                    if fault == 4 && n == 2 {
                        panic!("postflight")
                    };
                    Ok(())
                },
                || {
                    reads.set(reads.get() + 1);
                    if fault == 1 {
                        return Err(Error::Native);
                    };
                    if fault == 2 {
                        panic!("bounded reader")
                    };
                    Ok(())
                },
            )
        }));
        assert!(!matches!(result, Ok(Ok(()))));
        assert!(state.verify().is_err());
        assert!(run_module_only_read_call(
            &state,
            || panic!("no retry auth"),
            || panic!("no retry read")
        )
        .is_err());
        assert_eq!(reads.get(), usize::from(fault != 0));
    }
}

fn transfer_fixture(fixture: &mut StartupTransferFixture) -> std::io::Result<()> {
    transfer_startup_retained_into(
        &mut fixture.startup,
        &mut fixture.io,
        &mut fixture.journal,
        &mut fixture.pair,
        StartupTransferOwner::identity,
        StartupTransferOwner::cold,
    )
}

#[test]
fn retained_startup_transfer_roots_same_cold_owner_across_initial_journal_failures() {
    for fault in [
        ConstructionFault::LoadError(1),
        ConstructionFault::WriteError(true),
    ] {
        let mut fixture = StartupTransferFixture::new(fault);
        assert!(transfer_fixture(&mut fixture).is_err());
        fixture.assert_rooted();
        fixture.assert_denied();
        assert!(fixture.close().is_err());
        assert!(fixture.pair.as_ref().unwrap().cleanup_pending());
    }
}

#[test]
fn retained_startup_transfer_acknowledged_path_runs_actual_pair_lifecycle() {
    let mut fixture = StartupTransferFixture::new(ConstructionFault::None);
    transfer_fixture(&mut fixture).unwrap();
    fixture.assert_rooted();
    fixture.start_stop();
    fixture.assert_denied();
}

#[test]
fn retained_startup_transfer_journal_fault_and_unwind_matrix_retains_original_owner() {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    for fault in [
        ConstructionFault::LoadError(1),
        ConstructionFault::LoadUnwind(1),
        ConstructionFault::WriteError(false),
        ConstructionFault::WriteError(true),
        ConstructionFault::WriteUnwind(false),
        ConstructionFault::WriteUnwind(true),
        ConstructionFault::LoadError(2),
        ConstructionFault::LoadUnwind(2),
        ConstructionFault::ReadbackAbsent,
        ConstructionFault::ReadbackForeign,
    ] {
        let mut fixture = StartupTransferFixture::new(fault);
        let result = catch_unwind(AssertUnwindSafe(|| transfer_fixture(&mut fixture)));
        assert!(!matches!(result, Ok(Ok(()))), "{fault:?}");
        fixture.assert_rooted();
        fixture.assert_denied();
        assert!(fixture.pair.as_ref().unwrap().cleanup_pending());
        if matches!(
            fault,
            ConstructionFault::LoadError(2) | ConstructionFault::LoadUnwind(2)
        ) {
            fixture.close().unwrap();
            assert!(!fixture.pair.as_ref().unwrap().cleanup_pending());
        } else {
            assert!(fixture.close().is_err());
            assert!(fixture.pair.as_ref().unwrap().cleanup_pending());
        }
        fixture.assert_rooted();
        fixture.assert_denied();
    }
}

#[test]
fn retained_startup_transfer_invalid_identity_and_missing_owner_do_not_convert_or_publish() {
    for case in 0..7 {
        let mut fixture = StartupTransferFixture::new(ConstructionFault::None);
        let owner = fixture.startup.as_mut().unwrap();
        match case {
            0 => owner.scope.session_id = "invalid".into(),
            1 => owner.scope.runtime_generation = 0,
            2 => owner.scope.connection_generation = 0,
            3 => owner.provenance.boot_id = [0; 16],
            4 => owner.provenance.network_epoch = 0,
            5 => owner.provenance.runtime.slot = nelomai_contracts::RuntimeSlot::Latest,
            _ => owner.provenance.runtime.runtime_version = "v".repeat(70 * 1024),
        }
        assert!(transfer_startup_retained_into(
            &mut fixture.startup,
            &mut fixture.io,
            &mut fixture.journal,
            &mut fixture.pair,
            StartupTransferOwner::identity,
            |_| panic!("invalid original must not convert"),
        )
        .is_err());
        fixture.assert_untouched();
        assert!(fixture.io.is_none() && fixture.journal.is_none() && fixture.pair.is_none());
    }
    let mut fixture = StartupTransferFixture::new(ConstructionFault::None);
    let retained_elsewhere = fixture.startup.take();
    assert!(transfer_startup_retained_into(
        &mut fixture.startup,
        &mut fixture.io,
        &mut fixture.journal,
        &mut fixture.pair,
        |_| panic!("missing owner must not supply identity"),
        |_| panic!("missing owner must not convert"),
    )
    .is_err());
    assert!(fixture.io.is_none() && fixture.journal.is_none() && fixture.pair.is_none());
    fixture.startup = retained_elsewhere;
    fixture.assert_untouched();
}

#[test]
fn retained_startup_transfer_occupied_pair_preserves_incoming_and_fences_live_original() {
    let mut original = StartupTransferFixture::new(ConstructionFault::None);
    transfer_fixture(&mut original).unwrap();
    original.start();
    let mut incoming = StartupTransferFixture::new(ConstructionFault::None);
    incoming
        .startup
        .as_mut()
        .unwrap()
        .scope
        .connection_generation += 1;
    assert!(transfer_startup_retained_into(
        &mut incoming.startup,
        &mut incoming.io,
        &mut incoming.journal,
        &mut original.pair,
        |_| panic!("occupied Pair must not inspect incoming identity"),
        |_| panic!("occupied Pair must not convert incoming Startup"),
    )
    .is_err());
    incoming.assert_untouched();
    assert!(incoming.io.is_none() && incoming.journal.is_none());
    original.assert_rooted();
    original.assert_denied();
    original.close().unwrap();
    original.assert_denied();
}

#[test]
fn retained_startup_transfer_occupied_converted_slots_preserve_all_originals() {
    for occupied in 0..3 {
        let mut original = StartupTransferFixture::new(ConstructionFault::None);
        let mut incoming = StartupTransferFixture::new(ConstructionFault::None);
        let (io, journal) = original.startup.take().unwrap().cold();
        original.io = Some(io);
        original.journal = Some(journal);
        let mut absent_io = None;
        let mut absent_journal = None;
        assert!(transfer_startup_retained_into(
            &mut incoming.startup,
            if occupied != 1 {
                &mut original.io
            } else {
                &mut absent_io
            },
            if occupied != 0 {
                &mut original.journal
            } else {
                &mut absent_journal
            },
            &mut original.pair,
            |_| panic!("occupied IO/J must not inspect new identity"),
            |_| panic!("occupied IO/J must not convert new Startup"),
        )
        .is_err());
        original.assert_converted_rooted();
        incoming.assert_untouched();
        assert!(absent_io.is_none() && absent_journal.is_none());
    }
}

#[test]
fn retained_startup_transfer_converted_slots_survive_pair_pure_validation_error() {
    let mut fixture = StartupTransferFixture::new(ConstructionFault::None);
    let owner = fixture.startup.take().unwrap();
    let (mut scope, provenance) = owner.identity();
    let (io, journal) = owner.cold();
    fixture.io = Some(io);
    fixture.journal = Some(journal);
    scope.connection_generation = 0;
    assert!(
        crate::member_carrier_pair::CarrierNativePair::new_retained_into(
            &mut fixture.pair,
            scope,
            provenance,
            &mut fixture.io,
            &mut fixture.journal,
        )
        .is_err()
    );
    fixture.assert_converted_rooted();
}

#[test]
fn retained_startup_transfer_foreign_or_equal_nonempty_journal_never_adopts_or_retries() {
    for foreign in [false, true] {
        let mut fixture = StartupTransferFixture::new(ConstructionFault::None);
        fixture.seed_initial_fresh(foreign);
        assert!(transfer_fixture(&mut fixture).is_err());
        fixture.assert_rooted();
        fixture.assert_denied();
        assert!(fixture.close().is_err());
        // Even replacement input with matching DATA cannot recover this slot.
        let mut incoming = StartupTransferFixture::new(ConstructionFault::None);
        assert!(transfer_startup_retained_into(
            &mut incoming.startup,
            &mut incoming.io,
            &mut incoming.journal,
            &mut fixture.pair,
            StartupTransferOwner::identity,
            StartupTransferOwner::cold,
        )
        .is_err());
        incoming.assert_untouched();
        fixture.assert_rooted();
        fixture.assert_denied();
        assert!(fixture.pair.as_ref().unwrap().cleanup_pending());
    }
}

#[test]
fn retained_startup_transfer_readback_failure_cleanup_still_needs_actual_journal_and_native_gates()
{
    for lost in [false, true] {
        let mut fixture = StartupTransferFixture::new(ConstructionFault::LoadError(2));
        assert!(transfer_fixture(&mut fixture).is_err());
        fixture.fail_cleanup_entry(lost);
        assert!(fixture.close().is_err());
        fixture.assert_rooted();
        assert!(fixture.pair.as_ref().unwrap().cleanup_pending());
        fixture.make_native_foreign(true);
        assert!(fixture.close().is_err());
        assert!(fixture.pair.as_ref().unwrap().cleanup_pending());
        fixture.make_native_foreign(false);
        fixture.close().unwrap();
        assert!(!fixture.pair.as_ref().unwrap().cleanup_pending());
        fixture.assert_rooted();
        fixture.assert_denied();
    }
}

// Break: losing the completed original when binding/postflight fails, replacing
// it with an equal foreign outcome, or publishing readiness after reentry.
#[test]
fn initial_data_outcome_binding_retains_before_postflight_and_denies_replacement() {
    use std::{
        cell::RefCell,
        panic::{catch_unwind, AssertUnwindSafe},
        rc::Rc,
    };
    for fault in 0..4 {
        let original = Rc::new(17);
        let foreign = Rc::new(17);
        let slot = RefCell::new(None);
        let binding = TerminalCallState::new();
        let result = catch_unwind(AssertUnwindSafe(|| {
            bind_initial_data_outcome(&slot, &binding, original.clone(), |value| {
                assert!(Rc::ptr_eq(slot.borrow().as_ref().unwrap(), &original));
                assert_eq!(*value, 17);
                match fault {
                    0 => Err(Error::Conflict),
                    1 => panic!("NoC outcome binding postflight"),
                    2 => {
                        assert!(bind_initial_data_outcome(
                            &slot,
                            &binding,
                            foreign.clone(),
                            |_| Ok(())
                        )
                        .is_err());
                        Ok(())
                    }
                    _ => Ok(()),
                }
            })
        }));
        assert!(Rc::ptr_eq(slot.borrow().as_ref().unwrap(), &original));
        if fault < 3 {
            assert!(result.is_err() || result.unwrap().is_err());
            assert!(binding.verify().is_err());
        } else {
            result.unwrap().unwrap();
            binding.verify().unwrap();
        }
        assert!(
            bind_initial_data_outcome(&slot, &binding, foreign, |_| panic!("replace original"))
                .is_err()
        );
        assert!(Rc::ptr_eq(slot.borrow().as_ref().unwrap(), &original));
    }
}

// Bookkeeping comparison ONLY. Neither a state latch nor a foreign equal
// supervisor can replace this original's acknowledged whole read AND disposal.
#[test]
fn zero_effect_drop_requires_same_original_and_both_completed_calls() {
    use std::{
        panic::{catch_unwind, AssertUnwindSafe},
        rc::Rc,
    };
    let original = Rc::new(());
    let foreign = Rc::new(());
    for fault in 0..5 {
        let whole = TerminalCallState::new();
        let disposal = TerminalCallState::new();
        assert!(
            verify_zero_effect_rundown(&original, original.as_ref(), &whole, &disposal).is_err()
        );
        whole.run(|| Ok(())).unwrap();
        assert!(
            verify_zero_effect_rundown(&original, original.as_ref(), &whole, &disposal).is_err()
        );
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            disposal.run(|| match fault {
                0 => Err(std::io::Error::other("disposal error")),
                1 => panic!("disposal unwind"),
                2 => {
                    assert!(disposal.run(|| Ok(())).is_err());
                    Ok(())
                }
                _ => Ok(()),
            })
        }));
        if fault < 3 {
            assert!(outcome.is_err() || outcome.unwrap().is_err());
            assert!(
                verify_zero_effect_rundown(&original, original.as_ref(), &whole, &disposal)
                    .is_err()
            );
        } else {
            outcome.unwrap().unwrap();
            verify_zero_effect_rundown(&original, original.as_ref(), &whole, &disposal).unwrap();
            assert!(
                verify_zero_effect_rundown(&original, foreign.as_ref(), &whole, &disposal).is_err()
            );
            if fault == 4 {
                assert!(whole.run(|| Ok(())).is_err());
                assert!(verify_zero_effect_rundown(
                    &original,
                    original.as_ref(),
                    &whole,
                    &disposal
                )
                .is_err());
            }
        }
    }
}

// Break: initial storage publication happens while Startup is only a local
// owning Result value. No kernel or success grant is involved in this test.
#[test]
fn claim_startup_is_caller_retained_before_publication_error_or_unwind() {
    use std::{
        cell::Cell,
        panic::{catch_unwind, AssertUnwindSafe},
        rc::Rc,
    };
    struct Original(Rc<Cell<usize>>);
    impl Drop for Original {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    for unwind in [false, true] {
        let drops = Rc::new(Cell::new(0));
        let mut destination = None;
        let result = catch_unwind(AssertUnwindSafe(|| {
            retain_claim_startup(&mut destination, Original(drops.clone()), |root| {
                assert!(Rc::ptr_eq(&root.0, &drops));
                if unwind {
                    panic!("initial publication postflight");
                }
                Err(Error::Journal)
            })
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert!(
            destination.is_some(),
            "caller keeps original after publication failure"
        );
        assert_eq!(drops.get(), 0);
        let foreign_drops = Rc::new(Cell::new(0));
        assert!(retain_claim_startup(
            &mut destination,
            Original(foreign_drops.clone()),
            |_| panic!("occupied destination must not publish")
        )
        .is_err());
        assert_eq!(foreign_drops.get(), 1);
        assert_eq!(drops.get(), 0);
        drop(destination);
        assert_eq!(
            drops.get(),
            1,
            "helper retains, never grants disposal or forgets success"
        );
    }
}

// Break: selecting full graph from a successful original C before attach, or
// using unreadable/missing C evidence as Never/resource absence.
#[test]
fn attempted_layout_separates_published_pregraph_from_unknown_and_graph_entry() {
    let ledger = StartupInvocationLedger::new();
    assert!(classify_attempted_layout(&ledger, false, false, false, true).is_err());
    ledger.begin(false).unwrap();
    assert_eq!(
        classify_attempted_layout(&ledger, true, false, false, true).unwrap(),
        NativeAttemptedTerminalLayout::PublishedCarrierPregraph
    );
    assert_eq!(
        classify_attempted_layout(&ledger, true, false, false, false).unwrap(),
        NativeAttemptedTerminalLayout::OtherAttempted
    );
    assert_eq!(
        classify_attempted_layout(&ledger, true, false, true, true).unwrap(),
        NativeAttemptedTerminalLayout::GraphAttempted
    );
    assert!(classify_attempted_layout(&ledger, true, true, false, true).is_err());
    ledger.begin(true).unwrap();
    assert!(classify_attempted_layout(&ledger, true, true, false, true).is_err());
    assert_eq!(
        classify_attempted_layout(&ledger, true, true, true, true).unwrap(),
        NativeAttemptedTerminalLayout::GraphAttempted
    );
}

// Break: an invocation error/unwind or attach-only attempt is mistaken for
// untouched Startup; equal foreign invocation roots are also not this original.
#[test]
fn startup_invocation_ledger_retains_failed_attempt_and_denies_foreign_origin() {
    use std::rc::Rc;
    for attach in [false, true] {
        for unwind in [false, true] {
            let original = Rc::new(StartupInvocationLedger::new());
            let weak = Rc::downgrade(&original);
            assert!(!original.attempted(false, false).unwrap());
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                original.begin(attach)?;
                if unwind {
                    panic!("native invocation postflight");
                }
                Err::<(), _>(Error::Native)
            }));
            if unwind {
                assert!(outcome.is_err());
            } else {
                assert_eq!(outcome.unwrap(), Err(Error::Native));
            }
            assert!(original.attempted(!attach, attach).unwrap());
            assert!(original.attempted(false, false).is_err());
            let foreign = Rc::new(StartupInvocationLedger::new());
            foreign.begin(attach).unwrap();
            assert!(!Rc::ptr_eq(&weak.upgrade().unwrap(), &foreign));
            assert_eq!(original.begin(attach), Err(Error::Retired));
            drop(original);
            assert!(weak.upgrade().is_none());
        }
    }
}

// Break: a failed/reentered constructor returns an empty-looking graph and
// is accepted by the no-resource bootstrap lane. This is a denial fence,
// not a Never/native ownership proof.
#[test]
fn graph_construction_attempt_permanently_excludes_cold_bootstrap() {
    for unwind in [false, true] {
        let attempted = std::cell::Cell::new(false);
        require_uncaptured_graph(&attempted).unwrap();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            begin_graph_construction(&attempted)?;
            assert_eq!(require_uncaptured_graph(&attempted), Err(Error::Retired));
            if unwind {
                panic!("graph constructor postflight");
            }
            Err::<(), _>(Error::Native)
        }));
        if unwind {
            assert!(outcome.is_err());
        } else {
            assert_eq!(outcome.unwrap(), Err(Error::Native));
        }
        assert_eq!(require_uncaptured_graph(&attempted), Err(Error::Retired));
        assert_eq!(begin_graph_construction(&attempted), Err(Error::Retired));
        assert!(attempted.get());
    }
}

// Break: preparing a replacement before the caller's actual generation
// projection succeeds, or moving old originals before that callback returns.
#[test]
fn live_generation_projection_precedes_retention_and_new_preparation() {
    #[derive(Default)]
    struct OriginalSlots {
        events: Vec<&'static str>,
        old: Option<std::rc::Rc<u32>>,
        retained: Vec<std::rc::Rc<u32>>,
    }
    let original = std::rc::Rc::new(7);
    for fail in [false, true] {
        let mut slots = OriginalSlots {
            old: Some(original.clone()),
            ..Default::default()
        };
        let result = prepare_live_generation(
            &mut slots,
            true,
            |s| {
                s.events.push("ticket");
                Ok(original.clone())
            },
            |s, ticket| {
                assert!(std::rc::Rc::ptr_eq(s.old.as_ref().unwrap(), ticket));
                s.events.push("project");
                if fail {
                    Err(Error::Conflict)
                } else {
                    Ok(())
                }
            },
            |s, ticket| {
                assert!(std::rc::Rc::ptr_eq(s.old.as_ref().unwrap(), ticket));
                s.events.push("retain");
                s.retained.push(s.old.take().unwrap());
                Ok(())
            },
            |s| {
                assert!(s.old.is_none());
                assert!(std::rc::Rc::ptr_eq(&s.retained[0], &original));
                s.events.push("prepare");
                Err::<(), _>(Error::Pending)
            },
        );
        assert!(result.is_err());
        if fail {
            assert_eq!(slots.events, ["ticket", "project"]);
            assert!(slots.old.is_some());
            assert!(slots.retained.is_empty());
        } else {
            assert_eq!(slots.events, ["ticket", "project", "retain", "prepare"]);
            assert!(slots.old.is_none());
            assert!(std::rc::Rc::ptr_eq(&slots.retained[0], &original));
        }
    }
    let mut first = OriginalSlots::default();
    prepare_live_generation(
        &mut first,
        false,
        |_| Err::<std::rc::Rc<u32>, _>(Error::Conflict),
        |_, _| Err(Error::Conflict),
        |_, _| Err(Error::Conflict),
        |s| {
            s.events.push("prepare");
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        first.events,
        ["prepare"],
        "first Attach has no retirement callback"
    );
}

// Break: allowing another preparation after outer postflight error/unwind,
// or clearing a caught reentry failure merely because the outer call returns Ok.
#[test]
fn live_preparation_whole_call_failure_or_caught_reentry_is_permanent() {
    use std::{
        cell::Cell,
        panic::{catch_unwind, AssertUnwindSafe},
    };
    for unwind in [false, true] {
        let state = Cell::new(LivePreparationState::Idle);
        let original = std::rc::Rc::new(7);
        let retained = std::cell::RefCell::new(None);
        let result = catch_unwind(AssertUnwindSafe(|| {
            run_live_preparation(&state, || {
                *retained.borrow_mut() = Some(original.clone());
                if unwind {
                    panic!("actual outer postflight");
                }
                Err::<(), _>(Error::Pending)
            })
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert!(std::rc::Rc::ptr_eq(
            retained.borrow().as_ref().unwrap(),
            &original
        ));
        assert!(run_live_preparation(&state, || Ok(())).is_err());
    }
    let state = Cell::new(LivePreparationState::Idle);
    assert!(run_live_preparation(&state, || {
        assert!(run_live_preparation(&state, || Ok(())).is_err());
        Ok(())
    })
    .is_err());
    assert!(run_live_preparation(&state, || Ok(())).is_err());
    let fresh = Cell::new(LivePreparationState::Idle);
    run_live_preparation(&fresh, || Ok(())).unwrap();
    run_live_preparation(&fresh, || Ok(())).unwrap();
}

#[test]
fn cancelled_terminal_read_is_distinct_from_live_and_incomplete_closing() {
    use crate::member_carrier_pair::Phase;
    for cancelled in [false, true] {
        startup_read_allowed(cancelled, Phase::Stopped, StartupRead::Terminal).unwrap();
        for phase in [
            Phase::Fresh,
            Phase::Starting,
            Phase::Running,
            Phase::Closing,
        ] {
            assert!(startup_read_allowed(cancelled, phase, StartupRead::Terminal).is_err());
        }
    }
    assert!(startup_read_allowed(true, Phase::Stopped, StartupRead::Forward).is_err());
    assert!(startup_read_allowed(true, Phase::Stopped, StartupRead::Cleanup).is_err());
}
use nelomai_contracts::{dispatcher::EngineIdentity, RuntimeSlot};
use std::path::PathBuf;

// Break: binding before Starting, rebinding after an unknown first attempt, or
// using a carrier-present phase as a new native execution birth.
#[test]
fn native_birth_entry_is_one_shot_starting_only_before_carrier_construction() {
    use crate::member_carrier_pair::Phase;
    let mut attempted = false;
    begin_native_birth(&mut attempted, Phase::Starting, false, false).unwrap();
    assert!(begin_native_birth(&mut attempted, Phase::Starting, false, false).is_err());
    for phase in [Phase::Fresh, Phase::Running, Phase::Closing, Phase::Stopped] {
        let mut attempted = false;
        assert!(begin_native_birth(&mut attempted, phase, false, false).is_err());
        assert!(attempted, "even a failed first entry cannot rebind");
    }
    for (carrier, create) in [(true, false), (false, true), (true, true)] {
        let mut attempted = false;
        assert!(begin_native_birth(&mut attempted, Phase::Starting, carrier, create).is_err());
        assert!(attempted);
    }
}

// Break: accepting an absent lookup, foreign scope or any retained WFP base
// after the actual no-effect terminal reader returned its full SDK snapshot.
#[test]
fn uncaptured_terminal_snapshot_requires_exact_full_empty_not_foreign_or_partial() {
    let expected = scope();
    let actual = crate::member_carrier_guard::Snapshot {
        version: 2,
        scope: expected.clone(),
        carrier: None,
        egress: [None, None],
        sublayer: None,
        filters: vec![],
    };
    compare_uncaptured_terminal_snapshot(&expected, &actual).unwrap();
    for fault in 0..3 {
        let mut bad = actual.clone();
        match fault {
            0 => bad.version = 1,
            1 => bad.scope.connection_generation += 1,
            _ => {
                bad.egress[0] = Some(crate::member_carrier_guard::Identity {
                    scope: expected.clone(),
                    proof: crate::member_owner::InterfaceProof {
                        index: 7,
                        luid: 90,
                        guid: [1; 16],
                    },
                })
            }
        }
        assert!(compare_uncaptured_terminal_snapshot(&expected, &bad).is_err());
    }
}

// Shape comparison only: this does NOT construct the private Startup proof.
// Break: configured/attempted-C metadata can enter the Fresh OriginalNever
// owning disposal lane merely because its final SDK snapshot looks empty.
#[test]
fn zero_effect_terminal_record_requires_exact_unconfigured_stopped_frame() {
    let (context, mut stopped) = bootstrap_fixture();
    stopped.phase = crate::member_carrier_pair::Phase::Stopped;
    stopped.stop_stage = 12;
    stopped.pending = None;
    stopped.addresses.clear();
    stopped.dns.clear();
    stopped.options = None;
    stopped.validate().unwrap();
    compare_zero_effect_terminal_record(&context, &stopped).unwrap();
    for fault in 0..6 {
        let mut wrong = stopped.clone();
        match fault {
            0 => wrong.options = Some(nelomai_client_tunnel::DesktopTunnelOptions::default()),
            1 => wrong.addresses = context.intent.addresses.clone(),
            2 => wrong.scope.connection_generation += 1,
            3 => wrong.provenance.network_epoch += 1,
            4 => wrong.phase = crate::member_carrier_pair::Phase::Closing,
            _ => wrong.pending = Some(crate::member_carrier_pair::Effect::FullEmpty),
        }
        assert!(compare_zero_effect_terminal_record(&context, &wrong).is_err());
    }
}

// Break: genuine configured pre-C preflight failure is confused with an
// attempted C or refused solely for logical configuration. Facts never issue
// a proof: native issuance additionally checks real cold prepared originals.
#[test]
fn configured_never_terminal_frame_is_distinct_and_keeps_original_intent() {
    let (context, mut stopped) = bootstrap_fixture();
    stopped.phase = crate::member_carrier_pair::Phase::Stopped;
    stopped.stop_stage = 12;
    stopped.pending = None;
    assert_eq!(
        compare_zero_effect_terminal_record(&context, &stopped).unwrap(),
        NoCarrierConfiguration::Configured
    );
    for fault in 0..6 {
        let mut wrong = stopped.clone();
        match fault {
            0 => wrong.addresses.clear(),
            1 => wrong.options = None,
            2 => wrong.addresses = vec!["10.7.0.3/32".parse().unwrap()],
            3 => wrong.provenance.network_epoch += 1,
            4 => wrong.phase = crate::member_carrier_pair::Phase::Closing,
            _ => wrong.pending = Some(crate::member_carrier_pair::Effect::FullEmpty),
        }
        assert!(
            compare_zero_effect_terminal_record(&context, &wrong).is_err(),
            "fault {fault}"
        );
    }
    stopped.addresses.clear();
    stopped.dns.clear();
    stopped.options = None;
    assert_eq!(
        compare_zero_effect_terminal_record(&context, &stopped).unwrap(),
        NoCarrierConfiguration::Unconfigured
    );
}

// Break: selecting module-only from an unattempted/foreign invocation, created
// C metadata or graph entry. The separate typed loader/Assembly candidates,
// NOT this comparison or EMPTY JSON, remain mandatory in native production.
#[test]
fn module_only_candidate_frame_requires_original_attempt_and_no_c_or_graph() {
    let (context, mut stopped) = bootstrap_fixture();
    stopped.phase = crate::member_carrier_pair::Phase::Stopped;
    stopped.stop_stage = 12;
    stopped.pending = None;
    let invocation = StartupInvocationLedger::new();
    invocation.begin(false).unwrap();
    compare_module_only_candidate_frame(&invocation, true, false, false, &context, &stopped)
        .unwrap();
    for fault in 0..6 {
        let mut wrong = stopped.clone();
        match fault {
            0 => {
                wrong.carrier = Some(crate::member_owner::InterfaceProof {
                    index: 7,
                    luid: 90,
                    guid: [1; 16],
                })
            }
            1 => wrong.phase = crate::member_carrier_pair::Phase::Closing,
            2 => wrong.pending = Some(crate::member_carrier_pair::Effect::FullEmpty),
            3 => wrong.provenance.network_epoch += 1,
            4 => wrong.addresses.clear(),
            _ => wrong.scope.connection_generation += 1,
        }
        assert!(compare_module_only_candidate_frame(
            &invocation,
            true,
            false,
            false,
            &context,
            &wrong
        )
        .is_err());
    }
    assert!(compare_module_only_candidate_frame(
        &invocation,
        false,
        false,
        false,
        &context,
        &stopped
    )
    .is_err());
    assert!(compare_module_only_candidate_frame(
        &invocation,
        true,
        false,
        true,
        &context,
        &stopped
    )
    .is_err());
    let attached = StartupInvocationLedger::new();
    attached.begin(false).unwrap();
    attached.begin(true).unwrap();
    assert!(
        compare_module_only_candidate_frame(&attached, true, true, true, &context, &stopped)
            .is_err()
    );
}

fn bootstrap_fixture() -> (Context, crate::member_carrier_pair::Record) {
    let paths = paths();
    let context = requested_context(
        &scope(),
        &provenance(),
        &configuration(false),
        [&paths[0], &paths[1]],
    )
    .unwrap();
    let record = crate::member_carrier_pair::Record {
        version: 2,
        scope: scope(),
        provenance: provenance(),
        revision: 3,
        phase: crate::member_carrier_pair::Phase::Closing,
        addresses: vec!["10.7.0.2/32".parse().unwrap()],
        dns: vec!["1.1.1.1".parse().unwrap()],
        carrier: None,
        members: [None, None],
        active: None,
        options: Some(nelomai_client_tunnel::DesktopTunnelOptions::default()),
        guard: crate::member_carrier_guard::Model::empty(scope()).unwrap(),
        pending_guard: None,
        pending: Some(crate::member_carrier_pair::Effect::NativeEmpty),
        network: None,
        stop_stage: 9,
        operation: None,
    };
    record.validate().unwrap();
    (context, record)
}

#[test]
fn module_only_cleanup_reads_are_possible_before_stopped_without_disposal_grant() {
    use crate::member_carrier_pair::{Effect, Phase};
    let (context, mut record) = bootstrap_fixture();
    for (stage, effect) in [
        (0, Effect::Guard),
        (1, Effect::ReleaseProbes),
        (2, Effect::RestoreNetwork),
        (3, Effect::RestoreWeak),
        (
            4,
            Effect::MemberStop(nelomai_client_tunnel::redundancy::Slot::A),
        ),
        (
            5,
            Effect::MemberStop(nelomai_client_tunnel::redundancy::Slot::B),
        ),
        (6, Effect::CarrierAddressDelete),
        (7, Effect::CarrierSessionEnd),
        (8, Effect::CarrierClose),
        (9, Effect::NativeEmpty),
        (10, Effect::Guard),
        (11, Effect::RestoreKeys),
        (12, Effect::FullEmpty),
    ] {
        record.stop_stage = stage;
        record.pending = Some(effect);
        compare_module_only_read_record(&context, &record).unwrap();
        assert!(compare_zero_effect_terminal_record(&context, &record).is_err());
        for fault in 0..6 {
            let mut bad = record.clone();
            match fault {
                0 => bad.phase = Phase::Starting,
                1 => bad.pending = None,
                2 => {
                    bad.carrier = Some(crate::member_owner::InterfaceProof {
                        index: 1,
                        luid: 1,
                        guid: context.bindings[0].guid,
                    })
                }
                3 => bad.addresses.clear(),
                4 => bad.provenance.network_epoch += 1,
                _ => bad.guard.permits = true,
            }
            assert!(compare_module_only_read_record(&context, &bad).is_err());
        }
    }
    record.phase = Phase::Stopped;
    record.pending = None;
    compare_module_only_read_record(&context, &record).unwrap();
    compare_zero_effect_terminal_record(&context, &record).unwrap();
}

#[test]
fn module_only_cleanup_keeps_actual_prepared_member_until_stopped() {
    use crate::{member_carrier_pair as pair, member_owner as owner};
    let (context, mut original) = bootstrap_fixture();
    original.members[0] = Some(pair::MemberState {
        owner: owner::Record {
            intent: owner::Intent {
                scope: original.scope.clone(),
                slot: TunnelSlot::A,
                transport: TunnelTransport::WireGuard,
                engine: crate::test_engine_path("engine.exe"),
                config_sha256: [3; 32],
            },
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
    });
    original.validate().unwrap();
    compare_module_only_read_record(&context, &original).unwrap();
    let mut next = original.clone();
    next.stop_stage = 10;
    next.pending = Some(pair::Effect::Guard);
    next.revision += 1;
    compare_module_only_read_progress(&context, &original, &next).unwrap();
    let mut replaced = next.clone();
    replaced.members[0].as_mut().unwrap().lease_id = "33333333-3333-4333-8333-333333333333".into();
    assert!(compare_module_only_read_progress(&context, &original, &replaced).is_err());
    replaced = next.clone();
    replaced.members = [None, None];
    assert!(compare_module_only_read_progress(&context, &original, &replaced).is_err());
    for fault in 0..3 {
        let mut wrong = original.clone();
        let owner = &mut wrong.members[0].as_mut().unwrap().owner;
        match fault {
            0 => owner.phase = owner::Phase::Stopped,
            1 => owner.previous_config_sha256 = Some([4; 32]),
            _ => owner.intent.scope.connection_generation += 1,
        }
        assert!(compare_module_only_read_record(&context, &wrong).is_err());
    }
    next.phase = pair::Phase::Stopped;
    next.stop_stage = 12;
    next.pending = None;
    next.members = [None, None];
    compare_module_only_read_progress(&context, &original, &next).unwrap();
}

#[test]
fn module_only_read_views_keep_birth_identity_and_never_rewind_cleanup() {
    use crate::member_carrier_pair::{Effect, Phase};
    let (context, original) = bootstrap_fixture();
    for (phase, stage, effect) in [
        (Phase::Closing, 10, Some(Effect::Guard)),
        (Phase::Closing, 12, Some(Effect::FullEmpty)),
        (Phase::Stopped, 12, None),
    ] {
        let mut current = original.clone();
        current.phase = phase;
        current.stop_stage = stage;
        current.pending = effect;
        current.revision += 1;
        compare_module_only_read_progress(&context, &original, &current).unwrap();
        assert!(compare_module_only_read_progress(&context, &current, &original).is_err());
        for fault in 0..4 {
            let mut wrong = current.clone();
            match fault {
                0 => wrong.scope.connection_generation += 1,
                1 => wrong.provenance.network_epoch += 1,
                2 => wrong.dns = vec!["8.8.8.8".parse().unwrap()],
                _ => wrong.revision = original.revision - 1,
            }
            assert!(compare_module_only_read_progress(&context, &original, &wrong).is_err());
        }
    }
}

#[test]
fn pregraph_native_empty_join_brackets_both_reads_without_terminal_projection() {
    use crate::member_carrier_pair::Effect;
    use std::cell::Cell;
    let (context, mut record) = bootstrap_fixture();
    let empty = record.guard.expected.clone();
    for (stage, effect) in [(9, Effect::NativeEmpty), (10, Effect::Guard)] {
        record.stop_stage = stage;
        record.pending = Some(effect);
        let checks = Cell::new(0);
        let reads = Cell::new(0);
        let actual = inspect_prepublication_native_empty(
            &context,
            &record,
            || {
                checks.set(checks.get() + 1);
                Ok(())
            },
            || {
                reads.set(reads.get() + 1);
                Ok(empty.clone())
            },
        )
        .unwrap();
        assert_eq!(actual, empty);
        assert_eq!(reads.get(), 2);
        assert_eq!(checks.get(), 6);
        let valid = Cell::new(true);
        reads.set(0);
        assert_eq!(
            inspect_prepublication_native_empty(
                &context,
                &record,
                || {
                    if valid.get() {
                        Ok(())
                    } else {
                        Err(Error::Retired)
                    }
                },
                || {
                    reads.set(reads.get() + 1);
                    valid.set(false);
                    Ok(empty.clone())
                }
            ),
            Err(Error::Retired)
        );
        assert_eq!(reads.get(), 1);
        assert_eq!(
            inspect_prepublication_native_empty(
                &context,
                &record,
                || Ok(()),
                || Err(Error::Pending)
            ),
            Err(Error::Pending)
        );
        assert!(inspect_prepublication_full_empty(
            &context,
            &record,
            || Ok(()),
            || Ok(empty.clone())
        )
        .is_err());
    }
    record.stop_stage = 12;
    record.pending = Some(Effect::FullEmpty);
    assert!(inspect_prepublication_native_empty(
        &context,
        &record,
        || Ok(()),
        || Ok(empty.clone())
    )
    .is_err());
}

// Break: a full/interrupted graph or a wrong Closing effect is routed through
// bootstrap C-only cleanup. This is a factual dispatcher, NOT effect permission.
#[test]
fn pregraph_cleanup_routes_only_current_original_c_stages() {
    use crate::member_carrier_pair::Effect;
    let (context, mut record) = bootstrap_fixture();
    let ledger = StartupInvocationLedger::new();
    ledger.begin(false).unwrap();
    for (stage, effect) in [
        (3, Effect::RestoreWeak),
        (6, Effect::CarrierAddressDelete),
        (7, Effect::CarrierSessionEnd),
        (8, Effect::CarrierClose),
    ] {
        record.stop_stage = stage;
        record.pending = Some(effect);
        compare_pregraph_cleanup(&ledger, true, false, &context, &record).unwrap();
        let mut wrong = record.clone();
        wrong.pending = None;
        assert!(compare_pregraph_cleanup(&ledger, true, false, &context, &wrong).is_err());
        wrong = record.clone();
        wrong.pending = Some(Effect::FullEmpty);
        assert!(compare_pregraph_cleanup(&ledger, true, false, &context, &wrong).is_err());
        wrong = record.clone();
        wrong.scope.connection_generation += 1;
        assert!(compare_pregraph_cleanup(&ledger, true, false, &context, &wrong).is_err());
        assert!(compare_pregraph_cleanup(&ledger, false, false, &context, &record).is_err());
    }
    record.stop_stage = 12;
    record.pending = Some(Effect::FullEmpty);
    assert!(compare_pregraph_cleanup(&ledger, true, false, &context, &record).is_err());
    ledger.begin(true).unwrap();
    record.stop_stage = 8;
    record.pending = Some(Effect::CarrierClose);
    assert!(compare_pregraph_cleanup(&ledger, true, true, &context, &record).is_err());
    assert!(compare_pregraph_cleanup(&ledger, true, false, &context, &record).is_err());
}

// Break: the SAME retained prepared-origin check is performed only before
// reading, so an invalidated original or caught read failure is accepted.
// This tests production join ordering; it does not mint a member/native ACK.
#[test]
fn prepublication_full_empty_rechecks_original_preparation_around_both_reads() {
    use std::cell::Cell;
    let (context, mut current) = bootstrap_fixture();
    current.stop_stage = 12;
    current.pending = Some(crate::member_carrier_pair::Effect::FullEmpty);
    let empty = crate::member_carrier_guard::Snapshot {
        version: 2,
        scope: scope(),
        carrier: None,
        egress: [None, None],
        sublayer: None,
        filters: vec![],
    };
    let origin_current = Cell::new(true);
    let reads = Cell::new(0);
    let result = inspect_prepublication_full_empty(
        &context,
        &current,
        || {
            if origin_current.get() {
                Ok(())
            } else {
                Err(Error::Conflict)
            }
        },
        || {
            reads.set(reads.get() + 1);
            origin_current.set(false);
            Ok(empty.clone())
        },
    );
    assert_eq!(result, Err(Error::Conflict));
    assert_eq!(reads.get(), 1);
    reads.set(0);
    assert_eq!(
        inspect_prepublication_full_empty(
            &context,
            &current,
            || Err(Error::Retired),
            || {
                reads.set(reads.get() + 1);
                Ok(empty.clone())
            }
        ),
        Err(Error::Retired)
    );
    assert_eq!(reads.get(), 0);
    inspect_prepublication_full_empty(&context, &current, || Ok(()), || Ok(empty.clone())).unwrap();
}

// Break: Closing12 final-empty is projected through Closing9/10 or the
// Stopped channel; a single/foreign SDK snapshot becomes an absence grant.
#[test]
fn bootstrap_full_empty_uses_closing_twelve_and_two_actual_reads() {
    use crate::member_carrier_pair::{Effect, Phase};
    let (context, mut record) = bootstrap_fixture();
    record.stop_stage = 12;
    record.pending = Some(Effect::FullEmpty);
    let empty = crate::member_carrier_guard::Snapshot {
        version: 2,
        scope: scope(),
        carrier: None,
        egress: [None, None],
        sublayer: None,
        filters: vec![],
    };
    let mut calls = 0;
    let actual =
        inspect_bootstrap_full_empty(&context, &record, BootstrapOrigin::OriginalNever, || {
            calls += 1;
            Ok(empty.clone())
        })
        .unwrap();
    assert_eq!(calls, 2);
    assert_eq!(actual, empty);
    // Actual Fresh abort retains addresses[]; ONLY the real Never caller may
    // select this comparison channel. Created/retired C keeps original VIP.
    let mut fresh_abort = record.clone();
    fresh_abort.addresses.clear();
    fresh_abort.dns.clear();
    fresh_abort.options = None;
    fresh_abort.validate().unwrap();
    inspect_bootstrap_full_empty(
        &context,
        &fresh_abort,
        BootstrapOrigin::OriginalNever,
        || Ok(empty.clone()),
    )
    .unwrap();
    assert!(inspect_bootstrap_full_empty(
        &context,
        &fresh_abort,
        BootstrapOrigin::CreatedRetired,
        || panic!("absent VIP cannot turn created C into Never"),
    )
    .is_err());
    for fault in 0..5 {
        let mut wrong = record.clone();
        match fault {
            0 => wrong.phase = Phase::Stopped,
            1 => {
                wrong.stop_stage = 9;
                wrong.pending = Some(Effect::NativeEmpty);
            }
            2 => wrong.pending = Some(Effect::RestoreKeys),
            3 => wrong.provenance.network_epoch += 1,
            _ => wrong.scope.connection_generation += 1,
        }
        assert!(inspect_bootstrap_full_empty(
            &context,
            &wrong,
            BootstrapOrigin::OriginalNever,
            || panic!("foreign full-empty frame sampled")
        )
        .is_err());
    }
    calls = 0;
    assert!(inspect_bootstrap_full_empty(
        &context,
        &record,
        BootstrapOrigin::OriginalNever,
        || {
            calls += 1;
            let mut sampled = empty.clone();
            if calls == 2 {
                sampled.version = 1;
            }
            Ok(sampled)
        }
    )
    .is_err());
}

// Break: one read, wrong Closing effect/stage, foreign scope or changed second
// whole snapshot is accepted. These are facts only, NOT a Never/Retired ACK.
#[test]
fn bootstrap_empty_join_requires_exact_frame_and_two_full_matching_reads() {
    let (context, record) = bootstrap_fixture();
    let empty = crate::member_carrier_guard::Snapshot {
        version: 2,
        scope: scope(),
        carrier: None,
        egress: [None, None],
        sublayer: None,
        filters: vec![],
    };
    let mut reads = 0;
    inspect_bootstrap_empty(&context, &record, BootstrapOrigin::CreatedRetired, || {
        reads += 1;
        Ok(empty.clone())
    })
    .unwrap();
    assert_eq!(reads, 2);
    reads = 0;
    assert!(
        inspect_bootstrap_empty(&context, &record, BootstrapOrigin::CreatedRetired, || {
            reads += 1;
            let mut actual = empty.clone();
            if reads == 2 {
                actual.scope.connection_generation += 1;
            }
            Ok(actual)
        })
        .is_err()
    );
    for change in 0..4 {
        let mut wrong = record.clone();
        match change {
            0 => wrong.stop_stage = 8,
            1 => wrong.pending = Some(crate::member_carrier_pair::Effect::Guard),
            2 => wrong.phase = crate::member_carrier_pair::Phase::Stopped,
            _ => wrong.provenance.network_epoch += 1,
        }
        assert!(inspect_bootstrap_empty(
            &context,
            &wrong,
            BootstrapOrigin::CreatedRetired,
            || panic!("wrong frame sampled")
        )
        .is_err());
    }
    let mut removal = record.clone();
    removal.stop_stage = 10;
    removal.pending = Some(crate::member_carrier_pair::Effect::Guard);
    inspect_bootstrap_empty(&context, &removal, BootstrapOrigin::CreatedRetired, || {
        Ok(empty.clone())
    })
    .unwrap();
    assert!(
        inspect_bootstrap_empty(&context, &record, BootstrapOrigin::CreatedRetired, || Err(
            Error::Pending
        ))
        .is_err()
    );
}

// Break: genuine Fresh abort is denied for its empty addresses, or the same
// relaxation is incorrectly applied to a created/retired C original.
#[test]
fn fresh_abort_bootstrap_accepts_absent_vip_only_with_original_never_channel() {
    let (context, _) = bootstrap_fixture();
    let closing = fresh_coordinator_abort(&context, 9);
    let observed = crate::member_carrier_guard::Snapshot {
        version: 2,
        scope: scope(),
        carrier: None,
        egress: [None, None],
        sublayer: None,
        filters: vec![],
    };
    for stage in [9, 10] {
        let closing = if stage == 9 {
            closing.clone()
        } else {
            fresh_coordinator_abort(&context, stage)
        };
        assert!(closing.addresses.is_empty());
        let mut reads = 0;
        inspect_bootstrap_empty(&context, &closing, BootstrapOrigin::OriginalNever, || {
            reads += 1;
            Ok(observed.clone())
        })
        .unwrap();
        assert_eq!(reads, 2);
        assert!(inspect_bootstrap_empty(
            &context,
            &closing,
            BootstrapOrigin::CreatedRetired,
            || panic!("created-C exception queried native data")
        )
        .is_err());
        for fault in 0..4 {
            let mut wrong = closing.clone();
            match fault {
                0 => wrong.addresses = vec!["10.8.0.2/32".parse().unwrap()],
                1 => wrong.dns.push("1.1.1.1".parse().unwrap()),
                2 => wrong.options = Some(nelomai_client_tunnel::DesktopTunnelOptions::default()),
                _ => {
                    wrong.carrier = Some(crate::member_owner::InterfaceProof {
                        index: 7,
                        luid: 90,
                        guid: [1; 16],
                    })
                }
            }
            assert!(inspect_bootstrap_empty(
                &context,
                &wrong,
                BootstrapOrigin::OriginalNever,
                || panic!("foreign Never frame sampled")
            )
            .is_err());
        }
    }
    let (_, original_vip) = bootstrap_fixture();
    for channel in [
        BootstrapOrigin::OriginalNever,
        BootstrapOrigin::CreatedRetired,
    ] {
        inspect_bootstrap_empty(&context, &original_vip, channel, || Ok(observed.clone())).unwrap();
    }
}

// Actual coordinator new/Stop/CAS progression, not a decoder-generated record
// or a native capability. Every forward method denies; cleanup below is limited
// to the literal zero-owner fixture, and the target boundary deliberately fails.
fn fresh_coordinator_abort(context: &Context, halt: u8) -> crate::member_carrier_pair::Record {
    use crate::member_carrier_pair::{self as pair, CarrierPairIo, PairJournal, Record};
    use nelomai_client_tunnel::redundancy::Slot;
    use std::{cell::RefCell, io, rc::Rc};
    struct Disk(Rc<RefCell<Option<Record>>>);
    impl PairJournal for Disk {
        fn begin_cleanup(&mut self, scope: &SessionScope) -> io::Result<()> {
            if self.0.borrow().as_ref().is_none_or(|r| &r.scope != scope) {
                return Err(deny());
            }
            Ok(())
        }
        fn load(&mut self, scope: &SessionScope) -> io::Result<Option<Record>> {
            if self.0.borrow().as_ref().is_some_and(|r| &r.scope != scope) {
                return Err(deny());
            }
            Ok(self.0.borrow().clone())
        }
        fn compare_exchange(&mut self, old: Option<&Record>, new: &Record) -> io::Result<()> {
            if self.0.borrow().as_ref() != old {
                return Err(deny());
            }
            pair::validate_transition(old, new)?;
            *self.0.borrow_mut() = Some(new.clone());
            Ok(())
        }
    }
    fn deny() -> io::Error {
        io::ErrorKind::PermissionDenied.into()
    }
    struct NeverSocket;
    impl nelomai_client_tunnel::redundancy::ProbeDatagram for NeverSocket {
        fn send(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(deny())
        }
        fn receive(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(deny())
        }
    }
    impl crate::member_pair::PairSocket for NeverSocket {
        fn duplicate(&self) -> io::Result<Self> {
            Err(deny())
        }
    }
    struct EmptyIo {
        scope: SessionScope,
        halt: u8,
    }
    impl EmptyIo {
        fn absent(&self, r: &Record, stage: u8) -> io::Result<()> {
            r.validate()?;
            if r.scope != self.scope
                || r.phase != pair::Phase::Closing
                || r.stop_stage != stage
                || !r.addresses.is_empty()
                || !r.dns.is_empty()
                || r.options.is_some()
                || r.carrier.is_some()
                || r.members.iter().any(Option::is_some)
                || r.network.is_some()
                || r.pending_guard.is_some()
                || r.guard
                    != crate::member_carrier_guard::Model::empty(self.scope.clone())
                        .map_err(|_| deny())?
            {
                return Err(deny());
            }
            Ok(())
        }
    }
    macro_rules! denied {
        ($(fn $name:ident($($arg:ident: $ty:ty),*) -> $ret:ty;)*) => {
            $(fn $name(&mut self, $(_: $ty),*) -> io::Result<$ret> { Err(deny()) })*
        };
    }
    impl CarrierPairIo for EmptyIo {
        type Socket = NeverSocket;
        fn attest_effect(&mut self, r: &Record, effect: pair::Effect) -> io::Result<()> {
            self.absent(r, r.stop_stage)?;
            if r.pending.is_some_and(|p| p != effect) || r.stop_stage == self.halt {
                return Err(deny());
            }
            Ok(())
        }
        fn guard_snapshot(
            &mut self,
            s: &SessionScope,
        ) -> io::Result<crate::member_carrier_guard::Snapshot> {
            if *s != self.scope {
                return Err(deny());
            }
            Ok(crate::member_carrier_guard::Snapshot {
                version: 2,
                scope: s.clone(),
                carrier: None,
                egress: [None, None],
                sublayer: None,
                filters: vec![],
            })
        }
        fn close_dynamic_permits(&mut self, r: &Record) -> io::Result<()> {
            self.absent(r, 0)
        }
        fn release_unpublished_probes(&mut self, r: &Record) -> io::Result<()> {
            self.absent(r, 1)
        }
        fn restore_weak_rows(&mut self, r: &Record) -> io::Result<()> {
            self.absent(r, 3)
        }
        fn stop_member(&mut self, r: &Record, s: Slot) -> io::Result<()> {
            self.absent(r, if s == Slot::A { 4 } else { 5 })
        }
        fn verify_member_absent(&mut self, r: &Record, s: Slot) -> io::Result<()> {
            self.absent(r, if s == Slot::A { 4 } else { 5 })
        }
        fn delete_carrier_addresses(&mut self, r: &Record) -> io::Result<()> {
            self.absent(r, 6)
        }
        fn end_carrier_session(&mut self, r: &Record) -> io::Result<()> {
            self.absent(r, 7)
        }
        fn close_carrier_handle(&mut self, r: &Record) -> io::Result<()> {
            self.absent(r, 8)
        }
        fn verify_native_empty(&mut self, r: &Record) -> io::Result<()> {
            self.absent(r, 9)
        }
        denied! {
            fn select_running_execution(r: &Record) -> u64;
            fn preflight_fresh(r: &Record) -> ();
            fn create_carrier_ready(r: &Record) -> crate::member_owner::InterfaceProof;
            fn verify_carrier_ready(r: &Record) -> ();
            fn prepare_member(r: &Record, m: &nelomai_client_tunnel::redundancy::protocol::Member, n: &str) -> crate::member_owner::Record;
            fn start_member(r: &Record, s: Slot, n: &str) -> crate::member_owner::Record;
            fn verify_member(r: &Record, s: Slot) -> ();
            fn guard_exchange(r: &Record, k: crate::member_carrier_guard::SessionKind, e: &crate::member_carrier_guard::Model, d: &crate::member_carrier_guard::Model) -> crate::member_carrier_guard::Model;
            fn apply_weak_rows(r: &Record) -> ();
            fn restore_member_weak_rows(r: &Record, s: Slot) -> ();
            fn read_network(r: &Record) -> pair::NetworkSnapshot;
            fn plan_network(r: &Record, s: Slot) -> pair::NetworkSnapshot;
            fn plan_retirement_network(r: &Record, s: Slot) -> pair::NetworkSnapshot;
            fn verify_network_plan(r: &Record, s: Slot, d: &pair::NetworkSnapshot) -> ();
            fn exchange_network(r: &Record, e: &pair::NetworkSnapshot, d: &pair::NetworkSnapshot) -> ();
            fn verify_network_and_endpoints(r: &Record, s: Slot) -> ();
            fn hold_probe(r: &Record, s: Slot) -> (Self::Socket, crate::member_carrier_guard::ProbeTuple);
            fn verify_held_probe(r: &Record, s: Slot, h: &Self::Socket, t: &crate::member_carrier_guard::ProbeTuple) -> ();
            fn release_probe(r: &Record, s: Slot, h: Self::Socket) -> ();
            fn verify_target_health(r: &Record, s: Slot) -> ();
            fn verify_data(r: &Record, s: Slot) -> ();
            fn restore_owned_keys(r: &Record) -> ();
            fn restore_member_keys(r: &Record, s: Slot) -> ();
            fn verify_full_empty(r: &Record) -> ();
            fn observe(r: &Record, s: Slot) -> (nelomai_client_tunnel::TunnelMetrics, nelomai_client_tunnel::redundancy::evidence::NativeHealthSample);
            fn fingerprint(r: &Record) -> String;
            fn begin_rebind_execution(r: &Record) -> u64;
            fn seal_rebind_execution(r: &Record) -> ();
            fn complete_rebind_execution(r: &Record) -> u64;
            fn rebind_member(r: &Record, s: Slot) -> crate::member_owner::Record;
        }
    }
    let disk = Rc::new(RefCell::new(None));
    let mut coordinator = pair::CarrierNativePair::new(
        context.intent.scope.clone(),
        context.provenance.clone(),
        EmptyIo {
            scope: context.intent.scope.clone(),
            halt,
        },
        Disk(disk.clone()),
    )
    .unwrap();
    assert_eq!(coordinator.snapshot().phase, pair::Phase::Fresh);
    assert!(coordinator.snapshot().addresses.is_empty());
    assert!(coordinator.stop(&context.intent.scope).is_err());
    let captured = coordinator.snapshot().clone();
    assert_eq!(captured.phase, pair::Phase::Closing);
    assert_eq!(captured.stop_stage, halt);
    assert!(disk.borrow().as_ref() == Some(&captured));
    captured
}

#[test]
fn cancellation_keeps_only_precise_closing_read_channel_not_forward() {
    use crate::member_carrier_pair::Phase;
    startup_read_allowed(true, Phase::Closing, StartupRead::Cleanup).unwrap();
    for phase in [
        Phase::Fresh,
        Phase::Starting,
        Phase::Running,
        Phase::Closing,
        Phase::Stopped,
    ] {
        assert!(startup_read_allowed(true, phase, StartupRead::Forward).is_err());
        if phase != Phase::Closing {
            assert!(startup_read_allowed(true, phase, StartupRead::Cleanup).is_err());
            assert!(startup_read_allowed(false, phase, StartupRead::Cleanup).is_err());
        }
    }
    startup_read_allowed(false, Phase::Closing, StartupRead::Cleanup).unwrap();
    startup_read_allowed(false, Phase::Running, StartupRead::Forward).unwrap();
}

fn scope() -> SessionScope {
    SessionScope {
        runtime: RuntimeSlot::Stable,
        runtime_generation: 3,
        session_id: "11111111-1111-4111-8111-111111111111".into(),
        connection_generation: 4,
    }
}
fn provenance() -> Provenance {
    Provenance {
        boot_id: [7; 16],
        network_epoch: 6,
        runtime: EngineIdentity {
            slot: RuntimeSlot::Stable,
            runtime_version: "0.3.3".into(),
            container_version: "0.3.3".into(),
            runtime_contract_version: 1,
            manifest_sha256: "a".repeat(64),
        },
    }
}
fn configuration(awg: bool) -> String {
    format!("[Interface]\nPrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAddress = 10.7.0.2/32\nDNS = 1.1.1.1\n{}[Peer]\nPublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.11:51820\nPersistentKeepalive = 25\n", if awg { "Jc = 4\nJmin = 40\nJmax = 70\nHeaderProtectionKey = synthetic-header\nContentPaddingAddition = 1\n" } else { "" })
}
fn paths() -> [PathBuf; 2] {
    [TunnelSlot::A, TunnelSlot::B]
        .map(|slot| crate::test_engine_path(crate::redundancy::slot_config_filename(slot)))
}

#[test]
fn startup_layout_uses_same_server_address_and_exact_audited_member_identity() {
    for awg in [false, true] {
        let paths = paths();
        let context = requested_context(
            &scope(),
            &provenance(),
            &configuration(awg),
            [&paths[0], &paths[1]],
        )
        .unwrap();
        assert_eq!(
            context.intent,
            Intent {
                scope: scope(),
                addresses: vec!["10.7.0.2/32".parse().unwrap()]
            }
        );
        assert_eq!(context.provenance, provenance());
        let c = crate::member_carrier::carrier_key(&scope()).unwrap();
        assert_eq!(
            (
                context.bindings[0].role,
                context.bindings[0].guid,
                &context.bindings[0].name
            ),
            (Role::RoleCarrier, c.guid, &c.name)
        );
        let (provider, revision, transport) = if awg {
            (
                ProviderPath::AmneziaSignedDll,
                guid::AWG_SOURCE_REVISION,
                TunnelTransport::AmneziaWg3,
            )
        } else {
            (
                ProviderPath::WireGuardSignedDll,
                guid::WG_SOURCE_REVISION,
                TunnelTransport::WireGuard,
            )
        };
        for (i, slot) in [TunnelSlot::A, TunnelSlot::B].into_iter().enumerate() {
            let expected = guid::member_binding(
                provider,
                revision,
                slot,
                &paths[i],
                crate::redundancy::slot_service_name(slot, transport),
            )
            .unwrap();
            assert_eq!(context.bindings[i + 1], expected);
        }
        crate::member_carrier_native_ownership::validate_context(&context).unwrap();
    }
}

#[test]
fn startup_layout_refuses_invalid_address_scope_runtime_and_path_before_native_effects() {
    let paths = paths();
    for fault in 0..7 {
        let mut scope = scope();
        let mut provenance = provenance();
        let mut text = configuration(false);
        let mut paths = paths.clone();
        match fault {
            0 => text = text.replace("10.7.0.2/32", "10.7.0.2/24"),
            1 => text = text.replace("10.7.0.2/32", "2001:db8::2/128"),
            2 => text = text.replace("10.7.0.2/32", "10.7.0.2/32, 10.7.0.3/32"),
            3 => scope.connection_generation = 0,
            4 => provenance.runtime.slot = RuntimeSlot::Latest,
            5 => paths[1] = paths[0].clone(),
            _ => provenance.boot_id = [0; 16],
        }
        assert!(
            requested_context(&scope, &provenance, &text, [&paths[0], &paths[1]]).is_err(),
            "fault {fault}"
        );
    }
}

#[test]
fn startup_member_comparison_accepts_distinct_reserve_endpoint_only_on_same_carrier_provider() {
    let paths = paths();
    let primary = configuration(false);
    let context =
        requested_context(&scope(), &provenance(), &primary, [&paths[0], &paths[1]]).unwrap();
    let native = crate::redundancy::pair_configuration(&primary)
        .unwrap()
        .native;
    compare_member_text(
        &context,
        TunnelTransport::WireGuard,
        Some(&primary),
        &primary,
        &native,
    )
    .unwrap();
    let reserve = primary.replace("192.0.2.11:51820", "192.0.2.22:51821");
    let reserve_native = crate::redundancy::pair_configuration(&reserve)
        .unwrap()
        .native;
    compare_member_text(
        &context,
        TunnelTransport::WireGuard,
        None,
        &reserve,
        &reserve_native,
    )
    .unwrap();
    assert!(compare_member_text(
        &context,
        TunnelTransport::WireGuard,
        Some(&primary),
        &reserve,
        &reserve_native
    )
    .is_err());
    for fault in 0..5 {
        let mut logical = reserve.clone();
        let mut native = reserve_native.to_string();
        let mut transport = TunnelTransport::WireGuard;
        match fault {
            0 => logical = logical.replace("10.7.0.2/32", "10.7.0.3/32"),
            1 => logical = logical.replace("192.0.2.22:51821", "not-an-endpoint"),
            2 => transport = TunnelTransport::AmneziaWg3,
            3 => native.push_str("\nAddress = 10.7.0.2/32\n"),
            _ => native = native.replace("51821", "51822"),
        }
        assert!(
            compare_member_text(&context, transport, None, &logical, &native).is_err(),
            "fault {fault}"
        );
    }
}
