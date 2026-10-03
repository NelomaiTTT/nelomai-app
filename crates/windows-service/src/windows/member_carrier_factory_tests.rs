// This exercises the owning-result entry's production retention with the real
// SessionControl/carrier coordinator. It is NOT NativeStartup/SDK acceptance.
use super::*;
use crate::member_pair::FactoryPreparationSlot;

#[test]
fn factory_result_entry_retains_original_control_after_error_and_unwind() {
    for boundary in ["starting-ack", "post-starting-unwind", "fresh-ack"] {
        let external = Rc::new(RefCell::new(ExternalState::default()));
        external.borrow_mut().lose_starting_ack = boundary == "starting-ack";
        external.borrow_mut().fail_fresh_ack = boundary == "fresh-ack";
        let mut factory = Factory(external.clone());
        let mut retained = FactoryPreparationSlot::default();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            retained.prepare(|destination| {
                factory.prepare_retained_into(
                    destination,
                    RuntimeSlot::Stable,
                    &start(scope()),
                    7,
                )?;
                if boundary == "post-starting-unwind" {
                    panic!("external post-publication boundary");
                }
                Ok(())
            })
        }));
        assert!(result.is_err() || result.unwrap().is_err(), "{boundary}");
        assert!(retained.is_pending(), "original control lost at {boundary}");
        let mut replacement_called = false;
        assert!(retained
            .prepare(|_| {
                replacement_called = true;
                Ok(())
            })
            .is_err());
        assert!(!replacement_called);
        // A lost external postflight after real Stop is still an owning
        // failure. Repeat Stop may observe completion, never replay native IO.
        if boundary != "fresh-ack" {
            for unwind in [false, true] {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    retained.cleanup(|original| {
                        original.execute(Command::Stop { scope: scope() }, 8)?;
                        if unwind {
                            panic!("external terminal postflight");
                        }
                        Err(failed())
                    })
                }));
                assert!(result.is_err() || result.unwrap().is_err());
                assert!(retained.is_pending());
                assert_eq!(external.borrow().finalized[0].get(), 1);
            }
        }
        let stopped = retained.cleanup(|original| {
            assert_eq!(original.snapshot().session.scope, scope());
            original.execute(Command::Stop { scope: scope() }, 8)?;
            let snapshot = original.snapshot();
            if snapshot.cleanup_pending || snapshot.session.phase != SessionPhase::Stopped {
                return Err(failed());
            }
            Ok(())
        });
        if boundary == "fresh-ack" {
            assert!(stopped.is_err());
            assert!(retained.is_pending());
            assert_eq!(external.borrow().finalized[0].get(), 0);
        } else {
            stopped.unwrap();
            assert!(!retained.is_pending());
            assert_eq!(external.borrow().prepared[0].get(), 1);
            assert_eq!(external.borrow().finalized[0].get(), 1);
            // After exact original completion the SAME owning-result entry may
            // prepare a new session, with no old owner or receipt substitution.
            let mut next = scope();
            next.connection_generation += 1;
            next.session_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into();
            let mut control = retained
                .prepare(|destination| {
                    factory.prepare_retained_into(
                        destination,
                        RuntimeSlot::Stable,
                        &start(next.clone()),
                        9,
                    )
                })
                .unwrap();
            control
                .start_primary(&member(Slot::A), &DesktopTunnelOptions::default())
                .unwrap();
            let stopped = control.execute(Command::Stop { scope: next }, 10).unwrap();
            assert_eq!(stopped.session.phase, SessionPhase::Stopped);
            assert!(!stopped.cleanup_pending);
        }
    }
}
