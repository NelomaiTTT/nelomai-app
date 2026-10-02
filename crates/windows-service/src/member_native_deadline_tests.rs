use super::*;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    Condvar,
};

struct Events {
    ready: bool,
    stop: bool,
}
struct External {
    now: AtomicU64,
    events: Mutex<Events>,
    wake: Condvar,
    terminated: AtomicUsize,
    stop_signals: AtomicUsize,
    fail_ready: AtomicBool,
    fail_stop: AtomicBool,
    fail_wait: AtomicBool,
    panic_wait: AtomicBool,
    fail_terminate: AtomicBool,
    fail_factory: AtomicBool,
    await_return: AtomicBool,
    waiting: AtomicBool,
    largest_wait: AtomicU64,
    hold_stop_ack: AtomicBool,
    stop_ack_waiting: AtomicBool,
}
struct Boundary(Arc<External>);
struct Inputs(Arc<External>);
impl Factory for Inputs {
    type Kernel = Boundary;
    fn create(&mut self) -> Result<Boundary> {
        if self.0.fail_factory.load(Ordering::SeqCst) {
            return Err(Error::Start);
        }
        *self.0.events.lock().unwrap() = Events {
            ready: false,
            stop: false,
        };
        Ok(Boundary(self.0.clone()))
    }
}
impl Kernel for Boundary {
    fn now_ms(&self) -> u64 {
        self.0.now.load(Ordering::SeqCst)
    }
    fn signal_ready(&self) -> Result<()> {
        if self.0.fail_ready.load(Ordering::SeqCst) {
            return Err(Error::Worker);
        }
        self.0.events.lock().unwrap().ready = true;
        self.0.wake.notify_all();
        Ok(())
    }
    fn wait_ready(&self, _: u32) -> Result<Wait> {
        let e = self.0.events.lock().unwrap();
        let (e, _) = self
            .0
            .wake
            .wait_timeout_while(e, std::time::Duration::from_secs(1), |e| !e.ready)
            .unwrap();
        Ok(if e.ready {
            Wait::Signaled
        } else {
            Wait::Timeout
        })
    }
    fn signal_stop(&self) -> Result<()> {
        self.0.stop_signals.fetch_add(1, Ordering::SeqCst);
        self.0.events.lock().unwrap().stop = true;
        self.0.wake.notify_all();
        if self.0.hold_stop_ack.load(Ordering::SeqCst) {
            self.0.stop_ack_waiting.store(true, Ordering::SeqCst);
            let e = self.0.events.lock().unwrap();
            let (_events, timeout) = self
                .0
                .wake
                .wait_timeout_while(e, std::time::Duration::from_secs(2), |_| {
                    self.0.hold_stop_ack.load(Ordering::SeqCst)
                })
                .unwrap();
            assert!(!timeout.timed_out(), "test did not release stop ACK");
        }
        if self.0.fail_stop.load(Ordering::SeqCst) {
            Err(Error::Worker)
        } else {
            Ok(())
        }
    }
    fn wait_stop(&self, timeout: u32) -> Result<Wait> {
        self.0
            .largest_wait
            .fetch_max(u64::from(timeout), Ordering::SeqCst);
        self.0.waiting.store(true, Ordering::SeqCst);
        if self.0.await_return.load(Ordering::SeqCst) {
            let e = self.0.events.lock().unwrap();
            let (e, _) = self
                .0
                .wake
                .wait_timeout_while(e, std::time::Duration::from_millis(100), |e| !e.stop)
                .unwrap();
            return Ok(if e.stop {
                Wait::Signaled
            } else {
                Wait::Timeout
            });
        }
        assert!(
            !self.0.panic_wait.load(Ordering::SeqCst),
            "injected worker unwind"
        );
        if self.0.fail_wait.load(Ordering::SeqCst) {
            return Err(Error::Worker);
        }
        let e = self.0.events.lock().unwrap();
        let (e, _) = self
            .0
            .wake
            .wait_timeout_while(e, std::time::Duration::from_millis(1), |e| {
                !e.stop && self.now_ms() < 30_000
            })
            .unwrap();
        Ok(if e.stop {
            Wait::Signaled
        } else {
            Wait::Timeout
        })
    }
    fn terminate_current(&self) -> Result<()> {
        self.0.terminated.fetch_add(1, Ordering::SeqCst);
        if self.0.fail_terminate.load(Ordering::SeqCst) {
            Err(Error::Worker)
        } else {
            Ok(())
        }
    }
}
fn fixture(ready: bool, stop: bool, wait: bool) -> (Deadline<u64, Inputs>, Arc<External>) {
    let external = Arc::new(External {
        now: AtomicU64::new(0),
        events: Mutex::new(Events {
            ready: false,
            stop: false,
        }),
        wake: Condvar::new(),
        terminated: AtomicUsize::new(0),
        stop_signals: AtomicUsize::new(0),
        fail_ready: AtomicBool::new(ready),
        fail_stop: AtomicBool::new(stop),
        fail_wait: AtomicBool::new(wait),
        panic_wait: AtomicBool::new(false),
        fail_terminate: AtomicBool::new(false),
        fail_factory: AtomicBool::new(false),
        await_return: AtomicBool::new(false),
        waiting: AtomicBool::new(false),
        largest_wait: AtomicU64::new(0),
        hold_stop_ack: AtomicBool::new(false),
        stop_ack_waiting: AtomicBool::new(false),
    });
    (Deadline::new(7, Inputs(external.clone())), external)
}

#[test]
fn watchdog_rechecks_monotonic_deadline_after_short_os_waits() {
    let (deadline, external) = fixture(false, false, false);
    external.await_return.store(true, Ordering::SeqCst);
    deadline
        .run(&7, || {
            for _ in 0..1000 {
                if external.waiting.load(Ordering::SeqCst) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            assert!(external.waiting.load(Ordering::SeqCst));
            // Windows8+ waits exclude sleep time; monotonic deadline must be
            // rechecked within a short slice after scheduling resumes.
            assert!(external.largest_wait.load(Ordering::SeqCst) <= 1000);
            Ok::<_, ()>(())
        })
        .unwrap();
}

#[test]
fn late_returned_ack_denies_success_without_killing_quiescent_owner() {
    let (deadline, external) = fixture(false, false, false);
    external.await_return.store(true, Ordering::SeqCst);
    assert_eq!(
        deadline.run(&7, || {
            for _ in 0..100 {
                if external.waiting.load(Ordering::SeqCst) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            assert!(external.waiting.load(Ordering::SeqCst));
            external.now.store(HARD_BUDGET_MS, Ordering::SeqCst);
            Ok::<_, ()>(())
        }),
        Err(Failure::Supervisor(Error::Deadline))
    );
    assert_eq!(external.terminated.load(Ordering::SeqCst), 0);
    assert_eq!(
        deadline.run(&7, || Ok::<_, ()>(())),
        Err(Failure::Supervisor(Error::Revoked))
    );
}

#[test]
fn final_termination_boundary_rechecks_completion_and_never_kills_idle_owner() {
    for phase in [
        Phase::Idle,
        Phase::Starting,
        Phase::Armed,
        Phase::Completing,
        Phase::Closed,
    ] {
        let (deadline, external) = fixture(false, false, false);
        deadline.state.lock().unwrap().phase = phase;
        terminate_once(&deadline.state, &Boundary(external.clone())).unwrap();
        assert_eq!(external.terminated.load(Ordering::SeqCst), 0);
    }
    let (deadline, external) = fixture(false, false, false);
    {
        let mut state = deadline.state.lock().unwrap();
        state.phase = Phase::Calling;
        state.returned = Some(Returned::Acknowledged);
    }
    // Completion may win after the worker's earlier error decision, but before
    // its final termination boundary. That stale decision grants no kill.
    terminate_once(&deadline.state, &Boundary(external.clone())).unwrap();
    assert_eq!(external.terminated.load(Ordering::SeqCst), 0);
}

#[test]
fn effect_read_pin_requires_actual_inflight_same_supervised_call() {
    let (deadline, _) = fixture(false, false, false);
    let pin = deadline.pin().unwrap();
    deadline
        .run(&7, || {
            assert_eq!(deadline.verify_call(&pin, &7), Ok(()));
            Ok::<_, ()>(())
        })
        .unwrap();
    assert!(deadline.verify_call(&pin, &7).is_err());
    assert!(deadline.run(&7, || Ok::<_, ()>(())).is_err());
    let (idle, _) = fixture(false, false, false);
    let idle_pin = idle.pin().unwrap();
    assert!(idle.verify_call(&idle_pin, &7).is_err());
    assert!(idle.run(&7, || Ok::<_, ()>(())).is_err());
}

#[test]
fn transaction_call_state_is_read_only_exact_original_and_never_idle_permission() {
    let (deadline, external) = fixture(false, false, false);
    let pin = deadline.pin().unwrap();
    let (foreign, _) = fixture(false, false, false);
    let foreign_pin = foreign.pin().unwrap();
    assert_eq!(
        deadline.verify_call_state_only(&pin, &7),
        Err(Error::Revoked)
    );
    assert_eq!(external.stop_signals.load(Ordering::SeqCst), 0);
    // A failed factual read neither arms a call nor cancels a legitimate owner.
    deadline
        .run(&7, || {
            assert_eq!(deadline.verify_call_state_only(&pin, &7), Ok(()));
            let signals = external.stop_signals.load(Ordering::SeqCst);
            assert_eq!(
                deadline.verify_call_state_only(&foreign_pin, &7),
                Err(Error::Scope)
            );
            assert_eq!(deadline.verify_call_state_only(&pin, &8), Err(Error::Scope));
            assert_eq!(external.stop_signals.load(Ordering::SeqCst), signals);
            assert_eq!(deadline.verify_call_state_only(&pin, &7), Ok(()));
            Ok::<_, ()>(())
        })
        .unwrap();
    assert_eq!(
        deadline.verify_call_state_only(&pin, &7),
        Err(Error::Revoked)
    );
}

#[test]
fn transaction_call_state_denies_expired_budget_without_event_side_effects() {
    let (deadline, external) = fixture(false, false, false);
    let pin = deadline.pin().unwrap();
    deadline
        .run(&7, || {
            let limit = deadline.state.lock().unwrap().deadline;
            let signals = external.stop_signals.load(Ordering::SeqCst);
            external.now.store(limit, Ordering::SeqCst);
            assert_eq!(
                deadline.verify_call_state_only(&pin, &7),
                Err(Error::Deadline)
            );
            assert_eq!(external.stop_signals.load(Ordering::SeqCst), signals);
            // Reset ONLY the external fake clock to let the test owner finish.
            external.now.store(limit - 1, Ordering::SeqCst);
            Ok::<_, ()>(())
        })
        .unwrap();
}

#[test]
fn transaction_call_state_uses_original_cleanup_call_not_revived_live_state() {
    let (deadline, _) = fixture(false, false, false);
    let pin = deadline.pin().unwrap();
    assert_eq!(
        deadline.run(&7, || Err::<(), _>(19)),
        Err(Failure::Native(19))
    );
    assert!(deadline.verify_call_state_only(&pin, &7).is_err());
    deadline
        .run_cleanup(&7, || {
            assert_eq!(deadline.verify_call_state_only(&pin, &7), Ok(()));
            Ok::<_, ()>(())
        })
        .unwrap();
    assert!(deadline.verify_call_state_only(&pin, &7).is_err());
    assert!(deadline
        .run::<(), ()>(&7, || panic!("no revived forward"))
        .is_err());
}

#[test]
fn transaction_pin_never_crosses_to_a_later_call_with_equal_scope() {
    let (deadline, _) = fixture(false, false, false);
    let pin = deadline.pin().unwrap();
    let mut saved = None;
    assert!(deadline.transaction_pin(&pin, &7).is_err());
    deadline
        .run(&7, || {
            let call = deadline.transaction_pin(&pin, &7).unwrap();
            deadline.verify_transaction_call(&call, &7).unwrap();
            saved = Some(call);
            Ok::<_, ()>(())
        })
        .unwrap();
    assert!(deadline
        .verify_transaction_call(saved.as_ref().unwrap(), &7)
        .is_err());
    deadline
        .run(&7, || {
            assert_eq!(
                deadline.verify_transaction_call(saved.as_ref().unwrap(), &7),
                Err(Error::Scope)
            );
            let actual = deadline.transaction_pin(&pin, &7).unwrap();
            deadline.verify_transaction_call(&actual, &7).unwrap();
            Ok::<_, ()>(())
        })
        .unwrap();
}

#[test]
fn real_policy_requires_worker_start_ack_then_closes_before_returning_success() {
    // Break caught: enter a native call without a running/acknowledged watchdog,
    // or return success without consuming the same worker's exit acknowledgement.
    let (deadline, external) = fixture(false, false, false);
    assert_eq!(
        deadline.run(&7, || {
            assert!(external.events.lock().unwrap().ready);
            Ok::<_, ()>(41)
        }),
        Ok(41)
    );
    assert!(external.events.lock().unwrap().stop);
    assert_eq!(external.terminated.load(Ordering::SeqCst), 0);
}

#[test]
fn hung_call_hits_fixed_deadline_on_same_retained_target_and_late_ack_never_revives() {
    // Break caught: cooperative callback timeout, wrong process target, or late
    // completion/new-generation retry converts unknown outcome into success.
    let (deadline, external) = fixture(false, false, false);
    assert_eq!(
        deadline.run(&7, || {
            external.now.store(30_000, Ordering::SeqCst);
            external.wake.notify_all();
            for _ in 0..100 {
                if external.terminated.load(Ordering::SeqCst) != 0 {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            assert_eq!(external.terminated.load(Ordering::SeqCst), 1);
            Ok::<_, ()>(1)
        }),
        Err(Failure::Supervisor(Error::Deadline))
    );
    assert_eq!(
        deadline.run(&7, || Ok::<_, ()>(2)),
        Err(Failure::Supervisor(Error::Revoked))
    );
    assert_eq!(
        deadline.run(&8, || Ok::<_, ()>(2)),
        Err(Failure::Supervisor(Error::Revoked))
    );
    assert_eq!(external.terminated.load(Ordering::SeqCst), 1);
}

#[test]
fn cancellation_and_reentrancy_revoke_without_second_native_entry() {
    for cancel in [false, true] {
        let (deadline, external) = fixture(false, false, false);
        assert_eq!(
            deadline.run(&7, || {
                if cancel {
                    deadline.cancel().unwrap();
                } else {
                    assert_eq!(
                        deadline.run::<(), ()>(&7, || panic!("second native entry")),
                        Err(Failure::<()>::Supervisor(Error::Reentrant))
                    );
                }
                Ok::<_, ()>(1)
            }),
            Err(Failure::Supervisor(if cancel {
                Error::Cancelled
            } else {
                Error::Reentrant
            }))
        );
        assert_eq!(
            deadline.run(&7, || Ok::<_, ()>(1)),
            Err(Failure::Supervisor(Error::Revoked))
        );
        // Termination depends on whether the callback has returned by the time
        // the worker observes cancellation; never a native success either way.
        assert!(external.terminated.load(Ordering::SeqCst) <= 1);
    }
}

#[test]
fn missing_start_ack_and_worker_or_stop_ack_error_permanently_deny() {
    for (ready, stop, wait) in [
        (true, false, false),
        (false, true, false),
        (false, false, true),
    ] {
        let (deadline, external) = fixture(ready, stop, wait);
        let result = deadline.run(&7, || {
            if wait {
                // A fast synchronous return may legitimately let the worker
                // observe completion before it calls wait_stop. Injecting an
                // error into an uncalled boundary is not evidence of failure.
                // Keep this call in flight until the actual fake wait entered;
                // its Err must then deny success, regardless of return order.
                for _ in 0..1000 {
                    if external.waiting.load(Ordering::SeqCst) {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                assert!(external.waiting.load(Ordering::SeqCst));
            }
            Ok::<_, ()>(42)
        });
        assert!(result.is_err(), "ready={ready}, stop={stop}, wait={wait}");
        assert_eq!(
            deadline.run::<(), ()>(&7, || panic!("retry must not enter")),
            Err(Failure::<()>::Supervisor(Error::Revoked))
        );
    }
}

#[test]
fn owner_thread_retains_opaque_native_ack_before_later_completion_error() {
    // An ACK belongs in the actual integrating owner's retained obligation slot,
    // not merely in the value that run may discard after completion failure.
    // This non-Clone, !Send receipt also proves the closure stays on the owner.
    struct Receipt(std::rc::Rc<std::cell::Cell<usize>>);
    impl Drop for Receipt {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    for post_ack_check_error in [false, true] {
        let (deadline, _) = fixture(false, !post_ack_check_error, false);
        let released = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut actual_owner_slot = None;
        let result = deadline.run(&7, || {
            actual_owner_slot = Some(Receipt(released.clone()));
            if post_ack_check_error {
                Err(19)
            } else {
                Ok(())
            }
        });
        if post_ack_check_error {
            assert_eq!(result, Err(Failure::Native(19)));
        } else {
            assert_eq!(result, Err(Failure::Supervisor(Error::Worker)));
        }
        assert!(actual_owner_slot.is_some());
        assert_eq!(released.get(), 0);
        assert_eq!(
            deadline.run(&7, || Ok::<_, i32>(())),
            Err(Failure::Supervisor(Error::Revoked))
        );
        drop(actual_owner_slot);
        assert_eq!(released.get(), 1);
    }
}

#[test]
fn native_error_and_unwind_release_worker_but_never_supply_success_ack() {
    let (deadline, external) = fixture(false, false, false);
    assert_eq!(
        deadline.run(&7, || Err::<(), _>(19)),
        Err(Failure::Native(19))
    );
    assert_eq!(
        deadline.run(&7, || Ok::<_, ()>(1)),
        Err(Failure::Supervisor(Error::Revoked))
    );
    assert_eq!(external.terminated.load(Ordering::SeqCst), 0);
    let (deadline, external) = fixture(false, false, false);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| deadline.run(
            &7,
            || -> std::result::Result<(), ()> {
                panic!("native unwind");
            }
        )))
        .is_err()
    );
    assert_eq!(
        deadline.run(&7, || Ok::<_, ()>(1)),
        Err(Failure::Supervisor(Error::Revoked))
    );
    assert!(external.events.lock().unwrap().stop);
    assert_eq!(external.terminated.load(Ordering::SeqCst), 0);
}

#[test]
fn equal_scope_never_adopts_foreign_read_pin_and_generation_drift_revokes() {
    let (owner, _) = fixture(false, false, false);
    let (other, _) = fixture(false, false, false);
    let pin = owner.pin().unwrap();
    owner.verify_pin(&pin, &7).unwrap();
    assert_eq!(other.verify_pin(&pin, &7), Err(Error::Scope));
    assert_eq!(
        other.run(&7, || Ok::<_, ()>(1)),
        Err(Failure::Supervisor(Error::Revoked))
    );
    owner.verify_pin(&pin, &7).unwrap();
    assert_eq!(owner.verify_pin(&pin, &8), Err(Error::Scope));
    assert_eq!(owner.verify_pin(&pin, &7), Err(Error::Revoked));
}

#[test]
fn actual_process_lease_never_resets_uncertainty_through_new_constructor_or_pins() {
    // Break caught: second constructor/generation bypasses a lost ACK, or an
    // outstanding same-owner read pin releases the live constructor lease.
    let registry = Mutex::new(OwnerRegistry::empty());
    let owner = std::rc::Rc::new(ProcessOwner::acquire(&registry).unwrap());
    let pin = owner.clone();
    assert!(ProcessOwner::acquire(&registry).is_err());
    drop(owner);
    assert!(ProcessOwner::acquire(&registry).is_err());
    pin.uncertain();
    drop(pin);
    assert_eq!(ProcessOwner::acquire(&registry).err(), Some(Error::Revoked));
    let registry = Mutex::new(OwnerRegistry::empty());
    drop(ProcessOwner::acquire(&registry).unwrap());
    // A positively quiescent owner with no uncertainty/pins can be replaced.
    assert!(ProcessOwner::acquire(&registry).is_ok());
}

#[test]
fn duplicate_completion_and_rundown_never_supply_another_ack_or_worker() {
    // Break caught: duplicate completion readback/close fabricates a receipt.
    let (deadline, external) = fixture(false, false, false);
    deadline.run(&7, || Ok::<_, ()>(())).unwrap();
    let sequence = deadline.state.lock().unwrap().sequence;
    let mut guard = CallGuard {
        state: deadline.state.clone(),
        kernel: Arc::new(Boundary(external.clone())),
        sequence,
        worker: None,
    };
    guard.returned(Returned::Acknowledged, None);
    assert_eq!(guard.finish(), Err(Error::Worker));
    assert_eq!(external.stop_signals.load(Ordering::SeqCst), 1);
    assert_eq!(
        deadline.run(&7, || Ok::<_, ()>(())),
        Err(Failure::Supervisor(Error::Revoked))
    );
}

#[test]
fn successful_sequences_use_fresh_events_and_retire_exact_worker_before_reuse() {
    let (deadline, external) = fixture(false, false, false);
    let pin = deadline.pin().unwrap();
    for expected in 1..=3 {
        assert_eq!(deadline.run(&7, || Ok::<_, ()>(expected)), Ok(expected));
        assert_eq!(deadline.state.lock().unwrap().sequence, expected);
        deadline.verify_pin(&pin, &7).unwrap();
    }
    assert_eq!(external.terminated.load(Ordering::SeqCst), 0);
}

#[test]
fn worker_error_or_unwind_interrupts_without_progress_by_the_native_caller() {
    // Break caught: worker merely reports an error for a caller that is hung,
    // fails to revoke after unwind, or targets a separately reconstructed owner.
    for unwind in [false, true] {
        let (deadline, external) = fixture(false, false, false);
        let (_foreign_owner, foreign) = fixture(false, false, false);
        assert_eq!(
            deadline.run(&7, || {
                if unwind {
                    external.panic_wait.store(true, Ordering::SeqCst);
                } else {
                    external.fail_wait.store(true, Ordering::SeqCst);
                }
                external.wake.notify_all();
                for _ in 0..100 {
                    if external.terminated.load(Ordering::SeqCst) != 0 {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                assert_eq!(external.terminated.load(Ordering::SeqCst), 1);
                assert_eq!(foreign.terminated.load(Ordering::SeqCst), 0);
                Ok::<_, ()>(())
            }),
            Err(Failure::Supervisor(Error::Worker))
        );
        assert_eq!(
            deadline.run(&7, || Ok::<_, ()>(())),
            Err(Failure::Supervisor(Error::Revoked))
        );
        assert_eq!(external.terminated.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn failed_termination_is_unknown_and_once_attempted_not_a_successful_retry() {
    let (deadline, external) = fixture(false, false, false);
    external.fail_terminate.store(true, Ordering::SeqCst);
    assert_eq!(
        deadline.run(&7, || {
            external.now.store(30_000, Ordering::SeqCst);
            external.wake.notify_all();
            for _ in 0..100 {
                if external.terminated.load(Ordering::SeqCst) != 0 {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Ok::<_, ()>(())
        }),
        Err(Failure::Supervisor(Error::Deadline))
    );
    assert_eq!(external.terminated.load(Ordering::SeqCst), 1);
    assert_eq!(
        deadline.run(&7, || Ok::<_, ()>(())),
        Err(Failure::Supervisor(Error::Revoked))
    );
}

#[test]
fn event_creation_failure_has_no_call_entry_or_retry_after_lost_start() {
    let (deadline, external) = fixture(false, false, false);
    external.fail_factory.store(true, Ordering::SeqCst);
    assert_eq!(
        deadline.run::<(), ()>(&7, || panic!("no native entry")),
        Err(Failure::Supervisor(Error::Start))
    );
    external.fail_factory.store(false, Ordering::SeqCst);
    assert_eq!(
        deadline.run::<(), ()>(&7, || panic!("no retry")),
        Err(Failure::Supervisor(Error::Revoked))
    );
    assert_eq!(external.terminated.load(Ordering::SeqCst), 0);
}

fn deny_both(deadline: &Deadline<u64, Inputs>) {
    assert!(!deadline.cleanup_eligible());
    let entries = std::cell::Cell::new(0);
    assert!(deadline
        .run(&7, || {
            entries.set(entries.get() + 1);
            Ok::<_, ()>(())
        })
        .is_err());
    assert!(deadline
        .run_cleanup(&7, || {
            entries.set(entries.get() + 1);
            Ok::<_, ()>(())
        })
        .is_err());
    assert_eq!(entries.get(), 0, "denied timing must never enter effects");
}

#[test]
fn cleanup_normal_error_uses_original_calling_pin_and_never_revives_live() {
    // Break caught: resetting live revocation, replacing the supervisor/pin,
    // or admitting an idle revoked pin outside the real cleanup call.
    let (deadline, external) = fixture(false, false, false);
    let (_secondary, secondary) = fixture(false, false, false);
    let pin = deadline.pin().unwrap();
    let state = pin.state.clone();
    assert_eq!(
        deadline.run(&7, || Err::<(), _>(19)),
        Err(Failure::Native(19))
    );
    assert!(deadline.cleanup_eligible());
    assert_eq!(deadline.verify_pin(&pin, &7), Err(Error::Revoked));
    assert!(deadline.pin().is_err());
    for sequence in 2..=4 {
        assert_eq!(
            deadline.run::<(), ()>(&7, || panic!("live before cleanup")),
            Err(Failure::Supervisor(Error::Revoked))
        );
        assert_eq!(
            deadline.run_cleanup(&7, || {
                assert!(
                    deadline.cleanup_eligible(),
                    "SAME Calling cleanup is eligible for reauthentication"
                );
                assert!(Arc::ptr_eq(&state, &deadline.state));
                assert_eq!(deadline.verify_pin(&pin, &7), Ok(()));
                assert_eq!(deadline.verify_call(&pin, &7), Ok(()));
                let factual = deadline.pin().unwrap();
                assert_eq!(deadline.verify_call(&factual, &7), Ok(()));
                assert_eq!(
                    deadline.run::<(), ()>(&7, || panic!("live during cleanup")),
                    Err(Failure::Supervisor(Error::Revoked))
                );
                Ok::<_, ()>(sequence)
            }),
            Ok(sequence)
        );
        assert_eq!(deadline.state.lock().unwrap().sequence, sequence);
        assert!(deadline.cleanup_eligible());
        assert_eq!(deadline.verify_pin(&pin, &7), Err(Error::Revoked));
    }
    assert_eq!(
        deadline.run::<(), ()>(&7, || panic!("live after cleanup")),
        Err(Failure::Supervisor(Error::Revoked))
    );
    assert_eq!(external.terminated.load(Ordering::SeqCst), 0);
    assert_eq!(secondary.terminated.load(Ordering::SeqCst), 0);
}

#[test]
fn cleanup_idle_or_healthy_completed_owner_irreversibly_forbids_live() {
    for completed in [false, true] {
        let (deadline, external) = fixture(false, false, false);
        let pin = deadline.pin().unwrap();
        if completed {
            deadline.run(&7, || Ok::<_, ()>(())).unwrap();
        }
        assert!(deadline.cleanup_eligible());
        deadline
            .run_cleanup(&7, || {
                deadline.verify_call(&pin, &7).unwrap();
                Ok::<_, ()>(())
            })
            .unwrap();
        assert_eq!(deadline.verify_pin(&pin, &7), Err(Error::Revoked));
        assert_eq!(
            deadline.run::<(), ()>(&7, || panic!("cleanup is irreversible")),
            Err(Failure::Supervisor(Error::Revoked))
        );
        deadline
            .run_cleanup(&7, || {
                deadline.verify_call(&pin, &7).unwrap();
                Ok::<_, ()>(())
            })
            .unwrap();
        assert_eq!(external.terminated.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn cleanup_returned_error_can_continue_only_after_same_worker_rundown() {
    // Break caught: equating a normal error with unwind, or considering the
    // synchronous error itself sufficient before its worker has joined.
    let (deadline, external) = fixture(false, false, false);
    let pin = deadline.pin().unwrap();
    assert_eq!(
        deadline.run(&7, || Err::<(), _>(19)),
        Err(Failure::Native(19))
    );
    assert_eq!(
        deadline.run_cleanup(&7, || {
            deadline.verify_call(&pin, &7).unwrap();
            Err::<(), _>(23)
        }),
        Err(Failure::Native(23))
    );
    assert!(external.events.lock().unwrap().stop);
    assert_eq!(deadline.verify_pin(&pin, &7), Err(Error::Revoked));
    deadline
        .run_cleanup(&7, || {
            deadline.verify_call(&pin, &7).unwrap();
            Ok::<_, ()>(())
        })
        .unwrap();
    assert_eq!(external.terminated.load(Ordering::SeqCst), 0);
}

#[test]
fn cleanup_unwind_live_or_cleanup_is_irrecoverable() {
    for cleanup in [false, true] {
        let (deadline, external) = fixture(false, false, false);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if cleanup {
                deadline.run_cleanup(&7, || -> std::result::Result<(), ()> {
                    panic!("cleanup unwind")
                })
            } else {
                deadline.run(&7, || -> std::result::Result<(), ()> {
                    panic!("live unwind")
                })
            }
        }));
        assert!(outcome.is_err());
        deny_both(&deadline);
        assert_eq!(external.terminated.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn cleanup_late_quiescent_return_even_without_termination_is_denied() {
    for (cleanup, native_error) in [(false, false), (false, true), (true, false), (true, true)] {
        let (deadline, external) = fixture(false, false, false);
        external.await_return.store(true, Ordering::SeqCst);
        let call = || {
            for _ in 0..1000 {
                if external.waiting.load(Ordering::SeqCst) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            assert!(external.waiting.load(Ordering::SeqCst));
            external.now.store(30_000, Ordering::SeqCst);
            if native_error {
                Err(19)
            } else {
                Ok(())
            }
        };
        let result = if cleanup {
            deadline.run_cleanup(&7, call)
        } else {
            deadline.run(&7, call)
        };
        assert!(result.is_err());
        assert_eq!(external.terminated.load(Ordering::SeqCst), 0);
        external.now.store(0, Ordering::SeqCst);
        deny_both(&deadline);
    }
}

#[test]
fn cleanup_hung_call_uses_only_original_target_and_attempted_termination_denies() {
    for cleanup in [false, true] {
        for failed_termination in [false, true] {
            let (deadline, external) = fixture(false, false, false);
            let (_secondary, secondary) = fixture(false, false, false);
            external
                .fail_terminate
                .store(failed_termination, Ordering::SeqCst);
            let call = || {
                external.now.store(30_000, Ordering::SeqCst);
                external.wake.notify_all();
                for _ in 0..1000 {
                    if external.terminated.load(Ordering::SeqCst) != 0 {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                assert_eq!(external.terminated.load(Ordering::SeqCst), 1);
                Err::<(), _>(19)
            };
            assert!(if cleanup {
                deadline.run_cleanup(&7, call)
            } else {
                deadline.run(&7, call)
            }
            .is_err());
            external.now.store(0, Ordering::SeqCst);
            deny_both(&deadline);
            assert_eq!(external.terminated.load(Ordering::SeqCst), 1);
            assert_eq!(secondary.terminated.load(Ordering::SeqCst), 0);
        }
    }
}

#[test]
fn cleanup_cancel_and_reentry_deny_all_continuation() {
    for cancel in [false, true] {
        let (deadline, _) = fixture(false, false, false);
        assert!(deadline
            .run_cleanup(&7, || {
                if cancel {
                    assert_eq!(deadline.cancel(), Ok(()));
                } else {
                    assert_eq!(
                        deadline.run_cleanup::<(), ()>(&7, || panic!("cleanup reentry")),
                        Err(Failure::Supervisor(Error::Reentrant))
                    );
                }
                Ok::<_, ()>(())
            })
            .is_err());
        deny_both(&deadline);
    }
    let (deadline, _) = fixture(false, false, false);
    deadline.run(&7, || Err::<(), _>(19)).unwrap_err();
    let _ = deadline.cancel();
    deny_both(&deadline);
}

#[test]
fn cleanup_foreign_equal_pin_or_scope_sticks_across_both_modes() {
    for cleanup in [false, true] {
        for foreign_pin in [false, true] {
            let (deadline, _) = fixture(false, false, false);
            let (foreign, secondary) = fixture(false, false, false);
            let pin = if foreign_pin {
                foreign.pin().unwrap()
            } else {
                deadline.pin().unwrap()
            };
            let effects = std::cell::Cell::new(0);
            let call = || {
                // Entry checks the actual retained pin before its effect.
                deadline.verify_call(&pin, &if foreign_pin { 7 } else { 8 })?;
                effects.set(effects.get() + 1);
                Ok::<_, Error>(())
            };
            assert_eq!(
                if cleanup {
                    deadline.run_cleanup(&7, call)
                } else {
                    deadline.run(&7, call)
                },
                Err(Failure::Native(Error::Scope))
            );
            assert_eq!(effects.get(), 0);
            deny_both(&deadline);
            assert_eq!(secondary.terminated.load(Ordering::SeqCst), 0);
        }
    }
    let (deadline, _) = fixture(false, false, false);
    deadline.run(&7, || Err::<(), _>(19)).unwrap_err();
    assert_eq!(
        deadline.run_cleanup::<(), ()>(&8, || panic!("foreign scope")),
        Err(Failure::Supervisor(Error::Scope))
    );
    deny_both(&deadline);
}

#[test]
fn cleanup_missing_start_worker_error_and_missing_rundown_deny_without_retry_effects() {
    for cleanup in [false, true] {
        for (ready, stop, wait) in [
            (true, false, false),
            (false, true, false),
            (false, false, true),
        ] {
            let (deadline, external) = fixture(ready, stop, wait);
            let call = || {
                if wait {
                    for _ in 0..1000 {
                        if external.terminated.load(Ordering::SeqCst) != 0 {
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    assert_eq!(external.terminated.load(Ordering::SeqCst), 1);
                }
                Err::<(), _>(19)
            };
            let result = if cleanup {
                deadline.run_cleanup(&7, call)
            } else {
                deadline.run(&7, call)
            };
            assert!(result.is_err());
            deny_both(&deadline);
        }
        let (deadline, external) = fixture(false, false, false);
        external.fail_factory.store(true, Ordering::SeqCst);
        let effects = std::cell::Cell::new(0);
        let call = || {
            effects.set(1);
            Ok::<_, ()>(())
        };
        assert_eq!(
            if cleanup {
                deadline.run_cleanup(&7, call)
            } else {
                deadline.run(&7, call)
            },
            Err(Failure::Supervisor(Error::Start))
        );
        assert_eq!(effects.get(), 0);
        external.fail_factory.store(false, Ordering::SeqCst);
        deny_both(&deadline);
    }
}

#[test]
fn cleanup_eligibility_waits_for_real_rundown_and_denies_live_calling() {
    // Break caught: publish cleanup before the same worker's positive stop ACK
    // and join, or grant cleanup checks in an arbitrary live Calling phase.
    let (deadline, external) = fixture(false, false, false);
    let deadline = Arc::new(deadline);
    external.hold_stop_ack.store(true, Ordering::SeqCst);
    let owner = deadline.clone();
    let thread = std::thread::spawn(move || {
        owner.run(&7, || {
            assert!(!owner.cleanup_eligible());
            Err::<(), _>(19)
        })
    });
    for _ in 0..1000 {
        if external.stop_ack_waiting.load(Ordering::SeqCst) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    let waiting = external.stop_ack_waiting.load(Ordering::SeqCst);
    let premature = deadline.cleanup_eligible();
    external.hold_stop_ack.store(false, Ordering::SeqCst);
    external.wake.notify_all();
    assert_eq!(thread.join().unwrap(), Err(Failure::Native(19)));
    assert!(waiting);
    assert!(!premature);
    assert!(deadline.cleanup_eligible());
}

#[test]
fn cleanup_worker_unwind_and_failed_post_error_start_or_stop_never_admit_continuation() {
    for fault in ["ready", "stop", "factory", "worker", "unwind"] {
        let (deadline, external) = fixture(false, false, false);
        let (_secondary, secondary) = fixture(false, false, false);
        let pin = deadline.pin().unwrap();
        assert_eq!(
            deadline.run(&7, || Err::<(), _>(19)),
            Err(Failure::Native(19))
        );
        assert!(deadline.cleanup_eligible());
        match fault {
            "ready" => external.fail_ready.store(true, Ordering::SeqCst),
            "stop" => external.fail_stop.store(true, Ordering::SeqCst),
            "factory" => external.fail_factory.store(true, Ordering::SeqCst),
            _ => (),
        }
        let effects = std::cell::Cell::new(0);
        let result = deadline.run_cleanup(&7, || {
            if matches!(fault, "worker" | "unwind") {
                if fault == "worker" {
                    external.fail_wait.store(true, Ordering::SeqCst);
                } else {
                    external.panic_wait.store(true, Ordering::SeqCst);
                }
                external.wake.notify_all();
                for _ in 0..1000 {
                    if external.terminated.load(Ordering::SeqCst) != 0 {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                assert_eq!(external.terminated.load(Ordering::SeqCst), 1);
            }
            deadline.verify_call(&pin, &7)?;
            effects.set(effects.get() + 1);
            // Stop ACK failure occurs AFTER return; no result infers absence
            // of effects. This call models a returned operation error.
            Err::<(), _>(Error::Native)
        });
        assert!(result.is_err());
        assert_eq!(
            effects.get(),
            usize::from(fault == "stop"),
            "lost rundown after entry cannot imply native absence"
        );
        deny_both(&deadline);
        assert_eq!(secondary.terminated.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn cleanup_same_retained_process_lease_forbids_live_and_constructor_replacement() {
    // Break caught: treating cleanup-only retention like a healthy lease when
    // its last original pin drops, permitting a replacement live constructor.
    let registry = Mutex::new(OwnerRegistry::empty());
    let owner = std::rc::Rc::new(ProcessOwner::acquire(&registry).unwrap());
    let retained = owner.clone();
    assert_eq!(owner.verify_cleanup(), Err(Error::Revoked));
    owner.retain_cleanup_only().unwrap();
    assert_eq!(owner.verify(), Err(Error::Revoked));
    assert_eq!(retained.verify_cleanup(), Ok(()));
    assert!(ProcessOwner::acquire(&registry).is_err());
    drop(owner);
    assert_eq!(retained.verify_cleanup(), Ok(()));
    drop(retained);
    assert_eq!(ProcessOwner::acquire(&registry).err(), Some(Error::Revoked));
}

#[test]
fn verified_terminal_owner_releases_only_after_last_original_pin_drops() {
    let registry = Mutex::new(OwnerRegistry::empty());
    let owner = std::rc::Rc::new(ProcessOwner::acquire(&registry).unwrap());
    let pin = owner.clone();
    owner.retain_cleanup_only().unwrap();
    owner.verified_terminal_drop(|| Ok(())).unwrap();
    assert_eq!(owner.verify(), Err(Error::Revoked));
    assert!(ProcessOwner::acquire(&registry).is_err());
    drop(owner);
    assert!(ProcessOwner::acquire(&registry).is_err());
    drop(pin);
    assert!(ProcessOwner::acquire(&registry).is_ok());
}

#[test]
fn failed_terminal_drop_check_and_later_uncertainty_never_reopen_registry() {
    for fault_after in [false, true] {
        let registry = Mutex::new(OwnerRegistry::empty());
        let owner = ProcessOwner::acquire(&registry).unwrap();
        owner.retain_cleanup_only().unwrap();
        if fault_after {
            owner.verified_terminal_drop(|| Ok(())).unwrap();
            owner.uncertain();
        } else {
            assert!(owner.verified_terminal_drop(|| Err(Error::Native)).is_err());
        }
        drop(owner);
        assert_eq!(ProcessOwner::acquire(&registry).err(), Some(Error::Revoked));
    }
}

#[test]
fn terminal_drop_unwind_and_swallowed_reentry_poison_last_pin() {
    for unwind in [false, true] {
        let registry = Mutex::new(OwnerRegistry::empty());
        let owner = ProcessOwner::acquire(&registry).unwrap();
        owner.retain_cleanup_only().unwrap();
        if unwind {
            assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = owner.verified_terminal_drop(|| panic!("terminal verifier unwind"));
            }))
            .is_err());
        } else {
            assert_eq!(
                owner.verified_terminal_drop(|| {
                    assert_eq!(owner.verified_terminal_drop(|| Ok(())), Err(Error::Revoked));
                    Ok(())
                }),
                Err(Error::Revoked)
            );
        }
        assert_eq!(owner.verify_cleanup(), Err(Error::Revoked));
        drop(owner);
        assert_eq!(ProcessOwner::acquire(&registry).err(), Some(Error::Revoked));
    }
}

#[test]
fn duplicate_completed_terminal_drop_revokes_previously_verified_owner() {
    let registry = Mutex::new(OwnerRegistry::empty());
    let owner = ProcessOwner::acquire(&registry).unwrap();
    owner.retain_cleanup_only().unwrap();
    owner.verified_terminal_drop(|| Ok(())).unwrap();
    assert_eq!(
        owner.verified_terminal_drop(|| panic!("duplicate verifier must not run")),
        Err(Error::Revoked)
    );
    drop(owner);
    assert_eq!(ProcessOwner::acquire(&registry).err(), Some(Error::Revoked));
}

#[test]
fn cleanup_unknown_registry_never_revives_through_retention_or_another_registry() {
    let registry = Mutex::new(OwnerRegistry::empty());
    let owner = ProcessOwner::acquire(&registry).unwrap();
    owner.uncertain();
    assert_eq!(owner.retain_cleanup_only(), Err(Error::Revoked));
    assert_eq!(owner.verify_cleanup(), Err(Error::Revoked));
    let foreign = Mutex::new(OwnerRegistry::empty());
    let foreign_owner = ProcessOwner::acquire(&foreign).unwrap();
    foreign_owner.retain_cleanup_only().unwrap();
    assert_eq!(foreign_owner.verify_cleanup(), Ok(()));
    assert_eq!(owner.verify_cleanup(), Err(Error::Revoked));
    foreign_owner.uncertain();
    assert_eq!(foreign_owner.retain_cleanup_only(), Err(Error::Revoked));
    assert_eq!(foreign_owner.verify_cleanup(), Err(Error::Revoked));
    drop(owner);
    assert_eq!(ProcessOwner::acquire(&registry).err(), Some(Error::Revoked));
}

#[test]
fn cleanup_foreign_scope_on_fenced_forward_attempt_still_poison_both_modes() {
    // Break caught: using the early live fence to ignore a different scope and
    // leaving the original cleanup channel eligible after that scope violation.
    for during_cleanup in [false, true] {
        let (deadline, _) = fixture(false, false, false);
        let pin = deadline.pin().unwrap();
        deadline.run(&7, || Err::<(), _>(19)).unwrap_err();
        let foreign_attempt = || {
            assert!(deadline
                .run::<(), ()>(&8, || panic!("foreign forward effect"))
                .is_err());
            assert!(!deadline.cleanup_eligible());
            assert_eq!(deadline.verify_pin(&pin, &7), Err(Error::Revoked));
            Ok::<_, ()>(())
        };
        if during_cleanup {
            assert!(deadline.run_cleanup(&7, foreign_attempt).is_err());
        } else {
            foreign_attempt().unwrap();
        }
        deny_both(&deadline);
    }
}

#[test]
fn cleanup_calling_query_and_original_pin_deny_at_fixed_deadline_before_worker_wakes() {
    let (deadline, external) = fixture(false, false, false);
    external.await_return.store(true, Ordering::SeqCst);
    let pin = deadline.pin().unwrap();
    let effects = std::cell::Cell::new(0);
    assert!(deadline
        .run_cleanup(&7, || {
            external.now.store(29_999, Ordering::SeqCst);
            assert!(deadline.cleanup_eligible());
            deadline.verify_call(&pin, &7).unwrap();
            external.now.store(30_000, Ordering::SeqCst);
            assert!(!deadline.cleanup_eligible());
            deadline.verify_pin(&pin, &7)?;
            effects.set(effects.get() + 1);
            Ok::<_, Error>(())
        })
        .is_err());
    assert_eq!(effects.get(), 0);
    deny_both(&deadline);
}

#[test]
fn cleanup_rundown_crossing_original_deadline_never_admits_late_cleanup() {
    // Break caught: joining a worker which exited early masks the budget being
    // exhausted while the exact stop ACK is still pending on the caller.
    let (deadline, external) = fixture(false, false, false);
    let deadline = Arc::new(deadline);
    external.hold_stop_ack.store(true, Ordering::SeqCst);
    let owner = deadline.clone();
    let thread = std::thread::spawn(move || owner.run(&7, || Err::<(), _>(19)));
    for _ in 0..1000 {
        if external.stop_ack_waiting.load(Ordering::SeqCst) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    let waiting = external.stop_ack_waiting.load(Ordering::SeqCst);
    // Give the actual worker time to exit before exhausting the rundown budget.
    // No state/guard is synthesized: eligibility must hold for either schedule.
    std::thread::sleep(std::time::Duration::from_millis(10));
    external.now.store(30_000, Ordering::SeqCst);
    external.hold_stop_ack.store(false, Ordering::SeqCst);
    external.wake.notify_all();
    assert_eq!(thread.join().unwrap(), Err(Failure::Native(19)));
    assert!(waiting);
    deny_both(&deadline);
    assert_eq!(external.terminated.load(Ordering::SeqCst), 0);
}

#[test]
fn cleanup_fresh_factual_pin_is_same_state_and_valid_only_during_actual_calling() {
    // Break caught: factual reads inside Closing fail solely because live was
    // revoked, or a fresh factual pin escapes the actual cleanup Calling gate.
    let (deadline, external) = fixture(false, false, false);
    let (foreign, secondary) = fixture(false, false, false);
    let original = deadline.pin().unwrap();
    let owner_thread = std::thread::current().id();
    deadline.run(&7, || Err::<(), _>(19)).unwrap_err();
    assert_eq!(deadline.pin().err(), Some(Error::Revoked));
    assert_eq!(deadline.verify_call(&original, &7), Err(Error::Revoked));
    assert_eq!(
        deadline.run::<(), ()>(&7, || panic!("fenced live before")),
        Err(Failure::Supervisor(Error::Revoked))
    );
    let factual = deadline
        .run_cleanup(&7, || {
            assert_eq!(std::thread::current().id(), owner_thread);
            let factual = deadline.pin()?;
            deadline.verify_call(&factual, &7)?;
            deadline.verify_call(&original, &7)?;
            assert!(Arc::ptr_eq(&original.state, &factual.state));
            assert_eq!(
                deadline.run::<(), ()>(&7, || panic!("fenced live during")),
                Err(Failure::Supervisor(Error::Revoked))
            );
            Ok::<_, Error>(factual)
        })
        .unwrap();
    assert_eq!(deadline.pin().err(), Some(Error::Revoked));
    for pin in [&original, &factual] {
        assert_eq!(deadline.verify_pin(pin, &7), Err(Error::Revoked));
        assert_eq!(deadline.verify_call(pin, &7), Err(Error::Revoked));
    }
    assert_eq!(
        deadline.run::<(), ()>(&7, || panic!("fenced live after")),
        Err(Failure::Supervisor(Error::Revoked))
    );
    deadline
        .run_cleanup(&7, || {
            deadline.verify_call(&original, &7)?;
            deadline.verify_call(&factual, &7)?;
            deadline.verify_call(&deadline.pin()?, &7)?;
            Ok::<_, Error>(())
        })
        .unwrap();
    // Equal scope/new owner cannot adopt a pin minted by the original Calling.
    assert_eq!(foreign.verify_pin(&factual, &7), Err(Error::Scope));
    deny_both(&foreign);
    assert_eq!(external.terminated.load(Ordering::SeqCst), 0);
    assert_eq!(secondary.terminated.load(Ordering::SeqCst), 0);
}

#[test]
fn cleanup_fresh_pin_denied_after_current_fault_or_fixed_deadline() {
    for fault in ["deadline", "cancel", "scope"] {
        let (deadline, external) = fixture(false, false, false);
        external.await_return.store(true, Ordering::SeqCst);
        let original = deadline.pin().unwrap();
        deadline.run(&7, || Err::<(), _>(19)).unwrap_err();
        assert!(deadline
            .run_cleanup(&7, || {
                let factual = deadline.pin().unwrap();
                deadline.verify_call(&factual, &7).unwrap();
                match fault {
                    "deadline" => external.now.store(30_000, Ordering::SeqCst),
                    "cancel" => deadline.cancel().unwrap(),
                    "scope" => assert_eq!(deadline.verify_pin(&original, &8), Err(Error::Scope)),
                    _ => unreachable!(),
                }
                assert_eq!(deadline.pin().err(), Some(Error::Revoked));
                assert_eq!(deadline.verify_pin(&original, &7), Err(Error::Revoked));
                assert_eq!(deadline.verify_pin(&factual, &7), Err(Error::Revoked));
                Ok::<_, ()>(())
            })
            .is_err());
        assert_eq!(deadline.pin().err(), Some(Error::Revoked));
        deny_both(&deadline);
    }
}
