use super::*;
use crate::member_native_deadline::{self as policy, Kernel, Wait};
use std::sync::{Arc, Condvar, Mutex};

#[derive(Clone, Default)]
struct Native {
    events: Arc<(Mutex<(bool, bool)>, Condvar)>,
}
impl Kernel for Native {
    fn now_ms(&self) -> u64 {
        1
    }
    fn signal_ready(&self) -> policy::Result<()> {
        self.events.0.lock().unwrap().0 = true;
        self.events.1.notify_all();
        Ok(())
    }
    fn wait_ready(&self, ms: u32) -> policy::Result<Wait> {
        self.wait(ms, true)
    }
    fn signal_stop(&self) -> policy::Result<()> {
        self.events.0.lock().unwrap().1 = true;
        self.events.1.notify_all();
        Ok(())
    }
    fn wait_stop(&self, ms: u32) -> policy::Result<Wait> {
        self.wait(ms, false)
    }
    fn terminate_current(&self) -> policy::Result<()> {
        panic!("normal test must not terminate")
    }
}
impl Native {
    fn wait(&self, ms: u32, ready: bool) -> policy::Result<Wait> {
        let (guard, _) = self
            .events
            .1
            .wait_timeout_while(
                self.events.0.lock().unwrap(),
                std::time::Duration::from_millis(ms as u64),
                |state| !(if ready { state.0 } else { state.1 }),
            )
            .unwrap();
        Ok(if if ready { guard.0 } else { guard.1 } {
            Wait::Signaled
        } else {
            Wait::Timeout
        })
    }
}
struct Boundary;
impl Factory for Boundary {
    type Kernel = Native;
    fn create(&mut self) -> policy::Result<Native> {
        Ok(Native::default())
    }
}
#[test]
fn cold_call_is_current_bounded_and_one_shot() {
    let owner = ColdCall::new(7u8, Boundary);
    let reads = Cell::new(0);
    assert_eq!(
        owner
            .run(
                &7,
                || Ok(()),
                || owner.with_call(&7, || {
                    reads.set(reads.get() + 1);
                    Ok(11)
                })
            )
            .unwrap(),
        11
    );
    assert_eq!(reads.get(), 1);
    assert!(owner.with_call(&7, || Ok(())).is_err());
    assert!(owner.run(&7, || Ok(()), || Ok(())).is_err());
}
#[test]
fn cold_call_wrong_scope_error_reentry_and_unwind_are_sticky() {
    for fault in 0..4 {
        let owner = ColdCall::new(7u8, Boundary);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            owner.run(
                &7,
                || Ok(()),
                || {
                    match fault {
                        0 => {
                            let _ = owner.with_call(&8, || Ok(()));
                        }
                        1 => {
                            let _ = owner.with_call(&7, || Err::<(), _>(denied()));
                        }
                        2 => {
                            let _ = owner.run(&7, || Ok(()), || Ok(()));
                        }
                        _ => {
                            owner.with_call(&7, || -> io::Result<()> { panic!("unknown read") })?;
                        }
                    }
                    Ok(())
                },
            )
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert!(owner.run(&7, || Ok(()), || Ok(())).is_err());
    }
}
#[test]
fn cold_authentication_error_cannot_issue_or_preserve_call() {
    let owner = ColdCall::new(7u8, Boundary);
    let invoked = Cell::new(false);
    assert!(owner
        .run(
            &7,
            || Err(denied()),
            || {
                invoked.set(true);
                Ok(())
            }
        )
        .is_err());
    assert!(!invoked.get());
    assert!(owner.run(&7, || Ok(()), || Ok(())).is_err());
}

#[test]
fn cold_post_result_authentication_loss_is_not_completion_or_retry_authority() {
    for fail_at in 2..=4 {
        let owner = ColdCall::new(7u8, Boundary);
        let checks = Cell::new(0);
        let returned = Cell::new(false);
        let result = owner.run(
            &7,
            || {
                checks.set(checks.get() + 1);
                if checks.get() == fail_at {
                    Err(denied())
                } else {
                    Ok(())
                }
            },
            || {
                returned.set(true);
                Ok(13)
            },
        );
        assert!(result.is_err());
        assert_eq!(returned.get(), fail_at >= 3);
        assert!(owner.run(&7, || Ok(()), || Ok(())).is_err());
    }
}
