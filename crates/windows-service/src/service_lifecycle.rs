//! SCM lifecycle policy, with native status publication injected at the boundary.
use crate::ServiceError;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

/// The SCM invokes its FnMut control handler serially. Keep its first watchdog
/// alive across the service loop; never wait for the dispatcher in the handler.
pub(crate) struct StopRequest<T> {
    stopping: Arc<AtomicBool>,
    watchdog: OnceLock<Result<T, ServiceError>>,
}

impl<T> StopRequest<T> {
    pub(crate) fn new(stopping: Arc<AtomicBool>) -> Self {
        Self {
            stopping,
            watchdog: OnceLock::new(),
        }
    }

    pub(crate) fn handle(
        &self,
        control: u32,
        arm: impl FnOnce() -> Result<T, ServiceError>,
        wake: impl FnOnce(),
    ) -> bool {
        // Raw SERVICE_CONTROL_* values at the portable SCM policy boundary.
        match control {
            4 => true, // INTERROGATE
            1 | 5 | 15 => {
                // STOP / SHUTDOWN / PRESHUTDOWN
                if !self.stopping.load(Ordering::Acquire) {
                    // Publish the guard before the flag so even an immediate
                    // clean stop can complete the first watchdog.
                    let _ = self.watchdog.set(arm());
                    self.stopping.store(true, Ordering::Release);
                    wake();
                }
                true
            }
            _ => false,
        }
    }

    pub(crate) fn finish(&self, complete: impl FnOnce(&T)) -> Result<(), ServiceError> {
        if let Some(Ok(watchdog)) = self.watchdog.get() {
            complete(watchdog);
        }
        self.arm_result()
    }

    pub(crate) fn arm_result(&self) -> Result<(), ServiceError> {
        match self.watchdog.get() {
            Some(Err(error)) => Err(error.clone()),
            _ => Ok(()),
        }
    }
}

/// Wait under one absolute deadline. A stop watchdog can retry the existing
/// native pipe wakeup until accept observes the stop flag, including a wakeup
/// sent before the pipe existed. Ordinary request watchdogs do not poll.
pub(crate) fn wait_for_completion(
    completed: &(std::sync::Mutex<bool>, std::sync::Condvar),
    timeout: std::time::Duration,
    mut wake: Option<impl FnMut()>,
) -> bool {
    use std::time::{Duration, Instant};
    let deadline = Instant::now() + timeout;
    let (lock, condition) = completed;
    let mut guard = lock.lock().unwrap_or_else(|p| p.into_inner());
    loop {
        if *guard {
            return true;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        let step = if wake.is_some() {
            remaining.min(Duration::from_millis(100))
        } else {
            remaining
        };
        let (next, _) = condition
            .wait_timeout(guard, step)
            .unwrap_or_else(|p| p.into_inner());
        guard = next;
        if *guard {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        if let Some(wake) = &mut wake {
            drop(guard);
            wake();
            guard = lock.lock().unwrap_or_else(|p| p.into_inner());
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Status {
    StartPending,
    Running,
    StopPending,
    Stopped { failed: bool },
}

pub(crate) fn stop(
    report: &mut dyn FnMut(Status) -> Result<(), ServiceError>,
    cleanup: impl FnOnce() -> Result<(), ServiceError>,
) -> Result<(), ServiceError> {
    let pending = report(Status::StopPending);
    // A status publication failure must not prevent owned cleanup. Preserve a
    // cleanup failure if both operations fail, as run() does for final status.
    cleanup().and(pending)
}

pub(crate) fn run(
    mut report: impl FnMut(Status) -> Result<(), ServiceError>,
    serve: impl FnOnce(&mut dyn FnMut(Status) -> Result<(), ServiceError>) -> Result<(), ServiceError>,
) -> Result<(), ServiceError> {
    let result = report(Status::StartPending).and_then(|()| serve(&mut report));
    let stopped = report(Status::Stopped {
        failed: result.is_err(),
    });
    // Preserve the startup/cleanup error even if SCM also rejects the final
    // publication. A successful run still reports a publication failure.
    result.and(stopped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    #[test]
    fn shutdown_notifications_signal_stop_while_dispatcher_is_busy() {
        // Break caught: OS shutdown is acknowledged/ignored without asking the
        // service loop to run the existing serialized dispatcher Stop.
        for control in [5, 15] {
            // SERVICE_CONTROL_SHUTDOWN / PRESHUTDOWN
            let stopping = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let stop = Arc::new(StopRequest::new(Arc::clone(&stopping)));
            let owner = Arc::new(Mutex::new(()));
            let busy = owner.lock().unwrap();
            let owner_for_handler = Arc::clone(&owner);
            let (returned, receive) = std::sync::mpsc::channel();
            let handler = std::thread::spawn(move || {
                let mut woke = false;
                let acknowledged = stop.handle(
                    control,
                    || {
                        assert!(owner_for_handler.try_lock().is_err());
                        Ok(())
                    },
                    || woke = true,
                );
                returned.send((acknowledged, woke)).unwrap();
            });
            let result = receive.recv_timeout(std::time::Duration::from_secs(2));
            drop(busy);
            handler.join().unwrap();
            assert_eq!(result.unwrap(), (true, true));
            assert!(stopping.load(Ordering::Acquire));
        }
    }

    #[test]
    fn duplicate_stop_notifications_keep_one_watchdog_and_one_wakeup() {
        // Break caught: a second notification resets the overall stop deadline
        // or queues another stop instead of retaining the first request.
        let stopping = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop = StopRequest::new(Arc::clone(&stopping));
        let armed = AtomicUsize::new(0);
        let woken = AtomicUsize::new(0);
        for control in [1, 15, 5, 1, 15] {
            assert!(stop.handle(
                control,
                || Ok(armed.fetch_add(1, Ordering::Relaxed)),
                || {
                    woken.fetch_add(1, Ordering::Relaxed);
                },
            ));
        }
        assert!(stopping.load(Ordering::Acquire));
        assert_eq!(armed.load(Ordering::Relaxed), 1);
        assert_eq!(woken.load(Ordering::Relaxed), 1);
        stop.finish(|first_guard| assert_eq!(*first_guard, 0))
            .unwrap();
    }

    #[test]
    fn interrogate_and_unsupported_controls_do_not_request_stop() {
        let stopping = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop = StopRequest::<()>::new(Arc::clone(&stopping));
        for (control, acknowledged) in [(4, true), (0, false), (2, false), (128, false)] {
            assert_eq!(
                stop.handle(
                    control,
                    || panic!("non-stop control cannot arm the stop watchdog"),
                    || panic!("non-stop control cannot wake the dispatcher"),
                ),
                acknowledged
            );
            assert!(!stopping.load(Ordering::Acquire));
        }
        stop.finish(|_| panic!("there is no stop watchdog"))
            .unwrap();
    }

    #[test]
    fn watchdog_failure_still_signals_stop_and_is_propagated() {
        let stopping = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop = StopRequest::<()>::new(Arc::clone(&stopping));
        let mut woke = false;
        assert!(stop.handle(
            15,
            || Err(ServiceError::Backend("cannot_start_watchdog".into())),
            || woke = true,
        ));
        assert!(stopping.load(Ordering::Acquire));
        assert!(woke);
        assert_eq!(
            stop.arm_result(),
            Err(ServiceError::Backend("cannot_start_watchdog".into()))
        );
        assert!(stop.handle(
            1,
            || panic!("failed watchdog initialization cannot reset the request"),
            || panic!("duplicate request cannot wake again"),
        ));
        assert_eq!(
            stop.finish(|_| panic!("there is no watchdog")),
            Err(ServiceError::Backend("cannot_start_watchdog".into()))
        );
    }

    #[test]
    fn stop_pending_is_reported_before_serialized_cleanup() {
        // Break caught: cleanup is entered while SCM still sees Running.
        let statuses = RefCell::new(Vec::new());
        stop(
            &mut |status| {
                statuses.borrow_mut().push(status);
                Ok(())
            },
            || {
                assert_eq!(statuses.borrow().as_slice(), [Status::StopPending]);
                Ok(())
            },
        )
        .unwrap();
    }

    #[test]
    fn stop_pending_publication_failure_does_not_skip_cleanup() {
        let mut cleaned = false;
        let result = stop(&mut |_| Err(ServiceError::InvalidRequest), || {
            cleaned = true;
            Ok(())
        });
        assert!(cleaned);
        assert_eq!(result, Err(ServiceError::InvalidRequest));
        assert_eq!(
            stop(&mut |_| Err(ServiceError::InvalidRequest), || Err(
                ServiceError::UnauthorizedClient
            ),),
            Err(ServiceError::UnauthorizedClient)
        );
    }

    #[test]
    fn startup_recovery_error_reports_failed_stopped() {
        let mut statuses = Vec::new();
        let result = run(
            |status| {
                statuses.push(status);
                Ok(())
            },
            |_| Err(ServiceError::Backend("dispatcher_recovery_pending".into())),
        );
        assert!(
            matches!(result, Err(ServiceError::Backend(ref code)) if code == "dispatcher_recovery_pending")
        );
        assert_eq!(
            statuses,
            [Status::StartPending, Status::Stopped { failed: true }]
        );
    }

    #[test]
    fn running_failure_and_clean_stop_have_distinct_exit_status() {
        for fail in [false, true] {
            let mut statuses = Vec::new();
            let result = run(
                |status| {
                    statuses.push(status);
                    Ok(())
                },
                |report| {
                    report(Status::Running)?;
                    if fail {
                        Err(ServiceError::InvalidRequest)
                    } else {
                        Ok(())
                    }
                },
            );
            assert_eq!(result.is_err(), fail);
            assert_eq!(
                statuses,
                [
                    Status::StartPending,
                    Status::Running,
                    Status::Stopped { failed: fail }
                ]
            );
        }
    }

    #[test]
    fn failed_start_pending_report_still_attempts_stopped_and_preserves_error() {
        let mut statuses = Vec::new();
        let result = run(
            |status| {
                statuses.push(status);
                if status == Status::StartPending {
                    Err(ServiceError::InvalidRequest)
                } else {
                    Err(ServiceError::UnauthorizedClient)
                }
            },
            |_| panic!("cannot serve after failed status publication"),
        );
        assert!(matches!(result, Err(ServiceError::InvalidRequest)));
        assert_eq!(
            statuses,
            [Status::StartPending, Status::Stopped { failed: true }]
        );
    }
    #[test]
    fn stop_wakeup_retries_a_pipe_that_did_not_exist_at_the_first_signal() {
        let state = (Mutex::new(false), std::sync::Condvar::new());
        let calls = std::cell::Cell::new(0);
        assert!(wait_for_completion(
            &state,
            std::time::Duration::from_millis(600),
            Some(|| {
                calls.set(calls.get() + 1);
                // The first signal preceded CreateNamedPipe; the second connects.
                if calls.get() == 2 {
                    *state.0.lock().unwrap() = true;
                    state.1.notify_all();
                }
            })
        ));
        assert_eq!(calls.get(), 2);
    }
    #[test]
    fn stop_wakeup_retains_one_deadline_and_does_not_wake_after_completion() {
        let state = (Mutex::new(false), std::sync::Condvar::new());
        let calls = std::cell::Cell::new(0);
        let start = std::time::Instant::now();
        assert!(!wait_for_completion(
            &state,
            std::time::Duration::from_millis(220),
            Some(|| calls.set(calls.get() + 1))
        ));
        assert!(calls.get() > 0);
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
        *state.0.lock().unwrap() = true;
        assert!(wait_for_completion(
            &state,
            std::time::Duration::from_secs(1),
            Some(|| panic!("completed watchdog woke a pipe"))
        ));
    }
}
