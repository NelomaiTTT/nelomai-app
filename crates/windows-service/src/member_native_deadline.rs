//! Hard-call policy shared by the real Windows substrate and external-boundary
//! tests. No native effect/cleanup ACK is inferred from worker exit or Drop.
#![allow(dead_code)] // Main declares/integrates this module after sidecar handoff.

use std::sync::{Arc, Mutex};

pub(crate) const HARD_BUDGET_MS: u64 = 30_000;
const START_ACK_MS: u32 = 1_000;
const WATCHDOG_POLL_MS: u32 = 1_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    Revoked,
    Scope,
    Reentrant,
    Start,
    Worker,
    Deadline,
    Cancelled,
    Native,
    Unwind,
}
pub(crate) type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Wait {
    Signaled,
    Timeout,
}

/// ONLY the slow Win32/event/process boundary. No successful defaults or
/// caller-provided boolean authority. Concrete Windows construction privately
/// captures the authenticated CURRENT process; there is no target-PID API.
pub(crate) trait Kernel: Send + Sync + 'static {
    fn now_ms(&self) -> u64;
    fn signal_ready(&self) -> Result<()>;
    fn wait_ready(&self, timeout_ms: u32) -> Result<Wait>;
    fn signal_stop(&self) -> Result<()>;
    fn wait_stop(&self, timeout_ms: u32) -> Result<Wait>;
    fn terminate_current(&self) -> Result<()>;
}
pub(crate) trait Factory {
    type Kernel: Kernel;
    fn create(&mut self) -> Result<Self::Kernel>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Idle,
    Starting,
    Armed,
    Calling,
    Completing,
    Closed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Returned {
    Acknowledged,
    Unknown,
}
enum Termination {
    Unattempted,
    Attempted,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    Live,
    Cleanup,
}
struct State {
    sequence: u64,
    phase: Phase,
    deadline: u64,
    returned: Option<Returned>,
    revoked: Option<Error>,
    termination: Termination,
    mode: Mode,
    // Permanent uncertainty is distinct from permanent forward revocation.
    // Native Err alone can become quiescent only after the SAME worker joins
    // and its stop signal ACK succeeds. Nothing clears either revocation.
    blocked: Option<Error>,
    quiescent: bool,
}
impl State {
    fn deny(&mut self, reason: Error) {
        self.revoked.get_or_insert(reason);
        self.blocked.get_or_insert(reason);
        self.quiescent = false;
    }
    fn call_error(&self) -> Option<Error> {
        self.blocked.or_else(|| {
            if self.mode == Mode::Live {
                self.revoked
            } else {
                None
            }
        })
    }
    fn cleanup_eligible(&self) -> bool {
        self.quiescent
            && matches!(self.phase, Phase::Idle | Phase::Closed)
            && self.blocked.is_none()
            && matches!(self.termination, Termination::Unattempted)
            && matches!(self.revoked, None | Some(Error::Native | Error::Revoked))
    }
}
pub(crate) struct Deadline<S, F: Factory> {
    scope: S,
    state: Arc<Mutex<State>>,
    factory: Mutex<F>,
    active: Mutex<Option<Arc<F::Kernel>>>,
}
pub(crate) struct ReadPin<S> {
    scope: S,
    state: Arc<Mutex<State>>,
}
/// Only an actual Calling window can mint this sequence-bound factual pin.
/// Retaining it across calls never authorizes the next equal-scope operation.
pub(crate) struct TransactionCallPin<S> {
    original: ReadPin<S>,
    sequence: u64,
}
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Failure<E> {
    Supervisor(Error),
    Native(E),
}

enum OwnerPhase {
    Unclaimed,
    Held,
    CleanupOnly,
    Poisoned,
}
/// Serialization/revocation bookkeeping only, never authentication authority.
/// Native construction must independently verify actual RuntimeRead first.
pub(crate) struct OwnerRegistry {
    phase: OwnerPhase,
}
impl OwnerRegistry {
    pub(crate) const fn empty() -> Self {
        Self {
            phase: OwnerPhase::Unclaimed,
        }
    }
}
pub(crate) struct ProcessOwner<'a> {
    registry: &'a Mutex<OwnerRegistry>,
    uncertain: std::cell::Cell<bool>,
    terminal_attempted: std::cell::Cell<bool>,
    terminal_quiescent: std::cell::Cell<bool>,
}
impl<'a> ProcessOwner<'a> {
    pub(crate) fn acquire(registry: &'a Mutex<OwnerRegistry>) -> Result<Self> {
        let mut state = registry.lock().map_err(|_| Error::Worker)?;
        match state.phase {
            OwnerPhase::Held | OwnerPhase::CleanupOnly => return Err(Error::Reentrant),
            OwnerPhase::Poisoned => return Err(Error::Revoked),
            OwnerPhase::Unclaimed => state.phase = OwnerPhase::Held,
        }
        Ok(Self {
            registry,
            uncertain: std::cell::Cell::new(false),
            terminal_attempted: std::cell::Cell::new(false),
            terminal_quiescent: std::cell::Cell::new(false),
        })
    }
    pub(crate) fn verify(&self) -> Result<()> {
        let state = self.registry.lock().map_err(|_| Error::Worker)?;
        if self.uncertain.get() || !matches!(state.phase, OwnerPhase::Held) {
            Err(Error::Revoked)
        } else {
            Ok(())
        }
    }
    /// Irreversibly retain this SAME lease for cleanup bookkeeping only. This
    /// restriction supplies no timing or native operation permission.
    pub(crate) fn retain_cleanup_only(&self) -> Result<()> {
        let mut state = self.registry.lock().map_err(|_| Error::Worker)?;
        if self.uncertain.get()
            || !matches!(state.phase, OwnerPhase::Held | OwnerPhase::CleanupOnly)
        {
            return Err(Error::Revoked);
        }
        state.phase = OwnerPhase::CleanupOnly;
        Ok(())
    }
    /// Lease retention only. The caller must also check the SAME supervisor's
    /// actual Cleanup Calling pin and independently authenticated native proof.
    pub(crate) fn verify_cleanup(&self) -> Result<()> {
        let state = self.registry.lock().map_err(|_| Error::Worker)?;
        if self.uncertain.get() || !matches!(state.phase, OwnerPhase::CleanupOnly) {
            Err(Error::Revoked)
        } else {
            Ok(())
        }
    }
    pub(crate) fn uncertain(&self) {
        self.uncertain.set(true);
        if let Ok(mut registry) = self.registry.lock() {
            registry.phase = OwnerPhase::Poisoned;
        }
    }
    /// Drop bookkeeping only. Native composition must verify the SAME actual
    /// whole terminal ACK; this never re-arms this owner's forward lifetime.
    pub(crate) fn verified_terminal_drop(&self, verify: impl FnOnce() -> Result<()>) -> Result<()> {
        struct Attempt<'a, 'b> {
            owner: &'a ProcessOwner<'b>,
            success: bool,
        }
        impl Drop for Attempt<'_, '_> {
            fn drop(&mut self) {
                if !self.success {
                    self.owner.uncertain();
                }
            }
        }
        if self.terminal_attempted.replace(true) {
            self.uncertain();
            return Err(Error::Revoked);
        }
        let mut attempt = Attempt {
            owner: self,
            success: false,
        };
        self.verify_cleanup()?;
        verify()?;
        self.verify_cleanup()?;
        self.terminal_quiescent.set(true);
        attempt.success = true;
        Ok(())
    }
}
impl Drop for ProcessOwner<'_> {
    fn drop(&mut self) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.phase = if self.uncertain.get()
                || matches!(registry.phase, OwnerPhase::Poisoned)
                || (matches!(registry.phase, OwnerPhase::CleanupOnly)
                    && !self.terminal_quiescent.get())
            {
                OwnerPhase::Poisoned
            } else {
                OwnerPhase::Unclaimed
            };
        }
    }
}

impl<S: Clone + Eq, F: Factory> Deadline<S, F> {
    pub(crate) fn new(scope: S, factory: F) -> Self {
        Self {
            scope,
            factory: Mutex::new(factory),
            active: Mutex::new(None),
            state: Arc::new(Mutex::new(State {
                sequence: 0,
                phase: Phase::Idle,
                deadline: 0,
                returned: None,
                revoked: None,
                termination: Termination::Unattempted,
                mode: Mode::Live,
                blocked: None,
                quiescent: true,
            })),
        }
    }
    /// A factual read retains this SAME state, never native effect authority.
    /// After live revocation it can be minted only within eligible actual
    /// Cleanup Calling; idle cleanup eligibility cannot grant a new read pin.
    pub(crate) fn pin(&self) -> Result<ReadPin<S>> {
        let state = self.state.lock().map_err(|_| Error::Worker)?;
        if state.blocked.is_some() || (state.revoked.is_some() && !self.cleanup_calling(&state)) {
            return Err(Error::Revoked);
        }
        Ok(ReadPin {
            scope: self.scope.clone(),
            state: self.state.clone(),
        })
    }
    pub(crate) fn verify_pin(&self, pin: &ReadPin<S>, scope: &S) -> Result<()> {
        if !Arc::ptr_eq(&self.state, &pin.state) || pin.scope != self.scope || *scope != self.scope
        {
            self.revoke(Error::Scope);
            return Err(Error::Scope);
        }
        let state = self.state.lock().map_err(|_| Error::Worker)?;
        if state.blocked.is_some() || (state.revoked.is_some() && !self.cleanup_calling(&state)) {
            return Err(Error::Revoked);
        }
        Ok(())
    }
    pub(crate) fn verify_call(&self, pin: &ReadPin<S>, scope: &S) -> Result<()> {
        self.verify_pin(pin, scope)?;
        let result = (|| {
            let state = self.state.lock().map_err(|_| Error::Worker)?;
            if state.call_error().is_some()
                || state.phase != Phase::Calling
                || state.returned.is_some()
            {
                return Err(Error::Revoked);
            }
            let active = self.active.lock().map_err(|_| Error::Worker)?;
            let kernel = active.as_ref().ok_or(Error::Start)?;
            if kernel.now_ms() >= state.deadline {
                return Err(Error::Deadline);
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.revoke(error);
        }
        result
    }
    /// Read-only transaction timing fence. This checks only THIS original
    /// supervisor's in-flight state and clock; it cannot arm a call, signal an
    /// event, cancel a worker, authenticate a runtime, or grant native effects.
    /// The enclosing native owner must authenticate before/after the private
    /// transaction and irreversibly revoke its write attempt on any error.
    pub(crate) fn verify_call_state_only(&self, pin: &ReadPin<S>, scope: &S) -> Result<()> {
        if !Arc::ptr_eq(&self.state, &pin.state) || pin.scope != self.scope || *scope != self.scope
        {
            return Err(Error::Scope);
        }
        let state = self.state.lock().map_err(|_| Error::Worker)?;
        if state.call_error().is_some() || state.phase != Phase::Calling || state.returned.is_some()
        {
            return Err(Error::Revoked);
        }
        let active = self.active.lock().map_err(|_| Error::Worker)?;
        let kernel = active.as_ref().ok_or(Error::Start)?;
        if kernel.now_ms() >= state.deadline {
            return Err(Error::Deadline);
        }
        Ok(())
    }
    pub(crate) fn transaction_pin(
        &self,
        original: &ReadPin<S>,
        scope: &S,
    ) -> Result<TransactionCallPin<S>> {
        self.verify_call_state_only(original, scope)?;
        let state = self.state.lock().map_err(|_| Error::Worker)?;
        if state.phase != Phase::Calling || state.call_error().is_some() || state.returned.is_some()
        {
            return Err(Error::Revoked);
        }
        Ok(TransactionCallPin {
            original: ReadPin {
                scope: original.scope.clone(),
                state: original.state.clone(),
            },
            sequence: state.sequence,
        })
    }
    pub(crate) fn verify_transaction_call(
        &self,
        pin: &TransactionCallPin<S>,
        scope: &S,
    ) -> Result<()> {
        self.verify_call_state_only(&pin.original, scope)?;
        let state = self.state.lock().map_err(|_| Error::Worker)?;
        if state.sequence != pin.sequence {
            return Err(Error::Scope);
        }
        if state.phase != Phase::Calling || state.call_error().is_some() || state.returned.is_some()
        {
            return Err(Error::Revoked);
        }
        Ok(())
    }
    fn revoke(&self, reason: Error) {
        if let Ok(mut state) = self.state.lock() {
            state.deny(reason);
        }
        if let Ok(active) = self.active.lock() {
            if let Some(kernel) = active.as_ref() {
                let _ = kernel.signal_stop();
            }
        }
    }
    pub(crate) fn cancel(&self) -> Result<()> {
        let revoked = self
            .state
            .lock()
            .map_err(|_| Error::Worker)?
            .revoked
            .is_some();
        let cleanup_calling = {
            let state = self.state.lock().map_err(|_| Error::Worker)?;
            state.mode == Mode::Cleanup && state.phase == Phase::Calling
        };
        self.revoke(Error::Cancelled);
        if revoked && !cleanup_calling {
            Err(Error::Revoked)
        } else {
            Ok(())
        }
    }
    /// Cleanup timing only; native entry must authenticate its original Closing
    /// operation independently before and during the actual synchronous call.
    pub(crate) fn run_cleanup<T, E>(
        &self,
        scope: &S,
        call: impl FnOnce() -> std::result::Result<T, E>,
    ) -> std::result::Result<T, Failure<E>> {
        self.run_mode(Mode::Cleanup, scope, call)
    }
    /// Read-only timing evidence for pre-entry and Calling reauthentication;
    /// never native Closing/effect authority. Active live calls, startup,
    /// completion, late returns and every uncertain rundown are denied.
    pub(crate) fn cleanup_eligible(&self) -> bool {
        self.state
            .lock()
            .map(|state| state.cleanup_eligible() || self.cleanup_calling(&state))
            .unwrap_or(false)
    }
    fn cleanup_calling(&self, state: &State) -> bool {
        state.mode == Mode::Cleanup
            && state.phase == Phase::Calling
            && state.returned.is_none()
            && state.blocked.is_none()
            && matches!(state.termination, Termination::Unattempted)
            && self
                .active
                .lock()
                .map(|active| {
                    active
                        .as_ref()
                        .is_some_and(|kernel| kernel.now_ms() < state.deadline)
                })
                .unwrap_or(false)
    }
    /// `call` must be the integrating gate's actual synchronous operation. Its
    /// protected pending intent/static blocks MUST already be prepared. Worker
    /// exit proves only watchdog rundown, never effects or cleanup of that call.
    /// The closure runs here, not on the watchdog: it can borrow the actual
    /// owner's non-Send obligation slot and retain an opaque native ACK BEFORE
    /// returning. An error after ACK may discard T; do not put the only receipt
    /// in T or interpret Err as absence of native effects.
    pub(crate) fn run<T, E>(
        &self,
        scope: &S,
        call: impl FnOnce() -> std::result::Result<T, E>,
    ) -> std::result::Result<T, Failure<E>> {
        self.run_mode(Mode::Live, scope, call)
    }
    fn run_mode<T, E>(
        &self,
        mode: Mode,
        scope: &S,
        call: impl FnOnce() -> std::result::Result<T, E>,
    ) -> std::result::Result<T, Failure<E>> {
        let begin = (|| {
            let mut state = self.state.lock().map_err(|_| Error::Worker)?;
            // A fenced live retry never starts a worker or erases prior cleanup
            // evidence. Actual reentry/foreign reads still poison both modes.
            if mode == Mode::Live && state.revoked.is_some() {
                if *scope != self.scope {
                    state.deny(Error::Scope);
                }
                return Err(Error::Revoked);
            }
            if *scope != self.scope {
                state.deny(Error::Scope);
                return Err(Error::Scope);
            }
            if state.blocked.is_some() {
                return Err(Error::Revoked);
            }
            if !matches!(state.phase, Phase::Idle | Phase::Closed) {
                state.deny(Error::Reentrant);
                return Err(Error::Reentrant);
            }
            if mode == Mode::Cleanup {
                if !state.cleanup_eligible() {
                    state.deny(Error::Revoked);
                    return Err(Error::Revoked);
                }
                state.revoked.get_or_insert(Error::Revoked);
            }
            state.sequence = state.sequence.checked_add(1).ok_or(Error::Worker)?;
            state.mode = mode;
            state.phase = Phase::Starting;
            state.returned = None;
            state.quiescent = false;
            Ok(state.sequence)
        })();
        let sequence = match begin {
            Ok(s) => s,
            Err(e) => {
                if e != Error::Revoked {
                    self.revoke(e);
                }
                return Err(Failure::Supervisor(e));
            }
        };
        let result = self.run_started(sequence, call);
        if let Err(Failure::Supervisor(error)) = &result {
            self.revoke(*error);
        }
        result
    }
    fn run_started<T, E>(
        &self,
        sequence: u64,
        call: impl FnOnce() -> std::result::Result<T, E>,
    ) -> std::result::Result<T, Failure<E>> {
        let kernel = Arc::new(
            self.factory
                .lock()
                .map_err(|_| Failure::Supervisor(Error::Worker))?
                .create()
                .map_err(Failure::Supervisor)?,
        );
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| Failure::Supervisor(Error::Worker))?;
            if state.call_error().is_some() || state.sequence != sequence {
                return Err(Failure::Supervisor(Error::Revoked));
            }
            state.deadline = kernel
                .now_ms()
                .checked_add(HARD_BUDGET_MS)
                .ok_or(Failure::Supervisor(Error::Worker))?;
        }
        *self
            .active
            .lock()
            .map_err(|_| Failure::Supervisor(Error::Worker))? = Some(kernel.clone());
        let thread_state = self.state.clone();
        let thread_kernel = kernel.clone();
        let worker = std::thread::Builder::new()
            .name("nelomai-native-deadline".into())
            .spawn(move || worker_entry(&thread_state, &*thread_kernel, sequence))
            .map_err(|_| Failure::Supervisor(Error::Start))?;
        let mut guard = CallGuard {
            state: self.state.clone(),
            kernel,
            sequence,
            worker: Some(worker),
        };
        let ready = guard.kernel.wait_ready(START_ACK_MS);
        if ready != Ok(Wait::Signaled) {
            let reason = self
                .state
                .lock()
                .ok()
                .and_then(|s| s.call_error())
                .unwrap_or(Error::Start);
            guard.returned(Returned::Unknown, Some(reason));
            let _ = guard.finish();
            self.close_active(sequence).map_err(Failure::Supervisor)?;
            return Err(Failure::Supervisor(reason));
        }
        let permit = (|| {
            let mut state = self.state.lock().map_err(|_| Error::Worker)?;
            if let Some(e) = state.call_error() {
                return Err(e);
            }
            if state.sequence != sequence || state.phase != Phase::Armed {
                return Err(Error::Start);
            }
            if guard.kernel.now_ms() >= state.deadline {
                state.deny(Error::Deadline);
                return Err(Error::Deadline);
            }
            state.phase = Phase::Calling;
            Ok(())
        })();
        if let Err(reason) = permit {
            guard.returned(Returned::Unknown, Some(reason));
            let _ = guard.finish();
            self.close_active(sequence).map_err(Failure::Supervisor)?;
            return Err(Failure::Supervisor(reason));
        }
        // Catch only to signal/rundown our worker; preserve the caller's unwind.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(call));
        let (returned, reason) = match &outcome {
            Ok(Ok(_)) => (Returned::Acknowledged, None),
            Ok(Err(_)) => (Returned::Unknown, Some(Error::Native)),
            Err(_) => (Returned::Unknown, Some(Error::Unwind)),
        };
        guard.returned(returned, reason);
        let worker_result = guard.finish();
        self.close_active(sequence).map_err(Failure::Supervisor)?;
        let revoked = self
            .state
            .lock()
            .map_err(|_| Failure::Supervisor(Error::Worker))?
            .call_error();
        match outcome {
            Err(panic) => std::panic::resume_unwind(panic),
            Ok(Err(error)) => Err(Failure::Native(error)),
            Ok(Ok(value)) => {
                if let Some(e) = revoked {
                    return Err(Failure::Supervisor(e));
                }
                worker_result.map_err(Failure::Supervisor)?;
                Ok(value)
            }
        }
    }
    fn close_active(&self, sequence: u64) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| Error::Worker)?;
        if state.sequence != sequence || state.phase != Phase::Completing {
            state.deny(Error::Worker);
            return Err(Error::Worker);
        }
        *self.active.lock().map_err(|_| Error::Worker)? = None;
        // Publish reusable quiescence only after retiring the exact active
        // worker/kernel slot. Another call cannot replace it before this point.
        state.phase = Phase::Closed;
        Ok(())
    }
}

struct CallGuard<K: Kernel> {
    state: Arc<Mutex<State>>,
    kernel: Arc<K>,
    sequence: u64,
    worker: Option<std::thread::JoinHandle<Result<()>>>,
}
impl<K: Kernel> CallGuard<K> {
    fn returned(&mut self, returned: Returned, reason: Option<Error>) {
        if let Ok(mut state) = self.state.lock() {
            if state.sequence != self.sequence || state.returned.is_some() {
                state.deny(Error::Worker);
                return;
            }
            if self.kernel.now_ms() >= state.deadline {
                state.deny(Error::Deadline);
            }
            if let Some(e) = reason {
                if e == Error::Native {
                    state.revoked.get_or_insert(e);
                } else {
                    state.deny(e);
                }
            }
            state.returned = Some(returned);
            state.phase = Phase::Completing;
        }
    }
    fn finish(&mut self) -> Result<()> {
        if self.worker.is_none() {
            if let Ok(mut state) = self.state.lock() {
                state.deny(Error::Worker);
            }
            return Err(Error::Worker);
        }
        // Even a lost signal ACK denies success. Keep the real thread tracked
        // and join it exactly once; never detach a runnable targeting worker.
        let signal = self.kernel.signal_stop();
        if signal.is_err() {
            if let Ok(mut state) = self.state.lock() {
                state.deny(Error::Worker);
            }
        }
        let worker = self.worker.take().ok_or(Error::Worker)?;
        let exit = worker.join().map_err(|_| Error::Worker)?;
        let mut state = self.state.lock().map_err(|_| Error::Worker)?;
        if state.sequence != self.sequence {
            state.deny(Error::Worker);
            return Err(Error::Worker);
        }
        if let Err(e) = exit {
            state.deny(e);
        }
        if self.kernel.now_ms() >= state.deadline {
            state.deny(Error::Deadline);
        }
        state.quiescent = signal.is_ok()
            && exit.is_ok()
            && state.returned.is_some()
            && state.blocked.is_none()
            && matches!(state.termination, Termination::Unattempted);
        signal?;
        exit
    }
}
impl<K: Kernel> Drop for CallGuard<K> {
    fn drop(&mut self) {
        if self.worker.is_some() {
            self.returned(Returned::Unknown, Some(Error::Unwind));
            let _ = self.finish();
        }
    }
}

fn worker_entry<K: Kernel>(state: &Arc<Mutex<State>>, kernel: &K, sequence: u64) -> Result<()> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        worker_loop(state, kernel, sequence)
    })) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => worker_error(state, kernel, error),
        Err(_) => worker_error(state, kernel, Error::Worker),
    }
}
fn worker_error<K: Kernel>(state: &Mutex<State>, kernel: &K, error: Error) -> Result<()> {
    let kill = {
        let mut s = state.lock().map_err(|_| Error::Worker)?;
        s.deny(error);
        s.returned.is_none() && s.phase == Phase::Calling
    };
    if kill {
        terminate_once(state, kernel)?;
    }
    Err(error)
}
fn worker_loop<K: Kernel>(state: &Mutex<State>, kernel: &K, sequence: u64) -> Result<()> {
    {
        let mut s = state.lock().map_err(|_| Error::Worker)?;
        if s.sequence != sequence || s.phase != Phase::Starting || s.call_error().is_some() {
            return Err(Error::Start);
        }
        s.phase = Phase::Armed;
    }
    kernel.signal_ready()?;
    loop {
        let decision = {
            let mut s = state.lock().map_err(|_| Error::Worker)?;
            if s.sequence != sequence {
                return Err(Error::Worker);
            }
            if kernel.now_ms() >= s.deadline {
                s.deny(Error::Deadline);
            }
            if let Some(error) = s.blocked {
                Err(error)
            } else if s.returned.is_some() {
                return Ok(()); // Call returned; only caller interprets its ACK.
            } else if let Some(e) = s.call_error() {
                Err(e)
            } else {
                Ok(s.deadline
                    .saturating_sub(kernel.now_ms())
                    .min(u32::MAX as u64) as u32)
            }
        };
        match decision {
            Err(e) => {
                // worker_entry checks actual Calling + no return before any
                // termination. Late completion remains denied, but a returned
                // call/startup failure never kills a quiescent original owner.
                return Err(e);
            }
            Ok(remaining) => {
                // Windows 8+ event waits exclude low-power time. Recheck the
                // fixed monotonic deadline after short waits rather than
                // spending the entire pre-suspend remainder after resume.
                // This never renews the call budget or supplies an effect ACK.
                kernel.wait_stop(remaining.min(WATCHDOG_POLL_MS))?;
            }
        }
    }
}

fn terminate_once<K: Kernel>(state: &Mutex<State>, kernel: &K) -> Result<()> {
    let mut s = state.lock().map_err(|_| Error::Worker)?;
    if s.phase != Phase::Calling
        || s.returned.is_some()
        || matches!(s.termination, Termination::Attempted)
    {
        return Ok(());
    }
    s.termination = Termination::Attempted;
    #[cfg(test)]
    eprintln!(
        "native watchdog unknown outcome: reason={:?} phase={:?} tick={} deadline={}",
        s.blocked,
        s.phase,
        kernel.now_ms(),
        s.deadline
    );
    // Serialize the FINAL boundary with returned() publication, not merely an
    // earlier decision. If completion wins this lock, it suppresses termination;
    // if the watchdog wins, the still-inflight call remains UNKNOWN. The actual
    // native target is ONLY this current process; success does not return there.
    kernel.terminate_current()
}

#[cfg(test)]
#[path = "member_native_deadline_tests.rs"]
mod tests;
