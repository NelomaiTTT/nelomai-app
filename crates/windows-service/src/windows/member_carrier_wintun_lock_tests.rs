use super::*;
use std::{cell::RefCell, collections::VecDeque, panic::AssertUnwindSafe, rc::Rc};

// These fixtures replace only kernel operations/time. Acquisition, security
// policy, cancellation, budget accounting and RAII are the production code.
#[derive(Default)]
struct Trace {
    events: Vec<String>,
    released: Vec<usize>,
    closed: Vec<usize>,
    waits: Vec<u32>,
    cleanup_failures: usize,
}
struct Handle(usize, Rc<RefCell<Trace>>);
impl Drop for Handle {
    fn drop(&mut self) {
        self.1.borrow_mut().closed.push(self.0);
    }
}
struct Fake<'a> {
    trace: Rc<RefCell<Trace>>,
    cancel: &'a AtomicBool,
    time: Duration,
    outcomes: VecDeque<(Wait, u64)>,
    security: Security,
    open_count: usize,
    fail_open: Option<usize>,
    fail_security: Option<usize>,
    fail_release: Option<usize>,
    fail_wait: bool,
    panic_security: Option<usize>,
    security_queries: usize,
    deny_identity_on_security: Option<usize>,
    deny_identity: bool,
    namespace_retries: usize,
    namespace_cost: u64,
    cancel_at: Option<&'static str>,
    panic_at: Option<&'static str>,
    backwards: bool,
}
fn strong() -> Security {
    Security {
        owner: Principal::System,
        protected: true,
        dacl: Some(vec![
            Ace {
                kind: 0,
                flags: 0,
                mask: 0x001f0001,
                principal: Principal::System,
            },
            Ace {
                kind: 0,
                flags: 0,
                mask: 0x001f0001,
                principal: Principal::Admins,
            },
        ]),
    }
}
impl<'a> Fake<'a> {
    fn new(cancel: &'a AtomicBool) -> Self {
        Self {
            trace: Rc::new(RefCell::new(Trace::default())),
            cancel,
            time: Duration::ZERO,
            outcomes: VecDeque::from([(Wait::Acquired, 0), (Wait::Acquired, 0)]),
            security: strong(),
            open_count: 0,
            fail_open: None,
            fail_security: None,
            fail_release: None,
            fail_wait: false,
            panic_security: None,
            security_queries: 0,
            deny_identity_on_security: None,
            deny_identity: false,
            namespace_retries: 0,
            namespace_cost: 0,
            cancel_at: None,
            panic_at: None,
            backwards: false,
        }
    }
    fn event(&mut self, name: &'static str) {
        self.trace.borrow_mut().events.push(name.into());
        if self.cancel_at == Some(name) {
            self.cancel.store(true, Ordering::Release);
        }
        assert_ne!(self.panic_at, Some(name), "injected kernel panic");
    }
}
impl Kernel for Fake<'_> {
    type Handle = Handle;
    fn now(&mut self) -> Duration {
        self.time
    }
    fn authenticate(&mut self, _: &AtomicBool) -> Result<()> {
        self.event("authenticate");
        if self.deny_identity {
            Err(Error::Conflict)
        } else {
            Ok(())
        }
    }
    fn namespace(&mut self, _: &AtomicBool) -> Result<bool> {
        self.event("namespace");
        self.time += Duration::from_millis(self.namespace_cost);
        if self.namespace_retries > 0 {
            self.namespace_retries -= 1;
            Ok(false)
        } else {
            Ok(true)
        }
    }
    fn open(&mut self, name: &'static str, _: &AtomicBool) -> Result<Handle> {
        self.open_count += 1;
        self.trace.borrow_mut().events.push(name.into());
        self.event("open");
        if self.fail_open == Some(self.open_count) {
            return Err(Error::Native);
        }
        Ok(Handle(self.open_count, self.trace.clone()))
    }
    fn security(&mut self, handle: &Handle, _: &AtomicBool) -> Result<Security> {
        self.event("security");
        self.security_queries += 1;
        if self.deny_identity_on_security == Some(self.security_queries) {
            self.deny_identity = true;
        }
        assert_ne!(self.panic_security, Some(handle.0), "security panic");
        if self.fail_security == Some(handle.0) {
            Err(Error::Native)
        } else {
            Ok(self.security.clone())
        }
    }
    fn wait(&mut self, _handle: &Handle, milliseconds: u32, _: &AtomicBool) -> Result<Wait> {
        self.event("wait");
        self.trace.borrow_mut().waits.push(milliseconds);
        if self.fail_wait {
            return Err(Error::Native);
        }
        let (outcome, cost) = self
            .outcomes
            .pop_front()
            .unwrap_or((Wait::Timeout, milliseconds as u64));
        if self.backwards {
            self.time = Duration::ZERO;
        } else {
            self.time += Duration::from_millis(cost);
        }
        Ok(outcome)
    }
    fn release(&mut self, handle: &Handle) -> Result<()> {
        self.trace.borrow_mut().released.push(handle.0);
        if self.fail_release == Some(handle.0) {
            Err(Error::Native)
        } else {
            Ok(())
        }
    }
    fn cleanup_failed(&mut self) {
        self.trace.borrow_mut().cleanup_failures += 1;
    }
}
fn denied<K: Kernel>(result: Result<Held<K>>, want: Error) {
    match result {
        Err(error) => assert_eq!(error, want),
        Ok(_) => panic!("unexpected lease"),
    }
}

// Catches omitted acquisition, reversed order and releasing in acquisition order.
#[test]
fn retains_both_handles_until_reverse_release() {
    let cancel = AtomicBool::new(false);
    let fake = Fake::new(&cancel);
    let trace = fake.trace.clone();
    let lease = take(fake, &cancel, 5000).expect("lease");
    assert!(trace.borrow().closed.is_empty());
    assert!(trace.borrow().released.is_empty());
    let names: Vec<_> = trace
        .borrow()
        .events
        .iter()
        .filter(|s| s.starts_with("Wintun\\"))
        .cloned()
        .collect();
    assert_eq!(
        names,
        [
            "Wintun\\Wintun-Device-Installation-Mutex",
            "Wintun\\Wintun-Driver-Installation-Mutex"
        ]
    );
    lease.release().unwrap();
    assert_eq!(trace.borrow().released, [2, 1]);
    assert_eq!(trace.borrow().closed, [2, 1]);
}
#[test]
fn invalid_zero_over_five_seconds_and_infinite_never_reach_kernel() {
    for budget in [0, 5001, u32::MAX] {
        let cancel = AtomicBool::new(false);
        let fake = Fake::new(&cancel);
        let trace = fake.trace.clone();
        denied(take(fake, &cancel, budget), Error::Invalid);
        assert!(trace.borrow().events.is_empty());
    }
}
#[test]
fn cancellation_before_acquisition_never_reaches_kernel() {
    let cancel = AtomicBool::new(true);
    let fake = Fake::new(&cancel);
    let trace = fake.trace.clone();
    denied(take(fake, &cancel, 5000), Error::Retired);
    assert!(trace.borrow().events.is_empty());
}
#[test]
fn actual_identity_denial_precedes_namespace_and_mutex_calls() {
    let cancel = AtomicBool::new(false);
    let mut fake = Fake::new(&cancel);
    let trace = fake.trace.clone();
    fake.deny_identity = true;
    denied(take(fake, &cancel, 5000), Error::Conflict);
    assert_eq!(trace.borrow().events, ["authenticate"]);
}
#[test]
fn second_open_error_releases_all_prior_owned_handles() {
    let cancel = AtomicBool::new(false);
    let mut fake = Fake::new(&cancel);
    let trace = fake.trace.clone();
    fake.fail_open = Some(2);
    denied(take(fake, &cancel, 5000), Error::Native);
    assert_eq!(trace.borrow().released, [1]);
    assert_eq!(trace.borrow().closed, [1]);
}
#[test]
fn timeout_never_releases_unowned_mutex() {
    let cancel = AtomicBool::new(false);
    let mut fake = Fake::new(&cancel);
    let trace = fake.trace.clone();
    fake.outcomes = VecDeque::from([(Wait::Acquired, 0), (Wait::Timeout, 100)]);
    denied(take(fake, &cancel, 100), Error::Deadline);
    assert_eq!(trace.borrow().released, [1]);
    assert_eq!(trace.borrow().closed, [2, 1]);
}
#[test]
fn abandonment_denies_but_releases_acknowledged_ownership() {
    for abandoned_at in [1, 2] {
        let cancel = AtomicBool::new(false);
        let mut fake = Fake::new(&cancel);
        let trace = fake.trace.clone();
        fake.outcomes = if abandoned_at == 1 {
            VecDeque::from([(Wait::Abandoned, 0)])
        } else {
            VecDeque::from([(Wait::Acquired, 0), (Wait::Abandoned, 0)])
        };
        denied(take(fake, &cancel, 5000), Error::Conflict);
        assert_eq!(
            trace.borrow().released,
            if abandoned_at == 1 {
                vec![1]
            } else {
                vec![2, 1]
            }
        );
        assert_eq!(trace.borrow().closed, trace.borrow().released);
    }
}
#[test]
fn one_total_budget_includes_namespace_and_first_wait() {
    let cancel = AtomicBool::new(false);
    let mut fake = Fake::new(&cancel);
    let trace = fake.trace.clone();
    fake.namespace_cost = 20;
    fake.outcomes = VecDeque::from([(Wait::Acquired, 70), (Wait::Timeout, 10)]);
    denied(take(fake, &cancel, 100), Error::Deadline);
    // 100 - namespace20 - firstwait70 = 10, never another100.
    assert_eq!(trace.borrow().waits, [50, 10]);
    assert_eq!(trace.borrow().released, [1]);
}
#[test]
fn successful_wait_after_deadline_denies_and_releases() {
    let cancel = AtomicBool::new(false);
    let mut fake = Fake::new(&cancel);
    let trace = fake.trace.clone();
    fake.outcomes = VecDeque::from([(Wait::Acquired, 100)]);
    denied(take(fake, &cancel, 100), Error::Deadline);
    assert_eq!(trace.borrow().released, [1]);
}
#[test]
fn namespace_create_open_race_uses_same_budget() {
    let cancel = AtomicBool::new(false);
    let mut fake = Fake::new(&cancel);
    let trace = fake.trace.clone();
    fake.namespace_retries = 20;
    fake.namespace_cost = 30;
    denied(take(fake, &cancel, 100), Error::Deadline);
    assert_eq!(
        trace
            .borrow()
            .events
            .iter()
            .filter(|s| *s == "namespace")
            .count(),
        4
    );
    assert!(trace.borrow().waits.is_empty());
}
#[test]
fn backwards_clock_denies_after_releasing_acquired_handle() {
    let cancel = AtomicBool::new(false);
    let mut fake = Fake::new(&cancel);
    let trace = fake.trace.clone();
    fake.namespace_cost = 20;
    fake.backwards = true;
    denied(take(fake, &cancel, 100), Error::Deadline);
    assert_eq!(trace.borrow().released, [1]);
}
#[test]
fn cancellation_between_calls_closes_without_releasing_unowned_handle() {
    for at in ["authenticate", "namespace", "open", "security", "wait"] {
        let cancel = AtomicBool::new(false);
        let mut fake = Fake::new(&cancel);
        let trace = fake.trace.clone();
        fake.cancel_at = Some(at);
        denied(take(fake, &cancel, 5000), Error::Retired);
        assert_eq!(
            trace.borrow().released,
            if at == "wait" { vec![1] } else { vec![] }
        );
        assert_eq!(
            trace.borrow().closed.len(),
            usize::from(["open", "security", "wait"].contains(&at))
        );
    }
}
#[test]
fn security_failure_for_second_handle_releases_only_first() {
    let cancel = AtomicBool::new(false);
    let mut fake = Fake::new(&cancel);
    let trace = fake.trace.clone();
    fake.fail_security = Some(2);
    denied(take(fake, &cancel, 5000), Error::Native);
    assert_eq!(trace.borrow().released, [1]);
    assert_eq!(trace.borrow().closed, [2, 1]);
}
#[test]
fn foreign_null_weak_unknown_inherited_duplicate_and_missing_acl_deny_before_wait() {
    let mut bad = Vec::new();
    let mut s = strong();
    s.owner = Principal::Other;
    bad.push(s);
    let mut s = strong();
    s.protected = false;
    bad.push(s);
    let mut s = strong();
    s.dacl = None;
    bad.push(s);
    let mut s = strong();
    s.dacl = Some(vec![]);
    bad.push(s);
    for (kind, flags, mask, who) in [
        (1, 0, 0x001f0001, Principal::System),
        (5, 0, 0x001f0001, Principal::System),
        (0, 16, 0x001f0001, Principal::System),
        (0, 0, 0x00100001, Principal::System),
        (0, 0, 0x011f0001, Principal::System),
        (0, 0, 0x001f0001, Principal::Other),
        (0, 0, 0x001f0001, Principal::Admins),
    ] {
        let mut s = strong();
        s.dacl.as_mut().unwrap()[0] = Ace {
            kind,
            flags,
            mask,
            principal: who,
        };
        bad.push(s);
    }
    let mut s = strong();
    s.dacl.as_mut().unwrap().pop();
    bad.push(s);
    for security in bad {
        let cancel = AtomicBool::new(false);
        let mut fake = Fake::new(&cancel);
        let trace = fake.trace.clone();
        fake.security = security;
        denied(take(fake, &cancel, 5000), Error::Conflict);
        assert!(trace.borrow().waits.is_empty());
        assert!(trace.borrow().released.is_empty());
        assert_eq!(trace.borrow().closed, [1]);
    }
}
#[test]
fn builtin_admin_owner_and_exact_generic_all_are_accepted() {
    let cancel = AtomicBool::new(false);
    let mut fake = Fake::new(&cancel);
    fake.security.owner = Principal::Admins;
    for ace in fake.security.dacl.as_mut().unwrap() {
        ace.mask = 0x10000000;
    }
    take(fake, &cancel, 5000).unwrap().release().unwrap();
}
#[test]
fn caller_panic_unwinds_both_acquired_handles_once() {
    let cancel = AtomicBool::new(false);
    let mut fake = Fake::new(&cancel);
    let trace = fake.trace.clone();
    fake.panic_at = None;
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let lease = take(fake, &cancel, 5000).unwrap();
        let _owned = lease;
        panic!("caller unwind");
    }));
    assert!(result.is_err());
    assert_eq!(trace.borrow().released, [2, 1]);
    assert_eq!(trace.borrow().closed, [2, 1]);
}
#[test]
fn panic_before_wait_closes_unowned_handle_without_release() {
    let cancel = AtomicBool::new(false);
    let mut fake = Fake::new(&cancel);
    let trace = fake.trace.clone();
    fake.panic_at = Some("security");
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let _ = take(fake, &cancel, 5000);
    }));
    assert!(result.is_err());
    assert!(trace.borrow().released.is_empty());
    assert_eq!(trace.borrow().closed, [1]);
}
#[test]
fn failed_explicit_release_denies_and_does_not_double_release_on_drop() {
    let cancel = AtomicBool::new(false);
    let mut fake = Fake::new(&cancel);
    let trace = fake.trace.clone();
    fake.fail_release = Some(2);
    assert_eq!(
        take(fake, &cancel, 5000).unwrap().release(),
        Err(Error::Native)
    );
    assert_eq!(trace.borrow().released, [2, 1]);
    assert_eq!(trace.borrow().closed, [2, 1]);
}
#[test]
fn failed_implicit_release_invokes_mandatory_fail_stop_boundary() {
    let cancel = AtomicBool::new(false);
    let mut fake = Fake::new(&cancel);
    let trace = fake.trace.clone();
    fake.fail_release = Some(1);
    drop(take(fake, &cancel, 5000).unwrap());
    assert_eq!(trace.borrow().released, [2, 1]);
    assert_eq!(trace.borrow().cleanup_failures, 1);
}
#[test]
fn wait_api_error_closes_unowned_handle_without_release() {
    let cancel = AtomicBool::new(false);
    let mut fake = Fake::new(&cancel);
    let trace = fake.trace.clone();
    fake.fail_wait = true;
    denied(take(fake, &cancel, 5000), Error::Native);
    assert!(trace.borrow().released.is_empty());
    assert_eq!(trace.borrow().closed, [1]);
}
#[test]
fn panic_in_second_security_query_releases_first_and_closes_second() {
    let cancel = AtomicBool::new(false);
    let mut fake = Fake::new(&cancel);
    let trace = fake.trace.clone();
    fake.panic_security = Some(2);
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let _ = take(fake, &cancel, 5000);
    }));
    assert!(result.is_err());
    assert_eq!(trace.borrow().released, [1]);
    assert_eq!(trace.borrow().closed, [2, 1]);
}
#[test]
fn failed_reverification_is_permanent_even_if_identity_recovers() {
    let cancel = AtomicBool::new(false);
    let fake = Fake::new(&cancel);
    let trace = fake.trace.clone();
    let mut lease = take(fake, &cancel, 5000).unwrap();
    lease.kernel.deny_identity = true;
    assert_eq!(lease.verify(&cancel), Err(Error::Conflict));
    lease.kernel.deny_identity = false;
    assert_eq!(lease.verify(&cancel), Err(Error::Retired));
    lease.release().unwrap();
    assert_eq!(trace.borrow().released, [2, 1]);
}
#[test]
fn cancelled_retained_lease_cannot_be_revalidated_after_flag_reset() {
    let cancel = AtomicBool::new(false);
    let fake = Fake::new(&cancel);
    let mut lease = take(fake, &cancel, 5000).unwrap();
    cancel.store(true, Ordering::Release);
    assert_eq!(lease.verify(&cancel), Err(Error::Retired));
    cancel.store(false, Ordering::Release);
    assert_eq!(lease.verify(&cancel), Err(Error::Retired));
}
#[test]
fn retained_security_drift_denies_and_permanently_retires() {
    let cancel = AtomicBool::new(false);
    let fake = Fake::new(&cancel);
    let mut lease = take(fake, &cancel, 5000).unwrap();
    lease.kernel.security.owner = Principal::Other;
    assert_eq!(lease.verify(&cancel), Err(Error::Conflict));
    lease.kernel.security = strong();
    assert_eq!(lease.verify(&cancel), Err(Error::Retired));
}
// Catches authentication performed only before the final security observations.
#[test]
fn identity_loss_during_final_security_check_denies_lease_and_releases_both() {
    let cancel = AtomicBool::new(false);
    let mut fake = Fake::new(&cancel);
    let trace = fake.trace.clone();
    fake.deny_identity_on_security = Some(4);
    denied(take(fake, &cancel, 5000), Error::Conflict);
    assert_eq!(trace.borrow().released, [2, 1]);
    assert_eq!(trace.borrow().closed, [2, 1]);
}

#[test]
fn process_local_alias_never_occupies_upstream_mapping_and_never_reuses_a_lease() {
    let first = Alias::new(321, 1).unwrap();
    let second = Alias::new(321, 2).unwrap();
    let other_process = Alias::new(322, 1).unwrap();
    assert_eq!(first.0, "NelomaiWintunLease-321-1");
    assert_eq!(second.0, "NelomaiWintunLease-321-2");
    assert_ne!(first.0, second.0);
    assert_ne!(first.0, other_process.0);
    assert_ne!(first.0, "Wintun");
    assert!(!first.0.contains('\\'));
}

#[test]
fn qualified_alias_keeps_exact_upstream_object_name_and_rejects_other_names() {
    let alias = Alias::new(321, 1).unwrap();
    assert_eq!(
        alias
            .qualified("Wintun\\Wintun-Device-Installation-Mutex")
            .unwrap(),
        "NelomaiWintunLease-321-1\\Wintun-Device-Installation-Mutex"
    );
    assert_eq!(
        alias
            .qualified("Wintun\\Wintun-Driver-Installation-Mutex")
            .unwrap(),
        "NelomaiWintunLease-321-1\\Wintun-Driver-Installation-Mutex"
    );
    for name in [
        "Wintun-Device-Installation-Mutex",
        "Global\\Wintun-Device-Installation-Mutex",
        "Wintun\\other",
        "Wintun\\Wintun-Device-Installation-Mutex\\other",
        "",
    ] {
        assert_eq!(alias.qualified(name), Err(Error::Invalid));
    }
}

#[test]
fn zero_or_exhausted_alias_domain_is_rejected_not_wrapped_or_shared() {
    for (process, sequence) in [(0, 1), (321, 0), (321, u64::MAX)] {
        assert!(matches!(Alias::new(process, sequence), Err(Error::Invalid)));
    }
    assert!(Alias::new(u32::MAX, u64::MAX - 1).is_ok());
}
