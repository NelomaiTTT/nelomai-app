use super::*;
use std::{cell::RefCell, rc::Rc};

#[derive(Default)]
struct State {
    calls: Vec<&'static str>,
    fail: Option<usize>,
    panic: Option<usize>,
    lease_held: bool,
    loaded: usize,
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
    type Module = Module;
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
    fn verify_lease(&mut self, _: &mut Lease, _: &AtomicBool) -> Result<()> {
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
    fn load(&mut self) -> Result<Module> {
        assert!(self.0.borrow().lease_held);
        self.call("load")?;
        self.0.borrow_mut().loaded += 1;
        Ok(Module(self.0.clone()))
    }
    fn module(&mut self, _: &Module) -> Result<()> {
        self.call("module")
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

#[test]
fn authenticated_cold_load_holds_original_module_after_bracketed_load() {
    let s = Shared::default();
    let loaded = load(Boundary(s.clone()), &AtomicBool::new(false)).unwrap();
    assert!(loaded.valid);
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
fn each_failed_load_boundary_unloads_only_original_ack_and_releases_lease() {
    for failure in 1..=13 {
        let s = Shared::default();
        s.borrow_mut().fail = Some(failure);
        assert!(load(Boundary(s.clone()), &AtomicBool::new(false)).is_err());
        let state = s.borrow();
        assert!(!state.lease_held);
        assert_eq!(state.loaded, usize::from(failure > 9));
        assert_eq!(state.unloads, state.loaded);
        assert_eq!(&state.calls[..failure], &EXPECTED[..failure]);
        if failure > 9 {
            assert_eq!(state.calls[failure..], ["unload", "release"]);
        } else if failure > 3 {
            assert_eq!(state.calls[failure..], ["release"]);
        }
    }
}

#[test]
fn unwinding_after_load_keeps_pin_until_original_reference_is_released() {
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
        assert_eq!(state.unloads, state.loaded);
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
    assert!(loaded.valid);
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
            assert!(!loaded.valid);
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
    assert!(!loaded.valid);
    assert!(!s.borrow().lease_held);
    assert_eq!(s.borrow().loaded, 1);
}
