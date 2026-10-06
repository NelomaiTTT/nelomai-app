use super::*;
use std::panic::{catch_unwind, AssertUnwindSafe};

// Ordinary drop-tracked resources exercise the ACTUAL production retention
// helper. No opaque Windows resource, original ACK, or permissive G is mocked.
struct Original<'a> {
    name: &'static str,
    dropped: &'a RefCell<Vec<&'static str>>,
}
impl Drop for Original<'_> {
    fn drop(&mut self) {
        self.dropped.borrow_mut().push(self.name);
    }
}
struct Inputs<'a> {
    originals: Vec<Original<'a>>,
}
fn inputs<'a>(dropped: &'a RefCell<Vec<&'static str>>) -> Inputs<'a> {
    Inputs {
        originals: [
            "module",
            "runtime",
            "image",
            "producer",
            "scope",
            "gate",
            "cancellation",
        ]
        .into_iter()
        .map(|name| Original { name, dropped })
        .collect(),
    }
}
type Root<'a> =
    ConstructionRoot<Inputs<'a>, Inputs<'a>, Rc<Inputs<'a>>, (Rc<Inputs<'a>>, Original<'a>)>;
fn root<'a>(dropped: &'a RefCell<Vec<&'static str>>) -> Root<'a> {
    ConstructionRoot::new(inputs(dropped))
}
fn construct(root: &Root<'_>) -> Result<()> {
    root.attempt(ConstructionStep::Authority, |parts| {
        parts.authority = parts.inputs.take();
        Ok(())
    })
}

// Break: rejecting the valid first attempt or returning ownership through Result.
#[test]
fn success_leaves_authority_and_components_in_the_callers_same_root() {
    let dropped = RefCell::new(Vec::new());
    let mut root = root(&dropped);
    construct(&root).unwrap();
    root.attempt(ConstructionStep::Components, |parts| {
        parts.shared = Some(Rc::new(parts.authority.take().unwrap()));
        parts.components = Some((
            parts.shared.as_ref().unwrap().clone(),
            Original {
                name: "carrier",
                dropped: &dropped,
            },
        ));
        Ok(())
    })
    .unwrap();
    assert!(root.authority_complete.get());
    assert!(root.components_complete.get());
    assert!(!root.revoked.get());
    let parts = root.retained_parts();
    assert!(parts.inputs.is_none());
    assert!(parts.authority.is_none());
    assert!(Rc::ptr_eq(
        parts.shared.as_ref().unwrap(),
        &parts.components.as_ref().unwrap().0
    ));
    assert_eq!(parts.shared.as_ref().unwrap().originals[0].name, "module");
    assert!(dropped.borrow().is_empty());
    // Explicit caller release of all retained aliases, never an implicit retry.
    drop(parts.components.take());
    assert_eq!(&*dropped.borrow(), &["carrier"]);
    drop(parts.shared.take());
    assert_eq!(
        &*dropped.borrow(),
        &[
            "carrier",
            "module",
            "runtime",
            "image",
            "producer",
            "scope",
            "gate",
            "cancellation"
        ]
    );
}

// Break: losing inputs or allowing a failed preflight to be invoked again.
#[test]
fn constructor_error_retains_every_input_and_irreversibly_denies_retry() {
    let dropped = RefCell::new(Vec::new());
    let mut root = root(&dropped);
    assert_eq!(
        root.attempt(ConstructionStep::Authority, |_| Err(CarrierError::Journal)),
        Err(CarrierError::Journal)
    );
    assert!(root.revoked.get());
    assert!(!root.authority_complete.get());
    let called = Cell::new(false);
    assert!(root
        .attempt(ConstructionStep::Authority, |_| {
            called.set(true);
            Ok(())
        })
        .is_err());
    assert!(!called.get());
    assert_eq!(
        root.retained_parts()
            .inputs
            .as_ref()
            .unwrap()
            .originals
            .len(),
        7
    );
    assert!(dropped.borrow().is_empty());
}

// Break: leaving an assembled authority local during its current(Create) postflight.
#[test]
fn assembled_authority_is_retained_on_postflight_error_or_unwind() {
    for unwind in [false, true] {
        let dropped = RefCell::new(Vec::new());
        let mut root = root(&dropped);
        let result = catch_unwind(AssertUnwindSafe(|| {
            root.attempt(ConstructionStep::Authority, |parts| {
                parts.authority = parts.inputs.take();
                if unwind {
                    panic!("authority postflight");
                }
                Err(CarrierError::Conflict)
            })
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), Err(CarrierError::Conflict));
        }
        assert!(root.revoked.get());
        assert!(!root.authority_complete.get());
        assert!(root.retained_parts().authority.is_some());
        assert!(dropped.borrow().is_empty());
        assert!(root
            .attempt(ConstructionStep::Components, |_| Ok(()))
            .is_err());
    }
}

// Break: constructing the module from the only shared alias, which Err drops.
#[test]
fn shared_original_survives_native_resolve_error_or_unwind_in_the_caller_slot() {
    for unwind in [false, true] {
        let dropped = RefCell::new(Vec::new());
        let mut root = root(&dropped);
        construct(&root).unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| {
            root.attempt(ConstructionStep::Components, |parts| {
                parts.shared = Some(Rc::new(parts.authority.take().unwrap()));
                let module_alias = parts.shared.as_ref().unwrap().clone();
                assert!(Rc::ptr_eq(parts.shared.as_ref().unwrap(), &module_alias));
                if unwind {
                    panic!("native resolve");
                }
                drop(module_alias);
                Err(CarrierError::Native)
            })
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), Err(CarrierError::Native));
        }
        assert!(root.retained_parts().shared.is_some());
        assert!(root.revoked.get());
        assert!(!root.components_complete.get());
        assert!(dropped.borrow().is_empty());
    }
}

// Break: returning a complete Carrier/rows tuple through a fallible postflight.
#[test]
fn returned_components_survive_postflight_error_or_unwind_before_selection() {
    for unwind in [false, true] {
        let dropped = RefCell::new(Vec::new());
        let mut root = root(&dropped);
        construct(&root).unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| {
            root.attempt(ConstructionStep::Components, |parts| {
                parts.shared = Some(Rc::new(parts.authority.take().unwrap()));
                parts.components = Some((
                    parts.shared.as_ref().unwrap().clone(),
                    Original {
                        name: "carrier",
                        dropped: &dropped,
                    },
                ));
                if unwind {
                    panic!("supervisory postflight");
                }
                Err(CarrierError::Retired)
            })
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), Err(CarrierError::Retired));
        }
        assert!(root.revoked.get());
        assert!(!root.components_complete.get());
        let parts = root.retained_parts();
        assert!(Rc::ptr_eq(
            parts.shared.as_ref().unwrap(),
            &parts.components.as_ref().unwrap().0
        ));
        assert!(dropped.borrow().is_empty());
        assert!(root
            .attempt(ConstructionStep::Components, |_| Ok(()))
            .is_err());
    }
}

// Break: duplicate calls succeed, overwrite originals, or silently reset forward.
#[test]
fn duplicate_successful_constructor_revokes_forward_and_cannot_replace_originals() {
    let dropped = RefCell::new(Vec::new());
    let mut root = root(&dropped);
    construct(&root).unwrap();
    let called = Cell::new(false);
    assert!(root
        .attempt(ConstructionStep::Authority, |_| {
            called.set(true);
            Ok(())
        })
        .is_err());
    assert!(!called.get());
    assert!(root.revoked.get());
    assert!(root.retained_parts().authority.is_some());
    assert!(root
        .attempt(ConstructionStep::Components, |_| Ok(()))
        .is_err());
    assert!(dropped.borrow().is_empty());
}

// Break: a caught recursive failure allows the outer callback to select forward.
#[test]
fn swallowed_constructor_reentry_taints_outer_success_and_keeps_partial_authority() {
    let dropped = RefCell::new(Vec::new());
    let mut root = root(&dropped);
    let result = root.attempt(ConstructionStep::Authority, |parts| {
        parts.authority = parts.inputs.take();
        assert!(root
            .attempt(ConstructionStep::Authority, |_| Ok(()))
            .is_err());
        Ok(())
    });
    assert!(result.is_err());
    assert!(root.revoked.get());
    assert!(!root.authority_complete.get());
    assert!(root.retained_parts().authority.is_some());
    assert!(dropped.borrow().is_empty());
}

// Break: a component attempt can run without completed construction or during it.
#[test]
fn premature_components_and_cross_stage_reentry_permanently_deny_construction() {
    let dropped = RefCell::new(Vec::new());
    let root = root(&dropped);
    let called = Cell::new(false);
    assert!(root
        .attempt(ConstructionStep::Components, |_| {
            called.set(true);
            Ok(())
        })
        .is_err());
    assert!(!called.get());
    assert!(construct(&root).is_err());
    assert!(root.revoked.get());
    let mut other =
        ConstructionRoot::<_, Inputs<'_>, Rc<Inputs<'_>>, (Rc<Inputs<'_>>, Original<'_>)>::new(
            inputs(&dropped),
        );
    assert!(other
        .attempt(ConstructionStep::Authority, |parts| {
            parts.authority = parts.inputs.take();
            assert!(other
                .attempt(ConstructionStep::Components, |_| Ok(()))
                .is_err());
            Ok(())
        })
        .is_err());
    assert!(other.revoked.get());
    assert!(!other.authority_complete.get());
    assert!(other.retained_parts().authority.is_some());
    assert!(dropped.borrow().is_empty());
}
