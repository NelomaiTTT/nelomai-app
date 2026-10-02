//! Non-owning registration of an already retained original resource.
//! This proves only identity/liveness, never native absence or permission.
#![allow(dead_code)]
use std::rc::{Rc, Weak};

/// Actual rooted object identity only. No observation, absence, effect or
/// destructor permission; equal contents cannot substitute a registration.
pub(crate) fn require_retained_original<T, E>(
    registered: &Option<Rc<T>>,
    actual: &Rc<T>,
    conflict: E,
) -> Result<(), E> {
    if registered
        .as_ref()
        .is_some_and(|held| Rc::ptr_eq(held, actual))
    {
        Ok(())
    } else {
        Err(conflict)
    }
}

/// Caller-rooted first observation before any fallible consumer. This only
/// retains the actual supplied object; it mints neither ACKs nor permission.
pub(crate) fn retain_first_before<T, E>(
    slot: &mut Option<Rc<T>>,
    original: Rc<T>,
    duplicate: E,
    postflight: impl FnOnce(&Rc<T>) -> Result<(), E>,
) -> Result<Rc<T>, E> {
    if slot.is_some() {
        return Err(duplicate);
    }
    *slot = Some(original.clone());
    postflight(&original)?;
    Ok(original)
}

pub(crate) struct OriginalRead<T> {
    value: Weak<T>,
}
impl<T> OriginalRead<T> {
    pub(crate) fn from_retained(value: &Rc<T>) -> Self {
        Self {
            value: Rc::downgrade(value),
        }
    }
    pub(crate) fn upgrade(&self) -> Option<Rc<T>> {
        self.value.upgrade()
    }
    pub(crate) fn same_original(&self, other: &Self) -> bool {
        Weak::ptr_eq(&self.value, &other.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, cell::RefCell};

    #[test]
    fn retained_registration_accepts_only_the_rooted_actual_object() {
        let actual = Rc::new(23);
        assert_eq!(
            require_retained_original::<_, _>(&None, &actual, "conflict"),
            Err("conflict")
        );
        let registered = Some(actual.clone());
        assert_eq!(
            require_retained_original(&registered, &actual, "conflict"),
            Ok(())
        );
        let equal = Rc::new(23);
        assert_eq!(
            require_retained_original(&registered, &equal, "conflict"),
            Err("conflict")
        );
        assert!(Rc::ptr_eq(registered.as_ref().unwrap(), &actual));
        // No replacement, reset, callback or ownership transfer on rejection.
        assert_eq!(
            require_retained_original(&registered, &actual, "conflict"),
            Ok(())
        );
    }

    #[test]
    fn first_capture_retains_actual_pin_before_failed_or_unwound_postflight() {
        let first = Rc::new(23);
        let mut slot = None;
        assert_eq!(
            retain_first_before(&mut slot, first.clone(), "duplicate", |_| Err("postflight")),
            Err("postflight")
        );
        assert!(Rc::ptr_eq(slot.as_ref().unwrap(), &first));
        let called = Cell::new(false);
        assert_eq!(
            retain_first_before(&mut slot, Rc::new(23), "duplicate", |_| {
                called.set(true);
                Ok(())
            }),
            Err("duplicate")
        );
        assert!(!called.get());
        assert!(Rc::ptr_eq(slot.as_ref().unwrap(), &first));

        let mut other = None;
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: Result<Rc<i32>, &str> =
                retain_first_before(&mut other, first.clone(), "duplicate", |_| {
                    panic!("postflight unwind")
                });
        }));
        assert!(panic.is_err());
        assert!(Rc::ptr_eq(other.as_ref().unwrap(), &first));
    }

    #[test]
    fn factual_registration_does_not_keep_a_stopped_owner_alive() {
        let owner = Rc::new(17);
        let read = OriginalRead::from_retained(&owner);
        assert!(Rc::ptr_eq(&owner, &read.upgrade().unwrap()));
        drop(owner);
        assert!(read.upgrade().is_none());
    }

    #[test]
    fn registration_breaks_gate_owner_cycle_without_substituting_equal_owner() {
        struct Gate {
            read: RefCell<Option<OriginalRead<Owner>>>,
        }
        struct Owner {
            _gate: Rc<Gate>,
            dropped: Rc<Cell<bool>>,
        }
        impl Drop for Owner {
            fn drop(&mut self) {
                self.dropped.set(true);
            }
        }
        let gate = Rc::new(Gate {
            read: RefCell::new(None),
        });
        let dropped = Rc::new(Cell::new(false));
        let owner = Rc::new(Owner {
            _gate: gate.clone(),
            dropped: dropped.clone(),
        });
        let same = OriginalRead::from_retained(&owner);
        let other = Rc::new(Owner {
            _gate: gate.clone(),
            dropped: Rc::new(Cell::new(false)),
        });
        assert!(!same.same_original(&OriginalRead::from_retained(&other)));
        *gate.read.borrow_mut() = Some(OriginalRead::from_retained(&owner));
        assert!(same.same_original(gate.read.borrow().as_ref().unwrap()));
        drop(owner);
        assert!(dropped.get());
        assert!(gate.read.borrow().as_ref().unwrap().upgrade().is_none());
    }
}
