//! Retention of one original serialized guard; not runtime or effect authority.

use std::{rc::Rc, sync::MutexGuard};

struct Original<'a, T> {
    owner: T,
    _guard: MutexGuard<'a, ()>,
}

/// The one canonical owner; no Clone/Send and no lock reconstruction.
/// Runtime-specific constructors must independently authenticate the owner.
pub(crate) struct SerializedLease<'a, T>(Rc<Original<'a, T>>);

/// Read-only retention of the SAME original guard. No mutation or unlock API,
/// no constructor from facts, and no conversion back to the canonical owner.
/// This is a lifetime pin, NEVER authentication or native effect permission.
pub(crate) struct ReadPin<'a, T>(Rc<Original<'a, T>>);

impl<'a, T> SerializedLease<'a, T> {
    pub(crate) fn new(owner: T, guard: MutexGuard<'a, ()>) -> Self {
        Self(Rc::new(Original {
            owner,
            _guard: guard,
        }))
    }
    pub(crate) fn pin(&self) -> ReadPin<'a, T> {
        ReadPin(self.0.clone())
    }
    pub(crate) fn owner(&self) -> &T {
        &self.0.owner
    }
    pub(crate) fn matches(&self, pin: &ReadPin<'a, T>) -> bool {
        Rc::ptr_eq(&self.0, &pin.0)
    }
}
impl<'a, T> ReadPin<'a, T> {
    pub(crate) fn read_pin(&self) -> ReadPin<'a, T> {
        ReadPin(self.0.clone())
    }
    pub(crate) fn owner(&self) -> &T {
        &self.0.owner
    }
    pub(crate) fn matches(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex, TryLockError};

    #[test]
    fn read_pin_retains_the_original_mutex_after_mutable_owner_drops() {
        let mutex = Mutex::new(());
        let owner = Arc::new("original");
        let lease = SerializedLease::new(owner.clone(), mutex.try_lock().unwrap());
        let pin = lease.pin();
        assert!(Arc::ptr_eq(pin.owner(), &owner));
        assert!(matches!(mutex.try_lock(), Err(TryLockError::WouldBlock)));
        drop(lease);
        assert!(matches!(mutex.try_lock(), Err(TryLockError::WouldBlock)));
        drop(pin);
        assert!(mutex.try_lock().is_ok());
    }

    #[test]
    fn each_pin_and_canonical_owner_independently_retain_same_guard() {
        let mutex = Mutex::new(());
        let lease = SerializedLease::new(17, mutex.try_lock().unwrap());
        let first = lease.pin();
        let second = lease.pin();
        assert!(lease.matches(&first));
        assert!(lease.matches(&second));
        assert!(first.matches(&second));
        assert_eq!(*lease.owner(), 17);
        drop(first);
        drop(second);
        assert!(matches!(mutex.try_lock(), Err(TryLockError::WouldBlock)));
        drop(lease);
        assert!(mutex.try_lock().is_ok());
    }
    #[test]
    fn derived_read_pin_retains_same_real_guard_after_both_original_owners_drop() {
        let mutex = Mutex::new(());
        let lease = SerializedLease::new(23, mutex.try_lock().unwrap());
        let first = lease.pin();
        let derived = first.read_pin();
        assert!(first.matches(&derived));
        assert!(lease.matches(&derived));
        drop(first);
        drop(lease);
        assert_eq!(*derived.owner(), 23);
        assert!(matches!(mutex.try_lock(), Err(TryLockError::WouldBlock)));
        drop(derived);
        assert!(mutex.try_lock().is_ok());
    }

    #[test]
    fn same_owner_arc_is_not_a_proof_of_same_serialized_lease() {
        let a = Mutex::new(());
        let b = Mutex::new(());
        let owner = Arc::new("original");
        let first = SerializedLease::new(owner.clone(), a.try_lock().unwrap());
        let second = SerializedLease::new(owner.clone(), b.try_lock().unwrap());
        assert!(Arc::ptr_eq(first.owner(), second.owner()));
        assert!(!first.matches(&second.pin()));
        assert!(!first.pin().matches(&second.pin()));
    }

    #[test]
    fn unwind_of_mutable_owner_cannot_release_a_retained_guard() {
        let mutex = Mutex::new(());
        let lease = SerializedLease::new((), mutex.try_lock().unwrap());
        let pin = lease.pin();
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _owned = lease;
            panic!("simulated actor failure");
        }));
        assert!(failed.is_err());
        assert!(matches!(mutex.try_lock(), Err(TryLockError::WouldBlock)));
        drop(pin);
        // Final guard released outside unwind; no reconstructed lock claim.
        assert!(mutex.try_lock().is_ok());
    }

    #[test]
    fn original_owner_resource_is_retained_until_last_pin_drops() {
        struct Owner(Arc<std::sync::atomic::AtomicUsize>);
        impl Drop for Owner {
            fn drop(&mut self) {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mutex = Mutex::new(());
        let lease = SerializedLease::new(Owner(count.clone()), mutex.try_lock().unwrap());
        let a = lease.pin();
        let b = lease.pin();
        drop(lease);
        drop(a);
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 0);
        drop(b);
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(mutex.try_lock().is_ok());
    }
}
