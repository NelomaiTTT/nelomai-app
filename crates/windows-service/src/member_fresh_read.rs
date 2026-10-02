//! Re-read a factual value after expensive authentication; never effect authority.
use crate::member_carrier::{CarrierError, Result};

pub(crate) fn read<T: Eq>(
    mut authenticate: impl FnMut() -> Result<()>,
    mut current: impl FnMut() -> Result<T>,
) -> Result<T> {
    authenticate()?;
    let before = current()?;
    authenticate()?;
    // LAST query is after runtime/boot/file hashing. Both values are still
    // facts, not atomic CAS/authorization. Caller holds the actual actor lease.
    let after = current()?;
    if before != after {
        return Err(CarrierError::Conflict);
    }
    Ok(after)
}

#[cfg(test)]
mod tests {
    use crate::member_carrier::CarrierError;
    use std::cell::{Cell, RefCell};

    #[test]
    fn permission_revoked_during_final_authentication_is_not_returned_as_fresh() {
        // Break caught: return a cached permission sampled before runtime hashes.
        let fresh = Cell::new(true);
        let calls = Cell::new(0);
        let result = super::read(
            || {
                calls.set(calls.get() + 1);
                if calls.get() == 2 {
                    fresh.set(false);
                }
                Ok(())
            },
            || Ok(fresh.get()),
        );
        assert_eq!(result, Err(CarrierError::Conflict));
    }

    #[test]
    fn changed_durable_bytes_during_authentication_are_not_returned() {
        let bytes = RefCell::new(vec![1, 2, 3]);
        let calls = Cell::new(0);
        let result = super::read(
            || {
                calls.set(calls.get() + 1);
                if calls.get() == 2 {
                    *bytes.borrow_mut() = vec![1, 2, 4];
                }
                Ok(())
            },
            || Ok(bytes.borrow().clone()),
        );
        assert_eq!(result, Err(CarrierError::Conflict));
    }

    #[test]
    fn last_value_read_is_after_authentication_and_stable_false_is_not_permission() {
        let events = RefCell::new(vec![]);
        let result = super::read(
            || {
                events.borrow_mut().push("auth");
                Ok(())
            },
            || {
                events.borrow_mut().push("read");
                Ok(false)
            },
        );
        assert_eq!(result, Ok(false));
        assert_eq!(*events.borrow(), ["auth", "read", "auth", "read"]);
    }

    #[test]
    fn each_authentication_or_read_failure_propagates() {
        for fail in 1..=4 {
            let steps = Cell::new(0);
            let event = || {
                steps.set(steps.get() + 1);
                if steps.get() == fail {
                    Err(CarrierError::Journal)
                } else {
                    Ok(())
                }
            };
            let result = super::read(event, || {
                event()?;
                Ok(vec![3, 9])
            });
            assert_eq!(result, Err(CarrierError::Journal));
            assert_eq!(steps.get(), fail);
        }
    }
}
