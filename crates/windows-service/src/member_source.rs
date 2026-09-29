//! Readiness policy for an already owned source. Tentative is never permission
//! to bind/send; callers re-attest ownership on every observation and bound waits.
#![cfg_attr(not(windows), allow(dead_code))]
use std::io;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Readiness {
    Tentative,
    Preferred,
}

pub(crate) fn classify(
    expected: (u32, u64),
    actual: (u32, u64),
    dad_state: i32,
) -> io::Result<Readiness> {
    if expected.0 == 0 || expected.1 == 0 || expected != actual {
        return Err(io::Error::other("owned_source_identity_mismatch"));
    }
    match dad_state {
        1 => Ok(Readiness::Tentative),
        4 => Ok(Readiness::Preferred),
        _ => Err(io::Error::other("owned_source_not_preferred")),
    }
}

pub(crate) fn wait_until_preferred(
    mut observe: impl FnMut() -> io::Result<Readiness>,
    mut pause: impl FnMut() -> io::Result<()>,
) -> io::Result<()> {
    loop {
        match observe()? {
            Readiness::Preferred => return Ok(()),
            Readiness::Tentative => pause()?,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn tentative_source_waits_for_preferred_before_admitting_socket() {
        // Hardware: exact index/LUID with DAD=1 was rejected before Windows
        // completed DAD=4. Reverting to the one-shot check must fail this test.
        let reads = Cell::new(0);
        let pauses = Cell::new(0);
        wait_until_preferred(
            || {
                let n = reads.get();
                reads.set(n + 1);
                classify((73, 99), (73, 99), if n < 2 { 1 } else { 4 })
            },
            || {
                pauses.set(pauses.get() + 1);
                assert!(pauses.get() <= 2, "never observed readiness");
                Ok(())
            },
        )
        .unwrap();
        assert_eq!((reads.get(), pauses.get()), (3, 2));
    }

    #[test]
    fn foreign_identity_and_invalid_dad_never_wait_or_admit() {
        for (actual, dad) in [
            ((74, 99), 4),
            ((73, 100), 1),
            ((73, 99), 0),
            ((73, 99), 2),
            ((73, 99), 3),
            ((73, 99), 5),
        ] {
            assert!(wait_until_preferred(
                || classify((73, 99), actual, dad),
                || panic!("invalid source must fail immediately"),
            )
            .is_err());
        }
    }

    #[test]
    fn tentative_timeout_and_owner_loss_are_not_readiness() {
        let error = wait_until_preferred(
            || Ok(Readiness::Tentative),
            || Err(io::ErrorKind::TimedOut.into()),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let reads = Cell::new(0);
        let error = wait_until_preferred(
            || {
                reads.set(reads.get() + 1);
                if reads.get() == 1 {
                    Ok(Readiness::Tentative)
                } else {
                    Err(io::ErrorKind::PermissionDenied.into())
                }
            },
            || Ok(()),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(reads.get(), 2);
    }
}
