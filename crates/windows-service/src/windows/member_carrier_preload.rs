//! Read-only source/package composition. Not executable-load or effect authority.
#![allow(dead_code)] // Factory remains disabled pending native lifecycle integration.

use crate::member_carrier::{CarrierError as Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    SourceBefore,
    Package,
    SourceAfter,
}

#[derive(Debug, PartialEq, Eq)]
enum State {
    Verified,
    Denied,
}

fn recheck(state: &mut State, mut verify: impl FnMut(Step) -> Result<()>) -> Result<()> {
    if *state != State::Verified {
        return Err(Error::Conflict);
    }
    // Invalidate BEFORE invoking any check: errors/unwinding must never leave
    // a previously successful observation available for a later retry.
    *state = State::Denied;
    for step in [Step::SourceBefore, Step::Package, Step::SourceAfter] {
        verify(step)?;
    }
    *state = State::Verified;
    Ok(())
}

#[cfg(windows)]
pub(crate) mod native {
    use super::*;
    use crate::windows::{
        member_carrier_payload::native::WintunSource,
        member_carrier_wintun_package::native::{self as package, CheckedExistingPackage},
    };

    /// Retains a borrow of the ORIGINAL signed source, its File/ancestor pins
    /// and the SAME runtime MutationGuard. !Send/!Clone through the package
    /// borrow; cannot become an IPC value, source path or effect permission.
    /// This supports ONLY cold preload with no existing Wintun device. Creating
    /// a carrier/running the driver invalidates that inventory; post-load/create
    /// authorization requires separate original-creator-aware lifecycle proof.
    pub(crate) struct WintunPreload<'a> {
        source: &'a WintunSource,
        package: CheckedExistingPackage<'a>,
        state: State,
    }
    impl<'a> WintunPreload<'a> {
        pub(crate) fn new(source: &'a WintunSource) -> Result<Self> {
            source.verify()?;
            // SAFETY: WintunSource was constructed from kernelcurrentexe and
            // signed Installation/full payloads, holds real lock continuity
            // and non-replaceable readonly source handles. We borrow precisely
            // that retained File and bracket observation with full verification.
            // Neither API executes the DLL or changes driver/device state.
            let package = unsafe { package::from_authenticated_source(source.file()?) }
                .map_err(|_| Error::Conflict)?;
            source.verify()?;
            Ok(Self {
                source,
                package,
                state: State::Verified,
            })
        }
        pub(crate) fn reattest(&mut self) -> Result<()> {
            recheck(&mut self.state, |step| match step {
                Step::SourceBefore | Step::SourceAfter => self.source.verify(),
                Step::Package => self.package.reattest().map_err(|_| Error::Conflict),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_package_refresh_is_bracketed_by_actual_source_checks() {
        let mut state = State::Verified;
        for _ in 0..2 {
            let mut observed = vec![];
            recheck(&mut state, |step| {
                observed.push(step);
                Ok(())
            })
            .unwrap();
            assert_eq!(
                observed,
                [Step::SourceBefore, Step::Package, Step::SourceAfter]
            );
            assert_eq!(state, State::Verified);
        }
    }

    #[test]
    fn failure_at_any_boundary_permanently_denies_this_observation() {
        for failed in [Step::SourceBefore, Step::Package, Step::SourceAfter] {
            let mut state = State::Verified;
            let mut observed = vec![];
            assert_eq!(
                recheck(&mut state, |step| {
                    observed.push(step);
                    if step == failed {
                        Err(Error::Conflict)
                    } else {
                        Ok(())
                    }
                }),
                Err(Error::Conflict)
            );
            assert_eq!(observed.last(), Some(&failed));
            assert_eq!(state, State::Denied);
            let mut retry_called = false;
            assert_eq!(
                recheck(&mut state, |_| {
                    retry_called = true;
                    Ok(())
                }),
                Err(Error::Conflict)
            );
            assert!(!retry_called);
            assert_eq!(state, State::Denied);
        }
    }

    #[test]
    fn unwinding_during_any_check_also_poisoned_the_observation() {
        for failed in [Step::SourceBefore, Step::Package, Step::SourceAfter] {
            let mut state = State::Verified;
            assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                recheck(&mut state, |step| {
                    if step == failed {
                        panic!("injected read failure");
                    }
                    Ok(())
                })
            }))
            .is_err());
            assert_eq!(state, State::Denied);
            assert_eq!(
                recheck(&mut state, |_| panic!("must not retry")),
                Err(Error::Conflict)
            );
        }
    }
}
