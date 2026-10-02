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

fn recheck(state: &mut State, verify: impl FnMut(Step) -> Result<()>) -> Result<()> {
    recheck_mode(state, false, verify)
}

fn recheck_cleanup(state: &mut State, verify: impl FnMut(Step) -> Result<()>) -> Result<()> {
    recheck_mode(state, true, verify)
}

fn recheck_mode(
    state: &mut State,
    cleanup: bool,
    mut verify: impl FnMut(Step) -> Result<()>,
) -> Result<()> {
    let previously_verified = *state == State::Verified;
    if !cleanup && !previously_verified {
        return Err(Error::Conflict);
    }
    // Invalidate BEFORE invoking any check: errors/unwinding must never leave
    // a previously successful observation available for a later retry.
    *state = State::Denied;
    for step in [Step::SourceBefore, Step::Package, Step::SourceAfter] {
        verify(step)?;
    }
    if previously_verified {
        *state = State::Verified;
    }
    Ok(())
}

struct PackageRefresh<'a, P, D: FnMut(&mut P)> {
    package: &'a mut P,
    deny: D,
    complete: bool,
}
impl<P, D: FnMut(&mut P)> Drop for PackageRefresh<'_, P, D> {
    fn drop(&mut self) {
        if !self.complete {
            (self.deny)(self.package);
        }
    }
}

fn recheck_package<P>(
    state: &mut State,
    package: &mut P,
    cleanup: bool,
    mut verify: impl FnMut(Step, &mut P) -> Result<()>,
    deny: impl FnMut(&mut P),
) -> Result<()> {
    let mut guard = PackageRefresh {
        package,
        deny,
        complete: false,
    };
    if *state == State::Denied {
        (guard.deny)(guard.package);
    }
    if cleanup {
        recheck_cleanup(state, |step| verify(step, guard.package))?;
    } else {
        recheck(state, |step| verify(step, guard.package))?;
    }
    guard.complete = true;
    Ok(())
}

#[cfg(windows)]
pub(crate) mod native {
    use super::*;
    use crate::windows::{
        member_carrier_payload::native::WintunSource,
        member_carrier_wintun_package::{
            native::{self as package, CheckedOriginalPackage},
            Error as PackageError, OriginalDevices,
        },
    };
    use std::rc::Rc;

    /// Strongly retains the ORIGINAL signed source, File/ancestor pins and SAME
    /// runtime MutationGuard. !Send/!Clone, with no borrowed-source lifetime.
    /// Cold construction/reattest reject live Wintun devices; original-owned
    /// refresh additionally requires the unsafe original native ACK contract.
    /// Neither path grants executable-load/create/cleanup/effect permission.
    pub(crate) struct WintunPreload {
        source: Rc<WintunSource>,
        package: CheckedOriginalPackage,
        state: State,
    }
    impl WintunPreload {
        pub(crate) fn new(source: &Rc<WintunSource>) -> Result<Self> {
            source.verify()?;
            let package = package::from_original_source(source).map_err(|_| Error::Conflict)?;
            source.verify()?;
            Ok(Self {
                source: Rc::clone(source),
                package,
                state: State::Verified,
            })
        }
        pub(crate) fn reattest(&mut self) -> Result<()> {
            self.refresh(false, CheckedOriginalPackage::reattest)
        }
        fn refresh(
            &mut self,
            cleanup: bool,
            mut operation: impl FnMut(
                &mut CheckedOriginalPackage,
            ) -> std::result::Result<(), PackageError>,
        ) -> Result<()> {
            recheck_package(
                &mut self.state,
                &mut self.package,
                cleanup,
                |step, package| match step {
                    Step::SourceBefore | Step::SourceAfter => self.source.verify(),
                    Step::Package => operation(package).map_err(|_| Error::Conflict),
                },
                CheckedOriginalPackage::deny_forward,
            )
        }
        pub(crate) fn reattest_owned(
            &mut self,
            originals: &mut impl OriginalDevices,
        ) -> Result<()> {
            self.refresh(false, |package| package.reattest_owned(originals))
        }
        /// Factual source/package/source observation after forward denial.
        /// The original native ACK/lease contract remains mandatory; success
        /// never grants native close/effects or rearms a denied forward gate.
        pub(crate) fn reattest_owned_cleanup(
            &mut self,
            originals: &mut impl OriginalDevices,
        ) -> Result<()> {
            self.refresh(true, |package| package.reattest_owned_cleanup(originals))
        }
    }

    #[cfg(test)]
    mod ownership_contract {
        use super::*;
        use crate::windows::member_carrier_wintun_package::OriginalDevices;
        use std::rc::Rc;

        // Compiled against the ACTUAL signed WintunSource, never a File or a
        // test-created authentication surrogate. No installed/native effects
        // are executed. A source-borrowing return type cannot satisfy this API.
        fn compile_only_preload_owned_cleanup_api_retains_real_original_after_caller_drop(
            source: Rc<WintunSource>,
            originals: &mut impl OriginalDevices,
        ) -> Result<WintunPreload> {
            let weak = Rc::downgrade(&source);
            let mut preload = WintunPreload::new(&source)?;
            assert!(Rc::ptr_eq(&source, &preload.source));
            drop(source);
            assert!(weak.upgrade().is_some());
            preload.reattest()?;
            preload.reattest_owned(originals)?;
            preload.state = State::Denied;
            preload.reattest_owned_cleanup(originals)?;
            assert_eq!(preload.state, State::Denied);
            Ok(preload)
        }

        fn compile_only_package_owned_cleanup_api_retains_real_original_after_caller_drop(
            source: Rc<WintunSource>,
            originals: &mut impl OriginalDevices,
        ) -> std::result::Result<
            package::CheckedOriginalPackage,
            crate::windows::member_carrier_wintun_package::Error,
        > {
            let mut package = package::from_original_source(&source)?;
            drop(source);
            package.reattest()?;
            package.reattest_owned(originals)?;
            package.deny_forward();
            package.reattest_owned_cleanup(originals)?;
            Ok(package)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_preload_denial_also_denies_package_at_all_error_and_unwind_boundaries() {
        for previously_verified in [false, true] {
            for failed in [Step::SourceBefore, Step::Package, Step::SourceAfter] {
                for unwind in [false, true] {
                    let mut state = if previously_verified {
                        State::Verified
                    } else {
                        State::Denied
                    };
                    // A prior final-source failure can leave a package valid
                    // behind the denied preload. Cleanup must revoke that too.
                    let mut package_valid = true;
                    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        recheck_package(
                            &mut state,
                            &mut package_valid,
                            true,
                            |step, _| {
                                if step == failed {
                                    if unwind {
                                        panic!("injected source/package unwind");
                                    }
                                    return Err(Error::Conflict);
                                }
                                Ok(())
                            },
                            |valid| *valid = false,
                        )
                    }));
                    if unwind {
                        assert!(outcome.is_err());
                    } else {
                        assert_eq!(outcome.unwrap(), Err(Error::Conflict));
                    }
                    assert_eq!(state, State::Denied);
                    assert!(!package_valid);
                    recheck_package(
                        &mut state,
                        &mut package_valid,
                        true,
                        |_, _| Ok(()),
                        |valid| *valid = false,
                    )
                    .unwrap();
                    assert_eq!(state, State::Denied);
                    assert!(!package_valid);
                    assert_eq!(
                        recheck_package(
                            &mut state,
                            &mut package_valid,
                            false,
                            |_, _| panic!("forward checks must stay refused"),
                            |valid| *valid = false,
                        ),
                        Err(Error::Conflict)
                    );
                }
            }
        }
    }

    #[test]
    fn cleanup_preload_success_cannot_hide_a_previously_valid_package_behind_denial() {
        for previously_verified in [false, true] {
            let mut state = if previously_verified {
                State::Verified
            } else {
                State::Denied
            };
            let mut package_valid = true;
            let mut steps = vec![];
            recheck_package(
                &mut state,
                &mut package_valid,
                true,
                |step, _| {
                    steps.push(step);
                    Ok(())
                },
                |valid| *valid = false,
            )
            .unwrap();
            assert_eq!(
                steps,
                [Step::SourceBefore, Step::Package, Step::SourceAfter]
            );
            assert_eq!(package_valid, previously_verified);
            assert_eq!(state == State::Verified, previously_verified);
        }
    }

    #[test]
    fn cleanup_source_package_source_preserves_prior_state_without_forward_rearm() {
        for previously_verified in [false, true] {
            let mut state = if previously_verified {
                State::Verified
            } else {
                State::Denied
            };
            let mut observed = vec![];
            for _ in 0..2 {
                recheck_cleanup(&mut state, |step| {
                    observed.push(step);
                    Ok(())
                })
                .unwrap();
            }
            assert_eq!(
                observed,
                [
                    Step::SourceBefore,
                    Step::Package,
                    Step::SourceAfter,
                    Step::SourceBefore,
                    Step::Package,
                    Step::SourceAfter,
                ]
            );
            if previously_verified {
                assert_eq!(state, State::Verified);
                recheck(&mut state, |_| Ok(())).unwrap();
            } else {
                assert_eq!(state, State::Denied);
                assert_eq!(
                    recheck(&mut state, |_| panic!("must not retry")),
                    Err(Error::Conflict)
                );
            }
        }
    }

    #[test]
    fn cleanup_error_or_unwind_at_each_source_package_boundary_keeps_state_denied() {
        for previously_verified in [false, true] {
            for failed in [Step::SourceBefore, Step::Package, Step::SourceAfter] {
                for unwind in [false, true] {
                    let mut state = if previously_verified {
                        State::Verified
                    } else {
                        State::Denied
                    };
                    let mut observed = vec![];
                    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        recheck_cleanup(&mut state, |step| {
                            observed.push(step);
                            if step == failed {
                                if unwind {
                                    panic!("injected cleanup check unwind");
                                }
                                return Err(Error::Conflict);
                            }
                            Ok(())
                        })
                    }));
                    if unwind {
                        assert!(outcome.is_err());
                    } else {
                        assert_eq!(outcome.unwrap(), Err(Error::Conflict));
                    }
                    assert_eq!(observed.last(), Some(&failed));
                    assert_eq!(state, State::Denied);
                    assert_eq!(
                        recheck(&mut state, |_| panic!("must not retry")),
                        Err(Error::Conflict)
                    );
                    recheck_cleanup(&mut state, |_| Ok(())).unwrap();
                    assert_eq!(state, State::Denied);
                }
            }
        }
    }

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
