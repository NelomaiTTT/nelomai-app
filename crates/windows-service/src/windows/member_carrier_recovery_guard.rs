//! Concrete cold static BLOCK-only cleanup. No old SDK owner reconstruction.
#![allow(dead_code)] // Factory join follows independent native review.

use super::{
    member_carrier_guard::{self as guard, ColdGuardPolicies, ColdStaticAuthorization},
    member_carrier_recovery::native::{NativeFactoryRecoveryEntry, NativeNonWfpEmptyRead},
    member_native_deadline::NativeColdDeadline,
};
use crate::{
    member_carrier_guard::{GuardError, Result as GuardResult},
    member_carrier_native_ownership::Context,
};
use nelomai_client_tunnel::redundancy::SessionScope;
use std::{
    cell::{Cell, RefCell},
    io,
    rc::Rc,
};

fn denied() -> io::Error {
    io::Error::other("cold_static_guard_cleanup_pending")
}

struct AuthorizationFlight<'a> {
    authority: &'a NativeColdGuardAuthority,
    success: bool,
}
impl Drop for AuthorizationFlight<'_> {
    fn drop(&mut self) {
        self.authority.busy.set(false);
        if !self.success {
            self.authority.failed.set(true);
        }
    }
}
struct NativeColdGuardAuthority {
    entry: Rc<NativeFactoryRecoveryEntry>,
    context: Context,
    non_wfp: Rc<NativeNonWfpEmptyRead>,
    timing: Rc<NativeColdDeadline>,
    busy: Cell<bool>,
    failed: Cell<bool>,
}
// SAFETY: no constructor from foreign bytes/SDK handles/Source. Retained actual
// signed Engine/protected staged-helper entry and mutation owner, independent actual creator-death and
// full non-WFP scanner surround EVERY callback inside the same newly captured
// current-process hard watchdog Calling. The scanner holds original protected
// records unchanged across the callback. GuardPolicy remains DATA only.
// A swallowed reentry/error or unwind poisons this issuer permanently.
unsafe impl ColdStaticAuthorization for NativeColdGuardAuthority {
    fn with_cleanup_authority<T>(
        &self,
        scope: &SessionScope,
        read: impl FnOnce(&ColdGuardPolicies) -> GuardResult<T>,
    ) -> GuardResult<T> {
        if self.failed.get() || self.busy.replace(true) || *scope != self.context.intent.scope {
            self.failed.set(true);
            return Err(GuardError::Conflict);
        }
        let mut flight = AuthorizationFlight {
            authority: self,
            success: false,
        };
        let output = self
            .timing
            .with_current_call(scope, || {
                self.entry.require_bounded_cleanup_execution()?;
                self.non_wfp.inspect(|facts| {
                    if facts.context.as_ref() != Some(&self.context) || self.failed.get() {
                        return Err(denied());
                    }
                    let record = facts.guard.as_ref().ok_or_else(denied)?;
                    let policies = ColdGuardPolicies::from_authenticated_record(record)
                        .map_err(|_| denied())?;
                    let output = read(&policies).map_err(|_| denied())?;
                    if self.failed.get() {
                        return Err(denied());
                    }
                    self.entry.require_bounded_cleanup_execution()?;
                    Ok(output)
                })
            })
            .map_err(|_| GuardError::Conflict)?;
        if self.failed.get() {
            return Err(GuardError::Conflict);
        }
        flight.success = true;
        Ok(output)
    }
}

/// Caller retains this entire composition BEFORE cleanup(). Actual static
/// engine/transaction/commit outputs remain in `issuer` before postflight.
/// Unknown result cannot drop a reconstructed owner or retire the claim.
pub(crate) struct NativeColdGuardCleanup {
    scope: SessionScope,
    authority: Rc<NativeColdGuardAuthority>,
    issuer: RefCell<Option<Rc<guard::NativeColdStaticCleanup<NativeColdGuardAuthority>>>>,
    attempted: Cell<bool>,
    completed: Cell<bool>,
}
impl NativeColdGuardCleanup {
    pub(crate) fn new(entry: Rc<NativeFactoryRecoveryEntry>) -> io::Result<Self> {
        let facts = entry.retained_facts()?;
        let context = facts.context.as_ref().ok_or_else(denied)?.clone();
        if facts.guard.is_none() {
            return Err(denied());
        }
        entry.require_bounded_cleanup_execution()?;
        let timing = Rc::new(NativeColdDeadline::new(entry.clone(), context.clone())?);
        let non_wfp = entry.native_non_wfp_empty_authority();
        Ok(Self {
            scope: context.intent.scope.clone(),
            authority: Rc::new(NativeColdGuardAuthority {
                entry,
                context,
                timing,
                non_wfp,
                busy: Cell::new(false),
                failed: Cell::new(false),
            }),
            issuer: RefCell::new(None),
            attempted: Cell::new(false),
            completed: Cell::new(false),
        })
    }
    pub(crate) fn cleanup(&self) -> io::Result<()> {
        if self.attempted.replace(true) || self.completed.get() {
            return Err(denied());
        }
        self.authority.timing.run(|| {
            let issued = guard::issue_cold_static_cleanup(
                self.scope.clone(),
                self.authority.clone(),
                |issuer| {
                    let mut destination = self
                        .issuer
                        .try_borrow_mut()
                        .map_err(|_| GuardError::Conflict)?;
                    if destination.is_some() {
                        return Err(GuardError::Conflict);
                    }
                    *destination = Some(issuer);
                    Ok(())
                },
            )
            .map_err(|_| denied())?;
            let retained = self
                .issuer
                .try_borrow()
                .map_err(|_| denied())?
                .as_ref()
                .ok_or_else(denied)?
                .clone();
            if !Rc::ptr_eq(&issued, &retained) {
                return Err(denied());
            }
            retained.cleanup().map_err(|_| denied())?;
            let (committed, complete, failed) = retained.disposition();
            if !committed || !complete || failed || self.authority.failed.get() {
                return Err(denied());
            }
            self.authority.entry.require_bounded_cleanup_execution()?;
            Ok(())
        })?;
        self.completed.set(true);
        Ok(())
    }
}
