//! Current cleanup timing only. Never an old SDK receipt or effect authority.
#![allow(dead_code)] // Factory remains gated until the concrete consumer is joined.

use crate::member_native_deadline::{Deadline, Factory, Failure};
use std::{cell::Cell, io};

pub(crate) struct ColdCall<S, F: Factory> {
    scope: S,
    timing: Deadline<S, F>,
    calling: Cell<bool>,
    attempted: Cell<bool>,
    failed: Cell<bool>,
}
fn denied() -> io::Error {
    io::Error::other("cold_cleanup_current_call_required")
}
impl<S: Clone + Eq, F: Factory> ColdCall<S, F> {
    pub(crate) fn new(scope: S, factory: F) -> Self {
        Self {
            timing: Deadline::new(scope.clone(), factory),
            scope,
            calling: Cell::new(false),
            attempted: Cell::new(false),
            failed: Cell::new(false),
        }
    }
    /// Caller must independently authenticate current signed process and old
    /// obligations before capture and around EVERY effect. This is timing only.
    pub(crate) fn run<T>(
        &self,
        scope: &S,
        authenticate: impl Fn() -> io::Result<()>,
        call: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<T> {
        if scope != &self.scope || self.attempted.replace(true) || self.failed.get() {
            self.failed.set(true);
            return Err(denied());
        }
        let mut flight = Flight {
            owner: self,
            success: false,
        };
        authenticate()?;
        let outcome = self.timing.run(scope, || {
            self.calling.set(true);
            self.with_call(scope, &authenticate)?;
            let result = call()?;
            self.with_call(scope, &authenticate)?;
            Ok(result)
        });
        self.calling.set(false);
        let output = match outcome {
            Ok(output) => output,
            Err(Failure::Native(error)) => return Err(error),
            Err(Failure::Supervisor(_)) => return Err(denied()),
        };
        if self.failed.get() {
            return Err(denied());
        }
        authenticate()?;
        flight.success = true;
        Ok(output)
    }
    /// Read/callback inside the SAME actual current hard-call sequence. No
    /// idle bit, retained pin, equal context or earlier success opens a window.
    pub(crate) fn with_call<T>(
        &self,
        scope: &S,
        read: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<T> {
        if scope != &self.scope || !self.calling.get() || self.failed.get() {
            self.failed.set(true);
            return Err(denied());
        }
        let mut flight = Flight {
            owner: self,
            success: false,
        };
        let pin = self.timing.pin().map_err(|_| denied())?;
        self.timing.verify_call(&pin, scope).map_err(|_| denied())?;
        let output = read()?;
        self.timing.verify_call(&pin, scope).map_err(|_| denied())?;
        if self.failed.get() {
            return Err(denied());
        }
        flight.success = true;
        Ok(output)
    }
}
struct Flight<'a, S: Clone + Eq, F: Factory> {
    owner: &'a ColdCall<S, F>,
    success: bool,
}
impl<S: Clone + Eq, F: Factory> Drop for Flight<'_, S, F> {
    fn drop(&mut self) {
        if !self.success {
            self.owner.failed.set(true);
        }
    }
}

#[cfg(test)]
#[path = "member_cold_deadline_tests.rs"]
mod tests;
