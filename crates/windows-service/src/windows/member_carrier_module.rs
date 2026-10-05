//! Retained original DLL loading only; never NIC/key/row/effect authority.
#![allow(dead_code)] // Carrier factory is still gated on lifecycle integration.

#[cfg(windows)]
use super::member_carrier_terminal_release::TerminalCallState;
#[cfg(not(windows))]
use crate::member_carrier_terminal_release::TerminalCallState;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    Conflict,
    Native,
    Cancelled,
}
pub(crate) type Result<T> = std::result::Result<T, Error>;

/// Private factual comparison used only after both native sources are freshly
/// authenticated. Equal data never issues a module/PIN/SDK capability.
pub(super) fn compare_process_source_origin<T>(
    original_owner: &std::sync::Arc<T>,
    current_owner: &std::sync::Arc<T>,
    original_identity: &nelomai_contracts::dispatcher::EngineIdentity,
    current_identity: &nelomai_contracts::dispatcher::EngineIdentity,
    original_file: (u32, u32, u32),
    current_file: (u32, u32, u32),
) -> Result<()> {
    if !std::sync::Arc::ptr_eq(original_owner, current_owner)
        || original_identity != current_identity
        || original_file != current_file
        || (original_file.1 == 0 && original_file.2 == 0)
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

/// Native instantiation retains ONLY process source/engine owner + actual PIN
/// return. Never retain a session Module/Release/valid/serialized lock here.
struct ProcessAnchor<S, P> {
    source: S,
    ack: RefCell<Option<Rc<P>>>,
    pin_call: TerminalCallState,
    reading: Cell<bool>,
    tainted: Cell<bool>,
}
struct ProcessAnchorRegistry<S, P> {
    original: RefCell<Option<Rc<ProcessAnchor<S, P>>>>,
}
impl<S, P> ProcessAnchorRegistry<S, P> {
    fn new() -> Self {
        Self {
            original: RefCell::new(None),
        }
    }
    fn select(&self, source: S, claim: &AtomicBool) -> Result<(Rc<ProcessAnchor<S, P>>, bool)> {
        let mut slot = self
            .original
            .try_borrow_mut()
            .map_err(|_| Error::Conflict)?;
        if let Some(original) = slot.as_ref() {
            return Ok((original.clone(), false));
        }
        claim
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::Conflict)?;
        let original = Rc::new(ProcessAnchor::new(source));
        *slot = Some(original.clone()); // process source/owner before ANY fallible boundary
        Ok((original, true))
    }
    fn inspect_original(
        &self,
        expected: &Rc<ProcessAnchor<S, P>>,
        read: impl FnOnce(&S, &P) -> Result<()>,
    ) -> Result<()> {
        let original = self
            .original
            .try_borrow()
            .map_err(|_| Error::Conflict)?
            .as_ref()
            .ok_or(Error::Conflict)?
            .clone();
        if !Rc::ptr_eq(&original, expected) {
            return Err(Error::Conflict);
        }
        original.inspect(read)
    }
}
impl<S, P> Drop for ProcessAnchorRegistry<S, P> {
    fn drop(&mut self) {
        if let Some(original) = self.original.get_mut().take() {
            std::mem::forget(original);
        }
    }
}
impl<S, P> ProcessAnchor<S, P> {
    fn new(source: S) -> Self {
        Self {
            source,
            ack: RefCell::new(None),
            pin_call: TerminalCallState::new(),
            reading: Cell::new(false),
            tainted: Cell::new(false),
        }
    }
    fn pin(
        &self,
        check: impl FnOnce() -> Result<()>,
        native: impl FnOnce() -> Result<P>,
        post: impl FnOnce(&Rc<P>) -> Result<()>,
    ) -> Result<()> {
        let mut error = None;
        let result = self
            .pin_call
            .run(|| {
                if self.tainted.get() || self.ack.borrow().is_some() {
                    return Err(std::io::Error::other("anchor_unknown"));
                }
                let action = || {
                    check()?;
                    if self.tainted.get() {
                        return Err(Error::Conflict);
                    }
                    let ack = Rc::new(native()?);
                    *self.ack.borrow_mut() = Some(ack.clone()); // native PIN ACK BEFORE postflight
                    if self.tainted.get() {
                        return Err(Error::Conflict);
                    }
                    post(&ack)
                };
                action().map_err(|e| {
                    error = Some(e);
                    std::io::Error::other("anchor_pin_failed")
                })
            })
            .map_err(|_| error.unwrap_or(Error::Conflict));
        // A nested PIN rejected by TerminalCallState must revoke its caller
        // immediately, not only when the outer flight eventually returns.
        if result.is_err() {
            self.tainted.set(true);
        }
        result
    }
    fn inspect(&self, read: impl FnOnce(&S, &P) -> Result<()>) -> Result<()> {
        self.pin_call.verify().map_err(|_| Error::Conflict)?;
        if self.tainted.get() || self.reading.replace(true) {
            self.tainted.set(true);
            return Err(Error::Conflict);
        }
        let mut guard = ProcessAnchorRead {
            original: self,
            completed: false,
        };
        let ack = self
            .ack
            .try_borrow()
            .map_err(|_| Error::Conflict)?
            .as_ref()
            .ok_or(Error::Conflict)?
            .clone();
        read(&self.source, &ack)?;
        if self.tainted.get() {
            return Err(Error::Conflict);
        }
        guard.completed = true;
        Ok(())
    }
}
struct ProcessAnchorRead<'a, S, P> {
    original: &'a ProcessAnchor<S, P>,
    completed: bool,
}
impl<S, P> Drop for ProcessAnchorRead<'_, S, P> {
    fn drop(&mut self) {
        if !self.completed {
            self.original.tainted.set(true);
        }
        self.original.reading.set(false);
    }
}

/// Only the slow OS/authentication boundary is injected. No successful defaults.
trait Kernel {
    type Lease;
    type Module: Clone;
    fn source(&mut self) -> Result<()>;
    fn absent_module(&mut self) -> Result<()>;
    fn lease(&mut self, cancelled: &AtomicBool) -> Result<Self::Lease>;
    fn verify_lease(&mut self, lease: &mut Self::Lease, cancelled: &AtomicBool) -> Result<()>;
    fn package(&mut self) -> Result<()>;
    fn load(&mut self) -> Result<Self::Module>;
    /// Publish the actual OS return after its owning slot is populated, then
    /// establish the code lifetime floor through that SAME retained module.
    /// Failure retains the original ACK and never publishes successful load.
    fn original_load_retained(
        &mut self,
        module: &Self::Module,
        lease: &mut Self::Lease,
        cancelled: &AtomicBool,
    ) -> Result<()>;
    fn module(&mut self, module: &Self::Module) -> Result<()>;
}

struct Loaded<K: Kernel> {
    // Drop the original DLL reference BEFORE releasing the package/source pins.
    module: K::Module,
    kernel: K,
    valid: Rc<Cell<bool>>,
}

/// Exact retained native return, never an image/SDK/effect permission.
struct OriginalModuleLoadRead<M> {
    module: M,
    valid: Rc<Cell<bool>>,
    available: Rc<Cell<bool>>,
    inspecting: Cell<bool>,
    tainted: Cell<bool>,
}
struct LoadReadInspection<'a, M> {
    original: &'a OriginalModuleLoadRead<M>,
    completed: bool,
}
impl<M> Drop for LoadReadInspection<'_, M> {
    fn drop(&mut self) {
        if !self.completed {
            self.original.tainted.set(true);
        }
        self.original.inspecting.set(false);
    }
}
impl<M> OriginalModuleLoadRead<M> {
    fn inspect_release_pre_with(
        &self,
        release: &ModuleRelease,
        loans: &LeasePins,
        cancelled: &AtomicBool,
        read: impl FnOnce(&M) -> Result<()>,
    ) -> Result<()> {
        // Deny before ANY source/image/SDK query. Merely having an attempted
        // gate is insufficient: an error/unwind leaves that bit set forever.
        if !release.pre_read_available() {
            return Err(Error::Conflict);
        }
        if self.available.get()
            || self.valid.get()
            || self.tainted.get()
            || !loans.is_empty()
            || self.inspecting.replace(true)
        {
            release.tainted.set(true);
            return Err(Error::Conflict);
        }
        let mut inspection = ReleaseReadInspection {
            read: LoadReadInspection {
                original: self,
                completed: false,
            },
            release,
        };
        checkpoint(cancelled)?;
        read(&self.module)?;
        checkpoint(cancelled)?;
        if !release.pre_read_available()
            || !loans.is_empty()
            || self.available.get()
            || self.valid.get()
            || self.tainted.get()
        {
            return Err(Error::Conflict);
        }
        inspection.read.completed = true;
        // Query-only: never restore ordinary availability or forward validity.
        Ok(())
    }
    fn inspect_cleanup_with(
        &self,
        cancelled: &AtomicBool,
        available: impl FnOnce() -> Result<()>,
        read: impl FnOnce(&M) -> Result<()>,
    ) -> Result<()> {
        image_cleanup_read(&self.valid, || {
            if self.tainted.get() || self.inspecting.replace(true) {
                self.tainted.set(true);
                return Err(Error::Conflict);
            }
            let mut inspection = LoadReadInspection {
                original: self,
                completed: false,
            };
            if !self.available.get() {
                return Err(Error::Conflict);
            }
            checkpoint(cancelled)?;
            available()?; // deny disposition BEFORE any SDK/image query
            read(&self.module)?;
            checkpoint(cancelled)?;
            if self.tainted.get() {
                return Err(Error::Conflict);
            }
            inspection.completed = true;
            Ok(())
        })
    }
}
struct ReleaseReadInspection<'a, M> {
    read: LoadReadInspection<'a, M>,
    release: &'a ModuleRelease,
}
impl<M> Drop for ReleaseReadInspection<'_, M> {
    fn drop(&mut self) {
        if !self.read.completed {
            // A supplier catching a read error cannot proceed to native free.
            self.release.tainted.set(true);
        }
    }
}

/// Actor-retained ORIGINAL load outcome. Failure after the OS ACK keeps the
/// exact owner accessible and denies another load; Drop is not unload authority.
struct LoadAttempt<K: Kernel> {
    attempted: bool,
    owner: Option<Loaded<K>>,
    original_read: RefCell<Option<Rc<OriginalModuleLoadRead<K::Module>>>>,
    read_capture: TerminalCallState,
    read_available: Rc<Cell<bool>>,
}
// Borrowed original-reference backend inputs, not authorization or a permit.
struct OriginalLoadRelease<'a, M> {
    original: &'a Rc<OriginalModuleLoadRead<M>>,
    same_module: fn(&M, &M) -> bool,
    terminal: &'a mut Option<(M, Rc<Cell<bool>>)>,
    release: &'a ModuleRelease,
    loans: &'a LeasePins,
}
/// Unknown disposition retains supplier and immutable receipt until process
/// exit, even if the caller loses this stack frame. No native effect in Drop.
struct UnknownReleaseRoots<T>(Option<T>);
impl<T> Drop for UnknownReleaseRoots<T> {
    fn drop(&mut self) {
        if let Some(roots) = self.0.take() {
            std::mem::forget(roots);
        }
    }
}
impl<K: Kernel> LoadAttempt<K> {
    fn release_original_into<R, P, A>(
        &mut self,
        selected: OriginalLoadRelease<'_, K::Module>,
        roots: (Rc<R>, Rc<P>),
        retained: &mut Option<A>,
        pre: impl FnOnce(&Rc<R>, &Rc<P>) -> Result<()>,
        native_return: impl FnOnce(&Rc<R>, &Rc<P>) -> Result<A>,
        post: impl FnOnce(&A) -> Result<()>,
    ) -> Result<()> {
        let mut roots = UnknownReleaseRoots(Some(roots));
        // Pure receipt identity must be sampled BEFORE revocation. It is not
        // authorization and its failure is consumed INSIDE the one-shot gate.
        let initial = self.verify_original_load_read(selected.original, selected.same_module);
        self.deny_original_load_reads();
        let owner = self.owner.as_ref().ok_or(Error::Conflict)?;
        let already_selected = selected.terminal.is_some();
        if !already_selected {
            *selected.terminal = Some((owner.module.clone(), owner.valid.clone()));
        }
        let (receipt, proof) = roots.0.as_ref().expect("retained release roots");
        selected.release.run_into(
            retained,
            || {
                initial?;
                if already_selected
                    || !selected.release.image_available()
                    || !selected.loans.is_empty()
                {
                    return Err(Error::Conflict);
                }
                pre(receipt, proof)?;
                if !selected.loans.is_empty() {
                    return Err(Error::Conflict);
                }
                Ok(())
            },
            || native_return(receipt, proof),
            |ack| {
                post(ack)?;
                if !selected.loans.is_empty() {
                    return Err(Error::Conflict);
                }
                Ok(())
            },
        )?;
        // ACK is in caller storage and postflight finished. Failure/unwind at
        // any earlier boundary leaves this exact Loaded owner in its slot.
        drop(self.owner.take().ok_or(Error::Conflict)?);
        drop(roots.0.take());
        Ok(())
    }
    fn verify_original_release(
        &self,
        read: &Rc<OriginalModuleLoadRead<K::Module>>,
        terminal: &Option<(K::Module, Rc<Cell<bool>>)>,
        release: &ModuleRelease,
        same_module: impl Fn(&K::Module, &K::Module) -> bool,
    ) -> Result<()> {
        let (module, valid) = terminal.as_ref().ok_or(Error::Conflict)?;
        if self
            .original_read
            .try_borrow()
            .map_err(|_| Error::Conflict)?
            .as_ref()
            .is_none_or(|original| !Rc::ptr_eq(original, read))
            || !same_module(module, &read.module)
            || !Rc::ptr_eq(valid, &read.valid)
            || !Rc::ptr_eq(&self.read_available, &read.available)
            || self.read_available.get()
            || valid.get()
            || !release.acknowledged()
            || !release.effect_started.get()
            || self.owner.as_ref().is_some_and(|owner| {
                !same_module(module, &owner.module) || !Rc::ptr_eq(valid, &owner.valid)
            })
        {
            return Err(Error::Conflict);
        }
        // Factual returned-original identity only. Never reads a released image
        // and never uses the now-revoked cleanup reader for authorization.
        Ok(())
    }
    fn verify_original_disposition(
        &self,
        read: &Rc<OriginalModuleLoadRead<K::Module>>,
        terminal: &Option<(K::Module, Rc<Cell<bool>>)>,
        release: &ModuleRelease,
        loans: &LeasePins,
        same_module: impl Fn(&K::Module, &K::Module) -> bool,
    ) -> Result<()> {
        self.verify_original_release(read, terminal, release, same_module)?;
        if self.owner.is_some()
            || !release.complete.get()
            || release.tainted.get()
            || !loans.is_empty()
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    fn deny_original_load_reads(&self) {
        self.read_available.set(false);
        if let Some(owner) = &self.owner {
            owner.valid.set(false);
        }
    }
    fn retain_original_load_read_into(
        &self,
        destination: &mut Option<Rc<OriginalModuleLoadRead<K::Module>>>,
        postflight: impl FnOnce(&Rc<OriginalModuleLoadRead<K::Module>>) -> Result<()>,
    ) -> Result<()> {
        let owner = self.owner.as_ref().ok_or(Error::Conflict)?;
        if !self.read_available.get() {
            return Err(Error::Conflict);
        }
        let mut callback_error = None;
        image_cleanup_read(&owner.valid, || {
            self.read_capture
                .run(|| {
                    if destination.is_some() || self.original_read.borrow().is_some() {
                        return Err(std::io::Error::other("duplicate_original_load_read"));
                    }
                    let read = Rc::new(OriginalModuleLoadRead {
                        module: owner.module.clone(),
                        valid: owner.valid.clone(),
                        available: self.read_available.clone(),
                        inspecting: Cell::new(false),
                        tainted: Cell::new(false),
                    });
                    *self.original_read.borrow_mut() = Some(read.clone());
                    *destination = Some(read.clone()); // actual owner ACK BEFORE postflight
                    if let Err(error) = postflight(&read) {
                        callback_error = Some(error);
                        return Err(std::io::Error::other("original_load_read_postflight"));
                    }
                    Ok(())
                })
                .map_err(|_| callback_error.unwrap_or(Error::Conflict))
        })
    }
    fn verify_original_load_read(
        &self,
        read: &Rc<OriginalModuleLoadRead<K::Module>>,
        same_module: impl FnOnce(&K::Module, &K::Module) -> bool,
    ) -> Result<()> {
        let owner = self.owner.as_ref().ok_or(Error::Conflict)?;
        if self
            .original_read
            .try_borrow()
            .map_err(|_| Error::Conflict)?
            .as_ref()
            .is_none_or(|original| !Rc::ptr_eq(original, read))
            || !Rc::ptr_eq(&owner.valid, &read.valid)
            || !Rc::ptr_eq(&self.read_available, &read.available)
            || !self.read_available.get()
            || !same_module(&owner.module, &read.module)
        {
            return Err(Error::Conflict);
        }
        // Factual receipt identity only, including capture postflight failure.
        Ok(())
    }
    fn empty() -> Self {
        Self {
            attempted: false,
            owner: None,
            original_read: RefCell::new(None),
            read_capture: TerminalCallState::new(),
            read_available: Rc::new(Cell::new(true)),
        }
    }
    fn load(&mut self, mut kernel: K, cancelled: &AtomicBool) -> Result<()> {
        if self.attempted || self.owner.is_some() {
            return Err(Error::Conflict);
        }
        self.attempted = true;
        checkpoint(cancelled)?;
        kernel.source()?;
        checkpoint(cancelled)?;
        kernel.absent_module()?;
        let mut lease = kernel.lease(cancelled)?;
        checkpoint(cancelled)?;
        kernel.source()?;
        kernel.package()?;
        kernel.source()?;
        kernel.verify_lease(&mut lease, cancelled)?;
        checkpoint(cancelled)?;
        kernel.absent_module()?;
        checkpoint(cancelled)?;
        let module = kernel.load()?;
        // The actual OS ACK is in the caller's original slot BEFORE every
        // fallible image/package/source read or unwind. No return value carries
        // this unique owner through a fallible postflight.
        self.owner = Some(Loaded {
            module,
            kernel,
            valid: Rc::new(Cell::new(false)),
        });
        let loaded = self.owner.as_mut().expect("retained OS load ACK");
        loaded
            .kernel
            .original_load_retained(&loaded.module, &mut lease, cancelled)?;
        loaded.kernel.module(&loaded.module)?;
        loaded.kernel.package()?;
        loaded.kernel.source()?;
        loaded.kernel.verify_lease(&mut lease, cancelled)?;
        checkpoint(cancelled)?;
        loaded.valid.set(true);
        Ok(())
    }
}
impl<K: Kernel> Drop for LoadAttempt<K> {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.take() {
            std::mem::forget(owner);
        }
    }
}

/// Resource ownership only. Release our original module reference before the
/// cooperative lease; additional source/runtime pins are retained by native.
#[must_use = "retain this owner across the separately authorized operation"]
struct HeldModule<M, L> {
    module: M,
    lease: L,
}
impl<M, L> HeldModule<M, L> {
    fn verify_with(
        &mut self,
        valid: &Cell<bool>,
        cleanup: bool,
        cancelled: &AtomicBool,
        check: impl FnOnce(&M, &mut L) -> Result<()>,
    ) -> Result<()> {
        let action = || {
            checkpoint(cancelled)?;
            check(&self.module, &mut self.lease)?;
            checkpoint(cancelled)
        };
        if cleanup {
            image_cleanup_read(valid, action)
        } else {
            image_read(valid, action)
        }
    }
}

fn image_read(valid: &Cell<bool>, action: impl FnOnce() -> Result<()>) -> Result<()> {
    if !valid.get() {
        return Err(Error::Conflict);
    }
    valid.set(false);
    action()?;
    valid.set(true);
    Ok(())
}

fn image_cleanup_read(valid: &Cell<bool>, action: impl FnOnce() -> Result<()>) -> Result<()> {
    // Factual original-resource reads only, NOT permission to end/close. A
    // poisoned forward gate stays poisoned even when current cleanup facts
    // authenticate. Errors/unwinds poison a still-live forward gate as well.
    let was_valid = valid.replace(false);
    action()?;
    valid.set(was_valid);
    Ok(())
}

fn checkpoint(cancelled: &AtomicBool) -> Result<()> {
    if cancelled.load(Ordering::Acquire) {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}

/// One irreversible explicit release attempt. No implicit OS call in Drop.
pub(crate) struct ModuleRelease {
    attempted: Cell<bool>,
    busy: Cell<bool>,
    checking: Cell<bool>,
    tainted: Cell<bool>,
    effect_started: Cell<bool>,
    unloaded: Cell<bool>,
    complete: Cell<bool>,
}
// Actual active native preflight frame, not a saved observation of attempted.
struct ModulePreFrame<'a> {
    release: &'a ModuleRelease,
    completed: bool,
}
impl Drop for ModulePreFrame<'_> {
    fn drop(&mut self) {
        self.release.checking.set(false);
        if !self.completed {
            self.release.tainted.set(true);
        }
    }
}
// Counts actual OriginalModuleLease owners, not image Rc aliases or JSON.
// Impossible duplicate/overflow bookkeeping poisons unload rather than guessing.
struct LeasePins {
    held: Cell<usize>,
    conflicted: Cell<bool>,
}
struct ReadLeasePin<'a>(&'a LeasePins);
impl Drop for ReadLeasePin<'_> {
    fn drop(&mut self) {
        self.0.release();
    }
}
impl LeasePins {
    fn retain_read(&self) -> Result<ReadLeasePin<'_>> {
        self.retain()?;
        Ok(ReadLeasePin(self))
    }
    fn new() -> Self {
        Self {
            held: Cell::new(0),
            conflicted: Cell::new(false),
        }
    }
    fn retain(&self) -> Result<()> {
        if self.conflicted.get() {
            return Err(Error::Conflict);
        }
        let Some(next) = self.held.get().checked_add(1) else {
            self.conflicted.set(true);
            return Err(Error::Conflict);
        };
        self.held.set(next);
        Ok(())
    }
    fn release(&self) {
        match self.held.get().checked_sub(1) {
            Some(next) => self.held.set(next),
            None => self.conflicted.set(true),
        }
    }
    fn is_empty(&self) -> bool {
        self.held.get() == 0 && !self.conflicted.get()
    }
}
impl ModuleRelease {
    pub(crate) fn new() -> Self {
        Self {
            attempted: Cell::new(false),
            busy: Cell::new(false),
            checking: Cell::new(false),
            tainted: Cell::new(false),
            effect_started: Cell::new(false),
            unloaded: Cell::new(false),
            complete: Cell::new(false),
        }
    }
    pub(crate) fn run(
        &self,
        check: impl FnOnce() -> Result<()>,
        unload: impl FnOnce() -> Result<()>,
        post: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        self.run_into(&mut None, check, unload, |_| post())
    }
    /// Retain the exact returned original before any fallible postflight. This
    /// protocol stores facts only; native capability issuance stays sealed.
    fn run_into<T>(
        &self,
        retained: &mut Option<T>,
        check: impl FnOnce() -> Result<()>,
        unload: impl FnOnce() -> Result<T>,
        post: impl FnOnce(&T) -> Result<()>,
    ) -> Result<()> {
        if retained.is_some() {
            self.tainted.set(true);
            return Err(Error::Conflict);
        }
        if self.attempted.replace(true) || self.busy.replace(true) {
            self.tainted.set(true);
            return Err(Error::Conflict);
        }
        // Begin poisoned. A failed or unwound attempt can never be retried.
        // Reentry sets tainted even when its error is caught by a callback.
        self.checking.set(true);
        let mut pre_frame = ModulePreFrame {
            release: self,
            completed: false,
        };
        check()?;
        pre_frame.completed = true;
        drop(pre_frame); // close query aperture BEFORE selecting native effect
        if self.tainted.get() {
            return Err(Error::Conflict);
        }
        self.effect_started.set(true);
        *retained = Some(unload()?);
        // Retain the actual native success BEFORE fallible postflight.
        self.unloaded.set(true);
        post(retained.as_ref().ok_or(Error::Conflict)?)?;
        if self.tainted.get() {
            return Err(Error::Conflict);
        }
        self.complete.set(true);
        self.busy.set(false);
        Ok(())
    }
    fn image_available(&self) -> bool {
        !self.effect_started.get()
    }
    fn pre_read_available(&self) -> bool {
        self.attempted.get()
            && self.busy.get()
            && self.checking.get()
            && !self.effect_started.get()
            && !self.unloaded.get()
            && !self.complete.get()
            && !self.tainted.get()
    }
    /// Actual returned native reference-release ACK only. A failed postflight
    /// does not erase this factual ACK or authorize whole-call/module release.
    pub(crate) fn acknowledged(&self) -> bool {
        self.unloaded.get()
    }
    pub(crate) fn was_attempted(&self) -> bool {
        self.attempted.get()
    }
}
#[cfg(test)]
fn load<K: Kernel>(kernel: K, cancelled: &AtomicBool) -> Result<Loaded<K>> {
    // Test-only convenient successful-owner handoff; production retains the
    // LoadAttempt in its actual actor. Error/unwind preserves unknown ACKs.
    let mut attempt = LoadAttempt::empty();
    attempt.load(kernel, cancelled)?;
    attempt.owner.take().ok_or(Error::Conflict)
}
impl<K: Kernel> Loaded<K> {
    /// Full factual refresh with outer authentication inside the poison gate.
    /// The returned owner keeps the very lease used for this refresh.
    fn retain_with<P>(
        &mut self,
        cancelled: &AtomicBool,
        cleanup: bool,
        originals: &mut P,
        mut authenticate: impl FnMut(&mut K, &mut P) -> Result<()>,
        mut package: impl FnMut(&mut K, &mut P) -> Result<()>,
    ) -> Result<HeldModule<K::Module, K::Lease>>
    where
        K::Module: Clone,
    {
        let was_valid = self.valid.replace(false);
        if !cleanup && !was_valid {
            return Err(Error::Conflict);
        }
        checkpoint(cancelled)?;
        authenticate(&mut self.kernel, originals)?;
        checkpoint(cancelled)?;
        let mut lease = self.kernel.lease(cancelled)?;
        checkpoint(cancelled)?;
        self.kernel.source()?;
        checkpoint(cancelled)?;
        package(&mut self.kernel, originals)?;
        checkpoint(cancelled)?;
        self.kernel.source()?;
        checkpoint(cancelled)?;
        self.kernel.verify_lease(&mut lease, cancelled)?;
        checkpoint(cancelled)?;
        self.kernel.module(&self.module)?;
        checkpoint(cancelled)?;
        self.kernel.verify_lease(&mut lease, cancelled)?;
        checkpoint(cancelled)?;
        authenticate(&mut self.kernel, originals)?;
        checkpoint(cancelled)?;
        let held = HeldModule {
            module: self.module.clone(),
            lease,
        };
        self.valid.set(was_valid);
        Ok(held)
    }
    /// Factual full revalidation for separately authorized cleanup. Inherited
    /// forward poison is preserved; native lifecycle effects are not exposed.
    fn reattest_cleanup_with(
        &mut self,
        cancelled: &AtomicBool,
        mut package: impl FnMut(&mut K) -> Result<()>,
    ) -> Result<()> {
        let valid = self.valid.clone();
        image_cleanup_read(&valid, || {
            checkpoint(cancelled)?;
            let mut lease = self.kernel.lease(cancelled)?;
            self.kernel.source()?;
            package(&mut self.kernel)?;
            self.kernel.source()?;
            self.kernel.verify_lease(&mut lease, cancelled)?;
            self.kernel.module(&self.module)?;
            self.kernel.verify_lease(&mut lease, cancelled)?;
            checkpoint(cancelled)
        })
    }
    fn reattest_cold(&mut self, cancelled: &AtomicBool) -> Result<()> {
        self.reattest_with(cancelled, K::package)
    }
    fn reattest_with(
        &mut self,
        cancelled: &AtomicBool,
        mut package: impl FnMut(&mut K) -> Result<()>,
    ) -> Result<()> {
        if !self.valid.get() {
            return Err(Error::Conflict);
        }
        // A late error, cancellation or unwind cannot revive cached load trust.
        self.valid.set(false);
        checkpoint(cancelled)?;
        let mut lease = self.kernel.lease(cancelled)?;
        self.kernel.source()?;
        package(&mut self.kernel)?;
        self.kernel.source()?;
        self.kernel.verify_lease(&mut lease, cancelled)?;
        self.kernel.module(&self.module)?;
        self.kernel.verify_lease(&mut lease, cancelled)?;
        checkpoint(cancelled)?;
        self.valid.set(true);
        Ok(())
    }
}

#[cfg(windows)]
pub(crate) mod native {
    use super::*;
    use crate::windows::{
        member_carrier_key_authority::{KeyLock, KeyLockPin, RuntimeRead},
        member_carrier_payload::native::WintunSource,
        member_carrier_preload::native::WintunPreload,
        member_carrier_wintun::Functions,
        member_carrier_wintun_lock::native::Lease,
    };
    use std::{ffi::c_void, mem::size_of, os::windows::ffi::OsStrExt, ptr::NonNull};
    use windows_sys::{
        core::w,
        Win32::{
            Foundation::{FreeLibrary, GetLastError, ERROR_MOD_NOT_FOUND},
            System::{
                LibraryLoader::{
                    GetModuleFileNameW, GetModuleHandleExW, GetModuleHandleW, GetProcAddress,
                    LoadLibraryExW, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                    GET_MODULE_HANDLE_EX_FLAG_PIN, LOAD_LIBRARY_SEARCH_SYSTEM32,
                },
                ProcessStatus::{K32GetModuleInformation, MODULEINFO},
                Threading::GetCurrentProcess,
            },
        },
    };

    // No Drop implementation: loss of an owner is NOT unload permission.
    // The OS reference stays mapped on unknown/error/unwind, until process exit.
    struct Module(
        NonNull<c_void>,
        ModuleRelease,
        LeasePins,
        RefCell<Option<Rc<NativeProcessAnchor>>>,
    );
    /// Sealed real native return. No owning session Module or Release state.
    struct NativeProcessPin {
        mapping: *mut c_void,
    }
    type NativeProcessAnchor = ProcessAnchor<Rc<WintunSource>, NativeProcessPin>;
    static PROCESS_ANCHOR_CLAIMED: AtomicBool = AtomicBool::new(false);
    thread_local! {
        // Thread exit retains this source/engine-owner anchor until process exit.
        // Other threads cannot adopt it: global claim + existing mapping deny.
        static PROCESS_ANCHOR: ProcessAnchorRegistry<Rc<WintunSource>, NativeProcessPin> = ProcessAnchorRegistry::new();
    }

    fn verify_anchor_mapping(
        original: &WintunSource,
        current: &WintunSource,
        pin: &NativeProcessPin,
        mapping: NonNull<c_void>,
    ) -> Result<()> {
        if pin.mapping != mapping.as_ptr() {
            return Err(Error::Conflict);
        }
        if std::ptr::eq(original, current) {
            // The registry retained this exact original Source at successful
            // PIN creation, including its nonzero file ID. Full mapping reads
            // reverify that SAME pinned file/ancestors/owner/signed runtime
            // before and after bounds/exports. There is no second source to
            // join; repeated comparisons of this object to itself add no facts.
            return verify_mapping(original, mapping);
        }
        current
            .verify_process_anchor_origin(original)
            .map_err(|_| Error::Conflict)?;
        verify_mapping(original, mapping)?;
        verify_mapping(current, mapping)?;
        current
            .verify_process_anchor_origin(original)
            .map_err(|_| Error::Conflict)
    }
    fn require_process_anchor(source: &Rc<WintunSource>, module: &Module) -> Result<()> {
        let root = module
            .3
            .try_borrow()
            .map_err(|_| Error::Conflict)?
            .as_ref()
            .ok_or(Error::Conflict)?
            .clone();
        PROCESS_ANCHOR.with(|registry| {
            registry.inspect_original(&root, |original, ack| {
                verify_anchor_mapping(original, source, ack, module.0)
            })
        })
    }
    fn establish_process_anchor(
        source: &Rc<WintunSource>,
        module: &Module,
        cancelled: &AtomicBool,
        postflight: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let (root, first) = PROCESS_ANCHOR
            .with(|registry| registry.select(source.clone(), &PROCESS_ANCHOR_CLAIMED))?;
        *module.3.try_borrow_mut().map_err(|_| Error::Conflict)? = Some(root.clone()); // before PIN/postflight
        if first {
            root.pin(
                || {
                    checkpoint(cancelled)?;
                    source
                        .verify_process_anchor_origin(&root.source)
                        .map_err(|_| Error::Conflict)?;
                    verify_mapping(source, module.0)?;
                    checkpoint(cancelled)
                },
                || {
                    let mut mapping = std::ptr::null_mut();
                    // SAFETY: actual original LoadLibrary ACK + freshly authenticated
                    // image/source; address lies in that image. This pins code for
                    // process lifetime only, never workers/resources/session ACKs.
                    if unsafe {
                        GetModuleHandleExW(
                            GET_MODULE_HANDLE_EX_FLAG_PIN | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                            module.0.as_ptr().cast(),
                            &mut mapping,
                        )
                    } == 0
                    {
                        return Err(Error::Native);
                    }
                    Ok(NativeProcessPin { mapping }) // retained before checking returned identity
                },
                |ack| {
                    verify_anchor_mapping(&root.source, source, ack, module.0)?;
                    postflight()?;
                    verify_anchor_mapping(&root.source, source, ack, module.0)?;
                    checkpoint(cancelled)
                },
            )?;
        } else {
            root.inspect(|original, ack| {
                verify_anchor_mapping(original, source, ack, module.0)?;
                postflight()?;
                verify_anchor_mapping(original, source, ack, module.0)?;
                checkpoint(cancelled)
            })?;
        }
        require_process_anchor(source, module)
    }
    struct Boundary {
        source: Rc<WintunSource>,
        package: Option<WintunPreload>,
        actual_load_returned: Rc<Cell<bool>>,
    }
    impl Kernel for Boundary {
        type Lease = Lease;
        type Module = Rc<Module>;
        fn source(&mut self) -> Result<()> {
            self.source.verify().map_err(|_| Error::Conflict)
        }
        fn absent_module(&mut self) -> Result<()> {
            let mapping = unsafe { GetModuleHandleW(w!("wintun.dll")) };
            if let Some(mapping) = NonNull::new(mapping) {
                // ONLY the actually pinned process original may remain mapped.
                // A new session still calls LoadLibrary and gets its OWN ACK.
                return PROCESS_ANCHOR.with(|registry| {
                    let root = registry
                        .original
                        .try_borrow()
                        .map_err(|_| Error::Conflict)?
                        .as_ref()
                        .ok_or(Error::Conflict)?
                        .clone();
                    root.inspect(|original, ack| {
                        verify_anchor_mapping(original, &self.source, ack, mapping)
                    })
                });
            }
            if unsafe { GetLastError() } != ERROR_MOD_NOT_FOUND
                || PROCESS_ANCHOR_CLAIMED.load(Ordering::Acquire)
            {
                return Err(Error::Native);
            }
            Ok(())
        }
        fn lease(&mut self, cancelled: &AtomicBool) -> Result<Lease> {
            Lease::take(cancelled, 5000).map_err(|_| Error::Conflict)
        }
        fn verify_lease(&mut self, lease: &mut Lease, cancelled: &AtomicBool) -> Result<()> {
            lease.verify(cancelled).map_err(|_| Error::Conflict)
        }
        fn package(&mut self) -> Result<()> {
            match &mut self.package {
                Some(package) => package.reattest().map_err(|_| Error::Conflict),
                None => {
                    self.package =
                        Some(WintunPreload::new(&self.source).map_err(|_| Error::Conflict)?);
                    Ok(())
                }
            }
        }
        fn load(&mut self) -> Result<Rc<Module>> {
            // The trusted source constructor accepts NO IPC path, authenticates
            // kernelcurrentexe, full signed installed payloads, held owner lock
            // and write/delete-denied source/ancestor handles. Only this fixed
            // absolute path can be loaded; dependencies search SYSTEM32 only.
            self.source()?;
            let path = self.source.path().map_err(|_| Error::Conflict)?;
            let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            let raw = unsafe {
                LoadLibraryExW(
                    path.as_ptr(),
                    std::ptr::null_mut(),
                    LOAD_LIBRARY_SEARCH_SYSTEM32,
                )
            };
            NonNull::new(raw)
                .map(|raw| {
                    Rc::new(Module(
                        raw,
                        ModuleRelease::new(),
                        LeasePins::new(),
                        RefCell::new(None),
                    ))
                })
                .ok_or(Error::Native)
        }
        fn module(&mut self, module: &Rc<Module>) -> Result<()> {
            verify_image(&self.source, module)
        }
        fn original_load_retained(
            &mut self,
            module: &Rc<Module>,
            lease: &mut Lease,
            cancelled: &AtomicBool,
        ) -> Result<()> {
            self.actual_load_returned.set(true);
            #[cfg(test)]
            super::super::member_carrier_factory_test_os::native_module_loaded(module);
            // The original loader ACK is already rooted, but package/image
            // postflight has not run. Retain the actual immutable-source code
            // PIN before a later normal Err can enter no-constructor cleanup.
            // Unknown PIN outcomes remain owned and deny SDK/release entry.
            self.verify_lease(lease, cancelled)?;
            let source = self.source.clone();
            establish_process_anchor(&source, module, cancelled, || {
                self.verify_lease(lease, cancelled)?;
                self.source()?;
                checkpoint(cancelled)
            })
        }
    }
    fn verify_image(source: &WintunSource, module: &Module) -> Result<()> {
        // An attempted native unload invalidates EVERY surviving image alias,
        // even if FreeLibrary failed or the caller lost its postflight ACK.
        // Deny before asking Windows about a possibly unmapped address.
        if !module.1.image_available() {
            return Err(Error::Conflict);
        }
        verify_mapping(source, module.0)
    }
    /// Factual original image read, independent of client Release/valid state.
    /// Used for authenticating the process anchor; never resolves a new owner.
    fn verify_mapping(source: &WintunSource, mapping: NonNull<c_void>) -> Result<()> {
        // path() performs the full original source/runtime/owner verification.
        // Acquire it BEFORE any mapping query, then reauthenticate the same
        // source after all bounds/exports. A separate verify() immediately
        // before path() repeats the complete signed payload read.
        let expected_path = source.path().map_err(|_| Error::Conflict)?.to_path_buf();
        let mut path = vec![0; 32768];
        let count =
            unsafe { GetModuleFileNameW(mapping.as_ptr(), path.as_mut_ptr(), path.len() as u32) }
                as usize;
        if count == 0 || count >= path.len() {
            return Err(Error::Native);
        }
        let actual = std::path::PathBuf::from(std::ffi::OsString::from_wide(&path[..count]));
        // Windows canonicalize returns an extended DOS path. Compare both
        // sides in that same representation; the original source's payload
        // and ancestors remain pinned and authenticated before and after this
        // mapping read. Canonical equality supplies no SDK/resource authority.
        let expected = std::fs::canonicalize(expected_path).map_err(|_| Error::Native)?;
        if std::fs::canonicalize(actual).map_err(|_| Error::Native)? != expected {
            return Err(Error::Conflict);
        }
        let mut info: MODULEINFO = unsafe { std::mem::zeroed() };
        if unsafe {
            K32GetModuleInformation(
                GetCurrentProcess(),
                mapping.as_ptr(),
                &mut info,
                size_of::<MODULEINFO>() as u32,
            )
        } == 0
        {
            return Err(Error::Native);
        }
        let base = mapping.as_ptr() as usize;
        if info.lpBaseOfDll != mapping.as_ptr()
            || info.SizeOfImage == 0
            || info.SizeOfImage > 16 * 1024 * 1024
        {
            return Err(Error::Conflict);
        }
        let end = base
            .checked_add(info.SizeOfImage as usize)
            .ok_or(Error::Conflict)?;
        // Verify nine required audited exports, NEVER call one. Reject any
        // export forwarded outside the original retained image, not merely
        // an expected symbol name on an arbitrary loaded module.
        let _functions = unsafe {
            Functions::resolve(|name| {
                GetProcAddress(mapping.as_ptr(), name.as_ptr().cast()).filter(|symbol| {
                    let address = *symbol as usize;
                    address >= base && address < end
                })
            })
        }
        .map_err(|_| Error::Conflict)?;
        source.verify().map_err(|_| Error::Conflict)
    }
    use std::os::windows::ffi::OsStringExt;

    /// Original source+DLL reference only. The cold package is independently
    /// verified under cooperative upstream installation locks. No constructor
    /// for ModuleRuntimeAuthority or any creation/mutation permission is provided.
    /// Original-creator-aware POST-create maintenance/cleanup still must be
    /// integrated separately; cold reattestation cannot whitelist saved GUIDs.
    pub(crate) struct LoadedWintun {
        loaded: LoadAttempt<Boundary>,
        original_load_read: RefCell<Option<Rc<NativeOriginalModuleLoadRead>>>,
        // Immutable original identity retained independently of owner.take().
        // Never a numeric HMODULE lookup or a reconstructed load receipt.
        terminal_original: Option<(Rc<Module>, Rc<Cell<bool>>)>,
        original_source: Rc<WintunSource>,
        // Original actual process-wide serialized lease, not Arc file-only.
        // Field drops AFTER original DLL reference and package/source wrapper.
        lock: KeyLockPin,
    }
    impl Drop for LoadedWintun {
        fn drop(&mut self) {
            if self.loaded.owner.is_some() {
                // Unknown/abandoned module ownership keeps the SAME actual
                // serialized lease, not just an Arc to a lock filename. Only
                // explicit authenticated full cleanup may release these pins.
                std::mem::forget(self.lock.read_pin());
            }
        }
    }
    /// Actual ORIGINAL LoadLibraryExW return only, even when forward postflight
    /// failed. No public constructor, raw HMODULE, OriginalImage/Retired adapter
    /// conversion, SDK absence, lifecycle/effect or unload permission.
    pub(crate) struct NativeOriginalModuleLoadRead {
        original: Rc<OriginalModuleLoadRead<Rc<Module>>>,
        source: Rc<WintunSource>,
        lock: KeyLockPin,
    }
    /// Independently issued permission for ONLY the original own loader
    /// reference. This module provides no implementation or authority issuer.
    ///
    /// # Safety
    /// The actual issuer must authenticate the SAME original immutable
    /// no-constructor Assembly and actual successful loader, precise CURRENT
    /// protected Stopped12/None Pair ACK and whole positive bounded Calling,
    /// original Runtime/KeyLock/source/initial journal/creator, full absence of
    /// private/services/keys/mixed SDK/scoped BFE resources, zero own native
    /// resources/loans and no attempts. JSON, equal observations, missing fields
    /// or an earlier factual read alone can NEVER supply this permission.
    /// The supplier must retain its actual authenticated originals, not just
    /// copied identities or a snapshot. Pre must perform FRESH full SDK/private/
    /// BFE absence reads immediately before the effect under that same Calling.
    /// `pre_release` must run under the actual caller's Calling; that SAME
    /// Calling must span the effect and complete postflight, not just this
    /// callback. The receipt is revoked before this callback: independently
    /// compare its original identity; do not reauthorize via its ordinary image
    /// reader. `verify_release_pre_read` is a distinct query-only pre aperture,
    /// not release permission; fresh full SDK/private/BFE checks remain yours.
    /// `post_release` must authenticate ONLY the SAME runtime/source/CURRENT
    /// Pair/Calling/origins. It must NEVER query image/exports/SDK after native
    /// release, including on error. Neither callback may substitute another
    /// loader/runtime/authority or turn factual ACK into retry/disposal rights.
    pub(crate) unsafe trait NativeNoConstructorModuleReleaseProof {
        fn pre_release(&self, original: &NativeOriginalModuleLoadRead) -> Result<()>;
        fn post_release(&self, original: &NativeOriginalModuleLoadRead) -> Result<()>;
    }
    /// Sealed actual successful FreeLibrary return for the exact original own
    /// LoadLibraryExW reference. No construction from status, handles or reads.
    /// Retains original source/serialized-lock/proof roots; not Retired-C,
    /// process code unload, session rundown or DATA retirement evidence.
    #[must_use = "retain the actual original native release ACK through disposition"]
    pub(crate) struct NativeNoConstructorModuleReleased<P: NativeNoConstructorModuleReleaseProof> {
        original: Rc<NativeOriginalModuleLoadRead>,
        proof: Rc<P>,
        module: Rc<Module>,
    }
    impl NativeOriginalModuleLoadRead {
        /// Actual registered process PIN/source origin only, including after
        /// release of this session reference. Not a worker/resource/session ACK
        /// or SDK permission, and never resurrects this client's valid gate.
        pub(crate) fn verify_process_code_lifetime(&self) -> Result<()> {
            image_cleanup_read(&self.original.valid, || {
                require_process_anchor(&self.source, &self.original.module)
            })
        }
        pub(crate) fn same_original(&self, other: &Self) -> bool {
            std::ptr::eq(self, other)
        }
        pub(crate) fn matches_source(&self, source: &Rc<WintunSource>) -> bool {
            Rc::ptr_eq(&self.source, source)
        }
        pub(crate) fn matches_runtime(&self, runtime: &RuntimeRead) -> bool {
            runtime.matches_pin(&self.lock)
        }
        /// Distinct query-only aperture for the independently authorized native
        /// supplier's exact CURRENT Calling preflight. Ordinary cleanup reads
        /// stay revoked. This does not issue release/constructor authority or
        /// cache SDK/private/BFE absence; the supplier must freshly read those.
        /// Actual cooperative lease acquisition is bounded to 5000ms; the
        /// caller's positive bounded Calling must span these native reads.
        pub(crate) fn verify_release_pre_read(
            &self,
            runtime: &RuntimeRead,
            cancelled: &AtomicBool,
        ) -> Result<()> {
            let module = &self.original.module;
            self.original
                .inspect_release_pre_with(&module.1, &module.2, cancelled, |module| {
                    if !module.1.image_available() || !self.matches_runtime(runtime) {
                        return Err(Error::Conflict);
                    }
                    runtime
                        .verify_source(&self.source)
                        .map_err(|_| Error::Conflict)?;
                    self.lock
                        .verify_source(&self.source)
                        .map_err(|_| Error::Conflict)?;
                    let mut lease = Lease::take(cancelled, 5000).map_err(|_| Error::Conflict)?;
                    let _read_lease = module.2.retain_read()?;
                    runtime
                        .verify_source(&self.source)
                        .map_err(|_| Error::Conflict)?;
                    lease.verify(cancelled).map_err(|_| Error::Conflict)?;
                    // The complete anchor read includes this SAME source's
                    // mapping/bounds/exports and independently joins repeat sources.
                    require_process_anchor(&self.source, module)?;
                    lease.verify(cancelled).map_err(|_| Error::Conflict)?;
                    self.lock
                        .verify_source(&self.source)
                        .map_err(|_| Error::Conflict)?;
                    runtime
                        .verify_source(&self.source)
                        .map_err(|_| Error::Conflict)?;
                    if !self.matches_runtime(runtime) {
                        return Err(Error::Conflict);
                    }
                    Ok(())
                })
        }
        /// Read-only image/source/actual Runtime facts under the actual bounded
        /// cooperative lease. Prior forward poison remains poisoned. No cold
        /// package scan adopts an adapter and no native function is executed.
        pub(crate) fn verify_cleanup_read(
            &self,
            runtime: &RuntimeRead,
            cancelled: &AtomicBool,
        ) -> Result<()> {
            self.original.inspect_cleanup_with(
                cancelled,
                || {
                    let module = &self.original.module;
                    if module.1.was_attempted()
                        || !module.1.image_available()
                        || !self.matches_runtime(runtime)
                    {
                        return Err(Error::Conflict);
                    }
                    Ok(())
                },
                |module| {
                    runtime
                        .verify_source(&self.source)
                        .map_err(|_| Error::Conflict)?;
                    self.lock
                        .verify_source(&self.source)
                        .map_err(|_| Error::Conflict)?;
                    let mut lease = Lease::take(cancelled, 5000).map_err(|_| Error::Conflict)?;
                    // Count the actual held cooperative lease, not reader Rc
                    // aliases. Existing terminal unload refuses any holder.
                    let _read_lease = module.2.retain_read()?;
                    runtime
                        .verify_source(&self.source)
                        .map_err(|_| Error::Conflict)?;
                    lease.verify(cancelled).map_err(|_| Error::Conflict)?;
                    require_process_anchor(&self.source, module)?;
                    lease.verify(cancelled).map_err(|_| Error::Conflict)?;
                    self.lock
                        .verify_source(&self.source)
                        .map_err(|_| Error::Conflict)?;
                    runtime
                        .verify_source(&self.source)
                        .map_err(|_| Error::Conflict)?;
                    if module.1.was_attempted() || !self.matches_runtime(runtime) {
                        return Err(Error::Conflict);
                    }
                    Ok(())
                },
            )
        }
    }
    /// Original HMODULE and the actual Device+Driver cooperative lease used to
    /// refresh it, with the SAME serialized runtime/source pins. Keep this
    /// owner on this thread across an independently authorized Create/Close.
    /// It grants no record/HKEY/fresh/cleanup-ordering or native effect rights.
    /// Acquisition waits are bounded by Lease::take's 5000ms budget; trust and
    /// inventory calls and caller effects are not hard-interruptible here.
    #[must_use = "retain the cooperative lease across the authorized effect"]
    pub(crate) struct OriginalModuleLease {
        held: HeldModule<Rc<Module>, Lease>,
        source: Rc<WintunSource>,
        lock: KeyLockPin,
        runtime: RuntimeRead,
        valid: Rc<Cell<bool>>,
        cleanup: bool,
    }
    impl Drop for OriginalModuleLease {
        fn drop(&mut self) {
            self.held.module.2.release();
        }
    }
    impl OriginalModuleLease {
        /// Original image identity only; neither this number nor this holder
        /// independently authorizes a native lifecycle effect.
        pub(crate) fn module(&self) -> NonNull<c_void> {
            self.held.module.0
        }
        /// Fresh factual runtime/source/image and held-lease checks only.
        /// Main must separately refresh full package/original inventory and
        /// validate current record/HKEY/fresh permission or cleanup ordering.
        /// Failure/unwind poisons LoadedWintun and every OriginalImage reader.
        pub(crate) fn verify(&mut self, cancelled: &AtomicBool) -> Result<()> {
            self.verify_mode(cancelled, self.cleanup)
        }
        /// Factual verification of the SAME held lease/source/image during
        /// independently authorized cleanup. Even a forward-acquired holder
        /// remains available after forward revocation, without rearming it.
        pub(crate) fn verify_for_cleanup(&mut self, cancelled: &AtomicBool) -> Result<()> {
            self.verify_mode(cancelled, true)
        }
        fn verify_mode(&mut self, cancelled: &AtomicBool, cleanup: bool) -> Result<()> {
            self.held
                .verify_with(&self.valid, cleanup, cancelled, |module, lease| {
                    if !module.1.image_available() {
                        return Err(Error::Conflict);
                    }
                    if !self.runtime.matches_pin(&self.lock) {
                        return Err(Error::Conflict);
                    }
                    // Join the SAME serialized owner/source and actual protected
                    // context around the anchor's full source authentication.
                    self.runtime
                        .verify_original_source_context(&self.source)
                        .map_err(|_| Error::Conflict)?;
                    lease.verify(cancelled).map_err(|_| Error::Conflict)?;
                    // The full original anchor read also checks this SAME
                    // mapping, image bounds and audited exports. Keep both
                    // original lease/runtime/context fences around that read.
                    require_process_anchor(&self.source, module)?;
                    lease.verify(cancelled).map_err(|_| Error::Conflict)?;
                    self.runtime
                        .verify_original_source_context(&self.source)
                        .map_err(|_| Error::Conflict)?;
                    if !self.runtime.matches_pin(&self.lock) {
                        return Err(Error::Conflict);
                    }
                    Ok(())
                })
        }
    }
    /// Retains ONLY this original acknowledged DLL reference, actual source and
    /// SAME serialized owner lease. Independent read avoids creator-inventory
    /// recursion and cold-package checks on live adapters. This is not permission
    /// to create/end/close: post-create package and exact effects stay mandatory.
    pub(crate) struct OriginalImage {
        module: Rc<Module>,
        source: Rc<WintunSource>,
        lock: KeyLockPin,
        valid: Rc<Cell<bool>>,
    }
    impl OriginalImage {
        pub(crate) fn matches_source(&self, source: &Rc<WintunSource>) -> bool {
            Rc::ptr_eq(&self.source, source)
        }
        /// Factual read through the SAME pinned original DLL; not a cached
        /// driver version or permission to install/load/create/end/close.
        pub(crate) fn running_driver_version(
            &self,
            runtime: &crate::windows::member_carrier_key_authority::RuntimeRead,
        ) -> Result<Option<u32>> {
            let mut observed = None;
            image_cleanup_read(&self.valid, || {
                self.verify_runtime(runtime)?;
                // SAFETY: original HMODULE/source Rc/lease are retained and
                // freshly checked on both sides, including any query failure.
                let functions = unsafe {
                    Functions::resolve(|name| {
                        GetProcAddress(self.module.0.as_ptr(), name.as_ptr().cast())
                    })
                }
                .map_err(|_| Error::Conflict)?;
                let version =
                    unsafe { functions.running_driver_version() }.map_err(|_| Error::Conflict)?;
                self.verify_runtime(runtime)?;
                observed = Some(version);
                Ok(())
            })?;
            observed.ok_or(Error::Conflict)
        }
        pub(super) fn verify(&self) -> Result<()> {
            image_read(&self.valid, || {
                if !self.module.1.image_available() {
                    return Err(Error::Conflict);
                }
                self.lock
                    .verify_source(&self.source)
                    .map_err(|_| Error::Conflict)?;
                // One full source/mapping read through the SAME retained PIN.
                require_process_anchor(&self.source, &self.module)?;
                self.lock
                    .verify_source(&self.source)
                    .map_err(|_| Error::Conflict)
            })
        }
        pub(super) fn matches_lock(&self, lock: &KeyLock) -> bool {
            lock.matches_pin(&self.lock)
        }
        pub(crate) fn verify_cleanup_read(&self) -> Result<()> {
            image_cleanup_read(&self.valid, || {
                if !self.module.1.image_available() {
                    return Err(Error::Conflict);
                }
                self.lock
                    .verify_source(&self.source)
                    .map_err(|_| Error::Conflict)?;
                // One full source/mapping read through the SAME retained PIN.
                require_process_anchor(&self.source, &self.module)?;
                self.lock
                    .verify_source(&self.source)
                    .map_err(|_| Error::Conflict)
            })
        }
        pub(crate) fn read_pin(&self) -> Result<OriginalImage> {
            self.verify_cleanup_read()?;
            Ok(OriginalImage {
                module: self.module.clone(),
                source: self.source.clone(),
                lock: self.lock.read_pin(),
                valid: self.valid.clone(),
            })
        }
        pub(crate) fn matches_runtime(
            &self,
            runtime: &crate::windows::member_carrier_key_authority::RuntimeRead,
        ) -> bool {
            runtime.matches_pin(&self.lock)
        }
        /// Same actual source/runtime/serialized pin, without a DLL read.
        /// Terminal postflight ONLY; cannot grant forward/native effects and
        /// must never resolve exports through a possibly unloaded image.
        pub(crate) fn verify_terminal_runtime(&self, runtime: &RuntimeRead) -> Result<()> {
            if !self.matches_runtime(runtime) {
                return Err(Error::Conflict);
            }
            runtime
                .verify_source(&self.source)
                .map_err(|_| Error::Conflict)?;
            self.lock
                .verify_source(&self.source)
                .map_err(|_| Error::Conflict)?;
            runtime
                .verify_source(&self.source)
                .map_err(|_| Error::Conflict)
        }
        pub(crate) fn verify_runtime(
            &self,
            runtime: &crate::windows::member_carrier_key_authority::RuntimeRead,
        ) -> Result<()> {
            image_cleanup_read(&self.valid, || self.verify_runtime_facts(runtime))
        }
        /// Bind the supplied context BEFORE the full factual image read. Wrong
        /// caller context cannot enter authentication or change image poison.
        pub(crate) fn verify_runtime_for_context(
            &self,
            runtime: &RuntimeRead,
            context: &crate::member_carrier_native_ownership::Context,
        ) -> Result<()> {
            runtime
                .require_original_context(context)
                .map_err(|_| Error::Conflict)?;
            self.verify_runtime(runtime)
        }
        /// Freshly authenticate both actual images; only exact retained
        /// module/source/valid/serialized-pin aliases share one factual read.
        /// Equal HMODULE values alone never bypass a distinct source's read.
        pub(crate) fn verify_same_runtime_image(
            &self,
            runtime: &RuntimeRead,
            other: &OriginalImage,
        ) -> Result<()> {
            self.verify_runtime(runtime)?;
            if !Rc::ptr_eq(&self.module, &other.module)
                || !Rc::ptr_eq(&self.source, &other.source)
                || !Rc::ptr_eq(&self.valid, &other.valid)
                || !other.matches_runtime(runtime)
            {
                other.verify_runtime(runtime)?;
            }
            if self.module.0 != other.module.0 {
                return Err(Error::Conflict);
            }
            Ok(())
        }
        /// Fresh forward image read, not cleanup-only resurrection of a
        /// poisoned load observation. Actual effect permission is separate.
        pub(crate) fn verify_live_runtime(
            &self,
            runtime: &crate::windows::member_carrier_key_authority::RuntimeRead,
        ) -> Result<()> {
            image_read(&self.valid, || self.verify_runtime_facts(runtime))
        }
        fn verify_runtime_facts(&self, runtime: &RuntimeRead) -> Result<()> {
            if !self.module.1.image_available() || !self.matches_runtime(runtime) {
                return Err(Error::Conflict);
            }
            runtime
                .verify_original_source_context(&self.source)
                .map_err(|_| Error::Conflict)?;
            // This full anchor read also verifies the SAME current source's
            // actual mapping/bounds/exports, including distinct repeat sources.
            // Both source authentications remain inside that mapping read;
            // retain the original runtime/context facts on its two sides.
            require_process_anchor(&self.source, &self.module)?;
            runtime
                .verify_original_source_context(&self.source)
                .map_err(|_| Error::Conflict)
        }
        pub(crate) fn cleanup_read_module(&self) -> Result<NonNull<c_void>> {
            self.verify_cleanup_read()?;
            Ok(self.module.0)
        }
        /// Factual SAME retained module comparison after the full runtime-bound
        /// source/mapping read. Preserves cleanup poisoning and grants no native
        /// effect permission or new module ownership.
        pub(crate) fn cleanup_read_module_for_runtime(
            &self,
            runtime: &RuntimeRead,
            context: &crate::member_carrier_native_ownership::Context,
        ) -> Result<NonNull<c_void>> {
            self.verify_runtime_for_context(runtime, context)?;
            Ok(self.module.0)
        }
        /// Comparison/read only. Never a raw-handle authority constructor.
        pub(crate) fn module(&self) -> Result<NonNull<c_void>> {
            self.verify()?;
            Ok(self.module.0)
        }
    }
    impl LoadedWintun {
        fn verify_code_lifetime(&self) -> Result<()> {
            let owner = self.loaded.owner.as_ref().ok_or(Error::Conflict)?;
            image_cleanup_read(&owner.valid, || {
                require_process_anchor(&self.original_source, &owner.module)
            })
        }
        /// SDK-free receipt capture. SAME owning OS return/source/serialized
        /// lock is rooted in both this owner and caller before postflight.
        /// Wrapper presence before `LoadAttempt.owner` exists never suffices.
        /// Once only: caller clones the original Rc instead of reissuing it.
        pub(crate) fn retain_original_load_read_into(
            &self,
            destination: &mut Option<Rc<NativeOriginalModuleLoadRead>>,
        ) -> Result<()> {
            let mut original = None;
            self.loaded
                .retain_original_load_read_into(&mut original, |receipt| {
                    if destination.is_some() || self.original_load_read.borrow().is_some() {
                        return Err(Error::Conflict);
                    }
                    let read = Rc::new(NativeOriginalModuleLoadRead {
                        original: receipt.clone(),
                        source: self.original_source.clone(),
                        lock: self.lock.read_pin(),
                    });
                    *self.original_load_read.borrow_mut() = Some(read.clone());
                    *destination = Some(read.clone());
                    self.verify_original_load_read(&read)
                })
        }
        /// Exact Rc native receipt + actual retained owner/source/valid gate.
        /// Pure comparison only. Poisoned forward state is not restored, and
        /// any attempted unload/disposition (including failed preflight) denies.
        pub(crate) fn verify_original_load_read(
            &self,
            read: &Rc<NativeOriginalModuleLoadRead>,
        ) -> Result<()> {
            self.loaded
                .verify_original_load_read(&read.original, Rc::ptr_eq)?;
            let owner = self.loaded.owner.as_ref().ok_or(Error::Conflict)?;
            if self
                .original_load_read
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .as_ref()
                .is_none_or(|original| !Rc::ptr_eq(original, read))
                || self.terminal_original.is_some()
                || owner.module.1.was_attempted()
                || !owner.module.1.image_available()
                || !Rc::ptr_eq(&self.original_source, &read.source)
                || !Rc::ptr_eq(&owner.kernel.source, &read.source)
            {
                return Err(Error::Conflict);
            }
            Ok(())
        }
        /// Independently authorized no-constructor original-reference backend.
        /// The global process code PIN remains. No full-C terminal permit or
        /// fabricated OriginalImage is involved, and no automatic unknown free.
        pub(crate) fn release_no_constructor_into<P: NativeNoConstructorModuleReleaseProof>(
            &mut self,
            original: &Rc<NativeOriginalModuleLoadRead>,
            proof: Rc<P>,
            retained: &mut Option<NativeNoConstructorModuleReleased<P>>,
        ) -> Result<()> {
            let mut roots = UnknownReleaseRoots(Some((original.clone(), proof)));
            // Comparison-only check while the original read gate is still
            // available; the result is consumed under module.1 below, never
            // re-read after revocation/effect as if it were permission.
            let initial = self.verify_original_load_read(original);
            let Some(owner) = self.loaded.owner.as_ref() else {
                self.loaded.deny_original_load_reads();
                return Err(Error::Conflict);
            };
            let module = owner.module.clone();
            let source = &self.original_source;
            let lock = &self.lock;
            self.loaded.release_original_into(
                OriginalLoadRelease {
                    original: &original.original,
                    same_module: Rc::ptr_eq,
                    terminal: &mut self.terminal_original,
                    release: &module.1,
                    loans: &module.2,
                },
                roots.0.take().expect("retained original release inputs"),
                retained,
                |receipt, supplier| {
                    initial?;
                    lock.verify_source(source).map_err(|_| Error::Conflict)?;
                    receipt
                        .lock
                        .verify_source(source)
                        .map_err(|_| Error::Conflict)?;
                    require_process_anchor(source, &module)?;
                    supplier.pre_release(receipt)?;
                    // Actual own source/serialized owner/PIN identity still
                    // matches on the native side of the fallible caller check.
                    require_process_anchor(source, &module)?;
                    lock.verify_source(source).map_err(|_| Error::Conflict)
                },
                |receipt, supplier| {
                    // SAFETY: exact own original loader receipt and current
                    // serialized owner/process PIN were verified under the
                    // irreversible module.1 gate; actual module loans are zero.
                    // Unsafe supplier authenticates actual no-constructor,
                    // Stopped/Calling/resources/origins before this sole effect.
                    if unsafe { FreeLibrary(module.0.as_ptr()) } == 0 {
                        return Err(Error::Native);
                    }
                    // No fallible work between native success and opaque ACK.
                    Ok(NativeNoConstructorModuleReleased {
                        original: receipt.clone(),
                        proof: supplier.clone(),
                        module: module.clone(),
                    })
                },
                |ack| {
                    // ACK already retained. NEVER SDK/image/PIN queries here.
                    // Caller checks same runtime/source/current Pair/Calling.
                    ack.proof.post_release(&ack.original)?;
                    lock.verify_source(source).map_err(|_| Error::Conflict)
                },
            )
        }
        /// Pure factual native ACK identity, including failed postflight. No
        /// loaded-image read, supplier call, disposal or reauthorization.
        pub(crate) fn verify_original_no_constructor_native_release<
            P: NativeNoConstructorModuleReleaseProof,
        >(
            &self,
            ack: &NativeNoConstructorModuleReleased<P>,
        ) -> Result<()> {
            if self
                .original_load_read
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .as_ref()
                .is_none_or(|read| !Rc::ptr_eq(read, &ack.original))
                || !Rc::ptr_eq(&self.original_source, &ack.original.source)
                || !Rc::ptr_eq(&ack.module, &ack.original.original.module)
                || self
                    .loaded
                    .owner
                    .as_ref()
                    .is_some_and(|owner| !Rc::ptr_eq(&owner.kernel.source, &ack.original.source))
            {
                return Err(Error::Conflict);
            }
            self.loaded.verify_original_release(
                &ack.original.original,
                &self.terminal_original,
                &ack.module.1,
                Rc::ptr_eq,
            )
        }
        /// Complete owning disposition, not merely a successful native return.
        /// Original loaded owner was removed only after ACK + full postflight.
        pub(crate) fn verify_no_constructor_disposition<
            P: NativeNoConstructorModuleReleaseProof,
        >(
            &self,
            ack: &NativeNoConstructorModuleReleased<P>,
        ) -> Result<()> {
            self.verify_original_no_constructor_native_release(ack)?;
            self.loaded.verify_original_disposition(
                &ack.original.original,
                &self.terminal_original,
                &ack.module.1,
                &ack.module.2,
                Rc::ptr_eq,
            )
        }
        /// Explicit release of ONLY this original LoadLibraryExW reference.
        /// The caller's slot owns the opaque native return BEFORE both module
        /// and supervisor postflight. Err/unwind cannot erase that factual ACK;
        /// a failed postflight still forbids completed disposition/release.
        /// NativeKernel's separate reference requires its actual release ACK,
        /// authenticated by the mandatory terminal resource gate.
        pub(crate) fn release_terminal_into<T, G>(
            &mut self,
            permit: crate::windows::member_carrier_terminal_release::native::NativeTerminalPermit<
                T,
                G,
            >,
            retained: &mut Option<NativeModuleReleased<T, G>>,
        ) -> Result<()>
        where
            G: crate::windows::member_carrier_terminal_release::native::NativeTerminalResourceGate<
                T,
            >,
        {
            let owner = self.loaded.owner.as_ref().ok_or(Error::Conflict)?;
            // Revoke independent read pins BEFORE selecting disposition or
            // allocating the permit root; unwind cannot leave image reads live.
            self.loaded.deny_original_load_reads();
            let module = owner.module.clone();
            if self.terminal_original.is_some() || retained.is_some() {
                return Err(Error::Conflict);
            }
            self.terminal_original = Some((module.clone(), owner.valid.clone()));
            let permit = Rc::new(permit);
            module.1.run_into(
                retained,
                || {
                    let image = permit.original_image();
                    if !Rc::ptr_eq(&module, &image.module)
                        || !Rc::ptr_eq(&owner.valid, &image.valid)
                        || !Rc::ptr_eq(&self.original_source, &image.source)
                        || !module.1.image_available()
                        || !module.2.is_empty()
                    {
                        return Err(Error::Conflict);
                    }
                    self.lock
                        .verify_source(&self.original_source)
                        .map_err(|_| Error::Conflict)?;
                    permit.pre_unload().map_err(|_| Error::Conflict)?;
                    if !module.2.is_empty() {
                        return Err(Error::Conflict);
                    }
                    self.lock
                        .verify_source(&self.original_source)
                        .map_err(|_| Error::Conflict)
                },
                || {
                    // SAFETY: exact original load ACK, current protected Stopped
                    // ACK and actual terminal resource G checked; no original
                    // cooperative lease remains. All history stayed rooted.
                    if unsafe { FreeLibrary(module.0.as_ptr()) } == 0 {
                        return Err(Error::Native);
                    }
                    Ok(NativeModuleReleased {
                        permit: permit.clone(),
                        module: module.clone(),
                    })
                },
                |ack| {
                    // No SDK/exports/image query AFTER this effect. Still the
                    // same real Runtime/Calling/Pair/source/serialized lock.
                    ack.permit.post_unload().map_err(|_| Error::Conflict)?;
                    self.lock
                        .verify_source(&self.original_source)
                        .map_err(|_| Error::Conflict)
                },
            )?;
            // Removing ownership only after actual unload ACK + postflight.
            // On every error/unwind owner remained in its original caller slot.
            drop(self.loaded.owner.take().ok_or(Error::Conflict)?);
            Ok(())
        }
        /// Factual SDK-return identity only, including failed postflight. No
        /// image/SDK call after unload and no disposal or retry permission.
        pub(crate) fn verify_original_native_release<T, G>(
            &self,
            ack: &NativeModuleReleased<T, G>,
        ) -> Result<()>
        where
            G: crate::windows::member_carrier_terminal_release::native::NativeTerminalResourceGate<
                T,
            >,
        {
            let (module, valid) = self.terminal_original.as_ref().ok_or(Error::Conflict)?;
            let image = ack.permit.original_image();
            if !Rc::ptr_eq(module, &ack.module)
                || !Rc::ptr_eq(module, &image.module)
                || !Rc::ptr_eq(valid, &image.valid)
                || !Rc::ptr_eq(&self.original_source, &image.source)
                || !module.1.acknowledged()
                || !module.1.effect_started.get()
                || valid.get()
            {
                return Err(Error::Conflict);
            }
            Ok(())
        }
        /// Same original's completed loader disposition, never factual ACK alone.
        pub(crate) fn verify_terminal_disposition<T, G>(
            &self,
            ack: &NativeModuleReleased<T, G>,
        ) -> Result<()>
        where
            G: crate::windows::member_carrier_terminal_release::native::NativeTerminalResourceGate<
                T,
            >,
        {
            self.verify_original_native_release(ack)?;
            if self.loaded.owner.is_some()
                || !ack.module.1.complete.get()
                || ack.module.1.tainted.get()
                || !ack.module.2.is_empty()
            {
                return Err(Error::Conflict);
            }
            Ok(())
        }
        /// Full factual original-owned package/image read through an actual
        /// RuntimeRead with the SAME serialized pin, authenticated source and
        /// full runtime scope before and after. Drops the cooperative lease
        /// before returning this comparison-only HMODULE; no effect rights.
        pub(crate) fn original_owned_module_read(
            &mut self,
            runtime: &RuntimeRead,
            cancelled: &AtomicBool,
            originals: &mut crate::windows::member_carrier_wintun::native::OriginalPackageInventory,
        ) -> Result<NonNull<c_void>> {
            let held = self.retain_owned_module_read(runtime, cancelled, originals)?;
            Ok(held.module())
        }
        /// Full factual cleanup read using actual current Closing observation.
        /// Preserves forward poison and drops the cooperative lease on return.
        /// Current record/HKEY and row/guard/network ordering remain main's
        /// independent obligations; this HMODULE grants no end/close rights.
        pub(crate) fn original_owned_module_read_for_cleanup(
            &mut self,
            runtime: &RuntimeRead,
            cancelled: &AtomicBool,
            originals: &mut crate::windows::member_carrier_wintun::native::OriginalPackageInventory,
        ) -> Result<NonNull<c_void>> {
            let held = self.retain_owned_module_read_for_cleanup(runtime, cancelled, originals)?;
            Ok(held.module())
        }
        /// Full forward package/original-image refresh; transfers the SAME
        /// actual cooperative lease to the returned factual resource owner.
        /// Main must retain it across its separately authorized Create/Close
        /// and independently check record/HKEY/fresh/cleanup ordering.
        pub(crate) fn retain_owned_module_read(
            &mut self,
            runtime: &RuntimeRead,
            cancelled: &AtomicBool,
            originals: &mut crate::windows::member_carrier_wintun::native::OriginalPackageInventory,
        ) -> Result<OriginalModuleLease> {
            self.retain_owned_read(runtime, cancelled, originals, false)
        }
        /// Full cleanup package/original-image refresh under current Closing
        /// facts; retains the SAME actual cooperative lease without restoring
        /// denied forward trust. No native end/close or ordering permission.
        pub(crate) fn retain_owned_module_read_for_cleanup(
            &mut self,
            runtime: &RuntimeRead,
            cancelled: &AtomicBool,
            originals: &mut crate::windows::member_carrier_wintun::native::OriginalPackageInventory,
        ) -> Result<OriginalModuleLease> {
            self.retain_owned_read(runtime, cancelled, originals, true)
        }
        fn retain_owned_read(
            &mut self,
            runtime: &RuntimeRead,
            cancelled: &AtomicBool,
            originals: &mut crate::windows::member_carrier_wintun::native::OriginalPackageInventory,
            cleanup: bool,
        ) -> Result<OriginalModuleLease> {
            self.verify_code_lifetime()?;
            let source = &self.original_source;
            let lock = &self.lock;
            let loaded = self.loaded.owner.as_mut().ok_or(Error::Conflict)?;
            let mut retained_runtime = None;
            let held = loaded.retain_with(
                cancelled,
                cleanup,
                originals,
                |_, originals| {
                    if !originals.matches_source(source) || !runtime.matches_pin(lock) {
                        return Err(Error::Conflict);
                    }
                    lock.verify_source(source).map_err(|_| Error::Conflict)?;
                    runtime.verify_source(source).map_err(|_| Error::Conflict)?;
                    // This actual read pin retains the same Runtime and guard;
                    // a failed/unwound pin read is inside the shared poison gate.
                    retained_runtime = Some(runtime.read_pin().map_err(|_| Error::Conflict)?);
                    Ok(())
                },
                |boundary, originals| {
                    let package = boundary.package.as_mut().ok_or(Error::Conflict)?;
                    #[cfg(test)]
                    super::super::member_carrier_factory_test_os::trace_step(
                        "C module original package reattestation begin",
                    );
                    if cleanup {
                        package.reattest_owned_cleanup(&mut originals.cleanup_devices())
                    } else {
                        package.reattest_owned(originals)
                    }
                    .map_err(|_| Error::Conflict)?;
                    #[cfg(test)]
                    super::super::member_carrier_factory_test_os::trace_step(
                        "C module original package reattestation accepted",
                    );
                    Ok(())
                },
            )?;
            let Some(runtime) = retained_runtime else {
                loaded.valid.set(false);
                return Err(Error::Conflict);
            };
            held.module.2.retain()?;
            Ok(OriginalModuleLease {
                held,
                source: source.clone(),
                lock: lock.read_pin(),
                runtime,
                valid: loaded.valid.clone(),
                cleanup,
            })
        }
        /// Caller-owned slot is populated BEFORE LoadLibraryExW. All internal
        /// post-load errors retain the actual ACK and deny forward image trust.
        pub(crate) fn load_cold_into(
            slot: &mut Option<Self>,
            source: &Rc<WintunSource>,
            lock: &mut KeyLock,
            cancelled: &AtomicBool,
            actual_load_returned: &Rc<Cell<bool>>,
        ) -> Result<()> {
            if slot.is_some() {
                return Err(Error::Conflict);
            }
            checkpoint(cancelled)?;
            // Mutable borrow spans WHOLE load, read-only pin retains SAME actual
            // guard thereafter while canonical lock can issue key receipts.
            lock.verify_source(source).map_err(|_| Error::Conflict)?;
            let pin = lock.pin();
            *slot = Some(Self {
                loaded: LoadAttempt::empty(),
                original_load_read: RefCell::new(None),
                terminal_original: None,
                original_source: source.clone(),
                lock: pin,
            });
            let retained = slot.as_mut().expect("original actor slot");
            retained.loaded.load(
                Boundary {
                    source: source.clone(),
                    package: None,
                    actual_load_returned: actual_load_returned.clone(),
                },
                cancelled,
            )?;
            let loaded = retained.loaded.owner.as_mut().ok_or(Error::Conflict)?;
            // Outer lock/source authentication is still part of load trust.
            // Mark poisoned first so an error or unwind cannot leave it live.
            loaded.valid.set(false);
            lock.verify_source(source).map_err(|_| Error::Conflict)?;
            retained
                .lock
                .verify_source(source)
                .map_err(|_| Error::Conflict)?;
            checkpoint(cancelled)?;
            // Code anchor is independent of all session/serialized pins. Own
            // the actual cooperative lease across native PIN and postflight.
            let mut anchor_lease = loaded.kernel.lease(cancelled)?;
            loaded.kernel.verify_lease(&mut anchor_lease, cancelled)?;
            let module = loaded.module.clone();
            establish_process_anchor(source, &module, cancelled, || {
                loaded.kernel.verify_lease(&mut anchor_lease, cancelled)?;
                lock.verify_source(source).map_err(|_| Error::Conflict)?;
                retained
                    .lock
                    .verify_source(source)
                    .map_err(|_| Error::Conflict)?;
                checkpoint(cancelled)
            })?;
            loaded.valid.set(true);
            Ok(())
        }
        #[cfg(test)]
        fn new(
            source: &Rc<WintunSource>,
            lock: &mut KeyLock,
            cancelled: &AtomicBool,
        ) -> Result<Self> {
            let mut slot = None;
            Self::load_cold_into(
                &mut slot,
                source,
                lock,
                cancelled,
                &Rc::new(Cell::new(false)),
            )?;
            slot.take().ok_or(Error::Conflict)
        }
        /// Returning a number grants no effect authority. The unsafe native
        /// carrier seam additionally requires independently implemented real
        /// module/runtime/current protected context/key/fresh permission gates.
        pub(crate) fn original_cold_module(
            &mut self,
            lock: &mut KeyLock,
            cancelled: &AtomicBool,
        ) -> Result<NonNull<c_void>> {
            self.verify_code_lifetime()?;
            let pin = &self.lock;
            let loaded = self.loaded.owner.as_mut().ok_or(Error::Conflict)?;
            let held = loaded.retain_with(
                cancelled,
                false,
                &mut (),
                |boundary, ()| {
                    if !lock.matches_pin(pin) {
                        return Err(Error::Conflict);
                    }
                    pin.verify_source(&boundary.source)
                        .map_err(|_| Error::Conflict)?;
                    lock.verify_source(&boundary.source)
                        .map_err(|_| Error::Conflict)
                },
                |boundary, ()| boundary.package(),
            )?;
            Ok(held.module.0)
        }
        /// Read-only post-create package/module refresh from actual original
        /// ACKs, NEVER saved GUIDs. Still grants no native lifecycle effects.
        pub(crate) fn original_owned_module(
            &mut self,
            lock: &mut KeyLock,
            cancelled: &AtomicBool,
            originals: &mut crate::windows::member_carrier_wintun::native::OriginalPackageInventory,
        ) -> Result<NonNull<c_void>> {
            self.original_owned_module_locked(lock, cancelled, originals, false)
        }
        /// Full factual cleanup package/module read through original pins.
        /// Preserves any prior forward revocation and grants NO native effect.
        /// Actual observation requires current protected Closing bytes on both
        /// sides; end/close still need independent row/guard/network ordering.
        pub(crate) fn original_owned_module_for_cleanup(
            &mut self,
            lock: &mut KeyLock,
            cancelled: &AtomicBool,
            originals: &mut crate::windows::member_carrier_wintun::native::OriginalPackageInventory,
        ) -> Result<NonNull<c_void>> {
            self.original_owned_module_locked(lock, cancelled, originals, true)
        }
        fn original_owned_module_locked(
            &mut self,
            lock: &mut KeyLock,
            cancelled: &AtomicBool,
            originals: &mut crate::windows::member_carrier_wintun::native::OriginalPackageInventory,
            cleanup: bool,
        ) -> Result<NonNull<c_void>> {
            self.verify_code_lifetime()?;
            let source = &self.original_source;
            let pin = &self.lock;
            let loaded = self.loaded.owner.as_mut().ok_or(Error::Conflict)?;
            let held = loaded.retain_with(
                cancelled,
                cleanup,
                originals,
                |_, originals| {
                    if !originals.matches_source(source) || !lock.matches_pin(pin) {
                        return Err(Error::Conflict);
                    }
                    pin.verify_source(source).map_err(|_| Error::Conflict)?;
                    lock.verify_source(source).map_err(|_| Error::Conflict)
                },
                |boundary, originals| {
                    let package = boundary.package.as_mut().ok_or(Error::Conflict)?;
                    if cleanup {
                        package.reattest_owned_cleanup(&mut originals.cleanup_devices())
                    } else {
                        package.reattest_owned(originals)
                    }
                    .map_err(|_| Error::Conflict)
                },
            )?;
            Ok(held.module.0)
        }
        pub(in crate::windows) fn original_image(
            &mut self,
            lock: &mut KeyLock,
            cancelled: &AtomicBool,
        ) -> Result<OriginalImage> {
            self.original_cold_module(lock, cancelled)?;
            let loaded = self.loaded.owner.as_ref().ok_or(Error::Conflict)?;
            let read = OriginalImage {
                module: loaded.module.clone(),
                source: self.original_source.clone(),
                lock: lock.pin(),
                valid: loaded.valid.clone(),
            };
            read.verify()?;
            Ok(read)
        }
    }

    /// Private native ACK: no constructor from receipt data, handles or absence.
    /// Retains all root/history pins until explicit resource graph release.
    pub(crate) struct NativeModuleReleased<
        T,
        G: crate::windows::member_carrier_terminal_release::native::NativeTerminalResourceGate<T>,
    > {
        permit:
            Rc<crate::windows::member_carrier_terminal_release::native::NativeTerminalPermit<T, G>>,
        module: Rc<Module>,
    }
    impl<
            T,
            G: crate::windows::member_carrier_terminal_release::native::NativeTerminalResourceGate<T>,
        > NativeModuleReleased<T, G>
    {
        pub(crate) fn matches_root(
            &self,
            root: &crate::windows::member_carrier_terminal_release::native::NativeTerminalReleaseRoot<T, G>,
        ) -> bool {
            self.module.1.complete.get()
                && self.module.1.unloaded.get()
                && self.permit.matches_root(root)
        }
    }

    #[cfg(test)]
    fn actual_held_original_keeps_native_lease_after_loaded_is_dropped(
        mut loaded: LoadedWintun,
        runtime: &RuntimeRead,
        cancelled: &AtomicBool,
        originals: &mut crate::windows::member_carrier_wintun::native::OriginalPackageInventory,
    ) -> Result<OriginalModuleLease> {
        // Type-check actual RuntimeRead/inventory/module/native Lease ownership.
        // No native execution, lifecycle effect or effect grant is claimed.
        let mut held = loaded.retain_owned_module_read(runtime, cancelled, originals)?;
        let _: &mut Lease = &mut held.held.lease;
        drop(loaded);
        held.verify(cancelled)?;
        Ok(held)
    }

    // Compile-only integration regression: the independently held SAME key
    // lock must remain usable to obtain the NEW-key receipt while our original
    // source and DLL reference stay retained. No native execution in tests.
    #[cfg(test)]
    fn actual_same_module_cleanup_package_path_requires_real_serialized_lock(
        module: &mut LoadedWintun,
        lock: &mut KeyLock,
        cancelled: &AtomicBool,
        originals: &mut crate::windows::member_carrier_wintun::native::OriginalPackageInventory,
    ) -> Result<()> {
        // Compile-only: current Closing proof is checked in real observation,
        // not manufactured from this API or assumed to have run on Windows.
        module.original_owned_module_for_cleanup(lock, cancelled, originals)?;
        Ok(())
    }
    #[cfg(test)]
    fn cleanup_package_reader_requires_actual_originals_and_retains_revoked_forward_state(
        originals: &mut crate::windows::member_carrier_wintun::native::OriginalPackageInventory,
    ) -> std::result::Result<(), crate::windows::member_carrier_wintun_package::Error> {
        // Compile-only real boundary contract, not native execution.
        let mut cleanup = originals.cleanup_devices();
        crate::windows::member_carrier_wintun_package::OriginalDevices::observe(&mut cleanup)
            .map(|_| ())
    }
    #[cfg(test)]
    fn original_image_keeps_actual_source_pins_after_caller_releases_source(
        source: Rc<WintunSource>,
        lock: &mut KeyLock,
        cancelled: &AtomicBool,
    ) -> Result<OriginalImage> {
        let mut loaded = LoadedWintun::new(&source, lock, cancelled)?;
        let image = loaded.original_image(lock, cancelled)?;
        drop(loaded);
        drop(source);
        image.verify_cleanup_read()?;
        Ok(image)
    }
    #[cfg(test)]
    fn module_owns_cold_package_after_caller_source_drop_and_can_query_exact_originals(
        source: Rc<WintunSource>,
        lock: &mut KeyLock,
        cancelled: &AtomicBool,
        originals: &mut crate::windows::member_carrier_wintun::native::OriginalPackageInventory,
    ) -> Result<LoadedWintun> {
        let mut loaded = LoadedWintun::new(&source, lock, cancelled)?;
        drop(source);
        loaded.original_owned_module(lock, cancelled, originals)?;
        Ok(loaded)
    }
    #[cfg(test)]
    fn key_receipt_and_original_module_have_compatible_borrows(
        source: &Rc<WintunSource>,
        lock: &mut KeyLock,
        cancelled: &AtomicBool,
    ) -> Result<()> {
        let mut module = LoadedWintun::new(source, lock, cancelled)?;
        lock.verify_source(source).map_err(|_| Error::Conflict)?;
        module.original_cold_module(lock, cancelled)?;
        lock.verify_source(source).map_err(|_| Error::Conflict)?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "member_carrier_module_tests.rs"]
mod tests;
