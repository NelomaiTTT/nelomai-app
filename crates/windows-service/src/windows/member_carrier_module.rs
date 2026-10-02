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

/// Actor-retained ORIGINAL load outcome. Failure after the OS ACK keeps the
/// exact owner accessible and denies another load; Drop is not unload authority.
struct LoadAttempt<K: Kernel> {
    attempted: bool,
    owner: Option<Loaded<K>>,
    original_read: RefCell<Option<Rc<OriginalModuleLoadRead<K::Module>>>>,
    read_capture: TerminalCallState,
    read_available: Rc<Cell<bool>>,
}
impl<K: Kernel> LoadAttempt<K> {
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
    tainted: Cell<bool>,
    effect_started: Cell<bool>,
    unloaded: Cell<bool>,
    complete: Cell<bool>,
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
        check()?;
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
        source.verify().map_err(|_| Error::Conflict)?;
        let mut path = vec![0; 32768];
        let count =
            unsafe { GetModuleFileNameW(mapping.as_ptr(), path.as_mut_ptr(), path.len() as u32) }
                as usize;
        if count == 0 || count >= path.len() {
            return Err(Error::Native);
        }
        let actual = std::path::PathBuf::from(std::ffi::OsString::from_wide(&path[..count]));
        if std::fs::canonicalize(actual).map_err(|_| Error::Native)?
            != source.path().map_err(|_| Error::Conflict)?
        {
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
                    verify_image(&self.source, module)?;
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
                    require_process_anchor(&self.source, module)?;
                    if !self.runtime.matches_pin(&self.lock) {
                        return Err(Error::Conflict);
                    }
                    self.lock
                        .verify_source(&self.source)
                        .map_err(|_| Error::Conflict)?;
                    self.runtime
                        .verify_source(&self.source)
                        .map_err(|_| Error::Conflict)?;
                    lease.verify(cancelled).map_err(|_| Error::Conflict)?;
                    verify_image(&self.source, module)?;
                    lease.verify(cancelled).map_err(|_| Error::Conflict)?;
                    self.runtime
                        .verify_source(&self.source)
                        .map_err(|_| Error::Conflict)?;
                    if !self.runtime.matches_pin(&self.lock) {
                        return Err(Error::Conflict);
                    }
                    self.lock
                        .verify_source(&self.source)
                        .map_err(|_| Error::Conflict)?;
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
                require_process_anchor(&self.source, &self.module)?;
                self.lock
                    .verify_source(&self.source)
                    .map_err(|_| Error::Conflict)?;
                verify_image(&self.source, &self.module)?;
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
                require_process_anchor(&self.source, &self.module)?;
                self.lock
                    .verify_source(&self.source)
                    .map_err(|_| Error::Conflict)?;
                verify_image(&self.source, &self.module)?;
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
        /// Fresh forward image read, not cleanup-only resurrection of a
        /// poisoned load observation. Actual effect permission is separate.
        pub(crate) fn verify_live_runtime(
            &self,
            runtime: &crate::windows::member_carrier_key_authority::RuntimeRead,
        ) -> Result<()> {
            image_read(&self.valid, || self.verify_runtime_facts(runtime))
        }
        fn verify_runtime_facts(&self, runtime: &RuntimeRead) -> Result<()> {
            require_process_anchor(&self.source, &self.module)?;
            if !self.matches_runtime(runtime) {
                return Err(Error::Conflict);
            }
            runtime
                .verify_source(&self.source)
                .map_err(|_| Error::Conflict)?;
            self.lock
                .verify_source(&self.source)
                .map_err(|_| Error::Conflict)?;
            verify_image(&self.source, &self.module)?;
            self.lock
                .verify_source(&self.source)
                .map_err(|_| Error::Conflict)?;
            runtime
                .verify_source(&self.source)
                .map_err(|_| Error::Conflict)
        }
        pub(crate) fn cleanup_read_module(&self) -> Result<NonNull<c_void>> {
            self.verify_cleanup_read()?;
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
                    if cleanup {
                        package.reattest_owned_cleanup(&mut originals.cleanup_devices())
                    } else {
                        package.reattest_owned(originals)
                    }
                    .map_err(|_| Error::Conflict)
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
            Self::load_cold_into(&mut slot, source, lock, cancelled)?;
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
