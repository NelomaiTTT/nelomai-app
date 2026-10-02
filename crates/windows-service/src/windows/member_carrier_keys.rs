//! Exact retained-key IO for the production carrier's precreation receipts.
//! Native effect tests replace only RegistryKernel, never this identity/CAS logic.
#![allow(dead_code)]
use crate::member_carrier::{CarrierError as Error, Result};
use crate::member_carrier_native_ownership::{
    self as receipt, Binding, Context, KeyPhase, KeyPresence, NativeFacts, NativeKeyIo,
    NativeValue, NewKeyAck, Phase, Record, Value, ValueCas,
};
#[cfg(all(test, not(windows)))]
use crate::member_carrier_registry_metadata as registry_metadata;
#[cfg(windows)]
use crate::windows::member_carrier_registry_metadata as registry_metadata;
use std::rc::Rc;

// Measurement-only capsule. It is deliberately absent from every production
// build: no NativeOwnership issuer, factory seam or deletion permission exists.
#[cfg(test)]
mod relative_txr_probe {
    use super::{Error, Result};
    use std::{
        cell::{Cell, RefCell},
        mem::ManuallyDrop,
        rc::Rc,
    };
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(super) struct Metadata {
        pub name: String,
        pub class: String,
        pub subkeys: u32,
        pub values: u32,
        pub last_write: (u32, u32),
        pub security: Vec<u8>,
    }
    /// External IO contract for the opt-in OWN-HKCU measurement, NOT a native
    /// carrier permission. Capture CREATED_NEW only; derive ONLY by an empty
    /// relative open of that retained original in the actual transaction. No
    /// parent/name opens or replacement imports. Delete ONLY the derived HKEY.
    /// # Safety
    /// Preserve returned/uncertain original handles in owning IO slots before
    /// any fallible checks; no IO/implicit retry in Drop. Native success must be
    /// actual syscall ACK, never inferred from name/absence/metadata equality.
    pub(super) unsafe trait Kernel {
        type Key;
        type Transaction;
        fn create_original(&mut self) -> Result<Self::Key>;
        fn metadata(&mut self, key: &Self::Key) -> Result<Metadata>;
        fn begin(&mut self) -> Result<Self::Transaction>;
        fn derive_empty(
            &mut self,
            original: &Self::Key,
            tx: &Self::Transaction,
        ) -> Result<Self::Key>;
        fn delete_derived(&mut self, derived: &Self::Key, tx: &Self::Transaction) -> Result<()>;
        fn commit(&mut self, tx: &Self::Transaction) -> Result<()>;
        fn rollback(&mut self, tx: &Self::Transaction) -> Result<()>;
        fn close_key(&mut self, key: &Self::Key) -> Result<()>;
        fn close_transaction(&mut self, tx: &Self::Transaction) -> Result<()>;
        fn close_parent(&mut self) -> Result<()>;
        fn probe_path_absent(&mut self) -> Result<bool>;
    }
    #[derive(Clone, Copy, Eq, PartialEq)]
    pub(super) enum Phase {
        Stage,
        Commit,
        Rollback,
        CloseDerived,
        CloseOriginal,
        CloseTransaction,
        CloseParent,
    }
    impl Phase {
        pub(super) const CLOSES: [Self; 4] = [
            Self::CloseDerived,
            Self::CloseOriginal,
            Self::CloseTransaction,
            Self::CloseParent,
        ];
        fn index(self) -> usize {
            self as usize
        }
        fn forward(self) -> bool {
            matches!(self, Self::Stage | Self::Commit)
        }
    }
    pub(super) struct Binding {
        origin: Rc<()>,
    }
    pub(super) struct Ack {
        origin: Rc<()>,
        phase: Phase,
    }
    struct State<K: Kernel> {
        io: K,
        original: Option<K::Key>,
        tx: Option<K::Transaction>,
        derived: Option<K::Key>,
        baseline: Option<Metadata>,
    }
    pub(super) struct Capsule<K: Kernel> {
        state: ManuallyDrop<RefCell<State<K>>>,
        origin: Rc<()>,
        binding: RefCell<Option<Rc<Binding>>>,
        busy: Cell<bool>,
        failed: Cell<bool>,
        attempted: [Cell<bool>; 7],
        acks: [RefCell<Option<Rc<Ack>>>; 7],
    }
    // Any unwound/failed preflight, native call, retention or postflight closes
    // forward use. Cleanup phases remain explicit and independently one-shot.
    struct Flight<'a> {
        busy: &'a Cell<bool>,
        failed: &'a Cell<bool>,
        complete: bool,
    }
    impl Drop for Flight<'_> {
        fn drop(&mut self) {
            if !self.complete {
                self.failed.set(true);
            }
            self.busy.set(false);
        }
    }
    impl<K: Kernel> Drop for Capsule<K> {
        fn drop(&mut self) {
            if Phase::CLOSES
                .iter()
                .all(|p| self.acks[p.index()].get_mut().is_some())
            {
                // IO contract forbids native Drop. Only all real close ACKs
                // allow inert owning wrapper disposal, not registry absence.
                unsafe {
                    ManuallyDrop::drop(&mut self.state);
                }
            }
            // Unknown handles/transactions retain their SAME owning IO slots;
            // no rollback, close, lookup, implicit retry or synthetic ACK.
        }
    }
    impl<K: Kernel> Capsule<K> {
        pub(super) fn capture_into(slot: &mut Option<Rc<Self>>, io: K) -> Result<()> {
            if slot.is_some() {
                return Err(Error::Conflict);
            }
            let c = Rc::new(Self {
                state: ManuallyDrop::new(RefCell::new(State {
                    io,
                    original: None,
                    tx: None,
                    derived: None,
                    baseline: None,
                })),
                origin: Rc::new(()),
                binding: RefCell::new(None),
                busy: Cell::new(false),
                failed: Cell::new(false),
                attempted: std::array::from_fn(|_| Cell::new(false)),
                acks: std::array::from_fn(|_| RefCell::new(None)),
            });
            // WHOLE same kernel/owning outputs rooted before the first syscall.
            *slot = Some(c.clone());
            let mut flight = c.enter()?;
            let mut s = c.state.borrow_mut();
            s.original = Some(s.io.create_original()?);
            let State {
                io,
                original,
                tx,
                derived,
                baseline,
            } = &mut *s;
            let original = original.as_ref().ok_or(Error::Pending)?;
            let before = io.metadata(original)?;
            Self::empty(&before)?;
            *baseline = Some(before);
            *tx = Some(io.begin()?);
            *derived = Some(io.derive_empty(original, tx.as_ref().ok_or(Error::Pending)?)?);
            let after = io.metadata(derived.as_ref().ok_or(Error::Pending)?)?;
            if Some(&after) != baseline.as_ref() {
                return Err(Error::Conflict);
            }
            drop(s);
            *c.binding.borrow_mut() = Some(Rc::new(Binding {
                origin: c.origin.clone(),
            }));
            flight.complete = true;
            Ok(())
        }
        fn empty(m: &Metadata) -> Result<()> {
            if m.values != 0 || m.subkeys != 0 || m.name.is_empty() || m.security.is_empty() {
                Err(Error::Conflict)
            } else {
                Ok(())
            }
        }
        fn enter(&self) -> Result<Flight<'_>> {
            if self.busy.replace(true) {
                self.failed.set(true);
                return Err(Error::Conflict);
            }
            Ok(Flight {
                busy: &self.busy,
                failed: &self.failed,
                complete: false,
            })
        }
        pub(super) fn binding(&self) -> Result<Rc<Binding>> {
            self.binding
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .as_ref()
                .cloned()
                .ok_or(Error::Pending)
        }
        fn perform(
            &self,
            phase: Phase,
            io: impl FnOnce(&mut State<K>) -> Result<()>,
            retain: impl FnOnce(Rc<Ack>) -> Result<()>,
            post: impl FnOnce() -> Result<()>,
        ) -> Result<()> {
            let mut flight = self.enter()?;
            if (phase.forward() && self.failed.get()) || self.attempted[phase.index()].replace(true)
            {
                return Err(Error::Conflict);
            }
            io(&mut self.state.borrow_mut())?;
            let ack = Rc::new(Ack {
                origin: self.origin.clone(),
                phase,
            });
            *self.acks[phase.index()].borrow_mut() = Some(ack.clone());
            // Real native ACK retained before caller callback/postflight;
            // failed/unwound callers retain facts without continuation grant.
            retain(ack)?;
            post()?;
            if phase.forward() && self.failed.get() {
                return Err(Error::Conflict);
            }
            flight.complete = true;
            Ok(())
        }
        pub(super) fn stage(
            &self,
            binding: &Rc<Binding>,
            retain: impl FnOnce(Rc<Ack>) -> Result<()>,
            post: impl FnOnce() -> Result<()>,
        ) -> Result<()> {
            self.perform(
                Phase::Stage,
                |s| {
                    let original = self.binding()?;
                    if !Rc::ptr_eq(binding, &original) || !Rc::ptr_eq(&binding.origin, &self.origin)
                    {
                        return Err(Error::Conflict);
                    }
                    let derived = s.derived.as_ref().ok_or(Error::Pending)?;
                    let current = s.io.metadata(derived)?;
                    Self::empty(&current)?;
                    if Some(&current) != s.baseline.as_ref() {
                        return Err(Error::Conflict);
                    }
                    // Only actual original-relative derived handle. No name,
                    // parent, replacement or namespace lookup enters this call.
                    s.io.delete_derived(derived, s.tx.as_ref().ok_or(Error::Pending)?)
                },
                retain,
                post,
            )
        }
        pub(super) fn commit(
            &self,
            retain: impl FnOnce(Rc<Ack>) -> Result<()>,
            post: impl FnOnce() -> Result<()>,
        ) -> Result<()> {
            self.perform(
                Phase::Commit,
                |s| {
                    self.read_ack(Phase::Stage)?;
                    if self.attempted[Phase::Rollback.index()].get() {
                        return Err(Error::Conflict);
                    }
                    s.io.commit(s.tx.as_ref().ok_or(Error::Pending)?)
                },
                retain,
                post,
            )
        }
        pub(super) fn rollback(
            &self,
            retain: impl FnOnce(Rc<Ack>) -> Result<()>,
            post: impl FnOnce() -> Result<()>,
        ) -> Result<()> {
            self.perform(
                Phase::Rollback,
                |s| {
                    if self.read_ack(Phase::Commit).is_ok() {
                        return Err(Error::Conflict);
                    }
                    s.io.rollback(s.tx.as_ref().ok_or(Error::Pending)?)
                },
                retain,
                post,
            )
        }
        pub(super) fn close(
            &self,
            phase: Phase,
            retain: impl FnOnce(Rc<Ack>) -> Result<()>,
            post: impl FnOnce() -> Result<()>,
        ) -> Result<()> {
            if !Phase::CLOSES.contains(&phase) {
                self.failed.set(true);
                return Err(Error::Conflict);
            }
            self.perform(
                phase,
                |s| {
                    if self.read_ack(Phase::Commit).is_err()
                        && self.read_ack(Phase::Rollback).is_err()
                    {
                        return Err(Error::Pending);
                    }
                    match phase {
                        Phase::CloseDerived => {
                            s.io.close_key(s.derived.as_ref().ok_or(Error::Pending)?)
                        }
                        Phase::CloseOriginal => {
                            s.io.close_key(s.original.as_ref().ok_or(Error::Pending)?)
                        }
                        Phase::CloseTransaction => {
                            s.io.close_transaction(s.tx.as_ref().ok_or(Error::Pending)?)
                        }
                        Phase::CloseParent => s.io.close_parent(),
                        _ => Err(Error::Conflict),
                    }
                },
                retain,
                post,
            )
        }
        pub(super) fn read_ack(&self, phase: Phase) -> Result<Rc<Ack>> {
            self.acks[phase.index()]
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .as_ref()
                .cloned()
                .ok_or(Error::Pending)
        }
        pub(super) fn verify_ack(&self, phase: Phase, ack: &Rc<Ack>) -> Result<()> {
            let actual = self.read_ack(phase)?;
            if Rc::ptr_eq(&self.origin, &ack.origin)
                && phase == ack.phase
                && Rc::ptr_eq(&actual, ack)
            {
                Ok(())
            } else {
                Err(Error::Conflict)
            }
        }
        /// Measurement result ONLY. Never a NativeOwnership/absence/effect
        /// capability; includes fresh external post-close lookup for test data.
        pub(super) fn measurement_complete(&self) -> Result<()> {
            if self.busy.get() {
                self.failed.set(true);
                return Err(Error::Conflict);
            }
            if self.failed.get() {
                return Err(Error::Conflict);
            }
            self.read_ack(Phase::Stage)?;
            self.read_ack(Phase::Commit)?;
            for phase in Phase::CLOSES {
                self.read_ack(phase)?;
            }
            // Missing historical facts are Pending, not a native operation or
            // a latch-reset. Only the complete chain permits this SDK read.
            let mut flight = self.enter()?;
            if !self.state.borrow_mut().io.probe_path_absent()? {
                return Err(Error::Conflict);
            }
            flight.complete = true;
            Ok(())
        }
    }
}

#[cfg(windows)]
use super::member_carrier_module as release_policy;
#[cfg(not(windows))]
use crate::member_carrier_module as release_policy;

/// Actual once-close ACK, neither a key-restore record nor effect permission.
pub(crate) struct KeyHandleClosed {
    origin: Rc<()>,
}
struct KeyHandleClose {
    original: Rc<()>,
    release: release_policy::ModuleRelease,
    closed: std::cell::RefCell<Option<Rc<KeyHandleClosed>>>,
}
impl KeyHandleClose {
    fn new() -> Self {
        Self {
            original: Rc::new(()),
            release: release_policy::ModuleRelease::new(),
            closed: std::cell::RefCell::new(None),
        }
    }
    fn was_attempted(&self) -> bool {
        self.release.was_attempted()
    }
    fn run(
        &self,
        check: impl FnOnce() -> Result<()>,
        native: impl FnOnce() -> Result<()>,
        retain: impl FnOnce(Rc<KeyHandleClosed>) -> Result<()>,
        post: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let error = std::cell::Cell::new(None);
        let mapped = |value: Result<()>| {
            value.map_err(|e| {
                error.set(Some(e));
                release_policy::Error::Conflict
            })
        };
        self.release
            .run(
                || mapped(check()),
                || {
                    mapped(native())?;
                    // Native returned success. Root the factual ACK before ANY caller
                    // callback or postflight can fail/unwind. No raw handle is exposed.
                    let ack = Rc::new(KeyHandleClosed {
                        origin: self.original.clone(),
                    });
                    *self.closed.borrow_mut() = Some(ack.clone());
                    mapped(retain(ack))
                },
                || mapped(post()),
            )
            .map_err(|_| error.get().unwrap_or(Error::Conflict))
    }
    fn read_ack(&self) -> Result<Rc<KeyHandleClosed>> {
        let ack = self.closed.try_borrow().map_err(|_| Error::Conflict)?;
        ack.as_ref().cloned().ok_or(Error::Pending)
    }
    fn verify_ack(&self, ack: &Rc<KeyHandleClosed>) -> Result<()> {
        let actual = self.read_ack()?;
        if !Rc::ptr_eq(&self.original, &ack.origin) || !Rc::ptr_eq(&actual, ack) {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}

/// Concrete canonical terminal caller only; no record-based native permission.
/// # Safety
/// Verify SAME runtime/lease, original Stopped publication and active Pair/
/// Retired/Calling brackets plus native full absence before AND after close.
/// Postflight must not query the released handle. Preserve all actual originals
/// and returned ACKs outside fallible callbacks. Never use this for a live key.
#[cfg(windows)]
pub(crate) unsafe trait NativeKeyTerminalFence {
    fn verify_original_terminal(&self, context: &Context, binding: &Binding) -> Result<()>;
}

const PARENT: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
const VALUE: &str = "IPAutoconfigurationEnabled";
const MAX_NAME: usize = 2048;
// Native pacing is 25ms, at most forty waits (1s). The caller's independent
// hard deadline and original terminal fence remain mandatory around each read.
const MAX_TERMINAL_KEY_READS: usize = 41;
pub(crate) fn decode_value(kind: u32, bytes: &[u8]) -> Result<NativeValue> {
    if bytes.len() > 256 {
        return Err(Error::Invalid);
    }
    if kind == 4 && bytes.len() == 4 {
        Ok(NativeValue::Dword(u32::from_le_bytes(
            bytes.try_into().map_err(|_| Error::Invalid)?,
        )))
    } else {
        Ok(NativeValue::Other {
            kind,
            bytes: bytes.to_vec(),
        })
    }
}

/// Must perform independent actual runtime/boot/epoch and owning-lock checks.
/// No production implementation, successful defaults or journal-seeded proof.
pub(crate) trait NativeAuthority {
    type Lock;
    fn verify(&mut self, lock: &mut Self::Lock, context: &Context) -> Result<()>;
    /// Separate native-effect authorization from read-only context/lock checks.
    /// Must re-read the protected pending record and actual fresh/cleanup claim.
    fn authorize_effect(
        &mut self,
        lock: &mut Self::Lock,
        pending: &Record,
        binding: &Binding,
        effect: Effect,
    ) -> Result<()>;
    fn nic_absence(
        &mut self,
        lock: &mut Self::Lock,
        context: &Context,
        binding: &Binding,
    ) -> Result<(bool, bool, bool)>;
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Effect {
    Create,
    Value(ValueCas),
}

/// The storage snapshot is independently authenticated by SessionFiles, not
/// supplied by the caller. This pure policy does not attest native ownership.
pub(crate) fn effect_matches_storage(
    pending: &Record,
    binding: &Binding,
    effect: Effect,
    actual: &Record,
    fresh: bool,
) -> Result<()> {
    receipt::validate_record(pending)?;
    if actual != pending {
        return Err(Error::Conflict);
    }
    let index = pending
        .context
        .bindings
        .iter()
        .position(|b| b == binding)
        .ok_or(Error::Conflict)?;
    let key = &pending.keys[index];
    let allowed = match effect {
        Effect::Create => {
            fresh
                && pending.phase == Phase::Preparing
                && key.phase == KeyPhase::CreatePending
                && !key.new_key_ack
                && key.baseline == Value::Absent
                && key.current == Value::Absent
                && key.pending.is_none()
        }
        Effect::Value(value) => {
            value.value_name == VALUE
                && key.new_key_ack
                && key.current == value.expected
                && key.pending == Some(value.desired)
                && (matches!(
                    (pending.phase, key.phase, value.expected, value.desired),
                    (
                        Phase::Closing,
                        KeyPhase::RestorePending,
                        Value::DwordZero,
                        Value::Absent
                    )
                ) || fresh
                    && binding.role != receipt::Role::RoleCarrier
                    && matches!(
                        (pending.phase, key.phase, value.expected, value.desired),
                        (
                            Phase::Preparing,
                            KeyPhase::RestorePending,
                            Value::DwordZero,
                            Value::Absent
                        )
                    )
                    || fresh
                        && matches!(
                            (pending.phase, key.phase, value.expected, value.desired),
                            (
                                Phase::Preparing,
                                KeyPhase::DisablePending,
                                Value::Absent,
                                Value::DwordZero
                            )
                        ))
        }
    };
    if allowed {
        Ok(())
    } else {
        Err(Error::Conflict)
    }
}
pub(crate) trait RegistryKernel {
    type Handle;
    fn interfaces(&mut self) -> Result<Self::Handle>;
    fn name(&mut self, handle: &Self::Handle) -> Result<String>;
    fn open(&mut self, parent: &Self::Handle, child: &str) -> Result<Option<Self::Handle>>;
    fn create(&mut self, parent: &Self::Handle, child: &str) -> Result<(Self::Handle, u32)>;
    fn value(&mut self, handle: &Self::Handle) -> Result<NativeValue>;
    fn zero(&mut self, handle: &Self::Handle) -> Result<()>;
    fn delete_value(&mut self, handle: &Self::Handle) -> Result<()>;
    fn flush(&mut self, handle: &Self::Handle) -> Result<()>;
    /// Optional original-handle observation; an unsupported boundary DENIES
    /// this lane. Only the native implementation returns RegQueryInfoKeyW's
    /// actual status, never a path lookup or restored-value inference.
    fn original_key_info_status(&mut self, _handle: &Self::Handle) -> Result<u32> {
        Err(Error::Pending)
    }
    /// Optional bounded pacing for an SDK's asynchronous key deletion. False
    /// means do not wait. This supplies no absence or disposition permission.
    fn pause_original_delete_read(&mut self) -> Result<bool> {
        Ok(false)
    }
    /// Read DATA only, into a caller-owned capture. Unsupported full security
    /// observation denies; neither status nor metadata grants key disposition.
    fn original_key_metadata(
        &mut self,
        _handle: &Self::Handle,
        _capture: &registry_metadata::RegistryMetadataCapture,
    ) -> Result<()> {
        Err(Error::Pending)
    }
}
/// Sealed factual observation, never SDK absence/worker/effect permission.
pub(crate) struct OriginalSdkDeletedKeyRead {
    origin: Rc<()>,
    statuses: [std::cell::Cell<Option<u32>>; 2],
    last_status: std::cell::Cell<Option<u32>>,
}
#[derive(Default)]
struct OriginalReadState {
    busy: std::cell::Cell<bool>,
    failed: std::cell::Cell<bool>,
}
struct OriginalReadCall<'a> {
    state: &'a OriginalReadState,
    complete: bool,
}
// Implemented only by the actual native handle below (and external-I/O test
// handles). Callers cannot manufacture a root disposition with an Ok callback.
pub(crate) trait TerminalKeyHandle {
    fn close_original(
        &self,
        check: impl FnOnce() -> Result<()>,
        retain: impl FnOnce(Rc<KeyHandleClosed>) -> Result<()>,
        post: impl FnOnce() -> Result<()>,
    ) -> Result<()>;
    fn verify_closed(&self, ack: &Rc<KeyHandleClosed>) -> Result<()>;
}
impl OriginalReadState {
    fn begin(&self) -> Result<OriginalReadCall<'_>> {
        if self.busy.replace(true) || self.failed.get() {
            self.failed.set(true);
            return Err(Error::Conflict);
        }
        Ok(OriginalReadCall {
            state: self,
            complete: false,
        })
    }
    fn check(&self) -> Result<()> {
        if self.failed.get() {
            Err(Error::Conflict)
        } else {
            Ok(())
        }
    }
}
impl Drop for OriginalReadCall<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.state.failed.set(true);
        }
        self.state.busy.set(false);
    }
}
/// Historical original ownership, NOT current path absence/full key emptiness.
/// No variant can be minted by restored VALUE, closed HKEY or matching JSON as
/// a KEY-root deletion/absence acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KeyRootObligationKind {
    CreatedKeyRootRetained,
    ValueRestoreObservedRootRetained,
    OriginalHandleClosedRootRetained,
    UncertainOriginalKeyRoot,
}

/// Owns the SAME handle returned with CREATED_NEW, rooted before create
/// postflight. !Send/nonserializable; no raw-handle accessor or public ctor.
/// Unknown abandonment preserves the original native obligation. A factual
/// close ACK permits inert handle-wrapper destruction, never KEY-root absence.
pub(crate) struct OriginalKeyRootObligation<H> {
    handle: std::mem::ManuallyDrop<H>,
    // SAME actual parent used by the native CREATED_NEW operation. A saved
    // path or subsequently opened equal key cannot replace this origin. Root
    // Unknown abandonment preserves BOTH descriptors; a child-close ACK alone
    // does not authorize parent release or root disposition.
    parent_handle: std::mem::ManuallyDrop<H>,
    kind: std::cell::Cell<KeyRootObligationKind>,
    closed: std::cell::RefCell<Option<Rc<KeyHandleClosed>>>,
    origin: Rc<()>,
    sdk_deleted: std::cell::RefCell<Option<Rc<OriginalSdkDeletedKeyRead>>>,
    present_metadata: std::cell::RefCell<Option<Rc<registry_metadata::RegistryMetadataCapture>>>,
    observation: OriginalReadState,
    observed_deleted: std::cell::Cell<bool>,
    first_terminal_status: std::cell::Cell<Option<u32>>,
    terminal_status_history: std::cell::RefCell<Vec<u32>>,
    terminal: OriginalReadState,
    terminal_complete: std::cell::Cell<bool>,
    parent_closed: std::cell::RefCell<Option<Rc<KeyHandleClosed>>>,
    selection: OriginalReadState,
    selection_attempted: std::cell::Cell<bool>,
    sampling: OriginalReadState,
}
impl<H> OriginalKeyRootObligation<H> {
    fn check_health(&self) -> Result<()> {
        self.observation.check()?;
        self.terminal.check()?;
        self.selection.check()?;
        self.sampling.check()
    }
    fn new(handle: H, parent_handle: H) -> Self {
        Self {
            handle: std::mem::ManuallyDrop::new(handle),
            parent_handle: std::mem::ManuallyDrop::new(parent_handle),
            kind: std::cell::Cell::new(KeyRootObligationKind::UncertainOriginalKeyRoot),
            closed: std::cell::RefCell::new(None),
            origin: Rc::new(()),
            sdk_deleted: std::cell::RefCell::new(None),
            present_metadata: std::cell::RefCell::new(None),
            observation: OriginalReadState::default(),
            observed_deleted: std::cell::Cell::new(false),
            first_terminal_status: std::cell::Cell::new(None),
            terminal_status_history: std::cell::RefCell::new(Vec::new()),
            terminal: OriginalReadState::default(),
            terminal_complete: std::cell::Cell::new(false),
            parent_closed: std::cell::RefCell::new(None),
            selection: OriginalReadState::default(),
            selection_attempted: std::cell::Cell::new(false),
            sampling: OriginalReadState::default(),
        }
    }
    fn handle(&self) -> &H {
        &self.handle
    }
    fn parent_handle(&self) -> &H {
        &self.parent_handle
    }
    pub(crate) fn classification(&self) -> KeyRootObligationKind {
        self.kind.get()
    }
    pub(crate) fn present_metadata_capture(
        &self,
    ) -> Option<Rc<registry_metadata::RegistryMetadataCapture>> {
        self.present_metadata.try_borrow().ok()?.clone()
    }
    pub(crate) fn verify_original(self: &Rc<Self>, ack: &NewKeyAck<Held<H>>) -> Result<()> {
        if Rc::ptr_eq(self, &ack.retained_handle().handle) {
            Ok(())
        } else {
            Err(Error::Conflict)
        }
    }
    /// ONLY the sealed SDK-deleted-original lane plus both original native
    /// close ACKs completes this obligation. A surviving empty root is Pending.
    pub(crate) fn require_root_absent(&self) -> Result<()> {
        self.check_health()?;
        let read = self.sdk_deleted_read()?;
        if !Rc::ptr_eq(&read.origin, &self.origin)
            || read.statuses.each_ref().map(|s| s.get()) != [Some(1018), Some(1018)]
            || !self.observed_deleted.get()
            || !self.terminal_complete.get()
            || self.closed_handle_ack().is_err()
            || self
                .parent_closed
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .is_none()
        {
            return Err(Error::Pending);
        }
        Ok(())
    }
    pub(crate) fn sdk_deleted_read(&self) -> Result<Rc<OriginalSdkDeletedKeyRead>> {
        self.sdk_deleted
            .try_borrow()
            .map_err(|_| Error::Conflict)?
            .as_ref()
            .cloned()
            .ok_or(Error::Pending)
    }
    /// Pure SAME-original factual read verification. Even success cannot grant
    /// root disposal: require_root_absent additionally checks both close ACKs.
    pub(crate) fn verify_sdk_deleted_read(
        &self,
        read: &Rc<OriginalSdkDeletedKeyRead>,
    ) -> Result<()> {
        self.check_health()?;
        let original = self.sdk_deleted_read()?;
        if !Rc::ptr_eq(&original, read)
            || !Rc::ptr_eq(&self.origin, &read.origin)
            || !self.observed_deleted.get()
            || read.statuses.each_ref().map(|s| s.get()) != [Some(1018), Some(1018)]
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    fn observe_sdk_deleted<K: RegistryKernel<Handle = H>>(
        self: &Rc<Self>,
        original: &NewKeyAck<Held<H>>,
        kernel: &mut K,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<Rc<OriginalSdkDeletedKeyRead>> {
        let mut call = self.observation.begin()?;
        self.selection.check()?;
        self.verify_original(original)?;
        if self
            .closed
            .try_borrow()
            .map_err(|_| Error::Conflict)?
            .is_some()
            || self
                .parent_closed
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .is_some()
        {
            return Err(Error::Conflict);
        }
        let held = original.retained_handle();
        receipt::validate_context(&held.context)?;
        if !held.context.bindings.contains(&held.binding)
            || !parent_valid(&held.parent)
            || held.binding.registry_path != format!("{PARENT}\\{}", held.child)
        {
            return Err(Error::Conflict);
        }
        check()?;
        self.check_health()?; // caught reentry must prevent even the next read
        let read = {
            let mut slot = self
                .sdk_deleted
                .try_borrow_mut()
                .map_err(|_| Error::Conflict)?;
            slot.get_or_insert_with(|| {
                Rc::new(OriginalSdkDeletedKeyRead {
                    origin: self.origin.clone(),
                    statuses: std::array::from_fn(|_| std::cell::Cell::new(None)),
                    last_status: std::cell::Cell::new(None),
                })
            })
            .clone()
        };
        for status in &read.statuses {
            // Root the actual result BEFORE validation, subsequent I/O or postflight.
            let actual = kernel.original_key_info_status(self.handle())?;
            read.last_status.set(Some(actual));
            if status.get().is_none() {
                status.set(Some(actual));
            }
            self.check_health()?;
            if actual == 0 {
                // A surviving original is not SDK-deleted. Retain bounded
                // full metadata outputs BEFORE any fallible query/postflight.
                // This is DATA only; no deletion or handle-close permission.
                let capture = Rc::new(registry_metadata::RegistryMetadataCapture::new());
                *self
                    .present_metadata
                    .try_borrow_mut()
                    .map_err(|_| Error::Conflict)? = Some(capture.clone());
                check()?;
                kernel.original_key_metadata(self.handle(), &capture)?;
                check()?;
                self.check_health()?;
                return Err(Error::Pending);
            }
            if actual != 1018 {
                return Err(Error::Pending);
            }
            if !kernel
                .name(self.parent_handle())?
                .eq_ignore_ascii_case(&held.parent)
            {
                return Err(Error::Conflict);
            }
            self.check_health()?;
            if kernel.open(self.parent_handle(), &held.child)?.is_some() {
                return Err(Error::Conflict);
            }
            self.check_health()?;
        }
        check()?;
        self.check_health()?;
        self.observed_deleted.set(true);
        call.complete = true;
        Ok(read)
    }
    pub(crate) fn closed_handle_ack(&self) -> Result<Rc<KeyHandleClosed>> {
        self.closed
            .try_borrow()
            .map_err(|_| Error::Conflict)?
            .as_ref()
            .cloned()
            .ok_or(Error::Pending)
    }
    fn verify_parent_absent<K: RegistryKernel<Handle = H>>(
        &self,
        held: &Held<H>,
        kernel: &mut K,
    ) -> Result<()> {
        if !kernel
            .name(self.parent_handle())?
            .eq_ignore_ascii_case(&held.parent)
        {
            return Err(Error::Conflict);
        }
        self.terminal.check()?;
        self.selection.check()?;
        if kernel.open(self.parent_handle(), &held.child)?.is_some() {
            return Err(Error::Conflict);
        }
        self.terminal.check()?;
        self.selection.check()?;
        Ok(())
    }
    // Private: callers below hard-wire the SAME original Handle.close policy.
    // No caller-provided success fence, JSON or path lookup can invoke this.
    fn record_closed_handle_ack(
        &self,
        ack: Rc<KeyHandleClosed>,
        verify: impl FnOnce(&H, &Rc<KeyHandleClosed>) -> Result<()>,
    ) -> Result<()> {
        verify(self.handle(), &ack)?;
        *self.closed.borrow_mut() = Some(ack);
        self.kind
            .set(KeyRootObligationKind::OriginalHandleClosedRootRetained);
        Ok(())
    }
}
impl<H: TerminalKeyHandle> OriginalKeyRootObligation<H> {
    /// Shared production selector; only the external registry and the actual
    /// terminal fence are supplied by the native caller (or OS-boundary tests).
    fn close_terminal<K: RegistryKernel<Handle = H>>(
        self: &Rc<Self>,
        original: &NewKeyAck<Held<H>>,
        kernel: &mut K,
        check: impl Fn() -> Result<()>,
        retain: impl FnOnce(Rc<KeyHandleClosed>) -> Result<()>,
    ) -> Result<()> {
        let held = original.retained_handle();
        let mut selection = self.selection.begin()?;
        if self.selection_attempted.replace(true) {
            return Err(Error::Conflict);
        }
        self.verify_original(original)?;
        receipt::validate_context(&held.context)?;
        if held.context.bindings.get(held.binding.role as usize) != Some(&held.binding)
            || !parent_valid(&held.parent)
            || !held
                .binding
                .registry_path
                .ends_with(&format!("\\{}", held.child))
        {
            return Err(Error::Conflict);
        }
        let mut status = 0;
        for index in 0..MAX_TERMINAL_KEY_READS {
            check()?;
            self.check_health()?;
            status = kernel.original_key_info_status(self.handle())?;
            // Actual syscall outputs retained before every fallible postflight,
            // wait or subsequent read. A present result is not KEY_DELETED.
            self.terminal_status_history
                .try_borrow_mut()
                .map_err(|_| Error::Conflict)?
                .push(status);
            if index == 0 {
                self.first_terminal_status.set(Some(status));
            }
            check()?;
            self.check_health()?;
            if status != 0 || index + 1 == MAX_TERMINAL_KEY_READS {
                break;
            }
            if !kernel.pause_original_delete_read()? {
                break;
            }
            check()?;
            self.check_health()?;
        }
        if status == 1018 {
            self.close_sdk_deleted(
                original,
                kernel,
                || {
                    check()?;
                    self.selection.check()
                },
                retain,
            )?;
        } else {
            if status != 0 {
                return Err(Error::Pending);
            }
            if !kernel
                .name(self.handle())?
                .eq_ignore_ascii_case(&format!("{}\\{}", held.parent, held.child))
                || kernel.value(self.handle())? != NativeValue::Absent
            {
                return Err(Error::Conflict);
            }
            self.kind
                .set(KeyRootObligationKind::UncertainOriginalKeyRoot);
            // Closing the HKEY does not dispose the surviving registry root.
            // It would destroy the SAME original needed by any subsequent
            // exact-owned disposition, leaving permanent cleanup-pending.
            // Keep both originals open; metadata is retained DATA only.
            let capture = Rc::new(registry_metadata::RegistryMetadataCapture::new());
            *self
                .present_metadata
                .try_borrow_mut()
                .map_err(|_| Error::Conflict)? = Some(capture.clone());
            check()?;
            self.selection.check()?;
            kernel.original_key_metadata(self.handle(), &capture)?;
            check()?;
            self.selection.check()?;
            return Err(Error::Pending);
        }
        self.selection.check()?;
        selection.complete = true;
        Ok(())
    }
    fn close_sdk_deleted<K: RegistryKernel<Handle = H>>(
        self: &Rc<Self>,
        original: &NewKeyAck<Held<H>>,
        kernel: &mut K,
        check: impl Fn() -> Result<()>,
        retain: impl FnOnce(Rc<KeyHandleClosed>) -> Result<()>,
    ) -> Result<()> {
        let mut call = self.terminal.begin()?;
        if self.terminal_complete.get() {
            return Err(Error::Conflict);
        }
        self.observe_sdk_deleted(original, kernel, &check)?;
        self.terminal.check()?;
        let held = original.retained_handle();
        self.handle().close_original(
            || {
                check()?;
                self.terminal.check()
            },
            |ack| {
                self.record_closed_handle_ack(ack.clone(), |h, a| h.verify_closed(a))?;
                retain(ack)?;
                self.terminal.check()
            },
            || {
                check()?;
                self.terminal.check()
            },
        )?;
        // Do not query the now-closed child. Recheck SAME original parent and
        // relative name, never reopen a replacement parent/path.
        check()?;
        self.check_health()?;
        self.verify_parent_absent(held, kernel)?;
        self.check_health()?;
        self.parent_handle().close_original(
            // No HKEY query once close.run marks the handle attempted. The
            // actual original fence and relative reads ran immediately above.
            || self.check_health(),
            |ack| {
                self.parent_handle().verify_closed(&ack)?;
                *self
                    .parent_closed
                    .try_borrow_mut()
                    .map_err(|_| Error::Conflict)? = Some(ack);
                Ok(())
            },
            || {
                check()?;
                self.terminal.check()
            },
        )?;
        self.observation.check()?;
        self.terminal.check()?;
        self.terminal_complete.set(true);
        call.complete = true;
        Ok(())
    }
}
impl<H> Drop for OriginalKeyRootObligation<H> {
    fn drop(&mut self) {
        if self.closed.get_mut().is_some() {
            // Set ONLY after this SAME native Handle.close.verify_ack succeeds.
            // Native Handle Drop is now inert (its explicit close was attempted).
            unsafe {
                std::mem::ManuallyDrop::drop(&mut self.handle);
            }
        }
        if self.parent_closed.get_mut().is_some() {
            // SAME native parent close receipt, not child-close inference.
            unsafe {
                std::mem::ManuallyDrop::drop(&mut self.parent_handle);
            }
        }
        // Otherwise ManuallyDrop preserves the original, without implicit
        // RegCloseKey, native retry, effect grant or inference from absence.
    }
}
/// PURE owning handoff to Main/Pauli. Caller roots this SAME Rc before any
/// fallible terminal inspection. No Source/Authority/journal/native entry,
/// importing from equal metadata or handle/DLL reconstruction occurs here.
pub(crate) fn terminal_original_key_obligation<H>(
    original: &NewKeyAck<Held<H>>,
) -> Rc<OriginalKeyRootObligation<H>> {
    original.retained_handle().handle.clone()
}
/// Actual owning create ACK handle, not Clone, serde or a numeric journal key.
pub(crate) struct Held<H> {
    handle: Rc<OriginalKeyRootObligation<H>>,
    parent: String,
    child: String,
    context: Context,
    binding: Binding,
}
impl<H> Held<H> {
    fn handle(&self) -> &H {
        self.handle.handle()
    }
}
/// Read-only continuity of the SAME retained NEW-key ACK at the last NIC-create
/// seam. Does not create a capability or authenticate a runtime/claim/lock;
/// the concrete module authority must independently hold/recheck all of those.
/// Only original handles are read, no path adoption or registry mutation.
pub(crate) fn reattest_disabled_original_key<K: RegistryKernel>(
    kernel: &mut K,
    record: &Record,
    binding: &Binding,
    ack: &NewKeyAck<Held<K::Handle>>,
) -> Result<()> {
    receipt::validate_carrier_create_stage(record, &record.context, binding, record.generation)?;
    read_original_disabled_key(kernel, record, binding, ack)
}

/// Shared native contents only. Both entry points validate their OWN exact
/// lifecycle and role before entering this private reader.
fn read_original_disabled_key<K: RegistryKernel>(
    kernel: &mut K,
    record: &Record,
    binding: &Binding,
    ack: &NewKeyAck<Held<K::Handle>>,
) -> Result<()> {
    let held = ack.retained_handle();
    let child = binding
        .registry_path
        .strip_prefix(PARENT)
        .and_then(|s| s.strip_prefix('\\'))
        .filter(|s| s.len() == 38 && !s.contains('\\'))
        .ok_or(Error::Invalid)?;
    if held.context != record.context || held.binding != *binding || held.child != child {
        return Err(Error::Conflict);
    }
    let parent = kernel.interfaces()?;
    let parent_name = kernel.name(&parent)?;
    if !parent_valid(&parent_name) || !held.parent.eq_ignore_ascii_case(&parent_name) {
        return Err(Error::Conflict);
    }
    let current = kernel.open(&parent, child)?.ok_or(Error::Conflict)?;
    let expected = format!("{parent_name}\\{child}");
    for _ in 0..2 {
        if !kernel.name(held.handle())?.eq_ignore_ascii_case(&expected)
            || !kernel.name(&current)?.eq_ignore_ascii_case(&expected)
            || !kernel.name(&parent)?.eq_ignore_ascii_case(&parent_name)
            || kernel.value(held.handle())? != NativeValue::Dword(0)
            || kernel.value(&current)? != NativeValue::Dword(0)
        {
            return Err(Error::Conflict);
        }
    }
    Ok(())
}
/// Separate member prerequisite; never broadens the existing C-only API.
pub(crate) fn reattest_disabled_original_member_key<K: RegistryKernel>(
    kernel: &mut K,
    record: &Record,
    context: &Context,
    binding: &Binding,
    generation: u64,
    ack: &NewKeyAck<Held<K::Handle>>,
) -> Result<()> {
    receipt::validate_record(record)?;
    let index = match binding.role {
        receipt::Role::MemberA => 1,
        receipt::Role::MemberB => 2,
        receipt::Role::RoleCarrier => return Err(Error::Conflict),
    };
    let key = &record.keys[index];
    if record.context != *context
        || generation == 0
        || record.generation != generation
        || record.phase != Phase::Preparing
        || context.bindings[index] != *binding
        || key.role != binding.role
        || key.phase != KeyPhase::Disabled
        || !key.new_key_ack
        || key.baseline != Value::Absent
        || key.current != Value::DwordZero
        || key.pending.is_some()
    {
        return Err(Error::Conflict);
    }
    read_original_disabled_key(kernel, record, binding, ack)
}

pub(crate) struct Keys<K: RegistryKernel, A: NativeAuthority> {
    kernel: K,
    authority: A,
    context: Context,
    poisoned: bool,
    // SAME native NEW-create ACK, retained BEFORE any fallible postflight.
    // Private read aliases cannot escape. An uncertain attempt is never adopted
    // or retried; the owning assembly retains Keys and its original authority.
    pending_key: Option<Rc<NewKeyAck<Held<K::Handle>>>>,
}
impl<K: RegistryKernel, A: NativeAuthority> Drop for Keys<K, A> {
    fn drop(&mut self) {
        if let Some(original) = self.pending_key.take() {
            // No successful cleanup/transfer ACK: do not implicitly release the
            // actual newly-created handle merely because postflight failed.
            std::mem::forget(original);
        }
    }
}

#[cfg(windows)]
impl<I: super::member_carrier_key_authority::OriginalCreatorInventory>
    receipt::NativeKeyAttachment<
        super::member_session::WindowsNativeCarrierReceiptStore<
            super::member_session::NativeSessionFiles,
        >,
    > for Keys<win32::Kernel, super::member_carrier_key_authority::KeyAuthority<I>>
{
    fn assert_original_journal_lock(
        &mut self,
        journal: &super::member_session::WindowsNativeCarrierReceiptStore<
            super::member_session::NativeSessionFiles,
        >,
        lock: &mut Self::MutationLock,
        context: &Context,
    ) -> Result<()> {
        self.assert_serialized_lock(lock, context)?;
        let runtime = self.authority.read_pin(lock)?;
        if !runtime.fresh(context)? {
            return Err(Error::Retired);
        }
        runtime.verify_same_session_files(context, journal.original_files(context)?)?;
        self.assert_serialized_lock(lock, context)?;
        if !runtime.fresh(context)? {
            return Err(Error::Retired);
        }
        Ok(())
    }
}
pub(crate) fn decode_name(bytes: &[u8], returned: usize) -> Result<String> {
    if !(6..=MAX_NAME).contains(&returned) || returned > bytes.len() {
        return Err(Error::Invalid);
    }
    let n = u32::from_le_bytes(bytes[..4].try_into().map_err(|_| Error::Invalid)?) as usize;
    if n == 0 || n % 2 != 0 || n.checked_add(4) != Some(returned) {
        return Err(Error::Invalid);
    }
    let chars: Vec<u16> = bytes[4..returned]
        .chunks_exact(2)
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        .collect();
    let name = String::from_utf16(&chars).map_err(|_| Error::Invalid)?;
    if name.chars().any(|c| c.is_control()) {
        return Err(Error::Invalid);
    }
    Ok(name)
}
pub(crate) fn parent_valid(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let parts: Vec<_> = lower.split('\\').collect();
    parts.len() == 9
        && parts[..4] == ["", "registry", "machine", "system"]
        && parts[4].len() == 13
        && parts[4].starts_with("controlset")
        && parts[4][10..].bytes().all(|b| b.is_ascii_digit())
        && &parts[4][10..] != "000"
        && parts[5..] == ["services", "tcpip", "parameters", "interfaces"]
}
impl<K: RegistryKernel, A: NativeAuthority> Keys<K, A> {
    pub(crate) fn new(kernel: K, authority: A, context: Context) -> Self {
        Self {
            kernel,
            authority,
            context,
            poisoned: false,
            pending_key: None,
        }
    }
    /// Actual CREATED_NEW returned but later capture postflight failed. This
    /// retains the owning original floor only; it cannot adopt an unknown
    /// native-create result or synthesize NativeOwnership's journal/NEW ACK.
    pub(crate) fn pending_original_key_obligation(
        &self,
    ) -> Result<Rc<OriginalKeyRootObligation<K::Handle>>> {
        self.pending_key
            .as_ref()
            .map(|ack| terminal_original_key_obligation(ack))
            .ok_or(Error::Pending)
    }
    fn binding<'a>(&self, record: &'a Record, binding: &Binding) -> Result<&'a Binding> {
        receipt::validate_record(record)?;
        if record.context != self.context {
            return Err(Error::Conflict);
        }
        record
            .context
            .bindings
            .iter()
            .find(|b| *b == binding)
            .ok_or(Error::Conflict)
    }
    fn parent(&mut self) -> Result<(K::Handle, String)> {
        let handle = self.kernel.interfaces()?;
        let name = self.kernel.name(&handle)?;
        if !parent_valid(&name) {
            return Err(Error::Conflict);
        }
        Ok((handle, name))
    }
    fn child(binding: &Binding) -> Result<&str> {
        binding
            .registry_path
            .strip_prefix(PARENT)
            .and_then(|s| s.strip_prefix('\\'))
            .filter(|s| s.len() == 38 && !s.contains('\\'))
            .ok_or(Error::Invalid)
    }
    fn observed(
        &mut self,
        lock: &mut A::Lock,
        record: &Record,
        binding: &Binding,
        retained: Option<&NewKeyAck<Held<K::Handle>>>,
        challenge: u64,
    ) -> Result<NativeFacts> {
        if self.poisoned {
            return Err(Error::Pending);
        }
        let root = retained
            .filter(|_| matches!(record.phase, Phase::Closing | Phase::Stopped))
            .map(terminal_original_key_obligation);
        let mut call = root.as_ref().map(|r| r.sampling.begin()).transpose()?;
        let facts = self.observed_inner(lock, record, binding, retained, challenge)?;
        if let Some(root) = &root {
            root.check_health()?;
        }
        if let Some(call) = &mut call {
            call.complete = true;
        }
        Ok(facts)
    }
    fn observed_inner(
        &mut self,
        lock: &mut A::Lock,
        record: &Record,
        binding: &Binding,
        retained: Option<&NewKeyAck<Held<K::Handle>>>,
        challenge: u64,
    ) -> Result<NativeFacts> {
        self.assert_serialized_lock(lock, &record.context)?;
        self.binding(record, binding)?;
        if challenge == 0 {
            return Err(Error::Pending);
        }
        let child = Self::child(binding)?;
        let cleanup_original =
            retained.filter(|_| matches!(record.phase, Phase::Closing | Phase::Stopped));
        let fresh_parent = if cleanup_original.is_none() {
            Some(self.parent()?)
        } else {
            None
        };
        let (parent, parent_name) = if let Some(ack) = cleanup_original {
            let held = ack.retained_handle();
            if held.context != self.context || held.binding != *binding || held.child != child {
                return Err(Error::Conflict);
            }
            let name = self.kernel.name(held.handle.parent_handle())?;
            if !parent_valid(&name) || !name.eq_ignore_ascii_case(&held.parent) {
                return Err(Error::Conflict);
            }
            (held.handle.parent_handle(), name)
        } else {
            let (parent, name) = fresh_parent.as_ref().ok_or(Error::Conflict)?;
            (parent, name.clone())
        };
        let expected = format!("{parent_name}\\{child}");
        let opened = self.kernel.open(parent, child)?;
        let (key, value) = match (opened, retained) {
            (None, None) => (KeyPresence::Absent, NativeValue::Absent),
            (None, Some(ack)) if cleanup_original.is_some() => {
                let root = terminal_original_key_obligation(ack);
                let authority = &mut self.authority;
                root.observe_sdk_deleted(ack, &mut self.kernel, || {
                    authority.verify(lock, &self.context)
                })?;
                (KeyPresence::OriginalSdkDeleted, NativeValue::Absent)
            }
            (None, Some(_)) => return Err(Error::Conflict),
            (Some(opened), None) => {
                if !self.kernel.name(&opened)?.eq_ignore_ascii_case(&expected) {
                    return Err(Error::Conflict);
                }
                (KeyPresence::Foreign, self.kernel.value(&opened)?)
            }
            (Some(opened), Some(ack)) => {
                let held = ack.retained_handle();
                if held.context != self.context
                    || held.binding != *binding
                    || held.child != child
                    || !held.parent.eq_ignore_ascii_case(&parent_name)
                    || !self
                        .kernel
                        .name(held.handle())?
                        .eq_ignore_ascii_case(&expected)
                    || !self.kernel.name(&opened)?.eq_ignore_ascii_case(&expected)
                {
                    return Err(Error::Conflict);
                }
                let value = self.kernel.value(held.handle())?;
                if value != self.kernel.value(&opened)?
                    || !self
                        .kernel
                        .name(held.handle())?
                        .eq_ignore_ascii_case(&expected)
                    || !self.kernel.name(parent)?.eq_ignore_ascii_case(&parent_name)
                {
                    return Err(Error::Conflict);
                }
                (KeyPresence::ExactRetainedNewKey, value)
            }
        };
        let (name_absent, guid_absent, retained_nic_absent) =
            self.authority.nic_absence(lock, &self.context, binding)?;
        self.assert_serialized_lock(lock, &record.context)?;
        Ok(NativeFacts {
            context: self.context.clone(),
            binding: binding.clone(),
            generation: record.generation,
            challenge,
            key,
            value,
            name_absent,
            guid_absent,
            retained_nic_absent,
        })
    }
    fn check_fact(record: &Record, binding: &Binding, f: &NativeFacts) -> Result<()> {
        if f.context != record.context
            || f.binding != *binding
            || f.generation != record.generation
            || f.challenge == 0
            || !f.name_absent
            || !f.guid_absent
            || !f.retained_nic_absent
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    fn key_phase<'a>(record: &'a Record, binding: &Binding) -> Result<&'a receipt::KeyReceipt> {
        record
            .keys
            .iter()
            .find(|k| k.role == binding.role)
            .ok_or(Error::Invalid)
    }
}
impl<K: RegistryKernel, A: NativeAuthority> NativeKeyIo for Keys<K, A> {
    type Key = Held<K::Handle>;
    type MutationLock = A::Lock;
    fn assert_serialized_lock(&mut self, lock: &mut A::Lock, context: &Context) -> Result<()> {
        if context != &self.context {
            return Err(Error::Conflict);
        }
        self.authority.verify(lock, context)
    }
    fn inspect(
        &mut self,
        lock: &mut A::Lock,
        record: &Record,
        binding: &Binding,
        retained: Option<&NewKeyAck<Self::Key>>,
        challenge: u64,
    ) -> Result<NativeFacts> {
        self.observed(lock, record, binding, retained, challenge)
    }
    fn create_new_key(
        &mut self,
        lock: &mut A::Lock,
        pending: &Record,
        binding: &Binding,
        absent: &NativeFacts,
    ) -> Result<NewKeyAck<Self::Key>> {
        if self.poisoned || self.pending_key.is_some() {
            return Err(Error::Pending);
        }
        Self::check_fact(pending, binding, absent)?;
        self.binding(pending, binding)?;
        if pending.phase != Phase::Preparing
            || Self::key_phase(pending, binding)?.phase != KeyPhase::CreatePending
            || absent.key != KeyPresence::Absent
            || absent.value != NativeValue::Absent
        {
            return Err(Error::Conflict);
        }
        let fresh = self.observed(lock, pending, binding, None, absent.challenge)?;
        Self::check_fact(pending, binding, &fresh)?;
        if fresh.key != KeyPresence::Absent || fresh.value != NativeValue::Absent {
            return Err(Error::Conflict);
        }
        let (parent, parent_name) = self.parent()?;
        let child = Self::child(binding)?.to_owned();
        // Complete allocating metadata BEFORE a native owning handle exists.
        let key_context = self.context.clone();
        let key_binding = binding.clone();
        self.assert_serialized_lock(lock, &pending.context)?;
        self.authority
            .authorize_effect(lock, pending, binding, Effect::Create)?;
        self.poisoned = true;
        let (handle, disposition) = self
            .kernel
            .create(&parent, &child)
            .inspect_err(|_| self.poisoned = true)?;
        if disposition != 1 {
            self.poisoned = true;
            return Err(Error::Pending);
        }
        let held = Held {
            handle: Rc::new(OriginalKeyRootObligation::new(handle, parent)),
            parent: parent_name,
            child,
            context: key_context,
            binding: key_binding,
        };
        self.pending_key = Some(Rc::new(NewKeyAck::from_native_created_new_key(1, held)?));
        let ack = self
            .pending_key
            .as_ref()
            .expect("retained NEW-key ACK")
            .clone();
        self.kernel
            .flush(ack.retained_handle().handle.parent_handle())
            .inspect_err(|_| self.poisoned = true)?;
        let read = self
            .observed_inner(lock, pending, binding, Some(ack.as_ref()), absent.challenge)
            .inspect_err(|_| self.poisoned = true)?;
        Self::check_fact(pending, binding, &read)?;
        if read.key != KeyPresence::ExactRetainedNewKey || read.value != NativeValue::Absent {
            self.poisoned = true;
            return Err(Error::Conflict);
        }
        drop(ack);
        let retained = self.pending_key.take().expect("retained NEW-key ACK");
        match Rc::try_unwrap(retained) {
            Ok(original) => {
                original
                    .retained_handle()
                    .handle
                    .kind
                    .set(KeyRootObligationKind::CreatedKeyRootRetained);
                self.poisoned = false;
                Ok(original)
            }
            Err(original) => {
                self.pending_key = Some(original);
                Err(Error::Pending)
            }
        }
    }
    fn compare_exchange_value(
        &mut self,
        lock: &mut A::Lock,
        pending: &Record,
        binding: &Binding,
        retained: &NewKeyAck<Self::Key>,
        fresh: &NativeFacts,
        mutation: ValueCas,
    ) -> Result<()> {
        self.binding(pending, binding)?;
        Self::check_fact(pending, binding, fresh)?;
        let key = Self::key_phase(pending, binding)?;
        let phase_allows = matches!(
            (
                pending.phase,
                key.phase,
                mutation.expected,
                mutation.desired
            ),
            (
                Phase::Preparing,
                KeyPhase::DisablePending,
                Value::Absent,
                Value::DwordZero
            ) | (
                Phase::Closing,
                KeyPhase::RestorePending,
                Value::DwordZero,
                Value::Absent
            )
        ) || (pending.phase == Phase::Preparing
            && binding.role != receipt::Role::RoleCarrier
            && key.phase == KeyPhase::RestorePending
            && mutation.expected == Value::DwordZero
            && mutation.desired == Value::Absent);
        if mutation.value_name != VALUE
            || !key.new_key_ack
            || key.current != mutation.expected
            || key.pending != Some(mutation.desired)
            || !phase_allows
        {
            return Err(Error::Invalid);
        }
        let expected = match mutation.expected {
            Value::Absent => NativeValue::Absent,
            Value::DwordZero => NativeValue::Dword(0),
        };
        let desired = match mutation.desired {
            Value::Absent => NativeValue::Absent,
            Value::DwordZero => NativeValue::Dword(0),
        };
        if fresh.key != KeyPresence::ExactRetainedNewKey || fresh.value != expected {
            return Err(Error::Conflict);
        }
        let current = self.observed(lock, pending, binding, Some(retained), fresh.challenge)?;
        Self::check_fact(pending, binding, &current)?;
        if current.key != KeyPresence::ExactRetainedNewKey || current.value != expected {
            return Err(Error::Conflict);
        }
        self.assert_serialized_lock(lock, &pending.context)?;
        self.authority
            .authorize_effect(lock, pending, binding, Effect::Value(mutation))?;
        // Windows offers no registry value CAS. Serialization is independently
        // mandatory; only our captured handle is written, never an opened path.
        self.poisoned = true;
        let original = &retained.retained_handle().handle;
        original
            .kind
            .set(KeyRootObligationKind::UncertainOriginalKeyRoot);
        let h = original.handle();
        match mutation.desired {
            Value::DwordZero => self.kernel.zero(h)?,
            Value::Absent => self.kernel.delete_value(h)?,
        }
        self.kernel.flush(h)?;
        let after = self
            .observed_inner(lock, pending, binding, Some(retained), fresh.challenge)
            .inspect_err(|_| self.poisoned = true)?;
        Self::check_fact(pending, binding, &after).inspect_err(|_| self.poisoned = true)?;
        if after.key != KeyPresence::ExactRetainedNewKey || after.value != desired {
            self.poisoned = true;
            return Err(Error::Conflict);
        }
        self.poisoned = false;
        original.kind.set(if mutation.desired == Value::Absent {
            KeyRootObligationKind::ValueRestoreObservedRootRetained
        } else {
            KeyRootObligationKind::CreatedKeyRootRetained
        });
        Ok(())
    }
}

#[cfg(test)]
#[path = "member_carrier_keys_tests.rs"]
mod tests;

/// Actual retained NEW handle only, selected by NativeOwnership's terminal
/// callback. The caller roots its returned close ACK before terminal postflight.
#[cfg(windows)]
pub(crate) fn close_terminal_original_key(
    original: &NewKeyAck<Held<win32::Handle>>,
    fence: &impl NativeKeyTerminalFence,
    retain: impl FnOnce(Rc<KeyHandleClosed>) -> Result<()>,
) -> Result<()> {
    let held = original.retained_handle();
    held.handle.close_terminal(
        original,
        &mut win32::Kernel,
        || fence.verify_original_terminal(&held.context, &held.binding),
        retain,
    )
}
#[cfg(windows)]
pub(crate) fn verify_terminal_original_key_closed(
    original: &NewKeyAck<Held<win32::Handle>>,
    ack: &Rc<KeyHandleClosed>,
) -> Result<()> {
    original.retained_handle().handle().close.verify_ack(ack)
}

/// Audited SDK boundary, not a custom FFI or numeric/path ownership surrogate.
#[cfg(windows)]
pub(crate) mod win32 {
    use super::*;
    use std::ptr;
    use windows_sys::{
        Wdk::System::Registry::{KeyNameInformation, NtQueryKey},
        Win32::{
            Foundation::{ERROR_FILE_NOT_FOUND, NO_ERROR},
            System::Registry::*,
        },
    };
    pub(crate) struct Handle {
        raw: HKEY,
        pub(super) close: KeyHandleClose,
    }
    impl Handle {
        fn new(raw: HKEY) -> Self {
            Self {
                raw,
                close: KeyHandleClose::new(),
            }
        }
        fn raw(&self) -> Result<HKEY> {
            if self.raw.is_null() || self.close.was_attempted() {
                return Err(Error::Pending);
            }
            Ok(self.raw)
        }
        pub(super) fn close_terminal(
            &self,
            check: impl FnOnce() -> Result<()>,
            retain: impl FnOnce(Rc<KeyHandleClosed>) -> Result<()>,
            post: impl FnOnce() -> Result<()>,
        ) -> Result<()> {
            let raw = self.raw()?;
            self.close
                .run(check, || status(unsafe { RegCloseKey(raw) }), retain, post)
        }
    }
    impl Drop for Handle {
        fn drop(&mut self) {
            if !self.raw.is_null() && !self.close.was_attempted() {
                unsafe {
                    RegCloseKey(self.raw);
                }
            }
        }
    }
    impl TerminalKeyHandle for Handle {
        fn close_original(
            &self,
            check: impl FnOnce() -> Result<()>,
            retain: impl FnOnce(Rc<KeyHandleClosed>) -> Result<()>,
            post: impl FnOnce() -> Result<()>,
        ) -> Result<()> {
            self.close_terminal(check, retain, post)
        }
        fn verify_closed(&self, ack: &Rc<KeyHandleClosed>) -> Result<()> {
            self.close.verify_ack(ack)
        }
    }
    pub(crate) struct Kernel;
    fn wide(s: &str) -> Result<Vec<u16>> {
        if s.is_empty() || s.len() > 1024 || s.chars().any(|c| c.is_control()) {
            return Err(Error::Invalid);
        }
        Ok(s.encode_utf16().chain(Some(0)).collect())
    }
    fn status(rc: u32) -> Result<()> {
        if rc == NO_ERROR {
            Ok(())
        } else {
            Err(Error::Pending)
        }
    }
    fn owned(rc: u32, handle: HKEY) -> Result<Handle> {
        let h = Handle::new(handle);
        status(rc)?;
        if h.raw.is_null() {
            return Err(Error::Pending);
        }
        Ok(h)
    }
    impl RegistryKernel for Kernel {
        type Handle = Handle;
        fn pause_original_delete_read(&mut self) -> Result<bool> {
            std::thread::sleep(std::time::Duration::from_millis(25));
            Ok(true)
        }
        fn original_key_metadata(
            &mut self,
            h: &Handle,
            capture: &registry_metadata::RegistryMetadataCapture,
        ) -> Result<()> {
            // SAFETY: SAME still-open owning original is borrowed for the whole
            // synchronous query. No raw handle escapes, open/reopen or close.
            unsafe { capture.read_original_native(h.raw()?) }.map_err(|_| Error::Pending)
        }
        fn original_key_info_status(&mut self, h: &Handle) -> Result<u32> {
            // Status is factual even on failure; only exact KEY_DELETED from
            // this still-open original can enter the sealed observer protocol.
            Ok(unsafe {
                RegQueryInfoKeyW(
                    h.raw()?,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            })
        }
        fn interfaces(&mut self) -> Result<Handle> {
            let p = wide(PARENT)?;
            let mut h = ptr::null_mut();
            owned(
                unsafe {
                    RegOpenKeyExW(
                        HKEY_LOCAL_MACHINE,
                        p.as_ptr(),
                        0,
                        KEY_QUERY_VALUE | KEY_CREATE_SUB_KEY,
                        &mut h,
                    )
                },
                h,
            )
        }
        fn name(&mut self, h: &Handle) -> Result<String> {
            // Fixed aligned buffer, never use attacker-controlled required size
            // to allocate. Native result excludes a terminating WCHAR.
            let mut buffer = [0u32; MAX_NAME / 4];
            let mut n = 0u32;
            let rc = unsafe {
                NtQueryKey(
                    h.raw()?,
                    KeyNameInformation,
                    buffer.as_mut_ptr().cast(),
                    MAX_NAME as u32,
                    &mut n,
                )
            };
            if rc != 0 {
                return Err(Error::Conflict);
            }
            let bytes =
                unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), MAX_NAME) };
            decode_name(bytes, n as usize)
        }
        fn open(&mut self, parent: &Handle, child: &str) -> Result<Option<Handle>> {
            let child = wide(child)?;
            let mut h = ptr::null_mut();
            let rc = unsafe {
                RegOpenKeyExW(
                    parent.raw()?,
                    child.as_ptr(),
                    REG_OPTION_OPEN_LINK,
                    KEY_QUERY_VALUE,
                    &mut h,
                )
            };
            if rc == ERROR_FILE_NOT_FOUND {
                let _h = Handle::new(h);
                return Ok(None);
            }
            owned(rc, h).map(Some)
        }
        fn create(&mut self, parent: &Handle, child: &str) -> Result<(Handle, u32)> {
            let child = wide(child)?;
            let mut h = ptr::null_mut();
            let mut disposition = 0;
            let rc = unsafe {
                RegCreateKeyExW(
                    parent.raw()?,
                    child.as_ptr(),
                    0,
                    ptr::null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_QUERY_VALUE | KEY_SET_VALUE,
                    ptr::null(),
                    &mut h,
                    &mut disposition,
                )
            };
            Ok((owned(rc, h)?, disposition))
        }
        fn value(&mut self, h: &Handle) -> Result<NativeValue> {
            let name = wide(VALUE)?;
            let mut data = [0u8; 256];
            let mut len = data.len() as u32;
            let mut kind = 0;
            let rc = unsafe {
                RegQueryValueExW(
                    h.raw()?,
                    name.as_ptr(),
                    ptr::null(),
                    &mut kind,
                    data.as_mut_ptr(),
                    &mut len,
                )
            };
            if rc == ERROR_FILE_NOT_FOUND {
                return Ok(NativeValue::Absent);
            }
            status(rc)?;
            if len as usize > data.len() {
                return Err(Error::Invalid);
            }
            decode_value(kind, &data[..len as usize])
        }
        fn zero(&mut self, h: &Handle) -> Result<()> {
            let name = wide(VALUE)?;
            let bytes = 0u32.to_le_bytes();
            status(unsafe {
                RegSetValueExW(h.raw()?, name.as_ptr(), 0, REG_DWORD, bytes.as_ptr(), 4)
            })
        }
        fn delete_value(&mut self, h: &Handle) -> Result<()> {
            let name = wide(VALUE)?;
            status(unsafe { RegDeleteValueW(h.raw()?, name.as_ptr()) })
        }
        fn flush(&mut self, h: &Handle) -> Result<()> {
            status(unsafe { RegFlushKey(h.raw()?) })
        }
    }
}
