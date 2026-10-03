//! Serialized original-owner carrier actor. Not selected by any product factory.
//! Registration and copied comparison data never grant a native effect.
#![allow(dead_code)]

use std::{cell::Cell, io};

#[cfg(windows)]
use crate::windows::member_carrier_rows as storage_rows;

#[cfg(windows)]
/// Storage-only handoff. Canonical-file lookup can fail/unwind, so it must run
/// AFTER this SAME actual owner has irrevocably denied forward use. Neither
/// this ordering nor the supplied files grant a native effect or record ACK.
fn enter_original_row_storage_cleanup<
    A: storage_rows::Authority,
    K: storage_rows::Kernel,
    J: storage_rows::Journal,
    F,
>(
    owner: &mut storage_rows::RowOwner<A, K, J>,
    canonical: impl FnOnce() -> storage_rows::Result<F>,
    handoff: impl FnOnce(&mut J, F) -> storage_rows::Result<()>,
) -> storage_rows::Result<()> {
    owner.enter_storage_cleanup(|journal| handoff(journal, canonical()?))
}

#[cfg(windows)]
fn verify_terminal_member_row_original<
    A: storage_rows::Authority,
    K: storage_rows::Kernel,
    J: storage_rows::Journal,
>(
    owner: &storage_rows::RowOwner<A, K, J>,
    pin: &storage_rows::RowRecordReadPin,
    observed_ack: &storage_rows::Record,
) -> storage_rows::Result<()> {
    // Facts ONLY; caller independently holds original Runtime/Retired/protected
    // storage/full SDK bracket. Equal JSON cannot replace this actual owner.
    if !pin.same_original(&owner.record_read_pin()?) {
        return Err(storage_rows::Error::Conflict);
    }
    let binding = &observed_ack.binding;
    pin.with_cleanup_record(&binding.scope, binding.network_epoch, |actual| {
        if !matches!(
            actual.binding.role,
            storage_rows::Role::MemberA | storage_rows::Role::MemberB
        ) || actual.acknowledged != observed_ack
            || actual.acknowledged.phase != storage_rows::Phase::Stopped
            || actual.acknowledged.pending.is_some()
            || actual.acknowledged.current.address.is_some()
            || actual.acknowledged.current.interface.policy
                != actual.acknowledged.baseline.interface.policy
        {
            return Err(storage_rows::Error::Conflict);
        }
        Ok(())
    })
}

fn conflict() -> io::Error {
    io::Error::other("carrier_actor_original_or_pending")
}
fn clone_original_capture_pair<A, B>(
    first: &Option<std::rc::Rc<A>>,
    second: &Option<std::rc::Rc<B>>,
) -> io::Result<(std::rc::Rc<A>, std::rc::Rc<B>)> {
    let first = first.as_ref().ok_or_else(conflict)?;
    let second = second.as_ref().ok_or_else(conflict)?;
    Ok((first.clone(), second.clone()))
}

/// Provider-issued original facts only. No Unknown/metadata/default variant:
/// a failed provider boundary cannot reach the typed dispatcher at all.
pub(crate) enum OriginalTerminalBranch<N: ?Sized, A: ?Sized> {
    ZeroEffect(std::rc::Rc<N>),
    NativeAttempted(std::rc::Rc<A>),
}
fn dispatch_original_terminal_branch<N: ?Sized, A: ?Sized, T>(
    original: &OriginalTerminalBranch<N, A>,
    no_effect: impl FnOnce(&std::rc::Rc<N>) -> io::Result<T>,
    attempted: impl FnOnce(&std::rc::Rc<A>) -> io::Result<T>,
) -> io::Result<T> {
    match original {
        OriginalTerminalBranch::ZeroEffect(same) => no_effect(same),
        OriginalTerminalBranch::NativeAttempted(same) => attempted(same),
    }
}

/// Private owning history cut, not a terminal/native permission. The original
/// caller-retained raw destination exists BEFORE any field move or callback.
/// Reverse origin identity is Weak; no hidden source alias survives T release.
struct OriginalGenerationTransfer<T> {
    attempted: bool,
    original: std::rc::Weak<OriginalGenerationCut<T>>,
}
pub(crate) struct OriginalGenerationCut<T> {
    original: std::cell::RefCell<Option<T>>,
}
impl<T> Default for OriginalGenerationTransfer<T> {
    fn default() -> Self {
        Self {
            attempted: false,
            original: std::rc::Weak::new(),
        }
    }
}
impl<T> OriginalGenerationTransfer<T> {
    fn capture(
        &mut self,
        destination: &mut GenerationTerminalResources<T>,
        transfer: impl FnOnce(&mut Option<T>) -> io::Result<()>,
    ) -> io::Result<()> {
        if std::mem::replace(&mut self.attempted, true) || destination.retained().is_some() {
            return Err(conflict());
        }
        let original = std::rc::Rc::new(OriginalGenerationCut {
            original: std::cell::RefCell::new(None),
        });
        self.original = std::rc::Rc::downgrade(&original);
        *destination.retained_mut() = Some(original.clone());
        let result = transfer(&mut original.original.borrow_mut());
        result
    }
    fn original(&self) -> io::Result<std::rc::Rc<OriginalGenerationCut<T>>> {
        self.original.upgrade().ok_or_else(conflict)
    }
    fn read_cut(&self) -> io::Result<Option<std::rc::Rc<OriginalGenerationCut<T>>>> {
        if self.attempted {
            self.original().map(Some)
        } else {
            Ok(None)
        }
    }
    fn same_original(&self, original: &std::rc::Rc<OriginalGenerationCut<T>>) -> bool {
        self.attempted
            && self
                .original
                .upgrade()
                .is_some_and(|same| std::rc::Rc::ptr_eq(&same, original))
    }
}
impl<T> OriginalGenerationCut<T> {
    fn inspect<U>(&self, read: impl FnOnce(&T) -> io::Result<U>) -> io::Result<U> {
        let original = self.original.try_borrow().map_err(|_| conflict())?;
        read(original.as_ref().ok_or_else(conflict)?)
    }
}
#[cfg(not(windows))]
type GenerationTerminalResources<T> = crate::member_carrier_assembly::TerminalResources<
    Option<std::rc::Rc<OriginalGenerationCut<T>>>,
>;
#[cfg(windows)]
type GenerationTerminalResources<T> = crate::windows::member_carrier_assembly::TerminalResources<
    Option<std::rc::Rc<OriginalGenerationCut<T>>>,
>;

fn require_member_row_storage_cleanup_frame(
    record: &crate::member_carrier_pair::Record,
    slot: nelomai_client_tunnel::redundancy::Slot,
) -> io::Result<()> {
    use crate::member_carrier_pair::{Effect, Phase};
    use nelomai_client_tunnel::redundancy::Slot;
    record.validate()?;
    if record.phase != Phase::Closing
        || !matches!(
            (record.stop_stage, record.pending, slot),
            (3, Some(Effect::RestoreWeak), _)
                | (4, Some(Effect::MemberStop(Slot::A)), Slot::A)
                | (5, Some(Effect::MemberStop(Slot::B)), Slot::B)
        )
    {
        return Err(conflict());
    }
    Ok(())
}

/// Comparison only: native receipt/original-controller verification is mandatory
/// independently. A same-NIC rebind retires the process, never adopts a NIC.
fn compare_member_rebind_ack(
    prior: &crate::member_owner::Record,
    running: &crate::member_owner::Record,
) -> io::Result<()> {
    crate::member_owner::validate_record_shape(prior).map_err(|_| conflict())?;
    crate::member_owner::validate_record_shape(running).map_err(|_| conflict())?;
    let old = prior.proof.ok_or_else(conflict)?;
    let new = running.proof.ok_or_else(conflict)?;
    if prior.phase != crate::member_owner::Phase::Running
        || running.phase != crate::member_owner::Phase::Running
        || prior.intent != running.intent
        || running.retired_proof != Some(old)
        || new.interface != old.interface
        || new.process == old.process
        || running.previous_config_sha256.is_some()
    {
        return Err(conflict());
    }
    Ok(())
}

/// FullEmpty has two distinct actual Calling channels. This comparison does not
/// authorize either channel or infer absence from the coordinator's metadata.
fn require_full_empty_frame(record: &crate::member_carrier_pair::Record) -> io::Result<()> {
    use crate::member_carrier_pair::{Effect, Phase};
    record.validate()?;
    if record.phase == Phase::Stopped {
        return require_terminal_record(record);
    }
    if record.phase != Phase::Closing
        || record.stop_stage != 12
        || record.pending != Some(Effect::FullEmpty)
        || record.guard.expected
            != crate::member_carrier_guard::Model::empty(record.scope.clone())
                .map_err(|_| conflict())?
                .expected
    {
        return Err(conflict());
    }
    Ok(())
}

/// Observed factual SDK snapshot only. Native BFE/Retired/G brackets remain
/// mandatory; matching JSON or this comparison cannot authorize cleanup.
fn compare_full_empty_snapshot(
    record: &crate::member_carrier_pair::Record,
    observed: &crate::member_carrier_guard::Snapshot,
) -> io::Result<()> {
    require_full_empty_frame(record)?;
    let empty = crate::member_carrier_guard::Model::empty(record.scope.clone())
        .map_err(|_| conflict())?
        .expected;
    if observed != &empty || observed != &record.guard.expected {
        return Err(conflict());
    }
    Ok(())
}

/// Readonly no-constructor comparison, not FullEmpty/Stopped disposition.
#[cfg(any(windows, test))]
fn compare_no_constructor_cleanup_snapshot(
    record: &crate::member_carrier_pair::Record,
    observed: &crate::member_carrier_guard::Snapshot,
) -> io::Result<()> {
    require_no_constructor_cleanup_frame(record)?;
    if observed != &record.guard.expected {
        return Err(conflict());
    }
    Ok(())
}

/// Metadata dispatch only. The native caller must separately authenticate its
/// actual no-constructor history and read SDK/paths/keys/BFE inside Calling.
#[cfg(any(windows, test))]
pub(crate) fn require_no_constructor_cleanup_frame(
    record: &crate::member_carrier_pair::Record,
) -> io::Result<()> {
    use crate::member_carrier_pair::{Effect, Phase};
    use nelomai_client_tunnel::redundancy::Slot;
    record.validate()?;
    let empty =
        crate::member_carrier_guard::Model::empty(record.scope.clone()).map_err(|_| conflict())?;
    if record.carrier.is_some()
        || record.guard != empty
        || !matches!(
            (record.phase, record.stop_stage, record.pending),
            (Phase::Closing, 0, Some(Effect::Guard))
                | (Phase::Closing, 1, Some(Effect::ReleaseProbes))
                | (Phase::Closing, 2, Some(Effect::RestoreNetwork))
                | (Phase::Closing, 3, Some(Effect::RestoreWeak))
                | (Phase::Closing, 4, Some(Effect::MemberStop(Slot::A)))
                | (Phase::Closing, 5, Some(Effect::MemberStop(Slot::B)))
                | (Phase::Closing, 6, Some(Effect::CarrierAddressDelete))
                | (Phase::Closing, 7, Some(Effect::CarrierSessionEnd))
                | (Phase::Closing, 8, Some(Effect::CarrierClose))
                | (Phase::Closing, 9, Some(Effect::NativeEmpty))
                | (Phase::Closing, 10, Some(Effect::Guard))
                | (Phase::Closing, 11, Some(Effect::RestoreKeys))
                | (Phase::Closing, 12, Some(Effect::FullEmpty))
        )
    {
        return Err(conflict());
    }
    Ok(())
}

/// Factual reuse fence only. Actual capture calls additionally require the
/// retained pin to be from THIS RowOwner and freshly verify full native G.
fn require_reusable_member_rows(
    phase: crate::member_carrier_rows::Phase,
    pending: bool,
    cleanup_only: bool,
) -> io::Result<()> {
    if phase != crate::member_carrier_rows::Phase::Captured || pending || cleanup_only {
        return Err(conflict());
    }
    Ok(())
}

/// Retention protocol only; an actual original owner authenticates the ticket
/// and transition. A failed/unwinding projection must never enable preparation.
fn retain_generation_once<T, U>(
    retained: &mut Vec<std::rc::Rc<T>>,
    original: &std::rc::Rc<T>,
    transition: impl FnOnce(&std::rc::Rc<T>) -> io::Result<U>,
) -> io::Result<U> {
    if retained
        .iter()
        .any(|old| std::rc::Rc::ptr_eq(old, original))
    {
        return Err(conflict());
    }
    retained.try_reserve(1).map_err(denied_allocation)?;
    retained.push(original.clone()); // Actual owner pin BEFORE fallible projection.
    transition(original)
}

fn denied_allocation(_: std::collections::TryReserveError) -> io::Error {
    conflict()
}

/// Ownership retention only. New capture still requires its original native
/// authority, opaque generation token and exact durable ACK.
fn with_retained_row_original<T, P, U>(
    current: &mut Option<T>,
    history: &mut Vec<(T, P)>,
    receipt: P,
    capture: impl FnOnce() -> io::Result<U>,
) -> io::Result<U> {
    if current.is_none() {
        return Err(conflict());
    }
    history.try_reserve(1).map_err(denied_allocation)?;
    let original = current.take().ok_or_else(conflict)?;
    history.push((original, receipt)); // all originals BEFORE fallible capture.
    capture()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WeakRowsBoundary {
    Capture(nelomai_client_tunnel::redundancy::Slot),
    Carrier,
    Member(nelomai_client_tunnel::redundancy::Slot),
}
/// Dispatch order only, never member absence or SDK authorization. Every native
/// closure independently calls its original creator, protected ACK and G.
fn weak_rows_sequence(
    present: [bool; 2],
    mut call: impl FnMut(WeakRowsBoundary) -> io::Result<()>,
) -> io::Result<()> {
    use nelomai_client_tunnel::redundancy::Slot;
    for (i, slot) in [Slot::A, Slot::B].into_iter().enumerate() {
        if present[i] {
            call(WeakRowsBoundary::Capture(slot))?;
        }
    }
    call(WeakRowsBoundary::Carrier)?;
    for (i, slot) in [Slot::A, Slot::B].into_iter().enumerate() {
        if present[i] {
            call(WeakRowsBoundary::Member(slot))?;
        }
    }
    Ok(())
}

/// Order/retention only. Each native closure must invoke its actual original
/// owner, not a default success or imported receipt. Never enclose mutation in
/// a Source read callback; the owners independently bracket their native reads.
fn project_generation_order<T>(
    retained: &mut Vec<std::rc::Rc<T>>,
    rows_retire: impl FnOnce() -> io::Result<std::rc::Rc<T>>,
    inventory_retire: impl FnOnce() -> io::Result<()>,
    rows_complete: impl FnOnce(&std::rc::Rc<T>) -> io::Result<()>,
) -> io::Result<std::rc::Rc<T>> {
    let receipt = rows_retire()?;
    retain_generation_once(retained, &receipt, |original| {
        inventory_retire()?;
        rows_complete(original)?;
        Ok(original.clone())
    })
}

/// Exact factual cleanup dispatch only. The mandatory native/Startup reader
/// still proves actual originals, full SDK and ACKs in its current Calling.
fn native_empty_call<T>(
    serial: &ActorSerial,
    record: &crate::member_carrier_pair::Record,
    read: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    serial.run(true, || {
        require_native_empty_frame(record)?;
        read()
    })
}
fn require_native_empty_frame(record: &crate::member_carrier_pair::Record) -> io::Result<()> {
    use crate::member_carrier_pair::{Effect, Phase};
    record.validate()?;
    if record.phase != Phase::Closing
        || !matches!(
            (record.stop_stage, record.pending),
            (9, Some(Effect::NativeEmpty)) | (10, Some(Effect::Guard))
        )
    {
        return Err(conflict());
    }
    Ok(())
}

/// Shared by the actor and its socket aliases. Caught reentry/error/unwind is
/// sticky; a cleanup call can read facts but cannot rearm forward execution.
#[derive(Default)]
struct ActorSerial {
    busy: Cell<bool>,
    revoked: Cell<bool>,
    faults: Cell<u64>,
}
struct ActorCall<'a> {
    owner: &'a ActorSerial,
    faults: u64,
    done: bool,
}
impl ActorSerial {
    fn fault(&self) {
        self.revoked.set(true);
        self.faults.set(self.faults.get().saturating_add(1));
    }
    fn enter(&self, cleanup: bool) -> io::Result<ActorCall<'_>> {
        // Entry failure cannot release another call's serialized borrow.
        if self.busy.get() || (!cleanup && self.revoked.get()) {
            self.fault();
            return Err(conflict());
        }
        self.busy.set(true);
        if cleanup {
            self.revoked.set(true);
        }
        Ok(ActorCall {
            owner: self,
            faults: self.faults.get(),
            done: false,
        })
    }
    fn run<T>(&self, cleanup: bool, call: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
        let flight = self.enter(cleanup)?;
        let value = call()?;
        flight.finish()?;
        Ok(value)
    }
}
impl ActorCall<'_> {
    fn finish(mut self) -> io::Result<()> {
        if self.owner.faults.get() != self.faults {
            return Err(conflict());
        }
        self.done = true;
        Ok(())
    }
}
impl Drop for ActorCall<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.owner.fault();
        }
        self.owner.busy.set(false);
    }
}

/// Shared alias fence only. Actual native IO still authenticates its original
/// deadline/Pair/Guard/lease. A selected storage epoch alone cannot unblock IO
/// while a rebind SDK seal or common completion is pending.
fn execution_forward_call<T>(
    serial: &ActorSerial,
    pending: &Cell<bool>,
    call: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    serial.run(false, || {
        if pending.get() {
            return Err(conflict());
        }
        call()
    })
}

/// Factual comparison ONLY. Native caller supplies closed identity exclusively
/// from SAME actual Source window's private receipt-backed closed history; these
/// Option/bytes comparisons neither prove absence nor create a live provider.
#[cfg(any(windows, test))]
fn compare_execution_member_binding(
    expected_live: Option<crate::member_owner::InterfaceProof>,
    bound: Option<crate::member_owner::InterfaceProof>,
    original_closed: Option<crate::member_owner::InterfaceProof>,
) -> io::Result<()> {
    match (expected_live, bound, original_closed) {
        (Some(expected), Some(actual), None) if expected == actual => Ok(()),
        (None, Some(actual), Some(closed)) if actual == closed => Ok(()),
        (None, None, None) => Ok(()),
        _ => Err(conflict()),
    }
}

#[cfg(any(windows, test))]
#[derive(Debug, PartialEq, Eq)]
enum ExecutionProbeRead {
    Live,
    Retired,
    Uncaptured,
}
/// Chooses a factual read channel, NOT a close receipt/absence/effect grant.
#[cfg(any(windows, test))]
fn execution_probe_read(
    expected: usize,
    actor: bool,
    canonical: bool,
) -> io::Result<ExecutionProbeRead> {
    match (expected, actor, canonical) {
        (1, true, true) => Ok(ExecutionProbeRead::Live),
        (0, true, true) => Ok(ExecutionProbeRead::Retired),
        (0, false, false) => Ok(ExecutionProbeRead::Uncaptured),
        _ => Err(conflict()),
    }
}

/// Ownership transfer only, not a terminal/destructor permission. Both roots
/// retain THIS same Rc before the caller's first fallible handoff. Unknown Drop
/// keeps originals; only the typed native terminal root/ACK path may remove it.
struct ActorResourceTransfer<T> {
    original: Option<std::rc::Rc<T>>,
    attempted: bool,
    complete: bool,
}
/// Owned originals are inert only after the actual typed terminal ACK path.
/// Losing the last factual alias or failing a handoff never substitutes for it.
struct ActorTerminalParts<T> {
    original: std::cell::RefCell<Option<T>>,
    release: Cell<u8>,
}
/// Original coordinator inputs only; no SDK/cleanup/destructor grant.
struct ActorRootOriginals<I, J, H> {
    actor: ActorTerminalParts<I>,
    journal: ActorTerminalParts<Option<J>>,
    coordinator: Option<std::rc::Rc<H>>,
}
impl<I, J, H> ActorRootOriginals<I, J, H> {
    fn new(actor: I, journal: Option<J>, coordinator: Option<std::rc::Rc<H>>) -> Self {
        Self {
            actor: ActorTerminalParts::new(actor),
            journal: ActorTerminalParts::new(journal),
            coordinator,
        }
    }
    fn inspect_journal<T>(
        &self,
        inspect: impl FnOnce(Option<&J>) -> io::Result<T>,
    ) -> io::Result<T> {
        inspect(self.journal.try_borrow()?.as_ref())
    }
}
/// Private one-shot ordering only. A callback cannot manufacture module ACK
/// authority: native callers use the actual root and its opaque ACK exclusively.
#[derive(Default)]
struct ActorUnloadSequence {
    attempted: Cell<bool>,
    completed: Cell<bool>,
    failed: Cell<bool>,
}
/// One-shot ordering ONLY, never a Never/module/destructor capability. Native
/// instantiations retain the actual provider's opaque private-ledger proof;
/// every release still invokes its mandatory same-original disposition method.
struct ZeroEffectDisposition<P: ?Sized> {
    proof: std::cell::RefCell<Option<std::rc::Rc<P>>>,
    capture: Cell<u8>,
    disposal: Cell<u8>,
}
impl<P: ?Sized> Default for ZeroEffectDisposition<P> {
    fn default() -> Self {
        Self {
            proof: std::cell::RefCell::new(None),
            capture: Cell::new(0),
            disposal: Cell::new(0),
        }
    }
}
struct DispositionFlight<'a> {
    state: &'a Cell<u8>,
    done: bool,
}
impl Drop for DispositionFlight<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.state.set(3);
        }
    }
}
impl<P: ?Sized> ZeroEffectDisposition<P> {
    fn capture(
        &self,
        actual: impl FnOnce(&mut dyn FnMut(std::rc::Rc<P>) -> io::Result<()>) -> io::Result<()>,
    ) -> io::Result<()> {
        if self.capture.replace(1) != 0 {
            self.capture.set(3);
            return Err(conflict());
        }
        let mut flight = DispositionFlight {
            state: &self.capture,
            done: false,
        };
        actual(&mut |original| {
            if self.capture.get() != 1 {
                return Err(conflict());
            }
            let mut proof = self.proof.try_borrow_mut().map_err(|_| {
                self.capture.set(3);
                conflict()
            })?;
            if proof.is_some() {
                self.capture.set(3);
                return Err(conflict());
            }
            *proof = Some(original); // BEFORE provider's fallible postflight
            Ok(())
        })?;
        if self.capture.get() != 1 || self.retained_proof().is_err() {
            return Err(conflict());
        }
        self.capture.set(2);
        flight.done = true;
        Ok(())
    }
    fn retained_proof(&self) -> io::Result<std::rc::Rc<P>> {
        self.proof
            .try_borrow()
            .map_err(|_| conflict())?
            .clone()
            .ok_or_else(conflict)
    }
    fn sealed_proof(&self) -> io::Result<std::rc::Rc<P>> {
        if self.capture.get() != 2 || self.disposal.get() == 3 {
            return Err(conflict());
        }
        self.retained_proof()
    }
    fn invalidate_disposal(&self) {
        self.disposal.set(3);
    }
    fn verify_disposing(&self) -> io::Result<()> {
        if self.capture.get() == 2 && self.disposal.get() == 1 {
            Ok(())
        } else {
            Err(conflict())
        }
    }
    /// Private alias disposal AFTER actual owning disposition, not a native
    /// permit. The completed outcome must not secretly retain Runtime/lock/
    /// Source aliases through its proof after the original actor is gone.
    fn release_proof(&self, original: &std::rc::Rc<P>) -> io::Result<()> {
        if self.capture.get() != 2 || self.disposal.get() != 2 {
            return Err(conflict());
        }
        let mut retained = self.proof.try_borrow_mut().map_err(|_| conflict())?;
        if !std::rc::Rc::ptr_eq(retained.as_ref().ok_or_else(conflict)?, original) {
            return Err(conflict());
        }
        retained.take();
        Ok(())
    }
    fn dispose(
        &self,
        original: &std::rc::Rc<P>,
        actual: impl FnOnce(&P) -> io::Result<()>,
    ) -> io::Result<()> {
        if self.disposal.replace(1) != 0 {
            self.disposal.set(3);
            return Err(conflict());
        }
        let mut flight = DispositionFlight {
            state: &self.disposal,
            done: false,
        };
        if !std::rc::Rc::ptr_eq(&self.sealed_proof()?, original) {
            return Err(conflict());
        }
        actual(original)?;
        if self.disposal.get() != 1 || self.capture.get() != 2 {
            return Err(conflict());
        }
        self.disposal.set(2);
        flight.done = true;
        Ok(())
    }
}
struct ActorUnloadFlight<'a> {
    owner: &'a ActorUnloadSequence,
    done: bool,
}
impl Drop for ActorUnloadFlight<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.owner.failed.set(true);
        }
    }
}
impl ActorUnloadSequence {
    fn run<A, C>(
        &self,
        retained_ack: &mut Option<A>,
        context: &mut C,
        preflight: impl FnOnce(&C) -> io::Result<()>,
        unload: impl FnOnce(&mut Option<A>) -> io::Result<()>,
        release: impl FnOnce(&mut C, &A) -> io::Result<()>,
    ) -> io::Result<()> {
        if self.attempted.replace(true) || self.failed.get() {
            return Err(self.fail());
        }
        let mut flight = ActorUnloadFlight {
            owner: self,
            done: false,
        };
        if retained_ack.is_some() {
            return Err(self.fail());
        }
        preflight(context)?;
        if self.failed.get() {
            return Err(conflict());
        }
        unload(retained_ack)?;
        let ack = retained_ack.as_ref().ok_or_else(|| self.fail())?;
        if self.failed.get() {
            return Err(conflict());
        }
        self.completed.set(true);
        release(context, ack)?;
        if self.failed.get() {
            return Err(conflict());
        }
        flight.done = true;
        Ok(())
    }
    fn verify_release(&self) -> io::Result<()> {
        if self.failed.get() || (self.attempted.get() && !self.completed.get()) {
            return Err(self.fail());
        }
        Ok(())
    }
    fn fail(&self) -> io::Error {
        self.failed.set(true);
        conflict()
    }
}
impl<T> ActorTerminalParts<T> {
    fn new(original: T) -> Self {
        Self {
            original: std::cell::RefCell::new(Some(original)),
            release: Cell::new(0),
        }
    }
    fn try_borrow(&self) -> io::Result<std::cell::Ref<'_, T>> {
        std::cell::Ref::filter_map(
            self.original.try_borrow().map_err(|_| self.failed_read())?,
            Option::as_ref,
        )
        .map_err(|_| self.failed_read())
    }
    fn try_borrow_mut(&self) -> io::Result<std::cell::RefMut<'_, T>> {
        std::cell::RefMut::filter_map(
            self.original
                .try_borrow_mut()
                .map_err(|_| self.failed_read())?,
            Option::as_mut,
        )
        .map_err(|_| self.failed_read())
    }
    fn failed_read(&self) -> io::Error {
        // Swallowing a failed original read cannot let the outer actual ACK
        // callback approve destruction. The retained facts remain readable.
        self.release.set(2);
        conflict()
    }
    // PRIVATE mechanism: actual same-root module ACK OR actual OriginalNever
    // owning disposition + whole postflight, never a Boolean/record grant.
    fn release_with(&self, actual_ack: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
        if self.release.replace(1) != 0 {
            self.release.set(2);
            return Err(conflict());
        }
        actual_ack()?;
        if self.release.get() != 1 {
            return Err(conflict());
        }
        let original = self
            .original
            .try_borrow_mut()
            .map_err(|_| conflict())?
            .take()
            .ok_or_else(conflict)?;
        self.release.set(3);
        drop(original);
        Ok(())
    }
}
impl<T> Drop for ActorTerminalParts<T> {
    fn drop(&mut self) {
        if let Some(original) = self.original.get_mut().take() {
            std::mem::forget(original);
        }
    }
}
impl<T> Default for ActorResourceTransfer<T> {
    fn default() -> Self {
        Self {
            original: None,
            attempted: false,
            complete: false,
        }
    }
}
impl<T> ActorResourceTransfer<T> {
    fn capture(
        &mut self,
        destination: &mut Option<std::rc::Rc<T>>,
        build: impl FnOnce() -> T,
        handoff: impl FnOnce(&std::rc::Rc<T>) -> io::Result<()>,
    ) -> io::Result<()> {
        if std::mem::replace(&mut self.attempted, true) || destination.is_some() {
            return Err(conflict());
        }
        let original = std::rc::Rc::new(build());
        self.original = Some(original.clone());
        *destination = Some(original.clone());
        handoff(&original)?;
        self.complete = true;
        Ok(())
    }
    fn retained(&self) -> io::Result<&std::rc::Rc<T>> {
        self.original.as_ref().ok_or_else(conflict)
    }
    /// Private bookkeeping AFTER actual same-root module ACK + whole terminal
    /// postflight and root.release_resources. No public Boolean release seam.
    fn finish_release(&mut self, original: &std::rc::Rc<T>) -> io::Result<()> {
        if !self.complete || !std::rc::Rc::ptr_eq(self.retained()?, original) {
            return Err(conflict());
        }
        self.original.take();
        Ok(())
    }
}
impl<T> Drop for ActorResourceTransfer<T> {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            std::mem::forget(original);
        }
    }
}

/// Private retention/bookkeeping, NOT an execution or SDK capability. Native
/// callers can seal only after retaining their actual original SDK read; whole
/// Calling postflight must return successfully before completion is eligible.
struct RebindProofSlot<T> {
    active: bool,
    seal_attempted: bool,
    sealed: bool,
    completion_attempted: bool,
    original: Option<std::rc::Rc<T>>,
}
impl<T> Default for RebindProofSlot<T> {
    fn default() -> Self {
        Self {
            active: false,
            seal_attempted: false,
            sealed: false,
            completion_attempted: false,
            original: None,
        }
    }
}
impl<T> RebindProofSlot<T> {
    fn begin(&mut self) -> io::Result<()> {
        if self.active || self.original.is_some() {
            return Err(conflict());
        }
        self.active = true;
        self.seal_attempted = false;
        self.sealed = false;
        self.completion_attempted = false;
        Ok(())
    }
    fn retain(&mut self, actual: std::rc::Rc<T>) -> io::Result<()> {
        if !self.active || !self.seal_attempted || self.original.is_some() {
            return Err(conflict());
        }
        self.original = Some(actual);
        Ok(())
    }
    fn seal(&mut self, whole: impl FnOnce(&mut Self) -> io::Result<()>) -> io::Result<()> {
        if !self.active || std::mem::replace(&mut self.seal_attempted, true) {
            return Err(conflict());
        }
        whole(self)?;
        if self.original.is_none() {
            return Err(conflict());
        }
        self.sealed = true;
        Ok(())
    }
    fn complete<U>(
        &mut self,
        whole: impl FnOnce(&std::rc::Rc<T>) -> io::Result<U>,
    ) -> io::Result<U> {
        if !self.active || !self.sealed || std::mem::replace(&mut self.completion_attempted, true) {
            return Err(conflict());
        }
        let result = whole(self.original.as_ref().ok_or_else(conflict)?)?;
        self.original.take();
        self.active = false;
        self.sealed = false;
        Ok(result)
    }
}
impl<T> Drop for RebindProofSlot<T> {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            std::mem::forget(original);
        }
    }
}

/// Registration state only. The transferred mandatory native gate remains the
/// sole effect authority; this never caches a permission decision.
#[derive(Default)]
struct UpgradeRegistration {
    attempted: Cell<bool>,
    completed: Cell<bool>,
}
impl UpgradeRegistration {
    fn run(&self, eligible: bool, transfer: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
        if self.completed.get() {
            return Ok(()); // Already registered, not a grant for another effect.
        }
        if self.attempted.replace(true) || !eligible {
            return Err(conflict());
        }
        transfer()?;
        self.completed.set(true);
        Ok(())
    }
}

#[cfg(any(windows, test))]
fn network_active(
    active: Option<nelomai_client_tunnel::redundancy::Slot>,
    operation: Option<crate::member_carrier_pair::Operation>,
) -> io::Result<nelomai_client_tunnel::redundancy::Slot> {
    use crate::member_carrier_pair::Operation;
    match operation {
        Some(Operation::Start(s) | Operation::Switch(s)) => Ok(s),
        _ => active.ok_or_else(conflict),
    }
}

#[cfg(any(windows, test))]
fn guard_ack_plan(
    plan: &crate::member_carrier_guard::ExchangePlan,
    before: &crate::member_carrier_guard::Model,
    acknowledged: &crate::member_carrier_guard::Model,
) -> crate::member_carrier_guard::Result<crate::member_carrier_guard::ExchangePlan> {
    use crate::member_carrier_guard::GuardError;
    plan.validate()?;
    before.validate()?;
    acknowledged.validate()?;
    let mut retained = plan.clone();
    if !before.installed && acknowledged.installed {
        retained.base = plan
            .base
            .readback_after(&plan.expected, &acknowledged.expected)?;
        if retained.base != *acknowledged {
            return Err(GuardError::Conflict);
        }
        retained.captured_sublayer_weight = acknowledged.assigned_sublayer_weight;
        retained.desired = plan.desired.inherit_sublayer_weight(acknowledged)?;
        retained.validate()?;
    }
    if retained.resolve(&acknowledged.expected)? != *acknowledged {
        return Err(GuardError::Conflict);
    }
    Ok(retained)
}

#[cfg(any(windows, test))]
fn capture_once<T>(
    slot: &mut Option<T>,
    rejected: &mut Vec<T>,
    attempted: &mut bool,
    original: T,
) -> io::Result<()> {
    if std::mem::replace(attempted, true) || slot.is_some() {
        rejected.push(original);
        return Err(conflict());
    }
    *slot = Some(original);
    Ok(())
}

#[cfg(any(windows, test))]
struct PhysicalBypasses {
    routes: Vec<nelomai_client_tunnel::redundancy::network::RouteValue>,
    originals: Vec<crate::member_physical::PhysicalRoute>,
    retained: Vec<nelomai_client_tunnel::redundancy::network::RouteValue>,
}

/// Dispatch shape ONLY. A mandatory independently original no-Start/SDK read
/// follows this check; neither member=None nor this function supplies an ACK.
#[cfg(any(windows, test))]
fn require_unstarted_cleanup(
    record: &crate::member_carrier_pair::Record,
    slot: nelomai_client_tunnel::redundancy::Slot,
) -> io::Result<()> {
    use crate::member_carrier_pair::{Effect, Phase};
    use nelomai_client_tunnel::redundancy::Slot;
    record.validate()?;
    let i = usize::from(slot == Slot::B);
    if record.phase != Phase::Closing
        || record.stop_stage != if slot == Slot::A { 4 } else { 5 }
        || record.pending != Some(Effect::MemberStop(slot))
        || record.members[i].as_ref().is_some_and(|m| {
            m.owner.phase != crate::member_owner::Phase::Prepared
                || m.owner.proof.is_some()
                || m.owner.retired_proof.is_some()
        })
    {
        return Err(conflict());
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn require_effect(
    record: &crate::member_carrier_pair::Record,
    effect: crate::member_carrier_pair::Effect,
) -> io::Result<()> {
    record.validate()?;
    if record.pending != Some(effect) {
        return Err(conflict());
    }
    Ok(())
}

/// Route only, not native permission or a no-constructor proof. Each selected
/// consumer must independently authenticate its SAME original owner/Calling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CarrierCleanupRoute {
    NoConstructorRead,
    RetainedStartup,
    FullGraph,
}

/// Factual reader dispatch only; the selected original Startup authenticates
/// the precise private origin, complete SDK/rows and independent WFP samples.
fn require_pregraph_closing_read(record: &crate::member_carrier_pair::Record) -> io::Result<()> {
    use crate::member_carrier_pair::{Effect, Phase};
    use nelomai_client_tunnel::redundancy::Slot;
    record.validate()?;
    if record.phase != Phase::Closing
        || record.carrier.is_none()
        || !matches!(
            (record.stop_stage, record.pending),
            (0, Some(Effect::Guard))
                | (1, Some(Effect::ReleaseProbes))
                | (2, Some(Effect::RestoreNetwork))
                | (3, Some(Effect::RestoreWeak))
                | (4, Some(Effect::MemberStop(Slot::A)))
                | (5, Some(Effect::MemberStop(Slot::B)))
                | (6, Some(Effect::CarrierAddressDelete))
                | (7, Some(Effect::CarrierSessionEnd))
                | (8, Some(Effect::CarrierClose))
        )
    {
        return Err(conflict());
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PregraphGuardRead {
    EarlyClosing,
    NativeEmpty,
    FullEmpty,
    Stopped,
}
fn pregraph_guard_read_route(
    record: &crate::member_carrier_pair::Record,
) -> io::Result<PregraphGuardRead> {
    use crate::member_carrier_pair::Phase;
    if record.phase == Phase::Closing && record.stop_stage <= 8 {
        require_pregraph_closing_read(record)?;
        return Ok(PregraphGuardRead::EarlyClosing);
    }
    if record.phase == Phase::Closing && matches!(record.stop_stage, 9 | 10) {
        require_native_empty_frame(record)?;
        return Ok(PregraphGuardRead::NativeEmpty);
    }
    require_full_empty_frame(record)?;
    Ok(
        if record.phase == crate::member_carrier_pair::Phase::Stopped {
            PregraphGuardRead::Stopped
        } else {
            PregraphGuardRead::FullEmpty
        },
    )
}
fn carrier_cleanup_route(
    record: &crate::member_carrier_pair::Record,
    effect: crate::member_carrier_pair::Effect,
    graph: bool,
) -> io::Result<CarrierCleanupRoute> {
    use crate::member_carrier_pair::{Effect, Phase};
    require_effect(record, effect)?;
    if record.phase != Phase::Closing
        || !matches!(
            (record.stop_stage, effect),
            (3, Effect::RestoreWeak)
                | (6, Effect::CarrierAddressDelete)
                | (7, Effect::CarrierSessionEnd)
                | (8, Effect::CarrierClose)
        )
    {
        return Err(conflict());
    }
    if graph {
        Ok(CarrierCleanupRoute::FullGraph)
    } else if record.carrier.is_none() {
        Ok(CarrierCleanupRoute::NoConstructorRead)
    } else {
        Ok(CarrierCleanupRoute::RetainedStartup)
    }
}

#[cfg(any(windows, test))]
/// Factual callback dispatch ONLY. Stopped/None can request the independent
/// FullEmpty read; it cannot satisfy require_effect or any native mutation.
/// The caller must separately enter the actual terminal ACK/Calling channel.
pub(crate) fn require_attestation(
    record: &crate::member_carrier_pair::Record,
    effect: crate::member_carrier_pair::Effect,
) -> io::Result<()> {
    if effect == crate::member_carrier_pair::Effect::FullEmpty {
        return require_full_empty_frame(record);
    }
    require_effect(record, effect)
}

/// Comparison only. Native caller supplies a fresh SAME original Guard sample;
/// this does not authenticate a closed member, held key or restoration effect.
#[cfg(any(windows, test))]
fn compare_member_key_restore_guard(
    slot: nelomai_client_tunnel::redundancy::Slot,
    guard: &crate::member_carrier_guard::Model,
    observed: &crate::member_carrier_guard::Snapshot,
) -> io::Result<()> {
    guard.validate().map_err(|_| conflict())?;
    let index = usize::from(slot == nelomai_client_tunnel::redundancy::Slot::B);
    if !guard.installed
        || guard.permits
        || guard.active.is_some()
        || guard.members[index].is_some()
        || observed != &guard.expected
        || observed
            .filters
            .iter()
            .any(|f| f.action == crate::member_carrier_guard::Action::Permit)
    {
        return Err(conflict());
    }
    Ok(())
}

/// Completed Retire may have restored the OTHER active member's real allows.
/// Exact scoped SDK comparison only: no target membership and no WFP mutation.
#[cfg(any(windows, test))]
fn compare_member_generation_guard(
    slot: nelomai_client_tunnel::redundancy::Slot,
    guard: &crate::member_carrier_guard::Model,
    observed: &crate::member_carrier_guard::Snapshot,
) -> io::Result<()> {
    guard.validate().map_err(|_| conflict())?;
    let index = usize::from(slot == nelomai_client_tunnel::redundancy::Slot::B);
    if !guard.installed || guard.members[index].is_some() || observed != &guard.expected {
        return Err(conflict());
    }
    Ok(())
}

/// Dispatch only. The mandatory startup read must authenticate its original
/// Never ledger, terminal Pair publication and actual cleanup Calling itself.
#[cfg(any(windows, test))]
fn uncaptured_terminal_call(
    serial: &ActorSerial,
    record: &crate::member_carrier_pair::Record,
    read: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    serial.run(true, || {
        require_terminal_record(record)?;
        read()
    })
}

/// Compare independently observed facts only. Never mint an empty observation
/// from Pair JSON; the native startup reader proves its own ledger and SDK/BFE.
#[cfg(any(windows, test))]
fn compare_uncaptured_terminal_guard(
    record: &crate::member_carrier_pair::Record,
    observed: &crate::member_carrier_guard::Snapshot,
) -> io::Result<()> {
    require_terminal_record(record)?;
    if observed != &record.guard.expected {
        return Err(conflict());
    }
    Ok(())
}

/// Comparison/dispatch ONLY. Actual terminal Pair ACK, native original keys
/// receipt and cleanup Calling must be independently authenticated afterwards.
#[cfg(any(windows, test))]
fn require_terminal_record(record: &crate::member_carrier_pair::Record) -> io::Result<()> {
    record.validate()?;
    if record.phase != crate::member_carrier_pair::Phase::Stopped
        || record.stop_stage != 12
        || record.pending.is_some()
    {
        return Err(conflict());
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn cache_progress(
    old: &crate::member_carrier_pair::Record,
    next: &crate::member_carrier_pair::Record,
) -> io::Result<()> {
    use crate::member_carrier_pair::Phase;
    if next.revision <= old.revision
        || old.phase == Phase::Stopped
        || (old.phase == Phase::Closing && !matches!(next.phase, Phase::Closing | Phase::Stopped))
    {
        return Err(conflict());
    }
    if next.phase == Phase::Stopped {
        require_terminal_record(next)?;
    }
    Ok(())
}

/// Telemetry reduction only, called after an actual original-controller/SDK
/// bracket. These counters and handshake age are not a DNS/data/effect grant.
#[cfg(any(windows, test))]
fn native_health(
    metrics: &nelomai_client_tunnel::TunnelMetrics,
    sent_unicast_packets: u64,
    received_unicast_packets: u64,
    now: u64,
) -> nelomai_client_tunnel::redundancy::evidence::NativeHealthSample {
    nelomai_client_tunnel::redundancy::evidence::NativeHealthSample {
        admitted: true,
        closed: false,
        handshake_fresh: metrics
            .latest_handshake_epoch_millis
            .filter(|stamp| *stamp != 0)
            .and_then(|stamp| now.checked_sub(stamp))
            .is_some_and(|age| age <= 180_000),
        tx_packets: sent_unicast_packets,
        rx_data_packets: received_unicast_packets,
    }
}

/// Convert the actual retained process creation FILETIME, not caller wallclock
/// or a reconstructed Pair start timestamp. The SDK reader checks it again.
#[cfg(any(windows, test))]
fn process_birth_ms(filetime: u64) -> io::Result<u64> {
    filetime
        .checked_sub(116_444_736_000_000_000)
        .map(|ticks| ticks / 10_000)
        .ok_or_else(conflict)
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy)]
enum NetworkPlanUse {
    BeforeMutation,
    ReadOnly,
}

/// This selects a factual recomputation channel, never a route/DNS permission.
/// The readonly consumer independently compares the actual full Guard twice.
#[cfg(any(windows, test))]
fn network_plan_channel(
    permits: bool,
    pending_guard: bool,
    usage: NetworkPlanUse,
) -> io::Result<()> {
    if matches!(usage, NetworkPlanUse::BeforeMutation) && (permits || pending_guard) {
        return Err(conflict());
    }
    Ok(())
}

/// The Root getter's Pending means its actual capture slot is still empty;
/// it is NOT SDK absence or permission. Only pre-Close8 may use Closing instead,
/// where a fresh independent Closing SDK bracket must still succeed.
#[cfg(any(windows, test))]
fn retired_at_boundary<T>(
    stage: u8,
    captured: crate::member_carrier::Result<std::rc::Rc<T>>,
) -> io::Result<Option<std::rc::Rc<T>>> {
    match captured {
        Ok(original) => Ok(Some(original)),
        Err(crate::member_carrier::CarrierError::Pending) if stage == 8 => Ok(None),
        Err(_) => Err(conflict()),
    }
}

#[cfg(all(test, not(windows)))]
use crate::member_carrier_network::NetworkFacts as RouteFacts;
#[cfg(windows)]
use crate::windows::member_carrier_network::NetworkFacts as RouteFacts;

/// Owned factual comparison only. NativeNetworkFacts intentionally has no
/// Clone: cloning its borrowed reference must not escape the actual window.
#[cfg(any(windows, test))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct NetworkSample {
    current: Vec<(
        nelomai_client_tunnel::redundancy::network::RouteValue,
        Option<crate::member_routes::Row>,
    )>,
    pending: Option<
        Vec<(
            nelomai_client_tunnel::redundancy::network::RouteValue,
            Option<crate::member_routes::Row>,
        )>,
    >,
    carrier_rows: Vec<crate::member_routes::Row>,
    egress_rows: [Vec<crate::member_routes::Row>; 2],
    active: Option<nelomai_client_tunnel::redundancy::Slot>,
    pending_active: Option<nelomai_client_tunnel::redundancy::Slot>,
    stopping: bool,
    dns: crate::member_dns::Snapshot,
    protected_record: Option<Vec<u8>>,
}

#[cfg(any(windows, test))]
fn network_sample(
    facts: &RouteFacts,
    dns: &crate::member_dns::Snapshot,
    protected: Option<&[u8]>,
) -> NetworkSample {
    NetworkSample {
        current: facts
            .current
            .iter()
            .map(|r| (r.expected.clone(), r.actual.clone()))
            .collect(),
        pending: facts.pending.as_ref().map(|pending| {
            pending
                .iter()
                .map(|r| (r.expected.clone(), r.actual.clone()))
                .collect()
        }),
        carrier_rows: facts.carrier_rows.clone(),
        egress_rows: facts.egress_rows.clone(),
        active: facts.active,
        pending_active: facts.pending_active,
        stopping: facts.stopping,
        dns: dns.clone(),
        protected_record: protected.map(<[u8]>::to_vec),
    }
}

/// Pure planning facts, never an owner capture or mutation grant. Preserve the
/// COMPLETE source path, not the narrower bypass value derived from that path.
#[cfg(any(windows, test))]
fn physical_bypasses(
    physical: &crate::member_physical::PhysicalSnapshot,
    destinations: &[ipnet::IpNet],
) -> io::Result<PhysicalBypasses> {
    use nelomai_client_tunnel::redundancy::network::{RouteScope, RouteValue};
    let mut result = PhysicalBypasses {
        routes: Vec::new(),
        originals: Vec::new(),
        retained: Vec::new(),
    };
    for destination in destinations {
        let path = physical
            .resolve_bypass(*destination)
            .map_err(|_| conflict())?;
        let route = RouteValue {
            destination: *destination,
            scope: RouteScope::WindowsInterface(path.proof.identity.index),
            interface: path.proof.identity.index,
            gateway: path.row.route.gateway,
            metric: path.row.route.metric,
        };
        if path.row.route == route {
            result.retained.push(route.clone());
        }
        result.routes.push(route);
        result.originals.push(path);
    }
    Ok(result)
}

#[cfg(all(test, not(windows)))]
use crate::member_carrier_network_owner::RouteAttempt;
#[cfg(windows)]
use crate::windows::member_carrier_network_owner::RouteAttempt;

/// Comparison only. Its native caller supplies observed rows and THIS owner's
/// actual ACK histories inside the independently original SDK/Calling bracket.
#[cfg(any(windows, test))]
fn compare_network_ack(
    expected: &crate::member_carrier_pair::NetworkSnapshot,
    sampled: &[crate::member_routes::Row],
    dns: &crate::member_dns::Snapshot,
    baseline: &crate::member_dns::Snapshot,
    attempts: &[RouteAttempt],
    dns_history: &(usize, Vec<crate::member_dns::Snapshot>),
) -> io::Result<()> {
    if sampled.len() != expected.routes.len()
        || sampled.len() > crate::member_routes::MAX_TABLE_ROWS
        || attempts.len() > 32768
        || attempts.iter().any(|a| !a.acknowledged)
        || expected.dns.as_ref() != Some(dns)
        || dns_history.0 != dns_history.1.len()
        || dns_history.0 > 32768
        || (dns_history.0 == 0 && dns != baseline)
        || (dns_history.0 > 0 && dns_history.1.last() != Some(dns))
    {
        return Err(conflict());
    }
    let mut keys = std::collections::BTreeSet::new();
    for row in sampled {
        let key = (row.route.destination, row.route.interface);
        if !keys.insert(key) || !expected.routes.contains(&row.route) {
            return Err(conflict());
        }
        let last = attempts
            .iter()
            .rev()
            .find(|a| (a.row.route.destination, a.row.route.interface) == key)
            .ok_or_else(conflict)?;
        if last.deleting || last.row != *row {
            return Err(conflict());
        }
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) mod native {
    use super::*;
    use crate::{
        member_carrier::CarrierError,
        member_carrier_guard as policy,
        member_carrier_native_ownership::Context,
        member_carrier_pair::{self as pair, PairJournal},
        member_owner::InterfaceProof,
        member_pair::PairSocket,
        windows::{
            member_carrier_assembly::native::NativeAssemblySlot,
            member_carrier_creators::Observer,
            member_carrier_guard::{
                BindingAttestor, Bindings, LockedWfpRead, NativeApi, NativeGuard,
                TerminalBindingAttestor, Wfp, WindowBindingAttestor,
            },
            member_carrier_guard_attestor::native::{NativeGuardAttestor, NativeGuardSelection},
            member_carrier_guard_gate::native::{
                NativeGuardResourceSelection, NativeResourceGuardGate,
            },
            member_carrier_key_authority::{KeyLock, RuntimeRead},
            member_carrier_lifecycle_gate::native::NativeLifecycleSelection,
            member_carrier_member_controller::native::{
                NativeMemberAttachment, NativeMemberController, NativeMemberPreparationGeneration,
                NativeMemberRebindReceipt, NativeMemberStartedGeneration, NativeNeverMemberEffects,
            },
            member_carrier_member_gate::native::{NativeMemberGate, NativeMemberGateInputs},
            member_carrier_members::native::{
                MemberInventoryRead, NativeRebindPublication, NativeRetirementInputs,
            },
            member_carrier_module::native::NativeModuleReleased,
            member_carrier_module::native::OriginalImage,
            member_carrier_network::native::{NativeClosingNetworkRead, NativeNetworkRead},
            member_carrier_network_baseline::native::NativeNetworkBaselineRead,
            member_carrier_network_gate::native::NativeNetworkGate,
            member_carrier_network_owner::native::{
                NativeCarrierNetworkOwner, NativeNetworkAckRead,
            },
            member_carrier_pair_store::native_store::{
                NativeCarrierPairStore, NativeNetworkIntentRead, NativePairIntentRead,
            },
            member_carrier_payload::native::MemberSource,
            member_carrier_probe_gate::native::{NativeProbeResourceState, WfpProbeGate},
            member_carrier_probes::native::{
                HeldProbeLease, HeldProbeOwner, HeldProbeRead, ProbeInventory, ProbeInventoryRead,
            },
            member_carrier_ready::native::{NativeCarrierPins, NativeCarrierRoot},
            member_carrier_rows::{self as rows, RowOwner, RowRecordReadPin},
            member_carrier_runtime::native::{
                NativeBindingsWindow, NativeClosingRead, NativeLifecycleGate,
                NativeMemberCaptureInputs, NativeResourceRowsFacts, NativeResourceRowsRead,
                NativeRowGenerationCapture, NativeRowGenerationInputs, NativeRowGenerationReceipt,
                NativeSourceRead, RetiredCarrierRead,
            },
            member_carrier_terminal_release::native::{
                NativeTerminalReleaseRoot, NativeTerminalResourceGate,
            },
            member_carrier_wintun::native::OriginalWintun,
            member_session::{
                epoch::{NativeExecutionLease, NativeExecutionRoot, NativeSessionAckRoot},
                NativeSessionFiles, OriginalRowGenerationWrite, WindowsCarrierGuardStore,
                WindowsCarrierRowsGenerationStore, WindowsCarrierRowsStore,
            },
        },
    };
    use nelomai_client_tunnel::redundancy::ProbeDatagram;
    use nelomai_client_tunnel::redundancy::{SessionScope, Slot};
    use policy::SplitEngines;
    use std::{cell::RefCell, rc::Rc, sync::Arc};

    /// Nominal, finite-sized recursive graph. Reverse resource edges inside G
    /// are Weak: no recursive alias, unsafe Send, substitute attestor or default G.
    pub(crate) struct OriginalGuardAttestor {
        inner: NativeGuardAttestor<NativeResourceGuardGate<OriginalGuardAttestor>>,
    }
    impl OriginalGuardAttestor {
        pub(crate) fn original(inner: NativeGuardAttestor<NativeResourceGuardGate<Self>>) -> Self {
            Self { inner }
        }
    }
    impl BindingAttestor for OriginalGuardAttestor {
        fn observe(&mut self, scope: &SessionScope) -> policy::Result<Bindings> {
            self.inner.observe(scope)
        }
        fn authorize<N: NativeApi>(
            &mut self,
            kind: policy::SessionKind,
            expected: &policy::Model,
            desired: &policy::Model,
            locked: &mut LockedWfpRead<'_, N>,
        ) -> policy::Result<()> {
            self.inner.authorize(kind, expected, desired, locked)
        }
    }
    impl WindowBindingAttestor for OriginalGuardAttestor {
        fn verify_original_window(
            &mut self,
            window: &NativeBindingsWindow<'_>,
        ) -> policy::Result<()> {
            self.inner.verify_original_window(window)
        }
        fn verify_retired_bracket(
            &mut self,
            original: &RetiredCarrierRead,
            bindings: &Bindings,
        ) -> policy::Result<()> {
            self.inner.verify_retired_bracket(original, bindings)
        }
    }
    impl TerminalBindingAttestor for OriginalGuardAttestor {
        fn verify_terminal_bracket(
            &mut self,
            pair: &Rc<NativePairIntentRead>,
            stopped: &pair::Record,
            retired: &Rc<RetiredCarrierRead>,
            bindings: &Bindings,
        ) -> policy::Result<()> {
            // SAME retained native attestor: actual Runtime/KeyLock, private
            // Pair store origin/current Stopped ACK and already-active
            // original Retired history lease. No Source/Pair/Retired reentry,
            // replacement reader, equal imported facts or successful default.
            self.inner
                .verify_terminal_bracket(pair, stopped, retired, bindings)
        }
    }
    pub(crate) type Guard = NativeGuard<Wfp, OriginalGuardAttestor>;
    pub(crate) type ProbeGate = WfpProbeGate<OriginalGuardAttestor>;
    pub(crate) type Probes = ProbeInventory<Wfp, OriginalGuardAttestor, ProbeGate>;
    pub(crate) type ProbeRead = ProbeInventoryRead<Wfp, OriginalGuardAttestor, ProbeGate>;
    pub(crate) type Held = HeldProbeOwner<Wfp, OriginalGuardAttestor, ProbeGate>;
    pub(crate) type HeldRead = HeldProbeRead<Wfp, OriginalGuardAttestor, ProbeGate>;
    pub(crate) type NetworkGate = NativeNetworkGate<OriginalGuardAttestor>;
    pub(crate) type NetworkOwner = NativeCarrierNetworkOwner<NetworkGate>;
    pub(crate) type MemberGate = NativeMemberGate<OriginalGuardAttestor, ProbeGate, NetworkGate>;
    pub(crate) type Controller = NativeMemberController<MemberGate>;
    type RowAuthority = crate::windows::member_carrier_runtime::native::NativeRowsAuthority<
        crate::windows::member_carrier_coordinator::native::CarrierReadyGate,
    >;
    /// Explicit original first/generation journals. This local enum holds the
    /// non-Send generation authority; ProtectedSessionFiles remains unchanged.
    enum MemberRowJournal {
        First(WindowsCarrierRowsStore<NativeSessionFiles>),
        Generation(WindowsCarrierRowsGenerationStore<NativeSessionFiles>),
    }
    impl MemberRowJournal {
        fn enter_cleanup(&mut self, canonical: NativeSessionFiles) -> rows::Result<()> {
            // Actual original holder is changed in place; no open/reconstructed
            // owner, pin, generation journal, binding or capture authority.
            match self {
                Self::First(original) => original.enter_cleanup(canonical),
                Self::Generation(original) => original.enter_cleanup(canonical),
            }
            .map_err(|_| rows::Error::Journal)
        }
    }
    impl rows::Journal for MemberRowJournal {
        fn load(&mut self, binding: &rows::Binding) -> rows::Result<Option<rows::Record>> {
            match self {
                Self::First(original) => original.load(binding),
                Self::Generation(original) => original.load(binding),
            }
        }
        fn compare_exchange(
            &mut self,
            binding: &rows::Binding,
            expected: Option<&rows::Record>,
            desired: &rows::Record,
        ) -> rows::Result<()> {
            match self {
                Self::First(original) => original.compare_exchange(binding, expected, desired),
                Self::Generation(original) => original.compare_exchange(binding, expected, desired),
            }
        }
    }
    type MemberRowOwner = rows::NativeRowOwner<RowAuthority, MemberRowJournal>;
    struct HistoricalMemberRows {
        pin: Rc<RowRecordReadPin>,
        authority: RowAuthority,
        seal: Rc<rows::StoppedRowGeneration>,
    }
    struct MemberGenerationOriginal {
        ticket: Rc<NativeMemberPreparationGeneration>,
        never: Rc<NativeNeverMemberEffects>,
        receipt: RefCell<Option<Rc<NativeRowGenerationReceipt>>>,
    }

    /// Actual historical aliases, including partial projection/rebind roots.
    /// No controller/owner destructor ACK is invented by this raw field cut.
    pub(crate) struct NativeMemberGenerationRoots {
        tickets: Vec<Rc<NativeMemberPreparationGeneration>>,
        row_receipts: Vec<Rc<NativeRowGenerationReceipt>>,
        originals: Vec<Rc<MemberGenerationOriginal>>,
        rebind_receipts: Vec<Rc<NativeMemberRebindReceipt>>,
    }
    pub(crate) type NativeMemberGenerationTerminalResources =
        GenerationTerminalResources<NativeMemberGenerationRoots>;
    pub(crate) type NativeMemberGenerationTerminalCut =
        OriginalGenerationCut<NativeMemberGenerationRoots>;
    impl OriginalGenerationCut<NativeMemberGenerationRoots> {
        /// All SAME issued ticket/Never roots, not just the successful receipts.
        /// Missing row receipt remains an unresolved partial projection, never
        /// an absence/disarm ACK. Caller supplies independently actual terminal
        /// owner/history/destructor verification under its original bracket.
        pub(crate) fn inspect_originals(
            &self,
            mut read: impl FnMut(
                &Rc<NativeMemberPreparationGeneration>,
                &Rc<NativeNeverMemberEffects>,
                Option<&Rc<NativeRowGenerationReceipt>>,
            ) -> io::Result<()>,
        ) -> io::Result<()> {
            self.inspect(|roots| {
                for original in &roots.originals {
                    let receipt = original.receipt.try_borrow().map_err(denied)?;
                    read(&original.ticket, &original.never, receipt.as_ref())?;
                }
                Ok(())
            })
        }
        pub(crate) fn inspect_tickets<T>(
            &self,
            read: impl FnOnce(&[Rc<NativeMemberPreparationGeneration>]) -> io::Result<T>,
        ) -> io::Result<T> {
            self.inspect(|roots| read(&roots.tickets))
        }
        pub(crate) fn inspect_row_receipts<T>(
            &self,
            read: impl FnOnce(&[Rc<NativeRowGenerationReceipt>]) -> io::Result<T>,
        ) -> io::Result<T> {
            self.inspect(|roots| read(&roots.row_receipts))
        }
        pub(crate) fn inspect_rebind_receipts<T>(
            &self,
            read: impl FnOnce(&[Rc<NativeMemberRebindReceipt>]) -> io::Result<T>,
        ) -> io::Result<T> {
            self.inspect(|roots| read(&roots.rebind_receipts))
        }
    }

    /// Actual local originals, not a closed/inert certificate. Caller T owns
    /// this same Rc; mandatory terminal G verifies the exact original ACKs and
    /// full independent resource/SDK universe before any final destruction.
    /// No loaded module, terminal root, permit or module ACK is stored here.
    pub(crate) struct NativeActorLocalResources {
        parts: ActorTerminalParts<NativeActorLocalParts>,
        generation_terminal: RefCell<OriginalGenerationTransfer<NativeMemberGenerationRoots>>,
    }
    struct NativeActorLocalParts {
        canonical_probes: Option<Rc<ProbeRead>>,
        canonical_rows: Option<Rc<NativeResourceRowsRead>>,
        socket_context: Option<Rc<SocketContext>>,
        network_intents: Vec<Rc<NativeNetworkIntentRead>>,
        guard_acks: Vec<policy::Model>,
        held: [Option<Rc<RefCell<Held>>>; 2],
        held_reads: [Option<HeldRead>; 2],
        closing: Option<Rc<NativeClosingRead>>,
        closing_network: Option<Rc<NativeClosingNetworkRead>>,
        row_owners: [Option<MemberRowOwner>; 2],
        row_pins: [Option<Rc<RowRecordReadPin>>; 2],
        row_authorities: [Option<RowAuthority>; 2],
        row_attempted: [bool; 2],
        member_generation_tickets: Vec<Rc<NativeMemberPreparationGeneration>>,
        stopped_row_generations: [Option<Rc<rows::StoppedRowGeneration>>; 2],
        row_generation_receipts: Vec<Rc<NativeRowGenerationReceipt>>,
        member_generation_originals: Vec<Rc<MemberGenerationOriginal>>,
        historical_member_rows: Vec<(MemberRowOwner, HistoricalMemberRows)>,
        member_row_captures: Vec<Rc<NativeRowGenerationCapture>>,
        member_rebind_receipts: Vec<Rc<NativeMemberRebindReceipt>>,
        rebind_proof: Rc<RefCell<RebindProofSlot<NativeRebindProof>>>,
        startup_proof: Rc<RefCell<Option<Rc<NativeRebindProof>>>>,
    }
    /// Caller-rooted transfer envelope OUTSIDE T. Rejected full inputs may
    /// still own the original loaded module via Ready/Assembly; Pauli must cut
    /// those exact canonical roots into his retained raw owning destination.
    /// They are deliberately not hidden in the local resource T.
    pub(crate) struct NativeActorTerminalCut<'a> {
        locals: Rc<NativeActorLocalResources>,
        rejected_inputs: RefCell<Vec<Box<NativeActorInputs<'a>>>>,
        // Original execution/Session ACK lineage stays outside local T. It is
        // not terminal/module release authority and must never be reconstructed.
        execution: Option<NativeActorExecution>,
    }
    impl NativeActorTerminalCut<'_> {
        /// Defensive actor half only. None/empty here never grants Never or
        /// SDK absence; the independent private Startup proof is mandatory.
        fn require_unconstructed_originals(&self) -> io::Result<()> {
            if self.execution.is_some()
                || !self
                    .rejected_inputs
                    .try_borrow()
                    .map_err(denied)?
                    .is_empty()
            {
                return Err(conflict());
            }
            let parts = self.locals.parts.try_borrow()?;
            if parts.canonical_probes.is_some()
                || parts.canonical_rows.is_some()
                || parts.socket_context.is_some()
                || !parts.network_intents.is_empty()
                || !parts.guard_acks.is_empty()
                || parts.held.iter().any(Option::is_some)
                || parts.held_reads.iter().any(Option::is_some)
                || parts.closing.is_some()
                || parts.closing_network.is_some()
                || parts.row_owners.iter().any(Option::is_some)
                || parts.row_pins.iter().any(Option::is_some)
                || parts.row_authorities.iter().any(Option::is_some)
                || parts.row_attempted.iter().any(|attempted| *attempted)
                || !parts.member_generation_tickets.is_empty()
                || parts.stopped_row_generations.iter().any(Option::is_some)
                || !parts.row_generation_receipts.is_empty()
                || !parts.member_generation_originals.is_empty()
                || !parts.historical_member_rows.is_empty()
                || !parts.member_row_captures.is_empty()
                || !parts.member_rebind_receipts.is_empty()
                || self
                    .locals
                    .generation_terminal
                    .try_borrow()
                    .map_err(denied)?
                    .attempted
                || parts.startup_proof.try_borrow().map_err(denied)?.is_some()
            {
                return Err(conflict());
            }
            let rebind = parts.rebind_proof.try_borrow().map_err(denied)?;
            if rebind.active
                || rebind.seal_attempted
                || rebind.sealed
                || rebind.completion_attempted
                || rebind.original.is_some()
            {
                return Err(conflict());
            }
            Ok(())
        }
        pub(crate) fn local_resources(&self) -> Rc<NativeActorLocalResources> {
            self.locals.clone()
        }
        /// Defensive actor half for SAME original C-before-graph. Call ONLY
        /// inside the actual Retired lease supplied by Startup's private
        /// pregraph transfer/G. Empty local fields are not native absence or
        /// permission: the independent successful C history remains mandatory.
        pub(crate) fn verify_pregraph_terminal_in_retired(
            &self,
            context: &Context,
            stopped: &pair::Record,
            retired: &RetiredCarrierRead,
            bindings: &Bindings,
            history: &[crate::windows::member_carrier_members::ClosedMemberBinding],
        ) -> io::Result<()> {
            require_terminal_record(stopped)?;
            if stopped.scope != context.intent.scope
                || stopped.provenance != context.provenance
                || bindings.scope != stopped.scope
                || bindings.carrier.is_none()
                || !history.is_empty()
            {
                return Err(conflict());
            }
            retired
                .inspect_terminal_history_in_bracket(|actual| {
                    if actual != history {
                        return Err(native_denied(()));
                    }
                    Ok(())
                })
                .map_err(denied)?;
            // This is deliberately the stringent original actor-no-graph
            // fence. It says nothing about C/key/module absence or release.
            self.require_unconstructed_originals()
        }
        pub(crate) fn with_rejected_inputs<T>(
            &self,
            read: impl FnOnce(&[Box<NativeActorInputs<'_>>]) -> io::Result<T>,
        ) -> io::Result<T> {
            read(&self.rejected_inputs.try_borrow().map_err(denied)?)
        }
        pub(crate) fn with_execution_originals<T>(
            &self,
            read: impl FnOnce(
                Option<(&Rc<NativeExecutionRoot>, &[Arc<NativeExecutionLease>])>,
            ) -> io::Result<T>,
        ) -> io::Result<T> {
            read(
                self.execution
                    .as_ref()
                    .map(|s| (&s.root, s.leases.as_slice())),
            )
        }
    }
    impl<'a> NativeActorTerminalCut<'a> {
        /// # Safety
        /// The destination is an original caller-retained raw canonical root,
        /// kept OUTSIDE local T through every error/unwind. It must cut EACH
        /// transferred input's Ready/Assembly/Startup originals before allowing
        /// terminal G success; moving these wrappers is NOT disarm/release ACK.
        /// No input may be dropped/replaced/adopted while that proof is unknown.
        pub(crate) unsafe fn retain_rejected_inputs_into(
            &self,
            destination: &mut Vec<Box<NativeActorInputs<'a>>>,
        ) -> io::Result<()> {
            let mut originals = self.rejected_inputs.try_borrow_mut().map_err(denied)?;
            destination.append(&mut originals);
            Ok(())
        }
    }
    impl Drop for NativeActorTerminalCut<'_> {
        fn drop(&mut self) {
            // Remaining unpublished canonical roots were never cut/disarmed.
            // No phase/empty-SDK fallback to their destructive Drop exists.
            for original in self.rejected_inputs.get_mut().drain(..) {
                std::mem::forget(original);
            }
            if let Some(original) = self.execution.take() {
                std::mem::forget(original);
            }
        }
    }
    /// # Safety
    /// T owns the exact local Rc and ALL canonical originals moved from this
    /// actor, including Pauli's cuts of any rejected/partial full inputs. Its
    /// mandatory terminal G must authenticate those original transfers, real
    /// close/disarm ACKs and inert destructors, not just this getter or phase.
    /// Loaded module + terminal root/ACK are owned independently OUTSIDE T.
    /// No T/G strong backedge to that release root/ACK is permitted.
    pub(crate) unsafe trait NativeActorTerminalGraph {
        fn actor_local_resources(&self) -> &Rc<NativeActorLocalResources>;
    }
    // SAFETY: this getter exposes ONLY the SAME actual local capture. Concrete
    // pregraph G separately proves original C/keys/native release and transfer;
    // no fake full-graph row/probe pins or native ACK are constructed here.
    unsafe impl NativeActorTerminalGraph
        for crate::windows::member_carrier_terminal_graph::native::NativePregraphTerminalResources<
            '_,
        >
    {
        fn actor_local_resources(&self) -> &Rc<NativeActorLocalResources> {
            &self.original_local_cut().locals
        }
    }
    /// # Safety
    /// C owns Pauli/Main's actual canonical Ready/Assembly/Startup/member/
    /// Guard/network cuts, including every partial/rejected graph. Its mandatory
    /// NativeTerminalResourceGate<C> proves their original close/disarm ACKs,
    /// independent full SDK/48-WFP/registry absence and inert destructor state.
    /// It also accounts for ALL histories exposed by actor_local_resources,
    /// not only current rows/probes. Module/root/permit/ACK stay OUTSIDE C.
    /// Neither C nor its gate may retain a strong edge to the release root.
    pub(crate) unsafe trait NativeActorCanonicalTerminalResources:
        NativeActorTerminalGraph
    {
        fn actor_rows(&self) -> &Rc<NativeResourceRowsRead>;
        fn actor_probes(&self) -> &Rc<ProbeRead>;
        /// SAME raw generation cut retained in C before any fallible provider
        /// registration/postflight. No default empty history or disarm grant.
        /// C/G must independently prove the underlying opaque owners inert.
        fn actor_member_generation_roots(
            &self,
        ) -> io::Result<Rc<NativeMemberGenerationTerminalCut>>;
    }
    pub(crate) type NativeActorTerminalRelease<C, G> = NativeTerminalReleaseRoot<
        NativeActorTerminalResources<C, G>,
        NativeActorTerminalGate<C, G>,
    >;
    pub(crate) type NativeActorTerminalAck<C, G> =
        NativeModuleReleased<NativeActorTerminalResources<C, G>, NativeActorTerminalGate<C, G>>;
    /// Concrete T: owns the SAME local originals and actual canonical C. Even
    /// dropping T before constructing the native root cannot destroy unknown C.
    pub(crate) struct NativeActorTerminalResources<C, G> {
        locals: Rc<NativeActorLocalResources>,
        canonical: Rc<ActorTerminalParts<C>>,
        delegate: Rc<ActorTerminalParts<G>>,
    }
    /// Concrete G: mandatory real canonical delegate, never a successful default.
    /// Reverse identity edges are Weak; no terminal root or ACK is stored here.
    pub(crate) struct NativeActorTerminalGate<C, G> {
        locals: std::rc::Weak<NativeActorLocalResources>,
        canonical: std::rc::Weak<ActorTerminalParts<C>>,
        delegate: std::rc::Weak<ActorTerminalParts<G>>,
    }
    impl<C: NativeActorCanonicalTerminalResources, G: NativeTerminalResourceGate<C>>
        NativeActorTerminalResources<C, G>
    {
        pub(crate) fn original(
            locals: Rc<NativeActorLocalResources>,
            canonical: C,
            delegate: G,
        ) -> (Self, NativeActorTerminalGate<C, G>) {
            // No provider getter/callback before ownership exists. The actual
            // G checks this local Rc against C only AFTER the caller roots T.
            let canonical = Rc::new(ActorTerminalParts::new(canonical));
            let delegate = Rc::new(ActorTerminalParts::new(delegate));
            let gate = NativeActorTerminalGate {
                locals: Rc::downgrade(&locals),
                canonical: Rc::downgrade(&canonical),
                delegate: Rc::downgrade(&delegate),
            };
            (
                Self {
                    locals,
                    canonical,
                    delegate,
                },
                gate,
            )
        }
    }
    // SAFETY: owned C must satisfy the canonical ownership/disarm contract;
    // this wrapper retains the SAME local Rc and actual C, never matching data.
    unsafe impl<C: NativeActorCanonicalTerminalResources, G> NativeActorTerminalGraph
        for NativeActorTerminalResources<C, G>
    {
        fn actor_local_resources(&self) -> &Rc<NativeActorLocalResources> {
            &self.locals
        }
    }
    // SAFETY: original weak identities, actual row/probe ACKs and original
    // terminal lease are checked before/after the mandatory independent G<C>.
    // The unsafe canonical contract includes all native destructor/disarm ACKs.
    unsafe impl<C: NativeActorCanonicalTerminalResources, G: NativeTerminalResourceGate<C>>
        NativeTerminalResourceGate<NativeActorTerminalResources<C, G>>
        for NativeActorTerminalGate<C, G>
    {
        fn authorize_in_retired(
            &self,
            resources: &NativeActorTerminalResources<C, G>,
            context: &Context,
            stopped: &pair::Record,
            retired: &RetiredCarrierRead,
            bindings: &Bindings,
            history: &[crate::windows::member_carrier_members::ClosedMemberBinding],
        ) -> io::Result<()> {
            let locals = self.locals.upgrade().ok_or_else(conflict)?;
            let canonical = self.canonical.upgrade().ok_or_else(conflict)?;
            let delegate = self.delegate.upgrade().ok_or_else(conflict)?;
            if !Rc::ptr_eq(&locals, &resources.locals)
                || !Rc::ptr_eq(&canonical, &resources.canonical)
                || !Rc::ptr_eq(&delegate, &resources.delegate)
            {
                return Err(conflict());
            }
            let original = canonical.try_borrow()?;
            if !Rc::ptr_eq(original.actor_local_resources(), &locals) {
                return Err(conflict());
            }
            let check = || {
                locals.verify_terminal_in_retired(
                    context, stopped, retired, bindings, history, &*original,
                )
            };
            check()?;
            delegate
                .try_borrow()?
                .authorize_in_retired(&original, context, stopped, retired, bindings, history)?;
            check()
        }
    }
    impl NativeActorLocalResources {
        /// Pure factual clone of the SAME retained canonical originals. No
        /// constructor, SDK query, JSON comparison or effect/terminal grant.
        /// A partial capture lacking either actual pin remains unknown/denied.
        pub(crate) fn terminal_capture_originals(
            &self,
        ) -> io::Result<(Rc<NativeResourceRowsRead>, Rc<ProbeRead>)> {
            let parts = self.parts.try_borrow()?;
            clone_original_capture_pair(&parts.canonical_rows, &parts.canonical_probes)
        }
        /// Once-owning field cut into Pauli's caller-retained raw C. No opaque
        /// history is reconstructed; no strong reverse edge to local T remains.
        /// Unknown destination Drop preserves every moved root. Caller must
        /// still consume Kant's actual inert closed-generation proof in C/G.
        pub(crate) fn drain_member_generation_roots_into(
            &self,
            destination: &mut NativeMemberGenerationTerminalResources,
            retained: impl FnOnce(&Rc<NativeMemberGenerationTerminalCut>) -> io::Result<()>,
        ) -> io::Result<()> {
            {
                let mut transfer = self.generation_terminal.try_borrow_mut().map_err(denied)?;
                // Root destination first, even if the original local borrow is
                // unavailable. Failed entry never retries or moves replacements.
                transfer.capture(destination, |raw| {
                    let mut parts = self.parts.try_borrow_mut()?;
                    *raw = Some(NativeMemberGenerationRoots {
                        tickets: std::mem::take(&mut parts.member_generation_tickets),
                        row_receipts: std::mem::take(&mut parts.row_generation_receipts),
                        originals: std::mem::take(&mut parts.member_generation_originals),
                        rebind_receipts: std::mem::take(&mut parts.member_rebind_receipts),
                    });
                    Ok(())
                })?;
            }
            let original = self
                .generation_terminal
                .try_borrow()
                .map_err(denied)?
                .original()?;
            self.verify_member_generation_transfer(&original)?;
            // Neither source nor raw RefCell remains borrowed across C/G.
            retained(&original)
        }
        pub(crate) fn verify_member_generation_transfer(
            &self,
            original: &Rc<NativeMemberGenerationTerminalCut>,
        ) -> io::Result<()> {
            if !self
                .generation_terminal
                .try_borrow()
                .map_err(denied)?
                .same_original(original)
            {
                return Err(conflict());
            }
            let parts = self.parts.try_borrow()?;
            if !parts.member_generation_tickets.is_empty()
                || !parts.row_generation_receipts.is_empty()
                || !parts.member_generation_originals.is_empty()
                || !parts.member_rebind_receipts.is_empty()
            {
                return Err(conflict());
            }
            original.inspect(|_| Ok(())) // SAME owning field transfer only
        }
        /// Actual local owners + opaque ACKs in the already-active original
        /// terminal lease. No Authority, Source, journal or retired reentry.
        fn verify_terminal_in_retired<C: NativeActorCanonicalTerminalResources>(
            &self,
            context: &Context,
            stopped: &pair::Record,
            retired: &RetiredCarrierRead,
            bindings: &Bindings,
            history: &[crate::windows::member_carrier_members::ClosedMemberBinding],
            canonical: &C,
        ) -> io::Result<()> {
            let rows_root = canonical.actor_rows();
            let probes = canonical.actor_probes();
            let generations = canonical.actor_member_generation_roots()?;
            self.verify_member_generation_transfer(&generations)?;
            require_terminal_record(stopped)?;
            if stopped.scope != context.intent.scope
                || stopped.provenance != context.provenance
                || bindings.scope != stopped.scope
            {
                return Err(conflict());
            }
            retired
                .inspect_terminal_history_in_bracket(|actual| {
                    if actual != history {
                        return Err(native_denied(()));
                    }
                    Ok(())
                })
                .map_err(denied)?;
            self.verify_retired_probe_origins(probes)?;
            self.inspect_historical_member_rows(|pin, seal| {
                seal.inspect_original(pin, |ack| {
                    if ack.phase != rows::Phase::Stopped
                        || ack.pending.is_some()
                        || ack.current.address.is_some()
                        || ack.current.interface.policy != ack.baseline.interface.policy
                    {
                        return Err(rows::Error::Conflict);
                    }
                    Ok(())
                })
                .map_err(denied)
            })?;
            let parts = self.parts.try_borrow()?;
            if !Rc::ptr_eq(
                parts.canonical_rows.as_ref().ok_or_else(conflict)?,
                rows_root,
            ) {
                return Err(conflict());
            }
            rows_root
                .inspect_retired_in_bracket(retired, bindings, |facts| {
                    for i in 0..2 {
                        match (&parts.row_owners[i], &parts.row_pins[i], &facts.rows[i + 1]) {
                            (Some(owner), Some(pin), Some(row)) => {
                                let role = if i == 0 {
                                    rows::Role::MemberA
                                } else {
                                    rows::Role::MemberB
                                };
                                if !parts.row_attempted[i]
                                    || row.observed.is_some()
                                    || row.acknowledged.binding.role != role
                                    || row.acknowledged.binding.scope != stopped.scope
                                    || row.acknowledged.binding.network_epoch
                                        != context.provenance.network_epoch
                                    || !rows_root.matches_row_original(role, pin)
                                {
                                    return Err(native_denied(()));
                                }
                                verify_terminal_member_row_original(owner, pin, &row.acknowledged)
                                    .map_err(native_denied)?;
                            }
                            (None, None, None) if !parts.row_attempted[i] => {
                                // Canonical rows independently proved the actual
                                // original missing ledger; Option absence is not it.
                            }
                            _ => return Err(native_denied(())),
                        }
                    }
                    Ok(())
                })
                .map_err(denied)?;
            self.verify_retired_probe_origins(probes)?;
            self.verify_member_generation_transfer(&generations)?;
            retired
                .inspect_terminal_history_in_bracket(|actual| {
                    if actual != history {
                        return Err(native_denied(()));
                    }
                    Ok(())
                })
                .map_err(denied)
        }
        /// Historical originals only. SAME owner/pin/Stop seal is checked
        /// without current journal/NIC/Source queries or cleanup permission.
        /// Terminal G must separately prove current full SDK/protected absence.
        pub(crate) fn inspect_historical_member_rows(
            &self,
            mut read: impl FnMut(
                &Rc<RowRecordReadPin>,
                &Rc<rows::StoppedRowGeneration>,
            ) -> io::Result<()>,
        ) -> io::Result<()> {
            let parts = self.parts.try_borrow().map_err(denied)?;
            for (owner, original) in &parts.historical_member_rows {
                if !original
                    .pin
                    .same_original(&owner.record_read_pin().map_err(denied)?)
                {
                    return Err(conflict());
                }
                original
                    .seal
                    .inspect_original(&original.pin, |_| Ok(()))
                    .map_err(denied)?;
                read(&original.pin, &original.seal)?;
            }
            Ok(())
        }
        /// Original capture/write tokens remain in local T even on failed
        /// capture/registration/postflight. This is not their native authority
        /// or proof that the raw/native attempts successfully completed.
        pub(crate) fn inspect_member_row_captures<T>(
            &self,
            read: impl FnOnce(&[Rc<NativeRowGenerationCapture>]) -> io::Result<T>,
        ) -> io::Result<T> {
            read(&self.parts.try_borrow().map_err(denied)?.member_row_captures)
        }
        /// SAME controller-issued receipts, including failed publication or
        /// postflight. These are original history, not a successful terminal
        /// disposition or permission to query their retired processes/NICs.
        pub(crate) fn inspect_member_rebind_receipts<T>(
            &self,
            read: impl FnOnce(&[Rc<NativeMemberRebindReceipt>]) -> io::Result<T>,
        ) -> io::Result<T> {
            if let Some(original) = self
                .generation_terminal
                .try_borrow()
                .map_err(denied)?
                .read_cut()?
            {
                return original.inspect_rebind_receipts(read);
            }
            read(
                &self
                    .parts
                    .try_borrow()
                    .map_err(denied)?
                    .member_rebind_receipts,
            )
        }
        /// Borrow actual SDK-original read pins retained by a partial/successful
        /// rebind seal. No proof is imported or revived, no SDK/Authority call.
        /// Terminal G must account for THESE aliases when proving all references
        /// and destructors inert; missing/unsealed proof is NOT an empty graph.
        pub(crate) fn inspect_rebind_read_origins<T>(
            &self,
            read: impl FnOnce(Option<NativeRebindReadOrigins<'_>>) -> io::Result<T>,
        ) -> io::Result<T> {
            let parts = self.parts.try_borrow().map_err(denied)?;
            let slot = parts.rebind_proof.try_borrow().map_err(denied)?;
            read(slot.original.as_ref().map(|p| p.read_origins()))
        }
        pub(crate) fn inspect_startup_read_origins<T>(
            &self,
            read: impl FnOnce(Option<NativeRebindReadOrigins<'_>>) -> io::Result<T>,
        ) -> io::Result<T> {
            let parts = self.parts.try_borrow().map_err(denied)?;
            let original = parts.startup_proof.try_borrow().map_err(denied)?;
            read(original.as_ref().map(|p| p.read_origins()))
        }
        /// Factual pin access only, safe under caller's original terminal row
        /// bracket. None is unknown/not captured, NEVER a successful absence.
        pub(crate) fn member_row_pin(&self, slot: Slot) -> io::Result<Rc<RowRecordReadPin>> {
            self.parts.try_borrow().map_err(denied)?.row_pins[idx(slot)]
                .clone()
                .ok_or_else(conflict)
        }
        /// Original historical Stop seal only, not current absence or storage
        /// reuse permission. The supplied original row pin is checked by seal.
        pub(crate) fn stopped_row_generation(
            &self,
            slot: Slot,
        ) -> io::Result<Rc<rows::StoppedRowGeneration>> {
            self.parts
                .try_borrow()
                .map_err(denied)?
                .stopped_row_generations[idx(slot)]
            .clone()
            .ok_or_else(conflict)
        }
        /// Original row-generation roots, including failed postflight. Receipt
        /// presence is not current absence or a future private-storage grant.
        pub(crate) fn inspect_row_generation_receipts<T>(
            &self,
            read: impl FnOnce(&[Rc<NativeRowGenerationReceipt>]) -> io::Result<T>,
        ) -> io::Result<T> {
            if let Some(original) = self
                .generation_terminal
                .try_borrow()
                .map_err(denied)?
                .read_cut()?
            {
                return original.inspect_row_receipts(read);
            }
            read(
                &self
                    .parts
                    .try_borrow()
                    .map_err(denied)?
                    .row_generation_receipts,
            )
        }
        pub(crate) fn inspect_histories<T>(
            &self,
            read: impl FnOnce(&[Rc<NativeNetworkIntentRead>], &[policy::Model]) -> io::Result<T>,
        ) -> io::Result<T> {
            let parts = self.parts.try_borrow().map_err(denied)?;
            read(&parts.network_intents, &parts.guard_acks)
        }
        /// Original Stop-bound generation pins, including failed projections.
        /// Pure borrowed facts; no native cleanup or replacement permission.
        pub(crate) fn inspect_member_generation_tickets<T>(
            &self,
            read: impl FnOnce(&[Rc<NativeMemberPreparationGeneration>]) -> io::Result<T>,
        ) -> io::Result<T> {
            if let Some(original) = self
                .generation_terminal
                .try_borrow()
                .map_err(denied)?
                .read_cut()?
            {
                return original.inspect_tickets(read);
            }
            read(
                &self
                    .parts
                    .try_borrow()
                    .map_err(denied)?
                    .member_generation_tickets,
            )
        }
        /// SAME canonical probe membership and actual clone/base close ACKs
        /// ONLY. No Source/Retired/Pair/WFP/SDK reentry or terminal effect grant.
        /// The caller still must independently prove the full scoped universe.
        pub(crate) fn verify_retired_probe_origins(
            &self,
            inventory: &Rc<ProbeRead>,
        ) -> io::Result<()> {
            let parts = self.parts.try_borrow().map_err(denied)?;
            if !Rc::ptr_eq(
                parts.canonical_probes.as_ref().ok_or_else(conflict)?,
                inventory,
            ) {
                return Err(conflict());
            }
            inventory.inspect_retired().map_err(denied)?;
            for index in 0..2 {
                match (&parts.held[index], &parts.held_reads[index]) {
                    (None, None) => {} // canonical inventory above checks unpublished originals
                    (Some(owner), Some(read)) => {
                        let owner = owner.try_borrow().map_err(denied)?;
                        let actual = owner.read_pin();
                        if !actual.same_original(read) {
                            return Err(conflict());
                        }
                        inventory
                            .verify_member_slot(if index == 0 { Slot::A } else { Slot::B }, read)
                            .map_err(denied)?;
                        read.retired()
                            .map_err(denied)?
                            .verify_same_original(&actual)
                            .map_err(denied)?;
                    }
                    _ => return Err(conflict()),
                }
            }
            if let Some(context) = &parts.socket_context {
                if !context.serial.revoked.get() {
                    return Err(conflict());
                }
                for issued in context.issued.try_borrow().map_err(denied)?.iter() {
                    if issued.lease.try_borrow().map_err(denied)?.is_some() {
                        return Err(conflict());
                    }
                    let original = issued.original.try_borrow().map_err(denied)?.read_pin();
                    inventory.verify_member(&original).map_err(denied)?;
                    original
                        .retired()
                        .map_err(denied)?
                        .verify_same_original(&original)
                        .map_err(denied)?;
                }
            }
            inventory.inspect_retired().map_err(denied)?;
            Ok(())
        }
        pub(crate) fn verify_member_row_origin(&self, slot: Slot) -> io::Result<()> {
            let parts = self.parts.try_borrow().map_err(denied)?;
            let pin = parts.row_pins[idx(slot)].as_ref().ok_or_else(conflict)?;
            let rows = parts.canonical_rows.as_ref().ok_or_else(conflict)?;
            if !rows.matches_row_original(
                if slot == Slot::A {
                    rows::Role::MemberA
                } else {
                    rows::Role::MemberB
                },
                pin,
            ) {
                return Err(conflict());
            }
            // No authority/kernel call: original capture/CAS facts are compared
            // independently with the protected record + SDK by terminal G.
            Ok(())
        }
    }

    /// Fresh comparison data only. Raman's actual native capture protocol must
    /// independently retain/verify these exact paths before owner.select; the
    /// copied Snapshot alone cannot seed an original physical ACK.
    struct NativeNetworkPlan {
        snapshot: pair::NetworkSnapshot,
        physical: Vec<crate::member_physical::PhysicalRoute>,
    }

    /// Both coordinator CAS and actor pin minting use THIS SAME actual store.
    /// No second protected store, read-only reopened owner or imported receipt.
    pub(crate) struct NativePairJournal {
        original: Rc<RefCell<NativeCarrierPairStore>>,
    }
    impl NativePairJournal {
        pub(crate) fn original(original: Rc<RefCell<NativeCarrierPairStore>>) -> Self {
            Self { original }
        }
    }
    impl PairJournal for NativePairJournal {
        fn begin_cleanup(&mut self, scope: &SessionScope) -> io::Result<()> {
            // Explicit irreversible PRIVATE storage transition only. This is
            // THAT same actor/store Rc, not a reopened/equal origin. It performs
            // no SDK effects and supplies no native Closing/effect permission.
            self.original
                .try_borrow_mut()
                .map_err(denied)?
                .begin_cleanup(scope)
        }
        fn load(&mut self, scope: &SessionScope) -> io::Result<Option<pair::Record>> {
            self.original.try_borrow_mut().map_err(denied)?.load(scope)
        }
        fn compare_exchange(
            &mut self,
            old: Option<&pair::Record>,
            next: &pair::Record,
        ) -> io::Result<()> {
            self.original
                .try_borrow_mut()
                .map_err(denied)?
                .compare_exchange(old, next)
        }
    }

    pub(crate) type NativeAfterGenerationTicket<'s> = dyn FnMut(
            &Rc<NativeMemberPreparationGeneration>,
            &Rc<NativeNeverMemberEffects>,
            &mut KeyLock,
        ) -> crate::member_carrier::Result<()>
        + 's;

    /// Borrowed original preparation seam, not ownership adoption. Grouped to
    /// keep the mandatory Startup method explicit without an unbounded arg list.
    pub(crate) struct NativeLiveMemberPreparation<'s> {
        pub lock: &'s mut KeyLock,
        pub controller: &'s mut Option<Controller>,
        /// SAME surviving controller and actual Source for the mandatory
        /// verify_live_attach_proposal; Fresh-only verification is not valid.
        pub other: &'s mut Option<Controller>,
        pub source: &'s Rc<NativeSourceRead>,
        pub after_ticket: &'s mut NativeAfterGenerationTicket<'s>,
    }

    /// # Safety
    /// Implemented ONLY by the actual Startup's private OriginalNever issuer.
    /// Success authenticates its acknowledged whole terminal readonly bracket,
    /// zero native-create/attach attempts and SAME opaque Stopped publication.
    /// This method is PURE (no SDK/Authority reentry); an unacknowledged proof,
    /// equal foreign Pair, failed/unwound postflight or attempted C must deny.
    /// It is NOT a module ACK, native effect grant or generic empty observation.
    pub(crate) unsafe trait NativeZeroEffectTerminalProof {
        fn verify_original(
            &self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> crate::member_carrier::Result<()>;
    }
    /// # Safety
    /// ONLY the actual Startup's private retained create/attach invocation may
    /// issue this discriminator, under SAME original Stopped/serial bracket.
    /// verify_original is PURE exact opaque origin/ACK comparison, not SDK
    /// absence, successful creation, disarm or module permission. Unknown or
    /// foreign invocation denies. This factual proof holds NO owning native
    /// module/SDK/Runtime/KeyLock/Source aliases or strong actor/C/G backedges;
    /// original invocation identity is private/weak, never imported from JSON.
    pub(crate) unsafe trait NativeAttemptedTerminalProof {
        fn verify_original(
            &self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> crate::member_carrier::Result<()>;
        /// PURE SAME original invocation/graph-layout discriminator only.
        /// Unknown/changed origin denies; this never grants resource absence,
        /// a Source, native ACK, module unload or a fallback to Never.
        fn original_layout(
            &self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> crate::member_carrier::Result<
            crate::windows::member_carrier_startup::NativeAttemptedTerminalLayout,
        >;
    }
    pub(crate) type NativeStartupTerminalBranch<'a> = OriginalTerminalBranch<
        dyn NativeZeroEffectTerminalProof + 'a,
        dyn NativeAttemptedTerminalProof + 'a,
    >;
    /// Main's actual cold owning root, not an alternate factory or success G.
    ///
    /// # Safety
    /// Retain SAME Runtime/KeyLock/files/payload/prepared/Assembly/Ready roots
    /// before every fallible construction. Supplied SAME-store opaque Pair is
    /// used under whole original Calling; no invented Source/module before C.
    /// create_ready returns rooted C only; attach_full retains PARTIAL graph
    /// before baseline capture, then full inputs before registration/postflight.
    /// Errors/unwinds retain originals; registration NEVER grants an effect.
    pub(crate) unsafe trait NativeStartup<'a> {
        /// Exact original no-constructor module lane only. Must complete the
        /// actual typed own-DLL ACK under full original bounded native bracket
        /// BEFORE canonical capture. Failed/unknown constructor/load denies.
        fn release_module_only_terminal(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> crate::member_carrier::Result<()>;
        /// Pure SAME completed whole native release, while its original owner
        /// remains in Startup. No SDK access or raw/destructor permission.
        fn verify_module_only_release(
            &self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> crate::member_carrier::Result<()>;
        /// SAME original raw/canonical owners and acknowledged module release;
        /// no image/SDK reentry after release. Retain all partial roots on Err.
        /// Bind original initial-DATA issuer only after whole owning disposition.
        fn dispose_module_only_terminal(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            destination: &mut crate::windows::member_carrier_startup::native::TerminalStartupResources<'a>,
        ) -> crate::member_carrier::Result<()>;
        /// PURE completed SAME Startup/Pair owning-disposal comparison only.
        /// No import, SDK/Runtime/backend reentry or success based on phase.
        fn verify_module_only_disposition(
            &self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> crate::member_carrier::Result<()>;
        /// Retain/read SAME loader-only originals under the concrete bounded
        /// Calling/Pair reader. Observations are DATA: no release or completion
        /// permission. Unknown layouts deny while keeping Startup intact.
        fn observe_attempted_module_only_terminal(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> crate::member_carrier::Result<()>;
        /// Sole object-safe branch selection. Authenticate SAME Stopped pin,
        /// Runtime/serial/private invocation ledger before/after selection.
        /// No-attempt: issue the actual whole sealed Never/SDK/BFE proof using
        /// capture_zero_effect_terminal. Attempted: issue ONLY SAME retained
        /// original invocation discriminator, without entering/poisoning the
        /// no-C capture latch. Unknown -> Err, never catch/no-C/fallback.
        /// Retain actual original branch BEFORE fallible postflight. The enum
        /// does not grant absence/native effects/destruction; normal C/G must
        /// still prove every original native owner/ACK. No default success.
        fn select_terminal_branch(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            retain: &mut dyn FnMut(
                NativeStartupTerminalBranch<'a>,
            ) -> crate::member_carrier::Result<()>,
        ) -> crate::member_carrier::Result<()>;
        /// Issue ONLY from this SAME private OriginalNever ledger, actual
        /// Stopped ACK and full mixed SDK/48-key BFE terminal Calling. Retain
        /// the actual original proof BEFORE fallible whole-call postflight;
        /// error/unwind leaves it unacknowledged and irreversibly cleanup-only.
        /// Any create/attach attempt (even with no returned owner) denies this
        /// lane. No phase/None/JSON inference, successful default or module ACK.
        fn capture_zero_effect_terminal(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            retain: &mut dyn FnMut(
                Rc<dyn NativeZeroEffectTerminalProof + 'a>,
            ) -> crate::member_carrier::Result<()>,
        ) -> crate::member_carrier::Result<()>;
        /// The destination contains this SAME Startup's actual raw owners.
        /// Verify private issued-proof identity AND exact transfer provenance,
        /// perform fresh whole readonly postflight, explicitly disarm pristine/
        /// zero-effect wrappers and release their original ownership. Preserve
        /// all moved/unmoved unknown roots on error/unwind; never reconstruct a
        /// lock/module/source or implicitly close any uncertain native object.
        /// All SDK/J checks precede original KeyLock disposal. On success raw T
        /// is explicitly released and this empty Startup shell has inert Drop.
        fn dispose_zero_effect_terminal(
            &mut self,
            proof: &Rc<dyn NativeZeroEffectTerminalProof + 'a>,
            destination: &mut crate::windows::member_carrier_startup::native::TerminalStartupResources<'a>,
        ) -> crate::member_carrier::Result<()>;
        /// Owning destination already retained by the caller. Move SAME actual
        /// partial Startup/Ready/Assembly/graph originals before fallible checks;
        /// preserve both moved and unmoved originals on failure/unwind. This
        /// is registration only, never native disarm/absence/module permission.
        fn drain_terminal_into(
            &mut self,
            destination: &mut crate::windows::member_carrier_startup::native::TerminalStartupResources<'a>,
        ) -> crate::member_carrier::Result<()>;
        fn preflight_fresh(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> crate::member_carrier::Result<()>;
        fn prepare_member(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            proposal: &pair::Record,
            member: &nelomai_client_tunnel::redundancy::protocol::Member,
            native: &str,
        ) -> crate::member_carrier::Result<crate::member_owner::Record>;
        /// Reserve Attach preparation AFTER full graph handoff. The caller
        /// lends the SAME lock moved out of this startup root; current is the
        /// protected Running ACK, proposal is UNSAVED. Own the whole Calling
        /// interval and retain the actual new prepared owner before return.
        /// For an existing controller, mint/retain its SAME actual closed
        /// generation ticket, then invoke after_ticket BEFORE moving old roots
        /// or constructing/writing any replacement. Retain BOTH old prepared
        /// and controller roots before subsequent preparation/postflight.
        /// Callback error/unwind forbids preparation/retry; no Option absence
        /// is retirement authority. First Attach has no controller/callback.
        fn prepare_live_member(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            current: &pair::Record,
            proposal: &pair::Record,
            member: &nelomai_client_tunnel::redundancy::protocol::Member,
            native: &str,
            preparation: NativeLiveMemberPreparation<'_>,
        ) -> crate::member_carrier::Result<crate::member_owner::Record>;
        fn attest_bootstrap(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            effect: pair::Effect,
        ) -> crate::member_carrier::Result<()>;
        /// Actual C owner BEFORE graph attachment. Run the SAME precise
        /// Closing3/6/7/8 Calling with original Runtime/KeyLock/Pair/private
        /// invocation, pristine graph and native carrier/row/session gates.
        /// No absent-graph proof, substitute Never or full-G fabrication.
        fn cleanup_pregraph_carrier(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            effect: pair::Effect,
        ) -> crate::member_carrier::Result<()>;
        /// Precise Closing0..8 factual read of SAME original cold C/rows and
        /// never-started prepared members under full SDK + two BFE reads. No
        /// graph/constructor absence inference or native/disposition grant.
        fn read_pregraph_closing_cleanup(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> crate::member_carrier::Result<policy::Snapshot>;
        /// SAME actual retained key owner at Closing11; native key IO reattests
        /// every restore effect. Before/after full SDK + WFP facts are separate
        /// whole calls, not mutation inside an immutable SDK read callback.
        fn restore_pregraph_keys(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> crate::member_carrier::Result<()>;
        /// Exact Closing11 before OR after effect, selected from actual native
        /// receipt under SAME original SDK/Calling. Not FullEmpty12, final
        /// Stopped or a constructor/terminal disposition permission.
        fn read_pregraph_key_restore(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> crate::member_carrier::Result<policy::Snapshot>;
        /// Actual successful loader plus original no-constructor Assembly,
        /// exact current Closing stage/Pair ACK and bounded full SDK/keys/
        /// private paths/BFE read. This is readonly: it does not close absent
        /// resources, restore keys, unload modules or retire initial DATA.
        fn read_bootstrap_no_constructor_cleanup(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> crate::member_carrier::Result<policy::Snapshot>;
        /// Separate current Stopped12/None factual read, using original Never
        /// or successful loader/no-constructor lineage. No unload/disposition
        /// or ordinary fallback; each successful call rereads the full universe.
        fn read_bootstrap_no_constructor_terminal(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> crate::member_carrier::Result<policy::Snapshot>;
        fn create_ready(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> crate::member_carrier::Result<InterfaceProof>;
        /// After protected CarrierReady completion, under whole actual run()
        /// (pendingNone) and original raw-readonly C Source. Retain full graph
        /// BEFORE capture/registration/postflight. Never upgrade G at None.
        fn attach_full(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            retain: &mut dyn FnMut(NativeActorInputs<'a>) -> crate::member_carrier::Result<()>,
        ) -> crate::member_carrier::Result<()>;
        /// Called within Assembly's actual MemberStart Calling, borrowing the
        /// SAME NativePrecreation mutation_lock. Transfer only the prepared
        /// owner already retained before C, rooting destination before checks.
        fn attach_member(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            slot: Slot,
            attachment: NativeMemberAttachment<MemberGate>,
            destination: &mut Option<Controller>,
            lock: &mut KeyLock,
        ) -> crate::member_carrier::Result<()>;
        /// Factual no-Start verification, NEVER a fabricated Stopped receipt.
        /// Prove THIS retained prepared owner's no-Start capability (or original
        /// uncaptured slot), creator/member inventory Missing, protected native
        /// key/config/row baseline and full SDK absence before/after. Unknown
        /// attempt/lost ACK denies. Do not infer absence from controller=None.
        /// With actor_lock Some, use caller's existing Closing Calling interval
        /// and SAME lock. With None, own the whole cleanup Calling interval and
        /// use this cold startup root's actual retained lock/partial originals.
        fn verify_unstarted_member(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            slot: Slot,
            closing: Option<&Rc<NativeClosingRead>>,
            actor_lock: Option<&mut KeyLock>,
        ) -> crate::member_carrier::Result<()>;
        /// No-C Stopped12/None ONLY. Own the actual uncaptured terminal readonly
        /// Calling via SAME Never ledger and actual terminal Pair publication.
        /// Invoke Never.verify_uncaptured_terminal_absent inside Calling using
        /// this startup root's SAME retained lock. Missing roots/SDK lookup or
        /// imported JSON cannot replace the original zero-attempt ledger.
        /// Native-keys-Stopped, new Source and native effects are forbidden here.
        fn verify_uncaptured_terminal(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> crate::member_carrier::Result<()>;
        /// Same independently authenticated terminal Calling channel, plus
        /// two actual full scoped BFE reads under the original Never ledger.
        /// Return observed SDK facts, not an empty model derived from expected.
        fn read_uncaptured_terminal(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> crate::member_carrier::Result<policy::Snapshot>;
        /// Closing12/FullEmpty only, not an acknowledged Stopped read. Own
        /// the SAME bounded cleanup Calling; authenticate the original Never
        /// ledger/partial bootstrap owners, key restoration and full native
        /// absence before/after two actual 48-key BFE snapshots. No alternate
        /// Source, receipt recreation, metadata-only success or native effect.
        fn read_bootstrap_full_empty(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> crate::member_carrier::Result<policy::Snapshot>;
        /// Exact Closing9/NativeEmpty or Closing10/Guard READ only, under this
        /// startup root's whole original cleanup Calling. Prove original Never
        /// zero-attempt ledger OR retained partial C/closed ACKs, full mixed SDK,
        /// row/network/probe attempt histories and actual 48-key Guard facts.
        /// Missing inputs/unknown attempts deny; no synthesized receipts, new
        /// Source, terminal-Stopped fallback or native effects. Registration,
        /// phase, JSON, and Option absence never supply cleanup success.
        fn read_bootstrap_native_empty(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> crate::member_carrier::Result<policy::Snapshot>;
    }

    pub(crate) struct NativeColdActorInputs<'a> {
        pub store: Rc<RefCell<NativeCarrierPairStore>>,
        pub startup: Box<dyn NativeStartup<'a> + 'a>,
    }

    /// Main may assemble these actual initialized originals in its final
    /// factory. They are moved into the actor before any validation/registration.
    /// None is never an empty/absent/native-success fact.
    pub(crate) struct NativeActorInputs<'a> {
        pub context: Context,
        pub runtime: Rc<RuntimeRead>,
        pub lock: KeyLock,
        pub files: NativeSessionFiles,
        pub store: Rc<RefCell<NativeCarrierPairStore>>,
        pub pair: Rc<NativePairIntentRead>,
        pub expected: pair::Record,
        pub assembly: NativeAssemblySlot,
        pub carrier: NativeCarrierRoot<'a>,
        pub pins: NativeCarrierPins,
        pub originals: Rc<Observer<OriginalWintun>>,
        pub image: Rc<OriginalImage>,
        /// SAME loaded source retained by startup, not reopened for reserve B.
        pub member_source: Rc<MemberSource>,
        pub members: Rc<MemberInventoryRead>,
        pub rows: Rc<NativeResourceRowsRead>,
        pub guard: Rc<RefCell<Guard>>,
        pub guard_journal: WindowsCarrierGuardStore<NativeSessionFiles>,
        pub attestor: Rc<NativeGuardSelection>,
        pub guard_resources: Rc<NativeGuardResourceSelection<OriginalGuardAttestor>>,
        pub lifecycle: NativeLifecycleSelection<OriginalGuardAttestor>,
        /// Main's actual full resource gate. Rooted here BEFORE graph capture
        /// postflight, moved once to Ready Root on the first actual pending edge.
        /// None is NEVER successful late-effect authorization.
        pub lifecycle_gate: Option<Box<dyn NativeLifecycleGate>>,
        pub probes: Probes,
        pub probe_read: Rc<ProbeRead>,
        pub probe_state: Rc<NativeProbeResourceState<OriginalGuardAttestor>>,
        pub network_read: Rc<NativeNetworkRead>,
        pub baseline: Rc<NativeNetworkBaselineRead<OriginalGuardAttestor>>,
        pub network_gate: Rc<NetworkGate>,
        pub network_owner: NetworkOwner,
        pub network_ack: Rc<NativeNetworkAckRead<NetworkGate>>,
        pub controllers: [Option<Controller>; 2],
        pub member_gates: [Option<Rc<RefCell<MemberGate>>>; 2],
    }
    struct Selected {
        pin: Rc<NativePairIntentRead>,
        record: pair::Record,
    }
    #[derive(Clone, PartialEq, Eq)]
    struct NativeRebindSnapshot {
        guard: policy::Snapshot,
        rows: NativeResourceRowsFacts,
        network: NetworkSample,
        probes: [Option<policy::ProbeTuple>; 2],
    }
    /// Constructed ONLY inside actual supervised original Source SDK reads.
    /// Copied snapshots are facts; private original roots and whole-call seal
    /// are required again before Root's STORAGE-only completion is invoked.
    struct NativeRebindProof {
        root: Rc<NativeExecutionRoot>,
        lease: Arc<NativeExecutionLease>,
        session_ack: crate::windows::member_session::epoch::SessionWriteAck,
        pair: Rc<NativePairIntentRead>,
        record: pair::Record,
        source: Rc<NativeSourceRead>,
        rows: Rc<NativeResourceRowsRead>,
        probes: Rc<ProbeRead>,
        network: Rc<NativeNetworkRead>,
        guard: Rc<RefCell<Guard>>,
        members: Rc<MemberInventoryRead>,
        observed: NativeRebindSnapshot,
    }
    impl NativeRebindProof {
        fn read_origins(&self) -> NativeRebindReadOrigins<'_> {
            NativeRebindReadOrigins {
                pair: &self.pair,
                expected: &self.record,
                source: &self.source,
                rows: &self.rows,
                probes: &self.probes,
                network: &self.network,
                guard: &self.guard,
                members: &self.members,
            }
        }
    }
    pub(crate) struct NativeRebindReadOrigins<'a> {
        pub(crate) pair: &'a Rc<NativePairIntentRead>,
        pub(crate) expected: &'a pair::Record,
        pub(crate) source: &'a Rc<NativeSourceRead>,
        pub(crate) rows: &'a Rc<NativeResourceRowsRead>,
        pub(crate) probes: &'a Rc<ProbeRead>,
        pub(crate) network: &'a Rc<NativeNetworkRead>,
        pub(crate) guard: &'a Rc<RefCell<Guard>>,
        pub(crate) members: &'a Rc<MemberInventoryRead>,
    }
    struct NativeActorExecution {
        root: Rc<NativeExecutionRoot>,
        sessions: Option<NativeSessionAckRoot>,
        // Every returned selection remains rooted even when its next native
        // postflight fails. Runtime Root also retains selection before return.
        leases: Vec<Arc<NativeExecutionLease>>,
        startup_attempted: bool,
    }
    /// Borrow-free original aliases for the explicit inventory transition. The
    /// controller/lock remain borrowed by Startup's SAME supervised Calling.
    /// This object constructs no receipt, owner, SDK lease or permission.
    struct NativeMemberGenerationProjection {
        context: Context,
        runtime: Rc<RuntimeRead>,
        source: Rc<NativeSourceRead>,
        inventory: Rc<MemberInventoryRead>,
        rows: Rc<NativeResourceRowsRead>,
        supervisor: Rc<crate::windows::member_native_deadline::NativeDeadline>,
        guard: Rc<RefCell<Guard>>,
        row_pin: Option<Rc<RowRecordReadPin>>,
        row_seal: Option<Rc<rows::StoppedRowGeneration>>,
        slot: Slot,
    }
    impl NativeMemberGenerationProjection {
        fn guard_facts(&self, expected: &pair::Record) -> io::Result<policy::Snapshot> {
            self.source
                .inspect_window(|window| {
                    if !window.matches_source(&self.source)
                        || !window.matches_runtime(&self.runtime)
                        || window.bindings().scope != expected.scope
                        || window.bindings().carrier.as_ref().map(|c| c.identity.proof)
                            != expected.carrier
                    {
                        return Err(native_denied(()));
                    }
                    let actual = self
                        .guard
                        .try_borrow_mut()
                        .map_err(native_denied)?
                        .snapshot_in_window(window)
                        .map_err(native_denied)?;
                    compare_member_generation_guard(self.slot, &expected.guard, &actual)
                        .map_err(native_denied)?;
                    Ok(actual)
                })
                .map_err(denied)
        }
        fn project(
            &self,
            ticket: &Rc<NativeMemberPreparationGeneration>,
            never: &Rc<NativeNeverMemberEffects>,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            lock: &mut KeyLock,
            retained_rows: &mut Vec<Rc<NativeRowGenerationReceipt>>,
        ) -> io::Result<Rc<NativeRowGenerationReceipt>> {
            if !self.runtime.matches_lock(lock)
                || ticket.slot() != crate::member_pair::slot_native(self.slot)
                || ticket.context() != &self.context
            {
                return Err(conflict());
            }
            ticket
                .verify_original(never, &self.runtime, &self.context)
                .map_err(denied)?;
            ticket.verify_source(&self.source).map_err(denied)?;
            let row_pin = self.row_pin.as_ref().ok_or_else(conflict)?;
            let row_seal = self.row_seal.as_ref().ok_or_else(conflict)?;
            // Historical SAME Stop CAS only. Current absence comes from the
            // independent full SDK inventory transition, never this seal.
            row_seal
                .inspect_original(row_pin, |_| Ok(()))
                .map_err(denied)?;
            let verify_pair = || {
                original.inspect(&self.runtime, &self.supervisor, |actual| {
                    if actual != expected {
                        return Err(conflict());
                    }
                    Ok(())
                })
            };
            verify_pair()?;
            let keys = self
                .runtime
                .record(
                    &self.context,
                    crate::windows::member_session::RecordKind::NativeCarrierReceipts,
                )
                .map_err(denied)?;
            let native =
                crate::member_carrier_native_ownership::Record::decode(&keys).map_err(denied)?;
            let key = &native.keys[idx(self.slot) + 1];
            if native.context != self.context
                || native.phase != crate::member_carrier_native_ownership::Phase::Preparing
                || key.phase != crate::member_carrier_native_ownership::KeyPhase::Captured
                || !key.new_key_ack
                || key.pending.is_some()
                || key.current != key.baseline
            {
                return Err(conflict()); // Facts only; original key ownership remains in Assembly.
            }
            let before = self.guard_facts(expected)?;
            // Source/Guard/Pair callbacks have ALL returned before mutation.
            // SAME underlying inventory/health alias, not a new inventory.
            let mut inventory = self.inventory.read_pin();
            let row_inputs = || NativeRowGenerationInputs {
                ticket,
                never,
                pin: row_pin,
                seal: row_seal,
                pair: original,
                record: expected,
                supervisor: &self.supervisor,
            };
            let receipt = project_generation_order(
                retained_rows,
                || {
                    self.rows
                        .retire_member_generation(row_inputs())
                        .map_err(denied)
                },
                || {
                    inventory
                        .retire_generation(NativeRetirementInputs {
                            ticket,
                            never,
                            source: &self.source,
                            pair: original,
                            expected,
                            supervisor: &self.supervisor,
                        })
                        .map_err(denied)
                },
                |receipt| {
                    self.rows
                        .complete_member_generation_retirement(receipt, row_inputs())
                        .map_err(denied)
                },
            )?;
            // Resume ordinary Guard/Source reads ONLY after rows completion;
            // never sample the half-state or reset/reuse the stopped owner.
            let after = self.guard_facts(expected)?;
            if after != before
                || !self.runtime.matches_lock(lock)
                || self
                    .runtime
                    .record(
                        &self.context,
                        crate::windows::member_session::RecordKind::NativeCarrierReceipts,
                    )
                    .map_err(denied)?
                    != keys
            {
                return Err(conflict());
            }
            row_seal
                .inspect_original(row_pin, |_| Ok(()))
                .map_err(denied)?;
            ticket
                .verify_original(never, &self.runtime, &self.context)
                .map_err(denied)?;
            verify_pair()?;
            Ok(receipt)
        }
    }
    struct OriginalPairCache {
        store: Rc<RefCell<NativeCarrierPairStore>>,
        selected: RefCell<Option<Selected>>,
        attempted: RefCell<Vec<Rc<NativePairIntentRead>>>,
    }
    impl OriginalPairCache {
        fn current(&self, record: &pair::Record) -> io::Result<Rc<NativePairIntentRead>> {
            let mut selected = self.selected.try_borrow_mut().map_err(denied)?;
            if let Some(old) = selected.as_ref() {
                if old.record == *record {
                    return Ok(old.pin.clone());
                }
                cache_progress(&old.record, record)?;
            }
            let pin = Rc::new(
                self.store
                    .try_borrow_mut()
                    .map_err(denied)?
                    .record_intent(record)?,
            );
            self.attempted
                .try_borrow_mut()
                .map_err(denied)?
                .push(pin.clone());
            *selected = Some(Selected {
                pin: pin.clone(),
                record: record.clone(),
            });
            Ok(pin)
        }
    }
    type Lease = HeldProbeLease<Wfp, OriginalGuardAttestor, ProbeGate>;
    struct SocketContext {
        serial: Rc<ActorSerial>,
        execution_pending: Rc<Cell<bool>>,
        context: Context,
        supervisor: Rc<crate::windows::member_native_deadline::NativeDeadline>,
        runtime: Rc<RuntimeRead>,
        pair: Rc<OriginalPairCache>,
        probes: Rc<NativeProbeResourceState<OriginalGuardAttestor>>,
        attestor: Rc<NativeGuardSelection>,
        guard_resources: Rc<NativeGuardResourceSelection<OriginalGuardAttestor>>,
        issued: RefCell<Vec<IssuedLease>>,
    }
    struct IssuedLease {
        original: Rc<RefCell<Held>>,
        lease: Rc<RefCell<Option<Lease>>>,
    }
    impl SocketContext {
        fn issue(self: &Rc<Self>, original: &Rc<RefCell<Held>>) -> io::Result<NativePairSocket> {
            // Reserve the root borrow BEFORE native clone ACK. The underlying
            // owner also roots its handle before all native clone postflight.
            let mut issued = self.issued.try_borrow_mut().map_err(denied)?;
            let actual = original
                .try_borrow_mut()
                .map_err(denied)?
                .lease()
                .map_err(denied)?;
            let lease = Rc::new(RefCell::new(Some(actual)));
            issued.push(IssuedLease {
                original: original.clone(),
                lease: lease.clone(),
            });
            Ok(NativePairSocket {
                original: original.clone(),
                context: self.clone(),
                lease,
            })
        }
        /// Caller MUST first freshly authenticate actual full Guard allow
        /// absence in SAME Calling. Worker aliases share these exact token slots;
        /// they are revoked before original socket close, not dropped as ACKs.
        fn retire_original_leases(&self, original: &Rc<RefCell<Held>>) -> io::Result<()> {
            for issued in self.issued.try_borrow().map_err(denied)?.iter() {
                if Rc::ptr_eq(&issued.original, original) {
                    let token = issued.lease.try_borrow_mut().map_err(denied)?.take();
                    drop(token); // existing lease Drop keeps any unconfirmed native close canonically
                }
            }
            Ok(())
        }
        fn run<T>(&self, call: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
            execution_forward_call(&self.serial, &self.execution_pending, || {
                let record = self
                    .pair
                    .store
                    .try_borrow_mut()
                    .map_err(denied)?
                    .load(&self.context.intent.scope)?
                    .ok_or_else(conflict)?;
                if record.phase != pair::Phase::Running
                    || record.pending.is_some()
                    || record.operation.is_some()
                {
                    return Err(conflict());
                }
                let pin = self.pair.current(&record)?;
                self.supervisor
                    .run(&self.context, || {
                        pin.inspect(&self.runtime, &self.supervisor, |actual| {
                            if actual != &record {
                                return Err(conflict());
                            }
                            Ok(())
                        })
                        .map_err(carrier_denied)?;
                        self.attestor
                            .select(pin.clone(), record.clone())
                            .map_err(|_| CarrierError::Pending)?;
                        self.guard_resources
                            .select(pin.clone(), record.clone())
                            .map_err(|_| CarrierError::Pending)?;
                        self.probes
                            .select(pin.clone(), record.clone())
                            .map_err(|_| CarrierError::Pending)?;
                        // Nonblocking IO is not failed authority. Complete all real
                        // postflight checks before propagating an ordinary WouldBlock.
                        let value = call();
                        if value
                            .as_ref()
                            .is_err_and(|e| e.kind() != io::ErrorKind::WouldBlock)
                        {
                            return Err(CarrierError::Pending);
                        }
                        pin.inspect(&self.runtime, &self.supervisor, |actual| {
                            if actual != &record {
                                return Err(conflict());
                            }
                            Ok(())
                        })
                        .map_err(carrier_denied)?;
                        Ok(value)
                    })
                    .map_err(denied)
            })
            .and_then(|io_result| io_result)
        }
    }
    /// Every alias owns a REAL native held clone, not a copied tuple/JSON.
    /// PairSocket::duplicate runs after coordinator read callbacks return, so
    /// the socket itself enters fresh SAME Calling and updates the shared Rc pin.
    pub(crate) struct NativePairSocket {
        original: Rc<RefCell<Held>>,
        context: Rc<SocketContext>,
        lease: Rc<RefCell<Option<Lease>>>,
    }
    impl PairSocket for NativePairSocket {
        fn duplicate(&self) -> io::Result<Self> {
            self.context.run(|| {
                if self.lease.try_borrow().map_err(denied)?.is_none() {
                    return Err(conflict());
                }
                self.context.issue(&self.original)
            })
        }
    }
    impl ProbeDatagram for NativePairSocket {
        fn send(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let context = self.context.clone();
            context.run(|| {
                self.lease
                    .try_borrow_mut()
                    .map_err(denied)?
                    .as_mut()
                    .ok_or_else(conflict)?
                    .send(bytes)
            })
        }
        fn receive(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            let context = self.context.clone();
            context.run(|| {
                self.lease
                    .try_borrow_mut()
                    .map_err(denied)?
                    .as_mut()
                    .ok_or_else(conflict)?
                    .receive(bytes)
            })
        }
    }
    /// This root has no Drop-native effects. Until explicit final release is
    /// proven, abandonment retains ALL original owners (including partial ACKs).
    pub(crate) struct NativeCarrierPairIo<'a> {
        serial: Rc<ActorSerial>,
        // The native graph is retained as one owner; moving actor/control slots
        // must not copy its 78KiB aggregate through every factory frame.
        roots: Option<Box<NativeActorInputs<'a>>>,
        pair: Rc<OriginalPairCache>,
        socket_context: Option<Rc<SocketContext>>,
        startup: Option<Rc<RefCell<Box<dyn NativeStartup<'a> + 'a>>>>,
        full_capture_attempted: bool,
        rejected_inputs: Vec<Box<NativeActorInputs<'a>>>,
        network_intents: Vec<Rc<NativeNetworkIntentRead>>,
        guard_acks: Vec<policy::Model>,
        held: [Option<Rc<RefCell<Held>>>; 2],
        held_reads: [Option<HeldRead>; 2],
        closing: Option<Rc<NativeClosingRead>>,
        closing_network: Option<Rc<NativeClosingNetworkRead>>,
        closing_attempted: bool,
        row_owners: [Option<MemberRowOwner>; 2],
        row_pins: [Option<Rc<RowRecordReadPin>>; 2],
        row_authorities: [Option<RowAuthority>; 2],
        row_attempted: [bool; 2],
        registered: bool,
        member_generation_tickets: Vec<Rc<NativeMemberPreparationGeneration>>,
        stopped_row_generations: [Option<Rc<rows::StoppedRowGeneration>>; 2],
        row_generation_receipts: Vec<Rc<NativeRowGenerationReceipt>>,
        member_generation_originals: Vec<Rc<MemberGenerationOriginal>>,
        historical_member_rows: Vec<(MemberRowOwner, HistoricalMemberRows)>,
        member_row_captures: Vec<Rc<NativeRowGenerationCapture>>,
        member_rebind_receipts: Vec<Rc<NativeMemberRebindReceipt>>,
        lifecycle_upgrade: Rc<UpgradeRegistration>,
        terminal_cut: ActorResourceTransfer<NativeActorTerminalCut<'a>>,
        execution: Option<NativeActorExecution>,
        rebind_proof: Rc<RefCell<RebindProofSlot<NativeRebindProof>>>,
        startup_proof: Rc<RefCell<Option<Rc<NativeRebindProof>>>>,
        execution_pending: Rc<Cell<bool>>,
    }
    /// Actor destruction root, caller-retained OUTSIDE terminal T. It retains
    /// the actual actor before validation/handoff; no module/SDK effects in Drop.
    pub(crate) struct NativeActorRootHandoff<'a> {
        originals: ActorRootOriginals<
            NativeCarrierPairIo<'a>,
            NativePairJournal,
            pair::CarrierPairTerminalHandoff<NativeCarrierPairIo<'a>, NativePairJournal>,
        >,
        canonical: RefCell<ActorResourceTransfer<NativeActorCanonicalCut<'a>>>,
        zero_effect: RefCell<ActorResourceTransfer<NativeActorZeroEffectTerminalCut<'a>>>,
        zero_effect_capture: Cell<u8>,
        module_only: ActorTerminalParts<Option<NativeActorModuleOnlyOriginals<'a>>>,
        module_only_disposal: crate::windows::member_carrier_terminal_release::TerminalCallState,
        terminal_selection: RefCell<ActorResourceTransfer<NativeActorTerminalSelection<'a>>>,
        terminal_selection_state: Cell<u8>,
        release_attempted: Cell<bool>,
        unload: ActorUnloadSequence,
    }
    /// Owning selector envelope retained BEFORE original provider checks.
    /// Provisional proof is unavailable for dispatch until whole postflight;
    /// after adoption it is removed, not another hidden Runtime/module alias.
    pub(crate) struct NativeActorTerminalSelection<'a> {
        actor: std::rc::Weak<NativeActorRootHandoff<'a>>,
        provisional: ZeroEffectDisposition<NativeStartupTerminalBranch<'a>>,
        branch: RefCell<Option<NativeActorTerminalBranch<'a>>>,
    }
    pub(crate) enum NativeActorTerminalBranch<'a> {
        ZeroEffect(Rc<NativeActorZeroEffectTerminalCut<'a>>),
        NativeAttempted(Rc<NativeActorAttemptedTerminalWitness<'a>>),
    }
    /// Factual original-invocation discriminator ONLY. All actual native owners
    /// stay in original Startup/Ready/Assembly/C, never in this witness.
    pub(crate) struct NativeActorAttemptedTerminalWitness<'a> {
        actor: std::rc::Weak<NativeActorRootHandoff<'a>>,
        pair: std::rc::Weak<NativePairIntentRead>,
        record: pair::Record,
        proof: Rc<dyn NativeAttemptedTerminalProof + 'a>,
    }
    impl<'a> NativeActorAttemptedTerminalWitness<'a> {
        fn verify_original(
            &self,
            actor: &Rc<NativeActorRootHandoff<'a>>,
            original: &Rc<NativePairIntentRead>,
            record: &pair::Record,
        ) -> io::Result<()> {
            if !self
                .actor
                .upgrade()
                .is_some_and(|same| Rc::ptr_eq(&same, actor))
                || !self
                    .pair
                    .upgrade()
                    .is_some_and(|same| Rc::ptr_eq(&same, original))
                || self.record != *record
            {
                return Err(conflict());
            }
            self.proof.verify_original(original, record).map_err(denied)
        }
    }
    /// Caller-retained separate NO-native-effects disposition lane. Never a
    /// synthetic module ACK or alternative Source. Only the actual Startup
    /// provider can issue/seal/dispose its private OriginalNever proof. Reverse
    /// actor identity is Weak; proof/Startup/ownership roots stay outside C/T.
    pub(crate) struct NativeActorZeroEffectTerminalCut<'a> {
        actor: std::rc::Weak<NativeActorRootHandoff<'a>>,
        pair: RefCell<Option<Rc<NativePairIntentRead>>>,
        record: pair::Record,
        proof: ZeroEffectDisposition<dyn NativeZeroEffectTerminalProof + 'a>,
        originals: ActorTerminalParts<NativeActorZeroEffectOriginals<'a>>,
    }
    struct NativeActorZeroEffectOriginals<'a> {
        startup: Rc<RefCell<Box<dyn NativeStartup<'a> + 'a>>>,
        raw: crate::windows::member_carrier_startup::native::TerminalStartupResources<'a>,
        locals: Option<Rc<NativeActorTerminalCut<'a>>>,
        canonical: Option<Rc<NativeActorCanonicalCut<'a>>>,
    }
    struct NativeActorModuleOnlyOriginals<'a> {
        startup: Rc<RefCell<Box<dyn NativeStartup<'a> + 'a>>>,
        raw: crate::windows::member_carrier_startup::native::TerminalStartupResources<'a>,
        // Keep the actual captures rooted even if provider disposition fails.
        _locals: Rc<NativeActorTerminalCut<'a>>,
        _canonical: Rc<NativeActorCanonicalCut<'a>>,
    }
    impl NativeActorZeroEffectTerminalCut<'_> {
        /// PURE selection of an actual acknowledged outcome, not inferred from
        /// missing row/probe Options. Partial/lost postflight cannot select it.
        pub(crate) fn verify_sealed(
            &self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> io::Result<()> {
            require_terminal_record(expected)?;
            let pair = self.pair.try_borrow().map_err(denied)?;
            if !Rc::ptr_eq(pair.as_ref().ok_or_else(conflict)?, original)
                || self.record != *expected
            {
                return Err(conflict());
            }
            self.proof
                .sealed_proof()?
                .verify_original(original, expected)
                .map_err(denied)
        }
    }
    /// Original uncut canonical wrappers. Their DLL/source/Runtime ownership
    /// remains outside local T until Pauli moves actual raw resources into C.
    pub(crate) struct NativeActorCanonicalInputs<'a> {
        pub terminal_pair: Rc<NativePairIntentRead>,
        pub terminal_record: pair::Record,
        pub roots: Option<Box<NativeActorInputs<'a>>>,
        pub startup: Option<Rc<RefCell<Box<dyn NativeStartup<'a> + 'a>>>>,
    }
    pub(crate) struct NativeActorCanonicalCut<'a> {
        originals: ActorTerminalParts<NativeActorCanonicalInputs<'a>>,
    }
    impl<'a> NativeActorCanonicalCut<'a> {
        /// Actual object-safe provider dispatch. The original Box/Rc stays in
        /// THIS cut through partial/error/unwind; no temporary owning return and
        /// no absence inferred when startup was never provided.
        pub(crate) fn drain_startup_into(
            &self,
            destination: &mut crate::windows::member_carrier_startup::native::TerminalStartupResources<'a>,
        ) -> io::Result<()> {
            let originals = self.originals.try_borrow()?;
            let original = originals.startup.as_ref().ok_or_else(conflict)?;
            let mut startup = original.try_borrow_mut().map_err(denied)?;
            startup.drain_terminal_into(destination).map_err(denied)
        }
        /// # Safety
        /// Provider moves every actual canonical original into a caller-retained
        /// raw owning cut BEFORE any fallible disarm/registration/postflight.
        /// Unknown objects must not be dropped or replaced. No module/root/ACK
        /// may be moved into resource T. Merely taking Options proves nothing.
        pub(crate) unsafe fn with_originals_mut<T>(
            &self,
            retain: impl FnOnce(&mut NativeActorCanonicalInputs<'a>) -> io::Result<T>,
        ) -> io::Result<T> {
            retain(&mut *self.originals.try_borrow_mut()?)
        }
    }
    impl<'a> NativeActorRootHandoff<'a> {
        /// The ONLY finisher branch-selection entry. Caller/root retain this
        /// pending envelope before actual original provider postflight. Normal
        /// or partial native attempts never enter the no-C latch; unknown is a
        /// sticky error, not a caught exception selecting an alternative lane.
        pub(crate) fn select_terminal_branch(
            self: &Rc<Self>,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            destination: &mut Option<Rc<NativeActorTerminalSelection<'a>>>,
        ) -> io::Result<()> {
            if self.terminal_selection_state.replace(1) != 0 {
                self.terminal_selection_state.set(3);
                return Err(conflict());
            }
            let mut flight = DispositionFlight {
                state: &self.terminal_selection_state,
                done: false,
            };
            let (startup, serial) = {
                let actor = self.originals.actor.try_borrow()?;
                (
                    actor.startup.as_ref().ok_or_else(conflict)?.clone(),
                    actor.serial.clone(),
                )
            };
            serial.run(true, || {
                self.terminal_selection
                    .try_borrow_mut()
                    .map_err(denied)?
                    .capture(
                        destination,
                        || NativeActorTerminalSelection {
                            actor: Rc::downgrade(self),
                            provisional: ZeroEffectDisposition::default(),
                            branch: RefCell::new(None),
                        },
                        |selection| {
                            require_terminal_record(expected)?;
                            let (pin, record) = self.readback_terminal(&expected.scope)?;
                            if !Rc::ptr_eq(&pin, original) || record != *expected {
                                return Err(conflict());
                            }
                            selection.provisional.capture(|retain| {
                                startup
                                    .try_borrow_mut()
                                    .map_err(denied)?
                                    .select_terminal_branch(original, expected, &mut |actual| {
                                        retain(Rc::new(actual)).map_err(|_| CarrierError::Conflict)
                                    })
                                    .map_err(denied)?;
                                let (pin, record) = self.readback_terminal(&expected.scope)?;
                                if !Rc::ptr_eq(&pin, original) || record != *expected {
                                    return Err(conflict());
                                }
                                dispatch_original_terminal_branch(
                                    selection.provisional.retained_proof()?.as_ref(),
                                    |proof| {
                                        proof.verify_original(original, expected).map_err(denied)
                                    },
                                    |proof| {
                                        proof.verify_original(original, expected).map_err(denied)
                                    },
                                )
                            })
                        },
                    )
            })?;
            if self.terminal_selection_state.get() != 1 {
                return Err(conflict());
            }
            // Do NOT carry the serial or mutable Startup/selector borrow into
            // adoption. No SDK read or second issuance occurs in this step.
            let selection = self
                .terminal_selection
                .try_borrow()
                .map_err(denied)?
                .retained()?
                .clone();
            let provisional = selection.provisional.sealed_proof()?;
            let selected = dispatch_original_terminal_branch(
                &provisional,
                |proof| {
                    let mut cut = None;
                    self.capture_zero_effect_original(
                        original,
                        expected,
                        &mut cut,
                        Some(proof.clone()),
                    )?;
                    Ok(NativeActorTerminalBranch::ZeroEffect(
                        cut.ok_or_else(conflict)?,
                    ))
                },
                |proof| {
                    proof.verify_original(original, expected).map_err(denied)?;
                    Ok(NativeActorTerminalBranch::NativeAttempted(Rc::new(
                        NativeActorAttemptedTerminalWitness {
                            actor: Rc::downgrade(self),
                            pair: Rc::downgrade(original),
                            record: expected.clone(),
                            proof: proof.clone(),
                        },
                    )))
                },
            )?;
            *selection.branch.try_borrow_mut().map_err(denied)? = Some(selected);
            // Registration-only adoption: no resource destruction or native
            // permission. Remove the provisional duplicate strong proof alias.
            selection.provisional.dispose(&provisional, |_| Ok(()))?;
            selection.provisional.release_proof(&provisional)?;
            if self.terminal_selection_state.get() != 1 {
                return Err(conflict());
            }
            self.terminal_selection_state.set(2);
            flight.done = true;
            Ok(())
        }
        /// PURE finisher dispatch through a SAME completed selector. Both
        /// variants still require their independent actual owning disposition
        /// (Never or native C/G/ACK); this enum itself grants no release.
        pub(crate) fn sealed_terminal_branch(
            self: &Rc<Self>,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            candidate: &Rc<NativeActorTerminalSelection<'a>>,
        ) -> io::Result<NativeActorTerminalBranch<'a>> {
            let transfer = self.terminal_selection.try_borrow().map_err(denied)?;
            if self.terminal_selection_state.get() != 2
                || !transfer.complete
                || !Rc::ptr_eq(transfer.retained()?, candidate)
                || !candidate
                    .actor
                    .upgrade()
                    .is_some_and(|same| Rc::ptr_eq(&same, self))
            {
                return Err(conflict());
            }
            let branch = candidate.branch.try_borrow().map_err(denied)?;
            match branch.as_ref().ok_or_else(conflict)? {
                NativeActorTerminalBranch::ZeroEffect(actual) => {
                    self.sealed_zero_effect_terminal(original, expected, actual)?;
                    Ok(NativeActorTerminalBranch::ZeroEffect(actual.clone()))
                }
                NativeActorTerminalBranch::NativeAttempted(actual) => {
                    actual.verify_original(self, original, expected)?;
                    Ok(NativeActorTerminalBranch::NativeAttempted(actual.clone()))
                }
            }
        }
        /// Private owning shell disposal only AFTER the actual lane's entire
        /// resource disposition. No strong Runtime/module alias remains here.
        fn finish_terminal_selection(&self) -> io::Result<()> {
            if self.terminal_selection_state.get() == 0 {
                return Ok(()); // legacy explicit lane still requires its own actual ACK
            }
            if self.terminal_selection_state.get() != 2 {
                return Err(conflict());
            }
            let original = self
                .terminal_selection
                .try_borrow()
                .map_err(denied)?
                .retained()?
                .clone();
            original.branch.try_borrow_mut().map_err(denied)?.take();
            self.terminal_selection
                .try_borrow_mut()
                .map_err(denied)?
                .finish_release(&original)
        }
        fn require_native_terminal_selection(&self) -> io::Result<()> {
            if self.terminal_selection_state.get() == 0 {
                return Ok(()); // explicit original C/G/ACK lane, no inferred branch
            }
            if self.terminal_selection_state.get() != 2 {
                return Err(conflict());
            }
            let transfer = self.terminal_selection.try_borrow().map_err(denied)?;
            if !transfer.complete {
                return Err(conflict());
            }
            let branch = transfer.retained()?.branch.try_borrow().map_err(denied)?;
            if !matches!(
                branch.as_ref(),
                Some(NativeActorTerminalBranch::NativeAttempted(_))
            ) {
                return Err(conflict());
            }
            Ok(())
        }
        /// PURE dispatch through the SAME completed original selector and
        /// private Startup invocation. No full-capture error/field absence can
        /// select this lane, and the result grants no native disposal authority.
        pub(crate) fn attempted_terminal_layout(
            self: &Rc<Self>,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            witness: &Rc<NativeActorAttemptedTerminalWitness<'a>>,
        ) -> io::Result<crate::windows::member_carrier_startup::NativeAttemptedTerminalLayout>
        {
            self.require_native_terminal_selection()?;
            let same = {
                let transfer = self.terminal_selection.try_borrow().map_err(denied)?;
                if self.terminal_selection_state.get() != 2 || !transfer.complete {
                    return Err(conflict());
                }
                let branch = transfer.retained()?.branch.try_borrow().map_err(denied)?;
                match branch.as_ref() {
                    Some(NativeActorTerminalBranch::NativeAttempted(actual)) => {
                        Rc::ptr_eq(actual, witness)
                    }
                    _ => false,
                }
            };
            if !same {
                return Err(conflict());
            }
            witness.verify_original(self, original, expected)?;
            let layout = witness
                .proof
                .original_layout(original, expected)
                .map_err(denied)?;
            witness.verify_original(self, original, expected)?;
            Ok(layout)
        }
        /// Observe the pending lane BEFORE canonical capture drains Startup.
        /// A successful read still cannot retire the actor or publish Stopped.
        pub(crate) fn observe_pending_module_only_terminal(
            self: &Rc<Self>,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            witness: &Rc<NativeActorAttemptedTerminalWitness<'a>>,
        ) -> io::Result<()> {
            if self.attempted_terminal_layout(original, expected, witness)?
                != crate::windows::member_carrier_startup::NativeAttemptedTerminalLayout::OtherAttempted
            {
                return Err(conflict());
            }
            let (startup, serial) = {
                let actor = self.originals.actor.try_borrow().map_err(denied)?;
                (
                    actor.startup.as_ref().ok_or_else(conflict)?.clone(),
                    actor.serial.clone(),
                )
            };
            serial.run(true, || {
                witness.verify_original(self, original, expected)?;
                startup
                    .try_borrow_mut()
                    .map_err(denied)?
                    .observe_attempted_module_only_terminal(original, expected)
                    .map_err(denied)?;
                witness.verify_original(self, original, expected)
            })
        }
        /// Before any owning cut, consume ONLY the genuine original loader's
        /// once-only native release and mandatory whole postflight. A factual
        /// observation, OtherAttempted discriminator or Stopped is insufficient.
        pub(crate) fn release_module_only_terminal(
            self: &Rc<Self>,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            witness: &Rc<NativeActorAttemptedTerminalWitness<'a>>,
        ) -> io::Result<()> {
            if self.attempted_terminal_layout(original, expected, witness)?
                != crate::windows::member_carrier_startup::NativeAttemptedTerminalLayout::OtherAttempted
            { return Err(conflict()); }
            let (startup, serial) = {
                let actor = self.originals.actor.try_borrow().map_err(denied)?;
                (
                    actor.startup.as_ref().ok_or_else(conflict)?.clone(),
                    actor.serial.clone(),
                )
            };
            serial.run(true, || {
                witness.verify_original(self, original, expected)?;
                let mut source = startup.try_borrow_mut().map_err(denied)?;
                source
                    .release_module_only_terminal(original, expected)
                    .map_err(denied)?;
                source
                    .verify_module_only_release(original, expected)
                    .map_err(denied)?;
                witness.verify_original(self, original, expected)
            })
        }
        pub(crate) fn capture_module_only_locals(
            &self,
            original: &Rc<NativePairIntentRead>,
            stopped: &pair::Record,
            destination: &mut Option<Rc<NativeActorTerminalCut<'a>>>,
        ) -> io::Result<()> {
            self.originals
                .actor
                .try_borrow_mut()?
                .capture_terminal_locals_with(original, stopped, destination, true, |_| Ok(()))
        }
        /// Original completed loader + canonical owning Startup disposition,
        /// then pure actor-shell disposal. Neither Never nor full native-C G is
        /// substituted. Every unknown destination remains rooted on Err/unwind.
        pub(crate) fn dispose_module_only_terminal(
            self: &Rc<Self>,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            witness: &Rc<NativeActorAttemptedTerminalWitness<'a>>,
            local_destination: &mut Option<Rc<NativeActorTerminalCut<'a>>>,
            canonical_destination: &mut Option<Rc<NativeActorCanonicalCut<'a>>>,
        ) -> io::Result<()> {
            if self.attempted_terminal_layout(original, expected, witness)?
                != crate::windows::member_carrier_startup::NativeAttemptedTerminalLayout::OtherAttempted
                || self.release_attempted.replace(true)
            { return Err(conflict()); }
            self.module_only_disposal.run(|| {
                let local = local_destination.as_ref().ok_or_else(conflict)?.clone();
                let canonical = canonical_destination.as_ref().ok_or_else(conflict)?.clone();
                let startup = {
                    let raw = canonical.originals.try_borrow()?;
                    if raw.roots.is_some() || raw.terminal_record != *expected
                        || !Rc::ptr_eq(&raw.terminal_pair, original)
                    { return Err(conflict()); }
                    raw.startup.as_ref().ok_or_else(conflict)?.clone()
                };
                {
                    let mut retained = self.module_only.try_borrow_mut()?;
                    if retained.is_some() { return Err(conflict()); }
                    *retained = Some(NativeActorModuleOnlyOriginals {
                        startup: startup.clone(),
                        raw: crate::windows::member_carrier_startup::native::TerminalStartupResources::empty(),
                        _locals: local.clone(), _canonical: canonical.clone(),
                    }); // BEFORE drain/provider checks
                }
                {
                    let actor = self.originals.actor.try_borrow()?;
                    let captured = self.canonical.try_borrow().map_err(denied)?;
                    if !actor.terminal_cut.complete || !captured.complete
                        || !Rc::ptr_eq(actor.terminal_cut.retained()?, &local)
                        || !Rc::ptr_eq(captured.retained()?, &canonical)
                        || actor.roots.is_some() || actor.startup.is_some()
                        || actor.full_capture_attempted || actor.registered
                        || actor.closing_attempted || actor.execution.is_some()
                    { return Err(conflict()); }
                    local.require_unconstructed_originals()?; // shape only, NOT Never authority
                }
                startup.try_borrow().map_err(denied)?.verify_module_only_release(original, expected).map_err(denied)?;
                {
                    let mut retained = self.module_only.try_borrow_mut()?;
                    startup.try_borrow_mut().map_err(denied)?.drain_terminal_into(
                        &mut retained.as_mut().ok_or_else(conflict)?.raw,
                    ).map_err(denied)?;
                }
                // Last actual journal read while the original held KeyLock is
                // still alive. No native/storage query after owning disposal.
                let (pin, record) = self.readback_terminal(&expected.scope)?;
                witness.verify_original(self, &pin, &record)?;
                {
                    let mut retained = self.module_only.try_borrow_mut()?;
                    let retained = retained.as_mut().ok_or_else(conflict)?;
                    if !Rc::ptr_eq(&retained.startup, &startup) { return Err(conflict()); }
                    startup.try_borrow_mut().map_err(denied)?.dispose_module_only_terminal(
                        original, expected, &mut retained.raw,
                    ).map_err(denied)?;
                }
                startup.try_borrow().map_err(denied)?.verify_module_only_disposition(original, expected).map_err(denied)?;
                local.locals.parts.release_with(|| {
                    local.require_unconstructed_originals()?;
                    startup.try_borrow().map_err(denied)?.verify_module_only_disposition(original, expected).map_err(denied)
                })?;
                canonical.originals.try_borrow_mut()?.startup.take();
                canonical.originals.release_with(|| Ok(()))?;
                self.originals.actor.try_borrow_mut()?.terminal_cut.finish_release(&local)?;
                self.canonical.try_borrow_mut().map_err(denied)?.finish_release(&canonical)?;
                local_destination.take();
                canonical_destination.take();
                self.module_only.release_with(|| {
                    startup.try_borrow().map_err(denied)?.verify_module_only_disposition(original, expected).map_err(denied)
                })?;
                self.originals.journal.release_with(|| Ok(()))?;
                self.originals.actor.release_with(|| Ok(()))?;
                self.finish_terminal_selection()
            })
        }
        /// Call while SAME Startup is still in the original actor, before
        /// canonical capture. Caller and actor root retain the outcome FIRST.
        /// Provider decides eligibility from its private OriginalNever ledger;
        /// none of the defensive actor checks below can issue that proof.
        pub(crate) fn capture_zero_effect_terminal(
            self: &Rc<Self>,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            destination: &mut Option<Rc<NativeActorZeroEffectTerminalCut<'a>>>,
        ) -> io::Result<()> {
            self.capture_zero_effect_original(original, expected, destination, None)
        }
        fn capture_zero_effect_original(
            self: &Rc<Self>,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            destination: &mut Option<Rc<NativeActorZeroEffectTerminalCut<'a>>>,
            supplied: Option<Rc<dyn NativeZeroEffectTerminalProof + 'a>>,
        ) -> io::Result<()> {
            if self.zero_effect_capture.replace(1) != 0 {
                self.zero_effect_capture.set(3);
                return Err(conflict());
            }
            let mut flight = DispositionFlight {
                state: &self.zero_effect_capture,
                done: false,
            };
            let (startup, serial) = {
                let actor = self.originals.actor.try_borrow()?;
                (
                    actor.startup.as_ref().ok_or_else(conflict)?.clone(),
                    actor.serial.clone(),
                )
            };
            serial.run(true, || {
                self.zero_effect.try_borrow_mut().map_err(denied)?.capture(
                    destination,
                    || NativeActorZeroEffectTerminalCut {
                        actor: Rc::downgrade(self),
                        pair: RefCell::new(Some(original.clone())),
                        record: expected.clone(),
                        proof: ZeroEffectDisposition::default(),
                        originals: ActorTerminalParts::new(NativeActorZeroEffectOriginals {
                            startup: startup.clone(),
                            raw: crate::windows::member_carrier_startup::native::TerminalStartupResources::empty(),
                            locals: None,
                            canonical: None,
                        }),
                    },
                    |cut| {
                        require_terminal_record(expected)?;
                        let (pin, actual) = self.readback_terminal(&expected.scope)?;
                        if !Rc::ptr_eq(&pin, original) || actual != *expected {
                            return Err(conflict());
                        }
                        {
                            let actor = self.originals.actor.try_borrow()?;
                            // Negative checks only. Missing fields NEVER imply
                            // Never; actual private Startup issuer is mandatory.
                            if actor.full_capture_attempted || actor.registered
                                || actor.closing_attempted || actor.roots.is_some()
                                || !actor.rejected_inputs.is_empty()
                                || actor.execution.is_some()
                            {
                                return Err(conflict());
                            }
                        }
                        cut.proof.capture(|retain| {
                            if let Some(same) = supplied.as_ref() {
                                retain(same.clone())?;
                                same.verify_original(original, expected).map_err(denied)?;
                            } else {
                                startup.try_borrow_mut().map_err(denied)?
                                    .capture_zero_effect_terminal(original, expected, &mut |proof| {
                                        retain(proof).map_err(|_| CarrierError::Conflict)
                                    }).map_err(denied)?;
                            }
                            // Actual J remains rooted and is checked AFTER the
                            // provider's whole SDK/Calling postflight as well.
                            let (pin, actual) = self.readback_terminal(&expected.scope)?;
                            if !Rc::ptr_eq(&pin, original) || actual != *expected {
                                return Err(conflict());
                            }
                            cut.proof.retained_proof()?.verify_original(original, expected).map_err(denied)
                        })?;
                        cut.verify_sealed(original, expected)
                    },
                )
            })?;
            if self.zero_effect_capture.get() != 1 {
                return Err(conflict());
            }
            self.zero_effect_capture.set(2);
            flight.done = true;
            Ok(())
        }
        /// Dispatch only through the SAME acknowledged opaque outcome. No
        /// metadata/None discriminator, no fabricated ModuleReleased ACK.
        pub(crate) fn sealed_zero_effect_terminal(
            self: &Rc<Self>,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            candidate: &Rc<NativeActorZeroEffectTerminalCut<'a>>,
        ) -> io::Result<Rc<NativeActorZeroEffectTerminalCut<'a>>> {
            let transfer = self.zero_effect.try_borrow().map_err(denied)?;
            if self.zero_effect_capture.get() != 2
                || !transfer.complete
                || !Rc::ptr_eq(transfer.retained()?, candidate)
                || !candidate
                    .actor
                    .upgrade()
                    .is_some_and(|actor| Rc::ptr_eq(&actor, self))
            {
                return Err(conflict());
            }
            candidate.verify_sealed(original, expected)?;
            Ok(candidate.clone())
        }
        /// Explicit SAME I/J/Startup/local ownership disposition. No module
        /// ever existed in this lane; no unload or synthetic module ACK occurs.
        /// ALL owning destinations remain rooted on error/unwind. Actual
        /// provider must finish its fresh whole readonly bracket and disarm
        /// its original raw wrappers before any original KeyLock is dropped.
        pub(crate) fn dispose_zero_effect_terminal(
            self: &Rc<Self>,
            outcome: &Rc<NativeActorZeroEffectTerminalCut<'a>>,
            local_destination: &mut Option<Rc<NativeActorTerminalCut<'a>>>,
            canonical_destination: &mut Option<Rc<NativeActorCanonicalCut<'a>>>,
        ) -> io::Result<()> {
            if self.release_attempted.replace(true) {
                outcome.proof.invalidate_disposal();
                return Err(conflict());
            }
            let proof = outcome.proof.sealed_proof()?;
            outcome.proof.dispose(&proof, |_| {
                if self.terminal_selection_state.get() != 0 {
                    if self.terminal_selection_state.get() != 2 {
                        return Err(conflict());
                    }
                    let selected = self.terminal_selection.try_borrow().map_err(denied)?.retained()?.clone();
                    let branch = selected.branch.try_borrow().map_err(denied)?;
                    if !matches!(branch.as_ref(), Some(NativeActorTerminalBranch::ZeroEffect(same)) if Rc::ptr_eq(same, outcome)) {
                        return Err(conflict());
                    }
                }
                let local = local_destination.as_ref().ok_or_else(conflict)?.clone();
                let canonical = canonical_destination.as_ref().ok_or_else(conflict)?.clone();
                {
                    // Root all SAME inputs BEFORE drain/provider postflight.
                    let mut raw = outcome.originals.try_borrow_mut()?;
                    if raw.locals.is_some() || raw.canonical.is_some() {
                        return Err(conflict());
                    }
                    raw.locals = Some(local.clone());
                    raw.canonical = Some(canonical.clone());
                }
                let (pin, actual) = self.readback_terminal(&outcome.record.scope)?;
                self.sealed_zero_effect_terminal(&pin, &actual, outcome)?;
                {
                    let actor = self.originals.actor.try_borrow()?;
                    let captured = self.canonical.try_borrow().map_err(denied)?;
                    if !actor.terminal_cut.complete
                        || !captured.complete
                        || !Rc::ptr_eq(actor.terminal_cut.retained()?, &local)
                        || !Rc::ptr_eq(captured.retained()?, &canonical)
                        || actor.roots.is_some()
                        || actor.startup.is_some()
                        || actor.full_capture_attempted
                        || actor.registered
                        || actor.closing_attempted
                        || actor.execution.is_some()
                    {
                        return Err(conflict());
                    }
                    local.require_unconstructed_originals()?;
                }
                let startup = outcome.originals.try_borrow()?.startup.clone();
                {
                    let raw = canonical.originals.try_borrow()?;
                    if raw.roots.is_some()
                        || raw.terminal_record != actual
                        || !Rc::ptr_eq(&raw.terminal_pair, &pin)
                        || !Rc::ptr_eq(raw.startup.as_ref().ok_or_else(conflict)?, &startup)
                    {
                        return Err(conflict());
                    }
                }
                {
                    let mut raw = outcome.originals.try_borrow_mut()?;
                    // Startup Rc remains in BOTH captures even if transfer or
                    // real provider postflight fails/unwinds halfway through.
                    let mut original = startup.try_borrow_mut().map_err(denied)?;
                    original.drain_terminal_into(&mut raw.raw).map_err(denied)?;
                }
                // Last actual J read while the original held lock is still
                // alive. No storage/native query follows successful disposal.
                let (pin, actual) = self.readback_terminal(&outcome.record.scope)?;
                outcome.verify_sealed(&pin, &actual)?;
                {
                    let mut raw = outcome.originals.try_borrow_mut()?;
                    startup
                        .try_borrow_mut()
                        .map_err(denied)?
                        .dispose_zero_effect_terminal(&proof, &mut raw.raw)
                        .map_err(denied)?;
                }
                outcome.proof.verify_disposing()?;
                // The provider succeeded with actual same-original proof +
                // whole postflight. Remaining actor cuts contain NO SDK owner;
                // checks here are PURE and cannot revive forward use.
                local.locals.parts.release_with(|| {
                    local.require_unconstructed_originals()?;
                    proof.verify_original(&pin, &actual).map_err(denied)
                })?;
                canonical.originals.try_borrow_mut()?.startup.take();
                canonical.originals.release_with(|| Ok(()))?;
                {
                    let mut actor = self.originals.actor.try_borrow_mut()?;
                    actor.terminal_cut.finish_release(&local)?;
                }
                self.canonical
                    .try_borrow_mut()
                    .map_err(denied)?
                    .finish_release(&canonical)?;
                local_destination.take();
                canonical_destination.take();
                outcome.originals.release_with(|| Ok(()))?;
                // These private releases follow the mandatory actual provider
                // disposition, NEVER a copied Pair/empty Option/phase flag.
                self.originals.journal.release_with(|| Ok(()))?;
                self.originals.actor.release_with(|| Ok(()))
            })?;
            // Actual proof and actual Pair pin contain original Runtime/claim
            // aliases. No hidden receipt alias survives the explicit owning
            // disposition; post-disposal factual metadata grants nothing.
            outcome.proof.release_proof(&proof)?;
            outcome.pair.try_borrow_mut().map_err(denied)?.take();
            self.zero_effect
                .try_borrow_mut()
                .map_err(denied)?
                .finish_release(outcome)?;
            self.finish_terminal_selection()
        }
        fn verify_original_journal(&self) -> io::Result<()> {
            if self.originals.coordinator.is_none() {
                return Err(conflict());
            }
            let actor = self.originals.actor.try_borrow()?;
            self.originals.inspect_journal(|journal| {
                let journal = journal.ok_or_else(conflict)?;
                if !Rc::ptr_eq(&actor.pair.store, &journal.original) {
                    return Err(conflict());
                }
                Ok(())
            })
        }
        /// Read the SAME retained J after the coordinator's actual post-Stopped
        /// barrier, then return the opaque pin ALREADY selected by that barrier.
        /// No second actor observation, pin mint/import, SDK call or authority
        /// entry occurs here. Changed protected bytes deny rather than selecting
        /// a replacement. Failure retains I/J/history; no unload/Drop grant.
        pub(crate) fn readback_terminal(
            &self,
            scope: &SessionScope,
        ) -> io::Result<(Rc<NativePairIntentRead>, pair::Record)> {
            self.verify_original_journal()?;
            let stopped = {
                let mut original = self.originals.journal.try_borrow_mut()?;
                original
                    .as_mut()
                    .ok_or_else(conflict)?
                    .load(scope)?
                    .ok_or_else(conflict)?
            }; // end the journal borrow before accessing the original actor
            require_terminal_record(&stopped)?;
            let pin = self.retained_terminal_pair(&stopped)?;
            Ok((pin, stopped))
        }
        /// Factual accessor ONLY: returns the SAME already-selected opaque
        /// terminal Pair pin. Caller must first perform actual Stopped readback
        /// through this actor; no pin is minted/imported from `stopped` here.
        /// Closing12/Fresh/None is not promoted, and no SDK/Authority is entered.
        pub(crate) fn retained_terminal_pair(
            &self,
            stopped: &pair::Record,
        ) -> io::Result<Rc<NativePairIntentRead>> {
            require_terminal_record(stopped)?;
            let actor = self.originals.actor.try_borrow()?;
            let selected = actor.pair.selected.try_borrow().map_err(denied)?;
            let selected = selected.as_ref().ok_or_else(conflict)?;
            if selected.record != *stopped {
                return Err(conflict());
            }
            Ok(selected.pin.clone())
        }
        /// Whole actual module-unload -> ACK retention -> postflight -> actor
        /// destruction join. Invoke OUTSIDE Calling, with the SAME original
        /// loaded module retained outside T and an empty caller-owned ACK slot.
        /// Root supplies the actual supervised terminal call; this never nests
        /// it or substitutes a successful read/phase for native unload.
        pub(crate) fn unload_and_release<C, G>(
            &self,
            module: &mut crate::windows::member_carrier_module::native::LoadedWintun,
            root: &Rc<NativeActorTerminalRelease<C, G>>,
            retained_ack: &mut Option<NativeActorTerminalAck<C, G>>,
            destination: &mut Option<Rc<NativeActorTerminalCut<'a>>>,
            canonical_destination: &mut Option<Rc<NativeActorCanonicalCut<'a>>>,
        ) -> io::Result<()>
        where
            C: NativeActorCanonicalTerminalResources,
            G: NativeTerminalResourceGate<C>,
        {
            self.unload.run(
                retained_ack,
                &mut (destination, canonical_destination),
                |(destination, canonical_destination)| {
                    if self.release_attempted.get() {
                        return Err(conflict());
                    }
                    self.require_native_terminal_selection()?;
                    let actor = self.originals.actor.try_borrow()?;
                    actor.serial.fault();
                    let local = actor.terminal_cut.retained()?;
                    let graph = root.retained_resources()?;
                    let raw = self.canonical.try_borrow().map_err(denied)?;
                    let captured = raw.retained()?;
                    let originals = captured.originals.try_borrow()?;
                    if !actor.terminal_cut.complete
                        || !raw.complete
                        || !Rc::ptr_eq(destination.as_ref().ok_or_else(conflict)?, local)
                        || !Rc::ptr_eq(
                            canonical_destination.as_ref().ok_or_else(conflict)?,
                            captured,
                        )
                        || !Rc::ptr_eq(graph.actor_local_resources(), &local.locals)
                        || !local
                            .rejected_inputs
                            .try_borrow()
                            .map_err(denied)?
                            .is_empty()
                        || actor.roots.is_some()
                        || actor.startup.is_some()
                        || originals.roots.is_some()
                        || originals.startup.is_some()
                    {
                        return Err(conflict());
                    }
                    Ok(())
                },
                |retained_ack| {
                    // No actor/canonical borrow is carried into actual G/Calling.
                    // Root retains actual ACK before fallible supervised postflight.
                    root.unload_in_terminal_call(module, retained_ack)
                },
                |(destination, canonical_destination), ack| {
                    self.release(destination, canonical_destination, root, ack)
                },
            )
        }
        /// Separate original C-before-graph lane. Uses its genuine concrete
        /// pregraph T/G/root/ACK; never invents full-graph row/probe originals.
        /// Caller retains root, module and BOTH cuts before entering this call.
        pub(crate) fn unload_and_release_pregraph(
            &self,
            module: &mut crate::windows::member_carrier_module::native::LoadedWintun,
            root: &Rc<crate::windows::member_carrier_terminal_graph::native::NativePregraphTerminalRelease<'a>>,
            retained_ack: &mut Option<
                crate::windows::member_carrier_terminal_graph::native::NativePregraphTerminalAck<
                    'a,
                >,
            >,
            destination: &mut Option<Rc<NativeActorTerminalCut<'a>>>,
            canonical_destination: &mut Option<Rc<NativeActorCanonicalCut<'a>>>,
        ) -> io::Result<()> {
            self.unload.run(
                retained_ack,
                &mut (destination, canonical_destination),
                |(destination, canonical_destination)| {
                    if self.release_attempted.get() {
                        return Err(conflict());
                    }
                    self.require_native_terminal_selection()?;
                    let actor = self.originals.actor.try_borrow()?;
                    actor.serial.fault();
                    let local = actor.terminal_cut.retained()?;
                    let graph = root.retained_resources()?;
                    let raw = self.canonical.try_borrow().map_err(denied)?;
                    let captured = raw.retained()?;
                    let originals = captured.originals.try_borrow()?;
                    if self.terminal_selection_state.get() != 2
                        || !actor.terminal_cut.complete
                        || !raw.complete
                        || !Rc::ptr_eq(destination.as_ref().ok_or_else(conflict)?, local)
                        || !Rc::ptr_eq(
                            canonical_destination.as_ref().ok_or_else(conflict)?,
                            captured,
                        )
                        || !Rc::ptr_eq(graph.original_local_cut(), local)
                        || actor.roots.is_some()
                        || actor.startup.is_some()
                        || originals.roots.is_some()
                        || originals.startup.is_some()
                    {
                        return Err(conflict());
                    }
                    local.require_unconstructed_originals()
                },
                |retained_ack| root.unload_in_terminal_call(module, retained_ack),
                |(destination, canonical_destination), ack| {
                    if self.release_attempted.replace(true) {
                        return Err(conflict());
                    }
                    self.require_native_terminal_selection()?;
                    self.unload.verify_release()?;
                    let mut actor = self.originals.actor.try_borrow_mut()?;
                    actor.serial.fault();
                    let raw = self
                        .canonical
                        .try_borrow()
                        .map_err(denied)?
                        .retained()?
                        .clone();
                    if !self.canonical.try_borrow().map_err(denied)?.complete
                        || !Rc::ptr_eq(canonical_destination.as_ref().ok_or_else(conflict)?, &raw)
                        || actor.roots.is_some()
                        || actor.startup.is_some()
                    {
                        return Err(conflict());
                    }
                    {
                        let originals = raw.originals.try_borrow()?;
                        if originals.roots.is_some() || originals.startup.is_some() {
                            return Err(conflict());
                        }
                        let graph = root.retained_resources()?;
                        if !Rc::ptr_eq(
                            graph.original_local_cut(),
                            destination.as_ref().ok_or_else(conflict)?,
                        ) {
                            return Err(conflict());
                        }
                    }
                    // Existing original-cut disposer checks SAME T/ACK and
                    // successful whole terminal postflight before dropping T.
                    actor.release_terminal_locals(destination, root, ack)?;
                    raw.originals.release_with(|| Ok(()))?;
                    self.canonical
                        .try_borrow_mut()
                        .map_err(denied)?
                        .finish_release(&raw)?;
                    canonical_destination.take();
                    drop(actor);
                    // J/actor never lived in T; dispose only after actual
                    // original module/root completion, not a record/None flag.
                    self.originals.journal.release_with(|| Ok(()))?;
                    self.originals.actor.release_with(|| Ok(()))?;
                    self.finish_terminal_selection()
                },
            )
        }
        pub(crate) fn capture_locals(
            &self,
            original: &Rc<NativePairIntentRead>,
            stopped: &pair::Record,
            destination: &mut Option<Rc<NativeActorTerminalCut<'a>>>,
            handoff: impl FnOnce(&Rc<NativeActorTerminalCut<'a>>) -> io::Result<()>,
        ) -> io::Result<()> {
            self.originals
                .actor
                .try_borrow_mut()?
                .capture_terminal_locals(original, stopped, destination, handoff)
        }
        /// Ownership registration only. Exact original wrappers are rooted in
        /// BOTH shell and caller before validation/provider capture postflight.
        /// Local capture must have completed while the actual full graph existed.
        pub(crate) fn capture_canonical_inputs(
            &self,
            original: &Rc<NativePairIntentRead>,
            stopped: &pair::Record,
            destination: &mut Option<Rc<NativeActorCanonicalCut<'a>>>,
            handoff: impl FnOnce(&Rc<NativeActorCanonicalCut<'a>>) -> io::Result<()>,
        ) -> io::Result<()> {
            let mut actor = self.originals.actor.try_borrow_mut()?;
            actor.serial.fault();
            let completed_local_capture = actor.terminal_cut.complete;
            let pair = actor.pair.clone();
            self.canonical.try_borrow_mut().map_err(denied)?.capture(
                destination,
                || NativeActorCanonicalCut {
                    originals: ActorTerminalParts::new(NativeActorCanonicalInputs {
                        terminal_pair: original.clone(),
                        terminal_record: stopped.clone(),
                        roots: actor.roots.take(),
                        startup: actor.startup.take(),
                    }),
                },
                |actual| {
                    require_terminal_record(stopped)?;
                    if !completed_local_capture {
                        return Err(conflict());
                    }
                    if !Rc::ptr_eq(&pair.current(stopped)?, original) {
                        return Err(conflict());
                    }
                    handoff(actual)
                },
            )
        }
        /// Only actual typed same-root module ACK + successful whole terminal
        /// postflight can dispose T/G/local payloads and then the original actor.
        /// Canonical raw captures must already have moved all wrappers into C.
        pub(crate) fn release<C, G>(
            &self,
            destination: &mut Option<Rc<NativeActorTerminalCut<'a>>>,
            canonical_destination: &mut Option<Rc<NativeActorCanonicalCut<'a>>>,
            root: &NativeActorTerminalRelease<C, G>,
            ack: &NativeActorTerminalAck<C, G>,
        ) -> io::Result<()>
        where
            C: NativeActorCanonicalTerminalResources,
            G: NativeTerminalResourceGate<C>,
        {
            if self.release_attempted.replace(true) {
                return Err(conflict());
            }
            self.require_native_terminal_selection()?;
            self.unload.verify_release()?;
            let mut actor = self.originals.actor.try_borrow_mut()?;
            actor.serial.fault();
            let raw = self
                .canonical
                .try_borrow()
                .map_err(denied)?
                .retained()?
                .clone();
            if !self.canonical.try_borrow().map_err(denied)?.complete
                || !Rc::ptr_eq(canonical_destination.as_ref().ok_or_else(conflict)?, &raw)
                || actor.roots.is_some()
                || actor.startup.is_some()
            {
                return Err(conflict());
            }
            {
                let originals = raw.originals.try_borrow()?;
                if originals.roots.is_some() || originals.startup.is_some() {
                    return Err(conflict());
                }
            }
            let (canonical, delegate) = {
                let graph = root.retained_resources()?;
                (graph.canonical.clone(), graph.delegate.clone())
            };
            // Existing checked path authenticates SAME actor locals against T
            // and invokes actual root.release_resources(ack), never an ACK flag.
            actor.release_terminal_locals(destination, root, ack)?;
            canonical.release_with(|| Ok(()))?;
            delegate.release_with(|| Ok(()))?;
            raw.originals.release_with(|| Ok(()))?;
            self.canonical
                .try_borrow_mut()
                .map_err(denied)?
                .finish_release(&raw)?;
            canonical_destination.take();
            drop(actor);
            // Actual same-root module ACK + whole native/root release already
            // succeeded above. Only now may this SAME original J be disposed;
            // it never lived in T and no journal reconstruction was permitted.
            self.originals.journal.release_with(|| Ok(()))?;
            self.originals.actor.release_with(|| Ok(()))?;
            self.finish_terminal_selection()
        }
    }
    impl<'a> NativeCarrierPairIo<'a> {
        /// Consumes the SAME actor. Destination retains it before the first
        /// fallible callback; errors/unwinds leave the original destruction root
        /// available for factual cleanup, never forward reentry or replacement.
        pub(crate) fn capture_root_into(
            self,
            destination: &mut Option<Rc<NativeActorRootHandoff<'a>>>,
            handoff: impl FnOnce(&Rc<NativeActorRootHandoff<'a>>) -> io::Result<()>,
        ) -> io::Result<()> {
            self.capture_root_with_originals(None, None, destination, handoff)
        }
        fn capture_root_with_originals(
            self,
            journal: Option<NativePairJournal>,
            coordinator: Option<Rc<pair::CarrierPairTerminalHandoff<Self, NativePairJournal>>>,
            destination: &mut Option<Rc<NativeActorRootHandoff<'a>>>,
            handoff: impl FnOnce(&Rc<NativeActorRootHandoff<'a>>) -> io::Result<()>,
        ) -> io::Result<()> {
            self.serial.fault();
            let actual = Rc::new(NativeActorRootHandoff {
                originals: ActorRootOriginals::new(self, journal, coordinator),
                canonical: RefCell::new(ActorResourceTransfer::default()),
                zero_effect: RefCell::new(ActorResourceTransfer::default()),
                zero_effect_capture: Cell::new(0),
                module_only: ActorTerminalParts::new(None),
                module_only_disposal:
                    crate::windows::member_carrier_terminal_release::TerminalCallState::new(),
                terminal_selection: RefCell::new(ActorResourceTransfer::default()),
                terminal_selection_state: Cell::new(0),
                release_attempted: Cell::new(false),
                unload: ActorUnloadSequence::default(),
            });
            if destination.is_some() {
                return Err(conflict());
            } // local unknown owner retains the consumed actor
            *destination = Some(actual.clone());
            handoff(&actual)
        }
        /// Exact Main-owned extraction API: the caller retains the WHOLE
        /// original coordinator before its actual post-Stopped IO/J barrier and
        /// take_originals. This SAME I/J then live in the native shell BEFORE any
        /// origin/readback/canonical/G callback. The barrier selects the SAME
        /// opaque terminal Pair pin while I still belongs to the coordinator.
        /// Failure leaves both caller destinations and history rooted. Occupied
        /// destinations leave the original source intact; no factory selection.
        pub(crate) fn capture_coordinator_into(
            source: &mut Option<pair::CarrierNativePair<Self, NativePairJournal>>,
            coordinator_destination: &mut Option<
                Rc<pair::CarrierPairTerminalHandoff<Self, NativePairJournal>>,
            >,
            actor_destination: &mut Option<Rc<NativeActorRootHandoff<'a>>>,
            scope: &SessionScope,
            handoff: impl FnOnce(&Rc<NativeActorRootHandoff<'a>>) -> io::Result<()>,
        ) -> io::Result<()> {
            if actor_destination.is_some() {
                return Err(conflict());
            }
            pair::CarrierNativePair::capture_terminal_into(
                source,
                coordinator_destination,
                |coordinator| {
                    coordinator.verify_original_terminal(scope)?;
                    let (actor, journal) = coordinator.take_originals(scope)?;
                    // No fallible operation between owning extraction and
                    // retaining BOTH inputs under this caller-rooted shell.
                    actor.capture_root_with_originals(
                        Some(journal),
                        Some(coordinator.clone()),
                        actor_destination,
                        |actual| {
                            actual.verify_original_journal()?;
                            handoff(actual)
                        },
                    )
                },
            )
        }
        fn require_running_read(record: &pair::Record) -> io::Result<Slot> {
            record.validate()?;
            if record.phase != pair::Phase::Running
                || record.pending.is_some()
                || record.operation.is_some()
                || record.carrier.is_none()
                || record.network.as_ref().is_none_or(|n| n.pending.is_some())
            {
                return Err(conflict());
            }
            record.active.ok_or_else(conflict)
        }
        /// Factual Runtime getter deliberately precedes any current-epoch
        /// Runtime/Pair check after common has persisted the next Session ACK.
        fn retain_execution_root(&mut self) -> io::Result<()> {
            let r = self.roots()?;
            let root = r
                .runtime
                .native_execution_root(&r.context)
                .map_err(denied)?;
            if let Some(existing) = &self.execution {
                if !Rc::ptr_eq(&root, &existing.root) {
                    return Err(conflict());
                }
            } else {
                self.execution = Some(NativeActorExecution {
                    root,
                    sessions: None,
                    leases: Vec::new(),
                    startup_attempted: false,
                }); // Root FIRST, before original session reader / lease lookup.
            }
            let r = self.roots()?;
            let state = self.execution.as_ref().ok_or_else(conflict)?;
            if !state.root.matches_origin(&r.files) || !state.root.matches_birth_context(&r.context)
            {
                return Err(conflict());
            }
            if state.sessions.is_none() {
                let sessions = r.files.session_ack_root(&r.context.intent.scope)?;
                self.execution.as_mut().ok_or_else(conflict)?.sessions = Some(sessions);
            }
            let state = self.execution.as_mut().ok_or_else(conflict)?;
            if state.leases.is_empty() {
                state.leases.push(state.root.current_lease()?);
            }
            Ok(())
        }
        /// Explicit startup handoff, NOT called opportunistically by begin or
        /// a getter. Main must invoke at actual Running SDK-validation point,
        /// BEFORE a network callback saves n+1. No prior/equal ACK promotion.
        pub(crate) fn select_running_execution(
            &mut self,
            record: &pair::Record,
        ) -> io::Result<u64> {
            let serial = self.serial.clone();
            serial.run(false, || {
                Self::require_running_read(record)?;
                self.retain_execution_root()?;
                let state = self.execution.as_mut().ok_or_else(conflict)?;
                if std::mem::replace(&mut state.startup_attempted, true) {
                    return Err(conflict());
                }
                let root = state.root.clone();
                let old = state.leases.last().ok_or_else(conflict)?.clone();
                let session_ack = root.verify_current(&old)?.ack;
                let sdk_slot = self.startup_proof.clone();
                // in_call already serializes; here enter the actual whole native
                // Calling without recursively entering ActorSerial.
                let pin = self.current(record)?;
                let context = self.roots()?.context.clone();
                let supervisor = self.roots()?.pins.supervisor.clone();
                supervisor
                    .run(&context, || {
                        pin.inspect(
                            &self.roots().map_err(carrier_denied)?.runtime,
                            &supervisor,
                            |actual| {
                                if actual == record {
                                    Ok(())
                                } else {
                                    Err(conflict())
                                }
                            },
                        )
                        .map_err(carrier_denied)?;
                        let r = self.roots().map_err(carrier_denied)?;
                        let source = r.pins.source.clone();
                        let rows = r.rows.clone();
                        let probes = r.probe_read.clone();
                        let network = r.network_read.clone();
                        let guard = r.guard.clone();
                        let members = r.members.clone();
                        let actual = self
                            .execution_snapshot_retained_in_call(&pin, record, |observed| {
                                let mut retained = sdk_slot.try_borrow_mut().map_err(denied)?;
                                if retained.is_some() {
                                    return Err(conflict());
                                }
                                let proof = Rc::new(NativeRebindProof {
                                    root: root.clone(),
                                    lease: old.clone(),
                                    session_ack: session_ack.clone(),
                                    pair: pin.clone(),
                                    record: record.clone(),
                                    source,
                                    rows,
                                    probes,
                                    network,
                                    guard,
                                    members,
                                    observed: observed.clone(),
                                });
                                *retained = Some(proof.clone()); // before Source/controller/deadline postflight
                                Ok(())
                            })
                            .map_err(carrier_denied)?;
                        let state = self.execution.as_mut().ok_or(CarrierError::Pending)?;
                        let ack = state
                            .sessions
                            .as_ref()
                            .ok_or(CarrierError::Pending)?
                            .inspect(|f| Ok(f.ack.clone()))
                            .map_err(carrier_denied)?;
                        if !ack.same_original(&session_ack) {
                            return Err(CarrierError::Conflict);
                        }
                        let selected = root.select_running(&old, &ack).map_err(carrier_denied)?;
                        state.leases.push(selected.clone()); // before fallible native postflight
                        let facts = root.verify_current(&selected).map_err(carrier_denied)?;
                        if self
                            .execution_snapshot_in_call(&pin, record)
                            .map_err(carrier_denied)?
                            != actual
                        {
                            return Err(CarrierError::Conflict);
                        }
                        pin.inspect(
                            &self.roots().map_err(carrier_denied)?.runtime,
                            &supervisor,
                            |actual| {
                                if actual == record {
                                    Ok(())
                                } else {
                                    Err(conflict())
                                }
                            },
                        )
                        .map_err(carrier_denied)?;
                        Ok(facts.execution.value())
                    })
                    .map_err(denied)
            })
        }
        pub(crate) fn begin_rebind_execution(&mut self, record: &pair::Record) -> io::Result<u64> {
            let serial = self.serial.clone();
            serial.run(false, || {
                Self::require_running_read(record)?;
                self.execution_pending.set(true); // socket aliases cannot use n+1 as a grant
                self.rebind_proof
                    .try_borrow_mut()
                    .map_err(denied)?
                    .begin()?;
                self.retain_execution_root()?;
                let state = self.execution.as_mut().ok_or_else(conflict)?;
                let old = state.leases.last().ok_or_else(conflict)?.clone();
                let ack = state
                    .sessions
                    .as_ref()
                    .ok_or_else(conflict)?
                    .inspect(|f| Ok(f.ack.clone()))?; // detach ACK, no Root/Runtime reentry
                let selected = state.root.renew_for_rebind(&old, &ack)?;
                state.leases.push(selected.clone());
                let facts = state.root.verify_current(&selected)?;
                self.roots()?
                    .runtime
                    .verify(&self.roots()?.context)
                    .map_err(denied)?;
                let pin = self.current(record)?;
                let r = self.roots()?;
                r.pins
                    .supervisor
                    .run(&r.context, || {
                        pin.inspect(&r.runtime, &r.pins.supervisor, |actual| {
                            if actual == record {
                                Ok(())
                            } else {
                                Err(conflict())
                            }
                        })
                        .map_err(carrier_denied)?;
                        Ok(facts.execution.value())
                    })
                    .map_err(denied)
            })
        }
        pub(crate) fn seal_rebind_execution(&mut self, record: &pair::Record) -> io::Result<()> {
            let slot = self.rebind_proof.clone();
            let result = (|| {
                slot.try_borrow_mut().map_err(denied)?.seal(|slot| {
                    self.in_call(record, |this, pin| {
                        Self::require_running_read(record)?;
                        let r = this.roots()?;
                        let state = this.execution.as_ref().ok_or_else(conflict)?;
                        let lease = state.leases.last().ok_or_else(conflict)?.clone();
                        let session_ack = state.root.verify_current(&lease)?.ack;
                        let root = state.root.clone();
                        let source = r.pins.source.clone();
                        let rows = r.rows.clone();
                        let probes = r.probe_read.clone();
                        let network = r.network_read.clone();
                        let guard = r.guard.clone();
                        let members = r.members.clone();
                        this.execution_snapshot_retained_in_call(pin, record, |observed| {
                            slot.retain(Rc::new(NativeRebindProof {
                                root,
                                lease,
                                session_ack,
                                pair: pin.clone(),
                                record: record.clone(),
                                source,
                                rows,
                                probes,
                                network,
                                guard,
                                members,
                                observed: observed.clone(),
                            })) // BEFORE Source, controller AND whole Calling postflight
                        })
                        .map(|_| ())
                    })
                })
            })();
            if result.is_err() {
                self.serial.fault();
            }
            result
        }
        pub(crate) fn complete_rebind_execution(
            &mut self,
            record: &pair::Record,
        ) -> io::Result<u64> {
            let slot = self.rebind_proof.clone();
            let result = (|| {
                slot.try_borrow_mut().map_err(denied)?.complete(|proof| {
                    let serial = self.serial.clone();
                    // Renew first: n+2 has made old execution stale, so ordinary
                    // in_call/Runtime/Pair checks MUST NOT precede actual completion.
                    serial.run(false, || {
                        Self::require_running_read(record)?;
                        self.retain_execution_root()?;
                        let state = self.execution.as_mut().ok_or_else(conflict)?;
                        if record != &proof.record
                            || !Rc::ptr_eq(&state.root, &proof.root)
                            || !Arc::ptr_eq(state.leases.last().ok_or_else(conflict)?, &proof.lease)
                        {
                            return Err(conflict());
                        }
                        let ack = state
                            .sessions
                            .as_ref()
                            .ok_or_else(conflict)?
                            .inspect(|f| Ok(f.ack.clone()))?;
                        let history = state
                            .sessions
                            .as_ref()
                            .ok_or_else(conflict)?
                            .acknowledgements()?;
                        if history.len() < 2
                            || !history[history.len() - 2].same_original(&proof.session_ack)
                        {
                            return Err(conflict());
                        }
                        let selected = state.root.complete_rebind(&proof.lease, &ack)?;
                        state.leases.push(selected.clone());
                        let facts = state.root.verify_current(&selected)?;
                        let pin = self.current(record)?;
                        let r = self.roots()?;
                        if !Rc::ptr_eq(&pin, &proof.pair)
                            || !Rc::ptr_eq(&r.pins.source, &proof.source)
                            || !Rc::ptr_eq(&r.rows, &proof.rows)
                            || !Rc::ptr_eq(&r.probe_read, &proof.probes)
                            || !Rc::ptr_eq(&r.network_read, &proof.network)
                            || !Rc::ptr_eq(&r.guard, &proof.guard)
                            || !Rc::ptr_eq(&r.members, &proof.members)
                        {
                            return Err(conflict());
                        }
                        let context = r.context.clone();
                        let supervisor = r.pins.supervisor.clone();
                        supervisor
                            .run(&context, || {
                                pin.inspect(
                                    &self.roots().map_err(carrier_denied)?.runtime,
                                    &supervisor,
                                    |actual| {
                                        if actual == record {
                                            Ok(())
                                        } else {
                                            Err(conflict())
                                        }
                                    },
                                )
                                .map_err(carrier_denied)?;
                                if self
                                    .execution_snapshot_in_call(&pin, record)
                                    .map_err(carrier_denied)?
                                    != proof.observed
                                {
                                    return Err(CarrierError::Conflict);
                                }
                                pin.inspect(
                                    &self.roots().map_err(carrier_denied)?.runtime,
                                    &supervisor,
                                    |actual| {
                                        if actual == record {
                                            Ok(())
                                        } else {
                                            Err(conflict())
                                        }
                                    },
                                )
                                .map_err(carrier_denied)?;
                                Ok(facts.execution.value())
                            })
                            .map_err(denied)
                    })
                })
            })();
            if result.is_err() {
                self.serial.fault();
            }
            let value = result?;
            self.execution_pending.set(false); // only actual completed whole-call success
            Ok(value)
        }
        /// Cut only ACTOR-local originals. Pauli owns canonical Ready/Assembly/
        /// Startup cuts; their loaded module and terminal root/ACK stay outside
        /// this local T. Actor and caller retain this same envelope FIRST, even
        /// on invalid terminal input, callback failure or unwind. No retry.
        pub(crate) fn capture_terminal_locals(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            destination: &mut Option<Rc<NativeActorTerminalCut<'a>>>,
            handoff: impl FnOnce(&Rc<NativeActorTerminalCut<'a>>) -> io::Result<()>,
        ) -> io::Result<()> {
            self.capture_terminal_locals_with(original, expected, destination, false, handoff)
        }
        fn capture_terminal_locals_with(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            destination: &mut Option<Rc<NativeActorTerminalCut<'a>>>,
            completed_original_module: bool, // dispatch only: concrete provider ACK below
            handoff: impl FnOnce(&Rc<NativeActorTerminalCut<'a>>) -> io::Result<()>,
        ) -> io::Result<()> {
            let serial = self.serial.clone();
            let pair = self.pair.clone();
            let startup = self.startup.clone();
            let Self {
                roots,
                terminal_cut,
                socket_context,
                rejected_inputs,
                network_intents,
                guard_acks,
                held,
                held_reads,
                closing,
                closing_network,
                row_owners,
                row_pins,
                row_authorities,
                row_attempted,
                member_generation_tickets,
                stopped_row_generations,
                row_generation_receipts,
                member_generation_originals,
                historical_member_rows,
                member_row_captures,
                member_rebind_receipts,
                execution,
                rebind_proof,
                startup_proof,
                ..
            } = self;
            serial.run(true, || {
                terminal_cut.capture(
                    destination,
                    || NativeActorTerminalCut {
                        locals: Rc::new(NativeActorLocalResources {
                            generation_terminal: RefCell::new(OriginalGenerationTransfer::default()),
                            parts: ActorTerminalParts::new(NativeActorLocalParts {
                                canonical_probes: roots.as_ref().map(|r| r.probe_read.clone()),
                                canonical_rows: roots.as_ref().map(|r| r.rows.clone()),
                                socket_context: socket_context.take(),
                                network_intents: std::mem::take(network_intents),
                                guard_acks: std::mem::take(guard_acks),
                                held: std::mem::take(held),
                                held_reads: std::mem::take(held_reads),
                                closing: closing.take(),
                                closing_network: closing_network.take(),
                                row_owners: std::mem::take(row_owners),
                                row_pins: std::mem::take(row_pins),
                                row_authorities: std::mem::take(row_authorities),
                                row_attempted: *row_attempted,
                                member_generation_tickets: std::mem::take(
                                    member_generation_tickets,
                                ),
                                stopped_row_generations: std::mem::take(stopped_row_generations),
                                row_generation_receipts: std::mem::take(row_generation_receipts),
                                member_generation_originals: std::mem::take(
                                    member_generation_originals,
                                ),
                                historical_member_rows: std::mem::take(historical_member_rows),
                                member_row_captures: std::mem::take(member_row_captures),
                                member_rebind_receipts: std::mem::take(member_rebind_receipts),
                                rebind_proof: std::mem::replace(
                                    rebind_proof,
                                    Rc::new(RefCell::new(RebindProofSlot::default())),
                                ),
                                startup_proof: std::mem::replace(
                                    startup_proof,
                                    Rc::new(RefCell::new(None)),
                                ),
                            }),
                        }),
                        rejected_inputs: RefCell::new(std::mem::take(rejected_inputs)),
                        execution: execution.take(),
                    },
                    |cut| {
                        require_terminal_record(expected)?;
                        let current = pair.current(expected)?;
                        if !Rc::ptr_eq(&current, original) {
                            return Err(conflict());
                        }
                        if let Some(roots) = roots.as_ref() {
                            if completed_original_module { return Err(conflict()); }
                            original.verify_terminal_entry(
                                &roots.runtime,
                                &roots.context,
                                expected,
                            )?;
                        } else {
                            let mut actual = startup.as_ref().ok_or_else(conflict)?.try_borrow_mut().map_err(denied)?;
                            if completed_original_module {
                                actual.verify_module_only_release(original, expected).map_err(denied)?;
                            } else {
                                actual.verify_uncaptured_terminal(original, expected).map_err(denied)?;
                            }
                        }
                        handoff(cut)
                    },
                )
            })
        }
        /// The actual same-root module ACK/whole-call completion is the ONLY
        /// release authority. T must own the exact local Rc and every canonical
        /// rejected-input transfer. No root/ACK is stored in the local T.
        /// Call OUTSIDE native Calling, after Pauli's whole terminal unload.
        pub(crate) fn release_terminal_locals<T, G>(
            &mut self,
            destination: &mut Option<Rc<NativeActorTerminalCut<'a>>>,
            root: &NativeTerminalReleaseRoot<T, G>,
            ack: &NativeModuleReleased<T, G>,
        ) -> io::Result<()>
        where
            T: NativeActorTerminalGraph,
            G: NativeTerminalResourceGate<T>,
        {
            let serial = self.serial.clone();
            serial.run(true, || {
                let actual = self.terminal_cut.retained()?.clone();
                if !self.terminal_cut.complete
                    || !Rc::ptr_eq(destination.as_ref().ok_or_else(conflict)?, &actual)
                    || !actual
                        .rejected_inputs
                        .try_borrow()
                        .map_err(denied)?
                        .is_empty()
                {
                    return Err(conflict());
                }
                {
                    let graph = root.retained_resources()?;
                    if !Rc::ptr_eq(graph.actor_local_resources(), &actual.locals) {
                        return Err(conflict());
                    }
                }
                // Root checks actual sealed ACK identity, successful whole
                // terminal supervisor postflight and final protected Pair/runtime
                // continuity BEFORE dropping T. Its mandatory G established all
                // real closed/disarmed owner/DLL-reference prerequisites.
                // The owning payload is removed explicitly HERE, not whenever
                // an outside factual Rc happens to be dropped. All its original
                // aliases now expose released/unknown, never revived resources.
                actual
                    .locals
                    .parts
                    .release_with(|| root.release_resources(ack))?;
                self.terminal_cut.finish_release(&actual)?;
                destination.take();
                Ok(())
            })
        }
        pub(crate) fn original(input: NativeActorInputs<'a>) -> Self {
            let selected = Selected {
                pin: input.pair.clone(),
                record: input.expected.clone(),
            };
            let pair = Rc::new(OriginalPairCache {
                store: input.store.clone(),
                selected: RefCell::new(Some(selected)),
                attempted: RefCell::new(Vec::new()),
            });
            let serial = Rc::new(ActorSerial::default());
            let execution_pending = Rc::new(Cell::new(false));
            let socket_context = Rc::new(SocketContext {
                serial: serial.clone(),
                execution_pending: execution_pending.clone(),
                context: input.context.clone(),
                supervisor: input.pins.supervisor.clone(),
                runtime: input.runtime.clone(),
                pair: pair.clone(),
                probes: input.probe_state.clone(),
                attestor: input.attestor.clone(),
                guard_resources: input.guard_resources.clone(),
                issued: RefCell::new(Vec::new()),
            });
            Self {
                serial,
                roots: Some(Box::new(input)),
                pair,
                socket_context: Some(socket_context),
                startup: None,
                full_capture_attempted: true,
                rejected_inputs: Vec::new(),
                network_intents: Vec::new(),
                guard_acks: Vec::new(),
                held: [None, None],
                held_reads: [None, None],
                closing: None,
                closing_network: None,
                closing_attempted: false,
                row_owners: [None, None],
                row_pins: [None, None],
                row_authorities: [None, None],
                row_attempted: [false, false],
                registered: false,
                member_generation_tickets: Vec::new(),
                stopped_row_generations: [None, None],
                row_generation_receipts: Vec::new(),
                member_generation_originals: Vec::new(),
                historical_member_rows: Vec::new(),
                member_row_captures: Vec::new(),
                member_rebind_receipts: Vec::new(),
                lifecycle_upgrade: Rc::new(UpgradeRegistration::default()),
                terminal_cut: ActorResourceTransfer::default(),
                execution: None,
                rebind_proof: Rc::new(RefCell::new(RebindProofSlot::default())),
                startup_proof: Rc::new(RefCell::new(None)),
                execution_pending,
            }
        }
        /// Caller-rooted BEFORE cold preflight/C construction. Pair cache is
        /// created ONCE here and stays the same across actual full graph capture.
        pub(crate) fn cold(input: NativeColdActorInputs<'a>) -> Self {
            let pair = Rc::new(OriginalPairCache {
                store: input.store,
                selected: RefCell::new(None),
                attempted: RefCell::new(Vec::new()),
            });
            Self {
                serial: Rc::new(ActorSerial::default()),
                roots: None,
                pair,
                socket_context: None,
                startup: Some(Rc::new(RefCell::new(input.startup))),
                full_capture_attempted: false,
                rejected_inputs: Vec::new(),
                network_intents: Vec::new(),
                guard_acks: Vec::new(),
                held: [None, None],
                held_reads: [None, None],
                closing: None,
                closing_network: None,
                closing_attempted: false,
                row_owners: [None, None],
                row_pins: [None, None],
                row_authorities: [None, None],
                row_attempted: [false, false],
                registered: false,
                member_generation_tickets: Vec::new(),
                stopped_row_generations: [None, None],
                row_generation_receipts: Vec::new(),
                member_generation_originals: Vec::new(),
                historical_member_rows: Vec::new(),
                member_row_captures: Vec::new(),
                member_rebind_receipts: Vec::new(),
                lifecycle_upgrade: Rc::new(UpgradeRegistration::default()),
                terminal_cut: ActorResourceTransfer::default(),
                execution: None,
                rebind_proof: Rc::new(RefCell::new(RebindProofSlot::default())),
                startup_proof: Rc::new(RefCell::new(None)),
                execution_pending: Rc::new(Cell::new(false)),
            }
        }
        fn socket_context(&self) -> io::Result<Rc<SocketContext>> {
            self.socket_context.clone().ok_or_else(conflict)
        }
        fn retain_full_inputs(
            &mut self,
            input: NativeActorInputs<'a>,
        ) -> crate::member_carrier::Result<()> {
            if capture_once(
                &mut self.roots,
                &mut self.rejected_inputs,
                &mut self.full_capture_attempted,
                Box::new(input),
            )
            .is_err()
            {
                self.serial.fault();
                return Err(CarrierError::Pending);
            }
            // capture_once installed FIRST, before comparison/registration/postflight.
            let r = self.roots.as_ref().ok_or(CarrierError::Pending)?;
            self.socket_context = Some(Rc::new(SocketContext {
                serial: self.serial.clone(),
                execution_pending: self.execution_pending.clone(),
                context: r.context.clone(),
                supervisor: r.pins.supervisor.clone(),
                runtime: r.runtime.clone(),
                pair: self.pair.clone(),
                probes: r.probe_state.clone(),
                attestor: r.attestor.clone(),
                guard_resources: r.guard_resources.clone(),
                issued: RefCell::new(Vec::new()),
            }));
            let selected = self
                .pair
                .selected
                .try_borrow()
                .map_err(|_| CarrierError::Pending)?;
            let selected = selected.as_ref().ok_or(CarrierError::Pending)?;
            if !Rc::ptr_eq(&r.store, &self.pair.store)
                || !Rc::ptr_eq(&r.pair, &selected.pin)
                || r.expected != selected.record
                || !r.runtime.same_original_runtime(&r.pins.runtime)
                || r.context != r.pins.context
            {
                self.serial.fault();
                return Err(CarrierError::Conflict);
            }
            r.store
                .try_borrow_mut()
                .map_err(|_| CarrierError::Pending)?
                .verify_original_intent(&selected.pin, &selected.record)
                .map_err(|_| CarrierError::Conflict)?;
            Ok(())
        }
        pub(crate) fn preflight_fresh(&mut self, record: &pair::Record) -> io::Result<()> {
            let serial = self.serial.clone();
            serial.run(false, || {
                let pin = self.current(record)?;
                self.startup
                    .as_ref()
                    .ok_or_else(conflict)?
                    .try_borrow_mut()
                    .map_err(denied)?
                    .preflight_fresh(&pin, record)
                    .map_err(denied)
            })
        }
        pub(crate) fn prepare_member(
            &mut self,
            record: &pair::Record,
            member: &nelomai_client_tunnel::redundancy::protocol::Member,
            native: &str,
        ) -> io::Result<crate::member_owner::Record> {
            let serial = self.serial.clone();
            serial.run(false, || {
                // prepare_state passes an UNSAVED Starting proposal. Authenticate
                // current protected Fresh/Running ACK, not the proposed bytes.
                let actual = self
                    .pair
                    .store
                    .try_borrow_mut()
                    .map_err(denied)?
                    .load(&record.scope)?
                    .ok_or_else(conflict)?;
                let pin = self.current(&actual)?;
                if self.roots.is_some() {
                    self.select_guard(&pin, &actual)?;
                }
                let startup = self.startup.clone().ok_or_else(conflict)?;
                let mut startup = startup.try_borrow_mut().map_err(denied)?;
                if let Some(r) = self.roots.as_mut() {
                    let i = idx(member.slot);
                    let replacement = r.controllers[i].is_some();
                    let projection = NativeMemberGenerationProjection {
                        context: r.context.clone(),
                        runtime: r.runtime.clone(),
                        source: r.pins.source.clone(),
                        inventory: r.members.clone(),
                        rows: r.rows.clone(),
                        supervisor: r.pins.supervisor.clone(),
                        guard: r.guard.clone(),
                        row_pin: self.row_pins[i].clone(),
                        row_seal: self.stopped_row_generations[i].clone(),
                        slot: member.slot,
                    };
                    let invoked = Cell::new(false);
                    let completed = Cell::new(false);
                    let retained = &mut self.member_generation_tickets;
                    let retained_rows = &mut self.row_generation_receipts;
                    let originals = &mut self.member_generation_originals;
                    let mut after_ticket =
                        |ticket: &Rc<NativeMemberPreparationGeneration>,
                         never: &Rc<NativeNeverMemberEffects>,
                         lock: &mut KeyLock| {
                            // Retain first, even if the supplied pin/entry is denied.
                            retain_generation_once(retained, ticket, |original| {
                                if !replacement || invoked.replace(true) {
                                    return Err(conflict());
                                }
                                originals.try_reserve(1).map_err(denied_allocation)?;
                                let entry = Rc::new(MemberGenerationOriginal {
                                    ticket: original.clone(),
                                    never: never.clone(),
                                    receipt: RefCell::new(None),
                                });
                                originals.push(entry.clone()); // SAME Never before projection/postflight.
                                let receipt = projection.project(
                                    original,
                                    never,
                                    &pin,
                                    &actual,
                                    lock,
                                    retained_rows,
                                )?;
                                *entry.receipt.try_borrow_mut().map_err(denied)? = Some(receipt);
                                completed.set(true);
                                Ok(())
                            })
                            .map_err(carrier_denied)
                        };
                    let prepared = startup
                        .prepare_live_member(&pin, &actual, record, member, native, {
                            let [a, b] = &mut r.controllers;
                            let (controller, other) = if i == 0 { (a, b) } else { (b, a) };
                            NativeLiveMemberPreparation {
                                lock: &mut r.lock,
                                controller,
                                other,
                                source: &r.pins.source,
                                after_ticket: &mut after_ticket,
                            }
                        })
                        .map_err(denied)?;
                    if replacement != invoked.get() || replacement != completed.get() {
                        return Err(conflict()); // No delegate can skip actual projection.
                    }
                    Ok(prepared)
                } else {
                    startup
                        .prepare_member(&pin, record, member, native)
                        .map_err(denied)
                }
            })
        }
        fn roots(&self) -> io::Result<&NativeActorInputs<'a>> {
            self.roots.as_deref().ok_or_else(conflict)
        }
        fn roots_mut(&mut self) -> io::Result<&mut NativeActorInputs<'a>> {
            self.roots.as_deref_mut().ok_or_else(conflict)
        }
        /// Mint a current original only from the SAME coordinator store's exact
        /// durable ACK. At equal revision reuse THAT opaque Rc, never equal-clone.
        fn current(&mut self, record: &pair::Record) -> io::Result<Rc<NativePairIntentRead>> {
            self.pair.current(record)
        }
        fn select_guard(
            &self,
            pin: &Rc<NativePairIntentRead>,
            record: &pair::Record,
        ) -> io::Result<()> {
            let r = self.roots()?;
            r.attestor
                .select(pin.clone(), record.clone())
                .map_err(denied)?;
            r.guard_resources
                .select(pin.clone(), record.clone())
                .map_err(denied)?;
            Ok(())
        }
        fn upgrade_in_call(
            &mut self,
            pin: &Rc<NativePairIntentRead>,
            record: &pair::Record,
        ) -> io::Result<()> {
            let registration = self.lifecycle_upgrade.clone();
            registration.run(
                record.pending.is_some() && record.pending != Some(pair::Effect::CarrierReady),
                || {
                    let r = self.roots_mut()?;
                    let actual = r.lifecycle_gate.take().ok_or_else(conflict)?;
                    // SAFETY: NativeStartup/owning input contract requires Main's
                    // real SAME full-resource gate, not a successful stub. Root
                    // retains Box before provenance/SDK checks and hands off
                    // THAT actual bootstrap session before fallible postflight.
                    unsafe {
                        r.carrier
                            .upgrade_lifecycle_gate(actual, pin.clone(), record)
                    }
                    .map_err(denied)
                },
            )
        }
        /// The WHOLE operation is supervised; no Guard/Pair/Source borrow is
        /// held across callbacks. Native effects still invoke their mandatory G.
        fn in_call<T>(
            &mut self,
            record: &pair::Record,
            action: impl FnOnce(&mut Self, &Rc<NativePairIntentRead>) -> io::Result<T>,
        ) -> io::Result<T> {
            let serial = self.serial.clone();
            serial.run(
                matches!(record.phase, pair::Phase::Closing | pair::Phase::Stopped),
                || {
                    let pin = self.current(record)?;
                    let context = self.roots()?.context.clone();
                    let supervisor = self.roots()?.pins.supervisor.clone();
                    if record.phase == pair::Phase::Stopped {
                        require_terminal_record(record)?;
                        // Final/repeated Stop is factual cleanup only. No Closing
                        // recapture, lifecycle upgrade or forward run() can revive
                        // this original. NativeDeadline independently verifies the
                        // SAME terminal Pair CAS ACK/native keys-Stopped receipt.
                        supervisor
                            .run_terminal_cleanup(&context, &pin, record, || {
                                action(self, &pin).map_err(carrier_denied)
                            })
                            .map_err(denied)
                    } else if record.phase == pair::Phase::Closing {
                        // Journal-only transition precedes watchdog cleanup entry.
                        if self.closing.is_none() && !self.closing_attempted {
                            let r = self.roots_mut()?;
                            r.assembly
                                .begin_cleanup(&mut r.lock, &r.runtime, &pin)
                                .map_err(denied)?;
                        }
                        supervisor
                            .run_cleanup(&context, &pin, || {
                                self.capture_closing(&pin, record).map_err(carrier_denied)?;
                                action(self, &pin).map_err(carrier_denied)
                            })
                            .map_err(denied)
                    } else if let Some(effect) = record.pending {
                        supervisor
                            .run_intent(&context, &pin, record, effect, || {
                                if effect != pair::Effect::CarrierReady {
                                    // The full upgrade immediately observes actual
                                    // siblings. Select THIS opaque Pair before that
                                    // observation, not in the later effect callback.
                                    self.select_guard(&pin, record).map_err(carrier_denied)?;
                                    self.roots()
                                        .map_err(carrier_denied)?
                                        .probe_state
                                        .select(pin.clone(), record.clone())
                                        .map_err(denied)
                                        .map_err(carrier_denied)?;
                                    self.upgrade_in_call(&pin, record).map_err(carrier_denied)?;
                                }
                                action(self, &pin).map_err(carrier_denied)
                            })
                            .map_err(denied)
                    } else {
                        supervisor
                            .run(&context, || {
                                let runtime = &self.roots().map_err(carrier_denied)?.runtime;
                                pin.inspect(runtime, &supervisor, |actual| {
                                    if actual != record {
                                        return Err(conflict());
                                    }
                                    Ok(())
                                })
                                .map_err(carrier_denied)?;
                                let value = action(self, &pin).map_err(carrier_denied)?;
                                pin.inspect(
                                    &self.roots().map_err(carrier_denied)?.runtime,
                                    &supervisor,
                                    |actual| {
                                        if actual != record {
                                            return Err(conflict());
                                        }
                                        Ok(())
                                    },
                                )
                                .map_err(carrier_denied)?;
                                Ok(value)
                            })
                            .map_err(denied)
                    }
                },
            )
        }
        fn capture_closing(
            &mut self,
            pin: &Rc<NativePairIntentRead>,
            record: &pair::Record,
        ) -> io::Result<()> {
            if self.closing.is_some() {
                return Ok(());
            }
            if std::mem::replace(&mut self.closing_attempted, true) {
                return Err(conflict());
            }
            let r = self.roots.as_mut().ok_or_else(conflict)?;
            // Selection is factual and precedes first Closing registration;
            // none of these calls holds a Pair borrow across the next call.
            r.attestor
                .select(pin.clone(), record.clone())
                .map_err(denied)?;
            r.probe_state
                .select(pin.clone(), record.clone())
                .map_err(denied)?;
            let closing = &mut self.closing;
            let network = &mut self.closing_network;
            r.carrier
                .capture_closing_in_call(pin.clone(), record, |original| {
                    // Root callback strong slot FIRST, then reader/callback checks.
                    *closing = Some(original.clone());
                    *network = Some(Rc::new(
                        r.network_read
                            .closing_read(original.clone())
                            .map_err(native_denied)?,
                    ));
                    let n = network
                        .as_ref()
                        .ok_or(crate::windows::member_carrier_wintun::Error::Conflict)?;
                    r.rows.bind_closing(original.clone())?;
                    r.lifecycle.retain_closing(original)?;
                    r.lifecycle.retain_closing_network(n)?;
                    r.guard_resources
                        .retain_closing(original)
                        .map_err(native_denied)?;
                    r.attestor
                        .bind_closing(original.clone())
                        .map_err(native_denied)?;
                    r.probe_state
                        .bind_closing(original.clone(), n.clone())
                        .map_err(native_denied)?;
                    for g in r.member_gates.iter().flatten() {
                        g.try_borrow_mut()
                            .map_err(native_denied)?
                            .bind_closing(original, n)
                            .map_err(native_denied)?;
                    }
                    Ok(())
                })
                .map_err(denied)?;
            Ok(())
        }

        /// Strong owning input is already installed by `original`. Registration
        /// never returns an owner through Result, retries a partial handoff, or
        /// substitutes success for a missing full lifecycle delegate.
        pub(crate) fn register_originals(&mut self, record: &pair::Record) -> io::Result<()> {
            if std::mem::replace(&mut self.registered, true) {
                self.serial.fault();
                return Err(conflict());
            }
            self.in_call(record, |this, _| {
                let r = this.roots()?;
                if !r.runtime.same_original_runtime(&r.pins.runtime)
                    || !r.members.same_original(&r.pins.members)
                    || r.context != r.pins.context
                    || !r.network_ack.same_original(&r.network_owner.read_pin())
                    || !r
                        .network_ack
                        .matches_origin(&r.pins.source, &r.network_gate)
                    || !r.baseline.matches_source_origin(&r.pins.source)
                    || !r.baseline.matches_reader(&r.network_read)
                {
                    return Err(conflict());
                }
                r.guard_resources.retain_rows(&r.rows).map_err(denied)?;
                r.guard_resources
                    .retain_network_read(&r.network_read)
                    .map_err(denied)?;
                r.guard_resources
                    .retain_network(&r.network_gate)
                    .map_err(denied)?;
                r.guard_resources
                    .retain_probes(&r.probe_state)
                    .map_err(denied)?;
                r.lifecycle.retain_source(&r.pins.source).map_err(denied)?;
                r.lifecycle.retain_originals(&r.originals).map_err(denied)?;
                r.lifecycle.retain_members(&r.members).map_err(denied)?;
                r.lifecycle.retain_image(&r.image).map_err(denied)?;
                r.lifecycle.retain_rows(&r.rows).map_err(denied)?;
                r.lifecycle
                    .retain_row(rows::Role::Carrier, &r.pins.carrier_rows)
                    .map_err(denied)?;
                r.lifecycle.retain_guard(&r.guard).map_err(denied)?;
                r.lifecycle
                    .retain_guard_attestor_selection(&r.attestor)
                    .map_err(denied)?;
                r.lifecycle
                    .retain_guard_resource_selection(&r.guard_resources)
                    .map_err(denied)?;
                r.lifecycle.retain_probes(&r.probe_state).map_err(denied)?;
                r.lifecycle
                    .retain_probe_inventory(&r.probe_read)
                    .map_err(denied)?;
                r.lifecycle
                    .retain_network(&r.network_gate)
                    .map_err(denied)?;
                r.lifecycle
                    .retain_network_read(&r.network_read)
                    .map_err(denied)?;
                r.lifecycle
                    .retain_network_baseline(&r.baseline)
                    .map_err(denied)?;
                r.probe_state
                    .register_inventory(r.probe_read.pin())
                    .map_err(denied)?;
                r.network_gate.retain_owner_ack(r.network_ack.pin())?;
                for g in r.member_gates.iter().flatten() {
                    g.try_borrow_mut()
                        .map_err(denied)?
                        .bind_network(&r.network_ack, &r.network_gate)
                        .map_err(denied)?;
                }
                Ok(())
            })
        }

        pub(crate) fn create_carrier_ready(
            &mut self,
            record: &pair::Record,
        ) -> io::Result<InterfaceProof> {
            // Ready/Assembly own their whole SAME Calling scope. Never nest a
            // supervisor around their effect entry or return a borrowed owner.
            let serial = self.serial.clone();
            serial.run(false, || {
                let pin = self.current(record)?;
                if let Some(startup) = self.startup.clone() {
                    return startup
                        .try_borrow_mut()
                        .map_err(denied)?
                        .create_ready(&pin, record)
                        .map_err(denied);
                }
                let r = self.roots_mut()?;
                pin.verify_forward_entry(
                    &r.runtime,
                    &r.context,
                    record,
                    pair::Effect::CarrierReady,
                )?;
                r.carrier
                    .create_ready(&mut r.assembly, &mut r.lock, &r.files)
                    .map_err(denied)
            })
        }

        /// No constructor: the SAME Startup/Assembly/loader performs a full
        /// independently authenticated read. Missing actor slots alone never
        /// authorize a successful no-op, SDK call or terminal disposition.
        fn read_no_constructor_cleanup(
            &mut self,
            record: &pair::Record,
        ) -> io::Result<policy::Snapshot> {
            let serial = self.serial.clone();
            serial.run(true, || {
                if self.roots.is_some()
                    || self.full_capture_attempted
                    || !self.rejected_inputs.is_empty()
                    || self.registered
                    || record.phase != pair::Phase::Closing
                    || record.carrier.is_some()
                    || !self.network_intents.is_empty()
                    || !self.guard_acks.is_empty()
                    || self.held.iter().any(Option::is_some)
                    || self.held_reads.iter().any(Option::is_some)
                    || self.row_attempted.iter().any(|attempted| *attempted)
                    || self.row_owners.iter().any(Option::is_some)
                    || self.row_pins.iter().any(Option::is_some)
                    || self.row_authorities.iter().any(Option::is_some)
                    || !self.historical_member_rows.is_empty()
                    || !self.member_generation_originals.is_empty()
                {
                    return Err(conflict());
                }
                let pin = self.current(record)?;
                let actual = self
                    .startup
                    .as_ref()
                    .ok_or_else(conflict)?
                    .try_borrow_mut()
                    .map_err(denied)?
                    .read_bootstrap_no_constructor_cleanup(&pin, record)
                    .map_err(denied)?;
                compare_no_constructor_cleanup_snapshot(record, &actual)?;
                Ok(actual)
            })
        }

        fn read_pregraph_closing_cleanup(
            &mut self,
            record: &pair::Record,
        ) -> io::Result<policy::Snapshot> {
            let serial = self.serial.clone();
            serial.run(true, || {
                require_pregraph_closing_read(record)?;
                if self.roots.is_some()
                    || self.full_capture_attempted
                    || !self.rejected_inputs.is_empty()
                    || self.registered
                    || record.carrier.is_none()
                    || !self.network_intents.is_empty()
                    || !self.guard_acks.is_empty()
                    || self.held.iter().any(Option::is_some)
                    || self.held_reads.iter().any(Option::is_some)
                    || self.row_attempted.iter().any(|attempted| *attempted)
                    || self.row_owners.iter().any(Option::is_some)
                    || self.row_pins.iter().any(Option::is_some)
                    || self.row_authorities.iter().any(Option::is_some)
                    || !self.historical_member_rows.is_empty()
                    || !self.member_generation_originals.is_empty()
                {
                    return Err(conflict());
                }
                let pin = self.current(record)?;
                let actual = self
                    .startup
                    .as_ref()
                    .ok_or_else(conflict)?
                    .try_borrow_mut()
                    .map_err(denied)?
                    .read_pregraph_closing_cleanup(&pin, record)
                    .map_err(denied)?;
                if actual != record.guard.expected {
                    return Err(conflict());
                }
                Ok(actual)
            })
        }

        pub(crate) fn attest_effect(
            &mut self,
            record: &pair::Record,
            effect: pair::Effect,
        ) -> io::Result<()> {
            if let Err(error) = require_attestation(record, effect) {
                self.serial.fault();
                return Err(error);
            }
            if effect == pair::Effect::FullEmpty {
                return self.verify_full_empty(record);
            }
            if self.roots.is_none() {
                if record.phase == pair::Phase::Closing && record.carrier.is_none() {
                    return self.read_no_constructor_cleanup(record).map(|_| ());
                }
                if record.phase == pair::Phase::Closing && record.stop_stage <= 8 {
                    return self.read_pregraph_closing_cleanup(record).map(|_| ());
                }
                if matches!(record.stop_stage, 9 | 10) {
                    return self.verify_native_empty(record);
                }
                if record.phase == pair::Phase::Closing && record.stop_stage == 11 {
                    let serial = self.serial.clone();
                    return serial.run(true, || {
                        require_effect(record, pair::Effect::RestoreKeys)?;
                        let pin = self.current(record)?;
                        let actual = self
                            .startup
                            .as_ref()
                            .ok_or_else(conflict)?
                            .try_borrow_mut()
                            .map_err(denied)?
                            .read_pregraph_key_restore(&pin, record)
                            .map_err(denied)?;
                        if actual != record.guard.expected {
                            return Err(conflict());
                        }
                        Ok(())
                    });
                }
                if record.phase == pair::Phase::Stopped {
                    return self.verify_full_empty(record);
                }
                let serial = self.serial.clone();
                return serial.run(
                    matches!(record.phase, pair::Phase::Closing | pair::Phase::Stopped),
                    || {
                        let pin = self.current(record)?;
                        let mut startup = self
                            .startup
                            .as_ref()
                            .ok_or_else(conflict)?
                            .try_borrow_mut()
                            .map_err(denied)?;
                        startup
                            .attest_bootstrap(&pin, record, effect)
                            .map_err(denied)
                    },
                );
            }
            // This entry performs the first real pending-edge upgrade BEFORE
            // Assembly's member key precreation. Later calls still authenticate
            // THIS Pair/Calling and sample originals, not cached registration.
            self.in_call(record, |this, pin| {
                this.select_guard(pin, record)?;
                let r = this.roots()?;
                r.probe_state
                    .select(pin.clone(), record.clone())
                    .map_err(denied)?;
                r.runtime.verify(&r.context).map_err(denied)?;
                r.runtime.verify_source(&r.pins.wintun).map_err(denied)?;
                r.runtime
                    .verify_same_session_files(&r.context, &r.files)
                    .map_err(denied)?;
                r.image.verify_runtime(&r.runtime).map_err(denied)?;
                r.members
                    .matches_original_runtime_image(&r.runtime, &r.image)
                    .map_err(denied)?;
                if !r.originals.same_original_registry(&r.pins.originals)
                    || !r
                        .rows
                        .matches_row_original(rows::Role::Carrier, &r.pins.carrier_rows)
                    || !r
                        .network_ack
                        .matches_origin(&r.pins.source, &r.network_gate)
                    || !r.baseline.matches_source_origin(&r.pins.source)
                    || !r.baseline.matches_reader(&r.network_read)
                {
                    return Err(conflict());
                }
                r.probe_read
                    .matches_caps(&r.pins.source, &r.guard, &r.probe_state.gate())
                    .map_err(denied)?;
                let retired = if record.phase == pair::Phase::Closing && record.stop_stage >= 8 {
                    retired_at_boundary(record.stop_stage, r.carrier.retired_pin())?
                } else {
                    None
                };
                if let Some(retired) = retired {
                    if matches!(record.stop_stage, 9 | 10) {
                        return Self::native_empty_graph_in_call(r, record);
                    }
                    if record.stop_stage == 11 {
                        require_effect(record, pair::Effect::RestoreKeys)?;
                        let raw = r
                            .runtime
                            .record(
                                &r.context,
                                crate::windows::member_session::RecordKind::NativeCarrierReceipts,
                            )
                            .map_err(denied)?;
                        let native = crate::member_carrier_native_ownership::Record::decode(&raw)
                            .map_err(denied)?;
                        if crate::windows::member_carrier_ready::key_restore_read_is_terminal(
                            &r.context, record, &native,
                        )
                        .map_err(denied)?
                        {
                            return retired
                                .inspect_terminal_bindings_and_history(|bindings, history| {
                                    r.lifecycle.verify_restored_keys_in_retired_bracket(
                                        pin, record, &retired, bindings, history,
                                    )
                                })
                                .map_err(denied);
                        }
                        // Before effect: original Cleanup SDK requires Disabled.
                        // No caught denial/fallback to terminal or old Pair frame.
                    }
                    retired
                        .inspect_bindings(|bindings| {
                            let before = r
                                .guard
                                .try_borrow_mut()
                                .map_err(native_denied)?
                                .snapshot_in_retired_bracket(&retired, bindings)
                                .map_err(native_denied)?;
                            r.rows
                                .inspect_retired_in_bracket(&retired, bindings, |_| Ok(()))?;
                            // Every actual canonical open ACK must have its actual
                            // clone/base close receipts. No missing-lookup success.
                            r.probe_read.inspect_retired().map_err(native_denied)?;
                            if r.guard
                                .try_borrow_mut()
                                .map_err(native_denied)?
                                .snapshot_in_retired_bracket(&retired, bindings)
                                .map_err(native_denied)?
                                != before
                            {
                                return Err(native_denied(()));
                            }
                            Ok(())
                        })
                        .map_err(denied)?;
                } else {
                    let sample = |window: &NativeBindingsWindow<'_>| {
                        Self::attest_window(r, window).map_err(native_denied)
                    };
                    if record.phase == pair::Phase::Closing {
                        this.closing
                            .as_ref()
                            .ok_or_else(conflict)?
                            .inspect_window(sample)
                            .map_err(denied)?;
                    } else {
                        r.pins.source.inspect_window(sample).map_err(denied)?;
                    }
                }
                r.runtime.verify(&r.context).map_err(denied)
            })
        }

        pub(crate) fn verify_native_empty(&mut self, record: &pair::Record) -> io::Result<()> {
            if let Err(error) = require_native_empty_frame(record) {
                self.serial.fault();
                return Err(error);
            }
            if self.roots.is_none() {
                let serial = self.serial.clone();
                return native_empty_call(&serial, record, || {
                    let pin = self.current(record)?;
                    self.startup
                        .as_ref()
                        .ok_or_else(conflict)?
                        .try_borrow_mut()
                        .map_err(denied)?
                        .read_bootstrap_native_empty(&pin, record)
                        .map(|_| ())
                        .map_err(denied)
                });
            }
            self.in_call(record, |this, pin| {
                this.select_guard(pin, record)?;
                let r = this.roots()?;
                r.probe_state
                    .select(pin.clone(), record.clone())
                    .map_err(denied)?;
                Self::native_empty_graph_in_call(r, record)
            })
        }
        /// Existing actual Pair/Calling, SAME Retired full mixed SDK/history
        /// bracket. Sibling Guard, rows, probes and network ACK reads only; no
        /// Source/Authority reentry or successful cleanup inferred from JSON.
        fn native_empty_graph_in_call(
            r: &NativeActorInputs<'_>,
            record: &pair::Record,
        ) -> io::Result<()> {
            require_native_empty_frame(record)?;
            let original = r.carrier.retired_pin().map_err(denied)?;
            if !original.matches_source_origin(&r.pins.source)
                || !r.baseline.matches_reader(&r.network_read)
                || !r
                    .network_ack
                    .matches_origin(&r.pins.source, &r.network_gate)
            {
                return Err(conflict());
            }
            original
                .inspect_bindings(|bindings| {
                    let sample = || {
                        let guard = r
                            .guard
                            .try_borrow_mut()
                            .map_err(native_denied)?
                            .snapshot_in_retired_bracket(&original, bindings)
                            .map_err(native_denied)?;
                        if guard != record.guard.expected
                            || guard.scope != record.scope
                            || guard
                                .filters
                                .iter()
                                .any(|filter| filter.action == policy::Action::Permit)
                        {
                            return Err(native_denied(()));
                        }
                        let rows =
                            r.rows
                                .inspect_retired_in_bracket(&original, bindings, |facts| {
                                    if facts.rows.iter().flatten().any(|row| {
                                        row.observed.is_some()
                                            || row.acknowledged.phase != rows::Phase::Stopped
                                            || row.acknowledged.pending.is_some()
                                            || row.acknowledged.current.address.is_some()
                                            || row.acknowledged.current.interface.policy
                                                != row.acknowledged.baseline.interface.policy
                                    }) {
                                        return Err(native_denied(()));
                                    }
                                    Ok(facts.clone())
                                })?;
                        r.probe_read.inspect_retired().map_err(native_denied)?;
                        r.network_read
                            .verify_native_empty_in_retired_bracket(
                                record,
                                &original,
                                bindings,
                                &r.baseline,
                                &r.network_gate,
                            )
                            .map_err(native_denied)?;
                        Ok::<_, crate::windows::member_carrier_wintun::Error>((guard, rows))
                    };
                    let before = sample()?;
                    if sample()? != before {
                        return Err(native_denied(()));
                    }
                    Ok(())
                })
                .map_err(denied)?;
            r.runtime.verify(&r.context).map_err(denied)
        }

        /// Read ONLY in the exact original Closing12 or acknowledged Stopped
        /// Calling channel. The independent mandatory full G remains required
        /// even when all comparison data looks empty. No late native effects,
        /// Source reconstruction, row Authority reentry or invented release ACK.
        pub(crate) fn verify_full_empty(&mut self, record: &pair::Record) -> io::Result<()> {
            if let Err(error) = require_full_empty_frame(record) {
                self.serial.fault();
                return Err(error);
            }
            if self.roots.is_none() {
                let serial = self.serial.clone();
                return serial.run(true, || {
                    let pin = self.current(record)?;
                    let mut startup = self
                        .startup
                        .as_ref()
                        .ok_or_else(conflict)?
                        .try_borrow_mut()
                        .map_err(denied)?;
                    let actual = if record.phase == pair::Phase::Stopped {
                        startup.read_bootstrap_no_constructor_terminal(&pin, record)
                    } else {
                        startup.read_bootstrap_full_empty(&pin, record)
                    }
                    .map_err(denied)?;
                    compare_full_empty_snapshot(record, &actual)
                });
            }
            self.in_call(record, |this, pin| {
                this.select_guard(pin, record)?;
                let r = this.roots()?;
                r.probe_state
                    .select(pin.clone(), record.clone())
                    .map_err(denied)?;
                let original = r.carrier.retired_pin().map_err(denied)?;
                if !original.matches_source_origin(&r.pins.source)
                    || !r
                        .rows
                        .matches_row_original(rows::Role::Carrier, &r.pins.carrier_rows)
                    || !r.baseline.matches_reader(&r.network_read)
                    || !r
                        .network_ack
                        .matches_origin(&r.pins.source, &r.network_gate)
                {
                    return Err(conflict());
                }
                // Local roots MUST still point to their actual RowOwners, even
                // after storage cleanup or failed generation postflight. No
                // stopped metadata/old equal pin can replace that ownership.
                for i in 0..2 {
                    match (&this.row_owners[i], &this.row_pins[i]) {
                        (Some(owner), Some(pin))
                            if pin.same_original(&owner.record_read_pin().map_err(denied)?) => {}
                        (None, None) => {} // not absence: mandatory G below proves originals
                        _ => return Err(conflict()),
                    }
                }
                for (owner, old) in &this.historical_member_rows {
                    if !old
                        .pin
                        .same_original(&owner.record_read_pin().map_err(denied)?)
                    {
                        return Err(conflict());
                    }
                    old.seal
                        .inspect_original(&old.pin, |_| Ok(()))
                        .map_err(denied)?;
                }
                // Keys are already actually Stopped/restored at this stage.
                // Ordinary Closing Retired.inspect is deliberately ineligible.
                original
                    .inspect_terminal_bindings_and_history(|bindings, history| {
                        let sample = || {
                            r.lifecycle.verify_full_empty_in_retired_bracket(
                                pin, record, &original, bindings, history,
                            )?;
                            let guard = r
                                .guard
                                .try_borrow_mut()
                                .map_err(native_denied)?
                                .snapshot_in_retired_bracket(&original, bindings)
                                .map_err(native_denied)?;
                            compare_full_empty_snapshot(record, &guard).map_err(native_denied)?;
                            let facts = r.rows.inspect_retired_in_bracket(
                                &original,
                                bindings,
                                |facts| {
                                    if facts.rows.iter().flatten().any(|row| {
                                        row.observed.is_some()
                                            || row.acknowledged.phase != rows::Phase::Stopped
                                            || row.acknowledged.pending.is_some()
                                            || row.acknowledged.current.address.is_some()
                                            || row.acknowledged.current.interface.policy
                                                != row.acknowledged.baseline.interface.policy
                                    }) {
                                        return Err(native_denied(()));
                                    }
                                    Ok(facts.clone())
                                },
                            )?;
                            r.probe_read.inspect_retired().map_err(native_denied)?;
                            for i in 0..2 {
                                match (&this.held[i], &this.held_reads[i]) {
                                    (None, None) => {} // canonical inventory checks unpublished originals
                                    (Some(owner), Some(read)) => {
                                        let actual =
                                            owner.try_borrow().map_err(native_denied)?.read_pin();
                                        if !actual.same_original(read) {
                                            return Err(native_denied(()));
                                        }
                                        r.probe_read
                                            .verify_member_slot(
                                                if i == 0 { Slot::A } else { Slot::B },
                                                read,
                                            )
                                            .map_err(native_denied)?;
                                        read.retired()
                                            .map_err(native_denied)?
                                            .verify_same_original(&actual)
                                            .map_err(native_denied)?;
                                    }
                                    _ => return Err(native_denied(())),
                                }
                            }
                            if let Some(context) = &this.socket_context {
                                if !Rc::ptr_eq(&context.serial, &this.serial)
                                    || !context.serial.revoked.get()
                                {
                                    return Err(native_denied(()));
                                }
                                for issued in
                                    context.issued.try_borrow().map_err(native_denied)?.iter()
                                {
                                    if issued.lease.try_borrow().map_err(native_denied)?.is_some() {
                                        return Err(native_denied(()));
                                    }
                                    let actual = issued
                                        .original
                                        .try_borrow()
                                        .map_err(native_denied)?
                                        .read_pin();
                                    r.probe_read.verify_member(&actual).map_err(native_denied)?;
                                    actual
                                        .retired()
                                        .map_err(native_denied)?
                                        .verify_same_original(&actual)
                                        .map_err(native_denied)?;
                                }
                            }
                            Ok::<_, crate::windows::member_carrier_wintun::Error>((guard, facts))
                        };
                        let before = sample()?;
                        if sample()? != before {
                            return Err(native_denied(()));
                        }
                        Ok(())
                    })
                    .map_err(denied)?;
                r.runtime.verify(&r.context).map_err(denied)
            })
        }

        /// Only independently original factual samples. No Source adoption,
        /// journal write, nested Authority/RowOwner or mutation grant here.
        /// Each subsequent native effect still calls its mandatory concrete G.
        fn attest_window(
            r: &NativeActorInputs<'_>,
            window: &NativeBindingsWindow<'_>,
        ) -> io::Result<()> {
            let before_guard = r
                .guard
                .try_borrow_mut()
                .map_err(denied)?
                .snapshot_in_window(window)
                .map_err(denied)?;
            let before_rows = r
                .rows
                .inspect_in_window(window, |facts| Ok(facts.clone()))
                .map_err(denied)?;
            let before_network = r.network_read.inspect_in_window(window, |facts| {
                Ok(network_sample(
                    &facts.routes,
                    &facts.dns,
                    facts.protected_record.as_deref(),
                ))
            })?;
            let before_ack = r.network_ack.acknowledgements()?;
            let before_dns = r.network_ack.dns_exchange_history()?;
            if r.guard
                .try_borrow_mut()
                .map_err(denied)?
                .snapshot_in_window(window)
                .map_err(denied)?
                != before_guard
                || r.rows
                    .inspect_in_window(window, |facts| Ok(facts.clone()))
                    .map_err(denied)?
                    != before_rows
                || r.network_read.inspect_in_window(window, |facts| {
                    Ok(network_sample(
                        &facts.routes,
                        &facts.dns,
                        facts.protected_record.as_deref(),
                    ))
                })? != before_network
                || r.network_ack.acknowledgements()? != before_ack
                || r.network_ack.dns_exchange_history()? != before_dns
            {
                return Err(conflict());
            }
            Ok(())
        }

        /// Full original SDK observation under caller's EXISTING Calling. No
        /// nested actor/deadline, Source adoption, Authority lock or journal
        /// write. The row sampler joins actual same-owner ACKs/protected bytes;
        /// native controller reads prove actual full process + NIC originals.
        fn execution_snapshot_in_call(
            &mut self,
            pin: &Rc<NativePairIntentRead>,
            record: &pair::Record,
        ) -> io::Result<NativeRebindSnapshot> {
            self.execution_snapshot_retained_in_call(pin, record, |_| Ok(()))
        }
        fn execution_snapshot_retained_in_call(
            &mut self,
            pin: &Rc<NativePairIntentRead>,
            record: &pair::Record,
            retain: impl FnOnce(&NativeRebindSnapshot) -> io::Result<()>,
        ) -> io::Result<NativeRebindSnapshot> {
            let active = Self::require_running_read(record)?;
            self.select_guard(pin, record)?;
            let held = self
                .held_reads
                .each_ref()
                .map(|read| read.as_ref().map(HeldRead::pin));
            let r = self.roots_mut()?;
            r.probe_state
                .select(pin.clone(), record.clone())
                .map_err(denied)?;
            let mut members = [None, None];
            for slot in [Slot::A, Slot::B] {
                let i = idx(slot);
                if let Some(member) = &record.members[i] {
                    r.member_gates[i]
                        .as_ref()
                        .ok_or_else(conflict)?
                        .try_borrow_mut()
                        .map_err(denied)?
                        .select_pair(pin.clone())
                        .map_err(denied)?;
                    let original = r.controllers[i]
                        .as_mut()
                        .ok_or_else(conflict)?
                        .observe_original(pin, record, &mut r.lock)
                        .map_err(denied)?;
                    if original.0 != member.owner.intent || Some(original.1) != member.owner.proof {
                        return Err(conflict());
                    }
                    members[i] = Some(original);
                }
            }
            let network = record.network.as_ref().ok_or_else(conflict)?;
            let observed = r
                .pins
                .source
                .inspect_window(|window| {
                    let bindings = window.bindings();
                    if bindings.scope != record.scope
                        || bindings.carrier.as_ref().map(|c| c.identity.proof) != record.carrier
                    {
                        return Err(native_denied(()));
                    }
                    for i in 0..2 {
                        let slot = [
                            nelomai_contracts::dispatcher::TunnelSlot::A,
                            nelomai_contracts::dispatcher::TunnelSlot::B,
                        ][i];
                        let closed = window
                            .closed_member(slot)
                            .map(|original| {
                                // Factual validation of SAME window's already
                                // original-receipt/full-absence-authenticated history.
                                // Never query this historical NIC as a live provider.
                                original
                                    .comparison_provider(&r.context)
                                    .map_err(native_denied)?;
                                if original.intent.scope != record.scope
                                    || original.intent.slot != slot
                                {
                                    return Err(native_denied(()));
                                }
                                Ok(original.proof.interface)
                            })
                            .transpose()?;
                        compare_execution_member_binding(
                            record.members[i]
                                .as_ref()
                                .and_then(|m| m.owner.proof)
                                .map(|p| p.interface),
                            bindings.egress[i].as_ref().map(|m| m.proof),
                            closed,
                        )
                        .map_err(native_denied)?;
                    }
                    let guard = r
                        .guard
                        .try_borrow_mut()
                        .map_err(native_denied)?
                        .snapshot_in_window(window)
                        .map_err(native_denied)?;
                    if guard != record.guard.expected {
                        return Err(native_denied(()));
                    }
                    let fresh = Self::network_plan_in_window(
                        r,
                        record,
                        active,
                        window,
                        NetworkPlanUse::ReadOnly,
                    )
                    .map_err(native_denied)?;
                    if fresh.snapshot != network.current {
                        return Err(native_denied(()));
                    }
                    let ack = r.network_ack.acknowledgements().map_err(native_denied)?;
                    let dns = r
                        .network_ack
                        .dns_exchange_history()
                        .map_err(native_denied)?;
                    let native_network = r
                        .network_read
                        .inspect_in_window(window, |facts| {
                            if facts.routes.pending.is_some() {
                                return Err(conflict());
                            }
                            let sampled = facts
                                .routes
                                .current
                                .iter()
                                .map(|r| r.actual.clone().ok_or_else(conflict))
                                .collect::<io::Result<Vec<_>>>()?;
                            compare_network_ack(
                                &network.current,
                                &sampled,
                                &facts.dns,
                                r.baseline.snapshot(),
                                &ack.0,
                                &dns,
                            )?;
                            Ok(network_sample(
                                &facts.routes,
                                &facts.dns,
                                facts.protected_record.as_deref(),
                            ))
                        })
                        .map_err(native_denied)?;
                    let rows = r
                        .rows
                        .inspect_in_window(window, |facts| Ok(facts.clone()))?;
                    let canonical = r.probe_read.originals_by_slot().map_err(native_denied)?;
                    let mut probes = [None, None];
                    for slot in [Slot::A, Slot::B] {
                        let i = idx(slot);
                        let expected = record.guard.members[i]
                            .as_ref()
                            .map_or(&[][..], |m| m.probes.as_slice());
                        match execution_probe_read(
                            expected.len(),
                            held[i].is_some(),
                            canonical[i].is_some(),
                        )
                        .map_err(native_denied)?
                        {
                            ExecutionProbeRead::Live => {
                                let actual = held[i].as_ref().ok_or_else(|| native_denied(()))?;
                                let original =
                                    canonical[i].as_ref().ok_or_else(|| native_denied(()))?;
                                if !actual.same_original(original) {
                                    return Err(native_denied(()));
                                }
                                r.probe_read
                                    .verify_member_slot(slot, actual)
                                    .map_err(native_denied)?;
                                let tuple = actual
                                    .inspect_tuple_in_window(window)
                                    .map_err(native_denied)?;
                                if Some(&tuple) != expected.first() {
                                    return Err(native_denied(()));
                                }
                                probes[i] = Some(tuple);
                            }
                            ExecutionProbeRead::Retired => {
                                let actual = held[i].as_ref().ok_or_else(|| native_denied(()))?;
                                let original =
                                    canonical[i].as_ref().ok_or_else(|| native_denied(()))?;
                                r.probe_read
                                    .verify_member_slot(slot, actual)
                                    .map_err(native_denied)?;
                                actual
                                    .retired()
                                    .map_err(native_denied)?
                                    .verify_same_original(original)
                                    .map_err(native_denied)?;
                                // No historical port/NIC SDK lookup and no
                                // missing tuple/Option fabricated close receipt.
                            }
                            ExecutionProbeRead::Uncaptured => {}
                        }
                    }
                    // Same actual window spans these independent complete samples.
                    Self::attest_window(r, window).map_err(native_denied)?;
                    if r.guard
                        .try_borrow_mut()
                        .map_err(native_denied)?
                        .snapshot_in_window(window)
                        .map_err(native_denied)?
                        != guard
                        || r.rows
                            .inspect_in_window(window, |facts| Ok(facts.clone()))?
                            != rows
                        || r.network_read
                            .inspect_in_window(window, |facts| {
                                Ok(network_sample(
                                    &facts.routes,
                                    &facts.dns,
                                    facts.protected_record.as_deref(),
                                ))
                            })
                            .map_err(native_denied)?
                            != native_network
                        || r.network_ack.acknowledgements().map_err(native_denied)? != ack
                        || r.network_ack
                            .dns_exchange_history()
                            .map_err(native_denied)?
                            != dns
                    {
                        return Err(native_denied(()));
                    }
                    for i in 0..2 {
                        if let Some(actual) = &held[i] {
                            if let Some(expected) = &probes[i] {
                                if actual
                                    .inspect_tuple_in_window(window)
                                    .map_err(native_denied)?
                                    != *expected
                                {
                                    return Err(native_denied(()));
                                }
                            } else {
                                actual
                                    .retired()
                                    .map_err(native_denied)?
                                    .verify_same_original(
                                        canonical[i].as_ref().ok_or_else(|| native_denied(()))?,
                                    )
                                    .map_err(native_denied)?;
                            }
                        }
                    }
                    // Include original open ACKs never published to coordinator
                    // and prior retired slot generations. Any extra original
                    // requires its own actual clone/base closed ACK, twice.
                    for original in r.probe_read.originals().map_err(native_denied)? {
                        if !canonical
                            .iter()
                            .flatten()
                            .any(|live| live.same_original(&original))
                        {
                            original
                                .retired()
                                .map_err(native_denied)?
                                .verify_same_original(&original)
                                .map_err(native_denied)?;
                        }
                    }
                    let sampled = NativeRebindSnapshot {
                        guard,
                        rows,
                        network: native_network,
                        probes,
                    };
                    retain(&sampled).map_err(native_denied)?;
                    Ok(sampled)
                })
                .map_err(denied)?;
            for (i, original) in members.iter().enumerate() {
                if let Some(original) = original {
                    if r.controllers[i]
                        .as_mut()
                        .ok_or_else(conflict)?
                        .observe_original(pin, record, &mut r.lock)
                        .map_err(denied)?
                        != *original
                    {
                        return Err(conflict());
                    }
                }
            }
            Ok(observed)
        }

        pub(crate) fn verify_carrier_ready(&mut self, record: &pair::Record) -> io::Result<()> {
            if self.roots.is_none() {
                // C proof is now actually published by coordinator.finish.
                // Startup owns whole pendingNone run; capture callback roots
                // concrete graph before baseline/registration/postflight.
                let serial = self.serial.clone();
                serial.run(false, || {
                    if record.carrier.is_none() || record.pending.is_some() {
                        return Err(conflict());
                    }
                    let pin = self.current(record)?;
                    let startup = self.startup.clone().ok_or_else(conflict)?;
                    startup
                        .try_borrow_mut()
                        .map_err(denied)?
                        .attach_full(&pin, record, &mut |input| self.retain_full_inputs(input))
                        .map_err(denied)?;
                    self.roots().map(|_| ())
                })?;
                self.register_originals(record)?;
            }
            self.in_call(record, |this, _| {
                let r = this.roots()?;
                r.pins
                    .source
                    .inspect(|actual| {
                        if Some(actual.identity.proof) != record.carrier
                            || actual.identity.scope != record.scope
                            || actual.sources
                                != record
                                    .addresses
                                    .iter()
                                    .map(|a| a.addr())
                                    .collect::<Vec<_>>()
                        {
                            return Err(crate::windows::member_carrier_wintun::Error::Conflict);
                        }
                        Ok(())
                    })
                    .map_err(denied)
            })
        }

        pub(crate) fn guard_snapshot(
            &mut self,
            scope: &SessionScope,
        ) -> io::Result<policy::Snapshot> {
            let record = self
                .pair
                .store
                .try_borrow_mut()
                .map_err(denied)?
                .load(scope)?
                .ok_or_else(conflict)?;
            if self.roots.is_none() {
                if record.phase == pair::Phase::Closing && record.carrier.is_none() {
                    return self.read_no_constructor_cleanup(&record);
                }
                let route = match pregraph_guard_read_route(&record) {
                    Ok(route) => route,
                    Err(error) => {
                        self.serial.fault();
                        return Err(error);
                    }
                };
                if route == PregraphGuardRead::EarlyClosing {
                    return self.read_pregraph_closing_cleanup(&record);
                }
                let serial = self.serial.clone();
                return serial.run(true, || {
                    let pin = self.current(&record)?;
                    let mut startup = self
                        .startup
                        .as_ref()
                        .ok_or_else(conflict)?
                        .try_borrow_mut()
                        .map_err(denied)?;
                    let actual = match route {
                        PregraphGuardRead::NativeEmpty => {
                            startup.read_bootstrap_native_empty(&pin, &record)
                        }
                        PregraphGuardRead::Stopped => {
                            startup.read_bootstrap_no_constructor_terminal(&pin, &record)
                        }
                        PregraphGuardRead::FullEmpty => {
                            startup.read_bootstrap_full_empty(&pin, &record)
                        }
                        PregraphGuardRead::EarlyClosing => return Err(conflict()),
                    }
                    .map_err(denied)?;
                    if route == PregraphGuardRead::NativeEmpty {
                        require_native_empty_frame(&record)?;
                        if actual != record.guard.expected {
                            return Err(conflict());
                        }
                    } else {
                        compare_full_empty_snapshot(&record, &actual)?;
                    }
                    Ok(actual)
                });
            }
            self.in_call(&record, |this, pin| {
                this.select_guard(pin, &record)?;
                let r = this.roots()?;
                if (record.phase == pair::Phase::Closing && record.stop_stage == 12)
                    || record.phase == pair::Phase::Stopped
                {
                    require_full_empty_frame(&record)?;
                    let original = r.carrier.retired_pin().map_err(denied)?;
                    return original
                        .inspect_terminal_bindings_and_history(|bindings, _| {
                            let actual = r
                                .guard
                                .try_borrow_mut()
                                .map_err(native_denied)?
                                .snapshot_in_retired_bracket(&original, bindings)
                                .map_err(native_denied)?;
                            compare_full_empty_snapshot(&record, &actual).map_err(native_denied)?;
                            Ok(actual)
                        })
                        .map_err(denied);
                }
                if record.phase == pair::Phase::Closing && record.stop_stage >= 8 {
                    let original = r.carrier.retired_pin().map_err(denied)?;
                    return original
                        .inspect_bindings(|bindings| {
                            r.guard
                                .try_borrow_mut()
                                .map_err(native_denied)?
                                .snapshot_in_retired_bracket(&original, bindings)
                                .map_err(native_denied)
                        })
                        .map_err(denied);
                }
                r.guard
                    .try_borrow_mut()
                    .map_err(denied)?
                    .snapshot()
                    .map_err(denied)
            })
        }

        pub(crate) fn guard_exchange(
            &mut self,
            record: &pair::Record,
            kind: policy::SessionKind,
            expected: &policy::Model,
            desired: &policy::Model,
        ) -> io::Result<policy::Model> {
            self.in_call(record, |this, pin| {
                this.select_guard(pin, record)?;
                let guard_acks = &mut this.guard_acks;
                let r = this.roots.as_mut().ok_or_else(conflict)?;
                let plan = record.pending_guard.as_ref().ok_or_else(conflict)?;
                if record.guard != *expected
                    || plan.resolve(&expected.expected).map_err(denied)? != *expected
                {
                    return Err(conflict());
                }
                let actual = r.guard_journal.readback()?.ok_or_else(conflict)?;
                if actual.current != plan.expected {
                    return Err(conflict());
                }
                match actual.pending.as_ref() {
                    None => {
                        plan.persist(&mut r.guard_journal, None).map_err(denied)?;
                    }
                    Some(p) if p == plan => {}
                    _ => return Err(conflict()),
                }
                // Each edge is independently authorized by NativeGuard's actual
                // locked attestor/full resource G. Journaled plan is not a grant.
                let acknowledged =
                    if record.phase == pair::Phase::Closing && record.stop_stage == 10 {
                        let retired = r.carrier.retired_pin().map_err(denied)?;
                        r.network_gate.select_retired_guard_resources(
                            pin.clone(),
                            record.clone(),
                            retired.clone(),
                        )?;
                        // First actual Authority AfterClose hook already retained
                        // this SAME original in both selections. Never bind again.
                        if kind != policy::SessionKind::StaticBase || desired.installed {
                            return Err(conflict());
                        }
                        r.guard
                            .try_borrow_mut()
                            .map_err(denied)?
                            .remove_base_after_retirement(expected, &retired)
                            .map_err(denied)
                    } else {
                        if kind == policy::SessionKind::StaticBase {
                            r.network_gate
                                .select_static_base_resources(pin.clone(), record.clone())?;
                        } else if desired.permits {
                            r.network_gate
                                .select_guard_resources(pin.clone(), record.clone())?;
                            r.probe_state
                                .select(pin.clone(), record.clone())
                                .map_err(denied)?;
                        }
                        r.guard
                            .try_borrow_mut()
                            .map_err(denied)?
                            .exchange(kind, expected, desired)
                            .map_err(denied)
                    }?;
                // This value is returned by THAT actual retained NativeGuard,
                // not inferred from a recovery sample or private JSON. Root it
                // BEFORE any fallible native-journal capture/finish/postflight.
                guard_acks.push(acknowledged.clone());
                let captured = guard_ack_plan(plan, expected, &acknowledged).map_err(denied)?;
                if captured != *plan {
                    captured
                        .persist(&mut r.guard_journal, Some(plan))
                        .map_err(denied)?;
                }
                if captured.desired == acknowledged {
                    r.guard_journal.finish(&captured, &acknowledged)?;
                }
                Ok(acknowledged)
            })
        }

        pub(crate) fn close_dynamic_permits(&mut self, record: &pair::Record) -> io::Result<()> {
            if self.roots.is_none() {
                require_effect(record, pair::Effect::Guard)?;
                return if record.carrier.is_none() {
                    self.read_no_constructor_cleanup(record).map(|_| ())
                } else {
                    self.read_pregraph_closing_cleanup(record).map(|_| ())
                };
            }
            self.in_call(record, |this, pin| {
                this.select_guard(pin, record)?;
                let r = this.roots()?;
                r.guard
                    .try_borrow_mut()
                    .map_err(denied)?
                    .close_permits()
                    .map_err(denied)?;
                // Close request is not absence: freshly re-read all 48 keys.
                let actual = r
                    .guard
                    .try_borrow_mut()
                    .map_err(denied)?
                    .snapshot()
                    .map_err(denied)?;
                if actual
                    .filters
                    .iter()
                    .any(|f| f.action == policy::Action::Permit)
                {
                    return Err(conflict());
                }
                Ok(())
            })
        }

        fn cleanup_pregraph_carrier(
            &mut self,
            record: &pair::Record,
            effect: pair::Effect,
        ) -> io::Result<()> {
            let serial = self.serial.clone();
            serial.run(true, || {
                if carrier_cleanup_route(record, effect, self.roots.is_some())?
                    != CarrierCleanupRoute::RetainedStartup
                    || self.full_capture_attempted
                    || !self.rejected_inputs.is_empty()
                    || self.registered
                    || !self.network_intents.is_empty()
                    || !self.guard_acks.is_empty()
                    || self.held.iter().any(Option::is_some)
                    || self.held_reads.iter().any(Option::is_some)
                    || self.row_attempted.iter().any(|attempted| *attempted)
                    || self.row_owners.iter().any(Option::is_some)
                    || self.row_pins.iter().any(Option::is_some)
                    || self.row_authorities.iter().any(Option::is_some)
                    || !self.historical_member_rows.is_empty()
                    || !self.member_generation_originals.is_empty()
                {
                    return Err(conflict());
                }
                let pin = self.current(record)?;
                self.startup
                    .as_ref()
                    .ok_or_else(conflict)?
                    .try_borrow_mut()
                    .map_err(denied)?
                    .cleanup_pregraph_carrier(&pin, record, effect)
                    .map_err(denied)
            })
        }

        fn stop_c(
            &mut self,
            record: &pair::Record,
            stage: u8,
            effect: pair::Effect,
        ) -> io::Result<()> {
            if record.phase != pair::Phase::Closing
                || record.stop_stage != stage
                || record.pending != Some(effect)
            {
                self.serial.fault();
                return Err(conflict());
            }
            match carrier_cleanup_route(record, effect, self.roots.is_some())? {
                CarrierCleanupRoute::NoConstructorRead => {
                    return self.read_no_constructor_cleanup(record).map(|_| ());
                }
                CarrierCleanupRoute::RetainedStartup => {
                    return self.cleanup_pregraph_carrier(record, effect);
                }
                CarrierCleanupRoute::FullGraph => {}
            }
            self.in_call(record, |this, pin| {
                // Advance actual selections BEFORE Close/its first AfterClose
                // callback. Root's in-call method does not nest the supervisor.
                this.select_guard(pin, record)?;
                this.roots()?
                    .probe_state
                    .select(pin.clone(), record.clone())
                    .map_err(denied)?;
                this.roots_mut()?
                    .carrier
                    .cleanup_carrier_in_call(pin.clone(), record)
                    .map_err(denied)
            })
        }
        pub(crate) fn delete_carrier_addresses(&mut self, record: &pair::Record) -> io::Result<()> {
            self.stop_c(record, 6, pair::Effect::CarrierAddressDelete)
        }
        pub(crate) fn end_carrier_session(&mut self, record: &pair::Record) -> io::Result<()> {
            self.stop_c(record, 7, pair::Effect::CarrierSessionEnd)
        }
        pub(crate) fn close_carrier_handle(&mut self, record: &pair::Record) -> io::Result<()> {
            self.stop_c(record, 8, pair::Effect::CarrierClose)
        }

        pub(crate) fn stop_member(&mut self, record: &pair::Record, slot: Slot) -> io::Result<()> {
            if self.roots.is_none() {
                return self.verify_cold_unstarted_member(record, slot);
            }
            self.in_call(record, |this, pin| {
                if record.phase == pair::Phase::Closing && this.row_owners[idx(slot)].is_some() {
                    this.enter_member_rows_storage_cleanup_in_call(record, slot)?;
                }
                if this.roots()?.controllers[idx(slot)].is_none() {
                    return this.verify_unstarted_member_in_call(pin, record, slot);
                }
                let i = idx(slot);
                let closing = this.closing.clone();
                let r = this.roots_mut()?;
                r.member_gates[i]
                    .as_ref()
                    .ok_or_else(conflict)?
                    .try_borrow_mut()
                    .map_err(denied)?
                    .select_pair(pin.clone())
                    .map_err(denied)?;
                let c = r.controllers[i].as_mut().ok_or_else(conflict)?;
                if record.phase == pair::Phase::Closing {
                    c.stop(
                        pin,
                        record,
                        closing.as_deref().ok_or_else(conflict)?,
                        &mut r.lock,
                    )
                    .map_err(denied)?;
                } else {
                    c.retire(pin, record, &mut r.lock).map_err(denied)?;
                }
                Ok(())
            })
        }

        pub(crate) fn verify_member(
            &mut self,
            record: &pair::Record,
            slot: Slot,
        ) -> io::Result<()> {
            self.in_call(record, |this, pin| {
                let r = this.roots_mut()?;
                let i = idx(slot);
                r.member_gates[i]
                    .as_ref()
                    .ok_or_else(conflict)?
                    .try_borrow_mut()
                    .map_err(denied)?
                    .select_pair(pin.clone())
                    .map_err(denied)?;
                r.controllers[i]
                    .as_mut()
                    .ok_or_else(conflict)?
                    .verify(pin, record, &mut r.lock)
                    .map_err(denied)
            })
        }

        /// SAME service/owner, new original process generation, SAME NIC. The
        /// controller retains its actual ACK before returning; this actor roots
        /// that exact receipt before any reader/publication/postflight. No
        /// numeric lookup, saved-NIC adoption or new inventory is permitted.
        pub(crate) fn rebind_member(
            &mut self,
            record: &pair::Record,
            slot: Slot,
        ) -> io::Result<crate::member_owner::Record> {
            self.in_call(record, |this, pin| {
                let i = idx(slot);
                record.validate()?;
                if record.phase != pair::Phase::Running
                    || record.operation != Some(pair::Operation::Rebind)
                    || record.pending != Some(pair::Effect::Rebind(slot))
                    || record.stop_stage != 0
                    || record.pending_guard.is_some()
                    || record.guard.permits
                {
                    return Err(conflict());
                }
                let prior = &record.members[i].as_ref().ok_or_else(conflict)?.owner;
                let Self {
                    roots,
                    member_rebind_receipts,
                    ..
                } = this;
                let r = roots.as_mut().ok_or_else(conflict)?;
                r.member_gates[i]
                    .as_ref()
                    .ok_or_else(conflict)?
                    .try_borrow_mut()
                    .map_err(denied)?
                    .select_pair(pin.clone())
                    .map_err(denied)?;
                member_rebind_receipts
                    .try_reserve(1)
                    .map_err(denied_allocation)?;
                let controller = r.controllers[i].as_mut().ok_or_else(conflict)?;
                let actual = controller
                    .rebind(pin, record, &mut r.lock)
                    .map_err(denied)?;
                retain_generation_once(member_rebind_receipts, &actual, |original| {
                    compare_member_rebind_ack(prior, original.running_record())?;
                    let (reader, pending) = controller
                        .rebind_readers(pin, record, original, &mut r.lock)
                        .map_err(denied)?;
                    // The occupied inventory slot is renewed ONLY by the
                    // original receipt's retired/replacement lineage. This
                    // mutation occurs OUTSIDE Source's readonly callback.
                    r.members
                        .publish_rebind(
                            r.member_source.clone(),
                            reader,
                            pending,
                            NativeRebindPublication {
                                source: &r.pins.source,
                                receipt: original,
                                pair: pin,
                                expected: record,
                                supervisor: &r.pins.supervisor,
                            },
                        )
                        .map_err(denied)?;
                    let acknowledged = controller
                        .complete_rebind(pin, record, original, &mut r.lock)
                        .map_err(denied)?;
                    compare_member_rebind_ack(prior, &acknowledged)?;
                    if &acknowledged != original.running_record() {
                        return Err(conflict());
                    }
                    // complete_rebind independently brackets THIS Source with
                    // full SDK + mandatory resource G after publication. Only
                    // data backed by the rooted native ACK leaves this call.
                    Ok(acknowledged)
                })
            })
        }

        pub(crate) fn verify_member_absent(
            &mut self,
            record: &pair::Record,
            slot: Slot,
        ) -> io::Result<()> {
            if self.roots.is_none() {
                return self.verify_cold_unstarted_member(record, slot);
            }
            self.in_call(record, |this, pin| {
                if this.roots()?.controllers[idx(slot)].is_none() {
                    return this.verify_unstarted_member_in_call(pin, record, slot);
                }
                let closing = this.closing.clone();
                let r = this.roots_mut()?;
                let i = idx(slot);
                r.member_gates[i]
                    .as_ref()
                    .ok_or_else(conflict)?
                    .try_borrow_mut()
                    .map_err(denied)?
                    .select_pair(pin.clone())
                    .map_err(denied)?;
                // Actual controller opaque Stop receipt + fresh full SDK. No
                // missing lookup/equal Pair record can supply absence success.
                r.controllers[i]
                    .as_mut()
                    .ok_or_else(conflict)?
                    .verify_absent(pin, record, closing.as_deref(), &mut r.lock)
                    .map_err(denied)
            })
        }

        fn verify_cold_unstarted_member(
            &mut self,
            record: &pair::Record,
            slot: Slot,
        ) -> io::Result<()> {
            if record.carrier.is_none() {
                require_unstarted_cleanup(record, slot)?;
                return self.read_no_constructor_cleanup(record).map(|_| ());
            }
            require_unstarted_cleanup(record, slot)?;
            // The SAME original preparation ledger/owners plus full Closing C
            // SDK sample prove absence. Cold member keys are Unstarted, not
            // full-graph precreated Disabled keys; do not manufacture that ACK.
            self.read_pregraph_closing_cleanup(record).map(|_| ())
        }

        fn verify_unstarted_member_in_call(
            &mut self,
            pin: &Rc<NativePairIntentRead>,
            record: &pair::Record,
            slot: Slot,
        ) -> io::Result<()> {
            require_unstarted_cleanup(record, slot)?;
            let i = idx(slot);
            if self.row_owners[i].is_some()
                || self.row_pins[i].is_some()
                || self.held[i].is_some()
                || self.held_reads[i].is_some()
            {
                return Err(conflict());
            }
            let startup = self.startup.clone().ok_or_else(conflict)?;
            let closing = self.closing.clone().ok_or_else(conflict)?;
            let r = self.roots_mut()?;
            let result = startup
                .try_borrow_mut()
                .map_err(denied)?
                .verify_unstarted_member(pin, record, slot, Some(&closing), Some(&mut r.lock))
                .map_err(denied);
            result
        }

        pub(crate) fn read_network(
            &mut self,
            record: &pair::Record,
        ) -> io::Result<pair::NetworkSnapshot> {
            self.in_call(record, |this, _| {
                let r = this.roots()?;
                let sample =
                    |facts: &crate::windows::member_carrier_network::native::NativeNetworkFacts| {
                        if facts.routes.pending.is_some() {
                            return Err(conflict());
                        }
                        let routes = facts
                            .routes
                            .current
                            .iter()
                            .map(|f| {
                                let actual = f.actual.as_ref().ok_or_else(conflict)?;
                                if actual.route != f.expected {
                                    return Err(conflict());
                                }
                                Ok(actual.route.clone()) // independently observed row, not model
                            })
                            .collect::<io::Result<Vec<_>>>()?;
                        Ok(pair::NetworkSnapshot {
                            routes,
                            dns: Some(facts.dns.clone()),
                        })
                    };
                if record.phase == pair::Phase::Closing {
                    let n = this.closing_network.as_ref().ok_or_else(conflict)?;
                    this.closing
                        .as_ref()
                        .ok_or_else(conflict)?
                        .inspect_window(|window| {
                            n.inspect_in_window(window, sample).map_err(native_denied)
                        })
                        .map_err(denied)
                } else {
                    r.network_read.inspect(sample)
                }
            })
        }

        pub(crate) fn exchange_network(
            &mut self,
            record: &pair::Record,
            expected: &pair::NetworkSnapshot,
            desired: &pair::NetworkSnapshot,
        ) -> io::Result<()> {
            self.in_call(record, |this, pin| {
                let n = record.network.as_ref().ok_or_else(conflict)?;
                if &n.current != expected || n.pending.as_ref() != Some(desired) {
                    return Err(conflict());
                }
                let intent = Rc::new(
                    this.roots()?
                        .store
                        .try_borrow_mut()
                        .map_err(denied)?
                        .network_intent(record)?,
                );
                this.network_intents.push(intent.clone()); // retain before gate read
                let r = this.roots()?;
                r.network_gate
                    .select_pair_intent(pin.clone(), intent, record.clone())?;
                if record.phase == pair::Phase::Closing {
                    r.network_owner
                        .cleanup(this.closing.as_ref().ok_or_else(conflict)?.clone())
                } else {
                    let active = network_active(record.active, record.operation)?;
                    r.network_owner.select(
                        active,
                        desired
                            .routes
                            .iter()
                            .cloned()
                            .map(nelomai_client_tunnel::redundancy::network::NetworkValue::Route)
                            .collect(),
                        &record.dns,
                    )
                }
            })
        }

        pub(crate) fn plan_network(
            &mut self,
            record: &pair::Record,
            active: Slot,
        ) -> io::Result<pair::NetworkSnapshot> {
            self.in_call(record, |this, _| {
                let r = this.roots()?;
                r.pins
                    .source
                    .inspect_window(|window| {
                        Self::network_plan_in_window(
                            r,
                            record,
                            active,
                            window,
                            NetworkPlanUse::BeforeMutation,
                        )
                        .map(|plan| plan.snapshot)
                        .map_err(native_denied)
                    })
                    .map_err(denied)
            })
        }

        pub(crate) fn plan_retirement_network(
            &mut self,
            record: &pair::Record,
            retired: Slot,
        ) -> io::Result<pair::NetworkSnapshot> {
            if record.operation != Some(pair::Operation::Retire(retired))
                || record.active.is_none()
                || record.active == Some(retired)
            {
                self.serial.fault();
                return Err(conflict());
            }
            self.plan_network(record, record.active.ok_or_else(conflict)?)
        }

        pub(crate) fn verify_network_plan(
            &mut self,
            record: &pair::Record,
            active: Slot,
            desired: &pair::NetworkSnapshot,
        ) -> io::Result<()> {
            self.in_call(record, |this, _| {
                let r = this.roots()?;
                r.pins
                    .source
                    .inspect_window(|window| {
                        // Fresh independent native rows, complete physical metadata
                        // and original owner ACKs. Prior planning success is unused.
                        let fresh = Self::network_plan_in_window(
                            r,
                            record,
                            active,
                            window,
                            NetworkPlanUse::BeforeMutation,
                        )
                        .map_err(native_denied)?;
                        if &fresh.snapshot != desired {
                            return Err(native_denied(()));
                        }
                        Ok(())
                    })
                    .map_err(denied)
            })
        }

        pub(crate) fn verify_network_and_endpoints(
            &mut self,
            record: &pair::Record,
            active: Slot,
        ) -> io::Result<()> {
            self.in_call(record, |this, pin| {
                this.select_guard(pin, record)?;
                let r = this.roots()?;
                let network = record.network.as_ref().ok_or_else(conflict)?;
                let expected = network.pending.as_ref().unwrap_or(&network.current);
                r.pins
                    .source
                    .inspect_window(|window| {
                        let before = r
                            .guard
                            .try_borrow_mut()
                            .map_err(native_denied)?
                            .snapshot_in_window(window)
                            .map_err(native_denied)?;
                        if before != record.guard.expected {
                            return Err(native_denied(()));
                        }
                        let fresh = Self::network_plan_in_window(
                            r,
                            record,
                            active,
                            window,
                            NetworkPlanUse::ReadOnly,
                        )
                        .map_err(native_denied)?;
                        if &fresh.snapshot != expected {
                            return Err(native_denied(()));
                        }
                        let ack = r.network_ack.acknowledgements().map_err(native_denied)?;
                        let dns_history = r
                            .network_ack
                            .dns_exchange_history()
                            .map_err(native_denied)?;
                        r.network_read
                            .inspect_in_window(window, |facts| {
                                if facts.routes.pending.is_some() {
                                    return Err(conflict());
                                }
                                let sampled = facts
                                    .routes
                                    .current
                                    .iter()
                                    .map(|r| r.actual.clone().ok_or_else(conflict))
                                    .collect::<io::Result<Vec<_>>>()?;
                                compare_network_ack(
                                    expected,
                                    &sampled,
                                    &facts.dns,
                                    r.baseline.snapshot(),
                                    &ack.0,
                                    &dns_history,
                                )
                            })
                            .map_err(native_denied)?;
                        if r.network_ack.acknowledgements().map_err(native_denied)? != ack
                            || r.network_ack
                                .dns_exchange_history()
                                .map_err(native_denied)?
                                != dns_history
                            || r.guard
                                .try_borrow_mut()
                                .map_err(native_denied)?
                                .snapshot_in_window(window)
                                .map_err(native_denied)?
                                != before
                        {
                            return Err(native_denied(()));
                        }
                        Ok(())
                    })
                    .map_err(denied)
            })
        }

        fn network_plan_in_window(
            r: &NativeActorInputs<'_>,
            record: &pair::Record,
            active: Slot,
            window: &NativeBindingsWindow<'_>,
            usage: NetworkPlanUse,
        ) -> io::Result<NativeNetworkPlan> {
            use crate::member_physical::{Family, InterfaceIdentity, PhysicalProof, PhysicalRoute};
            use crate::member_plan::{InterfaceMetric, MAX_ROUTES};
            use nelomai_client_tunnel::redundancy::route_plan::MemberRoutes;
            if record.phase == pair::Phase::Closing
                || !window.matches_source(&r.pins.source)
                || !r
                    .network_ack
                    .matches_origin(&r.pins.source, &r.network_gate)
            {
                return Err(conflict());
            }
            network_plan_channel(record.guard.permits, record.pending_guard.is_some(), usage)?;
            let options = record.options.as_ref().ok_or_else(conflict)?;
            options.validate().map_err(denied)?;
            let owned = window
                .inspect(|b| {
                    let c = b.carrier.as_ref().ok_or_else(|| native_denied(()))?;
                    if Some(c.identity.proof) != record.carrier {
                        return Err(native_denied(()));
                    }
                    Ok(std::iter::once(&c.identity)
                        .chain(b.egress.iter().flatten())
                        .map(|id| InterfaceIdentity {
                            index: id.proof.index,
                            luid: id.proof.luid,
                            guid: id.proof.guid,
                        })
                        .collect::<Vec<_>>())
                })
                .map_err(denied)?;
            let before = crate::windows::member_physical::capture(&owned)?;
            let ack = r.network_ack.acknowledgements()?;
            let leases = r.network_ack.physical_leases()?;
            for lease in &leases {
                before
                    .verify(&PhysicalRoute {
                        proof: PhysicalProof {
                            identity: InterfaceIdentity {
                                index: lease.interface,
                                luid: lease.luid,
                                guid: lease.guid,
                            },
                            family: if lease.ipv6 { Family::V6 } else { Family::V4 },
                            metric: lease.interface_metric,
                        },
                        row: crate::member_routes::Row {
                            route: lease.route.clone(),
                            luid: lease.luid,
                            protocol: lease.protocol,
                            origin: lease.origin,
                            site_prefix_length: lease.site_prefix_length,
                            valid_lifetime: lease.valid_lifetime,
                            preferred_lifetime: lease.preferred_lifetime,
                            flags: lease.flags,
                        },
                    })
                    .map_err(denied)?;
            }
            let physical_owned = ack
                .0
                .iter()
                .filter(|a| {
                    before.proofs().contains_key(&(
                        Family::of(a.row.route.destination.addr()),
                        a.row.route.interface,
                    ))
                })
                .map(|a| a.row.clone())
                .collect::<Vec<_>>();
            // Only actual retained attempt rows are excluded, preserving all
            // foreign metadata at the same keys as a conflict, never adoption.
            let physical = before.without_owned_rows(&physical_owned).map_err(denied)?;
            let facts = r
                .rows
                .inspect_in_window(window, |facts| Ok(facts.clone()))
                .map_err(denied)?;
            let mut exclusions = options
                .excluded_ipv4_cidrs
                .iter()
                .map(|v| v.parse::<ipnet::IpNet>().map_err(denied))
                .collect::<io::Result<Vec<_>>>()?;
            if options.exclude_local_networks {
                exclusions.extend(physical.lan_prefixes());
            }
            let mut members = Vec::new();
            let mut metrics = Vec::new();
            for (i, member) in record.members.iter().enumerate() {
                let slot = if i == 0 { Slot::A } else { Slot::B };
                if record.operation == Some(pair::Operation::Retire(slot)) {
                    continue;
                }
                let Some(m) = member else { continue };
                let proof = m.owner.proof.ok_or_else(conflict)?.interface;
                if m.allowed.iter().any(|n| n.addr().is_ipv6()) {
                    return Err(conflict());
                }
                let row = facts.rows[i + 1].as_ref().ok_or_else(conflict)?;
                let observed = row.observed.as_ref().ok_or_else(conflict)?;
                if row.acknowledged.pending.is_some()
                    || row.acknowledged.phase == rows::Phase::Stopped
                    || row.binding.guid != proof.guid
                    || row.binding.key.index != proof.index
                    || row.binding.key.luid != proof.luid
                    || !rows::same_owned(&row.acknowledged.current, observed)
                    || !observed.interface.policy.weak_host_send
                    || !observed.interface.policy.weak_host_receive
                {
                    return Err(conflict());
                }
                physical.resolve_host(m.endpoint).map_err(denied)?;
                exclusions.push(ipnet::IpNet::from(m.endpoint));
                members.push(MemberRoutes {
                    slot,
                    interface: proof.index,
                    allowed: m.allowed.clone(),
                    probe: m.probe.target_ipv4,
                });
                metrics.push(InterfaceMetric {
                    interface: proof.index,
                    ipv6: false,
                    metric: observed.interface.policy.metric,
                });
            }
            if !members.iter().any(|m| m.slot == active) {
                return Err(conflict());
            }
            exclusions.sort();
            exclusions.dedup();
            let mut destinations = exclusions.clone();
            destinations.extend(
                members
                    .iter()
                    .map(|m| ipnet::IpNet::from(std::net::IpAddr::V4(m.probe))),
            );
            destinations.sort();
            destinations.dedup();
            if destinations.len() > MAX_ROUTES {
                return Err(conflict());
            }
            let bypasses = physical_bypasses(&physical, &destinations)?;
            for proof in physical.proofs().values() {
                metrics.push(InterfaceMetric {
                    interface: proof.identity.index,
                    ipv6: proof.family == Family::V6,
                    metric: proof.metric,
                });
            }
            let plan = crate::member_plan::member_route_plan(
                active,
                &members,
                &exclusions,
                &bypasses.routes,
                &metrics,
                0,
            )
            .map_err(denied)?;
            crate::member_plan::validate_retained_probe_routes(
                &plan,
                &members,
                &bypasses.retained,
                &metrics,
            )
            .map_err(denied)?;
            let dns = r.network_read.inspect_in_window(window, |facts| {
                facts.dns.with_servers(&record.dns).map_err(denied)
            })?;
            let after = crate::windows::member_physical::capture(&owned)?;
            if before.rows() != after.rows()
                || before.proofs() != after.proofs()
                || r.network_ack.acknowledgements()? != ack
                || r.network_ack.physical_leases()? != leases
                || r.rows
                    .inspect_in_window(window, |f| Ok(f.clone()))
                    .map_err(denied)?
                    != facts
            {
                return Err(conflict());
            }
            Ok(NativeNetworkPlan {
                snapshot: pair::NetworkSnapshot {
                    routes: plan
                        .routes
                        .into_iter()
                        .filter(|r| !bypasses.retained.contains(r))
                        .collect(),
                    dns: Some(dns),
                },
                physical: bypasses.originals,
            })
        }

        pub(crate) fn release_unpublished_probes(
            &mut self,
            record: &pair::Record,
        ) -> io::Result<()> {
            if self.roots.is_none() {
                require_effect(record, pair::Effect::ReleaseProbes)?;
                return if record.carrier.is_none() {
                    self.read_no_constructor_cleanup(record).map(|_| ())
                } else {
                    self.read_pregraph_closing_cleanup(record).map(|_| ())
                };
            }
            self.in_call(record, |this, pin| {
                this.select_guard(pin, record)?;
                let closing = this.closing.clone();
                let r = this.roots_mut()?;
                r.probe_state
                    .select(pin.clone(), record.clone())
                    .map_err(denied)?;
                if record.phase == pair::Phase::Closing {
                    r.probes
                        .release_unpublished(closing.as_deref().ok_or_else(conflict)?)
                        .map_err(denied)?;
                } else {
                    r.probes.release_unpublished_preparing().map_err(denied)?;
                }
                Ok(())
            })
        }

        pub(crate) fn hold_probe(
            &mut self,
            record: &pair::Record,
            slot: Slot,
        ) -> io::Result<(NativePairSocket, policy::ProbeTuple)> {
            self.in_call(record, |this, pin| {
                let i = idx(slot);
                if this.held[i].is_some() || record.pending != Some(pair::Effect::HoldProbe(slot)) {
                    return Err(conflict());
                }
                this.select_guard(pin, record)?;
                let target = record.members[i]
                    .as_ref()
                    .ok_or_else(conflict)?
                    .probe
                    .target_ipv4;
                this.roots()?
                    .probe_state
                    .select(pin.clone(), record.clone())
                    .map_err(denied)?;
                let actual = this
                    .roots_mut()?
                    .probes
                    .open(slot, target)
                    .map_err(denied)?;
                this.held[i] = Some(Rc::new(RefCell::new(actual))); // before all registration/return checks
                let original = this.held[i].as_ref().ok_or_else(conflict)?;
                let read = original.try_borrow().map_err(denied)?.read_pin();
                this.held_reads[i] = Some(read.pin());
                let tuple = this
                    .roots()?
                    .probe_state
                    .register_held(slot, read)
                    .map_err(denied)?;
                let socket = this.socket_context()?.issue(original)?;
                Ok((socket, tuple)) // actual lease token remains strong-rooted through supervisor postflight
            })
        }
        pub(crate) fn verify_held_probe(
            &mut self,
            record: &pair::Record,
            slot: Slot,
            socket: &NativePairSocket,
            tuple: &policy::ProbeTuple,
        ) -> io::Result<()> {
            self.in_call(record, |this, pin| {
                let original = this.held[idx(slot)].as_ref().ok_or_else(conflict)?;
                if !Rc::ptr_eq(original, &socket.original)
                    || !Rc::ptr_eq(&this.socket_context()?, &socket.context)
                    || socket.lease.try_borrow().map_err(denied)?.is_none()
                {
                    return Err(conflict());
                }
                this.select_guard(pin, record)?;
                let r = this.roots()?;
                r.probe_state
                    .select(pin.clone(), record.clone())
                    .map_err(denied)?;
                let read = this.held_reads[idx(slot)].as_ref().ok_or_else(conflict)?;
                r.probe_read
                    .verify_member_slot(slot, read)
                    .map_err(denied)?;
                let actual = read.inspect_tuple().map_err(denied)?;
                if &actual != tuple {
                    return Err(conflict());
                }
                Ok(())
            })
        }
        pub(crate) fn release_probe(
            &mut self,
            record: &pair::Record,
            slot: Slot,
            socket: NativePairSocket,
        ) -> io::Result<()> {
            // Socket lease is ALREADY retained in context. Even a preflight
            // failure cannot destroy the original clone/held canonical receipt.
            self.in_call(record, |this, pin| {
                let original = this.held[idx(slot)].as_ref().ok_or_else(conflict)?;
                if !Rc::ptr_eq(original, &socket.original)
                    || !Rc::ptr_eq(&this.socket_context()?, &socket.context)
                {
                    return Err(conflict());
                }
                this.select_guard(pin, record)?;
                let r = this.roots()?;
                r.probe_state
                    .select(pin.clone(), record.clone())
                    .map_err(denied)?;
                let before = r
                    .guard
                    .try_borrow_mut()
                    .map_err(denied)?
                    .snapshot()
                    .map_err(denied)?;
                if before
                    .filters
                    .iter()
                    .any(|f| f.action == policy::Action::Permit)
                {
                    return Err(conflict());
                }
                let after = r
                    .guard
                    .try_borrow_mut()
                    .map_err(denied)?
                    .snapshot()
                    .map_err(denied)?;
                if before != after {
                    return Err(conflict());
                }
                this.socket_context()?.retire_original_leases(original)?;
                let retired = if record.phase == pair::Phase::Closing {
                    original
                        .try_borrow_mut()
                        .map_err(denied)?
                        .release(this.closing.as_deref().ok_or_else(conflict)?)
                        .map_err(denied)?
                } else {
                    original
                        .try_borrow_mut()
                        .map_err(denied)?
                        .release_preparing()
                        .map_err(denied)?
                };
                retired
                    .verify_same_original(this.held_reads[idx(slot)].as_ref().ok_or_else(conflict)?)
                    .map_err(denied)
            })
        }

        pub(crate) fn restore_owned_keys(&mut self, record: &pair::Record) -> io::Result<()> {
            if self.roots.is_none() && record.carrier.is_none() {
                require_effect(record, pair::Effect::RestoreKeys)?;
                return self.read_no_constructor_cleanup(record).map(|_| ());
            }
            if self.roots.is_none() {
                let serial = self.serial.clone();
                return serial.run(true, || {
                    require_effect(record, pair::Effect::RestoreKeys)?;
                    if record.phase != pair::Phase::Closing
                        || record.stop_stage != 11
                        || record.carrier.is_none()
                    {
                        return Err(conflict());
                    }
                    let pin = self.current(record)?;
                    self.startup
                        .as_ref()
                        .ok_or_else(conflict)?
                        .try_borrow_mut()
                        .map_err(denied)?
                        .restore_pregraph_keys(&pin, record)
                        .map_err(denied)
                });
            }
            self.in_call(record, |this, _| {
                if record.phase != pair::Phase::Closing
                    || record.stop_stage != 11
                    || record.pending != Some(pair::Effect::RestoreKeys)
                {
                    return Err(conflict());
                }
                let r = this.roots_mut()?;
                let (owner, _) = r.assembly.retained_parts();
                let owner = owner.as_mut().ok_or_else(conflict)?;
                let current = owner.snapshot().map_err(denied)?.ok_or_else(conflict)?;
                owner.cleanup(&current, &mut r.lock).map_err(denied)?;
                Ok(())
            })
        }

        /// Actual normal Retire, not whole-C cleanup. Assembly retains the
        /// SAME original key retirement cap before CAS/postflight and checks
        /// the actual closed member in its original Source window itself.
        pub(crate) fn restore_member_keys(
            &mut self,
            record: &pair::Record,
            slot: Slot,
        ) -> io::Result<()> {
            self.in_call(record, |this, pin| {
                require_effect(record, pair::Effect::RestoreKeys)?;
                if record.phase != pair::Phase::Running
                    || record.operation != Some(pair::Operation::Retire(slot))
                    || record.stop_stage != 0
                    || record.active.is_none()
                    || record.active == Some(slot)
                    || record.pending_guard.is_some()
                    || record.network.as_ref().is_none_or(|n| n.pending.is_some())
                {
                    return Err(conflict());
                }
                this.select_guard(pin, record)?;
                let role = if slot == Slot::A {
                    rows::Role::MemberA
                } else {
                    rows::Role::MemberB
                };
                let original = this.row_pins[idx(slot)].as_ref().ok_or_else(conflict)?;
                if !this.roots()?.rows.matches_row_original(role, original) {
                    return Err(conflict());
                }
                Self::member_key_restore_facts(this.roots()?, record, slot)?;
                {
                    let r = this.roots_mut()?;
                    let role = if slot == Slot::A {
                        crate::member_carrier_native_ownership::Role::MemberA
                    } else {
                        crate::member_carrier_native_ownership::Role::MemberB
                    };
                    // No Source/Guard/Pair read borrow encloses the real key
                    // effect. Assembly and native Keys reattest originals and
                    // retained handle independently; this actor grants nothing.
                    r.assembly
                        .restore_member_key_in_call(&mut r.lock, &r.pins, pin, record, role)
                        .map_err(denied)?;
                }
                Self::member_key_restore_facts(this.roots()?, record, slot)
            })
        }

        /// Readonly siblings inside THIS original mixed live/closed Source
        /// bracket. Closed identities are history/exclusions, never NIC lookup.
        fn member_key_restore_facts(
            r: &NativeActorInputs<'_>,
            record: &pair::Record,
            slot: Slot,
        ) -> io::Result<()> {
            r.pins
                .source
                .inspect_window(|window| {
                    let native_slot = crate::member_pair::slot_native(slot);
                    let closed = window
                        .closed_member(native_slot)
                        .ok_or_else(|| native_denied(()))?;
                    let member = record.members[idx(slot)]
                        .as_ref()
                        .ok_or_else(|| native_denied(()))?;
                    if closed.intent != member.owner.intent
                        || Some(closed.proof) != member.owner.proof
                        || !window.matches_source(&r.pins.source)
                        || !window.matches_runtime(&r.runtime)
                    {
                        return Err(native_denied(()));
                    }
                    let sample = || {
                        let guard = r
                            .guard
                            .try_borrow_mut()
                            .map_err(native_denied)?
                            .snapshot_in_window(window)
                            .map_err(native_denied)?;
                        compare_member_key_restore_guard(slot, &record.guard, &guard)
                            .map_err(native_denied)?;
                        let rows = r.rows.inspect_in_window(window, |facts| {
                            let target = facts.rows[idx(slot) + 1]
                                .as_ref()
                                .ok_or_else(|| native_denied(()))?;
                            let ack = &target.acknowledged;
                            if target.observed.is_some()
                                || ack.phase != rows::Phase::Stopped
                                || ack.pending.is_some()
                                || ack.current.address.is_some()
                                || ack.current.interface.policy != ack.baseline.interface.policy
                            {
                                return Err(native_denied(()));
                            }
                            Ok(facts.clone())
                        })?;
                        Ok::<_, crate::windows::member_carrier_wintun::Error>((guard, rows))
                    };
                    let before = sample()?;
                    if sample()? != before {
                        return Err(native_denied(()));
                    }
                    Ok(())
                })
                .map_err(denied)
        }

        /// Actual full native C alias -> actual member RowOwner capture. The
        /// first durable baseline pin is rooted BEFORE registration/postflight;
        /// failure cannot import bytes or reopen an equal owner for cleanup.
        fn capture_member_rows(
            &mut self,
            pin: &Rc<NativePairIntentRead>,
            record: &pair::Record,
            slot: Slot,
        ) -> io::Result<()> {
            let i = idx(slot);
            if self.stopped_row_generations[i].is_some() {
                return self.capture_member_row_generation(pin, record, slot);
            }
            if let Some(owner) = &self.row_owners[i] {
                // Presence is not a current-generation ACK. Never reuse an
                // old Stopped owner after inventory projection. Typed new-row
                // capture/registration must retain and replace that bundle.
                let original = self.row_pins[i].as_ref().ok_or_else(conflict)?;
                if !original.same_original(&owner.record_read_pin().map_err(denied)?)
                    || self.row_authorities[i].is_none()
                    || self.stopped_row_generations[i].is_some()
                {
                    return Err(conflict());
                }
                original
                    .with_record(&record.scope, record.provenance.network_epoch, |facts| {
                        require_reusable_member_rows(
                            facts.acknowledged.phase,
                            facts.acknowledged.pending.is_some(),
                            facts.cleanup_only,
                        )
                        .map_err(|_| rows::Error::Conflict)
                    })
                    .map_err(denied)?;
                // This is only a factual reuse fence. The ensuing actual
                // change_interface independently enters mandatory native G.
                return Ok(());
            }
            if std::mem::replace(&mut self.row_attempted[i], true) {
                return Err(conflict());
            }
            let r = self.roots.as_mut().ok_or_else(conflict)?;
            let authority = r
                .carrier
                .rows_authority_in_call(pin.clone(), record)
                .map_err(denied)?;
            let role = if slot == Slot::A {
                rows::Role::MemberA
            } else {
                rows::Role::MemberB
            };
            let mut authority = authority.for_member(role).map_err(denied)?;
            let binding = authority.binding().map_err(denied)?;
            self.row_authorities[i] = Some(authority.read_pin()); // SAME owner alias before baseline capture
            let (journal, saved) = WindowsCarrierRowsStore::open(r.files.clone(), binding.clone())?;
            if saved.is_some() {
                return Err(conflict());
            }
            let first = &mut self.row_pins[i];
            let owner = RowOwner::capture_native_with_record_pin(
                binding,
                authority.read_pin(),
                MemberRowJournal::First(journal),
                |actual| {
                    let original = Rc::new(actual);
                    *first = Some(original.clone());
                    r.rows
                        .retain_member(slot, original.clone())
                        .map_err(|_| rows::Error::Conflict)?;
                    r.lifecycle
                        .retain_row(role, &original)
                        .map_err(|_| rows::Error::Conflict)
                },
            )
            .map_err(denied)?;
            self.row_owners[i] = Some(owner); // owner BEFORE any next SDK/check
            Ok(())
        }

        /// Derive comparison DATA from the actual Source window plus SAME C
        /// baseline pin. Authority.binding/capture still independently enter G;
        /// this does not mint a native binding/creator/effect capability.
        fn member_generation_binding(
            r: &NativeActorInputs<'_>,
            record: &pair::Record,
            slot: Slot,
            started: &NativeMemberStartedGeneration,
        ) -> io::Result<rows::Binding> {
            let i = idx(slot);
            let proof = started.proof().map_err(denied)?;
            r.pins
                .source
                .inspect_window(|window| {
                    let actual = window.bindings();
                    if !window.matches_source(&r.pins.source)
                        || !window.matches_runtime(&r.runtime)
                        || actual.scope != record.scope
                        || window
                            .closed_member(crate::member_pair::slot_native(slot))
                            .is_some()
                        || record.members[i]
                            .as_ref()
                            .is_none_or(|m| m.owner.proof != Some(proof))
                        || actual.egress[i]
                            .as_ref()
                            .is_none_or(|m| m.proof != proof.interface)
                        || actual.carrier.as_ref().map(|c| c.identity.proof) != record.carrier
                    {
                        return Err(native_denied(()));
                    }
                    r.pins
                        .carrier_rows
                        .with_record(&record.scope, record.provenance.network_epoch, |facts| {
                            if facts.binding.role != rows::Role::Carrier
                                || facts.binding.boot_id != r.context.provenance.boot_id
                                || facts.binding.runtime != r.context.provenance.runtime
                                || actual.carrier.as_ref().is_none_or(|c| {
                                    c.identity.proof.guid != facts.binding.guid
                                        || c.identity.proof.luid != facts.binding.key.luid
                                        || c.identity.proof.index != facts.binding.key.index
                                })
                            {
                                return Err(rows::Error::Conflict);
                            }
                            let mut binding = facts.binding.clone();
                            binding.role = [rows::Role::MemberA, rows::Role::MemberB][i];
                            binding.guid = proof.interface.guid;
                            binding.key = rows::RowKey {
                                luid: proof.interface.luid,
                                index: proof.interface.index,
                            };
                            binding.name = r.context.bindings[i + 1].name.clone();
                            // Canonical VIP comes from original C baseline, never
                            // target SDK/Pair address (members stay addressless).
                            binding.validate()?;
                            Ok(binding)
                        })
                        .map_err(native_denied)
                })
                .map_err(denied)
        }

        fn capture_member_row_generation(
            &mut self,
            pin: &Rc<NativePairIntentRead>,
            record: &pair::Record,
            slot: Slot,
        ) -> io::Result<()> {
            let i = idx(slot);
            let entry = self
                .member_generation_originals
                .iter()
                .rev()
                .find(|entry| entry.ticket.slot() == crate::member_pair::slot_native(slot))
                .cloned()
                .ok_or_else(conflict)?;
            let retired = entry
                .receipt
                .try_borrow()
                .map_err(denied)?
                .clone()
                .ok_or_else(conflict)?;
            let old_pin = self.row_pins[i].clone().ok_or_else(conflict)?;
            let old_seal = self.stopped_row_generations[i]
                .clone()
                .ok_or_else(conflict)?;
            old_seal
                .inspect_original(&old_pin, |_| Ok(()))
                .map_err(denied)?;
            let old = HistoricalMemberRows {
                pin: old_pin,
                authority: self.row_authorities[i]
                    .as_ref()
                    .ok_or_else(conflict)?
                    .read_pin(),
                seal: old_seal,
            };
            // Reserve before issuer can return a new token. Then token rooting
            // is infallible and precedes ALL authority/capture/registration G.
            self.member_row_captures
                .try_reserve(1)
                .map_err(denied_allocation)?;
            let r = self.roots.as_mut().ok_or_else(conflict)?;
            let started = r.controllers[i]
                .as_ref()
                .ok_or_else(conflict)?
                .started_generation_registration(&entry.ticket, &entry.never)
                .map_err(denied)?;
            started
                .verify_original(&entry.ticket, &entry.never, &r.runtime, &r.context)
                .map_err(denied)?;
            started.verify_source(&r.pins.source).map_err(denied)?;
            let binding = Self::member_generation_binding(r, record, slot, &started)?;
            let inputs = || NativeMemberCaptureInputs {
                ticket: &entry.ticket,
                never: &entry.never,
                started: &started,
                pair: pin,
                record,
                binding: &binding,
                supervisor: &r.pins.supervisor,
                guard: &r.guard,
                lock: &r.lock,
            };
            let capture = r
                .rows
                .issue_member_capture(&retired, inputs())
                .map_err(denied)?;
            self.member_row_captures.push(capture.clone()); // original token FIRST.
            r.lifecycle
                .begin_member_row_capture(&capture, &old.pin, &old.seal, inputs())
                .map_err(denied)?;
            let write: Rc<dyn OriginalRowGenerationWrite> = capture.clone();
            let journal = MemberRowJournal::Generation(WindowsCarrierRowsStore::open_generation(
                r.files.clone(),
                binding.clone(),
                capture.stopped_payload(),
                write,
            ));
            let first = &mut self.row_pins[i];
            let authority_pin = &mut self.row_authorities[i];
            let owner = with_retained_row_original(
                &mut self.row_owners[i],
                &mut self.historical_member_rows,
                old,
                || {
                    // No attempted reset and no old Stopped owner reuse. The
                    // original old owner/pin/authority/seal are already inert.
                    let authority = r
                        .carrier
                        .rows_authority_in_call(pin.clone(), record)
                        .map_err(denied)?;
                    let mut authority = authority.for_member(binding.role).map_err(denied)?;
                    if authority.binding().map_err(denied)? != binding {
                        return Err(conflict());
                    }
                    *authority_pin = Some(authority.read_pin());
                    RowOwner::capture_native_with_record_pin(
                        binding.clone(),
                        authority.read_pin(),
                        journal,
                        |actual| {
                            let original = Rc::new(actual);
                            *first = Some(original.clone()); // actual ACK BEFORE registration.
                            r.rows
                                .retain_member_generation(&capture, original.clone())
                                .map_err(|_| rows::Error::Conflict)?;
                            r.lifecycle
                                .retain_member_row_capture(&capture, &original)
                                .map_err(|_| rows::Error::Conflict)
                        },
                    )
                    .map_err(denied)
                },
            )?;
            self.row_owners[i] = Some(owner); // new owner BEFORE fallible final SDK check.
            self.stopped_row_generations[i] = None; // old seal remains in historical owner bundle.
            r.rows
                .complete_member_capture(
                    &capture,
                    NativeMemberCaptureInputs {
                        ticket: &entry.ticket,
                        never: &entry.never,
                        started: &started,
                        pair: pin,
                        record,
                        binding: &binding,
                        supervisor: &r.pins.supervisor,
                        guard: &r.guard,
                        lock: &r.lock,
                    },
                )
                .map_err(denied)?;
            r.lifecycle
                .complete_member_row_capture(&capture)
                .map_err(denied)
        }

        pub(crate) fn apply_weak_rows(&mut self, record: &pair::Record) -> io::Result<()> {
            self.in_call(record, |this, pin| {
                if record.pending != Some(pair::Effect::WeakRows) {
                    return Err(conflict());
                }
                weak_rows_sequence(
                    record.members.each_ref().map(|member| member.is_some()),
                    |step| match step {
                        WeakRowsBoundary::Capture(slot) => {
                            this.capture_member_rows(pin, record, slot)
                        }
                        WeakRowsBoundary::Carrier => {
                            let policy = this
                                .roots()?
                                .pins
                                .carrier_rows
                                .with_record(
                                    &record.scope,
                                    record.provenance.network_epoch,
                                    |facts| {
                                        let mut desired =
                                            facts.acknowledged.baseline.interface.policy.clone();
                                        desired.weak_host_send = true;
                                        desired.weak_host_receive = true;
                                        Ok(desired)
                                    },
                                )
                                .map_err(denied)?;
                            this.roots_mut()?
                                .carrier
                                .change_interface_in_call(pin.clone(), record, policy)
                                .map_err(denied)
                        }
                        WeakRowsBoundary::Member(slot) => {
                            let policy = this.row_pins[idx(slot)]
                                .as_ref()
                                .ok_or_else(conflict)?
                                .with_record(
                                    &record.scope,
                                    record.provenance.network_epoch,
                                    |facts| {
                                        let mut desired =
                                            facts.acknowledged.baseline.interface.policy.clone();
                                        desired.weak_host_send = true;
                                        desired.weak_host_receive = true;
                                        Ok(desired)
                                    },
                                )
                                .map_err(denied)?;
                            this.row_owners[idx(slot)]
                                .as_mut()
                                .ok_or_else(conflict)?
                                .change_interface(policy)
                                .map_err(denied)
                        }
                    },
                )
            })
        }

        pub(crate) fn restore_member_weak_rows(
            &mut self,
            record: &pair::Record,
            slot: Slot,
        ) -> io::Result<()> {
            self.in_call(record, |this, pin| {
                if record.pending != Some(pair::Effect::RestoreWeak) {
                    return Err(conflict());
                }
                this.select_guard(pin, record)?;
                // Select the current original into the SAME alias, not a new
                // authority. stop invokes mandatory G on actual latest ACKs.
                let i = idx(slot);
                let authority = this.row_authorities[i].as_mut().ok_or_else(conflict)?;
                authority
                    .select_pair_intent(pin.clone(), record)
                    .map_err(denied)?;
                this.row_owners[i]
                    .as_mut()
                    .ok_or_else(conflict)?
                    .stop()
                    .map_err(denied)?;
                if record.phase != pair::Phase::Running
                    || record.operation != Some(pair::Operation::Retire(slot))
                {
                    return Err(conflict());
                }
                // SAME Calling, old member/NIC still alive. Seal the actual
                // Stop CAS pointer now, never after old service closure.
                let first = &mut this.stopped_row_generations[i];
                this.row_owners[i]
                    .as_mut()
                    .ok_or_else(conflict)?
                    .seal_stopped_generation_with_pin(|original| {
                        if first.is_some() {
                            return Err(rows::Error::Conflict);
                        }
                        *first = Some(original); // BEFORE native/durable seal postflight.
                        Ok(())
                    })
                    .map_err(denied)?;
                this.stopped_row_generations[i]
                    .as_ref()
                    .ok_or_else(conflict)?
                    .inspect_original(this.row_pins[i].as_ref().ok_or_else(conflict)?, |_| Ok(()))
                    .map_err(denied)?;
                Ok(())
            })
        }

        /// Called only in the actor's independently actual Closing Calling.
        /// Storage handoff alone cannot prove member absence, stop success or
        /// authorize SDK changes. Missing owners are handled by their actual
        /// preparation/controller/absence path, not accepted by this method.
        fn enter_member_rows_storage_cleanup_in_call(
            &mut self,
            record: &pair::Record,
            slot: Slot,
        ) -> io::Result<()> {
            require_member_row_storage_cleanup_frame(record, slot)?;
            let r = self.roots.as_ref().ok_or_else(conflict)?;
            let owner = self.row_owners[idx(slot)].as_mut().ok_or_else(conflict)?;
            enter_original_row_storage_cleanup(
                owner,
                || {
                    r.runtime
                        .native_files_for_original(&r.context, &r.files)
                        .map_err(|_| rows::Error::Journal)
                },
                MemberRowJournal::enter_cleanup,
            )
            .map_err(denied)
        }

        pub(crate) fn restore_weak_rows(&mut self, record: &pair::Record) -> io::Result<()> {
            match carrier_cleanup_route(record, pair::Effect::RestoreWeak, self.roots.is_some())? {
                CarrierCleanupRoute::NoConstructorRead => {
                    return self.read_no_constructor_cleanup(record).map(|_| ());
                }
                CarrierCleanupRoute::RetainedStartup => {
                    return self.cleanup_pregraph_carrier(record, pair::Effect::RestoreWeak);
                }
                CarrierCleanupRoute::FullGraph => {}
            }
            self.in_call(record, |this, pin| {
                this.select_guard(pin, record)?;
                // Preserve and hand off EVERY actual A/B owner, including a
                // rooted Captured ACK whose later registration failed. No
                // Option/record-member absence is used as cleanup authority.
                for slot in [Slot::A, Slot::B] {
                    if this.row_owners[idx(slot)].is_some() {
                        this.enter_member_rows_storage_cleanup_in_call(record, slot)?;
                    }
                }
                // Closing3 is interface-only: SAME original C address stays
                // owned until stage6 invokes actual RowOwner.stop.
                this.roots_mut()?
                    .carrier
                    .restore_interface_in_call(pin.clone(), record)
                    .map_err(denied)?;
                for slot in [Slot::A, Slot::B] {
                    let i = idx(slot);
                    if record.members[i].is_none() {
                        continue;
                    }
                    this.row_authorities[i]
                        .as_mut()
                        .ok_or_else(conflict)?
                        .select_pair_intent(pin.clone(), record)
                        .map_err(denied)?;
                    // Addressless member owners may reach Stopped now. C must
                    // NOT: its SAME VIP is retained for later stage6 deletion.
                    this.row_owners[i]
                        .as_mut()
                        .ok_or_else(conflict)?
                        .stop()
                        .map_err(denied)?;
                }
                Ok(())
            })
        }

        pub(crate) fn start_member(
            &mut self,
            record: &pair::Record,
            slot: Slot,
            native: &str,
        ) -> io::Result<crate::member_owner::Record> {
            use sha2::{Digest, Sha256};
            let serial = self.serial.clone();
            serial.run(false, || {
                let pin = self.current(record)?;
                let startup = self.startup.clone();
                let r = self.roots_mut()?;
                let i = idx(slot);
                let needs_network_binding = r.member_gates[i].is_none();
                if needs_network_binding {
                    let prepared = record.members[i].as_ref().ok_or_else(conflict)?;
                    if record.pending != Some(pair::Effect::MemberStart(slot))
                        || prepared.owner.phase != crate::member_owner::Phase::Prepared
                        || prepared.owner.proof.is_some()
                    {
                        return Err(conflict());
                    }
                    // This constructor performs NO SDK reads/effects. The SAME
                    // prepared owner is still retained in NativeStartup and is
                    // consumed only by its actual attach_member below. Root G
                    // before registration/Assembly's fallible key precreation.
                    r.member_gates[i] = Some(Rc::new(RefCell::new(MemberGate::new(
                        NativeMemberGateInputs {
                            context: r.context.clone(),
                            intent: prepared.owner.intent.clone(),
                            runtime: r.runtime.read_pin().map_err(denied)?,
                            member_source: r.member_source.clone(),
                            source: r.pins.source.clone(),
                            guard: r.guard.clone(),
                            rows: r.rows.clone(),
                            members: r.members.clone(),
                            probes: r.probe_read.clone(),
                            probe_gate: r.probe_state.gate(),
                            network: r.network_read.clone(),
                            supervisor: r.pins.supervisor.clone(),
                            cancelled: r.pins.cancelled.clone(),
                        },
                    ))));
                }
                let controller = &mut r.controllers[i];
                let hash: [u8; 32] = Sha256::digest(native.as_bytes()).into();
                let gate = r.member_gates[i].as_ref().ok_or_else(conflict)?;
                let role = if slot == Slot::A {
                    crate::member_carrier_native_ownership::Role::MemberA
                } else {
                    crate::member_carrier_native_ownership::Role::MemberB
                };
                // Assembly owns the whole SAME Calling. Controller roots its
                // real Running/read ACK before inventory or native postflight.
                let mut acknowledged = None;
                r.assembly
                    .with_member_precreation(
                        &mut r.lock,
                        &r.pins,
                        &pin,
                        record,
                        role,
                        |receipt, _| {
                            if needs_network_binding {
                                gate.try_borrow_mut()
                                    .map_err(|_| CarrierError::Pending)?
                                    .bind_network(&r.network_ack, &r.network_gate)?;
                            }
                            gate.try_borrow_mut()
                                .map_err(|_| CarrierError::Pending)?
                                .select_pair(pin.clone())?;
                            if controller.is_none() {
                                let attachment = NativeMemberAttachment {
                                    image: r
                                        .image
                                        .read_pin()
                                        .map_err(|_| CarrierError::Conflict)?,
                                    original_source: r.pins.source.clone(),
                                    inventory: r.members.read_pin(),
                                    gate: gate.clone(),
                                };
                                startup
                                    .as_ref()
                                    .ok_or(CarrierError::Pending)?
                                    .try_borrow_mut()
                                    .map_err(|_| CarrierError::Pending)?
                                    .attach_member(
                                        &pin,
                                        record,
                                        slot,
                                        attachment,
                                        controller,
                                        receipt.mutation_lock,
                                    )?;
                            }
                            let controller = controller.as_mut().ok_or(CarrierError::Pending)?;
                            if controller.prepared_intent().config_sha256 != hash
                                || record.members[i].as_ref().map(|m| &m.owner.intent)
                                    != Some(controller.prepared_intent())
                            {
                                return Err(CarrierError::Conflict);
                            }
                            let prior = controller.retained_stopped().cloned();
                            acknowledged =
                                Some(controller.start(&pin, record, receipt, prior.as_ref())?);
                            Ok(())
                        },
                    )
                    .map_err(denied)?;
                acknowledged.ok_or_else(conflict)
            })
        }

        pub(crate) fn observe(
            &mut self,
            record: &pair::Record,
            slot: Slot,
        ) -> io::Result<(
            nelomai_client_tunnel::TunnelMetrics,
            nelomai_client_tunnel::redundancy::evidence::NativeHealthSample,
        )> {
            self.in_call(record, |this, pin| {
                this.select_guard(pin, record)?;
                if tokio::runtime::Handle::try_current().is_ok() {
                    return Err(conflict());
                }
                let r = this.roots_mut()?;
                let member = record.members[idx(slot)].as_ref().ok_or_else(conflict)?;
                let gate = r.member_gates[idx(slot)].as_ref().ok_or_else(conflict)?;
                gate.try_borrow_mut()
                    .map_err(denied)?
                    .select_pair(pin.clone())
                    .map_err(denied)?;
                let before = r.controllers[idx(slot)]
                    .as_mut()
                    .ok_or_else(conflict)?
                    .observe_original(pin, record, &mut r.lock)
                    .map_err(denied)?;
                if before.0 != member.owner.intent || Some(before.1) != member.owner.proof {
                    return Err(conflict());
                }
                r.pins
                    .source
                    .inspect_window(|window| Self::attest_window(r, window).map_err(native_denied))
                    .map_err(denied)?;
                // The telemetry constructor is addressed ONLY by THIS actual
                // owner proof. Numeric SCM/NIC lookup cannot adopt an original.
                let metrics = crate::windows::member_metrics::MemberMetrics::capture_owned(
                    before.0.slot,
                    before.0.transport,
                    before.1,
                    member.peer,
                    process_birth_ms(before.1.process.creation_time)?,
                )?;
                let executor = tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .enable_time()
                    .build()?;
                let sampled = executor.block_on(metrics.read())?;
                if r.controllers[idx(slot)]
                    .as_mut()
                    .ok_or_else(conflict)?
                    .observe_original(pin, record, &mut r.lock)
                    .map_err(denied)?
                    != before
                {
                    return Err(conflict());
                }
                r.pins
                    .source
                    .inspect_window(|window| Self::attest_window(r, window).map_err(native_denied))
                    .map_err(denied)?;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(denied)?
                    .as_millis()
                    .try_into()
                    .map_err(denied)?;
                let health = native_health(
                    &sampled.transport,
                    sampled.sent_unicast_packets,
                    sampled.received_unicast_packets,
                    now,
                );
                Ok((sampled.transport, health))
            })
        }

        pub(crate) fn verify_target_health(
            &mut self,
            record: &pair::Record,
            slot: Slot,
        ) -> io::Result<()> {
            if record.phase != pair::Phase::Running
                || record.pending.is_some()
                || record.operation.is_some()
                || record.active == Some(slot)
            {
                self.serial.fault();
                return Err(conflict());
            }
            let (_, actual) = self.observe(record, slot)?;
            if !actual.admitted || actual.closed || !actual.handshake_fresh {
                self.serial.fault();
                return Err(conflict());
            }
            Ok(())
        }

        pub(crate) fn verify_data(&mut self, record: &pair::Record, slot: Slot) -> io::Result<()> {
            if require_effect(record, pair::Effect::Data(slot)).is_err()
                || record.guard.active != Some(slot)
                || !record.guard.installed
                || !record.guard.permits
                || record.pending_guard.is_some()
                || record.network.as_ref().is_none_or(|n| n.pending.is_some())
            {
                self.serial.fault();
                return Err(conflict());
            }
            // Configuration/readiness facts, NOT source-bound traffic success
            // or health-driver promotion. ProbeEvidence still owns that policy.
            self.verify_network_and_endpoints(record, slot)?;
            self.observe(record, slot)?;
            self.verify_network_and_endpoints(record, slot)
        }

        pub(crate) fn fingerprint(&mut self, record: &pair::Record) -> io::Result<String> {
            use sha2::{Digest, Sha256};
            self.in_call(record, |this, _| {
                let r = this.roots()?;
                r.pins
                    .source
                    .inspect_window(|window| {
                        let owned = window.inspect(|bindings| {
                            let c = bindings.carrier.as_ref().ok_or_else(|| native_denied(()))?;
                            Ok(std::iter::once(&c.identity)
                                .chain(bindings.egress.iter().flatten())
                                .map(|id| crate::member_physical::InterfaceIdentity {
                                    index: id.proof.index,
                                    luid: id.proof.luid,
                                    guid: id.proof.guid,
                                })
                                .collect::<Vec<_>>())
                        })?;
                        let before = crate::windows::member_physical::capture(&owned)
                            .map_err(native_denied)?;
                        let after = crate::windows::member_physical::capture(&owned)
                            .map_err(native_denied)?;
                        if before.rows() != after.rows() || before.proofs() != after.proofs() {
                            return Err(native_denied(()));
                        }
                        // A fresh physical SDK comparison fingerprint only; it
                        // imports no route owner, path lease or effect permission.
                        let mut rows = before
                            .rows()
                            .iter()
                            .map(|r| format!("{r:?}"))
                            .collect::<Vec<_>>();
                        rows.sort();
                        let bytes = format!("{:?}|{:?}", rows, before.proofs());
                        Ok(format!("{:x}", Sha256::digest(bytes.as_bytes())))
                    })
                    .map_err(denied)
            })
        }
    }
    // Every mandatory coordinator method delegates to an actual body. Native
    // owner prerequisites remain mandatory typed calls, never defaults/Err
    // stand-ins. Missing provider APIs must fail compilation, not become a
    // falsely completed native graph or product enablement.
    impl pair::CarrierPairIo for NativeCarrierPairIo<'_> {
        type Socket = NativePairSocket;
        fn select_running_execution(&mut self, record: &pair::Record) -> io::Result<u64> {
            NativeCarrierPairIo::select_running_execution(self, record)
        }
        fn begin_rebind_execution(&mut self, record: &pair::Record) -> io::Result<u64> {
            NativeCarrierPairIo::begin_rebind_execution(self, record)
        }
        fn seal_rebind_execution(&mut self, record: &pair::Record) -> io::Result<()> {
            NativeCarrierPairIo::seal_rebind_execution(self, record)
        }
        fn complete_rebind_execution(&mut self, record: &pair::Record) -> io::Result<u64> {
            NativeCarrierPairIo::complete_rebind_execution(self, record)
        }
        fn preflight_fresh(&mut self, record: &pair::Record) -> io::Result<()> {
            NativeCarrierPairIo::preflight_fresh(self, record)
        }
        fn attest_effect(&mut self, record: &pair::Record, effect: pair::Effect) -> io::Result<()> {
            NativeCarrierPairIo::attest_effect(self, record, effect)
        }
        fn create_carrier_ready(&mut self, record: &pair::Record) -> io::Result<InterfaceProof> {
            NativeCarrierPairIo::create_carrier_ready(self, record)
        }
        fn verify_carrier_ready(&mut self, record: &pair::Record) -> io::Result<()> {
            NativeCarrierPairIo::verify_carrier_ready(self, record)
        }
        fn prepare_member(
            &mut self,
            record: &pair::Record,
            member: &nelomai_client_tunnel::redundancy::protocol::Member,
            native: &str,
        ) -> io::Result<crate::member_owner::Record> {
            NativeCarrierPairIo::prepare_member(self, record, member, native)
        }
        fn start_member(
            &mut self,
            record: &pair::Record,
            slot: Slot,
            native: &str,
        ) -> io::Result<crate::member_owner::Record> {
            NativeCarrierPairIo::start_member(self, record, slot, native)
        }
        fn verify_member(&mut self, record: &pair::Record, slot: Slot) -> io::Result<()> {
            NativeCarrierPairIo::verify_member(self, record, slot)
        }
        fn rebind_member(
            &mut self,
            record: &pair::Record,
            slot: Slot,
        ) -> io::Result<crate::member_owner::Record> {
            NativeCarrierPairIo::rebind_member(self, record, slot)
        }
        fn stop_member(&mut self, record: &pair::Record, slot: Slot) -> io::Result<()> {
            NativeCarrierPairIo::stop_member(self, record, slot)
        }
        fn verify_member_absent(&mut self, record: &pair::Record, slot: Slot) -> io::Result<()> {
            NativeCarrierPairIo::verify_member_absent(self, record, slot)
        }
        fn guard_snapshot(&mut self, scope: &SessionScope) -> io::Result<policy::Snapshot> {
            NativeCarrierPairIo::guard_snapshot(self, scope)
        }
        fn guard_exchange(
            &mut self,
            record: &pair::Record,
            kind: policy::SessionKind,
            expected: &policy::Model,
            desired: &policy::Model,
        ) -> io::Result<policy::Model> {
            NativeCarrierPairIo::guard_exchange(self, record, kind, expected, desired)
        }
        fn close_dynamic_permits(&mut self, record: &pair::Record) -> io::Result<()> {
            NativeCarrierPairIo::close_dynamic_permits(self, record)
        }
        fn apply_weak_rows(&mut self, record: &pair::Record) -> io::Result<()> {
            NativeCarrierPairIo::apply_weak_rows(self, record)
        }
        fn restore_weak_rows(&mut self, record: &pair::Record) -> io::Result<()> {
            NativeCarrierPairIo::restore_weak_rows(self, record)
        }
        fn restore_member_weak_rows(
            &mut self,
            record: &pair::Record,
            slot: Slot,
        ) -> io::Result<()> {
            NativeCarrierPairIo::restore_member_weak_rows(self, record, slot)
        }
        fn read_network(&mut self, record: &pair::Record) -> io::Result<pair::NetworkSnapshot> {
            NativeCarrierPairIo::read_network(self, record)
        }
        fn plan_network(
            &mut self,
            record: &pair::Record,
            active: Slot,
        ) -> io::Result<pair::NetworkSnapshot> {
            NativeCarrierPairIo::plan_network(self, record, active)
        }
        fn plan_retirement_network(
            &mut self,
            record: &pair::Record,
            retired: Slot,
        ) -> io::Result<pair::NetworkSnapshot> {
            NativeCarrierPairIo::plan_retirement_network(self, record, retired)
        }
        fn verify_network_plan(
            &mut self,
            record: &pair::Record,
            active: Slot,
            desired: &pair::NetworkSnapshot,
        ) -> io::Result<()> {
            NativeCarrierPairIo::verify_network_plan(self, record, active, desired)
        }
        fn exchange_network(
            &mut self,
            record: &pair::Record,
            expected: &pair::NetworkSnapshot,
            desired: &pair::NetworkSnapshot,
        ) -> io::Result<()> {
            NativeCarrierPairIo::exchange_network(self, record, expected, desired)
        }
        fn verify_network_and_endpoints(
            &mut self,
            record: &pair::Record,
            active: Slot,
        ) -> io::Result<()> {
            NativeCarrierPairIo::verify_network_and_endpoints(self, record, active)
        }
        fn hold_probe(
            &mut self,
            record: &pair::Record,
            slot: Slot,
        ) -> io::Result<(Self::Socket, policy::ProbeTuple)> {
            NativeCarrierPairIo::hold_probe(self, record, slot)
        }
        fn verify_held_probe(
            &mut self,
            record: &pair::Record,
            slot: Slot,
            socket: &Self::Socket,
            tuple: &policy::ProbeTuple,
        ) -> io::Result<()> {
            NativeCarrierPairIo::verify_held_probe(self, record, slot, socket, tuple)
        }
        fn release_probe(
            &mut self,
            record: &pair::Record,
            slot: Slot,
            socket: Self::Socket,
        ) -> io::Result<()> {
            NativeCarrierPairIo::release_probe(self, record, slot, socket)
        }
        fn release_unpublished_probes(&mut self, record: &pair::Record) -> io::Result<()> {
            NativeCarrierPairIo::release_unpublished_probes(self, record)
        }
        fn verify_target_health(&mut self, record: &pair::Record, slot: Slot) -> io::Result<()> {
            NativeCarrierPairIo::verify_target_health(self, record, slot)
        }
        fn verify_data(&mut self, record: &pair::Record, slot: Slot) -> io::Result<()> {
            NativeCarrierPairIo::verify_data(self, record, slot)
        }
        fn delete_carrier_addresses(&mut self, record: &pair::Record) -> io::Result<()> {
            NativeCarrierPairIo::delete_carrier_addresses(self, record)
        }
        fn end_carrier_session(&mut self, record: &pair::Record) -> io::Result<()> {
            NativeCarrierPairIo::end_carrier_session(self, record)
        }
        fn close_carrier_handle(&mut self, record: &pair::Record) -> io::Result<()> {
            NativeCarrierPairIo::close_carrier_handle(self, record)
        }
        fn verify_native_empty(&mut self, record: &pair::Record) -> io::Result<()> {
            NativeCarrierPairIo::verify_native_empty(self, record)
        }
        fn verify_full_empty(&mut self, record: &pair::Record) -> io::Result<()> {
            NativeCarrierPairIo::verify_full_empty(self, record)
        }
        fn restore_owned_keys(&mut self, record: &pair::Record) -> io::Result<()> {
            NativeCarrierPairIo::restore_owned_keys(self, record)
        }
        fn restore_member_keys(&mut self, record: &pair::Record, slot: Slot) -> io::Result<()> {
            NativeCarrierPairIo::restore_member_keys(self, record, slot)
        }
        fn observe(
            &mut self,
            record: &pair::Record,
            slot: Slot,
        ) -> io::Result<(
            nelomai_client_tunnel::TunnelMetrics,
            nelomai_client_tunnel::redundancy::evidence::NativeHealthSample,
        )> {
            NativeCarrierPairIo::observe(self, record, slot)
        }
        fn fingerprint(&mut self, record: &pair::Record) -> io::Result<String> {
            NativeCarrierPairIo::fingerprint(self, record)
        }
    }
    impl Drop for NativeCarrierPairIo<'_> {
        fn drop(&mut self) {
            self.serial.fault();
            std::mem::forget(std::mem::replace(
                &mut self.startup_proof,
                Rc::new(RefCell::new(None)),
            ));
            if let Some(original) = self.execution.take() {
                std::mem::forget(original);
            }
            // Keep every actual issued lease token, including failed coordinator
            // returns. Actor abandonment is not supervised port-release ACK.
            if let Some(original) = self.socket_context.take() {
                std::mem::forget(original);
            }
            if let Some(original) = self.startup.take() {
                std::mem::forget(original);
            }
            for original in self.rejected_inputs.drain(..) {
                std::mem::forget(original);
            }
            for original in self.member_generation_tickets.drain(..) {
                std::mem::forget(original);
            }
            for original in self.row_generation_receipts.drain(..) {
                std::mem::forget(original);
            }
            for original in self.member_generation_originals.drain(..) {
                std::mem::forget(original);
            }
            for original in self.historical_member_rows.drain(..) {
                std::mem::forget(original);
            }
            for original in self.member_row_captures.drain(..) {
                std::mem::forget(original);
            }
            for original in self.member_rebind_receipts.drain(..) {
                std::mem::forget(original);
            }
            for original in self
                .stopped_row_generations
                .iter_mut()
                .filter_map(Option::take)
            {
                std::mem::forget(original);
            }
            if let Some(original) = self.roots.take() {
                std::mem::forget(original);
            }
            for held in self.held.iter_mut() {
                if let Some(original) = held.take() {
                    std::mem::forget(original);
                }
            }
            for owner in self.row_owners.iter_mut() {
                if let Some(original) = owner.take() {
                    std::mem::forget(original);
                }
            }
            // The original owner bundles retain their ACK pins. These extra
            // factual aliases do not authorize cleanup or revive Source.
        }
    }
    fn denied(_: impl std::fmt::Debug) -> io::Error {
        #[cfg(test)]
        if crate::windows::member_carrier_factory_test_os::state().is_some() {
            // Scoped fixture diagnostics only: call frames, never configurations,
            // arbitrary native error text or a replacement cleanup decision.
            eprintln!(
                "actual actor boundary denied: {}",
                std::backtrace::Backtrace::force_capture()
            );
        }
        conflict()
    }
    fn carrier_denied(_: io::Error) -> CarrierError {
        CarrierError::Pending
    }
    fn native_denied(_: impl std::fmt::Debug) -> crate::windows::member_carrier_wintun::Error {
        crate::windows::member_carrier_wintun::Error::Conflict
    }
    fn idx(slot: Slot) -> usize {
        usize::from(slot == Slot::B)
    }
}

#[cfg(test)]
#[path = "member_carrier_pair_io_tests.rs"]
mod tests;
