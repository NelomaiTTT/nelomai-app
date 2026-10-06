//! Caller-rooted native carrier creation used by the retained product factory.
#![allow(dead_code)]

use crate::member_carrier::{CarrierError, Result};
use std::{cell::Cell, rc::Rc};

/// Original close-channel selection only; no native/read/disposal grant.
enum ClosedOriginal<P, U> {
    Published(P),
    Unpublished(U),
}
fn select_closed_original<P, U>(
    published: Result<P>,
    unpublished: Result<U>,
) -> Result<ClosedOriginal<P, U>> {
    match (published, unpublished) {
        (Ok(original), Err(CarrierError::Pending)) => Ok(ClosedOriginal::Published(original)),
        (Err(CarrierError::Pending), Ok(original)) => Ok(ClosedOriginal::Unpublished(original)),
        _ => Err(CarrierError::Conflict),
    }
}

/// Caller-rooted retention only; the supplied original must come from the
/// actual capture callback. This cannot construct a row ACK or native owner.
fn retain_before_postflight<T>(
    root: &mut Option<T>,
    original: T,
    postflight: impl FnOnce(&T) -> Result<()>,
) -> Result<()> {
    if root.is_some() {
        return Err(CarrierError::Retired);
    }
    *root = Some(original);
    postflight(root.as_ref().expect("retained actual original"))
}

/// Enter before the actual constructor. Capture itself MUST retain through
/// its pre-inspect callback, never after a return-only constructor postflight.
fn begin_original_capture(attempted: &mut bool) -> Result<()> {
    if std::mem::replace(attempted, true) {
        return Err(CarrierError::Retired);
    }
    Ok(())
}

/// The constructor must only perform infallible field moves into an actual
/// capture slot. No native/storage validation occurs until it is caller-rooted.
fn capture_in_retained_slot<T>(
    root: &mut Option<T>,
    construct: impl FnOnce() -> T,
    capture: impl FnOnce(&mut T) -> Result<()>,
) -> Result<()> {
    if root.is_some() {
        return Err(CarrierError::Retired);
    }
    *root = Some(construct());
    capture(root.as_mut().expect("caller-retained capture slot"))
}

/// Ownership sequencing only. The production caller uses RowCaptureSlot's
/// private completed take_owner: only that successful transfer empties its
/// unknown-retaining shell. Root the actual owner before dropping that shell
/// or running postflight. Failed/unwound capture stays intact for cleanup.
fn transfer_completed_capture_into<C, O>(
    capture: &mut Option<C>,
    owner: &mut Option<O>,
    transfer: impl FnOnce(&mut C) -> Result<O>,
    postflight: impl FnOnce(&O) -> Result<()>,
) -> Result<()> {
    if owner.is_some() {
        return Err(CarrierError::Retired);
    }
    let original = transfer(capture.as_mut().ok_or(CarrierError::Pending)?)?;
    *owner = Some(original);
    drop(capture.take());
    postflight(owner.as_ref().ok_or(CarrierError::Pending)?)
}

/// Ownership sequencing only; mandatory callbacks authenticate the actual
/// supplier's stopped receipt. Every intermediate owning slot belongs to the
/// caller before a fallible move/verification. Never drop unknown shells.
fn transfer_stopped_capture_into<C, S, O>(
    partial: &mut Option<C>,
    stopped: &mut Option<S>,
    owner: &mut Option<O>,
    drain: impl FnOnce(&mut C, &mut Option<S>) -> Result<()>,
    verify_partial: impl FnOnce(&C, &S) -> Result<()>,
    drain_owner: impl FnOnce(&mut S, &mut Option<O>) -> Result<()>,
    verify_owner: impl FnOnce(&C, &S, &O) -> Result<()>,
) -> Result<()> {
    if owner.is_some() {
        return Err(CarrierError::Retired);
    }
    drain(partial.as_mut().ok_or(CarrierError::Pending)?, stopped)?;
    verify_partial(
        partial.as_ref().ok_or(CarrierError::Pending)?,
        stopped.as_ref().ok_or(CarrierError::Pending)?,
    )?;
    drain_owner(stopped.as_mut().ok_or(CarrierError::Pending)?, owner)?;
    verify_owner(
        partial.as_ref().ok_or(CarrierError::Pending)?,
        stopped.as_ref().ok_or(CarrierError::Pending)?,
        owner.as_ref().ok_or(CarrierError::Pending)?,
    )?;
    drop(partial.take());
    drop(stopped.take());
    Ok(())
}

/// Root/borrow sequencing only, never ownership/SDK/cleanup permission. The
/// actual caller supplies SAME-original validation and an independently gated
/// operation. Owner stays in its caller slot across validation/call Err/unwind.
fn with_retained_owner<T, R>(
    root: &mut Option<T>,
    validate: impl FnOnce(&T) -> Result<()>,
    call: impl FnOnce(&mut T) -> Result<R>,
) -> Result<R> {
    let owner = root.as_mut().ok_or(CarrierError::Pending)?;
    validate(owner)?;
    call(owner)
}

/// Borrow the original owner in place, including an acknowledged capture
/// whose postflight failed. Neither branch transfers an owning input in Result.
fn with_retained_or_partial<'a, T, C, R>(
    root: &'a mut Option<T>,
    partial: &'a mut Option<C>,
    partial_owner: impl FnOnce(&'a mut C) -> Result<&'a mut T>,
    call: impl FnOnce(&mut T) -> Result<R>,
) -> Result<R> {
    let owner = match root.as_mut() {
        Some(owner) => owner,
        None => partial_owner(partial.as_mut().ok_or(CarrierError::Pending)?)?,
    };
    call(owner)
}

/// Ordering only. Actual native issuer, journal origin and sealed SDK receipt
/// are mandatory at the call sites; this helper cannot provide any of them.
fn created_cleanup_sequence<T>(
    owner: &mut T,
    retain: impl FnOnce(&mut T) -> Result<()>,
    handoff: impl FnOnce(&mut T) -> Result<()>,
    reconcile: impl FnOnce(&mut T) -> Result<()>,
) -> Result<()> {
    retain(owner)?;
    handoff(owner)?;
    reconcile(owner)
}

/// Decide whether to request the sealed owner's SPECIAL storage reconcile.
/// The actual private ACK is supplied by its opaque pin. A pending Create
/// DOES NOT prove an SDK ACK: RowOwner must independently hold that receipt,
/// and unknown SDK outcomes deny inside its actual reconciliation method.
fn needs_created_cleanup(acknowledged: &crate::member_carrier_rows::Record) -> Result<bool> {
    acknowledged.validate().map_err(denied_comparison)?;
    if acknowledged.binding.role != crate::member_carrier_rows::Role::Carrier {
        return Err(CarrierError::Conflict);
    }
    Ok(acknowledged.creation.is_none()
        && acknowledged.pending.as_ref().is_some_and(|pending| {
            matches!(
                pending.target,
                crate::member_carrier_rows::Target::Create(_)
            )
        }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadyStep {
    Construct,
    Resolve,
    Create,
    Session,
    CaptureRows,
    Address,
    Readiness,
    Drain,
    PublishSource,
}

/// Ordering/retirement only, not a native permission or a readiness receipt.
struct ReadyRun {
    attempted: Cell<bool>,
    completed: Cell<bool>,
    revoked: Rc<Cell<bool>>,
}
struct RunAttempt {
    revoked: Rc<Cell<bool>>,
    succeeded: bool,
}
impl Drop for RunAttempt {
    fn drop(&mut self) {
        if !self.succeeded {
            self.revoked.set(true);
        }
    }
}
impl ReadyRun {
    fn published(&self, whole_call_succeeded: bool) -> Result<()> {
        if !whole_call_succeeded || !self.completed.get() || self.revoked.get() {
            return Err(CarrierError::Retired);
        }
        Ok(())
    }
    fn new() -> Self {
        Self {
            attempted: Cell::new(false),
            completed: Cell::new(false),
            revoked: Rc::new(Cell::new(false)),
        }
    }
    fn execute(&self, effect: impl FnMut(ReadyStep) -> Result<()>) -> Result<()> {
        self.execute_in(&mut |call| call(), effect)
    }
    fn execute_in(
        &self,
        run: &mut impl FnMut(&mut dyn FnMut() -> Result<()>) -> Result<()>,
        mut effect: impl FnMut(ReadyStep) -> Result<()>,
    ) -> Result<()> {
        if self.attempted.replace(true) || self.revoked.get() {
            self.revoked.set(true);
            return Err(CarrierError::Retired);
        }
        let mut attempt = RunAttempt {
            revoked: self.revoked.clone(),
            succeeded: false,
        };
        for step in [
            ReadyStep::Construct,
            ReadyStep::Resolve,
            ReadyStep::Create,
            ReadyStep::Session,
            ReadyStep::CaptureRows,
            ReadyStep::Address,
            ReadyStep::Readiness,
            ReadyStep::Drain,
            ReadyStep::PublishSource,
        ] {
            crate::member_carrier_native_ownership::preparation_call(run, || effect(step))?;
            if self.revoked.get() {
                return Err(CarrierError::Retired);
            }
        }
        attempt.succeeded = true;
        self.completed.set(true);
        Ok(())
    }
}

fn creation_policy(
    context: &crate::member_carrier_native_ownership::Context,
) -> Result<crate::member_carrier_rows::AddressPolicy> {
    crate::member_carrier::validate_record_shape(&crate::member_carrier::Record {
        version: 1,
        intent: context.intent.clone(),
        provenance: context.provenance.clone(),
        generation: 1,
        phase: crate::member_carrier::Phase::Prepared,
        proof: None,
        rows: None,
    })?;
    let std::net::IpAddr::V4(address) = context.intent.addresses[0].addr() else {
        return Err(CarrierError::Invalid);
    };
    let policy = crate::member_carrier_rows::AddressPolicy {
        address: address.octets(),
        prefix_origin: 1,
        suffix_origin: 1,
        valid_lifetime: u32::MAX,
        preferred_lifetime: u32::MAX,
        on_link_prefix_length: 32,
        skip_as_source: false,
    };
    policy
        .validate_creation()
        .map_err(|_| CarrierError::Invalid)?;
    Ok(policy)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StopStep {
    Interface,
    Address,
    Session,
    Handle,
}
fn stop_boundary(
    context: &crate::member_carrier_native_ownership::Context,
    pair: &crate::member_carrier_pair::Record,
    original: Option<crate::member_owner::InterfaceProof>,
) -> Result<StopStep> {
    use crate::{member_carrier_guard as g, member_carrier_pair as p, member_owner as o};
    pair.validate().map_err(|_| CarrierError::Conflict)?;
    let original = original.ok_or(CarrierError::Pending)?;
    if pair.scope != context.intent.scope
        || pair.provenance != context.provenance
        || pair.addresses != context.intent.addresses
        || pair.phase != p::Phase::Closing
        || pair.operation.is_some()
        || pair.active.is_some()
        || pair.pending_guard.is_some()
        || pair.network.is_some()
        || pair.guard != g::Model::empty(pair.scope.clone()).map_err(|_| CarrierError::Conflict)?
        || pair.carrier.is_some_and(|p| p != original)
        || original.guid != context.bindings[0].guid
        || original.index == 0
        || original.luid == 0
        || pair.members.iter().flatten().any(|m| {
            m.owner.phase != o::Phase::Prepared
                || m.owner.proof.is_some()
                || m.owner.retired_proof.is_some()
                || m.owner.previous_config_sha256.is_some()
        })
    {
        return Err(CarrierError::Conflict);
    }
    match (pair.stop_stage, pair.pending) {
        (3, Some(p::Effect::RestoreWeak)) => Ok(StopStep::Interface),
        (6, Some(p::Effect::CarrierAddressDelete)) => Ok(StopStep::Address),
        (7, Some(p::Effect::CarrierSessionEnd)) => Ok(StopStep::Session),
        (8, Some(p::Effect::CarrierClose)) => Ok(StopStep::Handle),
        _ => Err(CarrierError::Conflict),
    }
}

/// Routing/comparison only. All actual permits/network/rows/member/session
/// receipts and each effect still require the registered unsafe full G.
fn full_interface_cleanup_boundary(
    context: &crate::member_carrier_native_ownership::Context,
    pair: &crate::member_carrier_pair::Record,
    original: Option<crate::member_owner::InterfaceProof>,
) -> Result<()> {
    full_cleanup_comparison(context, pair, original)?;
    if pair.stop_stage != 3 || pair.pending != Some(crate::member_carrier_pair::Effect::RestoreWeak)
    {
        return Err(CarrierError::Conflict);
    }
    Ok(())
}

fn full_stop_boundary(
    context: &crate::member_carrier_native_ownership::Context,
    pair: &crate::member_carrier_pair::Record,
    original: Option<crate::member_owner::InterfaceProof>,
) -> Result<StopStep> {
    use crate::member_carrier_pair as p;
    full_cleanup_comparison(context, pair, original)?;
    match (pair.stop_stage, pair.pending) {
        (6, Some(p::Effect::CarrierAddressDelete)) => Ok(StopStep::Address),
        (7, Some(p::Effect::CarrierSessionEnd)) => Ok(StopStep::Session),
        (8, Some(p::Effect::CarrierClose)) => Ok(StopStep::Handle),
        _ => Err(CarrierError::Conflict),
    }
}

/// Pure routing comparison, NEVER a row/native effect grant. The current
/// original Pair/Calling and registered full G independently prove resources.
fn full_cleanup_comparison(
    context: &crate::member_carrier_native_ownership::Context,
    pair: &crate::member_carrier_pair::Record,
    original: Option<crate::member_owner::InterfaceProof>,
) -> Result<()> {
    use crate::member_carrier_pair as p;
    pair.validate().map_err(|_| CarrierError::Conflict)?;
    let original = original.ok_or(CarrierError::Pending)?;
    if pair.scope != context.intent.scope
        || pair.provenance != context.provenance
        || pair.addresses != context.intent.addresses
        || pair.phase != p::Phase::Closing
        || pair.operation.is_some()
        || pair.active.is_some()
        || pair.pending_guard.is_some()
        || pair
            .network
            .as_ref()
            .is_some_and(|n| n.current != n.baseline || n.pending.is_some())
        || pair.guard.permits
        || pair.carrier != Some(original)
        || original.guid != context.bindings[0].guid
        || original.index == 0
        || original.luid == 0
    {
        return Err(CarrierError::Conflict);
    }
    Ok(())
}

/// Frame comparison only. Known prepublication C requires independently held
/// actual original CloseACK, terminal SDK bracket and all original row ACKs.
fn compare_prepublication_terminal_frame(
    context: &crate::member_carrier_native_ownership::Context,
    record: &crate::member_carrier_pair::Record,
    original: crate::member_owner::InterfaceProof,
) -> Result<()> {
    compare_prepublication_terminal_origin(context, record, Some(original))
}
fn compare_pregraph_native_empty_frame(
    context: &crate::member_carrier_native_ownership::Context,
    record: &crate::member_carrier_pair::Record,
    original: crate::member_owner::InterfaceProof,
) -> Result<()> {
    use crate::member_carrier_pair as p;
    if !matches!(
        (record.stop_stage, record.pending),
        (9, Some(p::Effect::NativeEmpty)) | (10, Some(p::Effect::Guard))
    ) {
        return Err(CarrierError::Conflict);
    }
    compare_prepublication_closed_origin(context, record, Some(original))
}
pub(crate) fn compare_pregraph_closing_frame(
    context: &crate::member_carrier_native_ownership::Context,
    record: &crate::member_carrier_pair::Record,
    original: crate::member_owner::InterfaceProof,
) -> Result<()> {
    use crate::member_carrier_pair as p;
    use nelomai_client_tunnel::redundancy::Slot;
    if record.carrier != Some(original)
        || !matches!(
            (record.stop_stage, record.pending),
            (0, Some(p::Effect::Guard))
                | (1, Some(p::Effect::ReleaseProbes))
                | (2, Some(p::Effect::RestoreNetwork))
                | (3, Some(p::Effect::RestoreWeak))
                | (4, Some(p::Effect::MemberStop(Slot::A)))
                | (5, Some(p::Effect::MemberStop(Slot::B)))
                | (6, Some(p::Effect::CarrierAddressDelete))
                | (7, Some(p::Effect::CarrierSessionEnd))
                | (8, Some(p::Effect::CarrierClose))
        )
    {
        return Err(CarrierError::Conflict);
    }
    compare_prepublication_closed_origin(context, record, Some(original))
}

/// Exact factual key-restoration window, not value/delete/handle permission.
// Factual selector only. Each selected native reader must independently
// authenticate SAME original SDK/journal/Calling; no failed-read fallback.
pub(crate) fn key_restore_read_is_terminal(
    context: &crate::member_carrier_native_ownership::Context,
    record: &crate::member_carrier_pair::Record,
    native: &crate::member_carrier_native_ownership::Record,
) -> Result<bool> {
    use crate::{member_carrier_native_ownership as n, member_carrier_pair as p};
    record.validate().map_err(denied_comparison)?;
    n::validate_record(native)?;
    if native.context != *context
        || record.scope != context.intent.scope
        || record.provenance != context.provenance
        || record.addresses != context.intent.addresses
        || record.options.is_none()
        || record.phase != p::Phase::Closing
        || record.stop_stage != 11
        || record.pending != Some(p::Effect::RestoreKeys)
        || record.pending_guard.is_some()
        || record.active.is_some()
        || record.operation.is_some()
        || record
            .carrier
            .is_none_or(|c| c.guid != context.bindings[0].guid)
    {
        return Err(CarrierError::Conflict);
    }
    match native.phase {
        n::Phase::Closing if native.keys[0].phase == n::KeyPhase::Disabled => Ok(false),
        n::Phase::Stopped => Ok(true), // validate_record requires ALL keys Clean
        _ => Err(CarrierError::Conflict),
    }
}

pub(crate) fn compare_pregraph_key_restore_frame(
    context: &crate::member_carrier_native_ownership::Context,
    record: &crate::member_carrier_pair::Record,
    original: crate::member_owner::InterfaceProof,
) -> Result<()> {
    use crate::member_carrier_pair as p;
    if record.stop_stage != 11
        || record.pending != Some(p::Effect::RestoreKeys)
        || record.carrier != Some(original)
    {
        return Err(CarrierError::Conflict);
    }
    compare_prepublication_closed_origin(context, record, Some(original))
}
fn compare_prepublication_terminal_origin(
    context: &crate::member_carrier_native_ownership::Context,
    record: &crate::member_carrier_pair::Record,
    original: Option<crate::member_owner::InterfaceProof>,
) -> Result<()> {
    use crate::member_carrier_pair as p;
    if record.stop_stage != 12 || record.pending != Some(p::Effect::FullEmpty) {
        return Err(CarrierError::Conflict);
    }
    compare_prepublication_closed_origin(context, record, original)
}
// Shared factual identity/empty-resource comparison, never a stage capability.
// The disjoint callers above keep Closing9/10 separate from terminal Closing12.
fn compare_prepublication_closed_origin(
    context: &crate::member_carrier_native_ownership::Context,
    record: &crate::member_carrier_pair::Record,
    original: Option<crate::member_owner::InterfaceProof>,
) -> Result<()> {
    use crate::{member_carrier_guard as g, member_carrier_pair as p, member_owner as o};
    crate::member_carrier_native_ownership::validate_context(context)?;
    record.validate().map_err(denied_comparison)?;
    if record.scope != context.intent.scope
        || record.provenance != context.provenance
        || record.addresses != context.intent.addresses
        || record.options.is_none()
        || record.phase != p::Phase::Closing
        || record.pending_guard.is_some()
        || record.active.is_some()
        || record.operation.is_some()
        || record.network.is_some()
        || record.guard != g::Model::empty(record.scope.clone()).map_err(denied_comparison)?
        || (original.is_none() && record.carrier.is_some())
        || original.is_some_and(|original| {
            record.carrier.is_some_and(|c| c != original)
                || original.guid != context.bindings[0].guid
                || original.index == 0
                || original.luid == 0
        })
        || record.members.iter().flatten().any(|m| {
            m.owner.phase != o::Phase::Prepared
                || m.owner.proof.is_some()
                || m.owner.retired_proof.is_some()
                || m.owner.previous_config_sha256.is_some()
        })
    {
        return Err(CarrierError::Conflict);
    }
    Ok(())
}
#[derive(Clone, Copy)]
enum PregraphRead {
    CarrierClosed,
    NativeEmpty,
    KeyRestoreBefore,
    KeyRestoreAfter,
    FullEmpty,
    Stopped,
}
fn compare_pregraph_stopped_frame(
    context: &crate::member_carrier_native_ownership::Context,
    record: &crate::member_carrier_pair::Record,
    original: crate::member_owner::InterfaceProof,
) -> Result<()> {
    use crate::{member_carrier_guard as g, member_carrier_pair as p};
    crate::member_carrier_native_ownership::validate_context(context).map_err(denied_comparison)?;
    record.validate().map_err(denied_comparison)?;
    if record.scope != context.intent.scope
        || record.provenance != context.provenance
        || record.addresses != context.intent.addresses
        || record.options.is_none()
        || record.phase != p::Phase::Stopped
        || record.stop_stage != 12
        || record.pending.is_some()
        || record.pending_guard.is_some()
        || record.carrier.is_some()
        || record.members.iter().any(Option::is_some)
        || record.active.is_some()
        || record.operation.is_some()
        || record.network.is_some()
        || record.guard != g::Model::empty(record.scope.clone()).map_err(denied_comparison)?
        || original.guid != context.bindings[0].guid
        || original.index == 0
        || original.luid == 0
    {
        return Err(CarrierError::Conflict);
    }
    Ok(())
}
fn denied_comparison<E>(_: E) -> CarrierError {
    CarrierError::Conflict
}

/// Complete comparison ONLY. Neither a historical stopped row nor a protected
/// copy supplies the private owner ACK or permits SDK/module destruction.
#[cfg(any(windows, test))]
pub(crate) fn compare_pregraph_stopped_rows(
    context: &crate::member_carrier_native_ownership::Context,
    original: crate::member_owner::InterfaceProof,
    binding: &crate::member_carrier_rows::Binding,
    acknowledged: &crate::member_carrier_rows::Record,
    protected: &crate::member_carrier_rows::Record,
) -> Result<()> {
    #[cfg(all(test, not(windows)))]
    use crate::member_carrier_coordinator_rows as comparison;
    use crate::member_carrier_rows as r;
    #[cfg(windows)]
    use crate::windows::member_carrier_coordinator_rows as comparison;
    crate::member_carrier_native_ownership::validate_context(context).map_err(denied_comparison)?;
    let policy = creation_policy(context)?;
    if protected != acknowledged
        || &protected.binding != binding
        || binding.role != r::Role::Carrier
        || binding.boot_id != context.provenance.boot_id
        || binding.runtime != context.provenance.runtime
        || binding.network_epoch != context.provenance.network_epoch
        || binding.scope != context.intent.scope
        || binding.guid != context.bindings[0].guid
        || binding.name != context.bindings[0].name
        || binding.guid != original.guid
        || binding.key.index != original.index
        || binding.key.luid != original.luid
        || binding.address != policy.address
    {
        return Err(CarrierError::Conflict);
    }
    comparison::compare(
        binding,
        protected,
        &protected.current,
        comparison::Stage::Stopped,
    )
    .map_err(denied_comparison)
}

#[cfg(windows)]
pub(crate) mod native {
    use super::*;
    use crate::windows::{
        member_carrier_assembly::drain_before_postflight,
        member_carrier_assembly::native::{
            NativeAssemblyAssets, NativeAssemblySlot, NativePrecreation,
        },
        member_carrier_coordinator::native::{CarrierGateUpgrade, CarrierReadyGate},
        member_carrier_creators as creators,
        member_carrier_key_authority::{KeyLock, RuntimeRead},
        member_carrier_members::native::MemberInventoryRead,
        member_carrier_module::native::OriginalImage,
        member_carrier_pair_store::native_store::NativePairIntentRead,
        member_carrier_payload::native::WintunSource,
        member_carrier_rows::{self as rows, RowOwner},
        member_carrier_runtime::native::{
            NativeClosingRead, NativeConstructionSlot, NativeLifecycleGate, NativeRowsAuthority,
            NativeSourceRead, RetiredCarrierRead, UnpublishedClosedCarrierRead,
        },
        member_carrier_wintun as wintun,
        member_native_deadline::NativeDeadline,
        member_session::{NativeSessionFiles, RecordKind, WindowsCarrierRowsStore},
    };
    use crate::{member_carrier_pair::Record as PairRecord, member_owner::InterfaceProof};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    type NativeRows = rows::NativeRowOwner<
        NativeRowsAuthority<CarrierReadyGate>,
        WindowsCarrierRowsStore<NativeSessionFiles>,
    >;
    type NativeCapture = rows::NativeRowCaptureSlot<
        NativeRowsAuthority<CarrierReadyGate>,
        WindowsCarrierRowsStore<NativeSessionFiles>,
    >;
    type NativeStoppedCapture = rows::NativeRowCaptureSlotStopped<
        NativeRowsAuthority<CarrierReadyGate>,
        WindowsCarrierRowsStore<NativeSessionFiles>,
    >;

    /// Actual first registered close origin only; never selected from Pair
    /// metadata or as a fallback after a published-reader error.
    pub(crate) enum PrepublicationTerminalRead {
        Published(Rc<RetiredCarrierRead>),
        Unpublished(Rc<UnpublishedClosedCarrierRead>),
    }

    pub(crate) struct Meta {
        pub(crate) scope: creators::Scope,
        pub(crate) runtime: RuntimeRead,
        pub(crate) pair: Rc<NativePairIntentRead>,
        pub(crate) expected: PairRecord,
        pub(crate) supervisor: Rc<NativeDeadline>,
        pub(crate) cancelled: Arc<AtomicBool>,
        pub(crate) image: OriginalImage,
        pub(crate) wintun: Rc<WintunSource>,
        pub(crate) members: MemberInventoryRead,
        pub(crate) originals:
            creators::Observer<crate::windows::member_carrier_wintun::native::OriginalWintun>,
        // SAME original rows journal backend/view, retained before construction.
        // Cleanup resolves its canonical view, never opens/imports another owner.
        pub(crate) files: NativeSessionFiles,
    }

    /// Raw canonical parts, NOT NativeCarrierRoot's retaining Drop wrapper.
    /// Empty/partial fields are unknown, not absence or destructor permission.
    pub(crate) struct NativeCarrierTerminalResources<'a> {
        run: Option<Rc<ReadyRun>>,
        pub(crate) construction: Option<NativeConstructionSlot<'a, CarrierReadyGate>>,
        pub(crate) rows: Option<NativeRows>,
        pub(crate) row_capture: Option<NativeCapture>,
        stopped_capture: Option<NativeStoppedCapture>,
        pub(crate) row_capture_attempted: bool,
        // Factual original initial invocation only; never the missing CAS ACK.
        pub(crate) initial_capture_original: Option<Rc<rows::RowRecordReadPin>>,
        pub(crate) original_rows: Option<Rc<rows::RowRecordReadPin>>,
        pub(crate) lifecycle: Option<Rc<CarrierGateUpgrade>>,
        pub(crate) source: Option<Rc<NativeSourceRead>>,
        pub(crate) closing: Option<
            Rc<crate::windows::member_carrier_coordinator::OriginalReadCapture<NativeClosingRead>>,
        >,
        pub(crate) meta: Option<Meta>,
        pub(crate) proof: Option<InterfaceProof>,
    }
    impl NativeCarrierTerminalResources<'_> {
        /// Original pregraph C rows under the caller's already-held terminal
        /// Retired SDK lease. No ResourceRowsRead, Source or old NIC is minted.
        pub(crate) fn verify_pregraph_original_rows(
            &self,
            context: &crate::member_carrier_native_ownership::Context,
            retired: &RetiredCarrierRead,
            bindings: &crate::windows::member_carrier_guard::Bindings,
        ) -> Result<()> {
            let meta = self.meta.as_ref().ok_or(CarrierError::Pending)?;
            let lifecycle = self.lifecycle.as_ref().ok_or(CarrierError::Pending)?;
            if meta.scope.context != *context
                || lifecycle.attempted()
                || !std::ptr::eq(lifecycle.retired_pin()?.as_ref(), retired)
                || self.construction.is_some()
                || self.row_capture.is_some()
                || self.stopped_capture.is_some()
                || self
                    .source
                    .as_ref()
                    .is_some_and(|s| !retired.matches_source_origin(s))
            {
                return Err(CarrierError::Conflict);
            }
            retired
                .inspect_terminal_history_in_bracket(|history| {
                    if history.is_empty() {
                        Ok(())
                    } else {
                        Err(wintun::Error::Conflict)
                    }
                })
                .map_err(denied)?;
            let row = self.original_rows.as_ref().ok_or(CarrierError::Pending)?;
            verify_row_owner_original(self.rows.as_ref().ok_or(CarrierError::Pending)?, row)?;
            let c = bindings.carrier.as_ref().ok_or(CarrierError::Conflict)?;
            if bindings.scope != context.intent.scope
                || c.identity.scope != context.intent.scope
                || c.sources
                    != context
                        .intent
                        .addresses
                        .iter()
                        .map(|a| a.addr())
                        .collect::<Vec<_>>()
                || bindings.egress.iter().any(Option::is_some)
            {
                return Err(CarrierError::Conflict);
            }
            row.with_cleanup_record(
                &context.intent.scope,
                context.provenance.network_epoch,
                |facts| {
                    let before = meta
                        .runtime
                        .record(context, RecordKind::CarrierRows)
                        .map_err(|_| rows::Error::Journal)?;
                    let protected = rows::Record::decode(&before)?;
                    compare_pregraph_stopped_rows(
                        context,
                        c.identity.proof,
                        facts.binding,
                        facts.acknowledged,
                        &protected,
                    )
                    .map_err(|_| rows::Error::Conflict)?;
                    if meta
                        .runtime
                        .record(context, RecordKind::CarrierRows)
                        .map_err(|_| rows::Error::Journal)?
                        != before
                    {
                        return Err(rows::Error::Conflict);
                    }
                    Ok(())
                },
            )
            .map_err(denied)
        }
        /// Owning disposition only under the actual Startup-issued Never proof.
        /// An empty-looking partial Create/capture can NEVER select this lane.
        pub(crate) fn verify_zero_effect_terminal(
            &self,
            proof: &dyn crate::windows::member_carrier_pair_io::native::NativeZeroEffectTerminalProof,
            original: &Rc<
                crate::windows::member_carrier_pair_store::native_store::NativePairIntentRead,
            >,
            expected: &crate::member_carrier_pair::Record,
        ) -> Result<()> {
            proof.verify_original(original, expected)?;
            self.verify_unconstructed_shape()?;
            proof.verify_original(original, expected)
        }
        /// Shape/provenance component only. An actual original terminal issuer
        /// must independently authenticate Never or completed no-constructor
        /// module disposition; this method grants no native or Drop authority.
        pub(crate) fn verify_unconstructed_shape(&self) -> Result<()> {
            let run = self.run.as_ref().ok_or(CarrierError::Pending)?;
            let lifecycle = self.lifecycle.as_ref().ok_or(CarrierError::Pending)?;
            if run.attempted.get()
                || run.completed.get()
                || lifecycle.attempted()
                || self.construction.is_some()
                || self.rows.is_some()
                || self.row_capture.is_some()
                || self.stopped_capture.is_some()
                || self.row_capture_attempted
                || self.initial_capture_original.is_some()
                || self.original_rows.is_some()
                || self.source.is_some()
                || self.meta.is_some()
                || self.proof.is_some()
            {
                return Err(CarrierError::Conflict);
            }
            Ok(())
        }
        fn empty() -> Self {
            Self {
                run: None,
                construction: None,
                rows: None,
                row_capture: None,
                stopped_capture: None,
                row_capture_attempted: false,
                initial_capture_original: None,
                original_rows: None,
                lifecycle: None,
                source: None,
                closing: None,
                meta: None,
                proof: None,
            }
        }
        pub(crate) fn with_original_loaded_module_for_terminal(
            &self,
            call: impl FnOnce(
                &mut crate::windows::member_carrier_module::native::LoadedWintun,
            ) -> std::io::Result<()>,
        ) -> std::io::Result<()> {
            self.construction
                .as_ref()
                .ok_or_else(|| std::io::Error::other("carrier_terminal_construction_missing"))?
                .with_original_loaded_module_for_terminal(call)
        }
        /// Pure SAME stopped-capture transfer in the actual Retired/protected
        /// rows callback. No Source/Authority/journal/old-NIC query or permission
        /// is supplied. Every partial owning return stays in THIS raw root.
        pub(crate) fn drain_stopped_partial_rows_in_retired(
            &mut self,
            retired: &RetiredCarrierRead,
            registered: &Rc<crate::windows::member_carrier_runtime::native::NativeResourceRowsRead>,
            facts: &crate::windows::member_carrier_runtime::native::NativeResourceRowsFacts,
            context: &crate::member_carrier_native_ownership::Context,
        ) -> std::io::Result<()> {
            let conflict = || std::io::Error::other("terminal_partial_row_original_missing");
            retired
                .inspect_terminal_history_in_bracket(|_| Ok(()))
                .map_err(|_| conflict())?;
            if self.rows.is_some() {
                if self.row_capture.is_some() || self.stopped_capture.is_some() {
                    return Err(conflict());
                }
                return self.verify_terminal_row_original(registered, facts, context);
            }
            let original = self.original_rows.as_ref().ok_or_else(conflict)?;
            let observed = facts.rows[0].as_ref().ok_or_else(conflict)?;
            if !registered.matches_row_original(rows::Role::Carrier, original)
                || observed.observed.is_some()
                || observed.binding != *original.binding_original()
            {
                return Err(conflict());
            }
            original
                .with_cleanup_record(
                    &context.intent.scope,
                    context.provenance.network_epoch,
                    |actual| {
                        if actual.acknowledged != &observed.acknowledged
                            || actual.acknowledged.phase != rows::Phase::Stopped
                            || actual.acknowledged.pending.is_some()
                        {
                            return Err(rows::Error::Conflict);
                        }
                        Ok(())
                    },
                )
                .map_err(|_| conflict())?;
            let capture = self.row_capture.as_mut().ok_or_else(conflict)?;
            capture
                .drain_stopped_into(original, &mut self.stopped_capture)
                .map_err(|_| conflict())?;
            let stopped = self.stopped_capture.as_mut().ok_or_else(conflict)?;
            capture
                .verify_stopped_drained_into(original, stopped)
                .map_err(|_| conflict())?;
            stopped
                .drain_owner_into(&mut self.rows)
                .map_err(|_| conflict())?;
            stopped
                .verify_owner_drained_into(self.rows.as_ref().ok_or_else(conflict)?)
                .map_err(|_| conflict())?;
            // Only supplier-authenticated empty wrappers are removed. The SAME
            // raw owner/ACK remains in C before any subsequent postflight.
            drop(self.row_capture.take());
            drop(self.stopped_capture.take());
            self.verify_terminal_row_original(registered, facts, context)
        }
        /// Factual SAME actual owner/last ACK join in an already-held terminal
        /// Retired/rows/protected bracket. No Source, journal, Authority or SDK
        /// reentry and no destructor/module permission is granted here.
        pub(crate) fn verify_terminal_row_original(
            &self,
            registered: &Rc<crate::windows::member_carrier_runtime::native::NativeResourceRowsRead>,
            facts: &crate::windows::member_carrier_runtime::native::NativeResourceRowsFacts,
            context: &crate::member_carrier_native_ownership::Context,
        ) -> std::io::Result<()> {
            let conflict = || std::io::Error::other("terminal_carrier_original_row_missing");
            // An unresolved partial capture is NOT a known inert owner. Its
            // cleanup may produce a new ACK, but raw terminal owner drain must
            // still be authenticated by the Rows owner before destruction.
            let owner = self.rows.as_ref().ok_or_else(conflict)?;
            let pin = self.original_rows.as_ref().ok_or_else(conflict)?;
            let row = facts.rows[0].as_ref().ok_or_else(conflict)?;
            if self.construction.is_some()
                || self.row_capture.is_some()
                || self.stopped_capture.is_some()
                || self
                    .meta
                    .as_ref()
                    .is_none_or(|m| m.scope.context != *context)
                || !registered.matches_row_original(rows::Role::Carrier, pin)
                || !owner
                    .record_read_pin()
                    .map_err(|_| conflict())?
                    .same_original(pin)
                || row.observed.is_some()
                || row.binding != *pin.binding_original()
            {
                return Err(conflict());
            }
            pin.with_cleanup_record(
                &context.intent.scope,
                context.provenance.network_epoch,
                |actual| {
                    if actual.acknowledged != &row.acknowledged {
                        return Err(rows::Error::Conflict);
                    }
                    crate::windows::member_carrier_coordinator_rows::compare(
                        actual.binding,
                        actual.acknowledged,
                        &actual.acknowledged.current,
                        crate::windows::member_carrier_coordinator_rows::Stage::Stopped,
                    )
                },
            )
            .map_err(|_| conflict())
        }
    }

    /// SAME original resources for the actual actor's A/B preparation. These
    /// readers still require their original Runtime/Calling on EVERY read;
    /// returning them is not a Member/row/WFP permission or a readiness boolean.
    pub(crate) struct NativeCarrierPins {
        pub(crate) context: crate::member_carrier_native_ownership::Context,
        pub(crate) runtime: RuntimeRead,
        pub(crate) image: OriginalImage,
        pub(crate) wintun: Rc<WintunSource>,
        pub(crate) members: MemberInventoryRead,
        pub(crate) originals: crate::windows::member_carrier_creators::Observer<
            crate::windows::member_carrier_wintun::native::OriginalWintun,
        >,
        pub(crate) source: Rc<NativeSourceRead>,
        pub(crate) carrier_rows: Rc<rows::RowRecordReadPin>,
        pub(crate) supervisor: Rc<NativeDeadline>,
        pub(crate) cancelled: Arc<AtomicBool>,
    }

    /// The caller creates this before ANY supervised C create. All owning
    /// objects occupy this root before their next fallible native/postflight
    /// boundary. Neither successful metadata nor equal JSON seeds an owner.
    /// The product factory remains OFF; full member/permit/cleanup integration
    /// must complete before this concrete sub-path is enabled.
    pub(crate) struct NativeCarrierRoot<'a> {
        run: Rc<ReadyRun>,
        construction: Option<NativeConstructionSlot<'a, CarrierReadyGate>>,
        rows: Option<NativeRows>,
        row_capture: Option<NativeCapture>,
        stopped_capture: Option<NativeStoppedCapture>,
        row_capture_attempted: bool,
        initial_capture_original: Option<Rc<rows::RowRecordReadPin>>,
        original_rows: Option<Rc<rows::RowRecordReadPin>>,
        lifecycle: Rc<CarrierGateUpgrade>,
        source: Option<Rc<NativeSourceRead>>,
        closing:
            Rc<crate::windows::member_carrier_coordinator::OriginalReadCapture<NativeClosingRead>>,
        closing_attempted: bool,
        meta: Option<Meta>,
        proof: Option<InterfaceProof>,
        ready: bool,
        terminal_attempted: bool,
        terminal_transferred: bool,
    }
    struct RootCall<'r, 'a> {
        root: &'r mut NativeCarrierRoot<'a>,
        completed: bool,
    }
    impl Drop for RootCall<'_, '_> {
        fn drop(&mut self) {
            if !self.completed {
                self.root.run.revoked.set(true);
                self.root.ready = false;
                self.root.lifecycle.retire_forward();
                if let Some(construction) = &self.root.construction {
                    construction.revoke_forward();
                }
            }
        }
    }
    impl<'a> NativeCarrierRoot<'a> {
        /// SAME actual destination read; proves empty wrapper only. Raw row/
        /// construction/source/lifecycle originals remain retained separately,
        /// and cannot be destroyed without actual terminal resource G/ACKs.
        pub(crate) fn verify_terminal_drained_into(
            &self,
            raw: &NativeCarrierTerminalResources<'a>,
        ) -> Result<()> {
            if !self.terminal_attempted
                || !self.terminal_transferred
                || self.construction.is_some()
                || self.rows.is_some()
                || self.row_capture.is_some()
                || self.stopped_capture.is_some()
                || self.initial_capture_original.is_some()
                || self.original_rows.is_some()
                || self.source.is_some()
                || self.meta.is_some()
                || self.proof.is_some()
                || raw
                    .run
                    .as_ref()
                    .is_none_or(|original| !Rc::ptr_eq(original, &self.run))
                || raw
                    .lifecycle
                    .as_ref()
                    .is_none_or(|original| !Rc::ptr_eq(original, &self.lifecycle))
                || raw
                    .closing
                    .as_ref()
                    .is_none_or(|original| !Rc::ptr_eq(original, &self.closing))
            {
                return Err(CarrierError::Conflict);
            }
            Ok(())
        }
        /// Destination must already be under caller-held TerminalResources.
        /// All canonical owners move before any subsequent fallible terminal
        /// G/postflight. This retires forward flow, NEVER certifies disarm.
        pub(crate) fn drain_terminal_into(
            &mut self,
            destination: &mut Option<NativeCarrierTerminalResources<'a>>,
        ) -> Result<()> {
            self.ready = false;
            self.run.revoked.set(true);
            self.lifecycle.retire_forward();
            if let Some(construction) = &self.construction {
                construction.revoke_forward();
            }
            drain_before_postflight(
                &mut self.terminal_attempted,
                destination,
                NativeCarrierTerminalResources::empty,
                |raw| {
                    raw.run = Some(self.run.clone());
                    raw.lifecycle = Some(self.lifecycle.clone());
                    raw.closing = Some(self.closing.clone());
                    raw.construction = self.construction.take();
                    raw.rows = self.rows.take();
                    raw.row_capture = self.row_capture.take();
                    raw.stopped_capture = self.stopped_capture.take();
                    raw.row_capture_attempted = self.row_capture_attempted;
                    raw.initial_capture_original = self.initial_capture_original.take();
                    raw.original_rows = self.original_rows.take();
                    raw.source = self.source.take();
                    raw.meta = self.meta.take();
                    raw.proof = self.proof.take();
                    self.terminal_transferred = true;
                },
                |_| Ok(()),
            )
        }
        pub(crate) fn member_pins(&self) -> Result<NativeCarrierPins> {
            self.run.published(self.ready)?;
            let meta = self.meta.as_ref().ok_or(CarrierError::Pending)?;
            Ok(NativeCarrierPins {
                context: meta.scope.context.clone(),
                runtime: meta.runtime.read_pin()?,
                image: meta.image.read_pin().map_err(denied)?,
                wintun: meta.wintun.clone(),
                members: meta.members.read_pin(),
                originals: meta.originals.clone(),
                source: self.source.as_ref().ok_or(CarrierError::Pending)?.clone(),
                carrier_rows: self.carrier_row_pin()?,
                supervisor: meta.supervisor.clone(),
                cancelled: meta.cancelled.clone(),
            })
        }
        pub(crate) fn empty() -> Self {
            let run = Rc::new(ReadyRun::new());
            Self {
                lifecycle: Rc::new(CarrierGateUpgrade::new(run.revoked.clone())),
                closing: Rc::new(
                    crate::windows::member_carrier_coordinator::OriginalReadCapture::new(
                        run.revoked.clone(),
                    ),
                ),
                run,
                construction: None,
                rows: None,
                row_capture: None,
                stopped_capture: None,
                row_capture_attempted: false,
                initial_capture_original: None,
                original_rows: None,
                source: None,
                closing_attempted: false,
                meta: None,
                proof: None,
                ready: false,
                terminal_attempted: false,
                terminal_transferred: false,
            }
        }
        /// Factual original ACK only, also available after capture postflight
        /// failure. The caller must supply its independent Closing/runtime/SDK
        /// bracket for cleanup; this accessor grants no ownership or effects.
        pub(crate) fn carrier_row_pin(&self) -> Result<Rc<rows::RowRecordReadPin>> {
            self.original_rows
                .as_ref()
                .cloned()
                .ok_or(CarrierError::Pending)
        }
        /// Pure original-envelope comparison for the prepared-member terminal
        /// reader. No files, Authority, Source, SDK or Calling reentry and no
        /// absence/effect/destructor permission. The outer caller separately
        /// authenticates its whole Pair/Calling/keys/full terminal SDK bracket.
        pub(crate) fn verify_member_terminal_original_inputs(
            &self,
            runtime: &RuntimeRead,
            context: &crate::member_carrier_native_ownership::Context,
            carrier_source: &Rc<WintunSource>,
            supervisor: &Rc<NativeDeadline>,
        ) -> Result<()> {
            let meta = self.meta.as_ref().ok_or(CarrierError::Pending)?;
            if self.terminal_attempted
                || meta.scope.context != *context
                || !meta.runtime.same_original_runtime(runtime)
                || !Rc::ptr_eq(&meta.wintun, carrier_source)
                || !Rc::ptr_eq(&meta.supervisor, supervisor)
            {
                return Err(CarrierError::Conflict);
            }
            Ok(())
        }
        /// SAME original once-close factual reader. G retains only a Weak to
        /// this actor-rooted Rc; no lookup, equal replacement or native effect.
        pub(crate) fn retired_pin(&self) -> Result<Rc<RetiredCarrierRead>> {
            // The SAME actor-rooted slot is filled by the actual gate hook
            // inside native AfterClose, not by a later reader constructor.
            self.lifecycle.retired_pin()
        }
        pub(crate) fn prepublication_terminal_read(&self) -> Result<PrepublicationTerminalRead> {
            if self.terminal_attempted || self.source.is_some() || self.lifecycle.attempted() {
                return Err(CarrierError::Retired);
            }
            self.pregraph_terminal_read()
        }
        /// Actual closed origin for an un-upgraded C, including successful
        /// Ready publication before graph attachment. Source is compared by
        /// its SAME opaque origin only, never reread as a historical NIC.
        pub(crate) fn pregraph_terminal_read(&self) -> Result<PrepublicationTerminalRead> {
            if self.terminal_attempted || self.lifecycle.attempted() {
                return Err(CarrierError::Retired);
            }
            match select_closed_original(
                self.lifecycle.retired_pin(),
                self.lifecycle.unpublished_pin(),
            )? {
                ClosedOriginal::Published(original) => {
                    if self
                        .source
                        .as_ref()
                        .is_some_and(|source| !original.matches_source_origin(source))
                    {
                        return Err(CarrierError::Conflict);
                    }
                    Ok(PrepublicationTerminalRead::Published(original))
                }
                ClosedOriginal::Unpublished(original) => {
                    if self.source.is_some() {
                        return Err(CarrierError::Conflict);
                    }
                    Ok(PrepublicationTerminalRead::Unpublished(original))
                }
            }
        }
        /// Whole Calling is supplied by Startup. This lane cannot furnish a
        /// provider binding, Source, row ACK, native effect or destructor grant.
        pub(crate) fn inspect_unpublished_terminal_in_call<T>(
            &mut self,
            pair: &Rc<NativePairIntentRead>,
            expected: &PairRecord,
            inspect: impl FnOnce() -> Result<T>,
        ) -> Result<T> {
            if self.terminal_attempted
                || self.source.is_some()
                || self.lifecycle.attempted()
                || self.row_capture_attempted
                || self.row_capture.is_some()
                || self.initial_capture_original.is_some()
                || self.rows.is_some()
                || self.original_rows.is_some()
                || self.proof.is_some()
                || self.lifecycle.retired_pin().is_ok()
            {
                return Err(CarrierError::Conflict);
            }
            let original = self.lifecycle.unpublished_pin()?;
            let meta = self.meta.as_ref().ok_or(CarrierError::Pending)?;
            let context = &meta.scope.context;
            compare_prepublication_terminal_origin(context, expected, None)?;
            if !pair.matches_runtime(&meta.runtime) {
                return Err(CarrierError::Conflict);
            }
            let (carrier, authority) = self
                .construction
                .as_mut()
                .ok_or(CarrierError::Pending)?
                .retained_parts()
                .components
                .as_mut()
                .ok_or(CarrierError::Pending)?;
            authority
                .verify_unpublished_closed_original_in_call(&original)
                .map_err(denied)?;
            let sample = || -> Result<Vec<u8>> {
                carrier
                    .session_end_read()
                    .verify_never_started()
                    .map_err(denied)?;
                pair.verify_cleanup_entry_for(&meta.runtime, context, expected)
                    .map_err(denied)?;
                if meta
                    .runtime
                    .optional_records(
                        context,
                        &[
                            RecordKind::CarrierRows,
                            RecordKind::MemberARows,
                            RecordKind::MemberBRows,
                            RecordKind::CarrierGuard,
                            RecordKind::Network,
                        ],
                    )?
                    .iter()
                    .any(Option::is_some)
                {
                    return Err(CarrierError::Conflict);
                }
                meta.runtime.record(context, RecordKind::Pair)
            };
            let before = sample()?;
            let value = original
                .inspect_terminal(|| {
                    if sample().map_err(native_denied)? != before {
                        return Err(wintun::Error::Conflict);
                    }
                    let value = inspect().map_err(native_denied)?;
                    if sample().map_err(native_denied)? != before {
                        return Err(wintun::Error::Conflict);
                    }
                    Ok(value)
                })
                .map_err(denied)?;
            if sample()? != before {
                return Err(CarrierError::Conflict);
            }
            authority
                .verify_unpublished_closed_original_in_call(&original)
                .map_err(denied)?;
            Ok(value)
        }
        /// Actual SAME source-origin Closing reader, also retained after an
        /// unsuccessful capture postflight. Getter facts supply no permission.
        pub(crate) fn closing_pin(&self) -> Result<Rc<NativeClosingRead>> {
            self.closing.pin()
        }
        /// Acquire ONE original Closing Rc after the actual journal Closing
        /// transition, inside the caller's actual supervised cleanup Calling.
        /// A full graph's `register` MUST weak-register THIS Rc in its actual
        /// gates; pregraph reads have only this Ready retention root and grant
        /// no delegate effect. The callback must never reenter the Authority.
        pub(crate) fn capture_closing_in_call(
            &mut self,
            current: Rc<NativePairIntentRead>,
            expected: &PairRecord,
            register: impl FnOnce(&Rc<NativeClosingRead>) -> wintun::Result<()>,
        ) -> Result<Rc<NativeClosingRead>> {
            let mut attempt = RootCall {
                root: self,
                completed: false,
            };
            let root = &mut attempt.root;
            root.run.revoked.set(true);
            root.ready = false;
            root.lifecycle.retire_forward();
            begin_original_capture(&mut root.closing_attempted)?;
            let meta = root.meta.as_ref().ok_or(CarrierError::Pending)?;
            if expected.phase != crate::member_carrier_pair::Phase::Closing
                || !current.matches_runtime(&meta.runtime)
            {
                return Err(CarrierError::Conflict);
            }
            current
                .inspect_cleanup_effect(
                    &meta.runtime,
                    &meta.supervisor,
                    expected,
                    expected.stop_stage,
                    |_| Ok(()),
                )
                .map_err(denied)?;
            let source = root.source.as_ref().ok_or(CarrierError::Pending)?.clone();
            let capture = root.closing.clone();
            let construction = root.construction.as_mut().ok_or(CarrierError::Pending)?;
            construction.revoke_forward();
            let (_, authority) = construction
                .retained_parts()
                .components
                .as_mut()
                .ok_or(CarrierError::Pending)?;
            authority
                .select_pair_intent(current.clone(), expected)
                .map_err(denied)?;
            let original = authority
                .closing_read_with_pin(|pin| {
                    capture
                        .capture(pin, |original| {
                            // The actor Rc is installed BEFORE even this pure origin
                            // comparison or the mandatory weak-registration callback.
                            if !original.matches_source_origin(&source) {
                                return Err(CarrierError::Conflict);
                            }
                            register(original).map_err(denied)
                        })
                        .map_err(native_denied)
                })
                .map_err(denied)?;
            capture.confirm(&original)?;
            current
                .inspect_cleanup_effect(
                    &meta.runtime,
                    &meta.supervisor,
                    expected,
                    expected.stop_stage,
                    |_| Ok(()),
                )
                .map_err(denied)?;
            attempt.completed = true;
            Ok(original)
        }
        /// One-shot caller-rooted registration, not a permission or grant.
        /// Invoke inside the SAME actual NativeDeadline Calling window.
        ///
        /// # Safety
        /// `full` MUST be Main's actual full-resource NativeLifecycleGate built
        /// from THIS root's unchanged source Rc, original row ACK, runtime,
        /// context, original registry/member inventory and supervisor. Its
        /// unsafe mandatory contract must authenticate current opaque Pair and
        /// full resources at every effect. Registration is NOT a substitute.
        /// The session handoff is the SAME bootstrap pin, now possibly Live;
        /// retain it before validation, never register an equal new session.
        pub(crate) unsafe fn upgrade_lifecycle_gate(
            &mut self,
            full: Box<dyn NativeLifecycleGate>,
            current: Rc<NativePairIntentRead>,
            expected: &PairRecord,
        ) -> Result<()> {
            let mut attempt = RootCall {
                root: self,
                completed: false,
            };
            let root = &mut attempt.root;
            let upgrade = root.lifecycle.clone();
            // The actual Box occupies the caller root BEFORE all fallible
            // readiness, provenance, Calling, Pair and full-G postflight reads.
            upgrade
                .register(full, |gate| {
                    root.run.published(root.ready).map_err(native_denied)?;
                    let meta = root.meta.as_ref().ok_or(wintun::Error::Pending)?;
                    if !Rc::ptr_eq(gate.supervisor(), &meta.supervisor)
                        || !current.matches_runtime(&meta.runtime)
                        || expected.scope != meta.scope.context.intent.scope
                        || expected.provenance != meta.scope.context.provenance
                        || expected.addresses != meta.scope.context.intent.addresses
                    {
                        return Err(wintun::Error::Conflict);
                    }
                    let deadline = meta.supervisor.read_pin().map_err(native_denied)?;
                    deadline
                        .verify_runtime_call(&meta.supervisor, &meta.runtime, &meta.scope.context)
                        .map_err(native_denied)?;
                    meta.runtime
                        .verify_source(&meta.wintun)
                        .map_err(native_denied)?;
                    meta.image
                        .verify_live_runtime(&meta.runtime)
                        .map_err(native_denied)?;
                    meta.members
                        .matches_original_runtime_image(&meta.runtime, &meta.image)
                        .map_err(native_denied)?;
                    root.carrier_row_pin().map_err(native_denied)?;
                    let source = root.source.as_ref().ok_or(wintun::Error::Pending)?;
                    source.inspect_bindings(|bindings| {
                        if bindings.carrier.as_ref().map(|c| c.identity.proof) != root.proof {
                            return Err(wintun::Error::Conflict);
                        }
                        Ok(())
                    })?;
                    let effect = expected.pending.ok_or(wintun::Error::Pending)?;
                    current
                        .inspect_effect(&meta.runtime, &meta.supervisor, expected, effect, |_| {
                            Ok(())
                        })
                        .map_err(native_denied)?;
                    gate.select_pair_intent(current.clone(), expected)?;
                    gate.authorize(&meta.scope, wintun::Stage::Observe, &meta.originals)?;
                    // Sequential Pair brackets: delegate authorization may read the
                    // SAME opaque Pair itself; never hold its busy callback over G.
                    current
                        .inspect_effect(&meta.runtime, &meta.supervisor, expected, effect, |_| {
                            Ok(())
                        })
                        .map_err(native_denied)?;
                    deadline
                        .verify_call(&meta.supervisor, &meta.scope.context)
                        .map_err(native_denied)?;
                    if !Rc::ptr_eq(gate.supervisor(), &meta.supervisor) {
                        return Err(wintun::Error::Conflict);
                    }
                    Ok(())
                })
                .map_err(denied)?;
            // Store only the caller's actual current opaque window. The source
            // and original ACK objects are never replaced or revived.
            let meta = root.meta.as_mut().ok_or(CarrierError::Pending)?;
            meta.pair = current;
            meta.expected = expected.clone();
            attempt.completed = true;
            Ok(())
        }
        /// Bounded late drain inside the caller's actual Calling operation.
        /// Every native read/receive requires the registered full gate, which
        /// receives THIS current opaque Pair before every authorization.
        pub(crate) fn drain_in_call(
            &mut self,
            current: Rc<NativePairIntentRead>,
            expected: &PairRecord,
            milliseconds: u32,
            packets: u32,
        ) -> Result<wintun::Drain> {
            let mut attempt = RootCall {
                root: self,
                completed: false,
            };
            let root = &mut attempt.root;
            root.run.published(root.ready)?;
            root.lifecycle
                .require_forward_registration()
                .map_err(denied)?;
            let meta = root.meta.as_ref().ok_or(CarrierError::Pending)?;
            let effect = expected.pending.ok_or(CarrierError::Pending)?;
            current
                .inspect_effect(
                    &meta.runtime,
                    &meta.supervisor,
                    expected,
                    effect,
                    |_| Ok(()),
                )
                .map_err(denied)?;
            let construction = root.construction.as_mut().ok_or(CarrierError::Pending)?;
            let (carrier, authority) = construction
                .retained_parts()
                .components
                .as_mut()
                .ok_or(CarrierError::Pending)?;
            authority
                .select_pair_intent(current.clone(), expected)
                .map_err(denied)?;
            let drained = carrier
                .drain(&meta.cancelled, milliseconds, packets)
                .map_err(denied)?;
            current
                .inspect_effect(
                    &meta.runtime,
                    &meta.supervisor,
                    expected,
                    effect,
                    |_| Ok(()),
                )
                .map_err(denied)?;
            attempt.completed = true;
            Ok(drained)
        }
        /// SAME original C authority only. Returning this alias grants no row
        /// effect: each locked/authorize path still enters the mandatory full
        /// gate and freshly authenticates the selected current opaque Pair.
        /// Callers use for_member() for actual addressless A/B RowOwners.
        pub(crate) fn rows_authority_in_call(
            &mut self,
            current: Rc<NativePairIntentRead>,
            expected: &PairRecord,
        ) -> Result<NativeRowsAuthority<CarrierReadyGate>> {
            let mut attempt = RootCall {
                root: self,
                completed: false,
            };
            let root = &mut attempt.root;
            root.run.published(root.ready)?;
            root.lifecycle
                .require_forward_registration()
                .map_err(denied)?;
            let meta = root.meta.as_ref().ok_or(CarrierError::Pending)?;
            let effect = expected.pending.ok_or(CarrierError::Pending)?;
            current
                .inspect_effect(
                    &meta.runtime,
                    &meta.supervisor,
                    expected,
                    effect,
                    |_| Ok(()),
                )
                .map_err(denied)?;
            let construction = root.construction.as_mut().ok_or(CarrierError::Pending)?;
            let (_, authority) = construction
                .retained_parts()
                .components
                .as_mut()
                .ok_or(CarrierError::Pending)?;
            authority
                .select_pair_intent(current.clone(), expected)
                .map_err(denied)?;
            let read = authority.read_pin();
            current
                .inspect_effect(
                    &meta.runtime,
                    &meta.supervisor,
                    expected,
                    effect,
                    |_| Ok(()),
                )
                .map_err(denied)?;
            attempt.completed = true;
            Ok(read)
        }
        /// Actual retained C RowOwner delta, under the caller's Calling. Full
        /// G must prove bases/network/held-port order; policy/JSON is no grant.
        pub(crate) fn change_interface_in_call(
            &mut self,
            current: Rc<NativePairIntentRead>,
            expected: &PairRecord,
            policy: rows::InterfacePolicy,
        ) -> Result<()> {
            let mut attempt = RootCall {
                root: self,
                completed: false,
            };
            let root = &mut attempt.root;
            root.rows_authority_in_call(current.clone(), expected)?;
            root.rows
                .as_mut()
                .ok_or(CarrierError::Pending)?
                .change_interface(policy)
                .map_err(denied)?;
            let meta = root.meta.as_ref().ok_or(CarrierError::Pending)?;
            current
                .inspect_effect(
                    &meta.runtime,
                    &meta.supervisor,
                    expected,
                    expected.pending.ok_or(CarrierError::Pending)?,
                    |_| Ok(()),
                )
                .map_err(denied)?;
            attempt.completed = true;
            Ok(())
        }
        /// Stage 3 changes ONLY the original C interface back to its baseline.
        /// Its SAME created VPN-IP survives until stage 6. No nested supervisor,
        /// no reconstruction/adoption and no forward row-read pin rearming.
        pub(crate) fn restore_interface_in_call(
            &mut self,
            current: Rc<NativePairIntentRead>,
            expected: &PairRecord,
        ) -> Result<()> {
            let mut attempt = RootCall {
                root: self,
                completed: false,
            };
            let root = &mut attempt.root;
            root.run.revoked.set(true);
            root.ready = false;
            root.lifecycle.retire_forward();
            let meta = root.meta.as_ref().ok_or(CarrierError::Pending)?;
            current
                .inspect_cleanup_effect(
                    &meta.runtime,
                    &meta.supervisor,
                    expected,
                    expected.stop_stage,
                    |_| Ok(()),
                )
                .map_err(denied)?;
            // Cold C may exist before Source/full-G publication. Select its
            // SAME original cleanup scope and freshly authenticate its live
            // binding; never infer the native owner from Pair.carrier absence.
            let (_, authority) = root
                .construction
                .as_mut()
                .ok_or(CarrierError::Pending)?
                .retained_parts()
                .components
                .as_mut()
                .ok_or(CarrierError::Pending)?;
            authority
                .select_pair_intent(current.clone(), expected)
                .map_err(denied)?;
            let binding = authority.binding().map_err(denied)?;
            root.proof = Some(InterfaceProof {
                guid: binding.guid,
                index: binding.key.index,
                luid: binding.key.luid,
            });
            if root.lifecycle.attempted() {
                full_interface_cleanup_boundary(&meta.scope.context, expected, root.proof)?;
            } else if stop_boundary(&meta.scope.context, expected, root.proof)?
                != StopStep::Interface
            {
                return Err(CarrierError::Conflict);
            }
            root.enter_rows_storage_cleanup_in_call(&current, expected)?;
            let meta = root.meta.as_ref().ok_or(CarrierError::Pending)?;
            let construction = root.construction.as_mut().ok_or(CarrierError::Pending)?;
            construction.revoke_forward();
            let (_, authority) = construction
                .retained_parts()
                .components
                .as_mut()
                .ok_or(CarrierError::Pending)?;
            authority
                .select_pair_intent(current.clone(), expected)
                .map_err(denied)?;
            let row_original = root.original_rows.as_ref().ok_or(CarrierError::Pending)?;
            with_retained_or_partial(
                &mut root.rows,
                &mut root.row_capture,
                |capture| capture.owner_mut().map_err(denied),
                |owner| {
                    verify_row_owner_original(owner, row_original)?;
                    owner.restore_interface_for_cleanup().map_err(denied)
                },
            )?;
            current
                .inspect_cleanup_effect(
                    &meta.runtime,
                    &meta.supervisor,
                    expected,
                    expected.stop_stage,
                    |_| Ok(()),
                )
                .map_err(denied)?;
            attempt.completed = true;
            Ok(())
        }
        /// SAME actual assembly's current borrowed key ACK determines scope.
        /// The precreation read and each existing C step use the SAME original
        /// Pair/supervisor. Readiness follows all independently checked returns.
        pub(crate) fn create_ready(
            &mut self,
            assembly: &mut NativeAssemblySlot,
            lock: &mut KeyLock,
            files: &NativeSessionFiles,
        ) -> Result<InterfaceProof> {
            let run = self.run.clone();
            let mut flight = RunAttempt {
                revoked: run.revoked.clone(),
                succeeded: false,
            };
            if run.attempted.get() || run.revoked.get() || self.ready {
                return Err(CarrierError::Retired);
            }
            assembly.with_carrier_precreation(lock, |assets, receipt, scope| {
                let original = assets.as_ref().ok_or(CarrierError::Pending)?;
                let supervisor = original.supervisor.clone();
                let intent = original.pair_intent.clone();
                let expected = original.expected.clone();
                let cancelled = original.cancelled.clone();
                let mut prerequisite = Some(receipt);
                run.execute_in(
                    &mut |call| {
                        supervisor.run_intent(
                            &scope.context,
                            &intent,
                            &expected,
                            crate::member_carrier_pair::Effect::CarrierReady,
                            || {
                                if cancelled.load(Ordering::SeqCst) {
                                    return Err(CarrierError::Retired);
                                }
                                call()?;
                                if cancelled.load(Ordering::SeqCst) {
                                    return Err(CarrierError::Retired);
                                }
                                Ok(())
                            },
                        )
                    },
                    |step| {
                        #[cfg(test)]
                        let label = match step {
                            ReadyStep::Construct => "C ready Construct",
                            ReadyStep::Resolve => "C ready Resolve",
                            ReadyStep::Create => "C ready Create",
                            ReadyStep::Session => "C ready Session",
                            ReadyStep::CaptureRows => "C ready CaptureRows",
                            ReadyStep::Address => "C ready Address",
                            ReadyStep::Readiness => "C ready Readiness",
                            ReadyStep::Drain => "C ready Drain",
                            ReadyStep::PublishSource => "C ready PublishSource",
                        };
                        #[cfg(test)]
                        super::super::member_carrier_factory_test_os::trace_step(label);
                        self.step(step, assets, &scope, &mut prerequisite, files)
                    },
                )
            })?;
            if run.revoked.get() {
                return Err(CarrierError::Retired);
            }
            // Captured INSIDE the SAME Calling from actual source read. Never
            // invoke a native source read after its supervised callback ended.
            let proof = self.proof.ok_or(CarrierError::Pending)?;
            self.ready = true;
            flight.succeeded = true;
            Ok(proof)
        }
        /// Compatibility entry for bootstrap C-only cleanup. Once upgrade was
        /// attempted this ALWAYS delegates to full G, never a narrow fallback.
        pub(crate) fn cleanup_c_only(
            &mut self,
            original: Rc<NativePairIntentRead>,
            expected: &PairRecord,
        ) -> Result<()> {
            self.cleanup_carrier(original, expected)
        }
        /// Three distinct C Closing operations, under each current original
        /// Pair/supervisor. Actual A/B/network/guard cleanup is independently
        /// required by full G; static bases remain until final removal.
        pub(crate) fn cleanup_carrier(
            &mut self,
            original: Rc<NativePairIntentRead>,
            expected: &PairRecord,
        ) -> Result<()> {
            let mut attempt = RootCall {
                root: self,
                completed: false,
            };
            let root = &mut attempt.root;
            root.run.revoked.set(true);
            root.ready = false;
            root.lifecycle.retire_forward();
            root.construction
                .as_ref()
                .ok_or(CarrierError::Pending)?
                .revoke_forward();
            let meta = root.meta.as_ref().ok_or(CarrierError::Pending)?;
            let context = meta.scope.context.clone();
            let supervisor = meta.supervisor.clone();
            supervisor.run_cleanup(&context, &original, || {
                root.cleanup_carrier_in_call(original.clone(), expected)
            })?;
            attempt.completed = true;
            Ok(())
        }
        /// Caller already owns the SAME whole cleanup Calling. Selecting the
        /// actual Guard/G before this entry is possible without opening a
        /// second supervisor or borrowing native Authority during registration.
        pub(crate) fn cleanup_carrier_in_call(
            &mut self,
            original: Rc<NativePairIntentRead>,
            expected: &PairRecord,
        ) -> Result<()> {
            let mut attempt = RootCall {
                root: self,
                completed: false,
            };
            let root = &mut attempt.root;
            root.run.revoked.set(true);
            root.ready = false;
            root.lifecycle.retire_forward();
            let meta = root.meta.as_ref().ok_or(CarrierError::Pending)?;
            let context = meta.scope.context.clone();
            let runtime = meta.runtime.read_pin()?;
            let supervisor = meta.supervisor.clone();
            let cancelled = meta.cancelled.clone();
            if !original.matches_runtime(&runtime) {
                return Err(CarrierError::Conflict);
            }
            root.construction
                .as_ref()
                .ok_or(CarrierError::Pending)?
                .revoke_forward();
            original
                .inspect_cleanup_effect(
                    &runtime,
                    &supervisor,
                    expected,
                    expected.stop_stage,
                    |_| Ok(()),
                )
                .map_err(denied)?;
            root.enter_rows_storage_cleanup_in_call(&original, expected)?;
            root.cleanup_step(&context, &original, expected, &cancelled)?;
            original
                .inspect_cleanup_effect(
                    &runtime,
                    &supervisor,
                    expected,
                    expected.stop_stage,
                    |_| Ok(()),
                )
                .map_err(denied)?;
            attempt.completed = true;
            Ok(())
        }
        /// Storage handoff ONLY in the same retained C owner. Runtime cleanup
        /// entry must already have selected its actual birth-root cleanup view.
        /// RowOwner revokes forward pins BEFORE the fallible canonical lookup;
        /// failure/unwind never replaces the owner/ACK or grants native cleanup.
        pub(crate) fn enter_rows_storage_cleanup_in_call(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &PairRecord,
        ) -> Result<()> {
            let mut attempt = RootCall {
                root: self,
                completed: false,
            };
            let root = &mut attempt.root;
            root.run.revoked.set(true);
            root.ready = false;
            root.lifecycle.retire_forward();
            if let Some(construction) = &root.construction {
                construction.revoke_forward();
            }
            let meta = root.meta.as_ref().ok_or(CarrierError::Pending)?;
            original
                .inspect_cleanup_effect(
                    &meta.runtime,
                    &meta.supervisor,
                    expected,
                    expected.stop_stage,
                    |_| Ok(()),
                )
                .map_err(denied)?;
            // Select this SAME actual Pair/Calling before RowOwner locks its
            // creator. Issuer creation and journal handoff must not recursively
            // select G while that mutable native owner is borrowed.
            let (_, authority) = root
                .construction
                .as_mut()
                .ok_or(CarrierError::Pending)?
                .retained_parts()
                .components
                .as_mut()
                .ok_or(CarrierError::Pending)?;
            authority
                .select_pair_intent(original.clone(), expected)
                .map_err(denied)?;
            if root.original_rows.is_none() {
                // Absence selects only a REQUEST for the sealed original
                // initial invocation. It is not no-effect/ACK/close authority.
                // Failed baseline CAS retained A/K/J in this exact slot.
                if root.rows.is_some() || root.lifecycle.attempted() || root.source.is_some() {
                    return Err(CarrierError::Conflict);
                }
                let owner = root
                    .row_capture
                    .as_mut()
                    .ok_or(CarrierError::Pending)?
                    .owner_mut()
                    .map_err(denied)?;
                if root.initial_capture_original.is_none() {
                    let pin = owner.initial_capture_cleanup_pin().map_err(denied)?;
                    retain_before_postflight(
                        &mut root.initial_capture_original,
                        Rc::new(pin),
                        |original| {
                            owner
                                .inspect_original_initial_capture(|_, pin, sealed| {
                                    if !pin.same_original(original)
                                        || !sealed.matches_record_original(original)
                                    {
                                        return Err(rows::Error::Conflict);
                                    }
                                    Ok(())
                                })
                                .map_err(denied)
                        },
                    )?;
                }
                let initial = root
                    .initial_capture_original
                    .as_ref()
                    .ok_or(CarrierError::Pending)?;
                // NEW actual Calling issuer on each retry. The native authority
                // roots it before postflight; no cached token or ACK adoption.
                let issuer = owner
                    .inspect_original_initial_capture(|actual, pin, sealed| {
                        if !pin.same_original(initial) || !sealed.matches_record_original(initial) {
                            return Err(rows::Error::Conflict);
                        }
                        actual
                            .initial_capture_cleanup_write_for_original(
                                owner,
                                initial,
                                &meta.files,
                                original,
                                expected,
                            )
                            .map_err(|_| rows::Error::Conflict)
                    })
                    .map_err(denied)?;
                created_cleanup_sequence(
                    owner,
                    |owner| {
                        owner
                            .enter_storage_cleanup(|journal| {
                                journal.retain_initial_capture_cleanup_authority(issuer)
                            })
                            .map_err(denied)
                    },
                    |owner| {
                        owner
                            .enter_storage_cleanup(|journal| {
                                let canonical = meta
                                    .runtime
                                    .native_files_for_original(&meta.scope.context, &meta.files)
                                    .map_err(|_| rows::Error::Conflict)?;
                                journal
                                    .enter_initial_capture_cleanup(canonical)
                                    .map_err(|_| rows::Error::Journal)
                            })
                            .map_err(denied)
                    },
                    |owner| {
                        owner
                            .reconcile_initial_capture_for_cleanup_with_record_pin(|pin| {
                                if !pin.same_original(initial) {
                                    return Err(rows::Error::Conflict);
                                }
                                // Publish ONLY its NEW Closing CAS ACK, before
                                // native postflight. The missing initial ACK is
                                // never reconstructed from captured JSON.
                                retain_before_postflight(
                                    &mut root.original_rows,
                                    Rc::new(pin),
                                    |ack| {
                                        ack.with_cleanup_record(
                                            &meta.scope.context.intent.scope,
                                            meta.scope.context.provenance.network_epoch,
                                            |facts| {
                                                let saved = facts.acknowledged;
                                                if saved.phase != rows::Phase::Closing
                                                    || saved.pending.is_some()
                                                    || saved.creation.is_some()
                                                    || saved.binding.role != rows::Role::Carrier
                                                    || !rows::same_owned(
                                                        &saved.current,
                                                        &saved.baseline,
                                                    )
                                                    || saved.baseline.address.is_some()
                                                    || saved
                                                        .baseline
                                                        .interface
                                                        .policy
                                                        .weak_host_send
                                                    || saved
                                                        .baseline
                                                        .interface
                                                        .policy
                                                        .weak_host_receive
                                                    || saved.baseline.interface.policy.forwarding
                                                    || saved.baseline.interface.policy.advertising
                                                {
                                                    return Err(rows::Error::Conflict);
                                                }
                                                Ok(())
                                            },
                                        )
                                        .map_err(denied)
                                    },
                                )
                                .map_err(|_| rows::Error::Conflict)
                            })
                            .map_err(denied)
                    },
                )?;
            }
            let row_original = root.original_rows.as_ref().ok_or(CarrierError::Pending)?;
            with_retained_or_partial(
                &mut root.rows,
                &mut root.row_capture,
                |capture| capture.owner_mut().map_err(denied),
                |owner| {
                    verify_row_owner_original(owner, row_original)?;
                    let reconcile = row_original
                        .with_cleanup_record(
                            &meta.scope.context.intent.scope,
                            meta.scope.context.provenance.network_epoch,
                            |facts| {
                                needs_created_cleanup(facts.acknowledged)
                                    .map_err(|_| rows::Error::Conflict)
                            },
                        )
                        .map_err(denied)?;
                    let handoff = |owner: &mut NativeRows| {
                        owner
                            .enter_storage_cleanup(|journal| {
                                let canonical = meta
                                    .runtime
                                    .native_files_for_original(&meta.scope.context, &meta.files)
                                    .map_err(|_| rows::Error::Conflict)?;
                                journal
                                    .enter_cleanup(canonical)
                                    .map_err(|_| rows::Error::Journal)
                            })
                            .map_err(denied)
                    };
                    if !reconcile {
                        // Only skip the special storage rewrite. Ordinary
                        // Stop/restore still require their complete native G,
                        // original SDK receipts and NEW durable effect ACKs.
                        return handoff(owner);
                    }
                    // Fresh on EACH Calling; never reuse an older sequence-
                    // bound issuer. Actual Authority roots EVERY issued Rc
                    // before its postflight, including Err/unwind outcomes.
                    let issuer = owner
                        .inspect_original_authority(|actual, _| {
                            actual
                                .created_cleanup_write_for_original(
                                    owner,
                                    row_original,
                                    &meta.files,
                                    original,
                                    expected,
                                )
                                .map_err(|_| rows::Error::Conflict)
                        })
                        .map_err(denied)?;
                    created_cleanup_sequence(
                        owner,
                        |owner| {
                            owner
                                .enter_storage_cleanup(|journal| {
                                    // Rotation must retain the old actual Rc before
                                    // installing this new SAME-origin Calling issuer.
                                    journal.retain_created_cleanup_authority(issuer)
                                })
                                .map_err(denied)
                        },
                        handoff,
                        |owner| {
                            owner
                                .reconcile_created_address_for_cleanup()
                                .map_err(denied)
                        },
                    )
                },
            )?;
            original
                .inspect_cleanup_effect(
                    &meta.runtime,
                    &meta.supervisor,
                    expected,
                    expected.stop_stage,
                    |_| Ok(()),
                )
                .map_err(denied)?;
            attempt.completed = true;
            Ok(())
        }
        /// Source-independent FACTUAL final reader for a C whose creator
        /// identity was actually published, but ready Source was not. Caller
        /// holds whole Closing12 Calling and authenticates its cold prepared /
        /// no-graph resource roots in callback. Never a destructor/effect grant.
        /// Unknown initial row capture/SDK ACK still denies until its original
        /// typed slot has produced a NEW acknowledged cleanup history.
        pub(crate) fn inspect_prepublication_terminal_in_call<T>(
            &mut self,
            pair: &Rc<NativePairIntentRead>,
            expected: &PairRecord,
            inspect: impl FnOnce(&crate::windows::member_carrier_guard::Bindings) -> Result<T>,
        ) -> Result<T> {
            if self.source.is_some() {
                return Err(CarrierError::Retired);
            }
            self.inspect_pregraph_terminal_in_call(pair, expected, inspect)
        }
        /// Caller additionally authenticates its private graph-construction
        /// ledger. No full-G fallback is available after upgrade attempted.
        /// Read-only original C/rows/terminal SDK join; not disposal authority.
        pub(crate) fn inspect_pregraph_terminal_in_call<T>(
            &mut self,
            pair: &Rc<NativePairIntentRead>,
            expected: &PairRecord,
            inspect: impl FnOnce(&crate::windows::member_carrier_guard::Bindings) -> Result<T>,
        ) -> Result<T> {
            self.inspect_pregraph_originals_in_call(
                pair,
                expected,
                PregraphRead::FullEmpty,
                inspect,
            )
        }
        /// READONLY Closing9/10 under the SAME actual Retired CloseACK and
        /// ordinary cleanup SDK bracket. Does not restore keys, move row owners
        /// or confer the disjoint FullEmpty/Stopped disposal authority.
        pub(crate) fn inspect_pregraph_native_empty_in_call<T>(
            &mut self,
            pair: &Rc<NativePairIntentRead>,
            expected: &PairRecord,
            inspect: impl FnOnce(&crate::windows::member_carrier_guard::Bindings) -> Result<T>,
        ) -> Result<T> {
            self.inspect_pregraph_originals_in_call(
                pair,
                expected,
                PregraphRead::NativeEmpty,
                inspect,
            )
        }
        /// Two DISJOINT factual SDK channels at actual Closing11. The caller's
        /// original key owner alone authenticates restoration effects between
        /// these reads; no key effect occurs inside either SDK bracket.
        pub(crate) fn inspect_pregraph_key_restore_in_call<T>(
            &mut self,
            pair: &Rc<NativePairIntentRead>,
            expected: &PairRecord,
            restored: bool,
            inspect: impl FnOnce(&crate::windows::member_carrier_guard::Bindings) -> Result<T>,
        ) -> Result<T> {
            self.inspect_pregraph_originals_in_call(
                pair,
                expected,
                if restored {
                    PregraphRead::KeyRestoreAfter
                } else {
                    PregraphRead::KeyRestoreBefore
                },
                inspect,
            )
        }
        /// Exact Closing0..8 before full-G attachment. This is a FACTUAL read:
        /// SAME actual source-origin Closing reader, original RowOwner/ACK,
        /// precise Pair/Calling and full SDK are mandatory before/after. It
        /// grants no row/member/Guard/native mutation or owner disposition.
        pub(crate) fn inspect_pregraph_closing_in_call<T>(
            &mut self,
            pair: &Rc<NativePairIntentRead>,
            expected: &PairRecord,
            inspect: impl FnOnce(&crate::windows::member_carrier_guard::Bindings) -> Result<T>,
        ) -> Result<T> {
            if self.terminal_attempted || self.lifecycle.attempted() {
                return Err(CarrierError::Retired);
            }
            let meta = self.meta.as_ref().ok_or(CarrierError::Pending)?;
            let context = meta.scope.context.clone();
            let runtime = meta.runtime.read_pin()?;
            let supervisor = meta.supervisor.clone();
            let proof = self.proof.ok_or(CarrierError::Pending)?;
            compare_pregraph_closing_frame(&context, expected, proof)?;
            // Select a genuine close-origin ONLY if its actual first AfterClose
            // callback retained it. A failed native read never falls back to a
            // live C or an unpublished/NoC sampler.
            match self.lifecycle.retired_pin() {
                Ok(_) if expected.stop_stage == 8 => {
                    return self.inspect_pregraph_originals_in_call(
                        pair,
                        expected,
                        PregraphRead::CarrierClosed,
                        inspect,
                    );
                }
                Ok(_) => return Err(CarrierError::Conflict),
                Err(CarrierError::Pending) => {}
                Err(error) => return Err(error),
            }
            pair.inspect_cleanup_effect(
                &runtime,
                &supervisor,
                expected,
                expected.stop_stage,
                |_| Ok(()),
            )
            .map_err(denied)?;
            let source = self.source.as_ref().ok_or(CarrierError::Pending)?.clone();
            let closing = if self.closing_attempted {
                self.closing.require_registered()?;
                self.closing.pin()?
            } else {
                // There is no full delegate to weak-register yet. The SAME
                // Ready root retains this original BEFORE origin/SDK checks;
                // no callback supplies a native permission or an absence ACK.
                self.capture_closing_in_call(pair.clone(), expected, |_| Ok(()))?
            };
            if !closing.matches_source_origin(&source) {
                return Err(CarrierError::Conflict);
            }
            {
                let (_, authority) = self
                    .construction
                    .as_mut()
                    .ok_or(CarrierError::Pending)?
                    .retained_parts()
                    .components
                    .as_mut()
                    .ok_or(CarrierError::Pending)?;
                authority
                    .select_pair_intent(pair.clone(), expected)
                    .map_err(denied)?;
            }
            let row = self.original_rows.as_ref().ok_or(CarrierError::Pending)?;
            // Published C requires the actual completed original row handoff,
            // not a failed capture inferred from an address/index in JSON.
            verify_row_owner_original(self.rows.as_ref().ok_or(CarrierError::Pending)?, row)?;
            let pair_before = runtime.record(&context, RecordKind::Pair)?;
            let value = closing
                .inspect_bindings(|bindings| {
                    if bindings.scope != expected.scope
                        || bindings.carrier.as_ref().map(|c| c.identity.proof) != Some(proof)
                        || bindings.egress.iter().any(Option::is_some)
                        || bindings.carrier.as_ref().is_none_or(|c| {
                            c.identity.scope != expected.scope
                                || c.sources
                                    != context
                                        .intent
                                        .addresses
                                        .iter()
                                        .map(|address| address.addr())
                                        .collect::<Vec<_>>()
                        })
                    {
                        return Err(wintun::Error::Conflict);
                    }
                    let read_rows = || -> Result<(Vec<u8>, rows::Snapshot)> {
                        if runtime
                            .optional_records(
                                &context,
                                &[
                                    RecordKind::Network,
                                    RecordKind::CarrierGuard,
                                    RecordKind::MemberARows,
                                    RecordKind::MemberBRows,
                                ],
                            )?
                            .iter()
                            .any(Option::is_some)
                        {
                            return Err(CarrierError::Conflict);
                        }
                        row.with_cleanup_record(
                            &expected.scope,
                            expected.provenance.network_epoch,
                            |facts| {
                                let b = facts.binding;
                                if b.guid != proof.guid
                                    || b.key.index != proof.index
                                    || b.key.luid != proof.luid
                                {
                                    return Err(rows::Error::Conflict);
                                }
                                let bytes = runtime
                                    .record(&context, RecordKind::CarrierRows)
                                    .map_err(|_| rows::Error::Journal)?;
                                let saved = rows::Record::decode(&bytes)?;
                                if saved != *facts.acknowledged || saved.binding != *b {
                                    return Err(rows::Error::Conflict);
                                }
                                let observed = rows::native::read_original_snapshot(b)?;
                                let stage =
                                    crate::windows::member_carrier_coordinator_rows::Stage::Observe;
                                crate::windows::member_carrier_coordinator_rows::compare(
                                    b, &saved, &observed, stage,
                                )?;
                                Ok((bytes, observed))
                            },
                        )
                        .map_err(denied)
                    };
                    let before = read_rows().map_err(native_denied)?;
                    let value = inspect(bindings).map_err(native_denied)?;
                    if read_rows().map_err(native_denied)? != before {
                        return Err(wintun::Error::Conflict);
                    }
                    Ok(value)
                })
                .map_err(denied)?;
            self.closing.require_registered()?;
            if !Rc::ptr_eq(&closing, &self.closing.pin()?)
                || runtime.record(&context, RecordKind::Pair)? != pair_before
            {
                return Err(CarrierError::Conflict);
            }
            pair.inspect_cleanup_effect(
                &runtime,
                &supervisor,
                expected,
                expected.stop_stage,
                |_| Ok(()),
            )
            .map_err(denied)?;
            Ok(value)
        }
        /// Genuine Stopped caller, never a projected Closing12 record. Caller
        /// MUST already hold this exact Pair.inspect frame and terminal Calling.
        /// The original Retired SDK and private row ACK are checked before/after
        /// callback; this is factual preparation, not module/disposal permission.
        pub(crate) fn inspect_pregraph_stopped_in_call<T>(
            &mut self,
            pair: &Rc<NativePairIntentRead>,
            expected: &PairRecord,
            inspect: impl FnOnce(&crate::windows::member_carrier_guard::Bindings) -> Result<T>,
        ) -> Result<T> {
            self.inspect_pregraph_originals_in_call(pair, expected, PregraphRead::Stopped, inspect)
        }
        fn inspect_pregraph_originals_in_call<T>(
            &mut self,
            pair: &Rc<NativePairIntentRead>,
            expected: &PairRecord,
            channel: PregraphRead,
            inspect: impl FnOnce(&crate::windows::member_carrier_guard::Bindings) -> Result<T>,
        ) -> Result<T> {
            if self.terminal_attempted || self.lifecycle.attempted() {
                return Err(CarrierError::Retired);
            }
            let meta = self.meta.as_ref().ok_or(CarrierError::Pending)?;
            if !pair.matches_runtime(&meta.runtime) {
                return Err(CarrierError::Conflict);
            }
            let runtime = meta.runtime.read_pin()?;
            let context = meta.scope.context.clone();
            let retired = self.lifecycle.retired_pin()?; // actual first AfterClose Rc only
            if self
                .source
                .as_ref()
                .is_some_and(|source| !retired.matches_source_origin(source))
            {
                return Err(CarrierError::Conflict);
            }
            {
                let construction = self.construction.as_mut().ok_or(CarrierError::Pending)?;
                let (_, authority) = construction
                    .retained_parts()
                    .components
                    .as_ref()
                    .ok_or(CarrierError::Pending)?;
                match channel {
                    PregraphRead::CarrierClosed
                    | PregraphRead::NativeEmpty
                    | PregraphRead::KeyRestoreBefore => {
                        authority.verify_retired_cleanup_original_in_call(&retired)
                    }
                    PregraphRead::KeyRestoreAfter
                    | PregraphRead::FullEmpty
                    | PregraphRead::Stopped => authority.verify_retired_original_in_call(&retired),
                }
                .map_err(denied)?;
            } // release authority borrow BEFORE Retired SDK callback
            let row_pin = self.original_rows.as_ref().ok_or(CarrierError::Pending)?;
            // A failed capture's SAME owner remains in its original partial
            // slot even after independently acknowledged terminal cleanup.
            // Borrow it in place; do not mark capture completed or import ACKs.
            with_retained_or_partial(
                &mut self.rows,
                &mut self.row_capture,
                |capture| capture.owner_mut().map_err(denied),
                |owner| verify_row_owner_original(owner, row_pin),
            )?;
            let verify_pair = || -> Result<()> {
                match channel {
                    PregraphRead::CarrierClosed
                    | PregraphRead::NativeEmpty
                    | PregraphRead::KeyRestoreBefore
                    | PregraphRead::KeyRestoreAfter
                    | PregraphRead::FullEmpty => pair
                        .verify_cleanup_entry_for(&runtime, &context, expected)
                        .map_err(denied),
                    PregraphRead::Stopped => pair
                        .verify_terminal_bracket(&runtime, &meta.supervisor, &context, expected)
                        .map_err(denied),
                }
            };
            verify_pair()?;
            let pair_before = runtime.record(&context, RecordKind::Pair)?;
            let read_rows = |bindings: &crate::windows::member_carrier_guard::Bindings| {
                let c = bindings.carrier.as_ref().ok_or(CarrierError::Conflict)?;
                match channel {
                    PregraphRead::CarrierClosed => {
                        if expected.stop_stage != 8 {
                            return Err(CarrierError::Conflict);
                        }
                        compare_pregraph_closing_frame(&context, expected, c.identity.proof)?
                    }
                    PregraphRead::NativeEmpty => {
                        compare_pregraph_native_empty_frame(&context, expected, c.identity.proof)?
                    }
                    PregraphRead::KeyRestoreBefore | PregraphRead::KeyRestoreAfter => {
                        compare_pregraph_key_restore_frame(&context, expected, c.identity.proof)?
                    }
                    PregraphRead::FullEmpty => {
                        compare_prepublication_terminal_frame(&context, expected, c.identity.proof)?
                    }
                    PregraphRead::Stopped => {
                        compare_pregraph_stopped_frame(&context, expected, c.identity.proof)?
                    }
                }
                if bindings.scope != expected.scope
                    || bindings.egress.iter().any(Option::is_some)
                    || c.identity.scope != expected.scope
                    || c.sources
                        != context
                            .intent
                            .addresses
                            .iter()
                            .map(|a| a.addr())
                            .collect::<Vec<_>>()
                {
                    return Err(CarrierError::Conflict);
                }
                if runtime
                    .optional_records(
                        &context,
                        &[
                            RecordKind::Network,
                            RecordKind::CarrierGuard,
                            RecordKind::MemberARows,
                            RecordKind::MemberBRows,
                        ],
                    )?
                    .iter()
                    .any(Option::is_some)
                {
                    return Err(CarrierError::Conflict);
                }
                row_pin
                    .with_cleanup_record(
                        &expected.scope,
                        expected.provenance.network_epoch,
                        |facts| {
                            let bytes = runtime
                                .record(&context, RecordKind::CarrierRows)
                                .map_err(|_| rows::Error::Journal)?;
                            let protected = rows::Record::decode(&bytes)?;
                            let b = facts.binding;
                            compare_pregraph_stopped_rows(
                                &context,
                                c.identity.proof,
                                b,
                                facts.acknowledged,
                                &protected,
                            )
                            .map_err(|_| rows::Error::Conflict)?;
                            if runtime
                                .record(&context, RecordKind::CarrierRows)
                                .map_err(|_| rows::Error::Journal)?
                                != bytes
                            {
                                return Err(rows::Error::Conflict);
                            }
                            Ok(bytes)
                        },
                    )
                    .map_err(denied)
            };
            let inspect_originals = |bindings: &crate::windows::member_carrier_guard::Bindings,
                                     history: &[crate::windows::member_carrier_members::ClosedMemberBinding]| {
                    if !history.is_empty() {
                        return Err(wintun::Error::Conflict);
                    }
                    let before = read_rows(bindings).map_err(native_denied)?;
                    if matches!(channel, PregraphRead::FullEmpty | PregraphRead::Stopped) && self.rows.is_none() {
                        // This exact private row ACK/protected payload and the
                        // independent full SDK absence have been authenticated
                        // ABOVE, inside the actual Retired terminal bracket.
                        // The supplier roots both cuts before postflight; no
                        // Source/ResourceRowsRead or imported ACK is invented.
                        transfer_stopped_capture_into(
                            &mut self.row_capture,
                            &mut self.stopped_capture,
                            &mut self.rows,
                            |capture, destination| {
                                capture
                                    .drain_stopped_into(row_pin, destination)
                                    .map_err(denied)
                            },
                            |capture, stopped| {
                                capture
                                    .verify_stopped_drained_into(row_pin, stopped)
                                    .map_err(denied)
                            },
                            |stopped, owner| stopped.drain_owner_into(owner).map_err(denied),
                            |capture, stopped, owner| {
                                stopped.verify_owner_drained_into(owner).map_err(denied)?;
                                capture
                                    .verify_stopped_owner_drained_into(row_pin, owner)
                                    .map_err(denied)?;
                                verify_row_owner_original(owner, row_pin)
                            },
                        )
                        .map_err(native_denied)?;
                    }
                    with_retained_or_partial(
                        &mut self.rows,
                        &mut self.row_capture,
                        |capture| capture.owner_mut().map_err(denied),
                        |owner| verify_row_owner_original(owner, row_pin),
                    ).map_err(native_denied)?;
                    let value = inspect(bindings).map_err(native_denied)?;
                    if read_rows(bindings).map_err(native_denied)? != before {
                        return Err(wintun::Error::Conflict);
                    }
                    Ok(value)
                };
            let value = match channel {
                PregraphRead::CarrierClosed
                | PregraphRead::NativeEmpty
                | PregraphRead::KeyRestoreBefore => {
                    retired.inspect_bindings_and_history(inspect_originals)
                }
                PregraphRead::KeyRestoreAfter | PregraphRead::FullEmpty | PregraphRead::Stopped => {
                    retired.inspect_terminal_bindings_and_history(inspect_originals)
                }
            }
            .map_err(denied)?;
            if runtime.record(&context, RecordKind::Pair)? != pair_before {
                return Err(CarrierError::Conflict);
            }
            verify_pair()?;
            let construction = self.construction.as_mut().ok_or(CarrierError::Pending)?;
            let (_, authority) = construction
                .retained_parts()
                .components
                .as_ref()
                .ok_or(CarrierError::Pending)?;
            match channel {
                PregraphRead::CarrierClosed
                | PregraphRead::NativeEmpty
                | PregraphRead::KeyRestoreBefore => {
                    authority.verify_retired_cleanup_original_in_call(&retired)
                }
                PregraphRead::KeyRestoreAfter | PregraphRead::FullEmpty | PregraphRead::Stopped => {
                    authority.verify_retired_original_in_call(&retired)
                }
            }
            .map_err(denied)?;
            Ok(value)
        }
        fn cleanup_step(
            &mut self,
            context: &crate::member_carrier_native_ownership::Context,
            original: &Rc<NativePairIntentRead>,
            expected: &PairRecord,
            cancelled: &AtomicBool,
        ) -> Result<()> {
            let root = self.construction.as_mut().ok_or(CarrierError::Pending)?;
            let (carrier, authority) = root
                .retained_parts()
                .components
                .as_mut()
                .ok_or(CarrierError::Pending)?;
            authority
                .select_pair_intent(original.clone(), expected)
                .map_err(denied)?;
            if !matches!(
                carrier.phase(),
                wintun::Phase::Closed | wintun::Phase::ClosePending
            ) {
                // Actual opaque retained creator, not a saved numeric index.
                let binding = authority.binding().map_err(denied)?;
                self.proof = Some(InterfaceProof {
                    guid: binding.guid,
                    index: binding.key.index,
                    luid: binding.key.luid,
                });
            }
            let boundary = if self.lifecycle.attempted() {
                full_stop_boundary(context, expected, self.proof)?
            } else {
                stop_boundary(context, expected, self.proof)?
            };
            match boundary {
                // Interface-only restore has its own current stage3 entry;
                // never route it into the C address/session/handle effects.
                StopStep::Interface => Err(CarrierError::Conflict),
                StopStep::Address => {
                    // No constructor from persisted rows on an uncertain
                    // capture. Keep originals and require cleanup-only recovery.
                    let original = self.original_rows.as_ref().ok_or(CarrierError::Pending)?;
                    with_retained_or_partial(
                        &mut self.rows,
                        &mut self.row_capture,
                        |capture| capture.owner_mut().map_err(denied),
                        |owner| {
                            verify_row_owner_original(owner, original)?;
                            owner.stop().map_err(denied)
                        },
                    )
                }
                StopStep::Session => {
                    if carrier.session_end_read().verify_never_started().is_ok() {
                        // Actual no-start outcome, independently reobserved C.
                        authority.binding().map_err(denied)?;
                        carrier
                            .session_end_read()
                            .verify_never_started()
                            .map_err(denied)
                    } else {
                        carrier.end_session_bounded(cancelled, 1000).map_err(denied)
                    }
                }
                StopStep::Handle => {
                    carrier.close_bounded(cancelled, 1000).map_err(denied)?;
                    let lifecycle = self.lifecycle.clone();
                    // AfterClose roots exactly one ACTUAL provider channel.
                    // A published read failure can never switch to unpublished.
                    // Both original read protocols independently query the full
                    // SDK universe under this same current Closing Calling.
                    match select_closed_original(
                        lifecycle.retired_pin(),
                        lifecycle.unpublished_pin(),
                    )? {
                        ClosedOriginal::Published(registered) => {
                            let retired = authority
                                .retired_carrier_read_with_pin(|original| {
                                    if !Rc::ptr_eq(&registered, &original) {
                                        return Err(wintun::Error::Conflict);
                                    }
                                    lifecycle.confirm_retired(&original).map_err(native_denied)
                                })
                                .map_err(denied)?;
                            lifecycle.confirm_retired(&retired)?;
                            retired.inspect(|_| Ok(())).map_err(denied)
                        }
                        ClosedOriginal::Unpublished(registered) => {
                            let original = authority
                                .unpublished_closed_carrier_read_with_pin(|original| {
                                    if !Rc::ptr_eq(&registered, &original)
                                        || !Rc::ptr_eq(
                                            &lifecycle.unpublished_pin().map_err(native_denied)?,
                                            &original,
                                        )
                                    {
                                        return Err(wintun::Error::Conflict);
                                    }
                                    Ok(()) // pointer confirmation only, never SDK permission
                                })
                                .map_err(denied)?;
                            original.inspect(|| Ok(())).map_err(denied)
                        }
                    }
                }
            }
        }
        fn step(
            &mut self,
            step: ReadyStep,
            assets: &mut Option<NativeAssemblyAssets>,
            scope: &creators::Scope,
            prerequisite: &mut Option<NativePrecreation<'_>>,
            files: &NativeSessionFiles,
        ) -> Result<()> {
            match step {
                ReadyStep::Construct => {
                    if self.construction.is_some() || self.meta.is_some() {
                        return Err(CarrierError::Conflict);
                    }
                    let original = assets.as_ref().ok_or(CarrierError::Pending)?;
                    original
                        .runtime
                        .verify_same_session_files(&scope.context, files)?;
                    creation_policy(&scope.context)?;
                    let gate = CarrierReadyGate::open_with_upgrade(
                        original,
                        scope.clone(),
                        self.lifecycle.clone(),
                    )
                    .map_err(denied)?;
                    // Allocate/clone every read-only metadata field while ALL
                    // original owning inputs still occupy the assembly slot.
                    let meta = Meta {
                        scope: scope.clone(),
                        runtime: original.runtime.read_pin()?,
                        pair: original.pair_intent.clone(),
                        expected: original.expected.clone(),
                        supervisor: original.supervisor.clone(),
                        cancelled: original.cancelled.clone(),
                        image: original.image.read_pin().map_err(denied)?,
                        wintun: original.source.clone(),
                        members: original.members.read_pin(),
                        originals: original.observer.clone(),
                        files: files.clone(),
                    };
                    let NativeAssemblyAssets {
                        module,
                        runtime,
                        image,
                        producer,
                        cancelled,
                        ..
                    } = assets.take().expect("retained assembly assets");
                    // Infallible field moves only between take and caller root.
                    self.construction = Some(NativeConstructionSlot::new(
                        module,
                        runtime,
                        image,
                        producer,
                        scope.clone(),
                        gate,
                        cancelled,
                    ));
                    self.meta = Some(meta);
                    let root = self.construction.as_ref().expect("retained construction");
                    #[cfg(test)]
                    super::super::member_carrier_factory_test_os::trace_step(
                        "C construct authority",
                    );
                    root.construct().map_err(denied)
                }
                ReadyStep::Resolve => {
                    let root = self.construction.as_ref().ok_or(CarrierError::Pending)?;
                    #[cfg(test)]
                    super::super::member_carrier_factory_test_os::trace_step("C construct resolve");
                    root.resolve_components().map_err(denied)
                }
                ReadyStep::Create => {
                    let root = self.construction.as_mut().ok_or(CarrierError::Pending)?;
                    let (carrier, _) = root
                        .retained_parts()
                        .components
                        .as_mut()
                        .ok_or(CarrierError::Pending)?;
                    carrier
                        .create(prerequisite.take().ok_or(CarrierError::Pending)?)
                        .map_err(denied)
                }
                ReadyStep::Session => {
                    let root = self.construction.as_mut().ok_or(CarrierError::Pending)?;
                    let (carrier, _) = root
                        .retained_parts()
                        .components
                        .as_mut()
                        .ok_or(CarrierError::Pending)?;
                    carrier.start().map_err(denied)
                }
                ReadyStep::CaptureRows => {
                    begin_original_capture(&mut self.row_capture_attempted)?;
                    if self.rows.is_some() || self.original_rows.is_some() {
                        return Err(CarrierError::Conflict);
                    }
                    let root = self.construction.as_mut().ok_or(CarrierError::Pending)?;
                    let (_, authority) = root
                        .retained_parts()
                        .components
                        .as_mut()
                        .ok_or(CarrierError::Pending)?;
                    let binding = authority.binding().map_err(denied)?;
                    let (journal, existing) =
                        WindowsCarrierRowsStore::open(files.clone(), binding.clone())
                            .map_err(denied)?;
                    if existing.is_some() {
                        return Err(CarrierError::Retired);
                    }
                    // The canonical construction slot keeps the SAME original
                    // authority even when capture's journal/postflight fails.
                    capture_in_retained_slot(
                        &mut self.row_capture,
                        || {
                            NativeCapture::new_native(
                                binding.clone(),
                                authority.read_pin(),
                                journal,
                            )
                        },
                        |slot| {
                            RowOwner::capture_native_with_record_pin_into(slot, |pin| {
                                retain_before_postflight(
                                    &mut self.original_rows,
                                    Rc::new(pin),
                                    |original| {
                                        original
                                            .with_record(
                                                &binding.scope,
                                                binding.network_epoch,
                                                |facts| {
                                                    if facts.binding != &binding
                                                        || facts.binding.role != rows::Role::Carrier
                                                    {
                                                        return Err(rows::Error::Conflict);
                                                    }
                                                    Ok(())
                                                },
                                            )
                                            .map_err(denied)
                                    },
                                )
                                .map_err(|_| rows::Error::Conflict)
                            })
                            .map_err(denied)
                        },
                    )?;
                    // No fallible external boundary between extracting the
                    // fully completed owner and its already-held Ready slot.
                    // All failed capture outcomes stay in row_capture instead.
                    let pin = self.original_rows.as_ref().ok_or(CarrierError::Pending)?;
                    transfer_completed_capture_into(
                        &mut self.row_capture,
                        &mut self.rows,
                        |capture| capture.take_owner().map_err(denied),
                        |owner| verify_row_owner_original(owner, pin),
                    )?;
                    Ok(())
                }
                ReadyStep::Address => {
                    let policy = creation_policy(&scope.context)?;
                    let original = self.original_rows.as_ref().ok_or(CarrierError::Pending)?;
                    with_retained_owner(
                        &mut self.rows,
                        |owner| verify_row_owner_original(owner, original),
                        |owner| owner.create_address(policy).map_err(denied),
                    )
                }
                ReadyStep::Readiness => {
                    let meta = self.meta.as_ref().ok_or(CarrierError::Pending)?;
                    if meta.cancelled.load(Ordering::Acquire) {
                        return Err(CarrierError::Retired);
                    }
                    self.rows
                        .as_mut()
                        .ok_or(CarrierError::Pending)?
                        .wait_address_ready(&meta.cancelled)
                        .map_err(denied)?;
                    Ok(())
                }
                ReadyStep::Drain => {
                    let meta = self.meta.as_ref().ok_or(CarrierError::Pending)?;
                    let root = self.construction.as_mut().ok_or(CarrierError::Pending)?;
                    let (carrier, _) = root
                        .retained_parts()
                        .components
                        .as_mut()
                        .ok_or(CarrierError::Pending)?;
                    // Discard bounded C packets; NEVER send a VPN packet to
                    // the address carrier. Full runtime pumping remains a
                    // later mandatory factory integration step.
                    carrier.drain(&meta.cancelled, 25, 32).map_err(denied)?;
                    Ok(())
                }
                ReadyStep::PublishSource => {
                    if self.source.is_some() {
                        return Err(CarrierError::Conflict);
                    }
                    let rows = self.rows.as_mut().ok_or(CarrierError::Pending)?;
                    let created = rows.created_address_read_pin().map_err(denied)?;
                    let root = self.construction.as_mut().ok_or(CarrierError::Pending)?;
                    let (_, authority) = root
                        .retained_parts()
                        .components
                        .as_mut()
                        .ok_or(CarrierError::Pending)?;
                    self.source = Some(Rc::new(authority.source_read(created).map_err(denied)?));
                    // The original ready/create pin is retained BEFORE the
                    // independently bracketed full native source postflight.
                    self.proof = Some(
                        self.source
                            .as_ref()
                            .expect("retained source")
                            .inspect_bindings(|bindings| {
                                Ok(bindings
                                    .carrier
                                    .as_ref()
                                    .ok_or(wintun::Error::Conflict)?
                                    .identity
                                    .proof)
                            })
                            .map_err(denied)?,
                    );
                    Ok(())
                }
            }
        }
    }
    impl Drop for NativeCarrierRoot<'_> {
        fn drop(&mut self) {
            self.run.revoked.set(true);
            // No implicit close/unload/delete on unknown or partial outcomes.
            // Explicit full cleanup/unload must consume these SAME originals;
            // until that joined path is present this actor cannot be selected.
            if let Some(root) = self.construction.take() {
                root.revoke_forward();
                std::mem::forget(root);
            }
            if let Some(rows) = self.rows.take() {
                std::mem::forget(rows);
            }
            if let Some(capture) = self.row_capture.take() {
                std::mem::forget(capture);
            }
            if let Some(original) = self.initial_capture_original.take() {
                std::mem::forget(original);
            }
            if let Some(original) = self.original_rows.take() {
                std::mem::forget(original);
            }
            // A replacement owns real originals even if upgrade was attempted
            // before construction. Never destroy it via implicit root Drop.
            self.lifecycle.retire_forward();
            if !self.terminal_transferred {
                std::mem::forget(self.lifecycle.clone());
            }
            if let Some(source) = self.source.take() {
                std::mem::forget(source);
            }
            // The lifecycle slot already retains retired. Closing also keeps
            // its SAME actual captured reader through Root Drop, without
            // implicit native effects or a replacement/source revival.
            if !self.terminal_transferred {
                std::mem::forget(self.closing.clone());
            }
            if let Some(meta) = self.meta.take() {
                std::mem::forget(meta);
            }
        }
    }
    // Pure private receipt identity only. Does not inspect SDK/journal, adopt
    // creation from metadata, or replace the real owner effect gate.
    fn verify_row_owner_original(
        owner: &NativeRows,
        original: &rows::RowRecordReadPin,
    ) -> Result<()> {
        if !owner
            .record_read_pin()
            .map_err(denied)?
            .same_original(original)
        {
            return Err(CarrierError::Conflict);
        }
        Ok(())
    }
    fn denied<E>(_: E) -> CarrierError {
        CarrierError::Conflict
    }
    fn native_denied<E>(_: E) -> wintun::Error {
        wintun::Error::Conflict
    }
    fn io_denied<E>(_: E) -> std::io::Error {
        std::io::Error::other("native_carrier_ready")
    }
}

#[cfg(test)]
#[path = "member_carrier_ready_tests.rs"]
mod tests;
