//! Original carrier runtime composition. Native factory remains disconnected.
#![allow(dead_code)]

use crate::member_carrier::{CarrierError, Result};
#[cfg(not(windows))]
use crate::member_carrier_creators;
use crate::member_carrier_native_ownership::{
    self as receipts, Binding, Context, KeyPhase, Phase, Record, Role, Value,
};
#[cfg(windows)]
use crate::windows::{
    member_carrier_members as carrier_members, member_carrier_provider as carrier_provider,
};
#[cfg(not(windows))]
use crate::{
    member_carrier_members as carrier_members, member_carrier_provider as carrier_provider,
};
use std::{
    cell::{Cell, RefCell, RefMut},
    rc::Rc,
};

/// Caller-owned retention only. These stages confer no native permission.
#[derive(Clone, Copy)]
enum ConstructionStep {
    Authority,
    Components,
}
enum ConstructionFailure {
    Conflict,
    Pending,
    Retired,
}
impl From<ConstructionFailure> for CarrierError {
    fn from(failure: ConstructionFailure) -> Self {
        match failure {
            ConstructionFailure::Conflict => Self::Conflict,
            ConstructionFailure::Pending => Self::Pending,
            ConstructionFailure::Retired => Self::Retired,
        }
    }
}
struct ConstructionParts<I, A, S, C> {
    inputs: Option<I>,
    authority: Option<A>,
    shared: Option<S>,
    components: Option<C>,
}
struct ConstructionRoot<I, A, S, C, E = CarrierError> {
    parts: RefCell<ConstructionParts<I, A, S, C>>,
    revoked: Rc<Cell<bool>>,
    authority_attempted: Cell<bool>,
    authority_complete: Cell<bool>,
    components_attempted: Cell<bool>,
    components_complete: Cell<bool>,
    supervisor_attempted: Cell<bool>,
    error: std::marker::PhantomData<E>,
}
struct ConstructionAttempt {
    revoked: Rc<Cell<bool>>,
    succeeded: bool,
}
impl Drop for ConstructionAttempt {
    fn drop(&mut self) {
        if !self.succeeded {
            self.revoked.set(true);
        }
    }
}
impl<I, A, S, C, E: From<ConstructionFailure>> ConstructionRoot<I, A, S, C, E> {
    fn new(inputs: I) -> Self {
        Self {
            parts: RefCell::new(ConstructionParts {
                inputs: Some(inputs),
                authority: None,
                shared: None,
                components: None,
            }),
            revoked: Rc::new(Cell::new(false)),
            authority_attempted: Cell::new(false),
            authority_complete: Cell::new(false),
            components_attempted: Cell::new(false),
            components_complete: Cell::new(false),
            supervisor_attempted: Cell::new(false),
            error: std::marker::PhantomData,
        }
    }
    fn attempt(
        &self,
        step: ConstructionStep,
        call: impl FnOnce(&mut ConstructionParts<I, A, S, C>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), E> {
        let (attempted, complete) = match step {
            ConstructionStep::Authority => (&self.authority_attempted, &self.authority_complete),
            ConstructionStep::Components => (&self.components_attempted, &self.components_complete),
        };
        // Fence BEFORE any borrow, validation or callback. Caught reentry also
        // revokes the still-running outer attempt; no successful retry exists.
        if attempted.replace(true) || self.revoked.get() {
            self.revoked.set(true);
            return Err(ConstructionFailure::Retired.into());
        }
        let mut attempt = ConstructionAttempt {
            revoked: self.revoked.clone(),
            succeeded: false,
        };
        let mut parts = self
            .parts
            .try_borrow_mut()
            .map_err(|_| ConstructionFailure::Conflict)?;
        let ready = match step {
            ConstructionStep::Authority => parts.inputs.is_some() && parts.authority.is_none(),
            ConstructionStep::Components => {
                self.authority_complete.get() && parts.authority.is_some() && parts.inputs.is_none()
            }
        };
        if !ready || parts.shared.is_some() || parts.components.is_some() {
            return Err(ConstructionFailure::Pending.into());
        }
        // All owning outputs are installed by the callback in these slots.
        // Err/unwind drops only the borrow and revokes; the caller's root lives.
        call(&mut parts)?;
        if self.revoked.get() {
            return Err(ConstructionFailure::Retired.into());
        }
        let retained = match step {
            ConstructionStep::Authority => {
                parts.authority.is_some() && parts.shared.is_none() && parts.components.is_none()
            }
            ConstructionStep::Components => {
                parts.authority.is_none() && parts.shared.is_some() && parts.components.is_some()
            }
        };
        if parts.inputs.is_some() || !retained {
            return Err(ConstructionFailure::Pending.into());
        }
        complete.set(true);
        attempt.succeeded = true;
        Ok(())
    }
    fn retained_parts(&mut self) -> &mut ConstructionParts<I, A, S, C> {
        self.parts.get_mut()
    }
    fn supervised(
        &self,
        call: impl FnOnce() -> std::result::Result<(), E>,
    ) -> std::result::Result<(), E> {
        let attempt = self.begin_supervised()?;
        call()?;
        self.finish_supervised(attempt)
    }
    fn begin_supervised(&self) -> std::result::Result<ConstructionAttempt, E> {
        if self.supervisor_attempted.replace(true) || self.revoked.get() {
            self.revoked.set(true);
            return Err(ConstructionFailure::Retired.into());
        }
        // Owned signal only: this guard does NOT borrow the root. Mutable
        // component operations can borrow the whole caller's slot underneath it.
        Ok(ConstructionAttempt {
            revoked: self.revoked.clone(),
            succeeded: false,
        })
    }
    fn finish_supervised(&self, mut attempt: ConstructionAttempt) -> std::result::Result<(), E> {
        // Covers the enclosing supervisor's postflight, after the inner stage
        // callbacks have already published their original owning outputs.
        if !Rc::ptr_eq(&self.revoked, &attempt.revoked) {
            self.revoked.set(true);
            return Err(ConstructionFailure::Conflict.into());
        }
        if self.revoked.get() {
            return Err(ConstructionFailure::Retired.into());
        }
        if !self.components_complete.get() {
            return Err(ConstructionFailure::Pending.into());
        }
        attempt.succeeded = true;
        Ok(())
    }
    fn supervised_mut(
        &mut self,
        call: impl FnOnce(&mut Self) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), E> {
        let attempt = self.begin_supervised()?;
        call(self)?;
        self.finish_supervised(attempt)
    }
}

/// Retention/serialization ONLY, never native or runtime authorization. Both
/// actual components share this object's same owner and irreversible signal.
struct SharedOriginal<T> {
    owner: Rc<RefCell<T>>,
    revoked: Rc<Cell<bool>>,
}
impl<T> SharedOriginal<T> {
    fn new(owner: T) -> Self {
        Self::with_signal(owner, Rc::new(Cell::new(false)))
    }
    fn with_signal(owner: T, revoked: Rc<Cell<bool>>) -> Self {
        Self {
            owner: Rc::new(RefCell::new(owner)),
            revoked,
        }
    }
    fn pin(&self) -> Self {
        Self {
            owner: self.owner.clone(),
            revoked: self.revoked.clone(),
        }
    }
    fn borrow(&self) -> Result<RefMut<'_, T>> {
        self.owner.try_borrow_mut().map_err(|_| {
            self.revoked.set(true);
            CarrierError::Conflict
        })
    }
}

/// Pure original-root lifetime/latch for callbacks under an already-held raw
/// transaction. This is NOT owner authentication or an SDK/ACK capability.
/// Native construction separately checks the actual Runtime/Pair/row origin.
struct CleanupWriteRoot<T> {
    owner: std::rc::Weak<RefCell<T>>,
    forward_revoked: Rc<Cell<bool>>,
    admitted: Cell<bool>,
    failed: Cell<bool>,
}
impl<T> CleanupWriteRoot<T> {
    fn new(original: &SharedOriginal<T>) -> Self {
        Self {
            owner: Rc::downgrade(&original.owner),
            forward_revoked: original.revoked.clone(),
            admitted: Cell::new(false),
            failed: Cell::new(false),
        }
    }
    fn admit(&self) -> Result<()> {
        if self.failed.get() || self.admitted.replace(true) || self.owner.strong_count() == 0 {
            self.fail();
            return Err(CarrierError::Conflict);
        }
        Ok(())
    }
    fn verify(&self) -> Result<()> {
        if self.failed.get() || !self.admitted.get() || self.owner.strong_count() == 0 {
            return Err(CarrierError::Conflict);
        }
        Ok(())
    }
    fn fail(&self) {
        self.failed.set(true);
        self.forward_revoked.set(true);
    }
}

/// Whole-callback serialization and irreversible health, shared with the SAME
/// original C authority. Samples remain factual values, never effect grants.
struct SourceFence {
    revoked: Rc<Cell<bool>>,
    busy: Cell<bool>,
    tainted: Cell<bool>,
    joined_busy: Cell<bool>,
    cleanup: Cell<bool>,
}
struct JoinedInspection<'a> {
    source: &'a SourceFence,
    succeeded: bool,
}
impl Drop for JoinedInspection<'_> {
    fn drop(&mut self) {
        if !self.succeeded {
            self.source.revoked.set(true);
            self.source.tainted.set(true);
        }
        // Never release the still-active outer actor's Source lease.
        self.source.joined_busy.set(false);
    }
}
struct SourceInspection<'a> {
    source: &'a SourceFence,
    succeeded: bool,
}
/// One original provider-generation projection. Error, unwind or caught
/// reentry irreversibly revokes forward use; retained roots remain for cleanup.
struct GenerationProjection<'a> {
    revoked: &'a Cell<bool>,
    busy: &'a Cell<bool>,
    succeeded: bool,
}
/// Byte-selection/lifetime only; cannot issue an original generation grant.
struct GenerationWriteSelection {
    attempted: Cell<bool>,
    revoked: Cell<bool>,
    desired: RefCell<Option<Vec<u8>>>,
}
impl GenerationWriteSelection {
    fn new() -> Self {
        Self {
            attempted: Cell::new(false),
            revoked: Cell::new(false),
            desired: RefCell::new(None),
        }
    }
    fn begin(&self, desired: &[u8]) -> Result<()> {
        if self.attempted.replace(true) || self.revoked.get() {
            self.revoke();
            return Err(CarrierError::Conflict);
        }
        let mut retained = Vec::new();
        retained
            .try_reserve(desired.len())
            .map_err(|_| CarrierError::Pending)?;
        retained.extend_from_slice(desired);
        *self
            .desired
            .try_borrow_mut()
            .map_err(|_| CarrierError::Conflict)? = Some(retained);
        Ok(())
    }
    fn verify(&self, desired: &[u8]) -> Result<()> {
        self.with_retained(|retained| {
            if retained != desired {
                return Err(CarrierError::Conflict);
            }
            Ok(())
        })
    }
    /// Retained initial byte selection only; the caller must independently
    /// authenticate its completed capture, SAME pin/root and backend identity.
    fn with_retained<T>(&self, read: impl FnOnce(&[u8]) -> Result<T>) -> Result<T> {
        if self.revoked.get() || !self.attempted.get() {
            return Err(CarrierError::Conflict);
        }
        let desired = self
            .desired
            .try_borrow()
            .map_err(|_| CarrierError::Conflict)?;
        let value = read(desired.as_deref().ok_or(CarrierError::Conflict)?)?;
        if self.revoked.get() {
            return Err(CarrierError::Conflict);
        }
        Ok(value)
    }
    /// Byte history ONLY. Actual completed original capture/root/pin checks
    /// are mandatory in the caller. This cannot confirm a failed initial CAS,
    /// restore live selection or authorize any write/native operation.
    fn with_historical_bytes<T>(&self, read: impl FnOnce(&[u8]) -> Result<T>) -> Result<T> {
        if !self.attempted.get() {
            return Err(CarrierError::Conflict);
        }
        let desired = self
            .desired
            .try_borrow()
            .map_err(|_| CarrierError::Conflict)?;
        read(desired.as_deref().ok_or(CarrierError::Conflict)?)
    }
    fn revoke(&self) {
        self.revoked.set(true);
    }
}
/// Structural storage comparison only. The native caller must ALSO hold the
/// same opaque closed generation, actual new creator and original capture
/// window. Ordinary row transitions deliberately do NOT allow this change.
fn compare_member_generation_storage(
    context: &Context,
    old: &crate::member_carrier_rows::Record,
    next: &crate::member_carrier_rows::Record,
    expected: &crate::member_carrier_rows::Binding,
) -> Result<()> {
    use crate::member_carrier_rows as rows;
    old.validate().map_err(|_| CarrierError::Conflict)?;
    next.validate().map_err(|_| CarrierError::Conflict)?;
    let before = &old.binding;
    let after = &next.binding;
    let i = match after.role {
        rows::Role::MemberA => 1,
        rows::Role::MemberB => 2,
        _ => return Err(CarrierError::Conflict),
    };
    if context.intent.addresses.len() != 1
        || context.intent.addresses[0].prefix_len() != 32
        || context.intent.addresses[0].addr()
            != std::net::IpAddr::V4(std::net::Ipv4Addr::from(before.address))
        || after != expected
        || before.role != after.role
        || before.scope != context.intent.scope
        || after.scope != before.scope
        || before.boot_id != context.provenance.boot_id
        || after.boot_id != before.boot_id
        || before.runtime != context.provenance.runtime
        || after.runtime != before.runtime
        || before.network_epoch != context.provenance.network_epoch
        || after.network_epoch != before.network_epoch
        || before.address != after.address
        || before.guid != context.bindings[i].guid
        || after.guid != before.guid
        || before.name != context.bindings[i].name
        || after.name != before.name
        || old.phase != rows::Phase::Stopped
        || old.pending.is_some()
        || old.current.address.is_some()
        || old.current.interface.policy != old.baseline.interface.policy
        || next.phase != rows::Phase::Captured
        || next.revision != 1
        || next.pending.is_some()
        || next.creation.is_some()
        || next.current != next.baseline
        || next.current.address.is_some()
        || next.baseline.interface.policy.weak_host_send
        || next.baseline.interface.policy.weak_host_receive
        || next.baseline.interface.policy.forwarding
        || next.baseline.interface.policy.advertising
    {
        return Err(CarrierError::Conflict);
    }
    Ok(())
}
/// Historical storage comparison only. The native caller must hold the SAME
/// registered completed capture/pin/root; this cannot authorize initial CAS,
/// adopt an ACK or grant an SDK effect from equal data.
fn compare_completed_capture_storage(
    binding: &crate::member_carrier_rows::Binding,
    captured: &crate::member_carrier_rows::Record,
    current_ack: &crate::member_carrier_rows::Record,
) -> Result<()> {
    use crate::member_carrier_rows as rows;
    captured.validate().map_err(|_| CarrierError::Conflict)?;
    current_ack.validate().map_err(|_| CarrierError::Conflict)?;
    if !matches!(binding.role, rows::Role::MemberA | rows::Role::MemberB)
        || captured.binding != *binding
        || current_ack.binding != *binding
        || captured.phase != rows::Phase::Captured
        || captured.revision != 1
        || captured.pending.is_some()
        || captured.creation.is_some()
        || captured.current != captured.baseline
        || captured.current.address.is_some()
        || current_ack.baseline != captured.baseline
    {
        return Err(CarrierError::Conflict);
    }
    Ok(())
}

/// Pure write-shape fence for the separately sealed original Create ACK.
/// This cannot construct that ACK or grant any SDK operation. The native
/// issuer additionally checks SAME actual owner/pin/backend/Calling/Pair ACK.
fn compare_initial_capture_cleanup_storage(
    context: &Context,
    pair: &crate::member_carrier_pair::Record,
    binding: &crate::member_carrier_rows::Binding,
    initial: &crate::member_carrier_rows::Record,
    expected: Option<&crate::member_carrier_rows::Record>,
    desired: &crate::member_carrier_rows::Record,
) -> Result<()> {
    use crate::member_carrier_rows as r;
    compare_early_cleanup_storage_context(context, pair, binding)?;
    initial.validate().map_err(|_| CarrierError::Conflict)?;
    desired.validate().map_err(|_| CarrierError::Conflict)?;
    if let Some(expected) = expected {
        expected.validate().map_err(|_| CarrierError::Conflict)?;
    }
    let inert_original = |row: &r::Record| {
        row.binding == *binding
            && row.baseline == initial.baseline
            && row.pending.is_none()
            && row.creation.is_none()
            && row.current.address.is_none()
            && r::same_owned(&row.current, &initial.baseline)
    };
    if initial.revision != 1
        || initial.phase != r::Phase::Captured
        || initial.current != initial.baseline
        || initial.baseline.address.is_some()
        || !inert_original(initial)
        || !inert_original(desired)
        || desired.phase != r::Phase::Closing
        || expected.is_some_and(|row| {
            !inert_original(row)
                || !(row == initial || (row.phase == r::Phase::Closing && row.revision >= 2))
        })
        || expected.map_or(Some(2), |row| row.revision.checked_add(1)) != Some(desired.revision)
    {
        return Err(CarrierError::Conflict);
    }
    Ok(())
}
fn compare_created_cleanup_storage(
    context: &Context,
    pair: &crate::member_carrier_pair::Record,
    binding: &crate::member_carrier_rows::Binding,
    expected: &crate::member_carrier_rows::Record,
    desired: &crate::member_carrier_rows::Record,
) -> Result<()> {
    use crate::member_carrier_rows as r;
    compare_early_cleanup_storage_context(context, pair, binding)?;
    expected.validate().map_err(|_| CarrierError::Conflict)?;
    desired.validate().map_err(|_| CarrierError::Conflict)?;
    if expected.binding != *binding
        || desired.binding != *binding
        || expected.phase == r::Phase::Stopped
        || desired.phase != r::Phase::Closing
        || expected.revision.checked_add(1) != Some(desired.revision)
        || desired.baseline != expected.baseline
        || desired.baseline.address.is_some()
        || desired.pending.is_some()
        || desired.creation.is_none()
    {
        return Err(CarrierError::Conflict);
    }
    Ok(())
}
fn compare_early_cleanup_storage_context(
    context: &Context,
    pair: &crate::member_carrier_pair::Record,
    binding: &crate::member_carrier_rows::Binding,
) -> Result<()> {
    use crate::{
        member_carrier_guard as guard, member_carrier_pair as p, member_carrier_rows as r,
    };
    receipts::validate_context(context)?;
    pair.validate().map_err(|_| CarrierError::Conflict)?;
    let selected_cleanup = match pair.stop_stage {
        0 => p::Effect::Guard,
        1 => p::Effect::ReleaseProbes,
        2 => p::Effect::RestoreNetwork,
        3 => p::Effect::RestoreWeak,
        4 => p::Effect::MemberStop(nelomai_client_tunnel::redundancy::Slot::A),
        5 => p::Effect::MemberStop(nelomai_client_tunnel::redundancy::Slot::B),
        6 => p::Effect::CarrierAddressDelete,
        _ => return Err(CarrierError::Conflict),
    };
    if pair.scope != context.intent.scope
        || pair.provenance != context.provenance
        || pair.addresses != context.intent.addresses
        || pair.options.is_none()
        || pair.phase != p::Phase::Closing
        || pair.stop_stage > 6
        || pair.pending != Some(selected_cleanup)
        || pair.operation.is_some()
        || pair.active.is_some()
        || pair.network.is_some()
        || pair.pending_guard.is_some()
        || pair.guard
            != guard::Model::empty(pair.scope.clone()).map_err(|_| CarrierError::Conflict)?
        || pair.members.iter().flatten().any(|m| {
            m.owner.phase != crate::member_owner::Phase::Prepared
                || m.owner.proof.is_some()
                || m.owner.retired_proof.is_some()
                || m.owner.previous_config_sha256.is_some()
        })
        || binding.role != r::Role::Carrier
        || binding.scope != context.intent.scope
        || binding.runtime != context.provenance.runtime
        || binding.boot_id != context.provenance.boot_id
        || binding.network_epoch != context.provenance.network_epoch
        || binding.guid != context.bindings[0].guid
        || binding.name != context.bindings[0].name
        || binding.key.index == 0
        || binding.key.luid == 0
        || context.intent.addresses.len() != 1
        || context.intent.addresses[0].addr() != std::net::IpAddr::V4(binding.address.into())
        || pair.carrier.is_some_and(|c| {
            c.guid != binding.guid || c.index != binding.key.index || c.luid != binding.key.luid
        })
    {
        return Err(CarrierError::Conflict);
    }
    Ok(())
}
impl<'a> GenerationProjection<'a> {
    fn begin(revoked: &'a Cell<bool>, busy: &'a Cell<bool>) -> Result<Self> {
        if revoked.get() || busy.replace(true) {
            revoked.set(true);
            return Err(CarrierError::Conflict);
        }
        Ok(Self {
            revoked,
            busy,
            succeeded: false,
        })
    }
    fn complete(&mut self) -> Result<()> {
        if self.revoked.get() {
            return Err(CarrierError::Conflict);
        }
        self.succeeded = true;
        Ok(())
    }
}
impl Drop for GenerationProjection<'_> {
    fn drop(&mut self) {
        if !self.succeeded {
            self.revoked.set(true);
        }
        self.busy.set(false);
    }
}
impl Drop for SourceInspection<'_> {
    fn drop(&mut self) {
        if !self.succeeded {
            self.source.revoked.set(true);
        }
        self.source.busy.set(false);
    }
}
impl SourceFence {
    fn joined_read<F: Eq, T, E>(
        &self,
        cleanup: bool,
        expected: &F,
        mut sample: impl FnMut() -> std::result::Result<F, E>,
        read: impl FnOnce() -> std::result::Result<T, E>,
        conflict: impl Fn() -> E,
    ) -> std::result::Result<T, E> {
        if !self.busy.get()
            || self.cleanup.get() != cleanup
            || self.tainted.get()
            || (!cleanup && self.revoked.get())
            || self.joined_busy.get()
        {
            self.revoked.set(true);
            self.tainted.set(true);
            return Err(conflict());
        }
        self.joined_busy.set(true);
        let mut joined = JoinedInspection {
            source: self,
            succeeded: false,
        };
        if sample()? != *expected
            || !self.busy.get()
            || self.tainted.get()
            || self.cleanup.get() != cleanup
            || (!cleanup && self.revoked.get())
        {
            return Err(conflict());
        }
        let result = read()?;
        if sample()? != *expected
            || !self.busy.get()
            || self.tainted.get()
            || self.cleanup.get() != cleanup
            || (!cleanup && self.revoked.get())
        {
            return Err(conflict());
        }
        joined.succeeded = true;
        Ok(result)
    }
    fn new(revoked: Rc<Cell<bool>>) -> Self {
        Self {
            revoked,
            busy: Cell::new(false),
            tainted: Cell::new(false),
            joined_busy: Cell::new(false),
            cleanup: Cell::new(false),
        }
    }
    fn inspect<F: Eq, T, E>(
        &self,
        sample: impl FnMut() -> std::result::Result<F, E>,
        inspect: impl FnOnce(&F) -> std::result::Result<T, E>,
        conflict: impl Fn() -> E,
    ) -> std::result::Result<T, E> {
        self.inspect_inner(false, sample, inspect, conflict)
    }
    fn inspect_cleanup<F: Eq, T, E>(
        &self,
        sample: impl FnMut() -> std::result::Result<F, E>,
        inspect: impl FnOnce(&F) -> std::result::Result<T, E>,
        conflict: impl Fn() -> E,
    ) -> std::result::Result<T, E> {
        self.inspect_inner(true, sample, inspect, conflict)
    }
    fn inspect_inner<F: Eq, T, E>(
        &self,
        cleanup: bool,
        mut sample: impl FnMut() -> std::result::Result<F, E>,
        inspect: impl FnOnce(&F) -> std::result::Result<T, E>,
        conflict: impl Fn() -> E,
    ) -> std::result::Result<T, E> {
        if self.busy.get() {
            self.revoked.set(true);
            self.tainted.set(true);
            return Err(conflict());
        }
        if !cleanup && self.revoked.get() {
            return Err(conflict());
        }
        self.busy.set(true);
        self.cleanup.set(cleanup);
        self.tainted.set(false);
        if cleanup {
            self.revoked.set(true);
        }
        let mut operation = SourceInspection {
            source: self,
            succeeded: false,
        };
        let before = sample()?;
        if self.tainted.get() || (!cleanup && self.revoked.get()) {
            return Err(conflict());
        }
        let result = inspect(&before)?;
        if self.tainted.get()
            || (!cleanup && self.revoked.get())
            || sample()? != before
            || self.tainted.get()
            || (!cleanup && self.revoked.get())
        {
            return Err(conflict());
        }
        operation.succeeded = true;
        Ok(result)
    }
}
#[cfg(windows)]
use crate::windows::member_carrier_creators;

/// Comparison DATA derived from an independently observed ORIGINAL identity.
/// This helper never grants row effects or native creator authority.
pub(super) fn rows_binding(
    context: &Context,
    identity: &member_carrier_creators::Identity,
) -> crate::member_carrier_rows::Result<crate::member_carrier_rows::Binding> {
    use crate::member_carrier_rows::{Binding as RowsBinding, Error, Role as RowsRole, RowKey};
    if context.bindings[0].role != Role::RoleCarrier
        || identity.guid != context.bindings[0].guid
        || identity.name != context.bindings[0].name
        || identity.if_type != 53
        || identity.tunnel_type != 0
        || context.intent.addresses.len() != 1
    {
        return Err(Error::Conflict);
    }
    let network = context.intent.addresses[0];
    let std::net::IpAddr::V4(ip) = network.addr() else {
        return Err(Error::Unsupported);
    };
    if network.prefix_len() != 32 {
        return Err(Error::Unsupported);
    }
    let binding = RowsBinding {
        scope: context.intent.scope.clone(),
        boot_id: context.provenance.boot_id,
        runtime: context.provenance.runtime.clone(),
        network_epoch: context.provenance.network_epoch,
        role: RowsRole::Carrier,
        guid: identity.guid,
        name: identity.name.clone(),
        key: RowKey {
            luid: identity.luid,
            index: identity.index,
        },
        address: ip.octets(),
    };
    binding.validate()?;
    Ok(binding)
}

/// Comparison DATA for an independently read ORIGINAL SCM/process member.
/// Caller must bracket this with full mixed native inventory and source/owner
/// reads; matching numbers or this function alone grant no row permission.
fn member_rows_binding(
    context: &Context,
    role: crate::member_carrier_rows::Role,
    identity: &member_carrier_creators::Identity,
) -> crate::member_carrier_rows::Result<crate::member_carrier_rows::Binding> {
    use crate::member_carrier_rows::{Binding as RowsBinding, Error, Role as RowsRole, RowKey};
    let index = match role {
        RowsRole::MemberA => 1,
        RowsRole::MemberB => 2,
        RowsRole::Carrier => return Err(Error::Conflict),
    };
    if context.bindings[index].role != [Role::MemberA, Role::MemberB][index - 1]
        || identity.guid != context.bindings[index].guid
        || identity.name != context.bindings[index].name
        || identity.if_type != 53
        || identity.tunnel_type != 0
        || context.intent.addresses.len() != 1
    {
        return Err(Error::Conflict);
    }
    let network = context.intent.addresses[0];
    let std::net::IpAddr::V4(ip) = network.addr() else {
        return Err(Error::Unsupported);
    };
    if network.prefix_len() != 32 {
        return Err(Error::Unsupported);
    }
    let binding = RowsBinding {
        scope: context.intent.scope.clone(),
        boot_id: context.provenance.boot_id,
        runtime: context.provenance.runtime.clone(),
        network_epoch: context.provenance.network_epoch,
        role,
        guid: identity.guid,
        name: identity.name.clone(),
        key: RowKey {
            luid: identity.luid,
            index: identity.index,
        },
        // Logical source ONLY: RowOwner forbids creating it on either member.
        address: ip.octets(),
    };
    binding.validate()?;
    Ok(binding)
}

/// Whole original binding comparison only. The native caller separately
/// authenticates this started interface through the original reader and a
/// full SDK window; constructing these data grants no ownership or effect.
fn compare_member_capture_binding(
    context: &Context,
    actual: &crate::member_carrier_rows::Binding,
    role: crate::member_carrier_rows::Role,
    proof: crate::member_owner::InterfaceProof,
) -> crate::member_carrier_rows::Result<()> {
    use crate::member_carrier_rows::{Error, Role};
    let index = match role {
        Role::MemberA => 1,
        Role::MemberB => 2,
        Role::Carrier => return Err(Error::Conflict),
    };
    let expected = member_rows_binding(
        context,
        role,
        &member_carrier_creators::Identity {
            guid: proof.guid,
            luid: proof.luid,
            index: proof.index,
            name: context.bindings[index].name.clone(),
            description: String::new(),
            // Schema DATA only. The actual original SDK query still checks
            // provider type and complete interface metadata independently.
            if_type: 53,
            tunnel_type: 0,
        },
    )?;
    if *actual != expected {
        return Err(Error::Conflict);
    }
    Ok(())
}

/// Comparison projection ONLY. The native caller supplies actual C/A/B readers
/// and independently proves either live SourcePreferred/full inventory or exact
/// once-close receipts/FULL native absence. This helper grants no readiness,
/// ACK, NIC adoption, live allow or WFP-removal permission.
struct ComparisonBindings {
    scope: nelomai_client_tunnel::redundancy::SessionScope,
    carrier: Option<crate::member_carrier_guard::Carrier>,
    egress: [Option<crate::member_carrier_guard::Identity>; 2],
}
fn comparison_bindings(
    context: &Context,
    carrier: &member_carrier_creators::Identity,
    members: &[carrier_provider::ExpectedProvider],
) -> crate::member_carrier_guard::Result<ComparisonBindings> {
    use crate::member_carrier_guard::{Carrier, GuardError, Identity};
    use crate::member_owner::InterfaceProof;
    let c = rows_binding(context, carrier).map_err(|_| GuardError::Conflict)?;
    let expected = carrier_provider::ExpectedProvider {
        identity: carrier_provider::Expected {
            guid: carrier.guid,
            luid: carrier.luid,
            index: carrier.index,
            name: carrier.name.clone(),
            description: carrier.description.clone(),
            if_type: carrier.if_type,
            tunnel_type: carrier.tunnel_type,
        },
        kind: carrier_provider::ProviderKind::Wintun,
    };
    carrier_members::complete_provider_inputs(context, &[expected], members)
        .map_err(|_| GuardError::Conflict)?;
    let identity = |proof| Identity {
        scope: context.intent.scope.clone(),
        proof,
    };
    let mut egress = [None, None];
    for member in members {
        let index = context.bindings[1..]
            .iter()
            .position(|binding| {
                binding.guid == member.identity.guid && binding.name == member.identity.name
            })
            .ok_or(GuardError::Conflict)?;
        egress[index] = Some(identity(InterfaceProof {
            guid: member.identity.guid,
            luid: member.identity.luid,
            index: member.identity.index,
        }));
    }
    Ok(ComparisonBindings {
        scope: context.intent.scope.clone(),
        carrier: Some(Carrier {
            identity: identity(InterfaceProof {
                guid: c.guid,
                luid: c.key.luid,
                index: c.key.index,
            }),
            sources: vec![std::net::IpAddr::V4(c.address.into())],
        }),
        egress,
    })
}

/// Mixed Closing comparison only. The native caller independently samples
/// SDK presence using ONLY live members, and attests closed histories through
/// each SAME original stopped receipt. A captured history is never live IO.
fn closing_comparison_bindings(
    context: &Context,
    carrier: &member_carrier_creators::Identity,
    live: &[carrier_provider::ExpectedProvider],
    closed: &[carrier_provider::ExpectedProvider],
) -> crate::member_carrier_guard::Result<ComparisonBindings> {
    // Full comparison validation rejects duplicate roles AND all index/LUID/
    // GUID reuse across the two disjoint sets, including equal copies.
    let mut captured = Vec::with_capacity(live.len() + closed.len());
    captured.extend_from_slice(live);
    captured.extend_from_slice(closed);
    comparison_bindings(context, carrier, &captured)
}

/// Classification DATA only, selected from the actual window's independently
/// reattested original histories, never from a caller's absence flag.
fn resource_row_channel(cleanup: bool, closed: bool) -> ResourceRowChannel {
    if closed {
        ResourceRowChannel::Closed
    } else if cleanup {
        ResourceRowChannel::Closing
    } else {
        ResourceRowChannel::Source
    }
}

/// Source comparison DATA ONLY. Native caller must hold the actual row-created
/// opaque read pin and original C/runtime/provider caps, and independently read
/// full current SDK rows plus protected current revision before/after. Neither
/// saved creation metadata nor this helper supplies an ACK or source authority.
fn ready_source_comparison(
    context: &Context,
    original: &member_carrier_creators::Identity,
    captured_binding: &crate::member_carrier_rows::Binding,
    captured_address: &crate::member_carrier_rows::AddressRow,
    record: &crate::member_carrier_rows::Record,
    native: &crate::member_carrier_rows::Snapshot,
) -> crate::member_carrier_guard::Result<crate::member_carrier_guard::Carrier> {
    source_comparison(
        context,
        original,
        captured_binding,
        captured_address,
        record,
        native,
        None,
    )
}

/// Separate factual row-effect view. The exact pending weak-host delta is not
/// source permission for WFP allows or application traffic. G must independently
/// require actual blocking bases and the permitted lifecycle BEFORE this Set.
fn row_effect_source_comparison(
    native_record: &Record,
    original: &member_carrier_creators::Identity,
    captured_binding: &crate::member_carrier_rows::Binding,
    captured_address: &crate::member_carrier_rows::AddressRow,
    record: &crate::member_carrier_rows::Record,
    native: &crate::member_carrier_rows::Snapshot,
    target: &crate::member_carrier_rows::Target,
) -> crate::member_carrier_guard::Result<crate::member_carrier_guard::Carrier> {
    use crate::member_carrier_guard::GuardError;
    use crate::member_carrier_rows::{same_owned, Target};
    if captured_binding.role != crate::member_carrier_rows::Role::Carrier
        || native_record.phase != Phase::Preparing
    {
        return Err(GuardError::Conflict);
    }
    validate_rows_effect(native_record, record, captured_binding, target)
        .map_err(|_| GuardError::Conflict)?;
    let Target::Interface(policy) = target else {
        return Err(GuardError::Conflict);
    };
    let pending = record.pending.as_ref().ok_or(GuardError::Conflict)?;
    let mut applied = pending.before.clone();
    applied.interface.policy = policy.clone();
    if !same_owned(native, &pending.before) && !same_owned(native, &applied) {
        return Err(GuardError::Conflict);
    }
    source_comparison(
        &native_record.context,
        original,
        captured_binding,
        captured_address,
        record,
        native,
        Some(()),
    )
}

fn source_comparison(
    context: &Context,
    original: &member_carrier_creators::Identity,
    captured_binding: &crate::member_carrier_rows::Binding,
    captured_address: &crate::member_carrier_rows::AddressRow,
    record: &crate::member_carrier_rows::Record,
    native: &crate::member_carrier_rows::Snapshot,
    pending_row_effect: Option<()>,
) -> crate::member_carrier_guard::Result<crate::member_carrier_guard::Carrier> {
    use crate::member_carrier_guard::{Carrier, GuardError, Identity};
    use crate::member_carrier_rows::{same_address, same_owned, Phase as RowPhase};
    let binding = rows_binding(context, original).map_err(|_| GuardError::Conflict)?;
    record.validate().map_err(|_| GuardError::Conflict)?;
    native
        .validate(&binding)
        .map_err(|_| GuardError::Conflict)?;
    let address = native.address.as_ref().ok_or(GuardError::Conflict)?;
    if *captured_binding != binding
        || record.binding != binding
        || record.phase != RowPhase::Captured
        || (pending_row_effect.is_none() && record.pending.is_some())
        || native.interface.policy.forwarding
        || (pending_row_effect.is_none() && !same_owned(native, &record.current))
        || address.observed.dad_state != 4
        || address.observed.creation_timestamp <= 0
        || !same_address(address, captured_address)
        || !record
            .creation
            .as_ref()
            .is_some_and(|saved| same_address(saved, captured_address))
    {
        return Err(GuardError::Conflict);
    }
    Ok(Carrier {
        identity: Identity {
            scope: context.intent.scope.clone(),
            proof: crate::member_owner::InterfaceProof {
                guid: binding.guid,
                luid: binding.key.luid,
                index: binding.key.index,
            },
        },
        sources: vec![std::net::IpAddr::V4(binding.address.into())],
    })
}

/// Exact durable DATA fence. The actual original owner/module/actor and G's
/// independent WFP/network/supervisor authorization remain mandatory below.
fn validate_rows_effect(
    native: &Record,
    rows: &crate::member_carrier_rows::Record,
    binding: &crate::member_carrier_rows::Binding,
    target: &crate::member_carrier_rows::Target,
) -> crate::member_carrier_rows::Result<()> {
    use crate::member_carrier_rows::{Error, Phase as RowPhase, Role as RowRole, Target};
    receipts::validate_record(native).map_err(|_| Error::Conflict)?;
    rows.validate()?;
    binding.validate()?;
    let pending = rows.pending.as_ref().ok_or(Error::Pending)?;
    let index = match binding.role {
        RowRole::Carrier => 0,
        RowRole::MemberA => 1,
        RowRole::MemberB => 2,
    };
    if native.context.intent.addresses.len() != 1
        || native.context.intent.addresses[0].prefix_len() != 32
        || native.context.intent.addresses[0].addr() != std::net::IpAddr::V4(binding.address.into())
    {
        return Err(Error::Conflict);
    }
    if rows.binding != *binding
        || binding.scope != native.context.intent.scope
        || binding.boot_id != native.context.provenance.boot_id
        || binding.runtime != native.context.provenance.runtime
        || binding.network_epoch != native.context.provenance.network_epoch
        || binding.guid != native.context.bindings[index].guid
        || binding.name != native.context.bindings[index].name
        || pending.target != *target
    {
        return Err(Error::Conflict);
    }
    if index != 0 {
        // Addressless members own weak-host flags ONLY. Native Closing is
        // persisted BEFORE restoring the exact baseline and SCM Stop. Cleanup never rearms
        // source/provider authority or granting member address mutations.
        let key = &native.keys[index];
        if !matches!(native.phase, Phase::Preparing | Phase::Closing)
            || key.phase != KeyPhase::Disabled
            || !key.new_key_ack
            || key.current != Value::DwordZero
            || key.pending.is_some()
        {
            return Err(Error::Conflict);
        }
        return match (rows.phase, target) {
            (RowPhase::Captured, Target::Interface(policy)) if native.phase == Phase::Preparing => {
                crate::member_carrier_rows::validate_interface_delta(
                    &rows.current.interface.policy,
                    policy,
                )
            }
            (RowPhase::Closing, Target::Interface(policy))
                if *policy == rows.baseline.interface.policy =>
            {
                Ok(())
            }
            _ => Err(Error::Retired),
        };
    }
    match (native.phase, rows.phase, target) {
        (Phase::Preparing, RowPhase::Captured, Target::Create(policy)) => {
            if policy.address != binding.address {
                return Err(Error::Conflict);
            }
            policy.validate_creation()
        }
        (Phase::Preparing, RowPhase::Captured, Target::Interface(policy)) => {
            crate::member_carrier_rows::validate_interface_delta(
                &rows.current.interface.policy,
                policy,
            )
        }
        (Phase::Closing, RowPhase::Closing, Target::Interface(policy))
            if *policy == rows.baseline.interface.policy =>
        {
            Ok(())
        }
        (Phase::Closing, RowPhase::Closing, Target::Delete) => Ok(()),
        _ => Err(Error::Retired),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Use {
    Create,
    Live,
    Cleanup,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResourceRowChannel {
    Source,
    Retiring,
    Closing,
    Closed,
    Retired,
}

/// Actual outer read supplies these immutable comparison facts. A nested
/// consumer must not recursively reopen inventory/SDK or use them afterwards.
struct BracketFacts<T> {
    active: RefCell<Option<T>>,
    tainted: Cell<bool>,
}
struct BracketFactCall<'a, T>(&'a BracketFacts<T>);
impl<T> Drop for BracketFactCall<'_, T> {
    fn drop(&mut self) {
        *self.0.active.borrow_mut() = None;
    }
}
impl<T: Clone> BracketFacts<T> {
    fn new() -> Self {
        Self {
            active: RefCell::new(None),
            tainted: Cell::new(false),
        }
    }
    fn within<U>(&self, facts: T, read: impl FnOnce() -> Result<U>) -> Result<U> {
        let mut current = self.active.try_borrow_mut().map_err(|_| {
            self.tainted.set(true);
            CarrierError::Conflict
        })?;
        if current.is_some() {
            self.tainted.set(true);
            return Err(CarrierError::Conflict);
        }
        *current = Some(facts);
        self.tainted.set(false);
        drop(current);
        let _call = BracketFactCall(self);
        let result = read();
        if self.tainted.get() {
            return Err(CarrierError::Conflict);
        }
        result
    }
    fn snapshot(&self) -> Result<T> {
        if self.tainted.get() {
            return Err(CarrierError::Conflict);
        }
        self.active
            .try_borrow()
            .map_err(|_| CarrierError::Conflict)?
            .clone()
            .ok_or(CarrierError::Conflict)
    }
}

// Factual comparison only. Native callers must obtain the record ACK from the
// SAME actual RowOwner and the identity from an original SDK-bracketed window.
fn compare_resource_rows(
    context: &Context,
    identity: &crate::member_carrier_guard::Identity,
    original: &crate::member_carrier_rows::Binding,
    ack: &crate::member_carrier_rows::Record,
    protected: &crate::member_carrier_rows::Record,
    observed: Option<&crate::member_carrier_rows::Snapshot>,
    channel: ResourceRowChannel,
) -> Result<()> {
    use crate::member_carrier_rows as rows;
    let bad = |_| CarrierError::Conflict;
    original.validate().map_err(bad)?;
    ack.validate().map_err(bad)?;
    protected.validate().map_err(bad)?;
    let role = match original.role {
        rows::Role::Carrier => 0,
        rows::Role::MemberA => 1,
        rows::Role::MemberB => 2,
    };
    if ack.binding != *original
        || ack != protected
        || ack.pending.is_some()
        || original.scope != context.intent.scope
        || identity.scope != original.scope
        || original.boot_id != context.provenance.boot_id
        || original.runtime != context.provenance.runtime
        || original.network_epoch != context.provenance.network_epoch
        || original.guid != context.bindings[role].guid
        || original.name != context.bindings[role].name
        || original.guid != identity.proof.guid
        || original.key.index != identity.proof.index
        || original.key.luid != identity.proof.luid
        || context.intent.addresses.len() != 1
        || context.intent.addresses[0].prefix_len() != 32
        || context.intent.addresses[0].addr() != std::net::IpAddr::V4(original.address.into())
        || ack.baseline.interface.policy.forwarding
        || ack.baseline.interface.policy.advertising
        || ack.baseline.interface.policy.weak_host_send
        || ack.baseline.interface.policy.weak_host_receive
    {
        return Err(CarrierError::Conflict);
    }
    if role != 0 && (ack.creation.is_some() || ack.current.address.is_some()) {
        return Err(CarrierError::Conflict);
    }
    if matches!(
        channel,
        ResourceRowChannel::Closed | ResourceRowChannel::Retired
    ) {
        // This is usable ONLY when the native window independently carries the
        // SAME original member's Closed ACK and FULL SDK absence. No old NIC query.
        return if (role != 0 || channel == ResourceRowChannel::Retired)
            && ack.phase == rows::Phase::Stopped
            && observed.is_none()
            && ack.current.address.is_none()
            && ack.current.interface.policy == ack.baseline.interface.policy
        {
            Ok(())
        } else {
            Err(CarrierError::Conflict)
        };
    }
    if channel == ResourceRowChannel::Source && ack.phase != rows::Phase::Captured {
        return Err(CarrierError::Conflict);
    }
    if channel == ResourceRowChannel::Retiring
        && (role == 0
            || ack.phase != rows::Phase::Stopped
            || ack.current.interface.policy != ack.baseline.interface.policy
            || ack.current.address.is_some())
    {
        return Err(CarrierError::Conflict);
    }
    let observed = observed.ok_or(CarrierError::Conflict)?;
    observed.validate(original).map_err(bad)?;
    if !rows::same_owned(&ack.current, observed) {
        return Err(CarrierError::Conflict);
    }
    if channel == ResourceRowChannel::Source
        && role == 0
        && observed.address.as_ref().is_none_or(|a| {
            a.observed.dad_state != 4
                || a.policy.skip_as_source
                || a.observed.creation_timestamp <= 0
                || ack
                    .creation
                    .as_ref()
                    .is_none_or(|created| !rows::same_address(created, a))
        })
    {
        return Err(CarrierError::Conflict);
    }
    Ok(())
}

fn same_record(before: &Record, after: Record) -> Result<Record> {
    if before == &after {
        Ok(after)
    } else {
        Err(CarrierError::Conflict)
    }
}

/// Durable DATA validation only. Native/source/lease/original/key and exact
/// effect ordering remain independently mandatory; no bool grants authority.
pub(super) fn validate_terminal_stage(
    record: &Record,
    context: &Context,
    binding: &Binding,
    original_generation: u64,
) -> Result<()> {
    receipts::validate_record(record)?;
    if record.context != *context
        || binding != &context.bindings[0]
        || binding.role != Role::RoleCarrier
        || original_generation == 0
        || record.generation < original_generation
        || record.phase != Phase::Stopped
        || !record.keys[0].new_key_ack
        || record.keys.iter().any(|key| {
            key.phase != KeyPhase::Clean
                || key.baseline != Value::Absent
                || key.current != Value::Absent
                || key.pending.is_some()
        })
    {
        return Err(CarrierError::Conflict);
    }
    Ok(())
}

/// Terminal provider query selection only, NEVER native ownership or absence
/// permission. The caller authenticates the original runtime/serialized lease
/// and close ACK. Even zero live originals MUST query the complete native SDK;
/// restored key metadata cannot hide an unexpected remaining device.
pub(super) fn inspect_terminal_universe<T>(
    record: &Record,
    context: &Context,
    live_inputs: usize,
    inspect: impl FnOnce() -> Result<Vec<T>>,
) -> Result<Vec<T>> {
    validate_terminal_stage(record, context, &context.bindings[0], 1)?;
    if live_inputs != 0 {
        return Err(CarrierError::Conflict);
    }
    let observed = inspect()?;
    if !observed.is_empty() {
        return Err(CarrierError::Conflict);
    }
    Ok(observed)
}

fn validate_stage(
    record: &Record,
    context: &Context,
    binding: &Binding,
    original_generation: u64,
    fresh: bool,
    use_: Use,
) -> Result<()> {
    receipts::validate_record(record)?;
    if record.context != *context
        || binding != &context.bindings[0]
        || binding.role != Role::RoleCarrier
        || original_generation == 0
        || record.generation < original_generation
    {
        return Err(CarrierError::Conflict);
    }
    if use_ == Use::Create {
        receipts::validate_carrier_create_stage(record, context, binding, original_generation)?;
    }
    let key = &record.keys[0];
    if key.phase != KeyPhase::Disabled
        || !key.new_key_ack
        || key.current != Value::DwordZero
        || key.pending.is_some()
        || record.phase
            != if use_ == Use::Cleanup {
                Phase::Closing
            } else {
                Phase::Preparing
            }
        || (use_ != Use::Cleanup && !fresh)
    {
        return Err(CarrierError::Conflict);
    }
    Ok(())
}
#[derive(Clone, Copy)]
enum RetiredReadStage {
    Cleanup,
    Terminal,
}
fn validate_retired_read_stage(
    record: &Record,
    context: &Context,
    binding: &Binding,
    generation: u64,
    stage: RetiredReadStage,
) -> Result<()> {
    match stage {
        RetiredReadStage::Cleanup => {
            validate_stage(record, context, binding, generation, false, Use::Cleanup)
        }
        RetiredReadStage::Terminal => validate_terminal_stage(record, context, binding, generation),
    }
}

#[cfg(windows)]
pub(crate) mod native {
    use super::{
        carrier_members, carrier_provider, compare_completed_capture_storage,
        compare_member_capture_binding, compare_member_generation_storage, member_rows_binding,
        rows_binding, same_record, validate_retired_read_stage, validate_rows_effect,
        validate_stage, validate_terminal_stage, BracketFacts, CleanupWriteRoot,
        GenerationProjection, GenerationWriteSelection, RetiredReadStage, Use,
    };
    use crate::member_carrier_native_ownership as receipts;
    use crate::windows::{
        member_carrier_creators::{self as creators, NativeAbsence, OriginalNative},
        member_carrier_key_authority::{KeyLock, RuntimeRead},
        member_carrier_keys::{self as keys, win32},
        member_carrier_module::native::{LoadedWintun, OriginalImage, OriginalModuleLease},
        member_carrier_rows as rows,
        member_carrier_wintun::{
            self as wintun,
            native::{
                AuthenticatedModule, ModuleRuntimeAuthority, NativeKernel,
                NativeOriginalReferenceFence, OriginalAdapterModuleReleased, OriginalAdapterRead,
                OriginalPackageInventory, OriginalUniverse, OriginalWintun, PreparedOriginal,
            },
            Binding, Carrier, Error, Identity, Result, Stage,
        },
        member_native_deadline::{NativeDeadline, NativeDeadlineReadPin},
        member_session::RecordKind,
    };
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use std::{
        cell::{Cell, RefCell, RefMut},
        rc::Rc,
    };

    /// Required INDEPENDENT lifecycle permission, not a protected record or
    /// provider match. No implementation/default is supplied here.
    ///
    /// # Safety
    /// The implementation retains the actual serialized coordinator, original
    /// row/network/member/WFP/socket owners and supervisor for this exact scope.
    /// Before live effects it freshly attests the exact permitted lifecycle.
    /// Before End/Close it proves Closing, permit absence before port release,
    /// restored routes/DNS/weak rows and removed carrier address, exact stopped
    /// members with static bases still blocking. AfterClose proves completion
    /// and actual absence; it NEVER infers ownership from equal JSON/GUID/name.
    /// It must retain these guarantees through the native call under the SAME
    /// actual actor lease. Synchronous native calls require a hard-call
    /// supervisor; the cooperative budget in Wintun is not that supervisor.
    pub(crate) unsafe trait NativeLifecycleGate {
        /// Called only by this authority's actual NativeKernel/Carrier
        /// construction seam before any native Start. Keep the original pin
        /// even when later validation fails; no equal-data replacement.
        fn retain_original_session(&mut self, original: wintun::SessionEndRead);
        /// Factual SAME-original once-close reader, retained by this actual
        /// authority BEFORE AfterClose postflight. Register only a Weak in G;
        /// this handoff itself grants neither absence nor cleanup effects.
        fn retain_retired_carrier(&mut self, original: &Rc<RetiredCarrierRead>) -> Result<()>;
        /// Distinct actual close ACK when raw C publication failed. Register
        /// only this SAME rooted object, without inventing a provider binding
        /// or reentering the borrowed authority/SDK. No successful default.
        fn retain_unpublished_closed_carrier(
            &mut self,
            original: &Rc<UnpublishedClosedCarrierRead>,
        ) -> Result<()>;
        /// Select ONLY the current opaque original protected Pair CAS window
        /// under this SAME Runtime/Calling owner. Comparison metadata alone
        /// cannot select/reopen an operation or rearm revoked forward use.
        fn select_pair_intent(
            &mut self,
            original: Rc<
                crate::windows::member_carrier_pair_store::native_store::NativePairIntentRead,
            >,
            expected: &crate::member_carrier_pair::Record,
        ) -> Result<()>;
        /// Actual authenticated SAME-runtime watchdog, not an armed flag. The
        /// coordinator wraps the whole owning Carrier/RowOwner operation in
        /// run; every native authority read below requires its Calling phase.
        /// This accessor itself supplies no WFP/network/lifecycle permission.
        fn supervisor(&self) -> &Rc<NativeDeadline>;
        fn authorize(
            &mut self,
            scope: &creators::Scope,
            stage: Stage,
            originals: &creators::Observer<OriginalWintun>,
        ) -> Result<()>;
        /// The SAME actual coordinator must authorize this exact C row change:
        /// C-only address creation/readiness precedes the first addressless
        /// primary and its bases: exact fresh original C/empty guard, no members,
        /// weak-host flags, routes/DNS or probes exist at this bootstrap stage.
        /// Weak-host flags require actual bases FIRST. Restoration requires no
        /// permits/owned routes/DNS; delete requires the original address ACK.
        /// Every stage requires the real hard-call supervisor. This ordering
        /// matches the approved spec; no data/default implementation is supplied.
        fn authorize_rows(
            &mut self,
            scope: &creators::Scope,
            binding: &rows::Binding,
            target: &rows::Target,
            originals: &creators::Observer<OriginalWintun>,
        ) -> Result<()>;
        /// Independently attest exact v2 blocks/permit/socket/network lifecycle
        /// for THIS addressless member's weak-host delta or exact restoration.
        /// The actual SAME member read capability is mandatory; it is not an
        /// inferred SCM owner from a GUID/record. No successful default.
        /// Restore-before-Stop only: native Closing uses SAME-original factual
        /// live+closed cleanup reads; final base removal still requires ALL
        /// actual closed receipts and FULL native EMPTY, never live exceptions.
        fn authorize_member_rows(
            &mut self,
            scope: &creators::Scope,
            binding: &rows::Binding,
            target: &rows::Target,
            originals: &creators::Observer<OriginalWintun>,
            members: &crate::windows::member_carrier_members::native::MemberInventoryRead,
        ) -> Result<()>;
    }

    /// Private shared ORIGINAL authority, not a second owner reconstructed from
    /// a GUID/context. Neither side exposes a cloning/reopen constructor.
    pub(crate) struct SharedCarrierAuthority<G: NativeLifecycleGate> {
        original: super::SharedOriginal<NativeCarrierAuthority<G>>,
    }
    /// Source facts through this SAME original C and this owner's actual
    /// address-create receipt. No address adoption or effects through this pin;
    /// G must separately verify bases, routes/DNS, members and held sockets.
    pub(crate) struct NativeSourceRead {
        address: rows::CreatedAddressReadPin,
        runtime: RuntimeRead,
        image: OriginalImage,
        originals: creators::Observer<OriginalWintun>,
        members: crate::windows::member_carrier_members::native::MemberInventoryRead,
        scope: creators::Scope,
        supervisor: Rc<NativeDeadline>,
        deadline: NativeDeadlineReadPin,
        fence: Rc<super::SourceFence>,
    }
    type SourceRevision = (Vec<u8>, Vec<u8>);
    #[derive(PartialEq, Eq)]
    struct SourceSample {
        revision: SourceRevision,
        rows: rows::Snapshot,
        original: creators::Identity,
        carrier: crate::member_carrier_guard::Carrier,
        members: Vec<crate::windows::member_carrier_provider::ExpectedProvider>,
        history: Vec<crate::windows::member_carrier_members::ClosedMemberBinding>,
    }
    /// Borrowed comparison window, minted only INSIDE the actual original
    /// Source/Closing callback. It joins read-only BFE checks without reentering
    /// the owning source lease; it cannot be imported, cloned or serialized.
    /// Each joined read freshly resamples ALL original/protected/SDK facts and
    /// taints the outer callback on any error/unwind, even if caught by G.
    pub(crate) struct NativeBindingsWindow<'a> {
        origin: WindowOrigin<'a>,
        bindings: crate::windows::member_carrier_guard::Bindings,
    }
    enum WindowOrigin<'a> {
        Source(
            &'a NativeSourceRead,
            &'a SourceSample,
            Option<(&'a rows::Binding, &'a rows::Target)>,
        ),
        Closing(&'a NativeClosingRead, &'a ClosingSample),
        PartialClosing(
            &'a NativeClosingRead,
            &'a crate::windows::member_carrier_member_controller::native::PartialCleanup,
            &'a ClosingSample,
        ),
    }
    impl NativeBindingsWindow<'_> {
        pub(crate) fn bindings(&self) -> &crate::windows::member_carrier_guard::Bindings {
            &self.bindings
        }
        pub(crate) fn matches_source(&self, source: &NativeSourceRead) -> bool {
            matches!(&self.origin, WindowOrigin::Source(original, _, _) if std::ptr::eq(*original, source))
        }
        pub(crate) fn matches_closing(&self, closing: &NativeClosingRead) -> bool {
            matches!(&self.origin, WindowOrigin::Closing(original, _) | WindowOrigin::PartialClosing(original, _, _) if std::ptr::eq(*original, closing))
        }
        pub(crate) fn matches_partial_member(
            &self,
            partial: &Rc<crate::windows::member_carrier_member_controller::native::PartialCleanup>,
        ) -> bool {
            matches!(&self.origin, WindowOrigin::PartialClosing(_, original, _) if std::ptr::eq(*original, partial.as_ref()))
        }
        pub(crate) fn is_partial_member_cleanup(&self) -> bool {
            matches!(&self.origin, WindowOrigin::PartialClosing(..))
        }
        pub(crate) fn matches_runtime(&self, runtime: &RuntimeRead) -> bool {
            match &self.origin {
                WindowOrigin::Source(source, _, _) => source.runtime.same_original_runtime(runtime),
                WindowOrigin::Closing(closing, _) => closing.runtime.same_original_runtime(runtime),
                WindowOrigin::PartialClosing(closing, _, _) => {
                    closing.runtime.same_original_runtime(runtime)
                }
            }
        }
        /// Comparison-only SAME original closed member history. No live SDK
        /// identity or Stop permission is created by this accessor.
        pub(crate) fn closed_member(
            &self,
            slot: nelomai_contracts::dispatcher::TunnelSlot,
        ) -> Option<&crate::windows::member_carrier_members::ClosedMemberBinding> {
            let history = match &self.origin {
                WindowOrigin::Source(_, sample, _) => &sample.history,
                WindowOrigin::Closing(_, sample) => &sample.history,
                WindowOrigin::PartialClosing(_, _, sample) => &sample.history,
            };
            history.iter().find(|closed| closed.intent.slot == slot)
        }
        /// Factual read bracket ONLY, not a lifecycle/native mutation grant.
        /// Callback must be read-only and must not open another Source callback
        /// or join recursively. Original G registration remains mandatory.
        pub(crate) fn inspect<T>(
            &self,
            read: impl FnOnce(&crate::windows::member_carrier_guard::Bindings) -> Result<T>,
        ) -> Result<T> {
            match &self.origin {
                WindowOrigin::Source(source, expected, effect) => source.fence.joined_read(
                    false,
                    *expected,
                    || source.sample_for_row(*effect),
                    || read(&self.bindings),
                    || Error::Conflict,
                ),
                WindowOrigin::Closing(closing, expected) => closing.fence.joined_read(
                    true,
                    *expected,
                    || closing.sample(),
                    || read(&self.bindings),
                    || Error::Conflict,
                ),
                WindowOrigin::PartialClosing(closing, partial, expected) => {
                    closing.fence.joined_read(
                        true,
                        *expected,
                        || closing.sample_partial(partial),
                        || read(&self.bindings),
                        || Error::Conflict,
                    )
                }
            }
        }
    }
    /// Actual RowOwner ACKs joined to the original Source/Closing observation.
    /// These immutable values are comparison facts, not a creation/effect grant.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct NativeResourceRowFact {
        pub binding: rows::Binding,
        pub acknowledged: rows::Record,
        pub observed: Option<rows::Snapshot>,
    }
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct NativeResourceRowsFacts {
        pub rows: [Option<NativeResourceRowFact>; 3],
    }
    pub(crate) struct NativeResourceRowsRead {
        context: receipts::Context,
        runtime: RuntimeRead,
        source: Rc<NativeSourceRead>,
        closing: RefCell<Option<Rc<NativeClosingRead>>>,
        closing_attempted: Cell<bool>,
        originals: RefCell<[Option<Rc<rows::RowRecordReadPin>>; 3]>,
        attempted: [Cell<bool>; 3],
        revoked: Cell<bool>,
        generation_pending: Cell<bool>,
        generation_busy: Cell<bool>,
        retired_generations: RefCell<Vec<Rc<NativeRowGenerationReceipt>>>,
        captures: RefCell<Vec<Rc<NativeRowGenerationCapture>>>,
    }
    /// Original stopped-row projection only. This does not authorize a new
    /// capture, protected CAS or native mutation; those remain separate gates.
    pub(crate) struct NativeRowGenerationReceipt {
        origin: std::rc::Weak<NativeResourceRowsRead>,
        ticket: Rc<crate::windows::member_carrier_member_controller::native::NativeMemberPreparationGeneration>,
        pin: Rc<rows::RowRecordReadPin>,
        seal: Rc<rows::StoppedRowGeneration>,
        protected: Vec<u8>,
        index: usize,
        acknowledged: Cell<bool>,
        capture_attempted: Cell<bool>,
    }
    /// Original replacement creation/storage join. No constructor, import or
    /// serialized representation; only this SAME row root can issue it.
    pub(crate) struct NativeRowGenerationCapture {
        origin: std::rc::Weak<NativeResourceRowsRead>,
        retired: Rc<NativeRowGenerationReceipt>,
        started: Rc<
            crate::windows::member_carrier_member_controller::native::NativeMemberStartedGeneration,
        >,
        never:
            Rc<crate::windows::member_carrier_member_controller::native::NativeNeverMemberEffects>,
        pair: Rc<crate::windows::member_carrier_pair_store::native_store::NativePairIntentRead>,
        record: crate::member_carrier_pair::Record,
        pair_payload: Vec<u8>,
        binding: rows::Binding,
        backend: crate::windows::member_session::OriginalSessionFilesIdentity,
        selection: GenerationWriteSelection,
        acknowledged: Cell<bool>,
        pin: RefCell<Option<Rc<rows::RowRecordReadPin>>>,
        completed: Cell<bool>,
    }
    pub(crate) struct NativeMemberCaptureInputs<'a> {
        pub ticket: &'a Rc<crate::windows::member_carrier_member_controller::native::NativeMemberPreparationGeneration>,
        pub never: &'a Rc<crate::windows::member_carrier_member_controller::native::NativeNeverMemberEffects>,
        pub started: &'a Rc<crate::windows::member_carrier_member_controller::native::NativeMemberStartedGeneration>,
        pub pair: &'a Rc<crate::windows::member_carrier_pair_store::native_store::NativePairIntentRead>,
        pub record: &'a crate::member_carrier_pair::Record,
        pub binding: &'a rows::Binding,
        pub supervisor: &'a NativeDeadline,
        pub guard: &'a Rc<RefCell<crate::windows::member_carrier_pair_io::native::Guard>>,
        pub lock: &'a KeyLock,
    }
    pub(crate) struct NativeRowGenerationInputs<'a> {
        pub ticket: &'a Rc<crate::windows::member_carrier_member_controller::native::NativeMemberPreparationGeneration>,
        pub never: &'a Rc<crate::windows::member_carrier_member_controller::native::NativeNeverMemberEffects>,
        pub pin: &'a Rc<rows::RowRecordReadPin>,
        pub seal: &'a Rc<rows::StoppedRowGeneration>,
        pub pair: &'a crate::windows::member_carrier_pair_store::native_store::NativePairIntentRead,
        pub record: &'a crate::member_carrier_pair::Record,
        pub supervisor: &'a NativeDeadline,
    }
    impl NativeRowGenerationReceipt {
        /// Exact immutable original Stop payload for the typed generation
        /// store. This is not absence, native creation or write authority.
        pub(crate) fn stopped_payload(&self) -> Vec<u8> {
            self.protected.clone()
        }
        fn verify_origin(self: &Rc<Self>, rows: &Rc<NativeResourceRowsRead>) -> Result<()> {
            if self
                .origin
                .upgrade()
                .is_none_or(|old| !Rc::ptr_eq(&old, rows))
                || !rows
                    .retired_generations
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .iter()
                    .any(|old| Rc::ptr_eq(old, self))
            {
                return Err(Error::Conflict);
            }
            self.seal
                .inspect_original(&self.pin, |_| Ok(()))
                .map_err(denied)
        }
    }
    impl NativeRowGenerationCapture {
        fn rows(&self) -> Result<Rc<NativeResourceRowsRead>> {
            let rows = self.origin.upgrade().ok_or(Error::Conflict)?;
            if !self.acknowledged.get()
                || rows.revoked.get()
                || rows.closing_attempted.get()
                || !rows
                    .captures
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .iter()
                    .any(|c| std::ptr::eq(c.as_ref(), self))
                || !self.retired.acknowledged.get()
            {
                return Err(Error::Conflict);
            }
            self.retired.verify_origin(&rows)?;
            self.started
                .verify_original(
                    &self.retired.ticket,
                    &self.never,
                    &rows.runtime,
                    &rows.context,
                )
                .map_err(denied)?;
            self.started.verify_source(&rows.source).map_err(denied)?;
            Ok(rows)
        }
        /// PURE historical original facts; never a live initial capture grant.
        /// Caller must separately select completed storage or genuine Closing
        /// cleanup. A raw CAS ACK without the actual rooted baseline pin cannot
        /// satisfy this comparison and cannot be imported from private bytes.
        fn verify_retained_storage_origin(
            &self,
            origin: &crate::windows::member_session::OriginalSessionFilesIdentity,
        ) -> Result<Rc<NativeResourceRowsRead>> {
            let root = self.origin.upgrade().ok_or(Error::Conflict)?;
            if !self.acknowledged.get()
                || !self.retired.acknowledged.get()
                || !root
                    .captures
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .iter()
                    .any(|c| std::ptr::eq(c.as_ref(), self))
                || !self.backend.same_original(origin)
            {
                return Err(Error::Conflict);
            }
            self.retired.verify_origin(&root)?;
            let pin = self
                .pin
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .clone()
                .ok_or(Error::Conflict)?;
            self.selection
                .with_historical_bytes(|bytes| {
                    let captured = rows::Record::decode(bytes)
                        .map_err(|_| crate::member_carrier::CarrierError::Conflict)?;
                    pin.with_cleanup_record(
                        &root.context.intent.scope,
                        root.context.provenance.network_epoch,
                        |facts| {
                            if facts.binding != &self.binding {
                                return Err(rows::Error::Conflict);
                            }
                            compare_completed_capture_storage(
                                &self.binding,
                                &captured,
                                facts.acknowledged,
                            )
                            .map_err(|_| rows::Error::Conflict)
                        },
                    )
                    .map_err(|_| crate::member_carrier::CarrierError::Conflict)
                })
                .map_err(denied)?;
            Ok(root)
        }
        pub(crate) fn stopped_payload(&self) -> Vec<u8> {
            self.retired.protected.clone()
        }
        /// PURE original registration facts for the actual lifecycle reader.
        /// G must still bracket its own SDK/private/Guard observations. Neither
        /// metadata equality nor these facts authorize a row/native effect.
        pub(crate) fn verify_lifecycle_origin(
            &self,
            original: &Rc<NativeResourceRowsRead>,
            old_pin: &Rc<rows::RowRecordReadPin>,
            old_seal: &Rc<rows::StoppedRowGeneration>,
            pair: &Rc<
                crate::windows::member_carrier_pair_store::native_store::NativePairIntentRead,
            >,
            record: &crate::member_carrier_pair::Record,
            binding: &rows::Binding,
        ) -> Result<()> {
            let retained = self.rows()?;
            if !Rc::ptr_eq(&retained, original)
                || !old_pin.same_original(&self.retired.pin)
                || !Rc::ptr_eq(old_seal, &self.retired.seal)
                || !Rc::ptr_eq(pair, &self.pair)
                || *record != self.record
                || *binding != self.binding
            {
                return Err(Error::Conflict);
            }
            Ok(())
        }
        pub(crate) fn verify_lifecycle_pin(
            &self,
            original: &Rc<NativeResourceRowsRead>,
            new_pin: &Rc<rows::RowRecordReadPin>,
        ) -> Result<()> {
            let retained = self.rows()?;
            if !Rc::ptr_eq(&retained, original)
                || self
                    .pin
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .as_ref()
                    .is_none_or(|pin| !pin.same_original(new_pin))
                || !original.matches_row_original(self.binding.role, new_pin)
            {
                return Err(Error::Conflict);
            }
            Ok(())
        }
        pub(crate) fn verify_lifecycle_complete(
            &self,
            original: &Rc<NativeResourceRowsRead>,
        ) -> Result<()> {
            if !self.completed.get() {
                return Err(Error::Pending);
            }
            let pin = self
                .pin
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .clone()
                .ok_or(Error::Pending)?;
            self.verify_lifecycle_pin(original, &pin)
        }
        fn verify_payloads(
            &self,
            scope: &nelomai_client_tunnel::redundancy::SessionScope,
            kind: RecordKind,
            old: &[u8],
            new: &[u8],
        ) -> Result<()> {
            let rows = self.rows()?;
            let expected_kind = if self.retired.index == 1 {
                RecordKind::MemberARows
            } else {
                RecordKind::MemberBRows
            };
            if scope != &rows.context.intent.scope
                || kind != expected_kind
                || old != self.retired.protected
            {
                return Err(Error::Conflict);
            }
            let old_record = rows::Record::decode(old).map_err(denied)?;
            self.retired
                .seal
                .inspect_original(&self.retired.pin, |actual| {
                    if actual != &old_record {
                        return Err(rows::Error::Conflict);
                    }
                    Ok(())
                })
                .map_err(denied)?;
            let new_record = rows::Record::decode(new).map_err(denied)?;
            compare_member_generation_storage(
                &rows.context,
                &old_record,
                &new_record,
                &self.binding,
            )
            .map_err(denied)
        }
    }
    // Safety: private construction below retains the actual original retired
    // row root and live replacement lineage BEFORE full Source/SDK/Pair/Guard
    // postflight. Raw callbacks are PURE origin/latch/byte comparisons, never
    // backend/native reentry. Native effects still require the actual Creator.
    unsafe impl crate::windows::member_session::OriginalRowGenerationWrite
        for NativeRowGenerationCapture
    {
        fn begin_write(
            &self,
            scope: &nelomai_client_tunnel::redundancy::SessionScope,
            kind: RecordKind,
            expected: &[u8],
            desired: &[u8],
        ) -> std::io::Result<()> {
            self.selection
                .begin(desired)
                .map_err(|_| std::io::Error::other("carrier_row_generation_conflict"))?;
            self.verify_payloads(scope, kind, expected, desired)
                .map_err(|_| std::io::Error::other("carrier_row_generation_conflict"))
        }
        fn verify_backend(
            &self,
            origin: &crate::windows::member_session::OriginalSessionFilesIdentity,
        ) -> std::io::Result<()> {
            self.rows()
                .map_err(|_| std::io::Error::other("carrier_row_generation_conflict"))?;
            if !self.backend.same_original(origin) {
                return Err(std::io::Error::other("carrier_row_generation_conflict"));
            }
            Ok(())
        }
        fn verify_storage_backend(
            &self,
            origin: &crate::windows::member_session::OriginalSessionFilesIdentity,
        ) -> std::io::Result<()> {
            let check = || -> Result<()> {
                if !self.completed.get() {
                    // A raw write ACK alone cannot outlive its initial grant.
                    self.rows()?;
                } else {
                    // Storage continuity is historical, not live Started/SDK
                    // authority. Stop/rebind must not prevent its own cleanup.
                    self.verify_retained_storage_origin(origin)?;
                }
                if !self.backend.same_original(origin) {
                    return Err(Error::Conflict);
                }
                Ok(())
            };
            check().map_err(|_| std::io::Error::other("carrier_row_generation_conflict"))
        }
        fn verify_pair(&self, payload: &[u8]) -> std::io::Result<()> {
            self.rows()
                .map_err(|_| std::io::Error::other("carrier_row_generation_conflict"))?;
            if self.pair_payload != payload {
                return Err(std::io::Error::other("carrier_row_generation_conflict"));
            }
            Ok(())
        }
        fn verify_completed_storage_backend(
            &self,
            origin: &crate::windows::member_session::OriginalSessionFilesIdentity,
        ) -> std::io::Result<()> {
            if !self.completed.get() {
                return Err(std::io::Error::other("carrier_row_capture_not_completed"));
            }
            // Reuse SAME actual completed capture/root/pin/baseline check,
            // not a boolean-derived permission or live initial CAS grant.
            self.verify_storage_backend(origin)
        }
        fn verify_cleanup_storage_backend(
            &self,
            origin: &crate::windows::member_session::OriginalSessionFilesIdentity,
        ) -> std::io::Result<()> {
            let verify = || -> Result<()> {
                // Historical original Captured ACK/pin is mandatory even when
                // full native postflight failed. This cannot adopt a lost raw
                // first CAS ACK or grant ordinary completed-storage permission.
                let root = self.verify_retained_storage_origin(origin)?;
                if !root.closing_attempted.get() {
                    return Err(Error::Conflict);
                }
                let closing = root
                    .closing
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .clone()
                    .ok_or(Error::Conflict)?;
                if !closing.matches_source_origin(&root.source)
                    || !closing.runtime.same_original_runtime(&root.runtime)
                    || closing.scope.context != root.context
                {
                    return Err(Error::Conflict);
                }
                // PURE facts only: typed SAME-parent cleanup files and their
                // raw transaction independently validate current claim/Pair;
                // actual Closing G/SDK brackets remain required for any effect.
                Ok(())
            };
            verify().map_err(|_| std::io::Error::other("carrier_row_capture_cleanup_conflict"))
        }
        fn verify_write(
            &self,
            scope: &nelomai_client_tunnel::redundancy::SessionScope,
            kind: RecordKind,
            old: &[u8],
            new: &[u8],
        ) -> std::io::Result<()> {
            self.selection
                .verify(new)
                .map_err(|_| std::io::Error::other("carrier_row_generation_conflict"))?;
            self.verify_payloads(scope, kind, old, new)
                .map_err(|_| std::io::Error::other("carrier_row_generation_conflict"))
        }
        fn fail_write(&self) {
            self.selection.revoke();
            if let Some(rows) = self.origin.upgrade() {
                rows.revoked.set(true);
            }
        }
    }
    impl NativeResourceRowsRead {
        fn capture_pair(&self, input: &NativeMemberCaptureInputs<'_>) -> Result<Vec<u8>> {
            use crate::{member_carrier_pair as pair, member_owner as owner};
            use nelomai_client_tunnel::redundancy::Slot;
            let slot = if input.ticket.slot() == nelomai_contracts::dispatcher::TunnelSlot::A {
                Slot::A
            } else {
                Slot::B
            };
            let index = usize::from(slot == Slot::B);
            if !self.runtime.matches_lock(input.lock)
                || input.binding.scope != self.context.intent.scope
                || input.ticket.context() != &self.context
                || input.started.context() != &self.context
                || input.started.slot() != input.ticket.slot()
                || input.started.next_generation() != input.ticket.next_generation()
            {
                return Err(Error::Conflict);
            }
            input
                .started
                .verify_original(input.ticket, input.never, &self.runtime, &self.context)
                .map_err(denied)?;
            input.started.verify_source(&self.source).map_err(denied)?;
            let proof = input.started.proof().map_err(denied)?;
            compare_member_capture_binding(
                &self.context,
                input.binding,
                [rows::Role::MemberA, rows::Role::MemberB][index],
                proof.interface,
            )
            .map_err(denied)?;
            input
                .pair
                .inspect_effect(
                    &self.runtime,
                    input.supervisor,
                    input.record,
                    pair::Effect::WeakRows,
                    |actual| {
                        if actual != input.record
                            || actual.scope != self.context.intent.scope
                            || actual.provenance != self.context.provenance
                            || actual.phase != pair::Phase::Running
                            || actual.operation != Some(pair::Operation::Attach(slot))
                            || actual.active
                                != Some(if slot == Slot::A { Slot::B } else { Slot::A })
                            || actual.pending_guard.is_some()
                            || !actual.guard.installed
                            || actual.guard.permits
                            || actual.guard.assigned_sublayer_weight.is_none()
                            || actual.members[index].as_ref().is_none_or(|m| {
                                m.owner.phase != owner::Phase::Running
                                    || m.owner.proof != Some(proof)
                            })
                            || input.binding.role
                                != [rows::Role::MemberA, rows::Role::MemberB][index]
                            || input.binding.guid != proof.interface.guid
                            || input.binding.key.index != proof.interface.index
                            || input.binding.key.luid != proof.interface.luid
                            || input.binding.name != self.context.bindings[index + 1].name
                        {
                            return Err(std::io::Error::other("carrier_row_generation_conflict"));
                        }
                        Ok(())
                    },
                )
                .map_err(denied)?;
            let payload = self
                .runtime
                .record(&self.context, RecordKind::Pair)
                .map_err(denied)?;
            if crate::windows::member_carrier_pair_store::carrier_payload(
                &self.context.intent.scope,
                &payload,
            )
            .map_err(denied)?
            .as_ref()
                != Some(input.record)
            {
                return Err(Error::Conflict);
            }
            Ok(payload)
        }
        /// Issue only for the actual new original native member. Old rows,
        /// ticket and new reader stay retained; there is no fresh JSON reopen.
        pub(crate) fn issue_member_capture(
            self: &Rc<Self>,
            retired: &Rc<NativeRowGenerationReceipt>,
            input: NativeMemberCaptureInputs<'_>,
        ) -> Result<Rc<NativeRowGenerationCapture>> {
            let mut flight = GenerationProjection::begin(&self.revoked, &self.generation_busy)
                .map_err(denied)?;
            retired.verify_origin(self)?;
            if !retired.acknowledged.get()
                || retired.capture_attempted.replace(true)
                || self.closing_attempted.get()
                || self.generation_pending.get()
                || !Rc::ptr_eq(&retired.ticket, input.ticket)
                || self.originals.try_borrow().map_err(|_| Error::Conflict)?[retired.index]
                    .is_some()
            {
                return Err(Error::Conflict);
            }
            let payload = self.capture_pair(&input)?;
            let capture = Rc::new(NativeRowGenerationCapture {
                origin: Rc::downgrade(self),
                retired: retired.clone(),
                started: input.started.clone(),
                never: input.never.clone(),
                pair: input.pair.clone(),
                record: input.record.clone(),
                pair_payload: payload.clone(),
                binding: input.binding.clone(),
                backend: self
                    .runtime
                    .native_birth_files(&self.context)
                    .map_err(denied)?
                    .read_identity(),
                selection: GenerationWriteSelection::new(),
                acknowledged: Cell::new(false),
                pin: RefCell::new(None),
                completed: Cell::new(false),
            });
            {
                let mut captures = self
                    .captures
                    .try_borrow_mut()
                    .map_err(|_| Error::Conflict)?;
                captures.try_reserve(1).map_err(|_| Error::Pending)?;
                captures.push(capture.clone()); // before native/protected postflight.
            }
            let before = self.capture_window(&capture, &input, false)?;
            if self.capture_pair(&input)? != payload
                || self.capture_window(&capture, &input, false)? != before
            {
                return Err(Error::Conflict);
            }
            flight.complete().map_err(denied)?;
            capture.acknowledged.set(true);
            Ok(capture)
        }
        fn capture_window(
            &self,
            capture: &NativeRowGenerationCapture,
            input: &NativeMemberCaptureInputs<'_>,
            registered: bool,
        ) -> Result<(
            NativeResourceRowsFacts,
            crate::member_carrier_guard::Snapshot,
        )> {
            self.source.inspect_window(|window| {
                let i = capture.retired.index - 1;
                let member = input.record.members[i].as_ref().ok_or(Error::Conflict)?;
                let proof = member.owner.proof.ok_or(Error::Conflict)?;
                if !window.matches_source(&self.source)
                    || !window.matches_runtime(&self.runtime)
                    || window.closed_member(input.ticket.slot()).is_some()
                    || window.bindings().egress[i]
                        .as_ref()
                        .is_none_or(|m| m.proof != proof.interface)
                    || window.bindings().carrier.as_ref().map(|c| c.identity.proof)
                        != input.record.carrier
                    || window.bindings().egress[1 - i].as_ref().map(|m| m.proof)
                        != input.record.members[1 - i]
                            .as_ref()
                            .and_then(|m| m.owner.proof.map(|p| p.interface))
                {
                    return Err(Error::Conflict);
                }
                let rows = self.sample_inner(
                    window,
                    false,
                    None,
                    (!registered).then_some(capture.retired.index),
                )?;
                let guard = input
                    .guard
                    .try_borrow_mut()
                    .map_err(|_| Error::Conflict)?
                    .snapshot_in_window(window)
                    .map_err(denied)?;
                if guard != input.record.guard.expected {
                    return Err(Error::Conflict);
                }
                let stored = self
                    .runtime
                    .record(
                        &self.context,
                        [
                            RecordKind::CarrierRows,
                            RecordKind::MemberARows,
                            RecordKind::MemberBRows,
                        ][capture.retired.index],
                    )
                    .map_err(denied)?;
                if !registered && stored != capture.retired.protected {
                    return Err(Error::Conflict);
                }
                if registered {
                    capture.selection.verify(&stored).map_err(denied)?;
                    let actual = rows.rows[capture.retired.index]
                        .as_ref()
                        .ok_or(Error::Conflict)?;
                    if actual.binding != capture.binding
                        || actual.acknowledged.encode().map_err(denied)? != stored
                        || actual.acknowledged.phase != rows::Phase::Captured
                        || actual.acknowledged.pending.is_some()
                        || actual.acknowledged.current != actual.acknowledged.baseline
                        || actual.acknowledged.current.address.is_some()
                    {
                        return Err(Error::Conflict);
                    }
                }
                Ok((rows, guard))
            })
        }
        /// Root the newly ACK'd baseline pin BEFORE registration postflight.
        /// Old attempted flags are not reset; only this exact capture can join.
        pub(crate) fn retain_member_generation(
            self: &Rc<Self>,
            capture: &Rc<NativeRowGenerationCapture>,
            original: Rc<rows::RowRecordReadPin>,
        ) -> Result<()> {
            let mut flight = GenerationProjection::begin(&self.revoked, &self.generation_busy)
                .map_err(denied)?;
            let same = capture.rows()?;
            if !Rc::ptr_eq(self, &same) || capture.completed.get() {
                return Err(Error::Conflict);
            }
            {
                let mut pin = capture.pin.try_borrow_mut().map_err(|_| Error::Conflict)?;
                if pin.is_some() {
                    return Err(Error::Conflict);
                }
                *pin = Some(original.clone()); // root first, even if later comparison fails.
            }
            original
                .with_record(
                    &self.context.intent.scope,
                    self.context.provenance.network_epoch,
                    |facts| {
                        if facts.binding != &capture.binding
                            || facts.acknowledged.phase != rows::Phase::Captured
                            || facts.acknowledged.pending.is_some()
                            || facts.acknowledged.current != facts.acknowledged.baseline
                            || facts.acknowledged.current.address.is_some()
                        {
                            return Err(rows::Error::Conflict);
                        }
                        capture
                            .selection
                            .verify(&facts.acknowledged.encode()?)
                            .map_err(|_| rows::Error::Conflict)
                    },
                )
                .map_err(denied)?;
            let mut originals = self
                .originals
                .try_borrow_mut()
                .map_err(|_| Error::Conflict)?;
            if originals[capture.retired.index].is_some()
                || originals
                    .iter()
                    .flatten()
                    .any(|old| old.same_original(&original))
            {
                return Err(Error::Conflict);
            }
            originals[capture.retired.index] = Some(original);
            flight.complete().map_err(denied)
        }
        pub(crate) fn complete_member_capture(
            self: &Rc<Self>,
            capture: &Rc<NativeRowGenerationCapture>,
            input: NativeMemberCaptureInputs<'_>,
        ) -> Result<()> {
            let mut flight = GenerationProjection::begin(&self.revoked, &self.generation_busy)
                .map_err(denied)?;
            let same = capture.rows()?;
            if !Rc::ptr_eq(self, &same)
                || capture.completed.get()
                || !Rc::ptr_eq(&capture.pair, input.pair)
                || !Rc::ptr_eq(&capture.retired.ticket, input.ticket)
                || !Rc::ptr_eq(&capture.started, input.started)
                || !Rc::ptr_eq(&capture.never, input.never)
                || capture.record != *input.record
                || capture.binding != *input.binding
                || capture
                    .pin
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .as_ref()
                    .is_none_or(|pin| !self.matches_row_original(capture.binding.role, pin))
            {
                return Err(Error::Conflict);
            }
            if self.capture_pair(&input)? != capture.pair_payload {
                return Err(Error::Conflict);
            }
            let before = self.capture_window(capture, &input, true)?;
            if self.capture_window(capture, &input, true)? != before
                || self.capture_pair(&input)? != capture.pair_payload
            {
                return Err(Error::Conflict);
            }
            flight.complete().map_err(denied)?;
            capture.completed.set(true);
            Ok(())
        }
        /// Remove only the actual closed row origin from CURRENT provider
        /// inputs, retaining it before postflight. Must precede inventory
        /// projection; completion follows BOTH transitions. Never reset the
        /// original capture attempt or issue a new RowOwner from equal bytes.
        pub(crate) fn retire_member_generation(
            self: &Rc<Self>,
            input: NativeRowGenerationInputs<'_>,
        ) -> Result<Rc<NativeRowGenerationReceipt>> {
            let mut flight = GenerationProjection::begin(&self.revoked, &self.generation_busy)
                .map_err(denied)?;
            let result = (|| {
                if self.revoked.get()
                    || self.closing_attempted.get()
                    || self.generation_pending.get()
                    || input.ticket.context() != &self.context
                {
                    return Err(Error::Conflict);
                }
                input.ticket.verify_source(&self.source).map_err(denied)?;
                input
                    .ticket
                    .verify_original(input.never, &self.runtime, &self.context)
                    .map_err(denied)?;
                let index = match input.ticket.slot() {
                    nelomai_contracts::dispatcher::TunnelSlot::A => 1,
                    nelomai_contracts::dispatcher::TunnelSlot::B => 2,
                };
                let role = [
                    rows::Role::Carrier,
                    rows::Role::MemberA,
                    rows::Role::MemberB,
                ][index];
                if !self.matches_row_original(role, input.pin) {
                    return Err(Error::Conflict);
                }
                let verify_pair = || {
                    input
                        .pair
                        .inspect(&self.runtime, input.supervisor, |actual| {
                            if actual != input.record {
                                return Err(std::io::Error::other(
                                    "carrier_row_generation_conflict",
                                ));
                            }
                            carrier_members::completed_retirement_registration(
                                &self.context,
                                receipts::Phase::Preparing,
                                actual,
                                index - 1,
                            )
                            .map_err(|_| std::io::Error::other("carrier_row_generation_conflict"))
                        })
                        .map_err(denied)
                };
                verify_pair()?;
                let before = self.source.inspect_window(|window| {
                    let facts = self.sample(window, false, None)?;
                    let fact = facts.rows[index].as_ref().ok_or(Error::Conflict)?;
                    let old_member = input
                        .ticket
                        .stopped_record()
                        .retired_proof
                        .ok_or(Error::Conflict)?;
                    let history = window
                        .closed_member(input.ticket.slot())
                        .ok_or(Error::Conflict)?;
                    if history.proof != old_member
                        || history.intent != input.ticket.stopped_record().intent
                        || fact.observed.is_some()
                        || fact.binding.guid != old_member.interface.guid
                        || fact.binding.key.index != old_member.interface.index
                        || fact.binding.key.luid != old_member.interface.luid
                        || window.bindings().carrier.as_ref().map(|c| c.identity.proof)
                            != input.record.carrier
                        || window.bindings().egress[2 - index]
                            .as_ref()
                            .map(|m| m.proof)
                            != input.record.members[2 - index]
                                .as_ref()
                                .and_then(|m| m.owner.proof.map(|p| p.interface))
                    {
                        return Err(Error::Conflict);
                    }
                    input
                        .seal
                        .inspect_original(input.pin, |record| {
                            if record != &fact.acknowledged || record.binding != fact.binding {
                                return Err(rows::Error::Conflict);
                            }
                            Ok(())
                        })
                        .map_err(denied)?;
                    let protected = self
                        .runtime
                        .record(
                            &self.context,
                            [
                                RecordKind::CarrierRows,
                                RecordKind::MemberARows,
                                RecordKind::MemberBRows,
                            ][index],
                        )
                        .map_err(denied)?;
                    Ok((
                        protected,
                        window.bindings().carrier.clone(),
                        window.bindings().egress[2 - index].clone(),
                        history.clone(),
                    ))
                })?;
                verify_pair()?;
                let receipt = Rc::new(NativeRowGenerationReceipt {
                    origin: Rc::downgrade(self),
                    ticket: input.ticket.clone(),
                    pin: input.pin.clone(),
                    seal: input.seal.clone(),
                    protected: before.0.clone(),
                    index,
                    acknowledged: Cell::new(false),
                    capture_attempted: Cell::new(false),
                });
                {
                    let mut roots = self
                        .retired_generations
                        .try_borrow_mut()
                        .map_err(|_| Error::Conflict)?;
                    roots.try_reserve(1).map_err(|_| Error::Pending)?;
                    roots.push(receipt.clone()); // root BEFORE removing the current origin.
                }
                self.generation_pending.set(true);
                {
                    let mut originals = self
                        .originals
                        .try_borrow_mut()
                        .map_err(|_| Error::Conflict)?;
                    if originals[index]
                        .as_ref()
                        .is_none_or(|old| !old.same_original(input.pin))
                    {
                        return Err(Error::Conflict);
                    }
                    originals[index] = None;
                }
                // Inventory has not moved yet. Recheck the unchanged original
                // Source/SDK window and SAME protected Stop ACK, not live rows.
                self.source.inspect_window(|window| {
                    if window.closed_member(input.ticket.slot()) != Some(&before.3)
                        || window.bindings().carrier != before.1
                        || window.bindings().egress[2 - index] != before.2
                        || self
                            .runtime
                            .record(
                                &self.context,
                                [
                                    RecordKind::CarrierRows,
                                    RecordKind::MemberARows,
                                    RecordKind::MemberBRows,
                                ][index],
                            )
                            .map_err(denied)?
                            != before.0
                    {
                        return Err(Error::Conflict);
                    }
                    input
                        .seal
                        .inspect_original(input.pin, |_| Ok(()))
                        .map_err(denied)
                })?;
                verify_pair()?;
                input.ticket.verify_source(&self.source).map_err(denied)?;
                input
                    .ticket
                    .verify_original(input.never, &self.runtime, &self.context)
                    .map_err(denied)?;
                receipt.verify_origin(self)?;
                Ok(receipt)
            })();
            let receipt = result?;
            flight.complete().map_err(denied)?;
            Ok(receipt)
        }
        /// Finish only AFTER actual MemberInventory retirement. No pending
        /// forward reader can sample a half-projected row/member generation.
        pub(crate) fn complete_member_generation_retirement(
            self: &Rc<Self>,
            receipt: &Rc<NativeRowGenerationReceipt>,
            input: NativeRowGenerationInputs<'_>,
        ) -> Result<()> {
            let mut flight = GenerationProjection::begin(&self.revoked, &self.generation_busy)
                .map_err(denied)?;
            let result = (|| {
                receipt.verify_origin(self)?;
                if self.revoked.get()
                    || self.closing_attempted.get()
                    || !self.generation_pending.get()
                    || receipt.acknowledged.get()
                    || !Rc::ptr_eq(&receipt.ticket, input.ticket)
                    || !Rc::ptr_eq(&receipt.pin, input.pin)
                    || !Rc::ptr_eq(&receipt.seal, input.seal)
                    || input.ticket.context() != &self.context
                {
                    return Err(Error::Conflict);
                }
                input.ticket.verify_source(&self.source).map_err(denied)?;
                input
                    .ticket
                    .verify_original(input.never, &self.runtime, &self.context)
                    .map_err(denied)?;
                input
                    .pair
                    .inspect(&self.runtime, input.supervisor, |actual| {
                        if actual != input.record {
                            return Err(std::io::Error::other("carrier_row_generation_conflict"));
                        }
                        carrier_members::completed_retirement_registration(
                            &self.context,
                            receipts::Phase::Preparing,
                            actual,
                            receipt.index - 1,
                        )
                        .map_err(|_| std::io::Error::other("carrier_row_generation_conflict"))
                    })
                    .map_err(denied)?;
                self.source.inspect_window(|window| {
                    if window.closed_member(input.ticket.slot()).is_some()
                        || window.bindings().egress[receipt.index - 1].is_some()
                    {
                        return Err(Error::Conflict);
                    }
                    let before = self.sample(window, false, None)?;
                    if before.rows[receipt.index].is_some()
                        || self
                            .runtime
                            .record(
                                &self.context,
                                [
                                    RecordKind::CarrierRows,
                                    RecordKind::MemberARows,
                                    RecordKind::MemberBRows,
                                ][receipt.index],
                            )
                            .map_err(denied)?
                            != receipt.protected
                        || self.sample(window, false, None)? != before
                    {
                        return Err(Error::Conflict);
                    }
                    receipt.verify_origin(self)
                })?;
                input
                    .ticket
                    .verify_original(input.never, &self.runtime, &self.context)
                    .map_err(denied)?;
                input
                    .pair
                    .inspect(&self.runtime, input.supervisor, |actual| {
                        if actual != input.record {
                            return Err(std::io::Error::other("carrier_row_generation_conflict"));
                        }
                        carrier_members::completed_retirement_registration(
                            &self.context,
                            receipts::Phase::Preparing,
                            actual,
                            receipt.index - 1,
                        )
                        .map_err(|_| std::io::Error::other("carrier_row_generation_conflict"))
                    })
                    .map_err(denied)?;
                Ok(())
            })();
            result?;
            flight.complete().map_err(denied)?;
            receipt.acknowledged.set(true);
            self.generation_pending.set(false);
            Ok(())
        }
        /// SAME immutable ACK-reader origin only. Not current row/read/effect
        /// authority; pending row callbacks still authenticate the full owner.
        pub(crate) fn matches_row_original(
            &self,
            role: rows::Role,
            original: &rows::RowRecordReadPin,
        ) -> bool {
            let index = match role {
                rows::Role::Carrier => 0,
                rows::Role::MemberA => 1,
                rows::Role::MemberB => 2,
            };
            self.originals.try_borrow().is_ok_and(|pins| {
                pins[index]
                    .as_ref()
                    .is_some_and(|pin| pin.same_original(original))
            })
        }
        /// Factual stopped row ACKs, ONLY for use inside the supplied original
        /// RetiredCarrierRead's independently SDK-bracketed whole callback.
        /// Does not enter Retired/Source or query any historical index. The
        /// caller must not turn these comparison values into absence authority.
        pub(crate) fn inspect_retired_in_bracket<T>(
            &self,
            retired: &RetiredCarrierRead,
            bindings: &crate::windows::member_carrier_guard::Bindings,
            inspect: impl FnOnce(&NativeResourceRowsFacts) -> Result<T>,
        ) -> Result<T> {
            if !retired.matches_source_origin(&self.source)
                || !self.closing_attempted.get()
                || bindings.scope != self.context.intent.scope
            {
                return Err(Error::Conflict);
            }
            let before = self.retired_rows(bindings)?;
            let value = inspect(&before);
            if self.retired_rows(bindings)? != before {
                return Err(Error::Conflict);
            }
            value
        }
        fn retired_rows(
            &self,
            bindings: &crate::windows::member_carrier_guard::Bindings,
        ) -> Result<NativeResourceRowsFacts> {
            self.runtime.verify(&self.context).map_err(denied)?;
            let originals = self
                .originals
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .clone();
            let identities = [
                bindings.carrier.as_ref().map(|c| &c.identity),
                bindings.egress[0].as_ref(),
                bindings.egress[1].as_ref(),
            ];
            let mut facts = NativeResourceRowsFacts {
                rows: [None, None, None],
            };
            for i in 0..3 {
                let (Some(original), Some(identity)) = (&originals[i], identities[i]) else {
                    if originals[i].is_some() || identities[i].is_some() {
                        return Err(Error::Conflict);
                    }
                    continue;
                };
                let kind = [
                    RecordKind::CarrierRows,
                    RecordKind::MemberARows,
                    RecordKind::MemberBRows,
                ][i];
                facts.rows[i] = Some(
                    original
                        .with_cleanup_record(
                            &self.context.intent.scope,
                            self.context.provenance.network_epoch,
                            |ack| {
                                let before = self
                                    .runtime
                                    .record(&self.context, kind)
                                    .map_err(|_| rows::Error::Journal)?;
                                let protected = rows::Record::decode(&before)?;
                                if ack.binding.role
                                    != [
                                        rows::Role::Carrier,
                                        rows::Role::MemberA,
                                        rows::Role::MemberB,
                                    ][i]
                                {
                                    return Err(rows::Error::Conflict);
                                }
                                super::compare_resource_rows(
                                    &self.context,
                                    identity,
                                    ack.binding,
                                    ack.acknowledged,
                                    &protected,
                                    None,
                                    super::ResourceRowChannel::Retired,
                                )
                                .map_err(|_| rows::Error::Conflict)?;
                                if self
                                    .runtime
                                    .record(&self.context, kind)
                                    .map_err(|_| rows::Error::Journal)?
                                    != before
                                {
                                    return Err(rows::Error::Conflict);
                                }
                                Ok(NativeResourceRowFact {
                                    binding: ack.binding.clone(),
                                    acknowledged: ack.acknowledged.clone(),
                                    observed: None,
                                })
                            },
                        )
                        .map_err(denied)?,
                );
            }
            self.runtime.verify(&self.context).map_err(denied)?;
            Ok(facts)
        }
        /// Caller roots the whole returned reader BEFORE any validation. Only
        /// original RowOwner::record_read_pin can supply these nonimportable ACKs.
        /// Construction alone does not authorize even a factual SDK observation.
        pub(crate) fn new(
            context: receipts::Context,
            runtime: RuntimeRead,
            source: Rc<NativeSourceRead>,
            carrier: Rc<rows::RowRecordReadPin>,
        ) -> Self {
            Self {
                context,
                runtime,
                source,
                closing: RefCell::new(None),
                closing_attempted: Cell::new(false),
                originals: RefCell::new([Some(carrier), None, None]),
                attempted: [Cell::new(true), Cell::new(false), Cell::new(false)],
                revoked: Cell::new(false),
                generation_pending: Cell::new(false),
                generation_busy: Cell::new(false),
                retired_generations: RefCell::new(Vec::new()),
                captures: RefCell::new(Vec::new()),
            }
        }
        /// Retain the first opaque original before any later role/SDK check.
        /// An equal replacement/retry cannot discard an unknown first obligation.
        /// The caller must subsequently inspect the SAME original live window.
        pub(crate) fn retain_member(
            &self,
            slot: nelomai_client_tunnel::redundancy::Slot,
            original: Rc<rows::RowRecordReadPin>,
        ) -> Result<()> {
            let index = if slot == nelomai_client_tunnel::redundancy::Slot::A {
                1
            } else {
                2
            };
            if self.attempted[index].replace(true) {
                self.revoked.set(true);
                return Err(Error::Conflict);
            }
            let mut retained = self.originals.try_borrow_mut().map_err(|_| {
                self.revoked.set(true);
                Error::Conflict
            })?;
            let reused = retained
                .iter()
                .flatten()
                .any(|old| old.same_original(&original));
            retained[index] = Some(original);
            if reused || self.revoked.get() || self.closing_attempted.get() {
                self.revoked.set(true);
                return Err(Error::Conflict);
            }
            Ok(())
        }
        pub(crate) fn bind_closing(&self, closing: Rc<NativeClosingRead>) -> Result<()> {
            if self.closing_attempted.replace(true) {
                self.revoked.set(true);
                return Err(Error::Conflict);
            }
            let same_origin = closing.matches_source_origin(&self.source);
            *self.closing.try_borrow_mut().map_err(|_| {
                self.revoked.set(true);
                Error::Conflict
            })? = Some(closing);
            if !same_origin {
                self.revoked.set(true);
                return Err(Error::Conflict);
            }
            Ok(())
        }
        /// Never call from an already joined window callback or RowOwner/G
        /// mutable borrow. This enters no authority, journal CAS, Source lease,
        /// Pair lease or Guard. Two independent full native/protected/ACK samples
        /// bracket the consumer inside one authenticated original window join.
        pub(crate) fn inspect_in_window<T>(
            &self,
            window: &NativeBindingsWindow<'_>,
            inspect: impl FnOnce(&NativeResourceRowsFacts) -> Result<T>,
        ) -> Result<T> {
            let cleanup = match &window.origin {
                WindowOrigin::Source(..)
                    if window.matches_source(&self.source)
                        && !self.closing_attempted.get()
                        && !self.generation_pending.get()
                        && !self.revoked.get() =>
                {
                    false
                }
                WindowOrigin::Closing(..) | WindowOrigin::PartialClosing(..)
                    if self
                        .closing
                        .try_borrow()
                        .map_err(|_| {
                            self.revoked.set(true);
                            Error::Conflict
                        })?
                        .as_ref()
                        .is_some_and(|closing| {
                            window.matches_closing(closing)
                                && closing.matches_source_origin(&self.source)
                        }) =>
                {
                    true
                }
                _ => return Err(Error::Conflict),
            };
            if !window.matches_runtime(&self.runtime) {
                return Err(Error::Conflict);
            }
            let result = window.inspect(|_| {
                let before = self.sample(window, cleanup, None)?;
                let value = inspect(&before);
                if self.sample(window, cleanup, None)? != before {
                    return Err(Error::Conflict);
                }
                value
            });
            if result.is_err() {
                self.revoked.set(true);
            }
            result
        }
        /// Normal Retire preflight: target RowOwner has genuinely restored and
        /// Stopped, but SAME original member/NIC is still SDK-LIVE until Stop.
        /// This narrow factual channel never revokes all sibling forward reads.
        pub(crate) fn inspect_retirement_in_window<T>(
            &self,
            window: &NativeBindingsWindow<'_>,
            pair: &crate::windows::member_carrier_pair_store::native_store::NativePairIntentRead,
            record: &crate::member_carrier_pair::Record,
            supervisor: &NativeDeadline,
            inspect: impl FnOnce(&NativeResourceRowsFacts) -> Result<T>,
        ) -> Result<T> {
            use nelomai_client_tunnel::redundancy::Slot;
            let target = match record.operation {
                Some(crate::member_carrier_pair::Operation::Retire(Slot::A)) => 0,
                Some(crate::member_carrier_pair::Operation::Retire(Slot::B)) => 1,
                _ => return Err(Error::Conflict),
            };
            if self.revoked.get()
                || self.closing_attempted.get()
                || !window.matches_source(&self.source)
                || !window.matches_runtime(&self.runtime)
                || !pair.matches_runtime(&self.runtime)
                || [
                    nelomai_contracts::dispatcher::TunnelSlot::A,
                    nelomai_contracts::dispatcher::TunnelSlot::B,
                ]
                .into_iter()
                .any(|slot| window.closed_member(slot).is_some())
            {
                return Err(Error::Conflict);
            }
            let current = || -> Result<Vec<u8>> {
                self.runtime.verify(&self.context).map_err(denied)?;
                let bytes = self
                    .runtime
                    .record(&self.context, RecordKind::NativeCarrierReceipts)
                    .map_err(denied)?;
                let native = receipts::Record::decode(&bytes).map_err(denied)?;
                carrier_members::retirement_registration(
                    &self.context,
                    native.phase,
                    record,
                    target,
                )
                .map_err(denied)?;
                pair.inspect_effect(
                    &self.runtime,
                    supervisor,
                    record,
                    crate::member_carrier_pair::Effect::MemberStop(if target == 0 {
                        Slot::A
                    } else {
                        Slot::B
                    }),
                    |actual| {
                        if actual == record {
                            Ok(())
                        } else {
                            Err(std::io::Error::other("carrier_row_retire_conflict"))
                        }
                    },
                )
                .map_err(denied)?;
                Ok(bytes)
            };
            let result = (|| {
                let native = current()?;
                let value = window.inspect(|_| {
                    let before = self.sample(window, false, Some(target + 1))?;
                    let value = inspect(&before);
                    if self.sample(window, false, Some(target + 1))? != before {
                        return Err(Error::Conflict);
                    }
                    value
                })?;
                if current()? != native {
                    return Err(Error::Conflict);
                }
                Ok(value)
            })();
            if result.is_err() {
                self.revoked.set(true);
            }
            result
        }
        fn sample(
            &self,
            window: &NativeBindingsWindow<'_>,
            cleanup: bool,
            retiring: Option<usize>,
        ) -> Result<NativeResourceRowsFacts> {
            self.sample_inner(window, cleanup, retiring, None)
        }
        // Only the private same-generation capture join above supplies
        // preparing. Ordinary/cleanup readers never infer a missing pin grant.
        fn sample_inner(
            &self,
            window: &NativeBindingsWindow<'_>,
            cleanup: bool,
            retiring: Option<usize>,
            preparing: Option<usize>,
        ) -> Result<NativeResourceRowsFacts> {
            self.runtime.verify(&self.context).map_err(denied)?;
            let originals = self
                .originals
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .clone();
            let bindings = window.bindings();
            if bindings.scope != self.context.intent.scope {
                return Err(Error::Conflict);
            }
            let identities = [
                bindings.carrier.as_ref().map(|c| &c.identity),
                bindings.egress[0].as_ref(),
                bindings.egress[1].as_ref(),
            ];
            let mut facts = NativeResourceRowsFacts {
                rows: [None, None, None],
            };
            for i in 0..3 {
                if preparing == Some(i) {
                    if i == 0
                        || cleanup
                        || retiring.is_some()
                        || originals[i].is_some()
                        || identities[i].is_none()
                        || window
                            .closed_member(if i == 1 {
                                nelomai_contracts::dispatcher::TunnelSlot::A
                            } else {
                                nelomai_contracts::dispatcher::TunnelSlot::B
                            })
                            .is_some()
                    {
                        return Err(Error::Conflict);
                    }
                    continue;
                }
                let (Some(original), Some(identity)) = (&originals[i], identities[i]) else {
                    if originals[i].is_some() || identities[i].is_some() {
                        return Err(Error::Conflict);
                    }
                    continue;
                };
                let closed = if i != 0 {
                    window
                        .closed_member(if i == 1 {
                            nelomai_contracts::dispatcher::TunnelSlot::A
                        } else {
                            nelomai_contracts::dispatcher::TunnelSlot::B
                        })
                        .is_some_and(|closed| {
                            closed.proof.interface == identity.proof
                                && closed.intent.scope == identity.scope
                                && closed.intent.slot
                                    == if i == 1 {
                                        nelomai_contracts::dispatcher::TunnelSlot::A
                                    } else {
                                        nelomai_contracts::dispatcher::TunnelSlot::B
                                    }
                        })
                } else {
                    false
                };
                let kind = [
                    RecordKind::CarrierRows,
                    RecordKind::MemberARows,
                    RecordKind::MemberBRows,
                ][i];
                let read = |ack: rows::RowRecordFacts<'_>| {
                    let before = self
                        .runtime
                        .record(&self.context, kind)
                        .map_err(|_| rows::Error::Journal)?;
                    let protected = rows::Record::decode(&before)?;
                    let observed = if closed {
                        None
                    } else {
                        Some(rows::native::read_original_snapshot(ack.binding)?)
                    };
                    if ack.binding.role
                        != [
                            rows::Role::Carrier,
                            rows::Role::MemberA,
                            rows::Role::MemberB,
                        ][i]
                    {
                        return Err(rows::Error::Conflict);
                    }
                    super::compare_resource_rows(
                        &self.context,
                        identity,
                        ack.binding,
                        ack.acknowledged,
                        &protected,
                        observed.as_ref(),
                        if retiring == Some(i) {
                            super::ResourceRowChannel::Retiring
                        } else {
                            super::resource_row_channel(cleanup, closed)
                        },
                    )
                    .map_err(|_| rows::Error::Conflict)?;
                    if !closed
                        && rows::native::read_original_snapshot(ack.binding)?
                            != *observed.as_ref().unwrap()
                        || self
                            .runtime
                            .record(&self.context, kind)
                            .map_err(|_| rows::Error::Journal)?
                            != before
                    {
                        return Err(rows::Error::Conflict);
                    }
                    Ok(NativeResourceRowFact {
                        binding: ack.binding.clone(),
                        acknowledged: ack.acknowledged.clone(),
                        observed,
                    })
                };
                facts.rows[i] = Some(
                    if cleanup || closed || retiring == Some(i) {
                        original.with_cleanup_record(
                            &self.context.intent.scope,
                            self.context.provenance.network_epoch,
                            read,
                        )
                    } else {
                        original.with_record(
                            &self.context.intent.scope,
                            self.context.provenance.network_epoch,
                            read,
                        )
                    }
                    .map_err(denied)?,
                );
            }
            self.runtime.verify(&self.context).map_err(denied)?;
            Ok(facts)
        }
    }
    /// Factual live-C bindings for Closing restoration BEFORE member Stop.
    /// No address/source-ready proof, dynamic allow or effect grant is exposed.
    /// Post-close base removal uses RetiredCarrierRead and FULL native absence.
    pub(crate) struct NativeClosingRead {
        runtime: RuntimeRead,
        image: OriginalImage,
        originals: creators::Observer<OriginalWintun>,
        members: crate::windows::member_carrier_members::native::MemberInventoryRead,
        scope: creators::Scope,
        supervisor: Rc<NativeDeadline>,
        deadline: NativeDeadlineReadPin,
        fence: Rc<super::SourceFence>,
    }
    #[derive(PartialEq, Eq)]
    struct ClosingSample {
        revision: SourceRevision,
        original: creators::Identity,
        // ONLY these providers may enter SDK queries; stopped histories never
        // enter that universe or re-create live source permission.
        members: Vec<crate::windows::member_carrier_provider::ExpectedProvider>,
        history: Vec<crate::windows::member_carrier_members::ClosedMemberBinding>,
        partial: Option<crate::member_owner::PartialServiceObservation>,
    }
    /// Independent SAME-original closed C reader for the final static-base
    /// read/removal gate. No current NIC/source-readiness or live row authority
    /// is supplied by these historical facts. NativeGuard still independently
    /// verifies all captured WFP IDs/priorities and exact removal permission.
    pub(crate) struct RetiredCarrierRead {
        original: creators::RetiredRead<OriginalWintun>,
        runtime: RuntimeRead,
        image: OriginalImage,
        members: crate::windows::member_carrier_members::native::MemberInventoryRead,
        scope: creators::Scope,
        supervisor: Rc<NativeDeadline>,
        deadline: NativeDeadlineReadPin,
        revoked: Rc<Cell<bool>>,
        history: BracketFacts<Vec<carrier_members::ClosedMemberBinding>>,
        adapter_reference: RefCell<Option<Rc<OriginalAdapterModuleReleased>>>,
    }
    struct RetiredAdapterReferenceFence<'a> {
        retired: &'a RetiredCarrierRead,
        pair: &'a crate::windows::member_carrier_pair_store::native_store::NativePairIntentRead,
        record: &'a crate::member_carrier_pair::Record,
        revision: &'a [u8],
    }
    // SAFETY: constructed only in the SAME active outer Pair + full Retired
    // callback. The actual Calling pin, private Stopped bytes, runtime lease
    // and independently closed A/B history are reattested without re-entry.
    unsafe impl NativeOriginalReferenceFence for RetiredAdapterReferenceFence<'_> {
        fn verify_original_terminal(&self, scope: &creators::Scope) -> creators::Result<()> {
            if scope != &self.retired.scope {
                return Err(creators::Error::Conflict);
            }
            self.pair
                .verify_terminal_bracket(
                    &self.retired.runtime,
                    &self.retired.supervisor,
                    &scope.context,
                    self.record,
                )
                .map_err(|_| creators::Error::Conflict)?;
            self.retired
                .history
                .snapshot()
                .map_err(|_| creators::Error::Conflict)?;
            if self
                .retired
                .terminal_revision()
                .map_err(|_| creators::Error::Conflict)?
                != self.revision
            {
                return Err(creators::Error::Conflict);
            }
            Ok(())
        }
    }
    /// Known raw C create/close ACK with NO published provider identity.
    /// No Bindings, Source, row identity, WFP history or effect grant escapes.
    pub(crate) struct UnpublishedClosedCarrierRead {
        original: creators::UnpublishedClosedRead<OriginalWintun>,
        runtime: RuntimeRead,
        image: OriginalImage,
        members: crate::windows::member_carrier_members::native::MemberInventoryRead,
        scope: creators::Scope,
        supervisor: Rc<NativeDeadline>,
        deadline: NativeDeadlineReadPin,
        revoked: Rc<Cell<bool>>,
    }
    struct ClosedHistoryCall<'a> {
        revoked: &'a Cell<bool>,
        succeeded: bool,
    }
    impl Drop for ClosedHistoryCall<'_> {
        fn drop(&mut self) {
            if !self.succeeded {
                self.revoked.set(true);
            }
        }
    }
    pub(crate) struct NativeRowsAuthority<G: NativeLifecycleGate> {
        shared: SharedCarrierAuthority<G>,
        role: rows::Role,
    }
    /// Actual issuer retained by the native C owner before postflight. Its
    /// callbacks compare only original pins/bytes and the same Calling sequence,
    /// never reborrow the C owner or inspect Runtime/backend/SDK under raw IO.
    struct NativeCreatedAddressCleanupWrite<G: NativeLifecycleGate> {
        root: CleanupWriteRoot<NativeCarrierAuthority<G>>,
        original: Rc<rows::RowRecordReadPin>,
        backend: crate::windows::member_session::OriginalSessionFilesIdentity,
        context: receipts::Context,
        pair_record: crate::member_carrier_pair::Record,
        pair_payload: Vec<u8>,
        _pair: Rc<crate::windows::member_carrier_pair_store::native_store::NativePairIntentRead>,
        supervisor: Rc<NativeDeadline>,
        calling: crate::windows::member_native_deadline::NativeTransactionCallPin,
    }
    /// Separate initial-invocation lane. It never implements known-Create
    /// authorization or imports an initial capture ACK from stored bytes.
    struct NativeInitialRowCaptureCleanupWrite<G: NativeLifecycleGate> {
        origin: NativeCreatedAddressCleanupWrite<G>,
        initial: rows::Record,
    }
    impl<G: NativeLifecycleGate> NativeInitialRowCaptureCleanupWrite<G> {
        fn verify_original(
            &self,
            original: &rows::InitialRowCaptureCleanupRead<'_>,
        ) -> std::io::Result<()> {
            let result = (|| {
                self.origin.root.verify().map_err(denied)?;
                self.origin
                    .calling
                    .verify(&self.origin.supervisor, &self.origin.context)
                    .map_err(denied)?;
                if !original.matches_record_original(&self.origin.original)
                    || original.initial_record() != &self.initial
                {
                    return Err(Error::Conflict);
                }
                Ok(())
            })();
            if result.is_err() {
                self.origin.root.fail();
            }
            result.map_err(|_| std::io::Error::other("carrier_initial_cleanup_original"))
        }
    }
    // SAFETY: actual construction below proves SAME private initial invocation,
    // actual RowOwner authority/baseline with no row effects, canonical backend,
    // protected Closing Pair ACK and SAME Calling sequence. All callbacks are
    // pure and consume sealed new-Closing facts; equal bytes never adopt an ACK.
    unsafe impl<G: NativeLifecycleGate>
        crate::windows::member_session::OriginalInitialRowCaptureCleanupWrite
        for NativeInitialRowCaptureCleanupWrite<G>
    {
        fn backend_original(
            &self,
        ) -> &crate::windows::member_session::OriginalSessionFilesIdentity {
            &self.origin.backend
        }
        fn row_original(&self) -> &rows::RowRecordReadPin {
            &self.origin.original
        }
        fn verify_backend(
            &self,
            backend: &crate::windows::member_session::OriginalSessionFilesIdentity,
            original: &rows::InitialRowCaptureCleanupRead<'_>,
        ) -> std::io::Result<()> {
            self.verify_original(original)?;
            if !self.origin.backend.same_original(backend) {
                self.origin.root.fail();
                return Err(std::io::Error::other("carrier_initial_cleanup_backend"));
            }
            self.verify_original(original)
        }
        fn verify_pair(
            &self,
            payload: &[u8],
            original: &rows::InitialRowCaptureCleanupRead<'_>,
        ) -> std::io::Result<()> {
            self.verify_original(original)?;
            if payload != self.origin.pair_payload {
                self.origin.root.fail();
                return Err(std::io::Error::other("carrier_initial_cleanup_pair"));
            }
            self.verify_original(original)
        }
        fn verify_write(
            &self,
            scope: &nelomai_client_tunnel::redundancy::SessionScope,
            kind: RecordKind,
            expected: Option<&[u8]>,
            desired: &[u8],
            original: &rows::InitialRowCaptureCleanupRead<'_>,
        ) -> std::io::Result<()> {
            self.verify_original(original)?;
            let result = (|| {
                if scope != &self.origin.context.intent.scope || kind != RecordKind::CarrierRows {
                    return Err(Error::Conflict);
                }
                original
                    .verify_payloads(expected, desired)
                    .map_err(denied)?;
                let expected = expected
                    .map(rows::Record::decode)
                    .transpose()
                    .map_err(denied)?;
                let desired = rows::Record::decode(desired).map_err(denied)?;
                super::compare_initial_capture_cleanup_storage(
                    &self.origin.context,
                    &self.origin.pair_record,
                    original.binding(),
                    &self.initial,
                    expected.as_ref(),
                    &desired,
                )
                .map_err(denied)
            })();
            if result.is_err() {
                self.origin.root.fail();
            }
            result.map_err(|_| std::io::Error::other("carrier_initial_cleanup_write"))?;
            self.verify_original(original)
        }
        fn fail_write(&self) {
            self.origin.root.fail();
        }
    }
    impl<G: NativeLifecycleGate> NativeCreatedAddressCleanupWrite<G> {
        fn verify_original(
            &self,
            original: &rows::CreatedAddressCleanupRead<'_>,
        ) -> std::io::Result<()> {
            let result = (|| {
                self.root.verify().map_err(denied)?;
                self.calling
                    .verify(&self.supervisor, &self.context)
                    .map_err(denied)?;
                if !original.matches_record_original(&self.original) {
                    return Err(Error::Conflict);
                }
                Ok(())
            })();
            if result.is_err() {
                self.root.fail();
            }
            result.map_err(|_| std::io::Error::other("carrier_created_cleanup_original"))
        }
    }
    // SAFETY: construction below binds the SAME actual RowOwner authority,
    // private capture pin, canonical cleanup backend, protected Closing Pair ACK
    // and authenticated Runtime/Calling sequence. Roots precede postflight;
    // callbacks are pure and errors retain obligations/irreversibly deny forward.
    // The sealed Create receipt independently verifies exact SDK before/applied
    // facts. This storage capability never authorizes native effects or adoption.
    unsafe impl<G: NativeLifecycleGate>
        crate::windows::member_session::OriginalCreatedAddressCleanupWrite
        for NativeCreatedAddressCleanupWrite<G>
    {
        fn backend_original(
            &self,
        ) -> &crate::windows::member_session::OriginalSessionFilesIdentity {
            &self.backend
        }
        fn row_original(&self) -> &rows::RowRecordReadPin {
            &self.original
        }
        fn verify_backend(
            &self,
            backend: &crate::windows::member_session::OriginalSessionFilesIdentity,
            original: &rows::CreatedAddressCleanupRead<'_>,
        ) -> std::io::Result<()> {
            self.verify_original(original)?;
            if !self.backend.same_original(backend) {
                self.root.fail();
                return Err(std::io::Error::other("carrier_created_cleanup_backend"));
            }
            self.verify_original(original)
        }
        fn verify_pair(
            &self,
            payload: &[u8],
            original: &rows::CreatedAddressCleanupRead<'_>,
        ) -> std::io::Result<()> {
            self.verify_original(original)?;
            if payload != self.pair_payload {
                self.root.fail();
                return Err(std::io::Error::other("carrier_created_cleanup_pair"));
            }
            self.verify_original(original)
        }
        fn verify_write(
            &self,
            scope: &nelomai_client_tunnel::redundancy::SessionScope,
            kind: RecordKind,
            expected: &[u8],
            desired: &[u8],
            original: &rows::CreatedAddressCleanupRead<'_>,
        ) -> std::io::Result<()> {
            self.verify_original(original)?;
            let result = (|| {
                if scope != &self.context.intent.scope || kind != RecordKind::CarrierRows {
                    return Err(Error::Conflict);
                }
                let expected = rows::Record::decode(expected).map_err(denied)?;
                let desired = rows::Record::decode(desired).map_err(denied)?;
                original
                    .verify_exchange(original.binding(), &expected, &desired)
                    .map_err(denied)?;
                super::compare_created_cleanup_storage(
                    &self.context,
                    &self.pair_record,
                    original.binding(),
                    &expected,
                    &desired,
                )
                .map_err(denied)?;
                Ok(())
            })();
            if result.is_err() {
                self.root.fail();
            }
            result.map_err(|_| std::io::Error::other("carrier_created_cleanup_write"))?;
            self.verify_original(original)
        }
        fn fail_write(&self) {
            self.root.fail();
        }
    }
    type CarrierComponents<'a, G> = (
        Carrier<NativeKernel<'a, SharedCarrierAuthority<G>>>,
        NativeRowsAuthority<G>,
    );
    impl<G: NativeLifecycleGate> SharedCarrierAuthority<G> {
        fn other_pin(&self) -> Self {
            Self {
                original: self.original.pin(),
            }
        }
        fn borrow(&self) -> Result<RefMut<'_, NativeCarrierAuthority<G>>> {
            let mut owner = self.original.borrow().map_err(denied)?;
            if self.original.revoked.get() {
                owner.failed = true;
            }
            Ok(owner)
        }
        pub(crate) fn source_read(
            &self,
            address: rows::CreatedAddressReadPin,
        ) -> Result<NativeSourceRead> {
            let mut call = ClosedHistoryCall {
                revoked: &self.original.revoked,
                succeeded: false,
            };
            let mut owner = self.borrow()?;
            owner.verify_supervised()?;
            let before = owner.current(Use::Live)?;
            let source = NativeSourceRead {
                address,
                runtime: owner.runtime.read_pin().map_err(denied)?,
                image: owner.image.read_pin().map_err(denied)?,
                originals: owner.producer.observer(),
                members: owner
                    .producer
                    .original_universe()
                    .member_read_pin()
                    .map_err(denied)?,
                scope: owner.scope.clone(),
                supervisor: owner.gate.supervisor().clone(),
                deadline: owner.gate.supervisor().read_pin().map_err(denied)?,
                fence: owner.source_fence.clone(),
            };
            source.inspect(|_| Ok(()))?;
            same_record(&before, owner.current(Use::Live)?).map_err(denied)?;
            owner.verify_supervised()?;
            call.succeeded = true;
            Ok(source)
        }
        pub(crate) fn closing_read_with_pin(
            &self,
            retain: impl FnOnce(Rc<NativeClosingRead>) -> Result<()>,
        ) -> Result<Rc<NativeClosingRead>> {
            let mut call = ClosedHistoryCall {
                revoked: &self.original.revoked,
                succeeded: false,
            };
            let mut owner = self.borrow()?;
            owner.verify_supervised()?;
            let before = owner.current(Use::Cleanup)?;
            let read = if let Some(original) = &owner.closing_reader {
                original.clone()
            } else {
                let read = Rc::new(NativeClosingRead {
                    runtime: owner.runtime.read_pin().map_err(denied)?,
                    image: owner.image.read_pin().map_err(denied)?,
                    originals: owner.producer.observer(),
                    members: owner
                        .producer
                        .original_universe()
                        .member_read_pin()
                        .map_err(denied)?,
                    scope: owner.scope.clone(),
                    supervisor: owner.gate.supervisor().clone(),
                    deadline: owner.gate.supervisor().read_pin().map_err(denied)?,
                    fence: owner.source_fence.clone(),
                });
                crate::windows::member_carrier_original_read::retain_first_before(
                    &mut owner.closing_reader,
                    read,
                    Error::Conflict,
                    |_| Ok(()),
                )?
            };
            // The authority roots the actual object first; the actor callback
            // must likewise retain it before validation/independent reads.
            retain(read.clone())?;
            read.inspect_bindings(|_| Ok(()))?;
            same_record(&before, owner.current(Use::Cleanup)?).map_err(denied)?;
            owner.verify_supervised()?;
            call.succeeded = true;
            Ok(read)
        }
        /// Retain ONLY this owner's actual once-close completion, after full
        /// C+A+B absence. The returned read pin can be kept by G independently
        /// of Carrier's outer RefMut, avoiding recursive ownership lookups.
        pub(crate) fn retired_read_for_cleanup_with_pin(
            &self,
            retain: impl FnOnce(Rc<RetiredCarrierRead>) -> Result<()>,
        ) -> Result<Rc<RetiredCarrierRead>> {
            let mut call = ClosedHistoryCall {
                revoked: &self.original.revoked,
                succeeded: false,
            };
            let mut owner = self.borrow()?;
            owner.verify_supervised()?;
            let before = owner.current(Use::Cleanup)?;
            let read = owner.retain_retired_reader()?;
            retain(read.clone())?;
            read.inspect(|_| Ok(()))?;
            same_record(&before, owner.current(Use::Cleanup)?).map_err(denied)?;
            owner.verify_supervised()?;
            call.succeeded = true;
            Ok(read)
        }
        pub(crate) fn unpublished_closed_read_with_pin(
            &self,
            retain: impl FnOnce(Rc<UnpublishedClosedCarrierRead>) -> Result<()>,
        ) -> Result<Rc<UnpublishedClosedCarrierRead>> {
            let mut call = ClosedHistoryCall {
                revoked: &self.original.revoked,
                succeeded: false,
            };
            let mut owner = self.borrow()?;
            owner.verify_supervised()?;
            let before = owner.current(Use::Cleanup)?;
            let read = owner.retain_unpublished_closed_reader()?;
            retain(read.clone())?; // caller roots BEFORE any SDK/postflight
            read.inspect(|| Ok(()))?;
            same_record(&before, owner.current(Use::Cleanup)?).map_err(denied)?;
            owner.verify_supervised()?;
            call.succeeded = true;
            Ok(read)
        }
    }
    impl NativeSourceRead {
        /// Narrow original-C factual bracket for process-reader renewal. This
        /// deliberately does not call the integrated A/B inventory recursively.
        /// Caller must authenticate actual old/new process receipts and query
        /// the FULL mixed SDK universe before and after its publication.
        pub(crate) fn inspect_inventory_renewal_carrier<T>(
            &self,
            context: &receipts::Context,
            runtime: &RuntimeRead,
            inventory: &crate::windows::member_carrier_members::native::MemberInventoryRead,
            inspect: impl FnOnce(&carrier_provider::ExpectedProvider) -> Result<T>,
        ) -> Result<T> {
            self.fence.inspect(
                || {
                    let revision = self.revision()?;
                    if context != &self.scope.context
                        || !self.runtime.same_original_runtime(runtime)
                        || !self.matches_member_inventory(inventory)
                    {
                        return Err(Error::Conflict);
                    }
                    let captured = self
                        .address
                        .read(&context.intent.scope, context.provenance.network_epoch)
                        .map_err(denied)?;
                    let snapshot = source_sdk_snapshot(captured.binding)?;
                    Ok((
                        revision,
                        captured.binding.clone(),
                        captured.captured.clone(),
                        snapshot,
                    ))
                },
                |(revision, binding, captured, snapshot)| {
                    self.originals
                        .inspect_live_carrier_identity(&self.scope, |actual| {
                            super::ready_source_comparison(
                                context,
                                &actual.identity,
                                binding,
                                captured,
                                &crate::member_carrier_rows::Record::decode(&revision.1)
                                    .map_err(|_| creators::Error::Conflict)?,
                                snapshot,
                            )
                            .map_err(|_| creators::Error::Conflict)?;
                            let c = carrier_provider::ExpectedProvider {
                                kind: carrier_provider::ProviderKind::Wintun,
                                identity: carrier_provider::Expected {
                                    guid: actual.identity.guid,
                                    luid: actual.identity.luid,
                                    index: actual.identity.index,
                                    name: actual.identity.name.clone(),
                                    description: actual.identity.description.clone(),
                                    if_type: actual.identity.if_type,
                                    tunnel_type: actual.identity.tunnel_type,
                                },
                            };
                            inspect(&c).map_err(|_| creators::Error::Conflict)
                        })
                        .map_err(denied)
                },
                || Error::Conflict,
            )
        }
        /// Original inventory identity only. No read, mutation or SDK authority
        /// is inferred from this comparison; generation changes still require
        /// independent whole Source windows before and after the transition.
        pub(crate) fn matches_member_inventory(
            &self,
            members: &crate::windows::member_carrier_members::native::MemberInventoryRead,
        ) -> bool {
            self.members.same_original(members)
        }
        /// Metadata and actual private-file read for the independently bracketed
        /// network sampler. These confer no route/DNS/WFP effect permission.
        pub(in crate::windows) fn network_scope(
            &self,
        ) -> &nelomai_client_tunnel::redundancy::SessionScope {
            &self.scope.context.intent.scope
        }
        pub(in crate::windows) fn protected_network_record(&self) -> Result<Option<Vec<u8>>> {
            self.deadline
                .verify_call(&self.supervisor, &self.scope.context)
                .map_err(denied)?;
            self.runtime
                .optional_record(&self.scope.context, RecordKind::Network)
                .map_err(denied)
        }
        fn revision(&self) -> Result<SourceRevision> {
            if self.fence.revoked.get() {
                return Err(Error::Retired);
            }
            self.deadline
                .verify_call(&self.supervisor, &self.scope.context)
                .map_err(denied)?;
            self.runtime.verify(&self.scope.context).map_err(denied)?;
            self.image.verify_runtime(&self.runtime).map_err(denied)?;
            if !self.runtime.fresh(&self.scope.context).map_err(denied)? {
                return Err(Error::Retired);
            }
            let native = self
                .runtime
                .record(&self.scope.context, RecordKind::NativeCarrierReceipts)
                .map_err(denied)?;
            let record = receipts::Record::decode(&native).map_err(denied)?;
            validate_stage(
                &record,
                &self.scope.context,
                &self.scope.binding,
                self.scope.generation,
                true,
                Use::Live,
            )
            .map_err(denied)?;
            let rows = self
                .runtime
                .record(&self.scope.context, RecordKind::CarrierRows)
                .map_err(denied)?;
            self.deadline
                .verify_call(&self.supervisor, &self.scope.context)
                .map_err(denied)?;
            if self.fence.revoked.get() {
                return Err(Error::Retired);
            }
            Ok((native, rows))
        }
        fn sample(&self) -> Result<SourceSample> {
            self.sample_for_row(None)
        }
        fn members_with_history(
            &self,
            carrier: &creators::Identity,
        ) -> Result<(
            Vec<carrier_provider::ExpectedProvider>,
            Vec<carrier_members::ClosedMemberBinding>,
        )> {
            let c = carrier_provider::ExpectedProvider {
                kind: carrier_provider::ProviderKind::Wintun,
                identity: carrier_provider::Expected {
                    guid: carrier.guid,
                    luid: carrier.luid,
                    index: carrier.index,
                    name: carrier.name.clone(),
                    description: carrier.description.clone(),
                    if_type: carrier.if_type,
                    tunnel_type: carrier.tunnel_type,
                },
            };
            self.members
                .inspect_source_bindings_full(
                    &self.scope.context,
                    &self.runtime,
                    &self.image,
                    &[c],
                    |live, history| Ok((live.to_vec(), history.to_vec())),
                )
                .map_err(denied)
        }
        fn sample_for_row(
            &self,
            effect: Option<(&rows::Binding, &rows::Target)>,
        ) -> Result<SourceSample> {
            let before = self.revision()?;
            self.members
                .matches_original_runtime_image(&self.runtime, &self.image)
                .map_err(denied)?;
            let captured = self
                .address
                .read(
                    &self.scope.context.intent.scope,
                    self.scope.context.provenance.network_epoch,
                )
                .map_err(denied)?;
            let all = self
                .originals
                .observe_all(&self.scope.context)
                .map_err(denied)?;
            if all.originals.len() != 1 || all.originals[0].scope != self.scope {
                return Err(Error::Conflict);
            }
            let (members, history) = self.members_with_history(&all.originals[0].identity)?;
            let record = crate::member_carrier_rows::Record::decode(&before.1).map_err(denied)?;
            let snapshot = source_sdk_snapshot(captured.binding)?;
            let source = if let Some((binding, target)) = effect {
                if captured.binding != binding {
                    return Err(Error::Conflict);
                }
                super::row_effect_source_comparison(
                    &receipts::Record::decode(&before.0).map_err(denied)?,
                    &all.originals[0].identity,
                    captured.binding,
                    captured.captured,
                    &record,
                    &snapshot,
                    target,
                )
            } else {
                super::ready_source_comparison(
                    &self.scope.context,
                    &all.originals[0].identity,
                    captured.binding,
                    captured.captured,
                    &record,
                    &snapshot,
                )
            }
            .map_err(denied)?;
            let after = self
                .originals
                .observe_all(&self.scope.context)
                .map_err(denied)?;
            let captured_after = self
                .address
                .read(
                    &self.scope.context.intent.scope,
                    self.scope.context.provenance.network_epoch,
                )
                .map_err(denied)?;
            if all != after
                || captured.binding != captured_after.binding
                || captured.captured != captured_after.captured
                || (members.clone(), history.clone())
                    != self.members_with_history(&all.originals[0].identity)?
                || snapshot != source_sdk_snapshot(captured.binding)?
                || before != self.revision()?
            {
                return Err(Error::Conflict);
            }
            Ok(SourceSample {
                revision: before,
                rows: snapshot,
                original: all.originals[0].identity.clone(),
                carrier: source,
                members,
                history,
            })
        }
        /// Full callback is bracketed, without calling RowOwner/NativeRowsAuthority
        /// or G recursively. Only raw readonly SDK calls follow actual opaque
        /// original/read-cap checks. Errors, unwind and ignored nested failure
        /// permanently revoke SAME C forward authority; no physical fallback.
        pub(crate) fn inspect<T>(
            &self,
            inspect: impl FnOnce(&crate::member_carrier_guard::Carrier) -> Result<T>,
        ) -> Result<T> {
            self.fence.inspect(
                || self.sample(),
                |facts| inspect(&facts.carrier),
                || Error::Conflict,
            )
        }
        /// WFP/network/probe comparison inputs from the actual SAME original C,
        /// actual address-create/readiness pin, and actual service-owner A/B
        /// readers. FULL mixed native inventory and all protected rows/runtime
        /// revisions bracket the WHOLE callback, not only a cached projection.
        pub(crate) fn inspect_bindings<T>(
            &self,
            inspect: impl FnOnce(&crate::windows::member_carrier_guard::Bindings) -> Result<T>,
        ) -> Result<T> {
            self.inspect_bindings_for_row(None, inspect)
        }
        pub(crate) fn inspect_window<T>(
            &self,
            inspect: impl FnOnce(&NativeBindingsWindow<'_>) -> Result<T>,
        ) -> Result<T> {
            self.inspect_window_for_row(None, inspect)
        }
        /// Exact pending C weak-row callback ONLY. It exports comparison facts,
        /// not an ordinary source/WFP allow grant. Protected target + actual
        /// before-or-applied full SDK row and SAME original ACK bracket callback;
        /// concrete G separately requires bases/no-permits/network ordering.
        pub(crate) fn inspect_row_effect<T>(
            &self,
            binding: &rows::Binding,
            target: &rows::Target,
            inspect: impl FnOnce(&crate::windows::member_carrier_guard::Bindings) -> Result<T>,
        ) -> Result<T> {
            self.inspect_bindings_for_row(Some((binding, target)), inspect)
        }
        /// The EXISTING exact pending C-row observation with its opaque
        /// read-only window, not an ordinary live-source/effect grant.
        pub(crate) fn inspect_row_effect_window<T>(
            &self,
            binding: &rows::Binding,
            target: &rows::Target,
            inspect: impl FnOnce(&NativeBindingsWindow<'_>) -> Result<T>,
        ) -> Result<T> {
            self.inspect_window_for_row(Some((binding, target)), inspect)
        }
        fn inspect_bindings_for_row<T>(
            &self,
            effect: Option<(&rows::Binding, &rows::Target)>,
            inspect: impl FnOnce(&crate::windows::member_carrier_guard::Bindings) -> Result<T>,
        ) -> Result<T> {
            self.inspect_window_for_row(effect, |window| inspect(window.bindings()))
        }
        fn inspect_window_for_row<T>(
            &self,
            effect: Option<(&rows::Binding, &rows::Target)>,
            inspect: impl FnOnce(&NativeBindingsWindow<'_>) -> Result<T>,
        ) -> Result<T> {
            self.fence.inspect(
                || self.sample_for_row(effect),
                |facts| {
                    let history = facts
                        .history
                        .iter()
                        .map(|h| h.comparison_provider(&self.scope.context))
                        .collect::<crate::member_carrier::Result<Vec<_>>>()
                        .map_err(denied)?;
                    let projected = super::closing_comparison_bindings(
                        &self.scope.context,
                        &facts.original,
                        &facts.members,
                        &history,
                    )
                    .map_err(denied)?;
                    if projected.carrier.as_ref() != Some(&facts.carrier) {
                        return Err(Error::Conflict);
                    }
                    let window = NativeBindingsWindow {
                        origin: WindowOrigin::Source(self, facts, effect),
                        bindings: crate::windows::member_carrier_guard::Bindings {
                            scope: projected.scope,
                            carrier: projected.carrier,
                            egress: projected.egress,
                        },
                    };
                    inspect(&window)
                },
                || Error::Conflict,
            )
        }
    }
    fn source_sdk_snapshot(binding: &rows::Binding) -> Result<rows::Snapshot> {
        // Factual SDK identity/full-row bracket is nested in this source's
        // SAME-original Runtime/Calling/create-ACK/protected revision bracket.
        // Exact absence is not a usable source; preserve the previous denial.
        let snapshot = rows::native::read_original_snapshot(binding).map_err(denied)?;
        if snapshot.address.is_none() {
            return Err(Error::Native);
        }
        Ok(snapshot)
    }
    impl NativeClosingRead {
        pub(in crate::windows) fn network_scope(
            &self,
        ) -> &nelomai_client_tunnel::redundancy::SessionScope {
            &self.scope.context.intent.scope
        }
        /// Factual protected-file read only. Network sampling must additionally
        /// bracket this with this SAME opaque Closing window/full SDK facts.
        pub(in crate::windows) fn protected_network_record(&self) -> Result<Option<Vec<u8>>> {
            self.deadline
                .verify_call(&self.supervisor, &self.scope.context)
                .map_err(denied)?;
            self.runtime
                .optional_record(&self.scope.context, RecordKind::Network)
                .map_err(denied)
        }
        /// Original provenance only, not Closing/absence/effect permission.
        /// These pins were minted through the SAME retained C authority; equal
        /// context/GUID/index from a different construction cannot match.
        pub(crate) fn matches_source_origin(&self, source: &NativeSourceRead) -> bool {
            Rc::ptr_eq(&self.fence, &source.fence)
                && self.runtime.same_original_runtime(&source.runtime)
                && self.scope == source.scope
        }
        fn revision(&self) -> Result<SourceRevision> {
            self.deadline
                .verify_call(&self.supervisor, &self.scope.context)
                .map_err(denied)?;
            self.runtime.verify(&self.scope.context).map_err(denied)?;
            self.image.verify_runtime(&self.runtime).map_err(denied)?;
            let native = self
                .runtime
                .record(&self.scope.context, RecordKind::NativeCarrierReceipts)
                .map_err(denied)?;
            validate_stage(
                &receipts::Record::decode(&native).map_err(denied)?,
                &self.scope.context,
                &self.scope.binding,
                self.scope.generation,
                false,
                Use::Cleanup,
            )
            .map_err(denied)?;
            let rows = self
                .runtime
                .record(&self.scope.context, RecordKind::CarrierRows)
                .map_err(denied)?;
            self.deadline
                .verify_call(&self.supervisor, &self.scope.context)
                .map_err(denied)?;
            Ok((native, rows))
        }
        fn members(
            &self,
            carrier: &creators::Identity,
            partial: Option<
                &crate::windows::member_carrier_member_controller::native::PartialCleanup,
            >,
        ) -> Result<(
            Vec<crate::windows::member_carrier_provider::ExpectedProvider>,
            Vec<crate::windows::member_carrier_members::ClosedMemberBinding>,
        )> {
            use crate::windows::member_carrier_provider::{
                Expected, ExpectedProvider, ProviderKind,
            };
            let c = ExpectedProvider {
                identity: Expected {
                    guid: carrier.guid,
                    luid: carrier.luid,
                    index: carrier.index,
                    name: carrier.name.clone(),
                    description: carrier.description.clone(),
                    if_type: carrier.if_type,
                    tunnel_type: carrier.tunnel_type,
                },
                kind: ProviderKind::Wintun,
            };
            if let Some(partial) = partial {
                return self
                    .members
                    .inspect_partial_closing_bindings(
                        &self.scope.context,
                        &self.runtime,
                        &self.image,
                        &[c],
                        partial,
                        |live, history| Ok((live.to_vec(), history.to_vec())),
                    )
                    .map_err(denied);
            }
            self.members
                .inspect_closing_bindings_full(
                    &self.scope.context,
                    &self.runtime,
                    &self.image,
                    &[c],
                    |live, history| Ok((live.to_vec(), history.to_vec())),
                )
                .map_err(denied)
        }
        fn sample(&self) -> Result<ClosingSample> {
            self.sample_inner(None)
        }
        fn sample_partial(
            &self,
            partial: &crate::windows::member_carrier_member_controller::native::PartialCleanup,
        ) -> Result<ClosingSample> {
            self.sample_inner(Some(partial))
        }
        fn sample_inner(
            &self,
            partial: Option<
                &crate::windows::member_carrier_member_controller::native::PartialCleanup,
            >,
        ) -> Result<ClosingSample> {
            let before = self.revision()?;
            let partial_observation = partial
                .map(|original| original.inspect().map_err(denied))
                .transpose()?;
            let all = self
                .originals
                .observe_all_for_cleanup(&self.scope.context)
                .map_err(denied)?;
            if all.originals.len() != 1 || all.originals[0].scope != self.scope {
                return Err(Error::Conflict);
            }
            let (members, history) = self.members(&all.originals[0].identity, partial)?;
            // Matching rows still grant no native ACK. Protected full-row
            // binding must agree with this actual retained original C.
            let rows = crate::member_carrier_rows::Record::decode(&before.1).map_err(denied)?;
            if rows.binding
                != super::rows_binding(&self.scope.context, &all.originals[0].identity)
                    .map_err(denied)?
            {
                return Err(Error::Conflict);
            }
            if (members.clone(), history.clone())
                != self.members(&all.originals[0].identity, partial)?
                || all
                    != self
                        .originals
                        .observe_all_for_cleanup(&self.scope.context)
                        .map_err(denied)?
                || before != self.revision()?
                || partial
                    .map(|original| original.inspect().map_err(denied))
                    .transpose()?
                    != partial_observation
            {
                return Err(Error::Conflict);
            }
            Ok(ClosingSample {
                revision: before,
                original: all.originals[0].identity.clone(),
                members,
                history,
                partial: partial_observation,
            })
        }
        /// Only SAME retained partial SCM cleanup, never a live Source window.
        /// Every joined row/network/BFE read reattests this exact original pin
        /// and full SDK namespace; target comparison never enters Bindings.
        pub(crate) fn inspect_partial_member_window<T>(
            &self,
            partial: &Rc<crate::windows::member_carrier_member_controller::native::PartialCleanup>,
            inspect: impl FnOnce(&NativeBindingsWindow<'_>) -> Result<T>,
        ) -> Result<T> {
            self.fence.inspect_cleanup(
                || self.sample_partial(partial),
                |facts| {
                    let history = facts
                        .history
                        .iter()
                        .map(|h| h.comparison_provider(&self.scope.context))
                        .collect::<crate::member_carrier::Result<Vec<_>>>()
                        .map_err(denied)?;
                    let projected = super::closing_comparison_bindings(
                        &self.scope.context,
                        &facts.original,
                        &facts.members,
                        &history,
                    )
                    .map_err(denied)?;
                    let window = NativeBindingsWindow {
                        origin: WindowOrigin::PartialClosing(self, partial, facts),
                        bindings: crate::windows::member_carrier_guard::Bindings {
                            scope: projected.scope,
                            carrier: projected.carrier,
                            egress: projected.egress,
                        },
                    };
                    inspect(&window)
                },
                || Error::Conflict,
            )
        }
        pub(crate) fn inspect_bindings<T>(
            &self,
            inspect: impl FnOnce(&crate::windows::member_carrier_guard::Bindings) -> Result<T>,
        ) -> Result<T> {
            self.inspect_window(|window| inspect(window.bindings()))
        }
        pub(crate) fn inspect_window<T>(
            &self,
            inspect: impl FnOnce(&NativeBindingsWindow<'_>) -> Result<T>,
        ) -> Result<T> {
            self.fence.inspect_cleanup(
                || self.sample(),
                |facts| {
                    // The typed closed facts have no native description and
                    // never become live provider inputs. Conversion here is
                    // exclusively for the comparison-only guard projection.
                    let history = facts
                        .history
                        .iter()
                        .map(|h| h.comparison_provider(&self.scope.context))
                        .collect::<crate::member_carrier::Result<Vec<_>>>()
                        .map_err(denied)?;
                    let projected = super::closing_comparison_bindings(
                        &self.scope.context,
                        &facts.original,
                        &facts.members,
                        &history,
                    )
                    .map_err(denied)?;
                    let window = NativeBindingsWindow {
                        origin: WindowOrigin::Closing(self, facts),
                        bindings: crate::windows::member_carrier_guard::Bindings {
                            scope: projected.scope,
                            carrier: projected.carrier,
                            egress: projected.egress,
                        },
                    };
                    inspect(&window)
                },
                || Error::Conflict,
            )
        }
    }
    impl UnpublishedClosedCarrierRead {
        /// Exact Closing factual bracket; no published row or Source required.
        pub(crate) fn inspect<T>(&self, inspect: impl FnOnce() -> Result<T>) -> Result<T> {
            self.inspect_for(false, inspect)
        }
        /// Separate exact Stopped/all-clean-keys factual bracket. Never aliases
        /// the earlier Closing channel or grants permission to release roots.
        pub(crate) fn inspect_terminal<T>(&self, inspect: impl FnOnce() -> Result<T>) -> Result<T> {
            self.inspect_for(true, inspect)
        }
        fn revision(&self, terminal: bool) -> Result<Vec<u8>> {
            self.deadline
                .verify_call(&self.supervisor, &self.scope.context)
                .map_err(denied)?;
            self.runtime.verify(&self.scope.context).map_err(denied)?;
            self.image.verify_runtime(&self.runtime).map_err(denied)?;
            let bytes = self
                .runtime
                .record(&self.scope.context, RecordKind::NativeCarrierReceipts)
                .map_err(denied)?;
            let record = receipts::Record::decode(&bytes).map_err(denied)?;
            if terminal {
                validate_terminal_stage(
                    &record,
                    &self.scope.context,
                    &self.scope.binding,
                    self.scope.generation,
                )
            } else {
                validate_stage(
                    &record,
                    &self.scope.context,
                    &self.scope.binding,
                    self.scope.generation,
                    false,
                    Use::Cleanup,
                )
            }
            .map_err(denied)?;
            self.deadline
                .verify_call(&self.supervisor, &self.scope.context)
                .map_err(denied)?;
            Ok(bytes)
        }
        fn inspect_for<T>(&self, terminal: bool, inspect: impl FnOnce() -> Result<T>) -> Result<T> {
            let mut call = ClosedHistoryCall {
                revoked: &self.revoked,
                succeeded: false,
            };
            let before = self.revision(terminal)?;
            let mut absence = OriginalUniverse::new(&self.runtime, &self.image).map_err(denied)?;
            let result = self
                .original
                .inspect(&self.scope, &mut absence, || {
                    let callback = |history: &[carrier_members::ClosedMemberBinding]| {
                        // A/B cannot legitimately have published before raw C.
                        // Actual member receipts + FULL mixed empty SDK, not a
                        // missing journal or equal numeric identity, prove this.
                        if !history.is_empty() {
                            return Err(crate::member_carrier::CarrierError::Conflict);
                        }
                        let value =
                            inspect().map_err(|_| crate::member_carrier::CarrierError::Conflict)?;
                        if self
                            .revision(terminal)
                            .map_err(|_| crate::member_carrier::CarrierError::Conflict)?
                            != before
                        {
                            return Err(crate::member_carrier::CarrierError::Conflict);
                        }
                        Ok(value)
                    };
                    if terminal {
                        self.members.inspect_terminal_bindings_full(
                            &self.scope.context,
                            &self.runtime,
                            &self.image,
                            callback,
                        )
                    } else {
                        self.members.inspect_retired_bindings_full(
                            &self.scope.context,
                            &self.runtime,
                            &self.image,
                            callback,
                        )
                    }
                    .map_err(|_| creators::Error::Conflict)
                })
                .map_err(denied)?;
            if self.revision(terminal)? != before {
                return Err(Error::Conflict);
            }
            call.succeeded = true;
            Ok(result)
        }
    }
    impl RetiredCarrierRead {
        /// Actual adapter's extra loader reference, NOT the owning module.
        /// Must be nested in Pair.inspect + this full terminal Retired callback.
        /// Keep the receipt rooted here BEFORE external retention/postflight.
        pub(crate) fn release_adapter_reference_in_terminal_bracket(
            &self,
            pair: &crate::windows::member_carrier_pair_store::native_store::NativePairIntentRead,
            record: &crate::member_carrier_pair::Record,
            retain: impl FnOnce(Rc<OriginalAdapterModuleReleased>) -> Result<()>,
        ) -> Result<()> {
            let revision = self.terminal_revision()?;
            let fence = RetiredAdapterReferenceFence {
                retired: self,
                pair,
                record,
                revision: &revision,
            };
            fence
                .verify_original_terminal(&self.scope)
                .map_err(denied)?;
            let mut retained = self
                .adapter_reference
                .try_borrow_mut()
                .map_err(|_| Error::Conflict)?;
            self.original
                .with_original_closed_in_bracket(|original, closed| {
                    if let Some(ack) = retained.as_ref() {
                        original.verify_closed_reference_in_terminal(&self.scope, closed, ack)?;
                        retain(ack.clone()).map_err(|_| creators::Error::Conflict)?;
                    } else {
                        original.release_closed_reference_in_terminal(
                            &self.scope,
                            closed,
                            &fence,
                            |ack| {
                                *retained = Some(ack.clone());
                                retain(ack).map_err(|_| creators::Error::Conflict)
                            },
                        )?;
                    }
                    fence.verify_original_terminal(&self.scope)
                })
                .map_err(denied)
        }
        /// Factual once-release receipt only; no SDK or native effect. The full
        /// outer Retired native bracket and exact Pair/Calling stay mandatory.
        pub(crate) fn verify_adapter_reference_in_terminal_bracket(
            &self,
            pair: &crate::windows::member_carrier_pair_store::native_store::NativePairIntentRead,
            record: &crate::member_carrier_pair::Record,
            ack: &Rc<OriginalAdapterModuleReleased>,
        ) -> Result<()> {
            let revision = self.terminal_revision()?;
            let fence = RetiredAdapterReferenceFence {
                retired: self,
                pair,
                record,
                revision: &revision,
            };
            fence
                .verify_original_terminal(&self.scope)
                .map_err(denied)?;
            let retained = self
                .adapter_reference
                .try_borrow()
                .map_err(|_| Error::Conflict)?;
            if retained
                .as_ref()
                .is_none_or(|original| !Rc::ptr_eq(original, ack))
            {
                return Err(Error::Conflict);
            }
            self.original
                .with_original_closed_in_bracket(|original, closed| {
                    original.verify_closed_reference_in_terminal(&self.scope, closed, ack)?;
                    fence.verify_original_terminal(&self.scope)
                })
                .map_err(denied)
        }
        /// SAME originating C capability only. Native closed ACK/full absence
        /// and precise protected cleanup stage are still verified by inspect.
        pub(crate) fn matches_source_origin(&self, source: &NativeSourceRead) -> bool {
            Rc::ptr_eq(&self.revoked, &source.fence.revoked)
                && self.runtime.same_original_runtime(&source.runtime)
                && self.scope == source.scope
        }
        /// Terminal-only factual comparison after ALL original registry keys
        /// are acknowledged restored. The ordinary Closing path is unchanged.
        /// The exact original C close ACK surrounds independently closed A/B
        /// histories and two full mixed SDK-empty queries, under one Calling.
        pub(crate) fn inspect_terminal_bindings_and_history<T>(
            &self,
            inspect: impl FnOnce(
                &crate::windows::member_carrier_guard::Bindings,
                &[carrier_members::ClosedMemberBinding],
            ) -> Result<T>,
        ) -> Result<T> {
            let mut call = ClosedHistoryCall {
                revoked: &self.revoked,
                succeeded: false,
            };
            let before = self.terminal_revision()?;
            // Do not use with_members: that constructor is deliberately tied
            // to live/Closing inventory. This raw-C query supplies no member
            // authority; the nested terminal reader authenticates their exact
            // originals and queries the FULL mixed provider universe itself.
            let mut absence = OriginalUniverse::new(&self.runtime, &self.image).map_err(denied)?;
            let result = self
                .original
                .inspect(&mut absence, |carrier| {
                    if carrier.captured().scope != self.scope {
                        return Err(creators::Error::Conflict);
                    }
                    self.members
                        .inspect_terminal_bindings_full(
                            &self.scope.context,
                            &self.runtime,
                            &self.image,
                            |history| {
                                let providers = history
                                    .iter()
                                    .map(|entry| entry.comparison_provider(&self.scope.context))
                                    .collect::<crate::member_carrier::Result<Vec<_>>>()?;
                                let facts = super::comparison_bindings(
                                    &self.scope.context,
                                    &carrier.captured().identity,
                                    &providers,
                                )
                                .map_err(|_| crate::member_carrier::CarrierError::Conflict)?;
                                let bindings = crate::windows::member_carrier_guard::Bindings {
                                    scope: facts.scope,
                                    carrier: facts.carrier,
                                    egress: facts.egress,
                                };
                                let value = self
                                    .history
                                    .within(history.to_vec(), || {
                                        inspect(&bindings, history).map_err(|_| {
                                            crate::member_carrier::CarrierError::Conflict
                                        })
                                    })
                                    .map_err(|_| crate::member_carrier::CarrierError::Conflict)?;
                                if self
                                    .terminal_revision()
                                    .map_err(|_| crate::member_carrier::CarrierError::Conflict)?
                                    != before
                                {
                                    return Err(crate::member_carrier::CarrierError::Conflict);
                                }
                                Ok(value)
                            },
                        )
                        .map_err(|_| creators::Error::Conflict)
                })
                .map_err(denied)?;
            if self.terminal_revision()? != before {
                return Err(Error::Conflict);
            }
            call.succeeded = true;
            Ok(result)
        }
        /// Only while the SAME terminal retired callback above is active.
        /// No recursive Pair, inventory or SDK queries; this is not permission
        /// to close/unload and cannot be used by the ordinary Closing gate.
        pub(crate) fn inspect_terminal_history_in_bracket<T>(
            &self,
            inspect: impl FnOnce(&[carrier_members::ClosedMemberBinding]) -> Result<T>,
        ) -> Result<T> {
            let before = self.terminal_revision()?;
            let history = self.history.snapshot().map_err(denied)?;
            let result = inspect(&history)?;
            if self.terminal_revision()? != before {
                return Err(Error::Conflict);
            }
            Ok(result)
        }
        fn terminal_revision(&self) -> Result<Vec<u8>> {
            self.deadline
                .verify_call(&self.supervisor, &self.scope.context)
                .map_err(denied)?;
            self.runtime.verify(&self.scope.context).map_err(denied)?;
            self.image.verify_runtime(&self.runtime).map_err(denied)?;
            let bytes = self
                .runtime
                .record(&self.scope.context, RecordKind::NativeCarrierReceipts)
                .map_err(denied)?;
            let record = receipts::Record::decode(&bytes).map_err(denied)?;
            validate_retired_read_stage(
                &record,
                &self.scope.context,
                &self.scope.binding,
                self.scope.generation,
                RetiredReadStage::Terminal,
            )
            .map_err(denied)?;
            self.deadline
                .verify_call(&self.supervisor, &self.scope.context)
                .map_err(denied)?;
            Ok(bytes)
        }
        /// Final cleanup comparison bindings from BOTH actual closed histories.
        /// Native empty queries remain empty; these historical identities are
        /// never passed as live provider inputs or source-readiness permission.
        pub(crate) fn inspect_bindings<T>(
            &self,
            inspect: impl FnOnce(&crate::windows::member_carrier_guard::Bindings) -> Result<T>,
        ) -> Result<T> {
            self.inspect_bindings_and_history(|bindings, _| inspect(bindings))
        }
        pub(crate) fn inspect_bindings_and_history<T>(
            &self,
            inspect: impl FnOnce(
                &crate::windows::member_carrier_guard::Bindings,
                &[carrier_members::ClosedMemberBinding],
            ) -> Result<T>,
        ) -> Result<T> {
            self.inspect(|carrier| {
                self.members
                    .inspect_retired_bindings_full(
                        &self.scope.context,
                        &self.runtime,
                        &self.image,
                        |history| {
                            let providers = history
                                .iter()
                                .map(|entry| entry.comparison_provider(&self.scope.context))
                                .collect::<std::result::Result<Vec<_>, _>>()?;
                            let facts = super::comparison_bindings(
                                &self.scope.context,
                                &carrier.captured().identity,
                                &providers,
                            )
                            .map_err(|_| crate::member_carrier::CarrierError::Conflict)?;
                            let bindings = crate::windows::member_carrier_guard::Bindings {
                                scope: facts.scope,
                                carrier: facts.carrier,
                                egress: facts.egress,
                            };
                            self.history
                                .within(history.to_vec(), || {
                                    inspect(&bindings, history)
                                        .map_err(|_| crate::member_carrier::CarrierError::Conflict)
                                })
                                .map_err(|_| crate::member_carrier::CarrierError::Conflict)
                        },
                    )
                    .map_err(denied)
            })
        }
        /// Factual original histories ONLY while the caller holds this retired
        /// full-empty bracket. Never re-enters Retired/Source or a mutable owner.
        pub(crate) fn inspect_history_in_bracket<T>(
            &self,
            inspect: impl FnOnce(&[carrier_members::ClosedMemberBinding]) -> Result<T>,
        ) -> Result<T> {
            let before = self.revision()?;
            // This is a lease over the exact outer SDK-bracketed callback, not
            // a nested inventory/Retired read. Facts vanish on Err/unwind.
            let history = self.history.snapshot().map_err(denied)?;
            let value = inspect(&history)?;
            if self.revision()? != before {
                return Err(Error::Conflict);
            }
            Ok(value)
        }
        fn revision(&self) -> Result<Vec<u8>> {
            self.deadline
                .verify_call(&self.supervisor, &self.scope.context)
                .map_err(denied)?;
            self.runtime.verify(&self.scope.context).map_err(denied)?;
            self.image.verify_runtime(&self.runtime).map_err(denied)?;
            let bytes = self
                .runtime
                .record(&self.scope.context, RecordKind::NativeCarrierReceipts)
                .map_err(denied)?;
            let record = receipts::Record::decode(&bytes).map_err(denied)?;
            validate_retired_read_stage(
                &record,
                &self.scope.context,
                &self.scope.binding,
                self.scope.generation,
                RetiredReadStage::Cleanup,
            )
            .map_err(denied)?;
            self.deadline
                .verify_call(&self.supervisor, &self.scope.context)
                .map_err(denied)?;
            Ok(bytes)
        }
        /// Bracket the caller's factual WFP read with SAME actual opaque closed
        /// C receipt and FULL C+A+B native absence. Historical identity never
        /// feeds a live provider/readiness query or gives mutation permission.
        /// The coordinator must supervise this whole read; errors/unwind keep
        /// the original pins and revoke forward authority, not permit recovery.
        pub(crate) fn inspect<T>(
            &self,
            inspect: impl FnOnce(
                &creators::RetiredObservation<crate::windows::member_carrier_provider::Observation>,
            ) -> Result<T>,
        ) -> Result<T> {
            let mut call = ClosedHistoryCall {
                revoked: &self.revoked,
                succeeded: false,
            };
            let before = self.revision()?;
            let mut absence = OriginalUniverse::new(&self.runtime, &self.image)
                .map_err(denied)?
                .with_members(self.members.read_pin())
                .map_err(denied)?;
            let result = self
                .original
                .inspect(&mut absence, |facts| {
                    if facts.captured().scope != self.scope {
                        return Err(creators::Error::Conflict);
                    }
                    let result = inspect(facts).map_err(|_| creators::Error::Conflict)?;
                    if before != self.revision().map_err(|_| creators::Error::Conflict)? {
                        return Err(creators::Error::Conflict);
                    }
                    Ok(result)
                })
                .map_err(denied)?;
            // The factual postflight itself is expensive and must remain inside
            // the SAME watchdog/protected revision, after the callback fence.
            if before != self.revision()? {
                return Err(Error::Conflict);
            }
            call.succeeded = true;
            Ok(result)
        }
    }
    struct RowsCall<'a, G: NativeLifecycleGate> {
        owner: RefMut<'a, NativeCarrierAuthority<G>>,
        succeeded: bool,
    }
    impl<G: NativeLifecycleGate> Drop for RowsCall<'_, G> {
        fn drop(&mut self) {
            if !self.succeeded {
                self.owner.failed = true;
            }
            self.owner.active_row_role = None;
            self.owner.release_call_resources();
        }
    }
    impl<G: NativeLifecycleGate> NativeRowsAuthority<G> {
        /// Create a storage-only issuer for THIS actual known-Create RowOwner.
        /// Call before entering RowOwner's lock. The caller must retain the
        /// returned Rc in that same journal before reconciliation/any raw CAS.
        pub(crate) fn created_cleanup_write_for_original<J: rows::Journal>(
            &self,
            row_owner: &rows::NativeRowOwner<Self, J>,
            row_original: &Rc<rows::RowRecordReadPin>,
            files: &crate::windows::member_session::NativeSessionFiles,
            pair: &Rc<
                crate::windows::member_carrier_pair_store::native_store::NativePairIntentRead,
            >,
            expected: &crate::member_carrier_pair::Record,
        ) -> Result<Rc<dyn crate::windows::member_session::OriginalCreatedAddressCleanupWrite>>
        where
            G: 'static,
        {
            let mut attempt = ClosedHistoryCall {
                revoked: &self.shared.original.revoked,
                succeeded: false,
            };
            row_owner
                .inspect_original_authority(|actual, pin| {
                    if self.role != rows::Role::Carrier
                        || actual.role != self.role
                        || !Rc::ptr_eq(&actual.shared.original.owner, &self.shared.original.owner)
                        || !Rc::ptr_eq(
                            &actual.shared.original.revoked,
                            &self.shared.original.revoked,
                        )
                        || !pin.same_original(row_original)
                    {
                        return Err(rows::Error::Conflict);
                    }
                    Ok(())
                })
                .map_err(denied)?;
            let mut owner = self.shared.borrow()?;
            owner.verify_supervised()?;
            let native_before = owner.current(Use::Cleanup)?;
            let context = owner.scope.context.clone();
            if expected.phase != crate::member_carrier_pair::Phase::Closing
                || expected.pending.is_none()
                || expected.stop_stage > 6
                || expected.scope != context.intent.scope
                || expected.provenance != context.provenance
            {
                return Err(Error::Conflict);
            }
            pair.verify_cleanup_entry_for(&owner.runtime, &context, expected)
                .map_err(denied)?;
            let canonical = owner
                .runtime
                .native_files_for_original(&context, files)
                .map_err(denied)?;
            let pair_payload = owner
                .runtime
                .record(&context, RecordKind::Pair)
                .map_err(denied)?;
            if crate::windows::member_carrier_pair_store::carrier_payload(
                &context.intent.scope,
                &pair_payload,
            )
            .map_err(denied)?
            .as_ref()
                != Some(expected)
            {
                return Err(Error::Conflict);
            }
            // Pin is an origin fact; it does NOT adopt a lost initial capture ACK.
            row_original
                .with_cleanup_record(
                    &context.intent.scope,
                    context.provenance.network_epoch,
                    |facts| {
                        if facts.binding.role != rows::Role::Carrier
                            || facts.binding.guid != context.bindings[0].guid
                            || facts.binding.name != context.bindings[0].name
                            || facts.binding.boot_id != context.provenance.boot_id
                            || facts.binding.runtime != context.provenance.runtime
                        {
                            return Err(rows::Error::Conflict);
                        }
                        Ok(())
                    },
                )
                .map_err(denied)?;
            let supervisor = owner.gate.supervisor().clone();
            let calling = owner
                .supervisor
                .transaction_pin(&supervisor, &context)
                .map_err(denied)?;
            owner
                .created_cleanup_writes
                .try_reserve(1)
                .map_err(|_| Error::Pending)?;
            let issuer = Rc::new(NativeCreatedAddressCleanupWrite {
                root: CleanupWriteRoot::new(&self.shared.original),
                original: row_original.clone(),
                backend: canonical.read_identity(),
                context: context.clone(),
                pair_record: expected.clone(),
                pair_payload: pair_payload.clone(),
                _pair: pair.clone(),
                supervisor,
                calling,
            });
            owner.created_cleanup_writes.push(issuer.clone()); // BEFORE every fallible postflight
            let postflight = (|| {
                pair.verify_cleanup_entry_for(&owner.runtime, &context, expected)
                    .map_err(denied)?;
                if owner
                    .runtime
                    .record(&context, RecordKind::Pair)
                    .map_err(denied)?
                    != pair_payload
                    || !owner
                        .runtime
                        .native_files_for_original(&context, files)
                        .map_err(denied)?
                        .read_identity()
                        .same_original(&issuer.backend)
                    || owner.current(Use::Cleanup)? != native_before
                {
                    return Err(Error::Conflict);
                }
                owner.verify_supervised()?;
                issuer
                    .calling
                    .verify(&issuer.supervisor, &context)
                    .map_err(denied)?;
                issuer.root.admit().map_err(denied)
            })();
            if postflight.is_err() {
                issuer.root.fail();
            }
            postflight?;
            attempt.succeeded = true;
            Ok(issuer)
        }
        /// Separate no-row-effects initial-invocation issuer. The same original
        /// RowOwner must retain this in its journal BEFORE sealed reconciliation.
        pub(crate) fn initial_capture_cleanup_write_for_original<J: rows::Journal>(
            &self,
            row_owner: &rows::NativeRowOwner<Self, J>,
            row_original: &Rc<rows::RowRecordReadPin>,
            files: &crate::windows::member_session::NativeSessionFiles,
            pair: &Rc<
                crate::windows::member_carrier_pair_store::native_store::NativePairIntentRead,
            >,
            expected: &crate::member_carrier_pair::Record,
        ) -> Result<Rc<dyn crate::windows::member_session::OriginalInitialRowCaptureCleanupWrite>>
        where
            G: 'static,
        {
            let mut attempt = ClosedHistoryCall {
                revoked: &self.shared.original.revoked,
                succeeded: false,
            };
            let initial = row_owner
                .inspect_original_initial_capture(|actual, pin, facts| {
                    if self.role != rows::Role::Carrier
                        || actual.role != self.role
                        || !Rc::ptr_eq(&actual.shared.original.owner, &self.shared.original.owner)
                        || !Rc::ptr_eq(
                            &actual.shared.original.revoked,
                            &self.shared.original.revoked,
                        )
                        || !pin.same_original(row_original)
                        || !facts.matches_record_original(row_original)
                    {
                        return Err(rows::Error::Conflict);
                    }
                    Ok(facts.initial_record().clone())
                })
                .map_err(denied)?;
            let mut owner = self.shared.borrow()?;
            owner.verify_supervised()?;
            let native_before = owner.current(Use::Cleanup)?;
            let context = owner.scope.context.clone();
            super::compare_early_cleanup_storage_context(&context, expected, &initial.binding)
                .map_err(denied)?;
            pair.verify_cleanup_entry_for(&owner.runtime, &context, expected)
                .map_err(denied)?;
            let canonical = owner
                .runtime
                .native_files_for_original(&context, files)
                .map_err(denied)?;
            let pair_payload = owner
                .runtime
                .record(&context, RecordKind::Pair)
                .map_err(denied)?;
            if crate::windows::member_carrier_pair_store::carrier_payload(
                &context.intent.scope,
                &pair_payload,
            )
            .map_err(denied)?
            .as_ref()
                != Some(expected)
            {
                return Err(Error::Conflict);
            }
            let supervisor = owner.gate.supervisor().clone();
            let calling = owner
                .supervisor
                .transaction_pin(&supervisor, &context)
                .map_err(denied)?;
            owner
                .initial_cleanup_writes
                .try_reserve(1)
                .map_err(|_| Error::Pending)?;
            let issuer = Rc::new(NativeInitialRowCaptureCleanupWrite {
                origin: NativeCreatedAddressCleanupWrite {
                    root: CleanupWriteRoot::new(&self.shared.original),
                    original: row_original.clone(),
                    backend: canonical.read_identity(),
                    context: context.clone(),
                    pair_record: expected.clone(),
                    pair_payload: pair_payload.clone(),
                    _pair: pair.clone(),
                    supervisor,
                    calling,
                },
                initial,
            });
            owner.initial_cleanup_writes.push(issuer.clone()); // BEFORE postflight
            let postflight = (|| {
                row_owner
                    .inspect_original_initial_capture(|actual, pin, facts| {
                        if actual.role != rows::Role::Carrier
                            || !Rc::ptr_eq(
                                &actual.shared.original.owner,
                                &self.shared.original.owner,
                            )
                            || !Rc::ptr_eq(
                                &actual.shared.original.revoked,
                                &self.shared.original.revoked,
                            )
                            || !pin.same_original(&issuer.origin.original)
                            || facts.initial_record() != &issuer.initial
                        {
                            return Err(rows::Error::Conflict);
                        }
                        Ok(())
                    })
                    .map_err(denied)?;
                pair.verify_cleanup_entry_for(&owner.runtime, &context, expected)
                    .map_err(denied)?;
                if owner
                    .runtime
                    .record(&context, RecordKind::Pair)
                    .map_err(denied)?
                    != pair_payload
                    || !owner
                        .runtime
                        .native_files_for_original(&context, files)
                        .map_err(denied)?
                        .read_identity()
                        .same_original(&issuer.origin.backend)
                    || owner.current(Use::Cleanup)? != native_before
                {
                    return Err(Error::Conflict);
                }
                owner.verify_supervised()?;
                issuer
                    .origin
                    .calling
                    .verify(&issuer.origin.supervisor, &context)
                    .map_err(denied)?;
                issuer.origin.root.admit().map_err(denied)
            })();
            if postflight.is_err() {
                issuer.origin.root.fail();
            }
            postflight?;
            attempt.succeeded = true;
            Ok(issuer)
        }
        /// Alias retains THIS actual C owner before RowOwner takes its authority.
        /// It mints no native/resource/row ACK and cannot change selected roles.
        pub(crate) fn read_pin(&self) -> Self {
            Self {
                shared: self.shared.other_pin(),
                role: self.role,
            }
        }
        pub(crate) fn source_read(
            &self,
            address: rows::CreatedAddressReadPin,
        ) -> Result<NativeSourceRead> {
            if self.role != rows::Role::Carrier {
                return Err(Error::Conflict);
            }
            self.shared.source_read(address)
        }
        pub(crate) fn closing_read_with_pin(
            &self,
            retain: impl FnOnce(Rc<NativeClosingRead>) -> Result<()>,
        ) -> Result<Rc<NativeClosingRead>> {
            if self.role != rows::Role::Carrier {
                return Err(Error::Conflict);
            }
            self.shared.closing_read_with_pin(retain)
        }
        /// Role selection on the SAME original owner, not a new authority or
        /// runtime/creator constructor. locked() freshly verifies ALL facts.
        pub(crate) fn for_member(&self, role: rows::Role) -> rows::Result<Self> {
            if !matches!(role, rows::Role::MemberA | rows::Role::MemberB) {
                return Err(rows::Error::Conflict);
            }
            Ok(Self {
                shared: self.shared.other_pin(),
                role,
            })
        }
        pub(crate) fn binding(&mut self) -> rows::Result<rows::Binding> {
            rows::Authority::locked(self, |original| original.row_binding())
        }
        /// Actual coordinator operation window through the SAME C authority.
        /// This read selection does not perform a row or native effect.
        pub(crate) fn select_pair_intent(
            &mut self,
            original: Rc<
                crate::windows::member_carrier_pair_store::native_store::NativePairIntentRead,
            >,
            expected: &crate::member_carrier_pair::Record,
        ) -> Result<()> {
            let mut owner = self.shared.borrow()?;
            owner.verify_supervised()?;
            owner.gate.select_pair_intent(original, expected)
        }
        /// SAME original owner only; no independent lookup/adoption constructor.
        /// Useful after C's native close, when live row_binding must deny.
        pub(crate) fn retired_carrier_read_with_pin(
            &self,
            retain: impl FnOnce(Rc<RetiredCarrierRead>) -> Result<()>,
        ) -> Result<Rc<RetiredCarrierRead>> {
            if self.role != rows::Role::Carrier {
                return Err(Error::Conflict);
            }
            self.shared.retired_read_for_cleanup_with_pin(retain)
        }
        pub(crate) fn unpublished_closed_carrier_read_with_pin(
            &self,
            retain: impl FnOnce(Rc<UnpublishedClosedCarrierRead>) -> Result<()>,
        ) -> Result<Rc<UnpublishedClosedCarrierRead>> {
            if self.role != rows::Role::Carrier {
                return Err(Error::Conflict);
            }
            self.shared.unpublished_closed_read_with_pin(retain)
        }
        pub(crate) fn verify_unpublished_closed_original_in_call(
            &self,
            original: &Rc<UnpublishedClosedCarrierRead>,
        ) -> Result<()> {
            let mut call = ClosedHistoryCall {
                revoked: &self.shared.original.revoked,
                succeeded: false,
            };
            let mut owner = self.shared.borrow()?;
            owner.verify_supervised()?;
            if self.role != rows::Role::Carrier
                || original.scope != owner.scope
                || !original.runtime.same_original_runtime(&owner.runtime)
                || !Rc::ptr_eq(&original.revoked, &owner.shared_revocation)
            {
                return Err(Error::Conflict);
            }
            crate::windows::member_carrier_original_read::require_retained_original(
                &owner.unpublished_closed_reader,
                original,
                Error::Conflict,
            )?;
            let before = original.revision(true)?;
            owner.verify_supervised()?;
            if original.revision(true)? != before {
                return Err(Error::Conflict);
            }
            call.succeeded = true;
            Ok(())
        }
        /// SAME actual original registered while C closed, even when no ready
        /// Source was ever published. This proves only root/runtime/Calling
        /// identity in the acknowledged terminal-key channel. Caller MUST
        /// independently enter this reader's terminal full-SDK/CloseACK bracket
        /// and authenticate every row/probe/network/Guard obligation.
        pub(crate) fn verify_retired_original_in_call(
            &self,
            original: &Rc<RetiredCarrierRead>,
        ) -> Result<()> {
            self.verify_retired_read_original_in_call(original, RetiredReadStage::Terminal)
        }
        /// READONLY actual original identity for Closing before key restoration.
        /// Caller still supplies exact Pair/Calling and full CloseACK/SDK bracket.
        pub(crate) fn verify_retired_cleanup_original_in_call(
            &self,
            original: &Rc<RetiredCarrierRead>,
        ) -> Result<()> {
            self.verify_retired_read_original_in_call(original, RetiredReadStage::Cleanup)
        }
        fn verify_retired_read_original_in_call(
            &self,
            original: &Rc<RetiredCarrierRead>,
            stage: RetiredReadStage,
        ) -> Result<()> {
            let mut call = ClosedHistoryCall {
                revoked: &self.shared.original.revoked,
                succeeded: false,
            };
            let mut owner = self.shared.borrow()?;
            owner.verify_supervised()?;
            if self.role != rows::Role::Carrier
                || original.scope != owner.scope
                || !original.runtime.same_original_runtime(&owner.runtime)
                || !Rc::ptr_eq(&original.revoked, &owner.shared_revocation)
            {
                return Err(Error::Conflict);
            }
            crate::windows::member_carrier_original_read::require_retained_original(
                &owner.retired_reader,
                original,
                Error::Conflict,
            )?;
            owner.runtime.verify(&owner.scope.context).map_err(denied)?;
            owner.image.verify_runtime(&owner.runtime).map_err(denied)?;
            let revision = || match stage {
                RetiredReadStage::Cleanup => original.revision(),
                RetiredReadStage::Terminal => original.terminal_revision(),
            };
            let before = revision()?;
            // No callback or SDK lookup is hidden in this identity check. An
            // error cannot replace the retained first reader or rearm forward.
            owner.verify_supervised()?;
            if revision()? != before {
                return Err(Error::Conflict);
            }
            call.succeeded = true;
            Ok(())
        }
    }
    impl<G: NativeLifecycleGate> rows::Authority for NativeRowsAuthority<G> {
        type Creator = NativeCarrierAuthority<G>;
        fn locked<T>(
            &mut self,
            action: impl FnOnce(&mut Self::Creator) -> rows::Result<T>,
        ) -> rows::Result<T> {
            let original = self.shared.borrow().map_err(|_| rows::Error::Conflict)?;
            let mut call = RowsCall {
                owner: original,
                succeeded: false,
            };
            if call.owner.active_row_role.is_some() {
                return Err(rows::Error::Conflict);
            }
            call.owner.active_row_role = Some(self.role);
            call.owner
                .verify_supervised()
                .map_err(|_| rows::Error::Conflict)?;
            let use_ = call.owner.row_use().map_err(|_| rows::Error::Conflict)?;
            if call.owner.failed && use_ != Use::Cleanup {
                return Err(rows::Error::Retired);
            }
            let held = call
                .owner
                .refresh(use_)
                .map_err(|_| rows::Error::Conflict)?;
            call.owner.effect = Some(held);
            let result = action(&mut call.owner);
            call.succeeded = result.is_ok();
            result
        }
    }

    // SAFETY: delegates exclusively to the SAME retained original source,
    // module, creator, actor and independent G. RefCell enforces nonreentrancy;
    // failed borrowing irreversibly revokes forward, never substitutes success.
    unsafe impl<G: NativeLifecycleGate> ModuleRuntimeAuthority for SharedCarrierAuthority<G> {
        type Key = keys::Held<win32::Handle>;
        type MutationLock = KeyLock;
        fn verify(&mut self, binding: &Binding, stage: Stage) -> Result<()> {
            self.borrow()?.verify(binding, stage)
        }
        fn authorize_create(
            &mut self,
            binding: &Binding,
            record: &receipts::Record,
            ack: &receipts::NewKeyAck<Self::Key>,
            lock: &mut KeyLock,
        ) -> Result<()> {
            self.borrow()?.authorize_create(binding, record, ack, lock)
        }
        fn provider(&mut self, binding: &Binding, identity: &Identity, stage: Stage) -> Result<()> {
            self.borrow()?.provider(binding, identity, stage)
        }
        fn acknowledged_original(&mut self, original: OriginalAdapterRead) {
            match self.borrow() {
                Ok(mut owner) => owner.acknowledged_original(original),
                Err(_) => {
                    // Unknown ACK may not destroy/unload native originals. The
                    // failed pending token stays retained, never treated empty.
                    std::mem::forget(original);
                }
            }
        }
        fn retain_original_session(&mut self, original: wintun::SessionEndRead) {
            match self.borrow() {
                Ok(mut owner) => owner.retain_original_session(original),
                Err(_) => std::mem::forget(original),
            }
        }
        fn release_call_resources(&mut self) {
            if let Ok(mut owner) = self.borrow() {
                owner.release_call_resources();
            }
        }
    }

    struct PendingCreate {
        begin: creators::Begin<OriginalWintun>,
        prepared: PreparedOriginal,
        // SAME module/source/runtime pins and real Device+Driver mutexes stay
        // held across CreateAdapter AND immediate raw-ACK publication.
        lease: Option<OriginalModuleLease>,
    }

    /// Concrete source/runtime/package/key/original composition. A real
    /// NativeLifecycleGate and coordinator integration are still required;
    /// this does NOT select a product factory or supply successful defaults.
    pub(crate) struct NativeCarrierAuthority<G: NativeLifecycleGate> {
        module: LoadedWintun,
        runtime: RuntimeRead,
        image: OriginalImage,
        producer: creators::Producer<OriginalWintun>,
        observer: creators::Observer<OriginalWintun>,
        package: OriginalPackageInventory,
        scope: creators::Scope,
        binding: Binding,
        gate: G,
        supervisor: NativeDeadlineReadPin,
        cancelled: Arc<AtomicBool>,
        pending: Option<PendingCreate>,
        effect: Option<OriginalModuleLease>,
        retirement: Option<creators::Retirement<OriginalWintun>>,
        released: Option<creators::Released<OriginalWintun>>,
        closing_reader: Option<Rc<NativeClosingRead>>,
        retired_reader: Option<Rc<RetiredCarrierRead>>,
        unpublished_closed_reader: Option<Rc<UnpublishedClosedCarrierRead>>,
        created_cleanup_writes: Vec<Rc<NativeCreatedAddressCleanupWrite<G>>>,
        initial_cleanup_writes: Vec<Rc<NativeInitialRowCaptureCleanupWrite<G>>>,
        failed: bool,
        shared_revocation: Rc<Cell<bool>>,
        // Whole factual callbacks share serialization/taint across ALL reader
        // aliases derived from this SAME actual owner, including Closing.
        source_fence: Rc<super::SourceFence>,
        // Present ONLY while the SAME original borrow covers the full row call.
        active_row_role: Option<rows::Role>,
    }
    fn denied<E>(_: E) -> Error {
        Error::Conflict
    }

    /// Actual original inputs, retained before the first fallible boundary.
    /// Cleanup access is not runtime, ownership, or native effect permission.
    pub(crate) struct NativeConstructionInputs<G: NativeLifecycleGate> {
        pub(crate) module: LoadedWintun,
        pub(crate) runtime: RuntimeRead,
        pub(crate) image: OriginalImage,
        pub(crate) producer: creators::Producer<OriginalWintun>,
        pub(crate) scope: creators::Scope,
        pub(crate) gate: G,
        pub(crate) cancelled: Arc<AtomicBool>,
    }
    struct NativeAuthorityPreparation {
        observer: creators::Observer<OriginalWintun>,
        package: OriginalPackageInventory,
        binding: Binding,
        supervisor: NativeDeadlineReadPin,
    }
    pub(crate) type RootedCarrierComponents<'a, G> = CarrierComponents<'a, G>;
    impl From<super::ConstructionFailure> for Error {
        fn from(failure: super::ConstructionFailure) -> Self {
            match failure {
                super::ConstructionFailure::Conflict => Self::Conflict,
                super::ConstructionFailure::Pending => Self::Pending,
                super::ConstructionFailure::Retired => Self::Retired,
            }
        }
    }
    /// Keep this slot OUTSIDE the supervisor/catch_unwind callback. Neither
    /// construction method returns owning originals through its Result.
    /// Failed attempts remain here for independently authorized explicit cleanup.
    /// Real references inside G retain their lifetimes; no static/Send conversion.
    pub(crate) struct NativeConstructionSlot<'a, G: NativeLifecycleGate + 'a> {
        root: super::ConstructionRoot<
            NativeConstructionInputs<G>,
            NativeCarrierAuthority<G>,
            SharedCarrierAuthority<G>,
            CarrierComponents<'a, G>,
            Error,
        >,
    }
    pub(crate) struct NativeConstructionParts<'r, 'a, G: NativeLifecycleGate + 'a> {
        pub(crate) inputs: &'r mut Option<NativeConstructionInputs<G>>,
        pub(crate) authority: &'r mut Option<NativeCarrierAuthority<G>>,
        pub(crate) shared: &'r mut Option<SharedCarrierAuthority<G>>,
        pub(crate) components: &'r mut Option<CarrierComponents<'a, G>>,
    }
    impl<'a, G: NativeLifecycleGate + 'a> NativeConstructionSlot<'a, G> {
        /// Infallible retention of ALL original owning inputs. Invoke this
        /// before entering any fallible supervisory/native construction call.
        pub(crate) fn new(
            module: LoadedWintun,
            runtime: RuntimeRead,
            image: OriginalImage,
            producer: creators::Producer<OriginalWintun>,
            scope: creators::Scope,
            gate: G,
            cancelled: Arc<AtomicBool>,
        ) -> Self {
            Self {
                root: super::ConstructionRoot::new(NativeConstructionInputs {
                    module,
                    runtime,
                    image,
                    producer,
                    scope,
                    gate,
                    cancelled,
                }),
            }
        }
        pub(crate) fn construct(&self) -> Result<()> {
            self.root
                .attempt(super::ConstructionStep::Authority, |parts| {
                    let inputs = parts.inputs.as_ref().ok_or(Error::Pending)?;
                    let prepared = NativeCarrierAuthority::prepare_construction(inputs)?;
                    // Allocate/clone while inputs still own everything. After take,
                    // only infallible field moves precede publishing the authority.
                    let signal = self.root.revoked.clone();
                    let fence = Rc::new(super::SourceFence::new(signal.clone()));
                    parts.authority = Some(NativeCarrierAuthority::from_prepared(
                        parts.inputs.take().expect("retained construction inputs"),
                        prepared,
                        signal,
                        fence,
                    ));
                    // FIRST postflight on the assembled owner is after publication.
                    parts
                        .authority
                        .as_ref()
                        .expect("retained authority")
                        .current(Use::Create)?;
                    Ok(())
                })
        }
        pub(crate) fn resolve_components(&self) -> Result<()> {
            self.root
                .attempt(super::ConstructionStep::Components, |parts| {
                    let authority = parts.authority.as_mut().ok_or(Error::Pending)?;
                    let before = authority.current(Use::Create)?;
                    let held = authority.refresh(Use::Create)?;
                    let raw = held.module();
                    authority.effect = Some(held);
                    if authority.image.module().map_err(denied)? != raw {
                        return Err(Error::Conflict);
                    }
                    // The native resolver independently refreshes this SAME
                    // retained authority and runs the complete Resolve gate
                    // LAST before GetModuleHandleExW. Alias construction below
                    // performs no SDK effect and cannot grant native permission.
                    same_record(&before, authority.current(Use::Create)?).map_err(denied)?;
                    let binding = authority.binding.clone();
                    let signal = authority.shared_revocation.clone();
                    // Rc storage construction/field moves are infallible. Publish
                    // the SAME alias before AuthenticatedModule/native resolution.
                    parts.shared = Some(SharedCarrierAuthority {
                        original: super::SharedOriginal::with_signal(
                            parts.authority.take().expect("retained authority"),
                            signal,
                        ),
                    });
                    let shared = parts.shared.as_ref().expect("retained shared authority");
                    let rows = NativeRowsAuthority {
                        shared: shared.other_pin(),
                        role: rows::Role::Carrier,
                    };
                    // SAFETY: retained original module/source/runtime/creator/G
                    // authenticate raw exactly as the legacy owning seam. The root
                    // keeps the SAME authority even if resolution consumes its alias.
                    let module = unsafe { AuthenticatedModule::own(raw, shared.other_pin()) };
                    parts.components =
                        Some((wintun::native::retained_carrier(module, binding)?, rows));
                    // Carrier AND rows now occupy the caller slot BEFORE postflight.
                    let mut owner = parts
                        .shared
                        .as_ref()
                        .expect("retained shared authority")
                        .borrow()?;
                    owner.verify_supervised()?;
                    same_record(&before, owner.current(Use::Create)?).map_err(denied)?;
                    Ok(())
                })
        }
        /// Wrap the caller's actual supervisor.run/run_intent around BOTH
        /// construction stages. The root exists before this call and survives
        /// its Err/unwind; the wrapper supplies retention/revocation ONLY.
        /// Actual G and Calling checks still gate every native stage inside it.
        pub(crate) fn in_supervised_call(
            &self,
            call: impl FnOnce(&Self) -> Result<()>,
        ) -> Result<()> {
            self.root.supervised(|| call(self))
        }
        /// SAME guard/signal as the read wrapper, held outside all mutable
        /// borrows. Main's actual supervisor covers construct, resolve and
        /// mutable Carrier/RowOwner work through its whole Calling window.
        pub(crate) fn in_supervised_call_mut(
            &mut self,
            call: impl FnOnce(&mut Self) -> Result<()>,
        ) -> Result<()> {
            let attempt = self.root.begin_supervised()?;
            call(self)?;
            self.root.finish_supervised(attempt)
        }
        /// Use after an external supervisor postflight failure (or in its unwind
        /// guard). Irreversible, shared by every actual native authority alias.
        /// This does not run cleanup, call G, or release any original.
        pub(crate) fn revoke_forward(&self) {
            self.root.revoked.set(true);
        }
        /// Mutable borrowed originals for the caller's real cleanup composition.
        /// Keep the slot alive on errors; removal/release needs independent ACKs.
        pub(crate) fn retained_parts(&mut self) -> NativeConstructionParts<'_, 'a, G> {
            let parts = self.root.retained_parts();
            NativeConstructionParts {
                inputs: &mut parts.inputs,
                authority: &mut parts.authority,
                shared: &mut parts.shared,
                components: &mut parts.components,
            }
        }
        /// Borrow ONLY the actual original LoadedWintun retained by this slot.
        /// No new HMODULE, close/disarm receipt, Calling or unload grant. The
        /// caller's terminal root independently joins SAME opaque originals/G.
        /// Borrow stays rooted across Err/unwind; G must not reborrow this same
        /// authority while the closure runs. Forward selection remains revoked.
        pub(crate) fn with_original_loaded_module_for_terminal(
            &self,
            call: impl FnOnce(&mut LoadedWintun) -> std::io::Result<()>,
        ) -> std::io::Result<()> {
            self.root.revoked.set(true);
            let conflict = || std::io::Error::other("carrier_original_terminal_module_conflict");
            let mut parts = self.root.parts.try_borrow_mut().map_err(|_| conflict())?;
            let owners = usize::from(parts.inputs.is_some())
                + usize::from(parts.authority.is_some())
                + usize::from(parts.shared.is_some());
            if owners != 1 {
                return Err(conflict());
            }
            if let Some(inputs) = parts.inputs.as_mut() {
                return call(&mut inputs.module);
            }
            if let Some(authority) = parts.authority.as_mut() {
                if authority.pending.is_some() || authority.effect.is_some() {
                    return Err(conflict());
                }
                return call(&mut authority.module);
            }
            let shared = parts.shared.as_ref().ok_or_else(conflict)?;
            let mut original = shared.original.borrow().map_err(|_| conflict())?;
            if original.pending.is_some() || original.effect.is_some() {
                return Err(conflict());
            }
            call(&mut original.module)
        }
    }

    impl<G: NativeLifecycleGate> NativeCarrierAuthority<G> {
        fn prepare_construction(
            inputs: &NativeConstructionInputs<G>,
        ) -> Result<NativeAuthorityPreparation> {
            let observer = inputs.producer.observer();
            if observer.context() != &inputs.scope.context
                || inputs.scope.binding != inputs.scope.context.bindings[0]
            {
                return Err(Error::Conflict);
            }
            inputs
                .producer
                .original_universe()
                .matches_original_runtime_image(&inputs.runtime, &inputs.image)
                .map_err(denied)?;
            let package = OriginalPackageInventory::from_producer(
                &inputs.producer,
                &inputs.runtime,
                &inputs.image,
            )
            .map_err(denied)?;
            let binding = Binding {
                guid: inputs.scope.binding.guid,
                name: inputs.scope.binding.name.clone(),
                tunnel_type: "Nelomai carrier".into(),
            };
            let supervisor = inputs.gate.supervisor().read_pin().map_err(denied)?;
            supervisor
                .verify_runtime(
                    inputs.gate.supervisor(),
                    &inputs.runtime,
                    &inputs.scope.context,
                )
                .map_err(denied)?;
            Ok(NativeAuthorityPreparation {
                observer,
                package,
                binding,
                supervisor,
            })
        }
        fn from_prepared(
            inputs: NativeConstructionInputs<G>,
            prepared: NativeAuthorityPreparation,
            shared_revocation: Rc<Cell<bool>>,
            source_fence: Rc<super::SourceFence>,
        ) -> Self {
            let NativeConstructionInputs {
                module,
                runtime,
                image,
                producer,
                scope,
                gate,
                cancelled,
            } = inputs;
            let NativeAuthorityPreparation {
                observer,
                package,
                binding,
                supervisor,
            } = prepared;
            Self {
                module,
                runtime,
                image,
                producer,
                observer,
                package,
                scope,
                binding,
                gate,
                supervisor,
                cancelled,
                pending: None,
                effect: None,
                retirement: None,
                released: None,
                closing_reader: None,
                retired_reader: None,
                unpublished_closed_reader: None,
                created_cleanup_writes: Vec::new(),
                initial_cleanup_writes: Vec::new(),
                failed: false,
                shared_revocation,
                source_fence,
                active_row_role: None,
            }
        }
        pub(crate) fn new(
            module: LoadedWintun,
            runtime: RuntimeRead,
            image: OriginalImage,
            producer: creators::Producer<OriginalWintun>,
            scope: creators::Scope,
            gate: G,
            cancelled: Arc<AtomicBool>,
        ) -> Result<Self> {
            // Legacy Result<Self> behavior/signature is preserved. New callers
            // must retain NativeConstructionSlot before supervisory work.
            let inputs = NativeConstructionInputs {
                module,
                runtime,
                image,
                producer,
                scope,
                gate,
                cancelled,
            };
            let prepared = Self::prepare_construction(&inputs)?;
            let shared_revocation = Rc::new(Cell::new(false));
            let source_fence = Rc::new(super::SourceFence::new(shared_revocation.clone()));
            let authority = Self::from_prepared(inputs, prepared, shared_revocation, source_fence);
            authority.current(Use::Create)?;
            Ok(authority)
        }
        /// Owns A with its REAL lifetimes. No leaked Box, fabricated static
        /// borrow, Send conversion, reopened module or path authentication.
        pub(crate) fn into_carrier<'a>(mut self) -> Result<Carrier<NativeKernel<'a, Self>>>
        where
            G: 'a,
        {
            let before = self.current(Use::Create)?;
            let held = self.refresh(Use::Create)?;
            let raw = held.module();
            if self.image.module().map_err(denied)? != raw {
                return Err(Error::Conflict);
            }
            self.gate
                .authorize(&self.scope, Stage::Resolve, &self.observer)?;
            same_record(&before, self.current(Use::Create)?).map_err(denied)?;
            self.effect = Some(held);
            let binding = self.binding.clone();
            // SAFETY: real cold loader/package, SAME authenticated runtime,
            // signed source, original image, serialized and cooperative leases
            // are retained in Self; the mandatory unsafe lifecycle gate grants
            // the independent actual effects, never this HMODULE number.
            let module = unsafe { AuthenticatedModule::own(raw, self) };
            wintun::native::retained_carrier(module, binding)
        }
        pub(crate) fn into_components<'a>(mut self) -> Result<CarrierComponents<'a, G>>
        where
            G: 'a,
        {
            let before = self.current(Use::Create)?;
            let held = self.refresh(Use::Create)?;
            let raw = held.module();
            if self.image.module().map_err(denied)? != raw {
                return Err(Error::Conflict);
            }
            self.gate
                .authorize(&self.scope, Stage::Resolve, &self.observer)?;
            same_record(&before, self.current(Use::Create)?).map_err(denied)?;
            self.effect = Some(held);
            let binding = self.binding.clone();
            let signal = self.shared_revocation.clone();
            let shared = SharedCarrierAuthority {
                original: super::SharedOriginal::with_signal(self, signal),
            };
            let rows = NativeRowsAuthority {
                shared: shared.other_pin(),
                role: rows::Role::Carrier,
            };
            // SAFETY: both components retain ONE actual authority, not equal
            // source/creator/lock metadata. G's required unsafe contract remains
            // unchanged and has no permissive factory implementation.
            let module = unsafe { AuthenticatedModule::own(raw, shared) };
            let carrier = wintun::native::retained_carrier(module, binding)?;
            Ok((carrier, rows))
        }
        fn row_use(&self) -> Result<Use> {
            let bytes = self
                .runtime
                .record(&self.scope.context, RecordKind::NativeCarrierReceipts)
                .map_err(denied)?;
            let record = receipts::Record::decode(&bytes).map_err(denied)?;
            let use_ = match record.phase {
                receipts::Phase::Preparing => Use::Live,
                receipts::Phase::Closing => Use::Cleanup,
                _ => return Err(Error::Retired),
            };
            same_record(&record, self.current(use_)?).map_err(denied)?;
            Ok(use_)
        }
        fn row_binding(&mut self) -> rows::Result<rows::Binding> {
            let role = self.active_row_role.ok_or(rows::Error::Retired)?;
            if role != rows::Role::Carrier {
                return self.member_row_binding(role);
            }
            let use_ = self.row_use().map_err(|_| rows::Error::Conflict)?;
            let before = self.current(use_).map_err(|_| rows::Error::Conflict)?;
            let held = self.effect.as_mut().ok_or(rows::Error::Retired)?;
            if use_ == Use::Cleanup {
                held.verify_for_cleanup(&self.cancelled)
            } else {
                held.verify(&self.cancelled)
            }
            .map_err(|_| rows::Error::Conflict)?;
            let stage = if use_ == Use::Cleanup {
                Stage::CleanupObserve
            } else {
                Stage::Observe
            };
            self.gate
                .authorize(&self.scope, stage, &self.observer)
                .map_err(|_| rows::Error::Conflict)?;
            let facts = if use_ == Use::Cleanup {
                self.observer.observe_all_for_cleanup(&self.scope.context)
            } else {
                self.observer.observe_all(&self.scope.context)
            }
            .map_err(|_| rows::Error::Conflict)?;
            let original = facts
                .originals
                .iter()
                .find(|o| o.scope == self.scope)
                .ok_or(rows::Error::Conflict)?;
            let binding = rows_binding(&self.scope.context, &original.identity)?;
            same_record(
                &before,
                self.current(use_).map_err(|_| rows::Error::Conflict)?,
            )
            .map_err(|_| rows::Error::Conflict)?;
            Ok(binding)
        }
        fn member_row_binding(&mut self, role: rows::Role) -> rows::Result<rows::Binding> {
            self.verify_supervised()
                .map_err(|_| rows::Error::Conflict)?;
            let use_ = self.row_use().map_err(|_| rows::Error::Conflict)?;
            let before = self.current(use_).map_err(|_| rows::Error::Conflict)?;
            if self.active_row_role != Some(role) || (self.failed && use_ != Use::Cleanup) {
                return Err(rows::Error::Retired);
            }
            let held = self.effect.as_mut().ok_or(rows::Error::Retired)?;
            if use_ == Use::Cleanup {
                held.verify_for_cleanup(&self.cancelled)
            } else {
                held.verify(&self.cancelled)
            }
            .map_err(|_| rows::Error::Conflict)?;
            let stage = if use_ == Use::Cleanup {
                Stage::CleanupObserve
            } else {
                Stage::Observe
            };
            self.gate
                .authorize(&self.scope, stage, &self.observer)
                .map_err(|_| rows::Error::Conflict)?;
            let all_before = if use_ == Use::Cleanup {
                self.observer.observe_all_for_cleanup(&self.scope.context)
            } else {
                self.observer.observe_all(&self.scope.context)
            }
            .map_err(|_| rows::Error::Conflict)?;
            if all_before.originals.len() != 1 || all_before.originals[0].scope != self.scope {
                return Err(rows::Error::Conflict);
            }
            let members = self
                .producer
                .original_universe()
                .member_read_pin()
                .map_err(|_| rows::Error::Conflict)?;
            members
                .matches_original_runtime_image(&self.runtime, &self.image)
                .map_err(|_| rows::Error::Conflict)?;
            let read_members = || {
                if use_ == Use::Cleanup {
                    members.inspect_closing_full(
                        &self.scope.context,
                        &self.runtime,
                        &self.image,
                        |facts| Ok(facts.to_vec()),
                    )
                } else {
                    members.read_all()
                }
            };
            let facts = read_members().map_err(|_| rows::Error::Conflict)?;
            let index = match role {
                rows::Role::MemberA => 1,
                rows::Role::MemberB => 2,
                rows::Role::Carrier => return Err(rows::Error::Conflict),
            };
            let context = &self.scope.context;
            let member = facts
                .iter()
                .find(|m| m.identity.guid == context.bindings[index].guid)
                .ok_or(rows::Error::Conflict)?;
            let identity = &member.identity;
            let binding = member_rows_binding(
                context,
                role,
                &creators::Identity {
                    guid: identity.guid,
                    luid: identity.luid,
                    index: identity.index,
                    name: identity.name.clone(),
                    description: identity.description.clone(),
                    if_type: identity.if_type,
                    tunnel_type: identity.tunnel_type,
                },
            )?;
            let all_after = if use_ == Use::Cleanup {
                self.observer.observe_all_for_cleanup(context)
            } else {
                self.observer.observe_all(context)
            }
            .map_err(|_| rows::Error::Conflict)?;
            if read_members().map_err(|_| rows::Error::Conflict)? != facts
                || all_after != all_before
                || self.current(use_).map_err(|_| rows::Error::Conflict)? != before
            {
                return Err(rows::Error::Conflict);
            }
            members
                .matches_original_runtime_image(&self.runtime, &self.image)
                .map_err(|_| rows::Error::Conflict)?;
            self.verify_supervised()
                .map_err(|_| rows::Error::Conflict)?;
            Ok(binding)
        }
        fn check_binding(&self, binding: &Binding) -> Result<()> {
            if *binding != self.binding {
                Err(Error::Conflict)
            } else {
                Ok(())
            }
        }
        fn checkpoint(&self) -> Result<()> {
            if self.cancelled.load(Ordering::Acquire) {
                Err(Error::Cancelled)
            } else {
                Ok(())
            }
        }
        fn verify_supervised(&mut self) -> Result<()> {
            if let Err(error) = self
                .supervisor
                .verify_call(self.gate.supervisor(), &self.scope.context)
            {
                self.failed = true;
                self.shared_revocation.set(true);
                return Err(denied(error));
            }
            Ok(())
        }
        fn current(&self, use_: Use) -> Result<receipts::Record> {
            if use_ != Use::Cleanup && self.shared_revocation.get() {
                return Err(Error::Pending);
            }
            self.checkpoint()?;
            self.runtime.verify(&self.scope.context).map_err(denied)?;
            let bytes = self
                .runtime
                .record(&self.scope.context, RecordKind::NativeCarrierReceipts)
                .map_err(denied)?;
            let record = receipts::Record::decode(&bytes).map_err(denied)?;
            let fresh = if use_ == Use::Cleanup {
                false
            } else {
                self.runtime.fresh(&self.scope.context).map_err(denied)?
            };
            validate_stage(
                &record,
                &self.scope.context,
                &self.scope.binding,
                self.scope.generation,
                fresh,
                use_,
            )
            .map_err(denied)?;
            // Freshness/runtime reads above can be expensive. Exact bytes must
            // still match AFTER them, under the original serialized owner.
            if bytes
                != self
                    .runtime
                    .record(&self.scope.context, RecordKind::NativeCarrierReceipts)
                    .map_err(denied)?
            {
                return Err(Error::Conflict);
            }
            self.checkpoint()?;
            if use_ != Use::Cleanup && self.shared_revocation.get() {
                return Err(Error::Pending);
            }
            Ok(record)
        }
        fn refresh(&mut self, use_: Use) -> Result<OriginalModuleLease> {
            self.verify_supervised()?;
            let before = self.current(use_)?;
            if let Some(held) = self.effect.as_mut() {
                if use_ == Use::Cleanup {
                    held.verify_for_cleanup(&self.cancelled)
                } else {
                    held.verify(&self.cancelled)
                }
                .map_err(denied)?;
            }
            let mut held = if use_ == Use::Cleanup {
                self.module.retain_owned_module_read_for_cleanup(
                    &self.runtime,
                    &self.cancelled,
                    &mut self.package,
                )
            } else {
                self.module.retain_owned_module_read(
                    &self.runtime,
                    &self.cancelled,
                    &mut self.package,
                )
            }
            .map_err(denied)?;
            if self.current(use_)? != before {
                return Err(Error::Conflict);
            }
            let original = if use_ == Use::Cleanup {
                self.image.cleanup_read_module()
            } else {
                self.image.module()
            }
            .map_err(denied)?;
            if held.module() != original {
                return Err(Error::Conflict);
            }
            held.verify(&self.cancelled).map_err(denied)?;
            same_record(&before, self.current(use_)?).map_err(denied)?;
            Ok(held)
        }
        fn retain_retired_reader(&mut self) -> Result<Rc<RetiredCarrierRead>> {
            if let Some(original) = &self.retired_reader {
                return Ok(original.clone());
            }
            let original = self
                .released
                .as_ref()
                .ok_or(Error::Pending)?
                .read_pin()
                .map_err(denied)?;
            let read = Rc::new(RetiredCarrierRead {
                original,
                history: BracketFacts::new(),
                adapter_reference: RefCell::new(None),
                runtime: self.runtime.read_pin().map_err(denied)?,
                image: self.image.read_pin().map_err(denied)?,
                members: self
                    .producer
                    .original_universe()
                    .member_read_pin()
                    .map_err(denied)?,
                scope: self.scope.clone(),
                supervisor: self.gate.supervisor().clone(),
                deadline: self.gate.supervisor().read_pin().map_err(denied)?,
                revoked: self.shared_revocation.clone(),
            });
            // No full SDK/reader inspection or G callback precedes rooting.
            let gate = &mut self.gate;
            crate::windows::member_carrier_original_read::retain_first_before(
                &mut self.retired_reader,
                read,
                Error::Conflict,
                |original| gate.retain_retired_carrier(original),
            )
        }
        fn retain_unpublished_closed_reader(&mut self) -> Result<Rc<UnpublishedClosedCarrierRead>> {
            if self.retired_reader.is_some() {
                return Err(Error::Conflict);
            }
            if let Some(original) = &self.unpublished_closed_reader {
                return Ok(original.clone());
            }
            let original = self
                .released
                .as_ref()
                .ok_or(Error::Pending)?
                .read_unpublished_closed_pin()
                .map_err(denied)?;
            let read = Rc::new(UnpublishedClosedCarrierRead {
                original,
                runtime: self.runtime.read_pin().map_err(denied)?,
                image: self.image.read_pin().map_err(denied)?,
                members: self
                    .producer
                    .original_universe()
                    .member_read_pin()
                    .map_err(denied)?,
                scope: self.scope.clone(),
                supervisor: self.gate.supervisor().clone(),
                deadline: self.gate.supervisor().read_pin().map_err(denied)?,
                revoked: self.shared_revocation.clone(),
            });
            let gate = &mut self.gate;
            crate::windows::member_carrier_original_read::retain_first_before(
                &mut self.unpublished_closed_reader,
                read,
                Error::Conflict,
                |original| gate.retain_unpublished_closed_carrier(original),
            )
        }
        fn complete_original_close(&mut self) -> Result<()> {
            if let Some(retirement) = self.retirement.as_ref() {
                // Obtain the actual once-close receipt BEFORE moving the token.
                // A transient factual error must retain retirement for retry.
                let closed = retirement.original().take_closed().map_err(denied)?;
                let retirement = self.retirement.take().ok_or(Error::Pending)?;
                let ack = retirement.acknowledge_closed(closed).map_err(denied)?;
                let mut universe =
                    OriginalUniverse::new(&self.runtime, &self.image).map_err(denied)?;
                self.released = Some(
                    self.producer
                        .complete_close(ack, &mut universe)
                        .map_err(denied)?,
                );
            } else if self.released.is_none()
                && self
                    .observer
                    .snapshot(&self.scope.context)
                    .map_err(denied)?[0]
                    == creators::State::Retiring
            {
                let ack = self.producer.resume_close(&self.scope).map_err(denied)?;
                let mut universe =
                    OriginalUniverse::new(&self.runtime, &self.image).map_err(denied)?;
                self.released = Some(
                    self.producer
                        .complete_close(ack, &mut universe)
                        .map_err(denied)?,
                );
            }
            if let Some(released) = &self.released {
                released
                    .original()
                    .verify_close_receipt(released.scope(), released.receipt())
                    .map_err(denied)?;
                self.observer
                    .assert_closed_for_cleanup(&self.scope.context, &self.scope.binding)
                    .map_err(denied)?;
            } else {
                self.observer
                    .assert_no_creator_for_key_cleanup(&self.scope.context, &self.scope.binding)
                    .map_err(denied)?;
            }
            // COMPLETE provider absence, not just missing original metadata.
            let mut universe = OriginalUniverse::new(&self.runtime, &self.image).map_err(denied)?;
            let facts = universe.inspect_absence(&self.scope).map_err(denied)?;
            if facts.scope != self.scope || !facts.matches.is_empty() {
                return Err(Error::Conflict);
            }
            Ok(())
        }
    }

    impl<G: NativeLifecycleGate> rows::OriginalCreator for NativeCarrierAuthority<G> {
        fn query(
            &mut self,
            scope: &nelomai_client_tunnel::redundancy::SessionScope,
            role: rows::Role,
            challenge: u64,
        ) -> rows::Result<rows::LiveOwner> {
            if scope != &self.scope.context.intent.scope
                || self.active_row_role != Some(role)
                || challenge == 0
            {
                return Err(rows::Error::Conflict);
            }
            Ok(rows::LiveOwner {
                binding: self.row_binding()?,
                challenge,
            })
        }
        fn authorize(
            &mut self,
            binding: &rows::Binding,
            target: &rows::Target,
        ) -> rows::Result<()> {
            if self.row_binding()? != *binding {
                return Err(rows::Error::Conflict);
            }
            let use_ = self.row_use().map_err(|_| rows::Error::Conflict)?;
            let native = self.current(use_).map_err(|_| rows::Error::Conflict)?;
            let kind = match binding.role {
                rows::Role::Carrier => RecordKind::CarrierRows,
                rows::Role::MemberA => RecordKind::MemberARows,
                rows::Role::MemberB => RecordKind::MemberBRows,
            };
            let bytes = self
                .runtime
                .record(&self.scope.context, kind)
                .map_err(|_| rows::Error::Journal)?;
            let record = rows::Record::decode(&bytes)?;
            validate_rows_effect(&native, &record, binding, target)?;
            if binding.role == rows::Role::Carrier {
                self.gate
                    .authorize_rows(&self.scope, binding, target, &self.observer)
                    .map_err(|_| rows::Error::Conflict)?;
            } else {
                let members = self
                    .producer
                    .original_universe()
                    .member_read_pin()
                    .map_err(|_| rows::Error::Conflict)?;
                self.gate
                    .authorize_member_rows(&self.scope, binding, target, &self.observer, &members)
                    .map_err(|_| rows::Error::Conflict)?;
            }
            if self.row_binding()? != *binding
                || self.current(use_).map_err(|_| rows::Error::Conflict)? != native
                || self
                    .runtime
                    .record(&self.scope.context, kind)
                    .map_err(|_| rows::Error::Journal)?
                    != bytes
            {
                return Err(rows::Error::Conflict);
            }
            Ok(())
        }
    }

    // SAFETY: mandatory original source/runtime/serialized/cooperative pins,
    // real protected revision, NEW-HKEY/current-value fence, full original
    // provider registry and raw ACK retention are composed below. G's unsafe
    // contract supplies independently proven row/guard/network/supervision
    // order; there is deliberately NO permissive production implementation.
    unsafe impl<G: NativeLifecycleGate> ModuleRuntimeAuthority for NativeCarrierAuthority<G> {
        type Key = keys::Held<win32::Handle>;
        type MutationLock = KeyLock;
        fn retain_original_session(&mut self, original: wintun::SessionEndRead) {
            self.gate.retain_original_session(original);
        }
        fn verify(&mut self, binding: &Binding, stage: Stage) -> Result<()> {
            self.verify_supervised()?;
            self.check_binding(binding)?;
            let cleanup = matches!(
                stage,
                Stage::CleanupObserve | Stage::BeforeEnd | Stage::BeforeClose | Stage::AfterClose
            );
            if !cleanup && self.failed {
                return Err(Error::Pending);
            }
            self.failed = true;
            let use_ = if cleanup {
                Use::Cleanup
            } else if matches!(stage, Stage::Resolve | Stage::BeforeCreate) {
                Use::Create
            } else {
                Use::Live
            };
            let before = self.current(use_)?;
            if stage == Stage::AfterClose {
                self.complete_original_close()?;
                // Actual owning once-close ACK exists before this handoff.
                // Keep the SAME Rc even when subsequent G/SDK postflight fails.
                match self
                    .released
                    .as_ref()
                    .ok_or(Error::Pending)?
                    .cleanup_read_pin()
                    .map_err(denied)?
                {
                    creators::ClosedRead::Published(_) => {
                        self.retain_retired_reader()?;
                    }
                    creators::ClosedRead::Unpublished(_) => {
                        self.retain_unpublished_closed_reader()?;
                    }
                }
            }
            // Acquire new recursive lease BEFORE replacing/releasing the old
            // one; no unlocked gap before a later EndSession/CloseAdapter.
            let held = self.refresh(use_)?;
            self.gate.authorize(&self.scope, stage, &self.observer)?;
            same_record(&before, self.current(use_)?).map_err(denied)?;
            self.effect = Some(held);
            if stage == Stage::BeforeClose && self.retirement.is_none() {
                self.retirement = Some(self.producer.retire(&self.scope).map_err(denied)?);
            }
            if stage == Stage::AfterClose {
                self.effect.take();
            }
            if !cleanup {
                self.failed = false;
            }
            Ok(())
        }
        fn authorize_create(
            &mut self,
            binding: &Binding,
            record: &receipts::Record,
            ack: &receipts::NewKeyAck<Self::Key>,
            lock: &mut KeyLock,
        ) -> Result<()> {
            self.verify_supervised()?;
            self.check_binding(binding)?;
            if self.failed || self.pending.is_some() || !self.runtime.matches_lock(lock) {
                return Err(Error::Pending);
            }
            self.failed = true;
            if self.current(Use::Create)? != *record {
                return Err(Error::Conflict);
            }
            let mut lease = self.refresh(Use::Create)?;
            let prepared = PreparedOriginal::new(&self.runtime, &self.image, self.scope.clone())
                .map_err(denied)?;
            self.gate
                .authorize(&self.scope, Stage::BeforeCreate, &self.observer)?;
            let state = self
                .observer
                .snapshot(&self.scope.context)
                .map_err(denied)?[0];
            if state == creators::State::Intent {
                let mut universe =
                    OriginalUniverse::new(&self.runtime, &self.image).map_err(denied)?;
                self.producer
                    .confirm_empty(self.scope.clone(), &mut universe)
                    .map_err(denied)?;
            }
            self.observer
                .assert_absent(&self.scope.context, &self.scope.binding)
                .map_err(denied)?;
            keys::reattest_disabled_original_key(
                &mut win32::Kernel,
                record,
                &self.scope.binding,
                ack,
            )
            .map_err(denied)?;
            lease.verify(&self.cancelled).map_err(denied)?;
            if self.current(Use::Create)? != *record {
                return Err(Error::Conflict);
            }
            // Runtime/package/lease checks above may be slow. The original
            // HKEY and exact current DWORD0 are rechecked LAST, not cached from
            // before authentication. Same canonical lock is still borrowed.
            keys::reattest_disabled_original_key(
                &mut win32::Kernel,
                record,
                &self.scope.binding,
                ack,
            )
            .map_err(denied)?;
            // Enter pending LAST, after the full native universe is checked.
            // Pending-without-ACK may NOT be mistaken for a fresh empty NIC set.
            let begin = self.producer.begin(self.scope.clone()).map_err(denied)?;
            self.pending = Some(PendingCreate {
                begin,
                prepared,
                lease: Some(lease),
            });
            self.effect.take(); // PendingCreate already holds real lease.
            Ok(())
        }
        fn acknowledged_original(&mut self, original: OriginalAdapterRead) {
            let Some(PendingCreate {
                begin,
                prepared,
                lease,
            }) = self.pending.take()
            else {
                // An impossible/repeated callback cannot drop unclosed native
                // pins or authorize lookup adoption/destruction.
                std::mem::forget(original);
                self.failed = true;
                return;
            };
            let native = prepared.acknowledge(original); // field moves only
                                                         // SAFETY: this is the SAME actual raw ACK from our sole authorized
                                                         // new CreateAdapter call and prepared unique original begin.
            let ack = unsafe { begin.acknowledge_original(native) };
            // Registry retains raw ACK BEFORE ANY fallible validation/query.
            // Failure keeps native pins and irreversibly denies forward reuse.
            self.failed = match ack {
                Ok(ack) => self.producer.publish(ack).is_err(),
                Err(_) => true,
            };
            self.effect = lease;
        }
        fn provider(&mut self, binding: &Binding, identity: &Identity, stage: Stage) -> Result<()> {
            self.verify_supervised()?;
            self.check_binding(binding)?;
            let use_ = match stage {
                Stage::Observe => Use::Live,
                Stage::CleanupObserve => Use::Cleanup,
                _ => return Err(Error::Invalid),
            };
            if use_ != Use::Cleanup && self.failed {
                return Err(Error::Pending);
            }
            let was_failed = self.failed;
            self.failed = true;
            let before = self.current(use_)?;
            let facts = if use_ == Use::Cleanup {
                self.observer.observe_all_for_cleanup(&self.scope.context)
            } else {
                self.observer.observe_all(&self.scope.context)
            }
            .map_err(denied)?;
            let actual = facts
                .originals
                .into_iter()
                .find(|o| o.scope == self.scope)
                .ok_or(Error::Conflict)?;
            let i = actual.identity;
            if i.guid != identity.guid
                || i.luid != identity.luid
                || i.index != identity.index
                || i.name != identity.name
                || i.description != identity.description
                || i.if_type != identity.if_type
                || i.tunnel_type != identity.tunnel_type
            {
                return Err(Error::Conflict);
            }
            if self.current(use_)? != before {
                return Err(Error::Conflict);
            }
            self.failed = was_failed;
            Ok(())
        }
        fn release_call_resources(&mut self) {
            self.effect.take();
            if let Some(pending) = self.pending.as_mut() {
                // An unknown/failed Create outcome remains pending with SAME
                // prepared image/runtime/creator state. Do not hold Driver
                // installation locks while the supervisor resolves it later.
                pending.lease.take();
            }
        }
    }
}

#[cfg(all(test, windows))]
fn actual_original_runtime_composes_without_fabricating_or_borrowing_an_owner<
    'a,
    G: native::NativeLifecycleGate + 'a,
>(
    module: super::member_carrier_module::native::LoadedWintun,
    runtime: super::member_carrier_key_authority::RuntimeRead,
    image: super::member_carrier_module::native::OriginalImage,
    producer: super::member_carrier_creators::Producer<
        super::member_carrier_wintun::native::OriginalWintun,
    >,
    scope: super::member_carrier_creators::Scope,
    gate: G,
    cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> super::member_carrier_wintun::Result<
    super::member_carrier_wintun::Carrier<
        super::member_carrier_wintun::native::NativeKernel<'a, native::NativeCarrierAuthority<G>>,
    >,
> {
    // Compile-only integration: ALL arguments are actual privileged opaque
    // owners. No mocked native authority or Windows execution is claimed.
    native::NativeCarrierAuthority::new(module, runtime, image, producer, scope, gate, cancelled)?
        .into_carrier()
}

#[cfg(test)]
#[path = "member_carrier_construction_tests.rs"]
mod construction_tests;
#[cfg(test)]
#[path = "member_carrier_runtime_tests.rs"]
mod tests;

#[cfg(all(test, windows))]
fn actual_row_owner_and_carrier_share_one_retained_original_authority<
    'a,
    'p,
    G: native::NativeLifecycleGate + 'a,
>(
    authority: native::NativeCarrierAuthority<G>,
    files: super::member_session::NativeSessionFiles,
    prerequisite: crate::member_carrier_native_ownership::PrecreationReceipt<
        'p,
        super::member_carrier_keys::Held<super::member_carrier_keys::win32::Handle>,
        super::member_carrier_key_authority::KeyLock,
    >,
    policy: crate::member_carrier_rows::AddressPolicy,
    cancelled: &std::sync::atomic::AtomicBool,
) -> super::member_carrier_wintun::Result<()> {
    // Compile only. Not a factory caller, authority implementation or claim
    // this stage was executed on Windows. Every owner is an actual native type.
    let (mut carrier, mut rows) = authority.into_components()?;
    carrier.create(prerequisite)?;
    carrier.start()?;
    let binding = rows
        .binding()
        .map_err(|_| super::member_carrier_wintun::Error::Conflict)?;
    let (store, old) = super::member_session::WindowsCarrierRowsStore::open(files, binding.clone())
        .map_err(|_| super::member_carrier_wintun::Error::Conflict)?;
    if old.is_some() {
        return Err(super::member_carrier_wintun::Error::Pending);
    }
    let row_read = rows.read_pin();
    let mut owner = super::member_carrier_rows::RowOwner::capture_native(binding, rows, store)
        .map_err(|_| super::member_carrier_wintun::Error::Conflict)?;
    owner
        .create_address(policy)
        .map_err(|_| super::member_carrier_wintun::Error::Conflict)?;
    owner
        .wait_address_ready(cancelled)
        .map_err(|_| super::member_carrier_wintun::Error::Conflict)?;
    let source = row_read.source_read(
        owner
            .created_address_read_pin()
            .map_err(|_| super::member_carrier_wintun::Error::Conflict)?,
    )?;
    source.inspect_bindings(|_| Ok(()))?;
    owner
        .stop()
        .map_err(|_| super::member_carrier_wintun::Error::Conflict)?;
    drop(owner);
    carrier.close_bounded(cancelled, 1000)
}
