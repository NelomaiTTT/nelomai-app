//! Actual coordinator gates. This module is not a selected product factory.
#![allow(dead_code)]

#[cfg(windows)]
use super::member_carrier_creators as creators;
use crate::member_carrier::{CarrierError as Error, Result};
#[cfg(not(windows))]
use crate::member_carrier_creators as creators;
use crate::member_carrier_native_ownership::{self as receipts, KeyPhase, Phase, Record, Value};

/// Actual constructor/close-ACK callback retention, not resource permission.
/// Native callers supply opaque readers; equal data cannot construct a receipt.
pub(crate) struct OriginalReadCapture<T> {
    original: std::cell::RefCell<Option<std::rc::Rc<T>>>,
    registered: std::cell::Cell<bool>,
    failed: std::cell::Cell<bool>,
    revoked: std::rc::Rc<std::cell::Cell<bool>>,
}
struct ReadCaptureAttempt<'a, T> {
    root: &'a OriginalReadCapture<T>,
    completed: bool,
}
impl<T> Drop for ReadCaptureAttempt<'_, T> {
    fn drop(&mut self) {
        if !self.completed {
            self.root.failed.set(true);
            self.root.revoked.set(true);
        }
    }
}
impl<T> OriginalReadCapture<T> {
    pub(crate) fn new(revoked: std::rc::Rc<std::cell::Cell<bool>>) -> Self {
        Self {
            original: std::cell::RefCell::new(None),
            registered: std::cell::Cell::new(false),
            failed: std::cell::Cell::new(false),
            revoked,
        }
    }
    pub(crate) fn pin(&self) -> Result<std::rc::Rc<T>> {
        self.original
            .borrow()
            .as_ref()
            .cloned()
            .ok_or(Error::Pending)
    }
    pub(crate) fn capture(
        &self,
        original: std::rc::Rc<T>,
        register: impl FnOnce(&std::rc::Rc<T>) -> Result<()>,
    ) -> Result<()> {
        self.revoked.set(true); // Closing/retired facts can never resume live use.
        let mut attempt = ReadCaptureAttempt {
            root: self,
            completed: false,
        };
        let mut retained = self
            .original
            .try_borrow_mut()
            .map_err(|_| Error::Conflict)?;
        if let Some(first) = retained.as_ref() {
            if !std::rc::Rc::ptr_eq(first, &original) {
                return Err(Error::Conflict);
            }
            // Re-observing THAT Rc does not retry a failed registration or
            // invoke an equal replacement's callback. Getter facts remain.
            self.require_registered()?;
            attempt.completed = true;
            return Ok(());
        }
        *retained = Some(original.clone()); // actor root BEFORE any callback
        drop(retained); // registration may read Root's factual accessor
        if self.failed.get() {
            return Err(Error::Retired);
        }
        register(&original)?;
        if self.failed.get() {
            return Err(Error::Retired);
        }
        self.registered.set(true);
        attempt.completed = true;
        Ok(())
    }
    pub(crate) fn confirm(&self, original: &std::rc::Rc<T>) -> Result<()> {
        if !std::rc::Rc::ptr_eq(&self.pin()?, original) {
            self.failed.set(true);
            self.revoked.set(true);
            return Err(Error::Conflict);
        }
        // SAME receipt facts only, even after lost/error/unwind postflight.
        // This neither registers a delegate nor authorizes any cleanup effect.
        Ok(())
    }
    pub(crate) fn require_registered(&self) -> Result<()> {
        if !self.registered.get() || self.failed.get() {
            return Err(Error::Retired);
        }
        Ok(())
    }
}

/// Owning registration mechanics only. No lifecycle authority is supplied here.
/// The mandatory native delegate remains responsible for every actual effect.
struct LifecycleUpgrade<G> {
    replacement: std::cell::RefCell<Option<G>>,
    rejected: std::cell::RefCell<Vec<G>>,
    attempted: std::cell::Cell<bool>,
    completed: std::cell::Cell<bool>,
    revoked: std::rc::Rc<std::cell::Cell<bool>>,
}
struct UpgradeAttempt {
    revoked: std::rc::Rc<std::cell::Cell<bool>>,
    completed: bool,
}
impl Drop for UpgradeAttempt {
    fn drop(&mut self) {
        if !self.completed {
            self.revoked.set(true);
        }
    }
}
impl<G> LifecycleUpgrade<G> {
    /// Factual native receipt registration only. Bootstrap is NOT a default
    /// full effect gate: its separate narrow native authorization still runs.
    fn retain_original_read<T>(
        &self,
        root: &OriginalReadCapture<T>,
        original: &std::rc::Rc<T>,
        register: impl FnOnce(&mut G, &std::rc::Rc<T>) -> Result<()>,
    ) -> Result<()> {
        root.capture(original.clone(), |pin| {
            if !self.attempted.get() {
                return Ok(());
            }
            self.inspect(true, |gate| register(gate, pin))
        })
    }
    fn new(revoked: std::rc::Rc<std::cell::Cell<bool>>) -> Self {
        Self {
            replacement: std::cell::RefCell::new(None),
            rejected: std::cell::RefCell::new(vec![]),
            attempted: std::cell::Cell::new(false),
            completed: std::cell::Cell::new(false),
            revoked,
        }
    }
    fn register(
        &self,
        replacement: G,
        postflight: impl FnOnce(&mut G) -> Result<()>,
    ) -> Result<()> {
        let mut attempt = UpgradeAttempt {
            revoked: self.revoked.clone(),
            completed: false,
        };
        if self.attempted.replace(true) {
            // An equal-looking retry never replaces or destroys the first
            // actual owning delegate. Keep the rejected input as well.
            self.rejected.borrow_mut().push(replacement);
            return Err(Error::Retired);
        }
        *self.replacement.borrow_mut() = Some(replacement);
        if self.revoked.get() {
            return Err(Error::Retired);
        }
        postflight(
            self.replacement
                .borrow_mut()
                .as_mut()
                .expect("retained replacement"),
        )?;
        if self.revoked.get() {
            return Err(Error::Retired);
        }
        self.completed.set(true);
        attempt.completed = true;
        Ok(())
    }
    fn inspect<T>(&self, cleanup: bool, call: impl FnOnce(&mut G) -> Result<T>) -> Result<T> {
        let mut attempt = UpgradeAttempt {
            revoked: self.revoked.clone(),
            completed: false,
        };
        if cleanup {
            self.revoked.set(true);
        }
        if !cleanup && (!self.completed.get() || self.revoked.get()) {
            return Err(Error::Retired);
        }
        let mut retained = self
            .replacement
            .try_borrow_mut()
            .map_err(|_| Error::Conflict)?;
        let result = call(retained.as_mut().ok_or(Error::Pending)?)?;
        if !cleanup && self.revoked.get() {
            return Err(Error::Retired);
        }
        // Cleanup success can never clear the shared forward signal.
        attempt.completed = true;
        Ok(result)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartupStage {
    Resolve,
    BeforeCreate,
    Observe,
    BeforeSession,
    BeforeDrain,
    AddressCreate,
}

/// Comparison only. The native caller must obtain originals from the SAME
/// original registry/full SDK universe, and authenticate the actual Pair ACK,
/// runtime, serial lock, BFE absence and other original resources independently.
fn validate_startup(
    native: &Record,
    scope: &creators::Scope,
    stage: StartupStage,
    originals: &[creators::OriginalIdentity],
) -> Result<()> {
    receipts::validate_record(native)?;
    let carrier = &native.keys[0];
    if native.context != scope.context
        || scope.binding != native.context.bindings[0]
        || native.generation != scope.generation
        || native.phase != Phase::Preparing
        || carrier.phase != KeyPhase::Disabled
        || !carrier.new_key_ack
        || carrier.current != Value::DwordZero
        || carrier.pending.is_some()
        || native.keys[1..].iter().any(|key| {
            key.phase != KeyPhase::Unstarted
                || key.new_key_ack
                || key.current != Value::Absent
                || key.pending.is_some()
        })
        || originals.len() > 1
    {
        return Err(Error::Conflict);
    }
    for original in originals {
        let identity = &original.identity;
        if original.scope != *scope
            || identity.guid != scope.binding.guid
            || identity.name != scope.binding.name
            || identity.index == 0
            || identity.luid == 0
            || identity.if_type != 53
            || identity.tunnel_type != 0
        {
            return Err(Error::Conflict);
        }
    }
    let present = !originals.is_empty();
    match stage {
        StartupStage::Resolve | StartupStage::BeforeCreate if !present => Ok(()),
        StartupStage::BeforeSession | StartupStage::BeforeDrain | StartupStage::AddressCreate
            if present =>
        {
            Ok(())
        }
        StartupStage::Observe => Ok(()),
        _ => Err(Error::Conflict),
    }
}

fn validate_carrier_ready_pair(
    native: &Record,
    pair: &crate::member_carrier_pair::Record,
) -> Result<()> {
    use crate::member_carrier_pair::{Effect, Operation, Phase};
    pair.validate().map_err(|_| Error::Conflict)?;
    if pair.scope != native.context.intent.scope
        || pair.provenance != native.context.provenance
        || pair.addresses != native.context.intent.addresses
        || pair.phase != Phase::Starting
        || pair.pending != Some(Effect::CarrierReady)
        || !matches!(pair.operation, Some(Operation::Start(_)))
        || pair.stop_stage != 0
        || pair.carrier.is_some()
        || pair.active.is_some()
        || pair.options.is_none()
        || pair.network.is_some()
        || pair.pending_guard.is_some()
        || pair.guard
            != crate::member_carrier_guard::Model::empty(pair.scope.clone())
                .map_err(|_| Error::Conflict)?
    {
        return Err(Error::Conflict);
    }
    // Prepared configuration is not a started member; original member inventory
    // and full mixed SDK absence are independently required by the native gate.
    if pair.members.iter().flatten().any(|m| {
        m.owner.proof.is_some()
            || m.owner.retired_proof.is_some()
            || m.owner.previous_config_sha256.is_some()
            || m.owner.phase != crate::member_owner::Phase::Prepared
    }) {
        return Err(Error::Conflict);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClosingStage {
    Observe,
    AddressDelete,
    SessionEnd,
    CarrierClose,
    AfterClose,
}

/// Comparison only; actual opaque C readiness, signed member/key handles,
/// whole SDK universe and current Pair Calling are checked by the native gate.
fn validate_primary_member_start(
    context: &receipts::Context,
    pair: &crate::member_carrier_pair::Record,
    intent: &crate::member_owner::Intent,
    carrier: &crate::member_carrier_guard::Carrier,
    egress: &[Option<crate::member_carrier_guard::Identity>; 2],
) -> Result<()> {
    use crate::{member_carrier_guard as g, member_carrier_pair as p, member_owner as o};
    use nelomai_client_tunnel::redundancy::Slot;
    use nelomai_contracts::dispatcher::TunnelSlot;
    let (index, target) = match intent.slot {
        TunnelSlot::A => (0, Slot::A),
        TunnelSlot::B => (1, Slot::B),
    };
    pair.validate().map_err(|_| Error::Conflict)?;
    let member = pair.members[index].as_ref().ok_or(Error::Conflict)?;
    if pair.scope != context.intent.scope
        || intent.scope != context.intent.scope
        || pair.provenance != context.provenance
        || pair.addresses != context.intent.addresses
        || pair.phase != p::Phase::Starting
        || pair.operation != Some(p::Operation::Start(target))
        || pair.pending != Some(p::Effect::MemberStart(target))
        || pair.stop_stage != 0
        || pair.active.is_some()
        || pair.network.is_some()
        || pair.pending_guard.is_some()
        || pair.guard != g::Model::empty(pair.scope.clone()).map_err(|_| Error::Conflict)?
        || member.owner.intent != *intent
        || member.owner.phase != o::Phase::Prepared
        || member.owner.proof.is_some()
        || member.owner.retired_proof.is_some()
        || member.owner.previous_config_sha256.is_some()
        || pair.members[1 - index].is_some()
        || egress.iter().any(Option::is_some)
        || carrier.identity.scope != pair.scope
        || carrier.identity.proof.guid != context.bindings[0].guid
        || carrier.identity.proof.index == 0
        || carrier.identity.proof.luid == 0
        || Some(carrier.identity.proof) != pair.carrier
        || carrier.sources != pair.addresses.iter().map(|a| a.addr()).collect::<Vec<_>>()
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

/// Comparison only; actual source/Pair/Calling and locked native WFP reads are
/// mandatory at the native attestor. This never grants permits or cleanup.
fn validate_initial_guard_base(
    context: &receipts::Context,
    pair: &crate::member_carrier_pair::Record,
    kind: crate::member_carrier_guard::SessionKind,
    expected: &crate::member_carrier_guard::Model,
    desired: &crate::member_carrier_guard::Model,
    carrier: &crate::member_carrier_guard::Carrier,
    egress: &[Option<crate::member_carrier_guard::Identity>; 2],
) -> Result<()> {
    use crate::{member_carrier_guard as g, member_carrier_pair as p, member_owner as o};
    pair.validate().map_err(|_| Error::Conflict)?;
    expected.validate().map_err(|_| Error::Conflict)?;
    desired.validate().map_err(|_| Error::Conflict)?;
    let plan = pair.pending_guard.as_ref().ok_or(Error::Conflict)?;
    if pair.scope != context.intent.scope
        || pair.provenance != context.provenance
        || pair.addresses != context.intent.addresses
        || pair.phase != p::Phase::Starting
        || !matches!(pair.operation, Some(p::Operation::Start(_)))
        || pair.pending != Some(p::Effect::Guard)
        || pair.stop_stage != 0
        || pair.active.is_some()
        || pair.network.is_some()
        || kind != g::SessionKind::StaticBase
        || pair.guard != *expected
        || *expected != g::Model::empty(pair.scope.clone()).map_err(|_| Error::Conflict)?
        || plan.expected != *expected
        || plan.withdrawn != *expected
        || plan.base != *desired
        || plan.desired != *desired
        || desired.permits
        || desired.active.is_some()
        || carrier.identity.scope != pair.scope
        || Some(carrier.identity.proof) != pair.carrier
        || carrier.sources != pair.addresses.iter().map(|a| a.addr()).collect::<Vec<_>>()
    {
        return Err(Error::Conflict);
    }
    let mut members = [None, None];
    for (i, actual) in egress.iter().enumerate() {
        match (&pair.members[i], actual) {
            (None, None) => {}
            (Some(saved), Some(actual))
                if saved.owner.phase == o::Phase::Running
                    && actual.scope == pair.scope
                    && saved
                        .owner
                        .proof
                        .is_some_and(|proof| proof.interface == actual.proof)
                    && saved.owner.retired_proof.is_none()
                    && saved.owner.previous_config_sha256.is_none() =>
            {
                members[i] = Some(g::Member {
                    identity: actual.clone(),
                    probes: vec![],
                });
            }
            _ => return Err(Error::Conflict),
        }
    }
    let canonical = g::Model::new(pair.scope.clone(), carrier.clone(), members, None)
        .and_then(|m| m.without_permits())
        .map_err(|_| Error::Conflict)?;
    if canonical != *desired {
        return Err(Error::Conflict);
    }
    Ok(())
}

/// Monotonic comparison only. New operation permission still comes exclusively
/// from the current original Pair-store CAS/Runtime/Calling read.
fn validate_operation_selection(
    context: &receipts::Context,
    before: &crate::member_carrier_pair::Record,
    after: &crate::member_carrier_pair::Record,
) -> Result<()> {
    use crate::member_carrier_pair::Phase as PairPhase;
    before.validate().map_err(|_| Error::Conflict)?;
    after.validate().map_err(|_| Error::Conflict)?;
    for record in [before, after] {
        if record.scope != context.intent.scope
            || record.provenance != context.provenance
            || record.addresses != context.intent.addresses
            || record.pending.is_none()
            || !matches!(record.phase, PairPhase::Starting | PairPhase::Closing)
        {
            return Err(Error::Conflict);
        }
    }
    if after.revision < before.revision
        || (after.revision == before.revision && after != before)
        || (before.phase == PairPhase::Closing
            && (after.phase != PairPhase::Closing || after.stop_stage < before.stop_stage))
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

/// C-only comparison, not native ownership/effect authority. The gate must
/// separately query all original native SDK/resources and session outcome.
fn validate_c_only_closing(
    native: &Record,
    scope: &creators::Scope,
    pair: &crate::member_carrier_pair::Record,
    stage: ClosingStage,
    originals: &[creators::OriginalIdentity],
) -> Result<()> {
    use crate::member_carrier_pair::{Effect, Phase as PairPhase};
    receipts::validate_record(native)?;
    pair.validate().map_err(|_| Error::Conflict)?;
    if native.context != scope.context
        || scope.binding != native.context.bindings[0]
        || scope.generation == 0
        || native.generation < scope.generation
        || native.phase != Phase::Closing
        || native.keys[0].phase != KeyPhase::Disabled
        || !native.keys[0].new_key_ack
        || native.keys[0].current != Value::DwordZero
        || native.keys[0].pending.is_some()
        || native.keys[1..].iter().any(|key| {
            key.phase != KeyPhase::Unstarted
                || key.new_key_ack
                || key.current != Value::Absent
                || key.pending.is_some()
        })
        || pair.scope != native.context.intent.scope
        || pair.provenance != native.context.provenance
        || pair.addresses != native.context.intent.addresses
        || pair.phase != PairPhase::Closing
        || pair.active.is_some()
        || pair.operation.is_some()
        || pair.network.is_some()
        || pair.pending_guard.is_some()
        || pair.guard
            != crate::member_carrier_guard::Model::empty(pair.scope.clone())
                .map_err(|_| Error::Conflict)?
        || pair.members.iter().flatten().any(|m| {
            m.owner.proof.is_some()
                || m.owner.retired_proof.is_some()
                || m.owner.previous_config_sha256.is_some()
                || m.owner.phase != crate::member_owner::Phase::Prepared
        })
        || originals.len() > 1
    {
        return Err(Error::Conflict);
    }
    let exact_stage = match stage {
        ClosingStage::AddressDelete => {
            pair.stop_stage == 6 && pair.pending == Some(Effect::CarrierAddressDelete)
        }
        ClosingStage::SessionEnd => {
            pair.stop_stage == 7 && pair.pending == Some(Effect::CarrierSessionEnd)
        }
        ClosingStage::CarrierClose | ClosingStage::AfterClose => {
            pair.stop_stage == 8 && pair.pending == Some(Effect::CarrierClose)
        }
        ClosingStage::Observe => pair.stop_stage <= 8 && pair.pending.is_some(),
    };
    if !exact_stage {
        return Err(Error::Conflict);
    }
    for original in originals {
        let identity = &original.identity;
        if original.scope != *scope
            || identity.guid != scope.binding.guid
            || identity.name != scope.binding.name
            || identity.luid == 0
            || identity.index == 0
            || identity.if_type != 53
            || identity.tunnel_type != 0
            || pair.carrier.is_some_and(|p| {
                p.guid != identity.guid || p.index != identity.index || p.luid != identity.luid
            })
        {
            return Err(Error::Conflict);
        }
    }
    match stage {
        ClosingStage::Observe => Ok(()),
        ClosingStage::AfterClose if originals.is_empty() => Ok(()),
        ClosingStage::AddressDelete | ClosingStage::SessionEnd | ClosingStage::CarrierClose
            if originals.len() == 1 =>
        {
            Ok(())
        }
        _ => Err(Error::Conflict),
    }
}

/// Factual frame only. The caller additionally needs the actual unpublished
/// raw Create ACK/once-close reader; no provider identity is created here.
fn validate_unpublished_after_close(
    native: &Record,
    scope: &creators::Scope,
    pair: &crate::member_carrier_pair::Record,
) -> Result<()> {
    if pair.carrier.is_some() {
        return Err(Error::Conflict);
    }
    validate_c_only_closing(native, scope, pair, ClosingStage::AfterClose, &[])
}

#[cfg(windows)]
pub(crate) mod native {
    use super::*;
    use crate::member_carrier_pair::{self as pair, Record as PairRecord};
    use crate::windows::{
        member_carrier_assembly::native::NativeAssemblyAssets,
        member_carrier_guard::{ScopedGuardAbsence, Wfp},
        member_carrier_key_authority::RuntimeRead,
        member_carrier_members::native::MemberInventoryRead,
        member_carrier_module::native::OriginalImage,
        member_carrier_pair_store::native_store::NativePairIntentRead,
        member_carrier_payload::native::WintunSource,
        member_carrier_rows as rows,
        member_carrier_runtime::native::{
            NativeLifecycleGate, RetiredCarrierRead, UnpublishedClosedCarrierRead,
        },
        member_carrier_wintun::{self as wintun, native::OriginalWintun, Stage},
        member_native_deadline::{NativeDeadline, NativeDeadlineReadPin},
        member_session::RecordKind,
    };
    use std::{
        cell::RefCell,
        rc::Rc,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
    };

    /// First static-base transaction only. The source is the SAME opaque
    /// readiness/create-ACK pin, not carrier/egress metadata from the journal.
    /// Later permit, detach and cleanup transactions require the full coordinator
    /// and are refused by this narrow implementation.
    pub(crate) struct InitialBaseAttestor {
        context: receipts::Context,
        runtime: RuntimeRead,
        source: Rc<crate::windows::member_carrier_runtime::native::NativeSourceRead>,
        pair: Rc<NativePairIntentRead>,
        expected: PairRecord,
        supervisor: Rc<NativeDeadline>,
        deadline: NativeDeadlineReadPin,
        failed: bool,
    }
    impl InitialBaseAttestor {
        pub(crate) fn new(
            context: receipts::Context,
            runtime: &RuntimeRead,
            source: Rc<crate::windows::member_carrier_runtime::native::NativeSourceRead>,
            original: Rc<NativePairIntentRead>,
            expected: PairRecord,
            supervisor: Rc<NativeDeadline>,
        ) -> crate::member_carrier_guard::Result<Self> {
            let deadline = supervisor.read_pin().map_err(guard_denied)?;
            let mut result = Self {
                context,
                runtime: runtime.read_pin().map_err(guard_denied)?,
                source,
                pair: original,
                expected,
                supervisor,
                deadline,
                failed: false,
            };
            use crate::windows::member_carrier_guard::BindingAttestor;
            let scope = result.context.intent.scope.clone();
            result.observe(&scope)?;
            Ok(result)
        }
        fn continuity(&self) -> crate::member_carrier_guard::Result<()> {
            if !self.pair.matches_runtime(&self.runtime) {
                return Err(crate::member_carrier_guard::GuardError::Conflict);
            }
            self.deadline
                .verify_runtime_call(&self.supervisor, &self.runtime, &self.context)
                .map_err(guard_denied)?;
            self.runtime.verify(&self.context).map_err(guard_denied)?;
            if !self.runtime.fresh(&self.context).map_err(guard_denied)? {
                return Err(crate::member_carrier_guard::GuardError::Conflict);
            }
            Ok(())
        }
        fn inspect<T>(
            &self,
            action: impl FnOnce(
                &crate::windows::member_carrier_runtime::native::NativeBindingsWindow<'_>,
            ) -> wintun::Result<T>,
        ) -> crate::member_carrier_guard::Result<T> {
            self.continuity()?;
            let result = self
                .pair
                .inspect_effect(
                    &self.runtime,
                    &self.supervisor,
                    &self.expected,
                    pair::Effect::Guard,
                    |_| {
                        self.source
                            .inspect_window(|window| {
                                if !window.matches_source(&self.source)
                                    || !window.matches_runtime(&self.runtime)
                                    || window.bindings().scope != self.context.intent.scope
                                {
                                    return Err(wintun::Error::Conflict);
                                }
                                action(window)
                            })
                            .map_err(io_denied)
                    },
                )
                .map_err(guard_denied)?;
            self.continuity()?;
            Ok(result)
        }
        fn verify_unmodified_rows(
            context: &receipts::Context,
            runtime: &RuntimeRead,
            bindings: &crate::windows::member_carrier_guard::Bindings,
        ) -> wintun::Result<()> {
            let native = receipts::Record::decode(
                &runtime
                    .record(context, RecordKind::NativeCarrierReceipts)
                    .map_err(denied)?,
            )
            .map_err(denied)?;
            if native.context != *context
                || native.phase != Phase::Preparing
                || context.intent.addresses.len() != 1
            {
                return Err(wintun::Error::Conflict);
            }
            for kind in [
                RecordKind::Network,
                RecordKind::MemberARows,
                RecordKind::MemberBRows,
            ] {
                if runtime
                    .optional_record(context, kind)
                    .map_err(denied)?
                    .is_some()
                {
                    return Err(wintun::Error::Conflict);
                }
            }
            let carrier = bindings.carrier.as_ref().ok_or(wintun::Error::Conflict)?;
            for (i, identity) in std::iter::once(Some(&carrier.identity))
                .chain(bindings.egress.iter().map(Option::as_ref))
                .enumerate()
            {
                let Some(identity) = identity else {
                    continue;
                };
                let key = &native.keys[i];
                if key.phase != KeyPhase::Disabled
                    || !key.new_key_ack
                    || key.current != Value::DwordZero
                    || key.pending.is_some()
                {
                    return Err(wintun::Error::Conflict);
                }
                // Binding DATA from this already-authenticated original Source
                // window. This neither creates nor adopts native row ownership.
                let std::net::IpAddr::V4(address) = context.intent.addresses[0].addr() else {
                    return Err(wintun::Error::Conflict);
                };
                let binding = rows::Binding {
                    scope: context.intent.scope.clone(),
                    boot_id: context.provenance.boot_id,
                    runtime: context.provenance.runtime.clone(),
                    network_epoch: context.provenance.network_epoch,
                    role: [
                        rows::Role::Carrier,
                        rows::Role::MemberA,
                        rows::Role::MemberB,
                    ][i],
                    guid: context.bindings[i].guid,
                    name: context.bindings[i].name.clone(),
                    key: rows::RowKey {
                        luid: identity.proof.luid,
                        index: identity.proof.index,
                    },
                    address: address.octets(),
                };
                if identity.scope != context.intent.scope || identity.proof.guid != binding.guid {
                    return Err(wintun::Error::Conflict);
                }
                let actual = rows::native::read_original_snapshot(&binding).map_err(denied)?;
                if actual.interface.policy.weak_host_send
                    || actual.interface.policy.weak_host_receive
                    || actual.interface.policy.forwarding
                    || actual.interface.policy.advertising
                    || (i > 0 && actual.address.is_some())
                {
                    return Err(wintun::Error::Conflict);
                }
                if i == 0 {
                    let saved = rows::Record::decode(
                        &runtime
                            .record(context, RecordKind::CarrierRows)
                            .map_err(denied)?,
                    )
                    .map_err(denied)?;
                    if saved.phase != rows::Phase::Captured || saved.pending.is_some() {
                        return Err(wintun::Error::Conflict);
                    }
                    super::super::member_carrier_coordinator_rows::compare(
                        &binding,
                        &saved,
                        &actual,
                        super::super::member_carrier_coordinator_rows::Stage::Observe,
                    )
                    .map_err(denied)?;
                }
            }
            Ok(())
        }
    }
    fn guard_denied<E>(_: E) -> crate::member_carrier_guard::GuardError {
        crate::member_carrier_guard::GuardError::Conflict
    }
    impl crate::windows::member_carrier_guard::BindingAttestor for InitialBaseAttestor {
        fn observe(
            &mut self,
            scope: &nelomai_client_tunnel::redundancy::SessionScope,
        ) -> crate::member_carrier_guard::Result<crate::windows::member_carrier_guard::Bindings>
        {
            let failed = self.failed;
            self.failed = true;
            if failed || *scope != self.context.intent.scope {
                return Err(guard_denied(()));
            }
            let result = self.inspect(|window| {
                window.inspect(|bindings| {
                    Self::verify_unmodified_rows(&self.context, &self.runtime, bindings)?;
                    Ok(crate::windows::member_carrier_guard::Bindings {
                        scope: bindings.scope.clone(),
                        carrier: bindings.carrier.clone(),
                        egress: bindings.egress.clone(),
                    })
                })
            })?;
            self.failed = false;
            Ok(result)
        }
        fn authorize<N: crate::windows::member_carrier_guard::NativeApi>(
            &mut self,
            kind: crate::member_carrier_guard::SessionKind,
            expected: &crate::member_carrier_guard::Model,
            desired: &crate::member_carrier_guard::Model,
            locked: &mut crate::windows::member_carrier_guard::LockedWfpRead<'_, N>,
        ) -> crate::member_carrier_guard::Result<()> {
            let failed = self.failed;
            self.failed = true;
            if failed {
                return Err(guard_denied(()));
            }
            self.inspect(|window| {
                window.inspect(|bindings| {
                    Self::verify_unmodified_rows(&self.context, &self.runtime, bindings)?;
                    validate_initial_guard_base(
                        &self.context,
                        &self.expected,
                        kind,
                        expected,
                        desired,
                        bindings.carrier.as_ref().ok_or(wintun::Error::Conflict)?,
                        &bindings.egress,
                    )
                    .map_err(denied)?;
                    if locked.snapshot(bindings).map_err(denied)? != expected.expected {
                        return Err(wintun::Error::Conflict);
                    }
                    Self::verify_unmodified_rows(&self.context, &self.runtime, bindings)?;
                    if locked.snapshot(bindings).map_err(denied)? != expected.expected {
                        return Err(wintun::Error::Conflict);
                    }
                    Ok(())
                })
            })?;
            self.failed = false;
            Ok(())
        }
    }

    /// First addressless member only, before any bases, weak rows or network
    /// effects. Reserve/detach/Stop require separate full-coordinator gates.
    pub(crate) struct PrimaryMemberGate {
        context: receipts::Context,
        runtime: RuntimeRead,
        source: Rc<crate::windows::member_carrier_runtime::native::NativeSourceRead>,
        pair: Rc<NativePairIntentRead>,
        expected: PairRecord,
        supervisor: Rc<NativeDeadline>,
        deadline: NativeDeadlineReadPin,
        cancelled: Arc<AtomicBool>,
        absence: RefCell<ScopedGuardAbsence<Wfp>>,
        failed: bool,
    }
    pub(crate) struct PrimaryMemberInputs {
        pub context: receipts::Context,
        pub runtime: RuntimeRead,
        pub source: Rc<crate::windows::member_carrier_runtime::native::NativeSourceRead>,
        pub pair: Rc<NativePairIntentRead>,
        pub expected: PairRecord,
        pub supervisor: Rc<NativeDeadline>,
        pub cancelled: Arc<AtomicBool>,
    }
    impl PrimaryMemberGate {
        pub(crate) fn open(input: PrimaryMemberInputs) -> Result<Self> {
            let target = match input.expected.pending {
                Some(pair::Effect::MemberStart(target)) => target,
                _ => return Err(Error::Conflict),
            };
            let deadline = input.supervisor.read_pin().map_err(|_| Error::Conflict)?;
            deadline
                .verify_runtime_call(&input.supervisor, &input.runtime, &input.context)
                .map_err(|_| Error::Conflict)?;
            if !input.pair.matches_runtime(&input.runtime)
                || input.cancelled.load(Ordering::Acquire)
            {
                return Err(Error::Conflict);
            }
            let absence = input
                .pair
                .inspect_effect(
                    &input.runtime,
                    &input.supervisor,
                    &input.expected,
                    pair::Effect::MemberStart(target),
                    |_| {
                        ScopedGuardAbsence::open(input.context.intent.scope.clone())
                            .map_err(io_denied)
                    },
                )
                .map_err(|_| Error::Conflict)?;
            Ok(Self {
                context: input.context,
                runtime: input.runtime,
                source: input.source,
                pair: input.pair,
                expected: input.expected,
                supervisor: input.supervisor,
                deadline,
                cancelled: input.cancelled,
                absence: RefCell::new(absence),
                failed: false,
            })
        }
        fn continuity(&self) -> wintun::Result<()> {
            if self.cancelled.load(Ordering::Acquire) || !self.pair.matches_runtime(&self.runtime) {
                return Err(wintun::Error::Conflict);
            }
            self.deadline
                .verify_runtime_call(&self.supervisor, &self.runtime, &self.context)
                .map_err(denied)?;
            self.runtime.verify(&self.context).map_err(denied)?;
            if !self.runtime.fresh(&self.context).map_err(denied)? {
                return Err(wintun::Error::Conflict);
            }
            Ok(())
        }
        fn precreation_rows(
            &self,
            intent: &crate::member_owner::Intent,
            bindings: &crate::windows::member_carrier_guard::Bindings,
        ) -> wintun::Result<()> {
            use nelomai_contracts::dispatcher::TunnelSlot;
            let index = match intent.slot {
                TunnelSlot::A => 1,
                TunnelSlot::B => 2,
            };
            let native = receipts::Record::decode(
                &self
                    .runtime
                    .record(&self.context, RecordKind::NativeCarrierReceipts)
                    .map_err(denied)?,
            )
            .map_err(denied)?;
            receipts::validate_record(&native).map_err(denied)?;
            if native.context != self.context
                || native.generation == 0
                || native.phase != Phase::Preparing
            {
                return Err(wintun::Error::Conflict);
            }
            for (i, key) in native.keys.iter().enumerate() {
                if i == 0 || i == index {
                    if key.phase != KeyPhase::Disabled
                        || !key.new_key_ack
                        || key.current != Value::DwordZero
                        || key.pending.is_some()
                    {
                        return Err(wintun::Error::Conflict);
                    }
                } else if key.phase != KeyPhase::Unstarted
                    || key.new_key_ack
                    || key.current != Value::Absent
                    || key.pending.is_some()
                {
                    return Err(wintun::Error::Conflict);
                }
            }
            if self
                .runtime
                .optional_record(&self.context, RecordKind::CarrierGuard)
                .map_err(denied)?
                .is_some()
            {
                return Err(wintun::Error::Conflict);
            }
            InitialBaseAttestor::verify_unmodified_rows(&self.context, &self.runtime, bindings)
        }
    }
    // SAFETY: the controller separately holds signed member input, the actual
    // disabled A/B NEW-HKEY receipt and original MemberOwner. This gate checks
    // actual C create/address pins, whole mixed native SDK, current original
    // Pair Calling and all 49 scoped BFE objects twice around each authorization.
    // It grants only primary creation before other resources exist; it never
    // substitutes equal journal data for an original handle or grants Stop.
    unsafe impl crate::windows::member_carrier_member_controller::native::NativeMemberLifecycle
        for PrimaryMemberGate
    {
        fn authorize_start(
            &mut self,
            context: &receipts::Context,
            expected: &PairRecord,
            intent: &crate::member_owner::Intent,
            window: &crate::windows::member_carrier_runtime::native::NativeBindingsWindow<'_>,
        ) -> Result<()> {
            let failed = self.failed;
            self.failed = true;
            if failed
                || context != &self.context
                || expected != &self.expected
                || !window.matches_source(&self.source)
                || !window.matches_runtime(&self.runtime)
            {
                return Err(Error::Conflict);
            }
            let effect = self.expected.pending.ok_or(Error::Conflict)?;
            self.continuity().map_err(|_| Error::Conflict)?;
            self.pair
                .inspect_effect(
                    &self.runtime,
                    &self.supervisor,
                    &self.expected,
                    effect,
                    |_| {
                        window
                            .inspect(|bindings| {
                                validate_primary_member_start(
                                    &self.context,
                                    &self.expected,
                                    intent,
                                    bindings.carrier.as_ref().ok_or(wintun::Error::Conflict)?,
                                    &bindings.egress,
                                )
                                .map_err(denied)?;
                                self.precreation_rows(intent, bindings)?;
                                self.absence
                                    .try_borrow_mut()
                                    .map_err(denied)?
                                    .verify(&self.context.intent.scope)
                                    .map_err(denied)?;
                                self.precreation_rows(intent, bindings)?;
                                self.absence
                                    .try_borrow_mut()
                                    .map_err(denied)?
                                    .verify(&self.context.intent.scope)
                                    .map_err(denied)?;
                                self.continuity()
                            })
                            .map_err(io_denied)
                    },
                )
                .map_err(|_| Error::Conflict)?;
            self.continuity().map_err(|_| Error::Conflict)?;
            self.failed = false;
            Ok(())
        }
        fn authorize_stop(
            &mut self,
            _: &receipts::Context,
            _: &PairRecord,
            _: &crate::member_owner::Intent,
            _: &crate::windows::member_carrier_runtime::native::NativeBindingsWindow<'_>,
        ) -> Result<()> {
            self.failed = true;
            Err(Error::Conflict)
        }
        fn authorize_retire(
            &mut self,
            _: &receipts::Context,
            _: &PairRecord,
            _: &crate::member_owner::Intent,
            _: &crate::windows::member_carrier_runtime::native::NativeBindingsWindow<'_>,
        ) -> Result<()> {
            // Bootstrap-only G has none of the original target closure,
            // network, weak-row or held-probe obligations required by Retire.
            self.failed = true;
            Err(Error::Conflict)
        }
        fn authorize_partial_stop(
            &mut self,
            _: &receipts::Context,
            _: &PairRecord,
            _: &crate::member_owner::Intent,
            _: &crate::windows::member_carrier_member_controller::native::Pending,
            _: Option<
                &std::rc::Rc<
                    crate::windows::member_carrier_member_controller::native::PartialCleanup,
                >,
            >,
        ) -> Result<()> {
            // This narrow first-member gate owns neither rows/network nor the
            // original bases/held-port cleanup facts. Unknown Start cannot turn
            // a factual pending-owner pin into Stop authorization.
            self.failed = true;
            Err(Error::Conflict)
        }
        fn authorize_rebind(
            &mut self,
            _: &receipts::Context,
            _: &PairRecord,
            _: &crate::member_owner::Intent,
            _: &crate::windows::member_carrier_runtime::native::NativeBindingsWindow<'_>,
        ) -> Result<()> {
            // Bootstrap-only G does not retain the original live network/weak
            // rows/static bases or retired probe ACKs needed for held-SCM
            // restart. Only the full concrete NativeMemberGate can grant it.
            self.failed = true;
            Err(Error::Conflict)
        }
    }

    /// Concrete CarrierReady sub-gate, NOT a selected factory or a permission
    /// for subsequent member/weak/network/permit/data/cleanup operations. Those
    /// stages are explicitly refused until their actual coordinator is joined.
    /// Only SAME bootstrap originals can construct this native implementation.
    /// Shared with the caller's actual C root BEFORE native construction. It
    /// retains the mandatory replacement even on failed/partial registration.
    pub(crate) struct CarrierGateUpgrade {
        slot: LifecycleUpgrade<Box<dyn NativeLifecycleGate>>,
        original_session: RefCell<Option<wintun::SessionEndRead>>,
        session_invalid: std::cell::Cell<bool>,
        session_handed: std::cell::Cell<bool>,
        retired: OriginalReadCapture<RetiredCarrierRead>,
        unpublished: OriginalReadCapture<UnpublishedClosedCarrierRead>,
    }
    impl CarrierGateUpgrade {
        pub(crate) fn new(revoked: Rc<std::cell::Cell<bool>>) -> Self {
            Self {
                slot: LifecycleUpgrade::new(revoked.clone()),
                original_session: RefCell::new(None),
                session_invalid: std::cell::Cell::new(false),
                session_handed: std::cell::Cell::new(false),
                retired: OriginalReadCapture::new(revoked.clone()),
                unpublished: OriginalReadCapture::new(revoked),
            }
        }
        pub(crate) fn attempted(&self) -> bool {
            self.slot.attempted.get()
        }
        pub(crate) fn retire_forward(&self) {
            self.slot.revoked.set(true);
        }
        pub(crate) fn require_forward_registration(&self) -> wintun::Result<()> {
            if !self.slot.completed.get() || self.slot.revoked.get() || !self.session_handed.get() {
                return Err(wintun::Error::Retired);
            }
            Ok(())
        }
        pub(crate) fn retired_pin(&self) -> Result<Rc<RetiredCarrierRead>> {
            self.retired.pin()
        }
        pub(crate) fn unpublished_pin(&self) -> Result<Rc<UnpublishedClosedCarrierRead>> {
            self.unpublished.pin()
        }
        pub(crate) fn confirm_retired(&self, original: &Rc<RetiredCarrierRead>) -> Result<()> {
            self.retired.confirm(original)
        }
        fn retain_retired_carrier(&self, original: &Rc<RetiredCarrierRead>) -> wintun::Result<()> {
            // Called by THIS actual Authority at its close ACK, BEFORE any
            // AfterClose postflight. Root owns this slot strongly already.
            // Never inspect/borrow Authority/Source here: Authority is borrowed.
            self.slot
                .retain_original_read(&self.retired, original, |gate, pin| {
                    // Mandatory full delegate roots only a Weak of THIS same
                    // actor Rc before fallible registration/AfterClose reads.
                    gate.retain_retired_carrier(pin)
                        .map_err(|_| Error::Conflict)
                })
                .map_err(denied)?;
            if self.unpublished.pin().is_ok() {
                return Err(wintun::Error::Conflict);
            }
            Ok(())
        }
        fn retain_unpublished_closed_carrier(
            &self,
            original: &Rc<UnpublishedClosedCarrierRead>,
        ) -> wintun::Result<()> {
            // Authority/Root already own this actual close pin. Keep it before
            // the mandatory full delegate can reject the impossible lane.
            self.slot
                .retain_original_read(&self.unpublished, original, |gate, pin| {
                    gate.retain_unpublished_closed_carrier(pin)
                        .map_err(|_| Error::Conflict)
                })
                .map_err(denied)?;
            if self.retired.pin().is_ok() {
                return Err(wintun::Error::Conflict);
            }
            Ok(())
        }
        fn retain_session(&self, original: &wintun::SessionEndRead) {
            if self.original_session.borrow().is_some() || self.session_invalid.get() {
                self.session_invalid.set(true);
                self.retire_forward();
                return;
            }
            // Actual native constructor pin, retained BEFORE validation and
            // BEFORE native Start; later handoff uses this SAME Rc state.
            *self.original_session.borrow_mut() = Some(original.read_pin());
            if original.verify_never_started().is_err() {
                self.session_invalid.set(true);
                self.retire_forward();
            }
        }
        pub(crate) fn register(
            &self,
            gate: Box<dyn NativeLifecycleGate>,
            postflight: impl FnOnce(&mut dyn NativeLifecycleGate) -> wintun::Result<()>,
        ) -> wintun::Result<()> {
            self.slot
                .register(gate, |gate| {
                    if self.session_invalid.get() {
                        return Err(Error::Pending);
                    }
                    let session = self.original_session.borrow();
                    let original = session.as_ref().ok_or(Error::Pending)?.read_pin();
                    // Mandatory unsafe delegate must retain this actual original
                    // BEFORE its own fallible checks. It is already Live at upgrade;
                    // this is a handoff, not a new NeverStarted registration.
                    gate.retain_original_session(original);
                    self.session_handed.set(true);
                    postflight(gate.as_mut()).map_err(|_| Error::Conflict)
                })
                .map_err(denied)
        }
        fn inspect<T>(
            &self,
            cleanup: bool,
            supervisor: &Rc<NativeDeadline>,
            original: Rc<NativePairIntentRead>,
            expected: &PairRecord,
            effect: bool,
            call: impl FnOnce(&mut dyn NativeLifecycleGate) -> wintun::Result<T>,
        ) -> wintun::Result<T> {
            self.slot
                .inspect(cleanup, |gate| {
                    if (effect && !self.session_handed.get())
                        || !Rc::ptr_eq(gate.supervisor(), supervisor)
                    {
                        return Err(Error::Conflict);
                    }
                    // Every call selects the current OPAQUE original, never a
                    // reconstructed window or an equal cloned/imported Record.
                    gate.select_pair_intent(original, expected)
                        .map_err(|_| Error::Conflict)?;
                    call(gate.as_mut()).map_err(|_| Error::Conflict)
                })
                .map_err(denied)
        }
    }
    pub(crate) struct CarrierReadyGate {
        scope: creators::Scope,
        runtime: RuntimeRead,
        image: OriginalImage,
        originals: creators::Observer<OriginalWintun>,
        members: MemberInventoryRead,
        pair: Rc<NativePairIntentRead>,
        expected: PairRecord,
        source: Rc<WintunSource>,
        supervisor: Rc<NativeDeadline>,
        deadline: NativeDeadlineReadPin,
        cancelled: Arc<AtomicBool>,
        absence: RefCell<ScopedGuardAbsence<Wfp>>,
        session: wintun::OriginalSessionRead,
        original_rows_binding: RefCell<Option<rows::Binding>>,
        closing_selected: bool,
        failed: bool,
        upgrade: Rc<CarrierGateUpgrade>,
    }
    #[derive(PartialEq, Eq)]
    struct Sample {
        native: Vec<u8>,
        rows: Option<Vec<u8>>,
        originals:
            creators::UniverseObservation<crate::windows::member_carrier_provider::Observation>,
        snapshot: Option<rows::Snapshot>,
    }
    fn denied<E>(_: E) -> wintun::Error {
        wintun::Error::Conflict
    }
    fn io_denied<E>(_: E) -> std::io::Error {
        std::io::Error::other("carrier_ready_native_gate")
    }

    impl CarrierReadyGate {
        /// Caller retains assets throughout this fallible READ-only constructor.
        /// Native engine opens are under SAME original CarrierReady Calling;
        /// both new sessions have no objects and confer no owning policy ACK.
        pub(crate) fn open(
            assets: &NativeAssemblyAssets,
            scope: creators::Scope,
        ) -> wintun::Result<Self> {
            Self::open_with_upgrade(
                assets,
                scope,
                Rc::new(CarrierGateUpgrade::new(Rc::new(std::cell::Cell::new(
                    false,
                )))),
            )
        }
        pub(crate) fn open_with_upgrade(
            assets: &NativeAssemblyAssets,
            scope: creators::Scope,
            upgrade: Rc<CarrierGateUpgrade>,
        ) -> wintun::Result<Self> {
            if upgrade.attempted() || upgrade.slot.revoked.get() {
                return Err(wintun::Error::Retired);
            }
            let deadline = assets.supervisor.read_pin().map_err(denied)?;
            deadline
                .verify_runtime_call(&assets.supervisor, &assets.runtime, &scope.context)
                .map_err(denied)?;
            if assets.context != scope.context || assets.cancelled.load(Ordering::Acquire) {
                return Err(wintun::Error::Conflict);
            }
            // Open ONLY inside the authenticated original operation callback;
            // equal Pair bytes cannot mint this actual opaque read capability.
            let absence = assets
                .pair_intent
                .inspect_effect(
                    &assets.runtime,
                    &assets.supervisor,
                    &assets.expected,
                    pair::Effect::CarrierReady,
                    |record| {
                        let native = receipts::Record::decode(
                            &assets
                                .runtime
                                .record(&scope.context, RecordKind::NativeCarrierReceipts)
                                .map_err(io_denied)?,
                        )
                        .map_err(io_denied)?;
                        validate_carrier_ready_pair(&native, record).map_err(io_denied)?;
                        ScopedGuardAbsence::open(scope.context.intent.scope.clone())
                            .map_err(io_denied)
                    },
                )
                .map_err(denied)?;
            Ok(Self {
                runtime: assets.runtime.read_pin().map_err(denied)?,
                image: assets.image.read_pin().map_err(denied)?,
                originals: assets.observer.clone(),
                members: assets.members.read_pin(),
                pair: assets.pair_intent.clone(),
                expected: assets.expected.clone(),
                source: assets.source.clone(),
                supervisor: assets.supervisor.clone(),
                deadline,
                cancelled: assets.cancelled.clone(),
                scope,
                absence: RefCell::new(absence),
                session: wintun::OriginalSessionRead::new(),
                closing_selected: false,
                failed: false,
                original_rows_binding: RefCell::new(None),
                upgrade,
            })
        }
        fn continuity(&self) -> wintun::Result<()> {
            if self.cancelled.load(Ordering::Acquire) {
                return Err(wintun::Error::Cancelled);
            }
            self.deadline
                .verify_runtime_call(&self.supervisor, &self.runtime, &self.scope.context)
                .map_err(denied)?;
            if !self.image.matches_source(&self.source) {
                return Err(wintun::Error::Conflict);
            }
            self.image
                .verify_live_runtime(&self.runtime)
                .map_err(denied)?;
            if !self.runtime.fresh(&self.scope.context).map_err(denied)? {
                return Err(wintun::Error::Conflict);
            }
            self.members
                .matches_original_runtime_image(&self.runtime, &self.image)
                .map_err(denied)?;
            Ok(())
        }
        fn continuity_cleanup(&self) -> wintun::Result<()> {
            if self.cancelled.load(Ordering::Acquire) {
                return Err(wintun::Error::Cancelled);
            }
            self.deadline
                .verify_runtime_call(&self.supervisor, &self.runtime, &self.scope.context)
                .map_err(denied)?;
            if !self.image.matches_source(&self.source) {
                return Err(wintun::Error::Conflict);
            }
            self.runtime.verify(&self.scope.context).map_err(denied)?;
            self.image.verify_runtime(&self.runtime).map_err(denied)?;
            self.members
                .matches_original_runtime_image(&self.runtime, &self.image)
                .map_err(denied)?;
            Ok(())
        }
        fn select(
            &mut self,
            original: Rc<NativePairIntentRead>,
            expected: &PairRecord,
        ) -> wintun::Result<()> {
            if self.upgrade.attempted() {
                let cleanup = expected.phase == pair::Phase::Closing;
                // Retain current opaque Pair before ANY postflight; a failed
                // selection never restores an earlier forward window.
                self.pair = original.clone();
                self.expected = expected.clone();
                if cleanup {
                    self.closing_selected = true;
                    self.failed = true;
                }
                if (!cleanup && (self.failed || self.closing_selected))
                    || !original.matches_runtime(&self.runtime)
                {
                    self.failed = true;
                    self.upgrade.retire_forward();
                    return Err(wintun::Error::Conflict);
                }
                let result = self.upgrade.inspect(
                    cleanup,
                    &self.supervisor,
                    original,
                    expected,
                    false,
                    |_| Ok(()),
                );
                if result.is_err() {
                    self.failed = true;
                }
                return result;
            }
            let was_failed = self.failed;
            self.failed = true;
            validate_operation_selection(&self.scope.context, &self.expected, expected)
                .map_err(denied)?;
            let cleanup = expected.phase == pair::Phase::Closing;
            if !cleanup && (was_failed || self.closing_selected) {
                return Err(wintun::Error::Conflict);
            }
            if !original.matches_runtime(&self.runtime) {
                return Err(wintun::Error::Conflict);
            }
            // Keep the new original window before fallible storage/postflight.
            // Failure never reconstructs the previous forward permission.
            self.pair = original.clone();
            self.expected = expected.clone();
            if cleanup {
                self.closing_selected = true;
                original
                    .inspect_cleanup_effect(
                        &self.runtime,
                        &self.supervisor,
                        expected,
                        expected.stop_stage,
                        |record| {
                            self.continuity_cleanup().map_err(io_denied)?;
                            let native = receipts::Record::decode(
                                &self
                                    .runtime
                                    .record(&self.scope.context, RecordKind::NativeCarrierReceipts)
                                    .map_err(io_denied)?,
                            )
                            .map_err(io_denied)?;
                            if native.context != self.scope.context
                                || native.phase != Phase::Closing
                                || native.generation < self.scope.generation
                                || record != expected
                            {
                                return Err(io_denied(()));
                            }
                            self.continuity_cleanup().map_err(io_denied)
                        },
                    )
                    .map_err(denied)?;
                // Successful cleanup read does NOT clear forward revocation.
            } else {
                original
                    .inspect_effect(
                        &self.runtime,
                        &self.supervisor,
                        expected,
                        pair::Effect::CarrierReady,
                        |record| {
                            self.continuity().map_err(io_denied)?;
                            let native = receipts::Record::decode(
                                &self
                                    .runtime
                                    .record(&self.scope.context, RecordKind::NativeCarrierReceipts)
                                    .map_err(io_denied)?,
                            )
                            .map_err(io_denied)?;
                            validate_carrier_ready_pair(&native, record).map_err(io_denied)?;
                            self.continuity().map_err(io_denied)
                        },
                    )
                    .map_err(denied)?;
                self.failed = false;
            }
            Ok(())
        }
        fn full<T>(
            &mut self,
            cleanup: bool,
            scope: &creators::Scope,
            originals: &creators::Observer<OriginalWintun>,
            call: impl FnOnce(&mut dyn NativeLifecycleGate) -> wintun::Result<T>,
        ) -> wintun::Result<T> {
            if *scope != self.scope
                || !self.originals.same_original_registry(originals)
                || (!cleanup && (self.failed || self.closing_selected))
            {
                self.failed = true;
                self.upgrade.retire_forward();
                return Err(wintun::Error::Conflict);
            }
            let result = self.upgrade.inspect(
                cleanup,
                &self.supervisor,
                self.pair.clone(),
                &self.expected,
                true,
                call,
            );
            if result.is_err() || cleanup {
                self.failed = true;
            }
            result
        }
        fn sample(&self, stage: StartupStage) -> wintun::Result<Sample> {
            self.continuity()?;
            let context = &self.scope.context;
            let [native, network, member_a, member_b, guard, rows]: [Option<Vec<u8>>; 6] = self
                .runtime
                .optional_records(
                    context,
                    &[
                        RecordKind::NativeCarrierReceipts,
                        RecordKind::Network,
                        RecordKind::MemberARows,
                        RecordKind::MemberBRows,
                        RecordKind::CarrierGuard,
                        RecordKind::CarrierRows,
                    ],
                )
                .map_err(denied)?
                .try_into()
                .map_err(denied)?;
            let native = native.ok_or(wintun::Error::Conflict)?;
            let record = receipts::Record::decode(&native).map_err(denied)?;
            // All original members, not a model projection or names-only query.
            if !self.members.read_all().map_err(denied)?.is_empty() {
                return Err(wintun::Error::Conflict);
            }
            let originals = self.originals.observe_all(context).map_err(denied)?;
            let identities = originals
                .originals
                .iter()
                .map(|o| creators::OriginalIdentity {
                    scope: o.scope.clone(),
                    identity: o.identity.clone(),
                })
                .collect::<Vec<_>>();
            validate_startup(&record, &self.scope, stage, &identities).map_err(denied)?;
            if [network, member_a, member_b, guard]
                .iter()
                .any(Option::is_some)
            {
                return Err(wintun::Error::Conflict);
            }
            let snapshot = if let Some(original) = identities.first() {
                let binding = crate::windows::member_carrier_runtime::rows_binding(
                    context,
                    &original.identity,
                )
                .map_err(denied)?;
                let actual = rows::native::read_original_snapshot(&binding).map_err(denied)?;
                if actual.interface.policy.weak_host_send
                    || actual.interface.policy.weak_host_receive
                    || actual.interface.policy.forwarding
                    || actual.interface.policy.advertising
                {
                    return Err(wintun::Error::Conflict);
                }
                if let Some(raw) = &rows {
                    let saved = rows::Record::decode(raw).map_err(denied)?;
                    if saved.binding != binding
                        || saved.phase != rows::Phase::Captured
                        || saved.current.interface.policy != saved.baseline.interface.policy
                        || actual.interface.policy != saved.baseline.interface.policy
                    {
                        return Err(wintun::Error::Conflict);
                    }
                    // Pending creation may have returned natively before its
                    // durable postflight. Reading it grants NO second create.
                    let address_matches = if let Some(pending) = &saved.pending {
                        match &pending.target {
                            rows::Target::Create(policy) => actual
                                .address
                                .as_ref()
                                .is_none_or(|a| a.policy == *policy && a.key == binding.key),
                            _ => false,
                        }
                    } else {
                        rows::same_owned(&actual, &saved.current)
                    };
                    if !address_matches {
                        return Err(wintun::Error::Conflict);
                    }
                    if stage == StartupStage::AddressCreate
                        && (actual.address.is_some()
                            || saved.creation.is_some()
                            || saved.current.address.is_some())
                    {
                        return Err(wintun::Error::Conflict);
                    }
                } else if actual.address.is_some() || stage == StartupStage::AddressCreate {
                    return Err(wintun::Error::Conflict);
                }
                if stage == StartupStage::BeforeSession && rows.is_some() {
                    return Err(wintun::Error::Conflict);
                }
                Some(actual)
            } else {
                if rows.is_some() {
                    return Err(wintun::Error::Conflict);
                }
                None
            };
            self.continuity()?;
            Ok(Sample {
                native,
                rows,
                originals,
                snapshot,
            })
        }
        fn authorize_startup(
            &mut self,
            scope: &creators::Scope,
            stage: StartupStage,
            originals: &creators::Observer<OriginalWintun>,
            row: Option<(&rows::Binding, &rows::Target)>,
        ) -> wintun::Result<()> {
            let was_failed = self.failed;
            self.failed = true;
            if was_failed
                || scope != &self.scope
                || !self.originals.same_original_registry(originals)
            {
                return Err(wintun::Error::Conflict);
            }
            let pair = self.pair.clone();
            #[cfg(test)]
            if stage == StartupStage::Resolve {
                crate::windows::member_carrier_factory_test_os::trace_step(
                    "C Resolve G original Pair inspection",
                );
            }
            pair.inspect_effect(
                &self.runtime,
                &self.supervisor,
                &self.expected,
                pair::Effect::CarrierReady,
                |actual_pair| {
                    let before = self.sample(stage).map_err(io_denied)?;
                    #[cfg(test)]
                    if stage == StartupStage::Resolve {
                        crate::windows::member_carrier_factory_test_os::trace_step(
                            "C Resolve G first complete sample accepted",
                        );
                    }
                    let native = receipts::Record::decode(&before.native).map_err(io_denied)?;
                    validate_carrier_ready_pair(&native, actual_pair).map_err(io_denied)?;
                    if let Some((binding, target)) = row {
                        let raw = before.rows.as_ref().ok_or_else(|| io_denied(()))?;
                        let saved = rows::Record::decode(raw).map_err(io_denied)?;
                        if saved.binding != *binding
                            || !matches!(target, rows::Target::Create(_))
                            || saved.pending.as_ref().is_none_or(|p| p.target != *target)
                        {
                            return Err(io_denied(()));
                        }
                    }
                    self.absence
                        .try_borrow_mut()
                        .map_err(io_denied)?
                        .verify(&scope.context.intent.scope)
                        .map_err(io_denied)?;
                    if before != self.sample(stage).map_err(io_denied)? {
                        return Err(io_denied(()));
                    }
                    #[cfg(test)]
                    if stage == StartupStage::Resolve {
                        crate::windows::member_carrier_factory_test_os::trace_step(
                            "C Resolve G second complete sample accepted",
                        );
                    }
                    self.absence
                        .try_borrow_mut()
                        .map_err(io_denied)?
                        .verify(&scope.context.intent.scope)
                        .map_err(io_denied)?;
                    self.continuity().map_err(io_denied)
                },
            )
            .map_err(denied)?;
            self.failed = false;
            Ok(())
        }
        fn sample_closing(&self, stage: ClosingStage) -> wintun::Result<Sample> {
            self.continuity_cleanup()?;
            let context = &self.scope.context;
            let [native, network, member_a, member_b, guard, rows]: [Option<Vec<u8>>; 6] = self
                .runtime
                .optional_records(
                    context,
                    &[
                        RecordKind::NativeCarrierReceipts,
                        RecordKind::Network,
                        RecordKind::MemberARows,
                        RecordKind::MemberBRows,
                        RecordKind::CarrierGuard,
                        RecordKind::CarrierRows,
                    ],
                )
                .map_err(denied)?
                .try_into()
                .map_err(denied)?;
            let native = native.ok_or(wintun::Error::Conflict)?;
            let record = receipts::Record::decode(&native).map_err(denied)?;
            let originals = self
                .members
                .inspect_closing_full(context, &self.runtime, &self.image, |members| {
                    if !members.is_empty() {
                        return Err(Error::Conflict);
                    }
                    self.originals
                        .observe_all_for_cleanup(context)
                        .map_err(|_| Error::Conflict)
                })
                .map_err(denied)?;
            let identities = originals
                .originals
                .iter()
                .map(|o| creators::OriginalIdentity {
                    scope: o.scope.clone(),
                    identity: o.identity.clone(),
                })
                .collect::<Vec<_>>();
            validate_c_only_closing(&record, &self.scope, &self.expected, stage, &identities)
                .map_err(denied)?;
            if [network, member_a, member_b, guard]
                .iter()
                .any(Option::is_some)
            {
                return Err(wintun::Error::Conflict);
            }
            let snapshot = if let Some(original) = identities.first() {
                let binding = crate::windows::member_carrier_runtime::rows_binding(
                    context,
                    &original.identity,
                )
                .map_err(denied)?;
                let mut retained = self
                    .original_rows_binding
                    .try_borrow_mut()
                    .map_err(denied)?;
                if retained.as_ref().is_some_and(|old| old != &binding) {
                    return Err(wintun::Error::Conflict);
                }
                *retained = Some(binding.clone());
                drop(retained);
                let actual = rows::native::read_original_snapshot(&binding).map_err(denied)?;
                if let Some(raw) = &rows {
                    let saved = rows::Record::decode(raw).map_err(denied)?;
                    let row_stage = match stage {
                        ClosingStage::Observe => {
                            super::super::member_carrier_coordinator_rows::Stage::Observe
                        }
                        ClosingStage::AddressDelete => {
                            super::super::member_carrier_coordinator_rows::Stage::Delete
                        }
                        _ => super::super::member_carrier_coordinator_rows::Stage::Stopped,
                    };
                    super::super::member_carrier_coordinator_rows::compare(
                        &binding, &saved, &actual, row_stage,
                    )
                    .map_err(denied)?;
                } else if stage == ClosingStage::AddressDelete
                    || actual.address.is_some()
                    || actual.interface.policy.weak_host_send
                    || actual.interface.policy.weak_host_receive
                    || actual.interface.policy.forwarding
                    || actual.interface.policy.advertising
                {
                    return Err(wintun::Error::Conflict);
                }
                Some(actual)
            } else {
                if let Some(raw) = &rows {
                    let saved = rows::Record::decode(raw).map_err(denied)?;
                    let retained = self.original_rows_binding.try_borrow().map_err(denied)?;
                    let binding = retained.as_ref().ok_or(wintun::Error::Conflict)?;
                    // Historical policy comparison ONLY. No historical index is
                    // queried or treated as a live adapter. Actual original
                    // Close ACK and full SDK universe absence are independent.
                    super::super::member_carrier_coordinator_rows::compare(
                        binding,
                        &saved,
                        &saved.current,
                        super::super::member_carrier_coordinator_rows::Stage::Stopped,
                    )
                    .map_err(denied)?;
                }
                None
            };
            self.continuity_cleanup()?;
            Ok(Sample {
                native,
                rows,
                originals,
                snapshot,
            })
        }
        fn verify_closing_session(&self, stage: ClosingStage) -> wintun::Result<()> {
            match stage {
                ClosingStage::SessionEnd => self.session.endable(),
                ClosingStage::CarrierClose | ClosingStage::AfterClose => {
                    self.session.no_live_session()
                }
                _ => Ok(()),
            }
        }
        fn authorize_closing(
            &mut self,
            scope: &creators::Scope,
            stage: ClosingStage,
            originals: &creators::Observer<OriginalWintun>,
            row: Option<(&rows::Binding, &rows::Target)>,
        ) -> wintun::Result<()> {
            self.failed = true; // cleanup never resurrects forward permission
            if !self.closing_selected
                || scope != &self.scope
                || !self.originals.same_original_registry(originals)
            {
                return Err(wintun::Error::Conflict);
            }
            let pair = self.pair.clone();
            pair.inspect_cleanup_effect(
                &self.runtime,
                &self.supervisor,
                &self.expected,
                self.expected.stop_stage,
                |_| {
                    self.verify_closing_session(stage).map_err(io_denied)?;
                    let before = self.sample_closing(stage).map_err(io_denied)?;
                    if let Some((binding, target)) = row {
                        let saved = rows::Record::decode(
                            before.rows.as_ref().ok_or_else(|| io_denied(()))?,
                        )
                        .map_err(io_denied)?;
                        if stage != ClosingStage::AddressDelete
                            || saved.binding != *binding
                            || *target != rows::Target::Delete
                            || saved.pending.as_ref().is_none_or(|p| p.target != *target)
                        {
                            return Err(io_denied(()));
                        }
                    }
                    self.absence
                        .try_borrow_mut()
                        .map_err(io_denied)?
                        .verify(&scope.context.intent.scope)
                        .map_err(io_denied)?;
                    if before != self.sample_closing(stage).map_err(io_denied)? {
                        return Err(io_denied(()));
                    }
                    self.absence
                        .try_borrow_mut()
                        .map_err(io_denied)?
                        .verify(&scope.context.intent.scope)
                        .map_err(io_denied)?;
                    self.verify_closing_session(stage).map_err(io_denied)?;
                    self.continuity_cleanup().map_err(io_denied)
                },
            )
            .map_err(denied)?;
            Ok(())
        }
        fn authorize_unpublished_after_close(
            &mut self,
            scope: &creators::Scope,
            originals: &creators::Observer<OriginalWintun>,
        ) -> wintun::Result<()> {
            self.failed = true;
            if self.upgrade.attempted()
                || !self.closing_selected
                || scope != &self.scope
                || !self.originals.same_original_registry(originals)
                || self.upgrade.retired.pin().is_ok()
            {
                return Err(wintun::Error::Conflict);
            }
            self.upgrade
                .unpublished
                .require_registered()
                .map_err(denied)?;
            let original = self.upgrade.unpublished_pin().map_err(denied)?;
            let pair = self.pair.clone();
            pair.inspect_cleanup_effect(
                &self.runtime,
                &self.supervisor,
                &self.expected,
                8,
                |expected| {
                    let sample = || -> wintun::Result<Vec<u8>> {
                        self.continuity_cleanup()?;
                        self.session.no_live_session()?;
                        let bytes = self
                            .runtime
                            .record(&scope.context, RecordKind::NativeCarrierReceipts)
                            .map_err(denied)?;
                        let native = receipts::Record::decode(&bytes).map_err(denied)?;
                        validate_unpublished_after_close(&native, scope, expected)
                            .map_err(denied)?;
                        for kind in [
                            RecordKind::Network,
                            RecordKind::MemberARows,
                            RecordKind::MemberBRows,
                            RecordKind::CarrierGuard,
                            RecordKind::CarrierRows,
                        ] {
                            if self
                                .runtime
                                .optional_record(&scope.context, kind)
                                .map_err(denied)?
                                .is_some()
                            {
                                return Err(wintun::Error::Conflict);
                            }
                        }
                        Ok(bytes)
                    };
                    let before = sample().map_err(io_denied)?;
                    // SAME original raw Create ACK + once-close outcome and
                    // full SDK absence, without Source/provider/history data.
                    original
                        .inspect(|| {
                            self.absence
                                .try_borrow_mut()
                                .map_err(denied)?
                                .verify(&scope.context.intent.scope)
                                .map_err(denied)?;
                            if sample()? != before {
                                return Err(wintun::Error::Conflict);
                            }
                            self.absence
                                .try_borrow_mut()
                                .map_err(denied)?
                                .verify(&scope.context.intent.scope)
                                .map_err(denied)?;
                            sample().and_then(|after| {
                                if after == before {
                                    Ok(())
                                } else {
                                    Err(wintun::Error::Conflict)
                                }
                            })
                        })
                        .map_err(io_denied)
                },
            )
            .map_err(denied)
        }
    }
    // SAFETY: exact CarrierReady original Pair ACK, original Runtime/KeyLock,
    // full SAME original C/member registry + SDK rows, native 49-key absence,
    // actual cancellation and SAME Calling hard watchdog bracket EACH allowed
    // bootstrap effect. Bootstrap Closing is limited to the original C-only
    // receipts. After a one-shot caller-rooted upgrade ALL later operations
    // require the retained unsafe full-resource delegate with THIS original
    // session/supervisor/registry and each current opaque Pair. Failed upgrade
    // never falls back to bootstrap or restores forward use. Registration and
    // comparisons supply no effect grant; product factory remains unselected.
    unsafe impl NativeLifecycleGate for CarrierReadyGate {
        fn retain_unpublished_closed_carrier(
            &mut self,
            original: &Rc<UnpublishedClosedCarrierRead>,
        ) -> wintun::Result<()> {
            self.failed = true;
            self.upgrade.retain_unpublished_closed_carrier(original)
        }
        fn retain_retired_carrier(
            &mut self,
            original: &Rc<RetiredCarrierRead>,
        ) -> wintun::Result<()> {
            self.failed = true; // close receipt can never revive bootstrap
            self.upgrade.retain_retired_carrier(original)
        }
        fn retain_original_session(&mut self, original: wintun::SessionEndRead) {
            self.upgrade.retain_session(&original);
            if self.upgrade.session_invalid.get() {
                self.failed = true;
            }
            self.session.retain(original);
        }
        fn select_pair_intent(
            &mut self,
            original: Rc<NativePairIntentRead>,
            expected: &PairRecord,
        ) -> wintun::Result<()> {
            self.select(original, expected)
        }
        fn supervisor(&self) -> &Rc<NativeDeadline> {
            &self.supervisor
        }
        fn authorize(
            &mut self,
            scope: &creators::Scope,
            stage: Stage,
            originals: &creators::Observer<OriginalWintun>,
        ) -> wintun::Result<()> {
            if self.upgrade.attempted() {
                if stage == Stage::AfterClose {
                    // Missing/failed weak registration is no successful close
                    // postflight. The full gate MUST also verify actual facts.
                    self.upgrade.retired.require_registered().map_err(denied)?;
                }
                let cleanup = matches!(
                    stage,
                    Stage::CleanupObserve
                        | Stage::BeforeEnd
                        | Stage::BeforeClose
                        | Stage::AfterClose
                );
                return self.full(cleanup, scope, originals, |gate| {
                    gate.authorize(scope, stage, originals)
                });
            }
            if stage == Stage::AfterClose && self.upgrade.unpublished.pin().is_ok() {
                return self.authorize_unpublished_after_close(scope, originals);
            }
            let closing = match stage {
                Stage::CleanupObserve => Some(ClosingStage::Observe),
                Stage::BeforeEnd => Some(ClosingStage::SessionEnd),
                Stage::BeforeClose => Some(ClosingStage::CarrierClose),
                Stage::AfterClose => Some(ClosingStage::AfterClose),
                _ => None,
            };
            if let Some(stage) = closing {
                return self.authorize_closing(scope, stage, originals, None);
            }
            let stage = match stage {
                Stage::Resolve => StartupStage::Resolve,
                Stage::Observe => StartupStage::Observe,
                Stage::BeforeCreate => StartupStage::BeforeCreate,
                Stage::BeforeSession => StartupStage::BeforeSession,
                Stage::BeforeDrain => StartupStage::BeforeDrain,
                _ => {
                    self.failed = true;
                    return Err(wintun::Error::Conflict);
                }
            };
            self.authorize_startup(scope, stage, originals, None)
        }
        fn authorize_rows(
            &mut self,
            scope: &creators::Scope,
            binding: &rows::Binding,
            target: &rows::Target,
            originals: &creators::Observer<OriginalWintun>,
        ) -> wintun::Result<()> {
            if self.upgrade.attempted() {
                let cleanup = self.expected.phase == pair::Phase::Closing;
                return self.full(cleanup, scope, originals, |gate| {
                    gate.authorize_rows(scope, binding, target, originals)
                });
            }
            if self.closing_selected {
                return self.authorize_closing(
                    scope,
                    ClosingStage::AddressDelete,
                    originals,
                    Some((binding, target)),
                );
            }
            self.authorize_startup(
                scope,
                StartupStage::AddressCreate,
                originals,
                Some((binding, target)),
            )
        }
        fn authorize_member_rows(
            &mut self,
            scope: &creators::Scope,
            binding: &rows::Binding,
            target: &rows::Target,
            originals: &creators::Observer<OriginalWintun>,
            members: &MemberInventoryRead,
        ) -> wintun::Result<()> {
            if self.upgrade.attempted() {
                let cleanup = self.expected.phase == pair::Phase::Closing;
                return self.full(cleanup, scope, originals, |gate| {
                    gate.authorize_member_rows(scope, binding, target, originals, members)
                });
            }
            self.failed = true;
            Err(wintun::Error::Conflict)
        }
    }
}

#[cfg(test)]
#[path = "member_carrier_coordinator_tests.rs"]
mod tests;
