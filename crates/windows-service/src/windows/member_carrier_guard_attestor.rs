//! Original-window guard transaction attestation. Product factory stays off.
#![allow(dead_code)]

#[cfg(not(windows))]
use crate::member_carrier_members as original_members;
#[cfg(not(windows))]
use crate::member_carrier_terminal_release as terminal_release;
#[cfg(windows)]
use crate::windows::member_carrier_members as original_members;
#[cfg(windows)]
use crate::windows::member_carrier_terminal_release as terminal_release;
use crate::{
    member_carrier_guard as policy, member_carrier_native_ownership::Context,
    member_carrier_pair as pair,
};
use policy::{Carrier, GuardError, Identity, Model, Result, SessionKind, Snapshot};
use std::cell::Cell;

struct BindingFacts<'a> {
    scope: &'a nelomai_client_tunnel::redundancy::SessionScope,
    carrier: Option<&'a Carrier>,
    egress: [Option<&'a Identity>; 2],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowChannel {
    Source,
    Closing,
    Retired,
}
/// Separate final factual lane. Empty models/serialized records do not grant
/// any engine close or destructor permission; the native caller must ALSO
/// authenticate the same opaque Pair, Retired lease, Runtime and Calling.
fn compare_terminal_read(context: &Context, record: &pair::Record) -> Result<()> {
    terminal_release::compare_terminal(context, record).map_err(|_| GuardError::Conflict)
}
fn compare_terminal_bindings(
    context: &Context,
    record: &pair::Record,
    actual: &BindingFacts<'_>,
    history: &[original_members::ClosedMemberBinding],
) -> Result<()> {
    compare_terminal_read(context, record)?;
    let carrier = actual.carrier.ok_or(GuardError::Conflict)?;
    if actual.scope != &record.scope
        || carrier.identity.scope != record.scope
        || carrier.identity.proof.guid != context.bindings[0].guid
        || carrier.sources
            != context
                .intent
                .addresses
                .iter()
                .map(|a| a.addr())
                .collect::<Vec<_>>()
    {
        return Err(GuardError::Conflict);
    }
    let mut seen = [false; 2];
    for closed in history {
        closed
            .comparison_provider(context)
            .map_err(|_| GuardError::Conflict)?;
        let index = match closed.intent.slot {
            nelomai_contracts::dispatcher::TunnelSlot::A => 0,
            nelomai_contracts::dispatcher::TunnelSlot::B => 1,
        };
        let identity = actual.egress[index].ok_or(GuardError::Conflict)?;
        if seen[index] || identity.scope != record.scope || identity.proof != closed.proof.interface
        {
            return Err(GuardError::Conflict);
        }
        seen[index] = true;
    }
    if actual
        .egress
        .iter()
        .zip(seen)
        .any(|(identity, seen)| identity.is_some() != seen)
    {
        return Err(GuardError::Conflict);
    }
    // Validate historical comparison identities, NEVER pass them as live SDK
    // inputs or adopt them as guard ownership.
    policy::validate_factual_bindings(&record.scope, Some(carrier), actual.egress)?;
    Ok(())
}
fn compare_retired_read(context: &Context, record: &pair::Record) -> Result<()> {
    compare_pair(context, record)?;
    if record.phase != pair::Phase::Closing
        || record.active.is_some()
        || record.operation.is_some()
        || record.guard.permits
    {
        return Err(GuardError::Conflict);
    }
    compare_model(record, &record.guard)?;
    match (record.stop_stage, record.pending) {
        (8, Some(pair::Effect::CarrierClose)) if record.pending_guard.is_none() => Ok(()),
        (9, Some(pair::Effect::NativeEmpty)) if record.pending_guard.is_none() => Ok(()),
        (10, Some(pair::Effect::Guard)) => {
            let Some(plan) = record.pending_guard.as_ref() else {
                return Ok(());
            };
            plan.validate()?;
            let empty = Model::empty(record.scope.clone())?;
            if plan.desired != empty || plan.expected.permits {
                return Err(GuardError::Conflict);
            }
            let mut before = plan.expected.clone();
            let mut known = record.guard == before;
            for target in [&plan.withdrawn, &plan.base, &plan.desired] {
                compare_model(record, target)?;
                if target.permits {
                    return Err(GuardError::Conflict);
                }
                before = target.inherit_sublayer_weight(&before)?;
                known |= record.guard == before;
            }
            compare_model(record, &plan.expected)?;
            if !known {
                return Err(GuardError::Conflict);
            }
            Ok(())
        }
        (11, Some(pair::Effect::RestoreKeys)) | (12, Some(pair::Effect::FullEmpty))
            if record.pending_guard.is_none()
                && record.guard == Model::empty(record.scope.clone())? =>
        {
            Ok(())
        }
        _ => Err(GuardError::Conflict),
    }
}
fn compare_retired_removal(
    context: &Context,
    record: &pair::Record,
    kind: SessionKind,
    expected: &Model,
    desired: &Model,
) -> Result<ExchangeEdge> {
    compare_retired_read(context, record)?;
    if record.stop_stage != 10
        || kind != SessionKind::StaticBase
        || expected.permits
        || *desired != Model::empty(record.scope.clone())?
    {
        return Err(GuardError::Conflict);
    }
    let edge = compare_exchange(context, record, kind, expected, desired)?;
    if edge != ExchangeEdge::RemoveBase {
        return Err(GuardError::Conflict);
    }
    Ok(edge)
}
struct Registration<T> {
    value: std::cell::RefCell<Option<T>>,
    attempted: Cell<bool>,
}
impl<T> Registration<T> {
    fn new(value: Option<T>) -> Self {
        Self {
            attempted: Cell::new(value.is_some()),
            value: std::cell::RefCell::new(value),
        }
    }
}
fn register_original<T>(
    slot: &Registration<T>,
    fence: &AttestorFence,
    original: T,
    check: impl FnOnce(&T) -> Result<()>,
) -> Result<()> {
    register_original_channel(slot, fence, original, false, check)
}
fn register_original_channel<T>(
    slot: &Registration<T>,
    fence: &AttestorFence,
    original: T,
    cleanup: bool,
    check: impl FnOnce(&T) -> Result<()>,
) -> Result<()> {
    if slot.attempted.replace(true) {
        fence.fail();
        return Err(GuardError::Conflict);
    }
    // Publish the actual owning pin BEFORE phase/origin/Calling checks or
    // callback unwind. Failure never restores forward selection or drops it.
    *slot.value.borrow_mut() = Some(original);
    fence.inspect_channel(cleanup, || {
        let retained = slot.value.try_borrow().map_err(|_| GuardError::Conflict)?;
        check(retained.as_ref().ok_or(GuardError::Conflict)?)
    })
}
fn window_channel(record: &pair::Record) -> Result<WindowChannel> {
    match record.phase {
        pair::Phase::Starting | pair::Phase::Running => Ok(WindowChannel::Source),
        pair::Phase::Closing if record.stop_stage < 9 => Ok(WindowChannel::Closing),
        pair::Phase::Closing if matches!(record.stop_stage, 9 | 10) => Ok(WindowChannel::Retired),
        pair::Phase::Closing => Err(GuardError::RemovalUnconfirmed),
        _ => Err(GuardError::Conflict),
    }
}
fn compare_selection(
    context: &Context,
    previous: &pair::Record,
    next: &pair::Record,
) -> Result<()> {
    compare_pair(context, previous)?;
    compare_pair(context, next)?;
    if next.revision < previous.revision
        || (next.revision == previous.revision && next != previous)
        || (previous.phase == pair::Phase::Closing && next.phase != pair::Phase::Closing)
    {
        return Err(GuardError::Conflict);
    }
    Ok(())
}
fn cancellation(record: &pair::Record, cancelled: bool) -> Result<()> {
    if cancelled && record.phase != pair::Phase::Closing {
        return Err(GuardError::Conflict);
    }
    Ok(())
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExchangeEdge {
    Withdraw,
    Base,
    Install,
    RemoveBase,
}

fn compare_pair(context: &Context, record: &pair::Record) -> Result<()> {
    record.validate().map_err(|_| GuardError::Conflict)?;
    if record.scope != context.intent.scope
        || record.provenance != context.provenance
        || record.addresses != context.intent.addresses
        || !matches!(
            record.phase,
            pair::Phase::Starting | pair::Phase::Running | pair::Phase::Closing
        )
        || record
            .carrier
            .is_none_or(|c| c.guid != context.bindings[0].guid)
    {
        return Err(GuardError::Conflict);
    }
    for (i, member) in record.members.iter().enumerate() {
        if let Some(member) = member {
            let proof = member.owner.proof.or(member.owner.retired_proof);
            if proof.is_some_and(|p| p.interface.guid != context.bindings[i + 1].guid)
                || (record.phase != pair::Phase::Closing && member.owner.retired_proof.is_some())
            {
                return Err(GuardError::Conflict);
            }
        }
    }
    Ok(())
}
fn compare_bindings(
    context: &Context,
    record: &pair::Record,
    actual: &BindingFacts<'_>,
) -> Result<()> {
    compare_pair(context, record)?;
    let carrier = actual.carrier.ok_or(GuardError::Conflict)?;
    if actual.scope != &record.scope
        || carrier.identity.scope != record.scope
        || Some(carrier.identity.proof) != record.carrier
        || carrier.sources
            != record
                .addresses
                .iter()
                .map(|a| a.addr())
                .collect::<Vec<_>>()
    {
        return Err(GuardError::Conflict);
    }
    for (member, identity) in record.members.iter().zip(actual.egress) {
        let proof = member
            .as_ref()
            .and_then(|m| m.owner.proof.or(m.owner.retired_proof));
        match (proof, identity) {
            (None, None) => (),
            (Some(proof), Some(identity))
                if identity.scope == record.scope && identity.proof == proof.interface => {}
            _ => return Err(GuardError::Conflict),
        }
    }
    Ok(())
}
fn compare_bindings_with_history(
    context: &Context,
    record: &pair::Record,
    actual: &BindingFacts<'_>,
    closed: [Option<&original_members::ClosedMemberBinding>; 2],
) -> Result<()> {
    // History is supplied ONLY by the already authenticated original native
    // window (or retired full-empty bracket). It is comparison data, never a
    // live provider input, row permission or substitute for resource G.
    compare_pair(context, record)?;
    let mut current = BindingFacts {
        scope: actual.scope,
        carrier: actual.carrier,
        egress: actual.egress,
    };
    for (index, history) in closed.into_iter().enumerate() {
        let Some(history) = history else { continue };
        history
            .comparison_provider(context)
            .map_err(|_| GuardError::Conflict)?;
        if history.intent.slot
            != if index == 0 {
                nelomai_contracts::dispatcher::TunnelSlot::A
            } else {
                nelomai_contracts::dispatcher::TunnelSlot::B
            }
            || actual.egress[index].is_none_or(|identity| {
                identity.scope != history.intent.scope || identity.proof != history.proof.interface
            })
        {
            return Err(GuardError::Conflict);
        }
        if let Some(member) = &record.members[index] {
            if member.owner.intent != history.intent
                || member.owner.proof.or(member.owner.retired_proof) != Some(history.proof)
            {
                return Err(GuardError::Conflict);
            }
        } else {
            current.egress[index] = None;
        }
    }
    compare_bindings(context, record, &current)
}
fn compare_model(record: &pair::Record, model: &Model) -> Result<()> {
    model.validate()?;
    if model.scope != record.scope {
        return Err(GuardError::Conflict);
    }
    if let Some(c) = &model.carrier {
        if Some(c.identity.proof) != record.carrier
            || c.identity.scope != record.scope
            || c.sources
                != record
                    .addresses
                    .iter()
                    .map(|a| a.addr())
                    .collect::<Vec<_>>()
        {
            return Err(GuardError::Conflict);
        }
    }
    for (i, member) in model.members.iter().enumerate() {
        if let Some(member) = member {
            let captured = record.members[i].as_ref().ok_or(GuardError::Conflict)?;
            let proof = captured
                .owner
                .proof
                .or(captured.owner.retired_proof)
                .ok_or(GuardError::Conflict)?;
            if member.identity.scope != record.scope
                || member.identity.proof != proof.interface
                || member
                    .probes
                    .iter()
                    .any(|p| p.target != std::net::IpAddr::V4(captured.probe.target_ipv4))
            {
                return Err(GuardError::Conflict);
            }
        }
    }
    Ok(())
}
/// Full-plan comparison ONLY. The native caller separately retains original
/// Pair/source/Calling pins, locked priority/IDs and the mandatory resource G.
fn compare_exchange(
    context: &Context,
    record: &pair::Record,
    kind: SessionKind,
    expected: &Model,
    desired: &Model,
) -> Result<ExchangeEdge> {
    compare_pair(context, record)?;
    if record.pending != Some(pair::Effect::Guard)
        || record.guard != *expected
        || (record.phase != pair::Phase::Closing
            && (record.operation.is_none() || record.stop_stage != 0))
    {
        return Err(GuardError::Conflict);
    }
    let plan = record.pending_guard.as_ref().ok_or(GuardError::Conflict)?;
    plan.validate()?;
    for candidate in [&plan.expected, &plan.withdrawn, &plan.base, &plan.desired] {
        compare_model(record, candidate)?;
    }
    policy::validate_session_exchange(&record.scope, expected, desired, kind)?;
    if expected.installed && expected.assigned_sublayer_weight.is_none() {
        return Err(GuardError::Conflict);
    }
    let mut before = plan.expected.clone();
    let mut matched = None;
    for (session, target, edge) in [
        (
            SessionKind::DynamicPermits,
            &plan.withdrawn,
            ExchangeEdge::Withdraw,
        ),
        (
            SessionKind::StaticBase,
            &plan.base,
            if plan.base.installed {
                ExchangeEdge::Base
            } else {
                ExchangeEdge::RemoveBase
            },
        ),
        (
            SessionKind::DynamicPermits,
            &plan.desired,
            ExchangeEdge::Install,
        ),
    ] {
        let after = target.inherit_sublayer_weight(&before)?;
        // Pair skips no-op edges. Do not allow duplicate/no-op native writes.
        if after != before
            && session == kind
            && before == *expected
            && after == *desired
            && matched.replace(edge).is_some()
        {
            return Err(GuardError::Conflict);
        }
        before = after;
    }
    let edge = matched.ok_or(GuardError::Conflict)?;
    if !expected.installed
        && desired.installed
        && (record.phase != pair::Phase::Starting
            || !matches!(record.operation, Some(pair::Operation::Start(_)))
            || record.active.is_some()
            || record.network.is_some())
    {
        return Err(GuardError::Conflict);
    }
    if record.phase == pair::Phase::Closing {
        if record.active.is_some()
            || record.operation.is_some()
            || desired.permits
            || !matches!(
                (record.stop_stage, edge),
                (0, ExchangeEdge::Withdraw) | (10, ExchangeEdge::RemoveBase)
            )
        {
            return Err(GuardError::Conflict);
        }
    } else if edge == ExchangeEdge::RemoveBase {
        return Err(GuardError::Conflict);
    }
    Ok(edge)
}
fn check_locked(
    expected: &Model,
    mut read: impl FnMut() -> Result<Snapshot>,
    mut gate: impl FnMut() -> Result<()>,
) -> Result<()> {
    expected.validate()?;
    if read()? != expected.expected {
        return Err(GuardError::Conflict);
    }
    gate()?;
    if read()? != expected.expected {
        return Err(GuardError::Conflict);
    }
    Ok(())
}
/// Read-only composition on ONE original outer window/locked transaction.
/// G is mandatory, but must be outside a joined read to use sibling resource
/// joins. No owning Source/guard/engine operation is exposed by this helper.
fn check_window_locked<B>(
    expected: &Model,
    mut join: impl FnMut(&mut dyn FnMut(&B) -> Result<()>) -> Result<()>,
    mut read: impl FnMut(&B) -> Result<Snapshot>,
    mut gate: impl FnMut() -> Result<()>,
) -> Result<()> {
    check_locked(
        expected,
        || {
            let mut snapshot = None;
            let mut calls = 0;
            join(&mut |bindings| {
                calls += 1;
                if calls != 1 {
                    return Err(GuardError::Conflict);
                }
                snapshot = Some(read(bindings)?);
                Ok(())
            })?;
            if calls != 1 {
                return Err(GuardError::Conflict);
            }
            snapshot.ok_or(GuardError::Conflict)
        },
        &mut gate,
    )
}
struct AttestorFence {
    busy: Cell<bool>,
    tainted: Cell<bool>,
    active_tainted: Cell<bool>,
}
struct AttestorCall<'a> {
    fence: &'a AttestorFence,
    completed: bool,
}
impl Drop for AttestorCall<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.fence.tainted.set(true);
        }
        self.fence.busy.set(false);
    }
}
impl AttestorFence {
    fn new() -> Self {
        Self {
            busy: Cell::new(false),
            tainted: Cell::new(false),
            active_tainted: Cell::new(false),
        }
    }
    fn inspect<T>(&self, call: impl FnOnce() -> Result<T>) -> Result<T> {
        self.inspect_channel(false, call)
    }
    fn fail(&self) {
        self.tainted.set(true);
        if self.busy.get() {
            self.active_tainted.set(true);
        }
    }
    fn inspect_channel<T>(&self, cleanup: bool, call: impl FnOnce() -> Result<T>) -> Result<T> {
        if self.busy.get() || (!cleanup && self.tainted.get()) {
            self.fail();
            return Err(GuardError::Conflict);
        }
        self.busy.set(true);
        self.active_tainted.set(false);
        // Entering Closing revokes forward forever, even on a successful read.
        // The surrounding actual Pair/Closing/Retired G still authenticates it.
        if cleanup {
            self.tainted.set(true);
        }
        let mut guard = AttestorCall {
            fence: self,
            completed: false,
        };
        let value = call()?;
        if self.active_tainted.get() {
            return Err(GuardError::Conflict);
        }
        guard.completed = true;
        Ok(value)
    }
    fn inspect_cleanup<T>(&self, call: impl FnOnce() -> Result<T>) -> Result<T> {
        self.inspect_channel(true, call)
    }
}

#[cfg(windows)]
pub(crate) mod native {
    use super::*;
    use crate::windows::{
        member_carrier_guard::{
            BindingAttestor, Bindings, LockedWfpRead, NativeApi, TerminalBindingAttestor,
            WindowBindingAttestor,
        },
        member_carrier_key_authority::RuntimeRead,
        member_carrier_pair_store::native_store::NativePairIntentRead,
        member_carrier_runtime::native::{
            NativeBindingsWindow, NativeClosingRead, NativeSourceRead, RetiredCarrierRead,
        },
        member_carrier_wintun as wintun,
        member_native_deadline::{NativeDeadline, NativeDeadlineReadPin},
    };
    use std::{
        cell::RefCell,
        io,
        rc::Rc,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
    };

    /// Independent permission from the actual retained resource owners. No
    /// implementation/default is supplied; Source bindings and Pair JSON are
    /// comparison facts, NOT held sockets, network/row/endpoint permission.
    ///
    /// # Safety
    /// Implementor retains the SAME serialized coordinator and original
    /// Runtime/Source/Closing, member, RowOwner, route/DNS, probe/socket and
    /// endpoint owners. verify_original_window authenticates the registered
    /// opaque window, not just equal bindings. authorize freshly verifies the
    /// exact current lifecycle/operation and actual resource state: before any
    /// active/probe allows, original C readiness, members, weak rows, selected
    /// route/DNS/endpoint and exclusively HELD original probe sockets; before
    /// any base deletion, the exact removed originals' stopped/absence ACKs
    /// and complete SDK universe. authorize_base_removal additionally requires
    /// actual closed C/member histories, full SDK absence, no outstanding held
    /// probes, rows, network or endpoint state, and the exact cleanup stage.
    /// These guarantees remain held through the actual native transaction and
    /// commit under Main's whole-Calling actor. These callbacks are READ-ONLY:
    /// never enter this guard, open a WFP engine/transaction, nest Source/Pair
    /// inspect, or perform any native effect. authorize runs BETWEEN joined
    /// snapshots: sibling resource window.inspect joins are permitted, but
    /// never recursive joins. authorize_base_removal is INSIDE the supplied
    /// retired full-absence bracket: never reenter that retired read.
    pub(crate) unsafe trait NativeGuardGate {
        fn verify_original_window(
            &self,
            runtime: &RuntimeRead,
            context: &Context,
            record: &pair::Record,
            window: &NativeBindingsWindow<'_>,
        ) -> Result<()>;
        fn authorize(
            &mut self,
            record: &pair::Record,
            kind: SessionKind,
            edge: ExchangeEdge,
            expected: &Model,
            desired: &Model,
            window: &NativeBindingsWindow<'_>,
        ) -> Result<()>;
        fn authorize_base_removal(
            &mut self,
            record: &pair::Record,
            retired: &RetiredCarrierRead,
            bindings: &Bindings,
            expected: &Model,
            desired: &Model,
        ) -> Result<()>;
    }

    struct Originals {
        context: Context,
        runtime: RuntimeRead,
        source: Option<Rc<NativeSourceRead>>,
        closing: Registration<Rc<NativeClosingRead>>,
        retired: Registration<Rc<RetiredCarrierRead>>,
        supervisor: Rc<NativeDeadline>,
        deadline: NativeDeadlineReadPin,
        cancelled: Arc<AtomicBool>,
    }
    struct Selected {
        pair: Rc<NativePairIntentRead>,
        record: pair::Record,
    }
    /// Outside handle for selecting the actual store's next opaque CAS ACK.
    /// Does not grant G, change guard ownership, or clear any sticky taint.
    pub(crate) struct NativeGuardSelection {
        originals: Rc<Originals>,
        selected: Rc<RefCell<Selected>>,
        fence: Rc<AttestorFence>,
    }
    pub(crate) struct NativeGuardAttestor<G: NativeGuardGate> {
        originals: Rc<Originals>,
        selected: Rc<RefCell<Selected>>,
        fence: Rc<AttestorFence>,
        gate: G,
    }
    fn denied<E>(_: E) -> GuardError {
        GuardError::Conflict
    }
    fn io_denied<E>(_: E) -> io::Error {
        io::Error::other("carrier_guard_attestor_conflict")
    }
    fn native_denied<E>(_: E) -> wintun::Error {
        wintun::Error::Conflict
    }
    fn facts(bindings: &Bindings) -> BindingFacts<'_> {
        BindingFacts {
            scope: &bindings.scope,
            carrier: bindings.carrier.as_ref(),
            egress: bindings.egress.each_ref().map(Option::as_ref),
        }
    }
    fn history_by_slot(
        history: &[original_members::ClosedMemberBinding],
    ) -> [Option<&original_members::ClosedMemberBinding>; 2] {
        [
            nelomai_contracts::dispatcher::TunnelSlot::A,
            nelomai_contracts::dispatcher::TunnelSlot::B,
        ]
        .map(|slot| history.iter().find(|entry| entry.intent.slot == slot))
    }
    fn window_history<'a>(
        window: &'a NativeBindingsWindow<'_>,
    ) -> [Option<&'a original_members::ClosedMemberBinding>; 2] {
        [
            nelomai_contracts::dispatcher::TunnelSlot::A,
            nelomai_contracts::dispatcher::TunnelSlot::B,
        ]
        .map(|slot| window.closed_member(slot))
    }
    impl Originals {
        fn continuity(&self, selected: &Selected) -> Result<()> {
            compare_pair(&self.context, &selected.record)?;
            cancellation(&selected.record, self.cancelled.load(Ordering::Acquire))?;
            if !selected.pair.matches_runtime(&self.runtime) {
                return Err(GuardError::Conflict);
            }
            self.deadline
                .verify_runtime_call(&self.supervisor, &self.runtime, &self.context)
                .map_err(denied)?;
            if selected.record.phase != pair::Phase::Closing
                && !self.runtime.fresh(&self.context).map_err(denied)?
            {
                return Err(GuardError::Conflict);
            }
            Ok(())
        }
        fn verify_window(
            &self,
            selected: &Selected,
            window: &NativeBindingsWindow<'_>,
        ) -> Result<()> {
            self.continuity(selected)?;
            let original = match window_channel(&selected.record)? {
                WindowChannel::Closing => self
                    .closing
                    .value
                    .try_borrow()
                    .map_err(denied)?
                    .as_ref()
                    .is_some_and(|c| {
                        window.matches_closing(c)
                            && self
                                .source
                                .as_ref()
                                .is_some_and(|s| c.matches_source_origin(s))
                    }),
                WindowChannel::Source => self
                    .source
                    .as_ref()
                    .is_some_and(|s| window.matches_source(s)),
                WindowChannel::Retired => false,
            };
            if !original || !window.matches_runtime(&self.runtime) {
                return Err(GuardError::Conflict);
            }
            compare_bindings_with_history(
                &self.context,
                &selected.record,
                &facts(window.bindings()),
                window_history(window),
            )
        }
        fn inspect_pair<T>(
            &self,
            selected: &Selected,
            effect: bool,
            call: impl FnOnce(&pair::Record) -> io::Result<T>,
        ) -> Result<T> {
            self.continuity(selected)?;
            let check = |actual: &pair::Record| {
                if actual != &selected.record {
                    return Err(io_denied(()));
                }
                compare_pair(&self.context, actual).map_err(io_denied)?;
                call(actual)
            };
            let result = if effect && selected.record.phase == pair::Phase::Closing {
                selected.pair.inspect_cleanup_effect(
                    &self.runtime,
                    &self.supervisor,
                    &selected.record,
                    selected.record.stop_stage,
                    check,
                )
            } else if effect {
                selected.pair.inspect_effect(
                    &self.runtime,
                    &self.supervisor,
                    &selected.record,
                    pair::Effect::Guard,
                    check,
                )
            } else {
                selected
                    .pair
                    .inspect(&self.runtime, &self.supervisor, check)
            }
            .map_err(denied)?;
            self.continuity(selected)?;
            Ok(result)
        }
        fn inspect_window<T>(
            &self,
            selected: &Selected,
            effect: bool,
            call: impl FnOnce(&NativeBindingsWindow<'_>) -> wintun::Result<T>,
        ) -> Result<T> {
            // No live-C window is a retired C/full SDK EMPTY capability.
            let channel = window_channel(&selected.record)?;
            if channel == WindowChannel::Retired {
                return Err(GuardError::Conflict);
            }
            self.inspect_pair(selected, effect, |_| {
                let checked = |window: &NativeBindingsWindow<'_>| {
                    self.verify_window(selected, window)
                        .map_err(native_denied)?;
                    call(window)
                };
                if channel == WindowChannel::Closing {
                    self.closing
                        .value
                        .try_borrow()
                        .map_err(io_denied)?
                        .as_ref()
                        .ok_or_else(|| io_denied(()))?
                        .inspect_window(checked)
                        .map_err(io_denied)
                } else {
                    self.source
                        .as_ref()
                        .ok_or_else(|| io_denied(()))?
                        .inspect_window(checked)
                        .map_err(io_denied)
                }
            })
        }
        fn inspect_retired<T>(
            &self,
            selected: &Selected,
            call: impl FnOnce(&RetiredCarrierRead, &Bindings) -> wintun::Result<T>,
        ) -> Result<T> {
            compare_retired_read(&self.context, &selected.record)?;
            // Stage 9 authenticates NativeEmpty, NOT Guard permission. Stage
            // 10 authenticates the exact original current Guard cleanup ACK.
            self.inspect_pair(selected, true, |_| {
                let slot = self.retired.value.try_borrow().map_err(io_denied)?;
                let retired = slot.as_ref().ok_or_else(|| io_denied(()))?;
                let source = self.source.as_ref().ok_or_else(|| io_denied(()))?;
                if !retired.matches_source_origin(source) {
                    return Err(io_denied(()));
                }
                retired
                    .inspect_bindings_and_history(|bindings, history| {
                        compare_bindings_with_history(
                            &self.context,
                            &selected.record,
                            &facts(bindings),
                            history_by_slot(history),
                        )
                        .map_err(native_denied)?;
                        call(retired, bindings)
                    })
                    .map_err(io_denied)
            })
        }
    }
    impl<G: NativeGuardGate> NativeGuardAttestor<G> {
        /// Infallibly retains actual opaque originals BEFORE validation. G has
        /// no default. Missing Source/Closing pins DENY that channel on use.
        /// Keep the returned selection handle outside the owning NativeGuard.
        #[allow(clippy::too_many_arguments)] // Every original is mandatory caller-supplied input, not inferred data.
        pub(crate) fn new(
            context: Context,
            runtime: RuntimeRead,
            source: Option<Rc<NativeSourceRead>>,
            closing: Option<Rc<NativeClosingRead>>,
            original_pair: Rc<NativePairIntentRead>,
            expected: pair::Record,
            supervisor: Rc<NativeDeadline>,
            deadline: NativeDeadlineReadPin,
            cancelled: Arc<AtomicBool>,
            gate: G,
        ) -> (Self, NativeGuardSelection) {
            let originals = Rc::new(Originals {
                context,
                runtime,
                source,
                closing: Registration::new(closing),
                retired: Registration::new(None),
                supervisor,
                deadline,
                cancelled,
            });
            let selected = Rc::new(RefCell::new(Selected {
                pair: original_pair,
                record: expected,
            }));
            let fence = Rc::new(AttestorFence::new());
            let selection = NativeGuardSelection {
                originals: originals.clone(),
                selected: selected.clone(),
                fence: fence.clone(),
            };
            (
                Self {
                    originals,
                    selected,
                    fence,
                    gate,
                },
                selection,
            )
        }
    }
    impl NativeGuardSelection {
        /// Retains first pin even if selected phase, opaque origin or Calling
        /// fails. An equal Rc is NOT a replacement/retry capability.
        pub(crate) fn bind_closing(&self, original: Rc<NativeClosingRead>) -> Result<()> {
            register_original_channel(
                &self.originals.closing,
                &self.fence,
                original,
                true,
                |retained| {
                    let selected = self.selected.try_borrow().map_err(denied)?;
                    if window_channel(&selected.record)? != WindowChannel::Closing
                        || !self
                            .originals
                            .source
                            .as_ref()
                            .is_some_and(|s| retained.matches_source_origin(s))
                    {
                        return Err(GuardError::Conflict);
                    }
                    self.originals.inspect_pair(&selected, false, |_| Ok(()))
                },
            )
        }
        /// Actual close hook runs while the native Authority is borrowed. Root
        /// has already retained THIS Rc; publish it here before pure origin
        /// validation only. Never re-enter Pair/SDK/Retired from this hook. Later
        /// mandatory retired brackets verify Calling/current Pair/full absence.
        pub(crate) fn retain_retired_origin(&self, original: Rc<RetiredCarrierRead>) -> Result<()> {
            register_original_channel(
                &self.originals.retired,
                &self.fence,
                original,
                true,
                |retained| {
                    if self
                        .originals
                        .source
                        .as_ref()
                        .is_some_and(|source| retained.matches_source_origin(source))
                    {
                        Ok(())
                    } else {
                        Err(GuardError::Conflict)
                    }
                },
            )
        }
        pub(crate) fn select(
            &self,
            original_pair: Rc<NativePairIntentRead>,
            expected: pair::Record,
        ) -> Result<()> {
            self.fence
                .inspect_channel(expected.phase == pair::Phase::Closing, || {
                    let mut old = self.selected.try_borrow_mut().map_err(denied)?;
                    compare_selection(&self.originals.context, &old.record, &expected)?;
                    if expected.revision == old.record.revision
                        && !Rc::ptr_eq(&original_pair, &old.pair)
                    {
                        return Err(GuardError::Conflict);
                    }
                    let next = Selected {
                        pair: original_pair,
                        record: expected,
                    };
                    self.originals.inspect_pair(&next, false, |_| Ok(()))?;
                    *old = next;
                    Ok(())
                })
        }
    }
    impl<G: NativeGuardGate> BindingAttestor for NativeGuardAttestor<G> {
        fn observe(
            &mut self,
            scope: &nelomai_client_tunnel::redundancy::SessionScope,
        ) -> Result<Bindings> {
            let fence = self.fence.clone();
            let cleanup =
                self.selected.try_borrow().map_err(denied)?.record.phase == pair::Phase::Closing;
            fence.inspect_channel(cleanup, || {
                let selected = self.selected.try_borrow().map_err(denied)?;
                if scope != &selected.record.scope {
                    return Err(GuardError::Conflict);
                }
                if window_channel(&selected.record)? == WindowChannel::Retired {
                    return self.originals.inspect_retired(&selected, |_, bindings| {
                        Ok(Bindings {
                            scope: bindings.scope.clone(),
                            carrier: bindings.carrier.clone(),
                            egress: bindings.egress.clone(),
                        })
                    });
                }
                self.originals.inspect_window(&selected, false, |window| {
                    self.gate
                        .verify_original_window(
                            &self.originals.runtime,
                            &self.originals.context,
                            &selected.record,
                            window,
                        )
                        .map_err(native_denied)?;
                    let bindings = window.bindings();
                    compare_bindings_with_history(
                        &self.originals.context,
                        &selected.record,
                        &facts(bindings),
                        window_history(window),
                    )
                    .map_err(native_denied)?;
                    Ok(Bindings {
                        scope: bindings.scope.clone(),
                        carrier: bindings.carrier.clone(),
                        egress: bindings.egress.clone(),
                    })
                })
            })
        }
        fn authorize<N: NativeApi>(
            &mut self,
            kind: SessionKind,
            expected: &Model,
            desired: &Model,
            locked: &mut LockedWfpRead<'_, N>,
        ) -> Result<()> {
            let fence = self.fence.clone();
            let cleanup =
                self.selected.try_borrow().map_err(denied)?.record.phase == pair::Phase::Closing;
            fence.inspect_channel(cleanup, || {
                let selected = self.selected.try_borrow().map_err(denied)?;
                let edge = compare_exchange(
                    &self.originals.context,
                    &selected.record,
                    kind,
                    expected,
                    desired,
                )?;
                if edge == ExchangeEdge::RemoveBase {
                    compare_retired_removal(
                        &self.originals.context,
                        &selected.record,
                        kind,
                        expected,
                        desired,
                    )?;
                    let gate = &mut self.gate;
                    return self
                        .originals
                        .inspect_retired(&selected, |retired, bindings| {
                            let current = RefCell::new(locked);
                            check_locked(
                                expected,
                                || current.borrow_mut().snapshot(bindings),
                                || {
                                    gate.authorize_base_removal(
                                        &selected.record,
                                        retired,
                                        bindings,
                                        expected,
                                        desired,
                                    )
                                },
                            )
                            .map_err(native_denied)
                        });
                }
                let gate = &mut self.gate;
                self.originals.inspect_window(&selected, true, |window| {
                    gate.verify_original_window(
                        &self.originals.runtime,
                        &self.originals.context,
                        &selected.record,
                        window,
                    )
                    .map_err(native_denied)?;
                    // Borrow ONLY the supplied actual locked read capability.
                    // Same outer Source/Pair/Calling spans two separate joined
                    // snapshots and G's standard sibling resource joins.
                    let current = RefCell::new(locked);
                    check_window_locked(
                        expected,
                        |callback| {
                            window
                                .inspect(|bindings| callback(bindings).map_err(native_denied))
                                .map_err(denied)
                        },
                        |bindings| {
                            compare_bindings_with_history(
                                &self.originals.context,
                                &selected.record,
                                &facts(bindings),
                                window_history(window),
                            )?;
                            current.borrow_mut().snapshot(bindings)
                        },
                        || {
                            if desired.permits {
                                current.borrow_mut().priority_barrier()?;
                            }
                            gate.authorize(&selected.record, kind, edge, expected, desired, window)
                        },
                    )
                    .map_err(native_denied)
                })
            })
        }
    }
    impl<G: NativeGuardGate> WindowBindingAttestor for NativeGuardAttestor<G> {
        fn verify_retired_bracket(
            &mut self,
            pair: &Rc<NativePairIntentRead>,
            record: &pair::Record,
            retired: &RetiredCarrierRead,
            bindings: &Bindings,
        ) -> Result<()> {
            if record.phase == pair::Phase::Stopped {
                let original = self
                    .originals
                    .retired
                    .value
                    .try_borrow()
                    .map_err(denied)?
                    .clone()
                    .ok_or(GuardError::Conflict)?;
                if !std::ptr::eq(original.as_ref(), retired) {
                    return Err(GuardError::Conflict);
                }
                return self.verify_terminal_bracket(pair, record, &original, bindings);
            }
            let fence = self.fence.clone();
            fence.inspect_cleanup(|| {
                compare_retired_read(&self.originals.context, record)?;
                let previous = self.selected.try_borrow().map_err(denied)?;
                compare_selection(&self.originals.context, &previous.record, record)?;
                if !pair.same_store_origin(&previous.pair)
                    || (record.revision == previous.record.revision
                        && !Rc::ptr_eq(pair, &previous.pair))
                {
                    return Err(GuardError::Conflict);
                }
                let selected = Selected {
                    pair: pair.clone(),
                    record: record.clone(),
                };
                let slot = self.originals.retired.value.try_borrow().map_err(denied)?;
                let original = slot.as_ref().ok_or(GuardError::Conflict)?;
                let source = self.originals.source.as_ref().ok_or(GuardError::Conflict)?;
                if !std::ptr::eq(original.as_ref(), retired)
                    || !retired.matches_source_origin(source)
                {
                    return Err(GuardError::Conflict);
                }
                self.originals.inspect_pair(&selected, false, |_| {
                    let bytes = self
                        .originals
                        .runtime
                        .record(
                            &self.originals.context,
                            crate::windows::member_session::RecordKind::NativeCarrierReceipts,
                        )
                        .map_err(io_denied)?;
                    let native = crate::member_carrier_native_ownership::Record::decode(&bytes)
                        .map_err(io_denied)?;
                    if native.context != self.originals.context {
                        return Err(io_denied(()));
                    }
                    let compare = |history: &[original_members::ClosedMemberBinding]| {
                        compare_bindings_with_history(
                            &self.originals.context,
                            record,
                            &facts(bindings),
                            history_by_slot(history),
                        )
                        .map_err(native_denied)
                    };
                    match native.phase {
                        crate::member_carrier_native_ownership::Phase::Closing
                            if record.stop_stage <= 11 =>
                        {
                            retired.inspect_history_in_bracket(compare)
                        }
                        crate::member_carrier_native_ownership::Phase::Stopped
                            if matches!(record.stop_stage, 11 | 12) =>
                        {
                            retired.inspect_terminal_history_in_bracket(compare)
                        }
                        _ => return Err(io_denied(())),
                    }
                    .map_err(io_denied)
                })
            })
        }
        fn verify_original_window(&mut self, window: &NativeBindingsWindow<'_>) -> Result<()> {
            let fence = self.fence.clone();
            let cleanup =
                self.selected.try_borrow().map_err(denied)?.record.phase == pair::Phase::Closing;
            fence.inspect_channel(cleanup, || {
                let selected = self.selected.try_borrow().map_err(denied)?;
                // Already inside the original outer Source/Closing window:
                // authenticate it directly, NEVER recursively enter Source.
                window_channel(&selected.record)?;
                self.originals.inspect_pair(&selected, false, |_| {
                    self.originals
                        .verify_window(&selected, window)
                        .map_err(io_denied)?;
                    self.gate
                        .verify_original_window(
                            &self.originals.runtime,
                            &self.originals.context,
                            &selected.record,
                            window,
                        )
                        .map_err(io_denied)
                })
            })
        }
    }
    impl<G: NativeGuardGate> TerminalBindingAttestor for NativeGuardAttestor<G> {
        fn verify_terminal_bracket(
            &mut self,
            pair: &Rc<NativePairIntentRead>,
            stopped: &pair::Record,
            retired: &Rc<RetiredCarrierRead>,
            bindings: &Bindings,
        ) -> Result<()> {
            let fence = self.fence.clone();
            fence.inspect_cleanup(|| {
                compare_terminal_read(&self.originals.context, stopped)?;
                let selected = self.selected.try_borrow().map_err(denied)?;
                let retained = self.originals.retired.value.try_borrow().map_err(denied)?;
                let actual = retained.as_ref().ok_or(GuardError::Conflict)?;
                let source = self.originals.source.as_ref().ok_or(GuardError::Conflict)?;
                if !Rc::ptr_eq(actual, retired)
                    || !retired.matches_source_origin(source)
                    || !pair.same_store_origin(&selected.pair)
                    || !pair.matches_runtime(&self.originals.runtime)
                    || stopped.revision <= selected.record.revision
                {
                    return Err(GuardError::Conflict);
                }
                let verify = || {
                    self.originals
                        .deadline
                        .verify_runtime_call(
                            &self.originals.supervisor,
                            &self.originals.runtime,
                            &self.originals.context,
                        )
                        .map_err(denied)?;
                    // Canonical G may already be inside Pair.inspect. The
                    // actual store method authenticates current original ACK,
                    // bytes, KeyLock and Calling WITHOUT Pair reentry.
                    pair.verify_terminal_bracket(
                        &self.originals.runtime,
                        &self.originals.supervisor,
                        &self.originals.context,
                        stopped,
                    )
                    .map_err(denied)
                };
                verify()?;
                // Read ONLY the SAME already-active terminal history lease.
                // No Source/inventory/Retired SDK query and no native effect.
                retired
                    .inspect_terminal_history_in_bracket(|history| {
                        compare_terminal_bindings(
                            &self.originals.context,
                            stopped,
                            &facts(bindings),
                            history,
                        )
                        .map_err(native_denied)
                    })
                    .map_err(denied)?;
                verify()
            })
        }
    }
}

#[cfg(test)]
#[path = "member_carrier_guard_attestor_tests.rs"]
mod tests;
