//! Full original C/member-row lifecycle join. No factory selection or effects.
//! Portable comparisons are not authority. Native G has no successful default,
//! resource trait, imported receipt, or reconstructed original constructor.
#![allow(dead_code)]

use crate::{
    member_carrier_guard as policy, member_carrier_native_ownership::Context,
    member_carrier_pair as pair, member_carrier_rows as rows,
};
use std::{cell::Cell, io};

fn conflict() -> io::Error {
    io::Error::other("carrier_lifecycle_gate_conflict")
}
fn denied<E>(_: E) -> io::Error {
    conflict()
}
fn role_index(role: rows::Role) -> usize {
    match role {
        rows::Role::Carrier => 0,
        rows::Role::MemberA => 1,
        rows::Role::MemberB => 2,
    }
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum LifecycleStage {
    Resolve,
    Create,
    Session,
    Drain,
    Observe,
    CleanupObserve,
    End,
    Close,
    AfterClose,
}

fn compare_context(context: &Context, record: &pair::Record) -> io::Result<()> {
    record.validate()?;
    if record.scope != context.intent.scope
        || record.provenance != context.provenance
        || record.addresses != context.intent.addresses
        || record.options.is_none()
        || record
            .carrier
            .is_none_or(|p| p.guid != context.bindings[0].guid)
    {
        return Err(conflict());
    }
    Ok(())
}
fn compare_member_bindings(
    record: &pair::Record,
    egress: &[Option<policy::Identity>; 2],
) -> io::Result<()> {
    for (i, member) in record.members.iter().enumerate() {
        if let Some(member) = member {
            crate::member_owner::validate_record_shape(&member.owner).map_err(denied)?;
            if let Some(proof) = member.owner.proof.or(member.owner.retired_proof) {
                if egress[i]
                    .as_ref()
                    .is_none_or(|identity| identity.proof != proof.interface)
                {
                    return Err(conflict());
                }
            } else if member.owner.phase != crate::member_owner::Phase::Prepared
                || egress[i].is_some()
            {
                return Err(conflict());
            }
        }
    }
    Ok(())
}
fn compare_lifecycle_stage(
    context: &Context,
    record: &pair::Record,
    stage: LifecycleStage,
) -> io::Result<()> {
    compare_context(context, record)?;
    match stage {
        LifecycleStage::Observe
            if matches!(record.phase, pair::Phase::Starting | pair::Phase::Running)
                && record.stop_stage == 0
                && record.pending.is_some() =>
        {
            Ok(())
        }
        LifecycleStage::CleanupObserve
            if record.phase == pair::Phase::Closing
                && record.active.is_none()
                && record.operation.is_none()
                && record.pending.is_some() =>
        {
            Ok(())
        }
        LifecycleStage::End | LifecycleStage::Close | LifecycleStage::AfterClose => {
            let (stop, effect) = if stage == LifecycleStage::End {
                (7, pair::Effect::CarrierSessionEnd)
            } else {
                (8, pair::Effect::CarrierClose)
            };
            if record.phase != pair::Phase::Closing
                || record.stop_stage != stop
                || record.pending != Some(effect)
                || record.active.is_some()
                || record.operation.is_some()
                || record.pending_guard.is_some()
                || record.guard.permits
            {
                return Err(conflict());
            }
            Ok(())
        }
        // Bootstrap has already created C and started THIS session. Full G
        // must not create/restart/drain a new session after the one-shot upgrade.
        _ => Err(conflict()),
    }
}
/// Comparison only for the selected inactive row's cleanup ACK read. Source,
/// session, registry and sibling rows retain their forward authorization.
fn retiring_member_row(record: &pair::Record, role: rows::Role, target: &rows::Target) -> bool {
    let slot = match role {
        rows::Role::MemberA => nelomai_client_tunnel::redundancy::Slot::A,
        rows::Role::MemberB => nelomai_client_tunnel::redundancy::Slot::B,
        rows::Role::Carrier => return false,
    };
    record.phase == pair::Phase::Running
        && record.stop_stage == 0
        && record.pending == Some(pair::Effect::RestoreWeak)
        && record.operation == Some(pair::Operation::Retire(slot))
        && record.active.is_some_and(|active| active != slot)
        && record.members[role_index(role) - 1]
            .as_ref()
            .is_some_and(|member| member.owner.phase == crate::member_owner::Phase::Running)
        && record.pending_guard.is_none()
        && !record.guard.permits
        && record.guard.installed
        && record.guard.assigned_sublayer_weight.is_some()
        && matches!(target, rows::Target::Interface(_))
}
fn compare_row_stage(
    context: &Context,
    record: &pair::Record,
    role: rows::Role,
    target: &rows::Target,
) -> io::Result<()> {
    compare_context(context, record)?;
    if record.pending_guard.is_some()
        || record.guard.permits
        || !((record.guard.installed && record.guard.assigned_sublayer_weight.is_some())
            || (role == rows::Role::Carrier
                && target == &rows::Target::Delete
                && record.network.is_none()
                && record.guard == policy::Model::empty(record.scope.clone()).map_err(denied)?))
    {
        return Err(conflict());
    }
    match (record.phase, record.pending, target) {
        (
            pair::Phase::Starting | pair::Phase::Running,
            Some(pair::Effect::WeakRows),
            rows::Target::Interface(_),
        ) if record.stop_stage == 0 && record.operation.is_some() => Ok(()),
        (pair::Phase::Running, Some(pair::Effect::RestoreWeak), rows::Target::Interface(_))
            if retiring_member_row(record, role, target) =>
        {
            Ok(())
        }
        (pair::Phase::Closing, Some(pair::Effect::RestoreWeak), rows::Target::Interface(_))
            if record.stop_stage == 3 && record.active.is_none() && record.operation.is_none() =>
        {
            Ok(())
        }
        (pair::Phase::Closing, Some(pair::Effect::CarrierAddressDelete), rows::Target::Delete)
            if record.stop_stage == 6
                && role == rows::Role::Carrier
                && record.active.is_none()
                && record.operation.is_none() =>
        {
            Ok(())
        }
        _ => Err(conflict()),
    }
}

/// Comparison only; current original publication/Retired bracket and actual
/// resource ACKs are mandatory independently of an empty policy record.
fn compare_full_empty_guard(
    context: &Context,
    record: &pair::Record,
    actual: &policy::Snapshot,
) -> io::Result<()> {
    compare_restored_resource_guard(context, record, actual, false)
}
fn compare_restored_resource_guard(
    context: &Context,
    record: &pair::Record,
    actual: &policy::Snapshot,
    keys_restored: bool,
) -> io::Result<()> {
    crate::member_carrier_native_ownership::validate_context(context).map_err(denied)?;
    record.validate()?;
    if record.scope != context.intent.scope
        || record.provenance != context.provenance
        || record.addresses != context.intent.addresses
        || record.options.is_none()
        || record.pending_guard.is_some()
        || record.active.is_some()
        || record.operation.is_some()
        || !(if keys_restored {
            matches!(
                (record.phase, record.stop_stage, record.pending),
                (pair::Phase::Closing, 11, Some(pair::Effect::RestoreKeys))
            )
        } else {
            matches!(
                (record.phase, record.stop_stage, record.pending),
                (pair::Phase::Closing, 12, Some(pair::Effect::FullEmpty))
                    | (pair::Phase::Stopped, 12, None)
            )
        })
        || (record.phase == pair::Phase::Closing
            && record
                .carrier
                .is_none_or(|c| c.guid != context.bindings[0].guid))
        || (record.phase == pair::Phase::Stopped
            && (record.carrier.is_some() || record.members.iter().any(Option::is_some)))
        || record.network.as_ref().is_some_and(|n| {
            n.pending.is_some() || n.current != n.baseline || !n.current.routes.is_empty()
        })
    {
        return Err(conflict());
    }
    let empty = policy::Model::empty(record.scope.clone()).map_err(denied)?;
    if record.guard != empty || actual != &empty.expected {
        return Err(conflict());
    }
    Ok(())
}

fn compare_restored_keys_guard(
    context: &Context,
    record: &pair::Record,
    actual: &policy::Snapshot,
) -> io::Result<()> {
    compare_restored_resource_guard(context, record, actual, true)
}

fn compare_full_empty_row(
    original: &CapturedRow,
    ack: &rows::Record,
    identity: &policy::Identity,
    observed: Option<&rows::Snapshot>,
) -> io::Result<()> {
    original.binding.validate().map_err(denied)?;
    ack.validate().map_err(denied)?;
    original
        .baseline
        .validate(&original.binding)
        .map_err(denied)?;
    if ack.binding != original.binding
        || ack.baseline != original.baseline
        || identity.scope != original.binding.scope
        || identity.proof.guid != original.binding.guid
        || identity.proof.index != original.binding.key.index
        || identity.proof.luid != original.binding.key.luid
        || ack.phase != rows::Phase::Stopped
        || ack.pending.is_some()
        || observed.is_some()
        || ack.current.address.is_some()
        || original.baseline.address.is_some()
        || ack.current.interface.key != original.baseline.interface.key
        || ack.current.interface.policy != original.baseline.interface.policy
        || original.baseline.interface.policy.weak_host_send
        || original.baseline.interface.policy.weak_host_receive
        || original.baseline.interface.policy.forwarding
        || original.baseline.interface.policy.advertising
        || (original.binding.role != rows::Role::Carrier && ack.creation.is_some())
    {
        return Err(conflict());
    }
    Ok(())
}
fn compare_guard_blocks(record: &pair::Record, observed: &policy::Snapshot) -> io::Result<()> {
    record.guard.validate().map_err(denied)?;
    let empty = policy::Model::empty(record.scope.clone()).map_err(denied)?;
    if record.guard == empty
        && observed == &empty.expected
        && record.pending_guard.is_none()
        && record.active.is_none()
        && record.operation.is_none()
        && record.network.is_none()
        && matches!(
            (record.phase, record.stop_stage, record.pending),
            (
                pair::Phase::Closing,
                6,
                Some(pair::Effect::CarrierAddressDelete)
            ) | (
                pair::Phase::Closing,
                7,
                Some(pair::Effect::CarrierSessionEnd)
            ) | (pair::Phase::Closing, 8, Some(pair::Effect::CarrierClose))
        )
    {
        return Ok(());
    }
    if !record.guard.installed
        || record.guard.permits
        || record.pending_guard.is_some()
        || record.guard.assigned_sublayer_weight.is_none()
        || observed != &record.guard.expected
        || observed
            .filters
            .iter()
            .any(|f| f.action != policy::Action::Block)
        || record
            .guard
            .carrier
            .as_ref()
            .is_none_or(|c| Some(c.identity.proof) != record.carrier)
    {
        return Err(conflict());
    }
    // The exact 49-key SDK snapshot is compared above; captured sublayer
    // priority, all conditions, IPv4/IPv6 classifications and owned IDs stay exact.
    for (i, member) in record.members.iter().enumerate() {
        if let Some(member) = member {
            let proof = member
                .owner
                .proof
                .or(member.owner.retired_proof)
                .ok_or_else(conflict)?;
            if record.guard.members[i]
                .as_ref()
                .is_none_or(|m| m.identity.proof != proof.interface)
            {
                return Err(conflict());
            }
        }
    }
    Ok(())
}
fn compare_row_binding(
    context: &Context,
    record: &pair::Record,
    binding: &rows::Binding,
) -> io::Result<()> {
    let i = role_index(binding.role);
    let proof = if i == 0 {
        record.carrier.ok_or_else(conflict)?
    } else {
        let owner = &record.members[i - 1].as_ref().ok_or_else(conflict)?.owner;
        owner
            .proof
            .or(owner.retired_proof)
            .ok_or_else(conflict)?
            .interface
    };
    let network = record.addresses.first().ok_or_else(conflict)?;
    if record.addresses.len() != 1 || network.prefix_len() != 32 {
        return Err(conflict());
    }
    let address = match network.addr() {
        std::net::IpAddr::V4(ip) => ip.octets(),
        _ => return Err(conflict()),
    };
    if binding.scope != record.scope
        || binding.boot_id != context.provenance.boot_id
        || binding.runtime != context.provenance.runtime
        || binding.network_epoch != context.provenance.network_epoch
        || binding.guid != context.bindings[i].guid
        || binding.name != context.bindings[i].name
        || binding.guid != proof.guid
        || binding.key.index != proof.index
        || binding.key.luid != proof.luid
        || binding.address != address
    {
        return Err(conflict());
    }
    Ok(())
}
fn row_target(record: &pair::Record, ack: &rows::Record) -> rows::Target {
    if record.pending == Some(pair::Effect::CarrierAddressDelete) {
        return rows::Target::Delete;
    }
    let mut target = ack.baseline.interface.policy.clone();
    if record.pending == Some(pair::Effect::WeakRows) {
        target.weak_host_send = true;
        target.weak_host_receive = true;
    }
    rows::Target::Interface(target)
}
fn compare_row_effect(
    context: &Context,
    record: &pair::Record,
    binding: &rows::Binding,
    target: &rows::Target,
    ack: &rows::Record,
    protected: &rows::Record,
    actual: &rows::Snapshot,
) -> io::Result<()> {
    compare_row_stage(context, record, binding.role, target)?;
    compare_row_binding(context, record, binding)?;
    ack.validate().map_err(denied)?;
    protected.validate().map_err(denied)?;
    let pending = ack.pending.as_ref().ok_or_else(conflict)?;
    if ack != protected
        || &ack.binding != binding
        || &pending.target != target
        || &row_target(record, ack) != target
        || pending.before != ack.current
        || !rows::same_owned(actual, &pending.before)
        || ack.baseline.interface.policy.forwarding
        || ack.baseline.interface.policy.advertising
        || ack.baseline.interface.policy.weak_host_send
        || ack.baseline.interface.policy.weak_host_receive
        || (record.phase == pair::Phase::Closing && ack.phase == rows::Phase::Captured)
        || (record.phase != pair::Phase::Closing
            && ack.phase
                != if retiring_member_row(record, binding.role, target) {
                    rows::Phase::Closing
                } else {
                    rows::Phase::Captured
                })
    {
        return Err(conflict());
    }
    let mut before_policy = ack.baseline.interface.policy.clone();
    before_policy.weak_host_send = ack.current.interface.policy.weak_host_send;
    before_policy.weak_host_receive = ack.current.interface.policy.weak_host_receive;
    if ack.current.interface.policy != before_policy
        || ack.current.interface.key != ack.baseline.interface.key
    {
        return Err(conflict());
    }
    if binding.role != rows::Role::Carrier {
        if ack.creation.is_some() || ack.baseline.address.is_some() || ack.current.address.is_some()
        {
            return Err(conflict());
        }
    } else {
        // Original RowOwner's non-importable ACK mirror is mandatory. JSON or a
        // matching SDK address with no successful own Create ACK cannot delete.
        let created = ack.creation.as_ref().ok_or_else(conflict)?;
        if ack.baseline.address.is_some()
            || ack
                .current
                .address
                .as_ref()
                .is_none_or(|current| !rows::same_address(current, created))
            || created.key != binding.key
            || created.policy.address != binding.address
            || (target == &rows::Target::Delete
                && ack.current.interface.policy != ack.baseline.interface.policy)
        {
            return Err(conflict());
        }
    }
    Ok(())
}
fn compare_closed_carrier_row(
    context: &Context,
    record: &pair::Record,
    ack: &rows::Record,
    actual: &rows::Snapshot,
) -> io::Result<()> {
    compare_context(context, record)?;
    compare_row_binding(context, record, &ack.binding)?;
    ack.validate().map_err(denied)?;
    if ack.binding.role != rows::Role::Carrier
        || ack.phase != rows::Phase::Stopped
        || ack.pending.is_some()
        || ack.creation.is_none()
        || ack.baseline.address.is_some()
        || ack.current.interface.policy != ack.baseline.interface.policy
        || ack.current.interface.key != ack.baseline.interface.key
        || !rows::same_owned(actual, &ack.current)
        || actual.address.is_some()
        || actual.interface.policy.weak_host_send
        || actual.interface.policy.weak_host_receive
        || actual.interface.policy.forwarding
        || actual.interface.policy.advertising
    {
        return Err(conflict());
    }
    Ok(())
}

struct LifecycleFence {
    busy: Cell<bool>,
    revoked: Cell<bool>,
    tainted: Cell<bool>,
}

// Comparison ONLY: native caller must have window.closed_member's SAME original
// closed receipt/full absence. Absence of a Snapshot is not that capability.
fn compare_closed_member_ack(
    original: &rows::Binding,
    baseline: &rows::Snapshot,
    ack: &rows::Record,
) -> io::Result<()> {
    original.validate().map_err(denied)?;
    ack.validate().map_err(denied)?;
    if original.role == rows::Role::Carrier
        || &ack.binding != original
        || &ack.baseline != baseline
        || ack.phase != rows::Phase::Stopped
        || ack.pending.is_some()
        || ack.creation.is_some()
        || ack.current.address.is_some()
        || baseline.address.is_some()
        || ack.current.interface.policy != baseline.interface.policy
        || ack.current.interface.key != baseline.interface.key
        || baseline.interface.policy.forwarding
        || baseline.interface.policy.advertising
        || baseline.interface.policy.weak_host_send
        || baseline.interface.policy.weak_host_receive
    {
        return Err(conflict());
    }
    Ok(())
}
#[derive(Clone)]
struct CapturedRow {
    binding: rows::Binding,
    baseline: rows::Snapshot,
}
/// Comparison only. Native callers authenticate the actual retained attempt
/// and Closing window. Neither this enum nor a protected record is an ACK.
#[derive(Debug, Eq, PartialEq)]
enum ClosingRowWriteState {
    Acknowledged,
    BeforeAttempt,
    DesiredAttempt,
}
struct ClosingRowObservation<'a> {
    context: &'a Context,
    pair: &'a pair::Record,
    original: &'a CapturedRow,
    acknowledged: &'a rows::Record,
    protected: &'a rows::Record,
    actual: &'a rows::Snapshot,
    attempt: Option<(&'a rows::Record, &'a rows::Record)>,
}
fn compare_closing_row_observation(
    facts: ClosingRowObservation<'_>,
) -> io::Result<ClosingRowWriteState> {
    compare_context(facts.context, facts.pair)?;
    let original = facts.original;
    compare_row_binding(facts.context, facts.pair, &original.binding)?;
    original.binding.validate().map_err(denied)?;
    original
        .baseline
        .validate(&original.binding)
        .map_err(denied)?;
    facts.actual.validate(&original.binding).map_err(denied)?;
    if facts.pair.phase != pair::Phase::Closing
        || facts.pair.active.is_some()
        || facts.pair.operation.is_some()
        || facts.pair.pending_guard.is_some()
        || facts.pair.guard.permits
        || !matches!(
            (facts.pair.stop_stage, facts.pair.pending),
            (3, Some(pair::Effect::RestoreWeak)) | (6, Some(pair::Effect::CarrierAddressDelete))
        )
        || (facts.pair.stop_stage == 6 && original.binding.role != rows::Role::Carrier)
        || original.baseline.address.is_some()
        || original.baseline.interface.policy.weak_host_send
        || original.baseline.interface.policy.weak_host_receive
        || original.baseline.interface.policy.forwarding
        || original.baseline.interface.policy.advertising
    {
        return Err(conflict());
    }
    let check = |record: &rows::Record| -> io::Result<()> {
        record.validate().map_err(denied)?;
        if record.binding != original.binding || record.baseline != original.baseline
            || record.current.interface.key != original.baseline.interface.key
            // Creation provenance is ONLY the actual last ACK. Attempts cannot
            // add/adopt even a matching creation, or replace that original.
            || record.creation != facts.acknowledged.creation
            || (original.binding.role != rows::Role::Carrier && record.creation.is_some())
        {
            return Err(conflict());
        }
        if let Some(pending) = &record.pending {
            match &pending.target {
                rows::Target::Interface(policy) => {
                    rows::validate_interface_delta(&record.baseline.interface.policy, policy)
                        .map_err(denied)?;
                }
                rows::Target::Delete
                    if facts.pair.stop_stage == 6
                        && original.binding.role == rows::Role::Carrier
                        && record.phase == rows::Phase::Closing
                        && record.creation.is_some()
                        && pending.before.interface.policy
                            == original.baseline.interface.policy => {}
                _ => return Err(conflict()),
            }
        }
        Ok(())
    };
    check(facts.acknowledged)?;
    check(facts.protected)?;
    let state = if facts.acknowledged == facts.protected {
        ClosingRowWriteState::Acknowledged
    } else {
        let (before, desired) = facts.attempt.ok_or_else(conflict)?;
        check(before)?;
        check(desired)?;
        if before.revision < facts.acknowledged.revision
            || before.revision.checked_add(1) != Some(desired.revision)
            || !matches!(
                (before.phase, desired.phase),
                (
                    rows::Phase::Captured,
                    rows::Phase::Captured | rows::Phase::Closing
                ) | (
                    rows::Phase::Closing,
                    rows::Phase::Closing | rows::Phase::Stopped
                )
            )
        {
            return Err(conflict());
        }
        if facts.protected == before {
            ClosingRowWriteState::BeforeAttempt
        } else if facts.protected == desired {
            ClosingRowWriteState::DesiredAttempt
        } else {
            return Err(conflict());
        }
    };
    // Observe only the SELECTED protected state. A false/unapplied CAS whose
    // file stayed before cannot claim the desired policy appeared in native.
    let matched = if let Some(pending) = &facts.protected.pending {
        if rows::same_owned(facts.actual, &pending.before) {
            true
        } else {
            let mut applied = pending.before.clone();
            match &pending.target {
                rows::Target::Interface(policy) => applied.interface.policy = policy.clone(),
                rows::Target::Delete => applied.address = None,
                rows::Target::Create(_) => return Err(conflict()),
            }
            rows::same_owned(facts.actual, &applied)
        }
    } else {
        rows::same_owned(facts.actual, &facts.protected.current)
    };
    if !matched {
        return Err(conflict());
    }
    Ok(state)
}
fn compare_member_capture_frame(
    context: &Context,
    record: &pair::Record,
    binding: &rows::Binding,
    replacement: bool,
) -> io::Result<()> {
    compare_context(context, record)?;
    compare_row_binding(context, record, binding)?;
    let slot = match binding.role {
        rows::Role::MemberA => nelomai_client_tunnel::redundancy::Slot::A,
        rows::Role::MemberB => nelomai_client_tunnel::redundancy::Slot::B,
        rows::Role::Carrier => return Err(conflict()),
    };
    let initial_prebase = !replacement && record.pending.is_none();
    let replacement_prebase = replacement
        && record.pending.is_none()
        && record.phase == pair::Phase::Running
        && record.operation == Some(pair::Operation::Attach(slot))
        && record.guard.installed;
    if (replacement && !replacement_prebase)
        || (record.pending != Some(pair::Effect::WeakRows)
            && !initial_prebase
            && !replacement_prebase)
        || record.pending_guard.is_some()
        || record.stop_stage != 0
        || (!record.guard.installed
            && (!initial_prebase
                || record.guard != policy::Model::empty(record.scope.clone()).map_err(denied)?))
        || record.guard.permits
        || (record.guard.installed && record.guard.assigned_sublayer_weight.is_none())
        || record
            .guard
            .expected
            .filters
            .iter()
            .any(|f| f.action != policy::Action::Block)
        || record.members[role_index(binding.role) - 1]
            .as_ref()
            .is_none_or(|m| {
                m.owner.phase != crate::member_owner::Phase::Running || m.owner.proof.is_none()
            })
    {
        return Err(conflict());
    }
    match record.phase {
        pair::Phase::Starting
            if !replacement
                && record.active.is_none()
                && record.operation == Some(pair::Operation::Start(slot)) =>
        {
            Ok(())
        }
        pair::Phase::Running
            if record.operation == Some(pair::Operation::Attach(slot))
                && record.active
                    == Some(if slot == nelomai_client_tunnel::redundancy::Slot::A {
                        nelomai_client_tunnel::redundancy::Slot::B
                    } else {
                        nelomai_client_tunnel::redundancy::Slot::A
                    }) =>
        {
            Ok(())
        }
        _ => Err(conflict()),
    }
}
fn compare_member_capture_baseline(binding: &rows::Binding, ack: &rows::Record) -> io::Result<()> {
    ack.validate().map_err(denied)?;
    if binding.role == rows::Role::Carrier
        || &ack.binding != binding
        || ack.phase != rows::Phase::Captured
        || ack.pending.is_some()
        || ack.creation.is_some()
        || ack.current != ack.baseline
        || ack.baseline.address.is_some()
        || ack.baseline.interface.policy.weak_host_send
        || ack.baseline.interface.policy.weak_host_receive
        || ack.baseline.interface.policy.forwarding
        || ack.baseline.interface.policy.advertising
    {
        return Err(conflict());
    }
    Ok(())
}
struct RowGeneration<P> {
    pin: Option<std::rc::Weak<P>>,
    captured: Option<CapturedRow>,
    complete: bool,
}
/// Append-only weak original registrations. Actor/Runtime owns the originals;
/// failed latest attempts retain cleanup facts but never rearm forward.
struct RowLineage<P> {
    generations: std::cell::RefCell<Vec<RowGeneration<P>>>,
    fence: LifecycleFence,
}
impl<P> RowLineage<P> {
    fn new() -> Self {
        Self {
            generations: std::cell::RefCell::new(Vec::new()),
            fence: LifecycleFence::new(),
        }
    }
    fn begin(&self, old: Option<&std::rc::Rc<P>>) -> io::Result<usize> {
        self.fence.run(false, || {
            let mut entries = self.generations.try_borrow_mut().map_err(denied)?;
            match (entries.last(), old) {
                (None, None) => {}
                (Some(previous), Some(old))
                    if previous.complete
                        && previous
                            .pin
                            .as_ref()
                            .and_then(std::rc::Weak::upgrade)
                            .is_some_and(|pin| std::rc::Rc::ptr_eq(&pin, old)) => {}
                _ => return Err(conflict()),
            }
            entries.try_reserve(1).map_err(denied)?;
            let index = entries.len();
            entries.push(RowGeneration {
                pin: None,
                captured: None,
                complete: false,
            });
            Ok(index)
        })
    }
    fn retain(
        &self,
        index: usize,
        pin: &std::rc::Rc<P>,
        read: impl FnOnce() -> io::Result<CapturedRow>,
        postflight: impl FnOnce(&CapturedRow) -> io::Result<()>,
    ) -> io::Result<()> {
        self.fence.run(false, || {
            {
                let mut entries = self.generations.try_borrow_mut().map_err(denied)?;
                let last = entries.len().checked_sub(1).ok_or_else(conflict)?;
                if entries.iter().any(|previous| {
                    previous
                        .pin
                        .as_ref()
                        .and_then(std::rc::Weak::upgrade)
                        .is_some_and(|old| std::rc::Rc::ptr_eq(&old, pin))
                }) {
                    return Err(conflict());
                }
                let entry = entries.get_mut(index).ok_or_else(conflict)?;
                if last != index || entry.pin.is_some() {
                    return Err(conflict());
                }
                entry.pin = Some(std::rc::Rc::downgrade(pin));
            }
            let captured = read()?;
            self.generations.try_borrow_mut().map_err(denied)?[index].captured =
                Some(captured.clone());
            postflight(&captured)
        })
    }
    fn complete(&self, index: usize) -> io::Result<()> {
        self.fence.run(false, || {
            let mut entries = self.generations.try_borrow_mut().map_err(denied)?;
            if entries.len().checked_sub(1) != Some(index) {
                return Err(conflict());
            }
            let entry = &mut entries[index];
            if entry.complete
                || entry.captured.is_none()
                || entry
                    .pin
                    .as_ref()
                    .and_then(std::rc::Weak::upgrade)
                    .is_none()
            {
                return Err(conflict());
            }
            entry.complete = true;
            Ok(())
        })
    }
    fn original(&self, index: usize) -> io::Result<(std::rc::Rc<P>, CapturedRow)> {
        let entries = self.generations.try_borrow().map_err(denied)?;
        let entry = entries.get(index).ok_or_else(conflict)?;
        Ok((
            entry
                .pin
                .as_ref()
                .and_then(std::rc::Weak::upgrade)
                .ok_or_else(conflict)?,
            entry.captured.clone().ok_or_else(conflict)?,
        ))
    }
    fn read(&self, cleanup: bool) -> io::Result<(std::rc::Rc<P>, CapturedRow)> {
        let entries = self.generations.try_borrow().map_err(denied)?;
        let index = entries.len().checked_sub(1).ok_or_else(conflict)?;
        if !cleanup && (self.fence.revoked.get() || !entries[index].complete) {
            return Err(conflict());
        }
        drop(entries);
        self.original(index)
    }
}
struct LifecycleCall<'a> {
    fence: &'a LifecycleFence,
    complete: bool,
}
impl Drop for LifecycleCall<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.fence.revoked.set(true);
            self.fence.tainted.set(true);
        }
        self.fence.busy.set(false);
    }
}
impl LifecycleFence {
    fn new() -> Self {
        Self {
            busy: Cell::new(false),
            revoked: Cell::new(false),
            tainted: Cell::new(false),
        }
    }
    fn run<T>(&self, cleanup: bool, call: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
        if self.busy.replace(true) {
            self.revoked.set(true);
            self.tainted.set(true);
            return Err(conflict());
        }
        self.tainted.set(false);
        let mut entered = LifecycleCall {
            fence: self,
            complete: false,
        };
        if self.tainted.get() || (!cleanup && self.revoked.get()) {
            return Err(conflict());
        }
        if cleanup {
            self.revoked.set(true);
        }
        let result = call()?;
        if self.tainted.get() || (!cleanup && self.revoked.get()) {
            return Err(conflict());
        }
        entered.complete = true;
        Ok(result)
    }
}

#[cfg(windows)]
pub(crate) mod native {
    use super::*;
    #[cfg(test)]
    use crate::windows::member_carrier_factory_test_os::trace_step;
    use crate::windows::{
        member_carrier_creators as creators,
        member_carrier_guard::{Bindings, NativeGuard, Wfp, WindowBindingAttestor},
        member_carrier_guard_attestor::native::NativeGuardSelection,
        member_carrier_guard_gate::native::NativeGuardResourceSelection,
        member_carrier_key_authority::RuntimeRead,
        member_carrier_member_controller::native::{
            NativeMemberStartedInitial, NativeNeverMemberEffects,
        },
        member_carrier_members::native::MemberInventoryRead,
        member_carrier_module::native::OriginalImage,
        member_carrier_network::native::{NativeClosingNetworkRead, NativeNetworkRead},
        member_carrier_network_baseline::native::NativeNetworkBaselineRead,
        member_carrier_network_gate::native::NativeNetworkGate,
        member_carrier_original_read::OriginalRead,
        member_carrier_pair_store::native_store::NativePairIntentRead,
        member_carrier_probe_gate::native::{NativeProbeResourceState, WfpProbeGate},
        member_carrier_probes::native::{ProbeInventoryRead, ProbeInventoryWeakRead},
        member_carrier_rows::{native::read_original_snapshot, RowRecordReadPin},
        member_carrier_runtime::native::{
            NativeBindingsWindow, NativeClosingRead, NativeLifecycleGate,
            NativeMemberCaptureInputs, NativeResourceRowsRead, NativeRowGenerationCapture,
            NativeSourceRead, RetiredCarrierRead, UnpublishedClosedCarrierRead,
        },
        member_carrier_wintun::{self as wintun, native::OriginalWintun, OriginalSessionRead},
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

    fn native_denied<E>(_: E) -> wintun::Error {
        wintun::Error::Conflict
    }
    // No strong owner here: Source owns member authorities which own G. The
    // actor MUST retain original roots independently before registering them.
    struct Original<T> {
        attempted: Cell<bool>,
        value: RefCell<Option<OriginalRead<T>>>,
    }
    impl<T> Original<T> {
        fn new() -> Self {
            Self {
                attempted: Cell::new(false),
                value: RefCell::new(None),
            }
        }
        fn retain(&self, value: &Rc<T>) -> io::Result<()> {
            if self.attempted.replace(true) {
                return Err(conflict());
            }
            *self.value.try_borrow_mut().map_err(denied)? =
                Some(OriginalRead::from_retained(value));
            Ok(())
        }
        fn read(&self) -> io::Result<Rc<T>> {
            self.value
                .try_borrow()
                .map_err(denied)?
                .as_ref()
                .and_then(OriginalRead::upgrade)
                .ok_or_else(conflict)
        }
    }
    struct Selected {
        pin: OriginalRead<NativePairIntentRead>,
        record: pair::Record,
    }
    enum CaptureOrigin {
        Replacement {
            token: OriginalRead<NativeRowGenerationCapture>,
            old_pin: OriginalRead<RowRecordReadPin>,
            old_seal: OriginalRead<crate::windows::member_carrier_rows::StoppedRowGeneration>,
        },
        Initial {
            started: OriginalRead<NativeMemberStartedInitial>,
            never: OriginalRead<NativeNeverMemberEffects>,
        },
    }
    struct MemberCapture {
        origin: CaptureOrigin,
        pair: OriginalRead<NativePairIntentRead>,
        record: pair::Record,
        binding: rows::Binding,
        generation: Cell<Option<usize>>,
        complete: Cell<bool>,
    }
    impl MemberCapture {
        fn same_replacement(&self, capture: &Rc<NativeRowGenerationCapture>) -> bool {
            matches!(&self.origin, CaptureOrigin::Replacement { token, .. }
                if token.same_original(&OriginalRead::from_retained(capture)))
        }
        fn same_initial(&self, capture: &Rc<NativeMemberStartedInitial>) -> bool {
            matches!(&self.origin, CaptureOrigin::Initial { started, .. }
                if started.same_original(&OriginalRead::from_retained(capture)))
        }
    }
    /// Actual inputs borrowed inside the actor's existing Calling. No receipt
    /// can be constructed here; actor/controller retain the concrete first Start.
    pub(crate) struct NativeInitialMemberCaptureInputs<'a, A: WindowBindingAttestor> {
        pub started: &'a Rc<NativeMemberStartedInitial>,
        pub never: &'a Rc<NativeNeverMemberEffects>,
        pub pair: &'a Rc<NativePairIntentRead>,
        pub record: &'a pair::Record,
        pub binding: &'a rows::Binding,
        pub supervisor: &'a NativeDeadline,
        pub guard: &'a Rc<RefCell<NativeGuard<Wfp, A>>>,
        pub lock: &'a crate::windows::member_carrier_key_authority::KeyLock,
    }
    type ProbeRead<A> = ProbeInventoryRead<Wfp, A, WfpProbeGate<A>>;
    type ProbeWeak<A> = ProbeInventoryWeakRead<Wfp, A, WfpProbeGate<A>>;

    struct Shared<A: WindowBindingAttestor> {
        context: Context,
        runtime: RuntimeRead,
        supervisor: Rc<NativeDeadline>,
        deadline: NativeDeadlineReadPin,
        cancelled: Arc<AtomicBool>,
        fence: LifecycleFence,
        selected: RefCell<Option<Selected>>,
        source: Original<NativeSourceRead>,
        closing: Original<NativeClosingRead>,
        retired: Original<RetiredCarrierRead>,
        unpublished: Original<UnpublishedClosedCarrierRead>,
        originals: Original<creators::Observer<OriginalWintun>>,
        members: Original<MemberInventoryRead>,
        image: Original<OriginalImage>,
        rows: Original<NativeResourceRowsRead>,
        row_pins: [Original<RowRecordReadPin>; 3],
        captured: [RefCell<Option<CapturedRow>>; 3],
        row_generations: [RowLineage<RowRecordReadPin>; 3],
        member_captures: RefCell<Vec<Rc<MemberCapture>>>,
        guard: Original<RefCell<NativeGuard<Wfp, A>>>,
        guard_attestor_selection: Original<NativeGuardSelection>,
        guard_resource_selection: Original<NativeGuardResourceSelection<A>>,
        probes: Original<NativeProbeResourceState<A>>,
        probe_attempted: Cell<bool>,
        probe_inventory: RefCell<Option<ProbeWeak<A>>>,
        network: Original<NativeNetworkGate<A>>,
        network_read: Original<NativeNetworkRead>,
        closing_network: Original<NativeClosingNetworkRead>,
        baseline: Original<NativeNetworkBaselineRead<A>>,
    }
    pub(crate) struct FullNativeLifecycleGate<A: WindowBindingAttestor> {
        shared: Rc<Shared<A>>,
        session: OriginalSessionRead,
        session_pin: Option<wintun::SessionEndRead>,
        ended: Option<wintun::SessionEnded>,
    }
    pub(crate) struct NativeLifecycleSelection<A: WindowBindingAttestor> {
        shared: Rc<Shared<A>>,
    }
    impl<A: WindowBindingAttestor> FullNativeLifecycleGate<A> {
        pub(crate) fn new(
            context: Context,
            runtime: RuntimeRead,
            supervisor: Rc<NativeDeadline>,
            deadline: NativeDeadlineReadPin,
            cancelled: Arc<AtomicBool>,
        ) -> (Self, NativeLifecycleSelection<A>) {
            let shared = Rc::new(Shared {
                context,
                runtime,
                supervisor,
                deadline,
                cancelled,
                fence: LifecycleFence::new(),
                selected: RefCell::new(None),
                source: Original::new(),
                closing: Original::new(),
                retired: Original::new(),
                unpublished: Original::new(),
                originals: Original::new(),
                members: Original::new(),
                image: Original::new(),
                rows: Original::new(),
                row_pins: std::array::from_fn(|_| Original::new()),
                captured: std::array::from_fn(|_| RefCell::new(None)),
                row_generations: std::array::from_fn(|_| RowLineage::new()),
                member_captures: RefCell::new(Vec::new()),
                guard: Original::new(),
                guard_attestor_selection: Original::new(),
                guard_resource_selection: Original::new(),
                probes: Original::new(),
                probe_attempted: Cell::new(false),
                probe_inventory: RefCell::new(None),
                network: Original::new(),
                network_read: Original::new(),
                closing_network: Original::new(),
                baseline: Original::new(),
            });
            (
                Self {
                    shared: shared.clone(),
                    session: OriginalSessionRead::new(),
                    session_pin: None,
                    ended: None,
                },
                NativeLifecycleSelection { shared },
            )
        }
    }
    impl<A: WindowBindingAttestor> NativeLifecycleSelection<A> {
        /// Caller is INSIDE this SAME original Retired terminal-history/full
        /// SDK bracket. This reads actual retained resources only; no recursive
        /// Retired/Source/Pair/Guard transaction, close, unload or effect grant.
        pub(crate) fn verify_full_empty_in_retired_bracket(
            &self,
            original: &Rc<NativePairIntentRead>,
            record: &pair::Record,
            retired: &RetiredCarrierRead,
            bindings: &Bindings,
            history: &[crate::windows::member_carrier_members::ClosedMemberBinding],
        ) -> wintun::Result<()> {
            self.verify_restored_resources_in_retired_bracket(
                original, record, retired, bindings, history, false,
            )
        }
        pub(crate) fn verify_restored_keys_in_retired_bracket(
            &self,
            original: &Rc<NativePairIntentRead>,
            record: &pair::Record,
            retired: &RetiredCarrierRead,
            bindings: &Bindings,
            history: &[crate::windows::member_carrier_members::ClosedMemberBinding],
        ) -> wintun::Result<()> {
            self.verify_restored_resources_in_retired_bracket(
                original, record, retired, bindings, history, true,
            )
        }
        fn verify_restored_resources_in_retired_bracket(
            &self,
            original: &Rc<NativePairIntentRead>,
            record: &pair::Record,
            retired: &RetiredCarrierRead,
            bindings: &Bindings,
            history: &[crate::windows::member_carrier_members::ClosedMemberBinding],
            keys_restored: bool,
        ) -> wintun::Result<()> {
            let shared = &self.shared;
            let compare = if keys_restored {
                compare_restored_keys_guard
            } else {
                compare_full_empty_guard
            };
            shared
                .fence
                .run(true, || {
                    // Reject wrong stages BEFORE SDK reads. Empty JSON is only a
                    // shape comparison; the actual Guard snapshot is checked below.
                    compare(&shared.context, record, &record.guard.expected)?;
                    let source = shared.source.read()?;
                    if !std::ptr::eq(shared.retired.read()?.as_ref(), retired)
                        || !retired.matches_source_origin(&source)
                        || !source.matches_member_inventory(shared.members.read()?.as_ref())
                        || bindings.scope != record.scope
                        || !original.matches_runtime(&shared.runtime)
                    {
                        return Err(conflict());
                    }
                    let current = || {
                        shared.continuity(true)?;
                        if record.phase == pair::Phase::Stopped {
                            original.verify_terminal_entry(
                                &shared.runtime,
                                &shared.context,
                                record,
                            )?;
                        } else {
                            original.verify_cleanup_entry_for(
                                &shared.runtime,
                                &shared.context,
                                record,
                            )?;
                        }
                        // Only the actual Retired callback can supply this witness.
                        // Caller-created matching history outside that bracket denies.
                        retired
                            .inspect_terminal_history_in_bracket(|actual| {
                                if actual != history {
                                    return Err(wintun::Error::Conflict);
                                }
                                Ok(())
                            })
                            .map_err(denied)?;
                        shared.continuity(true)
                    };
                    current()?;
                    let pair_before = shared
                        .runtime
                        .record(&shared.context, RecordKind::Pair)
                        .map_err(denied)?;
                    shared
                        .image
                        .read()?
                        .verify_runtime(&shared.runtime)
                        .map_err(denied)?;
                    for member in record.members.iter().flatten() {
                        if let Some(proof) = member.owner.proof {
                            if !history
                                .iter()
                                .any(|h| h.intent == member.owner.intent && h.proof == proof)
                            {
                                return Err(conflict());
                            }
                        } else if member.owner.phase != crate::member_owner::Phase::Prepared {
                            return Err(conflict());
                        }
                    }
                    let guard = shared.guard.read()?;
                    let before = guard
                        .try_borrow_mut()
                        .map_err(denied)?
                        .snapshot_in_retired_bracket(original, record, retired, bindings)
                        .map_err(denied)?;
                    compare(&shared.context, record, &before)?;
                    let rows_root = shared.rows.read()?;
                    rows_root
                        .inspect_retired_in_bracket(retired, bindings, |facts| {
                            let identities = [
                                bindings.carrier.as_ref().map(|c| &c.identity),
                                bindings.egress[0].as_ref(),
                                bindings.egress[1].as_ref(),
                            ];
                            for (i, identity) in identities.iter().enumerate() {
                                let captured =
                                    shared.captured_row(i, true).map_err(native_denied)?;
                                match (captured.as_ref(), facts.rows[i].as_ref(), *identity) {
                                    (None, None, None) if i != 0 => {}
                                    (Some(captured), Some(row), Some(identity)) => {
                                        let (pin, _) =
                                            shared.row_original(i, true).map_err(native_denied)?;
                                        if !rows_root
                                            .matches_row_original(captured.binding.role, &pin)
                                            || row.binding != captured.binding
                                        {
                                            return Err(wintun::Error::Conflict);
                                        }
                                        compare_full_empty_row(
                                            captured,
                                            &row.acknowledged,
                                            identity,
                                            row.observed.as_ref(),
                                        )
                                        .map_err(native_denied)?;
                                        if i == 0
                                            && record.carrier.is_some_and(|c| c != identity.proof)
                                        {
                                            return Err(wintun::Error::Conflict);
                                        }
                                    }
                                    _ => return Err(wintun::Error::Conflict),
                                }
                            }
                            Ok(())
                        })
                        .map_err(denied)?;
                    shared.probes_retired_origin(true)?;
                    let baseline = shared.baseline.read()?;
                    let reader = shared.network_read.read()?;
                    if !baseline.matches_source_origin(&source) || !baseline.matches_reader(&reader)
                    {
                        return Err(conflict());
                    }
                    let network = shared.network.read()?;
                    if keys_restored {
                        network.verify_restored_keys_in_retired_bracket(
                            record, retired, bindings, &baseline, &reader,
                        )?;
                    } else {
                        network.verify_full_empty_in_retired_bracket(
                            record, retired, bindings, &baseline, &reader,
                        )?;
                    }
                    let after = guard
                        .try_borrow_mut()
                        .map_err(denied)?
                        .snapshot_in_retired_bracket(original, record, retired, bindings)
                        .map_err(denied)?;
                    compare(&shared.context, record, &after)?;
                    if before != after
                        || shared
                            .runtime
                            .record(&shared.context, RecordKind::Pair)
                            .map_err(denied)?
                            != pair_before
                    {
                        return Err(conflict());
                    }
                    current()
                })
                .map_err(native_denied)
        }
        /// FIRST capture only. The actual committed controller receipt and
        /// Never lineage are rooted by actor/controller BEFORE this call. This
        /// read aperture cannot grant weak rows, traffic, ownership or Start.
        pub(crate) fn begin_initial_member_row_capture(
            &self,
            input: NativeInitialMemberCaptureInputs<'_, A>,
        ) -> wintun::Result<()> {
            self.shared
                .fence
                .run(false, || {
                    let selected = Rc::new(MemberCapture {
                        origin: CaptureOrigin::Initial {
                            started: OriginalRead::from_retained(input.started),
                            never: OriginalRead::from_retained(input.never),
                        },
                        pair: OriginalRead::from_retained(input.pair),
                        record: input.record.clone(),
                        binding: input.binding.clone(),
                        generation: Cell::new(None),
                        complete: Cell::new(false),
                    });
                    {
                        let mut entries = self
                            .shared
                            .member_captures
                            .try_borrow_mut()
                            .map_err(denied)?;
                        if entries
                            .iter()
                            .any(|old| old.same_initial(input.started) || !old.complete.get())
                        {
                            return Err(conflict());
                        }
                        entries.try_reserve(1).map_err(denied)?;
                        entries.push(selected.clone()); // SAME original before checks.
                    }
                    compare_member_capture_frame(
                        &self.shared.context,
                        input.record,
                        input.binding,
                        false,
                    )?;
                    let i = role_index(input.binding.role);
                    if self.shared.row_pins[i].attempted.get()
                        || !self.shared.row_generations[i]
                            .generations
                            .try_borrow()
                            .map_err(denied)?
                            .is_empty()
                        || !self.shared.runtime.matches_lock(input.lock)
                        || !std::ptr::eq(input.supervisor, Rc::as_ptr(&self.shared.supervisor))
                        || !Rc::ptr_eq(input.guard, &self.shared.guard.read()?)
                    {
                        return Err(conflict());
                    }
                    self.shared.verify_capture_origin(&selected)?;
                    // Only this actual first-Start capability can select the
                    // committed pendingNone/pre-base READ frame. Ordinary select
                    // remains effect-only and cannot create this aperture.
                    self.shared
                        .retain_selection(input.pair.clone(), input.record)?;
                    self.shared.current(input.record)?;
                    selected
                        .generation
                        .set(Some(self.shared.row_generations[i].begin(None)?));
                    self.shared.current(input.record)
                })
                .map_err(native_denied)
        }
        /// Runtime must first retain_member(SAME pin). This keeps the exact
        /// immutable baseline before fallible native/protected postflight.
        pub(crate) fn retain_initial_member_row_capture(
            &self,
            started: &Rc<NativeMemberStartedInitial>,
            pin: &Rc<RowRecordReadPin>,
        ) -> wintun::Result<()> {
            self.retain_selected_member_capture(|s| s.same_initial(started), pin)
        }
        pub(crate) fn complete_initial_member_row_capture(
            &self,
            started: &Rc<NativeMemberStartedInitial>,
        ) -> wintun::Result<()> {
            self.shared
                .fence
                .run(false, || {
                    let selected = self
                        .shared
                        .member_captures
                        .try_borrow()
                        .map_err(denied)?
                        .iter()
                        .find(|s| s.same_initial(started))
                        .cloned()
                        .ok_or_else(conflict)?;
                    if selected.complete.get() {
                        return Err(conflict());
                    }
                    self.shared.verify_capture_origin(&selected)?;
                    let i = role_index(selected.binding.role);
                    let index = selected.generation.get().ok_or_else(conflict)?;
                    let (pin, _) = self.shared.row_generations[i].original(index)?;
                    self.shared.verify_capture_pin(&selected, &pin)?;
                    self.shared.current(&selected.record)?;
                    self.shared.row_generations[i].complete(index)?;
                    selected.complete.set(true);
                    self.shared.current(&selected.record)
                })
                .map_err(native_denied)
        }
        /// Read-only aperture rooted BEFORE fallible checks. The actual actor
        /// keeps token, old pin/seal and new owner; this G stores weak aliases.
        /// This cannot grant a row effect or reuse/import the old journal.
        pub(crate) fn begin_member_row_capture(
            &self,
            capture: &Rc<NativeRowGenerationCapture>,
            old_pin: &Rc<RowRecordReadPin>,
            old_seal: &Rc<crate::windows::member_carrier_rows::StoppedRowGeneration>,
            input: NativeMemberCaptureInputs<'_>,
        ) -> wintun::Result<()> {
            self.shared
                .fence
                .run(false, || {
                    let selected = Rc::new(MemberCapture {
                        origin: CaptureOrigin::Replacement {
                            token: OriginalRead::from_retained(capture),
                            old_pin: OriginalRead::from_retained(old_pin),
                            old_seal: OriginalRead::from_retained(old_seal),
                        },
                        pair: OriginalRead::from_retained(input.pair),
                        record: input.record.clone(),
                        binding: input.binding.clone(),
                        generation: Cell::new(None),
                        complete: Cell::new(false),
                    });
                    {
                        let mut entries = self
                            .shared
                            .member_captures
                            .try_borrow_mut()
                            .map_err(denied)?;
                        if entries
                            .iter()
                            .any(|old| old.same_replacement(capture) || !old.complete.get())
                        {
                            return Err(conflict());
                        }
                        entries.try_reserve(1).map_err(denied)?;
                        entries.push(selected.clone()); // original selection BEFORE validation.
                    }
                    let i = role_index(input.binding.role);
                    compare_member_capture_frame(
                        &self.shared.context,
                        input.record,
                        input.binding,
                        true,
                    )?;
                    if !self.shared.runtime.matches_lock(input.lock)
                        || !std::ptr::eq(input.supervisor, Rc::as_ptr(&self.shared.supervisor))
                        || Rc::as_ptr(input.guard).cast::<()>()
                            != Rc::as_ptr(&self.shared.guard.read()?).cast::<()>()
                    {
                        return Err(conflict());
                    }
                    input
                        .started
                        .verify_original(
                            input.ticket,
                            input.never,
                            &self.shared.runtime,
                            &self.shared.context,
                        )
                        .map_err(denied)?;
                    input
                        .started
                        .verify_source(&self.shared.source.read()?)
                        .map_err(denied)?;
                    let started = input.started.proof().map_err(denied)?;
                    if input.record.members[i - 1]
                        .as_ref()
                        .and_then(|m| m.owner.proof)
                        != Some(started)
                    {
                        return Err(conflict());
                    }
                    self.shared.verify_capture_origin(&selected)?;
                    // This SAME replacement token selects only its committed
                    // read frame; ordinary lifecycle selection stays effect-only.
                    self.shared
                        .retain_selection(input.pair.clone(), input.record)?;
                    self.shared.current(input.record)?;
                    let (registered, baseline) = self.shared.row_original(i, false)?;
                    if !registered.same_original(old_pin) {
                        return Err(conflict());
                    }
                    old_seal
                        .inspect_original(old_pin, |stopped| {
                            compare_closed_member_ack(
                                &baseline.binding,
                                &baseline.baseline,
                                stopped,
                            )
                            .map_err(|_| rows::Error::Conflict)
                        })
                        .map_err(denied)?;
                    let lineage = &self.shared.row_generations[i];
                    if lineage.generations.try_borrow().map_err(denied)?.is_empty() {
                        let first = lineage.begin(None)?;
                        lineage.retain(first, old_pin, || Ok(baseline), |_| Ok(()))?;
                        lineage.complete(first)?;
                    }
                    selected.generation.set(Some(lineage.begin(Some(old_pin))?));
                    self.shared
                        .source
                        .read()?
                        .inspect_window(|window| {
                            self.shared
                                .capture_window(&selected, window)
                                .map_err(native_denied)
                        })
                        .map_err(denied)?;
                    self.shared.verify_capture_origin(&selected)?;
                    self.shared.current(input.record)
                })
                .map_err(native_denied)
        }
        /// Called ONLY after Runtime retained THIS actual durable baseline pin.
        /// Exact token/pin pointer verification precedes actual SDK postflight;
        /// the new registration survives any Err/unwind and never overwrites old.
        pub(crate) fn retain_member_row_capture(
            &self,
            capture: &Rc<NativeRowGenerationCapture>,
            new_pin: &Rc<RowRecordReadPin>,
        ) -> wintun::Result<()> {
            self.retain_selected_member_capture(|s| s.same_replacement(capture), new_pin)
        }
        fn retain_selected_member_capture(
            &self,
            matches: impl Fn(&MemberCapture) -> bool,
            new_pin: &Rc<RowRecordReadPin>,
        ) -> wintun::Result<()> {
            self.shared
                .fence
                .run(false, || {
                    let selected = self
                        .shared
                        .member_captures
                        .try_borrow()
                        .map_err(denied)?
                        .iter()
                        .find(|s| matches(s))
                        .cloned()
                        .ok_or_else(conflict)?;
                    if selected.complete.get() {
                        return Err(conflict());
                    }
                    let i = role_index(selected.binding.role);
                    let index = selected.generation.get().ok_or_else(conflict)?;
                    self.shared.row_generations[i].retain(
                        index,
                        new_pin,
                        || {
                            new_pin
                                .with_record(
                                    &selected.record.scope,
                                    selected.record.provenance.network_epoch,
                                    |facts| {
                                        compare_member_capture_baseline(
                                            &selected.binding,
                                            facts.acknowledged,
                                        )
                                        .map_err(|_| rows::Error::Conflict)?;
                                        Ok(CapturedRow {
                                            binding: facts.binding.clone(),
                                            baseline: facts.acknowledged.baseline.clone(),
                                        })
                                    },
                                )
                                .map_err(denied)
                        },
                        |baseline| {
                            self.shared.verify_capture_pin(&selected, new_pin)?;
                            self.shared.verify_capture_origin(&selected)?;
                            self.shared
                                .source
                                .read()?
                                .inspect_window(|window| {
                                    self.shared
                                        .capture_window(&selected, window)
                                        .map_err(native_denied)?;
                                    self.shared
                                        .row_ack_original(
                                            window,
                                            selected.binding.role,
                                            false,
                                            new_pin,
                                            baseline,
                                            |ack, actual| {
                                                compare_member_capture_baseline(
                                                    &selected.binding,
                                                    ack,
                                                )?;
                                                if !rows::same_owned(actual, &ack.current) {
                                                    return Err(conflict());
                                                }
                                                Ok(())
                                            },
                                        )
                                        .map_err(native_denied)
                                })
                                .map_err(denied)?;
                            self.shared.current(&selected.record)
                        },
                    )?;
                    // Final token completion belongs to Runtime; this ACK selection
                    // is not forward-ready until explicit complete below.
                    Ok(())
                })
                .map_err(native_denied)
        }
        pub(crate) fn complete_member_row_capture(
            &self,
            capture: &Rc<NativeRowGenerationCapture>,
        ) -> wintun::Result<()> {
            self.shared
                .fence
                .run(false, || {
                    let selected = self
                        .shared
                        .member_captures
                        .try_borrow()
                        .map_err(denied)?
                        .iter()
                        .find(|s| s.same_replacement(capture))
                        .cloned()
                        .ok_or_else(conflict)?;
                    if selected.complete.get() {
                        return Err(conflict());
                    }
                    self.shared.verify_capture_origin(&selected)?;
                    capture
                        .verify_lifecycle_complete(&self.shared.rows.read()?)
                        .map_err(denied)?;
                    self.shared.current(&selected.record)?;
                    self.shared.row_generations[role_index(selected.binding.role)]
                        .complete(selected.generation.get().ok_or_else(conflict)?)?;
                    selected.complete.set(true);
                    self.shared.current(&selected.record)
                })
                .map_err(native_denied)
        }
        fn register<T>(
            &self,
            slot: &Original<T>,
            root: &Rc<T>,
            cleanup: bool,
        ) -> wintun::Result<()> {
            // Retain the exact weak root before any fallible postflight; failure
            // never opens a slot for an equal-data replacement.
            let retained = slot.retain(root);
            if retained.is_err() {
                self.shared.fence.revoked.set(true);
            }
            retained.map_err(native_denied)?;
            self.shared
                .fence
                .run(cleanup, || self.shared.continuity(cleanup))
                .map_err(native_denied)
        }
        pub(crate) fn retain_source(&self, root: &Rc<NativeSourceRead>) -> wintun::Result<()> {
            self.register(&self.shared.source, root, false)
        }
        pub(crate) fn retain_originals(
            &self,
            root: &Rc<creators::Observer<OriginalWintun>>,
        ) -> wintun::Result<()> {
            self.register(&self.shared.originals, root, false)
        }
        pub(crate) fn retain_members(&self, root: &Rc<MemberInventoryRead>) -> wintun::Result<()> {
            self.register(&self.shared.members, root, false)
        }
        pub(crate) fn retain_image(&self, root: &Rc<OriginalImage>) -> wintun::Result<()> {
            self.register(&self.shared.image, root, false)
        }
        pub(crate) fn retain_rows(&self, root: &Rc<NativeResourceRowsRead>) -> wintun::Result<()> {
            self.register(&self.shared.rows, root, false)
        }
        pub(crate) fn retain_guard(
            &self,
            root: &Rc<RefCell<NativeGuard<Wfp, A>>>,
        ) -> wintun::Result<()> {
            self.register(&self.shared.guard, root, false)
        }
        pub(crate) fn retain_probes(
            &self,
            root: &Rc<NativeProbeResourceState<A>>,
        ) -> wintun::Result<()> {
            self.register(&self.shared.probes, root, false)
        }
        /// Actor owns both actual selection handles independently. Registration
        /// is weak/once-only; handles convey original handoff, never permission
        /// in place of the actual Guard's mandatory attestation.
        pub(crate) fn retain_guard_attestor_selection(
            &self,
            root: &Rc<NativeGuardSelection>,
        ) -> wintun::Result<()> {
            self.register(&self.shared.guard_attestor_selection, root, false)
        }
        pub(crate) fn retain_guard_resource_selection(
            &self,
            root: &Rc<NativeGuardResourceSelection<A>>,
        ) -> wintun::Result<()> {
            self.register(&self.shared.guard_resource_selection, root, false)
        }
        pub(crate) fn retain_network(&self, root: &Rc<NativeNetworkGate<A>>) -> wintun::Result<()> {
            self.register(&self.shared.network, root, false)
        }
        pub(crate) fn retain_probe_inventory(&self, original: &ProbeRead<A>) -> wintun::Result<()> {
            self.shared
                .fence
                .run(false, || {
                    if self.shared.probe_attempted.replace(true) {
                        return Err(conflict());
                    }
                    *self
                        .shared
                        .probe_inventory
                        .try_borrow_mut()
                        .map_err(denied)? = Some(original.downgrade());
                    self.shared.probes_retired_origin(false)?;
                    self.shared.continuity(false)
                })
                .map_err(native_denied)
        }
        pub(crate) fn retain_network_read(
            &self,
            root: &Rc<NativeNetworkRead>,
        ) -> wintun::Result<()> {
            self.register(&self.shared.network_read, root, false)
        }
        pub(crate) fn retain_closing_network(
            &self,
            root: &Rc<NativeClosingNetworkRead>,
        ) -> wintun::Result<()> {
            self.register(&self.shared.closing_network, root, true)
        }
        pub(crate) fn retain_closing(&self, root: &Rc<NativeClosingRead>) -> wintun::Result<()> {
            self.register(&self.shared.closing, root, true)?;
            if !root
                .matches_source_origin(self.shared.source.read().map_err(native_denied)?.as_ref())
            {
                return Err(wintun::Error::Conflict);
            }
            Ok(())
        }
        pub(crate) fn retain_row(
            &self,
            role: rows::Role,
            root: &Rc<RowRecordReadPin>,
        ) -> wintun::Result<()> {
            let i = role_index(role);
            self.register(&self.shared.row_pins[i], root, false)?;
            // Capture actual original binding/full baseline ACK, never one from
            // Pair metadata. Keep it before native/protected postflight fails.
            self.shared
                .fence
                .run(false, || {
                    root.with_record(
                        &self.shared.context.intent.scope,
                        self.shared.context.provenance.network_epoch,
                        |facts| {
                            if facts.binding.role != role || facts.acknowledged.pending.is_some() {
                                return Err(rows::Error::Conflict);
                            }
                            *self.shared.captured[i]
                                .try_borrow_mut()
                                .map_err(|_| rows::Error::Conflict)? = Some(CapturedRow {
                                binding: facts.binding.clone(),
                                baseline: facts.acknowledged.baseline.clone(),
                            });
                            let source = self
                                .shared
                                .source
                                .read()
                                .map_err(|_| rows::Error::Conflict)?;
                            source
                                .inspect_window(|window| {
                                    self.shared
                                        .row_ack(window, role, false, |ack, actual| {
                                            if ack != facts.acknowledged || !rows::same_owned(actual, &ack.current) {
                                                #[cfg(test)]
                                                crate::windows::member_carrier_factory_test_os::trace_step(&format!(
                                                    "lifecycle retain_row SDK/ACK comparison error owned_equal={} full_equal={} dad_old={:?} dad_new={:?}",
                                                    rows::same_owned(actual, &ack.current),
                                                    actual == &ack.current,
                                                    ack.current.address.as_ref().map(|a| a.observed.dad_state),
                                                    actual.address.as_ref().map(|a| a.observed.dad_state),
                                                ));
                                                return Err(conflict());
                                            }
                                            Ok(())
                                        })
                                        .map_err(native_denied)
                                })
                                .map_err(|_| rows::Error::Conflict)
                        },
                    )
                    .map_err(denied)?;
                    self.shared.continuity(false)
                })
                .map_err(native_denied)
        }
        /// Pauli's ONLY actual SDK baseline root/read, retained actor-side before
        /// capture. This G never recaptures or accepts caller Snapshot metadata.
        /// Weak registration survives failed postflight without a strong cycle.
        pub(crate) fn retain_network_baseline(
            &self,
            original: &Rc<NativeNetworkBaselineRead<A>>,
        ) -> wintun::Result<()> {
            let result = (|| {
                self.shared.baseline.retain(original)?;
                if !original.matches_source_origin(self.shared.source.read()?.as_ref())
                    || !original.matches_reader(self.shared.network_read.read()?.as_ref())
                {
                    return Err(conflict());
                }
                self.shared.continuity(true)
            })();
            if result.is_err() {
                self.shared.fence.revoked.set(true);
            }
            result.map_err(native_denied)
        }
    }
    impl<A: WindowBindingAttestor> Shared<A> {
        fn verify_capture_origin(&self, selected: &MemberCapture) -> io::Result<()> {
            let pair = selected.pair.upgrade().ok_or_else(conflict)?;
            let replacement = match &selected.origin {
                CaptureOrigin::Replacement {
                    token,
                    old_pin,
                    old_seal,
                } => {
                    token
                        .upgrade()
                        .ok_or_else(conflict)?
                        .verify_lifecycle_origin(
                            &self.rows.read()?,
                            &old_pin.upgrade().ok_or_else(conflict)?,
                            &old_seal.upgrade().ok_or_else(conflict)?,
                            &pair,
                            &selected.record,
                            &selected.binding,
                        )
                        .map_err(denied)?;
                    true
                }
                CaptureOrigin::Initial { started, never } => {
                    let started = started.upgrade().ok_or_else(conflict)?;
                    started
                        .verify_initial_original(
                            &never.upgrade().ok_or_else(conflict)?,
                            &self.runtime,
                            &self.context,
                        )
                        .map_err(denied)?;
                    started
                        .verify_source(&self.source.read()?)
                        .map_err(denied)?;
                    let i = role_index(selected.binding.role);
                    if i == 0
                        || started.slot()
                            != [
                                nelomai_contracts::dispatcher::TunnelSlot::A,
                                nelomai_contracts::dispatcher::TunnelSlot::B,
                            ][i - 1]
                        || started.generation() != 1
                        || selected.record.members[i - 1]
                            .as_ref()
                            .and_then(|m| m.owner.proof)
                            != Some(started.proof().map_err(denied)?)
                    {
                        return Err(conflict());
                    }
                    false
                }
            };
            compare_member_capture_frame(
                &self.context,
                &selected.record,
                &selected.binding,
                replacement,
            )?;
            self.continuity(false)
        }
        fn verify_capture_pin(
            &self,
            selected: &MemberCapture,
            pin: &Rc<RowRecordReadPin>,
        ) -> io::Result<()> {
            match &selected.origin {
                CaptureOrigin::Replacement { token, .. } => token
                    .upgrade()
                    .ok_or_else(conflict)?
                    .verify_lifecycle_pin(&self.rows.read()?, pin)
                    .map_err(denied),
                CaptureOrigin::Initial { .. } => {
                    self.verify_capture_origin(selected)?;
                    if !self
                        .rows
                        .read()?
                        .matches_row_original(selected.binding.role, pin)
                    {
                        return Err(conflict());
                    }
                    Ok(())
                }
            }
        }
        fn capture_window(
            &self,
            selected: &MemberCapture,
            window: &NativeBindingsWindow<'_>,
        ) -> io::Result<()> {
            self.verify_capture_origin(selected)?;
            self.window(&selected.record, window)?;
            let i = role_index(selected.binding.role);
            let slot = if i == 1 {
                nelomai_contracts::dispatcher::TunnelSlot::A
            } else {
                nelomai_contracts::dispatcher::TunnelSlot::B
            };
            if window.closed_member(slot).is_some()
                || window.bindings().egress[i - 1]
                    .as_ref()
                    .is_none_or(|actual| {
                        actual.proof.guid != selected.binding.guid
                            || actual.proof.index != selected.binding.key.index
                            || actual.proof.luid != selected.binding.key.luid
                    })
            {
                return Err(conflict());
            }
            // Only this typed target lacks its NEW baseline. All other rows
            // still join real original ACK/private bytes/full native samples.
            let before = self.capture_guard(selected, window)?;
            self.sibling_rows(&selected.record, window, selected.binding.role)?;
            if self.capture_guard(selected, window)? != before {
                return Err(conflict());
            }
            self.verify_capture_origin(selected)?;
            self.current(&selected.record)
        }
        fn capture_guard(
            &self,
            selected: &MemberCapture,
            window: &NativeBindingsWindow<'_>,
        ) -> io::Result<policy::Snapshot> {
            // Committed capture precedes additive base publication, so the
            // original base may exclude this newly started member. Compare the
            // complete actual WFP state without granting a guard exchange or
            // deriving the new original's ownership from base membership.
            self.window(&selected.record, window)?;
            let guard = self.guard.read()?;
            let snapshot = guard
                .try_borrow_mut()
                .map_err(denied)?
                .snapshot_in_window(window)
                .map_err(denied)?;
            if snapshot != selected.record.guard.expected
                || snapshot
                    .filters
                    .iter()
                    .any(|f| f.action == policy::Action::Permit)
            {
                return Err(conflict());
            }
            self.current(&selected.record)?;
            Ok(snapshot)
        }
        fn capture_observe(&self, record: &pair::Record) -> io::Result<Option<Rc<MemberCapture>>> {
            let selected = self
                .member_captures
                .try_borrow()
                .map_err(denied)?
                .iter()
                .rev()
                .find(|s| !s.complete.get())
                .cloned();
            if let Some(selected) = &selected {
                if &selected.record != record {
                    return Err(conflict());
                }
                self.verify_capture_origin(selected)?;
            }
            Ok(selected)
        }
        fn ordinary_observe_rows(&self, record: &pair::Record) -> io::Result<()> {
            // No missing-target or old-Stopped shortcut. A target whose SDK
            // original is already live needs its precise typed capture aperture
            // until the original new baseline has been durably registered.
            for (slot, member) in record.members.iter().enumerate() {
                if member
                    .as_ref()
                    .is_some_and(|m| m.owner.phase == crate::member_owner::Phase::Running)
                {
                    let row = self.captured_row(slot + 1, false)?.ok_or_else(conflict)?;
                    compare_row_binding(&self.context, record, &row.binding)?;
                }
            }
            Ok(())
        }
        fn row_original(
            &self,
            i: usize,
            cleanup: bool,
        ) -> io::Result<(Rc<RowRecordReadPin>, CapturedRow)> {
            if !self.row_generations[i]
                .generations
                .try_borrow()
                .map_err(denied)?
                .is_empty()
            {
                return self.row_generations[i].read(cleanup);
            }
            Ok((
                self.row_pins[i].read()?,
                self.captured[i]
                    .try_borrow()
                    .map_err(denied)?
                    .as_ref()
                    .cloned()
                    .ok_or_else(conflict)?,
            ))
        }
        fn captured_row(&self, i: usize, cleanup: bool) -> io::Result<Option<CapturedRow>> {
            if !self.row_generations[i]
                .generations
                .try_borrow()
                .map_err(denied)?
                .is_empty()
            {
                return self.row_generations[i]
                    .read(cleanup)
                    .map(|(_, row)| Some(row));
            }
            Ok(self.captured[i].try_borrow().map_err(denied)?.clone())
        }
        fn continuity(&self, cleanup: bool) -> io::Result<()> {
            self.deadline
                .verify_runtime_call(&self.supervisor, &self.runtime, &self.context)
                .map_err(denied)?;
            if !cleanup
                && (self.cancelled.load(Ordering::Acquire)
                    || !self.runtime.fresh(&self.context).map_err(denied)?
                    || self.closing.attempted.get()
                    || self.retired.attempted.get())
            {
                return Err(conflict());
            }
            Ok(())
        }
        fn selected(&self) -> io::Result<(Rc<NativePairIntentRead>, pair::Record)> {
            let selected = self.selected.try_borrow().map_err(denied)?;
            let selected = selected.as_ref().ok_or_else(conflict)?;
            Ok((
                selected.pin.upgrade().ok_or_else(conflict)?,
                selected.record.clone(),
            ))
        }
        // The Pair read completes BEFORE Guard uses its attestor's actual
        // Pair read. Never hold either Pair callback around Guard/SDK joins.
        fn current(&self, expected: &pair::Record) -> io::Result<()> {
            let (pin, record) = self.selected()?;
            if &record != expected || !pin.matches_runtime(&self.runtime) {
                return Err(conflict());
            }
            self.continuity(record.phase == pair::Phase::Closing)?;
            pin.inspect(&self.runtime, &self.supervisor, |actual| {
                if actual != expected {
                    return Err(conflict());
                }
                compare_context(&self.context, actual)
            })?;
            self.continuity(record.phase == pair::Phase::Closing)
        }
        fn select(&self, pin: Rc<NativePairIntentRead>, record: &pair::Record) -> io::Result<()> {
            let cleanup = record.phase == pair::Phase::Closing;
            self.fence.run(cleanup, || {
                compare_context(&self.context, record)?;
                if !pin.matches_runtime(&self.runtime) || record.pending.is_none() {
                    return Err(conflict());
                }
                self.retain_selection(pin, record)?;
                self.current(record)
            })
        }
        fn retain_selection(
            &self,
            pin: Rc<NativePairIntentRead>,
            record: &pair::Record,
        ) -> io::Result<()> {
            let cleanup = record.phase == pair::Phase::Closing;
            if !pin.matches_runtime(&self.runtime) {
                return Err(conflict());
            }
            let mut selected = self.selected.try_borrow_mut().map_err(denied)?;
            if selected.as_ref().is_some_and(|old| {
                record.revision < old.record.revision
                    || (record.revision == old.record.revision
                        && (record != &old.record
                            || !old.pin.same_original(&OriginalRead::from_retained(&pin))))
                    || (old.record.phase == pair::Phase::Closing && !cleanup)
            }) {
                return Err(conflict());
            }
            // Retain current original before fallible current-file validation.
            *selected = Some(Selected {
                pin: OriginalRead::from_retained(&pin),
                record: record.clone(),
            });
            drop(selected);
            Ok(())
        }
        fn registry(
            &self,
            scope: &creators::Scope,
            originals: &creators::Observer<OriginalWintun>,
            cleanup: bool,
        ) -> io::Result<Vec<u8>> {
            let registered = self.originals.read()?;
            if !registered.same_original_registry(originals)
                || originals.context() != &self.context
                || scope.context != self.context
                || scope.binding != self.context.bindings[0]
            {
                return Err(conflict());
            }
            self.members
                .read()?
                .matches_original_runtime_image(&self.runtime, self.image.read()?.as_ref())
                .map_err(denied)?;
            let bytes = self
                .runtime
                .record(&self.context, RecordKind::NativeCarrierReceipts)
                .map_err(denied)?;
            let native =
                crate::member_carrier_native_ownership::Record::decode(&bytes).map_err(denied)?;
            if native.context != self.context
                || native.generation < scope.generation
                || scope.generation == 0
            {
                return Err(conflict());
            }
            self.continuity(cleanup)?;
            Ok(bytes)
        }
        fn window(
            &self,
            record: &pair::Record,
            window: &NativeBindingsWindow<'_>,
        ) -> io::Result<()> {
            let source = self.source.read()?;
            if !window.matches_runtime(&self.runtime) {
                return Err(conflict());
            }
            if record.phase == pair::Phase::Closing {
                let closing = self.closing.read()?;
                if !closing.matches_source_origin(&source) || !window.matches_closing(&closing) {
                    return Err(conflict());
                }
            } else if !window.matches_source(&source) {
                return Err(conflict());
            }
            let bindings = window.bindings();
            if bindings.scope != record.scope
                || bindings.carrier.as_ref().is_none_or(|c| {
                    Some(c.identity.proof) != record.carrier
                        || c.sources
                            != record
                                .addresses
                                .iter()
                                .map(|n| n.addr())
                                .collect::<Vec<_>>()
                })
            {
                return Err(conflict());
            }
            compare_member_bindings(record, &bindings.egress)?;
            self.current(record)
        }
        fn row_ack<T>(
            &self,
            window: &NativeBindingsWindow<'_>,
            role: rows::Role,
            cleanup: bool,
            callback: impl FnOnce(&rows::Record, &rows::Snapshot) -> io::Result<T>,
        ) -> io::Result<T> {
            let i = role_index(role);
            let (pin, baseline) = self.row_original(i, cleanup)?;
            self.row_ack_original(window, role, cleanup, &pin, &baseline, callback)
        }
        /// Dedicated Closing READ lane; never ordinary ResourceRowsFacts or a
        /// permission predicate. The same original pin/attempt stays inside
        /// its callback while private bytes and full SDK snapshots are joined.
        fn closing_rows_observe(
            &self,
            record: &pair::Record,
            selected_role: rows::Role,
            window: &NativeBindingsWindow<'_>,
        ) -> io::Result<()> {
            let closing = self.closing.read()?;
            if !window.matches_closing(&closing)
                || !window.matches_runtime(&self.runtime)
                || !closing.matches_source_origin(self.source.read()?.as_ref())
            {
                return Err(conflict());
            }
            self.window(record, window)?;
            for i in 0..3 {
                let role = [
                    rows::Role::Carrier,
                    rows::Role::MemberA,
                    rows::Role::MemberB,
                ][i];
                let closed = if i == 0 {
                    None
                } else {
                    window.closed_member(
                        [
                            nelomai_contracts::dispatcher::TunnelSlot::A,
                            nelomai_contracts::dispatcher::TunnelSlot::B,
                        ][i - 1],
                    )
                };
                let Some(baseline) = self.captured_row(i, true)? else {
                    if i == 0
                        || closed.is_some()
                        || self.row_pins[i].attempted.get()
                        || record.members[i - 1].as_ref().is_some_and(|member| {
                            member.owner.phase != crate::member_owner::Phase::Prepared
                                || member.owner.proof.is_some()
                                || member.owner.retired_proof.is_some()
                        })
                        || window.bindings().egress[i - 1].is_some()
                    {
                        return Err(conflict());
                    }
                    continue;
                };
                let (pin, _) = self.row_original(i, true)?;
                if !self.rows.read()?.matches_row_original(role, &pin) {
                    return Err(conflict());
                }
                let kind = [
                    RecordKind::CarrierRows,
                    RecordKind::MemberARows,
                    RecordKind::MemberBRows,
                ][i];
                pin.with_cleanup_record(&record.scope, record.provenance.network_epoch, |ack| {
                    if ack.binding != &baseline.binding
                        || ack.acknowledged.baseline != baseline.baseline
                    {
                        return Err(rows::Error::Conflict);
                    }
                    window
                        .inspect(|_| {
                            let bytes = self
                                .runtime
                                .record(&self.context, kind)
                                .map_err(native_denied)?;
                            let protected = rows::Record::decode(&bytes).map_err(native_denied)?;
                            if let Some(history) = closed {
                                // Typed Stop history/full absence ONLY. Never use an
                                // attempt as Stopped ACK and never query its old NIC.
                                let provider = history
                                    .comparison_provider(&self.context)
                                    .map_err(native_denied)?;
                                if provider.identity.guid != baseline.binding.guid
                                    || provider.identity.index != baseline.binding.key.index
                                    || provider.identity.luid != baseline.binding.key.luid
                                    || provider.identity.name != baseline.binding.name
                                    || &protected != ack.acknowledged
                                {
                                    return Err(wintun::Error::Conflict);
                                }
                                compare_closed_member_ack(
                                    &baseline.binding,
                                    &baseline.baseline,
                                    ack.acknowledged,
                                )
                                .map_err(native_denied)?;
                            } else {
                                // A sibling's real partial Delete/held-exit facts
                                // permit only factual stopped-row comparison.
                                // The selected row still needs its live effect read.
                                let partial = if i != 0 && role != selected_role {
                                    window
                                        .partial_member(
                                            [
                                                nelomai_contracts::dispatcher::TunnelSlot::A,
                                                nelomai_contracts::dispatcher::TunnelSlot::B,
                                            ][i - 1],
                                        )
                                        .filter(|(intent, process, deleted, _)| {
                                            *deleted
                                                && process.is_some()
                                                && record.members[i - 1].as_ref().is_some_and(|m| {
                                                    m.owner.intent == *intent
                                                        && m.owner
                                                            .proof
                                                            .or(m.owner.retired_proof)
                                                            .is_some_and(|p| {
                                                                Some(p.process) == *process
                                                            })
                                                })
                                        })
                                } else {
                                    None
                                };
                                let (actual, interface_absent) = if partial
                                    .is_some_and(|(_, _, _, present)| !present)
                                {
                                    (None, false)
                                } else {
                                    match read_original_snapshot(&baseline.binding) {
                                        Ok(actual) => (Some(actual), false),
                                        Err(rows::Error::InterfaceAbsent) if partial.is_some() => {
                                            (None, true)
                                        }
                                        Err(error) => return Err(native_denied(error)),
                                    }
                                };
                                if actual.is_none() {
                                    compare_row_binding(&self.context, record, &baseline.binding)
                                        .map_err(native_denied)?;
                                    if ack.acknowledged != &protected {
                                        return Err(wintun::Error::Conflict);
                                    }
                                    compare_closed_member_ack(
                                        &baseline.binding,
                                        &baseline.baseline,
                                        ack.acknowledged,
                                    )
                                    .map_err(native_denied)?;
                                    if interface_absent
                                        && !matches!(
                                            read_original_snapshot(&baseline.binding),
                                            Err(rows::Error::InterfaceAbsent)
                                        )
                                    {
                                        return Err(wintun::Error::Conflict);
                                    }
                                    if self
                                        .runtime
                                        .record(&self.context, kind)
                                        .map_err(native_denied)?
                                        != bytes
                                    {
                                        return Err(wintun::Error::Conflict);
                                    }
                                    return Ok(());
                                }
                                let actual = actual.ok_or(wintun::Error::Conflict)?;
                                if ack.acknowledged == &protected {
                                    compare_closing_row_observation(ClosingRowObservation {
                                        context: &self.context,
                                        pair: record,
                                        original: &baseline,
                                        acknowledged: ack.acknowledged,
                                        protected: &protected,
                                        actual: &actual,
                                        attempt: None,
                                    })
                                    .map_err(native_denied)?;
                                } else {
                                    pin.with_cleanup_write_attempt(
                                        &record.scope,
                                        record.provenance.network_epoch,
                                        |attempt| {
                                            if attempt.binding != ack.binding
                                                || attempt.acknowledged != ack.acknowledged
                                            {
                                                return Err(rows::Error::Conflict);
                                            }
                                            compare_closing_row_observation(
                                                ClosingRowObservation {
                                                    context: &self.context,
                                                    pair: record,
                                                    original: &baseline,
                                                    acknowledged: ack.acknowledged,
                                                    protected: &protected,
                                                    actual: &actual,
                                                    attempt: Some((
                                                        attempt.before,
                                                        attempt.desired,
                                                    )),
                                                },
                                            )
                                            .map_err(|_| rows::Error::Conflict)?;
                                            // These reads are INSIDE the immutable attempt
                                            // callback, before its pointer/ACK postflight.
                                            if self
                                                .runtime
                                                .record(&self.context, kind)
                                                .map_err(|_| rows::Error::Journal)?
                                                != bytes
                                                || read_original_snapshot(&baseline.binding)?
                                                    != actual
                                            {
                                                return Err(rows::Error::Conflict);
                                            }
                                            Ok(())
                                        },
                                    )
                                    .map_err(native_denied)?;
                                }
                                if read_original_snapshot(&baseline.binding)
                                    .map_err(native_denied)?
                                    != actual
                                {
                                    return Err(wintun::Error::Conflict);
                                }
                            }
                            if self
                                .runtime
                                .record(&self.context, kind)
                                .map_err(native_denied)?
                                != bytes
                            {
                                return Err(wintun::Error::Conflict);
                            }
                            Ok(())
                        })
                        .map_err(|_| rows::Error::Conflict)
                })
                .map_err(denied)?;
            }
            self.current(record)
        }
        fn row_ack_original<T>(
            &self,
            window: &NativeBindingsWindow<'_>,
            role: rows::Role,
            cleanup: bool,
            pin: &RowRecordReadPin,
            baseline: &CapturedRow,
            callback: impl FnOnce(&rows::Record, &rows::Snapshot) -> io::Result<T>,
        ) -> io::Result<T> {
            let i = role_index(role);
            if !self.rows.read()?.matches_row_original(role, pin) {
                return Err(conflict());
            }
            let call = |facts: crate::windows::member_carrier_rows::RowRecordFacts<'_>| {
                let kind = [
                    RecordKind::CarrierRows,
                    RecordKind::MemberARows,
                    RecordKind::MemberBRows,
                ][i];
                if facts.binding != &baseline.binding
                    || facts.acknowledged.baseline != baseline.baseline
                {
                    return Err(rows::Error::Conflict);
                }
                window
                    .inspect(|_| {
                        let before = self
                            .runtime
                            .record(&self.context, kind)
                            .map_err(native_denied)?;
                        let protected = rows::Record::decode(&before).map_err(native_denied)?;
                        let observed =
                            read_original_snapshot(facts.binding).map_err(native_denied)?;
                        if &protected != facts.acknowledged || protected.binding != *facts.binding {
                            return Err(wintun::Error::Conflict);
                        }
                        let result = callback(facts.acknowledged, &observed).map_err(native_denied);
                        if self
                            .runtime
                            .record(&self.context, kind)
                            .map_err(native_denied)?
                            != before
                            || read_original_snapshot(facts.binding).map_err(native_denied)?
                                != observed
                        {
                            return Err(wintun::Error::Conflict);
                        }
                        result
                    })
                    .map_err(|_| rows::Error::Conflict)
            };
            if cleanup {
                pin.with_cleanup_record(
                    &self.context.intent.scope,
                    self.context.provenance.network_epoch,
                    call,
                )
            } else {
                pin.with_record(
                    &self.context.intent.scope,
                    self.context.provenance.network_epoch,
                    call,
                )
            }
            .map_err(denied)
        }
        fn blocks(
            &self,
            record: &pair::Record,
            window: &NativeBindingsWindow<'_>,
        ) -> io::Result<policy::Snapshot> {
            self.window(record, window)?;
            let guard = self.guard.read()?;
            let snapshot = guard
                .try_borrow_mut()
                .map_err(denied)?
                .snapshot_in_window(window)
                .map_err(denied)?;
            compare_guard_blocks(record, &snapshot)?;
            self.current(record)?;
            Ok(snapshot)
        }
        /// Join every sibling without invoking ANY RowOwner/Authority. During
        /// stage6 member NICs are already absent: use same-original closed
        /// histories plus stopped protected ACKs, never old SDK indices.
        fn sibling_rows(
            &self,
            record: &pair::Record,
            window: &NativeBindingsWindow<'_>,
            active: rows::Role,
        ) -> io::Result<()> {
            let cleanup = record.phase == pair::Phase::Closing;
            for i in 0..3 {
                let role = [
                    rows::Role::Carrier,
                    rows::Role::MemberA,
                    rows::Role::MemberB,
                ][i];
                let closed = if i == 0 {
                    None
                } else {
                    window.closed_member(if i == 1 {
                        nelomai_contracts::dispatcher::TunnelSlot::A
                    } else {
                        nelomai_contracts::dispatcher::TunnelSlot::B
                    })
                };
                if role == active {
                    continue;
                }
                let captured = self.captured_row(i, cleanup)?;
                let Some(captured) = captured.as_ref() else {
                    if i == 0
                        || closed.is_some()
                        || self.row_pins[i].attempted.get()
                        || record.members[i - 1].as_ref().is_some_and(|member| {
                            member.owner.phase != crate::member_owner::Phase::Prepared
                                || member.owner.proof.is_some()
                                || member.owner.retired_proof.is_some()
                        })
                        || window.bindings().egress[i - 1].is_some()
                    {
                        return Err(conflict());
                    }
                    continue;
                };
                if let Some(history) = closed {
                    let provider = history.comparison_provider(&self.context).map_err(denied)?;
                    if provider.identity.guid != captured.binding.guid
                        || provider.identity.index != captured.binding.key.index
                        || provider.identity.luid != captured.binding.key.luid
                        || provider.identity.name != captured.binding.name
                    {
                        return Err(conflict());
                    }
                } else if cleanup && record.stop_stage >= 6 && i > 0 {
                    return Err(conflict());
                }
                let compare = |ack: &rows::Record| {
                    ack.validate().map_err(denied)?;
                    if ack.binding != captured.binding
                        || ack.baseline != captured.baseline
                        || ack.pending.is_some()
                        || ack.current.interface.policy.forwarding
                        || ack.current.interface.policy.advertising
                    {
                        return Err(conflict());
                    }
                    if closed.is_some()
                        && (ack.phase != rows::Phase::Stopped
                            || ack.current.interface.policy != ack.baseline.interface.policy
                            || ack.current.address.is_some())
                    {
                        return Err(conflict());
                    }
                    if !cleanup && closed.is_none() {
                        compare_row_binding(&self.context, record, &ack.binding)?;
                    }
                    if i > 0
                        && (ack.creation.is_some()
                            || ack.current.address.is_some()
                            || ack.baseline.address.is_some())
                    {
                        return Err(conflict());
                    }
                    Ok(())
                };
                if closed.is_some() {
                    let (pin, _) = self.row_original(i, cleanup)?;
                    if !self.rows.read()?.matches_row_original(role, &pin) {
                        return Err(conflict());
                    }
                    pin.with_cleanup_record(
                        &record.scope,
                        record.provenance.network_epoch,
                        |facts| {
                            let kind = [
                                RecordKind::CarrierRows,
                                RecordKind::MemberARows,
                                RecordKind::MemberBRows,
                            ][i];
                            let raw = self
                                .runtime
                                .record(&self.context, kind)
                                .map_err(|_| rows::Error::Conflict)?;
                            let protected = rows::Record::decode(&raw)?;
                            if &protected != facts.acknowledged {
                                return Err(rows::Error::Conflict);
                            }
                            compare(facts.acknowledged).map_err(|_| rows::Error::Conflict)?;
                            compare_closed_member_ack(
                                &captured.binding,
                                &captured.baseline,
                                facts.acknowledged,
                            )
                            .map_err(|_| rows::Error::Conflict)?;
                            if self
                                .runtime
                                .record(&self.context, kind)
                                .map_err(|_| rows::Error::Conflict)?
                                != raw
                            {
                                return Err(rows::Error::Conflict);
                            }
                            Ok(())
                        },
                    )
                    .map_err(denied)?;
                } else {
                    self.row_ack(window, role, cleanup, |ack, actual| {
                        compare(ack)?;
                        if !rows::same_owned(actual, &ack.current) {
                            return Err(conflict());
                        }
                        Ok(())
                    })?;
                }
            }
            Ok(())
        }
        fn resources_restored(
            &self,
            record: &pair::Record,
            window: &NativeBindingsWindow<'_>,
        ) -> io::Result<()> {
            self.window(record, window)?;
            // Concrete original methods, not permissive opaque resource traits.
            // These lifecycle-specific APIs must attest their actual owner ACKs
            // without re-entering Pair/Guard/Source or borrowed mutable State.
            self.probes_retired_origin(true)?;
            let baseline = self.baseline.read()?;
            let source = self.source.read()?;
            let network = self.network_read.read()?;
            if !baseline.matches_source_origin(&source) || !baseline.matches_reader(&network) {
                return Err(conflict());
            }
            let expected = baseline.snapshot();
            self.network
                .read()?
                .verify_lifecycle_restored(record, window, &baseline)?;
            self.closing_network
                .read()?
                .inspect_in_window(window, |facts| {
                    if &facts.dns != expected
                        || facts.routes.pending.is_some()
                        || !facts.routes.current.is_empty()
                        || record.network.as_ref().is_some_and(|n| {
                            n.pending.is_some()
                                || n.current != n.baseline
                                || !n.current.routes.is_empty()
                                || n.baseline.dns.as_ref() != Some(expected)
                        })
                    {
                        return Err(conflict());
                    }
                    Ok(())
                })?;
            self.current(record)
        }
        fn probes_retired_origin(&self, require_retired: bool) -> io::Result<()> {
            let weak = self.probe_inventory.try_borrow().map_err(denied)?;
            let actual = weak
                .as_ref()
                .ok_or_else(conflict)?
                .upgrade()
                .map_err(denied)?;
            let state = self.probes.read()?;
            actual
                .matches_caps(&self.source.read()?, &self.guard.read()?, &state.gate())
                .map_err(denied)?;
            if require_retired {
                actual.inspect_retired().map_err(denied)?;
            }
            Ok(())
        }
        fn members_closed(
            &self,
            scope: &creators::Scope,
            originals: &creators::Observer<OriginalWintun>,
        ) -> io::Result<()> {
            let actual = originals
                .observe_all_for_cleanup(&self.context)
                .map_err(denied)?;
            if actual.originals.len() != 1 || actual.originals[0].scope != *scope {
                return Err(conflict());
            }
            let identity = &actual.originals[0].identity;
            let carrier = [crate::windows::member_carrier_provider::ExpectedProvider {
                identity: crate::windows::member_carrier_provider::Expected {
                    guid: identity.guid,
                    luid: identity.luid,
                    index: identity.index,
                    name: identity.name.clone(),
                    description: identity.description.clone(),
                    if_type: identity.if_type,
                    tunnel_type: identity.tunnel_type,
                },
                kind: crate::windows::member_carrier_provider::ProviderKind::Wintun,
            }];
            self.members
                .read()?
                .inspect_closing_bindings_full(
                    &self.context,
                    &self.runtime,
                    self.image.read()?.as_ref(),
                    &carrier,
                    |live, history, domains, partials| {
                        if !live.is_empty() || !domains.is_empty() || !partials.is_empty() {
                            return Err(crate::member_carrier::CarrierError::Conflict);
                        }
                        // Any captured row root MUST have a SAME closed original history.
                        for i in 1..3 {
                            if let Some(row) = self
                                .captured_row(i, true)
                                .map_err(|_| crate::member_carrier::CarrierError::Conflict)?
                                .as_ref()
                            {
                                if !history.iter().any(|h| {
                                    h.comparison_provider(&self.context).is_ok_and(|p| {
                                        p.identity.guid == row.binding.guid
                                            && p.identity.index == row.binding.key.index
                                            && p.identity.luid == row.binding.key.luid
                                    })
                                }) {
                                    return Err(crate::member_carrier::CarrierError::Conflict);
                                }
                            }
                        }
                        Ok(())
                    },
                )
                .map_err(denied)
        }
    }
    impl<A: WindowBindingAttestor> FullNativeLifecycleGate<A> {
        fn ended(&mut self) -> io::Result<()> {
            self.session.no_live_session().map_err(denied)?;
            let session = self.session_pin.as_ref().ok_or_else(conflict)?;
            if self.ended.is_none() {
                self.ended = Some(session.acknowledged().map_err(denied)?);
            }
            session
                .verify_acknowledged(self.ended.as_ref().ok_or_else(conflict)?)
                .map_err(denied)
        }
        fn authorize_row(
            &self,
            scope: &creators::Scope,
            binding: &rows::Binding,
            target: &rows::Target,
            originals: &creators::Observer<OriginalWintun>,
        ) -> wintun::Result<()> {
            let shared = &self.shared;
            let (_, record) = shared.selected().map_err(native_denied)?;
            let cleanup = record.phase == pair::Phase::Closing;
            shared
                .fence
                .run(cleanup, || {
                    compare_row_stage(&shared.context, &record, binding.role, target).inspect_err(
                        |_error| {
                            #[cfg(test)]
                            trace_step(&format!("lifecycle row stage error={_error:?}"));
                        },
                    )?;
                    if !cleanup {
                        self.session.live().map_err(denied)?;
                    }
                    shared.current(&record).inspect_err(|_error| {
                        #[cfg(test)]
                        trace_step(&format!("lifecycle row current before error={_error:?}"));
                    })?;
                    let registry =
                        shared
                            .registry(scope, originals, cleanup)
                            .inspect_err(|_error| {
                                #[cfg(test)]
                                trace_step(&format!(
                                    "lifecycle row registry before error={_error:?}"
                                ));
                            })?;
                    let verify = |window: &NativeBindingsWindow<'_>| {
                        shared
                            .window(&record, window)
                            .inspect_err(|_error| {
                                #[cfg(test)]
                                trace_step(&format!(
                                    "lifecycle row window before error={_error:?}"
                                ));
                            })
                            .map_err(native_denied)?;
                        let member_slot = match binding.role {
                            rows::Role::Carrier => None,
                            rows::Role::MemberA => {
                                Some(nelomai_contracts::dispatcher::TunnelSlot::A)
                            }
                            rows::Role::MemberB => {
                                Some(nelomai_contracts::dispatcher::TunnelSlot::B)
                            }
                        };
                        if member_slot.is_some_and(|slot| window.closed_member(slot).is_some()) {
                            return Err(wintun::Error::Conflict);
                        }
                        let before = shared
                            .blocks(&record, window)
                            .inspect_err(|_error| {
                                #[cfg(test)]
                                trace_step(&format!(
                                    "lifecycle row blocks before error={_error:?}"
                                ));
                            })
                            .map_err(native_denied)?;
                        if cleanup {
                            shared
                                .resources_restored(&record, window)
                                .inspect_err(|_error| {
                                    #[cfg(test)]
                                    trace_step(&format!(
                                        "lifecycle row resources_restored error={_error:?}"
                                    ));
                                })
                                .map_err(native_denied)?;
                        }
                        if target == &rows::Target::Delete {
                            shared
                                .members_closed(scope, originals)
                                .map_err(native_denied)?;
                        }
                        if cleanup {
                            // Factual unresolved sibling observations must not
                            // become effect ACKs for the selected target below.
                            shared
                                .closing_rows_observe(&record, binding.role, window)
                                .inspect_err(|_error| {
                                    #[cfg(test)]
                                    trace_step(&format!(
                                        "lifecycle row closing_rows_observe error={_error:?}"
                                    ));
                                })
                                .map_err(native_denied)?;
                        } else {
                            shared
                                .sibling_rows(&record, window, binding.role)
                                .map_err(native_denied)?;
                        }
                        shared
                            .row_ack(
                                window,
                                binding.role,
                                cleanup || retiring_member_row(&record, binding.role, target),
                                |ack, actual| {
                                    compare_row_effect(
                                        &shared.context,
                                        &record,
                                        binding,
                                        target,
                                        ack,
                                        ack,
                                        actual,
                                    )
                                },
                            )
                            .inspect_err(|_error| {
                                #[cfg(test)]
                                trace_step(&format!("lifecycle row row_ack error={_error:?}"));
                            })
                            .map_err(native_denied)?;
                        if shared
                            .blocks(&record, window)
                            .inspect_err(|_error| {
                                #[cfg(test)]
                                trace_step(&format!("lifecycle row blocks after error={_error:?}"));
                            })
                            .map_err(native_denied)?
                            != before
                        {
                            #[cfg(test)]
                            trace_step("lifecycle row blocks drift");
                            return Err(wintun::Error::Conflict);
                        }
                        shared
                            .window(&record, window)
                            .inspect_err(|_error| {
                                #[cfg(test)]
                                trace_step(&format!("lifecycle row window after error={_error:?}"));
                            })
                            .map_err(native_denied)
                    };
                    if cleanup {
                        shared.closing.read()?.inspect_window(verify)
                    } else if binding.role == rows::Role::Carrier {
                        shared
                            .source
                            .read()?
                            .inspect_row_effect_window(binding, target, verify)
                    } else {
                        shared.source.read()?.inspect_window(verify)
                    }
                    .inspect_err(|_error| {
                        #[cfg(test)]
                        trace_step(&format!(
                            "lifecycle row Source/Closing window error={_error:?}"
                        ));
                    })
                    .map_err(denied)?;
                    if registry
                        != shared
                            .registry(scope, originals, cleanup)
                            .inspect_err(|_error| {
                                #[cfg(test)]
                                trace_step(&format!(
                                    "lifecycle row registry after error={_error:?}"
                                ));
                            })?
                    {
                        #[cfg(test)]
                        trace_step("lifecycle row registry drift");
                        return Err(conflict());
                    }
                    shared.current(&record).inspect_err(|_error| {
                        #[cfg(test)]
                        trace_step(&format!("lifecycle row current after error={_error:?}"));
                    })?;
                    if !cleanup {
                        self.session.live().map_err(denied)?;
                    }
                    Ok(())
                })
                .map_err(native_denied)
        }
        fn authorize_stage(
            &mut self,
            scope: &creators::Scope,
            stage: LifecycleStage,
            originals: &creators::Observer<OriginalWintun>,
        ) -> wintun::Result<()> {
            let shared = self.shared.clone();
            let (_, record) = shared.selected().map_err(native_denied)?;
            let cleanup = record.phase == pair::Phase::Closing;
            shared
                .fence
                .run(cleanup, || {
                    let capture = if !cleanup && stage == LifecycleStage::Observe {
                        shared.capture_observe(&record)?
                    } else {
                        None
                    };
                    if capture.is_none() {
                        // Ordinary Observe remains effect-only. Only the
                        // exact typed member capture can observe its
                        // pendingNone committed pre-base frame.
                        compare_lifecycle_stage(&shared.context, &record, stage)?;
                    }
                    if !cleanup {
                        self.session.live().map_err(denied)?;
                    }
                    let registry = shared.registry(scope, originals, cleanup)?;
                    shared.current(&record)?;
                    if stage == LifecycleStage::AfterClose {
                        self.ended()?;
                        let retired = shared.retired.read()?;
                        if !retired.matches_source_origin(shared.source.read()?.as_ref()) {
                            return Err(conflict());
                        }
                        originals
                            .assert_closed_for_cleanup(&shared.context, &scope.binding)
                            .map_err(denied)?;
                        retired
                            .inspect_bindings(|bindings| {
                                shared
                                    .verify_after_close(&record, &retired, bindings)
                                    .map_err(native_denied)
                            })
                            .map_err(denied)?;
                        self.ended()?;
                    } else if matches!(stage, LifecycleStage::End | LifecycleStage::Close) {
                        if stage == LifecycleStage::End {
                            self.session.endable().map_err(denied)?;
                        } else {
                            self.ended()?;
                        }
                        shared
                            .closing
                            .read()?
                            .inspect_window(|window| {
                                let before =
                                    shared.blocks(&record, window).map_err(native_denied)?;
                                shared
                                    .resources_restored(&record, window)
                                    .map_err(native_denied)?;
                                shared
                                    .members_closed(scope, originals)
                                    .map_err(native_denied)?;
                                shared
                                    .sibling_rows(&record, window, rows::Role::Carrier)
                                    .map_err(native_denied)?;
                                shared
                                    .row_ack(window, rows::Role::Carrier, true, |ack, actual| {
                                        compare_closed_carrier_row(
                                            &shared.context,
                                            &record,
                                            ack,
                                            actual,
                                        )
                                    })
                                    .map_err(native_denied)?;
                                if shared.blocks(&record, window).map_err(native_denied)? != before
                                {
                                    return Err(wintun::Error::Conflict);
                                }
                                Ok(())
                            })
                            .map_err(denied)?;
                        if stage == LifecycleStage::End {
                            self.session.endable().map_err(denied)?;
                        } else {
                            self.ended()?;
                        }
                    } else {
                        // Observe is READ-only and occurs during RowOwner SDK
                        // before/after while pending still exists. It does not grant
                        // CAS and cannot insist that a stable sampler accepts pending.
                        let verify = |window: &NativeBindingsWindow<'_>| {
                            shared.window(&record, window).map_err(native_denied)?;
                            if cleanup
                                && matches!(
                                    (record.stop_stage, record.pending),
                                    (3, Some(pair::Effect::RestoreWeak))
                                        | (6, Some(pair::Effect::CarrierAddressDelete))
                                )
                            {
                                shared
                                    .closing_rows_observe(&record, rows::Role::Carrier, window)
                                    .map_err(native_denied)?;
                            }
                            Ok(())
                        };
                        if cleanup {
                            shared.closing.read()?.inspect_window(verify)
                        } else if let Some(capture) = capture {
                            shared.source.read()?.inspect_window(|window| {
                                shared
                                    .capture_window(&capture, window)
                                    .map_err(native_denied)
                            })
                        } else {
                            shared.ordinary_observe_rows(&record)?;
                            let cpin = shared.row_pins[0].read()?;
                            cpin.with_record(
                                &record.scope,
                                record.provenance.network_epoch,
                                |facts| {
                                    if let Some(pending) = &facts.acknowledged.pending {
                                        shared
                                            .source
                                            .read()
                                            .map_err(|_| rows::Error::Conflict)?
                                            .inspect_row_effect_window(
                                                facts.binding,
                                                &pending.target,
                                                verify,
                                            )
                                            .map_err(|_| rows::Error::Conflict)
                                    } else {
                                        shared
                                            .source
                                            .read()
                                            .map_err(|_| rows::Error::Conflict)?
                                            .inspect_window(verify)
                                            .map_err(|_| rows::Error::Conflict)
                                    }
                                },
                            )
                            .map_err(native_denied)
                        }
                        .map_err(denied)?;
                    }
                    if registry != shared.registry(scope, originals, cleanup)? {
                        return Err(conflict());
                    }
                    shared.current(&record)?;
                    if !cleanup {
                        self.session.live().map_err(denied)?;
                    }
                    Ok(())
                })
                .map_err(native_denied)
        }
    }
    impl<A: WindowBindingAttestor> Shared<A> {
        // Called only INSIDE actual retired full-native EMPTY bracket. Do not
        // enter Retired, Source, Pair or an old C DNS SDK reader from this helper.
        fn verify_after_close(
            &self,
            record: &pair::Record,
            retired: &RetiredCarrierRead,
            bindings: &Bindings,
        ) -> io::Result<()> {
            self.continuity(true)?;
            let (original, _) = self.selected()?;
            if bindings.scope != record.scope
                || !retired.matches_source_origin(self.source.read()?.as_ref())
            {
                return Err(conflict());
            }
            let guard = self.guard.read()?;
            let before = guard
                .try_borrow_mut()
                .map_err(denied)?
                .snapshot_in_retired_bracket(&original, record, retired, bindings)
                .map_err(denied)?;
            compare_guard_blocks(record, &before)?;
            self.rows
                .read()?
                .inspect_retired_in_bracket(retired, bindings, |facts| {
                    for i in 0..3 {
                        let captured = self.captured_row(i, true).map_err(native_denied)?;
                        match (captured.as_ref(), facts.rows[i].as_ref()) {
                            (None, None) => (),
                            (Some(original), Some(actual))
                                if actual.binding == original.binding
                                    && actual.acknowledged.baseline == original.baseline
                                    && actual.observed.is_none()
                                    && actual.acknowledged.phase == rows::Phase::Stopped
                                    && actual.acknowledged.pending.is_none()
                                    && actual.acknowledged.current.interface.policy
                                        == actual.acknowledged.baseline.interface.policy
                                    && actual.acknowledged.current.address.is_none() => {}
                            _ => return Err(wintun::Error::Conflict),
                        }
                    }
                    Ok(())
                })
                .map_err(denied)?;
            self.probes_retired_origin(true)?;
            let initial = self.baseline.read()?;
            if !initial.matches_source_origin(self.source.read()?.as_ref())
                || !initial.matches_reader(self.network_read.read()?.as_ref())
            {
                return Err(conflict());
            }
            self.network
                .read()?
                .verify_lifecycle_retired_in_bracket(record, retired, bindings, &initial)?;
            let after = guard
                .try_borrow_mut()
                .map_err(denied)?
                .snapshot_in_retired_bracket(&original, record, retired, bindings)
                .map_err(denied)?;
            if before != after {
                return Err(conflict());
            }
            self.continuity(true)
        }
    }
    // SAFETY: only real non-importable creator/session/row/Pair capabilities,
    // Wfp Guard and concrete original resource readers join exact effects under
    // SAME Calling. SDK/protected/ACK before/after and sticky fencing are required.
    // Pending row authorization never enters mutable RowOwner State; no permit
    // or successful fallback exists for missing/unexpired registrations.
    unsafe impl<A: WindowBindingAttestor> NativeLifecycleGate for FullNativeLifecycleGate<A> {
        fn retain_unpublished_closed_carrier(
            &mut self,
            original: &Rc<UnpublishedClosedCarrierRead>,
        ) -> wintun::Result<()> {
            self.shared.fence.revoked.set(true);
            self.shared
                .unpublished
                .retain(original)
                .map_err(native_denied)?;
            // Full graph publication requires a genuine Source/C identity.
            // Root the actual failed input, but never substitute raw absence
            // for that original or revive the bootstrap authorization lane.
            Err(wintun::Error::Conflict)
        }
        fn retain_original_session(&mut self, original: wintun::SessionEndRead) {
            if self.session_pin.is_some() {
                self.shared.fence.revoked.set(true);
                self.session.retain_handoff(original);
                return;
            }
            self.session_pin = Some(original.read_pin());
            // Hooke passes the SAME already-Live bootstrap original. This is a
            // factual handoff, not a request to Start another session.
            self.session.retain_handoff(original);
            if self.session.endable().is_err() {
                self.shared.fence.revoked.set(true);
            }
        }
        fn retain_retired_carrier(
            &mut self,
            original: &Rc<RetiredCarrierRead>,
        ) -> wintun::Result<()> {
            let result = (|| {
                self.shared.retired.retain(original)?;
                if !original.matches_source_origin(self.shared.source.read()?.as_ref()) {
                    return Err(conflict());
                }
                let attestor = self.shared.guard_attestor_selection.read()?;
                let resources = self.shared.guard_resource_selection.read()?;
                // Authority retained this SAME Rc first. Concrete factual
                // registrations only: no Source/Pair/Retired/native inspect.
                // Attempt both before returning an error so an attestor failure
                // cannot erase the resource owner's original cleanup obligation.
                let attestor_result = attestor.retain_retired_origin(original.clone());
                let resource_result = resources.retain_retired(original);
                attestor_result.map_err(denied)?;
                resource_result.map_err(denied)?;
                Ok(())
            })();
            // Registration is factual only: NO Retired/Pair/native inspect.
            // Authority owns same Rc before this once-only weak registration.
            self.shared.fence.revoked.set(true);
            result.map_err(native_denied)
        }
        fn select_pair_intent(
            &mut self,
            original: Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> wintun::Result<()> {
            self.shared
                .select(original, expected)
                .map_err(native_denied)
        }
        fn supervisor(&self) -> &Rc<NativeDeadline> {
            &self.shared.supervisor
        }
        fn authorize(
            &mut self,
            scope: &creators::Scope,
            stage: wintun::Stage,
            originals: &creators::Observer<OriginalWintun>,
        ) -> wintun::Result<()> {
            let stage = match stage {
                wintun::Stage::Resolve => LifecycleStage::Resolve,
                wintun::Stage::BeforeCreate => LifecycleStage::Create,
                wintun::Stage::BeforeSession => LifecycleStage::Session,
                wintun::Stage::BeforeDrain => LifecycleStage::Drain,
                wintun::Stage::Observe => LifecycleStage::Observe,
                wintun::Stage::CleanupObserve => LifecycleStage::CleanupObserve,
                wintun::Stage::BeforeEnd => LifecycleStage::End,
                wintun::Stage::BeforeClose => LifecycleStage::Close,
                wintun::Stage::AfterClose => LifecycleStage::AfterClose,
            };
            self.authorize_stage(scope, stage, originals)
        }
        fn authorize_rows(
            &mut self,
            scope: &creators::Scope,
            binding: &rows::Binding,
            target: &rows::Target,
            originals: &creators::Observer<OriginalWintun>,
        ) -> wintun::Result<()> {
            if binding.role != rows::Role::Carrier {
                self.shared.fence.revoked.set(true);
                return Err(wintun::Error::Conflict);
            }
            self.authorize_row(scope, binding, target, originals)
        }
        fn authorize_member_rows(
            &mut self,
            scope: &creators::Scope,
            binding: &rows::Binding,
            target: &rows::Target,
            originals: &creators::Observer<OriginalWintun>,
            members: &MemberInventoryRead,
        ) -> wintun::Result<()> {
            if binding.role == rows::Role::Carrier
                || !self
                    .shared
                    .members
                    .read()
                    .map_err(native_denied)?
                    .same_original(members)
            {
                self.shared.fence.revoked.set(true);
                return Err(wintun::Error::Conflict);
            }
            self.authorize_row(scope, binding, target, originals)
        }
    }
}

#[cfg(test)]
#[path = "member_carrier_lifecycle_gate_tests.rs"]
mod tests;
