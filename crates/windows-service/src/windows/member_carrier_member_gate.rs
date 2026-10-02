//! Original member lifecycle authorization. No factory or native effects.
#![allow(dead_code)]

use crate::{
    member_carrier::{CarrierError as Error, Result},
    member_carrier_guard as policy,
    member_carrier_native_ownership::Context,
    member_carrier_pair as pair, member_carrier_rows as rows,
    member_owner::{Intent, NativeProof},
};
use nelomai_client_tunnel::redundancy::Slot;
use nelomai_contracts::dispatcher::TunnelSlot;
use std::cell::Cell;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Use {
    Primary,
    Reserve,
    Stop,
    ServiceStop(usize),
    Retire(usize),
    Retired(usize),
    Rebind(usize),
}
fn cleanup_use(usage: Use) -> bool {
    matches!(usage, Use::Stop | Use::ServiceStop(_))
}
fn service_window_usage(usage: Use, partial: bool) -> Result<()> {
    if matches!(usage, Use::ServiceStop(_)) != partial {
        return Err(Error::Conflict);
    }
    Ok(())
}
fn service_stop_stage(context: &Context, record: &pair::Record, intent: &Intent) -> Result<Use> {
    stage(context, record, intent, true)?;
    let target = index(intent);
    if record.members[target]
        .as_ref()
        .is_none_or(|m| m.owner.proof.is_some())
        || record.guard.members[target].is_some()
    {
        return Err(Error::Conflict);
    }
    Ok(Use::ServiceStop(target))
}
fn retirement_target(usage: Use) -> Option<usize> {
    match usage {
        Use::Retire(target) | Use::Retired(target) => Some(target),
        _ => None,
    }
}
fn index(intent: &Intent) -> usize {
    usize::from(intent.slot == TunnelSlot::B)
}
fn shared_slot(intent: &Intent) -> Slot {
    if index(intent) == 0 {
        Slot::A
    } else {
        Slot::B
    }
}
fn stage(context: &Context, record: &pair::Record, intent: &Intent, cleanup: bool) -> Result<Use> {
    record.validate().map_err(|_| Error::Conflict)?;
    let target = index(intent);
    let slot = shared_slot(intent);
    let member = record.members[target].as_ref().ok_or(Error::Conflict)?;
    if record.scope != context.intent.scope
        || record.provenance != context.provenance
        || record.addresses != context.intent.addresses
        || member.owner.intent != *intent
        || record
            .carrier
            .is_none_or(|c| c.guid != context.bindings[0].guid)
        || record.pending_guard.is_some()
        || record.guard.permits
    {
        return Err(Error::Conflict);
    }
    if cleanup {
        if record.phase != pair::Phase::Closing
            || record.active.is_some()
            || record.operation.is_some()
            || record.stop_stage != 4 + target as u8
            || record.pending != Some(pair::Effect::MemberStop(slot))
        {
            return Err(Error::Conflict);
        }
        return Ok(Use::Stop);
    }
    if record.pending != Some(pair::Effect::MemberStart(slot))
        || record.stop_stage != 0
        || member.owner.phase != crate::member_owner::Phase::Prepared
        || member.owner.proof.is_some()
        || member.owner.retired_proof.is_some()
    {
        return Err(Error::Conflict);
    }
    match record.operation {
        Some(pair::Operation::Start(s))
            if s == slot
                && record.phase == pair::Phase::Starting
                && record.active.is_none()
                && record.members[1 - target].is_none()
                && record.network.is_none() =>
        {
            Ok(Use::Primary)
        }
        Some(pair::Operation::Attach(s))
            if s == slot
                && record.phase == pair::Phase::Running
                && record.active.is_some_and(|s| s != slot)
                && record.network.is_some()
                && record.members[1 - target].as_ref().is_some_and(|m| {
                    m.owner.phase == crate::member_owner::Phase::Running && m.owner.proof.is_some()
                }) =>
        {
            Ok(Use::Reserve)
        }
        _ => Err(Error::Conflict),
    }
}
pub(crate) fn validate_retirement(
    context: &Context,
    record: &pair::Record,
    intent: &Intent,
) -> Result<usize> {
    record.validate().map_err(|_| Error::Conflict)?;
    let target = index(intent);
    let slot = shared_slot(intent);
    let member = record.members[target].as_ref().ok_or(Error::Conflict)?;
    let other = record.members[1 - target].as_ref().ok_or(Error::Conflict)?;
    if record.scope != context.intent.scope
        || record.provenance != context.provenance
        || record.addresses != context.intent.addresses
        || member.owner.intent != *intent
        || record
            .carrier
            .is_none_or(|p| p.guid != context.bindings[0].guid)
        || record.phase != pair::Phase::Running
        || record.operation != Some(pair::Operation::Retire(slot))
        || record.active != Some(if target == 0 { Slot::B } else { Slot::A })
        || record.stop_stage != 0
        || record.pending != Some(pair::Effect::MemberStop(slot))
        || record.pending_guard.is_some()
        || record.guard.permits
        || record.network.is_none()
        || [member, other].iter().any(|m| {
            m.owner.phase != crate::member_owner::Phase::Running || m.owner.proof.is_none()
        })
    {
        return Err(Error::Conflict);
    }
    Ok(target)
}
fn retirement_stage(context: &Context, record: &pair::Record, intent: &Intent) -> Result<Use> {
    validate_retirement(context, record, intent).map(Use::Retire)
}
fn rebind_stage(context: &Context, record: &pair::Record, intent: &Intent) -> Result<Use> {
    record.validate().map_err(|_| Error::Conflict)?;
    let target = index(intent);
    if record.scope != context.intent.scope
        || record.provenance != context.provenance
        || record.addresses != context.intent.addresses
        || record.phase != pair::Phase::Running
        || record.operation != Some(pair::Operation::Rebind)
        || record.pending != Some(pair::Effect::Rebind(shared_slot(intent)))
        || record.pending_guard.is_some()
        || record.guard.permits
        || record.active.is_none()
        || record.stop_stage != 0
        || record.network.is_none()
        || record
            .carrier
            .is_none_or(|c| c.guid != context.bindings[0].guid)
        || record.members[target]
            .as_ref()
            .is_none_or(|m| m.owner.intent != *intent)
        || record.members.iter().flatten().any(|m| {
            m.owner.phase != crate::member_owner::Phase::Running || m.owner.proof.is_none()
        })
    {
        return Err(Error::Conflict);
    }
    Ok(Use::Rebind(target))
}
fn guard(record: &pair::Record, usage: Use, actual: &policy::Snapshot) -> Result<()> {
    record.guard.validate().map_err(|_| Error::Conflict)?;
    if record.pending_guard.is_some()
        || record.guard.permits
        || actual != &record.guard.expected
        || actual
            .filters
            .iter()
            .any(|f| f.action != policy::Action::Block)
    {
        return Err(Error::Conflict);
    }
    if usage == Use::Primary || matches!(usage, Use::ServiceStop(_)) && !record.guard.installed {
        if record.guard
            != policy::Model::empty(record.scope.clone()).map_err(|_| Error::Conflict)?
        {
            return Err(Error::Conflict);
        }
    } else if !record.guard.installed
        || record.guard.assigned_sublayer_weight.is_none()
        || actual.sublayer.as_ref().map(|s| s.weight) != record.guard.assigned_sublayer_weight
        || actual.carrier.as_ref().map(|c| c.identity.proof) != record.carrier
    {
        return Err(Error::Conflict);
    }
    if usage != Use::Primary {
        for (member, egress) in record.members.iter().zip(&actual.egress) {
            if member
                .as_ref()
                .and_then(|m| m.owner.proof.map(|p| p.interface))
                != egress.as_ref().map(|e| e.proof)
            {
                return Err(Error::Conflict);
            }
        }
    }
    Ok(())
}
struct RowFact<'a> {
    binding: &'a rows::Binding,
    acknowledged: &'a rows::Record,
    observed: Option<&'a rows::Snapshot>,
}
fn resource_rows(
    context: &Context,
    record: &pair::Record,
    usage: Use,
    facts: [Option<RowFact<'_>>; 3],
) -> Result<()> {
    let proofs = [
        record.carrier,
        record.members[0]
            .as_ref()
            .and_then(|m| m.owner.proof.map(|p| p.interface)),
        record.members[1]
            .as_ref()
            .and_then(|m| m.owner.proof.map(|p| p.interface)),
    ];
    for (n, (proof, fact)) in proofs.iter().zip(facts).enumerate() {
        let Some(proof) = proof else {
            if fact.is_some() {
                return Err(Error::Conflict);
            }
            continue;
        };
        let RowFact {
            binding,
            acknowledged: ack,
            observed,
        } = fact.ok_or(Error::Pending)?;
        binding.validate().map_err(|_| Error::Conflict)?;
        ack.validate().map_err(|_| Error::Conflict)?;
        if binding.scope != record.scope
            || binding.boot_id != context.provenance.boot_id
            || binding.runtime != context.provenance.runtime
            || binding.network_epoch != context.provenance.network_epoch
            || binding.role
                != [
                    rows::Role::Carrier,
                    rows::Role::MemberA,
                    rows::Role::MemberB,
                ][n]
            || binding.guid != proof.guid
            || binding.name != context.bindings[n].name
            || binding.key.index != proof.index
            || binding.key.luid != proof.luid
            || ack.binding != *binding
            || ack.pending.is_some()
            || binding.address
                != match record.addresses[0].addr() {
                    std::net::IpAddr::V4(ip) => ip.octets(),
                    _ => return Err(Error::Conflict),
                }
        {
            return Err(Error::Conflict);
        }
        let baseline = &ack.baseline.interface.policy;
        if baseline.forwarding
            || baseline.advertising
            || baseline.weak_host_send
            || baseline.weak_host_receive
            || baseline.link_local_behavior != 0
        {
            return Err(Error::Conflict);
        }
        let mut desired = baseline.clone();
        let restored =
            cleanup_use(usage) || retirement_target(usage).is_some_and(|target| n == target + 1);
        let weak = matches!(usage, Use::Reserve | Use::Rebind(_))
            || retirement_target(usage).is_some_and(|target| n != target + 1);
        if weak {
            desired.weak_host_send = true;
            desired.weak_host_receive = true;
        }
        if ack.current.interface.policy != desired
            || (!restored && ack.phase != rows::Phase::Captured)
            || (restored && ack.phase == rows::Phase::Captured)
            || retirement_target(usage)
                .is_some_and(|target| n == target + 1 && ack.phase != rows::Phase::Stopped)
        {
            return Err(Error::Conflict);
        }
        if let Some(actual) = observed {
            actual.validate(binding).map_err(|_| Error::Conflict)?;
            if !rows::same_owned(&ack.current, actual) {
                return Err(Error::Conflict);
            }
        } else if (!cleanup_use(usage) || n == 0)
            && !matches!(usage, Use::Retired(target) if n == target + 1)
        {
            return Err(Error::Pending);
        }
        if n == 0 {
            let address = ack.current.address.as_ref().ok_or(Error::Conflict)?;
            if ack
                .creation
                .as_ref()
                .is_none_or(|a| !rows::same_address(a, address))
                || address.policy.skip_as_source
                || address.observed.creation_timestamp <= 0
                || !cleanup_use(usage) && address.observed.dad_state != 4
            {
                return Err(Error::Conflict);
            }
        } else if ack.current.address.is_some() || ack.creation.is_some() {
            return Err(Error::Conflict);
        }
    }
    Ok(())
}
fn original_bindings(
    context: &Context,
    record: &pair::Record,
    intent: &Intent,
    usage: Use,
    carrier: &policy::Carrier,
    egress: &[Option<policy::Identity>; 2],
    partial: Option<NativeProof>,
) -> Result<()> {
    if carrier.identity.scope != record.scope
        || Some(carrier.identity.proof) != record.carrier
        || carrier.identity.proof.guid != context.bindings[0].guid
        || carrier.sources
            != record
                .addresses
                .iter()
                .map(|a| a.addr())
                .collect::<Vec<_>>()
    {
        return Err(Error::Conflict);
    }
    policy::Model::new(
        record.scope.clone(),
        carrier.clone(),
        egress.clone().map(|identity| {
            identity.map(|identity| policy::Member {
                identity,
                probes: vec![],
            })
        }),
        None,
    )
    .map_err(|_| Error::Conflict)?;
    for (n, actual) in egress.iter().enumerate() {
        let expected = if n == index(intent) && matches!(usage, Use::Primary | Use::Reserve) {
            None
        } else if n == index(intent) && partial.is_some() {
            partial.map(|p| p.interface)
        } else {
            record.members[n]
                .as_ref()
                .and_then(|m| m.owner.proof.map(|p| p.interface))
        };
        if actual.as_ref().map(|i| i.proof) != expected
            || actual.as_ref().is_some_and(|i| {
                i.scope != record.scope || i.proof.guid != context.bindings[n + 1].guid
            })
        {
            return Err(Error::Conflict);
        }
    }
    Ok(())
}
fn probes(record: &pair::Record, usage: Use, actual: &[policy::ProbeTuple]) -> Result<()> {
    if cleanup_use(usage) || matches!(usage, Use::Rebind(_)) {
        return if actual.is_empty() {
            Ok(())
        } else {
            Err(Error::Conflict)
        };
    }
    let mut expected = record
        .guard
        .members
        .iter()
        .enumerate()
        .filter(|(n, _)| retirement_target(usage) != Some(*n))
        .filter_map(|(_, m)| m.as_ref())
        .flat_map(|m| m.probes.clone())
        .collect::<Vec<_>>();
    let mut actual = actual.to_vec();
    let key =
        |p: &policy::ProbeTuple| (p.source, p.source_port, p.target, p.target_port, p.protocol);
    expected.sort_by_key(key);
    actual.sort_by_key(key);
    if actual != expected
        || actual.iter().enumerate().any(|(i, p)| {
            actual[..i]
                .iter()
                .any(|old| old.source == p.source && old.source_port == p.source_port)
        })
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
#[cfg(any(windows, test))]
struct NetworkFact<'a> {
    routes: &'a super::member_carrier_network::NetworkFacts,
    dns: &'a crate::member_dns::Snapshot,
    protected: Option<&'a [u8]>,
}
#[cfg(any(windows, test))]
type NetworkAcks = (
    Vec<super::member_carrier_network_owner::RouteAttempt>,
    Vec<crate::member_dns::Snapshot>,
);
#[cfg(any(windows, test))]
fn network(
    record: &pair::Record,
    usage: Use,
    fact: NetworkFact<'_>,
    ack: Option<&NetworkAcks>,
) -> Result<()> {
    let c = record.carrier.ok_or(Error::Conflict)?;
    let dns = fact.dns;
    if dns.interface.scope != record.scope
        || dns.interface.guid != c.guid
        || dns.interface.luid != c.luid
        || dns.interface.index != c.index
        || fact.routes.pending.is_some()
        || fact.routes.pending_active.is_some()
        || fact.routes.carrier_rows.iter().any(|r| {
            r.route.destination != record.addresses[0]
                || r.route.gateway.is_some()
                || r.flags[0] != 1
                || r.luid != c.luid
        })
    {
        return Err(Error::Conflict);
    }
    if usage == Use::Primary || matches!(usage, Use::ServiceStop(_)) && record.network.is_none() {
        if record.network.is_some()
            || fact.protected.is_some()
            || ack.is_some()
            || !fact.routes.current.is_empty()
            || fact.routes.egress_rows.iter().any(|r| !r.is_empty())
            || fact.routes.active.is_some()
            || fact.routes.stopping
            || dns.settings.name_server.is_some()
            || dns.settings.profile_name_server.is_some()
        {
            return Err(Error::Conflict);
        }
        return Ok(());
    }
    let n = record.network.as_ref().ok_or(Error::Conflict)?;
    let (routes, dns_acks) = ack.ok_or(Error::Pending)?;
    if fact.protected.is_none()
        || n.pending.is_some()
        || n.current.dns.as_ref() != Some(dns)
        || dns_acks.last() != Some(dns)
        || routes.iter().any(|a| !a.acknowledged)
    {
        return Err(Error::Conflict);
    }
    if cleanup_use(usage)
        && (n.current != n.baseline
            || !n.baseline.routes.is_empty()
            || !fact.routes.current.is_empty()
            || fact.routes.egress_rows.iter().any(|r| !r.is_empty())
            || fact.routes.active.is_some())
    {
        return Err(Error::Conflict);
    }
    if (matches!(usage, Use::Reserve | Use::Rebind(_)) || retirement_target(usage).is_some())
        && (fact.routes.stopping || fact.routes.active != record.active)
    {
        return Err(Error::Conflict);
    }
    if let Some(target) = retirement_target(usage) {
        let proof = record.members[target]
            .as_ref()
            .and_then(|m| m.owner.proof)
            .ok_or(Error::Conflict)?;
        if !fact.routes.egress_rows[target].is_empty()
            || n.current
                .routes
                .iter()
                .any(|r| r.interface == proof.interface.index)
            || fact
                .routes
                .current
                .iter()
                .any(|r| r.expected.interface == proof.interface.index)
        {
            return Err(Error::Conflict);
        }
    }
    let mut current = std::collections::BTreeSet::new();
    for route in &fact.routes.current {
        let actual = route.actual.as_ref().ok_or(Error::Pending)?;
        if actual.route != route.expected
            || !n.current.routes.contains(&route.expected)
            || !current.insert((route.expected.destination, route.expected.interface))
            || routes
                .iter()
                .rev()
                .find(|a| {
                    a.row.route.destination == route.expected.destination
                        && a.row.route.interface == route.expected.interface
                })
                .is_none_or(|a| a.deleting || a.row != *actual)
        {
            return Err(Error::Conflict);
        }
    }
    if current.len() != n.current.routes.len() {
        return Err(Error::Conflict);
    }
    for rows in &fact.routes.egress_rows {
        for row in rows {
            if !fact
                .routes
                .current
                .iter()
                .any(|r| r.actual.as_ref() == Some(row))
            {
                return Err(Error::Conflict);
            }
        }
    }
    for (i, a) in routes.iter().enumerate() {
        if routes[i + 1..].iter().any(|b| {
            b.row.route.destination == a.row.route.destination
                && b.row.route.interface == a.row.route.interface
        }) {
            continue;
        }
        let found = fact
            .routes
            .current
            .iter()
            .find(|r| {
                r.expected.destination == a.row.route.destination
                    && r.expected.interface == a.row.route.interface
            })
            .and_then(|r| r.actual.as_ref());
        if a.deleting && found.is_some() || !a.deleting && found != Some(&a.row) {
            return Err(Error::Conflict);
        }
    }
    Ok(())
}
fn advance(old: &pair::Record, next: &pair::Record) -> Result<()> {
    next.validate().map_err(|_| Error::Conflict)?;
    if next.scope != old.scope
        || next.provenance != old.provenance
        || next.addresses != old.addresses
        || next.revision <= old.revision
        || next.carrier != old.carrier
        || old.phase == pair::Phase::Closing
            && (next.phase != pair::Phase::Closing || next.stop_stage < old.stop_stage)
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
fn protected_continuity(before: Option<&[u8]>, after: Option<&[u8]>) -> Result<()> {
    if before != after {
        return Err(Error::Conflict);
    }
    Ok(())
}
/// Comparison-only projection AFTER the native inventory has authenticated
/// this SAME pending owner. Not a proof constructor or absence permission.
fn partial_original_proof(
    intent: &Intent,
    actual: (Intent, Option<NativeProof>),
) -> Result<NativeProof> {
    if actual.0 != *intent {
        return Err(Error::Conflict);
    }
    actual.1.ok_or(Error::Pending)
}

#[derive(Default)]
struct GateFence {
    busy: Cell<bool>,
    revoked: Cell<bool>,
    tainted: Cell<bool>,
}
impl GateFence {
    fn run<T>(&self, cleanup: bool, call: impl FnOnce() -> Result<T>) -> Result<T> {
        if self.busy.get() || !cleanup && self.revoked.get() {
            self.revoked.set(true);
            self.tainted.set(true);
            return Err(Error::Conflict);
        }
        self.busy.set(true);
        self.tainted.set(false);
        let mut flight = Flight {
            fence: self,
            complete: false,
        };
        if cleanup {
            self.revoked.set(true);
        }
        let value = call()?;
        if self.tainted.get() {
            return Err(Error::Conflict);
        }
        flight.complete = true;
        Ok(value)
    }
}
struct Flight<'a> {
    fence: &'a GateFence,
    complete: bool,
}
impl Drop for Flight<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.fence.revoked.set(true);
        }
        self.fence.busy.set(false);
    }
}
/// Keep all actual inputs and attempted registrations on Err/unwind/Drop.
/// Only the enclosing actor's complete original receipts may release them;
/// this authorization component has no completion or unchecked cleanup API.
struct Root<T>(Option<T>);
impl<T> Root<T> {
    fn new(value: T) -> Self {
        Self(Some(value))
    }
    fn get_mut(&mut self) -> Result<&mut T> {
        self.0.as_mut().ok_or(Error::Pending)
    }
}
impl<T> Drop for Root<T> {
    fn drop(&mut self) {
        if let Some(value) = self.0.take() {
            std::mem::forget(value);
        }
    }
}
struct Registration<T> {
    first: Option<std::rc::Weak<T>>,
}
impl<T> Default for Registration<T> {
    fn default() -> Self {
        Self { first: None }
    }
}
impl<T> Registration<T> {
    fn retain(&mut self, original: &std::rc::Rc<T>) -> Result<()> {
        if let Some(first) = &self.first {
            if !std::rc::Weak::ptr_eq(first, &std::rc::Rc::downgrade(original)) {
                return Err(Error::Conflict);
            }
            self.get()?;
        } else {
            self.first = Some(std::rc::Rc::downgrade(original));
        }
        Ok(())
    }
    fn get(&self) -> Result<std::rc::Rc<T>> {
        self.first
            .as_ref()
            .and_then(std::rc::Weak::upgrade)
            .ok_or(Error::Pending)
    }
}

#[cfg(windows)]
pub(crate) mod native {
    use super::*;
    use crate::member_carrier_native_ownership as receipts;
    use crate::windows::{
        member_carrier_guard::{NativeGuard, Wfp, WindowBindingAttestor},
        member_carrier_key_authority::RuntimeRead,
        member_carrier_member_controller::native::{
            NativeMemberLifecycle, PartialCleanup, Pending,
        },
        member_carrier_members::native::MemberInventoryRead,
        member_carrier_network::native::{NativeClosingNetworkRead, NativeNetworkRead},
        member_carrier_network_owner::native::{NativeNetworkAckRead, NativeNetworkEffectGate},
        member_carrier_pair_store::native_store::NativePairIntentRead,
        member_carrier_payload::native::MemberSource,
        member_carrier_probes::native::{NativeProbeGate, ProbeInventoryRead},
        member_carrier_runtime::native::{
            NativeBindingsWindow, NativeClosingRead, NativeResourceRowsRead, NativeSourceRead,
        },
        member_native_deadline::NativeDeadline,
        member_session::{CarrierGuardRecord, RecordKind},
    };
    use std::{
        cell::RefCell,
        rc::{Rc, Weak},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
    };

    /// Actor-owned actual Rc originals ONLY. The returned G keeps nonowning
    /// registrations for every Source/Guard/resource reverse edge. The actor
    /// MUST root these Rc objects independently across ALL effects/Err/unwind.
    pub(crate) struct NativeMemberGateInputs<A: WindowBindingAttestor, P: NativeProbeGate<Wfp, A>> {
        pub context: Context,
        pub intent: Intent,
        pub runtime: RuntimeRead,
        pub member_source: Rc<MemberSource>,
        pub source: Rc<NativeSourceRead>,
        pub guard: Rc<RefCell<NativeGuard<Wfp, A>>>,
        pub rows: Rc<NativeResourceRowsRead>,
        pub members: Rc<MemberInventoryRead>,
        pub probes: Rc<ProbeInventoryRead<Wfp, A, P>>,
        pub probe_gate: Rc<P>,
        pub network: Rc<NativeNetworkRead>,
        pub supervisor: Rc<NativeDeadline>,
        pub cancelled: Arc<AtomicBool>,
    }
    struct Selected {
        original: Rc<NativePairIntentRead>,
        record: pair::Record,
    }
    struct NetworkRegistration<N: NativeNetworkEffectGate> {
        original: Registration<NativeNetworkAckRead<N>>,
        gate: Registration<N>,
    }
    struct State<A: WindowBindingAttestor, P: NativeProbeGate<Wfp, A>, N: NativeNetworkEffectGate> {
        context: Context,
        intent: Intent,
        runtime: RuntimeRead,
        member_source: Rc<MemberSource>,
        source: Weak<NativeSourceRead>,
        guard: Weak<RefCell<NativeGuard<Wfp, A>>>,
        rows: Weak<NativeResourceRowsRead>,
        members: Weak<MemberInventoryRead>,
        probes: Weak<ProbeInventoryRead<Wfp, A, P>>,
        probe_gate: Weak<P>,
        network: Weak<NativeNetworkRead>,
        supervisor: Rc<NativeDeadline>,
        cancelled: Arc<AtomicBool>,
        selected: Option<Selected>,
        attempted_pairs: Vec<Rc<NativePairIntentRead>>,
        closing: Registration<NativeClosingRead>,
        closing_network: Registration<NativeClosingNetworkRead>,
        network_ack: Option<NetworkRegistration<N>>,
        generation: Option<u64>,
    }
    pub(crate) struct NativeMemberGate<
        A: WindowBindingAttestor,
        P: NativeProbeGate<Wfp, A>,
        N: NativeNetworkEffectGate,
    > {
        state: Root<State<A, P, N>>,
        fence: GateFence,
    }
    fn upgrade<T>(original: &Weak<T>) -> Result<Rc<T>> {
        original.upgrade().ok_or(Error::Pending)
    }
    fn denied<E>(_: E) -> Error {
        Error::Pending
    }
    fn io_denied(_: Error) -> std::io::Error {
        std::io::Error::other("carrier_member_gate_denied")
    }
    fn window_denied(_: Error) -> crate::windows::member_carrier_wintun::Error {
        crate::windows::member_carrier_wintun::Error::Conflict
    }
    impl<A: WindowBindingAttestor, P: NativeProbeGate<Wfp, A>, N: NativeNetworkEffectGate>
        NativeMemberGate<A, P, N>
    {
        /// No opening, native read/effect or successful validation here. Root
        /// the returned G in the actual actor/controller before selecting Pair.
        pub(crate) fn new(input: NativeMemberGateInputs<A, P>) -> Self {
            Self {
                state: Root::new(State {
                    context: input.context,
                    intent: input.intent,
                    runtime: input.runtime,
                    member_source: input.member_source,
                    source: Rc::downgrade(&input.source),
                    guard: Rc::downgrade(&input.guard),
                    rows: Rc::downgrade(&input.rows),
                    members: Rc::downgrade(&input.members),
                    probes: Rc::downgrade(&input.probes),
                    probe_gate: Rc::downgrade(&input.probe_gate),
                    network: Rc::downgrade(&input.network),
                    supervisor: input.supervisor,
                    cancelled: input.cancelled,
                    selected: None,
                    attempted_pairs: vec![],
                    closing: Registration::default(),
                    closing_network: Registration::default(),
                    network_ack: None,
                    generation: None,
                }),
                fence: GateFence::default(),
            }
        }
        /// Current exact opaque publication, not imported/equal Pair JSON.
        /// Each attempted original remains rooted before fallible verification.
        /// Bind Closing before selecting the cleanup publication; never revive
        /// a failed forward G with a fresh selection.
        pub(crate) fn select_pair(&mut self, original: Rc<NativePairIntentRead>) -> Result<()> {
            let state = self.state.get_mut()?;
            self.fence.run(state.closing.first.is_some(), || {
                if state.attempted_pairs.len() >= 4096 {
                    return Err(Error::Pending);
                }
                state.attempted_pairs.push(original.clone());
                state.continuity(state.closing.first.is_some())?;
                if !original.matches_runtime(&state.runtime) {
                    return Err(Error::Conflict);
                }
                let record = original
                    .inspect(&state.runtime, &state.supervisor, |r| Ok(r.clone()))
                    .map_err(denied)?;
                let cleanup = record.phase == pair::Phase::Closing;
                if cleanup != state.closing.first.is_some() {
                    return Err(Error::Conflict);
                }
                if let Some(old) = &state.selected {
                    if Rc::ptr_eq(&old.original, &original) {
                        if old.record != record {
                            return Err(Error::Conflict);
                        }
                    } else {
                        advance(&old.record, &record)?;
                    }
                }
                state.selected = Some(Selected { original, record });
                state.continuity(cleanup)?;
                state.verify_pair()
            })
        }
        /// Actor must also bind its SAME rows sampler to this Closing pin.
        /// Both weak registrations are retained BEFORE origin/postflight reads.
        /// Expired or foreign registrations cannot replace a first obligation.
        pub(crate) fn bind_closing(
            &mut self,
            closing: &Rc<NativeClosingRead>,
            network: &Rc<NativeClosingNetworkRead>,
        ) -> Result<()> {
            let state = self.state.get_mut()?;
            self.fence.run(true, || {
                state.closing.retain(closing)?;
                state.closing_network.retain(network)?;
                if !closing.matches_source_origin(upgrade(&state.source)?.as_ref()) {
                    return Err(Error::Conflict);
                }
                state.continuity(true).map(|_| ())
            })
        }
        pub(crate) fn bind_network(
            &mut self,
            original: &Rc<NativeNetworkAckRead<N>>,
            gate: &Rc<N>,
        ) -> Result<()> {
            let state = self.state.get_mut()?;
            self.fence.run(state.closing.first.is_some(), || {
                let registration = state
                    .network_ack
                    .get_or_insert_with(|| NetworkRegistration {
                        original: Registration::default(),
                        gate: Registration::default(),
                    });
                registration.original.retain(original)?;
                registration.gate.retain(gate)?;
                if !original.matches_origin(&upgrade(&state.source)?, gate) {
                    return Err(Error::Conflict);
                }
                original.acknowledgements().map_err(denied)?;
                state.continuity(state.closing.first.is_some()).map(|_| ())
            })
        }
    }
    impl<A: WindowBindingAttestor, P: NativeProbeGate<Wfp, A>, N: NativeNetworkEffectGate>
        State<A, P, N>
    {
        fn continuity(&mut self, cleanup: bool) -> Result<Vec<u8>> {
            if !cleanup && self.cancelled.load(Ordering::Acquire) {
                return Err(Error::Conflict);
            }
            let deadline = self.supervisor.read_pin().map_err(denied)?;
            deadline
                .verify_runtime(&self.supervisor, &self.runtime, &self.context)
                .map_err(denied)?;
            deadline
                .verify_call(&self.supervisor, &self.context)
                .map_err(denied)?;
            self.runtime
                .verify_member_intent(&self.context, &self.member_source, &self.intent)?;
            if !cleanup && !self.runtime.fresh(&self.context)? {
                return Err(Error::Conflict);
            }
            let native = self
                .runtime
                .record(&self.context, RecordKind::NativeCarrierReceipts)?;
            let record = receipts::Record::decode(&native)?;
            receipts::validate_record(&record)?;
            if record.context != self.context
                || record.generation == 0
                || record.phase
                    != if cleanup {
                        receipts::Phase::Closing
                    } else {
                        receipts::Phase::Preparing
                    }
                || self.generation.is_some_and(|g| g != record.generation)
            {
                return Err(Error::Conflict);
            }
            self.generation = Some(record.generation);
            let source = upgrade(&self.source)?;
            let guard = upgrade(&self.guard)?;
            let probes = upgrade(&self.probes)?;
            let probe_gate = upgrade(&self.probe_gate)?;
            probes
                .matches_caps(&source, &guard, &probe_gate)
                .map_err(denied)?;
            probe_gate.verify_inventory(&probes).map_err(denied)?;
            upgrade(&self.rows)?;
            upgrade(&self.members)?;
            upgrade(&self.network)?;
            deadline
                .verify_call(&self.supervisor, &self.context)
                .map_err(denied)?;
            Ok(native)
        }
        fn verify_pair(&mut self) -> Result<()> {
            let selected = self.selected.as_ref().ok_or(Error::Pending)?;
            let cleanup = selected.record.phase == pair::Phase::Closing;
            let effect = selected.record.pending.ok_or(Error::Conflict)?;
            if !selected.original.matches_runtime(&self.runtime) {
                return Err(Error::Conflict);
            }
            let check = |actual: &pair::Record| {
                if actual != &selected.record {
                    return Err(io_denied(Error::Conflict));
                }
                Ok(())
            };
            // Callback performs comparison ONLY. End this lease before any
            // Guard/Window/Rows/Probe/Network joined reads below.
            if cleanup {
                selected
                    .original
                    .inspect_cleanup_effect(
                        &self.runtime,
                        &self.supervisor,
                        &selected.record,
                        selected.record.stop_stage,
                        check,
                    )
                    .map_err(denied)?;
            } else {
                selected
                    .original
                    .inspect_effect(
                        &self.runtime,
                        &self.supervisor,
                        &selected.record,
                        effect,
                        check,
                    )
                    .map_err(denied)?;
            }
            Ok(())
        }
        fn check_arguments(
            &self,
            context: &Context,
            record: &pair::Record,
            intent: &Intent,
            cleanup: bool,
        ) -> Result<Use> {
            if context != &self.context
                || intent != &self.intent
                || self
                    .selected
                    .as_ref()
                    .is_none_or(|selected| selected.record != *record)
            {
                return Err(Error::Conflict);
            }
            stage(context, record, intent, cleanup)
        }
        fn authorize(
            &mut self,
            record: &pair::Record,
            usage: Use,
            window: &NativeBindingsWindow<'_>,
            partial: Option<NativeProof>,
        ) -> Result<()> {
            let cleanup = cleanup_use(usage);
            service_window_usage(usage, window.is_partial_member_cleanup())?;
            let before = self.continuity(cleanup)?;
            self.verify_pair()?;
            if !window.matches_runtime(&self.runtime)
                || if cleanup {
                    !window.matches_closing(self.closing.get()?.as_ref())
                } else {
                    !window.matches_source(upgrade(&self.source)?.as_ref())
                }
            {
                return Err(Error::Conflict);
            }
            let bindings = window.bindings();
            let c = bindings.carrier.as_ref().ok_or(Error::Conflict)?;
            original_bindings(
                &self.context,
                record,
                &self.intent,
                usage,
                c,
                &bindings.egress,
                partial,
            )?;
            if matches!(usage, Use::Retire(_) | Use::Rebind(_))
                && [TunnelSlot::A, TunnelSlot::B]
                    .into_iter()
                    .any(|s| window.closed_member(s).is_some())
            {
                // Preflight must see both originals genuinely live. A rooted
                // Stop ACK retry skips new effects and uses typed postflight.
                return Err(Error::Conflict);
            }
            // Current key rows remain exact. Controller additionally reattests
            // the borrowed original NEW held HKEY immediately before Start.
            if !cleanup {
                let native = receipts::Record::decode(&before)?;
                let keys = if retirement_target(usage).is_some() {
                    vec![0, 1, 2]
                } else if matches!(usage, Use::Rebind(_)) {
                    std::iter::once(0)
                        .chain(
                            record
                                .members
                                .iter()
                                .enumerate()
                                .filter_map(|(n, m)| m.as_ref().map(|_| n + 1)),
                        )
                        .collect()
                } else {
                    vec![0, index(&self.intent) + 1]
                };
                for n in keys {
                    let k = &native.keys[n];
                    if k.phase != receipts::KeyPhase::Disabled
                        || !k.new_key_ack
                        || k.baseline != receipts::Value::Absent
                        || k.current != receipts::Value::DwordZero
                        || k.pending.is_some()
                    {
                        return Err(Error::Conflict);
                    }
                }
            }
            let observed_guard = upgrade(&self.guard)?
                .try_borrow_mut()
                .map_err(denied)?
                .snapshot_in_window(window)
                .map_err(denied)?;
            guard(record, usage, &observed_guard)?;
            let protected = self
                .runtime
                .optional_record(&self.context, RecordKind::CarrierGuard)?;
            match &protected {
                None if usage == Use::Primary
                    || matches!(usage, Use::ServiceStop(_)) && !record.guard.installed => {}
                Some(bytes) => {
                    let saved = CarrierGuardRecord::decode(bytes).map_err(denied)?;
                    if saved.context != self.context
                        || saved.current != record.guard
                        || saved.pending.is_some()
                    {
                        return Err(Error::Conflict);
                    }
                }
                _ => return Err(Error::Pending),
            }
            let mut row_record = record.clone();
            if let Some(proof) = partial {
                row_record.members[index(&self.intent)]
                    .as_mut()
                    .ok_or(Error::Conflict)?
                    .owner
                    .proof = Some(proof);
            }
            let inspect_rows = |facts: &crate::windows::member_carrier_runtime::native::NativeResourceRowsFacts| {
                    resource_rows(
                        &self.context,
                        &row_record,
                        usage,
                        std::array::from_fn(|n| {
                            facts.rows[n].as_ref().map(|f| RowFact {
                                binding: &f.binding,
                                acknowledged: &f.acknowledged,
                                observed: f.observed.as_ref(),
                            })
                        }),
                    )
                    .map_err(window_denied)
                };
            let rows = upgrade(&self.rows)?;
            if matches!(usage, Use::Retire(_)) {
                // Pre-Stop: the target NIC is still SDK-live, but its SAME
                // RowOwner has already acknowledged Stopped/baseline. Only the
                // exact Preparing/current Retire/Calling bracket can read that
                // cleanup ACK here; this is not closed-history/absence authority.
                let selected = self.selected.as_ref().ok_or(Error::Pending)?;
                rows.inspect_retirement_in_window(
                    window,
                    &selected.original,
                    record,
                    &self.supervisor,
                    inspect_rows,
                )
                .map_err(denied)?;
            } else {
                // Retired postflight uses only the original typed Source history
                // and Stopped row ACK; never query the target's old SDK identity.
                rows.inspect_in_window(window, inspect_rows)
                    .map_err(denied)?;
            }
            let registration = self.network_ack.as_ref();
            let ack = registration
                .map(|r| {
                    let original = r.original.get()?;
                    let gate = r.gate.get()?;
                    if !original.matches_origin(&upgrade(&self.source)?, &gate) {
                        return Err(Error::Conflict);
                    }
                    original.acknowledgements().map_err(denied)
                })
                .transpose()?;
            let inspect_network =
                |facts: &crate::windows::member_carrier_network::native::NativeNetworkFacts| {
                    network(
                        record,
                        usage,
                        NetworkFact {
                            routes: &facts.routes,
                            dns: &facts.dns,
                            protected: facts.protected_record.as_deref(),
                        },
                        ack.as_ref(),
                    )
                    .map_err(io_denied)
                };
            if cleanup {
                self.closing_network
                    .get()?
                    .inspect_in_window(window, inspect_network)
                    .map_err(denied)?;
            } else {
                upgrade(&self.network)?
                    .inspect_in_window(window, inspect_network)
                    .map_err(denied)?;
            }
            let inventory = upgrade(&self.probes)?;
            if cleanup || matches!(usage, Use::Rebind(_)) {
                let originals = inventory.originals().map_err(denied)?;
                let retired = inventory.inspect_retired().map_err(denied)?;
                if originals.len() != retired.len() {
                    return Err(Error::Pending);
                }
                for (live, closed) in originals.iter().zip(&retired) {
                    closed.verify_same_original(live).map_err(denied)?;
                }
                if matches!(usage, Use::Rebind(_)) {
                    // Running members must have their actual canonical held
                    // originals, not an empty/missing slot treated as a close
                    // ACK. inspect_retired also checks older original attempts.
                    let by_slot = inventory.originals_by_slot().map_err(denied)?;
                    for (n, member) in record.members.iter().enumerate() {
                        if member.is_some() {
                            let original = by_slot[n].as_ref().ok_or(Error::Pending)?;
                            inventory
                                .verify_member_slot(
                                    if n == 0 { Slot::A } else { Slot::B },
                                    original,
                                )
                                .map_err(denied)?;
                            original
                                .retired()
                                .map_err(denied)?
                                .verify_same_original(original)
                                .map_err(denied)?;
                        }
                    }
                }
                probes(record, usage, &[])?;
            } else if let Some(target) = retirement_target(usage) {
                let originals = inventory.originals_by_slot().map_err(denied)?;
                let retired = originals[target].as_ref().ok_or(Error::Pending)?;
                let target_slot = if target == 0 { Slot::A } else { Slot::B };
                inventory
                    .verify_member_slot(target_slot, retired)
                    .map_err(denied)?;
                retired
                    .retired()
                    .map_err(denied)?
                    .verify_same_original(retired)
                    .map_err(denied)?;
                let other = originals[1 - target].as_ref().ok_or(Error::Pending)?;
                inventory
                    .verify_member_slot(if target == 0 { Slot::B } else { Slot::A }, other)
                    .map_err(denied)?;
                let tuple = other.inspect_tuple_in_window(window).map_err(denied)?;
                probes(record, usage, &[tuple])?;
            } else {
                let tuples = inventory
                    .originals()
                    .map_err(denied)?
                    .iter()
                    .map(|p| p.inspect_tuple_in_window(window).map_err(denied))
                    .collect::<Result<Vec<_>>>()?;
                probes(record, usage, &tuples)?;
            }
            let after_guard = upgrade(&self.guard)?
                .try_borrow_mut()
                .map_err(denied)?
                .snapshot_in_window(window)
                .map_err(denied)?;
            if after_guard != observed_guard {
                return Err(Error::Conflict);
            }
            guard(record, usage, &after_guard)?;
            let after_protected = self
                .runtime
                .optional_record(&self.context, RecordKind::CarrierGuard)?;
            protected_continuity(protected.as_deref(), after_protected.as_deref())?;
            // End all sibling borrows before the final original Pair lease.
            self.verify_pair()?;
            if self.continuity(cleanup)? != before {
                return Err(Error::Conflict);
            }
            Ok(())
        }
    }
    // SAFETY: actual Wfp/A guard and original nonimportable resource readers
    // are mandatory; all successful paths use full original joined SDK reads,
    // SAME current Pair/Runtime/Calling and exact original ACK comparisons.
    // Main's serialized actor roots the strong originals independently. No
    // effect, factory/default G, lookup adoption or unknown-absence path exists.
    unsafe impl<A: WindowBindingAttestor, P: NativeProbeGate<Wfp, A>, N: NativeNetworkEffectGate>
        NativeMemberLifecycle for NativeMemberGate<A, P, N>
    {
        fn authorize_start(
            &mut self,
            context: &Context,
            record: &pair::Record,
            intent: &Intent,
            window: &NativeBindingsWindow<'_>,
        ) -> Result<()> {
            let state = self.state.get_mut()?;
            self.fence.run(false, || {
                let usage = state.check_arguments(context, record, intent, false)?;
                state.authorize(record, usage, window, None)
            })
        }
        fn authorize_stop(
            &mut self,
            context: &Context,
            record: &pair::Record,
            intent: &Intent,
            window: &NativeBindingsWindow<'_>,
        ) -> Result<()> {
            let state = self.state.get_mut()?;
            self.fence.run(true, || {
                let usage = state.check_arguments(context, record, intent, true)?;
                state.authorize(record, usage, window, None)
            })
        }
        fn authorize_retire(
            &mut self,
            context: &Context,
            record: &pair::Record,
            intent: &Intent,
            window: &NativeBindingsWindow<'_>,
        ) -> Result<()> {
            let state = self.state.get_mut()?;
            self.fence.run(false, || {
                if context != &state.context
                    || intent != &state.intent
                    || state.selected.as_ref().is_none_or(|s| s.record != *record)
                {
                    return Err(Error::Conflict);
                }
                let mut usage = retirement_stage(context, record, intent)?;
                let target = index(intent);
                if window
                    .closed_member(if target == 0 {
                        TunnelSlot::B
                    } else {
                        TunnelSlot::A
                    })
                    .is_some()
                {
                    return Err(Error::Conflict);
                }
                if let Some(history) = window.closed_member(intent.slot) {
                    if history.intent != *intent
                        || record.members[target].as_ref().and_then(|m| m.owner.proof)
                            != Some(history.proof)
                    {
                        return Err(Error::Conflict);
                    }
                    // ONLY an authenticated original Source history can select
                    // the readonly postflight projection; not SDK absence/JSON.
                    usage = Use::Retired(target);
                }
                state.authorize(record, usage, window, None)
            })
        }
        fn authorize_rebind(
            &mut self,
            context: &Context,
            record: &pair::Record,
            intent: &Intent,
            window: &NativeBindingsWindow<'_>,
        ) -> Result<()> {
            let state = self.state.get_mut()?;
            self.fence.run(false, || {
                if context != &state.context
                    || intent != &state.intent
                    || state.selected.as_ref().is_none_or(|s| s.record != *record)
                {
                    return Err(Error::Conflict);
                }
                let usage = rebind_stage(context, record, intent)?;
                state.authorize(record, usage, window, None)
            })
        }
        fn authorize_partial_stop(
            &mut self,
            context: &Context,
            record: &pair::Record,
            intent: &Intent,
            original: &Pending,
            service: Option<&Rc<PartialCleanup>>,
        ) -> Result<()> {
            let state = self.state.get_mut()?;
            self.fence.run(true, || {
                let usage = state.check_arguments(context, record, intent, true)?;
                state.continuity(true)?;
                state.verify_pair()?;
                let inventory = upgrade(&state.members)?;
                inventory.verify_pending_cleanup(&state.member_source, original)?;
                if let Some(service) = service {
                    service.verify_pending_original(original).map_err(denied)?;
                    if service.intent() != intent {
                        return Err(Error::Conflict);
                    }
                    let usage = service_stop_stage(context, record, intent)?;
                    let before = service.inspect().map_err(denied)?;
                    let closing = state.closing.get()?;
                    closing
                        .inspect_partial_member_window(service, |window| {
                            if !window.matches_partial_member(service) {
                                return Err(window_denied(Error::Conflict));
                            }
                            state
                                .authorize(record, usage, window, None)
                                .map_err(window_denied)
                        })
                        .map_err(denied)?;
                    if service.inspect().map_err(denied)? != before {
                        return Err(Error::Conflict);
                    }
                    inventory.verify_pending_cleanup(&state.member_source, original)?;
                    service.verify_pending_original(original).map_err(denied)?;
                    state.verify_pair()?;
                    state.continuity(true)?;
                    return Ok(());
                }
                // Existing native samplers cannot bracket unknown partial IO
                // without demanding its live proof. NO absence/JSON substitute.
                let proof = partial_original_proof(
                    intent,
                    original.read_pin().read_for_cleanup().map_err(denied)?,
                )?;
                let closing = state.closing.get()?;
                closing
                    .inspect_window(|window| {
                        state
                            .authorize(record, usage, window, Some(proof))
                            .map_err(window_denied)
                    })
                    .map_err(denied)?;
                inventory.verify_pending_cleanup(&state.member_source, original)?;
                state.verify_pair()?;
                state.continuity(true)?;
                Ok(())
            })
        }
    }
}

#[cfg(test)]
#[path = "member_carrier_member_gate_tests.rs"]
mod tests;
