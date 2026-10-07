//! Concrete original-Wfp probe authorization. Factory remains disconnected.
//! Portable comparisons confer no socket/resource permission.
use crate::{
    member_carrier_guard as policy,
    member_carrier_native_ownership::Context,
    member_carrier_pair as pair, member_carrier_rows as rows, member_dns as dns,
    member_physical::{Family, InterfaceIdentity, PhysicalSnapshot},
    member_plan::InterfaceMetric,
    member_routes::{NativeProof, Row},
};
use nelomai_client_tunnel::redundancy::{
    network::{RouteScope, RouteValue},
    route_plan::MemberRoutes,
    Slot,
};
use policy::{GuardError, ProbeTuple, Result, Snapshot};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Purpose {
    Open(Slot),
    Use(Slot),
    Preparing,
    Closing,
    Guard,
}
fn idx(slot: Slot) -> usize {
    usize::from(slot == Slot::B)
}
fn denied<E>(_: E) -> GuardError {
    GuardError::Conflict
}
// Protected metadata origin only; Prepared members confer no effect permission.
fn compare_origin(context: &Context, r: &pair::Record) -> Result<()> {
    r.validate().map_err(denied)?;
    if r.scope != context.intent.scope
        || r.provenance != context.provenance
        || r.addresses != context.intent.addresses
        || r.options.is_none()
        || r.carrier.is_none_or(|c| c.guid != context.bindings[0].guid)
    {
        return Err(GuardError::Conflict);
    }
    for (i, m) in r.members.iter().enumerate() {
        if let Some(m) = m {
            if [m.owner.proof, m.owner.retired_proof]
                .into_iter()
                .flatten()
                .any(|p| p.interface.guid != context.bindings[i + 1].guid)
            {
                return Err(GuardError::Conflict);
            }
        }
    }
    Ok(())
}
fn compare_identity(context: &Context, r: &pair::Record) -> Result<()> {
    compare_origin(context, r)?;
    for (i, m) in r.members.iter().enumerate() {
        if let Some(m) = m {
            if m.owner.phase != crate::member_owner::Phase::Running
                || m.owner.retired_proof.is_some()
                || m.owner
                    .proof
                    .is_none_or(|p| p.interface.guid != context.bindings[i + 1].guid)
            {
                return Err(GuardError::Conflict);
            }
        }
    }
    Ok(())
}
fn compare_stage(context: &Context, r: &pair::Record, purpose: Purpose) -> Result<()> {
    compare_identity(context, r)?;
    if !r.guard.installed
        || r.guard.assigned_sublayer_weight.is_none()
        || r.network.is_none()
        || r.network.as_ref().is_some_and(|n| n.pending.is_some())
    {
        return Err(GuardError::Conflict);
    }
    if purpose != Purpose::Closing
        && (r.stop_stage != 0
            || r.pending_guard.is_some()
            || !matches!(r.phase, pair::Phase::Starting | pair::Phase::Running))
    {
        return Err(GuardError::Conflict);
    }
    match purpose {
        Purpose::Open(s) => {
            if r.pending != Some(pair::Effect::HoldProbe(s))
                || r.guard.permits
                || !(matches!((r.phase,r.operation),
                    (pair::Phase::Starting,Some(pair::Operation::Start(x))) if x==s)
                    || matches!((r.phase,r.operation),
                    (pair::Phase::Running,Some(pair::Operation::Attach(x))) if x==s)
                    || r.phase == pair::Phase::Running
                        && r.operation == Some(pair::Operation::Rebind))
                || r.members[idx(s)].is_none()
            {
                return Err(GuardError::Conflict);
            }
        }
        Purpose::Use(s) => {
            let allowed = match (r.phase, r.operation, r.pending) {
                (
                    pair::Phase::Starting,
                    Some(pair::Operation::Start(active)),
                    Some(pair::Effect::Data(data)),
                ) => active == data && r.guard.active == Some(data),
                (pair::Phase::Running, None, None) => r.guard.active == r.active,
                (
                    pair::Phase::Running,
                    Some(
                        pair::Operation::Attach(_)
                        | pair::Operation::Switch(_)
                        | pair::Operation::Rebind,
                    ),
                    Some(pair::Effect::Data(data)),
                ) => r.guard.active == Some(data),
                _ => false,
            };
            if !allowed
                || !r.guard.permits
                || r.guard.members[idx(s)]
                    .as_ref()
                    .is_none_or(|m| m.probes.is_empty())
            {
                return Err(GuardError::Conflict);
            }
        }
        Purpose::Preparing => {
            if r.phase != pair::Phase::Running
                || r.guard.permits
                || r.pending != Some(pair::Effect::ReleaseProbes)
                || !matches!(
                    r.operation,
                    Some(pair::Operation::Retire(_) | pair::Operation::Rebind)
                )
            {
                return Err(GuardError::Conflict);
            }
        }
        Purpose::Closing => {
            if r.phase != pair::Phase::Closing
                || r.active.is_some()
                || r.operation.is_some()
                || r.guard.permits
                || !matches!(
                    (r.stop_stage, r.pending),
                    (0, Some(pair::Effect::Guard)) | (1, Some(pair::Effect::ReleaseProbes))
                )
            {
                return Err(GuardError::Conflict);
            }
            if r.stop_stage == 0 {
                if let Some(plan) = &r.pending_guard {
                    plan.validate()?;
                    if ![&plan.expected, &plan.withdrawn, &plan.base, &plan.desired]
                        .contains(&&r.guard)
                    {
                        return Err(GuardError::Conflict);
                    }
                }
            } else if r.pending_guard.is_some() {
                return Err(GuardError::Conflict);
            }
        }
        Purpose::Guard => return Err(GuardError::Conflict),
    }
    Ok(())
}
fn compare_model(r: &pair::Record, model: &policy::Model) -> Result<()> {
    model.validate()?;
    if model.scope != r.scope
        || model.carrier.as_ref().is_some_and(|c| {
            Some(c.identity.proof) != r.carrier
                || c.identity.scope != r.scope
                || c.sources != r.addresses.iter().map(|a| a.addr()).collect::<Vec<_>>()
        })
    {
        return Err(GuardError::Conflict);
    }
    for (i, m) in model.members.iter().enumerate() {
        if let Some(m) = m {
            let original = r.members[i].as_ref().ok_or(GuardError::Conflict)?;
            if m.identity.scope != r.scope
                || original
                    .owner
                    .proof
                    .is_none_or(|p| p.interface != m.identity.proof)
                || m.probes.iter().any(|p| {
                    p.source != r.addresses[0].addr()
                        || p.target != std::net::IpAddr::V4(original.probe.target_ipv4)
                        || p.source_port == 0
                        || p.target_port != 53
                        || p.protocol != 17
                })
            {
                return Err(GuardError::Conflict);
            }
        }
    }
    Ok(())
}
/// Exact next split-engine edge, not a port or resource grant. Main's locked
/// attestor independently checks the actual SessionKind and current WFP state.
fn compare_guard_target(
    context: &Context,
    r: &pair::Record,
    desired: &policy::Model,
) -> Result<()> {
    compare_identity(context, r)?;
    if r.pending != Some(pair::Effect::Guard) {
        return Err(GuardError::Conflict);
    }
    let plan = r.pending_guard.as_ref().ok_or(GuardError::Conflict)?;
    plan.validate()?;
    for model in [&plan.expected, &plan.withdrawn, &plan.base, &plan.desired] {
        compare_model(r, model)?;
    }
    if r.guard.installed && r.guard.assigned_sublayer_weight.is_none() {
        return Err(GuardError::Conflict);
    }
    let mut before = plan.expected.clone();
    let mut matched = None;
    for (kind, target, edge) in [
        (policy::SessionKind::DynamicPermits, &plan.withdrawn, 0),
        (policy::SessionKind::StaticBase, &plan.base, 1),
        (policy::SessionKind::DynamicPermits, &plan.desired, 2),
    ] {
        let after = target.inherit_sublayer_weight(&before)?;
        if after != before && before == r.guard && after == *desired {
            policy::validate_session_exchange(&r.scope, &before, &after, kind)?;
            if matched.replace(edge).is_some() {
                return Err(GuardError::Conflict);
            }
        }
        before = after;
    }
    let edge = matched.ok_or(GuardError::Conflict)?;
    if r.phase == pair::Phase::Closing {
        if r.active.is_some()
            || r.operation.is_some()
            || desired.permits
            || !matches!((r.stop_stage, edge), (0, 0) | (10, 1))
            || (r.stop_stage == 10 && desired.installed)
        {
            return Err(GuardError::Conflict);
        }
    } else if !matches!(r.phase, pair::Phase::Starting | pair::Phase::Running)
        || r.operation.is_none()
        || r.stop_stage != 0
        || !desired.installed
    {
        return Err(GuardError::Conflict);
    }
    if !r.guard.installed
        && (r.phase != pair::Phase::Starting
            || !matches!(r.operation, Some(pair::Operation::Start(_)))
            || r.active.is_some()
            || r.network.is_some()
            || desired.assigned_sublayer_weight.is_some())
    {
        return Err(GuardError::Conflict);
    }
    Ok(())
}
fn compare_retired_target(
    context: &Context,
    r: &pair::Record,
    carrier: &policy::Carrier,
    egress: [Option<&policy::Identity>; 2],
) -> Result<()> {
    let empty = policy::Model::empty(r.scope.clone())?;
    compare_guard_target(context, r, &empty)?;
    if r.phase != pair::Phase::Closing
        || r.stop_stage != 10
        || r.guard.permits
        || r.guard.carrier.as_ref() != Some(carrier)
        || r.guard
            .members
            .iter()
            .enumerate()
            .any(|(i, m)| m.as_ref().map(|m| &m.identity) != egress[i])
    {
        return Err(GuardError::Conflict);
    }
    Ok(())
}
fn compare_closing_registration(context: &Context, r: &pair::Record) -> Result<()> {
    compare_origin(context, r)?;
    if r.phase != pair::Phase::Closing
        || r.active.is_some()
        || r.operation.is_some()
        || !matches!(
            (r.stop_stage, r.pending),
            (0, Some(pair::Effect::Guard)) | (1, Some(pair::Effect::ReleaseProbes))
        )
    {
        return Err(GuardError::Conflict);
    }
    compare_model(r, &r.guard)?;
    if r.stop_stage == 0 {
        if let Some(plan) = &r.pending_guard {
            plan.validate()?;
            for model in [&plan.expected, &plan.withdrawn, &plan.base, &plan.desired] {
                compare_model(r, model)?;
            }
            if ![&plan.expected, &plan.withdrawn, &plan.base, &plan.desired].contains(&&r.guard) {
                return Err(GuardError::Conflict);
            }
        }
    } else if r.pending_guard.is_some() {
        return Err(GuardError::Conflict);
    }
    Ok(())
}
fn compare_tuple(r: &pair::Record, s: Slot, t: &ProbeTuple) -> Result<()> {
    let member = r.members[idx(s)].as_ref().ok_or(GuardError::Conflict)?;
    if r.addresses.len() != 1
        || t.source != r.addresses[0].addr()
        || t.source_port == 0
        || t.target != std::net::IpAddr::V4(member.probe.target_ipv4)
        || t.target_port != 53
        || t.protocol != 17
        || r.guard.members[idx(s)]
            .as_ref()
            .is_none_or(|m| m.probes.as_slice() != [t.clone()])
    {
        return Err(GuardError::Conflict);
    }
    Ok(())
}
fn compare_open_tuple(r: &pair::Record, slot: Slot, tuple: &ProbeTuple) -> Result<()> {
    let member = r.members[idx(slot)].as_ref().ok_or(GuardError::Conflict)?;
    if r.pending != Some(pair::Effect::HoldProbe(slot))
        || r.guard.permits
        || r.addresses.len() != 1
        || tuple.source != r.addresses[0].addr()
        || tuple.source_port == 0
        || tuple.target != std::net::IpAddr::V4(member.probe.target_ipv4)
        || tuple.target_port != 53
        || tuple.protocol != 17
    {
        return Err(GuardError::Conflict);
    }
    Ok(())
}
fn compare_guard_probe(
    r: &pair::Record,
    desired: &policy::Model,
    slot: Slot,
    actual: Option<&ProbeTuple>,
    ack: Option<&ProbeTuple>,
) -> Result<()> {
    desired.validate()?;
    let Some(member) = &desired.members[idx(slot)] else {
        return if actual.is_none() && ack.is_none() {
            Ok(())
        } else {
            Err(GuardError::Conflict)
        };
    };
    let Some(tuple) = actual else {
        return if !desired.permits && member.probes.is_empty() && ack.is_none() {
            Ok(())
        } else {
            Err(GuardError::Conflict)
        };
    };
    let captured = r.members[idx(slot)].as_ref().ok_or(GuardError::Conflict)?;
    if tuple.source != r.addresses[0].addr()
        || tuple.source_port == 0
        || tuple.target != std::net::IpAddr::V4(captured.probe.target_ipv4)
        || tuple.target_port != 53
        || tuple.protocol != 17
        || ((desired.permits || !member.probes.is_empty())
            && (member.probes.as_slice() != [tuple.clone()] || ack != Some(tuple)))
    {
        return Err(GuardError::Conflict);
    }
    Ok(())
}
fn compare_guard(r: &pair::Record, purpose: Purpose, actual: &Snapshot) -> Result<()> {
    r.guard.validate()?;
    let weight = r
        .guard
        .assigned_sublayer_weight
        .ok_or(GuardError::Conflict)?;
    if !r.guard.installed
        || actual != &r.guard.expected
        || actual.sublayer.as_ref().is_none_or(|s| s.weight != weight)
        || (matches!(purpose, Purpose::Use(_)) != r.guard.permits)
        || (!matches!(purpose, Purpose::Use(_))
            && actual
                .filters
                .iter()
                .any(|f| f.action == policy::Action::Permit))
        || actual.carrier.as_ref().is_none_or(|c| {
            Some(c.identity.proof) != r.carrier
                || c.identity.scope != r.scope
                || c.sources != r.addresses.iter().map(|a| a.addr()).collect::<Vec<_>>()
        })
    {
        return Err(GuardError::Conflict);
    }
    for (i, m) in r.members.iter().enumerate() {
        if actual.egress[i].as_ref().map(|e| e.proof)
            != m.as_ref().and_then(|m| m.owner.proof.map(|p| p.interface))
        {
            return Err(GuardError::Conflict);
        }
    }
    Ok(())
}
type RowFacts<'a> = [Option<(&'a rows::Binding, &'a rows::Record, &'a rows::Snapshot)>; 3];
fn compare_rows(
    context: &Context,
    r: &pair::Record,
    facts: RowFacts<'_>,
) -> Result<Vec<InterfaceMetric>> {
    compare_rows_for(context, r, facts, RowMode::Ports)
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum RowMode {
    Bases,
    Ports,
}
type GuardRowFacts<'a> = [Option<(
    &'a rows::Binding,
    &'a rows::Record,
    Option<&'a rows::Snapshot>,
)>; 3];
fn compare_guard_rows(
    context: &Context,
    r: &pair::Record,
    desired: &policy::Model,
    facts: GuardRowFacts<'_>,
    history: [Option<&super::member_carrier_members::ClosedMemberBinding>; 2],
) -> Result<Vec<InterfaceMetric>> {
    compare_guard_target(context, r, desired)?;
    let mut closed_rows = [false; 3];
    for (i, closed) in history.into_iter().enumerate() {
        let Some(closed) = closed else { continue };
        closed.comparison_provider(context).map_err(denied)?;
        let slot = if i == 0 { Slot::A } else { Slot::B };
        let (binding, ack, actual) = facts[i + 1].ok_or(GuardError::Conflict)?;
        binding.validate().map_err(denied)?;
        ack.validate().map_err(denied)?;
        if closed.intent.slot
            != if i == 0 {
                nelomai_contracts::dispatcher::TunnelSlot::A
            } else {
                nelomai_contracts::dispatcher::TunnelSlot::B
            }
            || binding.scope != r.scope
            || binding.boot_id != context.provenance.boot_id
            || binding.runtime != context.provenance.runtime
            || binding.network_epoch != context.provenance.network_epoch
            || binding.role != [rows::Role::MemberA, rows::Role::MemberB][i]
            || binding.name != context.bindings[i + 1].name
            || binding.guid != closed.proof.interface.guid
            || binding.key.index != closed.proof.interface.index
            || binding.key.luid != closed.proof.interface.luid
            || r.addresses.as_slice()
                != [ipnet::IpNet::from(std::net::IpAddr::V4(
                    binding.address.into(),
                ))]
            || ack.binding != *binding
            || actual.is_some()
            || ack.phase != rows::Phase::Stopped
            || ack.pending.is_some()
            || ack.creation.is_some()
            || ack.baseline.address.is_some()
            || ack.current.address.is_some()
            || ack.current.interface.policy != ack.baseline.interface.policy
            || ack.baseline.interface.policy.weak_host_send
            || ack.baseline.interface.policy.weak_host_receive
            || ack.baseline.interface.policy.forwarding
            || ack.baseline.interface.policy.advertising
            || r.active == Some(slot)
            || desired.active == Some(slot)
            || desired.members[i].is_some()
            || r.network.as_ref().is_none_or(|n| {
                n.pending.is_some()
                    || n.current
                        .routes
                        .iter()
                        .any(|route| route.interface == binding.key.index)
            })
        {
            return Err(GuardError::Conflict);
        }
        if let Some(member) = &r.members[i] {
            // Removing old static bases is ONLY the exact standby Retire edge.
            // Preserve C, captured priority and the WHOLE other member unchanged.
            let plan = r.pending_guard.as_ref().ok_or(GuardError::Conflict)?;
            if r.phase != pair::Phase::Running
                || r.operation != Some(pair::Operation::Retire(slot))
                || r.active != Some(if i == 0 { Slot::B } else { Slot::A })
                || member.owner.intent != closed.intent
                || member.owner.proof != Some(closed.proof)
                || plan.expected != r.guard
                || plan.expected.permits
                || plan.expected.active.is_some()
                || plan.expected.members[i].as_ref().is_none_or(|m| {
                    m.identity.scope != closed.intent.scope
                        || m.identity.proof != closed.proof.interface
                })
                || !plan.base.installed
                || plan.base.permits
                || plan.base.active.is_some()
                || plan.base.carrier != plan.expected.carrier
                || plan.base.assigned_sublayer_weight != plan.expected.assigned_sublayer_weight
                || plan.base.members[i].is_some()
                || plan.base.members[1 - i].is_none()
                || plan.base.members[1 - i] != plan.expected.members[1 - i]
                || *desired != plan.base
                || plan.desired != plan.base
            {
                return Err(GuardError::Conflict);
            }
        }
        closed_rows[i + 1] = true;
    }
    let mut live = [None; 3];
    for (i, fact) in facts.into_iter().enumerate() {
        if closed_rows[i] {
            continue;
        }
        live[i] = match fact {
            Some((binding, ack, actual)) => {
                Some((binding, ack, actual.ok_or(GuardError::Conflict)?))
            }
            None => None,
        };
    }
    compare_live_rows(
        context,
        r,
        live,
        if desired.permits {
            RowMode::Ports
        } else {
            RowMode::Bases
        },
        closed_rows,
    )
}
fn compare_rows_for(
    context: &Context,
    r: &pair::Record,
    facts: RowFacts<'_>,
    mode: RowMode,
) -> Result<Vec<InterfaceMetric>> {
    compare_live_rows(context, r, facts, mode, [false; 3])
}
fn compare_live_rows(
    context: &Context,
    r: &pair::Record,
    facts: RowFacts<'_>,
    mode: RowMode,
    closed_rows: [bool; 3],
) -> Result<Vec<InterfaceMetric>> {
    compare_identity(context, r)?;
    let proofs = [
        r.carrier,
        r.members[0]
            .as_ref()
            .and_then(|m| m.owner.proof.map(|p| p.interface)),
        r.members[1]
            .as_ref()
            .and_then(|m| m.owner.proof.map(|p| p.interface)),
    ];
    let mut metrics = Vec::new();
    for (i, (proof, fact)) in proofs.iter().zip(facts).enumerate() {
        // Only compare_guard_rows' full actual-history comparison can skip a
        // stopped member. It supplies NO metric, live observation or permit.
        if closed_rows[i] {
            continue;
        }
        let Some(proof) = proof else {
            if fact.is_some() {
                return Err(GuardError::Conflict);
            }
            continue;
        };
        let (binding, ack, actual) = fact.ok_or(GuardError::Conflict)?;
        binding.validate().map_err(denied)?;
        ack.validate().map_err(denied)?;
        actual.validate(binding).map_err(denied)?;
        if binding.scope != r.scope
            || binding.boot_id != context.provenance.boot_id
            || binding.runtime != context.provenance.runtime
            || binding.network_epoch != context.provenance.network_epoch
            || binding.role
                != [
                    rows::Role::Carrier,
                    rows::Role::MemberA,
                    rows::Role::MemberB,
                ][i]
            || binding.name != context.bindings[i].name
            || binding.guid != proof.guid
            || binding.key.index != proof.index
            || binding.key.luid != proof.luid
            || r.addresses.as_slice()
                != [ipnet::IpNet::from(std::net::IpAddr::V4(
                    binding.address.into(),
                ))]
            || ack.binding != *binding
            || ack.phase != rows::Phase::Captured
            || ack.pending.is_some()
            || !rows::same_owned(&ack.current, actual)
            || ack.baseline.address.is_some()
            || ack.baseline.interface.policy.weak_host_send
            || ack.baseline.interface.policy.weak_host_receive
            || ack.baseline.interface.policy.forwarding
            || ack.baseline.interface.policy.advertising
        {
            return Err(GuardError::Conflict);
        }
        let mut desired = ack.baseline.interface.policy.clone();
        desired.weak_host_send = true;
        desired.weak_host_receive = true;
        if actual.interface.policy != desired
            && !(mode == RowMode::Bases && actual.interface.policy == ack.baseline.interface.policy)
        {
            return Err(GuardError::Conflict);
        }
        if i == 0 {
            let address = actual.address.as_ref().ok_or(GuardError::Conflict)?;
            address.policy.validate_creation().map_err(denied)?;
            if address.observed.dad_state != 4
                || address.observed.creation_timestamp <= 0
                || ack
                    .creation
                    .as_ref()
                    .is_none_or(|created| !rows::same_address(created, address))
            {
                return Err(GuardError::Conflict);
            }
        } else {
            if ack.creation.is_some() || actual.address.is_some() {
                return Err(GuardError::Conflict);
            }
            metrics.push(InterfaceMetric {
                interface: proof.index,
                ipv6: false,
                metric: actual.interface.policy.metric,
            });
        }
    }
    Ok(metrics)
}
struct MetadataFlight<'a> {
    fence: &'a Fence,
    completed: bool,
}
impl Drop for MetadataFlight<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.fence.failed.set(true);
            self.fence.reentered.set(true);
        }
    }
}
fn checked_metadata<T>(fence: &Fence, call: impl FnOnce() -> Result<T>) -> Result<T> {
    let mut flight = MetadataFlight {
        fence,
        completed: false,
    };
    let result = call()?;
    flight.completed = true;
    Ok(result)
}
fn selected(r: &pair::Record) -> Result<Slot> {
    if let Some(s) = r.guard.active.or(r.active) {
        return Ok(s);
    }
    if let Some(pair::Operation::Start(s)) = r.operation {
        return Ok(s);
    }
    // Closing retains no forward active field. Compare the original current
    // journal's active-probe metric, then require the actual network read's SAME
    // selection. This factual projection does not grant socket/route ownership.
    let n = r.network.as_ref().ok_or(GuardError::Conflict)?;
    let candidates = [Slot::A, Slot::B]
        .into_iter()
        .filter(|s| {
            r.members[idx(*s)].as_ref().is_some_and(|m| {
                m.owner.proof.is_some_and(|p| {
                    n.current.routes.iter().any(|route| {
                        route.interface == p.interface.index
                            && route.destination
                                == ipnet::IpNet::from(std::net::IpAddr::V4(m.probe.target_ipv4))
                            && route.metric == crate::member_plan::ACTIVE_PROBE_METRIC
                    })
                })
            })
        })
        .collect::<Vec<_>>();
    match candidates.as_slice() {
        [s] => Ok(*s),
        _ => Err(GuardError::Conflict),
    }
}
fn routes(routes: &[RouteValue]) -> Result<BTreeMap<(ipnet::IpNet, u32), &RouteValue>> {
    if routes.len() > crate::member_plan::MAX_ROUTES {
        return Err(GuardError::Conflict);
    }
    let mut keys = BTreeMap::new();
    for route in routes {
        crate::member_routes::validate_route(route, route.destination, route.interface)
            .map_err(denied)?;
        if keys
            .insert((route.destination, route.interface), route)
            .is_some()
        {
            return Err(GuardError::Conflict);
        }
    }
    Ok(keys)
}
fn network_plan(
    r: &pair::Record,
    physical: &PhysicalSnapshot,
    member_metrics: &[InterfaceMetric],
) -> Result<Vec<RouteValue>> {
    let options = r.options.as_ref().ok_or(GuardError::Conflict)?;
    options.validate().map_err(denied)?;
    let mut exclusions = options
        .excluded_ipv4_cidrs
        .iter()
        .map(|s| s.parse::<ipnet::IpNet>().map_err(denied))
        .collect::<Result<Vec<_>>>()?;
    if options.exclude_local_networks {
        exclusions.extend(physical.lan_prefixes());
    }
    let mut members = Vec::new();
    for (i, m) in r.members.iter().enumerate() {
        let s = if i == 0 { Slot::A } else { Slot::B };
        if r.operation == Some(pair::Operation::Retire(s)) {
            continue;
        }
        if let Some(m) = m {
            physical.resolve_host(m.endpoint).map_err(denied)?;
            exclusions.push(ipnet::IpNet::from(m.endpoint));
            if m.allowed.iter().any(|n| n.addr().is_ipv6()) {
                return Err(GuardError::Conflict);
            }
            members.push(MemberRoutes {
                slot: s,
                interface: m.owner.proof.ok_or(GuardError::Conflict)?.interface.index,
                allowed: m.allowed.clone(),
                probe: m.probe.target_ipv4,
            });
        }
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
    if destinations.len() > crate::member_plan::MAX_ROUTES {
        return Err(GuardError::Conflict);
    }
    let mut bypasses = Vec::new();
    let mut retained = Vec::new();
    for destination in destinations {
        let path = physical.resolve_bypass(destination).map_err(denied)?;
        let route = RouteValue {
            destination,
            scope: RouteScope::WindowsInterface(path.proof.identity.index),
            interface: path.proof.identity.index,
            gateway: path.row.route.gateway,
            metric: path.row.route.metric,
        };
        if route == path.row.route {
            retained.push(route.clone());
        }
        bypasses.push(route);
    }
    let mut metrics = member_metrics
        .iter()
        .copied()
        .filter(|m| members.iter().any(|member| member.interface == m.interface))
        .collect::<Vec<_>>();
    metrics.extend(physical.proofs().values().map(|p| InterfaceMetric {
        interface: p.identity.index,
        ipv6: p.family == Family::V6,
        metric: p.metric,
    }));
    let plan = crate::member_plan::member_route_plan(
        selected(r)?,
        &members,
        &exclusions,
        &bypasses,
        &metrics,
        0,
    )
    .map_err(denied)?;
    crate::member_plan::validate_retained_probe_routes(&plan, &members, &retained, &metrics)
        .map_err(denied)?;
    Ok(plan
        .routes
        .into_iter()
        .filter(|r| !retained.contains(r))
        .collect())
}
fn compare_network(
    r: &pair::Record,
    facts: &super::member_carrier_network::NetworkFacts,
    actual_dns: &dns::Snapshot,
    protected: Option<&[u8]>,
    physical: &PhysicalSnapshot,
    metrics: &[InterfaceMetric],
) -> Result<()> {
    let n = r.network.as_ref().ok_or(GuardError::Conflict)?;
    if protected.is_none_or(|b| b.is_empty())
        || n.pending.is_some()
        || facts.pending.is_some()
        || facts.pending_active.is_some()
        || facts.stopping
        || facts.active != Some(selected(r)?)
        || routes(&n.current.routes)? != routes(&network_plan(r, physical, metrics)?)?
    {
        return Err(GuardError::Conflict);
    }
    let expected_dns = n.current.dns.as_ref().ok_or(GuardError::Conflict)?;
    let baseline = n.baseline.dns.as_ref().ok_or(GuardError::Conflict)?;
    let desired = if r.dns.is_empty() {
        baseline.clone()
    } else {
        baseline.with_servers(&r.dns).map_err(denied)?
    };
    if expected_dns != &desired || actual_dns != expected_dns {
        return Err(GuardError::Conflict);
    }
    let c = r.carrier.ok_or(GuardError::Conflict)?;
    if actual_dns.interface.scope != r.scope
        || actual_dns.interface.guid != c.guid
        || actual_dns.interface.luid != c.luid
        || actual_dns.interface.index != c.index
    {
        return Err(GuardError::Conflict);
    }
    let expected = routes(&n.current.routes)?;
    let mut read = BTreeMap::new();
    for fact in &facts.current {
        let row = fact.actual.as_ref().ok_or(GuardError::Conflict)?;
        let proof = if let Some(m) = r.members.iter().find(|m| {
            m.as_ref()
                .and_then(|m| m.owner.proof)
                .is_some_and(|p| p.interface.index == fact.expected.interface)
        }) {
            let p = m.as_ref().unwrap().owner.proof.unwrap().interface;
            NativeProof {
                index: p.index,
                luid: p.luid,
            }
        } else {
            let p = physical
                .proofs()
                .get(&(
                    Family::of(fact.expected.destination.addr()),
                    fact.expected.interface,
                ))
                .ok_or(GuardError::Conflict)?;
            NativeProof {
                index: p.identity.index,
                luid: p.identity.luid,
            }
        };
        if row != &Row::static_route(fact.expected.clone(), proof)
            || read
                .insert(
                    (fact.expected.destination, fact.expected.interface),
                    &fact.expected,
                )
                .is_some()
        {
            return Err(GuardError::Conflict);
        }
    }
    if read != expected {
        return Err(GuardError::Conflict);
    }
    Ok(())
}
struct Fence {
    busy: Cell<bool>,
    failed: Cell<bool>,
    reentered: Cell<bool>,
}
struct Flight<'a> {
    fence: &'a Fence,
    complete: bool,
}
impl Drop for Flight<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.fence.failed.set(true);
        }
        self.fence.busy.set(false);
    }
}
impl Fence {
    fn new() -> Self {
        Self {
            busy: Cell::new(false),
            failed: Cell::new(false),
            reentered: Cell::new(false),
        }
    }
    fn inspect<T>(&self, purpose: Purpose, call: impl FnOnce() -> Result<T>) -> Result<T> {
        if self.busy.replace(true) {
            self.failed.set(true);
            self.reentered.set(true);
            return Err(GuardError::Conflict);
        }
        if self.failed.get() && purpose != Purpose::Closing {
            self.busy.set(false);
            return Err(GuardError::Conflict);
        }
        self.reentered.set(false);
        let mut flight = Flight {
            fence: self,
            complete: false,
        };
        let value = call()?;
        if self.reentered.get() {
            return Err(GuardError::Conflict);
        }
        flight.complete = true;
        Ok(value)
    }
}
struct Retained<T> {
    attempted: Cell<bool>,
    value: RefCell<Option<T>>,
}
impl<T> Retained<T> {
    fn new() -> Self {
        Self {
            attempted: Cell::new(false),
            value: RefCell::new(None),
        }
    }
    fn first(
        &self,
        original: T,
        fence: &Fence,
        check: impl FnOnce(&T) -> Result<()>,
    ) -> Result<()> {
        self.first_for(original, fence, Purpose::Open(Slot::A), check)
    }
    fn first_for(
        &self,
        original: T,
        fence: &Fence,
        purpose: Purpose,
        check: impl FnOnce(&T) -> Result<()>,
    ) -> Result<()> {
        if self.attempted.replace(true) {
            fence.failed.set(true);
            fence.reentered.set(true);
            return Err(GuardError::Conflict);
        }
        *self.value.borrow_mut() = Some(original);
        fence.inspect(purpose, || {
            let retained = self.value.try_borrow().map_err(denied)?;
            check(retained.as_ref().ok_or(GuardError::Conflict)?)
        })
    }
}
#[cfg(windows)]
pub(crate) mod native {
    use super::*;
    use crate::windows::{
        member_carrier_guard::{NativeGuard, Wfp, WindowBindingAttestor},
        member_carrier_key_authority::RuntimeRead,
        member_carrier_network::native::{NativeClosingNetworkRead, NativeNetworkRead},
        member_carrier_pair_store::native_store::NativePairIntentRead,
        member_carrier_probes::native::{
            HeldProbeRead, NativeProbeGate, ProbeInventoryRead, ProbeInventoryWeakRead,
        },
        member_carrier_runtime::native::{
            NativeBindingsWindow, NativeClosingRead, NativeResourceRowsRead, NativeSourceRead,
            RetiredCarrierRead,
        },
        member_carrier_wintun as wintun,
        member_native_deadline::{NativeDeadline, NativeDeadlineReadPin},
    };
    use std::{
        io,
        net::Ipv4Addr,
        rc::{Rc, Weak},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
    };
    type Inventory<A> = ProbeInventoryRead<Wfp, A, WfpProbeGate<A>>;
    type WeakInventory<A> = ProbeInventoryWeakRead<Wfp, A, WfpProbeGate<A>>;
    type Held<A> = HeldProbeRead<Wfp, A, WfpProbeGate<A>>;
    struct Selected {
        pin: Rc<NativePairIntentRead>,
        record: pair::Record,
    }
    struct Closing {
        pin: Rc<NativeClosingRead>,
        network: Rc<NativeClosingNetworkRead>,
    }
    struct HeldRegistration {
        tuple: RefCell<Option<ProbeTuple>>,
    }
    /// The CALLER must retain this root for the complete supervised actor call
    /// and through all cleanup. No owning original is returned solely in Err.
    /// Gate holds only Weak<Self>; inventory and held originals are owned by
    /// the caller's canonical inventory, never by a circular gate registration.
    pub(crate) struct NativeProbeResourceState<A: WindowBindingAttestor> {
        context: Context,
        runtime: RuntimeRead,
        source: Rc<NativeSourceRead>,
        guard: Rc<RefCell<NativeGuard<Wfp, A>>>,
        rows: Rc<NativeResourceRowsRead>,
        network: Rc<NativeNetworkRead>,
        supervisor: Rc<NativeDeadline>,
        deadline: NativeDeadlineReadPin,
        cancelled: Arc<AtomicBool>,
        selected: RefCell<Selected>,
        fence: Fence,
        gate: Rc<WfpProbeGate<A>>,
        inventory: Retained<WeakInventory<A>>,
        held: [Retained<HeldRegistration>; 2],
        closing: Retained<Closing>,
    }
    pub(crate) struct WfpProbeGate<A: WindowBindingAttestor> {
        state: Weak<NativeProbeResourceState<A>>,
    }
    fn io_denied<E>(_: E) -> io::Error {
        io::Error::other("carrier_probe_gate_conflict")
    }
    fn native_denied<E>(_: E) -> wintun::Error {
        wintun::Error::Conflict
    }
    impl<A: WindowBindingAttestor> NativeProbeResourceState<A> {
        /// Infallible retention BEFORE any fallible postflight. Keep the root
        /// outside Guard/ProbeInventory owners. All inputs are real SDK-backed
        /// originals; there is no bool/trait/default resource-permission input.
        #[allow(clippy::too_many_arguments)]
        pub(crate) fn new(
            context: Context,
            runtime: RuntimeRead,
            source: Rc<NativeSourceRead>,
            guard: Rc<RefCell<NativeGuard<Wfp, A>>>,
            rows: Rc<NativeResourceRowsRead>,
            network: Rc<NativeNetworkRead>,
            pair: Rc<NativePairIntentRead>,
            expected: pair::Record,
            supervisor: Rc<NativeDeadline>,
            deadline: NativeDeadlineReadPin,
            cancelled: Arc<AtomicBool>,
        ) -> Rc<Self> {
            Rc::new_cyclic(|state| Self {
                context,
                runtime,
                source,
                guard,
                rows,
                network,
                supervisor,
                deadline,
                cancelled,
                selected: RefCell::new(Selected {
                    pin: pair,
                    record: expected,
                }),
                fence: Fence::new(),
                gate: Rc::new(WfpProbeGate {
                    state: state.clone(),
                }),
                inventory: Retained::new(),
                held: [Retained::new(), Retained::new()],
                closing: Retained::new(),
            })
        }
        pub(crate) fn gate(&self) -> Rc<WfpProbeGate<A>> {
            self.gate.clone()
        }
        /// Mandatory G callback BETWEEN the attestor's locked WFP snapshots.
        /// Pair and Guard are already held by that outer transaction. This
        /// method never reads either, never enters Source, and never issues IO.
        /// Select this exact protected Pair ACK BEFORE entering that transaction.
        pub(crate) fn verify_guard_resources(
            &self,
            record: &pair::Record,
            window: &NativeBindingsWindow<'_>,
            desired: &policy::Model,
        ) -> Result<()> {
            let purpose = if record.phase == pair::Phase::Closing {
                Purpose::Closing
            } else {
                Purpose::Guard
            };
            self.fence.inspect(purpose, || {
                compare_guard_target(&self.context, record, desired)?;
                let selected = self.selected.try_borrow().map_err(denied)?;
                if selected.record != *record {
                    return Err(GuardError::Conflict);
                }
                self.continuity(&selected)?;
                self.original_window(window, purpose)?;
                let inventory = self.inventory()?;
                let history = [
                    window.closed_member(nelomai_contracts::dispatcher::TunnelSlot::A),
                    window.closed_member(nelomai_contracts::dispatcher::TunnelSlot::B),
                ];
                // Require the SAME canonical held original's real close ACK.
                // Never demand closure of the other live member, sample a
                // historical held socket, or infer a slot from tuple metadata.
                let originals = inventory.originals_by_slot()?;
                for (i, closed) in history.iter().enumerate() {
                    if closed.is_some() {
                        let slot = if i == 0 { Slot::A } else { Slot::B };
                        let original = originals[i].as_ref().ok_or(GuardError::Conflict)?;
                        inventory.verify_member_slot(slot, original)?;
                        original.retired()?;
                    }
                }
                let metrics = self
                    .rows
                    .inspect_in_window(window, |facts| {
                        let borrowed = std::array::from_fn(|i| {
                            facts.rows[i]
                                .as_ref()
                                .map(|r| (&r.binding, &r.acknowledged, r.observed.as_ref()))
                        });
                        compare_guard_rows(&self.context, record, desired, borrowed, history)
                            .map_err(native_denied)
                    })
                    .map_err(denied)?;
                if desired.permits {
                    // The pending target contains the new active selection;
                    // actual Pair.guard still holds the preceding deny-only
                    // base. Project ONLY that already-validated exact target
                    // for route comparison, never for ownership or WFP reads.
                    let mut target = record.clone();
                    target.guard = desired.clone();
                    self.network
                        .inspect_in_window(window, |facts| {
                            let physical =
                                self.physical(window, &facts.routes).map_err(io_denied)?;
                            compare_network(
                                &target,
                                &facts.routes,
                                &facts.dns,
                                facts.protected_record.as_deref(),
                                &physical,
                                &metrics,
                            )
                            .map_err(io_denied)?;
                            let after = self.physical(window, &facts.routes).map_err(io_denied)?;
                            if physical.rows() != after.rows()
                                || physical.proofs() != after.proofs()
                            {
                                return Err(io_denied(()));
                            }
                            Ok(())
                        })
                        .map_err(denied)?;
                }
                // No socket is held mutably here. Canonical slots come ONLY
                // from immutable actual inventory entries, never tuple values.
                // Closing withdraws allows; closed/failed sockets need not be
                // sampled with a forward Source reader to deny their permits.
                if purpose != Purpose::Closing {
                    for (i, original) in originals.iter().enumerate() {
                        let slot = if i == 0 { Slot::A } else { Slot::B };
                        match original {
                            Some(original) => {
                                inventory.verify_member_slot(slot, original)?;
                                if desired.members[i].is_none() {
                                    // Canonical entries retain real close ACKs
                                    // after standby retirement. Never sample a
                                    // closed original through live Source.
                                    original.retired()?;
                                    compare_guard_probe(record, desired, slot, None, None)?;
                                    continue;
                                }
                                let tuple = original.inspect_tuple_in_window(window)?;
                                let registration =
                                    self.held[i].value.try_borrow().map_err(denied)?;
                                let ack = registration
                                    .as_ref()
                                    .map(|r| r.tuple.try_borrow().map_err(denied))
                                    .transpose()?;
                                compare_guard_probe(
                                    record,
                                    desired,
                                    slot,
                                    Some(&tuple),
                                    ack.as_ref().and_then(|a| a.as_ref()),
                                )?;
                            }
                            None => compare_guard_probe(record, desired, slot, None, None)?,
                        }
                    }
                } else if desired.permits {
                    return Err(GuardError::Conflict);
                }
                self.original_window(window, purpose)?;
                self.continuity(&selected)
            })
        }
        /// Final static-base removal ONLY. Caller supplies the SAME registered
        /// opaque retired pin inside its original full-absence bracket. No live
        /// Source/Pair/Guard query, historical NIC query, or numeric adoption.
        pub(crate) fn verify_retired_guard_resources(
            &self,
            record: &pair::Record,
            retired: &RetiredCarrierRead,
            bindings: &crate::windows::member_carrier_guard::Bindings,
        ) -> Result<()> {
            self.fence.inspect(Purpose::Closing, || {
                let selected = self.selected.try_borrow().map_err(denied)?;
                if selected.record != *record
                    || bindings.scope != record.scope
                    || !retired.matches_source_origin(&self.source)
                {
                    return Err(GuardError::Conflict);
                }
                self.continuity(&selected)?;
                compare_retired_target(
                    &self.context,
                    record,
                    bindings.carrier.as_ref().ok_or(GuardError::Conflict)?,
                    bindings.egress.each_ref().map(Option::as_ref),
                )?;
                // Actual original clone/base close ACKs for ALL canonical
                // entries, including unpublished ACKs; never a forward sample.
                self.inventory()?.inspect_retired()?;
                self.continuity(&selected)
            })
        }
        fn continuity(&self, selected: &Selected) -> Result<()> {
            compare_origin(&self.context, &selected.record)?;
            if !selected.pin.matches_runtime(&self.runtime) {
                return Err(GuardError::Conflict);
            }
            self.deadline
                .verify_runtime_call(&self.supervisor, &self.runtime, &self.context)
                .map_err(denied)?;
            if selected.record.phase != pair::Phase::Closing
                && (self.cancelled.load(Ordering::Acquire)
                    || !self.runtime.fresh(&self.context).map_err(denied)?)
            {
                return Err(GuardError::Conflict);
            }
            Ok(())
        }
        fn current(&self, selected: &Selected, purpose: Option<Purpose>) -> Result<()> {
            compare_origin(&self.context, &selected.record)?;
            if !selected.pin.matches_runtime(&self.runtime)
                || (selected.record.phase != pair::Phase::Closing
                    && self.cancelled.load(Ordering::Acquire))
            {
                return Err(GuardError::Conflict);
            }
            if let Some(purpose) = purpose {
                compare_stage(&self.context, &selected.record, purpose).inspect_err(|_error| {
                    #[cfg(all(test, windows))]
                    eprintln!("actual native probe current stage: {_error:?}");
                })?;
            }
            let check = |actual: &pair::Record| {
                if actual == &selected.record {
                    Ok(())
                } else {
                    #[cfg(all(test, windows))]
                    eprintln!("actual native probe current selected record differs");
                    Err(io_denied(()))
                }
            };
            match purpose {
                Some(Purpose::Closing) => selected.pin.inspect_cleanup_effect(
                    &self.runtime,
                    &self.supervisor,
                    &selected.record,
                    selected.record.stop_stage,
                    check,
                ),
                Some(Purpose::Open(_) | Purpose::Preparing | Purpose::Use(_))
                    if selected.record.pending.is_some() =>
                {
                    selected.pin.inspect_effect(
                        &self.runtime,
                        &self.supervisor,
                        &selected.record,
                        selected.record.pending.ok_or(GuardError::Conflict)?,
                        check,
                    )
                }
                _ => selected.pin.inspect(&self.runtime, &self.supervisor, check),
            }
            .map_err(denied)
            .inspect_err(|_error| {
                #[cfg(all(test, windows))]
                eprintln!("actual native probe current original Pair read: {_error:?}");
            })?;
            self.continuity(selected).inspect_err(|_error| {
                #[cfg(all(test, windows))]
                eprintln!("actual native probe current final continuity: {_error:?}");
            })
        }
        fn caps(
            &self,
            source: &Rc<NativeSourceRead>,
            guard: &Rc<RefCell<NativeGuard<Wfp, A>>>,
        ) -> Result<()> {
            if !Rc::ptr_eq(source, &self.source) || !Rc::ptr_eq(guard, &self.guard) {
                return Err(GuardError::Conflict);
            }
            // Identity/Calling ONLY. Never enter Pair, Source, Guard or held
            // socket here: native tuple reads invoke this while already joined.
            let selected = self.selected.try_borrow().map_err(denied)?;
            self.continuity(&selected)
        }
        fn inventory(&self) -> Result<Inventory<A>> {
            let slot = self.inventory.value.try_borrow().map_err(denied)?;
            let inventory = slot.as_ref().ok_or(GuardError::Conflict)?.upgrade()?;
            inventory.matches_caps(&self.source, &self.guard, &self.gate)?;
            Ok(inventory)
        }
        fn original_window(
            &self,
            window: &NativeBindingsWindow<'_>,
            purpose: Purpose,
        ) -> Result<()> {
            if !window.matches_runtime(&self.runtime) {
                return Err(GuardError::Conflict);
            }
            if purpose == Purpose::Closing {
                let slot = self.closing.value.try_borrow().map_err(denied)?;
                let closing = slot.as_ref().ok_or(GuardError::Conflict)?;
                if !closing.pin.matches_source_origin(&self.source)
                    || !window.matches_closing(&closing.pin)
                {
                    return Err(GuardError::Conflict);
                }
            } else if self.closing.attempted.get() || !window.matches_source(&self.source) {
                return Err(GuardError::Conflict);
            }
            Ok(())
        }
        fn physical(
            &self,
            window: &NativeBindingsWindow<'_>,
            facts: &super::super::member_carrier_network::NetworkFacts,
        ) -> Result<PhysicalSnapshot> {
            let b = window.bindings();
            let identities = b
                .carrier
                .as_ref()
                .map(|c| &c.identity)
                .into_iter()
                .chain(b.egress.iter().flatten())
                .map(|i| InterfaceIdentity {
                    index: i.proof.index,
                    luid: i.proof.luid,
                    guid: i.proof.guid,
                })
                .collect::<Vec<_>>();
            let captured = crate::windows::member_physical::capture(&identities).map_err(denied)?;
            // Exclude ONLY exact sampled journal-owned physical rows; never a
            // guessed route key, allowing an endpoint bypass to resolve itself.
            let physical_owned = facts
                .current
                .iter()
                .filter(|f| {
                    !b.egress
                        .iter()
                        .flatten()
                        .any(|i| i.proof.index == f.expected.interface)
                })
                .map(|f| f.actual.clone().ok_or(GuardError::Conflict))
                .collect::<Result<Vec<_>>>()?;
            captured.without_owned_rows(&physical_owned).map_err(denied)
        }
        fn sample(
            &self,
            selected: &Selected,
            purpose: Purpose,
            window: &NativeBindingsWindow<'_>,
        ) -> Result<()> {
            self.original_window(window, purpose)
                .inspect_err(|_error| {
                    #[cfg(all(test, windows))]
                    eprintln!("actual native probe sample original window: {_error:?}");
                })?;
            self.current(selected, Some(purpose))
                .inspect_err(|_error| {
                    #[cfg(all(test, windows))]
                    eprintln!("actual native probe sample current before: {_error:?}");
                })?;
            // Each snapshot uses the original Wfp/IDs/priority inside its own
            // read-only transaction. No Guard/Pair lease spans a sibling read.
            let before = self
                .guard
                .try_borrow_mut()
                .map_err(denied)
                .inspect_err(|_error| {
                    #[cfg(all(test, windows))]
                    eprintln!("actual native probe sample guard borrow: {_error:?}");
                })?
                .snapshot_in_window(window)
                .inspect_err(|_error| {
                    #[cfg(all(test, windows))]
                    eprintln!("actual native probe sample guard snapshot: {_error:?}");
                })?;
            compare_guard(&selected.record, purpose, &before).inspect_err(|_error| {
                #[cfg(all(test, windows))]
                eprintln!("actual native probe sample compare guard before: {_error:?}");
                #[cfg(all(test, windows))]
                eprintln!("actual native probe guard values expected={} permits={} actualPermits={} assigned={:?} actualWeight={:?}", before == selected.record.guard.expected, selected.record.guard.permits, before.filters.iter().any(|f| f.action == policy::Action::Permit), selected.record.guard.assigned_sublayer_weight, before.sublayer.as_ref().map(|s| s.weight));
            })?;
            let metrics = self
                .rows
                .inspect_in_window(window, |facts| {
                    let borrowed = std::array::from_fn(|i| {
                        facts.rows[i].as_ref().and_then(|r| {
                            r.observed
                                .as_ref()
                                .map(|actual| (&r.binding, &r.acknowledged, actual))
                        })
                    });
                    compare_rows(&self.context, &selected.record, borrowed)
                        .inspect_err(|_error| {
                            #[cfg(all(test, windows))]
                            eprintln!("actual native probe sample compare rows: {_error:?}");
                            #[cfg(all(test, windows))]
                            for (i, fact) in borrowed.iter().enumerate() {
                                if let Some((binding, ack, actual)) = fact {
                                    eprintln!("actual native probe row i={i} role={:?} phase={:?} pending={} owned={}", binding.role, ack.phase, ack.pending.is_some(), rows::same_owned(&ack.current, actual));
                                    if i == 0 {
                                        eprintln!("actual native probe C row dad={:?} created={:?} creationMatch={}", actual.address.as_ref().map(|a| a.observed.dad_state), actual.address.as_ref().map(|a| a.observed.creation_timestamp), actual.address.as_ref().zip(ack.creation.as_ref()).is_some_and(|(a, c)| rows::same_address(a, c)));
                                    } else {
                                        eprintln!("actual native probe member row policy={:?} baseline={:?}", actual.interface.policy, ack.baseline.interface.policy);
                                    }
                                } else {
                                    eprintln!("actual native probe row i={i} absent");
                                }
                            }
                        })
                        .map_err(native_denied)
                })
                .map_err(denied)
                .inspect_err(|_error| {
                    #[cfg(all(test, windows))]
                    eprintln!("actual native probe sample rows original read: {_error:?}");
                })?;
            let network_read =
                |facts: &crate::windows::member_carrier_network::native::NativeNetworkFacts| {
                    let physical = self
                        .physical(window, &facts.routes)
                        .inspect_err(|_error| {
                            #[cfg(all(test, windows))]
                            eprintln!("actual native probe sample physical: {_error:?}");
                        })
                        .map_err(io_denied)?;
                    compare_network(
                        &selected.record,
                        &facts.routes,
                        &facts.dns,
                        facts.protected_record.as_deref(),
                        &physical,
                        &metrics,
                    )
                    .inspect_err(|_error| {
                        #[cfg(all(test, windows))]
                        eprintln!("actual native probe sample compare network: {_error:?}");
                        #[cfg(all(test, windows))]
                        {
                            eprintln!("actual native probe network routes={:?} active={:?} pending={} pendingActive={:?} stopping={} metrics={metrics:?}", selected.record.network.as_ref().map(|n| &n.current.routes), facts.routes.active, facts.routes.pending.is_some(), facts.routes.pending_active, facts.routes.stopping);
                            for fact in &facts.routes.current {
                                eprintln!("actual native probe route key=({},{}) actual={:?}", fact.expected.destination, fact.expected.interface, fact.actual.as_ref().map(|r| (r.luid, r.protocol)));
                            }
                        }
                    })
                    .map_err(io_denied)?;
                    let after = self
                        .physical(window, &facts.routes)
                        .inspect_err(|_error| {
                            #[cfg(all(test, windows))]
                            eprintln!("actual native probe sample physical: {_error:?}");
                        })
                        .map_err(io_denied)?;
                    if physical.rows() != after.rows() || physical.proofs() != after.proofs() {
                        #[cfg(all(test, windows))]
                        eprintln!("actual native probe sample physical changed");
                        return Err(io_denied(()));
                    }
                    Ok(())
                };
            if purpose == Purpose::Closing {
                self.closing
                    .value
                    .try_borrow()
                    .map_err(denied)?
                    .as_ref()
                    .ok_or(GuardError::Conflict)?
                    .network
                    .inspect_in_window(window, network_read)
                    .map_err(denied)
                    .inspect_err(|_error| {
                        #[cfg(all(test, windows))]
                        eprintln!("actual native probe sample network original read: {_error:?}");
                    })?;
            } else {
                self.network
                    .inspect_in_window(window, network_read)
                    .map_err(denied)
                    .inspect_err(|_error| {
                        #[cfg(all(test, windows))]
                        eprintln!("actual native probe sample network original read: {_error:?}");
                    })?;
            }
            let after = self
                .guard
                .try_borrow_mut()
                .map_err(denied)
                .inspect_err(|_error| {
                    #[cfg(all(test, windows))]
                    eprintln!("actual native probe sample guard borrow: {_error:?}");
                })?
                .snapshot_in_window(window)
                .inspect_err(|_error| {
                    #[cfg(all(test, windows))]
                    eprintln!("actual native probe sample guard snapshot: {_error:?}");
                })?;
            compare_guard(&selected.record, purpose, &after).inspect_err(|_error| {
                #[cfg(all(test, windows))]
                eprintln!("actual native probe sample compare guard after: {_error:?}");
                #[cfg(all(test, windows))]
                eprintln!("actual native probe guard values expected={} permits={} actualPermits={} assigned={:?} actualWeight={:?}", after == selected.record.guard.expected, selected.record.guard.permits, after.filters.iter().any(|f| f.action == policy::Action::Permit), selected.record.guard.assigned_sublayer_weight, after.sublayer.as_ref().map(|s| s.weight));
            })?;
            if before != after {
                #[cfg(all(test, windows))]
                eprintln!("actual native probe sample guard changed");
                return Err(GuardError::Conflict);
            }
            self.current(selected, Some(purpose)).inspect_err(|_error| {
                #[cfg(all(test, windows))]
                eprintln!("actual native probe sample current after: {_error:?}");
            })
        }
        pub(crate) fn select(
            &self,
            pin: Rc<NativePairIntentRead>,
            record: pair::Record,
        ) -> Result<()> {
            let purpose = if record.phase == pair::Phase::Closing {
                Purpose::Closing
            } else {
                Purpose::Open(Slot::A)
            };
            self.fence.inspect(purpose, || {
                let mut selected = self.selected.try_borrow_mut().map_err(denied)?;
                compare_origin(&self.context, &record)?;
                if record.revision < selected.record.revision
                    || (record.revision == selected.record.revision
                        && (record != selected.record || !Rc::ptr_eq(&pin, &selected.pin)))
                    || (selected.record.phase == pair::Phase::Closing
                        && record.phase != pair::Phase::Closing)
                {
                    return Err(GuardError::Conflict);
                }
                let next = Selected { pin, record };
                self.current(&next, None)?;
                *selected = next;
                Ok(())
            })
        }
        pub(crate) fn register_inventory(&self, pin: Inventory<A>) -> Result<()> {
            // Actor independently retains its strong owner. No gate->inventory
            // ->gate strong cycle, and expiry is an explicit denial.
            self.inventory
                .first(pin.downgrade(), &self.fence, |retained| {
                    let actual = retained.upgrade()?;
                    actual.matches_caps(&self.source, &self.guard, &self.gate)?;
                    let selected = self.selected.try_borrow().map_err(denied)?;
                    self.current(&selected, None)
                })
        }
        pub(crate) fn register_held(&self, slot: Slot, original: Held<A>) -> Result<ProbeTuple> {
            self.held[idx(slot)].first(
                HeldRegistration {
                    tuple: RefCell::new(None),
                },
                &self.fence,
                |retained| {
                    let inventory = self.inventory()?;
                    // Canonical A/B projection ONLY, never target/port slot inference.
                    let originals = inventory.originals_by_slot()?;
                    if originals[idx(slot)]
                        .as_ref()
                        .is_none_or(|p| !p.same_original(&original))
                    {
                        return Err(GuardError::Conflict);
                    }
                    inventory.verify_member(&original)?;
                    let selected = self.selected.try_borrow().map_err(denied)?;
                    self.current(&selected, Some(Purpose::Open(slot)))?;
                    self.source
                        .inspect_window(|window| {
                            self.sample(&selected, Purpose::Open(slot), window)
                                .map_err(native_denied)?;
                            let tuple = original
                                .inspect_tuple_in_window(window)
                                .map_err(native_denied)?;
                            compare_open_tuple(&selected.record, slot, &tuple)
                                .map_err(native_denied)?;
                            *retained.tuple.borrow_mut() = Some(tuple);
                            self.sample(&selected, Purpose::Open(slot), window)
                                .map_err(native_denied)
                        })
                        .map_err(denied)?;
                    self.current(&selected, Some(Purpose::Open(slot)))
                },
            )?;
            self.held[idx(slot)]
                .value
                .try_borrow()
                .map_err(denied)?
                .as_ref()
                .ok_or(GuardError::Conflict)?
                .tuple
                .try_borrow()
                .map_err(denied)?
                .clone()
                .ok_or(GuardError::Conflict)
        }
        pub(crate) fn bind_closing(
            &self,
            pin: Rc<NativeClosingRead>,
            network: Rc<NativeClosingNetworkRead>,
        ) -> Result<()> {
            self.closing.first_for(
                Closing { pin, network },
                &self.fence,
                Purpose::Closing,
                |retained| {
                    if !retained.pin.matches_source_origin(&self.source) {
                        return Err(GuardError::Conflict);
                    }
                    let selected = self.selected.try_borrow().map_err(denied)?;
                    compare_closing_registration(&self.context, &selected.record)?;
                    selected
                        .pin
                        .inspect_cleanup_effect(
                            &self.runtime,
                            &self.supervisor,
                            &selected.record,
                            selected.record.stop_stage,
                            |actual| {
                                if actual != &selected.record {
                                    return Err(io_denied(()));
                                }
                                self.continuity(&selected).map_err(io_denied)
                            },
                        )
                        .map_err(denied)
                },
            )
        }
    }
    impl<A: WindowBindingAttestor> WfpProbeGate<A> {
        fn root(&self) -> Result<Rc<NativeProbeResourceState<A>>> {
            self.state.upgrade().ok_or(GuardError::Conflict)
        }
    }
    // SAFETY: actual Wfp only. Caller retains root/canonical inventory across
    // the whole actual Calling operation. Original opaque pins are registered
    // once; every permission samples actual full Guard/SDK/ACK/network facts.
    // Use checks canonical membership without entering the borrowed socket.
    // No model store, fake backend, default G, native writes or strong cycle.
    unsafe impl<A: WindowBindingAttestor> NativeProbeGate<Wfp, A> for WfpProbeGate<A> {
        fn verify_inventory(&self, inventory: &Inventory<A>) -> Result<()> {
            let root = self.root()?;
            checked_metadata(&root.fence, || {
                let registered = root.inventory()?;
                if !registered.same_inventory(inventory) {
                    root.fence.failed.set(true);
                    return Err(GuardError::Conflict);
                }
                inventory.matches_caps(&root.source, &root.guard, &root.gate)?;
                root.caps(&root.source, &root.guard)
            })
        }
        fn verify_original(
            &self,
            source: &Rc<NativeSourceRead>,
            guard: &Rc<RefCell<NativeGuard<Wfp, A>>>,
        ) -> Result<()> {
            let root = self.root()?;
            checked_metadata(&root.fence, || {
                if root.fence.failed.get() || root.closing.attempted.get() {
                    return Err(GuardError::Conflict);
                }
                root.caps(source, guard)
            })
        }
        fn authorize_open(
            &self,
            inventory: &Inventory<A>,
            window: &NativeBindingsWindow<'_>,
            slot: Slot,
            target: Ipv4Addr,
        ) -> Result<()> {
            let root = self.root().inspect_err(|_error| {
                #[cfg(all(test, windows))]
                eprintln!("actual native probe authorize open root: {_error:?}");
            })?;
            root.fence
                .inspect(Purpose::Open(slot), || {
                    self.verify_inventory(inventory).inspect_err(|_error| {
                        #[cfg(all(test, windows))]
                        eprintln!("actual native probe authorize open inventory: {_error:?}");
                    })?;
                    let selected =
                        root.selected
                            .try_borrow()
                            .map_err(denied)
                            .inspect_err(|_error| {
                                #[cfg(all(test, windows))]
                                eprintln!(
                                    "actual native probe authorize open selected: {_error:?}"
                                );
                            })?;
                    if selected.record.members[idx(slot)]
                        .as_ref()
                        .is_none_or(|m| m.probe.target_ipv4 != target)
                    {
                        #[cfg(all(test, windows))]
                        eprintln!(
                            "actual native probe authorize open target differs slot={slot:?}"
                        );
                        return Err(GuardError::Conflict);
                    }
                    root.sample(&selected, Purpose::Open(slot), window)
                })
                .inspect_err(|_error| {
                    #[cfg(all(test, windows))]
                    eprintln!("actual native probe authorize open fence: {_error:?}");
                })
        }
        fn authorize_use(&self, original: &Held<A>, tuple: &ProbeTuple) -> Result<()> {
            let root = self.root()?;
            // NO original.inspect_tuple/retired/originals_by_slot: caller holds
            // that socket's mutable map already. Slot membership is opaque Rc.
            root.fence.inspect(Purpose::Use(Slot::A), || {
                let inventory = root.inventory()?;
                inventory.verify_member(original)?;
                let mut found = None;
                for slot in [Slot::A, Slot::B] {
                    if inventory.verify_member_slot(slot, original).is_ok()
                        && found.replace(slot).is_some()
                    {
                        return Err(GuardError::Conflict);
                    }
                }
                let slot = found.ok_or(GuardError::Conflict)?;
                let registered = root.held[idx(slot)].value.try_borrow().map_err(denied)?;
                let acknowledged = registered
                    .as_ref()
                    .ok_or(GuardError::Conflict)?
                    .tuple
                    .try_borrow()
                    .map_err(denied)?;
                if acknowledged.as_ref() != Some(tuple) {
                    return Err(GuardError::Conflict);
                }
                let selected = root.selected.try_borrow().map_err(denied)?;
                compare_tuple(&selected.record, slot, tuple)?;
                root.current(&selected, Some(Purpose::Use(slot)))?;
                root.source
                    .inspect_window(|window| {
                        root.sample(&selected, Purpose::Use(slot), window)
                            .map_err(native_denied)
                    })
                    .map_err(denied)?;
                root.current(&selected, Some(Purpose::Use(slot)))
            })
        }
        fn verify_preparing(
            &self,
            source: &Rc<NativeSourceRead>,
            guard: &Rc<RefCell<NativeGuard<Wfp, A>>>,
        ) -> Result<()> {
            let root = self.root()?;
            root.fence.inspect(Purpose::Preparing, || {
                root.caps(source, guard)?;
                let selected = root.selected.try_borrow().map_err(denied)?;
                root.current(&selected, Some(Purpose::Preparing))?;
                root.source
                    .inspect_window(|window| {
                        root.sample(&selected, Purpose::Preparing, window)
                            .map_err(native_denied)
                    })
                    .map_err(denied)?;
                root.current(&selected, Some(Purpose::Preparing))
            })
        }
        fn verify_closing(
            &self,
            source: &Rc<NativeSourceRead>,
            guard: &Rc<RefCell<NativeGuard<Wfp, A>>>,
            closing: &NativeClosingRead,
        ) -> Result<()> {
            let root = self.root()?;
            root.fence.inspect(Purpose::Closing, || {
                root.caps(source, guard)?;
                let retained = root.closing.value.try_borrow().map_err(denied)?;
                let retained = retained.as_ref().ok_or(GuardError::Conflict)?;
                if !std::ptr::eq(closing, retained.pin.as_ref())
                    || !closing.matches_source_origin(source)
                {
                    return Err(GuardError::Conflict);
                }
                let selected = root.selected.try_borrow().map_err(denied)?;
                root.current(&selected, Some(Purpose::Closing))?;
                retained
                    .pin
                    .inspect_window(|window| {
                        root.sample(&selected, Purpose::Closing, window)
                            .map_err(native_denied)
                    })
                    .map_err(denied)?;
                root.current(&selected, Some(Purpose::Closing))
            })
        }
    }
}
#[cfg(test)]
#[path = "member_carrier_probe_gate_tests.rs"]
mod tests;
