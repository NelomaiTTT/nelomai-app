//! Original network effect authorization. Deliberately not factory selected.
//! Portable comparisons below confer no authority. The native implementation
//! accepts only actual Runtime/Pair/Network/Row owners and NativeGuard<Wfp,A>.
#![allow(dead_code)]

use super::{
    member_carrier_members as carrier_members, member_carrier_network_owner::RouteAttempt,
};
#[cfg(not(windows))]
use crate::member_session::PhysicalLease;
#[cfg(windows)]
use crate::windows::member_session::PhysicalLease;
use crate::{
    member_carrier_guard as policy,
    member_carrier_native_ownership::Context,
    member_carrier_pair as pair, member_carrier_rows as rows, member_dns as dns,
    member_physical::{Family, InterfaceIdentity, PhysicalRoute, PhysicalSnapshot},
    member_plan::{InterfaceMetric, MAX_ROUTES},
    member_routes::{NativeProof, Row},
};
use nelomai_client_tunnel::redundancy::{
    network::{NetworkJournal, NetworkValue, RouteScope, RouteValue},
    route_plan::MemberRoutes,
    Slot,
};
use std::{cell::Cell, collections::BTreeMap, io};

// Value conversion ONLY, after native Calling/window/SDK authorization. Keeping
// full fields here is essential: a route key is not a captured physical path.
fn physical_plan_leases(paths: &[PhysicalRoute]) -> io::Result<Vec<PhysicalLease>> {
    if paths.len() > 32768 {
        return Err(conflict());
    }
    let mut leases = BTreeMap::new();
    for path in paths {
        let identity = path.proof.identity;
        if identity.index == 0
            || identity.luid == 0
            || identity.guid == [0; 16]
            || path.row.luid != identity.luid
            || path.row.route.interface != identity.index
            || path.row.route.scope != RouteScope::WindowsInterface(identity.index)
            || Family::of(path.row.route.destination.addr()) != path.proof.family
        {
            return Err(conflict());
        }
        let lease = PhysicalLease {
            interface: identity.index,
            luid: identity.luid,
            guid: identity.guid,
            ipv6: path.proof.family == Family::V6,
            interface_metric: path.proof.metric,
            route: path.row.route.clone(),
            protocol: path.row.protocol,
            origin: path.row.origin,
            site_prefix_length: path.row.site_prefix_length,
            valid_lifetime: path.row.valid_lifetime,
            preferred_lifetime: path.row.preferred_lifetime,
            flags: path.row.flags,
        };
        let key = (
            path.proof.family,
            identity.index,
            path.row.route.destination,
        );
        if leases
            .insert(key, lease.clone())
            .is_some_and(|old| old != lease)
        {
            return Err(conflict());
        }
    }
    Ok(leases.into_values().collect())
}

fn conflict() -> io::Error {
    io::Error::other("carrier_network_gate_conflict")
}
fn denied<E>(_: E) -> io::Error {
    conflict()
}
type RouteKey = (ipnet::IpNet, u32);
fn key(route: &RouteValue) -> RouteKey {
    (route.destination, route.interface)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Channel {
    Source,
    Closing,
}

fn routes_by_key(routes: &[RouteValue]) -> io::Result<BTreeMap<RouteKey, &RouteValue>> {
    if routes.len() > MAX_ROUTES {
        return Err(conflict());
    }
    let mut result = BTreeMap::new();
    for route in routes {
        crate::member_routes::validate_route(route, route.destination, route.interface)?;
        if result.insert(key(route), route).is_some() {
            return Err(conflict());
        }
    }
    Ok(result)
}
fn compare_stage(context: &Context, record: &pair::Record, cleanup: bool) -> io::Result<Channel> {
    record.validate()?;
    if record.scope != context.intent.scope
        || record.provenance != context.provenance
        || record.addresses != context.intent.addresses
        || record.options.is_none()
        || record
            .carrier
            .is_none_or(|c| c.guid != context.bindings[0].guid)
        || record.pending_guard.is_some()
        || record.guard.permits
    {
        return Err(conflict());
    }
    let channel = match (cleanup, record.phase, record.pending) {
        (false, pair::Phase::Starting | pair::Phase::Running, Some(pair::Effect::Network))
            if record.stop_stage == 0 && record.operation.is_some() =>
        {
            Channel::Source
        }
        (true, pair::Phase::Closing, Some(pair::Effect::RestoreNetwork))
            if record.stop_stage == 2 && record.active.is_none() && record.operation.is_none() =>
        {
            Channel::Closing
        }
        _ => return Err(conflict()),
    };
    for (i, member) in record.members.iter().enumerate() {
        if let Some(m) = member {
            if m.owner
                .proof
                .is_none_or(|p| p.interface.guid != context.bindings[i + 1].guid)
                || m.owner.retired_proof.is_some()
                || m.owner.phase != crate::member_owner::Phase::Running
            {
                return Err(conflict());
            }
        }
    }
    let n = record.network.as_ref().ok_or_else(conflict)?;
    let target = n.pending.as_ref().ok_or_else(conflict)?;
    let c = record.carrier.ok_or_else(conflict)?;
    for snapshot in [&n.baseline, &n.current, target] {
        routes_by_key(&snapshot.routes)?;
        if snapshot.routes.iter().any(|r| r.interface == c.index) {
            return Err(conflict());
        }
        let d = snapshot.dns.as_ref().ok_or_else(conflict)?;
        if d.interface.scope != record.scope
            || d.interface.guid != c.guid
            || d.interface.luid != c.luid
            || d.interface.index != c.index
        {
            return Err(conflict());
        }
    }
    if cleanup {
        if target != &n.baseline {
            return Err(conflict());
        }
    } else if n
        .current
        .dns
        .as_ref()
        .ok_or_else(conflict)?
        .with_servers(&record.dns)
        .map_err(denied)?
        != *target.dns.as_ref().ok_or_else(conflict)?
    {
        return Err(conflict());
    }
    Ok(channel)
}
fn selected_slot(record: &pair::Record) -> io::Result<Slot> {
    match record.operation.ok_or_else(conflict)? {
        pair::Operation::Start(s) | pair::Operation::Switch(s) => Ok(s),
        pair::Operation::Attach(_) | pair::Operation::Retire(_) | pair::Operation::Rebind => {
            record.active.ok_or_else(conflict)
        }
    }
}

// Factual bootstrap metadata ONLY, not a Network intent, DNS SDK baseline or
// restoration proof. Actual effect authorization still requires the real span.
fn compare_pre_network_record(context: &Context, record: &pair::Record) -> io::Result<()> {
    record.validate()?;
    if record.scope != context.intent.scope
        || record.provenance != context.provenance
        || record.addresses != context.intent.addresses
        || record.options.is_none()
        || record.network.is_some()
        || record.phase != pair::Phase::Starting
        || !matches!(record.operation, Some(pair::Operation::Start(_)))
        || record.stop_stage != 0
        || record.guard.permits
        || record
            .pending_guard
            .as_ref()
            .is_some_and(|p| p.desired.permits)
        || !matches!(
            record.pending,
            None | Some(
                pair::Effect::CarrierReady
                    | pair::Effect::MemberStart(_)
                    | pair::Effect::Guard
                    | pair::Effect::WeakRows
            )
        )
        || record
            .carrier
            .is_some_and(|c| c.guid != context.bindings[0].guid)
    {
        return Err(conflict());
    }
    Ok(())
}
fn compare_network_selection_records(
    context: &Context,
    old: &pair::Record,
    next: &pair::Record,
) -> io::Result<()> {
    compare_stage(context, next, next.phase == pair::Phase::Closing)?;
    old.validate()?;
    if next.revision < old.revision
        || next.scope != old.scope
        || next.provenance != old.provenance
        || next.addresses != old.addresses
        || next.options != old.options
        || next.dns != old.dns
        || old.carrier.is_some_and(|c| next.carrier != Some(c))
        || (old.phase == pair::Phase::Closing && next.phase != pair::Phase::Closing)
    {
        return Err(conflict());
    }
    if let Some(old_network) = &old.network {
        if next
            .network
            .as_ref()
            .is_none_or(|n| n.baseline != old_network.baseline)
        {
            return Err(conflict());
        }
    } else {
        compare_pre_network_record(context, old)?;
        if next.revision <= old.revision
            || next.phase != pair::Phase::Starting
            || next.pending != Some(pair::Effect::Network)
            || next.operation != old.operation
        {
            return Err(conflict());
        }
    }
    Ok(())
}

// Comparison only: called from the concrete read helper while its caller holds
// the original Pair read and locked native Guard transaction. Never authorizes
// an effect or substitutes for those enclosing original attestations.
fn compare_guard_resource_stage(context: &Context, record: &pair::Record) -> io::Result<Slot> {
    record.validate()?;
    let slot = selected_slot(record)?;
    let plan = record.pending_guard.as_ref().ok_or_else(conflict)?;
    let network = record.network.as_ref().ok_or_else(conflict)?;
    let carrier = record.carrier.ok_or_else(conflict)?;
    if record.scope != context.intent.scope
        || record.provenance != context.provenance
        || record.addresses != context.intent.addresses
        || record.options.is_none()
        || carrier.guid != context.bindings[0].guid
        || !matches!(record.phase, pair::Phase::Starting | pair::Phase::Running)
        || record.stop_stage != 0
        || record.pending != Some(pair::Effect::Guard)
        || record.guard.permits
        || !record.guard.installed
        || record.guard.assigned_sublayer_weight.is_none()
        || record.guard != plan.base
        || !plan.desired.permits
        || plan.desired.active != Some(slot)
        || network.pending.is_some()
        || !network.baseline.routes.is_empty()
    {
        return Err(conflict());
    }
    for (i, member) in record.members.iter().enumerate() {
        if let Some(member) = member {
            if member
                .owner
                .proof
                .is_none_or(|p| p.interface.guid != context.bindings[i + 1].guid)
                || member.owner.retired_proof.is_some()
                || member.owner.phase != crate::member_owner::Phase::Running
            {
                return Err(conflict());
            }
        }
    }
    for snapshot in [&network.baseline, &network.current] {
        routes_by_key(&snapshot.routes)?;
        let dns = snapshot.dns.as_ref().ok_or_else(conflict)?;
        if snapshot.routes.iter().any(|r| r.interface == carrier.index)
            || dns.interface.scope != record.scope
            || dns.interface.guid != carrier.guid
            || dns.interface.luid != carrier.luid
            || dns.interface.index != carrier.index
        {
            return Err(conflict());
        }
    }
    Ok(slot)
}
fn compare_guard_resource_plan(record: &pair::Record, plan: &ComputedPlan) -> io::Result<()> {
    let network = record.network.as_ref().ok_or_else(conflict)?;
    if network.pending.is_some()
        || routes_by_key(&network.current.routes)? != routes_by_key(&plan.routes)?
        || network
            .baseline
            .dns
            .as_ref()
            .ok_or_else(conflict)?
            .with_servers(&record.dns)
            .map_err(denied)?
            != *network.current.dns.as_ref().ok_or_else(conflict)?
    {
        return Err(conflict());
    }
    Ok(())
}
fn compare_guard_resource_journals(
    record: &pair::Record,
    journal: &NetworkJournal,
    child_dns: Option<&crate::member_pair::DnsRecord>,
    actual_dns: &dns::Snapshot,
    dns_acks: &[dns::Snapshot],
) -> io::Result<()> {
    let network = record.network.as_ref().ok_or_else(conflict)?;
    let slot = selected_slot(record)?;
    let (routes, pending) = journal_routes(journal)?;
    let view = journal.read_view()?;
    let child = child_dns.ok_or_else(conflict)?;
    if network.pending.is_some()
        || pending.is_some()
        || view.stopping()
        || view.pending_active().is_some()
        || view.recorded_active() != Some(slot)
        || routes_by_key(&routes)? != routes_by_key(&network.current.routes)?
        || child.pending.is_some()
        || Some(&child.baseline) != network.baseline.dns.as_ref()
        || Some(&child.current) != network.current.dns.as_ref()
        || actual_dns != &child.current
        || dns_acks.last() != Some(actual_dns)
    {
        return Err(conflict());
    }
    Ok(())
}
fn compare_retired_resource_stage(context: &Context, record: &pair::Record) -> io::Result<()> {
    record.validate()?;
    let network = record.network.as_ref().ok_or_else(conflict)?;
    let carrier = record.carrier.ok_or_else(conflict)?;
    let empty = policy::Model::empty(record.scope.clone()).map_err(denied)?;
    if record.scope != context.intent.scope
        || record.provenance != context.provenance
        || record.addresses != context.intent.addresses
        || carrier.guid != context.bindings[0].guid
        || record.phase != pair::Phase::Closing
        || record.stop_stage != 10
        || record.pending != Some(pair::Effect::Guard)
        || record.active.is_some()
        || record.operation.is_some()
        || record.guard.permits
        || record.pending_guard.as_ref().is_none_or(|plan| {
            plan.desired.installed || plan.desired.permits || plan.desired != empty
        })
        || network.current != network.baseline
        || network.pending.is_some()
        || !network.baseline.routes.is_empty()
    {
        return Err(conflict());
    }
    let dns = network.baseline.dns.as_ref().ok_or_else(conflict)?;
    if dns.interface.scope != record.scope
        || dns.interface.index != carrier.index
        || dns.interface.luid != carrier.luid
        || dns.interface.guid != carrier.guid
    {
        return Err(conflict());
    }
    Ok(())
}
fn compare_static_base_resource_stage(context: &Context, record: &pair::Record) -> io::Result<()> {
    record.validate()?;
    if record.scope != context.intent.scope
        || record.provenance != context.provenance
        || record.addresses != context.intent.addresses
        || !matches!(record.phase, pair::Phase::Starting | pair::Phase::Running)
        || record.stop_stage != 0
        || record.pending != Some(pair::Effect::Guard)
        || record.pending_guard.is_none()
        || record.guard.permits
        || record
            .carrier
            .is_none_or(|c| c.guid != context.bindings[0].guid)
        || record.network.as_ref().is_none_or(|n| n.pending.is_some())
    {
        return Err(conflict());
    }
    Ok(())
}

// READ-only lifecycle resource facts; these functions confer no effect grant.
// Caller supplies actual original Pair, Source/Closing or Retired SDK bracket,
// Pauli's actual capture, and this SAME native owner's IO attempt/ACK registry.
fn same_network_ack_reads(
    before: &(Vec<RouteAttempt>, Vec<dns::Snapshot>),
    after: &(Vec<RouteAttempt>, Vec<dns::Snapshot>),
) -> bool {
    before.1 == after.1
        && before.0.len() == after.0.len()
        && before.0.iter().zip(&after.0).all(|(a, b)| {
            a.row == b.row && a.deleting == b.deleting && a.acknowledged == b.acknowledged
        })
}
fn compare_lifecycle_resource_stage(
    context: &Context,
    record: &pair::Record,
    baseline: &dns::Snapshot,
    retired: bool,
) -> io::Result<()> {
    record.validate()?;
    let c = record.carrier.ok_or_else(conflict)?;
    let expected = match record.stop_stage {
        3 => pair::Effect::RestoreWeak,
        6 => pair::Effect::CarrierAddressDelete,
        7 => pair::Effect::CarrierSessionEnd,
        8 => pair::Effect::CarrierClose,
        _ => return Err(conflict()),
    };
    baseline.with_servers(&record.dns).map_err(denied)?;
    if record.scope != context.intent.scope
        || record.provenance != context.provenance
        || record.addresses != context.intent.addresses
        || record.options.is_none()
        || c.guid != context.bindings[0].guid
        || record.phase != pair::Phase::Closing
        || record.pending != Some(expected)
        || (retired && record.stop_stage != 8)
        || record.active.is_some()
        || record.operation.is_some()
        || record.pending_guard.is_some()
        || record.guard.permits
        || !record.guard.installed
        || record.guard.assigned_sublayer_weight.is_none()
        || baseline.interface.scope != record.scope
        || baseline.interface.guid != c.guid
        || baseline.interface.index != c.index
        || baseline.interface.luid != c.luid
    {
        return Err(conflict());
    }
    if let Some(network) = &record.network {
        if network.pending.is_some()
            || network.current != network.baseline
            || !network.baseline.routes.is_empty()
            || network.baseline.dns.as_ref() != Some(baseline)
        {
            return Err(conflict());
        }
    }
    Ok(())
}
// Read-only NativeEmpty prerequisite. Its distinct stage domain must never be
// projected through the stage8 lifecycle verifier or used as an effect grant.
fn compare_native_empty_resource_stage(
    context: &Context,
    record: &pair::Record,
    baseline: &dns::Snapshot,
) -> io::Result<()> {
    record.validate()?;
    let c = record.carrier.ok_or_else(conflict)?;
    let expected = match record.stop_stage {
        9 => pair::Effect::NativeEmpty,
        10 => pair::Effect::Guard,
        _ => return Err(conflict()),
    };
    let retained_base = record.guard.installed && record.guard.assigned_sublayer_weight.is_some();
    let completed_removal = record.stop_stage == 10
        && record.pending_guard.is_none()
        && record.guard == policy::Model::empty(record.scope.clone()).map_err(denied)?;
    baseline.with_servers(&record.dns).map_err(denied)?;
    if record.scope != context.intent.scope
        || record.provenance != context.provenance
        || record.addresses != context.intent.addresses
        || record.options.is_none()
        || c.guid != context.bindings[0].guid
        || record.phase != pair::Phase::Closing
        || record.pending != Some(expected)
        || record.active.is_some()
        || record.operation.is_some()
        || record.guard.permits
        || (!retained_base && !completed_removal)
        || baseline.interface.scope != record.scope
        || baseline.interface.guid != c.guid
        || baseline.interface.index != c.index
        || baseline.interface.luid != c.luid
    {
        return Err(conflict());
    }
    if let Some(plan) = &record.pending_guard {
        // Stage9 precedes removal; stage10 may already have journaled the
        // exact DENY-only-to-empty exchange. This read never grants that effect.
        if record.stop_stage != 10
            || plan.expected != record.guard
            || plan.desired != policy::Model::empty(record.scope.clone()).map_err(denied)?
            || plan.withdrawn.permits
            || plan.base.permits
        {
            return Err(conflict());
        }
    }
    if let Some(network) = &record.network {
        if network.pending.is_some()
            || network.current != network.baseline
            || !network.baseline.routes.is_empty()
            || network.baseline.dns.as_ref() != Some(baseline)
        {
            return Err(conflict());
        }
    }
    Ok(())
}

/// Terminal comparison DATA, not stage9/10 permission or a substitute for
/// genuine retired C/A/B ACKs. Original DNS/interface baseline stays retained
/// even when the final Pair tombstone has deliberately removed its live proof.
fn compare_full_empty_resource_stage(
    context: &Context,
    record: &pair::Record,
    baseline: &dns::Snapshot,
) -> io::Result<()> {
    compare_terminal_resource_stage(context, record, baseline, false)
}
fn compare_terminal_resource_stage(
    context: &Context,
    record: &pair::Record,
    baseline: &dns::Snapshot,
    keys_restored: bool,
) -> io::Result<()> {
    record.validate()?;
    baseline.with_servers(&record.dns).map_err(denied)?;
    let c = &baseline.interface;
    if record.scope != context.intent.scope
        || record.provenance != context.provenance
        || record.addresses != context.intent.addresses
        || record.options.is_none()
        || record.pending_guard.is_some()
        || record.active.is_some()
        || record.operation.is_some()
        || record.guard != policy::Model::empty(record.scope.clone()).map_err(denied)?
        || c.scope != record.scope
        || c.guid != context.bindings[0].guid
        || c.index == 0
        || c.luid == 0
    {
        return Err(conflict());
    }
    match (record.phase, record.pending) {
        (pair::Phase::Closing, Some(effect))
            if (keys_restored
                && record.stop_stage == 11
                && effect == pair::Effect::RestoreKeys)
                || (!keys_restored
                    && record.stop_stage == 12
                    && effect == pair::Effect::FullEmpty) =>
        {
            if record.carrier
                != Some(crate::member_owner::InterfaceProof {
                    guid: c.guid,
                    index: c.index,
                    luid: c.luid,
                })
            {
                return Err(conflict());
            }
        }
        (pair::Phase::Stopped, None)
            if !keys_restored
                && record.stop_stage == 12
                && record.carrier.is_none()
                && record.members.iter().all(Option::is_none) => {}
        _ => return Err(conflict()),
    }
    if record.network.as_ref().is_some_and(|network| {
        network.pending.is_some()
            || network.current != network.baseline
            || !network.baseline.routes.is_empty()
            || network.baseline.dns.as_ref() != Some(baseline)
    }) {
        return Err(conflict());
    }
    Ok(())
}
fn compare_restored_keys_resource_stage(
    context: &Context,
    record: &pair::Record,
    baseline: &dns::Snapshot,
) -> io::Result<()> {
    compare_terminal_resource_stage(context, record, baseline, true)
}

#[allow(clippy::too_many_arguments)]
fn compare_full_empty_resource_journals(
    context: &Context,
    record: &pair::Record,
    baseline: &dns::Snapshot,
    journal: Option<&NetworkJournal>,
    dns_child: Option<&crate::member_pair::DnsRecord>,
    routes: &[RouteAttempt],
    dns_attempts: usize,
    dns_acks: &[dns::Snapshot],
) -> io::Result<()> {
    compare_full_empty_resource_stage(context, record, baseline)?;
    compare_restored_resource_journals(
        record,
        baseline,
        journal,
        dns_child,
        routes,
        dns_attempts,
        dns_acks,
    )
}

#[derive(Clone, Copy)]
enum EmptyReadChannel {
    Native,
    KeysRestored,
    Full,
}
fn compare_terminal_empty_stage(
    channel: EmptyReadChannel,
    context: &Context,
    record: &pair::Record,
    baseline: &dns::Snapshot,
) -> io::Result<()> {
    match channel {
        EmptyReadChannel::KeysRestored => {
            compare_restored_keys_resource_stage(context, record, baseline)
        }
        EmptyReadChannel::Full => compare_full_empty_resource_stage(context, record, baseline),
        EmptyReadChannel::Native => Err(conflict()),
    }
}
#[allow(clippy::too_many_arguments)]
fn compare_restored_keys_resource_journals(
    context: &Context,
    record: &pair::Record,
    baseline: &dns::Snapshot,
    journal: Option<&NetworkJournal>,
    dns_child: Option<&crate::member_pair::DnsRecord>,
    routes: &[RouteAttempt],
    dns_attempts: usize,
    dns_acks: &[dns::Snapshot],
) -> io::Result<()> {
    compare_restored_keys_resource_stage(context, record, baseline)?;
    compare_restored_resource_journals(
        record,
        baseline,
        journal,
        dns_child,
        routes,
        dns_attempts,
        dns_acks,
    )
}
#[allow(clippy::too_many_arguments)]
fn compare_native_empty_resource_journals(
    context: &Context,
    record: &pair::Record,
    baseline: &dns::Snapshot,
    journal: Option<&NetworkJournal>,
    dns_child: Option<&crate::member_pair::DnsRecord>,
    routes: &[RouteAttempt],
    dns_attempts: usize,
    dns_acks: &[dns::Snapshot],
) -> io::Result<()> {
    compare_native_empty_resource_stage(context, record, baseline)?;
    compare_restored_resource_journals(
        record,
        baseline,
        journal,
        dns_child,
        routes,
        dns_attempts,
        dns_acks,
    )
}
#[allow(clippy::too_many_arguments)]
fn compare_lifecycle_resource_journals(
    context: &Context,
    record: &pair::Record,
    baseline: &dns::Snapshot,
    journal: Option<&NetworkJournal>,
    dns_child: Option<&crate::member_pair::DnsRecord>,
    routes: &[RouteAttempt],
    dns_attempts: usize,
    dns_acks: &[dns::Snapshot],
) -> io::Result<()> {
    compare_lifecycle_resource_stage(context, record, baseline, false)?;
    compare_restored_resource_journals(
        record,
        baseline,
        journal,
        dns_child,
        routes,
        dns_attempts,
        dns_acks,
    )
}
fn compare_restored_resource_journals(
    record: &pair::Record,
    baseline: &dns::Snapshot,
    journal: Option<&NetworkJournal>,
    dns_child: Option<&crate::member_pair::DnsRecord>,
    routes: &[RouteAttempt],
    dns_attempts: usize,
    dns_acks: &[dns::Snapshot],
) -> io::Result<()> {
    if dns_child.is_some()
        || dns_attempts > 32768
        || dns_attempts != dns_acks.len()
        || routes.len() > 32768
    {
        return Err(conflict());
    }
    // Every SDK attempt is recorded before IO. Unknown failures/unwind cannot
    // disappear into an empty successful ACK vector or become NeverExchanged.
    for ack in dns_acks {
        let mut nameserver_only = baseline.clone();
        nameserver_only.settings.name_server = ack.settings.name_server.clone();
        ack.with_servers(&record.dns).map_err(denied)?;
        if ack != &nameserver_only {
            return Err(conflict());
        }
    }
    if dns_attempts > 0 && dns_acks.last() != Some(baseline) {
        return Err(conflict());
    }
    if record.network.is_none() && (dns_attempts != 0 || !routes.is_empty()) {
        return Err(conflict());
    }
    match journal {
        Some(journal) => {
            let (current, pending) = journal_routes(journal)?;
            let view = journal.read_view()?;
            if !current.is_empty()
                || pending.is_some()
                || view.recorded_active().is_some()
                || view.pending_active().is_some()
            {
                return Err(conflict());
            }
        }
        None if routes.is_empty() && dns_attempts == 0 => (),
        None => return Err(conflict()),
    }
    let mut last = BTreeMap::new();
    for attempt in routes {
        last.insert(key(&attempt.row.route), attempt);
    }
    if last.values().any(|a| !a.acknowledged || !a.deleting) {
        return Err(conflict());
    }
    Ok(())
}
fn compare_lifecycle_route_table(
    record: &pair::Record,
    originals: [Option<crate::member_owner::InterfaceProof>; 3],
    attempts: &[RouteAttempt],
    actual: &[Row],
    carrier_alive: bool,
) -> io::Result<()> {
    if attempts.len() > 32768
        || actual.len() > crate::member_routes::MAX_TABLE_ROWS * 2
        || originals[0] != record.carrier
    {
        return Err(conflict());
    }
    let c = record.carrier.ok_or_else(conflict)?;
    for (i, member) in record.members.iter().enumerate() {
        if let Some(member) = member {
            if member
                .owner
                .proof
                .or(member.owner.retired_proof)
                .map(|p| p.interface)
                != originals[i + 1]
            {
                return Err(conflict());
            }
        }
    }
    compare_original_route_absence(record, originals, attempts, actual, carrier_alive, c)
}

/// Factual exact original-key exclusions. Terminal tombstones contain no live
/// C, so their separately authenticated historical identities must be supplied
/// explicitly; never rewrite the Pair into an earlier lifecycle stage.
fn compare_original_route_absence(
    record: &pair::Record,
    originals: [Option<crate::member_owner::InterfaceProof>; 3],
    attempts: &[RouteAttempt],
    actual: &[Row],
    carrier_alive: bool,
    c: crate::member_owner::InterfaceProof,
) -> io::Result<()> {
    if originals[0] != Some(c)
        || c.index == 0
        || c.luid == 0
        || c.guid == [0; 16]
        || attempts.len() > 32768
        || actual.len() > crate::member_routes::MAX_TABLE_ROWS * 2
    {
        return Err(conflict());
    }
    let mut last = BTreeMap::new();
    for attempt in attempts {
        crate::member_routes::validate_route(
            &attempt.row.route,
            attempt.row.route.destination,
            attempt.row.route.interface,
        )?;
        last.insert(key(&attempt.row.route), attempt);
    }
    if last.values().any(|a| !a.acknowledged || !a.deleting) {
        return Err(conflict());
    }
    let members_alive = carrier_alive
        && record.phase == pair::Phase::Closing
        && record.stop_stage == 3
        && record.pending == Some(pair::Effect::RestoreWeak);
    for row in actual {
        crate::member_routes::validate_route(
            &row.route,
            row.route.destination,
            row.route.interface,
        )?;
        // Owned journal keys must be absent even while their original NIC lives.
        if last.contains_key(&key(&row.route)) {
            return Err(conflict());
        }
        if row.route.interface == c.index || row.luid == c.luid {
            if !carrier_alive || row.route.interface != c.index || row.luid != c.luid {
                return Err(conflict());
            }
            continue;
        }
        if let Some(member) = originals[1..]
            .iter()
            .flatten()
            .find(|p| row.route.interface == p.index || row.luid == p.luid)
        {
            if !members_alive || row.route.interface != member.index || row.luid != member.luid {
                return Err(conflict());
            }
            continue;
        }
    }
    Ok(())
}
fn compare_retired_resource_journals(
    context: &Context,
    record: &pair::Record,
    journal: &NetworkJournal,
    dns_child_present: bool,
    dns_acks: &[dns::Snapshot],
) -> io::Result<()> {
    compare_retired_resource_stage(context, record)?;
    let (current, pending) = journal_routes(journal)?;
    let view = journal.read_view()?;
    if !current.is_empty()
        || pending.is_some()
        || view.recorded_active().is_some()
        || view.pending_active().is_some()
        || dns_child_present
        || dns_acks.last()
            != record
                .network
                .as_ref()
                .and_then(|n| n.baseline.dns.as_ref())
    {
        return Err(conflict());
    }
    Ok(())
}
fn compare_retired_route_reads(
    record: &pair::Record,
    attempts: &[RouteAttempt],
    actual: &[Row],
) -> io::Result<()> {
    if attempts.len() > 32768 || actual.len() > crate::member_routes::MAX_TABLE_ROWS * 2 {
        return Err(conflict());
    }
    let mut last = BTreeMap::new();
    for attempt in attempts {
        last.insert(key(&attempt.row.route), attempt);
    }
    // Absence alone does not convert an unknown create/delete into an ACK.
    if last.values().any(|a| !a.acknowledged || !a.deleting) {
        return Err(conflict());
    }
    let c = record.carrier.ok_or_else(conflict)?;
    let members = record
        .members
        .iter()
        .flatten()
        .filter_map(|m| m.owner.proof)
        .map(|p| p.interface)
        .collect::<Vec<_>>();
    for row in actual {
        if last.contains_key(&key(&row.route))
            || row.route.interface == c.index
            || row.luid == c.luid
            || members
                .iter()
                .any(|m| row.route.interface == m.index || row.luid == m.luid)
        {
            return Err(conflict());
        }
    }
    Ok(())
}
fn compare_guard(record: &pair::Record, actual: &policy::Snapshot) -> io::Result<()> {
    record.guard.validate().map_err(denied)?;
    let weight = record.guard.assigned_sublayer_weight.ok_or_else(conflict)?;
    if !record.guard.installed
        || record.guard.permits
        || record.pending_guard.is_some()
        || actual != &record.guard.expected
        || actual.sublayer.as_ref().is_none_or(|s| s.weight != weight)
        || actual
            .carrier
            .as_ref()
            .is_none_or(|c| Some(c.identity.proof) != record.carrier)
        || actual
            .filters
            .iter()
            .any(|f| f.action != policy::Action::Block)
    {
        return Err(conflict());
    }
    // The native snapshot has queried the complete 49-key universe with actual
    // retained IDs. Require bases for EVERY current member, including reserve.
    for (i, member) in record.members.iter().enumerate() {
        if actual.egress[i].as_ref().map(|m| m.proof)
            != member
                .as_ref()
                .and_then(|m| m.owner.proof.map(|p| p.interface))
        {
            return Err(conflict());
        }
    }
    Ok(())
}

struct ComputedPlan {
    routes: Vec<RouteValue>,
    physical: Vec<PhysicalRoute>,
}
fn compute_plan(
    record: &pair::Record,
    active: Slot,
    physical: &PhysicalSnapshot,
    member_metrics: &[InterfaceMetric],
) -> io::Result<ComputedPlan> {
    let options = record.options.as_ref().ok_or_else(conflict)?;
    options.validate().map_err(denied)?;
    let retained_members = record
        .members
        .iter()
        .enumerate()
        .filter_map(|(i, m)| {
            let slot = if i == 0 { Slot::A } else { Slot::B };
            if record.operation == Some(pair::Operation::Retire(slot)) {
                None
            } else {
                m.as_ref().map(|m| (slot, m))
            }
        })
        .collect::<Vec<_>>();
    let mut exclusions = options
        .excluded_ipv4_cidrs
        .iter()
        .map(|v| v.parse::<ipnet::IpNet>().map_err(denied))
        .collect::<io::Result<Vec<_>>>()?;
    if options.exclude_local_networks {
        exclusions.extend(physical.lan_prefixes());
    }
    let mut members = Vec::new();
    for (slot, m) in &retained_members {
        physical.resolve_host(m.endpoint).map_err(denied)?;
        exclusions.push(ipnet::IpNet::from(m.endpoint));
        let proof = m.owner.proof.ok_or_else(conflict)?.interface;
        // Rows/native carrier currently support IPv4 only. Reject unsupported
        // members before a route effect instead of guessing v6 metric facts.
        if m.allowed.iter().any(|n| n.addr().is_ipv6()) {
            return Err(conflict());
        }
        members.push(MemberRoutes {
            slot: *slot,
            interface: proof.index,
            allowed: m.allowed.clone(),
            probe: m.probe.target_ipv4,
        });
    }
    exclusions.sort();
    exclusions.dedup();
    let mut destinations = exclusions.clone();
    destinations.extend(
        retained_members
            .iter()
            .map(|(_, m)| ipnet::IpNet::from(std::net::IpAddr::V4(m.probe.target_ipv4))),
    );
    destinations.sort();
    destinations.dedup();
    if destinations.len() > MAX_ROUTES {
        return Err(conflict());
    }
    let mut bypasses = Vec::new();
    let mut paths = Vec::new();
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
        if path.row.route == route {
            retained.push(route.clone());
        }
        bypasses.push(route);
        paths.push(path);
    }
    let mut metrics = member_metrics
        .iter()
        .copied()
        .filter(|metric| members.iter().any(|m| m.interface == metric.interface))
        .collect::<Vec<_>>();
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
        &bypasses,
        &metrics,
        0,
    )
    .map_err(denied)?;
    crate::member_plan::validate_retained_probe_routes(&plan, &members, &retained, &metrics)
        .map_err(denied)?;
    Ok(ComputedPlan {
        routes: plan
            .routes
            .into_iter()
            .filter(|r| !retained.contains(r))
            .collect(),
        physical: paths,
    })
}
fn compare_desired(record: &pair::Record, plan: &ComputedPlan) -> io::Result<()> {
    let n = record.network.as_ref().ok_or_else(conflict)?;
    let target = n.pending.as_ref().ok_or_else(conflict)?;
    if routes_by_key(&target.routes)? != routes_by_key(&plan.routes)?
        || n.current
            .dns
            .as_ref()
            .ok_or_else(conflict)?
            .with_servers(&record.dns)
            .map_err(denied)?
            != *target.dns.as_ref().ok_or_else(conflict)?
    {
        return Err(conflict());
    }
    Ok(())
}
fn last_route<'a>(attempts: &'a [RouteAttempt], route: &RouteValue) -> Option<&'a RouteAttempt> {
    attempts
        .iter()
        .rev()
        .find(|a| key(&a.row.route) == key(route))
}
fn compare_route_ack(attempts: &[RouteAttempt], actual: &Row) -> io::Result<()> {
    let last = last_route(attempts, &actual.route).ok_or_else(conflict)?;
    if !last.acknowledged || last.deleting || &last.row != actual {
        return Err(conflict());
    }
    Ok(())
}
fn compare_dns_read(
    record: &pair::Record,
    actual: &dns::Snapshot,
    attempts: &[dns::Snapshot],
) -> io::Result<()> {
    let n = record.network.as_ref().ok_or_else(conflict)?;
    let before = n.current.dns.as_ref().ok_or_else(conflict)?;
    let after = n
        .pending
        .as_ref()
        .and_then(|n| n.dns.as_ref())
        .ok_or_else(conflict)?;
    // A post-effect target is covered only by the SDK ACK retained before the
    // owner returned to Source. Pending/native equality supplies no receipt.
    if actual == before || (actual == after && attempts.last() == Some(actual)) {
        Ok(())
    } else {
        Err(conflict())
    }
}
fn compare_dns_effect(
    record: &pair::Record,
    child: Option<&crate::member_pair::DnsRecord>,
    before: &dns::Snapshot,
    desired: &dns::Snapshot,
    actual: &dns::Snapshot,
    attempts: &[dns::Snapshot],
) -> io::Result<()> {
    let n = record.network.as_ref().ok_or_else(conflict)?;
    let child = child.ok_or_else(conflict)?;
    let target = n
        .pending
        .as_ref()
        .and_then(|n| n.dns.as_ref())
        .ok_or_else(conflict)?;
    if child.pending.as_ref() != Some(desired)
        || desired != target
        || before != actual
        || Some(&child.baseline) != n.baseline.dns.as_ref()
        || (before != &child.current && attempts.last() != Some(before))
    {
        return Err(conflict());
    }
    compare_dns_read(record, actual, attempts)
}

fn journal_routes(
    journal: &NetworkJournal,
) -> io::Result<(Vec<RouteValue>, Option<Vec<RouteValue>>)> {
    // Fresh Windows ownership never has an imported/preexisting original row.
    // A baseline route is excluded by the planner, not adopted for restoration.
    if !journal.windows_boot_resources_are_ephemeral() {
        return Err(conflict());
    }
    let view = journal.read_view()?;
    let read = |values: Vec<&NetworkValue>| {
        values
            .into_iter()
            .map(|value| match value {
                NetworkValue::Route(route) => Ok(route.clone()),
                _ => Err(conflict()),
            })
            .collect::<io::Result<Vec<_>>>()
    };
    let current = read(view.current().collect())?;
    let pending = view
        .pending()
        .map(|values| read(values.collect()))
        .transpose()?;
    routes_by_key(&current)?;
    if let Some(routes) = &pending {
        routes_by_key(routes)?;
    }
    Ok((current, pending))
}
fn compare_journal(
    record: &pair::Record,
    journal: &NetworkJournal,
    cleanup: bool,
) -> io::Result<()> {
    let n = record.network.as_ref().ok_or_else(conflict)?;
    let target = n.pending.as_ref().ok_or_else(conflict)?;
    let (current, pending) = journal_routes(journal)?;
    let before = routes_by_key(&n.current.routes)?;
    let after = routes_by_key(&target.routes)?;
    let actual = routes_by_key(&current)?;
    let view = journal.read_view()?;
    if cleanup {
        if !n.baseline.routes.is_empty() {
            return Err(conflict());
        }
        if current
            .iter()
            .any(|r| before.get(&key(r)).is_none_or(|known| *known != r))
            || pending.as_ref().is_some_and(|r| !r.is_empty())
            || (view.stopping() && view.pending_active().is_some())
        {
            return Err(conflict());
        }
    } else if view.stopping()
        || (actual != before && actual != after)
        || pending
            .as_ref()
            .is_some_and(|r| routes_by_key(r).map_or(true, |p| p != after))
        || (pending.is_some() && view.pending_active() != Some(selected_slot(record)?))
        || (actual == after
            && pending.is_none()
            && view.recorded_active() != Some(selected_slot(record)?))
    {
        return Err(conflict());
    }
    Ok(())
}
#[derive(Clone, Copy)]
enum RouteEffect {
    Create,
    Delete,
    Set,
}
fn compare_route_effect(
    record: &pair::Record,
    journal: &NetworkJournal,
    attempts: &[RouteAttempt],
    actual: &[Row],
    row: &Row,
    kind: RouteEffect,
    proof: NativeProof,
) -> io::Result<()> {
    if row != &Row::static_route(row.route.clone(), proof) {
        return Err(conflict());
    }
    let (current, pending) = journal_routes(journal)?;
    let pending = pending.ok_or_else(conflict)?;
    let before = current.iter().find(|r| key(r) == key(&row.route));
    let after = pending.iter().find(|r| key(r) == key(&row.route));
    let values = actual
        .iter()
        .filter(|r| key(&r.route) == key(&row.route))
        .collect::<Vec<_>>();
    if values.len() > 1 || before == after {
        return Err(conflict());
    }
    let last = last_route(attempts, &row.route);
    // Actual retained IO history and the independently sampled native before
    // row must agree. Unknown SDK outcomes never become ACKs from lookup.
    let held = match last {
        Some(a) if !a.acknowledged => return Err(conflict()),
        Some(a) if !a.deleting => Some(&a.row),
        _ => None,
    };
    if values.first().copied() != held {
        return Err(conflict());
    }
    let known = before == Some(&row.route) || after == Some(&row.route);
    if !known
        || !record.network.as_ref().is_some_and(|n| {
            n.current
                .routes
                .iter()
                .chain(n.pending.iter().flat_map(|n| &n.routes))
                .any(|r| r == &row.route)
        })
    {
        return Err(conflict());
    }
    match kind {
        RouteEffect::Create if held.is_none() => Ok(()),
        RouteEffect::Delete if held == Some(row) => Ok(()),
        RouteEffect::Set
            if held.is_some_and(|old| old.route.gateway == row.route.gateway && old != row) =>
        {
            Ok(())
        }
        _ => Err(conflict()),
    }
}
fn compare_route_reads(
    record: &pair::Record,
    journal: &NetworkJournal,
    attempts: &[RouteAttempt],
    actual: &[Row],
) -> io::Result<()> {
    if attempts.len() > 32768 || actual.len() > crate::member_routes::MAX_TABLE_ROWS * 2 {
        return Err(conflict());
    }
    let (current, pending) = journal_routes(journal)?;
    let n = record.network.as_ref().ok_or_else(conflict)?;
    let mut keys = std::collections::BTreeSet::new();
    for route in n
        .baseline
        .routes
        .iter()
        .chain(&n.current.routes)
        .chain(n.pending.iter().flat_map(|n| &n.routes))
        .chain(&current)
        .chain(pending.iter().flatten())
    {
        keys.insert(key(route));
    }
    for attempt in attempts {
        keys.insert(key(&attempt.row.route));
    }
    let mut table = BTreeMap::new();
    for row in actual {
        if keys.contains(&key(&row.route)) && table.insert(key(&row.route), row).is_some() {
            return Err(conflict());
        }
    }
    for k in keys {
        let last = attempts.iter().rev().find(|a| key(&a.row.route) == k);
        match (last, table.get(&k).copied()) {
            (None, None) => (),
            (Some(a), None) if a.acknowledged && a.deleting => (),
            (Some(a), Some(row)) if a.acknowledged && !a.deleting && &a.row == row => (),
            _ => return Err(conflict()),
        }
    }
    // Addressless egress must not acquire foreign or implicit data routes.
    let members = record
        .members
        .iter()
        .flatten()
        .filter_map(|m| m.owner.proof.map(|p| p.interface.index))
        .collect::<Vec<_>>();
    let c = record.carrier.ok_or_else(conflict)?;
    for row in actual {
        if members.contains(&row.route.interface) {
            compare_route_ack(attempts, row)?;
        }
        if row.route.interface == c.index
            && (row.route.destination != record.addresses[0]
                || row.route.gateway.is_some()
                || row.flags[0] != 1)
        {
            return Err(conflict());
        }
    }
    Ok(())
}

/// Read-only comparison DATA extracted inside Main's concrete resource sampler.
/// Never instantiated from a permissive trait or used as an original read pin.
type ResourceRows<'a> = [Option<(&'a rows::Binding, &'a rows::Record, &'a rows::Snapshot)>; 3];
type GuardResourceRows<'a> = [Option<(
    &'a rows::Binding,
    &'a rows::Record,
    Option<&'a rows::Snapshot>,
)>; 3];
type ClosedResources<'a> = [Option<&'a carrier_members::ClosedMemberBinding>; 2];

// Lineage DATA only. Actual closed history/Row ACK/native absence is mandatory
// in the later supplied window join; this never substitutes for that join.
fn compare_guard_member_lineage(
    old: &pair::Record,
    current: &pair::Record,
) -> io::Result<Option<Slot>> {
    if old.members == current.members {
        return Ok(None);
    }
    let slot = match old.operation {
        Some(pair::Operation::Retire(slot)) if current.operation == old.operation => slot,
        _ => return Err(conflict()),
    };
    let i = if slot == Slot::A { 0 } else { 1 };
    let original = old.members[i].as_ref().ok_or_else(conflict)?;
    let proof = original.owner.proof.ok_or_else(conflict)?;
    let committed = old
        .network
        .as_ref()
        .and_then(|n| n.pending.as_ref())
        .ok_or_else(conflict)?;
    if current.members[i].is_some()
        || current.members[1 - i] != old.members[1 - i]
        || current.active.is_none()
        || current.active == Some(slot)
        || current.active != old.active
        || original.owner.phase != crate::member_owner::Phase::Running
        || original.owner.retired_proof.is_some()
        || current
            .network
            .as_ref()
            .is_none_or(|n| n.pending.is_some() || n.current != *committed)
        || committed
            .routes
            .iter()
            .any(|r| r.interface == proof.interface.index)
    {
        return Err(conflict());
    }
    Ok(Some(slot))
}

fn compare_closed_resource_row(
    context: &Context,
    record: &pair::Record,
    history: &carrier_members::ClosedMemberBinding,
    binding: &rows::Binding,
    ack: &rows::Record,
    observed: Option<&rows::Snapshot>,
) -> io::Result<()> {
    compare_guard_resource_stage(context, record)?;
    let slot = match history.intent.slot {
        nelomai_contracts::dispatcher::TunnelSlot::A => Slot::A,
        nelomai_contracts::dispatcher::TunnelSlot::B => Slot::B,
    };
    let i = if slot == Slot::A { 1 } else { 2 };
    let provider = history.comparison_provider(context).map_err(denied)?;
    binding.validate().map_err(denied)?;
    ack.validate().map_err(denied)?;
    let p = &ack.baseline.interface.policy;
    if record.operation != Some(pair::Operation::Retire(slot))
        || record.active == Some(slot)
        || observed.is_some()
        || binding.scope != record.scope
        || binding.boot_id != context.provenance.boot_id
        || binding.runtime != context.provenance.runtime
        || binding.network_epoch != context.provenance.network_epoch
        || binding.role
            != [
                rows::Role::Carrier,
                rows::Role::MemberA,
                rows::Role::MemberB,
            ][i]
        || binding.guid != provider.identity.guid
        || binding.name != provider.identity.name
        || binding.key.index != provider.identity.index
        || binding.key.luid != provider.identity.luid
        || record.addresses.len() != 1
        || record.addresses[0].addr()
            != std::net::IpAddr::V4(std::net::Ipv4Addr::from(binding.address))
        || ack.binding != *binding
        || ack.phase != rows::Phase::Stopped
        || ack.pending.is_some()
        || ack.creation.is_some()
        || ack.baseline.address.is_some()
        || ack.current.address.is_some()
        || ack.current.interface.key != ack.baseline.interface.key
        || ack.current.interface.policy != *p
        || p.forwarding
        || p.advertising
        || p.weak_host_send
        || p.weak_host_receive
        || record.network.as_ref().is_none_or(|n| {
            n.current
                .routes
                .iter()
                .any(|r| r.interface == history.proof.interface.index)
        })
    {
        return Err(conflict());
    }
    if let Some(member) = &record.members[i - 1] {
        if member.owner.intent != history.intent
            || member.owner.proof != Some(history.proof)
            || member.owner.phase != crate::member_owner::Phase::Running
            || member.owner.retired_proof.is_some()
        {
            return Err(conflict());
        }
    }
    Ok(())
}

fn compare_guard_resource_rows(
    context: &Context,
    record: &pair::Record,
    resources: GuardResourceRows<'_>,
    closed: ClosedResources<'_>,
) -> io::Result<Vec<InterfaceMetric>> {
    compare_guard_resource_stage(context, record)?;
    compare_sampled_resource_rows(context, record, resources, closed)
}
fn compare_resource_rows(
    context: &Context,
    record: &pair::Record,
    resources: ResourceRows<'_>,
) -> io::Result<Vec<InterfaceMetric>> {
    compare_sampled_resource_rows(
        context,
        record,
        resources.map(|r| r.map(|(binding, ack, actual)| (binding, ack, Some(actual)))),
        [None, None],
    )
}
fn compare_sampled_resource_rows(
    context: &Context,
    record: &pair::Record,
    resources: GuardResourceRows<'_>,
    closed: ClosedResources<'_>,
) -> io::Result<Vec<InterfaceMetric>> {
    let c = record.carrier.ok_or_else(conflict)?;
    let proofs = [
        Some(c),
        record.members[0]
            .as_ref()
            .and_then(|m| m.owner.proof.map(|p| p.interface)),
        record.members[1]
            .as_ref()
            .and_then(|m| m.owner.proof.map(|p| p.interface)),
    ];
    let mut metrics = Vec::new();
    for (i, (proof, resource)) in proofs.iter().zip(resources).enumerate() {
        if let Some(history) = i.checked_sub(1).and_then(|i| closed[i]) {
            let (binding, ack, observed) = resource.ok_or_else(conflict)?;
            if history.intent.slot
                != if i == 1 {
                    nelomai_contracts::dispatcher::TunnelSlot::A
                } else {
                    nelomai_contracts::dispatcher::TunnelSlot::B
                }
            {
                return Err(conflict());
            }
            compare_closed_resource_row(context, record, history, binding, ack, observed)?;
            continue; // No historical metric, no usable route/member resource.
        }
        let Some(proof) = proof else {
            if resource.is_some() {
                return Err(conflict());
            }
            continue;
        };
        let (binding, ack, actual) = resource.ok_or_else(conflict)?;
        let actual = actual.ok_or_else(conflict)?;
        binding.validate().map_err(denied)?;
        ack.validate().map_err(denied)?;
        actual.validate(binding).map_err(denied)?;
        if binding.scope != record.scope
            || binding.boot_id != context.provenance.boot_id
            || binding.runtime != context.provenance.runtime
            || binding.network_epoch != context.provenance.network_epoch
            || binding.guid != proof.guid
            || binding.name != context.bindings[i].name
            || binding.key.index != proof.index
            || binding.key.luid != proof.luid
            || binding.role
                != [
                    rows::Role::Carrier,
                    rows::Role::MemberA,
                    rows::Role::MemberB,
                ][i]
            || ack.binding != *binding
            || ack.pending.is_some()
            || ack.phase == rows::Phase::Stopped
            || !rows::same_owned(&ack.current, actual)
        {
            return Err(conflict());
        }
        let baseline = &ack.baseline.interface.policy;
        let mut weak = baseline.clone();
        weak.weak_host_send = true;
        weak.weak_host_receive = true;
        if baseline.forwarding
            || baseline.advertising
            || baseline.weak_host_send
            || baseline.weak_host_receive
            || actual.interface.policy != weak
            || ack.current.interface.policy != weak
        {
            return Err(conflict());
        }
        if i == 0 {
            let address = actual.address.as_ref().ok_or_else(conflict)?;
            if ack
                .creation
                .as_ref()
                .is_none_or(|created| !rows::same_address(created, address))
                || address.observed.dad_state != 4
                || address.observed.creation_timestamp <= 0
                || std::net::IpAddr::V4(std::net::Ipv4Addr::from(address.policy.address))
                    != record.addresses[0].addr()
                || address.policy.skip_as_source
            {
                return Err(conflict());
            }
        } else if actual.address.is_some()
            || ack.current.address.is_some()
            || ack.creation.is_some()
        {
            return Err(conflict());
        }
        if i != 0 {
            metrics.push(InterfaceMetric {
                interface: proof.index,
                ipv6: false,
                metric: actual.interface.policy.metric,
            });
        }
    }
    Ok(metrics)
}

#[derive(Default)]
struct GateFence {
    busy: Cell<bool>,
    forward_closed: Cell<bool>,
    tainted: Cell<bool>,
}
struct GateFlight<'a> {
    fence: &'a GateFence,
    done: bool,
}
impl Drop for GateFlight<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.fence.forward_closed.set(true);
        }
        self.fence.busy.set(false);
    }
}
impl GateFence {
    fn run<T>(&self, cleanup: bool, call: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
        if self.busy.get() || (!cleanup && self.forward_closed.get()) {
            self.forward_closed.set(true);
            self.tainted.set(true);
            return Err(conflict());
        }
        self.busy.set(true);
        self.tainted.set(false);
        let mut flight = GateFlight {
            fence: self,
            done: false,
        };
        if cleanup {
            self.forward_closed.set(true);
        }
        let value = call()?;
        if self.tainted.get() {
            return Err(conflict());
        }
        flight.done = true;
        Ok(value)
    }
}

#[cfg(windows)]
pub(crate) mod native {
    use super::*;
    use crate::windows::{
        member_carrier_guard::{NativeGuard, Wfp, WindowBindingAttestor},
        member_carrier_key_authority::RuntimeRead,
        member_carrier_network::native::{NativeClosingNetworkRead, NativeNetworkRead},
        member_carrier_network_baseline::native::NativeNetworkBaselineRead,
        member_carrier_network_owner::native::{
            Effect, NativeNetworkAckRead, NativeNetworkAckWeakRead, NativeNetworkEffectGate,
            NativePhysicalPlanCapture,
        },
        member_carrier_pair_store::native_store::{NativeNetworkIntentRead, NativePairIntentRead},
        member_carrier_runtime::native::{
            NativeBindingsWindow, NativeClosingRead, NativeResourceRowsFacts,
            NativeResourceRowsRead, NativeSourceRead, RetiredCarrierRead,
        },
        member_native_deadline::{NativeDeadline, NativeDeadlineReadPin},
        member_physical::full_route_table,
        member_session::{NativeNetworkRecord, NativeSessionFiles, PhysicalLease, RecordKind},
    };
    use std::{
        cell::RefCell,
        net::IpAddr,
        rc::{Rc, Weak},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
    };

    struct Selected {
        pair: Rc<NativePairIntentRead>,
        // No successful default span: None denies all effects/publications.
        network: Option<Rc<NativeNetworkIntentRead>>,
        record: pair::Record,
    }
    struct GuardSelected {
        pair: Rc<NativePairIntentRead>,
        record: pair::Record,
        kind: GuardResourceKind,
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum GuardResourceKind {
        Install,
        StaticBase,
        Retired,
    }
    /// Exact Wfp specialization. Construction retains the actual originals;
    /// every use still verifies current protected intent and the Calling lease.
    pub(crate) struct NativeNetworkGate<A: WindowBindingAttestor> {
        original: Weak<Self>,
        context: Context,
        runtime: RuntimeRead,
        files: NativeSessionFiles,
        source: Rc<NativeSourceRead>,
        closing: RefCell<Option<Rc<NativeClosingRead>>>,
        supervisor: Rc<NativeDeadline>,
        deadline: NativeDeadlineReadPin,
        guard: Rc<RefCell<NativeGuard<Wfp, A>>>,
        rows: Rc<NativeResourceRowsRead>,
        selected: RefCell<Selected>,
        guard_selected: RefCell<Option<GuardSelected>>,
        retired: RefCell<Option<Rc<RetiredCarrierRead>>>,
        live_network: NativeNetworkRead,
        closing_network: RefCell<Option<NativeClosingNetworkRead>>,
        cancelled: Arc<AtomicBool>,
        // This exact self-specialization prevents an unrelated/default gate
        // registry from being presented as the original network effect owner.
        // Actor retains the original Owner strongly. A strong ACK here would
        // create Gate -> Pins -> Gate; weak upgrade must fail closed instead.
        ack: RefCell<Option<NativeNetworkAckWeakRead<Self>>>,
        dns_child: RefCell<Option<crate::member_pair::DnsRecord>>,
        dns_previous: RefCell<Option<Option<crate::member_pair::DnsRecord>>>,
        fence: GateFence,
    }
    impl<A: WindowBindingAttestor> NativeNetworkGate<A> {
        /// Retain every root BEFORE fallible validation. The actor wraps fresh
        /// network-owner construction in its actual supervisor Calling scope,
        /// then registers owner.read_pin() BEFORE invoking select/cleanup.
        /// Main owns the sampler's once-only member/Closing registrations.
        #[allow(clippy::too_many_arguments)]
        pub(crate) fn new(
            context: Context,
            runtime: RuntimeRead,
            files: NativeSessionFiles,
            source: Rc<NativeSourceRead>,
            pair: Rc<NativePairIntentRead>,
            network: Rc<NativeNetworkIntentRead>,
            expected: pair::Record,
            guard: Rc<RefCell<NativeGuard<Wfp, A>>>,
            rows: Rc<NativeResourceRowsRead>,
            supervisor: Rc<NativeDeadline>,
            deadline: NativeDeadlineReadPin,
            cancelled: Arc<AtomicBool>,
        ) -> Rc<Self> {
            Self::with_roots(
                context,
                runtime,
                files,
                source,
                pair,
                Some(network),
                expected,
                guard,
                rows,
                supervisor,
                deadline,
                cancelled,
            )
        }
        /// Actual composition root before the first logical Network CAS.
        /// Actor retains this Rc BEFORE fallible validation/owner construction;
        /// no future span or initial DNS capability is fabricated here.
        #[allow(clippy::too_many_arguments)]
        pub(crate) fn new_pre_network(
            context: Context,
            runtime: RuntimeRead,
            files: NativeSessionFiles,
            source: Rc<NativeSourceRead>,
            pair: Rc<NativePairIntentRead>,
            expected: pair::Record,
            guard: Rc<RefCell<NativeGuard<Wfp, A>>>,
            rows: Rc<NativeResourceRowsRead>,
            supervisor: Rc<NativeDeadline>,
            deadline: NativeDeadlineReadPin,
            cancelled: Arc<AtomicBool>,
        ) -> Rc<Self> {
            Self::with_roots(
                context, runtime, files, source, pair, None, expected, guard, rows, supervisor,
                deadline, cancelled,
            )
        }
        #[allow(clippy::too_many_arguments)]
        fn with_roots(
            context: Context,
            runtime: RuntimeRead,
            files: NativeSessionFiles,
            source: Rc<NativeSourceRead>,
            pair: Rc<NativePairIntentRead>,
            network: Option<Rc<NativeNetworkIntentRead>>,
            expected: pair::Record,
            guard: Rc<RefCell<NativeGuard<Wfp, A>>>,
            rows: Rc<NativeResourceRowsRead>,
            supervisor: Rc<NativeDeadline>,
            deadline: NativeDeadlineReadPin,
            cancelled: Arc<AtomicBool>,
        ) -> Rc<Self> {
            Rc::new_cyclic(|original| Self {
                original: original.clone(),
                context,
                runtime,
                files,
                live_network: NativeNetworkRead::new(source.clone()),
                source,
                closing: RefCell::new(None),
                supervisor,
                deadline,
                guard,
                rows,
                selected: RefCell::new(Selected {
                    pair,
                    network,
                    record: expected,
                }),
                guard_selected: RefCell::new(None),
                retired: RefCell::new(None),
                closing_network: RefCell::new(None),
                cancelled,
                ack: RefCell::new(None),
                dns_child: RefCell::new(None),
                dns_previous: RefCell::new(None),
                fence: GateFence::default(),
            })
        }
        pub(crate) fn retain_owner_ack(
            self: &Rc<Self>,
            original: NativeNetworkAckRead<Self>,
        ) -> io::Result<()> {
            let cleanup =
                self.selected.try_borrow().map_err(denied)?.record.phase == pair::Phase::Closing;
            self.fence.run(cleanup, || {
                let mut slot = self.ack.try_borrow_mut().map_err(denied)?;
                if let Some(old) = slot.as_ref() {
                    if !old.upgrade()?.same_original(&original) {
                        return Err(conflict());
                    }
                } else {
                    *slot = Some(original.downgrade());
                }
                // An unknown first registration remains retained on failure.
                let ack = slot.as_ref().ok_or_else(conflict)?.upgrade()?;
                if !ack.matches_origin(&self.source, self) {
                    return Err(conflict());
                }
                drop(slot);
                let selected = self.selected.try_borrow().map_err(denied)?;
                if selected.network.is_none() && !cleanup {
                    self.verify_pre_network_pair(&selected)
                } else {
                    self.verify_pair(&selected, cleanup)
                }
            })
        }
        pub(crate) fn select_pair_intent(
            &self,
            original_pair: Rc<NativePairIntentRead>,
            original_network: Rc<NativeNetworkIntentRead>,
            expected: pair::Record,
        ) -> io::Result<()> {
            let cleanup = expected.phase == pair::Phase::Closing;
            self.fence.run(cleanup, || {
                let mut old = self.selected.try_borrow_mut().map_err(denied)?;
                compare_network_selection_records(&self.context, &old.record, &expected)?;
                if expected.revision < old.record.revision
                    || (expected.revision == old.record.revision
                        && (expected != old.record
                            || !Rc::ptr_eq(&original_pair, &old.pair)
                            || old
                                .network
                                .as_ref()
                                .is_none_or(|old| !Rc::ptr_eq(&original_network, old))))
                    || (old.record.phase == pair::Phase::Closing && !cleanup)
                    || expected.options != old.record.options
                    || expected.dns != old.record.dns
                {
                    return Err(conflict());
                }
                let next = Selected {
                    pair: original_pair,
                    network: Some(original_network),
                    record: expected,
                };
                self.verify_pair(&next, cleanup)?;
                *old = next;
                Ok(())
            })
        }
        /// Select BEFORE entering the Pair callback/native Guard transaction.
        /// The Network whole-record intent is deliberately NOT reused after
        /// Pair advances to Guard. Its original owner ACK registry is unchanged.
        pub(crate) fn select_guard_resources(
            &self,
            original_pair: Rc<NativePairIntentRead>,
            expected: pair::Record,
        ) -> io::Result<()> {
            self.fence.run(false, || {
                self.guard_continuity(&expected)?;
                let mut retained = self.guard_selected.try_borrow_mut().map_err(denied)?;
                if retained.as_ref().is_some_and(|old| {
                    expected.revision < old.record.revision
                        || (expected.revision == old.record.revision
                            && (expected != old.record || !Rc::ptr_eq(&original_pair, &old.pair)))
                }) || !original_pair.matches_runtime(&self.runtime)
                {
                    return Err(conflict());
                }
                original_pair.inspect_effect(
                    &self.runtime,
                    &self.supervisor,
                    &expected,
                    pair::Effect::Guard,
                    |actual| {
                        if actual != &expected {
                            return Err(conflict());
                        }
                        compare_guard_resource_stage(&self.context, actual).map(|_| ())
                    },
                )?;
                self.guard_continuity(&expected)?;
                *retained = Some(GuardSelected {
                    pair: original_pair,
                    record: expected,
                    kind: GuardResourceKind::Install,
                });
                Ok(())
            })
        }
        pub(crate) fn select_static_base_resources(
            &self,
            original_pair: Rc<NativePairIntentRead>,
            expected: pair::Record,
        ) -> io::Result<()> {
            self.select_read_resources(original_pair, expected, GuardResourceKind::StaticBase)
        }
        pub(crate) fn select_retired_guard_resources(
            &self,
            original_pair: Rc<NativePairIntentRead>,
            expected: pair::Record,
            retired: Rc<RetiredCarrierRead>,
        ) -> io::Result<()> {
            // Registration is once/SAME original, retained before validation.
            self.fence.forward_closed.set(true);
            let mut slot = self.retired.try_borrow_mut().map_err(denied)?;
            if slot.as_ref().is_some_and(|old| !Rc::ptr_eq(old, &retired)) {
                return Err(conflict());
            }
            if slot.is_none() {
                *slot = Some(retired);
            }
            if !slot
                .as_ref()
                .ok_or_else(conflict)?
                .matches_source_origin(&self.source)
            {
                return Err(conflict());
            }
            drop(slot);
            self.select_read_resources(original_pair, expected, GuardResourceKind::Retired)
        }
        fn select_read_resources(
            &self,
            original_pair: Rc<NativePairIntentRead>,
            expected: pair::Record,
            kind: GuardResourceKind,
        ) -> io::Result<()> {
            self.fence.run(kind == GuardResourceKind::Retired, || {
                self.resource_read_continuity(&expected, kind)?;
                if !original_pair.matches_runtime(&self.runtime) {
                    return Err(conflict());
                }
                let mut selected = self.guard_selected.try_borrow_mut().map_err(denied)?;
                if selected.as_ref().is_some_and(|old| {
                    expected.revision < old.record.revision
                        || (expected.revision == old.record.revision
                            && (expected != old.record || !Rc::ptr_eq(&original_pair, &old.pair)))
                }) {
                    return Err(conflict());
                }
                let read = |actual: &pair::Record| {
                    if actual != &expected {
                        return Err(conflict());
                    }
                    self.resource_read_continuity(actual, kind)
                };
                if kind == GuardResourceKind::Retired {
                    original_pair.inspect_cleanup_effect(
                        &self.runtime,
                        &self.supervisor,
                        &expected,
                        10,
                        read,
                    )?;
                } else {
                    original_pair.inspect_effect(
                        &self.runtime,
                        &self.supervisor,
                        &expected,
                        pair::Effect::Guard,
                        read,
                    )?;
                }
                self.resource_read_continuity(&expected, kind)?;
                *selected = Some(GuardSelected {
                    pair: original_pair,
                    record: expected,
                    kind,
                });
                Ok(())
            })
        }
        fn resource_read_continuity(
            &self,
            record: &pair::Record,
            kind: GuardResourceKind,
        ) -> io::Result<()> {
            match kind {
                GuardResourceKind::Install => return self.guard_continuity(record),
                GuardResourceKind::StaticBase => {
                    compare_static_base_resource_stage(&self.context, record)?
                }
                GuardResourceKind::Retired => {
                    compare_retired_resource_stage(&self.context, record)?
                }
            }
            self.deadline
                .verify_runtime_call(&self.supervisor, &self.runtime, &self.context)
                .map_err(denied)?;
            self.runtime
                .verify_same_session_files(&self.context, &self.files)
                .map_err(denied)?;
            if kind == GuardResourceKind::Retired {
                self.runtime.verify(&self.context).map_err(denied)?;
            } else if self.cancelled.load(Ordering::Acquire)
                || !self.runtime.fresh(&self.context).map_err(denied)?
            {
                return Err(conflict());
            }
            self.deadline
                .verify_call(&self.supervisor, &self.context)
                .map_err(denied)
        }
        fn protected_pair(&self, record: &pair::Record) -> io::Result<Vec<u8>> {
            let raw = self
                .runtime
                .optional_record(&self.context, RecordKind::Pair)
                .map_err(denied)?
                .ok_or_else(conflict)?;
            let actual =
                crate::windows::member_carrier_pair_store::carrier_payload(&record.scope, &raw)?
                    .ok_or_else(conflict)?;
            if &actual != record {
                return Err(conflict());
            }
            Ok(raw)
        }
        /// Read-only stable facts for Main's independently validated initial/
        /// additive DENY-only Base boundary. Not an Install or removal grant.
        /// This variant needs an existing Network/owner; no initial empty ACK
        /// is invented if Main has not constructed the actual owner yet.
        pub(crate) fn verify_ack_for_static_base(
            &self,
            record: &pair::Record,
            window: &NativeBindingsWindow<'_>,
        ) -> io::Result<()> {
            self.fence.run(false, || {
                let selected = self.guard_selected.try_borrow().map_err(denied)?;
                let selected = selected.as_ref().ok_or_else(conflict)?;
                if selected.kind != GuardResourceKind::StaticBase
                    || &selected.record != record
                    || !selected.pair.matches_runtime(&self.runtime)
                {
                    return Err(conflict());
                }
                self.resource_read_continuity(record, GuardResourceKind::StaticBase)?;
                self.verify_bindings(record, false, window)?;
                let pair_bytes = self.protected_pair(record)?;
                let ack = self.ack_pin()?;
                let (attempts, dns_acks) = ack.acknowledgements()?;
                let leases = ack.physical_leases()?;
                if leases.len() > 32768 {
                    return Err(conflict());
                }
                // Main's real sampler compares original Row ACK/protected/full
                // SDK, with pending denied. New B baseline need not be weak yet.
                let read_rows = || {
                    self.rows
                        .inspect_in_window(window, |facts| Ok(facts.clone()))
                        .map_err(denied)
                };
                let rows = read_rows()?;
                let network = self.network_facts(false, window)?;
                let physical = self.capture_physical(window)?;
                let saved = NativeNetworkRecord::read_comparison(
                    &record.scope,
                    network.protected_record.as_deref().ok_or_else(conflict)?,
                )?;
                if saved.physical != leases {
                    return Err(conflict());
                }
                let child = self.dns_child.try_borrow().map_err(denied)?;
                compare_guard_resource_journals(
                    record,
                    &saved.journal,
                    child.as_ref(),
                    &network.dns,
                    &dns_acks,
                )?;
                compare_route_reads(record, &saved.journal, &attempts, physical.rows())?;
                for route in &record.network.as_ref().ok_or_else(conflict)?.current.routes {
                    compare_route_ack(
                        &attempts,
                        physical
                            .rows()
                            .iter()
                            .find(|r| &r.route == route)
                            .ok_or_else(conflict)?,
                    )?;
                }
                for lease in &leases {
                    physical.verify(&physical_route(lease)).map_err(denied)?;
                }
                let after = self.capture_physical(window)?;
                if read_rows()? != rows
                    || self.network_facts(false, window)? != network
                    || after.rows() != physical.rows()
                    || after.proofs() != physical.proofs()
                    || self.protected_pair(record)? != pair_bytes
                {
                    return Err(conflict());
                }
                self.resource_read_continuity(record, GuardResourceKind::StaticBase)?;
                self.verify_bindings(record, false, window)
            })
        }
        /// Called ONLY inside the actual SAME Retired full-native-EMPTY bracket.
        /// Does not enter Retired/Source/Pair/Guard and never queries old C DNS.
        pub(crate) fn verify_retired_guard_resources(
            &self,
            record: &pair::Record,
            retired: &RetiredCarrierRead,
            bindings: &crate::windows::member_carrier_guard::Bindings,
        ) -> io::Result<()> {
            self.fence.run(true, || {
                let selected = self.guard_selected.try_borrow().map_err(denied)?;
                let selected = selected.as_ref().ok_or_else(conflict)?;
                let original = self.retired.try_borrow().map_err(denied)?;
                if selected.kind != GuardResourceKind::Retired
                    || &selected.record != record
                    || !selected.pair.matches_runtime(&self.runtime)
                    || !original
                        .as_ref()
                        .is_some_and(|r| std::ptr::eq(r.as_ref(), retired))
                    || !retired.matches_source_origin(&self.source)
                {
                    return Err(conflict());
                }
                self.resource_read_continuity(record, GuardResourceKind::Retired)?;
                self.compare_retired_bindings(record, retired, bindings)?;
                let before_pair = self.protected_pair(record)?;
                let ack = self.ack_pin()?;
                let (attempts, dns_acks) = ack.acknowledgements()?;
                let leases = ack.physical_leases()?;
                if leases.len() > 32768 {
                    return Err(conflict());
                }
                let raw = self
                    .runtime
                    .optional_record(&self.context, RecordKind::Network)
                    .map_err(denied)?
                    .ok_or_else(conflict)?;
                let saved = NativeNetworkRecord::read_comparison(&record.scope, &raw)?;
                if saved.physical != leases {
                    return Err(conflict());
                }
                compare_retired_resource_journals(
                    &self.context,
                    record,
                    &saved.journal,
                    self.dns_child.try_borrow().map_err(denied)?.is_some(),
                    &dns_acks,
                )?;
                let read_rows = || {
                    self.rows
                        .inspect_retired_in_bracket(retired, bindings, |facts| Ok(facts.clone()))
                        .map_err(denied)
                };
                let rows = read_rows()?;
                let table = full_route_table()?;
                compare_retired_route_reads(record, &attempts, &table)?;
                if full_route_table()? != table
                    || read_rows()? != rows
                    || self.protected_pair(record)? != before_pair
                    || self
                        .runtime
                        .optional_record(&self.context, RecordKind::Network)
                        .map_err(denied)?
                        .as_ref()
                        != Some(&raw)
                {
                    return Err(conflict());
                }
                self.resource_read_continuity(record, GuardResourceKind::Retired)?;
                self.compare_retired_bindings(record, retired, bindings)
            })
        }
        fn lifecycle_continuity(
            &self,
            record: &pair::Record,
            baseline: &NativeNetworkBaselineRead<A>,
            retired: bool,
        ) -> io::Result<()> {
            compare_lifecycle_resource_stage(&self.context, record, baseline.snapshot(), retired)?;
            self.lifecycle_origin_continuity(record, baseline)
        }
        fn lifecycle_origin_continuity(
            &self,
            record: &pair::Record,
            baseline: &NativeNetworkBaselineRead<A>,
        ) -> io::Result<()> {
            if !baseline.matches_source_origin(&self.source) {
                return Err(conflict());
            }
            self.deadline
                .verify_runtime_call(&self.supervisor, &self.runtime, &self.context)
                .map_err(denied)?;
            self.runtime
                .verify_same_session_files(&self.context, &self.files)
                .map_err(denied)?;
            self.runtime.verify(&self.context).map_err(denied)?;
            let old = self.selected.try_borrow().map_err(denied)?;
            // The old Network intent is stale after its owning operation. It
            // establishes original lineage ONLY; NEVER inspect it recursively
            // or project this lifecycle record into a Network/Guard stage.
            if record.revision < old.record.revision
                || record.scope != old.record.scope
                || record.provenance != old.record.provenance
                || record.carrier != old.record.carrier
                || record.addresses != old.record.addresses
                || record.dns != old.record.dns
                || record.options != old.record.options
                || record.network.as_ref().is_some_and(|n| {
                    old.record
                        .network
                        .as_ref()
                        .is_none_or(|old| n.baseline != old.baseline)
                })
            {
                return Err(conflict());
            }
            drop(old);
            self.deadline
                .verify_call(&self.supervisor, &self.context)
                .map_err(denied)
        }
        fn native_empty_continuity(
            &self,
            record: &pair::Record,
            baseline: &NativeNetworkBaselineRead<A>,
        ) -> io::Result<()> {
            compare_native_empty_resource_stage(&self.context, record, baseline.snapshot())?;
            self.lifecycle_origin_continuity(record, baseline)?;
            let old = self.selected.try_borrow().map_err(denied)?;
            if !old.pair.matches_runtime(&self.runtime)
                || (old.record.network.is_some() && record.network.is_none())
            {
                return Err(conflict());
            }
            Ok(())
        }
        fn full_empty_continuity(
            &self,
            channel: EmptyReadChannel,
            record: &pair::Record,
            baseline: &NativeNetworkBaselineRead<A>,
        ) -> io::Result<()> {
            compare_terminal_empty_stage(channel, &self.context, record, baseline.snapshot())?;
            if record.phase != pair::Phase::Stopped {
                return self.lifecycle_origin_continuity(record, baseline);
            }
            if !baseline.matches_source_origin(&self.source) {
                return Err(conflict());
            }
            self.deadline
                .verify_runtime_call(&self.supervisor, &self.runtime, &self.context)
                .map_err(denied)?;
            self.runtime
                .verify_same_session_files(&self.context, &self.files)
                .map_err(denied)?;
            self.runtime.verify(&self.context).map_err(denied)?;
            let old = self.selected.try_borrow().map_err(denied)?;
            let c = &baseline.snapshot().interface;
            if !old.pair.matches_runtime(&self.runtime)
                || record.revision < old.record.revision
                || record.scope != old.record.scope
                || record.provenance != old.record.provenance
                || record.addresses != old.record.addresses
                || record.dns != old.record.dns
                || record.options != old.record.options
                || old.record.carrier
                    != Some(crate::member_owner::InterfaceProof {
                        guid: c.guid,
                        index: c.index,
                        luid: c.luid,
                    })
                || old.record.network.is_some() && record.network.is_none()
                || record.network.as_ref().is_some_and(|n| {
                    old.record
                        .network
                        .as_ref()
                        .is_none_or(|old| n.baseline != old.baseline)
                })
            {
                return Err(conflict());
            }
            drop(old);
            self.deadline
                .verify_call(&self.supervisor, &self.context)
                .map_err(denied)
        }
        fn empty_continuity(
            &self,
            channel: EmptyReadChannel,
            record: &pair::Record,
            baseline: &NativeNetworkBaselineRead<A>,
        ) -> io::Result<()> {
            match channel {
                EmptyReadChannel::Native => self.native_empty_continuity(record, baseline),
                EmptyReadChannel::Full | EmptyReadChannel::KeysRestored => {
                    self.full_empty_continuity(channel, record, baseline)
                }
            }
        }
        fn lifecycle_journal(
            &self,
            record: &pair::Record,
            baseline: &NativeNetworkBaselineRead<A>,
            raw: Option<&[u8]>,
            ack: &NativeNetworkAckRead<Self>,
        ) -> io::Result<()> {
            let (routes, dns_acks) = ack.acknowledgements()?;
            let (count, history) = ack.dns_exchange_history()?;
            if history != dns_acks {
                return Err(conflict());
            }
            let leases = ack.physical_obligations()?;
            let saved = raw
                .map(|bytes| NativeNetworkRecord::read_comparison(&record.scope, bytes))
                .transpose()?;
            ack.verify_physical_record(saved.as_ref().map(|saved| saved.physical.as_slice()))?;
            if leases.len() > 32768 {
                return Err(conflict());
            }
            let child = self.dns_child.try_borrow().map_err(denied)?;
            compare_lifecycle_resource_journals(
                &self.context,
                record,
                baseline.snapshot(),
                saved.as_ref().map(|s| &s.journal),
                child.as_ref(),
                &routes,
                count,
                &history,
            )
        }
        /// READ-only facts for lifecycle G inside the supplied actual Closing
        /// window. Caller separately brackets WFP and pending/restored rows and
        /// current original Pair. No Guard, Pair, Source or mutable State reentry.
        /// Pauli's SDK baseline is factual, never a fabricated exchange ACK.
        pub(crate) fn verify_lifecycle_restored(
            &self,
            record: &pair::Record,
            window: &NativeBindingsWindow<'_>,
            baseline: &NativeNetworkBaselineRead<A>,
        ) -> io::Result<()> {
            self.fence.run(true, || {
                self.lifecycle_continuity(record, baseline, false)?;
                self.verify_bindings(record, true, window)?;
                let pair = self.protected_pair(record)?;
                let ack = self.ack_pin()?;
                let before_acks = ack.acknowledgements()?;
                let before_dns = ack.dns_exchange_history()?;
                let obligations = ack.physical_obligations()?;
                let facts = self.network_facts(true, window)?;
                self.lifecycle_journal(record, baseline, facts.protected_record.as_deref(), &ack)?;
                if facts.dns != *baseline.snapshot()
                    || !facts.routes.current.is_empty()
                    || facts.routes.pending.is_some()
                    || facts.routes.active.is_some()
                    || facts.routes.pending_active.is_some()
                {
                    return Err(conflict());
                }
                let bindings = window.bindings();
                let proofs = [
                    bindings.carrier.as_ref().map(|c| c.identity.proof),
                    bindings.egress[0].as_ref().map(|e| e.proof),
                    bindings.egress[1].as_ref().map(|e| e.proof),
                ];
                let table = full_route_table()?;
                compare_lifecycle_route_table(record, proofs, &before_acks.0, &table, true)?;
                if !obligations.is_empty() {
                    // Keep exact original physical lease checks. Historical member
                    // identities remain EXCLUSIONS, not live NIC lookups/adoption.
                    let physical = self.capture_physical(window)?;
                    for lease in &obligations {
                        physical.verify(&physical_route(lease)).map_err(denied)?;
                    }
                    let after = self.capture_physical(window)?;
                    if after.rows() != physical.rows() || after.proofs() != physical.proofs() {
                        return Err(conflict());
                    }
                }
                if full_route_table()? != table
                    || self.network_facts(true, window)? != facts
                    || self.protected_pair(record)? != pair
                    || !same_network_ack_reads(&before_acks, &ack.acknowledgements()?)
                    || ack.dns_exchange_history()? != before_dns
                    || ack.physical_obligations()? != obligations
                {
                    return Err(conflict());
                }
                self.lifecycle_journal(record, baseline, facts.protected_record.as_deref(), &ack)?;
                self.verify_bindings(record, true, window)?;
                self.lifecycle_continuity(record, baseline, false)
            })
        }
        /// Caller holds SAME actual retired FULL native EMPTY bracket. Stage8
        /// ONLY, no live Window/old C DNS query. This is not stage10 removal or
        /// standalone effect permission, and does not borrow actual Guard/Pair.
        pub(crate) fn verify_lifecycle_retired_in_bracket(
            &self,
            record: &pair::Record,
            retired: &RetiredCarrierRead,
            bindings: &crate::windows::member_carrier_guard::Bindings,
            baseline: &NativeNetworkBaselineRead<A>,
        ) -> io::Result<()> {
            self.fence.run(true, || {
                self.lifecycle_continuity(record, baseline, true)?;
                if !retired.matches_source_origin(&self.source) {
                    return Err(conflict());
                }
                self.compare_retired_bindings(record, retired, bindings)?;
                let before_pair = self.protected_pair(record)?;
                let raw = self
                    .runtime
                    .optional_record(&self.context, RecordKind::Network)
                    .map_err(denied)?;
                let ack = self.ack_pin()?;
                let before_acks = ack.acknowledgements()?;
                let before_dns = ack.dns_exchange_history()?;
                let obligations = ack.physical_obligations()?;
                self.lifecycle_journal(record, baseline, raw.as_deref(), &ack)?;
                let proofs = [
                    bindings.carrier.as_ref().map(|c| c.identity.proof),
                    bindings.egress[0].as_ref().map(|e| e.proof),
                    bindings.egress[1].as_ref().map(|e| e.proof),
                ];
                let table = full_route_table()?;
                compare_lifecycle_route_table(record, proofs, &before_acks.0, &table, false)?;
                let physical_changed = !obligations.is_empty() && {
                    // Query only actual remaining table rows' physical interfaces;
                    // retired identities are exclusions. Never old C DNS/NIC SDK.
                    let owned = proofs
                        .iter()
                        .flatten()
                        .map(|p| InterfaceIdentity {
                            index: p.index,
                            luid: p.luid,
                            guid: p.guid,
                        })
                        .collect::<Vec<_>>();
                    let physical =
                        crate::windows::member_physical::capture(&owned).map_err(denied)?;
                    for lease in &obligations {
                        physical.verify(&physical_route(lease)).map_err(denied)?;
                    }
                    let after = crate::windows::member_physical::capture(&owned).map_err(denied)?;
                    after.rows() != physical.rows() || after.proofs() != physical.proofs()
                };
                if full_route_table()? != table
                    || physical_changed
                    || self
                        .runtime
                        .optional_record(&self.context, RecordKind::Network)
                        .map_err(denied)?
                        != raw
                    || self.protected_pair(record)? != before_pair
                    || !same_network_ack_reads(&before_acks, &ack.acknowledgements()?)
                    || ack.dns_exchange_history()? != before_dns
                    || ack.physical_obligations()? != obligations
                {
                    return Err(conflict());
                }
                self.lifecycle_journal(record, baseline, raw.as_deref(), &ack)?;
                self.lifecycle_continuity(record, baseline, true)
            })
        }
        /// Exact Closing9/NativeEmpty or Closing10/Guard read prerequisite.
        /// Caller holds original Pair ACK/Calling and Retired full SDK EMPTY
        /// brackets. Never projects through stage8 permission, enters Source,
        /// Pair or Guard, queries historical DNS/NICs, or invokes native IO.
        pub(crate) fn verify_native_empty_in_retired_bracket(
            &self,
            record: &pair::Record,
            retired: &RetiredCarrierRead,
            bindings: &crate::windows::member_carrier_guard::Bindings,
            baseline: &NativeNetworkBaselineRead<A>,
            reader: &NativeNetworkRead,
        ) -> io::Result<()> {
            self.verify_empty_in_retired_bracket(
                EmptyReadChannel::Native,
                record,
                retired,
                bindings,
                baseline,
                reader,
            )
        }
        pub(crate) fn verify_full_empty_in_retired_bracket(
            &self,
            record: &pair::Record,
            retired: &RetiredCarrierRead,
            bindings: &crate::windows::member_carrier_guard::Bindings,
            baseline: &NativeNetworkBaselineRead<A>,
            reader: &NativeNetworkRead,
        ) -> io::Result<()> {
            self.verify_empty_in_retired_bracket(
                EmptyReadChannel::Full,
                record,
                retired,
                bindings,
                baseline,
                reader,
            )
        }
        pub(crate) fn verify_restored_keys_in_retired_bracket(
            &self,
            record: &pair::Record,
            retired: &RetiredCarrierRead,
            bindings: &crate::windows::member_carrier_guard::Bindings,
            baseline: &NativeNetworkBaselineRead<A>,
            reader: &NativeNetworkRead,
        ) -> io::Result<()> {
            self.verify_empty_in_retired_bracket(
                EmptyReadChannel::KeysRestored,
                record,
                retired,
                bindings,
                baseline,
                reader,
            )
        }
        fn verify_empty_in_retired_bracket(
            &self,
            channel: EmptyReadChannel,
            record: &pair::Record,
            retired: &RetiredCarrierRead,
            bindings: &crate::windows::member_carrier_guard::Bindings,
            baseline: &NativeNetworkBaselineRead<A>,
            reader: &NativeNetworkRead,
        ) -> io::Result<()> {
            self.fence.run(true, || {
                self.empty_continuity(channel, record, baseline)?;
                if !baseline.matches_reader(reader) || !retired.matches_source_origin(&self.source)
                {
                    return Err(conflict());
                }
                let registered = self.retired.try_borrow().map_err(denied)?;
                if registered
                    .as_ref()
                    .is_some_and(|original| !std::ptr::eq(original.as_ref(), retired))
                {
                    return Err(conflict());
                }
                drop(registered);
                self.compare_empty_bindings(channel, record, retired, bindings, baseline)?;
                let pair_bytes = self.protected_pair(record)?;
                let ack = self.ack_pin()?; // upgrades SAME weak registry, never owner State
                let before_acks = ack.acknowledgements()?;
                let before_dns = ack.dns_exchange_history()?;
                let obligations = ack.physical_obligations()?;
                if obligations.len() > 32768 || before_dns.1 != before_acks.1 {
                    return Err(conflict());
                }
                let child = self.dns_child.try_borrow().map_err(denied)?.clone();
                // Unrelated Network journal is read from the immutable original
                // handle, not Runtime's typed birth/cleanup facet (which denies
                // Network). No reopening, imported snapshot or read fallback.
                let mut original_files = self.files.clone();
                let inspect = |raw: Option<Vec<u8>>| {
                    let saved = raw
                        .as_deref()
                        .map(|bytes| NativeNetworkRecord::read_comparison(&record.scope, bytes))
                        .transpose()?;
                    ack.verify_physical_record(
                        saved.as_ref().map(|saved| saved.physical.as_slice()),
                    )?;
                    let compare_journals = match channel {
                        EmptyReadChannel::Native => compare_native_empty_resource_journals,
                        EmptyReadChannel::KeysRestored => compare_restored_keys_resource_journals,
                        EmptyReadChannel::Full => compare_full_empty_resource_journals,
                    };
                    compare_journals(
                        &self.context,
                        record,
                        baseline.snapshot(),
                        saved.as_ref().map(|saved| &saved.journal),
                        child.as_ref(),
                        &before_acks.0,
                        before_dns.0,
                        &before_dns.1,
                    )?;
                    let read_rows =
                        || {
                            self.rows
                                .inspect_retired_in_bracket(retired, bindings, |facts| {
                                    Ok(facts.clone())
                                })
                                .map_err(denied)
                        };
                    let rows = read_rows()?; // actual stopped RowOwner ACK+protected bytes
                    let proofs = [
                        bindings.carrier.as_ref().map(|c| c.identity.proof),
                        bindings.egress[0].as_ref().map(|e| e.proof),
                        bindings.egress[1].as_ref().map(|e| e.proof),
                    ];
                    let table = full_route_table()?;
                    match channel {
                        EmptyReadChannel::Native => compare_lifecycle_route_table(
                            record,
                            proofs,
                            &before_acks.0,
                            &table,
                            false,
                        )?,
                        EmptyReadChannel::Full | EmptyReadChannel::KeysRestored => {
                            compare_original_route_absence(
                                record,
                                proofs,
                                &before_acks.0,
                                &table,
                                false,
                                proofs[0].ok_or_else(conflict)?,
                            )?
                        }
                    }
                    let physical_changed = !obligations.is_empty() && {
                        // Full route table capture resolves ONLY interfaces of
                        // actual remaining rows. Historical identities stay
                        // exclusions; never adopt a foreign/old member path.
                        let owned = proofs
                            .iter()
                            .flatten()
                            .map(|proof| InterfaceIdentity {
                                index: proof.index,
                                luid: proof.luid,
                                guid: proof.guid,
                            })
                            .collect::<Vec<_>>();
                        let physical =
                            crate::windows::member_physical::capture(&owned).map_err(denied)?;
                        for lease in &obligations {
                            physical.verify(&physical_route(lease)).map_err(denied)?;
                        }
                        let after =
                            crate::windows::member_physical::capture(&owned).map_err(denied)?;
                        for lease in &obligations {
                            after.verify(&physical_route(lease)).map_err(denied)?;
                        }
                        after.rows() != physical.rows() || after.proofs() != physical.proofs()
                    };
                    if full_route_table()? != table
                        || physical_changed
                        || read_rows()? != rows
                        || self.protected_pair(record)? != pair_bytes
                        || !same_network_ack_reads(&before_acks, &ack.acknowledgements()?)
                        || ack.dns_exchange_history()? != before_dns
                        || ack.physical_obligations()? != obligations
                        || *self.dns_child.try_borrow().map_err(denied)? != child
                    {
                        return Err(conflict());
                    }
                    ack.verify_physical_record(
                        saved.as_ref().map(|saved| saved.physical.as_slice()),
                    )?;
                    self.compare_empty_bindings(channel, record, retired, bindings, baseline)?;
                    self.empty_continuity(channel, record, baseline)
                };
                match channel {
                    EmptyReadChannel::Native => reader.inspect_original_retired_record(
                        &self.source,
                        retired,
                        &mut original_files,
                        inspect,
                    )?,
                    EmptyReadChannel::Full | EmptyReadChannel::KeysRestored => reader
                        .inspect_original_full_empty_record(
                            &self.source,
                            retired,
                            &mut original_files,
                            inspect,
                        )?,
                }
                // Reader finishes its shared protected Network postread before
                // the final Runtime/Calling/whole-Pair checks return any facts.
                if self.protected_pair(record)? != pair_bytes
                    || !same_network_ack_reads(&before_acks, &ack.acknowledgements()?)
                    || ack.dns_exchange_history()? != before_dns
                    || ack.physical_obligations()? != obligations
                    || *self.dns_child.try_borrow().map_err(denied)? != child
                {
                    return Err(conflict());
                }
                self.compare_empty_bindings(channel, record, retired, bindings, baseline)?;
                self.empty_continuity(channel, record, baseline)
            })
        }
        fn guard_continuity(&self, record: &pair::Record) -> io::Result<()> {
            compare_guard_resource_stage(&self.context, record)?;
            let network = self.selected.try_borrow().map_err(denied)?;
            // Pre-network metadata never establishes successful Install lineage.
            if network
                .network
                .as_ref()
                .is_none_or(|n| !n.matches_runtime(&self.runtime))
            {
                return Err(conflict());
            }
            compare_guard_member_lineage(&network.record, record)?;
            // The old successful Network operation establishes lineage only;
            // its now-stale NetworkIntentRead must NEVER inspect current Pair.
            if record.revision <= network.record.revision
                || record.scope != network.record.scope
                || record.provenance != network.record.provenance
                || record.carrier != network.record.carrier
                || record.operation != network.record.operation
                || record.options != network.record.options
                || record.dns != network.record.dns
                || record.network.as_ref().map(|n| &n.baseline)
                    != network.record.network.as_ref().map(|n| &n.baseline)
                || record.network.as_ref().map(|n| &n.current)
                    != network
                        .record
                        .network
                        .as_ref()
                        .and_then(|n| n.pending.as_ref())
                || network.record.phase == pair::Phase::Closing
                || self.cancelled.load(Ordering::Acquire)
            {
                return Err(conflict());
            }
            self.deadline
                .verify_runtime_call(&self.supervisor, &self.runtime, &self.context)
                .map_err(denied)?;
            self.runtime
                .verify_same_session_files(&self.context, &self.files)
                .map_err(denied)?;
            if !self.runtime.fresh(&self.context).map_err(denied)? {
                return Err(conflict());
            }
            self.deadline
                .verify_call(&self.supervisor, &self.context)
                .map_err(denied)
        }
        /// READ-ONLY Install resource facts. Caller MUST hold the selected
        /// original Pair inspection and native Guard transaction, with actual
        /// WFP/window attestation bracketing this call. This is not a grant.
        /// No Pair/NetworkIntent inspect, Source entry, or NativeGuard borrow.
        pub(crate) fn verify_guard_resources(
            &self,
            record: &pair::Record,
            window: &NativeBindingsWindow<'_>,
        ) -> io::Result<()> {
            self.fence.run(false, || {
                let selected = self.guard_selected.try_borrow().map_err(denied)?;
                let selected = selected.as_ref().ok_or_else(conflict)?;
                if selected.kind != GuardResourceKind::Install
                    || &selected.record != record
                    || !selected.pair.matches_runtime(&self.runtime)
                {
                    return Err(conflict());
                }
                self.guard_continuity(record)?;
                self.verify_bindings(record, false, window)?;
                let pair_bytes = self.protected_pair(record)?;
                let ack = self.ack_pin()?;
                let (attempts, dns_acks) = ack.acknowledgements()?;
                let leases = ack.physical_leases()?;
                if leases.len() > 32768 {
                    return Err(conflict());
                }
                let (resources, metrics) = self.resource_facts(record, window)?;
                let network = self.network_facts(false, window)?;
                let physical = self.capture_physical(window)?;
                let saved = NativeNetworkRecord::read_comparison(
                    &record.scope,
                    network.protected_record.as_deref().ok_or_else(conflict)?,
                )?;
                if saved.physical != leases {
                    return Err(conflict());
                }
                let child = self.dns_child.try_borrow().map_err(denied)?;
                compare_guard_resource_journals(
                    record,
                    &saved.journal,
                    child.as_ref(),
                    &network.dns,
                    &dns_acks,
                )?;
                compare_route_reads(record, &saved.journal, &attempts, physical.rows())?;
                // Unlike an in-flight Network before-or-after, stable Install
                // requires EVERY planned row actually present with native ACK.
                for route in &record.network.as_ref().ok_or_else(conflict)?.current.routes {
                    let actual = physical
                        .rows()
                        .iter()
                        .find(|r| &r.route == route)
                        .ok_or_else(conflict)?;
                    compare_route_ack(&attempts, actual)?;
                }
                for lease in &leases {
                    physical.verify(&physical_route(lease)).map_err(denied)?;
                }
                let clean = self.clean_physical(window, &physical, &attempts)?;
                let plan = compute_plan(
                    record,
                    compare_guard_resource_stage(&self.context, record)?,
                    &clean,
                    &metrics,
                )?;
                compare_guard_resource_plan(record, &plan)?;
                compare_physical_plan(&plan.physical, &leases)?;
                if self.resource_facts(record, window)?.0 != resources
                    || self.network_facts(false, window)? != network
                {
                    return Err(conflict());
                }
                let after = self.capture_physical(window)?;
                if after.rows() != physical.rows() || after.proofs() != physical.proofs() {
                    return Err(conflict());
                }
                if self.protected_pair(record)? != pair_bytes {
                    return Err(conflict());
                }
                self.guard_continuity(record)?;
                self.verify_bindings(record, false, window)
            })
        }
        fn continuity(&self, selected: &Selected, cleanup: bool) -> io::Result<()> {
            let network = selected.network.as_ref().ok_or_else(conflict)?;
            compare_stage(&self.context, &selected.record, cleanup)?;
            if !selected.pair.matches_runtime(&self.runtime)
                || !network.matches_runtime(&self.runtime)
                || (!cleanup && self.cancelled.load(Ordering::Acquire))
            {
                return Err(conflict());
            }
            self.deadline
                .verify_runtime_call(&self.supervisor, &self.runtime, &self.context)
                .map_err(denied)?;
            self.runtime
                .verify_same_session_files(&self.context, &self.files)
                .map_err(denied)?;
            if !cleanup && !self.runtime.fresh(&self.context).map_err(denied)? {
                return Err(conflict());
            }
            self.deadline
                .verify_call(&self.supervisor, &self.context)
                .map_err(denied)
        }
        fn verify_pre_network_pair(&self, selected: &Selected) -> io::Result<()> {
            if selected.network.is_some()
                || !selected.pair.matches_runtime(&self.runtime)
                || self.cancelled.load(Ordering::Acquire)
                || self.source.network_scope() != &selected.record.scope
            {
                return Err(conflict());
            }
            compare_pre_network_record(&self.context, &selected.record)?;
            self.deadline
                .verify_runtime(&self.supervisor, &self.runtime, &self.context)
                .map_err(denied)?;
            self.runtime
                .verify_same_session_files(&self.context, &self.files)
                .map_err(denied)?;
            if !self.runtime.fresh(&self.context).map_err(denied)? {
                return Err(conflict());
            }
            self.deadline
                .verify_call(&self.supervisor, &self.context)
                .map_err(denied)?;
            selected
                .pair
                .inspect(&self.runtime, &self.supervisor, |actual| {
                    if actual != &selected.record {
                        return Err(conflict());
                    }
                    compare_pre_network_record(&self.context, actual)
                })?;
            self.deadline
                .verify_call(&self.supervisor, &self.context)
                .map_err(denied)
        }
        fn verify_pair(&self, selected: &Selected, cleanup: bool) -> io::Result<()> {
            self.continuity(selected, cleanup)?;
            // End this Pair callback BEFORE the row/network/Guard sibling joins.
            // Guard's attestor may inspect this SAME original Pair pin itself.
            let verify = |actual: &pair::Record| {
                if actual != &selected.record {
                    return Err(conflict());
                }
                compare_stage(&self.context, actual, cleanup).map(|_| ())
            };
            if cleanup {
                selected.pair.inspect_cleanup_effect(
                    &self.runtime,
                    &self.supervisor,
                    &selected.record,
                    2,
                    verify,
                )?;
            } else {
                selected.pair.inspect_effect(
                    &self.runtime,
                    &self.supervisor,
                    &selected.record,
                    pair::Effect::Network,
                    verify,
                )?;
            }
            // SAME successful original whole-store ACK. This must be a sibling
            // read, never nested inside NativePairIntentRead's callback.
            selected.network.as_ref().ok_or_else(conflict)?.inspect(
                &self.runtime,
                &self.supervisor,
                &selected.record,
                |_| Ok(()),
            )?;
            self.continuity(selected, cleanup)
        }
        fn verify_window(
            &self,
            selected: &Selected,
            cleanup: bool,
            window: &NativeBindingsWindow<'_>,
        ) -> io::Result<()> {
            self.continuity(selected, cleanup)?;
            self.verify_bindings(&selected.record, cleanup, window)
        }
        fn verify_bindings(
            &self,
            r: &pair::Record,
            cleanup: bool,
            window: &NativeBindingsWindow<'_>,
        ) -> io::Result<()> {
            let channel = if cleanup {
                self.closing
                    .try_borrow()
                    .map_err(denied)?
                    .as_ref()
                    .is_some_and(|c| {
                        c.matches_source_origin(&self.source) && window.matches_closing(c)
                    })
            } else {
                window.matches_source(&self.source)
            };
            if !channel || !window.matches_runtime(&self.runtime) {
                return Err(conflict());
            }
            let bindings = window.bindings();
            self.compare_carrier_binding(r, bindings)?;
            for i in 0..2 {
                let slot = if i == 0 { Slot::A } else { Slot::B };
                let history = window.closed_member(if i == 0 {
                    nelomai_contracts::dispatcher::TunnelSlot::A
                } else {
                    nelomai_contracts::dispatcher::TunnelSlot::B
                });
                if let Some(history) = history {
                    // Stage2 Network/RestoreNetwork always precedes Stop. A
                    // factual closed original never grants one of those effects.
                    let lifecycle = cleanup
                        && r.phase == pair::Phase::Closing
                        && matches!(
                            (r.stop_stage, r.pending),
                            (3, Some(pair::Effect::RestoreWeak))
                                | (6, Some(pair::Effect::CarrierAddressDelete))
                                | (7, Some(pair::Effect::CarrierSessionEnd))
                                | (8, Some(pair::Effect::CarrierClose))
                        );
                    if !lifecycle {
                        if r.pending_guard
                            .as_ref()
                            .is_some_and(|plan| plan.desired.permits)
                        {
                            compare_guard_resource_stage(&self.context, r)?;
                        } else {
                            // Read-only static Base facts. Main's concrete
                            // Guard G separately proves exact closed receipts
                            // and stopped rows for removal; never an Install.
                            compare_static_base_resource_stage(&self.context, r)?;
                        }
                        if r.operation != Some(pair::Operation::Retire(slot)) {
                            return Err(conflict());
                        }
                    }
                    let old = self.selected.try_borrow().map_err(denied)?;
                    if let Some(original) = &old.record.members[i] {
                        if (!lifecycle && old.record.operation != r.operation)
                            || original.owner.intent != history.intent
                            || original.owner.proof != Some(history.proof)
                            || original.owner.phase != crate::member_owner::Phase::Running
                            || original.owner.retired_proof.is_some()
                            || r.members[i].as_ref().is_some_and(|m| m != original)
                        {
                            return Err(conflict());
                        }
                    } else if !lifecycle || r.members[i].is_some() {
                        return Err(conflict());
                    }
                    let provider = history.comparison_provider(&self.context).map_err(denied)?;
                    let egress = bindings.egress[i].as_ref().ok_or_else(conflict)?;
                    if egress.scope != r.scope
                        || egress.proof != history.proof.interface
                        || provider.identity.guid != egress.proof.guid
                        || provider.identity.index != egress.proof.index
                        || provider.identity.luid != egress.proof.luid
                    {
                        return Err(conflict());
                    }
                } else {
                    match (&r.members[i], &bindings.egress[i]) {
                        (None, None) => (),
                        (Some(m), Some(e))
                            if m.owner.proof.is_some_and(|p| p.interface == e.proof)
                                && e.scope == r.scope => {}
                        _ => return Err(conflict()),
                    }
                }
            }
            Ok(())
        }
        fn compare_carrier_binding(
            &self,
            r: &pair::Record,
            b: &crate::windows::member_carrier_guard::Bindings,
        ) -> io::Result<()> {
            let c = b.carrier.as_ref().ok_or_else(conflict)?;
            if b.scope != r.scope
                || Some(c.identity.proof) != r.carrier
                || c.identity.scope != r.scope
                || c.sources != r.addresses.iter().map(|a| a.addr()).collect::<Vec<_>>()
            {
                return Err(conflict());
            }
            Ok(())
        }
        fn compare_bindings(
            &self,
            r: &pair::Record,
            b: &crate::windows::member_carrier_guard::Bindings,
        ) -> io::Result<()> {
            self.compare_carrier_binding(r, b)?;
            for (member, egress) in r.members.iter().zip(&b.egress) {
                match (member, egress) {
                    (None, None) => (),
                    (Some(m), Some(e))
                        if m.owner.proof.is_some_and(|p| p.interface == e.proof)
                            && e.scope == r.scope => {}
                    _ => return Err(conflict()),
                }
            }
            Ok(())
        }
        fn compare_retired_bindings(
            &self,
            record: &pair::Record,
            retired: &RetiredCarrierRead,
            bindings: &crate::windows::member_carrier_guard::Bindings,
        ) -> io::Result<()> {
            self.compare_carrier_binding(record, bindings)?;
            // Lease over the caller's ALREADY ACTIVE actual full-empty bracket,
            // not Retired.inspect, Source, inventory or an old SDK query.
            retired
                .inspect_history_in_bracket(|history| {
                    if history.len() > 2 {
                        return Err(crate::windows::member_carrier_wintun::Error::Conflict);
                    }
                    for i in 0..2 {
                        let slot = if i == 0 {
                            nelomai_contracts::dispatcher::TunnelSlot::A
                        } else {
                            nelomai_contracts::dispatcher::TunnelSlot::B
                        };
                        let entries = history
                            .iter()
                            .filter(|h| h.intent.slot == slot)
                            .collect::<Vec<_>>();
                        match (&record.members[i], &bindings.egress[i], entries.as_slice()) {
                            (None, None, []) => (),
                            (member, Some(identity), [closed]) => {
                                closed.comparison_provider(&self.context).map_err(|_| {
                                    crate::windows::member_carrier_wintun::Error::Conflict
                                })?;
                                if identity.scope != record.scope
                                    || identity.proof != closed.proof.interface
                                    || member.as_ref().is_some_and(|m| {
                                        m.owner.intent != closed.intent
                                            || m.owner.proof.or(m.owner.retired_proof)
                                                != Some(closed.proof)
                                    })
                                {
                                    return Err(
                                        crate::windows::member_carrier_wintun::Error::Conflict,
                                    );
                                }
                            }
                            _ => {
                                return Err(crate::windows::member_carrier_wintun::Error::Conflict)
                            }
                        }
                    }
                    Ok(())
                })
                .map_err(denied)
        }
        fn compare_empty_bindings(
            &self,
            channel: EmptyReadChannel,
            record: &pair::Record,
            retired: &RetiredCarrierRead,
            bindings: &crate::windows::member_carrier_guard::Bindings,
            baseline: &NativeNetworkBaselineRead<A>,
        ) -> io::Result<()> {
            if matches!(channel, EmptyReadChannel::Native) {
                return self.compare_retired_bindings(record, retired, bindings);
            }
            compare_terminal_empty_stage(channel, &self.context, record, baseline.snapshot())?;
            let c = bindings.carrier.as_ref().ok_or_else(conflict)?;
            let original = &baseline.snapshot().interface;
            if bindings.scope != record.scope
                || c.identity.scope != record.scope
                || c.identity.proof.guid != original.guid
                || c.identity.proof.index != original.index
                || c.identity.proof.luid != original.luid
                || c.sources
                    != record
                        .addresses
                        .iter()
                        .map(|a| a.addr())
                        .collect::<Vec<_>>()
            {
                return Err(conflict());
            }
            // Post-RestoreKeys11 and FullEmpty use the terminal registry channel,
            // not a fabricated Closing9/10 or future Pair record. C comes from SAME retained
            // baseline and full-SDK bracket even when Stopped removes Pair.C.
            retired
                .inspect_terminal_history_in_bracket(|history| {
                    if history.len() > 2 {
                        return Err(crate::windows::member_carrier_wintun::Error::Conflict);
                    }
                    for i in 0..2 {
                        let slot = if i == 0 {
                            nelomai_contracts::dispatcher::TunnelSlot::A
                        } else {
                            nelomai_contracts::dispatcher::TunnelSlot::B
                        };
                        let entries = history
                            .iter()
                            .filter(|h| h.intent.slot == slot)
                            .collect::<Vec<_>>();
                        match (&record.members[i], &bindings.egress[i], entries.as_slice()) {
                            (None, None, []) => (),
                            (Some(member), None, [])
                                if record.phase == pair::Phase::Closing
                                    && member.owner.proof.is_none()
                                    && member.owner.retired_proof.is_none()
                                    && member.owner.phase
                                        == crate::member_owner::Phase::Prepared => {}
                            (member, Some(identity), [closed]) => {
                                closed.comparison_provider(&self.context).map_err(|_| {
                                    crate::windows::member_carrier_wintun::Error::Conflict
                                })?;
                                if identity.scope != record.scope
                                    || identity.proof != closed.proof.interface
                                    || member.as_ref().is_some_and(|m| {
                                        m.owner.intent != closed.intent
                                            || m.owner.proof.or(m.owner.retired_proof)
                                                != Some(closed.proof)
                                    })
                                {
                                    return Err(
                                        crate::windows::member_carrier_wintun::Error::Conflict,
                                    );
                                }
                            }
                            _ => {
                                return Err(crate::windows::member_carrier_wintun::Error::Conflict)
                            }
                        }
                    }
                    Ok(())
                })
                .map_err(denied)
        }
        fn capture_physical(
            &self,
            window: &NativeBindingsWindow<'_>,
        ) -> io::Result<PhysicalSnapshot> {
            window
                .inspect(|b| {
                    let owned = std::iter::once(
                        &b.carrier
                            .as_ref()
                            .ok_or(crate::windows::member_carrier_wintun::Error::Conflict)?
                            .identity,
                    )
                    .chain(b.egress.iter().flatten())
                    .map(|id| InterfaceIdentity {
                        index: id.proof.index,
                        luid: id.proof.luid,
                        guid: id.proof.guid,
                    })
                    .collect::<Vec<_>>();
                    crate::windows::member_physical::capture(&owned)
                        .map_err(|_| crate::windows::member_carrier_wintun::Error::Conflict)
                })
                .map_err(denied)
        }
        fn resource_facts(
            &self,
            record: &pair::Record,
            window: &NativeBindingsWindow<'_>,
        ) -> io::Result<(NativeResourceRowsFacts, Vec<InterfaceMetric>)> {
            self.rows
                .inspect_in_window(window, |facts| {
                    let closed = [
                        window.closed_member(nelomai_contracts::dispatcher::TunnelSlot::A),
                        window.closed_member(nelomai_contracts::dispatcher::TunnelSlot::B),
                    ];
                    let values = facts.rows.each_ref().map(|fact| {
                        fact.as_ref()
                            .map(|r| (&r.binding, &r.acknowledged, r.observed.as_ref()))
                    });
                    let metrics = if record.pending == Some(pair::Effect::Guard) {
                        compare_guard_resource_rows(&self.context, record, values, closed)
                    } else if closed.iter().any(Option::is_some) {
                        Err(conflict())
                    } else {
                        compare_sampled_resource_rows(&self.context, record, values, [None, None])
                    }
                    .map_err(|_| crate::windows::member_carrier_wintun::Error::Conflict)?;
                    if closed.iter().any(Option::is_some) {
                        // Actual full native table, both families; not an old NIC
                        // lookup. Stopped receipt/row history never licenses a
                        // remaining target route (including foreign metadata).
                        let table = full_route_table()
                            .map_err(|_| crate::windows::member_carrier_wintun::Error::Conflict)?;
                        if table.iter().any(|row| {
                            closed.iter().flatten().any(|h| {
                                row.route.interface == h.proof.interface.index
                                    || row.luid == h.proof.interface.luid
                            })
                        }) || full_route_table()
                            .map_err(|_| crate::windows::member_carrier_wintun::Error::Conflict)?
                            != table
                        {
                            return Err(crate::windows::member_carrier_wintun::Error::Conflict);
                        }
                    }
                    Ok((facts.clone(), metrics))
                })
                .map_err(denied)
        }
        fn network_facts(
            &self,
            cleanup: bool,
            window: &NativeBindingsWindow<'_>,
        ) -> io::Result<crate::windows::member_carrier_network::native::NativeNetworkFacts>
        {
            let clone =
                |facts: &crate::windows::member_carrier_network::native::NativeNetworkFacts| {
                    // Fact structs are intentionally not Clone capabilities. Move
                    // only their value data through a fresh sibling read callback.
                    let route = |r: &crate::windows::member_carrier_network::RouteFact| {
                        crate::windows::member_carrier_network::RouteFact {
                            expected: r.expected.clone(),
                            actual: r.actual.clone(),
                        }
                    };
                    Ok(
                        crate::windows::member_carrier_network::native::NativeNetworkFacts {
                            routes: crate::windows::member_carrier_network::NetworkFacts {
                                current: facts.routes.current.iter().map(route).collect(),
                                pending: facts
                                    .routes
                                    .pending
                                    .as_ref()
                                    .map(|v| v.iter().map(route).collect()),
                                carrier_rows: facts.routes.carrier_rows.clone(),
                                egress_rows: facts.routes.egress_rows.clone(),
                                active: facts.routes.active,
                                pending_active: facts.routes.pending_active,
                                stopping: facts.routes.stopping,
                            },
                            dns: facts.dns.clone(),
                            protected_record: facts.protected_record.clone(),
                        },
                    )
                };
            if cleanup {
                self.closing_network
                    .try_borrow()
                    .map_err(denied)?
                    .as_ref()
                    .ok_or_else(conflict)?
                    .inspect_in_window(window, clone)
            } else {
                self.live_network.inspect_in_window(window, clone)
            }
        }
        fn row_proof(
            &self,
            window: &NativeBindingsWindow<'_>,
            physical: &PhysicalSnapshot,
            row: &Row,
        ) -> io::Result<NativeProof> {
            let b = window.bindings();
            if b.carrier
                .as_ref()
                .is_some_and(|c| c.identity.proof.index == row.route.interface)
            {
                return Err(conflict());
            }
            if let Some(member) = b
                .egress
                .iter()
                .flatten()
                .find(|m| m.proof.index == row.route.interface)
            {
                return Ok(NativeProof {
                    index: member.proof.index,
                    luid: member.proof.luid,
                });
            }
            let proof = physical
                .proofs()
                .get(&(
                    Family::of(row.route.destination.addr()),
                    row.route.interface,
                ))
                .ok_or_else(conflict)?;
            Ok(NativeProof {
                index: proof.identity.index,
                luid: proof.identity.luid,
            })
        }
        fn ack_pin(&self) -> io::Result<NativeNetworkAckRead<Self>> {
            let root = self.original.upgrade().ok_or_else(conflict)?;
            let retained = self.ack.try_borrow().map_err(denied)?;
            let ack = retained.as_ref().ok_or_else(conflict)?.upgrade()?;
            if !ack.matches_origin(&self.source, &root) {
                return Err(conflict());
            }
            Ok(ack.pin())
        }
        fn clean_physical(
            &self,
            window: &NativeBindingsWindow<'_>,
            physical: &PhysicalSnapshot,
            attempts: &[RouteAttempt],
        ) -> io::Result<PhysicalSnapshot> {
            let member_indices = window
                .bindings()
                .egress
                .iter()
                .flatten()
                .map(|m| m.proof.index)
                .collect::<Vec<_>>();
            let mut retained = BTreeMap::new();
            for attempt in attempts {
                if !member_indices.contains(&attempt.row.route.interface) {
                    retained.insert(key(&attempt.row.route), attempt);
                }
            }
            let own = retained
                .values()
                .filter(|a| a.acknowledged && !a.deleting)
                .map(|a| a.row.clone())
                .collect::<Vec<_>>();
            physical.without_owned_rows(&own).map_err(denied)
        }
        fn authorize_in_window(
            &self,
            cleanup: bool,
            window: &NativeBindingsWindow<'_>,
            effect: &Effect<'_>,
            capture: Option<&mut NativePhysicalPlanCapture<'_>>,
        ) -> io::Result<()> {
            let selected = self.selected.try_borrow().map_err(denied)?;
            self.verify_window(&selected, cleanup, window)?;
            self.verify_pair(&selected, cleanup)?;
            let ack = self.ack_pin()?;
            let (attempts, dns_acks) = ack.acknowledgements()?;
            if capture
                .as_ref()
                .is_some_and(|c| cleanup || !c.matches_original(&ack))
            {
                return Err(conflict());
            }
            let obligations = ack.physical_obligations()?;
            let physical_leases = if capture.is_some() {
                obligations.clone()
            } else {
                ack.physical_leases()?
            };
            if physical_leases.len() > 32768 {
                return Err(conflict());
            }
            // Sequential sibling joins. There is NO owning Pair, Source,
            // joined window or Guard callback around any of these reads.
            let (resources, metrics) = self.resource_facts(&selected.record, window)?;
            let guard = self
                .guard
                .try_borrow_mut()
                .map_err(denied)?
                .snapshot_in_window(window)
                .map_err(denied)?;
            compare_guard(&selected.record, &guard)?;
            let network = self.network_facts(cleanup, window)?;
            let physical = self.capture_physical(window)?;
            let saved = network
                .protected_record
                .as_deref()
                .map(|raw| NativeNetworkRecord::read_comparison(&selected.record.scope, raw))
                .transpose()?;
            ack.verify_physical_record(saved.as_ref().map(|r| r.physical.as_slice()))?;
            if saved.is_none() && !attempts.is_empty() {
                return Err(conflict());
            }
            // Empty journal is a factual absence ONLY. Route effects below
            // require a protected child pending plan, so it grants no writes.
            let empty = NetworkJournal::default();
            let journal = saved.as_ref().map(|r| &r.journal).unwrap_or(&empty);
            compare_journal(&selected.record, journal, cleanup)?;
            compare_route_reads(&selected.record, journal, &attempts, physical.rows())?;
            compare_dns_read(&selected.record, &network.dns, &dns_acks)?;
            for lease in &obligations {
                physical.verify(&physical_route(lease)).map_err(denied)?;
            }
            let clean = self.clean_physical(window, &physical, &attempts)?;
            let mut capture_paths = None;
            if !cleanup {
                let computed = compute_plan(
                    &selected.record,
                    selected_slot(&selected.record)?,
                    &clean,
                    &metrics,
                )?;
                compare_desired(&selected.record, &computed)?;
                if capture.is_some() {
                    capture_paths = Some(computed.physical);
                } else {
                    compare_physical_plan(&computed.physical, &physical_leases)?;
                }
            }
            match effect {
                Effect::Read | Effect::VerifyDnsIntent => (),
                Effect::Plan {
                    slot,
                    values,
                    servers,
                } => {
                    if cleanup
                        || *slot != selected_slot(&selected.record)?
                        || *servers != selected.record.dns
                    {
                        return Err(conflict());
                    }
                    let routes = values
                        .iter()
                        .map(|v| match v {
                            NetworkValue::Route(r) => Ok(r.clone()),
                            _ => Err(conflict()),
                        })
                        .collect::<io::Result<Vec<_>>>()?;
                    let target = &selected
                        .record
                        .network
                        .as_ref()
                        .ok_or_else(conflict)?
                        .pending
                        .as_ref()
                        .ok_or_else(conflict)?
                        .routes;
                    if routes_by_key(&routes)? != routes_by_key(target)? {
                        return Err(conflict());
                    }
                }
                Effect::RouteCreate(row) | Effect::RouteDelete(row) | Effect::RouteSet(row) => {
                    if saved.is_none() {
                        return Err(conflict());
                    }
                    let kind = match effect {
                        Effect::RouteCreate(_) => RouteEffect::Create,
                        Effect::RouteDelete(_) => RouteEffect::Delete,
                        _ => RouteEffect::Set,
                    };
                    compare_route_effect(
                        &selected.record,
                        journal,
                        &attempts,
                        physical.rows(),
                        row,
                        kind,
                        self.row_proof(window, &physical, row)?,
                    )?;
                }
                Effect::Dns { before, desired } => {
                    compare_dns_effect(
                        &selected.record,
                        self.dns_child.try_borrow().map_err(denied)?.as_ref(),
                        before,
                        desired,
                        &network.dns,
                        &dns_acks,
                    )?;
                }
                Effect::PublishNetwork(next) => {
                    compare_journal(&selected.record, next, cleanup)?;
                    compare_route_reads(&selected.record, next, &attempts, physical.rows())?;
                    let (current, pending) = journal_routes(next)?;
                    if pending.is_none() {
                        // A committed list requires actual native ACKs for each
                        // value. Publishing request/target JSON is insufficient.
                        for route in current {
                            let actual = physical
                                .rows()
                                .iter()
                                .find(|row| row.route == route)
                                .ok_or_else(conflict)?;
                            compare_route_ack(&attempts, actual)?;
                        }
                    }
                }
            }
            if let Some(sink) = capture {
                // The ONLY capture entry is exact Plan, never Read/cleanup/
                // route/DNS or a caller-furnished list of physical leases.
                if !matches!(effect, Effect::Plan { .. }) {
                    return Err(conflict());
                }
                let paths = capture_paths.as_ref().ok_or_else(conflict)?;
                let leases = physical_plan_leases(paths)?;
                compare_physical_plan(paths, &leases)?;
                // Same-owner retention BEFORE every fallible postflight. If
                // it fails later, Owner/G sticky fences permit cleanup only.
                sink.retain(selected.record.revision, leases)?;
            }
            // Independent fresh postflight before returning authorization.
            // SDK/child publication follows outside this method; its owner
            // invokes Read again after retaining native ACKs before postflight.
            if self.resource_facts(&selected.record, window)?.0 != resources
                || self.network_facts(cleanup, window)? != network
            {
                return Err(conflict());
            }
            let after = self.capture_physical(window)?;
            if after.rows() != physical.rows() || after.proofs() != physical.proofs() {
                return Err(conflict());
            }
            let after_guard = self
                .guard
                .try_borrow_mut()
                .map_err(denied)?
                .snapshot_in_window(window)
                .map_err(denied)?;
            if after_guard != guard {
                return Err(conflict());
            }
            if ack.acknowledgements()? != (attempts, dns_acks) {
                return Err(conflict());
            }
            self.verify_pair(&selected, cleanup)?;
            self.verify_window(&selected, cleanup, window)
        }
    }
    // SAFETY: exact Wfp specialization, retained SAME original runtime/files,
    // Pair+Network publication ACKs, Calling scope and Source/Closing window;
    // actual row ACK/protected/fullSDK and 49-key Guard reads, no dynamic allows,
    // recomputed complete plan, exact physical paths and actual owner IO ACKs.
    // SDK effects remain in the original NetworkOwner, whose Read postflight
    // reenters this verifier only after storing actual native acknowledgements.
    unsafe impl<A: WindowBindingAttestor> NativeNetworkEffectGate for NativeNetworkGate<A> {
        fn capture_physical_plan(
            &self,
            window: &NativeBindingsWindow<'_>,
            slot: Slot,
            values: &[NetworkValue],
            servers: &[IpAddr],
            capture: &mut NativePhysicalPlanCapture<'_>,
        ) -> io::Result<()> {
            self.fence.run(false, || {
                self.authorize_in_window(
                    false,
                    window,
                    &Effect::Plan {
                        slot,
                        values,
                        servers,
                    },
                    Some(capture),
                )
            })
        }
        fn bind_originals(
            &self,
            source: &Rc<NativeSourceRead>,
            closing: Option<&Rc<NativeClosingRead>>,
            files: &NativeSessionFiles,
        ) -> io::Result<()> {
            let cleanup = closing.is_some();
            self.fence.run(cleanup, || {
                if !Rc::ptr_eq(source, &self.source) {
                    return Err(conflict());
                }
                self.runtime
                    .verify_same_session_files(&self.context, files)
                    .map_err(denied)?;
                if let Some(original) = closing {
                    let mut slot = self.closing.try_borrow_mut().map_err(denied)?;
                    if let Some(old) = slot.as_ref() {
                        if !Rc::ptr_eq(old, original) {
                            return Err(conflict());
                        }
                    } else {
                        *slot = Some(original.clone());
                    }
                    let retained = slot.as_ref().ok_or_else(conflict)?;
                    if !retained.matches_source_origin(&self.source) {
                        return Err(conflict());
                    }
                    if self.closing_network.try_borrow().map_err(denied)?.is_none() {
                        *self.closing_network.try_borrow_mut().map_err(denied)? =
                            Some(self.live_network.closing_read(retained.clone())?);
                    }
                }
                let selected = self.selected.try_borrow().map_err(denied)?;
                if selected.network.is_none() && !cleanup {
                    self.verify_pre_network_pair(&selected)
                } else {
                    self.verify_pair(&selected, cleanup)
                }
            })
        }
        fn authorize(
            &self,
            cleanup: bool,
            window: &NativeBindingsWindow<'_>,
            effect: &Effect<'_>,
        ) -> io::Result<()> {
            self.fence.run(cleanup, || {
                self.authorize_in_window(cleanup, window, effect, None)
            })
        }
        fn network_record(&self, cleanup: bool) -> io::Result<Option<Vec<u8>>> {
            self.fence.run(cleanup, || {
                let selected = self.selected.try_borrow().map_err(denied)?;
                if selected.network.is_none() && !cleanup {
                    // Original Owner::fresh reads protected absence ONLY. No
                    // Source/SDK/effect call and no inferred DNS/restoration.
                    self.verify_pre_network_pair(&selected)?;
                    let bytes = self
                        .runtime
                        .optional_record(&self.context, RecordKind::Network)
                        .map_err(denied)?;
                    if bytes.is_some() {
                        return Err(conflict());
                    }
                    self.verify_pre_network_pair(&selected)?;
                    return Ok(None);
                }
                self.verify_pair(&selected, cleanup)?;
                let bytes = self
                    .runtime
                    .optional_record(&self.context, RecordKind::Network)
                    .map_err(denied)?;
                self.verify_pair(&selected, cleanup)?;
                Ok(bytes)
            })
        }
        fn verify_dns_intent(
            &self,
            cleanup: bool,
            expected: Option<&crate::member_pair::DnsRecord>,
            desired: Option<&crate::member_pair::DnsRecord>,
        ) -> io::Result<()> {
            self.fence.run(cleanup, || {
                let selected = self.selected.try_borrow().map_err(denied)?;
                self.verify_pair(&selected, cleanup)?;
                let ack = self.ack_pin()?;
                let (_, native_dns) = ack.acknowledgements()?;
                let mut child = self.dns_child.try_borrow_mut().map_err(denied)?;
                // Source postflight can fail AFTER the original coverage ACK,
                // leaving DnsStore's expected value one step behind. Retain
                // both exact local states; only Closing may reconcile that
                // mismatch, and the actual NetworkIntent/native SDK ACK still
                // validates every transition below. Equality is never an ACK.
                if child.as_ref() != expected
                    && !(cleanup
                        && self
                            .dns_previous
                            .try_borrow()
                            .map_err(denied)?
                            .as_ref()
                            .is_some_and(|old| old.as_ref() == expected))
                {
                    return Err(conflict());
                }
                selected
                    .network
                    .as_ref()
                    .ok_or_else(conflict)?
                    .dns_transition(cleanup, expected, desired, native_dns.last())?;
                // Retain actual child publication coverage before any later
                // Source postflight can fail. This is not an out-of-band Pair
                // CAS; the whole current record/revision stays unchanged.
                *self.dns_previous.try_borrow_mut().map_err(denied)? = Some(child.clone());
                *child = desired.cloned();
                drop(child);
                self.verify_pair(&selected, cleanup)
            })
        }
    }
    fn compare_physical_plan(paths: &[PhysicalRoute], leases: &[PhysicalLease]) -> io::Result<()> {
        let mut expected = BTreeMap::new();
        let mut actual = BTreeMap::new();
        for path in paths {
            let key = (
                path.proof.family,
                path.proof.identity.index,
                path.row.route.destination,
            );
            if expected.insert(key, path).is_some_and(|old| old != path) {
                return Err(conflict());
            }
        }
        for lease in leases {
            let path = physical_route(lease);
            let key = (
                path.proof.family,
                path.proof.identity.index,
                path.row.route.destination,
            );
            if actual
                .insert(key, path.clone())
                .is_some_and(|old| old != path)
            {
                return Err(conflict());
            }
        }
        if expected.len() != actual.len()
            || expected
                .iter()
                .any(|(key, path)| actual.get(key) != Some(*path))
        {
            return Err(conflict());
        }
        Ok(())
    }
    fn physical_route(lease: &PhysicalLease) -> PhysicalRoute {
        PhysicalRoute {
            proof: crate::member_physical::PhysicalProof {
                identity: InterfaceIdentity {
                    index: lease.interface,
                    luid: lease.luid,
                    guid: lease.guid,
                },
                family: if lease.ipv6 { Family::V6 } else { Family::V4 },
                metric: lease.interface_metric,
            },
            row: Row {
                route: lease.route.clone(),
                luid: lease.luid,
                protocol: lease.protocol,
                origin: lease.origin,
                site_prefix_length: lease.site_prefix_length,
                valid_lifetime: lease.valid_lifetime,
                preferred_lifetime: lease.preferred_lifetime,
                flags: lease.flags,
            },
        }
    }
}

#[cfg(test)]
#[path = "member_carrier_network_gate_tests.rs"]
mod tests;
