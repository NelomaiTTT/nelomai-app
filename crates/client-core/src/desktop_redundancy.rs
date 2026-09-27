//! Pure desktop pair protocol coordinator. Callers own durable writes, fresh
//! helper reads, authentication and asynchronous effects; no I/O lives here.
use crate::{CoreApiError, CoreError};
use nelomai_client_storage::{StoredDesktopRedundancy, StoredDesktopRedundantStop};
use nelomai_client_tunnel::{
    redundancy::{
        protocol::{Command, Member, Snapshot},
        session::SessionPhase,
        SessionScope, Slot,
    },
    DesktopTunnelOptions, TunnelConfiguration,
};
use nelomai_contracts::{
    Connection, LeaseStatus, ProbeResult, RedundancyMemberSlot, RedundancyState,
    RedundantCandidateCommitRequest, RedundantHealthProbe, RedundantRoleAction,
    RedundantRoleRequest, RedundantRoleResponse, RedundantSessionResponse, RedundantSessionState,
    RedundantSessionView, RedundantStandbyAcquireRequest, RedundantStandbyAcquireResponse,
    RuntimeSlot,
};
use std::net::Ipv4Addr;

pub(crate) fn scope(
    pair: &StoredDesktopRedundancy,
    runtime: RuntimeSlot,
) -> Result<SessionScope, CoreError> {
    let scope = SessionScope {
        runtime,
        runtime_generation: pair.runtime_generation,
        session_id: pair.session.session_id.clone(),
        connection_generation: pair.connection_generation,
    };
    if !scope.validate()
        || !uuid(&pair.connection.lease_id)
        || !uuid(&pair.start_operation_id)
        || pair.request_fingerprint.len() != 64
        || !pair
            .request_fingerprint
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || pair
            .connection
            .session_id
            .as_ref()
            .is_some_and(|s| s != &scope.session_id)
        || pair.session.role_generation > i64::MAX as u64
        || pair.session.membership_generation > i64::MAX as u64
    {
        return Err(invalid());
    }
    Ok(scope)
}
pub(crate) fn validate_snapshot(
    pair: &StoredDesktopRedundancy,
    runtime: RuntimeSlot,
    snapshot: &Snapshot,
) -> Result<(), CoreError> {
    sane(snapshot)?;
    if snapshot.session.scope != scope(pair, runtime)?
        || snapshot.session.role_generation != pair.session.role_generation
        || snapshot.session.membership_generation != pair.session.membership_generation
    {
        return Err(invalid());
    }
    let mut known = [
        Some(pair.connection.lease_id.as_str()),
        pair.session
            .standby
            .as_ref()
            .map(|m| m.connection.lease_id.as_str()),
    ];
    let canonical = known;
    if let Some(candidate) = &pair.candidate {
        let i = index(slot(candidate.candidate_slot));
        if snapshot.leases[i].as_deref() == Some(candidate.candidate_lease_id.as_str()) {
            known[i] = Some(candidate.candidate_lease_id.as_str());
        }
    }
    for (i, lease) in snapshot.leases.iter().enumerate() {
        if lease.as_deref().is_some_and(|id| Some(id) != known[i]) {
            return Err(invalid());
        }
    }
    for (i, lease) in snapshot.current_leases.iter().enumerate() {
        if lease.as_deref().is_some_and(|id| {
            Some(id) != canonical[i] && !(snapshot.session.committed[i] && Some(id) == known[i])
        }) {
            return Err(invalid());
        }
    }
    Ok(())
}
pub(crate) fn primary_command(
    pair: &StoredDesktopRedundancy,
    runtime: RuntimeSlot,
    configuration: TunnelConfiguration,
    options: DesktopTunnelOptions,
    probe: RedundantHealthProbe,
) -> Result<Command, CoreError> {
    if pair.stop.is_some()
        || pair.pending_acquire.is_some()
        || pair.candidate.is_some()
        || pair.session.state == RedundancyState::Disabled
    {
        return Err(invalid());
    }
    let primary = member(pair, &pair.connection, Slot::A, configuration, probe)?;
    checked(
        Command::Start {
            scope: scope(pair, runtime)?,
            primary,
            role_generation: pair.session.role_generation,
            membership_generation: pair.session.membership_generation,
            warm_stop_v1: pair.session.warm_stop_v1,
            options,
        },
        runtime,
    )
}
pub(crate) fn attach_command(
    pair: &StoredDesktopRedundancy,
    runtime: RuntimeSlot,
    snapshot: &Snapshot,
) -> Result<Command, CoreError> {
    running(pair, runtime, snapshot)?;
    if snapshot.session.active != Slot::A
        || !snapshot.session.role_confirmed
        || snapshot.leases[1].is_some()
        || pair.pending_acquire.is_some()
        || pair.candidate.is_some()
    {
        return Err(invalid());
    }
    let standby = pair.session.standby.as_ref().ok_or_else(invalid)?;
    let member = member(
        pair,
        &standby.connection,
        Slot::B,
        TunnelConfiguration::new(standby.configuration.clone()),
        standby.health_probe.clone(),
    )?;
    checked(
        Command::Attach {
            scope: snapshot.session.scope.clone(),
            member,
            expected_revision: snapshot.session.local_revision,
            expected_network_epoch: snapshot.session.network_epoch,
            expected_membership_generation: snapshot.session.membership_generation,
            membership_generation: pair.session.membership_generation,
        },
        runtime,
    )
}
pub(crate) fn stage_command(
    pair: &StoredDesktopRedundancy,
    runtime: RuntimeSlot,
    snapshot: &Snapshot,
    candidate: &RedundantStandbyAcquireResponse,
) -> Result<Command, CoreError> {
    running(pair, runtime, snapshot)?;
    validate_candidate(pair, snapshot, candidate)?;
    let candidate_slot = slot(candidate.candidate_slot);
    if snapshot.leases[index(candidate_slot)].is_some() {
        return Err(invalid());
    }
    let member = member(
        pair,
        &candidate.connection,
        candidate_slot,
        TunnelConfiguration::new(candidate.configuration.clone()),
        candidate.health_probe.clone(),
    )?;
    checked(
        Command::StageCandidate {
            scope: snapshot.session.scope.clone(),
            member,
            expected_revision: snapshot.session.local_revision,
            expected_network_epoch: snapshot.session.network_epoch,
            expected_membership_generation: snapshot.session.membership_generation,
        },
        runtime,
    )
}

/// The caller first validates this fresh helper snapshot against protected state.
pub(crate) fn role_request(snapshot: &Snapshot) -> Result<RedundantRoleRequest, CoreError> {
    sane(snapshot)?;
    if snapshot.session.phase != SessionPhase::Running
        || snapshot.session.role_confirmed
        || snapshot.cleanup_pending
    {
        return Err(invalid());
    }
    Ok(RedundantRoleRequest {
        session_id: snapshot.session.scope.session_id.clone(),
        active_lease_id: active(snapshot)?.into(),
        expected_role_generation: snapshot.session.role_generation,
        expected_membership_generation: snapshot.session.membership_generation,
        reason: None,
        observed_at: None,
    })
}
pub(crate) fn confirm_role_command(
    snapshot: &Snapshot,
    response: &RedundantRoleResponse,
) -> Result<Command, CoreError> {
    sane(snapshot)?;
    if snapshot.session.phase != SessionPhase::Running
        || snapshot.cleanup_pending
        || response.local_active_lease_id != active(snapshot)?
    {
        return Err(invalid());
    }
    if response.action == RedundantRoleAction::Rebase {
        if snapshot.session.role_confirmed {
            return Err(invalid());
        }
        validate_role_rebase(
            &snapshot.session.scope.session_id,
            active(snapshot)?,
            &snapshot.current_leases,
            snapshot.session.role_generation,
            snapshot.session.membership_generation,
            response,
        )?;
    } else {
        let role = if snapshot.session.role_confirmed {
            snapshot.session.role_generation
        } else {
            validated_role_generation(snapshot.session.role_generation, response)?
        };
        validate_view(
            snapshot,
            &response.session,
            role,
            snapshot.session.membership_generation,
            false,
        )?;
    }
    checked(
        Command::ConfirmRole {
            scope: snapshot.session.scope.clone(),
            expected_revision: snapshot.session.local_revision,
            expected_network_epoch: snapshot.session.network_epoch,
            response: response.clone(),
        },
        snapshot.session.scope.runtime,
    )
}
pub(crate) fn acquire_request(
    pair: &StoredDesktopRedundancy,
    runtime: RuntimeSlot,
    snapshot: &Snapshot,
    operation: &str,
    probes: Vec<ProbeResult>,
) -> Result<RedundantStandbyAcquireRequest, CoreError> {
    running(pair, runtime, snapshot)?;
    active(snapshot)?;
    if !snapshot.primary_ready
        || !snapshot.session.role_confirmed
        || !pair.session.standby_desired
        || pair.pending_acquire.is_some()
        || pair.candidate.is_some()
        || snapshot.session.active == Slot::A
            && snapshot.current_leases[1].is_none()
            && pair.session.standby.is_some()
        || snapshot.leases[index(snapshot.session.active.other())].is_some()
        || !uuid(operation)
        || probes.len() > 20
        || probes
            .iter()
            .any(|p| p.latency_ms.is_some_and(|n| !n.is_finite() || n < 0.0))
    {
        return Err(invalid());
    }
    Ok(RedundantStandbyAcquireRequest {
        operation_id: operation.into(),
        session_id: pair.session.session_id.clone(),
        expected_role_generation: snapshot.session.role_generation,
        expected_membership_generation: snapshot.session.membership_generation,
        replace_lease_id: snapshot.current_leases[index(snapshot.session.active.other())].clone(),
        probes,
    })
}
pub(crate) fn commit_request(
    pair: &StoredDesktopRedundancy,
    runtime: RuntimeSlot,
    snapshot: &Snapshot,
) -> Result<RedundantCandidateCommitRequest, CoreError> {
    let candidate = ready_candidate(pair, runtime, snapshot)?;
    Ok(RedundantCandidateCommitRequest {
        session_id: pair.session.session_id.clone(),
        candidate_lease_id: candidate.candidate_lease_id.clone(),
        expected_active_lease_id: active(snapshot)?.into(),
        expected_role_generation: snapshot.session.role_generation,
        expected_membership_generation: snapshot.session.membership_generation,
    })
}
pub(crate) fn commit_command(
    pair: &StoredDesktopRedundancy,
    runtime: RuntimeSlot,
    snapshot: &Snapshot,
    response: &RedundantSessionResponse,
) -> Result<Command, CoreError> {
    // This is a receipt of an already committed panel operation, not permission
    // to request a commit or to promote. Health may change during that RPC.
    let candidate = installed_candidate(pair, runtime, snapshot)?;
    let current = snapshot.current_leases[index(slot(candidate.candidate_slot))].as_deref()
        == Some(candidate.candidate_lease_id.as_str());
    let membership = if current {
        snapshot.session.membership_generation
    } else {
        snapshot
            .session
            .membership_generation
            .checked_add(1)
            .ok_or_else(invalid)?
    };
    validate_view(
        snapshot,
        &response.session,
        snapshot.session.role_generation,
        membership,
        true,
    )?;
    checked(
        Command::CommitCandidate {
            scope: snapshot.session.scope.clone(),
            slot: slot(candidate.candidate_slot),
            expected_revision: snapshot.session.local_revision,
            expected_network_epoch: snapshot.session.network_epoch,
            session: response.session.clone(),
        },
        runtime,
    )
}
/// Freeze retention intent, not permission to send a warm Stop. The caller must
/// reconcile an unconfirmed role using this committed map before sending it.
/// WARM needs a pre-cleanup Stopping snapshot. After an unsaved Stop/closed
/// helper, a terminal snapshot permits cold cleanup only; never infer WARM.
pub(crate) fn stop_record(
    pair: &StoredDesktopRedundancy,
    runtime: RuntimeSlot,
    snapshot: &Snapshot,
    operation: &str,
    ordinary: bool,
) -> Result<StoredDesktopRedundantStop, CoreError> {
    validate_snapshot(pair, runtime, snapshot)?;
    if !matches!(
        snapshot.session.phase,
        SessionPhase::Stopping | SessionPhase::Stopped
    ) || snapshot.session.phase == SessionPhase::Stopped && ordinary
        || !uuid(operation)
    {
        return Err(invalid());
    }
    Ok(StoredDesktopRedundantStop {
        operation_id: operation.into(),
        active_lease_id: active(snapshot)?.into(),
        role_generation: snapshot.session.role_generation,
        membership_generation: snapshot.session.membership_generation,
        committed_leases: snapshot.current_leases.clone(),
        retain_active_peer: ordinary && pair.session.warm_stop_v1 && snapshot.warm_stop_v1,
        role_confirmed: snapshot.session.role_confirmed,
    })
}

/// Reconcile the durable pre-cleanup role without consulting a stopped helper.
pub(crate) fn stopped_role_request(
    pair: &StoredDesktopRedundancy,
    stop: &StoredDesktopRedundantStop,
) -> Result<RedundantRoleRequest, CoreError> {
    validate_stopped_record(pair, stop)?;
    Ok(RedundantRoleRequest {
        session_id: pair.session.session_id.clone(),
        active_lease_id: stop.active_lease_id.clone(),
        expected_role_generation: stop.role_generation,
        expected_membership_generation: stop.membership_generation,
        reason: None,
        observed_at: None,
    })
}

/// Returns the acknowledged generation, without mutating retention intent.
/// The caller must durably confirm this role before sending a retaining Stop;
/// no local ConfirmRole command is necessary after native cleanup.
pub(crate) fn validate_stopped_role_response(
    pair: &StoredDesktopRedundancy,
    stop: &StoredDesktopRedundantStop,
    response: &RedundantRoleResponse,
) -> Result<u64, CoreError> {
    validate_stopped_record(pair, stop)?;
    let role = validated_role_generation(stop.role_generation, response)?;
    let view = &response.session;
    if !matches!(
        response.action,
        RedundantRoleAction::Accepted | RedundantRoleAction::Acknowledged
    ) || !matches!(
        view.state,
        RedundantSessionState::Connected | RedundantSessionState::Degraded
    ) || view.session_id != pair.session.session_id
        || response.local_active_lease_id != stop.active_lease_id
        || view.active_lease_id.as_deref() != Some(stop.active_lease_id.as_str())
        || view.slot_a_lease_id != stop.committed_leases[0]
        || view.slot_b_lease_id != stop.committed_leases[1]
        || view.role_generation != role
        || view.membership_generation != stop.membership_generation
    {
        return Err(invalid());
    }
    Ok(role)
}

/// A delayed report for the previous native role may have advanced the panel.
/// Observe only its fenced generation; this is NOT permission to retain/Stop.
pub(crate) fn stopped_role_rebase(
    pair: &StoredDesktopRedundancy,
    stop: &StoredDesktopRedundantStop,
    response: &RedundantRoleResponse,
) -> Result<u64, CoreError> {
    validate_stopped_record(pair, stop)?;
    validate_role_rebase(
        &pair.session.session_id,
        &stop.active_lease_id,
        &stop.committed_leases,
        stop.role_generation,
        stop.membership_generation,
        response,
    )
}

fn validate_role_rebase(
    session_id: &str,
    local_active: &str,
    current: &[Option<String>; 2],
    role: u64,
    membership: u64,
    response: &RedundantRoleResponse,
) -> Result<u64, CoreError> {
    let view = &response.session;
    if response.action != RedundantRoleAction::Rebase
        || response.local_active_lease_id != local_active
        || view.session_id != session_id
        || view.membership_generation != membership
        || role.checked_add(1) != Some(view.role_generation)
        || view.role_generation > i64::MAX as u64
        || view.slot_a_lease_id != current[0]
        || view.slot_b_lease_id != current[1]
        || view.active_lease_id.as_deref() == Some(local_active)
        || !current
            .iter()
            .flatten()
            .any(|id| Some(id) == view.active_lease_id.as_ref())
        || !matches!(
            view.state,
            RedundantSessionState::Connected | RedundantSessionState::Degraded
        )
    {
        return Err(invalid());
    }
    Ok(view.role_generation)
}

fn validated_role_generation(
    expected: u64,
    response: &RedundantRoleResponse,
) -> Result<u64, CoreError> {
    let actual = response.session.role_generation;
    let next = expected.checked_add(1) == Some(actual);
    let valid = match response.action {
        RedundantRoleAction::Accepted => next,
        RedundantRoleAction::Acknowledged => actual == expected || next,
        RedundantRoleAction::Rebase => false,
    };
    if expected > i64::MAX as u64 || actual > i64::MAX as u64 || !valid {
        return Err(invalid());
    }
    Ok(actual)
}

fn validate_stopped_record(
    pair: &StoredDesktopRedundancy,
    stop: &StoredDesktopRedundantStop,
) -> Result<(), CoreError> {
    // The frozen map is authoritative even after cleanup clears installed flags
    // or the original primary metadata no longer describes the active member.
    if pair.stop.as_ref() != Some(stop)
        || stop.role_confirmed
        || !uuid(&pair.session.session_id)
        || !uuid(&stop.operation_id)
        || stop.role_generation > i64::MAX as u64
        || stop.membership_generation > i64::MAX as u64
        || stop.committed_leases.iter().flatten().any(|id| !uuid(id))
        || stop.committed_leases[0].is_some()
            && stop.committed_leases[0] == stop.committed_leases[1]
        || !stop
            .committed_leases
            .iter()
            .flatten()
            .any(|id| id == &stop.active_lease_id)
    {
        return Err(invalid());
    }
    Ok(())
}

fn running(
    pair: &StoredDesktopRedundancy,
    runtime: RuntimeSlot,
    snapshot: &Snapshot,
) -> Result<(), CoreError> {
    validate_snapshot(pair, runtime, snapshot)?;
    if pair.stop.is_some()
        || snapshot.session.phase != SessionPhase::Running
        || snapshot.cleanup_pending
    {
        return Err(invalid());
    }
    Ok(())
}
fn ready_candidate<'a>(
    pair: &'a StoredDesktopRedundancy,
    runtime: RuntimeSlot,
    snapshot: &Snapshot,
) -> Result<&'a RedundantStandbyAcquireResponse, CoreError> {
    let candidate = installed_candidate(pair, runtime, snapshot)?;
    if !snapshot.standby_ready {
        return Err(invalid());
    }
    Ok(candidate)
}
fn installed_candidate<'a>(
    pair: &'a StoredDesktopRedundancy,
    runtime: RuntimeSlot,
    snapshot: &Snapshot,
) -> Result<&'a RedundantStandbyAcquireResponse, CoreError> {
    running(pair, runtime, snapshot)?;
    let candidate = pair.candidate.as_ref().ok_or_else(invalid)?;
    validate_candidate(pair, snapshot, candidate)?;
    let i = index(slot(candidate.candidate_slot));
    if !snapshot.session.installed[i]
        || snapshot.session.committed[i]
        || snapshot.leases[i].as_deref() != Some(candidate.candidate_lease_id.as_str())
    {
        return Err(invalid());
    }
    Ok(candidate)
}
fn validate_candidate(
    pair: &StoredDesktopRedundancy,
    snapshot: &Snapshot,
    candidate: &RedundantStandbyAcquireResponse,
) -> Result<(), CoreError> {
    let request = pair.pending_acquire.as_ref().ok_or_else(invalid)?;
    let inactive = index(snapshot.session.active.other());
    let replaces = snapshot.current_leases[inactive].as_deref();
    if pair.candidate.as_ref() != Some(candidate)
        || !snapshot.session.role_confirmed
        || !pair.session.standby_desired
        || candidate.candidate_lease_id != candidate.connection.lease_id
        || !uuid(&candidate.candidate_lease_id)
        || slot(candidate.candidate_slot) == snapshot.session.active
        || candidate.candidate_lease_id == active(snapshot)?
        || replaces == Some(candidate.candidate_lease_id.as_str()) && !candidate.reused
        || request.session_id != pair.session.session_id
        || !uuid(&request.operation_id)
        || request.expected_role_generation != snapshot.session.role_generation
        || request.expected_membership_generation != snapshot.session.membership_generation
        || request.replace_lease_id.as_deref() != replaces
    {
        return Err(invalid());
    }
    validate_view(
        snapshot,
        &candidate.session,
        snapshot.session.role_generation,
        snapshot.session.membership_generation,
        false,
    )?;
    member(
        pair,
        &candidate.connection,
        slot(candidate.candidate_slot),
        TunnelConfiguration::new(candidate.configuration.clone()),
        candidate.health_probe.clone(),
    )?;
    Ok(())
}
fn validate_view(
    snapshot: &Snapshot,
    view: &RedundantSessionView,
    role: u64,
    membership: u64,
    include_candidate: bool,
) -> Result<(), CoreError> {
    if !matches!(
        view.state,
        RedundantSessionState::Connected | RedundantSessionState::Degraded
    ) || view.session_id != snapshot.session.scope.session_id
        || view.active_lease_id.as_deref() != Some(active(snapshot)?)
        || view.role_generation != role
        || view.membership_generation != membership
        || role > i64::MAX as u64
        || membership > i64::MAX as u64
    {
        return Err(invalid());
    }
    for (i, lease) in [&view.slot_a_lease_id, &view.slot_b_lease_id]
        .into_iter()
        .enumerate()
    {
        let expected = if include_candidate && snapshot.session.installed[i] {
            snapshot.leases[i].as_deref()
        } else {
            snapshot.current_leases[i].as_deref()
        };
        if lease.as_deref() != expected {
            return Err(invalid());
        }
    }
    Ok(())
}
fn sane(snapshot: &Snapshot) -> Result<(), CoreError> {
    let s = &snapshot.session;
    if !s.scope.validate()
        || s.local_revision == 0
        || s.network_epoch == 0
        || s.role_generation > i64::MAX as u64
        || s.membership_generation > i64::MAX as u64
        || snapshot.leases.iter().flatten().any(|id| !uuid(id))
        || snapshot.leases[0].is_some() && snapshot.leases[0] == snapshot.leases[1]
        || snapshot.current_leases.iter().flatten().any(|id| !uuid(id))
        || snapshot.current_leases[0].is_some()
            && snapshot.current_leases[0] == snapshot.current_leases[1]
        || (snapshot.primary_ready || snapshot.standby_ready) && s.phase != SessionPhase::Running
    {
        return Err(invalid());
    }
    for i in 0..2 {
        if s.committed[i] && (!s.installed[i] || snapshot.leases[i] != snapshot.current_leases[i])
            || s.installed[i] && snapshot.leases[i].is_none()
        {
            return Err(invalid());
        }
    }
    if s.phase == SessionPhase::Running
        && (!s.installed[index(s.active)] || !s.committed[index(s.active)])
        || matches!(s.phase, SessionPhase::Starting | SessionPhase::Stopped)
            && s.installed.iter().any(|v| *v)
        || snapshot.standby_ready && !s.installed[index(s.active.other())]
    {
        return Err(invalid());
    }
    active(snapshot)?;
    Ok(())
}
fn active(snapshot: &Snapshot) -> Result<&str, CoreError> {
    snapshot.leases[index(snapshot.session.active)]
        .as_deref()
        .ok_or_else(invalid)
}
fn member(
    pair: &StoredDesktopRedundancy,
    connection: &Connection,
    slot: Slot,
    configuration: TunnelConfiguration,
    health_probe: RedundantHealthProbe,
) -> Result<Member, CoreError> {
    if connection.layer != pair.connection.layer
        || connection.transport_protocol != pair.connection.transport_protocol
        || connection.tic_connection_mode != pair.connection.tic_connection_mode
        || connection.route_mode != pair.connection.route_mode
        || connection.egress_mode != pair.connection.egress_mode
        || connection
            .session_id
            .as_ref()
            .is_some_and(|id| id != &pair.session.session_id)
        || !matches!(
            connection.status,
            LeaseStatus::Issued | LeaseStatus::Connected
        )
    {
        return Err(invalid());
    }
    let member = Member {
        slot,
        lease_id: connection.lease_id.clone(),
        configuration,
        probe: health_probe,
    };
    member.validate().map_err(|_| invalid())?;
    let (address, prefix) = pair
        .session
        .virtual_address_v4
        .split_once('/')
        .ok_or_else(invalid)?;
    let vip: Ipv4Addr = address.parse().map_err(|_| invalid())?;
    if prefix != "32"
        || vip.is_unspecified()
        || vip.is_loopback()
        || vip.is_multicast()
        || vip.is_broadcast()
        || vip.to_string() != address
    {
        return Err(invalid());
    }
    // Configuration is opaque protected input here. Member validates bounds and
    // NULs; the native helper owns the complete WG/AWG parser and address checks.
    Ok(member)
}
fn checked(command: Command, runtime: RuntimeSlot) -> Result<Command, CoreError> {
    command.validate(runtime).map_err(|_| invalid())?;
    Ok(command)
}
fn uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.hyphenated().to_string() == value)
}
fn index(slot: Slot) -> usize {
    match slot {
        Slot::A => 0,
        Slot::B => 1,
    }
}
fn slot(slot: RedundancyMemberSlot) -> Slot {
    match slot {
        RedundancyMemberSlot::A => Slot::A,
        RedundancyMemberSlot::B => Slot::B,
    }
}

fn invalid() -> CoreError {
    CoreError::Api(CoreApiError::Rejected {
        code: "invalid_client_api_response".into(),
        message: "Некорректное состояние резервного подключения.".into(),
        retry_after_seconds: None,
    })
}

#[cfg(test)]
#[path = "desktop_redundancy_tests.rs"]
mod tests;
