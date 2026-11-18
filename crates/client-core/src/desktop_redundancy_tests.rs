use super::*;
use nelomai_contracts::{
    ConnectionStartResponse, RedundancyMemberSlot, RedundantRoleAction, RedundantSessionState,
    RedundantSessionView, TransportProtocol,
};

const A: &str = "20000000-0000-4000-8000-000000000002";
const B: &str = "20000000-0000-4000-8000-000000000003";
const C: &str = "20000000-0000-4000-8000-000000000004";
const OP: &str = "30000000-0000-4000-8000-000000000001";
const RT: RuntimeSlot = RuntimeSlot::Latest;
fn configuration() -> TunnelConfiguration {
    TunnelConfiguration::new("[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=\nAddress = 10.200.0.2/32\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI=\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n".into())
}
fn fixture() -> ConnectionStartResponse {
    serde_json::from_str(include_str!(
        "../../../contracts/fixtures/valid/connection-start-redundant-response.json"
    ))
    .unwrap()
}
fn pair() -> StoredDesktopRedundancy {
    let mut response = fixture();
    response.connection.transport_protocol = TransportProtocol::Wireguard;
    let mut session = response.redundancy.unwrap();
    session.warm_stop_v1 = true;
    let standby = session.standby.as_mut().unwrap();
    standby.connection.transport_protocol = TransportProtocol::Wireguard;
    standby.configuration = configuration().expose().into();
    StoredDesktopRedundancy {
        primary_reported: true,
        runtime_generation: 7,
        connection_generation: 9,
        start_operation_id: OP.into(),
        request_fingerprint: "ab".repeat(32),
        connection: response.connection,
        session,
        pending_acquire: None,
        candidate: None,
        stop: None,
    }
}
fn primary_snapshot(pair: &StoredDesktopRedundancy) -> Snapshot {
    Snapshot {
        session: nelomai_client_tunnel::redundancy::session::SessionSnapshot {
            scope: SessionScope {
                runtime: RT,
                runtime_generation: 7,
                connection_generation: 9,
                session_id: pair.session.session_id.clone(),
            },
            phase: SessionPhase::Running,
            active: Slot::A,
            installed: [true, false],
            committed: [true, false],
            network_epoch: 4,
            local_revision: 8,
            role_generation: 0,
            membership_generation: 0,
            role_confirmed: true,
        },
        leases: [Some(A.into()), None],
        current_leases: [Some(A.into()), None],
        standby_failed: false,
        stalled: false,
        primary_ready: true,
        standby_ready: false,
        cleanup_pending: false,
        retirement_pending: false,
        warm_stop_v1: true,
    }
}
fn both(pair: &StoredDesktopRedundancy) -> Snapshot {
    let mut snapshot = primary_snapshot(pair);
    snapshot.leases[1] = Some(B.into());
    snapshot.current_leases[1] = Some(B.into());
    snapshot.session.installed[1] = true;
    snapshot.session.committed[1] = true;
    snapshot.standby_ready = true;
    snapshot
}
fn view(snapshot: &Snapshot) -> RedundantSessionView {
    RedundantSessionView {
        session_id: snapshot.session.scope.session_id.clone(),
        state: RedundantSessionState::Connected,
        active_lease_id: snapshot.leases[if snapshot.session.active == Slot::A {
            0
        } else {
            1
        }]
        .clone(),
        slot_a_lease_id: snapshot.current_leases[0].clone(),
        slot_b_lease_id: snapshot.current_leases[1].clone(),
        standby_desired: true,
        role_generation: snapshot.session.role_generation,
        membership_generation: snapshot.session.membership_generation,
        reason: None,
    }
}
fn candidate(
    pair: &StoredDesktopRedundancy,
    snapshot: &Snapshot,
) -> RedundantStandbyAcquireResponse {
    let response = fixture();
    let mut connection = pair.connection.clone();
    connection.lease_id = C.into();
    RedundantStandbyAcquireResponse {
        api_version: response.api_version,
        request_id: "candidate".into(),
        session: view(snapshot),
        candidate_lease_id: C.into(),
        candidate_slot: RedundancyMemberSlot::B,
        connection,
        configuration: configuration().expose().into(),
        health_probe: response.health_probe.unwrap(),
        reused: false,
    }
}
fn stage_fixture() -> (StoredDesktopRedundancy, Snapshot) {
    let mut pair = pair();
    pair.session.standby = None;
    let snapshot = primary_snapshot(&pair);
    pair.pending_acquire = Some(RedundantStandbyAcquireRequest {
        operation_id: OP.into(),
        session_id: pair.session.session_id.clone(),
        expected_role_generation: 0,
        expected_membership_generation: 0,
        replace_lease_id: None,
        probes: vec![],
    });
    pair.candidate = Some(candidate(&pair, &snapshot));
    (pair, snapshot)
}

#[test]
fn primary_and_current_initial_b_commands_use_exact_owner_and_fresh_fences() {
    let pair = pair();
    let snap = primary_snapshot(&pair);
    validate_snapshot(&pair, RT, &snap).unwrap();
    let command = primary_command(
        &pair,
        RT,
        configuration(),
        DesktopTunnelOptions::default(),
        fixture().health_probe.unwrap(),
    )
    .unwrap();
    assert!(
        matches!(command,Command::Start{scope,primary:Member{slot:Slot::A,lease_id,..},warm_stop_v1:true,..} if scope==snap.session.scope && lease_id==A)
    );
    let command = attach_command(&pair, RT, &snap).unwrap();
    assert!(
        matches!(command,Command::Attach{member:Member{slot:Slot::B,lease_id,..},expected_revision:8,expected_network_epoch:4,expected_membership_generation:0,membership_generation:0,..} if lease_id==B)
    );
    assert!(acquire_request(&pair, RT, &snap, OP, vec![]).is_err());
    assert!(attach_command(&pair, RT, &both(&pair)).is_err());
}

#[test]
fn scope_and_snapshot_reject_changed_runtime_generation_owner_and_impossible_state() {
    let pair = pair();
    let good = both(&pair);
    validate_snapshot(&pair, RT, &good).unwrap();
    for mutate in [
        |s: &mut Snapshot| s.session.scope.runtime = RuntimeSlot::Stable,
        |s: &mut Snapshot| s.session.scope.runtime_generation += 1,
        |s: &mut Snapshot| s.session.scope.connection_generation += 1,
        |s: &mut Snapshot| s.session.scope.session_id = C.into(),
        |s: &mut Snapshot| s.leases[0] = Some(C.into()),
        |s: &mut Snapshot| s.leases.swap(0, 1),
        |s: &mut Snapshot| s.session.network_epoch = 0,
        |s: &mut Snapshot| s.session.local_revision = 0,
        |s: &mut Snapshot| s.session.role_generation += 1,
        |s: &mut Snapshot| s.session.membership_generation += 1,
        |s: &mut Snapshot| s.session.installed[0] = false,
        |s: &mut Snapshot| s.session.phase = SessionPhase::Stopped,
    ] {
        let mut snap = good.clone();
        mutate(&mut snap);
        assert!(validate_snapshot(&pair, RT, &snap).is_err());
    }
    let mut invalid_pair = pair.clone();
    invalid_pair.runtime_generation = 0;
    assert!(scope(&invalid_pair, RT).is_err());
}

#[test]
fn promotion_b_role_ack_uses_b_and_rejects_rebase_wrong_maps_or_generations() {
    let pair = pair();
    let mut snap = both(&pair);
    snap.session.active = Slot::B;
    snap.session.role_confirmed = false;
    validate_snapshot(&pair, RT, &snap).unwrap();
    let request = role_request(&snap).unwrap();
    assert_eq!(request.active_lease_id, B);
    assert_eq!(request.expected_role_generation, 0);
    let mut session = view(&snap);
    session.role_generation = 1;
    let response = RedundantRoleResponse {
        api_version: fixture().api_version,
        request_id: "role".into(),
        action: RedundantRoleAction::Accepted,
        local_active_lease_id: B.into(),
        session,
    };
    assert!(matches!(
        confirm_role_command(&snap, &response).unwrap(),
        Command::ConfirmRole {
            expected_revision: 8,
            expected_network_epoch: 4,
            ..
        }
    ));
    for mutate in [
        |r: &mut RedundantRoleResponse| r.action = RedundantRoleAction::Rebase,
        |r: &mut RedundantRoleResponse| r.local_active_lease_id = A.into(),
        |r: &mut RedundantRoleResponse| r.session.active_lease_id = Some(A.into()),
        |r: &mut RedundantRoleResponse| r.session.slot_b_lease_id = Some(C.into()),
        |r: &mut RedundantRoleResponse| r.session.session_id = C.into(),
        |r: &mut RedundantRoleResponse| r.session.role_generation = 0,
        |r: &mut RedundantRoleResponse| r.session.membership_generation = 1,
    ] {
        let mut bad = response.clone();
        mutate(&mut bad);
        assert!(confirm_role_command(&snap, &bad).is_err());
    }
    snap.session.role_confirmed = true;
    assert!(role_request(&snap).is_err());
}

#[test]
fn acquire_requires_ready_confirmed_primary_desire_no_current_or_pending_member() {
    let mut pair = pair();
    pair.session.standby = None;
    let snap = primary_snapshot(&pair);
    let request = acquire_request(&pair, RT, &snap, OP, vec![]).unwrap();
    assert_eq!(request.operation_id, OP);
    assert_eq!(request.expected_role_generation, 0);
    assert!(request.replace_lease_id.is_none());
    for mutate in [
        |s: &mut Snapshot| s.primary_ready = false,
        |s: &mut Snapshot| s.session.role_confirmed = false,
        |s: &mut Snapshot| s.cleanup_pending = true,
    ] {
        let mut bad = snap.clone();
        mutate(&mut bad);
        assert!(acquire_request(&pair, RT, &bad, OP, vec![]).is_err());
    }
    pair.session.standby_desired = false;
    assert!(acquire_request(&pair, RT, &snap, OP, vec![]).is_err());
    pair.session.standby_desired = true;
    pair.pending_acquire = Some(request);
    assert!(acquire_request(&pair, RT, &snap, OP, vec![]).is_err());
}

#[test]
fn promoted_b_can_acquire_and_stage_replacement_in_empty_a_without_relabeling_original_leases() {
    let mut pair = pair();
    pair.session.role_generation = 1;
    let mut snapshot = both(&pair);
    snapshot.session.role_generation = 1;
    snapshot.session.active = Slot::B;
    snapshot.leases[0] = None;
    snapshot.session.installed[0] = false;
    snapshot.session.committed[0] = false;
    snapshot.standby_ready = false;
    pair.pending_acquire = Some(acquire_request(&pair, RT, &snapshot, OP, vec![]).unwrap());
    let mut acquired = candidate(&pair, &snapshot);
    acquired.candidate_slot = RedundancyMemberSlot::A;
    pair.candidate = Some(acquired.clone());
    let command = stage_command(&pair, RT, &snapshot, &acquired).unwrap();
    assert!(
        matches!(command,Command::StageCandidate{member:Member{slot:Slot::A,lease_id,..},..} if lease_id==C)
    );
    snapshot.leases[0] = Some(C.into());
    snapshot.session.installed[0] = true;
    snapshot.standby_ready = true;
    let commit = commit_request(&pair, RT, &snapshot).unwrap();
    assert_eq!(commit.candidate_lease_id, C);
    assert_eq!(commit.expected_active_lease_id, B);
}

#[test]
fn candidate_stage_then_ready_commit_uses_current_generation_plus_one() {
    let (pair, mut snap) = stage_fixture();
    let candidate = pair.candidate.as_ref().unwrap();
    assert!(
        matches!(stage_command(&pair,RT,&snap,candidate).unwrap(),Command::StageCandidate{member:Member{slot:Slot::B,lease_id,..},expected_revision:8,expected_network_epoch:4,expected_membership_generation:0,..} if lease_id==C)
    );
    snap.leases[1] = Some(C.into());
    snap.session.installed[1] = true;
    assert!(commit_request(&pair, RT, &snap).is_err());
    snap.standby_ready = true;
    snap.session.local_revision = 9;
    let request = commit_request(&pair, RT, &snap).unwrap();
    assert_eq!(request.candidate_lease_id, C);
    assert_eq!(request.expected_active_lease_id, A);
    let mut session = view(&snap);
    session.slot_b_lease_id = Some(C.into());
    session.membership_generation = 1;
    let response = RedundantSessionResponse {
        api_version: fixture().api_version,
        request_id: "commit".into(),
        session,
    };
    assert!(matches!(
        commit_command(&pair, RT, &snap, &response).unwrap(),
        Command::CommitCandidate {
            slot: Slot::B,
            expected_revision: 9,
            expected_network_epoch: 4,
            ..
        }
    ));
    for mutate in [
        |r: &mut RedundantSessionResponse| r.session.membership_generation = 0,
        |r: &mut RedundantSessionResponse| r.session.role_generation = 1,
        |r: &mut RedundantSessionResponse| r.session.slot_b_lease_id = Some(B.into()),
        |r: &mut RedundantSessionResponse| r.session.active_lease_id = Some(C.into()),
    ] {
        let mut bad = response.clone();
        mutate(&mut bad);
        assert!(commit_command(&pair, RT, &snap, &bad).is_err());
    }
    snap.session.committed[1] = true;
    assert!(commit_request(&pair, RT, &snap).is_err());
}

#[test]
fn stage_rejects_stale_response_owner_active_generations_transport_and_virtual_address() {
    let (pair, snap) = stage_fixture();
    let candidate = pair.candidate.as_ref().unwrap();
    stage_command(&pair, RT, &snap, candidate).unwrap();
    for mutate in [
        |c: &mut RedundantStandbyAcquireResponse| c.session.session_id = C.into(),
        |c: &mut RedundantStandbyAcquireResponse| c.session.active_lease_id = Some(B.into()),
        |c: &mut RedundantStandbyAcquireResponse| c.session.role_generation = 1,
        |c: &mut RedundantStandbyAcquireResponse| c.session.membership_generation = 1,
        |c: &mut RedundantStandbyAcquireResponse| c.session.slot_b_lease_id = Some(C.into()),
        |c: &mut RedundantStandbyAcquireResponse| c.candidate_slot = RedundancyMemberSlot::A,
        |c: &mut RedundantStandbyAcquireResponse| c.connection.lease_id = A.into(),
        |c: &mut RedundantStandbyAcquireResponse| {
            c.connection.layer = nelomai_contracts::Layer::Tic
        },
        |c: &mut RedundantStandbyAcquireResponse| {
            c.connection.transport_protocol = TransportProtocol::Amneziawg3
        },
        |c: &mut RedundantStandbyAcquireResponse| {
            c.configuration = "SECRET_INVALID_CONFIG\0".into()
        },
    ] {
        let mut bad = pair.clone();
        mutate(bad.candidate.as_mut().unwrap());
        let error = stage_command(&bad, RT, &snap, bad.candidate.as_ref().unwrap()).unwrap_err();
        assert!(!error.to_string().contains("SECRET"));
    }
}

#[test]
fn core_defers_configuration_parser_to_helper_but_validates_advertised_contract_and_numeric_vip() {
    let mut pair = pair();
    pair.connection.transport_protocol = TransportProtocol::Amneziawg3;
    primary_command(
        &pair,
        RT,
        TunnelConfiguration::new(fixture().configuration),
        DesktopTunnelOptions::default(),
        fixture().health_probe.unwrap(),
    )
    .unwrap();
    let (mut pair, snapshot) = stage_fixture();
    pair.candidate.as_mut().unwrap().configuration = "synthetic payload for native parser".into();
    stage_command(&pair, RT, &snapshot, pair.candidate.as_ref().unwrap()).unwrap();
    for vip in ["host.example/32", "0.0.0.0/32", "10.200.0.2/24", "::1/128"] {
        pair.session.virtual_address_v4 = vip.into();
        assert!(stage_command(&pair, RT, &snapshot, pair.candidate.as_ref().unwrap()).is_err());
    }
}

#[test]
fn frozen_stop_preserves_b_warm_intent_and_unconfirmed_role_with_exact_committed_map() {
    let pair = pair();
    let mut snap = both(&pair);
    snap.session.active = Slot::B;
    snap.session.phase = SessionPhase::Stopping;
    snap.primary_ready = false;
    snap.standby_ready = false;
    let stop = stop_record(&pair, RT, &snap, OP, true).unwrap();
    assert_eq!(stop.active_lease_id, B);
    assert_eq!(stop.committed_leases, [Some(A.into()), Some(B.into())]);
    assert!(stop.retain_active_peer);
    assert!(
        !stop_record(&pair, RT, &snap, OP, false)
            .unwrap()
            .retain_active_peer
    );
    snap.session.role_confirmed = false;
    let stop = stop_record(&pair, RT, &snap, OP, true).unwrap();
    assert!(stop.retain_active_peer);
    assert!(!stop.role_confirmed);
    assert_eq!(stop.active_lease_id, B);
    assert_eq!(stop.role_generation, snap.session.role_generation);
    assert_eq!(
        stop.membership_generation,
        snap.session.membership_generation
    );
    assert_eq!(stop.committed_leases, [Some(A.into()), Some(B.into())]);
    snap.session.phase = SessionPhase::Stopped;
    snap.session.installed = [false; 2];
    snap.session.committed = [false; 2];
    assert!(
        !stop_record(&pair, RT, &snap, OP, false)
            .unwrap()
            .retain_active_peer
    );
    assert!(stop_record(&pair, RT, &snap, OP, true).is_err());
    snap.leases[1] = None;
    assert!(stop_record(&pair, RT, &snap, OP, true).is_err());
    assert!(stop_record(&pair, RT, &both(&pair), OP, true).is_err());
}

#[test]
fn frozen_stop_does_not_include_uncommitted_candidate_in_role_map() {
    let (pair, mut snap) = stage_fixture();
    snap.session.phase = SessionPhase::Stopping;
    snap.primary_ready = false;
    snap.leases[1] = Some(C.into());
    snap.session.installed[1] = true;
    let stop = stop_record(&pair, RT, &snap, OP, false).unwrap();
    assert_eq!(stop.committed_leases, [Some(A.into()), None]);
    assert!(!stop.retain_active_peer);
}

#[test]
fn retired_inactive_keeps_server_map_for_replacement_and_stop() {
    for active_slot in [Slot::A, Slot::B] {
        let mut pair = pair();
        let mut snap = both(&pair);
        snap.session.active = active_slot;
        let inactive = index(active_slot.other());
        snap.leases[inactive] = None;
        snap.session.installed[inactive] = false;
        snap.session.committed[inactive] = false;
        snap.standby_ready = false;
        let request = acquire_request(&pair, RT, &snap, OP, vec![]).unwrap();
        assert_eq!(request.replace_lease_id, snap.current_leases[inactive]);
        pair.pending_acquire = Some(request);
        let mut acquired = candidate(&pair, &snap);
        acquired.candidate_slot = if inactive == 0 {
            RedundancyMemberSlot::A
        } else {
            RedundancyMemberSlot::B
        };
        pair.candidate = Some(acquired.clone());
        stage_command(&pair, RT, &snap, &acquired).unwrap();
        snap.leases[inactive] = Some(C.into());
        snap.session.installed[inactive] = true;
        snap.primary_ready = false;
        snap.session.phase = SessionPhase::Stopping;
        assert_eq!(
            stop_record(&pair, RT, &snap, OP, true)
                .unwrap()
                .committed_leases,
            [Some(A.into()), Some(B.into())]
        );
    }
}

#[test]
fn reused_current_candidate_requires_same_exact_inactive_identity_and_generation() {
    let mut pair = pair();
    let mut snap = both(&pair);
    snap.leases[1] = None;
    snap.session.installed[1] = false;
    snap.session.committed[1] = false;
    snap.standby_ready = false;
    pair.pending_acquire = Some(acquire_request(&pair, RT, &snap, OP, vec![]).unwrap());
    let mut acquired = candidate(&pair, &snap);
    acquired.reused = true;
    acquired.candidate_lease_id = B.into();
    acquired.connection.lease_id = B.into();
    pair.candidate = Some(acquired.clone());
    stage_command(&pair, RT, &snap, &acquired).unwrap();
    snap.leases[1] = Some(B.into());
    snap.session.installed[1] = true;
    snap.standby_ready = true;
    let response = RedundantSessionResponse {
        api_version: fixture().api_version,
        request_id: "reused".into(),
        session: view(&snap),
    };
    commit_command(&pair, RT, &snap, &response).unwrap();
    let mut bad = response.clone();
    bad.session.membership_generation += 1;
    assert!(commit_command(&pair, RT, &snap, &bad).is_err());
    pair.candidate.as_mut().unwrap().reused = false;
    assert!(commit_command(&pair, RT, &snap, &response).is_err());
}

#[test]
fn delayed_previous_role_can_rebase_frozen_stop_without_confirming_or_changing_active() {
    let mut pair = pair();
    let mut snap = both(&pair);
    snap.session.phase = SessionPhase::Stopping;
    snap.primary_ready = false;
    snap.standby_ready = false;
    snap.session.role_confirmed = false;
    let stop = stop_record(&pair, RT, &snap, OP, true).unwrap();
    pair.stop = Some(stop.clone());
    let mut response = RedundantRoleResponse {
        api_version: fixture().api_version,
        request_id: "late-b".into(),
        action: RedundantRoleAction::Rebase,
        local_active_lease_id: A.into(),
        session: view(&snap),
    };
    response.session.active_lease_id = Some(B.into());
    response.session.role_generation = 1;
    assert!(validate_stopped_role_response(&pair, &stop, &response).is_err());
    assert_eq!(stopped_role_rebase(&pair, &stop, &response).unwrap(), 1);
    snap.session.phase = SessionPhase::Running;
    snap.primary_ready = true;
    assert!(matches!(
        confirm_role_command(&snap, &response).unwrap(),
        Command::ConfirmRole { .. }
    ));
    for mutate in [
        |r: &mut RedundantRoleResponse| r.session.active_lease_id = Some(A.into()),
        |r: &mut RedundantRoleResponse| r.session.slot_b_lease_id = Some(C.into()),
        |r: &mut RedundantRoleResponse| r.session.membership_generation = 1,
        |r: &mut RedundantRoleResponse| r.session.role_generation = 0,
        |r: &mut RedundantRoleResponse| r.session.role_generation = 2,
        |r: &mut RedundantRoleResponse| r.local_active_lease_id = B.into(),
    ] {
        let mut bad = response.clone();
        mutate(&mut bad);
        assert!(stopped_role_rebase(&pair, &stop, &bad).is_err());
    }
}

#[test]
fn missing_warm_negotiation_still_allows_exact_cold_cleanup() {
    let mut pair = pair();
    let mut snapshot = both(&pair);
    snapshot.session.phase = SessionPhase::Stopping;
    snapshot.primary_ready = false;
    snapshot.standby_ready = false;
    snapshot.warm_stop_v1 = false;
    assert!(
        !stop_record(&pair, RT, &snapshot, OP, true)
            .unwrap()
            .retain_active_peer
    );
    pair.session.warm_stop_v1 = false;
    snapshot.warm_stop_v1 = true;
    assert!(
        !stop_record(&pair, RT, &snapshot, OP, true)
            .unwrap()
            .retain_active_peer
    );
}

fn frozen_unconfirmed_pair() -> (
    StoredDesktopRedundancy,
    StoredDesktopRedundantStop,
    RedundantRoleResponse,
) {
    let mut pair = pair();
    let stop = StoredDesktopRedundantStop {
        background_cleanup: false,
        operation_id: OP.into(),
        active_lease_id: B.into(),
        role_generation: 0,
        membership_generation: 0,
        committed_leases: [Some(A.into()), Some(B.into())],
        retain_active_peer: true,
        role_confirmed: false,
    };
    pair.stop = Some(stop.clone());
    let response = RedundantRoleResponse {
        api_version: fixture().api_version,
        request_id: "stopped-role".into(),
        action: RedundantRoleAction::Accepted,
        local_active_lease_id: B.into(),
        session: RedundantSessionView {
            session_id: pair.session.session_id.clone(),
            state: RedundantSessionState::Connected,
            active_lease_id: Some(B.into()),
            slot_a_lease_id: Some(A.into()),
            slot_b_lease_id: Some(B.into()),
            standby_desired: true,
            role_generation: 1,
            membership_generation: 0,
            reason: None,
        },
    };
    (pair, stop, response)
}

#[test]
fn stopped_role_reconciles_last_active_b_and_lost_ack_without_changing_frozen_intent() {
    let (pair, stop, mut response) = frozen_unconfirmed_pair();
    let request = stopped_role_request(&pair, &stop).unwrap();
    assert_eq!(request.session_id, pair.session.session_id);
    assert_eq!(request.active_lease_id, B);
    assert_eq!(request.expected_role_generation, 0);
    assert_eq!(request.expected_membership_generation, 0);
    assert_eq!(request.reason, None);
    assert_eq!(request.observed_at, None);
    assert_eq!(
        validate_stopped_role_response(&pair, &stop, &response).unwrap(),
        1
    );
    response.action = RedundantRoleAction::Acknowledged;
    response.session.state = RedundantSessionState::Degraded;
    assert_eq!(
        validate_stopped_role_response(&pair, &stop, &response).unwrap(),
        1
    );
    assert_eq!(pair.stop.as_ref(), Some(&stop));
    assert!(stop.retain_active_peer);
    assert!(!stop.role_confirmed);
}

#[test]
fn stopped_role_rejects_wrong_identity_maps_membership_stale_role_and_rebase() {
    let (pair, stop, response) = frozen_unconfirmed_pair();
    assert_eq!(
        validate_stopped_role_response(&pair, &stop, &response).unwrap(),
        1
    );
    for mutate in [
        |r: &mut RedundantRoleResponse| r.session.session_id = C.into(),
        |r: &mut RedundantRoleResponse| r.local_active_lease_id = A.into(),
        |r: &mut RedundantRoleResponse| r.session.active_lease_id = Some(A.into()),
        |r: &mut RedundantRoleResponse| r.session.slot_a_lease_id = Some(C.into()),
        |r: &mut RedundantRoleResponse| r.session.slot_b_lease_id = None,
        |r: &mut RedundantRoleResponse| r.session.membership_generation = 1,
        |r: &mut RedundantRoleResponse| r.session.role_generation = 0,
        |r: &mut RedundantRoleResponse| r.session.role_generation = 2,
        |r: &mut RedundantRoleResponse| r.action = RedundantRoleAction::Rebase,
        |r: &mut RedundantRoleResponse| r.session.state = RedundantSessionState::Allocating,
        |r: &mut RedundantRoleResponse| r.session.state = RedundantSessionState::Stopping,
        |r: &mut RedundantRoleResponse| r.session.state = RedundantSessionState::Stopped,
        |r: &mut RedundantRoleResponse| r.session.state = RedundantSessionState::Failed,
    ] {
        let mut bad = response.clone();
        mutate(&mut bad);
        bad.session.reason = Some("SECRET_SERVER_DETAIL".into());
        let error = validate_stopped_role_response(&pair, &stop, &bad).unwrap_err();
        assert!(!error.to_string().contains("SECRET"));
    }
}

#[test]
fn stopped_role_requires_current_durable_unconfirmed_record_and_valid_frozen_map() {
    let (pair, stop, response) = frozen_unconfirmed_pair();
    assert!(stopped_role_request(&pair, &stop).is_ok());
    let mut absent = pair.clone();
    absent.stop = None;
    assert!(stopped_role_request(&absent, &stop).is_err());
    assert!(validate_stopped_role_response(&absent, &stop, &response).is_err());
    let mut stale = stop.clone();
    stale.operation_id = C.into();
    assert!(stopped_role_request(&pair, &stale).is_err());
    for mutate in [
        |s: &mut StoredDesktopRedundantStop| s.role_confirmed = true,
        |s: &mut StoredDesktopRedundantStop| s.active_lease_id = C.into(),
        |s: &mut StoredDesktopRedundantStop| s.committed_leases[1] = None,
        |s: &mut StoredDesktopRedundantStop| s.committed_leases[0] = Some(B.into()),
        |s: &mut StoredDesktopRedundantStop| s.committed_leases[0] = Some("invalid".into()),
        |s: &mut StoredDesktopRedundantStop| s.operation_id = "invalid".into(),
    ] {
        let mut bad_stop = stop.clone();
        mutate(&mut bad_stop);
        let mut bad_pair = pair.clone();
        bad_pair.stop = Some(bad_stop.clone());
        assert!(stopped_role_request(&bad_pair, &bad_stop).is_err());
        assert!(validate_stopped_role_response(&bad_pair, &bad_stop, &response).is_err());
    }
}

#[test]
fn stopped_role_rejects_overflow_and_accepts_last_representable_generation() {
    let (mut pair, mut stop, mut response) = frozen_unconfirmed_pair();
    stop.role_generation = i64::MAX as u64 - 1;
    stop.membership_generation = i64::MAX as u64;
    pair.stop = Some(stop.clone());
    response.session.role_generation = i64::MAX as u64;
    response.session.membership_generation = i64::MAX as u64;
    assert!(stopped_role_request(&pair, &stop).is_ok());
    assert_eq!(
        validate_stopped_role_response(&pair, &stop, &response).unwrap(),
        i64::MAX as u64
    );
    stop.role_generation = i64::MAX as u64;
    pair.stop = Some(stop.clone());
    assert!(stopped_role_request(&pair, &stop).is_ok());
    assert!(validate_stopped_role_response(&pair, &stop, &response).is_err());
    response.action = RedundantRoleAction::Acknowledged;
    assert_eq!(
        validate_stopped_role_response(&pair, &stop, &response).unwrap(),
        i64::MAX as u64
    );
    for generation in [i64::MAX as u64 + 1, u64::MAX] {
        stop.role_generation = generation;
        pair.stop = Some(stop.clone());
        assert!(stopped_role_request(&pair, &stop).is_err());
        assert!(validate_stopped_role_response(&pair, &stop, &response).is_err());
    }
    stop.role_generation = 0;
    stop.membership_generation = i64::MAX as u64 + 1;
    pair.stop = Some(stop.clone());
    assert!(stopped_role_request(&pair, &stop).is_err());
}

#[test]
fn canonical_role_ack_same_generation_is_action_fenced_for_running_and_stopped() {
    let pair = pair();
    let mut snapshot = both(&pair);
    snapshot.session.role_generation = 4;
    snapshot.session.role_confirmed = false;
    let mut response = RedundantRoleResponse {
        api_version: fixture().api_version,
        request_id: "canonical-a".into(),
        action: RedundantRoleAction::Acknowledged,
        local_active_lease_id: A.into(),
        session: view(&snapshot),
    };
    assert!(confirm_role_command(&snapshot, &response).is_ok());
    let mut frozen = pair.clone();
    let stop = StoredDesktopRedundantStop {
        background_cleanup: false,
        operation_id: OP.into(),
        active_lease_id: A.into(),
        role_generation: 4,
        membership_generation: 0,
        committed_leases: [Some(A.into()), Some(B.into())],
        retain_active_peer: true,
        role_confirmed: false,
    };
    frozen.stop = Some(stop.clone());
    assert_eq!(
        validate_stopped_role_response(&frozen, &stop, &response).unwrap(),
        4
    );
    for mutate in [
        |r: &mut RedundantRoleResponse| r.action = RedundantRoleAction::Accepted,
        |r: &mut RedundantRoleResponse| r.action = RedundantRoleAction::Rebase,
        |r: &mut RedundantRoleResponse| r.session.role_generation = 3,
        |r: &mut RedundantRoleResponse| r.session.role_generation = 6,
        |r: &mut RedundantRoleResponse| r.session.membership_generation = 1,
        |r: &mut RedundantRoleResponse| r.session.slot_a_lease_id = Some(C.into()),
        |r: &mut RedundantRoleResponse| r.session.slot_b_lease_id = None,
        |r: &mut RedundantRoleResponse| r.local_active_lease_id = B.into(),
        |r: &mut RedundantRoleResponse| r.session.active_lease_id = Some(B.into()),
        |r: &mut RedundantRoleResponse| r.session.session_id = C.into(),
    ] {
        let mut bad = response.clone();
        mutate(&mut bad);
        assert!(confirm_role_command(&snapshot, &bad).is_err());
        assert!(validate_stopped_role_response(&frozen, &stop, &bad).is_err());
    }
    response.session.role_generation = 5;
    for action in [
        RedundantRoleAction::Accepted,
        RedundantRoleAction::Acknowledged,
    ] {
        response.action = action;
        assert!(confirm_role_command(&snapshot, &response).is_ok());
        assert_eq!(
            validate_stopped_role_response(&frozen, &stop, &response).unwrap(),
            5
        );
    }
    assert!(!stop.role_confirmed);
    assert!(stop.retain_active_peer);
}

mod live_split_refresh {
    use super::*;
    use crate::split_tunnel::DomainResolutionMode;
    use crate::{CoreApi, CoreApiError, CoreError, CoreLocalStop, CoreLogger, RuntimeAuthProvider};
    use async_trait::async_trait;
    use nelomai_client_api::{AccessSnapshot, RuntimeAuthState, RuntimeLogin};
    use nelomai_client_storage::{
        MemorySplitTunnelStore, RuntimeAuthScope, RuntimePaths, RuntimeStateStore, RuntimeStateV1,
        SplitTunnelStore, StorageError, StoredSplitTunnelDomainResolution, StoredSplitTunnelState,
    };
    use nelomai_client_tunnel::{
        DesktopTunnelOptions, TunnelCapabilities, TunnelController, TunnelError, TunnelOptions,
        TunnelPlatform, TunnelStartRequest, TunnelStatus,
    };
    use nelomai_contracts::{
        Bootstrap, ConnectionOperationRequest, ConnectionOperationResponse, ConnectionStartRequest,
        RuntimeIdentity, SplitTunnelAddressRule, SplitTunnelAddressRuleKind,
        SplitTunnelAddressRuleScope, SplitTunnelMode, SplitTunnelPolicy,
    };
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Api {
        policy: Mutex<Option<SplitTunnelPolicy>>,
        bootstrap: Mutex<Option<Bootstrap>>,
        offline: std::sync::atomic::AtomicBool,
        policy_offline: std::sync::atomic::AtomicBool,
        apply_results: Mutex<Vec<nelomai_contracts::SplitTunnelApplyResult>>,
    }
    #[async_trait]
    impl CoreApi for Api {
        async fn bootstrap(&self, _: &AccessSnapshot) -> Result<Bootstrap, CoreApiError> {
            Ok(self
                .bootstrap
                .lock()
                .unwrap()
                .clone()
                .expect("unexpected bootstrap"))
        }
        async fn start_connection(
            &self,
            _: &AccessSnapshot,
            _: &ConnectionStartRequest,
        ) -> Result<ConnectionStartResponse, CoreApiError> {
            panic!("no Start")
        }
        async fn stop_connection(
            &self,
            _: &AccessSnapshot,
            _: &ConnectionOperationRequest,
        ) -> Result<ConnectionOperationResponse, CoreApiError> {
            panic!("no Stop")
        }
        async fn pin_stray(
            &self,
            _: &AccessSnapshot,
            _: &ConnectionOperationRequest,
        ) -> Result<ConnectionOperationResponse, CoreApiError> {
            unreachable!()
        }
        async fn unpin_stray(
            &self,
            _: &AccessSnapshot,
            _: &ConnectionOperationRequest,
        ) -> Result<ConnectionOperationResponse, CoreApiError> {
            unreachable!()
        }
        async fn split_tunnel_revision(
            &self,
            _: &AccessSnapshot,
        ) -> Result<nelomai_contracts::SplitTunnelRevision, CoreApiError> {
            if self.offline.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(CoreApiError::Retryable);
            }
            let p = self.policy.lock().unwrap();
            let p = p.as_ref().expect("unexpected panel fetch");
            Ok(nelomai_contracts::SplitTunnelRevision {
                enabled: p.enabled,
                revision: p.revision,
                force_revision: p.force_revision,
                address_revision: p.address_revision,
            })
        }
        async fn split_tunnel_policy(
            &self,
            _: &AccessSnapshot,
        ) -> Result<SplitTunnelPolicy, CoreApiError> {
            if self
                .policy_offline
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                return Err(CoreApiError::Retryable);
            }
            Ok(self
                .policy
                .lock()
                .unwrap()
                .clone()
                .expect("unexpected full fetch"))
        }
        async fn update_split_tunnel_settings(
            &self,
            _: &AccessSnapshot,
            _: &nelomai_contracts::SplitTunnelSettingsUpdate,
        ) -> Result<SplitTunnelPolicy, CoreApiError> {
            Ok(self.policy.lock().unwrap().clone().unwrap())
        }
        async fn report_split_tunnel_apply_result(
            &self,
            _: &AccessSnapshot,
            result: &nelomai_contracts::SplitTunnelApplyResult,
        ) -> Result<(), CoreApiError> {
            if self.offline.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(CoreApiError::Retryable);
            }
            self.apply_results.lock().unwrap().push(result.clone());
            Ok(())
        }
    }
    struct Auth(AccessSnapshot);
    #[async_trait]
    impl RuntimeAuthProvider for Auth {
        async fn state(&self) -> Result<RuntimeAuthState, CoreError> {
            unreachable!()
        }
        async fn login(&self, _: RuntimeLogin) -> Result<AccessSnapshot, CoreError> {
            unreachable!()
        }
        async fn access(&self, _: Option<&AccessSnapshot>) -> Result<AccessSnapshot, CoreError> {
            Ok(self.0.clone())
        }
        async fn logout(&self) -> Result<(), CoreError> {
            unreachable!()
        }
    }
    struct Runtime {
        paths: RuntimePaths,
        value: Mutex<RuntimeStateV1>,
    }
    impl RuntimeStateStore for Runtime {
        fn paths(&self) -> &RuntimePaths {
            &self.paths
        }
        fn load(&self) -> Result<Option<RuntimeStateV1>, StorageError> {
            Ok(Some(self.value.lock().unwrap().clone()))
        }
        fn save(&self, v: &RuntimeStateV1) -> Result<(), StorageError> {
            *self.value.lock().unwrap() = v.clone();
            Ok(())
        }
    }
    struct Log;
    impl CoreLogger for Log {
        fn record(&self, _: crate::CoreLogEvent) {}
    }
    #[derive(Clone, Copy, Default)]
    enum RefreshReply {
        #[default]
        Ack,
        Lost,
        Invalid,
        Pending,
    }
    enum RefreshCase<'a> {
        Live,
        Restored(&'a str),
        Ambiguous(RefreshReply),
        StalledSettings,
        BackgroundAfterStall,
        DeferredWithoutDomains,
        InvalidDomainBeforeSync,
        SameHashForce,
        ManualSupersedesPending,
        ManualRevisionAhead,
        ScheduledSupersedesPending,
        CoordinatorBeforeDueRevisionCheck,
        StartAfterCurrentPolicyApplyFailure,
        DeferredWithFullOutbox,
    }
    struct Tunnel {
        platform: TunnelPlatform,
        snapshot: Mutex<Snapshot>,
        applied: Mutex<Vec<DesktopTunnelOptions>>,
        next_reply: Mutex<RefreshReply>,
    }
    #[async_trait]
    impl TunnelController for Tunnel {
        async fn capabilities(&self) -> Result<TunnelCapabilities, TunnelError> {
            Ok(TunnelCapabilities {
                platform: self.platform,
                address_split_tunnel: true,
                ..Default::default()
            })
        }
        async fn start(&self, _: TunnelStartRequest) -> Result<(), TunnelError> {
            panic!("retained pair must not Start")
        }
        async fn stop(&self) -> Result<(), TunnelError> {
            panic!("retained pair must not Stop")
        }
        async fn status(&self) -> Result<TunnelStatus, TunnelError> {
            Ok(TunnelStatus::Running)
        }
        async fn desktop_redundancy_command(
            &self,
            command: Command,
        ) -> Result<Snapshot, TunnelError> {
            let wire = serde_json::to_value(command).unwrap();
            let (mut response, reply) = {
                let mut snapshot = self.snapshot.lock().unwrap();
                let mut reply = RefreshReply::Ack;
                match wire["action"].as_str().unwrap() {
                    "status" => (),
                    "refresh_split_tunnel" => {
                        assert_eq!(wire["expected_revision"], snapshot.session.local_revision);
                        assert_eq!(
                            wire["expected_network_epoch"],
                            snapshot.session.network_epoch
                        );
                        assert_eq!(
                            wire["expected_role_generation"],
                            snapshot.session.role_generation
                        );
                        assert_eq!(
                            wire["expected_membership_generation"],
                            snapshot.session.membership_generation
                        );
                        self.applied
                            .lock()
                            .unwrap()
                            .push(serde_json::from_value(wire["options"].clone()).unwrap());
                        snapshot.session.local_revision += 1;
                        reply = std::mem::take(&mut *self.next_reply.lock().unwrap());
                    }
                    other => panic!("unexpected pair command {other}"),
                }
                (snapshot.clone(), reply)
            };
            match reply {
                RefreshReply::Ack => Ok(response),
                RefreshReply::Lost => Err(TunnelError::Backend("lost_refresh_ack".into())),
                RefreshReply::Invalid => {
                    response.session.local_revision += 1;
                    Ok(response)
                }
                RefreshReply::Pending => std::future::pending().await,
            }
        }
    }
    #[tokio::test]
    async fn expired_domain_refresh_updates_retained_pair_before_revision_gate_without_saved_config(
    ) {
        for platform in [
            TunnelPlatform::Windows,
            TunnelPlatform::Macos,
            TunnelPlatform::Linux,
        ] {
            retained_pair_refresh_case(platform, RefreshCase::Live).await;
        }
    }

    #[tokio::test]
    async fn bootstrap_retained_split_recipe_requires_native_ack_even_with_equal_routes() {
        for resolution in ["198.51.100.10/32", "203.0.113.9/32"] {
            retained_pair_refresh_case(TunnelPlatform::Windows, RefreshCase::Restored(resolution))
                .await;
        }
    }

    #[tokio::test]
    async fn retained_split_lost_ack_requires_reapply_when_exclusions_are_disabled() {
        retained_pair_refresh_case(
            TunnelPlatform::Windows,
            RefreshCase::Ambiguous(RefreshReply::Lost),
        )
        .await;
    }

    #[tokio::test]
    async fn retained_split_invalid_ack_requires_reapply_when_exclusions_are_disabled() {
        retained_pair_refresh_case(
            TunnelPlatform::Windows,
            RefreshCase::Ambiguous(RefreshReply::Invalid),
        )
        .await;
    }

    #[tokio::test]
    async fn retained_split_interrupted_apply_requires_reapply_when_exclusions_are_disabled() {
        retained_pair_refresh_case(
            TunnelPlatform::Windows,
            RefreshCase::Ambiguous(RefreshReply::Pending),
        )
        .await;
    }

    #[tokio::test]
    async fn retained_pair_save_defers_live_route_change_windows() {
        retained_pair_refresh_case(TunnelPlatform::Windows, RefreshCase::StalledSettings).await;
    }

    #[tokio::test]
    async fn retained_pair_save_defers_live_route_change_macos() {
        retained_pair_refresh_case(TunnelPlatform::Macos, RefreshCase::StalledSettings).await;
    }

    #[tokio::test]
    async fn retained_pair_save_defers_live_route_change_linux() {
        retained_pair_refresh_case(TunnelPlatform::Linux, RefreshCase::StalledSettings).await;
    }

    #[tokio::test]
    async fn retained_pair_sync_replaces_unresolvable_cached_domain_macos() {
        retained_pair_refresh_case(TunnelPlatform::Macos, RefreshCase::InvalidDomainBeforeSync)
            .await;
    }

    #[tokio::test]
    async fn retained_pair_sync_replaces_unresolvable_cached_domain_linux() {
        retained_pair_refresh_case(TunnelPlatform::Linux, RefreshCase::InvalidDomainBeforeSync)
            .await;
    }

    #[tokio::test]
    async fn background_reports_deferred_policy_windows() {
        retained_pair_refresh_case(TunnelPlatform::Windows, RefreshCase::BackgroundAfterStall)
            .await;
    }

    #[tokio::test]
    async fn background_reports_deferred_policy_macos() {
        retained_pair_refresh_case(TunnelPlatform::Macos, RefreshCase::BackgroundAfterStall).await;
    }

    #[tokio::test]
    async fn background_reports_deferred_policy_linux() {
        retained_pair_refresh_case(TunnelPlatform::Linux, RefreshCase::BackgroundAfterStall).await;
    }

    #[tokio::test]
    async fn background_retries_saved_ip_rules_while_panel_offline_windows() {
        retained_pair_refresh_case(TunnelPlatform::Windows, RefreshCase::DeferredWithoutDomains)
            .await;
    }

    #[tokio::test]
    async fn background_retries_saved_ip_rules_while_panel_offline_macos() {
        retained_pair_refresh_case(TunnelPlatform::Macos, RefreshCase::DeferredWithoutDomains)
            .await;
    }

    #[tokio::test]
    async fn background_retries_saved_ip_rules_while_panel_offline_linux() {
        retained_pair_refresh_case(TunnelPlatform::Linux, RefreshCase::DeferredWithoutDomains)
            .await;
    }

    #[tokio::test]
    async fn retained_pair_retries_same_hash_force_revision_windows() {
        retained_pair_refresh_case(TunnelPlatform::Windows, RefreshCase::SameHashForce).await;
    }

    #[tokio::test]
    async fn retained_pair_retries_same_hash_force_revision_macos() {
        retained_pair_refresh_case(TunnelPlatform::Macos, RefreshCase::SameHashForce).await;
    }

    #[tokio::test]
    async fn retained_pair_retries_same_hash_force_revision_linux() {
        retained_pair_refresh_case(TunnelPlatform::Linux, RefreshCase::SameHashForce).await;
    }

    #[tokio::test]
    async fn retained_pair_manual_sync_skips_superseded_pending_rule_macos() {
        retained_pair_refresh_case(TunnelPlatform::Macos, RefreshCase::ManualSupersedesPending)
            .await;
    }

    #[tokio::test]
    async fn retained_pair_manual_sync_skips_superseded_pending_rule_linux() {
        retained_pair_refresh_case(TunnelPlatform::Linux, RefreshCase::ManualSupersedesPending)
            .await;
    }

    #[tokio::test]
    async fn retained_pair_newer_revision_blocks_stale_cached_policy_windows() {
        retained_pair_refresh_case(TunnelPlatform::Windows, RefreshCase::ManualRevisionAhead).await;
    }

    #[tokio::test]
    async fn retained_pair_newer_revision_blocks_stale_cached_policy_macos() {
        retained_pair_refresh_case(TunnelPlatform::Macos, RefreshCase::ManualRevisionAhead).await;
    }

    #[tokio::test]
    async fn retained_pair_newer_revision_blocks_stale_cached_policy_linux() {
        retained_pair_refresh_case(TunnelPlatform::Linux, RefreshCase::ManualRevisionAhead).await;
    }

    #[tokio::test]
    async fn retained_pair_full_outbox_keeps_current_applied_receipt_macos() {
        retained_pair_refresh_case(TunnelPlatform::Macos, RefreshCase::DeferredWithFullOutbox)
            .await;
    }

    #[tokio::test]
    async fn retained_pair_full_outbox_keeps_current_applied_receipt_linux() {
        retained_pair_refresh_case(TunnelPlatform::Linux, RefreshCase::DeferredWithFullOutbox)
            .await;
    }

    #[tokio::test]
    async fn retained_pair_scheduled_sync_skips_superseded_pending_rule_macos() {
        retained_pair_refresh_case(
            TunnelPlatform::Macos,
            RefreshCase::ScheduledSupersedesPending,
        )
        .await;
    }

    #[tokio::test]
    async fn retained_pair_scheduled_sync_skips_superseded_pending_rule_linux() {
        retained_pair_refresh_case(
            TunnelPlatform::Linux,
            RefreshCase::ScheduledSupersedesPending,
        )
        .await;
    }

    #[tokio::test]
    async fn pair_coordinator_waits_for_due_revision_check_windows() {
        retained_pair_refresh_case(
            TunnelPlatform::Windows,
            RefreshCase::CoordinatorBeforeDueRevisionCheck,
        )
        .await;
    }

    #[tokio::test]
    async fn pair_coordinator_waits_for_due_revision_check_macos() {
        retained_pair_refresh_case(
            TunnelPlatform::Macos,
            RefreshCase::CoordinatorBeforeDueRevisionCheck,
        )
        .await;
    }

    #[tokio::test]
    async fn pair_coordinator_waits_for_due_revision_check_linux() {
        retained_pair_refresh_case(
            TunnelPlatform::Linux,
            RefreshCase::CoordinatorBeforeDueRevisionCheck,
        )
        .await;
    }

    #[tokio::test]
    async fn start_keeps_revoked_exclusion_off_after_apply_failure_linux() {
        retained_pair_refresh_case(
            TunnelPlatform::Linux,
            RefreshCase::StartAfterCurrentPolicyApplyFailure,
        )
        .await;
    }

    #[tokio::test]
    async fn start_keeps_revoked_exclusion_off_after_apply_failure_macos() {
        retained_pair_refresh_case(
            TunnelPlatform::Macos,
            RefreshCase::StartAfterCurrentPolicyApplyFailure,
        )
        .await;
    }

    async fn retained_pair_refresh_case(platform: TunnelPlatform, case: RefreshCase<'_>) {
        let pair = pair();
        let before = both(&pair);
        let identity = RuntimeIdentity {
            slot: RT,
            runtime_version: "0.4.0".into(),
            container_version: "0.4.0".into(),
            runtime_contract_version: 2,
            session_generation: Some(7),
        };
        let access =
            AccessSnapshot::new("access".into(), identity.clone(), 1, "family".into()).unwrap();
        let paths = RuntimePaths::new("/synthetic-no-filesystem", RT, "0.4.0").unwrap();
        let mut runtime = RuntimeStateV1::empty(&paths, false);
        runtime.auth_scope = Some(RuntimeAuthScope {
            auth_epoch: 1,
            family: "family".into(),
            identity,
        });
        runtime.desktop_redundancy = Some(pair.clone());
        assert!(runtime.saved_connection.is_none() && runtime.pinned_connection.is_none());
        let policy = SplitTunnelPolicy {
            format_version: 2,
            enabled: !matches!(case, RefreshCase::Ambiguous(_)),
            revision: 1,
            force_revision: 0,
            address_revision: 1,
            policy_hash: format!("sha256:{}", "a".repeat(64)),
            mode: SplitTunnelMode::ExcludeSelected,
            exclude_local_networks: true,
            mandatory_excluded_packages: vec![],
            suggested_name_fragments: vec![],
            selected_packages: vec![],
            excluded_ipv4_cidrs: vec![],
            address_rules: vec![SplitTunnelAddressRule {
                id: 1,
                scope: SplitTunnelAddressRuleScope::ThisDevice,
                kind: SplitTunnelAddressRuleKind::Domain,
                value: "cached.example".into(),
            }],
            generated_at: "2026-07-31T12:00:00Z".into(),
        };
        let split = Arc::new(MemorySplitTunnelStore::default());
        split
            .save(&StoredSplitTunnelState {
                cached_policy: Some(policy.clone()),
                working_policy_hash: Some(policy.policy_hash.clone()),
                working_policy_revision: Some(nelomai_contracts::SplitTunnelRevision {
                    enabled: policy.enabled,
                    revision: policy.revision,
                    force_revision: policy.force_revision,
                    address_revision: policy.address_revision,
                }),
                last_revision_check_unix: Some(100),
                domain_resolutions: vec![StoredSplitTunnelDomainResolution {
                    domain: "cached.example".into(),
                    ipv4_cidrs: vec!["198.51.100.10/32".into()],
                    resolved_at_unix: 100,
                }],
                ..Default::default()
            })
            .unwrap();
        let tunnel = Arc::new(Tunnel {
            platform,
            snapshot: Mutex::new(before.clone()),
            applied: Mutex::new(vec![]),
            next_reply: Mutex::new(RefreshReply::Ack),
        });
        let api = Arc::new(Api::default());
        let core = Arc::new(crate::ClientCore::with_split_tunnel_store(
            api.clone(),
            Arc::new(Runtime {
                paths,
                value: Mutex::new(runtime),
            }),
            split.clone(),
            Arc::new(Auth(access)),
            CoreLocalStop::new(tunnel.clone()),
            Arc::new(Log),
        ));
        if matches!(case, RefreshCase::StartAfterCurrentPolicyApplyFailure) {
            let revoked = "203.0.113.9/32";
            let mut previous = policy.clone();
            previous.address_rules.clear();
            previous.excluded_ipv4_cidrs = vec![revoked.into()];
            let mut stored = split.load().unwrap();
            stored.cached_policy = Some(previous.clone());
            split.save(&stored).unwrap();

            let mut current = previous.clone();
            current.revision += 1;
            current.policy_hash = format!("sha256:{}", "b".repeat(64));
            current.excluded_ipv4_cidrs.clear();
            *api.policy.lock().unwrap() = Some(current.clone());
            core.synchronize_split_tunnel_with_resolver(401, true, |_| async {
                panic!("no domains")
            })
            .await
            .unwrap();

            let mut stored = split.load().unwrap();
            assert_eq!(
                stored.observed_panel_revision.as_ref().unwrap().revision,
                current.revision
            );
            assert_eq!(stored.cached_policy, Some(current.clone()));
            assert_eq!(stored.previous_working_policy, Some(previous));
            // Persist the state produced by a failed apply/rollback on a single tunnel.
            stored.failed_policy_hash = Some(current.policy_hash);
            split.save(&stored).unwrap();

            let policy = core.cached_policy_for_start().unwrap();
            assert!(
                !policy
                    .as_ref()
                    .is_some_and(|p| p.excluded_ipv4_cidrs.iter().any(|cidr| cidr == revoked)),
                "{platform:?}: Start would restore the revoked exclusion {revoked}: {policy:?}"
            );
            return;
        }
        if matches!(
            case,
            RefreshCase::SameHashForce
                | RefreshCase::ManualSupersedesPending
                | RefreshCase::ManualRevisionAhead
                | RefreshCase::ScheduledSupersedesPending
                | RefreshCase::CoordinatorBeforeDueRevisionCheck
        ) {
            *core.state.lock().await = crate::CoreState {
                phase: crate::Phase::Connected,
                connection: Some(pair.connection.clone()),
            };
            let mut applied = policy.clone();
            applied.address_rules.clear();
            let mut cached = split.load().unwrap();
            cached.cached_policy = Some(applied.clone());
            split.save(&cached).unwrap();
            if matches!(case, RefreshCase::SameHashForce) {
                let mut forced = applied;
                forced.force_revision += 1;
                *api.policy.lock().unwrap() = Some(forced.clone());
                tunnel.snapshot.lock().unwrap().stalled = true;
                core.synchronize_split_tunnel_with_resolver(401, false, |_| async {
                    panic!("no domains to resolve")
                })
                .await
                .unwrap();
                let saved = split.load().unwrap();
                assert_eq!(saved.cached_policy, Some(forced.clone()));
                assert!(tunnel.applied.lock().unwrap().is_empty());
                assert_eq!(saved.last_seen_force_revision, forced.force_revision);
                assert_eq!(saved.working_policy_revision.unwrap().force_revision, 0);
                assert!(api.apply_results.lock().unwrap().is_empty());
                tunnel.snapshot.lock().unwrap().stalled = false;
                core.synchronize_split_tunnel_with_resolver(702, false, |_| async {
                    panic!("no domains to resolve")
                })
                .await
                .unwrap();
                let saved = split.load().unwrap();
                let working = saved.working_policy_revision.unwrap();
                assert_eq!(working.revision, forced.revision);
                assert_eq!(working.force_revision, forced.force_revision);
                assert_eq!(working.address_revision, forced.address_revision);
                assert!(saved.pending_apply_results.is_empty());
                let results = api.apply_results.lock().unwrap();
                assert_eq!(results.len(), 1, "{platform:?}: forced revision receipt");
                assert_eq!(results[0].force_revision, forced.force_revision);
                assert_eq!(results[0].policy_hash, forced.policy_hash);
            } else {
                let added = "203.0.113.9/32";
                let mut pending = applied.clone();
                pending.revision += 1;
                pending.policy_hash = format!("sha256:{}", "b".repeat(64));
                pending.excluded_ipv4_cidrs.push(added.into());
                let mut newer = applied;
                newer.revision = pending.revision + 1;
                newer.enabled = false;
                newer.policy_hash = format!("sha256:{}", "c".repeat(64));
                cached.cached_policy = Some(pending.clone());
                split.save(&cached).unwrap();
                *api.policy.lock().unwrap() = Some(newer.clone());
                if matches!(case, RefreshCase::CoordinatorBeforeDueRevisionCheck) {
                    let now = time::OffsetDateTime::now_utc().unix_timestamp();
                    cached.last_revision_check_unix = Some(now - 301);
                    split.save(&cached).unwrap();
                    core.desktop_redundancy_tick(Vec::new()).await.unwrap();
                    let native = tunnel.applied.lock().unwrap().clone();
                    assert!(
                        native.is_empty(),
                        "{platform:?}: coordinator installed the obsolete exclusion before the overdue revision check"
                    );
                    core.synchronize_split_tunnel_with_resolver(now, false, |_| async {
                        panic!("no domains to resolve")
                    })
                    .await
                    .unwrap();
                    assert_eq!(split.load().unwrap().cached_policy, Some(newer));
                    let applied = tunnel.applied.lock().unwrap();
                    assert_eq!(applied.len(), 1);
                    assert!(applied[0].excluded_ipv4_cidrs.is_empty());
                    return;
                }
                if matches!(case, RefreshCase::ManualRevisionAhead) {
                    api.policy_offline
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                    assert_eq!(
                        core.synchronize_split_tunnel_with_resolver(401, true, |_| async {
                            panic!("no domains")
                        })
                        .await
                        .unwrap(),
                        crate::SplitTunnelSyncOutcome::CachedOffline
                    );
                    let saved = split.load().unwrap();
                    assert!(
                        tunnel.applied.lock().unwrap().is_empty(),
                        "{platform:?}: revision {} already seen but stale CIDR was installed; working hash {:?}",
                        newer.revision, saved.working_policy_hash
                    );
                    assert_eq!(saved.working_policy_hash, Some(policy.policy_hash.clone()));
                    assert_eq!(
                        saved.observed_panel_revision.unwrap().revision,
                        newer.revision
                    );
                    assert!(core.cached_policy_for_start().unwrap().is_none());
                    assert_eq!(
                        core.synchronize_split_tunnel_with_resolver(402, false, |_| async {
                            panic!("no domains")
                        })
                        .await
                        .unwrap(),
                        crate::SplitTunnelSyncOutcome::Skipped
                    );
                    assert!(tunnel.applied.lock().unwrap().is_empty());

                    api.policy_offline
                        .store(false, std::sync::atomic::Ordering::SeqCst);
                    *api.policy.lock().unwrap() = Some(pending);
                    assert_eq!(
                        core.synchronize_split_tunnel_with_resolver(403, true, |_| async {
                            panic!("no domains")
                        })
                        .await
                        .unwrap(),
                        crate::SplitTunnelSyncOutcome::CachedOffline
                    );
                    assert!(tunnel.applied.lock().unwrap().is_empty());
                    *api.policy.lock().unwrap() = Some(newer.clone());
                    core.synchronize_split_tunnel_with_resolver(404, true, |_| async {
                        panic!("no domains")
                    })
                    .await
                    .unwrap();
                    let applied = tunnel.applied.lock().unwrap();
                    assert_eq!(applied.len(), 1);
                    assert!(applied[0].excluded_ipv4_cidrs.is_empty());
                    assert_eq!(split.load().unwrap().cached_policy, Some(newer));
                    return;
                }
                let forced = !matches!(case, RefreshCase::ScheduledSupersedesPending);
                core.synchronize_split_tunnel_with_resolver(401, forced, |_| async {
                    panic!("no domains to resolve")
                })
                .await
                .unwrap();
                let saved = split.load().unwrap();
                assert_eq!(
                    saved.working_policy_hash.as_deref(),
                    Some(newer.policy_hash.as_str())
                );
                assert_eq!(saved.cached_policy, Some(newer.clone()));
                {
                    let applied = tunnel.applied.lock().unwrap();
                    assert_eq!(applied.len(), 1, "{platform:?}: temporarily installed superseded bypass during successful forced sync");
                    assert!(applied[0].excluded_ipv4_cidrs.is_empty());
                }
                if !forced {
                    return;
                }

                let mut pending = newer;
                pending.enabled = true;
                pending.revision += 1;
                pending.policy_hash = format!("sha256:{}", "d".repeat(64));
                pending.excluded_ipv4_cidrs = vec![added.into()];
                let mut saved = saved;
                saved.cached_policy = Some(pending.clone());
                split.save(&saved).unwrap();
                api.offline.store(true, std::sync::atomic::Ordering::SeqCst);
                assert_eq!(
                    core.synchronize_split_tunnel_with_resolver(402, true, |_| async {
                        panic!("no domains to resolve")
                    })
                    .await
                    .unwrap(),
                    crate::SplitTunnelSyncOutcome::CachedOffline
                );
                let saved = split.load().unwrap();
                assert_eq!(saved.working_policy_hash, Some(pending.policy_hash));
                assert_eq!(saved.pending_apply_results.len(), 1);
                assert_eq!(
                    tunnel.applied.lock().unwrap()[1].excluded_ipv4_cidrs,
                    [added]
                );
            }
            return;
        }
        if matches!(
            case,
            RefreshCase::StalledSettings
                | RefreshCase::BackgroundAfterStall
                | RefreshCase::DeferredWithoutDomains
                | RefreshCase::DeferredWithFullOutbox
                | RefreshCase::InvalidDomainBeforeSync
        ) {
            *core.state.lock().await = crate::CoreState {
                phase: crate::Phase::Connected,
                connection: Some(pair.connection.clone()),
            };
            let mut updated = policy.clone();
            updated.revision += 1;
            updated.policy_hash = format!("sha256:{}", "b".repeat(64));
            updated.exclude_local_networks = false;
            if matches!(
                case,
                RefreshCase::StalledSettings
                    | RefreshCase::BackgroundAfterStall
                    | RefreshCase::DeferredWithoutDomains
                    | RefreshCase::DeferredWithFullOutbox
            ) {
                tunnel.snapshot.lock().unwrap().stalled = true;
                // Save can return a newer full policy, including a panel-side
                // change to the active address exclusions.
                updated.excluded_ipv4_cidrs = vec!["203.0.113.0/24".into()];
                if matches!(
                    case,
                    RefreshCase::DeferredWithoutDomains | RefreshCase::DeferredWithFullOutbox
                ) {
                    updated.address_rules.clear();
                }
                *api.policy.lock().unwrap() = Some(updated.clone());
                let request = nelomai_contracts::SplitTunnelSettingsUpdate {
                    mode: policy.mode,
                    exclude_local_networks: false,
                    selected_packages: vec![],
                };
                let reply = core.save_split_tunnel_settings(&request, 161).await;
                let saved = split.load().unwrap();
                assert!(!saved.cached_policy.unwrap().exclude_local_networks);
                assert_eq!(
                    saved.working_policy_hash.as_deref(),
                    Some(policy.policy_hash.as_str())
                );
                assert!(tunnel.applied.lock().unwrap().is_empty());
                assert!(
                    matches!(reply, Err(CoreError::SplitTunnel(code)) if code == "split_tunnel_apply_deferred"),
                    "save must report deferred application for {platform:?}"
                );

                assert!(api.apply_results.lock().unwrap().is_empty());
                tunnel.snapshot.lock().unwrap().stalled = false;
                if matches!(
                    case,
                    RefreshCase::DeferredWithoutDomains | RefreshCase::DeferredWithFullOutbox
                ) {
                    api.offline.store(true, std::sync::atomic::Ordering::SeqCst);
                    if matches!(case, RefreshCase::DeferredWithFullOutbox) {
                        let mut saved = split.load().unwrap();
                        saved.pending_apply_results = (0..32)
                            .map(|_| nelomai_contracts::SplitTunnelApplyResult {
                                format_version: policy.format_version,
                                revision: policy.revision,
                                force_revision: policy.force_revision,
                                address_revision: policy.address_revision,
                                policy_hash: policy.policy_hash.clone(),
                                status: nelomai_contracts::SplitTunnelApplyStatus::Failed,
                                error_code: Some("split_tunnel_apply_failed".into()),
                                applied_at: policy.generated_at.clone(),
                            })
                            .collect();
                        split.save(&saved).unwrap();
                        let result = core
                            .synchronize_split_tunnel_with_resolver(162, false, |_| async {
                                panic!("no domains")
                            })
                            .await
                            .unwrap();
                        assert_eq!(
                            result,
                            crate::SplitTunnelSyncOutcome::Updated { reconnected: false }
                        );
                        let saved = split.load().unwrap();
                        assert_eq!(
                            saved.working_policy_hash.as_deref(),
                            Some(updated.policy_hash.as_str())
                        );
                        assert_eq!(saved.pending_apply_results.len(), 32);
                        assert!(
                            saved.pending_apply_results.iter().any(|report| report.policy_hash == updated.policy_hash),
                            "{platform:?}: stored working revision but discarded its only Applied receipt"
                        );
                        return;
                    }
                    let poll = core
                        .synchronize_split_tunnel_with_resolver(462, false, |_| async {
                            panic!("no domain addresses are needed")
                        })
                        .await
                        .unwrap();
                    let saved = split.load().unwrap();
                    assert_eq!(saved.cached_policy, Some(updated.clone()));
                    assert_eq!(
                        saved.working_policy_hash,
                        Some(updated.policy_hash),
                        "{platform:?}: acknowledged IP-only policy still pending after healthy pair, poll={poll:?}"
                    );
                    let commands = tunnel.applied.lock().unwrap();
                    assert_eq!(commands.len(), 1);
                    assert_eq!(commands[0].excluded_ipv4_cidrs, ["203.0.113.0/24"]);
                    let [queued] = saved.pending_apply_results.as_slice() else {
                        panic!("the confirmed result must survive the panel outage");
                    };
                    assert_eq!(queued.revision, updated.revision);
                    assert_eq!(
                        queued.status,
                        nelomai_contracts::SplitTunnelApplyStatus::Applied
                    );
                    return;
                }
                if matches!(case, RefreshCase::BackgroundAfterStall) {
                    for now in [162, 462] {
                        core.synchronize_split_tunnel_with_resolver(now, false, |_| async {
                            Some(vec!["198.51.100.10/32".into()])
                        })
                        .await
                        .unwrap();
                    }
                    assert_eq!(tunnel.applied.lock().unwrap().len(), 1);
                    let saved = split.load().unwrap();
                    assert_eq!(
                        saved.working_policy_hash.as_deref(),
                        Some(updated.policy_hash.as_str())
                    );
                    let results = api.apply_results.lock().unwrap();
                    assert_eq!(
                        results.len(),
                        1,
                        "{platform:?}: revision {} applied locally",
                        updated.revision
                    );
                    assert_eq!(results[0].policy_hash, updated.policy_hash);
                    assert_eq!(results[0].revision, updated.revision);
                    assert_eq!(
                        results[0].status,
                        nelomai_contracts::SplitTunnelApplyStatus::Applied
                    );
                    assert!(saved.pending_apply_results.is_empty());
                    return;
                }
                let applied = core
                    .save_split_tunnel_settings(&request, 162)
                    .await
                    .unwrap();
                assert_eq!(
                    split.load().unwrap().working_policy_hash.as_deref(),
                    Some(applied.policy_hash.as_str())
                );
                let commands = tunnel.applied.lock().unwrap();
                assert_eq!(commands.len(), 1);
                assert_eq!(
                    commands[0].excluded_ipv4_cidrs,
                    ["198.51.100.10/32", "203.0.113.0/24"]
                );
            } else {
                let mut cached = split.load().unwrap();
                cached.domain_resolutions.clear();
                split.save(&cached).unwrap();
                updated.enabled = false;
                updated.address_rules.clear();
                *api.policy.lock().unwrap() = Some(updated.clone());
                let outcome = core
                    .synchronize_split_tunnel_with_resolver(401, true, |_| async { None })
                    .await
                    .unwrap();
                assert_eq!(
                    outcome,
                    crate::SplitTunnelSyncOutcome::Updated { reconnected: false }
                );
                let saved = split.load().unwrap();
                assert_eq!(saved.cached_policy, Some(updated.clone()));
                assert_eq!(saved.working_policy_hash, Some(updated.policy_hash));
                let commands = tunnel.applied.lock().unwrap();
                assert_eq!(commands.len(), 1);
                assert!(commands[0].excluded_ipv4_cidrs.is_empty());
            }
            return;
        }
        if let RefreshCase::Ambiguous(reply) = case {
            *core.state.lock().await = crate::CoreState {
                phase: crate::Phase::Connected,
                connection: Some(pair.connection.clone()),
            };
            *core.split_tunnel_options.lock().await =
                crate::split_tunnel::RunningSplitTunnelOptions::confirmed(
                    TunnelOptions::default(),
                    &pair.connection.lease_id,
                    core.start_cancellation_epoch(),
                );
            let mut changed = split.load().unwrap();
            let next = changed.cached_policy.as_mut().unwrap();
            next.enabled = true;
            next.policy_hash = format!("sha256:{}", "b".repeat(64));
            next.address_rules[0].value = "new.example".into();
            split.save(&changed).unwrap();
            *tunnel.next_reply.lock().unwrap() = reply;
            let pending = tokio::time::timeout(
                std::time::Duration::from_millis(10),
                core.refresh_retained_split_tunnel(
                    &mut changed,
                    161,
                    |_| async { Some(vec!["203.0.113.9/32".into()]) },
                    None,
                    Some((
                        DomainResolutionMode::Refresh,
                        core.start_cancellation_epoch(),
                    )),
                ),
            )
            .await;
            match reply {
                RefreshReply::Pending => assert!(pending.is_err()),
                _ => assert!(pending.unwrap().is_err()),
            }
            // The native commit happened even though its exact proof was lost.
            assert_eq!(
                tunnel.applied.lock().unwrap()[0].excluded_ipv4_cidrs,
                ["203.0.113.9/32"]
            );
            let mut original = split.load().unwrap();
            original.cached_policy = Some(policy);
            split.save(&original).unwrap();
            core.refresh_retained_split_tunnel(
                &mut original,
                162,
                |_| async { panic!("disabled policy must not resolve domains") },
                None,
                Some((
                    DomainResolutionMode::Refresh,
                    core.start_cancellation_epoch(),
                )),
            )
            .await
            .unwrap();
            {
                let applied = tunnel.applied.lock().unwrap();
                assert_eq!(
                    applied.len(),
                    2,
                    "must reapply after an ambiguous native commit"
                );
                assert!(applied[1].excluded_ipv4_cidrs.is_empty());
            }
            // A positive retry ACK permits the next identical operation to skip apply.
            core.refresh_retained_split_tunnel(
                &mut original,
                163,
                |_| async { panic!("disabled policy must not resolve domains") },
                None,
                Some((
                    DomainResolutionMode::Refresh,
                    core.start_cancellation_epoch(),
                )),
            )
            .await
            .unwrap();
            assert_eq!(tunnel.applied.lock().unwrap().len(), 2);
            return;
        }
        if let RefreshCase::Restored(resolution) = case {
            let mut bootstrap: Bootstrap = serde_json::from_str(include_str!(
                "../../../contracts/fixtures/valid/bootstrap.json"
            ))
            .unwrap();
            bootstrap.connection = Some(pair.connection.clone());
            *api.bootstrap.lock().unwrap() = Some(bootstrap);
            core.bootstrap(161).await.unwrap();
            assert_eq!(core.state.lock().await.phase, crate::Phase::Connected);
            core.synchronize_split_tunnel_with_resolver(161, false, |_| async {
                Some(vec![resolution.into()])
            })
            .await
            .unwrap();
            let applied = tunnel.applied.lock().unwrap();
            assert_eq!(
                applied.len(),
                1,
                "disk recipe cannot prove the native applied plan"
            );
            assert_eq!(applied[0].excluded_ipv4_cidrs, [resolution]);
            return;
        }
        *core.state.lock().await = crate::CoreState {
            phase: crate::Phase::Connected,
            connection: Some(pair.connection.clone()),
        };
        *core.split_tunnel_options.lock().await =
            crate::split_tunnel::RunningSplitTunnelOptions::confirmed(
                TunnelOptions {
                    excluded_ipv4_cidrs: vec!["198.51.100.10/32".into()],
                    exclude_local_networks: true,
                    policy_hash: Some(policy.policy_hash.clone()),
                    ..Default::default()
                },
                &pair.connection.lease_id,
                core.start_cancellation_epoch(),
            );
        let preserves_previous_answers = platform == TunnelPlatform::Windows;
        let outcome = core
            .synchronize_split_tunnel_with_resolver(161, false, |_| async {
                Some(vec!["203.0.113.9/32".into()])
            })
            .await
            .unwrap();
        assert_eq!(
            outcome,
            crate::SplitTunnelSyncOutcome::Updated { reconnected: false }
        );
        {
            let applied = tunnel.applied.lock().unwrap();
            assert_eq!(applied.len(), 1);
            let expected: &[&str] = if preserves_previous_answers {
                &["198.51.100.10/32", "203.0.113.9/32"]
            } else {
                &["203.0.113.9/32"]
            };
            assert_eq!(applied[0].excluded_ipv4_cidrs, expected, "{platform:?}");
            let after = tunnel.snapshot.lock().unwrap();
            assert_eq!(after.session.scope, before.session.scope);
            assert_eq!(after.session.active, before.session.active);
            assert_eq!(after.session.network_epoch, before.session.network_epoch);
            assert_eq!(
                after.session.local_revision,
                before.session.local_revision + 1
            );
            assert_eq!(
                split.load().unwrap().domain_resolutions[0].resolved_at_unix,
                161
            );
        }

        assert_eq!(
            core.synchronize_split_tunnel_with_resolver(162, false, |_| async {
                panic!("not expired")
            })
            .await
            .unwrap(),
            crate::SplitTunnelSyncOutcome::Skipped
        );
        assert_eq!(tunnel.applied.lock().unwrap().len(), 1);
        // A new policy with identical effective routes still publishes its identity.
        let mut next = policy.clone();
        next.policy_hash = format!("sha256:{}", "b".repeat(64));
        if preserves_previous_answers {
            next.excluded_ipv4_cidrs = vec!["198.51.100.10/32".into()];
        }
        let mut cached = split.load().unwrap();
        cached.cached_policy = Some(next.clone());
        split.save(&cached).unwrap();
        let same = core
            .refresh_retained_split_tunnel(
                &mut cached,
                163,
                |_| async { Some(vec!["203.0.113.9/32".into()]) },
                None,
                Some((
                    DomainResolutionMode::Refresh,
                    core.start_cancellation_epoch(),
                )),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            same.session.local_revision,
            before.session.local_revision + 1
        );
        assert_eq!(
            cached.working_policy_hash.as_deref(),
            Some(next.policy_hash.as_str())
        );
        assert_eq!(
            core.split_tunnel_options
                .lock()
                .await
                .options
                .policy_hash
                .as_deref(),
            Some(next.policy_hash.as_str())
        );
        split.save(&cached).unwrap();
        core.synchronize_split_tunnel_with_resolver(224, false, |_| async {
            Some(vec!["203.0.113.10/32".into()])
        })
        .await
        .unwrap();
        let expected: &[&str] = if preserves_previous_answers {
            &["198.51.100.10/32", "203.0.113.10/32", "203.0.113.9/32"]
        } else {
            &["203.0.113.10/32"]
        };
        assert_eq!(
            tunnel.applied.lock().unwrap()[1].excluded_ipv4_cidrs,
            expected,
            "{platform:?}"
        );
        assert_eq!(
            core.synchronize_split_tunnel_with_resolver(285, false, |_| async { None })
                .await
                .unwrap(),
            crate::SplitTunnelSyncOutcome::Updated { reconnected: false }
        );
        assert_eq!(tunnel.applied.lock().unwrap().len(), 2);
        let failed_refresh = split.load().unwrap();
        assert_eq!(failed_refresh.domain_resolutions[0].resolved_at_unix, 224);
        assert_eq!(
            failed_refresh.domain_resolutions[0].ipv4_cidrs,
            ["203.0.113.10/32"]
        );
        if !preserves_previous_answers {
            assert_eq!(
                core.split_tunnel_warning().await.as_deref(),
                Some("split_tunnel_domain_resolution_failed")
            );
            core.synchronize_split_tunnel_with_resolver(346, false, |_| async {
                Some(vec!["203.0.113.10/32".into()])
            })
            .await
            .unwrap();
            assert_eq!(core.split_tunnel_warning().await, None);
        }
        // A Stop epoch wins while the system resolver is awaiting its response.
        let cancel = core.clone();
        api.offline.store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            core.synchronize_split_tunnel_with_resolver(461, false, move |_| {
                let cancel = cancel.clone();
                async move {
                    cancel
                        .start_cancel_epoch
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Some(vec!["203.0.113.10/32".into()])
                }
            })
            .await
            .unwrap(),
            crate::SplitTunnelSyncOutcome::CachedOffline
        );
        assert_eq!(tunnel.applied.lock().unwrap().len(), 2);
        assert_eq!(
            split.load().unwrap().domain_resolutions[0].resolved_at_unix,
            if preserves_previous_answers { 224 } else { 346 }
        );
        api.offline
            .store(false, std::sync::atomic::Ordering::SeqCst);
        // Disabling split must clear domain routes without saved configuration or Stop/Start.
        let mut removed = policy;
        removed.enabled = false;
        removed.address_rules[0].value = "uncached.invalid".into();
        removed.policy_hash = format!("sha256:{}", "c".repeat(64));
        removed.revision += 1;
        *api.policy.lock().unwrap() = Some(removed);
        assert_eq!(
            core.synchronize_split_tunnel(462, true).await.unwrap(),
            crate::SplitTunnelSyncOutcome::Updated { reconnected: false }
        );
        let applied = tunnel.applied.lock().unwrap();
        assert_eq!(applied.len(), 3);
        assert!(applied[2].excluded_ipv4_cidrs.is_empty());
    }
}
