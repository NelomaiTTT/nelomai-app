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
