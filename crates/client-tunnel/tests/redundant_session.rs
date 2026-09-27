use nelomai_client_tunnel::redundancy::{session::*, SessionScope, Slot};
use nelomai_contracts::RuntimeSlot;

fn scope() -> SessionScope {
    SessionScope {
        runtime: RuntimeSlot::Latest,
        runtime_generation: 10,
        session_id: "11111111-1111-4111-8111-111111111111".into(),
        connection_generation: 7,
    }
}
fn session() -> SessionState {
    SessionState::new(scope(), Slot::A, 4, 8).unwrap()
}

#[test]
fn role_ack_cannot_advance_beyond_signed_panel_generation_limit() {
    for generation in [i64::MAX as u64 - 1, i64::MAX as u64] {
        let mut s = SessionState::new(scope(), Slot::A, generation, 0).unwrap();
        s.primary_started(&scope()).unwrap();
        let ticket = s.install_ticket(&scope(), Slot::B).unwrap();
        s.standby_installed(ticket, 0).unwrap();
        let ticket = s.promotion_ticket(&scope(), Slot::B).unwrap();
        s.promote(ticket, || Ok::<(), &str>(())).unwrap();
        let update = s.role_update().unwrap();
        let before = s.snapshot();
        assert_eq!(
            s.ack_role(&update, generation + 1),
            generation < i64::MAX as u64
        );
        if generation == i64::MAX as u64 {
            assert_eq!(s.snapshot(), before);
            assert_eq!(s.warm_slot(), None);
        } else {
            assert_eq!(s.snapshot().role_generation, i64::MAX as u64);
        }
    }
}

#[test]
fn primary_is_running_without_waiting_for_standby() {
    let mut s = session();
    assert_eq!(s.snapshot().phase, SessionPhase::Starting);
    s.primary_started(&scope()).unwrap();
    assert_eq!(s.snapshot().phase, SessionPhase::Running);
    assert_eq!(s.snapshot().installed, [true, false]);
}

#[test]
fn delayed_standby_is_fenced_by_stop_and_network_change() {
    let mut s = session();
    s.primary_started(&scope()).unwrap();
    let ticket = s.install_ticket(&scope(), Slot::B).unwrap();
    s.network_changed(&scope()).unwrap();
    assert!(s.standby_installed(ticket, 9).is_err());
    let ticket = s.install_ticket(&scope(), Slot::B).unwrap();
    s.begin_stop(&scope()).unwrap();
    assert!(s.standby_installed(ticket, 9).is_err());
}

#[test]
fn failed_native_promotion_does_not_publish_new_active() {
    let mut s = session();
    s.primary_started(&scope()).unwrap();
    let ticket = s.install_ticket(&scope(), Slot::B).unwrap();
    s.standby_installed(ticket, 9).unwrap();
    let ticket = s.promotion_ticket(&scope(), Slot::B).unwrap();
    assert!(s
        .promote(ticket.clone(), || Err::<(), _>("route conflict"))
        .is_err());
    assert_eq!(s.snapshot().active, Slot::A);
    assert!(s.role_update().is_none());
    s.promote(ticket, || Ok::<(), &str>(())).unwrap();
    assert_eq!(s.snapshot().active, Slot::B);
    assert_eq!(s.role_update().unwrap().expected_role_generation, 4);
}

#[test]
fn network_epoch_rejects_late_promotion_before_native_call() {
    let mut s = session();
    s.primary_started(&scope()).unwrap();
    let ticket = s.install_ticket(&scope(), Slot::B).unwrap();
    s.standby_installed(ticket, 9).unwrap();
    let ticket = s.promotion_ticket(&scope(), Slot::B).unwrap();
    s.network_changed(&scope()).unwrap();
    assert!(s
        .promote(ticket, || {
            panic!("stale native promotion");
            #[allow(unreachable_code)]
            Ok::<(), &str>(())
        })
        .is_err());
}

#[test]
fn late_ack_cannot_undo_a_new_local_role_or_stop() {
    let mut s = session();
    s.primary_started(&scope()).unwrap();
    let ticket = s.install_ticket(&scope(), Slot::B).unwrap();
    s.standby_installed(ticket, 9).unwrap();
    let ticket = s.promotion_ticket(&scope(), Slot::B).unwrap();
    s.promote(ticket, || Ok::<(), &str>(())).unwrap();
    let old = s.role_update().unwrap();
    let ticket = s.promotion_ticket(&scope(), Slot::A).unwrap();
    s.promote(ticket, || Ok::<(), &str>(())).unwrap();
    assert!(!s.ack_role(&old, 5));
    assert_eq!(s.snapshot().active, Slot::A);
    let current = s.role_update().unwrap();
    s.begin_stop(&scope()).unwrap();
    assert!(!s.ack_role(&current, 5));
    assert_eq!(s.snapshot().phase, SessionPhase::Stopping);
}

#[test]
fn stop_keeps_last_local_active_but_warm_requires_reconciled_role() {
    let mut s = session();
    s.primary_started(&scope()).unwrap();
    let ticket = s.install_ticket(&scope(), Slot::B).unwrap();
    s.standby_installed(ticket, 9).unwrap();
    let ticket = s.promotion_ticket(&scope(), Slot::B).unwrap();
    s.promote(ticket, || Ok::<(), &str>(())).unwrap();
    let update = s.role_update().unwrap();
    assert_eq!(s.warm_slot(), None);
    assert!(s.ack_role(&update, 5));
    assert_eq!(s.warm_slot(), Some(Slot::B));
    s.begin_stop(&scope()).unwrap();
    assert_eq!(s.snapshot().active, Slot::B);
    s.stopped(&scope()).unwrap();
    assert_eq!(s.snapshot().phase, SessionPhase::Stopped);
    assert_eq!(s.snapshot().installed, [false, false]);
}

#[test]
fn scope_and_generation_mismatch_cannot_install_or_stop() {
    let mut s = session();
    let mut other = scope();
    other.connection_generation += 1;
    assert!(s.primary_started(&other).is_err());
    assert!(s.begin_stop(&other).is_err());
    s.primary_started(&scope()).unwrap();
    let ticket = s.install_ticket(&scope(), Slot::B).unwrap();
    assert!(s.standby_installed(ticket, 7).is_err());
    assert_eq!(s.snapshot().installed, [true, false]);
}

#[test]
fn recovered_snapshot_only_allows_cleanup_not_running_or_replayed_start() {
    let mut original = session();
    original.primary_started(&scope()).unwrap();
    let snapshot =
        serde_json::from_str(&serde_json::to_string(&original.snapshot()).unwrap()).unwrap();
    let mut recovered = SessionState::recover_for_cleanup(scope(), snapshot).unwrap();
    assert_eq!(recovered.snapshot().phase, SessionPhase::Stopping);
    assert!(recovered.primary_started(&scope()).is_err());
    assert!(recovered.install_ticket(&scope(), Slot::B).is_err());
    assert_eq!(recovered.warm_slot(), None);
    recovered.stopped(&scope()).unwrap();
}

#[test]
fn cancelled_primary_cannot_claim_a_warm_member() {
    let mut s = session();
    s.begin_stop(&scope()).unwrap();
    s.stopped(&scope()).unwrap();
    assert_eq!(s.warm_slot(), None);
}

#[test]
fn panel_zero_generation_primary_is_valid_and_recoverable() {
    let mut s = SessionState::new(scope(), Slot::A, 0, 0).unwrap();
    s.primary_started(&scope()).unwrap();
    assert!(SessionState::recover_for_cleanup(scope(), s.snapshot()).is_ok());
}

#[test]
fn same_generation_requires_acknowledged_exact_latest_unconfirmed_role() {
    use nelomai_contracts::RedundantRoleAction::{Accepted, Acknowledged, Rebase};
    for generation in [4, i64::MAX as u64] {
        let mut s = SessionState::new(scope(), Slot::A, generation, 8).unwrap();
        s.primary_started(&scope()).unwrap();
        s.standby_installed(s.install_ticket(&scope(), Slot::B).unwrap(), 8)
            .unwrap();
        s.promote(s.promotion_ticket(&scope(), Slot::B).unwrap(), || {
            Ok::<(), ()>(())
        })
        .unwrap();
        let stale_b = s.role_update().unwrap();
        s.promote(s.promotion_ticket(&scope(), Slot::A).unwrap(), || {
            Ok::<(), ()>(())
        })
        .unwrap();
        let current = s.role_update().unwrap();
        let before = s.snapshot();
        assert!(
            !s.ack_role(&current, generation),
            "legacy path remains strictly incrementing"
        );
        assert!(!s.ack_role_response(&current, generation, Accepted));
        assert!(!s.ack_role_response(&current, generation, Rebase));
        assert!(!s.ack_role_response(&stale_b, generation, Acknowledged));
        assert!(!s.ack_role_response(&current, generation - 1, Acknowledged));
        assert!(!s.ack_role_response(&current, generation + 2, Acknowledged));
        assert_eq!(s.snapshot(), before);
        assert!(s.ack_role_response(&current, generation, Acknowledged));
        assert_eq!(s.snapshot().role_generation, generation);
        assert_eq!(s.warm_slot(), Some(Slot::A));
        assert!(!s.ack_role_response(&current, generation, Acknowledged));
    }
}

#[test]
fn installed_candidate_cannot_be_promoted_before_membership_commit() {
    let mut s = SessionState::new(scope(), Slot::A, 0, 0).unwrap();
    s.primary_started(&scope()).unwrap();
    let ticket = s.install_ticket(&scope(), Slot::B).unwrap();
    s.candidate_installed(ticket).unwrap();
    assert_eq!(s.snapshot().installed, [true, true]);
    assert_eq!(s.snapshot().committed, [true, false]);
    assert!(s.promotion_ticket(&scope(), Slot::B).is_err());
    let revision = s.snapshot().local_revision;
    let epoch = s.snapshot().network_epoch;
    assert!(s
        .commit_candidate(&scope(), Slot::B, revision, epoch, 0, 0)
        .is_err());
    s.commit_candidate(&scope(), Slot::B, revision, epoch, 0, 1)
        .unwrap();
    assert!(s.promotion_ticket(&scope(), Slot::B).is_ok());
}

#[test]
fn late_candidate_commit_cannot_rejoin_after_stop_or_network_change() {
    for stop in [false, true] {
        let mut s = SessionState::new(scope(), Slot::A, 0, 0).unwrap();
        s.primary_started(&scope()).unwrap();
        s.candidate_installed(s.install_ticket(&scope(), Slot::B).unwrap())
            .unwrap();
        let v = s.snapshot();
        if stop {
            s.begin_stop(&scope()).unwrap();
        } else {
            s.network_changed(&scope()).unwrap();
        }
        assert!(s
            .commit_candidate(&scope(), Slot::B, v.local_revision, v.network_epoch, 0, 1)
            .is_err());
        assert!(!s.snapshot().committed[1]);
    }
}
