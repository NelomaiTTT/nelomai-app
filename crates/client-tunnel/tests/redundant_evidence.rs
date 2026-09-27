use nelomai_client_tunnel::redundancy::evidence::{NativeHealthSample, ProbeEvidence};
use nelomai_client_tunnel::redundancy::{
    BackendHealth, ProbeSchedule, ProbeTicket, RedundantHealthMonitor, Slot, StandbyProbeState,
};

fn metrics(tx: u64, rx: u64) -> Option<NativeHealthSample> {
    Some(NativeHealthSample {
        admitted: true,
        closed: false,
        handshake_fresh: true,
        tx_packets: tx,
        rx_data_packets: rx,
    })
}

fn ticket(slot: Slot, at: u64) -> ProbeTicket {
    ProbeSchedule::new(slot, at).poll(at).started[0]
}

fn complete(e: &mut ProbeEvidence, at: u64, tx: u64, rx: u64, ok: bool) {
    let t = ticket(Slot::A, at);
    e.probe_started(t, metrics(tx, rx));
    e.probe_finished(t, ok, at + 100, metrics(tx + 1, rx));
}

#[test]
fn initial_loss_starts_episode_and_only_two_subsequent_losses_confirm_it() {
    let mut e = ProbeEvidence::new(Slot::A, 0);
    let monitor = RedundantHealthMonitor::new(true);
    for (at, count) in [(0, 0), (2000, 1), (4000, 2)] {
        complete(&mut e, at, at, 0, false);
        let o = e.observation(true, at + 100, None);
        assert!(o.probe_failed && o.independent_failure_signal);
        assert_eq!(o.soft_failure_started_at_ms, Some(100));
        assert_eq!(o.corroborated_probe_failures, count);
        assert_eq!(monitor.failed(at + 100, &o), count == 2);
    }
    assert!(!monitor.failed(4100, &e.observation(false, 4100, None)));
    assert!(monitor.failed(5100, &e.observation(false, 5100, None)));
}

#[test]
fn dns_failure_with_decrypted_receive_progress_never_confirms_failure() {
    let mut e = ProbeEvidence::new(Slot::A, 0);
    for at in [0, 2000, 4000] {
        let t = ticket(Slot::A, at);
        e.probe_started(t, metrics(at, at));
        e.probe_finished(t, false, at + 100, metrics(at + 1, at + 1));
        let o = e.observation(true, at + 100, None);
        assert!(!o.independent_failure_signal);
        assert!(!RedundantHealthMonitor::new(true).failed(at + 100, &o));
    }
}

#[test]
fn no_transmit_growth_or_missing_baseline_cannot_corroborate_dns_failure() {
    for baseline in [None, metrics(10, 0)] {
        let mut e = ProbeEvidence::new(Slot::A, 0);
        let t = ticket(Slot::A, 0);
        e.probe_started(t, baseline);
        e.probe_finished(t, false, 100, metrics(10, 0));
        assert!(!e.observation(true, 100, None).independent_failure_signal);
    }
}

#[test]
fn receive_progress_clears_urgent_evidence_and_fences_inflight_completion() {
    let mut e = ProbeEvidence::new(Slot::A, 0);
    complete(&mut e, 0, 0, 0, false);
    let t = ticket(Slot::A, 2000);
    e.probe_started(t, metrics(1, 0));
    e.sample(metrics(2, 1), 2100);
    e.probe_finished(t, false, 2200, metrics(3, 1));
    let o = e.observation(true, 2200, None);
    assert!(!o.probe_failed && !o.independent_failure_signal);
    assert_eq!(o.soft_failure_started_at_ms, None);
    assert_eq!(o.corroborated_probe_failures, 0);
}

#[test]
fn uncorroborated_retry_and_success_each_clear_urgent_evidence() {
    for ok in [false, true] {
        let mut e = ProbeEvidence::new(Slot::A, 0);
        complete(&mut e, 0, 0, 0, false);
        let t = ticket(Slot::A, 2000);
        e.probe_started(t, metrics(1, 0));
        e.probe_finished(t, ok, 2100, metrics(1, 0));
        let o = e.observation(true, 2100, None);
        assert!(!o.independent_failure_signal);
        assert_eq!(o.soft_failure_started_at_ms, None);
        assert_eq!(o.corroborated_probe_failures, 0);
        assert_eq!(o.consecutive_probe_successes, u32::from(ok));
    }
}

#[test]
fn urgent_budget_expires_unconfirmed_evidence_but_retains_confirmed_loss() {
    for confirmed in [false, true] {
        let mut e = ProbeEvidence::new(Slot::A, 0);
        complete(&mut e, 0, 0, 0, false);
        complete(&mut e, 2000, 1, 0, false);
        if confirmed {
            complete(&mut e, 4000, 2, 0, false);
        }
        assert!(e.observation(true, 8099, None).independent_failure_signal);
        let expired = e.observation(true, 8100, None);
        assert_eq!(expired.independent_failure_signal, confirmed);
        assert_eq!(expired.probe_failed, confirmed);
        e.sample(metrics(3, 0), 8100);
        assert_eq!(
            e.observation(true, 8100, None).independent_failure_signal,
            confirmed
        );
    }
}

#[test]
fn third_consecutive_missing_sample_is_hard_failure_and_valid_sample_recovers() {
    let mut e = ProbeEvidence::new(Slot::A, 0);
    complete(&mut e, 0, 0, 0, true);
    for at in 1..=3 {
        e.sample(None, 100 + at);
        let o = e.observation(true, 100 + at, None);
        assert!(!o.handshake_fresh);
        assert_eq!(o.hard_failure, at == 3);
        assert_eq!(o.standby_probe_state, StandbyProbeState::Failed);
    }
    e.sample(metrics(1, 0), 200);
    assert!(!e.observation(true, 200, None).hard_failure);
    e.sample(None, 201);
    assert!(!e.observation(true, 201, None).hard_failure);
}

#[test]
fn poll_and_completion_missing_metrics_count_once_per_timestamp() {
    let mut e = ProbeEvidence::new(Slot::A, 0);
    let t = ticket(Slot::A, 0);
    e.probe_started(t, metrics(0, 0));
    e.sample(None, 100);
    e.probe_finished(t, false, 100, None);
    e.sample(None, 100);
    assert!(!e.observation(true, 100, None).hard_failure);
    e.sample(None, 200);
    e.sample(None, 200);
    assert!(!e.observation(true, 200, None).hard_failure);
    e.sample(None, 300);
    assert!(e.observation(true, 300, None).hard_failure);

    // The same clock value in a new epoch must count its first missing poll.
    e.reset(300);
    for at in [300, 400, 500] {
        e.sample(None, at);
        assert_eq!(e.observation(true, at, None).hard_failure, at == 500);
    }
}

#[test]
fn same_timestamp_valid_samples_recover_metrics_and_process_receive_progress() {
    let mut e = ProbeEvidence::new(Slot::A, 0);
    complete(&mut e, 0, 0, 0, false);
    e.sample(None, 100);
    assert!(!e.observation(true, 100, None).handshake_fresh);
    e.sample(metrics(1, 0), 100);
    assert!(e.observation(true, 100, None).handshake_fresh);
    assert!(e.observation(true, 100, None).independent_failure_signal);
    e.sample(metrics(2, 1), 100);
    assert!(!e.observation(true, 100, None).independent_failure_signal);

    // A repeated missing copy of this poll must not spend the budget again,
    // even after a valid update at that clock value has reset the streak.
    e.sample(None, 100);
    e.sample(None, 200);
    e.sample(None, 300);
    assert!(!e.observation(true, 300, None).hard_failure);
    e.sample(None, 400);
    assert!(e.observation(true, 400, None).hard_failure);
}

#[test]
fn native_closed_or_unadmitted_is_immediate_hard_failure() {
    for (admitted, closed) in [(false, false), (true, true)] {
        let mut e = ProbeEvidence::new(Slot::A, 0);
        let mut m = metrics(0, 0).unwrap();
        m.admitted = admitted;
        m.closed = closed;
        e.sample(Some(m), 0);
        let o = e.observation(true, 0, None);
        assert!(o.hard_failure);
        assert_eq!(o.health, BackendHealth::Unhealthy);
    }
}

#[test]
fn counter_reset_clears_evidence_and_cannot_underflow_into_a_failure() {
    for current in [metrics(0, 10), metrics(101, 0)] {
        let mut e = ProbeEvidence::new(Slot::A, 0);
        complete(&mut e, 0, 100, 10, false);
        let t = ticket(Slot::A, 2000);
        e.probe_started(t, metrics(101, 10));
        e.probe_finished(t, false, 2100, current);
        let o = e.observation(true, 2100, None);
        assert!(!o.probe_failed && !o.independent_failure_signal);
        assert_eq!(o.corroborated_probe_failures, 0);
        assert_eq!(o.consecutive_probe_successes, 0);
    }
}

#[test]
fn exact_ticket_fences_foreign_duplicate_cancelled_and_replaced_callbacks() {
    let mut e = ProbeEvidence::new(Slot::A, 0);
    let old = ticket(Slot::A, 0);
    let foreign = ticket(Slot::A, 0);
    e.probe_started(old, metrics(0, 0));
    e.probe_finished(foreign, false, 100, metrics(1, 0));
    e.probe_cancelled(foreign);
    e.probe_started(ticket(Slot::B, 0), metrics(0, 0));
    e.probe_finished(old, true, 100, metrics(1, 0));
    e.probe_finished(old, false, 101, metrics(2, 0));
    assert_eq!(
        e.observation(true, 101, None).consecutive_probe_successes,
        1
    );
    let cancelled = ticket(Slot::A, 2000);
    e.probe_started(cancelled, metrics(1, 0));
    e.probe_cancelled(cancelled);
    e.probe_finished(cancelled, false, 2100, metrics(2, 0));
    let o = e.observation(true, 2100, None);
    assert!(!o.probe_failed && !o.independent_failure_signal);
    assert_eq!(o.consecutive_probe_successes, 0);
    let replacement = ticket(Slot::A, 2200);
    e.probe_started(replacement, metrics(2, 0));
    e.probe_finished(cancelled, true, 2300, metrics(3, 0));
    assert_eq!(
        e.observation(true, 2300, None).consecutive_probe_successes,
        0
    );
}

#[test]
fn reset_clears_all_epoch_evidence_and_fences_old_tickets() {
    let mut e = ProbeEvidence::new(Slot::A, 0);
    complete(&mut e, 0, 0, 0, true);
    let old = ticket(Slot::A, 2000);
    e.probe_started(old, metrics(1, 0));
    e.reset(2100);
    e.probe_started(old, metrics(1, 0));
    e.probe_finished(old, true, 2200, metrics(2, 0));
    let o = e.observation(false, 2200, Some(2100));
    assert!(!o.handshake_fresh && !o.probe_failed && !o.independent_failure_signal);
    assert_eq!(o.consecutive_probe_successes, 0);
    assert_eq!(o.stable_since_ms, Some(2100));
    assert_eq!(o.standby_probe_state, StandbyProbeState::Pending);
}

#[test]
fn standby_requires_completed_query_started_in_episode_and_recent_by_start_time() {
    let mut e = ProbeEvidence::new(Slot::A, 0);
    complete(&mut e, 0, 0, 0, true);
    assert_eq!(
        e.observation(false, 100, Some(50)).standby_probe_state,
        StandbyProbeState::Pending
    );
    let t = ticket(Slot::A, 1000);
    e.probe_started(t, metrics(1, 0));
    assert_eq!(
        e.observation(false, 1000, Some(1000)).standby_probe_state,
        StandbyProbeState::Pending
    );
    e.probe_finished(t, true, 2999, metrics(2, 0));
    assert_eq!(
        e.observation(false, 4000, Some(1000)).standby_probe_state,
        StandbyProbeState::Succeeded
    );
    assert_eq!(
        e.observation(false, 4001, Some(1000)).standby_probe_state,
        StandbyProbeState::Pending
    );
    assert_eq!(
        e.observation(false, 9000, Some(1000)).standby_probe_state,
        StandbyProbeState::Failed
    );
    assert_eq!(
        e.observation(true, 9000, Some(1000)).standby_probe_state,
        StandbyProbeState::NotRequired
    );
}

#[test]
fn failed_episode_probe_is_failed_and_prior_episode_failure_is_pending() {
    let mut e = ProbeEvidence::new(Slot::A, 0);
    complete(&mut e, 0, 0, 0, false);
    assert_eq!(
        e.observation(false, 100, Some(0)).standby_probe_state,
        StandbyProbeState::Failed
    );
    assert_eq!(
        e.observation(false, 101, Some(101)).standby_probe_state,
        StandbyProbeState::Pending
    );
}

#[test]
fn late_success_and_completion_before_start_cannot_establish_readiness() {
    let mut e = ProbeEvidence::new(Slot::A, 0);
    let t = ticket(Slot::A, 1000);
    e.probe_started(t, metrics(0, 0));
    e.probe_finished(t, true, 999, metrics(1, 0));
    assert_eq!(
        e.observation(true, 999, None).consecutive_probe_successes,
        0
    );
    e.probe_finished(t, true, 3000, metrics(1, 0));
    assert_eq!(
        e.observation(true, 3000, None).consecutive_probe_successes,
        0
    );
    e.probe_finished(t, false, 3000, metrics(1, 0));
    assert!(e.observation(true, 3000, None).probe_failed);
}

#[test]
fn ready_requires_three_successes_fresh_handshake_and_fifteen_second_dwell() {
    let mut e = ProbeEvidence::new(Slot::A, 0);
    for at in [0, 2000, 4000] {
        complete(&mut e, at, at, 0, true);
    }
    assert_eq!(
        e.observation(true, 14999, None).health,
        BackendHealth::Warming
    );
    assert_eq!(
        e.observation(true, 15000, None).health,
        BackendHealth::Ready
    );
    let mut stale = metrics(4001, 0).unwrap();
    stale.handshake_fresh = false;
    e.sample(Some(stale), 15000);
    assert_eq!(
        e.observation(true, 15000, None).health,
        BackendHealth::Warming
    );
}

#[test]
fn reserve_fresh_success_after_original_deadline_recovers_but_old_or_late_proof_does_not() {
    let mut e = ProbeEvidence::new(Slot::A, 0);
    complete(&mut e, 0, 0, 0, true);
    assert_eq!(
        e.observation(false, 10000, Some(0)).standby_probe_state,
        StandbyProbeState::Failed
    );
    let late = ticket(Slot::A, 10000);
    e.probe_started(late, metrics(1, 0));
    e.probe_finished(late, true, late.deadline_ms(), metrics(2, 0));
    assert_eq!(
        e.observation(false, 12000, Some(0)).standby_probe_state,
        StandbyProbeState::Failed
    );
    e.probe_cancelled(late);
    complete(&mut e, 14000, 2, 0, true);
    assert_eq!(
        e.observation(false, 14100, Some(0)).standby_probe_state,
        StandbyProbeState::Succeeded
    );
    assert_eq!(
        e.observation(false, 17000, Some(0)).standby_probe_state,
        StandbyProbeState::Succeeded
    );
    assert_eq!(
        e.observation(false, 17001, Some(0)).standby_probe_state,
        StandbyProbeState::Failed
    );
    assert_eq!(
        e.observation(false, 14100, Some(14001)).standby_probe_state,
        StandbyProbeState::Pending
    );
}

#[test]
fn recovered_reserve_success_never_overrides_missing_or_hard_native_failure() {
    for sample in [
        None,
        Some(NativeHealthSample {
            closed: true,
            ..metrics(1, 0).unwrap()
        }),
        Some(NativeHealthSample {
            admitted: false,
            ..metrics(1, 0).unwrap()
        }),
    ] {
        let mut e = ProbeEvidence::new(Slot::A, 0);
        complete(&mut e, 10000, 0, 0, true);
        e.sample(sample, 10100);
        assert_eq!(
            e.observation(false, 10100, Some(0)).standby_probe_state,
            StandbyProbeState::Failed
        );
    }
}
