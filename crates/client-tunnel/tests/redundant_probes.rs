use nelomai_client_tunnel::redundancy::{ProbeSchedule, Slot};

fn healthy_primary_run(fail_reserve_number: Option<usize>) -> Vec<u64> {
    let mut schedule = ProbeSchedule::new(Slot::A, 0);
    schedule.set_standby_available(true);
    let mut pending_reserve = None;
    let mut starts = Vec::new();
    // A deterministic clock, 100ms reserve latency. No real sleep or networking.
    for now in (0..=41_000).step_by(100) {
        if let Some(ticket) = pending_reserve.take() {
            assert!(schedule.complete(ticket, fail_reserve_number != Some(starts.len()), now));
        }
        let batch = schedule.poll(now);
        assert!(batch.timed_out.is_empty());
        for ticket in batch.started {
            if ticket.slot() == Slot::A {
                assert!(schedule.complete(ticket, true, now));
            } else {
                starts.push(now);
                pending_reserve = Some(ticket);
            }
        }
    }
    starts
}

#[test]
fn healthy_standby_is_probed_during_warmup_then_every_fifteen_seconds_from_completion() {
    assert_eq!(
        healthy_primary_run(None),
        vec![0, 5_100, 10_200, 25_300, 40_400]
    );
}

#[test]
fn failed_background_probe_returns_reserve_to_warmup_cadence() {
    assert_eq!(
        healthy_primary_run(Some(3)),
        vec![0, 5_100, 10_200, 15_300, 20_400, 25_500, 40_600]
    );
}

#[test]
fn new_primary_failure_cancels_prior_normal_reserve_probe_and_requires_new_evidence() {
    let mut schedule = ProbeSchedule::new(Slot::A, 0);
    schedule.set_standby_available(true);
    let batch = schedule.poll(0);
    assert_eq!(batch.started.len(), 2);
    let old_reserve = batch.started[1];
    assert!(schedule.complete(batch.started[0], false, 100));
    assert!(!schedule.complete(old_reserve, true, 150));
    assert_eq!(schedule.poll(200).cancelled, vec![old_reserve]);
    assert!(schedule.poll(201).cancelled.is_empty());
    assert!(schedule.poll(999).started.is_empty());
    let fresh = schedule.poll(1000).started[0];
    assert_eq!(fresh.slot(), Slot::B);
    assert!(schedule.complete(fresh, true, 1100));
}

#[test]
fn normal_reserve_timeout_retries_after_completion_and_never_delays_primary() {
    let mut schedule = ProbeSchedule::new(Slot::A, 0);
    schedule.set_standby_available(true);
    let batch = schedule.poll(0);
    assert_eq!(batch.started.len(), 2);
    schedule.complete(batch.started[0], true, 0);
    let batch = schedule.poll(2000);
    assert_eq!(batch.timed_out.len(), 1);
    assert_eq!(batch.timed_out[0].slot(), Slot::B);
    assert_eq!(batch.started.len(), 1);
    schedule.complete(batch.started[0], true, 2000);
    for now in [4000, 6000] {
        let batch = schedule.poll(now);
        assert_eq!(batch.started.len(), 1);
        schedule.complete(batch.started[0], true, now);
    }
    assert!(schedule.poll(6999).started.is_empty());
    assert_eq!(schedule.poll(7000).started[0].slot(), Slot::B);
}

#[test]
fn repeated_failure_in_same_episode_keeps_its_fresh_reserve_probe() {
    let mut schedule = ProbeSchedule::new(Slot::A, 0);
    schedule.set_standby_available(true);
    let first = schedule.poll(0);
    schedule.complete(first.started[0], false, 100);
    let fresh = schedule.poll(1000).started[0];
    let primary = schedule.poll(2000).started[0];
    schedule.complete(primary, false, 2100);
    assert!(schedule.poll(2200).cancelled.is_empty());
    assert!(schedule.complete(fresh, true, 2500));
}

#[test]
fn new_network_resets_previously_successful_reserve_to_five_second_warmup() {
    let mut schedule = ProbeSchedule::new(Slot::A, 0);
    schedule.set_standby_available(true);
    for now in (0..=10_000).step_by(100) {
        for ticket in schedule.poll(now).started {
            assert!(schedule.complete(ticket, true, now));
        }
    }
    // Three background successes at 0/5000/10000 had extended the next gap.
    schedule.network_changed(11_000);
    let mut reserves = vec![];
    for now in (11_000..=16_000).step_by(100) {
        for ticket in schedule.poll(now).started {
            if ticket.slot() == Slot::B {
                reserves.push(now);
            }
            assert!(schedule.complete(ticket, true, now));
        }
    }
    assert_eq!(reserves, vec![11_000, 16_000]);
}

#[test]
fn network_change_and_replacement_discard_normal_cadence_and_old_completions() {
    for replace in [false, true] {
        let mut schedule = ProbeSchedule::new(Slot::A, 0);
        schedule.set_standby_available(true);
        let old = schedule.poll(0);
        assert_eq!(old.started.len(), 2);
        schedule.complete(old.started[0], true, 0);
        if replace {
            schedule.set_standby_available(false);
            schedule.set_standby_available(true);
        } else {
            schedule.network_changed(100);
        }
        assert!(!schedule.complete(old.started[1], true, 150));
        assert!(schedule
            .poll(200)
            .started
            .iter()
            .any(|t| t.slot() == Slot::B));
    }
}

#[test]
fn failed_primary_staggers_reserve_between_two_second_primary_probes() {
    let mut schedule = ProbeSchedule::new(Slot::A, 0);
    schedule.set_standby_available(true);
    let first = schedule.poll(0).started[0];
    assert_eq!(first.slot(), Slot::A);
    assert!(schedule.complete(first, false, 100));
    assert!(schedule.poll(999).started.is_empty());
    let reserve = schedule.poll(1000).started[0];
    assert_eq!(reserve.slot(), Slot::B);
    assert!(schedule.complete(reserve, true, 1100));
    let primary = schedule.poll(2000).started[0];
    assert_eq!(primary.slot(), Slot::A);
    assert!(schedule.complete(primary, false, 2100));
    assert_eq!(schedule.poll(3000).started[0].slot(), Slot::B);
}

#[test]
fn success_clears_suspicion_and_standby_does_not_delay_primary() {
    let mut schedule = ProbeSchedule::new(Slot::A, 0);
    let first = schedule.poll(0).started[0];
    assert!(schedule.complete(first, false, 100));
    assert!(schedule.poll(1000).started.is_empty());
    schedule.set_standby_available(true);
    let reserve = schedule.poll(1100).started[0];
    let primary = schedule.poll(2000).started[0];
    assert_eq!(primary.slot(), Slot::A);
    assert!(schedule.complete(primary, true, 2050));
    assert!(schedule.complete(reserve, true, 2050));
    assert!(schedule.poll(3100).started.is_empty());
    assert_eq!(schedule.poll(4000).started[0].slot(), Slot::A);
}

#[test]
fn timeout_is_reported_once_and_no_slot_has_two_live_probes() {
    let mut schedule = ProbeSchedule::new(Slot::A, 0);
    schedule.set_standby_available(true);
    let first = schedule.poll(0).started[0];
    assert!(schedule.poll(500).started.is_empty());
    let batch = schedule.poll(2000);
    assert_eq!(batch.timed_out, vec![first]);
    assert_eq!(batch.started.len(), 2);
    assert_eq!(batch.started[0].slot(), Slot::A);
    assert_eq!(batch.started[1].slot(), Slot::B);
    assert!(!schedule.complete(first, true, 2000));
    assert!(schedule.poll(2001).timed_out.is_empty());
}

#[test]
fn expired_success_is_not_accepted_before_timeout_poll() {
    let mut schedule = ProbeSchedule::new(Slot::A, 0);
    let first = schedule.poll(0).started[0];
    assert!(!schedule.complete(first, true, 2000));
    assert_eq!(schedule.poll(2000).timed_out, vec![first]);
}

#[test]
fn network_epoch_rejects_old_ticket_and_restarts_primary_immediately() {
    let mut schedule = ProbeSchedule::new(Slot::A, 0);
    let old = schedule.poll(0).started[0];
    schedule.network_changed(100);
    let new = schedule.poll(100).started[0];
    assert!(!schedule.complete(old, false, 150));
    assert!(schedule.complete(new, true, 150));
    assert!(!schedule.complete(new, true, 160));
}

#[test]
fn promotion_fences_both_slots_and_uses_new_active_cadence() {
    let mut schedule = ProbeSchedule::new(Slot::A, 0);
    schedule.set_standby_available(true);
    let primary = schedule.poll(0).started[0];
    schedule.complete(primary, false, 100);
    let old_reserve = schedule.poll(1000).started[0];
    schedule.promote(Slot::B, 1500);
    assert!(!schedule.complete(old_reserve, true, 1550));
    assert_eq!(schedule.poll(1500).started[0].slot(), Slot::B);
}

#[test]
fn removed_standby_ticket_cannot_validate_a_replacement() {
    let mut schedule = ProbeSchedule::new(Slot::A, 0);
    schedule.set_standby_available(true);
    let primary = schedule.poll(0).started[0];
    schedule.complete(primary, false, 100);
    let old = schedule.poll(1000).started[0];
    schedule.set_standby_available(false);
    schedule.set_standby_available(true);
    assert!(!schedule.complete(old, true, 1200));
}

#[test]
fn stopped_schedule_cannot_be_rearmed_by_old_network_callbacks() {
    let mut schedule = ProbeSchedule::new(Slot::A, 0);
    let old = schedule.poll(0).started[0];
    schedule.stop();
    schedule.network_changed(100);
    schedule.promote(Slot::B, 100);
    schedule.set_standby_available(true);
    assert!(!schedule.complete(old, true, 150));
    assert!(schedule.poll(9000).started.is_empty());
}

#[test]
fn late_tick_has_no_unbounded_catchup_and_backwards_completion_is_rejected() {
    let mut schedule = ProbeSchedule::new(Slot::A, 0);
    schedule.set_standby_available(true);
    let first = schedule.poll(0).started[0];
    let batch = schedule.poll(1_000_000);
    assert_eq!(batch.timed_out, vec![first]);
    assert_eq!(batch.started.len(), 2);
    assert!(!schedule.complete(batch.started[0], true, 999_999));
    assert!(schedule.poll(1_000_001).started.is_empty());
}

#[test]
fn ticket_from_another_session_cannot_complete_a_probe() {
    let mut first = ProbeSchedule::new(Slot::A, 0);
    let mut second = ProbeSchedule::new(Slot::A, 0);
    let old = first.poll(0).started[0];
    let current = second.poll(0).started[0];
    assert!(!second.complete(old, true, 100));
    assert!(second.complete(current, true, 100));
}

#[test]
fn ordinary_probe_keeps_android_two_second_response_budget() {
    let mut schedule = ProbeSchedule::new(Slot::A, 0);
    let probe = schedule.poll(0).started[0];
    assert!(schedule.poll(1_000).timed_out.is_empty());
    assert!(schedule.complete(probe, true, 1_500));
    assert!(schedule.poll(1_999).started.is_empty());
    assert_eq!(schedule.poll(2_000).started[0].slot(), Slot::A);
}
