use nelomai_client_tunnel::redundancy::{ProbeSchedule, Slot};

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
    let batch = schedule.poll(1000);
    assert_eq!(batch.timed_out, vec![first]);
    assert_eq!(batch.started.len(), 1);
    assert_eq!(batch.started[0].slot(), Slot::B);
    assert!(!schedule.complete(first, true, 1000));
    assert!(schedule.poll(1001).timed_out.is_empty());
}

#[test]
fn expired_success_is_not_accepted_before_timeout_poll() {
    let mut schedule = ProbeSchedule::new(Slot::A, 0);
    let first = schedule.poll(0).started[0];
    assert!(!schedule.complete(first, true, 1000));
    assert_eq!(schedule.poll(1000).timed_out, vec![first]);
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
