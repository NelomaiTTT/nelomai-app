use nelomai_client_tunnel::redundancy::{
    BackendHealth, FailoverDecision, RedundantHealthMonitor, Slot, SlotObservation,
    StandbyProbeState,
};

fn healthy(slot: Slot, active: bool) -> SlotObservation {
    SlotObservation {
        slot,
        active,
        health: BackendHealth::Warming,
        hard_failure: false,
        probe_failed: false,
        independent_failure_signal: false,
        soft_failure_started_at_ms: None,
        corroborated_probe_failures: 0,
        handshake_fresh: true,
        consecutive_probe_successes: 1,
        stable_since_ms: Some(0),
        standby_probe_state: StandbyProbeState::Succeeded,
    }
}

fn dead_primary() -> SlotObservation {
    SlotObservation {
        hard_failure: true,
        ..healthy(Slot::A, true)
    }
}

#[test]
fn primary_does_not_wait_for_standby_or_ready_dwell() {
    let mut monitor = RedundantHealthMonitor::new(true);
    let primary = healthy(Slot::A, true);
    assert!(monitor.primary_ready(100, &primary));
    assert!(!monitor.ready(100, &primary));
    assert_eq!(monitor.evaluate(100, &[primary]), FailoverDecision::None);
}

#[test]
fn hard_failure_selects_a_proven_warming_standby() {
    let mut monitor = RedundantHealthMonitor::new(true);
    assert_eq!(
        monitor.evaluate(100, &[dead_primary(), healthy(Slot::B, false)]),
        FailoverDecision::SwitchTo(Slot::B)
    );
}

#[test]
fn soft_failure_needs_two_corroborated_retries_not_dwell_on_active() {
    let mut monitor = RedundantHealthMonitor::new(true);
    let mut primary = healthy(Slot::A, true);
    primary.probe_failed = true;
    primary.independent_failure_signal = true;
    primary.soft_failure_started_at_ms = Some(100);
    primary.corroborated_probe_failures = 1;
    let reserve = healthy(Slot::B, false);
    assert_eq!(
        monitor.evaluate(200, &[primary, reserve]),
        FailoverDecision::None
    );
    primary.corroborated_probe_failures = 2;
    assert_eq!(
        monitor.evaluate(300, &[primary, reserve]),
        FailoverDecision::SwitchTo(Slot::B)
    );
    primary.independent_failure_signal = false;
    assert_eq!(
        monitor.evaluate(400, &[primary, reserve]),
        FailoverDecision::None
    );
}

#[test]
fn standby_soft_failure_retains_five_second_dwell() {
    let monitor = RedundantHealthMonitor::new(true);
    let standby = SlotObservation {
        probe_failed: true,
        independent_failure_signal: true,
        soft_failure_started_at_ms: Some(100),
        corroborated_probe_failures: 2,
        ..healthy(Slot::B, false)
    };
    assert!(!monitor.failed(5099, &standby));
    assert!(monitor.failed(5100, &standby));
}

#[test]
fn fresh_handshake_and_probe_are_required_even_for_cached_ready() {
    for (fresh, successes, failed) in [(false, 3, false), (true, 0, false), (true, 3, true)] {
        let mut monitor = RedundantHealthMonitor::new(true);
        let reserve = SlotObservation {
            health: BackendHealth::Ready,
            handshake_fresh: fresh,
            consecutive_probe_successes: successes,
            probe_failed: failed,
            ..healthy(Slot::B, false)
        };
        assert_eq!(
            monitor.evaluate(20_000, &[dead_primary(), reserve]),
            FailoverDecision::Stalled
        );
    }
}

#[test]
fn pending_candidate_delays_stalled_but_failed_candidate_does_not() {
    let mut monitor = RedundantHealthMonitor::new(true);
    let mut reserve = healthy(Slot::B, false);
    reserve.standby_probe_state = StandbyProbeState::Pending;
    assert_eq!(
        monitor.evaluate(0, &[dead_primary(), reserve]),
        FailoverDecision::None
    );
    reserve.standby_probe_state = StandbyProbeState::Failed;
    assert_eq!(
        monitor.evaluate(1000, &[dead_primary(), reserve]),
        FailoverDecision::Stalled
    );
    assert_eq!(
        monitor.evaluate(2000, &[dead_primary(), reserve]),
        FailoverDecision::None
    );
}

#[test]
fn hard_failed_pending_standby_cannot_delay_stalled_forever() {
    let mut monitor = RedundantHealthMonitor::new(true);
    let reserve = SlotObservation {
        hard_failure: true,
        standby_probe_state: StandbyProbeState::Pending,
        ..healthy(Slot::B, false)
    };
    assert_eq!(
        monitor.evaluate(0, &[dead_primary(), reserve]),
        FailoverDecision::Stalled
    );
}

#[test]
fn rebind_suppresses_failover_for_four_seconds_and_invalid_network_indefinitely() {
    let mut monitor = RedundantHealthMonitor::new(true);
    monitor.network_changed(100, false);
    let slots = [dead_primary(), healthy(Slot::B, false)];
    assert_eq!(monitor.evaluate(90_000, &slots), FailoverDecision::None);
    monitor.network_changed(90_000, true);
    assert_eq!(monitor.evaluate(93_999, &slots), FailoverDecision::None);
    assert_eq!(
        monitor.evaluate(94_000, &slots),
        FailoverDecision::SwitchTo(Slot::B)
    );
}

#[test]
fn ready_requires_fifteen_seconds_and_three_successes() {
    let monitor = RedundantHealthMonitor::new(true);
    let mut standby = healthy(Slot::B, false);
    standby.consecutive_probe_successes = 3;
    assert!(!monitor.ready(14_999, &standby));
    assert!(monitor.ready(15_000, &standby));
    standby.consecutive_probe_successes = 2;
    assert!(!monitor.ready(20_000, &standby));
}

#[test]
fn malformed_slot_set_does_not_switch_or_poison_next_observation() {
    let mut monitor = RedundantHealthMonitor::new(true);
    for slots in [
        vec![],
        vec![dead_primary(), healthy(Slot::A, false)],
        vec![dead_primary(), healthy(Slot::B, true)],
        vec![healthy(Slot::B, false)],
        vec![
            dead_primary(),
            healthy(Slot::B, false),
            healthy(Slot::A, false),
        ],
    ] {
        assert_eq!(monitor.evaluate(0, &slots), FailoverDecision::None);
    }
    assert_eq!(
        monitor.evaluate(1, &[dead_primary(), healthy(Slot::B, false)]),
        FailoverDecision::SwitchTo(Slot::B)
    );
}

#[test]
fn healthy_active_does_not_fail_back_to_old_primary() {
    let mut monitor = RedundantHealthMonitor::new(true);
    assert_eq!(
        monitor.evaluate(20_000, &[healthy(Slot::A, false), healthy(Slot::B, true)]),
        FailoverDecision::None
    );
}

#[test]
fn future_soft_failure_timestamp_and_invalid_network_do_not_confirm_failure() {
    let mut monitor = RedundantHealthMonitor::new(false);
    let primary = SlotObservation {
        probe_failed: true,
        independent_failure_signal: true,
        corroborated_probe_failures: 2,
        soft_failure_started_at_ms: Some(6000),
        ..healthy(Slot::A, true)
    };
    assert!(!monitor.failed(7000, &primary));
    monitor.network_changed(0, true);
    assert!(!monitor.failed(5000, &primary));
    assert!(monitor.failed(6000, &primary));
}

#[test]
fn emitted_stall_deduplicates_only_stalled_not_a_later_proven_reserve() {
    let mut monitor = RedundantHealthMonitor::new(true);
    assert_eq!(
        monitor.evaluate(0, &[dead_primary()]),
        FailoverDecision::Stalled
    );
    assert_eq!(
        monitor.evaluate(100, &[dead_primary()]),
        FailoverDecision::None
    );
    assert_eq!(
        monitor.evaluate(200, &[dead_primary(), healthy(Slot::B, false)]),
        FailoverDecision::SwitchTo(Slot::B)
    );
    let failed_b = SlotObservation {
        slot: Slot::B,
        ..dead_primary()
    };
    assert_eq!(
        monitor.evaluate(300, &[failed_b]),
        FailoverDecision::Stalled,
        "successful selection of a proven healthy reserve starts a new role episode"
    );
}

#[test]
fn healthy_primary_resets_stalled_episode_but_unproven_primary_does_not() {
    let mut monitor = RedundantHealthMonitor::new(true);
    assert_eq!(
        monitor.evaluate(0, &[dead_primary()]),
        FailoverDecision::Stalled
    );
    let mut unproven = healthy(Slot::A, true);
    unproven.consecutive_probe_successes = 0;
    assert_eq!(monitor.evaluate(100, &[unproven]), FailoverDecision::None);
    assert_eq!(
        monitor.evaluate(200, &[dead_primary()]),
        FailoverDecision::None
    );
    assert_eq!(
        monitor.evaluate(300, &[healthy(Slot::A, true)]),
        FailoverDecision::None
    );
    assert_eq!(
        monitor.evaluate(400, &[dead_primary()]),
        FailoverDecision::Stalled
    );
    assert_eq!(
        monitor.evaluate(500, &[dead_primary()]),
        FailoverDecision::None
    );
}

#[test]
fn validated_new_epoch_resets_stalled_after_existing_four_second_suppression() {
    let mut monitor = RedundantHealthMonitor::new(true);
    assert_eq!(
        monitor.evaluate(0, &[dead_primary()]),
        FailoverDecision::Stalled
    );
    monitor.network_changed(100, false);
    assert_eq!(
        monitor.evaluate(5000, &[healthy(Slot::A, true)]),
        FailoverDecision::None
    );
    monitor.network_changed(5100, true);
    assert_eq!(
        monitor.evaluate(9099, &[dead_primary()]),
        FailoverDecision::None
    );
    assert_eq!(
        monitor.evaluate(9100, &[dead_primary()]),
        FailoverDecision::Stalled
    );
    assert_eq!(
        monitor.evaluate(9200, &[dead_primary()]),
        FailoverDecision::None
    );
}
