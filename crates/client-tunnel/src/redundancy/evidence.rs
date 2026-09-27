use super::{BackendHealth, ProbeTicket, Slot, SlotObservation, StandbyProbeState};

const READY_SUCCESSES: u32 = 3;
const READY_STABILITY_MS: u64 = 15_000;
const REQUIRED_URGENT_FAILURES: u32 = 2;
const URGENT_BUDGET_MS: u64 = 8_000;
const STANDBY_CHECK_BUDGET_MS: u64 = 8_000;
// A result may be observed one Android health poll after the 2s query budget.
const RECENT_RESULT_MS: u64 = 2_000 + 1_000;
const MISSING_SAMPLE_BUDGET: u32 = 3;

/// Native packet counters, scoped to one slot and one network/session epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeHealthSample {
    pub admitted: bool,
    pub closed: bool,
    pub handshake_fresh: bool,
    pub tx_packets: u64,
    /// Successfully decrypted IP packets delivered by the tunnel. Encrypted UDP
    /// receives (including handshakes, keepalives and junk) are not progress.
    pub rx_data_packets: u64,
}

#[derive(Clone, Copy, Debug)]
struct InFlight {
    ticket: ProbeTicket,
    baseline: Option<NativeHealthSample>,
    urgent: bool,
}

#[derive(Clone, Copy, Debug)]
struct Urgent {
    started_ms: u64,
    rx_at_start: u64,
    failures: u32,
}

/// Pure evidence reduction matching Android's finishProbe/clearUrgent policy.
/// The owner schedules and cancels native I/O and calls `reset` on epoch changes.
/// Missing metrics shared by a health poll and completion count once per clock
/// timestamp. Valid samples still update evidence at the same timestamp.
/// Starting a probe only records its supplied baseline.
#[derive(Debug)]
pub struct ProbeEvidence {
    slot: Slot,
    stable_since_ms: u64,
    current: Option<NativeHealthSample>,
    previous: Option<NativeHealthSample>,
    missing_samples: u32,
    last_missing_sample_ms: Option<u64>,
    in_flight: Option<InFlight>,
    completed_started_ms: Option<u64>,
    successes: u32,
    probe_failed: bool,
    urgent: Option<Urgent>,
}

impl ProbeEvidence {
    pub fn new(slot: Slot, now_ms: u64) -> Self {
        Self {
            slot,
            stable_since_ms: now_ms,
            current: None,
            previous: None,
            missing_samples: 0,
            last_missing_sample_ms: None,
            in_flight: None,
            completed_started_ms: None,
            successes: 0,
            probe_failed: false,
            urgent: None,
        }
    }

    pub fn sample(&mut self, sample: Option<NativeHealthSample>, now_ms: u64) {
        if now_ms < self.stable_since_ms {
            return;
        }
        self.current = sample;
        let Some(current) = sample else {
            if self.last_missing_sample_ms != Some(now_ms) {
                self.missing_samples = self
                    .missing_samples
                    .saturating_add(1)
                    .min(MISSING_SAMPLE_BUDGET);
                self.last_missing_sample_ms = Some(now_ms);
            }
            self.expire_urgent(now_ms);
            return;
        };
        self.missing_samples = 0;
        let reset = self.previous.is_some_and(|previous| {
            current.tx_packets < previous.tx_packets
                || current.rx_data_packets < previous.rx_data_packets
        }) || self
            .in_flight
            .and_then(|probe| probe.baseline)
            .is_some_and(|baseline| {
                current.tx_packets < baseline.tx_packets
                    || current.rx_data_packets < baseline.rx_data_packets
            });
        self.previous = Some(current);
        if reset {
            // A restarted native counter is not a huge unsigned traffic delta.
            // Fence the old baseline and discard successful proof as well.
            self.clear_probe_evidence();
            self.stable_since_ms = now_ms;
            return;
        }
        if self
            .urgent
            .is_some_and(|urgent| current.rx_data_packets > urgent.rx_at_start)
        {
            self.in_flight = None;
            self.urgent = None;
            self.probe_failed = false;
        }
        self.expire_urgent(now_ms);
    }

    /// Only one query is live per slot. Wrong-slot, old-epoch and overlapping
    /// starts are ignored; cancel the old ticket before registering a replacement.
    pub fn probe_started(&mut self, ticket: ProbeTicket, sample: Option<NativeHealthSample>) {
        if ticket.slot() != self.slot || ticket.started_ms() < self.stable_since_ms {
            return;
        }
        self.expire_urgent(ticket.started_ms());
        if self.in_flight.is_some() || self.urgent_expired(ticket.started_ms()) {
            return;
        }
        self.in_flight = Some(InFlight {
            ticket,
            baseline: sample,
            urgent: self.urgent.is_some(),
        });
    }

    /// Accept an exact live ticket only. A timeout may finish as failure at its
    /// deadline; a late success cannot override the scheduler's timeout.
    pub fn probe_finished(
        &mut self,
        ticket: ProbeTicket,
        succeeded: bool,
        now_ms: u64,
        current_sample: Option<NativeHealthSample>,
    ) {
        if self.in_flight.is_none_or(|probe| probe.ticket != ticket)
            || now_ms < ticket.started_ms()
            || (succeeded && now_ms >= ticket.deadline_ms())
        {
            return;
        }
        self.sample(current_sample, now_ms);
        // Receive progress, counter reset or urgent expiry can fence the probe.
        let Some(probe) = self.in_flight.take() else {
            return;
        };
        let sent_without_receive = probe
            .baseline
            .zip(current_sample)
            .is_some_and(|(base, now)| {
                now.tx_packets > base.tx_packets && now.rx_data_packets == base.rx_data_packets
            });
        self.completed_started_ms = Some(ticket.started_ms());
        self.probe_failed = !succeeded;
        self.successes = if succeeded {
            (self.successes + 1).min(READY_SUCCESSES)
        } else {
            0
        };
        if succeeded {
            self.urgent = None;
        } else if probe.urgent {
            if sent_without_receive {
                if let Some(urgent) = &mut self.urgent {
                    urgent.failures = (urgent.failures + 1).min(REQUIRED_URGENT_FAILURES);
                }
            } else {
                self.urgent = None;
            }
        } else if sent_without_receive {
            self.urgent = Some(Urgent {
                started_ms: now_ms,
                rx_at_start: current_sample.expect("corroborated sample").rx_data_packets,
                failures: 0,
            });
        } else {
            self.urgent = None;
        }
    }

    /// Cancellation is not a failed query. Invalidate cached successful proof so
    /// a cancelled network operation cannot leave the old path looking ready.
    pub fn probe_cancelled(&mut self, ticket: ProbeTicket) {
        if self.in_flight.is_some_and(|probe| probe.ticket == ticket) {
            self.in_flight = None;
            self.completed_started_ms = None;
            self.successes = 0;
        }
    }

    pub fn reset(&mut self, now_ms: u64) {
        *self = Self::new(self.slot, now_ms);
    }

    pub fn observation(
        &self,
        active: bool,
        now_ms: u64,
        require_fresh_after: Option<u64>,
    ) -> SlotObservation {
        let hard_failure = self.missing_samples >= MISSING_SAMPLE_BUDGET
            || self
                .current
                .is_some_and(|sample| sample.closed || !sample.admitted);
        let handshake_fresh = self.current.is_some_and(|sample| sample.handshake_fresh);
        let urgent = self.urgent.filter(|urgent| {
            !self.urgent_expired(now_ms) || urgent.failures >= REQUIRED_URGENT_FAILURES
        });
        let expired_unconfirmed = self.urgent.is_some() && urgent.is_none();
        let probe_failed = self.probe_failed && !expired_unconfirmed;
        let ready = !hard_failure
            && handshake_fresh
            && self.successes >= READY_SUCCESSES
            && now_ms
                .checked_sub(self.stable_since_ms)
                .is_some_and(|age| age >= READY_STABILITY_MS);
        SlotObservation {
            slot: self.slot,
            active,
            health: if hard_failure {
                BackendHealth::Unhealthy
            } else if ready {
                BackendHealth::Ready
            } else if probe_failed {
                BackendHealth::Suspect
            } else {
                BackendHealth::Warming
            },
            hard_failure,
            probe_failed,
            independent_failure_signal: urgent.is_some(),
            soft_failure_started_at_ms: urgent.map(|urgent| urgent.started_ms),
            corroborated_probe_failures: urgent.map_or(0, |urgent| urgent.failures),
            handshake_fresh,
            consecutive_probe_successes: self.successes,
            stable_since_ms: Some(self.stable_since_ms),
            standby_probe_state: self.standby_state(
                active,
                now_ms,
                require_fresh_after,
                hard_failure,
                probe_failed,
            ),
        }
    }

    fn standby_state(
        &self,
        active: bool,
        now_ms: u64,
        since: Option<u64>,
        hard_failure: bool,
        probe_failed: bool,
    ) -> StandbyProbeState {
        if self.missing_samples > 0 {
            return StandbyProbeState::Failed;
        }
        let Some(since) = since.filter(|_| !active) else {
            return StandbyProbeState::NotRequired;
        };
        if hard_failure {
            return StandbyProbeState::Failed;
        }
        if let Some(started) = self
            .completed_started_ms
            .filter(|started| *started >= since && self.in_flight.is_none())
        {
            if probe_failed {
                return StandbyProbeState::Failed;
            }
            if self.successes > 0
                && now_ms
                    .checked_sub(started)
                    .is_some_and(|age| age <= RECENT_RESULT_MS)
            {
                return StandbyProbeState::Succeeded;
            }
        }
        // The initial check window bounds waiting, not all future recovery.
        // Only an exact accepted, recent post-incident completion above can
        // override it; in-flight, old and late-ticket successes cannot.
        if now_ms
            .checked_sub(since)
            .is_some_and(|age| age >= STANDBY_CHECK_BUDGET_MS)
        {
            return StandbyProbeState::Failed;
        }
        StandbyProbeState::Pending
    }

    fn urgent_expired(&self, now_ms: u64) -> bool {
        self.urgent.is_some_and(|urgent| {
            now_ms
                .checked_sub(urgent.started_ms)
                .is_some_and(|age| age >= URGENT_BUDGET_MS)
        })
    }

    fn expire_urgent(&mut self, now_ms: u64) {
        if self.urgent_expired(now_ms) {
            self.in_flight = None;
            if self
                .urgent
                .is_some_and(|urgent| urgent.failures < REQUIRED_URGENT_FAILURES)
            {
                self.urgent = None;
                self.probe_failed = false;
            }
        }
    }

    fn clear_probe_evidence(&mut self) {
        self.in_flight = None;
        self.completed_started_ms = None;
        self.successes = 0;
        self.probe_failed = false;
        self.urgent = None;
    }
}
