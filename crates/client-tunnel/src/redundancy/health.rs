use super::Slot;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendHealth {
    Warming,
    Ready,
    Suspect,
    Unhealthy,
    Recovering,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StandbyProbeState {
    NotRequired,
    Pending,
    Succeeded,
    Failed,
}

/// A current observation in the helper's monotonic clock domain. The caller must
/// discard samples from previous network/session epochs before constructing it.
#[derive(Clone, Copy, Debug)]
pub struct SlotObservation {
    pub slot: Slot,
    pub active: bool,
    pub health: BackendHealth,
    pub hard_failure: bool,
    pub probe_failed: bool,
    pub independent_failure_signal: bool,
    pub soft_failure_started_at_ms: Option<u64>,
    pub corroborated_probe_failures: u32,
    pub handshake_fresh: bool,
    pub consecutive_probe_successes: u32,
    pub stable_since_ms: Option<u64>,
    pub standby_probe_state: StandbyProbeState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailoverDecision {
    None,
    SwitchTo(Slot),
    Stalled,
}

/// Mirrors the accepted Android health policy without timers, networking or
/// platform effects. A stalled session is handed back to its lifecycle once;
/// that lifecycle creates a new monitor when recovery creates a new epoch.
pub struct RedundantHealthMonitor {
    network_validated: bool,
    suppress_until_ms: u64,
    stalled_emitted: bool,
}

impl RedundantHealthMonitor {
    pub fn new(initial_network_validated: bool) -> Self {
        Self {
            network_validated: initial_network_validated,
            suppress_until_ms: 0,
            stalled_emitted: false,
        }
    }

    pub fn network_changed(&mut self, now_ms: u64, validated: bool) {
        self.network_validated = validated;
        self.suppress_until_ms = now_ms.saturating_add(4_000);
    }

    pub fn network_ready(&self, now_ms: u64) -> bool {
        self.network_validated && now_ms >= self.suppress_until_ms
    }

    pub fn primary_ready(&self, now_ms: u64, slot: &SlotObservation) -> bool {
        self.network_ready(now_ms)
            && !slot.hard_failure
            && slot.health != BackendHealth::Unhealthy
            && !slot.probe_failed
            && slot.handshake_fresh
            && slot.consecutive_probe_successes >= 1
    }

    pub fn ready(&self, now_ms: u64, slot: &SlotObservation) -> bool {
        self.primary_ready(now_ms, slot) && self.classify(now_ms, slot) == BackendHealth::Ready
    }

    pub fn failed(&self, now_ms: u64, slot: &SlotObservation) -> bool {
        self.network_ready(now_ms)
            && (self.classify(now_ms, slot) == BackendHealth::Unhealthy
                || (slot.probe_failed
                    && slot.independent_failure_signal
                    && slot.corroborated_probe_failures >= 2
                    && slot.soft_failure_started_at_ms.is_some_and(|started| {
                        now_ms >= started && (slot.active || now_ms - started >= 5_000)
                    })))
    }

    pub fn evaluate(&mut self, now_ms: u64, slots: &[SlotObservation]) -> FailoverDecision {
        if self.stalled_emitted
            || !self.network_ready(now_ms)
            || slots.is_empty()
            || slots.len() > 2
            || (slots.len() == 2 && slots[0].slot == slots[1].slot)
            || slots.iter().filter(|s| s.active).count() != 1
        {
            return FailoverDecision::None;
        }
        let active = slots
            .iter()
            .find(|s| s.active)
            .expect("validated single active");
        if !self.failed(now_ms, active) {
            return FailoverDecision::None;
        }
        if let Some(candidate) = slots.iter().find(|s| !s.active && self.usable(now_ms, s)) {
            return FailoverDecision::SwitchTo(candidate.slot);
        }
        if slots.iter().any(|s| {
            !s.active
                && !s.hard_failure
                && s.health != BackendHealth::Unhealthy
                && s.standby_probe_state == StandbyProbeState::Pending
        }) {
            return FailoverDecision::None;
        }
        self.stalled_emitted = true;
        FailoverDecision::Stalled
    }

    fn usable(&self, now_ms: u64, slot: &SlotObservation) -> bool {
        self.primary_ready(now_ms, slot)
            && matches!(
                slot.standby_probe_state,
                StandbyProbeState::NotRequired | StandbyProbeState::Succeeded
            )
            && matches!(
                self.classify(now_ms, slot),
                BackendHealth::Ready | BackendHealth::Warming | BackendHealth::Recovering
            )
    }

    fn classify(&self, now_ms: u64, slot: &SlotObservation) -> BackendHealth {
        if slot.hard_failure || slot.health == BackendHealth::Unhealthy {
            return BackendHealth::Unhealthy;
        }
        if slot.probe_failed && slot.independent_failure_signal {
            return BackendHealth::Suspect;
        }
        if slot.handshake_fresh
            && slot.consecutive_probe_successes >= 3
            && slot
                .stable_since_ms
                .is_some_and(|started| now_ms >= started && now_ms - started >= 15_000)
        {
            return BackendHealth::Ready;
        }
        slot.health
    }
}
