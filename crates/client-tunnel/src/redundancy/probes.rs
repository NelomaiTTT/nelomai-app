use super::Slot;
use std::sync::atomic::{AtomicU64, Ordering};

const PERIOD_MS: u64 = 2_000;
const PHASE_MS: u64 = 1_000;
const TIMEOUT_MS: u64 = 1_000;
// Tickets are process-local, never persisted. A new helper process has no live
// callback from an old process. Across sessions in one helper they never repeat.
static NEXT_TICKET: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeTicket {
    slot: Slot,
    sequence: u64,
    started_ms: u64,
    deadline_ms: u64,
}

impl ProbeTicket {
    pub fn slot(self) -> Slot {
        self.slot
    }
    pub fn deadline_ms(self) -> u64 {
        self.deadline_ms
    }
}

#[derive(Debug, Default)]
pub struct ProbeBatch {
    pub started: Vec<ProbeTicket>,
    /// Caller must cancel these native probes and record failures before applying
    /// new health decisions. A late completion cannot turn a timeout into success.
    pub timed_out: Vec<ProbeTicket>,
}

/// Monotonic scheduling only; performs no I/O. Native code must cancel its probe
/// handles on network_changed, promote, standby removal and stop. Clearing a
/// ticket fences callbacks, but does not close the underlying socket for callers.
pub struct ProbeSchedule {
    active: Slot,
    standby_available: bool,
    in_flight: [Option<ProbeTicket>; 2],
    next_active_ms: u64,
    next_standby_ms: Option<u64>,
    stopped: bool,
}

impl ProbeSchedule {
    pub fn new(active: Slot, now_ms: u64) -> Self {
        Self {
            active,
            standby_available: false,
            in_flight: [None, None],
            next_active_ms: now_ms,
            next_standby_ms: None,
            stopped: false,
        }
    }

    pub fn set_standby_available(&mut self, available: bool) {
        self.standby_available = available;
        if !available {
            self.in_flight[self.active.other().index()] = None;
        }
    }

    pub fn network_changed(&mut self, now_ms: u64) {
        self.in_flight = [None, None];
        self.next_active_ms = now_ms;
        self.next_standby_ms = None;
    }

    pub fn promote(&mut self, slot: Slot, now_ms: u64) {
        self.active = slot;
        self.network_changed(now_ms);
    }

    pub fn stop(&mut self) {
        self.stopped = true;
        self.in_flight = [None, None];
        self.next_standby_ms = None;
    }

    pub fn poll(&mut self, now_ms: u64) -> ProbeBatch {
        let mut batch = ProbeBatch::default();
        if self.stopped {
            return batch;
        }
        for slot in [self.active, self.active.other()] {
            if let Some(ticket) = self.in_flight[slot.index()].filter(|t| now_ms >= t.deadline_ms) {
                self.in_flight[slot.index()] = None;
                self.observe_result(ticket, false);
                batch.timed_out.push(ticket);
            }
        }
        if now_ms >= self.next_active_ms {
            if let Some(ticket) = self.start(self.active, now_ms) {
                batch.started.push(ticket);
                self.next_active_ms = now_ms.saturating_add(PERIOD_MS);
            }
        }
        if self.standby_available && self.next_standby_ms.is_some_and(|due| now_ms >= due) {
            if let Some(ticket) = self.start(self.active.other(), now_ms) {
                batch.started.push(ticket);
                self.next_standby_ms = Some(now_ms.saturating_add(PERIOD_MS));
            }
        }
        batch
    }

    pub fn complete(&mut self, ticket: ProbeTicket, succeeded: bool, now_ms: u64) -> bool {
        if self.stopped
            || self.in_flight[ticket.slot.index()] != Some(ticket)
            || now_ms < ticket.started_ms
            || now_ms >= ticket.deadline_ms
        {
            return false;
        }
        self.in_flight[ticket.slot.index()] = None;
        self.observe_result(ticket, succeeded);
        true
    }

    fn observe_result(&mut self, ticket: ProbeTicket, succeeded: bool) {
        if ticket.slot == self.active {
            if succeeded {
                self.next_standby_ms = None;
            } else {
                self.next_standby_ms
                    .get_or_insert(ticket.started_ms.saturating_add(PHASE_MS));
            }
        }
    }

    fn start(&mut self, slot: Slot, now_ms: u64) -> Option<ProbeTicket> {
        if self.in_flight[slot.index()].is_some() {
            return None;
        }
        let deadline_ms = now_ms.checked_add(TIMEOUT_MS)?;
        let sequence = NEXT_TICKET
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .ok()?;
        let ticket = ProbeTicket {
            slot,
            sequence,
            started_ms: now_ms,
            deadline_ms,
        };
        self.in_flight[slot.index()] = Some(ticket);
        Some(ticket)
    }
}
