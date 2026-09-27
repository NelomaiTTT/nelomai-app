use super::Slot;
use std::sync::atomic::{AtomicU64, Ordering};

const PERIOD_MS: u64 = 2_000;
const PHASE_MS: u64 = 1_000;
// Same response budget as Android. The one-second standby phase is not a
// one-second DNS timeout; slow-but-valid replies must not create false failures.
const TIMEOUT_MS: u64 = 2_000;
const WARMUP_MS: u64 = 5_000;
const BACKGROUND_READY_MS: u64 = 15_000;
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
    pub fn started_ms(self) -> u64 {
        self.started_ms
    }
}

#[derive(Debug, Default)]
pub struct ProbeBatch {
    pub started: Vec<ProbeTicket>,
    /// Cancel native I/O without counting a failure. These probes began before
    /// the new active-failure episode and cannot prove the reserve works now.
    /// Drain cancellations before starting this batch's new native operations.
    pub cancelled: Vec<ProbeTicket>,
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
    next_background_ms: u64,
    standby_successes: u32,
    cancelled: Vec<ProbeTicket>,
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
            next_background_ms: now_ms,
            standby_successes: 0,
            cancelled: Vec::new(),
            stopped: false,
        }
    }

    pub fn set_standby_available(&mut self, available: bool) {
        self.standby_available = available;
        if !available {
            self.in_flight[self.active.other().index()] = None;
            self.standby_successes = 0;
            self.next_background_ms = 0;
        }
    }

    pub fn network_changed(&mut self, now_ms: u64) {
        self.in_flight = [None, None];
        self.next_active_ms = now_ms;
        self.next_standby_ms = None;
        self.next_background_ms = now_ms;
        self.standby_successes = 0;
        self.cancelled.clear();
    }

    pub fn promote(&mut self, slot: Slot, now_ms: u64) {
        self.active = slot;
        self.network_changed(now_ms);
    }

    pub fn stop(&mut self) {
        self.stopped = true;
        self.in_flight = [None, None];
        self.next_standby_ms = None;
        self.cancelled.clear();
    }

    /// Native disappearance can precede a DNS timeout. Start a fresh reserve
    /// check using the same phased cadence and cancel pre-incident evidence.
    pub fn suspect_active(&mut self, now_ms: u64) {
        if self.stopped || self.next_standby_ms.is_some() {
            return;
        }
        if let Some(old) = self.in_flight[self.active.other().index()].take() {
            self.cancelled.push(old);
        }
        self.next_standby_ms = Some(now_ms.saturating_add(PHASE_MS));
    }

    pub fn poll(&mut self, now_ms: u64) -> ProbeBatch {
        let mut batch = ProbeBatch::default();
        if self.stopped {
            return batch;
        }
        for slot in [self.active, self.active.other()] {
            if let Some(ticket) = self.in_flight[slot.index()].filter(|t| now_ms >= t.deadline_ms) {
                self.in_flight[slot.index()] = None;
                self.observe_result(ticket, false, now_ms);
                batch.timed_out.push(ticket);
            }
        }
        if now_ms >= self.next_active_ms {
            if let Some(ticket) = self.start(self.active, now_ms) {
                batch.started.push(ticket);
                self.next_active_ms = now_ms.saturating_add(PERIOD_MS);
            }
        }
        let urgent = self.next_standby_ms.is_some();
        let standby_due = self.next_standby_ms.unwrap_or(self.next_background_ms);
        if self.standby_available && now_ms >= standby_due {
            if let Some(ticket) = self.start(self.active.other(), now_ms) {
                batch.started.push(ticket);
                if urgent {
                    self.next_standby_ms = Some(now_ms.saturating_add(PERIOD_MS));
                }
            }
        }
        batch.cancelled = std::mem::take(&mut self.cancelled);
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
        self.observe_result(ticket, succeeded, now_ms);
        true
    }

    fn observe_result(&mut self, ticket: ProbeTicket, succeeded: bool, now_ms: u64) {
        if ticket.slot == self.active {
            if succeeded {
                self.next_standby_ms = None;
            } else {
                if self.next_standby_ms.is_none() {
                    if let Some(old) = self.in_flight[self.active.other().index()].take() {
                        self.cancelled.push(old);
                    }
                }
                self.next_standby_ms
                    .get_or_insert(ticket.started_ms.saturating_add(PHASE_MS));
            }
        } else {
            self.standby_successes = if succeeded {
                self.standby_successes.saturating_add(1)
            } else {
                0
            };
            // As on Android, normal reserve spacing starts at completion, not
            // launch. Three successes slow background polling; this is NOT a
            // health/Ready decision (which also requires handshake and dwell).
            let interval = if self.standby_successes >= 3 {
                BACKGROUND_READY_MS
            } else {
                WARMUP_MS
            };
            self.next_background_ms = now_ms.saturating_add(interval);
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
