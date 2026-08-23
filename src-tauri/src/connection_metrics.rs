use nelomai_client_tunnel::TunnelMetrics;
use serde::Serialize;
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const PROBE_INTERVAL: Duration = Duration::from_secs(10);
const INITIAL_PROBE_INTERVAL: Duration = Duration::from_secs(1);
const INITIAL_PROBE_SAMPLES: usize = 3;
const PROBE_WINDOW: usize = 12;
const OBSERVATION_TTL: Duration = Duration::from_secs(15);
#[cfg(any(target_os = "macos", windows, test))]
const STALL_RECOVERY_WINDOW_SECONDS: i64 = 600;
#[cfg(any(target_os = "macos", windows, test))]
const MAX_STALL_RECOVERY_ATTEMPTS: usize = 2;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionMetricsResponse {
    pub received_bytes: u64,
    pub sent_bytes: u64,
    pub latency_ms: Option<u32>,
    pub packet_loss_percent: Option<u8>,
}

#[derive(Default)]
struct SessionMetrics {
    lease_id: String,
    received_offset: u64,
    sent_offset: u64,
    previous_received: u64,
    previous_sent: u64,
    received_bytes: u64,
    sent_bytes: u64,
    probes: VecDeque<Option<u32>>,
    last_probe_at: Option<Instant>,
}

pub struct ConnectionMetricsTracker {
    session: Mutex<Option<SessionMetrics>>,
    last_observed_at: Mutex<Option<Instant>>,
}

#[cfg(any(target_os = "macos", windows, test))]
#[derive(Default)]
pub(crate) struct StallRecoveryLimiter {
    lease_id: String,
    attempts: VecDeque<i64>,
}

#[cfg(any(target_os = "macos", windows, test))]
impl StallRecoveryLimiter {
    pub(crate) fn begin_attempt(&mut self, lease_id: &str, now_unix: i64) -> bool {
        if self.lease_id != lease_id {
            self.lease_id = lease_id.to_string();
            self.attempts.clear();
        }
        let cutoff = now_unix.saturating_sub(STALL_RECOVERY_WINDOW_SECONDS);
        while self
            .attempts
            .front()
            .is_some_and(|attempt| *attempt <= cutoff)
        {
            self.attempts.pop_front();
        }
        if self.attempts.len() >= MAX_STALL_RECOVERY_ATTEMPTS {
            return false;
        }
        self.attempts.push_back(now_unix);
        true
    }

    pub(crate) fn cancel_attempt(&mut self, lease_id: &str, attempt_unix: i64) {
        if self.lease_id == lease_id && self.attempts.back().copied() == Some(attempt_unix) {
            self.attempts.pop_back();
        }
    }

    #[cfg(any(target_os = "macos", test))]
    pub(crate) fn next_attempt_at_unix(&self, lease_id: &str) -> Option<i64> {
        if self.lease_id != lease_id || self.attempts.len() < MAX_STALL_RECOVERY_ATTEMPTS {
            return None;
        }
        self.attempts
            .front()
            .copied()
            .map(|attempt| attempt.saturating_add(STALL_RECOVERY_WINDOW_SECONDS))
    }

    pub(crate) fn reset(&mut self) {
        self.lease_id.clear();
        self.attempts.clear();
    }
}

impl ConnectionMetricsTracker {
    pub fn new() -> Self {
        Self {
            session: Mutex::new(None),
            last_observed_at: Mutex::new(None),
        }
    }

    pub async fn mark_observed(&self) {
        *self.last_observed_at.lock().await = Some(Instant::now());
    }

    pub async fn is_observed(&self) -> bool {
        self.last_observed_at
            .lock()
            .await
            .is_some_and(|observed| observed.elapsed() <= OBSERVATION_TTL)
    }

    pub async fn should_probe(&self, lease_id: &str) -> bool {
        let mut session = self.session.lock().await;
        let current = session.get_or_insert_with(|| SessionMetrics {
            lease_id: lease_id.to_string(),
            ..SessionMetrics::default()
        });
        if current.lease_id != lease_id {
            *current = SessionMetrics {
                lease_id: lease_id.to_string(),
                ..SessionMetrics::default()
            };
        }
        let now = Instant::now();
        let interval = if current.probes.len() < INITIAL_PROBE_SAMPLES {
            INITIAL_PROBE_INTERVAL
        } else {
            PROBE_INTERVAL
        };
        let due = current
            .last_probe_at
            .is_none_or(|last| now.duration_since(last) >= interval);
        if due {
            current.last_probe_at = Some(now);
        }
        due
    }

    pub async fn record(
        &self,
        lease_id: &str,
        sample: TunnelMetrics,
        probe_result: Option<Option<u32>>,
    ) {
        let mut session = self.session.lock().await;
        let current = session.get_or_insert_with(|| SessionMetrics {
            lease_id: lease_id.to_string(),
            ..SessionMetrics::default()
        });
        if current.lease_id != lease_id {
            *current = SessionMetrics {
                lease_id: lease_id.to_string(),
                ..SessionMetrics::default()
            };
        }

        if sample.received_bytes < current.previous_received {
            current.received_offset = current
                .received_offset
                .saturating_add(current.previous_received);
        }
        if sample.sent_bytes < current.previous_sent {
            current.sent_offset = current.sent_offset.saturating_add(current.previous_sent);
        }
        current.previous_received = sample.received_bytes;
        current.previous_sent = sample.sent_bytes;
        current.received_bytes = current
            .received_offset
            .saturating_add(sample.received_bytes);
        current.sent_bytes = current.sent_offset.saturating_add(sample.sent_bytes);

        if let Some(latency_ms) = probe_result {
            if current.probes.len() == PROBE_WINDOW {
                current.probes.pop_front();
            }
            current.probes.push_back(latency_ms);
        }
    }

    pub async fn snapshot(&self, lease_id: &str) -> Option<ConnectionMetricsResponse> {
        let session = self.session.lock().await;
        let current = session
            .as_ref()
            .filter(|session| session.lease_id == lease_id)?;
        let mut successful = current.probes.iter().flatten().copied().collect::<Vec<_>>();
        let initial_sample_ready = current.probes.len() >= INITIAL_PROBE_SAMPLES;
        let latency_ms = (initial_sample_ready && !successful.is_empty()).then(|| {
            successful.sort_unstable();
            let middle = successful.len() / 2;
            if successful.len() % 2 == 0 {
                let left = u64::from(successful[middle - 1]);
                let right = u64::from(successful[middle]);
                ((left + right) / 2).min(u64::from(u32::MAX)) as u32
            } else {
                successful[middle]
            }
        });
        let packet_loss_percent = (initial_sample_ready && !successful.is_empty()).then(|| {
            let lost = current
                .probes
                .iter()
                .filter(|probe| probe.is_none())
                .count();
            ((lost * 100 + current.probes.len() / 2) / current.probes.len()).min(100) as u8
        });
        Some(ConnectionMetricsResponse {
            received_bytes: current.received_bytes,
            sent_bytes: current.sent_bytes,
            latency_ms,
            packet_loss_percent,
        })
    }

    pub async fn clear(&self) {
        *self.session.lock().await = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn aggregates_session_counters_restarts_and_probe_loss() {
        let tracker = ConnectionMetricsTracker::new();
        tracker
            .record(
                "lease",
                TunnelMetrics {
                    received_bytes: 100,
                    sent_bytes: 40,
                    latest_handshake_epoch_millis: None,
                    probe_target: None,
                },
                Some(Some(20)),
            )
            .await;
        tracker
            .record(
                "lease",
                TunnelMetrics {
                    received_bytes: 5,
                    sent_bytes: 2,
                    latest_handshake_epoch_millis: None,
                    probe_target: None,
                },
                Some(None),
            )
            .await;
        tracker
            .record(
                "lease",
                TunnelMetrics {
                    received_bytes: 5,
                    sent_bytes: 2,
                    latest_handshake_epoch_millis: None,
                    probe_target: None,
                },
                Some(Some(22)),
            )
            .await;

        let metrics = tracker.snapshot("lease").await.expect("session metrics");
        assert_eq!(metrics.received_bytes, 105);
        assert_eq!(metrics.sent_bytes, 42);
        assert_eq!(metrics.latency_ms, Some(21));
        assert_eq!(metrics.packet_loss_percent, Some(33));
    }

    #[tokio::test]
    async fn changing_lease_resets_the_session() {
        let tracker = ConnectionMetricsTracker::new();
        tracker
            .record(
                "first",
                TunnelMetrics {
                    received_bytes: 100,
                    ..TunnelMetrics::default()
                },
                None,
            )
            .await;
        tracker
            .record(
                "second",
                TunnelMetrics {
                    received_bytes: 3,
                    ..TunnelMetrics::default()
                },
                None,
            )
            .await;

        assert!(tracker.snapshot("first").await.is_none());
        assert_eq!(tracker.snapshot("second").await.unwrap().received_bytes, 3);
    }

    #[tokio::test]
    async fn reports_unavailable_loss_until_a_probe_succeeds() {
        let tracker = ConnectionMetricsTracker::new();
        tracker
            .record(
                "lease",
                TunnelMetrics {
                    ..TunnelMetrics::default()
                },
                Some(None),
            )
            .await;

        let metrics = tracker.snapshot("lease").await.unwrap();
        assert_eq!(metrics.latency_ms, None);
        assert_eq!(metrics.packet_loss_percent, None);
    }

    #[tokio::test]
    async fn waits_for_three_probes_and_uses_median_latency() {
        let tracker = ConnectionMetricsTracker::new();
        for latency in [Some(480), Some(31)] {
            tracker
                .record("lease", TunnelMetrics::default(), Some(latency))
                .await;
        }
        assert_eq!(tracker.snapshot("lease").await.unwrap().latency_ms, None);

        tracker
            .record("lease", TunnelMetrics::default(), Some(Some(29)))
            .await;
        let metrics = tracker.snapshot("lease").await.unwrap();
        assert_eq!(metrics.latency_ms, Some(31));
        assert_eq!(metrics.packet_loss_percent, Some(0));
    }

    #[tokio::test]
    async fn collection_activity_expires_without_a_visible_client() {
        let tracker = ConnectionMetricsTracker::new();
        assert!(!tracker.is_observed().await);
        tracker.mark_observed().await;
        assert!(tracker.is_observed().await);
        *tracker.last_observed_at.lock().await = Some(Instant::now() - OBSERVATION_TTL);
        assert!(!tracker.is_observed().await);
    }

    #[test]
    fn stall_recovery_limiter_prevents_loops_and_resets_for_a_new_lease() {
        let mut limiter = StallRecoveryLimiter::default();

        assert!(limiter.begin_attempt("lease-a", 1_000));
        assert!(limiter.begin_attempt("lease-a", 1_100));
        assert!(!limiter.begin_attempt("lease-a", 1_200));
        assert_eq!(limiter.next_attempt_at_unix("lease-a"), Some(1_600));
        assert!(limiter.begin_attempt("lease-a", 1_600));
        assert!(limiter.begin_attempt("lease-a", 1_700));
        assert!(limiter.begin_attempt("lease-b", 1_201));

        limiter.reset();
        assert!(limiter.begin_attempt("lease-b", 1_202));
        assert_eq!(limiter.attempts.len(), 1);
    }

    #[test]
    fn stall_recovery_limiter_does_not_charge_cancelled_attempts() {
        let mut limiter = StallRecoveryLimiter::default();

        assert!(limiter.begin_attempt("lease-a", 1_000));
        limiter.cancel_attempt("lease-a", 1_000);
        assert!(limiter.begin_attempt("lease-a", 1_001));
        limiter.cancel_attempt("lease-a", 1_001);

        assert!(limiter.begin_attempt("lease-a", 1_002));
        assert!(limiter.begin_attempt("lease-a", 1_003));
        assert!(!limiter.begin_attempt("lease-a", 1_004));
    }
}
