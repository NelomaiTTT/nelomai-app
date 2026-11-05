//! Timing policy for one retryable close attempt; no resource authority.
#![cfg_attr(not(windows), allow(dead_code))]
use std::{
    io,
    time::{Duration, Instant},
};

pub(crate) fn graceful_stop_timeout(
    deadline: Instant,
    now: Instant,
    withdrawn: bool,
) -> io::Result<Duration> {
    let rpc = Duration::from_secs(4);
    let remaining = deadline.saturating_duration_since(now);
    if withdrawn && remaining < rpc {
        // No Stop bytes sent: retain original worker/pipe for the next scoped
        // cleanup attempt instead of treating local work as an RPC failure.
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "worker_stop_retry_budget",
        ));
    }
    // Without positive DATA withdrawal preserve the existing fail-closed path,
    // including terminal handling of a zero RPC budget. Never retain forwarding.
    Ok(remaining.min(rpc))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unconfirmed_data_withdrawal_keeps_fail_closed_timeout_path() {
        let now = Instant::now();
        // No positive DATA deny ACK: do not turn the original terminal path
        // into a retry that leaves a potentially forwarding worker alive.
        assert_eq!(
            graceful_stop_timeout(now, now, false).unwrap(),
            Duration::ZERO
        );
        assert_eq!(
            graceful_stop_timeout(now + Duration::from_secs(2), now, false).unwrap(),
            Duration::from_secs(2)
        );
    }

    #[test]
    fn slow_cleanup_yields_before_graceful_stop_and_fresh_retry_can_send() {
        let start = Instant::now();
        let deadline = start + Duration::from_secs(7);
        for elapsed in [
            Duration::from_millis(3001),
            Duration::from_secs(7),
            Duration::from_secs(8),
        ] {
            let mut sent = false;
            let outcome =
                graceful_stop_timeout(deadline, start + elapsed, true).map(|_| sent = true);
            assert!(
                outcome.is_err(),
                "insufficient budget after {elapsed:?} cleanup"
            );
            assert!(
                !sent,
                "pending attempt must retain the original worker/pipe for retry"
            );
        }
        let retry = start + Duration::from_secs(8);
        assert_eq!(
            graceful_stop_timeout(retry + Duration::from_secs(7), retry, true).unwrap(),
            Duration::from_secs(4)
        );
    }

    #[test]
    fn graceful_stop_never_refreshes_attempt_deadline_or_exceeds_rpc_cap() {
        let start = Instant::now();
        let deadline = start + Duration::from_secs(7);
        assert_eq!(
            graceful_stop_timeout(deadline, start, true).unwrap(),
            Duration::from_secs(4)
        );
        assert_eq!(
            graceful_stop_timeout(deadline, start + Duration::from_secs(3), true).unwrap(),
            Duration::from_secs(4)
        );
        assert!(graceful_stop_timeout(
            deadline,
            start + Duration::from_secs(3) + Duration::from_nanos(1),
            true
        )
        .is_err());
        assert!(graceful_stop_timeout(deadline, deadline, true).is_err());
        assert!(graceful_stop_timeout(deadline, deadline + Duration::from_secs(1), true).is_err());
    }
}
