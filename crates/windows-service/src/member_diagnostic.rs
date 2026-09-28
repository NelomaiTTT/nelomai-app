//! Bounded pair failure metadata. Never format arbitrary native errors, paths,
//! configuration, addresses or credentials into service diagnostics.
#![cfg_attr(not(windows), allow(dead_code))]
use std::io;

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("stage={stage}; origin={origin}; cause={cause}; native_status={status:?}")]
pub struct PairFailure {
    stage: &'static str,
    origin: &'static str,
    cause: &'static str,
    status: Option<i64>,
}

impl PairFailure {
    pub(crate) fn io(stage: &'static str, error: io::Error) -> Self {
        if let Some(previous) = error.get_ref().and_then(|e| e.downcast_ref::<Self>()) {
            return Self {
                stage,
                ..previous.clone()
            };
        }
        let cause = match error.kind() {
            io::ErrorKind::PermissionDenied => "permission_denied",
            io::ErrorKind::NotFound => "not_found",
            io::ErrorKind::InvalidData => "invalid_data",
            io::ErrorKind::InvalidInput => "invalid_input",
            io::ErrorKind::TimedOut => "timed_out",
            io::ErrorKind::WouldBlock => "would_block",
            io::ErrorKind::AlreadyExists => "already_exists",
            io::ErrorKind::Unsupported => "unsupported",
            io::ErrorKind::BrokenPipe => "broken_pipe",
            io::ErrorKind::Interrupted => "interrupted",
            io::ErrorKind::WriteZero => "write_zero",
            _ => "io_failure",
        };
        Self {
            stage,
            origin: stage,
            cause,
            status: error.raw_os_error().map(i64::from),
        }
    }
    fn coded(stage: &'static str, cause: &'static str, status: Option<u32>) -> io::Error {
        io::Error::other(Self {
            stage,
            origin: stage,
            cause,
            status: status.map(i64::from),
        })
    }
    pub(crate) fn guard(stage: &'static str, error: crate::member_guard::GuardError) -> io::Error {
        use crate::member_guard::GuardError::*;
        let cause = match error {
            Invalid => "guard_invalid",
            Conflict => "guard_conflict",
            EpochLost => "guard_epoch_lost",
            RemovalUnconfirmed => "guard_removal_unconfirmed",
            Native(_) => "guard_native",
        };
        Self::coded(
            stage,
            cause,
            if let Native(status) = error {
                Some(status)
            } else {
                None
            },
        )
    }
    pub(crate) fn dns(stage: &'static str, error: crate::member_dns::DnsError) -> io::Error {
        use crate::member_dns::DnsError::*;
        let cause = match error {
            Invalid => "dns_invalid",
            Ipv6Unsupported => "dns_ipv6_unsupported",
            Unsupported => "dns_settings_unsupported",
            Ownership => "dns_ownership_conflict",
            Conflict => "dns_compare_conflict",
            Indeterminate => "dns_indeterminate",
            Native(_) => "dns_native",
        };
        Self::coded(
            stage,
            cause,
            if let Native(status) = error {
                Some(status)
            } else {
                None
            },
        )
    }
    pub(crate) fn owner(stage: &'static str, error: crate::member_owner::OwnerError) -> io::Error {
        use crate::member_owner::OwnerError::*;
        Self::coded(
            stage,
            match error {
                Invalid => "owner_invalid",
                Conflict => "owner_conflict",
                Pending => "owner_pending",
                Retired => "owner_retired",
                Native => "owner_native",
                Journal => "owner_journal",
            },
            None,
        )
    }
    pub(crate) fn plan(error: crate::member_plan::PlanError) -> io::Error {
        use crate::member_plan::PlanError::*;
        Self::coded(
            "route_plan",
            match error {
                Invalid => "route_plan_invalid",
                TooLarge => "route_plan_too_large",
                MissingMetric { .. } => "route_missing_metric",
                UnequalMemberMetrics { .. } => "route_unequal_metrics",
                MissingPhysicalProbe(_) => "route_missing_physical_probe",
                MissingExclusion(_) => "route_missing_exclusion",
                UnsupportedMetric(_) => "route_unsupported_metric",
                Conflict => "route_conflict",
            },
            None,
        )
    }
}

pub(crate) fn context(stage: &'static str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), PairFailure::io(stage, error))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nested_context_keeps_native_status_and_origin_without_raw_text() {
        let error = PairFailure::guard(
            "guard_apply",
            crate::member_guard::GuardError::Native(0x80320009),
        );
        let error = PairFailure::io("start", context("activate", error));
        let error = crate::ServiceError::PairOperation(error);
        assert_eq!(error.code(), "redundant_actor_failed");
        let text = error.to_string();
        assert!(text.contains("stage=start"));
        assert!(text.contains("origin=guard_apply"));
        assert!(text.contains("cause=guard_native"));
        assert!(text.contains("2150760457"));
    }
    #[test]
    fn untrusted_native_text_and_route_addresses_are_not_logged() {
        let error = io::Error::other("PrivateKey=private; endpoint=192.0.2.11; C:/secret");
        let text = PairFailure::io("start", error).to_string();
        assert!(text.contains("cause=io_failure"));
        assert!(!text.contains("private") && !text.contains("secret") && !text.contains("192.0.2"));
        let text = PairFailure::plan(crate::member_plan::PlanError::UnsupportedMetric(
            "192.0.2.11/32".parse().unwrap(),
        ))
        .to_string();
        assert!(text.contains("route_unsupported_metric") && !text.contains("192.0.2"));
    }
    #[test]
    fn raw_os_status_survives_without_os_message() {
        let failure = PairFailure::io("route_apply", io::Error::from_raw_os_error(5));
        assert_eq!(failure.status, Some(5));
        assert_eq!(failure.origin, "route_apply");
    }
    #[test]
    fn annotation_preserves_io_control_flow_kind() {
        let failure = context(
            "pair_journal",
            io::Error::new(io::ErrorKind::WriteZero, "private disk path"),
        );
        assert_eq!(failure.kind(), io::ErrorKind::WriteZero);
        assert!(failure.to_string().contains("write_zero"));
        assert!(!failure.to_string().contains("private"));
    }
}
