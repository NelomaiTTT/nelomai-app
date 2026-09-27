//! SCM lifecycle policy, with native status publication injected at the boundary.
use crate::ServiceError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Status {
    StartPending,
    Running,
    Stopped { failed: bool },
}

pub(crate) fn run(
    mut report: impl FnMut(Status) -> Result<(), ServiceError>,
    serve: impl FnOnce(&mut dyn FnMut(Status) -> Result<(), ServiceError>) -> Result<(), ServiceError>,
) -> Result<(), ServiceError> {
    let result = report(Status::StartPending).and_then(|()| serve(&mut report));
    let stopped = report(Status::Stopped {
        failed: result.is_err(),
    });
    // Preserve the startup/cleanup error even if SCM also rejects the final
    // publication. A successful run still reports a publication failure.
    result.and(stopped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_recovery_error_reports_failed_stopped() {
        let mut statuses = Vec::new();
        let result = run(
            |status| {
                statuses.push(status);
                Ok(())
            },
            |_| Err(ServiceError::Backend("dispatcher_recovery_pending".into())),
        );
        assert!(
            matches!(result, Err(ServiceError::Backend(ref code)) if code == "dispatcher_recovery_pending")
        );
        assert_eq!(
            statuses,
            [Status::StartPending, Status::Stopped { failed: true }]
        );
    }

    #[test]
    fn running_failure_and_clean_stop_have_distinct_exit_status() {
        for fail in [false, true] {
            let mut statuses = Vec::new();
            let result = run(
                |status| {
                    statuses.push(status);
                    Ok(())
                },
                |report| {
                    report(Status::Running)?;
                    if fail {
                        Err(ServiceError::InvalidRequest)
                    } else {
                        Ok(())
                    }
                },
            );
            assert_eq!(result.is_err(), fail);
            assert_eq!(
                statuses,
                [
                    Status::StartPending,
                    Status::Running,
                    Status::Stopped { failed: fail }
                ]
            );
        }
    }

    #[test]
    fn failed_start_pending_report_still_attempts_stopped_and_preserves_error() {
        let mut statuses = Vec::new();
        let result = run(
            |status| {
                statuses.push(status);
                if status == Status::StartPending {
                    Err(ServiceError::InvalidRequest)
                } else {
                    Err(ServiceError::UnauthorizedClient)
                }
            },
            |_| panic!("cannot serve after failed status publication"),
        );
        assert!(matches!(result, Err(ServiceError::InvalidRequest)));
        assert_eq!(
            statuses,
            [Status::StartPending, Status::Stopped { failed: true }]
        );
    }
}
