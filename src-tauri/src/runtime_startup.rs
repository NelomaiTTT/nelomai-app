//! One scheduler launch after owner admission; a failed attempt remains retryable.
use nelomai_client_container::ipc::PrivateError;
use std::future::Future;
use tokio::sync::Mutex;

pub(crate) async fn request_ready(
    port: &nelomai_client_container::ipc::PrivateRuntimeAuthClient,
    diagnostics: &crate::diagnostics::AppDiagnostics,
) -> Result<(), PrivateError> {
    use nelomai_client_container::host::{HostRequestV1, HostResponseV1};
    match port.owner_request(HostRequestV1::RuntimeReady).await {
        Ok(HostResponseV1::Done) => Ok(()),
        Ok(_) => Err(PrivateError::Protocol),
        Err(error) => {
            diagnostics.record_named(
                "startup.runtime_recovery_required",
                None,
                None,
                Some(match error {
                    PrivateError::RecoveryRequired => "runtime_admission_pending",
                    PrivateError::Timeout => "runtime_admission_timeout",
                    PrivateError::Service => "runtime_admission_service_unavailable",
                    _ => "runtime_admission_rejected",
                }),
            );
            Err(error)
        }
    }
}

pub(crate) struct RuntimeStartup {
    start: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}
impl RuntimeStartup {
    pub fn new(start: impl FnOnce() + Send + 'static) -> Self {
        Self {
            start: Mutex::new(Some(Box::new(start))),
        }
    }
    pub async fn ensure_ready(
        &self,
        ready: impl Future<Output = Result<(), PrivateError>>,
    ) -> Result<(), PrivateError> {
        let mut start = self.start.lock().await;
        ready.await?;
        if let Some(start) = start.take() {
            start();
        }
        Ok(())
    }
    pub async fn recover<F, Fut>(&self, mut ready: F) -> Result<(), PrivateError>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<(), PrivateError>>,
    {
        let mut delay = 1;
        loop {
            match self.ensure_ready(ready()).await {
                Ok(()) => return Ok(()),
                Err(
                    PrivateError::RecoveryRequired | PrivateError::Service | PrivateError::Timeout,
                ) => {
                    tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
                    delay = (delay * 2).min(30);
                }
                Err(error) => return Err(error),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    fn fixture() -> (RuntimeStartup, Arc<AtomicUsize>) {
        let starts = Arc::new(AtomicUsize::new(0));
        let count = starts.clone();
        (
            RuntimeStartup::new(move || {
                count.fetch_add(1, Ordering::SeqCst);
            }),
            starts,
        )
    }
    #[tokio::test]
    async fn failed_admission_does_not_consume_scheduler_launch() {
        let (startup, starts) = fixture();
        assert!(startup
            .ensure_ready(async { Err(PrivateError::RecoveryRequired) })
            .await
            .is_err());
        assert_eq!(starts.load(Ordering::SeqCst), 0);
        startup.ensure_ready(async { Ok(()) }).await.unwrap();
        startup.ensure_ready(async { Ok(()) }).await.unwrap();
        assert_eq!(starts.load(Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn automatic_recovery_polls_pending_admission_until_ready() {
        let (startup, starts) = fixture();
        let mut attempts = 0;
        startup
            .recover(|| {
                attempts += 1;
                let pending = attempts == 1;
                async move {
                    if pending {
                        Err(PrivateError::RecoveryRequired)
                    } else {
                        Ok(())
                    }
                }
            })
            .await
            .unwrap();
        assert_eq!(attempts, 2);
        assert_eq!(starts.load(Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn replacement_or_closed_owner_never_launches_schedulers() {
        for error in [PrivateError::Closed, PrivateError::Cancelled] {
            let (startup, starts) = fixture();
            assert!(startup.recover(|| async { Err(error) }).await.is_err());
            assert_eq!(starts.load(Ordering::SeqCst), 0);
        }
    }
    #[tokio::test]
    async fn simultaneous_background_and_button_retry_launch_once() {
        let (startup, starts) = fixture();
        let (first, second) = tokio::join!(
            startup.ensure_ready(async {
                tokio::task::yield_now().await;
                Ok(())
            }),
            startup.ensure_ready(async { Ok(()) }),
        );
        first.unwrap();
        second.unwrap();
        assert_eq!(starts.load(Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn cancelled_wait_can_be_retried_without_losing_scheduler_launch() {
        let (startup, starts) = fixture();
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(1),
            startup.ensure_ready(std::future::pending())
        )
        .await
        .is_err());
        startup.ensure_ready(async { Ok(()) }).await.unwrap();
        assert_eq!(starts.load(Ordering::SeqCst), 1);
    }
}
