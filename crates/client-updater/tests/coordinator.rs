use async_trait::async_trait;
use nelomai_client_api::AccessSnapshot;

fn access() -> AccessSnapshot {
    AccessSnapshot::new(
        "access-secret".into(),
        nelomai_contracts::RuntimeIdentity {
            container_version: "0.2.16".into(),
            runtime_version: "0.2.15".into(),
            runtime_contract_version: 1,
            slot: nelomai_contracts::RuntimeSlot::Stable,
            session_generation: Some(7),
        },
        4,
        "synthetic-family".into(),
    )
    .unwrap()
}
use nelomai_client_updater::{
    DownloadProgress, InstallResult, InstalledUpdate, UpdateBackend, UpdateBackendError,
    UpdateBarrierError, UpdateBarrierPhase, UpdateCoordinator, UpdateInstallBarrier, UpdateOffer,
    UpdatePhase, UpdatePreferences,
};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Duration;
use tokio::sync::Notify;

#[derive(Default)]
struct RecordingBarrier {
    prepares: Mutex<Vec<String>>,
    opened: AtomicUsize,
    failed: AtomicUsize,
    prepare_started: Notify,
    prepare_released: AtomicBool,
    prepare_release: Notify,
    blocked: AtomicBool,
    reject_prepare: AtomicBool,
    reject_opened: AtomicBool,
    reject_failed: AtomicBool,
}

impl RecordingBarrier {
    fn released() -> Self {
        Self {
            prepare_released: AtomicBool::new(true),
            ..Self::default()
        }
    }

    fn release_prepare(&self) {
        self.prepare_released.store(true, Ordering::SeqCst);
        self.prepare_release.notify_waiters();
    }
}

#[async_trait]
impl UpdateInstallBarrier for RecordingBarrier {
    async fn prepare(
        &self,
        target_version: &str,
    ) -> Result<UpdateBarrierPhase, UpdateBarrierError> {
        self.prepares
            .lock()
            .unwrap()
            .push(target_version.to_owned());
        self.prepare_started.notify_one();
        while !self.prepare_released.load(Ordering::SeqCst) {
            self.prepare_release.notified().await;
        }
        if self.reject_prepare.load(Ordering::SeqCst) {
            return Err(UpdateBarrierError::new("update_barrier_prepare_failed"));
        }
        self.blocked.store(true, Ordering::SeqCst);
        Ok(UpdateBarrierPhase::LocalStopped)
    }

    async fn installer_opened(&self) -> Result<(), UpdateBarrierError> {
        assert!(self.blocked.load(Ordering::SeqCst));
        if self.reject_opened.load(Ordering::SeqCst) {
            return Err(UpdateBarrierError::new("update_journal_failed"));
        }
        self.opened.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn installer_failed(&self) -> Result<(), UpdateBarrierError> {
        assert!(self.blocked.load(Ordering::SeqCst));
        if self.reject_failed.load(Ordering::SeqCst) {
            return Err(UpdateBarrierError::new("update_recovery_failed"));
        }
        self.failed.fetch_add(1, Ordering::SeqCst);
        self.blocked.store(false, Ordering::SeqCst);
        Ok(())
    }
}

fn coordinator<B: UpdateBackend>(backend: Arc<B>) -> (UpdateCoordinator<B>, Arc<RecordingBarrier>) {
    let barrier = Arc::new(RecordingBarrier::released());
    (UpdateCoordinator::new(backend, barrier.clone()), barrier)
}

struct RecordingBackend {
    calls: AtomicUsize,
    delay: Duration,
    expected_versions: Mutex<Vec<String>>,
    installed_version: Option<String>,
    opens_installer: bool,
}

impl RecordingBackend {
    fn new(delay: Duration) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            delay,
            expected_versions: Mutex::new(Vec::new()),
            installed_version: None,
            opens_installer: false,
        }
    }

    fn returning(version: &str) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            delay: Duration::ZERO,
            expected_versions: Mutex::new(Vec::new()),
            installed_version: Some(version.to_string()),
            opens_installer: false,
        }
    }

    fn opening_installer() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            delay: Duration::ZERO,
            expected_versions: Mutex::new(Vec::new()),
            installed_version: None,
            opens_installer: true,
        }
    }
}

#[async_trait]
impl UpdateBackend for RecordingBackend {
    async fn install(
        &self,
        access_token: &AccessSnapshot,
        expected_version: &str,
        barrier: UpdateBarrierPhase,
        progress: Arc<dyn Fn(DownloadProgress) + Send + Sync>,
    ) -> Result<InstallResult, UpdateBackendError> {
        assert_eq!(barrier, UpdateBarrierPhase::LocalStopped);
        assert_eq!(access_token.bearer_headers(), access().bearer_headers());
        assert_eq!(access_token.auth_epoch(), 4);
        assert_eq!(access_token.family(), "synthetic-family");
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.expected_versions
            .lock()
            .unwrap()
            .push(expected_version.to_string());
        progress(DownloadProgress {
            downloaded: 32,
            total: Some(128),
        });
        tokio::time::sleep(self.delay).await;
        let installed = InstalledUpdate {
            version: self
                .installed_version
                .clone()
                .unwrap_or_else(|| expected_version.to_string()),
        };
        Ok(if self.opens_installer {
            InstallResult::InstallerOpened(installed)
        } else {
            InstallResult::Installed(installed)
        })
    }
}

struct BlockingBackend {
    calls: AtomicUsize,
    started: Notify,
    released: AtomicBool,
    release: Notify,
    opens_installer: bool,
}

impl BlockingBackend {
    fn installed() -> Self {
        Self::new(false)
    }

    fn opening_installer() -> Self {
        Self::new(true)
    }

    fn new(opens_installer: bool) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            started: Notify::new(),
            released: AtomicBool::new(false),
            release: Notify::new(),
            opens_installer,
        }
    }

    fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
        self.release.notify_waiters();
    }
}

#[async_trait]
impl UpdateBackend for BlockingBackend {
    async fn install(
        &self,
        _access_token: &AccessSnapshot,
        expected_version: &str,
        barrier: UpdateBarrierPhase,
        _progress: Arc<dyn Fn(DownloadProgress) + Send + Sync>,
    ) -> Result<InstallResult, UpdateBackendError> {
        assert_eq!(barrier, UpdateBarrierPhase::LocalStopped);
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.started.notify_one();
        while !self.released.load(Ordering::SeqCst) {
            self.release.notified().await;
        }
        let installed = InstalledUpdate {
            version: expected_version.to_string(),
        };
        Ok(if self.opens_installer {
            InstallResult::InstallerOpened(installed)
        } else {
            InstallResult::Installed(installed)
        })
    }
}

fn offer() -> UpdateOffer {
    offer_for("0.2.0")
}

fn offer_for(version: &str) -> UpdateOffer {
    UpdateOffer {
        version: version.to_string(),
        notes: Some("Исправлена работа туннеля.".to_string()),
        required: false,
    }
}

#[tokio::test]
async fn disabled_automatic_updates_keep_the_offer_available() {
    let backend = Arc::new(RecordingBackend::new(Duration::ZERO));
    let (coordinator, barrier) = coordinator(backend.clone());
    coordinator.observe(Some(offer()));

    let phase = coordinator
        .install_automatically(&access(), UpdatePreferences { automatic: false })
        .await
        .unwrap();

    assert_eq!(phase, UpdatePhase::Available(offer()));
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
    assert!(barrier.prepares.lock().unwrap().is_empty());
}

#[tokio::test]
async fn automatic_update_reports_progress_and_finishes_once() {
    let backend = Arc::new(RecordingBackend::new(Duration::ZERO));
    let (coordinator, barrier) = coordinator(backend.clone());
    coordinator.observe(Some(offer()));

    let phase = coordinator
        .install_automatically(&access(), UpdatePreferences::default())
        .await
        .unwrap();

    assert_eq!(
        phase,
        UpdatePhase::ReadyToRestart {
            version: "0.2.0".to_string()
        }
    );
    assert_eq!(coordinator.phase(), phase);
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        backend.expected_versions.lock().unwrap().as_slice(),
        ["0.2.0"]
    );
    assert_eq!(barrier.opened.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn concurrent_automatic_installs_call_backend_once_after_install() {
    let backend = Arc::new(BlockingBackend::installed());
    let (coordinator, barrier) = coordinator(backend.clone());
    let coordinator = Arc::new(coordinator);
    coordinator.observe(Some(offer()));

    let first = {
        let coordinator = coordinator.clone();
        tokio::spawn(async move {
            coordinator
                .install_automatically(&access(), UpdatePreferences::default())
                .await
        })
    };
    backend.started.notified().await;
    let second = {
        let coordinator = coordinator.clone();
        tokio::spawn(async move {
            coordinator
                .install_automatically(&access(), UpdatePreferences::default())
                .await
        })
    };
    tokio::task::yield_now().await;
    backend.release();

    let (first, second) = tokio::join!(first, second);
    let expected = UpdatePhase::ReadyToRestart {
        version: "0.2.0".to_string(),
    };
    assert_eq!(first.unwrap().unwrap(), expected);
    assert_eq!(second.unwrap().unwrap(), expected);
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    assert_eq!(barrier.opened.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn concurrent_automatic_installs_open_android_installer_once() {
    let backend = Arc::new(BlockingBackend::opening_installer());
    let (coordinator, barrier) = coordinator(backend.clone());
    let coordinator = Arc::new(coordinator);
    coordinator.observe(Some(offer()));

    let first = {
        let coordinator = coordinator.clone();
        tokio::spawn(async move {
            coordinator
                .install_automatically(&access(), UpdatePreferences::default())
                .await
        })
    };
    backend.started.notified().await;
    let second = {
        let coordinator = coordinator.clone();
        tokio::spawn(async move {
            coordinator
                .install_automatically(&access(), UpdatePreferences::default())
                .await
        })
    };
    tokio::task::yield_now().await;
    backend.release();

    let (first, second) = tokio::join!(first, second);
    let expected = UpdatePhase::AwaitingInstallation {
        version: "0.2.0".to_string(),
    };
    assert_eq!(first.unwrap().unwrap(), expected);
    assert_eq!(second.unwrap().unwrap(), expected);
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    assert_eq!(barrier.opened.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn concurrent_manual_install_requests_share_one_backend_operation() {
    let backend = Arc::new(RecordingBackend::new(Duration::from_millis(10)));
    let (coordinator, _) = coordinator(backend.clone());
    let coordinator = Arc::new(coordinator);
    coordinator.observe(Some(offer()));

    let first = {
        let coordinator = coordinator.clone();
        tokio::spawn(async move { coordinator.install_now(&access()).await })
    };
    let second = {
        let coordinator = coordinator.clone();
        tokio::spawn(async move { coordinator.install_now(&access()).await })
    };
    let (first, second) = tokio::join!(first, second);

    assert_eq!(first.unwrap().unwrap(), second.unwrap().unwrap());
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn newer_offer_is_installed_after_an_older_version_is_ready() {
    let backend = Arc::new(RecordingBackend::new(Duration::ZERO));
    let (coordinator, _) = coordinator(backend.clone());
    coordinator.observe(Some(offer_for("0.2.0")));

    assert_eq!(
        coordinator.install_now(&access()).await.unwrap(),
        UpdatePhase::ReadyToRestart {
            version: "0.2.0".to_string()
        }
    );

    coordinator.observe(Some(offer_for("0.3.0")));
    assert_eq!(
        coordinator.install_now(&access()).await.unwrap(),
        UpdatePhase::ReadyToRestart {
            version: "0.3.0".to_string()
        }
    );
    assert_eq!(backend.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        backend.expected_versions.lock().unwrap().as_slice(),
        ["0.2.0", "0.3.0"]
    );
}

#[tokio::test]
async fn backend_cannot_mark_an_unexpected_version_as_installed() {
    let backend = Arc::new(RecordingBackend::returning("9.9.9"));
    let (coordinator, barrier) = coordinator(backend);
    coordinator.observe(Some(offer_for("0.2.0")));

    let error = coordinator.install_now(&access()).await.unwrap_err();

    assert_eq!(
        error.to_string(),
        "update backend failed: installed_update_version_mismatch"
    );
    assert_eq!(
        coordinator.phase(),
        UpdatePhase::Failed {
            version: "0.2.0".to_string(),
            code: "installed_update_version_mismatch".to_string(),
        }
    );
    assert_eq!(barrier.failed.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn android_installer_state_is_stable_until_the_app_is_replaced() {
    let backend = Arc::new(RecordingBackend::opening_installer());
    let (coordinator, barrier) = coordinator(backend.clone());
    coordinator.observe(Some(offer()));

    let phase = coordinator.install_now(&access()).await.unwrap();

    assert_eq!(
        phase,
        UpdatePhase::AwaitingInstallation {
            version: "0.2.0".to_string()
        }
    );
    coordinator.observe(Some(offer()));
    assert_eq!(coordinator.phase(), phase);
    assert_eq!(
        coordinator
            .install_automatically(&access(), UpdatePreferences::default())
            .await
            .unwrap(),
        phase
    );
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);

    assert_eq!(coordinator.install_now(&access()).await.unwrap(), phase);
    assert_eq!(backend.calls.load(Ordering::SeqCst), 2);
    assert_eq!(barrier.opened.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn backend_waits_until_the_shutdown_barrier_reports_local_stopped() {
    let backend = Arc::new(RecordingBackend::new(Duration::ZERO));
    let barrier = Arc::new(RecordingBarrier::default());
    let coordinator = Arc::new(UpdateCoordinator::new(backend.clone(), barrier.clone()));
    coordinator.observe(Some(offer()));

    let install = {
        let coordinator = coordinator.clone();
        tokio::spawn(async move { coordinator.install_now(&access()).await })
    };
    barrier.prepare_started.notified().await;
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);

    barrier.release_prepare();
    assert!(matches!(
        install.await.unwrap().unwrap(),
        UpdatePhase::ReadyToRestart { .. }
    ));
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    assert_eq!(barrier.prepares.lock().unwrap().as_slice(), ["0.2.0"]);
}

struct FailingBackend(AtomicUsize);

#[async_trait]
impl UpdateBackend for FailingBackend {
    async fn install(
        &self,
        _: &AccessSnapshot,
        _: &str,
        barrier: UpdateBarrierPhase,
        _: Arc<dyn Fn(DownloadProgress) + Send + Sync>,
    ) -> Result<InstallResult, UpdateBackendError> {
        assert_eq!(barrier, UpdateBarrierPhase::LocalStopped);
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(UpdateBackendError::new("synthetic_installer_failure"))
    }
}

struct NoUpdateBackend(AtomicUsize);

#[async_trait]
impl UpdateBackend for NoUpdateBackend {
    async fn install(
        &self,
        _: &AccessSnapshot,
        _: &str,
        barrier: UpdateBarrierPhase,
        _: Arc<dyn Fn(DownloadProgress) + Send + Sync>,
    ) -> Result<InstallResult, UpdateBackendError> {
        assert_eq!(barrier, UpdateBarrierPhase::LocalStopped);
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(InstallResult::NoUpdate)
    }
}

#[tokio::test]
async fn installer_error_cancels_the_shutdown_barrier_before_returning() {
    let backend = Arc::new(FailingBackend(AtomicUsize::new(0)));
    let (coordinator, barrier) = coordinator(backend.clone());
    coordinator.observe(Some(offer()));

    let error = coordinator.install_now(&access()).await.unwrap_err();

    assert_eq!(
        error.to_string(),
        "update backend failed: synthetic_installer_failure"
    );
    assert_eq!(backend.0.load(Ordering::SeqCst), 1);
    assert_eq!(barrier.failed.load(Ordering::SeqCst), 1);
    assert!(!barrier.blocked.load(Ordering::SeqCst));
}

#[tokio::test]
async fn no_update_cancels_the_barrier_without_marking_an_install() {
    let backend = Arc::new(NoUpdateBackend(AtomicUsize::new(0)));
    let (coordinator, barrier) = coordinator(backend.clone());
    coordinator.observe(Some(offer()));

    assert_eq!(
        coordinator.install_now(&access()).await.unwrap(),
        UpdatePhase::Idle
    );
    assert_eq!(backend.0.load(Ordering::SeqCst), 1);
    assert_eq!(barrier.failed.load(Ordering::SeqCst), 1);
    assert_eq!(barrier.opened.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn failed_prepare_never_invokes_the_backend() {
    let backend = Arc::new(RecordingBackend::new(Duration::ZERO));
    let barrier = Arc::new(RecordingBarrier::released());
    barrier.reject_prepare.store(true, Ordering::SeqCst);
    let coordinator = UpdateCoordinator::new(backend.clone(), barrier);
    coordinator.observe(Some(offer()));

    assert!(coordinator.install_now(&access()).await.is_err());
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn installer_journal_failure_is_reported_as_a_failed_phase() {
    let backend = Arc::new(RecordingBackend::new(Duration::ZERO));
    let barrier = Arc::new(RecordingBarrier::released());
    barrier.reject_opened.store(true, Ordering::SeqCst);
    let coordinator = UpdateCoordinator::new(backend.clone(), barrier);
    coordinator.observe(Some(offer()));

    assert!(coordinator.install_now(&access()).await.is_err());
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        coordinator.phase(),
        UpdatePhase::Failed {
            version: "0.2.0".into(),
            code: "update_journal_failed".into(),
        }
    );
}

#[tokio::test]
async fn rollback_failure_replaces_the_backend_error_in_the_failed_phase() {
    let backend = Arc::new(FailingBackend(AtomicUsize::new(0)));
    let barrier = Arc::new(RecordingBarrier::released());
    barrier.reject_failed.store(true, Ordering::SeqCst);
    let coordinator = UpdateCoordinator::new(backend, barrier);
    coordinator.observe(Some(offer()));

    assert!(coordinator.install_now(&access()).await.is_err());
    assert_eq!(
        coordinator.phase(),
        UpdatePhase::Failed {
            version: "0.2.0".into(),
            code: "update_recovery_failed".into(),
        }
    );
}
