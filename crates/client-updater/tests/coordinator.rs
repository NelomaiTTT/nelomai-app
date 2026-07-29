use async_trait::async_trait;
use nelomai_client_updater::{
    DownloadProgress, InstallResult, InstalledUpdate, UpdateBackend, UpdateBackendError,
    UpdateCoordinator, UpdateOffer, UpdatePhase, UpdatePreferences,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

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
        _access_token: &str,
        expected_version: &str,
        progress: Arc<dyn Fn(DownloadProgress) + Send + Sync>,
    ) -> Result<InstallResult, UpdateBackendError> {
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
    let coordinator = UpdateCoordinator::new(backend.clone());
    coordinator.observe(Some(offer()));

    let phase = coordinator
        .install_automatically("access-secret", UpdatePreferences { automatic: false })
        .await
        .unwrap();

    assert_eq!(phase, UpdatePhase::Available(offer()));
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn automatic_update_reports_progress_and_finishes_once() {
    let backend = Arc::new(RecordingBackend::new(Duration::ZERO));
    let coordinator = UpdateCoordinator::new(backend.clone());
    coordinator.observe(Some(offer()));

    let phase = coordinator
        .install_automatically("access-secret", UpdatePreferences::default())
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
}

#[tokio::test]
async fn concurrent_manual_install_requests_share_one_backend_operation() {
    let backend = Arc::new(RecordingBackend::new(Duration::from_millis(10)));
    let coordinator = Arc::new(UpdateCoordinator::new(backend.clone()));
    coordinator.observe(Some(offer()));

    let first = {
        let coordinator = coordinator.clone();
        tokio::spawn(async move { coordinator.install_now("access-secret").await })
    };
    let second = {
        let coordinator = coordinator.clone();
        tokio::spawn(async move { coordinator.install_now("access-secret").await })
    };
    let (first, second) = tokio::join!(first, second);

    assert_eq!(first.unwrap().unwrap(), second.unwrap().unwrap());
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn newer_offer_is_installed_after_an_older_version_is_ready() {
    let backend = Arc::new(RecordingBackend::new(Duration::ZERO));
    let coordinator = UpdateCoordinator::new(backend.clone());
    coordinator.observe(Some(offer_for("0.2.0")));

    assert_eq!(
        coordinator.install_now("access-secret").await.unwrap(),
        UpdatePhase::ReadyToRestart {
            version: "0.2.0".to_string()
        }
    );

    coordinator.observe(Some(offer_for("0.3.0")));
    assert_eq!(
        coordinator.install_now("access-secret").await.unwrap(),
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
    let coordinator = UpdateCoordinator::new(backend);
    coordinator.observe(Some(offer_for("0.2.0")));

    let error = coordinator.install_now("access-secret").await.unwrap_err();

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
}

#[tokio::test]
async fn android_installer_state_is_stable_until_the_app_is_replaced() {
    let backend = Arc::new(RecordingBackend::opening_installer());
    let coordinator = UpdateCoordinator::new(backend.clone());
    coordinator.observe(Some(offer()));

    let phase = coordinator.install_now("access-secret").await.unwrap();

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
            .install_automatically("access-secret", UpdatePreferences::default())
            .await
            .unwrap(),
        phase
    );
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);

    assert_eq!(
        coordinator.install_now("access-secret").await.unwrap(),
        phase
    );
    assert_eq!(backend.calls.load(Ordering::SeqCst), 2);
}
