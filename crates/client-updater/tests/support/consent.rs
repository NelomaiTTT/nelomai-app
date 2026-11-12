use async_trait::async_trait;
use nelomai_client_api::AccessSnapshot;
use nelomai_client_updater::*;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use tokio::sync::Notify;
fn access() -> AccessSnapshot {
    AccessSnapshot::new(
        "secret".into(),
        nelomai_contracts::RuntimeIdentity {
            container_version: "0.4.0".into(),
            runtime_version: "0.4.0".into(),
            runtime_contract_version: 1,
            slot: nelomai_contracts::RuntimeSlot::Latest,
            session_generation: Some(7),
        },
        4,
        "test-family".into(),
    )
    .unwrap()
}
fn descriptor() -> ResolvedUpdate {
    ResolvedUpdate {
        version: "0.4.1".into(),
        target: "synthetic-target".into(),
        artifact_url: "https://nelomai.ru/api/client/v1/updates/artifacts/test".into(),
        signature: "test-signature".into(),
        key_identity: "test-key".into(),
        sha256: None,
        size_bytes: None,
    }
}
fn offer() -> UpdateOffer {
    UpdateOffer {
        version: "0.4.1".into(),
        notes: None,
        required: false,
    }
}
struct Backend {
    current: Mutex<Option<ResolvedUpdate>>,
    downloads: AtomicUsize,
    installs: AtomicUsize,
    block: AtomicBool,
    started: Notify,
    release: Notify,
    fail_download: AtomicBool,
    remove_after_prepare: AtomicBool,
    install_block: AtomicBool,
    install_started: Notify,
    install_release: Notify,
    dir: tempfile::TempDir,
    result: Mutex<Option<Result<InstallResult, UpdateBackendError>>>,
}
impl Backend {
    fn new() -> Self {
        Self {
            current: Mutex::new(Some(descriptor())),
            downloads: AtomicUsize::new(0),
            installs: AtomicUsize::new(0),
            block: AtomicBool::new(false),
            started: Notify::new(),
            install_block: AtomicBool::new(false),
            install_started: Notify::new(),
            install_release: Notify::new(),
            release: Notify::new(),
            fail_download: AtomicBool::new(false),
            remove_after_prepare: AtomicBool::new(false),
            dir: tempfile::tempdir().unwrap(),
            result: Mutex::new(None),
        }
    }
}
#[async_trait]
impl UpdateBackend for Backend {
    async fn resolve(
        &self,
        _: &AccessSnapshot,
        _: &str,
    ) -> Result<Option<ResolvedUpdate>, UpdateBackendError> {
        Ok(self.current.lock().unwrap().clone())
    }
    async fn prepare(
        &self,
        _: &AccessSnapshot,
        resolved: &ResolvedUpdate,
        _: Arc<dyn Fn(DownloadProgress) + Send + Sync>,
    ) -> Result<PreparedUpdate, UpdateBackendError> {
        self.downloads.fetch_add(1, Ordering::SeqCst);
        self.started.notify_one();
        if self.block.load(Ordering::SeqCst) {
            self.release.notified().await;
        }
        if self.fail_download.load(Ordering::SeqCst) {
            return Err(UpdateBackendError::new("download_failed"));
        }
        let path = self.dir.path().join("verified-package");
        std::fs::write(&path, b"verified-test-payload").unwrap();
        let prepared = PreparedUpdate::from_verified_file(resolved.clone(), path)?;
        if self.remove_after_prepare.load(Ordering::SeqCst) {
            std::fs::remove_file(prepared.path()).unwrap();
        }
        Ok(prepared)
    }
    async fn install_prepared(
        &self,
        prepared: &PreparedUpdate,
        barrier: UpdateBarrierPhase,
    ) -> Result<InstallResult, UpdateBackendError> {
        assert_eq!(barrier, UpdateBarrierPhase::LocalStopped);
        prepared.revalidate()?;
        self.installs.fetch_add(1, Ordering::SeqCst);
        self.install_started.notify_one();
        if self.install_block.load(Ordering::SeqCst) {
            self.install_release.notified().await;
        }
        if let Some(result) = self.result.lock().unwrap().clone() {
            return result;
        }
        Ok(InstallResult::Installed(InstalledUpdate {
            version: prepared.resolved().version.clone(),
        }))
    }
}
#[derive(Default)]
struct Barrier {
    stops: AtomicUsize,
    opened: AtomicUsize,
    failed: AtomicUsize,
    reject: AtomicBool,
    stale: AtomicBool,
    reject_opened: AtomicBool,
    reject_failed: AtomicBool,
    block: AtomicBool,
    started: Notify,
    release: Notify,
    stale_after_stop: AtomicBool,
}
#[async_trait]
impl UpdateInstallBarrier for Barrier {
    async fn validate_authority(&self, _: &AccessSnapshot) -> Result<(), UpdateBarrierError> {
        if self.stale.load(Ordering::SeqCst) {
            Err(UpdateBarrierError::new("stale_auth"))
        } else {
            Ok(())
        }
    }
    async fn prepare(&self, _: &str) -> Result<UpdateBarrierPhase, UpdateBarrierError> {
        self.stops.fetch_add(1, Ordering::SeqCst);
        self.started.notify_one();
        if self.block.load(Ordering::SeqCst) {
            self.release.notified().await;
        }
        if self.stale_after_stop.load(Ordering::SeqCst) {
            self.stale.store(true, Ordering::SeqCst);
        }
        if self.reject.load(Ordering::SeqCst) {
            Err(UpdateBarrierError::new("stop_failed"))
        } else {
            Ok(UpdateBarrierPhase::LocalStopped)
        }
    }
    async fn installer_opened(&self) -> Result<(), UpdateBarrierError> {
        if self.reject_opened.load(Ordering::SeqCst) {
            return Err(UpdateBarrierError::new("update_journal_failed"));
        }
        self.opened.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn installer_failed(&self) -> Result<(), UpdateBarrierError> {
        if self.reject_failed.load(Ordering::SeqCst) {
            return Err(UpdateBarrierError::new("update_recovery_failed"));
        }
        self.failed.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
fn setup() -> (
    Arc<UpdateCoordinator<Backend>>,
    Arc<Backend>,
    Arc<Barrier>,
    String,
) {
    let backend = Arc::new(Backend::new());
    let barrier = Arc::new(Barrier::default());
    let owner = Arc::new(UpdateCoordinator::new(backend.clone(), barrier.clone()));
    owner.observe_resolved(Some((offer(), descriptor())), &access());
    let id = owner.offer_id().unwrap();
    (owner, backend, barrier, id)
}
