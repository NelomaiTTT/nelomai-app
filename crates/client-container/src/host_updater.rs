//! Common-owned updater. Runtime commands carry actions, never Bearer tokens,
//! download URLs, installer paths or signing identities.
use crate::ipc::PrivateError;
use crate::{AuthBroker, SwitchCoordinator, UpdateBarrier, UpdatePrepare};
use nelomai_client_api::{AccessSnapshot, ClientApi};
use nelomai_client_updater::{
    DownloadProgress, FileUpdatePreferenceStore, InstallResult, UpdateBackend, UpdateBackendError,
    UpdateBarrierError, UpdateBarrierPhase, UpdateCoordinator, UpdateInstallBarrier, UpdateOffer,
    UpdatePhase, UpdatePreferenceStore, UpdatePreferences,
};
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    sync::{Arc, Mutex},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostUpdateStatusV1 {
    pub supported: bool,
    pub automatic: bool,
    pub phase: String,
    pub version: Option<String>,
    pub notes: Option<String>,
    pub required: bool,
    pub downloaded: u64,
    pub total: Option<u64>,
    pub error_code: Option<String>,
}
struct Backend(Arc<dyn UpdateBackend>);
#[async_trait::async_trait]
impl UpdateBackend for Backend {
    async fn install(
        &self,
        access: &AccessSnapshot,
        version: &str,
        barrier: UpdateBarrierPhase,
        progress: Arc<dyn Fn(DownloadProgress) + Send + Sync>,
    ) -> Result<InstallResult, UpdateBackendError> {
        self.0.install(access, version, barrier, progress).await
    }
}
struct Barrier(Arc<UpdateBarrier>);
#[async_trait::async_trait]
impl UpdateInstallBarrier for Barrier {
    async fn prepare(&self, target: &str) -> Result<UpdateBarrierPhase, UpdateBarrierError> {
        match self
            .0
            .prepare(target)
            .await
            .map_err(|_| UpdateBarrierError::new("update_shutdown_failed"))?
        {
            UpdatePrepare::LocalStopped => Ok(UpdateBarrierPhase::LocalStopped),
        }
    }
    async fn installer_opened(&self) -> Result<(), UpdateBarrierError> {
        self.0
            .installer_opened()
            .await
            .map_err(|_| UpdateBarrierError::new("update_journal_failed"))
    }
    async fn installer_failed(&self) -> Result<(), UpdateBarrierError> {
        self.0
            .installer_failed()
            .await
            .map_err(|_| UpdateBarrierError::new("update_recovery_failed"))
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InstallKind {
    Automatic,
    Manual,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UpdateOperation {
    Idle,
    Refreshing { install_after: Option<InstallKind> },
    Installing,
}
pub(crate) struct HostUpdater {
    api: ClientApi,
    broker: Arc<AuthBroker>,
    preferences: FileUpdatePreferenceStore,
    current: Mutex<UpdatePreferences>,
    offer: Mutex<Option<UpdateOffer>>,
    coordinator: Option<UpdateCoordinator<Backend>>,
    barrier: Arc<UpdateBarrier>,
    version: String,
    operation: Mutex<UpdateOperation>,
    refresh_error: Mutex<Option<String>>,
}
impl HostUpdater {
    #[cfg(not(target_os = "android"))]
    pub fn stop_proof(
        &self,
        target: &str,
        phase: crate::UpdateJournalPhase,
    ) -> Result<crate::UpdateStopProof, PrivateError> {
        self.barrier
            .stop_proof(target, phase)
            .map_err(|_| PrivateError::RecoveryRequired)
    }
    #[cfg(not(target_os = "android"))]
    pub fn native_start_blocked(&self) -> Result<bool, PrivateError> {
        self.barrier
            .snapshot()
            .map(|journal| journal.is_some())
            .map_err(|_| PrivateError::RecoveryRequired)
    }
    pub fn new(
        root: &Path,
        api: ClientApi,
        broker: Arc<AuthBroker>,
        switch: Arc<SwitchCoordinator>,
        version: String,
        backend: Option<Arc<dyn UpdateBackend>>,
    ) -> Result<Self, PrivateError> {
        let preferences = FileUpdatePreferenceStore::new(root.join("updates/preferences.json"));
        let current = preferences
            .load()
            .map_err(|_| PrivateError::RecoveryRequired)?;
        let barrier =
            Arc::new(UpdateBarrier::open(switch).map_err(|_| PrivateError::RecoveryRequired)?);
        let coordinator = backend.map(|backend| {
            UpdateCoordinator::new(
                Arc::new(Backend(backend)),
                Arc::new(Barrier(barrier.clone())),
            )
        });
        Ok(Self {
            api,
            broker,
            preferences,
            current: Mutex::new(current),
            offer: Mutex::new(None),
            coordinator,
            barrier,
            version,
            operation: Mutex::new(UpdateOperation::Idle),
            refresh_error: Mutex::new(None),
        })
    }
    pub async fn recover(&self) -> Result<(), PrivateError> {
        self.barrier
            .recover(&self.version)
            .await
            .map_err(|_| PrivateError::RecoveryRequired)
    }
    pub fn status(&self) -> Result<HostUpdateStatusV1, PrivateError> {
        let automatic = self
            .current
            .lock()
            .map_err(|_| PrivateError::Closed)?
            .automatic;
        let offer = self.offer.lock().map_err(|_| PrivateError::Closed)?.clone();
        let phase = self
            .coordinator
            .as_ref()
            .map(|coordinator| coordinator.phase())
            .unwrap_or_else(|| {
                offer
                    .clone()
                    .map(UpdatePhase::Available)
                    .unwrap_or(UpdatePhase::Idle)
            });
        let operation = *self.operation.lock().map_err(|_| PrivateError::Closed)?;
        let install_preparing = matches!(
            operation,
            UpdateOperation::Refreshing {
                install_after: Some(_)
            } | UpdateOperation::Installing
        ) && !matches!(
            phase,
            UpdatePhase::Downloading { .. } | UpdatePhase::ReadyToRestart { .. }
        );
        let (phase, version, downloaded, total, phase_error_code) = match phase {
            UpdatePhase::Idle => ("idle", None, 0, None, None),
            UpdatePhase::Available(offer) => ("available", Some(offer.version), 0, None, None),
            UpdatePhase::Downloading {
                version,
                downloaded,
                total,
            } => ("downloading", Some(version), downloaded, total, None),
            UpdatePhase::ReadyToRestart { version } => {
                ("ready_to_restart", Some(version), 0, None, None)
            }
            UpdatePhase::AwaitingInstallation { version } => {
                ("awaiting_installation", Some(version), 0, None, None)
            }
            UpdatePhase::Failed { version, code } => ("failed", Some(version), 0, None, Some(code)),
        };
        let refreshing = matches!(
            operation,
            UpdateOperation::Refreshing {
                install_after: None
            }
        );
        let error_code = if refreshing {
            Some("update_refresh_pending".into())
        } else if install_preparing {
            Some("update_install_preparing".into())
        } else {
            phase_error_code.or_else(|| {
                self.refresh_error
                    .lock()
                    .ok()
                    .and_then(|error| error.clone())
            })
        };
        Ok(HostUpdateStatusV1 {
            supported: self.coordinator.is_some(),
            automatic,
            phase: phase.into(),
            version,
            notes: offer.as_ref().and_then(|offer| offer.notes.clone()),
            required: offer.as_ref().is_some_and(|offer| offer.required),
            downloaded,
            total,
            error_code,
        })
    }
    pub fn set_automatic(&self, automatic: bool) -> Result<HostUpdateStatusV1, PrivateError> {
        let mut current = self.current.lock().map_err(|_| PrivateError::Closed)?;
        let next = UpdatePreferences { automatic };
        self.preferences
            .save(next)
            .map_err(|_| PrivateError::RecoveryRequired)?;
        *current = next;
        drop(current);
        self.status()
    }
    async fn refresh(self: &Arc<Self>) -> Result<HostUpdateStatusV1, PrivateError> {
        let access = self
            .broker
            .access_token(None)
            .await
            .map_err(|_| PrivateError::RecoveryRequired)?;
        let response = self
            .api
            .clone()
            .with_access_snapshot(&access)
            .map_err(|_| PrivateError::RecoveryRequired)?
            .bootstrap(access.access_token())
            .await
            .map_err(|_| PrivateError::Service)?;
        let offer =
            UpdateOffer::from_state(&response.update).map_err(|_| PrivateError::Protocol)?;
        self.broker
            .with_current_access(&access, || {
                *self
                    .offer
                    .lock()
                    .map_err(|_| crate::BrokerError::RecoveryRequired)? = offer.clone();
                if let Some(coordinator) = &self.coordinator {
                    coordinator.observe(offer);
                }
                Ok(())
            })
            .await
            .map_err(|_| PrivateError::Cancelled)?;
        self.status()
    }
    /// Panel I/O may use the full HTTP request timeout, which is longer than
    /// the runtime IPC budget. Keep that work in the common owner and let the
    /// runtime poll status instead of holding its shared control channel.
    pub fn start_refresh(self: &Arc<Self>) -> Result<HostUpdateStatusV1, PrivateError> {
        let should_start = {
            let mut operation = self.operation.lock().map_err(|_| PrivateError::Closed)?;
            if *operation == UpdateOperation::Idle {
                *operation = UpdateOperation::Refreshing {
                    install_after: None,
                };
                true
            } else {
                false
            }
        };
        if should_start {
            let mut refresh_error = match self.refresh_error.lock() {
                Ok(refresh_error) => refresh_error,
                Err(_) => {
                    self.reset_operation();
                    return Err(PrivateError::Closed);
                }
            };
            *refresh_error = None;
            drop(refresh_error);

            // Capture the pending state before spawning so even an immediate
            // panel response cannot win the race with the IPC reply.
            let pending = match self.status() {
                Ok(status) => status,
                Err(error) => {
                    self.reset_operation();
                    return Err(error);
                }
            };
            let owner = self.clone();
            tokio::spawn(async move {
                owner.run_refresh().await;
            });
            return Ok(pending);
        }
        self.status()
    }
    /// Download/installer work belongs to the common owner, not the 10s IPC
    /// waiter. Status is polled; closing the product UI does not cancel updater.
    pub fn install(self: &Arc<Self>, automatic: bool) -> Result<HostUpdateStatusV1, PrivateError> {
        if self.coordinator.is_none() {
            return Err(PrivateError::RecoveryRequired);
        }
        let kind = if automatic {
            InstallKind::Automatic
        } else {
            InstallKind::Manual
        };
        let should_start = {
            let mut operation = self.operation.lock().map_err(|_| PrivateError::Closed)?;
            match *operation {
                UpdateOperation::Idle => {
                    *operation = UpdateOperation::Installing;
                    true
                }
                UpdateOperation::Refreshing { install_after } => {
                    let install_after = match (install_after, kind) {
                        (Some(InstallKind::Manual), _) | (_, InstallKind::Manual) => {
                            InstallKind::Manual
                        }
                        _ => InstallKind::Automatic,
                    };
                    *operation = UpdateOperation::Refreshing {
                        install_after: Some(install_after),
                    };
                    false
                }
                UpdateOperation::Installing => false,
            }
        };
        if !automatic {
            let mut refresh_error = match self.refresh_error.lock() {
                Ok(refresh_error) => refresh_error,
                Err(_) => {
                    if should_start {
                        self.reset_operation();
                    }
                    return Err(PrivateError::Closed);
                }
            };
            *refresh_error = None;
        }
        let pending = match self.status() {
            Ok(status) => status,
            Err(error) => {
                if should_start {
                    self.reset_operation();
                }
                return Err(error);
            }
        };
        if should_start {
            let owner = self.clone();
            tokio::spawn(async move {
                if kind == InstallKind::Manual {
                    if let Err(error) = owner.refresh().await {
                        owner.record_refresh_error(error);
                        owner.reset_operation();
                        return;
                    }
                }
                owner.run_install(kind).await;
                owner.reset_operation();
            });
        }
        Ok(pending)
    }

    async fn run_refresh(self: &Arc<Self>) {
        if let Err(error) = self.refresh().await {
            self.record_refresh_error(error);
            self.reset_operation();
            return;
        }
        let automatic = self
            .current
            .lock()
            .ok()
            .is_some_and(|current| current.automatic);
        let install = {
            let Ok(mut operation) = self.operation.lock() else {
                return;
            };
            match *operation {
                UpdateOperation::Refreshing { install_after } => {
                    let install =
                        install_after.or_else(|| automatic.then_some(InstallKind::Automatic));
                    *operation = if install.is_some() {
                        UpdateOperation::Installing
                    } else {
                        UpdateOperation::Idle
                    };
                    install
                }
                _ => None,
            }
        };
        if let Some(kind) = install {
            self.run_install(kind).await;
            self.reset_operation();
        }
    }

    async fn run_install(&self, kind: InstallKind) {
        let Ok(access) = self.broker.access_token(None).await else {
            return;
        };
        let Some(coordinator) = &self.coordinator else {
            return;
        };
        match kind {
            InstallKind::Automatic => {
                let preferences = self.current.lock().ok().map(|current| *current);
                if let Some(preferences) = preferences {
                    let _ = coordinator
                        .install_automatically(&access, preferences)
                        .await;
                }
            }
            InstallKind::Manual => {
                let _ = coordinator.install_now(&access).await;
            }
        }
    }

    fn record_refresh_error(&self, error: PrivateError) {
        if let Ok(mut refresh_error) = self.refresh_error.lock() {
            *refresh_error = Some(refresh_error_code(error).into());
        }
    }

    fn reset_operation(&self) {
        if let Ok(mut operation) = self.operation.lock() {
            *operation = UpdateOperation::Idle;
        }
    }
}

fn refresh_error_code(error: PrivateError) -> &'static str {
    match error {
        PrivateError::Timeout => "update_refresh_timeout",
        PrivateError::Service => "update_refresh_service",
        PrivateError::RefreshPending => "update_refresh_auth_pending",
        PrivateError::RefreshRejected => "update_refresh_auth_rejected",
        PrivateError::Cancelled => "update_refresh_cancelled",
        PrivateError::Closed => "update_refresh_closed",
        PrivateError::Protocol => "update_refresh_protocol",
        PrivateError::RecoveryRequired => "update_refresh_recovery_required",
        PrivateError::OutcomeUnknown => "update_refresh_auth_unknown",
        PrivateError::AccessUnavailable => "update_refresh_access_unavailable",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        LocalAuthStop, RuntimeRecordSwitchControl, SlotSelectionV1, UnavailableRuntimeForceStop,
    };
    use async_trait::async_trait;
    use axum::{extract::State, routing::get, Json, Router};
    use ed25519_dalek::{Signer, SigningKey};
    use nelomai_client_storage::{
        AuthStore, AuthStoreV1, BrokerMetadataV1, ContainerOwnerLock, ProtectedAuthStore,
        ProtectedRecordStore, ProtectedRuntimeStore, RuntimePaths, RuntimeRecordOwner,
        RuntimeStateStore, RuntimeStateV1, StorageError, StoredAuth,
    };
    use nelomai_client_tunnel::{TunnelController, TunnelError, TunnelStartRequest, TunnelStatus};
    use nelomai_contracts::{
        verify_container_manifest, ContainerManifestV1, RuntimeArtifactManifestV1, RuntimeFileRole,
        RuntimeFileV1, RuntimeSlot, RuntimeSlotManifestV1, CONTAINER_MANIFEST_SIGNATURE_DOMAIN,
    };
    use serde_json::json;
    use std::{
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc, Mutex,
        },
        time::Duration,
    };
    use tokio::sync::Notify;

    #[derive(Clone, Default)]
    struct Record(Arc<Mutex<Option<Vec<u8>>>>);
    impl ProtectedRecordStore for Record {
        fn load_record(&self) -> Result<Option<Vec<u8>>, StorageError> {
            Ok(self.0.lock().unwrap().clone())
        }
        fn save_record(&self, bytes: &[u8]) -> Result<(), StorageError> {
            *self.0.lock().unwrap() = Some(bytes.to_vec());
            Ok(())
        }
        fn delete_record(&self) -> Result<(), StorageError> {
            *self.0.lock().unwrap() = None;
            Ok(())
        }
    }

    struct Stop;
    #[async_trait]
    impl LocalAuthStop for Stop {
        async fn stop_local(&self) -> Result<(), crate::BrokerError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct Tunnel {
        stops: AtomicUsize,
    }
    #[async_trait]
    impl TunnelController for Tunnel {
        async fn start(&self, _: TunnelStartRequest) -> Result<(), TunnelError> {
            Ok(())
        }
        async fn stop(&self) -> Result<(), TunnelError> {
            self.stops.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn status(&self) -> Result<TunnelStatus, TunnelError> {
            Ok(TunnelStatus::Stopped)
        }
    }

    #[derive(Default)]
    struct RecordingBackend {
        versions: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl UpdateBackend for RecordingBackend {
        async fn install(
            &self,
            _: &AccessSnapshot,
            version: &str,
            _: UpdateBarrierPhase,
            _: Arc<dyn Fn(DownloadProgress) + Send + Sync>,
        ) -> Result<InstallResult, UpdateBackendError> {
            self.versions.lock().unwrap().push(version.to_owned());
            Ok(InstallResult::Installed(
                nelomai_client_updater::InstalledUpdate {
                    version: version.to_owned(),
                },
            ))
        }
    }

    fn manifest() -> nelomai_contracts::VerifiedContainerManifest {
        let unsigned = ContainerManifestV1 {
            format_version: 1,
            container_version: "0.2.20".into(),
            release_set_id: "runtime-0.2.20".into(),
            minimum_runtime_contract: 1,
            maximum_runtime_contract: 1,
            stable_release_set_sha256: None,
            stable_platform_manifest_sha256: None,
            slots: vec![RuntimeSlotManifestV1 {
                slot: RuntimeSlot::Latest,
                manifest: RuntimeArtifactManifestV1 {
                    format_version: 1,
                    runtime_version: "0.2.20".into(),
                    source_commit: "0123456789abcdef0123456789abcdef01234567".into(),
                    platform: "linux".into(),
                    architecture: "x86_64".into(),
                    contract_version: 1,
                    files: vec![RuntimeFileV1 {
                        path: "bin/nelomai-runtime".into(),
                        size_bytes: 1,
                        sha256: "a".repeat(64),
                        role: RuntimeFileRole::Executable,
                    }],
                },
            }],
        };
        let bytes = serde_json::to_vec(&serde_json::to_value(unsigned).unwrap()).unwrap();
        let key = SigningKey::from_bytes(&[71; 32]);
        let mut signed = CONTAINER_MANIFEST_SIGNATURE_DOMAIN.to_vec();
        signed.extend_from_slice(&bytes);
        verify_container_manifest(
            &bytes,
            &key.sign(&signed).to_bytes(),
            &key.verifying_key().to_bytes(),
            "linux",
            "x86_64",
        )
        .unwrap()
    }

    struct Panel {
        calls: AtomicUsize,
        fail: AtomicBool,
        version: Mutex<String>,
        release: Notify,
    }

    async fn bootstrap(
        State(panel): State<Arc<Panel>>,
    ) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
        panel.calls.fetch_add(1, Ordering::SeqCst);
        panel.release.notified().await;
        if panel.fail.swap(false, Ordering::SeqCst) {
            return Err(axum::http::StatusCode::SERVICE_UNAVAILABLE);
        }
        let version = panel.version.lock().unwrap().clone();
        Ok(Json(json!({
            "api_version": "1",
            "request_id": "update-refresh",
            "access": {
                "state": "active",
                "can_login": true,
                "can_connect": true,
                "expires_at": "2030-01-01T00:00:00Z"
            },
            "device": {"id": "device-a", "name": "Mac", "platform": "macos"},
            "binding": null,
            "connection": null,
            "pinned_stray": null,
            "defaults": {"layer": "stray", "tic_connection_mode": "dynamic", "route_mode": "standalone"},
            "update": {
                "current_version": version,
                "minimum_version": null,
                "update_available": true,
                "required": false,
                "release_notes": "test"
            }
        })))
    }

    async fn updater(
        fail_first: bool,
    ) -> (
        Arc<HostUpdater>,
        Arc<Panel>,
        Arc<RecordingBackend>,
        Arc<Tunnel>,
        tokio::task::JoinHandle<()>,
        tempfile::TempDir,
    ) {
        let panel = Arc::new(Panel {
            calls: AtomicUsize::new(0),
            fail: AtomicBool::new(fail_first),
            version: Mutex::new("0.2.21".into()),
            release: Notify::new(),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = ClientApi::new(&format!("http://{}", listener.local_addr().unwrap()))
            .unwrap()
            .with_app_version("0.2.20")
            .unwrap();
        let router = Router::new()
            .route("/api/client/v1/bootstrap", get(bootstrap))
            .with_state(panel.clone());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("common")).unwrap();
        std::fs::write(
            root.path().join("common/runtime-selection-v1.json"),
            SlotSelectionV1 {
                container_version: "0.2.20".into(),
                selected_slot: RuntimeSlot::Latest,
                pending_slot: None,
            }
            .to_persisted_bytes()
            .unwrap(),
        )
        .unwrap();
        let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
        let auth = Arc::new(ProtectedAuthStore::new(Record::default()));
        let mut legacy = StoredAuth::new_install();
        legacy.access_token = Some("access".into());
        legacy.refresh_token = Some("refresh".into());
        let mut stored = AuthStoreV1::from_legacy(&legacy);
        stored.confirmed_identity = Some(nelomai_contracts::RuntimeIdentity {
            container_version: "0.2.20".into(),
            runtime_version: "0.2.20".into(),
            runtime_contract_version: 1,
            slot: RuntimeSlot::Latest,
            session_generation: Some(1),
        });
        stored.session_generation = Some(1);
        stored.broker = Some(BrokerMetadataV1 {
            family: "family".into(),
            next_attempt: 0,
            pending_request: None,
            completed_resume: None,
            pending_logout: None,
            pending_recovery: None,
            cancelled_login: None,
            authentication_outcome_unknown: false,
            pending_login_account: None,
            confirmed_device_id: Some("device-a".into()),
            pending_push_cleanup_epoch: None,
            transition_authorities: Vec::new(),
        });
        auth.save(&stored).unwrap();
        let broker = Arc::new(AuthBroker::new(api.clone(), auth, Arc::new(Stop)).unwrap());
        let paths = RuntimePaths::new(root.path(), RuntimeSlot::Latest, "0.2.20").unwrap();
        let runtime = ProtectedRuntimeStore::new(Record::default(), paths);
        runtime
            .save(&RuntimeStateV1::empty(runtime.paths(), false))
            .unwrap();
        let tunnel = Arc::new(Tunnel::default());
        let local = nelomai_client_core::CoreLocalStop::new(tunnel.clone());
        let control = Arc::new(RuntimeRecordSwitchControl::new(
            RuntimeRecordOwner::new(runtime),
            Vec::new(),
            local,
            Arc::new(UnavailableRuntimeForceStop),
        ));
        let coordinator = Arc::new(
            SwitchCoordinator::open(owner, manifest())
                .unwrap()
                .attach(broker.clone(), control),
        );
        let backend = Arc::new(RecordingBackend::default());
        let updater = Arc::new(
            HostUpdater::new(
                root.path(),
                api,
                broker,
                coordinator,
                "0.2.20".into(),
                Some(backend.clone()),
            )
            .unwrap(),
        );
        updater.set_automatic(false).unwrap();
        (updater, panel, backend, tunnel, server, root)
    }

    #[tokio::test]
    async fn slow_refresh_returns_immediately_and_duplicate_requests_share_one_flight() {
        let (updater, panel, _backend, _tunnel, server, _root) = updater(false).await;

        let first = tokio::time::timeout(Duration::from_millis(100), async {
            updater.start_refresh()
        })
        .await
        .expect("starting a refresh must not wait for panel I/O")
        .unwrap();
        assert_eq!(first.error_code.as_deref(), Some("update_refresh_pending"));
        let wire = serde_json::to_value(&first).unwrap();
        let keys = wire
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            keys,
            [
                "automatic",
                "downloaded",
                "errorCode",
                "notes",
                "phase",
                "required",
                "supported",
                "total",
                "version",
            ]
        );
        assert_eq!(
            updater.start_refresh().unwrap().error_code.as_deref(),
            Some("update_refresh_pending")
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while panel.calls.load(Ordering::SeqCst) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(panel.calls.load(Ordering::SeqCst), 1);

        panel.release.notify_one();
        tokio::time::timeout(Duration::from_secs(1), async {
            while updater.status().unwrap().error_code.as_deref() == Some("update_refresh_pending")
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let completed = updater.status().unwrap();
        assert_eq!(completed.phase, "available");
        assert_eq!(completed.version.as_deref(), Some("0.2.21"));
        server.abort();
    }

    #[tokio::test]
    async fn failed_background_refresh_can_be_retried_without_restarting_owner() {
        let (updater, panel, _backend, _tunnel, server, _root) = updater(true).await;

        assert_eq!(
            updater.start_refresh().unwrap().error_code.as_deref(),
            Some("update_refresh_pending")
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while panel.calls.load(Ordering::SeqCst) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        panel.release.notify_one();
        tokio::time::timeout(Duration::from_secs(1), async {
            while updater.status().unwrap().error_code.as_deref() == Some("update_refresh_pending")
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            updater.status().unwrap().error_code.as_deref(),
            Some("update_refresh_service")
        );

        assert_eq!(
            updater.start_refresh().unwrap().error_code.as_deref(),
            Some("update_refresh_pending")
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while panel.calls.load(Ordering::SeqCst) != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        panel.release.notify_one();
        tokio::time::timeout(Duration::from_secs(1), async {
            while updater.status().unwrap().error_code.as_deref() == Some("update_refresh_pending")
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(updater.status().unwrap().version.as_deref(), Some("0.2.21"));
        server.abort();
    }

    #[tokio::test]
    async fn manual_install_joins_in_flight_refresh_without_a_second_panel_request() {
        let (updater, panel, _backend, _tunnel, server, _root) = updater(false).await;

        updater.start_refresh().unwrap();
        wait_for_calls(&panel, 1).await;
        assert_eq!(
            updater.install(false).unwrap().error_code.as_deref(),
            Some("update_install_preparing")
        );

        panel.release.notify_one();
        wait_for_idle(&updater).await;
        assert_eq!(panel.calls.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[tokio::test]
    async fn manual_install_refreshes_current_offer_before_attempting_install() {
        let (updater, panel, backend, _tunnel, server, _root) = updater(false).await;

        updater.start_refresh().unwrap();
        wait_for_calls(&panel, 1).await;
        panel.release.notify_one();
        wait_for_refresh(&updater).await;
        *panel.version.lock().unwrap() = "0.2.22".into();

        assert_eq!(
            updater.install(false).unwrap().error_code.as_deref(),
            Some("update_install_preparing")
        );
        wait_for_calls(&panel, 2).await;
        assert!(backend.versions.lock().unwrap().is_empty());
        panel.release.notify_one();
        wait_for_idle(&updater).await;
        assert_eq!(updater.status().unwrap().version.as_deref(), Some("0.2.22"));
        assert!(!backend
            .versions
            .lock()
            .unwrap()
            .iter()
            .any(|version| version == "0.2.21"));
        server.abort();
    }

    #[tokio::test]
    async fn manual_install_does_not_stop_or_install_when_refresh_fails() {
        let (updater, panel, backend, tunnel, server, _root) = updater(false).await;

        updater.start_refresh().unwrap();
        wait_for_calls(&panel, 1).await;
        panel.release.notify_one();
        wait_for_refresh(&updater).await;
        panel.fail.store(true, Ordering::SeqCst);

        updater.install(false).unwrap();
        wait_for_calls(&panel, 2).await;
        panel.release.notify_one();
        wait_for_idle(&updater).await;
        assert!(backend.versions.lock().unwrap().is_empty());
        assert_eq!(tunnel.stops.load(Ordering::SeqCst), 0);
        server.abort();
    }

    #[tokio::test]
    async fn refresh_request_during_manual_install_joins_its_refresh() {
        let (updater, panel, _backend, _tunnel, server, _root) = updater(false).await;

        updater.start_refresh().unwrap();
        wait_for_calls(&panel, 1).await;
        panel.release.notify_one();
        wait_for_refresh(&updater).await;

        updater.install(false).unwrap();
        wait_for_calls(&panel, 2).await;
        assert_eq!(
            updater.start_refresh().unwrap().error_code.as_deref(),
            Some("update_install_preparing")
        );
        panel.release.notify_one();
        wait_for_idle(&updater).await;
        assert_eq!(panel.calls.load(Ordering::SeqCst), 2);
        server.abort();
    }

    async fn wait_for_calls(panel: &Panel, expected: usize) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while panel.calls.load(Ordering::SeqCst) != expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    async fn wait_for_refresh(updater: &HostUpdater) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while matches!(
                *updater.operation.lock().unwrap(),
                UpdateOperation::Refreshing { .. }
            ) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    async fn wait_for_idle(updater: &HostUpdater) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while *updater.operation.lock().unwrap() != UpdateOperation::Idle {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}
