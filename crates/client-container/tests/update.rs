use async_trait::async_trait;
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use ed25519_dalek::{Signer, SigningKey};
use nelomai_client_container::{
    AuthBroker, BrokerError, LocalAuthStop, LocalStopReceiptV1, RuntimeCleanupHandoff,
    RuntimeRecordSwitchControl, RuntimeSwitchControl, SlotSelectionV1, SwitchCoordinator,
    SwitchPhase, UnavailableRuntimeForceStop, UpdateBarrier, UpdateJournalPhase, UpdatePrepare,
};
use nelomai_client_core::{CoreLocalStop, RuntimeWriterGates};
use nelomai_client_storage::{
    AuthStore, AuthStoreV1, BrokerMetadataV1, ContainerOwnerLock, ProtectedAuthStore,
    ProtectedRecordStore, ProtectedRuntimeStore, RuntimeAuthScope, RuntimeCleanupSnapshotV1,
    RuntimePaths, RuntimeRecordOwner, RuntimeStateStore, RuntimeStateV1, StorageError, StoredAuth,
};
use nelomai_client_tunnel::{TunnelController, TunnelError, TunnelStartRequest, TunnelStatus};
use nelomai_contracts::{
    verify_container_manifest, ContainerManifestV1, RuntimeArtifactManifestV1, RuntimeFileRole,
    RuntimeFileV1, RuntimeSlot, RuntimeSlotManifestV1, CONTAINER_MANIFEST_SIGNATURE_DOMAIN,
};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use tokio::sync::Notify;

fn manifest(
    container: &str,
    runtime: &str,
    stable: bool,
) -> nelomai_contracts::VerifiedContainerManifest {
    let artifact = |slot, version: &str| RuntimeSlotManifestV1 {
        slot,
        manifest: RuntimeArtifactManifestV1 {
            format_version: 1,
            runtime_version: version.into(),
            source_commit: "0123456789abcdef0123456789abcdef01234567".into(),
            platform: "linux".into(),
            architecture: "x86_64".into(),
            contract_version: 1,
            files: vec![RuntimeFileV1 {
                path: "bin/nelomai-runtime".into(),
                size_bytes: 17,
                sha256: "a".repeat(64),
                role: RuntimeFileRole::Executable,
            }],
        },
    };
    let mut slots = vec![artifact(RuntimeSlot::Latest, runtime)];
    if stable {
        slots.push(artifact(RuntimeSlot::Stable, "0.2.15"));
    }
    let unsigned = ContainerManifestV1 {
        format_version: 1,
        container_version: container.into(),
        release_set_id: format!("runtime-{container}"),
        minimum_runtime_contract: 1,
        maximum_runtime_contract: 1,
        stable_release_set_sha256: stable.then(|| "b".repeat(64)),
        stable_platform_manifest_sha256: stable.then(|| "c".repeat(64)),
        slots,
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

struct FailRetirementSave {
    inner: Arc<dyn AuthStore>,
    // 1 fails before atomic replacement; 2 reports a crash after replacement.
    mode: AtomicUsize,
}

impl AuthStore for FailRetirementSave {
    fn load(&self) -> Result<Option<AuthStoreV1>, StorageError> {
        self.inner.load()
    }

    fn save(&self, value: &AuthStoreV1) -> Result<(), StorageError> {
        let count = |auth: &AuthStoreV1| auth.broker.as_ref().unwrap().transition_authorities.len();
        if self
            .inner
            .load()?
            .as_ref()
            .is_some_and(|before| count(value) < count(before))
        {
            match self.mode.swap(0, Ordering::SeqCst) {
                1 => {
                    return Err(StorageError::RecoveryRequired(
                        "crash before retirement save",
                    ))
                }
                2 => {
                    self.inner.save(value)?;
                    return Err(StorageError::RecoveryRequired(
                        "crash after retirement save",
                    ));
                }
                _ => {}
            }
        }
        self.inner.save(value)
    }
}

#[async_trait]
impl LocalAuthStop for Stop {
    async fn stop_local(&self) -> Result<(), BrokerError> {
        Ok(())
    }
}

fn enrolled_store(slot: RuntimeSlot) -> Arc<dyn AuthStore> {
    let store = Arc::new(ProtectedAuthStore::new(Record::default()));
    let mut legacy = StoredAuth::new_install();
    legacy.install_secret = "synthetic-install".into();
    legacy.access_token = Some("source-access".into());
    legacy.refresh_token = Some("source-refresh".into());
    let mut auth = AuthStoreV1::from_legacy(&legacy);
    auth.confirmed_identity = Some(nelomai_contracts::RuntimeIdentity {
        container_version: "0.2.16".into(),
        runtime_version: if slot == RuntimeSlot::Stable {
            "0.2.15"
        } else {
            "0.2.16"
        }
        .into(),
        runtime_contract_version: 1,
        slot,
        session_generation: Some(7),
    });
    auth.session_generation = Some(7);
    auth.broker = Some(BrokerMetadataV1 {
        family: "source-family".into(),
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
    store.save(&auth).unwrap();
    store
}

#[derive(Default)]
struct Control {
    handoffs: AtomicUsize,
    graceful: AtomicUsize,
    forced: AtomicUsize,
    completed: AtomicUsize,
    fail_graceful: AtomicUsize,
    fail_force: AtomicUsize,
    stall_graceful: AtomicBool,
    graceful_entered: Notify,
    graceful_release: Notify,
    gates: Arc<RuntimeWriterGates>,
    #[cfg(unix)]
    forced_native: Mutex<Option<ForcedNative>>,
}

#[cfg(unix)]
struct ForcedNative {
    runtime: std::os::unix::net::UnixStream,
    common: std::os::unix::net::UnixStream,
    owner: Arc<nelomai_client_container::desktop::RuntimeExitOwner>,
    helper_receipts: Arc<AtomicUsize>,
}

impl Control {
    fn release_graceful(&self) {
        self.stall_graceful.store(false, Ordering::SeqCst);
        self.graceful_release.notify_waiters();
    }
}

#[async_trait]
impl RuntimeSwitchControl for Control {
    async fn handoff_cleanup(
        &self,
        source: &nelomai_client_container::TransitionSourceSnapshot,
    ) -> Result<RuntimeCleanupHandoff, BrokerError> {
        self.handoffs.fetch_add(1, Ordering::SeqCst);
        let identity = source.identity().ok_or(BrokerError::RecoveryRequired)?;
        let snapshot = RuntimeCleanupSnapshotV1 {
            slot: identity.slot,
            runtime_version: identity.runtime_version.clone(),
            auth_scope: Some(nelomai_client_storage::RuntimeAuthScope {
                auth_epoch: source.auth_epoch(),
                family: source.family().into(),
                identity: identity.clone(),
            }),
            lease_ids: vec!["lease-a".into()],
            operations: Vec::new(),
            cleanup_only: false,
        };
        Ok(RuntimeCleanupHandoff::new(
            snapshot,
            self.gates.quiesce().await,
        ))
    }

    async fn graceful_stop(
        &self,
        _: &str,
        _: &RuntimeCleanupSnapshotV1,
    ) -> Result<(), BrokerError> {
        self.graceful.fetch_add(1, Ordering::SeqCst);
        self.graceful_entered.notify_one();
        if self.fail_graceful.swap(0, Ordering::SeqCst) > 0 {
            return Err(BrokerError::RecoveryRequired);
        }
        while self.stall_graceful.load(Ordering::SeqCst) {
            self.graceful_release.notified().await;
        }
        Ok(())
    }

    async fn force_stop(&self, _: &str, _: &RuntimeCleanupSnapshotV1) -> Result<(), BrokerError> {
        self.forced.fetch_add(1, Ordering::SeqCst);
        if self.fail_force.swap(0, Ordering::SeqCst) == 1 {
            return Err(BrokerError::RecoveryRequired);
        }
        #[cfg(unix)]
        {
            let native = self.forced_native.lock().unwrap().take();
            if let Some(mut native) = native {
                let process = Mutex::new(None);
                native
                    .owner
                    .stop_for_transition(&process, async {
                        use std::io::Read;
                        drop(native.runtime);
                        assert_eq!(native.common.read(&mut [0; 1]).unwrap(), 0);
                        assert!(
                            !native.owner.finish_on_native_eof(),
                            "forced timeout EOF must not exit the common operation"
                        );
                        native.helper_receipts.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    })
                    .await
                    .map_err(|_| BrokerError::RecoveryRequired)?;
            }
        }
        Ok(())
    }

    async fn complete_cleanup_and_admit(
        &self,
        _: &RuntimeCleanupSnapshotV1,
        _: &LocalStopReceiptV1,
        _: &nelomai_client_api::AccessSnapshot,
    ) -> Result<(), BrokerError> {
        self.completed.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn write_selection(root: &std::path::Path, container: &str, slot: RuntimeSlot) {
    std::fs::create_dir_all(root.join("common")).unwrap();
    std::fs::write(
        root.join("common/runtime-selection-v1.json"),
        SlotSelectionV1 {
            container_version: container.into(),
            selected_slot: slot,
            pending_slot: None,
        }
        .to_persisted_bytes()
        .unwrap(),
    )
    .unwrap();
}

fn offline_coordinator(
    owner: Arc<ContainerOwnerLock>,
    store: Arc<dyn AuthStore>,
    control: Arc<Control>,
    installed_manifest: nelomai_contracts::VerifiedContainerManifest,
) -> Arc<SwitchCoordinator> {
    let api = nelomai_client_api::ClientApi::new("http://127.0.0.1:9")
        .unwrap()
        .with_app_version("0.2.16")
        .unwrap();
    let broker = Arc::new(AuthBroker::new(api, store, Arc::new(Stop)).unwrap());
    Arc::new(
        SwitchCoordinator::open(owner, installed_manifest)
            .unwrap()
            .attach(broker, control),
    )
}

#[tokio::test]
async fn active_or_stopped_source_is_durably_local_stopped_before_installation() {
    for slot in [RuntimeSlot::Latest, RuntimeSlot::Stable] {
        let root = tempfile::tempdir().unwrap();
        write_selection(root.path(), "0.2.16", slot);
        let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
        let control = Arc::new(Control::default());
        let coordinator = offline_coordinator(
            owner,
            enrolled_store(slot),
            control.clone(),
            manifest("0.2.16", "0.2.16", true),
        );
        let barrier = UpdateBarrier::open(coordinator.clone()).unwrap();

        assert_eq!(
            barrier.prepare("0.2.17").await.unwrap(),
            UpdatePrepare::LocalStopped
        );
        let journal = barrier.snapshot().unwrap().unwrap();
        assert_eq!(journal.source_container(), "0.2.16");
        assert_eq!(journal.source_runtime().slot, slot);
        assert_eq!(journal.target_container(), "0.2.17");
        assert_eq!(journal.previous_slot(), slot);
        assert_eq!(journal.phase(), UpdateJournalPhase::LocalStopped);
        assert_eq!(
            coordinator.snapshot().unwrap().unwrap().phase(),
            SwitchPhase::LocalStopped
        );
        assert_eq!(control.handoffs.load(Ordering::SeqCst), 1);
        assert_eq!(control.graceful.load(Ordering::SeqCst), 1);
        assert_eq!(control.forced.load(Ordering::SeqCst), 0);
    }
}

#[cfg(not(target_os = "android"))]
#[test]
fn nonreturning_windows_handoff_retains_pending_authority_not_install_success() {
    const ROOT: &str = "NELOMAI_TEST_HANDOFF_ROOT";
    if let Some(path) = std::env::var_os(ROOT) {
        let root = std::path::PathBuf::from(path);
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            write_selection(&root, "0.2.16", RuntimeSlot::Latest);
            let owner = Arc::new(ContainerOwnerLock::try_acquire(&root).unwrap());
            let coordinator = offline_coordinator(
                owner,
                enrolled_store(RuntimeSlot::Latest),
                Arc::new(Control::default()),
                manifest("0.2.16", "0.2.16", false),
            );
            let barrier = UpdateBarrier::open(coordinator).unwrap();
            barrier.prepare("0.2.17").await.unwrap();
            let proof = barrier
                .stop_proof("0.2.17", UpdateJournalPhase::LocalStopped)
                .unwrap();
            let exit_owner = nelomai_client_container::desktop::RuntimeExitOwner::default();
            exit_owner
                .handoff_installer(
                    &Mutex::new(None),
                    async {
                        assert_eq!(
                            barrier
                                .stop_proof("0.2.17", UpdateJournalPhase::LocalStopped)
                                .unwrap(),
                            proof
                        );
                        Ok(())
                    },
                    || {
                        // Characterize the installed updater's real contract: it ignores
                        // ShellExecuteW's result and exits without unwinding/returning.
                        // Exercise our boundary in a separate OS process, not a returning
                        // mock that would incorrectly permit a success continuation.
                        std::process::exit(73)
                    },
                )
                .await
                .unwrap();
            std::fs::write(root.join("incorrect-success"), b"success").unwrap();
        });
        panic!("Windows install must not return success");
    }
    for installed in ["0.2.16", "0.2.17"] {
        let root = tempfile::tempdir().unwrap();
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "nonreturning_windows_handoff_retains_pending_authority_not_install_success",
            ])
            .env(ROOT, root.path())
            .status()
            .unwrap();
        assert_eq!(result.code(), Some(73));
        assert!(!root.path().join("incorrect-success").exists());
        let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
        let coordinator = offline_coordinator(
            owner,
            enrolled_store(RuntimeSlot::Latest),
            Arc::new(Control::default()),
            manifest("0.2.16", "0.2.16", false),
        );
        let barrier = UpdateBarrier::open(coordinator).unwrap();
        let pending = barrier.snapshot().unwrap().unwrap();
        assert_eq!(pending.phase(), UpdateJournalPhase::LocalStopped);
        assert_eq!(pending.target_container(), "0.2.17");
        assert!(barrier
            .stop_proof("0.2.17", UpdateJournalPhase::LocalStopped)
            .is_ok());
        assert!(barrier
            .stop_proof("0.2.17", UpdateJournalPhase::InstallerOpened)
            .is_err());
        drop(barrier);
        // Reopen in this new OS process after the updater's abrupt exit. An ignored
        // failed launch/unchanged installation cancels; a verified new version resumes.
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (panel, api, server) = panel().await;
            let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
            write_selection(root.path(), installed, RuntimeSlot::Latest);
            let coordinator = online_coordinator(
                owner,
                enrolled_store(RuntimeSlot::Latest),
                Arc::new(Control::default()),
                manifest(installed, installed, false),
                api,
            );
            let barrier = UpdateBarrier::open(coordinator.clone()).unwrap();
            barrier.recover(installed).await.unwrap();
            assert!(barrier.snapshot().unwrap().is_none());
            assert_eq!(
                coordinator.snapshot().unwrap().unwrap().phase(),
                SwitchPhase::Complete
            );
            assert_eq!(panel.resume.load(Ordering::SeqCst), 1);
            assert_eq!(
                panel.supersede.load(Ordering::SeqCst),
                usize::from(installed == "0.2.17")
            );
            server.abort();
        });
    }
}

struct Tunnel {
    status: Mutex<TunnelStatus>,
    stops: AtomicUsize,
}

#[async_trait]
impl TunnelController for Tunnel {
    async fn start(&self, _: TunnelStartRequest) -> Result<(), TunnelError> {
        *self.status.lock().unwrap() = TunnelStatus::Running;
        Ok(())
    }

    async fn stop(&self) -> Result<(), TunnelError> {
        self.stops.fetch_add(1, Ordering::SeqCst);
        *self.status.lock().unwrap() = TunnelStatus::Stopped;
        Ok(())
    }

    async fn status(&self) -> Result<TunnelStatus, TunnelError> {
        Ok(*self.status.lock().unwrap())
    }
}

#[tokio::test]
async fn running_and_already_stopped_tunnels_use_the_actual_local_stop_path() {
    for initial_status in [TunnelStatus::Running, TunnelStatus::Stopped] {
        let root = tempfile::tempdir().unwrap();
        write_selection(root.path(), "0.2.16", RuntimeSlot::Latest);
        let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
        let store = enrolled_store(RuntimeSlot::Latest);
        let auth = store.load().unwrap().unwrap();
        let tunnel = Arc::new(Tunnel {
            status: Mutex::new(initial_status),
            stops: AtomicUsize::new(0),
        });
        let local = CoreLocalStop::new(tunnel.clone());
        let api = nelomai_client_api::ClientApi::new("http://127.0.0.1:9")
            .unwrap()
            .with_app_version("0.2.16")
            .unwrap();
        let broker = Arc::new(AuthBroker::new(api, store, local.clone()).unwrap());
        let paths = RuntimePaths::new(root.path(), RuntimeSlot::Latest, "0.2.16").unwrap();
        let runtime = ProtectedRuntimeStore::new(Record::default(), paths);
        let mut state = RuntimeStateV1::empty(runtime.paths(), false);
        state.auth_scope = Some(RuntimeAuthScope {
            auth_epoch: auth.auth_epoch,
            family: auth.broker.unwrap().family,
            identity: auth.confirmed_identity.unwrap(),
        });
        runtime.save(&state).unwrap();
        let record = RuntimeRecordOwner::new(runtime);
        let control = Arc::new(RuntimeRecordSwitchControl::new(
            record,
            Vec::new(),
            local,
            Arc::new(UnavailableRuntimeForceStop),
        ));
        let coordinator = Arc::new(
            SwitchCoordinator::open(owner, manifest("0.2.16", "0.2.16", false))
                .unwrap()
                .attach(broker, control),
        );
        let barrier = UpdateBarrier::open(coordinator).unwrap();

        assert_eq!(
            barrier.prepare("0.2.17").await.unwrap(),
            UpdatePrepare::LocalStopped
        );
        assert_eq!(tunnel.stops.load(Ordering::SeqCst), 1);
        assert_eq!(tunnel.status().await.unwrap(), TunnelStatus::Stopped);
    }
}

#[tokio::test(start_paused = true)]
async fn graceful_stop_timeout_is_forced_once_and_retry_reuses_the_same_journal() {
    let root = tempfile::tempdir().unwrap();
    write_selection(root.path(), "0.2.16", RuntimeSlot::Latest);
    let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    let store = enrolled_store(RuntimeSlot::Latest);
    let control = Arc::new(Control::default());
    control.stall_graceful.store(true, Ordering::SeqCst);
    let coordinator = offline_coordinator(
        owner.clone(),
        store.clone(),
        control.clone(),
        manifest("0.2.16", "0.2.16", false),
    );
    let barrier = Arc::new(UpdateBarrier::open(coordinator).unwrap());
    let task = {
        let barrier = barrier.clone();
        tokio::spawn(async move { barrier.prepare("0.2.17").await })
    };
    control.graceful_entered.notified().await;
    tokio::time::advance(std::time::Duration::from_secs(5)).await;
    assert_eq!(task.await.unwrap().unwrap(), UpdatePrepare::LocalStopped);
    assert_eq!(control.forced.load(Ordering::SeqCst), 1);
    let operation = barrier
        .snapshot()
        .unwrap()
        .unwrap()
        .operation_id()
        .to_owned();
    drop(barrier);

    let reopened = UpdateBarrier::open(offline_coordinator(
        owner,
        store,
        control.clone(),
        manifest("0.2.16", "0.2.16", false),
    ))
    .unwrap();
    assert_eq!(
        reopened.prepare("0.2.17").await.unwrap(),
        UpdatePrepare::LocalStopped
    );
    assert_eq!(
        reopened.snapshot().unwrap().unwrap().operation_id(),
        operation
    );
    assert_eq!(control.forced.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn immediate_graceful_error_uses_durable_force_stop() {
    let root = tempfile::tempdir().unwrap();
    write_selection(root.path(), "0.2.16", RuntimeSlot::Latest);
    let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    let control = Arc::new(Control::default());
    control.fail_graceful.store(1, Ordering::SeqCst);
    let coordinator = offline_coordinator(
        owner,
        enrolled_store(RuntimeSlot::Latest),
        control.clone(),
        manifest("0.2.16", "0.2.16", false),
    );
    let barrier = UpdateBarrier::open(coordinator.clone()).unwrap();
    assert_eq!(
        barrier.prepare("0.2.17").await.unwrap(),
        UpdatePrepare::LocalStopped
    );
    let journal = serde_json::to_value(coordinator.snapshot().unwrap().unwrap()).unwrap();
    assert_eq!(journal["force_stop_requested"], true);
    assert_eq!(journal["local_stop_receipt"]["forced"], true);
    assert!(barrier
        .stop_proof("0.2.17", UpdateJournalPhase::LocalStopped)
        .is_ok());
    assert_eq!(control.graceful.load(Ordering::SeqCst), 1);
    assert_eq!(control.forced.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn immediate_graceful_error_and_failed_force_recover_without_inventing_receipt() {
    let root = tempfile::tempdir().unwrap();
    write_selection(root.path(), "0.2.16", RuntimeSlot::Latest);
    let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    let store = enrolled_store(RuntimeSlot::Latest);
    let control = Arc::new(Control::default());
    control.fail_graceful.store(1, Ordering::SeqCst);
    control.fail_force.store(1, Ordering::SeqCst);
    let coordinator = offline_coordinator(
        owner.clone(),
        store.clone(),
        control.clone(),
        manifest("0.2.16", "0.2.16", false),
    );
    let barrier = UpdateBarrier::open(coordinator.clone()).unwrap();
    assert!(barrier.prepare("0.2.17").await.is_err());
    let stopped = coordinator.snapshot().unwrap().unwrap();
    let pending = serde_json::to_value(&stopped).unwrap();
    assert_eq!(stopped.phase(), SwitchPhase::RuntimeStopping);
    assert!(pending["local_stop_receipt"].is_null());
    assert!(barrier
        .stop_proof("0.2.17", UpdateJournalPhase::LocalStopped)
        .is_err());
    assert_eq!(pending["force_stop_requested"], true);
    drop(barrier);
    drop(coordinator);

    let recovered = offline_coordinator(
        owner,
        store,
        control.clone(),
        manifest("0.2.16", "0.2.16", false),
    );
    let reopened = UpdateBarrier::open(recovered.clone()).unwrap();
    assert_eq!(
        reopened.prepare("0.2.17").await.unwrap(),
        UpdatePrepare::LocalStopped
    );
    let completed = serde_json::to_value(recovered.snapshot().unwrap().unwrap()).unwrap();
    assert_eq!(completed["operation_id"], pending["operation_id"]);
    assert_eq!(completed["local_stop_receipt"]["forced"], true);
    assert_eq!(control.graceful.load(Ordering::SeqCst), 1);
    assert_eq!(control.forced.load(Ordering::SeqCst), 2);
}

#[cfg(unix)]
#[tokio::test(start_paused = true)]
async fn forced_timeout_native_eof_preserves_common_until_durable_helper_receipt() {
    let root = tempfile::tempdir().unwrap();
    write_selection(root.path(), "0.2.16", RuntimeSlot::Latest);
    let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    let control = Arc::new(Control::default());
    control.stall_graceful.store(true, Ordering::SeqCst);
    let (runtime, common) = std::os::unix::net::UnixStream::pair().unwrap();
    let helper_receipts = Arc::new(AtomicUsize::new(0));
    let exit_owner = Arc::new(nelomai_client_container::desktop::RuntimeExitOwner::default());
    *control.forced_native.lock().unwrap() = Some(ForcedNative {
        runtime,
        common,
        owner: exit_owner.clone(),
        helper_receipts: helper_receipts.clone(),
    });
    let coordinator = offline_coordinator(
        owner,
        enrolled_store(RuntimeSlot::Latest),
        control.clone(),
        manifest("0.2.16", "0.2.16", false),
    );
    let barrier = Arc::new(UpdateBarrier::open(coordinator.clone()).unwrap());
    let task = {
        let barrier = barrier.clone();
        tokio::spawn(async move { barrier.prepare("0.2.17").await })
    };
    control.graceful_entered.notified().await;
    tokio::time::advance(std::time::Duration::from_secs(5)).await;
    assert_eq!(task.await.unwrap().unwrap(), UpdatePrepare::LocalStopped);
    assert_eq!(helper_receipts.load(Ordering::SeqCst), 1);
    let switch = coordinator.snapshot().unwrap().unwrap();
    let switch_json = serde_json::to_value(&switch).unwrap();
    assert_eq!(switch_json["local_stop_receipt"]["forced"], true);
    assert_eq!(switch.phase(), SwitchPhase::LocalStopped);
    assert!(barrier
        .stop_proof("0.2.17", UpdateJournalPhase::LocalStopped)
        .is_ok());
    assert!(!exit_owner.finish_on_native_eof());
    barrier.installer_opened().await.unwrap();
    assert_eq!(
        barrier.snapshot().unwrap().unwrap().phase(),
        UpdateJournalPhase::InstallerOpened
    );
}

#[tokio::test(start_paused = true)]
async fn failed_force_stop_keeps_exact_work_retryable_instead_of_permanently_busy() {
    let root = tempfile::tempdir().unwrap();
    write_selection(root.path(), "0.2.16", RuntimeSlot::Latest);
    let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    let store = enrolled_store(RuntimeSlot::Latest);
    let control = Arc::new(Control::default());
    control.stall_graceful.store(true, Ordering::SeqCst);
    control.fail_force.store(1, Ordering::SeqCst);
    let coordinator = offline_coordinator(
        owner,
        store,
        control.clone(),
        manifest("0.2.16", "0.2.16", false),
    );
    let barrier = Arc::new(UpdateBarrier::open(coordinator).unwrap());
    let first = {
        let barrier = barrier.clone();
        tokio::spawn(async move { barrier.prepare("0.2.17").await })
    };
    control.graceful_entered.notified().await;
    tokio::time::advance(std::time::Duration::from_secs(5)).await;
    assert!(first.await.unwrap().is_err());
    let operation = barrier
        .snapshot()
        .unwrap()
        .unwrap()
        .operation_id()
        .to_owned();

    assert_eq!(
        barrier.prepare("0.2.17").await.unwrap(),
        UpdatePrepare::LocalStopped
    );
    assert_eq!(
        barrier.snapshot().unwrap().unwrap().operation_id(),
        operation
    );
    assert_eq!(control.graceful.load(Ordering::SeqCst), 1);
    assert_eq!(control.forced.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn installer_opened_is_pending_replacement_not_installed_version_proof() {
    let root = tempfile::tempdir().unwrap();
    write_selection(root.path(), "0.2.16", RuntimeSlot::Latest);
    let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    let coordinator = offline_coordinator(
        owner,
        enrolled_store(RuntimeSlot::Latest),
        Arc::new(Control::default()),
        manifest("0.2.16", "0.2.16", false),
    );
    let barrier = UpdateBarrier::open(coordinator).unwrap();
    barrier.prepare("0.2.17").await.unwrap();

    barrier.installer_opened().await.unwrap();

    assert_eq!(
        barrier.snapshot().unwrap().unwrap().phase(),
        UpdateJournalPhase::InstallerOpened
    );
    let selection: Value = serde_json::from_slice(
        &std::fs::read(root.path().join("common/runtime-selection-v1.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(selection["container_version"], "0.2.16");
}

#[tokio::test]
async fn replacement_restart_reuses_only_matching_verified_stop_receipt() {
    let root = tempfile::tempdir().unwrap();
    write_selection(root.path(), "0.2.16", RuntimeSlot::Latest);
    let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    let coordinator = offline_coordinator(
        owner,
        enrolled_store(RuntimeSlot::Latest),
        Arc::new(Control::default()),
        manifest("0.2.16", "0.2.16", false),
    );
    let barrier = UpdateBarrier::open(coordinator).unwrap();
    assert!(barrier
        .stop_proof("0.2.17", UpdateJournalPhase::LocalStopped)
        .is_err());
    barrier.prepare("0.2.17").await.unwrap();
    let proof = barrier
        .stop_proof("0.2.17", UpdateJournalPhase::LocalStopped)
        .unwrap();
    assert!(barrier
        .stop_proof("0.2.18", UpdateJournalPhase::LocalStopped)
        .is_err());
    let executable = root.path().join("common-broker");
    std::fs::write(&executable, b"old common").unwrap();
    let old_hash = nelomai_contracts::dispatcher::file_digest(&executable).unwrap();
    std::fs::write(&executable, b"replacement common").unwrap();
    assert_ne!(
        old_hash,
        nelomai_contracts::dispatcher::file_digest(&executable).unwrap(),
        "old dispatcher binding no longer authorizes this path"
    );
    assert!(barrier
        .stop_proof("0.2.17", UpdateJournalPhase::InstallerOpened)
        .is_err());
    barrier.installer_opened().await.unwrap();
    assert_eq!(
        proof,
        barrier
            .stop_proof("0.2.17", UpdateJournalPhase::InstallerOpened)
            .unwrap()
    );
    let journal = root.path().join("common/runtime-switch-v1.json");
    let mut value: Value = serde_json::from_slice(&std::fs::read(&journal).unwrap()).unwrap();
    value["local_stop_receipt"] = Value::Null;
    std::fs::write(journal, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(barrier
        .stop_proof("0.2.17", UpdateJournalPhase::InstallerOpened)
        .is_err());
}

#[tokio::test]
async fn update_journal_keeps_start_blocked_if_the_switch_journal_is_retired_mid_install() {
    let root = tempfile::tempdir().unwrap();
    write_selection(root.path(), "0.2.16", RuntimeSlot::Latest);
    let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    let coordinator = offline_coordinator(
        owner,
        enrolled_store(RuntimeSlot::Latest),
        Arc::new(Control::default()),
        manifest("0.2.16", "0.2.16", false),
    );
    let barrier = UpdateBarrier::open(coordinator.clone()).unwrap();
    barrier.prepare("0.2.17").await.unwrap();

    std::fs::remove_file(root.path().join("common/runtime-switch-v1.json")).unwrap();

    assert!(
        nelomai_client_core::RuntimeStartPreflight::check_start_barrier(coordinator.as_ref())
            .is_err()
    );
    assert!(coordinator.request(RuntimeSlot::Latest).await.is_err());
    assert!(coordinator.snapshot().unwrap().is_none());
}

#[tokio::test]
async fn reopened_update_rejects_a_mismatched_live_switch_operation() {
    let root = tempfile::tempdir().unwrap();
    write_selection(root.path(), "0.2.16", RuntimeSlot::Latest);
    let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    let store = enrolled_store(RuntimeSlot::Latest);
    let control = Arc::new(Control::default());
    let coordinator = offline_coordinator(
        owner.clone(),
        store.clone(),
        control.clone(),
        manifest("0.2.16", "0.2.16", false),
    );
    let barrier = UpdateBarrier::open(coordinator).unwrap();
    barrier.prepare("0.2.17").await.unwrap();
    let path = root.path().join("common/update-journal-v1.json");
    let mut journal: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    journal["operation_id"] = json!("99999999-9999-4999-8999-999999999999");
    std::fs::write(path, serde_json::to_vec(&journal).unwrap()).unwrap();

    assert!(UpdateBarrier::open(offline_coordinator(
        owner,
        store,
        control,
        manifest("0.2.16", "0.2.16", false),
    ))
    .is_err());
}

#[derive(Default)]
struct Panel {
    reconcile: AtomicUsize,
    resume: AtomicUsize,
    supersede: AtomicUsize,
    retry_reconcile: AtomicUsize,
    fail_resume: AtomicUsize,
    resume_apply: AtomicUsize,
    resume_cancel: AtomicUsize,
}

async fn reconcile(State(panel): State<Arc<Panel>>, Json(body): Json<Value>) -> Json<Value> {
    panel.reconcile.fetch_add(1, Ordering::SeqCst);
    if panel.retry_reconcile.swap(0, Ordering::SeqCst) > 0 {
        return Json(json!({"state":"retry","operation_id":body["operation_id"],
            "retired_lease_ids":[],"retired_session_ids":[],
            "retired_operation_ids":[],"retry_after_seconds":1}));
    }
    Json(json!({"state":"clean","operation_id":body["operation_id"],
        "retired_lease_ids":body["lease_ids"],"retired_session_ids":body["redundant_session_ids"],
        "retired_operation_ids":body["client_operation_ids"],"retry_after_seconds":null}))
}

async fn resume(
    State(panel): State<Arc<Panel>>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    panel.resume.fetch_add(1, Ordering::SeqCst);
    match body["decision"].as_str() {
        Some("apply") => {
            panel.resume_apply.fetch_add(1, Ordering::SeqCst);
        }
        Some("cancel") => {
            panel.resume_cancel.fetch_add(1, Ordering::SeqCst);
        }
        _ => {}
    }
    if panel.fail_resume.swap(0, Ordering::SeqCst) > 0 {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    Ok(Json(
        json!({"identity":{"container_version":body["target_identity"]["container_version"],
        "runtime_version":body["target_identity"]["runtime_version"],
        "runtime_contract_version":body["target_identity"]["runtime_contract_version"],
        "runtime_slot":body["target_identity"]["runtime_slot"],
        "session_generation":body["expected_session_generation"].as_u64().unwrap_or(0) + 1},
        "access_token":"resumed-access","token_type":"Bearer","access_expires_in":900}),
    ))
}

async fn supersede(State(panel): State<Arc<Panel>>) -> Json<Value> {
    panel.supersede.fetch_add(1, Ordering::SeqCst);
    Json(
        json!({"state":"clean","reconcile_operation_id":"44444444-4444-4444-8444-444444444444",
        "retry_after_seconds":null}),
    )
}

async fn panel() -> (
    Arc<Panel>,
    nelomai_client_api::ClientApi,
    tokio::task::JoinHandle<()>,
) {
    let state = Arc::new(Panel::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api =
        nelomai_client_api::ClientApi::new(&format!("http://{}", listener.local_addr().unwrap()))
            .unwrap()
            .with_app_version("0.2.16")
            .unwrap();
    let router = Router::new()
        .route(
            "/api/client/v1/connections/runtime-switch/reconcile",
            post(reconcile),
        )
        .route("/api/client/v1/auth/runtime/resume", post(resume))
        .route("/api/client/v1/auth/runtime/supersede", post(supersede))
        .with_state(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (state, api, server)
}

fn online_coordinator(
    owner: Arc<ContainerOwnerLock>,
    store: Arc<dyn AuthStore>,
    control: Arc<Control>,
    installed_manifest: nelomai_contracts::VerifiedContainerManifest,
    api: nelomai_client_api::ClientApi,
) -> Arc<SwitchCoordinator> {
    let broker = Arc::new(AuthBroker::new(api, store, Arc::new(Stop)).unwrap());
    Arc::new(
        SwitchCoordinator::open(owner, installed_manifest)
            .unwrap()
            .attach(broker, control),
    )
}

#[tokio::test]
async fn completed_update_cancellations_exceed_authority_capacity_across_restarts() {
    let (panel, api, server) = panel().await;
    let root = tempfile::tempdir().unwrap();
    write_selection(root.path(), "0.2.16", RuntimeSlot::Latest);
    let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    let store = enrolled_store(RuntimeSlot::Latest);
    let initial = store.load().unwrap().unwrap();
    let mut first_resume = None;
    for cycle in 0..20 {
        let broker = Arc::new(AuthBroker::new(api.clone(), store.clone(), Arc::new(Stop)).unwrap());
        let coordinator = Arc::new(
            SwitchCoordinator::open(owner.clone(), manifest("0.2.16", "0.2.16", false))
                .unwrap()
                .attach(broker.clone(), Arc::new(Control::default())),
        );
        let barrier = UpdateBarrier::open(coordinator.clone()).unwrap();
        assert_eq!(
            barrier.prepare("0.2.17").await.unwrap(),
            UpdatePrepare::LocalStopped
        );
        barrier
            .installer_failed()
            .await
            .unwrap_or_else(|error| panic!("cycle {cycle}: {error:?}"));
        assert!(barrier.snapshot().unwrap().is_none());
        coordinator.before_tunnel_start().await.unwrap();
        assert_eq!(
            coordinator.snapshot().unwrap().unwrap().phase(),
            SwitchPhase::Complete
        );
        let auth = store.load().unwrap().unwrap();
        assert_eq!(auth.auth_epoch, initial.auth_epoch);
        assert_eq!(auth.install_secret, initial.install_secret);
        assert_eq!(auth.session_generation, Some(8 + cycle));
        let metadata = auth.broker.as_ref().unwrap();
        assert_eq!(
            metadata.confirmed_device_id,
            initial.broker.as_ref().unwrap().confirmed_device_id
        );
        let current = metadata.completed_resume.as_ref().unwrap();
        let args = current.request.resume.as_ref().unwrap();
        let resume = nelomai_client_container::ResumeArguments {
            operation_id: current.request.operation_id.clone(),
            reconcile_operation_id: args.reconcile_operation_id.clone(),
            decision: args.decision.clone(),
            target: nelomai_client_api::RuntimeTarget::from_identity(&args.target),
            expected_session_generation: args.expected_session_generation,
        };
        // The current Complete journal still owns its exact replay evidence.
        assert!(broker
            .resume_transition(resume.clone())
            .await
            .unwrap()
            .current_access()
            .is_some());
        if first_resume.is_none() {
            first_resume = Some(resume);
        }
        if cycle == 19 {
            assert!(metadata.transition_authorities.len() < 16);
            assert!(broker
                .resume_transition(first_resume.clone().unwrap())
                .await
                .is_err());
            assert_eq!(store.load().unwrap().unwrap(), auth);
        }
    }
    assert_eq!(panel.resume_cancel.load(Ordering::SeqCst), 20);
    assert_eq!(panel.resume_apply.load(Ordering::SeqCst), 0);
    server.abort();
}

#[tokio::test]
async fn retirement_save_crashes_recover_with_current_replay_and_unresolved_authority() {
    for mode in [1, 2] {
        let (_, api, server) = panel().await;
        let root = tempfile::tempdir().unwrap();
        write_selection(root.path(), "0.2.16", RuntimeSlot::Latest);
        let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
        let store = Arc::new(FailRetirementSave {
            inner: enrolled_store(RuntimeSlot::Latest),
            mode: AtomicUsize::new(0),
        });
        let coordinator = online_coordinator(
            owner.clone(),
            store.clone(),
            Arc::new(Control::default()),
            manifest("0.2.16", "0.2.16", false),
            api.clone(),
        );
        let barrier = UpdateBarrier::open(coordinator.clone()).unwrap();
        barrier.prepare("0.2.17").await.unwrap();
        barrier.installer_failed().await.unwrap();
        let mut auth = store.load().unwrap().unwrap();
        let mut unresolved = auth.broker.as_ref().unwrap().transition_authorities[0].clone();
        unresolved.reconcile_operation_id = "99999999-9999-4999-8999-999999999999".into();
        unresolved.reconcile_receipt.as_mut().unwrap().operation_id =
            unresolved.reconcile_operation_id.clone();
        unresolved.resume_ticket = None;
        unresolved.resume_evidence = None;
        auth.broker
            .as_mut()
            .unwrap()
            .transition_authorities
            .push(unresolved.clone());
        store.save(&auth).unwrap();

        // New journal is durably installed before old authority can retire.
        barrier.prepare("0.2.17").await.unwrap();
        let operation = barrier
            .snapshot()
            .unwrap()
            .unwrap()
            .operation_id()
            .to_owned();
        store.mode.store(mode, Ordering::SeqCst);
        assert!(barrier.installer_failed().await.is_err());
        let persisted = store.load().unwrap().unwrap();
        assert!(persisted
            .broker
            .as_ref()
            .unwrap()
            .transition_authorities
            .contains(&unresolved));
        assert_eq!(persisted.session_generation, Some(9));
        drop(barrier);
        drop(coordinator);

        let reopened = online_coordinator(
            owner,
            store.clone(),
            Arc::new(Control::default()),
            manifest("0.2.16", "0.2.16", false),
            api,
        );
        let barrier = UpdateBarrier::open(reopened.clone()).unwrap();
        reopened.before_tunnel_start().await.unwrap();
        assert!(barrier.snapshot().unwrap().is_none());
        reopened.before_tunnel_start().await.unwrap();
        assert_eq!(
            serde_json::to_value(reopened.snapshot().unwrap().unwrap()).unwrap()["operation_id"],
            operation
        );
        let recovered = store.load().unwrap().unwrap();
        assert_eq!(recovered.session_generation, persisted.session_generation);
        assert_eq!(recovered.auth_epoch, persisted.auth_epoch);
        assert_eq!(recovered.access_token, persisted.access_token);
        let entries = &recovered.broker.as_ref().unwrap().transition_authorities;
        assert_eq!(entries.len(), 2);
        assert!(entries.contains(&unresolved));
        assert!(entries
            .iter()
            .any(|entry| entry.reconcile_operation_id == operation
                && entry.resume_evidence.is_some()));
        server.abort();
    }
}

#[tokio::test]
async fn retirement_waits_for_pending_auth_logout_and_supersede_dependencies() {
    let (_, api, server) = panel().await;
    let root = tempfile::tempdir().unwrap();
    write_selection(root.path(), "0.2.16", RuntimeSlot::Latest);
    let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    let store = enrolled_store(RuntimeSlot::Latest);
    let coordinator = online_coordinator(
        owner,
        store.clone(),
        Arc::new(Control::default()),
        manifest("0.2.16", "0.2.16", false),
        api,
    );
    let barrier = UpdateBarrier::open(coordinator.clone()).unwrap();
    barrier.prepare("0.2.17").await.unwrap();
    barrier.installer_failed().await.unwrap();
    let old = store
        .load()
        .unwrap()
        .unwrap()
        .broker
        .unwrap()
        .transition_authorities[0]
        .clone();
    barrier.prepare("0.2.17").await.unwrap();
    barrier.installer_failed().await.unwrap();
    let mut base = store.load().unwrap().unwrap();
    // Restore the valid state left by a crash before a prior retirement save.
    base.broker
        .as_mut()
        .unwrap()
        .transition_authorities
        .push(old.clone());
    let source = nelomai_client_storage::RuntimeLogoutSourceV1 {
        auth_epoch: old.source_auth_epoch,
        family: old.source_family.clone(),
        identity: old.source_identity.clone(),
        device_id: old.source_device_id.clone(),
        scope_fingerprint: old.source_scope_fingerprint.clone(),
    };
    for dependency in ["resume", "recovery", "logout", "logout_ack", "supersede"] {
        let mut pending = base.clone();
        let meta = pending.broker.as_mut().unwrap();
        match dependency {
            "resume" => meta.pending_request = old.resume_ticket.clone(),
            "recovery" => {
                meta.pending_recovery = Some(nelomai_client_storage::RecoveryTicketV1 {
                    operation_id: "88888888-8888-4888-8888-888888888888".into(),
                    auth_epoch: pending.auth_epoch,
                    attempt: meta.next_attempt,
                    family: meta.family.clone(),
                    identity: pending.confirmed_identity.clone().unwrap(),
                    device_id: meta.confirmed_device_id.clone(),
                })
            }
            "logout" => {
                meta.pending_logout = Some(nelomai_client_storage::PendingLogoutV1 {
                    operation_id: "88888888-8888-4888-8888-888888888888".into(),
                    refresh_proof: old.resume_refresh_proof.clone(),
                    source: Some(source.clone()),
                })
            }
            "logout_ack" => {
                pending.completed_runtime_logout =
                    Some(nelomai_client_storage::CompletedRuntimeLogoutV1 {
                        operation_id: "88888888-8888-4888-8888-888888888888".into(),
                        source: source.clone(),
                        code: "session_revoked_cleanup_accepted".into(),
                        cleanup_reconcile_operation_id: Some(old.reconcile_operation_id.clone()),
                    })
            }
            "supersede" => {
                pending.pending_runtime_supersede =
                    Some(nelomai_client_storage::PendingRuntimeSupersedeV1 {
                        operation_id: "88888888-8888-4888-8888-888888888888".into(),
                        superseded_reconcile_operation_id: old.reconcile_operation_id.clone(),
                        expected_session_generation: old.expected_session_generation,
                        target_identity: old.target_identity.clone(),
                        source: source.clone(),
                        refresh_proof: old.resume_refresh_proof.clone(),
                        response_state: None,
                        response_reconcile_operation_id: None,
                        retry_after_seconds: None,
                    })
            }
            _ => unreachable!(),
        }
        store.save(&pending).unwrap();
        coordinator.recover().await.unwrap();
        assert_eq!(store.load().unwrap().unwrap(), pending, "{dependency}");
    }
    store.save(&base).unwrap();
    coordinator.recover().await.unwrap();
    let retired = store.load().unwrap().unwrap();
    assert_eq!(
        retired
            .broker
            .as_ref()
            .unwrap()
            .transition_authorities
            .len(),
        1
    );
    assert_eq!(retired.session_generation, base.session_generation);
    assert_eq!(retired.auth_epoch, base.auth_epoch);
    assert_eq!(retired.access_token, base.access_token);
    server.abort();
}

async fn interrupt_after_update_cancel_before_switch_cancel(
    root: &std::path::Path,
    barrier: Arc<UpdateBarrier>,
    coordinator: Arc<SwitchCoordinator>,
    control: Arc<Control>,
) -> Value {
    control.stall_graceful.store(true, Ordering::SeqCst);
    let prepare = {
        let barrier = barrier.clone();
        tokio::spawn(async move { barrier.prepare("0.2.17").await })
    };
    control.graceful_entered.notified().await;
    assert_eq!(
        barrier.snapshot().unwrap().unwrap().phase(),
        UpdateJournalPhase::Requested
    );
    assert_eq!(
        coordinator.snapshot().unwrap().unwrap().phase(),
        SwitchPhase::RuntimeStopping
    );
    prepare.abort();
    let _ = prepare.await;
    control.release_graceful();

    let switch_path = root.join("common/runtime-switch-v1.json");
    let original_switch: Value =
        serde_json::from_slice(&std::fs::read(&switch_path).unwrap()).unwrap();
    assert_eq!(original_switch["cancel_requested"], false);
    let update_path = root.join("common/update-journal-v1.json");
    let mut update: Value = serde_json::from_slice(&std::fs::read(&update_path).unwrap()).unwrap();
    update["phase"] = json!("cancel_requested");
    std::fs::write(update_path, serde_json::to_vec(&update).unwrap()).unwrap();
    original_switch
}

#[tokio::test]
async fn installer_failure_restores_previous_slot_before_the_old_runtime_can_start() {
    let (panel, api, server) = panel().await;
    let root = tempfile::tempdir().unwrap();
    write_selection(root.path(), "0.2.16", RuntimeSlot::Stable);
    let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    let control = Arc::new(Control::default());
    let coordinator = online_coordinator(
        owner,
        enrolled_store(RuntimeSlot::Stable),
        control.clone(),
        manifest("0.2.16", "0.2.16", true),
        api,
    );
    let barrier = UpdateBarrier::open(coordinator.clone()).unwrap();
    barrier.prepare("0.2.17").await.unwrap();
    assert!(
        nelomai_client_core::RuntimeStartPreflight::check_start_barrier(coordinator.as_ref())
            .is_err()
    );

    barrier.installer_failed().await.unwrap();

    assert!(barrier.snapshot().unwrap().is_none());
    assert!(
        nelomai_client_core::RuntimeStartPreflight::check_start_barrier(coordinator.as_ref())
            .is_ok()
    );
    assert_eq!(
        coordinator.status().unwrap().selected_slot,
        RuntimeSlot::Stable
    );
    assert_eq!(panel.reconcile.load(Ordering::SeqCst), 1);
    assert_eq!(panel.resume.load(Ordering::SeqCst), 1);
    assert_eq!(control.completed.load(Ordering::SeqCst), 1);
    server.abort();
}

#[tokio::test]
async fn tunnel_preflight_cannot_resume_the_source_while_the_installer_is_in_flight() {
    let (_panel, api, server) = panel().await;
    let root = tempfile::tempdir().unwrap();
    write_selection(root.path(), "0.2.16", RuntimeSlot::Latest);
    let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    let control = Arc::new(Control::default());
    let coordinator = online_coordinator(
        owner,
        enrolled_store(RuntimeSlot::Latest),
        control.clone(),
        manifest("0.2.16", "0.2.16", false),
        api,
    );
    let barrier = UpdateBarrier::open(coordinator.clone()).unwrap();
    barrier.prepare("0.2.17").await.unwrap();

    assert!(coordinator.before_tunnel_start().await.is_err());
    assert_eq!(
        coordinator.snapshot().unwrap().unwrap().phase(),
        SwitchPhase::LocalStopped
    );
    assert_eq!(control.completed.load(Ordering::SeqCst), 0);
    assert!(coordinator.cancel_pending().await.is_err());
    assert_eq!(
        coordinator.snapshot().unwrap().unwrap().phase(),
        SwitchPhase::LocalStopped
    );

    barrier.installer_failed().await.unwrap();
    assert!(barrier.snapshot().unwrap().is_none());
    server.abort();
}

#[tokio::test]
async fn restart_after_every_old_container_phase_recovers_by_cancelling_exact_work() {
    for mark_opened in [false, true] {
        let (_panel, api, server) = panel().await;
        let root = tempfile::tempdir().unwrap();
        write_selection(root.path(), "0.2.16", RuntimeSlot::Latest);
        let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
        let store = enrolled_store(RuntimeSlot::Latest);
        let control = Arc::new(Control::default());
        let coordinator = online_coordinator(
            owner.clone(),
            store.clone(),
            control.clone(),
            manifest("0.2.16", "0.2.16", false),
            api.clone(),
        );
        let barrier = UpdateBarrier::open(coordinator).unwrap();
        barrier.prepare("0.2.17").await.unwrap();
        if mark_opened {
            barrier.installer_opened().await.unwrap();
        }
        drop(barrier);

        let reopened = UpdateBarrier::open(online_coordinator(
            owner,
            store,
            control,
            manifest("0.2.16", "0.2.16", false),
            api,
        ))
        .unwrap();
        reopened.recover("0.2.16").await.unwrap();
        assert!(reopened.snapshot().unwrap().is_none());
        server.abort();
    }
}

#[tokio::test]
async fn restart_from_requested_replays_the_same_cleanup_before_old_container_cancellation() {
    let (_panel, api, server) = panel().await;
    let root = tempfile::tempdir().unwrap();
    write_selection(root.path(), "0.2.16", RuntimeSlot::Latest);
    let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    let store = enrolled_store(RuntimeSlot::Latest);
    let control = Arc::new(Control::default());
    control.stall_graceful.store(true, Ordering::SeqCst);
    let coordinator = online_coordinator(
        owner.clone(),
        store.clone(),
        control.clone(),
        manifest("0.2.16", "0.2.16", false),
        api.clone(),
    );
    let barrier = Arc::new(UpdateBarrier::open(coordinator).unwrap());
    let prepare = {
        let barrier = barrier.clone();
        tokio::spawn(async move { barrier.prepare("0.2.17").await })
    };
    control.graceful_entered.notified().await;
    assert_eq!(
        barrier.snapshot().unwrap().unwrap().phase(),
        UpdateJournalPhase::Requested
    );
    let operation = barrier
        .snapshot()
        .unwrap()
        .unwrap()
        .operation_id()
        .to_owned();
    prepare.abort();
    let _ = prepare.await;
    drop(barrier);
    control.release_graceful();

    let reopened = UpdateBarrier::open(online_coordinator(
        owner,
        store,
        control,
        manifest("0.2.16", "0.2.16", false),
        api,
    ))
    .unwrap();
    assert_eq!(
        reopened.snapshot().unwrap().unwrap().operation_id(),
        operation
    );
    reopened.recover("0.2.16").await.unwrap();
    assert!(reopened.snapshot().unwrap().is_none());
    server.abort();
}

#[tokio::test]
async fn new_container_first_launch_reconciles_to_verified_latest_before_clearing_update() {
    let (panel, api, server) = panel().await;
    let root = tempfile::tempdir().unwrap();
    write_selection(root.path(), "0.2.16", RuntimeSlot::Stable);
    let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    let store = enrolled_store(RuntimeSlot::Stable);
    let old_control = Arc::new(Control::default());
    let old = online_coordinator(
        owner.clone(),
        store.clone(),
        old_control,
        manifest("0.2.16", "0.2.16", true),
        api.clone(),
    );
    let old_barrier = UpdateBarrier::open(old).unwrap();
    old_barrier.prepare("0.2.17").await.unwrap();
    old_barrier.installer_opened().await.unwrap();
    drop(old_barrier);

    write_selection(root.path(), "0.2.17", RuntimeSlot::Latest);
    let new_control = Arc::new(Control::default());
    let updated = online_coordinator(
        owner,
        store,
        new_control.clone(),
        manifest("0.2.17", "0.2.17", false),
        api,
    );
    let barrier = UpdateBarrier::open(updated.clone()).unwrap();

    barrier.recover("0.2.17").await.unwrap();

    assert!(barrier.snapshot().unwrap().is_none());
    assert_eq!(updated.status().unwrap().selected_slot, RuntimeSlot::Latest);
    assert_eq!(
        updated.snapshot().unwrap().unwrap().phase(),
        SwitchPhase::Complete
    );
    assert_eq!(panel.reconcile.load(Ordering::SeqCst), 1);
    assert_eq!(panel.supersede.load(Ordering::SeqCst), 1);
    assert_eq!(panel.resume.load(Ordering::SeqCst), 1);
    assert_eq!(new_control.completed.load(Ordering::SeqCst), 1);
    server.abort();
}

#[tokio::test]
async fn pending_installer_cancellation_reopens_and_tunnel_admission_retries_exact_work() {
    let (panel, api, server) = panel().await;
    panel.retry_reconcile.store(1, Ordering::SeqCst);
    let root = tempfile::tempdir().unwrap();
    write_selection(root.path(), "0.2.16", RuntimeSlot::Latest);
    let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    let store = enrolled_store(RuntimeSlot::Latest);
    let control = Arc::new(Control::default());
    let coordinator = online_coordinator(
        owner.clone(),
        store.clone(),
        control,
        manifest("0.2.16", "0.2.16", false),
        api.clone(),
    );
    let barrier = UpdateBarrier::open(coordinator).unwrap();
    barrier.prepare("0.2.17").await.unwrap();
    let operation = barrier
        .snapshot()
        .unwrap()
        .unwrap()
        .operation_id()
        .to_owned();

    assert!(matches!(
        barrier.installer_failed().await,
        Err(nelomai_client_container::UpdateBarrierError::Pending)
    ));
    assert!(barrier.snapshot().unwrap().is_some());
    let persisted: Value = serde_json::from_slice(
        &std::fs::read(root.path().join("common/update-journal-v1.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(persisted["phase"], "cancel_requested");
    drop(barrier);

    let reopened_coordinator = online_coordinator(
        owner,
        store,
        Arc::new(Control::default()),
        manifest("0.2.16", "0.2.16", false),
        api,
    );
    let reopened = UpdateBarrier::open(reopened_coordinator.clone()).unwrap();
    assert_eq!(
        reopened.snapshot().unwrap().unwrap().operation_id(),
        operation
    );
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;

    reopened_coordinator.before_tunnel_start().await.unwrap();

    assert!(reopened.snapshot().unwrap().is_none());
    assert_eq!(
        reopened_coordinator.snapshot().unwrap().unwrap().phase(),
        SwitchPhase::Complete
    );
    server.abort();
}

#[tokio::test]
async fn changed_container_admission_retries_server_reconciliation_in_the_same_process() {
    let (panel, api, server) = panel().await;
    let root = tempfile::tempdir().unwrap();
    write_selection(root.path(), "0.2.16", RuntimeSlot::Latest);
    let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    let store = enrolled_store(RuntimeSlot::Latest);
    let old = online_coordinator(
        owner.clone(),
        store.clone(),
        Arc::new(Control::default()),
        manifest("0.2.16", "0.2.16", false),
        api.clone(),
    );
    let old_barrier = UpdateBarrier::open(old).unwrap();
    old_barrier.prepare("0.2.17").await.unwrap();
    old_barrier.installer_opened().await.unwrap();
    drop(old_barrier);

    write_selection(root.path(), "0.2.17", RuntimeSlot::Latest);
    panel.retry_reconcile.store(1, Ordering::SeqCst);
    let updated = online_coordinator(
        owner,
        store,
        Arc::new(Control::default()),
        manifest("0.2.17", "0.2.17", false),
        api,
    );
    let barrier = UpdateBarrier::open(updated.clone()).unwrap();
    assert!(barrier.recover("0.2.17").await.is_err());
    assert_eq!(
        updated.snapshot().unwrap().unwrap().phase(),
        SwitchPhase::ServerReconciling
    );
    drop(barrier);

    let reopened = UpdateBarrier::open(updated.clone()).unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    updated.before_tunnel_start().await.unwrap();

    assert!(reopened.snapshot().unwrap().is_none());
    assert_eq!(panel.reconcile.load(Ordering::SeqCst), 2);
    assert_eq!(panel.resume.load(Ordering::SeqCst), 1);
    server.abort();
}

#[tokio::test]
async fn interrupted_auth_resume_reopens_with_original_update_provenance() {
    let (panel, api, server) = panel().await;
    let root = tempfile::tempdir().unwrap();
    write_selection(root.path(), "0.2.16", RuntimeSlot::Latest);
    let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    let store = enrolled_store(RuntimeSlot::Latest);
    let old = online_coordinator(
        owner.clone(),
        store.clone(),
        Arc::new(Control::default()),
        manifest("0.2.16", "0.2.16", false),
        api.clone(),
    );
    let old_barrier = UpdateBarrier::open(old).unwrap();
    old_barrier.prepare("0.2.17").await.unwrap();
    let operation = old_barrier
        .snapshot()
        .unwrap()
        .unwrap()
        .operation_id()
        .to_owned();
    old_barrier.installer_opened().await.unwrap();
    drop(old_barrier);

    write_selection(root.path(), "0.2.17", RuntimeSlot::Latest);
    panel.fail_resume.store(1, Ordering::SeqCst);
    let updated = online_coordinator(
        owner,
        store,
        Arc::new(Control::default()),
        manifest("0.2.17", "0.2.17", false),
        api,
    );
    let barrier = UpdateBarrier::open(updated.clone()).unwrap();
    assert!(barrier.recover("0.2.17").await.is_err());
    assert_eq!(
        updated.snapshot().unwrap().unwrap().phase(),
        SwitchPhase::AuthResuming
    );
    drop(barrier);

    let reopened = UpdateBarrier::open(updated).unwrap();
    assert_eq!(
        reopened.snapshot().unwrap().unwrap().operation_id(),
        operation
    );
    reopened.recover("0.2.17").await.unwrap();
    assert!(reopened.snapshot().unwrap().is_none());
    server.abort();
}

#[tokio::test]
async fn verified_installed_container_newer_than_the_offer_recovers_to_its_latest_runtime() {
    let (panel, api, server) = panel().await;
    let root = tempfile::tempdir().unwrap();
    write_selection(root.path(), "0.2.16", RuntimeSlot::Latest);
    let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    let store = enrolled_store(RuntimeSlot::Latest);
    let old = online_coordinator(
        owner.clone(),
        store.clone(),
        Arc::new(Control::default()),
        manifest("0.2.16", "0.2.16", false),
        api.clone(),
    );
    let old_barrier = UpdateBarrier::open(old).unwrap();
    old_barrier.prepare("0.2.17").await.unwrap();
    old_barrier.installer_opened().await.unwrap();
    drop(old_barrier);

    write_selection(root.path(), "0.2.18", RuntimeSlot::Latest);
    let updated = online_coordinator(
        owner,
        store,
        Arc::new(Control::default()),
        manifest("0.2.18", "0.2.18", false),
        api,
    );
    let barrier = UpdateBarrier::open(updated.clone()).unwrap();

    barrier.recover("0.2.18").await.unwrap();

    assert!(barrier.snapshot().unwrap().is_none());
    assert_eq!(updated.status().unwrap().selected_slot, RuntimeSlot::Latest);
    assert_eq!(panel.supersede.load(Ordering::SeqCst), 1);
    assert_eq!(panel.resume.load(Ordering::SeqCst), 1);
    server.abort();
}

#[tokio::test]
async fn interrupted_pre_stop_cancellation_reopens_and_resumes_as_exact_cancel() {
    let (panel, api, server) = panel().await;
    let root = tempfile::tempdir().unwrap();
    write_selection(root.path(), "0.2.16", RuntimeSlot::Latest);
    let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    let store = enrolled_store(RuntimeSlot::Latest);
    let control = Arc::new(Control::default());
    let coordinator = online_coordinator(
        owner.clone(),
        store.clone(),
        control.clone(),
        manifest("0.2.16", "0.2.16", false),
        api.clone(),
    );
    let barrier = Arc::new(UpdateBarrier::open(coordinator.clone()).unwrap());
    let original_switch = interrupt_after_update_cancel_before_switch_cancel(
        root.path(),
        barrier.clone(),
        coordinator,
        control,
    )
    .await;
    let operation = original_switch["operation_id"].clone();
    drop(barrier);

    let reopened_coordinator = online_coordinator(
        owner,
        store,
        Arc::new(Control::default()),
        manifest("0.2.16", "0.2.16", false),
        api,
    );
    let reopened = UpdateBarrier::open(reopened_coordinator.clone()).unwrap();
    reopened_coordinator.before_tunnel_start().await.unwrap();

    assert!(reopened.snapshot().unwrap().is_none());
    let completed: Value = serde_json::from_slice(
        &std::fs::read(root.path().join("common/runtime-switch-v1.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(completed["operation_id"], operation);
    assert_eq!(
        completed["source_identity"],
        original_switch["source_identity"]
    );
    assert_eq!(
        completed["cleanup_envelope"],
        original_switch["cleanup_envelope"]
    );
    assert_eq!(
        completed["runtime_snapshot"],
        original_switch["runtime_snapshot"]
    );
    assert_eq!(completed["decision"], "cancel");
    assert_eq!(panel.resume_cancel.load(Ordering::SeqCst), 1);
    assert_eq!(panel.resume_apply.load(Ordering::SeqCst), 0);
    server.abort();
}

#[tokio::test]
async fn failed_pre_stop_cancellation_keeps_exact_work_reopenable_for_admission_retry() {
    let (panel, api, server) = panel().await;
    let root = tempfile::tempdir().unwrap();
    write_selection(root.path(), "0.2.16", RuntimeSlot::Latest);
    let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    let store = enrolled_store(RuntimeSlot::Latest);
    let initial_control = Arc::new(Control::default());
    let initial = online_coordinator(
        owner.clone(),
        store.clone(),
        initial_control.clone(),
        manifest("0.2.16", "0.2.16", false),
        api.clone(),
    );
    let barrier = Arc::new(UpdateBarrier::open(initial.clone()).unwrap());
    let original_switch = interrupt_after_update_cancel_before_switch_cancel(
        root.path(),
        barrier.clone(),
        initial,
        initial_control,
    )
    .await;
    drop(barrier);

    let failing_control = Arc::new(Control::default());
    failing_control.fail_graceful.store(1, Ordering::SeqCst);
    failing_control.fail_force.store(1, Ordering::SeqCst);
    let failing = online_coordinator(
        owner.clone(),
        store.clone(),
        failing_control,
        manifest("0.2.16", "0.2.16", false),
        api.clone(),
    );
    let pending = UpdateBarrier::open(failing.clone()).unwrap();
    assert!(failing.before_tunnel_start().await.is_err());
    assert!(pending.snapshot().unwrap().is_some());
    assert_eq!(
        failing.snapshot().unwrap().unwrap().phase(),
        SwitchPhase::RuntimeStopping
    );
    let failed_switch: Value = serde_json::from_slice(
        &std::fs::read(root.path().join("common/runtime-switch-v1.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(failed_switch["cancel_requested"], true);
    assert_eq!(
        failed_switch["operation_id"],
        original_switch["operation_id"]
    );
    drop(pending);

    let recovered = online_coordinator(
        owner,
        store,
        Arc::new(Control::default()),
        manifest("0.2.16", "0.2.16", false),
        api,
    );
    let reopened = UpdateBarrier::open(recovered.clone()).unwrap();
    recovered.before_tunnel_start().await.unwrap();

    assert!(reopened.snapshot().unwrap().is_none());
    let completed: Value = serde_json::from_slice(
        &std::fs::read(root.path().join("common/runtime-switch-v1.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(completed["operation_id"], original_switch["operation_id"]);
    assert_eq!(
        completed["source_identity"],
        original_switch["source_identity"]
    );
    assert_eq!(
        completed["cleanup_envelope"],
        original_switch["cleanup_envelope"]
    );
    assert_eq!(completed["decision"], "cancel");
    assert_eq!(panel.resume_cancel.load(Ordering::SeqCst), 1);
    assert_eq!(panel.resume_apply.load(Ordering::SeqCst), 0);
    server.abort();
}
