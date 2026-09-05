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
        "runtime_slot":body["target_identity"]["runtime_slot"],"session_generation":8},
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
