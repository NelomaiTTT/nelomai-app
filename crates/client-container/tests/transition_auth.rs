use async_trait::async_trait;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use nelomai_client_api::{
    AccessSnapshot, LoginRequest, RuntimeSwitchReconcileRequest, RuntimeSwitchState, RuntimeTarget,
};
use nelomai_client_container::{
    AuthBroker, BrokerError, CleanupEngineRoleV1, FrozenReconcileRequest, LocalAuthStop,
    LocalStopReceiptV1, ResumeArguments, RuntimeCleanupHandoff, RuntimeRecordSwitchControl,
    RuntimeSwitchControl, SlotSelectionV1, SwitchCoordinator, SwitchPhase, SwitchProgress,
    UnavailableRuntimeForceStop,
};
use nelomai_client_core::{CoreLocalStop, RuntimeWriterGates};
use nelomai_client_storage::{
    AuthStore, AuthStoreV1, BrokerMetadataV1, BrokerRequestKind, BrokerRequestV1,
    ContainerOwnerLock, ProtectedAuthStore, ProtectedRecordStore, ProtectedRuntimeStore,
    RuntimeCleanupSnapshotV1, RuntimePaths, RuntimeRecordOwner, RuntimeStateStore, RuntimeStateV1,
    StorageError, StoredAuth, StoredConnection, StoredConnectionKind, StoredSplitTunnelState,
    TransitionAuthorityV1, TransitionDispatchStateV1,
};
use nelomai_client_tunnel::{TunnelController, TunnelError, TunnelStartRequest, TunnelStatus};
use nelomai_contracts::{
    verify_container_manifest, ContainerManifestV1, Platform, RuntimeArtifactManifestV1,
    RuntimeFileRole, RuntimeFileV1, RuntimeSlot, RuntimeSlotManifestV1,
    CONTAINER_MANIFEST_SIGNATURE_DOMAIN,
};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use tokio::sync::Notify;

fn manifest() -> nelomai_contracts::VerifiedContainerManifest {
    manifest_for("0.2.16", "0.2.16")
}

fn manifest_for(
    container_version: &str,
    runtime_version: &str,
) -> nelomai_contracts::VerifiedContainerManifest {
    manifest_with_optional_stable(container_version, runtime_version, false)
}

fn manifest_with_optional_stable(
    container_version: &str,
    runtime_version: &str,
    stable: bool,
) -> nelomai_contracts::VerifiedContainerManifest {
    use ed25519_dalek::{Signer, SigningKey};
    let mut manifest = ContainerManifestV1 {
        format_version: 1,
        container_version: container_version.into(),
        release_set_id: format!("runtime-{runtime_version}"),
        minimum_runtime_contract: 1,
        maximum_runtime_contract: 1,
        stable_release_set_sha256: None,
        stable_platform_manifest_sha256: None,
        slots: vec![RuntimeSlotManifestV1 {
            slot: RuntimeSlot::Latest,
            manifest: RuntimeArtifactManifestV1 {
                format_version: 1,
                runtime_version: runtime_version.into(),
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
        }],
    };
    if stable {
        let mut slot = manifest.slots[0].clone();
        slot.slot = RuntimeSlot::Stable;
        slot.manifest.runtime_version = "0.2.15".into();
        manifest.slots.push(slot);
        manifest.stable_release_set_sha256 = Some("b".repeat(64));
        manifest.stable_platform_manifest_sha256 = Some("c".repeat(64));
    }
    let bytes = serde_json::to_vec(&serde_json::to_value(manifest).unwrap()).unwrap();
    let key = SigningKey::from_bytes(&[59; 32]);
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

struct FailOnceRuntimeStore {
    inner: ProtectedRuntimeStore<Record>,
    fail_after_commit: Arc<AtomicUsize>,
}
impl RuntimeStateStore for FailOnceRuntimeStore {
    fn paths(&self) -> &RuntimePaths {
        self.inner.paths()
    }
    fn load(&self) -> Result<Option<RuntimeStateV1>, StorageError> {
        self.inner.load()
    }
    fn save(&self, value: &RuntimeStateV1) -> Result<(), StorageError> {
        self.inner.save(value)?;
        if self.fail_after_commit.swap(0, Ordering::SeqCst) == 1 {
            return Err(StorageError::RecoveryRequired(
                "synthetic crash after runtime record save",
            ));
        }
        Ok(())
    }
}

struct SaveGate {
    inner: Arc<dyn AuthStore>,
    saves_until_cancel: AtomicUsize,
}

struct FailAfterAtomicLegacyRefresh {
    inner: Arc<dyn AuthStore>,
    armed: AtomicUsize,
}
impl FailAfterAtomicLegacyRefresh {
    fn new(inner: Arc<dyn AuthStore>) -> Self {
        Self {
            inner,
            armed: AtomicUsize::new(0),
        }
    }
    fn arm(&self) {
        self.armed.store(1, Ordering::SeqCst);
    }
}
impl AuthStore for FailAfterAtomicLegacyRefresh {
    fn load(&self) -> Result<Option<AuthStoreV1>, StorageError> {
        self.inner.load()
    }
    fn save(&self, value: &AuthStoreV1) -> Result<(), StorageError> {
        self.inner.save(value)?;
        let atomic_completion = value.broker.as_ref().is_some_and(|meta| {
            meta.pending_request.is_none()
                && meta
                    .transition_authorities
                    .iter()
                    .any(|authority| authority.legacy_refresh_completed)
        });
        if atomic_completion && self.armed.swap(0, Ordering::SeqCst) == 1 {
            return Err(StorageError::RecoveryRequired(
                "synthetic crash after atomic legacy refresh save",
            ));
        }
        Ok(())
    }
}
impl SaveGate {
    fn new(inner: Arc<dyn AuthStore>) -> Self {
        Self {
            inner,
            saves_until_cancel: AtomicUsize::new(0),
        }
    }
    fn arm(&self) {
        self.arm_after(1);
    }
    fn arm_after(&self, saves: usize) {
        self.saves_until_cancel.store(saves, Ordering::SeqCst);
    }
}
impl AuthStore for SaveGate {
    fn load(&self) -> Result<Option<AuthStoreV1>, StorageError> {
        self.inner.load()
    }
    fn save(&self, value: &AuthStoreV1) -> Result<(), StorageError> {
        self.inner.save(value)?;
        if self
            .saves_until_cancel
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            == Ok(1)
        {
            let mut cancelled = value.clone();
            cancelled.auth_epoch += 1;
            cancelled.logout_state = nelomai_client_storage::LogoutState::LoggedOut;
            cancelled.access_token = None;
            cancelled.refresh_token = None;
            cancelled.broker.as_mut().unwrap().pending_request = None;
            self.inner.save(&cancelled)?;
        }
        Ok(())
    }
}
struct Stop;

struct RejectFirstResumeSave {
    inner: Arc<dyn AuthStore>,
    armed: AtomicUsize,
    reject_logout_consumption: AtomicUsize,
}
impl AuthStore for RejectFirstResumeSave {
    fn load(&self) -> Result<Option<AuthStoreV1>, StorageError> {
        self.inner.load()
    }
    fn save(&self, value: &AuthStoreV1) -> Result<(), StorageError> {
        if value.completed_runtime_logout.is_none()
            && self
                .inner
                .load()?
                .is_some_and(|auth| auth.completed_runtime_logout.is_some())
            && self.reject_logout_consumption.swap(0, Ordering::SeqCst) == 1
        {
            return Err(StorageError::RecoveryRequired(
                "synthetic crash before logout receipt consumption",
            ));
        }
        if value
            .broker
            .as_ref()
            .and_then(|meta| meta.pending_request.as_ref())
            .is_some_and(|ticket| ticket.kind == BrokerRequestKind::Resume)
            && self.armed.swap(0, Ordering::SeqCst) == 1
        {
            return Err(StorageError::RecoveryRequired(
                "synthetic crash before resume intent save",
            ));
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

#[derive(Default)]
struct SwitchTunnel(AtomicUsize);

#[async_trait]
impl TunnelController for SwitchTunnel {
    async fn start(&self, _: TunnelStartRequest) -> Result<(), TunnelError> {
        Ok(())
    }
    async fn stop(&self) -> Result<(), TunnelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn status(&self) -> Result<TunnelStatus, TunnelError> {
        Ok(TunnelStatus::Stopped)
    }
}

#[derive(Default)]
struct SwitchControl {
    handoffs: AtomicUsize,
    stops: AtomicUsize,
    completions: AtomicUsize,
    writer_gates: Arc<RuntimeWriterGates>,
    race_writer: AtomicUsize,
    writer_waiting: Arc<Notify>,
    writer_acquired: Arc<AtomicUsize>,
    hold_completion: AtomicUsize,
    completion_entered: Notify,
    completion_release: Notify,
    reject_completion: AtomicUsize,
}
#[async_trait]
impl RuntimeSwitchControl for SwitchControl {
    async fn handoff_cleanup(
        &self,
        source: &nelomai_client_container::TransitionSourceSnapshot,
    ) -> Result<RuntimeCleanupHandoff, BrokerError> {
        self.handoffs.fetch_add(1, Ordering::SeqCst);
        let auth_scope =
            source
                .identity()
                .map(|identity| nelomai_client_storage::RuntimeAuthScope {
                    auth_epoch: source.auth_epoch(),
                    family: source.family().into(),
                    identity: identity.clone(),
                });
        let snapshot = RuntimeCleanupSnapshotV1 {
            slot: source
                .identity()
                .map_or(RuntimeSlot::Latest, |identity| identity.slot),
            runtime_version: source.identity().map_or_else(
                || "0.2.16".into(),
                |identity| identity.runtime_version.clone(),
            ),
            auth_scope,
            lease_ids: vec!["lease-a".into()],
            operations: Vec::new(),
            cleanup_only: source.identity().is_none(),
        };
        let quiescence = self.writer_gates.quiesce().await;
        if self.race_writer.load(Ordering::SeqCst) == 1 {
            let waiting = self.writer_waiting.notified();
            let gate = self.writer_gates.lifecycle();
            let entered = self.writer_waiting.clone();
            let acquired = self.writer_acquired.clone();
            tokio::spawn(async move {
                entered.notify_one();
                let _writer = gate.lock_owned().await;
                acquired.store(1, Ordering::SeqCst);
            });
            waiting.await;
        }
        Ok(RuntimeCleanupHandoff::new(snapshot, quiescence))
    }
    async fn graceful_stop(
        &self,
        _operation_id: &str,
        _snapshot: &RuntimeCleanupSnapshotV1,
    ) -> Result<(), BrokerError> {
        assert_eq!(self.writer_acquired.load(Ordering::SeqCst), 0);
        self.stops.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn force_stop(
        &self,
        _operation_id: &str,
        _snapshot: &RuntimeCleanupSnapshotV1,
    ) -> Result<(), BrokerError> {
        panic!("graceful stop must not force")
    }
    async fn complete_cleanup_and_admit(
        &self,
        _snapshot: &RuntimeCleanupSnapshotV1,
        _receipt: &LocalStopReceiptV1,
        _access: &nelomai_client_api::AccessSnapshot,
    ) -> Result<(), BrokerError> {
        if self.reject_completion.load(Ordering::SeqCst) == 1 {
            return Err(BrokerError::RecoveryRequired);
        }
        if self.hold_completion.load(Ordering::SeqCst) == 1 {
            self.completion_entered.notify_one();
            self.completion_release.notified().await;
        }
        self.completions.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn legacy_store() -> Arc<dyn AuthStore> {
    let store = Arc::new(ProtectedAuthStore::new(Record::default()));
    let mut legacy = StoredAuth::new_install();
    legacy.install_secret = "synthetic-install".into();
    legacy.access_token = Some("legacy-access".into());
    legacy.refresh_token = Some("legacy-refresh".into());
    let mut auth = AuthStoreV1::from_legacy(&legacy);
    auth.broker = Some(BrokerMetadataV1 {
        family: "legacy-family".into(),
        next_attempt: 0,
        pending_request: None,
        completed_resume: None,
        pending_logout: None,
        pending_recovery: None,
        cancelled_login: None,
        authentication_outcome_unknown: false,
        pending_login_account: None,
        confirmed_device_id: None,
        pending_push_cleanup_epoch: None,
        transition_authorities: Vec::new(),
    });
    store.save(&auth).unwrap();
    store
}

fn enrolled_store() -> Arc<dyn AuthStore> {
    let store = legacy_store();
    let mut auth = store.load().unwrap().unwrap();
    let identity = target().identity(Some(7)).unwrap();
    auth.confirmed_identity = Some(identity);
    auth.session_generation = Some(7);
    auth.broker.as_mut().unwrap().confirmed_device_id = Some("device-a".into());
    store.save(&auth).unwrap();
    store
}

fn target() -> RuntimeTarget {
    RuntimeTarget {
        container_version: "0.2.16".into(),
        runtime_version: "0.2.16".into(),
        runtime_contract_version: 1,
        runtime_slot: RuntimeSlot::Latest,
    }
}

fn stable_target() -> RuntimeTarget {
    RuntimeTarget {
        runtime_slot: RuntimeSlot::Stable,
        ..target()
    }
}

#[derive(Default)]
struct Panel {
    bootstrap_calls: AtomicUsize,
    refresh_calls: AtomicUsize,
    reconcile_calls: AtomicUsize,
    headers: Mutex<Vec<HeaderMap>>,
    reject_bootstrap_access: AtomicUsize,
    fail_bootstrap: AtomicUsize,
    fail_refresh: AtomicUsize,
    bound_refresh: AtomicUsize,
    hold_refresh: AtomicUsize,
    refresh_entered: Notify,
    refresh_release: Notify,
    reject_reconcile_access: AtomicUsize,
    fail_reconcile: AtomicUsize,
    return_full_device_snapshot: AtomicUsize,
    return_retry: AtomicUsize,
    reconcile_bodies: Mutex<Vec<Value>>,
    resume_calls: AtomicUsize,
    supersede_calls: AtomicUsize,
    supersede_bodies: Mutex<Vec<Value>>,
    hold_resume: AtomicUsize,
    resume_entered: Notify,
    resume_release: Notify,
}

fn legacy_device() -> Value {
    json!({"id":"device-a","name":"legacy","platform":"macos",
        "container_version":"legacy","runtime_version":null,
        "runtime_contract_version":null,"runtime_slot":null,"session_generation":null})
}
async fn bootstrap(
    State(state): State<Arc<Panel>>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    state.bootstrap_calls.fetch_add(1, Ordering::SeqCst);
    state.headers.lock().unwrap().push(headers);
    if state.reject_bootstrap_access.swap(0, Ordering::SeqCst) == 1 {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"request_id":"r","code":"invalid_access_token","message":"expired"})),
        ));
    }
    if state.fail_bootstrap.swap(0, Ordering::SeqCst) == 1 {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"request_id":"r","code":"temporarily_unavailable","message":"offline"})),
        ));
    }
    Ok(Json(json!({"device":legacy_device()})))
}
async fn refresh(
    State(state): State<Arc<Panel>>,
    Json(_): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    state.refresh_calls.fetch_add(1, Ordering::SeqCst);
    if state.hold_refresh.load(Ordering::SeqCst) == 1 {
        state.refresh_entered.notify_one();
        state.refresh_release.notified().await;
    }
    if state.fail_refresh.load(Ordering::SeqCst) == 1 {
        return Err(StatusCode::BAD_GATEWAY);
    }
    Ok(Json(
        json!({"api_version":"1","request_id":"r","token_type":"Bearer",
        "access_token":"refreshed-access","access_expires_in":900,
        "refresh_token":"refreshed-refresh","refresh_expires_in":3600,
        "access":{"state":"active","can_login":true,"can_connect":true,"expires_at":null},
        "device":if state.bound_refresh.load(Ordering::SeqCst) == 1 { json!({"id":"device-a","name":"bound","platform":"macos","container_version":"0.2.16","runtime_version":"0.2.16","runtime_contract_version":1,"runtime_slot":"latest","session_generation":7}) } else { legacy_device() }}),
    ))
}
async fn reconcile(
    State(state): State<Arc<Panel>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    state.reconcile_calls.fetch_add(1, Ordering::SeqCst);
    state.headers.lock().unwrap().push(headers);
    state.reconcile_bodies.lock().unwrap().push(body.clone());
    if state.reject_reconcile_access.swap(0, Ordering::SeqCst) == 1 {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"request_id":"r","code":"invalid_access_token","message":"expired"})),
        ));
    }
    if state.fail_reconcile.swap(0, Ordering::SeqCst) == 1 {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"request_id":"r","code":"temporarily_unavailable","message":"offline"})),
        ));
    }
    if state.return_full_device_snapshot.load(Ordering::SeqCst) == 1 {
        return Ok(Json(
            json!({"state":"clean","operation_id":body["operation_id"],
            "retired_lease_ids":["server-lease"],
            "retired_session_ids":["server-session"],
            "retired_operation_ids":["server-operation"],
            "retry_after_seconds":null}),
        ));
    }
    if state.return_retry.swap(0, Ordering::SeqCst) == 1 {
        return Ok(Json(
            json!({"state":"retry","operation_id":body["operation_id"],
            "retired_lease_ids":[],"retired_session_ids":[],
            "retired_operation_ids":[],"retry_after_seconds":1}),
        ));
    }
    Ok(Json(
        json!({"state":"clean","operation_id":body["operation_id"],
        "retired_lease_ids":body["lease_ids"],"retired_session_ids":body["redundant_session_ids"],
        "retired_operation_ids":body["client_operation_ids"],"retry_after_seconds":null}),
    ))
}
async fn resume(State(state): State<Arc<Panel>>, Json(body): Json<Value>) -> Json<Value> {
    state.resume_calls.fetch_add(1, Ordering::SeqCst);
    state.resume_entered.notify_one();
    if state.hold_resume.load(Ordering::SeqCst) == 1 {
        state.resume_release.notified().await;
    }
    let generation = body["expected_session_generation"].as_u64().unwrap_or(0) + 1;
    Json(
        json!({"identity":{"container_version":body["target_identity"]["container_version"],
        "runtime_version":body["target_identity"]["runtime_version"],
        "runtime_contract_version":body["target_identity"]["runtime_contract_version"],
        "runtime_slot":body["target_identity"]["runtime_slot"],"session_generation":generation},
        "access_token":"runtime-access","token_type":"Bearer","access_expires_in":900}),
    )
}
async fn supersede(State(state): State<Arc<Panel>>, Json(body): Json<Value>) -> Json<Value> {
    let call = state.supersede_calls.fetch_add(1, Ordering::SeqCst);
    state.supersede_bodies.lock().unwrap().push(body);
    Json(json!({
        "state":"clean",
        "reconcile_operation_id":if call == 0 { "44444444-4444-4444-8444-444444444444" } else { "55555555-5555-4555-8555-555555555555" },
        "retry_after_seconds":null
    }))
}

#[tokio::test]
async fn retry_receipt_replays_the_exact_frozen_request_until_clean() {
    let state = Arc::new(Panel::default());
    state.return_retry.store(1, Ordering::SeqCst);
    let (api, server) = panel(state.clone()).await;
    let store = legacy_store();
    let broker = AuthBroker::new(api.clone(), store.clone(), Arc::new(Stop)).unwrap();
    let source = broker.transition_source().await.unwrap();
    let frozen = FrozenReconcileRequest::new(reconcile_request(&source), &source).unwrap();

    assert_eq!(
        broker
            .reconcile_transition(frozen.clone())
            .await
            .unwrap()
            .state,
        RuntimeSwitchState::Retry
    );
    drop(broker);
    let reopened = AuthBroker::new(api, store, Arc::new(Stop)).unwrap();
    assert_eq!(
        reopened.reconcile_transition(frozen).await.unwrap().state,
        RuntimeSwitchState::Clean
    );
    assert_eq!(state.reconcile_calls.load(Ordering::SeqCst), 2);
    let bodies = state.reconcile_bodies.lock().unwrap();
    assert_eq!(bodies[0], bodies[1]);
    server.abort();
}

#[tokio::test]
async fn unresolved_current_transition_fences_ordinary_issuance_but_allows_exact_completion() {
    let state = Arc::new(Panel::default());
    state.fail_reconcile.store(1, Ordering::SeqCst);
    let (api, server) = panel(state.clone()).await;
    let store = enrolled_store();
    let broker = AuthBroker::new(api, store, Arc::new(Stop)).unwrap();
    let current = broker.access_token(None).await.unwrap();
    let source = broker.transition_source().await.unwrap();
    let frozen = FrozenReconcileRequest::new(reconcile_request(&source), &source).unwrap();
    assert!(broker.reconcile_transition(frozen.clone()).await.is_err());

    assert!(matches!(
        broker.access_token(Some(&current)).await,
        Err(BrokerError::RecoveryRequired)
    ));
    assert!(matches!(
        broker
            .resume(ResumeArguments {
                operation_id: "22222222-2222-4222-8222-222222222222".into(),
                reconcile_operation_id: frozen.request().operation_id.clone(),
                decision: "apply".into(),
                target: target(),
                expected_session_generation: Some(7),
            })
            .await,
        Err(BrokerError::RecoveryRequired)
    ));
    assert!(matches!(
        broker.begin_background_recovery().await,
        Err(BrokerError::RecoveryRequired)
    ));
    assert_eq!(state.refresh_calls.load(Ordering::SeqCst), 0);
    assert_eq!(state.resume_calls.load(Ordering::SeqCst), 0);

    broker.reconcile_transition(frozen.clone()).await.unwrap();
    broker
        .resume_transition(ResumeArguments {
            operation_id: "22222222-2222-4222-8222-222222222222".into(),
            reconcile_operation_id: frozen.request().operation_id.clone(),
            decision: "apply".into(),
            target: target(),
            expected_session_generation: Some(7),
        })
        .await
        .unwrap();
    assert_eq!(state.resume_calls.load(Ordering::SeqCst), 1);
    server.abort();
}

#[tokio::test]
async fn enrolled_cancel_resumes_the_frozen_source_without_rewriting_the_apply_target() {
    let state = Arc::new(Panel::default());
    let (api, server) = panel(state).await;
    let store = enrolled_store();
    let broker = AuthBroker::new(api, store.clone(), Arc::new(Stop)).unwrap();
    let source = broker.transition_source().await.unwrap();
    let mut request = reconcile_request(&source);
    request.target_identity = stable_target();
    let frozen = FrozenReconcileRequest::new(request, &source).unwrap();
    broker.reconcile_transition(frozen.clone()).await.unwrap();

    let receipt = broker
        .resume_transition(ResumeArguments {
            operation_id: "22222222-2222-4222-8222-222222222222".into(),
            reconcile_operation_id: frozen.request().operation_id.clone(),
            decision: "cancel".into(),
            target: target(),
            expected_session_generation: Some(7),
        })
        .await
        .unwrap();
    assert_eq!(receipt.identity().slot, RuntimeSlot::Latest);
    let authority = &store
        .load()
        .unwrap()
        .unwrap()
        .broker
        .unwrap()
        .transition_authorities[0];
    assert_eq!(authority.target_identity.slot, RuntimeSlot::Stable);
    assert_eq!(
        authority
            .resume_evidence
            .as_ref()
            .unwrap()
            .target_identity
            .slot,
        RuntimeSlot::Latest
    );
    server.abort();
}

#[tokio::test]
async fn reconcile_rechecks_cancellation_after_dispatch_intent_before_http() {
    let state = Arc::new(Panel::default());
    let (api, server) = panel(state.clone()).await;
    let gated = Arc::new(SaveGate::new(legacy_store()));
    let store: Arc<dyn AuthStore> = gated.clone();
    let broker = AuthBroker::new(api, store, Arc::new(Stop)).unwrap();
    let source = broker.transition_source().await.unwrap();
    let frozen = FrozenReconcileRequest::new(reconcile_request(&source), &source).unwrap();
    gated.arm_after(2);

    assert!(matches!(
        broker.reconcile_transition(frozen).await,
        Err(BrokerError::Cancelled)
    ));
    assert_eq!(state.reconcile_calls.load(Ordering::SeqCst), 0);
    server.abort();
}
async fn logout() -> Json<Value> {
    Json(json!({"code":"session_revoked_cleanup_accepted",
        "cleanup_reconcile_operation_id":"11111111-1111-4111-8111-111111111111"}))
}
async fn login() -> Json<Value> {
    Json(
        json!({"api_version":"1","request_id":"r","token_type":"Bearer",
        "access_token":"login-b-access","access_expires_in":900,
        "refresh_token":"login-b-refresh","refresh_expires_in":3600,
        "access":{"state":"active","can_login":true,"can_connect":true,"expires_at":null},
        "device":{"id":"device-b","name":"B","platform":"macos",
            "container_version":"0.2.16","runtime_version":"0.2.16",
            "runtime_contract_version":1,"runtime_slot":"latest","session_generation":1}}),
    )
}
async fn panel(state: Arc<Panel>) -> (nelomai_client_api::ClientApi, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api =
        nelomai_client_api::ClientApi::new(&format!("http://{}", listener.local_addr().unwrap()))
            .unwrap()
            .with_app_version("0.2.16")
            .unwrap();
    let router = Router::new()
        .route("/api/client/v1/bootstrap", get(bootstrap))
        .route("/api/client/v1/auth/refresh", post(refresh))
        .route(
            "/api/client/v1/connections/runtime-switch/reconcile",
            post(reconcile),
        )
        .route("/api/client/v1/auth/runtime/resume", post(resume))
        .route("/api/client/v1/auth/runtime/supersede", post(supersede))
        .route("/api/client/v1/auth/logout-runtime", post(logout))
        .route("/api/client/v1/auth/login", post(login))
        .with_state(state);
    (
        api,
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        }),
    )
}

#[tokio::test]
async fn exact_legacy_401_rotates_once_but_generic_bootstrap_failure_never_rotates() {
    let state = Arc::new(Panel::default());
    state.reject_bootstrap_access.store(1, Ordering::SeqCst);
    let (api, server) = panel(state.clone()).await;
    let broker = AuthBroker::new(api, legacy_store(), Arc::new(Stop)).unwrap();
    assert_eq!(
        broker.transition_source().await.unwrap().device_id(),
        "device-a"
    );
    assert_eq!(state.bootstrap_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.refresh_calls.load(Ordering::SeqCst), 1);
    server.abort();

    let state = Arc::new(Panel::default());
    state.fail_bootstrap.store(1, Ordering::SeqCst);
    let (api, server) = panel(state.clone()).await;
    let broker = AuthBroker::new(api, legacy_store(), Arc::new(Stop)).unwrap();
    assert!(broker.transition_source().await.is_err());
    assert_eq!(state.refresh_calls.load(Ordering::SeqCst), 0);
    server.abort();
}

#[tokio::test]
async fn exact_first_reconcile_401_updates_proof_once_and_lost_reply_replays_exact_body() {
    let state = Arc::new(Panel::default());
    state.reject_reconcile_access.store(1, Ordering::SeqCst);
    let (api, server) = panel(state.clone()).await;
    let store = legacy_store();
    let broker = AuthBroker::new(api.clone(), store.clone(), Arc::new(Stop)).unwrap();
    let source = broker.transition_source().await.unwrap();
    let frozen = FrozenReconcileRequest::new(reconcile_request(&source), &source).unwrap();
    assert_eq!(
        broker
            .reconcile_transition(frozen.clone())
            .await
            .unwrap()
            .state,
        RuntimeSwitchState::Clean
    );
    assert_eq!(state.refresh_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.reconcile_calls.load(Ordering::SeqCst), 2);

    let mut saved = store.load().unwrap().unwrap();
    saved
        .broker
        .as_mut()
        .unwrap()
        .transition_authorities
        .clear();
    store.save(&saved).unwrap();
    state.fail_reconcile.store(1, Ordering::SeqCst);
    let source = broker.transition_source().await.unwrap();
    let mut request = reconcile_request(&source);
    request.operation_id = "33333333-3333-4333-8333-333333333333".into();
    let frozen = FrozenReconcileRequest::new(request, &source).unwrap();
    assert!(broker.reconcile_transition(frozen.clone()).await.is_err());
    drop(broker);
    let reopened = AuthBroker::new(api, store.clone(), Arc::new(Stop)).unwrap();
    reopened.reconcile_transition(frozen).await.unwrap();
    let bodies = state.reconcile_bodies.lock().unwrap();
    assert_eq!(bodies[bodies.len() - 2], bodies[bodies.len() - 1]);
    assert_eq!(
        store
            .load()
            .unwrap()
            .unwrap()
            .broker
            .unwrap()
            .transition_authorities
            .len(),
        1
    );
    server.abort();
}

#[tokio::test]
async fn crash_after_atomic_legacy_refresh_save_never_rotates_the_family_twice() {
    let state = Arc::new(Panel::default());
    state.reject_reconcile_access.store(1, Ordering::SeqCst);
    let (api, server) = panel(state.clone()).await;
    let inner = legacy_store();
    let store = Arc::new(FailAfterAtomicLegacyRefresh::new(inner));
    let broker = AuthBroker::new(api.clone(), store.clone(), Arc::new(Stop)).unwrap();
    let source = broker.transition_source().await.unwrap();
    let frozen = FrozenReconcileRequest::new(reconcile_request(&source), &source).unwrap();
    store.arm();

    assert!(broker.reconcile_transition(frozen.clone()).await.is_err());
    drop(broker);
    let reopened = AuthBroker::new(api, store, Arc::new(Stop)).unwrap();
    assert_eq!(
        reopened.reconcile_transition(frozen).await.unwrap().state,
        RuntimeSwitchState::Clean
    );
    assert_eq!(state.refresh_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.reconcile_calls.load(Ordering::SeqCst), 2);
    server.abort();
}

#[tokio::test]
async fn broker_persists_and_replays_the_exact_server_full_device_snapshot() {
    let state = Arc::new(Panel::default());
    state.return_full_device_snapshot.store(1, Ordering::SeqCst);
    let (api, server) = panel(state.clone()).await;
    let store = legacy_store();
    let broker = AuthBroker::new(api.clone(), store.clone(), Arc::new(Stop)).unwrap();
    let source = broker.transition_source().await.unwrap();
    let mut request = reconcile_request(&source);
    request.lease_ids.clear();
    request.redundant_session_ids.clear();
    request.client_operation_ids.clear();
    let frozen = FrozenReconcileRequest::new(request, &source).unwrap();
    let first = broker.reconcile_transition(frozen.clone()).await.unwrap();
    assert_eq!(first.retired_lease_ids, ["server-lease"]);
    assert_eq!(first.retired_session_ids, ["server-session"]);
    assert_eq!(first.retired_operation_ids, ["server-operation"]);
    drop(broker);

    let reopened = AuthBroker::new(api, store, Arc::new(Stop)).unwrap();
    let replay = reopened.reconcile_transition(frozen).await.unwrap();
    assert_eq!(replay, first);
    assert_eq!(state.reconcile_calls.load(Ordering::SeqCst), 1);
    server.abort();
}

#[tokio::test]
async fn clean_supersede_is_protected_replay_and_exposes_only_the_successor_authority() {
    let state = Arc::new(Panel::default());
    let (api, server) = panel(state.clone()).await;
    let store = enrolled_store();
    let broker = AuthBroker::new(api, store.clone(), Arc::new(Stop)).unwrap();
    let source = broker.transition_source().await.unwrap();
    let predecessor = FrozenReconcileRequest::new(reconcile_request(&source), &source).unwrap();
    broker
        .reconcile_transition(predecessor.clone())
        .await
        .unwrap();
    let operation_id = "33333333-3333-4333-8333-333333333333";
    let first = broker
        .supersede_transition(operation_id, predecessor.clone(), stable_target())
        .await
        .unwrap();
    let replay = broker
        .supersede_transition(operation_id, predecessor.clone(), stable_target())
        .await
        .unwrap();
    assert_eq!(first, replay);
    assert_eq!(state.supersede_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.supersede_bodies.lock().unwrap().len(), 1);

    let mut successor_request = predecessor.request().clone();
    successor_request.operation_id = first.reconcile_operation_id.clone();
    successor_request.target_identity = stable_target();
    let successor = FrozenReconcileRequest::new(successor_request, &source).unwrap();
    assert_eq!(
        broker.reconcile_transition(successor).await.unwrap().state,
        RuntimeSwitchState::Clean
    );
    broker
        .finish_supersede(operation_id, &first.reconcile_operation_id)
        .await
        .unwrap();
    assert!(store
        .load()
        .unwrap()
        .unwrap()
        .pending_runtime_supersede
        .is_none());
    server.abort();
}

#[tokio::test]
async fn bound_known_expiry_refreshes_same_source_without_changing_frozen_reconcile() {
    for accepted in [false, true] {
        let state = Arc::new(Panel::default());
        state.bound_refresh.store(1, Ordering::SeqCst);
        let (api, server) = panel(state.clone()).await;
        let store = enrolled_store();
        let broker = AuthBroker::new(api, store.clone(), Arc::new(Stop)).unwrap();
        let source = broker.transition_source().await.unwrap();
        let frozen = FrozenReconcileRequest::new(reconcile_request(&source), &source).unwrap();
        if accepted {
            state.return_retry.store(1, Ordering::SeqCst);
            assert_eq!(
                broker
                    .reconcile_transition(frozen.clone())
                    .await
                    .unwrap()
                    .state,
                RuntimeSwitchState::Retry
            );
            state.return_retry.store(0, Ordering::SeqCst);
        }
        state.reject_reconcile_access.store(1, Ordering::SeqCst);
        assert_eq!(
            broker
                .reconcile_transition(frozen.clone())
                .await
                .unwrap()
                .state,
            RuntimeSwitchState::Clean
        );
        assert_eq!(state.refresh_calls.load(Ordering::SeqCst), 1);
        let auth = store.load().unwrap().unwrap();
        assert_eq!(auth.session_generation, Some(7));
        assert_eq!(auth.access_token.as_deref(), Some("refreshed-access"));
        let authorities = auth.broker.unwrap().transition_authorities;
        assert_eq!(authorities.len(), 1);
        assert_eq!(
            authorities[0].request_fingerprint,
            frozen.request_fingerprint()
        );
        assert_eq!(authorities[0].resume_refresh_proof, "refreshed-refresh");
        assert!(state
            .reconcile_bodies
            .lock()
            .unwrap()
            .windows(2)
            .all(|pair| pair[0] == pair[1]));
        server.abort();
    }
}

#[tokio::test]
async fn bound_persisted_known_rejection_can_refresh_but_uncertain_dispatch_never_can() {
    for dispatch in [
        TransitionDispatchStateV1::InvalidAccessRejected,
        TransitionDispatchStateV1::DispatchIntent,
        TransitionDispatchStateV1::OutcomeUnknown,
    ] {
        let state = Arc::new(Panel::default());
        state.bound_refresh.store(1, Ordering::SeqCst);
        let (api, server) = panel(state.clone()).await;
        let store = enrolled_store();
        let broker = AuthBroker::new(api.clone(), store.clone(), Arc::new(Stop)).unwrap();
        let source = broker.transition_source().await.unwrap();
        let frozen = FrozenReconcileRequest::new(reconcile_request(&source), &source).unwrap();
        insert_reconcile_authority(&store, &frozen, dispatch);
        drop(broker);
        if dispatch == TransitionDispatchStateV1::InvalidAccessRejected {
            let broker = AuthBroker::new(api, store, Arc::new(Stop)).unwrap();
            assert_eq!(
                broker.reconcile_transition(frozen).await.unwrap().state,
                RuntimeSwitchState::Clean
            );
            assert_eq!(state.refresh_calls.load(Ordering::SeqCst), 1);
        } else {
            for _ in 0..2 {
                state.reject_reconcile_access.store(1, Ordering::SeqCst);
                let broker = AuthBroker::new(api.clone(), store.clone(), Arc::new(Stop)).unwrap();
                assert!(broker.reconcile_transition(frozen.clone()).await.is_err());
                assert_eq!(state.refresh_calls.load(Ordering::SeqCst), 0);
                assert_eq!(
                    store
                        .load()
                        .unwrap()
                        .unwrap()
                        .broker
                        .unwrap()
                        .transition_authorities[0]
                        .dispatch_state,
                    TransitionDispatchStateV1::OutcomeUnknown
                );
            }
        }
        server.abort();
    }
}

#[tokio::test]
async fn lost_bound_refresh_response_keeps_pending_ticket_and_never_rotates_again() {
    let state = Arc::new(Panel::default());
    state.bound_refresh.store(1, Ordering::SeqCst);
    state.reject_reconcile_access.store(1, Ordering::SeqCst);
    state.fail_refresh.store(1, Ordering::SeqCst);
    let (api, server) = panel(state.clone()).await;
    let store = enrolled_store();
    let broker = AuthBroker::new(api.clone(), store.clone(), Arc::new(Stop)).unwrap();
    let source = broker.transition_source().await.unwrap();
    let frozen = FrozenReconcileRequest::new(reconcile_request(&source), &source).unwrap();
    assert!(broker.reconcile_transition(frozen.clone()).await.is_err());
    drop(broker);
    let before = store.load().unwrap().unwrap();
    assert_eq!(
        before
            .broker
            .as_ref()
            .unwrap()
            .pending_request
            .as_ref()
            .unwrap()
            .kind,
        BrokerRequestKind::Refresh
    );
    state.fail_refresh.store(0, Ordering::SeqCst);
    let broker = AuthBroker::new(api, store.clone(), Arc::new(Stop)).unwrap();
    assert!(broker.reconcile_transition(frozen).await.is_err());
    assert_eq!(state.refresh_calls.load(Ordering::SeqCst), 1);
    assert_eq!(before, store.load().unwrap().unwrap());
    server.abort();
}

#[tokio::test]
async fn logout_fences_late_bound_transition_refresh_and_new_family_replay() {
    let state = Arc::new(Panel::default());
    state.bound_refresh.store(1, Ordering::SeqCst);
    state.hold_refresh.store(1, Ordering::SeqCst);
    state.reject_reconcile_access.store(1, Ordering::SeqCst);
    let (api, server) = panel(state.clone()).await;
    let store = enrolled_store();
    let broker = Arc::new(AuthBroker::new(api, store.clone(), Arc::new(Stop)).unwrap());
    let source = broker.transition_source().await.unwrap();
    let frozen = FrozenReconcileRequest::new(reconcile_request(&source), &source).unwrap();
    let pending = {
        let broker = broker.clone();
        let frozen = frozen.clone();
        tokio::spawn(async move { broker.reconcile_transition(frozen).await })
    };
    state.refresh_entered.notified().await;
    broker.logout().await.unwrap();
    let logged_out = store.load().unwrap().unwrap();
    state.refresh_release.notify_one();
    assert!(matches!(
        pending.await.unwrap(),
        Err(BrokerError::Cancelled)
    ));
    assert_eq!(store.load().unwrap().unwrap(), logged_out);
    assert!(broker.access_token(None).await.is_err());
    broker
        .login(
            &LoginRequest {
                login: "b".into(),
                password: "synthetic-password".into(),
                install_secret: "ignored".into(),
                device_name: "B".into(),
                platform: Platform::Macos,
                platform_version: None,
                architecture: "aarch64".into(),
                app_version: "0.2.16".into(),
            },
            &target(),
        )
        .await
        .unwrap();
    let new_family = store.load().unwrap().unwrap();
    assert!(broker.reconcile_transition(frozen).await.is_err());
    assert_eq!(store.load().unwrap().unwrap(), new_family);
    assert_eq!(new_family.access_token.as_deref(), Some("login-b-access"));
    assert_eq!(state.refresh_calls.load(Ordering::SeqCst), 1);
    server.abort();
}

#[tokio::test]
async fn uncertain_reconcile_replays_before_401_and_never_rotates_the_legacy_proof() {
    let state = Arc::new(Panel::default());
    state.fail_reconcile.store(1, Ordering::SeqCst);
    let (api, server) = panel(state.clone()).await;
    let store = legacy_store();
    let broker = AuthBroker::new(api.clone(), store.clone(), Arc::new(Stop)).unwrap();
    let source = broker.transition_source().await.unwrap();
    let frozen = FrozenReconcileRequest::new(reconcile_request(&source), &source).unwrap();
    assert!(broker.reconcile_transition(frozen.clone()).await.is_err());

    state.reject_reconcile_access.store(1, Ordering::SeqCst);
    drop(broker);
    let reopened = AuthBroker::new(api, store, Arc::new(Stop)).unwrap();
    assert!(reopened.reconcile_transition(frozen).await.is_err());

    assert_eq!(state.reconcile_calls.load(Ordering::SeqCst), 2);
    assert_eq!(state.refresh_calls.load(Ordering::SeqCst), 0);
    let bodies = state.reconcile_bodies.lock().unwrap();
    assert_eq!(bodies[0], bodies[1]);
    server.abort();
}

#[tokio::test]
async fn newer_login_preserves_old_replay_authority_without_adopting_old_access() {
    let state = Arc::new(Panel::default());
    state.fail_reconcile.store(1, Ordering::SeqCst);
    let (api, server) = panel(state.clone()).await;
    let store = legacy_store();
    let broker = AuthBroker::new(api, store.clone(), Arc::new(Stop)).unwrap();
    let source = broker.transition_source().await.unwrap();
    let frozen = FrozenReconcileRequest::new(reconcile_request(&source), &source).unwrap();
    assert!(broker.reconcile_transition(frozen.clone()).await.is_err());
    broker.logout().await.unwrap();
    broker
        .login(
            &LoginRequest {
                login: "b".into(),
                password: "synthetic-password".into(),
                install_secret: "ignored".into(),
                device_name: "B".into(),
                platform: Platform::Macos,
                platform_version: None,
                architecture: "aarch64".into(),
                app_version: "0.2.16".into(),
            },
            &target(),
        )
        .await
        .unwrap();
    broker.reconcile_transition(frozen).await.unwrap();
    let saved = store.load().unwrap().unwrap();
    assert_eq!(saved.access_token.as_deref(), Some("login-b-access"));
    assert_eq!(
        saved.broker.as_ref().unwrap().transition_authorities.len(),
        1
    );
    assert!(saved.broker.unwrap().transition_authorities[0]
        .reconcile_receipt
        .is_some());
    server.abort();
}

#[tokio::test]
async fn authority_count_and_record_budget_reject_new_work_without_replacing_old_state() {
    let state = Arc::new(Panel::default());
    let (api, server) = panel(state.clone()).await;
    let store = legacy_store();
    let broker = AuthBroker::new(api, store.clone(), Arc::new(Stop)).unwrap();
    let source = broker.transition_source().await.unwrap();
    let first = FrozenReconcileRequest::new(reconcile_request(&source), &source).unwrap();
    broker.reconcile_transition(first).await.unwrap();
    let mut auth = store.load().unwrap().unwrap();
    auth.broker.as_mut().unwrap().transition_authorities[0].source_family =
        "historical-family".into();
    let template = auth.broker.as_ref().unwrap().transition_authorities[0].clone();
    for index in 2..=16 {
        let mut entry = template.clone();
        entry.reconcile_operation_id = format!("{index:08x}-1111-4111-8111-111111111111");
        entry.reconcile_receipt.as_mut().unwrap().operation_id =
            entry.reconcile_operation_id.clone();
        auth.broker
            .as_mut()
            .unwrap()
            .transition_authorities
            .push(entry);
    }
    store.save(&auth).unwrap();
    let before = serde_json::to_value(store.load().unwrap().unwrap()).unwrap();
    let mut next = reconcile_request(&source);
    next.operation_id = "22222222-2222-4222-8222-222222222222".into();
    let next = FrozenReconcileRequest::new(next, &source).unwrap();
    assert!(matches!(
        broker.reconcile_transition(next).await,
        Err(BrokerError::RecoveryRequired)
    ));
    assert_eq!(
        serde_json::to_value(store.load().unwrap().unwrap()).unwrap(),
        before
    );
    assert_eq!(state.reconcile_calls.load(Ordering::SeqCst), 1);
    server.abort();

    let state = Arc::new(Panel::default());
    let (api, server) = panel(state.clone()).await;
    let store = legacy_store();
    let broker = AuthBroker::new(api, store.clone(), Arc::new(Stop)).unwrap();
    let source = broker.transition_source().await.unwrap();
    let first = FrozenReconcileRequest::new(reconcile_request(&source), &source).unwrap();
    broker.reconcile_transition(first).await.unwrap();
    let mut auth = store.load().unwrap().unwrap();
    auth.broker.as_mut().unwrap().transition_authorities[0].source_family =
        "historical-family".into();
    let ids: Vec<String> = (0..1024)
        .map(|index| format!("{index:04}-{}", "x".repeat(250)))
        .collect();
    let authority = &mut auth.broker.as_mut().unwrap().transition_authorities[0];
    let receipt = authority.reconcile_receipt.as_mut().unwrap();
    receipt.retired_lease_ids = ids.clone();
    receipt.retired_session_ids = ids.clone();
    receipt.retired_operation_ids = ids;
    let mut second = authority.clone();
    second.reconcile_operation_id = "33333333-3333-4333-8333-333333333333".into();
    second.reconcile_receipt.as_mut().unwrap().operation_id = second.reconcile_operation_id.clone();
    auth.broker
        .as_mut()
        .unwrap()
        .transition_authorities
        .push(second);
    store.save(&auth).unwrap();
    let before = serde_json::to_value(store.load().unwrap().unwrap()).unwrap();
    let mut next = reconcile_request(&source);
    next.operation_id = "44444444-4444-4444-8444-444444444444".into();
    let next = FrozenReconcileRequest::new(next, &source).unwrap();
    assert!(matches!(
        broker.reconcile_transition(next).await,
        Err(BrokerError::Storage(_))
    ));
    assert_eq!(
        serde_json::to_value(store.load().unwrap().unwrap()).unwrap(),
        before
    );
    assert_eq!(state.reconcile_calls.load(Ordering::SeqCst), 1);
    server.abort();
}

#[tokio::test]
async fn persisted_fingerprint_scope_and_confirmed_device_are_mandatory_before_owner_calls() {
    let state = Arc::new(Panel::default());
    let (api, server) = panel(state.clone()).await;
    let store = legacy_store();
    let broker = AuthBroker::new(api, store.clone(), Arc::new(Stop)).unwrap();
    let source = broker.transition_source().await.unwrap();
    let request = reconcile_request(&source);
    assert!(FrozenReconcileRequest::from_persisted(
        request.clone(),
        source.device_id().into(),
        source.scope_fingerprint().into(),
        Some(&"c".repeat(64)),
    )
    .is_err());
    let wrong_scope = FrozenReconcileRequest::from_persisted(
        request.clone(),
        source.device_id().into(),
        "d".repeat(64),
        None,
    )
    .unwrap();
    assert!(matches!(
        broker.reconcile_transition(wrong_scope).await,
        Err(BrokerError::IdentityMismatch)
    ));
    assert_eq!(state.reconcile_calls.load(Ordering::SeqCst), 0);

    let frozen = FrozenReconcileRequest::new(request, &source).unwrap();
    assert!(!format!("{frozen:?}").contains("legacy-access"));
    broker.reconcile_transition(frozen).await.unwrap();
    let mut auth = store.load().unwrap().unwrap();
    auth.broker.as_mut().unwrap().confirmed_device_id = None;
    store.save(&auth).unwrap();
    assert!(matches!(
        broker
            .resume_transition(ResumeArguments {
                operation_id: "22222222-2222-4222-8222-222222222222".into(),
                reconcile_operation_id: "11111111-1111-4111-8111-111111111111".into(),
                decision: "apply".into(),
                target: target(),
                expected_session_generation: None,
            })
            .await,
        Err(BrokerError::IdentityMismatch)
    ));
    server.abort();
}

#[tokio::test]
async fn enrolled_source_snapshot_rejects_an_incompatible_pending_issuance() {
    let state = Arc::new(Panel::default());
    let (api, server) = panel(state).await;
    let store = legacy_store();
    let mut auth = store.load().unwrap().unwrap();
    let identity = target().identity(Some(7)).unwrap();
    auth.session_generation = Some(7);
    auth.confirmed_identity = Some(identity.clone());
    auth.broker.as_mut().unwrap().confirmed_device_id = Some("device-a".into());
    auth.broker.as_mut().unwrap().next_attempt = 1;
    auth.broker.as_mut().unwrap().pending_request = Some(BrokerRequestV1 {
        kind: BrokerRequestKind::Refresh,
        operation_id: "11111111-1111-4111-8111-111111111111".into(),
        attempt: 1,
        auth_epoch: 0,
        source_identity: Some(identity),
        source_device_id: Some("device-a".into()),
        prior_login_outcome_unknown: false,
        resume: None,
    });
    store.save(&auth).unwrap();
    let broker = AuthBroker::new(api, store, Arc::new(Stop)).unwrap();
    assert!(matches!(
        broker.transition_source().await,
        Err(BrokerError::RecoveryRequired)
    ));
    server.abort();
}

#[tokio::test]
async fn durable_cancellation_after_ticket_persistence_prevents_the_http_call() {
    let state = Arc::new(Panel::default());
    let (api, server) = panel(state.clone()).await;
    let gated = Arc::new(SaveGate::new(legacy_store()));
    let store: Arc<dyn AuthStore> = gated.clone();
    let broker = AuthBroker::new(api, store, Arc::new(Stop)).unwrap();
    gated.arm();
    assert!(matches!(
        broker.transition_source().await,
        Err(BrokerError::Cancelled)
    ));
    assert_eq!(state.bootstrap_calls.load(Ordering::SeqCst), 0);
    server.abort();
}

#[tokio::test]
async fn logout_archives_one_resume_ticket_and_new_login_cannot_adopt_its_late_result() {
    let state = Arc::new(Panel::default());
    let (api, server) = panel(state.clone()).await;
    let store = legacy_store();
    let broker = Arc::new(AuthBroker::new(api, store.clone(), Arc::new(Stop)).unwrap());
    let source = broker.transition_source().await.unwrap();
    broker
        .reconcile_transition(
            FrozenReconcileRequest::new(reconcile_request(&source), &source).unwrap(),
        )
        .await
        .unwrap();
    let args = ResumeArguments {
        operation_id: "22222222-2222-4222-8222-222222222222".into(),
        reconcile_operation_id: "11111111-1111-4111-8111-111111111111".into(),
        decision: "apply".into(),
        target: target(),
        expected_session_generation: None,
    };
    state.hold_resume.store(1, Ordering::SeqCst);
    let pending = {
        let broker = broker.clone();
        let args = args.clone();
        tokio::spawn(async move { broker.resume_transition(args).await })
    };
    state.resume_entered.notified().await;
    broker.logout().await.unwrap();
    state.resume_release.notify_one();
    assert!(matches!(
        pending.await.unwrap(),
        Err(BrokerError::Cancelled)
    ));
    state.hold_resume.store(0, Ordering::SeqCst);
    broker
        .login(
            &LoginRequest {
                login: "b".into(),
                password: "synthetic-password".into(),
                install_secret: "ignored".into(),
                device_name: "B".into(),
                platform: Platform::Macos,
                platform_version: None,
                architecture: "aarch64".into(),
                app_version: "0.2.16".into(),
            },
            &target(),
        )
        .await
        .unwrap();
    let historical = broker.resume_transition(args).await.unwrap();
    assert!(historical.current_access().is_none());
    let saved = store.load().unwrap().unwrap();
    assert_eq!(saved.access_token.as_deref(), Some("login-b-access"));
    assert!(saved.broker.unwrap().transition_authorities[0]
        .resume_evidence
        .is_some());
    server.abort();
}

fn reconcile_request(
    source: &nelomai_client_container::TransitionSourceSnapshot,
) -> RuntimeSwitchReconcileRequest {
    RuntimeSwitchReconcileRequest {
        operation_id: "11111111-1111-4111-8111-111111111111".into(),
        source_identity: source.identity().cloned(),
        target_identity: target(),
        expected_session_generation: source.expected_session_generation(),
        cleanup_contract_version: 1,
        lease_ids: vec!["lease-a".into()],
        redundant_session_ids: vec!["session-a".into()],
        client_operation_ids: vec!["operation-a".into()],
    }
}

fn insert_reconcile_authority(
    store: &Arc<dyn AuthStore>,
    frozen: &FrozenReconcileRequest,
    dispatch_state: TransitionDispatchStateV1,
) {
    let mut auth = store.load().unwrap().unwrap();
    let meta = auth.broker.as_ref().unwrap();
    let authority = TransitionAuthorityV1 {
        schema_version: 1,
        reconcile_operation_id: frozen.request().operation_id.clone(),
        request_fingerprint: frozen.request_fingerprint().into(),
        source_auth_epoch: auth.auth_epoch,
        source_family: meta.family.clone(),
        source_identity: auth.confirmed_identity.clone(),
        source_device_id: frozen.source_device_id().into(),
        source_scope_fingerprint: frozen.source_scope_fingerprint().into(),
        expected_session_generation: auth.session_generation,
        target_identity: frozen.request().target_identity.identity(None).unwrap(),
        cleanup_contract_version: frozen.request().cleanup_contract_version,
        cleanup_access_proof: auth.access_token.clone().unwrap(),
        resume_refresh_proof: auth.refresh_token.clone().unwrap(),
        legacy_refresh_completed: false,
        superseded_by: None,
        dispatch_state,
        reconcile_receipt: None,
        resume_ticket: None,
        resume_evidence: None,
    };
    auth.broker
        .as_mut()
        .unwrap()
        .transition_authorities
        .push(authority);
    store.save(&auth).unwrap();
}

#[tokio::test]
async fn durable_captured_and_invalid_access_states_resume_the_one_eligible_legacy_refresh() {
    for dispatch_state in [
        TransitionDispatchStateV1::Captured,
        TransitionDispatchStateV1::InvalidAccessRejected,
    ] {
        let state = Arc::new(Panel::default());
        if dispatch_state == TransitionDispatchStateV1::Captured {
            state.reject_reconcile_access.store(1, Ordering::SeqCst);
        }
        let (api, server) = panel(state.clone()).await;
        let store = legacy_store();
        let broker = AuthBroker::new(api.clone(), store.clone(), Arc::new(Stop)).unwrap();
        let source = broker.transition_source().await.unwrap();
        let frozen = FrozenReconcileRequest::new(reconcile_request(&source), &source).unwrap();
        insert_reconcile_authority(&store, &frozen, dispatch_state);
        drop(broker);

        let reopened = AuthBroker::new(api, store, Arc::new(Stop)).unwrap();
        assert_eq!(
            reopened.reconcile_transition(frozen).await.unwrap().state,
            RuntimeSwitchState::Clean
        );
        assert_eq!(state.refresh_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            state.reconcile_calls.load(Ordering::SeqCst),
            if dispatch_state == TransitionDispatchStateV1::Captured {
                2
            } else {
                1
            }
        );
        server.abort();
    }
}

#[tokio::test]
async fn unknown_transition_legacy_refresh_never_resends_the_rejected_bearer() {
    let state = Arc::new(Panel::default());
    state.reject_reconcile_access.store(1, Ordering::SeqCst);
    state.fail_refresh.store(1, Ordering::SeqCst);
    let (api, server) = panel(state.clone()).await;
    let store = legacy_store();
    let broker = AuthBroker::new(api.clone(), store.clone(), Arc::new(Stop)).unwrap();
    let source = broker.transition_source().await.unwrap();
    let frozen = FrozenReconcileRequest::new(reconcile_request(&source), &source).unwrap();
    assert!(broker.reconcile_transition(frozen.clone()).await.is_err());
    assert_eq!(state.reconcile_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.refresh_calls.load(Ordering::SeqCst), 1);
    drop(broker);

    let reopened = AuthBroker::new(api, store, Arc::new(Stop)).unwrap();
    assert!(matches!(
        reopened.reconcile_transition(frozen).await,
        Err(BrokerError::RecoveryRequired)
    ));
    assert_eq!(state.reconcile_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.refresh_calls.load(Ordering::SeqCst), 1);
    server.abort();
}

#[tokio::test]
async fn migrated_owner_bootstraps_reconciles_and_resumes_without_exposing_legacy_access() {
    let state = Arc::new(Panel::default());
    let (api, server) = panel(state.clone()).await;
    let store = legacy_store();
    let broker = AuthBroker::new(api, store.clone(), Arc::new(Stop)).unwrap();

    let source = broker.transition_source().await.unwrap();
    assert!(source.identity().is_none());
    assert_eq!(source.device_id(), "device-a");
    let request = FrozenReconcileRequest::new(reconcile_request(&source), &source).unwrap();
    let receipt = broker.reconcile_transition(request).await.unwrap();
    assert_eq!(receipt.state, RuntimeSwitchState::Clean);
    let resume = ResumeArguments {
        operation_id: "22222222-2222-4222-8222-222222222222".into(),
        reconcile_operation_id: "11111111-1111-4111-8111-111111111111".into(),
        decision: "apply".into(),
        target: target(),
        expected_session_generation: None,
    };
    let resumed = broker.resume_transition(resume.clone()).await.unwrap();
    assert_eq!(
        resumed
            .current_access()
            .unwrap()
            .identity()
            .session_generation,
        Some(1)
    );
    assert!(broker
        .resume_transition(resume.clone())
        .await
        .unwrap()
        .current_access()
        .is_some());
    let saved = store.load().unwrap().unwrap();
    assert_eq!(
        saved.broker.as_ref().unwrap().transition_authorities.len(),
        1
    );
    assert_eq!(state.bootstrap_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.refresh_calls.load(Ordering::SeqCst), 0);
    for headers in state.headers.lock().unwrap().iter() {
        assert!(!headers
            .keys()
            .any(|name| name.as_str().starts_with("x-nelomai-")));
    }
    broker.logout().await.unwrap();
    broker
        .login(
            &LoginRequest {
                login: "b".into(),
                password: "synthetic-password".into(),
                install_secret: "ignored".into(),
                device_name: "B".into(),
                platform: Platform::Macos,
                platform_version: None,
                architecture: "aarch64".into(),
                app_version: "0.2.16".into(),
            },
            &target(),
        )
        .await
        .unwrap();
    let historical = broker.resume_transition(resume).await.unwrap();
    assert!(historical.current_access().is_none());
    assert_eq!(
        store.load().unwrap().unwrap().access_token.as_deref(),
        Some("login-b-access")
    );
    server.abort();
}

#[tokio::test]
async fn coordinator_runs_the_real_broker_flow_and_recovery_stays_complete() {
    let state = Arc::new(Panel::default());
    let (api, server) = panel(state.clone()).await;
    let store = legacy_store();
    let broker = Arc::new(AuthBroker::new(api, store, Arc::new(Stop)).unwrap());
    let root = tempfile::tempdir().unwrap();
    let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    std::fs::create_dir_all(root.path().join("common")).unwrap();
    std::fs::write(
        root.path().join("common/runtime-selection-v1.json"),
        SlotSelectionV1 {
            container_version: "0.2.16".into(),
            selected_slot: RuntimeSlot::Latest,
            pending_slot: None,
        }
        .to_persisted_bytes()
        .unwrap(),
    )
    .unwrap();
    let control = Arc::new(SwitchControl::default());
    control.race_writer.store(1, Ordering::SeqCst);
    let coordinator = SwitchCoordinator::open(owner, manifest())
        .unwrap()
        .attach(broker, control.clone());

    assert_eq!(
        coordinator.request(RuntimeSlot::Latest).await.unwrap(),
        SwitchProgress::Ready
    );
    assert_eq!(
        coordinator.snapshot().unwrap().unwrap().phase(),
        SwitchPhase::Complete
    );
    assert_eq!(coordinator.recover().await.unwrap(), SwitchProgress::Ready);
    assert_eq!(control.handoffs.load(Ordering::SeqCst), 1);
    assert_eq!(control.stops.load(Ordering::SeqCst), 1);
    assert_eq!(control.completions.load(Ordering::SeqCst), 1);
    for _ in 0..10 {
        if control.writer_acquired.load(Ordering::SeqCst) == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(control.writer_acquired.load(Ordering::SeqCst), 1);
    assert_eq!(state.reconcile_calls.load(Ordering::SeqCst), 1);
    server.abort();
}

#[tokio::test]
async fn actual_record_control_clears_the_frozen_source_and_binds_only_resumed_scope() {
    let state = Arc::new(Panel::default());
    let (api, server) = panel(state).await;
    let store = legacy_store();
    let tunnel = Arc::new(SwitchTunnel::default());
    let local = CoreLocalStop::new(tunnel.clone());
    let broker = Arc::new(AuthBroker::new(api, store, local.clone()).unwrap());
    let root = tempfile::tempdir().unwrap();
    let paths = RuntimePaths::new(root.path(), RuntimeSlot::Latest, "0.2.16").unwrap();
    let backend = ProtectedRuntimeStore::new(Record::default(), paths);
    let mut legacy = StoredAuth::new_install();
    legacy.saved_connection = Some(StoredConnection {
        lease_id: "lease-a".into(),
        pool_id: None,
        layer: nelomai_contracts::Layer::Stray,
        tic_connection_mode: nelomai_contracts::TicConnectionMode::Dynamic,
        route_mode: nelomai_contracts::RouteMode::Standalone,
        egress_mode: nelomai_contracts::EgressMode::Ipv4,
        probe_url: None,
        kind: StoredConnectionKind::Fixed,
        configuration: "PrivateKey = synthetic-not-exported".into(),
        valid_until_unix: None,
    });
    backend
        .save(&RuntimeStateV1::import_legacy(
            &legacy,
            StoredSplitTunnelState::default(),
            backend.paths(),
        ))
        .unwrap();
    let record_owner = RuntimeRecordOwner::new(backend);
    let control = Arc::new(RuntimeRecordSwitchControl::new(
        record_owner.clone(),
        Vec::new(),
        local,
        Arc::new(UnavailableRuntimeForceStop),
    ));
    let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    std::fs::create_dir_all(root.path().join("common")).unwrap();
    std::fs::write(
        root.path().join("common/runtime-selection-v1.json"),
        SlotSelectionV1 {
            container_version: "0.2.16".into(),
            selected_slot: RuntimeSlot::Latest,
            pending_slot: None,
        }
        .to_persisted_bytes()
        .unwrap(),
    )
    .unwrap();
    let coordinator = SwitchCoordinator::open(owner, manifest())
        .unwrap()
        .attach(broker, control);

    assert_eq!(
        coordinator.request(RuntimeSlot::Latest).await.unwrap(),
        SwitchProgress::Ready
    );
    let completed = record_owner.cleanup_snapshot().unwrap();
    assert!(!completed.cleanup_only);
    assert!(completed.lease_ids.is_empty());
    assert!(completed.operations.is_empty());
    assert_eq!(
        completed
            .auth_scope
            .as_ref()
            .unwrap()
            .identity
            .session_generation,
        Some(1)
    );
    assert_eq!(tunnel.0.load(Ordering::SeqCst), 1);
    server.abort();
}

fn write_test_selection(root: &std::path::Path, version: &str) {
    std::fs::create_dir_all(root.join("common")).unwrap();
    std::fs::write(
        root.join("common/runtime-selection-v1.json"),
        SlotSelectionV1 {
            container_version: version.into(),
            selected_slot: RuntimeSlot::Latest,
            pending_slot: None,
        }
        .to_persisted_bytes()
        .unwrap(),
    )
    .unwrap();
}

#[derive(Default)]
struct StartupRecords {
    records: Mutex<std::collections::HashMap<String, Record>>,
    legacy: Mutex<Option<StoredAuth>>,
}
impl nelomai_client_storage::SecretStore for StartupRecords {
    fn load(&self) -> Result<Option<StoredAuth>, StorageError> {
        Ok(self.legacy.lock().unwrap().clone())
    }
    fn save(&self, value: &StoredAuth) -> Result<(), StorageError> {
        *self.legacy.lock().unwrap() = Some(value.clone());
        Ok(())
    }
    fn delete(&self) -> Result<(), StorageError> {
        panic!("startup must retain install identity")
    }
}
impl nelomai_client_storage::ProtectedRecordFactory for StartupRecords {
    type Record = Record;
    fn record(&self, namespace: &str) -> Record {
        self.records
            .lock()
            .unwrap()
            .entry(namespace.into())
            .or_default()
            .clone()
    }
    fn legacy(&self) -> &dyn nelomai_client_storage::SecretStore {
        self
    }
}

#[tokio::test]
async fn completed_enrollment_does_not_mask_admission_of_a_new_namespace() {
    use nelomai_client_storage::{prepare_runtime_storage, ProtectedRecordFactory};
    let state = Arc::new(Panel::default());
    let (api, server) = panel(state.clone()).await;
    let local = CoreLocalStop::new(Arc::new(SwitchTunnel::default()));
    let root = tempfile::tempdir().unwrap();
    let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    write_test_selection(root.path(), "0.2.16");
    let records = StartupRecords::default();
    let mut legacy = StoredAuth::new_install();
    legacy.access_token = Some("legacy-access".into());
    legacy.refresh_token = Some("legacy-refresh".into());
    records.legacy().save(&legacy).unwrap();
    let old_storage =
        prepare_runtime_storage(&owner, &manifest(), RuntimeSlot::Latest, &records).unwrap();
    let install_secret = old_storage.auth.load().unwrap().unwrap().install_secret;
    let store = Arc::new(old_storage.auth);
    let broker = Arc::new(AuthBroker::new(api, store.clone(), local.clone()).unwrap());
    let old_record = RuntimeRecordOwner::new(old_storage.runtime);
    let old = SwitchCoordinator::open(owner.clone(), manifest())
        .unwrap()
        .attach(
            broker.clone(),
            Arc::new(RuntimeRecordSwitchControl::new(
                old_record.clone(),
                vec![],
                local.clone(),
                Arc::new(UnavailableRuntimeForceStop),
            )),
        )
        .require_initial_transition(RuntimeSlot::Latest);
    old.before_tunnel_start().await.unwrap();
    assert!(!old_record.cleanup_snapshot().unwrap().cleanup_only);
    let _quiescence = local.runtime_writer_gates().quiesce().await;
    assert_eq!(
        nelomai_client_storage::acknowledge_migration_bootstrap(
            &nelomai_client_storage::LegacyMigrationSource::new(
                records.legacy(),
                &nelomai_client_storage::FileSplitTunnelStore::new(root.path())
            ),
            store.as_ref(),
            &old_record.operational(),
            &nelomai_client_storage::FileMigrationJournal::new(
                root.path().join("common/auth-migration-v1.json")
            ),
        )
        .unwrap(),
        nelomai_client_storage::MigrationOutcome::Complete
    );
    drop(_quiescence);
    let old_operation =
        serde_json::to_value(old.snapshot().unwrap().unwrap()).unwrap()["operation_id"].clone();
    drop(old);
    write_test_selection(root.path(), "0.2.17");
    let updated_manifest = manifest_for("0.2.17", "0.2.17");
    let new_storage =
        prepare_runtime_storage(&owner, &updated_manifest, RuntimeSlot::Latest, &records).unwrap();
    assert_eq!(
        new_storage.auth.load().unwrap().unwrap().install_secret,
        install_secret
    );
    assert_eq!(new_storage.retained.len(), 1);
    let new_record = RuntimeRecordOwner::new(new_storage.runtime);
    let updated = SwitchCoordinator::open(owner, manifest_for("0.2.17", "0.2.17"))
        .unwrap()
        .attach(
            broker,
            Arc::new(RuntimeRecordSwitchControl::new(
                new_record.clone(),
                vec![old_record],
                local,
                Arc::new(UnavailableRuntimeForceStop),
            )),
        )
        .require_initial_transition(RuntimeSlot::Latest);
    updated.before_tunnel_start().await.unwrap();
    let admitted = new_record.cleanup_snapshot().unwrap();
    assert!(
        !admitted.cleanup_only,
        "completed predecessor cannot admit the new namespace"
    );
    assert_eq!(
        admitted.auth_scope.unwrap().identity.runtime_version,
        "0.2.17"
    );
    assert_ne!(
        serde_json::to_value(updated.snapshot().unwrap().unwrap()).unwrap()["operation_id"],
        old_operation
    );
    updated.before_tunnel_start().await.unwrap();
    assert_eq!(state.reconcile_calls.load(Ordering::SeqCst), 2);
    assert_eq!(state.resume_calls.load(Ordering::SeqCst), 2);
    assert_eq!(state.supersede_calls.load(Ordering::SeqCst), 0);
    server.abort();
}

#[tokio::test]
async fn satisfied_initial_admission_does_not_override_a_later_explicit_slot_switch() {
    let state = Arc::new(Panel::default());
    let (api, server) = panel(state.clone()).await;
    let broker = Arc::new(AuthBroker::new(api, legacy_store(), Arc::new(Stop)).unwrap());
    let root = tempfile::tempdir().unwrap();
    let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    write_test_selection(root.path(), "0.2.16");
    let manifest = manifest_with_optional_stable("0.2.16", "0.2.16", true);
    let active =
        RuntimeTarget::from_identity(&manifest.identity(RuntimeSlot::Latest, None).unwrap());
    let coordinator = SwitchCoordinator::open(owner, manifest)
        .unwrap()
        .attach(broker, Arc::new(SwitchControl::default()))
        .require_initial_transition(RuntimeSlot::Latest);
    coordinator.before_tunnel_start().await.unwrap();
    state.return_retry.store(1, Ordering::SeqCst);
    assert!(matches!(
        coordinator.request(RuntimeSlot::Stable).await.unwrap(),
        SwitchProgress::Pending { .. }
    ));
    let status = coordinator.status_for(&active).unwrap();
    assert_eq!(status.container_version, "0.2.16");
    assert_eq!(status.active_slot, RuntimeSlot::Latest);
    assert_eq!(status.selected_slot, RuntimeSlot::Latest);
    assert_eq!(status.pending_slot, Some(RuntimeSlot::Stable));
    assert_eq!(status.latest_version, "0.2.16");
    assert_eq!(status.stable_version.as_deref(), Some("0.2.15"));
    assert_eq!(status.runtime_contract_version, 1);
    assert!(status.manifest_verified);
    assert!(status.stable_available);
    assert!(status.switch_id.is_some());
    assert_eq!(status.phase, Some(SwitchPhase::ServerReconciling));
    assert_eq!(status.engine_role, CleanupEngineRoleV1::Primary);
    assert!(status.restart_required());
    assert!(coordinator.before_tunnel_start_for(&active).await.is_err());
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    assert_eq!(
        coordinator.cancel_pending_for(&active).await.unwrap(),
        SwitchProgress::Ready,
    );
    let cancelled = coordinator.status_for(&active).unwrap();
    assert_eq!(cancelled.selected_slot, RuntimeSlot::Latest);
    assert_eq!(cancelled.pending_slot, None);
    assert!(!cancelled.restart_required());
    coordinator.before_tunnel_start_for(&active).await.unwrap();
    assert_eq!(state.reconcile_calls.load(Ordering::SeqCst), 3);
    assert_eq!(state.resume_calls.load(Ordering::SeqCst), 2);
    server.abort();
}

#[tokio::test]
async fn completed_switch_returns_to_active_slot_through_a_fresh_reverse_authority() {
    let state = Arc::new(Panel::default());
    let (api, server) = panel(state.clone()).await;
    let broker = Arc::new(AuthBroker::new(api, legacy_store(), Arc::new(Stop)).unwrap());
    let root = tempfile::tempdir().unwrap();
    let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    write_test_selection(root.path(), "0.2.16");
    let manifest = manifest_with_optional_stable("0.2.16", "0.2.16", true);
    let active =
        RuntimeTarget::from_identity(&manifest.identity(RuntimeSlot::Latest, None).unwrap());
    let coordinator = SwitchCoordinator::open(owner, manifest)
        .unwrap()
        .attach(broker, Arc::new(SwitchControl::default()))
        .require_initial_transition(RuntimeSlot::Latest);
    coordinator.before_tunnel_start().await.unwrap();
    assert_eq!(
        coordinator.request(RuntimeSlot::Stable).await.unwrap(),
        SwitchProgress::Ready,
    );
    let applied = coordinator.status_for(&active).unwrap();
    let applied_operation = applied.switch_id.clone().unwrap();
    assert_eq!(applied.phase, Some(SwitchPhase::Complete));
    assert_eq!(applied.selected_slot, RuntimeSlot::Stable);
    assert!(applied.restart_required());

    assert_eq!(
        coordinator.cancel_pending_for(&active).await.unwrap(),
        SwitchProgress::Ready,
    );
    let reversed = coordinator.status_for(&active).unwrap();
    assert_eq!(reversed.phase, Some(SwitchPhase::Complete));
    assert_eq!(reversed.selected_slot, RuntimeSlot::Latest);
    assert_ne!(
        reversed.switch_id.as_deref(),
        Some(applied_operation.as_str())
    );
    assert!(!reversed.restart_required());
    coordinator.before_tunnel_start_for(&active).await.unwrap();
    assert_eq!(state.reconcile_calls.load(Ordering::SeqCst), 3);
    assert_eq!(state.resume_calls.load(Ordering::SeqCst), 3);
    server.abort();
}

#[tokio::test]
async fn restart_can_recover_an_auth_resuming_switch_after_local_stop_is_durable() {
    let state = Arc::new(Panel::default());
    let (api, server) = panel(state).await;
    let broker = Arc::new(AuthBroker::new(api, legacy_store(), Arc::new(Stop)).unwrap());
    let root = tempfile::tempdir().unwrap();
    let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    write_test_selection(root.path(), "0.2.16");
    let manifest = manifest_with_optional_stable("0.2.16", "0.2.16", true);
    let active =
        RuntimeTarget::from_identity(&manifest.identity(RuntimeSlot::Latest, None).unwrap());
    let control = Arc::new(SwitchControl::default());
    let coordinator = SwitchCoordinator::open(owner, manifest)
        .unwrap()
        .attach(broker, control.clone())
        .require_initial_transition(RuntimeSlot::Latest);
    coordinator.before_tunnel_start().await.unwrap();
    control.reject_completion.store(1, Ordering::SeqCst);

    assert!(coordinator.request(RuntimeSlot::Stable).await.is_err());
    assert_eq!(
        coordinator.status_for(&active).unwrap().phase,
        Some(SwitchPhase::AuthResuming),
    );
    let restart = coordinator.prepare_runtime_restart(&active).await.unwrap();
    assert_eq!(restart.selected_slot, RuntimeSlot::Stable);
    assert_eq!(restart.pending_slot, None);
    assert_eq!(restart.phase, Some(SwitchPhase::AuthResuming));
    assert!(restart.local_stop_confirmed());
    assert_eq!(control.stops.load(Ordering::SeqCst), 2);
    server.abort();
}

struct PausedStartPreflight {
    coordinator: Arc<SwitchCoordinator>,
    passed: Notify,
    release: Notify,
}

#[async_trait]
impl nelomai_client_core::RuntimeStartPreflight for PausedStartPreflight {
    async fn before_tunnel_start(&self) -> Result<(), nelomai_client_core::CoreError> {
        self.coordinator
            .before_tunnel_start()
            .await
            .map_err(|_| nelomai_client_core::CoreError::AuthRecoveryRequired)?;
        self.passed.notify_one();
        self.release.notified().await;
        Ok(())
    }
    fn check_start_barrier(&self) -> Result<(), nelomai_client_core::CoreError> {
        nelomai_client_core::RuntimeStartPreflight::check_start_barrier(self.coordinator.as_ref())
    }
}

#[derive(Default)]
struct OfflineRaceTunnel {
    starts: AtomicUsize,
    stops: AtomicUsize,
}
#[async_trait]
impl TunnelController for OfflineRaceTunnel {
    async fn start(&self, _: TunnelStartRequest) -> Result<(), TunnelError> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        Err(TunnelError::Backend("synthetic start reached".into()))
    }
    async fn stop(&self) -> Result<(), TunnelError> {
        self.stops.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn status(&self) -> Result<TunnelStatus, TunnelError> {
        Ok(TunnelStatus::Stopped)
    }
}

#[tokio::test]
async fn offline_start_rechecks_switch_barrier_after_preflight_and_lifecycle_gap() {
    use nelomai_client_container::{OwnerRuntimeAuth, RuntimeCacheAdmission, RuntimeClientProfile};
    let state = Arc::new(Panel::default());
    state.return_retry.store(1, Ordering::SeqCst);
    let (api, server) = panel(state).await;
    let store = enrolled_store();
    let tunnel = Arc::new(OfflineRaceTunnel::default());
    let local = CoreLocalStop::new(tunnel.clone());
    let broker = Arc::new(AuthBroker::new(api.clone(), store.clone(), local.clone()).unwrap());
    let root = tempfile::tempdir().unwrap();
    let paths = RuntimePaths::new(root.path(), RuntimeSlot::Latest, "0.2.16").unwrap();
    let backend = ProtectedRuntimeStore::new(Record::default(), paths);
    let auth = store.load().unwrap().unwrap();
    let mut runtime = RuntimeStateV1::empty(backend.paths(), false);
    runtime.auth_scope = Some(nelomai_client_storage::RuntimeAuthScope {
        auth_epoch: auth.auth_epoch,
        family: auth.broker.unwrap().family,
        identity: auth.confirmed_identity.unwrap(),
    });
    runtime.saved_connection = Some(StoredConnection {
        lease_id: "lease-a".into(),
        pool_id: None,
        layer: nelomai_contracts::Layer::Stray,
        tic_connection_mode: nelomai_contracts::TicConnectionMode::Dynamic,
        route_mode: nelomai_contracts::RouteMode::Standalone,
        egress_mode: nelomai_contracts::EgressMode::Ipv4,
        probe_url: None,
        kind: StoredConnectionKind::DynamicWarm,
        configuration: "PrivateKey = synthetic".into(),
        valid_until_unix: Some(1_900_000_000),
    });
    backend.save(&runtime).unwrap();
    let record = RuntimeRecordOwner::new(backend);
    let port = Arc::new(
        OwnerRuntimeAuth::new(
            broker.clone(),
            target(),
            RuntimeClientProfile {
                platform: Platform::Macos,
                platform_version: None,
                architecture: "aarch64".into(),
            },
            Arc::new(RuntimeCacheAdmission::new(record.clone())),
            local.runtime_writer_gates(),
        )
        .unwrap(),
    );
    let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    write_test_selection(root.path(), "0.2.16");
    let manifest = manifest_with_optional_stable("0.2.16", "0.2.16", true);
    let active =
        RuntimeTarget::from_identity(&manifest.identity(RuntimeSlot::Latest, None).unwrap());
    let coordinator = Arc::new(SwitchCoordinator::open(owner, manifest).unwrap().attach(
        broker,
        Arc::new(RuntimeRecordSwitchControl::new(
            record.clone(),
            vec![],
            local.clone(),
            Arc::new(UnavailableRuntimeForceStop),
        )),
    ));
    let preflight = Arc::new(PausedStartPreflight {
        coordinator: coordinator.clone(),
        passed: Notify::new(),
        release: Notify::new(),
    });
    let application =
        nelomai_client_application::ClientApplication::with_split_tunnel_store_and_preflight(
            Arc::new(api),
            Arc::new(record.operational()),
            Arc::new(record.split()),
            port,
            local.clone(),
            Arc::new(nelomai_client_core::NoopLogger),
            preflight.clone(),
        );
    let start = application.start_saved_stray_offline(1_800_000_000);
    tokio::pin!(start);
    tokio::select! { biased;
        result = &mut start => panic!("start must pause after preflight: {result:?}"),
        _ = preflight.passed.notified() => {}
    }
    assert!(matches!(
        coordinator.request(RuntimeSlot::Stable).await.unwrap(),
        SwitchProgress::Pending { .. }
    ));
    assert_eq!(
        coordinator.status().unwrap().phase,
        Some(SwitchPhase::ServerReconciling)
    );
    assert_eq!(tunnel.stops.load(Ordering::SeqCst), 1);
    let restart = coordinator.prepare_runtime_restart(&active).await.unwrap();
    assert_eq!(restart.active_slot, RuntimeSlot::Latest);
    assert_eq!(restart.selected_slot, RuntimeSlot::Stable);
    assert_eq!(restart.pending_slot, None);
    assert_eq!(restart.phase, Some(SwitchPhase::ServerReconciling));
    assert_eq!(tunnel.stops.load(Ordering::SeqCst), 1);
    preflight.release.notify_one();
    let result = tokio::time::timeout(std::time::Duration::from_secs(2), start)
        .await
        .expect("barrier recheck must not recover under lifecycle lock");
    assert_eq!(
        tunnel.starts.load(Ordering::SeqCst),
        0,
        "a queued source start must not invalidate the durable local-stop receipt"
    );
    assert!(
        matches!(
            result,
            Err(nelomai_client_application::ApplicationError::Core(
                nelomai_client_core::CoreError::AuthRecoveryRequired
            ))
        ),
        "{result:?}"
    );
    let _quiescence = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        local.runtime_writer_gates().quiesce(),
    )
    .await
    .unwrap();
    server.abort();
}

#[tokio::test]
async fn runtime_admission_replays_after_the_atomic_record_save_committed_before_error() {
    let root = tempfile::tempdir().unwrap();
    let paths = RuntimePaths::new(root.path(), RuntimeSlot::Latest, "0.2.16").unwrap();
    let inner = ProtectedRuntimeStore::new(Record::default(), paths);
    inner
        .save(&RuntimeStateV1::import_legacy(
            &StoredAuth::new_install(),
            StoredSplitTunnelState::default(),
            inner.paths(),
        ))
        .unwrap();
    let fail_after_commit = Arc::new(AtomicUsize::new(1));
    let owner = RuntimeRecordOwner::new(FailOnceRuntimeStore {
        inner,
        fail_after_commit,
    });
    let local = CoreLocalStop::new(Arc::new(SwitchTunnel::default()));
    let control = RuntimeRecordSwitchControl::new(
        owner.clone(),
        Vec::new(),
        local,
        Arc::new(UnavailableRuntimeForceStop),
    );
    let snapshot = owner.cleanup_snapshot().unwrap();
    let access = AccessSnapshot::new(
        "resumed-access".into(),
        target().identity(Some(1)).unwrap(),
        1,
        "family-a".into(),
    )
    .unwrap();
    let receipt = LocalStopReceiptV1 {
        operation_id: "11111111-1111-4111-8111-111111111111".into(),
        source_scope_fingerprint: "a".repeat(64),
        runtime_slot: snapshot.slot,
        runtime_version: snapshot.runtime_version.clone(),
        forced: false,
    };

    assert!(control
        .complete_cleanup_and_admit(&snapshot, &receipt, &access)
        .await
        .is_err());
    control
        .complete_cleanup_and_admit(&snapshot, &receipt, &access)
        .await
        .unwrap();
    let completed = owner.cleanup_snapshot().unwrap();
    assert!(!completed.cleanup_only);
    assert_eq!(
        completed.auth_scope.unwrap().identity.session_generation,
        Some(1)
    );
}

#[tokio::test]
async fn coordinator_persists_bounded_retry_before_an_offline_dispatch() {
    let api = nelomai_client_api::ClientApi::new("http://127.0.0.1:9")
        .unwrap()
        .with_app_version("0.2.16")
        .unwrap();
    let broker = Arc::new(AuthBroker::new(api, enrolled_store(), Arc::new(Stop)).unwrap());
    let control = Arc::new(SwitchControl::default());
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("common")).unwrap();
    std::fs::write(
        root.path().join("common/runtime-selection-v1.json"),
        SlotSelectionV1 {
            container_version: "0.2.16".into(),
            selected_slot: RuntimeSlot::Latest,
            pending_slot: None,
        }
        .to_persisted_bytes()
        .unwrap(),
    )
    .unwrap();
    let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    let coordinator = SwitchCoordinator::open(owner.clone(), manifest())
        .unwrap()
        .attach(broker.clone(), control.clone());

    assert_eq!(
        coordinator.request(RuntimeSlot::Latest).await.unwrap(),
        SwitchProgress::Pending {
            retry_after_seconds: 1
        }
    );
    drop(coordinator);
    let reopened = SwitchCoordinator::open(owner, manifest())
        .unwrap()
        .attach(broker, control);
    assert_eq!(
        reopened.recover().await.unwrap(),
        SwitchProgress::Pending {
            retry_after_seconds: 1
        }
    );
    assert_eq!(
        reopened.status().unwrap().phase,
        Some(SwitchPhase::ServerReconciling)
    );
}

#[tokio::test]
async fn updated_manifest_supersedes_only_the_clean_predecessor_and_resumes_successor() {
    let state = Arc::new(Panel::default());
    state.return_retry.store(1, Ordering::SeqCst);
    let (api, server) = panel(state.clone()).await;
    let store = enrolled_store();
    let broker = Arc::new(AuthBroker::new(api, store.clone(), Arc::new(Stop)).unwrap());
    let control = Arc::new(SwitchControl::default());
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("common")).unwrap();
    std::fs::write(
        root.path().join("common/runtime-selection-v1.json"),
        SlotSelectionV1 {
            container_version: "0.2.16".into(),
            selected_slot: RuntimeSlot::Latest,
            pending_slot: None,
        }
        .to_persisted_bytes()
        .unwrap(),
    )
    .unwrap();
    let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    let first = SwitchCoordinator::open(owner.clone(), manifest())
        .unwrap()
        .attach(broker.clone(), control.clone());
    assert!(matches!(
        first.request(RuntimeSlot::Latest).await.unwrap(),
        SwitchProgress::Pending { .. }
    ));
    drop(first);

    let journal_path = root.path().join("common/runtime-switch-v1.json");
    let mut journal: Value =
        serde_json::from_slice(&std::fs::read(&journal_path).unwrap()).unwrap();
    journal["retry"]["retry_not_before_unix_ms"] = json!(1);
    std::fs::write(&journal_path, serde_json::to_vec(&journal).unwrap()).unwrap();
    std::fs::write(
        root.path().join("common/runtime-selection-v1.json"),
        SlotSelectionV1 {
            container_version: "0.2.17".into(),
            selected_slot: RuntimeSlot::Latest,
            pending_slot: None,
        }
        .to_persisted_bytes()
        .unwrap(),
    )
    .unwrap();
    let updated = SwitchCoordinator::open(owner, manifest_for("0.2.17", "0.2.17"))
        .unwrap()
        .attach(broker, control);
    let result = updated.recover().await;
    assert!(
        matches!(result, Ok(SwitchProgress::Ready)),
        "{result:?}; reconcile={}, supersede={}, resume={}, pending={:?}, authorities={:?}, journal={}",
        state.reconcile_calls.load(Ordering::SeqCst),
        state.supersede_calls.load(Ordering::SeqCst),
        state.resume_calls.load(Ordering::SeqCst),
        store.load().unwrap().unwrap().pending_runtime_supersede,
        store
            .load()
            .unwrap()
            .unwrap()
            .broker
            .unwrap()
            .transition_authorities
            .iter()
            .map(|authority| (&authority.reconcile_operation_id, &authority.request_fingerprint))
            .collect::<Vec<_>>(),
        serde_json::from_slice::<Value>(&std::fs::read(&journal_path).unwrap()).unwrap()
    );
    assert_eq!(state.reconcile_calls.load(Ordering::SeqCst), 2);
    assert_eq!(state.supersede_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.resume_calls.load(Ordering::SeqCst), 1);
    assert_eq!(updated.status().unwrap().selected_slot, RuntimeSlot::Latest);
    server.abort();
}

#[tokio::test]
async fn lost_committed_old_apply_is_replayed_without_old_admission_then_superseded() {
    exercise_committed_apply_updates(false).await;
}

#[tokio::test]
async fn repeated_updates_recover_active_successor_source_after_committed_apply() {
    exercise_committed_apply_updates(true).await;
}

#[tokio::test]
async fn logout_at_auth_resuming_retires_only_its_barrier_before_new_login_start() {
    exercise_logout_switch_cleanup(false, false, false).await;
}

#[tokio::test]
async fn logout_cleanup_replays_after_journal_retirement_before_receipt_consumption() {
    exercise_logout_switch_cleanup(false, true, false).await;
}

#[tokio::test]
async fn old_logout_cleanup_cannot_stop_new_login_or_retire_barrier_with_unrelated_ack() {
    exercise_logout_switch_cleanup(true, false, false).await;
}

#[tokio::test]
async fn logout_cancels_login_already_waiting_for_prior_logout_cleanup() {
    exercise_logout_switch_cleanup(false, false, true).await;
}

#[derive(Default)]
struct AdmissionTunnel {
    starts: AtomicUsize,
    stops: AtomicUsize,
    hold_next_stop: AtomicUsize,
    stop_entered: Notify,
    stop_release: Notify,
}
#[async_trait]
impl TunnelController for AdmissionTunnel {
    async fn start(&self, _: TunnelStartRequest) -> Result<(), TunnelError> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn stop(&self) -> Result<(), TunnelError> {
        self.stops.fetch_add(1, Ordering::SeqCst);
        if self.hold_next_stop.swap(0, Ordering::SeqCst) == 1 {
            self.stop_entered.notify_one();
            self.stop_release.notified().await;
        }
        Ok(())
    }
    async fn status(&self) -> Result<TunnelStatus, TunnelError> {
        Ok(TunnelStatus::Running)
    }
}

async fn exercise_logout_switch_cleanup(
    unrelated: bool,
    crash_after_retirement: bool,
    cancel_waiting_login: bool,
) {
    use nelomai_client_container::{OwnerRuntimeAuth, RuntimeCacheAdmission, RuntimeClientProfile};
    use nelomai_client_core::{NoopLogger, RuntimeAuthProvider};
    let state = Arc::new(Panel::default());
    let (api, server) = panel(state.clone()).await;
    let store = Arc::new(RejectFirstResumeSave {
        inner: enrolled_store(),
        armed: AtomicUsize::new(1),
        reject_logout_consumption: AtomicUsize::new(0),
    });
    let tunnel = Arc::new(AdmissionTunnel::default());
    let local = CoreLocalStop::new(tunnel.clone());
    let broker = Arc::new(AuthBroker::new(api.clone(), store.clone(), local.clone()).unwrap());
    let root = tempfile::tempdir().unwrap();
    let backend = ProtectedRuntimeStore::new(
        Record::default(),
        RuntimePaths::new(root.path(), RuntimeSlot::Latest, "0.2.16").unwrap(),
    );
    let auth = store.load().unwrap().unwrap();
    let mut runtime = RuntimeStateV1::empty(backend.paths(), false);
    runtime.auth_scope = Some(nelomai_client_storage::RuntimeAuthScope {
        auth_epoch: auth.auth_epoch,
        family: auth.broker.unwrap().family,
        identity: auth.confirmed_identity.unwrap(),
    });
    backend.save(&runtime).unwrap();
    let record = RuntimeRecordOwner::new(backend);
    let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    write_test_selection(root.path(), "0.2.16");
    let control = Arc::new(RuntimeRecordSwitchControl::new(
        record.clone(),
        vec![],
        local.clone(),
        Arc::new(UnavailableRuntimeForceStop),
    ));
    let mut coordinator = Arc::new(
        SwitchCoordinator::open(owner.clone(), manifest())
            .unwrap()
            .attach(broker.clone(), control.clone()),
    );
    let make_port = |coordinator: Arc<SwitchCoordinator>| {
        Arc::new(
            OwnerRuntimeAuth::new(
                broker.clone(),
                target(),
                RuntimeClientProfile {
                    platform: Platform::Macos,
                    platform_version: None,
                    architecture: "aarch64".into(),
                },
                Arc::new(RuntimeCacheAdmission::new(record.clone())),
                local.runtime_writer_gates(),
            )
            .unwrap()
            .with_switch_coordinator(coordinator),
        )
    };
    let mut port = make_port(coordinator.clone());
    assert!(coordinator.request(RuntimeSlot::Latest).await.is_err());
    assert_eq!(
        coordinator.status().unwrap().phase,
        Some(SwitchPhase::AuthResuming)
    );
    assert_eq!(state.resume_calls.load(Ordering::SeqCst), 0);
    assert!(store
        .load()
        .unwrap()
        .unwrap()
        .broker
        .unwrap()
        .transition_authorities[0]
        .resume_ticket
        .is_none());
    broker.logout().await.unwrap();
    if cancel_waiting_login {
        tunnel.hold_next_stop.store(1, Ordering::SeqCst);
        let worker = port.clone();
        let login = tokio::spawn(async move {
            worker
                .login(nelomai_client_api::RuntimeLogin {
                    login: "b".into(),
                    password: "synthetic-password".into(),
                    device_name: "B".into(),
                })
                .await
        });
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tunnel.stop_entered.notified(),
        )
        .await
        .unwrap();
        broker.logout().await.unwrap();
        tunnel.stop_release.notify_one();
        assert!(
            login.await.unwrap().is_err(),
            "logout must cancel a login already waiting for cleanup"
        );
        assert_eq!(
            store.load().unwrap().unwrap().logout_state,
            nelomai_client_storage::LogoutState::LoggedOut
        );
        server.abort();
        return;
    }
    if unrelated {
        let pending = coordinator.snapshot().unwrap();
        let cached = record.cleanup_snapshot().unwrap();
        let request = LoginRequest {
            login: "b".into(),
            password: "synthetic-password".into(),
            device_name: "B".into(),
            install_secret: "synthetic-install".into(),
            platform: Platform::Macos,
            platform_version: None,
            architecture: "aarch64".into(),
            app_version: "0.2.16".into(),
        };
        broker.login(&request, &target()).await.unwrap();
        let newer = store.load().unwrap().unwrap();
        let stops = tunnel.stops.load(Ordering::SeqCst);
        assert!(port.recover_logout_cleanup().await.is_err());
        assert_eq!(store.load().unwrap().unwrap(), newer);
        assert_eq!(
            tunnel.stops.load(Ordering::SeqCst),
            stops,
            "old receipt must not stop B"
        );
        broker.logout().await.unwrap();
        assert!(port.recover_logout_cleanup().await.is_err());
        assert_eq!(
            coordinator.snapshot().unwrap(),
            pending,
            "B's ACK must not retire A's barrier"
        );
        assert_eq!(record.cleanup_snapshot().unwrap(), cached);
        assert!(store
            .load()
            .unwrap()
            .unwrap()
            .completed_runtime_logout
            .is_some());
        server.abort();
        return;
    }
    if crash_after_retirement {
        store.reject_logout_consumption.store(1, Ordering::SeqCst);
        assert!(port.recover_logout_cleanup().await.is_err());
        assert!(coordinator.snapshot().unwrap().is_none());
        assert!(store
            .load()
            .unwrap()
            .unwrap()
            .completed_runtime_logout
            .is_some());
        coordinator = Arc::new(
            SwitchCoordinator::open(owner.clone(), manifest())
                .unwrap()
                .attach(broker.clone(), control),
        );
        port = make_port(coordinator.clone());
    }
    port.recover_logout_cleanup().await.unwrap();
    port.login(nelomai_client_api::RuntimeLogin {
        login: "b".into(),
        password: "synthetic-password".into(),
        device_name: "B".into(),
    })
    .await
    .unwrap();
    let before = store.load().unwrap().unwrap();
    let application =
        nelomai_client_application::ClientApplication::with_split_tunnel_store_and_preflight(
            Arc::new(api),
            Arc::new(record.operational()),
            Arc::new(record.split()),
            port,
            local,
            Arc::new(NoopLogger),
            coordinator.clone(),
        );
    coordinator
        .before_tunnel_start()
        .await
        .expect("logout must retire A's pending switch before B starts");
    let mut fresh = record.operational().load().unwrap().unwrap();
    fresh.saved_connection = Some(StoredConnection {
        lease_id: "b-lease".into(),
        pool_id: None,
        layer: nelomai_contracts::Layer::Stray,
        tic_connection_mode: nelomai_contracts::TicConnectionMode::Dynamic,
        route_mode: nelomai_contracts::RouteMode::Standalone,
        egress_mode: nelomai_contracts::EgressMode::Ipv4,
        probe_url: None,
        kind: StoredConnectionKind::DynamicWarm,
        configuration: "PrivateKey = synthetic-b".into(),
        valid_until_unix: Some(1_900_000_000),
    });
    record.operational().save(&fresh).unwrap();
    application
        .start_saved_stray_offline(1_800_000_000)
        .await
        .unwrap();
    assert_eq!(tunnel.starts.load(Ordering::SeqCst), 1);
    assert_eq!(store.load().unwrap().unwrap(), before);
    assert_eq!(state.resume_calls.load(Ordering::SeqCst), 0);
    server.abort();
}

async fn exercise_committed_apply_updates(repeated: bool) {
    let state = Arc::new(Panel::default());
    let (api, server) = panel(state.clone()).await;
    let store = enrolled_store();
    let broker = Arc::new(AuthBroker::new(api, store, Arc::new(Stop)).unwrap());
    let control = Arc::new(SwitchControl::default());
    control.hold_completion.store(1, Ordering::SeqCst);
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("common")).unwrap();
    std::fs::write(
        root.path().join("common/runtime-selection-v1.json"),
        SlotSelectionV1 {
            container_version: "0.2.16".into(),
            selected_slot: RuntimeSlot::Latest,
            pending_slot: None,
        }
        .to_persisted_bytes()
        .unwrap(),
    )
    .unwrap();
    let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    let old = Arc::new(
        SwitchCoordinator::open(owner.clone(), manifest())
            .unwrap()
            .attach(broker.clone(), control.clone()),
    );
    let request_owner = old.clone();
    let request = tokio::spawn(async move { request_owner.request(RuntimeSlot::Latest).await });
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        control.completion_entered.notified(),
    )
    .await
    .unwrap();
    request.abort();
    let _ = request.await;
    drop(old);
    control.hold_completion.store(0, Ordering::SeqCst);
    control.completion_release.notify_waiters();
    std::fs::write(
        root.path().join("common/runtime-selection-v1.json"),
        SlotSelectionV1 {
            container_version: "0.2.17".into(),
            selected_slot: RuntimeSlot::Latest,
            pending_slot: None,
        }
        .to_persisted_bytes()
        .unwrap(),
    )
    .unwrap();
    let updated = Arc::new(
        SwitchCoordinator::open(owner.clone(), manifest_for("0.2.17", "0.2.17"))
            .unwrap()
            .attach(broker.clone(), control.clone()),
    );

    if repeated {
        control.hold_completion.store(1, Ordering::SeqCst);
        let worker = updated.clone();
        let recovery = tokio::spawn(async move { worker.recover().await });
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            control.completion_entered.notified(),
        )
        .await
        .unwrap();
        recovery.abort();
        let _ = recovery.await;
        drop(updated);
        control.hold_completion.store(0, Ordering::SeqCst);
        write_test_selection(root.path(), "0.2.18");
        let newest = SwitchCoordinator::open(owner, manifest_for("0.2.18", "0.2.18"))
            .unwrap()
            .attach(broker.clone(), control.clone());
        assert_eq!(newest.recover().await.unwrap(), SwitchProgress::Ready);
        assert_eq!(state.supersede_calls.load(Ordering::SeqCst), 2);
        assert_eq!(state.resume_calls.load(Ordering::SeqCst), 3);
        assert_eq!(
            broker
                .observe()
                .await
                .unwrap()
                .access
                .unwrap()
                .identity()
                .runtime_version,
            "0.2.18"
        );
        assert_eq!(control.completions.load(Ordering::SeqCst), 1);
        server.abort();
        return;
    }

    assert_eq!(updated.recover().await.unwrap(), SwitchProgress::Ready);
    assert_eq!(state.supersede_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.resume_calls.load(Ordering::SeqCst), 2);
    assert_eq!(control.completions.load(Ordering::SeqCst), 1);
    server.abort();
}

#[tokio::test]
async fn unknown_legacy_refresh_is_durable_and_never_automatically_resent() {
    let state = Arc::new(Panel::default());
    state.reject_bootstrap_access.store(1, Ordering::SeqCst);
    state.fail_refresh.store(1, Ordering::SeqCst);
    let (api, server) = panel(state.clone()).await;
    let store = legacy_store();
    let broker = AuthBroker::new(api.clone(), store.clone(), Arc::new(Stop)).unwrap();
    assert!(broker.transition_source().await.is_err());
    assert_eq!(state.refresh_calls.load(Ordering::SeqCst), 1);
    let pending = store
        .load()
        .unwrap()
        .unwrap()
        .broker
        .unwrap()
        .pending_request
        .unwrap();
    assert_eq!(pending.kind, BrokerRequestKind::LegacyRefresh);
    drop(broker);
    let reopened = AuthBroker::new(api, store, Arc::new(Stop)).unwrap();
    assert!(matches!(
        reopened.transition_source().await,
        Err(BrokerError::RecoveryRequired)
    ));
    assert_eq!(state.refresh_calls.load(Ordering::SeqCst), 1);
    server.abort();
}
