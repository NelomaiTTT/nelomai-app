use async_trait::async_trait;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use nelomai_client_api::{
    LoginRequest, RuntimeSwitchReconcileRequest, RuntimeSwitchState, RuntimeTarget,
};
use nelomai_client_container::{
    AuthBroker, BrokerError, FrozenReconcileRequest, LocalAuthStop, LocalStopReceiptV1,
    ResumeArguments, RuntimeSwitchControl, SwitchCoordinator, SwitchPhase, SwitchProgress,
};
use nelomai_client_storage::{
    AuthStore, AuthStoreV1, BrokerMetadataV1, BrokerRequestKind, BrokerRequestV1,
    ContainerOwnerLock, ProtectedAuthStore, ProtectedRecordStore, RuntimeCleanupSnapshotV1,
    StorageError, StoredAuth, TransitionAuthorityV1, TransitionDispatchStateV1,
};
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
    use ed25519_dalek::{Signer, SigningKey};
    let manifest = ContainerManifestV1 {
        format_version: 1,
        container_version: "0.2.16".into(),
        release_set_id: "runtime-0.2.16".into(),
        minimum_runtime_contract: 1,
        maximum_runtime_contract: 1,
        stable_release_set_sha256: None,
        stable_platform_manifest_sha256: None,
        slots: vec![RuntimeSlotManifestV1 {
            slot: RuntimeSlot::Latest,
            manifest: RuntimeArtifactManifestV1 {
                format_version: 1,
                runtime_version: "0.2.16".into(),
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

struct SaveGate {
    inner: Arc<dyn AuthStore>,
    saves_until_cancel: AtomicUsize,
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
#[async_trait]
impl LocalAuthStop for Stop {
    async fn stop_local(&self) -> Result<(), BrokerError> {
        Ok(())
    }
}

#[derive(Default)]
struct SwitchControl {
    handoffs: AtomicUsize,
    stops: AtomicUsize,
    completions: AtomicUsize,
}
#[async_trait]
impl RuntimeSwitchControl for SwitchControl {
    async fn handoff_cleanup(
        &self,
        _source: &nelomai_client_container::TransitionSourceSnapshot,
    ) -> Result<RuntimeCleanupSnapshotV1, BrokerError> {
        self.handoffs.fetch_add(1, Ordering::SeqCst);
        Ok(RuntimeCleanupSnapshotV1 {
            slot: RuntimeSlot::Latest,
            runtime_version: "0.2.16".into(),
            auth_scope: None,
            lease_ids: vec!["lease-a".into()],
            operations: Vec::new(),
            cleanup_only: true,
        })
    }
    async fn graceful_stop(
        &self,
        _operation_id: &str,
        _snapshot: &RuntimeCleanupSnapshotV1,
    ) -> Result<(), BrokerError> {
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
    reject_reconcile_access: AtomicUsize,
    fail_reconcile: AtomicUsize,
    return_full_device_snapshot: AtomicUsize,
    return_retry: AtomicUsize,
    reconcile_bodies: Mutex<Vec<Value>>,
    resume_calls: AtomicUsize,
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
    if state.fail_refresh.load(Ordering::SeqCst) == 1 {
        return Err(StatusCode::BAD_GATEWAY);
    }
    Ok(Json(
        json!({"api_version":"1","request_id":"r","token_type":"Bearer",
        "access_token":"refreshed-access","access_expires_in":900,
        "refresh_token":"refreshed-refresh","refresh_expires_in":3600,
        "access":{"state":"active","can_login":true,"can_connect":true,"expires_at":null},
        "device":legacy_device()}),
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
    let control = Arc::new(SwitchControl::default());
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
    assert_eq!(state.reconcile_calls.load(Ordering::SeqCst), 1);
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
