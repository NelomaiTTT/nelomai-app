use async_trait::async_trait;
use axum::{extract::State, routing::post, Json, Router};
use nelomai_client_api::{ClientApi, ClientApiError, LoginRequest, RuntimeTarget};
use nelomai_client_container::{
    AuthBroker, BrokerAuthState, BrokerError, LocalAuthStop, ResumeArguments,
};
use nelomai_client_storage::{
    AuthStore, AuthStoreV1, LogoutState, ProtectedAuthStore, ProtectedRecordStore, StorageError,
    StoredAuth,
};
use nelomai_contracts::{RuntimeIdentity, RuntimeSlot};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
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
#[derive(Default)]
struct Stop(AtomicUsize);
#[async_trait]
impl LocalAuthStop for Stop {
    async fn stop_local(&self) -> Result<(), BrokerError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[derive(Default)]
struct NativeStop {
    stops: AtomicUsize,
    hold_stop: AtomicBool,
    handoff_entered: Notify,
    handoffs: AtomicUsize,
    handoff_release: Notify,
    hold: AtomicBool,
    fail: AtomicBool,
}
#[async_trait]
impl LocalAuthStop for NativeStop {
    async fn stop_local(&self) -> Result<(), BrokerError> {
        self.stops.fetch_add(1, Ordering::SeqCst);
        if self.hold_stop.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        Ok(())
    }
    async fn prepare_revocation(&self, _cancel_epoch: u64) -> Result<(), BrokerError> {
        self.handoffs.fetch_add(1, Ordering::SeqCst);
        self.handoff_entered.notify_one();
        if self.hold.load(Ordering::SeqCst) {
            self.handoff_release.notified().await;
        }
        if self.fail.swap(false, Ordering::SeqCst) {
            return Err(BrokerError::RecoveryRequired);
        }
        Ok(())
    }
}

#[tokio::test(start_paused = true)]
async fn native_stop_wait_cannot_exceed_owner_budget_or_prevent_handoff_poll() {
    let state = Arc::new(Panel::default());
    let (api, server) = panel(state).await;
    let store = auth_store();
    let native = Arc::new(NativeStop::default());
    native.hold_stop.store(true, Ordering::SeqCst);
    let broker = AuthBroker::new(api, store.clone(), native.clone()).unwrap();
    let result = tokio::time::timeout(std::time::Duration::from_secs(11), broker.logout())
        .await
        .expect("local native stop must share the bounded owner request budget");
    assert!(matches!(result, Err(BrokerError::Timeout)));
    assert_eq!(native.stops.load(Ordering::SeqCst), 1);
    assert_eq!(native.handoffs.load(Ordering::SeqCst), 1);
    assert!(store.load().unwrap().unwrap().auth_epoch > 0);
    server.abort();
}

#[tokio::test]
async fn native_handoff_never_delays_logout_fence_or_stop_and_failure_retries_exact_proof() {
    let state = Arc::new(Panel::default());
    let (api, server) = panel(state.clone()).await;
    let store = auth_store();
    let native = Arc::new(NativeStop::default());
    native.hold.store(true, Ordering::SeqCst);
    native.fail.store(true, Ordering::SeqCst);
    let broker = Arc::new(AuthBroker::new(api, store.clone(), native.clone()).unwrap());
    let before_epoch = store.load().unwrap().unwrap().auth_epoch;
    let owner = broker.clone();
    let logout = tokio::spawn(async move { owner.logout().await });
    tokio::time::timeout(
        std::time::Duration::from_millis(200),
        native.handoff_entered.notified(),
    )
    .await
    .expect("revocation must await native handoff");
    let pending = store.load().unwrap().unwrap();
    assert_eq!(pending.logout_state, LogoutState::Pending);
    assert!(pending.auth_epoch > before_epoch);
    assert_eq!(native.stops.load(Ordering::SeqCst), 1);
    assert!(broker.access_token(None).await.is_err());
    assert_eq!(state.logout_calls.load(Ordering::SeqCst), 0);
    let proof = pending
        .broker
        .as_ref()
        .unwrap()
        .pending_logout
        .clone()
        .unwrap();
    native.handoff_release.notify_one();
    assert!(logout.await.unwrap().is_err());
    assert_eq!(store.load().unwrap().unwrap(), pending);
    native.hold.store(false, Ordering::SeqCst);
    broker.logout().await.unwrap();
    assert_eq!(
        state.logout_requests.lock().unwrap()[0]["operation_id"],
        proof.operation_id
    );
    assert_eq!(
        state.logout_requests.lock().unwrap()[0]["refresh_token"],
        proof.refresh_proof
    );
    assert_eq!(
        store.load().unwrap().unwrap().logout_state,
        LogoutState::LoggedOut
    );
    server.abort();
}

#[tokio::test]
async fn push_cleanup_journal_survives_owner_restart_and_only_accepted_login_supersedes_it() {
    let state = Arc::new(Panel::default());
    state.lose_logout.store(true, Ordering::SeqCst);
    let (api, server) = panel(state.clone()).await;
    let store = auth_store();
    let broker = AuthBroker::new(api.clone(), store.clone(), Arc::new(Stop::default())).unwrap();
    assert!(broker.logout().await.is_err());
    let epoch = store.load().unwrap().unwrap().auth_epoch;
    broker.stage_push_cleanup(epoch).await.unwrap();
    drop(broker);
    let broker = AuthBroker::new(api, store.clone(), Arc::new(Stop::default())).unwrap();
    assert_eq!(broker.pending_push_cleanup().await.unwrap(), Some(epoch));
    assert!(broker.push_cleanup_is_current(epoch).await.unwrap());
    broker.logout().await.unwrap();
    assert_eq!(
        broker.pending_push_cleanup().await.unwrap(),
        Some(epoch),
        "HTTP ACK is not a push cleanup ACK"
    );
    assert!(broker.finish_push_cleanup(epoch + 1).await.is_err());
    broker.logout().await.unwrap();
    let repeated_epoch = store.load().unwrap().unwrap().auth_epoch;
    assert!(repeated_epoch > epoch);
    assert_eq!(
        broker.pending_push_cleanup().await.unwrap(),
        Some(repeated_epoch)
    );
    assert!(broker
        .push_cleanup_is_current(repeated_epoch)
        .await
        .unwrap());
    let request = LoginRequest {
        login: "synthetic-user".into(),
        password: "synthetic-password".into(),
        install_secret: "ignored".into(),
        device_name: "test".into(),
        platform: nelomai_contracts::Platform::Macos,
        platform_version: None,
        architecture: "aarch64".into(),
        app_version: "0.2.16".into(),
    };
    state.fail_login.store(true, Ordering::SeqCst);
    assert!(broker
        .login(&request, &RuntimeTarget::from_identity(&identity(8)))
        .await
        .is_err());
    assert_eq!(
        broker.pending_push_cleanup().await.unwrap(),
        Some(repeated_epoch)
    );
    broker
        .login(&request, &RuntimeTarget::from_identity(&identity(8)))
        .await
        .unwrap();
    assert_eq!(broker.pending_push_cleanup().await.unwrap(), None);
    assert!(!broker.push_cleanup_is_current(epoch).await.unwrap());
    server.abort();
}
fn identity(generation: u64) -> RuntimeIdentity {
    RuntimeIdentity {
        container_version: "0.2.16".into(),
        runtime_version: "0.2.16".into(),
        runtime_contract_version: 1,
        slot: RuntimeSlot::Latest,
        session_generation: Some(generation),
    }
}
fn auth_store() -> Arc<dyn AuthStore> {
    let store = Arc::new(ProtectedAuthStore::new(Record::default()));
    let mut legacy = StoredAuth::new_install();
    legacy.install_secret = "synthetic-install".into();
    legacy.access_token = Some("initial-access".into());
    legacy.refresh_token = Some("initial-refresh".into());
    let mut value = AuthStoreV1::from_legacy(&legacy);
    value.session_generation = Some(7);
    value.confirmed_identity = Some(identity(7));
    value.broker = Some(nelomai_client_storage::BrokerMetadataV1 {
        family: "synthetic-family".into(),
        next_attempt: 0,
        pending_request: None,
        completed_resume: None,
        pending_logout: None,
        pending_recovery: None,
        cancelled_login: None,
        authentication_outcome_unknown: false,
        pending_login_account: None,
        confirmed_device_id: Some("device".into()),
        pending_push_cleanup_epoch: None,
    });
    store.save(&value).unwrap();
    store
}

#[tokio::test]
async fn runtime_owner_port_binds_trusted_target_and_keeps_migration_credentials_private() {
    use nelomai_client_container::{OwnerRuntimeAuth, RuntimeCacheAdmission, RuntimeClientProfile};
    use nelomai_client_core::{RuntimeAuthProvider, RuntimeWriterGates};
    use nelomai_client_storage::{
        ProtectedRuntimeStore, RuntimePaths, RuntimeRecordOwner, RuntimeStateStore, RuntimeStateV1,
        StoredSplitTunnelState,
    };
    let state = Arc::new(Panel::default());
    let (api, server) = panel(state.clone()).await;
    let store = auth_store();
    let broker = Arc::new(AuthBroker::new(api, store.clone(), Arc::new(Stop::default())).unwrap());
    let profile = RuntimeClientProfile {
        platform: nelomai_contracts::Platform::Macos,
        platform_version: None,
        architecture: "aarch64".into(),
    };
    let target = RuntimeTarget::from_identity(&identity(7));
    let root = tempfile::tempdir().unwrap();
    let paths = RuntimePaths::new(root.path(), RuntimeSlot::Latest, "0.2.16").unwrap();
    let runtime = ProtectedRuntimeStore::new(Record::default(), paths.clone());
    let mut value = RuntimeStateV1::import_legacy(
        &StoredAuth::new_install(),
        StoredSplitTunnelState::default(),
        &paths,
    );
    value.cleanup_only = false;
    runtime.save(&value).unwrap();
    let admission = Arc::new(RuntimeCacheAdmission::new(RuntimeRecordOwner::new(runtime)));
    let writers = Arc::new(RuntimeWriterGates::default());
    let port = OwnerRuntimeAuth::new(
        broker.clone(),
        target.clone(),
        profile.clone(),
        admission.clone(),
        writers.clone(),
    )
    .unwrap();
    port.admit_empty_current().await.unwrap();
    assert_eq!(port.access(None).await.unwrap().identity(), &identity(7));
    let wrong = OwnerRuntimeAuth::new(
        broker,
        RuntimeTarget {
            runtime_slot: RuntimeSlot::Stable,
            ..target
        },
        profile,
        admission,
        writers,
    )
    .unwrap();
    assert!(wrong.access(None).await.is_err());
    assert!(
        wrong.state().await.is_err(),
        "offline admission also respects the trusted target"
    );
    assert_eq!(state.calls.load(Ordering::SeqCst), 0);
    let mut legacy = store.load().unwrap().unwrap();
    legacy.session_generation = None;
    legacy.confirmed_identity = None;
    store.save(&legacy).unwrap();
    assert!(port.access(None).await.is_err());
    assert_eq!(store.load().unwrap().unwrap(), legacy);
    assert_eq!(state.calls.load(Ordering::SeqCst), 0);
    server.abort();
}
fn response(generation: u64, access: &str) -> Value {
    json!({"api_version":"1","request_id":"synthetic","token_type":"Bearer",
        "access_token":access,"access_expires_in":900,"refresh_token":"successor-refresh","refresh_expires_in":3600,
        "access":{"state":"active","can_login":true,"can_connect":true,"expires_at":null},
        "device":{"id":"device","name":"test","platform":"macos","container_version":"0.2.16",
            "runtime_version":"0.2.16","runtime_contract_version":1,"runtime_slot":"latest","session_generation":generation}})
}
#[derive(Default)]
struct Panel {
    calls: AtomicUsize,
    entered: Notify,
    release: Notify,
    held: AtomicBool,
    old_generation: AtomicBool,
    foreign_refresh_device: AtomicBool,
    logout_calls: AtomicUsize,
    lose_logout: AtomicBool,
    resume_requests: Mutex<Vec<Value>>,
    login_requests: Mutex<Vec<Value>>,
    hold_login: AtomicBool,
    login_entered: Notify,
    login_release: Notify,
    fail_login: AtomicBool,
    hold_resume: AtomicBool,
    resume_entered: Notify,
    resume_release: Notify,
    logout_requests: Mutex<Vec<Value>>,
    login_reply: Mutex<Option<Value>>,
    login_rejection: Mutex<Option<(u16, String)>>,
}
async fn login(
    State(panel): State<Arc<Panel>>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    panel.login_requests.lock().unwrap().push(body);
    panel.login_entered.notify_one();
    if panel.hold_login.load(Ordering::SeqCst) {
        panel.login_release.notified().await;
    }
    if panel.fail_login.swap(false, Ordering::SeqCst) {
        return Err((axum::http::StatusCode::BAD_GATEWAY, Json(json!({}))));
    }
    if let Some((status, code)) = panel.login_rejection.lock().unwrap().take() {
        return Err((
            axum::http::StatusCode::from_u16(status).unwrap(),
            Json(json!({"request_id":"synthetic",
            "code":code, "message":"rejected"})),
        ));
    }
    Ok(Json(
        panel
            .login_reply
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| response(8, "login-access")),
    ))
}
async fn refresh(State(panel): State<Arc<Panel>>, Json(body): Json<Value>) -> Json<Value> {
    assert_eq!(body["refresh_token"], "initial-refresh");
    panel.calls.fetch_add(1, Ordering::SeqCst);
    panel.entered.notify_one();
    if panel.held.load(Ordering::SeqCst) {
        panel.release.notified().await;
    }
    let mut reply = response(
        if panel.old_generation.load(Ordering::SeqCst) {
            6
        } else {
            7
        },
        "successor-access",
    );
    if panel.foreign_refresh_device.load(Ordering::SeqCst) {
        reply["device"]["id"] = json!("another-device");
    }
    Json(reply)
}
async fn logout(
    State(panel): State<Arc<Panel>>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, axum::http::StatusCode> {
    assert!(matches!(
        body["refresh_token"].as_str(),
        Some("initial-refresh" | "successor-refresh")
    ));
    panel.logout_calls.fetch_add(1, Ordering::SeqCst);
    panel.logout_requests.lock().unwrap().push(body);
    if panel.lose_logout.swap(false, Ordering::SeqCst) {
        return Err(axum::http::StatusCode::SERVICE_UNAVAILABLE);
    }
    Ok(Json(
        json!({"code":"session_revoked_cleanup_accepted","cleanup_reconcile_operation_id":"cleanup"}),
    ))
}
async fn resume(State(panel): State<Arc<Panel>>, Json(body): Json<Value>) -> Json<Value> {
    panel.resume_requests.lock().unwrap().push(body);
    panel.resume_entered.notify_one();
    if panel.hold_resume.load(Ordering::SeqCst) {
        panel.resume_release.notified().await;
    }
    Json(
        json!({"identity":{"container_version":"0.2.16","runtime_version":"0.2.16","runtime_contract_version":1,"runtime_slot":"latest","session_generation":8},"access_token":"resumed-access","token_type":"Bearer","access_expires_in":900}),
    )
}
async fn panel(state: Arc<Panel>) -> (ClientApi, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = ClientApi::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let router = Router::new()
        .route("/api/client/v1/auth/refresh", post(refresh))
        .route("/api/client/v1/auth/login", post(login))
        .route("/api/client/v1/auth/logout-runtime", post(logout))
        .route("/api/client/v1/runtime/resume", post(resume))
        .with_state(state);
    (
        api,
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        }),
    )
}

#[tokio::test]
async fn concurrent_stale_access_requests_serialize_refresh_and_keep_identity() {
    let state = Arc::new(Panel::default());
    let (api, server) = panel(state.clone()).await;
    let store = auth_store();
    let broker = AuthBroker::new(api, store.clone(), Arc::new(Stop::default())).unwrap();
    let old = broker.access_token(None).await.unwrap();
    let (a, b) = tokio::join!(
        broker.access_token(Some(&old)),
        broker.access_token(Some(&old))
    );
    let a = a.unwrap();
    let b = b.unwrap();
    assert_eq!(a, b);
    assert_eq!(a.identity(), &identity(7));
    assert_eq!(a.family(), old.family());
    assert_eq!(state.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        store.load().unwrap().unwrap().refresh_token.as_deref(),
        Some("successor-refresh")
    );
    server.abort();
}

#[tokio::test]
async fn ordinary_refresh_rejects_foreign_device_with_same_runtime_identity() {
    let state = Arc::new(Panel::default());
    state.foreign_refresh_device.store(true, Ordering::SeqCst);
    let (api, server) = panel(state.clone()).await;
    let store = auth_store();
    let broker = AuthBroker::new(api, store.clone(), Arc::new(Stop::default())).unwrap();
    let previous = broker.access_token(None).await.unwrap();
    assert!(matches!(
        broker.access_token(Some(&previous)).await,
        Err(BrokerError::IdentityMismatch)
    ));
    let retained = store.load().unwrap().unwrap();
    assert_eq!(retained.access_token.as_deref(), Some("initial-access"));
    assert_eq!(retained.refresh_token.as_deref(), Some("initial-refresh"));
    assert!(retained.broker.unwrap().pending_request.is_some());
    assert!(matches!(
        broker.access_token(None).await,
        Err(BrokerError::RecoveryRequired)
    ));
    assert_eq!(state.calls.load(Ordering::SeqCst), 1);
    server.abort();
}

#[tokio::test]
async fn logout_persists_epoch_and_stops_without_waiting_for_refresh_then_rejects_late_response() {
    let state = Arc::new(Panel::default());
    state.held.store(true, Ordering::SeqCst);
    let (api, server) = panel(state.clone()).await;
    let store = auth_store();
    let stop = Arc::new(Stop::default());
    let broker = Arc::new(AuthBroker::new(api, store.clone(), stop.clone()).unwrap());
    let old = broker.access_token(None).await.unwrap();
    let task = {
        let broker = broker.clone();
        tokio::spawn(async move { broker.access_token(Some(&old)).await })
    };
    state.entered.notified().await;
    tokio::time::timeout(std::time::Duration::from_secs(1), broker.logout())
        .await
        .unwrap()
        .unwrap();
    let saved = store.load().unwrap().unwrap();
    assert_eq!(saved.auth_epoch, 1);
    assert_eq!(saved.logout_state, LogoutState::LoggedOut);
    assert_eq!(stop.0.load(Ordering::SeqCst), 1);
    assert_eq!(state.logout_calls.load(Ordering::SeqCst), 1);
    state.release.notify_one();
    assert!(matches!(task.await.unwrap(), Err(BrokerError::Cancelled)));
    assert!(store.load().unwrap().unwrap().access_token.is_none());
    assert!(broker.access_token(None).await.is_err());
    server.abort();
}

#[tokio::test]
async fn old_generation_refresh_cannot_replace_current_pair() {
    let state = Arc::new(Panel::default());
    state.old_generation.store(true, Ordering::SeqCst);
    let (api, server) = panel(state).await;
    let store = auth_store();
    let broker = AuthBroker::new(api, store.clone(), Arc::new(Stop::default())).unwrap();
    let old = broker.access_token(None).await.unwrap();
    assert!(broker.access_token(Some(&old)).await.is_err());
    let saved = store.load().unwrap().unwrap();
    assert_eq!(saved.confirmed_identity, Some(identity(7)));
    assert_eq!(saved.access_token.as_deref(), Some("initial-access"));
    server.abort();
}

#[tokio::test]
async fn fresh_owner_retries_pending_logout_with_same_proof_and_no_issuance() {
    let state = Arc::new(Panel::default());
    state.lose_logout.store(true, Ordering::SeqCst);
    let (api, server) = panel(state.clone()).await;
    let store = auth_store();
    let broker = AuthBroker::new(api.clone(), store.clone(), Arc::new(Stop::default())).unwrap();
    assert!(broker.logout().await.is_err());
    assert_eq!(
        store.load().unwrap().unwrap().logout_state,
        LogoutState::Pending
    );
    let bytes_before = serde_json::to_value(store.load().unwrap().unwrap()).unwrap();
    drop(broker);
    let reopened = AuthBroker::new(api, store.clone(), Arc::new(Stop::default())).unwrap();
    assert!(reopened.access_token(None).await.is_err());
    assert_eq!(
        serde_json::to_value(store.load().unwrap().unwrap()).unwrap(),
        bytes_before
    );
    reopened.logout().await.unwrap();
    assert_eq!(
        store.load().unwrap().unwrap().logout_state,
        LogoutState::LoggedOut
    );
    assert_eq!(state.logout_calls.load(Ordering::SeqCst), 2);
    server.abort();
    let requests = state.logout_requests.lock().unwrap();
    assert_eq!(requests[0], requests[1]);
}

#[tokio::test]
async fn accepted_resume_commits_server_identity_and_cannot_be_replayed_over_newer_auth() {
    let state = Arc::new(Panel::default());
    let (api, server) = panel(state.clone()).await;
    let store = auth_store();
    let broker = AuthBroker::new(api, store.clone(), Arc::new(Stop::default())).unwrap();
    let args = ResumeArguments {
        operation_id: "11111111-1111-4111-8111-111111111111".into(),
        reconcile_operation_id: "22222222-2222-4222-8222-222222222222".into(),
        decision: "apply".into(),
        target: RuntimeTarget::from_identity(&identity(8)),
        expected_session_generation: Some(7),
    };
    let result = broker.resume(args.clone()).await.unwrap();
    assert_eq!(result.identity(), &identity(8));
    assert_eq!(
        store.load().unwrap().unwrap().refresh_token.as_deref(),
        Some("initial-refresh")
    );
    assert_eq!(broker.resume(args.clone()).await.unwrap(), result);
    let mut later = store.load().unwrap().unwrap();
    later.auth_epoch += 1;
    later.confirmed_identity = Some(identity(9));
    later.session_generation = Some(9);
    store.save(&later).unwrap();
    assert!(broker.resume(args).await.is_err());
    assert_eq!(state.resume_requests.lock().unwrap().len(), 1);
    server.abort();
}

#[tokio::test]
async fn owner_recovery_ticket_preserves_successor_family_but_rejects_replayed_or_logged_out_callback(
) {
    let state = Arc::new(Panel::default());
    let (api, server) = panel(state).await;
    let store = auth_store();
    let broker = AuthBroker::new(api, store.clone(), Arc::new(Stop::default())).unwrap();
    let old = broker.access_token(None).await.unwrap();
    let ticket = broker.begin_background_recovery().await.unwrap();
    let recovered = serde_json::from_value(response(7, "background-access")).unwrap();
    let first = broker
        .accept_background_recovery(&ticket, recovered)
        .await
        .unwrap();
    assert_eq!(first.identity(), old.identity());
    assert_eq!(first.family(), old.family());
    let next_ticket = broker.begin_background_recovery().await.unwrap();
    let successor = serde_json::from_value(response(7, "next-background-access")).unwrap();
    let next = broker
        .accept_background_recovery(&next_ticket, successor)
        .await
        .unwrap();
    assert_eq!(next.family(), first.family());
    let stale = serde_json::from_value(response(7, "stale-access")).unwrap();
    assert!(matches!(
        broker.accept_background_recovery(&ticket, stale).await,
        Err(BrokerError::Cancelled)
    ));
    assert_eq!(
        store.load().unwrap().unwrap().access_token.as_deref(),
        Some("next-background-access")
    );
    let final_ticket = broker.begin_background_recovery().await.unwrap();
    // Model durable logout invalidation without rotating/probing any callback token.
    let mut logged_out = store.load().unwrap().unwrap();
    logged_out.auth_epoch += 1;
    logged_out.logout_state = LogoutState::Pending;
    store.save(&logged_out).unwrap();
    let late = serde_json::from_value(response(7, "late-access")).unwrap();
    assert!(broker
        .accept_background_recovery(&final_ticket, late)
        .await
        .is_err());
    assert_eq!(
        store.load().unwrap().unwrap().logout_state,
        LogoutState::Pending
    );
    server.abort();
}

#[tokio::test]
async fn recovery_callback_cannot_import_another_identity_even_with_current_ticket() {
    let state = Arc::new(Panel::default());
    let (api, server) = panel(state).await;
    let store = auth_store();
    let broker = AuthBroker::new(api, store.clone(), Arc::new(Stop::default())).unwrap();
    let ticket = broker.begin_background_recovery().await.unwrap();
    let foreign = serde_json::from_value(response(8, "foreign-access")).unwrap();
    assert!(broker
        .accept_background_recovery(&ticket, foreign)
        .await
        .is_err());
    assert_eq!(
        store.load().unwrap().unwrap().access_token.as_deref(),
        Some("initial-access")
    );
    server.abort();
}

#[tokio::test]
async fn recovery_callback_rejects_another_device_with_identical_runtime_identity() {
    let state = Arc::new(Panel::default());
    let (api, server) = panel(state.clone()).await;
    let store = auth_store();
    let broker = AuthBroker::new(api, store.clone(), Arc::new(Stop::default())).unwrap();
    let mut known = store.load().unwrap().unwrap();
    known.broker.as_mut().unwrap().confirmed_device_id = Some("device".into());
    store.save(&known).unwrap();
    let ticket = broker.begin_background_recovery().await.unwrap();
    let before = store.load().unwrap();
    let mut foreign = response(7, "foreign-access");
    foreign["device"]["id"] = json!("other-device");
    assert!(matches!(
        broker
            .accept_background_recovery(&ticket, serde_json::from_value(foreign).unwrap())
            .await,
        Err(BrokerError::IdentityMismatch)
    ));
    assert_eq!(store.load().unwrap(), before);
    assert_eq!(
        state.calls.load(Ordering::SeqCst),
        0,
        "no ordinary refresh validation probe"
    );
    server.abort();
}

#[tokio::test]
async fn owner_native_recovery_checks_real_runtime_admission_and_ignores_stale_errors() {
    use nelomai_client_container::{
        NativeAuthFailure, OwnerRuntimeAuth, RuntimeCacheAdmission, RuntimeClientProfile,
    };
    use nelomai_client_core::RuntimeWriterGates;
    use nelomai_client_storage::{
        ProtectedRuntimeStore, RuntimePaths, RuntimeRecordOwner, RuntimeStateStore, RuntimeStateV1,
        StoredSplitTunnelState,
    };
    let state = Arc::new(Panel::default());
    let (api, server) = panel(state.clone()).await;
    let store = auth_store();
    let broker = Arc::new(AuthBroker::new(api, store.clone(), Arc::new(Stop::default())).unwrap());
    let root = tempfile::tempdir().unwrap();
    let runtime = ProtectedRuntimeStore::new(
        Record::default(),
        RuntimePaths::new(root.path(), RuntimeSlot::Latest, "0.2.16").unwrap(),
    );
    let mut empty = RuntimeStateV1::import_legacy(
        &StoredAuth::new_install(),
        StoredSplitTunnelState::default(),
        runtime.paths(),
    );
    // Synthetic fresh, non-migrating runtime; no cleanup references exist.
    empty.cleanup_only = false;
    runtime.save(&empty).unwrap();
    let record = RuntimeRecordOwner::new(runtime);
    let port = OwnerRuntimeAuth::new(
        broker.clone(),
        RuntimeTarget::from_identity(&identity(7)),
        RuntimeClientProfile {
            platform: nelomai_contracts::Platform::Macos,
            platform_version: None,
            architecture: "aarch64".into(),
        },
        Arc::new(RuntimeCacheAdmission::new(record)),
        Arc::new(RuntimeWriterGates::default()),
    )
    .unwrap();
    let dispatches = AtomicUsize::new(0);
    assert!(port
        .recover_background(|_| async {
            dispatches.fetch_add(1, Ordering::SeqCst);
            Err(NativeAuthFailure::NotIssued)
        })
        .await
        .is_err());
    assert_eq!(
        dispatches.load(Ordering::SeqCst),
        0,
        "missing runtime scope is not recovery eligibility"
    );
    port.admit_empty_current().await.unwrap();
    let dispatch_store = store.clone();
    let recovered = port
        .recover_background(|request| async move {
            assert_eq!(request.install_secret, "synthetic-install");
            assert_eq!(request.ticket.device_id.as_deref(), Some("device"));
            assert_eq!(
                dispatch_store
                    .load()
                    .unwrap()
                    .unwrap()
                    .broker
                    .unwrap()
                    .pending_recovery,
                Some(request.ticket.clone())
            );
            Ok(serde_json::from_value(response(7, "native-access")).unwrap())
        })
        .await
        .unwrap();
    assert_eq!(recovered.access_token(), "native-access");
    assert_eq!(state.calls.load(Ordering::SeqCst), 0);
    assert!(matches!(
        port.recover_background(|_| async { Err(NativeAuthFailure::AccessUnavailable) })
            .await,
        Err(nelomai_client_core::CoreError::AccessExpired)
    ));
    assert!(port
        .recover_background(|_| async {
            broker.logout().await.unwrap();
            Err(NativeAuthFailure::NotIssued)
        })
        .await
        .is_err());
    assert_eq!(
        store.load().unwrap().unwrap().logout_state,
        LogoutState::LoggedOut
    );
    assert!(store.load().unwrap().unwrap().access_token.is_none());
    server.abort();
}

#[tokio::test]
async fn explicit_reauthentication_after_logout_preserves_install_identity_and_uses_new_family() {
    let state = Arc::new(Panel::default());
    let (api, server) = panel(state.clone()).await;
    let store = auth_store();
    let broker = AuthBroker::new(api, store.clone(), Arc::new(Stop::default())).unwrap();
    let original = broker.access_token(None).await.unwrap();
    broker.logout().await.unwrap();
    let login = LoginRequest {
        login: "synthetic-user".into(),
        password: "synthetic-password".into(),
        install_secret: "must-not-be-used".into(),
        device_name: "test".into(),
        platform: nelomai_contracts::Platform::Macos,
        platform_version: None,
        architecture: "aarch64".into(),
        app_version: "0.2.16".into(),
    };
    let next = broker
        .login(&login, &RuntimeTarget::from_identity(&identity(8)))
        .await
        .unwrap();
    assert_eq!(next.identity(), &identity(8));
    assert_ne!(next.family(), original.family());
    assert!(next.auth_epoch() > original.auth_epoch());
    assert_eq!(
        store.load().unwrap().unwrap().install_secret,
        "synthetic-install"
    );
    assert_eq!(
        state.login_requests.lock().unwrap()[0]["install_secret"],
        "synthetic-install"
    );
    server.abort();
}

#[test]
fn broker_error_debug_does_not_expose_server_controlled_secrets() {
    let error = BrokerError::Api(ClientApiError::InvalidBaseUrl("synthetic-secret".into()));
    assert!(!format!("{error:?} {error}").contains("synthetic-secret"));
}

fn login_request() -> LoginRequest {
    LoginRequest {
        login: "synthetic-user".into(),
        password: "synthetic-password".into(),
        install_secret: "untrusted-ignored".into(),
        device_name: "test".into(),
        platform: nelomai_contracts::Platform::Macos,
        platform_version: None,
        architecture: "aarch64".into(),
        app_version: "0.2.16".into(),
    }
}

#[tokio::test]
async fn logout_cancels_login_already_waiting_for_broker_issuance() {
    let state = Arc::new(Panel::default());
    state.held.store(true, Ordering::SeqCst);
    let (api, server) = panel(state.clone()).await;
    let store = auth_store();
    let broker = Arc::new(AuthBroker::new(api, store.clone(), Arc::new(Stop::default())).unwrap());
    let stale = broker.access_token(None).await.unwrap();
    let refreshing = broker.clone();
    let refresh = tokio::spawn(async move { refreshing.access_token(Some(&stale)).await });
    state.entered.notified().await;
    let request = login_request();
    let target = RuntimeTarget::from_identity(&identity(7));
    let queued = broker.login(&request, &target);
    tokio::pin!(queued);
    tokio::select! { biased;
        _ = &mut queued => panic!("login must wait behind the real HTTP refresh"),
        _ = tokio::task::yield_now() => {}
    }
    broker.logout().await.unwrap();
    let logged_out = store.load().unwrap();
    state.release.notify_one();
    assert!(refresh.await.unwrap().is_err());
    assert!(matches!(queued.await, Err(BrokerError::Cancelled)));
    assert!(state.login_requests.lock().unwrap().is_empty());
    assert_eq!(store.load().unwrap(), logged_out);
    server.abort();
}

#[tokio::test]
async fn cancelled_login_late_family_is_persisted_and_revoked_never_issued() {
    let state = Arc::new(Panel::default());
    state.hold_login.store(true, Ordering::SeqCst);
    let (api, server) = panel(state.clone()).await;
    let store = auth_store();
    let broker = Arc::new(AuthBroker::new(api, store.clone(), Arc::new(Stop::default())).unwrap());
    broker.logout().await.unwrap();
    let login = {
        let broker = broker.clone();
        tokio::spawn(async move {
            broker
                .login(
                    &login_request(),
                    &RuntimeTarget::from_identity(&identity(8)),
                )
                .await
        })
    };
    state.login_entered.notified().await;
    assert!(matches!(
        broker.logout().await,
        Err(BrokerError::AuthenticationOutcomeUnknown)
    ));
    assert_eq!(
        broker.auth_state().await.unwrap(),
        BrokerAuthState::AuthenticationOutcomeUnknown
    );
    assert!(broker.access_token(None).await.is_err());
    state.login_release.notify_one();
    assert!(matches!(login.await.unwrap(), Err(BrokerError::Cancelled)));
    assert_eq!(
        store.load().unwrap().unwrap().logout_state,
        LogoutState::LoggedOut
    );
    assert!(store.load().unwrap().unwrap().refresh_token.is_none());
    assert_eq!(state.logout_calls.load(Ordering::SeqCst), 2);
    server.abort();
}

#[tokio::test]
async fn lost_password_login_outcome_is_explicit_and_only_explicit_same_install_reauth_resolves_it()
{
    let state = Arc::new(Panel::default());
    state.fail_login.store(true, Ordering::SeqCst);
    let (api, server) = panel(state.clone()).await;
    let store = auth_store();
    let broker = AuthBroker::new(api.clone(), store.clone(), Arc::new(Stop::default())).unwrap();
    broker.logout().await.unwrap();
    assert!(broker
        .login(
            &login_request(),
            &RuntimeTarget::from_identity(&identity(8))
        )
        .await
        .is_err());
    drop(broker);
    let reopened = AuthBroker::new(api, store.clone(), Arc::new(Stop::default())).unwrap();
    assert_eq!(
        reopened.auth_state().await.unwrap(),
        BrokerAuthState::AuthenticationOutcomeUnknown
    );
    assert!(reopened.access_token(None).await.is_err());
    assert_eq!(state.login_requests.lock().unwrap().len(), 1);
    let mut other_account = login_request();
    other_account.login = "different-account".into();
    assert!(reopened
        .login(&other_account, &RuntimeTarget::from_identity(&identity(8)))
        .await
        .is_err());
    assert_eq!(state.login_requests.lock().unwrap().len(), 1);
    let result = reopened
        .login(
            &login_request(),
            &RuntimeTarget::from_identity(&identity(8)),
        )
        .await
        .unwrap();
    assert_eq!(result.identity(), &identity(8));
    let requests = state.login_requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0]["install_secret"], requests[1]["install_secret"]);
    assert_eq!(
        store.load().unwrap().unwrap().install_secret,
        "synthetic-install"
    );
    server.abort();
}

#[tokio::test]
async fn refresh_timeout_exposes_recovery_instead_of_retrying_old_proof_and_scoped_recovery_unblocks_it(
) {
    let state = Arc::new(Panel::default());
    state.held.store(true, Ordering::SeqCst);
    let (api, server) = panel(state.clone()).await;
    let store = auth_store();
    let broker = Arc::new(AuthBroker::new(api, store, Arc::new(Stop::default())).unwrap());
    let old = broker.access_token(None).await.unwrap();
    let task = {
        let broker = broker.clone();
        tokio::spawn(async move { broker.access_token(Some(&old)).await })
    };
    state.entered.notified().await;
    tokio::time::pause();
    tokio::time::advance(std::time::Duration::from_secs(10)).await;
    assert!(matches!(task.await.unwrap(), Err(BrokerError::Timeout)));
    assert_eq!(
        broker.auth_state().await.unwrap(),
        BrokerAuthState::RecoveryRequired
    );
    assert!(broker.access_token(None).await.is_err());
    assert_eq!(state.calls.load(Ordering::SeqCst), 1);
    let ticket = broker.begin_background_recovery().await.unwrap();
    broker
        .accept_background_recovery(
            &ticket,
            serde_json::from_value(response(7, "recovered-access")).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(broker.auth_state().await.unwrap(), BrokerAuthState::Active);
    assert_eq!(
        broker.access_token(None).await.unwrap().access_token(),
        "recovered-access"
    );
    server.abort();
}

#[tokio::test]
async fn abandoned_login_future_has_explicit_outcome_and_does_not_remain_busy() {
    let state = Arc::new(Panel::default());
    state.hold_login.store(true, Ordering::SeqCst);
    let (api, server) = panel(state.clone()).await;
    let broker = Arc::new(AuthBroker::new(api, auth_store(), Arc::new(Stop::default())).unwrap());
    broker.logout().await.unwrap();
    let request = {
        let broker = broker.clone();
        tokio::spawn(async move {
            broker
                .login(
                    &login_request(),
                    &RuntimeTarget::from_identity(&identity(8)),
                )
                .await
        })
    };
    state.login_entered.notified().await;
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    assert_eq!(
        broker.auth_state().await.unwrap(),
        BrokerAuthState::AuthenticationOutcomeUnknown
    );
    state.hold_login.store(false, Ordering::SeqCst);
    let result = broker
        .login(
            &login_request(),
            &RuntimeTarget::from_identity(&identity(8)),
        )
        .await
        .unwrap();
    assert_eq!(result.identity(), &identity(8));
    state.login_release.notify_one();
    server.abort();
}

#[tokio::test]
async fn same_operation_old_attempt_response_cannot_commit_over_durable_superseding_ticket() {
    let state = Arc::new(Panel::default());
    state.hold_resume.store(true, Ordering::SeqCst);
    let (api, server) = panel(state.clone()).await;
    let store = auth_store();
    let broker = Arc::new(AuthBroker::new(api, store.clone(), Arc::new(Stop::default())).unwrap());
    let request = {
        let broker = broker.clone();
        tokio::spawn(async move { broker.resume(resume_args()).await })
    };
    state.resume_entered.notified().await;
    let mut saved = store.load().unwrap().unwrap();
    let meta = saved.broker.as_mut().unwrap();
    let original = meta.pending_request.clone().unwrap();
    // Fault injection of a durable superseding attempt: same epoch/op/target,
    // only attempt differs. The real HTTP response is still from attempt one.
    meta.next_attempt += 1;
    meta.pending_request.as_mut().unwrap().attempt = meta.next_attempt;
    store.save(&saved).unwrap();
    state.resume_release.notify_one();
    assert!(matches!(
        request.await.unwrap(),
        Err(BrokerError::Cancelled)
    ));
    let after = store.load().unwrap().unwrap();
    assert_eq!(after.session_generation, Some(7));
    assert_eq!(after.access_token.as_deref(), Some("initial-access"));
    let pending = after.broker.unwrap().pending_request.unwrap();
    assert_eq!(pending.operation_id, original.operation_id);
    assert!(pending.attempt > original.attempt);
    server.abort();
}

#[derive(Clone, Default)]
struct FaultRecord {
    record: Record,
    countdown: Arc<AtomicUsize>,
    after_write: Arc<AtomicBool>,
}
impl ProtectedRecordStore for FaultRecord {
    fn load_record(&self) -> Result<Option<Vec<u8>>, StorageError> {
        self.record.load_record()
    }
    fn save_record(&self, bytes: &[u8]) -> Result<(), StorageError> {
        let previous = self
            .countdown
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                Some(n.saturating_sub(1))
            })
            .unwrap();
        let fail = previous == 1;
        if fail && !self.after_write.load(Ordering::SeqCst) {
            return Err(StorageError::RecoveryRequired(
                "synthetic before-write failure",
            ));
        }
        self.record.save_record(bytes)?;
        if fail {
            return Err(StorageError::RecoveryRequired(
                "synthetic after-write failure",
            ));
        }
        Ok(())
    }
    fn delete_record(&self) -> Result<(), StorageError> {
        self.record.delete_record()
    }
}

#[tokio::test]
async fn protected_ticket_and_result_write_failures_never_issue_or_reuse_uncertain_refresh() {
    for (write, after) in [(1, false), (1, true), (2, false), (2, true)] {
        let state = Arc::new(Panel::default());
        let (api, server) = panel(state.clone()).await;
        let raw = FaultRecord::default();
        let store = Arc::new(ProtectedAuthStore::new(raw.clone()));
        store.save(&auth_store().load().unwrap().unwrap()).unwrap();
        let broker =
            AuthBroker::new(api.clone(), store.clone(), Arc::new(Stop::default())).unwrap();
        let old = broker.access_token(None).await.unwrap();
        raw.after_write.store(after, Ordering::SeqCst);
        raw.countdown.store(write, Ordering::SeqCst);
        assert!(matches!(
            broker.access_token(Some(&old)).await,
            Err(BrokerError::Storage(_))
        ));
        let calls = state.calls.load(Ordering::SeqCst);
        assert_eq!(calls, usize::from(write == 2));
        drop(broker);
        let reopened = AuthBroker::new(api, store.clone(), Arc::new(Stop::default())).unwrap();
        if (write, after) == (2, true) {
            assert_eq!(
                reopened.access_token(None).await.unwrap().access_token(),
                "successor-access"
            );
        } else if (write, after) == (1, false) {
            assert_eq!(reopened.access_token(None).await.unwrap(), old);
        } else {
            assert_eq!(
                reopened.auth_state().await.unwrap(),
                BrokerAuthState::RecoveryRequired
            );
            assert!(reopened.access_token(Some(&old)).await.is_err());
        }
        assert_eq!(state.calls.load(Ordering::SeqCst), calls);
        server.abort();
    }
}

#[tokio::test]
async fn known_pending_revocation_cannot_be_discarded_by_fresh_login() {
    let state = Arc::new(Panel::default());
    let (api, server) = panel(state.clone()).await;
    let store = auth_store();
    let mut fresh = store.load().unwrap().unwrap();
    fresh.access_token = None;
    fresh.refresh_token = None;
    fresh.confirmed_identity = None;
    fresh.session_generation = None;
    store.save(&fresh).unwrap();
    let broker = AuthBroker::new(api, store.clone(), Arc::new(Stop::default())).unwrap();
    let mut pending = store.load().unwrap().unwrap();
    pending.logout_state = LogoutState::Pending;
    pending.broker.as_mut().unwrap().pending_logout =
        Some(nelomai_client_storage::PendingLogoutV1 {
            operation_id: "11111111-1111-4111-8111-111111111111".into(),
            refresh_proof: "initial-refresh".into(),
        });
    store.save(&pending).unwrap();
    assert!(broker
        .login(
            &login_request(),
            &RuntimeTarget::from_identity(&identity(8))
        )
        .await
        .is_err());
    assert_eq!(state.login_requests.lock().unwrap().len(), 0);
    assert!(store
        .load()
        .unwrap()
        .unwrap()
        .broker
        .unwrap()
        .pending_logout
        .is_some());
    server.abort();
}

struct FirstStopFails(AtomicUsize);
#[async_trait]
impl LocalAuthStop for FirstStopFails {
    async fn stop_local(&self) -> Result<(), BrokerError> {
        if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
            Err(BrokerError::RecoveryRequired)
        } else {
            Ok(())
        }
    }
}
#[tokio::test]
async fn logout_retry_retries_local_stop_even_after_remote_ack_cleared_credentials() {
    let state = Arc::new(Panel::default());
    let (api, server) = panel(state.clone()).await;
    let stop = Arc::new(FirstStopFails(AtomicUsize::new(0)));
    let broker = AuthBroker::new(api, auth_store(), stop.clone()).unwrap();
    assert!(broker.logout().await.is_err());
    assert_eq!(
        broker.auth_state().await.unwrap(),
        BrokerAuthState::LoggedOut
    );
    broker.logout().await.unwrap();
    assert_eq!(stop.0.load(Ordering::SeqCst), 2);
    assert_eq!(state.logout_calls.load(Ordering::SeqCst), 1);
    server.abort();
}

#[tokio::test]
async fn resume_retires_background_ticket_and_completed_replay_does_not_bypass_pending_issuance() {
    let state = Arc::new(Panel::default());
    let (api, server) = panel(state).await;
    let store = auth_store();
    let broker = AuthBroker::new(api, store, Arc::new(Stop::default())).unwrap();
    let old_ticket = broker.begin_background_recovery().await.unwrap();
    let resumed = broker.resume(resume_args()).await.unwrap();
    assert_eq!(broker.access_token(None).await.unwrap(), resumed);
    let old_response = serde_json::from_value(response(7, "old-background")).unwrap();
    assert!(broker
        .accept_background_recovery(&old_ticket, old_response)
        .await
        .is_err());
    let _pending_new_recovery = broker.begin_background_recovery().await.unwrap();
    assert!(broker.resume(resume_args()).await.is_err());
    server.abort();
}

#[tokio::test]
async fn never_authenticated_install_logout_is_local_and_does_not_block_first_login() {
    let state = Arc::new(Panel::default());
    let (api, server) = panel(state.clone()).await;
    let store = auth_store();
    let mut fresh = store.load().unwrap().unwrap();
    fresh.access_token = None;
    fresh.refresh_token = None;
    fresh.confirmed_identity = None;
    fresh.session_generation = None;
    store.save(&fresh).unwrap();
    let broker = AuthBroker::new(api, store, Arc::new(Stop::default())).unwrap();
    broker.logout().await.unwrap();
    assert_eq!(
        broker.auth_state().await.unwrap(),
        BrokerAuthState::LoggedOut
    );
    assert_eq!(state.logout_calls.load(Ordering::SeqCst), 0);
    broker
        .login(
            &login_request(),
            &RuntimeTarget::from_identity(&identity(8)),
        )
        .await
        .unwrap();
    server.abort();
}

#[tokio::test]
async fn controlled_account_change_accepts_new_device_generation_one() {
    let state = Arc::new(Panel::default());
    let mut reply_a = response(7, "account-a-access");
    reply_a["device"]["id"] = json!("device-a");
    *state.login_reply.lock().unwrap() = Some(reply_a);
    let (api, server) = panel(state.clone()).await;
    let store = auth_store();
    let mut previous = store.load().unwrap().unwrap();
    previous.confirmed_identity = Some(identity(6));
    previous.session_generation = Some(6);
    store.save(&previous).unwrap();
    let broker = AuthBroker::new(api, store.clone(), Arc::new(Stop::default())).unwrap();
    broker.logout().await.unwrap();
    let original = broker
        .login(
            &login_request(),
            &RuntimeTarget::from_identity(&identity(7)),
        )
        .await
        .unwrap();
    assert_eq!(original.identity().session_generation, Some(7));
    broker.logout().await.unwrap();
    let mut reply_b = response(1, "account-b-access");
    reply_b["device"]["id"] = json!("device-b");
    *state.login_reply.lock().unwrap() = Some(reply_b);
    let mut request = login_request();
    request.login = "account-b".into();
    let next = broker
        .login(&request, &RuntimeTarget::from_identity(&identity(1)))
        .await
        .unwrap();
    assert_eq!(next.identity().session_generation, Some(1));
    assert_ne!(next.family(), original.family());
    assert_eq!(
        store.load().unwrap().unwrap().install_secret,
        "synthetic-install"
    );
    server.abort();
}

#[tokio::test]
async fn rejected_cancelled_login_retains_received_proof_across_owner_restart_and_exact_retry() {
    let state = Arc::new(Panel::default());
    state.hold_login.store(true, Ordering::SeqCst);
    let mut invalid = response(8, "must-never-issue");
    invalid["device"]["runtime_slot"] = json!("stable");
    *state.login_reply.lock().unwrap() = Some(invalid);
    let (api, server) = panel(state.clone()).await;
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(ProtectedAuthStore::new(FileRecord(
        root.path().join("record"),
    )));
    store.save(&auth_store().load().unwrap().unwrap()).unwrap();
    let broker =
        Arc::new(AuthBroker::new(api.clone(), store.clone(), Arc::new(Stop::default())).unwrap());
    broker.logout().await.unwrap();
    let request = {
        let broker = broker.clone();
        tokio::spawn(async move {
            broker
                .login(
                    &login_request(),
                    &RuntimeTarget::from_identity(&identity(8)),
                )
                .await
        })
    };
    state.login_entered.notified().await;
    assert!(broker.logout().await.is_err());
    state.lose_logout.store(true, Ordering::SeqCst);
    state.login_release.notify_one();
    assert!(request.await.unwrap().is_err());
    let pending = store.load().unwrap().unwrap();
    assert_eq!(pending.logout_state, LogoutState::Pending);
    assert!(pending.access_token.is_none());
    let proof = pending
        .broker
        .unwrap()
        .pending_logout
        .expect("received rejected proof must remain durable");
    assert_eq!(proof.refresh_proof, "successor-refresh");
    assert_eq!(state.logout_requests.lock().unwrap().len(), 2);
    drop(broker);
    let reopened = AuthBroker::new(api, store.clone(), Arc::new(Stop::default())).unwrap();
    assert!(reopened.access_token(None).await.is_err());
    reopened.logout().await.unwrap();
    {
        let requests = state.logout_requests.lock().unwrap();
        assert_eq!(requests[1], requests[2]);
    }
    assert_eq!(
        store.load().unwrap().unwrap().logout_state,
        LogoutState::LoggedOut
    );
    state.hold_login.store(false, Ordering::SeqCst);
    *state.login_reply.lock().unwrap() = None;
    let next = reopened
        .login(
            &login_request(),
            &RuntimeTarget::from_identity(&identity(8)),
        )
        .await
        .unwrap();
    assert_eq!(reopened.access_token(None).await.unwrap(), next);
    server.abort();
}

#[tokio::test]
async fn pre_http_stop_failure_and_definitive_rejection_allow_corrected_username() {
    for rejection in [
        None,
        Some((401, "invalid_credentials")),
        Some((403, "app_access_unavailable")),
        Some((429, "login_rate_limited")),
        Some((422, "invalid_request")),
    ] {
        let local_failure = rejection.is_none();
        let state = Arc::new(Panel::default());
        *state.login_rejection.lock().unwrap() =
            rejection.map(|(status, code)| (status, code.into()));
        let (api, server) = panel(state.clone()).await;
        let store = auth_store();
        let mut initial = store.load().unwrap().unwrap();
        initial.logout_state = LogoutState::LoggedOut;
        initial.access_token = None;
        initial.refresh_token = None;
        store.save(&initial).unwrap();
        let stop: Arc<dyn LocalAuthStop> = if local_failure {
            Arc::new(FirstStopFails(AtomicUsize::new(0)))
        } else {
            Arc::new(Stop::default())
        };
        let broker = AuthBroker::new(api, store.clone(), stop).unwrap();
        assert!(broker
            .login(
                &login_request(),
                &RuntimeTarget::from_identity(&identity(8))
            )
            .await
            .is_err());
        assert_eq!(
            broker.auth_state().await.unwrap(),
            BrokerAuthState::LoggedOut
        );
        assert!(store
            .load()
            .unwrap()
            .unwrap()
            .broker
            .unwrap()
            .pending_login_account
            .is_none());
        assert_eq!(
            state.login_requests.lock().unwrap().len(),
            usize::from(!local_failure)
        );
        let mut corrected = login_request();
        corrected.login = "corrected-user".into();
        broker
            .login(&corrected, &RuntimeTarget::from_identity(&identity(8)))
            .await
            .unwrap();
        server.abort();
    }
}

#[tokio::test]
async fn same_server_device_not_login_spelling_controls_generation_monotonicity() {
    let state = Arc::new(Panel::default());
    let (api, server) = panel(state.clone()).await;
    let store = auth_store();
    let broker = AuthBroker::new(api, store.clone(), Arc::new(Stop::default())).unwrap();
    broker.logout().await.unwrap();
    broker
        .login(
            &login_request(),
            &RuntimeTarget::from_identity(&identity(8)),
        )
        .await
        .unwrap();
    broker.logout().await.unwrap();
    *state.login_reply.lock().unwrap() = Some(response(7, "regressed-access"));
    let mut spelling = login_request();
    spelling.login = "SYNTHETIC-USER".into();
    assert!(broker
        .login(&spelling, &RuntimeTarget::from_identity(&identity(7)))
        .await
        .is_err());
    assert!(store.load().unwrap().unwrap().access_token.is_none());
    assert_eq!(state.logout_calls.load(Ordering::SeqCst), 3); // Includes rejected-family compensation.
    server.abort();
}

#[tokio::test]
async fn definitive_rejection_does_not_erase_earlier_unknown_login_outcome() {
    let state = Arc::new(Panel::default());
    state.fail_login.store(true, Ordering::SeqCst);
    let (api, server) = panel(state.clone()).await;
    let broker = AuthBroker::new(api, auth_store(), Arc::new(Stop::default())).unwrap();
    broker.logout().await.unwrap();
    assert!(broker
        .login(
            &login_request(),
            &RuntimeTarget::from_identity(&identity(8))
        )
        .await
        .is_err());
    *state.login_rejection.lock().unwrap() = Some((401, "invalid_credentials".into()));
    assert!(broker
        .login(
            &login_request(),
            &RuntimeTarget::from_identity(&identity(8))
        )
        .await
        .is_err());
    assert_eq!(
        broker.auth_state().await.unwrap(),
        BrokerAuthState::AuthenticationOutcomeUnknown
    );
    let mut other = login_request();
    other.login = "other-account".into();
    assert!(broker
        .login(&other, &RuntimeTarget::from_identity(&identity(8)))
        .await
        .is_err());
    assert_eq!(state.login_requests.lock().unwrap().len(), 2);
    server.abort();
}

#[tokio::test]
async fn definitive_rejection_after_logout_does_not_clear_cancelled_ticket_or_epoch() {
    let state = Arc::new(Panel::default());
    state.hold_login.store(true, Ordering::SeqCst);
    *state.login_rejection.lock().unwrap() = Some((401, "invalid_credentials".into()));
    let (api, server) = panel(state.clone()).await;
    let store = auth_store();
    let broker = Arc::new(AuthBroker::new(api, store.clone(), Arc::new(Stop::default())).unwrap());
    broker.logout().await.unwrap();
    let task = {
        let broker = broker.clone();
        tokio::spawn(async move {
            broker
                .login(
                    &login_request(),
                    &RuntimeTarget::from_identity(&identity(8)),
                )
                .await
        })
    };
    state.login_entered.notified().await;
    assert!(broker.logout().await.is_err());
    let cancelled = store.load().unwrap().unwrap();
    state.login_release.notify_one();
    assert!(task.await.unwrap().is_err());
    assert_eq!(store.load().unwrap().unwrap(), cancelled);
    server.abort();
}

struct FileRecord(std::path::PathBuf);
impl ProtectedRecordStore for FileRecord {
    fn load_record(&self) -> Result<Option<Vec<u8>>, StorageError> {
        match std::fs::read(&self.0) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    fn save_record(&self, bytes: &[u8]) -> Result<(), StorageError> {
        use std::io::Write;
        let parent = self.0.parent().unwrap();
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        file.write_all(bytes)?;
        file.as_file().sync_all()?;
        file.persist(&self.0).map_err(|e| e.error)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    }
    fn delete_record(&self) -> Result<(), StorageError> {
        std::fs::remove_file(&self.0)?;
        Ok(())
    }
}
fn resume_args() -> ResumeArguments {
    ResumeArguments {
        operation_id: "11111111-1111-4111-8111-111111111111".into(),
        reconcile_operation_id: "22222222-2222-4222-8222-222222222222".into(),
        decision: "apply".into(),
        target: RuntimeTarget::from_identity(&identity(8)),
        expected_session_generation: Some(7),
    }
}

#[tokio::test]
async fn resume_child_process() {
    let Ok(path) = std::env::var("NELOMAI_BROKER_TEST_RECORD") else {
        return;
    };
    // Only this test's parent passes its fresh private directory; no keychain.
    let store = Arc::new(ProtectedAuthStore::new(FileRecord(path.into())));
    let api = ClientApi::new(&std::env::var("NELOMAI_BROKER_TEST_URL").unwrap()).unwrap();
    let broker = AuthBroker::new(api, store, Arc::new(Stop::default())).unwrap();
    let result = broker.resume(resume_args()).await;
    if std::env::var("NELOMAI_BROKER_TEST_LOST_REPLY").unwrap() == "1" {
        assert!(matches!(result, Err(BrokerError::Api(_))));
    } else {
        assert_eq!(result.unwrap().identity(), &identity(8));
    }
}

#[test]
fn process_exit_after_lost_committed_resume_reply_replays_same_operation_from_protected_file() {
    use std::io::{Read, Write};
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("auth-record");
    let store = ProtectedAuthStore::new(FileRecord(path.clone()));
    store.save(&auth_store().load().unwrap().unwrap()).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let mut requests = Vec::new();
        for attempt in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut bytes = Vec::new();
            loop {
                let mut chunk = [0; 4096];
                let n = stream.read(&mut chunk).unwrap();
                assert_ne!(n, 0);
                bytes.extend_from_slice(&chunk[..n]);
                if let Some(end) = bytes.windows(4).position(|b| b == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&bytes[..end]).to_lowercase();
                    let len = headers
                        .lines()
                        .find_map(|s| s.strip_prefix("content-length: "))
                        .unwrap()
                        .parse::<usize>()
                        .unwrap();
                    if bytes.len() >= end + 4 + len {
                        requests.push(serde_json::from_slice::<Value>(&bytes[end + 4..]).unwrap());
                        break;
                    }
                }
            }
            // Fake panel commits once, then drops the response connection. It
            // returns the same committed generation on exact current replay.
            if attempt == 0 {
                continue;
            }
            let body = json!({"identity":{"container_version":"0.2.16","runtime_version":"0.2.16","runtime_contract_version":1,
                "runtime_slot":"latest","session_generation":8},"access_token":"resumed-access","token_type":"Bearer","access_expires_in":900}).to_string();
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        }
        requests
    });
    for lost in ["1", "0"] {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "resume_child_process", "--nocapture"])
            .env("NELOMAI_BROKER_TEST_RECORD", &path)
            .env("NELOMAI_BROKER_TEST_URL", &url)
            .env("NELOMAI_BROKER_TEST_LOST_REPLY", lost)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "child failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let saved = store.load().unwrap().unwrap();
        if lost == "1" {
            assert_eq!(saved.session_generation, Some(7));
            assert_eq!(
                saved.broker.unwrap().pending_request.unwrap().operation_id,
                "11111111-1111-4111-8111-111111111111"
            );
        } else {
            assert_eq!(saved.session_generation, Some(8));
        }
    }
    let requests = server.join().unwrap();
    assert_eq!(requests[0], requests[1]);
    assert_eq!(
        store.load().unwrap().unwrap().access_token.as_deref(),
        Some("resumed-access")
    );
}
