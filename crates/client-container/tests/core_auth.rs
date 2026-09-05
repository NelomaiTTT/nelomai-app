//! Actual Application → Core → owner broker → isolated HTTP. No legacy auth
//! fixture adapter or user keychain is involved in this integration boundary.
use async_trait::async_trait;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post, put},
    Json, Router,
};
use nelomai_client_api::{ClientApi, RuntimeTarget};
use nelomai_client_application::ClientApplication;
use nelomai_client_container::{
    AuthBroker, OwnerRuntimeAuth, RuntimeCacheAdmission, RuntimeClientProfile,
};
use nelomai_client_core::{
    CoreApi, CoreError, CoreLocalStop, NoopLogger, Phase, RuntimeAuthProvider,
};
use nelomai_client_storage::*;
use nelomai_client_tunnel::{
    TunnelCapabilities, TunnelController, TunnelError, TunnelPlatform, TunnelStartRequest,
    TunnelStatus,
};
use nelomai_contracts::{
    ConnectionOperationRequest, EgressMode, Layer, Platform, RouteMode, RuntimeIdentity,
    RuntimeSlot, SplitTunnelMode, SplitTunnelPolicy, SplitTunnelSettingsUpdate, TicConnectionMode,
};
use serde_json::{json, Value};
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
        *self.0.lock().unwrap() = Some(bytes.into());
        Ok(())
    }
    fn delete_record(&self) -> Result<(), StorageError> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}
#[derive(Default)]
struct Tunnel {
    running: AtomicBool,
    hold_start: AtomicBool,
    fail_stop: AtomicBool,
    entered: Notify,
    release: Notify,
    hold_status: AtomicBool,
    status_entered: Notify,
    status_release: Notify,
    starts: AtomicUsize,
    hold_start_at: AtomicUsize,
    fail_start_at: AtomicUsize,
    hold_next_stop: AtomicBool,
    stop_entered: Notify,
    stop_release: Notify,
}
#[async_trait]
impl TunnelController for Tunnel {
    async fn start(&self, _: TunnelStartRequest) -> Result<(), TunnelError> {
        let call = self.starts.fetch_add(1, Ordering::SeqCst) + 1;
        self.entered.notify_one();
        if self.hold_start.load(Ordering::SeqCst)
            || self.hold_start_at.load(Ordering::SeqCst) == call
        {
            self.release.notified().await;
        }
        self.running.store(true, Ordering::SeqCst);
        if self.fail_start_at.load(Ordering::SeqCst) == call {
            return Err(TunnelError::Backend(
                "synthetic-start-failed-after-dispatch".into(),
            ));
        }
        Ok(())
    }
    async fn stop(&self) -> Result<(), TunnelError> {
        if self.hold_next_stop.swap(false, Ordering::SeqCst) {
            self.stop_entered.notify_one();
            self.stop_release.notified().await;
        }
        if self.fail_stop.load(Ordering::SeqCst) {
            return Err(TunnelError::Backend("synthetic-stop-failed".into()));
        }
        self.running.store(false, Ordering::SeqCst);
        Ok(())
    }
    async fn status(&self) -> Result<TunnelStatus, TunnelError> {
        let captured = if self.running.load(Ordering::SeqCst) {
            TunnelStatus::Running
        } else {
            TunnelStatus::Stopped
        };
        if self.hold_status.load(Ordering::SeqCst) {
            self.status_entered.notify_one();
            self.status_release.notified().await;
        }
        Ok(captured)
    }
    async fn capabilities(&self) -> Result<TunnelCapabilities, TunnelError> {
        Ok(TunnelCapabilities {
            platform: TunnelPlatform::Windows,
            android_api_level: None,
            address_split_tunnel: true,
            application_split_tunnel: false,
        })
    }
}
#[derive(Default)]
struct Panel {
    proofs: Mutex<Vec<Value>>,
    bearer: Mutex<Vec<HeaderMap>>,
}
async fn logout(State(panel): State<Arc<Panel>>, Json(body): Json<Value>) -> Json<Value> {
    panel.proofs.lock().unwrap().push(body);
    Json(
        json!({"code":"session_revoked_cleanup_accepted","cleanup_reconcile_operation_id":"11111111-1111-4111-8111-111111111111"}),
    )
}
async fn bearer(State(panel): State<Arc<Panel>>, headers: HeaderMap) -> (StatusCode, Json<Value>) {
    panel.bearer.lock().unwrap().push(headers);
    (
        StatusCode::CONFLICT,
        Json(
            json!({"request_id":"synthetic", "code":"connection_active", "message":"synthetic refusal"}),
        ),
    )
}

#[tokio::test]
async fn actual_application_logout_bypasses_pending_start_and_preserves_exact_runtime_cleanup() {
    exercise_logout(false, false).await;
}

#[tokio::test]
async fn actual_owner_stop_failure_never_reports_physical_stop_and_late_poll_cannot_revive_auth() {
    exercise_logout(true, false).await;
}

#[tokio::test]
async fn actual_new_login_cannot_reuse_old_offline_cache_with_no_bootstrap_connection() {
    exercise_logout(false, true).await;
}

async fn exercise_logout(fail_stop: bool, new_login: bool) {
    let panel = Arc::new(Panel::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api =
        Arc::new(ClientApi::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap());
    let router = Router::new()
        .route("/api/client/v1/auth/logout-runtime", post(logout))
        .route("/api/client/v1/connections/pin-stray", post(bearer))
        .route("/api/client/v1/auth/login", post(|| async { Json(json!({"api_version":"1","request_id":"synthetic","token_type":"Bearer","access_token":"b-access","access_expires_in":900,"refresh_token":"b-refresh","refresh_expires_in":3600,"access":{"state":"active","can_login":true,"can_connect":true,"expires_at":null},"device":{"id":"device-b","name":"synthetic","platform":"macos","container_version":"0.2.16","runtime_version":"0.2.16","runtime_contract_version":1,"runtime_slot":"stable","session_generation":1}})) }))
        .route("/api/client/v1/bootstrap", get(|| async {
            let mut value: Value = serde_json::from_str(include_str!("../../../contracts/fixtures/valid/bootstrap.json")).unwrap();
            value["connection"] = Value::Null;
            Json(value)
        }))
        .with_state(panel.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let root = tempfile::tempdir().unwrap();
    let paths = RuntimePaths::new(root.path(), RuntimeSlot::Stable, "0.2.16").unwrap();
    let identity = RuntimeIdentity {
        slot: RuntimeSlot::Stable,
        runtime_version: "0.2.16".into(),
        container_version: "0.2.16".into(),
        runtime_contract_version: 1,
        session_generation: Some(7),
    };
    let mut legacy = StoredAuth::new_install();
    legacy.install_secret = "synthetic-install".into();
    legacy.access_token = Some("synthetic-access".into());
    legacy.refresh_token = Some("synthetic-refresh".into());
    legacy.saved_connection = Some(StoredConnection {
        lease_id: "synthetic-lease".into(),
        pool_id: None,
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        egress_mode: EgressMode::Ipv4,
        probe_url: None,
        kind: StoredConnectionKind::DynamicWarm,
        configuration: "[Interface]\nPrivateKey = synthetic".into(),
        valid_until_unix: Some(2000),
    });
    let auth = Arc::new(ProtectedAuthStore::new(Record::default()));
    let mut auth_value = AuthStoreV1::from_legacy(&legacy);
    auth_value.confirmed_identity = Some(identity.clone());
    auth_value.session_generation = Some(7);
    auth.save(&auth_value).unwrap();
    let tunnel = Arc::new(Tunnel::default());
    tunnel.hold_start.store(true, Ordering::SeqCst);
    tunnel.fail_stop.store(fail_stop, Ordering::SeqCst);
    let local = CoreLocalStop::new(tunnel.clone());
    let broker =
        Arc::new(AuthBroker::new(api.as_ref().clone(), auth.clone(), local.clone()).unwrap());
    let mut enrolled = auth.load().unwrap().unwrap();
    enrolled.broker.as_mut().unwrap().confirmed_device_id = Some("device-a".into());
    auth.save(&enrolled).unwrap();
    let access = broker.observe().await.unwrap().access.unwrap();
    let runtime = ProtectedRuntimeStore::new(Record::default(), paths);
    let mut runtime_value =
        RuntimeStateV1::import_legacy(&legacy, StoredSplitTunnelState::default(), runtime.paths());
    runtime_value.cleanup_only = false;
    runtime_value.auth_scope = Some(RuntimeAuthScope {
        auth_epoch: access.auth_epoch(),
        family: access.family().into(),
        identity: access.identity().clone(),
    });
    runtime.save(&runtime_value).unwrap();
    let owner = RuntimeRecordOwner::new(runtime);
    let operational = Arc::new(owner.operational());
    let split = Arc::new(owner.split());
    let port = Arc::new(
        OwnerRuntimeAuth::new(
            broker,
            RuntimeTarget::from_identity(&identity),
            RuntimeClientProfile {
                platform: Platform::Macos,
                platform_version: None,
                architecture: "aarch64".into(),
            },
            Arc::new(RuntimeCacheAdmission::new(owner.clone())),
            local.runtime_writer_gates(),
        )
        .unwrap(),
    );
    let application = Arc::new(ClientApplication::with_split_tunnel_store(
        api.clone(),
        operational.clone(),
        split,
        port.clone(),
        local,
        Arc::new(NoopLogger),
    ));
    let access = application.current_access_token().await.unwrap();
    assert!(CoreApi::pin_stray(
        api.as_ref(),
        &access,
        &ConnectionOperationRequest {
            operation_id: "synthetic-op".into(),
            lease_id: "synthetic-lease".into(),
            failure_code: None
        }
    )
    .await
    .is_err());
    {
        let headers = panel.bearer.lock().unwrap();
        assert_eq!(headers.len(), 1);
        for (name, value) in [
            ("authorization", "Bearer synthetic-access"),
            ("x-nelomai-app-version", "0.2.16"),
            ("x-nelomai-container-version", "0.2.16"),
            ("x-nelomai-runtime-version", "0.2.16"),
            ("x-nelomai-runtime-contract-version", "1"),
            ("x-nelomai-runtime-slot", "stable"),
            ("x-nelomai-session-generation", "7"),
        ] {
            assert_eq!(
                headers[0].get(name).unwrap().to_str().unwrap(),
                value,
                "{name}"
            );
        }
    }
    let starter = application.clone();
    let start = tokio::spawn(async move { starter.start_saved_stray_offline(1000).await });
    tokio::time::timeout(Duration::from_secs(2), tunnel.entered.notified())
        .await
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), application.logout())
        .await
        .expect("logout must bypass lifecycle gate");
    assert_eq!(result.is_err(), fail_stop);
    assert_eq!(
        auth.load().unwrap().unwrap().logout_state,
        LogoutState::LoggedOut
    );
    assert!(port.access(None).await.is_err());
    tunnel.release.notify_one();
    let result = start.await.unwrap();
    if fail_stop {
        assert!(matches!(
            result,
            Err(nelomai_client_application::ApplicationError::Core(
                CoreError::Tunnel(_)
            ))
        ));
        assert_eq!(
            application.reconcile_external_tunnel_state().await.phase,
            Phase::Error
        );
        assert_eq!(tunnel.status().await.unwrap(), TunnelStatus::Running);
        let before_cleanup = owner.cleanup_snapshot().unwrap();
        assert!(
            port.recover_logout_cleanup().await.is_err(),
            "failed stop must keep logout cleanup pending"
        );
        assert_eq!(owner.cleanup_snapshot().unwrap(), before_cleanup);
        assert!(auth
            .load()
            .unwrap()
            .unwrap()
            .completed_runtime_logout
            .is_some());
        tunnel.hold_status.store(true, Ordering::SeqCst);
        let poll_application = application.clone();
        let poll =
            tokio::spawn(async move { poll_application.reconcile_external_tunnel_state().await });
        tokio::time::timeout(Duration::from_secs(2), tunnel.status_entered.notified())
            .await
            .unwrap();
        tunnel.fail_stop.store(false, Ordering::SeqCst);
        application.logout().await.unwrap();
        tunnel.hold_status.store(false, Ordering::SeqCst);
        tunnel.status_release.notify_one();
        assert_eq!(poll.await.unwrap().phase, Phase::SignedOut);
    } else {
        assert!(matches!(
            result,
            Err(nelomai_client_application::ApplicationError::Core(
                CoreError::StartCancelled
            ))
        ));
    }
    assert_eq!(
        application.reconcile_external_tunnel_state().await.phase,
        Phase::SignedOut
    );
    assert_eq!(tunnel.status().await.unwrap(), TunnelStatus::Stopped);
    for _ in 0..20 {
        if operational
            .load()
            .unwrap()
            .as_ref()
            .is_some_and(|state| state.saved_connection.is_none())
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(operational.load().unwrap().unwrap().saved_connection, None);
    assert_eq!(
        panel.proofs.lock().unwrap()[0]["refresh_token"],
        "synthetic-refresh"
    );
    assert_eq!(panel.proofs.lock().unwrap().len(), 1);
    assert!(!root
        .path()
        .join("runtime/stable/state/0.2.16/state-v1.json")
        .exists());
    if new_login {
        tunnel.hold_start.store(false, Ordering::SeqCst);
        let starts = tunnel.starts.load(Ordering::SeqCst);
        application
            .login(
                nelomai_client_application::LoginParameters {
                    login: "b".into(),
                    password: "synthetic-password".into(),
                    device_name: "synthetic".into(),
                },
                1100,
            )
            .await
            .unwrap();
        assert_eq!(
            auth.load().unwrap().unwrap().access_token.as_deref(),
            Some("b-access")
        );
        assert_eq!(
            port.state().await.unwrap(),
            nelomai_client_api::RuntimeAuthState::Active
        );
        application.bootstrap(1100).await.unwrap();
        assert!(application.start_saved_stray_offline(1100).await.is_err());
        assert_eq!(tunnel.starts.load(Ordering::SeqCst), starts);
        assert!(operational
            .load()
            .unwrap()
            .unwrap()
            .saved_connection
            .is_none());
    }
    server.abort();
}

fn changed_policy() -> SplitTunnelPolicy {
    SplitTunnelPolicy {
        format_version: 1,
        enabled: true,
        revision: 8,
        force_revision: 0,
        address_revision: 0,
        policy_hash: format!("sha256:{}", "b".repeat(64)),
        mode: SplitTunnelMode::ExcludeSelected,
        exclude_local_networks: true,
        mandatory_excluded_packages: vec![],
        suggested_name_fragments: vec![],
        selected_packages: vec![],
        excluded_ipv4_cidrs: vec!["203.0.113.0/24".into()],
        address_rules: vec![],
        generated_at: "2026-09-05T12:00:00Z".into(),
    }
}

#[tokio::test]
async fn actual_owner_logout_fences_split_stop() {
    exercise_split_logout(0, false).await;
}
#[tokio::test]
async fn actual_owner_logout_compensates_late_split_start() {
    exercise_split_logout(2, false).await;
}
#[tokio::test]
async fn actual_owner_logout_prevents_failed_forward_rollback() {
    exercise_split_logout(2, true).await;
}
#[tokio::test]
async fn actual_owner_logout_compensates_dispatched_split_rollback() {
    exercise_split_logout(3, true).await;
}

async fn exercise_split_logout(held_start: usize, fail_forward: bool) {
    let panel = Arc::new(Panel::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api =
        Arc::new(ClientApi::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap());
    let router = Router::new()
        .route("/api/client/v1/auth/logout-runtime", post(logout))
        .route(
            "/api/client/v1/split-tunnel/settings",
            put(|| async { Json(changed_policy()) }),
        )
        .with_state(panel.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let root = tempfile::tempdir().unwrap();
    let paths = RuntimePaths::new(root.path(), RuntimeSlot::Stable, "0.2.16").unwrap();
    let identity = RuntimeIdentity {
        slot: RuntimeSlot::Stable,
        runtime_version: "0.2.16".into(),
        container_version: "0.2.16".into(),
        runtime_contract_version: 1,
        session_generation: Some(7),
    };
    let mut legacy = StoredAuth::new_install();
    legacy.install_secret = "synthetic-install".into();
    legacy.access_token = Some("synthetic-access".into());
    legacy.refresh_token = Some("synthetic-refresh".into());
    legacy.saved_connection = Some(StoredConnection {
        lease_id: "synthetic-lease".into(),
        pool_id: None,
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        egress_mode: EgressMode::Ipv4,
        probe_url: None,
        kind: StoredConnectionKind::DynamicWarm,
        configuration: "[Interface]\nPrivateKey = synthetic".into(),
        valid_until_unix: Some(2000),
    });
    let auth = Arc::new(ProtectedAuthStore::new(Record::default()));
    let mut auth_value = AuthStoreV1::from_legacy(&legacy);
    auth_value.confirmed_identity = Some(identity.clone());
    auth_value.session_generation = Some(7);
    auth.save(&auth_value).unwrap();
    let tunnel = Arc::new(Tunnel::default());
    let local = CoreLocalStop::new(tunnel.clone());
    let broker =
        Arc::new(AuthBroker::new(api.as_ref().clone(), auth.clone(), local.clone()).unwrap());
    let access = broker.observe().await.unwrap().access.unwrap();
    let runtime = ProtectedRuntimeStore::new(Record::default(), paths);
    let mut runtime_value =
        RuntimeStateV1::import_legacy(&legacy, StoredSplitTunnelState::default(), runtime.paths());
    runtime_value.cleanup_only = false;
    runtime_value.auth_scope = Some(RuntimeAuthScope {
        auth_epoch: access.auth_epoch(),
        family: access.family().into(),
        identity: access.identity().clone(),
    });
    runtime.save(&runtime_value).unwrap();
    let owner = RuntimeRecordOwner::new(runtime);
    let operational = Arc::new(owner.operational());
    let port = Arc::new(
        OwnerRuntimeAuth::new(
            broker,
            RuntimeTarget::from_identity(&identity),
            RuntimeClientProfile {
                platform: Platform::Macos,
                platform_version: None,
                architecture: "aarch64".into(),
            },
            Arc::new(RuntimeCacheAdmission::new(owner.clone())),
            local.runtime_writer_gates(),
        )
        .unwrap(),
    );
    let application = Arc::new(ClientApplication::with_split_tunnel_store(
        api,
        operational.clone(),
        Arc::new(owner.split()),
        port.clone(),
        local,
        Arc::new(NoopLogger),
    ));
    application.start_saved_stray_offline(1000).await.unwrap();
    // Consume the notification from the initial start; all later waits are exact callbacks.
    tunnel.entered.notified().await;
    tunnel
        .hold_next_stop
        .store(held_start == 0, Ordering::SeqCst);
    tunnel.hold_start_at.store(held_start, Ordering::SeqCst);
    tunnel
        .fail_start_at
        .store(if fail_forward { 2 } else { 0 }, Ordering::SeqCst);
    let worker = application.clone();
    let pending = tokio::spawn(async move {
        worker
            .save_split_tunnel_settings(
                &SplitTunnelSettingsUpdate {
                    mode: SplitTunnelMode::ExcludeSelected,
                    exclude_local_networks: true,
                    selected_packages: vec![],
                },
                1100,
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        if held_start == 0 {
            tunnel.stop_entered.notified().await;
        } else {
            while tunnel.starts.load(Ordering::SeqCst) < held_start {
                tunnel.entered.notified().await;
            }
        }
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(2), application.logout())
        .await
        .expect("owner logout must not queue behind policy callback")
        .unwrap();
    assert_eq!(
        auth.load().unwrap().unwrap().logout_state,
        LogoutState::LoggedOut
    );
    assert!(port.access(None).await.is_err());
    tunnel.stop_release.notify_one();
    tunnel.release.notify_one();
    let result = tokio::time::timeout(Duration::from_secs(2), pending)
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(
            result,
            Err(nelomai_client_application::ApplicationError::Core(
                CoreError::StartCancelled
            ))
        ),
        "{result:?}"
    );
    assert_eq!(
        tunnel.starts.load(Ordering::SeqCst),
        held_start.max(1),
        "no new start may dispatch after logout"
    );
    assert_eq!(tunnel.status().await.unwrap(), TunnelStatus::Stopped);
    assert_eq!(
        application.reconcile_external_tunnel_state().await.phase,
        Phase::SignedOut
    );
    assert_eq!(
        operational.load().unwrap().unwrap().saved_connection,
        legacy.saved_connection
    );
    assert_eq!(panel.proofs.lock().unwrap().len(), 1);
    server.abort();
}
