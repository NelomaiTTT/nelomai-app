//! Actual Application → Core → owner broker → isolated HTTP. No legacy auth
//! fixture adapter or user keychain is involved in this integration boundary.
use async_trait::async_trait;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use nelomai_client_api::{ClientApi, RuntimeTarget};
use nelomai_client_application::ClientApplication;
use nelomai_client_container::{AuthBroker, OwnerRuntimeAuth, RuntimeClientProfile};
use nelomai_client_core::{
    CoreApi, CoreError, CoreLocalStop, NoopLogger, Phase, RuntimeAuthProvider,
};
use nelomai_client_storage::*;
use nelomai_client_tunnel::{TunnelController, TunnelError, TunnelStartRequest, TunnelStatus};
use nelomai_contracts::{
    ConnectionOperationRequest, EgressMode, Layer, Platform, RouteMode, RuntimeIdentity,
    RuntimeSlot, TicConnectionMode,
};
use serde_json::{json, Value};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
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
}
#[async_trait]
impl TunnelController for Tunnel {
    async fn start(&self, _: TunnelStartRequest) -> Result<(), TunnelError> {
        self.entered.notify_one();
        if self.hold_start.load(Ordering::SeqCst) {
            self.release.notified().await;
        }
        self.running.store(true, Ordering::SeqCst);
        Ok(())
    }
    async fn stop(&self) -> Result<(), TunnelError> {
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
}
#[derive(Default)]
struct Panel {
    proofs: Mutex<Vec<Value>>,
    bearer: Mutex<Vec<HeaderMap>>,
}
async fn logout(State(panel): State<Arc<Panel>>, Json(body): Json<Value>) -> Json<Value> {
    panel.proofs.lock().unwrap().push(body);
    Json(
        json!({"code":"session_revoked_cleanup_accepted","cleanup_reconcile_operation_id":"synthetic-cleanup"}),
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
    exercise_logout(false).await;
}

#[tokio::test]
async fn actual_owner_stop_failure_never_reports_physical_stop_and_late_poll_cannot_revive_auth() {
    exercise_logout(true).await;
}

async fn exercise_logout(fail_stop: bool) {
    let panel = Arc::new(Panel::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api =
        Arc::new(ClientApi::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap());
    let router = Router::new()
        .route("/api/client/v1/auth/logout-runtime", post(logout))
        .route("/api/client/v1/connections/pin-stray", post(bearer))
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
    let runtime = ProtectedRuntimeStore::new(Record::default(), paths);
    let mut runtime_value =
        RuntimeStateV1::import_legacy(&legacy, StoredSplitTunnelState::default(), runtime.paths());
    runtime_value.cleanup_only = false;
    runtime.save(&runtime_value).unwrap();
    let owner = RuntimeRecordOwner::new(runtime);
    let operational = Arc::new(owner.operational());
    let split = Arc::new(owner.split());
    let tunnel = Arc::new(Tunnel::default());
    tunnel.hold_start.store(true, Ordering::SeqCst);
    tunnel.fail_stop.store(fail_stop, Ordering::SeqCst);
    let local = CoreLocalStop::new(tunnel.clone());
    let broker =
        Arc::new(AuthBroker::new(api.as_ref().clone(), auth.clone(), local.clone()).unwrap());
    let port = Arc::new(
        OwnerRuntimeAuth::new(
            broker,
            RuntimeTarget::from_identity(&identity),
            RuntimeClientProfile {
                platform: Platform::Macos,
                platform_version: None,
                architecture: "aarch64".into(),
            },
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
    assert_eq!(
        operational.load().unwrap().unwrap().saved_connection,
        legacy.saved_connection
    );
    assert_eq!(
        panel.proofs.lock().unwrap()[0]["refresh_token"],
        "synthetic-refresh"
    );
    assert_eq!(panel.proofs.lock().unwrap().len(), 1);
    assert!(!root
        .path()
        .join("runtime/stable/state/0.2.16/state-v1.json")
        .exists());
    server.abort();
}
