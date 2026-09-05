//! Real broker/admission with synthetic protected records and isolated HTTP.
use async_trait::async_trait;
use axum::{routing::post, Json, Router};
use nelomai_client_api::{ClientApi, RuntimeAuthState, RuntimeLogin, RuntimeTarget};
use nelomai_client_container::{
    AuthBroker, OwnerRuntimeAuth, RuntimeCacheAdmission, RuntimeClientProfile,
};
use nelomai_client_core::{CoreLocalStop, RuntimeAuthProvider};
use nelomai_client_storage::*;
use nelomai_client_tunnel::{TunnelController, TunnelError, TunnelStartRequest, TunnelStatus};
use nelomai_contracts::{Platform, RuntimeIdentity, RuntimeSlot};
use serde_json::json;
use std::sync::{Arc, Mutex};

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
struct Tunnel;
#[async_trait]
impl TunnelController for Tunnel {
    async fn start(&self, _: TunnelStartRequest) -> Result<(), TunnelError> {
        Ok(())
    }
    async fn stop(&self) -> Result<(), TunnelError> {
        Ok(())
    }
    async fn status(&self) -> Result<TunnelStatus, TunnelError> {
        Ok(TunnelStatus::Stopped)
    }
}

#[tokio::test(start_paused = true)]
async fn held_runtime_writer_times_out_before_auth_issuance_without_changing_owner() {
    let root = tempfile::tempdir().unwrap();
    let paths = RuntimePaths::new(root.path(), RuntimeSlot::Stable, "0.2.16").unwrap();
    let legacy = StoredAuth::new_install();
    let auth = Arc::new(ProtectedAuthStore::new(Record::default()));
    auth.save(&AuthStoreV1::from_legacy(&legacy)).unwrap();
    let local = CoreLocalStop::new(Arc::new(Tunnel));
    let broker = Arc::new(
        AuthBroker::new(
            ClientApi::new("http://127.0.0.1:9").unwrap(),
            auth.clone(),
            local.clone(),
        )
        .unwrap(),
    );
    let runtime = ProtectedRuntimeStore::new(Record::default(), paths);
    let mut value =
        RuntimeStateV1::import_legacy(&legacy, StoredSplitTunnelState::default(), runtime.paths());
    value.cleanup_only = false;
    runtime.save(&value).unwrap();
    let owner = RuntimeRecordOwner::new(runtime);
    let writers = local.runtime_writer_gates();
    let lifecycle = writers.lifecycle();
    let guard = lifecycle.lock().await;
    let target = RuntimeTarget {
        container_version: "0.2.16".into(),
        runtime_version: "0.2.16".into(),
        runtime_contract_version: 1,
        runtime_slot: RuntimeSlot::Stable,
    };
    let port = OwnerRuntimeAuth::new(
        broker,
        target,
        RuntimeClientProfile {
            platform: Platform::Macos,
            platform_version: None,
            architecture: "aarch64".into(),
        },
        Arc::new(RuntimeCacheAdmission::new(owner.clone())),
        writers.clone(),
    )
    .unwrap();
    let before = auth.load().unwrap();
    let started = tokio::time::Instant::now();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(11),
        port.login(RuntimeLogin {
            login: "synthetic".into(),
            password: "synthetic".into(),
            device_name: "synthetic".into(),
        }),
    )
    .await;
    assert!(
        result.is_ok(),
        "outer watchdog: owner login has no bounded quiescence budget"
    );
    assert!(result.unwrap().is_err());
    assert_eq!(started.elapsed(), std::time::Duration::from_secs(10));
    assert_eq!(
        auth.load().unwrap(),
        before,
        "no ticket/password request may issue while blocked"
    );
    assert_eq!(owner.operational().load().unwrap(), Some(value));
    drop(guard);
    let _released = tokio::time::timeout(std::time::Duration::from_secs(1), writers.quiesce())
        .await
        .unwrap();
}

#[tokio::test]
async fn new_login_cannot_inherit_retained_cache_or_relabel_an_unknown_scope() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = ClientApi::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let router = Router::new()
        .route("/api/client/v1/auth/logout-runtime", post(|| async { Json(json!({"code":"session_revoked_cleanup_accepted","cleanup_reconcile_operation_id":"synthetic-cleanup"})) }))
        .route("/api/client/v1/auth/login", post(|| async { Json(json!({"api_version":"1","request_id":"synthetic","token_type":"Bearer","access_token":"b-access","access_expires_in":900,"refresh_token":"b-refresh","refresh_expires_in":3600,"access":{"state":"active","can_login":true,"can_connect":true,"expires_at":null},"device":{"id":"device-b","name":"synthetic","platform":"macos","container_version":"0.2.16","runtime_version":"0.2.16","runtime_contract_version":1,"runtime_slot":"stable","session_generation":1}})) }));
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    for missing_scope in [false, true] {
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
        legacy.access_token = Some("a-access".into());
        legacy.refresh_token = Some("a-refresh".into());
        let auth = Arc::new(ProtectedAuthStore::new(Record::default()));
        let mut initial = AuthStoreV1::from_legacy(&legacy);
        initial.confirmed_identity = Some(identity.clone());
        initial.session_generation = Some(7);
        auth.save(&initial).unwrap();
        let local = CoreLocalStop::new(Arc::new(Tunnel));
        let broker = Arc::new(AuthBroker::new(api.clone(), auth.clone(), local.clone()).unwrap());
        let observation = broker.observe().await.unwrap();
        let access = observation.access.unwrap();
        let backend = ProtectedRuntimeStore::new(Record::default(), paths);
        let mut runtime = RuntimeStateV1::import_legacy(
            &legacy,
            StoredSplitTunnelState::default(),
            backend.paths(),
        );
        runtime.cleanup_only = false;
        runtime.compatibility = Some(StoredCompatibility {
            update_required: false,
            observed_at_unix: 11,
        });
        runtime.auth_scope = if missing_scope {
            None
        } else {
            Some(RuntimeAuthScope {
                auth_epoch: access.auth_epoch(),
                family: access.family().into(),
                identity: access.identity().clone(),
            })
        };
        backend.save(&runtime).unwrap();
        let owner = RuntimeRecordOwner::new(backend);
        let port = OwnerRuntimeAuth::new(
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
        .unwrap();
        assert_eq!(
            port.state().await.unwrap(),
            if missing_scope {
                RuntimeAuthState::RecoveryRequired
            } else {
                RuntimeAuthState::Active
            }
        );
        port.logout().await.unwrap();
        assert!(port
            .login(RuntimeLogin {
                login: "b".into(),
                password: "synthetic-password".into(),
                device_name: "synthetic".into()
            })
            .await
            .is_err());
        assert_eq!(
            auth.load().unwrap().unwrap().access_token.as_deref(),
            Some("b-access"),
            "B login succeeded remotely; quarantine must not erase its owner credentials"
        );
        assert_eq!(
            port.state().await.unwrap(),
            RuntimeAuthState::RecoveryRequired
        );
        assert!(port.access(None).await.is_err());
        assert_eq!(owner.operational().load().unwrap(), Some(runtime));
    }
    server.abort();
}
