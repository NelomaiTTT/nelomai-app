use async_trait::async_trait;
use nelomai_client_api::{AccessSnapshot, RuntimeAuthState, RuntimeLogin};
use nelomai_client_core::{ClientCore, CoreError, CoreLocalStop, NoopLogger, RuntimeAuthProvider};
use nelomai_client_storage::{
    RuntimePaths, RuntimeStateStore, RuntimeStateV1, StorageError, StoredSplitTunnelState,
};
use nelomai_client_tunnel::{TunnelController, TunnelError, TunnelStartRequest, TunnelStatus};
use nelomai_contracts::{RuntimeIdentity, RuntimeSlot};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

struct ReadOnlyRuntime(RuntimePaths);
impl RuntimeStateStore for ReadOnlyRuntime {
    fn paths(&self) -> &RuntimePaths {
        &self.0
    }
    fn load(&self) -> Result<Option<RuntimeStateV1>, StorageError> {
        Ok(Some(RuntimeStateV1 {
            schema_version: 1,
            slot: RuntimeSlot::Stable,
            runtime_version: "0.2.16".into(),
            cleanup_only: false,
            saved_connection: None,
            pinned_connection: None,
            pending_start: None,
            pending_stalled_stop: None,
            pending_compensation_stop: None,
            compatibility: None,
            applied_split_tunnel: StoredSplitTunnelState::default(),
        }))
    }
    fn save(&self, _: &RuntimeStateV1) -> Result<(), StorageError> {
        panic!("access-only requests cannot write runtime or auth state")
    }
}
struct StoppedTunnel;
#[async_trait]
impl TunnelController for StoppedTunnel {
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

struct Provider(AtomicUsize);
#[async_trait]
impl RuntimeAuthProvider for Provider {
    async fn state(&self) -> Result<RuntimeAuthState, CoreError> {
        Ok(RuntimeAuthState::Active)
    }
    async fn login(&self, _: RuntimeLogin) -> Result<AccessSnapshot, CoreError> {
        Err(CoreError::SignedOut)
    }
    async fn access(&self, stale: Option<&AccessSnapshot>) -> Result<AccessSnapshot, CoreError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        let identity = RuntimeIdentity {
            slot: RuntimeSlot::Stable,
            runtime_version: "0.2.16".into(),
            runtime_contract_version: 1,
            container_version: "0.2.16".into(),
            session_generation: Some(7),
        };
        if stale.is_some_and(|s| s.auth_epoch() != 9) {
            return Err(CoreError::StartCancelled);
        }
        Ok(AccessSnapshot::new(
            "synthetic-access".into(),
            identity,
            9,
            "synthetic-family".into(),
        )
        .unwrap())
    }
    async fn logout(&self) -> Result<(), CoreError> {
        Ok(())
    }
}

#[tokio::test]
async fn neutral_access_port_preserves_the_whole_snapshot_and_has_no_credential_store() {
    let provider = Arc::new(Provider(AtomicUsize::new(0)));
    let core = ClientCore::new(
        Arc::new(nelomai_client_api::ClientApi::new("http://127.0.0.1:9").unwrap()),
        Arc::new(ReadOnlyRuntime(
            RuntimePaths::new(
                "/synthetic-no-filesystem-access",
                RuntimeSlot::Stable,
                "0.2.16",
            )
            .unwrap(),
        )),
        provider.clone(),
        CoreLocalStop::new(Arc::new(StoppedTunnel)),
        Arc::new(NoopLogger),
    );
    let first = core.access_snapshot().await.unwrap();
    let next = core.refresh_access_token(&first).await.unwrap();
    assert_eq!(provider.0.load(Ordering::SeqCst), 2);
    assert_eq!(next.identity().session_generation, Some(7));
    assert_eq!(next.auth_epoch(), 9);
    assert_eq!(next.family(), "synthetic-family");
    assert!(!format!("{next:?}").contains("synthetic-access"));
}

#[test]
fn runtime_login_cannot_supply_install_secret_or_select_the_runtime_target() {
    for field in [
        "install_secret",
        "runtime_slot",
        "runtime_version",
        "container_version",
        "session_generation",
        "app_version",
    ] {
        let mut value = serde_json::json!({"login":"synthetic", "password":"synthetic-password", "device_name":"test"});
        value[field] = serde_json::json!("forbidden");
        assert!(
            serde_json::from_value::<RuntimeLogin>(value).is_err(),
            "{field}"
        );
    }
    let login: RuntimeLogin = serde_json::from_value(serde_json::json!({"login":"synthetic", "password":"synthetic-password", "device_name":"test"})).unwrap();
    assert!(!format!("{login:?}").contains("synthetic-password"));
}
