//! Exercise the scheduler entry point after reconstruction. Panel/native are
//! controlled ports; the application/core state and durable replay are real.
use async_trait::async_trait;
use nelomai_client_api::{AccessSnapshot, RuntimeAuthState, RuntimeLogin};
use nelomai_client_application::{ApplicationApi, ClientApplication};
use nelomai_client_core::{
    CoreApi, CoreApiError, CoreError, CoreLocalStop, NoopLogger, RuntimeAuthProvider,
};
use nelomai_client_storage::*;
use nelomai_client_tunnel::*;
use nelomai_contracts::*;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use tokio::sync::Notify;

struct Store {
    paths: RuntimePaths,
    value: Mutex<RuntimeStateV1>,
}
impl RuntimeStateStore for Store {
    fn paths(&self) -> &RuntimePaths {
        &self.paths
    }
    fn load(&self) -> Result<Option<RuntimeStateV1>, StorageError> {
        Ok(Some(self.value.lock().unwrap().clone()))
    }
    fn save(&self, state: &RuntimeStateV1) -> Result<(), StorageError> {
        *self.value.lock().unwrap() = state.clone();
        Ok(())
    }
}
struct Auth(AccessSnapshot);
#[async_trait]
impl RuntimeAuthProvider for Auth {
    async fn state(&self) -> Result<RuntimeAuthState, CoreError> {
        Ok(RuntimeAuthState::Active)
    }
    async fn access(&self, _: Option<&AccessSnapshot>) -> Result<AccessSnapshot, CoreError> {
        Ok(self.0.clone())
    }
    async fn login(&self, _: RuntimeLogin) -> Result<AccessSnapshot, CoreError> {
        panic!("no Login")
    }
    async fn logout(&self) -> Result<(), CoreError> {
        panic!("no Logout")
    }
}
#[derive(Default)]
struct Tunnel {
    running: AtomicBool,
    commands: AtomicUsize,
    stops: AtomicUsize,
}
#[async_trait]
impl TunnelController for Tunnel {
    async fn start(&self, _: TunnelStartRequest) -> Result<(), TunnelError> {
        panic!("no Start")
    }
    async fn stop(&self) -> Result<(), TunnelError> {
        self.stops.fetch_add(1, Ordering::SeqCst);
        panic!("passive replay must not Stop")
    }
    async fn status(&self) -> Result<TunnelStatus, TunnelError> {
        Ok(if self.running.load(Ordering::SeqCst) {
            TunnelStatus::Running
        } else {
            TunnelStatus::Stopped
        })
    }
    // Deliberately retain desktop's default owns_redundant_session=false.
    async fn desktop_redundancy_command(
        &self,
        _: nelomai_client_tunnel::redundancy::protocol::Command,
    ) -> Result<nelomai_client_tunnel::redundancy::protocol::Snapshot, TunnelError> {
        self.commands.fetch_add(1, Ordering::SeqCst);
        Err(TunnelError::Backend("unexpected_pair_command".into()))
    }
}
#[derive(Default)]
struct Api {
    requests: Mutex<Vec<OperationReconcileRequest>>,
    after_reconcile: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    hold: AtomicBool,
    entered: Notify,
    release: Notify,
}
#[async_trait]
impl CoreApi for Api {
    async fn bootstrap(&self, _: &AccessSnapshot) -> Result<Bootstrap, CoreApiError> {
        panic!("no bootstrap")
    }
    async fn start_connection(
        &self,
        _: &AccessSnapshot,
        _: &ConnectionStartRequest,
    ) -> Result<ConnectionStartResponse, CoreApiError> {
        panic!("no Start")
    }
    async fn stop_connection(
        &self,
        _: &AccessSnapshot,
        _: &ConnectionOperationRequest,
    ) -> Result<ConnectionOperationResponse, CoreApiError> {
        panic!("no Stop")
    }
    async fn pin_stray(
        &self,
        _: &AccessSnapshot,
        _: &ConnectionOperationRequest,
    ) -> Result<ConnectionOperationResponse, CoreApiError> {
        panic!("no pin")
    }
    async fn unpin_stray(
        &self,
        _: &AccessSnapshot,
        _: &ConnectionOperationRequest,
    ) -> Result<ConnectionOperationResponse, CoreApiError> {
        panic!("no unpin")
    }
    async fn reconcile_operation(
        &self,
        _: &AccessSnapshot,
        request: &OperationReconcileRequest,
    ) -> Result<OperationReconcileResponse, CoreApiError> {
        self.requests.lock().unwrap().push(request.clone());
        if self.hold.load(Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        if let Some(action) = self.after_reconcile.lock().unwrap().take() {
            action();
        }
        Ok(OperationReconcileResponse {
            api_version: ApiVersion::V1,
            request_id: "cancel-A".into(),
            state: OperationState::NotFound,
            cancel_requested: true,
            lease_id: None,
            lease_status: None,
            retry_count: 0,
            next_attempt_at: None,
        })
    }
}
#[async_trait]
impl ApplicationApi for Api {
    async fn peer_options(&self, _: &AccessSnapshot) -> Result<PeerOptions, CoreApiError> {
        panic!("no peer options")
    }
    async fn bind_peer(
        &self,
        _: &AccessSnapshot,
        _: &BindPeerRequest,
    ) -> Result<PeerBindingResponse, CoreApiError> {
        panic!("no bind")
    }
    async fn unbind_peer(&self, _: &AccessSnapshot) -> Result<PeerBindingResponse, CoreApiError> {
        panic!("no unbind")
    }
    async fn server_candidates(
        &self,
        _: &AccessSnapshot,
        _: Layer,
        _: EgressMode,
    ) -> Result<ServerCandidatesResponse, CoreApiError> {
        panic!("no candidates")
    }
    async fn probe_latency_ms(&self, _: &str) -> Option<f64> {
        panic!("no probe")
    }
}
fn pair() -> StoredDesktopRedundancy {
    let response: ConnectionStartResponse = serde_json::from_str(include_str!(
        "../../../contracts/fixtures/valid/connection-start-redundant-response.json"
    ))
    .unwrap();
    StoredDesktopRedundancy {
        primary_reported: true,
        runtime_generation: 1,
        connection_generation: 2,
        start_operation_id: "30000000-0000-4000-8000-000000000001".into(),
        request_fingerprint: "ab".repeat(32),
        connection: response.connection,
        session: response.redundancy.unwrap(),
        pending_acquire: None,
        candidate: None,
        stop: None,
    }
}
fn cache() -> StoredConnection {
    StoredConnection {
        lease_id: pair().connection.lease_id,
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        egress_mode: EgressMode::Ipv4,
        pool_id: None,
        probe_url: None,
        kind: StoredConnectionKind::Fixed,
        configuration: "synthetic-B".into(),
        valid_until_unix: None,
    }
}
type App = ClientApplication<Api, Store, Tunnel, NoopLogger>;
fn fixture() -> (Arc<App>, Arc<Store>, Arc<Api>, Arc<Tunnel>) {
    let identity = RuntimeIdentity {
        container_version: "0.4.0".into(),
        runtime_version: "0.4.0".into(),
        slot: RuntimeSlot::Latest,
        runtime_contract_version: 2,
        session_generation: Some(7),
    };
    let access =
        AccessSnapshot::new("synthetic".into(), identity.clone(), 1, "family".into()).unwrap();
    let paths =
        RuntimePaths::new("/synthetic-no-filesystem", RuntimeSlot::Latest, "0.4.0").unwrap();
    let mut state = RuntimeStateV1::empty(&paths, false);
    state.auth_scope = Some(RuntimeAuthScope {
        auth_epoch: 1,
        family: "family".into(),
        identity,
    });
    state.pending_start = Some(StoredPendingStart {
        operation_id: "30000000-0000-4000-8000-000000000009".into(),
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        egress_mode: EgressMode::Ipv4,
        allow_alternate: true,
        probes: vec![],
        recovery_contract_version: Some(2),
        redundancy_contract_version: Some(1),
        reserve_enabled: Some(true),
        request_fingerprint: Some("cd".repeat(32)),
        cancel_operation_id: Some("30000000-0000-4000-8000-000000000008".into()),
    });
    let store = Arc::new(Store {
        paths,
        value: Mutex::new(state),
    });
    let api = Arc::new(Api::default());
    let tunnel = Arc::new(Tunnel::default());
    let app = Arc::new(App::new(
        api.clone(),
        store.clone(),
        Arc::new(Auth(access)),
        CoreLocalStop::new(tunnel.clone()),
        Arc::new(NoopLogger),
    ));
    (app, store, api, tunnel)
}
#[tokio::test]
async fn passive_cancel_replay_preserves_unrelated_retained_pair_native_and_cache() {
    for (retained, running) in [(true, true), (true, false), (false, true)] {
        let (app, store, api, tunnel) = fixture();
        {
            let mut state = store.value.lock().unwrap();
            state.saved_connection = Some(cache());
            state.pinned_connection = Some(cache());
            if retained {
                state.desktop_redundancy = Some(pair());
            }
        }
        tunnel.running.store(running, Ordering::SeqCst);
        let before = store.load().unwrap().unwrap();
        assert!(app.retry_pending_stop().await.is_err());
        assert_eq!(
            tunnel.commands.load(Ordering::SeqCst),
            0,
            "no commands for unrelated pair B"
        );
        assert_eq!(tunnel.stops.load(Ordering::SeqCst), 0);
        assert!(api.requests.lock().unwrap().is_empty());
        assert_eq!(
            store.load().unwrap().unwrap(),
            before,
            "no cache mutation before scope proof"
        );
    }
}
#[tokio::test]
async fn passive_cancel_replay_without_native_owner_clears_only_original_marker() {
    let (app, store, api, tunnel) = fixture();
    let original = store.load().unwrap().unwrap().pending_start.unwrap();
    assert!(app.retry_pending_stop().await.unwrap().is_none());
    assert!(store.load().unwrap().unwrap().pending_start.is_none());
    assert!(app.retry_pending_stop().await.unwrap().is_none());
    let requests = api.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].operation_id, original.operation_id);
    assert_eq!(requests[0].kind, OperationKind::RedundantStart);
    assert!(requests[0].cancel_if_absent);
    assert_eq!(tunnel.stops.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn passive_cancel_replay_rechecks_pair_and_native_ownership_after_reconciliation() {
    for retained in [false, true] {
        let (app, store, api, tunnel) = fixture();
        let activate_store = store.clone();
        let activate_tunnel = tunnel.clone();
        *api.after_reconcile.lock().unwrap() = Some(Box::new(move || {
            if retained {
                let mut state = activate_store.value.lock().unwrap();
                state.desktop_redundancy = Some(pair());
                state.saved_connection = Some(cache());
            } else {
                activate_tunnel.running.store(true, Ordering::SeqCst);
            }
        }));
        assert!(app.retry_pending_stop().await.is_err());
        let state = store.load().unwrap().unwrap();
        assert!(state.pending_start.is_some());
        assert_eq!(state.desktop_redundancy.is_some(), retained);
        assert_eq!(state.saved_connection.is_some(), retained);
        assert_eq!(tunnel.stops.load(Ordering::SeqCst), 0);
        assert_eq!(tunnel.commands.load(Ordering::SeqCst), 0);
    }
}
#[tokio::test]
async fn interrupted_passive_cancel_replays_the_same_durable_operation() {
    let (app, store, api, _) = fixture();
    let original = store.load().unwrap().unwrap().pending_start.unwrap();
    api.hold.store(true, Ordering::SeqCst);
    let worker = {
        let app = app.clone();
        tokio::spawn(async move { app.retry_pending_stop().await })
    };
    api.entered.notified().await;
    worker.abort();
    assert!(worker.await.unwrap_err().is_cancelled());
    assert_eq!(store.load().unwrap().unwrap().pending_start, Some(original));
    api.hold.store(false, Ordering::SeqCst);
    assert!(app.retry_pending_stop().await.unwrap().is_none());
    assert!(store.load().unwrap().unwrap().pending_start.is_none());
    let requests = api.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0], requests[1]);
}
