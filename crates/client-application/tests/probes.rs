use async_trait::async_trait;
use nelomai_client_api::{LoginRequest, TokenResponse};
use nelomai_client_application::{ApplicationApi, ApplicationError, ClientApplication};
use nelomai_client_core::{ConnectOptions, CoreApi, CoreApiError, CoreError, NoopLogger};
use nelomai_client_storage::{SecretStore, StorageError, StoredAuth, StoredCompatibility};
use nelomai_client_tunnel::{TunnelController, TunnelError, TunnelStartRequest, TunnelStatus};
use nelomai_contracts::{
    ApiVersion, BindPeerRequest, Bootstrap, Connection, ConnectionOperationRequest,
    ConnectionOperationResponse, ConnectionStartRequest, ConnectionStartResponse, Layer,
    LeaseStatus, PeerBindingResponse, PeerOptions, ProbeResult, RouteMode, ServerCandidate,
    ServerCandidatesResponse, TicConnectionMode,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

struct ProbeApi {
    candidate_calls: AtomicUsize,
    probe_calls: AtomicUsize,
    start_request: Mutex<Option<ConnectionStartRequest>>,
}

#[async_trait]
impl CoreApi for ProbeApi {
    async fn refresh(&self, _refresh_token: &str) -> Result<TokenResponse, CoreApiError> {
        unreachable!("refresh is not used by this test")
    }

    async fn bootstrap(&self, _access_token: &str) -> Result<Bootstrap, CoreApiError> {
        unreachable!("bootstrap is not used by this test")
    }

    async fn start_connection(
        &self,
        _access_token: &str,
        request: &ConnectionStartRequest,
    ) -> Result<ConnectionStartResponse, CoreApiError> {
        *self.start_request.lock().unwrap() = Some(request.clone());
        Ok(ConnectionStartResponse {
            api_version: ApiVersion::V1,
            request_id: "start-request".to_string(),
            connection: Connection {
                lease_id: "lease-1".to_string(),
                layer: request.layer,
                tic_connection_mode: request.tic_connection_mode,
                route_mode: request.route_mode,
                probe_url: Some("https://1a.example.test/probe".to_string()),
                status: LeaseStatus::Issued,
                pinned: false,
                stopped_at: None,
            },
            configuration: "PrivateKey = test".to_string(),
            reused: false,
        })
    }

    async fn stop_connection(
        &self,
        _access_token: &str,
        _request: &ConnectionOperationRequest,
    ) -> Result<ConnectionOperationResponse, CoreApiError> {
        unreachable!("stop is not used by this test")
    }

    async fn pin_stray(
        &self,
        _access_token: &str,
        _request: &ConnectionOperationRequest,
    ) -> Result<ConnectionOperationResponse, CoreApiError> {
        unreachable!("pin is not used by this test")
    }

    async fn unpin_stray(
        &self,
        _access_token: &str,
        _request: &ConnectionOperationRequest,
    ) -> Result<ConnectionOperationResponse, CoreApiError> {
        unreachable!("unpin is not used by this test")
    }
}

#[async_trait]
impl ApplicationApi for ProbeApi {
    async fn login(&self, _request: &LoginRequest) -> Result<TokenResponse, CoreApiError> {
        unreachable!("login is not used by this test")
    }

    async fn peer_options(&self, _access_token: &str) -> Result<PeerOptions, CoreApiError> {
        unreachable!("peer options are not used by this test")
    }

    async fn bind_peer(
        &self,
        _access_token: &str,
        _request: &BindPeerRequest,
    ) -> Result<PeerBindingResponse, CoreApiError> {
        unreachable!("peer binding is not used by this test")
    }

    async fn unbind_peer(&self, _access_token: &str) -> Result<PeerBindingResponse, CoreApiError> {
        unreachable!("peer unbinding is not used by this test")
    }

    async fn server_candidates(
        &self,
        _access_token: &str,
        layer: Layer,
    ) -> Result<ServerCandidatesResponse, CoreApiError> {
        self.candidate_calls.fetch_add(1, Ordering::SeqCst);
        Ok(ServerCandidatesResponse {
            api_version: ApiVersion::V1,
            request_id: "candidate-request".to_string(),
            candidates: vec![
                candidate("candidate-fast", layer, "https://fast.example/probe"),
                candidate("candidate-down", layer, "https://down.example/probe"),
            ],
        })
    }

    async fn probe_latency_ms(&self, probe_url: &str) -> Option<f64> {
        self.probe_calls.fetch_add(1, Ordering::SeqCst);
        probe_url.contains("fast").then_some(24.5)
    }

    async fn logout(&self, _access_token: &str) -> Result<(), CoreApiError> {
        Ok(())
    }
}

#[derive(Default)]
struct MemoryStore(Mutex<Option<StoredAuth>>);

impl SecretStore for MemoryStore {
    fn load(&self) -> Result<Option<StoredAuth>, StorageError> {
        Ok(self.0.lock().unwrap().clone())
    }

    fn save(&self, auth: &StoredAuth) -> Result<(), StorageError> {
        *self.0.lock().unwrap() = Some(auth.clone());
        Ok(())
    }

    fn delete(&self) -> Result<(), StorageError> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}

struct StoppedTunnel;

#[async_trait]
impl TunnelController for StoppedTunnel {
    async fn start(&self, _request: TunnelStartRequest) -> Result<(), TunnelError> {
        Ok(())
    }

    async fn stop(&self) -> Result<(), TunnelError> {
        Ok(())
    }

    async fn status(&self) -> Result<TunnelStatus, TunnelError> {
        Ok(TunnelStatus::Stopped)
    }
}

#[tokio::test]
async fn probes_are_cached_for_five_minutes_and_only_successes_are_kept() {
    let (application, api) = application();

    let first = application
        .refresh_probes(Layer::Stray, 1_800_000_000)
        .await
        .unwrap();
    let cached = application
        .refresh_probes(Layer::Stray, 1_800_000_299)
        .await
        .unwrap();
    let refreshed = application
        .refresh_probes(Layer::Stray, 1_800_000_300)
        .await
        .unwrap();

    assert_eq!(first, cached);
    assert_ne!(
        cached.probes[0].measured_at,
        refreshed.probes[0].measured_at
    );
    assert_eq!(first.probes.len(), 1);
    assert_eq!(first.probes[0].candidate_id, "candidate-fast");
    assert_eq!(first.probes[0].latency_ms, 24.5);
    assert_eq!(api.candidate_calls.load(Ordering::SeqCst), 2);
    assert_eq!(api.probe_calls.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn concurrent_refreshes_share_one_measurement() {
    let (application, api) = application();

    let (first, second) = tokio::join!(
        application.refresh_probes(Layer::Stray, 1_800_000_000),
        application.refresh_probes(Layer::Stray, 1_800_000_000),
    );

    assert_eq!(first.unwrap(), second.unwrap());
    assert_eq!(api.candidate_calls.load(Ordering::SeqCst), 1);
    assert_eq!(api.probe_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn expired_candidate_tokens_are_refreshed_before_connection() {
    let (application, api) = application();
    application
        .refresh_probes(Layer::Stray, 1_800_000_000)
        .await
        .unwrap();

    application
        .start(
            ConnectOptions {
                layer: Layer::Stray,
                tic_connection_mode: TicConnectionMode::Dynamic,
                route_mode: RouteMode::Standalone,
                probes: Vec::new(),
                allow_alternate: true,
            },
            1_893_456_001,
        )
        .await
        .unwrap();

    assert_eq!(api.candidate_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn connection_uses_native_probe_cache_instead_of_webview_values() {
    let (application, api) = application();
    application
        .refresh_probes(Layer::Stray, 1_800_000_000)
        .await
        .unwrap();

    application
        .start(
            ConnectOptions {
                layer: Layer::Stray,
                tic_connection_mode: TicConnectionMode::Dynamic,
                route_mode: RouteMode::Standalone,
                probes: vec![ProbeResult {
                    candidate_id: "injected-from-webview".to_string(),
                    latency_ms: 0.1,
                    measured_at: "2026-01-01T00:00:00Z".to_string(),
                }],
                allow_alternate: true,
            },
            1_800_000_010,
        )
        .await
        .unwrap();

    let request = api.start_request.lock().unwrap().clone().unwrap();
    assert_eq!(request.probes.len(), 1);
    assert_eq!(request.probes[0].candidate_id, "candidate-fast");
    assert_eq!(api.candidate_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn personal_tic_connection_skips_server_candidates() {
    let (application, api) = application();

    application
        .start(
            ConnectOptions {
                layer: Layer::Tic,
                tic_connection_mode: TicConnectionMode::Personal,
                route_mode: RouteMode::ViaTak,
                probes: Vec::new(),
                allow_alternate: true,
            },
            1_800_000_000,
        )
        .await
        .unwrap();

    let request = api.start_request.lock().unwrap().clone().unwrap();
    assert!(request.probes.is_empty());
    assert_eq!(api.candidate_calls.load(Ordering::SeqCst), 0);
    assert_eq!(api.probe_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn quick_connection_sends_no_probes_and_does_not_measure_candidates() {
    let (application, api) = application();

    application
        .start_without_probe_refresh(
            ConnectOptions {
                layer: Layer::Stray,
                tic_connection_mode: TicConnectionMode::Dynamic,
                route_mode: RouteMode::Standalone,
                probes: vec![ProbeResult {
                    candidate_id: "must-be-discarded".to_string(),
                    latency_ms: 1.0,
                    measured_at: "2026-01-01T00:00:00Z".to_string(),
                }],
                allow_alternate: true,
            },
            1_800_000_000,
        )
        .await
        .unwrap();

    let request = api.start_request.lock().unwrap().clone().unwrap();
    assert!(request.probes.is_empty());
    assert_eq!(api.candidate_calls.load(Ordering::SeqCst), 0);
    assert_eq!(api.probe_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn probe_tokens_are_not_reused_after_logout() {
    let (application, _) = application();
    application
        .refresh_probes(Layer::Stray, 1_800_000_000)
        .await
        .unwrap();

    application.logout().await.unwrap();
    let error = application
        .refresh_probes(Layer::Stray, 1_800_000_010)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        ApplicationError::Core(CoreError::SignedOut)
    ));
}

fn application() -> (
    ClientApplication<ProbeApi, MemoryStore, StoppedTunnel, NoopLogger>,
    Arc<ProbeApi>,
) {
    let api = Arc::new(ProbeApi {
        candidate_calls: AtomicUsize::new(0),
        probe_calls: AtomicUsize::new(0),
        start_request: Mutex::new(None),
    });
    let store = Arc::new(MemoryStore::default());
    let mut auth = StoredAuth::new_install();
    auth.access_token = Some("access-token".to_string());
    auth.refresh_token = Some("refresh-token".to_string());
    auth.compatibility = Some(StoredCompatibility {
        update_required: false,
        observed_at_unix: 1_800_000_000,
    });
    *store.0.lock().unwrap() = Some(auth);
    (
        ClientApplication::new(
            api.clone(),
            store,
            Arc::new(StoppedTunnel),
            Arc::new(NoopLogger),
        ),
        api,
    )
}

fn candidate(id: &str, layer: Layer, probe_url: &str) -> ServerCandidate {
    ServerCandidate {
        candidate_id: id.to_string(),
        layer,
        region_label: "Тест".to_string(),
        probe_url: probe_url.to_string(),
        expires_at: "2030-01-01T00:00:00Z".to_string(),
    }
}
