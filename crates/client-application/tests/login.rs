use async_trait::async_trait;
use nelomai_client_api::{AuthDevice, LoginRequest, TokenResponse};
use nelomai_client_application::{ApplicationApi, ClientApplication, LoginParameters};
use nelomai_client_core::{CoreApi, CoreApiError, NoopLogger, Phase};
use nelomai_client_storage::{
    SecretStore, StorageError, StoredAuth, StoredCompatibility, StoredConnection,
    StoredConnectionKind,
};
use nelomai_client_tunnel::{TunnelController, TunnelError, TunnelStartRequest, TunnelStatus};
use nelomai_contracts::{
    Access, AccessState, ApiVersion, BindPeerRequest, Bootstrap, BootstrapDefaults,
    ConnectionOperationRequest, ConnectionOperationResponse, ConnectionStartRequest,
    ConnectionStartResponse, Device, EgressMode, Layer, PeerBinding, PeerBindingResponse,
    PeerOption, PeerOptions, Platform, RouteMode, ServerCandidatesResponse, TicConnectionMode,
    UpdateState,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

struct FakeApi {
    login_request: Mutex<Option<LoginRequest>>,
    bind_request: Mutex<Option<BindPeerRequest>>,
    bootstrap: Mutex<Bootstrap>,
    bootstrap_calls: AtomicUsize,
    refresh_calls: AtomicUsize,
    logout_calls: AtomicUsize,
    reject_first_bootstrap: bool,
    logout_fails: bool,
    unbind_fails: bool,
}

impl FakeApi {
    fn new(bootstrap: Bootstrap) -> Self {
        Self {
            login_request: Mutex::new(None),
            bind_request: Mutex::new(None),
            bootstrap: Mutex::new(bootstrap),
            bootstrap_calls: AtomicUsize::new(0),
            refresh_calls: AtomicUsize::new(0),
            logout_calls: AtomicUsize::new(0),
            reject_first_bootstrap: false,
            logout_fails: false,
            unbind_fails: false,
        }
    }

    fn rejecting_first_bootstrap(mut self) -> Self {
        self.reject_first_bootstrap = true;
        self
    }

    fn with_logout_failure(mut self) -> Self {
        self.logout_fails = true;
        self
    }

    fn with_unbind_failure(mut self) -> Self {
        self.unbind_fails = true;
        self
    }
}

#[async_trait]
impl CoreApi for FakeApi {
    async fn refresh(&self, _refresh_token: &str) -> Result<TokenResponse, CoreApiError> {
        self.refresh_calls.fetch_add(1, Ordering::SeqCst);
        Ok(TokenResponse {
            api_version: ApiVersion::V1,
            request_id: "refresh-request".to_string(),
            token_type: "Bearer".to_string(),
            access_token: "fresh-access".to_string(),
            access_expires_in: 900,
            refresh_token: "fresh-refresh".to_string(),
            refresh_expires_in: 7_776_000,
            access: active_access(),
            device: AuthDevice {
                id: "device-1".to_string(),
                name: "Laptop".to_string(),
                platform: Platform::Macos,
            },
        })
    }

    async fn bootstrap(&self, _access_token: &str) -> Result<Bootstrap, CoreApiError> {
        let call = self.bootstrap_calls.fetch_add(1, Ordering::SeqCst);
        if self.reject_first_bootstrap && call == 0 {
            return Err(CoreApiError::Unauthorized);
        }
        Ok(self.bootstrap.lock().unwrap().clone())
    }

    async fn start_connection(
        &self,
        _access_token: &str,
        _request: &ConnectionStartRequest,
    ) -> Result<ConnectionStartResponse, CoreApiError> {
        unreachable!("start is not used by this test")
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
impl ApplicationApi for FakeApi {
    async fn login(&self, request: &LoginRequest) -> Result<TokenResponse, CoreApiError> {
        *self.login_request.lock().unwrap() = Some(request.clone());
        Ok(TokenResponse {
            api_version: ApiVersion::V1,
            request_id: "login-request".to_string(),
            token_type: "Bearer".to_string(),
            access_token: "new-access".to_string(),
            access_expires_in: 900,
            refresh_token: "new-refresh".to_string(),
            refresh_expires_in: 7_776_000,
            access: active_access(),
            device: AuthDevice {
                id: "device-1".to_string(),
                name: "Laptop".to_string(),
                platform: Platform::Macos,
            },
        })
    }

    async fn peer_options(&self, _access_token: &str) -> Result<PeerOptions, CoreApiError> {
        Ok(peer_options())
    }

    async fn bind_peer(
        &self,
        _access_token: &str,
        request: &BindPeerRequest,
    ) -> Result<PeerBindingResponse, CoreApiError> {
        *self.bind_request.lock().unwrap() = Some(request.clone());
        Ok(binding_response(request))
    }

    async fn unbind_peer(&self, _access_token: &str) -> Result<PeerBindingResponse, CoreApiError> {
        if self.unbind_fails {
            return Err(CoreApiError::Retryable);
        }
        Ok(PeerBindingResponse {
            api_version: ApiVersion::V1,
            request_id: "unbind-request".to_string(),
            binding: None,
            configuration: None,
        })
    }

    async fn server_candidates(
        &self,
        _access_token: &str,
        _layer: Layer,
        _egress_mode: EgressMode,
    ) -> Result<ServerCandidatesResponse, CoreApiError> {
        unreachable!("server candidates are not used by this test")
    }

    async fn probe_latency_ms(&self, _probe_url: &str) -> Option<f64> {
        unreachable!("server probes are not used by this test")
    }

    async fn logout(&self, _access_token: &str) -> Result<(), CoreApiError> {
        self.logout_calls.fetch_add(1, Ordering::SeqCst);
        if self.logout_fails {
            Err(CoreApiError::Retryable)
        } else {
            Ok(())
        }
    }
}

#[derive(Default)]
struct MemoryStore {
    value: Mutex<Option<StoredAuth>>,
}

impl SecretStore for MemoryStore {
    fn load(&self) -> Result<Option<StoredAuth>, StorageError> {
        Ok(self.value.lock().unwrap().clone())
    }

    fn save(&self, auth: &StoredAuth) -> Result<(), StorageError> {
        *self.value.lock().unwrap() = Some(auth.clone());
        Ok(())
    }

    fn delete(&self) -> Result<(), StorageError> {
        *self.value.lock().unwrap() = None;
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

struct UnavailableTunnel;

#[async_trait]
impl TunnelController for UnavailableTunnel {
    async fn start(&self, _request: TunnelStartRequest) -> Result<(), TunnelError> {
        Err(TunnelError::Backend("service_unavailable".to_string()))
    }

    async fn stop(&self) -> Result<(), TunnelError> {
        Err(TunnelError::Backend("service_unavailable".to_string()))
    }

    async fn status(&self) -> Result<TunnelStatus, TunnelError> {
        Err(TunnelError::Backend("service_unavailable".to_string()))
    }
}

#[derive(Default)]
struct TrackingTunnel {
    stop_calls: AtomicUsize,
}

#[async_trait]
impl TunnelController for TrackingTunnel {
    async fn start(&self, _request: TunnelStartRequest) -> Result<(), TunnelError> {
        Ok(())
    }

    async fn stop(&self) -> Result<(), TunnelError> {
        self.stop_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn status(&self) -> Result<TunnelStatus, TunnelError> {
        Ok(TunnelStatus::Running)
    }
}

#[tokio::test]
async fn login_preserves_install_identity_but_drops_previous_account_state() {
    let api = Arc::new(FakeApi::new(bootstrap()));
    let store = Arc::new(MemoryStore::default());
    *store.value.lock().unwrap() = Some(previous_account());
    let tunnel = Arc::new(TrackingTunnel::default());
    let application = ClientApplication::new(
        api.clone(),
        store.clone(),
        tunnel.clone(),
        Arc::new(NoopLogger),
    );

    let response = application
        .login(
            LoginParameters {
                login: "new-user".to_string(),
                password: "password-secret".to_string(),
                device_name: "Laptop".to_string(),
                platform: Platform::Macos,
                platform_version: Some("15.5".to_string()),
                architecture: "aarch64".to_string(),
                app_version: "0.1.0".to_string(),
            },
            1_800_000_000,
        )
        .await
        .unwrap();

    assert_eq!(response.request_id, "bootstrap-request");
    let request = api.login_request.lock().unwrap().clone().unwrap();
    assert_eq!(request.install_secret, "stable-install-secret");
    let stored = store.value.lock().unwrap().clone().unwrap();
    assert_eq!(stored.install_secret, "stable-install-secret");
    assert_eq!(stored.access_token.as_deref(), Some("new-access"));
    assert_eq!(stored.refresh_token.as_deref(), Some("new-refresh"));
    assert!(stored.saved_connection.is_none());
    assert_eq!(tunnel.stop_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        stored.compatibility,
        Some(StoredCompatibility {
            update_required: false,
            observed_at_unix: 1_800_000_000,
        })
    );
}

#[tokio::test]
async fn unavailable_tunnel_service_does_not_block_login() {
    let api = Arc::new(FakeApi::new(bootstrap()));
    let store = Arc::new(MemoryStore::default());
    let application = ClientApplication::new(
        api,
        store.clone(),
        Arc::new(UnavailableTunnel),
        Arc::new(NoopLogger),
    );

    let response = application
        .login(
            LoginParameters {
                login: "windows-user".to_string(),
                password: "password-secret".to_string(),
                device_name: "Windows PC".to_string(),
                platform: Platform::Windows,
                platform_version: Some("11".to_string()),
                architecture: "x86_64".to_string(),
                app_version: "0.1.0".to_string(),
            },
            1_800_000_000,
        )
        .await
        .unwrap();

    assert_eq!(response.request_id, "bootstrap-request");
    assert_eq!(
        store
            .value
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|stored| stored.access_token.as_deref()),
        Some("new-access")
    );
}

#[tokio::test]
async fn peer_selection_lists_unused_peers_first_and_preserves_comments() {
    let api = Arc::new(FakeApi::new(bootstrap()));
    let store = Arc::new(MemoryStore::default());
    *store.value.lock().unwrap() = Some(previous_account());
    let application =
        ClientApplication::new(api, store, Arc::new(StoppedTunnel), Arc::new(NoopLogger));

    let options = application.peer_options().await.unwrap();

    assert_eq!(
        options
            .peers
            .iter()
            .map(|peer| peer.id.as_str())
            .collect::<Vec<_>>(),
        ["unused-peer", "used-peer"]
    );
    assert_eq!(
        options.peers[0].comment.as_deref(),
        Some("Пир для телефона")
    );
}

#[tokio::test]
async fn background_token_is_not_issued_for_a_stale_device_scope() {
    let api = Arc::new(FakeApi::new(bootstrap()));
    let store = Arc::new(MemoryStore::default());
    *store.value.lock().unwrap() = Some(previous_account());
    let application =
        ClientApplication::new(api, store, Arc::new(StoppedTunnel), Arc::new(NoopLogger));

    let response = application
        .background_token_for_device("device-from-previous-account", 1_800_000_000)
        .await
        .unwrap();

    assert!(response.is_none());
}

#[tokio::test]
async fn binding_uses_the_peer_selected_by_the_user() {
    let api = Arc::new(FakeApi::new(bootstrap()));
    let store = Arc::new(MemoryStore::default());
    *store.value.lock().unwrap() = Some(previous_account());
    let application = ClientApplication::new(
        api.clone(),
        store,
        Arc::new(StoppedTunnel),
        Arc::new(NoopLogger),
    );
    let request = BindPeerRequest {
        peer_id: "peer-chosen-by-user".to_string(),
        preferred_layer: Layer::Tic,
        tic_connection_mode: TicConnectionMode::Personal,
        route_mode: RouteMode::ViaTak,
        egress_mode: EgressMode::PreferIpv6,
    };

    let response = application.bind_peer(request.clone()).await.unwrap();

    assert_eq!(api.bind_request.lock().unwrap().as_ref(), Some(&request));
    assert_eq!(
        response
            .binding
            .as_ref()
            .map(|binding| binding.peer_id.as_str()),
        Some("peer-chosen-by-user")
    );
}

#[tokio::test]
async fn failed_unbind_keeps_the_local_tunnel_and_saved_configuration() {
    let api = Arc::new(FakeApi::new(bootstrap()).with_unbind_failure());
    let store = Arc::new(MemoryStore::default());
    *store.value.lock().unwrap() = Some(previous_account());
    let tunnel = Arc::new(TrackingTunnel::default());
    let application =
        ClientApplication::new(api, store.clone(), tunnel.clone(), Arc::new(NoopLogger));

    assert!(application.unbind_peer().await.is_err());

    assert_eq!(tunnel.stop_calls.load(Ordering::SeqCst), 0);
    assert!(store
        .value
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .saved_connection
        .is_some());
}

#[tokio::test]
async fn logout_clears_account_and_stops_tunnel_when_server_is_unavailable() {
    let api = Arc::new(FakeApi::new(bootstrap()).with_logout_failure());
    let store = Arc::new(MemoryStore::default());
    *store.value.lock().unwrap() = Some(previous_account());
    let tunnel = Arc::new(TrackingTunnel::default());
    let application =
        ClientApplication::new(api, store.clone(), tunnel.clone(), Arc::new(NoopLogger));

    application.logout().await.unwrap();

    assert_eq!(tunnel.stop_calls.load(Ordering::SeqCst), 1);
    let stored = store.value.lock().unwrap().clone().unwrap();
    assert_eq!(stored.install_secret, "stable-install-secret");
    assert!(stored.access_token.is_none());
    assert!(stored.refresh_token.is_none());
    assert!(stored.saved_connection.is_none());
    assert!(stored.pinned_connection.is_none());
    assert!(stored.compatibility.is_none());
    assert_eq!(
        application.state().await.phase,
        nelomai_client_core::Phase::SignedOut
    );
}

#[tokio::test]
async fn local_logout_clears_account_without_calling_remote_revoke() {
    let api = Arc::new(FakeApi::new(bootstrap()));
    let store = Arc::new(MemoryStore::default());
    *store.value.lock().unwrap() = Some(previous_account());
    let tunnel = Arc::new(TrackingTunnel::default());
    let application = ClientApplication::new(
        api.clone(),
        store.clone(),
        tunnel.clone(),
        Arc::new(NoopLogger),
    );

    application.logout_local().await.unwrap();

    assert_eq!(api.logout_calls.load(Ordering::SeqCst), 0);
    assert_eq!(tunnel.stop_calls.load(Ordering::SeqCst), 1);
    let stored = store.value.lock().unwrap().clone().unwrap();
    assert!(stored.access_token.is_none());
    assert!(stored.refresh_token.is_none());
    assert_eq!(application.state().await.phase, Phase::SignedOut);
}

#[tokio::test]
async fn remote_logout_success_revokes_without_clearing_local_authentication() {
    let api = Arc::new(FakeApi::new(bootstrap()));
    let store = Arc::new(MemoryStore::default());
    *store.value.lock().unwrap() = Some(previous_account());
    let application = ClientApplication::new(
        api.clone(),
        store.clone(),
        Arc::new(TrackingTunnel::default()),
        Arc::new(NoopLogger),
    );

    application.logout_remote().await.unwrap();

    assert_eq!(api.logout_calls.load(Ordering::SeqCst), 1);
    let stored = store.value.lock().unwrap().clone().unwrap();
    assert!(stored.access_token.is_some());
    assert!(stored.refresh_token.is_some());
    assert!(application.current_access_token().is_ok());
}

#[tokio::test]
async fn remote_logout_failure_keeps_local_authentication_for_retry() {
    let api = Arc::new(FakeApi::new(bootstrap()).with_logout_failure());
    let store = Arc::new(MemoryStore::default());
    *store.value.lock().unwrap() = Some(previous_account());
    let application = ClientApplication::new(
        api.clone(),
        store.clone(),
        Arc::new(TrackingTunnel::default()),
        Arc::new(NoopLogger),
    );

    assert!(application.logout_remote().await.is_err());

    assert_eq!(api.logout_calls.load(Ordering::SeqCst), 1);
    let stored = store.value.lock().unwrap().clone().unwrap();
    assert!(stored.access_token.is_some());
    assert!(stored.refresh_token.is_some());
    assert!(application.current_access_token().is_ok());
}

#[tokio::test]
async fn refresh_update_state_returns_required_offer_without_changing_core_phase() {
    let api = Arc::new(FakeApi::new(bootstrap()));
    let store = Arc::new(MemoryStore::default());
    *store.value.lock().unwrap() = Some(previous_account());
    let application = ClientApplication::new(
        api.clone(),
        store,
        Arc::new(StoppedTunnel),
        Arc::new(NoopLogger),
    );
    application.bootstrap(1_800_000_000).await.unwrap();
    let initial_state = application.state().await;
    let required_update = UpdateState {
        current_version: Some("0.1.0".to_string()),
        minimum_version: Some("0.2.0".to_string()),
        update_available: true,
        required: true,
        release_notes: Some("Обязательное обновление".to_string()),
    };
    api.bootstrap.lock().unwrap().update = required_update.clone();

    let update = application.refresh_update_state().await.unwrap();

    assert_eq!(update, required_update);
    assert_eq!(application.state().await, initial_state);
}

#[tokio::test]
async fn refresh_update_state_refreshes_an_expired_access_token_once() {
    let api = Arc::new(FakeApi::new(bootstrap()).rejecting_first_bootstrap());
    let store = Arc::new(MemoryStore::default());
    *store.value.lock().unwrap() = Some(previous_account());
    let application = ClientApplication::new(
        api.clone(),
        store.clone(),
        Arc::new(StoppedTunnel),
        Arc::new(NoopLogger),
    );

    application.refresh_update_state().await.unwrap();

    assert_eq!(api.bootstrap_calls.load(Ordering::SeqCst), 2);
    assert_eq!(api.refresh_calls.load(Ordering::SeqCst), 1);
    let stored = store.value.lock().unwrap().clone().unwrap();
    assert_eq!(stored.access_token.as_deref(), Some("fresh-access"));
    assert_eq!(stored.refresh_token.as_deref(), Some("fresh-refresh"));
}

#[tokio::test]
async fn cold_bootstrap_applies_update_required_after_warm_refresh_does_not() {
    let api = Arc::new(FakeApi::new(bootstrap()));
    let store = Arc::new(MemoryStore::default());
    *store.value.lock().unwrap() = Some(previous_account());
    let application = ClientApplication::new(
        api.clone(),
        store,
        Arc::new(StoppedTunnel),
        Arc::new(NoopLogger),
    );
    application.bootstrap(1_800_000_000).await.unwrap();
    let phase_before_refresh = application.state().await.phase;
    assert_ne!(phase_before_refresh, Phase::UpdateRequired);
    api.bootstrap.lock().unwrap().update = UpdateState {
        current_version: Some("0.1.0".to_string()),
        minimum_version: Some("0.2.0".to_string()),
        update_available: true,
        required: true,
        release_notes: Some("Обязательное обновление".to_string()),
    };

    let update = application.refresh_update_state().await.unwrap();
    assert!(update.required);
    assert_eq!(application.state().await.phase, phase_before_refresh);

    let bootstrap = application.bootstrap(1_800_000_001).await.unwrap();
    assert!(bootstrap.update.required);
    assert_eq!(application.state().await.phase, Phase::UpdateRequired);
}

fn previous_account() -> StoredAuth {
    StoredAuth {
        install_secret: "stable-install-secret".to_string(),
        access_token: Some("old-access".to_string()),
        refresh_token: Some("old-refresh".to_string()),
        saved_connection: Some(StoredConnection {
            lease_id: "old-lease".to_string(),
            pool_id: None,
            layer: Layer::Stray,
            tic_connection_mode: TicConnectionMode::Dynamic,
            route_mode: RouteMode::Standalone,
            egress_mode: EgressMode::Ipv4,
            probe_url: Some("https://5a.example.test/probe".to_string()),
            kind: StoredConnectionKind::Pinned,
            configuration: "PrivateKey = old-account-secret".to_string(),
            valid_until_unix: None,
        }),
        pinned_connection: None,
        pending_start: None,
        pending_stalled_stop: None,
        pending_compensation_stop: None,
        compatibility: Some(StoredCompatibility {
            update_required: true,
            observed_at_unix: 1_700_000_000,
        }),
    }
}

fn peer_options() -> PeerOptions {
    PeerOptions {
        api_version: ApiVersion::V1,
        request_id: "peer-options-request".to_string(),
        peers: vec![
            peer("used-peer", Some("2026-07-26T10:00:00Z"), None),
            peer("unused-peer", None, Some("Пир для телефона")),
        ],
    }
}

fn peer(id: &str, last_handshake_at: Option<&str>, comment: Option<&str>) -> PeerOption {
    PeerOption {
        id: id.to_string(),
        interface_id: "interface-1".to_string(),
        interface_name: "Основной".to_string(),
        slot: 1,
        name: id.to_string(),
        comment: comment.map(ToOwned::to_owned),
        last_handshake_at: last_handshake_at.map(ToOwned::to_owned),
        bound_to_app: false,
        bound_to_this_device: false,
        selectable: true,
    }
}

fn binding_response(request: &BindPeerRequest) -> PeerBindingResponse {
    PeerBindingResponse {
        api_version: ApiVersion::V1,
        request_id: "bind-request".to_string(),
        binding: Some(PeerBinding {
            id: "binding-1".to_string(),
            peer_id: request.peer_id.clone(),
            interface_id: "interface-1".to_string(),
            interface_name: "Основной".to_string(),
            slot: 1,
            preferred_layer: request.preferred_layer,
            tic_connection_mode: request.tic_connection_mode,
            route_mode: request.route_mode,
            egress_mode: request.egress_mode,
        }),
        configuration: Some("PrivateKey = must-not-reach-ui".to_string()),
    }
}

fn bootstrap() -> Bootstrap {
    Bootstrap {
        api_version: ApiVersion::V1,
        request_id: "bootstrap-request".to_string(),
        access: active_access(),
        device: Device {
            id: "device-1".to_string(),
            name: "Laptop".to_string(),
            platform: Platform::Macos,
        },
        binding: None,
        connection: None,
        pinned_stray: None,
        defaults: BootstrapDefaults {
            layer: Layer::Stray,
            tic_connection_mode: TicConnectionMode::Dynamic,
            route_mode: RouteMode::Standalone,
        },
        update: nelomai_contracts::UpdateState {
            current_version: Some("0.1.0".to_string()),
            minimum_version: None,
            update_available: false,
            required: false,
            release_notes: None,
        },
        capabilities: None,
    }
}

fn active_access() -> Access {
    Access {
        state: AccessState::Active,
        can_login: true,
        can_connect: true,
        expires_at: None,
    }
}
