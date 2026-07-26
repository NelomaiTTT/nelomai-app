use async_trait::async_trait;
use nelomai_client_api::{AuthDevice, LoginRequest, TokenResponse};
use nelomai_client_application::{ApplicationApi, ClientApplication, LoginParameters};
use nelomai_client_core::{CoreApi, CoreApiError, NoopLogger};
use nelomai_client_storage::{
    SecretStore, StorageError, StoredAuth, StoredCompatibility, StoredConnection,
    StoredConnectionKind,
};
use nelomai_client_tunnel::{TunnelConfiguration, TunnelController, TunnelError, TunnelStatus};
use nelomai_contracts::{
    Access, AccessState, ApiVersion, BindPeerRequest, Bootstrap, BootstrapDefaults,
    ConnectionOperationRequest, ConnectionOperationResponse, ConnectionStartRequest,
    ConnectionStartResponse, Device, Layer, PeerBinding, PeerBindingResponse, PeerOption,
    PeerOptions, Platform, RouteMode, TicConnectionMode,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

struct FakeApi {
    login_request: Mutex<Option<LoginRequest>>,
    bind_request: Mutex<Option<BindPeerRequest>>,
    bootstrap: Bootstrap,
    logout_fails: bool,
}

#[async_trait]
impl CoreApi for FakeApi {
    async fn refresh(&self, _refresh_token: &str) -> Result<TokenResponse, CoreApiError> {
        unreachable!("refresh is not used by this test")
    }

    async fn bootstrap(&self, _access_token: &str) -> Result<Bootstrap, CoreApiError> {
        Ok(self.bootstrap.clone())
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

    async fn logout(&self, _access_token: &str) -> Result<(), CoreApiError> {
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
    async fn start(&self, _configuration: TunnelConfiguration) -> Result<(), TunnelError> {
        Ok(())
    }

    async fn stop(&self) -> Result<(), TunnelError> {
        Ok(())
    }

    async fn status(&self) -> Result<TunnelStatus, TunnelError> {
        Ok(TunnelStatus::Stopped)
    }
}

#[derive(Default)]
struct TrackingTunnel {
    stop_calls: AtomicUsize,
}

#[async_trait]
impl TunnelController for TrackingTunnel {
    async fn start(&self, _configuration: TunnelConfiguration) -> Result<(), TunnelError> {
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
    let api = Arc::new(FakeApi {
        login_request: Mutex::new(None),
        bind_request: Mutex::new(None),
        bootstrap: bootstrap(),
        logout_fails: false,
    });
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
async fn peer_selection_lists_unused_peers_first_and_preserves_comments() {
    let api = Arc::new(FakeApi {
        login_request: Mutex::new(None),
        bind_request: Mutex::new(None),
        bootstrap: bootstrap(),
        logout_fails: false,
    });
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
async fn binding_uses_the_peer_selected_by_the_user() {
    let api = Arc::new(FakeApi {
        login_request: Mutex::new(None),
        bind_request: Mutex::new(None),
        bootstrap: bootstrap(),
        logout_fails: false,
    });
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
async fn logout_clears_account_and_stops_tunnel_when_server_is_unavailable() {
    let api = Arc::new(FakeApi {
        login_request: Mutex::new(None),
        bind_request: Mutex::new(None),
        bootstrap: bootstrap(),
        logout_fails: true,
    });
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
    assert!(stored.compatibility.is_none());
    assert_eq!(
        application.state().await.phase,
        nelomai_client_core::Phase::SignedOut
    );
}

fn previous_account() -> StoredAuth {
    StoredAuth {
        install_secret: "stable-install-secret".to_string(),
        access_token: Some("old-access".to_string()),
        refresh_token: Some("old-refresh".to_string()),
        saved_connection: Some(StoredConnection {
            lease_id: "old-lease".to_string(),
            layer: Layer::Stray,
            tic_connection_mode: TicConnectionMode::Dynamic,
            route_mode: RouteMode::Standalone,
            kind: StoredConnectionKind::Pinned,
            configuration: "PrivateKey = old-account-secret".to_string(),
            valid_until_unix: None,
        }),
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
