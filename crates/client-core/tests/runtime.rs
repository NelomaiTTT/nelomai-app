use async_trait::async_trait;
use nelomai_client_api::{AuthDevice, TokenResponse};
use nelomai_client_core::{
    ClientCore, ConnectOptions, CoreApi, CoreApiError, CoreLogEvent, CoreLogger, Phase, RetryPolicy,
};
use nelomai_client_storage::{
    SecretStore, StorageError, StoredAuth, StoredCompatibility, StoredConnection,
    StoredConnectionKind,
};
use nelomai_client_tunnel::{TunnelConfiguration, TunnelController, TunnelError, TunnelStatus};
use nelomai_contracts::{
    Access, AccessState, ApiVersion, Bootstrap, BootstrapDefaults, Connection,
    ConnectionOperationRequest, ConnectionOperationResponse, ConnectionStartRequest,
    ConnectionStartResponse, Device, Layer, LeaseStatus, Platform, RouteMode, TicConnectionMode,
    UpdateState,
};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

struct MemoryStore(Mutex<Option<StoredAuth>>);

impl MemoryStore {
    fn new(auth: StoredAuth) -> Self {
        Self(Mutex::new(Some(auth)))
    }
}

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

#[derive(Default)]
struct MemoryLogger(Mutex<Vec<CoreLogEvent>>);

impl CoreLogger for MemoryLogger {
    fn record(&self, event: CoreLogEvent) {
        self.0.lock().unwrap().push(event);
    }
}

#[derive(Default)]
struct MemoryTunnel {
    starts: AtomicUsize,
    configuration: Mutex<Option<String>>,
    status: Mutex<TunnelStatus>,
}

#[async_trait]
impl TunnelController for MemoryTunnel {
    async fn start(&self, configuration: TunnelConfiguration) -> Result<(), TunnelError> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        *self.configuration.lock().unwrap() = Some(configuration.expose().to_string());
        *self.status.lock().unwrap() = TunnelStatus::Running;
        Ok(())
    }

    async fn stop(&self) -> Result<(), TunnelError> {
        *self.status.lock().unwrap() = TunnelStatus::Stopped;
        Ok(())
    }

    async fn status(&self) -> Result<TunnelStatus, TunnelError> {
        Ok(*self.status.lock().unwrap())
    }
}

struct MockApi {
    refresh_calls: AtomicUsize,
    start_calls: AtomicUsize,
    start_failures: AtomicUsize,
    operation_ids: Mutex<Vec<String>>,
    stop_calls: AtomicUsize,
    stop_failures: AtomicUsize,
    stop_operation_ids: Mutex<Vec<String>>,
    bootstrap_fails: AtomicBool,
    reject_stale_bootstrap: AtomicBool,
    reject_stale_start: AtomicBool,
    reject_stale_stop: AtomicBool,
    pinned_start: AtomicBool,
    start_lease_override: Mutex<Option<String>>,
    pin_calls: AtomicUsize,
    unpin_calls: AtomicUsize,
    pin_fails: AtomicBool,
}

impl MockApi {
    fn new(start_failures: usize) -> Self {
        Self {
            refresh_calls: AtomicUsize::new(0),
            start_calls: AtomicUsize::new(0),
            start_failures: AtomicUsize::new(start_failures),
            operation_ids: Mutex::new(Vec::new()),
            stop_calls: AtomicUsize::new(0),
            stop_failures: AtomicUsize::new(0),
            stop_operation_ids: Mutex::new(Vec::new()),
            bootstrap_fails: AtomicBool::new(false),
            reject_stale_bootstrap: AtomicBool::new(false),
            reject_stale_start: AtomicBool::new(false),
            reject_stale_stop: AtomicBool::new(false),
            pinned_start: AtomicBool::new(false),
            start_lease_override: Mutex::new(None),
            pin_calls: AtomicUsize::new(0),
            unpin_calls: AtomicUsize::new(0),
            pin_fails: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl CoreApi for MockApi {
    async fn refresh(&self, _refresh_token: &str) -> Result<TokenResponse, CoreApiError> {
        self.refresh_calls.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(20)).await;
        Ok(token_response("fresh-access", "fresh-refresh"))
    }

    async fn bootstrap(&self, access_token: &str) -> Result<Bootstrap, CoreApiError> {
        if self.reject_stale_bootstrap.load(Ordering::SeqCst) && access_token == "stale-access" {
            return Err(CoreApiError::Unauthorized);
        }
        if self.bootstrap_fails.load(Ordering::SeqCst) {
            return Err(CoreApiError::Retryable);
        }
        Ok(bootstrap())
    }

    async fn start_connection(
        &self,
        access_token: &str,
        request: &ConnectionStartRequest,
    ) -> Result<ConnectionStartResponse, CoreApiError> {
        self.start_calls.fetch_add(1, Ordering::SeqCst);
        self.operation_ids
            .lock()
            .unwrap()
            .push(request.operation_id.clone());
        if self.reject_stale_start.load(Ordering::SeqCst) && access_token == "stale-access" {
            return Err(CoreApiError::Unauthorized);
        }
        if self
            .start_failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                value.checked_sub(1)
            })
            .is_ok()
        {
            return Err(CoreApiError::Retryable);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        let lease_id = self
            .start_lease_override
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| request.operation_id.clone());
        let mut response = start_response(&lease_id);
        response.connection.layer = request.layer;
        response.connection.tic_connection_mode = request.tic_connection_mode;
        response.connection.route_mode = request.route_mode;
        response.connection.pinned = self.pinned_start.load(Ordering::SeqCst);
        Ok(response)
    }

    async fn stop_connection(
        &self,
        access_token: &str,
        request: &ConnectionOperationRequest,
    ) -> Result<ConnectionOperationResponse, CoreApiError> {
        self.stop_calls.fetch_add(1, Ordering::SeqCst);
        self.stop_operation_ids
            .lock()
            .unwrap()
            .push(request.operation_id.clone());
        if self.reject_stale_stop.load(Ordering::SeqCst) && access_token == "stale-access" {
            return Err(CoreApiError::Unauthorized);
        }
        if self
            .stop_failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                value.checked_sub(1)
            })
            .is_ok()
        {
            return Err(CoreApiError::Retryable);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        Ok(ConnectionOperationResponse {
            api_version: ApiVersion::V1,
            request_id: "req-stop".to_string(),
            connection: Connection {
                lease_id: request.lease_id.clone(),
                status: LeaseStatus::Warm,
                stopped_at: Some("2026-07-26T10:00:00Z".to_string()),
                ..connection(&request.lease_id)
            },
        })
    }

    async fn pin_stray(
        &self,
        _access_token: &str,
        request: &ConnectionOperationRequest,
    ) -> Result<ConnectionOperationResponse, CoreApiError> {
        self.pin_calls.fetch_add(1, Ordering::SeqCst);
        if self.pin_fails.load(Ordering::SeqCst) {
            return Err(CoreApiError::Rejected {
                code: "connection_not_pinnable".to_string(),
                message: "Подключение нельзя закрепить.".to_string(),
            });
        }
        Ok(ConnectionOperationResponse {
            api_version: ApiVersion::V1,
            request_id: "req-pin".to_string(),
            connection: Connection {
                pinned: true,
                ..connection(&request.lease_id)
            },
        })
    }

    async fn unpin_stray(
        &self,
        _access_token: &str,
        request: &ConnectionOperationRequest,
    ) -> Result<ConnectionOperationResponse, CoreApiError> {
        self.unpin_calls.fetch_add(1, Ordering::SeqCst);
        Ok(ConnectionOperationResponse {
            api_version: ApiVersion::V1,
            request_id: "req-unpin".to_string(),
            connection: Connection {
                status: LeaseStatus::Warm,
                stopped_at: Some("2026-07-26T10:00:00Z".to_string()),
                ..connection(&request.lease_id)
            },
        })
    }
}

fn auth() -> StoredAuth {
    let mut auth = StoredAuth::new_install();
    auth.access_token = Some("stale-access".to_string());
    auth.refresh_token = Some("refresh-secret".to_string());
    auth
}

fn token_response(access_token: &str, refresh_token: &str) -> TokenResponse {
    TokenResponse {
        api_version: ApiVersion::V1,
        request_id: "req-auth".to_string(),
        token_type: "bearer".to_string(),
        access_token: access_token.to_string(),
        access_expires_in: 900,
        refresh_token: refresh_token.to_string(),
        refresh_expires_in: 7_776_000,
        access: Access {
            state: AccessState::Active,
            can_login: true,
            can_connect: true,
            expires_at: None,
        },
        device: AuthDevice {
            id: "device-1".to_string(),
            name: "Mac".to_string(),
            platform: Platform::Macos,
        },
    }
}

fn connection(lease_id: &str) -> Connection {
    Connection {
        lease_id: lease_id.to_string(),
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        status: LeaseStatus::Issued,
        pinned: false,
        stopped_at: None,
    }
}

fn start_response(lease_id: &str) -> ConnectionStartResponse {
    ConnectionStartResponse {
        api_version: ApiVersion::V1,
        request_id: "req-start".to_string(),
        connection: connection(lease_id),
        configuration: "[Interface]\nPrivateKey = tunnel-secret\n".to_string(),
        reused: false,
    }
}

fn bootstrap() -> Bootstrap {
    Bootstrap {
        api_version: ApiVersion::V1,
        request_id: "req-bootstrap".to_string(),
        access: Access {
            state: AccessState::Active,
            can_login: true,
            can_connect: true,
            expires_at: None,
        },
        device: Device {
            id: "device-1".to_string(),
            name: "Mac".to_string(),
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
        update: UpdateState {
            current_version: Some("0.1.0".to_string()),
            minimum_version: None,
            update_available: false,
            required: false,
            release_notes: None,
        },
    }
}

fn options() -> ConnectOptions {
    ConnectOptions {
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        probes: Vec::new(),
        allow_alternate: false,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn refresh_is_single_flight_and_rotates_tokens_once() {
    let api = Arc::new(MockApi::new(0));
    let store = Arc::new(MemoryStore::new(auth()));
    let core = Arc::new(ClientCore::new(
        api.clone(),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    ));

    let (first, second) = tokio::join!(
        core.refresh_access_token("stale-access"),
        core.refresh_access_token("stale-access")
    );
    assert_eq!(first.unwrap(), "fresh-access");
    assert_eq!(second.unwrap(), "fresh-access");
    assert_eq!(api.refresh_calls.load(Ordering::SeqCst), 1);
    let stored = store.load().unwrap().unwrap();
    assert_eq!(stored.refresh_token.as_deref(), Some("fresh-refresh"));
}

#[tokio::test(flavor = "current_thread")]
async fn bootstrap_refreshes_an_expired_access_token_without_signing_out() {
    let api = Arc::new(MockApi::new(0));
    api.reject_stale_bootstrap.store(true, Ordering::SeqCst);
    let store = Arc::new(MemoryStore::new(auth()));
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    );

    let response = core.bootstrap(1_700_000_000).await.unwrap();

    assert_eq!(response.request_id, "req-bootstrap");
    assert_eq!(api.refresh_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        store.load().unwrap().unwrap().access_token.as_deref(),
        Some("fresh-access")
    );
    assert_ne!(core.state().await.phase, Phase::SignedOut);
}

#[tokio::test(flavor = "current_thread")]
async fn start_refreshes_once_and_reuses_the_same_operation() {
    let api = Arc::new(MockApi::new(0));
    api.reject_stale_start.store(true, Ordering::SeqCst);
    let core = ClientCore::new(
        api.clone(),
        Arc::new(MemoryStore::new(auth())),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    );

    core.start(options(), 1_700_000_000).await.unwrap();

    assert_eq!(api.refresh_calls.load(Ordering::SeqCst), 1);
    let operation_ids = api.operation_ids.lock().unwrap();
    assert_eq!(operation_ids.len(), 2);
    assert_eq!(operation_ids[0], operation_ids[1]);
}

#[tokio::test(flavor = "current_thread")]
async fn stop_refreshes_once_after_the_local_tunnel_is_stopped() {
    let api = Arc::new(MockApi::new(0));
    let tunnel = Arc::new(MemoryTunnel::default());
    let core = ClientCore::new(
        api.clone(),
        Arc::new(MemoryStore::new(auth())),
        tunnel,
        Arc::new(MemoryLogger::default()),
    );
    core.start(options(), 1_700_000_000).await.unwrap();
    api.reject_stale_stop.store(true, Ordering::SeqCst);

    core.stop().await.unwrap();

    assert_eq!(api.refresh_calls.load(Ordering::SeqCst), 1);
    {
        let operation_ids = api.stop_operation_ids.lock().unwrap();
        assert_eq!(operation_ids.len(), 2);
        assert_eq!(operation_ids[0], operation_ids[1]);
    }
    assert_eq!(core.state().await.phase, Phase::Ready);
}

#[tokio::test(flavor = "current_thread")]
async fn concurrent_start_is_single_flight_and_configuration_never_enters_logs() {
    let api = Arc::new(MockApi::new(0));
    let store = Arc::new(MemoryStore::new(auth()));
    let tunnel = Arc::new(MemoryTunnel::default());
    let logger = Arc::new(MemoryLogger::default());
    let core = Arc::new(ClientCore::new(
        api.clone(),
        store.clone(),
        tunnel.clone(),
        logger.clone(),
    ));

    let (first, second) = tokio::join!(
        core.start(options(), 1_700_000_000),
        core.start(options(), 1_700_000_000)
    );
    assert_eq!(first.unwrap().lease_id, second.unwrap().lease_id);
    assert_eq!(api.start_calls.load(Ordering::SeqCst), 1);
    assert_eq!(tunnel.starts.load(Ordering::SeqCst), 1);
    assert_eq!(
        tunnel.configuration.lock().unwrap().as_deref(),
        Some("[Interface]\nPrivateKey = tunnel-secret\n")
    );
    let logs = format!("{:?}", logger.0.lock().unwrap());
    assert!(!logs.contains("tunnel-secret"));
    assert!(!logs.contains("stale-access"));
    assert!(!logs.contains("refresh-secret"));
    assert_eq!(core.state().await.phase, Phase::Connected);
}

#[tokio::test(flavor = "current_thread")]
async fn retries_reuse_one_operation_id_and_stop_after_the_bound() {
    let api = Arc::new(MockApi::new(2));
    let core = ClientCore::new(
        api.clone(),
        Arc::new(MemoryStore::new(auth())),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    )
    .with_retry_policy(RetryPolicy::new(vec![0, 0, 0]));

    core.start(options(), 1_700_000_000).await.unwrap();
    assert_eq!(api.start_calls.load(Ordering::SeqCst), 3);
    let ids = api.operation_ids.lock().unwrap();
    assert_eq!(ids.len(), 3);
    assert!(ids.iter().all(|value| value == &ids[0]));
}

#[tokio::test(flavor = "current_thread")]
async fn concurrent_stop_is_single_flight() {
    let api = Arc::new(MockApi::new(0));
    let core = Arc::new(ClientCore::new(
        api.clone(),
        Arc::new(MemoryStore::new(auth())),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    ));
    core.start(options(), 1_700_000_000).await.unwrap();

    let (first, second) = tokio::join!(core.stop(), core.stop());
    assert_eq!(first.unwrap().lease_id, second.unwrap().lease_id);
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
    assert_eq!(core.state().await.phase, Phase::Ready);
}

#[tokio::test(flavor = "current_thread")]
async fn stop_retries_are_bounded_and_reuse_the_operation_id() {
    let api = Arc::new(MockApi::new(0));
    api.stop_failures.store(2, Ordering::SeqCst);
    let core = ClientCore::new(
        api.clone(),
        Arc::new(MemoryStore::new(auth())),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    )
    .with_retry_policy(RetryPolicy::new(vec![0, 0]));
    core.start(options(), 1_700_000_000).await.unwrap();

    core.stop().await.unwrap();
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 3);
    let ids = api.stop_operation_ids.lock().unwrap();
    assert!(ids.iter().all(|value| value == &ids[0]));
}

#[tokio::test(flavor = "current_thread")]
async fn valid_saved_stray_starts_offline_but_a_critical_update_blocks_it() {
    let mut stored = auth();
    stored.saved_connection = Some(StoredConnection {
        lease_id: "11111111-1111-4111-8111-111111111111".to_string(),
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        kind: StoredConnectionKind::DynamicWarm,
        configuration: "[Interface]\nPrivateKey = offline-secret\n".to_string(),
        valid_until_unix: Some(1_700_000_100),
    });
    stored.compatibility = Some(StoredCompatibility {
        update_required: false,
        observed_at_unix: 1_699_999_000,
    });
    let store = Arc::new(MemoryStore::new(stored));
    let tunnel = Arc::new(MemoryTunnel::default());
    let core = ClientCore::new(
        Arc::new(MockApi::new(0)),
        store.clone(),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    );

    assert_eq!(
        core.start_saved_stray_offline(1_700_000_000).await.unwrap(),
        "11111111-1111-4111-8111-111111111111"
    );
    assert_eq!(tunnel.starts.load(Ordering::SeqCst), 1);

    let mut blocked = store.load().unwrap().unwrap();
    blocked.compatibility.as_mut().unwrap().update_required = true;
    store.save(&blocked).unwrap();
    let error = core
        .start_saved_stray_offline(1_700_000_000)
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "требуется обязательное обновление приложения"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn expired_warm_stray_is_not_started_offline() {
    let mut stored = auth();
    stored.saved_connection = Some(StoredConnection {
        lease_id: "11111111-1111-4111-8111-111111111111".to_string(),
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        kind: StoredConnectionKind::DynamicWarm,
        configuration: "PrivateKey = expired".to_string(),
        valid_until_unix: Some(1_700_000_000),
    });
    let tunnel = Arc::new(MemoryTunnel::default());
    let core = ClientCore::new(
        Arc::new(MockApi::new(0)),
        Arc::new(MemoryStore::new(stored)),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    );

    assert!(core.start_saved_stray_offline(1_700_000_000).await.is_err());
    assert_eq!(tunnel.starts.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn remembered_critical_update_blocks_online_start_before_the_api_call() {
    let mut stored = auth();
    stored.compatibility = Some(StoredCompatibility {
        update_required: true,
        observed_at_unix: 1_700_000_000,
    });
    let api = Arc::new(MockApi::new(0));
    let core = ClientCore::new(
        api.clone(),
        Arc::new(MemoryStore::new(stored)),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    );

    let error = core.start(options(), 1_700_000_001).await.unwrap_err();
    assert_eq!(
        error.to_string(),
        "требуется обязательное обновление приложения"
    );
    assert_eq!(api.start_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn retry_policy_stops_after_its_configured_bound() {
    let api = Arc::new(MockApi::new(usize::MAX));
    let core = ClientCore::new(
        api.clone(),
        Arc::new(MemoryStore::new(auth())),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    )
    .with_retry_policy(RetryPolicy::new(vec![0, 0]));

    assert!(core.start(options(), 1_700_000_000).await.is_err());
    assert_eq!(api.start_calls.load(Ordering::SeqCst), 3);
    assert_eq!(core.state().await.phase, Phase::ServerUnavailable);
}

#[tokio::test(flavor = "current_thread")]
async fn offline_bootstrap_can_fall_back_to_a_valid_saved_stray() {
    let mut stored = auth();
    stored.saved_connection = Some(StoredConnection {
        lease_id: "11111111-1111-4111-8111-111111111111".to_string(),
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        kind: StoredConnectionKind::Pinned,
        configuration: "PrivateKey = offline".to_string(),
        valid_until_unix: None,
    });
    let api = Arc::new(MockApi::new(0));
    api.bootstrap_fails.store(true, Ordering::SeqCst);
    let store = Arc::new(MemoryStore::new(stored));
    let core = ClientCore::new(
        api,
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    );

    assert!(core.bootstrap(1_700_000_000).await.is_err());
    assert_eq!(core.state().await.phase, Phase::ServerUnavailable);
    assert_eq!(
        core.start_saved_stray_offline(1_700_000_000).await.unwrap(),
        "11111111-1111-4111-8111-111111111111"
    );
    let migrated = store.load().unwrap().unwrap();
    assert!(migrated.saved_connection.is_none());
    assert_eq!(
        migrated.pinned_connection.unwrap().lease_id,
        "11111111-1111-4111-8111-111111111111"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn pinned_and_fixed_configurations_are_kept_without_a_synthetic_expiry() {
    let api = Arc::new(MockApi::new(0));
    api.pinned_start.store(true, Ordering::SeqCst);
    let pinned_store = Arc::new(MemoryStore::new(auth()));
    let pinned_core = ClientCore::new(
        api,
        pinned_store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    );
    pinned_core.start(options(), 1_700_000_000).await.unwrap();
    let pinned = pinned_store
        .load()
        .unwrap()
        .unwrap()
        .pinned_connection
        .unwrap();
    assert_eq!(pinned.kind, StoredConnectionKind::Pinned);
    assert_eq!(pinned.valid_until_unix, None);

    let fixed_store = Arc::new(MemoryStore::new(auth()));
    let fixed_core = ClientCore::new(
        Arc::new(MockApi::new(0)),
        fixed_store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    );
    fixed_core
        .start(
            ConnectOptions {
                layer: Layer::Tic,
                tic_connection_mode: TicConnectionMode::Personal,
                route_mode: RouteMode::ViaTak,
                probes: Vec::new(),
                allow_alternate: false,
            },
            1_700_000_000,
        )
        .await
        .unwrap();
    let fixed = fixed_store
        .load()
        .unwrap()
        .unwrap()
        .saved_connection
        .unwrap();
    assert_eq!(fixed.kind, StoredConnectionKind::Fixed);
    assert_eq!(fixed.valid_until_unix, None);
}

#[tokio::test(flavor = "current_thread")]
async fn fixed_connection_uses_a_new_operation_after_stop() {
    let api = Arc::new(MockApi::new(0));
    let core = ClientCore::new(
        api.clone(),
        Arc::new(MemoryStore::new(auth())),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    );
    let options = ConnectOptions {
        layer: Layer::Tic,
        tic_connection_mode: TicConnectionMode::Personal,
        route_mode: RouteMode::ViaTak,
        probes: Vec::new(),
        allow_alternate: false,
    };

    core.start(options.clone(), 1_700_000_000).await.unwrap();
    core.stop().await.unwrap();
    core.start(options, 1_700_000_100).await.unwrap();

    let operation_ids = api.operation_ids.lock().unwrap();
    assert_eq!(operation_ids.len(), 2);
    assert_ne!(operation_ids[0], operation_ids[1]);
}

#[tokio::test(flavor = "current_thread")]
async fn pin_and_unpin_move_the_configuration_between_separate_slots() {
    let api = Arc::new(MockApi::new(0));
    let store = Arc::new(MemoryStore::new(auth()));
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    );

    let started = core.start(options(), 1_700_000_000).await.unwrap();
    let pinned = core.pin_stray().await.unwrap();
    assert_eq!(pinned.lease_id, started.lease_id);
    assert!(pinned.pinned);
    let stored = store.load().unwrap().unwrap();
    assert!(stored.saved_connection.is_none());
    assert_eq!(
        stored.pinned_connection.as_ref().unwrap().kind,
        StoredConnectionKind::Pinned
    );

    let unpinned = core
        .unpin_stray(&pinned.lease_id, 1_700_000_100)
        .await
        .unwrap();
    assert!(!unpinned.pinned);
    let stored = store.load().unwrap().unwrap();
    assert!(stored.pinned_connection.is_none());
    let warm = stored.saved_connection.unwrap();
    assert_eq!(warm.kind, StoredConnectionKind::DynamicWarm);
    assert_eq!(warm.valid_until_unix, Some(1_700_003_700));
    assert_eq!(api.pin_calls.load(Ordering::SeqCst), 1);
    assert_eq!(api.unpin_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn rejected_pin_keeps_the_active_tunnel_and_saved_configuration() {
    let api = Arc::new(MockApi::new(0));
    let store = Arc::new(MemoryStore::new(auth()));
    let tunnel = Arc::new(MemoryTunnel::default());
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    );
    let started = core.start(options(), 1_700_000_000).await.unwrap();
    api.pin_fails.store(true, Ordering::SeqCst);

    assert!(core.pin_stray().await.is_err());

    assert_eq!(core.state().await.phase, Phase::Connected);
    assert_eq!(tunnel.status().await.unwrap(), TunnelStatus::Running);
    let stored = store.load().unwrap().unwrap();
    assert_eq!(stored.saved_connection.unwrap().lease_id, started.lease_id);
    assert!(stored.pinned_connection.is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn alternate_stray_does_not_overwrite_the_saved_pin() {
    let api = Arc::new(MockApi::new(0));
    let mut stored = auth();
    stored.pinned_connection = Some(StoredConnection {
        lease_id: "pinned-lease".to_string(),
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        kind: StoredConnectionKind::Pinned,
        configuration: "PrivateKey = pinned-secret".to_string(),
        valid_until_unix: None,
    });
    *api.start_lease_override.lock().unwrap() = Some("alternate-lease".to_string());
    let store = Arc::new(MemoryStore::new(stored));
    let core = ClientCore::new(
        api,
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    );

    let connection = core.start(options(), 1_700_000_000).await.unwrap();

    assert_eq!(connection.lease_id, "alternate-lease");
    let stored = store.load().unwrap().unwrap();
    assert_eq!(stored.pinned_connection.unwrap().lease_id, "pinned-lease");
    assert_eq!(stored.saved_connection.unwrap().lease_id, "alternate-lease");
}

#[tokio::test(flavor = "current_thread")]
async fn unbind_clears_dynamic_and_pinned_connections() {
    let mut stored = auth();
    stored.saved_connection = Some(StoredConnection {
        lease_id: "alternate-lease".to_string(),
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        kind: StoredConnectionKind::DynamicWarm,
        configuration: "PrivateKey = alternate-secret".to_string(),
        valid_until_unix: Some(1_700_003_600),
    });
    stored.pinned_connection = Some(StoredConnection {
        lease_id: "pinned-lease".to_string(),
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        kind: StoredConnectionKind::Pinned,
        configuration: "PrivateKey = pinned-secret".to_string(),
        valid_until_unix: None,
    });
    let store = Arc::new(MemoryStore::new(stored));
    let tunnel = Arc::new(MemoryTunnel::default());
    *tunnel.status.lock().unwrap() = TunnelStatus::Running;
    let core = ClientCore::new(
        Arc::new(MockApi::new(0)),
        store.clone(),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    );

    core.complete_unbind().await.unwrap();

    let stored = store.load().unwrap().unwrap();
    assert!(stored.saved_connection.is_none());
    assert!(stored.pinned_connection.is_none());
    assert_eq!(tunnel.status().await.unwrap(), TunnelStatus::Stopped);
    assert_eq!(core.state().await.phase, Phase::NeedsPeerBinding);
}
