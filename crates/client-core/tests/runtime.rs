use async_trait::async_trait;
use nelomai_client_api::{AuthDevice, TokenResponse};
use nelomai_client_core::{
    ClientCore, ConnectOptions, CoreApi, CoreApiError, CoreError, CoreLogEvent, CoreLogger, Phase,
    RetryPolicy, StalledDataPlaneRecovery, StalledDataPlaneRecoveryOutcome,
};
use nelomai_client_storage::{
    SecretStore, StorageError, StoredAuth, StoredCompatibility, StoredConnection,
    StoredConnectionKind, StoredPendingStart,
};
use nelomai_client_tunnel::{
    TunnelController, TunnelError, TunnelMetrics, TunnelOptions, TunnelStartRequest, TunnelStatus,
};
use nelomai_contracts::{
    Access, AccessState, ApiVersion, Bootstrap, BootstrapDefaults, Connection,
    ConnectionOperationRequest, ConnectionOperationResponse, ConnectionStartRequest,
    ConnectionStartResponse, Device, Layer, LeaseStatus, PeerBinding, Platform, RouteMode,
    TicConnectionMode, UpdateState,
};
use std::collections::VecDeque;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

struct MemoryStore(Mutex<Option<StoredAuth>>);

impl MemoryStore {
    fn new(auth: StoredAuth) -> Self {
        Self(Mutex::new(Some(auth)))
    }
}

struct FailingSaveStore(Mutex<Option<StoredAuth>>);

impl FailingSaveStore {
    fn new(auth: StoredAuth) -> Self {
        Self(Mutex::new(Some(auth)))
    }
}

struct RejectDynamicCacheRemovalStore(Mutex<Option<StoredAuth>>);

impl RejectDynamicCacheRemovalStore {
    fn new(auth: StoredAuth) -> Self {
        Self(Mutex::new(Some(auth)))
    }
}

impl SecretStore for RejectDynamicCacheRemovalStore {
    fn load(&self) -> Result<Option<StoredAuth>, StorageError> {
        Ok(self.0.lock().unwrap().clone())
    }

    fn save(&self, auth: &StoredAuth) -> Result<(), StorageError> {
        let mut stored = self.0.lock().unwrap();
        let removes_existing_dynamic_cache = stored
            .as_ref()
            .is_some_and(|current| current.saved_connection.is_some())
            && auth.saved_connection.is_none();
        if removes_existing_dynamic_cache {
            return Err(StorageError::SplitTunnelStateLock);
        }
        *stored = Some(auth.clone());
        Ok(())
    }

    fn delete(&self) -> Result<(), StorageError> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}

impl SecretStore for FailingSaveStore {
    fn load(&self) -> Result<Option<StoredAuth>, StorageError> {
        Ok(self.0.lock().unwrap().clone())
    }

    fn save(&self, _auth: &StoredAuth) -> Result<(), StorageError> {
        Err(StorageError::SplitTunnelStateLock)
    }

    fn delete(&self) -> Result<(), StorageError> {
        *self.0.lock().unwrap() = None;
        Ok(())
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
    stops: AtomicUsize,
    fail_next_starts: AtomicUsize,
    fail_next_stops: AtomicUsize,
    leave_running_on_start_failure: AtomicBool,
    leave_failed_on_start_failure: AtomicBool,
    start_delay_millis: AtomicU64,
    status_failures: AtomicUsize,
    metrics_supported: AtomicBool,
    metric_successes_before_failures: AtomicUsize,
    metric_failures: AtomicUsize,
    fail_tunnel_on_metrics_error: AtomicBool,
    metrics_delay_millis: AtomicU64,
    handshake_before_rebind: AtomicBool,
    handshake_after_rebind: AtomicBool,
    zero_handshake_before_rebind: AtomicBool,
    zero_handshake_after_rebind: AtomicBool,
    rebinds: AtomicUsize,
    rebind_supported: AtomicBool,
    rebind_failures: AtomicUsize,
    rebind_delay_millis: AtomicU64,
    configuration: Mutex<Option<String>>,
    options: Mutex<Option<TunnelOptions>>,
    status: Mutex<TunnelStatus>,
}

#[async_trait]
impl TunnelController for MemoryTunnel {
    async fn start(&self, request: TunnelStartRequest) -> Result<(), TunnelError> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        let delay_millis = self.start_delay_millis.load(Ordering::SeqCst);
        if delay_millis > 0 {
            tokio::time::sleep(Duration::from_millis(delay_millis)).await;
        }
        if self
            .fail_next_starts
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            *self.status.lock().unwrap() =
                if self.leave_running_on_start_failure.load(Ordering::SeqCst) {
                    TunnelStatus::Running
                } else if self.leave_failed_on_start_failure.load(Ordering::SeqCst) {
                    TunnelStatus::Failed
                } else {
                    TunnelStatus::Stopped
                };
            return Err(TunnelError::Backend("test_start_failed".to_string()));
        }
        *self.configuration.lock().unwrap() = Some(request.configuration.expose().to_string());
        *self.options.lock().unwrap() = Some(request.options);
        *self.status.lock().unwrap() = TunnelStatus::Running;
        Ok(())
    }

    async fn stop(&self) -> Result<(), TunnelError> {
        self.stops.fetch_add(1, Ordering::SeqCst);
        if self
            .fail_next_stops
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(TunnelError::Backend("test_stop_failed".to_string()));
        }
        *self.status.lock().unwrap() = TunnelStatus::Stopped;
        Ok(())
    }

    async fn status(&self) -> Result<TunnelStatus, TunnelError> {
        if self
            .status_failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(TunnelError::Backend("service_unavailable".to_string()));
        }
        Ok(*self.status.lock().unwrap())
    }

    async fn rebind_udp(&self) -> Result<bool, TunnelError> {
        self.rebinds.fetch_add(1, Ordering::SeqCst);
        let delay_millis = self.rebind_delay_millis.load(Ordering::SeqCst);
        if delay_millis > 0 {
            tokio::time::sleep(Duration::from_millis(delay_millis)).await;
        }
        if self
            .rebind_failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(TunnelError::Backend("test_rebind_failed".to_string()));
        }
        Ok(self.rebind_supported.load(Ordering::SeqCst))
    }

    async fn metrics(&self, _probe: bool) -> Result<Option<TunnelMetrics>, TunnelError> {
        let delay_millis = self.metrics_delay_millis.load(Ordering::SeqCst);
        if delay_millis > 0 {
            tokio::time::sleep(Duration::from_millis(delay_millis)).await;
        }
        let forced_success = self
            .metric_successes_before_failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok();
        if !forced_success
            && self
                .metric_failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
        {
            if self.fail_tunnel_on_metrics_error.load(Ordering::SeqCst) {
                *self.status.lock().unwrap() = TunnelStatus::Failed;
            }
            return Err(TunnelError::Backend("test_metrics_failed".to_string()));
        }
        if !self.metrics_supported.load(Ordering::SeqCst) {
            return Ok(None);
        }
        let rebound = self.rebinds.load(Ordering::SeqCst) > 0;
        let established = if rebound {
            self.handshake_after_rebind.load(Ordering::SeqCst)
        } else {
            self.handshake_before_rebind.load(Ordering::SeqCst)
        };
        let zero_handshake = if rebound {
            self.zero_handshake_after_rebind.load(Ordering::SeqCst)
        } else {
            self.zero_handshake_before_rebind.load(Ordering::SeqCst)
        };
        Ok(Some(TunnelMetrics {
            latest_handshake_epoch_millis: if established {
                Some(1)
            } else if zero_handshake {
                Some(0)
            } else {
                None
            },
            ..TunnelMetrics::default()
        }))
    }
}

struct MockApi {
    transport_resets: AtomicUsize,
    refresh_calls: AtomicUsize,
    start_calls: AtomicUsize,
    start_failures: AtomicUsize,
    start_errors: Mutex<VecDeque<CoreApiError>>,
    operation_ids: Mutex<Vec<String>>,
    stop_calls: AtomicUsize,
    stop_failures: AtomicUsize,
    stop_error: Mutex<Option<CoreApiError>>,
    stop_operation_ids: Mutex<Vec<String>>,
    stop_failure_codes: Mutex<Vec<Option<String>>>,
    bootstrap_fails: AtomicBool,
    reject_stale_bootstrap: AtomicBool,
    reject_stale_start: AtomicBool,
    reject_stale_stop: AtomicBool,
    pinned_start: AtomicBool,
    awg3_start: AtomicBool,
    start_lease_override: Mutex<Option<String>>,
    bootstrap_connection: Mutex<Option<Connection>>,
    bootstrap_binding_without_connection: AtomicBool,
    pin_calls: AtomicUsize,
    unpin_calls: AtomicUsize,
    pin_fails: AtomicBool,
}

impl MockApi {
    fn new(start_failures: usize) -> Self {
        Self {
            transport_resets: AtomicUsize::new(0),
            refresh_calls: AtomicUsize::new(0),
            start_calls: AtomicUsize::new(0),
            start_failures: AtomicUsize::new(start_failures),
            start_errors: Mutex::new(VecDeque::new()),
            operation_ids: Mutex::new(Vec::new()),
            stop_calls: AtomicUsize::new(0),
            stop_failures: AtomicUsize::new(0),
            stop_error: Mutex::new(None),
            stop_operation_ids: Mutex::new(Vec::new()),
            stop_failure_codes: Mutex::new(Vec::new()),
            bootstrap_fails: AtomicBool::new(false),
            reject_stale_bootstrap: AtomicBool::new(false),
            reject_stale_start: AtomicBool::new(false),
            reject_stale_stop: AtomicBool::new(false),
            pinned_start: AtomicBool::new(false),
            awg3_start: AtomicBool::new(false),
            start_lease_override: Mutex::new(None),
            bootstrap_connection: Mutex::new(None),
            bootstrap_binding_without_connection: AtomicBool::new(false),
            pin_calls: AtomicUsize::new(0),
            unpin_calls: AtomicUsize::new(0),
            pin_fails: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl CoreApi for MockApi {
    fn reset_transport(&self) -> Result<(), CoreApiError> {
        self.transport_resets.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

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
        let mut response = bootstrap();
        response.connection = self.bootstrap_connection.lock().unwrap().clone();
        if response.connection.is_some()
            || self
                .bootstrap_binding_without_connection
                .load(Ordering::SeqCst)
        {
            response.binding = Some(PeerBinding {
                id: "binding-1".to_string(),
                peer_id: "peer-1".to_string(),
                interface_id: "interface-1".to_string(),
                interface_name: "Основной".to_string(),
                slot: 1,
                preferred_layer: Layer::Stray,
                tic_connection_mode: TicConnectionMode::Dynamic,
                route_mode: RouteMode::Standalone,
            });
        }
        Ok(response)
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
        if let Some(error) = self.start_errors.lock().unwrap().pop_front() {
            return Err(error);
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
        if self.awg3_start.load(Ordering::SeqCst) {
            response.configuration = awg3_configuration("tunnel-secret");
        }
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
        self.stop_failure_codes
            .lock()
            .unwrap()
            .push(request.failure_code.clone());
        if self.reject_stale_stop.load(Ordering::SeqCst) && access_token == "stale-access" {
            return Err(CoreApiError::Unauthorized);
        }
        if let Some(error) = self.stop_error.lock().unwrap().clone() {
            return Err(error);
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
        probe_url: Some("https://5a.example.test/probe".to_string()),
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

fn awg3_configuration(private_key: &str) -> String {
    format!(
        "[Interface]\nPrivateKey = {private_key}\nHeaderProtectionKey = test\nContentPaddingAddition = 0-32\n"
    )
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
async fn local_dns_servers_are_forwarded_to_the_tunnel() {
    let tunnel = Arc::new(MemoryTunnel::default());
    let core = ClientCore::new(
        Arc::new(MockApi::new(0)),
        Arc::new(MemoryStore::new(auth())),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    );
    let dns_servers = vec![
        "9.9.9.9".parse().unwrap(),
        "149.112.112.112".parse().unwrap(),
    ];
    core.set_dns_servers(dns_servers.clone());

    core.start(options(), 1_700_000_000).await.unwrap();

    assert_eq!(
        tunnel.options.lock().unwrap().as_ref().unwrap().dns_servers,
        dns_servers
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn transient_metrics_error_does_not_trigger_awg3_rebind() {
    let api = Arc::new(MockApi::new(0));
    api.awg3_start.store(true, Ordering::SeqCst);
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.metrics_supported.store(true, Ordering::SeqCst);
    tunnel.metric_failures.store(1, Ordering::SeqCst);
    tunnel.handshake_before_rebind.store(true, Ordering::SeqCst);
    let core = ClientCore::new(
        api,
        Arc::new(MemoryStore::new(auth())),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    );

    core.start(options(), 1_700_000_000).await.unwrap();

    assert_eq!(tunnel.rebinds.load(Ordering::SeqCst), 0);
    assert_eq!(core.state().await.phase, Phase::Connected);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn persistent_metrics_error_cannot_confirm_a_running_tunnel() {
    let api = Arc::new(MockApi::new(0));
    api.awg3_start.store(true, Ordering::SeqCst);
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.metric_failures.store(100, Ordering::SeqCst);
    let core = ClientCore::new(
        api.clone(),
        Arc::new(MemoryStore::new(auth())),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    );

    let error = core.start(options(), 1_700_000_000).await.unwrap_err();

    assert!(matches!(
        error,
        CoreError::Tunnel(code) if code == "test_metrics_failed"
    ));
    assert_eq!(tunnel.rebinds.load(Ordering::SeqCst), 1);
    assert_eq!(tunnel.stops.load(Ordering::SeqCst), 1);
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
    assert_eq!(api.stop_failure_codes.lock().unwrap().as_slice(), &[None]);
    assert_eq!(core.state().await.phase, Phase::Ready);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn fatal_metrics_error_is_not_reported_as_a_connected_tunnel() {
    let api = Arc::new(MockApi::new(0));
    api.awg3_start.store(true, Ordering::SeqCst);
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.metric_failures.store(100, Ordering::SeqCst);
    tunnel
        .fail_tunnel_on_metrics_error
        .store(true, Ordering::SeqCst);
    let core = ClientCore::new(
        api.clone(),
        Arc::new(MemoryStore::new(auth())),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    );

    let error = core.start(options(), 1_700_000_000).await.unwrap_err();

    assert!(matches!(
        error,
        CoreError::Tunnel(code) if code == "test_metrics_failed"
    ));
    assert_eq!(tunnel.rebinds.load(Ordering::SeqCst), 0);
    assert_eq!(tunnel.stops.load(Ordering::SeqCst), 1);
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
    assert_eq!(core.state().await.phase, Phase::Ready);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn metrics_failure_after_a_no_handshake_sample_cannot_confirm_the_tunnel() {
    let api = Arc::new(MockApi::new(0));
    api.awg3_start.store(true, Ordering::SeqCst);
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.metrics_supported.store(true, Ordering::SeqCst);
    tunnel
        .metric_successes_before_failures
        .store(1, Ordering::SeqCst);
    tunnel.metric_failures.store(100, Ordering::SeqCst);
    let core = ClientCore::new(
        api.clone(),
        Arc::new(MemoryStore::new(auth())),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    );

    let error = core.start(options(), 1_700_000_000).await.unwrap_err();

    assert!(matches!(
        error,
        CoreError::Tunnel(code) if code == "test_metrics_failed"
    ));
    assert_eq!(tunnel.rebinds.load(Ordering::SeqCst), 1);
    assert_eq!(tunnel.stops.load(Ordering::SeqCst), 1);
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
    assert_eq!(core.state().await.phase, Phase::Ready);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn hung_metrics_call_is_bounded_and_cannot_confirm_the_tunnel() {
    let api = Arc::new(MockApi::new(0));
    api.awg3_start.store(true, Ordering::SeqCst);
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.metrics_delay_millis.store(30_000, Ordering::SeqCst);
    let core = ClientCore::new(
        api.clone(),
        Arc::new(MemoryStore::new(auth())),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    );
    let started = tokio::time::Instant::now();

    let error = core.start(options(), 1_700_000_000).await.unwrap_err();

    assert!(started.elapsed() < Duration::from_secs(4));
    assert!(matches!(
        error,
        CoreError::Tunnel(code) if code == "tunnel_metrics_timeout"
    ));
    assert_eq!(tunnel.rebinds.load(Ordering::SeqCst), 1);
    assert_eq!(tunnel.stops.load(Ordering::SeqCst), 1);
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
    assert_eq!(core.state().await.phase, Phase::Ready);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn awg3_start_rebinds_once_and_recovers_the_handshake() {
    let api = Arc::new(MockApi::new(0));
    api.awg3_start.store(true, Ordering::SeqCst);
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.metrics_supported.store(true, Ordering::SeqCst);
    tunnel.rebind_supported.store(true, Ordering::SeqCst);
    tunnel.handshake_after_rebind.store(true, Ordering::SeqCst);
    let core = ClientCore::new(
        api,
        Arc::new(MemoryStore::new(auth())),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    );

    core.start(options(), 1_700_000_000).await.unwrap();

    assert_eq!(tunnel.rebinds.load(Ordering::SeqCst), 1);
    assert_eq!(core.state().await.phase, Phase::Connected);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn zero_handshake_timestamp_cannot_confirm_an_awg3_tunnel() {
    let api = Arc::new(MockApi::new(0));
    api.awg3_start.store(true, Ordering::SeqCst);
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.metrics_supported.store(true, Ordering::SeqCst);
    tunnel
        .zero_handshake_before_rebind
        .store(true, Ordering::SeqCst);
    tunnel.rebind_supported.store(true, Ordering::SeqCst);
    tunnel.handshake_after_rebind.store(true, Ordering::SeqCst);
    let core = ClientCore::new(
        api,
        Arc::new(MemoryStore::new(auth())),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    );

    core.start(options(), 1_700_000_000).await.unwrap();

    assert_eq!(tunnel.rebinds.load(Ordering::SeqCst), 1);
    assert_eq!(core.state().await.phase, Phase::Connected);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn zero_handshake_timestamp_after_rebind_still_fails_the_awg3_tunnel() {
    let api = Arc::new(MockApi::new(0));
    api.awg3_start.store(true, Ordering::SeqCst);
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.metrics_supported.store(true, Ordering::SeqCst);
    tunnel.rebind_supported.store(true, Ordering::SeqCst);
    tunnel
        .zero_handshake_after_rebind
        .store(true, Ordering::SeqCst);
    let store = Arc::new(MemoryStore::new(auth()));
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    );

    let error = core.start(options(), 1_700_000_000).await.unwrap_err();

    assert!(matches!(
        error,
        CoreError::Tunnel(code) if code == "tunnel_handshake_timeout"
    ));
    assert_eq!(tunnel.rebinds.load(Ordering::SeqCst), 1);
    assert_eq!(tunnel.stops.load(Ordering::SeqCst), 1);
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
    assert_eq!(core.state().await.phase, Phase::Ready);
    assert!(store.load().unwrap().unwrap().saved_connection.is_none());
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn slow_successful_metrics_poll_still_reaches_handshake_recovery() {
    let api = Arc::new(MockApi::new(0));
    api.awg3_start.store(true, Ordering::SeqCst);
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.metrics_supported.store(true, Ordering::SeqCst);
    tunnel.metrics_delay_millis.store(50, Ordering::SeqCst);
    tunnel.rebind_supported.store(true, Ordering::SeqCst);
    tunnel.handshake_after_rebind.store(true, Ordering::SeqCst);
    let core = ClientCore::new(
        api,
        Arc::new(MemoryStore::new(auth())),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    );

    core.start(options(), 1_700_000_000).await.unwrap();

    assert_eq!(tunnel.rebinds.load(Ordering::SeqCst), 1);
    assert_eq!(core.state().await.phase, Phase::Connected);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn healthy_metrics_after_rebind_replace_the_initial_metrics_error() {
    let api = Arc::new(MockApi::new(0));
    api.awg3_start.store(true, Ordering::SeqCst);
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.metrics_supported.store(true, Ordering::SeqCst);
    tunnel.metric_failures.store(10, Ordering::SeqCst);
    tunnel.rebind_supported.store(true, Ordering::SeqCst);
    let core = ClientCore::new(
        api.clone(),
        Arc::new(MemoryStore::new(auth())),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    );

    let error = core.start(options(), 1_700_000_000).await.unwrap_err();

    assert!(matches!(
        error,
        CoreError::Tunnel(code) if code == "tunnel_handshake_timeout"
    ));
    assert_eq!(tunnel.rebinds.load(Ordering::SeqCst), 1);
    assert_eq!(tunnel.stops.load(Ordering::SeqCst), 1);
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
    assert_eq!(core.state().await.phase, Phase::Ready);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn awg3_start_stops_and_releases_the_lease_when_handshake_never_appears() {
    let api = Arc::new(MockApi::new(0));
    api.awg3_start.store(true, Ordering::SeqCst);
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.metrics_supported.store(true, Ordering::SeqCst);
    tunnel.rebind_supported.store(true, Ordering::SeqCst);
    let store = Arc::new(MemoryStore::new(auth()));
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    );

    let error = core.start(options(), 1_700_000_000).await.unwrap_err();

    assert!(matches!(
        error,
        CoreError::Tunnel(code) if code == "tunnel_handshake_timeout"
    ));
    assert_eq!(tunnel.rebinds.load(Ordering::SeqCst), 1);
    assert_eq!(tunnel.stops.load(Ordering::SeqCst), 1);
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        api.stop_failure_codes.lock().unwrap().as_slice(),
        &[Some("tunnel_handshake_timeout".to_string())]
    );
    assert_eq!(core.state().await.phase, Phase::Ready);
    assert!(store.load().unwrap().unwrap().saved_connection.is_none());
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn handshake_timeout_surfaces_dynamic_cache_reconciliation_failure() {
    let api = Arc::new(MockApi::new(0));
    api.awg3_start.store(true, Ordering::SeqCst);
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.metrics_supported.store(true, Ordering::SeqCst);
    tunnel.rebind_supported.store(true, Ordering::SeqCst);
    let logger = Arc::new(MemoryLogger::default());
    let store = Arc::new(RejectDynamicCacheRemovalStore::new(auth()));
    let core = ClientCore::new(api, store.clone(), tunnel, logger.clone());

    let error = core.start(options(), 1_700_000_000).await.unwrap_err();

    assert!(matches!(error, CoreError::Storage));
    assert!(store.load().unwrap().unwrap().saved_connection.is_some());
    assert!(logger
        .0
        .lock()
        .unwrap()
        .iter()
        .any(|event| event.kind == "connection.start_compensation_storage_failed"));
    assert!(matches!(
        core.start_saved_stray_offline(1_700_000_000).await,
        Err(CoreError::SavedConnectionUnavailable)
    ));
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn pinned_awg3_handshake_timeout_blocks_offline_cache_until_online_reissue() {
    let api = Arc::new(MockApi::new(0));
    api.awg3_start.store(true, Ordering::SeqCst);
    api.pinned_start.store(true, Ordering::SeqCst);
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.metrics_supported.store(true, Ordering::SeqCst);
    tunnel.rebind_supported.store(true, Ordering::SeqCst);
    let store = Arc::new(MemoryStore::new(auth()));
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        tunnel,
        Arc::new(MemoryLogger::default()),
    );

    let error = core.start(options(), 1_700_000_000).await.unwrap_err();

    assert!(matches!(
        error,
        CoreError::Tunnel(code) if code == "tunnel_handshake_timeout"
    ));
    let stored = store.load().unwrap().unwrap();
    let pinned = stored.pinned_connection.unwrap();
    let retry_not_before = pinned.valid_until_unix.unwrap();
    assert!(retry_not_before > 1_700_000_000);
    assert!(matches!(
        core.start_saved_stray_offline(retry_not_before - 1).await,
        Err(CoreError::SavedConnectionUnavailable)
    ));
    assert!(matches!(
        core.start_saved_stray_offline(retry_not_before).await,
        Err(CoreError::SavedConnectionUnavailable)
    ));
    assert!(matches!(
        core.start(options(), retry_not_before).await,
        Err(CoreError::Tunnel(code)) if code == "tunnel_handshake_timeout"
    ));
    let operation_ids = api.operation_ids.lock().unwrap();
    assert_eq!(operation_ids.len(), 2);
    assert_eq!(operation_ids[0], operation_ids[1]);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn awg3_rebind_has_a_bounded_window() {
    let api = Arc::new(MockApi::new(0));
    api.awg3_start.store(true, Ordering::SeqCst);
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.metrics_supported.store(true, Ordering::SeqCst);
    tunnel.rebind_supported.store(true, Ordering::SeqCst);
    tunnel.rebind_delay_millis.store(10_000, Ordering::SeqCst);
    let core = ClientCore::new(
        api,
        Arc::new(MemoryStore::new(auth())),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    );
    let started = tokio::time::Instant::now();

    let error = core.start(options(), 1_700_000_000).await.unwrap_err();

    assert!(matches!(
        error,
        CoreError::Tunnel(code) if code == "udp_rebind_timeout"
    ));
    assert!(started.elapsed() < Duration::from_secs(6));
    assert_eq!(tunnel.rebinds.load(Ordering::SeqCst), 1);
    assert_eq!(tunnel.stops.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn slow_rebind_still_gets_a_separate_post_rebind_handshake_window() {
    let api = Arc::new(MockApi::new(0));
    api.awg3_start.store(true, Ordering::SeqCst);
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.metrics_supported.store(true, Ordering::SeqCst);
    tunnel.metrics_delay_millis.store(200, Ordering::SeqCst);
    tunnel.rebind_supported.store(true, Ordering::SeqCst);
    tunnel.rebind_delay_millis.store(2_900, Ordering::SeqCst);
    tunnel.handshake_after_rebind.store(true, Ordering::SeqCst);
    let logger = Arc::new(MemoryLogger::default());
    let core = ClientCore::new(
        api,
        Arc::new(MemoryStore::new(auth())),
        tunnel.clone(),
        logger.clone(),
    );

    core.start(options(), 1_700_000_000).await.unwrap();

    assert_eq!(tunnel.rebinds.load(Ordering::SeqCst), 1);
    assert!(logger
        .0
        .lock()
        .unwrap()
        .iter()
        .any(|event| event.kind == "connection.handshake_recovered"));
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn awg3_rebind_backend_error_is_preserved_for_service_recovery() {
    let api = Arc::new(MockApi::new(0));
    api.awg3_start.store(true, Ordering::SeqCst);
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.metrics_supported.store(true, Ordering::SeqCst);
    tunnel.rebind_failures.store(1, Ordering::SeqCst);
    let core = ClientCore::new(
        api.clone(),
        Arc::new(MemoryStore::new(auth())),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    );

    let error = core.start(options(), 1_700_000_000).await.unwrap_err();

    assert!(matches!(
        error,
        CoreError::Tunnel(code) if code == "test_rebind_failed"
    ));
    assert_eq!(tunnel.stops.load(Ordering::SeqCst), 1);
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn online_awg3_cleanup_failure_is_returned_and_remains_stoppable() {
    let api = Arc::new(MockApi::new(0));
    api.awg3_start.store(true, Ordering::SeqCst);
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.metrics_supported.store(true, Ordering::SeqCst);
    tunnel.fail_next_stops.store(1, Ordering::SeqCst);
    let logger = Arc::new(MemoryLogger::default());
    let store = Arc::new(MemoryStore::new(auth()));
    let core = ClientCore::new(api.clone(), store.clone(), tunnel.clone(), logger.clone());

    let error = core.start(options(), 1_700_000_000).await.unwrap_err();

    assert!(matches!(
        error,
        CoreError::Tunnel(code) if code == "test_stop_failed"
    ));
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        api.stop_failure_codes.lock().unwrap().as_slice(),
        &[Some("tunnel_handshake_timeout".to_string())]
    );
    assert!(store.load().unwrap().unwrap().saved_connection.is_none());
    assert_eq!(core.state().await.phase, Phase::Stopping);
    assert!(logger
        .0
        .lock()
        .unwrap()
        .iter()
        .any(|event| event.kind == "connection.handshake_cleanup_failed"));
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
async fn sign_out_cannot_be_undone_by_an_in_flight_token_refresh() {
    let api = Arc::new(MockApi::new(0));
    let store = Arc::new(MemoryStore::new(auth()));
    let core = Arc::new(ClientCore::new(
        api.clone(),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    ));

    let refresh_core = core.clone();
    let refresh =
        tokio::spawn(async move { refresh_core.refresh_access_token("stale-access").await });
    while api.refresh_calls.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }

    core.sign_out().await.unwrap();
    assert_eq!(refresh.await.unwrap().unwrap(), "fresh-access");

    let stored = store.load().unwrap().unwrap();
    assert!(stored.access_token.is_none());
    assert!(stored.refresh_token.is_none());
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
    let store = Arc::new(MemoryStore::new(auth()));
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    );

    core.start(options(), 1_700_000_000).await.unwrap();

    assert_eq!(api.refresh_calls.load(Ordering::SeqCst), 1);
    let operation_ids = api.operation_ids.lock().unwrap();
    assert_eq!(operation_ids.len(), 2);
    assert_eq!(operation_ids[0], operation_ids[1]);
    let stored = store.load().unwrap().unwrap();
    assert_eq!(stored.access_token.as_deref(), Some("fresh-access"));
    assert_eq!(stored.refresh_token.as_deref(), Some("fresh-refresh"));
    assert!(stored.saved_connection.is_some());
}

#[tokio::test(flavor = "current_thread")]
async fn local_start_failure_stops_the_panel_lease_and_returns_to_ready() {
    let api = Arc::new(MockApi::new(0));
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.fail_next_starts.store(1, Ordering::SeqCst);
    let logger = Arc::new(MemoryLogger::default());
    let core = ClientCore::new(
        api.clone(),
        Arc::new(MemoryStore::new(auth())),
        tunnel.clone(),
        logger.clone(),
    )
    .with_retry_policy(RetryPolicy::new(Vec::new()));

    let error = core.start(options(), 1_700_000_000).await.unwrap_err();

    assert!(error.to_string().contains("test_start_failed"));
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
    assert_eq!(core.state().await.phase, Phase::Ready);
    assert_eq!(
        core.state().await.connection.unwrap().status,
        LeaseStatus::Warm
    );
    assert_eq!(*tunnel.status.lock().unwrap(), TunnelStatus::Stopped);
    assert!(logger
        .0
        .lock()
        .unwrap()
        .iter()
        .any(|event| event.kind == "connection.local_start_failed"));
}

#[tokio::test(flavor = "current_thread")]
async fn partial_local_start_failure_is_cleaned_up_by_a_later_stop_retry() {
    let api = Arc::new(MockApi::new(0));
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.fail_next_starts.store(1, Ordering::SeqCst);
    tunnel
        .leave_running_on_start_failure
        .store(true, Ordering::SeqCst);
    let core = ClientCore::new(
        api.clone(),
        Arc::new(MemoryStore::new(auth())),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    )
    .with_retry_policy(RetryPolicy::new(Vec::new()));

    core.start(options(), 1_700_000_000).await.unwrap_err();

    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
    assert_eq!(core.state().await.phase, Phase::Stopping);
    core.stop().await.unwrap();
    assert_eq!(tunnel.stops.load(Ordering::SeqCst), 1);
    assert_eq!(core.state().await.phase, Phase::Ready);
}

#[tokio::test(flavor = "current_thread")]
async fn failed_local_status_is_cleaned_up_by_a_later_stop_retry() {
    let api = Arc::new(MockApi::new(0));
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.fail_next_starts.store(1, Ordering::SeqCst);
    tunnel
        .leave_failed_on_start_failure
        .store(true, Ordering::SeqCst);
    let core = ClientCore::new(
        api.clone(),
        Arc::new(MemoryStore::new(auth())),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    )
    .with_retry_policy(RetryPolicy::new(Vec::new()));

    core.start(options(), 1_700_000_000).await.unwrap_err();

    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
    assert_eq!(core.state().await.phase, Phase::Stopping);
    core.stop().await.unwrap();
    assert_eq!(tunnel.stops.load(Ordering::SeqCst), 1);
    assert_eq!(core.state().await.phase, Phase::Ready);
}

#[tokio::test(flavor = "current_thread")]
async fn storage_failure_before_start_never_allocates_a_panel_lease() {
    let api = Arc::new(MockApi::new(0));
    let tunnel = Arc::new(MemoryTunnel::default());
    let logger = Arc::new(MemoryLogger::default());
    let core = ClientCore::new(
        api.clone(),
        Arc::new(FailingSaveStore::new(auth())),
        tunnel.clone(),
        logger.clone(),
    )
    .with_retry_policy(RetryPolicy::new(Vec::new()));

    let error = core.start(options(), 1_700_000_000).await.unwrap_err();

    assert!(matches!(error, nelomai_client_core::CoreError::Storage));
    assert_eq!(api.start_calls.load(Ordering::SeqCst), 0);
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 0);
    assert_eq!(tunnel.starts.load(Ordering::SeqCst), 0);
    assert!(core.state().await.connection.is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn interrupted_start_reuses_its_durable_operation_id() {
    let api = Arc::new(MockApi::new(0));
    let mut stored_auth = auth();
    stored_auth.pending_start = Some(StoredPendingStart {
        operation_id: "pending-operation".to_string(),
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
    });
    let store = Arc::new(MemoryStore::new(stored_auth));
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    );

    core.start(options(), 1_700_000_000).await.unwrap();

    assert_eq!(
        api.operation_ids.lock().unwrap().as_slice(),
        ["pending-operation"]
    );
    assert!(store.load().unwrap().unwrap().pending_start.is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn recovered_fixed_start_uses_a_new_operation_after_stale_cleanup() {
    let api = Arc::new(MockApi::new(0));
    api.stop_failures.store(1, Ordering::SeqCst);
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.fail_next_starts.store(1, Ordering::SeqCst);
    let store = Arc::new(MemoryStore::new(auth()));
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        tunnel,
        Arc::new(MemoryLogger::default()),
    )
    .with_retry_policy(RetryPolicy::new(Vec::new()));
    let fixed = ConnectOptions {
        layer: Layer::Tic,
        tic_connection_mode: TicConnectionMode::Personal,
        route_mode: RouteMode::ViaTak,
        probes: Vec::new(),
        allow_alternate: false,
    };

    core.start(fixed.clone(), 1_700_000_000).await.unwrap_err();
    assert!(store.load().unwrap().unwrap().pending_start.is_some());

    core.start(fixed, 1_700_000_001).await.unwrap();

    let operation_ids = api.operation_ids.lock().unwrap();
    assert_eq!(operation_ids.len(), 2);
    assert_ne!(operation_ids[0], operation_ids[1]);
    assert!(store.load().unwrap().unwrap().pending_start.is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn failed_start_request_never_leaves_the_core_connecting() {
    let api = Arc::new(MockApi::new(1));
    let store = Arc::new(MemoryStore::new(auth()));
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    )
    .with_retry_policy(RetryPolicy::new(Vec::new()));

    core.start(options(), 1_700_000_000).await.unwrap_err();

    assert_eq!(core.state().await.phase, Phase::ServerUnavailable);
    let pending_operation = store
        .load()
        .unwrap()
        .unwrap()
        .pending_start
        .unwrap()
        .operation_id;

    core.start(options(), 1_700_000_001).await.unwrap();

    assert_eq!(
        api.operation_ids.lock().unwrap().as_slice(),
        [pending_operation.as_str(), pending_operation.as_str()]
    );
    assert!(store.load().unwrap().unwrap().pending_start.is_none());
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

    assert_eq!(api.transport_resets.load(Ordering::SeqCst), 1);
    assert_eq!(api.refresh_calls.load(Ordering::SeqCst), 1);
    {
        let operation_ids = api.stop_operation_ids.lock().unwrap();
        assert_eq!(operation_ids.len(), 2);
        assert_eq!(operation_ids[0], operation_ids[1]);
    }
    assert_eq!(core.state().await.phase, Phase::Ready);
}

#[tokio::test(flavor = "current_thread")]
async fn failed_panel_stop_can_be_retried_after_the_local_tunnel_is_stopped() {
    let api = Arc::new(MockApi::new(0));
    api.stop_failures.store(1, Ordering::SeqCst);
    let tunnel = Arc::new(MemoryTunnel::default());
    let core = ClientCore::new(
        api.clone(),
        Arc::new(MemoryStore::new(auth())),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    )
    .with_retry_policy(RetryPolicy::new(Vec::new()));
    core.start(options(), 1_700_000_000).await.unwrap();

    assert!(core.stop().await.is_err());
    assert_eq!(core.state().await.phase, Phase::Stopping);

    core.stop().await.unwrap();

    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 2);
    assert_eq!(tunnel.stops.load(Ordering::SeqCst), 1);
    assert_eq!(core.state().await.phase, Phase::Ready);
}

#[tokio::test(flavor = "current_thread")]
async fn failed_local_stop_stays_pending_and_can_be_retried() {
    let api = Arc::new(MockApi::new(0));
    let tunnel = Arc::new(MemoryTunnel::default());
    let core = ClientCore::new(
        api.clone(),
        Arc::new(MemoryStore::new(auth())),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    );
    core.start(options(), 1_700_000_000).await.unwrap();
    tunnel.fail_next_stops.store(1, Ordering::SeqCst);

    assert!(core.stop().await.is_err());
    assert_eq!(core.state().await.phase, Phase::Stopping);
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 0);
    assert_eq!(api.transport_resets.load(Ordering::SeqCst), 0);

    core.stop().await.unwrap();

    assert_eq!(tunnel.stops.load(Ordering::SeqCst), 2);
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
    assert_eq!(api.transport_resets.load(Ordering::SeqCst), 1);
    assert_eq!(core.state().await.phase, Phase::Ready);
}

#[tokio::test(flavor = "current_thread")]
async fn start_releases_an_active_panel_connection_left_without_a_local_tunnel() {
    let api = Arc::new(MockApi::new(0));
    *api.bootstrap_connection.lock().unwrap() = Some(Connection {
        status: LeaseStatus::Connected,
        ..connection("11111111-1111-4111-8111-111111111111")
    });
    let tunnel = Arc::new(MemoryTunnel::default());
    let logger = Arc::new(MemoryLogger::default());
    let core = ClientCore::new(
        api.clone(),
        Arc::new(MemoryStore::new(auth())),
        tunnel,
        logger.clone(),
    );
    core.bootstrap(1_700_000_000).await.unwrap();
    assert_eq!(core.state().await.phase, Phase::Ready);

    core.start(options(), 1_700_000_001).await.unwrap();

    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
    assert_eq!(api.start_calls.load(Ordering::SeqCst), 1);
    assert!(logger
        .0
        .lock()
        .unwrap()
        .iter()
        .any(|event| event.kind == "connection.stale_released"));
}

#[tokio::test(flavor = "current_thread")]
async fn binding_change_releases_an_active_panel_connection_without_a_local_tunnel() {
    let api = Arc::new(MockApi::new(0));
    *api.bootstrap_connection.lock().unwrap() = Some(Connection {
        status: LeaseStatus::Issued,
        ..connection("11111111-1111-4111-8111-111111111111")
    });
    let core = ClientCore::new(
        api.clone(),
        Arc::new(MemoryStore::new(auth())),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    );
    core.bootstrap(1_700_000_000).await.unwrap();

    core.prepare_binding_change().await.unwrap();

    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
    assert_eq!(core.state().await.phase, Phase::Ready);
    assert!(matches!(
        core.state().await.connection.unwrap().status,
        LeaseStatus::Warm | LeaseStatus::Released
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn start_keeps_a_warm_panel_connection_available_for_reuse() {
    let api = Arc::new(MockApi::new(0));
    *api.bootstrap_connection.lock().unwrap() = Some(Connection {
        status: LeaseStatus::Warm,
        stopped_at: Some("2026-07-26T10:00:00Z".to_string()),
        ..connection("11111111-1111-4111-8111-111111111111")
    });
    let core = ClientCore::new(
        api.clone(),
        Arc::new(MemoryStore::new(auth())),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    );
    core.bootstrap(1_700_000_000).await.unwrap();

    core.start(options(), 1_700_000_001).await.unwrap();

    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 0);
    assert_eq!(api.start_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn stop_always_stops_a_running_device_tunnel_when_the_panel_lease_is_finished() {
    let api = Arc::new(MockApi::new(0));
    let tunnel = Arc::new(MemoryTunnel::default());
    *tunnel.status.lock().unwrap() = TunnelStatus::Running;
    let released = Connection {
        status: LeaseStatus::Released,
        stopped_at: Some("2026-07-31T10:00:00Z".to_string()),
        ..connection("11111111-1111-4111-8111-111111111111")
    };
    *api.bootstrap_connection.lock().unwrap() = Some(released.clone());
    let core = ClientCore::new(
        api.clone(),
        Arc::new(MemoryStore::new(auth())),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    );
    core.bootstrap(1_700_000_000).await.unwrap();
    assert_eq!(core.state().await.phase, Phase::Connected);

    let stopped = core.stop().await.unwrap();

    assert_eq!(stopped, released);
    assert_eq!(tunnel.stops.load(Ordering::SeqCst), 1);
    assert_eq!(*tunnel.status.lock().unwrap(), TunnelStatus::Stopped);
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 0);
    assert_eq!(core.state().await.phase, Phase::Ready);
}

#[tokio::test(flavor = "current_thread")]
async fn external_quick_action_reconciles_the_local_tunnel_without_panel_operations() {
    let api = Arc::new(MockApi::new(0));
    let tunnel = Arc::new(MemoryTunnel::default());
    let core = ClientCore::new(
        api.clone(),
        Arc::new(MemoryStore::new(auth())),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    );
    core.start(options(), 1_700_000_000).await.unwrap();
    *tunnel.status.lock().unwrap() = TunnelStatus::Stopped;

    let stopped = core.reconcile_external_tunnel_state().await;

    assert_eq!(stopped.phase, Phase::Ready);
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 0);

    *tunnel.status.lock().unwrap() = TunnelStatus::Running;
    let started = core.reconcile_external_tunnel_state().await;

    assert_eq!(started.phase, Phase::Connected);
    assert_eq!(api.start_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn bootstrap_recovers_configuration_after_external_quick_start_changes_lease() {
    let api = Arc::new(MockApi::new(0));
    let fresh_connection = connection("22222222-2222-4222-8222-222222222222");
    *api.bootstrap_connection.lock().unwrap() = Some(fresh_connection.clone());
    let tunnel = Arc::new(MemoryTunnel::default());
    *tunnel.status.lock().unwrap() = TunnelStatus::Running;
    let mut stored = auth();
    stored.saved_connection = Some(StoredConnection {
        lease_id: "11111111-1111-4111-8111-111111111111".to_string(),
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        probe_url: Some("https://old.example.test/probe".to_string()),
        kind: StoredConnectionKind::DynamicWarm,
        configuration: "PrivateKey = stale-secret".to_string(),
        valid_until_unix: Some(1_700_003_600),
    });
    let store = Arc::new(MemoryStore::new(stored));
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        tunnel,
        Arc::new(MemoryLogger::default()),
    );

    core.bootstrap(1_700_000_000).await.unwrap();

    assert_eq!(core.state().await.connection, Some(fresh_connection));
    let saved = store
        .load()
        .unwrap()
        .unwrap()
        .saved_connection
        .expect("configuration recovered for the running lease");
    assert_eq!(saved.lease_id, "22222222-2222-4222-8222-222222222222");
    assert_eq!(
        saved.configuration,
        "[Interface]\nPrivateKey = tunnel-secret\n"
    );
    assert_eq!(api.start_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        api.operation_ids.lock().unwrap().as_slice(),
        ["22222222-2222-4222-8222-222222222222"]
    );
}

#[tokio::test(flavor = "current_thread")]
async fn saved_quick_connection_keeps_its_metrics_context() {
    let api = Arc::new(MockApi::new(0));
    let tunnel = Arc::new(MemoryTunnel::default());
    let core = ClientCore::new(
        api,
        Arc::new(MemoryStore::new(auth())),
        tunnel,
        Arc::new(MemoryLogger::default()),
    );
    let started = core.start(options(), 1_700_000_000).await.unwrap();

    let context = core
        .connection_metrics_context()
        .await
        .expect("saved connection metrics context");

    assert_eq!(context.session_id, started.lease_id);
    assert_eq!(context.probe_url, started.probe_url);
}

#[tokio::test(flavor = "current_thread")]
async fn running_quick_tunnel_uses_saved_metrics_context_after_bootstrap() {
    let api = Arc::new(MockApi::new(0));
    api.bootstrap_binding_without_connection
        .store(true, Ordering::SeqCst);
    let tunnel = Arc::new(MemoryTunnel::default());
    *tunnel.status.lock().unwrap() = TunnelStatus::Running;
    let mut stored = auth();
    stored.saved_connection = Some(StoredConnection {
        lease_id: "quick-lease".to_string(),
        layer: Layer::Tic,
        tic_connection_mode: TicConnectionMode::Personal,
        route_mode: RouteMode::ViaTak,
        probe_url: Some("https://1b.example.test/probe".to_string()),
        kind: StoredConnectionKind::Fixed,
        configuration: "[Interface]\nPrivateKey = tunnel-secret\n".to_string(),
        valid_until_unix: None,
    });
    let core = ClientCore::new(
        api,
        Arc::new(MemoryStore::new(stored)),
        tunnel,
        Arc::new(MemoryLogger::default()),
    );

    core.bootstrap(1_700_000_000).await.unwrap();
    let state = core.state().await;
    let context = core
        .connection_metrics_context()
        .await
        .expect("quick tunnel metrics context after bootstrap");

    assert_eq!(state.phase, Phase::Connected);
    assert_eq!(state.connection, None);
    assert_eq!(context.session_id, "quick-lease");
    assert_eq!(
        context.probe_url.as_deref(),
        Some("https://1b.example.test/probe")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn failed_fixed_runtime_requires_cleanup_before_it_can_start_again() {
    let api = Arc::new(MockApi::new(0));
    let tunnel = Arc::new(MemoryTunnel::default());
    let core = ClientCore::new(
        api.clone(),
        Arc::new(MemoryStore::new(auth())),
        tunnel.clone(),
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
    *tunnel.status.lock().unwrap() = TunnelStatus::Failed;

    let state = core.state().await;

    assert_eq!(state.phase, Phase::Stopping);
    assert_eq!(
        core.split_tunnel_warning().await.as_deref(),
        Some("tunnel_runtime_stopped")
    );
    core.stop().await.unwrap();
    assert_eq!(tunnel.stops.load(Ordering::SeqCst), 1);
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
    assert_eq!(core.state().await.phase, Phase::Ready);

    core.start(options, 1_700_000_100).await.unwrap();
    assert_eq!(api.start_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "current_thread")]
async fn state_preserves_connected_during_transient_tunnel_status_failure() {
    let api = Arc::new(MockApi::new(0));
    let tunnel = Arc::new(MemoryTunnel::default());
    let logger = Arc::new(MemoryLogger::default());
    let core = ClientCore::new(
        api,
        Arc::new(MemoryStore::new(auth())),
        tunnel.clone(),
        logger.clone(),
    );
    core.start(options(), 1_700_000_000).await.unwrap();
    tunnel.status_failures.store(1, Ordering::SeqCst);

    let state = core.state().await;

    assert_eq!(state.phase, Phase::Connected);
    assert_eq!(
        core.split_tunnel_warning().await.as_deref(),
        Some("tunnel_status_unavailable")
    );
    assert!(logger
        .0
        .lock()
        .unwrap()
        .iter()
        .any(|event| event.kind == "tunnel.status.unavailable"));

    assert_eq!(core.state().await.phase, Phase::Connected);
    assert_ne!(
        core.split_tunnel_warning().await.as_deref(),
        Some("tunnel_status_unavailable")
    );
    assert_eq!(
        logger
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.kind == "tunnel.status.unavailable")
            .count(),
        1
    );
}

#[tokio::test(flavor = "current_thread")]
async fn access_expiry_during_stop_is_not_overwritten_by_retry_state() {
    let api = Arc::new(MockApi::new(0));
    *api.stop_error.lock().unwrap() = Some(CoreApiError::AccessExpired);
    let tunnel = Arc::new(MemoryTunnel::default());
    let core = ClientCore::new(
        api,
        Arc::new(MemoryStore::new(auth())),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    );
    core.start(options(), 1_700_000_000).await.unwrap();

    let error = core.stop().await.unwrap_err();

    assert!(matches!(
        error,
        nelomai_client_core::CoreError::AccessExpired
    ));
    assert_eq!(core.state().await.phase, Phase::AccessExpired);
    assert_eq!(tunnel.stops.load(Ordering::SeqCst), 1);
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
async fn finished_tic_start_operation_is_replaced_once() {
    let api = Arc::new(MockApi::new(0));
    api.start_errors
        .lock()
        .unwrap()
        .push_back(CoreApiError::Rejected {
            code: "connection_no_longer_active".to_string(),
            message: "Это подключение уже завершено. Начните новое.".to_string(),
        });
    let store = Arc::new(MemoryStore::new(auth()));
    let logger = Arc::new(MemoryLogger::default());
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        logger.clone(),
    )
    .with_retry_policy(RetryPolicy::new(Vec::new()));
    let fixed = ConnectOptions {
        layer: Layer::Tic,
        tic_connection_mode: TicConnectionMode::Personal,
        route_mode: RouteMode::ViaTak,
        probes: Vec::new(),
        allow_alternate: false,
    };

    core.start(fixed, 1_700_000_000).await.unwrap();

    let operation_ids = api.operation_ids.lock().unwrap();
    assert_eq!(operation_ids.len(), 2);
    assert_ne!(operation_ids[0], operation_ids[1]);
    assert!(store.load().unwrap().unwrap().pending_start.is_none());
    assert!(logger
        .0
        .lock()
        .unwrap()
        .iter()
        .any(|event| event.kind == "connection.start_operation_replaced"));
}

#[tokio::test(flavor = "current_thread")]
async fn finished_stray_start_operation_is_replaced_once() {
    let api = Arc::new(MockApi::new(0));
    api.start_errors
        .lock()
        .unwrap()
        .push_back(CoreApiError::Rejected {
            code: "connection_no_longer_active".to_string(),
            message: "Это подключение уже завершено. Начните новое.".to_string(),
        });
    let store = Arc::new(MemoryStore::new(auth()));
    let logger = Arc::new(MemoryLogger::default());
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        logger.clone(),
    )
    .with_retry_policy(RetryPolicy::new(Vec::new()));

    core.start(options(), 1_700_000_000).await.unwrap();

    let operation_ids = api.operation_ids.lock().unwrap();
    assert_eq!(operation_ids.len(), 2);
    assert_ne!(operation_ids[0], operation_ids[1]);
    assert!(store.load().unwrap().unwrap().pending_start.is_none());
    assert!(logger
        .0
        .lock()
        .unwrap()
        .iter()
        .any(|event| event.kind == "connection.start_operation_replaced"));
}

#[tokio::test(flavor = "current_thread")]
async fn configuration_fetch_failure_does_not_retry_a_finished_operation() {
    let api = Arc::new(MockApi::new(0));
    api.start_errors
        .lock()
        .unwrap()
        .push_back(CoreApiError::Rejected {
            code: "configuration_fetch_failed".to_string(),
            message: "Не удалось получить конфигурацию. Повторите попытку.".to_string(),
        });
    let store = Arc::new(MemoryStore::new(auth()));
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    )
    .with_retry_policy(RetryPolicy::new(vec![0, 0, 0]));

    let error = core.start(options(), 1_700_000_000).await.unwrap_err();

    assert!(error.to_string().contains("configuration_fetch_failed"));
    assert_eq!(api.start_calls.load(Ordering::SeqCst), 1);
    assert!(store.load().unwrap().unwrap().pending_start.is_none());
    assert_eq!(core.state().await.phase, Phase::ServerUnavailable);
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

#[tokio::test]
async fn stalled_data_plane_recovery_rebinds_then_restarts_only_the_local_tunnel() {
    let api = Arc::new(MockApi::new(0));
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.rebind_supported.store(true, Ordering::SeqCst);
    let core = ClientCore::new(
        api.clone(),
        Arc::new(MemoryStore::new(auth())),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    );
    let connection = core.start(options(), 1_700_000_000).await.unwrap();

    assert_eq!(
        core.recover_stalled_data_plane(&connection.lease_id, StalledDataPlaneRecovery::RebindUdp,)
            .await
            .unwrap(),
        StalledDataPlaneRecoveryOutcome::Rebound,
    );
    assert_eq!(tunnel.rebinds.load(Ordering::SeqCst), 1);
    assert_eq!(tunnel.starts.load(Ordering::SeqCst), 1);
    assert_eq!(tunnel.stops.load(Ordering::SeqCst), 0);

    assert_eq!(
        core.recover_stalled_data_plane(
            &connection.lease_id,
            StalledDataPlaneRecovery::RestartLocalTunnel,
        )
        .await
        .unwrap(),
        StalledDataPlaneRecoveryOutcome::Reconnected,
    );
    assert_eq!(tunnel.starts.load(Ordering::SeqCst), 2);
    assert_eq!(tunnel.stops.load(Ordering::SeqCst), 1);
    assert_eq!(api.start_calls.load(Ordering::SeqCst), 1);
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 0);
    assert_eq!(core.state().await.phase, Phase::Connected);
}

#[tokio::test]
async fn stalled_recovery_continues_after_stop_error_when_tunnel_is_already_stopped() {
    let api = Arc::new(MockApi::new(0));
    let tunnel = Arc::new(MemoryTunnel::default());
    let core = ClientCore::new(
        api.clone(),
        Arc::new(MemoryStore::new(auth())),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    );
    let connection = core.start(options(), 1_700_000_000).await.unwrap();
    *tunnel.status.lock().unwrap() = TunnelStatus::Stopped;
    tunnel.fail_next_stops.store(1, Ordering::SeqCst);

    assert_eq!(
        core.recover_stalled_data_plane(
            &connection.lease_id,
            StalledDataPlaneRecovery::RestartLocalTunnel,
        )
        .await
        .unwrap(),
        StalledDataPlaneRecoveryOutcome::Reconnected,
    );
    assert_eq!(core.state().await.phase, Phase::Connected);
    assert_eq!(api.start_calls.load(Ordering::SeqCst), 1);
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn stalled_recovery_retries_one_local_start_failure_without_replacing_the_lease() {
    let api = Arc::new(MockApi::new(0));
    let tunnel = Arc::new(MemoryTunnel::default());
    let core = ClientCore::new(
        api.clone(),
        Arc::new(MemoryStore::new(auth())),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    );
    let connection = core.start(options(), 1_700_000_000).await.unwrap();
    tunnel.fail_next_starts.store(1, Ordering::SeqCst);

    assert_eq!(
        core.recover_stalled_data_plane(
            &connection.lease_id,
            StalledDataPlaneRecovery::RestartLocalTunnel,
        )
        .await
        .unwrap(),
        StalledDataPlaneRecoveryOutcome::Reconnected,
    );
    let recovered_state = core.state().await;
    assert_eq!(recovered_state.phase, Phase::Connected);
    assert_eq!(
        recovered_state
            .connection
            .as_ref()
            .map(|value| value.lease_id.as_str()),
        Some(connection.lease_id.as_str()),
    );
    assert_eq!(tunnel.starts.load(Ordering::SeqCst), 3);
    assert_eq!(api.start_calls.load(Ordering::SeqCst), 1);
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn stalled_awg3_recovery_does_not_report_reconnected_without_a_handshake() {
    let api = Arc::new(MockApi::new(0));
    let store = Arc::new(MemoryStore::new(auth()));
    let tunnel = Arc::new(MemoryTunnel::default());
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    );
    let connection = core.start(options(), 1_700_000_000).await.unwrap();
    let mut stored = store.load().unwrap().unwrap();
    stored.saved_connection.as_mut().unwrap().configuration = awg3_configuration("tunnel-secret");
    store.save(&stored).unwrap();
    tunnel.metrics_supported.store(true, Ordering::SeqCst);

    assert!(core
        .recover_stalled_data_plane(
            &connection.lease_id,
            StalledDataPlaneRecovery::RestartLocalTunnel,
        )
        .await
        .is_err());
    assert_eq!(core.state().await.phase, Phase::Stopping);
    assert_eq!(*tunnel.status.lock().unwrap(), TunnelStatus::Stopped);
    assert_eq!(tunnel.stops.load(Ordering::SeqCst), 2);
    assert_eq!(api.start_calls.load(Ordering::SeqCst), 1);
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 0);
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
        probe_url: Some("https://5a.example.test/probe".to_string()),
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

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn offline_start_exposes_connecting_until_the_tunnel_is_ready() {
    let mut stored = auth();
    stored.saved_connection = Some(StoredConnection {
        lease_id: "11111111-1111-4111-8111-111111111111".to_string(),
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        probe_url: Some("https://5a.example.test/probe".to_string()),
        kind: StoredConnectionKind::DynamicWarm,
        configuration: "[Interface]\nPrivateKey = offline-secret\n".to_string(),
        valid_until_unix: Some(1_700_000_100),
    });
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.start_delay_millis.store(1_000, Ordering::SeqCst);
    let core = Arc::new(ClientCore::new(
        Arc::new(MockApi::new(0)),
        Arc::new(MemoryStore::new(stored)),
        tunnel,
        Arc::new(MemoryLogger::default()),
    ));
    let start = tokio::spawn({
        let core = core.clone();
        async move { core.start_saved_stray_offline(1_700_000_000).await }
    });

    tokio::task::yield_now().await;

    let state = core.state().await;
    assert_eq!(state.phase, Phase::Connecting);
    assert_eq!(
        state
            .connection
            .as_ref()
            .map(|value| value.lease_id.as_str()),
        Some("11111111-1111-4111-8111-111111111111")
    );

    tokio::time::advance(Duration::from_secs(1)).await;
    start.await.unwrap().unwrap();
    assert_eq!(core.state().await.phase, Phase::Connected);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn offline_awg3_handshake_cleanup_failure_remains_stoppable() {
    let mut stored = auth();
    stored.saved_connection = Some(StoredConnection {
        lease_id: "11111111-1111-4111-8111-111111111111".to_string(),
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        probe_url: Some("https://5a.example.test/probe".to_string()),
        kind: StoredConnectionKind::DynamicWarm,
        configuration: awg3_configuration("offline-secret"),
        valid_until_unix: Some(1_700_000_100),
    });
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.metrics_supported.store(true, Ordering::SeqCst);
    tunnel.rebind_supported.store(true, Ordering::SeqCst);
    tunnel.fail_next_stops.store(1, Ordering::SeqCst);
    let core = ClientCore::new(
        Arc::new(MockApi::new(0)),
        Arc::new(MemoryStore::new(stored)),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    );

    let error = core
        .start_saved_stray_offline(1_700_000_000)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        CoreError::Tunnel(code) if code == "test_stop_failed"
    ));
    assert_eq!(tunnel.rebinds.load(Ordering::SeqCst), 1);
    assert_eq!(tunnel.stops.load(Ordering::SeqCst), 1);
    let state = core.state().await;
    assert_eq!(state.phase, Phase::Stopping);
    assert_eq!(
        state
            .connection
            .as_ref()
            .map(|connection| connection.lease_id.as_str()),
        Some("11111111-1111-4111-8111-111111111111")
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn offline_awg3_handshake_failure_returns_to_ready_after_cleanup() {
    let mut stored = auth();
    stored.saved_connection = Some(StoredConnection {
        lease_id: "11111111-1111-4111-8111-111111111111".to_string(),
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        probe_url: Some("https://5a.example.test/probe".to_string()),
        kind: StoredConnectionKind::DynamicWarm,
        configuration: awg3_configuration("offline-secret"),
        valid_until_unix: Some(1_700_000_100),
    });
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.metrics_supported.store(true, Ordering::SeqCst);
    tunnel.rebind_supported.store(true, Ordering::SeqCst);
    let store = Arc::new(MemoryStore::new(stored));
    let core = ClientCore::new(
        Arc::new(MockApi::new(0)),
        store.clone(),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    );

    let error = core
        .start_saved_stray_offline(1_700_000_000)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        CoreError::Tunnel(code) if code == "tunnel_handshake_timeout"
    ));
    assert_eq!(tunnel.stops.load(Ordering::SeqCst), 1);
    let state = core.state().await;
    assert_eq!(state.phase, Phase::Ready);
    assert!(state.connection.is_none());
    assert!(store.load().unwrap().unwrap().saved_connection.is_none());
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn offline_handshake_timeout_surfaces_dynamic_cache_reconciliation_failure() {
    let mut stored = auth();
    stored.saved_connection = Some(StoredConnection {
        lease_id: "11111111-1111-4111-8111-111111111111".to_string(),
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        probe_url: Some("https://5a.example.test/probe".to_string()),
        kind: StoredConnectionKind::DynamicWarm,
        configuration: awg3_configuration("offline-secret"),
        valid_until_unix: Some(1_700_000_100),
    });
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.metrics_supported.store(true, Ordering::SeqCst);
    tunnel.rebind_supported.store(true, Ordering::SeqCst);
    let logger = Arc::new(MemoryLogger::default());
    let store = Arc::new(RejectDynamicCacheRemovalStore::new(stored));
    let core = ClientCore::new(
        Arc::new(MockApi::new(0)),
        store.clone(),
        tunnel.clone(),
        logger.clone(),
    );

    let error = core
        .start_saved_stray_offline(1_700_000_000)
        .await
        .unwrap_err();

    assert!(matches!(error, CoreError::Storage));
    assert!(store.load().unwrap().unwrap().saved_connection.is_some());
    assert!(logger
        .0
        .lock()
        .unwrap()
        .iter()
        .any(|event| event.kind == "connection.offline_handshake_storage_failed"));
    let starts_after_failure = tunnel.starts.load(Ordering::SeqCst);
    assert!(matches!(
        core.start_saved_stray_offline(1_700_000_000).await,
        Err(CoreError::SavedConnectionUnavailable)
    ));
    assert_eq!(tunnel.starts.load(Ordering::SeqCst), starts_after_failure);
    assert!(logger
        .0
        .lock()
        .unwrap()
        .iter()
        .any(|event| event.kind == "connection.offline_cache_quarantined"));
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn offline_pinned_awg3_handshake_failure_blocks_the_saved_configuration() {
    let mut stored = auth();
    stored.pinned_connection = Some(StoredConnection {
        lease_id: "11111111-1111-4111-8111-111111111111".to_string(),
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        probe_url: Some("https://5a.example.test/probe".to_string()),
        kind: StoredConnectionKind::Pinned,
        configuration: awg3_configuration("offline-secret"),
        valid_until_unix: None,
    });
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.metrics_supported.store(true, Ordering::SeqCst);
    tunnel.rebind_supported.store(true, Ordering::SeqCst);
    let store = Arc::new(MemoryStore::new(stored));
    let core = ClientCore::new(
        Arc::new(MockApi::new(0)),
        store.clone(),
        tunnel,
        Arc::new(MemoryLogger::default()),
    );

    let error = core
        .start_saved_stray_offline(1_700_000_000)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        CoreError::Tunnel(code) if code == "tunnel_handshake_timeout"
    ));
    let retry_not_before = store
        .load()
        .unwrap()
        .unwrap()
        .pinned_connection
        .unwrap()
        .valid_until_unix
        .unwrap();
    assert!(matches!(
        core.start_saved_stray_offline(retry_not_before).await,
        Err(CoreError::SavedConnectionUnavailable)
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn expired_warm_stray_is_not_started_offline() {
    let mut stored = auth();
    stored.saved_connection = Some(StoredConnection {
        lease_id: "11111111-1111-4111-8111-111111111111".to_string(),
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        probe_url: Some("https://5a.example.test/probe".to_string()),
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
        probe_url: Some("https://5a.example.test/probe".to_string()),
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
        probe_url: Some("https://5a.example.test/probe".to_string()),
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
        probe_url: Some("https://5a.example.test/probe".to_string()),
        kind: StoredConnectionKind::DynamicWarm,
        configuration: "PrivateKey = alternate-secret".to_string(),
        valid_until_unix: Some(1_700_003_600),
    });
    stored.pinned_connection = Some(StoredConnection {
        lease_id: "pinned-lease".to_string(),
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        probe_url: Some("https://5a.example.test/probe".to_string()),
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
