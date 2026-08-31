use async_trait::async_trait;
use nelomai_client_api::{AuthDevice, BackgroundTokenResponse, TokenResponse};
use nelomai_client_core::{
    classify_recovery, stall_recovery_plan, ClientCore, ConnectOptions,
    ConnectionIntentCoordinator, CoreApi, CoreApiError, CoreError, CoreLogEvent, CoreLogger, Phase,
    RecoveryDecision, RecoveryPolicyContext, RecoveryTransport, RetryPolicy, RetrySchedule,
    StallRecoveryPlan, StallTrigger, StalledDataPlaneRecovery, StalledDataPlaneRecoveryOutcome,
    StartDisposition,
};
use nelomai_client_storage::{
    SecretStore, StorageError, StoredAuth, StoredCompatibility, StoredConnection,
    StoredConnectionKind, StoredPendingCompensationStop, StoredPendingStalledStop,
    StoredPendingStart,
};
use nelomai_client_tunnel::{
    TunnelController, TunnelError, TunnelMetrics, TunnelOptions, TunnelStartRequest, TunnelStatus,
};
use nelomai_contracts::{
    Access, AccessState, ApiVersion, Bootstrap, BootstrapDefaults, Connection,
    ConnectionOperationRequest, ConnectionOperationResponse, ConnectionStartRequest,
    ConnectionStartResponse, Device, EgressMode, Layer, LeaseStatus, OperationReconcileRequest,
    OperationReconcileResponse, OperationState, PeerBinding, Platform, ProbeResult, RouteMode,
    TicConnectionMode, UpdateState,
};
use std::collections::VecDeque;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Duration;
use tokio::sync::Notify;

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

struct ToggleLoadStore {
    stored: Mutex<Option<StoredAuth>>,
    fail_load: AtomicBool,
}

struct RejectCompensationJournalOnceStore {
    stored: Mutex<Option<StoredAuth>>,
    reject_compensation_journal: AtomicBool,
}

impl RejectCompensationJournalOnceStore {
    fn new(auth: StoredAuth) -> Self {
        Self {
            stored: Mutex::new(Some(auth)),
            reject_compensation_journal: AtomicBool::new(true),
        }
    }
}

impl ToggleLoadStore {
    fn new(auth: StoredAuth) -> Self {
        Self {
            stored: Mutex::new(Some(auth)),
            fail_load: AtomicBool::new(false),
        }
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

impl SecretStore for ToggleLoadStore {
    fn load(&self) -> Result<Option<StoredAuth>, StorageError> {
        if self.fail_load.load(Ordering::SeqCst) {
            return Err(StorageError::SplitTunnelStateLock);
        }
        Ok(self.stored.lock().unwrap().clone())
    }

    fn save(&self, auth: &StoredAuth) -> Result<(), StorageError> {
        *self.stored.lock().unwrap() = Some(auth.clone());
        Ok(())
    }

    fn delete(&self) -> Result<(), StorageError> {
        *self.stored.lock().unwrap() = None;
        Ok(())
    }
}

impl SecretStore for RejectCompensationJournalOnceStore {
    fn load(&self) -> Result<Option<StoredAuth>, StorageError> {
        Ok(self.stored.lock().unwrap().clone())
    }

    fn save(&self, auth: &StoredAuth) -> Result<(), StorageError> {
        if auth.pending_compensation_stop.is_some()
            && self
                .reject_compensation_journal
                .swap(false, Ordering::SeqCst)
        {
            return Err(StorageError::SplitTunnelStateLock);
        }
        *self.stored.lock().unwrap() = Some(auth.clone());
        Ok(())
    }

    fn delete(&self) -> Result<(), StorageError> {
        *self.stored.lock().unwrap() = None;
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
    block_start: AtomicBool,
    start_release: Notify,
    status_failures: AtomicUsize,
    metrics_supported: AtomicBool,
    metrics_calls: AtomicUsize,
    metric_successes_before_failures: AtomicUsize,
    metric_failures: AtomicUsize,
    fail_tunnel_on_metrics_error: AtomicBool,
    metrics_delay_millis: AtomicU64,
    block_metrics: AtomicBool,
    block_metrics_after_rebind: AtomicBool,
    blocked_metrics_calls: AtomicUsize,
    metrics_release: Notify,
    handshake_before_rebind: AtomicBool,
    handshake_after_rebind: AtomicBool,
    zero_handshake_before_rebind: AtomicBool,
    zero_handshake_after_rebind: AtomicBool,
    rebinds: AtomicUsize,
    rebind_supported: AtomicBool,
    rebind_failures: AtomicUsize,
    rebind_delay_millis: AtomicU64,
    block_rebind: AtomicBool,
    blocked_rebinds: AtomicUsize,
    rebind_release: Notify,
    configuration: Mutex<Option<String>>,
    options: Mutex<Option<TunnelOptions>>,
    status: Mutex<TunnelStatus>,
    operation_events: Mutex<Option<Arc<Mutex<Vec<&'static str>>>>>,
}

#[async_trait]
impl TunnelController for MemoryTunnel {
    async fn start(&self, request: TunnelStartRequest) -> Result<(), TunnelError> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        if self.block_start.load(Ordering::SeqCst) {
            self.start_release.notified().await;
        }
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
        if let Some(events) = self.operation_events.lock().unwrap().as_ref() {
            events.lock().unwrap().push("local_stop");
        }
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
        if self.block_rebind.load(Ordering::SeqCst) {
            self.blocked_rebinds.fetch_add(1, Ordering::SeqCst);
            self.rebind_release.notified().await;
        }
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
        self.metrics_calls.fetch_add(1, Ordering::SeqCst);
        let rebound = self.rebinds.load(Ordering::SeqCst) > 0;
        if self.block_metrics.load(Ordering::SeqCst)
            || rebound && self.block_metrics_after_rebind.load(Ordering::SeqCst)
        {
            self.blocked_metrics_calls.fetch_add(1, Ordering::SeqCst);
            self.metrics_release.notified().await;
        }
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
    start_requests: Mutex<Vec<ConnectionStartRequest>>,
    operation_ids: Mutex<Vec<String>>,
    stop_calls: AtomicUsize,
    stop_failures: AtomicUsize,
    stop_error: Mutex<Option<CoreApiError>>,
    stop_apply_then_fail_once: AtomicBool,
    applied_stop_replays_as_released: AtomicBool,
    stop_operation_ids: Mutex<Vec<String>>,
    stop_failure_codes: Mutex<Vec<Option<String>>>,
    stop_as_released: AtomicBool,
    stop_as_failed: AtomicBool,
    server_observed_handshake: AtomicBool,
    bootstrap_fails: AtomicBool,
    reject_stale_bootstrap: AtomicBool,
    reject_stale_start: AtomicBool,
    reject_stale_stop: AtomicBool,
    pinned_start: AtomicBool,
    awg3_start: AtomicBool,
    warm_start: AtomicBool,
    mismatched_egress: AtomicBool,
    start_lease_override: Mutex<Option<String>>,
    bootstrap_connection: Mutex<Option<Connection>>,
    bootstrap_binding_without_connection: AtomicBool,
    pin_calls: AtomicUsize,
    unpin_calls: AtomicUsize,
    pin_fails: AtomicBool,
    reconcile_requests: Mutex<Vec<OperationReconcileRequest>>,
    reconcile_responses: Mutex<VecDeque<OperationReconcileResponse>>,
    operation_events: Mutex<Option<Arc<Mutex<Vec<&'static str>>>>>,
}

impl MockApi {
    fn new(start_failures: usize) -> Self {
        Self {
            transport_resets: AtomicUsize::new(0),
            refresh_calls: AtomicUsize::new(0),
            start_calls: AtomicUsize::new(0),
            start_failures: AtomicUsize::new(start_failures),
            start_errors: Mutex::new(VecDeque::new()),
            start_requests: Mutex::new(Vec::new()),
            operation_ids: Mutex::new(Vec::new()),
            stop_calls: AtomicUsize::new(0),
            stop_failures: AtomicUsize::new(0),
            stop_error: Mutex::new(None),
            stop_apply_then_fail_once: AtomicBool::new(false),
            applied_stop_replays_as_released: AtomicBool::new(false),
            stop_operation_ids: Mutex::new(Vec::new()),
            stop_failure_codes: Mutex::new(Vec::new()),
            stop_as_released: AtomicBool::new(false),
            stop_as_failed: AtomicBool::new(false),
            server_observed_handshake: AtomicBool::new(false),
            bootstrap_fails: AtomicBool::new(false),
            reject_stale_bootstrap: AtomicBool::new(false),
            reject_stale_start: AtomicBool::new(false),
            reject_stale_stop: AtomicBool::new(false),
            pinned_start: AtomicBool::new(false),
            awg3_start: AtomicBool::new(false),
            warm_start: AtomicBool::new(false),
            mismatched_egress: AtomicBool::new(false),
            start_lease_override: Mutex::new(None),
            bootstrap_connection: Mutex::new(None),
            bootstrap_binding_without_connection: AtomicBool::new(false),
            pin_calls: AtomicUsize::new(0),
            unpin_calls: AtomicUsize::new(0),
            pin_fails: AtomicBool::new(false),
            reconcile_requests: Mutex::new(Vec::new()),
            reconcile_responses: Mutex::new(VecDeque::new()),
            operation_events: Mutex::new(None),
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
                egress_mode: EgressMode::Ipv4,
            });
        }
        Ok(response)
    }

    async fn background_token(
        &self,
        _access_token: &str,
    ) -> Result<BackgroundTokenResponse, CoreApiError> {
        Ok(BackgroundTokenResponse {
            api_version: ApiVersion::V1,
            request_id: "background-token-request".to_string(),
            token: "background-token".to_string(),
            expires_in: 3_600,
        })
    }

    async fn reconcile_background_operation(
        &self,
        _background_token: &str,
        request: &OperationReconcileRequest,
    ) -> Result<OperationReconcileResponse, CoreApiError> {
        self.reconcile_requests
            .lock()
            .unwrap()
            .push(request.clone());
        Ok(self
            .reconcile_responses
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(OperationReconcileResponse {
                api_version: ApiVersion::V1,
                request_id: "reconcile-request".to_string(),
                state: OperationState::Cancelled,
                cancel_requested: true,
                lease_id: None,
                lease_status: None,
                retry_count: 0,
                next_attempt_at: None,
            }))
    }

    async fn start_connection(
        &self,
        access_token: &str,
        request: &ConnectionStartRequest,
    ) -> Result<ConnectionStartResponse, CoreApiError> {
        self.start_calls.fetch_add(1, Ordering::SeqCst);
        self.start_requests.lock().unwrap().push(request.clone());
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
        if !self.mismatched_egress.load(Ordering::SeqCst) {
            response.connection.egress_mode = request.egress_mode;
        }
        response.connection.pool_id = (request.tic_connection_mode == TicConnectionMode::Dynamic)
            .then(|| "pool-test".to_string());
        response.connection.pinned = self.pinned_start.load(Ordering::SeqCst);
        if self.warm_start.load(Ordering::SeqCst) {
            response.connection.status = LeaseStatus::Warm;
        }
        Ok(response)
    }

    async fn stop_connection(
        &self,
        access_token: &str,
        request: &ConnectionOperationRequest,
    ) -> Result<ConnectionOperationResponse, CoreApiError> {
        self.stop_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(events) = self.operation_events.lock().unwrap().as_ref() {
            events.lock().unwrap().push("panel_stop");
        }
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
        if self.stop_apply_then_fail_once.swap(false, Ordering::SeqCst) {
            *self.bootstrap_connection.lock().unwrap() = None;
            if self.applied_stop_replays_as_released.load(Ordering::SeqCst) {
                self.stop_as_released.store(true, Ordering::SeqCst);
            }
            return Err(CoreApiError::Retryable);
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
        let last_start_mode = self
            .start_requests
            .lock()
            .unwrap()
            .last()
            .map(|start| start.tic_connection_mode);
        let fixed_personal = !self.pinned_start.load(Ordering::SeqCst)
            && last_start_mode == Some(TicConnectionMode::Personal);
        let dynamic_handshake_failure = request.failure_code.as_deref()
            == Some("tunnel_handshake_timeout")
            && !self.pinned_start.load(Ordering::SeqCst)
            && !self.server_observed_handshake.load(Ordering::SeqCst)
            && last_start_mode == Some(TicConnectionMode::Dynamic);
        Ok(ConnectionOperationResponse {
            api_version: ApiVersion::V1,
            request_id: "req-stop".to_string(),
            connection: Connection {
                lease_id: request.lease_id.clone(),
                pinned: self.pinned_start.load(Ordering::SeqCst),
                status: if request.failure_code.as_deref() == Some("tunnel_data_plane_stalled") {
                    LeaseStatus::Failed
                } else if self.stop_as_released.load(Ordering::SeqCst) {
                    LeaseStatus::Released
                } else if self.stop_as_failed.load(Ordering::SeqCst) || dynamic_handshake_failure {
                    LeaseStatus::Failed
                } else if fixed_personal {
                    if request.failure_code.as_deref() == Some("tunnel_handshake_timeout") {
                        LeaseStatus::Failed
                    } else {
                        LeaseStatus::Released
                    }
                } else {
                    LeaseStatus::Warm
                },
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
                retry_after_seconds: None,
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
        pool_id: None,
        layer: Layer::Stray,
        transport_protocol: Default::default(),
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        egress_mode: EgressMode::Ipv4,
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
        redundancy: None,
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
        capabilities: None,
    }
}

fn options() -> ConnectOptions {
    ConnectOptions {
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        egress_mode: EgressMode::Ipv4,
        probes: Vec::new(),
        allow_alternate: false,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn start_diagnostics_identify_the_egress_mode_and_selected_pool() {
    let logger = Arc::new(MemoryLogger::default());
    let core = ClientCore::new(
        Arc::new(MockApi::new(0)),
        Arc::new(MemoryStore::new(auth())),
        Arc::new(MemoryTunnel::default()),
        logger.clone(),
    );

    core.start(
        ConnectOptions {
            layer: Layer::Tic,
            tic_connection_mode: TicConnectionMode::Dynamic,
            route_mode: RouteMode::ViaTak,
            egress_mode: EgressMode::PreferIpv6,
            probes: Vec::new(),
            allow_alternate: true,
        },
        1_700_000_000,
    )
    .await
    .unwrap();

    let events = logger.0.lock().unwrap();
    assert!(events.iter().any(|event| {
        event.kind == "connection.egress_selected" && event.code.as_deref() == Some("prefer_ipv6")
    }));
    assert!(events.iter().any(|event| {
        event.kind == "connection.pool_selected" && event.code.as_deref() == Some("pool-test")
    }));
}

#[tokio::test(flavor = "current_thread")]
async fn start_rejects_a_silent_ipv6_to_ipv4_server_downgrade() {
    let api = Arc::new(MockApi::new(0));
    api.mismatched_egress.store(true, Ordering::SeqCst);
    let tunnel = Arc::new(MemoryTunnel::default());
    let core = ClientCore::new(
        api.clone(),
        Arc::new(MemoryStore::new(auth())),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    );

    let error = core
        .start(
            ConnectOptions {
                layer: Layer::Tic,
                tic_connection_mode: TicConnectionMode::Dynamic,
                route_mode: RouteMode::ViaTak,
                egress_mode: EgressMode::PreferIpv6,
                probes: Vec::new(),
                allow_alternate: true,
            },
            1_700_000_000,
        )
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        CoreError::Api(CoreApiError::Rejected { ref code, .. })
            if code == "invalid_client_api_response"
    ));
    assert_eq!(tunnel.starts.load(Ordering::SeqCst), 0);
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
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

    assert!(started.elapsed() < Duration::from_secs(16));
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
async fn awg3_accepts_a_handshake_after_the_first_protocol_retransmission() {
    let api = Arc::new(MockApi::new(0));
    api.awg3_start.store(true, Ordering::SeqCst);
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.metrics_supported.store(true, Ordering::SeqCst);
    tunnel.metrics_delay_millis.store(6_000, Ordering::SeqCst);
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
async fn awg3_accepts_a_post_rebind_handshake_after_a_protocol_retransmission() {
    let api = Arc::new(MockApi::new(0));
    api.awg3_start.store(true, Ordering::SeqCst);
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.metrics_supported.store(true, Ordering::SeqCst);
    tunnel.metrics_delay_millis.store(6_000, Ordering::SeqCst);
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
async fn handshake_timeout_requires_a_durable_compensation_identity_before_panel_stop() {
    let api = Arc::new(MockApi::new(0));
    api.awg3_start.store(true, Ordering::SeqCst);
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.metrics_supported.store(true, Ordering::SeqCst);
    tunnel.rebind_supported.store(true, Ordering::SeqCst);
    let store = Arc::new(RejectCompensationJournalOnceStore::new(auth()));
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        tunnel,
        Arc::new(MemoryLogger::default()),
    );

    let error = core.start(options(), 1_700_000_000).await.unwrap_err();

    assert!(matches!(error, CoreError::Storage));
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 0);
    let stored = store.load().unwrap().unwrap();
    assert!(stored.pending_start.is_some());
    assert!(stored.pending_compensation_stop.is_none());
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn personal_handshake_timeout_accepts_panel_failed_and_clears_compensation() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let api = Arc::new(MockApi::new(0));
    api.awg3_start.store(true, Ordering::SeqCst);
    *api.operation_events.lock().unwrap() = Some(events.clone());
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.metrics_supported.store(true, Ordering::SeqCst);
    tunnel.rebind_supported.store(true, Ordering::SeqCst);
    *tunnel.operation_events.lock().unwrap() = Some(events.clone());
    let store = Arc::new(MemoryStore::new(auth()));
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    );
    let personal = ConnectOptions {
        layer: Layer::Tic,
        tic_connection_mode: TicConnectionMode::Personal,
        route_mode: RouteMode::ViaTak,
        egress_mode: EgressMode::Ipv4,
        probes: Vec::new(),
        allow_alternate: false,
    };

    let error = core
        .start(personal.clone(), 1_700_000_000)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        CoreError::Tunnel(code) if code == "tunnel_handshake_timeout"
    ));
    assert_eq!(tunnel.stops.load(Ordering::SeqCst), 1);
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        events.lock().unwrap().as_slice(),
        &["local_stop", "panel_stop"]
    );
    let stored = store.load().unwrap().unwrap();
    assert!(stored.pending_start.is_none());
    assert!(stored.pending_compensation_stop.is_none());
    assert!(stored.saved_connection.is_none());
    assert_eq!(
        api.stop_failure_codes.lock().unwrap().as_slice(),
        &[Some("tunnel_handshake_timeout".to_string())]
    );
    assert_eq!(core.state().await.phase, Phase::Ready);
    assert_eq!(
        core.state().await.connection.unwrap().status,
        LeaseStatus::Failed
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn pinned_handshake_timeout_accepts_panel_warm_and_clears_compensation() {
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
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    );

    let error = core.start(options(), 1_700_000_000).await.unwrap_err();
    assert!(matches!(
        error,
        CoreError::Tunnel(code) if code == "tunnel_handshake_timeout"
    ));

    assert_eq!(tunnel.stops.load(Ordering::SeqCst), 1);
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
    let stored = store.load().unwrap().unwrap();
    assert!(stored.pending_start.is_none());
    assert!(stored.pending_compensation_stop.is_none());
    assert!(stored
        .pinned_connection
        .as_ref()
        .and_then(|connection| connection.valid_until_unix)
        .is_some());
    assert_eq!(core.state().await.phase, Phase::Ready);
    assert_eq!(
        core.state().await.connection.unwrap().status,
        LeaseStatus::Warm
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn dynamic_handshake_timeout_accepts_panel_warm_after_server_observed_handshake() {
    let api = Arc::new(MockApi::new(0));
    api.awg3_start.store(true, Ordering::SeqCst);
    api.server_observed_handshake.store(true, Ordering::SeqCst);
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
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
    let stored = store.load().unwrap().unwrap();
    assert!(stored.pending_start.is_none());
    assert!(stored.pending_compensation_stop.is_none());
    assert!(stored.saved_connection.is_none());
    assert_eq!(core.state().await.phase, Phase::Ready);
    assert_eq!(
        core.state().await.connection.unwrap().status,
        LeaseStatus::Warm
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn dynamic_handshake_timeout_replays_transient_stop_with_exact_marker_and_clears_on_failed() {
    let api = Arc::new(MockApi::new(0));
    api.awg3_start.store(true, Ordering::SeqCst);
    *api.stop_error.lock().unwrap() = Some(CoreApiError::Retryable);
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.metrics_supported.store(true, Ordering::SeqCst);
    tunnel.rebind_supported.store(true, Ordering::SeqCst);
    let store = Arc::new(MemoryStore::new(auth()));
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        tunnel,
        Arc::new(MemoryLogger::default()),
    )
    .with_retry_policy(RetryPolicy::new(Vec::new()));

    assert!(matches!(
        core.start(options(), 1_700_000_000).await,
        Err(CoreError::Tunnel(code)) if code == "tunnel_handshake_timeout"
    ));
    let pending = store
        .load()
        .unwrap()
        .unwrap()
        .pending_compensation_stop
        .expect("transient stop must retain the handshake compensation marker");
    assert!(pending.accept_warm);
    assert_eq!(
        serde_json::to_value(&pending).unwrap()["failure_code"],
        "tunnel_handshake_timeout"
    );
    assert_eq!(
        pending.lease_id,
        core.state().await.connection.unwrap().lease_id
    );

    *api.stop_error.lock().unwrap() = None;
    api.stop_as_failed.store(true, Ordering::SeqCst);
    let reconstructed = ClientCore::new(
        api.clone(),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    )
    .with_retry_policy(RetryPolicy::new(Vec::new()));

    reconstructed
        .reconcile_pending_operation_for_retry()
        .await
        .unwrap();

    assert_eq!(
        api.stop_operation_ids.lock().unwrap().as_slice(),
        &[pending.operation_id.clone(), pending.operation_id]
    );
    assert_eq!(
        api.stop_failure_codes.lock().unwrap().as_slice(),
        &[
            Some("tunnel_handshake_timeout".to_string()),
            Some("tunnel_handshake_timeout".to_string())
        ]
    );
    let stored = store.load().unwrap().unwrap();
    assert!(stored.pending_start.is_none());
    assert!(stored.pending_compensation_stop.is_none());
    assert!(stored.saved_connection.is_none());
    assert_eq!(reconstructed.state().await.phase, Phase::Ready);
    assert_eq!(
        reconstructed.state().await.connection.unwrap().status,
        LeaseStatus::Failed
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn dynamic_handshake_timeout_replays_applied_lost_stop_with_exact_failure_code() {
    let api = Arc::new(MockApi::new(0));
    api.awg3_start.store(true, Ordering::SeqCst);
    api.stop_apply_then_fail_once.store(true, Ordering::SeqCst);
    api.applied_stop_replays_as_released
        .store(true, Ordering::SeqCst);
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.metrics_supported.store(true, Ordering::SeqCst);
    tunnel.rebind_supported.store(true, Ordering::SeqCst);
    let store = Arc::new(MemoryStore::new(auth()));
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        tunnel,
        Arc::new(MemoryLogger::default()),
    )
    .with_retry_policy(RetryPolicy::new(Vec::new()));

    assert!(matches!(
        core.start(options(), 1_700_000_000).await,
        Err(CoreError::Tunnel(code)) if code == "tunnel_handshake_timeout"
    ));
    let pending = store
        .load()
        .unwrap()
        .unwrap()
        .pending_compensation_stop
        .expect("lost applied stop must retain the handshake compensation marker");
    assert_eq!(
        pending.lease_id,
        core.state().await.connection.unwrap().lease_id
    );

    let reconstructed = ClientCore::new(
        api.clone(),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    )
    .with_retry_policy(RetryPolicy::new(Vec::new()));
    reconstructed
        .reconcile_pending_operation_for_retry()
        .await
        .unwrap();

    assert_eq!(
        api.stop_operation_ids.lock().unwrap().as_slice(),
        &[pending.operation_id.clone(), pending.operation_id]
    );
    assert_eq!(
        api.stop_failure_codes.lock().unwrap().as_slice(),
        &[
            Some("tunnel_handshake_timeout".to_string()),
            Some("tunnel_handshake_timeout".to_string())
        ]
    );
    let stored = store.load().unwrap().unwrap();
    assert!(stored.pending_start.is_none());
    assert!(stored.pending_compensation_stop.is_none());
    assert!(stored.saved_connection.is_none());
    assert_eq!(reconstructed.state().await.phase, Phase::Ready);
    assert_eq!(
        reconstructed.state().await.connection.unwrap().status,
        LeaseStatus::Released
    );
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
    assert!(started.elapsed() < Duration::from_secs(12));
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
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 0);
    assert!(api.stop_failure_codes.lock().unwrap().is_empty());
    let stored = store.load().unwrap().unwrap();
    assert!(stored.saved_connection.is_some());
    assert!(stored.pending_start.is_some());
    assert_eq!(core.state().await.phase, Phase::Stopping);
    let pending = stored
        .pending_compensation_stop
        .expect("handshake cleanup failure must retain the exact panel compensation");
    assert_eq!(
        serde_json::to_value(&pending).unwrap()["failure_code"],
        "tunnel_handshake_timeout"
    );
    assert!(logger
        .0
        .lock()
        .unwrap()
        .iter()
        .any(|event| event.kind == "connection.handshake_cleanup_failed"));

    core.stop().await.unwrap();

    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        api.stop_operation_ids.lock().unwrap().as_slice(),
        &[pending.operation_id]
    );
    assert_eq!(
        api.stop_failure_codes.lock().unwrap().as_slice(),
        &[Some("tunnel_handshake_timeout".to_string())]
    );
    let stored = store.load().unwrap().unwrap();
    assert!(stored.pending_start.is_none());
    assert!(stored.pending_compensation_stop.is_none());
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
async fn bootstrap_without_refresh_preserves_a_stale_session_for_external_recovery() {
    let api = Arc::new(MockApi::new(0));
    api.reject_stale_bootstrap.store(true, Ordering::SeqCst);
    let store = Arc::new(MemoryStore::new(auth()));
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    );

    let error = core
        .bootstrap_without_refresh(1_700_000_000)
        .await
        .unwrap_err();

    assert!(matches!(error, CoreError::SignedOut));
    assert_eq!(api.refresh_calls.load(Ordering::SeqCst), 0);
    let stored = store.load().unwrap().unwrap();
    assert_eq!(stored.access_token.as_deref(), Some("stale-access"));
    assert_eq!(stored.refresh_token.as_deref(), Some("refresh-secret"));
}

#[tokio::test(flavor = "current_thread")]
async fn replacing_session_tokens_preserves_device_state() {
    let api = Arc::new(MockApi::new(0));
    let mut original = auth();
    original.compatibility = Some(StoredCompatibility {
        update_required: false,
        observed_at_unix: 1_700_000_000,
    });
    let expected_install_secret = original.install_secret.clone();
    let expected_compatibility = original.compatibility.clone();
    let store = Arc::new(MemoryStore::new(original));
    let core = ClientCore::new(
        api,
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    );

    core.replace_session_tokens("recovered-access", "recovered-refresh")
        .await
        .unwrap();

    let stored = store.load().unwrap().unwrap();
    assert_eq!(stored.install_secret, expected_install_secret);
    assert_eq!(stored.compatibility, expected_compatibility);
    assert_eq!(stored.access_token.as_deref(), Some("recovered-access"));
    assert_eq!(stored.refresh_token.as_deref(), Some("recovered-refresh"));
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
async fn failed_fixed_start_accepts_panel_release_and_clears_compensation() {
    let api = Arc::new(MockApi::new(0));
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
        egress_mode: EgressMode::Ipv4,
        probes: Vec::new(),
        allow_alternate: false,
    };

    let start_error = core.start(fixed, 1_700_000_000).await.unwrap_err();
    assert!(start_error.to_string().contains("test_start_failed"));

    let stored = store.load().unwrap().unwrap();
    assert!(stored.pending_start.is_none());
    assert!(stored.pending_compensation_stop.is_none());
    assert_eq!(api.stop_operation_ids.lock().unwrap().len(), 1);
    assert_eq!(core.state().await.phase, Phase::Ready);
    assert_eq!(
        core.state().await.connection.unwrap().status,
        LeaseStatus::Released
    );
}

#[cfg(not(target_os = "android"))]
#[tokio::test]
async fn failed_local_start_compensation_reuses_its_stop_id_after_process_reconstruction() {
    let api = Arc::new(MockApi::new(0));
    *api.stop_error.lock().unwrap() = Some(CoreApiError::Retryable);
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

    assert!(core.start(options(), 1_700_000_000).await.is_err());
    let pending = store
        .load()
        .unwrap()
        .unwrap()
        .pending_compensation_stop
        .expect("failed-start compensation must be durable before the first stop");
    assert_eq!(
        api.stop_operation_ids.lock().unwrap().as_slice(),
        &[pending.operation_id.clone()]
    );

    *api.stop_error.lock().unwrap() = None;
    let issued = connection(&pending.lease_id);
    *api.bootstrap_connection.lock().unwrap() = Some(issued);
    let reconstructed = ClientCore::new(
        api.clone(),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    );
    reconstructed.bootstrap(1_700_000_001).await.unwrap();
    reconstructed
        .reconcile_pending_operation_for_retry()
        .await
        .unwrap();

    assert_eq!(
        api.stop_operation_ids.lock().unwrap().as_slice(),
        &[pending.operation_id.clone(), pending.operation_id]
    );
    let stored = store.load().unwrap().unwrap();
    assert!(stored.pending_compensation_stop.is_none());
    assert!(stored.pending_start.is_none());
}

#[cfg(not(target_os = "android"))]
#[tokio::test]
async fn reconstructed_core_replays_applied_compensation_stop_when_bootstrap_omits_terminal_lease()
{
    let api = Arc::new(MockApi::new(0));
    api.stop_apply_then_fail_once.store(true, Ordering::SeqCst);
    api.applied_stop_replays_as_released
        .store(true, Ordering::SeqCst);
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

    assert!(core.start(options(), 1_700_000_000).await.is_err());
    let pending = store
        .load()
        .unwrap()
        .unwrap()
        .pending_compensation_stop
        .expect("lost applied stop response must retain its durable identity");
    assert_eq!(
        api.stop_operation_ids.lock().unwrap().as_slice(),
        &[pending.operation_id.clone()]
    );
    assert!(api.bootstrap_connection.lock().unwrap().is_none());

    let reconstructed = ClientCore::new(
        api.clone(),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    )
    .with_retry_policy(RetryPolicy::new(Vec::new()));
    let bootstrap = reconstructed.bootstrap(1_700_000_001).await.unwrap();
    assert!(bootstrap.connection.is_none());
    assert!(reconstructed.state().await.connection.is_none());

    reconstructed
        .reconcile_pending_operation_for_retry()
        .await
        .unwrap();

    assert_eq!(
        api.stop_operation_ids.lock().unwrap().as_slice(),
        &[pending.operation_id.clone(), pending.operation_id]
    );
    let stored = store.load().unwrap().unwrap();
    assert!(stored.pending_compensation_stop.is_none());
    assert!(stored.pending_start.is_none());
    assert_eq!(
        reconstructed.state().await.connection.unwrap().status,
        LeaseStatus::Released
    );
}

#[cfg(not(target_os = "android"))]
#[tokio::test]
async fn failed_local_start_waits_for_durable_compensation_identity_before_stopping_panel_lease() {
    let api = Arc::new(MockApi::new(0));
    *api.stop_error.lock().unwrap() = Some(CoreApiError::Retryable);
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.fail_next_starts.store(1, Ordering::SeqCst);
    let store = Arc::new(RejectCompensationJournalOnceStore::new(auth()));
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        tunnel,
        Arc::new(MemoryLogger::default()),
    )
    .with_retry_policy(RetryPolicy::new(Vec::new()));

    assert!(matches!(
        core.start(options(), 1_700_000_000).await,
        Err(CoreError::Storage)
    ));
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 0);
    let stored_after_failure = store.load().unwrap().unwrap();
    assert!(stored_after_failure.pending_start.is_some());
    assert!(stored_after_failure.pending_compensation_stop.is_none());
    let lease_id = core
        .state()
        .await
        .connection
        .expect("failed start must retain the issued lease")
        .lease_id;

    *api.bootstrap_connection.lock().unwrap() = Some(connection(&lease_id));
    let reconstructed = ClientCore::new(
        api.clone(),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    )
    .with_retry_policy(RetryPolicy::new(Vec::new()));
    reconstructed.bootstrap(1_700_000_001).await.unwrap();

    assert!(reconstructed.start(options(), 1_700_000_001).await.is_err());
    let pending = store
        .load()
        .unwrap()
        .unwrap()
        .pending_compensation_stop
        .expect("recovered storage must contain the compensation identity before panel stop");
    assert_eq!(
        api.stop_operation_ids.lock().unwrap().as_slice(),
        &[pending.operation_id.clone()]
    );

    *api.stop_error.lock().unwrap() = None;
    reconstructed.stop().await.unwrap();

    assert_eq!(
        api.stop_operation_ids.lock().unwrap().as_slice(),
        &[pending.operation_id.clone(), pending.operation_id]
    );
    let stored = store.load().unwrap().unwrap();
    assert!(stored.pending_compensation_stop.is_none());
    assert!(stored.pending_start.is_none());
}

#[cfg(not(target_os = "android"))]
#[tokio::test]
async fn explicit_retry_finishes_failed_start_compensation_with_the_same_stop_id() {
    let api = Arc::new(MockApi::new(0));
    *api.stop_error.lock().unwrap() = Some(CoreApiError::Retryable);
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

    assert!(core.start(options(), 1_700_000_000).await.is_err());
    let pending = store
        .load()
        .unwrap()
        .unwrap()
        .pending_compensation_stop
        .unwrap();
    *api.stop_error.lock().unwrap() = None;

    core.start(options(), 1_700_000_001).await.unwrap();

    assert_eq!(
        api.stop_operation_ids.lock().unwrap().as_slice(),
        &[pending.operation_id.clone(), pending.operation_id]
    );
    assert_eq!(api.start_calls.load(Ordering::SeqCst), 2);
    assert!(store
        .load()
        .unwrap()
        .unwrap()
        .pending_compensation_stop
        .is_none());
}

#[cfg(not(target_os = "android"))]
#[tokio::test]
async fn explicit_stop_finishes_failed_start_compensation_with_the_same_stop_id() {
    let api = Arc::new(MockApi::new(0));
    *api.stop_error.lock().unwrap() = Some(CoreApiError::Retryable);
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

    assert!(core.start(options(), 1_700_000_000).await.is_err());
    let pending = store
        .load()
        .unwrap()
        .unwrap()
        .pending_compensation_stop
        .unwrap();
    *api.stop_error.lock().unwrap() = None;

    core.stop().await.unwrap();

    assert_eq!(
        api.stop_operation_ids.lock().unwrap().as_slice(),
        &[pending.operation_id.clone(), pending.operation_id]
    );
    assert!(store
        .load()
        .unwrap()
        .unwrap()
        .pending_compensation_stop
        .is_none());
}

#[cfg(not(target_os = "android"))]
#[tokio::test]
async fn reconstructed_core_without_authoritative_bootstrap_replays_failed_start_compensation() {
    let mut stored_auth = auth();
    stored_auth.pending_compensation_stop = Some(StoredPendingCompensationStop {
        operation_id: "durable-stop".to_string(),
        lease_id: "issued-lease".to_string(),
        accept_warm: true,
        failure_code: None,
    });
    let store = Arc::new(MemoryStore::new(stored_auth));
    let api = Arc::new(MockApi::new(0));
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    );

    core.reconcile_pending_operation_for_retry().await.unwrap();

    assert_eq!(
        api.stop_operation_ids.lock().unwrap().as_slice(),
        &["durable-stop".to_string()]
    );
    assert!(store
        .load()
        .unwrap()
        .unwrap()
        .pending_compensation_stop
        .is_none());
    assert_eq!(
        core.state().await.connection.unwrap().status,
        LeaseStatus::Warm
    );
}

#[cfg(not(target_os = "android"))]
#[tokio::test]
async fn reconstructed_legacy_pinned_compensation_migrates_before_exact_replay() {
    let mut stored_auth = auth();
    stored_auth.pending_start = Some(StoredPendingStart {
        operation_id: "legacy-pinned-start".to_string(),
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        egress_mode: EgressMode::Ipv4,
        allow_alternate: true,
        probes: Vec::new(),
        recovery_contract_version: None,
        request_fingerprint: None,
        cancel_operation_id: None,
    });
    stored_auth.pinned_connection = Some(StoredConnection {
        lease_id: "legacy-pinned-lease".to_string(),
        pool_id: Some("pool-test".to_string()),
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        egress_mode: EgressMode::Ipv4,
        probe_url: Some("https://5a.example.test/probe".to_string()),
        kind: StoredConnectionKind::Pinned,
        configuration: awg3_configuration("legacy-pinned-secret"),
        valid_until_unix: None,
    });
    stored_auth.pending_compensation_stop = Some(StoredPendingCompensationStop {
        operation_id: "legacy-pinned-stop".to_string(),
        lease_id: "legacy-pinned-lease".to_string(),
        accept_warm: false,
        failure_code: Some("tunnel_handshake_timeout".to_string()),
    });
    let store = Arc::new(MemoryStore::new(stored_auth));
    let api = Arc::new(MockApi::new(0));
    api.pinned_start.store(true, Ordering::SeqCst);
    *api.stop_error.lock().unwrap() = Some(CoreApiError::Retryable);
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    )
    .with_retry_policy(RetryPolicy::new(Vec::new()));

    assert!(matches!(
        core.reconcile_pending_operation_for_retry().await,
        Err(CoreError::Api(CoreApiError::Retryable))
    ));
    let migrated = store
        .load()
        .unwrap()
        .unwrap()
        .pending_compensation_stop
        .expect("legacy compensation must remain durable after a transient replay");
    assert!(migrated.accept_warm);
    assert_eq!(migrated.operation_id, "legacy-pinned-stop");

    *api.stop_error.lock().unwrap() = None;
    let reconstructed = ClientCore::new(
        api.clone(),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    )
    .with_retry_policy(RetryPolicy::new(Vec::new()));
    reconstructed
        .reconcile_pending_operation_for_retry()
        .await
        .unwrap();

    assert_eq!(
        api.stop_operation_ids.lock().unwrap().as_slice(),
        &["legacy-pinned-stop", "legacy-pinned-stop"]
    );
    let stored = store.load().unwrap().unwrap();
    assert!(stored.pending_start.is_none());
    assert!(stored.pending_compensation_stop.is_none());
    assert!(stored.pinned_connection.unwrap().valid_until_unix.is_some());
    assert_eq!(reconstructed.state().await.phase, Phase::Ready);
    assert_eq!(
        reconstructed.state().await.connection.unwrap().status,
        LeaseStatus::Warm
    );
}

#[cfg(not(target_os = "android"))]
#[tokio::test]
async fn unrelated_dynamic_connection_cannot_migrate_a_legacy_fixed_compensation() {
    let mut stored_auth = auth();
    stored_auth.pending_compensation_stop = Some(StoredPendingCompensationStop {
        operation_id: "legacy-fixed-stop".to_string(),
        lease_id: "legacy-fixed-lease".to_string(),
        accept_warm: false,
        failure_code: None,
    });
    let store = Arc::new(MemoryStore::new(stored_auth));
    let api = Arc::new(MockApi::new(0));
    *api.bootstrap_connection.lock().unwrap() = Some(Connection {
        status: LeaseStatus::Warm,
        ..connection("unrelated-dynamic-lease")
    });
    let core = ClientCore::new(
        api,
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    );
    core.bootstrap(1_700_000_000).await.unwrap();

    assert!(matches!(
        core.reconcile_pending_operation_for_retry().await,
        Err(CoreError::Storage)
    ));

    let pending = store
        .load()
        .unwrap()
        .unwrap()
        .pending_compensation_stop
        .unwrap();
    assert!(!pending.accept_warm);
    assert_eq!(pending.lease_id, "legacy-fixed-lease");
}

#[cfg(not(target_os = "android"))]
#[tokio::test]
async fn reconstructed_terminal_compensation_does_not_accept_a_warm_personal_response() {
    let mut stored_auth = auth();
    stored_auth.pending_compensation_stop = Some(StoredPendingCompensationStop {
        operation_id: "terminal-stop".to_string(),
        lease_id: "personal-lease".to_string(),
        accept_warm: false,
        failure_code: None,
    });
    let store = Arc::new(MemoryStore::new(stored_auth));
    let api = Arc::new(MockApi::new(0));
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    );

    let error = core
        .reconcile_pending_operation_for_retry()
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        CoreError::Api(CoreApiError::Rejected { ref code, .. })
            if code == "connection_release_pending"
    ));

    assert_eq!(
        api.stop_operation_ids.lock().unwrap().as_slice(),
        &["terminal-stop".to_string()]
    );
    assert_eq!(
        store
            .load()
            .unwrap()
            .unwrap()
            .pending_compensation_stop
            .unwrap()
            .operation_id,
        "terminal-stop"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn partial_local_start_failure_stops_local_before_panel_compensation() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let api = Arc::new(MockApi::new(0));
    *api.operation_events.lock().unwrap() = Some(events.clone());
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.fail_next_starts.store(1, Ordering::SeqCst);
    tunnel
        .leave_running_on_start_failure
        .store(true, Ordering::SeqCst);
    *tunnel.operation_events.lock().unwrap() = Some(events.clone());
    let core = ClientCore::new(
        api.clone(),
        Arc::new(MemoryStore::new(auth())),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    )
    .with_retry_policy(RetryPolicy::new(Vec::new()));

    core.start(options(), 1_700_000_000).await.unwrap_err();

    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
    assert_eq!(tunnel.stops.load(Ordering::SeqCst), 1);
    assert_eq!(
        events.lock().unwrap().as_slice(),
        &["local_stop", "panel_stop"]
    );
    assert_eq!(core.state().await.phase, Phase::Ready);
}

#[tokio::test(flavor = "current_thread")]
async fn failed_local_status_is_stopped_before_panel_compensation() {
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
        egress_mode: EgressMode::Ipv4,
        allow_alternate: false,
        probes: Vec::new(),
        recovery_contract_version: None,
        request_fingerprint: None,
        cancel_operation_id: None,
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

#[cfg(not(target_os = "android"))]
#[tokio::test(flavor = "current_thread")]
async fn legacy_pending_start_without_allow_alternate_exact_replays_normal_dynamic_intent() {
    let api = Arc::new(MockApi::new(0));
    let stored_auth: StoredAuth = serde_json::from_value(serde_json::json!({
        "install_secret": "legacy-install-secret",
        "access_token": "stale-access",
        "refresh_token": "refresh-secret",
        "pending_start": {
            "operation_id": "legacy-pending-operation",
            "layer": "stray",
            "tic_connection_mode": "dynamic",
            "route_mode": "standalone"
        }
    }))
    .unwrap();
    let store = Arc::new(MemoryStore::new(stored_auth));
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    );
    let mut normal_dynamic_options = options();
    normal_dynamic_options.allow_alternate = true;

    core.connection_intent_attempt(normal_dynamic_options, 1_700_000_000)
        .await
        .unwrap();

    assert_eq!(api.start_calls.load(Ordering::SeqCst), 1);
    let requests = api.start_requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].operation_id, "legacy-pending-operation");
    assert!(requests[0].allow_alternate);
    assert!(store.load().unwrap().unwrap().pending_start.is_none());
}

#[test]
fn persisted_pending_start_is_cancellable_immediately_after_core_construction() {
    let mut stored_auth = auth();
    stored_auth.pending_start = Some(StoredPendingStart {
        operation_id: "pending-operation".to_string(),
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        egress_mode: EgressMode::Ipv4,
        allow_alternate: false,
        probes: Vec::new(),
        recovery_contract_version: None,
        request_fingerprint: None,
        cancel_operation_id: None,
    });
    let core = ClientCore::new(
        Arc::new(MockApi::new(0)),
        Arc::new(MemoryStore::new(stored_auth)),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    );

    assert!(core.signal_start_cancellation());
}

#[cfg(not(target_os = "android"))]
#[tokio::test(flavor = "current_thread")]
async fn legacy_entry_replays_the_stored_recovery_contract_without_mutating_it() {
    let api = Arc::new(MockApi::new(1));
    let mut stored_auth = auth();
    stored_auth.pending_start = Some(StoredPendingStart {
        operation_id: "pending-recovery-operation".to_string(),
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        egress_mode: EgressMode::Ipv4,
        allow_alternate: false,
        probes: Vec::new(),
        recovery_contract_version: Some(1),
        request_fingerprint: Some("stored-fingerprint".to_string()),
        cancel_operation_id: None,
    });
    let store = Arc::new(MemoryStore::new(stored_auth));
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    )
    .with_retry_policy(RetryPolicy::new(Vec::new()));

    assert!(matches!(
        core.start(options(), 1_700_000_000).await,
        Err(CoreError::Api(CoreApiError::Retryable))
    ));

    let requests = api.start_requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].operation_id, "pending-recovery-operation");
    assert_eq!(requests[0].recovery_contract_version, Some(1));
    assert_eq!(
        requests[0].request_fingerprint.as_deref(),
        Some("stored-fingerprint")
    );
    assert_eq!(
        store.load().unwrap().unwrap().pending_start,
        Some(StoredPendingStart {
            operation_id: "pending-recovery-operation".to_string(),
            layer: Layer::Stray,
            tic_connection_mode: TicConnectionMode::Dynamic,
            route_mode: RouteMode::Standalone,
            egress_mode: EgressMode::Ipv4,
            allow_alternate: false,
            probes: Vec::new(),
            recovery_contract_version: Some(1),
            request_fingerprint: Some("stored-fingerprint".to_string()),
            cancel_operation_id: None,
        })
    );
}

#[cfg(not(target_os = "android"))]
#[tokio::test(flavor = "current_thread")]
async fn recovery_entry_replays_the_stored_legacy_contract_without_mutating_it() {
    let api = Arc::new(MockApi::new(1));
    let mut stored_auth = auth();
    stored_auth.pending_start = Some(StoredPendingStart {
        operation_id: "pending-legacy-operation".to_string(),
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        egress_mode: EgressMode::Ipv4,
        allow_alternate: false,
        probes: Vec::new(),
        recovery_contract_version: None,
        request_fingerprint: None,
        cancel_operation_id: None,
    });
    let store = Arc::new(MemoryStore::new(stored_auth));
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    );

    assert!(matches!(
        core.connection_intent_attempt(options(), 1_700_000_000)
            .await,
        Err(CoreError::Api(CoreApiError::Retryable))
    ));

    let requests = api.start_requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].operation_id, "pending-legacy-operation");
    assert_eq!(requests[0].recovery_contract_version, None);
    assert_eq!(requests[0].request_fingerprint, None);
    assert_eq!(
        store
            .load()
            .unwrap()
            .unwrap()
            .pending_start
            .unwrap()
            .cancel_operation_id,
        None
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_different_start_intent_cannot_replace_an_unresolved_operation() {
    let api = Arc::new(MockApi::new(0));
    let mut stored_auth = auth();
    stored_auth.pending_start = Some(StoredPendingStart {
        operation_id: "unresolved-operation".to_string(),
        layer: Layer::Tic,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::ViaTak,
        egress_mode: EgressMode::Ipv4,
        allow_alternate: false,
        probes: Vec::new(),
        recovery_contract_version: None,
        request_fingerprint: None,
        cancel_operation_id: None,
    });
    let store = Arc::new(MemoryStore::new(stored_auth));
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    );
    let mut different_options = options();
    different_options.layer = Layer::Tic;
    different_options.route_mode = RouteMode::ViaTak;
    different_options.egress_mode = EgressMode::PreferIpv6;

    let error = core
        .start(different_options, 1_700_000_000)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        CoreError::Api(CoreApiError::Rejected { ref code, .. })
            if code == "operation_in_progress"
    ));
    assert_eq!(api.start_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        store
            .load()
            .unwrap()
            .unwrap()
            .pending_start
            .unwrap()
            .operation_id,
        "unresolved-operation"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn allow_alternate_is_part_of_the_durable_start_intent() {
    let api = Arc::new(MockApi::new(0));
    let mut stored_auth = auth();
    stored_auth.pending_start = Some(StoredPendingStart {
        operation_id: "unresolved-operation".to_string(),
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        egress_mode: EgressMode::Ipv4,
        allow_alternate: false,
        probes: Vec::new(),
        recovery_contract_version: None,
        request_fingerprint: None,
        cancel_operation_id: None,
    });
    let store = Arc::new(MemoryStore::new(stored_auth));
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    );
    let mut different_options = options();
    different_options.allow_alternate = true;

    let error = core
        .start(different_options, 1_700_000_000)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        CoreError::Api(CoreApiError::Rejected { ref code, .. })
            if code == "operation_in_progress"
    ));
    assert_eq!(api.start_calls.load(Ordering::SeqCst), 0);
    assert!(
        !store
            .load()
            .unwrap()
            .unwrap()
            .pending_start
            .unwrap()
            .allow_alternate
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_start_with_durable_cancellation_in_progress_cannot_be_replayed() {
    let api = Arc::new(MockApi::new(0));
    let mut stored_auth = auth();
    stored_auth.pending_start = Some(StoredPendingStart {
        operation_id: "cancelling-operation".to_string(),
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        egress_mode: EgressMode::Ipv4,
        allow_alternate: false,
        probes: Vec::new(),
        recovery_contract_version: None,
        request_fingerprint: None,
        cancel_operation_id: Some("stable-stop-operation".to_string()),
    });
    let store = Arc::new(MemoryStore::new(stored_auth));
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    );

    let error = core.start(options(), 1_700_000_000).await.unwrap_err();

    assert!(matches!(
        error,
        CoreError::Api(CoreApiError::Rejected { ref code, .. })
            if code == "operation_in_progress"
    ));
    assert_eq!(core.state().await.phase, Phase::Stopping);
    assert_eq!(api.start_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        store
            .load()
            .unwrap()
            .unwrap()
            .pending_start
            .unwrap()
            .cancel_operation_id
            .as_deref(),
        Some("stable-stop-operation")
    );
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
        egress_mode: EgressMode::Ipv4,
        probes: Vec::new(),
        allow_alternate: false,
    };

    core.start(fixed.clone(), 1_700_000_000).await.unwrap_err();
    assert!(store.load().unwrap().unwrap().pending_start.is_some());

    api.stop_as_released.store(true, Ordering::SeqCst);
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
async fn fixed_stale_release_rejects_warm_and_keeps_its_durable_compensation() {
    let mut stored_auth = auth();
    stored_auth.pending_start = Some(StoredPendingStart {
        operation_id: "fixed-pending-start".to_string(),
        layer: Layer::Tic,
        tic_connection_mode: TicConnectionMode::Personal,
        route_mode: RouteMode::ViaTak,
        egress_mode: EgressMode::Ipv4,
        allow_alternate: false,
        probes: Vec::new(),
        recovery_contract_version: None,
        request_fingerprint: None,
        cancel_operation_id: None,
    });
    let store = Arc::new(MemoryStore::new(stored_auth));
    let api = Arc::new(MockApi::new(0));
    *api.bootstrap_connection.lock().unwrap() = Some(Connection {
        layer: Layer::Tic,
        tic_connection_mode: TicConnectionMode::Personal,
        route_mode: RouteMode::ViaTak,
        status: LeaseStatus::Issued,
        ..connection("fixed-stale-lease")
    });
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    );
    core.bootstrap(1_700_000_000).await.unwrap();

    let error = core.prepare_binding_change().await.unwrap_err();

    assert!(matches!(
        error,
        CoreError::Api(CoreApiError::Rejected { ref code, .. })
            if code == "connection_release_pending"
    ));
    let stored = store.load().unwrap().unwrap();
    assert!(stored.pending_start.is_some());
    let pending = stored
        .pending_compensation_stop
        .expect("fixed stale release must remain durable after an unexpected Warm");
    assert!(!pending.accept_warm);
    assert_eq!(api.stop_operation_ids.lock().unwrap().len(), 1);
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
        pool_id: None,
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        egress_mode: EgressMode::Ipv4,
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
        pool_id: None,
        layer: Layer::Tic,
        tic_connection_mode: TicConnectionMode::Personal,
        route_mode: RouteMode::ViaTak,
        egress_mode: EgressMode::Ipv4,
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
        egress_mode: EgressMode::Ipv4,
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
            retry_after_seconds: None,
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
        egress_mode: EgressMode::Ipv4,
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
            retry_after_seconds: None,
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
async fn replacing_a_finished_start_operation_drops_its_old_cancel_operation_id() {
    let api = Arc::new(MockApi::new(0));
    api.start_errors.lock().unwrap().extend([
        CoreApiError::Rejected {
            code: "connection_no_longer_active".to_string(),
            message: "Это подключение уже завершено. Начните новое.".to_string(),
            retry_after_seconds: None,
        },
        CoreApiError::Retryable,
    ]);
    let mut stored_auth = auth();
    stored_auth.pending_start = Some(StoredPendingStart {
        operation_id: "finished-operation".to_string(),
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        egress_mode: EgressMode::Ipv4,
        allow_alternate: false,
        probes: Vec::new(),
        recovery_contract_version: None,
        request_fingerprint: None,
        cancel_operation_id: None,
    });
    let store = Arc::new(MemoryStore::new(stored_auth));
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    )
    .with_retry_policy(RetryPolicy::new(Vec::new()));

    assert!(matches!(
        core.start(options(), 1_700_000_000).await,
        Err(CoreError::Api(CoreApiError::Retryable))
    ));

    let operation_ids = api.operation_ids.lock().unwrap();
    assert_eq!(operation_ids.len(), 2);
    assert_eq!(operation_ids[0], "finished-operation");
    assert_ne!(operation_ids[1], operation_ids[0]);
    let pending = store.load().unwrap().unwrap().pending_start.unwrap();
    assert_eq!(pending.operation_id, operation_ids[1]);
    assert_eq!(pending.cancel_operation_id, None);
}

#[cfg(not(target_os = "android"))]
#[tokio::test(flavor = "current_thread")]
async fn retry_same_and_retry_after_policy_replay_the_exact_start_operation() {
    let raw = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../contracts/fixtures/valid/connection-intent-error-policy.json"),
    )
    .unwrap();
    let policy: serde_json::Value = serde_json::from_str(&raw).unwrap();
    for case in policy["cases"].as_array().unwrap().iter().filter(|case| {
        matches!(
            case["decision"].as_str(),
            Some("retry_same_operation" | "retry_after")
        )
    }) {
        let code = case["code"].as_str().unwrap();
        let api = Arc::new(MockApi::new(0));
        api.start_errors
            .lock()
            .unwrap()
            .push_back(CoreApiError::Rejected {
                code: code.to_string(),
                message: "retry the durable operation".to_string(),
                retry_after_seconds: (case["decision"] == "retry_after").then_some(17),
            });
        let store = Arc::new(MemoryStore::new(auth()));
        let core = ClientCore::new(
            api.clone(),
            store.clone(),
            Arc::new(MemoryTunnel::default()),
            Arc::new(MemoryLogger::default()),
        );

        assert!(core
            .connection_intent_attempt(options(), 1_700_000_000)
            .await
            .is_err());
        let durable = store
            .load()
            .unwrap()
            .unwrap()
            .pending_start
            .expect("retryable server operation must remain durable");
        assert_eq!(durable.recovery_contract_version, Some(1), "code={code}");
        assert!(
            durable
                .request_fingerprint
                .as_deref()
                .is_some_and(|value| !value.is_empty()),
            "code={code}"
        );

        core.connection_intent_attempt(options(), 1_700_000_017)
            .await
            .unwrap();

        let requests = api.start_requests.lock().unwrap();
        assert_eq!(requests.len(), 2, "code={code}");
        assert_eq!(requests[0], requests[1], "code={code}");
    }
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
        pool_id: None,
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        egress_mode: EgressMode::Ipv4,
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
        pool_id: None,
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        egress_mode: EgressMode::Ipv4,
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
        pool_id: None,
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        egress_mode: EgressMode::Ipv4,
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
        pool_id: None,
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        egress_mode: EgressMode::Ipv4,
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
        pool_id: None,
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        egress_mode: EgressMode::Ipv4,
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
        pool_id: None,
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        egress_mode: EgressMode::Ipv4,
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
        pool_id: None,
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        egress_mode: EgressMode::Ipv4,
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
        pool_id: None,
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        egress_mode: EgressMode::Ipv4,
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
                egress_mode: EgressMode::Ipv4,
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
        egress_mode: EgressMode::Ipv4,
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
        pool_id: None,
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        egress_mode: EgressMode::Ipv4,
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
        pool_id: None,
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        egress_mode: EgressMode::Ipv4,
        probe_url: Some("https://5a.example.test/probe".to_string()),
        kind: StoredConnectionKind::DynamicWarm,
        configuration: "PrivateKey = alternate-secret".to_string(),
        valid_until_unix: Some(1_700_003_600),
    });
    stored.pinned_connection = Some(StoredConnection {
        lease_id: "pinned-lease".to_string(),
        pool_id: None,
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        egress_mode: EgressMode::Ipv4,
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

#[test]
fn connection_intent_backoff_and_network_wakeup_are_bounded_and_coalesced() {
    assert_eq!(
        RetrySchedule::default().delays_seconds(),
        [0, 2, 5, 15, 30, 60, 300]
    );

    let mut coordinator = ConnectionIntentCoordinator::default();
    assert!(matches!(
        coordinator.start_or_resume(options(), 1_000).unwrap(),
        StartDisposition::Recovering { .. }
    ));
    let generation = coordinator.generation();
    assert!(coordinator.wake_for_network_change());
    assert!(!coordinator.wake_for_network_change());
    assert!(coordinator.take_network_wakeup());
    assert!(!coordinator.take_network_wakeup());

    let expected = [1_000, 1_002, 1_005, 1_015, 1_030, 1_060, 1_300, 1_300];
    for next_retry_at in expected {
        assert_eq!(
            coordinator.schedule_retry(generation, 1_000),
            Some(next_retry_at)
        );
    }
    assert!(coordinator.wake_for_network_change());
    assert!(coordinator.take_network_wakeup());
    assert_eq!(coordinator.schedule_retry(generation, 1_000), Some(1_002));
}

#[test]
fn connection_intent_has_one_attempt_and_late_success_is_compensated_after_cancel() {
    let mut coordinator = ConnectionIntentCoordinator::default();
    coordinator.start_or_resume(options(), 1_000).unwrap();
    let old_generation = coordinator.generation();
    assert!(coordinator.begin_attempt(old_generation));
    assert!(!coordinator.begin_attempt(old_generation));
    assert!(coordinator.cancel_intent(old_generation));
    assert_eq!(
        coordinator.accept_result(old_generation),
        RecoveryDecision::DiscardAndCompensate
    );
    assert_eq!(
        coordinator.start_or_resume(options(), 1_001),
        Err(nelomai_client_core::ConnectionIntentError::AttemptStillActive)
    );
    assert!(coordinator.complete_compensation(old_generation));
    assert!(matches!(
        coordinator.start_or_resume(options(), 1_002).unwrap(),
        StartDisposition::Recovering { .. }
    ));
}

#[test]
fn connection_intent_explicit_retry_rearms_a_blocked_terminal_intent() {
    let mut coordinator = ConnectionIntentCoordinator::default();
    coordinator.start_or_resume(options(), 1_000).unwrap();
    let blocked_generation = coordinator.generation();
    assert!(coordinator.begin_attempt(blocked_generation));
    assert!(coordinator.mark_terminal(blocked_generation, true));
    assert_eq!(
        coordinator.status(),
        nelomai_client_core::ConnectionIntentStatus::BlockedTerminal
    );

    let disposition = coordinator.start_or_resume(options(), 1_001).unwrap();
    let StartDisposition::Recovering {
        generation,
        next_retry_at_unix,
    } = disposition
    else {
        panic!("blocked intent must be rearmed")
    };
    assert_ne!(generation, blocked_generation);
    assert_eq!(next_retry_at_unix, None);
    assert_eq!(
        coordinator.status(),
        nelomai_client_core::ConnectionIntentStatus::Recovering
    );
    assert!(coordinator.begin_attempt(generation));
}

#[test]
fn connection_intent_classifier_matches_the_shared_policy_fixture() {
    let raw = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../contracts/fixtures/valid/connection-intent-error-policy.json"),
    )
    .unwrap();
    let policy: serde_json::Value = serde_json::from_str(&raw).unwrap();
    for case in policy["cases"].as_array().unwrap() {
        let code = case["code"].as_str().unwrap();
        let expected = case["decision"].as_str().unwrap();
        let decision = classify_recovery(code, RecoveryPolicyContext::default());
        assert_eq!(
            decision.policy_name(),
            expected,
            "wrong decision for {code}"
        );
        assert_eq!(
            decision.preserves_operation(),
            !matches!(expected, "retry_new_operation" | "terminal"),
            "wrong operation preservation for {code}"
        );
    }
    assert_eq!(
        classify_recovery("future_unknown_error", RecoveryPolicyContext::default()),
        RecoveryDecision::Terminal
    );
}

#[test]
fn connection_intent_bounded_retries_and_retry_after_do_not_loop() {
    assert_eq!(
        classify_recovery(
            "connection_release_pending",
            RecoveryPolicyContext::default()
        ),
        RecoveryDecision::RetrySameOperation
    );
    for (code, retry_after_seconds) in [("operation_in_progress", 2), ("device_operation_busy", 30)]
    {
        assert_eq!(
            classify_recovery(
                code,
                RecoveryPolicyContext {
                    retry_after_seconds: Some(retry_after_seconds),
                    ..RecoveryPolicyContext::default()
                }
            ),
            RecoveryDecision::RetryAfter(retry_after_seconds),
            "{code} must preserve the same operation and the panel retry window",
        );
    }
    assert_eq!(
        classify_recovery("service_unavailable", RecoveryPolicyContext::default()),
        RecoveryDecision::RetryOnce
    );
    assert_eq!(
        classify_recovery(
            "service_unavailable",
            RecoveryPolicyContext {
                service_recovery_attempted: true,
                ..RecoveryPolicyContext::default()
            }
        ),
        RecoveryDecision::Terminal
    );
    assert_eq!(
        classify_recovery(
            "amneziawg_profile_mismatch",
            RecoveryPolicyContext {
                profile_reissue_attempted: true,
                ..RecoveryPolicyContext::default()
            }
        ),
        RecoveryDecision::Terminal
    );
    assert_eq!(
        classify_recovery(
            "connection_stall_not_recyclable",
            RecoveryPolicyContext {
                stalled_reconcile_attempted: true,
                ..RecoveryPolicyContext::default()
            }
        ),
        RecoveryDecision::Terminal
    );
    assert_eq!(
        classify_recovery(
            "connection_stall_recycle_rate_limited",
            RecoveryPolicyContext {
                retry_after_seconds: Some(10_000),
                ..RecoveryPolicyContext::default()
            }
        ),
        RecoveryDecision::RetryAfter(900)
    );
    assert_eq!(
        classify_recovery(
            "connection_stall_recycle_rate_limited",
            RecoveryPolicyContext::default()
        ),
        RecoveryDecision::RetryAfter(300)
    );
}

#[test]
fn connection_intent_stall_plan_replaces_only_unpinned_dynamic_awg3() {
    assert_eq!(
        stall_recovery_plan(&options(), false, RecoveryTransport::AmneziaWg3),
        StallRecoveryPlan::ReplaceDynamic {
            failure_code: "tunnel_data_plane_stalled",
            allow_alternate: true,
        }
    );

    let mut personal = options();
    personal.layer = Layer::Tic;
    personal.tic_connection_mode = TicConnectionMode::Personal;
    personal.route_mode = RouteMode::ViaTak;
    assert_eq!(
        stall_recovery_plan(&personal, false, RecoveryTransport::AmneziaWg3),
        StallRecoveryPlan::PreservePeer
    );
    assert_eq!(
        stall_recovery_plan(&options(), true, RecoveryTransport::AmneziaWg3),
        StallRecoveryPlan::PreservePeer
    );
    assert_eq!(
        stall_recovery_plan(&options(), false, RecoveryTransport::Other),
        StallRecoveryPlan::PreservePeer
    );
}

#[test]
fn connection_intent_handle_stall_keeps_the_same_intent_generation() {
    let mut coordinator = ConnectionIntentCoordinator::default();
    coordinator.start_or_resume(options(), 1_000).unwrap();
    let generation = coordinator.generation();
    assert!(coordinator.begin_attempt(generation));
    assert_eq!(
        coordinator.mark_connected(
            generation,
            connection("11111111-1111-4111-8111-111111111111"),
        ),
        RecoveryDecision::Accept
    );

    assert_eq!(
        coordinator
            .handle_stall(
                generation,
                StallTrigger {
                    options: options(),
                    pinned: false,
                    transport: RecoveryTransport::AmneziaWg3,
                }
            )
            .unwrap(),
        StallRecoveryPlan::ReplaceDynamic {
            failure_code: "tunnel_data_plane_stalled",
            allow_alternate: true,
        }
    );
    assert_eq!(coordinator.generation(), generation);
    assert_eq!(
        coordinator.status(),
        nelomai_client_core::ConnectionIntentStatus::Recovering
    );
}

#[test]
fn connection_intent_can_replace_a_quick_toggle_placeholder_during_its_first_attempt() {
    let mut coordinator = ConnectionIntentCoordinator::default();
    coordinator.start_or_resume(options(), 1_000).unwrap();
    let generation = coordinator.generation();
    assert!(coordinator.begin_attempt(generation));
    let mut resolved = options();
    resolved.egress_mode = EgressMode::PreferIpv6;

    assert!(coordinator.replace_active_options(generation, resolved.clone()));
    assert_eq!(
        coordinator.mark_connected(generation, connection("resolved-lease")),
        RecoveryDecision::Accept
    );
    assert!(coordinator
        .handle_stall(
            generation,
            StallTrigger {
                options: resolved,
                pinned: false,
                transport: RecoveryTransport::AmneziaWg3,
            },
        )
        .is_ok());
}

#[test]
fn connection_intent_rejects_a_stale_stall_callback_for_a_new_generation() {
    let mut coordinator = ConnectionIntentCoordinator::default();
    coordinator.start_or_resume(options(), 1_000).unwrap();
    let stale_generation = coordinator.generation();
    assert!(coordinator.cancel_intent(stale_generation));

    coordinator.start_or_resume(options(), 1_001).unwrap();
    let current_generation = coordinator.generation();
    let scheduled_retry = coordinator
        .schedule_retry(current_generation, 1_001)
        .unwrap();

    assert!(coordinator
        .handle_stall(
            stale_generation,
            StallTrigger {
                options: options(),
                pinned: false,
                transport: RecoveryTransport::AmneziaWg3,
            },
        )
        .is_err());
    assert_eq!(coordinator.generation(), current_generation);
    assert_eq!(
        coordinator.start_or_resume(options(), 1_002).unwrap(),
        StartDisposition::Recovering {
            generation: current_generation,
            next_retry_at_unix: Some(scheduled_retry),
        }
    );
}

#[cfg(not(target_os = "android"))]
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn connection_intent_core_attempt_leaves_retries_to_the_coordinator() {
    let api = Arc::new(MockApi::new(1));
    let core = ClientCore::new(
        api.clone(),
        Arc::new(MemoryStore::new(auth())),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    );

    assert!(matches!(
        core.connection_intent_attempt(options(), 1_700_000_000)
            .await,
        Err(CoreError::Api(CoreApiError::Retryable))
    ));
    assert_eq!(api.start_calls.load(Ordering::SeqCst), 1);
    let request = api.start_requests.lock().unwrap()[0].clone();
    assert!(request.require_measured_selection);
    assert_eq!(request.recovery_contract_version, Some(1));
    assert_eq!(
        request.request_fingerprint.as_deref(),
        Some("b359819586b12285e3c8636ac51d823ade7f87a084f4097bf3f3735bae8c3c39")
    );
}

#[cfg(not(target_os = "android"))]
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn connection_intent_busy_retry_reuses_the_durable_operation_id() {
    for code in ["operation_in_progress", "device_operation_busy"] {
        let api = Arc::new(MockApi::new(0));
        api.start_errors
            .lock()
            .unwrap()
            .push_back(CoreApiError::Rejected {
                code: code.to_string(),
                message: "Retry later".to_string(),
                retry_after_seconds: Some(2),
            });
        let core = ClientCore::new(
            api.clone(),
            Arc::new(MemoryStore::new(auth())),
            Arc::new(MemoryTunnel::default()),
            Arc::new(MemoryLogger::default()),
        );

        assert!(core
            .connection_intent_attempt(options(), 1_700_000_000)
            .await
            .is_err());
        core.connection_intent_attempt(options(), 1_700_000_002)
            .await
            .unwrap();

        let operation_ids = api.operation_ids.lock().unwrap();
        assert_eq!(
            operation_ids.len(),
            2,
            "unexpected request count for {code}"
        );
        assert_eq!(
            operation_ids[0], operation_ids[1],
            "{code} must retry the exact server operation",
        );
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn legacy_start_retries_structured_busy_with_the_same_operation_id() {
    for code in ["operation_in_progress", "device_operation_busy"] {
        let api = Arc::new(MockApi::new(0));
        api.start_errors
            .lock()
            .unwrap()
            .push_back(CoreApiError::Rejected {
                code: code.to_string(),
                message: "Retry later".to_string(),
                retry_after_seconds: Some(2),
            });
        let core = ClientCore::new(
            api.clone(),
            Arc::new(MemoryStore::new(auth())),
            Arc::new(MemoryTunnel::default()),
            Arc::new(MemoryLogger::default()),
        )
        .with_retry_policy(RetryPolicy::new(vec![0]));

        core.start(options(), 1_700_000_000).await.unwrap();

        let operation_ids = api.operation_ids.lock().unwrap();
        assert_eq!(
            operation_ids.len(),
            2,
            "unexpected request count for {code}"
        );
        assert_eq!(
            operation_ids[0], operation_ids[1],
            "legacy {code} retry must keep the original operation",
        );
    }
}

#[cfg(not(target_os = "android"))]
#[tokio::test(flavor = "current_thread")]
async fn cancellation_polls_server_owned_unknown_start_until_authoritative_terminal() {
    for nonterminal in [
        OperationState::Pending,
        OperationState::Applying,
        OperationState::Compensating,
    ] {
        let api = Arc::new(MockApi::new(0));
        api.start_errors
            .lock()
            .unwrap()
            .push_back(CoreApiError::Retryable);
        api.reconcile_responses.lock().unwrap().extend([
            OperationReconcileResponse {
                api_version: ApiVersion::V1,
                request_id: "reconcile-pending".to_string(),
                state: nonterminal,
                cancel_requested: true,
                lease_id: Some("server-owned-lease".to_string()),
                lease_status: Some(LeaseStatus::Issued),
                retry_count: 1,
                next_attempt_at: None,
            },
            OperationReconcileResponse {
                api_version: ApiVersion::V1,
                request_id: "reconcile-terminal".to_string(),
                state: OperationState::Terminal,
                cancel_requested: false,
                lease_id: Some("server-owned-lease".to_string()),
                lease_status: Some(LeaseStatus::Failed),
                retry_count: 2,
                next_attempt_at: None,
            },
        ]);
        let store = Arc::new(MemoryStore::new(auth()));
        let core = ClientCore::new(
            api.clone(),
            store.clone(),
            Arc::new(MemoryTunnel::default()),
            Arc::new(MemoryLogger::default()),
        );

        assert!(core
            .connection_intent_attempt(options(), 1_700_000_000)
            .await
            .is_err());
        let pending = store.load().unwrap().unwrap().pending_start.unwrap();
        assert!(core.signal_start_cancellation());

        let error = core.stop().await.unwrap_err();
        assert!(matches!(
            error,
            CoreError::Api(CoreApiError::Rejected {
                ref code,
                retry_after_seconds: Some(2),
                ..
            }) if code == "operation_in_progress"
        ));
        assert_eq!(core.state().await.phase, Phase::Stopping);
        assert_eq!(
            store.load().unwrap().unwrap().pending_start,
            Some(pending.clone()),
            "state={nonterminal:?}"
        );
        assert_eq!(api.stop_calls.load(Ordering::SeqCst), 0);

        assert!(matches!(
            core.stop().await,
            Err(CoreError::SavedConnectionUnavailable)
        ));
        assert_eq!(core.state().await.phase, Phase::Ready);
        assert!(store.load().unwrap().unwrap().pending_start.is_none());

        core.connection_intent_attempt(options(), 1_700_000_002)
            .await
            .unwrap();
        let operation_ids = api.operation_ids.lock().unwrap();
        assert_eq!(operation_ids.len(), 2);
        assert_ne!(operation_ids[0], operation_ids[1]);
        let reconciliations = api.reconcile_requests.lock().unwrap();
        assert_eq!(reconciliations.len(), 2);
        assert!(reconciliations.iter().all(|request| {
            request.operation_id == pending.operation_id
                && request.contract_version == 1
                && request.request_fingerprint == pending.request_fingerprint.clone().unwrap()
                && request.cancel_if_absent
        }));
    }
}

#[cfg(not(target_os = "android"))]
#[tokio::test(flavor = "current_thread")]
async fn cancellation_not_found_tombstone_clears_pending_without_replaying_start() {
    let api = Arc::new(MockApi::new(0));
    api.start_errors
        .lock()
        .unwrap()
        .push_back(CoreApiError::Retryable);
    api.reconcile_responses
        .lock()
        .unwrap()
        .push_back(OperationReconcileResponse {
            api_version: ApiVersion::V1,
            request_id: "reconcile-cancelled-absence".to_string(),
            state: OperationState::NotFound,
            cancel_requested: true,
            lease_id: None,
            lease_status: None,
            retry_count: 0,
            next_attempt_at: None,
        });
    let store = Arc::new(MemoryStore::new(auth()));
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    );

    assert!(core
        .connection_intent_attempt(options(), 1_700_000_000)
        .await
        .is_err());
    let pending = store.load().unwrap().unwrap().pending_start.unwrap();
    let first_request = api.start_requests.lock().unwrap()[0].clone();
    assert!(core.signal_start_cancellation());

    assert!(matches!(
        core.stop().await,
        Err(CoreError::SavedConnectionUnavailable)
    ));

    assert_eq!(core.state().await.phase, Phase::Ready);
    assert!(store.load().unwrap().unwrap().pending_start.is_none());
    assert_eq!(
        api.start_requests.lock().unwrap().as_slice(),
        &[first_request]
    );
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 0);
    let reconciliations = api.reconcile_requests.lock().unwrap();
    assert_eq!(reconciliations.len(), 1);
    assert_eq!(reconciliations[0].operation_id, pending.operation_id);
    assert_eq!(reconciliations[0].contract_version, 1);
    assert_eq!(
        reconciliations[0].request_fingerprint,
        pending.request_fingerprint.unwrap()
    );
    assert!(reconciliations[0].cancel_if_absent);
}

#[cfg(not(target_os = "android"))]
#[tokio::test(flavor = "current_thread")]
async fn retry_reconcile_polls_nonterminal_server_owned_operations_without_replay() {
    for state in [
        OperationState::Pending,
        OperationState::Applying,
        OperationState::Compensating,
    ] {
        let api = Arc::new(MockApi::new(0));
        api.start_errors
            .lock()
            .unwrap()
            .push_back(CoreApiError::Retryable);
        api.reconcile_responses
            .lock()
            .unwrap()
            .push_back(OperationReconcileResponse {
                api_version: ApiVersion::V1,
                request_id: "reconcile-request".to_string(),
                state,
                cancel_requested: false,
                lease_id: Some("server-owned-lease".to_string()),
                lease_status: Some(LeaseStatus::Issued),
                retry_count: 3,
                next_attempt_at: None,
            });
        let store = Arc::new(MemoryStore::new(auth()));
        let core = ClientCore::new(
            api.clone(),
            store.clone(),
            Arc::new(MemoryTunnel::default()),
            Arc::new(MemoryLogger::default()),
        );
        assert!(core
            .connection_intent_attempt(options(), 1_700_000_000)
            .await
            .is_err());
        let durable = store.load().unwrap().unwrap().pending_start.unwrap();

        let error = core
            .reconcile_pending_operation_for_retry()
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            CoreError::Api(CoreApiError::Rejected {
                ref code,
                retry_after_seconds: Some(15),
                ..
            }) if code == "operation_in_progress"
        ));
        assert_eq!(api.start_calls.load(Ordering::SeqCst), 1, "state={state:?}");
        assert_eq!(
            store.load().unwrap().unwrap().pending_start,
            Some(durable.clone()),
            "state={state:?}"
        );
        let reconciliations = api.reconcile_requests.lock().unwrap();
        assert_eq!(reconciliations.len(), 1, "state={state:?}");
        assert_eq!(reconciliations[0].operation_id, durable.operation_id);
        assert_eq!(reconciliations[0].contract_version, 1);
        assert_eq!(
            reconciliations[0].request_fingerprint,
            durable.request_fingerprint.unwrap()
        );
        assert!(!reconciliations[0].cancel_if_absent);
    }
}

#[cfg(not(target_os = "android"))]
#[tokio::test(flavor = "current_thread")]
async fn retry_reconcile_exact_replays_not_found_and_applied_active_and_replaces_only_authoritative_terminal(
) {
    for (state, lease_status, must_replay_exactly) in [
        (OperationState::NotFound, None, true),
        (OperationState::Applied, Some(LeaseStatus::Issued), true),
        (OperationState::Applied, Some(LeaseStatus::Released), false),
        (OperationState::Terminal, Some(LeaseStatus::Failed), false),
        (OperationState::Cancelled, None, false),
    ] {
        let api = Arc::new(MockApi::new(0));
        api.start_errors
            .lock()
            .unwrap()
            .push_back(CoreApiError::Retryable);
        api.reconcile_responses
            .lock()
            .unwrap()
            .push_back(OperationReconcileResponse {
                api_version: ApiVersion::V1,
                request_id: "reconcile-request".to_string(),
                state,
                cancel_requested: false,
                lease_id: lease_status.map(|_| "reconciled-lease".to_string()),
                lease_status,
                retry_count: 0,
                next_attempt_at: None,
            });
        let store = Arc::new(MemoryStore::new(auth()));
        let core = ClientCore::new(
            api.clone(),
            store.clone(),
            Arc::new(MemoryTunnel::default()),
            Arc::new(MemoryLogger::default()),
        );
        assert!(core
            .connection_intent_attempt(options(), 1_700_000_000)
            .await
            .is_err());
        let first_request = api.start_requests.lock().unwrap()[0].clone();
        let durable = store.load().unwrap().unwrap().pending_start.unwrap();

        core.reconcile_pending_operation_for_retry().await.unwrap();
        if must_replay_exactly {
            assert_eq!(
                store.load().unwrap().unwrap().pending_start,
                Some(durable),
                "state={state:?} must retain the exact durable request"
            );
        } else {
            assert!(
                store.load().unwrap().unwrap().pending_start.is_none(),
                "state={state:?} status={lease_status:?} is authoritative"
            );
        }
        core.connection_intent_attempt(options(), 1_700_000_001)
            .await
            .unwrap();

        let requests = api.start_requests.lock().unwrap();
        assert_eq!(requests.len(), 2, "state={state:?} status={lease_status:?}");
        if must_replay_exactly {
            assert_eq!(requests[1], first_request, "state={state:?}");
        } else {
            assert_ne!(
                requests[1].operation_id, first_request.operation_id,
                "state={state:?} status={lease_status:?}"
            );
        }
    }
}

#[cfg(not(target_os = "android"))]
#[tokio::test(flavor = "current_thread")]
async fn retry_reconcile_does_not_clear_a_lease_without_authoritative_terminal_status() {
    let api = Arc::new(MockApi::new(0));
    api.start_errors
        .lock()
        .unwrap()
        .push_back(CoreApiError::Retryable);
    api.reconcile_responses
        .lock()
        .unwrap()
        .push_back(OperationReconcileResponse {
            api_version: ApiVersion::V1,
            request_id: "reconcile-request".to_string(),
            state: OperationState::Terminal,
            cancel_requested: false,
            lease_id: Some("unconfirmed-lease".to_string()),
            lease_status: None,
            retry_count: 0,
            next_attempt_at: None,
        });
    let store = Arc::new(MemoryStore::new(auth()));
    let core = ClientCore::new(
        api,
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    );
    assert!(core
        .connection_intent_attempt(options(), 1_700_000_000)
        .await
        .is_err());
    let pending = store.load().unwrap().unwrap().pending_start.unwrap();

    let error = core
        .reconcile_pending_operation_for_retry()
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        CoreError::Api(CoreApiError::Rejected { ref code, .. })
            if code == "invalid_client_api_response"
    ));
    assert_eq!(store.load().unwrap().unwrap().pending_start, Some(pending));
}

#[cfg(not(target_os = "android"))]
#[tokio::test(flavor = "current_thread")]
async fn cancellation_stops_an_already_applied_unknown_recovery_lease() {
    let api = Arc::new(MockApi::new(0));
    api.stop_failures.store(1, Ordering::SeqCst);
    api.start_errors
        .lock()
        .unwrap()
        .push_back(CoreApiError::Retryable);
    api.reconcile_responses.lock().unwrap().extend([
        OperationReconcileResponse {
            api_version: ApiVersion::V1,
            request_id: "reconcile-request-1".to_string(),
            state: OperationState::Applied,
            cancel_requested: true,
            lease_id: Some("late-lease".to_string()),
            lease_status: Some(LeaseStatus::Issued),
            retry_count: 0,
            next_attempt_at: None,
        },
        OperationReconcileResponse {
            api_version: ApiVersion::V1,
            request_id: "reconcile-request-2".to_string(),
            state: OperationState::Applied,
            cancel_requested: true,
            lease_id: Some("late-lease".to_string()),
            lease_status: Some(LeaseStatus::Issued),
            retry_count: 0,
            next_attempt_at: None,
        },
    ]);
    let store = Arc::new(MemoryStore::new(auth()));
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    )
    .with_retry_policy(RetryPolicy::new(Vec::new()));
    assert!(core
        .connection_intent_attempt(options(), 1_700_000_000)
        .await
        .is_err());

    assert!(core.signal_start_cancellation());
    assert!(matches!(
        core.stop().await,
        Err(CoreError::Api(CoreApiError::Retryable))
    ));
    assert_eq!(core.state().await.phase, Phase::Stopping);
    let pending_after_failed_stop = store.load().unwrap().unwrap().pending_start.unwrap();
    assert!(pending_after_failed_stop.cancel_operation_id.is_some());

    *api.stop_error.lock().unwrap() = None;
    let stopped = core.stop().await.unwrap();

    assert_eq!(stopped.lease_id, "late-lease");
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 2);
    {
        let stop_operation_ids = api.stop_operation_ids.lock().unwrap();
        assert_eq!(stop_operation_ids.len(), 2);
        assert_eq!(stop_operation_ids[0], stop_operation_ids[1]);
    }
    assert!(store.load().unwrap().unwrap().pending_start.is_none());
    assert_eq!(core.state().await.phase, Phase::Ready);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn cancelling_a_legacy_retry_after_interrupts_the_wait_then_cleans_up_the_unknown_start() {
    let api = Arc::new(MockApi::new(0));
    api.start_errors
        .lock()
        .unwrap()
        .push_back(CoreApiError::Rejected {
            code: "device_operation_busy".to_string(),
            message: "Retry later".to_string(),
            retry_after_seconds: Some(900),
        });
    let store = Arc::new(MemoryStore::new(auth()));
    let core = Arc::new(
        ClientCore::new(
            api.clone(),
            store.clone(),
            Arc::new(MemoryTunnel::default()),
            Arc::new(MemoryLogger::default()),
        )
        .with_retry_policy(RetryPolicy::new(vec![0])),
    );
    let mut start_options = options();
    start_options.allow_alternate = true;
    start_options.probes = vec![ProbeResult {
        candidate_id: "candidate-1".to_string(),
        latency_ms: Some(12.5),
        failure_code: None,
        measured_at: "2026-08-30T10:00:00Z".to_string(),
    }];
    let start = {
        let core = core.clone();
        tokio::spawn(async move { core.start(start_options, 1_700_000_000).await })
    };
    tokio::task::yield_now().await;
    assert_eq!(api.start_calls.load(Ordering::SeqCst), 1);

    assert!(core.signal_start_cancellation());
    let error = start.await.unwrap().unwrap_err();

    assert!(matches!(error, CoreError::StartCancelled));
    assert_eq!(core.state().await.phase, Phase::Ready);
    assert_eq!(api.start_calls.load(Ordering::SeqCst), 1);
    assert!(store.load().unwrap().unwrap().pending_start.is_some());

    let stopped = core.stop().await.unwrap();

    assert_eq!(stopped.lease_id, api.operation_ids.lock().unwrap()[0]);
    assert!(store.load().unwrap().unwrap().pending_start.is_none());
    assert_eq!(api.start_calls.load(Ordering::SeqCst), 2);
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
    let requests = api.start_requests.lock().unwrap();
    assert_eq!(requests[0], requests[1]);
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_pending_clears_after_probe_validation_proves_no_operation_exists() {
    for (code, probes) in [
        ("probe_results_required", Vec::new()),
        (
            "stale_probe_result",
            vec![ProbeResult {
                candidate_id: "expired-candidate".to_string(),
                latency_ms: Some(12.5),
                failure_code: None,
                measured_at: "2026-08-30T10:00:00Z".to_string(),
            }],
        ),
        (
            "candidate_expired",
            vec![ProbeResult {
                candidate_id: "expired-candidate".to_string(),
                latency_ms: Some(12.5),
                failure_code: None,
                measured_at: "2026-08-30T10:00:00Z".to_string(),
            }],
        ),
    ] {
        let api = Arc::new(MockApi::new(0));
        api.start_errors
            .lock()
            .unwrap()
            .push_back(CoreApiError::Rejected {
                code: code.to_string(),
                message: "Probe validation failed".to_string(),
                retry_after_seconds: None,
            });
        let mut stored_auth = auth();
        stored_auth.pending_start = Some(StoredPendingStart {
            operation_id: "22222222-2222-4222-8222-222222222222".to_string(),
            layer: Layer::Stray,
            tic_connection_mode: TicConnectionMode::Dynamic,
            route_mode: RouteMode::Standalone,
            egress_mode: EgressMode::Ipv4,
            allow_alternate: false,
            probes,
            recovery_contract_version: None,
            request_fingerprint: None,
            cancel_operation_id: None,
        });
        let store = Arc::new(MemoryStore::new(stored_auth));
        let core = ClientCore::new(
            api.clone(),
            store.clone(),
            Arc::new(MemoryTunnel::default()),
            Arc::new(MemoryLogger::default()),
        );

        assert!(matches!(
            core.stop().await,
            Err(CoreError::SavedConnectionUnavailable)
        ));

        assert_eq!(api.start_calls.load(Ordering::SeqCst), 1, "code={code}");
        assert!(
            store.load().unwrap().unwrap().pending_start.is_none(),
            "code={code}"
        );
        assert_eq!(core.state().await.phase, Phase::Ready, "code={code}");
    }
}

#[tokio::test(start_paused = true)]
async fn cancellation_during_panel_start_compensates_the_late_lease_before_local_start() {
    let api = Arc::new(MockApi::new(0));
    let store = Arc::new(MemoryStore::new(auth()));
    let tunnel = Arc::new(MemoryTunnel::default());
    let core = Arc::new(ClientCore::new(
        api.clone(),
        store.clone(),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    ));
    let cancel_epoch = core.begin_start_attempt();
    let attempt = {
        let core = core.clone();
        tokio::spawn(async move {
            core.start_with_cancellation_epoch(options(), 1_700_000_000, cancel_epoch)
                .await
        })
    };
    while api.start_calls.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }

    assert!(core.signal_start_cancellation());
    tokio::time::advance(Duration::from_millis(20)).await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(20)).await;
    tokio::task::yield_now().await;
    let error = attempt.await.unwrap().unwrap_err();
    core.finish_start_attempt();

    assert!(matches!(error, CoreError::StartCancelled));
    assert_eq!(api.start_calls.load(Ordering::SeqCst), 1);
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
    assert_eq!(tunnel.starts.load(Ordering::SeqCst), 0);
    assert_eq!(*tunnel.status.lock().unwrap(), TunnelStatus::Stopped);
    let stored = store.load().unwrap().unwrap();
    assert!(stored.pending_start.is_none());
    assert!(stored.pending_compensation_stop.is_none());

    let next_start = {
        let core = core.clone();
        tokio::spawn(async move { core.start(options(), 1_700_000_001).await })
    };
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(20)).await;
    tokio::task::yield_now().await;
    next_start.await.unwrap().unwrap();

    assert_eq!(api.start_calls.load(Ordering::SeqCst), 2);
    assert_eq!(tunnel.starts.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn cancellation_while_local_start_is_in_flight_stops_local_before_panel_compensation() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let api = Arc::new(MockApi::new(0));
    *api.operation_events.lock().unwrap() = Some(events.clone());
    let store = Arc::new(MemoryStore::new(auth()));
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.block_start.store(true, Ordering::SeqCst);
    *tunnel.operation_events.lock().unwrap() = Some(events.clone());
    let core = Arc::new(ClientCore::new(
        api.clone(),
        store.clone(),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    ));
    let cancel_epoch = core.begin_start_attempt();
    let attempt = {
        let core = core.clone();
        tokio::spawn(async move {
            core.start_with_cancellation_epoch(options(), 1_700_000_000, cancel_epoch)
                .await
        })
    };
    while tunnel.starts.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }

    assert!(core.signal_start_cancellation());
    tunnel.block_start.store(false, Ordering::SeqCst);
    tunnel.start_release.notify_one();
    let error = attempt.await.unwrap().unwrap_err();
    core.finish_start_attempt();

    assert!(matches!(error, CoreError::StartCancelled));
    assert_eq!(core.state().await.phase, Phase::Ready);
    assert_eq!(*tunnel.status.lock().unwrap(), TunnelStatus::Stopped);
    assert_eq!(tunnel.stops.load(Ordering::SeqCst), 1);
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        events.lock().unwrap().as_slice(),
        &["local_stop", "panel_stop"]
    );
    assert_eq!(api.stop_operation_ids.lock().unwrap().len(), 1);
    let stored = store.load().unwrap().unwrap();
    assert!(stored.pending_start.is_none());
    assert!(stored.pending_compensation_stop.is_none());

    core.start(options(), 1_700_000_001).await.unwrap();

    assert_eq!(api.start_calls.load(Ordering::SeqCst), 2);
    assert_eq!(core.state().await.phase, Phase::Connected);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn cancellation_while_handshake_is_in_flight_stops_local_before_panel_compensation() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let api = Arc::new(MockApi::new(0));
    api.awg3_start.store(true, Ordering::SeqCst);
    *api.operation_events.lock().unwrap() = Some(events.clone());
    let store = Arc::new(MemoryStore::new(auth()));
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.metrics_supported.store(true, Ordering::SeqCst);
    tunnel.handshake_before_rebind.store(true, Ordering::SeqCst);
    tunnel.block_metrics.store(true, Ordering::SeqCst);
    *tunnel.operation_events.lock().unwrap() = Some(events.clone());
    let core = Arc::new(ClientCore::new(
        api.clone(),
        store.clone(),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    ));
    let cancel_epoch = core.begin_start_attempt();
    let attempt = {
        let core = core.clone();
        tokio::spawn(async move {
            core.start_with_cancellation_epoch(options(), 1_700_000_000, cancel_epoch)
                .await
        })
    };
    for _ in 0..10 {
        if tunnel.blocked_metrics_calls.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::time::advance(Duration::from_millis(20)).await;
        tokio::task::yield_now().await;
    }
    assert_eq!(tunnel.blocked_metrics_calls.load(Ordering::SeqCst), 1);

    assert!(core.signal_start_cancellation());
    for _ in 0..32 {
        if api.stop_calls.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(tunnel.stops.load(Ordering::SeqCst), 1);
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_millis(20)).await;
    tokio::task::yield_now().await;
    let error = attempt.await.unwrap().unwrap_err();
    core.finish_start_attempt();

    assert!(matches!(error, CoreError::StartCancelled));
    assert_eq!(core.state().await.phase, Phase::Ready);
    assert_eq!(*tunnel.status.lock().unwrap(), TunnelStatus::Stopped);
    assert_eq!(tunnel.stops.load(Ordering::SeqCst), 1);
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        events.lock().unwrap().as_slice(),
        &["local_stop", "panel_stop"]
    );
    assert_eq!(api.stop_operation_ids.lock().unwrap().len(), 1);
    let stored = store.load().unwrap().unwrap();
    assert!(stored.pending_start.is_none());
    assert!(stored.pending_compensation_stop.is_none());
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn cancellation_while_post_rebind_handshake_is_in_flight_compensates_promptly() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let api = Arc::new(MockApi::new(0));
    api.awg3_start.store(true, Ordering::SeqCst);
    *api.operation_events.lock().unwrap() = Some(events.clone());
    let store = Arc::new(MemoryStore::new(auth()));
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.metrics_supported.store(true, Ordering::SeqCst);
    tunnel.rebind_supported.store(true, Ordering::SeqCst);
    tunnel
        .block_metrics_after_rebind
        .store(true, Ordering::SeqCst);
    *tunnel.operation_events.lock().unwrap() = Some(events.clone());
    let core = Arc::new(ClientCore::new(
        api.clone(),
        store.clone(),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    ));
    let cancel_epoch = core.begin_start_attempt();
    let attempt = {
        let core = core.clone();
        tokio::spawn(async move {
            core.start_with_cancellation_epoch(options(), 1_700_000_000, cancel_epoch)
                .await
        })
    };
    for _ in 0..40 {
        if tunnel.blocked_metrics_calls.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::time::advance(Duration::from_millis(200)).await;
        tokio::task::yield_now().await;
    }
    assert_eq!(tunnel.rebinds.load(Ordering::SeqCst), 1);
    assert_eq!(tunnel.blocked_metrics_calls.load(Ordering::SeqCst), 1);

    assert!(core.signal_start_cancellation());
    for _ in 0..32 {
        if api.stop_calls.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(tunnel.stops.load(Ordering::SeqCst), 1);
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_millis(20)).await;
    tokio::task::yield_now().await;
    let error = attempt.await.unwrap().unwrap_err();
    core.finish_start_attempt();

    assert!(matches!(error, CoreError::StartCancelled));
    assert_eq!(core.state().await.phase, Phase::Ready);
    assert_eq!(*tunnel.status.lock().unwrap(), TunnelStatus::Stopped);
    assert_eq!(tunnel.stops.load(Ordering::SeqCst), 1);
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        events.lock().unwrap().as_slice(),
        &["local_stop", "panel_stop"]
    );
    assert_eq!(api.stop_operation_ids.lock().unwrap().len(), 1);
    let stored = store.load().unwrap().unwrap();
    assert!(stored.pending_start.is_none());
    assert!(stored.pending_compensation_stop.is_none());
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn cancellation_while_udp_rebind_is_in_flight_compensates_promptly() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let api = Arc::new(MockApi::new(0));
    api.awg3_start.store(true, Ordering::SeqCst);
    *api.operation_events.lock().unwrap() = Some(events.clone());
    let store = Arc::new(MemoryStore::new(auth()));
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.metrics_supported.store(true, Ordering::SeqCst);
    tunnel.block_rebind.store(true, Ordering::SeqCst);
    *tunnel.operation_events.lock().unwrap() = Some(events.clone());
    let core = Arc::new(ClientCore::new(
        api.clone(),
        store.clone(),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    ));
    let cancel_epoch = core.begin_start_attempt();
    let attempt = {
        let core = core.clone();
        tokio::spawn(async move {
            core.start_with_cancellation_epoch(options(), 1_700_000_000, cancel_epoch)
                .await
        })
    };
    for _ in 0..40 {
        if tunnel.blocked_rebinds.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::time::advance(Duration::from_millis(200)).await;
        tokio::task::yield_now().await;
    }
    assert_eq!(tunnel.blocked_rebinds.load(Ordering::SeqCst), 1);

    assert!(core.signal_start_cancellation());
    for _ in 0..32 {
        if api.stop_calls.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(tunnel.stops.load(Ordering::SeqCst), 1);
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_millis(20)).await;
    tokio::task::yield_now().await;
    let error = attempt.await.unwrap().unwrap_err();
    core.finish_start_attempt();

    assert!(matches!(error, CoreError::StartCancelled));
    assert_eq!(core.state().await.phase, Phase::Ready);
    assert_eq!(*tunnel.status.lock().unwrap(), TunnelStatus::Stopped);
    assert_eq!(
        events.lock().unwrap().as_slice(),
        &["local_stop", "panel_stop"]
    );
    assert_eq!(api.stop_operation_ids.lock().unwrap().len(), 1);
    let stored = store.load().unwrap().unwrap();
    assert!(stored.pending_start.is_none());
    assert!(stored.pending_compensation_stop.is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_post_local_start_replays_lost_compensation_id_after_reconstruction() {
    let api = Arc::new(MockApi::new(0));
    api.stop_apply_then_fail_once.store(true, Ordering::SeqCst);
    api.applied_stop_replays_as_released
        .store(true, Ordering::SeqCst);
    let store = Arc::new(MemoryStore::new(auth()));
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.block_start.store(true, Ordering::SeqCst);
    let core = Arc::new(
        ClientCore::new(
            api.clone(),
            store.clone(),
            tunnel.clone(),
            Arc::new(MemoryLogger::default()),
        )
        .with_retry_policy(RetryPolicy::new(Vec::new())),
    );
    let cancel_epoch = core.begin_start_attempt();
    let attempt = {
        let core = core.clone();
        tokio::spawn(async move {
            core.start_with_cancellation_epoch(options(), 1_700_000_000, cancel_epoch)
                .await
        })
    };
    while tunnel.starts.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }

    assert!(core.signal_start_cancellation());
    tunnel.block_start.store(false, Ordering::SeqCst);
    tunnel.start_release.notify_one();
    assert!(matches!(
        attempt.await.unwrap(),
        Err(CoreError::StartCancelled)
    ));
    core.finish_start_attempt();

    assert_eq!(*tunnel.status.lock().unwrap(), TunnelStatus::Stopped);
    let pending = store
        .load()
        .unwrap()
        .unwrap()
        .pending_compensation_stop
        .expect("lost response must preserve the durable compensation identity");
    assert_eq!(
        api.stop_operation_ids.lock().unwrap().as_slice(),
        &[pending.operation_id.clone()]
    );

    let reconstructed = ClientCore::new(
        api.clone(),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    )
    .with_retry_policy(RetryPolicy::new(Vec::new()));
    reconstructed.start(options(), 1_700_000_001).await.unwrap();

    assert_eq!(
        api.stop_operation_ids.lock().unwrap().as_slice(),
        &[pending.operation_id.clone(), pending.operation_id]
    );
    assert!(store
        .load()
        .unwrap()
        .unwrap()
        .pending_compensation_stop
        .is_none());
    assert_eq!(api.start_calls.load(Ordering::SeqCst), 2);
    assert_eq!(reconstructed.state().await.phase, Phase::Connected);
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_start_defers_panel_compensation_until_local_cleanup_retry_succeeds() {
    let api = Arc::new(MockApi::new(0));
    let store = Arc::new(MemoryStore::new(auth()));
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.block_start.store(true, Ordering::SeqCst);
    tunnel.fail_next_stops.store(1, Ordering::SeqCst);
    let core = Arc::new(ClientCore::new(
        api.clone(),
        store.clone(),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    ));
    let cancel_epoch = core.begin_start_attempt();
    let attempt = {
        let core = core.clone();
        tokio::spawn(async move {
            core.start_with_cancellation_epoch(options(), 1_700_000_000, cancel_epoch)
                .await
        })
    };
    while tunnel.starts.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }

    assert!(core.signal_start_cancellation());
    tunnel.block_start.store(false, Ordering::SeqCst);
    tunnel.start_release.notify_one();
    let error = attempt.await.unwrap().unwrap_err();
    core.finish_start_attempt();

    assert!(matches!(
        error,
        CoreError::Tunnel(code) if code == "test_stop_failed"
    ));
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 0);
    assert_eq!(core.state().await.phase, Phase::Stopping);
    assert_eq!(*tunnel.status.lock().unwrap(), TunnelStatus::Running);
    let pending = store
        .load()
        .unwrap()
        .unwrap()
        .pending_compensation_stop
        .expect("local cleanup failure must retain the durable compensation identity");

    core.stop().await.unwrap();

    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        api.stop_operation_ids.lock().unwrap().as_slice(),
        &[pending.operation_id]
    );
    let stored = store.load().unwrap().unwrap();
    assert!(stored.pending_start.is_none());
    assert!(stored.pending_compensation_stop.is_none());
}

#[cfg(not(target_os = "android"))]
#[tokio::test(flavor = "current_thread")]
async fn desktop_coordinator_does_not_double_compensate_an_internally_cancelled_start() {
    let api = Arc::new(MockApi::new(0));
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.block_start.store(true, Ordering::SeqCst);
    let core = Arc::new(ClientCore::new(
        api.clone(),
        Arc::new(MemoryStore::new(auth())),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    ));
    let mut coordinator = ConnectionIntentCoordinator::default();
    coordinator
        .start_or_resume(options(), 1_700_000_000)
        .unwrap();
    let generation = coordinator.generation();
    assert!(coordinator.begin_attempt(generation));
    let attempt = {
        let core = core.clone();
        tokio::spawn(async move {
            core.connection_intent_attempt(options(), 1_700_000_000)
                .await
        })
    };
    while tunnel.starts.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }

    assert!(coordinator.cancel_intent(generation));
    assert!(core.signal_start_cancellation());
    tunnel.block_start.store(false, Ordering::SeqCst);
    tunnel.start_release.notify_one();
    let result = attempt.await.unwrap();
    assert!(matches!(result, Err(CoreError::StartCancelled)));

    match result {
        Err(CoreError::StartCancelled) => {
            assert!(coordinator.complete_compensation(generation));
        }
        Ok(connection) => {
            assert_eq!(
                coordinator.mark_connected(generation, connection),
                RecoveryDecision::DiscardAndCompensate
            );
            core.compensate_stale_connection_intent_result()
                .await
                .unwrap();
            assert!(coordinator.complete_compensation(generation));
        }
        Err(error) => panic!("unexpected start result: {error}"),
    }

    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
    assert_eq!(tunnel.stops.load(Ordering::SeqCst), 1);
}

#[cfg(not(target_os = "android"))]
#[tokio::test(start_paused = true)]
async fn cancelled_panel_start_replays_lost_compensation_with_the_same_id_after_reconstruction() {
    let api = Arc::new(MockApi::new(0));
    api.stop_apply_then_fail_once.store(true, Ordering::SeqCst);
    api.applied_stop_replays_as_released
        .store(true, Ordering::SeqCst);
    let store = Arc::new(MemoryStore::new(auth()));
    let tunnel = Arc::new(MemoryTunnel::default());
    let core = Arc::new(
        ClientCore::new(
            api.clone(),
            store.clone(),
            tunnel.clone(),
            Arc::new(MemoryLogger::default()),
        )
        .with_retry_policy(RetryPolicy::new(Vec::new())),
    );
    let cancel_epoch = core.begin_start_attempt();
    let attempt = {
        let core = core.clone();
        tokio::spawn(async move {
            core.start_with_cancellation_epoch(options(), 1_700_000_000, cancel_epoch)
                .await
        })
    };
    while api.start_calls.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }

    assert!(core.signal_start_cancellation());
    tokio::time::advance(Duration::from_millis(20)).await;
    tokio::task::yield_now().await;
    assert!(matches!(
        attempt.await.unwrap(),
        Err(CoreError::StartCancelled)
    ));
    core.finish_start_attempt();

    assert_eq!(tunnel.starts.load(Ordering::SeqCst), 0);
    let pending = store
        .load()
        .unwrap()
        .unwrap()
        .pending_compensation_stop
        .expect("lost stop response must retain the pre-dispatch compensation identity");
    assert_eq!(
        api.stop_operation_ids.lock().unwrap().as_slice(),
        &[pending.operation_id.clone()]
    );
    assert_eq!(api.stop_failure_codes.lock().unwrap().as_slice(), &[None]);
    assert_eq!(api.bootstrap_connection.lock().unwrap().as_ref(), None);

    let reconstructed = Arc::new(
        ClientCore::new(
            api.clone(),
            store.clone(),
            Arc::new(MemoryTunnel::default()),
            Arc::new(MemoryLogger::default()),
        )
        .with_retry_policy(RetryPolicy::new(Vec::new())),
    );
    let bootstrap = reconstructed.bootstrap(1_700_000_001).await.unwrap();
    assert!(bootstrap.connection.is_none());
    let reconciliation = {
        let reconstructed = reconstructed.clone();
        tokio::spawn(async move { reconstructed.reconcile_pending_operation_for_retry().await })
    };
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(20)).await;
    tokio::task::yield_now().await;
    reconciliation.await.unwrap().unwrap();

    assert_eq!(
        api.stop_operation_ids.lock().unwrap().as_slice(),
        &[pending.operation_id.clone(), pending.operation_id]
    );
    let stored = store.load().unwrap().unwrap();
    assert!(stored.pending_compensation_stop.is_none());
    assert!(stored.pending_start.is_none());

    let next_start = {
        let reconstructed = reconstructed.clone();
        tokio::spawn(async move { reconstructed.start(options(), 1_700_000_002).await })
    };
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(20)).await;
    tokio::task::yield_now().await;
    next_start.await.unwrap().unwrap();

    assert_eq!(api.start_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "current_thread")]
async fn secret_store_failure_during_stop_never_blocks_the_local_tunnel_stop() {
    let api = Arc::new(MockApi::new(0));
    let store = Arc::new(ToggleLoadStore::new(auth()));
    let tunnel = Arc::new(MemoryTunnel::default());
    let core = ClientCore::new(
        api,
        store.clone(),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    );
    core.start(options(), 1_700_000_000).await.unwrap();
    store.fail_load.store(true, Ordering::SeqCst);

    let error = core.stop().await.unwrap_err();

    assert!(matches!(error, CoreError::Storage));
    assert_eq!(tunnel.stops.load(Ordering::SeqCst), 1);
    assert_eq!(*tunnel.status.lock().unwrap(), TunnelStatus::Stopped);
}

#[tokio::test]
async fn connection_intent_metrics_context_survives_a_failed_local_recovery() {
    let api = Arc::new(MockApi::new(0));
    let tunnel = Arc::new(MemoryTunnel::default());
    let core = ClientCore::new(
        api,
        Arc::new(MemoryStore::new(auth())),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    );
    let connection = core.start(options(), 1_700_000_000).await.unwrap();
    tunnel.fail_next_starts.store(2, Ordering::SeqCst);

    assert!(core
        .recover_stalled_data_plane(
            &connection.lease_id,
            StalledDataPlaneRecovery::RestartLocalTunnel,
        )
        .await
        .is_err());
    assert_eq!(core.state().await.phase, Phase::Stopping);
    assert_eq!(
        core.connection_metrics_context()
            .await
            .map(|context| context.session_id),
        Some(connection.lease_id)
    );
    core.stop().await.unwrap();
    assert!(core.connection_metrics_context().await.is_none());
}

#[tokio::test]
async fn connection_intent_missing_local_configuration_does_not_arm_recovery_metrics() {
    let store = Arc::new(MemoryStore::new(auth()));
    let core = ClientCore::new(
        Arc::new(MockApi::new(0)),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    );
    let connection = core.start(options(), 1_700_000_000).await.unwrap();
    let mut stored = store.load().unwrap().unwrap();
    stored.saved_connection = None;
    stored.pinned_connection = None;
    store.save(&stored).unwrap();

    assert_eq!(
        core.recover_stalled_data_plane(
            &connection.lease_id,
            StalledDataPlaneRecovery::RestartLocalTunnel,
        )
        .await
        .unwrap(),
        StalledDataPlaneRecoveryOutcome::Skipped
    );
    assert!(core.active_recovery_options().await.is_none());
}

#[cfg(not(target_os = "android"))]
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn connection_intent_cancel_during_api_local_start_and_handshake_compensates_late_success() {
    for stage in ["api", "local_start", "handshake"] {
        let api = Arc::new(MockApi::new(0));
        let tunnel = Arc::new(MemoryTunnel::default());
        match stage {
            "local_start" => tunnel.start_delay_millis.store(100, Ordering::SeqCst),
            "handshake" => {
                api.awg3_start.store(true, Ordering::SeqCst);
                tunnel.metrics_supported.store(true, Ordering::SeqCst);
                tunnel.handshake_before_rebind.store(true, Ordering::SeqCst);
                tunnel.metrics_delay_millis.store(100, Ordering::SeqCst);
            }
            _ => {}
        }
        let store = Arc::new(MemoryStore::new(auth()));
        let core = Arc::new(ClientCore::new(
            api.clone(),
            store.clone(),
            tunnel.clone(),
            Arc::new(MemoryLogger::default()),
        ));
        let mut coordinator = ConnectionIntentCoordinator::default();
        coordinator
            .start_or_resume(options(), 1_700_000_000)
            .unwrap();
        let generation = coordinator.generation();
        assert!(coordinator.begin_attempt(generation));

        let attempt_core = core.clone();
        let attempt = tokio::spawn(async move {
            attempt_core
                .connection_intent_attempt(options(), 1_700_000_000)
                .await
        });
        loop {
            let reached_stage = match stage {
                "api" => api.start_calls.load(Ordering::SeqCst) > 0,
                "local_start" => tunnel.starts.load(Ordering::SeqCst) > 0,
                "handshake" => tunnel.metrics_calls.load(Ordering::SeqCst) > 0,
                _ => unreachable!(),
            };
            if reached_stage {
                break;
            }
            tokio::time::advance(Duration::from_millis(1)).await;
            tokio::task::yield_now().await;
        }
        assert!(coordinator.cancel_intent(generation));
        let late_connection = attempt.await.unwrap().unwrap();
        assert_eq!(
            coordinator.accept_result(generation),
            RecoveryDecision::DiscardAndCompensate,
            "stage={stage} lease={}",
            late_connection.lease_id,
        );
        core.compensate_stale_connection_intent_result()
            .await
            .unwrap();
        assert!(coordinator.complete_compensation(generation));
        assert_eq!(core.state().await.phase, Phase::Ready);
        assert_eq!(
            core.state().await.connection.unwrap().status,
            LeaseStatus::Warm
        );
        assert_ne!(*tunnel.status.lock().unwrap(), TunnelStatus::Running);
        assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
        assert_eq!(api.stop_failure_codes.lock().unwrap().as_slice(), &[None]);
        assert!(store
            .load()
            .unwrap()
            .unwrap()
            .pending_compensation_stop
            .is_none());
    }
}

#[cfg(not(target_os = "android"))]
#[tokio::test]
async fn stale_success_compensation_reuses_durable_stop_id_after_lost_response() {
    let api = Arc::new(MockApi::new(0));
    let store = Arc::new(MemoryStore::new(auth()));
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    )
    .with_retry_policy(RetryPolicy::new(Vec::new()));
    let started = core.start(options(), 1_700_000_000).await.unwrap();
    api.stop_apply_then_fail_once.store(true, Ordering::SeqCst);

    assert!(core
        .compensate_stale_connection_intent_result()
        .await
        .is_err());
    let pending = store
        .load()
        .unwrap()
        .unwrap()
        .pending_compensation_stop
        .expect("compensation journal must precede the first stop");
    assert_eq!(pending.lease_id, started.lease_id);
    assert!(pending.accept_warm);

    let reconstructed = ClientCore::new(
        api.clone(),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    );
    let bootstrap = reconstructed.bootstrap(1_700_000_001).await.unwrap();
    assert!(bootstrap.connection.is_none());
    reconstructed
        .reconcile_pending_operation_for_retry()
        .await
        .unwrap();

    {
        let operation_ids = api.stop_operation_ids.lock().unwrap();
        assert_eq!(operation_ids.len(), 2);
        assert!(operation_ids
            .iter()
            .all(|operation_id| operation_id == &operation_ids[0]));
    }
    assert!(api
        .stop_failure_codes
        .lock()
        .unwrap()
        .iter()
        .all(Option::is_none));
    assert!(store
        .load()
        .unwrap()
        .unwrap()
        .pending_compensation_stop
        .is_none());
    assert_eq!(
        reconstructed.state().await.connection.unwrap().status,
        LeaseStatus::Warm
    );
}

#[cfg(not(target_os = "android"))]
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn connection_intent_dynamic_stall_stops_terminal_lease_before_new_attempt() {
    let api = Arc::new(MockApi::new(0));
    api.awg3_start.store(true, Ordering::SeqCst);
    let store = Arc::new(MemoryStore::new(auth()));
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.metrics_supported.store(true, Ordering::SeqCst);
    tunnel.handshake_before_rebind.store(true, Ordering::SeqCst);
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        tunnel,
        Arc::new(MemoryLogger::default()),
    );
    let previous = core.start(options(), 1_700_000_000).await.unwrap();

    let replacement = core
        .replace_stalled_connection(options(), 1_700_000_100)
        .await
        .unwrap();

    assert_ne!(replacement.lease_id, previous.lease_id);
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
    assert_eq!(api.start_calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        api.stop_failure_codes.lock().unwrap().as_slice(),
        &[Some("tunnel_data_plane_stalled".to_string())]
    );
    assert_eq!(
        store
            .load()
            .unwrap()
            .unwrap()
            .saved_connection
            .unwrap()
            .lease_id,
        replacement.lease_id
    );
}

#[cfg(not(target_os = "android"))]
#[tokio::test(flavor = "current_thread")]
async fn cancellation_captured_before_stall_probes_blocks_replacement_side_effects() {
    let api = Arc::new(MockApi::new(0));
    api.awg3_start.store(true, Ordering::SeqCst);
    let core = ClientCore::new(
        api.clone(),
        Arc::new(MemoryStore::new(auth())),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    );
    core.start(options(), 1_700_000_000).await.unwrap();
    let cancel_epoch = core.begin_start_attempt();
    assert!(core.signal_start_cancellation());

    let error = core
        .replace_stalled_connection_with_cancellation_epoch(options(), 1_700_000_100, cancel_epoch)
        .await
        .unwrap_err();
    core.finish_start_attempt();

    assert!(matches!(error, CoreError::StartCancelled));
    assert_eq!(api.start_calls.load(Ordering::SeqCst), 1);
    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 0);
}

#[cfg(not(target_os = "android"))]
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn connection_intent_dynamic_warm_stall_is_marked_failed_before_replacement() {
    let api = Arc::new(MockApi::new(0));
    api.awg3_start.store(true, Ordering::SeqCst);
    api.warm_start.store(true, Ordering::SeqCst);
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.metrics_supported.store(true, Ordering::SeqCst);
    tunnel.handshake_before_rebind.store(true, Ordering::SeqCst);
    let core = ClientCore::new(
        api.clone(),
        Arc::new(MemoryStore::new(auth())),
        tunnel,
        Arc::new(MemoryLogger::default()),
    );
    core.start(options(), 1_700_000_000).await.unwrap();

    core.replace_stalled_connection(options(), 1_700_000_100)
        .await
        .unwrap();

    assert_eq!(api.stop_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        api.stop_failure_codes.lock().unwrap().as_slice(),
        &[Some("tunnel_data_plane_stalled".to_string())]
    );
}

#[cfg(not(target_os = "android"))]
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn connection_intent_stalled_stop_retry_reuses_its_operation_id() {
    let api = Arc::new(MockApi::new(0));
    api.awg3_start.store(true, Ordering::SeqCst);
    *api.stop_error.lock().unwrap() = Some(CoreApiError::Rejected {
        code: "connection_stall_recycle_rate_limited".to_string(),
        message: "Retry later".to_string(),
        retry_after_seconds: Some(120),
    });
    let tunnel = Arc::new(MemoryTunnel::default());
    tunnel.metrics_supported.store(true, Ordering::SeqCst);
    tunnel.handshake_before_rebind.store(true, Ordering::SeqCst);
    let core = ClientCore::new(
        api.clone(),
        Arc::new(MemoryStore::new(auth())),
        tunnel,
        Arc::new(MemoryLogger::default()),
    );
    core.start(options(), 1_700_000_000).await.unwrap();

    assert!(core
        .replace_stalled_connection(options(), 1_700_000_100)
        .await
        .is_err());
    assert_eq!(api.start_calls.load(Ordering::SeqCst), 1);
    let first_stop_operation = api.stop_operation_ids.lock().unwrap()[0].clone();

    *api.stop_error.lock().unwrap() = None;
    core.replace_stalled_connection(options(), 1_700_000_400)
        .await
        .unwrap();
    assert_eq!(api.start_calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        api.stop_operation_ids.lock().unwrap().as_slice(),
        [first_stop_operation.as_str(), first_stop_operation.as_str()]
    );
}

#[cfg(not(target_os = "android"))]
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn stalled_stop_identity_is_durable_before_the_first_request() {
    const LEASE_ID: &str = "11111111-1111-4111-8111-111111111111";
    const FINGERPRINT: &str = "9808141ba59407c91cb5e3b96c4b2051387fe876297dcbacde665c5b656d179f";
    let api = Arc::new(MockApi::new(0));
    api.awg3_start.store(true, Ordering::SeqCst);
    *api.start_lease_override.lock().unwrap() = Some(LEASE_ID.to_string());
    *api.stop_error.lock().unwrap() = Some(CoreApiError::Rejected {
        code: "connection_stall_not_recyclable".to_string(),
        message: "Cannot recycle".to_string(),
        retry_after_seconds: None,
    });
    let store = Arc::new(MemoryStore::new(auth()));
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    );
    core.start(options(), 1_700_000_000).await.unwrap();

    assert!(core
        .replace_stalled_connection(options(), 1_700_000_100)
        .await
        .is_err());

    let stop_operation_id = api.stop_operation_ids.lock().unwrap()[0].clone();
    let stored = serde_json::to_value(store.load().unwrap().unwrap()).unwrap();
    assert_eq!(
        stored["pending_stalled_stop"]["operation_id"],
        stop_operation_id
    );
    assert_eq!(stored["pending_stalled_stop"]["lease_id"], LEASE_ID);
    assert_eq!(stored["pending_stalled_stop"]["contract_version"], 1);
    assert_eq!(
        stored["pending_stalled_stop"]["request_fingerprint"],
        FINGERPRINT
    );
}

#[cfg(not(target_os = "android"))]
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn explicit_stop_finishes_the_durable_stalled_stop_with_the_same_operation_id() {
    let api = Arc::new(MockApi::new(0));
    api.awg3_start.store(true, Ordering::SeqCst);
    *api.stop_error.lock().unwrap() = Some(CoreApiError::Rejected {
        code: "connection_stall_verification_unavailable".to_string(),
        message: "Retry later".to_string(),
        retry_after_seconds: Some(2),
    });
    let store = Arc::new(MemoryStore::new(auth()));
    let core = ClientCore::new(
        api.clone(),
        store.clone(),
        Arc::new(MemoryTunnel::default()),
        Arc::new(MemoryLogger::default()),
    );
    core.start(options(), 1_700_000_000).await.unwrap();
    assert!(core
        .replace_stalled_connection(options(), 1_700_000_100)
        .await
        .is_err());
    let stalled_operation_id = api.stop_operation_ids.lock().unwrap()[0].clone();

    *api.stop_error.lock().unwrap() = None;
    core.stop().await.unwrap();

    assert_eq!(
        api.stop_operation_ids.lock().unwrap().as_slice(),
        [stalled_operation_id.as_str(), stalled_operation_id.as_str()]
    );
    assert_eq!(
        api.stop_failure_codes.lock().unwrap().as_slice(),
        [
            Some("tunnel_data_plane_stalled".to_string()),
            Some("tunnel_data_plane_stalled".to_string())
        ]
    );
    assert!(store
        .load()
        .unwrap()
        .unwrap()
        .pending_stalled_stop
        .is_none());
}

#[cfg(not(target_os = "android"))]
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn stalled_stop_not_found_reconciles_and_exact_replays_after_core_reconstruction() {
    const LEASE_ID: &str = "11111111-1111-4111-8111-111111111111";
    const FINGERPRINT: &str = "9808141ba59407c91cb5e3b96c4b2051387fe876297dcbacde665c5b656d179f";
    let api = Arc::new(MockApi::new(0));
    api.awg3_start.store(true, Ordering::SeqCst);
    *api.start_lease_override.lock().unwrap() = Some(LEASE_ID.to_string());
    *api.stop_error.lock().unwrap() = Some(CoreApiError::Rejected {
        code: "connection_stall_not_recyclable".to_string(),
        message: "Cannot recycle".to_string(),
        retry_after_seconds: None,
    });
    let store = Arc::new(MemoryStore::new(auth()));
    let tunnel = Arc::new(MemoryTunnel::default());
    let first_core = ClientCore::new(
        api.clone(),
        store.clone(),
        tunnel.clone(),
        Arc::new(MemoryLogger::default()),
    );
    let first_connection = first_core.start(options(), 1_700_000_000).await.unwrap();
    assert!(first_core
        .replace_stalled_connection(options(), 1_700_000_100)
        .await
        .is_err());
    let stop_operation_id = api.stop_operation_ids.lock().unwrap()[0].clone();

    *api.bootstrap_connection.lock().unwrap() = Some(first_connection);
    api.reconcile_responses
        .lock()
        .unwrap()
        .push_back(OperationReconcileResponse {
            api_version: ApiVersion::V1,
            request_id: "stalled-stop-not-found".to_string(),
            state: OperationState::NotFound,
            cancel_requested: false,
            lease_id: None,
            lease_status: None,
            retry_count: 0,
            next_attempt_at: None,
        });
    let reconstructed = ClientCore::new(
        api.clone(),
        store,
        tunnel,
        Arc::new(MemoryLogger::default()),
    );
    reconstructed.bootstrap(1_700_000_101).await.unwrap();

    reconstructed
        .reconcile_pending_operation_for_retry()
        .await
        .unwrap();

    {
        let reconciliations = api.reconcile_requests.lock().unwrap();
        assert_eq!(reconciliations.len(), 1);
        assert_eq!(reconciliations[0].operation_id, stop_operation_id);
        assert_eq!(
            reconciliations[0].kind,
            nelomai_contracts::OperationKind::StalledStop
        );
        assert_eq!(reconciliations[0].contract_version, 1);
        assert_eq!(reconciliations[0].request_fingerprint, FINGERPRINT);
        assert!(!reconciliations[0].cancel_if_absent);
    }

    *api.stop_error.lock().unwrap() = None;
    reconstructed
        .replace_stalled_connection(options(), 1_700_000_102)
        .await
        .unwrap();
    assert_eq!(
        api.stop_operation_ids.lock().unwrap().as_slice(),
        [stop_operation_id.as_str(), stop_operation_id.as_str()]
    );
}

#[cfg(not(target_os = "android"))]
#[tokio::test(flavor = "current_thread")]
async fn stalled_stop_reconcile_polls_nonterminal_completes_only_terminal_lease_and_blocks_active()
{
    const OPERATION_ID: &str = "22222222-2222-4222-8222-222222222222";
    const LEASE_ID: &str = "11111111-1111-4111-8111-111111111111";
    const FINGERPRINT: &str = "9808141ba59407c91cb5e3b96c4b2051387fe876297dcbacde665c5b656d179f";
    for (operation_state, lease_status, expected) in [
        (OperationState::Pending, Some(LeaseStatus::Issued), "poll"),
        (
            OperationState::Applying,
            Some(LeaseStatus::Connected),
            "poll",
        ),
        (
            OperationState::Compensating,
            Some(LeaseStatus::Connected),
            "poll",
        ),
        (OperationState::Applied, Some(LeaseStatus::Issued), "block"),
        (
            OperationState::Applied,
            Some(LeaseStatus::Failed),
            "complete",
        ),
        (
            OperationState::Terminal,
            Some(LeaseStatus::Connected),
            "block",
        ),
        (
            OperationState::Terminal,
            Some(LeaseStatus::Released),
            "complete",
        ),
        (OperationState::Cancelled, None, "block"),
        (
            OperationState::Cancelled,
            Some(LeaseStatus::Failed),
            "complete",
        ),
    ] {
        let api = Arc::new(MockApi::new(0));
        *api.bootstrap_connection.lock().unwrap() = Some(connection(LEASE_ID));
        api.reconcile_responses
            .lock()
            .unwrap()
            .push_back(OperationReconcileResponse {
                api_version: ApiVersion::V1,
                request_id: "stalled-stop-reconcile".to_string(),
                state: operation_state,
                cancel_requested: false,
                lease_id: lease_status.map(|_| LEASE_ID.to_string()),
                lease_status,
                retry_count: 2,
                next_attempt_at: None,
            });
        let mut stored = auth();
        stored.pending_stalled_stop = Some(StoredPendingStalledStop {
            operation_id: OPERATION_ID.to_string(),
            lease_id: LEASE_ID.to_string(),
            contract_version: 1,
            request_fingerprint: FINGERPRINT.to_string(),
        });
        let store = Arc::new(MemoryStore::new(stored));
        let core = ClientCore::new(
            api.clone(),
            store.clone(),
            Arc::new(MemoryTunnel::default()),
            Arc::new(MemoryLogger::default()),
        );
        core.bootstrap(1_700_000_000).await.unwrap();

        let result = core.reconcile_pending_operation_for_retry().await;

        match expected {
            "poll" => assert!(matches!(
                result,
                Err(CoreError::Api(CoreApiError::Rejected {
                    ref code,
                    retry_after_seconds: Some(5),
                    ..
                })) if code == "operation_in_progress"
            )),
            "block" => assert!(matches!(
                result,
                Err(CoreError::Api(CoreApiError::Rejected { ref code, .. }))
                    if code == "connection_stall_not_recyclable"
            )),
            "complete" => {
                result.unwrap();
                assert_eq!(
                    core.state().await.connection.unwrap().status,
                    lease_status.unwrap()
                );
            }
            _ => unreachable!(),
        }
        assert_eq!(
            store
                .load()
                .unwrap()
                .unwrap()
                .pending_stalled_stop
                .is_none(),
            expected == "complete",
            "state={operation_state:?} status={lease_status:?}"
        );
        let reconciliations = api.reconcile_requests.lock().unwrap();
        assert_eq!(reconciliations.len(), 1);
        assert_eq!(reconciliations[0].operation_id, OPERATION_ID);
        assert_eq!(
            reconciliations[0].kind,
            nelomai_contracts::OperationKind::StalledStop
        );
        assert_eq!(reconciliations[0].contract_version, 1);
        assert_eq!(reconciliations[0].request_fingerprint, FINGERPRINT);
        assert!(!reconciliations[0].cancel_if_absent);
    }
}
