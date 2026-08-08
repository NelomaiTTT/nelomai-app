use async_trait::async_trait;
use nelomai_client_api::{ClientApi, ClientApiError, TokenResponse};
use nelomai_client_storage::{
    MemorySplitTunnelStore, SecretStore, SplitTunnelStore, StoredCompatibility, StoredConnection,
    StoredConnectionKind, StoredPendingStart,
};
use nelomai_client_tunnel::{
    QuickConnection, QuickReconnect, TunnelConfiguration, TunnelController, TunnelError,
    TunnelOptions, TunnelStartRequest, TunnelStatus,
};
use nelomai_contracts::{
    AccessState, Bootstrap, Connection, ConnectionOperationRequest, ConnectionOperationResponse,
    ConnectionStartRequest, ConnectionStartResponse, Layer, LeaseStatus, ProbeResult, RouteMode,
    SplitTunnelAddressRuleScope, SplitTunnelAddressRuleUpdate, SplitTunnelApplyResult,
    SplitTunnelPolicy, SplitTunnelRevision, SplitTunnelSelectedPackage, SplitTunnelSettingsUpdate,
    TicConnectionMode,
};
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use thiserror::Error;
use tokio::sync::Mutex;
use uuid::Uuid;

mod split_tunnel;

pub use split_tunnel::{
    split_tunnel_active, validate_split_tunnel_policy, EffectiveSplitTunnelPolicy,
    PhysicalNetworkPollOutcome, SplitTunnelContext, SplitTunnelPolicyError, SplitTunnelSyncOutcome,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    SignedOut,
    Authenticating,
    NeedsPeerBinding,
    AccessExpired,
    Ready,
    Measuring,
    Connecting,
    Connected,
    Stopping,
    UpdateRequired,
    ServerUnavailable,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreState {
    pub phase: Phase,
    pub connection: Option<Connection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionMetricsContext {
    pub session_id: String,
    pub probe_url: Option<String>,
}

impl Default for CoreState {
    fn default() -> Self {
        Self {
            phase: Phase::SignedOut,
            connection: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SplitTunnelWarningKind {
    Sync,
    Dns,
    Operation,
    Runtime,
    Storage,
}

#[derive(Debug, Default)]
struct SplitTunnelWarnings {
    sync: Option<String>,
    dns: Option<String>,
    operation: Option<String>,
    runtime: Option<String>,
    storage: Option<String>,
}

impl SplitTunnelWarnings {
    fn current(&self) -> Option<String> {
        self.runtime
            .as_ref()
            .or(self.operation.as_ref())
            .or(self.storage.as_ref())
            .or(self.dns.as_ref())
            .or(self.sync.as_ref())
            .cloned()
    }

    fn set(&mut self, kind: SplitTunnelWarningKind, code: String) -> bool {
        let slot = self.slot(kind);
        if slot.as_deref() == Some(code.as_str()) {
            return false;
        }
        *slot = Some(code);
        true
    }

    fn clear(&mut self, kind: SplitTunnelWarningKind) {
        *self.slot(kind) = None;
    }

    fn clear_all(&mut self) {
        *self = Self::default();
    }

    fn slot(&mut self, kind: SplitTunnelWarningKind) -> &mut Option<String> {
        match kind {
            SplitTunnelWarningKind::Sync => &mut self.sync,
            SplitTunnelWarningKind::Dns => &mut self.dns,
            SplitTunnelWarningKind::Operation => &mut self.operation,
            SplitTunnelWarningKind::Runtime => &mut self.runtime,
            SplitTunnelWarningKind::Storage => &mut self.storage,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreEvent {
    AuthStarted,
    Authenticated,
    PeerBound,
    AccessExpired,
    UpdateRequired,
    MeasurementStarted,
    MeasurementFinished,
    ConnectionStarted,
    ConnectionEstablished,
    StopStarted,
    Stopped,
    ServerUnavailable,
    Failed,
    SignedOut,
}

pub fn reduce(mut state: CoreState, event: CoreEvent) -> CoreState {
    state.phase = match event {
        CoreEvent::AuthStarted => Phase::Authenticating,
        CoreEvent::Authenticated => Phase::NeedsPeerBinding,
        CoreEvent::PeerBound | CoreEvent::MeasurementFinished | CoreEvent::Stopped => Phase::Ready,
        CoreEvent::AccessExpired => Phase::AccessExpired,
        CoreEvent::UpdateRequired => Phase::UpdateRequired,
        CoreEvent::MeasurementStarted => Phase::Measuring,
        CoreEvent::ConnectionStarted => Phase::Connecting,
        CoreEvent::ConnectionEstablished => Phase::Connected,
        CoreEvent::StopStarted => Phase::Stopping,
        CoreEvent::ServerUnavailable => Phase::ServerUnavailable,
        CoreEvent::Failed => Phase::Error,
        CoreEvent::SignedOut => Phase::SignedOut,
    };
    state
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryFacts {
    pub signed_in: bool,
    pub peer_bound: bool,
    pub access_active: bool,
    pub update_required: bool,
    pub tunnel_status: TunnelStatus,
}

pub fn recover_phase(_previous: Phase, facts: RecoveryFacts) -> Phase {
    if !facts.signed_in {
        return Phase::SignedOut;
    }
    if facts.update_required {
        return Phase::UpdateRequired;
    }
    if !facts.access_active {
        return Phase::AccessExpired;
    }
    if !facts.peer_bound {
        return Phase::NeedsPeerBinding;
    }
    if matches!(
        facts.tunnel_status,
        TunnelStatus::Running | TunnelStatus::Starting
    ) {
        return Phase::Connected;
    }
    Phase::Ready
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeScheduler {
    refresh_seconds: i64,
    last_probe_unix: Option<i64>,
    bootstrapped: bool,
    foreground: bool,
    connected: bool,
}

impl ProbeScheduler {
    pub fn new(refresh_seconds: i64) -> Self {
        Self {
            refresh_seconds,
            last_probe_unix: None,
            bootstrapped: false,
            foreground: true,
            connected: false,
        }
    }

    pub fn set_bootstrapped(&mut self, value: bool) {
        self.bootstrapped = value;
    }

    pub fn set_foreground(&mut self, value: bool) {
        self.foreground = value;
    }

    pub fn set_connected(&mut self, value: bool) {
        self.connected = value;
    }

    pub fn mark_probed(&mut self, now_unix: i64) {
        self.last_probe_unix = Some(now_unix);
    }

    pub fn should_probe(&self, now_unix: i64) -> bool {
        self.bootstrapped
            && self.foreground
            && !self.connected
            && self
                .last_probe_unix
                .is_none_or(|last| now_unix.saturating_sub(last) >= self.refresh_seconds)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryPolicy {
    delays_millis: Vec<u64>,
}

impl RetryPolicy {
    pub fn new(delays_millis: Vec<u64>) -> Self {
        Self {
            delays_millis: delays_millis.into_iter().take(6).collect(),
        }
    }

    pub fn delays_millis(&self) -> Vec<u64> {
        self.delays_millis.clone()
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            delays_millis: vec![250, 500, 1_000],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreLogEvent {
    pub kind: &'static str,
    pub operation_id: Option<String>,
    pub request_id: Option<String>,
    pub code: Option<String>,
}

pub trait CoreLogger: Send + Sync {
    fn record(&self, event: CoreLogEvent);

    fn record_timed(&self, event: CoreLogEvent, _duration_ms: u64) {
        self.record(event);
    }
}

pub struct NoopLogger;

impl CoreLogger for NoopLogger {
    fn record(&self, _event: CoreLogEvent) {}
}

fn elapsed_millis(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u64::MAX as u128) as u64
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConnectOptions {
    pub layer: Layer,
    pub tic_connection_mode: TicConnectionMode,
    pub route_mode: RouteMode,
    pub probes: Vec<ProbeResult>,
    pub allow_alternate: bool,
}

impl ConnectOptions {
    pub fn android_default() -> Self {
        Self {
            layer: Layer::Tic,
            tic_connection_mode: TicConnectionMode::Personal,
            route_mode: RouteMode::ViaTak,
            probes: Vec::new(),
            allow_alternate: true,
        }
    }

    pub fn windows_default() -> Self {
        Self::desktop_default()
    }

    pub fn unix_desktop_default() -> Self {
        Self::desktop_default()
    }

    fn desktop_default() -> Self {
        Self {
            layer: Layer::Stray,
            tic_connection_mode: TicConnectionMode::Dynamic,
            route_mode: RouteMode::Standalone,
            probes: Vec::new(),
            allow_alternate: true,
        }
    }
}

#[cfg(test)]
mod platform_default_tests {
    use super::*;

    #[test]
    fn android_defaults_to_personal_tic_via_tak() {
        let options = ConnectOptions::android_default();

        assert_eq!(options.layer, Layer::Tic);
        assert_eq!(options.tic_connection_mode, TicConnectionMode::Personal);
        assert_eq!(options.route_mode, RouteMode::ViaTak);
        assert!(options.probes.is_empty());
        assert!(options.allow_alternate);
    }

    #[test]
    fn windows_defaults_to_dynamic_stray() {
        let options = ConnectOptions::windows_default();

        assert_eq!(options.layer, Layer::Stray);
        assert_eq!(options.tic_connection_mode, TicConnectionMode::Dynamic);
        assert_eq!(options.route_mode, RouteMode::Standalone);
        assert!(options.probes.is_empty());
        assert!(options.allow_alternate);
    }

    #[test]
    fn unix_desktop_defaults_to_dynamic_stray() {
        let options = ConnectOptions::unix_desktop_default();

        assert_eq!(options.layer, Layer::Stray);
        assert_eq!(options.tic_connection_mode, TicConnectionMode::Dynamic);
        assert_eq!(options.route_mode, RouteMode::Standalone);
        assert!(options.probes.is_empty());
        assert!(options.allow_alternate);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CoreApiError {
    #[error("авторизация истекла")]
    Unauthorized,
    #[error("срок доступа истёк")]
    AccessExpired,
    #[error("временная ошибка сети")]
    Retryable,
    #[error("панель отклонила запрос: {code}: {message}")]
    Rejected { code: String, message: String },
}

impl From<ClientApiError> for CoreApiError {
    fn from(error: ClientApiError) -> Self {
        match error {
            ClientApiError::Transport(_) => Self::Retryable,
            ClientApiError::Api { status, .. } if status.as_u16() == 401 => Self::Unauthorized,
            ClientApiError::Api { code, .. } if code == "access_expired" => Self::AccessExpired,
            ClientApiError::Api { code, message, .. } if code == "configuration_fetch_failed" => {
                Self::Rejected { code, message }
            }
            ClientApiError::Api { status, .. } if status.is_server_error() => Self::Retryable,
            ClientApiError::Api { code, message, .. } => Self::Rejected { code, message },
            ClientApiError::InvalidErrorResponse { status } if status.is_server_error() => {
                Self::Retryable
            }
            ClientApiError::InvalidPayload { code }
            | ClientApiError::PayloadTooLarge { code, .. } => Self::Rejected {
                code: code.to_string(),
                message: "Панель вернула некорректные данные split-tunnel.".to_string(),
            },
            ClientApiError::InvalidBaseUrl(_)
            | ClientApiError::InvalidAppVersion(_)
            | ClientApiError::InvalidErrorResponse { .. } => Self::Rejected {
                code: "invalid_client_api_response".to_string(),
                message: "Панель вернула некорректный ответ.".to_string(),
            },
        }
    }
}

#[async_trait]
pub trait CoreApi: Send + Sync {
    async fn refresh(&self, refresh_token: &str) -> Result<TokenResponse, CoreApiError>;
    async fn bootstrap(&self, access_token: &str) -> Result<Bootstrap, CoreApiError>;
    async fn start_connection(
        &self,
        access_token: &str,
        request: &ConnectionStartRequest,
    ) -> Result<ConnectionStartResponse, CoreApiError>;
    async fn stop_connection(
        &self,
        access_token: &str,
        request: &ConnectionOperationRequest,
    ) -> Result<ConnectionOperationResponse, CoreApiError>;
    async fn pin_stray(
        &self,
        access_token: &str,
        request: &ConnectionOperationRequest,
    ) -> Result<ConnectionOperationResponse, CoreApiError>;
    async fn unpin_stray(
        &self,
        access_token: &str,
        request: &ConnectionOperationRequest,
    ) -> Result<ConnectionOperationResponse, CoreApiError>;
    async fn split_tunnel_revision(
        &self,
        _access_token: &str,
    ) -> Result<SplitTunnelRevision, CoreApiError> {
        Err(CoreApiError::Retryable)
    }
    async fn split_tunnel_policy(
        &self,
        _access_token: &str,
    ) -> Result<SplitTunnelPolicy, CoreApiError> {
        Err(CoreApiError::Retryable)
    }
    async fn update_split_tunnel_settings(
        &self,
        _access_token: &str,
        _request: &SplitTunnelSettingsUpdate,
    ) -> Result<SplitTunnelPolicy, CoreApiError> {
        Err(CoreApiError::Retryable)
    }
    async fn add_split_tunnel_address_rule(
        &self,
        _access_token: &str,
        _request: &SplitTunnelAddressRuleUpdate,
    ) -> Result<SplitTunnelPolicy, CoreApiError> {
        Err(CoreApiError::Retryable)
    }
    async fn remove_split_tunnel_address_rule(
        &self,
        _access_token: &str,
        _rule_id: i64,
        _scope: SplitTunnelAddressRuleScope,
    ) -> Result<SplitTunnelPolicy, CoreApiError> {
        Err(CoreApiError::Retryable)
    }
    async fn report_split_tunnel_apply_result(
        &self,
        _access_token: &str,
        _request: &SplitTunnelApplyResult,
    ) -> Result<(), CoreApiError> {
        Err(CoreApiError::Retryable)
    }
}

#[async_trait]
impl CoreApi for ClientApi {
    async fn refresh(&self, refresh_token: &str) -> Result<TokenResponse, CoreApiError> {
        ClientApi::refresh(self, refresh_token.to_string())
            .await
            .map_err(Into::into)
    }

    async fn bootstrap(&self, access_token: &str) -> Result<Bootstrap, CoreApiError> {
        ClientApi::bootstrap(self, access_token)
            .await
            .map_err(Into::into)
    }

    async fn start_connection(
        &self,
        access_token: &str,
        request: &ConnectionStartRequest,
    ) -> Result<ConnectionStartResponse, CoreApiError> {
        ClientApi::start_connection(self, access_token, request)
            .await
            .map_err(Into::into)
    }

    async fn stop_connection(
        &self,
        access_token: &str,
        request: &ConnectionOperationRequest,
    ) -> Result<ConnectionOperationResponse, CoreApiError> {
        ClientApi::stop_connection(self, access_token, request)
            .await
            .map_err(Into::into)
    }

    async fn pin_stray(
        &self,
        access_token: &str,
        request: &ConnectionOperationRequest,
    ) -> Result<ConnectionOperationResponse, CoreApiError> {
        ClientApi::pin_stray(self, access_token, request)
            .await
            .map_err(Into::into)
    }

    async fn unpin_stray(
        &self,
        access_token: &str,
        request: &ConnectionOperationRequest,
    ) -> Result<ConnectionOperationResponse, CoreApiError> {
        ClientApi::unpin_stray(self, access_token, request)
            .await
            .map_err(Into::into)
    }

    async fn split_tunnel_revision(
        &self,
        access_token: &str,
    ) -> Result<SplitTunnelRevision, CoreApiError> {
        ClientApi::split_tunnel_revision(self, access_token)
            .await
            .map_err(Into::into)
    }

    async fn split_tunnel_policy(
        &self,
        access_token: &str,
    ) -> Result<SplitTunnelPolicy, CoreApiError> {
        ClientApi::split_tunnel_policy(self, access_token)
            .await
            .map_err(Into::into)
    }

    async fn update_split_tunnel_settings(
        &self,
        access_token: &str,
        request: &SplitTunnelSettingsUpdate,
    ) -> Result<SplitTunnelPolicy, CoreApiError> {
        ClientApi::update_split_tunnel_settings(self, access_token, request)
            .await
            .map_err(Into::into)
    }

    async fn add_split_tunnel_address_rule(
        &self,
        access_token: &str,
        request: &SplitTunnelAddressRuleUpdate,
    ) -> Result<SplitTunnelPolicy, CoreApiError> {
        ClientApi::add_split_tunnel_address_rule(self, access_token, request)
            .await
            .map_err(Into::into)
    }

    async fn remove_split_tunnel_address_rule(
        &self,
        access_token: &str,
        rule_id: i64,
        scope: SplitTunnelAddressRuleScope,
    ) -> Result<SplitTunnelPolicy, CoreApiError> {
        ClientApi::remove_split_tunnel_address_rule(self, access_token, rule_id, scope)
            .await
            .map_err(Into::into)
    }

    async fn report_split_tunnel_apply_result(
        &self,
        access_token: &str,
        request: &SplitTunnelApplyResult,
    ) -> Result<(), CoreApiError> {
        ClientApi::report_split_tunnel_apply_result(self, access_token, request)
            .await
            .map(|_| ())
            .map_err(Into::into)
    }
}

#[derive(Clone, Copy)]
enum ConnectionOperation {
    Stop,
    PinStray,
    UnpinStray,
}

#[derive(Clone, Copy)]
enum FailedStartStage {
    Preparation,
    Storage,
    Local,
}

impl FailedStartStage {
    fn log_kind(self) -> &'static str {
        match self {
            Self::Preparation => "connection.start_preparation_failed",
            Self::Storage => "connection.start_storage_failed",
            Self::Local => "connection.local_start_failed",
        }
    }

    fn local_start_may_be_incomplete(self) -> bool {
        matches!(self, Self::Local)
    }
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("требуется вход в приложение")]
    SignedOut,
    #[error("срок доступа истёк")]
    AccessExpired,
    #[error("требуется обязательное обновление приложения")]
    UpdateRequired,
    #[error("сохранённое подключение недоступно")]
    SavedConnectionUnavailable,
    #[error("защищённое хранилище недоступно")]
    Storage,
    #[error(transparent)]
    Api(CoreApiError),
    #[error("не удалось изменить состояние туннеля: {0}")]
    Tunnel(String),
    #[error("не удалось применить политику split-tunnel: {0}")]
    SplitTunnel(String),
}

impl From<TunnelError> for CoreError {
    fn from(error: TunnelError) -> Self {
        match error {
            TunnelError::Backend(code) => Self::Tunnel(code),
            TunnelError::InvalidOptions { code } => Self::Tunnel(code.to_string()),
        }
    }
}

impl From<CoreApiError> for CoreError {
    fn from(error: CoreApiError) -> Self {
        match error {
            CoreApiError::Unauthorized => Self::SignedOut,
            CoreApiError::AccessExpired => Self::AccessExpired,
            CoreApiError::Rejected { ref code, .. } if code == "critical_update_required" => {
                Self::UpdateRequired
            }
            other => Self::Api(other),
        }
    }
}

pub struct ClientCore<A, S, T, L> {
    api: Arc<A>,
    store: Arc<S>,
    tunnel: Arc<T>,
    logger: Arc<L>,
    state: Mutex<CoreState>,
    refresh_gate: Mutex<()>,
    connection_gate: Mutex<()>,
    split_tunnel_store: Arc<dyn SplitTunnelStore>,
    split_tunnel_gate: Mutex<()>,
    split_tunnel_packages: RwLock<Vec<SplitTunnelSelectedPackage>>,
    split_tunnel_options: Mutex<TunnelOptions>,
    dns_servers: RwLock<Vec<IpAddr>>,
    split_tunnel_warning: Mutex<SplitTunnelWarnings>,
    physical_network_change: Mutex<split_tunnel::PhysicalNetworkChangeDetector>,
    retry_policy: RetryPolicy,
}

impl<A, S, T, L> ClientCore<A, S, T, L>
where
    A: CoreApi,
    S: SecretStore,
    T: TunnelController,
    L: CoreLogger,
{
    pub fn new(api: Arc<A>, store: Arc<S>, tunnel: Arc<T>, logger: Arc<L>) -> Self {
        Self::with_split_tunnel_store(
            api,
            store,
            Arc::new(MemorySplitTunnelStore::default()),
            tunnel,
            logger,
        )
    }

    pub fn with_split_tunnel_store(
        api: Arc<A>,
        store: Arc<S>,
        split_tunnel_store: Arc<dyn SplitTunnelStore>,
        tunnel: Arc<T>,
        logger: Arc<L>,
    ) -> Self {
        Self {
            api,
            store,
            tunnel,
            logger,
            state: Mutex::new(CoreState::default()),
            refresh_gate: Mutex::new(()),
            connection_gate: Mutex::new(()),
            split_tunnel_store,
            split_tunnel_gate: Mutex::new(()),
            split_tunnel_packages: RwLock::new(Vec::new()),
            split_tunnel_options: Mutex::new(TunnelOptions::default()),
            dns_servers: RwLock::new(Vec::new()),
            split_tunnel_warning: Mutex::new(SplitTunnelWarnings::default()),
            physical_network_change: Mutex::new(
                split_tunnel::PhysicalNetworkChangeDetector::default(),
            ),
            retry_policy: RetryPolicy::default(),
        }
    }

    pub fn with_retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.retry_policy = retry_policy;
        self
    }

    pub fn set_dns_servers(&self, servers: Vec<IpAddr>) {
        if let Ok(mut current) = self.dns_servers.write() {
            *current = servers;
        }
    }

    pub(crate) fn with_dns_servers(&self, mut options: TunnelOptions) -> TunnelOptions {
        options.dns_servers = self
            .dns_servers
            .read()
            .map(|servers| servers.clone())
            .unwrap_or_default();
        options
    }

    async fn set_split_tunnel_warning(
        &self,
        kind: SplitTunnelWarningKind,
        code: impl Into<String>,
    ) -> bool {
        self.split_tunnel_warning
            .lock()
            .await
            .set(kind, code.into())
    }

    async fn clear_split_tunnel_warning(&self, kind: SplitTunnelWarningKind) {
        self.split_tunnel_warning.lock().await.clear(kind);
    }

    async fn clear_all_split_tunnel_warnings(&self) {
        self.split_tunnel_warning.lock().await.clear_all();
    }

    pub async fn state(&self) -> CoreState {
        let current = self.state.lock().await.clone();
        if current.phase != Phase::Connected {
            return current;
        }
        match self.tunnel.status().await {
            Ok(TunnelStatus::Stopped | TunnelStatus::Failed) => {
                let (state, changed) = self.leave_unconfirmed_connected_state().await;
                if changed {
                    self.set_split_tunnel_warning(
                        SplitTunnelWarningKind::Runtime,
                        "tunnel_runtime_stopped",
                    )
                    .await;
                }
                state
            }
            Ok(_) => {
                self.clear_split_tunnel_warning(SplitTunnelWarningKind::Runtime)
                    .await;
                current
            }
            Err(error) => {
                let changed = self
                    .set_split_tunnel_warning(
                        SplitTunnelWarningKind::Runtime,
                        "tunnel_status_unavailable",
                    )
                    .await;
                if changed {
                    self.logger.record(CoreLogEvent {
                        kind: "tunnel.status.unavailable",
                        operation_id: None,
                        request_id: None,
                        code: Some(error.to_string()),
                    });
                }
                current
            }
        }
    }

    pub async fn connection_metrics_context(&self) -> Option<ConnectionMetricsContext> {
        let state = self.state.lock().await.clone();
        if state.phase != Phase::Connected {
            return None;
        }
        if let Some(connection) = state.connection {
            return Some(ConnectionMetricsContext {
                session_id: connection.lease_id,
                probe_url: connection.probe_url,
            });
        }
        let stored = self.load_auth().ok()?;
        let connection = stored.saved_connection.or(stored.pinned_connection)?;
        Some(ConnectionMetricsContext {
            session_id: connection.lease_id,
            probe_url: connection.probe_url,
        })
    }

    pub async fn reconcile_external_tunnel_state(&self) -> CoreState {
        let status = match self.tunnel.status().await {
            Ok(status) => status,
            Err(_) => return self.state.lock().await.clone(),
        };
        let mut state = self.state.lock().await;
        if state.connection.is_some() {
            state.phase = match status {
                TunnelStatus::Running | TunnelStatus::Starting => Phase::Connected,
                TunnelStatus::Stopped => Phase::Ready,
                TunnelStatus::Stopping => Phase::Stopping,
                TunnelStatus::Failed => Phase::Error,
            };
        }
        state.clone()
    }

    async fn leave_unconfirmed_connected_state(&self) -> (CoreState, bool) {
        let mut state = self.state.lock().await;
        let changed = state.phase == Phase::Connected;
        if changed {
            state.phase = Phase::Stopping;
        }
        (state.clone(), changed)
    }

    pub fn record_tunnel_unavailable(&self, kind: &'static str, code: String) {
        self.logger.record(CoreLogEvent {
            kind,
            operation_id: None,
            request_id: None,
            code: Some(code),
        });
    }

    pub async fn sign_out(&self) -> Result<(), CoreError> {
        let _split_guard = self.split_tunnel_gate.lock().await;
        let _connection_guard = self.connection_gate.lock().await;
        let tunnel_result = self.tunnel.stop().await;
        let stored = self
            .store
            .load()
            .map_err(|_| CoreError::Storage)?
            .unwrap_or_else(nelomai_client_storage::StoredAuth::new_install);
        self.store
            .save(&nelomai_client_storage::StoredAuth {
                install_secret: stored.install_secret,
                access_token: None,
                refresh_token: None,
                saved_connection: None,
                pinned_connection: None,
                pending_start: None,
                compatibility: None,
            })
            .map_err(|_| CoreError::Storage)?;
        self.split_tunnel_store
            .delete()
            .map_err(|_| CoreError::Storage)?;
        if let Ok(mut packages) = self.split_tunnel_packages.write() {
            packages.clear();
        }
        *self.split_tunnel_options.lock().await = TunnelOptions::default();
        self.clear_all_split_tunnel_warnings().await;
        self.physical_network_change.lock().await.reset();
        *self.state.lock().await = CoreState::default();
        self.logger.record(CoreLogEvent {
            kind: "auth.signed_out",
            operation_id: None,
            request_id: None,
            code: None,
        });
        tunnel_result.map_err(Into::into)
    }

    pub async fn refresh_access_token(&self, stale_access: &str) -> Result<String, CoreError> {
        let _guard = self.refresh_gate.lock().await;
        let mut stored = self.load_auth()?;
        if let Some(current) = &stored.access_token {
            if current != stale_access {
                return Ok(current.clone());
            }
        }
        let refresh_token = stored.refresh_token.clone().ok_or(CoreError::SignedOut)?;
        let response = self.api.refresh(&refresh_token).await?;
        stored.access_token = Some(response.access_token.clone());
        stored.refresh_token = Some(response.refresh_token);
        self.store.save(&stored).map_err(|_| CoreError::Storage)?;
        self.logger.record(CoreLogEvent {
            kind: "auth.refreshed",
            operation_id: None,
            request_id: Some(response.request_id),
            code: None,
        });
        Ok(response.access_token)
    }

    pub async fn bootstrap(&self, now_unix: i64) -> Result<Bootstrap, CoreError> {
        let stored = self.load_auth()?;
        let access_token = stored.access_token.clone().ok_or(CoreError::SignedOut)?;
        let response = match self.api.bootstrap(&access_token).await {
            Ok(response) => response,
            Err(CoreApiError::Unauthorized) => {
                let access_token = self.refresh_access_token(&access_token).await?;
                match self.api.bootstrap(&access_token).await {
                    Ok(response) => response,
                    Err(error) => {
                        self.set_phase(phase_for_api_error(&error)).await;
                        return Err(error.into());
                    }
                }
            }
            Err(error) => {
                self.set_phase(phase_for_api_error(&error)).await;
                return Err(error.into());
            }
        };
        let mut current_stored = self.load_auth()?;
        current_stored.compatibility = Some(StoredCompatibility {
            update_required: response.update.required,
            observed_at_unix: now_unix,
        });
        if let Some(connection) = response.connection.as_ref() {
            if connection.pinned {
                if current_stored
                    .pinned_connection
                    .as_ref()
                    .is_some_and(|saved| saved.lease_id != connection.lease_id)
                {
                    current_stored.pinned_connection = None;
                }
            } else if current_stored
                .saved_connection
                .as_ref()
                .is_some_and(|saved| saved.lease_id != connection.lease_id)
            {
                current_stored.saved_connection = None;
            }
        }
        self.store
            .save(&current_stored)
            .map_err(|_| CoreError::Storage)?;
        let tunnel_status = match self.tunnel.status().await {
            Ok(status) => status,
            Err(TunnelError::Backend(code)) => {
                self.logger.record(CoreLogEvent {
                    kind: "tunnel.status.unavailable",
                    operation_id: None,
                    request_id: Some(response.request_id.clone()),
                    code: Some(code),
                });
                TunnelStatus::Stopped
            }
            Err(TunnelError::InvalidOptions { code }) => {
                self.logger.record(CoreLogEvent {
                    kind: "tunnel.status.unavailable",
                    operation_id: None,
                    request_id: Some(response.request_id.clone()),
                    code: Some(code.to_string()),
                });
                TunnelStatus::Stopped
            }
        };
        let phase = recover_phase(
            self.state.lock().await.phase,
            RecoveryFacts {
                signed_in: true,
                peer_bound: response.binding.is_some(),
                access_active: response.access.state == AccessState::Active
                    && response.access.can_connect,
                update_required: response.update.required,
                tunnel_status,
            },
        );
        *self.state.lock().await = CoreState {
            phase,
            connection: response.connection.clone(),
        };
        if phase == Phase::Connected {
            if let Some(connection) = &response.connection {
                self.restore_running_split_tunnel_options(connection).await;
            }
        }
        self.logger.record(CoreLogEvent {
            kind: "bootstrap.completed",
            operation_id: None,
            request_id: Some(response.request_id.clone()),
            code: None,
        });
        self.retry_pending_split_tunnel_results().await;
        Ok(response)
    }

    pub async fn start(
        &self,
        options: ConnectOptions,
        now_unix: i64,
    ) -> Result<Connection, CoreError> {
        let total_started = Instant::now();
        let _split_guard = self.split_tunnel_gate.lock().await;
        let _guard = self.connection_gate.lock().await;
        if let Some(connection) = self.connected_connection().await {
            return Ok(connection);
        }
        let mut stored = self.load_auth()?;
        if stored
            .compatibility
            .as_ref()
            .is_some_and(|compatibility| compatibility.update_required)
        {
            self.set_phase(Phase::UpdateRequired).await;
            return Err(CoreError::UpdateRequired);
        }
        self.release_stale_panel_connection_before_start(&stored)
            .await?;
        stored = self.load_auth()?;
        let split_policy = self.cached_policy_for_start()?;
        let preflight_tunnel_options = match &split_policy {
            Some(policy) => Some(
                self.effective_tunnel_options(
                    policy,
                    options.layer,
                    options.route_mode,
                    now_unix,
                    true,
                )
                .await?,
            ),
            None => None,
        };
        let mut access_token = stored.access_token.clone().ok_or(CoreError::SignedOut)?;
        let mut operation_id = pending_operation_id(&stored, &options)
            .or_else(|| reusable_operation_id(&stored, &options, now_unix))
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let mut pending_stored = self.load_auth()?;
        pending_stored.pending_start = Some(StoredPendingStart {
            operation_id: operation_id.clone(),
            layer: options.layer,
            tic_connection_mode: options.tic_connection_mode,
            route_mode: options.route_mode,
        });
        self.store
            .save(&pending_stored)
            .map_err(|_| CoreError::Storage)?;
        self.set_phase(Phase::Connecting).await;
        let mut request = ConnectionStartRequest {
            operation_id: operation_id.clone(),
            layer: options.layer,
            tic_connection_mode: options.tic_connection_mode,
            route_mode: options.route_mode,
            probes: options.probes,
            allow_alternate: options.allow_alternate,
        };
        let panel_started = Instant::now();
        let start_result = self.retry_start(&access_token, &mut request).await;
        operation_id.clone_from(&request.operation_id);
        let response = match start_result {
            Ok(response) => response,
            Err(error) => {
                if !matches!(&error, CoreError::Api(CoreApiError::Retryable)) {
                    let _ = self.clear_pending_start(&operation_id);
                }
                self.logger.record_timed(
                    CoreLogEvent {
                        kind: "connection.start_failed",
                        operation_id: Some(operation_id.clone()),
                        request_id: None,
                        code: Some(error.to_string()),
                    },
                    elapsed_millis(panel_started),
                );
                self.set_phase(phase_for_start_error(&error)).await;
                return Err(error);
            }
        };
        self.logger.record_timed(
            CoreLogEvent {
                kind: "connection.panel_ready",
                operation_id: Some(operation_id.clone()),
                request_id: Some(response.request_id.clone()),
                code: None,
            },
            elapsed_millis(panel_started),
        );
        *self.state.lock().await = CoreState {
            phase: Phase::Connecting,
            connection: Some(response.connection.clone()),
        };
        let tunnel_options = match &split_policy {
            Some(_)
                if response.connection.layer == options.layer
                    && response.connection.route_mode == options.route_mode =>
            {
                preflight_tunnel_options.unwrap_or_default()
            }
            Some(policy) => match self
                .effective_tunnel_options(
                    policy,
                    response.connection.layer,
                    response.connection.route_mode,
                    now_unix,
                    true,
                )
                .await
            {
                Ok(options) => options,
                Err(error) => {
                    self.compensate_failed_start(
                        &access_token,
                        &response.connection,
                        &response.request_id,
                        &operation_id,
                        FailedStartStage::Preparation,
                        &error,
                    )
                    .await;
                    return Err(error);
                }
            },
            None => {
                self.set_split_tunnel_warning(
                    SplitTunnelWarningKind::Sync,
                    "split_tunnel_policy_unavailable",
                )
                .await;
                TunnelOptions::default()
            }
        };
        let tunnel_options = self.with_dns_servers(tunnel_options);
        if split_policy.is_some() {
            self.clear_split_tunnel_warning(SplitTunnelWarningKind::Sync)
                .await;
        }
        let kind = stored_connection_kind(&response.connection);
        let valid_until_unix = match kind {
            StoredConnectionKind::DynamicWarm => Some(now_unix.saturating_add(3_600)),
            StoredConnectionKind::Fixed | StoredConnectionKind::Pinned => None,
        };
        let saved_connection = StoredConnection {
            lease_id: response.connection.lease_id.clone(),
            layer: response.connection.layer,
            tic_connection_mode: response.connection.tic_connection_mode,
            route_mode: response.connection.route_mode,
            probe_url: response.connection.probe_url.clone(),
            kind,
            configuration: response.configuration.clone(),
            valid_until_unix,
        };
        // The start request may rotate the tokens after an unauthorized response.
        // Reload before persisting the connection so stale credentials cannot
        // overwrite the freshly rotated session.
        let mut current_stored = self.load_auth()?;
        if kind == StoredConnectionKind::Pinned {
            current_stored.pinned_connection = Some(saved_connection);
            current_stored.saved_connection = None;
        } else {
            current_stored.saved_connection = Some(saved_connection);
        }
        if self.store.save(&current_stored).is_err() {
            let error = CoreError::Storage;
            self.compensate_failed_start(
                &access_token,
                &response.connection,
                &response.request_id,
                &operation_id,
                FailedStartStage::Storage,
                &error,
            )
            .await;
            return Err(error);
        }
        let local_start_started = Instant::now();
        if let Err(start_error) = self
            .tunnel
            .start(TunnelStartRequest {
                configuration: TunnelConfiguration::new(response.configuration),
                options: tunnel_options.clone(),
                quick_reconnect: match valid_until_unix {
                    Some(valid_until_unix) => QuickReconnect::Until(valid_until_unix),
                    None => QuickReconnect::Persistent,
                },
                quick_connection: Some(QuickConnection {
                    lease_id: response.connection.lease_id.clone(),
                    layer: response.connection.layer,
                    tic_connection_mode: response.connection.tic_connection_mode,
                    route_mode: response.connection.route_mode,
                    allow_alternate: options.allow_alternate,
                }),
            })
            .await
        {
            let error = CoreError::from(start_error);
            self.logger.record_timed(
                CoreLogEvent {
                    kind: "connection.local_start_rejected",
                    operation_id: Some(operation_id.clone()),
                    request_id: Some(response.request_id.clone()),
                    code: Some(error.to_string()),
                },
                elapsed_millis(local_start_started),
            );
            self.compensate_failed_start(
                &access_token,
                &response.connection,
                &response.request_id,
                &operation_id,
                FailedStartStage::Local,
                &error,
            )
            .await;
            return Err(error);
        }
        self.logger.record_timed(
            CoreLogEvent {
                kind: "connection.local_start_succeeded",
                operation_id: Some(operation_id.clone()),
                request_id: Some(response.request_id.clone()),
                code: None,
            },
            elapsed_millis(local_start_started),
        );
        let _ = self.clear_pending_start(&operation_id);
        let applied_physical_network_fingerprint = self
            .initialize_physical_network_detector(&tunnel_options)
            .await;
        *self.state.lock().await = CoreState {
            phase: Phase::Connected,
            connection: Some(response.connection.clone()),
        };
        self.clear_split_tunnel_warning(SplitTunnelWarningKind::Operation)
            .await;
        self.clear_split_tunnel_warning(SplitTunnelWarningKind::Runtime)
            .await;
        if let Some(policy) = &split_policy {
            let split_record_started = Instant::now();
            if let Err(record_error) = self
                .record_started_split_tunnel_policy(
                    policy,
                    tunnel_options,
                    applied_physical_network_fingerprint,
                    Some(&mut access_token),
                    now_unix,
                )
                .await
            {
                self.set_split_tunnel_warning(
                    SplitTunnelWarningKind::Storage,
                    "split_tunnel_state_save_failed",
                )
                .await;
                self.logger.record_timed(
                    CoreLogEvent {
                        kind: "split_tunnel.state_record_failed",
                        operation_id: Some(operation_id.clone()),
                        request_id: Some(response.request_id.clone()),
                        code: Some(record_error.to_string()),
                    },
                    elapsed_millis(split_record_started),
                );
            } else {
                self.logger.record_timed(
                    CoreLogEvent {
                        kind: "split_tunnel.state_recorded",
                        operation_id: Some(operation_id.clone()),
                        request_id: Some(response.request_id.clone()),
                        code: None,
                    },
                    elapsed_millis(split_record_started),
                );
                self.clear_split_tunnel_warning(SplitTunnelWarningKind::Operation)
                    .await;
                self.clear_split_tunnel_warning(SplitTunnelWarningKind::Runtime)
                    .await;
                self.clear_split_tunnel_warning(SplitTunnelWarningKind::Storage)
                    .await;
            }
        } else {
            *self.split_tunnel_options.lock().await = TunnelOptions::default();
            self.clear_applied_physical_network_fingerprint();
        }
        self.logger.record_timed(
            CoreLogEvent {
                kind: "connection.started",
                operation_id: Some(operation_id),
                request_id: Some(response.request_id),
                code: None,
            },
            elapsed_millis(total_started),
        );
        Ok(response.connection)
    }

    pub async fn prepare_binding_change(&self) -> Result<(), CoreError> {
        let _guard = self.connection_gate.lock().await;
        let stored = self.load_auth()?;
        self.release_stale_panel_connection_before_start(&stored)
            .await
    }

    pub async fn stop(&self) -> Result<Connection, CoreError> {
        let _split_guard = self.split_tunnel_gate.lock().await;
        let _guard = self.connection_gate.lock().await;
        let current_state = self.state.lock().await.clone();
        let current = current_state
            .connection
            .ok_or(CoreError::SavedConnectionUnavailable)?;
        let panel_connection_finished = matches!(
            current.status,
            nelomai_contracts::LeaseStatus::Warm
                | nelomai_contracts::LeaseStatus::Released
                | nelomai_contracts::LeaseStatus::Failed
        );
        self.set_phase(Phase::Stopping).await;
        let tunnel_status = self.tunnel.status().await.unwrap_or(TunnelStatus::Running);
        if tunnel_status != TunnelStatus::Stopped {
            if let Err(error) = self.tunnel.stop().await {
                self.set_phase(Phase::Stopping).await;
                return Err(error.into());
            }
        }
        self.physical_network_change.lock().await.reset();
        self.clear_applied_physical_network_fingerprint();
        self.clear_split_tunnel_warning(SplitTunnelWarningKind::Operation)
            .await;
        self.clear_split_tunnel_warning(SplitTunnelWarningKind::Runtime)
            .await;
        if panel_connection_finished {
            *self.state.lock().await = CoreState {
                phase: Phase::Ready,
                connection: Some(current.clone()),
            };
            return Ok(current);
        }
        let stored = self.load_auth()?;
        let access_token = stored.access_token.ok_or(CoreError::SignedOut)?;
        let request = ConnectionOperationRequest {
            operation_id: Uuid::new_v4().to_string(),
            lease_id: current.lease_id.clone(),
        };
        let response = match self
            .retry_operation(&access_token, &request, ConnectionOperation::Stop)
            .await
        {
            Ok(response) => response,
            Err(error) => {
                let phase = match &error {
                    CoreError::SignedOut => Phase::SignedOut,
                    CoreError::AccessExpired => Phase::AccessExpired,
                    CoreError::UpdateRequired => Phase::UpdateRequired,
                    _ if self.state.lock().await.phase == Phase::Error => Phase::Error,
                    _ => Phase::Stopping,
                };
                *self.state.lock().await = CoreState {
                    phase,
                    connection: Some(current),
                };
                self.logger.record(CoreLogEvent {
                    kind: "connection.stop_failed",
                    operation_id: Some(request.operation_id),
                    request_id: None,
                    code: Some(error.to_string()),
                });
                return Err(error);
            }
        };
        if let Some(pending) = &stored.pending_start {
            self.clear_pending_start(&pending.operation_id)?;
        }
        *self.state.lock().await = CoreState {
            phase: Phase::Ready,
            connection: Some(response.connection.clone()),
        };
        self.logger.record(CoreLogEvent {
            kind: "connection.stopped",
            operation_id: Some(request.operation_id),
            request_id: Some(response.request_id),
            code: None,
        });
        Ok(response.connection)
    }

    pub async fn pin_stray(&self) -> Result<Connection, CoreError> {
        let _guard = self.connection_gate.lock().await;
        let current_state = self.state.lock().await.clone();
        let current = current_state
            .connection
            .filter(|connection| {
                current_state.phase == Phase::Connected
                    && connection.layer == Layer::Stray
                    && !connection.pinned
            })
            .ok_or(CoreError::SavedConnectionUnavailable)?;
        let mut stored = self.load_auth()?;
        let saved = stored
            .saved_connection
            .take()
            .filter(|saved| saved.lease_id == current.lease_id)
            .ok_or(CoreError::SavedConnectionUnavailable)?;
        let access_token = stored.access_token.clone().ok_or(CoreError::SignedOut)?;
        let request = ConnectionOperationRequest {
            operation_id: Uuid::new_v4().to_string(),
            lease_id: current.lease_id,
        };
        let response = self
            .retry_operation(&access_token, &request, ConnectionOperation::PinStray)
            .await?;
        stored.pinned_connection = Some(StoredConnection {
            kind: StoredConnectionKind::Pinned,
            valid_until_unix: None,
            ..saved
        });
        self.store.save(&stored).map_err(|_| CoreError::Storage)?;
        *self.state.lock().await = CoreState {
            phase: Phase::Connected,
            connection: Some(response.connection.clone()),
        };
        self.logger.record(CoreLogEvent {
            kind: "connection.pinned",
            operation_id: Some(request.operation_id),
            request_id: Some(response.request_id),
            code: None,
        });
        Ok(response.connection)
    }

    pub async fn unpin_stray(
        &self,
        lease_id: &str,
        now_unix: i64,
    ) -> Result<Connection, CoreError> {
        let _guard = self.connection_gate.lock().await;
        let mut stored = self.load_auth()?;
        let saved = stored
            .pinned_connection
            .take()
            .filter(|saved| saved.lease_id == lease_id)
            .ok_or(CoreError::SavedConnectionUnavailable)?;
        let access_token = stored.access_token.clone().ok_or(CoreError::SignedOut)?;
        let request = ConnectionOperationRequest {
            operation_id: Uuid::new_v4().to_string(),
            lease_id: lease_id.to_string(),
        };
        let response = self
            .retry_operation(&access_token, &request, ConnectionOperation::UnpinStray)
            .await?;
        if stored.saved_connection.is_none() {
            stored.saved_connection = Some(StoredConnection {
                kind: StoredConnectionKind::DynamicWarm,
                valid_until_unix: Some(now_unix.saturating_add(3_600)),
                ..saved
            });
        }
        self.store.save(&stored).map_err(|_| CoreError::Storage)?;
        let mut state = self.state.lock().await;
        if state
            .connection
            .as_ref()
            .is_some_and(|connection| connection.lease_id == lease_id)
        {
            state.connection = Some(response.connection.clone());
        }
        self.logger.record(CoreLogEvent {
            kind: "connection.unpinned",
            operation_id: Some(request.operation_id),
            request_id: Some(response.request_id),
            code: None,
        });
        Ok(response.connection)
    }

    pub async fn complete_unbind(&self) -> Result<(), CoreError> {
        let _guard = self.connection_gate.lock().await;
        self.tunnel.stop().await?;
        let mut stored = self.load_auth()?;
        stored.saved_connection = None;
        stored.pinned_connection = None;
        self.store.save(&stored).map_err(|_| CoreError::Storage)?;
        *self.state.lock().await = CoreState {
            phase: Phase::NeedsPeerBinding,
            connection: None,
        };
        self.logger.record(CoreLogEvent {
            kind: "device.peer_unbound",
            operation_id: None,
            request_id: None,
            code: None,
        });
        Ok(())
    }

    pub async fn start_saved_stray_offline(&self, now_unix: i64) -> Result<String, CoreError> {
        let _split_guard = self.split_tunnel_gate.lock().await;
        let _guard = self.connection_gate.lock().await;
        let stored = self.load_auth()?;
        if stored
            .compatibility
            .as_ref()
            .is_some_and(|compatibility| compatibility.update_required)
        {
            return Err(CoreError::UpdateRequired);
        }
        let saved = stored
            .saved_connection
            .filter(|connection| {
                connection.layer == Layer::Stray
                    && match connection.kind {
                        StoredConnectionKind::Pinned => true,
                        StoredConnectionKind::DynamicWarm => connection
                            .valid_until_unix
                            .is_some_and(|expiry| expiry > now_unix),
                        StoredConnectionKind::Fixed => false,
                    }
            })
            .or_else(|| {
                stored
                    .pinned_connection
                    .filter(|connection| connection.layer == Layer::Stray)
            })
            .ok_or(CoreError::SavedConnectionUnavailable)?;
        let split_policy = self.cached_policy_for_start()?;
        let tunnel_options = match &split_policy {
            Some(policy) => {
                self.effective_tunnel_options(policy, saved.layer, saved.route_mode, now_unix, true)
                    .await?
            }
            None => {
                self.set_split_tunnel_warning(
                    SplitTunnelWarningKind::Sync,
                    "split_tunnel_policy_unavailable",
                )
                .await;
                TunnelOptions::default()
            }
        };
        let tunnel_options = self.with_dns_servers(tunnel_options);
        if split_policy.is_some() {
            self.clear_split_tunnel_warning(SplitTunnelWarningKind::Sync)
                .await;
        }
        self.tunnel
            .start(TunnelStartRequest {
                configuration: TunnelConfiguration::new(saved.configuration),
                options: tunnel_options.clone(),
                quick_reconnect: match saved.valid_until_unix {
                    Some(valid_until_unix) => QuickReconnect::Until(valid_until_unix),
                    None => QuickReconnect::Persistent,
                },
                quick_connection: Some(QuickConnection {
                    lease_id: saved.lease_id.clone(),
                    layer: saved.layer,
                    tic_connection_mode: saved.tic_connection_mode,
                    route_mode: saved.route_mode,
                    allow_alternate: false,
                }),
            })
            .await?;
        let applied_physical_network_fingerprint = self
            .initialize_physical_network_detector(&tunnel_options)
            .await;
        let connection = Connection {
            lease_id: saved.lease_id.clone(),
            layer: saved.layer,
            tic_connection_mode: saved.tic_connection_mode,
            route_mode: saved.route_mode,
            probe_url: saved.probe_url.clone(),
            status: nelomai_contracts::LeaseStatus::Connected,
            pinned: saved.kind == StoredConnectionKind::Pinned,
            stopped_at: None,
        };
        *self.state.lock().await = CoreState {
            phase: Phase::Connected,
            connection: Some(connection),
        };
        self.clear_split_tunnel_warning(SplitTunnelWarningKind::Operation)
            .await;
        self.clear_split_tunnel_warning(SplitTunnelWarningKind::Runtime)
            .await;
        if let Some(policy) = &split_policy {
            if let Err(record_error) = self
                .record_started_split_tunnel_policy(
                    policy,
                    tunnel_options,
                    applied_physical_network_fingerprint,
                    None,
                    now_unix,
                )
                .await
            {
                self.set_split_tunnel_warning(
                    SplitTunnelWarningKind::Storage,
                    "split_tunnel_state_save_failed",
                )
                .await;
                self.logger.record(CoreLogEvent {
                    kind: "split_tunnel.state_record_failed",
                    operation_id: Some(saved.lease_id.clone()),
                    request_id: None,
                    code: Some(record_error.to_string()),
                });
            } else {
                self.clear_split_tunnel_warning(SplitTunnelWarningKind::Operation)
                    .await;
                self.clear_split_tunnel_warning(SplitTunnelWarningKind::Runtime)
                    .await;
                self.clear_split_tunnel_warning(SplitTunnelWarningKind::Storage)
                    .await;
            }
        } else {
            *self.split_tunnel_options.lock().await = TunnelOptions::default();
            self.clear_applied_physical_network_fingerprint();
        }
        self.logger.record(CoreLogEvent {
            kind: "connection.started_offline",
            operation_id: Some(saved.lease_id.clone()),
            request_id: None,
            code: None,
        });
        Ok(saved.lease_id)
    }

    fn load_auth(&self) -> Result<nelomai_client_storage::StoredAuth, CoreError> {
        let mut stored = self
            .store
            .load()
            .map_err(|_| CoreError::Storage)?
            .ok_or(CoreError::SignedOut)?;
        if stored.pinned_connection.is_none()
            && stored
                .saved_connection
                .as_ref()
                .is_some_and(|connection| connection.kind == StoredConnectionKind::Pinned)
        {
            stored.pinned_connection = stored.saved_connection.take();
            self.store.save(&stored).map_err(|_| CoreError::Storage)?;
        }
        Ok(stored)
    }

    async fn connected_connection(&self) -> Option<Connection> {
        let state = self.state.lock().await;
        (state.phase == Phase::Connected)
            .then(|| state.connection.clone())
            .flatten()
    }

    async fn release_stale_panel_connection_before_start(
        &self,
        stored: &nelomai_client_storage::StoredAuth,
    ) -> Result<(), CoreError> {
        let stale = {
            let state = self.state.lock().await;
            state.connection.clone().filter(|connection| {
                state.phase != Phase::Connected
                    && matches!(
                        connection.status,
                        LeaseStatus::Allocating | LeaseStatus::Issued | LeaseStatus::Connected
                    )
            })
        };
        let Some(connection) = stale else {
            return Ok(());
        };
        if !matches!(
            self.tunnel.status().await?,
            TunnelStatus::Stopped | TunnelStatus::Failed
        ) {
            return Ok(());
        }
        let access_token = stored.access_token.clone().ok_or(CoreError::SignedOut)?;
        let request = ConnectionOperationRequest {
            operation_id: Uuid::new_v4().to_string(),
            lease_id: connection.lease_id,
        };
        let response = match self
            .retry_operation(&access_token, &request, ConnectionOperation::Stop)
            .await
        {
            Ok(response) => response,
            Err(error) => {
                self.logger.record(CoreLogEvent {
                    kind: "connection.stale_release_failed",
                    operation_id: Some(request.operation_id),
                    request_id: None,
                    code: Some(error.to_string()),
                });
                return Err(error);
            }
        };
        if let Some(pending) = &stored.pending_start {
            self.clear_pending_start(&pending.operation_id)?;
        }
        *self.state.lock().await = CoreState {
            phase: Phase::Ready,
            connection: Some(response.connection),
        };
        self.logger.record(CoreLogEvent {
            kind: "connection.stale_released",
            operation_id: Some(request.operation_id),
            request_id: Some(response.request_id),
            code: None,
        });
        Ok(())
    }

    async fn set_phase(&self, phase: Phase) {
        self.state.lock().await.phase = phase;
    }

    fn clear_pending_start(&self, operation_id: &str) -> Result<(), CoreError> {
        let Some(mut stored) = self.store.load().map_err(|_| CoreError::Storage)? else {
            return Ok(());
        };
        if stored
            .pending_start
            .as_ref()
            .is_some_and(|pending| pending.operation_id == operation_id)
        {
            stored.pending_start = None;
            self.store.save(&stored).map_err(|_| CoreError::Storage)?;
        }
        Ok(())
    }

    fn replace_pending_start_operation(
        &self,
        previous_operation_id: &str,
        replacement_operation_id: &str,
    ) -> Result<(), CoreError> {
        let Some(mut stored) = self.store.load().map_err(|_| CoreError::Storage)? else {
            return Err(CoreError::Storage);
        };
        let Some(pending) = stored
            .pending_start
            .as_mut()
            .filter(|pending| pending.operation_id == previous_operation_id)
        else {
            return Err(CoreError::Storage);
        };
        pending.operation_id = replacement_operation_id.to_string();
        self.store.save(&stored).map_err(|_| CoreError::Storage)
    }

    async fn compensate_failed_start(
        &self,
        access_token: &str,
        connection: &Connection,
        request_id: &str,
        operation_id: &str,
        stage: FailedStartStage,
        error: &CoreError,
    ) {
        self.physical_network_change.lock().await.reset();
        let compensation_request = ConnectionOperationRequest {
            operation_id: Uuid::new_v4().to_string(),
            lease_id: connection.lease_id.clone(),
        };
        let (connection, mut phase) = match self
            .retry_operation(
                access_token,
                &compensation_request,
                ConnectionOperation::Stop,
            )
            .await
        {
            Ok(compensation) => {
                let _ = self.clear_pending_start(operation_id);
                (compensation.connection, phase_for_start_error(error))
            }
            Err(compensation_error) => {
                self.logger.record(CoreLogEvent {
                    kind: "connection.start_compensation_failed",
                    operation_id: Some(compensation_request.operation_id.clone()),
                    request_id: None,
                    code: Some(compensation_error.to_string()),
                });
                (
                    connection.clone(),
                    phase_for_start_error(&compensation_error),
                )
            }
        };
        if stage.local_start_may_be_incomplete()
            && !matches!(self.tunnel.status().await, Ok(TunnelStatus::Stopped))
        {
            phase = Phase::Stopping;
        }
        *self.state.lock().await = CoreState {
            phase,
            connection: Some(connection),
        };
        self.logger.record(CoreLogEvent {
            kind: stage.log_kind(),
            operation_id: Some(operation_id.to_string()),
            request_id: Some(request_id.to_string()),
            code: Some(error.to_string()),
        });
    }

    async fn retry_start(
        &self,
        access_token: &str,
        request: &mut ConnectionStartRequest,
    ) -> Result<ConnectionStartResponse, CoreError> {
        let delays = self.retry_policy.delays_millis();
        let mut retry_index = 0;
        let mut access_token = access_token.to_string();
        let mut refreshed = false;
        let mut replaced_finished_operation = false;
        loop {
            match self.api.start_connection(&access_token, request).await {
                Ok(response) => return Ok(response),
                Err(CoreApiError::Unauthorized) if !refreshed => {
                    access_token = self.refresh_access_token(&access_token).await?;
                    refreshed = true;
                }
                Err(CoreApiError::Retryable) if retry_index < delays.len() => {
                    let delay = delays[retry_index];
                    retry_index += 1;
                    if delay > 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                    }
                }
                Err(CoreApiError::Rejected { ref code, .. })
                    if code == "connection_no_longer_active"
                        && request.layer == Layer::Tic
                        && !replaced_finished_operation =>
                {
                    let previous_operation_id = request.operation_id.clone();
                    let replacement_operation_id = Uuid::new_v4().to_string();
                    self.replace_pending_start_operation(
                        &previous_operation_id,
                        &replacement_operation_id,
                    )?;
                    request.operation_id = replacement_operation_id.clone();
                    replaced_finished_operation = true;
                    retry_index = 0;
                    self.logger.record(CoreLogEvent {
                        kind: "connection.start_operation_replaced",
                        operation_id: Some(replacement_operation_id),
                        request_id: None,
                        code: Some("connection_no_longer_active".to_string()),
                    });
                }
                Err(error) => {
                    self.set_phase(phase_for_api_error(&error)).await;
                    return Err(error.into());
                }
            }
        }
    }

    async fn retry_operation(
        &self,
        access_token: &str,
        request: &ConnectionOperationRequest,
        operation: ConnectionOperation,
    ) -> Result<ConnectionOperationResponse, CoreError> {
        let delays = self.retry_policy.delays_millis();
        let mut retry_index = 0;
        let mut access_token = access_token.to_string();
        let mut refreshed = false;
        loop {
            let result = match operation {
                ConnectionOperation::Stop => self.api.stop_connection(&access_token, request).await,
                ConnectionOperation::PinStray => self.api.pin_stray(&access_token, request).await,
                ConnectionOperation::UnpinStray => {
                    self.api.unpin_stray(&access_token, request).await
                }
            };
            match result {
                Ok(response) => return Ok(response),
                Err(CoreApiError::Unauthorized) if !refreshed => {
                    access_token = self.refresh_access_token(&access_token).await?;
                    refreshed = true;
                }
                Err(CoreApiError::Retryable) if retry_index < delays.len() => {
                    let delay = delays[retry_index];
                    retry_index += 1;
                    if delay > 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                    }
                }
                Err(error) => {
                    if matches!(operation, ConnectionOperation::Stop) {
                        self.set_phase(phase_for_api_error(&error)).await;
                    }
                    return Err(error.into());
                }
            }
        }
    }
}

fn reusable_operation_id(
    stored: &nelomai_client_storage::StoredAuth,
    options: &ConnectOptions,
    now_unix: i64,
) -> Option<String> {
    stored
        .saved_connection
        .as_ref()
        .filter(|saved| {
            saved.layer == options.layer
                && saved.tic_connection_mode == options.tic_connection_mode
                && saved.route_mode == options.route_mode
                && match saved.kind {
                    StoredConnectionKind::Pinned => true,
                    StoredConnectionKind::Fixed => false,
                    StoredConnectionKind::DynamicWarm => saved
                        .valid_until_unix
                        .is_some_and(|expiry| expiry > now_unix),
                }
        })
        .or_else(|| {
            stored.pinned_connection.as_ref().filter(|saved| {
                saved.layer == options.layer
                    && saved.tic_connection_mode == options.tic_connection_mode
                    && saved.route_mode == options.route_mode
            })
        })
        .map(|saved| saved.lease_id.clone())
}

fn pending_operation_id(
    stored: &nelomai_client_storage::StoredAuth,
    options: &ConnectOptions,
) -> Option<String> {
    stored
        .pending_start
        .as_ref()
        .filter(|pending| {
            pending.layer == options.layer
                && pending.tic_connection_mode == options.tic_connection_mode
                && pending.route_mode == options.route_mode
        })
        .map(|pending| pending.operation_id.clone())
}

fn stored_connection_kind(connection: &Connection) -> StoredConnectionKind {
    if connection.pinned {
        StoredConnectionKind::Pinned
    } else if connection.layer == Layer::Tic
        && connection.tic_connection_mode == TicConnectionMode::Personal
    {
        StoredConnectionKind::Fixed
    } else {
        StoredConnectionKind::DynamicWarm
    }
}

fn phase_for_api_error(error: &CoreApiError) -> Phase {
    match error {
        CoreApiError::Unauthorized => Phase::SignedOut,
        CoreApiError::AccessExpired => Phase::AccessExpired,
        CoreApiError::Retryable => Phase::ServerUnavailable,
        CoreApiError::Rejected { code, .. } if transient_start_rejection(code) => {
            Phase::ServerUnavailable
        }
        CoreApiError::Rejected { .. } => Phase::Error,
    }
}

fn phase_for_start_error(error: &CoreError) -> Phase {
    match error {
        CoreError::SignedOut | CoreError::Api(CoreApiError::Unauthorized) => Phase::SignedOut,
        CoreError::AccessExpired | CoreError::Api(CoreApiError::AccessExpired) => {
            Phase::AccessExpired
        }
        CoreError::UpdateRequired => Phase::UpdateRequired,
        CoreError::Api(CoreApiError::Retryable) => Phase::ServerUnavailable,
        CoreError::Api(CoreApiError::Rejected { code, .. }) if transient_start_rejection(code) => {
            Phase::ServerUnavailable
        }
        CoreError::Api(CoreApiError::Rejected { .. }) => Phase::Error,
        CoreError::SavedConnectionUnavailable
        | CoreError::Storage
        | CoreError::Tunnel(_)
        | CoreError::SplitTunnel(_) => Phase::Ready,
    }
}

fn transient_start_rejection(code: &str) -> bool {
    code == "configuration_fetch_failed"
}

#[cfg(test)]
mod tests {
    use super::*;
    use nelomai_client_tunnel::TunnelStatus;

    #[test]
    fn reducer_covers_the_primary_connection_lifecycle() {
        let mut state = CoreState::default();
        for (event, expected) in [
            (CoreEvent::AuthStarted, Phase::Authenticating),
            (CoreEvent::Authenticated, Phase::NeedsPeerBinding),
            (CoreEvent::PeerBound, Phase::Ready),
            (CoreEvent::MeasurementStarted, Phase::Measuring),
            (CoreEvent::ConnectionStarted, Phase::Connecting),
            (CoreEvent::ConnectionEstablished, Phase::Connected),
            (CoreEvent::StopStarted, Phase::Stopping),
            (CoreEvent::Stopped, Phase::Ready),
        ] {
            state = reduce(state, event);
            assert_eq!(state.phase, expected);
        }
    }

    #[test]
    fn every_transient_phase_recovers_from_persisted_facts() {
        for phase in [
            Phase::Authenticating,
            Phase::Measuring,
            Phase::Connecting,
            Phase::Stopping,
        ] {
            let recovered = recover_phase(
                phase,
                RecoveryFacts {
                    signed_in: true,
                    peer_bound: true,
                    access_active: true,
                    update_required: false,
                    tunnel_status: TunnelStatus::Stopped,
                },
            );
            assert_eq!(recovered, Phase::Ready, "failed to recover {phase:?}");
        }
    }

    #[test]
    fn recovery_prioritizes_auth_access_update_and_real_tunnel_status() {
        let base = RecoveryFacts {
            signed_in: true,
            peer_bound: true,
            access_active: true,
            update_required: false,
            tunnel_status: TunnelStatus::Stopped,
        };
        assert_eq!(
            recover_phase(
                Phase::Error,
                RecoveryFacts {
                    signed_in: false,
                    ..base
                }
            ),
            Phase::SignedOut
        );
        assert_eq!(
            recover_phase(
                Phase::Error,
                RecoveryFacts {
                    update_required: true,
                    ..base
                }
            ),
            Phase::UpdateRequired
        );
        assert_eq!(
            recover_phase(
                Phase::Error,
                RecoveryFacts {
                    peer_bound: false,
                    ..base
                }
            ),
            Phase::NeedsPeerBinding
        );
        assert_eq!(
            recover_phase(
                Phase::Error,
                RecoveryFacts {
                    access_active: false,
                    ..base
                }
            ),
            Phase::AccessExpired
        );
        assert_eq!(
            recover_phase(
                Phase::Error,
                RecoveryFacts {
                    tunnel_status: TunnelStatus::Running,
                    ..base
                }
            ),
            Phase::Connected
        );
        assert_eq!(
            recover_phase(
                Phase::Error,
                RecoveryFacts {
                    peer_bound: false,
                    access_active: false,
                    ..base
                }
            ),
            Phase::AccessExpired
        );
    }

    #[test]
    fn probe_scheduler_is_idle_in_background_or_while_connected() {
        let mut scheduler = ProbeScheduler::new(300);
        scheduler.set_bootstrapped(true);
        assert!(scheduler.should_probe(1_000));
        scheduler.mark_probed(1_000);
        assert!(!scheduler.should_probe(1_299));
        assert!(scheduler.should_probe(1_300));
        scheduler.set_foreground(false);
        assert!(!scheduler.should_probe(2_000));
        scheduler.set_foreground(true);
        scheduler.set_connected(true);
        assert!(!scheduler.should_probe(2_000));
    }

    #[test]
    fn retry_policy_is_bounded_exponential_backoff() {
        assert_eq!(
            RetryPolicy::default().delays_millis(),
            vec![250, 500, 1_000]
        );
    }

    #[test]
    fn panel_access_expired_error_maps_to_a_distinct_core_state() {
        let error = ClientApiError::Api {
            status: reqwest::StatusCode::FORBIDDEN,
            request_id: "req".to_string(),
            code: "access_expired".to_string(),
            message: "expired".to_string(),
        };
        assert_eq!(CoreApiError::from(error), CoreApiError::AccessExpired);
    }

    #[test]
    fn rejected_request_keeps_the_panel_message() {
        let error = ClientApiError::Api {
            status: reqwest::StatusCode::CONFLICT,
            request_id: "req".to_string(),
            code: "connection_active".to_string(),
            message: "Сначала остановите текущее подключение.".to_string(),
        };
        assert_eq!(
            CoreApiError::from(error),
            CoreApiError::Rejected {
                code: "connection_active".to_string(),
                message: "Сначала остановите текущее подключение.".to_string(),
            },
        );
    }

    #[test]
    fn configuration_fetch_failure_keeps_its_stable_code() {
        let error = ClientApiError::Api {
            status: reqwest::StatusCode::SERVICE_UNAVAILABLE,
            request_id: "req".to_string(),
            code: "configuration_fetch_failed".to_string(),
            message: "Не удалось получить конфигурацию. Повторите попытку.".to_string(),
        };

        assert_eq!(
            CoreApiError::from(error),
            CoreApiError::Rejected {
                code: "configuration_fetch_failed".to_string(),
                message: "Не удалось получить конфигурацию. Повторите попытку.".to_string(),
            },
        );
    }

    #[test]
    fn critical_update_rejection_opens_the_required_update_state() {
        let error = CoreApiError::Rejected {
            code: "critical_update_required".to_string(),
            message: "Для подключения необходимо обновить приложение.".to_string(),
        };

        assert!(matches!(CoreError::from(error), CoreError::UpdateRequired));
    }
}
