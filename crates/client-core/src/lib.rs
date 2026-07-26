use async_trait::async_trait;
use nelomai_client_api::{ClientApi, ClientApiError, TokenResponse};
use nelomai_client_storage::{
    SecretStore, StoredCompatibility, StoredConnection, StoredConnectionKind,
};
use nelomai_client_tunnel::{TunnelConfiguration, TunnelController, TunnelError, TunnelStatus};
use nelomai_contracts::{
    AccessState, Bootstrap, Connection, ConnectionOperationRequest, ConnectionOperationResponse,
    ConnectionStartRequest, ConnectionStartResponse, Layer, ProbeResult, RouteMode,
    TicConnectionMode,
};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;
use uuid::Uuid;

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

impl Default for CoreState {
    fn default() -> Self {
        Self {
            phase: Phase::SignedOut,
            connection: None,
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
}

pub struct NoopLogger;

impl CoreLogger for NoopLogger {
    fn record(&self, _event: CoreLogEvent) {}
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
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CoreApiError {
    #[error("авторизация истекла")]
    Unauthorized,
    #[error("срок доступа истёк")]
    AccessExpired,
    #[error("временная ошибка сети")]
    Retryable,
    #[error("панель отклонила запрос: {code}")]
    Rejected { code: String },
}

impl From<ClientApiError> for CoreApiError {
    fn from(error: ClientApiError) -> Self {
        match error {
            ClientApiError::Transport(_) => Self::Retryable,
            ClientApiError::Api { status, .. } if status.as_u16() == 401 => Self::Unauthorized,
            ClientApiError::Api { code, .. } if code == "access_expired" => Self::AccessExpired,
            ClientApiError::Api { status, .. } if status.is_server_error() => Self::Retryable,
            ClientApiError::Api { code, .. } => Self::Rejected { code },
            ClientApiError::InvalidErrorResponse { status } if status.is_server_error() => {
                Self::Retryable
            }
            ClientApiError::InvalidBaseUrl(_) | ClientApiError::InvalidErrorResponse { .. } => {
                Self::Rejected {
                    code: "invalid_client_api_response".to_string(),
                }
            }
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
    #[error("не удалось изменить состояние туннеля")]
    Tunnel,
}

impl From<TunnelError> for CoreError {
    fn from(_error: TunnelError) -> Self {
        Self::Tunnel
    }
}

impl From<CoreApiError> for CoreError {
    fn from(error: CoreApiError) -> Self {
        match error {
            CoreApiError::Unauthorized => Self::SignedOut,
            CoreApiError::AccessExpired => Self::AccessExpired,
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
        Self {
            api,
            store,
            tunnel,
            logger,
            state: Mutex::new(CoreState::default()),
            refresh_gate: Mutex::new(()),
            connection_gate: Mutex::new(()),
            retry_policy: RetryPolicy::default(),
        }
    }

    pub fn with_retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.retry_policy = retry_policy;
        self
    }

    pub async fn state(&self) -> CoreState {
        self.state.lock().await.clone()
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
        let mut stored = self.load_auth()?;
        let access_token = stored.access_token.clone().ok_or(CoreError::SignedOut)?;
        let response = match self.api.bootstrap(&access_token).await {
            Ok(response) => response,
            Err(error) => {
                self.set_phase(phase_for_api_error(&error)).await;
                return Err(error.into());
            }
        };
        stored.compatibility = Some(StoredCompatibility {
            update_required: response.update.required,
            observed_at_unix: now_unix,
        });
        self.store.save(&stored).map_err(|_| CoreError::Storage)?;
        let tunnel_status = self.tunnel.status().await?;
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
        self.logger.record(CoreLogEvent {
            kind: "bootstrap.completed",
            operation_id: None,
            request_id: Some(response.request_id.clone()),
            code: None,
        });
        Ok(response)
    }

    pub async fn start(
        &self,
        options: ConnectOptions,
        now_unix: i64,
    ) -> Result<Connection, CoreError> {
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
        let access_token = stored.access_token.clone().ok_or(CoreError::SignedOut)?;
        let operation_id = reusable_operation_id(&stored, &options, now_unix)
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        self.set_phase(Phase::Connecting).await;
        let request = ConnectionStartRequest {
            operation_id: operation_id.clone(),
            layer: options.layer,
            tic_connection_mode: options.tic_connection_mode,
            route_mode: options.route_mode,
            probes: options.probes,
            allow_alternate: options.allow_alternate,
        };
        let response = self
            .retry_start(&access_token, &request)
            .await
            .inspect_err(|error| {
                self.logger.record(CoreLogEvent {
                    kind: "connection.start_failed",
                    operation_id: Some(operation_id.clone()),
                    request_id: None,
                    code: Some(error.to_string()),
                });
            })?;
        let kind = stored_connection_kind(&response.connection);
        let valid_until_unix = match kind {
            StoredConnectionKind::DynamicWarm => Some(now_unix.saturating_add(3_600)),
            StoredConnectionKind::Fixed | StoredConnectionKind::Pinned => None,
        };
        stored.saved_connection = Some(StoredConnection {
            lease_id: response.connection.lease_id.clone(),
            layer: response.connection.layer,
            tic_connection_mode: response.connection.tic_connection_mode,
            route_mode: response.connection.route_mode,
            kind,
            configuration: response.configuration.clone(),
            valid_until_unix,
        });
        self.store.save(&stored).map_err(|_| CoreError::Storage)?;
        self.tunnel
            .start(TunnelConfiguration::new(response.configuration))
            .await?;
        *self.state.lock().await = CoreState {
            phase: Phase::Connected,
            connection: Some(response.connection.clone()),
        };
        self.logger.record(CoreLogEvent {
            kind: "connection.started",
            operation_id: Some(operation_id),
            request_id: Some(response.request_id),
            code: None,
        });
        Ok(response.connection)
    }

    pub async fn stop(&self) -> Result<Connection, CoreError> {
        let _guard = self.connection_gate.lock().await;
        let current_state = self.state.lock().await.clone();
        let current = current_state
            .connection
            .ok_or(CoreError::SavedConnectionUnavailable)?;
        if current_state.phase != Phase::Connected {
            return Ok(current);
        }
        self.set_phase(Phase::Stopping).await;
        self.tunnel.stop().await?;
        let stored = self.load_auth()?;
        let access_token = stored.access_token.ok_or(CoreError::SignedOut)?;
        let request = ConnectionOperationRequest {
            operation_id: Uuid::new_v4().to_string(),
            lease_id: current.lease_id,
        };
        let response = self.retry_stop(&access_token, &request).await?;
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

    pub async fn start_saved_stray_offline(&self, now_unix: i64) -> Result<String, CoreError> {
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
            .ok_or(CoreError::SavedConnectionUnavailable)?;
        self.tunnel
            .start(TunnelConfiguration::new(saved.configuration))
            .await?;
        let connection = Connection {
            lease_id: saved.lease_id.clone(),
            layer: saved.layer,
            tic_connection_mode: saved.tic_connection_mode,
            route_mode: saved.route_mode,
            status: nelomai_contracts::LeaseStatus::Connected,
            pinned: saved.kind == StoredConnectionKind::Pinned,
            stopped_at: None,
        };
        *self.state.lock().await = CoreState {
            phase: Phase::Connected,
            connection: Some(connection),
        };
        self.logger.record(CoreLogEvent {
            kind: "connection.started_offline",
            operation_id: Some(saved.lease_id.clone()),
            request_id: None,
            code: None,
        });
        Ok(saved.lease_id)
    }

    fn load_auth(&self) -> Result<nelomai_client_storage::StoredAuth, CoreError> {
        self.store
            .load()
            .map_err(|_| CoreError::Storage)?
            .ok_or(CoreError::SignedOut)
    }

    async fn connected_connection(&self) -> Option<Connection> {
        let state = self.state.lock().await;
        (state.phase == Phase::Connected)
            .then(|| state.connection.clone())
            .flatten()
    }

    async fn set_phase(&self, phase: Phase) {
        self.state.lock().await.phase = phase;
    }

    async fn retry_start(
        &self,
        access_token: &str,
        request: &ConnectionStartRequest,
    ) -> Result<ConnectionStartResponse, CoreError> {
        let delays = self.retry_policy.delays_millis();
        let mut retry_index = 0;
        loop {
            match self.api.start_connection(access_token, request).await {
                Ok(response) => return Ok(response),
                Err(CoreApiError::Retryable) if retry_index < delays.len() => {
                    let delay = delays[retry_index];
                    retry_index += 1;
                    if delay > 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                    }
                }
                Err(error) => {
                    self.set_phase(phase_for_api_error(&error)).await;
                    return Err(error.into());
                }
            }
        }
    }

    async fn retry_stop(
        &self,
        access_token: &str,
        request: &ConnectionOperationRequest,
    ) -> Result<ConnectionOperationResponse, CoreError> {
        let delays = self.retry_policy.delays_millis();
        let mut retry_index = 0;
        loop {
            match self.api.stop_connection(access_token, request).await {
                Ok(response) => return Ok(response),
                Err(CoreApiError::Retryable) if retry_index < delays.len() => {
                    let delay = delays[retry_index];
                    retry_index += 1;
                    if delay > 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                    }
                }
                Err(error) => {
                    self.set_phase(phase_for_api_error(&error)).await;
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
                    StoredConnectionKind::Pinned | StoredConnectionKind::Fixed => true,
                    StoredConnectionKind::DynamicWarm => saved
                        .valid_until_unix
                        .is_some_and(|expiry| expiry > now_unix),
                }
        })
        .map(|saved| saved.lease_id.clone())
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
        CoreApiError::Rejected { .. } => Phase::Error,
    }
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
}
