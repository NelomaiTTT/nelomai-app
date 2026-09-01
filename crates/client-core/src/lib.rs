use async_trait::async_trait;
use nelomai_client_api::{BackgroundTokenResponse, ClientApi, ClientApiError, TokenResponse};
use nelomai_client_storage::{
    MemorySplitTunnelStore, SecretStore, SplitTunnelStore, StoredCompatibility, StoredConnection,
    StoredConnectionKind, StoredPendingCompensationStop, StoredPendingStalledStop,
    StoredPendingStart,
};
use nelomai_client_tunnel::{
    QuickConnection, QuickReconnect, RedundantTunnelMemberStart, RedundantTunnelStandbyStart,
    RedundantTunnelStart, TunnelConfiguration, TunnelController, TunnelError, TunnelOptions,
    TunnelStartRequest, TunnelStatus, TunnelTransport,
};
use nelomai_contracts::{
    AccessState, Bootstrap, Connection, ConnectionOperationRequest, ConnectionOperationResponse,
    ConnectionStartRequest, ConnectionStartResponse, EgressMode, Layer, LeaseStatus, OperationKind,
    OperationReconcileRequest, OperationReconcileResponse, OperationState, ProbeResult,
    RecoveryContractV2, RedundancyMemberSlot, RedundancyState, RedundantCandidateCommitRequest,
    RedundantRoleRequest, RedundantRoleResponse, RedundantSessionResponse,
    RedundantStandbyAcquireRequest, RedundantStandbyAcquireResponse,
    RedundantStandbyReleaseRequest, RedundantStopRequest, RouteMode, SplitTunnelAddressRuleScope,
    SplitTunnelAddressRuleUpdate, SplitTunnelApplyResult, SplitTunnelPolicy, SplitTunnelRevision,
    SplitTunnelSelectedPackage, SplitTunnelSettingsUpdate, TicConnectionMode,
};
use std::collections::HashSet;
use std::future::Future;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::{Mutex, Notify};
use uuid::Uuid;

mod connection_intent;
mod split_tunnel;

pub use connection_intent::{
    classify_recovery, stall_recovery_plan, ConnectionIntentStatus, IntentGeneration,
    RecoveryDecision, RecoveryPolicyContext, RecoveryTransport, RetrySchedule, StallRecoveryPlan,
    StallTrigger,
};
#[cfg(not(target_os = "android"))]
pub use connection_intent::{ConnectionIntentCoordinator, ConnectionIntentError, StartDisposition};

// AWG retries its handshake after 5 s plus up to 334 ms jitter. Each gate must
// leave room for one protocol-level retransmission before changing strategy.
const INITIAL_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(7);
const UDP_REBIND_TIMEOUT: Duration = Duration::from_millis(3_500);
const POST_REBIND_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(7);
const HANDSHAKE_STATUS_TIMEOUT: Duration = Duration::from_secs(1);
const HANDSHAKE_POLL_INTERVAL: Duration = Duration::from_millis(200);
const PINNED_HANDSHAKE_RETRY_COOLDOWN_SECONDS: i64 = 30;

fn current_unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}

fn pinned_connection_retry_allowed(connection: &StoredConnection, now_unix: i64) -> bool {
    connection
        .valid_until_unix
        .is_none_or(|retry_not_before| retry_not_before <= now_unix)
}

fn pinned_connection_offline_allowed(connection: &StoredConnection) -> bool {
    connection.valid_until_unix.is_none()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandshakeWaitOutcome {
    Established,
    MetricsUnsupported,
    TimedOut,
}

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
    pub layer: Layer,
    pub probe_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
struct ActiveRecoveryEpisode {
    metrics: ConnectionMetricsContext,
    options: ConnectOptions,
    armed: bool,
    stop_operation_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionStartContract {
    Legacy,
    RecoveryV1,
    RecoveryV2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StalledDataPlaneRecovery {
    RebindUdp,
    RestartLocalTunnel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartCancellationEpoch(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StalledDataPlaneRecoveryOutcome {
    Busy,
    Skipped,
    Unsupported,
    Rebound,
    Reconnected,
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
    pub egress_mode: EgressMode,
    pub probes: Vec<ProbeResult>,
    pub allow_alternate: bool,
}

impl ConnectOptions {
    pub fn normalized_for_layer(mut self) -> Self {
        if self.layer == Layer::Stray {
            self.tic_connection_mode = TicConnectionMode::Dynamic;
            self.route_mode = RouteMode::Standalone;
        }
        if self.layer == Layer::Stray || self.route_mode == RouteMode::Standalone {
            self.egress_mode = EgressMode::Ipv4;
        }
        self
    }

    pub fn android_default() -> Self {
        Self {
            layer: Layer::Tic,
            tic_connection_mode: TicConnectionMode::Personal,
            route_mode: RouteMode::ViaTak,
            egress_mode: EgressMode::Ipv4,
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
            egress_mode: EgressMode::Ipv4,
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

    #[test]
    fn stray_never_inherits_personal_tic_preferences() {
        let options = ConnectOptions {
            layer: Layer::Stray,
            tic_connection_mode: TicConnectionMode::Personal,
            route_mode: RouteMode::ViaTak,
            egress_mode: EgressMode::PreferIpv6,
            probes: Vec::new(),
            allow_alternate: true,
        }
        .normalized_for_layer();

        assert_eq!(options.tic_connection_mode, TicConnectionMode::Dynamic);
        assert_eq!(options.route_mode, RouteMode::Standalone);
        assert_eq!(options.egress_mode, EgressMode::Ipv4);
    }

    #[test]
    fn standalone_tic_never_uses_ipv6_egress_pool() {
        let options = ConnectOptions {
            layer: Layer::Tic,
            tic_connection_mode: TicConnectionMode::Dynamic,
            route_mode: RouteMode::Standalone,
            egress_mode: EgressMode::PreferIpv6,
            probes: Vec::new(),
            allow_alternate: true,
        }
        .normalized_for_layer();

        assert_eq!(options.egress_mode, EgressMode::Ipv4);
    }

    #[test]
    fn tic_preferences_are_not_changed_by_normalization() {
        let options = ConnectOptions::android_default().normalized_for_layer();

        assert_eq!(options.layer, Layer::Tic);
        assert_eq!(options.tic_connection_mode, TicConnectionMode::Personal);
        assert_eq!(options.route_mode, RouteMode::ViaTak);
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
    Rejected {
        code: String,
        message: String,
        retry_after_seconds: Option<u64>,
    },
}

impl From<ClientApiError> for CoreApiError {
    fn from(error: ClientApiError) -> Self {
        match error {
            ClientApiError::Transport(_) => Self::Retryable,
            ClientApiError::Api { code, message, .. } if code == "invalid_credentials" => {
                Self::Rejected {
                    code,
                    message,
                    retry_after_seconds: None,
                }
            }
            ClientApiError::Api { status, .. } if status.as_u16() == 401 => Self::Unauthorized,
            ClientApiError::Api { code, .. } if code == "access_expired" => Self::AccessExpired,
            ClientApiError::Api {
                code,
                message,
                retry_after_seconds,
                ..
            } if preserves_structured_recovery_error(&code) => Self::Rejected {
                code,
                message,
                retry_after_seconds,
            },
            ClientApiError::Api { status, .. } if status.is_server_error() => Self::Retryable,
            ClientApiError::Api {
                code,
                message,
                retry_after_seconds,
                ..
            } => Self::Rejected {
                code,
                message,
                retry_after_seconds,
            },
            ClientApiError::InvalidErrorResponse { status } if status.is_server_error() => {
                Self::Retryable
            }
            ClientApiError::InvalidPayload { code }
            | ClientApiError::PayloadTooLarge { code, .. } => Self::Rejected {
                code: code.to_string(),
                message: "Панель вернула некорректные данные split-tunnel.".to_string(),
                retry_after_seconds: None,
            },
            ClientApiError::InvalidBaseUrl(_)
            | ClientApiError::InvalidAppVersion(_)
            | ClientApiError::InvalidErrorResponse { .. } => Self::Rejected {
                code: "invalid_client_api_response".to_string(),
                message: "Панель вернула некорректный ответ.".to_string(),
                retry_after_seconds: None,
            },
        }
    }
}

fn preserves_structured_recovery_error(code: &str) -> bool {
    matches!(
        code,
        "configuration_fetch_failed"
            | "connection_stall_verification_unavailable"
            | "operation_in_progress"
            | "device_operation_busy"
    )
}

#[async_trait]
pub trait CoreApi: Send + Sync {
    fn reset_transport(&self) -> Result<(), CoreApiError> {
        Ok(())
    }

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
    async fn report_redundant_role(
        &self,
        _access_token: &str,
        _request: &RedundantRoleRequest,
    ) -> Result<RedundantRoleResponse, CoreApiError> {
        Err(CoreApiError::Retryable)
    }
    async fn release_redundant_standby(
        &self,
        _access_token: &str,
        _request: &RedundantStandbyReleaseRequest,
    ) -> Result<RedundantSessionResponse, CoreApiError> {
        Err(CoreApiError::Retryable)
    }
    async fn acquire_redundant_standby(
        &self,
        _access_token: &str,
        _request: &RedundantStandbyAcquireRequest,
    ) -> Result<RedundantStandbyAcquireResponse, CoreApiError> {
        Err(CoreApiError::Retryable)
    }
    async fn commit_redundant_candidate(
        &self,
        _access_token: &str,
        _request: &RedundantCandidateCommitRequest,
    ) -> Result<RedundantSessionResponse, CoreApiError> {
        Err(CoreApiError::Retryable)
    }
    async fn stop_redundant_connection(
        &self,
        _access_token: &str,
        _request: &RedundantStopRequest,
    ) -> Result<ConnectionOperationResponse, CoreApiError> {
        Err(CoreApiError::Retryable)
    }
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
    async fn background_token(
        &self,
        _access_token: &str,
    ) -> Result<BackgroundTokenResponse, CoreApiError> {
        Err(CoreApiError::Retryable)
    }
    async fn reconcile_background_operation(
        &self,
        _background_token: &str,
        _request: &OperationReconcileRequest,
    ) -> Result<OperationReconcileResponse, CoreApiError> {
        Err(CoreApiError::Retryable)
    }
    async fn background_report_redundant_role(
        &self,
        _background_token: &str,
        _request: &RedundantRoleRequest,
    ) -> Result<RedundantRoleResponse, CoreApiError> {
        Err(CoreApiError::Retryable)
    }
    async fn background_start_connection(
        &self,
        _background_token: &str,
        _request: &ConnectionStartRequest,
    ) -> Result<ConnectionStartResponse, CoreApiError> {
        Err(CoreApiError::Retryable)
    }
    async fn background_release_redundant_standby(
        &self,
        _background_token: &str,
        _request: &RedundantStandbyReleaseRequest,
    ) -> Result<RedundantSessionResponse, CoreApiError> {
        Err(CoreApiError::Retryable)
    }
    async fn background_acquire_redundant_standby(
        &self,
        _background_token: &str,
        _request: &RedundantStandbyAcquireRequest,
    ) -> Result<RedundantStandbyAcquireResponse, CoreApiError> {
        Err(CoreApiError::Retryable)
    }
    async fn background_commit_redundant_candidate(
        &self,
        _background_token: &str,
        _request: &RedundantCandidateCommitRequest,
    ) -> Result<RedundantSessionResponse, CoreApiError> {
        Err(CoreApiError::Retryable)
    }
    async fn background_stop_redundant_connection(
        &self,
        _background_token: &str,
        _request: &RedundantStopRequest,
    ) -> Result<ConnectionOperationResponse, CoreApiError> {
        Err(CoreApiError::Retryable)
    }
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
    fn reset_transport(&self) -> Result<(), CoreApiError> {
        ClientApi::reset_transport(self).map_err(Into::into)
    }

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

    async fn report_redundant_role(
        &self,
        access_token: &str,
        request: &RedundantRoleRequest,
    ) -> Result<RedundantRoleResponse, CoreApiError> {
        ClientApi::report_redundant_role(self, access_token, request)
            .await
            .map_err(Into::into)
    }

    async fn release_redundant_standby(
        &self,
        access_token: &str,
        request: &RedundantStandbyReleaseRequest,
    ) -> Result<RedundantSessionResponse, CoreApiError> {
        ClientApi::release_redundant_standby(self, access_token, request)
            .await
            .map_err(Into::into)
    }

    async fn acquire_redundant_standby(
        &self,
        access_token: &str,
        request: &RedundantStandbyAcquireRequest,
    ) -> Result<RedundantStandbyAcquireResponse, CoreApiError> {
        ClientApi::acquire_redundant_standby(self, access_token, request)
            .await
            .map_err(Into::into)
    }

    async fn commit_redundant_candidate(
        &self,
        access_token: &str,
        request: &RedundantCandidateCommitRequest,
    ) -> Result<RedundantSessionResponse, CoreApiError> {
        ClientApi::commit_redundant_candidate(self, access_token, request)
            .await
            .map_err(Into::into)
    }

    async fn stop_redundant_connection(
        &self,
        access_token: &str,
        request: &RedundantStopRequest,
    ) -> Result<ConnectionOperationResponse, CoreApiError> {
        ClientApi::stop_redundant_connection(self, access_token, request)
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

    async fn background_token(
        &self,
        access_token: &str,
    ) -> Result<BackgroundTokenResponse, CoreApiError> {
        ClientApi::background_token(self, access_token)
            .await
            .map_err(Into::into)
    }

    async fn reconcile_background_operation(
        &self,
        background_token: &str,
        request: &OperationReconcileRequest,
    ) -> Result<OperationReconcileResponse, CoreApiError> {
        ClientApi::reconcile_background_operation(self, background_token, request)
            .await
            .map_err(Into::into)
    }

    async fn background_report_redundant_role(
        &self,
        background_token: &str,
        request: &RedundantRoleRequest,
    ) -> Result<RedundantRoleResponse, CoreApiError> {
        ClientApi::background_report_redundant_role(self, background_token, request)
            .await
            .map_err(Into::into)
    }

    async fn background_start_connection(
        &self,
        background_token: &str,
        request: &ConnectionStartRequest,
    ) -> Result<ConnectionStartResponse, CoreApiError> {
        ClientApi::background_start_connection(self, background_token, request)
            .await
            .map_err(Into::into)
    }

    async fn background_release_redundant_standby(
        &self,
        background_token: &str,
        request: &RedundantStandbyReleaseRequest,
    ) -> Result<RedundantSessionResponse, CoreApiError> {
        ClientApi::background_release_redundant_standby(self, background_token, request)
            .await
            .map_err(Into::into)
    }

    async fn background_acquire_redundant_standby(
        &self,
        background_token: &str,
        request: &RedundantStandbyAcquireRequest,
    ) -> Result<RedundantStandbyAcquireResponse, CoreApiError> {
        ClientApi::background_acquire_redundant_standby(self, background_token, request)
            .await
            .map_err(Into::into)
    }

    async fn background_commit_redundant_candidate(
        &self,
        background_token: &str,
        request: &RedundantCandidateCommitRequest,
    ) -> Result<RedundantSessionResponse, CoreApiError> {
        ClientApi::background_commit_redundant_candidate(self, background_token, request)
            .await
            .map_err(Into::into)
    }

    async fn background_stop_redundant_connection(
        &self,
        background_token: &str,
        request: &RedundantStopRequest,
    ) -> Result<ConnectionOperationResponse, CoreApiError> {
        ClientApi::background_stop_redundant_connection(self, background_token, request)
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
    #[error("запуск подключения отменён")]
    StartCancelled,
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
    intent_recovery_gate: Mutex<()>,
    start_cancel_epoch: AtomicU64,
    start_in_progress: AtomicBool,
    pending_start_active: AtomicBool,
    start_retry_wake: Notify,
    active_recovery_episode: Mutex<Option<ActiveRecoveryEpisode>>,
    refresh_gate: Mutex<()>,
    connection_gate: Mutex<()>,
    split_tunnel_store: Arc<dyn SplitTunnelStore>,
    split_tunnel_gate: Mutex<()>,
    split_tunnel_packages: RwLock<Vec<SplitTunnelSelectedPackage>>,
    split_tunnel_options: Mutex<TunnelOptions>,
    dns_servers: RwLock<Vec<IpAddr>>,
    split_tunnel_warning: Mutex<SplitTunnelWarnings>,
    physical_network_change: Mutex<split_tunnel::PhysicalNetworkChangeDetector>,
    offline_connection_quarantine: RwLock<HashSet<String>>,
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
        let pending_start_active = store
            .load()
            .ok()
            .flatten()
            .is_some_and(|stored| stored.pending_start.is_some());
        Self {
            api,
            store,
            tunnel,
            logger,
            state: Mutex::new(CoreState::default()),
            intent_recovery_gate: Mutex::new(()),
            start_cancel_epoch: AtomicU64::new(0),
            start_in_progress: AtomicBool::new(false),
            pending_start_active: AtomicBool::new(pending_start_active),
            start_retry_wake: Notify::new(),
            active_recovery_episode: Mutex::new(None),
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
            offline_connection_quarantine: RwLock::new(HashSet::new()),
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

    fn quarantine_offline_connection(&self, lease_id: &str) {
        if let Ok(mut quarantined) = self.offline_connection_quarantine.write() {
            quarantined.insert(lease_id.to_string());
        }
    }

    fn clear_offline_connection_quarantine(&self, lease_id: &str) {
        if let Ok(mut quarantined) = self.offline_connection_quarantine.write() {
            quarantined.remove(lease_id);
        }
    }

    fn clear_all_offline_connection_quarantines(&self) {
        if let Ok(mut quarantined) = self.offline_connection_quarantine.write() {
            quarantined.clear();
        }
    }

    fn offline_connection_is_quarantined(&self, lease_id: &str) -> bool {
        self.offline_connection_quarantine
            .read()
            .map(|quarantined| quarantined.contains(lease_id))
            .unwrap_or(true)
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
        if state.phase == Phase::Connected {
            if let Some(connection) = state.connection {
                return Some(ConnectionMetricsContext {
                    session_id: connection.lease_id,
                    layer: connection.layer,
                    probe_url: connection.probe_url,
                });
            }
            let stored = self.load_auth().ok()?;
            let connection = stored.saved_connection.or(stored.pinned_connection)?;
            return Some(ConnectionMetricsContext {
                session_id: connection.lease_id,
                layer: connection.layer,
                probe_url: connection.probe_url,
            });
        }
        self.active_recovery_episode
            .lock()
            .await
            .as_ref()
            .filter(|episode| episode.armed)
            .map(|episode| episode.metrics.clone())
    }

    pub async fn active_recovery_options(&self) -> Option<ConnectOptions> {
        self.active_recovery_episode
            .lock()
            .await
            .as_ref()
            .map(|episode| episode.options.clone())
    }

    pub fn connection_recovery_transport(
        &self,
        lease_id: &str,
    ) -> Result<RecoveryTransport, CoreError> {
        let stored = self.load_auth()?;
        let saved = stored
            .saved_connection
            .as_ref()
            .into_iter()
            .chain(stored.pinned_connection.as_ref())
            .find(|saved| saved.lease_id == lease_id)
            .ok_or(CoreError::SavedConnectionUnavailable)?;
        Ok(
            if TunnelConfiguration::new(saved.configuration.clone()).transport()
                == TunnelTransport::AmneziaWg3
            {
                RecoveryTransport::AmneziaWg3
            } else {
                RecoveryTransport::Other
            },
        )
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
        let _intent_recovery_guard = self.intent_recovery_gate.lock().await;
        let _split_guard = self.split_tunnel_gate.lock().await;
        let _connection_guard = self.connection_gate.lock().await;
        let _refresh_guard = self.refresh_gate.lock().await;
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
                pending_stalled_stop: None,
                pending_compensation_stop: None,
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
        self.clear_all_offline_connection_quarantines();
        *self.active_recovery_episode.lock().await = None;
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

    pub async fn replace_session_tokens(
        &self,
        access_token: &str,
        refresh_token: &str,
    ) -> Result<(), CoreError> {
        let _guard = self.refresh_gate.lock().await;
        let mut stored = self.load_auth()?;
        stored.access_token = Some(access_token.to_string());
        stored.refresh_token = Some(refresh_token.to_string());
        self.store.save(&stored).map_err(|_| CoreError::Storage)?;
        self.logger.record(CoreLogEvent {
            kind: "auth.background_recovered",
            operation_id: None,
            request_id: None,
            code: None,
        });
        Ok(())
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
        self.complete_bootstrap(response, now_unix).await
    }

    pub async fn bootstrap_without_refresh(&self, now_unix: i64) -> Result<Bootstrap, CoreError> {
        let stored = self.load_auth()?;
        let access_token = stored.access_token.ok_or(CoreError::SignedOut)?;
        let response = match self.api.bootstrap(&access_token).await {
            Ok(response) => response,
            Err(error) => {
                self.set_phase(phase_for_api_error(&error)).await;
                return Err(error.into());
            }
        };
        self.complete_bootstrap(response, now_unix).await
    }

    async fn complete_bootstrap(
        &self,
        response: Bootstrap,
        now_unix: i64,
    ) -> Result<Bootstrap, CoreError> {
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
                self.restore_running_connection_configuration(connection, now_unix)
                    .await;
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

    async fn restore_running_connection_configuration(
        &self,
        connection: &Connection,
        now_unix: i64,
    ) {
        let Ok(stored) = self.load_auth() else {
            return;
        };
        let already_saved = stored
            .saved_connection
            .as_ref()
            .into_iter()
            .chain(stored.pinned_connection.as_ref())
            .any(|saved| saved.lease_id == connection.lease_id);
        if already_saved {
            return;
        }
        let Some(mut access_token) = stored.access_token else {
            return;
        };
        let request = ConnectionStartRequest {
            operation_id: connection.lease_id.clone(),
            layer: connection.layer,
            tic_connection_mode: connection.tic_connection_mode,
            route_mode: connection.route_mode,
            egress_mode: connection.egress_mode,
            probes: Vec::new(),
            allow_alternate: false,
            require_measured_selection: false,
            recovery_contract_version: None,
            redundancy_contract_version: None,
            reserve_enabled: None,
            request_fingerprint: None,
        };
        let mut recovered = self.api.start_connection(&access_token, &request).await;
        if matches!(recovered, Err(CoreApiError::Unauthorized)) {
            recovered = match self.refresh_access_token(&access_token).await {
                Ok(refreshed) => {
                    access_token = refreshed;
                    self.api.start_connection(&access_token, &request).await
                }
                Err(_) => return,
            };
        }
        let Ok(recovered) = recovered else {
            self.logger.record(CoreLogEvent {
                kind: "connection.configuration_restore_failed",
                operation_id: Some(connection.lease_id.clone()),
                request_id: None,
                code: Some("configuration_fetch_failed".to_string()),
            });
            return;
        };
        if recovered.connection.lease_id != connection.lease_id
            || recovered.configuration.is_empty()
        {
            self.logger.record(CoreLogEvent {
                kind: "connection.configuration_restore_failed",
                operation_id: Some(connection.lease_id.clone()),
                request_id: Some(recovered.request_id),
                code: Some("invalid_client_api_response".to_string()),
            });
            return;
        }
        let kind = stored_connection_kind(&recovered.connection);
        let saved_connection = StoredConnection {
            lease_id: recovered.connection.lease_id.clone(),
            pool_id: recovered.connection.pool_id.clone(),
            layer: recovered.connection.layer,
            tic_connection_mode: recovered.connection.tic_connection_mode,
            route_mode: recovered.connection.route_mode,
            egress_mode: recovered.connection.egress_mode,
            probe_url: recovered.connection.probe_url.clone(),
            kind,
            configuration: recovered.configuration,
            valid_until_unix: match kind {
                StoredConnectionKind::DynamicWarm => Some(now_unix.saturating_add(3_600)),
                StoredConnectionKind::Fixed | StoredConnectionKind::Pinned => None,
            },
        };
        let Ok(mut current_stored) = self.load_auth() else {
            return;
        };
        if kind == StoredConnectionKind::Pinned {
            current_stored.pinned_connection = Some(saved_connection);
            current_stored.saved_connection = None;
        } else {
            current_stored.saved_connection = Some(saved_connection);
        }
        if self.store.save(&current_stored).is_err() {
            self.logger.record(CoreLogEvent {
                kind: "connection.configuration_restore_failed",
                operation_id: Some(connection.lease_id.clone()),
                request_id: Some(recovered.request_id),
                code: Some("storage_unavailable".to_string()),
            });
            return;
        }
        self.logger.record(CoreLogEvent {
            kind: "connection.configuration_restored",
            operation_id: Some(connection.lease_id.clone()),
            request_id: Some(recovered.request_id),
            code: None,
        });
    }

    pub async fn start(
        &self,
        options: ConnectOptions,
        now_unix: i64,
    ) -> Result<Connection, CoreError> {
        let cancel_epoch = self.begin_start_attempt();
        let result = self
            .start_with_cancellation_epoch(options, now_unix, cancel_epoch)
            .await;
        self.finish_start_attempt();
        result
    }

    pub async fn start_with_cancellation_epoch(
        &self,
        options: ConnectOptions,
        now_unix: i64,
        cancel_epoch: StartCancellationEpoch,
    ) -> Result<Connection, CoreError> {
        let _intent_recovery_guard = self.intent_recovery_gate.lock().await;
        self.start_internal(
            options,
            now_unix,
            true,
            ConnectionStartContract::Legacy,
            false,
            cancel_epoch,
        )
        .await
    }

    pub async fn start_recovery_v2(
        &self,
        options: ConnectOptions,
        now_unix: i64,
        reserve_enabled: bool,
    ) -> Result<Connection, CoreError> {
        let cancel_epoch = self.begin_start_attempt();
        let result = self
            .start_internal(
                options,
                now_unix,
                true,
                ConnectionStartContract::RecoveryV2,
                reserve_enabled,
                cancel_epoch,
            )
            .await;
        self.finish_start_attempt();
        result
    }

    #[cfg(not(target_os = "android"))]
    pub async fn connection_intent_attempt(
        &self,
        options: ConnectOptions,
        now_unix: i64,
    ) -> Result<Connection, CoreError> {
        let cancel_epoch = self.begin_start_attempt();
        let result = self
            .connection_intent_attempt_with_cancellation_epoch(options, now_unix, cancel_epoch)
            .await;
        self.finish_start_attempt();
        result
    }

    #[cfg(not(target_os = "android"))]
    pub async fn connection_intent_attempt_with_cancellation_epoch(
        &self,
        options: ConnectOptions,
        now_unix: i64,
        cancel_epoch: StartCancellationEpoch,
    ) -> Result<Connection, CoreError> {
        let _intent_recovery_guard = self.intent_recovery_gate.lock().await;
        self.start_internal(
            options,
            now_unix,
            false,
            ConnectionStartContract::RecoveryV1,
            false,
            cancel_epoch,
        )
        .await
    }

    async fn start_internal(
        &self,
        options: ConnectOptions,
        now_unix: i64,
        allow_internal_retry: bool,
        requested_contract: ConnectionStartContract,
        requested_reserve_enabled: bool,
        cancel_epoch: StartCancellationEpoch,
    ) -> Result<Connection, CoreError> {
        let options = options.normalized_for_layer();
        let total_started = Instant::now();
        self.ensure_start_not_cancelled(cancel_epoch)?;
        if let Some(pending) = self.load_auth()?.pending_compensation_stop {
            self.set_phase(Phase::Stopping).await;
            self.resume_pending_compensation_stop(pending).await?;
            self.ensure_start_not_cancelled(cancel_epoch)?;
        }
        let _split_guard = self.split_tunnel_gate.lock().await;
        let _guard = self.connection_gate.lock().await;
        let mut stored = self.load_auth()?;
        if let Some(connection) = self.connected_connection().await {
            return Ok(connection);
        }
        if stored
            .compatibility
            .as_ref()
            .is_some_and(|compatibility| compatibility.update_required)
        {
            self.set_phase(Phase::UpdateRequired).await;
            return Err(CoreError::UpdateRequired);
        }
        if let Some(pending) = stored.pending_start.as_ref() {
            if pending.cancel_operation_id.is_some() {
                self.set_phase(Phase::Stopping).await;
                return Err(unresolved_start_operation_error());
            }
            if !pending_start_matches_options(pending, &options) {
                self.set_phase(Phase::ServerUnavailable).await;
                return Err(unresolved_start_operation_error());
            }
        }
        self.ensure_start_not_cancelled(cancel_epoch)?;
        self.release_stale_panel_connection_before_start(&stored)
            .await?;
        self.ensure_start_not_cancelled(cancel_epoch)?;
        stored = self.load_auth()?;
        if let Some(pending) = stored.pending_start.as_ref() {
            if pending.cancel_operation_id.is_some() {
                self.set_phase(Phase::Stopping).await;
                return Err(unresolved_start_operation_error());
            }
            if !pending_start_matches_options(pending, &options) {
                self.set_phase(Phase::ServerUnavailable).await;
                return Err(unresolved_start_operation_error());
            }
        }
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
        self.ensure_start_not_cancelled(cancel_epoch)?;
        let access_token = stored.access_token.clone().ok_or(CoreError::SignedOut)?;
        let (
            contract,
            operation_id,
            recovery_contract_version,
            redundancy_contract_version,
            reserve_enabled,
            request_fingerprint,
        ) = match stored.pending_start.as_ref() {
            Some(pending) => {
                let (contract, recovery, redundancy, reserve, fingerprint) =
                    pending_start_contract(pending)?;
                (
                    contract,
                    pending.operation_id.clone(),
                    recovery,
                    redundancy,
                    reserve,
                    fingerprint,
                )
            }
            None => {
                let require_measured_selection = matches!(
                    requested_contract,
                    ConnectionStartContract::RecoveryV1 | ConnectionStartContract::RecoveryV2
                ) && (options.layer != Layer::Tic
                    || options.tic_connection_mode == TicConnectionMode::Dynamic);
                let fingerprint = match requested_contract {
                    ConnectionStartContract::Legacy => None,
                    ConnectionStartContract::RecoveryV1 => {
                        Some(connection_intent::request_fingerprint_v1(
                            &options,
                            require_measured_selection,
                        ))
                    }
                    ConnectionStartContract::RecoveryV2 => {
                        Some(connection_intent::request_fingerprint_v2(
                            &options,
                            require_measured_selection,
                            requested_reserve_enabled,
                        ))
                    }
                };
                (
                    requested_contract,
                    if requested_contract == ConnectionStartContract::RecoveryV2 {
                        Uuid::new_v4().to_string()
                    } else {
                        reusable_operation_id(&stored, &options, now_unix)
                            .unwrap_or_else(|| Uuid::new_v4().to_string())
                    },
                    match requested_contract {
                        ConnectionStartContract::Legacy => None,
                        ConnectionStartContract::RecoveryV1 => Some(1),
                        ConnectionStartContract::RecoveryV2 => Some(2),
                    },
                    (requested_contract == ConnectionStartContract::RecoveryV2).then_some(1),
                    (requested_contract == ConnectionStartContract::RecoveryV2)
                        .then_some(requested_reserve_enabled),
                    fingerprint,
                )
            }
        };
        let replay_probes = stored
            .pending_start
            .as_ref()
            .map(|pending| pending.probes.clone())
            .unwrap_or_else(|| options.probes.clone());
        let require_measured_selection = matches!(
            contract,
            ConnectionStartContract::RecoveryV1 | ConnectionStartContract::RecoveryV2
        ) && (options.layer != Layer::Tic
            || options.tic_connection_mode == TicConnectionMode::Dynamic);
        let mut operation_id = operation_id;
        self.logger.record(CoreLogEvent {
            kind: "connection.egress_selected",
            operation_id: Some(operation_id.clone()),
            request_id: None,
            code: Some(
                match options.egress_mode {
                    EgressMode::Ipv4 => "ipv4",
                    EgressMode::PreferIpv6 => "prefer_ipv6",
                }
                .to_string(),
            ),
        });
        let pending_start_created_for_dispatch = stored.pending_start.is_none();
        if pending_start_created_for_dispatch {
            let mut pending_stored = self.load_auth()?;
            pending_stored.pending_start = Some(StoredPendingStart {
                operation_id: operation_id.clone(),
                layer: options.layer,
                tic_connection_mode: options.tic_connection_mode,
                route_mode: options.route_mode,
                egress_mode: options.egress_mode,
                allow_alternate: options.allow_alternate,
                probes: options.probes.clone(),
                recovery_contract_version,
                redundancy_contract_version,
                reserve_enabled,
                request_fingerprint: request_fingerprint.clone(),
                cancel_operation_id: None,
            });
            self.store
                .save(&pending_stored)
                .map_err(|_| CoreError::Storage)?;
        }
        self.pending_start_active.store(true, Ordering::SeqCst);
        self.set_phase(Phase::Connecting).await;
        let mut request = ConnectionStartRequest {
            operation_id: operation_id.clone(),
            layer: options.layer,
            tic_connection_mode: options.tic_connection_mode,
            route_mode: options.route_mode,
            egress_mode: options.egress_mode,
            probes: replay_probes,
            allow_alternate: options.allow_alternate,
            require_measured_selection,
            recovery_contract_version,
            redundancy_contract_version,
            reserve_enabled,
            request_fingerprint,
        };
        let panel_started = Instant::now();
        let start_result = self
            .retry_start(
                &access_token,
                &mut request,
                allow_internal_retry,
                cancel_epoch,
                pending_start_created_for_dispatch,
            )
            .await;
        operation_id.clone_from(&request.operation_id);
        let response = match start_result {
            Ok(response) => response,
            Err(error) => {
                if !start_error_preserves_operation(&error) {
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
        let redundant_session_id = response
            .redundancy
            .as_ref()
            .map(|redundancy| redundancy.session_id.as_str());
        if self.ensure_start_not_cancelled(cancel_epoch).is_err() {
            return Err(self
                .compensate_cancelled_start(
                    &access_token,
                    &response.connection,
                    &response.request_id,
                    &operation_id,
                    redundant_session_id,
                    FailedStartStage::Preparation,
                    false,
                )
                .await);
        }
        if response.connection.layer != options.layer
            || response.connection.tic_connection_mode != options.tic_connection_mode
            || response.connection.route_mode != options.route_mode
            || response.connection.egress_mode != options.egress_mode
        {
            let error = CoreError::Api(CoreApiError::Rejected {
                code: "invalid_client_api_response".to_string(),
                message: "Панель вернула подключение с другими параметрами.".to_string(),
                retry_after_seconds: None,
            });
            let compensation_error = self
                .compensate_failed_start(
                    &access_token,
                    &response.connection,
                    &response.request_id,
                    &operation_id,
                    redundant_session_id,
                    FailedStartStage::Preparation,
                    &error,
                )
                .await
                .err();
            return Err(compensation_error.unwrap_or(error));
        }
        self.logger.record_timed(
            CoreLogEvent {
                kind: "connection.panel_ready",
                operation_id: Some(operation_id.clone()),
                request_id: Some(response.request_id.clone()),
                code: None,
            },
            elapsed_millis(panel_started),
        );
        self.logger.record(CoreLogEvent {
            kind: "connection.pool_selected",
            operation_id: Some(operation_id.clone()),
            request_id: Some(response.request_id.clone()),
            code: Some(
                response
                    .connection
                    .pool_id
                    .clone()
                    .unwrap_or_else(|| "personal".to_string()),
            ),
        });
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
                    let compensation_error = self
                        .compensate_failed_start(
                            &access_token,
                            &response.connection,
                            &response.request_id,
                            &operation_id,
                            redundant_session_id,
                            FailedStartStage::Preparation,
                            &error,
                        )
                        .await
                        .err();
                    return Err(compensation_error.unwrap_or(error));
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
        let redundant_start = match redundant_tunnel_start(
            &response,
            &operation_id,
            request.request_fingerprint.as_deref(),
            request.reserve_enabled,
        ) {
            Ok(start) => start,
            Err(error) => {
                let compensation_error = self
                    .compensate_failed_start(
                        &access_token,
                        &response.connection,
                        &response.request_id,
                        &operation_id,
                        redundant_session_id,
                        FailedStartStage::Preparation,
                        &error,
                    )
                    .await
                    .err();
                return Err(compensation_error.unwrap_or(error));
            }
        };
        let is_redundant = redundant_start.is_some();
        let kind = stored_connection_kind(&response.connection);
        let valid_until_unix = match kind {
            StoredConnectionKind::DynamicWarm => Some(now_unix.saturating_add(3_600)),
            StoredConnectionKind::Fixed | StoredConnectionKind::Pinned => None,
        };
        let saved_connection = (!is_redundant).then(|| StoredConnection {
            lease_id: response.connection.lease_id.clone(),
            pool_id: response.connection.pool_id.clone(),
            layer: response.connection.layer,
            tic_connection_mode: response.connection.tic_connection_mode,
            route_mode: response.connection.route_mode,
            egress_mode: response.connection.egress_mode,
            probe_url: response.connection.probe_url.clone(),
            kind,
            configuration: response.configuration.clone(),
            valid_until_unix,
        });
        // The start request may rotate the tokens after an unauthorized response.
        // Reload before persisting the connection so stale credentials cannot
        // overwrite the freshly rotated session.
        let mut current_stored = self.load_auth()?;
        if let Some(saved_connection) = saved_connection {
            if kind == StoredConnectionKind::Pinned {
                current_stored.pinned_connection = Some(saved_connection);
                current_stored.saved_connection = None;
            } else {
                current_stored.saved_connection = Some(saved_connection);
            }
        } else {
            current_stored.saved_connection = None;
        }
        if self.store.save(&current_stored).is_err() {
            let error = CoreError::Storage;
            let compensation_error = self
                .compensate_failed_start(
                    &access_token,
                    &response.connection,
                    &response.request_id,
                    &operation_id,
                    redundant_session_id,
                    FailedStartStage::Storage,
                    &error,
                )
                .await
                .err();
            return Err(compensation_error.unwrap_or(error));
        }
        let configuration = TunnelConfiguration::new(response.configuration);
        let transport = configuration.transport();
        let local_start_started = Instant::now();
        let local_start_result = self
            .tunnel
            .start(TunnelStartRequest {
                configuration,
                options: tunnel_options.clone(),
                quick_reconnect: match (is_redundant, valid_until_unix) {
                    (true, _) => QuickReconnect::Disabled,
                    (false, Some(valid_until_unix)) => QuickReconnect::Until(valid_until_unix),
                    (false, None) => QuickReconnect::Persistent,
                },
                quick_connection: (!is_redundant).then(|| QuickConnection {
                    lease_id: response.connection.lease_id.clone(),
                    layer: response.connection.layer,
                    tic_connection_mode: response.connection.tic_connection_mode,
                    route_mode: response.connection.route_mode,
                    egress_mode: response.connection.egress_mode,
                    allow_alternate: options.allow_alternate,
                }),
                redundancy: redundant_start,
            })
            .await;
        if self.ensure_start_not_cancelled(cancel_epoch).is_err() {
            return Err(self
                .compensate_cancelled_start(
                    &access_token,
                    &response.connection,
                    &response.request_id,
                    &operation_id,
                    redundant_session_id,
                    FailedStartStage::Local,
                    true,
                )
                .await);
        }
        if let Err(start_error) = local_start_result {
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
            let compensation_error = self
                .compensate_failed_start(
                    &access_token,
                    &response.connection,
                    &response.request_id,
                    &operation_id,
                    redundant_session_id,
                    FailedStartStage::Local,
                    &error,
                )
                .await
                .err();
            return Err(compensation_error.unwrap_or(error));
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
        if transport == TunnelTransport::AmneziaWg3 && !is_redundant {
            let handshake_result = self
                .ensure_awg3_handshake(
                    &operation_id,
                    Some(&response.request_id),
                    Some(cancel_epoch),
                )
                .await;
            if self.ensure_start_not_cancelled(cancel_epoch).is_err() {
                return Err(self
                    .compensate_cancelled_start(
                        &access_token,
                        &response.connection,
                        &response.request_id,
                        &operation_id,
                        redundant_session_id,
                        FailedStartStage::Local,
                        true,
                    )
                    .await);
            }
            if let Err(error) = handshake_result {
                let compensation_error = self
                    .compensate_failed_start(
                        &access_token,
                        &response.connection,
                        &response.request_id,
                        &operation_id,
                        redundant_session_id,
                        FailedStartStage::Local,
                        &error,
                    )
                    .await
                    .err();
                return Err(compensation_error.unwrap_or(error));
            }
        }
        let applied_physical_network_fingerprint = self
            .initialize_physical_network_detector(&tunnel_options)
            .await;
        let mut state = self.state.lock().await;
        if self.ensure_start_not_cancelled(cancel_epoch).is_err() {
            drop(state);
            return Err(self
                .compensate_cancelled_start(
                    &access_token,
                    &response.connection,
                    &response.request_id,
                    &operation_id,
                    redundant_session_id,
                    FailedStartStage::Local,
                    true,
                )
                .await);
        }
        let _ = self.clear_pending_start(&operation_id);
        *state = CoreState {
            phase: Phase::Connected,
            connection: Some(response.connection.clone()),
        };
        drop(state);
        self.clear_offline_connection_quarantine(&response.connection.lease_id);
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

    pub fn begin_start_attempt(&self) -> StartCancellationEpoch {
        self.start_in_progress.store(true, Ordering::SeqCst);
        StartCancellationEpoch(self.start_cancel_epoch.load(Ordering::SeqCst))
    }

    pub fn finish_start_attempt(&self) {
        self.start_in_progress.store(false, Ordering::SeqCst);
    }

    pub fn signal_start_cancellation(&self) -> bool {
        let cancelled = self.start_in_progress.load(Ordering::SeqCst)
            || self.pending_start_active.load(Ordering::SeqCst);
        self.start_cancel_epoch.fetch_add(1, Ordering::SeqCst);
        self.start_retry_wake.notify_waiters();
        cancelled
    }

    fn ensure_start_not_cancelled(
        &self,
        cancel_epoch: StartCancellationEpoch,
    ) -> Result<(), CoreError> {
        if self.start_cancel_epoch.load(Ordering::SeqCst) == cancel_epoch.0 {
            Ok(())
        } else {
            Err(CoreError::StartCancelled)
        }
    }

    pub async fn stop(&self) -> Result<Connection, CoreError> {
        self.signal_start_cancellation();
        let _intent_recovery_guard = self.intent_recovery_gate.lock().await;
        if let Some(pending) = self
            .store
            .load()
            .ok()
            .flatten()
            .and_then(|stored| stored.pending_compensation_stop)
        {
            self.resume_pending_compensation_stop(pending).await?;
            return self
                .state
                .lock()
                .await
                .connection
                .clone()
                .ok_or(CoreError::SavedConnectionUnavailable);
        }
        if self.pending_start_active.load(Ordering::SeqCst) {
            let pending_is_recovery_v2 = self
                .store
                .load()
                .ok()
                .flatten()
                .and_then(|stored| stored.pending_start)
                .is_some_and(|pending| pending.recovery_contract_version == Some(2));
            if pending_is_recovery_v2 {
                return Err(unresolved_start_operation_error());
            }
            let current = self.state.lock().await.connection.clone();
            if let Some(current) = current {
                let accept_warm = stored_connection_accepts_warm(&current);
                let pending = self.pending_compensation_stop_identity(
                    &current.lease_id,
                    accept_warm,
                    None,
                    None,
                )?;
                self.resume_pending_compensation_stop(pending).await?;
                return self
                    .state
                    .lock()
                    .await
                    .connection
                    .clone()
                    .ok_or(CoreError::SavedConnectionUnavailable);
            }
        }
        if self.state.lock().await.connection.is_none() {
            if let Some(connection) = self.cancel_unknown_pending_start().await? {
                return Ok(connection);
            }
        }
        #[cfg(not(target_os = "android"))]
        let pending_stalled_stop = {
            let current_lease_id = self
                .state
                .lock()
                .await
                .connection
                .as_ref()
                .map(|connection| connection.lease_id.clone());
            self.store
                .load()
                .ok()
                .flatten()
                .and_then(|stored| stored.pending_stalled_stop)
                .filter(|pending| current_lease_id.as_deref() == Some(pending.lease_id.as_str()))
        };
        #[cfg(not(target_os = "android"))]
        if let Some(pending) = pending_stalled_stop {
            let stopped = self
                .stop_internal(
                    Some("tunnel_data_plane_stalled"),
                    true,
                    Some(&pending.operation_id),
                    true,
                )
                .await?;
            self.clear_pending_stalled_stop(&pending.operation_id, &pending.lease_id)?;
            return Ok(stopped);
        }
        self.stop_internal(None, true, None, true).await
    }

    #[cfg(not(target_os = "android"))]
    pub async fn reconcile_pending_operation_for_retry(&self) -> Result<(), CoreError> {
        let _intent_recovery_guard = self.intent_recovery_gate.lock().await;
        let stored = self.load_auth()?;
        if let Some(pending) = stored.pending_compensation_stop.clone() {
            return self.resume_pending_compensation_stop(pending).await;
        }
        if let Some(pending) = stored.pending_stalled_stop.clone() {
            return self
                .reconcile_pending_stalled_stop_for_retry(&stored, pending)
                .await;
        }
        let Some(pending) = stored.pending_start.clone() else {
            return Ok(());
        };
        let (contract_version, request_fingerprint) = match (
            pending.recovery_contract_version,
            pending.request_fingerprint.clone(),
        ) {
            (Some(contract_version), Some(request_fingerprint))
                if !request_fingerprint.is_empty() =>
            {
                (contract_version, request_fingerprint)
            }
            (None, None) => return Ok(()),
            _ => return Err(CoreError::Storage),
        };
        let (access_token, reconciliation) = self
            .reconcile_background_operation(
                &stored,
                OperationReconcileRequest {
                    operation_id: pending.operation_id.clone(),
                    kind: OperationKind::Start,
                    contract_version,
                    request_fingerprint,
                    cancel_if_absent: false,
                },
            )
            .await?;
        match reconciliation.state {
            OperationState::Pending | OperationState::Applying | OperationState::Compensating => {
                Err(unresolved_start_operation_retry_error(
                    reconciliation.retry_count,
                ))
            }
            OperationState::NotFound => {
                if reconciliation.lease_id.is_some() || reconciliation.lease_status.is_some() {
                    return Err(invalid_operation_reconcile_response());
                }
                Ok(())
            }
            OperationState::Applied => {
                let lease_id = reconciliation
                    .lease_id
                    .ok_or_else(invalid_operation_reconcile_response)?;
                let lease_status = reconciliation
                    .lease_status
                    .ok_or_else(invalid_operation_reconcile_response)?;
                if terminal_lease_status(lease_status) {
                    return self.clear_pending_start(&pending.operation_id);
                }
                if reconciliation.cancel_requested {
                    self.stop_unknown_pending_lease(
                        &access_token,
                        &pending.operation_id,
                        &lease_id,
                    )
                    .await?;
                }
                Ok(())
            }
            OperationState::Terminal | OperationState::Cancelled => {
                if !reconcile_confirms_terminal_or_absent(
                    reconciliation.lease_id.as_deref(),
                    reconciliation.lease_status,
                ) {
                    return Err(invalid_operation_reconcile_response());
                }
                self.clear_pending_start(&pending.operation_id)
            }
        }
    }

    #[cfg(not(target_os = "android"))]
    async fn reconcile_pending_stalled_stop_for_retry(
        &self,
        stored: &nelomai_client_storage::StoredAuth,
        pending: StoredPendingStalledStop,
    ) -> Result<(), CoreError> {
        if pending.contract_version != 1
            || pending.request_fingerprint
                != connection_intent::stalled_stop_request_fingerprint_v1(&pending.lease_id)
        {
            return Err(CoreError::Storage);
        }
        let (_, reconciliation) = self
            .reconcile_background_operation(
                stored,
                OperationReconcileRequest {
                    operation_id: pending.operation_id.clone(),
                    kind: OperationKind::StalledStop,
                    contract_version: pending.contract_version,
                    request_fingerprint: pending.request_fingerprint.clone(),
                    cancel_if_absent: false,
                },
            )
            .await?;
        if reconciliation
            .lease_id
            .as_deref()
            .is_some_and(|lease_id| lease_id != pending.lease_id)
            || (reconciliation.lease_id.is_none() && reconciliation.lease_status.is_some())
        {
            return Err(invalid_operation_reconcile_response());
        }
        match reconciliation.state {
            OperationState::Pending | OperationState::Applying | OperationState::Compensating => {
                Err(unresolved_start_operation_retry_error(
                    reconciliation.retry_count,
                ))
            }
            OperationState::NotFound => {
                if reconciliation.lease_id.is_some() || reconciliation.lease_status.is_some() {
                    return Err(invalid_operation_reconcile_response());
                }
                Ok(())
            }
            OperationState::Applied | OperationState::Terminal | OperationState::Cancelled => {
                if let Some(lease_status) = reconciliation
                    .lease_status
                    .filter(|status| terminal_lease_status(*status))
                {
                    self.apply_reconciled_stalled_stop_terminal(&pending.lease_id, lease_status)
                        .await?;
                    self.clear_pending_stalled_stop(&pending.operation_id, &pending.lease_id)?;
                    return Ok(());
                }
                Err(stalled_stop_not_recyclable_error())
            }
        }
    }

    async fn resume_pending_compensation_stop(
        &self,
        pending: StoredPendingCompensationStop,
    ) -> Result<(), CoreError> {
        let current = self.state.lock().await.connection.clone();
        if current
            .as_ref()
            .is_some_and(|current| current.lease_id != pending.lease_id)
        {
            return Err(CoreError::Storage);
        }
        let pending = self.migrate_legacy_pending_compensation_stop(pending, current.as_ref())?;
        if pending_compensation_redundant_session(&pending)?.is_some() {
            return self
                .replay_pending_compensation_stop_without_connection(pending)
                .await;
        }
        if current.is_none() {
            return self
                .replay_pending_compensation_stop_without_connection(pending)
                .await;
        }
        let stopped = self
            .stop_internal(
                pending.failure_code.as_deref(),
                true,
                Some(&pending.operation_id),
                pending.accept_warm,
            )
            .await?;
        require_compensation_stop_finished(
            pending.failure_code.as_deref(),
            pending.accept_warm,
            stopped.status,
        )?;
        if pending.failure_code.as_deref() == Some("tunnel_handshake_timeout") {
            self.reconcile_pending_handshake_timeout_storage(&stopped)?;
        }
        self.clear_pending_compensation_stop(&pending.operation_id, &pending.lease_id)
    }

    async fn replay_pending_compensation_stop_without_connection(
        &self,
        pending: StoredPendingCompensationStop,
    ) -> Result<(), CoreError> {
        let _split_guard = self.split_tunnel_gate.lock().await;
        let _guard = self.connection_gate.lock().await;
        self.set_phase(Phase::Stopping).await;
        if !matches!(self.tunnel.status().await, Ok(TunnelStatus::Stopped)) {
            self.tunnel.stop().await?;
        }
        match self.api.reset_transport() {
            Ok(()) => self.logger.record(CoreLogEvent {
                kind: "connection.transport_reset",
                operation_id: None,
                request_id: None,
                code: None,
            }),
            Err(error) => self.logger.record(CoreLogEvent {
                kind: "connection.transport_reset_failed",
                operation_id: None,
                request_id: None,
                code: Some(error.to_string()),
            }),
        }
        self.physical_network_change.lock().await.reset();
        self.clear_applied_physical_network_fingerprint();
        self.clear_split_tunnel_warning(SplitTunnelWarningKind::Operation)
            .await;
        self.clear_split_tunnel_warning(SplitTunnelWarningKind::Runtime)
            .await;

        let stored = self.load_auth()?;
        if stored.pending_compensation_stop.as_ref() != Some(&pending) {
            return Err(CoreError::Storage);
        }
        let access_token = stored.access_token.ok_or(CoreError::SignedOut)?;
        let response = match self.retry_compensation_stop(&access_token, &pending).await {
            Ok(response) => response,
            Err(error) => {
                self.logger.record(CoreLogEvent {
                    kind: "connection.stop_failed",
                    operation_id: Some(pending.operation_id.clone()),
                    request_id: None,
                    code: Some(error.to_string()),
                });
                return Err(error);
            }
        };
        require_compensation_stop_finished(
            pending.failure_code.as_deref(),
            pending.accept_warm,
            response.connection.status,
        )?;
        if pending.failure_code.as_deref() == Some("tunnel_handshake_timeout") {
            self.reconcile_pending_handshake_timeout_storage(&response.connection)?;
        } else if let Some(pending_start) = stored.pending_start {
            self.clear_pending_start(&pending_start.operation_id)?;
        }
        self.clear_pending_compensation_stop(&pending.operation_id, &pending.lease_id)?;
        *self.state.lock().await = CoreState {
            phase: Phase::Ready,
            connection: Some(response.connection.clone()),
        };
        self.logger.record(CoreLogEvent {
            kind: "connection.stopped",
            operation_id: Some(pending.operation_id.clone()),
            request_id: Some(response.request_id),
            code: None,
        });
        Ok(())
    }

    #[cfg(not(target_os = "android"))]
    async fn reconcile_background_operation(
        &self,
        stored: &nelomai_client_storage::StoredAuth,
        request: OperationReconcileRequest,
    ) -> Result<(String, OperationReconcileResponse), CoreError> {
        let mut access_token = stored.access_token.clone().ok_or(CoreError::SignedOut)?;
        let background = match self.api.background_token(&access_token).await {
            Ok(response) => response,
            Err(CoreApiError::Unauthorized) => {
                access_token = self.refresh_access_token(&access_token).await?;
                self.api.background_token(&access_token).await?
            }
            Err(error) => return Err(error.into()),
        };
        let reconciliation = self
            .api
            .reconcile_background_operation(&background.token, &request)
            .await?;
        Ok((access_token, reconciliation))
    }

    #[cfg(not(target_os = "android"))]
    async fn apply_reconciled_stalled_stop_terminal(
        &self,
        lease_id: &str,
        lease_status: LeaseStatus,
    ) -> Result<(), CoreError> {
        let mut state = self.state.lock().await;
        let connection = state
            .connection
            .as_mut()
            .filter(|connection| connection.lease_id == lease_id)
            .ok_or_else(invalid_operation_reconcile_response)?;
        connection.status = lease_status;
        state.phase = Phase::Stopping;
        Ok(())
    }

    async fn cancel_unknown_pending_start(&self) -> Result<Option<Connection>, CoreError> {
        let stored = self.load_auth()?;
        let Some(pending) = stored.pending_start.clone() else {
            return Ok(None);
        };
        self.set_phase(Phase::Stopping).await;
        let (contract_version, request_fingerprint) = match (
            pending.recovery_contract_version,
            pending.request_fingerprint.clone(),
        ) {
            (None, None) => return self.cancel_unknown_legacy_start(stored, pending).await,
            (Some(contract_version), Some(request_fingerprint))
                if !request_fingerprint.is_empty() =>
            {
                (contract_version, request_fingerprint)
            }
            _ => return Err(CoreError::Storage),
        };
        let mut access_token = stored.access_token.ok_or(CoreError::SignedOut)?;
        let background = match self.api.background_token(&access_token).await {
            Ok(response) => response,
            Err(CoreApiError::Unauthorized) => {
                access_token = self.refresh_access_token(&access_token).await?;
                self.api.background_token(&access_token).await?
            }
            Err(error) => return Err(error.into()),
        };
        let reconciliation = self
            .api
            .reconcile_background_operation(
                &background.token,
                &OperationReconcileRequest {
                    operation_id: pending.operation_id.clone(),
                    kind: OperationKind::Start,
                    contract_version,
                    request_fingerprint,
                    cancel_if_absent: true,
                },
            )
            .await?;
        match reconciliation.state {
            OperationState::Pending | OperationState::Applying | OperationState::Compensating => {
                if !reconciliation.cancel_requested {
                    return Err(invalid_operation_reconcile_response());
                }
                Err(unresolved_start_operation_retry_error(
                    reconciliation.retry_count,
                ))
            }
            OperationState::NotFound => {
                if !reconciliation.cancel_requested
                    || reconciliation.lease_id.is_some()
                    || reconciliation.lease_status.is_some()
                {
                    return Err(invalid_operation_reconcile_response());
                }
                self.clear_pending_start(&pending.operation_id)?;
                self.set_phase(Phase::Ready).await;
                Ok(None)
            }
            OperationState::Applied => {
                let lease_id = reconciliation
                    .lease_id
                    .ok_or_else(invalid_operation_reconcile_response)?;
                let lease_status = reconciliation
                    .lease_status
                    .ok_or_else(invalid_operation_reconcile_response)?;
                if terminal_lease_status(lease_status) {
                    self.clear_pending_start(&pending.operation_id)?;
                    self.set_phase(Phase::Ready).await;
                    return Ok(None);
                }
                if !reconciliation.cancel_requested {
                    return Err(invalid_operation_reconcile_response());
                }
                self.stop_unknown_pending_lease(&access_token, &pending.operation_id, &lease_id)
                    .await
                    .map(Some)
            }
            OperationState::Terminal | OperationState::Cancelled => {
                if !reconcile_confirms_terminal_or_absent(
                    reconciliation.lease_id.as_deref(),
                    reconciliation.lease_status,
                ) {
                    return Err(invalid_operation_reconcile_response());
                }
                self.clear_pending_start(&pending.operation_id)?;
                self.set_phase(Phase::Ready).await;
                Ok(None)
            }
        }
    }

    async fn cancel_unknown_legacy_start(
        &self,
        stored: nelomai_client_storage::StoredAuth,
        pending: StoredPendingStart,
    ) -> Result<Option<Connection>, CoreError> {
        let mut access_token = stored.access_token.ok_or(CoreError::SignedOut)?;
        let request = ConnectionStartRequest {
            operation_id: pending.operation_id.clone(),
            layer: pending.layer,
            tic_connection_mode: pending.tic_connection_mode,
            route_mode: pending.route_mode,
            egress_mode: pending.egress_mode,
            probes: pending.probes.clone(),
            allow_alternate: pending.allow_alternate,
            require_measured_selection: false,
            recovery_contract_version: None,
            redundancy_contract_version: None,
            reserve_enabled: None,
            request_fingerprint: None,
        };
        let replay = match self.api.start_connection(&access_token, &request).await {
            Ok(response) => response,
            Err(CoreApiError::Unauthorized) => {
                access_token = self.refresh_access_token(&access_token).await?;
                self.api.start_connection(&access_token, &request).await?
            }
            Err(CoreApiError::Rejected { ref code, .. })
                if code == "connection_no_longer_active" =>
            {
                self.clear_pending_start(&pending.operation_id)?;
                self.set_phase(Phase::Ready).await;
                return Ok(None);
            }
            Err(CoreApiError::Rejected { ref code, .. })
                if legacy_replay_confirms_operation_absent(code) =>
            {
                self.clear_pending_start(&pending.operation_id)?;
                self.set_phase(Phase::Ready).await;
                return Ok(None);
            }
            Err(error @ CoreApiError::Retryable) | Err(error @ CoreApiError::Rejected { .. }) => {
                self.set_phase(Phase::Stopping).await;
                return Err(error.into());
            }
            Err(error) => return Err(error.into()),
        };
        self.stop_unknown_pending_lease(
            &access_token,
            &pending.operation_id,
            &replay.connection.lease_id,
        )
        .await
        .map(Some)
    }

    async fn stop_unknown_pending_lease(
        &self,
        access_token: &str,
        pending_operation_id: &str,
        lease_id: &str,
    ) -> Result<Connection, CoreError> {
        let stop_operation_id = self.pending_cancel_operation_id(pending_operation_id)?;
        let response = match self
            .retry_operation(
                access_token,
                &ConnectionOperationRequest {
                    operation_id: stop_operation_id,
                    lease_id: lease_id.to_string(),
                    failure_code: None,
                },
                ConnectionOperation::Stop,
            )
            .await
        {
            Ok(response) => response,
            Err(error) => {
                self.set_phase(Phase::Stopping).await;
                return Err(error);
            }
        };
        self.clear_pending_start(pending_operation_id)?;
        *self.state.lock().await = CoreState {
            phase: Phase::Ready,
            connection: Some(response.connection.clone()),
        };
        Ok(response.connection)
    }

    async fn stop_internal(
        &self,
        failure_code: Option<&str>,
        clear_recovery_episode: bool,
        operation_id: Option<&str>,
        accept_warm_as_finished: bool,
    ) -> Result<Connection, CoreError> {
        let _split_guard = self.split_tunnel_gate.lock().await;
        let _guard = self.connection_gate.lock().await;
        let current_state = self.state.lock().await.clone();
        let current = current_state
            .connection
            .ok_or(CoreError::SavedConnectionUnavailable)?;
        if clear_recovery_episode {
            *self.active_recovery_episode.lock().await = None;
        }
        let panel_connection_finished = compensation_stop_confirms_finished(
            failure_code,
            accept_warm_as_finished,
            current.status,
        );
        self.set_phase(Phase::Stopping).await;
        let tunnel_status = self.tunnel.status().await.unwrap_or(TunnelStatus::Running);
        if tunnel_status != TunnelStatus::Stopped {
            if let Err(error) = self.tunnel.stop().await {
                self.set_phase(Phase::Stopping).await;
                return Err(error.into());
            }
        }
        match self.api.reset_transport() {
            Ok(()) => self.logger.record(CoreLogEvent {
                kind: "connection.transport_reset",
                operation_id: None,
                request_id: None,
                code: None,
            }),
            Err(error) => self.logger.record(CoreLogEvent {
                kind: "connection.transport_reset_failed",
                operation_id: None,
                request_id: None,
                code: Some(error.to_string()),
            }),
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
            operation_id: operation_id
                .map(str::to_string)
                .unwrap_or_else(|| Uuid::new_v4().to_string()),
            lease_id: current.lease_id.clone(),
            failure_code: failure_code.map(str::to_string),
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
        if !compensation_stop_confirms_finished(
            failure_code,
            accept_warm_as_finished,
            response.connection.status,
        ) {
            *self.state.lock().await = CoreState {
                phase: Phase::Stopping,
                connection: Some(response.connection.clone()),
            };
            return Ok(response.connection);
        }
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

    #[cfg(not(target_os = "android"))]
    pub async fn compensate_stale_connection_intent_result(&self) -> Result<(), CoreError> {
        self.signal_start_cancellation();
        let _intent_recovery_guard = self.intent_recovery_gate.lock().await;
        let current = self.state.lock().await.connection.clone();
        let Some(current) = current else {
            self.clear_pending_compensation_stop_if_absent()?;
            return Ok(());
        };
        let accept_warm = stored_connection_accepts_warm(&current);
        let pending =
            self.pending_compensation_stop_identity(&current.lease_id, accept_warm, None, None)?;
        match self
            .stop_internal(None, true, Some(&pending.operation_id), pending.accept_warm)
            .await
        {
            Ok(stopped)
                if terminal_lease_status(stopped.status)
                    || pending.accept_warm && stopped.status == LeaseStatus::Warm =>
            {
                self.clear_pending_compensation_stop(&pending.operation_id, &pending.lease_id)?;
                Ok(())
            }
            Ok(_) => Err(CoreError::Api(CoreApiError::Rejected {
                code: "connection_release_pending".to_string(),
                message: "Панель ещё не завершила отменённое подключение.".to_string(),
                retry_after_seconds: None,
            })),
            Err(CoreError::SavedConnectionUnavailable) => {
                self.clear_pending_compensation_stop(&pending.operation_id, &pending.lease_id)?;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    #[cfg(not(target_os = "android"))]
    pub async fn replace_stalled_connection(
        &self,
        options: ConnectOptions,
        now_unix: i64,
    ) -> Result<Connection, CoreError> {
        let cancel_epoch = self.begin_start_attempt();
        let result = self
            .replace_stalled_connection_with_cancellation_epoch(options, now_unix, cancel_epoch)
            .await;
        self.finish_start_attempt();
        result
    }

    #[cfg(not(target_os = "android"))]
    pub async fn replace_stalled_connection_with_cancellation_epoch(
        &self,
        options: ConnectOptions,
        now_unix: i64,
        cancel_epoch: StartCancellationEpoch,
    ) -> Result<Connection, CoreError> {
        let _intent_recovery_guard = self.intent_recovery_gate.lock().await;
        self.ensure_start_not_cancelled(cancel_epoch)?;
        let options = options.normalized_for_layer();
        let current = self
            .state
            .lock()
            .await
            .connection
            .clone()
            .ok_or(CoreError::SavedConnectionUnavailable)?;
        let stored = self.load_auth()?;
        let saved = stored
            .saved_connection
            .as_ref()
            .into_iter()
            .chain(stored.pinned_connection.as_ref())
            .find(|saved| saved.lease_id == current.lease_id)
            .ok_or(CoreError::SavedConnectionUnavailable)?;
        let transport = TunnelConfiguration::new(saved.configuration.clone()).transport();
        let recovery_transport = if transport == TunnelTransport::AmneziaWg3 {
            RecoveryTransport::AmneziaWg3
        } else {
            RecoveryTransport::Other
        };
        self.begin_recovery_episode(&current, options.clone()).await;
        let plan = stall_recovery_plan(&options, current.pinned, recovery_transport);
        let already_terminal = terminal_lease_status(current.status);
        let stop_operation_id = match plan {
            StallRecoveryPlan::ReplaceDynamic { .. } if !already_terminal => {
                self.pending_stalled_stop_identity(&current.lease_id)?
                    .operation_id
            }
            StallRecoveryPlan::ReplaceDynamic { .. } | StallRecoveryPlan::PreservePeer => self
                .active_recovery_episode
                .lock()
                .await
                .as_ref()
                .map(|episode| episode.stop_operation_id.clone())
                .ok_or(CoreError::Storage)?,
        };
        let failure_code = match plan {
            StallRecoveryPlan::ReplaceDynamic { failure_code, .. } => Some(failure_code),
            StallRecoveryPlan::PreservePeer => None,
        };
        let stopped = self
            .stop_internal(failure_code, false, Some(&stop_operation_id), true)
            .await?;
        let terminal = match plan {
            StallRecoveryPlan::ReplaceDynamic { .. } => {
                matches!(stopped.status, LeaseStatus::Released | LeaseStatus::Failed)
            }
            StallRecoveryPlan::PreservePeer => matches!(
                stopped.status,
                LeaseStatus::Warm | LeaseStatus::Released | LeaseStatus::Failed
            ),
        };
        if !terminal {
            return Err(CoreError::Api(CoreApiError::Rejected {
                code: "connection_release_failed".to_string(),
                message: "Панель ещё не завершила предыдущее подключение.".to_string(),
                retry_after_seconds: None,
            }));
        }
        if matches!(plan, StallRecoveryPlan::ReplaceDynamic { .. }) {
            self.clear_pending_stalled_stop(&stop_operation_id, &current.lease_id)?;
            self.remove_dynamic_recovery_cache(&current.lease_id)?;
        }
        if let Err(error) = self.ensure_start_not_cancelled(cancel_epoch) {
            *self.active_recovery_episode.lock().await = None;
            return Err(error);
        }
        let mut replacement_options = options;
        if let StallRecoveryPlan::ReplaceDynamic {
            allow_alternate, ..
        } = plan
        {
            replacement_options.allow_alternate = allow_alternate;
        }
        let replacement = self
            .start_internal(
                replacement_options,
                now_unix,
                false,
                ConnectionStartContract::RecoveryV1,
                false,
                cancel_epoch,
            )
            .await;
        if matches!(replacement, Err(CoreError::StartCancelled)) {
            *self.active_recovery_episode.lock().await = None;
        }
        let replacement = replacement?;
        *self.active_recovery_episode.lock().await = None;
        Ok(replacement)
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
            failure_code: None,
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
        self.clear_offline_connection_quarantine(&response.connection.lease_id);
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
            failure_code: None,
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
        self.clear_all_offline_connection_quarantines();
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
                        StoredConnectionKind::Pinned => {
                            pinned_connection_offline_allowed(connection)
                        }
                        StoredConnectionKind::DynamicWarm => connection
                            .valid_until_unix
                            .is_some_and(|expiry| expiry > now_unix),
                        StoredConnectionKind::Fixed => false,
                    }
            })
            .or_else(|| {
                stored.pinned_connection.filter(|connection| {
                    connection.layer == Layer::Stray
                        && pinned_connection_offline_allowed(connection)
                })
            })
            .ok_or(CoreError::SavedConnectionUnavailable)?;
        if self.offline_connection_is_quarantined(&saved.lease_id) {
            self.logger.record(CoreLogEvent {
                kind: "connection.offline_cache_quarantined",
                operation_id: Some(saved.lease_id.clone()),
                request_id: None,
                code: Some("storage_reconciliation_pending".to_string()),
            });
            return Err(CoreError::SavedConnectionUnavailable);
        }
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
        let configuration = TunnelConfiguration::new(saved.configuration.clone());
        let transport = configuration.transport();
        let connection = Connection {
            lease_id: saved.lease_id.clone(),
            pool_id: saved.pool_id.clone(),
            layer: saved.layer,
            transport_protocol: match transport {
                TunnelTransport::WireGuard => nelomai_contracts::TransportProtocol::Wireguard,
                TunnelTransport::AmneziaWg3 => nelomai_contracts::TransportProtocol::Amneziawg3,
            },
            tic_connection_mode: saved.tic_connection_mode,
            route_mode: saved.route_mode,
            egress_mode: saved.egress_mode,
            probe_url: saved.probe_url.clone(),
            status: nelomai_contracts::LeaseStatus::Connected,
            pinned: saved.kind == StoredConnectionKind::Pinned,
            stopped_at: None,
        };
        *self.state.lock().await = CoreState {
            phase: Phase::Connecting,
            connection: Some(connection.clone()),
        };
        if let Err(error) = self
            .tunnel
            .start(TunnelStartRequest {
                configuration,
                options: tunnel_options.clone(),
                quick_reconnect: match (saved.kind, saved.valid_until_unix) {
                    (StoredConnectionKind::DynamicWarm, Some(valid_until_unix)) => {
                        QuickReconnect::Until(valid_until_unix)
                    }
                    _ => QuickReconnect::Persistent,
                },
                quick_connection: Some(QuickConnection {
                    lease_id: saved.lease_id.clone(),
                    layer: saved.layer,
                    tic_connection_mode: saved.tic_connection_mode,
                    route_mode: saved.route_mode,
                    egress_mode: saved.egress_mode,
                    allow_alternate: false,
                }),
                redundancy: None,
            })
            .await
        {
            *self.state.lock().await = CoreState {
                phase: Phase::Ready,
                connection: None,
            };
            return Err(error.into());
        }
        if transport == TunnelTransport::AmneziaWg3 {
            if let Err(error) = self
                .ensure_awg3_handshake(&saved.lease_id, None, None)
                .await
            {
                if let Err(stop_error) = self.tunnel.stop().await {
                    let stop_error = CoreError::from(stop_error);
                    *self.state.lock().await = CoreState {
                        phase: Phase::Stopping,
                        connection: Some(Connection {
                            lease_id: saved.lease_id.clone(),
                            pool_id: saved.pool_id.clone(),
                            layer: saved.layer,
                            transport_protocol: match transport {
                                TunnelTransport::WireGuard => {
                                    nelomai_contracts::TransportProtocol::Wireguard
                                }
                                TunnelTransport::AmneziaWg3 => {
                                    nelomai_contracts::TransportProtocol::Amneziawg3
                                }
                            },
                            tic_connection_mode: saved.tic_connection_mode,
                            route_mode: saved.route_mode,
                            egress_mode: saved.egress_mode,
                            probe_url: saved.probe_url.clone(),
                            status: nelomai_contracts::LeaseStatus::Connected,
                            pinned: saved.kind == StoredConnectionKind::Pinned,
                            stopped_at: None,
                        }),
                    };
                    self.logger.record(CoreLogEvent {
                        kind: "connection.offline_handshake_cleanup_failed",
                        operation_id: Some(saved.lease_id.clone()),
                        request_id: None,
                        code: Some(stop_error.to_string()),
                    });
                    return Err(stop_error);
                }
                *self.state.lock().await = CoreState {
                    phase: Phase::Ready,
                    connection: None,
                };
                let error = if matches!(&error, CoreError::Tunnel(code) if code == "tunnel_handshake_timeout")
                {
                    match self.reconcile_handshake_timeout_storage(&saved.lease_id, &connection) {
                        Ok(()) => error,
                        Err(storage_error) => {
                            self.logger.record(CoreLogEvent {
                                kind: "connection.offline_handshake_storage_failed",
                                operation_id: Some(saved.lease_id.clone()),
                                request_id: None,
                                code: Some(storage_error.to_string()),
                            });
                            storage_error
                        }
                    }
                } else {
                    error
                };
                self.logger.record(CoreLogEvent {
                    kind: "connection.offline_handshake_failed",
                    operation_id: Some(saved.lease_id.clone()),
                    request_id: None,
                    code: Some(error.to_string()),
                });
                return Err(error);
            }
        }
        let applied_physical_network_fingerprint = self
            .initialize_physical_network_detector(&tunnel_options)
            .await;
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
        self.pending_start_active
            .store(stored.pending_start.is_some(), Ordering::SeqCst);
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
        if stored
            .pending_start
            .as_ref()
            .is_some_and(|pending| pending.recovery_contract_version == Some(2))
        {
            // The exact v2 replay returns the session identity needed for a safe stop.
            // Never release one member through the legacy endpoint before that replay.
            return Ok(());
        }
        if !matches!(
            self.tunnel.status().await?,
            TunnelStatus::Stopped | TunnelStatus::Failed
        ) {
            return Ok(());
        }
        let access_token = stored.access_token.clone().ok_or(CoreError::SignedOut)?;
        let accept_warm = stored_connection_accepts_warm(&connection);
        let pending_compensation = stored
            .pending_start
            .as_ref()
            .map(|_| {
                self.pending_compensation_stop_identity(
                    &connection.lease_id,
                    accept_warm,
                    None,
                    None,
                )
            })
            .transpose()?;
        let request = ConnectionOperationRequest {
            operation_id: pending_compensation
                .as_ref()
                .map(|pending| pending.operation_id.clone())
                .unwrap_or_else(|| Uuid::new_v4().to_string()),
            lease_id: connection.lease_id,
            failure_code: None,
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
        require_compensation_stop_finished(None, accept_warm, response.connection.status)?;
        if let Some(pending) = &stored.pending_start {
            self.clear_pending_start(&pending.operation_id)?;
        }
        if let Some(pending) = pending_compensation {
            self.clear_pending_compensation_stop(&pending.operation_id, &pending.lease_id)?;
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
            self.pending_start_active.store(false, Ordering::SeqCst);
        }
        Ok(())
    }

    fn pending_cancel_operation_id(&self, operation_id: &str) -> Result<String, CoreError> {
        let mut stored = self.load_auth()?;
        let pending = stored
            .pending_start
            .as_mut()
            .filter(|pending| pending.operation_id == operation_id)
            .ok_or(CoreError::SavedConnectionUnavailable)?;
        if let Some(cancel_operation_id) = &pending.cancel_operation_id {
            return Ok(cancel_operation_id.clone());
        }
        let cancel_operation_id = Uuid::new_v4().to_string();
        pending.cancel_operation_id = Some(cancel_operation_id.clone());
        self.store.save(&stored).map_err(|_| CoreError::Storage)?;
        Ok(cancel_operation_id)
    }

    #[cfg(not(target_os = "android"))]
    fn pending_stalled_stop_identity(
        &self,
        lease_id: &str,
    ) -> Result<StoredPendingStalledStop, CoreError> {
        let mut stored = self.load_auth()?;
        if let Some(pending) = stored.pending_stalled_stop.as_ref() {
            let expected_fingerprint =
                connection_intent::stalled_stop_request_fingerprint_v1(lease_id);
            if pending.lease_id != lease_id
                || pending.contract_version != 1
                || pending.request_fingerprint != expected_fingerprint
            {
                return Err(CoreError::Storage);
            }
            return Ok(pending.clone());
        }
        let pending = StoredPendingStalledStop {
            operation_id: Uuid::new_v4().to_string(),
            lease_id: lease_id.to_string(),
            contract_version: 1,
            request_fingerprint: connection_intent::stalled_stop_request_fingerprint_v1(lease_id),
        };
        stored.pending_stalled_stop = Some(pending.clone());
        self.store.save(&stored).map_err(|_| CoreError::Storage)?;
        Ok(pending)
    }

    fn pending_compensation_stop_identity(
        &self,
        lease_id: &str,
        accept_warm: bool,
        failure_code: Option<&str>,
        redundant_session_id: Option<&str>,
    ) -> Result<StoredPendingCompensationStop, CoreError> {
        if redundant_session_id.is_some_and(str::is_empty) {
            return Err(CoreError::Storage);
        }
        let recovery_contract_version = redundant_session_id.map(|_| 2);
        let mut stored = self.load_auth()?;
        if let Some(pending) = stored.pending_compensation_stop.as_ref() {
            if pending.lease_id != lease_id
                || pending.recovery_contract_version != recovery_contract_version
                || pending.redundant_session_id.as_deref() != redundant_session_id
                || pending.accept_warm != accept_warm
                || pending.failure_code.as_deref() != failure_code
            {
                return Err(CoreError::Storage);
            }
            return Ok(pending.clone());
        }
        let pending = StoredPendingCompensationStop {
            operation_id: Uuid::new_v4().to_string(),
            lease_id: lease_id.to_string(),
            recovery_contract_version,
            redundant_session_id: redundant_session_id.map(str::to_string),
            accept_warm,
            failure_code: failure_code.map(str::to_string),
        };
        stored.pending_compensation_stop = Some(pending.clone());
        self.store.save(&stored).map_err(|_| CoreError::Storage)?;
        Ok(pending)
    }

    fn migrate_legacy_pending_compensation_stop(
        &self,
        mut pending: StoredPendingCompensationStop,
        current: Option<&Connection>,
    ) -> Result<StoredPendingCompensationStop, CoreError> {
        if pending.accept_warm
            || !matches!(
                pending.failure_code.as_deref(),
                None | Some("tunnel_handshake_timeout")
            )
        {
            return Ok(pending);
        }
        let mut stored = self.load_auth()?;
        let accepts_warm = current
            .map(stored_connection_accepts_warm)
            .unwrap_or_else(|| {
                stored
                    .saved_connection
                    .as_ref()
                    .into_iter()
                    .chain(stored.pinned_connection.as_ref())
                    .find(|connection| connection.lease_id == pending.lease_id)
                    .is_some_and(|connection| connection.kind != StoredConnectionKind::Fixed)
            });
        if !accepts_warm {
            return Ok(pending);
        }
        let stored_pending = stored
            .pending_compensation_stop
            .as_mut()
            .filter(|stored_pending| {
                stored_pending.operation_id == pending.operation_id
                    && stored_pending.lease_id == pending.lease_id
                    && stored_pending.failure_code == pending.failure_code
            })
            .ok_or(CoreError::Storage)?;
        stored_pending.accept_warm = true;
        self.store.save(&stored).map_err(|_| CoreError::Storage)?;
        pending.accept_warm = true;
        Ok(pending)
    }

    fn clear_pending_compensation_stop(
        &self,
        operation_id: &str,
        lease_id: &str,
    ) -> Result<(), CoreError> {
        let mut stored = self.load_auth()?;
        if stored
            .pending_compensation_stop
            .as_ref()
            .is_some_and(|pending| {
                pending.operation_id == operation_id && pending.lease_id == lease_id
            })
        {
            stored.pending_compensation_stop = None;
            self.store.save(&stored).map_err(|_| CoreError::Storage)?;
        }
        Ok(())
    }

    #[cfg(not(target_os = "android"))]
    fn clear_pending_compensation_stop_if_absent(&self) -> Result<(), CoreError> {
        let mut stored = self.load_auth()?;
        if stored.pending_compensation_stop.take().is_some() {
            self.store.save(&stored).map_err(|_| CoreError::Storage)?;
        }
        Ok(())
    }

    #[cfg(not(target_os = "android"))]
    fn clear_pending_stalled_stop(
        &self,
        operation_id: &str,
        lease_id: &str,
    ) -> Result<(), CoreError> {
        let mut stored = self.load_auth()?;
        if stored.pending_stalled_stop.as_ref().is_some_and(|pending| {
            pending.operation_id == operation_id && pending.lease_id == lease_id
        }) {
            stored.pending_stalled_stop = None;
            self.store.save(&stored).map_err(|_| CoreError::Storage)?;
        }
        Ok(())
    }

    async fn begin_recovery_episode(&self, connection: &Connection, options: ConnectOptions) {
        let mut active = self.active_recovery_episode.lock().await;
        if let Some(episode) = active
            .as_mut()
            .filter(|episode| episode.metrics.session_id == connection.lease_id)
        {
            episode.options = options;
            episode.armed = true;
            return;
        }
        *active = Some(ActiveRecoveryEpisode {
            metrics: ConnectionMetricsContext {
                session_id: connection.lease_id.clone(),
                layer: connection.layer,
                probe_url: connection.probe_url.clone(),
            },
            options,
            armed: true,
            stop_operation_id: Uuid::new_v4().to_string(),
        });
    }

    #[cfg(not(target_os = "android"))]
    fn remove_dynamic_recovery_cache(&self, lease_id: &str) -> Result<(), CoreError> {
        let mut stored = self.load_auth()?;
        if stored.saved_connection.as_ref().is_some_and(|saved| {
            saved.lease_id == lease_id && saved.kind == StoredConnectionKind::DynamicWarm
        }) {
            stored.saved_connection = None;
            self.store.save(&stored).map_err(|_| CoreError::Storage)?;
        }
        self.clear_offline_connection_quarantine(lease_id);
        Ok(())
    }

    fn reconcile_handshake_timeout_storage(
        &self,
        operation_id: &str,
        connection: &Connection,
    ) -> Result<(), CoreError> {
        let result = (|| {
            let Some(mut stored) = self.store.load().map_err(|_| CoreError::Storage)? else {
                return Ok(());
            };
            if stored
                .pending_start
                .as_ref()
                .is_some_and(|pending| pending.operation_id == operation_id)
            {
                stored.pending_start = None;
            }
            if connection.pinned {
                let retry_not_before = current_unix_timestamp()
                    .saturating_add(PINNED_HANDSHAKE_RETRY_COOLDOWN_SECONDS);
                for saved in [
                    stored.saved_connection.as_mut(),
                    stored.pinned_connection.as_mut(),
                ]
                .into_iter()
                .flatten()
                {
                    if saved.lease_id == connection.lease_id
                        && saved.kind == StoredConnectionKind::Pinned
                    {
                        saved.valid_until_unix = Some(retry_not_before);
                    }
                }
            } else if stored
                .saved_connection
                .as_ref()
                .is_some_and(|saved| saved.lease_id == connection.lease_id)
            {
                stored.saved_connection = None;
            }
            self.store.save(&stored).map_err(|_| CoreError::Storage)
        })();
        match result {
            Ok(()) => self.clear_offline_connection_quarantine(&connection.lease_id),
            Err(_) => self.quarantine_offline_connection(&connection.lease_id),
        }
        result
    }

    fn reconcile_pending_handshake_timeout_storage(
        &self,
        connection: &Connection,
    ) -> Result<(), CoreError> {
        let pending_operation_id = self
            .load_auth()?
            .pending_start
            .map(|pending| pending.operation_id)
            .unwrap_or_default();
        self.reconcile_handshake_timeout_storage(&pending_operation_id, connection)
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
        pending.cancel_operation_id = None;
        self.store.save(&stored).map_err(|_| CoreError::Storage)
    }

    async fn ensure_awg3_handshake(
        &self,
        operation_id: &str,
        request_id: Option<&str>,
        cancel_epoch: Option<StartCancellationEpoch>,
    ) -> Result<(), CoreError> {
        let handshake_started = Instant::now();
        let event = |kind, code| CoreLogEvent {
            kind,
            operation_id: Some(operation_id.to_string()),
            request_id: request_id.map(str::to_string),
            code,
        };
        let mut initial_metrics_error = None;
        let handshake_outcome = match self
            .wait_for_handshake(INITIAL_HANDSHAKE_TIMEOUT, cancel_epoch)
            .await
        {
            Ok(outcome) => outcome,
            Err(CoreError::StartCancelled) => return Err(CoreError::StartCancelled),
            Err(metrics_error) => {
                self.logger.record(event(
                    "connection.handshake_metrics_failed",
                    Some(metrics_error.to_string()),
                ));
                if !self
                    .tunnel_is_running_after_metrics_failure(cancel_epoch)
                    .await?
                {
                    return Err(metrics_error);
                }
                initial_metrics_error = Some(metrics_error);
                HandshakeWaitOutcome::TimedOut
            }
        };
        match handshake_outcome {
            HandshakeWaitOutcome::Established => {
                self.logger.record_timed(
                    event("connection.handshake_established", None),
                    elapsed_millis(handshake_started),
                );
                return Ok(());
            }
            HandshakeWaitOutcome::MetricsUnsupported => {
                self.logger.record(event(
                    "connection.handshake_gate_skipped",
                    Some("metrics_unsupported".to_string()),
                ));
                return Ok(());
            }
            HandshakeWaitOutcome::TimedOut if initial_metrics_error.is_none() => {
                self.logger.record_timed(
                    event(
                        "connection.handshake_wait_timed_out",
                        Some("initial".to_string()),
                    ),
                    elapsed_millis(handshake_started),
                )
            }
            HandshakeWaitOutcome::TimedOut => {}
        }

        let mut rebind_error = None;
        let rebind_result = self
            .await_with_start_cancellation(
                cancel_epoch,
                tokio::time::timeout(UDP_REBIND_TIMEOUT, self.tunnel.rebind_udp()),
            )
            .await?;
        let rebound = match rebind_result {
            Ok(Ok(rebound)) => rebound,
            Ok(Err(error)) => {
                let error = CoreError::from(error);
                self.logger.record(event(
                    "connection.udp_rebind_failed",
                    Some(error.to_string()),
                ));
                rebind_error = Some(error);
                false
            }
            Err(_) => {
                let error = CoreError::Tunnel("udp_rebind_timeout".to_string());
                self.logger.record(event(
                    "connection.udp_rebind_failed",
                    Some(error.to_string()),
                ));
                rebind_error = Some(error);
                false
            }
        };
        if rebound {
            self.logger.record(event("connection.udp_rebound", None));
        }
        let rebound_started = Instant::now();
        let recovered = if rebound {
            match self
                .wait_for_handshake(POST_REBIND_HANDSHAKE_TIMEOUT, cancel_epoch)
                .await
            {
                Ok(HandshakeWaitOutcome::Established) => true,
                Ok(HandshakeWaitOutcome::TimedOut) => false,
                Ok(HandshakeWaitOutcome::MetricsUnsupported) => {
                    self.logger.record(event(
                        "connection.handshake_gate_skipped",
                        Some("metrics_unsupported_after_rebind".to_string()),
                    ));
                    return Ok(());
                }
                Err(CoreError::StartCancelled) => return Err(CoreError::StartCancelled),
                Err(metrics_error) => {
                    self.logger.record(event(
                        "connection.handshake_metrics_failed",
                        Some(metrics_error.to_string()),
                    ));
                    return Err(metrics_error);
                }
            }
        } else {
            false
        };
        if recovered {
            self.logger.record_timed(
                event("connection.handshake_recovered", None),
                elapsed_millis(rebound_started),
            );
            return Ok(());
        }

        if let Some(error) = rebind_error {
            self.logger.record_timed(
                event("connection.handshake_failed", Some(error.to_string())),
                elapsed_millis(handshake_started),
            );
            return Err(error);
        }
        if !rebound {
            if let Some(error) = initial_metrics_error {
                self.logger.record_timed(
                    event("connection.handshake_failed", Some(error.to_string())),
                    elapsed_millis(handshake_started),
                );
                return Err(error);
            }
        }

        self.logger.record_timed(
            event(
                "connection.handshake_failed",
                Some("tunnel_handshake_timeout".to_string()),
            ),
            elapsed_millis(handshake_started),
        );
        Err(CoreError::Tunnel("tunnel_handshake_timeout".to_string()))
    }

    async fn tunnel_is_running_after_metrics_failure(
        &self,
        cancel_epoch: Option<StartCancellationEpoch>,
    ) -> Result<bool, CoreError> {
        Ok(matches!(
            self.await_with_start_cancellation(
                cancel_epoch,
                tokio::time::timeout(HANDSHAKE_STATUS_TIMEOUT, self.tunnel.status()),
            )
            .await?,
            Ok(Ok(TunnelStatus::Running))
        ))
    }

    async fn wait_for_handshake(
        &self,
        timeout: Duration,
        cancel_epoch: Option<StartCancellationEpoch>,
    ) -> Result<HandshakeWaitOutcome, CoreError> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut last_metrics_error = None;
        loop {
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            let metrics = match self
                .await_with_start_cancellation(
                    cancel_epoch,
                    tokio::time::timeout_at(deadline, self.tunnel.metrics(false)),
                )
                .await?
            {
                Ok(metrics) => metrics,
                Err(_) => {
                    last_metrics_error =
                        Some(CoreError::Tunnel("tunnel_metrics_timeout".to_string()));
                    break;
                }
            };
            match metrics {
                Ok(Some(metrics))
                    if metrics
                        .latest_handshake_epoch_millis
                        .is_some_and(|timestamp| timestamp > 0) =>
                {
                    return Ok(HandshakeWaitOutcome::Established);
                }
                Ok(Some(_)) => {
                    last_metrics_error = None;
                }
                Ok(None) => return Ok(HandshakeWaitOutcome::MetricsUnsupported),
                Err(TunnelError::Backend(code))
                    if matches!(
                        code.as_str(),
                        "metrics_unavailable" | "metrics_not_supported"
                    ) =>
                {
                    return Ok(HandshakeWaitOutcome::MetricsUnsupported);
                }
                Err(error) => last_metrics_error = Some(CoreError::from(error)),
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            self.await_with_start_cancellation(
                cancel_epoch,
                tokio::time::sleep(
                    HANDSHAKE_POLL_INTERVAL
                        .min(deadline.saturating_duration_since(tokio::time::Instant::now())),
                ),
            )
            .await?;
        }
        if let Some(error) = last_metrics_error {
            Err(error)
        } else {
            Ok(HandshakeWaitOutcome::TimedOut)
        }
    }

    async fn await_with_start_cancellation<Output, F>(
        &self,
        cancel_epoch: Option<StartCancellationEpoch>,
        future: F,
    ) -> Result<Output, CoreError>
    where
        F: Future<Output = Output>,
    {
        let Some(cancel_epoch) = cancel_epoch else {
            return Ok(future.await);
        };
        tokio::pin!(future);
        loop {
            let notified = self.start_retry_wake.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            self.ensure_start_not_cancelled(cancel_epoch)?;
            tokio::select! {
                output = &mut future => {
                    self.ensure_start_not_cancelled(cancel_epoch)?;
                    return Ok(output);
                }
                _ = &mut notified => {
                    self.ensure_start_not_cancelled(cancel_epoch)?;
                }
            }
        }
    }

    async fn compensate_failed_start(
        &self,
        access_token: &str,
        connection: &Connection,
        request_id: &str,
        operation_id: &str,
        redundant_session_id: Option<&str>,
        stage: FailedStartStage,
        error: &CoreError,
    ) -> Result<(), CoreError> {
        self.physical_network_change.lock().await.reset();
        let failure_code = match error {
            CoreError::Tunnel(code) if code == "tunnel_handshake_timeout" => Some(code.clone()),
            _ => None,
        };
        let mut storage_error = None;
        let accept_warm = stored_connection_accepts_warm(connection);
        let durable_compensation = match self.pending_compensation_stop_identity(
            &connection.lease_id,
            accept_warm,
            failure_code.as_deref(),
            redundant_session_id,
        ) {
            Ok(pending) => pending,
            Err(storage_error) => {
                let mut phase = phase_for_start_error(&storage_error);
                if stage.local_start_may_be_incomplete()
                    && !matches!(self.tunnel.status().await, Ok(TunnelStatus::Stopped))
                {
                    phase = Phase::Stopping;
                }
                *self.state.lock().await = CoreState {
                    phase,
                    connection: Some(connection.clone()),
                };
                self.logger.record(CoreLogEvent {
                    kind: stage.log_kind(),
                    operation_id: Some(operation_id.to_string()),
                    request_id: Some(request_id.to_string()),
                    code: Some(error.to_string()),
                });
                self.logger.record(CoreLogEvent {
                    kind: "connection.start_compensation_storage_failed",
                    operation_id: Some(operation_id.to_string()),
                    request_id: Some(request_id.to_string()),
                    code: Some(storage_error.to_string()),
                });
                return Err(storage_error);
            }
        };
        if stage.local_start_may_be_incomplete()
            && !matches!(self.tunnel.status().await, Ok(TunnelStatus::Stopped))
        {
            if let Err(cleanup_error) = self.tunnel.stop().await.map_err(CoreError::from) {
                *self.state.lock().await = CoreState {
                    phase: Phase::Stopping,
                    connection: Some(connection.clone()),
                };
                if matches!(error, CoreError::StartCancelled) {
                    self.logger.record(CoreLogEvent {
                        kind: "connection.cancelled_start_cleanup_failed",
                        operation_id: Some(operation_id.to_string()),
                        request_id: Some(request_id.to_string()),
                        code: Some(cleanup_error.to_string()),
                    });
                } else if matches!(error, CoreError::Tunnel(code) if code == "tunnel_handshake_timeout")
                {
                    self.logger.record(CoreLogEvent {
                        kind: "connection.handshake_cleanup_failed",
                        operation_id: Some(operation_id.to_string()),
                        request_id: Some(request_id.to_string()),
                        code: Some(cleanup_error.to_string()),
                    });
                }
                self.logger.record(CoreLogEvent {
                    kind: stage.log_kind(),
                    operation_id: Some(operation_id.to_string()),
                    request_id: Some(request_id.to_string()),
                    code: Some(error.to_string()),
                });
                return Err(cleanup_error);
            }
        }
        let (connection, mut phase) = match self
            .retry_compensation_stop(access_token, &durable_compensation)
            .await
        {
            Ok(compensation) => {
                let authoritative = compensation_stop_confirms_finished(
                    durable_compensation.failure_code.as_deref(),
                    durable_compensation.accept_warm,
                    compensation.connection.status,
                );
                if !authoritative {
                    let compensation_error = compensation_stop_not_terminal_error();
                    *self.state.lock().await = CoreState {
                        phase: Phase::Stopping,
                        connection: Some(compensation.connection),
                    };
                    self.logger.record(CoreLogEvent {
                        kind: "connection.start_compensation_failed",
                        operation_id: Some(durable_compensation.operation_id.clone()),
                        request_id: None,
                        code: Some(compensation_error.to_string()),
                    });
                    self.logger.record(CoreLogEvent {
                        kind: stage.log_kind(),
                        operation_id: Some(operation_id.to_string()),
                        request_id: Some(request_id.to_string()),
                        code: Some(error.to_string()),
                    });
                    return Err(compensation_error);
                }
                if matches!(error, CoreError::Tunnel(code) if code == "tunnel_handshake_timeout") {
                    storage_error = self
                        .reconcile_handshake_timeout_storage(operation_id, connection)
                        .err();
                } else {
                    storage_error =
                        storage_error.or_else(|| self.clear_pending_start(operation_id).err());
                }
                if storage_error.is_none() {
                    storage_error = self
                        .clear_pending_compensation_stop(
                            &durable_compensation.operation_id,
                            &durable_compensation.lease_id,
                        )
                        .err();
                }
                (compensation.connection, phase_for_start_error(error))
            }
            Err(compensation_error) => {
                self.logger.record(CoreLogEvent {
                    kind: "connection.start_compensation_failed",
                    operation_id: Some(durable_compensation.operation_id.clone()),
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
        if let Some(storage_error) = storage_error {
            self.logger.record(CoreLogEvent {
                kind: "connection.start_compensation_storage_failed",
                operation_id: Some(operation_id.to_string()),
                request_id: Some(request_id.to_string()),
                code: Some(storage_error.to_string()),
            });
            return Err(storage_error);
        }
        Ok(())
    }

    async fn compensate_cancelled_start(
        &self,
        access_token: &str,
        connection: &Connection,
        request_id: &str,
        operation_id: &str,
        redundant_session_id: Option<&str>,
        stage: FailedStartStage,
        _local_runtime_may_be_up: bool,
    ) -> CoreError {
        let cancellation_error = CoreError::StartCancelled;
        let compensation_error = self
            .compensate_failed_start(
                access_token,
                connection,
                request_id,
                operation_id,
                redundant_session_id,
                stage,
                &cancellation_error,
            )
            .await
            .err();
        compensation_error.unwrap_or(cancellation_error)
    }

    async fn retry_start(
        &self,
        access_token: &str,
        request: &mut ConnectionStartRequest,
        allow_internal_retry: bool,
        cancel_epoch: StartCancellationEpoch,
        clear_fresh_pending_on_pre_dispatch_cancel: bool,
    ) -> Result<ConnectionStartResponse, CoreError> {
        let delays = if allow_internal_retry {
            self.retry_policy.delays_millis()
        } else {
            Vec::new()
        };
        let mut retry_index = 0;
        let mut access_token = access_token.to_string();
        let mut refreshed = false;
        let mut replaced_finished_operation = false;
        let mut dispatched = false;
        loop {
            if self.start_cancel_epoch.load(Ordering::SeqCst) != cancel_epoch.0 {
                if clear_fresh_pending_on_pre_dispatch_cancel && !dispatched {
                    self.clear_pending_start(&request.operation_id)?;
                }
                return Err(CoreError::StartCancelled);
            }
            dispatched = true;
            match self.api.start_connection(&access_token, request).await {
                Ok(response) => return Ok(response),
                Err(CoreApiError::Unauthorized) if !refreshed => {
                    access_token = self.refresh_access_token(&access_token).await?;
                    refreshed = true;
                }
                Err(CoreApiError::Retryable) if retry_index < delays.len() => {
                    let delay = delays[retry_index];
                    retry_index += 1;
                    self.wait_for_start_retry(delay, cancel_epoch).await?;
                }
                Err(CoreApiError::Rejected { ref code, .. })
                    if allow_internal_retry
                        && code == "connection_no_longer_active"
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
                Err(error) if allow_internal_retry && retry_index < delays.len() => {
                    let Some(server_delay) = structured_retry_delay_millis(&error) else {
                        self.set_phase(phase_for_api_error(&error)).await;
                        return Err(error.into());
                    };
                    let delay = delays[retry_index].max(server_delay);
                    retry_index += 1;
                    self.wait_for_start_retry(delay, cancel_epoch).await?;
                }
                Err(error) => {
                    self.set_phase(phase_for_api_error(&error)).await;
                    return Err(error.into());
                }
            }
        }
    }

    async fn wait_for_start_retry(
        &self,
        delay_millis: u64,
        cancel_epoch: StartCancellationEpoch,
    ) -> Result<(), CoreError> {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(delay_millis);
        loop {
            let notified = self.start_retry_wake.notified();
            tokio::pin!(notified);
            if self.start_cancel_epoch.load(Ordering::SeqCst) != cancel_epoch.0 {
                return Err(CoreError::StartCancelled);
            }
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {
                    return if self.start_cancel_epoch.load(Ordering::SeqCst) == cancel_epoch.0 {
                        Ok(())
                    } else {
                        Err(CoreError::StartCancelled)
                    };
                }
                _ = &mut notified => {}
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

    async fn retry_compensation_stop(
        &self,
        access_token: &str,
        pending: &StoredPendingCompensationStop,
    ) -> Result<ConnectionOperationResponse, CoreError> {
        let Some(session_id) = pending_compensation_redundant_session(pending)? else {
            return self
                .retry_operation(
                    access_token,
                    &ConnectionOperationRequest {
                        operation_id: pending.operation_id.clone(),
                        lease_id: pending.lease_id.clone(),
                        failure_code: pending.failure_code.clone(),
                    },
                    ConnectionOperation::Stop,
                )
                .await;
        };
        let request = RedundantStopRequest {
            operation_id: pending.operation_id.clone(),
            lease_id: pending.lease_id.clone(),
            recovery_contract_version: RecoveryContractV2,
            session_id: session_id.to_string(),
        };
        let delays = self.retry_policy.delays_millis();
        let mut retry_index = 0;
        let mut access_token = access_token.to_string();
        let mut refreshed = false;
        loop {
            match self
                .api
                .stop_redundant_connection(&access_token, &request)
                .await
            {
                Ok(response) => return Ok(response),
                Err(CoreApiError::Unauthorized) if !refreshed => {
                    access_token = self.refresh_access_token(&access_token).await?;
                    refreshed = true;
                }
                Err(CoreApiError::Retryable) if retry_index < delays.len() => {
                    let delay = delays[retry_index];
                    retry_index += 1;
                    if delay > 0 {
                        tokio::time::sleep(Duration::from_millis(delay)).await;
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
                && saved.egress_mode == options.egress_mode
                && match saved.kind {
                    StoredConnectionKind::Pinned => {
                        pinned_connection_retry_allowed(saved, now_unix)
                    }
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
                    && saved.egress_mode == options.egress_mode
                    && pinned_connection_retry_allowed(saved, now_unix)
            })
        })
        .map(|saved| saved.lease_id.clone())
}

fn pending_compensation_redundant_session(
    pending: &StoredPendingCompensationStop,
) -> Result<Option<&str>, CoreError> {
    match (
        pending.recovery_contract_version,
        pending.redundant_session_id.as_deref(),
    ) {
        (None, None) => Ok(None),
        (Some(2), Some(session_id)) if !session_id.is_empty() => Ok(Some(session_id)),
        _ => Err(CoreError::Storage),
    }
}

fn pending_start_matches_options(pending: &StoredPendingStart, options: &ConnectOptions) -> bool {
    pending.layer == options.layer
        && pending.tic_connection_mode == options.tic_connection_mode
        && pending.route_mode == options.route_mode
        && pending.egress_mode == options.egress_mode
        && pending.allow_alternate == options.allow_alternate
}

fn pending_start_contract(
    pending: &StoredPendingStart,
) -> Result<
    (
        ConnectionStartContract,
        Option<u32>,
        Option<u32>,
        Option<bool>,
        Option<String>,
    ),
    CoreError,
> {
    match (
        pending.recovery_contract_version,
        pending.redundancy_contract_version,
        pending.reserve_enabled,
        pending.request_fingerprint.as_ref(),
    ) {
        (None, None, None, None) => Ok((ConnectionStartContract::Legacy, None, None, None, None)),
        (Some(1), None, None, Some(fingerprint)) if !fingerprint.is_empty() => Ok((
            ConnectionStartContract::RecoveryV1,
            Some(1),
            None,
            None,
            Some(fingerprint.clone()),
        )),
        (Some(2), Some(1), Some(reserve_enabled), Some(fingerprint)) if !fingerprint.is_empty() => {
            Ok((
                ConnectionStartContract::RecoveryV2,
                Some(2),
                Some(1),
                Some(reserve_enabled),
                Some(fingerprint.clone()),
            ))
        }
        _ => Err(CoreError::Storage),
    }
}

fn unresolved_start_operation_error() -> CoreError {
    unresolved_start_operation_error_after(1)
}

fn unresolved_start_operation_retry_error(retry_count: u32) -> CoreError {
    let retry_index = usize::try_from(retry_count).unwrap_or(usize::MAX);
    let retry_after_seconds = RetrySchedule::default().delay_seconds(retry_index).max(1);
    unresolved_start_operation_error_after(retry_after_seconds)
}

fn unresolved_start_operation_error_after(retry_after_seconds: u64) -> CoreError {
    CoreError::Api(CoreApiError::Rejected {
        code: "operation_in_progress".to_string(),
        message: "Предыдущее подключение ещё не завершено.".to_string(),
        retry_after_seconds: Some(retry_after_seconds),
    })
}

fn invalid_operation_reconcile_response() -> CoreError {
    CoreError::Api(CoreApiError::Rejected {
        code: "invalid_client_api_response".to_string(),
        message: "Панель вернула некорректное состояние операции подключения.".to_string(),
        retry_after_seconds: None,
    })
}

fn stalled_stop_not_recyclable_error() -> CoreError {
    CoreError::Api(CoreApiError::Rejected {
        code: "connection_stall_not_recyclable".to_string(),
        message: "Панель не подтвердила завершение stalled подключения.".to_string(),
        retry_after_seconds: None,
    })
}

fn compensation_stop_not_terminal_error() -> CoreError {
    CoreError::Api(CoreApiError::Rejected {
        code: "connection_release_pending".to_string(),
        message: "Панель ещё не завершила отменённое подключение.".to_string(),
        retry_after_seconds: None,
    })
}

fn terminal_lease_status(status: LeaseStatus) -> bool {
    matches!(status, LeaseStatus::Released | LeaseStatus::Failed)
}

fn compensation_stop_confirms_finished(
    failure_code: Option<&str>,
    accept_warm: bool,
    status: LeaseStatus,
) -> bool {
    terminal_lease_status(status)
        || (matches!(failure_code, None | Some("tunnel_handshake_timeout"))
            && accept_warm
            && status == LeaseStatus::Warm)
}

fn require_compensation_stop_finished(
    failure_code: Option<&str>,
    accept_warm: bool,
    status: LeaseStatus,
) -> Result<(), CoreError> {
    if compensation_stop_confirms_finished(failure_code, accept_warm, status) {
        Ok(())
    } else {
        Err(compensation_stop_not_terminal_error())
    }
}

fn reconcile_confirms_terminal_or_absent(
    lease_id: Option<&str>,
    lease_status: Option<LeaseStatus>,
) -> bool {
    match (lease_id, lease_status) {
        (None, None) => true,
        (Some(_), Some(status)) => terminal_lease_status(status),
        _ => false,
    }
}

fn legacy_replay_confirms_operation_absent(code: &str) -> bool {
    matches!(
        code,
        "probe_results_required"
            | "invalid_probe_results"
            | "duplicate_candidate"
            | "stale_probe_result"
            | "invalid_probe_result"
            | "invalid_candidate"
            | "candidate_expired"
            | "candidate_unavailable"
    )
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

fn stored_connection_accepts_warm(connection: &Connection) -> bool {
    stored_connection_kind(connection) != StoredConnectionKind::Fixed
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
        CoreError::StartCancelled => Phase::Ready,
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

fn start_error_preserves_operation(error: &CoreError) -> bool {
    match error {
        CoreError::StartCancelled => true,
        CoreError::Api(CoreApiError::Retryable) => {
            classify_recovery("transport_error", RecoveryPolicyContext::default())
                .preserves_operation()
        }
        CoreError::Api(CoreApiError::Rejected {
            code,
            retry_after_seconds,
            ..
        }) => classify_recovery(
            code,
            RecoveryPolicyContext {
                retry_after_seconds: *retry_after_seconds,
                ..RecoveryPolicyContext::default()
            },
        )
        .preserves_operation(),
        _ => false,
    }
}

fn structured_retry_delay_millis(error: &CoreApiError) -> Option<u64> {
    let CoreApiError::Rejected {
        code,
        retry_after_seconds,
        ..
    } = error
    else {
        return None;
    };
    let RecoveryDecision::RetryAfter(delay_seconds) = classify_recovery(
        code,
        RecoveryPolicyContext {
            retry_after_seconds: *retry_after_seconds,
            ..RecoveryPolicyContext::default()
        },
    ) else {
        return None;
    };
    Some(delay_seconds.saturating_mul(1_000))
}

fn transient_start_rejection(code: &str) -> bool {
    code == "configuration_fetch_failed"
}

fn redundant_tunnel_start(
    response: &ConnectionStartResponse,
    operation_id: &str,
    request_fingerprint: Option<&str>,
    reserve_enabled: Option<bool>,
) -> Result<Option<RedundantTunnelStart>, CoreError> {
    let Some(redundancy) = response.redundancy.as_ref() else {
        return Ok(None);
    };
    let Some(request_fingerprint) = request_fingerprint.filter(|value| value.len() == 64) else {
        return Err(CoreError::Api(CoreApiError::Rejected {
            code: "invalid_client_api_response".to_string(),
            message: "Панель вернула резервную сессию без отпечатка операции.".to_string(),
            retry_after_seconds: None,
        }));
    };
    let Some(reserve_enabled) = reserve_enabled else {
        return Err(CoreError::Api(CoreApiError::Rejected {
            code: "invalid_client_api_response".to_string(),
            message: "Панель вернула резервную сессию без исходного режима резерва.".to_string(),
            retry_after_seconds: None,
        }));
    };
    let primary_probe = response.health_probe.clone();
    if redundancy.state != RedundancyState::Disabled && primary_probe.is_none() {
        return Err(CoreError::Api(CoreApiError::Rejected {
            code: "invalid_client_api_response".to_string(),
            message: "Панель не вернула проверку основного подключения.".to_string(),
            retry_after_seconds: None,
        }));
    }
    if redundancy.state == RedundancyState::Disabled
        && (redundancy.standby_desired || redundancy.standby.is_some())
    {
        return Err(CoreError::Api(CoreApiError::Rejected {
            code: "invalid_client_api_response".to_string(),
            message: "Панель вернула противоречивую отключённую резервную сессию.".to_string(),
            retry_after_seconds: None,
        }));
    }
    let standby = redundancy
        .standby
        .as_ref()
        .map(|member| RedundantTunnelStandbyStart {
            member: RedundantTunnelMemberStart {
                slot: RedundancyMemberSlot::B,
                lease_id: member.connection.lease_id.clone(),
                health_probe: Some(member.health_probe.clone()),
            },
            configuration: TunnelConfiguration::new(member.configuration.clone()),
        });
    Ok(Some(RedundantTunnelStart {
        session_id: redundancy.session_id.clone(),
        operation_id: operation_id.to_string(),
        request_fingerprint: request_fingerprint.to_string(),
        reserve_enabled,
        virtual_address_v4: redundancy.virtual_address_v4.clone(),
        standby_desired: redundancy.standby_desired,
        active_lease_id: response.connection.lease_id.clone(),
        local_active_lease_id: response.connection.lease_id.clone(),
        role_generation: redundancy.role_generation,
        membership_generation: redundancy.membership_generation,
        primary: RedundantTunnelMemberStart {
            slot: RedundancyMemberSlot::A,
            lease_id: response.connection.lease_id.clone(),
            health_probe: primary_probe,
        },
        standby,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nelomai_client_tunnel::TunnelStatus;

    #[test]
    fn redundant_response_maps_both_members_into_tunnel_start() {
        let response: ConnectionStartResponse = serde_json::from_str(include_str!(
            "../../../contracts/fixtures/valid/connection-start-redundant-response.json"
        ))
        .unwrap();

        let start =
            redundant_tunnel_start(&response, "operation-1", Some(&"f".repeat(64)), Some(true))
                .unwrap()
                .unwrap();

        assert_eq!(start.session_id, "20000000-0000-4000-8000-000000000001");
        assert!(start.reserve_enabled);
        assert_eq!(
            start.primary.slot,
            nelomai_contracts::RedundancyMemberSlot::A
        );
        assert_eq!(
            start.primary.lease_id,
            "20000000-0000-4000-8000-000000000002"
        );
        let standby = start.standby.as_ref().unwrap();
        assert_eq!(
            standby.member.slot,
            nelomai_contracts::RedundancyMemberSlot::B
        );
        assert_eq!(
            standby.member.lease_id,
            "20000000-0000-4000-8000-000000000003"
        );
        assert!(standby
            .configuration
            .expose()
            .contains("standby-delivered-only-to-core"));
        assert!(!format!("{start:?}").contains("standby-delivered-only-to-core"));
    }

    #[test]
    fn pending_compensation_uses_a_generic_release_error() {
        let error = require_compensation_stop_finished(
            Some("tunnel_handshake_timeout"),
            false,
            LeaseStatus::Warm,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            CoreError::Api(CoreApiError::Rejected { ref code, .. })
                if code == "connection_release_pending"
        ));
    }

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
            retry_after_seconds: None,
        };
        assert_eq!(CoreApiError::from(error), CoreApiError::AccessExpired);
    }

    #[test]
    fn invalid_login_credentials_keep_their_actionable_error() {
        let error = ClientApiError::Api {
            status: reqwest::StatusCode::UNAUTHORIZED,
            request_id: "req".to_string(),
            code: "invalid_credentials".to_string(),
            message: "Неверный логин или пароль.".to_string(),
            retry_after_seconds: None,
        };

        assert_eq!(
            CoreApiError::from(error),
            CoreApiError::Rejected {
                code: "invalid_credentials".to_string(),
                message: "Неверный логин или пароль.".to_string(),
                retry_after_seconds: None,
            },
        );
    }

    #[test]
    fn invalid_access_token_still_maps_to_signed_out_state() {
        let error = ClientApiError::Api {
            status: reqwest::StatusCode::UNAUTHORIZED,
            request_id: "req".to_string(),
            code: "invalid_access_token".to_string(),
            message: "Недействительный токен доступа.".to_string(),
            retry_after_seconds: None,
        };

        assert_eq!(CoreApiError::from(error), CoreApiError::Unauthorized);
    }

    #[test]
    fn rejected_request_keeps_the_panel_message() {
        let error = ClientApiError::Api {
            status: reqwest::StatusCode::CONFLICT,
            request_id: "req".to_string(),
            code: "connection_active".to_string(),
            message: "Сначала остановите текущее подключение.".to_string(),
            retry_after_seconds: None,
        };
        assert_eq!(
            CoreApiError::from(error),
            CoreApiError::Rejected {
                code: "connection_active".to_string(),
                message: "Сначала остановите текущее подключение.".to_string(),
                retry_after_seconds: None,
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
            retry_after_seconds: None,
        };

        assert_eq!(
            CoreApiError::from(error),
            CoreApiError::Rejected {
                code: "configuration_fetch_failed".to_string(),
                message: "Не удалось получить конфигурацию. Повторите попытку.".to_string(),
                retry_after_seconds: None,
            },
        );
    }

    #[test]
    fn structured_recovery_service_error_keeps_its_stable_code() {
        let error = ClientApiError::Api {
            status: reqwest::StatusCode::SERVICE_UNAVAILABLE,
            request_id: "req".to_string(),
            code: "connection_stall_verification_unavailable".to_string(),
            message: "Retry later".to_string(),
            retry_after_seconds: None,
        };

        assert!(matches!(
            CoreApiError::from(error),
            CoreApiError::Rejected { ref code, .. }
                if code == "connection_stall_verification_unavailable"
        ));
    }

    #[test]
    fn device_operation_busy_keeps_its_code_and_retry_after() {
        let error = ClientApiError::Api {
            status: reqwest::StatusCode::SERVICE_UNAVAILABLE,
            request_id: "req".to_string(),
            code: "device_operation_busy".to_string(),
            message: "Операция устройства ещё завершается.".to_string(),
            retry_after_seconds: Some(30),
        };

        assert_eq!(
            CoreApiError::from(error),
            CoreApiError::Rejected {
                code: "device_operation_busy".to_string(),
                message: "Операция устройства ещё завершается.".to_string(),
                retry_after_seconds: Some(30),
            },
        );
    }

    #[test]
    fn structured_rate_limit_keeps_bounded_retry_after() {
        let error = ClientApiError::Api {
            status: reqwest::StatusCode::TOO_MANY_REQUESTS,
            request_id: "req".to_string(),
            code: "connection_stall_recycle_rate_limited".to_string(),
            message: "Retry later".to_string(),
            retry_after_seconds: Some(120),
        };

        assert!(matches!(
            CoreApiError::from(error),
            CoreApiError::Rejected {
                retry_after_seconds: Some(120),
                ..
            }
        ));
    }

    #[test]
    fn critical_update_rejection_opens_the_required_update_state() {
        let error = CoreApiError::Rejected {
            code: "critical_update_required".to_string(),
            message: "Для подключения необходимо обновить приложение.".to_string(),
            retry_after_seconds: None,
        };

        assert!(matches!(CoreError::from(error), CoreError::UpdateRequired));
    }
}
