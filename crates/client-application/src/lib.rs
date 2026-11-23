use async_trait::async_trait;
use futures_util::{stream, StreamExt};
use nelomai_client_api::{
    AccessSnapshot, BackgroundTokenResponse, ClientApi, ClientApiError, DiagnosticUploadRequest,
    DiagnosticUploadResponse, RuntimeLogin,
};
use nelomai_client_core::{
    AllowRuntimeStart, ClientCore, ConnectOptions, ConnectionMetricsContext, CoreApi, CoreApiError,
    CoreError, CoreLocalStop, CoreLogger, CoreState, Phase, PhysicalNetworkPollOutcome,
    RuntimeAuthProvider, RuntimeStartPreflight, SavedSplitTunnelAddressRules,
    SplitTunnelSyncOutcome, StalledDataPlaneRecovery, StalledDataPlaneRecoveryOutcome,
    StartCancellationEpoch,
};
use nelomai_client_storage::{MemorySplitTunnelStore, RuntimeStateStore, SplitTunnelStore};
use nelomai_client_tunnel::TunnelController;
use nelomai_contracts::{
    AppNotificationList, AppNotificationReadResponse, BindPeerRequest, Bootstrap, Connection,
    ConnectionIntentCapabilityResponse, EgressMode, Layer, OperationReconcileRequest,
    OperationReconcileResponse, PeerBindingResponse, PeerOptions, ProbeFailureCode, ProbeResult,
    ProbeResults, RouteMode, ServerCandidatesResponse, SplitTunnelAddressRuleScope,
    SplitTunnelAddressRuleUpdate, SplitTunnelPolicy, SplitTunnelSelectedPackage,
    SplitTunnelSettingsUpdate, TicConnectionMode, UpdateState,
};
use std::sync::{Arc, Mutex as StdMutex};
use thiserror::Error;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::sync::{Mutex as AsyncMutex, Notify};

const PROBE_REFRESH_SECONDS: i64 = 300;
const MAX_CONCURRENT_PROBES: usize = 4;

// Diagnostic uploads retry every failure through their own persistent queue.
// Preserve a bounded reason here before the general CoreApiError conversion
// collapses transport failures and HTTP 5xx into Retryable. Never copy URLs,
// server messages, response bodies or arbitrary server codes into the journal.
fn diagnostic_upload_error(error: ClientApiError) -> CoreApiError {
    if matches!(&error, ClientApiError::Api { status, code, .. }
        if status.as_u16() == 401 || code == "access_expired")
    {
        let mut error = CoreApiError::from(error);
        if let CoreApiError::Rejected { message, .. } = &mut error {
            *message = "Не удалось отправить диагностику.".into();
        }
        return error;
    }
    let code = match &error {
        ClientApiError::Transport(error) if error.is_timeout() => "diagnostics_timeout".into(),
        ClientApiError::Transport(error) if error.is_connect() => {
            "diagnostics_connect_failed".into()
        }
        ClientApiError::Transport(error) if error.is_decode() => {
            "diagnostics_response_decode_failed".into()
        }
        ClientApiError::Transport(error) if error.is_body() => "diagnostics_body_failed".into(),
        ClientApiError::Transport(_) => "diagnostics_transport_failed".into(),
        ClientApiError::ControlTransportUnavailable => "diagnostics_connect_failed".into(),
        ClientApiError::Api { status, .. }
        | ClientApiError::InvalidErrorResponse { status, .. } => {
            format!("diagnostics_http_{}", status.as_u16())
        }
        ClientApiError::InvalidBaseUrl(_)
        | ClientApiError::InvalidAppVersion(_)
        | ClientApiError::InvalidPayload { .. }
        | ClientApiError::PayloadTooLarge { .. } => "diagnostics_invalid_request".into(),
    };
    CoreApiError::Rejected {
        code,
        message: "Не удалось отправить диагностику.".into(),
        retry_after_seconds: error.retry_after_seconds(),
    }
}

pub type LoginParameters = RuntimeLogin;

#[async_trait]
pub trait ApplicationApi: CoreApi {
    async fn peer_options(
        &self,
        access_token: &AccessSnapshot,
    ) -> Result<PeerOptions, CoreApiError>;
    async fn bind_peer(
        &self,
        access_token: &AccessSnapshot,
        request: &BindPeerRequest,
    ) -> Result<PeerBindingResponse, CoreApiError>;
    async fn unbind_peer(
        &self,
        access_token: &AccessSnapshot,
    ) -> Result<PeerBindingResponse, CoreApiError>;
    async fn server_candidates(
        &self,
        access_token: &AccessSnapshot,
        layer: Layer,
        egress_mode: EgressMode,
    ) -> Result<ServerCandidatesResponse, CoreApiError>;
    async fn probe_latency_ms(&self, probe_url: &str) -> Option<f64>;
    async fn probe_fresh_latency_ms(&self, probe_url: &str) -> Option<f64> {
        self.probe_latency_ms(probe_url).await
    }
    async fn probe_fresh_latency_ms_resolved(
        &self,
        probe_url: &str,
        _resolved_ip: std::net::IpAddr,
    ) -> Option<f64> {
        self.probe_fresh_latency_ms(probe_url).await
    }
    async fn probe_candidate_latency_ms(&self, probe_url: &str) -> Result<f64, ProbeFailureCode> {
        self.probe_latency_ms(probe_url)
            .await
            .ok_or(ProbeFailureCode::Unknown)
    }
    async fn background_token(
        &self,
        _access_token: &AccessSnapshot,
    ) -> Result<BackgroundTokenResponse, CoreApiError> {
        Err(CoreApiError::Retryable)
    }
    async fn background_capabilities(
        &self,
        _background_token: &str,
    ) -> Result<ConnectionIntentCapabilityResponse, CoreApiError> {
        Err(CoreApiError::Retryable)
    }
    async fn background_candidates(
        &self,
        _background_token: &str,
        _layer: Layer,
        _egress_mode: EgressMode,
    ) -> Result<ServerCandidatesResponse, CoreApiError> {
        Err(CoreApiError::Retryable)
    }
    async fn reconcile_background_operation(
        &self,
        _background_token: &str,
        _request: &OperationReconcileRequest,
    ) -> Result<OperationReconcileResponse, CoreApiError> {
        Err(CoreApiError::Retryable)
    }
    async fn upload_diagnostics(
        &self,
        _access_token: &AccessSnapshot,
        _request: &DiagnosticUploadRequest,
    ) -> Result<DiagnosticUploadResponse, CoreApiError> {
        Err(CoreApiError::Retryable)
    }
    async fn notifications(
        &self,
        _access_token: &AccessSnapshot,
        _cursor: Option<i64>,
        _limit: u32,
    ) -> Result<AppNotificationList, CoreApiError> {
        Err(CoreApiError::Retryable)
    }
    async fn mark_notification_read(
        &self,
        _access_token: &AccessSnapshot,
        _message_id: i64,
    ) -> Result<AppNotificationReadResponse, CoreApiError> {
        Err(CoreApiError::Retryable)
    }
    async fn mark_all_notifications_read(
        &self,
        _access_token: &AccessSnapshot,
    ) -> Result<AppNotificationReadResponse, CoreApiError> {
        Err(CoreApiError::Retryable)
    }
    async fn register_push_token(
        &self,
        _access_token: &AccessSnapshot,
        _token: &str,
    ) -> Result<(), CoreApiError> {
        Err(CoreApiError::Retryable)
    }
    async fn unregister_push_token(
        &self,
        _access_token: &AccessSnapshot,
    ) -> Result<(), CoreApiError> {
        Ok(())
    }
}

#[async_trait]
impl ApplicationApi for ClientApi {
    async fn peer_options(
        &self,
        access_token: &AccessSnapshot,
    ) -> Result<PeerOptions, CoreApiError> {
        ClientApi::peer_options(
            &self.clone().with_access_snapshot(access_token)?,
            access_token.access_token(),
        )
        .await
        .map_err(Into::into)
    }

    async fn bind_peer(
        &self,
        access_token: &AccessSnapshot,
        request: &BindPeerRequest,
    ) -> Result<PeerBindingResponse, CoreApiError> {
        ClientApi::bind_peer(
            &self.clone().with_access_snapshot(access_token)?,
            access_token.access_token(),
            request,
        )
        .await
        .map_err(Into::into)
    }

    async fn unbind_peer(
        &self,
        access_token: &AccessSnapshot,
    ) -> Result<PeerBindingResponse, CoreApiError> {
        ClientApi::unbind_peer(
            &self.clone().with_access_snapshot(access_token)?,
            access_token.access_token(),
        )
        .await
        .map_err(Into::into)
    }

    async fn server_candidates(
        &self,
        access_token: &AccessSnapshot,
        layer: Layer,
        egress_mode: EgressMode,
    ) -> Result<ServerCandidatesResponse, CoreApiError> {
        ClientApi::server_candidates(
            &self.clone().with_access_snapshot(access_token)?,
            access_token.access_token(),
            layer,
            egress_mode,
        )
        .await
        .map_err(Into::into)
    }

    async fn probe_latency_ms(&self, probe_url: &str) -> Option<f64> {
        ClientApi::probe_latency_ms(self, probe_url).await
    }

    async fn probe_fresh_latency_ms(&self, probe_url: &str) -> Option<f64> {
        ClientApi::probe_fresh_latency_ms(self, probe_url).await
    }

    async fn probe_fresh_latency_ms_resolved(
        &self,
        probe_url: &str,
        resolved_ip: std::net::IpAddr,
    ) -> Option<f64> {
        ClientApi::probe_fresh_latency_ms_resolved(self, probe_url, resolved_ip).await
    }

    async fn probe_candidate_latency_ms(&self, probe_url: &str) -> Result<f64, ProbeFailureCode> {
        ClientApi::probe_candidate_latency_ms(self, probe_url).await
    }

    async fn background_token(
        &self,
        access_token: &AccessSnapshot,
    ) -> Result<BackgroundTokenResponse, CoreApiError> {
        ClientApi::background_token(
            &self.clone().with_access_snapshot(access_token)?,
            access_token.access_token(),
        )
        .await
        .map_err(Into::into)
    }

    async fn background_capabilities(
        &self,
        background_token: &str,
    ) -> Result<ConnectionIntentCapabilityResponse, CoreApiError> {
        ClientApi::background_capabilities(self, background_token)
            .await
            .map_err(Into::into)
    }

    async fn background_candidates(
        &self,
        background_token: &str,
        layer: Layer,
        egress_mode: EgressMode,
    ) -> Result<ServerCandidatesResponse, CoreApiError> {
        ClientApi::background_candidates(self, background_token, layer, egress_mode)
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

    async fn upload_diagnostics(
        &self,
        access_token: &AccessSnapshot,
        request: &DiagnosticUploadRequest,
    ) -> Result<DiagnosticUploadResponse, CoreApiError> {
        ClientApi::upload_diagnostics(
            &self.clone().with_access_snapshot(access_token)?,
            access_token.access_token(),
            request,
        )
        .await
        .map_err(diagnostic_upload_error)
    }

    async fn notifications(
        &self,
        access_token: &AccessSnapshot,
        cursor: Option<i64>,
        limit: u32,
    ) -> Result<AppNotificationList, CoreApiError> {
        ClientApi::notifications(
            &self.clone().with_access_snapshot(access_token)?,
            access_token.access_token(),
            cursor,
            limit,
        )
        .await
        .map_err(Into::into)
    }

    async fn mark_notification_read(
        &self,
        access_token: &AccessSnapshot,
        message_id: i64,
    ) -> Result<AppNotificationReadResponse, CoreApiError> {
        ClientApi::mark_notification_read(
            &self.clone().with_access_snapshot(access_token)?,
            access_token.access_token(),
            message_id,
        )
        .await
        .map_err(Into::into)
    }

    async fn mark_all_notifications_read(
        &self,
        access_token: &AccessSnapshot,
    ) -> Result<AppNotificationReadResponse, CoreApiError> {
        ClientApi::mark_all_notifications_read(
            &self.clone().with_access_snapshot(access_token)?,
            access_token.access_token(),
        )
        .await
        .map_err(Into::into)
    }

    async fn register_push_token(
        &self,
        access_token: &AccessSnapshot,
        token: &str,
    ) -> Result<(), CoreApiError> {
        ClientApi::register_push_token(
            &self.clone().with_access_snapshot(access_token)?,
            access_token.access_token(),
            token,
        )
        .await
        .map(|_| ())
        .map_err(Into::into)
    }

    async fn unregister_push_token(
        &self,
        access_token: &AccessSnapshot,
    ) -> Result<(), CoreApiError> {
        ClientApi::unregister_push_token(
            &self.clone().with_access_snapshot(access_token)?,
            access_token.access_token(),
        )
        .await
        .map(|_| ())
        .map_err(Into::into)
    }
}

#[derive(Debug, Error)]
pub enum ApplicationError {
    #[error("автоматическое восстановление отложено до пробуждения")]
    RecoveryDeferred,
    #[error("защищённое хранилище недоступно")]
    Storage,
    #[error("не удалось определить текущее время")]
    Clock,
    #[error(transparent)]
    Api(#[from] CoreApiError),
    #[error(transparent)]
    Core(CoreError),
}

impl From<CoreError> for ApplicationError {
    fn from(error: CoreError) -> Self {
        match error {
            CoreError::RecoveryDeferred => Self::RecoveryDeferred,
            other => Self::Core(other),
        }
    }
}

#[derive(Clone)]
struct CachedProbes {
    measured_at_unix: i64,
    valid_until_unix: i64,
    results: ProbeResults,
}

#[derive(Default)]
struct ProbeCache {
    tic_ipv4: Option<CachedProbes>,
    tic_ipv6: Option<CachedProbes>,
    stray: Option<CachedProbes>,
}

impl ProbeCache {
    fn get(&self, layer: Layer, egress_mode: EgressMode) -> Option<&CachedProbes> {
        match (layer, egress_mode) {
            (Layer::Tic, EgressMode::Ipv4) => self.tic_ipv4.as_ref(),
            (Layer::Tic, EgressMode::PreferIpv6) => self.tic_ipv6.as_ref(),
            (Layer::Stray, _) => self.stray.as_ref(),
        }
    }

    fn set(&mut self, layer: Layer, egress_mode: EgressMode, value: Option<CachedProbes>) {
        match (layer, egress_mode) {
            (Layer::Tic, EgressMode::Ipv4) => self.tic_ipv4 = value,
            (Layer::Tic, EgressMode::PreferIpv6) => self.tic_ipv6 = value,
            (Layer::Stray, _) => self.stray = value,
        }
    }
}

/// Result of the existing cleanup worker, before any automatic restart.
/// The source and cancellation epoch are captured under the lifecycle gate.
#[derive(Debug)]
pub struct PendingStopCompletion {
    pub cleaned_pair: Option<nelomai_client_tunnel::redundancy::SessionScope>,
    #[cfg(not(target_os = "android"))]
    pub cleaned_singleton: bool,
    pub connection: Connection,
    pub cancel_epoch: StartCancellationEpoch,
}

pub struct ClientApplication<A, S, T, L> {
    api: Arc<A>,
    auth: Arc<dyn RuntimeAuthProvider>,
    core: ClientCore<A, S, T, L>,
    start_preflight: Arc<dyn RuntimeStartPreflight>,
    lifecycle_gate: Arc<AsyncMutex<()>>,
    probe_gate: AsyncMutex<()>,
    pending_stop_wake: Notify,
    probe_cache: StdMutex<ProbeCache>,
}

#[cfg(target_os = "macos")]
impl<S, T, L> ClientApplication<ClientApi, S, T, L> {
    pub async fn probe_wake_control_network(&self) -> bool {
        self.api.probe_wake_control_network().await
    }
}

impl<A, S, T, L> ClientApplication<A, S, T, L>
where
    A: ApplicationApi,
    S: RuntimeStateStore,
    T: TunnelController,
    L: CoreLogger,
{
    pub fn new(
        api: Arc<A>,
        store: Arc<S>,
        auth: Arc<dyn RuntimeAuthProvider>,
        local: Arc<CoreLocalStop<T>>,
        logger: Arc<L>,
    ) -> Self {
        Self::with_split_tunnel_store(
            api,
            store,
            Arc::new(MemorySplitTunnelStore::default()),
            auth,
            local,
            logger,
        )
    }

    pub fn with_split_tunnel_store(
        api: Arc<A>,
        store: Arc<S>,
        split_tunnel_store: Arc<dyn SplitTunnelStore>,
        auth: Arc<dyn RuntimeAuthProvider>,
        local: Arc<CoreLocalStop<T>>,
        logger: Arc<L>,
    ) -> Self {
        Self::with_split_tunnel_store_and_preflight(
            api,
            store,
            split_tunnel_store,
            auth,
            local,
            logger,
            Arc::new(AllowRuntimeStart),
        )
    }

    pub fn with_split_tunnel_store_and_preflight(
        api: Arc<A>,
        store: Arc<S>,
        split_tunnel_store: Arc<dyn SplitTunnelStore>,
        auth: Arc<dyn RuntimeAuthProvider>,
        local: Arc<CoreLocalStop<T>>,
        logger: Arc<L>,
        start_preflight: Arc<dyn RuntimeStartPreflight>,
    ) -> Self {
        let lifecycle_gate = local.runtime_writer_gates().lifecycle();
        let core = ClientCore::with_split_tunnel_store(
            api.clone(),
            store.clone(),
            split_tunnel_store,
            auth.clone(),
            local,
            logger,
        );
        Self {
            api,
            auth,
            core,
            start_preflight,
            lifecycle_gate,
            probe_gate: AsyncMutex::new(()),
            pending_stop_wake: Notify::new(),
            probe_cache: StdMutex::new(ProbeCache::default()),
        }
    }

    pub async fn login(
        &self,
        parameters: LoginParameters,
        now_unix: i64,
    ) -> Result<Bootstrap, ApplicationError> {
        // The owner drains the shared lifecycle/Core writers before issuance.
        // Do not retain this lock while asking the owner to acquire it.
        self.auth.login(parameters).await?;
        let _lifecycle_guard = self.lifecycle_gate.lock().await;
        self.clear_probe_cache()?;
        Box::pin(self.core.bootstrap(now_unix))
            .await
            .map_err(Into::into)
    }

    pub async fn peer_options(&self) -> Result<PeerOptions, ApplicationError> {
        let access_token = self.access_token().await?;
        let mut options = match self.api.peer_options(&access_token).await {
            Ok(options) => options,
            Err(CoreApiError::Unauthorized) => {
                let access_token = self.core.refresh_access_token(&access_token).await?;
                self.api.peer_options(&access_token).await?
            }
            Err(error) => return Err(error.into()),
        };
        options
            .peers
            .sort_by_key(|peer| peer.last_handshake_at.is_some());
        Ok(options)
    }

    pub async fn probe_connection_latency_ms(
        &self,
        probe_url: &str,
    ) -> Result<f64, ProbeFailureCode> {
        self.api.probe_candidate_latency_ms(probe_url).await
    }

    pub async fn probe_fresh_connection_latency_ms(&self, probe_url: &str) -> Option<f64> {
        self.api.probe_fresh_latency_ms(probe_url).await
    }

    pub async fn probe_fresh_connection_latency_ms_resolved(
        &self,
        probe_url: &str,
        resolved_ip: std::net::IpAddr,
    ) -> Option<f64> {
        self.api
            .probe_fresh_latency_ms_resolved(probe_url, resolved_ip)
            .await
    }

    pub fn set_split_tunnel_installed_packages(&self, packages: Vec<SplitTunnelSelectedPackage>) {
        self.core.set_split_tunnel_installed_packages(packages);
    }

    pub fn set_dns_servers(&self, servers: Vec<std::net::IpAddr>) {
        self.core.set_dns_servers(servers);
    }

    pub async fn synchronize_split_tunnel(
        &self,
        now_unix: i64,
        force_full: bool,
    ) -> Result<SplitTunnelSyncOutcome, ApplicationError> {
        Box::pin(self.core.synchronize_split_tunnel(now_unix, force_full))
            .await
            .map_err(Into::into)
    }

    #[cfg(target_os = "macos")]
    pub async fn synchronize_split_tunnel_guarded(
        &self,
        now_unix: i64,
        retry_revision: bool,
        allowed: &(impl Fn() -> bool + Sync),
    ) -> Result<SplitTunnelSyncOutcome, ApplicationError> {
        if retry_revision {
            return Box::pin(
                self.core
                    .retry_split_tunnel_revision_guarded(now_unix, allowed),
            )
            .await
            .map_err(Into::into);
        }
        Box::pin(
            self.core
                .synchronize_split_tunnel_guarded(now_unix, false, allowed),
        )
        .await
        .map_err(Into::into)
    }

    #[cfg(target_os = "macos")]
    pub async fn synchronize_split_tunnel_for_wake(
        &self,
        now_unix: i64,
        retry_revision: bool,
        wake_stamp: Option<i64>,
        allowed: impl Fn() -> bool + Send + Sync + 'static,
    ) -> Result<SplitTunnelSyncOutcome, ApplicationError> {
        let preflight = self.start_preflight.clone();
        Box::pin(self.core.synchronize_split_tunnel_for_wake(
            now_unix,
            retry_revision,
            wake_stamp,
            move || allowed() && preflight.check_start_barrier().is_ok(),
        ))
        .await
        .map_err(Into::into)
    }

    pub async fn save_split_tunnel_settings(
        &self,
        request: &SplitTunnelSettingsUpdate,
        now_unix: i64,
    ) -> Result<SplitTunnelPolicy, ApplicationError> {
        Box::pin(self.core.save_split_tunnel_settings(request, now_unix))
            .await
            .map_err(Into::into)
    }

    pub async fn add_split_tunnel_address_rule(
        &self,
        request: &SplitTunnelAddressRuleUpdate,
        now_unix: i64,
    ) -> Result<SavedSplitTunnelAddressRules, ApplicationError> {
        Box::pin(self.core.add_split_tunnel_address_rule(request, now_unix))
            .await
            .map_err(Into::into)
    }

    pub async fn remove_split_tunnel_address_rule(
        &self,
        rule_id: i64,
        scope: SplitTunnelAddressRuleScope,
        now_unix: i64,
    ) -> Result<SavedSplitTunnelAddressRules, ApplicationError> {
        Box::pin(
            self.core
                .remove_split_tunnel_address_rule(rule_id, scope, now_unix),
        )
        .await
        .map_err(Into::into)
    }

    pub async fn split_tunnel_warning(&self) -> Option<String> {
        self.core.split_tunnel_warning().await
    }

    pub async fn poll_physical_network(
        &self,
        now_unix: i64,
    ) -> Result<PhysicalNetworkPollOutcome, ApplicationError> {
        self.core
            .poll_physical_network(now_unix)
            .await
            .map_err(Into::into)
    }

    pub async fn poll_physical_network_guarded(
        &self,
        now_unix: i64,
        allowed: impl Fn() -> bool + Send + Sync,
    ) -> Result<PhysicalNetworkPollOutcome, ApplicationError> {
        self.core
            .poll_physical_network_guarded(now_unix, allowed)
            .await
            .map_err(Into::into)
    }

    #[cfg(target_os = "macos")]
    pub async fn poll_physical_network_for_wake(
        &self,
        now_unix: i64,
        wake_stamp: Option<i64>,
        allowed: impl Fn() -> bool + Send + Sync + 'static,
    ) -> Result<PhysicalNetworkPollOutcome, ApplicationError> {
        let preflight = self.start_preflight.clone();
        self.core
            .poll_physical_network_for_wake(now_unix, wake_stamp, move || {
                allowed() && preflight.check_start_barrier().is_ok()
            })
            .await
            .map_err(Into::into)
    }

    pub fn cached_split_tunnel_policy(
        &self,
    ) -> Result<Option<SplitTunnelPolicy>, ApplicationError> {
        self.core.cached_split_tunnel_policy().map_err(Into::into)
    }

    pub async fn saved_split_tunnel_policy(
        &self,
    ) -> Result<Option<SplitTunnelPolicy>, ApplicationError> {
        self.core
            .saved_split_tunnel_policy()
            .await
            .map_err(Into::into)
    }

    pub async fn split_tunnel_capabilities(
        &self,
    ) -> Result<nelomai_client_tunnel::TunnelCapabilities, ApplicationError> {
        self.core
            .split_tunnel_capabilities()
            .await
            .map_err(Into::into)
    }

    pub async fn connection_intent_tunnel_options(
        &self,
        layer: Layer,
        route_mode: RouteMode,
        now_unix: i64,
    ) -> Result<nelomai_client_tunnel::TunnelOptions, ApplicationError> {
        self.core
            .connection_intent_tunnel_options(layer, route_mode, now_unix)
            .await
            .map_err(Into::into)
    }

    pub async fn split_tunnel_settings_require_reconnect(
        &self,
        request: &SplitTunnelSettingsUpdate,
    ) -> Result<bool, ApplicationError> {
        self.core
            .split_tunnel_settings_require_reconnect(request)
            .await
            .map_err(Into::into)
    }

    pub async fn bind_peer(
        &self,
        request: BindPeerRequest,
    ) -> Result<PeerBindingResponse, ApplicationError> {
        self.bind_peer_guarded(request, &|| true).await
    }

    pub async fn bind_peer_guarded(
        &self,
        request: BindPeerRequest,
        admission: &dyn nelomai_client_core::StartAdmission,
    ) -> Result<PeerBindingResponse, ApplicationError> {
        let allowed = || admission.allows_start();
        let _lifecycle_guard = self.lifecycle_gate.lock().await;
        if !allowed() {
            return Err(ApplicationError::RecoveryDeferred);
        }
        self.core.prepare_binding_change_guarded(admission).await?;
        let access_token = self.access_token().await?;
        let _probe_guard = self.probe_gate.lock().await;
        if !allowed() {
            return Err(ApplicationError::RecoveryDeferred);
        }
        let response = match self.api.bind_peer(&access_token, &request).await {
            Ok(response) => response,
            Err(CoreApiError::Unauthorized) if allowed() => {
                let access_token = self.core.refresh_access_token(&access_token).await?;
                if !allowed() {
                    return Err(ApplicationError::RecoveryDeferred);
                }
                self.api.bind_peer(&access_token, &request).await?
            }
            Err(error) => return Err(error.into()),
        };
        self.clear_probe_cache()?;
        Ok(response)
    }

    pub async fn unbind_peer(&self) -> Result<PeerBindingResponse, ApplicationError> {
        let _lifecycle_guard = self.lifecycle_gate.lock().await;
        let _probe_guard = self.probe_gate.lock().await;
        let access_token = self.access_token().await?;
        let response = match self.api.unbind_peer(&access_token).await {
            Ok(response) => response,
            Err(CoreApiError::Unauthorized) => {
                let access_token = self.core.refresh_access_token(&access_token).await?;
                self.api.unbind_peer(&access_token).await?
            }
            Err(error) => return Err(error.into()),
        };
        // Invalidate the old peer before releasing lifecycle ownership, even
        // if the local half has to be retried after the panel accepts unbind.
        #[cfg(not(target_os = "android"))]
        self.core.signal_start_cancellation();
        self.core.complete_unbind().await?;
        self.clear_probe_cache()?;
        Ok(response)
    }

    pub async fn logout(&self) -> Result<(), ApplicationError> {
        // Enter the protected owner without waiting for lifecycle/probe gates.
        let result = self.core.sign_out().await;
        self.clear_probe_cache()?;
        result.map_err(Into::into)
    }

    pub async fn background_token_for_device(
        &self,
        expected_device_id: &str,
        now_unix: i64,
    ) -> Result<Option<BackgroundTokenResponse>, ApplicationError> {
        let _lifecycle_guard = self.lifecycle_gate.lock().await;
        let bootstrap = self.core.bootstrap(now_unix).await?;
        if bootstrap.device.id != expected_device_id {
            return Ok(None);
        }
        let access_token = self.access_token().await?;
        match ApplicationApi::background_token(self.api.as_ref(), &access_token).await {
            Ok(response) => Ok(Some(response)),
            Err(CoreApiError::Unauthorized) => {
                let access_token = self.core.refresh_access_token(&access_token).await?;
                ApplicationApi::background_token(self.api.as_ref(), &access_token)
                    .await
                    .map(Some)
                    .map_err(Into::into)
            }
            Err(error) => Err(error.into()),
        }
    }

    pub async fn upload_diagnostics(
        &self,
        request: &DiagnosticUploadRequest,
    ) -> Result<DiagnosticUploadResponse, ApplicationError> {
        let access_token = self.access_token().await?;
        match self.api.upload_diagnostics(&access_token, request).await {
            Ok(response) => Ok(response),
            Err(CoreApiError::Unauthorized) => {
                let access_token = self.core.refresh_access_token(&access_token).await?;
                self.api
                    .upload_diagnostics(&access_token, request)
                    .await
                    .map_err(Into::into)
            }
            Err(error) => Err(error.into()),
        }
    }

    pub async fn notifications(
        &self,
        cursor: Option<i64>,
        limit: u32,
    ) -> Result<AppNotificationList, ApplicationError> {
        let access_token = self.access_token().await?;
        match self.api.notifications(&access_token, cursor, limit).await {
            Ok(response) => Ok(response),
            Err(CoreApiError::Unauthorized) => {
                let access_token = self.core.refresh_access_token(&access_token).await?;
                self.api
                    .notifications(&access_token, cursor, limit)
                    .await
                    .map_err(Into::into)
            }
            Err(error) => Err(error.into()),
        }
    }

    pub async fn mark_notification_read(
        &self,
        message_id: i64,
    ) -> Result<AppNotificationReadResponse, ApplicationError> {
        let access_token = self.access_token().await?;
        match self
            .api
            .mark_notification_read(&access_token, message_id)
            .await
        {
            Ok(response) => Ok(response),
            Err(CoreApiError::Unauthorized) => {
                let access_token = self.core.refresh_access_token(&access_token).await?;
                self.api
                    .mark_notification_read(&access_token, message_id)
                    .await
                    .map_err(Into::into)
            }
            Err(error) => Err(error.into()),
        }
    }

    pub async fn mark_all_notifications_read(
        &self,
    ) -> Result<AppNotificationReadResponse, ApplicationError> {
        let access_token = self.access_token().await?;
        match self.api.mark_all_notifications_read(&access_token).await {
            Ok(response) => Ok(response),
            Err(CoreApiError::Unauthorized) => {
                let access_token = self.core.refresh_access_token(&access_token).await?;
                self.api
                    .mark_all_notifications_read(&access_token)
                    .await
                    .map_err(Into::into)
            }
            Err(error) => Err(error.into()),
        }
    }

    pub async fn register_push_token(&self, token: &str) -> Result<(), ApplicationError> {
        let access_token = self.access_token().await?;
        match self.api.register_push_token(&access_token, token).await {
            Ok(()) => Ok(()),
            Err(CoreApiError::Unauthorized) => {
                let access_token = self.core.refresh_access_token(&access_token).await?;
                self.api
                    .register_push_token(&access_token, token)
                    .await
                    .map_err(Into::into)
            }
            Err(error) => Err(error.into()),
        }
    }

    pub async fn unregister_push_token(&self) -> Result<(), ApplicationError> {
        let access_token = self.access_token().await?;
        match self.api.unregister_push_token(&access_token).await {
            Ok(()) => Ok(()),
            Err(CoreApiError::Unauthorized) => {
                let access_token = self.core.refresh_access_token(&access_token).await?;
                self.api
                    .unregister_push_token(&access_token)
                    .await
                    .map_err(Into::into)
            }
            Err(error) => Err(error.into()),
        }
    }

    pub async fn state(&self) -> CoreState {
        #[cfg(target_os = "linux")]
        let was_connected =
            self.core.begin_foreground_observation().await.phase() == Phase::Connected;
        let state = self.core.state().await;
        #[cfg(target_os = "linux")]
        if was_connected && state.phase == Phase::Stopping {
            // Advisory only: the existing worker revalidates auth, the exact
            // protected owner and native cleanup before contacting the panel.
            self.pending_stop_wake.notify_one();
        }
        state
    }

    pub fn runtime_channel_closed(&self) -> bool {
        self.core.runtime_channel_closed()
    }

    pub async fn begin_foreground_observation(&self) -> nelomai_client_core::ForegroundObservation {
        self.core.begin_foreground_observation().await
    }

    pub async fn foreground_state_guarded(
        &self,
        observation: nelomai_client_core::ForegroundObservation,
        intent: Option<nelomai_client_core::NativeConnectionIntent>,
        allowed: impl Fn() -> bool,
    ) -> CoreState {
        // Do not acquire lifecycle_gate: bootstrap/restoration may be waiting
        // on the panel while the foreground needs the native owner's state.
        self.core
            .foreground_state_guarded(observation, intent, allowed)
            .await
    }

    pub async fn refresh_update_state(&self) -> Result<UpdateState, ApplicationError> {
        let access_token = self.access_token().await?;
        match self.api.bootstrap(&access_token).await {
            Ok(response) => Ok(response.update),
            Err(CoreApiError::Unauthorized) => {
                let access_token = self.core.refresh_access_token(&access_token).await?;
                self.api
                    .bootstrap(&access_token)
                    .await
                    .map(|response| response.update)
                    .map_err(Into::into)
            }
            Err(error) => Err(error.into()),
        }
    }

    pub async fn connection_metrics_context(&self) -> Option<ConnectionMetricsContext> {
        self.core.connection_metrics_context().await
    }

    #[cfg(not(target_os = "android"))]
    pub async fn desktop_redundancy_status(
        &self,
    ) -> Result<Option<nelomai_client_tunnel::redundancy::protocol::Snapshot>, ApplicationError>
    {
        self.core
            .desktop_redundancy_status()
            .await
            .map_err(Into::into)
    }

    /// Freeze an exact stalled helper owner and journal a cold stop. Panel cleanup
    /// remains on the existing worker. An unjournaled freeze failure belongs to
    /// the exact intent retry, not the worker's ordinary Stop path.
    #[cfg(not(target_os = "android"))]
    pub async fn prepare_desktop_recovery(
        &self,
        snapshot: &nelomai_client_tunnel::redundancy::protocol::Snapshot,
    ) -> Result<bool, ApplicationError> {
        self.prepare_desktop_recovery_guarded(snapshot, None, || true)
            .await
    }

    #[cfg(not(target_os = "android"))]
    pub async fn prepare_desktop_recovery_guarded(
        &self,
        snapshot: &nelomai_client_tunnel::redundancy::protocol::Snapshot,
        wake_stamp: Option<i64>,
        allowed: impl Fn() -> bool + Send + Sync + 'static,
    ) -> Result<bool, ApplicationError> {
        let _lifecycle_guard = self.lifecycle_gate.lock().await;
        let result = self
            .core
            .prepare_desktop_recovery_guarded(snapshot, wake_stamp, allowed)
            .await;
        if matches!(result, Ok(Some(true))) || self.core.has_pending_stop_cleanup().unwrap_or(false)
        {
            self.pending_stop_wake.notify_one();
        }
        result?.ok_or(ApplicationError::RecoveryDeferred)
    }

    /// One coordination step, not a native health loop. Refresh the scoped cache
    /// only when the exact Core/helper owner needs a reserve acquisition.
    #[cfg(not(target_os = "android"))]
    pub async fn desktop_redundancy_tick(
        &self,
        now_unix: i64,
    ) -> Result<Option<nelomai_client_tunnel::redundancy::protocol::Snapshot>, ApplicationError>
    {
        self.desktop_redundancy_tick_guarded(now_unix, None, || true)
            .await
    }

    #[cfg(not(target_os = "android"))]
    pub async fn desktop_redundancy_tick_guarded(
        &self,
        now_unix: i64,
        wake_stamp: Option<i64>,
        allowed: impl Fn() -> bool + Send + Sync + 'static,
    ) -> Result<Option<nelomai_client_tunnel::redundancy::protocol::Snapshot>, ApplicationError>
    {
        if !allowed() {
            return Ok(None);
        }
        let probe_context = self.core.desktop_redundancy_probe_context().await;
        if !allowed() {
            return Ok(None);
        }
        let used = match probe_context? {
            Some((layer, egress_mode)) => {
                let probes = self
                    .refresh_probes_guarded(layer, egress_mode, now_unix, &allowed)
                    .await;
                if !allowed() {
                    return Ok(None);
                }
                Some(probes?)
            }
            None => None,
        };
        let result = self
            .core
            .desktop_redundancy_tick_guarded(
                used.as_ref()
                    .map(|used| used.probes.clone())
                    .unwrap_or_default(),
                wake_stamp,
                allowed,
            )
            .await;
        if matches!(&result, Err(CoreError::Api(CoreApiError::Rejected { code, .. })) if code == "standby_unavailable")
        {
            if let Some(used) = used {
                // A delayed rejection must not discard a concurrent refresh.
                if let Ok(mut cache) = self.probe_cache.lock() {
                    if cache
                        .get(used.layer, used.egress_mode)
                        .is_some_and(|cached| cached.results == used)
                    {
                        cache.set(used.layer, used.egress_mode, None);
                    }
                }
            }
        }
        result.map_err(Into::into)
    }

    pub fn record_tunnel_unavailable(&self, kind: &'static str, code: String) {
        self.core.record_tunnel_unavailable(kind, code);
    }

    pub async fn recover_stalled_data_plane(
        &self,
        lease_id: &str,
        recovery: StalledDataPlaneRecovery,
    ) -> Result<StalledDataPlaneRecoveryOutcome, ApplicationError> {
        self.recover_stalled_data_plane_guarded(lease_id, recovery, &|| true)
            .await
    }

    pub async fn recover_stalled_data_plane_guarded(
        &self,
        lease_id: &str,
        recovery: StalledDataPlaneRecovery,
        allowed: &(impl Fn() -> bool + Sync),
    ) -> Result<StalledDataPlaneRecoveryOutcome, ApplicationError> {
        self.core
            .recover_stalled_data_plane_guarded(lease_id, recovery, allowed)
            .await
            .map_err(Into::into)
    }

    #[cfg(target_os = "macos")]
    pub async fn recover_stalled_data_plane_guarded_for_wake(
        &self,
        lease_id: &str,
        recovery: StalledDataPlaneRecovery,
        wake_stamp: Option<i64>,
        allowed: impl Fn() -> bool + Send + Sync + 'static,
    ) -> Result<StalledDataPlaneRecoveryOutcome, ApplicationError> {
        let preflight = self.start_preflight.clone();
        self.core
            .recover_stalled_data_plane_guarded_for_wake(
                lease_id,
                recovery,
                wake_stamp,
                move || allowed() && preflight.check_start_barrier().is_ok(),
            )
            .await
            .map_err(Into::into)
    }

    #[cfg(target_os = "macos")]
    pub async fn resume_stalled_data_plane_restart_guarded(
        &self,
        lease_id: &str,
        allowed: &(impl Fn() -> bool + Sync),
    ) -> Result<Option<nelomai_client_core::StalledDataPlaneRestartOutcome>, ApplicationError> {
        self.core
            .resume_stalled_data_plane_restart_guarded(lease_id, &|| {
                allowed() && self.start_preflight.check_start_barrier().is_ok()
            })
            .await
            .map_err(Into::into)
    }

    #[cfg(target_os = "macos")]
    pub async fn resume_stalled_data_plane_restart_guarded_for_wake(
        &self,
        lease_id: &str,
        wake_stamp: Option<i64>,
        allowed: impl Fn() -> bool + Send + Sync + 'static,
    ) -> Result<Option<nelomai_client_core::StalledDataPlaneRestartOutcome>, ApplicationError> {
        let preflight = self.start_preflight.clone();
        self.core
            .resume_stalled_data_plane_restart_guarded_for_wake(lease_id, wake_stamp, move || {
                allowed() && preflight.check_start_barrier().is_ok()
            })
            .await
            .map_err(Into::into)
    }

    pub async fn reconcile_external_tunnel_state(&self) -> CoreState {
        self.core.reconcile_external_tunnel_state().await
    }

    #[cfg(not(target_os = "android"))]
    pub async fn reconcile_pending_operation_for_retry(&self) -> Result<(), ApplicationError> {
        self.reconcile_pending_operation_for_retry_guarded(&|| true)
            .await
    }

    #[cfg(not(target_os = "android"))]
    pub async fn reconcile_pending_operation_for_retry_guarded(
        &self,
        allowed: &(dyn Fn() -> bool + Sync),
    ) -> Result<(), ApplicationError> {
        let _lifecycle_guard = self.lifecycle_gate.lock().await;
        self.core
            .reconcile_pending_operation_for_retry_guarded(allowed)
            .await
            .map_err(Into::into)
    }

    // Keep large Core futures off callers' inline state (notably Tauri JNI IPC).
    pub async fn bootstrap(&self, now_unix: i64) -> Result<Bootstrap, ApplicationError> {
        self.bootstrap_guarded(now_unix, &|| true).await
    }

    pub async fn bootstrap_guarded(
        &self,
        now_unix: i64,
        allowed: &(impl Fn() -> bool + Sync),
    ) -> Result<Bootstrap, ApplicationError> {
        let _lifecycle_guard = self.lifecycle_gate.lock().await;
        Box::pin(self.core.bootstrap_guarded(now_unix, allowed))
            .await
            .map_err(Into::into)
    }

    pub async fn bootstrap_without_refresh(
        &self,
        now_unix: i64,
    ) -> Result<Bootstrap, ApplicationError> {
        let _lifecycle_guard = self.lifecycle_gate.lock().await;
        Box::pin(self.core.bootstrap_without_refresh(now_unix))
            .await
            .map_err(Into::into)
    }

    pub async fn start(
        &self,
        options: ConnectOptions,
        now_unix: i64,
    ) -> Result<Connection, ApplicationError> {
        let cancel_epoch = self.core.begin_start_attempt();
        let result = self
            .start_with_cancellation_epoch(options, now_unix, cancel_epoch)
            .await;
        self.core.finish_start_attempt();
        result
    }

    pub fn start_cancellation_epoch(&self) -> StartCancellationEpoch {
        self.core.start_cancellation_epoch()
    }

    #[cfg(target_os = "macos")]
    pub fn macos_stall_epoch(&self) -> Option<nelomai_client_core::MacosStallEpoch> {
        self.core.macos_stall_epoch()
    }

    #[cfg(target_os = "macos")]
    pub fn macos_stall_epoch_is_current(
        &self,
        epoch: nelomai_client_core::MacosStallEpoch,
    ) -> bool {
        self.core.macos_stall_epoch_is_current(epoch)
    }

    pub fn check_start_cancellation(
        &self,
        epoch: StartCancellationEpoch,
    ) -> Result<(), ApplicationError> {
        self.core
            .check_start_cancellation(epoch)
            .map_err(Into::into)
    }

    pub fn begin_start_attempt(&self) -> StartCancellationEpoch {
        self.core.begin_start_attempt()
    }

    pub fn finish_start_attempt(&self) {
        self.core.finish_start_attempt();
    }

    pub async fn start_with_cancellation_epoch(
        &self,
        options: ConnectOptions,
        now_unix: i64,
        cancel_epoch: StartCancellationEpoch,
    ) -> Result<Connection, ApplicationError> {
        self.start_with_contract(options, now_unix, cancel_epoch, None, &|| true)
            .await
    }

    pub async fn start_recovery_v2(
        &self,
        options: ConnectOptions,
        now_unix: i64,
        reserve_enabled: bool,
    ) -> Result<Connection, ApplicationError> {
        let cancel_epoch = self.core.begin_start_attempt();
        let result = self
            .start_with_contract(
                options,
                now_unix,
                cancel_epoch,
                Some(reserve_enabled),
                &|| true,
            )
            .await;
        self.core.finish_start_attempt();
        result
    }

    async fn start_with_contract(
        &self,
        mut options: ConnectOptions,
        now_unix: i64,
        cancel_epoch: StartCancellationEpoch,
        reserve_enabled: Option<bool>,
        admission: &dyn nelomai_client_core::StartAdmission,
    ) -> Result<Connection, ApplicationError> {
        let allowed = || admission.allows_start();
        self.start_preflight.before_tunnel_start().await?;
        let _lifecycle_guard = self.lifecycle_gate.lock().await;
        self.start_preflight.check_start_barrier()?;
        if !allowed() {
            return Err(ApplicationError::RecoveryDeferred);
        }
        options = options.normalized_for_layer();
        self.core
            .prepare_explicit_start_guarded(&options, cancel_epoch, &allowed)
            .await?;
        options.probes = if options.layer == Layer::Tic
            && options.tic_connection_mode == TicConnectionMode::Personal
        {
            Vec::new()
        } else {
            match self
                .refresh_probes_guarded(options.layer, options.egress_mode, now_unix, &allowed)
                .await
            {
                Ok(results) => results.probes,
                Err(_) => self
                    .cached_probes(options.layer, options.egress_mode, now_unix)
                    .map(|results| results.probes)
                    .unwrap_or_default(),
            }
        };
        match reserve_enabled {
            Some(reserve) => {
                self.core
                    .start_recovery_v2_with_cancellation_epoch(
                        options,
                        now_unix,
                        reserve,
                        cancel_epoch,
                    )
                    .await
            }
            None => {
                self.core
                    .start_with_cancellation_epoch_guarded(
                        options,
                        now_unix,
                        cancel_epoch,
                        admission,
                    )
                    .await
            }
        }
        .map_err(Into::into)
    }

    #[cfg(not(target_os = "android"))]
    pub async fn start_legacy_intent_guarded(
        &self,
        mut options: ConnectOptions,
        now_unix: i64,
        cancel_epoch: StartCancellationEpoch,
        skip_probe_refresh: bool,
        admission: &dyn nelomai_client_core::StartAdmission,
    ) -> Result<Connection, ApplicationError> {
        self.core.begin_start_attempt();
        let result = async {
            if !skip_probe_refresh {
                return self
                    .start_with_contract(options, now_unix, cancel_epoch, None, admission)
                    .await;
            }
            self.start_preflight.before_tunnel_start().await?;
            let _lifecycle_guard = self.lifecycle_gate.lock().await;
            self.start_preflight.check_start_barrier()?;
            options.probes.clear();
            self.core
                .start_with_cancellation_epoch_guarded(options, now_unix, cancel_epoch, admission)
                .await
                .map_err(Into::into)
        }
        .await;
        self.core.finish_start_attempt();
        result
    }

    pub async fn start_without_probe_refresh(
        &self,
        mut options: ConnectOptions,
        now_unix: i64,
    ) -> Result<Connection, ApplicationError> {
        self.start_preflight.before_tunnel_start().await?;
        let _lifecycle_guard = self.lifecycle_gate.lock().await;
        self.start_preflight.check_start_barrier()?;
        let cancel_epoch = self.core.begin_start_attempt();
        options = options.normalized_for_layer();
        options.probes.clear();
        let result = self
            .core
            .start_with_cancellation_epoch(options, now_unix, cancel_epoch)
            .await;
        self.core.finish_start_attempt();
        result.map_err(Into::into)
    }

    #[cfg(not(target_os = "android"))]
    pub async fn connection_intent_attempt(
        &self,
        options: ConnectOptions,
        now_unix: i64,
    ) -> Result<Connection, ApplicationError> {
        self.connection_intent_attempt_guarded(options, now_unix, || true)
            .await
    }

    #[cfg(not(target_os = "android"))]
    pub async fn connection_intent_attempt_guarded(
        &self,
        options: ConnectOptions,
        now_unix: i64,
        allowed: impl Fn() -> bool + Send + Sync,
    ) -> Result<Connection, ApplicationError> {
        self.desktop_connection_intent_attempt_guarded(options, now_unix, false, allowed)
            .await
    }

    #[cfg(not(target_os = "android"))]
    pub async fn desktop_connection_intent_attempt_guarded(
        &self,
        options: ConnectOptions,
        now_unix: i64,
        reserve: bool,
        allowed: impl Fn() -> bool + Send + Sync,
    ) -> Result<Connection, ApplicationError> {
        let cancel_epoch = self.core.start_cancellation_epoch();
        self.desktop_connection_intent_attempt_at_epoch(
            options,
            now_unix,
            reserve,
            cancel_epoch,
            &allowed,
        )
        .await
    }

    #[cfg(not(target_os = "android"))]
    pub async fn desktop_connection_intent_attempt_at_epoch(
        &self,
        mut options: ConnectOptions,
        now_unix: i64,
        reserve: bool,
        cancel_epoch: StartCancellationEpoch,
        admission: &dyn nelomai_client_core::StartAdmission,
    ) -> Result<Connection, ApplicationError> {
        let allowed = || admission.allows_start();
        self.core.check_start_cancellation(cancel_epoch)?;
        self.start_preflight.before_tunnel_start().await?;
        self.core.check_start_cancellation(cancel_epoch)?;
        let _lifecycle_guard = self.lifecycle_gate.lock().await;
        self.core.check_start_cancellation(cancel_epoch)?;
        self.start_preflight.check_start_barrier()?;
        if !allowed() {
            return Err(ApplicationError::RecoveryDeferred);
        }
        self.core.begin_start_attempt();
        options = options.normalized_for_layer();
        options.probes = if options.layer == Layer::Tic
            && options.tic_connection_mode == TicConnectionMode::Personal
        {
            Vec::new()
        } else {
            match self
                .refresh_probes_guarded(options.layer, options.egress_mode, now_unix, &allowed)
                .await
            {
                Ok(results) => results.probes,
                Err(_) => self
                    .cached_probes(options.layer, options.egress_mode, now_unix)
                    .map(|results| results.probes)
                    .unwrap_or_default(),
            }
        };
        let result = if allowed() {
            self.core
                .desktop_connection_intent_attempt_guarded(
                    options.clone(),
                    now_unix,
                    reserve && options.tic_connection_mode == TicConnectionMode::Dynamic,
                    cancel_epoch,
                    admission,
                )
                .await
                .map_err(Into::into)
        } else {
            Err(ApplicationError::RecoveryDeferred)
        };
        self.core.finish_start_attempt();
        result
    }

    #[cfg(not(target_os = "android"))]
    pub async fn compensate_stale_connection_intent_result(&self) -> Result<(), ApplicationError> {
        let _lifecycle_guard = self.lifecycle_gate.lock().await;
        self.core
            .compensate_stale_connection_intent_result()
            .await
            .map_err(Into::into)
    }

    #[cfg(not(target_os = "android"))]
    pub async fn replace_stalled_connection(
        &self,
        options: ConnectOptions,
        now_unix: i64,
    ) -> Result<Connection, ApplicationError> {
        self.replace_stalled_connection_guarded(options, now_unix, || true)
            .await
    }

    #[cfg(not(target_os = "android"))]
    pub async fn replace_stalled_connection_guarded(
        &self,
        options: ConnectOptions,
        now_unix: i64,
        allowed: impl Fn() -> bool + Send + Sync,
    ) -> Result<Connection, ApplicationError> {
        let epoch = self.core.start_cancellation_epoch();
        self.replace_stalled_connection_at_epoch(options, now_unix, epoch, &allowed)
            .await
    }

    #[cfg(not(target_os = "android"))]
    pub async fn replace_stalled_connection_at_epoch(
        &self,
        mut options: ConnectOptions,
        now_unix: i64,
        cancel_epoch: StartCancellationEpoch,
        admission: &dyn nelomai_client_core::StartAdmission,
    ) -> Result<Connection, ApplicationError> {
        let allowed = || admission.allows_start();
        self.core.check_start_cancellation(cancel_epoch)?;
        self.start_preflight.before_tunnel_start().await?;
        let _lifecycle_guard = self.lifecycle_gate.lock().await;
        self.core.check_start_cancellation(cancel_epoch)?;
        self.start_preflight.check_start_barrier()?;
        if !allowed() {
            return Err(ApplicationError::RecoveryDeferred);
        }
        self.core.begin_start_attempt();
        let result = async {
            options = options.normalized_for_layer();
            options.probes = if options.layer == Layer::Tic
                && options.tic_connection_mode == TicConnectionMode::Personal
            {
                Vec::new()
            } else {
                let probes = self
                    .refresh_probes_guarded(options.layer, options.egress_mode, now_unix, &allowed)
                    .await;
                if !allowed() {
                    return Err(ApplicationError::RecoveryDeferred);
                }
                probes?.probes
            };
            if !allowed() {
                return Err(ApplicationError::RecoveryDeferred);
            }
            self.core
                .replace_stalled_connection_guarded(options, now_unix, cancel_epoch, admission)
                .await
                .map_err(Into::into)
        }
        .await;
        self.core.finish_start_attempt();
        result
    }

    pub async fn active_recovery_options(&self) -> Option<ConnectOptions> {
        self.core.active_recovery_options().await
    }

    pub fn connection_recovery_transport(
        &self,
        lease_id: &str,
    ) -> Result<nelomai_client_core::RecoveryTransport, ApplicationError> {
        self.core
            .connection_recovery_transport(lease_id)
            .map_err(Into::into)
    }

    pub async fn refresh_probes(
        &self,
        layer: Layer,
        egress_mode: EgressMode,
        now_unix: i64,
    ) -> Result<ProbeResults, ApplicationError> {
        self.refresh_probes_guarded(layer, egress_mode, now_unix, &|| true)
            .await
    }

    async fn refresh_probes_guarded(
        &self,
        layer: Layer,
        egress_mode: EgressMode,
        now_unix: i64,
        allowed: &(impl Fn() -> bool + Sync),
    ) -> Result<ProbeResults, ApplicationError> {
        if !allowed() {
            return Err(ApplicationError::RecoveryDeferred);
        }
        if let Some(results) = self.fresh_probes(layer, egress_mode, now_unix) {
            return Ok(results);
        }

        let _guard = self.probe_gate.lock().await;
        if !allowed() {
            return Err(ApplicationError::RecoveryDeferred);
        }
        if let Some(results) = self.fresh_probes(layer, egress_mode, now_unix) {
            return Ok(results);
        }

        let candidates = self
            .load_server_candidates(layer, egress_mode, allowed)
            .await?;
        if !allowed() {
            return Err(ApplicationError::RecoveryDeferred);
        }
        let measured_at = timestamp(now_unix)?;
        let candidates = candidates
            .candidates
            .into_iter()
            .filter_map(|candidate| {
                if candidate.layer != layer {
                    return None;
                }
                let expires_at = OffsetDateTime::parse(&candidate.expires_at, &Rfc3339)
                    .ok()?
                    .unix_timestamp();
                if expires_at <= now_unix {
                    return None;
                }
                Some((candidate, expires_at))
            })
            .collect::<Vec<_>>();
        let measured = stream::iter(candidates.into_iter().map(|(candidate, expires_at)| {
            let api = self.api.clone();
            let measured_at = measured_at.clone();
            async move {
                if !allowed() {
                    return None;
                }
                let outcome = api.probe_candidate_latency_ms(&candidate.probe_url).await;
                let (latency_ms, failure_code) = match outcome {
                    Ok(latency_ms)
                        if latency_ms.is_finite() && latency_ms > 0.0 && latency_ms <= 10_000.0 =>
                    {
                        (Some(latency_ms), None)
                    }
                    Ok(_) => (None, Some(ProbeFailureCode::Unknown)),
                    Err(code) => (None, Some(code)),
                };
                Some((
                    ProbeResult {
                        candidate_id: candidate.candidate_id,
                        latency_ms,
                        failure_code,
                        measured_at,
                    },
                    expires_at,
                ))
            }
        }))
        .buffer_unordered(MAX_CONCURRENT_PROBES)
        .filter_map(std::future::ready)
        .collect::<Vec<_>>()
        .await;
        if !allowed() {
            return Err(ApplicationError::RecoveryDeferred);
        }
        let valid_until_unix = measured
            .iter()
            .map(|(_, expires_at)| *expires_at)
            .min()
            .unwrap_or_else(|| now_unix.saturating_add(PROBE_REFRESH_SECONDS));
        let probes = measured
            .into_iter()
            .map(|(result, _)| result)
            .collect::<Vec<_>>();
        let results = ProbeResults {
            layer,
            egress_mode,
            probes,
        };
        self.probe_cache
            .lock()
            .map_err(|_| ApplicationError::Storage)?
            .set(
                layer,
                egress_mode,
                Some(CachedProbes {
                    measured_at_unix: now_unix,
                    valid_until_unix,
                    results: results.clone(),
                }),
            );
        Ok(results)
    }

    pub async fn stop(&self) -> Result<Connection, ApplicationError> {
        self.core.signal_start_cancellation();
        let _lifecycle_guard = self.lifecycle_gate.lock().await;
        #[cfg(not(target_os = "android"))]
        {
            let result = Box::pin(self.core.stop_locally()).await;
            if result.is_ok() || self.core.has_pending_stop_cleanup().unwrap_or(false) {
                // Retain one permit if the scheduler is busy or has not started yet.
                self.pending_stop_wake.notify_one();
            }
            result.map_err(Into::into)
        }
        #[cfg(target_os = "android")]
        Box::pin(self.core.stop()).await.map_err(Into::into)
    }

    pub async fn local_stop_pending_cleanup(&self) -> bool {
        self.core.local_stop_pending_cleanup().await
    }

    pub fn signal_start_cancellation(&self) -> bool {
        self.core.signal_start_cancellation()
    }

    pub async fn wait_for_pending_stop(&self) {
        self.pending_stop_wake.notified().await;
    }

    pub async fn retry_pending_stop(
        &self,
    ) -> Result<Option<PendingStopCompletion>, ApplicationError> {
        let _lifecycle_guard = self.lifecycle_gate.lock().await;
        self.retry_pending_stop_locked(true, None, || true).await
    }

    /// Take the desktop intent snapshot under the same gate as native cleanup.
    /// An unpublished Start only defers inferred cleanup, not a journaled Stop.
    #[cfg(not(target_os = "android"))]
    pub async fn retry_pending_stop_observed<Context>(
        &self,
        observe: impl std::future::Future<Output = Option<Context>>,
    ) -> Result<Option<(Context, PendingStopCompletion)>, ApplicationError> {
        self.retry_pending_stop_observed_guarded(observe, None, || true)
            .await
    }

    #[cfg(not(target_os = "android"))]
    pub async fn retry_pending_stop_observed_guarded<Context>(
        &self,
        observe: impl std::future::Future<Output = Option<Context>>,
        wake_stamp: Option<i64>,
        inferred_stop_allowed: impl Fn() -> bool + Send + Sync + 'static,
    ) -> Result<Option<(Context, PendingStopCompletion)>, ApplicationError> {
        let _lifecycle_guard = self.lifecycle_gate.lock().await;
        let context = observe.await;
        let completion = self
            .retry_pending_stop_locked(context.is_some(), wake_stamp, inferred_stop_allowed)
            .await?;
        Ok(context.zip(completion))
    }

    async fn retry_pending_stop_locked(
        &self,
        infer_stop: bool,
        wake_stamp: Option<i64>,
        inferred_stop_allowed: impl Fn() -> bool + Send + Sync + 'static,
    ) -> Result<Option<PendingStopCompletion>, ApplicationError> {
        let cancel_epoch = self.core.start_cancellation_epoch();
        let pending_cleanup = self.core.has_pending_stop_cleanup()?;
        if !pending_cleanup && !infer_stop {
            return Ok(None);
        }
        let previous = if pending_cleanup && cfg!(target_os = "android") {
            None
        } else {
            Some(self.core.state().await)
        };
        if !pending_cleanup
            && previous
                .as_ref()
                .is_none_or(|state| state.phase != Phase::Stopping)
        {
            return Ok(None);
        }
        let pair = self.core.desktop_cleanup_scope();
        let Some(connection) = self
            .core
            .retry_pending_stop_cleanup_guarded(wake_stamp, inferred_stop_allowed)
            .await?
        else {
            return Ok(None);
        };
        // Both a terminal Stop and an explicit accepted background-cleanup
        // receipt can release local ownership. Core validates the native ACK
        // and panel response before removing this exact protected pair.
        let cleanup_confirmed = cfg!(not(target_os = "android"))
            && self.core.check_start_cancellation(cancel_epoch).is_ok()
            && matches!(self.core.desktop_cleanup_scope(), Ok(None))
            && matches!(self.core.has_pending_stop_cleanup(), Ok(false));
        // Single tunnels receive no pair receipt. Require the exact lease and
        // the completed cleanup phase before resuming that desktop intent.
        #[cfg(not(target_os = "android"))]
        let cleaned_singleton = cleanup_confirmed
            && matches!(&pair, Ok(None))
            && connection.session_id.is_none()
            && previous
                .and_then(|state| state.connection)
                .is_some_and(|active| {
                    active.session_id.is_none() && active.lease_id == connection.lease_id
                })
            && self.core.state().await.phase == Phase::Ready;
        Ok(Some(PendingStopCompletion {
            cleaned_pair: pair.ok().flatten().filter(|_| cleanup_confirmed),
            #[cfg(not(target_os = "android"))]
            cleaned_singleton,
            connection,
            cancel_epoch,
        }))
    }

    pub async fn stop_for_shutdown(&self) -> Result<Option<Connection>, ApplicationError> {
        let cancelled_pending_start = self.core.signal_start_cancellation();
        let _lifecycle_guard = self.lifecycle_gate.lock().await;
        let state = self.core.state().await;
        let pending = self.core.has_pending_stop_cleanup();
        #[cfg(not(target_os = "android"))]
        if state.connection.is_none() && matches!(pending, Ok(true)) {
            // Canonical cleanup of an already retired lease has no connection to return.
            return Box::pin(self.core.retry_pending_stop_cleanup())
                .await
                .map_err(Into::into);
        }
        if shutdown_requires_core_stop(state.phase, cancelled_pending_start) || pending? {
            return Box::pin(self.core.stop())
                .await
                .map(Some)
                .map_err(Into::into);
        }
        Ok(None)
    }

    pub fn reset_transport(&self) -> Result<(), ApplicationError> {
        self.api.reset_transport().map_err(Into::into)
    }

    pub async fn pin_stray(&self) -> Result<Connection, ApplicationError> {
        let _lifecycle_guard = self.lifecycle_gate.lock().await;
        self.core.pin_stray().await.map_err(Into::into)
    }

    pub async fn unpin_stray(
        &self,
        lease_id: &str,
        now_unix: i64,
    ) -> Result<Connection, ApplicationError> {
        let _lifecycle_guard = self.lifecycle_gate.lock().await;
        self.core
            .unpin_stray(lease_id, now_unix)
            .await
            .map_err(Into::into)
    }

    pub async fn start_saved_stray_offline(
        &self,
        now_unix: i64,
    ) -> Result<String, ApplicationError> {
        self.start_preflight.before_tunnel_start().await?;
        let _lifecycle_guard = self.lifecycle_gate.lock().await;
        self.start_preflight.check_start_barrier()?;
        self.core
            .start_saved_stray_offline(now_unix)
            .await
            .map_err(Into::into)
    }

    pub async fn current_access_token(&self) -> Result<AccessSnapshot, ApplicationError> {
        self.core.access_snapshot().await.map_err(Into::into)
    }

    async fn access_token(&self) -> Result<AccessSnapshot, ApplicationError> {
        self.current_access_token().await
    }

    async fn load_server_candidates(
        &self,
        layer: Layer,
        egress_mode: EgressMode,
        allowed: &(impl Fn() -> bool + Sync),
    ) -> Result<ServerCandidatesResponse, ApplicationError> {
        let access_token = self.access_token().await?;
        if !allowed() {
            return Err(ApplicationError::RecoveryDeferred);
        }
        match self
            .api
            .server_candidates(&access_token, layer, egress_mode)
            .await
        {
            Ok(response) => Ok(response),
            Err(CoreApiError::Unauthorized) if allowed() => {
                let access_token = self.core.refresh_access_token(&access_token).await?;
                if !allowed() {
                    return Err(ApplicationError::RecoveryDeferred);
                }
                self.api
                    .server_candidates(&access_token, layer, egress_mode)
                    .await
                    .map_err(Into::into)
            }
            Err(error) => Err(error.into()),
        }
    }

    fn fresh_probes(
        &self,
        layer: Layer,
        egress_mode: EgressMode,
        now_unix: i64,
    ) -> Option<ProbeResults> {
        self.probe_cache
            .lock()
            .ok()?
            .get(layer, egress_mode)
            .filter(|cached| {
                now_unix.saturating_sub(cached.measured_at_unix) < PROBE_REFRESH_SECONDS
                    && now_unix < cached.valid_until_unix
                    && cached
                        .results
                        .probes
                        .iter()
                        .any(|probe| probe.latency_ms.is_some())
            })
            .map(|cached| cached.results.clone())
    }

    fn cached_probes(
        &self,
        layer: Layer,
        egress_mode: EgressMode,
        now_unix: i64,
    ) -> Option<ProbeResults> {
        self.probe_cache
            .lock()
            .ok()?
            .get(layer, egress_mode)
            .filter(|cached| {
                now_unix < cached.valid_until_unix
                    && cached
                        .results
                        .probes
                        .iter()
                        .any(|probe| probe.latency_ms.is_some())
            })
            .map(|cached| cached.results.clone())
    }

    fn clear_probe_cache(&self) -> Result<(), ApplicationError> {
        *self
            .probe_cache
            .lock()
            .map_err(|_| ApplicationError::Storage)? = ProbeCache::default();
        Ok(())
    }
}

fn timestamp(now_unix: i64) -> Result<String, ApplicationError> {
    OffsetDateTime::from_unix_timestamp(now_unix)
        .map_err(|_| ApplicationError::Clock)?
        .format(&Rfc3339)
        .map_err(|_| ApplicationError::Clock)
}

fn shutdown_requires_core_stop(phase: Phase, cancelled_pending_start: bool) -> bool {
    cancelled_pending_start
        || matches!(
            phase,
            Phase::Connected | Phase::Connecting | Phase::Stopping
        )
}

#[cfg(test)]
mod tests {
    use super::shutdown_requires_core_stop;
    use nelomai_client_core::Phase;

    #[test]
    fn shutdown_stops_unresolved_start_even_when_the_visible_phase_is_not_connecting() {
        assert!(shutdown_requires_core_stop(Phase::Ready, true));
        assert!(shutdown_requires_core_stop(Phase::ServerUnavailable, true));
        assert!(!shutdown_requires_core_stop(Phase::Ready, false));
    }

    #[tokio::test]
    async fn desktop_state_bypasses_lifecycle_and_wakes_linux_cleanup_once_per_crash() {
        use super::*;
        use nelomai_client_api::RuntimeAuthState;
        use nelomai_client_storage::{RuntimePaths, RuntimeStateV1, StorageError};
        use nelomai_client_tunnel::{TunnelError, TunnelStartRequest, TunnelStatus};
        use nelomai_contracts::RuntimeSlot;
        use std::sync::atomic::{AtomicU8, Ordering};

        struct RuntimeStore(RuntimePaths);
        impl RuntimeStateStore for RuntimeStore {
            fn paths(&self) -> &RuntimePaths {
                &self.0
            }
            fn load(&self) -> Result<Option<RuntimeStateV1>, StorageError> {
                Ok(Some(RuntimeStateV1::empty(&self.0, false)))
            }
            fn save(&self, _: &RuntimeStateV1) -> Result<(), StorageError> {
                panic!("foreground reads cannot write runtime state")
            }
        }
        struct ActiveAuth;
        #[async_trait]
        impl RuntimeAuthProvider for ActiveAuth {
            async fn state(&self) -> Result<RuntimeAuthState, CoreError> {
                Ok(RuntimeAuthState::Active)
            }
            async fn access(
                &self,
                _: Option<&AccessSnapshot>,
            ) -> Result<AccessSnapshot, CoreError> {
                panic!("foreground reads cannot refresh auth or obtain network access")
            }
            async fn login(&self, _: RuntimeLogin) -> Result<AccessSnapshot, CoreError> {
                panic!("no login")
            }
            async fn logout(&self) -> Result<(), CoreError> {
                panic!("no logout")
            }
        }
        struct NativeTunnel(AtomicU8);
        #[async_trait]
        impl TunnelController for NativeTunnel {
            async fn start(&self, _: TunnelStartRequest) -> Result<(), TunnelError> {
                panic!("no start")
            }
            async fn stop(&self) -> Result<(), TunnelError> {
                self.0.store(0, Ordering::SeqCst);
                Ok(())
            }
            async fn status(&self) -> Result<TunnelStatus, TunnelError> {
                Ok(match self.0.load(Ordering::SeqCst) {
                    1 => TunnelStatus::Running,
                    2 => TunnelStatus::Failed,
                    _ => TunnelStatus::Stopped,
                })
            }
        }
        let tunnel = Arc::new(NativeTunnel(AtomicU8::new(0)));
        let local = CoreLocalStop::new(tunnel.clone());
        local.stop_local_for_transition().await.unwrap();
        let application = ClientApplication::new(
            Arc::new(ClientApi::new("http://127.0.0.1:9").unwrap()),
            Arc::new(RuntimeStore(
                RuntimePaths::new(
                    "/synthetic-no-filesystem-access",
                    RuntimeSlot::Stable,
                    "0.2.16",
                )
                .unwrap(),
            )),
            Arc::new(ActiveAuth),
            local,
            Arc::new(nelomai_client_core::NoopLogger),
        );
        let _stalled_bootstrap = application.lifecycle_gate.lock().await;
        tunnel.0.store(1, Ordering::SeqCst);
        let observation = application.begin_foreground_observation().await;
        let state = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            application.foreground_state_guarded(
                observation,
                Some(nelomai_client_core::NativeConnectionIntent {
                    generation: 1,
                    desired_active: true,
                }),
                || true,
            ),
        )
        .await
        .expect("foreground must bypass stalled bootstrap");
        assert_eq!(state.phase, Phase::Connected);
        assert!(state.connection.is_none());
        for status in [0, 2] {
            tunnel.0.store(1, Ordering::SeqCst);
            let observation = application.begin_foreground_observation().await;
            assert_eq!(
                application
                    .foreground_state_guarded(observation, None, || true)
                    .await
                    .phase,
                Phase::Connected
            );
            tunnel.0.store(status, Ordering::SeqCst);
            let stale = application.begin_foreground_observation().await;
            let current = application.begin_foreground_observation().await;
            assert_eq!(
                application
                    .foreground_state_guarded(stale, None, || true)
                    .await
                    .phase,
                Phase::Connected
            );
            assert!(tokio::time::timeout(
                std::time::Duration::from_millis(10),
                application.wait_for_pending_stop()
            )
            .await
            .is_err());
            let state =
                tokio::time::timeout(std::time::Duration::from_millis(100), application.state())
                    .await
                    .expect("desktop state must bypass stalled bootstrap");
            assert_eq!(state.phase, Phase::Stopping);
            let wake = tokio::time::timeout(
                std::time::Duration::from_millis(10),
                application.wait_for_pending_stop(),
            )
            .await;
            assert_eq!(
                wake.is_ok(),
                cfg!(target_os = "linux"),
                "desktop state observing stopped/failed native must wake Linux cleanup once"
            );
            // This captured Connected observation is now stale. The guarded
            // wrapper must not send a second cleanup hint for its late reply.
            assert_eq!(
                application
                    .foreground_state_guarded(current, None, || true)
                    .await
                    .phase,
                Phase::Stopping
            );
            assert!(
                tokio::time::timeout(
                    std::time::Duration::from_millis(10),
                    application.wait_for_pending_stop()
                )
                .await
                .is_err(),
                "late guarded observations must not duplicate the desktop state wake"
            );
            assert_eq!(application.state().await.phase, Phase::Stopping);
            assert!(
                tokio::time::timeout(
                    std::time::Duration::from_millis(10),
                    application.wait_for_pending_stop()
                )
                .await
                .is_err(),
                "Stopping polls must not wake cleanup again"
            );
        }
    }
}
