use async_trait::async_trait;
use futures_util::{stream, StreamExt};
use nelomai_client_api::{
    BackgroundTokenResponse, ClientApi, DiagnosticUploadRequest, DiagnosticUploadResponse,
    LoginRequest, TokenResponse,
};
use nelomai_client_core::{
    ClientCore, ConnectOptions, ConnectionMetricsContext, CoreApi, CoreApiError, CoreError,
    CoreLogger, CoreState, Phase, PhysicalNetworkPollOutcome, SplitTunnelSyncOutcome,
};
use nelomai_client_storage::{MemorySplitTunnelStore, SecretStore, SplitTunnelStore, StoredAuth};
use nelomai_client_tunnel::{TunnelController, TunnelError};
use nelomai_contracts::{
    AppNotificationList, AppNotificationReadResponse, BindPeerRequest, Bootstrap, Connection,
    Layer, PeerBindingResponse, PeerOptions, Platform, ProbeFailureCode, ProbeResult, ProbeResults,
    ServerCandidatesResponse, SplitTunnelAddressRuleScope, SplitTunnelAddressRuleUpdate,
    SplitTunnelPolicy, SplitTunnelSelectedPackage, SplitTunnelSettingsUpdate, TicConnectionMode,
};
use std::sync::{Arc, Mutex as StdMutex};
use thiserror::Error;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::sync::Mutex as AsyncMutex;

const PROBE_REFRESH_SECONDS: i64 = 300;
const MAX_CONCURRENT_PROBES: usize = 4;

pub struct LoginParameters {
    pub login: String,
    pub password: String,
    pub device_name: String,
    pub platform: Platform,
    pub platform_version: Option<String>,
    pub architecture: String,
    pub app_version: String,
}

#[async_trait]
pub trait ApplicationApi: CoreApi {
    async fn login(&self, request: &LoginRequest) -> Result<TokenResponse, CoreApiError>;
    async fn peer_options(&self, access_token: &str) -> Result<PeerOptions, CoreApiError>;
    async fn bind_peer(
        &self,
        access_token: &str,
        request: &BindPeerRequest,
    ) -> Result<PeerBindingResponse, CoreApiError>;
    async fn unbind_peer(&self, access_token: &str) -> Result<PeerBindingResponse, CoreApiError>;
    async fn server_candidates(
        &self,
        access_token: &str,
        layer: Layer,
    ) -> Result<ServerCandidatesResponse, CoreApiError>;
    async fn probe_latency_ms(&self, probe_url: &str) -> Option<f64>;
    async fn probe_candidate_latency_ms(&self, probe_url: &str) -> Result<f64, ProbeFailureCode> {
        self.probe_latency_ms(probe_url)
            .await
            .ok_or(ProbeFailureCode::Unknown)
    }
    async fn logout(&self, access_token: &str) -> Result<(), CoreApiError>;
    async fn background_token(
        &self,
        _access_token: &str,
    ) -> Result<BackgroundTokenResponse, CoreApiError> {
        Err(CoreApiError::Retryable)
    }
    async fn upload_diagnostics(
        &self,
        _access_token: &str,
        _request: &DiagnosticUploadRequest,
    ) -> Result<DiagnosticUploadResponse, CoreApiError> {
        Err(CoreApiError::Retryable)
    }
    async fn notifications(
        &self,
        _access_token: &str,
        _cursor: Option<i64>,
        _limit: u32,
    ) -> Result<AppNotificationList, CoreApiError> {
        Err(CoreApiError::Retryable)
    }
    async fn mark_notification_read(
        &self,
        _access_token: &str,
        _message_id: i64,
    ) -> Result<AppNotificationReadResponse, CoreApiError> {
        Err(CoreApiError::Retryable)
    }
    async fn mark_all_notifications_read(
        &self,
        _access_token: &str,
    ) -> Result<AppNotificationReadResponse, CoreApiError> {
        Err(CoreApiError::Retryable)
    }
    async fn register_push_token(
        &self,
        _access_token: &str,
        _token: &str,
    ) -> Result<(), CoreApiError> {
        Err(CoreApiError::Retryable)
    }
    async fn unregister_push_token(&self, _access_token: &str) -> Result<(), CoreApiError> {
        Ok(())
    }
}

#[async_trait]
impl ApplicationApi for ClientApi {
    async fn login(&self, request: &LoginRequest) -> Result<TokenResponse, CoreApiError> {
        ClientApi::login(self, request).await.map_err(Into::into)
    }

    async fn peer_options(&self, access_token: &str) -> Result<PeerOptions, CoreApiError> {
        ClientApi::peer_options(self, access_token)
            .await
            .map_err(Into::into)
    }

    async fn bind_peer(
        &self,
        access_token: &str,
        request: &BindPeerRequest,
    ) -> Result<PeerBindingResponse, CoreApiError> {
        ClientApi::bind_peer(self, access_token, request)
            .await
            .map_err(Into::into)
    }

    async fn unbind_peer(&self, access_token: &str) -> Result<PeerBindingResponse, CoreApiError> {
        ClientApi::unbind_peer(self, access_token)
            .await
            .map_err(Into::into)
    }

    async fn server_candidates(
        &self,
        access_token: &str,
        layer: Layer,
    ) -> Result<ServerCandidatesResponse, CoreApiError> {
        ClientApi::server_candidates(self, access_token, layer)
            .await
            .map_err(Into::into)
    }

    async fn probe_latency_ms(&self, probe_url: &str) -> Option<f64> {
        ClientApi::probe_latency_ms(self, probe_url).await
    }

    async fn probe_candidate_latency_ms(&self, probe_url: &str) -> Result<f64, ProbeFailureCode> {
        ClientApi::probe_candidate_latency_ms(self, probe_url).await
    }

    async fn logout(&self, access_token: &str) -> Result<(), CoreApiError> {
        ClientApi::logout(self, access_token)
            .await
            .map(|_| ())
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

    async fn upload_diagnostics(
        &self,
        access_token: &str,
        request: &DiagnosticUploadRequest,
    ) -> Result<DiagnosticUploadResponse, CoreApiError> {
        ClientApi::upload_diagnostics(self, access_token, request)
            .await
            .map_err(Into::into)
    }

    async fn notifications(
        &self,
        access_token: &str,
        cursor: Option<i64>,
        limit: u32,
    ) -> Result<AppNotificationList, CoreApiError> {
        ClientApi::notifications(self, access_token, cursor, limit)
            .await
            .map_err(Into::into)
    }

    async fn mark_notification_read(
        &self,
        access_token: &str,
        message_id: i64,
    ) -> Result<AppNotificationReadResponse, CoreApiError> {
        ClientApi::mark_notification_read(self, access_token, message_id)
            .await
            .map_err(Into::into)
    }

    async fn mark_all_notifications_read(
        &self,
        access_token: &str,
    ) -> Result<AppNotificationReadResponse, CoreApiError> {
        ClientApi::mark_all_notifications_read(self, access_token)
            .await
            .map_err(Into::into)
    }

    async fn register_push_token(
        &self,
        access_token: &str,
        token: &str,
    ) -> Result<(), CoreApiError> {
        ClientApi::register_push_token(self, access_token, token)
            .await
            .map(|_| ())
            .map_err(Into::into)
    }

    async fn unregister_push_token(&self, access_token: &str) -> Result<(), CoreApiError> {
        ClientApi::unregister_push_token(self, access_token)
            .await
            .map(|_| ())
            .map_err(Into::into)
    }
}

#[derive(Debug, Error)]
pub enum ApplicationError {
    #[error("защищённое хранилище недоступно")]
    Storage,
    #[error("не удалось определить текущее время")]
    Clock,
    #[error(transparent)]
    Api(#[from] CoreApiError),
    #[error(transparent)]
    Core(#[from] CoreError),
}

#[derive(Clone)]
struct CachedProbes {
    measured_at_unix: i64,
    valid_until_unix: i64,
    results: ProbeResults,
}

#[derive(Default)]
struct ProbeCache {
    tic: Option<CachedProbes>,
    stray: Option<CachedProbes>,
}

impl ProbeCache {
    fn get(&self, layer: Layer) -> Option<&CachedProbes> {
        match layer {
            Layer::Tic => self.tic.as_ref(),
            Layer::Stray => self.stray.as_ref(),
        }
    }

    fn set(&mut self, layer: Layer, value: CachedProbes) {
        match layer {
            Layer::Tic => self.tic = Some(value),
            Layer::Stray => self.stray = Some(value),
        }
    }
}

pub struct ClientApplication<A, S, T, L> {
    api: Arc<A>,
    store: Arc<S>,
    tunnel: Arc<T>,
    core: ClientCore<A, S, T, L>,
    lifecycle_gate: AsyncMutex<()>,
    probe_gate: AsyncMutex<()>,
    probe_cache: StdMutex<ProbeCache>,
}

impl<A, S, T, L> ClientApplication<A, S, T, L>
where
    A: ApplicationApi,
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
        let core = ClientCore::with_split_tunnel_store(
            api.clone(),
            store.clone(),
            split_tunnel_store,
            tunnel.clone(),
            logger,
        );
        Self {
            api,
            store,
            tunnel,
            core,
            lifecycle_gate: AsyncMutex::new(()),
            probe_gate: AsyncMutex::new(()),
            probe_cache: StdMutex::new(ProbeCache::default()),
        }
    }

    pub async fn login(
        &self,
        parameters: LoginParameters,
        now_unix: i64,
    ) -> Result<Bootstrap, ApplicationError> {
        let _lifecycle_guard = self.lifecycle_gate.lock().await;
        let install_secret = self
            .store
            .load()
            .map_err(|_| ApplicationError::Storage)?
            .unwrap_or_else(StoredAuth::new_install)
            .install_secret;
        let response = self
            .api
            .login(&LoginRequest {
                login: parameters.login,
                password: parameters.password,
                install_secret: install_secret.clone(),
                device_name: parameters.device_name,
                platform: parameters.platform,
                platform_version: parameters.platform_version,
                architecture: parameters.architecture,
                app_version: parameters.app_version,
            })
            .await?;
        let _probe_guard = self.probe_gate.lock().await;
        if let Err(TunnelError::Backend(code)) = self.tunnel.stop().await {
            self.core
                .record_tunnel_unavailable("tunnel.stop_before_login.unavailable", code);
        }
        self.clear_probe_cache()?;
        self.store
            .save(&StoredAuth {
                install_secret,
                access_token: Some(response.access_token),
                refresh_token: Some(response.refresh_token),
                saved_connection: None,
                pinned_connection: None,
                pending_start: None,
                compatibility: None,
            })
            .map_err(|_| ApplicationError::Storage)?;
        self.core.reset_split_tunnel_state().await?;
        self.core.bootstrap(now_unix).await.map_err(Into::into)
    }

    pub async fn peer_options(&self) -> Result<PeerOptions, ApplicationError> {
        let access_token = self.access_token()?;
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

    pub async fn probe_connection_latency_ms(&self, probe_url: &str) -> Option<f64> {
        self.api.probe_latency_ms(probe_url).await
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
        self.core
            .synchronize_split_tunnel(now_unix, force_full)
            .await
            .map_err(Into::into)
    }

    pub async fn save_split_tunnel_settings(
        &self,
        request: &SplitTunnelSettingsUpdate,
        now_unix: i64,
    ) -> Result<SplitTunnelPolicy, ApplicationError> {
        self.core
            .save_split_tunnel_settings(request, now_unix)
            .await
            .map_err(Into::into)
    }

    pub async fn add_split_tunnel_address_rule(
        &self,
        request: &SplitTunnelAddressRuleUpdate,
        now_unix: i64,
    ) -> Result<SplitTunnelPolicy, ApplicationError> {
        self.core
            .add_split_tunnel_address_rule(request, now_unix)
            .await
            .map_err(Into::into)
    }

    pub async fn remove_split_tunnel_address_rule(
        &self,
        rule_id: i64,
        scope: SplitTunnelAddressRuleScope,
        now_unix: i64,
    ) -> Result<SplitTunnelPolicy, ApplicationError> {
        self.core
            .remove_split_tunnel_address_rule(rule_id, scope, now_unix)
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

    pub fn cached_split_tunnel_policy(
        &self,
    ) -> Result<Option<SplitTunnelPolicy>, ApplicationError> {
        self.core.cached_split_tunnel_policy().map_err(Into::into)
    }

    pub async fn split_tunnel_capabilities(
        &self,
    ) -> Result<nelomai_client_tunnel::TunnelCapabilities, ApplicationError> {
        self.core
            .split_tunnel_capabilities()
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
        let _lifecycle_guard = self.lifecycle_gate.lock().await;
        self.core.prepare_binding_change().await?;
        let access_token = self.access_token()?;
        let _probe_guard = self.probe_gate.lock().await;
        let response = match self.api.bind_peer(&access_token, &request).await {
            Ok(response) => response,
            Err(CoreApiError::Unauthorized) => {
                let access_token = self.core.refresh_access_token(&access_token).await?;
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
        let access_token = self.access_token()?;
        let response = match self.api.unbind_peer(&access_token).await {
            Ok(response) => response,
            Err(CoreApiError::Unauthorized) => {
                let access_token = self.core.refresh_access_token(&access_token).await?;
                self.api.unbind_peer(&access_token).await?
            }
            Err(error) => return Err(error.into()),
        };
        self.core.complete_unbind().await?;
        self.clear_probe_cache()?;
        Ok(response)
    }

    pub async fn logout(&self) -> Result<(), ApplicationError> {
        let _lifecycle_guard = self.lifecycle_gate.lock().await;
        let _probe_guard = self.probe_gate.lock().await;
        if let Ok(access_token) = self.access_token() {
            let _ = self.api.unregister_push_token(&access_token).await;
            let _ = self.api.logout(&access_token).await;
        }
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
        let access_token = self.access_token()?;
        match self.api.background_token(&access_token).await {
            Ok(response) => Ok(Some(response)),
            Err(CoreApiError::Unauthorized) => {
                let access_token = self.core.refresh_access_token(&access_token).await?;
                self.api
                    .background_token(&access_token)
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
        let access_token = self.access_token()?;
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
        let access_token = self.access_token()?;
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
        let access_token = self.access_token()?;
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
        let access_token = self.access_token()?;
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
        let access_token = self.access_token()?;
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
        let access_token = self.access_token()?;
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
        self.core.state().await
    }

    pub async fn connection_metrics_context(&self) -> Option<ConnectionMetricsContext> {
        self.core.connection_metrics_context().await
    }

    pub fn record_tunnel_unavailable(&self, kind: &'static str, code: String) {
        self.core.record_tunnel_unavailable(kind, code);
    }

    pub async fn reconcile_external_tunnel_state(&self) -> CoreState {
        self.core.reconcile_external_tunnel_state().await
    }

    pub async fn bootstrap(&self, now_unix: i64) -> Result<Bootstrap, ApplicationError> {
        let _lifecycle_guard = self.lifecycle_gate.lock().await;
        self.core.bootstrap(now_unix).await.map_err(Into::into)
    }

    pub async fn start(
        &self,
        mut options: ConnectOptions,
        now_unix: i64,
    ) -> Result<Connection, ApplicationError> {
        let _lifecycle_guard = self.lifecycle_gate.lock().await;
        options.probes = if options.layer == Layer::Tic
            && options.tic_connection_mode == TicConnectionMode::Personal
        {
            Vec::new()
        } else {
            match self.refresh_probes(options.layer, now_unix).await {
                Ok(results) => results.probes,
                Err(_) => self
                    .cached_probes(options.layer, now_unix)
                    .map(|results| results.probes)
                    .unwrap_or_default(),
            }
        };
        self.core.start(options, now_unix).await.map_err(Into::into)
    }

    pub async fn start_without_probe_refresh(
        &self,
        mut options: ConnectOptions,
        now_unix: i64,
    ) -> Result<Connection, ApplicationError> {
        let _lifecycle_guard = self.lifecycle_gate.lock().await;
        options.probes.clear();
        self.core.start(options, now_unix).await.map_err(Into::into)
    }

    pub async fn refresh_probes(
        &self,
        layer: Layer,
        now_unix: i64,
    ) -> Result<ProbeResults, ApplicationError> {
        if let Some(results) = self.fresh_probes(layer, now_unix) {
            return Ok(results);
        }

        let _guard = self.probe_gate.lock().await;
        if let Some(results) = self.fresh_probes(layer, now_unix) {
            return Ok(results);
        }

        let candidates = self.load_server_candidates(layer).await?;
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
                (
                    ProbeResult {
                        candidate_id: candidate.candidate_id,
                        latency_ms,
                        failure_code,
                        measured_at,
                    },
                    expires_at,
                )
            }
        }))
        .buffer_unordered(MAX_CONCURRENT_PROBES)
        .collect::<Vec<_>>()
        .await;
        let valid_until_unix = measured
            .iter()
            .map(|(_, expires_at)| *expires_at)
            .min()
            .unwrap_or_else(|| now_unix.saturating_add(PROBE_REFRESH_SECONDS));
        let probes = measured
            .into_iter()
            .map(|(result, _)| result)
            .collect::<Vec<_>>();
        let results = ProbeResults { layer, probes };
        self.probe_cache
            .lock()
            .map_err(|_| ApplicationError::Storage)?
            .set(
                layer,
                CachedProbes {
                    measured_at_unix: now_unix,
                    valid_until_unix,
                    results: results.clone(),
                },
            );
        Ok(results)
    }

    pub async fn stop(&self) -> Result<Connection, ApplicationError> {
        let _lifecycle_guard = self.lifecycle_gate.lock().await;
        self.core.stop().await.map_err(Into::into)
    }

    pub async fn retry_pending_stop(&self) -> Result<Option<Connection>, ApplicationError> {
        let _lifecycle_guard = self.lifecycle_gate.lock().await;
        if self.core.state().await.phase != Phase::Stopping {
            return Ok(None);
        }
        self.core.stop().await.map(Some).map_err(Into::into)
    }

    pub async fn stop_for_shutdown(&self) -> Result<Option<Connection>, ApplicationError> {
        let _lifecycle_guard = self.lifecycle_gate.lock().await;
        let state = self.core.state().await;
        if matches!(
            state.phase,
            nelomai_client_core::Phase::Connected
                | nelomai_client_core::Phase::Connecting
                | nelomai_client_core::Phase::Stopping
        ) {
            return self.core.stop().await.map(Some).map_err(Into::into);
        }
        Ok(None)
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
        self.core
            .start_saved_stray_offline(now_unix)
            .await
            .map_err(Into::into)
    }

    pub fn current_access_token(&self) -> Result<String, ApplicationError> {
        self.store
            .load()
            .map_err(|_| ApplicationError::Storage)?
            .and_then(|stored| stored.access_token)
            .ok_or(ApplicationError::Core(CoreError::SignedOut))
    }

    fn access_token(&self) -> Result<String, ApplicationError> {
        self.current_access_token()
    }

    async fn load_server_candidates(
        &self,
        layer: Layer,
    ) -> Result<ServerCandidatesResponse, ApplicationError> {
        let access_token = self.access_token()?;
        match self.api.server_candidates(&access_token, layer).await {
            Ok(response) => Ok(response),
            Err(CoreApiError::Unauthorized) => {
                let access_token = self.core.refresh_access_token(&access_token).await?;
                self.api
                    .server_candidates(&access_token, layer)
                    .await
                    .map_err(Into::into)
            }
            Err(error) => Err(error.into()),
        }
    }

    fn fresh_probes(&self, layer: Layer, now_unix: i64) -> Option<ProbeResults> {
        self.probe_cache
            .lock()
            .ok()?
            .get(layer)
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

    fn cached_probes(&self, layer: Layer, now_unix: i64) -> Option<ProbeResults> {
        self.probe_cache
            .lock()
            .ok()?
            .get(layer)
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
