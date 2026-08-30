use futures_util::StreamExt;
use nelomai_contracts::{
    Access, ApiVersion, AppNotificationList, AppNotificationReadResponse, BindPeerRequest,
    Bootstrap, ConnectionIntentCapabilityResponse, ConnectionOperationRequest,
    ConnectionOperationResponse, ConnectionStartRequest, ConnectionStartResponse, EgressMode,
    ErrorPayload, Layer, OperationReconcileRequest, OperationReconcileResponse,
    PeerBindingResponse, PeerOptions, Platform, ProbeFailureCode, PushRegistrationRequest,
    PushRegistrationResponse, RedundantCandidateCommitRequest, RedundantRoleRequest,
    RedundantRoleResponse, RedundantSessionResponse, RedundantStandbyAcquireRequest,
    RedundantStandbyAcquireResponse, RedundantStandbyReleaseRequest, RedundantStopRequest,
    ServerCandidatesResponse, ServerSelectionRequest, ServerSelectionResponse,
    SplitTunnelAddressRuleScope, SplitTunnelAddressRuleUpdate, SplitTunnelApplyResult,
    SplitTunnelPolicy, SplitTunnelRevision, SplitTunnelSettingsUpdate, API_PREFIX,
};
use reqwest::{
    header::{HeaderValue, InvalidHeaderValue, AUTHORIZATION, CONTENT_TYPE, RETRY_AFTER},
    Client as HttpClient, RequestBuilder, Response, StatusCode, Url,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use thiserror::Error;

const SPLIT_TUNNEL_POLICY_RESPONSE_LIMIT: usize = 1024 * 1024;
const SPLIT_TUNNEL_SETTINGS_REQUEST_LIMIT: usize = 256 * 1024;
const SPLIT_TUNNEL_SELECTED_PACKAGES_LIMIT: usize = 512;
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct LoginRequest {
    pub login: String,
    pub password: String,
    pub install_secret: String,
    pub device_name: String,
    pub platform: Platform,
    pub platform_version: Option<String>,
    pub architecture: String,
    pub app_version: String,
}

impl fmt::Debug for LoginRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoginRequest")
            .field("login", &self.login)
            .field("password", &"<redacted>")
            .field("install_secret", &"<redacted>")
            .field("device_name", &self.device_name)
            .field("platform", &self.platform)
            .field("platform_version", &self.platform_version)
            .field("architecture", &self.architecture)
            .field("app_version", &self.app_version)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

impl fmt::Debug for RefreshRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RefreshRequest")
            .field("refresh_token", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AuthDevice {
    pub id: String,
    pub name: String,
    pub platform: Platform,
}

#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct TokenResponse {
    pub api_version: ApiVersion,
    pub request_id: String,
    pub token_type: String,
    pub access_token: String,
    pub access_expires_in: u64,
    pub refresh_token: String,
    pub refresh_expires_in: u64,
    pub access: Access,
    pub device: AuthDevice,
}

#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct BackgroundTokenResponse {
    pub api_version: ApiVersion,
    pub request_id: String,
    pub token: String,
    pub expires_in: u64,
}

impl fmt::Debug for BackgroundTokenResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackgroundTokenResponse")
            .field("api_version", &self.api_version)
            .field("request_id", &self.request_id)
            .field("token", &"<redacted>")
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

impl fmt::Debug for TokenResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokenResponse")
            .field("api_version", &self.api_version)
            .field("request_id", &self.request_id)
            .field("token_type", &self.token_type)
            .field("access_token", &"<redacted>")
            .field("access_expires_in", &self.access_expires_in)
            .field("refresh_token", &"<redacted>")
            .field("refresh_expires_in", &self.refresh_expires_in)
            .field("access", &self.access)
            .field("device", &self.device)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SuccessResponse {
    pub api_version: ApiVersion,
    pub request_id: String,
    pub ok: bool,
}

#[derive(Clone, Deserialize, PartialEq, Eq, Serialize)]
pub struct DiagnosticUploadRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report_id: Option<String>,
    pub trigger: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel_session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval_started_at_unix: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval_ended_at_unix: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel_running: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_lease_id: Option<String>,
    pub generated_at_unix: i64,
    pub app_version: String,
    pub platform_version: Option<String>,
    pub architecture: String,
    pub application_log: String,
    pub helper_log: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_incidents: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_usage: Option<DiagnosticResourceUsage>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
pub struct DiagnosticResourceUsage {
    pub measurement_mode: String,
    pub session_duration_ms: u64,
    pub components: Vec<DiagnosticResourceComponent>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
pub struct DiagnosticResourceComponent {
    pub component: String,
    pub source: String,
    pub process_id: Option<u64>,
    pub process_name: Option<String>,
    pub cpu_user_ms: Option<u64>,
    pub cpu_system_ms: Option<u64>,
    pub cpu_average_basis_points: Option<u64>,
    pub current_resident_memory_bytes: Option<u64>,
    pub peak_resident_memory_bytes: Option<u64>,
    pub current_proportional_memory_bytes: Option<u64>,
    pub current_private_dirty_memory_bytes: Option<u64>,
    pub read_bytes: Option<u64>,
    pub write_bytes: Option<u64>,
    pub page_faults: Option<u64>,
    pub minor_page_faults: Option<u64>,
    pub major_page_faults: Option<u64>,
    pub voluntary_context_switches: Option<u64>,
    pub involuntary_context_switches: Option<u64>,
    pub network_rx_bytes: Option<u64>,
    pub network_tx_bytes: Option<u64>,
    pub cpu_charge_milliamp_milliseconds: Option<u64>,
    pub mobile_charge_milliamp_milliseconds: Option<u64>,
    pub wifi_charge_milliamp_milliseconds: Option<u64>,
}

impl fmt::Debug for DiagnosticUploadRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiagnosticUploadRequest")
            .field("report_id", &self.report_id)
            .field("trigger", &self.trigger)
            .field("tunnel_session_id", &self.tunnel_session_id)
            .field("sequence", &self.sequence)
            .field("connection_lease_id", &self.connection_lease_id)
            .field("generated_at_unix", &self.generated_at_unix)
            .field("app_version", &self.app_version)
            .field("platform_version", &self.platform_version)
            .field("architecture", &self.architecture)
            .field("application_log", &"<redacted>")
            .field(
                "helper_log",
                &self.helper_log.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "network_incidents",
                &self.network_incidents.as_ref().map(|_| "<redacted>"),
            )
            .field("resource_usage", &self.resource_usage)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticUploadResponse {
    pub api_version: ApiVersion,
    pub request_id: String,
    pub report_id: String,
    pub received_bytes: u64,
}

#[derive(Debug, Error)]
pub enum ClientApiError {
    #[error("invalid panel URL: {0}")]
    InvalidBaseUrl(String),
    #[error("request failed: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("invalid application version header")]
    InvalidAppVersion(#[from] InvalidHeaderValue),
    #[error("{code}: {message}")]
    Api {
        status: StatusCode,
        request_id: String,
        code: String,
        message: String,
        retry_after_seconds: Option<u64>,
    },
    #[error("panel returned an invalid error response ({status})")]
    InvalidErrorResponse { status: StatusCode },
    #[error("{code}")]
    InvalidPayload { code: &'static str },
    #[error("{code}: payload exceeds the {limit_bytes}-byte limit")]
    PayloadTooLarge {
        code: &'static str,
        limit_bytes: usize,
    },
}

impl ClientApiError {
    pub fn stable_code(&self) -> Option<&str> {
        match self {
            Self::Api { code, .. } => Some(code),
            Self::InvalidPayload { code } | Self::PayloadTooLarge { code, .. } => Some(code),
            _ => None,
        }
    }

    pub fn retry_after_seconds(&self) -> Option<u64> {
        match self {
            Self::Api {
                retry_after_seconds,
                ..
            } => *retry_after_seconds,
            _ => None,
        }
    }

    pub fn disables_new_connection_intent_operations(&self) -> bool {
        matches!(
            self,
            Self::Api { status, .. } | Self::InvalidErrorResponse { status }
                if *status == StatusCode::NOT_FOUND
        ) || matches!(
            self.stable_code(),
            Some("recovery_contract_unavailable" | "recovery_contract_unsupported")
        )
    }
}

#[derive(Clone)]
pub struct ClientApi {
    http: ResettableHttpClient,
    api_base: Url,
    app_version: Option<HeaderValue>,
}

#[derive(Clone)]
struct ResettableHttpClient {
    current: Arc<RwLock<HttpClient>>,
}

impl ResettableHttpClient {
    fn new() -> Result<Self, ClientApiError> {
        Ok(Self {
            current: Arc::new(RwLock::new(Self::build()?)),
        })
    }

    fn build() -> Result<HttpClient, ClientApiError> {
        Ok(HttpClient::builder()
            .connect_timeout(HTTP_CONNECT_TIMEOUT)
            .timeout(HTTP_REQUEST_TIMEOUT)
            .build()?)
    }

    fn reset(&self) -> Result<(), ClientApiError> {
        let replacement = Self::build()?;
        let mut current = self
            .current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *current = replacement;
        Ok(())
    }

    fn client(&self) -> HttpClient {
        self.current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn get(&self, endpoint: Url) -> RequestBuilder {
        self.client().get(endpoint)
    }

    fn post(&self, endpoint: Url) -> RequestBuilder {
        self.client().post(endpoint)
    }

    fn put(&self, endpoint: Url) -> RequestBuilder {
        self.client().put(endpoint)
    }

    fn delete(&self, endpoint: Url) -> RequestBuilder {
        self.client().delete(endpoint)
    }
}

impl ClientApi {
    pub fn new(panel_base: &str) -> Result<Self, ClientApiError> {
        let mut base = Url::parse(panel_base)
            .map_err(|error| ClientApiError::InvalidBaseUrl(error.to_string()))?;
        let scheme_allowed =
            base.scheme() == "https" || (cfg!(debug_assertions) && base.scheme() == "http");
        if !scheme_allowed {
            return Err(ClientApiError::InvalidBaseUrl(
                "HTTPS is required outside debug builds".to_string(),
            ));
        }
        base.set_query(None);
        base.set_fragment(None);
        let api_base = base
            .join(&format!("{API_PREFIX}/"))
            .map_err(|error| ClientApiError::InvalidBaseUrl(error.to_string()))?;
        Ok(Self {
            // Reqwest has no cookie jar unless its optional `cookies` feature is enabled.
            http: ResettableHttpClient::new()?,
            api_base,
            app_version: None,
        })
    }

    pub fn reset_transport(&self) -> Result<(), ClientApiError> {
        self.http.reset()
    }

    pub fn with_app_version(mut self, app_version: &str) -> Result<Self, ClientApiError> {
        self.app_version = Some(HeaderValue::from_str(app_version)?);
        Ok(self)
    }

    pub async fn login(&self, request: &LoginRequest) -> Result<TokenResponse, ClientApiError> {
        self.send_json(self.http.post(self.endpoint("auth/login")?).json(request))
            .await
    }

    pub async fn refresh(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<TokenResponse, ClientApiError> {
        self.send_json(
            self.http
                .post(self.endpoint("auth/refresh")?)
                .json(&RefreshRequest {
                    refresh_token: refresh_token.into(),
                }),
        )
        .await
    }

    pub async fn logout(&self, access_token: &str) -> Result<SuccessResponse, ClientApiError> {
        self.send_json(
            self.http
                .post(self.endpoint("auth/logout")?)
                .bearer_auth(access_token),
        )
        .await
    }

    pub async fn logout_all(&self, access_token: &str) -> Result<SuccessResponse, ClientApiError> {
        self.send_json(
            self.http
                .post(self.endpoint("auth/logout-all")?)
                .bearer_auth(access_token),
        )
        .await
    }

    pub async fn background_token(
        &self,
        access_token: &str,
    ) -> Result<BackgroundTokenResponse, ClientApiError> {
        self.send_json(
            self.http
                .post(self.endpoint("background/token")?)
                .bearer_auth(access_token),
        )
        .await
    }

    pub async fn peer_options(&self, access_token: &str) -> Result<PeerOptions, ClientApiError> {
        self.send_json(
            self.http
                .get(self.endpoint("peer-options")?)
                .bearer_auth(access_token),
        )
        .await
    }

    pub async fn notifications(
        &self,
        access_token: &str,
        cursor: Option<i64>,
        limit: u32,
    ) -> Result<AppNotificationList, ClientApiError> {
        let mut endpoint = self.endpoint("notifications")?;
        {
            let mut query = endpoint.query_pairs_mut();
            query.append_pair("limit", &limit.clamp(1, 100).to_string());
            if let Some(cursor) = cursor {
                query.append_pair("cursor", &cursor.to_string());
            }
        }
        self.send_json(self.http.get(endpoint).bearer_auth(access_token))
            .await
    }

    pub async fn mark_notification_read(
        &self,
        access_token: &str,
        message_id: i64,
    ) -> Result<AppNotificationReadResponse, ClientApiError> {
        self.send_json(
            self.http
                .post(self.endpoint(&format!("notifications/{message_id}/read"))?)
                .bearer_auth(access_token),
        )
        .await
    }

    pub async fn mark_all_notifications_read(
        &self,
        access_token: &str,
    ) -> Result<AppNotificationReadResponse, ClientApiError> {
        self.send_json(
            self.http
                .post(self.endpoint("notifications/read-all")?)
                .bearer_auth(access_token),
        )
        .await
    }

    pub async fn register_push_token(
        &self,
        access_token: &str,
        token: &str,
    ) -> Result<PushRegistrationResponse, ClientApiError> {
        self.send_json(
            self.http
                .put(self.endpoint("push-registration")?)
                .bearer_auth(access_token)
                .json(&PushRegistrationRequest {
                    provider: "fcm".to_string(),
                    token: token.to_string(),
                }),
        )
        .await
    }

    pub async fn unregister_push_token(
        &self,
        access_token: &str,
    ) -> Result<PushRegistrationResponse, ClientApiError> {
        self.send_json(
            self.http
                .delete(self.endpoint("push-registration")?)
                .bearer_auth(access_token),
        )
        .await
    }

    pub async fn upload_diagnostics(
        &self,
        access_token: &str,
        request: &DiagnosticUploadRequest,
    ) -> Result<DiagnosticUploadResponse, ClientApiError> {
        self.send_json(
            self.http
                .post(self.endpoint("diagnostics")?)
                .bearer_auth(access_token)
                .json(request),
        )
        .await
    }

    pub async fn split_tunnel_revision(
        &self,
        access_token: &str,
    ) -> Result<SplitTunnelRevision, ClientApiError> {
        self.send_json(
            self.http
                .get(self.endpoint("split-tunnel/revision")?)
                .bearer_auth(access_token),
        )
        .await
    }

    pub async fn split_tunnel_policy(
        &self,
        access_token: &str,
    ) -> Result<SplitTunnelPolicy, ClientApiError> {
        self.send_limited_json(
            self.http
                .get(self.endpoint("split-tunnel/policy")?)
                .bearer_auth(access_token),
            SPLIT_TUNNEL_POLICY_RESPONSE_LIMIT,
            "split_tunnel_policy_too_large",
            "split_tunnel_policy_invalid",
        )
        .await
    }

    pub async fn update_split_tunnel_settings(
        &self,
        access_token: &str,
        settings: &SplitTunnelSettingsUpdate,
    ) -> Result<SplitTunnelPolicy, ClientApiError> {
        if settings.selected_packages.len() > SPLIT_TUNNEL_SELECTED_PACKAGES_LIMIT {
            return Err(ClientApiError::InvalidPayload {
                code: "split_tunnel_selected_packages_limit",
            });
        }
        let body = serde_json::to_vec(settings).map_err(|_| ClientApiError::InvalidPayload {
            code: "split_tunnel_settings_invalid",
        })?;
        if body.len() > SPLIT_TUNNEL_SETTINGS_REQUEST_LIMIT {
            return Err(ClientApiError::PayloadTooLarge {
                code: "split_tunnel_settings_too_large",
                limit_bytes: SPLIT_TUNNEL_SETTINGS_REQUEST_LIMIT,
            });
        }

        self.send_limited_json(
            self.http
                .put(self.endpoint("split-tunnel/settings")?)
                .bearer_auth(access_token)
                .header(CONTENT_TYPE, "application/json")
                .body(body),
            SPLIT_TUNNEL_POLICY_RESPONSE_LIMIT,
            "split_tunnel_policy_too_large",
            "split_tunnel_policy_invalid",
        )
        .await
    }

    pub async fn add_split_tunnel_address_rule(
        &self,
        access_token: &str,
        rule: &SplitTunnelAddressRuleUpdate,
    ) -> Result<SplitTunnelPolicy, ClientApiError> {
        self.send_limited_json(
            self.http
                .post(self.endpoint("split-tunnel/address-rules")?)
                .bearer_auth(access_token)
                .json(rule),
            SPLIT_TUNNEL_POLICY_RESPONSE_LIMIT,
            "split_tunnel_policy_too_large",
            "split_tunnel_policy_invalid",
        )
        .await
    }

    pub async fn remove_split_tunnel_address_rule(
        &self,
        access_token: &str,
        rule_id: i64,
        scope: SplitTunnelAddressRuleScope,
    ) -> Result<SplitTunnelPolicy, ClientApiError> {
        let scope = match scope {
            SplitTunnelAddressRuleScope::ThisDevice => "this_device",
            SplitTunnelAddressRuleScope::AllDevices => "all_devices",
        };
        self.send_limited_json(
            self.http
                .delete(self.endpoint(&format!("split-tunnel/address-rules/{rule_id}"))?)
                .bearer_auth(access_token)
                .query(&[("scope", scope)]),
            SPLIT_TUNNEL_POLICY_RESPONSE_LIMIT,
            "split_tunnel_policy_too_large",
            "split_tunnel_policy_invalid",
        )
        .await
    }

    pub async fn report_split_tunnel_apply_result(
        &self,
        access_token: &str,
        result: &SplitTunnelApplyResult,
    ) -> Result<SuccessResponse, ClientApiError> {
        self.send_json(
            self.http
                .post(self.endpoint("split-tunnel/apply-result")?)
                .bearer_auth(access_token)
                .json(result),
        )
        .await
    }

    pub async fn bind_peer(
        &self,
        access_token: &str,
        request: &BindPeerRequest,
    ) -> Result<PeerBindingResponse, ClientApiError> {
        self.send_json(
            self.http
                .post(self.endpoint("device/bind-peer")?)
                .bearer_auth(access_token)
                .json(request),
        )
        .await
    }

    pub async fn unbind_peer(
        &self,
        access_token: &str,
    ) -> Result<PeerBindingResponse, ClientApiError> {
        self.send_json(
            self.http
                .post(self.endpoint("device/unbind-peer")?)
                .bearer_auth(access_token),
        )
        .await
    }

    pub async fn bootstrap(&self, access_token: &str) -> Result<Bootstrap, ClientApiError> {
        self.send_json(self.bootstrap_request(access_token)?).await
    }

    pub async fn server_candidates(
        &self,
        access_token: &str,
        layer: Layer,
        egress_mode: EgressMode,
    ) -> Result<ServerCandidatesResponse, ClientApiError> {
        self.send_json(
            self.http
                .get(self.server_candidates_endpoint(layer, egress_mode)?)
                .bearer_auth(access_token),
        )
        .await
    }

    pub async fn background_capabilities(
        &self,
        background_token: &str,
    ) -> Result<ConnectionIntentCapabilityResponse, ClientApiError> {
        self.send_json(self.device_request(
            self.http.get(self.endpoint("background/capabilities")?),
            background_token,
        ))
        .await
    }

    pub async fn background_candidates(
        &self,
        background_token: &str,
        layer: Layer,
        egress_mode: EgressMode,
    ) -> Result<ServerCandidatesResponse, ClientApiError> {
        self.send_json(
            self.device_request(
                self.http
                    .get(self.background_candidates_endpoint(layer, egress_mode)?),
                background_token,
            ),
        )
        .await
    }

    pub async fn reconcile_background_operation(
        &self,
        background_token: &str,
        request: &OperationReconcileRequest,
    ) -> Result<OperationReconcileResponse, ClientApiError> {
        self.send_json(
            self.device_request(
                self.http
                    .post(self.endpoint("background/operations/reconcile")?),
                background_token,
            )
            .json(request),
        )
        .await
    }

    pub async fn select_server(
        &self,
        access_token: &str,
        request: &ServerSelectionRequest,
    ) -> Result<ServerSelectionResponse, ClientApiError> {
        self.send_json(
            self.http
                .post(self.endpoint("server-selection")?)
                .bearer_auth(access_token)
                .json(request),
        )
        .await
    }

    pub async fn probe_candidate_latency_ms(
        &self,
        probe_url: &str,
    ) -> Result<f64, ProbeFailureCode> {
        let endpoint = Url::parse(probe_url).map_err(|_| ProbeFailureCode::InvalidUrl)?;
        let scheme_allowed =
            endpoint.scheme() == "https" || (cfg!(debug_assertions) && endpoint.scheme() == "http");
        if !scheme_allowed {
            return Err(ProbeFailureCode::UnsupportedScheme);
        }

        let started = Instant::now();
        let response = self
            .http
            .get(endpoint)
            .header(reqwest::header::CACHE_CONTROL, "no-cache")
            .timeout(Duration::from_secs(3))
            .send()
            .await
            .map_err(|error| {
                if error.is_timeout() {
                    ProbeFailureCode::Timeout
                } else {
                    ProbeFailureCode::NetworkError
                }
            })?;
        if !response.status().is_success() {
            return Err(ProbeFailureCode::HttpError);
        }
        Ok(started.elapsed().as_secs_f64() * 1_000.0)
    }

    fn fresh_probe_request(
        endpoint: Url,
        resolved_ip: Option<IpAddr>,
    ) -> Result<RequestBuilder, ProbeFailureCode> {
        let mut client = HttpClient::builder()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(3))
            .http1_only()
            .pool_max_idle_per_host(0);
        if let Some(resolved_ip) = resolved_ip {
            let host = endpoint
                .host_str()
                .ok_or(ProbeFailureCode::InvalidUrl)?
                .to_string();
            let port = endpoint
                .port_or_known_default()
                .ok_or(ProbeFailureCode::InvalidUrl)?;
            client = client.resolve(&host, SocketAddr::new(resolved_ip, port));
        }
        let client = client.build().map_err(|_| ProbeFailureCode::NetworkError)?;
        Ok(client
            .get(endpoint)
            .header(reqwest::header::CACHE_CONTROL, "no-cache")
            .header(reqwest::header::CONNECTION, "close"))
    }

    pub async fn probe_fresh_latency_ms(&self, probe_url: &str) -> Option<f64> {
        let endpoint = Url::parse(probe_url).ok()?;
        let scheme_allowed =
            endpoint.scheme() == "https" || (cfg!(debug_assertions) && endpoint.scheme() == "http");
        if !scheme_allowed {
            return None;
        }
        let started = Instant::now();
        let response = Self::fresh_probe_request(endpoint, None)
            .ok()?
            .send()
            .await
            .ok()?;
        response
            .status()
            .is_success()
            .then(|| started.elapsed().as_secs_f64() * 1_000.0)
    }

    pub async fn probe_fresh_latency_ms_resolved(
        &self,
        probe_url: &str,
        resolved_ip: IpAddr,
    ) -> Option<f64> {
        let endpoint = Url::parse(probe_url).ok()?;
        let scheme_allowed =
            endpoint.scheme() == "https" || (cfg!(debug_assertions) && endpoint.scheme() == "http");
        if !scheme_allowed {
            return None;
        }
        let started = Instant::now();
        let response = Self::fresh_probe_request(endpoint, Some(resolved_ip))
            .ok()?
            .send()
            .await
            .ok()?;
        response
            .status()
            .is_success()
            .then(|| started.elapsed().as_secs_f64() * 1_000.0)
    }

    pub async fn probe_latency_ms(&self, probe_url: &str) -> Option<f64> {
        self.probe_candidate_latency_ms(probe_url).await.ok()
    }

    pub async fn start_connection(
        &self,
        access_token: &str,
        request: &ConnectionStartRequest,
    ) -> Result<ConnectionStartResponse, ClientApiError> {
        self.send_json(
            self.http
                .post(self.endpoint("connections/start")?)
                .bearer_auth(access_token)
                .json(request),
        )
        .await
    }

    pub async fn report_redundant_role(
        &self,
        access_token: &str,
        request: &RedundantRoleRequest,
    ) -> Result<RedundantRoleResponse, ClientApiError> {
        self.redundant_operation(access_token, "connections/role", request)
            .await
    }

    pub async fn release_redundant_standby(
        &self,
        access_token: &str,
        request: &RedundantStandbyReleaseRequest,
    ) -> Result<RedundantSessionResponse, ClientApiError> {
        self.redundant_operation(access_token, "connections/standby/release", request)
            .await
    }

    pub async fn acquire_redundant_standby(
        &self,
        access_token: &str,
        request: &RedundantStandbyAcquireRequest,
    ) -> Result<RedundantStandbyAcquireResponse, ClientApiError> {
        self.redundant_operation(access_token, "connections/standby/acquire", request)
            .await
    }

    pub async fn commit_redundant_candidate(
        &self,
        access_token: &str,
        request: &RedundantCandidateCommitRequest,
    ) -> Result<RedundantSessionResponse, ClientApiError> {
        self.redundant_operation(access_token, "connections/standby/commit", request)
            .await
    }

    pub async fn stop_redundant_connection(
        &self,
        access_token: &str,
        request: &RedundantStopRequest,
    ) -> Result<ConnectionOperationResponse, ClientApiError> {
        self.redundant_operation(access_token, "connections/stop", request)
            .await
    }

    async fn redundant_operation<Request, ResponseBody>(
        &self,
        access_token: &str,
        path: &str,
        request: &Request,
    ) -> Result<ResponseBody, ClientApiError>
    where
        Request: Serialize + ?Sized,
        ResponseBody: for<'de> Deserialize<'de>,
    {
        self.send_json(
            self.http
                .post(self.endpoint(path)?)
                .bearer_auth(access_token)
                .json(request),
        )
        .await
    }

    pub async fn background_report_redundant_role(
        &self,
        background_token: &str,
        request: &RedundantRoleRequest,
    ) -> Result<RedundantRoleResponse, ClientApiError> {
        self.background_redundant_operation(
            background_token,
            "background/connections/role",
            request,
        )
        .await
    }

    pub async fn background_start_connection(
        &self,
        background_token: &str,
        request: &ConnectionStartRequest,
    ) -> Result<ConnectionStartResponse, ClientApiError> {
        self.background_redundant_operation(
            background_token,
            "background/connections/start",
            request,
        )
        .await
    }

    pub async fn background_release_redundant_standby(
        &self,
        background_token: &str,
        request: &RedundantStandbyReleaseRequest,
    ) -> Result<RedundantSessionResponse, ClientApiError> {
        self.background_redundant_operation(
            background_token,
            "background/connections/standby/release",
            request,
        )
        .await
    }

    pub async fn background_acquire_redundant_standby(
        &self,
        background_token: &str,
        request: &RedundantStandbyAcquireRequest,
    ) -> Result<RedundantStandbyAcquireResponse, ClientApiError> {
        self.background_redundant_operation(
            background_token,
            "background/connections/standby/acquire",
            request,
        )
        .await
    }

    pub async fn background_commit_redundant_candidate(
        &self,
        background_token: &str,
        request: &RedundantCandidateCommitRequest,
    ) -> Result<RedundantSessionResponse, ClientApiError> {
        self.background_redundant_operation(
            background_token,
            "background/connections/standby/commit",
            request,
        )
        .await
    }

    pub async fn background_stop_redundant_connection(
        &self,
        background_token: &str,
        request: &RedundantStopRequest,
    ) -> Result<ConnectionOperationResponse, ClientApiError> {
        self.background_redundant_operation(
            background_token,
            "background/connections/stop",
            request,
        )
        .await
    }

    async fn background_redundant_operation<Request, ResponseBody>(
        &self,
        background_token: &str,
        path: &str,
        request: &Request,
    ) -> Result<ResponseBody, ClientApiError>
    where
        Request: Serialize + ?Sized,
        ResponseBody: for<'de> Deserialize<'de>,
    {
        self.send_json(
            self.device_request(self.http.post(self.endpoint(path)?), background_token)
                .json(request),
        )
        .await
    }

    pub async fn stop_connection(
        &self,
        access_token: &str,
        request: &ConnectionOperationRequest,
    ) -> Result<ConnectionOperationResponse, ClientApiError> {
        self.connection_operation(access_token, "connections/stop", request)
            .await
    }

    pub async fn pin_stray(
        &self,
        access_token: &str,
        request: &ConnectionOperationRequest,
    ) -> Result<ConnectionOperationResponse, ClientApiError> {
        self.connection_operation(access_token, "connections/pin-stray", request)
            .await
    }

    pub async fn unpin_stray(
        &self,
        access_token: &str,
        request: &ConnectionOperationRequest,
    ) -> Result<ConnectionOperationResponse, ClientApiError> {
        self.connection_operation(access_token, "connections/unpin-stray", request)
            .await
    }

    async fn connection_operation(
        &self,
        access_token: &str,
        path: &str,
        request: &ConnectionOperationRequest,
    ) -> Result<ConnectionOperationResponse, ClientApiError> {
        self.send_json(
            self.http
                .post(self.endpoint(path)?)
                .bearer_auth(access_token)
                .json(request),
        )
        .await
    }

    fn server_candidates_endpoint(
        &self,
        layer: Layer,
        egress_mode: EgressMode,
    ) -> Result<Url, ClientApiError> {
        self.candidates_endpoint("server-candidates", layer, egress_mode)
    }

    fn background_candidates_endpoint(
        &self,
        layer: Layer,
        egress_mode: EgressMode,
    ) -> Result<Url, ClientApiError> {
        self.candidates_endpoint("background/server-candidates", layer, egress_mode)
    }

    fn candidates_endpoint(
        &self,
        path: &str,
        layer: Layer,
        egress_mode: EgressMode,
    ) -> Result<Url, ClientApiError> {
        let mut endpoint = self.endpoint(path)?;
        endpoint.query_pairs_mut().append_pair(
            "layer",
            match layer {
                Layer::Tic => "tic",
                Layer::Stray => "stray",
            },
        );
        endpoint.query_pairs_mut().append_pair(
            "egress_mode",
            match egress_mode {
                EgressMode::Ipv4 => "ipv4",
                EgressMode::PreferIpv6 => "prefer_ipv6",
            },
        );
        Ok(endpoint)
    }

    fn device_request(&self, request: RequestBuilder, background_token: &str) -> RequestBuilder {
        request.header(AUTHORIZATION, format!("Device {background_token}"))
    }

    fn endpoint(&self, path: &str) -> Result<Url, ClientApiError> {
        self.api_base
            .join(path)
            .map_err(|error| ClientApiError::InvalidBaseUrl(error.to_string()))
    }

    fn bootstrap_request(&self, access_token: &str) -> Result<RequestBuilder, ClientApiError> {
        let request = self
            .http
            .get(self.endpoint("bootstrap")?)
            .bearer_auth(access_token);
        Ok(match &self.app_version {
            Some(app_version) => request.header("X-Nelomai-App-Version", app_version),
            None => request,
        })
    }

    async fn send_json<T: for<'de> Deserialize<'de>>(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<T, ClientApiError> {
        let response = request.send().await?;
        let status = response.status();
        if status.is_success() {
            return Ok(response.json().await?);
        }
        Err(Self::api_error(response, status).await)
    }

    async fn send_limited_json<T: for<'de> Deserialize<'de>>(
        &self,
        request: RequestBuilder,
        limit_bytes: usize,
        limit_code: &'static str,
        invalid_code: &'static str,
    ) -> Result<T, ClientApiError> {
        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(Self::api_error(response, status).await);
        }
        if response
            .content_length()
            .is_some_and(|length| length > limit_bytes as u64)
        {
            return Err(ClientApiError::PayloadTooLarge {
                code: limit_code,
                limit_bytes,
            });
        }

        let mut body = Vec::with_capacity(
            response
                .content_length()
                .unwrap_or_default()
                .min(limit_bytes as u64) as usize,
        );
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if body.len().saturating_add(chunk.len()) > limit_bytes {
                return Err(ClientApiError::PayloadTooLarge {
                    code: limit_code,
                    limit_bytes,
                });
            }
            body.extend_from_slice(&chunk);
        }

        serde_json::from_slice(&body)
            .map_err(|_| ClientApiError::InvalidPayload { code: invalid_code })
    }

    async fn api_error(response: Response, status: StatusCode) -> ClientApiError {
        let retry_after_seconds = parse_retry_after_seconds(response.headers().get(RETRY_AFTER));
        let payload = response
            .json::<ErrorPayload>()
            .await
            .map_err(|_| ClientApiError::InvalidErrorResponse { status });
        match payload {
            Ok(payload) => ClientApiError::Api {
                status,
                request_id: payload.request_id,
                code: payload.code,
                message: payload.message,
                retry_after_seconds,
            },
            Err(error) => error,
        }
    }
}

fn parse_retry_after_seconds(value: Option<&HeaderValue>) -> Option<u64> {
    value
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|seconds| (1..=900).contains(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nelomai_contracts::{
        ConnectionOperationRequest, ConnectionStartRequest, Layer, RouteMode, TicConnectionMode,
    };
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, TcpListener};
    use std::thread;

    #[test]
    fn builds_versioned_endpoint_without_browser_cookie_state() {
        let client = ClientApi::new("https://nelomai.ru").unwrap();
        assert_eq!(
            client.endpoint("auth/login").unwrap().as_str(),
            "https://nelomai.ru/api/client/v1/auth/login"
        );
    }

    #[test]
    fn fresh_probe_closes_its_dedicated_http_connection() {
        let request =
            ClientApi::fresh_probe_request(Url::parse("https://nelomai.ru/health").unwrap(), None)
                .unwrap()
                .build()
                .unwrap();

        assert_eq!(
            request
                .headers()
                .get(reqwest::header::CONNECTION)
                .and_then(|value| value.to_str().ok()),
            Some("close"),
        );
    }

    #[tokio::test]
    async fn fresh_probe_can_pin_hostname_to_known_endpoint_ip() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let received = stream.read(&mut request).unwrap();
            assert!(
                String::from_utf8_lossy(&request[..received]).starts_with("GET /probe HTTP/1.1")
            );
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .unwrap();
        });
        let client = ClientApi::new("https://nelomai.ru").unwrap();

        let latency = client
            .probe_fresh_latency_ms_resolved(
                &format!("http://unresolvable.invalid:{port}/probe"),
                IpAddr::V4(Ipv4Addr::LOCALHOST),
            )
            .await;

        assert!(latency.is_some());
        server.join().unwrap();
    }

    #[test]
    fn bootstrap_reports_the_running_application_version() {
        let client = ClientApi::new("https://nelomai.ru")
            .unwrap()
            .with_app_version("0.1.4")
            .unwrap();
        let request = client
            .bootstrap_request("access-secret")
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(
            request
                .headers()
                .get("X-Nelomai-App-Version")
                .and_then(|value| value.to_str().ok()),
            Some("0.1.4")
        );
        assert_eq!(
            request
                .headers()
                .get(reqwest::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer access-secret")
        );
    }

    #[test]
    fn background_redundancy_requests_use_device_authorization() {
        let client = ClientApi::new("https://nelomai.ru").unwrap();
        let request = client
            .device_request(
                client
                    .http
                    .post(client.endpoint("background/connections/role").unwrap()),
                "background-secret",
            )
            .build()
            .unwrap();

        assert_eq!(
            request
                .headers()
                .get(reqwest::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
            Some("Device background-secret")
        );
    }

    #[test]
    fn rejects_non_http_urls() {
        assert!(ClientApi::new("not a URL").is_err());
    }

    #[test]
    fn builds_every_connection_endpoint_from_the_v1_base() {
        let client = ClientApi::new("https://nelomai.ru").unwrap();
        assert_eq!(
            client.endpoint("bootstrap").unwrap().path(),
            "/api/client/v1/bootstrap"
        );
        assert_eq!(
            client
                .server_candidates_endpoint(Layer::Tic, nelomai_contracts::EgressMode::PreferIpv6,)
                .unwrap()
                .as_str(),
            "https://nelomai.ru/api/client/v1/server-candidates?layer=tic&egress_mode=prefer_ipv6"
        );
        for path in [
            "server-selection",
            "connections/start",
            "connections/role",
            "connections/standby/release",
            "connections/standby/acquire",
            "connections/standby/commit",
            "connections/stop",
            "connections/pin-stray",
            "connections/unpin-stray",
            "background/connections/role",
            "background/connections/start",
            "background/connections/standby/release",
            "background/connections/standby/acquire",
            "background/connections/standby/commit",
            "background/connections/stop",
        ] {
            assert_eq!(
                client.endpoint(path).unwrap().path(),
                format!("/api/client/v1/{path}")
            );
        }
    }

    #[test]
    fn serializes_start_and_operation_requests_exactly_as_the_panel_contract() {
        let start = ConnectionStartRequest {
            operation_id: "11111111-1111-4111-8111-111111111111".to_string(),
            layer: Layer::Stray,
            tic_connection_mode: TicConnectionMode::Dynamic,
            route_mode: RouteMode::Standalone,
            egress_mode: EgressMode::Ipv4,
            probes: Vec::new(),
            allow_alternate: false,
            require_measured_selection: false,
            recovery_contract_version: None,
            redundancy_contract_version: None,
            reserve_enabled: None,
            request_fingerprint: None,
        };
        let value = serde_json::to_value(&start).unwrap();
        assert_eq!(value["tic_connection_mode"], "dynamic");
        assert!(value.get("mode").is_none());
        assert!(value.get("api_version").is_none());
        assert!(value.get("require_measured_selection").is_none());
        assert!(value.get("recovery_contract_version").is_none());
        assert!(value.get("redundancy_contract_version").is_none());
        assert!(value.get("reserve_enabled").is_none());
        assert!(value.get("request_fingerprint").is_none());

        let recovery_start = ConnectionStartRequest {
            require_measured_selection: true,
            recovery_contract_version: Some(1),
            request_fingerprint: Some("a".repeat(64)),
            ..start.clone()
        };
        let recovery_value = serde_json::to_value(recovery_start).unwrap();
        assert_eq!(recovery_value["require_measured_selection"], true);
        assert_eq!(recovery_value["recovery_contract_version"], 1);
        assert_eq!(recovery_value["request_fingerprint"], "a".repeat(64));

        let recovery_v2_start = ConnectionStartRequest {
            recovery_contract_version: Some(2),
            redundancy_contract_version: Some(1),
            reserve_enabled: Some(true),
            request_fingerprint: Some("b".repeat(64)),
            ..start
        };
        let recovery_v2_value = serde_json::to_value(recovery_v2_start).unwrap();
        assert_eq!(recovery_v2_value["recovery_contract_version"], 2);
        assert_eq!(recovery_v2_value["redundancy_contract_version"], 1);
        assert_eq!(recovery_v2_value["reserve_enabled"], true);
        assert_eq!(recovery_v2_value["request_fingerprint"], "b".repeat(64));

        let operation = ConnectionOperationRequest {
            operation_id: "11111111-1111-4111-8111-111111111111".to_string(),
            lease_id: "22222222-2222-4222-8222-222222222222".to_string(),
            failure_code: None,
        };
        assert_eq!(
            serde_json::to_value(operation).unwrap(),
            serde_json::json!({
                "operation_id": "11111111-1111-4111-8111-111111111111",
                "lease_id": "22222222-2222-4222-8222-222222222222"
            })
        );

        let failed_operation = ConnectionOperationRequest {
            operation_id: "33333333-3333-4333-8333-333333333333".to_string(),
            lease_id: "22222222-2222-4222-8222-222222222222".to_string(),
            failure_code: Some("tunnel_handshake_timeout".to_string()),
        };
        assert_eq!(
            serde_json::to_value(failed_operation).unwrap(),
            serde_json::json!({
                "operation_id": "33333333-3333-4333-8333-333333333333",
                "lease_id": "22222222-2222-4222-8222-222222222222",
                "failure_code": "tunnel_handshake_timeout"
            })
        );

        let stalled_operation = ConnectionOperationRequest {
            operation_id: "44444444-4444-4444-8444-444444444444".to_string(),
            lease_id: "22222222-2222-4222-8222-222222222222".to_string(),
            failure_code: Some("tunnel_data_plane_stalled".to_string()),
        };
        assert_eq!(
            serde_json::to_value(stalled_operation).unwrap()["failure_code"],
            "tunnel_data_plane_stalled"
        );

        let redundant_stop = RedundantStopRequest {
            operation_id: "55555555-5555-4555-8555-555555555555".to_string(),
            lease_id: "22222222-2222-4222-8222-222222222222".to_string(),
            recovery_contract_version: nelomai_contracts::RecoveryContractV2,
            session_id: "66666666-6666-4666-8666-666666666666".to_string(),
        };
        assert_eq!(
            serde_json::to_value(redundant_stop).unwrap(),
            serde_json::json!({
                "operation_id": "55555555-5555-4555-8555-555555555555",
                "lease_id": "22222222-2222-4222-8222-222222222222",
                "recovery_contract_version": 2,
                "session_id": "66666666-6666-4666-8666-666666666666"
            })
        );
    }

    #[test]
    fn connection_intent_capability_absence_and_unsupported_errors_disable_only_new_work() {
        let missing = ClientApiError::Api {
            status: StatusCode::NOT_FOUND,
            request_id: "req-missing".to_string(),
            code: "not_found".to_string(),
            message: "Not found".to_string(),
            retry_after_seconds: None,
        };
        assert!(missing.disables_new_connection_intent_operations());

        let unsupported = ClientApiError::Api {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            request_id: "req-unsupported".to_string(),
            code: "recovery_contract_unsupported".to_string(),
            message: "Unsupported".to_string(),
            retry_after_seconds: None,
        };
        assert!(unsupported.disables_new_connection_intent_operations());

        let malformed_missing = ClientApiError::InvalidErrorResponse {
            status: StatusCode::NOT_FOUND,
        };
        assert!(malformed_missing.disables_new_connection_intent_operations());

        let transport = ClientApiError::InvalidBaseUrl("offline".to_string());
        assert!(!transport.disables_new_connection_intent_operations());
    }

    #[test]
    fn retry_after_accepts_only_the_bounded_delta_seconds_contract() {
        assert_eq!(
            parse_retry_after_seconds(Some(&HeaderValue::from_static("120"))),
            Some(120),
        );
        assert_eq!(
            parse_retry_after_seconds(Some(&HeaderValue::from_static("0"))),
            None,
        );
        assert_eq!(
            parse_retry_after_seconds(Some(&HeaderValue::from_static("901"))),
            None,
        );
        assert_eq!(
            parse_retry_after_seconds(Some(&HeaderValue::from_static("invalid"))),
            None,
        );
    }

    #[test]
    fn auth_debug_output_redacts_password_install_secret_and_tokens() {
        let login = LoginRequest {
            login: "user".to_string(),
            password: "password-secret".to_string(),
            install_secret: "install-secret".to_string(),
            device_name: "Mac".to_string(),
            platform: Platform::Macos,
            platform_version: None,
            architecture: "aarch64".to_string(),
            app_version: "0.1.0".to_string(),
        };
        let refresh = RefreshRequest {
            refresh_token: "refresh-secret".to_string(),
        };
        let response = TokenResponse {
            api_version: ApiVersion::V1,
            request_id: "req-auth".to_string(),
            token_type: "bearer".to_string(),
            access_token: "access-secret".to_string(),
            access_expires_in: 900,
            refresh_token: "response-refresh-secret".to_string(),
            refresh_expires_in: 7_776_000,
            access: Access {
                state: nelomai_contracts::AccessState::Active,
                can_login: true,
                can_connect: true,
                expires_at: None,
            },
            device: AuthDevice {
                id: "device".to_string(),
                name: "Mac".to_string(),
                platform: Platform::Macos,
            },
        };

        let debug = format!("{login:?} {refresh:?} {response:?}");
        for secret in [
            "password-secret",
            "install-secret",
            "refresh-secret",
            "access-secret",
            "response-refresh-secret",
        ] {
            assert!(!debug.contains(secret));
        }
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn diagnostics_debug_output_redacts_both_logs() {
        let request = DiagnosticUploadRequest {
            report_id: None,
            trigger: "manual".to_string(),
            tunnel_session_id: None,
            sequence: None,
            interval_started_at_unix: None,
            interval_ended_at_unix: None,
            tunnel_running: None,
            connection_lease_id: None,
            generated_at_unix: 1,
            app_version: "0.1.0".to_string(),
            platform_version: Some("test".to_string()),
            architecture: "x86_64".to_string(),
            application_log: "application-secret".to_string(),
            helper_log: Some("helper-secret".to_string()),
            network_incidents: Some("incident-secret".to_string()),
            resource_usage: None,
        };

        let debug = format!("{request:?}");

        assert!(!debug.contains("application-secret"));
        assert!(!debug.contains("helper-secret"));
        assert!(!debug.contains("incident-secret"));
        assert!(debug.contains("<redacted>"));
        let serialized = serde_json::to_value(&request).unwrap();
        assert!(serialized.get("resource_usage").is_none());
    }
}
