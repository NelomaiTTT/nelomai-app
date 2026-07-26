use nelomai_contracts::{
    Access, ApiVersion, BindPeerRequest, ErrorPayload, PeerBindingResponse, PeerOptions, Platform,
    API_PREFIX,
};
use reqwest::{Client as HttpClient, StatusCode, Url};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AuthDevice {
    pub id: String,
    pub name: String,
    pub platform: Platform,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SuccessResponse {
    pub api_version: ApiVersion,
    pub request_id: String,
    pub ok: bool,
}

#[derive(Debug, Error)]
pub enum ClientApiError {
    #[error("invalid panel URL: {0}")]
    InvalidBaseUrl(String),
    #[error("request failed: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("{code}: {message}")]
    Api {
        status: StatusCode,
        request_id: String,
        code: String,
        message: String,
    },
    #[error("panel returned an invalid error response ({status})")]
    InvalidErrorResponse { status: StatusCode },
}

#[derive(Clone)]
pub struct ClientApi {
    http: HttpClient,
    api_base: Url,
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
            http: HttpClient::builder().build()?,
            api_base,
        })
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

    pub async fn peer_options(&self, access_token: &str) -> Result<PeerOptions, ClientApiError> {
        self.send_json(
            self.http
                .get(self.endpoint("peer-options")?)
                .bearer_auth(access_token),
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

    fn endpoint(&self, path: &str) -> Result<Url, ClientApiError> {
        self.api_base
            .join(path)
            .map_err(|error| ClientApiError::InvalidBaseUrl(error.to_string()))
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
        let payload = response
            .json::<ErrorPayload>()
            .await
            .map_err(|_| ClientApiError::InvalidErrorResponse { status })?;
        Err(ClientApiError::Api {
            status,
            request_id: payload.request_id,
            code: payload.code,
            message: payload.message,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_versioned_endpoint_without_browser_cookie_state() {
        let client = ClientApi::new("https://nelomai.ru").unwrap();
        assert_eq!(
            client.endpoint("auth/login").unwrap().as_str(),
            "https://nelomai.ru/api/client/v1/auth/login"
        );
    }

    #[test]
    fn rejects_non_http_urls() {
        assert!(ClientApi::new("not a URL").is_err());
    }
}
