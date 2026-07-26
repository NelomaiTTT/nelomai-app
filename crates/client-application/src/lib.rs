use async_trait::async_trait;
use nelomai_client_api::{ClientApi, LoginRequest, TokenResponse};
use nelomai_client_core::{
    ClientCore, ConnectOptions, CoreApi, CoreApiError, CoreError, CoreLogger, CoreState,
};
use nelomai_client_storage::{SecretStore, StoredAuth};
use nelomai_client_tunnel::TunnelController;
use nelomai_contracts::{
    BindPeerRequest, Bootstrap, Connection, PeerBindingResponse, PeerOptions, Platform,
};
use std::sync::Arc;
use thiserror::Error;

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
    async fn logout(&self, access_token: &str) -> Result<(), CoreApiError>;
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

    async fn logout(&self, access_token: &str) -> Result<(), CoreApiError> {
        ClientApi::logout(self, access_token)
            .await
            .map(|_| ())
            .map_err(Into::into)
    }
}

#[derive(Debug, Error)]
pub enum ApplicationError {
    #[error("защищённое хранилище недоступно")]
    Storage,
    #[error(transparent)]
    Api(#[from] CoreApiError),
    #[error(transparent)]
    Core(#[from] CoreError),
}

pub struct ClientApplication<A, S, T, L> {
    api: Arc<A>,
    store: Arc<S>,
    tunnel: Arc<T>,
    core: ClientCore<A, S, T, L>,
}

impl<A, S, T, L> ClientApplication<A, S, T, L>
where
    A: ApplicationApi,
    S: SecretStore,
    T: TunnelController,
    L: CoreLogger,
{
    pub fn new(api: Arc<A>, store: Arc<S>, tunnel: Arc<T>, logger: Arc<L>) -> Self {
        let core = ClientCore::new(api.clone(), store.clone(), tunnel.clone(), logger);
        Self {
            api,
            store,
            tunnel,
            core,
        }
    }

    pub async fn login(
        &self,
        parameters: LoginParameters,
        now_unix: i64,
    ) -> Result<Bootstrap, ApplicationError> {
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
        self.tunnel.stop().await.map_err(CoreError::from)?;
        self.store
            .save(&StoredAuth {
                install_secret,
                access_token: Some(response.access_token),
                refresh_token: Some(response.refresh_token),
                saved_connection: None,
                compatibility: None,
            })
            .map_err(|_| ApplicationError::Storage)?;
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

    pub async fn bind_peer(
        &self,
        request: BindPeerRequest,
    ) -> Result<PeerBindingResponse, ApplicationError> {
        let access_token = self.access_token()?;
        match self.api.bind_peer(&access_token, &request).await {
            Ok(response) => Ok(response),
            Err(CoreApiError::Unauthorized) => {
                let access_token = self.core.refresh_access_token(&access_token).await?;
                self.api
                    .bind_peer(&access_token, &request)
                    .await
                    .map_err(Into::into)
            }
            Err(error) => Err(error.into()),
        }
    }

    pub async fn logout(&self) -> Result<(), ApplicationError> {
        if let Ok(access_token) = self.access_token() {
            let _ = self.api.logout(&access_token).await;
        }
        self.core.sign_out().await.map_err(Into::into)
    }

    pub async fn state(&self) -> CoreState {
        self.core.state().await
    }

    pub async fn bootstrap(&self, now_unix: i64) -> Result<Bootstrap, ApplicationError> {
        self.core.bootstrap(now_unix).await.map_err(Into::into)
    }

    pub async fn start(
        &self,
        options: ConnectOptions,
        now_unix: i64,
    ) -> Result<Connection, ApplicationError> {
        self.core.start(options, now_unix).await.map_err(Into::into)
    }

    pub async fn stop(&self) -> Result<Connection, ApplicationError> {
        self.core.stop().await.map_err(Into::into)
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

    fn access_token(&self) -> Result<String, ApplicationError> {
        self.store
            .load()
            .map_err(|_| ApplicationError::Storage)?
            .and_then(|stored| stored.access_token)
            .ok_or(ApplicationError::Core(CoreError::SignedOut))
    }
}
