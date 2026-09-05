//! In-process ownership adapter. Private-channel runtime transport is separate.
use crate::{AuthBroker, BrokerAuthState, BrokerError, LocalAuthStop};
use async_trait::async_trait;
use nelomai_client_api::{
    AccessSnapshot, LoginRequest, RuntimeAuthState, RuntimeLogin, RuntimeTarget,
};
use nelomai_client_core::{CoreError, CoreLocalStop, RuntimeAuthProvider};
use nelomai_client_tunnel::TunnelController;
use nelomai_contracts::Platform;
use std::sync::Arc;

/// Trusted host facts. RuntimeLogin cannot override these or the target.
#[derive(Debug, Clone)]
pub struct RuntimeClientProfile {
    pub platform: Platform,
    pub platform_version: Option<String>,
    pub architecture: String,
}

pub struct OwnerRuntimeAuth {
    broker: Arc<AuthBroker>,
    target: RuntimeTarget,
    profile: RuntimeClientProfile,
}
impl OwnerRuntimeAuth {
    /// Does not enroll, refresh or erase migration credentials. The coordinator
    /// must complete cleanup before runtime operational admission is enabled.
    pub fn new(
        broker: Arc<AuthBroker>,
        target: RuntimeTarget,
        profile: RuntimeClientProfile,
    ) -> Result<Self, BrokerError> {
        target.identity(None)?;
        Ok(Self {
            broker,
            target,
            profile,
        })
    }
    fn check_target(&self, value: AccessSnapshot) -> Result<AccessSnapshot, CoreError> {
        if RuntimeTarget::from_identity(value.identity()) != self.target {
            return Err(CoreError::StartCancelled);
        }
        Ok(value)
    }
}
fn map_error(error: BrokerError) -> CoreError {
    match error {
        BrokerError::Cancelled | BrokerError::IdentityMismatch => CoreError::StartCancelled,
        BrokerError::Api(error) => CoreError::from(nelomai_client_core::CoreApiError::from(error)),
        BrokerError::Storage(_) => CoreError::Storage,
        BrokerError::AuthenticationOutcomeUnknown => CoreError::AuthenticationOutcomeUnknown,
        BrokerError::RecoveryRequired => CoreError::AuthRecoveryRequired,
        BrokerError::Timeout => CoreError::Api(nelomai_client_core::CoreApiError::Retryable),
    }
}
#[async_trait]
impl RuntimeAuthProvider for OwnerRuntimeAuth {
    async fn state(&self) -> Result<RuntimeAuthState, CoreError> {
        Ok(match self.broker.auth_state().await.map_err(map_error)? {
            BrokerAuthState::Active => {
                self.check_target(self.broker.access_token(None).await.map_err(map_error)?)?;
                RuntimeAuthState::Active
            }
            BrokerAuthState::RecoveryRequired => RuntimeAuthState::RecoveryRequired,
            BrokerAuthState::LogoutPending => RuntimeAuthState::LogoutPending,
            BrokerAuthState::LoggedOut => RuntimeAuthState::LoggedOut,
            BrokerAuthState::AuthenticationOutcomeUnknown => {
                RuntimeAuthState::AuthenticationOutcomeUnknown
            }
        })
    }
    async fn login(&self, request: RuntimeLogin) -> Result<AccessSnapshot, CoreError> {
        let request = LoginRequest {
            login: request.login,
            password: request.password,
            device_name: request.device_name,
            install_secret: self.broker.owned_install_secret().map_err(map_error)?,
            platform: self.profile.platform,
            platform_version: self.profile.platform_version.clone(),
            architecture: self.profile.architecture.clone(),
            app_version: self.target.container_version.clone(),
        };
        self.check_target(
            self.broker
                .login(&request, &self.target)
                .await
                .map_err(map_error)?,
        )
    }
    async fn access(&self, stale: Option<&AccessSnapshot>) -> Result<AccessSnapshot, CoreError> {
        // Reject a replaced runtime before any refresh side effect. Generation
        // can evolve within the bound target; it is not a launch-time pin.
        let current =
            self.check_target(self.broker.access_token(None).await.map_err(map_error)?)?;
        match stale {
            None => Ok(current),
            Some(stale) => self.check_target(
                self.broker
                    .access_token(Some(stale))
                    .await
                    .map_err(map_error)?,
            ),
        }
    }
    async fn logout(&self) -> Result<(), CoreError> {
        self.broker.logout().await.map_err(map_error)
    }
}

#[async_trait]
impl<T: TunnelController> LocalAuthStop for CoreLocalStop<T> {
    async fn stop_local(&self) -> Result<(), BrokerError> {
        CoreLocalStop::stop_local(self)
            .await
            .map_err(|_| BrokerError::RecoveryRequired)
    }
}
