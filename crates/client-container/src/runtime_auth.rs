//! In-process ownership adapter. Private-channel runtime transport is separate.
use crate::{AuthBroker, BrokerAuthState, BrokerError, LocalAuthStop};
use async_trait::async_trait;
use nelomai_client_api::{
    AccessSnapshot, LoginRequest, RuntimeAuthState, RuntimeLogin, RuntimeTarget,
};
use nelomai_client_core::{
    CoreError, CoreLocalStop, RuntimeAuthProvider, RuntimeWriterGates, RuntimeWriterQuiescence,
};
use nelomai_client_storage::{RuntimeAuthScope, RuntimeRecordOwner, RuntimeStateStore};
use nelomai_client_tunnel::TunnelController;
use nelomai_contracts::Platform;
use std::sync::Arc;
use std::time::Duration;

const OWNER_REQUEST_BUDGET: Duration = Duration::from_secs(10);

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
    admission: Arc<dyn RuntimeAdmission>,
    writers: Arc<RuntimeWriterGates>,
}

/// Host control capability; the future child implements command/ACK with its
/// own exact-runtime record owner, never a second container backend writer.
pub trait RuntimeAdmission: Send + Sync {
    fn check(&self, access: &AccessSnapshot) -> Result<(), CoreError>;
    fn bind_empty(
        &self,
        access: &AccessSnapshot,
        quiescence: &RuntimeWriterQuiescence,
    ) -> Result<(), CoreError>;
}
pub struct RuntimeCacheAdmission<S> {
    owner: Arc<RuntimeRecordOwner<S>>,
}
impl<S: RuntimeStateStore> RuntimeCacheAdmission<S> {
    pub fn new(owner: Arc<RuntimeRecordOwner<S>>) -> Self {
        Self { owner }
    }
    fn scope(access: &AccessSnapshot) -> RuntimeAuthScope {
        RuntimeAuthScope {
            auth_epoch: access.auth_epoch(),
            family: access.family().into(),
            identity: access.identity().clone(),
        }
    }
}
impl<S: RuntimeStateStore> RuntimeAdmission for RuntimeCacheAdmission<S> {
    fn check(&self, access: &AccessSnapshot) -> Result<(), CoreError> {
        self.owner
            .check_scope(&Self::scope(access))
            .map_err(|_| CoreError::AuthRecoveryRequired)
    }
    fn bind_empty(
        &self,
        access: &AccessSnapshot,
        _: &RuntimeWriterQuiescence,
    ) -> Result<(), CoreError> {
        if self.check(access).is_ok() {
            return Ok(());
        }
        self.owner
            .bind_empty_scope(&Self::scope(access))
            .map_err(|_| CoreError::AuthRecoveryRequired)
    }
}
impl OwnerRuntimeAuth {
    pub async fn recover_background<F, Fut>(&self, dispatch: F) -> Result<AccessSnapshot, CoreError>
    where
        F: FnOnce(crate::NativeAuthRequest) -> Fut,
        Fut: std::future::Future<
            Output = Result<nelomai_client_api::TokenResponse, crate::NativeAuthFailure>,
        >,
    {
        self.broker
            .native_auth(
                |access| self.check_native_admission(access),
                |request| async { dispatch(request).await.map(Some) },
                true,
            )
            .await
            .map_err(map_error)
    }

    pub async fn provision_background<F, Fut>(&self, dispatch: F) -> Result<(), CoreError>
    where
        F: FnOnce(crate::NativeAuthRequest) -> Fut,
        Fut: std::future::Future<Output = Result<(), crate::NativeAuthFailure>>,
    {
        self.broker
            .native_auth(
                |access| self.check_native_admission(access),
                |request| async { dispatch(request).await.map(|()| None) },
                false,
            )
            .await
            .map(|_| ())
            .map_err(map_error)
    }

    fn check_native_admission(&self, access: &AccessSnapshot) -> Result<(), BrokerError> {
        if RuntimeTarget::from_identity(access.identity()) != self.target {
            return Err(BrokerError::Cancelled);
        }
        self.admission
            .check(access)
            .map_err(|_| BrokerError::RecoveryRequired)
    }

    /// Does not enroll, refresh or erase migration credentials. The coordinator
    /// must complete cleanup before runtime operational admission is enabled.
    pub fn new(
        broker: Arc<AuthBroker>,
        target: RuntimeTarget,
        profile: RuntimeClientProfile,
        admission: Arc<dyn RuntimeAdmission>,
        writers: Arc<RuntimeWriterGates>,
    ) -> Result<Self, BrokerError> {
        target.identity(None)?;
        Ok(Self {
            broker,
            target,
            profile,
            admission,
            writers,
        })
    }
    /// Startup/control only. Migration refs and absent scope never become an
    /// admitted cache merely because a valid auth snapshot exists.
    pub async fn admit_empty_current(&self) -> Result<(), CoreError> {
        let quiescence = tokio::time::timeout(OWNER_REQUEST_BUDGET, self.writers.quiesce())
            .await
            .map_err(|_| CoreError::Api(nelomai_client_core::CoreApiError::Retryable))?;
        let observation = self.broker.observe().await.map_err(map_error)?;
        let access =
            self.check_target(observation.access.ok_or(CoreError::AuthRecoveryRequired)?)?;
        self.bind_current(&access, &quiescence).await
    }
    async fn bind_current(
        &self,
        access: &AccessSnapshot,
        quiescence: &RuntimeWriterQuiescence,
    ) -> Result<(), CoreError> {
        self.broker
            .with_current_access(access, || {
                self.admission
                    .bind_empty(access, quiescence)
                    .map_err(|_| BrokerError::RecoveryRequired)
            })
            .await
            .map_err(map_error)
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
        BrokerError::AccessUnavailable => CoreError::AccessExpired,
        BrokerError::RecoveryRequired => CoreError::AuthRecoveryRequired,
        BrokerError::Timeout => CoreError::Api(nelomai_client_core::CoreApiError::Retryable),
    }
}
#[async_trait]
impl RuntimeAuthProvider for OwnerRuntimeAuth {
    async fn state(&self) -> Result<RuntimeAuthState, CoreError> {
        let observation = self.broker.observe().await.map_err(map_error)?;
        Ok(match observation.state {
            BrokerAuthState::Active => {
                let access =
                    self.check_target(observation.access.ok_or(CoreError::AuthRecoveryRequired)?)?;
                if self.admission.check(&access).is_ok() {
                    RuntimeAuthState::Active
                } else {
                    RuntimeAuthState::RecoveryRequired
                }
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
        // Drain actual lifecycle/intent/split/connection writers BEFORE the
        // broker takes issuance. Logout deliberately never takes this barrier.
        let deadline = tokio::time::Instant::now() + OWNER_REQUEST_BUDGET;
        let fence = tokio::time::timeout_at(deadline, self.broker.capture_login_fence())
            .await
            .map_err(|_| CoreError::Api(nelomai_client_core::CoreApiError::Retryable))?
            .map_err(map_error)?;
        let quiescence = tokio::time::timeout_at(deadline, self.writers.quiesce())
            .await
            .map_err(|_| CoreError::Api(nelomai_client_core::CoreApiError::Retryable))?;
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
        if tokio::time::Instant::now() >= deadline {
            return Err(CoreError::Api(nelomai_client_core::CoreApiError::Retryable));
        }
        let access = self.check_target(
            tokio::time::timeout_at(
                deadline,
                self.broker.login_fenced(&request, &self.target, &fence),
            )
            .await
            .map_err(|_| CoreError::AuthenticationOutcomeUnknown)?
            .map_err(map_error)?,
        )?;
        tokio::time::timeout_at(deadline, self.bind_current(&access, &quiescence))
            .await
            .map_err(|_| CoreError::Api(nelomai_client_core::CoreApiError::Retryable))??;
        Ok(access)
    }
    async fn access(&self, stale: Option<&AccessSnapshot>) -> Result<AccessSnapshot, CoreError> {
        // Reject a replaced runtime before any refresh side effect. Generation
        // can evolve within the bound target; it is not a launch-time pin.
        let current =
            self.check_target(self.broker.access_token(None).await.map_err(map_error)?)?;
        self.admission.check(&current)?;
        match stale {
            None => Ok(current),
            Some(stale) => {
                let access = self.check_target(
                    self.broker
                        .access_token(Some(stale))
                        .await
                        .map_err(map_error)?,
                )?;
                self.admission.check(&access)?;
                Ok(access)
            }
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
