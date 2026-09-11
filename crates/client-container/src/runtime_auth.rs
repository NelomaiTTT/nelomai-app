//! In-process ownership adapter. Private-channel runtime transport is separate.
use crate::{
    AuthBroker, BrokerAuthState, BrokerError, LocalAuthStop, LocalStopReceiptV1,
    RuntimeCleanupHandoff, RuntimeSwitchControl, TransitionSourceSnapshot,
};
use async_trait::async_trait;
use nelomai_client_api::{
    AccessSnapshot, LoginRequest, RuntimeAuthState, RuntimeLogin, RuntimeTarget,
};
use nelomai_client_core::{
    CoreError, CoreLocalStop, RuntimeAuthProvider, RuntimeWriterGates, RuntimeWriterQuiescence,
};
use nelomai_client_storage::{
    CompletedRuntimeLogoutV1, RuntimeAuthScope, RuntimeCleanupSnapshotV1, RuntimeRecordOwner,
    RuntimeStateStore,
};
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

#[derive(Clone)]
pub struct OwnerRuntimeAuth {
    broker: Arc<AuthBroker>,
    target: RuntimeTarget,
    profile: RuntimeClientProfile,
    admission: Arc<dyn RuntimeAdmission>,
    writers: Arc<RuntimeWriterGates>,
    switch_coordinator: Option<Arc<crate::SwitchCoordinator>>,
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
    fn complete_logout(
        &self,
        receipt: &CompletedRuntimeLogoutV1,
        quiescence: &RuntimeWriterQuiescence,
    ) -> Result<(), CoreError>;
}
pub struct RuntimeCacheAdmission<S> {
    owner: Arc<RuntimeRecordOwner<S>>,
}

#[async_trait]
pub trait RuntimeForceStop: Send + Sync {
    async fn force_stop(&self, operation_id: &str) -> Result<(), BrokerError>;
}

pub struct UnavailableRuntimeForceStop;
#[async_trait]
impl RuntimeForceStop for UnavailableRuntimeForceStop {
    async fn force_stop(&self, _: &str) -> Result<(), BrokerError> {
        Err(BrokerError::RecoveryRequired)
    }
}

pub struct RuntimeRecordSwitchControl<S, T> {
    target: Arc<RuntimeRecordOwner<S>>,
    retained: Vec<Arc<RuntimeRecordOwner<S>>>,
    local: Arc<CoreLocalStop<T>>,
    force: Arc<dyn RuntimeForceStop>,
}

impl<S: RuntimeStateStore, T: TunnelController> RuntimeRecordSwitchControl<S, T> {
    pub fn new(
        target: Arc<RuntimeRecordOwner<S>>,
        retained: Vec<Arc<RuntimeRecordOwner<S>>>,
        local: Arc<CoreLocalStop<T>>,
        force: Arc<dyn RuntimeForceStop>,
    ) -> Self {
        Self {
            target,
            retained,
            local,
            force,
        }
    }

    fn record_for_snapshot(
        &self,
        snapshot: &RuntimeCleanupSnapshotV1,
    ) -> Result<&Arc<RuntimeRecordOwner<S>>, BrokerError> {
        let mut matching = self.retained.iter().chain([&self.target]).filter(|owner| {
            owner
                .cleanup_snapshot()
                .is_ok_and(|current| current == *snapshot)
        });
        let record = matching.next().ok_or(BrokerError::RecoveryRequired)?;
        if matching.next().is_some() {
            return Err(BrokerError::RecoveryRequired);
        }
        Ok(record)
    }

    fn target_for_access(
        &self,
        access: &AccessSnapshot,
    ) -> Result<&Arc<RuntimeRecordOwner<S>>, BrokerError> {
        self.retained
            .iter()
            .chain([&self.target])
            .find(|owner| {
                owner.cleanup_snapshot().is_ok_and(|current| {
                    current.slot == access.identity().slot
                        && current.runtime_version == access.identity().runtime_version
                })
            })
            .ok_or(BrokerError::RecoveryRequired)
    }
}

#[async_trait]
impl<S: RuntimeStateStore, T: TunnelController> RuntimeSwitchControl
    for RuntimeRecordSwitchControl<S, T>
{
    async fn handoff_cleanup(
        &self,
        source: &TransitionSourceSnapshot,
    ) -> Result<RuntimeCleanupHandoff, BrokerError> {
        let quiescence = tokio::time::timeout(
            OWNER_REQUEST_BUDGET,
            self.local.runtime_writer_gates().quiesce(),
        )
        .await
        .map_err(|_| BrokerError::Timeout)?;
        let mut matches = self
            .retained
            .iter()
            .chain([&self.target])
            .filter_map(|owner| {
                let snapshot = owner.cleanup_snapshot().ok()?;
                if source.matches_runtime_scope(snapshot.auth_scope.as_ref())
                    && source.identity().is_none_or(|identity| {
                        identity.slot == snapshot.slot
                            && identity.runtime_version == snapshot.runtime_version
                    })
                {
                    Some(snapshot)
                } else {
                    None
                }
            });
        let snapshot = matches.next().ok_or(BrokerError::RecoveryRequired)?;
        if matches.next().is_some() {
            return Err(BrokerError::RecoveryRequired);
        }
        Ok(RuntimeCleanupHandoff::new(snapshot, quiescence))
    }

    async fn graceful_stop(
        &self,
        _: &str,
        snapshot: &RuntimeCleanupSnapshotV1,
    ) -> Result<(), BrokerError> {
        self.record_for_snapshot(snapshot)?;
        self.local
            .stop_local()
            .await
            .map_err(|_| BrokerError::RecoveryRequired)
    }

    async fn force_stop(
        &self,
        operation_id: &str,
        snapshot: &RuntimeCleanupSnapshotV1,
    ) -> Result<(), BrokerError> {
        self.record_for_snapshot(snapshot)?;
        self.force.force_stop(operation_id).await
    }

    async fn complete_cleanup_and_admit(
        &self,
        snapshot: &RuntimeCleanupSnapshotV1,
        receipt: &LocalStopReceiptV1,
        access: &AccessSnapshot,
    ) -> Result<(), BrokerError> {
        if receipt.runtime_slot != snapshot.slot
            || receipt.runtime_version != snapshot.runtime_version
        {
            return Err(BrokerError::IdentityMismatch);
        }
        let _quiescence = tokio::time::timeout(
            OWNER_REQUEST_BUDGET,
            self.local.runtime_writer_gates().quiesce(),
        )
        .await
        .map_err(|_| BrokerError::Timeout)?;
        let target = self.target_for_access(access)?;
        let target_snapshot = target.cleanup_snapshot()?;
        let target_scope = RuntimeAuthScope {
            auth_epoch: access.auth_epoch(),
            family: access.family().into(),
            identity: access.identity().clone(),
        };
        if !target_snapshot.cleanup_only
            && target_snapshot.auth_scope.as_ref() == Some(&target_scope)
        {
            if let Ok(source) = self.record_for_snapshot(snapshot) {
                if !Arc::ptr_eq(source, target) {
                    source.complete_cleanup(snapshot)?;
                }
            }
            return Ok(());
        }
        let source = self.record_for_snapshot(snapshot)?;
        if Arc::ptr_eq(source, target) {
            source.complete_cleanup_and_bind(snapshot, &target_scope)?;
            return Ok(());
        }
        if !target_snapshot.cleanup_only
            || !target_snapshot.lease_ids.is_empty()
            || !target_snapshot.operations.is_empty()
            || target_snapshot.auth_scope.is_some()
        {
            return Err(BrokerError::RecoveryRequired);
        }
        target.complete_cleanup_and_bind(&target_snapshot, &target_scope)?;
        source.complete_cleanup(snapshot)?;
        Ok(())
    }
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
    fn complete_logout(
        &self,
        receipt: &CompletedRuntimeLogoutV1,
        _quiescence: &RuntimeWriterQuiescence,
    ) -> Result<(), CoreError> {
        let snapshot = self
            .owner
            .cleanup_snapshot()
            .map_err(|_| CoreError::AuthRecoveryRequired)?;
        let exact_runtime = receipt.source.identity.as_ref().is_none_or(|identity| {
            snapshot.slot == identity.slot && snapshot.runtime_version == identity.runtime_version
        });
        if exact_runtime
            && snapshot.auth_scope.is_none()
            && snapshot.lease_ids.is_empty()
            && snapshot.operations.is_empty()
            && !snapshot.cleanup_only
        {
            return Ok(());
        }
        let matches = match (&receipt.source.identity, &snapshot.auth_scope) {
            (None, None) => snapshot.cleanup_only,
            (None, Some(_)) => {
                // Only the selected namespace receives a legacy receipt. The
                // owner has confirmed logout and stopped the local tunnel under
                // writer quiescence. Recover an empty orphan binding, never
                // erase another scope's leases, pending work or split state.
                return self
                    .owner
                    .complete_empty_logout(&snapshot)
                    .map_err(|_| CoreError::AuthRecoveryRequired);
            }
            (Some(identity), Some(scope)) => {
                &scope.identity == identity
                    && scope.auth_epoch == receipt.source.auth_epoch
                    && scope.family == receipt.source.family
                    && snapshot.slot == identity.slot
                    && snapshot.runtime_version == identity.runtime_version
            }
            _ => false,
        };
        if !matches {
            return Err(CoreError::AuthRecoveryRequired);
        }
        self.owner
            .complete_cleanup(&snapshot)
            .map_err(|_| CoreError::AuthRecoveryRequired)
    }
}
impl OwnerRuntimeAuth {
    pub fn with_switch_coordinator(mut self, coordinator: Arc<crate::SwitchCoordinator>) -> Self {
        self.switch_coordinator = Some(coordinator);
        self
    }

    pub async fn recover_logout_cleanup(&self) -> Result<(), CoreError> {
        let Some(receipt) = self
            .broker
            .completed_runtime_logout()
            .await
            .map_err(map_error)?
        else {
            return Ok(());
        };
        let _execution = match &self.switch_coordinator {
            Some(coordinator) => Some(
                tokio::time::timeout(OWNER_REQUEST_BUDGET, coordinator.lock_logout_cleanup())
                    .await
                    .map_err(|_| CoreError::Api(nelomai_client_core::CoreApiError::Retryable))?,
            ),
            None => None,
        };
        let quiescence = tokio::time::timeout(OWNER_REQUEST_BUDGET, self.writers.quiesce())
            .await
            .map_err(|_| CoreError::Api(nelomai_client_core::CoreApiError::Retryable))?;
        match self
            .broker
            .completed_runtime_logout()
            .await
            .map_err(map_error)?
        {
            None => return Ok(()),
            Some(current) if current == receipt => {}
            Some(_) => return Err(CoreError::AuthRecoveryRequired),
        }
        self.broker
            .stop_runtime_logout_cleanup(&receipt)
            .await
            .map_err(map_error)?;
        self.admission.complete_logout(&receipt, &quiescence)?;
        if let Some(coordinator) = &self.switch_coordinator {
            coordinator
                .retire_logout_journal(&receipt)
                .await
                .map_err(|_| CoreError::AuthRecoveryRequired)?;
        }
        self.broker
            .finish_runtime_logout_cleanup(&receipt)
            .await
            .map_err(map_error)
    }

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
            switch_coordinator: None,
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
        BrokerError::RecoveryRequired | BrokerError::RefreshRejected => {
            CoreError::AuthRecoveryRequired
        }
        BrokerError::Timeout | BrokerError::RefreshPending => {
            CoreError::Api(nelomai_client_core::CoreApiError::Retryable)
        }
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
        tokio::time::timeout_at(deadline, self.recover_logout_cleanup())
            .await
            .map_err(|_| CoreError::Api(nelomai_client_core::CoreApiError::Retryable))??;
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
        let (_, observation) = self
            .broker
            .observe_access_stamped()
            .await
            .map_err(map_error)?;
        let current = self.check_target(match observation.access {
            Some(access) => access,
            None => self
                .broker
                .pending_refresh_access()
                .await
                .map_err(map_error)?,
        })?;
        self.admission.check(&current)?;
        let stamp = crate::auth_broker::ScopeStamp::from_access(&current);
        let access = self.check_target(
            self.broker
                .access_token_fenced(&stamp, stale)
                .await
                .map_err(map_error)?,
        )?;
        self.admission.check(&access)?;
        Ok(access)
    }
    async fn logout(&self) -> Result<(), CoreError> {
        self.broker.logout().await.map_err(map_error)?;
        let recovery = self.clone();
        tokio::spawn(async move {
            let _ = recovery.recover_logout_cleanup().await;
        });
        Ok(())
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
