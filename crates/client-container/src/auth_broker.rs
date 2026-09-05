//! Single protected credential owner. The launcher must hold the cross-process
//! single-instance lock and finish migration before construction. Never retain
//! a writable RuntimeStorageSession compatibility projection beside this owner.
use async_trait::async_trait;
use nelomai_client_api::{
    AccessSnapshot, ClientApi, ClientApiError, LoginRequest, RuntimeLogoutRequest,
    RuntimeResumeRequest, RuntimeTarget, TokenResponse,
};
use nelomai_client_storage::RecoveryTicketV1;
use nelomai_client_storage::{
    AuthStore, AuthStoreV1, BrokerMetadataV1, BrokerRequestKind, BrokerRequestV1,
    CompletedResumeV1, LogoutState, PendingLogoutV1, StorageError, StoredResumeArgumentsV1,
};
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;
use uuid::Uuid;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(thiserror::Error)]
pub enum BrokerError {
    #[error("authentication operation cancelled")]
    Cancelled,
    #[error("protected authentication requires recovery")]
    RecoveryRequired,
    #[error("runtime identity mismatch")]
    IdentityMismatch,
    #[error("authentication request timed out")]
    Timeout,
    #[error("authentication outcome unknown; explicit reauthentication required")]
    AuthenticationOutcomeUnknown,
    #[error("protected storage failed")]
    Storage(#[from] StorageError),
    // Do not format server-controlled errors or request data into runtime logs.
    #[error("authentication service request failed")]
    Api(#[from] ClientApiError),
}
impl std::fmt::Debug for BrokerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerAuthState {
    Active,
    RecoveryRequired,
    LogoutPending,
    LoggedOut,
    AuthenticationOutcomeUnknown,
}

/// State and optional access (including its owner scope) from one protected
/// record under one broker fence. Never pair two independent observations.
#[derive(Debug)]
pub struct BrokerObservation {
    pub state: BrokerAuthState,
    pub access: Option<AccessSnapshot>,
}

#[async_trait]
pub trait LocalAuthStop: Send + Sync {
    async fn stop_local(&self) -> Result<(), BrokerError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeArguments {
    pub operation_id: String,
    pub reconcile_operation_id: String,
    pub decision: String,
    pub target: RuntimeTarget,
    pub expected_session_generation: Option<u64>,
}
impl ResumeArguments {
    fn stored(&self) -> Result<StoredResumeArgumentsV1, BrokerError> {
        for id in [&self.operation_id, &self.reconcile_operation_id] {
            let uuid = Uuid::parse_str(id).map_err(|_| BrokerError::RecoveryRequired)?;
            if uuid.to_string() != *id {
                return Err(BrokerError::RecoveryRequired);
            }
        }
        if !matches!(self.decision.as_str(), "apply" | "cancel") {
            return Err(BrokerError::RecoveryRequired);
        }
        Ok(StoredResumeArgumentsV1 {
            reconcile_operation_id: self.reconcile_operation_id.clone(),
            decision: self.decision.clone(),
            target: self.target.identity(None)?,
            expected_session_generation: self.expected_session_generation,
        })
    }
}

pub struct AuthBroker {
    api: ClientApi,
    store: Arc<dyn AuthStore>,
    stop: Arc<dyn LocalAuthStop>,
    state: Mutex<()>,
    issuance: Mutex<()>,
}
impl AuthBroker {
    pub(crate) fn owned_install_secret(&self) -> Result<String, BrokerError> {
        Ok(self.load()?.install_secret)
    }
    pub fn new(
        api: ClientApi,
        store: Arc<dyn AuthStore>,
        stop: Arc<dyn LocalAuthStop>,
    ) -> Result<Self, BrokerError> {
        let mut auth = store.load()?.ok_or(BrokerError::RecoveryRequired)?;
        auth.validate()?;
        if auth.broker.is_none() {
            auth.broker = Some(BrokerMetadataV1 {
                family: Uuid::new_v4().to_string(),
                next_attempt: 0,
                pending_request: None,
                completed_resume: None,
                pending_logout: None,
                pending_recovery: None,
                cancelled_login: None,
                authentication_outcome_unknown: false,
                pending_login_account: None,
                confirmed_device_id: None,
            });
            store.save(&auth)?;
        } else if let Some(meta) = &mut auth.broker {
            // The single-instance precondition means this is a fresh owner,
            // not a second observer of another process's pending password login.
            if meta
                .pending_request
                .as_ref()
                .is_some_and(|p| p.kind == BrokerRequestKind::Login)
            {
                meta.authentication_outcome_unknown = true;
                store.save(&auth)?;
            }
        }
        Ok(Self {
            api,
            store,
            stop,
            state: Mutex::new(()),
            issuance: Mutex::new(()),
        })
    }

    fn load(&self) -> Result<AuthStoreV1, BrokerError> {
        let auth = self.store.load()?.ok_or(BrokerError::RecoveryRequired)?;
        auth.validate()?;
        if auth.broker.is_none() {
            return Err(BrokerError::RecoveryRequired);
        }
        Ok(auth)
    }
    fn active(auth: &AuthStoreV1) -> Result<(), BrokerError> {
        if auth.logout_state != LogoutState::Active {
            return Err(BrokerError::Cancelled);
        }
        if auth
            .broker
            .as_ref()
            .is_some_and(|m| m.authentication_outcome_unknown)
        {
            return Err(BrokerError::AuthenticationOutcomeUnknown);
        }
        Ok(())
    }
    fn snapshot(auth: &AuthStoreV1) -> Result<AccessSnapshot, BrokerError> {
        Self::active(auth)?;
        Ok(AccessSnapshot::new(
            auth.access_token
                .clone()
                .ok_or(BrokerError::RecoveryRequired)?,
            auth.confirmed_identity
                .clone()
                .ok_or(BrokerError::RecoveryRequired)?,
            auth.auth_epoch,
            auth.broker
                .as_ref()
                .ok_or(BrokerError::RecoveryRequired)?
                .family
                .clone(),
        )?)
    }
    fn begin(
        &self,
        auth: &mut AuthStoreV1,
        kind: BrokerRequestKind,
        operation_id: String,
        resume: Option<StoredResumeArgumentsV1>,
        prior_login_outcome_unknown: bool,
    ) -> Result<BrokerRequestV1, BrokerError> {
        Self::active(auth)?;
        let meta = auth.broker.as_mut().ok_or(BrokerError::RecoveryRequired)?;
        meta.next_attempt = meta
            .next_attempt
            .checked_add(1)
            .ok_or(BrokerError::RecoveryRequired)?;
        let request = BrokerRequestV1 {
            kind,
            operation_id,
            attempt: meta.next_attempt,
            auth_epoch: auth.auth_epoch,
            source_identity: auth.confirmed_identity.clone(),
            source_device_id: meta.confirmed_device_id.clone(),
            prior_login_outcome_unknown,
            resume,
        };
        meta.pending_request = Some(request.clone());
        self.store.save(auth)?;
        Ok(request)
    }
    fn fenced(&self, ticket: &BrokerRequestV1) -> Result<AuthStoreV1, BrokerError> {
        let auth = self.load()?;
        Self::active(&auth)?;
        if !Self::owns_ticket(&auth, ticket) {
            return Err(BrokerError::Cancelled);
        }
        Ok(auth)
    }

    fn owns_ticket(auth: &AuthStoreV1, ticket: &BrokerRequestV1) -> bool {
        auth.auth_epoch == ticket.auth_epoch
            && auth.logout_state == LogoutState::Active
            && auth.confirmed_identity == ticket.source_identity
            && auth.broker.as_ref().is_some_and(|m| {
                m.next_attempt == ticket.attempt
                    && m.confirmed_device_id == ticket.source_device_id
                    && m.pending_request.as_ref() == Some(ticket)
            })
    }

    pub async fn auth_state(&self) -> Result<BrokerAuthState, BrokerError> {
        Ok(self.observe().await?.state)
    }

    pub async fn observe(&self) -> Result<BrokerObservation, BrokerError> {
        let _state = self.state.lock().await;
        let auth = self.load()?;
        let state = Self::observed_state(&auth)?;
        let access = if state == BrokerAuthState::Active {
            Self::snapshot(&auth).ok()
        } else {
            None
        };
        Ok(BrokerObservation {
            state: if state == BrokerAuthState::Active && access.is_none() {
                BrokerAuthState::RecoveryRequired
            } else {
                state
            },
            access,
        })
    }

    fn observed_state(auth: &AuthStoreV1) -> Result<BrokerAuthState, BrokerError> {
        let meta = auth.broker.as_ref().ok_or(BrokerError::RecoveryRequired)?;
        if meta.authentication_outcome_unknown {
            return Ok(BrokerAuthState::AuthenticationOutcomeUnknown);
        }
        Ok(match auth.logout_state {
            LogoutState::Pending => BrokerAuthState::LogoutPending,
            LogoutState::LoggedOut => BrokerAuthState::LoggedOut,
            // A persisted password attempt has an unknown outcome until commit,
            // including when its caller future was dropped in this process.
            LogoutState::Active
                if meta
                    .pending_request
                    .as_ref()
                    .is_some_and(|p| p.kind == BrokerRequestKind::Login) =>
            {
                BrokerAuthState::AuthenticationOutcomeUnknown
            }
            LogoutState::Active
                if meta.pending_request.is_some()
                    || meta.pending_recovery.is_some()
                    || auth.confirmed_identity.is_none()
                    || auth.access_token.is_none() =>
            {
                BrokerAuthState::RecoveryRequired
            }
            LogoutState::Active => BrokerAuthState::Active,
        })
    }

    /// Container-only password ingress. Install identity is read from protected
    /// ownership, never accepted from the caller's request. No password is stored.
    pub async fn login(
        &self,
        request: &LoginRequest,
        target: &RuntimeTarget,
    ) -> Result<AccessSnapshot, BrokerError> {
        target.identity(None)?;
        let _issuance = self.issuance.lock().await;
        let (ticket, request) = {
            let _state = self.state.lock().await;
            let mut auth = self.load()?;
            let meta = auth.broker.as_ref().ok_or(BrokerError::RecoveryRequired)?;
            if meta.pending_logout.is_some() {
                return Err(BrokerError::RecoveryRequired);
            }
            // Acquiring issuance above proves no previous in-process password
            // future still owns the operation. A dropped future is not busy.
            let controlled_unknown = (meta.authentication_outcome_unknown
                || meta
                    .pending_request
                    .as_ref()
                    .is_some_and(|p| p.kind == BrokerRequestKind::Login))
                && meta.pending_logout.is_none();
            if controlled_unknown
                && meta.pending_login_account.as_deref() != Some(request.login.as_str())
            {
                return Err(BrokerError::RecoveryRequired);
            }
            let fresh = auth.logout_state == LogoutState::Active
                && auth.access_token.is_none()
                && auth.refresh_token.is_none()
                && auth.confirmed_identity.is_none();
            if !(auth.logout_state == LogoutState::LoggedOut || controlled_unknown || fresh) {
                return Err(BrokerError::RecoveryRequired);
            }
            auth.auth_epoch = auth
                .auth_epoch
                .checked_add(1)
                .ok_or(BrokerError::RecoveryRequired)?;
            auth.logout_state = LogoutState::Active;
            let meta = auth.broker.as_mut().ok_or(BrokerError::RecoveryRequired)?;
            meta.authentication_outcome_unknown = false;
            meta.cancelled_login = None;
            meta.pending_recovery = None;
            meta.pending_login_account = Some(request.login.clone());
            let ticket = self.begin(
                &mut auth,
                BrokerRequestKind::Login,
                Uuid::new_v4().to_string(),
                None,
                controlled_unknown,
            )?;
            let mut request = request.clone();
            request.install_secret = auth.install_secret;
            (ticket, request)
        };
        let stop = self.stop.stop_local().await;
        let local_not_issued = stop.is_err();
        let response = if let Err(error) = stop {
            Err(error)
        } else {
            match tokio::time::timeout(REQUEST_TIMEOUT, self.api.login_runtime(&request, target))
                .await
            {
                Ok(result) => result.map_err(BrokerError::Api),
                Err(_) => Err(BrokerError::Timeout),
            }
        };
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                let _state = self.state.lock().await;
                let mut auth = self.load()?;
                if Self::owns_ticket(&auth, &ticket) {
                    let known_not_issued = local_not_issued
                        || matches!(&error,
                        BrokerError::Api(ClientApiError::Api { status, code, .. })
                            if matches!((status.as_u16(), code.as_str()),
                                (401, "invalid_credentials") | (403, "app_access_unavailable")
                                | (429, "login_rate_limited") | (422, "invalid_request")));
                    let meta = auth.broker.as_mut().ok_or(BrokerError::RecoveryRequired)?;
                    if known_not_issued && !ticket.prior_login_outcome_unknown {
                        meta.pending_request = None;
                        meta.pending_login_account = None;
                        meta.authentication_outcome_unknown = false;
                        auth.logout_state = LogoutState::LoggedOut;
                    } else {
                        meta.authentication_outcome_unknown = true;
                    }
                    self.store.save(&auth)?;
                }
                return Err(error);
            }
        };
        let confirmed = response.device.confirmed_identity();
        let invalid_response = confirmed.as_ref().is_err()
            || confirmed
                .as_ref()
                .is_ok_and(|identity| RuntimeTarget::from_identity(identity) != *target)
            || response.token_type != "Bearer"
            || response.access_token.is_empty()
            || response.refresh_token.is_empty()
            || response.device.id.is_empty()
            || response.access_expires_in == 0
            || (ticket.source_device_id.as_deref() == Some(response.device.id.as_str())
                && confirmed.as_ref().is_ok_and(|identity| {
                    identity.session_generation
                        <= ticket
                            .source_identity
                            .as_ref()
                            .and_then(|i| i.session_generation)
                }));
        let _state = self.state.lock().await;
        let mut auth = self.load()?;
        let cancelled = auth.logout_state == LogoutState::Pending
            && auth.confirmed_identity == ticket.source_identity
            && auth
                .broker
                .as_ref()
                .is_some_and(|m| m.confirmed_device_id == ticket.source_device_id)
            && auth.auth_epoch
                == ticket
                    .auth_epoch
                    .checked_add(1)
                    .ok_or(BrokerError::RecoveryRequired)?
            && auth
                .broker
                .as_ref()
                .and_then(|m| m.cancelled_login.as_ref())
                == Some(&ticket);
        let owned = Self::owns_ticket(&auth, &ticket);
        if cancelled || (owned && invalid_response) {
            // A usable proof must survive even if the accompanying identity is
            // rejected. It authorizes only this returned family, not newer auth.
            if response.refresh_token.is_empty() || response.refresh_token.len() > 256 {
                if owned {
                    auth.broker
                        .as_mut()
                        .ok_or(BrokerError::RecoveryRequired)?
                        .authentication_outcome_unknown = true;
                    self.store.save(&auth)?;
                }
                return Err(BrokerError::IdentityMismatch);
            }
            if owned {
                auth.auth_epoch = auth
                    .auth_epoch
                    .checked_add(1)
                    .ok_or(BrokerError::RecoveryRequired)?;
                auth.logout_state = LogoutState::Pending;
            }
            let meta = auth.broker.as_mut().ok_or(BrokerError::RecoveryRequired)?;
            meta.pending_logout = Some(PendingLogoutV1 {
                operation_id: Uuid::new_v4().to_string(),
                refresh_proof: response.refresh_token,
            });
            meta.cancelled_login = None;
            meta.pending_request = None;
            meta.authentication_outcome_unknown = false;
            self.store.save(&auth)?;
            drop(_state);
            self.logout().await?;
            return Err(if cancelled {
                BrokerError::Cancelled
            } else {
                BrokerError::IdentityMismatch
            });
        }
        auth = self.fenced(&ticket)?;
        let confirmed = confirmed?;
        auth.access_token = Some(response.access_token);
        auth.refresh_token = Some(response.refresh_token);
        auth.session_generation = confirmed.session_generation;
        auth.confirmed_identity = Some(confirmed);
        let meta = auth.broker.as_mut().ok_or(BrokerError::RecoveryRequired)?;
        meta.family = Uuid::new_v4().to_string();
        meta.pending_request = None;
        meta.completed_resume = None;
        meta.pending_login_account = None;
        meta.confirmed_device_id = Some(response.device.id);
        self.store.save(&auth)?;
        Self::snapshot(&auth)
    }

    pub async fn access_token(
        &self,
        stale: Option<&AccessSnapshot>,
    ) -> Result<AccessSnapshot, BrokerError> {
        {
            let _state = self.state.lock().await;
            Self::active(&self.load()?)?;
        }
        let _issuance = self.issuance.lock().await;
        let (ticket, refresh) = {
            let _state = self.state.lock().await;
            let mut auth = self.load()?;
            Self::active(&auth)?;
            // A lost ordinary refresh response has no idempotency key. Never
            // probe its old token after restart and risk family reuse revocation.
            if auth
                .broker
                .as_ref()
                .is_some_and(|m| m.pending_request.is_some() || m.pending_recovery.is_some())
            {
                return Err(BrokerError::RecoveryRequired);
            }
            let current = Self::snapshot(&auth)?;
            if let Some(stale) = stale {
                if stale.identity() != current.identity()
                    || stale.auth_epoch() != current.auth_epoch()
                    || stale.family() != current.family()
                {
                    return Err(BrokerError::Cancelled);
                }
                if stale.access_token() != current.access_token() {
                    return Ok(current);
                }
            } else {
                return Ok(current);
            }
            let refresh = auth
                .refresh_token
                .clone()
                .ok_or(BrokerError::RecoveryRequired)?;
            let ticket = self.begin(
                &mut auth,
                BrokerRequestKind::Refresh,
                Uuid::new_v4().to_string(),
                None,
                false,
            )?;
            (ticket, refresh)
        };
        let response = tokio::time::timeout(REQUEST_TIMEOUT, self.api.refresh(refresh))
            .await
            .map_err(|_| BrokerError::Timeout)??;
        let _state = self.state.lock().await;
        let mut auth = self.fenced(&ticket)?;
        let confirmed = response.device.confirmed_identity()?;
        if Some(&confirmed) != ticket.source_identity.as_ref()
            || response.token_type != "Bearer"
            || response.access_token.is_empty()
            || response.refresh_token.is_empty()
            || response.access_expires_in == 0
        {
            return Err(BrokerError::IdentityMismatch);
        }
        auth.access_token = Some(response.access_token);
        auth.refresh_token = Some(response.refresh_token);
        auth.broker
            .as_mut()
            .ok_or(BrokerError::RecoveryRequired)?
            .pending_request = None;
        self.store.save(&auth)?;
        Self::snapshot(&auth)
    }

    /// Cleanup coordinator supplies an accepted clean reconcile operation.
    /// Server independently verifies that authority; this method cannot bypass it.
    pub async fn resume(&self, args: ResumeArguments) -> Result<AccessSnapshot, BrokerError> {
        let stored = args.stored()?;
        let _issuance = self.issuance.lock().await;
        let (ticket, refresh) = {
            let _state = self.state.lock().await;
            let mut auth = self.load()?;
            Self::active(&auth)?;
            let meta = auth.broker.as_ref().ok_or(BrokerError::RecoveryRequired)?;
            if let Some(done) = &meta.completed_resume {
                if done.request.operation_id == args.operation_id {
                    if meta.pending_request.is_some() || meta.pending_recovery.is_some() {
                        return Err(BrokerError::RecoveryRequired);
                    }
                    if done.request.resume.as_ref() == Some(&stored)
                        && done.request.auth_epoch == auth.auth_epoch
                        && auth.confirmed_identity.as_ref() == Some(&done.identity)
                    {
                        return Self::snapshot(&auth);
                    }
                    return Err(BrokerError::Cancelled);
                }
            }
            if auth.session_generation != args.expected_session_generation {
                return Err(BrokerError::IdentityMismatch);
            }
            if let Some(pending) = &meta.pending_request {
                if pending.kind != BrokerRequestKind::Resume
                    || pending.operation_id != args.operation_id
                    || pending.resume.as_ref() != Some(&stored)
                    || pending.auth_epoch != auth.auth_epoch
                    || pending.source_identity != auth.confirmed_identity
                {
                    return Err(BrokerError::Cancelled);
                }
            }
            let refresh = auth
                .refresh_token
                .clone()
                .ok_or(BrokerError::RecoveryRequired)?;
            let ticket = self.begin(
                &mut auth,
                BrokerRequestKind::Resume,
                args.operation_id.clone(),
                Some(stored),
                false,
            )?;
            (ticket, refresh)
        };
        let request = RuntimeResumeRequest {
            refresh_token: refresh,
            operation_id: args.operation_id,
            expected_session_generation: args.expected_session_generation,
            target_identity: args.target.clone(),
            reconcile_operation_id: args.reconcile_operation_id,
            decision: args.decision,
        };
        let response = tokio::time::timeout(REQUEST_TIMEOUT, self.api.resume_runtime(&request))
            .await
            .map_err(|_| BrokerError::Timeout)??;
        let _state = self.state.lock().await;
        let mut auth = self.fenced(&ticket)?;
        let expected_generation = args
            .expected_session_generation
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(BrokerError::IdentityMismatch)?;
        if RuntimeTarget::from_identity(&response.identity) != args.target
            || response.identity.session_generation != Some(expected_generation)
            || response.token_type != "Bearer"
            || response.access_token.is_empty()
            || response.access_expires_in == 0
        {
            return Err(BrokerError::IdentityMismatch);
        }
        auth.session_generation = response.identity.session_generation;
        auth.confirmed_identity = Some(response.identity.clone());
        auth.access_token = Some(response.access_token);
        let meta = auth.broker.as_mut().ok_or(BrokerError::RecoveryRequired)?;
        // Resume invalidates ordinary background scope, unlike ordinary refresh.
        meta.family = Uuid::new_v4().to_string();
        meta.pending_recovery = None;
        meta.completed_resume = Some(CompletedResumeV1 {
            request: ticket,
            identity: response.identity,
        });
        meta.pending_request = None;
        self.store.save(&auth)?;
        Self::snapshot(&auth)
    }

    pub async fn logout(&self) -> Result<(), BrokerError> {
        // Deliberately never acquire issuance: a hung refresh/resume cannot
        // delay the durable cancellation fence, local stop, or family revocation.
        let (epoch, proof) = {
            let _state = self.state.lock().await;
            let mut auth = self.load()?;
            if auth.logout_state == LogoutState::LoggedOut {
                drop(_state);
                return self.stop.stop_local().await;
            }
            if auth.logout_state == LogoutState::Active {
                let never_authenticated = auth.confirmed_identity.is_none()
                    && auth.access_token.is_none()
                    && auth.refresh_token.is_none()
                    && auth.broker.as_ref().is_some_and(|m| {
                        !m.authentication_outcome_unknown
                            && m.pending_request.is_none()
                            && m.cancelled_login.is_none()
                    });
                auth.auth_epoch = auth
                    .auth_epoch
                    .checked_add(1)
                    .ok_or(BrokerError::RecoveryRequired)?;
                auth.logout_state = LogoutState::Pending;
                if never_authenticated {
                    auth.logout_state = LogoutState::LoggedOut;
                    self.store.save(&auth)?;
                    drop(_state);
                    return self.stop.stop_local().await;
                }
                let meta = auth.broker.as_mut().ok_or(BrokerError::RecoveryRequired)?;
                if meta
                    .pending_request
                    .as_ref()
                    .is_some_and(|p| p.kind == BrokerRequestKind::Login)
                {
                    meta.cancelled_login = meta.pending_request.take();
                    meta.authentication_outcome_unknown = true;
                }
                meta.pending_request = None;
                meta.pending_recovery = None;
                meta.pending_logout =
                    auth.refresh_token
                        .clone()
                        .map(|refresh_proof| PendingLogoutV1 {
                            operation_id: Uuid::new_v4().to_string(),
                            refresh_proof,
                        });
                self.store.save(&auth)?;
            }
            (
                auth.auth_epoch,
                auth.broker.as_ref().and_then(|m| m.pending_logout.clone()),
            )
        };
        let Some(proof) = proof else {
            self.stop.stop_local().await?;
            return Err(BrokerError::AuthenticationOutcomeUnknown);
        };
        let request = RuntimeLogoutRequest {
            operation_id: proof.operation_id.clone(),
            refresh_token: proof.refresh_proof.clone(),
        };
        // Initiate both immediately; physical stop failure must not suppress
        // revocation, and a slow remote server must not delay the stop attempt.
        let (stop, response) = tokio::join!(
            self.stop.stop_local(),
            tokio::time::timeout(REQUEST_TIMEOUT, self.api.logout_runtime(&request))
        );
        let response = response.map_err(|_| BrokerError::Timeout)??;
        if !matches!(
            response.code.as_str(),
            "already_inactive" | "session_revoked_cleanup_accepted"
        ) {
            return Err(BrokerError::RecoveryRequired);
        }
        let _state = self.state.lock().await;
        let mut auth = self.load()?;
        if auth.auth_epoch != epoch
            || auth.logout_state != LogoutState::Pending
            || auth.broker.as_ref().and_then(|m| m.pending_logout.as_ref()) != Some(&proof)
        {
            return Err(BrokerError::Cancelled);
        }
        auth.access_token = None;
        auth.refresh_token = None;
        auth.pending_resume = None;
        auth.logout_state = LogoutState::LoggedOut;
        let meta = auth.broker.as_mut().ok_or(BrokerError::RecoveryRequired)?;
        meta.pending_logout = None;
        meta.completed_resume = None;
        meta.pending_login_account = None;
        self.store.save(&auth)?;
        stop
    }

    /// Owner-only: issue provenance before invoking a platform recovery. The
    /// ticket must never be reconstructed from caller-provided identity fields.
    pub async fn begin_background_recovery(&self) -> Result<RecoveryTicketV1, BrokerError> {
        let _issuance = self.issuance.lock().await;
        let _state = self.state.lock().await;
        let mut auth = self.load()?;
        Self::active(&auth)?;
        let identity = auth
            .confirmed_identity
            .clone()
            .ok_or(BrokerError::RecoveryRequired)?;
        let meta = auth.broker.as_mut().ok_or(BrokerError::RecoveryRequired)?;
        if meta
            .pending_request
            .as_ref()
            .is_some_and(|p| p.kind != BrokerRequestKind::Refresh)
        {
            return Err(BrokerError::RecoveryRequired);
        }
        meta.next_attempt = meta
            .next_attempt
            .checked_add(1)
            .ok_or(BrokerError::RecoveryRequired)?;
        let ticket = RecoveryTicketV1 {
            operation_id: Uuid::new_v4().to_string(),
            auth_epoch: auth.auth_epoch,
            attempt: meta.next_attempt,
            family: meta.family.clone(),
            identity,
        };
        meta.pending_recovery = Some(ticket.clone());
        self.store.save(&auth)?;
        Ok(ticket)
    }

    /// Owner callback ingress, not runtime IPC. No network request is made with
    /// returned refresh: validate protected provenance *before* accepting data.
    pub async fn accept_background_recovery(
        &self,
        ticket: &RecoveryTicketV1,
        response: TokenResponse,
    ) -> Result<AccessSnapshot, BrokerError> {
        let _state = self.state.lock().await;
        let mut auth = self.load()?;
        Self::active(&auth)?;
        let meta = auth.broker.as_ref().ok_or(BrokerError::RecoveryRequired)?;
        if meta.pending_recovery.as_ref() != Some(ticket)
            || meta.next_attempt != ticket.attempt
            || meta.family != ticket.family
            || auth.auth_epoch != ticket.auth_epoch
            || auth.confirmed_identity.as_ref() != Some(&ticket.identity)
        {
            return Err(BrokerError::Cancelled);
        }
        if response.device.confirmed_identity()? != ticket.identity
            || response.token_type != "Bearer"
            || response.access_token.is_empty()
            || response.refresh_token.is_empty()
            || response.access_expires_in == 0
        {
            return Err(BrokerError::IdentityMismatch);
        }
        auth.access_token = Some(response.access_token);
        auth.refresh_token = Some(response.refresh_token);
        let meta = auth.broker.as_mut().ok_or(BrokerError::RecoveryRequired)?;
        meta.pending_request = None;
        meta.pending_recovery = None;
        self.store.save(&auth)?;
        Self::snapshot(&auth)
    }
}
